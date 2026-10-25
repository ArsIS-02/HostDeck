"""HostDeck: сервер инвентаризации и управления хостами (Starlette, без внешних зависимостей сверх requirements.txt)."""
import asyncio
import base64
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import db

STATIC = os.path.join(os.path.dirname(__file__), "static")
SESSION_COOKIE = "hd_session"
SESSION_TTL = 12 * 3600
ONLINE_WINDOW = 90          # секунд без опроса -> хост офлайн
POLL_TIMEOUT = 25           # секунд длинного опроса агента
ENROLL_TTL = 24 * 3600
ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}

# --- состояние в памяти --------------------------------------------------
queues = {}                          # host_id -> asyncio.Queue команд
login_attempts = defaultdict(deque)  # ip -> времена неудачных входов


def queue_for(host_id):
    if host_id not in queues:
        queues[host_id] = asyncio.Queue()
    return queues[host_id]


def err(msg, status=400):
    return JSONResponse({"error": msg}, status_code=status)


async def body(request: Request):
    """JSON-тело; требуем application/json, чтобы форма с чужого сайта не могла отправить POST."""
    if "application/json" not in request.headers.get("content-type", ""):
        raise ValueError("нужен Content-Type: application/json")
    data = await request.json()
    if not isinstance(data, dict):
        raise ValueError("ожидается объект JSON")
    return data


# --- терминал -------------------------------------------------------------
TERM_IDLE = 15 * 60         # секунд без ввода -> сессия закрывается
TERM_MAX_BUFFER = 1 << 20   # сколько вывода держим для переподключения браузера
TERM_MAX_PER_HOST = 2
terms = {}                  # sid -> Term


class Term:
    def __init__(self, sid, host_id, user, cols, rows):
        self.sid, self.host_id, self.user, self.cols, self.rows = sid, host_id, user, cols, rows
        self.created = self.last_input = time.time()
        self.chunks = deque()          # (seq, bytes)
        self.size = 0
        self.next_seq = 0              # номер для браузера (свой, сквозной)
        self.agent_seq = 0             # последний принятый от агента, для защиты от дублей
        self.cond = asyncio.Condition()
        self.closed = False
        self.exit_code = None
        self.error = None
        self.bytes_in = self.bytes_out = 0

    async def push(self, data: bytes):
        async with self.cond:
            self.next_seq += 1
            self.chunks.append((self.next_seq, data))
            self.size += len(data)
            self.bytes_out += len(data)
            while self.size > TERM_MAX_BUFFER and len(self.chunks) > 1:
                self.size -= len(self.chunks.popleft()[1])
            self.cond.notify_all()

    async def finish(self, code=None, error=None):
        async with self.cond:
            if not self.closed:
                self.closed = True
                self.exit_code, self.error = code, error
                self.cond.notify_all()
                dur = int(time.time() - self.created)
                db.audit(self.user, "term-closed", host=self.host_id,
                         detail=f"{dur} с, ввод {self.bytes_in} Б, вывод {self.bytes_out} Б" + (f", ошибка: {error}" if error else ""))


def term_for(request: Request, user):
    t = terms.get(request.path_params["sid"])
    if not t or (t.user != user["name"] and user["role"] != "admin"):
        return None
    return t


async def term_open(request: Request):
    u, e = need(request, "admin")  # root-консоль — только администратору
    if e:
        return e
    hid = request.path_params["id"]
    row = db.q1("SELECT * FROM hosts WHERE id=?", (hid,))
    if not row:
        return err("хост не найден", 404)
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    if not (row["last_seen"] and time.time() - row["last_seen"] < ONLINE_WINDOW):
        return err("хост не в сети", 409)
    info = (json.loads(row["posture"]) if row["posture"] else {}).get("info", {})
    if info.get("terminal") != "on":
        db.audit(u["name"], "term-denied", host=hid, detail="консоль не разрешена на хосте")
        return err("консоль не разрешена на этом хосте (агент запущен без allow_terminal)", 409)
    if sum(1 for t in terms.values() if t.host_id == hid and not t.closed) >= TERM_MAX_PER_HOST:
        return err("слишком много открытых сессий на этом хосте", 429)
    try:
        cols = max(20, min(400, int(data.get("cols", 100))))
        rows = max(5, min(200, int(data.get("rows", 30))))
    except (TypeError, ValueError):
        return err("некорректный размер")
    sid = secrets.token_urlsafe(18)
    terms[sid] = Term(sid, hid, u["name"], cols, rows)
    await queue_for(hid).put({"id": secrets.token_hex(4), "type": "term_open", "sid": sid, "cols": cols, "rows": rows})
    db.audit(u["name"], "term-open", host=hid, detail=client_ip(request))
    return JSONResponse({"sid": sid})


async def term_stream(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    t = term_for(request, u)
    if not t:
        return err("сессия не найдена", 404)
    try:
        last = int(request.headers.get("last-event-id") or request.query_params.get("from") or 0)
    except ValueError:
        last = 0

    async def gen():
        nonlocal last
        yield ": ok\n\n"
        while True:
            async with t.cond:
                pending = [(s, d) for s, d in t.chunks if s > last]
                if not pending and not t.closed:
                    try:
                        await asyncio.wait_for(t.cond.wait(), 15)
                    except asyncio.TimeoutError:
                        pass
                    pending = [(s, d) for s, d in t.chunks if s > last]
                closed = t.closed
            for s, d in pending:
                last = s
                yield f"id: {s}\ndata: {base64.b64encode(d).decode()}\n\n"
            if closed and not pending:
                yield f"event: exit\ndata: {json.dumps({'code': t.exit_code, 'error': t.error})}\n\n"
                return
            if not pending:
                yield ": ping\n\n"
            if await request.is_disconnected():
                return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def term_input(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    t = term_for(request, u)
    if not t or t.closed:
        return err("сессия не найдена", 404)
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    d = data.get("d")
    if not isinstance(d, str) or not d or len(d) > 8192:
        return err("некорректный ввод")
    t.last_input = time.time()
    t.bytes_in += len(d.encode())
    await queue_for(t.host_id).put({"id": secrets.token_hex(4), "type": "term_in", "sid": t.sid, "data": d})
    return JSONResponse({"ok": True})


async def term_resize(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    t = term_for(request, u)
    if not t or t.closed:
        return err("сессия не найдена", 404)
    try:
        data = await body(request)
        cols, rows = int(data["cols"]), int(data["rows"])
    except (ValueError, KeyError, TypeError):
        return err("некорректный размер")
    await queue_for(t.host_id).put({"id": secrets.token_hex(4), "type": "term_resize", "sid": t.sid, "cols": cols, "rows": rows})
    return JSONResponse({"ok": True})


async def term_close(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    t = term_for(request, u)
    if not t:
        return err("сессия не найдена", 404)
    if not t.closed:
        await queue_for(t.host_id).put({"id": secrets.token_hex(4), "type": "term_close", "sid": t.sid})
        # если агент не ответит (завис, офлайн) — закрываем со своей стороны
        asyncio.get_running_loop().call_later(5, lambda: asyncio.ensure_future(t.finish(None, "закрыто сервером")) if not t.closed else None)
    return JSONResponse({"ok": True})


async def agent_term(request: Request):
    host = agent_auth(request)
    if not host:
        return err("не авторизован", 401)
    try:
        data = await body(request)
    except ValueError as e:
        return err(str(e))
    t = terms.get(str(data.get("sid", "")))
    if not t or t.host_id != host["id"]:
        return err("сессия не найдена", 404)
    if data.get("error"):
        msg = "консоль отключена на хосте" if data["error"] == "disabled" else str(data["error"])[:200]
        await t.push(f"\r\n\x1b[31m{msg}\x1b[0m\r\n".encode())
        await t.finish(None, msg)
    elif data.get("exit"):
        await t.finish(data.get("code"))
    else:
        try:
            raw = base64.b64decode(str(data.get("data", "")), validate=True)
        except Exception:
            return err("некорректные данные")
        seq = int(data.get("seq", 0) or 0)
        if seq and seq <= t.agent_seq:
            return JSONResponse({"ok": True})  # повтор
        t.agent_seq = max(t.agent_seq, seq)
        if raw and len(raw) <= 1 << 20:
            await t.push(raw)
    return JSONResponse({"ok": True})


async def term_janitor():
    """Закрывает сессии без ввода и забывает давно закрытые."""
    while True:
        await asyncio.sleep(30)
        now = time.time()
        for sid, t in list(terms.items()):
            if not t.closed and now - t.last_input > TERM_IDLE:
                await queue_for(t.host_id).put({"id": secrets.token_hex(4), "type": "term_close", "sid": sid})
                await t.push("\r\n\x1b[33m[сессия закрыта по бездействию]\x1b[0m\r\n".encode())
                await t.finish(None, "простой")
            elif t.closed and now - t.last_input > TERM_IDLE + 300:
                terms.pop(sid, None)


# --- пользователи --------------------------------------------------------
def current_user(request: Request):
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        return None
    row = db.q1("SELECT u.id,u.name,u.role,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
                (db.sha(tok),))
    if not row or row["expires"] < time.time():
        return None
    return row


def need(request: Request, role: str):
    u = current_user(request)
    if not u:
        return None, err("требуется вход", 401)
    if ROLE_ORDER[u["role"]] < ROLE_ORDER[role]:
        return None, err("недостаточно прав", 403)
    return u, None


def client_ip(request: Request):
    return request.client.host if request.client else "?"


async def login(request: Request):
    ip = client_ip(request)
    now = time.time()
    dq = login_attempts[ip]
    while dq and dq[0] < now - 600:
        dq.popleft()
    if len(dq) >= 10:
        return err("слишком много попыток, подождите 10 минут", 429)
    try:
        data = await body(request)
    except ValueError as e:
        return err(str(e))
    name, pw = str(data.get("name", "")), str(data.get("password", ""))
    row = db.q1("SELECT * FROM users WHERE name=?", (name,))
    ok = bool(row) and db.check_password(pw, row["pw_hash"])
    if not row:
        db.check_password(pw, "scrypt$00$00")  # выравниваем время ответа
    if not ok:
        dq.append(now)
        db.audit(name or "?", "login-failed", detail=ip)
        return err("неверное имя или пароль", 401)
    tok = secrets.token_urlsafe(32)
    db.x("INSERT INTO sessions(token_hash,user_id,created,expires) VALUES(?,?,?,?)",
         (db.sha(tok), row["id"], now, now + SESSION_TTL))
    db.audit(name, "login", detail=ip)
    resp = JSONResponse({"name": row["name"], "role": row["role"]})
    resp.set_cookie(SESSION_COOKIE, tok, max_age=SESSION_TTL, httponly=True, samesite="strict",
                    secure=request.url.scheme == "https", path="/")
    return resp


async def logout(request: Request):
    tok = request.cookies.get(SESSION_COOKIE)
    if tok:
        db.x("DELETE FROM sessions WHERE token_hash=?", (db.sha(tok),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


async def me(request: Request):
    u = current_user(request)
    if not u:
        return JSONResponse(None)  # не 401: иначе консоль браузера засоряется ошибкой на странице входа
    return JSONResponse({"name": u["name"], "role": u["role"]})


# --- хосты ---------------------------------------------------------------
# список ПО в сводку не тянем: считаем записи на стороне SQLite
HOST_SELECT = ("SELECT id,name,os,agent_version,last_seen,posture,posture_at,metrics,metrics_at,software_at,"
               "CASE WHEN software IS NULL THEN NULL ELSE json_array_length(software) END AS software_count FROM hosts")
RANK = {"fail": 3, "warn": 2, "unknown": 1, "ok": 0, "info": 0}


def summarize(row, detail=False):
    now = time.time()
    online = bool(row["last_seen"]) and now - row["last_seen"] < ONLINE_WINDOW
    posture = json.loads(row["posture"]) if row["posture"] else None
    counts = {"ok": 0, "warn": 0, "fail": 0, "unknown": 0}
    worst = "unknown"
    if posture:
        worst = "ok"
        for c in posture.get("checks", []):
            st = c.get("status", "unknown")
            if st in counts:
                counts[st] += 1
            if RANK.get(st, 1) > RANK.get(worst, 0):
                worst = st
    out = {
        "id": row["id"], "name": row["name"], "os": row["os"], "agent_version": row["agent_version"],
        "online": online, "last_seen": row["last_seen"], "posture_at": row["posture_at"],
        "status": worst, "counts": counts,
        "info": (posture or {}).get("info", {}),
        "metrics": json.loads(row["metrics"]) if row["metrics"] else None,
        "metrics_at": row["metrics_at"],
        "software_at": row["software_at"],
        "software_count": row["software_count"],
    }
    if detail:
        out["checks"] = (posture or {}).get("checks", [])
    return out


async def hosts_list(request: Request):
    u, e = need(request, "viewer")
    if e:
        return e
    rows = db.q(HOST_SELECT + " ORDER BY name COLLATE NOCASE")
    return JSONResponse([summarize(r) for r in rows])


async def host_detail(request: Request):
    u, e = need(request, "viewer")
    if e:
        return e
    row = db.q1(HOST_SELECT + " WHERE id=?", (request.path_params["id"],))
    if not row:
        return err("хост не найден", 404)
    return JSONResponse(summarize(row, detail=True))


async def host_refresh(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    hid = request.path_params["id"]
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    await queue_for(hid).put({"id": secrets.token_hex(4), "type": "collect"})
    db.audit(u["name"], "refresh", host=hid)
    return JSONResponse({"queued": True})


async def host_software(request: Request):
    u, e = need(request, "viewer")
    if e:
        return e
    row = db.q1("SELECT software, software_at FROM hosts WHERE id=?", (request.path_params["id"],))
    if not row:
        return err("хост не найден", 404)
    items = json.loads(row["software"]) if row["software"] else []
    return JSONResponse({"at": row["software_at"], "items": items})


async def host_software_refresh(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    hid = request.path_params["id"]
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    await queue_for(hid).put({"id": secrets.token_hex(4), "type": "software"})
    db.audit(u["name"], "software-refresh", host=hid)
    return JSONResponse({"queued": True})


async def host_delete(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    hid = request.path_params["id"]
    db.x("DELETE FROM hosts WHERE id=?", (hid,))
    queues.pop(hid, None)
    db.audit(u["name"], "host-deleted", host=hid)
    return JSONResponse({"ok": True})


async def token_create(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    tok = "hde_" + secrets.token_urlsafe(24)
    now = time.time()
    db.x("INSERT INTO enroll_tokens(token_hash,label,created,expires) VALUES(?,?,?,?)",
         (db.sha(tok), str(data.get("label", ""))[:80], now, now + ENROLL_TTL))
    db.audit(u["name"], "enroll-token-created", detail=str(data.get("label", ""))[:80])
    return JSONResponse({"token": tok, "expires": now + ENROLL_TTL})


async def audit_list(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    rows = db.q("SELECT ts,actor,host,action,detail FROM audit ORDER BY id DESC LIMIT 200")
    return JSONResponse([dict(r) for r in rows])


# --- агент ---------------------------------------------------------------
def agent_auth(request: Request):
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer ") or "." not in h:
        return None
    hid, key = h[7:].split(".", 1)
    row = db.q1("SELECT * FROM hosts WHERE id=?", (hid,))
    if not row or not secrets.compare_digest(row["key_hash"], db.sha(key)):
        return None
    return row


async def agent_enroll(request: Request):
    try:
        data = await body(request)
    except ValueError as e:
        return err(str(e))
    tok = str(data.get("token", ""))
    row = db.q1("SELECT * FROM enroll_tokens WHERE token_hash=?", (db.sha(tok),))
    if not row or row["used"] or row["expires"] < time.time():
        db.audit("agent", "enroll-rejected", detail=client_ip(request))
        return err("токен регистрации недействителен", 403)
    name = str(data.get("name", "")).strip()[:100] or "host-" + secrets.token_hex(3)
    hid = secrets.token_hex(8)
    key = secrets.token_urlsafe(32)
    db.x("UPDATE enroll_tokens SET used=1 WHERE token_hash=?", (db.sha(tok),))
    db.x("INSERT INTO hosts(id,name,os,agent_version,key_hash,created,last_seen) VALUES(?,?,?,?,?,?,?)",
         (hid, name, str(data.get("os", ""))[:40], str(data.get("version", ""))[:40], db.sha(key), time.time(), time.time()))
    db.audit("agent", "enrolled", host=hid, detail=name)
    return JSONResponse({"host_id": hid, "host_key": key})


async def agent_poll(request: Request):
    host = agent_auth(request)
    if not host:
        return err("не авторизован", 401)
    hid = host["id"]
    db.x("UPDATE hosts SET last_seen=? WHERE id=?", (time.time(), hid))
    q = queue_for(hid)
    cmds = []
    try:
        cmds.append(await asyncio.wait_for(q.get(), POLL_TIMEOUT))
        while not q.empty() and len(cmds) < 20:
            cmds.append(q.get_nowait())
    except asyncio.TimeoutError:
        pass
    db.x("UPDATE hosts SET last_seen=? WHERE id=?", (time.time(), hid))
    return JSONResponse({"commands": cmds})


async def agent_report(request: Request):
    host = agent_auth(request)
    if not host:
        return err("не авторизован", 401)
    try:
        data = await body(request)
    except ValueError as e:
        return err(str(e))
    now = time.time()
    kind = data.get("kind")
    if kind == "posture":
        d = data.get("data")
        if not isinstance(d, dict) or len(json.dumps(d)) > 200_000:
            return err("некорректные данные")
        db.x("UPDATE hosts SET posture=?, posture_at=?, last_seen=?, agent_version=COALESCE(?,agent_version), os=COALESCE(?,os) WHERE id=?",
             (json.dumps(d, ensure_ascii=False), now, now, data.get("version"), data.get("os"), host["id"]))
        return JSONResponse({"ok": True})
    if kind == "metrics":
        d = data.get("data")
        if not isinstance(d, dict) or len(json.dumps(d)) > 4_000:
            return err("некорректные данные")
        db.x("UPDATE hosts SET metrics=?, metrics_at=?, last_seen=? WHERE id=?", (json.dumps(d), now, now, host["id"]))
        return JSONResponse({"ok": True})
    if kind == "software":
        d = data.get("data")
        if not isinstance(d, list) or len(d) > 20_000:
            return err("некорректные данные")
        clean = []
        for it in d:
            if isinstance(it, dict) and isinstance(it.get("n"), str):
                clean.append({"n": it["n"][:200], "v": str(it.get("v", ""))[:100],
                              "s": str(it.get("s", ""))[:20], "p": str(it.get("p", ""))[:300]})
        db.x("UPDATE hosts SET software=?, software_at=?, last_seen=? WHERE id=?",
             (json.dumps(clean, ensure_ascii=False), now, now, host["id"]))
        return JSONResponse({"ok": True, "count": len(clean)})
    return err("неизвестный тип отчёта")


async def index(request: Request):
    return FileResponse(os.path.join(STATIC, "index.html"))


async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store" if request.url.path.startswith(("/api", "/agent")) else "no-cache"
    return resp


from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware


@asynccontextmanager
async def lifespan(app):
    janitor = asyncio.create_task(term_janitor())
    r = db.ensure_admin()
    if r == "no-admin":
        print("HostDeck: пользователей нет. Задайте HOSTDECK_ADMIN_PASSWORD и перезапустите, чтобы создать администратора.", flush=True)
    yield
    janitor.cancel()


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/login", login, methods=["POST"]),
        Route("/api/logout", logout, methods=["POST"]),
        Route("/api/me", me),
        Route("/api/hosts", hosts_list),
        Route("/api/hosts/{id}", host_detail),
        Route("/api/hosts/{id}/refresh", host_refresh, methods=["POST"]),
        Route("/api/hosts/{id}/software", host_software),
        Route("/api/hosts/{id}/software/refresh", host_software_refresh, methods=["POST"]),
        Route("/api/hosts/{id}", host_delete, methods=["DELETE"]),
        Route("/api/enroll-tokens", token_create, methods=["POST"]),
        Route("/api/audit", audit_list),
        Route("/agent/enroll", agent_enroll, methods=["POST"]),
        Route("/agent/poll", agent_poll, methods=["POST"]),
        Route("/agent/report", agent_report, methods=["POST"]),
        Route("/agent/term", agent_term, methods=["POST"]),
        Route("/api/hosts/{id}/term", term_open, methods=["POST"]),
        Route("/api/term/{sid}/stream", term_stream),
        Route("/api/term/{sid}/input", term_input, methods=["POST"]),
        Route("/api/term/{sid}/resize", term_resize, methods=["POST"]),
        Route("/api/term/{sid}/close", term_close, methods=["POST"]),
        Mount("/static", StaticFiles(directory=STATIC), name="static"),
    ],
    middleware=[Middleware(BaseHTTPMiddleware, dispatch=security_headers)],
    lifespan=lifespan,
)
