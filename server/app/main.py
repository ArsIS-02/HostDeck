"""HostDeck: сервер инвентаризации и управления хостами (Starlette, без внешних зависимостей сверх requirements.txt)."""
import asyncio
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
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
    r = db.ensure_admin()
    if r == "no-admin":
        print("HostDeck: пользователей нет. Задайте HOSTDECK_ADMIN_PASSWORD и перезапустите, чтобы создать администратора.", flush=True)
    yield


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
        Mount("/static", StaticFiles(directory=STATIC), name="static"),
    ],
    middleware=[Middleware(BaseHTTPMiddleware, dispatch=security_headers)],
    lifespan=lifespan,
)
