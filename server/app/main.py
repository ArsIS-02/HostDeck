"""HostDeck: сервер инвентаризации и управления хостами (Starlette, без внешних зависимостей сверх requirements.txt)."""
import asyncio
import base64
import hashlib
import json
import re
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import db

STATIC = os.path.join(os.path.dirname(__file__), "static")
AGENT_DIR = os.environ.get("HOSTDECK_AGENT_DIR", "/agents")   # сюда образ кладёт собранные агенты
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+){1,3}([-+][0-9A-Za-z.]+)?$")
AGENT_FILE = re.compile(r"^hostdeck-agent-(darwin|linux)-(arm64|amd64)$")
CA_FILE = os.environ.get("HOSTDECK_CA_FILE", "")   # корневой сертификат внутреннего CA, если он есть (отдаётся хостам для установки)
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$")
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
HOST_SELECT = ("SELECT id,name,os,agent_version,last_seen,posture,posture_at,metrics,metrics_at,software_at,profile,"
               "CASE WHEN software IS NULL THEN NULL ELSE json_array_length(software) END AS software_count FROM hosts")
RANK = {"fail": 3, "warn": 2, "unknown": 1, "ok": 0, "info": 0, "na": 0}

# Профили хоста. У «сервера» пороги строгие (как есть). У остальных часть замечаний «warn» понижается до справки «info»:
# это не скрывает проверку, а убирает из итога то, что для такой роли нормально. «fail» профиль не смягчает никогда.
PROFILES = ("server", "laptop", "lab")
_LAPTOP = {"legacy_svc", "net_daemons", "update_channel", "internet_sharing", "sharing_screen", "sharing_remote", "airdrop",
           "lockout", "ports", "timemachine", "display_sleep", "screensaver"}
_LAB = _LAPTOP | {"ssh_hardening", "crypto_policy", "pw_policy", "sysctl", "tmp_mount", "log_forward", "integrity", "journal",
                  "audit_rules", "audit_state", "sudo_timeout", "sudo_nopasswd", "sharing_files"}
RELAX = {"server": set(), "laptop": _LAPTOP, "lab": _LAB}


def host_profile(row):
    p = row["profile"] if "profile" in row.keys() else None
    return p if p in PROFILES else "server"


def active_exceptions(hid, now=None):
    now = now or time.time()
    return {r["check_id"]: {"reason": r["reason"], "expires": r["expires"], "actor": r["actor"]}
            for r in db.q("SELECT check_id,reason,expires,actor FROM exceptions WHERE host_id=?", (hid,))
            if not r["expires"] or r["expires"] > now}


def effective_checks(checks, profile, exceptions):
    """Применяет профиль и исключения. Сырой статус сохраняется в raw_status."""
    out = []
    for c in checks:
        c = dict(c)
        c["raw_status"] = st = c.get("status", "unknown")
        ex = exceptions.get(c.get("id"))
        if ex and st in ("warn", "fail", "unknown"):
            c["status"], c["exception"] = "info", ex
        elif st == "warn" and c.get("id") in RELAX[profile]:
            c["status"], c["relaxed"] = "info", True
        out.append(c)
    return out


def compliance_index(checks):
    """Доля соответствия, 0–100. Считаются только проверки с определённым результатом: ok=1, warn=0.5, fail=0.
    Справочные, неприменимые, исключённые и «нет данных» в расчёт не входят. Если считать нечего — None."""
    n = tot = 0
    for c in checks:
        st = c.get("status")
        if c.get("exception") or c.get("relaxed") or st not in ("ok", "warn", "fail"):
            continue
        n += 1
        tot += {"ok": 1, "warn": 0.5, "fail": 0}[st]
    return round(100 * tot / n) if n else None

# --- история изменений ----------------------------------------------------------------------------------------------------------------
HISTORY_KEEP_DAYS = 400
HISTORY_MAX_ROWS = 2000      # на один хост
POINT_EVERY = 6 * 3600       # точка индекса пишется при изменении значения или не реже, чем раз в 6 часов


def record_history(hid, old, new, now):
    """Сохраняет смены сырого статуса проверок (то, что сообщил агент, без учёта профиля и исключений).
    Первый отчёт хоста и появление новой проверки (после обновления агента) сменой не считаются."""
    if not old:
        return
    prev = {c.get("id"): c for c in old.get("checks", []) if c.get("id")}
    for c in new.get("checks", []):
        cid, st = c.get("id"), c.get("status", "unknown")
        o = prev.get(cid)
        if not o or o.get("status") == st:
            continue
        db.x("INSERT INTO history(host_id,ts,check_id,from_status,to_status,value,detail) VALUES(?,?,?,?,?,?,?)",
             (hid, now, cid, o.get("status"), st, str(c.get("value") or "")[:60], str(c.get("detail") or "")[:200]))
    db.x("DELETE FROM history WHERE host_id=? AND (ts<? OR id NOT IN (SELECT id FROM history WHERE host_id=? ORDER BY id DESC LIMIT ?))",
         (hid, now - HISTORY_KEEP_DAYS * 86400, hid, HISTORY_MAX_ROWS))


def record_index_point(hid, posture, now):
    row = db.q1("SELECT profile FROM hosts WHERE id=?", (hid,))
    prof = host_profile(row) if row else "server"
    checks = effective_checks(posture.get("checks", []), prof, active_exceptions(hid, now))
    idx = compliance_index(checks)
    worst = "ok"
    for c in checks:
        if RANK.get(c.get("status", "unknown"), 1) > RANK.get(worst, 0):
            worst = c.get("status")
    last = db.q1("SELECT ts,idx,worst FROM idx_points WHERE host_id=? ORDER BY ts DESC LIMIT 1", (hid,))
    if last and last["idx"] == idx and last["worst"] == worst and now - last["ts"] < POINT_EVERY:
        return
    db.x("INSERT INTO idx_points(host_id,ts,idx,worst) VALUES(?,?,?,?)", (hid, now, idx, worst))
    db.x("DELETE FROM idx_points WHERE host_id=? AND ts<?", (hid, now - HISTORY_KEEP_DAYS * 86400))


def since_map(hid):
    """Для каждой проверки — когда она получила текущий статус (последняя смена в него)."""
    out = {}
    for r in db.q("SELECT check_id,to_status,ts FROM history WHERE host_id=? ORDER BY id", (hid,)):
        out[r["check_id"]] = (r["to_status"], r["ts"])
    return out

_latest = {"mtime": None, "v": None}


def agent_latest():
    """Версия агентов, лежащих на сервере (файл VERSION рядом с бинарниками; его пишет сборка образа)."""
    path = os.path.join(AGENT_DIR, "VERSION")
    try:
        mt = os.stat(path).st_mtime_ns
        if _latest["mtime"] != mt:
            with open(path, encoding="utf-8") as f:
                v = f.read().strip()
            _latest["mtime"], _latest["v"] = mt, (v if VERSION_RE.match(v) else None)
    except OSError:
        _latest["mtime"], _latest["v"] = None, None
    return _latest["v"]


def vtuple(v):
    try:
        return tuple(int(x) for x in str(v).split("-")[0].split("."))
    except ValueError:
        return None


def summarize(row, detail=False):
    now = time.time()
    online = bool(row["last_seen"]) and now - row["last_seen"] < ONLINE_WINDOW
    posture = json.loads(row["posture"]) if row["posture"] else None
    counts = {"ok": 0, "warn": 0, "fail": 0, "unknown": 0}
    worst = "unknown"
    profile = host_profile(row)
    exc = active_exceptions(row["id"], now)
    checks = effective_checks((posture or {}).get("checks", []), profile, exc) if posture else []
    if posture:
        worst = "ok"
        for c in checks:
            st = c.get("status", "unknown")
            if st in counts:
                counts[st] += 1
            if RANK.get(st, 1) > RANK.get(worst, 0):
                worst = st
        # отдельные проверки без данных не должны превращать в «нет данных» хост, у которого остальное в порядке
        if worst == "unknown" and counts["ok"] > 0:
            worst = "ok"
    out = {
        "id": row["id"], "name": row["name"], "os": row["os"], "agent_version": row["agent_version"],
        "online": online, "last_seen": row["last_seen"], "posture_at": row["posture_at"],
        "status": worst, "counts": counts, "profile": profile, "index": compliance_index(checks) if posture else None,
        "exceptions": len(exc),
        "info": (posture or {}).get("info", {}),
        "metrics": json.loads(row["metrics"]) if row["metrics"] else None,
        "metrics_at": row["metrics_at"],
        "software_at": row["software_at"],
        "software_count": row["software_count"],
    }
    latest = agent_latest()
    cur, lat = vtuple(row["agent_version"]), vtuple(latest) if latest else None
    out["agent_latest"] = latest
    out["update_available"] = bool(cur and lat and cur < lat)
    if detail:
        sm = since_map(row["id"])
        for c in checks:
            t = sm.get(c.get("id"))
            if t and t[0] == c.get("raw_status"):
                c["since"] = t[1]
        out["checks"] = checks
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


async def host_history(request: Request):
    u, e = need(request, "viewer")
    if e:
        return e
    hid = request.path_params["id"]
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    try:
        days = max(1, min(int(request.query_params.get("days", "90")), HISTORY_KEEP_DAYS))
    except ValueError:
        return err("days: число")
    since = time.time() - days * 86400
    changes = [{"ts": r["ts"], "check": r["check_id"], "from": r["from_status"], "to": r["to_status"], "value": r["value"], "detail": r["detail"]}
               for r in db.q("SELECT ts,check_id,from_status,to_status,value,detail FROM history WHERE host_id=? AND ts>=? ORDER BY ts DESC LIMIT 500", (hid, since))]
    points = [{"ts": r["ts"], "idx": r["idx"], "worst": r["worst"]}
              for r in db.q("SELECT ts,idx,worst FROM idx_points WHERE host_id=? AND ts>=? ORDER BY ts", (hid, since))]
    return JSONResponse({"days": days, "changes": changes, "points": points})


def _ids(data):
    ids = data.get("ids")
    if not isinstance(ids, list) or not ids or len(ids) > 500 or not all(isinstance(i, str) for i in ids):
        return None
    return [i for i in dict.fromkeys(ids) if db.q1("SELECT 1 FROM hosts WHERE id=?", (i,))]


def _exc_args(data):
    """Проверка параметров исключения. Возвращает (check, reason, days, expires) или текст ошибки."""
    cid, reason = str(data.get("check") or "").strip(), str(data.get("reason") or "").strip()
    if not re.fullmatch(r"[a-z0-9_]{1,40}", cid):
        return "не указана проверка"
    if not (3 <= len(reason) <= 300):
        return "причина обязательна (от 3 до 300 знаков)"
    days = data.get("days")
    if days in (None, "", 0):
        return cid, reason, None, None
    try:
        days = int(days)
    except (TypeError, ValueError):
        return "срок должен быть числом дней"
    if not 1 <= days <= 3650:
        return "срок от 1 до 3650 дней"
    return cid, reason, days, time.time() + days * 86400


async def hosts_profile_many(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    prof, ids = data.get("profile"), _ids(data)
    if prof not in PROFILES:
        return err("профиль: server, laptop или lab")
    if ids is None:
        return err("нужен список ids")
    for hid in ids:
        db.x("UPDATE hosts SET profile=? WHERE id=?", (prof, hid))
        db.audit(u["name"], "profile-set", host=hid, detail=prof)
    return JSONResponse({"updated": len(ids)})


async def hosts_exception_many(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    ids = _ids(data)
    if ids is None:
        return err("нужен список ids")
    a = _exc_args(data)
    if isinstance(a, str):
        return err(a)
    cid, reason, days, expires = a
    for hid in ids:
        db.x("INSERT OR REPLACE INTO exceptions(host_id,check_id,reason,expires,actor,created) VALUES(?,?,?,?,?,?)",
             (hid, cid, reason, expires, u["name"], time.time()))
        db.audit(u["name"], "exception-set", host=hid, detail=f"{cid}: {reason}" + (f" (дней: {days})" if expires else ""))
    return JSONResponse({"updated": len(ids)})


async def exceptions_list(request: Request):
    """Исключения, срок которых истекает в ближайшие N дней, и недавно истёкшие (они уже не действуют)."""
    u, e = need(request, "viewer")
    if e:
        return e
    try:
        days = max(1, min(int(request.query_params.get("days", "7")), 365))
    except ValueError:
        return err("days: число")
    now = time.time()
    rows = db.q("SELECT x.host_id,h.name,x.check_id,x.reason,x.expires FROM exceptions x JOIN hosts h ON h.id=x.host_id "
                "WHERE x.expires IS NOT NULL AND x.expires<? AND x.expires>? ORDER BY x.expires", (now + days * 86400, now - 14 * 86400))
    return JSONResponse([{"host_id": r["host_id"], "host": r["name"], "check": r["check_id"], "reason": r["reason"], "expires": r["expires"], "expired": r["expires"] <= now} for r in rows])


async def host_profile_set(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    hid = request.path_params["id"]
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    prof = data.get("profile")
    if prof not in PROFILES:
        return err("профиль: server, laptop или lab")
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    db.x("UPDATE hosts SET profile=? WHERE id=?", (prof, hid))
    db.audit(u["name"], "profile-set", host=hid, detail=prof)
    return JSONResponse({"profile": prof})


async def exception_set(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    hid = request.path_params["id"]
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    a = _exc_args(data)
    if isinstance(a, str):
        return err(a)
    cid, reason, days, expires = a
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    db.x("INSERT OR REPLACE INTO exceptions(host_id,check_id,reason,expires,actor,created) VALUES(?,?,?,?,?,?)",
         (hid, cid, reason, expires, u["name"], time.time()))
    db.audit(u["name"], "exception-set", host=hid, detail=f"{cid}: {reason}" + (f" (дней: {days})" if expires else ""))
    return JSONResponse({"ok": True})


async def exception_delete(request: Request):
    u, e = need(request, "operator")
    if e:
        return e
    hid, cid = request.path_params["id"], request.path_params["check"]
    db.x("DELETE FROM exceptions WHERE host_id=? AND check_id=?", (hid, cid))
    db.audit(u["name"], "exception-removed", host=hid, detail=cid)
    return JSONResponse({"ok": True})


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


async def queue_update(u, hid):
    """Ставит хосту команду обновления агента. Возвращает причину отказа или None."""
    row = db.q1(HOST_SELECT + " WHERE id=?", (hid,))
    if not row:
        return "not_found"
    if summarize(row)["info"].get("auto_update") != "on":
        return "disabled"
    await queue_for(hid).put({"id": secrets.token_hex(4), "type": "update"})
    db.audit(u["name"], "agent-update", host=hid, detail=row["agent_version"] or "")
    return None


async def host_update(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    why = await queue_update(u, request.path_params["id"])
    if why == "not_found":
        return err("хост не найден", 404)
    if why == "disabled":
        return err("обновление из веб-интерфейса не разрешено на этом хосте (агент установлен без autoupdate)", 409)
    return JSONResponse({"queued": True})


async def hosts_update_many(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    ids = data.get("ids")
    if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(i, str) for i in ids):
        return err("нужен список идентификаторов хостов (до 200)")
    queued, skipped = 0, []
    for hid in dict.fromkeys(ids):
        why = await queue_update(u, hid)
        if why is None:
            queued += 1
        else:
            skipped.append({"id": hid, "reason": why})
    return JSONResponse({"queued": queued, "skipped": skipped})


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


async def close_host_terms(hid):
    """Закрывает открытые консольные сессии хоста (его агент после удаления всё равно перестанет подключаться)."""
    for t in [t for t in terms.values() if t.host_id == hid and not t.closed]:
        try:
            await t.finish(error="хост удалён")
        except Exception:  # noqa: BLE001 — удаление хоста важнее аккуратного закрытия сессии
            pass


async def delete_hosts(user, ids):
    """Удаляет хосты из базы вместе со всеми собранными данными (состояние, ПО, метрики, ключ агента). Возвращает число удалённых."""
    n = 0
    for hid in ids:
        row = db.q1("SELECT id,name FROM hosts WHERE id=?", (hid,))
        if not row:
            continue
        await close_host_terms(hid)
        db.audit(user["name"], "host-deleted", host=hid, host_name=row["name"])
        db.x("DELETE FROM hosts WHERE id=?", (hid,))
        db.x("DELETE FROM exceptions WHERE host_id=?", (hid,))
        db.x("DELETE FROM history WHERE host_id=?", (hid,))
        db.x("DELETE FROM idx_points WHERE host_id=?", (hid,))
        queues.pop(hid, None)
        n += 1
    return n


async def host_delete(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    hid = request.path_params["id"]
    if not db.q1("SELECT 1 FROM hosts WHERE id=?", (hid,)):
        return err("хост не найден", 404)
    n = await delete_hosts(u, [hid])
    return JSONResponse({"ok": True, "deleted": n})


async def hosts_delete_many(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    try:
        data = await body(request)
    except ValueError as ex:
        return err(str(ex))
    ids = data.get("ids")
    if not isinstance(ids, list) or not ids or len(ids) > 200 or not all(isinstance(i, str) for i in ids):
        return err("нужен список идентификаторов хостов (до 200)")
    n = await delete_hosts(u, list(dict.fromkeys(ids)))
    return JSONResponse({"ok": True, "deleted": n})


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
    script = render_install(request)
    return JSONResponse({"token": tok, "expires": now + ENROLL_TTL, "ca_sha256": ca_sha256() if CA_FILE else None,
                         "install_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest() if script else None})


async def audit_list(request: Request):
    u, e = need(request, "admin")
    if e:
        return e
    try:
        limit = max(1, min(1000, int(request.query_params.get("limit", 200))))
    except ValueError:
        limit = 200
    rows = db.q("SELECT a.id,a.ts,a.actor,a.host,COALESCE(a.host_name,h.name) AS host_name,a.action,a.detail "
                "FROM audit a LEFT JOIN hosts h ON h.id=a.host ORDER BY a.id DESC LIMIT ?", (limit + 1,))
    return JSONResponse({"rows": [dict(r) for r in rows[:limit]], "more": len(rows) > limit})


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
    # Ждём команду, но следим за соединением: если агент перезапустился (например, после обновления), его старый запрос
    # остаётся висеть до таймаута и не должен перехватить команду, которая предназначена уже новому процессу.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + POLL_TIMEOUT
    getter = asyncio.ensure_future(q.get())
    try:
        while not getter.done():
            left = deadline - loop.time()
            if left <= 0:
                break
            await asyncio.wait({getter}, timeout=min(1.0, left))
            if not getter.done() and await request.is_disconnected():
                break
    except BaseException:
        # обработчик отменён: команду, которую успели достать из очереди, возвращаем
        if getter.done() and not getter.cancelled():
            q.put_nowait(getter.result())
        raise
    finally:
        if not getter.done():
            getter.cancel()
    if getter.done() and not getter.cancelled():
        first = getter.result()
        if await request.is_disconnected():
            q.put_nowait(first)   # получателя уже нет: вернуть команду в очередь
            return JSONResponse({"commands": []})
        cmds.append(first)
        while not q.empty() and len(cmds) < 20:
            cmds.append(q.get_nowait())
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
        new_v = str(data.get("version") or "")[:40]
        if new_v and host["agent_version"] and new_v != host["agent_version"]:
            db.audit("agent", "agent-updated", host=host["id"], detail=f"{host['agent_version']} → {new_v}")
        prev = db.q1("SELECT posture FROM hosts WHERE id=?", (host["id"],))
        record_history(host["id"], json.loads(prev["posture"]) if prev and prev["posture"] else None, d, now)
        db.x("UPDATE hosts SET posture=?, posture_at=?, last_seen=?, agent_version=COALESCE(?,agent_version), os=COALESCE(?,os) WHERE id=?",
             (json.dumps(d, ensure_ascii=False), now, now, data.get("version"), data.get("os"), host["id"]))
        record_index_point(host["id"], d, now)
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
    if kind == "event":
        ev = str(data.get("event", ""))
        if ev in ("update-failed", "update-current"):
            db.audit("agent", "agent-" + ev, host=host["id"], detail=str(data.get("message", ""))[:300])
            return JSONResponse({"ok": True})
    return err("неизвестный тип отчёта")


# --- установка агента: скрипт и бинарники отдаёт сам сервер -------------------
def render_install(request: Request):
    host = request.headers.get("host", "")
    if not HOST_RE.match(host):
        return None
    with open(os.path.join(os.path.dirname(__file__), "install.sh"), encoding="utf-8") as f:
        text = f.read()
    return text.replace("@@SERVER@@", f"{request.url.scheme}://{host}").replace("@@SUMS@@", agent_sums().rstrip("\n"))


async def install_script(request: Request):
    text = render_install(request)
    if text is None:
        return PlainTextResponse("некорректный заголовок Host\n", status_code=400)
    return PlainTextResponse(text, media_type="text/x-shellscript; charset=utf-8")


_sums = {"key": None, "text": ""}


def agent_sums():
    try:
        names = sorted(n for n in os.listdir(AGENT_DIR) if AGENT_FILE.match(n))
    except OSError:
        return ""
    key = tuple((n, os.stat(os.path.join(AGENT_DIR, n)).st_mtime_ns) for n in names)
    if key != _sums["key"]:
        lines = []
        for n in names:
            h = hashlib.sha256()
            with open(os.path.join(AGENT_DIR, n), "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            lines.append(f"{h.hexdigest()}  {n}")
        _sums["key"], _sums["text"] = key, "\n".join(lines) + ("\n" if lines else "")
    return _sums["text"]


def ca_sha256():
    """SHA-256 файла сертификата ровно в том виде, в каком его скачает хост (sha256sum файла)."""
    try:
        with open(CA_FILE, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


async def ca_pem(request: Request):
    if not CA_FILE or not ca_sha256():
        return err("сертификат CA не настроен", 404)
    return FileResponse(CA_FILE, media_type="application/x-pem-file", filename="hostdeck-ca.pem")


async def download(request: Request):
    name = request.path_params["name"]
    if name == "SHA256SUMS":
        text = agent_sums()
        return PlainTextResponse(text) if text else err("агенты не найдены на сервере", 404)
    if not AGENT_FILE.match(name):
        return err("файл не найден", 404)
    path = os.path.join(AGENT_DIR, name)
    if not os.path.isfile(path):
        return err("файл не найден", 404)
    return FileResponse(path, media_type="application/octet-stream", filename=name)


async def os_logos(request: Request):
    """Какие собственные значки ОС положены в static/os (чтобы браузер не стучался за отсутствующими файлами)."""
    found = {}
    for base in ("apple", "tux"):
        for ext in ("svg", "png"):
            if os.path.isfile(os.path.join(STATIC, "os", f"{base}.{ext}")):
                found[base] = f"/static/os/{base}.{ext}"
                break
    return JSONResponse(found)


async def index(request: Request):
    return FileResponse(os.path.join(STATIC, "index.html"))


class SecurityHeaders:
    """Заголовки безопасности. Чистый ASGI-слой, а не BaseHTTPMiddleware: тот скрывает от обработчиков разрыв соединения
    (request.is_disconnected()), а он нужен длинному опросу агентов."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")

        async def send_wrap(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in
                           (b"content-security-policy", b"x-content-type-options", b"referrer-policy", b"cache-control")]
                headers += [
                    (b"content-security-policy", b"default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store" if path.startswith(("/api", "/agent")) else b"no-cache"),
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrap)


from starlette.middleware import Middleware


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
        Route("/api/hosts/{id}/history", host_history),
        Route("/api/hosts/{id}/profile", host_profile_set, methods=["POST"]),
        Route("/api/hosts/{id}/exceptions", exception_set, methods=["POST"]),
        Route("/api/hosts/{id}/exceptions/{check}", exception_delete, methods=["DELETE"]),
        Route("/api/hosts/{id}/software", host_software),
        Route("/api/hosts/{id}/software/refresh", host_software_refresh, methods=["POST"]),
        Route("/api/hosts/{id}", host_delete, methods=["DELETE"]),
        Route("/api/enroll-tokens", token_create, methods=["POST"]),
        Route("/api/audit", audit_list),
        Route("/api/hosts/delete", hosts_delete_many, methods=["POST"]),
        Route("/api/hosts/profile", hosts_profile_many, methods=["POST"]),
        Route("/api/hosts/exceptions", hosts_exception_many, methods=["POST"]),
        Route("/api/exceptions", exceptions_list),
        Route("/api/hosts/update", hosts_update_many, methods=["POST"]),
        Route("/api/hosts/{id}/update", host_update, methods=["POST"]),
        Route("/api/os-logos", os_logos),
        Route("/install.sh", install_script),
        Route("/dl/{name}", download),
        Route("/ca.pem", ca_pem),
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
    middleware=[Middleware(SecurityHeaders)],
    lifespan=lifespan,
)
