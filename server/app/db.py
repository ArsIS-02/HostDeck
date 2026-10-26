"""SQLite-хранилище HostDeck (без внешних зависимостей)."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time

DB_PATH = os.environ.get("HOSTDECK_DB", "/data/hostdeck.db")
_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS enroll_tokens(
  token_hash TEXT PRIMARY KEY, label TEXT, created REAL NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS hosts(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT, agent_version TEXT, key_hash TEXT NOT NULL,
  created REAL NOT NULL, last_seen REAL, posture TEXT, posture_at REAL, software TEXT, software_at REAL);
CREATE TABLE IF NOT EXISTS exceptions(
  host_id TEXT NOT NULL, check_id TEXT NOT NULL, reason TEXT NOT NULL, expires REAL, actor TEXT, created REAL NOT NULL,
  PRIMARY KEY(host_id, check_id));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT, host TEXT, action TEXT NOT NULL, detail TEXT);
"""


def conn():
    global _conn
    with _lock:
        if _conn is None:
            os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
            _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.executescript(SCHEMA)
            acols = {r[1] for r in _conn.execute("PRAGMA table_info(audit)")}
            if "host_name" not in acols:  # имя хоста хранится в записи журнала, чтобы после удаления хоста история оставалась читаемой
                _conn.execute("ALTER TABLE audit ADD COLUMN host_name TEXT")
            cols = {r[1] for r in _conn.execute("PRAGMA table_info(hosts)")}
            for col, typ in (("metrics", "TEXT"), ("metrics_at", "REAL"), ("profile", "TEXT")):  # миграция баз этапа 1
                if col not in cols:
                    _conn.execute(f"ALTER TABLE hosts ADD COLUMN {col} {typ}")
        return _conn


def q(sql, args=()):
    with _lock:
        return conn().execute(sql, args).fetchall()


def q1(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def x(sql, args=()):
    with _lock:
        return conn().execute(sql, args)


def reset_for_tests(path):
    global _conn, DB_PATH
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
        DB_PATH = path


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + salt.hex() + "$" + h.hex()


def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


def audit(actor, action, host=None, detail=None, host_name=None):
    if host and not host_name:
        row = q1("SELECT name FROM hosts WHERE id=?", (host,))
        host_name = row["name"] if row else None
    x("INSERT INTO audit(ts,actor,host,host_name,action,detail) VALUES(?,?,?,?,?,?)",
      (time.time(), actor, host, host_name, action, detail))


def ensure_admin():
    """Создаёт первого администратора из HOSTDECK_ADMIN_PASSWORD (только если пользователей нет)."""
    if q1("SELECT 1 FROM users LIMIT 1"):
        return None
    pw = os.environ.get("HOSTDECK_ADMIN_PASSWORD")
    pw_file = os.environ.get("HOSTDECK_ADMIN_PASSWORD_FILE")  # для podman/docker secret
    if not pw and pw_file:
        try:
            with open(pw_file, encoding="utf-8") as f:
                pw = f.read().strip()
        except OSError:
            return "no-admin"
    if not pw:
        return "no-admin"
    name = os.environ.get("HOSTDECK_ADMIN_USER", "admin")
    x("INSERT INTO users(name,pw_hash,role,created) VALUES(?,?,?,?)", (name, hash_password(pw), "admin", time.time()))
    audit("system", "admin-created", detail=name)
    return "created"
