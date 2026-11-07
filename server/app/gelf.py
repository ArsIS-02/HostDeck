"""Оповещения HostDeck в Graylog по GELF (UDP или TCP): смена статуса проверок и журнал действий.
Только стандартная библиотека.

Включается переменными окружения:
    HOSTDECK_GELF_HOST   адрес входа GELF (пусто — отправка выключена)
    HOSTDECK_GELF_PORT   порт, по умолчанию 12201
    HOSTDECK_GELF_PROTO  udp (по умолчанию) или tcp
    HOSTDECK_GELF_SOURCE поле source в Graylog, по умолчанию hostdeck

Сообщения уходят из фонового потока через очередь: недоступный Graylog не задерживает приём отчётов
агентов, а история и журнал в базе остаются полными.
"""
import json
import logging
import os
import queue
import socket
import struct
import threading
import time
import zlib

log = logging.getLogger("hostdeck.gelf")

CHUNK = 8000          # полезная нагрузка UDP-части, с запасом под MTU и заголовок 12 байт
MAX_CHUNKS = 128      # предел GELF
QUEUE_MAX = 1000


def udp_packets(payload, chunk=CHUNK):
    """Готовые UDP-датаграммы: одна, если влезает, иначе части с заголовком 0x1e 0x0f."""
    data = zlib.compress(payload)
    if len(data) <= chunk:
        return [data]
    parts = [data[i:i + chunk] for i in range(0, len(data), chunk)]
    if len(parts) > MAX_CHUNKS:
        raise ValueError("GELF: сообщение слишком большое (%d частей)" % len(parts))
    mid = os.urandom(8)
    return [b"\x1e\x0f" + mid + struct.pack("BB", i, len(parts)) + p for i, p in enumerate(parts)]


def message(short, fields, source, level=6, ts=None):
    """Словарь GELF 1.1: свои поля получают префикс «_», пустые значения не отправляются."""
    msg = {"version": "1.1", "host": source, "short_message": str(short)[:1000] or "-",
           "timestamp": round(ts if ts is not None else time.time(), 3), "level": int(level)}
    for k, v in fields.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, (list, tuple, set)):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = json.dumps(v, ensure_ascii=False, sort_keys=True)
        key = "_" + "".join(c if c.isalnum() or c == "_" else "_" for c in str(k))
        if key in ("_id", "_source"):
            key = "_f" + key
        msg[key] = v
    return msg


class Sender:
    def __init__(self, host, port=12201, proto="udp", source="hostdeck", timeout=2.0):
        self.host, self.port = host, int(port)
        self.proto = (proto or "udp").lower()
        self.source = source or "hostdeck"
        self.timeout = timeout
        self.status = {"sent": 0, "errors": 0, "last_ok": None, "last_error": ""}
        self._q = queue.Queue(QUEUE_MAX)
        self._t = None

    @classmethod
    def from_env(cls, env=os.environ):
        host = (env.get("HOSTDECK_GELF_HOST") or "").strip()
        if not host:
            return None
        try:
            port = int(env.get("HOSTDECK_GELF_PORT") or 12201)
        except ValueError:
            port = 12201
        return cls(host, port, env.get("HOSTDECK_GELF_PROTO") or "udp", env.get("HOSTDECK_GELF_SOURCE") or "hostdeck")

    def send_now(self, msg):
        """Отправить сразу, в вызывающем потоке. Ошибки сети поднимаются наверх."""
        raw = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        if self.proto == "tcp":
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(raw + b"\0")
        else:
            infos = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_DGRAM)
            fam, _, _, _, addr = infos[0]
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                for p in udp_packets(raw):
                    s.sendto(p, addr)

    def submit(self, short, fields, level=6, ts=None):
        """Поставить сообщение в очередь фонового потока. Никогда не бросает исключений."""
        try:
            self._q.put_nowait(message(short, fields, self.source, level, ts))
        except queue.Full:
            self.status["errors"] += 1
            self.status["last_error"] = "очередь переполнена"
            return
        if self._t is None or not self._t.is_alive():
            self._t = threading.Thread(target=self._run, name="hostdeck-gelf", daemon=True)
            self._t.start()

    def _run(self):
        while True:
            msg = self._q.get()
            try:
                self.send_now(msg)
                self.status["sent"] += 1
                self.status["last_ok"] = time.time()
            except (OSError, ValueError) as e:
                self.status["errors"] += 1
                self.status["last_error"] = str(e)
                log.warning("GELF %s:%s: %s", self.host, self.port, e)
            finally:
                self._q.task_done()

    def flush(self, timeout=5.0):
        """Дождаться отправки очереди (для тестов и остановки)."""
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:
            time.sleep(0.02)


# ---------- что уходит в Graylog ----------

SENDER = Sender.from_env()


def reset(new=None):
    """Для тестов: подставить своего отправителя."""
    global SENDER
    SENDER = new


# syslog: 3 — error, 4 — warning, 5 — notice, 6 — info
STATUS_LEVEL = {"fail": 3, "warn": 4, "unknown": 5}
WARN_ACTIONS = {"login-failed", "term-open", "term-denied", "exception-set", "host-deleted", "enrolled",
                "enroll-rejected", "enroll-token-created", "backup-download", "agent-update"}
INFO_ACTIONS = {"login", "refresh", "software-refresh", "backup-check", "term-closed"}


def check_changed(host, check, old_status, effective, profile, exception=None):
    """Проверка на хосте сменила сырой статус. effective — статус с учётом профиля и исключений:
    по нему строятся алерты (исключённое и смягчённое профилем приходит, но с уровнем info)."""
    s = SENDER
    if not s:
        return
    new = check.get("status", "unknown")
    level = STATUS_LEVEL.get(effective, 6)
    s.submit("HostDeck: %s — %s: %s → %s" % (host.get("name", ""), check.get("id", ""), old_status or "—", new),
             {"hd_source": "hostdeck", "homelab_app": "hostdeck", "hd_event": "check_changed",
              "hd_host": host.get("name", ""), "hd_host_id": host.get("id", ""), "hd_os": host.get("os") or "",
              "hd_profile": profile or "", "hd_check": check.get("id", ""), "hd_from": old_status or "",
              "hd_to": new, "hd_effective": effective, "hd_value": str(check.get("value") or "")[:120],
              "hd_detail": str(check.get("detail") or "")[:500],
              "hd_exception": (exception or {}).get("reason", "") if exception else "",
              "hd_recovered": new == "ok" and old_status in ("warn", "fail")}, level)


def audit(actor, action, host_id=None, host_name=None, detail=None):
    s = SENDER
    if not s:
        return
    try:
        s.submit("HostDeck: %s — %s%s" % (action, actor or "?", " — " + host_name if host_name else ""),
                 {"hd_source": "hostdeck", "homelab_app": "hostdeck", "hd_event": "audit", "hd_action": action,
                  "hd_actor": actor or "", "hd_host": host_name or "", "hd_host_id": host_id or "",
                  "hd_detail": str(detail or "")[:1000]},
                 4 if action in WARN_ACTIONS else (6 if action in INFO_ACTIONS else 5))
    except Exception as e:  # noqa: BLE001
        log.warning("GELF: запись журнала не отправлена: %s", e)
