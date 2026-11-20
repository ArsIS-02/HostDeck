"""Окна обслуживания HostDeck и их синхронизация с Zabbix."""
from __future__ import annotations

from datetime import datetime
import json
import math
import os
import ssl
import time
from urllib import request

MAX_MAINTENANCE_SEC = 366 * 86400
NAME_PREFIX = "HostDeck / "


def clean_reason(value) -> str:
    """Короткая причина без переводов строк: она попадёт в журнал и описание Zabbix."""
    reason = " ".join(str(value or "").split())
    if not 1 <= len(reason) <= 300:
        raise ValueError("причина обслуживания: от 1 до 300 символов")
    return reason


def normalize_until(value, now=None) -> int:
    """Принимает Unix timestamp или ISO 8601 с часовым поясом, возвращает секунды UTC."""
    now = time.time() if now is None else now
    if type(value) in (int, float):
        if not math.isfinite(value) or int(value) != value:
            raise ValueError("maintenance_until: целое число секунд UTC")
        ts = int(value)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            if text.isdigit():
                ts = int(text)
            else:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError("maintenance_until: укажите часовой пояс")
                ts = int(dt.timestamp())
        except (ValueError, OverflowError) as exc:
            raise ValueError("maintenance_until: Unix timestamp или ISO 8601") from exc
    else:
        raise ValueError("maintenance_until: Unix timestamp или ISO 8601")
    if ts < int(now) + 60:
        raise ValueError("окончание обслуживания должно быть минимум через минуту")
    if ts > int(now) + MAX_MAINTENANCE_SEC:
        raise ValueError("обслуживание нельзя назначить больше чем на 366 суток")
    return ts


def active_until(value, now=None) -> int | None:
    """Возвращает только ещё не истёкший срок; старое значение не считается активным."""
    now = time.time() if now is None else now
    try:
        ts = int(value or 0)
    except (TypeError, ValueError):
        return None
    return ts if ts > now else None


class ZabbixMaintenance:
    """Небольшой JSON-RPC клиент; управляет только объектами с NAME_PREFIX."""

    def __init__(self, api=None, token=None, ca_file=None, timeout=10):
        self.api = api if api is not None else os.environ.get("ZABBIX_API", "")
        self.ca_file = ca_file if ca_file is not None else os.environ.get("ZABBIX_CA_FILE", "")
        self.timeout = timeout
        token_file = os.environ.get("ZABBIX_TOKEN_FILE", "")
        if token is None and token_file:
            try:
                with open(token_file, encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError:
                token = ""
        self.token = token if token is not None else os.environ.get("ZABBIX_TOKEN", "")
        self.request_id = 0

    @property
    def enabled(self) -> bool:
        return bool(self.api and self.token)

    def call(self, method, params):
        if not self.enabled:
            raise RuntimeError("Zabbix не настроен")
        self.request_id += 1
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params,
                              "id": self.request_id}).encode()
        req = request.Request(self.api, data=payload, method="POST",
                              headers={"Content-Type": "application/json-rpc",
                                       "Authorization": "Bearer " + self.token})
        context = ssl.create_default_context(cafile=self.ca_file or None)
        with request.urlopen(req, timeout=self.timeout, context=context) as response:
            result = json.load(response)
        if "error" in result:
            error = result["error"]
            raise RuntimeError(f"{method}: {error.get('message')} {error.get('data', '')}".strip())
        return result["result"]

    def _host(self, host_name):
        candidates = self.call("host.get", {
            "output": ["hostid", "host", "name"],
            "search": {"host": host_name, "name": host_name}, "searchByAny": True,
        })
        wanted = host_name.casefold()
        exact = [h for h in candidates if wanted in (h["host"].casefold(), h["name"].casefold())]
        if len(exact) != 1:
            raise RuntimeError(f"в Zabbix ожидался один хост {host_name!r}, найдено: {len(exact)}")
        return exact[0]

    def sync(self, host_name, until, reason="", now=None):
        now = int(time.time() if now is None else now)
        host = self._host(host_name)
        name = NAME_PREFIX + host_name
        existing = self.call("maintenance.get", {
            "output": ["maintenanceid", "name"], "filter": {"name": name},
        })
        owned = [m for m in existing if m.get("name") == name]
        ids = [m["maintenanceid"] for m in owned]
        if until is None:
            if ids:
                self.call("maintenance.delete", ids)
            return {"status": "ok", "action": "cleared", "deleted": len(ids)}
        data = {
            "name": name, "maintenance_type": 0,
            "active_since": now - 60, "active_till": int(until),
            "description": "HostDeck: " + clean_reason(reason),
            "hosts": [{"hostid": host["hostid"]}], "groups": [], "tags": [],
            "timeperiods": [{"timeperiod_type": 0, "start_date": now,
                             "period": max(60, int(until) - now)}],
        }
        if owned:
            maintenance_id = ids[0]
            self.call("maintenance.update", dict(data, maintenanceid=maintenance_id))
            if len(ids) > 1:
                self.call("maintenance.delete", ids[1:])
            action = "updated"
        else:
            maintenance_id = self.call("maintenance.create", data)["maintenanceids"][0]
            action = "created"
        return {"status": "ok", "action": action, "maintenance_id": maintenance_id}


def sync_zabbix(host_name, until, reason=""):
    """Ошибка интеграции возвращается явно, но не отменяет сохранение состояния HostDeck."""
    client = ZabbixMaintenance()
    if not client.enabled:
        return {"status": "disabled"}
    try:
        return client.sync(host_name, until, reason)
    except Exception as exc:  # сеть, TLS и JSON-RPC: текст ошибки нужен оператору
        return {"status": "error", "error": str(exc)[:500]}
