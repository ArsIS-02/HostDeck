"""Проверки окон обслуживания и безопасной синхронизации с Zabbix."""
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
from app import host_maintenance as hm  # noqa: E402


class FakeZabbix(hm.ZabbixMaintenance):
    def __init__(self, hosts=None, existing=None):
        super().__init__(api="http://zabbix.example/api", token="test")
        self.hosts = hosts if hosts is not None else [
            {"hostid": "42", "host": "server.example", "name": "Server"}]
        self.existing = existing or []
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "host.get":
            return self.hosts
        if method == "maintenance.get":
            return self.existing
        if method == "maintenance.create":
            return {"maintenanceids": ["900"]}
        return []


class ValidationTests(unittest.TestCase):
    def test_timestamp_and_iso_are_normalized(self):
        now = 1_800_000_000
        self.assertEqual(hm.normalize_until(now + 3600, now), now + 3600)
        iso = hm.normalize_until("2027-01-16T00:00:00+00:00", now)
        self.assertIsInstance(iso, int)

    def test_past_naive_and_non_boolean_values_are_rejected(self):
        now = 1_800_000_000
        for value in (now, True, "2027-01-16T00:00:00", "not-a-date", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hm.normalize_until(value, now)

    def test_reason_is_required_and_single_line(self):
        self.assertEqual(hm.clean_reason("  плановое\nобновление  "), "плановое обновление")
        with self.assertRaises(ValueError):
            hm.clean_reason("   ")
        with self.assertRaises(ValueError):
            hm.clean_reason("x" * 301)

    def test_active_until_expires_automatically(self):
        now = 1_800_000_000
        self.assertEqual(hm.active_until(now + 1, now), now + 1)
        self.assertIsNone(hm.active_until(now, now))
        self.assertIsNone(hm.active_until("bad", now))


class ZabbixTests(unittest.TestCase):
    def test_create_uses_owned_name_host_and_active_till(self):
        zbx = FakeZabbix()
        result = zbx.sync("server.example", 1_800_003_600, "update", now=1_800_000_000)
        self.assertEqual(result["action"], "created")
        create = [c for c in zbx.calls if c[0] == "maintenance.create"][0][1]
        self.assertEqual(create["name"], "HostDeck / server.example")
        self.assertEqual(create["active_till"], 1_800_003_600)
        self.assertEqual(create["hosts"], [{"hostid": "42"}])

    def test_update_does_not_touch_unrelated_maintenance(self):
        zbx = FakeZabbix(existing=[
            {"maintenanceid": "901", "name": "HostDeck / server.example"},
            {"maintenanceid": "902", "name": "Manual / server.example"},
        ])
        result = zbx.sync("server.example", 1_800_003_600, "update", now=1_800_000_000)
        self.assertEqual(result["action"], "updated")
        update = [c for c in zbx.calls if c[0] == "maintenance.update"][0][1]
        self.assertEqual(update["maintenanceid"], "901")
        self.assertFalse([c for c in zbx.calls if c[0] == "maintenance.delete"])

    def test_clear_deletes_only_owned_window(self):
        zbx = FakeZabbix(existing=[
            {"maintenanceid": "901", "name": "HostDeck / server.example"}])
        result = zbx.sync("server.example", None)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(zbx.calls[-1], ("maintenance.delete", ["901"]))

    def test_ambiguous_host_is_an_error(self):
        zbx = FakeZabbix(hosts=[
            {"hostid": "1", "host": "server.example", "name": "one"},
            {"hostid": "2", "host": "server.example", "name": "two"},
        ])
        with self.assertRaises(RuntimeError):
            zbx.sync("server.example", None)

    def test_sync_error_is_returned_not_raised(self):
        with patch.object(hm.ZabbixMaintenance, "sync", side_effect=RuntimeError("unavailable")), \
                patch.dict(os.environ, {"ZABBIX_API": "http://zabbix.example/api", "ZABBIX_TOKEN": "test"}):
            result = hm.sync_zabbix("server.example", None)
        self.assertEqual(result["status"], "error")
        self.assertIn("unavailable", result["error"])


if __name__ == "__main__":
    unittest.main()
