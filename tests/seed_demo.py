"""Заполняет базу демонстрационными хостами (для скриншотов и ручной проверки интерфейса).
Запуск: HOSTDECK_DB=/путь/demo.db python3 tests/seed_demo.py"""
import json, os, random, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))
from app import db

random.seed(7)
now = time.time()


def checks(**ov):
    base = {"filevault": ("ok", "on"), "sip": ("ok", "on"), "gatekeeper": ("ok", "on"), "firewall": ("ok", "on"),
            "stealth": ("warn", "off"), "auto_check": ("ok", "on"), "auto_critical": ("ok", "on"),
            "screenlock": ("ok", "immediate"), "ssh": ("info", "off"), "mdm": ("info", "No enrollment")}
    base.update(ov)
    out = [{"id": k, "status": s, "value": v} for k, (s, v) in base.items()]
    out.append({"id": "updates", "status": "ok", "value": "none", "num": now - 3600})
    out.append({"id": "disk", "status": "ok", "value": "used", "num": 42.0, "detail": "276.0"})
    return out


APPS = [("Safari", "18.1", "app", "/Applications/Safari.app"), ("Xcode", "16.1", "app", "/Applications/Xcode.app"),
        ("Visual Studio Code", "1.95.2", "app", "/Applications/Visual Studio Code.app"), ("Telegram", "11.2", "app", "/Applications/Telegram.app"),
        ("Docker", "4.35.1", "app", "/Applications/Docker.app"), ("git", "2.47.0", "brew", "/opt/homebrew/Cellar/git"),
        ("go", "1.23.3", "brew", "/opt/homebrew/Cellar/go"), ("python@3.12", "3.12.7", "brew", "/opt/homebrew/Cellar/python@3.12"),
        ("iterm2", "3.5.10", "cask", "/opt/homebrew/Caskroom/iterm2"), ("wireshark", "4.4.1", "cask", "/opt/homebrew/Caskroom/wireshark")]

HOSTS = [
    ("MacMiniM2", "MacBook" and "Macmini9,1", "Apple M2", "16 GB", "15.1", "ok", dict(cpu=14, mu=0.46, disk=42, bat=-1)),
    ("MacBookPro", "MacBookPro18,3", "Apple M1 Pro", "32 GB", "15.1", "warn", dict(cpu=37, mu=0.71, disk=63, bat=82)),
    ("MacBookPro-M4Pro", "Mac16,7", "Apple M4 Pro", "48 GB", "15.1", "fail", dict(cpu=88, mu=0.93, disk=91, bat=23)),
    ("homeserver", "", "ARM Cortex-A72", "8 GB", "Debian 12", "ok", dict(cpu=6, mu=0.28, disk=35, bat=-1)),
]
for i, (name, model, chip, mem, ver, st, m) in enumerate(HOSTS):
    hid = "demo%02d" % i
    mac = bool(model)
    ck = checks()
    if st == "warn":
        ck = checks(filevault=("ok", "on"), stealth=("warn", "off"))
        ck = [c for c in ck if c["id"] != "updates"] + [{"id": "updates", "status": "warn", "value": "available", "num": 2, "detail": "macOS Sequoia 15.1.1; Safari 18.1.1"}]
    if st == "fail":
        ck = checks(filevault=("fail", "off"), firewall=("fail", "off"), screenlock=("warn", "after:3600"))
        for c in ck:
            if c["id"] == "disk":
                c.update(status="fail", num=91.0, detail="43.0")
    posture = {"collected_at": now, "info": {"os": "macOS" if mac else "linux", "os_version": ver, "model": model or "Raspberry Pi 4B", "chip": chip,
               "memory": mem, "arch": "arm64", "hostname": name, "agent": "0.2.0", "boot_time": str(int(now - 86400 * (3 + i))), "console_user": "arsentyev" if mac else ""},
               "checks": ck if mac else [{"id": "platform", "status": "info", "value": "mac_only"}, ck[-1]]}
    tot = float(mem.split()[0]) * 2**30
    metrics = {"at": now, "cpu": m["cpu"], "load1": m["cpu"] / 100 * 8, "cores": 8, "mem_used": tot * m["mu"], "mem_total": tot, "swap_pct": 12 * i,
               "disk_pct": m["disk"], "disk_total": 494e9, "disk_free": 494e9 * (1 - m["disk"] / 100), "battery": m["bat"], "battery_chrg": i == 1}
    sw = [{"n": a, "v": v, "s": s, "p": p} for a, v, s, p in APPS] if mac else [{"n": "nginx", "v": "1.22.1", "s": "pkg", "p": ""}, {"n": "zabbix-server-mysql", "v": "6.4.21", "s": "pkg", "p": ""}]
    seen = now - (5 if i != 3 else 3600 * 5)
    db.x("INSERT OR REPLACE INTO hosts(id,name,os,agent_version,key_hash,created,last_seen,posture,posture_at,software,software_at,metrics,metrics_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (hid, name, posture["info"]["os"], "0.2.0", "x", now - 86400 * 9, seen, json.dumps(posture), seen, json.dumps(sw), seen, json.dumps(metrics), seen))
print("ok")
