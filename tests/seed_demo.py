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
    out.append({"id": "timemachine", "status": "warn", "value": "backup_at", "num": now - 9 * 86400})
    out.append({"id": "admins", "status": "ok", "value": "admins", "num": 1, "detail": "demo"})
    out.append({"id": "airdrop", "status": "ok", "value": "contacts"})
    out.append({"id": "xprotect", "status": "ok", "value": "updated_at", "num": now - 5 * 86400, "detail": "v5311"})
    out.append({"id": "disk", "status": "ok", "value": "used", "num": 42.0, "detail": "276.0"})
    return out


APPS = [("Safari", "18.1", "app", "/Applications/Safari.app"), ("Xcode", "16.1", "app", "/Applications/Xcode.app"),
        ("Visual Studio Code", "1.95.2", "app", "/Applications/Visual Studio Code.app"), ("Telegram", "11.2", "app", "/Applications/Telegram.app"),
        ("Docker", "4.35.1", "app", "/Applications/Docker.app"), ("git", "2.47.0", "brew", "/opt/homebrew/Cellar/git"),
        ("go", "1.23.3", "brew", "/opt/homebrew/Cellar/go"), ("python@3.12", "3.12.7", "brew", "/opt/homebrew/Cellar/python@3.12"),
        ("iterm2", "3.5.10", "cask", "/opt/homebrew/Caskroom/iterm2"), ("wireshark", "4.4.1", "cask", "/opt/homebrew/Caskroom/wireshark")]

NETHOSTS = (0, 1, 3)  # хосты со включённым сбором для сетевой карты
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
               "memory": mem, "arch": "arm64", "hostname": name, "agent": "0.2.0", "boot_time": str(int(now - 86400 * (3 + i))), "console_user": "demo" if mac else "", **({"auto_update": "on"} if i != 3 else {"containers_mgmt": "on"}), **({"network": "on"} if i in NETHOSTS else {})},
               "checks": ck if mac else [{"id": "platform", "status": "info", "value": "mac_only"}, ck[-1]]}
    if i == 3:  # у homeserver есть контейнеры: рабочие, упавший и дубликат в Docker
        posture["containers"] = [
            {"id": "a1b2c3d4e111", "unit": "caddy.service", "name": "caddy", "image": "docker.io/library/caddy:2.8", "runtime": "podman", "owner": "redos", "state": "running", "restart": "always", "health": "healthy", "ports": ["0.0.0.0:80->80/tcp", "0.0.0.0:443->443/tcp"], "started": int(now - 10 * 86400)},
            {"id": "a1b2c3d4e222", "name": "atrium", "image": "localhost/atrium:1.0.0", "runtime": "podman", "owner": "redos", "state": "running", "restart": "always", "ports": ["0.0.0.0:5000->5000/tcp"], "started": int(now - 43 * 3600)},
            {"id": "a1b2c3d4e333", "name": "myhomelab-v6-old", "image": "localhost/myhomelab:v6", "runtime": "podman", "owner": "redos", "state": "exited", "exit": 137, "restart": "always", "ports": ["0.0.0.0:5000->5000/tcp"]},
            {"id": "a1b2c3d4e444", "name": "logatlas", "image": "localhost/logatlas:latest", "runtime": "podman", "state": "running", "restart": "unless-stopped", "health": "healthy", "started": int(now - 3 * 86400)},
            {"id": "a1b2c3d4e555", "name": "logatlas", "image": "logatlas:old", "runtime": "docker", "state": "exited", "exit": 128, "restart": "always"},
            {"id": "a1b2c3d4e666", "name": "portainer", "image": "docker.io/portainer/portainer-ce:2.21", "runtime": "podman", "state": "running", "restart": "always", "ports": ["0.0.0.0:9443->9443/tcp"], "started": int(now - 5 * 86400)},
            {"id": "a1b2c3d4e777", "name": "fluent-bit", "image": "docker.io/fluent/fluent-bit:3.1", "runtime": "podman", "state": "running", "restart": "always", "started": int(now - 2 * 86400)},
        ]
    if i == 3:  # список образов хоста для вкладки «Образы»
        GB = 1024 ** 3
        imgs = [
            {"runtime": "podman", "owner": "redos", "id": "d1e2f3a4b5c6", "full_id": "d1e2f3a4b5c6" + "0" * 52, "names": ["docker.io/library/caddy:2.8"], "size": 50 * 2**20, "created": int(now - 30 * 86400), "used_by": ["caddy"]},
            {"runtime": "podman", "owner": "redos", "id": "e2f3a4b5c6d1", "full_id": "e2f3a4b5c6d1" + "0" * 52, "names": ["localhost/atrium:1.0.0"], "size": 310 * 2**20, "created": int(now - 5 * 86400), "used_by": ["atrium"]},
            {"runtime": "podman", "owner": "redos", "id": "f3a4b5c6d1e2", "full_id": "f3a4b5c6d1e2" + "0" * 52, "names": ["localhost/myhomelab:v5"], "size": int(1.2 * GB), "created": int(now - 90 * 86400), "used_by": []},
            {"runtime": "podman", "owner": "redos", "id": "a4b5c6d1e2f3", "full_id": "a4b5c6d1e2f3" + "0" * 52, "names": [], "size": 420 * 2**20, "created": int(now - 60 * 86400), "used_by": []},
            {"runtime": "podman", "owner": "", "id": "b5c6d1e2f3a4", "full_id": "b5c6d1e2f3a4" + "0" * 52, "names": ["docker.io/portainer/portainer-ce:2.21"], "size": 280 * 2**20, "created": int(now - 12 * 86400), "used_by": ["portainer"]},
            {"runtime": "docker", "owner": "", "id": "c6d1e2f3a4b5", "full_id": "c6d1e2f3a4b5" + "0" * 52, "names": ["logatlas:old"], "size": 640 * 2**20, "created": int(now - 120 * 86400), "used_by": ["logatlas"]},
        ]
        db.x("INSERT OR REPLACE INTO host_images(host_id,at,data) VALUES(?,?,?)", (hid, now - 120, json.dumps(imgs)))
    tot = float(mem.split()[0]) * 2**30
    metrics = {"at": now, "cpu": m["cpu"], "load1": m["cpu"] / 100 * 8, "cores": 8, "mem_used": tot * m["mu"], "mem_total": tot, "swap_pct": 12 * i,
               "disk_pct": m["disk"], "disk_total": 494e9, "disk_free": 494e9 * (1 - m["disk"] / 100), "battery": m["bat"], "battery_chrg": i == 1}
    sw = [{"n": a, "v": v, "s": s, "p": p} for a, v, s, p in APPS] if mac else [{"n": "nginx", "v": "1.22.1", "s": "pkg", "p": ""}, {"n": "zabbix-server-mysql", "v": "6.4.21", "s": "pkg", "p": ""}]
    seen = now - (5 if i != 3 else 3600 * 5)
    db.x("INSERT OR REPLACE INTO hosts(id,name,os,agent_version,key_hash,created,last_seen,posture,posture_at,software,software_at,metrics,metrics_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (hid, name, posture["info"]["os"], "0.9.0" if i in NETHOSTS else "0.2.0", "x", now - 86400 * 9, seen, json.dumps(posture), seen, json.dumps(sw), seen, json.dumps(metrics), seen))
    # история метрик для мини-графиков: 6 часов с шагом в минуту
    import math
    db.x("DELETE FROM metric_points WHERE host_id=?", (hid,))
    rows = []
    for k in range(360, 0, -1):
        t = now - k * 60
        w = math.sin(k / 23.0 + i) * 0.5 + 0.5
        spike = 1 if (k % 97) < 6 else 0
        cpu = max(1.0, min(99.0, m["cpu"] * (0.5 + w) + spike * 35 + random.random() * 6))
        mem = max(5.0, min(98.0, m["mu"] * 100 + math.sin(k / 41.0) * 6 + random.random() * 2))
        rows.append((hid, t, round(cpu, 1), round(mem, 1), float(m["disk"]), round(min(100.0, cpu / 100 * 80 + random.random() * 5), 1)))
    for r in rows:
        db.x("INSERT INTO metric_points(host_id,ts,cpu,mem,disk,load) VALUES(?,?,?,?,?,?)", r)

# --- сетевая карта: три хоста со включённым сбором и несколько устройств без агента -------------------------------------------------
from app import netmap
LAN = {0: ("192.168.1.20", "a8:5b:78:00:00:20"), 1: ("192.168.1.21", "a8:5b:78:00:00:21"), 3: ("192.168.1.30", "dc:a6:32:00:00:30")}
DEV = {"192.168.1.1": "f4:ec:38:00:00:01", "192.168.1.40": "b8:27:eb:00:00:40", "192.168.1.55": "3c:2a:f4:00:00:55", "192.168.1.70": "00:11:32:00:00:70"}
def snap(i, conns, listen):
    ip, mac = LAN[i]
    nb = [{"ip": k, "mac": v, "dev": "en0"} for k, v in DEV.items()] + [{"ip": LAN[j][0], "mac": LAN[j][1], "dev": "en0"} for j in LAN if j != i]
    return netmap.clean_snap({"at": now, "ifaces": [{"name": "en0", "mac": mac, "addrs": [ip + "/24", "fe80::1/64"], "up": True},
        {"name": "podman0", "mac": "02:42:ac:11:00:01", "addrs": ["10.88.0.1/16"], "up": True, "virtual": True}] if i == 3 else
        [{"name": "en0", "mac": mac, "addrs": [ip + "/24"], "up": True}, {"name": "utun3", "mac": "", "addrs": ["fe80::2/64"], "up": True, "virtual": True}],
        "gateways": ["192.168.1.1"], "dns": ["192.168.1.1"], "neigh": nb, "listen": listen, "conns": conns})
c = lambda d, peer, port, proc, n=1: {"dir": d, "peer": peer, "port": port, "proc": proc, "n": n}
SN = {
    0: snap(0, [c("out", "192.168.1.30", 22, "ssh"), c("out", "192.168.1.30", 9000, "Safari", 3), c("out", "192.168.1.30", 3000, "Safari", 2), c("out", "192.168.1.1", 53, "mDNSResponder", 4),
                c("out", "17.253.144.10", 443, "Safari", 6), c("out", "142.250.74.78", 443, "Google Chrome", 9), c("out", "140.82.121.4", 443, "git", 1), c("out", "192.168.1.55", 8009, "Google Chrome", 1), c("out", "192.168.1.70", 445, "smbd", 1)],
           [{"port": 22, "addr": "0.0.0.0", "proc": "launchd"}]),
    1: snap(1, [c("out", "192.168.1.30", 443, "Safari", 4), c("out", "192.168.1.30", 514, "syslog", 2), c("out", "192.168.1.1", 53, "mDNSResponder", 3), c("out", "151.101.1.69", 443, "Slack", 5),
                c("out", "192.168.1.70", 445, "smbd", 2), c("in", "192.168.1.20", 22, "launchd")], [{"port": 22, "addr": "0.0.0.0", "proc": "launchd"}]),
    3: snap(3, [c("in", "192.168.1.20", 22, "sshd"), c("in", "192.168.1.20", 9000, "podman", 3), c("in", "192.168.1.20", 3000, "grafana", 2), c("in", "192.168.1.21", 443, "caddy", 4), c("in", "192.168.1.21", 514, "fluent-bit", 2),
                c("out", "192.168.1.1", 53, "systemd-resolved", 5), c("out", "185.125.190.57", 443, "apt", 2), c("out", "192.168.1.40", 1883, "mosquitto", 2), c("in", "192.168.1.55", 5432, "postgres", 1)],
           [{"port": 22, "addr": "0.0.0.0", "proc": "sshd"}, {"port": 80, "addr": "::", "proc": "caddy"}, {"port": 443, "addr": "::", "proc": "caddy"}, {"port": 9000, "addr": "0.0.0.0", "proc": "graylog"}, {"port": 3000, "addr": "0.0.0.0", "proc": "grafana"}, {"port": 5432, "addr": "127.0.0.1", "proc": "postgres"}]),
}
for i, sn in SN.items():
    hid = "demo%02d" % i
    netmap.record(hid, sn, now)
    # накопленные за день связи: часть была давно
    db.x("UPDATE net_edges SET first=? WHERE host_id=?", (now - 20 * 3600, hid))
netmap.set_label("192.168.1.55", "Принтер HP", "кабинет", now)
print("ok")
