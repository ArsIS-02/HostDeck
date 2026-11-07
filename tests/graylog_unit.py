"""Связь с Graylog: смены статуса проверок и журнал по GELF, выгрузка хостов для Lookup Tables.
Запуск: python3 tests/graylog_unit.py"""
import csv, io, json, os, socket, sys, tempfile, time, zlib
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
tmp = tempfile.mkdtemp(prefix="hostdeck-gl-")
os.environ["HOSTDECK_DB"] = os.path.join(tmp, "g.db")
os.environ["HOSTDECK_EXPORT_TOKEN"] = "s3cr3t"
from app import db, gelf, main as m, netmap  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

res = []
def ok(c, msg):
    print(("PASS " if c else "FAIL ") + msg); res.append(bool(c))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
gelf.reset(gelf.Sender("127.0.0.1", sock.getsockname()[1], "udp", "hostdeck-test"))

def recv(wait=1.0):
    gelf.SENDER.flush()
    sock.settimeout(wait)
    out = []
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return out
        out.append(json.loads(zlib.decompress(data)))

now = time.time()
db.x("INSERT INTO hosts(id,name,os,key_hash,created,profile,agent_version) VALUES('h1','redos-server.corp.example','RED OS 8','x',?,'server','0.9.0')", (now,))
db.x("INSERT INTO hosts(id,name,os,key_hash,created,profile) VALUES('h2','mac-1','macOS 26','x',?,'laptop')", (now,))
P = lambda **kw: {"checks": [{"id": k, "status": v, "value": "v-" + v, "detail": "d-" + k} for k, v in kw.items()]}

m.record_history("h1", P(selinux="ok", sshd="ok", auditd="warn"), P(selinux="fail", sshd="warn", auditd="ok"), now)
by = {x["_hd_check"]: x for x in recv() if x.get("_hd_event") == "check_changed"}
ok(by["selinux"]["level"] == 3 and by["selinux"]["_hd_to"] == "fail" and by["selinux"]["_hd_from"] == "ok", "ok → fail: level 3 (error)")
ok(by["sshd"]["level"] == 4 and by["sshd"]["_hd_effective"] == "warn", "ok → warn: level 4")
ok(by["auditd"]["level"] == 6 and by["auditd"]["_hd_recovered"] == "true", "warn → ok: восстановление, level 6")
ok(by["selinux"]["_hd_host"] == "redos-server.corp.example" and by["selinux"]["_hd_os"] == "RED OS 8" and by["selinux"]["_hd_profile"] == "server", "имя, ОС и профиль хоста в событии")
ok(by["selinux"]["_hd_source"] == "hostdeck" and by["selinux"]["_homelab_app"] == "hostdeck", "поля потока hd_source и homelab_app")

db.x("INSERT INTO exceptions(host_id,check_id,reason,expires,actor,created) VALUES('h1','sshd','нужен для мониторинга',NULL,'admin',?)", (now,))
m.record_history("h1", P(sshd="ok"), P(sshd="fail"), now + 60)
x = [x for x in recv() if x.get("_hd_check") == "sshd"][0]
ok(x["_hd_effective"] == "info" and x["level"] == 6 and x["_hd_exception"] == "нужен для мониторинга", "исключение: событие приходит, но с уровнем info")
m.record_history("h2", P(ssh_hardening="ok"), P(ssh_hardening="warn"), now)
x = [x for x in recv() if x.get("_hd_check") == "ssh_hardening"][0]
ok(x["_hd_effective"] == "warn" and x["level"] == 4, "ноутбук: ssh_hardening не смягчается профилем laptop")
db.x("UPDATE hosts SET profile='lab' WHERE id='h2'")
m.record_history("h2", P(ssh_hardening="ok"), P(ssh_hardening="warn"), now)
x = [x for x in recv() if x.get("_hd_check") == "ssh_hardening"][0]
ok(x["_hd_effective"] == "info" and x["level"] == 6, "лаборатория смягчает warn до info")
m.record_history("h1", None, P(selinux="fail"), now)
ok(not [x for x in recv(0.3) if x.get("_hd_event") == "check_changed"], "первый отчёт хоста событий не создаёт")

db.audit("admin", "term-open", host="h1", detail="root")
db.audit("guest", "login-failed", detail="198.51.100.7")
db.audit("admin", "login", detail="198.51.100.7")
au = {x["_hd_action"]: x for x in recv() if x.get("_hd_event") == "audit"}
ok(au["term-open"]["level"] == 4 and au["term-open"]["_hd_host"] == "redos-server.corp.example", "консоль root: warning, имя хоста")
ok(au["login-failed"]["level"] == 4 and au["login-failed"]["_hd_detail"] == "198.51.100.7", "неудачный вход: warning, адрес")
ok(au["login"]["level"] == 6, "вход: info")

# выгрузка
netmap.record("h1", netmap.clean_snap({"at": now, "ifaces": [{"name": "eth0", "addrs": ["192.0.2.10/24", "fe80::1/64"], "up": True},
                                                              {"name": "podman0", "addrs": ["10.88.0.1/16"], "up": True, "virtual": True}],
                                       "conns": []}), now)
db.x("INSERT INTO net_labels(ip,name,note,updated) VALUES('192.0.2.1','router-1','',?)", (now,))
db.x("INSERT INTO net_labels(ip,name,note,updated) VALUES('192.0.2.10','dup','',?)", (now,))
c = TestClient(m.app)
ok(c.get("/api/export/hosts.csv").status_code == 403, "без токена — 403")
r = c.get("/api/export/hosts.csv?token=s3cr3t")
rows = {x["key"]: x for x in csv.DictReader(io.StringIO(r.text))}
ok(r.status_code == 200 and rows["redos-server.corp.example"]["os"] == "RED OS 8" and rows["redos-server"]["profile"] == "server", "key=name: полное и короткое имя, ОС, профиль")
ok(rows["mac-1"]["profile"] == "lab", "профиль второго хоста")
r = c.get("/api/export/hosts.csv?token=s3cr3t&key=ip&header=0")
keys = {ln.split(",")[0]: ln.split(",")[1] for ln in r.text.splitlines()}
ok(keys.get("192.0.2.10") == "redos-server.corp.example" and "10.88.0.1" not in keys and not any(k.startswith("fe80") for k in keys), "key=ip: адрес хоста, без виртуальных и link-local")
ok(keys.get("192.0.2.1") == "router-1", "подписи адресов с карты сети попадают в выгрузку")
ok(c.get("/api/export/hosts.csv?token=s3cr3t&key=mac").status_code == 400, "неизвестный key — 400")

print("\nИТОГО: %d/%d" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
