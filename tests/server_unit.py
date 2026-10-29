"""Модульные проверки серверной логики без запуска сервера: история статусов, индекс, профили.
Запуск: python3 tests/server_unit.py"""
import os, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
tmp = tempfile.mkdtemp(prefix="hostdeck-unit-")
os.environ["HOSTDECK_DB"] = os.path.join(tmp, "u.db")
from app import db, main as m  # noqa: E402

res = []
def ok(c, msg):
    print(("PASS " if c else "FAIL ") + msg); res.append(bool(c))

db.x("INSERT INTO hosts(id,name,key_hash,created,profile) VALUES('h1','host-1','x',?, 'server')", (time.time(),))
P = lambda **kw: {"checks": [{"id": k, "status": v, "value": "v-" + v} for k, v in kw.items()]}
t0 = 1_700_000_000.0

m.record_history("h1", None, P(a="ok", b="warn"), t0)
ok(db.q1("SELECT COUNT(*) n FROM history")["n"] == 0, "первый отчёт хоста не создаёт смен")
m.record_history("h1", P(a="ok", b="warn"), P(a="ok", b="warn"), t0 + 60)
ok(db.q1("SELECT COUNT(*) n FROM history")["n"] == 0, "без изменений записей нет")
m.record_history("h1", P(a="ok", b="warn"), P(a="fail", b="warn", c="ok"), t0 + 120)
rows = db.q("SELECT check_id,from_status,to_status FROM history")
ok(len(rows) == 1 and tuple(rows[0]) == ("a", "ok", "fail"), "смена ok → fail записана, новая проверка c смены не даёт")
m.record_history("h1", P(a="fail"), P(a="ok"), t0 + 3600)
sm = m.since_map("h1")
ok(sm["a"] == ("ok", t0 + 3600), "since_map: последняя смена проверки")

# индекс и профили
chk = [{"id": "a", "status": "ok"}, {"id": "ssh_hardening", "status": "warn"}, {"id": "x", "status": "fail"}, {"id": "i", "status": "info"}]
ok(m.compliance_index(m.effective_checks(chk, "server", {})) == 50, "индекс сервера: (1 + 0.5 + 0) / 3 = 50")
ok(m.compliance_index(m.effective_checks(chk, "lab", {})) == 50, "лаборатория смягчает warn, но не fail")
ok(m.compliance_index([{"id": "i", "status": "info"}]) is None, "нечего считать — индекса нет")

# точки индекса: не чаще раза в 6 часов, если значение не менялось
post = P(a="ok", b="ok")
m.record_index_point("h1", post, t0)
m.record_index_point("h1", post, t0 + 600)
ok(db.q1("SELECT COUNT(*) n FROM idx_points")["n"] == 1, "одинаковые точки в пределах 6 часов не дублируются")
m.record_index_point("h1", post, t0 + 7 * 3600)
ok(db.q1("SELECT COUNT(*) n FROM idx_points")["n"] == 2, "через 6 часов точка записывается")
m.record_index_point("h1", P(a="ok", b="fail"), t0 + 7 * 3600 + 60)
ok(db.q1("SELECT COUNT(*) n FROM idx_points")["n"] == 3, "изменение индекса записывается сразу")

# лимит строк истории на хост
for i in range(m.HISTORY_MAX_ROWS + 50):
    m.record_history("h1", P(z="ok"), P(z="warn"), time.time())
ok(db.q1("SELECT COUNT(*) n FROM history WHERE host_id='h1'")["n"] <= m.HISTORY_MAX_ROWS, "история хоста ограничена по числу строк")

# сравнение версий для поиска ПО
ok(m.vkey("130.0.6723") < m.vkey("131.0"), "версии: 130.0.6723 < 131.0")
ok(m.vkey("9.9") < m.vkey("10.1"), "версии сравниваются как числа: 9.9 < 10.1")
ok(m.vkey("1.2.3") < m.vkey("1.2.10"), "версии: 1.2.3 < 1.2.10")
ok(m.vkey("2.0") == m.vkey("2.0") and not (m.vkey("2.0") < m.vkey("2.0")), "равные версии не «старше»")
ok(sorted(["1.10", "1.2", "1.9"], key=m.vkey) == ["1.2", "1.9", "1.10"], "сортировка версий по возрастанию")
ok(m.vkey("") == [], "пустая версия даёт пустой ключ")

# список контейнеров из отчёта агента: только известные поля, ограниченной длины
ok(m.clean_containers(None) is None and m.clean_containers("x") is None, "контейнеры: нет списка -> None")
cc = m.clean_containers([{"name": "web", "image": "i" * 500, "runtime": "docker", "state": "running", "exit": "boom", "ports": ["0.0.0.0:80->80/tcp"], "env": ["SECRET=1"]}, {"x": 1}, "str"])
ok(len(cc) == 1 and len(cc[0]["image"]) == 200 and cc[0]["exit"] == 0 and "env" not in cc[0] and cc[0]["ports"] == ["0.0.0.0:80->80/tcp"], "контейнеры: лишние поля и мусор отброшены")
ok(len(m.clean_containers([{"name": str(i)} for i in range(400)])) == 150, "контейнеры: не больше 150")

# точки для мини-графиков
db.x("INSERT INTO hosts(id,name,key_hash,created) VALUES('h2','host-2','x',?)", (time.time(),))
mm = {"cpu": 40.0, "mem_used": 4e9, "mem_total": 8e9, "disk_pct": 55.0, "load1": 2.0, "cores": 4}
base = 1_800_000_000.0
m.record_metric_point("h2", mm, base)
m.record_metric_point("h2", mm, base + 1)   # реже 3 секунд не храним
m.record_metric_point("h2", dict(mm, cpu=60.0), base + 5)
pts = m.metric_points("h2", base - 10, base + 100)
ok(len(pts) == 2 and pts[0][1:] == [40.0, 50.0, 55.0, 50.0] and pts[1][1] == 60.0, "точки: 2 записи, память и нагрузка в процентах")
ok(m.metric_points("h2", base + 2, base + 100) == [pts[1]], "точки: выборка после since")
m.record_metric_point("h2", {"cpu": "x"}, base + 50)
ok(len(m.metric_points("h2", base - 10, base + 100)) == 2, "точки: мусорные метрики не пишутся")
for i in range(1000):
    db.x("INSERT INTO metric_points(host_id,ts,cpu,mem,disk,load) VALUES('h2',?,?,1,1,1)", (base + 1000 + i, float(i % 100)))
big = m.metric_points("h2", base + 999, base + 2000, limit=100)
ok(0 < len(big) <= 101, "точки: избыток усредняется до ~100 штук")

# версия сервера (VERSION) совпадает с версией агента: релиз у них общий
import re as _re
agent_v = _re.search(r'var version = "([^"]+)"', open(os.path.join(ROOT, "agent", "collect.go"), encoding="utf-8").read()).group(1)
ok(m.APP_VERSION == agent_v, "версия сервера (%s) совпадает с версией агента (%s)" % (m.APP_VERSION, agent_v))

# управление контейнерами: очистка данных, учёт операций, тайм-аут
cc = m.clean_containers([{"name": "web", "id": "ab" * 6, "image_id": "cd" * 6, "unit": "web.service", "compose": "proj", "runtime": "podman", "x": 1}])
ok(cc[0]["id"] == "ab" * 6 and cc[0]["unit"] == "web.service" and cc[0]["compose"] == "proj" and "x" not in cc[0], "операции: в списке контейнеров сохранены id, юнит и проект")
im = m.clean_images([{"runtime": "podman", "id": "a" * 12, "full_id": "a" * 64, "names": ["x"] * 30, "size": 5, "created": 1, "used_by": ["c"]},
                     {"runtime": "podman", "id": "zz", "full_id": "-rf"}, "мусор", {"id": 5}])
ok(len(im) == 1 and len(im[0]["names"]) == 20 and im[0]["used_by"] == ["c"], "операции: образы очищены от мусора и ограничены по длине")
m.OPS.clear()
m.OPS["o1"] = {"host": "h1", "actor": "admin", "action": "rm", "target": "web", "created": time.time(), "result": None}
m.finish_op("h2", {"op": "o1", "ok": True, "code": "ok"})
ok(m.OPS["o1"]["result"] is None, "операции: ответ от чужого хоста игнорируется")
m.finish_op("h1", {"op": "o1", "ok": True, "code": "взлом", "detail": "x" * 999, "items": [{"target": "t", "ok": 1, "code": "in_use"}, "мусор"]})
r1 = m.OPS["o1"]["result"]
ok(r1["code"] == "failed" and len(r1["detail"]) == 300 and r1["items"] == [{"target": "t", "ok": True, "code": "in_use", "detail": ""}], "операции: неизвестный код заменён на failed, ответ очищен")
m.finish_op("h1", {"op": "o1", "ok": True, "code": "ok"})
ok(m.OPS["o1"]["result"] is r1, "операции: повторный ответ не меняет итог")
ok(db.q1("SELECT action, actor FROM audit WHERE action='ctr-rm'") is not None, "операции: итог записан в журнал")
m.OPS["o2"] = {"host": "h1", "actor": "admin", "action": "start", "target": "web", "created": time.time() - m.OP_TIMEOUT - 1, "result": None}
ok(m.pending_op("h1") is not None, "операции: незавершённая операция видна")
m.expire_ops(time.time())
ok(m.OPS["o2"]["result"]["code"] == "timeout" and m.pending_op("h1") is None, "операции: без ответа агента по тайм-ауту завершается с кодом timeout")
m.OPS["o3"] = {"host": "h1", "actor": "admin", "action": "start", "target": "web", "created": time.time() - m.OP_TTL - 1, "result": {"ok": True}}
m.expire_ops(time.time())
ok("o3" not in m.OPS, "операции: старые записи удаляются")

# сетевая карта
from app import netmap  # noqa: E402
now = time.time()
db.x("INSERT INTO hosts(id,name,key_hash,created,last_seen) VALUES('hA','alpha','x',?,?)", (now, now))
db.x("INSERT INTO hosts(id,name,key_hash,created,last_seen) VALUES('hB','beta','x',?,?)", (now, now))
def snap(ip, mac, conns, neigh=(), gw="192.168.1.1"):
    return netmap.clean_snap({"at": now, "ifaces": [{"name": "eth0", "mac": mac, "addrs": [ip + "/24"], "up": True},
        {"name": "docker0", "mac": "02:42:00:00:00:01", "addrs": ["172.17.0.1/16"], "up": True, "virtual": True}],
        "gateways": [gw], "dns": [gw], "neigh": list(neigh), "listen": [{"port": 22, "addr": "0.0.0.0", "proc": "sshd"}], "conns": conns})
bad = netmap.clean_snap({"ifaces": [{"name": "x", "addrs": ["не-адрес"]}], "conns": [{"dir": "sideways", "peer": "1.2.3.4", "port": 1}, {"dir": "out", "peer": "bad", "port": 1}]})
ok(bad["ifaces"][0]["addrs"] == [] and bad["conns"] == [], "карта: мусорные адреса и направления отбрасываются")
netmap.record("hA", snap("192.168.1.10", "aa:aa:aa:aa:aa:01", [
    {"dir": "out", "peer": "192.168.1.11", "port": 22, "proc": "ssh", "n": 1},
    {"dir": "out", "peer": "93.184.216.34", "port": 443, "proc": "curl", "n": 2},
    {"dir": "out", "peer": "8.8.4.4", "port": 443, "proc": "curl", "n": 1},
    {"dir": "out", "peer": "192.168.1.50", "port": 9000, "proc": "agent", "n": 3}],
    neigh=[{"ip": "192.168.1.1", "mac": "aa:aa:aa:00:00:01"}, {"ip": "192.168.1.50", "mac": "aa:aa:aa:00:00:50"}, {"ip": "192.168.1.11", "mac": "aa:aa:aa:aa:aa:02"}]), now)
netmap.record("hB", snap("192.168.1.11", "aa:aa:aa:aa:aa:02", [{"dir": "in", "peer": "192.168.1.10", "port": 22, "proc": "sshd", "n": 1}]), now)
mp = netmap.build_map(24, now, 90)
kinds = {n["id"]: n["kind"] for n in mp["nodes"]}
ok(kinds.get("hA") == "host" and kinds.get("hB") == "host" and kinds.get("inet") == "internet" and kinds.get("ip:192.168.1.50") == "device", "карта: узлы — хосты, Интернет и неизвестное устройство")
ssh = [l for l in mp["links"] if l["port"] == 22]
ok(len(ssh) == 1 and ssh[0]["from"] == "hA" and ssh[0]["to"] == "hB" and sorted(ssh[0]["procs"]) == ["ssh", "sshd"], "карта: out на A и in на B сливаются в одну связь A → B")
inet = [l for l in mp["links"] if l["to"] == "inet"]
ok(len(inet) == 1 and inet[0]["n"] == 3 and inet[0]["peers"] == 2 and next(n for n in mp["nodes"] if n["id"] == "inet")["count"] == 2, "карта: внешние адреса сворачиваются в «Интернет»")
ok(all(172 != int(i.split(".")[0]) for n in mp["nodes"] for i in n["ips"] if n["kind"] == "host"), "карта: адреса мостов контейнеров не считаются адресами хоста")
mp2 = netmap.build_map(24, now, 90, "ip")
ok(any(n["kind"] == "external" for n in mp2["nodes"]), "карта: режим «по адресам» раскрывает внешние узлы")
tp = netmap.build_topology(now, 90)
sn = tp["subnets"]
ok(len(sn) == 1 and sn[0]["cidr"] == "192.168.1.0/24" and len(sn[0]["hosts"]) == 2, "топология: одна подсеть, два хоста, мост контейнеров не в счёт")
ok([d["ip"] for d in sn[0]["devices"]] == ["192.168.1.1", "192.168.1.50"] and sn[0]["devices"][0]["gateway"], "топология: соседи по ARP без агента — неизвестные устройства, шлюз отмечен")
netmap.set_label("192.168.1.50", "Принтер", "кабинет 2", now)
ok(netmap.build_topology(now, 90)["subnets"][0]["devices"][1]["name"] == "Принтер" and next(n for n in netmap.build_map(24, now, 90)["nodes"] if n["id"] == "ip:192.168.1.50")["name"] == "Принтер", "метка устройства видна и в топологии, и на графе")
ok(not netmap.set_label("не-адрес", "x", "", now), "метка: неверный адрес отклоняется")
netmap.set_label("192.168.1.50", "", "", now)
ok(db.q1("SELECT COUNT(*) n FROM net_labels")["n"] == 0, "метка: пустое имя снимает метку")
hv = netmap.host_view("hA")
ok(hv["listen"][0]["service"] == "SSH" and hv["conns"][0]["service"] and hv["hosts"].get("192.168.1.11") == "beta", "вид хоста: службы и имена известных хостов")
db.x("UPDATE net_edges SET last=?", (now - 3 * 86400,))
ok(not any(l["from"] == "hA" for l in netmap.build_map(24, now, 90)["links"]) and any(l["from"] == "hA" for l in netmap.build_map(168, now, 90)["links"]), "карта: окно времени отсекает старые связи")
netmap.forget_host("hB")
ok(netmap.host_view("hB")["at"] is None, "удаление хоста чистит его данные карты")

# IPv4 и IPv6 разделены; link-local и «шум» на карту не попадают; зоны = подсети
db.x("INSERT INTO hosts(id,name,key_hash,created,last_seen) VALUES('hC','gamma','x',?,?)", (now, now))
db.x("INSERT INTO hosts(id,name,key_hash,created,last_seen) VALUES('hD','delta','x',?,?)", (now, now))
def snap6(v4, v6, conns):
    return netmap.clean_snap({"at": now, "ifaces": [{"name": "eth0", "mac": "aa:aa:aa:aa:00:" + v4[-2:], "addrs": [v4 + "/24", v6 + "/64", "fe80::1/64"], "up": True}],
        "gateways": [], "dns": [], "neigh": [], "listen": [], "conns": conns})
netmap.record("hC", snap6("10.1.0.3", "fd00:1::3", [
    {"dir": "out", "peer": "10.1.0.4", "port": 22, "proc": "ssh", "n": 1}, {"dir": "out", "peer": "fd00:1::4", "port": 443, "proc": "curl", "n": 2},
    {"dir": "out", "peer": "fe80::99", "port": 5353, "proc": "avahi", "n": 1}, {"dir": "out", "peer": "2606:4700::1111", "port": 443, "proc": "curl", "n": 3},
    {"dir": "out", "peer": "10.1.0.50", "port": 80, "proc": "curl", "n": 1}]), now)
netmap.record("hD", snap6("10.1.0.4", "fd00:1::4", []), now)
m4 = netmap.build_map(24, now, 90, "group", 4)
m6 = netmap.build_map(24, now, 90, "group", 6)
ok(m4["family"] == 4 and m6["family"] == 6, "семейство адресов указано в ответе")
ok(any(l["from"] == "hC" and l["to"] == "hD" and l["port"] == 22 for l in m4["links"]) and not any(l["port"] == 443 and l["to"] == "hD" for l in m4["links"]), "IPv4: ssh между хостами есть, IPv6-соединение сюда не попадает")
ok(any(l["from"] == "hC" and l["to"] == "hD" and l["port"] == 443 for l in m6["links"]) and not any(l["port"] == 22 and l["to"] == "hD" for l in m6["links"]), "IPv6: соединение по fd00:: есть, IPv4 сюда не попадает")
ok(not any(l["port"] == 5353 for l in m4["links"] + m6["links"]) and not any(i.startswith("fe80") for n in m6["nodes"] for i in n["ips"]), "link-local (fe80::) на карту не попадает")
ok(all(not i.count(":") for n in m4["nodes"] if n["kind"] == "host" for i in n["ips"]) and next(n for n in m6["nodes"] if n["id"] == "hC")["ips"] == ["fd00:1::3"], "адреса хоста разделены по семейству")
zn = {n["id"]: n["zone"] for n in m4["nodes"]}
ok(zn["hC"] == zn["hD"] == "10.1.0.0/24" and zn["ip:10.1.0.50"] == "10.1.0.0/24" and "inet" not in zn, "зоны: хосты и устройство в одной подсети")
ok(next(n for n in m6["nodes"] if n["id"] == "hC")["zone"] == "fd00:1::/64" and any(n["kind"] == "internet" and n["zone"] == "ext" for n in m6["nodes"]), "IPv6: зона /64 и внешний адрес сворачивается в «Интернет»")
ok(netmap.build_topology(now, 90, 6)["subnets"][0]["cidr"] == "fd00:1::/64" and all(":" not in x["cidr"] for x in netmap.build_topology(now, 90, 4)["subnets"]), "топология разделена по IPv4 и IPv6")

print("\nИТОГО: %d/%d" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
