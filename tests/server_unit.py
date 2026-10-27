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

print("\nИТОГО: %d/%d" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
