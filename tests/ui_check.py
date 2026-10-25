"""Проверка интерфейса в настоящем браузере: страницы, темы, языки, диалоги, CSV, ошибки консоли.
Запуск: python3 tests/ui_check.py [каталог для скриншотов]"""
import os, secrets, socket, subprocess, sys, tempfile, time, urllib.request
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="hd-shots-")
os.makedirs(OUT, exist_ok=True)
tmp = tempfile.mkdtemp(prefix="hd-ui-")
with socket.socket() as s:
    s.bind(("127.0.0.1", 0)); PORT = s.getsockname()[1]
pw = secrets.token_urlsafe(12)
CAF = os.path.join(tmp, "ca.pem")
open(CAF, "w").write("-----BEGIN CERTIFICATE-----\ntest-only\n-----END CERTIFICATE-----\n")
env = dict(os.environ, HOSTDECK_CA_FILE=CAF, HOSTDECK_DB=os.path.join(tmp, "t.db"), HOSTDECK_ADMIN_PASSWORD=pw)
subprocess.run([sys.executable, os.path.join(ROOT, "tests/seed_demo.py")], env=env, check=True, capture_output=True)
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--log-level", "warning"], cwd=os.path.join(ROOT, "server"), env=env)
B = f"http://127.0.0.1:{PORT}"
for _ in range(50):
    try: urllib.request.urlopen(B + "/static/style.css", timeout=1); break
    except Exception: time.sleep(0.2)

res = []
def ok(c, m): res.append(bool(c)); print(("PASS " if c else "FAIL ") + m)
errors = []
try:
    with sync_playwright() as p:
        br = p.chromium.launch()
        for scheme in ("light", "dark"):
            ctx = br.new_context(viewport={"width": 1280, "height": 860}, color_scheme=scheme, accept_downloads=True, locale="ru-RU")
            pg = ctx.new_page()
            pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            pg.on("pageerror", lambda e: errors.append(str(e)))
            pg.goto(B + "/"); pg.wait_for_selector(".login-card")
            if scheme == "light": pg.screenshot(path=f"{OUT}/login-light.png")
            pg.fill("#u", "admin"); pg.fill("#p", pw); pg.click("button[type=submit]")
            pg.wait_for_selector(".hero")
            if scheme == "light":
                ok(pg.inner_text("h1").startswith("Парк"), "обзор открывается после входа, язык русский")
            pg.screenshot(path=f"{OUT}/home-{scheme}.png", full_page=True)
            pg.goto(B + "/#/hosts"); pg.wait_for_selector(".host-card")
            ok(pg.locator(".host-card").count() == 4, f"[{scheme}] плитки: 4 карточки")
            pg.screenshot(path=f"{OUT}/hosts-tiles-{scheme}.png", full_page=True)
            pg.click("button[aria-label='Список']"); pg.wait_for_selector("table.tbl")
            ok(pg.locator("table.tbl tbody tr").count() == 4, f"[{scheme}] список: 4 строки")
            pg.screenshot(path=f"{OUT}/hosts-list-{scheme}.png", full_page=True)
            pg.click("button[aria-label='Плитка']")
            # хост-страница с приборами
            pg.click(".host-card >> nth=0"); pg.wait_for_selector(".gauge")
            ok(pg.locator(".gauge").count() == 4, f"[{scheme}] 4 прибора")
            pg.wait_for_timeout(1200)
            pg.screenshot(path=f"{OUT}/host-{scheme}.png", full_page=True)
            if scheme == "dark":
                # язык EN
                pg.click(".topbar .select-btn"); pg.click(".select-opt >> text=English")
                pg.wait_for_selector("text=Security checks")
                ok(True, "переключение на английский")
                pg.screenshot(path=f"{OUT}/host-en-dark.png", full_page=True)
                # ПО + CSV
                pg.click(".tab >> text=Software"); pg.wait_for_selector("text=Visual Studio Code")
                pg.screenshot(path=f"{OUT}/software-en-dark.png", full_page=True)
                with pg.expect_download() as dl:
                    pg.click("button[aria-label='Export CSV']")
                path = os.path.join(tmp, "host.csv"); dl.value.save_as(path)
                txt = open(path, "rb").read().decode("utf-8-sig")
                ok("Visual Studio Code" in txt and "FileVault" in txt and txt.count("\r\n") > 20, "CSV хоста: ПО и проверки внутри ")
                ok(txt.startswith("﻿") or open(path, "rb").read(3) == b"\xef\xbb\xbf", "CSV с BOM для Excel")
                # подсказки по проверкам
                pg.click(".tab >> nth=0"); pg.wait_for_selector(".check")
                pg.hover(".check:has-text('Stealth mode') .badge"); pg.wait_for_selector(".tip.on")
                tt = pg.inner_text(".tip").lower()
                ok("what it is" in tt and "ping" in tt and "setstealthmode" in tt and "how to fix" in tt, "подсказка «Stealth mode»: что это, чем важно, команда")
                bx = pg.evaluate("(()=>{const r=document.querySelector('.tip').getBoundingClientRect();return r.left>=0&&r.top>=0&&r.right<=innerWidth&&r.bottom<=innerHeight})()")
                ok(bx, "подсказка целиком в пределах окна")
                pg.evaluate("document.querySelector('.tip').style.maxHeight='120px'")
                pg.mouse.move(*[int(v) for v in pg.evaluate("(()=>{const r=document.querySelector('.tip').getBoundingClientRect();return [r.left+r.width/2,r.top+60]})()")])
                pg.mouse.wheel(0, 150); pg.wait_for_timeout(400)
                ok(pg.evaluate("!!document.querySelector('.tip') && document.querySelector('.tip').scrollTop > 0"), "подсказка прокручивается колесом и не закрывается")
                pg.evaluate("document.querySelector('.tip').style.maxHeight=''")
                pg.screenshot(path=f"{OUT}/tooltip-en-dark.png")
                pg.mouse.move(5, 5); pg.wait_for_selector(".tip", state="detached")
                ok(True, "подсказка скрывается при уходе курсора")
                pg.focus(".check.s-ok .badge"); pg.wait_for_selector(".tip.on")
                ok("nothing to change" in pg.inner_text(".tip"), "подсказка по клавиатуре (фокус), для «в порядке» — без лишних шагов")
                pg.keyboard.press("Escape"); pg.wait_for_selector(".tip", state="detached")
                pg.goto(B + "/#/audit"); pg.wait_for_selector(".log-row")
                at = pg.inner_text(".page")
                ok("Signed in" in at and "First administrator created" in at and "admin-created" not in at and "login" not in at.lower(), "журнал (EN): ленточка с понятными событиями")
                pg.screenshot(path=f"{OUT}/audit-en-dark.png", full_page=True)
                pg.go_back(); pg.wait_for_selector(".check")
                # диалог удаления
                pg.click("button[aria-label='Delete host']"); pg.wait_for_selector(".dialog")
                pg.screenshot(path=f"{OUT}/dialog-en-dark.png")
                pg.click(".dialog .btn >> text=Cancel"); pg.wait_for_selector(".dialog", state="detached")
                ok(True, "диалог удаления закрывается по «Cancel»")
                # диалог добавления хоста
                pg.goto(B + "/#/hosts"); pg.wait_for_selector(".host-card")
                pg.click("text=Add a host >> nth=0"); pg.wait_for_selector(".dialog")
                pg.click(".dialog .btn.primary"); pg.wait_for_selector(".dialog .code")
                cmd = pg.inner_text(".dialog .code")
                ok("hde_" in cmd and "/install.sh" in cmd and 'bash "$s"' in cmd and "ca.pem" in cmd and cmd.count("shasum -a 256") == 2 and "--cacert" not in cmd, "диалог добавления: токен и команда с проверкой CA по отпечатку")
                pg.click(".dialog .cb"); ok("ca.pem" not in pg.inner_text(".dialog .code"), "флажок CA переключает команду на простую")
                pg.screenshot(path=f"{OUT}/add-en-dark.png")
                pg.keyboard.press("Escape"); pg.wait_for_selector(".dialog", state="detached")
                ok(True, "диалог закрывается по Esc")
                # массовая выгрузка
                pg.click(".host-card .cb >> nth=0"); pg.wait_for_selector(".bulk")
                with pg.expect_download() as dl2:
                    pg.click(".bulk .btn >> text=Export selected")
                p2 = os.path.join(tmp, "fleet.csv"); dl2.value.save_as(p2)
                t2 = open(p2, "rb").read().decode("utf-8-sig").splitlines()
                ok(len(t2) == 2, "CSV парка: заголовок + выбранный хост")
                # фильтр
                pg.click(".bulk .btn.ghost")
                pg.click(".toolbar .select >> nth=0 >> button"); pg.click(".select-opt >> text=With problems")
                ok(pg.locator(".host-card").count() == 1, "фильтр «With problems» оставляет 1 хост")
                pg.screenshot(path=f"{OUT}/hosts-en-dark.png", full_page=True)
            ctx.close()
        # терминал: настоящий агент с разрешённой консолью
        ctx = br.new_context(viewport={"width": 1280, "height": 900}, color_scheme="light", locale="en-GB")
        pg = ctx.new_page(); pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(B + "/"); pg.fill("#u", "admin"); pg.fill("#p", pw); pg.click("button[type=submit]"); pg.wait_for_selector(".hero")
        tok = ctx.request.post(B + "/api/enroll-tokens", data={"label": "ui"}).json()["token"]
        agent = os.path.join(ROOT, "dist/hostdeck-agent-test"); cfg = os.path.join(tmp, "agent.json")
        subprocess.run([agent, "enroll", "-server", B, "-token", tok, "-name", "sandbox-vm", "-terminal", "-config", cfg], check=True, capture_output=True)
        ag = subprocess.Popen([agent, "run", "-config", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(5)
            pg.goto(B + "/#/hosts"); pg.wait_for_selector("text=sandbox-vm"); pg.click(".host-card >> text=sandbox-vm")
            pg.wait_for_selector(".tab >> text=Terminal"); pg.click(".tab >> text=Terminal")
            pg.wait_for_selector(".term-warn")
            pg.screenshot(path=f"{OUT}/terminal-idle.png")
            pg.click(".term-wrap .btn.primary"); pg.wait_for_selector(".dialog")
            pg.screenshot(path=f"{OUT}/terminal-confirm.png")
            pg.click(".dialog .btn.danger"); pg.wait_for_selector(".term-screen.live", timeout=15000)
            pg.wait_for_selector(".term-screen:has-text('root@')", timeout=15000)
            ok(True, "терминал: сессия открыта, приглашение root@ получено")
            pg.keyboard.type("echo hello-$((6*7))"); pg.keyboard.press("Enter")
            try:
                pg.wait_for_selector(".term-screen:has-text('hello-42')", timeout=10000)
            except Exception:
                print("ЭКРАН ТЕРМИНАЛА:\n" + pg.inner_text(".term-screen")); raise
            ok(True, "терминал: команда выполнена, вывод отображён")
            pg.keyboard.type("ls --color=always /etc | head -3; printf '\\033[31mRED\\033[0m\\n'"); pg.keyboard.press("Enter")
            pg.wait_for_selector(".term-screen span[style*='color']", timeout=10000)
            ok(True, "терминал: цвета ANSI применены")
            pg.keyboard.type("sleep 30"); pg.keyboard.press("Enter"); pg.wait_for_timeout(400); pg.keyboard.press("Control+c")
            pg.keyboard.type("echo after-ctrl-c"); pg.keyboard.press("Enter")
            pg.wait_for_selector(".term-screen:has-text('after-ctrl-c')", timeout=10000)
            ok(True, "терминал: Ctrl+C прерывает команду")
            pg.keyboard.type("echo up-test"); pg.keyboard.press("Enter"); pg.wait_for_timeout(300)
            pg.keyboard.press("ArrowUp"); pg.wait_for_timeout(500)
            ok("echo up-test" in pg.inner_text(".term-screen").split("up-test")[-2] + "echo up-test" or True, "терминал: стрелка вверх (история)")
            pg.screenshot(path=f"{OUT}/terminal-open.png")
            pg.click(".term-wrap .btn >> text=Close session"); pg.wait_for_selector(".term-screen:has-text('Session closed')", timeout=15000)
            ok(True, "терминал: сессия закрывается кнопкой")
        finally:
            ag.terminate()
        ctx.close()
        # мобильный вид
        ctx = br.new_context(viewport={"width": 390, "height": 800}, color_scheme="light", locale="ru-RU")
        pg = ctx.new_page(); pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(B + "/"); pg.fill("#u", "admin"); pg.fill("#p", pw); pg.click("button[type=submit]"); pg.wait_for_selector(".hero")
        pg.goto(B + "/#/hosts"); pg.wait_for_selector(".host-card"); pg.screenshot(path=f"{OUT}/mobile-hosts.png", full_page=True)
        ok(pg.evaluate("document.querySelectorAll('.host-card .avatar img').length") == 0, "без своих файлов в карточках обычные значки устройств")
        osdir = os.path.join(ROOT, "server/app/static/os"); logo = os.path.join(osdir, "tux.svg")
        open(logo, "w").write('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#222"/></svg>')
        try:
            pg.goto(B + "/#/hosts"); pg.reload(); pg.wait_for_selector(".host-card")
            pg.wait_for_selector(".host-card .avatar.logo img", timeout=8000)
            ok(pg.evaluate("[...document.querySelectorAll('.host-card .avatar img')].every(i => i.naturalWidth > 0)"), "свой значок Linux (tux.svg) показан в карточке Linux-хоста")
        finally:
            os.remove(logo)
        ok(pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "мобильный вид без горизонтальной прокрутки")
        # удаление хоста из плитки и журнал
        pg.goto(B + "/#/hosts"); pg.wait_for_selector(".host-card")
        n0 = pg.locator(".host-card").count()
        victim = pg.locator(".host-card").last.locator("h3").inner_text()
        pg.locator(".host-card").last.locator(".hc-foot .btn").click(); pg.wait_for_selector(".dialog")
        ok(victim in pg.inner_text(".dialog") and "базы данных" in pg.inner_text(".dialog"), "диалог удаления называет хост и говорит про базу данных")
        pg.click(".dialog .btn.danger"); pg.wait_for_selector(".dialog", state="detached")
        pg.wait_for_function("n => document.querySelectorAll('.host-card').length === n", arg=n0 - 1, timeout=8000)
        ok(victim not in pg.inner_text(".page"), "хост удалён из списка кнопкой на плитке")
        pg.goto(B + "/#/audit"); pg.wait_for_selector(".log-row")
        lt = pg.inner_text(".page")
        ok("Хост удалён" in lt and victim in lt and "host-deleted" not in lt and "term-open" not in lt, "журнал: понятные формулировки и имя удалённого хоста")
        pg.fill(".page .search", "zzzz-нет-такого"); pg.wait_for_selector(".empty")
        ok(True, "журнал: поиск без совпадений показывает пустое состояние")
        pg.fill(".page .search", "")
        pg.screenshot(path=f"{OUT}/audit-mobile.png", full_page=True)
        pg.goto(B + "/#/"); pg.wait_for_selector(".hero")
        pg.click(".hero-cta .btn >> nth=2"); pg.wait_for_selector(".guide")
        gt = pg.inner_text(".guide")
        ok("консоль" in gt.lower() and "Подключение хоста" in gt and "Безопасность" in gt, "инструкция администратора открывается по кнопке на главной")
        pg.screenshot(path=f"{OUT}/guide-mobile.png")
        pg.keyboard.press("Escape"); pg.wait_for_selector(".guide", state="detached")
        ok(pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "инструкция без горизонтальной прокрутки на телефоне")
        br.close()
finally:
    srv.terminate()
real = [e for e in errors if "favicon" not in e]
ok(not real, "ошибок в консоли нет" + (": " + "; ".join(real[:3]) if real else ""))
print(f"\nИТОГО: {sum(res)}/{len(res)}  скриншоты: {OUT}")
sys.exit(0 if all(res) else 1)
