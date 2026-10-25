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
env = dict(os.environ, HOSTDECK_DB=os.path.join(tmp, "t.db"), HOSTDECK_ADMIN_PASSWORD=pw)
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
                ok("hde_" in cmd and "install-mac.sh" in cmd, "диалог добавления: выдан токен и команда")
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
        # мобильный вид
        ctx = br.new_context(viewport={"width": 390, "height": 800}, color_scheme="light", locale="ru-RU")
        pg = ctx.new_page(); pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(B + "/"); pg.fill("#u", "admin"); pg.fill("#p", pw); pg.click("button[type=submit]"); pg.wait_for_selector(".hero")
        pg.goto(B + "/#/hosts"); pg.wait_for_selector(".host-card"); pg.screenshot(path=f"{OUT}/mobile-hosts.png", full_page=True)
        ok(pg.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "мобильный вид без горизонтальной прокрутки")
        br.close()
finally:
    srv.terminate()
real = [e for e in errors if "favicon" not in e]
ok(not real, "ошибок в консоли нет" + (": " + "; ".join(real[:3]) if real else ""))
print(f"\nИТОГО: {sum(res)}/{len(res)}  скриншоты: {OUT}")
sys.exit(0 if all(res) else 1)
