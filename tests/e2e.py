"""Сквозной тест HostDeck: поднимает сервер на свободном порту, регистрирует и запускает агента.
Запуск: python3 tests/e2e.py <путь к собранному агенту>"""
import json, os, secrets, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request, http.cookiejar

AGENT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "dist/hostdeck-agent-test")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tmp = tempfile.mkdtemp(prefix="hostdeck-e2e-")
with socket.socket() as s:
    s.bind(("127.0.0.1", 0)); PORT = s.getsockname()[1]
B = f"http://127.0.0.1:{PORT}"
pw = secrets.token_urlsafe(12)
env = dict(os.environ, HOSTDECK_DB=os.path.join(tmp, "t.db"), HOSTDECK_ADMIN_PASSWORD=pw)
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
                       cwd=os.path.join(ROOT, "server"), env=env)
for _ in range(50):
    try: urllib.request.urlopen(B + "/static/style.css", timeout=1); break
    except Exception: time.sleep(0.2)
cj=http.cookiejar.CookieJar()
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def call(path,method="GET",body=None,ctype="application/json",headers=None,opener=op):
    data=None
    h=dict(headers or {})
    if body is not None:
        data=json.dumps(body).encode(); h["Content-Type"]=ctype
    r=urllib.request.Request(B+path,data=data,method=method,headers=h)
    try:
        with opener.open(r,timeout=40) as resp:
            return resp.status, json.loads(resp.read() or b"null"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null"), e.headers
def ok(c, m):
    c = bool(c); print(("PASS " if c else "FAIL ") + m); return c
res=[]
anon=urllib.request.build_opener()
res.append(ok(call("/api/hosts",opener=anon)[0]==401,"список хостов без входа -> 401"))
res.append(ok(call("/api/login","POST",{"name":"admin","password":"x"})[0]==401,"неверный пароль -> 401"))
res.append(ok(call("/api/login","POST",{"name":"admin","password":pw},"text/plain")[0]==400,"вход не-JSON телом отклонён"))
s,d,h=call("/api/login","POST",{"name":"admin","password":pw})
res.append(ok(s==200 and d["role"]=="admin","вход администратора"))
ck=[c for c in cj if c.name=="hd_session"][0]
res.append(ok(ck.has_nonstandard_attr("HttpOnly") and ck.get_nonstandard_attr("SameSite")=="strict","cookie HttpOnly+SameSite=strict"))
res.append(ok("default-src 'self'" in h.get("Content-Security-Policy",""),"заголовок CSP"))
s,d,_=call("/api/enroll-tokens","POST",{"label":"e2e"}); tok=d["token"]
res.append(ok(s==200 and tok.startswith("hde_"),"токен регистрации создан"))
# агент
env=dict(os.environ); cfg=os.path.join(tmp,"agent.json")
if os.path.exists(cfg): os.remove(cfg)
r=subprocess.run([AGENT,"enroll","-server",B,"-token",tok,"-name","sandbox-linux","-config",cfg],capture_output=True,text=True)
res.append(ok(r.returncode==0,"агент зарегистрирован: "+r.stdout.strip()))
res.append(ok(oct(os.stat(cfg).st_mode&0o777)=="0o600","конфиг агента 0600"))
r2=subprocess.run([AGENT,"enroll","-server",B,"-token",tok,"-name","dup","-config",os.path.join(tmp,"dup.json")],capture_output=True,text=True)
res.append(ok(r2.returncode!=0,"повторное использование токена отклонено"))
r3=subprocess.run([AGENT,"enroll","-server","http://example.com","-token","x","-config",os.path.join(tmp,"dup.json")],capture_output=True,text=True)
res.append(ok(r3.returncode!=0 and "https" in r3.stderr,"агент не работает по голому http вне localhost"))
ag=subprocess.Popen([AGENT,"run","-config",cfg],stdout=open(os.path.join(tmp,"agent.log"),"w"),stderr=subprocess.STDOUT)
time.sleep(4)
s,hosts,_=call("/api/hosts")
res.append(ok(s==200 and len(hosts)==1 and hosts[0]["online"] and hosts[0]["posture_at"],"хост в списке, на связи, отчёт получен"))
hid=hosts[0]["id"]
s,d,_=call("/api/hosts/"+hid)
res.append(ok(len(d["checks"])>=2 and d["info"].get("os"),"подробности хоста: проверок=%d"%len(d["checks"])))
t0=d["posture_at"]
call("/api/hosts/"+hid+"/refresh","POST",{})
time.sleep(3)
s,d,_=call("/api/hosts/"+hid)
res.append(ok(d["posture_at"]>t0,"команда «обновить» дошла до агента (длинный опрос)"))
# чужой ключ
bad=urllib.request.Request(B+"/agent/poll",data=b"{}",method="POST",headers={"Content-Type":"application/json","Authorization":"Bearer "+hid+".wrong"})
try: urllib.request.urlopen(bad,timeout=5); res.append(ok(False,"неверный ключ хоста должен давать 401"))
except urllib.error.HTTPError as e: res.append(ok(e.code==401,"неверный ключ хоста -> 401"))
s,d,_=call("/api/audit")
res.append(ok(s==200 and any(r["action"]=="enrolled" for r in d),"аудит содержит регистрацию хоста"))
# удаление хоста -> агент должен остановиться по 401
call("/api/hosts/"+hid,"DELETE")
time.sleep(30)
res.append(ok(ag.poll() is not None,"после удаления хоста агент завершился (401)"))
ag.terminate()
print("\nИТОГО: %d/%d"%(sum(res),len(res)))
srv.terminate()
sys.exit(0 if all(res) else 1)
