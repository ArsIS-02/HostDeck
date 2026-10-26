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
CAF = os.path.join(tmp, "ca.pem")
open(CAF, "w").write("-----BEGIN CERTIFICATE-----\ntest-only\n-----END CERTIFICATE-----\n")
env = dict(os.environ, HOSTDECK_CA_FILE=CAF, HOSTDECK_AGENT_DIR=os.path.join(ROOT, "dist"), HOSTDECK_DB=os.path.join(tmp, "t.db"), HOSTDECK_ADMIN_PASSWORD=pw)
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
import hashlib as _h
caw=_h.sha256(open(CAF,"rb").read()).hexdigest()
res.append(ok(d.get("ca_sha256")==caw,"ответ с токеном содержит отпечаток CA"))
sc_,cab=(lambda r:(r.status,r.read()))(urllib.request.urlopen(B+"/ca.pem",timeout=10))
res.append(ok(sc_==200 and cab==open(CAF,"rb").read(),"/ca.pem отдаёт сертификат CA"))
bashfp=subprocess.run(["bash","-c",'(sha256sum || shasum -a 256) < "%s" | cut -d" " -f1'%CAF],capture_output=True,text=True).stdout.strip()
res.append(ok(bashfp==caw,"отпечаток из команды установки совпадает с серверным"))
# установка: скрипт и бинарники отдаёт сервер
def raw(path,headers=None):
    r=urllib.request.Request(B+path,headers=headers or {})
    try:
        with urllib.request.urlopen(r,timeout=20) as resp: return resp.status,resp.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
s,scr=raw("/install.sh")
res.append(ok(s==200 and (B).encode() in scr and b"@@SERVER@@" not in scr.replace(b'"@@SERVER@@"',b'').replace(b"@@*",b""),"/install.sh отдаётся с адресом сервера, без входа"))
res.append(ok(raw("/install.sh",{"Host":"x;rm -rf /"})[0]==400,"/install.sh отклоняет подозрительный заголовок Host"))
s,sums=raw("/dl/SHA256SUMS")
res.append(ok(s==200 and b"hostdeck-agent-linux-amd64" in sums and b"hostdeck-agent-darwin-arm64" in sums,"SHA256SUMS перечисляет агентов"))
s,binr=raw("/dl/hostdeck-agent-linux-amd64")
import hashlib
want=[l.split()[0] for l in sums.decode().splitlines() if l.endswith("hostdeck-agent-linux-amd64")][0]
res.append(ok(s==200 and hashlib.sha256(binr).hexdigest()==want,"бинарник скачивается, сумма совпадает"))
res.append(ok(raw("/dl/..%2f..%2fetc%2fpasswd")[0]==404 and raw("/dl/evil")[0]==404,"/dl не отдаёт посторонние файлы"))
sc=os.path.join(tmp,"install.sh"); open(sc,"wb").write(scr)
r=subprocess.run(["bash",sc,"dryrun-token"],env=dict(os.environ,HOSTDECK_DRYRUN="1"),capture_output=True,text=True)
res.append(ok(r.returncode==0 and "Контрольная сумма совпала" in r.stdout and "DRYRUN" in r.stdout,"скрипт установки: скачивание и проверка суммы (dry-run) "+r.stdout.strip().replace("\n"," | ")[-120:]+r.stderr[-120:]))
res.append(ok(d.get("install_sha256")==hashlib.sha256(scr).hexdigest(),"хеш скрипта в ответе с токеном совпадает с отданным скриптом"))
res.append(ok(b"@@SUMS@@" not in scr and want.encode() in scr,"контрольные суммы агентов вшиты в скрипт"))
r=subprocess.run(["bash",sc,"dryrun-token"],env=dict(os.environ,HOSTDECK_DRYRUN="1",HOSTDECK_CA=CAF,PATH="/nonexistent-curl:"+os.environ["PATH"]),capture_output=True,text=True)
res.append(ok(r.returncode==0 and "DRYRUN" in r.stdout,"режим с CA: суммы берутся из скрипта (dry-run) "+(r.stdout+r.stderr).strip().replace("\n"," | ")[-120:]))
# агент
env=dict(os.environ); cfg=os.path.join(tmp,"agent.json")
if os.path.exists(cfg): os.remove(cfg)
r=subprocess.run([AGENT,"enroll","-server",B,"-token",tok,"-name","sandbox-linux","-terminal","-config",cfg],capture_output=True,text=True)
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
ids={c["id"] for c in d["checks"]}
res.append(ok("platform" not in ids and "disk" in ids and ("iptables" in ids or "failed_units" in ids or "pkg_updates" in ids),"Linux-проверки собраны: "+", ".join(sorted(ids))))
want={"uid0","empty_pw","sudo_nopasswd","pw_policy","sysctl","tmp_mount","log_forward","integrity","freeipa","ports","sec_updates"}
res.append(ok(len(want-ids)<=1,"проверки соответствия Linux собраны (нет: %s)"%", ".join(sorted(want-ids))))
t0=d["posture_at"]
call("/api/hosts/"+hid+"/refresh","POST",{})
time.sleep(3)
s,d,_=call("/api/hosts/"+hid)
res.append(ok(d["posture_at"]>t0,"команда «обновить» дошла до агента (длинный опрос)"))
# метрики и ПО
s,d,_=call("/api/hosts/"+hid)
res.append(ok(d.get("metrics") and d["metrics"].get("cores",0)>=1 and "mem_total" in d["metrics"],"метрики для приборов получены"))
s,sw,_=call("/api/hosts/"+hid+"/software")
res.append(ok(s==200 and len(sw["items"])>0 and sw["at"],"список ПО получен: %d"%len(sw["items"])))
call("/api/hosts/"+hid+"/software/refresh","POST",{})
time.sleep(4)
s,d,_=call("/api/hosts/"+hid)
res.append(ok(d.get("software_count")==len(sw["items"]),"software_count в сводке хоста"))
res.append(ok(call("/api/hosts/"+hid+"/software/refresh","POST",{},opener=anon)[0]==401,"запрос ПО без входа -> 401"))
# терминал (root-консоль): сессия, ввод, вывод, закрытие
import threading, base64
res.append(ok(call("/api/hosts/"+hid+"/term","POST",{"cols":100,"rows":30},opener=anon)[0]==401,"терминал без входа -> 401"))
s,d,_=call("/api/hosts/"+hid+"/term","POST",{"cols":100,"rows":30})
res.append(ok(s==200 and d.get("sid"),"сессия терминала открыта"))
sid=d["sid"]
got=bytearray()
def reader():
    r=urllib.request.Request(B+"/api/term/"+sid+"/stream")
    try:
        with op.open(r,timeout=30) as resp:
            ev=None
            for line in resp:
                line=line.decode().rstrip("\n")
                if line.startswith("event:"): ev=line[6:].strip()
                elif line.startswith("data:"):
                    if ev=="exit": return
                    got.extend(base64.b64decode(line[5:].strip()))
                elif line=="": ev=None
    except Exception as e: got.extend(("ERR "+str(e)).encode())
th=threading.Thread(target=reader,daemon=True); th.start()
time.sleep(1.5)
call("/api/term/"+sid+"/input","POST",{"d":"id -u; echo hd-$((20+22))\r"})
for _ in range(30):
    if b"hd-42" in got: break
    time.sleep(0.3)
txt=got.decode(errors="replace")
res.append(ok("hd-42" in txt,"команда выполнена в консоли, вывод получен через SSE"))
res.append(ok("\r0\r\nhd-42" in txt and "root@" in txt,"оболочка работает от root (id -u = 0)"))
call("/api/term/"+sid+"/input","POST",{"d":"exit\r"})
th.join(15)
res.append(ok(not th.is_alive(),"после exit поток вывода завершён событием exit"))
s,au,_=call("/api/audit")
au=au["rows"]
acts=[r["action"] for r in au]
res.append(ok("term-open" in acts and "term-closed" in acts,"аудит: открытие и закрытие консоли"))
# хост без разрешения консоли
s,d2,_=call("/api/enroll-tokens","POST",{"label":"noterm"})
cfg2=os.path.join(tmp,"agent2.json")
subprocess.run([AGENT,"enroll","-server",B,"-token",d2["token"],"-name","no-term","-config",cfg2],capture_output=True)
ag2=subprocess.Popen([AGENT,"run","-config",cfg2],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(4)
s,hs,_=call("/api/hosts")
h2=[h for h in hs if h["name"]=="no-term"][0]
s,d3,_=call("/api/hosts/"+h2["id"]+"/term","POST",{"cols":100,"rows":30})
res.append(ok(s==409,"консоль на хосте без allow_terminal отклонена (409)"))
ag2.terminate()
# чужой ключ
bad=urllib.request.Request(B+"/agent/poll",data=b"{}",method="POST",headers={"Content-Type":"application/json","Authorization":"Bearer "+hid+".wrong"})
try: urllib.request.urlopen(bad,timeout=5); res.append(ok(False,"неверный ключ хоста должен давать 401"))
except urllib.error.HTTPError as e: res.append(ok(e.code==401,"неверный ключ хоста -> 401"))
s,d,_=call("/api/audit")
res.append(ok(s==200 and any(r["action"]=="enrolled" and r["host_name"] for r in d["rows"]),"аудит содержит регистрацию хоста с именем"))
# удаление хоста -> агент должен остановиться по 401, а из базы пропасть всё
import sqlite3
s,dd,_=call("/api/hosts/"+hid,"DELETE")
res.append(ok(s==200 and dd.get("deleted")==1,"удаление хоста: ответ"))
cx=sqlite3.connect(os.path.join(tmp,"t.db"))
res.append(ok(cx.execute("SELECT COUNT(*) FROM hosts WHERE id=?",(hid,)).fetchone()[0]==0,"хост удалён из базы данных"))
res.append(ok(call("/api/hosts/"+hid,"DELETE")[0]==404,"повторное удаление -> 404"))
s,au2,_=call("/api/audit")
dl=[r for r in au2["rows"] if r["action"]=="host-deleted" and r["host"]==hid]
res.append(ok(dl and dl[0]["host_name"]=="sandbox-linux","журнал помнит имя удалённого хоста"))
# массовое удаление
ids=[]
for nm in ("bulk-a","bulk-b"):
    s,t,_=call("/api/enroll-tokens","POST",{"label":nm})
    cfgx=os.path.join(tmp,nm+".json")
    subprocess.run([AGENT,"enroll","-server",B,"-token",t["token"],"-name",nm,"-config",cfgx],capture_output=True)
s,hs,_=call("/api/hosts")
ids=[h["id"] for h in hs if h["name"].startswith("bulk-")]
res.append(ok(len(ids)==2,"для массового удаления зарегистрировано 2 хоста"))
res.append(ok(call("/api/hosts/delete","POST",{"ids":[]})[0]==400 and call("/api/hosts/delete","POST",{"ids":"x"})[0]==400,"массовое удаление: пустой и неверный список отклоняются"))
s,dd,_=call("/api/hosts/delete","POST",{"ids":ids+["несуществующий"]})
res.append(ok(s==200 and dd.get("deleted")==2,"массовое удаление: удалено 2, лишний id пропущен"))
res.append(ok(cx.execute("SELECT COUNT(*) FROM hosts WHERE name LIKE 'bulk-%'").fetchone()[0]==0,"массовое удаление: в базе хостов не осталось"))
time.sleep(30)
res.append(ok(ag.poll() is not None,"после удаления хоста агент завершился (401)"))
ag.terminate()
print("\nИТОГО: %d/%d"%(sum(res),len(res)))
srv.terminate()
sys.exit(0 if all(res) else 1)
