"""Сетевая карта: хранение снимков от агентов и сборка графа связей и топологии.
Данные только пассивные: то, что сам хост видит у себя (интерфейсы, ARP, соединения). Ничего не сканируется."""
import ipaddress
import json
import time

from . import db

KEEP_SEC = 7 * 86400
MAX_EDGES_PER_HOST = 600

# порт -> (название службы, категория); категории окрашивают связи на карте
SERVICES = {
    22: ("SSH", "admin"), 23: ("Telnet", "admin"), 3389: ("RDP", "admin"), 5900: ("VNC", "admin"), 9090: ("Cockpit", "admin"),
    80: ("HTTP", "web"), 443: ("HTTPS", "web"), 8080: ("HTTP-alt", "web"), 8443: ("HTTPS-alt", "web"), 3000: ("Grafana/Node", "web"),
    53: ("DNS", "infra"), 123: ("NTP", "infra"), 67: ("DHCP", "infra"), 389: ("LDAP", "infra"), 636: ("LDAPS", "infra"), 88: ("Kerberos", "infra"),
    514: ("Syslog", "logs"), 1514: ("Wazuh/Syslog", "logs"), 1515: ("Wazuh", "logs"), 5044: ("Beats", "logs"), 9200: ("Elasticsearch", "logs"),
    9000: ("Graylog/Portainer", "logs"), 12201: ("GELF", "logs"), 5601: ("Kibana", "logs"), 3100: ("Loki", "logs"),
    3306: ("MySQL", "db"), 5432: ("PostgreSQL", "db"), 6379: ("Redis", "db"), 27017: ("MongoDB", "db"), 1433: ("MSSQL", "db"), 5672: ("RabbitMQ", "db"),
    25: ("SMTP", "mail"), 465: ("SMTPS", "mail"), 587: ("SMTP", "mail"), 143: ("IMAP", "mail"), 993: ("IMAPS", "mail"),
    445: ("SMB", "files"), 139: ("SMB", "files"), 2049: ("NFS", "files"), 21: ("FTP", "files"), 548: ("AFP", "files"), 873: ("rsync", "files"),
    9100: ("Node exporter", "mon"), 9093: ("Alertmanager", "mon"), 10050: ("Zabbix agent", "mon"), 10051: ("Zabbix", "mon"), 161: ("SNMP", "mon"),
    1883: ("MQTT", "infra"), 8883: ("MQTTS", "infra"), 5353: ("mDNS", "infra"), 1900: ("SSDP", "infra"), 8009: ("Chromecast", "other"), 8123: ("Home Assistant", "web"),
    8000: ("HTTP-alt", "web"), 5000: ("HTTP-alt", "web"), 8008: ("HTTP-alt", "web"),
}


def service_of(port):
    s = SERVICES.get(port)
    return {"name": s[0], "cat": s[1]} if s else {"name": str(port), "cat": "other"}


def _ip(v):
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def _s(v, n):
    return str(v or "")[:n]


def clean_snap(d):
    """Проверка и очистка снимка от агента: типы, длины, корректные адреса."""
    if not isinstance(d, dict):
        return None
    out = {"at": int(d.get("at") or time.time()), "ifaces": [], "gateways": [], "dns": [], "neigh": [], "listen": [], "conns": []}
    for it in (d.get("ifaces") or [])[:64]:
        if not isinstance(it, dict):
            continue
        addrs = []
        for a in (it.get("addrs") or [])[:16]:
            try:
                addrs.append(str(ipaddress.ip_interface(str(a))))
            except ValueError:
                pass
        out["ifaces"].append({"name": _s(it.get("name"), 40), "mac": _s(it.get("mac"), 20).lower(), "addrs": addrs,
                              "up": bool(it.get("up")), "virtual": bool(it.get("virtual"))})
    for k in ("gateways", "dns"):
        out[k] = [x for x in (_ip(i) for i in (d.get(k) or [])[:16]) if x]
    for it in (d.get("neigh") or [])[:300]:
        if isinstance(it, dict) and _ip(it.get("ip")):
            out["neigh"].append({"ip": _ip(it["ip"]), "mac": _s(it.get("mac"), 20).lower(), "dev": _s(it.get("dev"), 40)})
    for it in (d.get("listen") or [])[:200]:
        if isinstance(it, dict) and isinstance(it.get("port"), int) and 0 < it["port"] < 65536:
            out["listen"].append({"port": it["port"], "addr": _ip(it.get("addr")) or "", "proc": _s(it.get("proc"), 60)})
    for it in (d.get("conns") or [])[:400]:
        if not isinstance(it, dict) or it.get("dir") not in ("in", "out") or not _ip(it.get("peer")):
            continue
        p = it.get("port")
        if not isinstance(p, int) or not 0 < p < 65536:
            continue
        n = it.get("n")
        out["conns"].append({"dir": it["dir"], "peer": _ip(it["peer"]), "port": p, "proc": _s(it.get("proc"), 60),
                             "n": n if isinstance(n, int) and n > 0 else 1})
    return out


def record(hid, snap, now):
    """Сохраняет последний снимок и накапливает рёбра (кто к кому подключался)."""
    db.x("INSERT OR REPLACE INTO host_net(host_id,at,data) VALUES(?,?,?)", (hid, now, json.dumps(snap, ensure_ascii=False)))
    for c in snap["conns"][:MAX_EDGES_PER_HOST]:
        row = db.q1("SELECT procs FROM net_edges WHERE host_id=? AND peer=? AND port=? AND dir=?", (hid, c["peer"], c["port"], c["dir"]))
        procs = set(json.loads(row["procs"])) if row else set()
        if c["proc"]:
            procs.add(c["proc"])
        procs = sorted(procs)[:8]
        if row:
            db.x("UPDATE net_edges SET last=?, n=?, samples=samples+1, procs=? WHERE host_id=? AND peer=? AND port=? AND dir=?",
                 (now, c["n"], json.dumps(procs, ensure_ascii=False), hid, c["peer"], c["port"], c["dir"]))
        else:
            db.x("INSERT INTO net_edges(host_id,peer,port,dir,procs,first,last,n,samples) VALUES(?,?,?,?,?,?,?,?,1)",
                 (hid, c["peer"], c["port"], c["dir"], json.dumps(procs, ensure_ascii=False), now, now, c["n"]))
    db.x("DELETE FROM net_edges WHERE last<?", (now - KEEP_SEC,))


def _is_private(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_link_local


def _lan_nets(iface):
    """IPv4-подсети интерфейса, не служебные: без link-local и loopback."""
    for a in iface.get("addrs", []):
        i = ipaddress.ip_interface(a)
        if i.version == 4 and not i.ip.is_link_local and not i.ip.is_loopback and i.network.prefixlen < 32:
            yield i


def _load(now, online_window):
    hosts = db.q("SELECT id,name,os,last_seen FROM hosts")
    snaps = {}
    for r in db.q("SELECT host_id,at,data FROM host_net"):
        snaps[r["host_id"]] = (r["at"], json.loads(r["data"]))
    labels = {r["ip"]: {"name": r["name"], "note": r["note"] or ""} for r in db.q("SELECT ip,name,note FROM net_labels")}
    ip2host = {}
    for h in hosts:
        sn = snaps.get(h["id"])
        if not sn:
            continue
        for itf in sn[1]["ifaces"]:
            if itf["virtual"] or not itf["up"]:
                continue
            for a in itf["addrs"]:
                i = ipaddress.ip_interface(a)
                if not i.ip.is_link_local and not i.ip.is_loopback:
                    ip2host.setdefault(str(i.ip), h["id"])
    return hosts, snaps, labels, ip2host


def build_map(hours, now, online_window, external="group"):
    """Граф: узлы — хосты, неизвестные устройства сети и «Интернет»; рёбра — группы соединений по службе."""
    hosts, snaps, labels, ip2host = _load(now, online_window)
    since = now - hours * 3600
    nodes = {}
    for h in hosts:
        sn = snaps.get(h["id"])
        ips = []
        if sn:
            for itf in sn[1]["ifaces"]:
                if not itf["virtual"] and itf["up"]:
                    ips += [str(i.ip) for i in _lan_nets(itf)]
        nodes[h["id"]] = {"id": h["id"], "kind": "host", "name": h["name"], "ips": ips, "os": h["os"],
                          "online": bool(h["last_seen"] and now - h["last_seen"] <= online_window),
                          "collecting": sn is not None, "listen": len(sn[1]["listen"]) if sn else 0}
    links = {}

    def node_for(ip):
        if ip in ip2host:
            return ip2host[ip]
        if _is_private(ip):
            nid = "ip:" + ip
            if nid not in nodes:
                lb = labels.get(ip)
                nodes[nid] = {"id": nid, "kind": "device", "name": lb["name"] if lb else ip, "ips": [ip], "labeled": bool(lb)}
            return nid
        if external == "ip":
            nid = "ip:" + ip
            if nid not in nodes:
                lb = labels.get(ip)
                nodes[nid] = {"id": nid, "kind": "external", "name": lb["name"] if lb else ip, "ips": [ip], "labeled": bool(lb)}
            return nid
        if "inet" not in nodes:
            nodes["inet"] = {"id": "inet", "kind": "internet", "name": "Интернет", "ips": [], "count": 0}
        nodes["inet"]["ips"].append(ip)
        return "inet"

    for e in db.q("SELECT host_id,peer,port,dir,procs,first,last,n,samples FROM net_edges WHERE last>=?", (since,)):
        if e["host_id"] not in nodes:
            continue
        peer = node_for(e["peer"])
        if peer == e["host_id"]:
            continue
        a, b = (e["host_id"], peer) if e["dir"] == "out" else (peer, e["host_id"])
        k = (a, b, e["port"])
        L = links.get(k)
        procs = json.loads(e["procs"])
        if not L:
            sv = service_of(e["port"])
            L = links[k] = {"from": a, "to": b, "port": e["port"], "service": sv["name"], "cat": sv["cat"], "n": 0, "first": e["first"], "last": e["last"],
                            "procs": [], "peers": set(), "samples": 0}
        L["n"] = max(L["n"], e["n"]) if (a in nodes and b in nodes and nodes[a]["kind"] == "host" and nodes[b]["kind"] == "host") else L["n"] + e["n"]
        L["first"], L["last"] = min(L["first"], e["first"]), max(L["last"], e["last"])
        L["samples"] += e["samples"]
        L["peers"].add(e["peer"])
        for p in procs:
            if p not in L["procs"]:
                L["procs"].append(p)
    out_links = []
    for L in links.values():
        L["peers"] = len(L["peers"])
        L["procs"] = L["procs"][:8]
        out_links.append(L)
    out_links.sort(key=lambda l: -l["n"])
    if "inet" in nodes:
        nodes["inet"]["ips"] = sorted(set(nodes["inet"]["ips"]))
        nodes["inet"]["count"] = len(nodes["inet"]["ips"])
        nodes["inet"]["ips"] = nodes["inet"]["ips"][:20]
    return {"now": now, "hours": hours, "nodes": list(nodes.values()), "links": out_links[:1500]}


def build_topology(now, online_window):
    """Подсети: хосты с агентами, шлюз, DNS и соседи по ARP, которых мы не знаем (неизвестные устройства)."""
    hosts, snaps, labels, ip2host = _load(now, online_window)
    names = {h["id"]: h["name"] for h in hosts}
    nets = {}
    for h in hosts:
        sn = snaps.get(h["id"])
        if not sn:
            continue
        for itf in sn[1]["ifaces"]:
            if itf["virtual"] or not itf["up"]:
                continue
            for i in _lan_nets(itf):
                n = nets.setdefault(str(i.network), {"cidr": str(i.network), "hosts": [], "gateways": {}, "dns": {}, "devices": {}, "_net": i.network})
                n["hosts"].append({"id": h["id"], "name": h["name"], "ip": str(i.ip), "mac": itf["mac"], "iface": itf["name"]})
    for hid, (at, sn) in snaps.items():
        for n in nets.values():
            if not any(x["id"] == hid for x in n["hosts"]):
                continue
            for g in sn["gateways"]:
                if ipaddress.ip_address(g) in n["_net"]:
                    n["gateways"].setdefault(g, set()).add(hid)
            for g in sn["dns"]:
                if ipaddress.ip_address(g) in n["_net"]:
                    n["dns"].setdefault(g, set()).add(hid)
            for nb in sn["neigh"]:
                ip = ipaddress.ip_address(nb["ip"])
                if ip.version == 4 and ip in n["_net"] and nb["ip"] not in ip2host:
                    d = n["devices"].setdefault(nb["ip"], {"ip": nb["ip"], "mac": nb["mac"], "seen_by": set()})
                    d["seen_by"].add(hid)
    res = []
    for n in sorted(nets.values(), key=lambda n: n["cidr"]):
        devs = []
        for ip, d in sorted(n["devices"].items(), key=lambda kv: ipaddress.ip_address(kv[0])):
            lb = labels.get(ip)
            devs.append({"ip": ip, "mac": d["mac"], "name": lb["name"] if lb else "", "note": lb["note"] if lb else "",
                         "gateway": ip in n["gateways"], "dns": ip in n["dns"], "seen_by": sorted(names.get(x, x) for x in d["seen_by"])})
        for g in list(n["gateways"]) + list(n["dns"]):
            if g in ip2host and g not in [h["ip"] for h in n["hosts"]]:
                pass
        res.append({"cidr": n["cidr"], "hosts": sorted(n["hosts"], key=lambda h: ipaddress.ip_address(h["ip"])),
                    "gateways": [{"ip": g, "host": names.get(ip2host.get(g, ""), ""), "by": len(v)} for g, v in n["gateways"].items()],
                    "dns": [{"ip": g, "host": names.get(ip2host.get(g, ""), ""), "by": len(v)} for g, v in n["dns"].items()],
                    "devices": devs})
    return {"now": now, "subnets": res, "collecting": len(snaps), "hosts": len(hosts)}


def host_view(hid):
    row = db.q1("SELECT at,data FROM host_net WHERE host_id=?", (hid,))
    if not row:
        return {"at": None}
    sn = json.loads(row["data"])
    for l in sn["listen"]:
        l["service"] = service_of(l["port"])["name"]
    for c in sn["conns"]:
        c["service"] = service_of(c["port"])["name"]
    ips = {}
    sn["labels"] = {r["ip"]: r["name"] for r in db.q("SELECT ip,name FROM net_labels")}
    ip2host = {}
    for r in db.q("SELECT id,name FROM hosts"):
        s = db.q1("SELECT data FROM host_net WHERE host_id=?", (r["id"],))
        if s:
            for itf in json.loads(s["data"])["ifaces"]:
                if not itf["virtual"]:
                    for a in itf["addrs"]:
                        ip2host[str(ipaddress.ip_interface(a).ip)] = r["name"]
    sn["hosts"] = ip2host
    return {"at": row["at"], **sn}


def set_label(ip, name, note, now):
    ip = _ip(ip)
    if not ip:
        return False
    name = _s(name, 80).strip()
    if not name:
        db.x("DELETE FROM net_labels WHERE ip=?", (ip,))
    else:
        db.x("INSERT OR REPLACE INTO net_labels(ip,name,note,updated) VALUES(?,?,?,?)", (ip, name, _s(note, 300), now))
    return True


def forget_host(hid):
    db.x("DELETE FROM host_net WHERE host_id=?", (hid,))
    db.x("DELETE FROM net_edges WHERE host_id=?", (hid,))
