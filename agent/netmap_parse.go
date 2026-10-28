package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Сетевая карта: агент отдаёт только то, что видит хост (интерфейсы, шлюз, соседей по ARP, слушающие порты и
// установленные TCP-соединения). Ничего не сканируется, чужой трафик не перехватывается, содержимое пакетов не читается.

type NetIface struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac,omitempty"`
	Addrs   []string `json:"addrs"` // адреса в виде CIDR
	Up      bool     `json:"up"`
	Virtual bool     `json:"virtual,omitempty"` // мосты и пары veth контейнеров, туннели, служебные интерфейсы
}

type NetNeigh struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
	Dev string `json:"dev,omitempty"`
}

type NetListen struct {
	Port int    `json:"port"`
	Addr string `json:"addr"` // адрес привязки: 0.0.0.0, ::, конкретный адрес или 127.0.0.1
	Proc string `json:"proc,omitempty"`
	PID  int    `json:"pid,omitempty"`
}

// NetConn — агрегированные установленные TCP-соединения одного процесса с одним адресом.
type NetConn struct {
	Dir  string `json:"dir"`            // out — хост подключился сам, in — к хосту подключились
	Peer string `json:"peer"`           // адрес другой стороны
	Port int    `json:"port"`           // порт службы: для out удалённый, для in — локальный слушающий
	Proc string `json:"proc,omitempty"` // процесс на этом хосте
	N    int    `json:"n"`              // число одновременных соединений в момент снимка
}

type NetSnap struct {
	At       int64       `json:"at"`
	Ifaces   []NetIface  `json:"ifaces"`
	Gateways []string    `json:"gateways,omitempty"`
	DNS      []string    `json:"dns,omitempty"`
	Neigh    []NetNeigh  `json:"neigh,omitempty"`
	Listen   []NetListen `json:"listen,omitempty"`
	Conns    []NetConn   `json:"conns,omitempty"`
}

const (
	netMaxConns  = 400
	netMaxListen = 200
	netMaxNeigh  = 300
)

// rawSock — строка таблицы сокетов до сопоставления с процессами.
type rawSock struct {
	State string // LISTEN, ESTABLISHED
	LAddr string
	LPort int
	RAddr string
	RPort int
	Inode string // только Linux
	Proc  string // только macOS (из lsof)
	PID   int
}

// virtualIface — интерфейсы, которые не соединяют хост с домашней сетью: мосты контейнеров, туннели, служебные.
func virtualIface(name string) bool {
	for _, p := range []string{"lo", "veth", "docker", "br-", "cni", "podman", "virbr", "vnet", "tun", "tap", "utun", "awdl", "llw", "bridge", "ap", "anpi", "gif", "stf", "vmnet", "flannel", "cali", "kube"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// hexIP разбирает адрес из /proc/net/tcp: 8 hex-символов (IPv4) или 32 (IPv6), слова в порядке байтов хоста (little-endian).
func hexIP(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	switch len(b) {
	case 4:
		return net.IPv4(b[3], b[2], b[1], b[0]).String()
	case 16:
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i*4], ip[i*4+1], ip[i*4+2], ip[i*4+3] = b[i*4+3], b[i*4+2], b[i*4+1], b[i*4]
		}
		return normIP(ip.String())
	}
	return ""
}

// normIP приводит ::ffff:a.b.c.d к a.b.c.d и убирает зону (fe80::1%en0).
func normIP(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// parseProcNetTCP разбирает /proc/net/tcp и /proc/net/tcp6: только LISTEN (0A) и ESTABLISHED (01).
func parseProcNetTCP(data string) []rawSock {
	var out []rawSock
	for i, ln := range strings.Split(data, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 10 {
			continue
		}
		var st string
		switch f[3] {
		case "0A":
			st = "LISTEN"
		case "01":
			st = "ESTABLISHED"
		default:
			continue
		}
		l, r := strings.Split(f[1], ":"), strings.Split(f[2], ":")
		if len(l) != 2 || len(r) != 2 {
			continue
		}
		lp, err1 := strconv.ParseUint(l[1], 16, 16)
		rp, err2 := strconv.ParseUint(r[1], 16, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, rawSock{State: st, LAddr: hexIP(l[0]), LPort: int(lp), RAddr: hexIP(r[0]), RPort: int(rp), Inode: f[9]})
	}
	return out
}

// parseProcARP разбирает /proc/net/arp: IP address, HW type, Flags, HW address, Mask, Device. Неполные записи (флаг 0x0) пропускаются.
func parseProcARP(data string) []NetNeigh {
	var out []NetNeigh
	for i, ln := range strings.Split(data, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 6 {
			continue
		}
		mac := strings.ToLower(f[3])
		if f[2] == "0x0" || mac == "00:00:00:00:00:00" || net.ParseIP(f[0]) == nil {
			continue
		}
		out = append(out, NetNeigh{IP: f[0], MAC: mac, Dev: f[5]})
	}
	return out
}

// parseProcRoute возвращает шлюзы по умолчанию из /proc/net/route (отбор: адрес назначения 0, флаги UP|GATEWAY).
func parseProcRoute(data string) []string {
	var out []string
	for i, ln := range strings.Split(data, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 4 || f[1] != "00000000" {
			continue
		}
		fl, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || fl&0x3 != 0x3 {
			continue
		}
		if ip := hexIP(f[2]); ip != "" && ip != "0.0.0.0" {
			out = append(out, ip)
		}
	}
	return uniqStr(out)
}

// parseResolvConf возвращает адреса серверов имён из /etc/resolv.conf.
func parseResolvConf(data string) []string {
	var out []string
	for _, ln := range strings.Split(data, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := normIP(f[1]); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return uniqStr(out)
}

// parseLsof разбирает вывод `lsof -nP -iTCP -F pcnT` (macOS): процесс, команда, имя сокета, состояние.
func parseLsof(data string) []rawSock {
	var out []rawSock
	var pid int
	var cmd, name, st string
	flush := func() {
		if name == "" {
			return
		}
		defer func() { name, st = "", "" }()
		local, remote := name, ""
		if i := strings.Index(name, "->"); i >= 0 {
			local, remote = name[:i], name[i+2:]
		}
		la, lp, ok := splitHostPort(local)
		if !ok {
			return
		}
		rs := rawSock{LAddr: la, LPort: lp, Proc: cmd, PID: pid}
		switch st {
		case "LISTEN":
			rs.State = "LISTEN"
		case "ESTABLISHED":
			ra, rp, ok := splitHostPort(remote)
			if !ok {
				return
			}
			rs.State, rs.RAddr, rs.RPort = "ESTABLISHED", ra, rp
		default:
			return
		}
		out = append(out, rs)
	}
	for _, ln := range strings.Split(data, "\n") {
		if ln == "" {
			continue
		}
		v := ln[1:]
		switch ln[0] {
		case 'p':
			flush()
			pid, _ = strconv.Atoi(v)
			cmd = ""
		case 'c':
			cmd = v
		case 'f':
			flush()
		case 'n':
			name = v
		case 'T':
			if strings.HasPrefix(v, "ST=") {
				st = v[3:]
			}
		}
	}
	flush()
	return out
}

// splitHostPort разбирает "192.168.1.5:443", "*:22", "[fe80::1]:5353".
func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	h := strings.Trim(s[:i], "[]")
	if h == "*" {
		return "0.0.0.0", p, true
	}
	if h = normIP(h); h == "" {
		return "", 0, false
	}
	return h, p, true
}

// parseARPMac разбирает `arp -an` (macOS): "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]".
func parseARPMac(data string) []NetNeigh {
	var out []NetNeigh
	for _, ln := range strings.Split(data, "\n") {
		a, b := strings.Index(ln, "("), strings.Index(ln, ")")
		if a < 0 || b < a {
			continue
		}
		f := strings.Fields(ln[b+1:])
		if len(f) < 3 || f[0] != "at" || strings.Contains(f[1], "incomplete") {
			continue
		}
		mac := normMAC(f[1])
		ip := ln[a+1 : b]
		if mac == "" || net.ParseIP(ip) == nil || ip == "255.255.255.255" || strings.HasPrefix(mac, "ff:ff") {
			continue
		}
		dev := ""
		if len(f) >= 4 && f[2] == "on" {
			dev = f[3]
		}
		out = append(out, NetNeigh{IP: ip, MAC: mac, Dev: dev})
	}
	return out
}

// normMAC дополняет нулями байты вида "a:b:c:1:2:3" (так их печатает macOS) и приводит к нижнему регистру.
func normMAC(s string) string {
	p := strings.Split(strings.ToLower(s), ":")
	if len(p) != 6 {
		return ""
	}
	for i, x := range p {
		if len(x) == 1 {
			p[i] = "0" + x
		}
		if len(p[i]) != 2 {
			return ""
		}
	}
	return strings.Join(p, ":")
}

// parseRouteGet разбирает `route -n get default` (macOS): строку "gateway: 192.168.1.1".
func parseRouteGet(data string) []string {
	for _, ln := range strings.Split(data, "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[0] == "gateway:" {
			if ip := normIP(f[1]); ip != "" {
				return []string{ip}
			}
		}
	}
	return nil
}

// parseScutilDNS разбирает `scutil --dns`: строки "nameserver[0] : 192.168.1.1".
func parseScutilDNS(data string) []string {
	var out []string
	for _, ln := range strings.Split(data, "\n") {
		if !strings.Contains(ln, "nameserver[") {
			continue
		}
		if i := strings.Index(ln, " : "); i >= 0 {
			if ip := normIP(strings.TrimSpace(ln[i+3:])); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return uniqStr(out)
}

func uniqStr(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsUnspecified())
}

// buildNet собирает снимок из таблицы сокетов. procOf сопоставляет сокет с процессом (на macOS процесс уже указан в строке).
func buildNet(socks []rawSock, procOf func(rawSock) (string, int), own map[string]bool) ([]NetListen, []NetConn) {
	var listens []NetListen
	listening := map[int]bool{}
	for _, s := range socks {
		if s.State != "LISTEN" {
			continue
		}
		name, pid := procOf(s)
		listens = append(listens, NetListen{Port: s.LPort, Addr: s.LAddr, Proc: name, PID: pid})
		listening[s.LPort] = true
	}
	type key struct {
		dir, peer, proc string
		port            int
	}
	agg := map[key]int{}
	for _, s := range socks {
		if s.State != "ESTABLISHED" || isLoopback(s.RAddr) || isLoopback(s.LAddr) || own[s.RAddr] && own[s.LAddr] {
			continue
		}
		name, _ := procOf(s)
		k := key{dir: "out", peer: s.RAddr, proc: name, port: s.RPort}
		if listening[s.LPort] {
			k = key{dir: "in", peer: s.RAddr, proc: name, port: s.LPort}
		}
		agg[k]++
	}
	var conns []NetConn
	for k, n := range agg {
		conns = append(conns, NetConn{Dir: k.dir, Peer: k.peer, Port: k.port, Proc: k.proc, N: n})
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].N != conns[j].N {
			return conns[i].N > conns[j].N
		}
		return fmt.Sprint(conns[i].Peer, conns[i].Port, conns[i].Dir, conns[i].Proc) < fmt.Sprint(conns[j].Peer, conns[j].Port, conns[j].Dir, conns[j].Proc)
	})
	if len(conns) > netMaxConns {
		conns = conns[:netMaxConns]
	}
	// слушающие порты: одинаковые порт+процесс на нескольких адресах привязки сворачиваются, наружу видимый адрес первым
	sort.Slice(listens, func(i, j int) bool {
		if listens[i].Port != listens[j].Port {
			return listens[i].Port < listens[j].Port
		}
		return !isLoopback(listens[i].Addr) && isLoopback(listens[j].Addr)
	})
	var ls []NetListen
	seen := map[string]bool{}
	for _, l := range listens {
		k := fmt.Sprint(l.Port, "|", l.Proc)
		if seen[k] {
			continue
		}
		seen[k] = true
		ls = append(ls, l)
	}
	if len(ls) > netMaxListen {
		ls = ls[:netMaxListen]
	}
	return ls, conns
}
