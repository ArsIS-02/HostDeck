package main

import (
	"net"
	"sort"
	"time"
)

// allowNetwork включает сбор данных для сетевой карты. Выключено по умолчанию.
var allowNetwork bool

// netPlat — то, что зависит от ОС: таблица сокетов с владельцами, соседи, шлюзы, DNS.
type netPlat struct {
	socks    []rawSock
	procOf   func(rawSock) (string, int)
	neigh    []NetNeigh
	gateways []string
	dns      []string
}

func collectNet() NetSnap {
	s := NetSnap{At: time.Now().Unix()}
	own := map[string]bool{}
	ifs, _ := net.Interfaces()
	for _, in := range ifs {
		ni := NetIface{Name: in.Name, MAC: in.HardwareAddr.String(), Up: in.Flags&net.FlagUp != 0, Virtual: virtualIface(in.Name)}
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			ni.Addrs = append(ni.Addrs, a.String())
			if ipn, ok := a.(*net.IPNet); ok {
				own[normIP(ipn.IP.String())] = true
			}
		}
		if in.Flags&net.FlagLoopback != 0 || (len(ni.Addrs) == 0 && ni.MAC == "") {
			continue
		}
		s.Ifaces = append(s.Ifaces, ni)
	}
	sort.Slice(s.Ifaces, func(i, j int) bool { return s.Ifaces[i].Name < s.Ifaces[j].Name })
	p := readNetPlat()
	if p.procOf == nil {
		p.procOf = func(r rawSock) (string, int) { return r.Proc, r.PID }
	}
	s.Gateways, s.DNS = p.gateways, p.dns
	s.Neigh = p.neigh
	if len(s.Neigh) > netMaxNeigh {
		s.Neigh = s.Neigh[:netMaxNeigh]
	}
	s.Listen, s.Conns = buildNet(p.socks, p.procOf, own)
	return s
}
