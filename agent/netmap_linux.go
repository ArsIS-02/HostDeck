//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readNetPlat() netPlat {
	var p netPlat
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(f); err == nil {
			p.socks = append(p.socks, parseProcNetTCP(string(b))...)
		}
	}
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		p.neigh = parseProcARP(string(b))
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		p.gateways = parseProcRoute(string(b))
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		p.dns = parseResolvConf(string(b))
	}
	// inode сокета → процесс (нужны права root; без них процессы остаются пустыми)
	owners := map[string]struct {
		name string
		pid  int
	}{}
	if dirs, err := filepath.Glob("/proc/[0-9]*/fd/*"); err == nil {
		comm := map[int]string{}
		for _, fd := range dirs {
			l, err := os.Readlink(fd)
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
			pid, _ := strconv.Atoi(strings.Split(fd, "/")[2])
			if _, ok := owners[ino]; ok {
				continue
			}
			n, ok := comm[pid]
			if !ok {
				if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil {
					n = strings.TrimSpace(string(b))
				}
				comm[pid] = n
			}
			owners[ino] = struct {
				name string
				pid  int
			}{n, pid}
		}
	}
	p.procOf = func(r rawSock) (string, int) { o := owners[r.Inode]; return o.name, o.pid }
	return p
}
