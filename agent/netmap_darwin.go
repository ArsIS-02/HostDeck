//go:build darwin

package main

import "time"

func readNetPlat() netPlat {
	var p netPlat
	if out, err := run(20*time.Second, "lsof", "-nP", "-iTCP", "-F", "pcnT"); err == nil || out != "" {
		p.socks = parseLsof(out)
	}
	if out, err := run(10*time.Second, "arp", "-an"); err == nil {
		p.neigh = parseARPMac(out)
	}
	if out, err := run(10*time.Second, "route", "-n", "get", "default"); err == nil {
		p.gateways = parseRouteGet(out)
	}
	if out, err := run(10*time.Second, "scutil", "--dns"); err == nil {
		p.dns = parseScutilDNS(out)
	}
	return p
}
