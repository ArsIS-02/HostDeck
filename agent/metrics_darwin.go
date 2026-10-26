//go:build darwin

package main

import (
	"strconv"
	"time"
)

func platformMetrics(m *Metrics) {
	if o, err := run(15*time.Second, "/usr/bin/top", "-l", "2", "-n", "0", "-s", "1"); err == nil {
		if v, ok := parseTopCPU(o); ok {
			m.CPU = v
		}
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "hw.memsize"); err == nil {
		if n, err := strconv.ParseFloat(trim(o), 64); err == nil {
			m.MemTotal = n
		}
	}
	if o, err := run(5*time.Second, "/usr/bin/vm_stat"); err == nil {
		if u, ok := parseVMStat(o); ok {
			m.MemUsed = u
		}
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "vm.swapusage"); err == nil {
		if p, _, ok := parseSwap(o); ok {
			m.SwapPct = p
		}
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "vm.loadavg"); err == nil {
		if v, ok := parseLoadAvg(o); ok {
			m.Load1 = v
		}
	}
	if o, err := run(5*time.Second, "/usr/bin/pmset", "-g", "batt"); err == nil {
		if p, chrg, ok := parseBattery(o); ok {
			m.Battery, m.BatteryChrg = p, chrg
		}
	}
}
