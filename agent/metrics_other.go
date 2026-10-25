//go:build !darwin

package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

var prevCPU [2]float64 // busy, total

// platformMetrics для Linux — только чтобы проверять цепочку вне Mac.
func platformMetrics(m *Metrics) {
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		if len(f) > 5 {
			var tot, idle float64
			for i, s := range f[1:] {
				v, _ := strconv.ParseFloat(s, 64)
				tot += v
				if i == 3 || i == 4 {
					idle += v
				}
			}
			busy := tot - idle
			if prevCPU[1] > 0 && tot > prevCPU[1] {
				m.CPU = (busy - prevCPU[0]) / (tot - prevCPU[1]) * 100
			}
			prevCPU = [2]float64{busy, tot}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail float64
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				avail = v * 1024
			}
		}
		m.MemTotal, m.MemUsed = total, total-avail
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if v, ok := parseLoadAvg(string(b)); ok {
			m.Load1 = v
		}
	}
	_ = time.Now
}
