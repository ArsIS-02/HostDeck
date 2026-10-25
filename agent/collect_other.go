//go:build !darwin

package main

import (
	"os"
	"strings"
)

// platformCollect на не-macOS хостах: минимальный набор (нужен для проверки всей цепочки вне Mac).
func platformCollect(p *Posture) {
	if h, err := os.Hostname(); err == nil {
		p.Info["hostname"] = h
	}
	p.Info["os"] = "linux"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "PRETTY_NAME=") {
				p.Info["os_version"] = strings.Trim(strings.TrimPrefix(ln, "PRETTY_NAME="), `"`)
			}
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		var up float64
		if _, err := fmtSscan(string(b), &up); err == nil {
			p.Info["uptime"] = fmtDuration(int64(up))
		}
	}
	p.Checks = append(p.Checks, Check{ID: "platform", Label: "Платформа", Status: "info", Value: "проверки безопасности реализованы только для macOS"})
}
