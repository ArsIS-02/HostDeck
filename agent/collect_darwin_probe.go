//go:build darwin

package main

import (
	"os"
	"strings"
	"time"
)

// Проверки macOS, построенные на выводах probe с реального Mac (macOS 27.2, Apple Silicon).
func darwinProbeChecks(add func(Check)) {
	// Signed System Volume
	if out, _ := run(10*time.Second, "/usr/bin/csrutil", "authenticated-root", "status"); out != "" {
		if on, ok := parseCsrutil(out); ok {
			if on {
				add(Check{ID: "ssv", Status: "ok", Value: "ssv_on"})
			} else {
				add(Check{ID: "ssv", Status: "fail", Value: "ssv_off"})
			}
		}
	}
	// канал обновлений (бета-каталог)
	if out, err := run(10*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"); err == nil {
		st, v := parseCatalog(out)
		add(Check{ID: "update_channel", Status: st, Value: v})
	}
	// сетевое время
	if out, _ := run(10*time.Second, "/usr/sbin/systemsetup", "-getusingnetworktime"); out != "" {
		srv, _ := run(10*time.Second, "/usr/sbin/systemsetup", "-getnetworktimeserver")
		if st, v, server := parseNetTime(out + "\n" + srv); st != "unknown" {
			add(Check{ID: "net_time", Status: st, Value: v, Detail: server})
		}
	}
	// SSH: слабые параметры, если удалённый вход включён
	if out, _ := run(10*time.Second, "/usr/sbin/systemsetup", "-getremotelogin"); out != "" {
		if _, v := parseRemoteLogin(out); v == "on" {
			if cfg, _ := run(10*time.Second, "/usr/sbin/sshd", "-T"); strings.Contains(strings.ToLower(cfg), "permitrootlogin") {
				if weak := parseSSHWeak(cfg); len(weak) > 0 {
					add(Check{ID: "ssh_hardening", Status: "warn", Value: "ssh_weak", Num: float64(len(weak)), Detail: strings.Join(weak, ", ")})
				} else {
					add(Check{ID: "ssh_hardening", Status: "ok", Value: "ssh_strong"})
				}
			}
		}
	}
	// Internet Sharing: нет домена настроек = выключено
	if _, err := os.Stat("/Library/Preferences/SystemConfiguration/com.apple.nat.plist"); err == nil {
		if out, e := run(10*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.nat"); e == nil && strings.Contains(out, "Enabled = 1") {
			add(Check{ID: "internet_sharing", Status: "warn", Value: "inet_share_on"})
		} else {
			add(Check{ID: "internet_sharing", Status: "ok", Value: "inet_share_off"})
		}
	} else {
		add(Check{ID: "internet_sharing", Status: "ok", Value: "inet_share_off"})
	}
	// сетевые службы, которые реально работают (SNMP, NoMachine): решение за пользователем, поэтому справка
	var daemons []string
	for _, d := range []struct{ proc, name string }{{"snmpd", "SNMP"}, {"nxserver.bin", "NoMachine"}, {"nxd", "NoMachine"}, {"telnetd", "telnet"}, {"ftpd", "FTP"}} {
		if _, err := run(5*time.Second, "/usr/bin/pgrep", "-x", d.proc); err == nil {
			daemons = append(daemons, d.name)
		}
	}
	if len(daemons) > 0 {
		add(Check{ID: "net_daemons", Status: "info", Value: "daemons_on", Num: float64(len(daemons)), Detail: strings.Join(uniq(daemons), ", ")})
	}
	// таймаут sudo
	if out, err := run(10*time.Second, "/usr/bin/sudo", "-n", "-V"); err == nil || out != "" {
		if m := parseSudoTimeout(out); m >= 0 {
			if m > 15 || m < 0 {
				add(Check{ID: "sudo_timeout", Status: "warn", Value: "sudo_long", Num: m})
			} else {
				add(Check{ID: "sudo_timeout", Status: "ok", Value: "sudo_short", Num: m})
			}
		}
	}
	// журнал аудита BSM: на современных macOS не настроен, это не недостаток
	if _, err := os.Stat("/etc/security/audit_control"); err != nil {
		add(Check{ID: "audit_bsm", Status: "na", Value: "bsm_absent"})
	}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
