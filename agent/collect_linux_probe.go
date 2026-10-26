//go:build linux

package main

import (
	"os"
	"strings"
	"time"
)

// Проверки, построенные на выводах probe с реальных хостов (RED OS 8, x86_64 и aarch64).
// Если данных нет (нет утилиты или прав), проверка не добавляется или получает «unknown» с причиной.
func linuxProbeChecks(add func(Check), active func(string) bool) {
	// криптополитика системы
	if b := find("update-crypto-policies"); b != "" {
		out, _ := runCode(10*time.Second, b, "--show")
		if st, v := parseCryptoPolicy(out); st != "unknown" {
			add(Check{ID: "crypto_policy", Status: st, Value: v, Detail: trim(firstLine(out))})
		}
	}
	// слабые параметры SSH в действующей конфигурации
	if sshd := find("sshd"); sshd != "" && (active("sshd") || active("ssh")) {
		if out, _ := runCode(10*time.Second, sshd, "-T"); strings.Contains(strings.ToLower(out), "permitrootlogin") {
			if weak := parseSSHWeak(out); len(weak) > 0 {
				add(Check{ID: "ssh_hardening", Status: "warn", Value: "ssh_weak", Num: float64(len(weak)), Detail: strings.Join(weak, ", ")})
			} else {
				add(Check{ID: "ssh_hardening", Status: "ok", Value: "ssh_strong"})
			}
		}
	}
	// блокировка после неудачных входов
	pam := readFileOr("/etc/pam.d/system-auth") + "\n" + readFileOr("/etc/pam.d/password-auth")
	if strings.TrimSpace(pam) != "" {
		if parseLockout(pam, readFileOr("/etc/security/faillock.conf")) {
			add(Check{ID: "lockout", Status: "ok", Value: "lockout_on"})
		} else {
			add(Check{ID: "lockout", Status: "warn", Value: "lockout_off"})
		}
	}
	// состояние auditd
	if b := find("auditctl"); b != "" {
		out, _ := runCode(10*time.Second, b, "-s")
		if st, v, lost := parseAuditStatus(out); st != "unknown" {
			add(Check{ID: "audit_state", Status: st, Value: v, Num: float64(lost)})
		}
	}
	// агент Wazuh
	if _, err := os.Stat("/var/ossec"); err == nil {
		if st, ok := readFile("/var/ossec/var/run/wazuh-agentd.state"); ok {
			s, v := parseWazuhState(st, time.Now())
			add(Check{ID: "wazuh", Status: s, Value: v})
		} else if active("wazuh-agent") {
			add(Check{ID: "wazuh", Status: "unknown", Value: "wazuh_nostate"})
		} else {
			add(Check{ID: "wazuh", Status: "fail", Value: "wazuh_down"})
		}
	}
	// постоянный журнал systemd: без /var/log/journal записи пропадают после перезагрузки
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if fi, err := os.Stat("/var/log/journal"); err == nil && fi.IsDir() {
			add(Check{ID: "journal", Status: "ok", Value: "journal_persistent"})
		} else {
			add(Check{ID: "journal", Status: "warn", Value: "journal_volatile"})
		}
	}
	// небезопасные и лишние службы
	var bad, extra []string
	for _, u := range []string{"telnet.socket", "rsh.socket", "rlogin.socket", "rexec.socket", "vsftpd", "tftp.socket"} {
		if active(strings.TrimSuffix(u, ".service")) {
			bad = append(bad, strings.TrimSuffix(u, ".socket"))
		}
	}
	for _, u := range []string{"cups", "avahi-daemon"} {
		if active(u) {
			extra = append(extra, u)
		}
	}
	switch {
	case len(bad) > 0:
		add(Check{ID: "legacy_svc", Status: "fail", Value: "legacy_on", Num: float64(len(bad)), Detail: strings.Join(bad, ", ")})
	case len(extra) > 0:
		add(Check{ID: "legacy_svc", Status: "info", Value: "extra_svc", Num: float64(len(extra)), Detail: strings.Join(extra, ", ")})
	default:
		add(Check{ID: "legacy_svc", Status: "ok", Value: "clean"})
	}
}
