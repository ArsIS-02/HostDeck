package main

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Разборщики для проверок, добавленных после probe. Тесты — на выводах реальных хостов (RED OS x86_64 и aarch64).

// parseCryptoPolicy: вывод `update-crypto-policies --show`. LEGACY допускает SHA-1, CBC и 3DES.
func parseCryptoPolicy(out string) (status, value string) {
	p := strings.ToUpper(strings.TrimSpace(firstLine(out)))
	switch {
	case p == "" || strings.ContainsAny(p, " :"):
		return "unknown", ""
	case strings.HasPrefix(p, "LEGACY"):
		return "warn", "legacy"
	case strings.HasPrefix(p, "FIPS"), strings.HasPrefix(p, "FUTURE"), strings.HasPrefix(p, "DEFAULT"):
		return "ok", "policy_ok"
	}
	return "info", "other"
}

// parseWazuhState: файл wazuh-agentd.state (строки status='connected', last_ack='2026-10-26 13:47:42', время локальное).
func parseWazuhState(state string, now time.Time) (status, value string) {
	get := func(k string) string {
		m := regexp.MustCompile(`(?m)^` + k + `='([^']*)'`).FindStringSubmatch(state)
		if m == nil {
			return ""
		}
		return m[1]
	}
	st := get("status")
	switch st {
	case "":
		return "unknown", ""
	case "connected":
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", get("last_ack"), now.Location()); err == nil && now.Sub(t) > 10*time.Minute {
			return "warn", "wazuh_stale"
		}
		return "ok", "wazuh_connected"
	case "pending":
		return "warn", "wazuh_pending"
	}
	return "fail", "wazuh_disconnected"
}

// parseAuditStatus: вывод `auditctl -s`.
func parseAuditStatus(out string) (status, value string, lost int) {
	m := regexp.MustCompile(`(?m)^enabled (\d)`).FindStringSubmatch(out)
	if m == nil {
		return "unknown", "", 0
	}
	if l := regexp.MustCompile(`(?m)^lost (\d+)`).FindStringSubmatch(out); l != nil {
		lost, _ = strconv.Atoi(l[1])
	}
	switch {
	case m[1] == "0":
		return "fail", "audit_off", lost
	case lost > 0:
		return "info", "audit_lost", lost
	case m[1] == "2":
		return "ok", "audit_locked", lost
	}
	return "ok", "audit_on", lost
}

// parseLockout: есть ли блокировка после неудачных входов (pam_faillock или pam_tally2 в PAM-файлах, deny > 0 в faillock.conf).
func parseLockout(pam, conf string) bool {
	if !strings.Contains(pam, "pam_faillock") && !strings.Contains(pam, "pam_tally2") {
		return false
	}
	for _, ln := range strings.Split(conf, "\n") {
		f := strings.Fields(strings.ReplaceAll(strings.TrimSpace(ln), "=", " "))
		if len(f) >= 2 && f[0] == "deny" {
			n, _ := strconv.Atoi(f[1])
			return n > 0
		}
	}
	return true
}

// parseSSHWeak: недостатки действующей конфигурации по выводу `sshd -T` (имена параметров в любом регистре).
func parseSSHWeak(out string) []string {
	var weak []string
	vals := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimSpace(ln), " ", 2)
		if len(f) == 2 {
			vals[strings.ToLower(f[0])] = strings.TrimSpace(f[1])
		}
	}
	if vals["x11forwarding"] == "yes" {
		weak = append(weak, "X11Forwarding")
	}
	if n, err := strconv.Atoi(vals["maxauthtries"]); err == nil && n > 4 {
		weak = append(weak, "MaxAuthTries "+vals["maxauthtries"])
	}
	if c := vals["ciphers"]; strings.Contains(c, "-cbc") || strings.Contains(c, "3des") {
		weak = append(weak, "CBC/3DES")
	}
	if k := vals["kexalgorithms"]; strings.Contains(k, "-sha1") {
		weak = append(weak, "SHA-1 kex")
	}
	return weak
}

// --- macOS ---

// parseCatalog: адрес каталога обновлений из com.apple.SoftwareUpdate. В адресе есть «seed» — это бета-канал.
func parseCatalog(defaultsOut string) (status, value string) {
	m := regexp.MustCompile(`CatalogURL = "([^"]*)"`).FindStringSubmatch(defaultsOut)
	if m == nil {
		return "ok", "channel_release"
	}
	if strings.Contains(strings.ToLower(m[1]), "seed") {
		return "info", "channel_beta"
	}
	return "ok", "channel_release"
}

// parseNetTime: вывод `systemsetup -getusingnetworktime` и `-getnetworktimeserver`.
func parseNetTime(out string) (status, value, server string) {
	on := regexp.MustCompile(`Network Time: (On|Off)`).FindStringSubmatch(out)
	if on == nil {
		return "unknown", "", ""
	}
	if m := regexp.MustCompile(`Network Time Server: (\S+)`).FindStringSubmatch(out); m != nil {
		server = m[1]
	}
	if on[1] == "On" {
		return "ok", "ntp_on", server
	}
	return "warn", "ntp_off", server
}

// parseSudoTimeout: строка из `sudo -V`: «Authentication timestamp timeout: 5.0 minutes». Минуты, -1 если не найдено.
func parseSudoTimeout(out string) float64 {
	m := regexp.MustCompile(`timestamp timeout: (-?[\d.]+) minutes`).FindStringSubmatch(out)
	if m == nil {
		return -1
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

// parseCsrutil: «enabled» / «disabled» в выводе csrutil (status и authenticated-root status).
func parseCsrutil(out string) (on, ok bool) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "enabled"):
		return true, true
	case strings.Contains(l, "disabled"):
		return false, true
	}
	return false, false
}
