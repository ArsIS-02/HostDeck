package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseCryptoPolicy(t *testing.T) {
	for in, want := range map[string]string{"LEGACY\n": "warn", "DEFAULT\n": "ok", "FIPS:OSPP": "unknown", "": "unknown", "FUTURE": "ok"} {
		if s, _ := parseCryptoPolicy(in); s != want {
			t.Errorf("%q: %s, ждали %s", in, s, want)
		}
	}
}

func TestParseWazuhState(t *testing.T) {
	st := "# c\nstatus='connected'\n\nlast_ack='2026-10-26 13:47:42'\n"
	loc := time.FixedZone("x", 5*3600)
	if s, _ := parseWazuhState(st, time.Date(2026, 10, 26, 13, 50, 0, 0, loc)); s != "ok" {
		t.Error("свежий ack должен быть ok:", s)
	}
	if s, _ := parseWazuhState(st, time.Date(2026, 10, 26, 14, 30, 0, 0, loc)); s != "warn" {
		t.Error("старый ack должен быть warn:", s)
	}
	if s, _ := parseWazuhState("status='disconnected'", time.Now()); s != "fail" {
		t.Error("disconnected → fail")
	}
	if s, _ := parseWazuhState("", time.Now()); s != "unknown" {
		t.Error("пусто → unknown")
	}
}

func TestParseAuditStatus(t *testing.T) {
	if s, v, l := parseAuditStatus("enabled 1\nfailure 1\npid 412\nlost 10\nbacklog 0\n"); s != "info" || v != "audit_lost" || l != 10 {
		t.Error(s, v, l)
	}
	if s, v, _ := parseAuditStatus("enabled 1\nlost 0\n"); s != "ok" || v != "audit_on" {
		t.Error(s, v)
	}
	if s, _, _ := parseAuditStatus("enabled 0\n"); s != "fail" {
		t.Error("выключен → fail")
	}
	if s, _, _ := parseAuditStatus("Cannot open netlink socket"); s != "unknown" {
		t.Error("ошибка → unknown")
	}
}

func TestParseLockout(t *testing.T) {
	// RED OS 8: в PAM нет faillock, faillock.conf отсутствует
	if parseLockout("/etc/pam.d/system-auth:21:password requisite pam_pwquality.so local_users_only", "") {
		t.Error("RED OS без faillock должен давать false")
	}
	if !parseLockout("auth required pam_faillock.so preauth", "deny = 5\n") {
		t.Error("deny=5 → блокировка есть")
	}
	if parseLockout("auth required pam_faillock.so preauth", "deny = 0\n") {
		t.Error("deny=0 → блокировки нет")
	}
}

func TestParseSSHWeak(t *testing.T) {
	x86 := "PermitRootLogin prohibit-password\nX11Forwarding yes\nMaxAuthTries 6\nCiphers aes256-gcm@openssh.com,aes256-cbc,3des-cbc\nKexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1\n"
	if got := strings.Join(parseSSHWeak(x86), ","); got != "X11Forwarding,MaxAuthTries 6,CBC/3DES,SHA-1 kex" {
		t.Error(got)
	}
	mac := "x11forwarding no\nmaxauthtries 3\nciphers aes128-gcm@openssh.com,aes256-ctr\nkexalgorithms curve25519-sha256\n"
	if w := parseSSHWeak(mac); len(w) != 0 {
		t.Error(w)
	}
}
