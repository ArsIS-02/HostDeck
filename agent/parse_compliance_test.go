package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestTimeMachine(t *testing.T) {
	out := `{
    AutoBackup = 1;
    Destinations =     (
                {
            DestinationID = "ABC";
            SnapshotDates =             (
                "2026-10-20 06:12:11 +0000",
                "2026-10-25 06:00:00 +0000"
            );
        }
    );
}`
	last, conf := parseTimeMachine(out)
	if !conf || last != time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("got %d %v", last, conf)
	}
	if _, conf := parseTimeMachine("{ AutoBackup = 0; }"); conf {
		t.Fatal("destination not configured")
	}
	if ts, ok := parseLatestBackup("/Volumes/TM/Backups.backupdb/Mac/2026-10-25-120000.backup"); !ok || ts == 0 {
		t.Fatal("latestbackup path")
	}
}

func TestMacAccounts(t *testing.T) {
	if on, ok := parseGuest("Guest account disabled"); on || !ok {
		t.Fatal("guest disabled")
	}
	if on, ok := parseGuest("Guest account enabled"); !on || !ok {
		t.Fatal("guest enabled")
	}
	if on, ok := parseGuest("1\n"); !on || !ok {
		t.Fatal("guest 1")
	}
	if parseAutoLogin("The domain/default pair of (...) does not exist") != "" || parseAutoLogin("alice\n") != "alice" {
		t.Fatal("autologin")
	}
	got := parseAdmins("GroupMembership: root alice _spotlight bob\n")
	if !reflect.DeepEqual(got, []string{"alice", "bob"}) {
		t.Fatal(got)
	}
}

func TestMacProfilesAndExt(t *testing.T) {
	out := "_computerlevel[1] attribute: profileIdentifier: com.acme.wifi\n_computerlevel[2] attribute: profileIdentifier: com.acme.fv\n"
	if got := parseProfiles(out); len(got) != 2 || got[0] != "com.acme.wifi" {
		t.Fatal(got)
	}
	if len(parseProfiles("There are no configuration profiles installed")) != 0 {
		t.Fatal("none")
	}
	ext := "1 extension(s)\n--- com.apple.system_extension.endpoint_security\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tABCDE12345\tcom.vendor.agent.sysext (1.0/1)\tAgent\t[activated enabled]\n"
	if got := parseSysExt(ext); len(got) != 1 || got[0] != "com.vendor.agent.sysext" {
		t.Fatal(got)
	}
}

func TestMacIdle(t *testing.T) {
	if n, ok := parseDisplaySleep("Currently in use:\n displaysleep         10\n disksleep 10"); !ok || n != 10 {
		t.Fatal(n, ok)
	}
	if parseDiscoverable("Contacts Only") != "contacts" || parseDiscoverable("Everyone") != "everyone" || parseDiscoverable("Off") != "off" || parseDiscoverable("does not exist") != "" {
		t.Fatal("discoverable")
	}
	if n, ok := parseIntDefault("1200\n"); !ok || n != 1200 {
		t.Fatal("int")
	}
}

func TestLinuxAccounts(t *testing.T) {
	pw := "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbob:x:1000:1000::/home/bob:/bin/bash\n"
	if got := parseUID0(pw); !reflect.DeepEqual(got, []string{"toor"}) {
		t.Fatal(got)
	}
	sh := "root:$6$abc:19000::::::\nguest::19000::::::\nsvc:!!:19000::::::\n"
	if got := parseEmptyPasswords(sh); !reflect.DeepEqual(got, []string{"guest"}) {
		t.Fatal(got)
	}
	sudo := "# %wheel ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL)   ALL\nops ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"
	if got := parseNopasswd(sudo); len(got) != 1 || got[0] != "ops ALL=(ALL) NOPASSWD: /usr/bin/systemctl" {
		t.Fatal(got)
	}
	md, ml := parseLoginDefs("PASS_MAX_DAYS\t90\n#PASS_MIN_LEN 5\nPASS_MIN_LEN 10\n")
	if md != 90 || ml != 10 {
		t.Fatal(md, ml)
	}
	if md, _ := parseLoginDefs("# nothing"); md != 99999 {
		t.Fatal("default max days")
	}
	if parsePwQuality("# minlen = 8\n minlen = 12\n") != 12 {
		t.Fatal("pwquality")
	}
	if weak, _ := pwPolicy(90, 12); weak {
		t.Fatal("policy should be ok")
	}
	if weak, _ := pwPolicy(99999, 12); !weak {
		t.Fatal("never-expiring passwords are weak")
	}
}

func TestParseSS(t *testing.T) {
	out := `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=801,fd=3))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=801,fd=4))
tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("conmon",pid=900,fd=5))
udp UNCONN 0 0 *:5353 *:* users:(("avahi-daemon",pid=700,fd=12))
tcp LISTEN 0 511 *:443 *:* users:(("caddy",pid=950,fd=7))
`
	ls := parseSS(out)
	if len(ls) != 3 || ls[0].Port != 22 || ls[0].Proc != "sshd" || ls[1].Port != 443 || ls[2].Proto != "udp" {
		t.Fatalf("%+v", ls)
	}
}

func TestSysctlAndMounts(t *testing.T) {
	devs := evalSysctl(map[string]string{"kernel.randomize_va_space": "2", "net.ipv4.conf.all.send_redirects": "1", "kernel.kptr_restrict": "0", "fs.suid_dumpable": "0"})
	if len(devs) != 2 {
		t.Fatal(devs)
	}
	if len(evalSysctl(map[string]string{"kernel.randomize_va_space": "2"})) != 0 {
		t.Fatal("ok")
	}
	m := parseMounts("/dev/sda1 / xfs rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n/dev/sda2 /var/tmp xfs rw,nosuid 0 0\n")
	probs := evalTmp(m)
	if len(probs) != 1 || probs[0] != "/var/tmp: нет noexec" {
		t.Fatal(probs)
	}
	if got := evalTmp(parseMounts("/dev/sda1 / xfs rw 0 0\n")); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestSmartAndAudit(t *testing.T) {
	if parseSmartHealth("SMART overall-health self-assessment test result: PASSED") != "passed" ||
		parseSmartHealth("SMART overall-health self-assessment test result: FAILED!") != "failed" ||
		parseSmartHealth("SMART support is: Unavailable - device lacks SMART capability.") != "" {
		t.Fatal("smart")
	}
	if parseAuditRules("No rules\n") != 0 || parseAuditRules("-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S execve\n") != 2 {
		t.Fatal("audit rules")
	}
}

func TestLogForward(t *testing.T) {
	conf := "# *.* @@old.example.com:514\n*.* @@graylog.lab:514\nauth.* @10.0.0.5\naction(type=\"omfwd\" target=\"wazuh.lab\" port=\"514\" protocol=\"tcp\")\n$ModLoad imuxsock\nmail.* /var/log/maillog\n"
	got := parseRsyslogForward(conf)
	if !reflect.DeepEqual(got, []string{"graylog.lab:514", "10.0.0.5", "wazuh.lab"}) {
		t.Fatal(got)
	}
	if len(parseRsyslogForward("*.info;mail.none /var/log/messages\nuser@host.example\n")) != 0 {
		t.Fatal("false positive")
	}
	if !parseAuditRemote("active = yes\ndirection = out\n") || parseAuditRemote("active = no\n") {
		t.Fatal("au-remote")
	}
}

func TestSecurityUpdates(t *testing.T) {
	out := "Last metadata expiration check: 0:10:00 ago\nRLSA-2026:1234 Important/Sec. kernel-5.14.0-1.x86_64\nRLSA-2026:1300 Moderate/Sec.  openssl-3.0.1-2.x86_64\nRLEA-2026:5 enhancement vim-1.2.x86_64\n"
	adv := parseDnfSecurity(out)
	if len(adv) != 2 || adv[0].Sev != "important" || adv[1].Pkg != "openssl-3.0.1-2.x86_64" {
		t.Fatalf("%+v", adv)
	}
	apt := "Inst libssl3 [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])\nInst vim [1] (2 Debian:12/stable [amd64])\n"
	if got := parseAptSecurity(apt); !reflect.DeepEqual(got, []string{"libssl3"}) {
		t.Fatal(got)
	}
}

func TestIPAAndCerts(t *testing.T) {
	if parseIPADomain("[global]\nhost = a.lab\ndomain = lab.test\n") != "lab.test" {
		t.Fatal("domain")
	}
	if parseSssctlOnline("Online status: Offline\n") != "offline" || parseSssctlOnline("Online status: Online\n") != "online" || parseSssctlOnline("") != "" {
		t.Fatal("sssctl")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cs := parseCerts("ca.crt", data)
	if len(cs) != 1 || cs[0].Name != "lab-ca (ca.crt)" || time.Until(cs[0].NotAfter) > 11*24*time.Hour {
		t.Fatalf("%+v", cs)
	}
	if len(parseCerts("junk.pem", []byte("not a pem"))) != 0 {
		t.Fatal("junk")
	}
}

func TestProcNet(t *testing.T) {
	tcp := "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n   2: 0100007F:9999 0100007F:0016 01 00000000:00000000\n"
	ls := parseProcNet(tcp, "tcp")
	if len(ls) != 1 || ls[0].Port != 22 || ls[0].Proto != "tcp" {
		t.Fatalf("%+v", ls)
	}
}
