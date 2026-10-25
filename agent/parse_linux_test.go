package main

import "testing"

func TestLinuxParsers(t *testing.T) {
	if s, v := parseSELinux("Enforcing\n"); s != "ok" || v != "enforcing" {
		t.Errorf("selinux enforcing: %s %s", s, v)
	}
	if s, _ := parseSELinux("Permissive"); s != "warn" {
		t.Error("selinux permissive")
	}
	if s, v := parseSELinux("Disabled"); s != "fail" || v != "off" {
		t.Error("selinux disabled")
	}
	if s, _ := parseSELinux("bash: getenforce: command not found"); s != "unknown" {
		t.Error("selinux junk")
	}

	pol, n := parseIptables("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N f2b-sshd\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n")
	if pol != "DROP" || n != 2 {
		t.Errorf("iptables: %s %d", pol, n)
	}
	pol, n = parseIptables("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n")
	if pol != "ACCEPT" || n != 0 {
		t.Errorf("iptables empty: %s %d", pol, n)
	}

	nft := `table inet firewalld {
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
		iifname "lo" accept
		jump filter_INPUT_ZONES
	}
	chain filter_FORWARD {
		type filter hook forward priority filter + 10; policy accept;
	}
}
`
	pol, n = parseNft(nft)
	if pol != "ACCEPT" || n != 3 {
		t.Errorf("nft: %s %d", pol, n)
	}
	pol, _ = parseNft("table inet f {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n")
	if pol != "DROP" {
		t.Errorf("nft drop: %s", pol)
	}

	if !parseUFW("Status: active\n\nTo   Action  From\n") || parseUFW("Status: inactive") {
		t.Error("ufw")
	}

	root, pw, ok := parseSSHD("port 22\npermitrootlogin without-password\npasswordauthentication yes\n")
	if !ok || root || !pw {
		t.Errorf("sshd: %v %v %v", root, pw, ok)
	}
	root, pw, ok = parseSSHD("permitrootlogin yes\npasswordauthentication no\n")
	if !ok || !root || pw {
		t.Errorf("sshd2: %v %v %v", root, pw, ok)
	}
	if _, _, ok := parseSSHD("sshd: command not found"); ok {
		t.Error("sshd junk")
	}

	dnf := "\nLast metadata expiration check: 0:10:00 ago.\nkernel.x86_64   5.14.0-1   baseos\nopenssl.x86_64  3.0.1-2  appstream\n\nObsoleting Packages\nold.x86_64 1 2\n"
	if got := parseDnfUpdates(dnf); len(got) != 2 || got[0] != "kernel.x86_64" {
		t.Errorf("dnf: %v", got)
	}
	if len(parseDnfUpdates("")) != 0 {
		t.Error("dnf empty")
	}
	apt := "Reading package lists...\nInst libc6 [2.31-1] (2.31-2 Debian:11/stable [amd64])\nInst curl [7.1] (7.2 Debian)\nConf libc6 (2.31-2)\n"
	if got := parseAptUpdates(apt); len(got) != 2 || got[1] != "curl" {
		t.Errorf("apt: %v", got)
	}

	failed := "● foo.service loaded failed failed Foo daemon\n  bar.mount loaded failed failed /bar\n"
	if got := parseFailedUnits(failed); len(got) != 2 || got[0] != "foo.service" {
		t.Errorf("failed: %v", got)
	}
	if len(parseFailedUnits("")) != 0 {
		t.Error("failed empty")
	}
	if !parseLsblkCrypt("disk\npart\ncrypt\nlvm\n") || parseLsblkCrypt("disk\npart\nlvm\n") {
		t.Error("lsblk")
	}
}
