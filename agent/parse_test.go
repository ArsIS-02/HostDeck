package main

import "testing"

func TestParsers(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"fv on", first(parseFileVault("FileVault is On.\n")), "ok"},
		{"fv off", first(parseFileVault("FileVault is Off.")), "fail"},
		{"fv progress", first(parseFileVault("FileVault is On.\nEncryption in progress: 40%")), "ok"},
		{"fv junk", first(parseFileVault("")), "unknown"},
		{"sip on", first(parseSIP("System Integrity Protection status: enabled.")), "ok"},
		{"sip off", first(parseSIP("System Integrity Protection status: disabled.")), "fail"},
		{"sip custom", first(parseSIP("System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled")), "warn"},
		{"gk on", first(parseGatekeeper("assessments enabled")), "ok"},
		{"gk off", first(parseGatekeeper("assessments disabled")), "fail"},
		{"fw on", first(parseFirewall("Firewall is enabled. (State = 1)")), "ok"},
		{"fw off", first(parseFirewall("Firewall is disabled. (State = 0)")), "fail"},
		{"fw block all", first(parseFirewall("Firewall is enabled. (State = 2)")), "ok"},
		{"stealth on", first(parseStealth("Stealth mode enabled")), "ok"},
		{"stealth off", first(parseStealth("Stealth mode disabled")), "warn"},
		{"lock imm", first(parseScreenLock("sysadminctl[1] screenLock delay is immediate")), "ok"},
		{"lock 5", first(parseScreenLock("screenLock delay is 5 seconds")), "ok"},
		{"lock 1h", first(parseScreenLock("screenLock delay is 3600 seconds")), "warn"},
		{"lock off", first(parseScreenLock("screenLock is off")), "warn"},
		{"ssh on", first(parseRemoteLogin("Remote Login: On")), "info"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}

func first(a, _ string) string { return a }

func TestSIPCustomIsNotOK(t *testing.T) {
	// «unknown ... Custom Configuration ... disabled» не должно считаться «ok».
	if s, _ := parseSIP("System Integrity Protection status: enabled (Custom Configuration)."); s != "warn" {
		t.Errorf("custom enabled: got %s want warn", s)
	}
}

func TestUpdates(t *testing.T) {
	none := "Software Update Tool\n\nFinding available software\nNo new software available.\n"
	if ti, known := parseUpdates(none); len(ti) != 0 || !known {
		t.Errorf("none: %v %v", ti, known)
	}
	some := "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: macOS Sequoia 15.1-24B83\n\tTitle: macOS Sequoia 15.1, Version: 15.1, Size: 1234K, Recommended: YES, Action: restart,\n* Label: Safari18.1-18.1\n\tTitle: Safari, Version: 18.1\n"
	ti, known := parseUpdates(some)
	if len(ti) != 2 || !known || ti[0] != "macOS Sequoia 15.1-24B83" {
		t.Errorf("some: %v %v", ti, known)
	}
	if _, known := parseUpdates("error: network"); known {
		t.Errorf("garbage must be unknown")
	}
}

func TestBootAndDefaults(t *testing.T) {
	if n, ok := parseBootTime("{ sec = 1761350000, usec = 123 } Sat Oct 25 2026"); !ok || n != 1761350000 {
		t.Errorf("boot: %d %v", n, ok)
	}
	if v, set := parseDefaultsBool("1\n"); !v || !set {
		t.Errorf("defaults 1")
	}
	if _, set := parseDefaultsBool("The domain/default pair does not exist"); set {
		t.Errorf("defaults missing must be unset")
	}
}

func TestMetricParsers(t *testing.T) {
	top := "CPU usage: 50.0% user, 10.0% sys, 40.0% idle\nCPU usage: 8.5% user, 3.5% sys, 88.0% idle\n"
	if v, ok := parseTopCPU(top); !ok || v < 11.9 || v > 12.1 {
		t.Errorf("cpu: %v %v", v, ok)
	}
	vm := "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100.\nPages active: 1000.\nPages wired down: 500.\nPages occupied by compressor: 100.\n"
	if u, ok := parseVMStat(vm); !ok || u != 1600*16384 {
		t.Errorf("vm: %v %v", u, ok)
	}
	if p, _, ok := parseSwap("vm.swapusage: total = 2048.00M  used = 512.00M  free = 1536.00M  (encrypted)"); !ok || p != 25 {
		t.Errorf("swap: %v", p)
	}
	batt := "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t87%; discharging; 5:12 remaining present: true"
	if p, chrg, ok := parseBattery(batt); !ok || p != 87 || chrg {
		t.Errorf("batt: %v %v %v", p, chrg, ok)
	}
	if _, _, ok := parseBattery("Now drawing from 'AC Power'"); ok {
		t.Error("battery must be absent")
	}
	if v, ok := parseLoadAvg("{ 1.52 1.60 1.71 }"); !ok || v != 1.52 {
		t.Errorf("load: %v", v)
	}
}
