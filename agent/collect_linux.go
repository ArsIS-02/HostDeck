//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// find ищет утилиту в PATH и в системных каталогах: у службы PATH бывает урезан.
func find(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		if st, err := os.Stat(d + "/" + name); err == nil && !st.IsDir() {
			return d + "/" + name
		}
	}
	return ""
}

// runCode: как run, но возвращает код выхода (dnf check-update использует 100 как «есть обновления»).
func runCode(timeout time.Duration, name string, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	return string(out), -1
}

// Обновления пакетов проверяются в фоне: dnf check-update может идти минуту и дольше.
var (
	pkgMu    sync.Mutex
	pkgAt    time.Time
	pkgNames []string
	pkgKnown bool
	pkgBusy  bool
	pkgTried time.Time
)

func refreshPkgUpdates() {
	pkgMu.Lock()
	if pkgBusy || (!pkgTried.IsZero() && time.Since(pkgTried) < 30*time.Minute) {
		pkgMu.Unlock()
		return
	}
	pkgBusy, pkgTried = true, time.Now()
	pkgMu.Unlock()
	go func() {
		var names []string
		ok := false
		if dnf := find("dnf"); dnf != "" {
			out, code := runCode(10*time.Minute, dnf, "-q", "check-update")
			if code == 0 || code == 100 {
				names, ok = parseDnfUpdates(out), true
			}
		} else if apt := find("apt-get"); apt != "" {
			out, code := runCode(2*time.Minute, apt, "-s", "-o", "Debug::NoLocking=1", "upgrade")
			if code == 0 {
				names, ok = parseAptUpdates(out), true
			}
		}
		pkgMu.Lock()
		pkgBusy = false
		if ok {
			pkgAt, pkgNames, pkgKnown = time.Now(), names, true
		}
		pkgMu.Unlock()
	}()
}

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
			p.Info["boot_time"] = strconv.FormatInt(time.Now().Unix()-int64(up), 10)
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		p.Info["kernel"] = strings.TrimSpace(string(b))
	}

	add := func(c Check) { p.Checks = append(p.Checks, c) }
	active := func(unit string) bool {
		sc := find("systemctl")
		if sc == "" {
			return false
		}
		out, _ := runCode(5*time.Second, sc, "is-active", unit)
		return strings.TrimSpace(firstLine(out)) == "active"
	}

	// SELinux
	if ge := find("getenforce"); ge != "" {
		out, _ := runCode(5*time.Second, ge)
		s, v := parseSELinux(out)
		add(Check{ID: "selinux", Status: s, Value: v})
	}

	// Брандмауэр: firewalld, затем ufw
	fwDone := false
	if active("firewalld") {
		c := Check{ID: "firewall", Status: "ok", Value: "firewalld"}
		if fc := find("firewall-cmd"); fc != "" {
			out, _ := runCode(5*time.Second, fc, "--get-default-zone")
			c.Detail = strings.TrimSpace(firstLine(out))
		}
		add(c)
		fwDone = true
	} else if ufw := find("ufw"); ufw != "" {
		out, _ := runCode(5*time.Second, ufw, "status")
		if parseUFW(out) {
			add(Check{ID: "firewall", Status: "ok", Value: "ufw"})
			fwDone = true
		}
	}

	// Правила netfilter (iptables и nftables)
	var policy string
	rules, seen := 0, false
	if ipt := find("iptables"); ipt != "" {
		out, code := runCode(10*time.Second, ipt, "-S")
		if code == 0 {
			seen = true
			pl, n := parseIptables(out)
			policy, rules = pl, rules+n
		}
	}
	if nft := find("nft"); nft != "" {
		out, code := runCode(10*time.Second, nft, "list", "ruleset")
		if code == 0 {
			seen = true
			pl, n := parseNft(out)
			if policy == "" || (strings.EqualFold(pl, "drop") && !strings.EqualFold(policy, "drop")) {
				policy = pl
			}
			rules += n
		}
	}
	if seen {
		c := Check{ID: "iptables", Num: float64(rules)}
		if policy != "" {
			c.Detail = "INPUT: " + policy
		}
		if rules > 0 || strings.EqualFold(policy, "drop") || strings.EqualFold(policy, "reject") {
			c.Status, c.Value = "ok", "rules"
		} else {
			c.Status, c.Value = "warn", "empty"
		}
		add(c)
		if !fwDone {
			// нет менеджера брандмауэра, но правила есть — считаем, что защита настроена вручную
			if c.Status == "ok" {
				add(Check{ID: "firewall", Status: "ok", Value: "manual"})
			} else {
				add(Check{ID: "firewall", Status: "fail", Value: "off"})
			}
		}
	} else if !fwDone && (find("firewall-cmd") != "" || find("ufw") != "") {
		add(Check{ID: "firewall", Status: "fail", Value: "off"})
	}

	// SSH-сервер
	if sshd := find("sshd"); sshd != "" {
		if active("sshd") || active("ssh") {
			out, _ := runCode(10*time.Second, sshd, "-T")
			if root, pw, ok := parseSSHD(out); ok {
				switch {
				case root:
					add(Check{ID: "sshd", Status: "fail", Value: "root_login"})
				case pw:
					add(Check{ID: "sshd", Status: "warn", Value: "password_auth"})
				default:
					add(Check{ID: "sshd", Status: "ok", Value: "keys_only"})
				}
			} else {
				add(Check{ID: "sshd", Status: "unknown", Detail: trim(firstLine(out))})
			}
		} else {
			add(Check{ID: "sshd", Status: "info", Value: "inactive"})
		}
	}

	// Обновления пакетов
	if find("dnf") != "" || find("apt-get") != "" {
		refreshPkgUpdates()
		pkgMu.Lock()
		at, names, known, busy := pkgAt, pkgNames, pkgKnown, pkgBusy
		pkgMu.Unlock()
		switch {
		case !known && busy:
			add(Check{ID: "pkg_updates", Status: "unknown", Value: "running"})
		case !known:
			add(Check{ID: "pkg_updates", Status: "unknown", Value: "failed"})
		case len(names) == 0:
			add(Check{ID: "pkg_updates", Status: "ok", Value: "none", Num: float64(at.Unix())})
		default:
			shown := names
			if len(shown) > 8 {
				shown = shown[:8]
			}
			d := strings.Join(shown, ", ")
			if len(names) > len(shown) {
				d += " …"
			}
			add(Check{ID: "pkg_updates", Status: "warn", Value: "available", Num: float64(len(names)), Detail: d})
		}
	}

	// Требуется ли перезагрузка
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		add(Check{ID: "reboot", Status: "warn", Value: "required"})
	} else if nr := find("needs-restarting"); nr != "" {
		if _, code := runCode(30*time.Second, nr, "-r"); code == 1 {
			add(Check{ID: "reboot", Status: "warn", Value: "required"})
		} else if code == 0 {
			add(Check{ID: "reboot", Status: "ok", Value: "not_needed"})
		}
	} else if _, err := os.Stat("/etc/debian_version"); err == nil {
		add(Check{ID: "reboot", Status: "ok", Value: "not_needed"})
	}

	// auditd
	if find("auditctl") != "" || find("auditd") != "" {
		if active("auditd") {
			add(Check{ID: "auditd", Status: "ok", Value: "active"})
		} else {
			add(Check{ID: "auditd", Status: "warn", Value: "inactive"})
		}
	}

	// Синхронизация времени
	if td := find("timedatectl"); td != "" {
		out, _ := runCode(5*time.Second, td, "show", "-p", "NTPSynchronized", "--value")
		switch strings.TrimSpace(firstLine(out)) {
		case "yes":
			add(Check{ID: "time_sync", Status: "ok", Value: "synced"})
		case "no":
			add(Check{ID: "time_sync", Status: "warn", Value: "not_synced"})
		}
	}

	// Сбойные службы systemd
	if sc := find("systemctl"); sc != "" {
		out, code := runCode(10*time.Second, sc, "--failed", "--plain", "--no-legend")
		if code == 0 {
			if names := parseFailedUnits(out); len(names) == 0 {
				add(Check{ID: "failed_units", Status: "ok", Value: "no_failed"})
			} else {
				shown := names
				if len(shown) > 6 {
					shown = shown[:6]
				}
				add(Check{ID: "failed_units", Status: "warn", Value: "units_failed", Num: float64(len(names)), Detail: strings.Join(shown, ", ")})
			}
		}
	}

	// Шифрование диска (LUKS)
	if lb := find("lsblk"); lb != "" {
		out, code := runCode(10*time.Second, lb, "-rno", "TYPE")
		if code == 0 {
			if parseLsblkCrypt(out) {
				add(Check{ID: "luks", Status: "ok", Value: "on"})
			} else {
				add(Check{ID: "luks", Status: "warn", Value: "off"})
			}
		}
	}
}
