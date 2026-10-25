//go:build darwin

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const updatesEvery = 6 * time.Hour

var (
	updMu     sync.Mutex
	updAt     time.Time
	updTitles []string
	updKnown  bool
	updBusy   bool
)

// refreshUpdates запускает проверку обновлений в фоне: `softwareupdate --list` ходит в сеть и бывает долгой.
func refreshUpdates() {
	updMu.Lock()
	if updBusy || (!updAt.IsZero() && time.Since(updAt) < updatesEvery) {
		updMu.Unlock()
		return
	}
	updBusy = true
	updMu.Unlock()
	go func() {
		out, _ := run(180*time.Second, "/usr/sbin/softwareupdate", "--list")
		titles, known := parseUpdates(out)
		updMu.Lock()
		updTitles, updKnown, updAt, updBusy = titles, known, time.Now(), false
		updMu.Unlock()
	}()
}

func platformCollect(p *Posture) {
	info := p.Info
	info["os"] = "macOS"
	if h, err := os.Hostname(); err == nil {
		info["hostname"] = h
	}
	if o, err := run(5*time.Second, "/usr/bin/sw_vers", "-productVersion"); err == nil {
		info["os_version"] = trim(o)
	}
	if o, err := run(5*time.Second, "/usr/bin/sw_vers", "-buildVersion"); err == nil {
		info["build"] = trim(o)
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "hw.model"); err == nil {
		info["model"] = trim(o)
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
		info["chip"] = trim(o)
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "hw.memsize"); err == nil {
		if n, err := strconv.ParseInt(trim(o), 10, 64); err == nil {
			info["memory"] = fmt.Sprintf("%d ГБ", n/(1<<30))
		}
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "kern.boottime"); err == nil {
		if sec, ok := parseBootTime(o); ok {
			info["uptime"] = fmtDuration(time.Now().Unix() - sec)
		}
	}
	if o, err := run(5*time.Second, "/usr/bin/stat", "-f", "%Su", "/dev/console"); err == nil {
		info["console_user"] = trim(o)
	}

	add := func(id, label, status, value string) {
		p.Checks = append(p.Checks, Check{ID: id, Label: label, Status: status, Value: value})
	}
	unknown := func(id, label string, err error, out string) {
		d := trim(out)
		if err != nil && d == "" {
			d = err.Error()
		}
		p.Checks = append(p.Checks, Check{ID: id, Label: label, Status: "unknown", Detail: d})
	}

	if o, err := run(10*time.Second, "/usr/bin/fdesetup", "status"); err != nil && trim(o) == "" {
		unknown("filevault", "Шифрование диска (FileVault)", err, o)
	} else {
		s, v := parseFileVault(o)
		add("filevault", "Шифрование диска (FileVault)", s, v)
	}
	if o, err := run(10*time.Second, "/usr/bin/csrutil", "status"); err != nil && trim(o) == "" {
		unknown("sip", "SIP (защита целостности системы)", err, o)
	} else {
		s, v := parseSIP(o)
		add("sip", "SIP (защита целостности системы)", s, v)
	}
	if o, err := run(10*time.Second, "/usr/sbin/spctl", "--status"); err != nil && trim(o) == "" {
		unknown("gatekeeper", "Gatekeeper", err, o)
	} else {
		s, v := parseGatekeeper(o)
		add("gatekeeper", "Gatekeeper", s, v)
	}
	const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if o, err := run(10*time.Second, sfw, "--getglobalstate"); err != nil && trim(o) == "" {
		unknown("firewall", "Брандмауэр", err, o)
	} else {
		s, v := parseFirewall(o)
		add("firewall", "Брандмауэр", s, v)
	}
	if o, err := run(10*time.Second, sfw, "--getstealthmode"); err == nil || trim(o) != "" {
		s, v := parseStealth(o)
		add("stealth", "Режим невидимки (stealth)", s, v)
	}

	// автообновления: ключи com.apple.SoftwareUpdate
	autoChk := func(key, label, id string) {
		o, _ := run(5*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key)
		v, set := parseDefaultsBool(o)
		switch {
		case !set:
			add(id, label, "unknown", "не задано")
		case v:
			add(id, label, "ok", "включено")
		default:
			add(id, label, "warn", "выключено")
		}
	}
	autoChk("AutomaticCheckEnabled", "Автопроверка обновлений", "auto_check")
	autoChk("CriticalUpdateInstall", "Автоустановка обновлений безопасности", "auto_critical")

	refreshUpdates()
	updMu.Lock()
	at, titles, known, busy := updAt, updTitles, updKnown, updBusy
	updMu.Unlock()
	switch {
	case at.IsZero() && busy:
		p.Checks = append(p.Checks, Check{ID: "updates", Label: "Доступные обновления macOS", Status: "unknown", Detail: "проверка выполняется"})
	case !known:
		p.Checks = append(p.Checks, Check{ID: "updates", Label: "Доступные обновления macOS", Status: "unknown", Detail: "не удалось получить список"})
	case len(titles) == 0:
		p.Checks = append(p.Checks, Check{ID: "updates", Label: "Доступные обновления macOS", Status: "ok", Value: "обновлений нет", Detail: "проверено " + at.Format("02.01 15:04")})
	default:
		p.Checks = append(p.Checks, Check{ID: "updates", Label: "Доступные обновления macOS", Status: "warn",
			Value: fmt.Sprintf("доступно: %d", len(titles)), Detail: strings.Join(titles, "; ")})
	}

	if o, err := run(10*time.Second, "/usr/sbin/sysadminctl", "-screenLock", "status"); err == nil || trim(o) != "" {
		s, v := parseScreenLock(o)
		add("screenlock", "Блокировка экрана", s, v)
	}
	if o, err := run(10*time.Second, "/usr/sbin/systemsetup", "-getremotelogin"); err == nil || trim(o) != "" {
		s, v := parseRemoteLogin(o)
		add("ssh", "Удалённый вход (SSH)", s, v)
	}
	if o, err := run(10*time.Second, "/usr/bin/profiles", "status", "-type", "enrollment"); err == nil {
		add("mdm", "Регистрация в MDM", "info", firstLine(trim(o)))
	}
}
