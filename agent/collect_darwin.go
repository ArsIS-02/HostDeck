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
			info["memory"] = fmt.Sprintf("%d GB", n/(1<<30))
		}
	}
	if o, err := run(5*time.Second, "/usr/sbin/sysctl", "-n", "kern.boottime"); err == nil {
		if sec, ok := parseBootTime(o); ok {
			info["boot_time"] = strconv.FormatInt(sec, 10)
		}
	}
	if o, err := run(5*time.Second, "/usr/bin/stat", "-f", "%Su", "/dev/console"); err == nil {
		info["console_user"] = trim(o)
	}

	add := func(id, status, value string) {
		p.Checks = append(p.Checks, Check{ID: id, Status: status, Value: value})
	}
	unknown := func(id string, err error, out string) {
		d := trim(out)
		if err != nil && d == "" {
			d = err.Error()
		}
		p.Checks = append(p.Checks, Check{ID: id, Status: "unknown", Detail: d})
	}

	if o, err := run(10*time.Second, "/usr/bin/fdesetup", "status"); err != nil && trim(o) == "" {
		unknown("filevault", err, o)
	} else {
		s, v := parseFileVault(o)
		add("filevault", s, v)
	}
	if o, err := run(10*time.Second, "/usr/bin/csrutil", "status"); err != nil && trim(o) == "" {
		unknown("sip", err, o)
	} else {
		s, v := parseSIP(o)
		add("sip", s, v)
	}
	if o, err := run(10*time.Second, "/usr/sbin/spctl", "--status"); err != nil && trim(o) == "" {
		unknown("gatekeeper", err, o)
	} else {
		s, v := parseGatekeeper(o)
		add("gatekeeper", s, v)
	}
	const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if o, err := run(10*time.Second, sfw, "--getglobalstate"); err != nil && trim(o) == "" {
		unknown("firewall", err, o)
	} else {
		s, v := parseFirewall(o)
		add("firewall", s, v)
	}
	if o, err := run(10*time.Second, sfw, "--getstealthmode"); err == nil || trim(o) != "" {
		s, v := parseStealth(o)
		add("stealth", s, v)
	}

	// автообновления. Ключ в com.apple.SoftwareUpdate записан не всегда: пока пользователь не менял настройку,
	// macOS использует значение по умолчанию (включено). Поэтому «не задано» — это не «нет данных».
	autoChk := func(key, id string, schedule bool) {
		if schedule {
			if o, err := run(10*time.Second, "/usr/sbin/softwareupdate", "--schedule"); err == nil || trim(o) != "" {
				if v, ok := parseSchedule(o); ok {
					if v {
						add(id, "ok", "on")
					} else {
						add(id, "warn", "off")
					}
					return
				}
			}
		}
		o, _ := run(5*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key)
		v, set := parseDefaultsBool(o)
		switch {
		case !set:
			add(id, "ok", "default")
		case v:
			add(id, "ok", "on")
		default:
			add(id, "warn", "off")
		}
	}
	autoChk("AutomaticCheckEnabled", "auto_check", true)
	autoChk("CriticalUpdateInstall", "auto_critical", false)

	refreshUpdates()
	updMu.Lock()
	at, titles, known, busy := updAt, updTitles, updKnown, updBusy
	updMu.Unlock()
	switch {
	case at.IsZero() && busy:
		p.Checks = append(p.Checks, Check{ID: "updates", Status: "unknown", Value: "running"})
	case !known:
		p.Checks = append(p.Checks, Check{ID: "updates", Status: "unknown", Value: "failed"})
	case len(titles) == 0:
		p.Checks = append(p.Checks, Check{ID: "updates", Status: "ok", Value: "none", Num: float64(at.Unix())})
	default:
		p.Checks = append(p.Checks, Check{ID: "updates", Status: "warn",
			Value: "available", Num: float64(len(titles)), Detail: strings.Join(titles, "; ")})
	}

	if o, err := run(10*time.Second, "/usr/sbin/sysadminctl", "-screenLock", "status"); err == nil || trim(o) != "" {
		s, v := parseScreenLock(o)
		add("screenlock", s, v)
	}
	if o, err := run(10*time.Second, "/usr/sbin/systemsetup", "-getremotelogin"); err == nil || trim(o) != "" {
		s, v := parseRemoteLogin(o)
		add("ssh", s, v)
	}
	if o, err := run(10*time.Second, "/usr/bin/profiles", "status", "-type", "enrollment"); err == nil {
		add("mdm", "info", firstLine(trim(o)))
	}
}
