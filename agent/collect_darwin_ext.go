//go:build darwin

package main

import (
	"os"
	"strings"
	"time"
)

// Проверки соответствия для macOS. Если данные получить нельзя, проверка не добавляется (или помечается «нет данных» там, где это важно).

// asUser выполняет defaults от имени пользователя у экрана: настройки AirDrop и заставки хранятся в его домене, а не в домене root.
func asUser(user string, args ...string) (string, error) {
	return run(10*time.Second, "/usr/bin/sudo", append([]string{"-n", "-u", user}, args...)...)
}

func launchdLoaded(label string) bool {
	_, err := run(10*time.Second, "/bin/launchctl", "print", "system/"+label)
	return err == nil
}

func darwinCompliance(p *Posture) {
	add := func(c Check) { p.Checks = append(p.Checks, c) }

	// --- Time Machine ---
	tm, err := run(10*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.TimeMachine")
	last, configured := parseTimeMachine(tm)
	if err != nil || !configured {
		// на Mac mini-сервере без Time Machine — осознанный выбор: справка, не замечание
		add(Check{ID: "timemachine", Status: "info", Value: "not_configured"})
	} else {
		if last == 0 {
			if o, e := run(20*time.Second, "/usr/bin/tmutil", "latestbackup"); e == nil {
				if t, ok := parseLatestBackup(o); ok {
					last = t
				}
			}
		}
		age := time.Since(time.Unix(last, 0))
		switch {
		case last == 0:
			add(Check{ID: "timemachine", Status: "info", Value: "no_backups"})
		case age > 30*24*time.Hour:
			add(Check{ID: "timemachine", Status: "fail", Value: "backup_at", Num: float64(last)})
		case age > 7*24*time.Hour:
			add(Check{ID: "timemachine", Status: "warn", Value: "backup_at", Num: float64(last)})
		default:
			add(Check{ID: "timemachine", Status: "ok", Value: "backup_at", Num: float64(last)})
		}
	}

	// --- учётные записи ---
	guest, gok := false, false
	if o, err := run(10*time.Second, "/usr/sbin/sysadminctl", "-guestAccount", "status"); err == nil || trim(o) != "" {
		guest, gok = parseGuest(o)
	}
	if !gok {
		o, _ := run(5*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
		guest, gok = parseGuest(o)
		if !gok {
			guest, gok = false, true // ключа нет — гостевой вход выключен
		}
	}
	if guest {
		add(Check{ID: "guest", Status: "warn", Value: "on"})
	} else {
		add(Check{ID: "guest", Status: "ok", Value: "off"})
	}
	o, _ := run(5*time.Second, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
	if u := parseAutoLogin(o); u != "" {
		add(Check{ID: "autologin", Status: "fail", Value: "on", Detail: u})
	} else {
		add(Check{ID: "autologin", Status: "ok", Value: "off"})
	}
	if o, err := run(10*time.Second, "/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"); err == nil {
		admins := parseAdmins(o)
		st := "ok"
		if len(admins) > 2 {
			st = "warn"
		}
		add(Check{ID: "admins", Status: st, Value: "admins", Num: float64(len(admins)), Detail: strings.Join(admins, ", ")})
	}

	// --- общий доступ ---
	// onStatus — как оценивать «включено»: общий доступ к экрану и удалённое управление на домашних
	// хостах включают сознательно (удалённая работа), поэтому это справка; доступ к файлам остаётся замечанием.
	onOff := func(id string, on bool) {
		if on {
			st := "warn"
			if id == "sharing_screen" || id == "sharing_remote" {
				st = "info"
			}
			add(Check{ID: id, Status: st, Value: "on"})
		} else {
			add(Check{ID: id, Status: "ok", Value: "off"})
		}
	}
	onOff("sharing_screen", launchdLoaded("com.apple.screensharing"))
	onOff("sharing_files", launchdLoaded("com.apple.smbd"))
	// Удалённое управление (ARD): признак — работающий процесс ARDAgent (эвристика, прямого флага в системе нет)
	_, ardErr := run(5*time.Second, "/usr/bin/pgrep", "-x", "ARDAgent")
	onOff("sharing_remote", ardErr == nil)

	user := p.Info["console_user"]
	hasUser := user != "" && user != "root" && user != "loginwindow"
	if hasUser {
		o, _ := asUser(user, "/usr/bin/defaults", "read", "com.apple.sharingd", "DiscoverableMode")
		switch parseDiscoverable(o) {
		case "everyone":
			add(Check{ID: "airdrop", Status: "warn", Value: "everyone"})
		case "off":
			add(Check{ID: "airdrop", Status: "ok", Value: "off"})
		default:
			add(Check{ID: "airdrop", Status: "ok", Value: "contacts"})
		}
	}

	// --- XProtect: возраст набора сигнатур по дате изменения файлов ---
	for _, base := range []string{"/Library/Apple/System/Library/CoreServices/XProtect.bundle", "/System/Library/CoreServices/XProtect.bundle"} {
		var newest time.Time
		for _, f := range []string{"/Contents/Resources/XProtect.yara", "/Contents/Resources/XProtect.meta.plist", "/Contents/Info.plist"} {
			if st, err := os.Stat(base + f); err == nil && st.ModTime().After(newest) {
				newest = st.ModTime()
			}
		}
		if newest.IsZero() {
			continue
		}
		ver, _ := run(5*time.Second, "/usr/bin/defaults", "read", base+"/Contents/Info", "CFBundleShortVersionString")
		age := time.Since(newest)
		st := "ok"
		switch {
		case age > 90*24*time.Hour:
			st = "fail"
		case age > 30*24*time.Hour:
			st = "warn"
		}
		d := ""
		if v := trim(ver); v != "" && !strings.Contains(v, "does not exist") {
			d = "v" + v
		}
		add(Check{ID: "xprotect", Status: st, Value: "updated_at", Num: float64(newest.Unix()), Detail: d})
		break
	}

	// --- профили конфигурации и системные расширения ---
	if o, err := run(20*time.Second, "/usr/bin/profiles", "list"); err == nil || trim(o) != "" {
		if ids := parseProfiles(o); len(ids) > 0 {
			add(Check{ID: "profiles", Status: "info", Value: "profiles", Num: float64(len(ids)), Detail: shortStr(ids, 4)})
		} else if !strings.Contains(strings.ToLower(o), "error") {
			add(Check{ID: "profiles", Status: "info", Value: "no_profiles"})
		}
	}
	if o, err := run(20*time.Second, "/usr/bin/systemextensionsctl", "list"); err == nil || trim(o) != "" {
		if ids := parseSysExt(o); len(ids) > 0 {
			add(Check{ID: "sysext", Status: "info", Value: "extensions", Num: float64(len(ids)), Detail: shortStr(ids, 4)})
		} else {
			add(Check{ID: "sysext", Status: "info", Value: "no_ext"})
		}
	}

	// --- простой: дисплей и заставка ---
	if o, err := run(5*time.Second, "/usr/bin/pmset", "-g"); err == nil || trim(o) != "" {
		if n, ok := parseDisplaySleep(o); ok {
			switch {
			case n == 0:
				add(Check{ID: "display_sleep", Status: "warn", Value: "never_sleep"})
			case n > 15:
				add(Check{ID: "display_sleep", Status: "warn", Value: "after_min", Num: float64(n)})
			default:
				add(Check{ID: "display_sleep", Status: "ok", Value: "after_min", Num: float64(n)})
			}
		}
	}
	if hasUser {
		o, _ := asUser(user, "/usr/bin/defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime")
		n, ok := parseIntDefault(o)
		switch {
		case !ok:
			add(Check{ID: "screensaver", Status: "info", Value: "unset"})
		case n == 0:
			add(Check{ID: "screensaver", Status: "warn", Value: "never_sleep"})
		case n > 1200:
			add(Check{ID: "screensaver", Status: "warn", Value: "after_min", Num: float64(n / 60)})
		default:
			add(Check{ID: "screensaver", Status: "ok", Value: "after_min", Num: float64(n / 60)})
		}
	}
}

func shortStr(names []string, n int) string {
	if len(names) > n {
		return strings.Join(names[:n], ", ") + " …"
	}
	return strings.Join(names, ", ")
}
