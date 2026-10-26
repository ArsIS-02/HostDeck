package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// probe — сбор сырых выводов системных команд, на которых строятся проверки. Файл нужен, чтобы разборщики
// проверялись на настоящих форматах конкретных систем (RED OS x86_64 и aarch64, macOS), а не на предположениях.
// Секреты не собираются: хэши паролей не читаются (только состояние учётной записи), ключи агентов Wazuh не читаются.
// Имя хоста и адреса IPv4 по умолчанию заменяются на HOST и x.x.x.x.

type probeItem struct {
	Title string
	Sh    string // команда для /bin/sh -c
}

func probeItems() []probeItem {
	common := []probeItem{
		{"система", "uname -a; echo; cat /etc/os-release 2>/dev/null; command -v sw_vers >/dev/null && sw_vers; true"},
		{"SSH: действующая конфигурация (sshd -T)", "PATH=$PATH:/usr/sbin:/sbin; sshd -T 2>&1 | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|x11forwarding|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax|allowusers|allowgroups|usepam|kbdinteractiveauthentication|challengeresponseauthentication|port|protocol|banner|ciphers|macs|kexalgorithms) '"},
	}
	if runtime.GOOS == "darwin" {
		return append(common, []probeItem{
			{"macOS: Signed System Volume", "/usr/bin/csrutil authenticated-root status 2>&1"},
			{"macOS: SIP", "/usr/bin/csrutil status 2>&1"},
			{"macOS: настройки обновлений (defaults)", "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>&1"},
			{"macOS: сетевое время", "/usr/sbin/systemsetup -getusingnetworktime 2>&1; /usr/sbin/systemsetup -getnetworktimeserver 2>&1"},
			{"macOS: Internet Sharing", "/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>&1"},
			{"macOS: права audit_control", "/usr/bin/stat -f '%Sp %Su %Sg %Lp %N' /etc/security/audit_control /etc/security/audit_user 2>&1"},
			{"macOS: общий доступ (launchd)", "/bin/launchctl print-disabled system 2>&1 | head -60"},
			{"macOS: права критичных файлов", "/usr/bin/stat -f '%Sp %Su %Sg %Lp %N' /etc/sudoers /etc/ssh/sshd_config /etc/passwd /etc/master.passwd 2>&1"},
			{"macOS: Удалённый вход и общий доступ", "/usr/sbin/systemsetup -getremotelogin 2>&1; for l in com.openssh.sshd com.apple.screensharing org.net-snmp.snmpd com.nomachine.nxserver; do echo \"$l: $(/bin/launchctl print system/$l 2>&1 | grep -E '^[[:space:]]*(state|pid) =' | tr -s ' \\t' ' ' | tr '\\n' ';')\"; done; /usr/bin/pgrep -lx 'snmpd|nxserver.bin|screensharingd|ARDAgent' 2>&1"},
			{"macOS: гостевой вход и политика паролей", "/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>&1; /usr/bin/pwpolicy -getaccountpolicies 2>&1 | head -40"},
			{"macOS: таймаут sudo", "/usr/bin/sudo -V 2>&1 | grep -i 'timestamp_timeout\\|Authentication timestamp timeout'; /usr/bin/grep -rn timestamp_timeout /etc/sudoers /etc/sudoers.d 2>&1"},
		}...)
	}
	return append(common, []probeItem{
		{"права критичных файлов", "stat -c '%a %U %G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/sudoers /etc/crontab 2>&1"},
		{"права cron", "stat -c '%a %U %G %n' /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>&1 | head -80"},
		{"учётные записи (хэши НЕ выводятся)", "awk -F: 'NR==FNR{sh[$1]=$7;uid[$1]=$3;next} {st=($2==\"\")?\"empty\":(($2 ~ /^[!*]/)?\"locked\":\"set\"); print $1\" uid=\"uid[$1]\" shell=\"sh[$1]\" pw=\"st\" lastchg=\"$3\" min=\"$4\" max=\"$5\" warn=\"$6\" inactive=\"$7\" expire=\"$8}' /etc/passwd /etc/shadow 2>&1"},
		{"login.defs", "grep -vE '^[[:space:]]*(#|$)' /etc/login.defs 2>&1"},
		{"faillock.conf", "grep -vE '^[[:space:]]*(#|$)' /etc/security/faillock.conf 2>&1"},
		{"pwquality", "grep -vE '^[[:space:]]*(#|$)' /etc/security/pwquality.conf 2>&1; ls /etc/security/pwquality.conf.d 2>&1"},
		{"PAM: faillock / pwhistory / pwquality / wheel", "grep -nE 'faillock|pwhistory|pwquality|pam_wheel|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/su /etc/pam.d/sshd /etc/pam.d/passwd 2>&1; echo; authselect current 2>&1"},
		{"TMOUT в login-shell", "env -i HOME=/root PATH=/usr/bin:/bin bash -l -c 'echo TMOUT=${TMOUT-unset}' 2>&1; grep -rn TMOUT /etc/profile /etc/profile.d /etc/bashrc 2>/dev/null"},
		{"sticky bit", "stat -c '%A %a %U %n' /tmp /var/tmp 2>&1; echo '--- каталоги с записью для всех без sticky:'; find / -xdev \\( -path /var/lib/docker -o -path /var/lib/containers -o -path /proc -o -path /sys -o -path /run -o -path /var/lib/kubelet \\) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -20"},
		{"SUID/SGID (usr, bin, sbin, opt)", "find /usr /bin /sbin /opt -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -printf '%m %u %g %p\\n' 2>/dev/null | sort -k4 | head -150"},
		{"криптополитика и FIPS", "update-crypto-policies --show 2>&1; echo \"fips_enabled=$(cat /proc/sys/crypto/fips_enabled 2>&1)\"; ls -l /etc/system-fips 2>&1"},
		{"модули ядра и форвардинг", "echo \"modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>&1)\"; echo \"ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>&1)\"; for c in docker podman kubelet containerd; do command -v $c >/dev/null 2>&1 && echo \"found:$c\"; done; systemctl is-active docker podman containerd kubelet 2>&1"},
		{"auditctl -s", "PATH=$PATH:/usr/sbin:/sbin; auditctl -s 2>&1"},
		{"auditctl -l (первые 40)", "PATH=$PATH:/usr/sbin:/sbin; auditctl -l 2>&1 | head -40"},
		{"auditd.conf", "grep -vE '^[[:space:]]*(#|$)' /etc/audit/auditd.conf 2>&1"},
		{"журнал systemd", "ls -ld /var/log/journal 2>&1; journalctl --disk-usage 2>&1; systemd-analyze cat-config systemd/journald.conf 2>&1 | grep -vE '^[[:space:]]*(#|$)'"},
		{"время: timedatectl show", "timedatectl show 2>&1"},
		{"время: chrony", "chronyc tracking 2>&1; echo; chronyc -n sources 2>&1 | head -12; echo; systemctl is-active chronyd ntpd systemd-timesyncd 2>&1"},
		{"Wazuh-агент", "systemctl is-active wazuh-agent 2>&1; echo; cat /var/ossec/var/run/wazuh-agentd.state 2>&1; echo; ls -l /var/ossec/etc/client.keys 2>&1 | awk '{print $1,$3,$4,$5}'; echo; tail -n 6 /var/ossec/logs/ossec.log 2>&1"},
		{"устаревшие службы", "for u in telnet.socket rsh.socket rlogin.socket rexec.socket vsftpd.service tftp.socket cups.service avahi-daemon.service; do echo \"$u enabled=$(systemctl is-enabled $u 2>&1 | head -1) active=$(systemctl is-active $u 2>&1 | head -1)\"; done"},
		{"подбор паролей: неудачные SSH-входы за 24 ч", "echo \"failed_password=$(journalctl _COMM=sshd --since -24h --no-pager -o cat 2>/dev/null | grep -c 'Failed password')\"; echo \"invalid_user=$(journalctl _COMM=sshd --since -24h --no-pager -o cat 2>/dev/null | grep -c 'Invalid user')\"; echo \"root_password_logins_30d=$(journalctl _COMM=sshd --since -30d --no-pager -o cat 2>/dev/null | grep -c 'Accepted password for root')\""},
		{"SELinux и архитектура", "uname -m; getenforce 2>&1; sestatus 2>&1 | head -8"},
	}...)
}

var (
	reIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reMAC  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
)

// redact заменяет имя хоста и адреса. Служебные адреса (127.*, 0.*, 255.*) оставляем: они нужны разборщикам.
func redact(s, host string) string {
	if host != "" {
		for _, h := range []string{host, strings.SplitN(host, ".", 2)[0]} {
			if len(h) >= 3 {
				s = strings.ReplaceAll(s, h, "HOST")
			}
		}
	}
	s = reMAC.ReplaceAllString(s, "xx:xx:xx:xx:xx:xx")
	return reIPv4.ReplaceAllStringFunc(s, func(ip string) string {
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "255.") {
			return ip
		}
		return "x.x.x.x"
	})
}

func runSh(timeout time.Duration, script string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		if ctx.Err() != nil {
			buf.WriteString("\n[таймаут]\n")
		}
	}
	out := buf.String()
	if len(out) > 32<<10 {
		out = out[:32<<10] + "\n[обрезано]\n"
	}
	return out, code
}

func cmdProbe(args []string) {
	out := ""
	raw := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			if i+1 < len(args) {
				out = args[i+1]
				i++
			}
		case "-raw":
			raw = true
		}
	}
	host, _ := os.Hostname()
	var b strings.Builder
	fmt.Fprintf(&b, "# hostdeck-agent %s probe\n# os=%s arch=%s uid=%d time=%s redacted=%v\n", version, runtime.GOOS, runtime.GOARCH, os.Geteuid(), time.Now().UTC().Format(time.RFC3339), !raw)
	if os.Geteuid() != 0 {
		b.WriteString("# ВНИМАНИЕ: запущено не от root, часть команд покажет «permission denied». Запустите через sudo.\n")
	}
	for _, it := range probeItems() {
		o, code := runSh(25*time.Second, it.Sh)
		fmt.Fprintf(&b, "\n===== %s =====\n$ %s\n[exit %d]\n%s", it.Title, it.Sh, code, o)
		if !strings.HasSuffix(o, "\n") {
			b.WriteString("\n")
		}
	}
	text := b.String()
	if !raw {
		text = redact(text, host)
	}
	if out == "" {
		out = fmt.Sprintf("hostdeck-probe-%s-%s.txt", runtime.GOOS+"-"+runtime.GOARCH, time.Now().Format("20060102-1504"))
	}
	if err := os.WriteFile(out, []byte(text), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "не удалось записать файл:", err)
		os.Exit(1)
	}
	// запуск через sudo: отдаём файл тому, кто его запустил, иначе его не прочитать и не прикрепить
	if u, g := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); u != "" && g != "" {
		var ui, gi int
		if _, e1 := fmt.Sscan(u, &ui); e1 == nil {
			if _, e2 := fmt.Sscan(g, &gi); e2 == nil {
				_ = os.Chown(out, ui, gi)
			}
		}
	}
	fmt.Printf("Готово: %s (%d КБ). Пришлите этот файл. Пароли и ключи в нём не собираются; имя хоста и адреса заменены. Просмотрите файл перед отправкой.\n", out, len(text)/1024+1)
}
