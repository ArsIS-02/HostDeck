//go:build linux

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Проверки соответствия для Linux: учётные записи, порты, параметры ядра, монтирование, диски, журналы, целостность, домен, сертификаты.
// Каждая проверка независима: если данных получить нельзя (нет утилиты, нет прав), проверка просто не добавляется.

func readFile(p string) (string, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func readDirFiles(dir, suffix string) string {
	ents, _ := os.ReadDir(dir)
	var sb strings.Builder
	for _, e := range ents {
		if e.IsDir() || (suffix != "" && !strings.HasSuffix(e.Name(), suffix)) {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			sb.Write(b)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func shortList(names []string, n int) string {
	if len(names) > n {
		return strings.Join(names[:n], ", ") + " …"
	}
	return strings.Join(names, ", ")
}

func linuxCompliance(p *Posture, active func(string) bool) {
	add := func(c Check) { p.Checks = append(p.Checks, c) }

	// --- учётные записи ---
	if pw, ok := readFile("/etc/passwd"); ok {
		if extra := parseUID0(pw); len(extra) > 0 {
			add(Check{ID: "uid0", Status: "fail", Value: "extra_uid0", Num: float64(len(extra)), Detail: strings.Join(extra, ", ")})
		} else {
			add(Check{ID: "uid0", Status: "ok", Value: "only_root"})
		}
	}
	if sh, ok := readFile("/etc/shadow"); ok {
		if empty := parseEmptyPasswords(sh); len(empty) > 0 {
			add(Check{ID: "empty_pw", Status: "fail", Value: "empty_pw", Num: float64(len(empty)), Detail: shortList(empty, 6)})
		} else {
			add(Check{ID: "empty_pw", Status: "ok", Value: "clean"})
		}
	}
	if _, ok := readFile("/etc/sudoers"); ok {
		all := readFileOr("/etc/sudoers") + "\n"
		if ents, err := os.ReadDir("/etc/sudoers.d"); err == nil {
			for _, e := range ents {
				// sudo пропускает файлы с точкой и тильдой в имени
				if e.IsDir() || strings.ContainsAny(e.Name(), ".~") {
					continue
				}
				all += readFileOr(filepath.Join("/etc/sudoers.d", e.Name())) + "\n"
			}
		}
		if lines := parseNopasswd(all); len(lines) > 0 {
			add(Check{ID: "sudo_nopasswd", Status: "warn", Value: "nopasswd", Num: float64(len(lines)), Detail: shortList(lines, 3)})
		} else {
			add(Check{ID: "sudo_nopasswd", Status: "ok", Value: "clean"})
		}
	}
	if ld, ok := readFile("/etc/login.defs"); ok {
		maxDays, minLen := parseLoginDefs(ld)
		if q, ok := readFile("/etc/security/pwquality.conf"); ok {
			n := parsePwQuality(q + "\n" + readDirFiles("/etc/security/pwquality.conf.d", ".conf"))
			if n == 0 {
				n = 8 // умолчание libpwquality
			}
			if n > minLen {
				minLen = n
			}
		}
		weak, d := pwPolicy(maxDays, minLen)
		if weak {
			add(Check{ID: "pw_policy", Status: "warn", Value: "policy_weak", Detail: d})
		} else {
			add(Check{ID: "pw_policy", Status: "ok", Value: "policy_ok", Detail: d})
		}
	}

	// --- слушающие порты ---
	var ls []listener
	portsOK := false
	if ss := find("ss"); ss != "" {
		if out, code := runCode(10*time.Second, ss, "-H", "-tulnp"); code == 0 {
			ls, portsOK = parseSS(out), true
		}
	}
	if !portsOK { // нет ss: читаем таблицы сокетов ядра напрямую (имён процессов в этом случае не будет)
		seen := map[string]bool{}
		for _, pr := range []string{"tcp", "tcp6", "udp", "udp6"} {
			if t, ok := readFile("/proc/net/" + pr); ok {
				portsOK = true
				for _, l := range parseProcNet(t, pr) {
					if k := l.Proto + strconv.Itoa(l.Port); !seen[k] {
						seen[k] = true
						ls = append(ls, l)
					}
				}
			}
		}
		sort.Slice(ls, func(i, j int) bool { return ls[i].Port < ls[j].Port })
	}
	if portsOK {
		var unexpected, all []string
		allowed := map[int]bool{}
		for _, a := range allowedPorts {
			allowed[a] = true
		}
		for _, l := range ls {
			all = append(all, l.String())
			if !allowed[l.Port] {
				unexpected = append(unexpected, l.String())
			}
		}
		switch {
		case len(allowedPorts) == 0:
			add(Check{ID: "ports", Status: "info", Value: "ports_listed", Num: float64(len(ls)), Detail: shortList(all, 12)})
		case len(unexpected) > 0:
			add(Check{ID: "ports", Status: "warn", Value: "ports_extra", Num: float64(len(unexpected)), Detail: shortList(unexpected, 8)})
		default:
			add(Check{ID: "ports", Status: "ok", Value: "ports_ok", Num: float64(len(ls)), Detail: shortList(all, 12)})
		}
	}

	// --- параметры ядра ---
	vals := map[string]string{}
	for _, r := range sysctlRules {
		if b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(r.Key, ".", "/")); err == nil {
			vals[r.Key] = strings.TrimSpace(string(b))
		}
	}
	if len(vals) > 0 {
		if devs := evalSysctl(vals); len(devs) > 0 {
			add(Check{ID: "sysctl", Status: "warn", Value: "deviations", Num: float64(len(devs)), Detail: shortList(devs, 4)})
		} else {
			add(Check{ID: "sysctl", Status: "ok", Value: "hardened"})
		}
	}

	// --- монтирование /tmp и /var/tmp ---
	if m, ok := readFile("/proc/mounts"); ok {
		if probs := evalTmp(parseMounts(m)); len(probs) > 0 {
			v := "tmp_opts"
			if strings.Contains(strings.Join(probs, ";"), "нет отдельного") {
				v = "tmp_not_separate"
			}
			add(Check{ID: "tmp_mount", Status: "warn", Value: v, Num: float64(len(probs)), Detail: strings.Join(probs, "; ")})
		} else {
			add(Check{ID: "tmp_mount", Status: "ok", Value: "tmp_ok"})
		}
	}

	// --- здоровье дисков (SMART); в виртуальных машинах SMART недоступен, и проверки не будет ---
	if sc, lb := find("smartctl"), find("lsblk"); sc != "" && lb != "" {
		if out, code := runCode(10*time.Second, lb, "-dno", "NAME,TYPE"); code == 0 {
			var failed, passed []string
			for _, ln := range strings.Split(out, "\n") {
				f := strings.Fields(ln)
				if len(f) < 2 || f[1] != "disk" || strings.HasPrefix(f[0], "zram") || strings.HasPrefix(f[0], "loop") {
					continue
				}
				o, _ := runCode(20*time.Second, sc, "-H", "/dev/"+f[0])
				switch parseSmartHealth(o) {
				case "failed":
					failed = append(failed, f[0])
				case "passed":
					passed = append(passed, f[0])
				}
			}
			if len(failed) > 0 {
				add(Check{ID: "smart", Status: "fail", Value: "smart_failed", Num: float64(len(failed)), Detail: strings.Join(failed, ", ")})
			} else if len(passed) > 0 {
				add(Check{ID: "smart", Status: "ok", Value: "passed", Detail: strings.Join(passed, ", ")})
			}
		}
	}

	// --- правила аудита и пересылка журналов ---
	if ac := find("auditctl"); ac != "" && active("auditd") {
		out, code := runCode(10*time.Second, ac, "-l")
		n := parseAuditRules(out)
		switch {
		case n > 0:
			add(Check{ID: "audit_rules", Status: "ok", Value: "rules", Num: float64(n)})
		case code == 0 || strings.Contains(strings.ToLower(out), "no rules"):
			add(Check{ID: "audit_rules", Status: "warn", Value: "empty"})
		default:
			add(Check{ID: "audit_rules", Status: "unknown", Detail: trim(firstLine(out))})
		}
	}
	linuxLogForward(add, active)
	linuxProbeChecks(add, active)
	linuxContainers(add)

	// --- целостность файлов ---
	linuxIntegrity(add, active)

	// --- FreeIPA и sssd ---
	linuxIPA(add, active)

	// --- сроки действия сертификатов ---
	linuxCerts(add)
}

func readFileOr(p string) string { s, _ := readFile(p); return s }

var syslogNGNet = regexp.MustCompile(`(?i)\b(?:network|syslog)\s*\(\s*"([^"]+)"`)

func linuxLogForward(add func(Check), active func(string) bool) {
	var found []string
	if active("rsyslog") {
		conf := readFileOr("/etc/rsyslog.conf") + "\n" + readDirFiles("/etc/rsyslog.d", ".conf")
		for _, t := range parseRsyslogForward(conf) {
			found = append(found, "rsyslog→"+t)
		}
	}
	if active("syslog-ng") {
		conf := readFileOr("/etc/syslog-ng/syslog-ng.conf") + "\n" + readDirFiles("/etc/syslog-ng/conf.d", ".conf")
		for _, m := range syslogNGNet.FindAllStringSubmatch(conf, -1) {
			found = append(found, "syslog-ng→"+m[1])
		}
	}
	if active("systemd-journal-upload") {
		found = append(found, "journal-upload")
	}
	if plug := readFileOr("/etc/audit/plugins.d/au-remote.conf") + readFileOr("/etc/audit/plugins.d/audisp-remote.conf"); parseAuditRemote(plug) && active("auditd") {
		found = append(found, "audisp-remote")
	}
	for _, svc := range []string{"wazuh-agent", "graylog-sidecar", "filebeat", "nxlog", "vector", "fluent-bit", "td-agent", "promtail", "SplunkForwarder"} {
		if active(svc) {
			found = append(found, svc)
		}
	}
	if len(found) > 0 {
		add(Check{ID: "log_forward", Status: "ok", Value: "forwarding", Num: float64(len(found)), Detail: shortList(found, 5)})
	} else {
		add(Check{ID: "log_forward", Status: "warn", Value: "no_forward"})
	}
}

func linuxIntegrity(add func(Check), active func(string) bool) {
	var tools []string
	if find("aide") != "" {
		for _, db := range []string{"/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db", "/var/lib/aide/aide.db.new.gz"} {
			if st, err := os.Stat(db); err == nil {
				tools = append(tools, "AIDE ("+st.ModTime().Format("2006-01-02")+")")
				break
			}
		}
	}
	if s, ok := readFile("/sys/kernel/security/ima/runtime_measurements_count"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 1 {
			tools = append(tools, "IMA")
		}
	}
	if find("tripwire") != "" {
		if _, err := os.Stat("/var/lib/tripwire"); err == nil {
			tools = append(tools, "Tripwire")
		}
	}
	if active("samhain") {
		tools = append(tools, "Samhain")
	}
	if len(tools) > 0 {
		add(Check{ID: "integrity", Status: "ok", Value: "integrity_on", Detail: strings.Join(tools, ", ")})
	} else {
		add(Check{ID: "integrity", Status: "warn", Value: "integrity_off"})
	}
}

func linuxIPA(add func(Check), active func(string) bool) {
	conf, ipa := readFile("/etc/ipa/default.conf")
	sssd := active("sssd")
	domain := parseIPADomain(conf)
	switch {
	case !ipa && !sssd:
		add(Check{ID: "freeipa", Status: "info", Value: "not_joined"})
	case !ipa:
		add(Check{ID: "freeipa", Status: "info", Value: "sssd_only"})
	case !sssd:
		add(Check{ID: "freeipa", Status: "fail", Value: "sssd_down", Detail: domain})
	default:
		if _, err := os.Stat("/etc/krb5.keytab"); err != nil {
			add(Check{ID: "freeipa", Status: "fail", Value: "no_keytab", Detail: domain})
			return
		}
		if sc := find("sssctl"); sc != "" && domain != "" {
			out, _ := runCode(15*time.Second, sc, "domain-status", domain)
			if parseSssctlOnline(out) == "offline" {
				add(Check{ID: "freeipa", Status: "warn", Value: "ipa_offline", Detail: domain})
				return
			}
		}
		add(Check{ID: "freeipa", Status: "ok", Value: "enrolled", Detail: domain})
	}
}

var certDirs = []string{"/etc/letsencrypt/live", "/etc/pki/tls/certs", "/etc/pki/ca-trust/source/anchors", "/usr/local/share/ca-certificates",
	"/etc/ipa", "/var/lib/ipa/certs", "/etc/ssl/localcerts"}

func linuxCerts(add func(Check)) {
	var certs []certInfo
	seen := map[string]bool{}
	for _, dir := range certDirs {
		base := strings.Count(dir, "/")
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(path, "/")-base >= 2 {
					return filepath.SkipDir
				}
				return nil
			}
			n := strings.ToLower(d.Name())
			ext := filepath.Ext(n)
			if ext != ".crt" && ext != ".pem" && ext != ".cer" {
				return nil
			}
			if strings.Contains(n, "bundle") || strings.Contains(n, "trust") || strings.Contains(n, "key") || n == "chain.pem" || n == "fullchain.pem" {
				return nil
			}
			st, err := os.Stat(path) // следуем за ссылками: в letsencrypt/live они указывают на archive
			if err != nil || st.IsDir() || st.Size() > 256*1024 {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, c := range parseCerts(filepath.Base(path), b) {
				k := c.Name + c.NotAfter.String()
				if !seen[k] {
					seen[k] = true
					certs = append(certs, c)
				}
			}
			return nil
		})
	}
	if len(certs) == 0 {
		return
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotAfter.Before(certs[j].NotAfter) })
	now := time.Now()
	var expired []string
	for _, c := range certs {
		if c.NotAfter.Before(now) {
			expired = append(expired, c.Name+" — "+c.NotAfter.Format("2006-01-02"))
		}
	}
	first := certs[0]
	days := int(first.NotAfter.Sub(now).Hours() / 24)
	switch {
	case len(expired) > 0:
		add(Check{ID: "certs", Status: "fail", Value: "expired", Num: float64(len(expired)), Detail: shortList(expired, 3)})
	case days < 30:
		add(Check{ID: "certs", Status: "warn", Value: "valid", Num: float64(days), Detail: first.Name + " — " + first.NotAfter.Format("2006-01-02")})
	default:
		add(Check{ID: "certs", Status: "ok", Value: "valid", Num: float64(days), Detail: first.Name + " — " + first.NotAfter.Format("2006-01-02")})
	}
}
