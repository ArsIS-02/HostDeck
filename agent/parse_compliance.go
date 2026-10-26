package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Разборщики для проверок соответствия (macOS и Linux). Файл без build-тегов: тесты идут на любой платформе.

// ---------- macOS ----------

var tmDate = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}`)
var tmPath = regexp.MustCompile(`(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})`)

// parseTimeMachine читает `defaults read /Library/Preferences/com.apple.TimeMachine`:
// время последней копии (по SnapshotDates) и настроен ли хотя бы один диск назначения.
func parseTimeMachine(out string) (latest int64, configured bool) {
	configured = strings.Contains(out, "DestinationID") || strings.Contains(out, "Destinations")
	now := time.Now().Unix()
	for _, s := range tmDate.FindAllString(out, -1) {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", s); err == nil && t.Unix() > latest && t.Unix() <= now+86400 {
			latest = t.Unix()
		}
	}
	return
}

// parseLatestBackup читает путь из `tmutil latestbackup` (…/2026-10-25-120000 или …-120000.backup).
func parseLatestBackup(out string) (int64, bool) {
	m := tmPath.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", fmt.Sprintf("%s-%s-%s %s:%s:%s", m[1], m[2], m[3], m[4], m[5], m[6]), time.Local)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

// parseGuest: on — гостевой вход включён; ok=false — вывод не распознан.
func parseGuest(out string) (on bool, ok bool) {
	l := strings.ToLower(strings.TrimSpace(out))
	switch {
	case strings.Contains(l, "disabled"), l == "0":
		return false, true
	case strings.Contains(l, "enabled"), l == "1":
		return true, true
	}
	return false, false
}

// parseAutoLogin: имя пользователя автовхода или "" (ключа нет).
func parseAutoLogin(out string) string {
	s := strings.TrimSpace(out)
	if s == "" || strings.Contains(s, "does not exist") || strings.Contains(s, "Could not find") || strings.HasPrefix(s, "Error") || strings.Contains(s, "Domain") {
		return ""
	}
	return firstLine(s)
}

// parseAdmins читает `dscl . -read /Groups/admin GroupMembership`: пользователи без root и служебных (_имя).
func parseAdmins(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if !strings.HasPrefix(ln, "GroupMembership:") {
			continue
		}
		for _, n := range strings.Fields(strings.TrimPrefix(ln, "GroupMembership:")) {
			if n != "root" && !strings.HasPrefix(n, "_") {
				names = append(names, n)
			}
		}
	}
	return names
}

// parseProfiles читает `profiles list`: идентификаторы установленных профилей.
func parseProfiles(out string) []string {
	var ids []string
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "profileIdentifier:"); i >= 0 {
			ids = append(ids, strings.TrimSpace(ln[i+len("profileIdentifier:"):]))
		}
	}
	return ids
}

// parseSysExt читает `systemextensionsctl list`: идентификаторы включённых системных расширений.
func parseSysExt(out string) []string {
	var ids []string
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, "activated enabled") {
			continue
		}
		for _, f := range strings.Fields(ln) {
			if strings.Count(f, ".") >= 2 && !strings.HasPrefix(f, "[") && !strings.HasPrefix(f, "(") {
				ids = append(ids, f)
				break
			}
		}
	}
	return ids
}

var displaySleepRe = regexp.MustCompile(`(?m)^\s*displaysleep\s+(\d+)`)

// parseDisplaySleep: через сколько минут простоя гаснет дисплей (0 — никогда).
func parseDisplaySleep(out string) (int, bool) {
	m := displaySleepRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// parseDiscoverable: режим AirDrop: off, contacts, everyone; "" — не задан.
func parseDiscoverable(out string) string {
	l := strings.ToLower(strings.TrimSpace(out))
	switch {
	case l == "" || strings.Contains(l, "does not exist"):
		return ""
	case strings.Contains(l, "everyone"):
		return "everyone"
	case strings.Contains(l, "contacts"):
		return "contacts"
	case strings.Contains(l, "off"):
		return "off"
	}
	return ""
}

// parseIntDefault читает одно число из вывода `defaults read`.
func parseIntDefault(out string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(firstLine(out)))
	return n, err == nil
}

// ---------- Linux: учётные записи ----------

// parseUID0 читает /etc/passwd: имена с UID 0, кроме root.
func parseUID0(passwd string) []string {
	var names []string
	for _, ln := range strings.Split(passwd, "\n") {
		f := strings.Split(ln, ":")
		if len(f) >= 4 && f[2] == "0" && f[0] != "root" && !strings.HasPrefix(f[0], "#") {
			names = append(names, f[0])
		}
	}
	return names
}

// parseEmptyPasswords читает /etc/shadow: учётные записи с пустым полем пароля (вход без пароля).
func parseEmptyPasswords(shadow string) []string {
	var names []string
	for _, ln := range strings.Split(shadow, "\n") {
		f := strings.Split(ln, ":")
		if len(f) >= 2 && f[0] != "" && !strings.HasPrefix(f[0], "#") && f[1] == "" {
			names = append(names, f[0])
		}
	}
	return names
}

// parseNopasswd ищет правила sudo с NOPASSWD (комментарии пропускаются).
func parseNopasswd(text string) []string {
	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.Contains(ln, "NOPASSWD") {
			lines = append(lines, strings.Join(strings.Fields(ln), " "))
		}
	}
	return lines
}

// parseLoginDefs возвращает значение PASS_MAX_DAYS (если нет — 99999, то есть пароль не стареет) и PASS_MIN_LEN.
func parseLoginDefs(text string) (maxDays int, minLen int) {
	maxDays = 99999
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch f[0] {
		case "PASS_MAX_DAYS":
			maxDays = n
		case "PASS_MIN_LEN":
			minLen = n
		}
	}
	return
}

// parsePwQuality читает minlen из pwquality.conf (0 — не задан).
func parsePwQuality(text string) int {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") || !strings.Contains(ln, "=") {
			continue
		}
		kv := strings.SplitN(ln, "=", 2)
		if strings.TrimSpace(kv[0]) == "minlen" {
			n, _ := strconv.Atoi(strings.TrimSpace(kv[1]))
			return n
		}
	}
	return 0
}

// pwPolicy оценивает политику паролей: нужна длина не меньше 8 и срок действия не больше года.
func pwPolicy(maxDays, minLen int) (weak bool, detail string) {
	if maxDays <= 0 || maxDays > 365 {
		weak = true
	}
	if minLen < 8 {
		weak = true
	}
	md := strconv.Itoa(maxDays)
	if maxDays >= 99999 {
		md = "∞"
	}
	ml := strconv.Itoa(minLen)
	if minLen == 0 {
		ml = "—"
	}
	return weak, fmt.Sprintf("PASS_MAX_DAYS=%s, minlen=%s", md, ml)
}

// ---------- Linux: порты ----------

type listener struct {
	Proto string
	Addr  string
	Port  int
	Proc  string
}

var ssProc = regexp.MustCompile(`\(\("([^"]+)"`)

// parseSS читает `ss -H -tulnp`; слушатели на loopback пропускаются.
func parseSS(out string) []listener {
	var res []listener
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, ps := strings.Trim(local[:i], "[]"), local[i+1:]
		port, err := strconv.Atoi(ps)
		if err != nil {
			continue
		}
		if i := strings.Index(addr, "%"); i >= 0 {
			addr = addr[:i]
		}
		if strings.HasPrefix(addr, "127.") || addr == "::1" {
			continue
		}
		key := proto + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		proc := ""
		if m := ssProc.FindStringSubmatch(ln); m != nil {
			proc = m[1]
		}
		res = append(res, listener{proto, addr, port, proc})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Port != res[j].Port {
			return res[i].Port < res[j].Port
		}
		return res[i].Proto < res[j].Proto
	})
	return res
}

func (l listener) String() string {
	s := fmt.Sprintf("%s/%d", l.Proto, l.Port)
	if l.Proc != "" {
		s += " " + l.Proc
	}
	return s
}

// ---------- Linux: параметры ядра ----------

type sysctlRule struct {
	Key  string
	Want func(int) bool
	Hint string
}

var sysctlRules = []sysctlRule{
	{"kernel.randomize_va_space", func(v int) bool { return v == 2 }, "=2"},
	{"net.ipv4.conf.all.rp_filter", func(v int) bool { return v >= 1 }, "≥1"},
	{"net.ipv4.tcp_syncookies", func(v int) bool { return v == 1 }, "=1"},
	{"net.ipv4.conf.all.accept_redirects", func(v int) bool { return v == 0 }, "=0"},
	{"net.ipv4.conf.all.send_redirects", func(v int) bool { return v == 0 }, "=0"},
	{"net.ipv4.conf.all.accept_source_route", func(v int) bool { return v == 0 }, "=0"},
	{"kernel.kptr_restrict", func(v int) bool { return v >= 1 }, "≥1"},
	{"kernel.dmesg_restrict", func(v int) bool { return v == 1 }, "=1"},
	{"fs.suid_dumpable", func(v int) bool { return v == 0 }, "=0"},
}

// evalSysctl сравнивает значения с рекомендациями; отсутствующие параметры не считаются нарушением.
func evalSysctl(values map[string]string) (devs []string) {
	for _, r := range sysctlRules {
		s, ok := values[r.Key]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if !r.Want(n) {
			devs = append(devs, fmt.Sprintf("%s=%d (нужно %s)", r.Key, n, r.Hint))
		}
	}
	return
}

// ---------- Linux: монтирование /tmp ----------

// parseMounts читает /proc/mounts: точка → набор опций.
func parseMounts(text string) map[string]map[string]bool {
	res := map[string]map[string]bool{}
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		opts := map[string]bool{}
		for _, o := range strings.Split(f[3], ",") {
			opts[o] = true
		}
		res[f[1]] = opts // последняя запись выигрывает: она и действует
	}
	return res
}

// evalTmp: для каждого из /tmp и /var/tmp нужен либо отдельный монтируемый раздел с noexec и nosuid, либо привязка (bind) к такому.
func evalTmp(mounts map[string]map[string]bool) (problems []string) {
	for _, p := range []string{"/tmp", "/var/tmp"} {
		o, ok := mounts[p]
		if !ok {
			problems = append(problems, p+": нет отдельного раздела")
			continue
		}
		var miss []string
		for _, need := range []string{"noexec", "nosuid"} {
			if !o[need] {
				miss = append(miss, need)
			}
		}
		if len(miss) > 0 {
			problems = append(problems, p+": нет "+strings.Join(miss, ", "))
		}
	}
	return
}

// ---------- Linux: диски, журналы, целостность ----------

// parseSmartHealth читает `smartctl -H`: passed, failed или "" (SMART недоступен, например в виртуальной машине).
func parseSmartHealth(out string) string {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "test result: failed"), strings.Contains(l, "health status: failed"), strings.Contains(l, "failing_now"):
		return "failed"
	case strings.Contains(l, "test result: passed"), strings.Contains(l, "health status: ok"):
		return "passed"
	}
	return ""
}

// parseAuditRules считает правила в выводе `auditctl -l`.
func parseAuditRules(out string) int {
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && !strings.HasPrefix(strings.ToLower(ln), "no rules") && strings.HasPrefix(ln, "-") {
			n++
		}
	}
	return n
}

var rsyslogAt = regexp.MustCompile(`\s@{1,2}(\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9._\-]*)(:\d+)?\s*($|;|\s)`)
var rsyslogTarget = regexp.MustCompile(`(?i)target\s*=\s*"([^"]+)"`)

// parseRsyslogForward находит адреса, куда rsyslog пересылает журнал (@host, @@host, omfwd target=).
func parseRsyslogForward(text string) []string {
	var res []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		var target string
		if strings.Contains(t, "omfwd") {
			if m := rsyslogTarget.FindStringSubmatch(t); m != nil {
				target = m[1]
			}
		} else if m := rsyslogAt.FindStringSubmatch(" " + t + " "); m != nil && !strings.HasPrefix(t, "$") {
			target = m[1] + m[2]
		}
		if target != "" && !seen[target] {
			seen[target] = true
			res = append(res, target)
		}
	}
	return res
}

// parseAuditRemote: включён ли плагин audisp-remote (active = yes).
func parseAuditRemote(text string) bool {
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(strings.ReplaceAll(strings.ToLower(ln), "=", " "))
		if len(f) >= 2 && f[0] == "active" {
			return f[1] == "yes"
		}
	}
	return false
}

// ---------- Linux: обновления безопасности ----------

type secAdvisory struct{ ID, Sev, Pkg string }

// parseDnfSecurity читает `dnf updateinfo list security` (строки «RLSA-2026:1234 Important/Sec. kernel-5.14…»).
func parseDnfSecurity(out string) []secAdvisory {
	var res []secAdvisory
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 || strings.HasPrefix(ln, "Last metadata") {
			continue
		}
		if !strings.Contains(f[1], "/Sec") && !strings.Contains(strings.ToLower(f[1]), "security") {
			continue
		}
		sev := strings.ToLower(strings.SplitN(f[1], "/", 2)[0])
		res = append(res, secAdvisory{f[0], sev, f[2]})
	}
	return res
}

// parseAptSecurity выбирает из `apt-get -s upgrade` строки, пришедшие из репозиториев безопасности.
func parseAptSecurity(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Inst ") && strings.Contains(strings.ToLower(ln), "security") {
			if f := strings.Fields(ln); len(f) > 1 {
				names = append(names, f[1])
			}
		}
	}
	return names
}

// ---------- Linux: FreeIPA и sssd ----------

// parseIPADomain читает domain= из /etc/ipa/default.conf.
func parseIPADomain(text string) string {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "domain") {
			if kv := strings.SplitN(ln, "=", 2); len(kv) == 2 && strings.TrimSpace(kv[0]) == "domain" {
				return strings.TrimSpace(kv[1])
			}
		}
	}
	return ""
}

// parseSssctlOnline читает `sssctl domain-status`: online, offline или "".
func parseSssctlOnline(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(l, "online status:") {
			if strings.Contains(l, "offline") {
				return "offline"
			}
			if strings.Contains(l, "online") {
				return "online"
			}
		}
	}
	return ""
}

// ---------- Linux: сертификаты ----------

type certInfo struct {
	Name     string
	NotAfter time.Time
}

// parseCerts разбирает все сертификаты PEM из файла.
func parseCerts(name string, data []byte) []certInfo {
	var res []certInfo
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		n := c.Subject.CommonName
		if n == "" {
			n = name
		}
		res = append(res, certInfo{Name: n + " (" + name + ")", NotAfter: c.NotAfter})
	}
	return res
}

// parseProcNet читает /proc/net/{tcp,tcp6,udp,udp6} (запасной путь, если нет утилиты ss): слушающие сокеты без loopback.
func parseProcNet(text, proto string) []listener {
	var res []listener
	for i, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 4 {
			continue
		}
		if strings.HasPrefix(proto, "tcp") && f[3] != "0A" { // 0A — LISTEN
			continue
		}
		if strings.HasPrefix(proto, "udp") && f[3] != "07" { // 07 — несвязанный UDP-сокет
			continue
		}
		a := strings.SplitN(f[1], ":", 2)
		if len(a) != 2 {
			continue
		}
		port, err := strconv.ParseInt(a[1], 16, 32)
		if err != nil {
			continue
		}
		if a[0] == "0100007F" || a[0] == "00000000000000000000000001000000" || strings.HasSuffix(a[0], "7F") && len(a[0]) == 8 {
			continue
		}
		res = append(res, listener{Proto: strings.TrimSuffix(proto, "6"), Addr: a[0], Port: int(port)})
	}
	return res
}
