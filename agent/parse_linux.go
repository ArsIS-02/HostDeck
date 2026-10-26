package main

import (
	"regexp"
	"strings"
)

// Разборщики вывода Linux-утилит. Файл без build-тегов: тесты идут на любой платформе.

func parseSELinux(out string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(firstLine(out))) {
	case "enforcing":
		return "ok", "enforcing"
	case "permissive":
		return "warn", "permissive"
	case "disabled":
		return "fail", "off"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

// selinuxForArch: на arm64 в используемых дистрибутивах SELinux не предусмотрен. Если он там не работает,
// это не проблема хоста, а особенность архитектуры: статус «na» (не применимо). Если же реально включён — показываем как есть.
func selinuxForArch(arch, status, value string) (string, string) {
	if arch == "arm64" && (status == "fail" || status == "unknown") {
		return "na", "arch_unsupported"
	}
	return status, value
}

// parseIptables читает вывод `iptables -S`: политика цепочки INPUT и число правил (-A).
func parseIptables(out string) (policy string, rules int) {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "-P INPUT "):
			policy = strings.TrimSpace(strings.TrimPrefix(ln, "-P INPUT "))
		case strings.HasPrefix(ln, "-A "):
			rules++
		}
	}
	return
}

var nftHookInput = regexp.MustCompile(`hook input .*policy (\w+)`)
var nftRule = regexp.MustCompile(`\b(accept|drop|reject|jump|goto|masquerade|dnat|snat|redirect|queue)\b`)

// parseNft читает `nft list ruleset`: политика базовой цепочки input и число правил.
func parseNft(out string) (policy string, rules int) {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if m := nftHookInput.FindStringSubmatch(ln); m != nil {
			if policy == "" || strings.EqualFold(m[1], "drop") {
				policy = strings.ToUpper(m[1])
			}
			continue
		}
		if strings.Contains(ln, " hook ") || strings.HasPrefix(ln, "type ") || strings.HasPrefix(ln, "table ") || strings.HasPrefix(ln, "chain ") || ln == "}" {
			continue
		}
		if nftRule.MatchString(ln) {
			rules++
		}
	}
	return
}

func parseUFW(out string) bool {
	return strings.Contains(strings.ToLower(out), "status: active")
}

// parseSSHD читает `sshd -T` (ключи в нижнем регистре).
func parseSSHD(out string) (rootLogin bool, passAuth bool, ok bool) {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(strings.ToLower(ln))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "permitrootlogin":
			ok = true
			rootLogin = f[1] == "yes"
		case "passwordauthentication":
			passAuth = f[1] == "yes"
		}
	}
	return
}

var dnfLine = regexp.MustCompile(`^\S+\.\S+\s+\S+\s+\S+\s*$`)

// parseDnfUpdates считает строки с пакетами в выводе `dnf check-update`.
func parseDnfUpdates(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Obsoleting Packages") {
			break
		}
		if dnfLine.MatchString(ln) && !strings.HasPrefix(ln, "Last metadata") {
			names = append(names, strings.Fields(ln)[0])
		}
	}
	return names
}

// parseAptUpdates считает строки "Inst" в выводе `apt-get -s upgrade`.
func parseAptUpdates(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Inst ") {
			if f := strings.Fields(ln); len(f) > 1 {
				names = append(names, f[1])
			}
		}
	}
	return names
}

// parseFailedUnits читает `systemctl --failed --plain --no-legend`.
func parseFailedUnits(out string) []string {
	var names []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimLeft(ln, "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			names = append(names, f[0])
		}
	}
	return names
}

func parseLsblkCrypt(out string) bool {
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "crypt" {
			return true
		}
	}
	return false
}
