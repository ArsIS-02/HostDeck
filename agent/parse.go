package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Check — один пункт проверки состояния хоста.
type Check struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warn | fail | unknown | info
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func parseFileVault(out string) (string, string) {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return "ok", "включено"
	case strings.Contains(out, "Encryption in progress"), strings.Contains(out, "Decryption in progress"):
		return "warn", "идёт шифрование/расшифровка"
	case strings.Contains(out, "FileVault is Off"):
		return "fail", "выключено"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseSIP(out string) (string, string) {
	// Статус читаем по первой строке: в нестандартной конфигурации ниже идёт список опций,
	// где встречается слово "disabled".
	l := strings.ToLower(firstLine(out))
	switch {
	case strings.Contains(l, "custom configuration"):
		return "warn", "нестандартная конфигурация"
	case strings.Contains(l, "disabled"):
		return "fail", "отключена"
	case strings.Contains(l, "enabled"):
		return "ok", "включена"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseGatekeeper(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "assessments disabled"):
		return "fail", "отключён"
	case strings.Contains(l, "assessments enabled"):
		return "ok", "включён"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseFirewall(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "state = 0"), strings.Contains(l, "disabled"):
		return "fail", "выключен"
	case strings.Contains(l, "state = 1"), strings.Contains(l, "state = 2"), strings.Contains(l, "enabled"):
		return "ok", "включён"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseStealth(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "disabled"), strings.Contains(l, "is off"):
		return "warn", "выключен"
	case strings.Contains(l, "enabled"), strings.Contains(l, "is on"):
		return "ok", "включён"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

var updLine = regexp.MustCompile(`^\s*\*\s+(?:Label:\s*)?(.+?)\s*$`)

// parseUpdates разбирает вывод `softwareupdate --list`: возвращает названия доступных обновлений.
func parseUpdates(out string) (titles []string, known bool) {
	if strings.Contains(out, "No new software available") {
		return nil, true
	}
	for _, ln := range strings.Split(out, "\n") {
		if m := updLine.FindStringSubmatch(ln); m != nil {
			titles = append(titles, m[1])
		}
	}
	if len(titles) > 0 {
		return titles, true
	}
	return nil, strings.Contains(out, "Software Update Tool")
}

// parseDefaultsBool разбирает вывод `defaults read`: "1"/"0"/"true"/"false".
func parseDefaultsBool(out string) (val bool, set bool) {
	s := strings.ToLower(strings.TrimSpace(out))
	switch s {
	case "1", "true", "yes":
		return true, true
	case "0", "false", "no":
		return false, true
	}
	return false, false
}

var bootRe = regexp.MustCompile(`sec\s*=\s*(\d+)`)

func parseBootTime(out string) (int64, bool) {
	m := bootRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	return n, err == nil
}

var delayRe = regexp.MustCompile(`(?i)delay is (\d+) seconds?`)

func parseScreenLock(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "screenlock is off"), strings.Contains(l, "disabled"):
		return "warn", "выключена"
	case strings.Contains(l, "immediate"):
		return "ok", "сразу"
	}
	if m := delayRe.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n <= 300 {
			return "ok", "через " + m[1] + " с"
		}
		return "warn", "через " + m[1] + " с"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseRemoteLogin(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "remote login: on"):
		return "info", "включён"
	case strings.Contains(l, "remote login: off"):
		return "info", "выключен"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
