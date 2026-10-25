package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Check — один пункт проверки состояния хоста.
type Check struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`          // ok | warn | fail | unknown | info
	Value  string  `json:"value,omitempty"` // код значения (on, off, after:300, ...) — подписывает интерфейс на нужном языке
	Num    float64 `json:"num,omitempty"`   // число для значений с параметром (процент, количество)
	Detail string  `json:"detail,omitempty"`
}

func parseFileVault(out string) (string, string) {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return "ok", "on"
	case strings.Contains(out, "Encryption in progress"), strings.Contains(out, "Decryption in progress"):
		return "warn", "in_progress"
	case strings.Contains(out, "FileVault is Off"):
		return "fail", "off"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseSIP(out string) (string, string) {
	// Статус читаем по первой строке: в нестандартной конфигурации ниже идёт список опций,
	// где встречается слово "disabled".
	l := strings.ToLower(firstLine(out))
	switch {
	case strings.Contains(l, "custom configuration"):
		return "warn", "custom"
	case strings.Contains(l, "disabled"):
		return "fail", "off"
	case strings.Contains(l, "enabled"):
		return "ok", "on"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseGatekeeper(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "assessments disabled"):
		return "fail", "off"
	case strings.Contains(l, "assessments enabled"):
		return "ok", "on"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseFirewall(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "state = 0"), strings.Contains(l, "disabled"):
		return "fail", "off"
	case strings.Contains(l, "state = 1"), strings.Contains(l, "state = 2"), strings.Contains(l, "enabled"):
		return "ok", "on"
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseStealth(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "disabled"), strings.Contains(l, "is off"):
		return "warn", "off"
	case strings.Contains(l, "enabled"), strings.Contains(l, "is on"):
		return "ok", "on"
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
		return "warn", "off"
	case strings.Contains(l, "immediate"):
		return "ok", "immediate"
	}
	if m := delayRe.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n <= 300 {
			return "ok", "after:" + m[1]
		}
		return "warn", "after:" + m[1]
	}
	return "unknown", strings.TrimSpace(firstLine(out))
}

func parseRemoteLogin(out string) (string, string) {
	l := strings.ToLower(out)
	switch {
	case strings.Contains(l, "remote login: on"):
		return "info", "on"
	case strings.Contains(l, "remote login: off"):
		return "info", "off"
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

// ---- метрики ----

var cpuRe = regexp.MustCompile(`CPU usage:\s*([\d.]+)% user,\s*([\d.]+)% sys,\s*([\d.]+)% idle`)

// parseTopCPU берёт последнюю строку "CPU usage" из вывода `top -l 2` (первый замер у top всегда накопительный).
func parseTopCPU(out string) (float64, bool) {
	all := cpuRe.FindAllStringSubmatch(out, -1)
	if len(all) == 0 {
		return 0, false
	}
	m := all[len(all)-1]
	idle, err := strconv.ParseFloat(m[3], 64)
	if err != nil {
		return 0, false
	}
	return 100 - idle, true
}

var vmLineRe = regexp.MustCompile(`^(.+?):\s+(\d+)\.?$`)
var pageSizeRe = regexp.MustCompile(`page size of (\d+) bytes`)

// parseVMStat возвращает занятую память в байтах: активная + закреплённая + сжатая (как «Память» в Мониторе системы).
func parseVMStat(out string) (usedBytes float64, ok bool) {
	ps := 4096.0
	if m := pageSizeRe.FindStringSubmatch(out); m != nil {
		ps, _ = strconv.ParseFloat(m[1], 64)
	}
	vals := map[string]float64{}
	for _, ln := range strings.Split(out, "\n") {
		if m := vmLineRe.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			v, _ := strconv.ParseFloat(m[2], 64)
			vals[m[1]] = v
		}
	}
	act, ok1 := vals["Pages active"]
	wired, ok2 := vals["Pages wired down"]
	if !ok1 || !ok2 {
		return 0, false
	}
	return (act + wired + vals["Pages occupied by compressor"]) * ps, true
}

var swapRe = regexp.MustCompile(`total = ([\d.]+)M\s+used = ([\d.]+)M`)

func parseSwap(out string) (usedPct float64, totalMB float64, ok bool) {
	m := swapRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	t, _ := strconv.ParseFloat(m[1], 64)
	u, _ := strconv.ParseFloat(m[2], 64)
	if t == 0 {
		return 0, 0, true
	}
	return u / t * 100, t, true
}

var battRe = regexp.MustCompile(`(\d+)%;\s*([a-zA-Z ]+?);`)

// parseBattery: процент и признак «заряжается / на питании от сети». Нет батареи — ok=false.
func parseBattery(out string) (pct float64, charging bool, ok bool) {
	m := battRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false, false
	}
	pct, _ = strconv.ParseFloat(m[1], 64)
	st := strings.ToLower(strings.TrimSpace(m[2]))
	charging = st == "charging" || st == "charged" || st == "finishing charge" || strings.Contains(out, "AC Power")
	return pct, charging, true
}

// parseLoadAvg: "{ 1.52 1.60 1.71 }" (macOS sysctl) или "1.52 1.60 1.71 1/234 5678" (Linux /proc/loadavg).
func parseLoadAvg(out string) (float64, bool) {
	f := strings.Fields(strings.NewReplacer("{", " ", "}", " ").Replace(out))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}
