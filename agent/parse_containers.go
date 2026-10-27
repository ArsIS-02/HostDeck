package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Контейнер в том виде, в каком его видит проверка. Поля берутся из `podman inspect` и `docker inspect` (формат у них общий).
type ctr struct {
	ID      string
	Name    string
	Owner   string // root или имя пользователя (rootless Podman)
	Status  string // running, exited, created, restarting, paused, ...
	Exit    int
	Policy  string // no, always, unless-stopped, on-failure
	Restart int
	Started time.Time
	Health  string // healthy, unhealthy, starting или пусто
	Runtime string // podman или docker
	Image   string
	ImageID string // полный ID образа без префикса sha256:
	Unit    string // юнит systemd, который запускает контейнер (метка PODMAN_SYSTEMD_UNIT: Quadlet, generate systemd)
	Compose string // проект docker compose
	Binds   []portBind
}

// portBind: опубликованный на хосте порт контейнера.
type portBind struct {
	IP, Host, Cont, Proto string
}

func (b portBind) String() string {
	ip := b.IP
	if ip == "" {
		ip = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%s->%s/%s", ip, b.Host, b.Cont, b.Proto)
}

func (b portBind) anyIP() bool { return b.IP == "" || b.IP == "0.0.0.0" || b.IP == "::" }

// CtrInfo: строка списка контейнеров в отчёте агента. Переменные окружения, команды запуска и тома не собираются:
// в них бывают пароли и токены.
type CtrInfo struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Image    string   `json:"image,omitempty"`
	ImageID  string   `json:"image_id,omitempty"`
	Unit     string   `json:"unit,omitempty"`
	Compose  string   `json:"compose,omitempty"`
	Runtime  string   `json:"runtime"`
	Owner    string   `json:"owner,omitempty"`
	State    string   `json:"state"`
	Exit     int      `json:"exit,omitempty"`
	Restart  string   `json:"restart,omitempty"`
	Restarts int      `json:"restarts,omitempty"`
	Health   string   `json:"health,omitempty"`
	Ports    []string `json:"ports,omitempty"`
	Started  int64    `json:"started,omitempty"`
}

func ctrInfos(cs []ctr) []CtrInfo {
	out := make([]CtrInfo, 0, len(cs))
	for _, c := range cs {
		it := CtrInfo{ID: shortID(c.ID), ImageID: shortID(c.ImageID), Unit: c.Unit, Compose: c.Compose, Name: c.Name, Image: c.Image, Runtime: c.Runtime, State: c.Status, Exit: c.Exit, Restart: c.Policy,
			Restarts: c.Restart, Health: c.Health}
		if c.Owner != "" && c.Owner != "root" {
			it.Owner = c.Owner
		}
		if !c.Started.IsZero() && c.Status == "running" {
			it.Started = c.Started.Unix()
		}
		for _, b := range c.Binds {
			it.Ports = append(it.Ports, b.String())
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Owner < out[j].Owner
	})
	if len(out) > 150 {
		out = out[:150]
	}
	return out
}

type inspectDoc struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Restart int    `json:"RestartCount"`
	State   struct {
		Status    string `json:"Status"`
		ExitCode  int    `json:"ExitCode"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	ImageName string `json:"ImageName"`
	ImageID   string `json:"Image"`
}

// parseInspect разбирает вывод `inspect` (JSON-массив). Лишние поля игнорируются, чужие версии формата не ломают разбор.
func parseInspect(js, owner string) ([]ctr, error) {
	js = strings.TrimSpace(js)
	if js == "" || js == "[]" {
		return nil, nil
	}
	var docs []inspectDoc
	if err := json.Unmarshal([]byte(js), &docs); err != nil {
		return nil, err
	}
	out := make([]ctr, 0, len(docs))
	for _, d := range docs {
		c := ctr{ID: d.ID, Name: strings.TrimPrefix(d.Name, "/"), Owner: owner, Status: strings.ToLower(d.State.Status),
			Exit: d.State.ExitCode, Policy: strings.ToLower(d.HostConfig.RestartPolicy.Name), Restart: d.Restart}
		if t, err := time.Parse(time.RFC3339Nano, d.State.StartedAt); err == nil && t.Year() > 2000 {
			c.Started = t
		}
		if d.State.Health != nil {
			c.Health = strings.ToLower(d.State.Health.Status)
		}
		c.ImageID = normID(d.ImageID)
		c.Unit = d.Config.Labels["PODMAN_SYSTEMD_UNIT"]
		c.Compose = d.Config.Labels["com.docker.compose.project"]
		c.Image = d.ImageName
		if c.Image == "" {
			c.Image = d.Config.Image
		}
		if len(c.Image) > 200 {
			c.Image = c.Image[:200]
		}
		keys := make([]string, 0, len(d.HostConfig.PortBindings))
		for k := range d.HostConfig.PortBindings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cp, proto := k, "tcp"
			if i := strings.IndexByte(k, '/'); i >= 0 {
				cp, proto = k[:i], k[i+1:]
			}
			for _, b := range d.HostConfig.PortBindings[k] {
				if b.HostPort != "" && b.HostPort != "0" {
					c.Binds = append(c.Binds, portBind{IP: b.HostIP, Host: b.HostPort, Cont: cp, Proto: proto})
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// parseIDs достаёт идентификаторы из вывода `ps -aq`.
func parseIDs(out string) []string {
	var ids []string
	for _, f := range strings.Fields(out) {
		if len(f) >= 6 && !strings.ContainsAny(f, ":/[]") {
			ids = append(ids, f)
		}
	}
	return ids
}

// dedupCtr убирает повторы: docker-обёртка над Podman показывает те же контейнеры, что и podman.
func dedupCtr(in []ctr) []ctr {
	seen := map[string]bool{}
	var out []ctr
	for _, c := range in {
		k := c.ID
		if k == "" {
			k = c.Owner + "/" + c.Name
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}

func wantsRestart(p string) bool { return p == "always" || p == "unless-stopped" }

// judgeContainers оценивает набор контейнеров.
//
//	fail    контейнер перезапускается по кругу;
//	warn    контейнер должен работать (restart=always|unless-stopped), но остановлен с ошибкой или не стартовал; контейнер нездоров (unhealthy);
//	        сбойная пользовательская служба (units); политика always есть, а podman-restart.service выключен (после перезагрузки не поднимутся);
//	ok      остальное.
//
// restartSvc: "disabled", "enabled" или "" (не Podman или не удалось определить).
func judgeContainers(cs []ctr, units []string, restartSvc string, now time.Time) (status, value string, num float64, detail string) {
	var loops, warns []string
	running := 0
	needRestartSvc := false
	for _, c := range cs {
		label := ctrLabel(c)
		switch {
		case c.Status == "running":
			running++
			if c.Restart >= 5 && !c.Started.IsZero() && now.Sub(c.Started) < 10*time.Minute {
				loops = append(loops, fmt.Sprintf("%s: restarts=%d", label, c.Restart))
			} else if c.Health == "unhealthy" {
				warns = append(warns, label+": unhealthy")
			}
		case c.Status == "restarting":
			loops = append(loops, label+": restarting")
		case wantsRestart(c.Policy) && (c.Exit != 0 || c.Status == "created"):
			if c.Status == "created" {
				warns = append(warns, fmt.Sprintf("%s: not started (restart=%s)", label, c.Policy))
			} else {
				warns = append(warns, fmt.Sprintf("%s: exited(%d) restart=%s", label, c.Exit, c.Policy))
			}
		}
		if c.Policy == "always" && (c.Owner == "" || c.Owner == "root") {
			needRestartSvc = true
		}
	}
	for _, u := range units {
		warns = append(warns, "unit "+u+" failed")
	}
	if needRestartSvc && restartSvc == "disabled" {
		warns = append(warns, "podman-restart.service disabled")
	}
	sort.Strings(loops)
	summary := fmt.Sprintf("%d/%d", running, len(cs))
	switch {
	case len(loops) > 0:
		return "fail", "ctr_loop", float64(len(loops) + len(warns)), summary + "; " + ctrList(append(loops, warns...), 6)
	case len(warns) > 0:
		return "warn", "ctr_warn", float64(len(warns)), summary + "; " + ctrList(warns, 6)
	}
	return "ok", "ctr_ok", float64(running), summary
}

func ctrList(names []string, n int) string {
	if len(names) > n {
		return strings.Join(names[:n], ", ") + " …"
	}
	return strings.Join(names, ", ")
}

func sameEnv(a, b ctr) bool { return a.Runtime == b.Runtime && a.Owner == b.Owner }

func envLabel(c ctr) string {
	l := c.Runtime
	if c.Owner != "" && c.Owner != "root" {
		l += "@" + c.Owner
	}
	return l
}

func ctrLabel(c ctr) string {
	l := c.Name
	if c.Owner != "" && c.Owner != "root" {
		l += "@" + c.Owner
	}
	if c.Runtime == "docker" {
		l += "@docker"
	}
	return l
}

// judgeConflicts ищет контейнеры, которые мешают друг другу:
//   - одно имя в разных средах (Podman root, Podman пользователя, Docker): обычно остаток старого запуска;
//   - один порт хоста у нескольких контейнеров, из которых хотя бы один остановлен, но должен подниматься сам
//     (restart=always|unless-stopped): после перезагрузки они займутся гонкой за порт.
func judgeConflicts(cs []ctr) (status, value string, num float64, detail string) {
	var parts []string
	byName := map[string][]ctr{}
	var names []string
	for _, c := range cs {
		if _, ok := byName[c.Name]; !ok {
			names = append(names, c.Name)
		}
		byName[c.Name] = append(byName[c.Name], c)
	}
	sort.Strings(names)
	n := 0
	for _, nm := range names {
		g := byName[nm]
		envs := map[string]bool{}
		var ls []string
		for _, c := range g {
			if !envs[envLabel(c)] {
				ls = append(ls, envLabel(c))
			}
			envs[envLabel(c)] = true
		}
		if len(envs) > 1 {
			parts = append(parts, "name "+nm+" ("+strings.Join(ls, "+")+")")
			n++
		}
	}
	type pk struct{ proto, port string }
	byPort := map[pk][]ctr{}
	var keys []pk
	for _, c := range cs {
		seen := map[pk]bool{}
		for _, b := range c.Binds {
			k := pk{b.Proto, b.Host}
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, ok := byPort[k]; !ok {
				keys = append(keys, k)
			}
			byPort[k] = append(byPort[k], c)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].port < keys[j].port
	})
	for _, k := range keys {
		g := byPort[k]
		if len(g) < 2 {
			continue
		}
		flag := false
		for _, c := range g {
			if wantsRestart(c.Policy) && c.Status != "running" {
				flag = true
			}
		}
		if !flag {
			continue
		}
		var ls []string
		for _, c := range g {
			ls = append(ls, ctrLabel(c))
		}
		parts = append(parts, "port "+k.port+"/"+k.proto+" ("+strings.Join(ls, "+")+")")
		n++
	}
	if n == 0 {
		return "", "", 0, ""
	}
	return "warn", "ctr_conflict", float64(n), ctrList(parts, 6)
}

// lastContainers: список контейнеров последнего сбора; collect() забирает его в отчёт (под collectMu).
var lastContainers []CtrInfo

func takeContainers() []CtrInfo {
	c := lastContainers
	lastContainers = nil
	return c
}

// normID приводит идентификатор к виду «64 hex без префикса»: docker пишет sha256:..., podman без префикса.
func normID(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
}

func shortID(s string) string {
	s = normID(s)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
