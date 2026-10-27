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
	} `json:"HostConfig"`
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
		label := c.Name
		if c.Owner != "" && c.Owner != "root" {
			label += "@" + c.Owner
		}
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
