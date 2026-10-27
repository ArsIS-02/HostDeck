//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Проверка контейнеров Podman и Docker: от имени root и от имени обычных пользователей (rootless Podman).
// Если ни Podman, ни Docker на хосте нет, проверка не добавляется.
func linuxContainers(add func(Check)) {
	lastContainers = nil
	podman, docker := find("podman"), find("docker")
	if podman == "" && docker == "" {
		return
	}
	var all []ctr
	collect := func(owner, runtime string, argv ...string) {
		out, code := runCode(20*time.Second, argv[0], append(append([]string{}, argv[1:]...), "ps", "-aq")...)
		if code != 0 {
			return
		}
		ids := parseIDs(out)
		if len(ids) == 0 {
			return
		}
		js, code := runCode(30*time.Second, argv[0], append(append([]string{}, argv[1:]...), append([]string{"inspect"}, ids...)...)...)
		if code != 0 {
			return
		}
		if cs, err := parseInspect(js, owner); err == nil {
			for i := range cs {
				cs[i].Runtime = runtime
			}
			all = append(all, cs...)
		}
	}
	if podman != "" {
		collect("root", "podman", podman)
	}
	if docker != "" {
		collect("root", "docker", docker)
	}
	var units []string
	if podman != "" {
		units = rootlessContainers(podman, collect)
	}
	all = dedupCtr(all)
	lastContainers = ctrInfos(all)
	if len(all) == 0 && len(units) == 0 {
		// runtime есть, контейнеров нет: это не повод для замечаний
		return
	}
	restartSvc := ""
	if podman != "" {
		if sc := find("systemctl"); sc != "" {
			if out, _ := runCode(10*time.Second, sc, "is-enabled", "podman-restart.service"); strings.HasPrefix(strings.TrimSpace(out), "enabled") {
				restartSvc = "enabled"
			} else if strings.HasPrefix(strings.TrimSpace(out), "disabled") {
				restartSvc = "disabled"
			}
		}
	}
	st, v, n, d := judgeContainers(all, units, restartSvc, time.Now())
	add(Check{ID: "containers", Status: st, Value: v, Num: n, Detail: d})
	if cst, cv, cn, cd := judgeConflicts(all); cst != "" {
		add(Check{ID: "container_conflicts", Status: cst, Value: cv, Num: cn, Detail: cd})
	}
}

// rootlessContainers собирает контейнеры обычных пользователей, у которых есть сеанс systemd (/run/user/UID), и их сбойные
// пользовательские службы. Команды выполняются от имени пользователя через runuser: корень не видит чужое хранилище rootless Podman.
func rootlessContainers(podman string, collect func(owner, runtime string, argv ...string)) (failed []string) {
	ru := find("runuser")
	if ru == "" {
		return nil
	}
	pw, ok := readFile("/etc/passwd")
	if !ok {
		return nil
	}
	for _, line := range strings.Split(pw, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < 1000 || uid >= 60000 || strings.HasSuffix(f[6], "nologin") || strings.HasSuffix(f[6], "/false") {
			continue
		}
		rt := fmt.Sprintf("/run/user/%d", uid)
		if _, err := os.Stat(rt); err != nil {
			continue // у пользователя нет запущенного сеанса: его контейнеры сейчас не работают
		}
		env := []string{"env", "XDG_RUNTIME_DIR=" + rt, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus"}
		collect(f[0], "podman", append(append([]string{ru, "-u", f[0], "--"}, env...), podman)...)
		if sc := find("systemctl"); sc != "" {
			out, code := runCode(10*time.Second, ru, append(append([]string{"-u", f[0], "--"}, env...), sc, "--user", "--failed", "--plain", "--no-legend")...)
			if code == 0 {
				for _, u := range parseFailedUnits(out) {
					failed = append(failed, u+"@"+f[0])
				}
			}
		}
	}
	return failed
}
