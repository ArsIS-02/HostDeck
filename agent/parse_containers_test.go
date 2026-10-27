package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Вывод podman inspect (сокращённый) для контейнера, упавшего после перезагрузки, и рабочего контейнера.
const inspectSample = `[
 {"Id":"d31aa6f674a1aaaa","Name":"portainer_agent","RestartCount":0,
  "State":{"Status":"exited","ExitCode":2,"StartedAt":"2026-10-27T00:24:30.12345+05:00"},
  "HostConfig":{"RestartPolicy":{"Name":"always"}}},
 {"Id":"3f2abe8d7625bbbb","Name":"netalertx","RestartCount":0,
  "State":{"Status":"running","ExitCode":0,"StartedAt":"2026-10-27T00:25:00Z","Health":{"Status":"healthy"}},
  "HostConfig":{"RestartPolicy":{"Name":"no"}}}
]`

func TestParseInspect(t *testing.T) {
	cs, err := parseInspect(inspectSample, "root")
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %d", err, len(cs))
	}
	if cs[0].Name != "portainer_agent" || cs[0].Status != "exited" || cs[0].Exit != 2 || cs[0].Policy != "always" || cs[0].Started.IsZero() {
		t.Errorf("%+v", cs[0])
	}
	if cs[1].Health != "healthy" || cs[1].Status != "running" {
		t.Errorf("%+v", cs[1])
	}
	// docker добавляет «/» к имени
	d, _ := parseInspect(`[{"Id":"x1x1x1","Name":"/web","State":{"Status":"running"}}]`, "root")
	if d[0].Name != "web" {
		t.Errorf("имя docker: %q", d[0].Name)
	}
	for _, in := range []string{"", "[]", "  \n"} {
		if cs, err := parseInspect(in, "root"); err != nil || len(cs) != 0 {
			t.Errorf("%q: %v %v", in, cs, err)
		}
	}
	if _, err := parseInspect("not json", "root"); err == nil {
		t.Error("ожидалась ошибка разбора")
	}
}

func TestParseIDsAndDedup(t *testing.T) {
	ids := parseIDs("d31aa6f674a1\n3f2abe8d7625\nWARN[0000] something: odd\n")
	if len(ids) != 2 {
		t.Errorf("%v", ids)
	}
	got := dedupCtr([]ctr{{ID: "a1", Name: "x"}, {ID: "a1", Name: "x"}, {ID: "b2", Name: "y"}, {Name: "z", Owner: "u"}, {Name: "z", Owner: "u"}})
	if len(got) != 3 {
		t.Errorf("%v", got)
	}
}

func TestJudgeContainers(t *testing.T) {
	now := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	run := func(name string) ctr {
		return ctr{ID: name, Name: name, Owner: "root", Status: "running", Policy: "no"}
	}

	// всё работает
	st, v, n, d := judgeContainers([]ctr{run("a"), run("b")}, nil, "enabled", now)
	if st != "ok" || v != "ctr_ok" || n != 2 || d != "2/2" {
		t.Errorf("ok: %s %s %v %q", st, v, n, d)
	}
	// остановленный с always и кодом 2 (случай portainer_agent) и выключенный podman-restart
	cs := []ctr{run("a"), {ID: "p", Name: "portainer_agent", Owner: "root", Status: "exited", Exit: 2, Policy: "always"}}
	st, v, n, d = judgeContainers(cs, nil, "disabled", now)
	if st != "warn" || v != "ctr_warn" || n != 2 || !strings.Contains(d, "portainer_agent: exited(2) restart=always") || !strings.Contains(d, "podman-restart.service disabled") {
		t.Errorf("warn: %s %s %v %q", st, v, n, d)
	}
	// остановленный вручную (код 0) контейнер замечанием не является
	st, _, _, _ = judgeContainers([]ctr{{ID: "q", Name: "q", Owner: "root", Status: "exited", Exit: 0, Policy: "always"}}, nil, "enabled", now)
	if st != "ok" {
		t.Errorf("остановленный с кодом 0: %s", st)
	}
	// контейнер без политики перезапуска, упавший с ошибкой: не замечание
	st, _, _, _ = judgeContainers([]ctr{{ID: "q", Name: "q", Owner: "root", Status: "exited", Exit: 1, Policy: "no"}}, nil, "enabled", now)
	if st != "ok" {
		t.Errorf("exited без политики: %s", st)
	}
	// не стартовал (created)
	st, _, _, d = judgeContainers([]ctr{{ID: "q", Name: "q", Owner: "root", Status: "created", Policy: "always"}}, nil, "enabled", now)
	if st != "warn" || !strings.Contains(d, "not started") {
		t.Errorf("created: %s %q", st, d)
	}
	// нездоровый
	u := run("u")
	u.Health = "unhealthy"
	st, _, _, d = judgeContainers([]ctr{u}, nil, "", now)
	if st != "warn" || !strings.Contains(d, "u: unhealthy") {
		t.Errorf("unhealthy: %s %q", st, d)
	}
	// цикл перезапусков
	loop := run("loop")
	loop.Restart = 7
	loop.Started = now.Add(-30 * time.Second)
	st, v, _, d = judgeContainers([]ctr{loop}, nil, "", now)
	if st != "fail" || v != "ctr_loop" || !strings.Contains(d, "loop: restarts=7") {
		t.Errorf("loop: %s %s %q", st, v, d)
	}
	// много перезапусков, но давно работает: это не цикл
	old := run("old")
	old.Restart = 9
	old.Started = now.Add(-48 * time.Hour)
	if st, _, _, _ = judgeContainers([]ctr{old}, nil, "", now); st != "ok" {
		t.Errorf("давно работает: %s", st)
	}
	// docker: состояние restarting
	st, _, _, _ = judgeContainers([]ctr{{ID: "r", Name: "r", Status: "restarting"}}, nil, "", now)
	if st != "fail" {
		t.Errorf("restarting: %s", st)
	}
	// сбойная пользовательская служба (случай лишнего netalertx)
	st, _, n, d = judgeContainers([]ctr{run("a")}, []string{"netalertx.service@user"}, "enabled", now)
	if st != "warn" || n != 1 || !strings.Contains(d, "unit netalertx.service@user failed") {
		t.Errorf("unit: %s %v %q", st, n, d)
	}
	// rootless-контейнер с always не требует podman-restart.service (его обслуживает systemd пользователя)
	st, _, _, _ = judgeContainers([]ctr{{ID: "z", Name: "z", Owner: "user", Status: "running", Policy: "always"}}, nil, "disabled", now)
	if st != "ok" {
		t.Errorf("rootless: %s", st)
	}
	// метка владельца у rootless-контейнера
	_, _, _, d = judgeContainers([]ctr{{ID: "z", Name: "z", Owner: "user", Status: "exited", Exit: 1, Policy: "always"}}, nil, "enabled", now)
	if !strings.Contains(d, "z@user: exited(1)") {
		t.Errorf("метка: %q", d)
	}
}

const inspectPorts = `[
 {"Id":"a1a1a1a1","Name":"/atrium","ImageName":"localhost/atrium:latest","RestartCount":0,
  "State":{"Status":"running","StartedAt":"2026-10-25T10:00:00Z"},
  "HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"","HostPort":"5000"}]}},
  "Config":{"Image":"ignored","Env":["SECRET=hunter2"],"Cmd":["run","--token","abc"]}},
 {"Id":"b2b2b2b2","Name":"myhomelab-v6-old","RestartCount":0,
  "State":{"Status":"exited","ExitCode":137},
  "HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"5000/tcp":[{"HostIp":"0.0.0.0","HostPort":"5000"}]}},
  "Config":{"Image":"myhomelab:v6"}}
]`

func TestInspectPortsAndInfo(t *testing.T) {
	cs, err := parseInspect(inspectPorts, "redos")
	if err != nil || len(cs) != 2 {
		t.Fatalf("%v %d", err, len(cs))
	}
	if cs[0].Image != "localhost/atrium:latest" || cs[1].Image != "myhomelab:v6" {
		t.Errorf("образы: %q %q", cs[0].Image, cs[1].Image)
	}
	if len(cs[0].Binds) != 1 || cs[0].Binds[0].String() != "0.0.0.0:5000->5000/tcp" {
		t.Errorf("порты: %+v", cs[0].Binds)
	}
	for i := range cs {
		cs[i].Runtime = "podman"
	}
	info := ctrInfos(cs)
	b := strings.ToLower(fmt.Sprintf("%+v", info))
	if strings.Contains(b, "hunter2") || strings.Contains(b, "token") {
		t.Errorf("в отчёт попали переменные или команда запуска: %s", b)
	}
	if len(info) != 2 || info[0].Name != "atrium" || info[0].Owner != "redos" || info[0].Started == 0 || info[1].Started != 0 {
		t.Errorf("%+v", info)
	}
}

func TestJudgeConflicts(t *testing.T) {
	cs, _ := parseInspect(inspectPorts, "redos")
	for i := range cs {
		cs[i].Runtime = "podman"
	}
	st, v, n, d := judgeConflicts(cs)
	// порт 5000: atrium работает, остановленный старый контейнер должен подниматься сам (restart=always)
	if st != "warn" || v != "ctr_conflict" || n != 1 || !strings.Contains(d, "port 5000/tcp") || !strings.Contains(d, "myhomelab-v6-old@redos") {
		t.Errorf("%s %s %v %q", st, v, n, d)
	}
	// остановленный без restart-политики порт не делит всерьёз
	cs[1].Policy = "no"
	if st, _, _, _ := judgeConflicts(cs); st != "" {
		t.Errorf("лишнее замечание: %q", st)
	}
	// то же имя в Docker и Podman
	a := []ctr{{Name: "logatlas", Runtime: "podman", Owner: "root"}, {Name: "logatlas", Runtime: "docker", Owner: "root"}, {Name: "web", Runtime: "podman", Owner: "root"}}
	st, _, n, d = judgeConflicts(a)
	if st != "warn" || n != 1 || d != "name logatlas (podman+docker)" {
		t.Errorf("%s %v %q", st, n, d)
	}
	// одно имя в одной среде (два rootless-пользователя с разными именами среды — это разные среды)
	if st, _, _, _ := judgeConflicts([]ctr{{Name: "web", Runtime: "podman", Owner: "root"}}); st != "" {
		t.Error("одиночный контейнер не конфликт")
	}
}
