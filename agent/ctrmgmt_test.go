//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Поддельный podman: хранит состояние контейнеров и образов и отвечает на те же команды, что использует агент.
type fakeCtr struct {
	ID, Name, Status, Image, Unit, Policy string
	Exit                                  int
	Started                               time.Time
	crashAfter                            int // сколько ещё проверок контейнер «работает», потом падает (0 — не падает)
	failStart                             bool
}
type fakeEnv struct {
	ctrs   map[string]*fakeCtr // по имени
	images map[string]*fakeImg // по полному ID
	log    [][]string
	clock  time.Time
}
type fakeImg struct {
	ID    string
	Names []string
	Size  int64
}

func hx(c byte) string { return strings.Repeat(string(c), 64) }

func newFake() *fakeEnv {
	f := &fakeEnv{ctrs: map[string]*fakeCtr{}, images: map[string]*fakeImg{}, clock: time.Unix(1_800_000_000, 0)}
	f.images[hx('a')] = &fakeImg{hx('a'), []string{"localhost/app:1", "localhost/app:latest"}, 1000}
	f.images[hx('b')] = &fakeImg{hx('b'), []string{"docker.io/library/caddy:2"}, 500}
	f.images[hx('c')] = &fakeImg{hx('c'), nil, 300} // висячий
	f.ctrs["web"] = &fakeCtr{ID: hx('1'), Name: "web", Status: "exited", Image: hx('b'), Policy: "always", Exit: 0}
	f.ctrs["live"] = &fakeCtr{ID: hx('2'), Name: "live", Status: "running", Image: hx('a'), Started: f.clock}
	f.ctrs["svc"] = &fakeCtr{ID: hx('3'), Name: "svc", Status: "running", Image: hx('a'), Unit: "svc.service", Started: f.clock}
	return f
}

func (f *fakeEnv) install(t *testing.T) {
	oldE, oldF, oldU, oldS, oldA := ctrExec, ctrFind, ctrUsers, ctrSleep, allowContainers
	t.Cleanup(func() { ctrExec, ctrFind, ctrUsers, ctrSleep, allowContainers = oldE, oldF, oldU, oldS, oldA })
	allowContainers = true
	ctrFind = func(n string) string { return "/fake/" + n }
	ctrUsers = func() []rootlessUser { return []rootlessUser{{"redos", "/run/user/1000"}} }
	ctrSleep = func(d time.Duration) { f.clock = f.clock.Add(d) }
	ctrExec = f.exec
}

func (f *fakeEnv) byRef(ref string) *fakeCtr {
	for _, c := range f.ctrs {
		if c.Name == ref || c.ID == ref || strings.HasPrefix(c.ID, ref) {
			return c
		}
	}
	return nil
}

func (f *fakeEnv) inspectDoc(c *fakeCtr) map[string]any {
	if c.crashAfter > 0 {
		c.crashAfter--
		if c.crashAfter == 0 {
			c.Status, c.Exit = "exited", 1
		}
	}
	d := map[string]any{"Id": c.ID, "Name": "/" + c.Name, "Image": c.Image,
		"State":      map[string]any{"Status": c.Status, "ExitCode": c.Exit, "StartedAt": c.Started.Format(time.RFC3339Nano)},
		"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": c.Policy}},
		"Config":     map[string]any{"Image": "img", "Labels": map[string]string{}}}
	if c.Unit != "" {
		d["Config"].(map[string]any)["Labels"] = map[string]string{"PODMAN_SYSTEMD_UNIT": c.Unit}
	}
	return d
}

func (f *fakeEnv) exec(_ time.Duration, argv ...string) (string, int) {
	f.log = append(f.log, argv)
	// найти утилиту в строке (после runuser … env … podman)
	i := 0
	for ; i < len(argv); i++ {
		if strings.HasSuffix(argv[i], "/podman") || strings.HasSuffix(argv[i], "/docker") || strings.HasSuffix(argv[i], "/systemctl") {
			break
		}
	}
	if i == len(argv) {
		return "no tool", 127
	}
	tool, args := argv[i], argv[i+1:]
	if strings.HasSuffix(tool, "/systemctl") {
		if args[0] == "--user" {
			args = args[1:]
		}
		c := f.byUnit(args[1])
		if c == nil {
			return "Unit not found", 5
		}
		switch args[0] {
		case "start":
			c.Status, c.Started = "running", f.clock
		case "stop":
			c.Status = "exited"
		case "restart":
			c.Status, c.Started = "running", f.clock
			c.ID = hx('9') // Quadlet пересоздаёт контейнер: новый ID
		}
		return "", 0
	}
	switch args[0] {
	case "inspect":
		var docs []any
		for _, ref := range args[1:] {
			c := f.byRef(ref)
			if c == nil {
				return "Error: no such object", 125
			}
			docs = append(docs, f.inspectDoc(c))
		}
		b, _ := json.Marshal(docs)
		return string(b), 0
	case "ps":
		var ids []string
		for _, c := range f.ctrs {
			ids = append(ids, c.ID[:12])
		}
		return strings.Join(ids, "\n"), 0
	case "start":
		c := f.byRef(args[1])
		if c == nil || c.failStart {
			return "Error: cannot start", 125
		}
		c.Status, c.Started = "running", f.clock
		return "", 0
	case "stop":
		c := f.byRef(args[len(args)-1])
		c.Status = "exited"
		return "", 0
	case "restart":
		c := f.byRef(args[len(args)-1])
		c.Status = "running"
		c.Started = f.clock.Add(time.Second)
		return "", 0
	case "rm":
		c := f.byRef(args[len(args)-1])
		if c == nil {
			return "no such container", 1
		}
		if c.Status == "running" {
			return "cannot remove a running container", 2
		}
		delete(f.ctrs, c.Name)
		return "", 0
	case "images":
		var ids []string
		for _, im := range f.images {
			if len(im.Names) == 0 {
				ids = append(ids, "sha256:"+im.ID)
			}
			for range im.Names {
				ids = append(ids, "sha256:"+im.ID)
			}
		}
		return strings.Join(ids, "\n"), 0
	case "image":
		var docs []map[string]any
		for _, ref := range args[2:] {
			im := f.imgByRef(ref)
			if im == nil {
				return "no such image", 125
			}
			docs = append(docs, map[string]any{"Id": "sha256:" + im.ID, "RepoTags": im.Names, "Size": im.Size, "Created": "2026-10-01T00:00:00Z"})
		}
		b, _ := json.Marshal(docs)
		return string(b), 0
	case "rmi":
		ref := args[len(args)-1]
		im := f.imgByRef(ref)
		if im == nil {
			return "no such image", 1
		}
		for _, c := range f.ctrs {
			if c.Image == im.ID {
				return "image is in use", 2
			}
		}
		if len(im.Names) > 1 && !strings.HasPrefix(ref, "sha") && !isHex(ref) {
			var rest []string
			for _, n := range im.Names {
				if n != ref {
					rest = append(rest, n)
				}
			}
			im.Names = rest
			return "Untagged", 0
		}
		if len(im.Names) > 1 {
			return "image has multiple tags", 2
		}
		delete(f.images, im.ID)
		return "Deleted", 0
	}
	return "unsupported " + args[0], 125
}

func isHex(s string) bool { return hexID.MatchString(s) }

func (f *fakeEnv) byUnit(u string) *fakeCtr {
	for _, c := range f.ctrs {
		if c.Unit == u {
			return c
		}
	}
	return nil
}

func (f *fakeEnv) imgByRef(ref string) *fakeImg {
	ref = strings.TrimPrefix(ref, "sha256:")
	for _, im := range f.images {
		if im.ID == ref || strings.HasPrefix(im.ID, ref) {
			return im
		}
		for _, n := range im.Names {
			if n == ref {
				return im
			}
		}
	}
	return nil
}

func (f *fakeEnv) ran(sub string) bool {
	for _, a := range f.log {
		if strings.Contains(strings.Join(a, " "), sub) {
			return true
		}
	}
	return false
}

func act(a, id, name string) OpArgs {
	return OpArgs{Action: a, Runtime: "podman", ID: id[:12], Name: name}
}

func TestCtrStartStopRestart(t *testing.T) {
	f := newFake()
	f.install(t)
	if r := runOp(act("start", hx('1'), "web")); !r.OK || r.Code != resOK || r.State != "running" {
		t.Fatalf("start: %v", r)
	}
	if r := runOp(act("start", hx('1'), "web")); !r.OK || r.Code != resAlready {
		t.Fatalf("повторный start должен быть no-op: %v", r)
	}
	if r := runOp(act("stop", hx('1'), "web")); !r.OK || r.Code != resOK {
		t.Fatalf("stop: %v", r)
	}
	if r := runOp(act("stop", hx('1'), "web")); !r.OK || r.Code != resAlready {
		t.Fatalf("повторный stop: %v", r)
	}
	f.ctrs["web"].Status = "running"
	f.ctrs["web"].Started = f.clock.Add(-time.Hour)
	if r := runOp(act("restart", hx('1'), "web")); !r.OK || r.State != "running" {
		t.Fatalf("restart: %v", r)
	}
}

func TestCtrStartCrashes(t *testing.T) {
	f := newFake()
	f.install(t)
	f.ctrs["web"].crashAfter = 3 // работает пару проверок, потом падает
	r := runOp(act("start", hx('1'), "web"))
	if r.OK || r.Code != resCrashed {
		t.Fatalf("упавший сразу после запуска контейнер не должен считаться успехом: %v", r)
	}
	f.ctrs["web"].crashAfter, f.ctrs["web"].failStart, f.ctrs["web"].Status = 0, true, "exited"
	if r := runOp(act("start", hx('1'), "web")); r.OK || r.Code != resFailed {
		t.Fatalf("ошибка запуска: %v", r)
	}
}

func TestCtrRemoveSafety(t *testing.T) {
	f := newFake()
	f.install(t)
	if r := runOp(act("rm", hx('2'), "live")); r.OK || r.Code != resRunning {
		t.Fatalf("работающий контейнер без stop_first: %v", r)
	}
	if f.ran(" rm ") {
		t.Fatal("rm не должен вызываться для работающего контейнера без stop_first")
	}
	a := act("rm", hx('2'), "live")
	a.StopFirst = true
	if r := runOp(a); !r.OK || f.byRef("live") != nil {
		t.Fatalf("остановка и удаление: %v", r)
	}
	if r := runOp(act("rm", hx('1'), "web")); !r.OK || f.byRef("web") != nil {
		t.Fatalf("удаление остановленного: %v", r)
	}
	for _, a := range f.log {
		j := " " + strings.Join(a, " ") + " "
		if strings.Contains(j, " -f ") || strings.Contains(j, " -v ") || strings.Contains(j, " --force ") || strings.Contains(j, " --volumes ") {
			t.Fatalf("опасные флаги в команде: %v", a)
		}
	}
	if r := runOp(act("rm", hx('1'), "web")); r.OK || r.Code != resNotFound {
		t.Fatalf("повторное удаление: контейнера уже нет: %v", r)
	}
}

func TestCtrSystemdManaged(t *testing.T) {
	f := newFake()
	f.install(t)
	f.ctrs["svc"].Status = "exited"
	if r := runOp(act("start", hx('3'), "svc")); !r.OK {
		t.Fatalf("start юнита: %v", r)
	}
	if !f.ran("/fake/systemctl start svc.service") || f.ran("/fake/podman start") {
		t.Fatalf("контейнер юнита должен запускаться через systemctl: %v", f.log)
	}
	if r := runOp(act("stop", hx('3'), "svc")); !r.OK {
		t.Fatalf("stop юнита: %v", r)
	}
	if !f.ran("/fake/systemctl stop svc.service") {
		t.Fatal("остановка должна идти через systemctl")
	}
	if r := runOp(act("rm", hx('3'), "svc")); r.OK || r.Code != resManaged {
		t.Fatalf("удалять контейнер юнита нельзя: %v", r)
	}
	if f.ran("podman rm") {
		t.Fatal("rm не должен быть выполнен")
	}
	// перезапуск юнита пересоздаёт контейнер с новым ID: итог проверяется по имени
	f.ctrs["svc"].Status = "running"
	if r := runOp(act("restart", f.ctrs["svc"].ID, "svc")); !r.OK {
		t.Fatalf("restart юнита: %v", r)
	}
}

func TestCtrStaleAndValidation(t *testing.T) {
	f := newFake()
	f.install(t)
	if r := runOp(act("start", hx('1'), "other-name")); r.OK || r.Code != resNotFound {
		t.Fatalf("имя не совпало с контейнером: %v", r)
	}
	for _, bad := range []OpArgs{
		{Action: "start", Runtime: "lxc", ID: hx('1')[:12]},
		{Action: "format", Runtime: "podman", ID: hx('1')[:12]},
		{Action: "start", Runtime: "podman", ID: "web"},
		{Action: "start", Runtime: "podman", ID: "--all"},
		{Action: "start", Runtime: "podman", ID: hx('1')[:12], Owner: "a b"},
		{Action: "start", Runtime: "docker", ID: hx('1')[:12], Owner: "redos"},
		{Action: "stop", Runtime: "podman", ID: hx('1')[:12], StopFirst: true},
		{Action: "img_rm", Runtime: "podman"},
		{Action: "img_rm", Runtime: "podman", Images: []string{"-a"}},
	} {
		if r := runOp(bad); r.OK || r.Code != resBad {
			t.Errorf("%+v должен быть отклонён: %v", bad, r)
		}
	}
	// неизвестный rootless-пользователь
	a := act("start", hx('1'), "web")
	a.Owner = "nobody1"
	if r := runOp(a); r.OK || r.Code != resNotFound {
		t.Errorf("среда неизвестного пользователя: %v", r)
	}
	// rootless-пользователь выполняется через runuser
	a.Owner = "redos"
	runOp(a)
	if !f.ran("/fake/runuser -u redos -- env XDG_RUNTIME_DIR=/run/user/1000") {
		t.Errorf("rootless-команда должна идти через runuser: %v", f.log[len(f.log)-1])
	}
	allowContainers = false
	if r := runOp(act("start", hx('1'), "web")); r.OK || r.Code != resDisabled {
		t.Errorf("при выключенном управлении команда не выполняется: %v", r)
	}
}

func TestImages(t *testing.T) {
	f := newFake()
	f.install(t)
	ctrFind = func(n string) string {
		if n == "docker" {
			return ""
		}
		return "/fake/" + n
	}
	ctrUsers = func() []rootlessUser { return nil }
	imgs := collectImages()
	if len(imgs) != 3 {
		t.Fatalf("образов должно быть 3, получено %d: %+v", len(imgs), imgs)
	}
	used := map[string][]string{}
	for _, im := range imgs {
		used[im.FullID] = im.UsedBy
	}
	if len(used[hx('a')]) != 2 || len(used[hx('b')]) != 1 || len(used[hx('c')]) != 0 {
		t.Errorf("использование образов: %+v", used)
	}
	// образ в использовании не удаляется, висячий и неиспользуемый удаляются
	r := runOp(OpArgs{Action: "img_rm", Runtime: "podman", Images: []string{hx('a')[:12], hx('c')[:12]}})
	if r.OK || r.Code != resPartial || len(r.Items) != 2 || r.Items[0].Code != resInUse || !r.Items[1].OK || r.Freed != 300 {
		b, _ := json.Marshal(r); t.Fatalf("частичный результат: %s", b)
	}
	if f.imgByRef(hx('a')) == nil || f.imgByRef(hx('c')) != nil {
		t.Fatal("образ в использовании должен остаться, висячий — исчезнуть")
	}
	// образ с двумя тегами без контейнеров: теги снимаются по очереди, без -f
	delete(f.ctrs, "live")
	delete(f.ctrs, "svc")
	r = runOp(OpArgs{Action: "img_rm", Runtime: "podman", Images: []string{hx('a')[:12]}})
	if !r.OK || r.Freed != 1000 || f.imgByRef(hx('a')) != nil {
		t.Fatalf("образ с несколькими тегами: %+v", r)
	}
	for _, a := range f.log {
		if strings.Contains(" "+strings.Join(a, " ")+" ", " -f ") {
			t.Fatalf("rmi с -f запрещён: %v", a)
		}
	}
	// повторное удаление уже удалённого образа — не ошибка
	if r := runOp(OpArgs{Action: "img_rm", Runtime: "podman", Images: []string{hx('c')[:12]}}); !r.OK || r.Items[0].Code != resAlready {
		t.Fatalf("повторное удаление: %+v", r)
	}
	_ = fmt.Sprint()
}
