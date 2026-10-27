//go:build linux

package main

import (
	"strings"
	"sync"
	"time"
)

// Управление контейнерами и образами из веб-интерфейса (только если на хосте включено `-containers`).
//
// Правила, ради которых всё устроено так:
//   - аргументы от сервера проверяются заново (validateOp), команды выполняются без оболочки;
//   - контейнер находится по идентификатору заново перед действием, имя должно совпасть с тем, что видел интерфейс;
//   - после действия проверяется итоговое состояние, а не код возврата;
//   - контейнеры под юнитом systemd (Quadlet) запускаются и останавливаются через systemctl: иначе systemd поднимет их обратно;
//   - удаление без -f и без -v: работающий контейнер сначала останавливается явно, тома остаются;
//   - образ удаляется только если на него не ссылается ни один контейнер; общий «prune» не используется, удаляется ровно тот список, который подтвердил человек.

var (
	ctrExec  = func(t time.Duration, argv ...string) (string, int) { return runCode(t, argv[0], argv[1:]...) }
	ctrFind  = find
	ctrUsers = rootlessUsers
	ctrSleep = time.Sleep
	opMu     sync.Mutex // одна операция за раз
)

// ctrEnvPrefix возвращает начало командной строки для среды: путь к утилите (для rootless через runuser от имени пользователя).
func ctrEnvPrefix(runtime, owner string) ([]string, bool) {
	bin := ctrFind(runtime)
	if bin == "" {
		return nil, false
	}
	if owner == "" {
		return []string{bin}, true
	}
	ru := ctrFind("runuser")
	if ru == "" || runtime != "podman" {
		return nil, false
	}
	for _, u := range ctrUsers() {
		if u.Name == owner {
			return append(append([]string{ru, "-u", u.Name, "--"}, userEnv(u)...), bin), true
		}
	}
	return nil, false
}

// ctrSystemctl: systemctl для юнита среды (для пользователя — --user).
func ctrSystemctl(owner string) ([]string, bool) {
	sc := ctrFind("systemctl")
	if sc == "" {
		return nil, false
	}
	if owner == "" {
		return []string{sc}, true
	}
	ru := ctrFind("runuser")
	if ru == "" {
		return nil, false
	}
	for _, u := range ctrUsers() {
		if u.Name == owner {
			return append(append([]string{ru, "-u", u.Name, "--"}, userEnv(u)...), sc, "--user"), true
		}
	}
	return nil, false
}

func cmdArgv(prefix []string, args ...string) []string {
	return append(append([]string{}, prefix...), args...)
}

// inspectCtr: контейнер по имени или идентификатору; nil, если его нет.
func inspectCtr(prefix []string, ref string) *ctr {
	out, code := ctrExec(20*time.Second, cmdArgv(prefix, "inspect", ref)...)
	if code != 0 {
		return nil
	}
	cs, err := parseInspect(out, "")
	if err != nil || len(cs) == 0 {
		return nil
	}
	return &cs[0]
}

func isLive(st string) bool { return st == "running" || st == "restarting" || st == "paused" }

// waitRunning ждёт запуска и убеждается, что контейнер не падает сразу.
func waitRunning(prefix []string, name string, before time.Time, needNewStart bool) OpResult {
	deadline := 20
	var last *ctr
	for i := 0; i < deadline; i++ {
		last = inspectCtr(prefix, name)
		if last != nil && last.Status == "running" && (!needNewStart || last.Started.After(before)) {
			break
		}
		if last != nil && (last.Status == "exited" || last.Status == "dead") && i >= 2 {
			return OpResult{OK: false, Code: resCrashed, State: last.Status, Detail: "код выхода " + itoa(last.Exit)}
		}
		ctrSleep(time.Second)
		last = nil
	}
	if last == nil {
		return OpResult{OK: false, Code: resFailed, Detail: "контейнер не перешёл в состояние «работает» за 20 секунд"}
	}
	// устойчивость: через несколько секунд контейнер всё ещё работает
	ctrSleep(3 * time.Second)
	again := inspectCtr(prefix, name)
	if again == nil || again.Status != "running" {
		st, ex := "gone", 0
		if again != nil {
			st, ex = again.Status, again.Exit
		}
		return OpResult{OK: false, Code: resCrashed, State: st, Detail: "контейнер запустился и остановился, код выхода " + itoa(ex)}
	}
	return okRes(resOK, "running")
}

func waitStopped(prefix []string, name string) OpResult {
	for i := 0; i < 30; i++ {
		c := inspectCtr(prefix, name)
		if c == nil {
			return okRes(resOK, "gone") // контейнер с --rm исчез сам
		}
		if !isLive(c.Status) {
			return okRes(resOK, c.Status)
		}
		ctrSleep(time.Second)
	}
	return failRes(resFailed, "контейнер не остановился за 30 секунд")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// runCtrAction выполняет start, stop, restart или rm одного контейнера.
func runCtrAction(a OpArgs) OpResult {
	rt, owner := a.env()
	prefix, ok := ctrEnvPrefix(rt, owner)
	if !ok {
		return failRes(resNotFound, "среда недоступна: "+rt+" "+owner)
	}
	cur := inspectCtr(prefix, a.ID)
	if cur == nil || (a.Name != "" && cur.Name != a.Name) {
		return failRes(resNotFound, "контейнер не найден: обновите список")
	}
	name := cur.Name
	unit := ""
	if rt == "podman" {
		unit = cur.Unit
	}
	var sc []string
	if unit != "" {
		if sc, ok = ctrSystemctl(owner); !ok {
			return failRes(resFailed, "не найден systemctl для юнита "+unit)
		}
	}
	run := func(args ...string) (string, int) { return ctrExec(60*time.Second, cmdArgv(prefix, args...)...) }
	runUnit := func(act string) (string, int) { return ctrExec(60*time.Second, cmdArgv(sc, act, unit)...) }

	switch a.Action {
	case "start":
		if cur.Status == "running" {
			return okRes(resAlready, cur.Status)
		}
		before := time.Now().Add(-time.Second)
		var out string
		var code int
		if unit != "" {
			out, code = runUnit("start")
		} else {
			out, code = run("start", cur.ID)
		}
		if code != 0 {
			return failRes(resFailed, out)
		}
		return waitRunning(prefix, name, before, false).withDetail(before)
	case "restart":
		before := time.Now().Add(-time.Second)
		var out string
		var code int
		if unit != "" {
			out, code = runUnit("restart")
		} else {
			out, code = run("restart", "-t", "10", cur.ID)
		}
		if code != 0 {
			return failRes(resFailed, out)
		}
		return waitRunning(prefix, name, before, true)
	case "stop":
		if !isLive(cur.Status) {
			return okRes(resAlready, cur.Status)
		}
		var out string
		var code int
		if unit != "" {
			out, code = runUnit("stop")
		} else {
			out, code = run("stop", "-t", "10", cur.ID)
		}
		if code != 0 {
			return failRes(resFailed, out)
		}
		return waitStopped(prefix, name)
	case "rm":
		if unit != "" {
			return failRes(resManaged, "контейнер запускает юнит "+unit+": удалите его описание (Quadlet) или остановите юнит")
		}
		if isLive(cur.Status) {
			if !a.StopFirst {
				return failRes(resRunning, "контейнер работает: сначала остановите его")
			}
			if out, code := run("stop", "-t", "10", cur.ID); code != 0 {
				return failRes(resFailed, out)
			}
			if r := waitStopped(prefix, name); !r.OK {
				return r
			}
		}
		// без -f и без -v: тома остаются
		if out, code := run("rm", cur.ID); code != 0 {
			if inspectCtr(prefix, name) == nil {
				return okRes(resAlready, "gone")
			}
			return failRes(resFailed, out)
		}
		if inspectCtr(prefix, name) != nil {
			return failRes(resFailed, "контейнер остался после удаления")
		}
		return okRes(resOK, "gone")
	}
	return failRes(resBad, "неизвестное действие")
}

func (r OpResult) withDetail(time.Time) OpResult { return r }

// envCtrs: все контейнеры среды (для привязки образов).
func envCtrs(prefix []string) []ctr {
	out, code := ctrExec(20*time.Second, cmdArgv(prefix, "ps", "-aq")...)
	if code != 0 {
		return nil
	}
	ids := parseIDs(out)
	if len(ids) == 0 {
		return nil
	}
	js, code := ctrExec(30*time.Second, cmdArgv(prefix, append([]string{"inspect"}, ids...)...)...)
	if code != 0 {
		return nil
	}
	cs, _ := parseInspect(js, "")
	return cs
}

func envImages(prefix []string, runtime, owner string, cs []ctr) []ImgInfo {
	out, code := ctrExec(30*time.Second, cmdArgv(prefix, "images", "-aq", "--no-trunc")...)
	if code != 0 {
		return nil
	}
	ids := parseIDLines(out)
	if len(ids) == 0 {
		return nil
	}
	js, code := ctrExec(40*time.Second, cmdArgv(prefix, append([]string{"image", "inspect"}, ids...)...)...)
	if code != 0 {
		return nil
	}
	imgs, err := parseImages(js, runtime, owner)
	if err != nil {
		return nil
	}
	markUsed(imgs, cs)
	return imgs
}

// ctrEnvList: все среды хоста, в которых есть утилита.
func ctrEnvList() (envs []struct {
	Runtime, Owner string
	Prefix         []string
}) {
	add := func(rt, owner string) {
		if p, ok := ctrEnvPrefix(rt, owner); ok {
			envs = append(envs, struct {
				Runtime, Owner string
				Prefix         []string
			}{rt, owner, p})
		}
	}
	add("podman", "")
	add("docker", "")
	if ctrFind("podman") != "" {
		for _, u := range ctrUsers() {
			add("podman", u.Name)
		}
	}
	return envs
}

// collectImages: образы всех сред хоста.
func collectImages() []ImgInfo {
	var all []ImgInfo
	seen := map[string]bool{}
	for _, e := range ctrEnvList() {
		for _, im := range envImages(e.Prefix, e.Runtime, e.Owner, envCtrs(e.Prefix)) {
			k := im.Runtime + "|" + im.Owner + "|" + im.FullID
			if !seen[k] { // docker-обёртка над Podman показывает те же образы
				seen[k] = true
				all = append(all, im)
			}
		}
	}
	if len(all) > 400 {
		all = all[:400]
	}
	return all
}

// removeImages удаляет подтверждённый список образов одной среды. Образ, на который ссылается контейнер, не трогается.
func removeImages(a OpArgs) OpResult {
	rt, owner := a.env()
	prefix, ok := ctrEnvPrefix(rt, owner)
	if !ok {
		return failRes(resNotFound, "среда недоступна: "+rt+" "+owner)
	}
	cs := envCtrs(prefix)
	res := OpResult{}
	okN := 0
	for _, id := range a.Images {
		it := OpItem{Target: shortID(id)}
		js, code := ctrExec(20*time.Second, cmdArgv(prefix, "image", "inspect", id)...)
		if code != 0 {
			it.OK, it.Code = true, resAlready // уже нет
			res.Items = append(res.Items, it)
			okN++
			continue
		}
		imgs, _ := parseImages(js, rt, owner)
		if len(imgs) == 0 {
			it.Code, it.Detail = resFailed, "не удалось разобрать сведения об образе"
			res.Items = append(res.Items, it)
			continue
		}
		markUsed(imgs, cs)
		im := imgs[0]
		if len(im.UsedBy) > 0 {
			it.Code, it.Detail = resInUse, strings.Join(im.UsedBy, ", ")
			res.Items = append(res.Items, it)
			continue
		}
		if len(im.Names) > 0 {
			it.Target = im.Names[0]
		}
		// теги снимаются по одному (без -f): сам образ удаляется вместе с последним тегом
		var lastOut string
		var lastCode int
		for _, n := range im.Names {
			lastOut, lastCode = ctrExec(60*time.Second, cmdArgv(prefix, "rmi", n)...)
		}
		if _, still := ctrExec(20*time.Second, cmdArgv(prefix, "image", "inspect", im.FullID)...); still == 0 {
			lastOut, lastCode = ctrExec(60*time.Second, cmdArgv(prefix, "rmi", im.FullID)...)
		}
		if _, still := ctrExec(20*time.Second, cmdArgv(prefix, "image", "inspect", im.FullID)...); still == 0 {
			it.Code, it.Detail = resFailed, trimDetail(lastOut)
			if lastCode == 0 && it.Detail == "" {
				it.Detail = "образ остался после удаления"
			}
			res.Items = append(res.Items, it)
			continue
		}
		it.OK, it.Code = true, resOK
		res.Freed += im.Size
		res.Items = append(res.Items, it)
		okN++
	}
	switch {
	case okN == len(res.Items):
		res.OK, res.Code = true, resOK
	case okN == 0:
		res.Code = resFailed
	default:
		res.Code = resPartial
	}
	return res
}

// runOp выполняет команду управления и возвращает результат.
func runOp(a OpArgs) OpResult {
	if !allowContainers {
		return failRes(resDisabled, "управление контейнерами выключено на хосте: hostdeck-agent set -containers on")
	}
	if msg := validateOp(a); msg != "" {
		return failRes(resBad, msg)
	}
	opMu.Lock()
	defer opMu.Unlock()
	if a.Action == "img_rm" {
		return removeImages(a)
	}
	return runCtrAction(a)
}
