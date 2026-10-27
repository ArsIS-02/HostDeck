package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Управление контейнерами и образами. Здесь разбор, проверка аргументов и типы результатов (без обращения к системе),
// сами действия в ctrmgmt.go.

var hexID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
var userName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// OpArgs: аргументы команды. Всё, что приходит от сервера, проверяется заново: агент работает от root.
type OpArgs struct {
	Action    string   `json:"action"`  // start, stop, restart, rm, img_rm
	Runtime   string   `json:"runtime"` // podman или docker
	Owner     string   `json:"owner"`   // пусто или root для системных, иначе имя пользователя rootless Podman
	ID        string   `json:"id"`      // идентификатор контейнера (hex)
	Name      string   `json:"name"`    // имя контейнера, как его видел интерфейс (защита от устаревшего списка)
	StopFirst bool     `json:"stop_first,omitempty"`
	Images    []string `json:"images,omitempty"`
}

// Коды результата. Интерфейс переводит их на язык пользователя, detail остаётся как есть (сообщение утилиты).
const (
	resOK        = "ok"
	resAlready   = "already"  // нечего делать: уже в нужном состоянии
	resDisabled  = "disabled" // управление выключено на хосте
	resBad       = "bad_request"
	resNotFound  = "not_found" // контейнера или образа больше нет (список устарел)
	resManaged   = "managed"   // контейнер принадлежит юниту systemd: удалять нельзя
	resRunning   = "running"   // удаление работающего без stop_first
	resInUse     = "in_use"    // образ используется контейнером
	resFailed    = "failed"
	resCrashed   = "crashed" // контейнер запустился и тут же остановился
	resPartial   = "partial"
	resUnsupport = "unsupported"
)

type OpItem struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

type OpResult struct {
	Op     string   `json:"op"`
	OK     bool     `json:"ok"`
	Code   string   `json:"code"`
	Detail string   `json:"detail,omitempty"`
	State  string   `json:"state,omitempty"`
	Items  []OpItem `json:"items,omitempty"`
	Freed  int64    `json:"freed,omitempty"`
}

func (a OpArgs) env() (runtime, owner string) {
	o := a.Owner
	if o == "root" {
		o = ""
	}
	return a.Runtime, o
}

// validateOp возвращает "" или текст ошибки.
func validateOp(a OpArgs) string {
	if a.Runtime != "podman" && a.Runtime != "docker" {
		return "неизвестная среда"
	}
	if a.Owner != "" && a.Owner != "root" {
		if a.Runtime != "podman" || !userName.MatchString(a.Owner) {
			return "неверный владелец"
		}
	}
	switch a.Action {
	case "start", "stop", "restart", "rm":
		if !hexID.MatchString(a.ID) {
			return "неверный идентификатор контейнера"
		}
		if a.StopFirst && a.Action != "rm" {
			return "stop_first только для удаления"
		}
	case "img_rm":
		if len(a.Images) == 0 || len(a.Images) > 50 {
			return "нужно от 1 до 50 образов"
		}
		for _, id := range a.Images {
			if !hexID.MatchString(id) {
				return "неверный идентификатор образа"
			}
		}
	default:
		return "неизвестное действие"
	}
	return ""
}

// ImgInfo: образ в списке образов хоста.
type ImgInfo struct {
	Runtime string   `json:"runtime"`
	Owner   string   `json:"owner,omitempty"`
	ID      string   `json:"id"` // первые 12 символов
	FullID  string   `json:"full_id"`
	Names   []string `json:"names,omitempty"`
	Size    int64    `json:"size"`
	Created int64    `json:"created,omitempty"`
	UsedBy  []string `json:"used_by,omitempty"`
}

type imgDoc struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
	Size     int64    `json:"Size"`
	Created  string   `json:"Created"`
}

// parseImages разбирает вывод `image inspect` (JSON-массив) обоих рантаймов.
func parseImages(js, runtime, owner string) ([]ImgInfo, error) {
	js = strings.TrimSpace(js)
	if js == "" || js == "[]" {
		return nil, nil
	}
	var docs []imgDoc
	if err := json.Unmarshal([]byte(js), &docs); err != nil {
		return nil, err
	}
	var out []ImgInfo
	for _, d := range docs {
		full := normID(d.ID)
		if full == "" {
			continue
		}
		im := ImgInfo{Runtime: runtime, Owner: ownerLabel(owner), ID: shortID(full), FullID: full, Size: d.Size}
		for _, n := range d.RepoTags {
			if n != "" && !strings.HasPrefix(n, "<none>") {
				im.Names = append(im.Names, n)
			}
		}
		sort.Strings(im.Names)
		if t, err := time.Parse(time.RFC3339Nano, d.Created); err == nil && t.Year() > 1990 {
			im.Created = t.Unix()
		}
		out = append(out, im)
	}
	return out, nil
}

func ownerLabel(o string) string {
	if o == "root" {
		return ""
	}
	return o
}

// markUsed заполняет UsedBy: имена контейнеров (в том числе остановленных), которые ссылаются на образ.
func markUsed(imgs []ImgInfo, cs []ctr) {
	for i := range imgs {
		for _, c := range cs {
			if c.ImageID != "" && c.ImageID == imgs[i].FullID {
				imgs[i].UsedBy = append(imgs[i].UsedBy, c.Name)
			}
		}
		sort.Strings(imgs[i].UsedBy)
	}
}

// parseIDLines разбирает вывод `images -aq --no-trunc`: по строке на тег, повторы убираются.
func parseIDLines(out string) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range strings.Fields(out) {
		id := normID(f)
		if hexID.MatchString(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

func trimDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func okRes(code, state string) OpResult { return OpResult{OK: true, Code: code, State: state} }

func failRes(code, detail string) OpResult {
	return OpResult{OK: false, Code: code, Detail: trimDetail(detail)}
}

func (r OpResult) String() string {
	return fmt.Sprintf("%s ok=%v %s %s", r.Code, r.OK, r.State, r.Detail)
}
