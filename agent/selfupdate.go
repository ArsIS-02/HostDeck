package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// allowUpdate разрешает серверу обновлять этого агента по команде из веб-интерфейса. По умолчанию выключено:
// обновление заменяет программу, работающую от root, поэтому включается явно (флаг -autoupdate при установке).
var allowUpdate bool

var updMuAgent sync.Mutex

func (c *Client) get(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &httpError{resp.StatusCode, strings.TrimSpace(string(b))}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("файл больше допустимого размера")
	}
	return b, nil
}

// sumFor ищет в тексте SHA256SUMS хеш файла.
func sumFor(sums, file string) string {
	for _, ln := range strings.Split(sums, "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[1] == file {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// selfUpdate скачивает агента с сервера, сверяет контрольную сумму, проверяет, что файл запускается, и подменяет им текущий.
// Возвращает новую версию и признак «заменён» (false — уже последняя). Процесс после замены нужно перезапустить.
func selfUpdate(ctx context.Context, c *Client) (string, bool, error) {
	updMuAgent.Lock()
	defer updMuAgent.Unlock()
	file := "hostdeck-agent-" + runtime.GOOS + "-" + runtime.GOARCH
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	sums, err := c.get(ctx, "/dl/SHA256SUMS", 64<<10)
	if err != nil {
		return "", false, fmt.Errorf("список контрольных сумм: %w", err)
	}
	want := sumFor(string(sums), file)
	if want == "" {
		return "", false, fmt.Errorf("в SHA256SUMS нет %s", file)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", false, err
	}
	// если на диске уже лежит нужный файл, скачивать нечего
	if cur, err := os.ReadFile(exe); err == nil {
		h := sha256.Sum256(cur)
		if hex.EncodeToString(h[:]) == want {
			return version, false, nil
		}
	}
	bin, err := c.get(ctx, "/dl/"+file, 64<<20)
	if err != nil {
		return "", false, fmt.Errorf("скачивание: %w", err)
	}
	h := sha256.Sum256(bin)
	if got := hex.EncodeToString(h[:]); got != want {
		return "", false, fmt.Errorf("контрольная сумма не совпала (ожидалась %s, получена %s)", want[:12], got[:12])
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", false, err
	}
	defer os.Remove(tmp)
	// новый файл должен запуститься и назвать версию, иначе замена оставила бы хост без агента
	vctx, vcancel := context.WithTimeout(ctx, 15*time.Second)
	defer vcancel()
	out, err := exec.CommandContext(vctx, tmp, "version").Output()
	nv := strings.TrimSpace(string(out))
	if err != nil || nv == "" || strings.ContainsAny(nv, " \n") {
		return "", false, fmt.Errorf("новый файл не запускается: %v", err)
	}
	if nv == version {
		return nv, false, nil
	}
	prev := exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Link(exe, prev); err != nil { // копия прежней версии на случай отката руками
		log.Printf("копия прежней версии не сохранена: %v", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", false, err
	}
	return nv, true, nil
}

// handleUpdate выполняется по команде сервера. После успешной замены процесс завершается: systemd и launchd запустят новую версию.
func handleUpdate(ctx context.Context, c *Client) {
	if !allowUpdate {
		msg := "обновление из веб-интерфейса не разрешено на этом хосте (allow_update выключен)"
		log.Print(msg)
		_ = c.reportEvent(ctx, "update-failed", msg)
		return
	}
	log.Printf("получена команда обновления, текущая версия %s", version)
	nv, changed, err := selfUpdate(ctx, c)
	if err != nil {
		log.Printf("обновление не удалось: %v", err)
		_ = c.reportEvent(ctx, "update-failed", err.Error())
		return
	}
	if !changed {
		log.Printf("уже последняя версия (%s)", nv)
		_ = c.reportEvent(ctx, "update-current", nv)
		return
	}
	log.Printf("установлена версия %s, перезапуск", nv)
	closeAllTerms()
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}
