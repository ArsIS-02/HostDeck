package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.1.0"

// Posture — снимок состояния хоста, который уходит на сервер.
type Posture struct {
	CollectedAt int64             `json:"collected_at"`
	Info        map[string]string `json:"info"`
	Checks      []Check           `json:"checks"`
}

var collectMu sync.Mutex

// run выполняет команду с таймаутом и возвращает объединённый stdout+stderr.
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func collect() Posture {
	collectMu.Lock()
	defer collectMu.Unlock()
	p := Posture{CollectedAt: time.Now().Unix(), Info: map[string]string{}}
	p.Info["agent"] = version
	p.Info["arch"] = runtime.GOARCH
	platformCollect(&p)
	p.Checks = append(p.Checks, diskCheck("/"))
	return p
}

func diskCheck(path string) Check {
	c := Check{ID: "disk"}
	total, free, ok := diskUsage(path)
	if !ok || total == 0 {
		c.Status = "unknown"
		return c
	}
	used := (total - free) / total * 100
	c.Num = used
	c.Value = "used"
	c.Detail = fmt.Sprintf("%.1f", free/1e9)
	switch {
	case used >= 95:
		c.Status = "fail"
	case used >= 85:
		c.Status = "warn"
	default:
		c.Status = "ok"
	}
	return c
}

func diskUsage(path string) (total, free float64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return float64(st.Blocks) * float64(st.Bsize), float64(st.Bavail) * float64(st.Bsize), true
}

func trim(s string) string { return strings.TrimSpace(s) }

func fmtSscan(s string, v *float64) (int, error) { return fmt.Sscan(strings.Fields(s)[0], v) }
