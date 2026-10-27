package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// Живой режим приборов: пока веб-интерфейс держит карточку хоста открытой, он каждые полминуты просит агента
// присылать метрики чаще (live). Режим сам выключается через liveMax после последнего запроса.
const (
	liveEvery = 4 * time.Second
	liveMax   = 90 * time.Second
)

var (
	liveMu      sync.Mutex
	liveUntil   time.Time
	liveRunning bool
)

// extendLive продлевает живой режим на sec секунд (не больше liveMax) и сообщает, нужно ли запускать цикл.
func extendLive(now time.Time, sec int) (start bool) {
	d := time.Duration(sec) * time.Second
	if d <= 0 || d > liveMax {
		d = liveMax
	}
	liveMu.Lock()
	defer liveMu.Unlock()
	if t := now.Add(d); t.After(liveUntil) {
		liveUntil = t
	}
	if liveRunning {
		return false
	}
	liveRunning = true
	return true
}

func liveActive(now time.Time) bool {
	liveMu.Lock()
	defer liveMu.Unlock()
	if now.Before(liveUntil) {
		return true
	}
	liveRunning = false
	return false
}

// liveLoop шлёт метрики каждые liveEvery, пока режим продлевается.
func liveLoop(ctx context.Context, report func(context.Context, Metrics) error) {
	t := time.NewTicker(liveEvery)
	defer t.Stop()
	for {
		if err := report(ctx, collectMetrics()); err != nil && ctx.Err() == nil {
			log.Printf("живые метрики: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !liveActive(time.Now()) {
			return
		}
	}
}
