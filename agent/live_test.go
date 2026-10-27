package main

import (
	"testing"
	"time"
)

func TestLiveWindow(t *testing.T) {
	liveUntil, liveRunning = time.Time{}, false
	now := time.Unix(1_000_000, 0)
	if !extendLive(now, 60) {
		t.Fatal("первый запрос должен запустить цикл")
	}
	if extendLive(now.Add(10*time.Second), 60) {
		t.Fatal("повторный запрос не запускает второй цикл")
	}
	if !liveActive(now.Add(30 * time.Second)) {
		t.Fatal("режим должен быть активен")
	}
	// запрос больше предела обрезается
	liveUntil, liveRunning = time.Time{}, false
	extendLive(now, 100000)
	if liveUntil.Sub(now) != liveMax {
		t.Fatalf("предел: %v", liveUntil.Sub(now))
	}
	// после окончания цикл останавливается и может быть запущен снова
	if liveActive(now.Add(liveMax + time.Second)) {
		t.Fatal("режим должен был закончиться")
	}
	if !extendLive(now.Add(liveMax+2*time.Second), 30) {
		t.Fatal("после остановки цикл запускается снова")
	}
}
