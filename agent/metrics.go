package main

import "runtime"

// Metrics — быстрые показатели для приборов; собираются раз в минуту и отдельно от проверок.
type Metrics struct {
	At          int64   `json:"at"`
	CPU         float64 `json:"cpu"`          // загрузка процессора, %
	Load1       float64 `json:"load1"`        // load average за 1 мин
	Cores       int     `json:"cores"`        // логических ядер
	MemUsed     float64 `json:"mem_used"`     // байт
	MemTotal    float64 `json:"mem_total"`    // байт
	SwapPct     float64 `json:"swap_pct"`     // %
	DiskPct     float64 `json:"disk_pct"`     // %
	DiskTotal   float64 `json:"disk_total"`   // байт
	DiskFree    float64 `json:"disk_free"`    // байт
	Battery     float64 `json:"battery"`      // %, -1 если батареи нет
	BatteryChrg bool    `json:"battery_chrg"` // подключено питание
}

func collectMetrics() Metrics {
	m := Metrics{At: nowUnix(), Cores: runtime.NumCPU(), Battery: -1}
	if t, f, ok := diskUsage("/"); ok && t > 0 {
		m.DiskTotal, m.DiskFree, m.DiskPct = t, f, (t-f)/t*100
	}
	platformMetrics(&m)
	return m
}
