package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	Server      string `json:"server"`
	HostID      string `json:"host_id"`
	HostKey     string `json:"host_key"`
	Name        string `json:"name"`
	CAFile      string `json:"ca_file,omitempty"`
	IntervalMin int    `json:"interval_min,omitempty"`
	// AllowTerminal разрешает администратору открывать root-консоль из веб-интерфейса. По умолчанию выключено.
	AllowTerminal bool `json:"allow_terminal,omitempty"`
	// AllowUpdate разрешает серверу обновлять агента по команде из веб-интерфейса. По умолчанию выключено.
	AllowUpdate bool `json:"allow_update,omitempty"`
	// AllowedPorts — порты, которым разрешено слушать на внешних адресах. Всё остальное проверка «Открытые порты» считает лишним.
	AllowedPorts []int `json:"allowed_ports,omitempty"`
}

func defaultConfigPath() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/HostDeck/agent.json"
	}
	return "/etc/hostdeck/agent.json"
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Server == "" || c.HostID == "" || c.HostKey == "" {
		return nil, errors.New("конфиг неполный: выполните `hostdeck-agent enroll`")
	}
	if c.IntervalMin <= 0 {
		c.IntervalMin = 15
	}
	return &c, nil
}

func saveConfig(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	// ключ хоста — секрет: файл только для владельца (root)
	return os.WriteFile(path, b, 0o600)
}
