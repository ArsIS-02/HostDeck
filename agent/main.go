package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, `hostdeck-agent %s

  hostdeck-agent enroll -server https://host -token hde_... [-name имя] [-ca ca.pem] [-terminal] [-autoupdate] [-config путь]
  hostdeck-agent set -autoupdate on|off [-config путь]   # разрешить или запретить обновление из веб-интерфейса
  hostdeck-agent run [-config путь]
  hostdeck-agent collect        # один раз собрать состояние и вывести JSON (для проверки)
  hostdeck-agent version
`, version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "collect":
		out := map[string]any{"posture": collect(), "metrics": collectMetrics()}
		if len(os.Args) > 2 && os.Args[2] == "-software" {
			out["software"] = collectSoftware()
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "set":
		cmdSet(os.Args[2:])
	default:
		usage()
	}
}

func osName() string {
	p := Posture{Info: map[string]string{}}
	platformCollect(&p)
	return p.Info["os"]
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "адрес сервера, https://...")
	token := fs.String("token", "", "одноразовый токен регистрации")
	name := fs.String("name", "", "имя хоста (по умолчанию hostname)")
	ca := fs.String("ca", "", "файл корневого сертификата (PEM), если сервер подписан своим CA")
	terminal := fs.Bool("terminal", false, "разрешить root-консоль из веб-интерфейса (по умолчанию выключено)")
	autoupd := fs.Bool("autoupdate", false, "разрешить обновление агента из веб-интерфейса (по умолчанию выключено)")
	cfgPath := fs.String("config", defaultConfigPath(), "путь к конфигу")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		usage()
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	c, err := newClient(*server, *ca, "", "")
	if err != nil {
		log.Fatal(err)
	}
	var r struct {
		HostID  string `json:"host_id"`
		HostKey string `json:"host_key"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.post(ctx, "/agent/enroll", map[string]string{"token": *token, "name": *name, "os": osName(), "version": version}, &r); err != nil {
		log.Fatalf("регистрация не удалась: %v", err)
	}
	cfg := &Config{Server: *server, HostID: r.HostID, HostKey: r.HostKey, Name: *name, CAFile: *ca, IntervalMin: 15, AllowTerminal: *terminal, AllowUpdate: *autoupd}
	if err := saveConfig(*cfgPath, cfg); err != nil {
		log.Fatalf("не удалось сохранить конфиг: %v", err)
	}
	fmt.Printf("Хост %q зарегистрирован. Конфиг: %s\n", *name, *cfgPath)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "путь к конфигу")
	_ = fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	c, err := newClient(cfg.Server, cfg.CAFile, cfg.HostID, cfg.HostKey)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os_ := osName()
	allowTerminal = cfg.AllowTerminal
	allowUpdate = cfg.AllowUpdate
	allowedPorts = cfg.AllowedPorts
	defer closeAllTerms()
	if allowTerminal {
		log.Printf("внимание: root-консоль из веб-интерфейса разрешена на этом хосте")
	}

	send := func() {
		p := collect()
		if err := c.reportPosture(ctx, p, os_); err != nil {
			log.Printf("отправка состояния: %v", err)
			return
		}
		log.Printf("состояние отправлено (%d проверок)", len(p.Checks))
	}
	sendSoftware := func() {
		items := collectSoftware()
		if err := c.reportSoftware(ctx, items); err != nil {
			log.Printf("отправка списка ПО: %v", err)
			return
		}
		log.Printf("список ПО отправлен (%d)", len(items))
	}
	go func() { // метрики для приборов — раз в минуту
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if err := c.reportMetrics(ctx, collectMetrics()); err != nil && ctx.Err() == nil {
				log.Printf("отправка метрик: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	go func() { // список ПО — раз в сутки и по запросу
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			sendSoftware()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	go func() {
		send()
		t := time.NewTicker(time.Duration(cfg.IntervalMin) * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				send()
			}
		}
	}()

	backoff := time.Second
	for ctx.Err() == nil {
		cmds, err := c.poll(ctx)
		if err != nil {
			var he *httpError
			if errors.As(err, &he) && he.code == 401 {
				log.Fatalf("сервер отклонил ключ хоста (хост удалён?): %v", err)
			}
			if ctx.Err() == nil {
				log.Printf("опрос: %v (повтор через %s)", err, backoff)
			}
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for _, cmd := range cmds {
			switch cmd.Type {
			case "collect":
				go send()
			case "software":
				go sendSoftware()
			case "update":
				go handleUpdate(ctx, c)
			case "term_open":
				go termOpen(ctx, c, cmd.SID, cmd.Cols, cmd.Rows)
			case "term_in":
				termInput(cmd.SID, cmd.Data)
			case "term_resize":
				termResize(cmd.SID, cmd.Cols, cmd.Rows)
			case "term_close":
				termClose(cmd.SID)
			default:
				log.Printf("неизвестная команда %q", cmd.Type)
			}
		}
	}
}

// cmdSet меняет настройки уже зарегистрированного агента (без повторной регистрации).
func cmdSet(args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "путь к конфигу")
	au := fs.String("autoupdate", "", "on или off: обновление агента из веб-интерфейса")
	_ = fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	switch *au {
	case "on":
		cfg.AllowUpdate = true
	case "off":
		cfg.AllowUpdate = false
	case "":
		usage()
	default:
		log.Fatalf("autoupdate: ожидается on или off, получено %q", *au)
	}
	if err := saveConfig(*cfgPath, cfg); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("обновление из веб-интерфейса: %s\n", *au)
}
