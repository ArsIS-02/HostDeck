package main

import (
	"context"
	"encoding/base64"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// allowTerminal включает root-консоль для этого хоста. Выключено по умолчанию: включается явно
// при регистрации (-terminal) или правкой allow_terminal в конфиге на самом хосте.
var allowTerminal bool

type termSession struct {
	sid    string
	master *os.File
	cmd    *exec.Cmd
	in     chan []byte
	done   chan struct{}
	once   sync.Once
}

var (
	termMu   sync.Mutex
	sessions = map[string]*termSession{}
)

func setWinsize(f *os.File, cols, rows uint16) {
	ws := struct{ Row, Col, X, Y uint16 }{rows, cols, 0, 0}
	_ = ioctl(f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

func shellPath() string {
	if runtime.GOOS == "darwin" {
		return "/bin/zsh"
	}
	for _, p := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/bin/sh"
}

func (s *termSession) close() {
	s.once.Do(func() {
		close(s.done)
		if s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGHUP) // вся группа процессов сессии
			_ = s.cmd.Process.Kill()
		}
		_ = s.master.Close()
	})
}

// termOpen запускает оболочку root в псевдотерминале и начинает пересылать вывод на сервер.
func termOpen(ctx context.Context, c *Client, sid string, cols, rows int) {
	if !allowTerminal {
		_ = c.reportTerm(ctx, sid, 0, nil, "disabled")
		return
	}
	if cols < 20 || cols > 400 {
		cols = 100
	}
	if rows < 5 || rows > 200 {
		rows = 30
	}
	master, slave, err := openPTY()
	if err != nil {
		log.Printf("терминал: pty: %v", err)
		_ = c.reportTerm(ctx, sid, 0, nil, "pty: "+err.Error())
		return
	}
	setWinsize(master, uint16(cols), uint16(rows))
	home := "/var/root"
	if runtime.GOOS != "darwin" {
		home = "/root"
	}
	cmd := exec.Command(shellPath(), "-i")
	cmd.Dir = home
	cmd.Env = []string{"TERM=xterm-256color", "HOME=" + home, "USER=root", "LOGNAME=root", "LANG=en_US.UTF-8",
		"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOSTDECK_SESSION=1"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		master.Close()
		_ = c.reportTerm(ctx, sid, 0, nil, "start: "+err.Error())
		return
	}
	slave.Close()
	s := &termSession{sid: sid, master: master, cmd: cmd, in: make(chan []byte, 256), done: make(chan struct{})}
	termMu.Lock()
	sessions[sid] = s
	termMu.Unlock()
	log.Printf("терминал: сессия %s открыта (root)", sid)

	// ввод: отдельная горутина, чтобы запись в pty не блокировала опрос команд
	go func() {
		for {
			select {
			case <-s.done:
				return
			case b := <-s.in:
				if _, err := master.Write(b); err != nil {
					return
				}
			}
		}
	}()

	// вывод: читаем pty и отправляем пачками раз в ~20 мс, чтобы не слать запрос на каждый байт
	var (
		mu  sync.Mutex
		buf []byte
		seq int
	)
	flush := func() {
		mu.Lock()
		b := buf
		buf = nil
		mu.Unlock()
		if len(b) == 0 {
			return
		}
		seq++
		if err := c.reportTerm(ctx, sid, seq, b, ""); err != nil {
			log.Printf("терминал: отправка вывода: %v", err)
		}
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		chunk := make([]byte, 8192)
		for {
			n, err := master.Read(chunk)
			if n > 0 {
				mu.Lock()
				buf = append(buf, chunk[:n]...)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				flush()
			case <-readDone:
				flush()
				_ = cmd.Wait()
				code := 0
				if cmd.ProcessState != nil {
					code = cmd.ProcessState.ExitCode()
				}
				s.close()
				termMu.Lock()
				delete(sessions, sid)
				termMu.Unlock()
				_ = c.reportTermExit(ctx, sid, code)
				log.Printf("терминал: сессия %s закрыта (код %d)", sid, code)
				return
			}
		}
	}()
}

func termInput(sid string, data string) {
	termMu.Lock()
	s := sessions[sid]
	termMu.Unlock()
	if s == nil || len(data) > 16384 {
		return
	}
	select {
	case s.in <- []byte(data):
	default: // очередь переполнена — отбрасываем ввод, чем подвешиваем опрос
	}
}

func termResize(sid string, cols, rows int) {
	termMu.Lock()
	s := sessions[sid]
	termMu.Unlock()
	if s != nil && cols >= 20 && cols <= 400 && rows >= 5 && rows <= 200 {
		setWinsize(s.master, uint16(cols), uint16(rows))
	}
}

func termClose(sid string) {
	termMu.Lock()
	s := sessions[sid]
	termMu.Unlock()
	if s != nil {
		s.close()
	}
}

func closeAllTerms() {
	termMu.Lock()
	list := make([]*termSession, 0, len(sessions))
	for _, s := range sessions {
		list = append(list, s)
	}
	termMu.Unlock()
	for _, s := range list {
		s.close()
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
