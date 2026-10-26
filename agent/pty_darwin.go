//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// Запросы ioctl для /dev/ptmx в macOS (sys/ttycom.h).
const (
	tiocPtyGrant = 0x20007454
	tiocPtyUnlk  = 0x20007452
	tiocPtyGName = 0x40807453
)

func ioctl(fd, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); e != 0 {
		return e
	}
	return nil
}

func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := ioctl(m.Fd(), tiocPtyGrant, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	if err := ioctl(m.Fd(), tiocPtyUnlk, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	var name [128]byte
	if err := ioctl(m.Fd(), tiocPtyGName, uintptr(unsafe.Pointer(&name[0]))); err != nil {
		m.Close()
		return nil, nil, err
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	s, err := os.OpenFile(string(name[:n]), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}
