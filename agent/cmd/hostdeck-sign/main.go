// hostdeck-sign — подпись списка контрольных сумм агентов ключом Ed25519. Запускается на вашем компьютере, закрытый ключ на сервер не попадает.
//
//	go run ./cmd/hostdeck-sign keygen -out ~/.hostdeck/sign.key      # один раз; печатает открытый ключ
//	go run ./cmd/hostdeck-sign sign -key ~/.hostdeck/sign.key -in dist/SHA256SUMS   # создаёт dist/SHA256SUMS.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func main() {
	if len(os.Args) < 2 {
		die("использование: hostdeck-sign keygen -out файл | sign -key файл -in SHA256SUMS")
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "", "куда записать закрытый ключ")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			die("укажите -out")
		}
		if _, err := os.Stat(*out); err == nil {
			die("%s уже существует: ключ не перезаписывается", *out)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("%v", err)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			die("%v", err)
		}
		fmt.Printf("Закрытый ключ: %s (храните вне сервера, сделайте копию)\nОткрытый ключ (его указывают на хостах, HOSTDECK_UPDATE_KEY):\n%s\n", *out, base64.StdEncoding.EncodeToString(pub))
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		key := fs.String("key", "", "файл закрытого ключа")
		in := fs.String("in", "", "файл SHA256SUMS")
		_ = fs.Parse(os.Args[2:])
		if *key == "" || *in == "" {
			die("укажите -key и -in")
		}
		kb, err := os.ReadFile(*key)
		if err != nil {
			die("%v", err)
		}
		seed, err := base64.StdEncoding.DecodeString(string(trim(kb)))
		if err != nil || len(seed) != ed25519.SeedSize {
			die("файл ключа повреждён")
		}
		msg, err := os.ReadFile(*in)
		if err != nil {
			die("%v", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		sig := ed25519.Sign(priv, msg)
		if err := os.WriteFile(*in+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("Подпись записана: %s.sig\nОткрытый ключ: %s\n", *in, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	default:
		die("неизвестная команда %q", os.Args[1])
	}
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
