package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifySums(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := base64.StdEncoding.EncodeToString(pub)
	sums := []byte("abc  hostdeck-agent-linux-amd64\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)))
	if err := verifySums(sums, sig, key); err != nil {
		t.Fatal("верная подпись отклонена:", err)
	}
	if err := verifySums([]byte("abc  other\n"), sig, key); err == nil {
		t.Error("изменённый список принят")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifySums(sums, sig, base64.StdEncoding.EncodeToString(pub2)); err == nil {
		t.Error("чужой ключ принят")
	}
	if err := verifySums(sums, []byte("мусор"), key); err == nil {
		t.Error("мусор вместо подписи принят")
	}
	if err := verifySums(sums, sig, "не ключ"); err == nil {
		t.Error("неверный ключ принят")
	}
}

func TestCheckSignedSums(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte("abc  hostdeck-agent-linux-amd64\n")
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums))
	mode := "good"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "good":
			w.Write([]byte(good))
		case "forged":
			w.Write([]byte(strings.Repeat("A", 86) + "=="))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old := updateKey
	defer func() { updateKey = old }()

	updateKey = ""
	mode = "missing"
	if err := checkSignedSums(ctx, c, sums); err != nil {
		t.Error("без закреплённого ключа проверка не нужна:", err)
	}
	updateKey = base64.StdEncoding.EncodeToString(pub)
	mode = "good"
	if err := checkSignedSums(ctx, c, sums); err != nil {
		t.Error("верная подпись не принята:", err)
	}
	mode = "forged"
	if err := checkSignedSums(ctx, c, sums); err == nil {
		t.Error("поддельная подпись принята")
	}
	mode = "missing"
	if err := checkSignedSums(ctx, c, sums); err == nil {
		t.Error("отсутствие подписи при закреплённом ключе должно быть отказом")
	}
}

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		w    int
	}{{"0.6.1", "0.6.1", 0}, {"0.6.1", "0.7.0", -1}, {"0.10.0", "0.9.9", 1}, {"1.0", "1.0.0", 0}, {"0.6.1-dev", "0.6.1", 0}} {
		if g := cmpVersion(c.a, c.b); g != c.w {
			t.Errorf("%s vs %s: %d, ждали %d", c.a, c.b, g, c.w)
		}
	}
}
