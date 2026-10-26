package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// updateKey — закреплённый открытый ключ (base64, Ed25519), которым подписан список SHA256SUMS. Если задан, агент обновляется только
// из списка с верной подписью: захват сервера не позволяет подсунуть подменённого агента, пока закрытый ключ хранится вне сервера.
// Ключ записывается в конфиг при установке (HOSTDECK_UPDATE_KEY) или командой `hostdeck-agent set -update-key`, а удалённо не меняется.
var updateKey string

func parseKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("ключ подписи должен быть открытым ключом Ed25519 в base64 (32 байта)")
	}
	return ed25519.PublicKey(raw), nil
}

// verifySums проверяет подпись (base64 текст или 64 сырых байта) списка контрольных сумм.
func verifySums(sums, sig []byte, keyB64 string) error {
	pub, err := parseKey(keyB64)
	if err != nil {
		return err
	}
	raw := sig
	if len(sig) != ed25519.SignatureSize {
		if raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig))); err != nil {
			return errors.New("подпись не разобрана")
		}
	}
	if len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, raw) {
		return errors.New("подпись списка контрольных сумм неверна")
	}
	return nil
}

// checkSignedSums скачивает подпись и проверяет список. Без закреплённого ключа проверка не выполняется (прежнее поведение).
func checkSignedSums(ctx context.Context, c *Client, sums []byte) error {
	if updateKey == "" {
		return nil
	}
	sig, err := c.get(ctx, "/dl/SHA256SUMS.sig", 1<<10)
	if err != nil {
		return fmt.Errorf("подпись обновления не получена (на хосте закреплён ключ, сервер подписи не отдал): %w", err)
	}
	return verifySums(sums, sig, updateKey)
}

// cmpVersion сравнивает версии вида 1.2.3 (суффикс после «-» отбрасывается): -1, 0 или 1.
func cmpVersion(a, b string) int {
	pa, pb := strings.Split(strings.SplitN(a, "-", 2)[0], "."), strings.Split(strings.SplitN(b, "-", 2)[0], ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
