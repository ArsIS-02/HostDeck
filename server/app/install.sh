#!/bin/bash
# HostDeck: установка и обновление агента (macOS и Linux).
#
#   curl -fsSL https://СЕРВЕР/install.sh | sudo bash -s -- <токен> [имя]
#   curl -fsSL https://СЕРВЕР/install.sh | sudo bash -s --            # обновить уже установленный агент
#
# Переменные окружения (ставятся перед bash: sudo HOSTDECK_TERMINAL=1 bash -s -- ...):
#   HOSTDECK_TERMINAL=1   разрешить root-консоль из веб-интерфейса на этом хосте (по умолчанию выключено)
#   HOSTDECK_AUTOUPDATE=1 разрешить серверу обновлять этого агента по кнопке в веб-интерфейсе (0 — запретить; не задано —
#                         оставить как есть). Обновление заменяет программу, работающую от root, поэтому по умолчанию выключено
#   HOSTDECK_CA=/путь     корневой сертификат (PEM), если сервер подписан внутренним CA. Он используется только
#                         агентом HostDeck (сохраняется рядом с его конфигом), в системное хранилище не добавляется
#   HOSTDECK_BIN=/путь    взять агент из файла, а не скачивать
#   HOSTDECK_DRYRUN=1     только скачать и проверить контрольную сумму, ничего не устанавливая
set -euo pipefail

SERVER="${HOSTDECK_SERVER:-@@SERVER@@}"
case "$SERVER" in @@*) echo "Не задан адрес сервера: запускайте скрипт через curl с вашего сервера или задайте HOSTDECK_SERVER"; exit 1;; esac
TOKEN="${1:-}"
NAME="${2:-$(hostname -s 2>/dev/null || hostname)}"
CA="${HOSTDECK_CA:-}"
# Контрольные суммы агентов сервер вшивает в сам скрипт. Сам скрипт проверяется по хешу из команды установки,
# поэтому цепочка доверия не зависит от TLS-клиента (системный curl в macOS игнорирует --cacert).
SUMS='@@SUMS@@'
case "$SUMS" in @@*) SUMS="";; esac

[ "$(id -u)" = 0 ] || [ "${HOSTDECK_DRYRUN:-0}" = 1 ] || { echo "Запустите от root (через sudo)"; exit 1; }

case "$(uname -s)" in Darwin) OS=darwin;; Linux) OS=linux;; *) echo "Система не поддерживается: $(uname -s)"; exit 1;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64;; x86_64|amd64) ARCH=amd64;; *) echo "Архитектура не поддерживается: $(uname -m)"; exit 1;; esac
FILE="hostdeck-agent-$OS-$ARCH"

if [ "$OS" = darwin ]; then CONF="/Library/Application Support/HostDeck/agent.json"; else CONF=/etc/hostdeck/agent.json; fi
if [ -z "$TOKEN" ] && [ ! -f "$CONF" ]; then
  echo "Хост ещё не зарегистрирован: укажите токен из окна «Добавить хост»."; exit 1
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
if [ "$OS" = darwin ]; then CA_DEST="/Library/Application Support/HostDeck/ca.pem"; else CA_DEST=/etc/hostdeck/ca.pem; fi
CURL=(curl -fsSL --retry 2)
if [ -n "$CA" ]; then
  # при вшитых суммах канал можно не проверять: подлинность файла доказывает хеш; иначе проверяем по CA
  if [ -n "$SUMS" ]; then CURL+=(-k); else CURL+=(--cacert "$CA"); fi
fi

if [ -n "${HOSTDECK_BIN:-}" ]; then
  cp "$HOSTDECK_BIN" "$TMP/agent"
else
  echo "Скачиваю $FILE с $SERVER ..."
  "${CURL[@]}" "$SERVER/dl/$FILE" -o "$TMP/agent"
  if [ -n "$SUMS" ]; then printf '%s\n' "$SUMS" > "$TMP/sums"; else "${CURL[@]}" "$SERVER/dl/SHA256SUMS" -o "$TMP/sums"; fi
  WANT="$(awk -v f="$FILE" '$2==f {print $1}' "$TMP/sums")"
  if command -v sha256sum >/dev/null; then GOT="$(sha256sum "$TMP/agent" | awk '{print $1}')"; else GOT="$(shasum -a 256 "$TMP/agent" | awk '{print $1}')"; fi
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo "Контрольная сумма не совпала (ожидалась $WANT, получена $GOT). Установка прервана."; exit 1; }
  echo "Контрольная сумма совпала."
fi
chmod 755 "$TMP/agent"
if [ -n "$CA" ] && [ "${HOSTDECK_DRYRUN:-0}" != 1 ]; then
  install -d -m 755 "$(dirname "$CA_DEST")"
  [ "$CA" = "$CA_DEST" ] || install -m 644 "$CA" "$CA_DEST"
  CA="$CA_DEST"
fi
if [ "${HOSTDECK_DRYRUN:-0}" = 1 ]; then echo "DRYRUN: $("$TMP/agent" version) для $OS/$ARCH, установка пропущена."; exit 0; fi

install -d -m 755 /usr/local/bin
install -m 755 "$TMP/agent" /usr/local/bin/hostdeck-agent.new
mv -f /usr/local/bin/hostdeck-agent.new /usr/local/bin/hostdeck-agent
[ "$OS" = darwin ] && xattr -d com.apple.quarantine /usr/local/bin/hostdeck-agent 2>/dev/null || true

if [ -n "$TOKEN" ]; then
  ARGS=(enroll -server "$SERVER" -token "$TOKEN" -name "$NAME")
  [ -n "$CA" ] && ARGS+=(-ca "$CA")
  [ "${HOSTDECK_TERMINAL:-0}" = 1 ] && ARGS+=(-terminal)   # root-консоль включается только явно
  [ "${HOSTDECK_AUTOUPDATE:-0}" = 1 ] && ARGS+=(-autoupdate)   # обновление из веба тоже только явно
  /usr/local/bin/hostdeck-agent "${ARGS[@]}"
elif [ -n "${HOSTDECK_AUTOUPDATE:-}" ]; then
  case "$HOSTDECK_AUTOUPDATE" in 1) /usr/local/bin/hostdeck-agent set -autoupdate on;; 0) /usr/local/bin/hostdeck-agent set -autoupdate off;; esac
fi

if [ "$OS" = darwin ]; then
  PLIST=/Library/LaunchDaemons/local.hostdeck.agent.plist
  cat > "$PLIST" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.hostdeck.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/hostdeck-agent</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/hostdeck-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/hostdeck-agent.log</string>
</dict></plist>
P
  chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  launchctl bootout system "$PLIST" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  echo "Готово. Журнал: /var/log/hostdeck-agent.log"
elif command -v systemctl >/dev/null; then
  cat > /etc/systemd/system/hostdeck-agent.service <<'U'
[Unit]
Description=HostDeck agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hostdeck-agent run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
U
  systemctl daemon-reload
  systemctl enable hostdeck-agent >/dev/null 2>&1 || true
  systemctl restart hostdeck-agent
  echo "Готово. Журнал: journalctl -u hostdeck-agent -f"
else
  echo "systemd не найден: запустите агент сами: /usr/local/bin/hostdeck-agent run"
fi
