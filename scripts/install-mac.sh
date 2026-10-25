#!/bin/bash
# Установка агента HostDeck на macOS. Запуск: sudo ./install-mac.sh <адрес сервера> <токен> [имя] [путь к ca.pem]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запустите через sudo"; exit 1; }
SERVER="${1:?адрес сервера, например https://hostdeck.apps.monitoring.test}"
TOKEN="${2:?токен регистрации из веб-интерфейса}"
NAME="${3:-$(hostname -s)}"
CA="${4:-}"
SRC="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="${HOSTDECK_BIN:-$SRC/hostdeck-agent}"
[ -x "$BIN_SRC" ] || { echo "Не найден исполняемый файл агента: $BIN_SRC (положите hostdeck-agent рядом со скриптом или задайте HOSTDECK_BIN)"; exit 1; }

install -d -m 755 /usr/local/bin
install -m 755 "$BIN_SRC" /usr/local/bin/hostdeck-agent
xattr -d com.apple.quarantine /usr/local/bin/hostdeck-agent 2>/dev/null || true

ARGS=(enroll -server "$SERVER" -token "$TOKEN" -name "$NAME")
[ -n "$CA" ] && ARGS+=(-ca "$CA")
/usr/local/bin/hostdeck-agent "${ARGS[@]}"

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
