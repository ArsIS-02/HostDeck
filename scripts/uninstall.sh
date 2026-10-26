#!/bin/bash
# Удаление агента HostDeck (macOS и Linux). Запуск: sudo ./uninstall.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запустите через sudo"; exit 1; }
if [ "$(uname -s)" = Darwin ]; then
  PLIST=/Library/LaunchDaemons/local.hostdeck.agent.plist
  launchctl bootout system "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"; rm -rf "/Library/Application Support/HostDeck"
else
  systemctl disable --now hostdeck-agent 2>/dev/null || true
  rm -f /etc/systemd/system/hostdeck-agent.service; systemctl daemon-reload 2>/dev/null || true
  rm -rf /etc/hostdeck
fi
rm -f /usr/local/bin/hostdeck-agent
echo "Агент удалён. Не забудьте удалить хост в веб-интерфейсе HostDeck."
