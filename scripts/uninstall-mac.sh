#!/bin/bash
# Удаление агента HostDeck с macOS. Запуск: sudo ./uninstall-mac.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запустите через sudo"; exit 1; }
PLIST=/Library/LaunchDaemons/local.hostdeck.agent.plist
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST" /usr/local/bin/hostdeck-agent
rm -rf "/Library/Application Support/HostDeck"
echo "Агент удалён. Не забудьте удалить хост в веб-интерфейсе HostDeck."
