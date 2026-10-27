#!/usr/bin/env bash
# Автозапуск ВСЕХ контейнеров Podman (root и rootless-пользователей) после перезагрузки хоста.
#
#   sudo ./containers-autostart.sh                применить
#   sudo ./containers-autostart.sh --dry-run      только показать, что будет сделано
#   sudo ./containers-autostart.sh --now          сверх того сразу запустить все остановленные контейнеры
#   sudo ./containers-autostart.sh --docker       заодно настроить Docker (docker.service и restart=unless-stopped)
#   sudo ./containers-autostart.sh --uninstall    убрать установленные скриптом службы
#
# Как это работает (повторный запуск безопасен):
#   1. Для root и каждого пользователя с rootless-Podman ставится служба podman-autostart-all.service:
#      при загрузке она выполняет «podman start --all». Работает с любой версией Podman, не зависит от политик
#      перезапуска (always, unless-stopped, no), поэтому поднимает и контейнеры, созданные через compose.
#   2. Для rootless-пользователей включается linger (иначе их службы не стартуют до входа в систему).
#   3. Контейнеры, которыми управляет systemd-юнит (Quadlet и т. п.), стартуют этим юнитом; скрипт проверяет,
#      что юнит включён, и включает его, если он выключен.
# Внимание: запускаются ВСЕ контейнеры, в том числе остановленные вами намеренно. Исключить контейнер можно,
# удалив его или управляя им через юнит.
set -u

DRY=0; NOW=0; DOCKER=0; UNINST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --now) NOW=1 ;;
    --docker) DOCKER=1 ;;
    --uninstall) UNINST=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "неизвестный параметр: $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo $0" >&2; exit 1; }
[ "$DRY" = 1 ] && echo "РЕЖИМ ПРОВЕРКИ: изменений не вносится"

SVC=podman-autostart-all.service
ROOT_UNIT_DIR="${AUTOSTART_ROOT_UNIT_DIR:-/etc/systemd/system}"
CHANGED=0; OK=0; WARN=0
say()  { printf '%s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; WARN=$((WARN+1)); }
do_it() { # do_it ОПИСАНИЕ команда...
  local what="$1"; shift
  if [ "$DRY" = 1 ]; then say "  [проверка] $what"; CHANGED=$((CHANGED+1)); return 0; fi
  if "$@" >/dev/null 2>&1; then say "  + $what"; CHANGED=$((CHANGED+1)); return 0; fi
  warn "не удалось: $what"; return 1
}

PODMAN=$(command -v podman 2>/dev/null || true)
unit_text() { # $1 = цель установки; для системной службы ждём сеть
  echo "[Unit]"
  echo "Description=Start all Podman containers at boot (containers-autostart.sh)"
  [ "$1" = multi-user.target ] && { echo "After=network-online.target"; echo "Wants=network-online.target"; }
  echo; echo "[Service]"; echo "Type=oneshot"; echo "RemainAfterExit=yes"
  echo "ExecStart=-$PODMAN start --all"
  echo; echo "[Install]"; echo "WantedBy=$1"
}

# установка (или удаление) службы в одной среде: $1 подпись, $2 каталог юнита, $3 цель, остальное — префикс запуска
install_svc() {
  local label="$1" dir="$2" target="$3"; shift 3
  local P=("$@") su=(); [ ${#P[@]} -gt 0 ] && su=(--user)
  local file="$dir/$SVC"
  if [ "$UNINST" = 1 ]; then
    [ -f "$file" ] || { say "  = $label: службы нет"; return; }
    if [ "$DRY" = 1 ]; then say "  [проверка] $label: служба отключена и удалена"; CHANGED=$((CHANGED+1))
    else
      "${P[@]}" systemctl "${su[@]}" disable "$SVC" >/dev/null 2>&1; rm -f "$file"; "${P[@]}" systemctl "${su[@]}" daemon-reload >/dev/null 2>&1
      say "  + $label: служба отключена и удалена"; CHANGED=$((CHANGED+1))
    fi
    return
  fi
  if [ -f "$file" ] && [ "$(unit_text "$target")" = "$(cat "$file" 2>/dev/null)" ]; then
    say "  = $label: служба $SVC уже установлена"; OK=$((OK+1))
  else
    if [ "$DRY" = 1 ]; then say "  [проверка] $label: установлена служба $SVC"; CHANGED=$((CHANGED+1))
    else
      if [ ${#P[@]} -gt 0 ]; then
        "${P[@]}" mkdir -p "$dir" && unit_text "$target" | "${P[@]}" tee "$file" >/dev/null
      else
        mkdir -p "$dir" && unit_text "$target" > "$file"
      fi
      if [ -f "$file" ]; then say "  + $label: установлена служба $SVC"; CHANGED=$((CHANGED+1)); else warn "$label: не удалось записать $file"; return; fi
    fi
    [ "$DRY" = 1 ] || "${P[@]}" systemctl "${su[@]}" daemon-reload >/dev/null 2>&1
  fi
  if "${P[@]}" systemctl "${su[@]}" is-enabled "$SVC" >/dev/null 2>&1; then say "  = $label: служба включена"; OK=$((OK+1))
  else do_it "$label: служба включена при загрузке" "${P[@]}" systemctl "${su[@]}" enable "$SVC"; fi
  if [ "$NOW" = 1 ]; then do_it "$label: запущены все контейнеры" "${P[@]}" "$PODMAN" start --all; fi
}

# обзор контейнеров среды: кто запускается юнитом, кто — службой podman-autostart-all
scan_env() { # $1 подпись, $2 пользователь для подсказки, остальное — префикс запуска
  local label="$1" who="$2"; shift 2
  local P=("$@") su=(); [ ${#P[@]} -gt 0 ] && su=(--user)
  local ids; ids=$("${P[@]}" "$PODMAN" ps -aq 2>/dev/null) || { warn "$label: не удалось получить список контейнеров"; return; }
  local id line name unit st seen=""
  for id in $ids; do
    line=$("${P[@]}" "$PODMAN" inspect --format '{{.Name}}|{{index .Config.Labels "PODMAN_SYSTEMD_UNIT"}}' "$id" 2>/dev/null | head -n1) || continue
    IFS='|' read -r name unit <<<"$line"; name="${name#/}"
    if [ -n "$unit" ]; then
      st=$("${P[@]}" systemctl "${su[@]}" is-enabled "$unit" 2>/dev/null | head -n1)
      case "$st" in
        enabled|enabled-runtime|generated|alias|linked) say "  = $name: запускает юнит $unit ($st)"; continue ;;
        ""|not-found) ;;   # метку ставит и podman-compose, хотя юнита может не быть: контейнер обычный
        disabled|static|indirect|masked) case " $seen " in *" $unit "*) ;; *) seen="$seen $unit"
            if [ "$st" = disabled ]; then do_it "$label: включён юнит $unit" "${P[@]}" systemctl "${su[@]}" enable "$unit"
            else warn "$name: юнит $unit не включается при загрузке (is-enabled: $st); исправьте его [Install] или удалите метку"; fi ;; esac
          continue ;;
      esac
    fi
    say "  = $name: запустится службой $SVC"
  done
}

# --- Podman --------------------------------------------------------------------------------------------------
if [ -z "$PODMAN" ]; then
  say "Podman не найден — пропускаю"
else
  say "== Podman (root)"
  [ "$UNINST" = 1 ] || scan_env "root" root
  install_svc "root" "$ROOT_UNIT_DIR" multi-user.target

  while IFS=: read -r user _ uid _ _ home _; do
    [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 60000 ] || continue
    [ -d "$home/.local/share/containers" ] || continue
    rt="/run/user/$uid"
    say "== Podman ($user)"
    if [ "$UNINST" != 1 ]; then
      if [ "$(loginctl show-user "$user" -p Linger --value 2>/dev/null)" = yes ]; then say "  = linger уже включён"; OK=$((OK+1))
      else do_it "$user: включён linger" loginctl enable-linger "$user"; fi
      if [ "$DRY" != 1 ] && [ ! -d "$rt" ]; then systemctl start "user@$uid.service" >/dev/null 2>&1; sleep 1; fi
    fi
    if [ -d "$rt" ]; then pre=(runuser -u "$user" -- env "XDG_RUNTIME_DIR=$rt" "DBUS_SESSION_BUS_ADDRESS=unix:path=$rt/bus")
    else
      pre=(runuser -u "$user" -- env "XDG_RUNTIME_DIR=$rt")
      [ "$DRY" = 1 ] || warn "$user: нет $rt, пользовательская служба systemd не запущена; повторите запуск через минуту"
    fi
    [ "$UNINST" = 1 ] || scan_env "$user" "$user" "${pre[@]}"
    install_svc "$user" "$home/.config/systemd/user" default.target "${pre[@]}"
  done < <(getent passwd)
fi

# --- Docker (по параметру --docker) ---------------------------------------------------------------------------
if [ "$DOCKER" = 1 ] && [ "$UNINST" != 1 ]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    say "== Docker"
    for id in $(docker ps -aq 2>/dev/null); do
      read -r name pol <<<"$(docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' "$id" 2>/dev/null)"; name="${name#/}"
      case "$pol" in always|unless-stopped) say "  = $name: политика $pol" ;; *) do_it "$name: restart=unless-stopped" docker update --restart=unless-stopped "$id" ;; esac
    done
    if systemctl is-enabled docker.service >/dev/null 2>&1; then say "  = docker.service уже включён"; OK=$((OK+1))
    else do_it "включён docker.service" systemctl enable docker.service; fi
  else say "Docker не найден или не запущен — пропускаю"; fi
fi

say ""
say "Итог: изменено $CHANGED, уже в порядке $OK, предупреждений $WARN."
[ "$DRY" = 1 ] && say "Это была проверка. Для применения запустите без --dry-run."
if [ "$UNINST" != 1 ] && [ "$DRY" != 1 ]; then
  say "После перезагрузки будут запущены ВСЕ контейнеры, включая остановленные вами намеренно."
  say "Проверка: перезагрузите хост и откройте вкладку «Контейнеры» в HostDeck."
fi
exit 0
