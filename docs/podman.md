# Запуск в Podman (RED OS)

Проверено на уровне конфигурации: сам образ собирается обычным `Dockerfile`, юнит рассчитан на rootless Podman 4.4+ (`podman --version`). Если версия ниже, используйте `podman run` из раздела «Без Quadlet».

## 1. Сборка образа

```bash
cd hostdeck
podman build -t hostdeck:latest .
```

Базовый образ указан полностью (`docker.io/library/python:3.13-slim`): Podman не спрашивает, из какого реестра брать короткое имя. Нужен доступ в интернет к docker.io и PyPI; если их нет, соберите образ на другой машине и перенесите: `podman save hostdeck:latest | ssh хост podman load`.

## 2. Пароль администратора как секрет

```bash
read -rs -p "Пароль админа: " P; echo
printf %s "$P" | podman secret create hostdeck_admin_pw -
unset P
```

Пароль не попадает в историю команд, в `ps` и в переменные окружения контейнера: сервер читает его из файла `/run/secrets/admin_pw` (`HOSTDECK_ADMIN_PASSWORD_FILE`). Нужен только при первом запуске, пока в базе нет пользователей.

## 3. Quadlet и автозапуск

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/podman/hostdeck.container deploy/podman/hostdeck-data.volume ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start hostdeck
loginctl enable-linger "$USER"      # чтобы сервис жил без открытой сессии
systemctl --user status hostdeck
```

Журнал: `journalctl --user -u hostdeck -f`.

## 3a. Сертификат внутреннего CA для установки агентов

Если хосты не доверяют CA, которым подписан HostDeck (например, внутренний CA Caddy), сервер может раздавать его корневой сертификат. Хост скачивает его и сверяет с отпечатком SHA-256, который окно «Добавить хост» вшивает в команду из вашей авторизованной сессии. Подмена в сети не пройдёт. В системное хранилище сертификат не ставится: он нужен только агенту (`ca_file`).

```bash
mkdir -p ~/hostdeck-ca && cp ~/caddy-root.crt ~/hostdeck-ca/ca.pem
diff ~/hostdeck-ca/ca.pem ~/n8n-docker-caddy/caddy_data/caddy/pki/authorities/local/root.crt && echo "это действующий корень Caddy"
mkdir -p ~/.config/containers/systemd/hostdeck.container.d
cat > ~/.config/containers/systemd/hostdeck.container.d/ca.conf <<'EOC'
[Container]
Volume=/home/redos/hostdeck-ca/ca.pem:/etc/hostdeck/ca.pem:ro,Z
Environment=HOSTDECK_CA_FILE=/etc/hostdeck/ca.pem
EOC
systemctl --user daemon-reload && systemctl --user restart hostdeck
```

## 4. Caddy в контейнере (вариант домашней лаборатории)

Юнит подключает HostDeck к podman-сети `n8n-net`, где уже работает контейнер `caddy`. В Caddyfile добавляется блок:

```caddy
hostdeck.apps.monitoring.test {
    reverse_proxy hostdeck:8080 {
        flush_interval -1      # поток вывода консоли (SSE) не буферизуется
    }
}
```

После правки: `podman exec caddy caddy reload --config /etc/caddy/Caddyfile` (путь внутри контейнера может отличаться). Если Caddyfile генерируется из `services.yaml`, добавьте службу там в формате соседних записей.

## 4a. Обратный прокси nginx (общий вариант)

Контейнер слушает только `127.0.0.1:8080`. TLS должен давать ваш прокси, например для nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 1h;         # поток вывода консоли (SSE) держится открытым; длинный опрос агентов идёт до 25 секунд
    proxy_buffering off;           # SSE не должен буферизоваться
}
```

Если прокси стоит на другом хосте, опубликуйте порт на его адресе (`PublishPort=<ip>:8080:8080`) и укажите этот IP в `FORWARDED_ALLOW_IPS`, но только для доверенного прокси.

## Типичные проблемы

- **`Permission denied` на `/data`** при bind-mount каталога из домашней папки: в rootless-режиме uid внутри контейнера (10001) отображается на другой uid хоста. Используйте именованный том, как в юните, либо `podman unshare chown 10001:10001 ./data`.
- **SELinux** на RED OS блокирует чтение bind-mount: добавьте `:Z` к тому (`-v ./data:/data:Z`). Именованному тому метка не нужна.
- **`error mounting ... /run/secrets/admin_pw: read-only file system`**: на RED OS (runc) секрет нельзя смонтировать при `ReadOnly=true`, даже если файл-точка есть в образе. Поэтому в юните `ReadOnly` не используется; защита держится на непривилегированном пользователе, `DropCapability=ALL` и `NoNewPrivileges`.
- **`HEALTHCHECK` игнорируется**, если образ собран не в формате docker: `podman build --format docker ...`.
- **Порты ниже 1024** в rootless недоступны: поэтому контейнер на 8080.

## Без Quadlet

```bash
podman volume create hostdeck-data
podman run -d --name hostdeck --restart=always \
  -p 127.0.0.1:8080:8080 \
  -v hostdeck-data:/data \
  --secret hostdeck_admin_pw,target=/run/secrets/admin_pw \
  -e HOSTDECK_ADMIN_PASSWORD_FILE=/run/secrets/admin_pw \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges \
  localhost/hostdeck:latest
```
