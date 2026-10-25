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

## 4. Обратный прокси

Контейнер слушает только `127.0.0.1:8080`. TLS должен давать ваш прокси, например для nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 60s;
    proxy_buffering off;           # поток вывода консоли (SSE) не должен буферизоваться
    # для /api/term/ можно поднять proxy_read_timeout до 1h: поток держится открытым        # длинный опрос агентов идёт до 25 секунд
}
```

Если прокси стоит на другом хосте, опубликуйте порт на его адресе (`PublishPort=<ip>:8080:8080`) и укажите этот IP в `FORWARDED_ALLOW_IPS`, но только для доверенного прокси.

## Типичные проблемы

- **`Permission denied` на `/data`** при bind-mount каталога из домашней папки: в rootless-режиме uid внутри контейнера (10001) отображается на другой uid хоста. Используйте именованный том, как в юните, либо `podman unshare chown 10001:10001 ./data`.
- **SELinux** на RED OS блокирует чтение bind-mount: добавьте `:Z` к тому (`-v ./data:/data:Z`). Именованному тому метка не нужна.
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
