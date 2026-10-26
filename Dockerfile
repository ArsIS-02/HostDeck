# AGENTS=built  — агенты собираются в образе, SHA256SUMS сервер считает сам (по умолчанию);
# AGENTS=signed — берутся готовые из dist/ после `make release` (с подписью SHA256SUMS.sig).
ARG AGENTS=built

# Этап 1: сборка агентов под macOS и Linux (статические бинарники без CGO)
FROM docker.io/library/golang:1.24 AS agents-built
WORKDIR /src
COPY agent/ ./
RUN set -e; mkdir /agents; \
    for t in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do \
      CGO_ENABLED=0 GOOS=${t%-*} GOARCH=${t#*-} go build -trimpath -ldflags "-s -w" -o /agents/hostdeck-agent-$t . ; \
    done; \
    go run . version > /agents/VERSION

FROM docker.io/library/busybox:1.36 AS agents-signed
COPY dist/hostdeck-agent-* dist/VERSION dist/SHA256SUMS dist/SHA256SUMS.sig /agents/

FROM agents-${AGENTS} AS agents

# Этап 2: сервер
FROM docker.io/library/python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/app ./app
COPY --from=agents /agents /agents
RUN useradd --system --uid 10001 --no-create-home hostdeck && mkdir -p /data /run/secrets && touch /run/secrets/admin_pw && chown hostdeck /data
USER hostdeck
VOLUME /data
ENV HOSTDECK_DB=/data/hostdeck.db HOSTDECK_AGENT_DIR=/agents
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/static/style.css',timeout=4)"
# --proxy-headers: схема https берётся от обратного прокси (нужна для Secure-cookie)
CMD ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--proxy-headers"]
