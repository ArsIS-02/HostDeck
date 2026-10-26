VERSION ?= 0.1.0
.PHONY: agents test release
agents:   ## собрать агенты в dist/
	mkdir -p dist
	cd agent && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/hostdeck-agent-darwin-arm64 .
	cd agent && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/hostdeck-agent-darwin-amd64 .
	cd agent && GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/hostdeck-agent-linux-amd64 .
	cd agent && GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../dist/hostdeck-agent-linux-arm64 .
	cd agent && go run . version > ../dist/VERSION
test: agents    ## unit-тесты агента + сквозной тест
	cd agent && go test ./...
	cd agent && go build -o ../dist/hostdeck-agent-test .
	python3 tests/e2e.py dist/hostdeck-agent-test

# Подписанный выпуск: make release KEY=~/.hostdeck/update.key
# Результат в dist/: бинарники, VERSION, SHA256SUMS и SHA256SUMS.sig. Затем: podman build --build-arg AGENTS=signed ...
release: agents   ## собрать агенты и подписать SHA256SUMS закрытым ключом (KEY=файл)
	@test -n "$(KEY)" || { echo "укажите KEY=файл закрытого ключа (см. docs/lab-notes.md, «Подпись обновлений»)"; exit 2; }
	cd dist && sha256sum hostdeck-agent-darwin-arm64 hostdeck-agent-darwin-amd64 hostdeck-agent-linux-amd64 hostdeck-agent-linux-arm64 > SHA256SUMS
	cd agent && go run ./cmd/hostdeck-sign sign -key $(KEY) -in ../dist/SHA256SUMS
	@ls -l dist/SHA256SUMS dist/SHA256SUMS.sig
