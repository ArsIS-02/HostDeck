VERSION ?= 0.1.0
.PHONY: agents test
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
