VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

.PHONY: all tidy windows linux darwin clean vuln security

all: windows

tidy:
	go mod tidy

windows: tidy
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/kubeport-windows-amd64.exe ./cmd/kubeport
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/kubeport-windows-arm64.exe ./cmd/kubeport

linux: tidy
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/kubeport-linux-amd64 ./cmd/kubeport

darwin: tidy
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/kubeport-darwin-amd64 ./cmd/kubeport
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/kubeport-darwin-arm64 ./cmd/kubeport

clean:
	rm -rf $(DIST)

# Scan dependencies + stdlib for known vulnerabilities with reachability
# analysis. GOTOOLCHAIN=go1.26.2 forces govulncheck itself to build with the
# repo's toolchain so it can load packages that require that Go version.
vuln:
	GOTOOLCHAIN=go1.26.2 go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Static security analysis for Go (insecure file perms, shell injection,
# unhandled errors, etc.). False positives are annotated with #nosec.
security:
	GOTOOLCHAIN=go1.26.2 go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
