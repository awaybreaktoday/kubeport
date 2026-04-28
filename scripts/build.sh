#!/usr/bin/env bash
#
# Cross-compile the kubeport static binary. Produces:
#   dist/kubeport-windows-amd64.exe
#   dist/kubeport-windows-arm64.exe
#   dist/kubeport-linux-amd64       (optional; handy for local testing)
#   dist/kubeport-darwin-arm64      (optional; handy for local testing)
#
# Usage:
#   scripts/build.sh [version]
#
# If no version is supplied, the git short SHA (or "dev") is used.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
DIST=dist
mkdir -p "${DIST}"

LDFLAGS="-s -w -X main.version=${VERSION}"

build() {
  local goos="$1"
  local goarch="$2"
  local ext=""
  [[ "${goos}" == "windows" ]] && ext=".exe"
  local out="${DIST}/kubeport-${goos}-${goarch}${ext}"

  echo "==> ${out}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${out}" ./cmd/kubeport
}

# Primary target.
build windows amd64
build windows arm64

# Optional secondary targets (useful for smoke-testing without a Windows box).
if [[ "${KUBEPORT_BUILD_UNIX:-0}" == "1" ]]; then
  build linux  amd64
  build linux  arm64
  build darwin amd64
  build darwin arm64
fi

echo
echo "Built kubeport ${VERSION}:"
ls -lh "${DIST}"
