#!/usr/bin/env bash
# setup.sh — Bootstrap Loom from source.
# Usage: chmod +x scripts/setup.sh && ./scripts/setup.sh
set -euo pipefail

echo ""
echo "  🧵 Setting up Loom..."
echo ""

# Check Go
if ! command -v go &>/dev/null; then
  echo "  ✗ Go not found. Install Go 1.21+ from https://golang.org/dl/"
  exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "  ✓ $GO_VERSION"

# Download dependencies
echo "  Downloading dependencies..."
go mod download
echo "  ✓ Dependencies ready"

mkdir -p bin

echo "  Building loom..."
go build -ldflags="-s -w" -o bin/loom .
echo "  ✓ bin/loom"

echo "  Building testserver..."
go build -ldflags="-s -w" -o bin/testserver ./testserver
echo "  ✓ bin/testserver"

echo ""
echo "  ─────────────────────────────────────────"
echo "  Done!  Quick start:"
echo ""
echo "  # Terminal 1 — start test backend"
echo "  ./bin/testserver"
echo ""
echo "  # Terminal 2 — start Loom"
echo "  ./bin/loom -backend localhost:50051 -ui :9998"
echo ""
echo "  # Terminal 3 — make a call"
echo "  grpcurl -plaintext -d '{\"userId\":\"abc123\"}' localhost:9999 user.UserService/GetUser"
echo ""
echo "  # Browser — open the Web Inspector"
echo "  open http://localhost:9998"
echo "  ─────────────────────────────────────────"
echo ""
