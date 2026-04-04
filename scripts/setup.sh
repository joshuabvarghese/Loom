#!/usr/bin/env bash
# setup.sh — Bootstrap Loom from source.
# Usage: chmod +x scripts/setup.sh && ./scripts/setup.sh
set -euo pipefail

echo ""
echo "  🧵 Setting up Loom..."
echo ""

# Check Go is installed
if ! command -v go &>/dev/null; then
  echo "  ✗ Go not found. Install Go 1.21+ from https://golang.org/dl/"
  exit 1
fi

# Check Go version (need at least 1.21)
GO_VERSION_RAW=$(go version | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo "$GO_VERSION_RAW" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION_RAW" | cut -d. -f2)

echo "  ✓ go$GO_VERSION_RAW"

if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]; }; then
  echo ""
  echo "  ✗ Go 1.21 or newer is required (you have go$GO_VERSION_RAW)"
  echo "  → Download from https://golang.org/dl/"
  exit 1
fi

# Download dependencies
echo "  Downloading dependencies..."
go mod tidy
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
echo "  # Option A — demo mode (no backend needed)"
echo "  ./bin/loom -demo"
echo "  # then open http://localhost:9998"
echo ""
echo "  # Option B — proxy your own service"
echo "  ./bin/testserver                          # Terminal 1"
echo "  ./bin/loom -backend localhost:50051 -ui :9998  # Terminal 2"
echo "  open http://localhost:9998"
echo "  ─────────────────────────────────────────"
echo ""
