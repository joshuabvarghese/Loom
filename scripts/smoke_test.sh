#!/usr/bin/env bash
# smoke_test.sh — Runs a full end-to-end smoke test automatically.
# Requires grpcurl to be installed (https://github.com/fullstorydev/grpcurl).

set -euo pipefail

LOOM_ADDR="localhost:9999"
BACKEND_ADDR="localhost:50051"

echo ""
echo "  🧵 Loom Smoke Test"
echo "  ─────────────────────────────────────────"
echo ""

if ! command -v grpcurl &>/dev/null; then
  echo "  ✗ grpcurl not found. Install from https://github.com/fullstorydev/grpcurl"
  exit 1
fi

# Build if needed
if [[ ! -f bin/loom || ! -f bin/testserver ]]; then
  echo "  Building..."
  go build -o bin/loom . && go build -o bin/testserver ./testserver
fi

# Start testserver
echo "  Starting testserver on $BACKEND_ADDR..."
./bin/testserver -addr "$BACKEND_ADDR" &
BACKEND_PID=$!

# Start Loom
echo "  Starting Loom on $LOOM_ADDR..."
./bin/loom -backend "$BACKEND_ADDR" -listen "$LOOM_ADDR" &
LOOM_PID=$!

cleanup() {
  echo ""
  echo "  Cleaning up..."
  kill "$BACKEND_PID" "$LOOM_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1
echo ""
echo "  ─── Test 1: GetUser (OK) ───────────────"
grpcurl -plaintext -d '{"userId":"abc123"}' "$LOOM_ADDR" user.UserService/GetUser

echo ""
echo "  ─── Test 2: GetUser (NOT_FOUND) ─────────"
grpcurl -plaintext -d '{"userId":"notfound"}' "$LOOM_ADDR" user.UserService/GetUser || true

echo ""
echo "  ─── Test 3: CreateUser ──────────────────"
grpcurl -plaintext -d '{"name":"Grace Hopper","email":"grace@example.com"}' \
  "$LOOM_ADDR" user.UserService/CreateUser

echo ""
echo "  ─── Test 4: List services via reflection ─"
grpcurl -plaintext "$LOOM_ADDR" list

echo ""
echo "  ✓ Smoke test complete. Check Loom output above for decoded JSON!"
echo ""
