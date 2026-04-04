# Loom — gRPC L7 Debugging Proxy
# ─────────────────────────────────────────────────────────────────────────────

BINARY     := bin/loom
TESTSERVER := bin/testserver
VERSION    ?= dev
LDFLAGS    := -s -w -X main.Version=$(VERSION)

.PHONY: all build build-testserver run-demo test test-race smoke clean tidy help

all: build build-testserver ## Build loom and testserver binaries

## ── Build ────────────────────────────────────────────────────────────────────

build: ## Build the loom binary → bin/loom
	@mkdir -p bin
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .
	@echo "  ✓ $(BINARY)"

build-testserver: ## Build the test gRPC backend → bin/testserver
	@mkdir -p bin
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(TESTSERVER) ./testserver
	@echo "  ✓ $(TESTSERVER)"

## ── Run ─────────────────────────────────────────────────────────────────────

run-demo: build ## Start loom in demo mode (no backend needed)
	./$(BINARY) -demo

run: build build-testserver ## Start testserver + loom proxy
	@echo "Starting testserver on :50051 and loom on :9999 (UI :9998)..."
	@./$(TESTSERVER) &
	@sleep 0.5
	./$(BINARY) -backend localhost:50051 -listen :9999 -ui :9998

## ── Test ─────────────────────────────────────────────────────────────────────

test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with race detector
	go test -race ./...

test-verbose: ## Run unit tests with verbose output
	go test -v ./...

## ── Smoke test ───────────────────────────────────────────────────────────────

smoke: build build-testserver ## End-to-end smoke test (requires grpcurl)
	@command -v grpcurl >/dev/null 2>&1 || { echo "grpcurl not found — install from https://github.com/fullstorydev/grpcurl/releases"; exit 1; }
	@bash scripts/smoke_test.sh

## ── Docker ───────────────────────────────────────────────────────────────────

docker-build: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) -t loom:$(VERSION) .

docker-demo: docker-build ## Run Docker image in demo mode
	docker run --rm -p 9999:9999 -p 9998:9998 loom:$(VERSION) -demo

docker-compose-demo: ## Start demo stack with docker compose
	docker compose --profile demo up

docker-compose-test: ## Start testserver + loom with docker compose
	docker compose --profile test up

## ── Maintenance ──────────────────────────────────────────────────────────────

tidy: ## Run go mod tidy
	go mod tidy

clean: ## Remove build artifacts
	rm -rf bin/

fmt: ## Run gofmt
	gofmt -l -w .

vet: ## Run go vet
	go vet ./...

lint: ## Run staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
	staticcheck ./...

## ── Help ─────────────────────────────────────────────────────────────────────

help: ## Show this help
	@echo "Loom — gRPC L7 Debugging Proxy"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
