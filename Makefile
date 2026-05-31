# Loom — gRPC L7 Debugging Proxy
# Works with both BSD make (macOS default) and GNU make.

BINARY     = bin/loom
TESTSERVER = bin/testserver
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    = -s -w -X main.Version=$(VERSION)
GOFLAGS    =

all: build build-testserver

build:
	mkdir -p bin
	go build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .
	@echo "  ✓ $(BINARY)"

build-testserver:
	mkdir -p bin
	go build $(GOFLAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(TESTSERVER) ./testserver
	@echo "  ✓ $(TESTSERVER)"

run-demo: build
	./$(BINARY) -demo

run: build build-testserver
	@echo "Starting testserver on :50051..."
	./$(TESTSERVER) &
	@sleep 0.5
	./$(BINARY) -backend localhost:50051 -listen :9999 -ui :9998

test:
	go test $(GOFLAGS) ./...

test-race:
	go test $(GOFLAGS) -race ./...

test-verbose:
	go test $(GOFLAGS) -v ./...

smoke: build build-testserver
	bash scripts/smoke_test.sh

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t loom:$(VERSION) .

docker-demo: docker-build
	docker run --rm -p 9999:9999 -p 9998:9998 loom:$(VERSION) -demo

tidy:
	go mod tidy

vendor: ## (optional) create a local vendor/ directory
	go mod tidy
	go mod vendor

clean:
	rm -rf bin/

fmt:
	gofmt -l -w .

vet:
	go vet $(GOFLAGS) ./...

help:
	@echo ""
	@echo "  Loom — gRPC L7 Debugging Proxy"
	@echo ""
	@echo "  make build            build bin/loom"
	@echo "  make build-testserver build bin/testserver"
	@echo "  make run-demo         build + start in demo mode"
	@echo "  make run              build + start testserver + loom"
	@echo "  make test             run unit tests"
	@echo "  make test-race        run with race detector"
	@echo "  make smoke            end-to-end smoke test (needs grpcurl)"
	@echo "  make vendor           go mod vendor (regenerate vendor/)"
	@echo "  make tidy             go mod tidy"
	@echo "  make clean            remove bin/"
	@echo "  make fmt              gofmt"
	@echo "  make vet              go vet"
	@echo ""

.PHONY: all build build-testserver run-demo run test test-race test-verbose smoke docker-build docker-demo vendor tidy clean fmt vet help
