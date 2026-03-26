# Contributing to Loom

Thank you for considering a contribution! Loom is a small, focused tool and we value quality over quantity.

## Getting Started

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom
make build          # build loom + testserver
make test           # run the full test suite
make run-dev        # start testserver + loom with -demo
```

## Project Layout

```
loom/
├── main.go                    # CLI flags, startup, replay mode
├── proxy/handler.go           # HTTP/2 reverse proxy (unary + streaming)
├── internal/
│   ├── recorder/              # Ring buffer, SSE hub, NDJSON log
│   ├── store/                 # Persistent session storage (~/.loom/)
│   ├── reflector/             # gRPC Server Reflection client + cache
│   ├── transcoder/            # gRPC wire format ↔ JSON
│   ├── mutator/               # Rule-based JSON body mutation
│   ├── metadata/              # Rule-based gRPC header mutation
│   └── webui/                 # Embedded HTTP server + single-file SPA
├── demo/                      # Embedded demo backend (-demo mode)
└── testserver/                # Standalone test gRPC server
```

## Development Guidelines

### Code Style

- Run `make fmt` before committing (`gofmt -w .`)
- Run `make vet` to catch common errors
- Run `make lint` for full linting (requires `golangci-lint`)
- Every exported function should have a doc comment

### Testing

- All new functionality must have unit tests
- Tests go in `_test.go` files in the same package (use `package foo_test` for black-box tests)
- Run with the race detector: `make test-race`
- Aim to keep coverage above 70% per package

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add -max-calls flag to cap ring buffer size
fix: nil pointer in handleStreaming when reflector is off
docs: add mutation rules example for auth injection
test: add TestStore_AppendsDontDuplicate
```

This drives the automated changelog in GoReleaser.

### Pull Requests

1. Fork the repo and create a branch: `git checkout -b feat/my-feature`
2. Make your changes with tests
3. Run `make test fmt vet` — all must pass
4. Open a PR against `main` with a clear description

### What We're Looking For

Great ideas for contributions:
- **New mutation capabilities** — e.g., delay injection, response stubbing
- **UI improvements** — filtering, syntax highlighting, diff view
- **Protocol support** — gRPC-Web, Connect protocol
- **Performance** — the proxy hot path must stay allocation-light

Things we'll decline:
- Breaking the single-binary distribution model
- Adding mandatory external dependencies at runtime
- Features that belong in a service mesh, not a dev tool

## Running the Full Dev Setup

```bash
# Terminal 1
make run-testserver   # starts gRPC backend on :50051

# Terminal 2  
make run              # starts loom on :9999, UI on :9998

# Terminal 3
make smoke            # end-to-end grpcurl test (requires grpcurl)
```

Or use demo mode (no external server needed):
```bash
make run-demo
```

## Release Process (maintainers only)

```bash
git tag v0.2.0
git push origin v0.2.0
# GitHub Actions picks up the tag and runs GoReleaser
```
