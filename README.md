# Loom

A gRPC debugging proxy. Point it at your backend, point your client at Loom, and watch every call decoded in a browser tab.

```
Your gRPC Client  →  Loom (:9999)  →  Your Backend (:50051)
                          ↓
                    Web Inspector
                  http://localhost:9998
```

[![CI](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml/badge.svg)](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml)
[![Release](https://github.com/joshuabvarghese/loom/actions/workflows/release.yml/badge.svg)](https://github.com/joshuabvarghese/loom/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENCE)

---

## Why

gRPC traffic is binary. Wireshark can't read it. `grpcurl` is great for one-off calls but you can't watch a flow. I kept running it over and over trying to understand what was happening between services.

Loom sits transparently between your client and backend. It uses [Server Reflection](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md) to decode every frame on the fly — no `.proto` files required — and streams the results into a browser UI. You see the JSON payloads, the status codes, how long each call took, and a ready-to-copy `grpcurl` command to replay any of them.

## What it does

- Intercepts **all four gRPC stream types** — unary, server-streaming, client-streaming, bidi
- **Auto-decodes** using Server Reflection (no proto files, no codegen step)
- **Web Inspector** with a live call feed, JSON pretty-printing, and one-click grpcurl replay
- **Session history** — calls saved to `~/.loom/sessions/` and reloaded on next start
- **Mutation rules** — JSON file to inject/override/delete fields in requests or responses on the fly
- **Circuit breaker** — surfaces backend failures cleanly instead of hanging
- **Prometheus metrics** at `/metrics`, health probes at `/live` and `/ready`
- **Single binary** — no config needed to get started

---

## Quick start

You need **Go 1.21+**. That's it.

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom
./scripts/setup.sh
```

Or skip setup and run directly:

```bash
go run -mod=vendor . -demo
# open http://localhost:9998
```

### Proxying your own service

```bash
# Terminal 1 — your backend (or the included test server)
./bin/testserver

# Terminal 2 — Loom
./bin/loom -backend localhost:50051

# Terminal 3 — make a call through Loom
grpcurl -plaintext -d '{"userId":"abc123"}' localhost:9999 user.UserService/GetUser
```

Then open **http://localhost:9998**. You'll see the call decoded, the request and response as JSON, latency, and a grpcurl command to replay it.

---

## Flags

```
Connection:
  -backend                  localhost:50051   gRPC backend address
  -listen                   :9999             Proxy listen address
  -backend-tls                                Connect to backend with TLS
  -backend-tls-skip-verify                    Skip TLS cert verification

Output:
  -ui                       :9998             Web Inspector address (empty to disable)
  -session                  default           Session name (affects history file)
  -log                      ""                Write calls to an NDJSON file too
  -verbose                                    Debug logging
  -no-color                                   Disable color output

Mutation:
  -mutate                   ""                Path to a JSON mutation rules file

Protocol:
  -proto-dir                ""                .proto directory (fallback when reflection is off)

Modes:
  -demo                                       Embedded backend + sample traffic (no setup needed)
  -replay                   ""                Replay an NDJSON log file then exit
  -version                                    Print version and exit
```

Config file works too — see [`loom.toml`](loom.toml) for the full list.

---

## Mutation rules

Create a `rules.json` to modify traffic on the fly without touching your code:

```json
[
  {
    "method": "/user.UserService/*",
    "direction": "request",
    "headers": {
      "set": { "authorization": "Bearer test-token" }
    }
  },
  {
    "method": "/user.UserService/GetUser",
    "direction": "response",
    "set": { "user.role": "\"ROLE_ADMIN\"" },
    "delete": ["user.createdAt"]
  }
]
```

```bash
./bin/loom -backend localhost:50051 -mutate rules.json
```

Rules match on exact method paths or globs (`/pkg.Service/*`). Body and header rules can be mixed freely.

---

## Session replay

Every call is appended to `~/.loom/sessions/<name>.jsonl`. On restart, Loom reads it back and populates the history.

```bash
# Save calls under a named session
./bin/loom -backend localhost:50051 -session staging

# Replay against a different backend later
./bin/loom -replay ~/.loom/sessions/staging.jsonl -backend localhost:50052
```

You can also hit **Replay** in the Web Inspector to resend any individual call.

---

## Make targets

```
make build            build bin/loom
make build-testserver build bin/testserver
make run-demo         build + start in demo mode
make run              build + start testserver and loom together
make test             run unit tests
make test-race        run with race detector
make smoke            end-to-end grpcurl test (requires grpcurl)
make fmt              gofmt
make vet              go vet
make vendor           regenerate vendor/
make clean            remove bin/
```

---

## Project layout

```
loom/
├── main.go                    Entry point — flags, config loading, startup sequence
├── proxy/
│   ├── proxy.go               HTTP/2 reverse proxy (unary + all streaming modes)
│   └── proxy_integration_test.go
├── internal/
│   ├── circuitbreaker/        Open/half-open/closed state machine
│   ├── config/                TOML + flag config merging
│   ├── health/                /live and /ready handlers
│   ├── metadata/              Header mutation (add/set/delete)
│   ├── metrics/               Prometheus counters and histograms
│   ├── mutator/               JSON body mutation engine
│   ├── recorder/              Ring buffer + SSE hub + NDJSON writer
│   ├── reflector/             Server Reflection client with method caching
│   ├── slog/                  Structured JSON logging helpers
│   ├── store/                 Session file persistence
│   ├── transcoder/            gRPC wire format ↔ JSON
│   └── webui/                 Embedded HTTP server + single-page inspector
├── demo/                      Embedded demo backend (-demo flag)
├── testserver/                Standalone test gRPC server + generated protos
├── scripts/
│   ├── setup.sh               Build from source
│   └── smoke_test.sh          End-to-end grpcurl smoke test
├── loom.toml                  Example config file
└── Dockerfile
```

---

## Security

This is a **dev/debugging tool**. Don't expose it on a public network.

The Web Inspector has no auth — keep the `-ui` port bound to localhost. See [SECURITY.md](SECURITY.md).

---

## Contributing

PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENCE) © 2026 Joshua Varghese
