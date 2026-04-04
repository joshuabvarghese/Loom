# Loom — gRPC L7 Debugging Proxy

[![CI](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml/badge.svg)](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/joshuabvarghese/loom)](https://github.com/joshuabvarghese/loom/releases/latest)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/joshuabvarghese/loom)](https://goreportcard.com/report/github.com/joshuabvarghese/loom)

Loom sits between your gRPC client and server, decodes every message in real-time, and streams it to a Web Inspector — so you can see exactly what's happening without changing a line of application code.

```
Your gRPC Client  →  Loom (:9999)  →  Your Backend (:50051)
                          ↓
                    Web Inspector        Admin Server
                   http://localhost:9998  :9997
                                         /healthz  /readyz
                                         /metrics  /debug/pprof
```

---

## Features

- **Zero-config inspection** — point Loom at your backend, change your client's port, done
- **Live JSON decode** — uses gRPC Server Reflection; shows field names, not binary blobs
- **Web Inspector** — real-time call stream, request/response viewer, one-click `grpcurl` copy
- **Session persistence** — call history survives restarts; browse past sessions by name
- **Body mutation** — inject, override, or strip JSON fields on any request or response
- **Header mutation** — set, add, or delete gRPC metadata per rule
- **Proto fallback** — works even when reflection is disabled on the backend (`-proto-dir`)
- **Replay** — re-send any recorded call with one click (UI) or `loom -replay calls.ndjson`
- **TLS** — proxy to TLS-enabled backends with `-backend-tls`
- **Demo mode** — `loom -demo` spins up an embedded backend instantly — no setup needed
- **Single static binary** — no runtime, no dependencies, works on macOS / Linux / Windows
- **Prometheus metrics** — request rate, error rate, p50/p95/p99 latency, and more at `/metrics`
- **Health probes** — `/healthz` and `/readyz` for Kubernetes liveness and readiness checks
- **Structured logging** — JSON-formatted logs for aggregation pipelines (`-log-format json`)
- **pprof** — CPU and heap profiling at `/debug/pprof` on the admin port
- **Kubernetes-ready** — sidecar manifest with probes, PDB, NetworkPolicy, and HPA in `deploy/`

---

## Install

### Homebrew (macOS / Linux) — recommended

```bash
brew install joshuabvarghese/tap/loom
```

### go install

```bash
go install github.com/joshuabvarghese/loom@latest
```

### Direct download

```bash
# macOS Apple Silicon
curl -L https://github.com/joshuabvarghese/loom/releases/latest/download/loom_darwin_arm64.tar.gz | tar xz
sudo mv loom /usr/local/bin/

# macOS Intel
curl -L https://github.com/joshuabvarghese/loom/releases/latest/download/loom_darwin_amd64.tar.gz | tar xz
sudo mv loom /usr/local/bin/

# Linux amd64
curl -L https://github.com/joshuabvarghese/loom/releases/latest/download/loom_linux_amd64.tar.gz | tar xz
sudo mv loom /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/joshuabvarghese/loom/releases/latest/download/loom_windows_amd64.zip" -OutFile loom.zip
Expand-Archive loom.zip -DestinationPath .
```

### Docker

```bash
# Demo mode — no backend needed
docker run --rm -p 9999:9999 -p 9998:9998 -p 9997:9997 ghcr.io/joshuabvarghese/loom:latest -demo

# Proxy to a local backend
docker run --rm -p 9999:9999 -p 9998:9998 -p 9997:9997 \
  ghcr.io/joshuabvarghese/loom:latest \
  -backend host.docker.internal:50051
```

---

## Quick Start

### 1 — Try it instantly with demo mode

```bash
loom -demo
# Open: http://localhost:9998
```

No backend required. Loom starts an embedded gRPC server and sends sample traffic so you can explore the Web Inspector right away.

### 2 — Proxy your own service

```bash
# Terminal 1 — your backend
./your-service --port 50051

# Terminal 2 — start Loom
loom -backend localhost:50051 -listen :9999 -ui :9998

# Terminal 3 — point your client at Loom instead of the backend
grpcurl -plaintext -d '{"userId":"abc"}' localhost:9999 user.UserService/GetUser
```

Open **http://localhost:9998** to see the decoded request and response.

---

## All Flags

```
loom [flags]

Connection:
  -backend             localhost:50051    Backend gRPC server address
  -listen              :9999             Proxy listen address (point clients here)
  -backend-tls                           Connect to backend with TLS
  -backend-tls-skip-verify               Skip TLS certificate verification (insecure)
  -dial-timeout        10s               Connection timeout to the backend
  -max-call-size-mb    32                Max gRPC message size in MB (send + receive)

Output:
  -ui                  :9998             Web Inspector address (empty = disabled)
  -session             default           Session name (persisted to ~/.loom/sessions/)
  -log                 ""                Also write calls to an NDJSON file
  -log-format          text              Structured log format: text or json
  -verbose                               Print extra debug information
  -no-color                              Disable ANSI color output

Observability:
  -admin               :9997             Admin server address (empty = disabled)
                                          Exposes: /healthz /readyz /livez
                                                   /metrics (Prometheus)
                                                   /debug/pprof

Mutation:
  -mutate              ""                Path to JSON mutation rules file

Protocol:
  -proto-dir           ""                Directory of .proto files (fallback without reflection)

Lifecycle:
  -shutdown-timeout    15s               How long to wait for in-flight RPCs on shutdown

Modes:
  -demo                                  Start with embedded backend + sample traffic
  -replay              ""                Replay an NDJSON log file then exit

Info:
  -version                               Print version and exit
```

---

## Observability

### Prometheus metrics

Loom exposes Prometheus metrics at `GET /metrics` on the admin port (`:9997` by default). All metrics are on a private registry — they will not appear on any existing `/metrics` endpoint if you embed Loom.

| Metric | Type | Description |
|--------|------|-------------|
| `loom_calls_total` | Counter | Total RPCs by method, stream kind, status code |
| `loom_call_duration_seconds` | Histogram | End-to-end latency by method and stream kind |
| `loom_mutations_total` | Counter | Mutated frames by method and direction |
| `loom_reflection_errors_total` | Counter | Server reflection lookup failures |
| `loom_sse_active_clients` | Gauge | Browser tabs connected to the inspector |
| `loom_recorded_calls_total` | Counter | Total calls written to session store |
| `loom_storage_write_errors_total` | Counter | Session file write failures |
| `loom_build_info` | Gauge | Build metadata (version, Go version) |

### Grafana dashboard

Import `deploy/grafana/dashboard.json` into Grafana for a pre-built dashboard with request rate, error rate, latency percentiles, and build info panels.

### Alerting

Import `deploy/grafana/alerts.yaml` into Prometheus for four ready-to-use alerts:
- `LoomHighGRPCErrorRate` — >5% error rate (warning), >20% (critical)
- `LoomHighP99Latency` — p99 exceeds 5 seconds
- `LoomStorageWriteErrors` — any session write failure
- `LoomDown` — no metrics scraped in the last minute

### Health probes

```bash
# Liveness — is the process alive?
curl http://localhost:9997/healthz

# Readiness — is the backend connected and accepting traffic?
curl http://localhost:9997/readyz
```

Both endpoints return JSON:
```json
{ "status": "ok", "uptime": "2m30s", "version": "v0.2.0" }
```

### pprof

```bash
# Port-forward the admin port in Kubernetes
kubectl port-forward pod/<n> 9997:9997

# 30-second CPU profile
go tool pprof http://localhost:9997/debug/pprof/profile?seconds=30

# Heap snapshot
go tool pprof http://localhost:9997/debug/pprof/heap
```

---

## Mutation Rules

Create a `rules.json` file to modify gRPC traffic on the fly:

```json
[
  {
    "method": "/user.UserService/*",
    "direction": "request",
    "headers": {
      "set": { "authorization": "Bearer expired-token-for-testing" }
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
loom -backend localhost:50051 -mutate rules.json
```

Rules support exact method paths and globs (`/pkg.Service/*`). A single file can contain both body and header rules.

---

## Session Persistence

Calls are saved to `~/.loom/sessions/<n>.jsonl` and loaded on next start:

```bash
loom -backend localhost:50051 -session staging
# After restart, history is automatically restored in the Web Inspector
```

Override the storage directory: `LOOM_DATA_DIR=/tmp/loom loom -demo`

---

## Replay

```bash
# Replay an entire session file
loom -replay ~/.loom/sessions/staging.jsonl -backend localhost:50051

# Or click Replay in the Web Inspector to replay individual calls
```

---

## Kubernetes Sidecar

```bash
kubectl apply -f deploy/kubernetes/sidecar.yaml

# Port-forward the inspector
kubectl port-forward deployment/my-service 9998:9998

# Open http://localhost:9998
```

The manifest includes liveness/readiness probes, a PodDisruptionBudget, NetworkPolicy, and HPA. See [`deploy/kubernetes/README.md`](deploy/kubernetes/README.md) for full instructions.

---

## Structured Logging

For production deployments, use JSON log output to integrate with Loki, Datadog, Splunk, or any other log aggregation system:

```bash
loom -backend localhost:50051 -log-format json 2>&1 | your-log-shipper
```

Example JSON log line:
```json
{"time":"2026-03-21T14:23:01Z","level":"INFO","msg":"grpc call",
 "method":"/user.UserService/GetUser","status_code":"0",
 "stream_kind":"unary","duration_ms":"12.40","mutated":false,
 "call_id":"1742566981234567890"}
```

---

## Build from Source

**Requirements:** Go 1.22+. No other runtime dependencies — Loom compiles to a single static binary.

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom

# First time: fetch all dependencies
go mod tidy

# Then build
make build            # → bin/loom
make build-testserver # → bin/testserver (optional local gRPC backend)

# Or use the all-in-one setup script
chmod +x scripts/setup.sh && ./scripts/setup.sh
```

### Common make targets

```
make run-demo    # build + start immediately in demo mode (no backend needed)
make run         # build + launch testserver AND loom together
make test        # run unit tests
make test-race   # run with race detector
make smoke       # end-to-end smoke test (requires grpcurl)
make help        # list all available targets
```

---

## Security

Loom is designed for **local development and trusted networks only**.

- The Web Inspector has **no authentication** — bind `-ui` to `localhost` only
- The admin server (`-admin`) exposes pprof — bind to `localhost` or use NetworkPolicy
- Do not expose Loom's ports to the public internet
- See [SECURITY.md](SECURITY.md) for the full policy

---

## License

[MIT](LICENSE) © 2026 Joshua Varghese
