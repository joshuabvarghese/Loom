# Loom — gRPC L7 Debugging Proxy

[![CI](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml/badge.svg)](https://github.com/joshuabvarghese/loom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/joshuabvarghese/loom)](https://github.com/joshuabvarghese/loom/releases/latest)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/joshuabvarghese/loom)](https://goreportcard.com/report/github.com/joshuabvarghese/loom)

Loom sits between your gRPC client and server, decodes every message in real-time, and streams it to a Web Inspector — so you can see exactly what's happening without changing a line of application code.

```
Your gRPC Client  →  Loom (:9999)  →  Your Backend (:50051)
                          ↓
                    Web Inspector
                   http://localhost:9998
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
docker run --rm -p 9999:9999 -p 9998:9998 ghcr.io/joshuabvarghese/loom:latest -demo

# Proxy to a local backend
docker run --rm -p 9999:9999 -p 9998:9998 \
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
# Terminal 1 — your backend (example)
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

Output:
  -ui                  :9998             Web Inspector address (empty = disabled)
  -session             default           Session name (persisted to ~/.loom/sessions/)
  -log                 ""                Also write calls to an NDJSON file
  -verbose                               Print extra debug information
  -no-color                              Disable ANSI color output

Mutation:
  -mutate              ""                Path to JSON mutation rules file

Protocol:
  -proto-dir           ""                Directory of .proto files (fallback without reflection)

Modes:
  -demo                                  Start with embedded backend + sample traffic
  -replay              ""                Replay an NDJSON log file then exit

Info:
  -version                               Print version and exit
```

---

## Mutation Rules

Create a `rules.json` file to modify gRPC traffic on the fly — no code changes needed:

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

Calls are saved to `~/.loom/sessions/<name>.jsonl` and loaded on next start:

```bash
loom -backend localhost:50051 -session staging
# After restart, browse the previous session in the Web Inspector
```

---

## Replay

Re-send recorded calls from a session file or a NDJSON log:

```bash
loom -replay ~/.loom/sessions/staging.jsonl -backend localhost:50051
```

Or click **Replay** in the Web Inspector to replay individual calls through the running proxy.

---

## Kubernetes Sidecar

Inject Loom as a sidecar in your pod to inspect in-cluster traffic:

```yaml
containers:
  - name: loom
    image: ghcr.io/joshuabvarghese/loom:latest
    args:
      - "-backend"
      - "localhost:50051"    # your app's gRPC port
      - "-listen"
      - ":9999"
      - "-ui"
      - ":9998"
    ports:
      - containerPort: 9999   # clients connect here
      - containerPort: 9998   # port-forward this to view the inspector
```

```bash
kubectl port-forward pod/my-pod 9998:9998
# Open: http://localhost:9998
```

---

## Build from Source

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom
make build       # → bin/loom
make test        # run unit tests
make run-demo    # start in demo mode
```

---

## Security

Loom is designed for **local development and trusted networks only**.

- The Web Inspector has **no authentication** — bind `-ui` to `localhost` only
- Do not expose Loom's ports to the public internet
- See [SECURITY.md](SECURITY.md) for the full policy

---

## License

[MIT](LICENSE) © 2026 Joshua Varghese
