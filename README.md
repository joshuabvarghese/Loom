# Loom — gRPC Debugging Proxy

[![Go Version](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENCE)

Loom sits between your gRPC client and server, decodes every message in real-time, and shows it in a web UI — so you can see exactly what's happening without changing a line of application code.

```
Your gRPC Client  →  Loom (:9999)  →  Your Backend (:50051)
                          ↓
                    Web Inspector
                  http://localhost:9998
```

> **Status: early development.** Core proxy, Web Inspector, session persistence, and mutation rules work. Streaming RPCs, the admin/metrics server, and structured logging are not yet implemented.

---

## What works right now

- **Intercept & decode** — proxies any unary gRPC call and decodes request/response using Server Reflection (no proto files needed)
- **Web Inspector** — live call stream in the browser with request/response JSON viewer and one-click `grpcurl` copy
- **Session persistence** — call history saved to `~/.loom/sessions/` and restored on restart
- **Body mutation** — inject, override, or strip JSON fields on any request or response via a rules file
- **Header mutation** — set, add, or delete gRPC metadata per rule
- **Replay** — re-send any recorded call from the UI or with `-replay`
- **TLS** — proxy to TLS-enabled backends with `-backend-tls`
- **Demo mode** — `loom -demo` spins up an embedded backend with sample traffic, no setup needed
- **Single binary** — no runtime, no dependencies

## What's not done yet

- Streaming RPCs (server, client, bidi) — currently treated as unary
- Admin server (`/healthz`, `/readyz`, `/metrics`, `/debug/pprof`)
- Structured JSON logging (`-log-format json`)
- Pre-built releases (Homebrew, `go install`, Docker image)

---

## Getting started

**Requirements:** Go 1.21+

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom
go mod tidy
./scripts/setup.sh
```

That builds `bin/loom` and `bin/testserver`.

### Try demo mode (no backend needed)

```bash
./bin/loom -demo
# Open http://localhost:9998
```

Loom starts an embedded gRPC server, sends some sample calls through itself, and you can explore the Web Inspector immediately.

### Proxy your own service

```bash
# Terminal 1 — your backend (or use the included testserver)
./bin/testserver

# Terminal 2 — start Loom
./bin/loom -backend localhost:50051

# Terminal 3 — make a call through Loom
grpcurl -plaintext -d '{"userId":"abc123"}' localhost:9999 user.UserService/GetUser
```

Open **http://localhost:9998** to see the decoded call.

---

## Flags

```
Connection:
  -backend        localhost:50051   Backend gRPC server address
  -listen         :9999            Proxy listen address (point your client here)
  -backend-tls                     Connect to backend with TLS
  -backend-tls-skip-verify         Skip TLS certificate verification (insecure)

Output:
  -ui             :9998            Web Inspector address (empty = disabled)
  -session        default          Session name — history saved to ~/.loom/sessions/<name>.jsonl
  -log            ""               Also write calls to an NDJSON file
  -verbose                         Print extra debug info
  -no-color                        Disable ANSI colour output

Mutation:
  -mutate         ""               Path to a JSON mutation rules file

Protocol:
  -proto-dir      ""               Directory of .proto files (fallback if reflection is disabled)

Modes:
  -demo                            Start with embedded backend + sample traffic
  -replay         ""               Replay an NDJSON log file then exit

Info:
  -version                         Print version and exit
```

---

## Mutation rules

Create a `rules.json` to modify traffic on the fly:

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
./bin/loom -backend localhost:50051 -mutate rules.json
```

Rules support exact method paths and globs (`/pkg.Service/*`). Body and header rules can live in the same file.

---

## Session persistence

Calls are saved to `~/.loom/sessions/<name>.jsonl` and reloaded on next start:

```bash
./bin/loom -backend localhost:50051 -session staging
```

Override the directory: `LOOM_DATA_DIR=/tmp/loom ./bin/loom -demo`

---

## Replay

```bash
# Replay a whole session file against a backend
./bin/loom -replay ~/.loom/sessions/staging.jsonl -backend localhost:50051

# Or click Replay in the Web Inspector to replay individual calls
```

---

## Make targets

```
make build            build bin/loom
make build-testserver build bin/testserver
make run-demo         build + start in demo mode
make run              build + start testserver and loom together
make test             run unit tests
make test-race        run with race detector
make clean            remove bin/
make help             list all targets
```

---

## Security

Loom is for **local development and trusted networks only**.

- The Web Inspector has no authentication — keep `-ui` bound to localhost
- Don't expose Loom's ports to the public internet
- See [SECURITY.md](SECURITY.md) for the full policy

---

## License

[MIT](LICENCE) © 2026 Joshua Varghese
