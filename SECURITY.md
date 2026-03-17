# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email **joshuavarghese.jv@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You can expect an initial response within **48 hours** and a full assessment within **7 days**.

## Security Model

Loom is a **local development tool** designed to run on a developer's machine or in a trusted network environment. Key points:

- **Not designed for production exposure** — Loom's proxy and Web Inspector ports should not be exposed to the public internet.
- **No authentication** — The Web Inspector (`-ui` port) has no authentication. Bind it to `localhost` only.
- **Mutation rules** (`-mutate`) can modify gRPC payloads. Keep rule files access-controlled.
- **TLS passthrough** — When using `-backend-tls`, Loom connects to the backend using TLS but the client-to-Loom leg is plaintext H2C. Do not use Loom as a TLS terminator in production.

## Dependency Scanning

Dependencies are pinned in `go.sum` and verified with `go mod verify`. Dependabot is enabled to flag known CVEs in transitive dependencies.
