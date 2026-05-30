# Security

## Supported versions

| Version | Maintained |
|---------|-----------|
| 0.1.x   | ✅         |

## Reporting a vulnerability

Please don't open a public issue for security bugs.

Email **joshuavarghese.jv@gmail.com** with:

- What the vulnerability is
- Steps to reproduce
- What you think the impact is
- A suggested fix if you have one

I'll reply within 48 hours and aim to have a fix out within a week.

## Security model

Loom is a local development tool. It's not designed to be hardened for production.

A few things to be aware of:

**No authentication.** The Web Inspector and the proxy port have no auth. Bind them to `localhost` — the defaults do this. If you're running on a shared machine or in a container, be explicit: `-listen 127.0.0.1:9999 -ui 127.0.0.1:9998`.

**Mutation rules can modify payloads.** The `-mutate` flag applies rules to requests and responses. Keep rule files out of version control if they contain real credentials.

**Client-to-Loom is plaintext H2C.** When you use `-backend-tls`, Loom connects to your backend over TLS, but the client-to-Loom leg is unencrypted HTTP/2. That's fine on localhost. Don't put Loom in a production traffic path.

**Call history is written to disk.** Sessions go to `~/.loom/sessions/`. If you're proxying services that handle sensitive data, be aware the payloads are stored there in plaintext NDJSON.
