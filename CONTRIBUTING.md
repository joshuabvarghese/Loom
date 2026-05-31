# Contributing

Thanks for taking a look. Loom is a small tool — I try to keep the scope tight, but good PRs are always welcome.

## Getting started

```bash
git clone https://github.com/joshuabvarghese/loom
cd loom
make build        # builds bin/loom and bin/testserver
make test         # run the full test suite
make run-demo     # start in demo mode, open http://localhost:9998
```

For the full dev loop with a live backend:

```bash
# Terminal 1
make run-testserver   # gRPC backend on :50051

# Terminal 2
make run              # loom on :9999, UI on :9998

# Terminal 3
make smoke            # end-to-end grpcurl test (needs grpcurl installed)
```

## Code style

- `make fmt` before committing (`gofmt -w .`)
- `make vet` to catch obvious issues
- Exported types and functions need doc comments
- Keep the proxy hot path allocation-light — no per-request heap allocations in the frame read/write loops

## Tests

- New behavior needs a test
- Black-box tests go in `package foo_test`, internal ones in `package foo`
- Run with the race detector before opening a PR: `make test-race`
- The integration tests in `proxy/proxy_integration_test.go` spin up a real gRPC server and proxy — use those as a pattern for end-to-end coverage

## Commits

I use [Conventional Commits](https://www.conventionalcommits.org/) loosely:

```
feat: add -max-calls flag to cap ring buffer size
fix: nil deref in serveStreaming when reflector is disabled
docs: document mutation rule glob syntax
test: add round-trip test for bidi streaming with mutations
```

## Pull requests

1. Fork, branch off `main`: `git checkout -b fix/my-thing`
2. Make the change, add tests
3. `make test fmt vet` — all must pass
4. Open a PR with a short description of what and why

## What I'm interested in

- Mutation features — delay injection, response stubbing, conditional rules
- UI improvements — call filtering, diff view between replays, syntax highlighting
- gRPC-Web / Connect protocol support
- Performance improvements to the proxy hot path

## What I'll probably decline

- Anything that breaks the single-binary distribution
- Runtime dependencies that need to be installed separately
- Features that belong in a service mesh rather than a local dev tool
