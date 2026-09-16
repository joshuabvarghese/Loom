# Dockerfile for Loom — gRPC L7 Debugging Proxy
#
# Build:
#   docker build -t loom .
#   docker build --build-arg VERSION=v0.1.0 -t loom:v0.1.0 .
#
# Run (proxy mode):
#   docker run --rm -p 9999:9999 -p 9998:9998 \
#     loom -backend host.docker.internal:50051
#
# Run (demo mode — no backend needed):
#   docker run --rm -p 9999:9999 -p 9998:9998 loom -demo
#
# Kubernetes sidecar example:
#   containers:
#     - name: loom
#       image: ghcr.io/joshuabvarghese/loom:latest
#       args: ["-backend", "localhost:50051", "-listen", ":9999", "-ui", ":9998"]
#       ports:
#         - containerPort: 9999  # gRPC proxy
#         - containerPort: 9998  # Web Inspector

# ── Stage 1: Build frontend ──────────────────────────────────────────────────
FROM node:22-alpine AS frontend

WORKDIR /build/webui
COPY webui/package.json webui/package-lock.json* ./
RUN npm ci

COPY webui/ ./
RUN npm run build
# Vite's outDir (../internal/webui/dist) lands at /build/internal/webui/dist

# ── Stage 2: Build backend ───────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

ARG VERSION=dev
WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source, pull in the compiled frontend, then build a fully static binary
COPY . .
COPY --from=frontend /build/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o loom .

# ── Stage 3: Minimal runtime image ───────────────────────────────────────────
FROM scratch

# CA certificates for TLS backend connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Binary
COPY --from=builder /build/loom /loom

# Example mutation rules
COPY --from=builder /build/examples /examples

# gRPC proxy port
EXPOSE 9999
# Web Inspector port
EXPOSE 9998

ENTRYPOINT ["/loom"]
CMD ["-listen", ":9999", "-ui", ":9998", "-backend", "localhost:50051"]
