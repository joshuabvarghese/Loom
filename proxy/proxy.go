// Package proxy implements the gRPC L7 reverse proxy at the heart of Loom.
//
// It accepts any gRPC call (identified by its HTTP/2 :path header), forwards
// it to the configured backend, and records the decoded request/response for
// the Web Inspector.
//
// New in this version:
//   - Circuit breaker around backend RoundTrip (sheds load on repeated failures)
//   - Prometheus metrics (requests, latency, active sessions, mutations)
//   - Structured JSON logging with per-call request_id propagation
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/joshuabvarghese/loom/internal/circuitbreaker"
	"github.com/joshuabvarghese/loom/internal/metrics"
	"github.com/joshuabvarghese/loom/internal/mutator"
	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	slogpkg "github.com/joshuabvarghese/loom/internal/slog"
	"github.com/joshuabvarghese/loom/internal/transcoder"
)

// MetaMutator is implemented by metadata.Engine.
type MetaMutator interface {
	Apply(method, direction string, h http.Header) bool
	RuleCount() int
}

// Config holds all dependencies for the proxy handler.
type Config struct {
	BackendAddr          string
	GRPCConn             *grpc.ClientConn
	Reflector            *reflector.Reflector
	Recorder             *recpkg.Recorder
	Mutator              *mutator.Engine
	MetaMutator          MetaMutator
	CircuitBreaker       *circuitbreaker.Breaker // nil = disabled
	Verbose              bool
	Color                bool
	BackendTLS           bool
	BackendTLSSkipVerify bool
}

// Handler is an http.Handler that acts as a gRPC reverse proxy.
type Handler struct {
	cfg Config
}

// NewHandler creates a new proxy Handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path // e.g. "/user.UserService/GetUser"
	start := time.Now()
	callID := fmt.Sprintf("%d", start.UnixNano())

	// Attach request ID to context so all log lines for this call are correlated.
	ctx := slogpkg.WithRequestID(r.Context(), callID)

	slogpkg.Debug(ctx, "incoming call", "method", method)

	// Track in-flight call count.
	metrics.SessionStart()
	defer metrics.SessionEnd()

	call := &recpkg.CallRecord{
		ID:         callID,
		Timestamp:  start,
		Method:     method,
		StreamKind: recpkg.StreamUnary,
	}

	// ── Resolve method descriptor via gRPC reflection ─────────────────────────
	methodInfo, reflectErr := h.cfg.Reflector.Resolve(ctx, method)

	// ── Read full request body ────────────────────────────────────────────────
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// ── Decode request frames ─────────────────────────────────────────────────
	if reflectErr == nil && methodInfo != nil {
		frames, _ := transcoder.DecodeStream(bytes.NewReader(reqBody), methodInfo.Input)
		for i, f := range frames {
			call.Request = append(call.Request, recpkg.FrameRecord{
				Index: i,
				Raw:   f.Raw,
				JSON:  f.JSON,
			})
		}
	} else {
		call.Request = []recpkg.FrameRecord{{Index: 0, Raw: reqBody}}
	}

	// ── Apply body mutations on the request ───────────────────────────────────
	if h.cfg.Mutator != nil && len(call.Request) > 0 && call.Request[0].JSON != "" {
		newJSON, mutated, mutErr := h.cfg.Mutator.Apply(method, mutator.DirRequest, call.Request[0].JSON)
		if mutErr != nil {
			slogpkg.Warn(ctx, "request mutation error", "err", mutErr)
		} else if mutated {
			call.Request[0].JSON = newJSON
			call.Mutated = true
			metrics.RecordMutation(method, "request")
			if reflectErr == nil && methodInfo != nil {
				if raw, encErr := transcoder.BuildFrame(methodInfo.Input, newJSON); encErr == nil {
					call.Request[0].Raw = raw
					reqBody = raw
				} else {
					slogpkg.Warn(ctx, "could not re-encode mutated request frame", "err", encErr)
				}
			}
		}
	}

	// ── Apply header mutations ────────────────────────────────────────────────
	upReqHeaders := r.Header.Clone()
	if h.cfg.MetaMutator != nil {
		if h.cfg.MetaMutator.Apply(method, "request", upReqHeaders) {
			call.Mutated = true
			metrics.RecordMutation(method, "request-header")
		}
	}

	// ── Build upstream request ────────────────────────────────────────────────
	scheme := "http"
	if h.cfg.BackendTLS {
		scheme = "https"
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, h.cfg.BackendAddr, method)

	upReq, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(reqBody))
	if err != nil {
		writeGRPCError(w, codes.Internal, fmt.Sprintf("building upstream request: %v", err))
		return
	}
	for k, vs := range upReqHeaders {
		for _, v := range vs {
			upReq.Header.Add(k, v)
		}
	}
	upReq.Header.Set("Content-Type", "application/grpc")
	upReq.Header.Set("TE", "trailers")

	// ── Forward to backend (wrapped in circuit breaker if configured) ─────────
	transport := newH2Transport(h.cfg.BackendTLS, h.cfg.BackendTLSSkipVerify)

	var resp *http.Response
	doRoundTrip := func() error {
		var rtErr error
		resp, rtErr = transport.RoundTrip(upReq)
		return rtErr
	}

	var tripErr error
	if h.cfg.CircuitBreaker != nil {
		tripErr = h.cfg.CircuitBreaker.Call(doRoundTrip)
		// Keep metrics gauge in sync with circuit state after every call.
		metrics.SetCircuitBreakerState(h.cfg.CircuitBreaker.State())
	} else {
		tripErr = doRoundTrip()
	}

	if tripErr != nil {
		statusCode := codes.Unavailable
		statusName := statusCode.String()

		if errors.Is(tripErr, circuitbreaker.ErrCircuitOpen) {
			// Circuit is open — fast fail without logging a full error.
			slogpkg.Warn(ctx, "circuit open — shedding load", "method", method)
		} else {
			slogpkg.Error(ctx, "backend unreachable", "method", method, "err", tripErr)
		}

		writeGRPCError(w, statusCode, fmt.Sprintf("backend unreachable: %v", tripErr))
		call.StatusCode = fmt.Sprintf("%d", statusCode)
		call.StatusName = statusName
		call.Error = tripErr.Error()
		call.DurationMs = ms(start)
		metrics.RecordCall(method, statusName, call.DurationMs)
		printCall(call, h.cfg.Color)
		h.cfg.Recorder.Record(call)
		return
	}
	defer resp.Body.Close()

	// ── Read response body ────────────────────────────────────────────────────
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeGRPCError(w, codes.Internal, "reading backend response")
		slogpkg.Error(ctx, "reading backend response body", "err", err)
		return
	}

	// ── Decode response frames ────────────────────────────────────────────────
	if reflectErr == nil && methodInfo != nil {
		frames, _ := transcoder.DecodeStream(bytes.NewReader(respBody), methodInfo.Output)
		for i, f := range frames {
			call.Response = append(call.Response, recpkg.FrameRecord{
				Index: i,
				Raw:   f.Raw,
				JSON:  f.JSON,
			})
		}
	} else {
		call.Response = []recpkg.FrameRecord{{Index: 0, Raw: respBody}}
	}

	// ── Apply body mutations on the response ──────────────────────────────────
	if h.cfg.Mutator != nil && len(call.Response) > 0 && call.Response[0].JSON != "" {
		newJSON, mutated, mutErr := h.cfg.Mutator.Apply(method, mutator.DirResponse, call.Response[0].JSON)
		if mutErr != nil {
			slogpkg.Warn(ctx, "response mutation error", "err", mutErr)
		} else if mutated {
			call.Response[0].JSON = newJSON
			call.Mutated = true
			metrics.RecordMutation(method, "response")
			if reflectErr == nil && methodInfo != nil {
				if raw, encErr := transcoder.BuildFrame(methodInfo.Output, newJSON); encErr == nil {
					call.Response[0].Raw = raw
					respBody = raw
				} else {
					slogpkg.Warn(ctx, "could not re-encode mutated response frame", "err", encErr)
				}
			}
		}
	}

	// ── Extract gRPC status ───────────────────────────────────────────────────
	statusCode := resp.Trailer.Get("grpc-status")
	if statusCode == "" {
		statusCode = resp.Header.Get("grpc-status")
	}
	if statusCode == "" {
		statusCode = "0"
	}
	call.StatusCode = statusCode
	call.StatusName = grpcCodeName(statusCode)
	call.GRPCMessage = resp.Trailer.Get("grpc-message")
	call.DurationMs = ms(start)

	// ── Build grpcurl command ─────────────────────────────────────────────────
	call.GrpcurlCmd = recpkg.BuildGrpcurlCommand(call, proxyAddr(r), h.cfg.BackendTLS)

	// ── Write response back to client ─────────────────────────────────────────
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	// Trailers must be set after WriteHeader.
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	// ── Record and emit metrics ───────────────────────────────────────────────
	metrics.RecordCall(method, call.StatusName, call.DurationMs)

	slogpkg.Info(ctx, "call complete",
		"method", method,
		"status", call.StatusName,
		"duration_ms", call.DurationMs,
		"mutated", call.Mutated,
	)

	printCall(call, h.cfg.Color)
	h.cfg.Recorder.Record(call)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newH2Transport returns an http2.Transport configured for plain h2c or TLS.
func newH2Transport(useTLS, skipVerify bool) *http2.Transport {
	if useTLS {
		return &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec
		}
	}
	// For h2c (cleartext HTTP/2) we supply a plain TCP dialer.
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}

func writeGRPCError(w http.ResponseWriter, code codes.Code, msg string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-status", fmt.Sprintf("%d", code))
	w.Header().Set("grpc-message", msg)
	w.WriteHeader(http.StatusOK)
}

func grpcCodeName(code string) string {
	names := map[string]string{
		"0": "OK", "1": "CANCELLED", "2": "UNKNOWN",
		"3": "INVALID_ARGUMENT", "4": "DEADLINE_EXCEEDED",
		"5": "NOT_FOUND", "6": "ALREADY_EXISTS",
		"7": "PERMISSION_DENIED", "8": "RESOURCE_EXHAUSTED",
		"9": "FAILED_PRECONDITION", "10": "ABORTED",
		"11": "OUT_OF_RANGE", "12": "UNIMPLEMENTED",
		"13": "INTERNAL", "14": "UNAVAILABLE",
		"15": "DATA_LOSS", "16": "UNAUTHENTICATED",
	}
	if n, ok := names[code]; ok {
		return n
	}
	return "STATUS_" + code
}

func ms(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func proxyAddr(r *http.Request) string {
	h := r.Host
	if h == "" {
		return "localhost:9999"
	}
	if strings.HasPrefix(h, ":") {
		return "localhost" + h
	}
	return h
}

func printCall(call *recpkg.CallRecord, color bool) {
	green := "\033[32m"
	red := "\033[31m"
	reset := "\033[0m"
	if !color {
		green, red, reset = "", "", ""
	}
	col := green
	if call.StatusCode != "0" && call.StatusCode != "" {
		col = red
	}
	fmt.Printf("  %s%-20s%s  %s  %.2fms\n", col, call.StatusName, reset, call.Method, call.DurationMs)
}
