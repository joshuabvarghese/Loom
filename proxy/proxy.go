// Package proxy implements the gRPC L7 reverse proxy at the heart of Loom.
//
// It accepts any gRPC call (identified by its HTTP/2 :path header), forwards
// it to the configured backend, and records the decoded request/response for
// the Web Inspector.
//
// Supported RPC types:
//   - Unary             — single request, single response
//   - Server-streaming  — single request, multiple response frames
//   - Client-streaming  — multiple request frames, single response
//   - Bidirectional     — multiple request frames, multiple response frames
//
// Features:
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
	"sync"
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
	ListenAddr           string // used to build grpcurl commands; defaults to ":9999"
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
	grpcMethod := r.URL.Path // e.g. "/user.UserService/GetUser"
	start := time.Now()
	callID := fmt.Sprintf("%d", start.UnixNano())

	// Attach request ID to context so all log lines for this call are correlated.
	ctx := slogpkg.WithRequestID(r.Context(), callID)

	slogpkg.Debug(ctx, "incoming call", "method", grpcMethod)

	// Track in-flight call count.
	metrics.SessionStart()
	defer metrics.SessionEnd()

	call := &recpkg.CallRecord{
		ID:        callID,
		Timestamp: start,
		Method:    grpcMethod,
	}

	// ── Resolve method descriptor via gRPC reflection ─────────────────────────
	methodInfo, reflectErr := h.cfg.Reflector.Resolve(ctx, grpcMethod)

	// ── Detect streaming type ─────────────────────────────────────────────────
	var isClientStream, isServerStream bool
	if reflectErr == nil && methodInfo != nil {
		md := methodInfo.Method
		isClientStream = md.IsClientStreaming()
		isServerStream = md.IsServerStreaming()
	}

	if isClientStream || isServerStream {
		call.StreamKind = streamKind(isClientStream, isServerStream)
		h.serveStreaming(ctx, w, r, call, methodInfo, reflectErr, start)
	} else {
		call.StreamKind = recpkg.StreamUnary
		h.serveUnary(ctx, w, r, call, methodInfo, reflectErr, start)
	}
}

// streamKind returns the appropriate StreamKind based on the streaming flags.
func streamKind(clientStream, serverStream bool) recpkg.StreamKind {
	switch {
	case clientStream && serverStream:
		return recpkg.StreamBidi
	case clientStream:
		return recpkg.StreamClient
	default:
		return recpkg.StreamServer
	}
}

// ── Unary RPC ─────────────────────────────────────────────────────────────────

func (h *Handler) serveUnary(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	call *recpkg.CallRecord,
	methodInfo *reflector.MethodInfo,
	reflectErr error,
	start time.Time,
) {
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
		newJSON, mutated, mutErr := h.cfg.Mutator.Apply(call.Method, mutator.DirRequest, call.Request[0].JSON)
		if mutErr != nil {
			slogpkg.Warn(ctx, "request mutation error", "err", mutErr)
		} else if mutated {
			call.Request[0].JSON = newJSON
			call.Mutated = true
			metrics.RecordMutation(call.Method, "request")
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
		if h.cfg.MetaMutator.Apply(call.Method, "request", upReqHeaders) {
			call.Mutated = true
			metrics.RecordMutation(call.Method, "request-header")
		}
	}

	// ── Build upstream request ────────────────────────────────────────────────
	scheme := "http"
	if h.cfg.BackendTLS {
		scheme = "https"
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, h.cfg.BackendAddr, call.Method)

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
		metrics.SetCircuitBreakerState(h.cfg.CircuitBreaker.State())
	} else {
		tripErr = doRoundTrip()
	}

	if tripErr != nil {
		h.handleTripErr(ctx, w, call, tripErr, start)
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
		newJSON, mutated, mutErr := h.cfg.Mutator.Apply(call.Method, mutator.DirResponse, call.Response[0].JSON)
		if mutErr != nil {
			slogpkg.Warn(ctx, "response mutation error", "err", mutErr)
		} else if mutated {
			call.Response[0].JSON = newJSON
			call.Mutated = true
			metrics.RecordMutation(call.Method, "response")
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

	h.finishCall(ctx, call, resp, start)
}

// ── Streaming RPC ─────────────────────────────────────────────────────────────

// serveStreaming handles server-streaming, client-streaming, and bidi RPCs.
//
// Strategy: pipe the request body from the client to the backend via an
// io.Pipe (so the backend sees a live stream, not a buffered blob), while
// simultaneously reading response frames from the backend and forwarding them
// to the client. Both halves run concurrently, recording frames as they arrive.
func (h *Handler) serveStreaming(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	call *recpkg.CallRecord,
	methodInfo *reflector.MethodInfo,
	reflectErr error,
	start time.Time,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeGRPCError(w, codes.Internal, "streaming not supported by this ResponseWriter")
		return
	}

	// ── Apply header mutations ────────────────────────────────────────────────
	upReqHeaders := r.Header.Clone()
	if h.cfg.MetaMutator != nil {
		if h.cfg.MetaMutator.Apply(call.Method, "request", upReqHeaders) {
			call.Mutated = true
			metrics.RecordMutation(call.Method, "request-header")
		}
	}

	// ── Pipe client body → backend ────────────────────────────────────────────
	// We use an io.Pipe so the upstream sees a streaming body (not a buffer).
	// A goroutine copies from r.Body → reqPipeW while simultaneously recording
	// decoded request frames.
	reqPipeR, reqPipeW := io.Pipe()

	var reqMu sync.Mutex
	var reqFrameIdx int

	go func() {
		defer reqPipeW.Close()

		if reflectErr == nil && methodInfo != nil {
			// Tee: raw bytes → reqPipeW AND decode frames for recording.
			//
			// StreamFrames reads from r.Body, writes raw bytes to pw, and
			// emits decoded Frame values on a channel. We copy from pr to
			// reqPipeW in a separate goroutine so backpressure flows correctly.
			pr, pw := io.Pipe()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(reqPipeW, pr)
			}()

			frameCh := transcoder.StreamFrames(r.Body, pw, methodInfo.Input)
			for f := range frameCh {
				if f.Err != nil {
					slogpkg.Debug(ctx, "request frame decode error", "err", f.Err)
					continue
				}
				reqMu.Lock()
				idx := reqFrameIdx
				reqFrameIdx++
				reqMu.Unlock()
				call.Request = append(call.Request, recpkg.FrameRecord{
					Index: idx,
					Raw:   f.Raw,
					JSON:  f.JSON,
				})
			}
			pw.Close()
			wg.Wait()
		} else {
			// No descriptor — pipe raw bytes through and record them.
			buf := make([]byte, 32*1024)
			var idx int
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					chunk := make([]byte, n)
					copy(chunk, buf[:n])
					if _, werr := reqPipeW.Write(chunk); werr != nil {
						break
					}
					reqMu.Lock()
					call.Request = append(call.Request, recpkg.FrameRecord{
						Index: idx,
						Raw:   chunk,
					})
					idx++
					reqMu.Unlock()
				}
				if err != nil {
					break
				}
			}
		}
	}()

	// ── Build upstream request with streaming body ────────────────────────────
	scheme := "http"
	if h.cfg.BackendTLS {
		scheme = "https"
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, h.cfg.BackendAddr, call.Method)

	upReq, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, reqPipeR)
	if err != nil {
		reqPipeR.CloseWithError(err)
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

	// ── Forward to backend ────────────────────────────────────────────────────
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
		metrics.SetCircuitBreakerState(h.cfg.CircuitBreaker.State())
	} else {
		tripErr = doRoundTrip()
	}

	if tripErr != nil {
		reqPipeR.CloseWithError(tripErr)
		h.handleTripErr(ctx, w, call, tripErr, start)
		return
	}
	defer resp.Body.Close()

	// ── Stream response frames back to client ─────────────────────────────────
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	var respFrameIdx int

	if reflectErr == nil && methodInfo != nil {
		// Tee: raw bytes → w AND decode frames for recording.
		pr, pw := io.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, readErr := pr.Read(buf)
				if n > 0 {
					_, _ = w.Write(buf[:n])
					flusher.Flush()
				}
				if readErr != nil {
					break
				}
			}
		}()

		frameCh := transcoder.StreamFrames(resp.Body, pw, methodInfo.Output)
		for f := range frameCh {
			if f.Err != nil {
				slogpkg.Debug(ctx, "response frame decode error", "err", f.Err)
				continue
			}
			call.Response = append(call.Response, recpkg.FrameRecord{
				Index: respFrameIdx,
				Raw:   f.Raw,
				JSON:  f.JSON,
			})
			respFrameIdx++
		}
		pw.Close()
		wg.Wait()
	} else {
		// No descriptor — pipe raw bytes and record chunks.
		buf := make([]byte, 32*1024)
		var idx int
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				_, _ = w.Write(chunk)
				flusher.Flush()
				call.Response = append(call.Response, recpkg.FrameRecord{
					Index: idx,
					Raw:   chunk,
				})
				idx++
			}
			if readErr != nil {
				break
			}
		}
	}

	// Trailers arrive after the body is fully consumed.
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	h.finishCall(ctx, call, resp, start)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// handleTripErr records a backend-unreachable error and writes a gRPC error response.
func (h *Handler) handleTripErr(ctx context.Context, w http.ResponseWriter, call *recpkg.CallRecord, tripErr error, start time.Time) {
	statusCode := codes.Unavailable
	statusName := statusCode.String()

	if errors.Is(tripErr, circuitbreaker.ErrCircuitOpen) {
		slogpkg.Warn(ctx, "circuit open — shedding load", "method", call.Method)
	} else {
		slogpkg.Error(ctx, "backend unreachable", "method", call.Method, "err", tripErr)
	}

	writeGRPCError(w, statusCode, fmt.Sprintf("backend unreachable: %v", tripErr))
	call.StatusCode = fmt.Sprintf("%d", statusCode)
	call.StatusName = statusName
	call.Error = tripErr.Error()
	call.DurationMs = ms(start)
	metrics.RecordCall(call.Method, statusName, call.DurationMs)
	printCall(call, h.cfg.Color)
	h.cfg.Recorder.Record(call)
}

// finishCall extracts gRPC status, builds the grpcurl command, logs, and records.
func (h *Handler) finishCall(ctx context.Context, call *recpkg.CallRecord, resp *http.Response, start time.Time) {
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
	grpcurlTarget := h.cfg.ListenAddr
	if grpcurlTarget == "" || strings.HasPrefix(grpcurlTarget, ":") {
		grpcurlTarget = "localhost" + grpcurlTarget
		if grpcurlTarget == "localhost" {
			grpcurlTarget = "localhost:9999"
		}
	}
	call.GrpcurlCmd = recpkg.BuildGrpcurlCommand(call, grpcurlTarget, h.cfg.BackendTLS)

	metrics.RecordCall(call.Method, call.StatusName, call.DurationMs)

	slogpkg.Info(ctx, "call complete",
		"method", call.Method,
		"stream_kind", string(call.StreamKind),
		"status", call.StatusName,
		"duration_ms", call.DurationMs,
		"req_frames", len(call.Request),
		"resp_frames", len(call.Response),
		"mutated", call.Mutated,
	)

	printCall(call, h.cfg.Color)
	h.cfg.Recorder.Record(call)
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

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
	cyan := "\033[36m"
	reset := "\033[0m"
	if !color {
		green, red, cyan, reset = "", "", "", ""
	}
	col := green
	if call.StatusCode != "0" && call.StatusCode != "" {
		col = red
	}
	streamTag := ""
	if call.StreamKind != recpkg.StreamUnary {
		streamTag = fmt.Sprintf(" %s[%s]%s", cyan, call.StreamKind, reset)
	}
	fmt.Printf("  %s%-20s%s%s  %s  %.2fms  (%d req / %d resp frames)\n",
		col, call.StatusName, reset,
		streamTag,
		call.Method,
		call.DurationMs,
		len(call.Request),
		len(call.Response),
	)
}


