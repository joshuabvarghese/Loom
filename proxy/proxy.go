// Package proxy implements the gRPC L7 reverse proxy at the heart of Loom.
//
// It accepts any gRPC call (identified by its HTTP/2 :path header), forwards
// it to the configured backend, and records the decoded request/response for
// the Web Inspector.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/joshuabvarghese/loom/internal/mutator"
	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
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

	if h.cfg.Verbose {
		log.Printf("[proxy] → %s", method)
	}

	start := time.Now()
	callID := fmt.Sprintf("%d", start.UnixNano())

	call := &recpkg.CallRecord{
		ID:         callID,
		Timestamp:  start,
		Method:     method,
		StreamKind: recpkg.StreamUnary,
	}

	// ── Resolve method descriptor via reflection ──────────────────────────────
	methodInfo, reflectErr := h.cfg.Reflector.Resolve(r.Context(), method)

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

	// ── Apply body mutations on request ───────────────────────────────────────
	if h.cfg.Mutator != nil && len(call.Request) > 0 && call.Request[0].JSON != "" {
		newJSON, mutated, _ := h.cfg.Mutator.Apply(method, mutator.DirRequest, call.Request[0].JSON)
		if mutated {
			call.Request[0].JSON = newJSON
			call.Mutated = true
			if reflectErr == nil && methodInfo != nil {
				if raw, encErr := transcoder.BuildFrame(methodInfo.Input, newJSON); encErr == nil {
					call.Request[0].Raw = raw
					reqBody = raw
				}
			}
		}
	}

	// ── Apply header mutations ────────────────────────────────────────────────
	// We'll build the upstream headers after copying, then mutate
	upReqHeaders := r.Header.Clone()
	if h.cfg.MetaMutator != nil {
		if h.cfg.MetaMutator.Apply(method, "request", upReqHeaders) {
			call.Mutated = true
		}
	}

	// ── Build upstream request ────────────────────────────────────────────────
	scheme := "http"
	if h.cfg.BackendTLS {
		scheme = "https"
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, h.cfg.BackendAddr, method)

	upReq, err := http.NewRequestWithContext(r.Context(), "POST", upstreamURL, bytes.NewReader(reqBody))
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

	// ── Forward to backend ────────────────────────────────────────────────────
	transport := newH2Transport(h.cfg.BackendTLS)
	resp, err := transport.RoundTrip(upReq)
	if err != nil {
		writeGRPCError(w, codes.Unavailable, fmt.Sprintf("backend unreachable: %v", err))
		call.StatusCode = fmt.Sprintf("%d", codes.Unavailable)
		call.StatusName = codes.Unavailable.String()
		call.Error = err.Error()
		call.DurationMs = ms(start)
		printCall(call, h.cfg.Color)
		h.cfg.Recorder.Record(call)
		return
	}
	defer resp.Body.Close()

	// ── Read response body ────────────────────────────────────────────────────
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeGRPCError(w, codes.Internal, "reading response")
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
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	printCall(call, h.cfg.Color)
	h.cfg.Recorder.Record(call)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newH2Transport returns an http2.Transport configured for plain h2c or TLS.
func newH2Transport(useTLS bool) *http2.Transport {
	if useTLS {
		return &http2.Transport{}
	}
	// For h2c (cleartext HTTP/2) we supply a plain TCP dialer via DialTLSContext.
	// The field accepts a func(ctx, network, addr string, cfg *tls.Config) (net.Conn, error).
	// We use a raw net.Dialer and ignore the TLS config since we want plain TCP.
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
	red   := "\033[31m"
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
