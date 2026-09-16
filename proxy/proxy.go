// Package proxy is the HTTP/2 reverse proxy that sits between the gRPC client
// and backend. It copies frames in both directions, decodes them via the
// reflector/transcoder, and hands the results to the recorder.
//
// All four gRPC stream types are handled: unary, server-streaming,
// client-streaming, and bidi. A circuit breaker wraps each backend round-trip.
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

	"github.com/jhump/protoreflect/desc"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/joshuabvarghese/loom/internal/circuitbreaker"
	"github.com/joshuabvarghese/loom/internal/h2sniff"
	"github.com/joshuabvarghese/loom/internal/metrics"
	"github.com/joshuabvarghese/loom/internal/mutator"
	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	slogpkg "github.com/joshuabvarghese/loom/internal/slog"
	"github.com/joshuabvarghese/loom/internal/transcoder"
)

type MetaMutator interface {
	Apply(method, direction string, h http.Header) bool
	RuleCount() int
}

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
	FrameSniffer         *h2sniff.Sniffer // nil disables HTTP/2 frame capture entirely
}

type Handler struct {
	cfg Config
}

func NewHandler(cfg Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	grpcMethod := r.URL.Path // e.g. "/user.UserService/GetUser"
	start := time.Now()
	callID := fmt.Sprintf("%d", start.UnixNano())

	ctx := slogpkg.WithRequestID(r.Context(), callID)
	slogpkg.Debug(ctx, "incoming call", "method", grpcMethod)

	metrics.SessionStart()
	defer metrics.SessionEnd()

	call := &recpkg.CallRecord{
		ID:        callID,
		Timestamp: start,
		Method:    grpcMethod,
	}

	methodInfo, reflectErr := h.cfg.Reflector.Resolve(ctx, grpcMethod)

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

// framesFromBytes decodes raw into individual FrameRecords when a message
// descriptor is available, or wraps it as a single opaque frame otherwise.
func framesFromBytes(raw []byte, msgDesc *desc.MessageDescriptor, haveDescriptor bool) []recpkg.FrameRecord {
	if !haveDescriptor {
		return []recpkg.FrameRecord{{Index: 0, Raw: raw}}
	}
	frames, _ := transcoder.DecodeStream(bytes.NewReader(raw), msgDesc)
	out := make([]recpkg.FrameRecord, len(frames))
	for i, f := range frames {
		out[i] = recpkg.FrameRecord{Index: i, Raw: f.Raw, JSON: f.JSON}
	}
	return out
}

// mutateFirstFrame runs body-mutation rules against frames[0]'s JSON and, if
// a rule fired, re-encodes it to wire format. It returns the new raw bytes,
// or nil if nothing changed (so the caller's existing body can be reused).
func (h *Handler) mutateFirstFrame(
	ctx context.Context,
	call *recpkg.CallRecord,
	frames []recpkg.FrameRecord,
	dir mutator.Direction,
	directionLabel string,
	msgDesc *desc.MessageDescriptor,
	haveDescriptor bool,
) []byte {
	if h.cfg.Mutator == nil || len(frames) == 0 || frames[0].JSON == "" {
		return nil
	}

	newJSON, mutated, mutErr := h.cfg.Mutator.Apply(call.Method, dir, frames[0].JSON)
	if mutErr != nil {
		slogpkg.Warn(ctx, directionLabel+" mutation error", "err", mutErr)
		return nil
	}
	if !mutated {
		return nil
	}

	frames[0].JSON = newJSON
	call.Mutated = true
	metrics.RecordMutation(call.Method, directionLabel)

	if !haveDescriptor {
		return nil
	}
	raw, encErr := transcoder.BuildFrame(msgDesc, newJSON)
	if encErr != nil {
		slogpkg.Warn(ctx, "could not re-encode mutated "+directionLabel+" frame", "err", encErr)
		return nil
	}
	frames[0].Raw = raw
	return raw
}

func (h *Handler) buildUpstreamRequest(ctx context.Context, method string, headers http.Header, body io.Reader) (*http.Request, error) {
	scheme := "http"
	if h.cfg.BackendTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, h.cfg.BackendAddr, method)

	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	return req, nil
}

// roundTrip performs upReq through transport, routed through the circuit
// breaker when one is configured.
func (h *Handler) roundTrip(transport *http2.Transport, upReq *http.Request) (*http.Response, error) {
	var resp *http.Response
	doRoundTrip := func() error {
		var rtErr error
		resp, rtErr = transport.RoundTrip(upReq) //nolint:bodyclose // closed via defer resp.Body.Close() by the caller
		return rtErr
	}

	var tripErr error
	if h.cfg.CircuitBreaker != nil {
		tripErr = h.cfg.CircuitBreaker.Call(doRoundTrip)
		metrics.SetCircuitBreakerState(h.cfg.CircuitBreaker.State())
	} else {
		tripErr = doRoundTrip()
	}
	return resp, tripErr
}

func (h *Handler) serveUnary(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	call *recpkg.CallRecord,
	methodInfo *reflector.MethodInfo,
	reflectErr error,
	start time.Time,
) {
	haveDescriptor := reflectErr == nil && methodInfo != nil

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var inputDesc, outputDesc *desc.MessageDescriptor
	if haveDescriptor {
		inputDesc, outputDesc = methodInfo.Input, methodInfo.Output
	}

	call.Request = framesFromBytes(reqBody, inputDesc, haveDescriptor)
	if raw := h.mutateFirstFrame(ctx, call, call.Request, mutator.DirRequest, "request", inputDesc, haveDescriptor); raw != nil {
		reqBody = raw
	}

	upReqHeaders := r.Header.Clone()
	if h.cfg.MetaMutator != nil && h.cfg.MetaMutator.Apply(call.Method, "request", upReqHeaders) {
		call.Mutated = true
		metrics.RecordMutation(call.Method, "request-header")
	}

	upReq, err := h.buildUpstreamRequest(ctx, call.Method, upReqHeaders, bytes.NewReader(reqBody))
	if err != nil {
		writeGRPCError(w, codes.Internal, fmt.Sprintf("building upstream request: %v", err))
		return
	}

	transport := newH2Transport(h.cfg.BackendTLS, h.cfg.BackendTLSSkipVerify, h.cfg.FrameSniffer)
	resp, tripErr := h.roundTrip(transport, upReq)
	if tripErr != nil {
		h.handleTripErr(ctx, w, call, tripErr, start)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeGRPCError(w, codes.Internal, "reading backend response")
		slogpkg.Error(ctx, "reading backend response body", "err", err)
		return
	}

	call.Response = framesFromBytes(respBody, outputDesc, haveDescriptor)
	if raw := h.mutateFirstFrame(ctx, call, call.Response, mutator.DirResponse, "response", outputDesc, haveDescriptor); raw != nil {
		respBody = raw
	}

	// gRPC allows "trailers-only" responses where grpc-status arrives in the
	// initial HEADERS frame (resp.Header) rather than a trailing one
	// (resp.Trailer) — Go's http2.Transport surfaces these in resp.Header.
	// We forward grpc-status/grpc-message as real HTTP/2 trailers either way.
	grpcTrailers := make(map[string][]string)
	for _, key := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
		if vs := resp.Trailer.Values(key); len(vs) > 0 {
			grpcTrailers[key] = vs
		} else if vs := resp.Header.Values(key); len(vs) > 0 {
			grpcTrailers[key] = vs
			resp.Header.Del(key)
		}
	}
	for k, vs := range resp.Trailer {
		if _, already := grpcTrailers[k]; !already {
			grpcTrailers[k] = vs
		}
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for k := range grpcTrailers { // pre-declare so net/http emits them in the trailing HEADERS frame
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	for k, vs := range grpcTrailers {
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v) // works after WriteHeader in HTTP/2
		}
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	h.finishCall(ctx, call, resp, start)
}

// serveStreaming handles server-streaming, client-streaming, and bidi RPCs
// by piping the request body to the backend through an io.Pipe (so the
// backend sees a live stream, not a buffered blob) while concurrently
// streaming the response back, recording frames on both sides as they arrive.
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
	haveDescriptor := reflectErr == nil && methodInfo != nil

	// mutatedMu guards call.Mutated, which the request-header path (this
	// goroutine) and the request-body goroutine can both set concurrently
	// in a bidi-streaming call.
	var mutatedMu sync.Mutex
	setMutated := func() {
		mutatedMu.Lock()
		call.Mutated = true
		mutatedMu.Unlock()
	}

	upReqHeaders := r.Header.Clone()
	if h.cfg.MetaMutator != nil && h.cfg.MetaMutator.Apply(call.Method, "request", upReqHeaders) {
		setMutated()
		metrics.RecordMutation(call.Method, "request-header")
	}

	reqPipeR, reqPipeW := io.Pipe()
	var reqMu sync.Mutex
	var reqFrameIdx int

	// reqCancel signals the request-body goroutine to stop if the backend
	// round-trip fails; otherwise it can block writing to a pipe whose
	// read end is already closed, leaking until the client disconnects.
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	go func() {
		defer reqPipeW.Close()

		if haveDescriptor {
			// Tee: raw bytes -> reqPipeW, and decode frames for recording.
			// The copy from pr to reqPipeW runs in its own goroutine so
			// backpressure flows correctly back to StreamFrames.
			pr, pw := io.Pipe()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(reqPipeW, pr)
				// Drain pr once reqPipeW closes so StreamFrames (writing to
				// pw) never blocks permanently on a dead downstream pipe.
				_, _ = io.Copy(io.Discard, pr)
			}()

			frameCh := transcoder.StreamFrames(r.Body, pw, methodInfo.Input)
			for {
				select {
				case f, ok := <-frameCh:
					if !ok {
						pw.Close()
						wg.Wait()
						return
					}
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
				case <-reqCtx.Done():
					pw.CloseWithError(reqCtx.Err())
					wg.Wait()
					return
				}
			}
		}

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
				call.Request = append(call.Request, recpkg.FrameRecord{Index: idx, Raw: chunk})
				idx++
				reqMu.Unlock()
			}
			if err != nil {
				break
			}
		}
	}()

	upReq, err := h.buildUpstreamRequest(ctx, call.Method, upReqHeaders, reqPipeR)
	if err != nil {
		reqPipeR.CloseWithError(err)
		writeGRPCError(w, codes.Internal, fmt.Sprintf("building upstream request: %v", err))
		return
	}

	transport := newH2Transport(h.cfg.BackendTLS, h.cfg.BackendTLSSkipVerify, h.cfg.FrameSniffer)
	resp, tripErr := h.roundTrip(transport, upReq)
	if tripErr != nil {
		reqCancel() // stop the request-body goroutine before closing the pipe
		reqPipeR.CloseWithError(tripErr)
		h.handleTripErr(ctx, w, call, tripErr, start)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	var respFrameIdx int
	if haveDescriptor {
		// Tee: raw bytes -> w, and decode frames for recording.
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
		buf := make([]byte, 32*1024)
		var idx int
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				_, _ = w.Write(chunk)
				flusher.Flush()
				call.Response = append(call.Response, recpkg.FrameRecord{Index: idx, Raw: chunk})
				idx++
			}
			if readErr != nil {
				break
			}
		}
	}

	// Trailers arrive after the body is fully consumed. Handle both regular
	// trailers and the "trailers-only" case where grpc-status is in
	// resp.Header instead of resp.Trailer.
	for _, key := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
		if vs := resp.Header.Values(key); len(vs) > 0 && len(resp.Trailer.Values(key)) == 0 {
			for _, v := range vs {
				w.Header().Add(http.TrailerPrefix+key, v)
			}
		}
	}
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	h.finishCall(ctx, call, resp, start)
}

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

func newH2Transport(useTLS, skipVerify bool, sniffer *h2sniff.Sniffer) *http2.Transport {
	if useTLS {
		return &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
				if err != nil || sniffer == nil {
					return conn, err
				}
				return sniffer.WrapDialedConn(conn), nil
			},
		}
	}
	return &http2.Transport{
		AllowHTTP: true, // h2c: cleartext HTTP/2
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
			if err != nil || sniffer == nil {
				return conn, err
			}
			return sniffer.WrapDialedConn(conn), nil
		},
	}
}

func writeGRPCError(w http.ResponseWriter, code codes.Code, msg string) {
	w.Header().Set("Content-Type", "application/grpc")
	// The gRPC spec requires grpc-status/grpc-message in the trailing HEADERS
	// frame; pre-declaring them as Trailer tells net/http to emit them that way.
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", fmt.Sprintf("%d", code))
	w.Header().Set(http.TrailerPrefix+"Grpc-Message", msg)
}

func grpcCodeName(code string) string {
	names := map[string]string{
		"0": "OK", "1": "canceled", "2": "UNKNOWN",
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

func printCall(call *recpkg.CallRecord, color bool) {
	green, red, cyan, reset := "\033[32m", "\033[31m", "\033[36m", "\033[0m"
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
