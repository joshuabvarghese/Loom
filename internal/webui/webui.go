// Package webui serves the Loom Studio frontend and its backing API.
//
// The frontend lives in the top-level webui/ directory as a Vite + React +
// TypeScript SPA. `npm run build` there compiles it into internal/webui/dist,
// which this package embeds into the Go binary via go:embed.
//
// API surface:
//
//	GET  /api/config     — {proxyAddr} the frontend needs to render the header
//	GET  /api/calls      — JSON array of all recorded calls (newest first)
//	GET  /api/calls/:id  — single call record by ID
//	GET  /api/stream     — SSE stream of new calls in real-time
//	POST /api/replay/:id — replay a recorded call through the proxy
//	GET  /api/v1/schema  — draft-07 JSON Schema for a method's request or
//	                        response message, derived from server reflection
//	GET  /api/frames     — JSON array of recent HTTP/2 frame telemetry (newest first)
//	GET  /api/events     — SSE stream of HTTP/2 frame telemetry in real-time
//	GET  /*              — the SPA (index.html for unknown paths, so the app
//	                        keeps working if the SPA later grows client routes)
package webui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/joshuabvarghese/loom/internal/h2sniff"
	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
)

//go:embed all:dist
var distFS embed.FS

type ReplayFunc func(call *recpkg.CallRecord) (string, error)

type Server struct {
	rec        *recpkg.Recorder
	replay     ReplayFunc
	refl       *reflector.Reflector
	frames     *h2sniff.Sniffer
	proxyAddr  string
	backendTLS bool
}

// refl and frames may be nil; their endpoints then respond 501 instead of panicking.
func NewWithOptions(
	rec *recpkg.Recorder,
	replayFn ReplayFunc,
	refl *reflector.Reflector,
	frames *h2sniff.Sniffer,
	proxyAddr string,
	backendTLS bool,
) *Server {
	return &Server{
		rec:        rec,
		replay:     replayFn,
		refl:       refl,
		frames:     frames,
		proxyAddr:  proxyAddr,
		backendTLS: backendTLS,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/calls", s.handleCalls)
	mux.HandleFunc("/api/calls/", s.handleCallByID)
	mux.HandleFunc("/api/stream", s.handleSSE)
	mux.HandleFunc("/api/replay/", s.handleReplay)
	mux.HandleFunc("/api/v1/schema", s.handleSchema)
	mux.HandleFunc("/api/frames", s.handleFrames)
	mux.HandleFunc("/api/events", s.handleFrameSSE)
	mux.Handle("/", s.staticHandler())
	return mux
}

// Falls back to index.html for any path that isn't a real file, so a
// client-side route the SPA might add later still resolves.
func (s *Server) staticHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// Only reachable if the frontend was never built — surface a clear
		// error instead of a confusing embed.FS panic deep in net/http.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "webui: frontend not built — run `npm run build` in webui/ before building Loom", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(sub, path); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"proxyAddr": s.proxyAddr}) //nolint:errcheck
}

func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	calls := s.rec.Store.All()
	if err := json.NewEncoder(w).Encode(calls); err != nil {
		http.Error(w, "encoding calls", http.StatusInternalServerError)
	}
}

func (s *Server) handleCallByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/calls/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	call, ok := s.rec.Store.ByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(call) //nolint:errcheck
}

func (s *Server) handleFrames(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s.frames == nil {
		http.Error(w, "frame telemetry not configured", http.StatusNotImplemented)
		return
	}
	if err := json.NewEncoder(w).Encode(s.frames.Store.All()); err != nil {
		http.Error(w, "encoding frames", http.StatusInternalServerError)
	}
}

func (s *Server) handleFrameSSE(w http.ResponseWriter, r *http.Request) {
	if s.frames == nil {
		http.Error(w, "frame telemetry not configured", http.StatusNotImplemented)
		return
	}
	ch := s.frames.Hub.Subscribe()
	defer s.frames.Hub.Unsubscribe(ch)
	serveEventStream(w, r, ch)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	ch := s.rec.Hub.Subscribe()
	defer s.rec.Hub.Unsubscribe(ch)
	serveEventStream(w, r, ch)
}

// serveEventStream writes events as they arrive on ch as an SSE stream,
// with a periodic heartbeat so idle connections don't get reaped by
// intermediate proxies, until ch closes or the client disconnects.
func serveEventStream[T any](w http.ResponseWriter, r *http.Request, ch <-chan T) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte(": connected\n\n")) //nolint:errcheck
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			w.Write([]byte("data: ")) //nolint:errcheck
			w.Write(data)             //nolint:errcheck
			w.Write([]byte("\n\n"))   //nolint:errcheck
			flusher.Flush()

		case <-heartbeat.C:
			w.Write([]byte(": heartbeat\n\n")) //nolint:errcheck
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.replay == nil {
		http.Error(w, "replay not configured", http.StatusNotImplemented)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/replay/")
	call, ok := s.rec.Store.ByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Optional body {"payload": "<edited request JSON>"} lets the Monaco
	// Replay modal replay an edited request; a plain POST with no body
	// replays the call verbatim.
	if body, readErr := io.ReadAll(io.LimitReader(r.Body, 1<<20)); readErr == nil && len(bytes.TrimSpace(body)) > 0 {
		var override struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(body, &override); err != nil {
			http.Error(w, "replay: malformed JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if override.Payload != "" {
			edited, err := s.applyPayloadOverride(r.Context(), call, override.Payload)
			if err != nil {
				http.Error(w, "replay: "+err.Error(), http.StatusUnprocessableEntity)
				return
			}
			call = edited
		}
	}

	result, err := s.replay(call)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "replayed", "id": result}) //nolint:errcheck
}

// GET /api/v1/schema?method=/pkg.Service/Method&type=request|response — powers
// Monaco's live validation/autocomplete for a method's payload in the SPA.
func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if s.refl == nil {
		http.Error(w, "schema: reflector not configured for this session", http.StatusNotImplemented)
		return
	}

	method := r.URL.Query().Get("method")
	if method == "" {
		http.Error(w, `schema: missing required "method" query param`, http.StatusBadRequest)
		return
	}

	kind := r.URL.Query().Get("type")
	if kind == "" {
		kind = "request"
	}
	if kind != "request" && kind != "response" {
		http.Error(w, `schema: "type" must be "request" or "response"`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	info, err := s.refl.Resolve(ctx, method)
	if err != nil {
		http.Error(w, "schema: "+err.Error(), http.StatusBadGateway)
		return
	}

	md := info.Input
	if kind == "response" {
		md = info.Output
	}
	if md == nil {
		http.Error(w, fmt.Sprintf("schema: no %s message descriptor found for %q", kind, method), http.StatusNotFound)
		return
	}

	schema := newSchemaConverter().buildSchema(md)
	if err := json.NewEncoder(w).Encode(schema); err != nil {
		http.Error(w, "schema: encoding response", http.StatusInternalServerError)
	}
}
