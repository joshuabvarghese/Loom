// Package recorder captures gRPC calls for logging, replay, and real-time
// streaming to the Web UI. Every completed call produces a CallRecord which is:
//   - Written to an NDJSON log file (if -log is set)
//   - Pushed to all active SSE subscribers (for the Web UI)
//   - Kept in a bounded in-memory ring buffer (for /api/calls)
package recorder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────────────────────

// StreamKind describes the RPC streaming type.
type StreamKind string

const (
	StreamUnary  StreamKind = "unary"
	StreamServer StreamKind = "server_streaming"
	StreamClient StreamKind = "client_streaming"
	StreamBidi   StreamKind = "bidi_streaming"
)

// FrameRecord is one decoded message frame (request or response).
type FrameRecord struct {
	Index int    `json:"index"`
	JSON  string `json:"json"`
	Raw   []byte `json:"raw,omitempty"` // populated for replay
}

// CallRecord is the complete record of one gRPC call.
type CallRecord struct {
	ID          string        `json:"id"`
	Timestamp   time.Time     `json:"timestamp"`
	Method      string        `json:"method"`
	StreamKind  StreamKind    `json:"streamKind"`
	Request     []FrameRecord `json:"request"`
	Response    []FrameRecord `json:"response"`
	StatusCode  string        `json:"statusCode"`
	StatusName  string        `json:"statusName"`
	GRPCMessage string        `json:"grpcMessage,omitempty"`
	DurationMs  float64       `json:"durationMs"`
	Error       string        `json:"error,omitempty"`
	Mutated     bool          `json:"mutated,omitempty"`
	// GrpcurlCmd is a ready-to-paste grpcurl command reproducing this call.
	// Populated at record time; omitted if request body can't be decoded.
	GrpcurlCmd  string        `json:"grpcurlCmd,omitempty"`
}

// BuildGrpcurlCommand constructs a grpcurl CLI command that reproduces the
// given CallRecord against targetAddr. Returns an empty string if the
// request has no decoded JSON frame (e.g. compressed or opaque bytes).
//
// Example output:
//
//	grpcurl -plaintext -d '{"userId":"abc123"}' localhost:9999 user.UserService/GetUser
func BuildGrpcurlCommand(call *CallRecord, targetAddr string, useTLS bool) string {
	if call == nil || len(call.Request) == 0 {
		return ""
	}

	// Use the first request frame's JSON
	frameJSON := ""
	for _, f := range call.Request {
		if f.JSON != "" {
			frameJSON = f.JSON
			break
		}
	}

	// Parse the gRPC path: "/pkg.Service/Method" → "pkg.Service/Method"
	method := strings.TrimPrefix(call.Method, "/")
	if method == "" {
		return ""
	}

	tlsFlag := "-plaintext"
	if useTLS {
		tlsFlag = "" // TLS by default in grpcurl
	}

	var parts []string
	parts = append(parts, "grpcurl")
	if tlsFlag != "" {
		parts = append(parts, tlsFlag)
	}

	if frameJSON != "" {
		// Compact the JSON for the -d flag; single-quote safe for bash
		compact, err := compactJSON(frameJSON)
		if err == nil && compact != "" {
			parts = append(parts, "-d", "'"+compact+"'")
		}
	}

	parts = append(parts, targetAddr, method)
	return strings.Join(parts, " ")
}

// compactJSON marshals JSON to a single line without extra whitespace.
func compactJSON(s string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory ring buffer
// ─────────────────────────────────────────────────────────────────────────────

const defaultRingSize = 500

// Store is a thread-safe ring buffer of CallRecords.
type Store struct {
	mu      sync.RWMutex
	records []*CallRecord
	maxSize int
}

// NewStore creates a Store with a bounded capacity.
func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = defaultRingSize
	}
	return &Store{maxSize: maxSize}
}

// Add appends a record, evicting the oldest if at capacity.
func (s *Store) Add(r *CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) >= s.maxSize {
		s.records = s.records[1:]
	}
	s.records = append(s.records, r)
}

// All returns a copy of all records, newest first.
func (s *Store) All() []*CallRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CallRecord, len(s.records))
	for i, r := range s.records {
		out[len(s.records)-1-i] = r
	}
	return out
}

// ByID finds a record by its ID.
func (s *Store) ByID(id string) (*CallRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.records {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE Event Hub
// ─────────────────────────────────────────────────────────────────────────────

// EventHub broadcasts CallRecord events to all active SSE subscribers.
type EventHub struct {
	mu          sync.RWMutex
	subscribers map[chan *CallRecord]struct{}
}

// NewEventHub creates a new hub.
func NewEventHub() *EventHub {
	return &EventHub{
		subscribers: make(map[chan *CallRecord]struct{}),
	}
}

// Subscribe registers a new subscriber channel. Call Unsubscribe when done.
func (h *EventHub) Subscribe() chan *CallRecord {
	ch := make(chan *CallRecord, 32)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a subscriber channel.
func (h *EventHub) Unsubscribe(ch chan *CallRecord) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
	close(ch)
}

// Publish sends a call record to all subscribers (non-blocking; slow subscribers
// get their oldest events dropped).
func (h *EventHub) Publish(r *CallRecord) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- r:
		default:
			// subscriber too slow — drop rather than block
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Recorder: wires store + hub + optional NDJSON file together
// ─────────────────────────────────────────────────────────────────────────────

// Recorder receives completed CallRecords and fans them out.
type Recorder struct {
	Store *Store
	Hub   *EventHub

	mu      sync.Mutex
	logFile *os.File
	enc     *json.Encoder
}

// New creates a Recorder. If logPath is non-empty, records are also written
// to that file as NDJSON (one JSON object per line).
func New(logPath string) (*Recorder, error) {
	r := &Recorder{
		Store: NewStore(defaultRingSize),
		Hub:   NewEventHub(),
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file %q: %w", logPath, err)
		}
		r.logFile = f
		r.enc = json.NewEncoder(f)
	}
	return r, nil
}

// Record fans out a completed call to the store, hub, and log file.
func (r *Recorder) Record(call *CallRecord) {
	r.Store.Add(call)
	r.Hub.Publish(call)

	if r.enc != nil {
		r.mu.Lock()
		_ = r.enc.Encode(call) // NDJSON: encoder adds \n
		r.mu.Unlock()
	}
}

// Close flushes and closes the log file (if open).
func (r *Recorder) Close() error {
	if r.logFile != nil {
		return r.logFile.Close()
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay
// ─────────────────────────────────────────────────────────────────────────────

// ReplayRecord is the shape persisted in the NDJSON file for replay.
// It is the same as CallRecord but we focus on Request frames.
type ReplayRecord = CallRecord

// ReadNDJSON reads CallRecords from an NDJSON log file.
func ReadNDJSON(path string) ([]*ReplayRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening replay file %q: %w", path, err)
	}
	defer f.Close()

	var records []*ReplayRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec ReplayRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("parsing NDJSON line: %w", err)
		}
		records = append(records, &rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading NDJSON: %w", err)
	}
	return records, nil
}

// BuildRawBody reassembles the raw gRPC wire body from a CallRecord's Request
// frames. This is used by the replay engine to reconstruct the exact bytes
// that were originally sent.
func BuildRawBody(frames []FrameRecord) io.Reader {
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(f.Raw)
	}
	return &buf
}
