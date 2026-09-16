// Package recorder captures gRPC calls and fans them out to the
// NDJSON log, the SSE stream for the Web UI, and the in-memory ring buffer
// that backs /api/calls.
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
	"sync/atomic"
	"time"
)

type StreamKind string

const (
	StreamUnary  StreamKind = "unary"
	StreamServer StreamKind = "server_streaming"
	StreamClient StreamKind = "client_streaming"
	StreamBidi   StreamKind = "bidi_streaming"
)

type FrameRecord struct {
	Index int    `json:"index"`
	JSON  string `json:"json"`
	Raw   []byte `json:"raw,omitempty"` // populated for replay
}

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
	GrpcurlCmd  string        `json:"grpcurlCmd,omitempty"`
}

// Example output: grpcurl -plaintext -d '{"userId":"abc123"}' localhost:9999 user.UserService/GetUser
func BuildGrpcurlCommand(call *CallRecord, targetAddr string, useTLS bool) string {
	if call == nil || len(call.Request) == 0 {
		return ""
	}

	frameJSON := ""
	for _, f := range call.Request {
		if f.JSON != "" {
			frameJSON = f.JSON
			break
		}
	}

	method := strings.TrimPrefix(call.Method, "/")
	if method == "" {
		return ""
	}

	tlsFlag := "-plaintext"
	if useTLS {
		tlsFlag = "" // grpcurl defaults to TLS, so the flag is only needed for plaintext
	}

	var parts []string
	parts = append(parts, "grpcurl")
	if tlsFlag != "" {
		parts = append(parts, tlsFlag)
	}

	if frameJSON != "" {
		if compact, err := compactJSON(frameJSON); err == nil && compact != "" {
			parts = append(parts, "-d", "'"+compact+"'") // compact + single-quoted so it's safe as one bash argument
		}
	}

	parts = append(parts, targetAddr, method)
	return strings.Join(parts, " ")
}

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

const defaultRingSize = 500

type Store struct {
	mu      sync.RWMutex
	records []*CallRecord
	maxSize int
}

func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = defaultRingSize
	}
	return &Store{maxSize: maxSize}
}

func (s *Store) Add(r *CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) >= s.maxSize {
		s.records = s.records[1:]
	}
	s.records = append(s.records, r)
}

func (s *Store) All() []*CallRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CallRecord, len(s.records))
	for i, r := range s.records {
		out[len(s.records)-1-i] = r
	}
	return out
}

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

type EventHub struct {
	mu            sync.RWMutex
	subscribers   map[chan *CallRecord]struct{}
	droppedEvents atomic.Int64
}

func NewEventHub() *EventHub {
	return &EventHub{
		subscribers: make(map[chan *CallRecord]struct{}),
	}
}

func (h *EventHub) Subscribe() chan *CallRecord {
	ch := make(chan *CallRecord, 32)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *EventHub) Unsubscribe(ch chan *CallRecord) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *EventHub) DroppedEvents() int64 {
	return h.droppedEvents.Load()
}

func (h *EventHub) Publish(r *CallRecord) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- r:
		default:
			h.droppedEvents.Add(1) // slow subscriber: drop rather than block the proxy, but count it
		}
	}
}

type Recorder struct {
	Store *Store
	Hub   *EventHub

	mu      sync.Mutex
	logFile *os.File
	enc     *json.Encoder
}

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

func (r *Recorder) Record(call *CallRecord) {
	r.Store.Add(call)
	r.Hub.Publish(call)

	if r.enc != nil {
		r.mu.Lock()
		_ = r.enc.Encode(call)
		r.mu.Unlock()
	}
}

func (r *Recorder) Close() error {
	if r.logFile != nil {
		return r.logFile.Close()
	}
	return nil
}

// Alias, not a distinct type: NDJSON replay reads the same records back in,
// it just only cares about the Request frames.
type ReplayRecord = CallRecord

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

func BuildRawBody(frames []FrameRecord) io.Reader {
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(f.Raw)
	}
	return &buf
}
