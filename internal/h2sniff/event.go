// Package h2sniff passively decodes real HTTP/2 frames on TCP connections
// Loom already owns, for the frame-level visualizer in the Web Inspector.
//
// net/http and golang.org/x/net/http2 don't expose a hook for observing
// raw HEADERS/DATA/SETTINGS/RST_STREAM/WINDOW_UPDATE frames, so this
// package taps the wire directly instead — see sniff.go.
package h2sniff

import (
	"sync"
	"sync/atomic"
	"time"
)

type FrameEvent struct {
	Seq       int64     `json:"seq"`
	ConnID    string    `json:"connId"`
	StreamID  uint32    `json:"streamId"`
	Type      string    `json:"type"`
	Length    uint32    `json:"length"`
	Flags     []string  `json:"flags,omitempty"`
	Direction string    `json:"direction"`
	Timestamp time.Time `json:"timestamp"`

	// HEADERS-only, decoded via HPACK; empty otherwise.
	Path   string `json:"path,omitempty"`
	Method string `json:"method,omitempty"`
	Status string `json:"status,omitempty"`

	WindowIncrement uint32 `json:"windowIncrement,omitempty"` // WINDOW_UPDATE only
	ErrorCode       string `json:"errorCode,omitempty"`       // RST_STREAM / GOAWAY only
}

type Hub struct {
	mu          sync.RWMutex
	subscribers map[chan *FrameEvent]struct{}
	dropped     atomic.Int64
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[chan *FrameEvent]struct{})}
}

func (h *Hub) Subscribe() chan *FrameEvent {
	ch := make(chan *FrameEvent, 256) // frames are far higher-volume than calls
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan *FrameEvent) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) DroppedEvents() int64 {
	return h.dropped.Load()
}

func (h *Hub) Publish(e *FrameEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subscribers {
		select {
		case ch <- e:
		default:
			h.dropped.Add(1) // slow subscriber: drop rather than stall the proxy
		}
	}
}

const defaultRingSize = 4000 // frames are much higher-volume than calls

type Store struct {
	mu      sync.RWMutex
	events  []*FrameEvent
	maxSize int
}

func NewStore(maxSize int) *Store {
	if maxSize <= 0 {
		maxSize = defaultRingSize
	}
	return &Store{maxSize: maxSize}
}

func (s *Store) Add(e *FrameEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxSize {
		s.events = s.events[1:]
	}
	s.events = append(s.events, e)
}

func (s *Store) All() []*FrameEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*FrameEvent, len(s.events))
	for i, e := range s.events {
		out[len(s.events)-1-i] = e
	}
	return out
}
