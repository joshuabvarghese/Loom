// Package circuitbreaker provides a thread-safe three-state circuit breaker
// for Loom's backend connections.
//
// States:
//
//	Closed   — normal; every call passes through to the backend.
//	Open     — failure threshold exceeded; calls return ErrCircuitOpen immediately
//	           without touching the backend, preventing thundering-herd.
//	HalfOpen — timeout elapsed; exactly one probe call is allowed through.
//	           Success → Closed. Failure → Open (resets timeout).
//
// Usage:
//
//	cb := circuitbreaker.New(circuitbreaker.Options{Threshold: 5, Timeout: 30*time.Second})
//	err := cb.Call(func() error { return transport.RoundTrip(req) })
//	if errors.Is(err, circuitbreaker.ErrCircuitOpen) { /* shed load */ }
package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit is open and calls are being shed.
var ErrCircuitOpen = errors.New("circuit breaker open: backend unavailable")

type state int

const (
	stateClosed   state = iota
	stateOpen
	stateHalfOpen
)

func (s state) String() string {
	switch s {
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// Options configures a Breaker.
type Options struct {
	// Threshold is the number of consecutive failures that open the circuit.
	// Defaults to 5.
	Threshold int
	// Timeout is how long the circuit stays open before a probe is allowed.
	// Defaults to 30 seconds.
	Timeout time.Duration
}

func (o Options) resolvedThreshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return 5
}

func (o Options) resolvedTimeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 30 * time.Second
}

// Breaker is a thread-safe circuit breaker.
type Breaker struct {
	opts        Options
	mu          sync.Mutex
	current     state
	failures    int
	lastFailure time.Time
}

// New returns a Breaker with the given options.
// Zero-value options apply sensible defaults (threshold=5, timeout=30s).
func New(opts Options) *Breaker {
	return &Breaker{opts: opts}
}

// Call executes fn if the circuit permits it.
// Returns ErrCircuitOpen when the circuit is open without calling fn.
func (b *Breaker) Call(fn func() error) error {
	b.mu.Lock()
	switch b.current {
	case stateOpen:
		if time.Since(b.lastFailure) < b.opts.resolvedTimeout() {
			b.mu.Unlock()
			return ErrCircuitOpen
		}
		// Timeout elapsed — allow a single probe.
		b.current = stateHalfOpen
	case stateHalfOpen:
		// A probe is already in flight; reject concurrent requests.
		b.mu.Unlock()
		return ErrCircuitOpen
	}
	b.mu.Unlock()

	err := fn()

	b.mu.Lock()
	defer b.mu.Unlock()

	if err != nil {
		b.failures++
		b.lastFailure = time.Now()
		if b.failures >= b.opts.resolvedThreshold() {
			b.current = stateOpen
		}
		return err
	}

	// Success — reset to healthy state.
	b.failures = 0
	b.current = stateClosed
	return nil
}

// State returns "closed", "half-open", or "open" for health and metrics endpoints.
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current.String()
}

// Failures returns the current consecutive failure count.
func (b *Breaker) Failures() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}
