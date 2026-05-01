// Package circuitbreaker provides a simple three-state circuit breaker for
// protecting backend connections from cascading failures.
//
// States:
//   - Closed   — normal operation; all calls pass through.
//   - Open     — consecutive failures exceeded Threshold; calls are rejected
//                immediately with ErrCircuitOpen to shed load fast.
//   - HalfOpen — Timeout has elapsed since the last failure; one probe call
//                is allowed through to test whether the backend recovered.
//
// Typical usage:
//
//	cb := circuitbreaker.New() // Threshold=5, Timeout=30s
//	err := cb.Call(func() error {
//	    return doBackendRequest()
//	})
//	if errors.Is(err, circuitbreaker.ErrCircuitOpen) {
//	    // fast-path rejection — backend is known-bad
//	}
package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit is open and calls are being shed.
var ErrCircuitOpen = errors.New("circuit breaker open: backend unavailable")

// state is the internal finite-state-machine state of the breaker.
type state int

const (
	stateClosed   state = iota // normal — calls pass through
	stateOpen                  // tripped — calls rejected immediately
	stateHalfOpen              // probe window — one call allowed through
)

// Breaker is a thread-safe circuit breaker.
//
// Zero value is not usable; construct with New().
type Breaker struct {
	mu          sync.Mutex
	current     state
	failures    int
	lastFailure time.Time

	// Threshold is the number of consecutive failures that trip the circuit.
	// Defaults to 5 when New() is used.
	Threshold int

	// Timeout is how long the circuit stays open before allowing one probe
	// call through (transitioning to HalfOpen).
	// Defaults to 30 seconds when New() is used.
	Timeout time.Duration
}

// New returns a Breaker with production-ready defaults:
//   - Threshold = 5 consecutive failures
//   - Timeout   = 30 seconds in the open state before probing
func New() *Breaker {
	return &Breaker{
		Threshold: 5,
		Timeout:   30 * time.Second,
	}
}

// Call executes fn if the circuit allows it.
//
//   - Closed:   fn is called normally.
//   - Open:     ErrCircuitOpen is returned without calling fn, unless Timeout
//               has elapsed, in which case the circuit moves to HalfOpen and
//               fn is called as a probe.
//   - HalfOpen: a probe is already in flight; concurrent callers receive
//               ErrCircuitOpen to prevent thundering-herd on recovery.
//
// On success, the failure counter resets and the circuit closes.
// On failure, the failure counter increments; once it reaches the threshold
// the circuit opens.
func (b *Breaker) Call(fn func() error) error {
	b.mu.Lock()
	switch b.current {
	case stateOpen:
		if time.Since(b.lastFailure) < b.timeout() {
			b.mu.Unlock()
			return ErrCircuitOpen
		}
		// Timeout elapsed — allow exactly one probe through.
		b.current = stateHalfOpen

	case stateHalfOpen:
		// A probe is already in flight; shed this concurrent caller.
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
		if b.failures >= b.threshold() {
			b.current = stateOpen
		}
		return err
	}

	// Successful call — reset to fully closed.
	b.failures = 0
	b.current = stateClosed
	return nil
}

// State returns a human-readable description of the current circuit state.
// The return value is one of "closed", "half-open", or "open".
// It is safe to call concurrently and is used by the health checker.
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.current {
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// ── private helpers ────────────────────────────────────────────────────────────

// threshold returns the effective failure threshold, applying the default (5)
// when the caller left Threshold at its zero value.
func (b *Breaker) threshold() int {
	if b.Threshold > 0 {
		return b.Threshold
	}
	return 5
}

// timeout returns the effective open-state timeout, applying the default
// (30 s) when the caller left Timeout at its zero value.
func (b *Breaker) timeout() time.Duration {
	if b.Timeout > 0 {
		return b.Timeout
	}
	return 30 * time.Second
}
