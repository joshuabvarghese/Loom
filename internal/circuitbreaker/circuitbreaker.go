package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker open: backend unavailable")

type state int

const (
	stateClosed state = iota
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

type Options struct {
	Threshold int
	Timeout   time.Duration
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

type Breaker struct {
	opts        Options
	mu          sync.Mutex
	current     state
	failures    int
	lastFailure time.Time
}

func New(opts Options) *Breaker {
	return &Breaker{opts: opts}
}

func (b *Breaker) Call(fn func() error) error {
	if err := b.admit(); err != nil {
		return err
	}
	err := fn()
	b.recordResult(err)
	return err
}

// Half-open allows exactly one probe through; any concurrent caller while a
// probe is in flight is rejected rather than queued, so a recovering backend
// isn't immediately hit with a burst of retries.
func (b *Breaker) admit() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.current {
	case stateOpen:
		if !b.cooldownElapsed() {
			return ErrCircuitOpen
		}
		b.current = stateHalfOpen
	case stateHalfOpen:
		return ErrCircuitOpen
	}
	return nil
}

func (b *Breaker) cooldownElapsed() bool {
	return time.Since(b.lastFailure) >= b.opts.resolvedTimeout()
}

func (b *Breaker) recordResult(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err == nil {
		b.failures = 0
		b.current = stateClosed
		return
	}

	b.failures++
	b.lastFailure = time.Now()
	if b.failures >= b.opts.resolvedThreshold() {
		b.current = stateOpen
	}
}

func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current.String()
}

func (b *Breaker) Failures() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}
