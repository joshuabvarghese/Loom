// Package health provides /health, /ready, and /live HTTP handlers for
// Kubernetes probes and general operational visibility.
//
// Usage in main.go:
//
//	hc := health.New()
//	hc.SetBackendReady(true)              // call after backend connection succeeds
//	hc.SetCircuitBreaker(cb)              // wire in the circuit breaker
//
//	mux := http.NewServeMux()
//	mux.Handle("/health", hc.Handler())  // combined — used by k8s readiness
//	mux.Handle("/ready",  hc.ReadyHandler())
//	mux.Handle("/live",   hc.LiveHandler())
//	mux.Handle("/metrics", metrics.Handler())
package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// CircuitBreakerStatus is satisfied by circuitbreaker.Breaker.
type CircuitBreakerStatus interface {
	State() string
}

// Checker holds health state.
type Checker struct {
	backendReady atomic.Bool
	cb           CircuitBreakerStatus
	startTime    time.Time
}

// New returns a Checker. It starts in "not ready" state until SetBackendReady(true).
func New() *Checker {
	return &Checker{startTime: time.Now()}
}

// SetBackendReady marks whether the backend gRPC connection is healthy.
func (c *Checker) SetBackendReady(ok bool) {
	c.backendReady.Store(ok)
}

// SetCircuitBreaker wires in a circuit breaker whose state is reported in /health.
func (c *Checker) SetCircuitBreaker(cb CircuitBreakerStatus) {
	c.cb = cb
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// LiveHandler returns 200 as long as the process is running.
// Kubernetes uses this to decide whether to restart the container.
func (c *Checker) LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "alive",
			"uptime": time.Since(c.startTime).String(),
		})
	})
}

// ReadyHandler returns 200 only when Loom is connected to its backend.
// Kubernetes uses this to decide whether to send traffic.
func (c *Checker) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.backendReady.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not ready",
				"reason": "backend not connected",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
}

// Handler returns a combined health payload — handy for ops dashboards.
//   - 200 when healthy
//   - 503 when the backend is down or the circuit breaker is open
func (c *Checker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendOK := c.backendReady.Load()
		cbState := "n/a"
		if c.cb != nil {
			cbState = c.cb.State()
		}

		payload := map[string]any{
			"status":          "ok",
			"uptime":          time.Since(c.startTime).String(),
			"backend":         boolStr(backendOK),
			"circuit_breaker": cbState,
		}

		code := http.StatusOK
		if !backendOK || cbState == "open" {
			payload["status"] = "degraded"
			code = http.StatusServiceUnavailable
		}

		writeJSON(w, code, payload)
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func boolStr(b bool) string {
	if b {
		return "connected"
	}
	return "disconnected"
}
