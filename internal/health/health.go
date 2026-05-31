// Package health provides HTTP health-check handlers for Loom.
//
// /live is always 200 while the process is running (k8s liveness).
// /ready returns 503 if the circuit breaker is open (k8s readiness).
// /health gives a combined JSON summary for dashboards.
//
//   - /ready — readiness: 200 only when the backend is connected.
//     Kubernetes uses this to decide whether to route traffic.
//
//   - /health — combined: 200 when healthy, 503 when the backend is
//     disconnected or the circuit breaker is open. Useful for ops dashboards.
//
// Usage:
//
//	hc := health.New()
//	hc.SetBackendReady(true)        // call after backend connection succeeds
//	hc.SetCircuitBreaker(cb)        // optional — wires circuit breaker state
//
//	mux.Handle("/live",   hc.LiveHandler())
//	mux.Handle("/ready",  hc.ReadyHandler())
//	mux.Handle("/health", hc.Handler())
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

// Checker holds operational health state.
type Checker struct {
	backendReady atomic.Bool
	cb           CircuitBreakerStatus
	startTime    time.Time
}

// New returns a Checker. It starts in "not ready" state until SetBackendReady(true).
func New() *Checker {
	return &Checker{startTime: time.Now()}
}

// SetBackendReady marks whether the backend gRPC connection is currently healthy.
func (c *Checker) SetBackendReady(ok bool) {
	c.backendReady.Store(ok)
}

// SetCircuitBreaker wires a circuit breaker whose state is included in /health responses.
func (c *Checker) SetCircuitBreaker(cb CircuitBreakerStatus) {
	c.cb = cb
}

// LiveHandler returns 200 as long as the process is running.
func (c *Checker) LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "alive",
			"uptime": time.Since(c.startTime).Round(time.Second).String(),
		})
	})
}

// ReadyHandler returns 200 when the backend connection is established,
// or 503 when it is not.
func (c *Checker) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

// Handler returns a combined health payload.
//
// HTTP 200 when healthy; 503 when backend is down or circuit breaker is open.
// The JSON body always includes status, uptime, backend connection state,
// and circuit breaker state.
func (c *Checker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendOK := c.backendReady.Load()
		cbState := "n/a"
		if c.cb != nil {
			cbState = c.cb.State()
		}

		status := "ok"
		code := http.StatusOK
		if !backendOK || cbState == "open" {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		writeJSON(w, code, map[string]any{
			"status":          status,
			"uptime":          time.Since(c.startTime).Round(time.Second).String(),
			"backend":         connectionState(backendOK),
			"circuit_breaker": cbState,
		})
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func connectionState(connected bool) string {
	if connected {
		return "connected"
	}
	return "disconnected"
}
