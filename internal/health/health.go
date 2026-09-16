package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

type CircuitBreakerStatus interface {
	State() string
}

type Checker struct {
	backendReady atomic.Bool
	cb           CircuitBreakerStatus
	startTime    time.Time
}

func New() *Checker {
	return &Checker{startTime: time.Now()}
}

func (c *Checker) SetBackendReady(ok bool) {
	c.backendReady.Store(ok)
}

func (c *Checker) SetCircuitBreaker(cb CircuitBreakerStatus) {
	c.cb = cb
}

func (c *Checker) LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "alive",
			"uptime": c.uptime(),
		})
	})
}

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

func (c *Checker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendOK := c.backendReady.Load()
		cbState := c.circuitBreakerState()

		status, code := "ok", http.StatusOK
		if isDegraded(backendOK, cbState) {
			status, code = "degraded", http.StatusServiceUnavailable
		}

		writeJSON(w, code, map[string]any{
			"status":          status,
			"uptime":          c.uptime(),
			"backend":         connectionState(backendOK),
			"circuit_breaker": cbState,
		})
	})
}

func (c *Checker) uptime() string {
	return time.Since(c.startTime).Round(time.Second).String()
}

func (c *Checker) circuitBreakerState() string {
	if c.cb == nil {
		return "n/a"
	}
	return c.cb.State()
}

func isDegraded(backendOK bool, cbState string) bool {
	return !backendOK || cbState == "open"
}

func connectionState(connected bool) string {
	if connected {
		return "connected"
	}
	return "disconnected"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
