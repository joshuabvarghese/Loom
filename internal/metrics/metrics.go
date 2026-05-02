// Package metrics exposes Prometheus metrics for the Loom proxy.
//
// Import this package for its side effects — registering the collectors —
// then call Handler() to mount the scrape endpoint.
//
// Usage in main.go:
//
//	import "github.com/joshuabvarghese/loom/internal/metrics"
//	...
//	http.Handle("/metrics", metrics.Handler())
//	metrics.RecordCall(method, statusCode, durationMs)
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// proxyRequestsTotal counts completed RPC calls, labelled by method and
	// gRPC status code name (e.g. "OK", "UNAVAILABLE").
	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "proxy_requests_total",
			Help:      "Total number of gRPC calls proxied.",
		},
		[]string{"method", "status"},
	)

	// proxyLatencyMs tracks end-to-end proxy latency in milliseconds.
	proxyLatencyMs = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "loom",
			Name:      "proxy_latency_ms",
			Help:      "End-to-end proxy latency in milliseconds.",
			// Buckets suitable for gRPC: <1 ms fast path up to 30 s timeout.
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 30000},
		},
		[]string{"method"},
	)

	// activeSessions is a gauge of currently open proxy connections.
	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "loom",
			Name:      "active_sessions",
			Help:      "Number of in-flight gRPC calls being proxied right now.",
		},
	)

	// mutationsTotal counts how many calls had at least one mutation applied.
	mutationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "mutations_total",
			Help:      "Number of calls where mutation rules fired.",
		},
		[]string{"method", "direction"},
	)

	// circuitBreakerState exports the circuit-breaker state as a gauge.
	// 0 = closed (healthy), 1 = half-open, 2 = open (shedding load).
	circuitBreakerState = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "loom",
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state: 0=closed 1=half-open 2=open.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		proxyRequestsTotal,
		proxyLatencyMs,
		activeSessions,
		mutationsTotal,
		circuitBreakerState,
	)
}

// Handler returns an http.Handler for the /metrics scrape endpoint.
func Handler() http.Handler {
	return promhttp.Handler()
}

// SessionStart increments the active-sessions gauge. Call at the start of
// ServeHTTP and defer SessionEnd.
func SessionStart() {
	activeSessions.Inc()
}

// SessionEnd decrements the active-sessions gauge.
func SessionEnd() {
	activeSessions.Dec()
}

// RecordCall records a completed proxy call.
//
//	method     — full gRPC method path, e.g. "/user.UserService/GetUser"
//	statusName — gRPC status name, e.g. "OK", "UNAVAILABLE"
//	durationMs — end-to-end latency in milliseconds
func RecordCall(method, statusName string, durationMs float64) {
	proxyRequestsTotal.WithLabelValues(method, statusName).Inc()
	proxyLatencyMs.WithLabelValues(method).Observe(durationMs)
}

// RecordMutation records that a mutation fired for method in direction
// ("request" or "response").
func RecordMutation(method, direction string) {
	mutationsTotal.WithLabelValues(method, direction).Inc()
}

// SetCircuitBreakerState updates the circuit-breaker gauge.
// state must be one of "closed", "half-open", "open".
func SetCircuitBreakerState(state string) {
	switch state {
	case "closed":
		circuitBreakerState.Set(0)
	case "half-open":
		circuitBreakerState.Set(1)
	case "open":
		circuitBreakerState.Set(2)
	}
}
