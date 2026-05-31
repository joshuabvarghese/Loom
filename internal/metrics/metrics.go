// Package metrics registers and exposes Prometheus metrics for Loom.
//
// Import this package for its side-effects (collector registration), then
// mount Handler() on the UI server's /metrics path.
//
//	import "github.com/joshuabvarghese/loom/internal/metrics"
//
//	mux.Handle("/metrics", metrics.Handler())
//
// Instrument the proxy by calling the record helpers at the end of each call:
//
//	metrics.SessionStart()
//	defer metrics.SessionEnd()
//	// ... proxy logic ...
//	metrics.RecordCall(method, statusName, durationMs)
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// proxyRequestsTotal counts completed RPC calls, labeled by gRPC method
	// path and gRPC status name (e.g. "OK", "UNAVAILABLE").
	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "proxy_requests_total",
			Help:      "Total number of gRPC calls proxied, by method and status.",
		},
		[]string{"method", "status"},
	)

	// proxyLatencyMs measures end-to-end proxy latency in milliseconds,
	// labeled by gRPC method path.
	proxyLatencyMs = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "loom",
			Name:      "proxy_latency_ms",
			Help:      "End-to-end proxy latency in milliseconds.",
			// Buckets cover sub-millisecond fast paths through 30-second timeouts.
			Buckets: []float64{0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 30000},
		},
		[]string{"method"},
	)

	// activeSessions tracks the number of gRPC calls currently in flight.
	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "loom",
			Name:      "active_sessions",
			Help:      "Number of gRPC calls currently being proxied.",
		},
	)

	// mutationsTotal counts calls where at least one mutation rule fired,
	// labeled by method and direction ("request" or "response").
	mutationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "mutations_total",
			Help:      "Number of proxied calls where a mutation rule was applied.",
		},
		[]string{"method", "direction"},
	)

	// circuitBreakerState tracks the circuit breaker state as a gauge.
	// 0 = closed (healthy), 1 = half-open (probing), 2 = open (shedding load).
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

// Handler returns an http.Handler that serves the Prometheus /metrics scrape endpoint.
func Handler() http.Handler {
	return promhttp.Handler()
}

// SessionStart increments the in-flight sessions gauge.
// Call at the top of ServeHTTP and pair with a deferred SessionEnd.
func SessionStart() { activeSessions.Inc() }

// SessionEnd decrements the in-flight sessions gauge.
func SessionEnd() { activeSessions.Dec() }

// RecordCall records a completed proxy call.
//
//   - method     — full gRPC method path, e.g. "/user.UserService/GetUser"
//   - statusName — gRPC status name, e.g. "OK", "UNAVAILABLE"
//   - durationMs — end-to-end latency in milliseconds
func RecordCall(method, statusName string, durationMs float64) {
	proxyRequestsTotal.WithLabelValues(method, statusName).Inc()
	proxyLatencyMs.WithLabelValues(method).Observe(durationMs)
}

// RecordMutation records that a mutation rule fired for method in direction
// (pass "request" or "response").
func RecordMutation(method, direction string) {
	mutationsTotal.WithLabelValues(method, direction).Inc()
}

// SetCircuitBreakerState updates the circuit-breaker gauge.
// state must be one of "closed", "half-open", or "open".
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
