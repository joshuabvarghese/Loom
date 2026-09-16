package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "proxy_requests_total",
			Help:      "Total number of gRPC calls proxied, by method and status.",
		},
		[]string{"method", "status"},
	)

	// Buckets span sub-millisecond fast paths up to the 30s proxy timeout.
	proxyLatencyMs = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "loom",
			Name:      "proxy_latency_ms",
			Help:      "End-to-end proxy latency in milliseconds.",
			Buckets:   []float64{0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 30000},
		},
		[]string{"method"},
	)

	activeSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "loom",
			Name:      "active_sessions",
			Help:      "Number of gRPC calls currently being proxied.",
		},
	)

	mutationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "loom",
			Name:      "mutations_total",
			Help:      "Number of proxied calls where a mutation rule was applied.",
		},
		[]string{"method", "direction"},
	)

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

func Handler() http.Handler {
	return promhttp.Handler()
}

func SessionStart() { activeSessions.Inc() }

func SessionEnd() { activeSessions.Dec() }

func RecordCall(method, statusName string, durationMs float64) {
	proxyRequestsTotal.WithLabelValues(method, statusName).Inc()
	proxyLatencyMs.WithLabelValues(method).Observe(durationMs)
}

func RecordMutation(method, direction string) {
	mutationsTotal.WithLabelValues(method, direction).Inc()
}

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
