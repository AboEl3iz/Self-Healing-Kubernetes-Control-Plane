// Package telemetry provides Prometheus metrics for the SelfHeal-CP system.
//
// Metric naming convention: selfheal_<component>_<name>_<unit>
//
// All metrics are registered here. Each component imports this package
// and calls the appropriate counter/gauge/histogram.
//
// Prometheus endpoint: exposed via HTTP /metrics on configurable port.
//
// TODO(Phase 2): Implement actual metric registration and exposition.

package telemetry

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all registered Prometheus metrics for SelfHeal-CP.
type Metrics struct {
	// ─── Agent (Layer 1) ────────────────────────────────────────────────────
	// Total raw eBPF signals emitted
	SignalsTotal *prometheus.CounterVec

	// ─── Analyzer (Layer 2) ─────────────────────────────────────────────────
	// Anomalies detected and scored
	AnomaliesDetectedTotal *prometheus.CounterVec
	// Confidence score distribution per anomaly type
	ConfidenceScore *prometheus.HistogramVec
	// False positives (suppressed due to low confidence)
	FalsePositivesTotal *prometheus.CounterVec

	// ─── Controller (Layer 3) ───────────────────────────────────────────────
	// Actions dispatched to Kubernetes
	ActionsDispatchedTotal *prometheus.CounterVec
	// Actions that resulted in resolution
	ActionsResolvedTotal *prometheus.CounterVec
	// Time from action dispatch to resolution
	ActionLatencyMs *prometheus.HistogramVec
	// Pod restart counter (live gauge)
	PodRestartCount *prometheus.GaugeVec
}

// Register creates and registers all Prometheus metrics.
// Call once at startup in each component.
func Register() *Metrics {
	return &Metrics{
		SignalsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "selfheal_signals_total",
				Help: "Total raw eBPF signal events emitted by the agent",
			},
			[]string{"node", "metric", "pod"},
		),

		AnomaliesDetectedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "selfheal_anomalies_detected_total",
				Help: "Total anomalies detected by the heuristics engine",
			},
			[]string{"type", "namespace"},
		),

		ConfidenceScore: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "selfheal_confidence_score",
				Help:    "Confidence score distribution per anomaly type",
				Buckets: []float64{0.3, 0.5, 0.6, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 1.0},
			},
			[]string{"anomaly_type"},
		),

		FalsePositivesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "selfheal_false_positives_total",
				Help: "Anomalies suppressed due to insufficient confidence",
			},
			[]string{"anomaly_type"},
		),

		ActionsDispatchedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "selfheal_actions_dispatched_total",
				Help: "Total healing actions dispatched to Kubernetes",
			},
			[]string{"action", "namespace"},
		),

		ActionsResolvedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "selfheal_actions_resolved_total",
				Help: "Total actions that resulted in anomaly resolution",
			},
			[]string{"action", "resolution_type"},
		),

		ActionLatencyMs: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "selfheal_action_latency_ms",
				Help:    "Time from action dispatch to anomaly resolution (ms)",
				Buckets: []float64{100, 500, 1000, 5000, 15000, 30000, 60000, 120000},
			},
			[]string{"action"},
		),

		PodRestartCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "selfheal_pod_restart_count",
				Help: "Current restart count per pod (gauge, resets on pod delete)",
			},
			[]string{"pod", "namespace"},
		),
	}
}

// ServeMetrics starts the Prometheus HTTP /metrics endpoint.
func ServeMetrics(addr string, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	logger.Info("prometheus metrics serving", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("metrics server failed", "error", err)
	}
}
