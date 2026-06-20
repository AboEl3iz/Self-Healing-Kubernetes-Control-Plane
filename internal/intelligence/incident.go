// Package intelligence — incident.go defines the IncidentEvent type and its
// Prometheus metrics.
//
// An IncidentEvent is emitted when the Reasoner determines that multiple pods on
// the same node share a common root cause. It is published to:
//
//	NATS:       selfheal.incidents.<namespace>
//	Prometheus: selfheal_node_incident_confidence{node, root_cause}
//	Prometheus: selfheal_node_incidents_total{node, root_cause}
//
// Consumers:
//   - Phase 3 controller (subscribed to selfheal.incidents.*) maps incidents
//     to cordon_node actions after guardrail checks.
//   - Grafana cluster health dashboard.

package intelligence

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ─── Root Cause types ─────────────────────────────────────────────────────────

// RootCause is the inferred cause of a node-level incident.
type RootCause string

const (
	RootCauseDegradedDisk      RootCause = "degraded_disk"
	RootCauseNetworkPartition  RootCause = "network_partition"
	RootCauseCPUStarvation     RootCause = "cpu_starvation"
	RootCauseMemoryPressure    RootCause = "memory_pressure"
	RootCauseUnknown           RootCause = "unknown"
)

// ─── PodRef ───────────────────────────────────────────────────────────────────

// PodRef identifies one of the pods involved in an incident.
type PodRef struct {
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Deployment string   `json:"deployment,omitempty"`
	Signals    []string `json:"signals"` // active anomaly signals for this pod
}

// ─── IncidentEvent ────────────────────────────────────────────────────────────

// IncidentEvent is published when the Reasoner determines that multiple pods on
// the same node share a common root cause.
type IncidentEvent struct {
	IncidentID      string            `json:"incident_id"`
	RootCause       RootCause         `json:"root_cause"`
	RootCauseConf   float64           `json:"root_cause_confidence"` // 0.0–1.0
	AffectedNode    string            `json:"affected_node"`
	AffectedPods    []PodRef          `json:"affected_pods"`
	SignalSummary   map[string]int    `json:"signal_summary"` // signal → count
	SharedVolumes   []string          `json:"shared_volumes,omitempty"`
	SuggestedAction string            `json:"suggested_action"`
	Namespace       string            `json:"namespace"`
	DetectedAt      time.Time         `json:"detected_at"`
	Timestamp       int64             `json:"timestamp"` // Unix ms
}

// ─── NodeIncident (internal) ──────────────────────────────────────────────────

// AnomalyEntry is one anomaly record collected by the Aggregator.
type AnomalyEntry struct {
	PodName    string
	Namespace  string
	Deployment string
	NodeName   string
	Signals    []string // active_signals from AnomalyEvent
	Confidence float64
	ReceivedAt time.Time
}

// NodeIncident is the internal aggregation result from the Aggregator.
// The Reasoner converts it into a full IncidentEvent.
type NodeIncident struct {
	NodeName    string
	Anomalies   []AnomalyEntry
	WindowStart time.Time
	WindowEnd   time.Time
}

// ─── Prometheus Metrics ───────────────────────────────────────────────────────

var (
	// nodeIncidentConf is a gauge tracking the current root cause confidence per node.
	nodeIncidentConf = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "selfheal_node_incident_confidence",
		Help: "Root cause confidence score for the most recent node incident (0.0–1.0)",
	}, []string{"node", "root_cause"})

	// nodeIncidentsTotal counts all incidents emitted per node and root cause.
	nodeIncidentsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "selfheal_node_incidents_total",
		Help: "Total node incidents attributed by the causal reasoning engine",
	}, []string{"node", "root_cause"})

	// nodeHealthScore is a gauge for each node's current health score.
	nodeHealthGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "selfheal_node_health_score",
		Help: "Current health score for each node (0.0=unhealthy, 1.0=healthy)",
	}, []string{"node"})
)

// RecordIncidentMetrics emits Prometheus metrics for an IncidentEvent.
func RecordIncidentMetrics(ev IncidentEvent) {
	rc := string(ev.RootCause)
	nodeIncidentConf.WithLabelValues(ev.AffectedNode, rc).Set(ev.RootCauseConf)
	nodeIncidentsTotal.WithLabelValues(ev.AffectedNode, rc).Inc()
}

// RecordNodeHealth emits the current health score for a node.
func RecordNodeHealth(node string, score float64) {
	nodeHealthGauge.WithLabelValues(node).Set(score)
}
