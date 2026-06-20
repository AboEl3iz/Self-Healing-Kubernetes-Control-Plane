// Package intelligence — reasoner.go is the causal graph traversal engine.
//
// The Reasoner receives a NodeIncident from the Aggregator and determines:
//   - What is the root cause? (disk, network, CPU, memory, unknown)
//   - What confidence does the attribution have?
//   - Are there shared PVCs that confirm the root cause?
//   - What action should be recommended?
//
// # Root Cause Classification (deterministic, no ML)
//
// Signal patterns → root cause:
//
//	io_wait_high + disk_io_lat on ≥60% of pods → degraded_disk     (conf=0.80)
//	tcp_retransmit on ≥60% of pods             → network_partition  (conf=0.75)
//	cpu_runqueue_delay on ≥60% of pods         → cpu_starvation     (conf=0.75)
//	oom_kill + memory_pressure on ≥60% of pods → memory_pressure    (conf=0.80)
//	no majority pattern                        → unknown            (conf=0.50)
//
// Shared PVCs add a +0.10 confidence boost (confirms the disk root cause).
//
// # Integration
//
// The Reasoner emits an IncidentEvent to:
//   1. NATS selfheal.incidents.<namespace>  (consumed by Phase 3 controller)
//   2. Prometheus metrics (via RecordIncidentMetrics)
//   3. Node health scorer (via NodeHealthScorer.RecordAnomaly)

package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
)

// ─── Signal pattern definitions ───────────────────────────────────────────────

// signalPattern maps a group of signals to a root cause with a base confidence.
type signalPattern struct {
	signals    []string
	rootCause  RootCause
	baseConf   float64
	suggestion string // suggested_action
}

// rootCausePatterns is evaluated in priority order.
var rootCausePatterns = []signalPattern{
	{
		signals:    []string{"io_wait_high", "disk_io_lat"},
		rootCause:  RootCauseDegradedDisk,
		baseConf:   0.80,
		suggestion: "cordon_node",
	},
	{
		signals:    []string{"tcp_retransmit"},
		rootCause:  RootCauseNetworkPartition,
		baseConf:   0.75,
		suggestion: "investigate_network",
	},
	{
		signals:    []string{"cpu_runqueue_delay"},
		rootCause:  RootCauseCPUStarvation,
		baseConf:   0.75,
		suggestion: "cordon_node",
	},
	{
		signals:    []string{"oom_kill"},
		rootCause:  RootCauseMemoryPressure,
		baseConf:   0.80,
		suggestion: "patch_resource_limits",
	},
}

// MajorityThreshold: fraction of pods that must show a signal to count.
const MajorityThreshold = 0.6

// SharedVolumeConfidenceBoost is added when affected pods share a PVC.
const SharedVolumeConfidenceBoost = 0.10

// ─── Reasoner ─────────────────────────────────────────────────────────────────

// Reasoner converts NodeIncidents into fully-attributed IncidentEvents.
type Reasoner struct {
	graph     *DependencyGraph
	scorer    *NodeHealthScorer
	publisher *bus.Publisher
	logger    *slog.Logger
}

// NewReasoner creates a Reasoner.
func NewReasoner(
	graph *DependencyGraph,
	scorer *NodeHealthScorer,
	publisher *bus.Publisher,
	logger *slog.Logger,
) *Reasoner {
	return &Reasoner{
		graph:     graph,
		scorer:    scorer,
		publisher: publisher,
		logger:    logger,
	}
}

// Analyse receives a NodeIncident and emits an IncidentEvent.
// Satisfies the IncidentHandler type expected by Aggregator.
func (r *Reasoner) Analyse(ctx context.Context, incident NodeIncident) {
	ev, err := r.classify(incident)
	if err != nil {
		r.logger.Warn("reasoner: failed to classify incident", "node", incident.NodeName, "error", err)
		return
	}

	r.logger.Info("reasoner: incident attributed",
		"node", ev.AffectedNode,
		"root_cause", ev.RootCause,
		"confidence", fmt.Sprintf("%.2f", ev.RootCauseConf),
		"affected_pods", len(ev.AffectedPods),
		"suggestion", ev.SuggestedAction,
	)

	// Update node health score.
	nodeID := NodeID(incident.NodeName)
	for range incident.Anomalies {
		r.scorer.RecordAnomaly(nodeID)
	}

	// Emit Prometheus metrics.
	RecordIncidentMetrics(*ev)

	// Publish to NATS if we have a publisher.
	if r.publisher != nil {
		if err := r.publishIncident(ctx, ev); err != nil {
			r.logger.Error("reasoner: failed to publish IncidentEvent", "error", err)
		}
	}
}

// classify is the pure classification logic — used directly in tests.
func (r *Reasoner) classify(incident NodeIncident) (*IncidentEvent, error) {
	if len(incident.Anomalies) == 0 {
		return nil, fmt.Errorf("reasoner: empty incident")
	}

	n := len(incident.Anomalies)
	// Build signal frequency map across all affected pods.
	signalCounts := make(map[string]int)
	for _, a := range incident.Anomalies {
		for _, sig := range a.Signals {
			signalCounts[sig]++
		}
	}

	// Build PodRef list.
	pods := make([]PodRef, 0, n)
	podIDs := make([]string, 0, n)
	namespaceSet := make(map[string]struct{})
	for _, a := range incident.Anomalies {
		pods = append(pods, PodRef{
			Name:       a.PodName,
			Namespace:  a.Namespace,
			Deployment: a.Deployment,
			Signals:    a.Signals,
		})
		podIDs = append(podIDs, PodID(a.Namespace, a.PodName))
		namespaceSet[a.Namespace] = struct{}{}
	}

	// Use the first namespace as the incident namespace (or "cluster" if cross-NS).
	ns := incident.Anomalies[0].Namespace
	if len(namespaceSet) > 1 {
		ns = "cluster"
	}

	// Match root cause patterns.
	rootCause := RootCauseUnknown
	baseConf := 0.50
	suggestion := "investigate_node"
	for _, pattern := range rootCausePatterns {
		if patternMatchesMajority(pattern.signals, signalCounts, n) {
			rootCause = pattern.rootCause
			baseConf = pattern.baseConf
			suggestion = pattern.suggestion
			break
		}
	}

	// Confidence = base × (matching_pods_fraction boosted by majority).
	matchFraction := countPodsMeetingPattern(rootCause, incident.Anomalies, rootCausePatterns)
	confidence := baseConf * matchFraction
	if confidence > 1.0 {
		confidence = 1.0
	}

	// Shared PVC boost (confirms disk root cause).
	sharedVolumes := r.graph.SharedVolumes(podIDs)
	if len(sharedVolumes) > 0 && rootCause == RootCauseDegradedDisk {
		confidence = clampF(confidence+SharedVolumeConfidenceBoost, 0, 1)
		r.logger.Info("reasoner: shared PVCs confirm disk root cause",
			"volumes", sharedVolumes,
			"confidence_boost", SharedVolumeConfidenceBoost,
		)
	}

	ev := &IncidentEvent{
		IncidentID:      uuid.New().String(),
		RootCause:       rootCause,
		RootCauseConf:   confidence,
		AffectedNode:    incident.NodeName,
		AffectedPods:    pods,
		SignalSummary:   signalCounts,
		SharedVolumes:   sharedVolumes,
		SuggestedAction: suggestion,
		Namespace:       ns,
		DetectedAt:      time.Now(),
		Timestamp:       time.Now().UnixMilli(),
	}

	return ev, nil
}

// publishIncident marshals and publishes an IncidentEvent to NATS.
func (r *Reasoner) publishIncident(ctx context.Context, ev *IncidentEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("reasoner: marshal IncidentEvent: %w", err)
	}
	return r.publisher.PublishIncident(ctx, ev.Namespace, data)
}

// ─── Pattern matching helpers ─────────────────────────────────────────────────

// patternMatchesMajority returns true if all pattern signals appear in more
// than MajorityThreshold of the affected pods.
func patternMatchesMajority(signals []string, signalCounts map[string]int, totalPods int) bool {
	threshold := int(float64(totalPods)*MajorityThreshold) + 1
	for _, sig := range signals {
		if signalCounts[sig] < threshold {
			return false
		}
	}
	return true
}

// countPodsMeetingPattern returns the fraction of pods that have at least one
// signal from the matched root cause pattern.
func countPodsMeetingPattern(rc RootCause, anomalies []AnomalyEntry, patterns []signalPattern) float64 {
	// Find the matched pattern.
	var matchedSignals []string
	for _, p := range patterns {
		if p.rootCause == rc {
			matchedSignals = p.signals
			break
		}
	}
	if len(matchedSignals) == 0 || len(anomalies) == 0 {
		return 1.0
	}
	matching := 0
	for _, a := range anomalies {
		for _, sig := range a.Signals {
			for _, pat := range matchedSignals {
				if strings.EqualFold(sig, pat) {
					matching++
					goto nextPod
				}
			}
		}
	nextPod:
	}
	return float64(matching) / float64(len(anomalies))
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ─── Reasoner as a standalone classifier (for tests) ─────────────────────────

// Classify is the exported wrapper for classify(), used by tests.
func (r *Reasoner) Classify(incident NodeIncident) (*IncidentEvent, error) {
	return r.classify(incident)
}
