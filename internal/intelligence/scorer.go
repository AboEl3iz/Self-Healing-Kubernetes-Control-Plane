// Package intelligence — scorer.go implements the NodeHealthScorer.
//
// The health score is a real-valued metric in [0.0, 1.0] representing the
// reliability of a node as observed by the self-healing system:
//
//	1.0 = perfectly healthy, no autonomous actions needed
//	0.7 = some anomalies, under control (amber)
//	< 0.4 = degraded — recommend cordon_node (red)
//
// Score formula per node (updated on every anomaly or outcome event):
//
//	score = 1.0
//	      − (anomaly_rate_factor  × 0.40)   // how often are pods anomalous?
//	      − (unresolved_factor    × 0.35)   // fraction of anomalies unresolved?
//	      − (escalation_factor    × 0.25)   // fraction that reached cordon/manual?
//
// Where:
//   anomaly_rate_factor  = min(1, anomalies_in_last_hour / 10)
//   unresolved_factor    = unresolved_count / max(total_count, 1)
//   escalation_factor    = escalated_count / max(total_count, 1)
//
// Score decays every 5 minutes by a small amount if no new data arrives,
// recovering toward 1.0 slowly (avoids stale unhealthy scores).

package intelligence

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// HealthThresholdCordon is the score below which a cordon recommendation is raised.
	HealthThresholdCordon = 0.40
	// HealthThresholdAmber is the score below which a warning is emitted.
	HealthThresholdAmber = 0.70
)

// nodeStats holds running statistics for a single node.
type nodeStats struct {
	totalAnomalies    int
	unresolvedCount   int
	escalatedCount    int
	anomalyTimestamps []time.Time // rolling 1-hour window
	lastUpdated       time.Time
}

// NodeScore is the output of Scorer.Score().
type NodeScore struct {
	NodeName string
	Score    float64
	Tier     string // "healthy", "amber", "unhealthy"
}

// NodeHealthScorer computes and tracks health scores for every node.
// All methods are thread-safe.
type NodeHealthScorer struct {
	mu     sync.RWMutex
	stats  map[string]*nodeStats // nodeID → stats
	logger *slog.Logger
}

// NewNodeHealthScorer creates a NodeHealthScorer.
func NewNodeHealthScorer(logger *slog.Logger) *NodeHealthScorer {
	return &NodeHealthScorer{
		stats:  make(map[string]*nodeStats),
		logger: logger,
	}
}

// RecordAnomaly records a new anomaly observation for the given node.
// Call this whenever an AnomalyEntry is received for a node.
func (s *NodeHealthScorer) RecordAnomaly(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.getOrCreate(nodeID)
	now := time.Now()
	ns.totalAnomalies++
	ns.unresolvedCount++
	ns.anomalyTimestamps = append(ns.anomalyTimestamps, now)
	ns.lastUpdated = now
	s.emitMetric(nodeID, ns)
}

// RecordOutcome updates the stats when an outcome is known.
// outcome: "resolved", "escalated", "failed"
func (s *NodeHealthScorer) RecordOutcome(nodeID, outcome string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.getOrCreate(nodeID)
	switch outcome {
	case "resolved":
		if ns.unresolvedCount > 0 {
			ns.unresolvedCount--
		}
	case "escalated", "cordon":
		if ns.unresolvedCount > 0 {
			ns.unresolvedCount--
		}
		ns.escalatedCount++
	}
	ns.lastUpdated = time.Now()
	s.emitMetric(nodeID, ns)
}

// Score computes the current health score for the given node.
// Returns 1.0 (fully healthy) if the node has no history.
func (s *NodeHealthScorer) Score(nodeID string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ns, ok := s.stats[nodeID]
	if !ok {
		return 1.0
	}
	return computeScore(ns)
}

// AllScores returns the health score for every tracked node.
func (s *NodeHealthScorer) AllScores() []NodeScore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]NodeScore, 0, len(s.stats))
	for nodeID, ns := range s.stats {
		score := computeScore(ns)
		result = append(result, NodeScore{
			NodeName: nodeID,
			Score:    score,
			Tier:     tier(score),
		})
	}
	return result
}

// UnhealthyNodes returns all nodes with a score below the given threshold,
// sorted descending by severity (lowest score first).
func (s *NodeHealthScorer) UnhealthyNodes(threshold float64) []NodeScore {
	all := s.AllScores()
	var unhealthy []NodeScore
	for _, ns := range all {
		if ns.Score < threshold {
			unhealthy = append(unhealthy, ns)
		}
	}
	// Sort: lowest score first (most critical).
	for i := 1; i < len(unhealthy); i++ {
		for j := i; j > 0 && unhealthy[j].Score < unhealthy[j-1].Score; j-- {
			unhealthy[j], unhealthy[j-1] = unhealthy[j-1], unhealthy[j]
		}
	}
	return unhealthy
}

// DecayAll applies a small score recovery to all nodes that have not had a new
// anomaly in the last 15 minutes. Call periodically (e.g., every 5 minutes).
func (s *NodeHealthScorer) DecayAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	for nodeID, ns := range s.stats {
		if ns.lastUpdated.Before(cutoff) {
			// Reduce unresolved count slightly — the situation is improving.
			if ns.unresolvedCount > 0 {
				ns.unresolvedCount--
			}
		}
		s.emitMetric(nodeID, ns)
	}
}

// ─── Internals ────────────────────────────────────────────────────────────────

func (s *NodeHealthScorer) getOrCreate(nodeID string) *nodeStats {
	ns, ok := s.stats[nodeID]
	if !ok {
		ns = &nodeStats{lastUpdated: time.Now()}
		s.stats[nodeID] = ns
	}
	return ns
}

func (s *NodeHealthScorer) emitMetric(nodeID string, ns *nodeStats) {
	score := computeScore(ns)
	RecordNodeHealth(nodeID, score)
	if score < HealthThresholdCordon {
		s.logger.Warn("intelligence: node health score below cordon threshold",
			"node", nodeID,
			"score", score,
			"unresolved", ns.unresolvedCount,
			"escalated", ns.escalatedCount,
		)
	}
}

// computeScore is the pure scoring function — safe to call under RLock.
func computeScore(ns *nodeStats) float64 {
	// Prune anomaly timestamps older than 1 hour.
	cutoff := time.Now().Add(-1 * time.Hour)
	fresh := ns.anomalyTimestamps[:0]
	for _, t := range ns.anomalyTimestamps {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	ns.anomalyTimestamps = fresh

	total := ns.totalAnomalies
	if total == 0 {
		return 1.0
	}

	// Factor 1: anomaly frequency in the last hour (capped at 10 → factor=1.0).
	anomalyRateFactor := float64(len(fresh)) / 10.0
	if anomalyRateFactor > 1.0 {
		anomalyRateFactor = 1.0
	}

	// Factor 2: fraction still unresolved.
	unresolvedFactor := float64(ns.unresolvedCount) / float64(total)
	if unresolvedFactor > 1.0 {
		unresolvedFactor = 1.0
	}

	// Factor 3: fraction that escalated to cordon/manual.
	escalationFactor := float64(ns.escalatedCount) / float64(total)
	if escalationFactor > 1.0 {
		escalationFactor = 1.0
	}

	score := 1.0 -
		(anomalyRateFactor * 0.40) -
		(unresolvedFactor * 0.35) -
		(escalationFactor * 0.25)

	if score < 0.0 {
		return 0.0
	}
	return score
}

func tier(score float64) string {
	switch {
	case score < HealthThresholdCordon:
		return "unhealthy"
	case score < HealthThresholdAmber:
		return "amber"
	default:
		return "healthy"
	}
}
