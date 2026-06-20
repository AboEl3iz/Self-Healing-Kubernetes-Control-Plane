// Package intelligence — aggregator.go groups pod-level AnomalyEvents by the
// node they run on, within a sliding time window.
//
// When ≥ MinPodsThreshold pods on the same node exhibit anomalies within
// the AggregationWindow, the Aggregator emits a NodeIncident for the Reasoner
// to analyse.
//
// Design decisions:
//   - Node is resolved from the DependencyGraph (populated from K8s Informers)
//     so the AnomalyEvent schema does not need a node field.
//   - Aggregator runs as a goroutine. Call Run(ctx) which blocks until context
//     is cancelled. It processes records via Record() called from the NATS
//     subscription callback in the same goroutine (or channels for concurrent use).
//   - Each node window is pruned when all entries fall outside the AggregationWindow.
//   - Flush() is called every FlushInterval to evaluate pending windows.

package intelligence

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/karim-aboelaiz/selfheal-cp/internal/analyzer"
	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
)

// AggregatorConfig controls the Aggregator behavior.
type AggregatorConfig struct {
	// AggregationWindow is how long anomalies are considered "concurrent".
	// Default: 5 minutes.
	AggregationWindow time.Duration
	// FlushInterval is how often to evaluate windows for incidents.
	// Default: 30 seconds.
	FlushInterval time.Duration
	// MinPodsThreshold is the minimum number of affected pods on a node
	// to trigger root cause analysis.
	// Default: 2.
	MinPodsThreshold int
}

// DefaultAggregatorConfig returns production-ready defaults.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		AggregationWindow: 5 * time.Minute,
		FlushInterval:     30 * time.Second,
		MinPodsThreshold:  2,
	}
}

// IncidentHandler is called by the Aggregator when a NodeIncident is ready.
type IncidentHandler func(ctx context.Context, incident NodeIncident)

// Aggregator subscribes to NATS selfheal.anomalies.* and groups AnomalyEvents
// by node within the AggregationWindow.
type Aggregator struct {
	graph      *DependencyGraph
	subscriber *bus.Subscriber
	cfg        AggregatorConfig
	handler    IncidentHandler
	logger     *slog.Logger

	mu      sync.Mutex
	windows map[string][]AnomalyEntry // nodeID → sorted anomaly entries
}

// NewAggregator creates an Aggregator.
func NewAggregator(
	graph *DependencyGraph,
	subscriber *bus.Subscriber,
	cfg AggregatorConfig,
	handler IncidentHandler,
	logger *slog.Logger,
) *Aggregator {
	if cfg.AggregationWindow == 0 {
		cfg.AggregationWindow = 5 * time.Minute
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	if cfg.MinPodsThreshold == 0 {
		cfg.MinPodsThreshold = 2
	}
	return &Aggregator{
		graph:      graph,
		subscriber: subscriber,
		cfg:        cfg,
		handler:    handler,
		logger:     logger,
		windows:    make(map[string][]AnomalyEntry),
	}
}

// Run starts the NATS subscription and the periodic flush ticker.
// Blocks until ctx is cancelled.
func (a *Aggregator) Run(ctx context.Context) error {
	a.logger.Info("intelligence aggregator: starting",
		"window", a.cfg.AggregationWindow,
		"flush_interval", a.cfg.FlushInterval,
		"min_pods", a.cfg.MinPodsThreshold,
	)

	// Start periodic flush goroutine.
	go func() {
		ticker := time.NewTicker(a.cfg.FlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.flush(ctx)
			}
		}
	}()

	// Subscribe to all anomaly events using the intelligence-specific consumer group.
	return a.subscriber.SubscribeAnomaliesIntelligence(ctx, func(data []byte) error {
		return a.handleAnomalyMessage(ctx, data)
	})
}

// handleAnomalyMessage decodes an AnomalyEvent, resolves its node, and records
// it in the node's aggregation window.
func (a *Aggregator) handleAnomalyMessage(ctx context.Context, data []byte) error {
	var ev analyzer.AnomalyEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		a.logger.Warn("aggregator: failed to decode AnomalyEvent", "error", err)
		return nil // ACK — don't redeliver malformed messages
	}

	// Resolve pod→node via dependency graph.
	podID := PodID(ev.Namespace, ev.Pod)
	nodeID, ok := a.graph.NodeForPod(podID)
	if !ok {
		// Pod not in graph (unscheduled or system pod) — skip node-level analysis.
		a.logger.Debug("aggregator: pod not in graph — skipping node analysis",
			"pod", ev.Pod, "namespace", ev.Namespace)
		return nil
	}

	nodeName := ""
	if n, ok := a.graph.NodeOf(nodeID); ok {
		nodeName = n.Name
	}

	entry := AnomalyEntry{
		PodName:    ev.Pod,
		Namespace:  ev.Namespace,
		Deployment: ev.Deployment,
		NodeName:   nodeName,
		Signals:    ev.ActiveSignals,
		Confidence: ev.Confidence,
		ReceivedAt: time.Now(),
	}

	a.record(nodeID, entry)
	return nil
}

// record adds an entry to the node's aggregation window.
func (a *Aggregator) record(nodeID string, entry AnomalyEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.windows[nodeID] = append(a.windows[nodeID], entry)
}

// flush evaluates all windows and emits NodeIncidents for nodes that exceed
// the threshold. Prunes stale entries.
func (a *Aggregator) flush(ctx context.Context) {
	a.mu.Lock()
	cutoff := time.Now().Add(-a.cfg.AggregationWindow)
	for nodeID, entries := range a.windows {
		// Prune entries older than the window.
		fresh := entries[:0]
		for _, e := range entries {
			if e.ReceivedAt.After(cutoff) {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			delete(a.windows, nodeID)
			continue
		}
		a.windows[nodeID] = fresh

		// Deduplicate by pod (only count each pod once per flush).
		podSeen := make(map[string]struct{})
		uniquePods := fresh[:0]
		for _, e := range fresh {
			key := e.Namespace + "/" + e.PodName
			if _, seen := podSeen[key]; !seen {
				podSeen[key] = struct{}{}
				uniquePods = append(uniquePods, e)
			}
		}

		if len(uniquePods) < a.cfg.MinPodsThreshold {
			continue
		}

		// Build NodeIncident from the window.
		incident := NodeIncident{
			NodeName:    uniquePods[0].NodeName,
			Anomalies:   uniquePods,
			WindowStart: cutoff,
			WindowEnd:   time.Now(),
		}
		a.mu.Unlock()
		a.logger.Info("aggregator: node incident threshold reached",
			"node", incident.NodeName,
			"affected_pods", len(uniquePods),
		)
		a.handler(ctx, incident)
		a.mu.Lock()

		// Clear the window after emitting to avoid repeated incidents.
		delete(a.windows, nodeID)
	}
	a.mu.Unlock()
}

// RecordDirect allows injecting AnomalyEntry directly (used by tests).
func (a *Aggregator) RecordDirect(nodeID string, entry AnomalyEntry) {
	a.record(nodeID, entry)
}

// FlushDirect triggers a flush synchronously (used by tests).
func (a *Aggregator) FlushDirect(ctx context.Context) {
	a.flush(ctx)
}
