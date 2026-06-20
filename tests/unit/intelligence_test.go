// Package unit — intelligence_test.go covers the Phase 4 root cause intelligence
// components: dependency graph, aggregator window logic, causal reasoner, and
// node health scorer.
//
// All tests are pure in-memory (no Kubernetes cluster, no NATS required).

package unit

import (
	"context"
	"testing"
	"time"

	"github.com/karim-aboelaiz/selfheal-cp/internal/intelligence"
)

// ─── Dependency Graph ─────────────────────────────────────────────────────────

func TestDependencyGraph_PeersOnNode(t *testing.T) {
	g := intelligence.NewDependencyGraph()

	nodeID := intelligence.NodeID("node-1")
	pod1 := intelligence.PodID("default", "pod-a")
	pod2 := intelligence.PodID("default", "pod-b")
	pod3 := intelligence.PodID("kube-system", "pod-c")

	g.AddNode(intelligence.ResourceNode{ID: nodeID, Kind: intelligence.KindNode, Name: "node-1"})
	g.AddNode(intelligence.ResourceNode{ID: pod1, Kind: intelligence.KindPod, Name: "pod-a", Namespace: "default"})
	g.AddNode(intelligence.ResourceNode{ID: pod2, Kind: intelligence.KindPod, Name: "pod-b", Namespace: "default"})
	g.AddNode(intelligence.ResourceNode{ID: pod3, Kind: intelligence.KindPod, Name: "pod-c", Namespace: "kube-system"})

	g.AddEdge(pod1, nodeID, intelligence.RelRunsOn)
	g.AddEdge(pod2, nodeID, intelligence.RelRunsOn)
	g.AddEdge(pod3, nodeID, intelligence.RelRunsOn)

	peers := g.PeersOnNode(nodeID)
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers on node-1, got %d", len(peers))
	}
}

func TestDependencyGraph_NodeForPod(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	nodeID := intelligence.NodeID("node-2")
	podID := intelligence.PodID("prod", "api-0")

	g.AddEdge(podID, nodeID, intelligence.RelRunsOn)

	got, ok := g.NodeForPod(podID)
	if !ok {
		t.Fatal("expected pod to be found in graph")
	}
	if got != nodeID {
		t.Fatalf("expected nodeID %s, got %s", nodeID, got)
	}
}

func TestDependencyGraph_UnknownPodReturnsNotFound(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	_, ok := g.NodeForPod(intelligence.PodID("ns", "nonexistent"))
	if ok {
		t.Fatal("expected non-existent pod to return not-found")
	}
}

func TestDependencyGraph_UnregisterPod(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	nodeID := intelligence.NodeID("node-3")
	podID := intelligence.PodID("default", "pod-x")

	g.AddEdge(podID, nodeID, intelligence.RelRunsOn)
	g.UnregisterPod("default", "pod-x")

	_, ok := g.NodeForPod(podID)
	if ok {
		t.Fatal("expected pod to be removed after UnregisterPod")
	}
	peers := g.PeersOnNode(nodeID)
	for _, p := range peers {
		if p == podID {
			t.Fatal("expected pod to be removed from node peer list")
		}
	}
}

func TestDependencyGraph_SharedVolumes(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	pod1 := intelligence.PodID("default", "pod-a")
	pod2 := intelligence.PodID("default", "pod-b")
	vol := intelligence.NodeID("pv-data-01") // using NodeID helper for PV

	g.AddEdge(pod1, vol, intelligence.RelUsesPVC)
	g.AddEdge(pod2, vol, intelligence.RelUsesPVC)

	shared := g.SharedVolumes([]string{pod1, pod2})
	if len(shared) != 1 {
		t.Fatalf("expected 1 shared volume, got %d: %v", len(shared), shared)
	}
	if shared[0] != vol {
		t.Fatalf("expected shared volume %s, got %s", vol, shared[0])
	}
}

// ─── Aggregator ───────────────────────────────────────────────────────────────

func TestAggregator_FlushesOnThreshold(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	cfg := intelligence.AggregatorConfig{
		AggregationWindow: 5 * time.Minute,
		FlushInterval:     1 * time.Hour, // no auto-flush
		MinPodsThreshold:  2,
	}

	var received []intelligence.NodeIncident
	handler := func(ctx context.Context, inc intelligence.NodeIncident) {
		received = append(received, inc)
	}

	agg := intelligence.NewAggregator(g, nil, cfg, handler, testLogger)
	nodeID := intelligence.NodeID("node-5")

	agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-a", Namespace: "default", NodeName: "node-5", Signals: []string{"io_wait_high"}, ReceivedAt: time.Now()})
	agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-b", Namespace: "default", NodeName: "node-5", Signals: []string{"disk_io_lat"}, ReceivedAt: time.Now()})

	agg.FlushDirect(context.Background())

	if len(received) != 1 {
		t.Fatalf("expected 1 NodeIncident, got %d", len(received))
	}
	if received[0].NodeName != "node-5" {
		t.Fatalf("expected node-5, got %s", received[0].NodeName)
	}
	if len(received[0].Anomalies) != 2 {
		t.Fatalf("expected 2 anomalies in incident, got %d", len(received[0].Anomalies))
	}
}

func TestAggregator_IgnoresBelowThreshold(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	cfg := intelligence.AggregatorConfig{
		AggregationWindow: 5 * time.Minute,
		FlushInterval:     1 * time.Hour,
		MinPodsThreshold:  3, // require 3 pods
	}

	var received []intelligence.NodeIncident
	handler := func(ctx context.Context, inc intelligence.NodeIncident) {
		received = append(received, inc)
	}

	agg := intelligence.NewAggregator(g, nil, cfg, handler, testLogger)
	nodeID := intelligence.NodeID("node-6")

	// Only 2 pods — below threshold of 3.
	agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-a", Namespace: "default", NodeName: "node-6", Signals: []string{"io_wait_high"}, ReceivedAt: time.Now()})
	agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-b", Namespace: "default", NodeName: "node-6", Signals: []string{"disk_io_lat"}, ReceivedAt: time.Now()})

	agg.FlushDirect(context.Background())

	if len(received) != 0 {
		t.Fatalf("expected no incidents below threshold, got %d", len(received))
	}
}

func TestAggregator_DedupsSamePodMultipleAnomalies(t *testing.T) {
	g := intelligence.NewDependencyGraph()
	cfg := intelligence.AggregatorConfig{
		AggregationWindow: 5 * time.Minute,
		FlushInterval:     1 * time.Hour,
		MinPodsThreshold:  2,
	}

	var received []intelligence.NodeIncident
	handler := func(ctx context.Context, inc intelligence.NodeIncident) {
		received = append(received, inc)
	}

	agg := intelligence.NewAggregator(g, nil, cfg, handler, testLogger)
	nodeID := intelligence.NodeID("node-7")

	// Same pod recorded 3 times — should count as 1 unique pod.
	for i := 0; i < 3; i++ {
		agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-a", Namespace: "default", NodeName: "node-7", Signals: []string{"io_wait_high"}, ReceivedAt: time.Now()})
	}
	// Second distinct pod.
	agg.RecordDirect(nodeID, intelligence.AnomalyEntry{PodName: "pod-b", Namespace: "default", NodeName: "node-7", Signals: []string{"disk_io_lat"}, ReceivedAt: time.Now()})

	agg.FlushDirect(context.Background())

	if len(received) != 1 {
		t.Fatalf("expected 1 incident (deduped), got %d", len(received))
	}
	// Should have exactly 2 unique pods.
	if len(received[0].Anomalies) != 2 {
		t.Fatalf("expected 2 unique pods in incident, got %d", len(received[0].Anomalies))
	}
}

// ─── Causal Reasoner ──────────────────────────────────────────────────────────

func makeReasoner() *intelligence.Reasoner {
	g := intelligence.NewDependencyGraph()
	scorer := intelligence.NewNodeHealthScorer(testLogger)
	return intelligence.NewReasoner(g, scorer, nil, testLogger)
}

func makeIncident(nodeName string, anomalies []intelligence.AnomalyEntry) intelligence.NodeIncident {
	return intelligence.NodeIncident{
		NodeName:    nodeName,
		Anomalies:   anomalies,
		WindowStart: time.Now().Add(-5 * time.Minute),
		WindowEnd:   time.Now(),
	}
}

func TestReasoner_AttributesDegradedDisk(t *testing.T) {
	r := makeReasoner()
	incident := makeIncident("node-1", []intelligence.AnomalyEntry{
		{PodName: "pod-a", Namespace: "ns", Signals: []string{"io_wait_high", "disk_io_lat"}},
		{PodName: "pod-b", Namespace: "ns", Signals: []string{"io_wait_high", "disk_io_lat"}},
		{PodName: "pod-c", Namespace: "ns", Signals: []string{"io_wait_high"}},
	})

	ev, err := r.Classify(incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.RootCause != intelligence.RootCauseDegradedDisk {
		t.Fatalf("expected degraded_disk, got %s", ev.RootCause)
	}
	if ev.RootCauseConf < 0.50 {
		t.Fatalf("expected confidence >= 0.50, got %.2f", ev.RootCauseConf)
	}
	if ev.SuggestedAction != "cordon_node" {
		t.Fatalf("expected cordon_node suggestion, got %s", ev.SuggestedAction)
	}
}

func TestReasoner_AttributesNetworkPartition(t *testing.T) {
	r := makeReasoner()
	incident := makeIncident("node-2", []intelligence.AnomalyEntry{
		{PodName: "pod-a", Namespace: "ns", Signals: []string{"tcp_retransmit"}},
		{PodName: "pod-b", Namespace: "ns", Signals: []string{"tcp_retransmit"}},
		{PodName: "pod-c", Namespace: "ns", Signals: []string{"tcp_retransmit", "high_latency"}},
	})

	ev, err := r.Classify(incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.RootCause != intelligence.RootCauseNetworkPartition {
		t.Fatalf("expected network_partition, got %s", ev.RootCause)
	}
}

func TestReasoner_AttributesCPUStarvation(t *testing.T) {
	r := makeReasoner()
	incident := makeIncident("node-3", []intelligence.AnomalyEntry{
		{PodName: "pod-a", Namespace: "ns", Signals: []string{"cpu_runqueue_delay"}},
		{PodName: "pod-b", Namespace: "ns", Signals: []string{"cpu_runqueue_delay"}},
	})

	ev, err := r.Classify(incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.RootCause != intelligence.RootCauseCPUStarvation {
		t.Fatalf("expected cpu_starvation, got %s", ev.RootCause)
	}
}

func TestReasoner_AttributesMemoryPressure(t *testing.T) {
	r := makeReasoner()
	incident := makeIncident("node-4", []intelligence.AnomalyEntry{
		{PodName: "pod-a", Namespace: "ns", Signals: []string{"oom_kill"}},
		{PodName: "pod-b", Namespace: "ns", Signals: []string{"oom_kill"}},
	})

	ev, err := r.Classify(incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.RootCause != intelligence.RootCauseMemoryPressure {
		t.Fatalf("expected memory_pressure, got %s", ev.RootCause)
	}
}

func TestReasoner_MixedSignalsReturnUnknown(t *testing.T) {
	r := makeReasoner()
	incident := makeIncident("node-5", []intelligence.AnomalyEntry{
		{PodName: "pod-a", Namespace: "ns", Signals: []string{"io_wait_high"}},
		{PodName: "pod-b", Namespace: "ns", Signals: []string{"tcp_retransmit"}},
		{PodName: "pod-c", Namespace: "ns", Signals: []string{"cpu_runqueue_delay"}},
	})

	ev, err := r.Classify(incident)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.RootCause != intelligence.RootCauseUnknown {
		t.Fatalf("expected unknown for mixed signals, got %s", ev.RootCause)
	}
}

// ─── Node Health Scorer ───────────────────────────────────────────────────────

func TestNodeHealthScorer_StartsAt1(t *testing.T) {
	s := intelligence.NewNodeHealthScorer(testLogger)
	score := s.Score("Node/node-fresh")
	if score != 1.0 {
		t.Fatalf("expected score 1.0 for new node, got %.2f", score)
	}
}

func TestNodeHealthScorer_DecaysOnUnresolvedAnomalies(t *testing.T) {
	s := intelligence.NewNodeHealthScorer(testLogger)
	nodeID := "Node/node-bad"

	// Record 5 anomalies, none resolved.
	for i := 0; i < 5; i++ {
		s.RecordAnomaly(nodeID)
	}

	score := s.Score(nodeID)
	if score >= 1.0 {
		t.Fatalf("expected score < 1.0 after anomalies, got %.2f", score)
	}
	if score < 0.0 {
		t.Fatalf("expected non-negative score, got %.2f", score)
	}
}

func TestNodeHealthScorer_RecoverOnResolution(t *testing.T) {
	s := intelligence.NewNodeHealthScorer(testLogger)
	nodeID := "Node/node-recover"

	for i := 0; i < 3; i++ {
		s.RecordAnomaly(nodeID)
	}
	scoreBefore := s.Score(nodeID)

	// Resolve all anomalies.
	for i := 0; i < 3; i++ {
		s.RecordOutcome(nodeID, "resolved")
	}
	scoreAfter := s.Score(nodeID)

	if scoreAfter <= scoreBefore {
		t.Fatalf("expected score to improve after resolution: before=%.2f after=%.2f", scoreBefore, scoreAfter)
	}
}

func TestNodeHealthScorer_BelowCordonThreshold(t *testing.T) {
	s := intelligence.NewNodeHealthScorer(testLogger)
	nodeID := "Node/node-failing"

	// Simulate many unresolved anomalies + escalations.
	for i := 0; i < 10; i++ {
		s.RecordAnomaly(nodeID)
	}
	for i := 0; i < 8; i++ {
		s.RecordOutcome(nodeID, "escalated")
	}

	score := s.Score(nodeID)
	if score >= intelligence.HealthThresholdCordon {
		t.Fatalf("expected score below cordon threshold (%.2f), got %.2f",
			intelligence.HealthThresholdCordon, score)
	}

	unhealthy := s.UnhealthyNodes(intelligence.HealthThresholdCordon)
	found := false
	for _, ns := range unhealthy {
		if ns.NodeName == nodeID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected node to appear in UnhealthyNodes() result")
	}
}
