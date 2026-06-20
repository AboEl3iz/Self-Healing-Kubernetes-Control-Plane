package unit_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/karim-aboelaiz/selfheal-cp/internal/analyzer"
)

// ─── Window Tests ─────────────────────────────────────────────────────────────

func TestWindowStore(t *testing.T) {
	t.Parallel()
	store := analyzer.NewWindowStore()
	pod := "test-pod"
	metric := "cpu_usage_pct"
	duration := 1 * time.Second

	now := time.Now()
	store.Record(pod, metric, 10, now.Add(-500*time.Millisecond), duration)
	store.Record(pod, metric, 20, now.Add(-100*time.Millisecond), duration)

	w := store.Get(pod, metric)
	if w == nil {
		t.Fatal("expected window to exist")
	}

	if count := w.Count(); count != 2 {
		t.Errorf("expected 2 samples, got %d", count)
	}

	if avg := w.Average(); avg != 15 {
		t.Errorf("expected average 15, got %v", avg)
	}

	if max := w.Max(); max != 20 {
		t.Errorf("expected max 20, got %v", max)
	}

	latest, ok := w.Latest()
	if !ok || latest != 20 {
		t.Errorf("expected latest 20, got %v (ok=%v)", latest, ok)
	}

	// Test eviction (sample older than 1s)
	store.Record(pod, metric, 30, now.Add(2*time.Second), duration)
	if count := w.Count(); count != 1 {
		t.Errorf("expected 1 sample after eviction, got %d", count)
	}
}

func TestWindowPercentile(t *testing.T) {
	t.Parallel()
	store := analyzer.NewWindowStore()
	now := time.Now()
	
	// Add 100 samples 1..100
	for i := 1; i <= 100; i++ {
		store.Record("p1", "m1", float64(i), now.Add(time.Duration(i)*time.Millisecond), time.Minute)
	}

	w := store.Get("p1", "m1")
	p50 := w.Percentile(50)
	if p50 != 50 && p50 != 51 { // approx mid
		t.Errorf("expected p50 around 50, got %v", p50)
	}
	p99 := w.Percentile(99)
	if p99 != 99 && p99 != 100 {
		t.Errorf("expected p99 around 100, got %v", p99)
	}
}

// ─── Cooldown Tests ───────────────────────────────────────────────────────────

func TestCooldownStore(t *testing.T) {
	t.Parallel()
	store := analyzer.NewCooldownStore()
	pod := "test-pod"
	action := "restart_pod"
	policy := analyzer.CooldownPolicy{Duration: 60 * time.Second, MaxPerHour: 3}
	now := time.Now()

	// First action should be allowed
	if !store.Allow(pod, action, policy, now) {
		t.Error("expected first action to be allowed")
	}
	store.Record(pod, action, now)

	// Second action immediately after should NOT be allowed
	if store.Allow(pod, action, policy, now.Add(10*time.Second)) {
		t.Error("expected action during cooldown duration to be denied")
	}

	// Action after duration should be allowed
	if !store.Allow(pod, action, policy, now.Add(61*time.Second)) {
		t.Error("expected action after cooldown duration to be allowed")
	}
	store.Record(pod, action, now.Add(61*time.Second))
	store.Record(pod, action, now.Add(122*time.Second)) // 3rd action

	// 4th action should hit MaxPerHour
	if store.Allow(pod, action, policy, now.Add(183*time.Second)) {
		t.Error("expected 4th action to hit MaxPerHour limit")
	}

	// Evict
	store.Evict(pod)
	if !store.Allow(pod, action, policy, now.Add(183*time.Second)) {
		t.Error("expected action to be allowed after eviction")
	}
}

// ─── Confidence Scoring Tests ─────────────────────────────────────────────────

func TestConfidenceScoring(t *testing.T) {
	t.Parallel()
	input := analyzer.ScoreInput{
		BaseConfidence: 0.65,
		ActiveSignals:  []string{"high_runqueue_delay"},
		Correlations: []analyzer.Correlation{
			{Signals: []string{"high_tcp_retransmit_rate", "high_runqueue_delay"}, Boost: 0.10},
		},
		SingleSignalPenalty: -0.20,
	}

	// Single signal -> penalty applied
	score := analyzer.Score(input)
	if score != 0.45 {
		t.Errorf("expected single signal score 0.45, got %v", score)
	}

	// Correlated signals
	input.ActiveSignals = []string{"high_runqueue_delay", "high_tcp_retransmit_rate"}
	score = analyzer.Score(input)
	// base 0.65 + boost 0.10 = 0.75
	if score != 0.75 {
		t.Errorf("expected correlated score 0.75, got %v", score)
	}
}

// ─── Engine Pipeline Tests ────────────────────────────────────────────────────

type mockPublisher struct {
	events [][]byte
}

func (m *mockPublisher) PublishAnomaly(ctx context.Context, namespace string, data []byte) error {
	m.events = append(m.events, data)
	return nil
}

func TestEngineProcessSignal(t *testing.T) {
	t.Parallel()

	cfg := &analyzer.RulesConfig{
		SingleSignalPenalty: -0.10,
		Thresholds: struct {
			Suppress   float64 `yaml:"suppress"`
			LogOnly    float64 `yaml:"log_only"`
			TakeAction float64 `yaml:"take_action"`
		}{0.60, 0.75, 0.75},
	}

	rules := []analyzer.Rule{
		{
			ID: "test_rule",
			Metric: "test_metric",
			Condition: analyzer.Condition{Operator: ">", Value: 10},
			Window: "10s",
			ConfidenceBase: 0.90, // high enough to survive single signal penalty (0.9 - 0.1 = 0.8 >= 0.75)
			SuggestedAction: "restart_pod",
			Enabled: true,
		},
	}

	pub := &mockPublisher{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine := analyzer.NewEngine(rules, cfg, pub, false, logger)

	// Send a signal that doesn't breach
	sig1 := analyzer.SignalEvent{
		Metric: "test_metric",
		Value: 5,
		Pod: "p1",
		Timestamp: time.Now().UnixMilli(),
	}
	b1, _ := json.Marshal(sig1)
	_ = engine.ProcessSignal(context.Background(), b1)

	if len(pub.events) != 0 {
		t.Errorf("expected 0 events, got %d", len(pub.events))
	}

	// Send a signal that breaches
	sig2 := analyzer.SignalEvent{
		Metric: "test_metric",
		Value: 25,
		Pod: "p1",
		Timestamp: time.Now().UnixMilli(),
	}
	b2, _ := json.Marshal(sig2)
	_ = engine.ProcessSignal(context.Background(), b2)

	if len(pub.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(pub.events))
	}

	var event analyzer.AnomalyEvent
	if err := json.Unmarshal(pub.events[0], &event); err != nil {
		t.Fatalf("failed to unmarshal published event: %v", err)
	}

	if event.ID != "test_rule" {
		t.Errorf("expected rule test_rule, got %v", event.ID)
	}
	if event.Confidence != 0.80 {
		t.Errorf("expected confidence 0.80, got %v", event.Confidence)
	}
	if event.MetricValue != 15 { // average of 5 and 25
		t.Errorf("expected metric value 15, got %v", event.MetricValue)
	}
}
