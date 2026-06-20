// Package analyzer — engine.go is the core heuristics pipeline.
//
// Processing pipeline per SignalEvent:
//
//  1. Decode JSON → SignalEvent
//  2. WindowStore.Record(pod, metric, value, t, window_duration)
//  3. Evaluate every enabled Rule whose metric matches
//  4. Build ActiveSignalSet across all triggered rules for this pod
//  5. For each triggered rule:
//     a. EvaluateCorrelations → boost
//     b. Score(base + boost ± single_signal_penalty)
//     c. Decide(score, thresholds)
//     d. If DecisionLogOnly or DecisionTakeAction AND cooldown allows:
//        → build AnomalyEvent → publish → record cooldown
//
// Thread safety: all shared state (WindowStore, CooldownStore) is internally
// protected. Engine.ProcessSignal is safe to call from multiple goroutines.

package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ─── AnomalyEvent ─────────────────────────────────────────────────────────────

// AnomalyEvent is published to selfheal.anomalies.<namespace> when an anomaly
// is detected with sufficient confidence.
type AnomalyEvent struct {
	Version         string    `json:"version"`
	ID              string    `json:"id"`           // rule ID
	Namespace       string    `json:"namespace"`
	Pod             string    `json:"pod"`
	Deployment      string    `json:"deployment"`
	Container       string    `json:"container"`
	Metric          string    `json:"metric"`
	Confidence      float64   `json:"confidence"`
	ActiveSignals   []string  `json:"active_signals"`
	SuggestedCause  string    `json:"suggested_cause"`
	SuggestedAction string    `json:"suggested_action"`
	MetricValue     float64   `json:"metric_value"`
	Threshold       float64   `json:"threshold"`
	Window          string    `json:"window"`
	DryRun          bool      `json:"dry_run"`
	DetectedAt      time.Time `json:"detected_at"`
}

// SignalEvent mirrors the JSON payload published by the agent.
type SignalEvent struct {
	Version    string  `json:"version"`
	Node       string  `json:"node"`
	Pod        string  `json:"pod"`
	Namespace  string  `json:"namespace"`
	Deployment string  `json:"deployment"`
	Container  string  `json:"container"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit"`
	DurationMs int64   `json:"duration_ms"`
	Timestamp  int64   `json:"timestamp"` // Unix ms
	CgroupID   uint64  `json:"cgroup_id"`
}

// ─── AnomalyPublisher interface ────────────────────────────────────────────────

// AnomalyPublisher is the interface the Engine uses to emit anomalies.
// The real implementation lives in internal/bus; this keeps engine testable.
type AnomalyPublisher interface {
	PublishAnomaly(ctx context.Context, namespace string, data []byte) error
}

// ─── Prometheus metrics ────────────────────────────────────────────────────────

var (
	anomaliesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "selfheal_anomalies_detected_total",
		Help: "Total anomalies detected by the heuristics engine",
	}, []string{"rule", "namespace", "decision"})

	confidenceHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "selfheal_confidence_score",
		Help:    "Confidence score distribution per rule",
		Buckets: []float64{0.3, 0.5, 0.6, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 1.0},
	}, []string{"rule"})

	falsePositives = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "selfheal_false_positives_total",
		Help: "Anomalies suppressed due to low confidence or cooldown",
	}, []string{"rule", "reason"})
)

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine orchestrates the full anomaly detection pipeline.
type Engine struct {
	rules      []Rule
	cfg        *RulesConfig
	windows    *WindowStore
	cooldowns  *CooldownStore
	publisher  AnomalyPublisher
	dryRun     bool
	logger     *slog.Logger
	thresholds Thresholds
}

// NewEngine creates an Engine wired to the given publisher.
// Set publisher=nil to run in dry-run mode (anomalies logged, not sent).
func NewEngine(rules []Rule, cfg *RulesConfig, publisher AnomalyPublisher, dryRun bool, logger *slog.Logger) *Engine {
	t := Thresholds{
		Suppress:   cfg.Thresholds.Suppress,
		LogOnly:    cfg.Thresholds.LogOnly,
		TakeAction: cfg.Thresholds.TakeAction,
	}
	return &Engine{
		rules:     rules,
		cfg:       cfg,
		windows:   NewWindowStore(),
		cooldowns: NewCooldownStore(),
		publisher: publisher,
		dryRun:    dryRun,
		logger:    logger,
		thresholds: t,
	}
}

// ParseWindowDuration parses rule window strings like "30s", "5m", "1h".
func ParseWindowDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 30 * time.Second, nil // safe default
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid window duration %q: %w", s, err)
	}
	return d, nil
}

// ProcessSignal is the hot path: called once per received SignalEvent.
// It is safe to call concurrently from multiple goroutines.
func (e *Engine) ProcessSignal(ctx context.Context, data []byte) error {
	var sig SignalEvent
	if err := json.Unmarshal(data, &sig); err != nil {
		return fmt.Errorf("engine: decode signal: %w", err)
	}

	t := time.UnixMilli(sig.Timestamp)
	if t.IsZero() {
		t = time.Now()
	}

	// 1. Record into all matching windows.
	for _, rule := range e.rules {
		if rule.Metric != sig.Metric {
			continue
		}
		dur, err := ParseWindowDuration(rule.Window)
		if err != nil {
			e.logger.Warn("engine: bad window", "rule", rule.ID, "error", err)
			continue
		}
		e.windows.Record(sig.Pod, sig.Metric, sig.Value, t, dur)
	}

	// 2. Evaluate all rules and collect triggered rule IDs.
	var triggeredIDs []string
	type ruleHit struct {
		rule  Rule
		value float64
	}
	var hits []ruleHit

	for _, rule := range e.rules {
		if rule.Metric != sig.Metric {
			continue
		}
		w := e.windows.Get(sig.Pod, sig.Metric)
		if w == nil {
			continue
		}
		// Use the window average as the representative value.
		windowVal := w.Average()
		if breaches(windowVal, rule.Condition) {
			triggeredIDs = append(triggeredIDs, rule.ID)
			hits = append(hits, ruleHit{rule: rule, value: windowVal})
		}
	}

	if len(hits) == 0 {
		return nil // no anomaly
	}

	// 3. Build active signal set for correlation.
	activeSet := BuildActiveSet(triggeredIDs)
	corrBoost := EvaluateCorrelations(activeSet, e.cfg.Correlations)

	// 4. Score, decide, and emit per triggered rule.
	now := time.Now()
	for _, hit := range hits {
		score := Score(ScoreInput{
			BaseConfidence:      hit.rule.ConfidenceBase,
			ActiveSignals:       activeSet.Names(),
			Correlations:        e.cfg.Correlations,
			SingleSignalPenalty: e.cfg.SingleSignalPenalty,
		})
		// Apply correlation boost at engine level (Score already handles it,
		// but add extra boost if correlations span multiple rules).
		if corrBoost > 0 && len(triggeredIDs) > 1 {
			score = clamp(score+corrBoost*0.5, 0, 1)
		}

		decision := Decide(score, e.thresholds)
		confidenceHistogram.WithLabelValues(hit.rule.ID).Observe(score)

		label := decisionLabel(decision)
		anomaliesDetected.WithLabelValues(hit.rule.ID, sig.Namespace, label).Inc()

		if decision == DecisionSuppress {
			falsePositives.WithLabelValues(hit.rule.ID, "low_confidence").Inc()
			e.logger.Debug("engine: suppressed",
				"rule", hit.rule.ID,
				"pod", sig.Pod,
				"score", score,
			)
			continue
		}

		// 5. Check cooldown.
		policy := cooldownPolicyFor(hit.rule.SuggestedAction)
		if !e.cooldowns.Allow(sig.Pod, hit.rule.SuggestedAction, policy, now) {
			remaining := e.cooldowns.RemainingCooldown(sig.Pod, hit.rule.SuggestedAction, policy, now)
			falsePositives.WithLabelValues(hit.rule.ID, "cooldown").Inc()
			e.logger.Debug("engine: cooldown active",
				"rule", hit.rule.ID,
				"pod", sig.Pod,
				"remaining", remaining,
			)
			continue
		}

		// 6. Emit anomaly.
		event := &AnomalyEvent{
			Version:         "1.0",
			ID:              hit.rule.ID,
			Namespace:       sig.Namespace,
			Pod:             sig.Pod,
			Deployment:      sig.Deployment,
			Container:       sig.Container,
			Metric:          sig.Metric,
			Confidence:      score,
			ActiveSignals:   activeSet.Names(),
			SuggestedCause:  hit.rule.SuggestedCause,
			SuggestedAction: hit.rule.SuggestedAction,
			MetricValue:     hit.value,
			Threshold:       hit.rule.Condition.Value,
			Window:          hit.rule.Window,
			DryRun:          e.dryRun || decision == DecisionLogOnly,
			DetectedAt:      now,
		}

		e.logger.Info("engine: anomaly detected",
			"rule", event.ID,
			"pod", event.Pod,
			"namespace", event.Namespace,
			"confidence", fmt.Sprintf("%.2f", event.Confidence),
			"action", event.SuggestedAction,
			"dry_run", event.DryRun,
		)

		// Record cooldown before publish so a panic in publish doesn't allow retry.
		e.cooldowns.Record(sig.Pod, hit.rule.SuggestedAction, now)

		if e.publisher != nil && !e.dryRun {
			data, err := json.Marshal(event)
			if err != nil {
				e.logger.Warn("engine: publish marshal failed", "rule", event.ID, "error", err)
			} else if err := e.publisher.PublishAnomaly(ctx, sig.Namespace, data); err != nil {
				e.logger.Warn("engine: publish failed", "rule", event.ID, "error", err)
			}
		}
	}

	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// breaches returns true if value satisfies the threshold condition.
func breaches(value float64, c Condition) bool {
	switch c.Operator {
	case OpGreaterThan:
		return value > c.Value
	case OpGreaterOrEqual:
		return value >= c.Value
	case OpLessThan:
		return value < c.Value
	case OpLessOrEqual:
		return value <= c.Value
	case OpEqual:
		return value == c.Value
	}
	return false
}

// clamp restricts v to [lo, hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// cooldownPolicyFor returns the policy for a given action type.
func cooldownPolicyFor(action string) CooldownPolicy {
	if p, ok := DefaultCooldowns[action]; ok {
		return p
	}
	return CooldownPolicy{Duration: 60 * time.Second, MaxPerHour: 3}
}

// decisionLabel converts a Decision to a Prometheus label string.
func decisionLabel(d Decision) string {
	switch d {
	case DecisionTakeAction:
		return "action"
	case DecisionLogOnly:
		return "log_only"
	default:
		return "suppressed"
	}
}
