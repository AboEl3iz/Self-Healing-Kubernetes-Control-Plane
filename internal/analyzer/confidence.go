// Package analyzer — Confidence scoring algorithm.
//
// Algorithm:
//   confidence = base_confidence(rule)
//   if signal_count == 1: confidence -= single_signal_penalty (default -0.20)
//   for each correlated signal pair: confidence += correlation_boost
//   clamp to [0.0, 1.0]
//
// Action thresholds (from guardrails.yaml):
//   < 0.60 → suppress
//   0.60–0.75 → log only (dry-run equivalent)
//   >= 0.75 → take action
//
// TODO(Phase 2): Implement full scoring with correlation matrix.

package analyzer

// ScoreInput holds the inputs for computing an anomaly confidence score.
type ScoreInput struct {
	BaseConfidence      float64  // from the triggered rule
	ActiveSignals       []string // list of signal names contributing
	Correlations        []Correlation
	SingleSignalPenalty float64 // from rules config (default -0.20)
}

// Thresholds defines the confidence decision boundaries.
type Thresholds struct {
	Suppress   float64 // below this: no action
	LogOnly    float64 // between suppress and take_action: log only
	TakeAction float64 // at or above: execute action
}

// Decision is the outcome of confidence scoring.
type Decision int

const (
	DecisionSuppress   Decision = iota // confidence too low
	DecisionLogOnly                    // borderline — log but don't act
	DecisionTakeAction                 // high confidence — act
)

// Score computes the final confidence score for an anomaly.
// TODO(Phase 2): Implement full correlation matrix lookup.
func Score(input ScoreInput) float64 {
	confidence := input.BaseConfidence

	// Single-signal penalty
	if len(input.ActiveSignals) == 1 {
		confidence += input.SingleSignalPenalty // penalty is negative
	}

	// Correlation boosts
	for _, corr := range input.Correlations {
		if allMatch(input.ActiveSignals, corr.Signals) {
			confidence += corr.Boost
		}
	}

	// Clamp to [0.0, 1.0]
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	return confidence
}

// Decide maps a confidence score to an action decision.
func Decide(confidence float64, t Thresholds) Decision {
	if confidence < t.Suppress {
		return DecisionSuppress
	}
	if confidence < t.TakeAction {
		return DecisionLogOnly
	}
	return DecisionTakeAction
}

// allMatch returns true if all required signals are present in active.
func allMatch(active, required []string) bool {
	set := make(map[string]struct{}, len(active))
	for _, s := range active {
		set[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
