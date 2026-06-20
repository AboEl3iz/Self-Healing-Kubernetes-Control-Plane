// Package analyzer — correlate.go handles multi-signal correlation evaluation.
//
// When multiple signals are active for the same pod simultaneously,
// the correlations defined in rules.yaml provide confidence boosts.
// This is what prevents false positives from single noisy metrics.
//
// Example: io_wait_high + syscall_latency_spike together → +0.15 boost
// because both signals confirm a disk bottleneck, not just one metric spike.

package analyzer

// ActiveSignalSet is the set of metric names currently breaching a threshold
// for a given pod (populated by the Engine during rule evaluation).
type ActiveSignalSet map[string]struct{}

// Has returns true if the signal is in the active set.
func (s ActiveSignalSet) Has(metric string) bool {
	_, ok := s[metric]
	return ok
}

// Names returns the list of active signal names.
func (s ActiveSignalSet) Names() []string {
	names := make([]string, 0, len(s))
	for k := range s {
		names = append(names, k)
	}
	return names
}

// EvaluateCorrelations computes the total confidence boost from all
// correlation rules that are fully satisfied by the active signal set.
//
// A correlation is satisfied when ALL of its signals are in active.
func EvaluateCorrelations(active ActiveSignalSet, correlations []Correlation) float64 {
	var totalBoost float64
	for _, corr := range correlations {
		if allSignalsActive(active, corr.Signals) {
			totalBoost += corr.Boost
		}
	}
	return totalBoost
}

// allSignalsActive returns true if every signal in required is in active.
func allSignalsActive(active ActiveSignalSet, required []string) bool {
	for _, sig := range required {
		if !active.Has(sig) {
			return false
		}
	}
	return true
}

// BuildActiveSet returns the set of rule IDs (used as signal names in
// correlation definitions) that are currently breaching their thresholds
// for a given pod, based on the current window state.
//
// Called by the Engine for each pod after evaluating all individual rules.
func BuildActiveSet(triggeredRuleIDs []string) ActiveSignalSet {
	set := make(ActiveSignalSet, len(triggeredRuleIDs))
	for _, id := range triggeredRuleIDs {
		set[id] = struct{}{}
	}
	return set
}
