// Package guardrails — circuit_breaker.go implements a sliding-window
// circuit breaker that pauses all autonomous healing when the action
// failure rate exceeds the configured threshold.
//
// Configured in guardrails.yaml:
//   circuit_breaker:
//     enabled: true
//     trigger_on_failure_pct: 50   # trip when >50% of actions fail
//     evaluation_window: 5m
//     pause_duration: 10m
//     alert_on_trip: true
//
// States:
//   CLOSED  — normal operation, actions permitted
//   OPEN    — tripped, all actions blocked for pause_duration
//   HALF    — (not used; we reclose after pause_duration automatically)

package guardrails

import (
	"log/slog"
	"sync"
	"time"
)

// outcomeRecord captures a single action result within the evaluation window.
type outcomeRecord struct {
	at      time.Time
	success bool
}

// CircuitBreaker pauses all autonomous actions when the failure rate
// exceeds the configured threshold within the evaluation window.
// Thread-safe via internal mutex.
type CircuitBreaker struct {
	mu            sync.Mutex
	history       []outcomeRecord
	trippedAt     time.Time
	isOpen        bool
	failurePct    int           // trigger threshold, e.g., 50
	evalWindow    time.Duration // e.g., 5m
	pauseDuration time.Duration // e.g., 10m
	enabled       bool
	logger        *slog.Logger
}

// NewCircuitBreaker creates a CircuitBreaker from the loaded policy.
// If the policy has circuit_breaker.enabled = false, Allow() always returns true.
func NewCircuitBreaker(policy *Policy, logger *slog.Logger) *CircuitBreaker {
	cb := policy.Guardrails.CircuitBreaker
	window, _ := time.ParseDuration(cb.EvaluationWindow)
	if window == 0 {
		window = 5 * time.Minute
	}
	pause, _ := time.ParseDuration(cb.PauseDuration)
	if pause == 0 {
		pause = 10 * time.Minute
	}

	return &CircuitBreaker{
		failurePct:    cb.TriggerOnFailurePct,
		evalWindow:    window,
		pauseDuration: pause,
		enabled:       cb.Enabled,
		logger:        logger,
	}
}

// Allow returns true if autonomous actions are currently permitted.
// Returns false when the circuit is OPEN (failure rate threshold exceeded).
func (cb *CircuitBreaker) Allow() bool {
	if !cb.enabled {
		return true
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.isOpen {
		if time.Since(cb.trippedAt) >= cb.pauseDuration {
			cb.logger.Info("circuit breaker: auto-closing after pause duration")
			cb.isOpen = false
			cb.history = cb.history[:0]
		} else {
			return false
		}
	}
	return true
}

// RecordSuccess records a successful action outcome.
func (cb *CircuitBreaker) RecordSuccess() {
	if !cb.enabled {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.record(true)
}

// RecordFailure records a failed action outcome and may trip the breaker.
func (cb *CircuitBreaker) RecordFailure() {
	if !cb.enabled {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.record(false)
	cb.maybeTrip()
}

// IsOpen returns true if the circuit breaker is currently tripped.
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.isOpen
}

// TripReason returns a human-readable description of why the breaker is open.
func (cb *CircuitBreaker) TripReason() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.isOpen {
		return ""
	}
	remaining := cb.pauseDuration - time.Since(cb.trippedAt)
	return "circuit breaker open — autonomous healing paused for " + remaining.Round(time.Second).String()
}

// record appends an outcome and prunes stale entries outside the eval window.
func (cb *CircuitBreaker) record(success bool) {
	now := time.Now()
	cutoff := now.Add(-cb.evalWindow)
	pruned := cb.history[:0]
	for _, r := range cb.history {
		if r.at.After(cutoff) {
			pruned = append(pruned, r)
		}
	}
	cb.history = append(pruned, outcomeRecord{at: now, success: success})
}

// maybeTrip evaluates current history and trips the breaker if threshold exceeded.
func (cb *CircuitBreaker) maybeTrip() {
	if len(cb.history) < 2 {
		return // not enough data to judge
	}
	failures := 0
	for _, r := range cb.history {
		if !r.success {
			failures++
		}
	}
	failurePct := (failures * 100) / len(cb.history)
	if failurePct > cb.failurePct {
		cb.isOpen = true
		cb.trippedAt = time.Now()
		cb.logger.Error("circuit breaker TRIPPED",
			"failure_pct", failurePct,
			"threshold_pct", cb.failurePct,
			"total_actions", len(cb.history),
			"failures", failures,
			"pause_duration", cb.pauseDuration,
		)
	}
}
