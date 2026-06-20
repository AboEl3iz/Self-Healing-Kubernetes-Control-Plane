// Package controller — escalation.go implements the per-(pod, anomaly_type)
// healing escalation state machine.
//
// State transitions per (pod, namespace, anomalyType) tuple:
//
//   OBSERVING
//       │  anomaly detected
//       ▼
//   ACTION_TAKEN  (restart_pod, attempts 1–3)
//       │  anomaly persists after observation window
//       ▼
//   ESCALATING    (reschedule_pod, attempts 1–2)
//       │  anomaly still persists
//       ▼
//   NODE_SUSPECT  (cordon_node, attempt 1 — only if ≥3 pods affected)
//       │  still not resolved, or cordon limit reached
//       ▼
//   MANUAL        (no more autonomous actions — page on-call)
//
// Resolution resets the state machine to OBSERVING.
//
// All state is in-memory (sync.Map). A controller restart resets escalation
// history — this is acceptable because the cooldown store prevents rapid
// re-escalation on restart.

package controller

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// escalationKey identifies a unique (pod, namespace, anomalyType) healing context.
type escalationKey struct {
	pod         string
	namespace   string
	anomalyType string
}

// escalationEntry holds the mutable state for one healing context.
type escalationEntry struct {
	state      EscalationState
	action     ActionType
	attempt    int
	lastAction time.Time
	updatedAt  time.Time
}

// EscalationManager tracks escalation state for all active anomalies.
// Thread-safe via sync.Map.
type EscalationManager struct {
	entries sync.Map
	logger  *slog.Logger
}

// NewEscalationManager creates an EscalationManager.
func NewEscalationManager(logger *slog.Logger) *EscalationManager {
	return &EscalationManager{logger: logger}
}

// NextAction returns the next action to attempt for a given (pod, namespace, anomalyType).
// It advances the state machine and returns the ActionType to dispatch.
// Returns (ActionManual, attempt) when no more autonomous actions are possible.
func (em *EscalationManager) NextAction(pod, namespace, anomalyType string) (ActionType, int, error) {
	key := escalationKey{pod: pod, namespace: namespace, anomalyType: anomalyType}

	raw, _ := em.entries.Load(key)
	var entry *escalationEntry
	if raw == nil {
		entry = &escalationEntry{
			state:     StateObserving,
			action:    ActionRestartPod,
			attempt:   0,
			updatedAt: time.Now(),
		}
	} else {
		entry = raw.(*escalationEntry)
	}

	// Clone to mutate safely.
	next := *entry

	switch entry.state {
	case StateObserving, StateResolved:
		// First anomaly detection — start with restart.
		next.state = StateActionTaken
		next.action = ActionRestartPod
		next.attempt = 1

	case StateActionTaken:
		if entry.action == ActionRestartPod {
			if entry.attempt < 3 {
				// More restart attempts available.
				next.attempt = entry.attempt + 1
			} else {
				// Exhausted restarts → escalate to reschedule.
				em.logger.Warn("escalating from restart to reschedule",
					"pod", pod, "namespace", namespace, "anomaly", anomalyType)
				next.state = StateEscalating
				next.action = ActionReschedulePod
				next.attempt = 1
			}
		} else if entry.action == ActionReschedulePod {
			if entry.attempt < 2 {
				next.attempt = entry.attempt + 1
			} else {
				// Exhausted reschedules → suspect node.
				em.logger.Warn("escalating from reschedule to cordon",
					"pod", pod, "namespace", namespace, "anomaly", anomalyType)
				next.state = StateNodeSuspect
				next.action = ActionCordonNode
				next.attempt = 1
			}
		}

	case StateEscalating:
		if entry.attempt < 2 {
			next.attempt = entry.attempt + 1
		} else {
			next.state = StateNodeSuspect
			next.action = ActionCordonNode
			next.attempt = 1
		}

	case StateNodeSuspect:
		// Cordon already attempted or not possible → manual required.
		em.logger.Error("escalation reached MANUAL state — human intervention required",
			"pod", pod, "namespace", namespace, "anomaly", anomalyType)
		next.state = StateManual
		next.action = ActionManual
		next.attempt = 0

	case StateManual:
		// Already in manual — no further autonomous actions.
		return ActionManual, 0, fmt.Errorf("escalation[%s/%s]: in MANUAL state — autonomous healing disabled", namespace, pod)
	}

	next.lastAction = time.Now()
	next.updatedAt = time.Now()
	em.entries.Store(key, &next)

	em.logger.Info("escalation state advanced",
		"pod", pod,
		"namespace", namespace,
		"anomaly", anomalyType,
		"state", next.state,
		"action", next.action,
		"attempt", next.attempt,
	)

	return next.action, next.attempt, nil
}

// MarkResolved resets the escalation state for a (pod, namespace, anomalyType)
// to RESOLVED. Called by the outcome observer when a pod is healthy.
func (em *EscalationManager) MarkResolved(pod, namespace, anomalyType string) {
	key := escalationKey{pod: pod, namespace: namespace, anomalyType: anomalyType}
	em.entries.Store(key, &escalationEntry{
		state:     StateResolved,
		updatedAt: time.Now(),
	})
	em.logger.Info("escalation reset to RESOLVED",
		"pod", pod, "namespace", namespace, "anomaly", anomalyType)
}

// CurrentState returns the current escalation state for a (pod, namespace, anomalyType).
// Returns StateObserving if no entry exists.
func (em *EscalationManager) CurrentState(pod, namespace, anomalyType string) EscalationState {
	key := escalationKey{pod: pod, namespace: namespace, anomalyType: anomalyType}
	raw, ok := em.entries.Load(key)
	if !ok {
		return StateObserving
	}
	return raw.(*escalationEntry).state
}

// IsManual returns true if the given healing context has reached the manual state
// and requires human intervention.
func (em *EscalationManager) IsManual(pod, namespace, anomalyType string) bool {
	return em.CurrentState(pod, namespace, anomalyType) == StateManual
}

// Purge removes all resolved or stale entries older than the given duration.
// Call periodically (e.g., every 10 minutes) to prevent unbounded memory growth.
func (em *EscalationManager) Purge(olderThan time.Duration) int {
	cutoff := time.Now().Add(-olderThan)
	purged := 0
	em.entries.Range(func(k, v interface{}) bool {
		entry := v.(*escalationEntry)
		if entry.state == StateResolved && entry.updatedAt.Before(cutoff) {
			em.entries.Delete(k)
			purged++
		}
		return true
	})
	return purged
}
