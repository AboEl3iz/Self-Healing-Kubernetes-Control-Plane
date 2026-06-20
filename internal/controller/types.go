// Package controller — types.go defines the event structs shared across
// the controller, actions, escalation, and observer subsystems.
//
// These structs are the Go representation of the protobuf-defined event
// schemas. JSON is used for NATS transport in Phase 1-3.
//
// AnomalyEvent  ← consumed from selfheal.anomalies.<namespace>
// ActionEvent   → published to   selfheal.actions.<namespace>
// OutcomeEvent  → published to   selfheal.outcomes.<namespace>

package controller

import "time"

// ─── Incoming ────────────────────────────────────────────────────────────────

// AnomalyEvent is the message produced by the Analyzer and consumed by the
// Controller. It carries full context for the healing decision.
type AnomalyEvent struct {
	AnomalyID       string   `json:"id"`
	Type            string   `json:"metric"`             // "high_io_wait", "memory_pressure", …
	Confidence      float64  `json:"confidence"`
	AffectedPod     string   `json:"pod"`
	AffectedNode    string   `json:"node"`
	Namespace       string   `json:"namespace"`
	Deployment      string   `json:"deployment"`
	Signals         []string `json:"active_signals"`
	SuggestedCause  string   `json:"suggested_cause"`
	SuggestedAction string   `json:"suggested_action"`
	Timestamp       int64    `json:"timestamp"`        // Unix ms
	TTLS            int      `json:"ttl_s"`
}

// ─── Outgoing ─────────────────────────────────────────────────────────────────

// ActionEvent is published to selfheal.actions.<namespace> immediately after
// the controller dispatches a healing action.
type ActionEvent struct {
	ActionID        string            `json:"action_id"`
	AnomalyID       string            `json:"anomaly_id"`
	Action          string            `json:"action"`          // "restart_pod", "patch_resource_limits", …
	TargetKind      string            `json:"target_kind"`     // "Pod", "Deployment", "Node"
	TargetName      string            `json:"target_name"`
	TargetNamespace string            `json:"target_namespace"`
	TargetNode      string            `json:"target_node,omitempty"`
	Patch           map[string]string `json:"patch,omitempty"` // for patch_resource_limits
	FromValue       string            `json:"from_value,omitempty"`
	ToValue         string            `json:"to_value,omitempty"`
	Reason          string            `json:"reason"`
	Confidence      float64           `json:"confidence"`
	DryRun          bool              `json:"dry_run"`
	Attempt         int               `json:"attempt"`         // escalation attempt number
	Timestamp       int64             `json:"timestamp"`       // Unix ms
}

// OutcomeEvent is published to selfheal.outcomes.<namespace> after the
// observation window elapses and the target's health is re-evaluated.
type OutcomeEvent struct {
	ActionID       string        `json:"action_id"`
	AnomalyID      string        `json:"anomaly_id"`
	Resolved       bool          `json:"resolved"`
	ResolutionType string        `json:"resolution_type"` // "immediate", "escalated", "failed"
	ResolutionMs   int64         `json:"resolution_ms"`
	ObservedAt     time.Time     `json:"observed_at"`
	Timestamp      int64         `json:"timestamp"` // Unix ms
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// ActionType enumerates the supported autonomous healing actions.
type ActionType string

const (
	ActionRestartPod        ActionType = "restart_pod"
	ActionPatchLimits       ActionType = "patch_resource_limits"
	ActionReschedulePod     ActionType = "reschedule_pod"
	ActionCordonNode        ActionType = "cordon_node"
	ActionManual            ActionType = "manual" // terminal: page on-call
)

// EscalationState tracks where a (pod, anomalyType) tuple is in the
// healing state machine.
type EscalationState string

const (
	StateObserving   EscalationState = "OBSERVING"
	StateActionTaken EscalationState = "ACTION_TAKEN"
	StateEscalating  EscalationState = "ESCALATING"
	StateNodeSuspect EscalationState = "NODE_SUSPECT"
	StateManual      EscalationState = "MANUAL"
	StateResolved    EscalationState = "RESOLVED"
)
