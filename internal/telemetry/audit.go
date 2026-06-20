// Package telemetry — Audit writes immutable action audit records to the
// Kubernetes Events API and to structured logs.
//
// Every healing action taken by the controller produces an audit entry with:
//   - what action was taken
//   - on what target (pod/node/deployment)
//   - why (anomaly + confidence + signals)
//   - whether it was a dry-run
//
// Kubernetes Events API provides a native audit trail visible via:
//
//	kubectl get events --field-selector reason=SelfHealAction -n <namespace>
//	kubectl get events --field-selector reason=SelfHealAction --all-namespaces

package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AuditEntry represents a single audit record.
type AuditEntry struct {
	ActionID    string // UUID of the ActionEvent
	AnomalyID   string // UUID of the AnomalyEvent
	Action      string // "restart_pod", "patch_resource_limits", etc.
	Target      string // resource name (pod or node)
	Namespace   string
	Reason      string // human-readable cause
	Confidence  float64
	DryRun      bool
	OutcomeType string // "resolved", "escalated", "failed" — filled by observer
}

// AuditLog writes audit entries to Kubernetes Events API and structured logs.
type AuditLog struct {
	k8s    kubernetes.Interface
	logger *slog.Logger
}

// NewAuditLog creates an AuditLog.
// k8s may be nil in test environments — RecordAction will log-only in that case.
func NewAuditLog(k8s kubernetes.Interface, logger *slog.Logger) *AuditLog {
	return &AuditLog{k8s: k8s, logger: logger}
}

// RecordAction writes an audit record for a dispatched healing action.
// It creates a native Kubernetes Event on the involved Pod so the audit trail
// is visible without any additional tooling.
func (a *AuditLog) RecordAction(ctx context.Context, entry AuditEntry) error {
	// Always emit a structured log entry.
	a.logger.Info("AUDIT",
		"action_id", entry.ActionID,
		"anomaly_id", entry.AnomalyID,
		"action", entry.Action,
		"target", entry.Target,
		"namespace", entry.Namespace,
		"reason", entry.Reason,
		"confidence", entry.Confidence,
		"dry_run", entry.DryRun,
	)

	// Write a Kubernetes Event if a K8s client is available.
	if a.k8s == nil {
		return nil
	}

	eventType := corev1.EventTypeNormal
	if entry.DryRun {
		eventType = corev1.EventTypeNormal
	}

	message := fmt.Sprintf(
		"SelfHeal action=%s confidence=%.2f anomaly_id=%s dry_run=%v reason=%s",
		entry.Action,
		entry.Confidence,
		entry.AnomalyID,
		entry.DryRun,
		entry.Reason,
	)

	now := metav1.NewTime(time.Now())
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "selfheal-",
			Namespace:    entry.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Name:      entry.Target,
			Namespace: entry.Namespace,
		},
		Reason:         "SelfHealAction",
		Message:        message,
		Type:           eventType,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source: corev1.EventSource{
			Component: "selfheal-controller",
		},
		Action: entry.Action,
	}

	_, err := a.k8s.CoreV1().Events(entry.Namespace).Create(ctx, event, metav1.CreateOptions{})
	if err != nil {
		// Non-fatal: log the error but don't block the controller.
		a.logger.Warn("audit: failed to create Kubernetes Event", "error", err, "action", entry.Action)
	}
	return nil
}
