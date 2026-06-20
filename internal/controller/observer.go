// Package controller — observer.go watches pod/node health after a healing
// action is dispatched and publishes an OutcomeEvent to NATS.
//
// Design principles:
//   - Uses the Kubernetes API (polling with backoff) to check pod status.
//   - Does NOT use a long-lived Informer watch to avoid complexity; polling
//     is acceptable given the observation window is 60–120s.
//   - Runs in a detached goroutine so the reconciler can accept new anomalies.
//   - Publishes OutcomeEvent to selfheal.outcomes.<namespace>.
//   - Calls escalation.MarkResolved() on success.
//   - Calls circuitBreaker.RecordSuccess/Failure().
//
// Observation logic:
//   Poll every 5s for up to observationWindow. If pod is Running+Ready → resolved.
//   If not resolved by end of window → outcome=failed → escalation advances.

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
	"github.com/karim-aboelaiz/selfheal-cp/internal/controller/guardrails"
	"github.com/karim-aboelaiz/selfheal-cp/internal/telemetry"
)

const observerPollInterval = 5 * time.Second

// OutcomeObserver watches pod health after a healing action and publishes results.
type OutcomeObserver struct {
	client         kubernetes.Interface
	publisher      *bus.Publisher
	escalation     *EscalationManager
	circuitBreaker *guardrails.CircuitBreaker
	metrics        *telemetry.Metrics
	logger         *slog.Logger
}

// NewOutcomeObserver creates an OutcomeObserver.
func NewOutcomeObserver(
	client kubernetes.Interface,
	publisher *bus.Publisher,
	escalation *EscalationManager,
	cb *guardrails.CircuitBreaker,
	metrics *telemetry.Metrics,
	logger *slog.Logger,
) *OutcomeObserver {
	return &OutcomeObserver{
		client:         client,
		publisher:      publisher,
		escalation:     escalation,
		circuitBreaker: cb,
		metrics:        metrics,
		logger:         logger,
	}
}

// WatchAsync launches a goroutine to observe the outcome of the given action.
// It returns immediately; the goroutine runs for up to observationWindow.
func (o *OutcomeObserver) WatchAsync(
	ctx context.Context,
	action ActionEvent,
	anomalyType string,
	observationWindow time.Duration,
) {
	go func() {
		resolved, resolutionMs := o.watch(ctx, action, observationWindow)
		o.publish(ctx, action, anomalyType, resolved, resolutionMs)
	}()
}

// watch polls pod status until the pod is healthy or the observation window expires.
func (o *OutcomeObserver) watch(ctx context.Context, action ActionEvent, window time.Duration) (resolved bool, resolutionMs int64) {
	deadline := time.Now().Add(window)
	start := time.Now()

	logger := o.logger.With(
		"action_id", action.ActionID,
		"pod", action.TargetName,
		"namespace", action.TargetNamespace,
		"action", action.Action,
	)

	logger.Info("outcome observer started", "window", window)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			logger.Info("outcome observer cancelled")
			return false, time.Since(start).Milliseconds()
		case <-time.After(observerPollInterval):
		}

		// For cordon_node: check that the node is now unschedulable.
		if action.Action == string(ActionCordonNode) {
			ok, err := o.checkNodeCordoned(ctx, action.TargetNode)
			if err != nil {
				logger.Warn("observer: error checking node", "error", err)
				continue
			}
			if ok {
				elapsed := time.Since(start).Milliseconds()
				logger.Info("outcome: node cordoned successfully", "elapsed_ms", elapsed)
				return true, elapsed
			}
			continue
		}

		// For pod actions: check that the pod is Running+Ready.
		ok, err := o.checkPodReady(ctx, action.TargetName, action.TargetNamespace)
		if err != nil {
			logger.Warn("observer: error checking pod", "error", err)
			continue
		}
		if ok {
			elapsed := time.Since(start).Milliseconds()
			logger.Info("outcome: pod is Running+Ready", "elapsed_ms", elapsed)
			return true, elapsed
		}
	}

	elapsed := time.Since(start).Milliseconds()
	logger.Warn("outcome: observation window expired — pod not recovered", "elapsed_ms", elapsed)
	return false, elapsed
}

// checkPodReady returns true if the named pod exists and all containers are Ready.
func (o *OutcomeObserver) checkPodReady(ctx context.Context, podName, namespace string) (bool, error) {
	pod, err := o.client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		// Pod not found yet (being recreated after delete) — not ready.
		return false, nil //nolint:nilerr
	}

	if pod.Status.Phase != corev1.PodRunning {
		return false, nil
	}

	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true, nil
		}
	}
	return false, nil
}

// checkNodeCordoned returns true if the node is marked Unschedulable.
func (o *OutcomeObserver) checkNodeCordoned(ctx context.Context, nodeName string) (bool, error) {
	node, err := o.client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("observer: get node %s: %w", nodeName, err)
	}
	return node.Spec.Unschedulable, nil
}

// publish records the outcome, updates metrics, and publishes to NATS.
func (o *OutcomeObserver) publish(
	ctx context.Context,
	action ActionEvent,
	anomalyType string,
	resolved bool,
	resolutionMs int64,
) {
	resolutionType := "failed"
	if resolved {
		resolutionType = "immediate"
		o.circuitBreaker.RecordSuccess()
		o.escalation.MarkResolved(action.TargetName, action.TargetNamespace, anomalyType)
		if o.metrics != nil {
			o.metrics.ActionsResolvedTotal.WithLabelValues(action.Action, resolutionType).Inc()
			o.metrics.ActionLatencyMs.WithLabelValues(action.Action).Observe(float64(resolutionMs))
		}
	} else {
		o.circuitBreaker.RecordFailure()
		if o.metrics != nil {
			o.metrics.ActionsResolvedTotal.WithLabelValues(action.Action, resolutionType).Inc()
		}
	}

	outcome := OutcomeEvent{
		ActionID:       action.ActionID,
		AnomalyID:      action.AnomalyID,
		Resolved:       resolved,
		ResolutionType: resolutionType,
		ResolutionMs:   resolutionMs,
		ObservedAt:     time.Now(),
		Timestamp:      time.Now().UnixMilli(),
	}

	data, err := json.Marshal(outcome)
	if err != nil {
		o.logger.Error("observer: marshal outcome event", "error", err)
		return
	}

	if err := o.publisher.PublishOutcome(ctx, action.TargetNamespace, data); err != nil {
		o.logger.Error("observer: publish outcome event", "error", err)
		return
	}

	o.logger.Info("outcome event published",
		"action_id", action.ActionID,
		"resolved", resolved,
		"resolution_type", resolutionType,
		"resolution_ms", resolutionMs,
	)
}
