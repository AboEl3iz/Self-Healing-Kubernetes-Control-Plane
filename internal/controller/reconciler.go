// Package controller — Reconciler is the Kubernetes healing action dispatcher.
//
// Pipeline per AnomalyEvent:
//   1. Decode AnomalyEvent from NATS selfheal.anomalies.*
//   2. Guardrail gates:
//        a. IsProtectedNamespace / IsProtectedPod
//        b. CircuitBreaker.Allow()
//        c. GlobalRateLimiter.Allow()
//        d. CooldownStore.Allow(pod, namespace, action)
//        e. RequiresConfirmation (drain_node always blocked)
//   3. EscalationManager.NextAction() — pick next action in state machine
//   4. Cordon gate: verify min affected pod count (for cordon_node only)
//   5. Dispatcher.Execute() — call Kubernetes API (or dry-run)
//   6. Publish ActionEvent to selfheal.actions.<namespace>
//   7. AuditLog.RecordAction()
//   8. Launch OutcomeObserver goroutine (observes for window, then publishes OutcomeEvent)

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
	"github.com/karim-aboelaiz/selfheal-cp/internal/controller/actions"
	"github.com/karim-aboelaiz/selfheal-cp/internal/controller/guardrails"
	"github.com/karim-aboelaiz/selfheal-cp/internal/telemetry"

	"github.com/google/uuid"
)

// Reconciler manages the full healing action lifecycle.
type Reconciler struct {
	k8s            kubernetes.Interface
	subscriber     *bus.Subscriber
	publisher      *bus.Publisher
	policy         *guardrails.Policy
	rateLimiter    *guardrails.GlobalRateLimiter
	cooldowns      *guardrails.CooldownStore
	circuitBreaker *guardrails.CircuitBreaker
	escalation     *EscalationManager
	dispatcher     *actions.Dispatcher
	observer       *OutcomeObserver
	audit          *telemetry.AuditLog
	metrics        *telemetry.Metrics
	dryRun         bool
	logger         *slog.Logger
}

// ReconcilerConfig bundles all dependencies for NewReconciler.
type ReconcilerConfig struct {
	K8s        kubernetes.Interface
	Subscriber *bus.Subscriber
	Publisher  *bus.Publisher
	Policy     *guardrails.Policy
	Audit      *telemetry.AuditLog
	Metrics    *telemetry.Metrics
	DryRun     bool
	Logger     *slog.Logger
}

// NewReconciler wires all Phase 3 components into the Reconciler.
func NewReconciler(cfg ReconcilerConfig) *Reconciler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	rateLimiter := guardrails.NewGlobalRateLimiter(10 * time.Second)
	cooldowns := guardrails.NewCooldownStore(cfg.Policy)
	cb := guardrails.NewCircuitBreaker(cfg.Policy, logger)
	escalation := NewEscalationManager(logger)
	dispatcher := actions.NewDispatcher(cfg.Policy.MaxMemoryIncreasePct())
	observer := NewOutcomeObserver(cfg.K8s, cfg.Publisher, escalation, cb, cfg.Metrics, logger)

	return &Reconciler{
		k8s:            cfg.K8s,
		subscriber:     cfg.Subscriber,
		publisher:      cfg.Publisher,
		policy:         cfg.Policy,
		rateLimiter:    rateLimiter,
		cooldowns:      cooldowns,
		circuitBreaker: cb,
		escalation:     escalation,
		dispatcher:     dispatcher,
		observer:       observer,
		audit:          cfg.Audit,
		metrics:        cfg.Metrics,
		dryRun:         cfg.DryRun || cfg.Policy.IsDryRun(),
		logger:         logger,
	}
}

// Run starts the reconciliation loop. Blocks until ctx is canceled.
// It subscribes to selfheal.anomalies.* and processes each AnomalyEvent.
func (r *Reconciler) Run(ctx context.Context) error {
	r.logger.Info("reconciler: starting — subscribing to anomalies",
		"dry_run", r.dryRun,
	)

	// Background goroutine: purge stale escalation entries every 10 minutes.
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n := r.escalation.Purge(2 * time.Hour)
				if n > 0 {
					r.logger.Debug("escalation: purged stale entries", "count", n)
				}
			}
		}
	}()

	return r.subscriber.SubscribeAnomalies(ctx, r.handleAnomaly)
}

// handleAnomaly is the MessageHandler called for each AnomalyEvent from NATS.
// Returns nil to ACK, non-nil to NAK (message will be redelivered).
func (r *Reconciler) handleAnomaly(data []byte) error {
	r.logger.Info("received raw NATS message", "data", string(data))
	var anomaly AnomalyEvent
	if err := json.Unmarshal(data, &anomaly); err != nil {
		r.logger.Error("reconciler: failed to decode AnomalyEvent", "error", err)
		// Return nil to ACK — a malformed message should not be redelivered.
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.reconcile(ctx, anomaly); err != nil {
		r.logger.Warn("reconciler: anomaly processing skipped",
			"anomaly_id", anomaly.AnomalyID,
			"reason", err,
		)
		// Return nil to ACK — guardrail blocks are not delivery failures.
		return nil
	}
	return nil
}

// reconcile contains the full decision + dispatch pipeline for one AnomalyEvent.
func (r *Reconciler) reconcile(ctx context.Context, anomaly AnomalyEvent) error {
	log := r.logger.With(
		"anomaly_id", anomaly.AnomalyID,
		"type", anomaly.Type,
		"pod", anomaly.AffectedPod,
		"namespace", anomaly.Namespace,
		"confidence", anomaly.Confidence,
	)

	// ── Gate 1: Protected namespace ─────────────────────────────────────────
	if r.policy.IsProtectedNamespace(anomaly.Namespace) {
		return fmt.Errorf("namespace %q is protected", anomaly.Namespace)
	}

	// ── Gate 2: Fetch pod labels for protected-pod check ────────────────────
	var podLabels map[string]string
	pod, err := r.k8s.CoreV1().Pods(anomaly.Namespace).Get(ctx, anomaly.AffectedPod, metav1.GetOptions{})
	if err == nil {
		podLabels = pod.Labels
	}
	if r.policy.IsProtectedPod(podLabels) {
		return fmt.Errorf("pod %s/%s has a protected label", anomaly.Namespace, anomaly.AffectedPod)
	}

	// ── Gate 3: Circuit breaker ──────────────────────────────────────────────
	if !r.circuitBreaker.Allow() {
		return fmt.Errorf("circuit breaker open: %s", r.circuitBreaker.TripReason())
	}

	// ── Gate 4: Global rate limiter ──────────────────────────────────────────
	if !r.rateLimiter.Allow() {
		wait := r.rateLimiter.TimeUntilNext()
		return fmt.Errorf("global rate limit: next action in %s", wait)
	}

	// ── Gate 5: Escalation — determine next action ───────────────────────────
	if r.escalation.IsManual(anomaly.AffectedPod, anomaly.Namespace, anomaly.Type) {
		return fmt.Errorf("pod %s/%s is in MANUAL state — human intervention required", anomaly.Namespace, anomaly.AffectedPod)
	}

	nextAction, attempt, err := r.escalation.NextAction(anomaly.AffectedPod, anomaly.Namespace, anomaly.Type)
	if err != nil {
		return err
	}

	actionName := string(nextAction)

	// ── Gate 6: Actions that require manual confirmation ─────────────────────
	if r.policy.RequiresConfirmation(actionName) {
		r.escalation.MarkResolved(anomaly.AffectedPod, anomaly.Namespace, anomaly.Type) // reset so we don't loop
		return fmt.Errorf("action %q requires manual confirmation — not executing autonomously", actionName)
	}

	// ── Gate 7: Cooldown ─────────────────────────────────────────────────────
	if !r.cooldowns.Allow(anomaly.AffectedPod, anomaly.Namespace, actionName) {
		reason, wait := r.cooldowns.TimeUntilNext(anomaly.AffectedPod, anomaly.Namespace, actionName)
		return fmt.Errorf("cooldown active: %s (wait %s)", reason, wait)
	}

	// ── Gate 8: Cordon min-pod-count check ───────────────────────────────────
	if nextAction == ActionCordonNode {
		count, err := actions.AffectedPodCount(ctx, r.k8s, anomaly.AffectedNode, anomaly.Namespace)
		if err != nil {
			log.Warn("could not count affected pods on node", "error", err)
		}
		minCount := r.policy.CordonMinPodCount()
		if count < minCount {
			return fmt.Errorf("cordon gate: only %d pods affected on node %s (need %d)", count, anomaly.AffectedNode, minCount)
		}
	}

	// ── Dispatch ─────────────────────────────────────────────────────────────
	target := actions.Target{
		Pod:        anomaly.AffectedPod,
		Namespace:  anomaly.Namespace,
		Node:       anomaly.AffectedNode,
		Deployment: anomaly.Deployment,
		Labels:     podLabels,
	}

	log.Info("dispatching healing action",
		"action", actionName,
		"attempt", attempt,
		"dry_run", r.dryRun,
	)

	dispatchErr := r.dispatcher.Execute(ctx, r.k8s, actionName, target, r.dryRun)

	actionID := uuid.New().String()
	actionEvent := ActionEvent{
		ActionID:        actionID,
		AnomalyID:       anomaly.AnomalyID,
		Action:          actionName,
		TargetKind:      "Pod",
		TargetName:      anomaly.AffectedPod,
		TargetNamespace: anomaly.Namespace,
		TargetNode:      anomaly.AffectedNode,
		Reason:          anomaly.SuggestedCause,
		Confidence:      anomaly.Confidence,
		DryRun:          r.dryRun,
		Attempt:         attempt,
		Timestamp:       time.Now().UnixMilli(),
	}
	if nextAction == ActionCordonNode {
		actionEvent.TargetKind = "Node"
		actionEvent.TargetName = anomaly.AffectedNode
	}

	if dispatchErr != nil {
		r.circuitBreaker.RecordFailure()
		log.Error("action dispatch failed", "action", actionName, "error", dispatchErr)
		// Still emit the action event with the error context.
	} else {
		// Publish ActionEvent to NATS.
		if eventData, err := json.Marshal(actionEvent); err == nil {
			_ = r.publisher.PublishAction(ctx, anomaly.Namespace, eventData)
		}
		// Increment dispatched counter.
		if r.metrics != nil {
			r.metrics.ActionsDispatchedTotal.WithLabelValues(actionName, anomaly.Namespace).Inc()
		}
	}

	// ── Audit ─────────────────────────────────────────────────────────────────
	_ = r.audit.RecordAction(ctx, telemetry.AuditEntry{
		ActionID:   actionID,
		AnomalyID:  anomaly.AnomalyID,
		Action:     actionName,
		Target:     anomaly.AffectedPod,
		Namespace:  anomaly.Namespace,
		Reason:     anomaly.SuggestedCause,
		Confidence: anomaly.Confidence,
		DryRun:     r.dryRun,
	})

	// ── Outcome observer ──────────────────────────────────────────────────────
	if dispatchErr == nil && !r.dryRun {
		window := r.policy.ObservationWindow(actionName)
		r.observer.WatchAsync(context.Background(), actionEvent, anomaly.Type, window)
	}

	return dispatchErr
}
