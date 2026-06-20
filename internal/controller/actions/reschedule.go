// Package actions — reschedule.go implements the reschedule_pod action.
//
// Strategy:
//   1. Add a temporary node anti-affinity annotation to the pod's owning
//      Deployment so the scheduler avoids placing the replacement on the
//      same problematic node.
//   2. Delete the current pod (GracePeriodSeconds=0).
//   3. The Deployment controller recreates the pod; the anti-affinity
//      forces placement on a different node.
//
// The annotation key "selfheal.io/avoid-node" is purely informational
// (visible in `kubectl describe deploy`). Real anti-affinity is injected
// into spec.template.spec.affinity.podAntiAffinity.
//
// Risk: MEDIUM — triggers a rolling restart; pod migrates to a new node.

package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// RescheduleExecutor forces a pod to migrate to a different node.
type RescheduleExecutor struct{}

// Name satisfies the Executor interface.
func (r *RescheduleExecutor) Name() string {
	return "reschedule_pod"
}

// Execute adds node anti-affinity to the owning Deployment, then deletes the pod.
func (r *RescheduleExecutor) Execute(ctx context.Context, client kubernetes.Interface, target Target, dryRun bool) error {
	logger := slog.Default().With(
		"action", "reschedule_pod",
		"pod", target.Pod,
		"namespace", target.Namespace,
		"node", target.Node,
		"deployment", target.Deployment,
		"dry_run", dryRun,
	)

	if target.Pod == "" || target.Namespace == "" {
		return fmt.Errorf("reschedule_pod: pod name and namespace are required")
	}
	if target.Node == "" {
		return fmt.Errorf("reschedule_pod: node name is required for anti-affinity injection")
	}

	// ── Step 1: Inject anti-affinity on the Deployment ──────────────────────
	if target.Deployment != "" {
		if err := r.injectAntiAffinity(ctx, client, target, dryRun, logger); err != nil {
			// Non-fatal: log and continue to pod deletion.
			// The pod will still be rescheduled; it may land on the same node
			// but the outcome observer will detect this and escalate.
			logger.Warn("could not inject anti-affinity — proceeding with pod deletion only", "error", err)
		}
	}

	// ── Step 2: Delete the pod (forces reschedule) ───────────────────────────
	zero := int64(0)
	deleteOpts := metav1.DeleteOptions{GracePeriodSeconds: &zero}

	if dryRun {
		deleteOpts.DryRun = []string{metav1.DryRunAll}
		logger.Info("DRY RUN: would delete pod for reschedule", "pod", target.Pod)
		return nil
	}

	logger.Info("deleting pod to force reschedule away from node", "pod", target.Pod, "node", target.Node)

	if err := client.CoreV1().Pods(target.Namespace).Delete(ctx, target.Pod, deleteOpts); err != nil {
		return fmt.Errorf("reschedule_pod: delete pod %s/%s: %w", target.Namespace, target.Pod, err)
	}

	logger.Info("pod deleted — will be rescheduled on a different node", "pod", target.Pod)
	return nil
}

// injectAntiAffinity patches the owning Deployment to add node anti-affinity
// that prevents new pods from being scheduled on the problematic node.
func (r *RescheduleExecutor) injectAntiAffinity(
	ctx context.Context,
	client kubernetes.Interface,
	target Target,
	dryRun bool,
	logger *slog.Logger,
) error {
	// Build a strategic merge patch that adds a requiredDuringSchedulingIgnoredDuringExecution
	// anti-affinity rule excluding the problematic node.
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"affinity": map[string]interface{}{
						"nodeAffinity": map[string]interface{}{
							"requiredDuringSchedulingIgnoredDuringExecution": map[string]interface{}{
								"nodeSelectorTerms": []map[string]interface{}{
									{
										"matchExpressions": []map[string]interface{}{
											{
												"key":      "kubernetes.io/hostname",
												"operator": "NotIn",
												"values":   []string{target.Node},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("reschedule: marshal anti-affinity patch: %w", err)
	}

	patchOpts := metav1.PatchOptions{}
	if dryRun {
		patchOpts.DryRun = []string{metav1.DryRunAll}
	}

	logger.Info("injecting node anti-affinity on deployment",
		"deployment", target.Deployment,
		"avoid_node", target.Node,
	)

	_, err = client.AppsV1().Deployments(target.Namespace).Patch(
		ctx,
		target.Deployment,
		types.StrategicMergePatchType,
		patchBytes,
		patchOpts,
	)
	return err
}
