// Package actions — cordon.go implements the cordon_node healing action.
//
// Strategy: Patch Node.Spec.Unschedulable = true via the Kubernetes Nodes API.
// This prevents new pods from being scheduled on the node while existing pods
// continue running (use drain for eviction — drain requires manual approval).
//
// Guardrail gate (enforced by the Reconciler before calling this executor):
//   - At least cordon_requires_min_affected_pods pods must be affected on
//     the node before this action is permitted (default: 3).
//
// Risk: HIGH — affects all future scheduling on the node.
//
// Un-cordon: performed manually via `kubectl uncordon <node>`.

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

// CordonExecutor cordons a node by setting Spec.Unschedulable = true.
type CordonExecutor struct{}

// Name satisfies the Executor interface.
func (c *CordonExecutor) Name() string {
	return "cordon_node"
}

// Execute patches the node to make it unschedulable.
// NOTE: The caller (Reconciler) must have already verified that the
// minimum affected pod count guardrail is met before invoking this.
func (c *CordonExecutor) Execute(ctx context.Context, client kubernetes.Interface, target Target, dryRun bool) error {
	logger := slog.Default().With(
		"action", "cordon_node",
		"node", target.Node,
		"dry_run", dryRun,
	)

	if target.Node == "" {
		return fmt.Errorf("cordon_node: node name is required")
	}

	// Verify the node exists before attempting to patch.
	node, err := client.CoreV1().Nodes().Get(ctx, target.Node, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("cordon_node: get node %q: %w", target.Node, err)
	}

	if node.Spec.Unschedulable {
		logger.Info("node is already cordoned — no action needed", "node", target.Node)
		return nil
	}

	// Build a strategic merge patch to set Spec.Unschedulable = true.
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"unschedulable": true,
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("cordon_node: marshal patch: %w", err)
	}

	patchOpts := metav1.PatchOptions{}
	if dryRun {
		patchOpts.DryRun = []string{metav1.DryRunAll}
		logger.Info("DRY RUN: would cordon node", "node", target.Node)
		return nil
	}

	logger.Warn("cordoning node — no new pods will be scheduled here",
		"node", target.Node,
		"action_reason", "multiple pods affected with hardware-level anomalies",
	)

	_, err = client.CoreV1().Nodes().Patch(
		ctx,
		target.Node,
		types.StrategicMergePatchType,
		patchBytes,
		patchOpts,
	)
	if err != nil {
		return fmt.Errorf("cordon_node: patch node %q: %w", target.Node, err)
	}

	logger.Warn("node cordoned successfully",
		"node", target.Node,
		"uncordon_cmd", fmt.Sprintf("kubectl uncordon %s", target.Node),
	)
	return nil
}

// AffectedPodCount returns the number of pods from the given namespace+pod list
// that are running on the specified node. Used by the Reconciler to enforce
// the cordon_requires_min_affected_pods guardrail.
func AffectedPodCount(ctx context.Context, client kubernetes.Interface, node, namespace string) (int, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", node),
	})
	if err != nil {
		return 0, fmt.Errorf("cordon: list pods on node %s: %w", node, err)
	}
	return len(pods.Items), nil
}
