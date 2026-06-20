// Package actions — restart.go implements the restart_pod healing action.
//
// Strategy: Delete the target pod by name + namespace.
// The owning ReplicaSet or StatefulSet controller will immediately create a
// replacement pod, which the Kubernetes scheduler will place on a healthy node.
//
// Kubernetes delete options:
//   - GracePeriodSeconds=0 for OOM/hung-process scenarios (immediate SIGKILL)
//   - Default grace period for normal latency anomalies
//
// Risk: LOW — fully reversible, pod is recreated automatically.

package actions

import (
	"context"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RestartExecutor implements the restart_pod action by deleting the target pod.
type RestartExecutor struct{}

// Name satisfies the Executor interface.
func (r *RestartExecutor) Name() string {
	return "restart_pod"
}

// Execute deletes the named pod, causing its controller to recreate it.
// If dryRun=true, the action is logged but the K8s API is not called.
func (r *RestartExecutor) Execute(ctx context.Context, client kubernetes.Interface, target Target, dryRun bool) error {
	logger := slog.Default().With(
		"action", "restart_pod",
		"pod", target.Pod,
		"namespace", target.Namespace,
		"dry_run", dryRun,
	)

	if target.Pod == "" || target.Namespace == "" {
		return fmt.Errorf("restart_pod: pod name and namespace are required")
	}

	deleteOpts := metav1.DeleteOptions{}
	// For OOM scenarios, use immediate deletion to avoid stuck terminating state.
	// grace=0 sends SIGKILL immediately; the container runtime removes it from
	// the pod CIDR so traffic is not routed to it.
	zero := int64(0)
	deleteOpts.GracePeriodSeconds = &zero

	if dryRun {
		deleteOpts.DryRun = []string{metav1.DryRunAll}
		logger.Info("DRY RUN: would delete pod (GracePeriod=0)", "pod", target.Pod)
		return nil
	}

	logger.Info("deleting pod to trigger restart", "pod", target.Pod)

	if err := client.CoreV1().Pods(target.Namespace).Delete(ctx, target.Pod, deleteOpts); err != nil {
		return fmt.Errorf("restart_pod: delete pod %s/%s: %w", target.Namespace, target.Pod, err)
	}

	logger.Info("pod deleted — controller will recreate it", "pod", target.Pod)
	return nil
}
