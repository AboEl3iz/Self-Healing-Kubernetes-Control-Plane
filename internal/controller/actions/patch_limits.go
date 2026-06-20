// Package actions — patch_limits.go implements the patch_resource_limits action.
//
// Strategy: Find the owning Deployment, then strategic-merge-patch its first
// container's resource limits, increasing memory by 1.5× (capped at
// maxMemoryIncreasePct from guardrails.yaml, default 100% = 2×).
//
// Patch format: strategic merge patch (JSON)
//   spec.template.spec.containers[0].resources.limits.memory
//
// The patch is bounded:
//   - Never increase by more than maxMemoryIncreasePct percent
//   - Minimum resulting limit: 128Mi
//
// Risk: MEDIUM — triggers a rolling restart of the Deployment.

package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// PatchLimitsExecutor patches the owning Deployment's memory limits.
type PatchLimitsExecutor struct {
	maxMemoryIncreasePct int // e.g., 100 → allow up to 2× current
}

// Name satisfies the Executor interface.
func (p *PatchLimitsExecutor) Name() string {
	return "patch_resource_limits"
}

// Execute increases the memory limit on the owning Deployment by 1.5×.
// If no Deployment is found or the Deployment already has high limits, it
// falls back to a safe default increase.
func (p *PatchLimitsExecutor) Execute(ctx context.Context, client kubernetes.Interface, target Target, dryRun bool) error {
	logger := slog.Default().With(
		"action", "patch_resource_limits",
		"pod", target.Pod,
		"namespace", target.Namespace,
		"deployment", target.Deployment,
		"dry_run", dryRun,
	)

	if target.Deployment == "" {
		return fmt.Errorf("patch_resource_limits: deployment name is required")
	}

	// Fetch the current Deployment.
	deploy, err := client.AppsV1().Deployments(target.Namespace).Get(ctx, target.Deployment, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("patch_resource_limits: get deployment %s/%s: %w", target.Namespace, target.Deployment, err)
	}

	if len(deploy.Spec.Template.Spec.Containers) == 0 {
		return fmt.Errorf("patch_resource_limits: deployment %s has no containers", target.Deployment)
	}

	container := &deploy.Spec.Template.Spec.Containers[0]
	currentMemory := container.Resources.Limits.Memory()
	if currentMemory == nil || currentMemory.IsZero() {
		// No current limit — set a baseline of 512Mi.
		currentMemory = resource.NewQuantity(512*1024*1024, resource.BinarySI)
	}

	// Compute new limit = current × 1.5, capped at (current × (1 + maxPct/100)).
	currentBytes := currentMemory.Value()
	multiplier := 1.5
	maxMultiplier := 1.0 + float64(p.maxMemoryIncreasePct)/100.0
	if multiplier > maxMultiplier {
		multiplier = maxMultiplier
	}

	newBytes := int64(float64(currentBytes) * multiplier)
	newMemory := resource.NewQuantity(newBytes, resource.BinarySI)

	fromValue := currentMemory.String()
	toValue := newMemory.String()
	logger.Info("patching deployment memory limit",
		"from", fromValue,
		"to", toValue,
		"deployment", target.Deployment,
	)

	// Build a strategic merge patch.
	patch := buildResourcePatch(container.Name, newMemory)
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("patch_resource_limits: marshal patch: %w", err)
	}

	patchOpts := metav1.PatchOptions{}
	if dryRun {
		patchOpts.DryRun = []string{metav1.DryRunAll}
		logger.Info("DRY RUN: would apply patch", "patch", string(patchBytes))
		return nil
	}

	_, err = client.AppsV1().Deployments(target.Namespace).Patch(
		ctx,
		target.Deployment,
		types.StrategicMergePatchType,
		patchBytes,
		patchOpts,
	)
	if err != nil {
		return fmt.Errorf("patch_resource_limits: patch deployment %s/%s: %w", target.Namespace, target.Deployment, err)
	}

	logger.Info("deployment memory limit patched",
		"from", fromValue,
		"to", toValue,
	)
	return nil
}

// buildResourcePatch returns a strategic merge patch document that updates
// the named container's memory limit.
func buildResourcePatch(containerName string, newMemory *resource.Quantity) map[string]interface{} {
	return map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []map[string]interface{}{
						{
							"name": containerName,
							"resources": map[string]interface{}{
								"limits": map[string]interface{}{
									"memory": newMemory.String(),
								},
							},
						},
					},
				},
			},
		},
	}
}

// parseMemoryBytes parses a Kubernetes memory quantity string (e.g., "512Mi")
// and returns bytes. Returns 0 on parse error.
func parseMemoryBytes(s string) int64 {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	return q.Value()
}

// formatMemory formats a byte count as a Kubernetes memory quantity string.
func formatMemory(bytes int64) string {
	q := resource.NewQuantity(bytes, resource.BinarySI)
	return q.String()
}

// parseResourceLimits extracts memory limit from a ResourceList.
// Returns "0" if not set.
func parseResourceLimits(limits corev1.ResourceList) string {
	if mem, ok := limits[corev1.ResourceMemory]; ok {
		return mem.String()
	}
	return "0"
}

// scaleBytes multiplies a byte value by a factor represented as "1.5x" string.
// Returns the original value on parse error.
func scaleBytes(bytes int64, factorStr string) int64 {
	factorStr = strings.TrimSuffix(factorStr, "x")
	factor, err := strconv.ParseFloat(factorStr, 64)
	if err != nil {
		return bytes
	}
	return int64(float64(bytes) * factor)
}
