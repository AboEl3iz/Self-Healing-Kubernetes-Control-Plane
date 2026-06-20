// Package actions defines the Executor interface and Target struct shared
// by all healing action implementations.
//
// Each action (restart, patch_limits, reschedule, cordon) implements
// the Executor interface, which the Reconciler uses to dispatch actions
// without knowing the specifics of each K8s API call.
//
// The Dispatcher provides a registry to look up Executors by ActionType.

package actions

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
)

// Target identifies the Kubernetes resource to act upon.
type Target struct {
	Pod        string // pod name
	Namespace  string // pod namespace
	Node       string // node name (for cordon)
	Deployment string // owning deployment (for patch_limits, reschedule)
	// Labels holds the pod labels, used for protected-pod checks upstream.
	Labels map[string]string
}

// Executor is the interface every healing action must implement.
type Executor interface {
	// Name returns the action identifier (matches ActionType constants).
	Name() string
	// Execute performs the healing action. Returns nil on success.
	// dryRun=true means: compute and log the action but do NOT call the K8s API.
	Execute(ctx context.Context, client kubernetes.Interface, target Target, dryRun bool) error
}

// Dispatcher holds a registry of Executors and resolves them by action name.
type Dispatcher struct {
	executors map[string]Executor
}

// NewDispatcher builds a Dispatcher pre-populated with all known action
// executors. Pass the policy limits needed by individual executors.
func NewDispatcher(maxMemoryIncreasePct int) *Dispatcher {
	d := &Dispatcher{executors: make(map[string]Executor)}

	d.register(&RestartExecutor{})
	d.register(&PatchLimitsExecutor{maxMemoryIncreasePct: maxMemoryIncreasePct})
	d.register(&RescheduleExecutor{})
	d.register(&CordonExecutor{})

	return d
}

func (d *Dispatcher) register(e Executor) {
	d.executors[e.Name()] = e
}

// Execute looks up and invokes the named action executor.
func (d *Dispatcher) Execute(ctx context.Context, client kubernetes.Interface, action string, target Target, dryRun bool) error {
	e, ok := d.executors[action]
	if !ok {
		return fmt.Errorf("dispatcher: unknown action %q", action)
	}
	return e.Execute(ctx, client, target, dryRun)
}
