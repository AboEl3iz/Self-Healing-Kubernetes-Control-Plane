// Package guardrails — Policy loads and enforces the safety guardrails.
//
// The policy is loaded from config/guardrails.yaml and enforced by the
// Reconciler before every action. No action may bypass these constraints.
//
// Policy is reloadable via SIGHUP (live update without restart).

package guardrails

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── YAML schema ──────────────────────────────────────────────────────────────

// ActionConfig mirrors the per-action block in guardrails.yaml.
type ActionConfig struct {
	RiskLevel            string `yaml:"risk_level"`
	RequiresConfirmation bool   `yaml:"requires_confirmation"`
	Cooldown             string `yaml:"cooldown"`
	MaxPerHour           int    `yaml:"max_per_hour"`
	// patch_resource_limits specific
	MaxMemoryIncreasePct int `yaml:"max_memory_increase_pct"`
	MaxCPUIncreasePct    int `yaml:"max_cpu_increase_pct"`
	// cordon_node specific
	MinAffectedPods int `yaml:"min_affected_pods"`
	// scale_deployment specific
	MaxScaleFactor int `yaml:"max_scale_factor"`
}

// ProtectedLabel mirrors the protected_labels list entries.
type ProtectedLabel struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// CircuitBreakerConfig mirrors the circuit_breaker block.
type CircuitBreakerConfig struct {
	Enabled             bool   `yaml:"enabled"`
	TriggerOnFailurePct int    `yaml:"trigger_on_failure_pct"`
	EvaluationWindow    string `yaml:"evaluation_window"`
	Response            string `yaml:"response"`
	PauseDuration       string `yaml:"pause_duration"`
	AlertOnTrip         bool   `yaml:"alert_on_trip"`
}

// EscalationStep mirrors one entry in escalation_path.
type EscalationStep struct {
	Action              string `yaml:"action"`
	MaxAttempts         int    `yaml:"max_attempts"`
	WaitBetweenAttempts string `yaml:"wait_between_attempts"`
	RequiresPodCount    int    `yaml:"requires_pod_count"`
	Alert               bool   `yaml:"alert"`
}

// Policy holds the complete guardrails configuration deserialized from YAML.
type Policy struct {
	Guardrails struct {
		Global struct {
			MaxActionsPer10s   int  `yaml:"max_actions_per_10s"`
			MaxActionsPerMinute int  `yaml:"max_actions_per_minute"`
			DryRun             bool `yaml:"dry_run"`
		} `yaml:"global"`

		DryRunMode struct {
			Enabled           bool `yaml:"enabled"`
			LogWouldHaveActed bool `yaml:"log_would_have_acted"`
		} `yaml:"dry_run_mode"`

		PerPod struct {
			MaxRestartsPerHour          int    `yaml:"max_restarts_per_hour"`
			CooldownAfterRestart        string `yaml:"cooldown_after_restart"`
			MaxResourcePatchesPerHour   int    `yaml:"max_resource_patches_per_hour"`
			CooldownAfterResourcePatch  string `yaml:"cooldown_after_resource_patch"`
			MaxReschedulesPerHour       int    `yaml:"max_reschedules_per_hour"`
			CooldownAfterReschedule     string `yaml:"cooldown_after_reschedule"`
		} `yaml:"per_pod"`

		PerNode struct {
			MaxCordonsPerHour             int    `yaml:"max_cordons_per_hour"`
			CooldownAfterCordon           string `yaml:"cooldown_after_cordon"`
			CordonRequiresMinAffectedPods int    `yaml:"cordon_requires_min_affected_pods"`
			DrainRequiresManualApproval   bool   `yaml:"drain_requires_manual_approval"`
		} `yaml:"per_node"`

		Escalation struct {
			RestartObservationWindow   string           `yaml:"restart_observation_window"`
			RescheduleObservationWindow string          `yaml:"reschedule_observation_window"`
			MaxAutonomousAttempts       int             `yaml:"max_autonomous_attempts"`
			EscalationPath              []EscalationStep `yaml:"escalation_path"`
		} `yaml:"escalation"`

		CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`

		ProtectedNamespaces []string         `yaml:"protected_namespaces"`
		ProtectedLabels     []ProtectedLabel `yaml:"protected_labels"`

		Actions map[string]ActionConfig `yaml:"actions"`
	} `yaml:"guardrails"`
}

// ─── Loader ───────────────────────────────────────────────────────────────────

// LoadPolicy parses config/guardrails.yaml and returns a validated Policy.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading guardrails file %q: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing guardrails YAML: %w", err)
	}
	return &p, nil
}

// ─── Namespace / Pod guards ───────────────────────────────────────────────────

// IsProtectedNamespace returns true if the namespace is shielded from all
// autonomous actions (kube-system, kube-public, monitoring, etc.).
func (p *Policy) IsProtectedNamespace(ns string) bool {
	for _, protected := range p.Guardrails.ProtectedNamespaces {
		if ns == protected {
			return true
		}
	}
	return false
}

// IsProtectedPod returns true if any of the pod's labels match a protected
// label rule (e.g., selfheal.io/exclude=true, critical=true).
func (p *Policy) IsProtectedPod(labels map[string]string) bool {
	for _, pl := range p.Guardrails.ProtectedLabels {
		if v, ok := labels[pl.Key]; ok && v == pl.Value {
			return true
		}
	}
	return false
}

// ─── Action configuration helpers ────────────────────────────────────────────

// CooldownFor returns the configured cooldown duration for the given action name.
// Falls back to 60s if not found.
func (p *Policy) CooldownFor(action string) time.Duration {
	if cfg, ok := p.Guardrails.Actions[action]; ok {
		if d, err := time.ParseDuration(cfg.Cooldown); err == nil {
			return d
		}
	}
	return 60 * time.Second // safe default
}

// MaxPerHour returns the maximum number of times the given action may be
// executed per pod per hour. Returns 0 if never permitted autonomously.
func (p *Policy) MaxPerHour(action string) int {
	if cfg, ok := p.Guardrails.Actions[action]; ok {
		return cfg.MaxPerHour
	}
	return 1 // safe default
}

// RequiresConfirmation returns true if the action must not be taken autonomously.
func (p *Policy) RequiresConfirmation(action string) bool {
	if cfg, ok := p.Guardrails.Actions[action]; ok {
		return cfg.RequiresConfirmation
	}
	return true // safe default — unknown actions are blocked
}

// MaxMemoryIncreasePct returns the maximum percentage by which memory limits
// may be increased in a single patch_resource_limits action.
func (p *Policy) MaxMemoryIncreasePct() int {
	if cfg, ok := p.Guardrails.Actions["patch_resource_limits"]; ok && cfg.MaxMemoryIncreasePct > 0 {
		return cfg.MaxMemoryIncreasePct
	}
	return 100 // default: allow up to 2x
}

// CordonMinPodCount returns the minimum number of affected pods required
// before a cordon_node action is permitted.
func (p *Policy) CordonMinPodCount() int {
	return p.Guardrails.PerNode.CordonRequiresMinAffectedPods
}

// IsDryRun returns true if all actions should be simulated without modifying cluster state.
func (p *Policy) IsDryRun() bool {
	return p.Guardrails.DryRunMode.Enabled || p.Guardrails.Global.DryRun
}

// ObservationWindow returns the post-action observation window for the given action.
func (p *Policy) ObservationWindow(action string) time.Duration {
	switch action {
	case "restart_pod":
		if d, err := time.ParseDuration(p.Guardrails.Escalation.RestartObservationWindow); err == nil {
			return d
		}
		return 60 * time.Second
	case "reschedule_pod":
		if d, err := time.ParseDuration(p.Guardrails.Escalation.RescheduleObservationWindow); err == nil {
			return d
		}
		return 120 * time.Second
	default:
		return 90 * time.Second
	}
}

