// Package guardrails — cooldown.go enforces per-pod, per-action cooldowns
// and hourly action caps for the SelfHeal-CP controller.
//
// Keyed on (pod, namespace, action) triples.
// All state is in-memory. A controller restart resets all cooldown state —
// this is acceptable because the escalation state machine (escalation.go)
// tracks attempt counts durably within its own sync.Map.
//
// Cooldown rules (from guardrails.yaml):
//   restart_pod:        cooldown=60s,  max=3/hour
//   patch_limits:       cooldown=300s, max=2/hour
//   reschedule_pod:     cooldown=120s, max=2/hour
//   cordon_node:        cooldown=600s, max=1/hour

package guardrails

import (
	"fmt"
	"sync"
	"time"
)

// cooldownKey uniquely identifies a (pod, namespace, action) combination.
type cooldownKey struct {
	pod       string
	namespace string
	action    string
}

// cooldownEntry tracks timing state for one (pod, namespace, action).
type cooldownEntry struct {
	lastAction time.Time
	// history stores timestamps of actions taken within the rolling hour window.
	history []time.Time
}

// CooldownStore enforces per-pod, per-action timing constraints.
// Thread-safe via internal mutex.
type CooldownStore struct {
	mu      sync.Mutex
	entries map[cooldownKey]*cooldownEntry
	policy  *Policy
}

// NewCooldownStore creates a CooldownStore backed by the loaded policy.
func NewCooldownStore(policy *Policy) *CooldownStore {
	return &CooldownStore{
		entries: make(map[cooldownKey]*cooldownEntry),
		policy:  policy,
	}
}

// Allow returns true if the given action is permitted on (pod, namespace)
// right now, considering both the per-action cooldown interval and the
// hourly cap. If allowed, it records the action.
func (c *CooldownStore) Allow(pod, namespace, action string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cooldownKey{pod: pod, namespace: namespace, action: action}
	entry, ok := c.entries[key]
	if !ok {
		entry = &cooldownEntry{}
		c.entries[key] = entry
	}

	// Prune history older than 1 hour.
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	pruned := entry.history[:0]
	for _, t := range entry.history {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	entry.history = pruned

	// Check per-action cooldown interval.
	cooldown := c.policy.CooldownFor(action)
	if !entry.lastAction.IsZero() && now.Sub(entry.lastAction) < cooldown {
		return false
	}

	// Check hourly cap.
	maxPerHour := c.policy.MaxPerHour(action)
	if maxPerHour > 0 && len(entry.history) >= maxPerHour {
		return false
	}

	// Record the action.
	entry.lastAction = now
	entry.history = append(entry.history, now)
	return true
}

// TimeUntilNext returns a human-readable reason why an action is blocked,
// along with the duration to wait. Returns ("", 0) if action is allowed.
func (c *CooldownStore) TimeUntilNext(pod, namespace, action string) (string, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cooldownKey{pod: pod, namespace: namespace, action: action}
	entry, ok := c.entries[key]
	if !ok {
		return "", 0
	}

	now := time.Now()
	cutoff := now.Add(-time.Hour)

	// Check cooldown interval.
	cooldown := c.policy.CooldownFor(action)
	if !entry.lastAction.IsZero() {
		remaining := cooldown - now.Sub(entry.lastAction)
		if remaining > 0 {
			return fmt.Sprintf("cooldown active for %s on pod %s/%s", action, namespace, pod), remaining
		}
	}

	// Check hourly cap.
	count := 0
	for _, t := range entry.history {
		if t.After(cutoff) {
			count++
		}
	}
	maxPerHour := c.policy.MaxPerHour(action)
	if maxPerHour > 0 && count >= maxPerHour {
		return fmt.Sprintf("hourly cap reached (%d/%d) for %s on pod %s/%s", count, maxPerHour, action, namespace, pod), time.Hour
	}

	return "", 0
}

// Reset clears cooldown state for a pod (called when pod is confirmed resolved).
func (c *CooldownStore) Reset(pod, namespace string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if key.pod == pod && key.namespace == namespace {
			delete(c.entries, key)
		}
	}
}
