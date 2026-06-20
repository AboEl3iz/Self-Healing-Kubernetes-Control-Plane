// Package analyzer — cooldown.go implements the per-pod cooldown state machine.
//
// For each (pod, anomaly_type) pair, the state machine tracks:
//   - When the last action was taken
//   - How many actions have been taken in the current hour
//   - The cooldown window that must elapse before another action
//
// Default cooldown windows (from guardrails.yaml):
//   restart_pod           → 60s,  max 3/hour
//   patch_resource_limits → 300s, max 2/hour
//   reschedule_pod        → 120s, max 2/hour
//   cordon_node           → 600s, max 1/hour

package analyzer

import (
	"sync"
	"time"
)

// CooldownPolicy defines the rate limits for a given action type.
type CooldownPolicy struct {
	Duration   time.Duration // minimum time between actions
	MaxPerHour int           // maximum actions per rolling hour
}

// DefaultCooldowns maps action name → cooldown policy.
var DefaultCooldowns = map[string]CooldownPolicy{
	"restart_pod":           {Duration: 60 * time.Second, MaxPerHour: 3},
	"patch_resource_limits": {Duration: 300 * time.Second, MaxPerHour: 2},
	"reschedule_pod":        {Duration: 120 * time.Second, MaxPerHour: 2},
	"cordon_node":           {Duration: 600 * time.Second, MaxPerHour: 1},
}

// cooldownEntry tracks state for one (pod, actionType) pair.
type cooldownEntry struct {
	lastAction  time.Time
	recentTimes []time.Time // timestamps of actions within the last hour
}

// CooldownStore manages cooldown state for all pod/action pairs.
type CooldownStore struct {
	mu      sync.Mutex
	entries map[cooldownKey]*cooldownEntry
}

type cooldownKey struct {
	Pod        string
	ActionType string
}

// NewCooldownStore creates an empty CooldownStore.
func NewCooldownStore() *CooldownStore {
	return &CooldownStore{entries: make(map[cooldownKey]*cooldownEntry)}
}

// Allow returns true if an action is permitted given the cooldown policy.
// It does NOT record the action — call Record() if you proceed.
func (c *CooldownStore) Allow(pod, actionType string, policy CooldownPolicy, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cooldownKey{Pod: pod, ActionType: actionType}
	entry, ok := c.entries[key]
	if !ok {
		return true // first time — always allow
	}

	// Check minimum cooldown duration.
	if now.Sub(entry.lastAction) < policy.Duration {
		return false
	}

	// Check hourly rate limit.
	hourAgo := now.Add(-time.Hour)
	recent := 0
	for _, t := range entry.recentTimes {
		if t.After(hourAgo) {
			recent++
		}
	}
	return recent < policy.MaxPerHour
}

// Record marks an action as taken. Call after Allow() returns true.
func (c *CooldownStore) Record(pod, actionType string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cooldownKey{Pod: pod, ActionType: actionType}
	entry, ok := c.entries[key]
	if !ok {
		entry = &cooldownEntry{}
		c.entries[key] = entry
	}
	entry.lastAction = now

	// Append and prune entries older than 1 hour.
	entry.recentTimes = append(entry.recentTimes, now)
	hourAgo := now.Add(-time.Hour)
	pruned := entry.recentTimes[:0]
	for _, t := range entry.recentTimes {
		if t.After(hourAgo) {
			pruned = append(pruned, t)
		}
	}
	entry.recentTimes = pruned
}

// RemainingCooldown returns how long until the next action is allowed.
// Returns 0 if action is currently allowed.
func (c *CooldownStore) RemainingCooldown(pod, actionType string, policy CooldownPolicy, now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cooldownKey{Pod: pod, ActionType: actionType}
	entry, ok := c.entries[key]
	if !ok {
		return 0
	}
	remaining := policy.Duration - now.Sub(entry.lastAction)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Evict removes all cooldown state for a pod (called on pod delete).
func (c *CooldownStore) Evict(pod string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.Pod == pod {
			delete(c.entries, k)
		}
	}
}
