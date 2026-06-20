// Package guardrails — GlobalRateLimiter enforces the 1-action/10s global limit.
//
// This is the primary safety mechanism. At most 1 healing action may be
// dispatched across the ENTIRE cluster within any 10-second window.
//
// Implementation uses a token bucket with mutex-protected state.
// The rate limiter must be a singleton shared across all reconciler goroutines.

package guardrails

import (
	"sync"
	"time"
)

// GlobalRateLimiter enforces the cluster-wide action rate limit.
// Thread-safe via internal mutex.
type GlobalRateLimiter struct {
	mu          sync.Mutex
	lastAction  time.Time
	minInterval time.Duration
}

// NewGlobalRateLimiter creates a limiter with the given minimum interval.
// Default from ERP: 10 seconds (1 action per cluster per 10s).
func NewGlobalRateLimiter(minInterval time.Duration) *GlobalRateLimiter {
	return &GlobalRateLimiter{
		minInterval: minInterval,
	}
}

// Allow returns true if an action is permitted at this moment.
// If true, it also records the action time (consuming the token).
// If false, the caller must wait and retry.
func (r *GlobalRateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastAction) < r.minInterval {
		return false
	}
	r.lastAction = time.Now()
	return true
}

// TimeUntilNext returns the duration until the next action is permitted.
// Returns 0 if an action can be taken immediately.
func (r *GlobalRateLimiter) TimeUntilNext() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := time.Since(r.lastAction)
	if elapsed >= r.minInterval {
		return 0
	}
	return r.minInterval - elapsed
}
