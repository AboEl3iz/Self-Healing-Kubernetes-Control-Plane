// Package tests — controller_test.go covers Phase 3 guardrails, escalation,
// and circuit breaker behaviour.
//
// Tests are purely in-memory (no Kubernetes cluster required).
// All test cases verify the safety constraints are enforced correctly.

package unit

import (
	"testing"
	"time"

	"github.com/karim-aboelaiz/selfheal-cp/internal/controller"
	"github.com/karim-aboelaiz/selfheal-cp/internal/controller/guardrails"

	"log/slog"
	"os"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

// ─── Global Rate Limiter ──────────────────────────────────────────────────────

func TestGlobalRateLimiter_AllowsFirstAction(t *testing.T) {
	rl := guardrails.NewGlobalRateLimiter(10 * time.Second)
	if !rl.Allow() {
		t.Fatal("expected first action to be allowed")
	}
}

func TestGlobalRateLimiter_BlocksSecondActionWithinWindow(t *testing.T) {
	rl := guardrails.NewGlobalRateLimiter(10 * time.Second)
	rl.Allow() // consume token
	if rl.Allow() {
		t.Fatal("expected second action within 10s to be blocked")
	}
}

func TestGlobalRateLimiter_AllowsAfterInterval(t *testing.T) {
	rl := guardrails.NewGlobalRateLimiter(50 * time.Millisecond)
	rl.Allow() // consume
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow() {
		t.Fatal("expected action to be allowed after interval elapsed")
	}
}

func TestGlobalRateLimiter_TimeUntilNext(t *testing.T) {
	rl := guardrails.NewGlobalRateLimiter(10 * time.Second)
	rl.Allow()
	wait := rl.TimeUntilNext()
	if wait == 0 {
		t.Fatal("expected non-zero wait time after consuming token")
	}
	if wait > 10*time.Second {
		t.Fatalf("wait time %s exceeds interval 10s", wait)
	}
}

// ─── Cooldown Store ───────────────────────────────────────────────────────────

func makeTestPolicy() *guardrails.Policy {
	// Minimal inline policy for tests — avoids needing to read a file.
	p := &guardrails.Policy{}
	p.Guardrails.Actions = map[string]guardrails.ActionConfig{
		"restart_pod": {
			Cooldown:   "100ms",
			MaxPerHour: 3,
		},
		"reschedule_pod": {
			Cooldown:   "200ms",
			MaxPerHour: 2,
		},
	}
	return p
}

func TestCooldownStore_AllowsFirstAction(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	if !store.Allow("pod-a", "default", "restart_pod") {
		t.Fatal("expected first action to be allowed")
	}
}

func TestCooldownStore_BlocksDuringCooldown(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	store.Allow("pod-a", "default", "restart_pod") // first: allowed
	if store.Allow("pod-a", "default", "restart_pod") {
		t.Fatal("expected second restart within cooldown to be blocked")
	}
}

func TestCooldownStore_AllowsAfterCooldown(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	store.Allow("pod-a", "default", "restart_pod")
	time.Sleep(150 * time.Millisecond) // cooldown is 100ms
	if !store.Allow("pod-a", "default", "restart_pod") {
		t.Fatal("expected action to be allowed after cooldown elapsed")
	}
}

func TestCooldownStore_EnforcesHourlyCap(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	// reschedule_pod: cooldown=200ms, max=2/hour
	for i := 0; i < 2; i++ {
		time.Sleep(210 * time.Millisecond) // wait for cooldown each time
		if !store.Allow("pod-a", "default", "reschedule_pod") {
			t.Fatalf("expected action %d to be allowed", i+1)
		}
	}
	time.Sleep(210 * time.Millisecond)
	// 3rd attempt within same hour — should be blocked by hourly cap
	if store.Allow("pod-a", "default", "reschedule_pod") {
		t.Fatal("expected hourly cap to block 3rd reschedule")
	}
}

func TestCooldownStore_DifferentPodsIndependent(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	store.Allow("pod-a", "default", "restart_pod")
	// pod-b should not be affected by pod-a's cooldown
	if !store.Allow("pod-b", "default", "restart_pod") {
		t.Fatal("expected different pod to not be affected by other pod's cooldown")
	}
}

func TestCooldownStore_Reset(t *testing.T) {
	store := guardrails.NewCooldownStore(makeTestPolicy())
	store.Allow("pod-a", "default", "restart_pod")
	store.Reset("pod-a", "default")
	if !store.Allow("pod-a", "default", "restart_pod") {
		t.Fatal("expected action to be allowed after Reset()")
	}
}

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

func makeTestCircuitBreaker(failurePct int) *guardrails.CircuitBreaker {
	p := &guardrails.Policy{}
	p.Guardrails.CircuitBreaker = guardrails.CircuitBreakerConfig{
		Enabled:             true,
		TriggerOnFailurePct: failurePct,
		EvaluationWindow:    "5m",
		PauseDuration:       "100ms", // very short for tests
	}
	return guardrails.NewCircuitBreaker(p, testLogger)
}

func TestCircuitBreaker_OpenOnHighFailureRate(t *testing.T) {
	cb := makeTestCircuitBreaker(50)
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure() // 2/3 = 66% failures > 50% threshold → should trip
	if !cb.IsOpen() {
		t.Fatal("expected circuit breaker to be open after >50% failure rate")
	}
	if cb.Allow() {
		t.Fatal("expected Allow() to return false when breaker is open")
	}
}

func TestCircuitBreaker_ClosesAfterPauseDuration(t *testing.T) {
	cb := makeTestCircuitBreaker(50)
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.IsOpen() {
		t.Skip("circuit breaker did not trip — skipping close test")
	}
	time.Sleep(150 * time.Millisecond) // pause_duration is 100ms
	if !cb.Allow() {
		t.Fatal("expected circuit breaker to auto-close after pause duration")
	}
}

func TestCircuitBreaker_StaysClosedBelowThreshold(t *testing.T) {
	cb := makeTestCircuitBreaker(50)
	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure() // 1/3 = 33% < 50%
	if cb.IsOpen() {
		t.Fatal("expected circuit breaker to remain closed below threshold")
	}
}

// ─── Escalation State Machine ─────────────────────────────────────────────────

func TestEscalation_FirstAnomalyTriggersRestart(t *testing.T) {
	em := controller.NewEscalationManager(testLogger)
	action, attempt, err := em.NextAction("pod-a", "default", "high_io_wait")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != controller.ActionRestartPod {
		t.Fatalf("expected restart_pod, got %s", action)
	}
	if attempt != 1 {
		t.Fatalf("expected attempt=1, got %d", attempt)
	}
}

func TestEscalation_ThreeRestartsLeadToReschedule(t *testing.T) {
	em := controller.NewEscalationManager(testLogger)
	// Exhaust 3 restart attempts
	for i := 1; i <= 3; i++ {
		action, attempt, err := em.NextAction("pod-a", "default", "memory_pressure")
		if err != nil {
			t.Fatalf("attempt %d: unexpected error: %v", i, err)
		}
		if action != controller.ActionRestartPod {
			t.Fatalf("attempt %d: expected restart_pod, got %s", i, action)
		}
		if attempt != i {
			t.Fatalf("attempt %d: expected attempt=%d, got %d", i, i, attempt)
		}
	}
	// 4th call should escalate to reschedule
	action, attempt, err := em.NextAction("pod-a", "default", "memory_pressure")
	if err != nil {
		t.Fatalf("escalation error: %v", err)
	}
	if action != controller.ActionReschedulePod {
		t.Fatalf("expected reschedule_pod after 3 restarts, got %s", action)
	}
	if attempt != 1 {
		t.Fatalf("expected attempt=1 for new action, got %d", attempt)
	}
}

func TestEscalation_ReachesManualAfterFullEscalation(t *testing.T) {
	em := controller.NewEscalationManager(testLogger)
	// 3× restart
	for i := 0; i < 3; i++ {
		em.NextAction("pod-x", "prod", "syscall_spike")
	}
	// 2× reschedule
	for i := 0; i < 2; i++ {
		em.NextAction("pod-x", "prod", "syscall_spike")
	}
	// 1× cordon (advances to NODE_SUSPECT)
	em.NextAction("pod-x", "prod", "syscall_spike")
	// 1× more call from NODE_SUSPECT → advances to MANUAL
	em.NextAction("pod-x", "prod", "syscall_spike")

	// Now should be MANUAL
	if !em.IsManual("pod-x", "prod", "syscall_spike") {
		state := em.CurrentState("pod-x", "prod", "syscall_spike")
		t.Fatalf("expected MANUAL state after full escalation path, got %s", state)
	}
}

func TestEscalation_MarkResolvedResetsState(t *testing.T) {
	em := controller.NewEscalationManager(testLogger)
	em.NextAction("pod-b", "default", "high_io_wait")
	em.MarkResolved("pod-b", "default", "high_io_wait")
	state := em.CurrentState("pod-b", "default", "high_io_wait")
	if state != controller.StateResolved {
		t.Fatalf("expected RESOLVED state, got %s", state)
	}
	// Next anomaly should start fresh with restart
	action, attempt, err := em.NextAction("pod-b", "default", "high_io_wait")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != controller.ActionRestartPod || attempt != 1 {
		t.Fatalf("expected fresh restart_pod/1 after resolve, got %s/%d", action, attempt)
	}
}

func TestEscalation_DifferentPodsIndependent(t *testing.T) {
	em := controller.NewEscalationManager(testLogger)
	// Exhaust pod-a restarts
	for i := 0; i < 3; i++ {
		em.NextAction("pod-a", "ns1", "memory_pressure")
	}
	// pod-b should still start at restart
	action, attempt, _ := em.NextAction("pod-b", "ns1", "memory_pressure")
	if action != controller.ActionRestartPod || attempt != 1 {
		t.Fatalf("pod-b should be independent, got %s/%d", action, attempt)
	}
}
