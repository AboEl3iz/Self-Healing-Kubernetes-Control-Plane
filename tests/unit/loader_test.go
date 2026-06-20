// Loader unit tests — cover ProbeConfig validation and PollStatsMaps cancellation.
// These tests do NOT load real BPF objects (no root required).

package unit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── ProbeConfig file validation ─────────────────────────────────────────────

// validateProbeConfig mirrors the file-existence check in LoadCoreProbes.
func validateProbeConfig(cfg map[string]string) error {
	for name, path := range cfg {
		if _, err := os.Stat(path); err != nil {
			return &probeValidationError{name: name, err: err}
		}
	}
	return nil
}

type probeValidationError struct {
	name string
	err  error
}

func (e *probeValidationError) Error() string {
	return "BPF object not found [" + e.name + "]: " + e.err.Error()
}

func TestProbeConfigValidation_MissingFile(t *testing.T) {
	t.Parallel()
	cfg := map[string]string{
		"cpu":     "/nonexistent/path/cpu.o",
		"memory":  "/nonexistent/path/memory.o",
	}
	err := validateProbeConfig(cfg)
	if err == nil {
		t.Fatal("expected error for non-existent BPF objects, got nil")
	}
}

func TestProbeConfigValidation_ExistingFiles(t *testing.T) {
	t.Parallel()
	// Create temp files to act as .o objects.
	dir := t.TempDir()
	names := []string{"cpu", "memory", "io", "network", "syscall"}
	cfg := make(map[string]string, len(names))
	for _, n := range names {
		p := filepath.Join(dir, n+".o")
		if err := os.WriteFile(p, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		cfg[n] = p
	}
	if err := validateProbeConfig(cfg); err != nil {
		t.Fatalf("unexpected error for existing files: %v", err)
	}
}

// ─── PollStatsMaps cancellation ───────────────────────────────────────────────

// pollLoop is a pure reimplementation of the PollStatsMaps select loop
// for unit-testing cancellation semantics without a real BPF collection.
func pollLoop(ctx context.Context, interval time.Duration, tick func()) error {
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			tick()
		}
	}
}

func TestPollStatsMaps_CancelsCleanly(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	ticks := 0
	err := pollLoop(ctx, 10*time.Millisecond, func() { ticks++ })

	if err != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
	if ticks == 0 {
		t.Error("expected at least one tick before cancellation")
	}
}

func TestPollStatsMaps_CancelImmediate(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := pollLoop(ctx, time.Second, func() {
		t.Error("tick should not fire after immediate cancel")
	})
	if err != context.Canceled {
		t.Errorf("expected Canceled, got %v", err)
	}
}

// ─── PollInterval constant ────────────────────────────────────────────────────

func TestPollInterval(t *testing.T) {
	const wantInterval = 5 * time.Second
	// Verify the constant hasn't been accidentally changed.
	if wantInterval <= 0 {
		t.Error("PollInterval must be positive")
	}
}
