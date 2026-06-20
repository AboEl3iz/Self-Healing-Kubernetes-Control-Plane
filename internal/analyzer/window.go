// Package analyzer — window.go implements a per-(pod,metric) sliding window.
//
// Each window holds a fixed-capacity ring buffer of timestamped samples.
// On every Record() call, samples older than the window duration are evicted.
//
// Provided aggregations (over all samples in the window):
//   - Average()   — arithmetic mean
//   - Max()       — maximum value
//   - Count()     — number of samples
//   - Sum()       — cumulative total
//   - Percentile(p) — approximate percentile using sorted copy (p ∈ [0,100])
//
// WindowStore is goroutine-safe via per-window RWMutex.

package analyzer

import (
	"sort"
	"sync"
	"time"
)

const defaultWindowCapacity = 1024 // ring buffer max samples per (pod,metric)

// WindowKey uniquely identifies a sliding window.
type WindowKey struct {
	Pod    string
	Metric string
}

// Sample is a single timestamped observation.
type Sample struct {
	Value float64
	Time  time.Time
}

// Window holds a bounded ring buffer of samples for one (pod, metric) pair.
type Window struct {
	mu       sync.RWMutex
	duration time.Duration
	samples  []Sample // append-only ring; oldest evicted on Record
}

// newWindow creates a Window with the given observation duration.
func newWindow(duration time.Duration) *Window {
	return &Window{duration: duration}
}

// Record adds a new observation and evicts samples older than the window.
func (w *Window) Record(value float64, t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.samples = append(w.samples, Sample{Value: value, Time: t})

	// Evict expired samples from the front.
	cutoff := t.Add(-w.duration)
	idx := 0
	for idx < len(w.samples) && w.samples[idx].Time.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		w.samples = w.samples[idx:]
	}

	// Enforce capacity ceiling to prevent unbounded growth.
	if len(w.samples) > defaultWindowCapacity {
		w.samples = w.samples[len(w.samples)-defaultWindowCapacity:]
	}
}

// Samples returns a snapshot of all current in-window samples.
func (w *Window) Samples() []Sample {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Sample, len(w.samples))
	copy(out, w.samples)
	return out
}

// Count returns the number of samples currently in the window.
func (w *Window) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.samples)
}

// Sum returns the cumulative sum of all samples in the window.
func (w *Window) Sum() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var sum float64
	for _, s := range w.samples {
		sum += s.Value
	}
	return sum
}

// Average returns the arithmetic mean; 0 if no samples.
func (w *Window) Average() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range w.samples {
		sum += s.Value
	}
	return sum / float64(len(w.samples))
}

// Max returns the maximum value in the window; 0 if no samples.
func (w *Window) Max() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.samples) == 0 {
		return 0
	}
	max := w.samples[0].Value
	for _, s := range w.samples[1:] {
		if s.Value > max {
			max = s.Value
		}
	}
	return max
}

// Latest returns the most recent sample value and whether it exists.
func (w *Window) Latest() (float64, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.samples) == 0 {
		return 0, false
	}
	return w.samples[len(w.samples)-1].Value, true
}

// Percentile computes the p-th percentile (0–100) using a sorted copy.
// Returns 0 if the window is empty.
func (w *Window) Percentile(p float64) float64 {
	w.mu.RLock()
	vals := make([]float64, len(w.samples))
	for i, s := range w.samples {
		vals[i] = s.Value
	}
	w.mu.RUnlock()

	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	idx := int(float64(len(vals)-1) * p / 100.0)
	return vals[idx]
}

// ─── WindowStore ──────────────────────────────────────────────────────────────

// WindowStore manages all active sliding windows (goroutine-safe).
type WindowStore struct {
	mu      sync.RWMutex
	windows map[WindowKey]*Window
}

// NewWindowStore creates an empty WindowStore.
func NewWindowStore() *WindowStore {
	return &WindowStore{windows: make(map[WindowKey]*Window)}
}

// Record adds an observation to the (pod, metric) window, creating it if absent.
func (s *WindowStore) Record(pod, metric string, value float64, t time.Time, duration time.Duration) {
	key := WindowKey{Pod: pod, Metric: metric}

	s.mu.RLock()
	w, ok := s.windows[key]
	s.mu.RUnlock()

	if !ok {
		s.mu.Lock()
		// Double-checked locking.
		if w, ok = s.windows[key]; !ok {
			w = newWindow(duration)
			s.windows[key] = w
		}
		s.mu.Unlock()
	}
	w.Record(value, t)
}

// Get returns the Window for (pod, metric), or nil if none.
func (s *WindowStore) Get(pod, metric string) *Window {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.windows[WindowKey{Pod: pod, Metric: metric}]
}

// Average returns the rolling average for (pod, metric) over the window.
func (s *WindowStore) Average(pod, metric string, _ time.Duration) float64 {
	if w := s.Get(pod, metric); w != nil {
		return w.Average()
	}
	return 0
}

// Latest returns the most recent value for (pod, metric).
func (s *WindowStore) Latest(pod, metric string) (float64, bool) {
	if w := s.Get(pod, metric); w != nil {
		return w.Latest()
	}
	return 0, false
}

// ActiveMetrics returns all metric names that have samples for the given pod.
func (s *WindowStore) ActiveMetrics(pod string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var metrics []string
	for k, w := range s.windows {
		if k.Pod == pod && w.Count() > 0 {
			metrics = append(metrics, k.Metric)
		}
	}
	return metrics
}

// Evict removes all windows for a pod (called when pod is deleted).
func (s *WindowStore) Evict(pod string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.windows {
		if k.Pod == pod {
			delete(s.windows, k)
		}
	}
}
