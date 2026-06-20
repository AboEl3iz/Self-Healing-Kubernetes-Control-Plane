// Package ebpf — loader.go loads and manages all 5 core eBPF probes.
//
// LoadCoreProbes:
//  1. LoadCollectionSpec for each .o file
//  2. NewCollection to load into kernel
//  3. link.Tracepoint for every SEC("tracepoint/...") program
//  4. ringbuf.NewReader for ring-buffer maps (OOM, file events, TCP, slow syscalls)
//  5. Goroutines to drain each ring buffer → Mapper → Publisher
//
// PollStatsMaps (every 5s):
//   - Iterate cpu_stats_map, io_stats_map, page_fault_map, conn_stats_map, syscall_stats_map
//   - Per entry: Mapper.Resolve(cgroup_id) → build SignalEvent → Publisher.PublishSignal
//   - Emit selfheal_signals_total Prometheus counter

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PollInterval controls how often accumulated BPF map stats are read.
const PollInterval = 5 * time.Second

// ProbeConfig holds paths to compiled BPF object files.
type ProbeConfig struct {
	CPUObj     string // ebpf/probes/cpu.o
	MemoryObj  string // ebpf/probes/memory.o
	IOObj      string // ebpf/probes/io.o
	NetworkObj string // ebpf/probes/network.o
	SyscallObj string // ebpf/probes/syscall.o

	// Security probes (optional, Phase 5)
	LineageObj string
	ExecObj    string
	DNSObj     string
	PrivescObj string
	EscapeObj  string
}

// LoadedProbes holds all open BPF collections and attached links.
type LoadedProbes struct {
	collections []*ciliumebpf.Collection
	links       []link.Link
	ringbufs    []*ringbuf.Reader
	logger      *slog.Logger
}

// Loader coordinates loading and managing eBPF probes.
type Loader struct {
	cfg       ProbeConfig
	mapper    *Mapper
	publisher *Publisher
	logger    *slog.Logger

	// Prometheus metrics
	signalsTotal *prometheus.CounterVec
}

// ─── Prometheus metrics ────────────────────────────────────────────────────────

var agentSignalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "selfheal_signals_total",
	Help: "Total raw eBPF signal events emitted by the agent",
}, []string{"node", "metric", "pod"})

// ServeMetrics starts the Prometheus /metrics endpoint on addr (e.g. ":8080").
func ServeMetrics(addr string, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	logger.Info("agent: metrics serving", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("metrics server failed", "error", err)
	}
}

// ─── Constructor ──────────────────────────────────────────────────────────────

// NewLoader creates a new eBPF probe loader.
func NewLoader(cfg ProbeConfig, mapper *Mapper, logger *slog.Logger) *Loader {
	return &Loader{
		cfg:       cfg,
		mapper:    mapper,
		logger:    logger,
		signalsTotal: agentSignalsTotal,
	}
}

// SetPublisher wires the NATS publisher after it has been created.
// Must be called before PollStatsMaps.
func (l *Loader) SetPublisher(p *Publisher) { l.publisher = p }

// ─── LoadCoreProbes ───────────────────────────────────────────────────────────

// LoadCoreProbes loads and attaches all 5 core self-heal probes.
// Must be called as root (requires CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN).
func (l *Loader) LoadCoreProbes(ctx context.Context) (*LoadedProbes, error) {
	l.logger.Info("loading core eBPF probes",
		"cpu", l.cfg.CPUObj,
		"memory", l.cfg.MemoryObj,
		"io", l.cfg.IOObj,
		"network", l.cfg.NetworkObj,
		"syscall", l.cfg.SyscallObj,
	)

	// Validate all object files exist before loading into the kernel.
	for name, path := range map[string]string{
		"cpu":     l.cfg.CPUObj,
		"memory":  l.cfg.MemoryObj,
		"io":      l.cfg.IOObj,
		"network": l.cfg.NetworkObj,
		"syscall": l.cfg.SyscallObj,
	} {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("BPF object not found [%s]: %w", name, err)
		}
	}

	lp := &LoadedProbes{logger: l.logger}

	// Load each probe, collect links and ring buffer readers.
	probeSpecs := []struct {
		name string
		path string
		load func(*ciliumebpf.Collection, *LoadedProbes) error
	}{
		{"cpu", l.cfg.CPUObj, l.attachCPU},
		{"memory", l.cfg.MemoryObj, l.attachMemory},
		{"io", l.cfg.IOObj, l.attachIO},
		{"network", l.cfg.NetworkObj, l.attachNetwork},
		{"syscall", l.cfg.SyscallObj, l.attachSyscall},
	}

	for _, ps := range probeSpecs {
		spec, err := ciliumebpf.LoadCollectionSpec(ps.path)
		if err != nil {
			lp.Close()
			return nil, fmt.Errorf("LoadCollectionSpec(%s): %w", ps.name, err)
		}

		coll, err := ciliumebpf.NewCollection(spec)
		if err != nil {
			lp.Close()
			return nil, fmt.Errorf("NewCollection(%s): %w", ps.name, err)
		}
		lp.collections = append(lp.collections, coll)

		if err := ps.load(coll, lp); err != nil {
			lp.Close()
			return nil, fmt.Errorf("attach(%s): %w", ps.name, err)
		}
		l.logger.Info("  eBPF probe loaded", "probe", ps.name)
	}

	l.logger.Info("all core eBPF probes attached")
	return lp, nil
}

// ─── Per-probe attachment helpers ─────────────────────────────────────────────

func (l *Loader) attachCPU(coll *ciliumebpf.Collection, lp *LoadedProbes) error {
	progs := []struct{ group, name, prog string }{
		{"sched", "sched_switch", "trace_sched_switch"},
		{"sched", "sched_wakeup", "trace_sched_wakeup"},
		{"sched", "sched_process_fork", "trace_sched_fork"},
		{"sched", "sched_process_exit", "trace_sched_exit"},
	}
	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, coll.Programs[p.prog], nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", p.group, p.name, err)
		}
		lp.links = append(lp.links, lnk)
	}
	return nil
}

func (l *Loader) attachMemory(coll *ciliumebpf.Collection, lp *LoadedProbes) error {
	progs := []struct{ group, name, prog string }{
		{"oom", "mark_victim", "trace_oom_mark_victim"},
		{"exceptions", "page_fault_user", "trace_page_fault_user"},
	}
	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, coll.Programs[p.prog], nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", p.group, p.name, err)
		}
		lp.links = append(lp.links, lnk)
	}
	// OOM ring buffer
	rb, err := ringbuf.NewReader(coll.Maps["oom_events"])
	if err != nil {
		return fmt.Errorf("ringbuf oom_events: %w", err)
	}
	lp.ringbufs = append(lp.ringbufs, rb)
	go l.drainOOMEvents(rb)
	return nil
}

func (l *Loader) attachIO(coll *ciliumebpf.Collection, lp *LoadedProbes) error {
	progs := []struct{ group, name, prog string }{
		{"block", "block_rq_issue", "trace_block_rq_issue"},
		{"block", "block_rq_complete", "trace_block_rq_complete"},
		{"syscalls", "sys_enter_openat", "trace_sys_enter_openat"},
	}
	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, coll.Programs[p.prog], nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", p.group, p.name, err)
		}
		lp.links = append(lp.links, lnk)
	}
	// file_events ring buffer (optional — skip if map absent)
	if m, ok := coll.Maps["file_events"]; ok {
		rb, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("ringbuf file_events: %w", err)
		}
		lp.ringbufs = append(lp.ringbufs, rb)
		go l.drainFileEvents(rb)
	}
	return nil
}

func (l *Loader) attachNetwork(coll *ciliumebpf.Collection, lp *LoadedProbes) error {
	progs := []struct{ group, name, prog string }{
		{"sock", "inet_sock_set_state", "trace_inet_sock_set_state"},
		{"tcp", "tcp_retransmit_skb", "trace_tcp_retransmit"},
	}
	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, coll.Programs[p.prog], nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", p.group, p.name, err)
		}
		lp.links = append(lp.links, lnk)
	}
	rb, err := ringbuf.NewReader(coll.Maps["tcp_event_rb"])
	if err != nil {
		return fmt.Errorf("ringbuf tcp_event_rb: %w", err)
	}
	lp.ringbufs = append(lp.ringbufs, rb)
	go l.drainTCPEvents(rb)
	return nil
}

func (l *Loader) attachSyscall(coll *ciliumebpf.Collection, lp *LoadedProbes) error {
	progs := []struct{ group, name, prog string }{
		{"raw_syscalls", "sys_enter", "trace_sys_enter"},
		{"raw_syscalls", "sys_exit", "trace_sys_exit"},
	}
	for _, p := range progs {
		lnk, err := link.Tracepoint(p.group, p.name, coll.Programs[p.prog], nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", p.group, p.name, err)
		}
		lp.links = append(lp.links, lnk)
	}
	rb, err := ringbuf.NewReader(coll.Maps["slow_syscall_rb"])
	if err != nil {
		return fmt.Errorf("ringbuf slow_syscall_rb: %w", err)
	}
	lp.ringbufs = append(lp.ringbufs, rb)
	go l.drainSlowSyscallEvents(rb)
	return nil
}

// ─── Ring buffer drainers ─────────────────────────────────────────────────────

func (l *Loader) drainOOMEvents(rb *ringbuf.Reader) {
	for {
		rec, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			l.logger.Warn("oom_events read error", "error", err)
			continue
		}
		var ev OomEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			l.logger.Warn("oom_events decode", "error", err)
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(ev.CgroupID)
		sig := &SignalEvent{
			Node:       l.mapper.nodeName,
			Pod:        pod,
			Namespace:  ns,
			Deployment: dep,
			Container:  container,
			Metric:     "oom_kill",
			Value:      1,
			Unit:       "count",
			DurationMs: 0,
			CgroupID:   ev.CgroupID,
			PID:        int32(ev.VictimPID),
		}
		l.emit(sig)
	}
}

func (l *Loader) drainFileEvents(rb *ringbuf.Reader) {
	for {
		rec, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}
		var ev FileEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(ev.CgroupID)
		sig := &SignalEvent{
			Node:       l.mapper.nodeName,
			Pod:        pod,
			Namespace:  ns,
			Deployment: dep,
			Container:  container,
			Metric:     "file_open",
			Value:      1,
			Unit:       "count",
			CgroupID:   ev.CgroupID,
			PID:        int32(ev.PID),
		}
		l.emit(sig)
	}
}

func (l *Loader) drainTCPEvents(rb *ringbuf.Reader) {
	for {
		rec, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}
		var ev TcpEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		// Only publish retransmit transitions (newstate == TCP_CLOSE indicates we're tracking retransmits via conn_stats_map).
		pod, ns, dep, container := l.resolveOrUnknown(ev.CgroupID)
		sig := &SignalEvent{
			Node:       l.mapper.nodeName,
			Pod:        pod,
			Namespace:  ns,
			Deployment: dep,
			Container:  container,
			Metric:     "tcp_state_change",
			Value:      float64(ev.NewState),
			Unit:       "state",
			CgroupID:   ev.CgroupID,
		}
		l.emit(sig)
	}
}

func (l *Loader) drainSlowSyscallEvents(rb *ringbuf.Reader) {
	for {
		rec, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}
		var ev SlowSyscallEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(ev.CgroupID)
		sig := &SignalEvent{
			Node:       l.mapper.nodeName,
			Pod:        pod,
			Namespace:  ns,
			Deployment: dep,
			Container:  container,
			Metric:     "slow_syscall",
			Value:      float64(ev.LatencyNs) / 1e6, // convert ns → ms
			Unit:       "milliseconds",
			CgroupID:   ev.CgroupID,
			PID:        int32(ev.PID),
		}
		l.emit(sig)
	}
}

// ─── PollStatsMaps ────────────────────────────────────────────────────────────

// PollStatsMaps periodically reads accumulated statistics from BPF hash maps
// and converts them into SignalEvents. Blocks until ctx is cancelled.
func (l *Loader) PollStatsMaps(ctx context.Context, loaded *LoadedProbes) error {
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	// Build index: collection name → collection (by order of attachment)
	// cpu=0, memory=1, io=2, network=3, syscall=4
	colls := loaded.collections
	if len(colls) < 5 {
		l.logger.Warn("PollStatsMaps: fewer collections than expected", "count", len(colls))
		<-ctx.Done()
		return ctx.Err()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			l.pollCPU(colls[0])
			l.pollMemory(colls[1])
			l.pollIO(colls[2])
			l.pollNetwork(colls[3])
			l.pollSyscall(colls[4])
		}
	}
}

func (l *Loader) pollCPU(coll *ciliumebpf.Collection) {
	m, ok := coll.Maps["cpu_stats_map"]
	if !ok {
		return
	}
	var key CpuKey
	var val CpuStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.TotalNs == 0 && val.CtxSwitches == 0 {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(key.CgroupID)

		// CPU on-time as a percentage proxy (total_ns / poll_interval)
		cpuPct := float64(val.TotalNs) / float64(PollInterval.Nanoseconds()) * 100

		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "cpu_usage_pct", Value: cpuPct, Unit: "percent",
			DurationMs: PollInterval.Milliseconds(), CgroupID: key.CgroupID,
		})
		if val.RunqLatencyNs > 0 {
			avgRunqMs := float64(val.RunqLatencyNs) / float64(val.CtxSwitches+1) / 1e6
			l.emit(&SignalEvent{
				Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
				Metric: "cpu_runq_latency_ms", Value: avgRunqMs, Unit: "milliseconds",
				DurationMs: PollInterval.Milliseconds(), CgroupID: key.CgroupID,
			})
		}
		if val.ThreadCount > 0 {
			l.emit(&SignalEvent{
				Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
				Metric: "thread_count", Value: float64(val.ThreadCount), Unit: "count",
				DurationMs: PollInterval.Milliseconds(), CgroupID: key.CgroupID,
			})
		}
	}
	if err := iter.Err(); err != nil {
		l.logger.Warn("pollCPU iterate error", "error", err)
	}
}

func (l *Loader) pollMemory(coll *ciliumebpf.Collection) {
	m, ok := coll.Maps["page_fault_map"]
	if !ok {
		return
	}
	var key uint64
	var val PfStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.MinorFaults == 0 && val.MajorFaults == 0 {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(key)
		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "page_faults_minor", Value: float64(val.MinorFaults), Unit: "count",
			DurationMs: PollInterval.Milliseconds(), CgroupID: key,
		})
		if val.MajorFaults > 0 {
			l.emit(&SignalEvent{
				Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
				Metric: "page_faults_major", Value: float64(val.MajorFaults), Unit: "count",
				DurationMs: PollInterval.Milliseconds(), CgroupID: key,
			})
		}
	}
}

func (l *Loader) pollIO(coll *ciliumebpf.Collection) {
	m, ok := coll.Maps["io_stats_map"]
	if !ok {
		return
	}
	var key uint64
	var val IoStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.ReadIOs == 0 && val.WriteIOs == 0 {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(key)

		// Average I/O latency
		var avgReadMs, avgWriteMs float64
		if val.ReadIOs > 0 {
			avgReadMs = float64(val.ReadLatencyNs) / float64(val.ReadIOs) / 1e6
		}
		if val.WriteIOs > 0 {
			avgWriteMs = float64(val.WriteLatencyNs) / float64(val.WriteIOs) / 1e6
		}
		// io_wait as average of read + write latency (simplified proxy)
		ioWait := (avgReadMs + avgWriteMs) / 2

		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "io_wait_ms", Value: ioWait, Unit: "milliseconds",
			DurationMs: PollInterval.Milliseconds(), CgroupID: key,
		})
		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "io_read_bytes", Value: float64(val.ReadBytes), Unit: "bytes",
			DurationMs: PollInterval.Milliseconds(), CgroupID: key,
		})
		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "io_write_bytes", Value: float64(val.WriteBytes), Unit: "bytes",
			DurationMs: PollInterval.Milliseconds(), CgroupID: key,
		})
	}
}

func (l *Loader) pollNetwork(coll *ciliumebpf.Collection) {
	m, ok := coll.Maps["conn_stats_map"]
	if !ok {
		return
	}
	// Aggregate retransmits per cgroup_id across all flows.
	type aggKey struct{ cgroupID uint64 }
	type aggVal struct{ retransmits, totalFlows uint64 }
	agg := make(map[uint64]aggVal)

	var key ConnKey
	var val ConnStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		a := agg[key.CgroupID]
		a.retransmits += uint64(val.Retransmits)
		a.totalFlows++
		agg[key.CgroupID] = a
	}

	for cgroupID, a := range agg {
		if a.totalFlows == 0 {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(cgroupID)
		retransmitRate := float64(a.retransmits) / float64(a.totalFlows) * 100
		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "tcp_retransmit_rate", Value: retransmitRate, Unit: "percent",
			DurationMs: PollInterval.Milliseconds(), CgroupID: cgroupID,
		})
	}
}

func (l *Loader) pollSyscall(coll *ciliumebpf.Collection) {
	m, ok := coll.Maps["syscall_stats_map"]
	if !ok {
		return
	}
	// Aggregate across all syscall IDs per cgroup.
	type agg struct{ count, failures, latencyNs uint64 }
	cgroupAgg := make(map[uint64]agg)

	var key SyscallKey
	var val SyscallStats
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		a := cgroupAgg[key.CgroupID]
		a.count += val.Count
		a.failures += val.Failures
		a.latencyNs += val.TotalLatencyNs
		cgroupAgg[key.CgroupID] = a
	}

	for cgroupID, a := range cgroupAgg {
		if a.count == 0 {
			continue
		}
		pod, ns, dep, container := l.resolveOrUnknown(cgroupID)
		avgLatMs := float64(a.latencyNs) / float64(a.count) / 1e6
		failRate := float64(a.failures) / float64(a.count) * 100
		l.emit(&SignalEvent{
			Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
			Metric: "syscall_avg_latency_ms", Value: avgLatMs, Unit: "milliseconds",
			DurationMs: PollInterval.Milliseconds(), CgroupID: cgroupID,
		})
		if failRate > 0 {
			l.emit(&SignalEvent{
				Node: l.mapper.nodeName, Pod: pod, Namespace: ns, Deployment: dep, Container: container,
				Metric: "syscall_failure_rate", Value: failRate, Unit: "percent",
				DurationMs: PollInterval.Milliseconds(), CgroupID: cgroupID,
			})
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// resolveOrUnknown attempts mapper resolution and returns "<unknown>" on failure.
func (l *Loader) resolveOrUnknown(cgroupID uint64) (pod, ns, dep, container string) {
	info, err := l.mapper.Resolve(cgroupID)
	if err != nil {
		return "<unknown>", "<unknown>", "", ""
	}
	return info.PodName, info.Namespace, info.Deployment, info.Container
}

// emit publishes a signal event and bumps the Prometheus counter.
func (l *Loader) emit(sig *SignalEvent) {
	l.signalsTotal.WithLabelValues(sig.Node, sig.Metric, sig.Pod).Inc()
	if l.publisher == nil {
		l.logger.Debug("signal (no publisher)", "metric", sig.Metric, "pod", sig.Pod, "value", sig.Value)
		return
	}
	if err := l.publisher.PublishSignal(context.Background(), sig); err != nil {
		l.logger.Warn("publish signal failed", "metric", sig.Metric, "error", err)
	} else {
		l.logger.Debug("signal published", "metric", sig.Metric, "pod", sig.Pod, "value", sig.Value)
	}
}

// ─── Close ────────────────────────────────────────────────────────────────────

// Close detaches all probes and releases kernel resources.
func (p *LoadedProbes) Close() {
	for _, rb := range p.ringbufs {
		rb.Close()
	}
	for _, lnk := range p.links {
		lnk.Close()
	}
	for _, c := range p.collections {
		c.Close()
	}
	if p.logger != nil {
		p.logger.Info("eBPF probes detached and closed")
	}
}

