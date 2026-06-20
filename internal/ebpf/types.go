// Package ebpf — types.go mirrors the C structs defined in each eBPF probe.
//
// cilium/ebpf requires the Go types to exactly match the C struct layout
// (field order, sizes, alignment/padding) so that it can safely copy bytes
// from kernel maps into Go values.
//
// Mapping:
//   ebpf/probes/cpu.c      → CpuKey, CpuStats
//   ebpf/probes/memory.c   → OomEvent, PfStats
//   ebpf/probes/io.c       → IoStats, FileEvent
//   ebpf/probes/network.c  → ConnKey, ConnStats, TcpEvent
//   ebpf/probes/syscall.c  → SyscallKey, SyscallStats, SlowSyscallEvent

package ebpf

// ─── cpu.c ────────────────────────────────────────────────────────────────────

// CpuKey is the map key for cpu_stats_map (struct cpu_key in C).
type CpuKey struct {
	CgroupID uint64
}

// CpuStats mirrors struct cpu_stats from cpu.c.
type CpuStats struct {
	TotalNs       uint64 // total on-CPU nanoseconds
	RunqLatencyNs uint64 // cumulative runqueue wait nanoseconds
	CtxSwitches   uint64 // voluntary + involuntary context switches
	ThreadCount   uint32 // live thread gauge
	Pad           uint32 // explicit padding to match C struct
}

// ─── memory.c ─────────────────────────────────────────────────────────────────

// OomEvent mirrors struct oom_event from memory.c (ring buffer).
type OomEvent struct {
	CgroupID    uint64
	VictimPID   uint32
	OomScoreAdj uint32
	Pages       uint64
	Comm        [16]byte
}

// PfStats mirrors struct pf_stats from memory.c (page_fault_map).
type PfStats struct {
	MinorFaults uint64
	MajorFaults uint64
}

// ─── io.c ─────────────────────────────────────────────────────────────────────

// IoStats mirrors struct io_stats from io.c (io_stats_map).
type IoStats struct {
	ReadBytes      uint64
	WriteBytes     uint64
	ReadIOs        uint64
	WriteIOs       uint64
	ReadLatencyNs  uint64
	WriteLatencyNs uint64
}

// FileEvent mirrors struct file_event from io.c (ring buffer).
type FileEvent struct {
	CgroupID uint64
	PID      uint32
	Flags    uint32
	Comm     [16]byte
	Filename [128]byte
}

// ─── network.c ────────────────────────────────────────────────────────────────

// ConnKey mirrors struct conn_key from network.c (conn_stats_map key).
type ConnKey struct {
	CgroupID uint64
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Pad      uint32
}

// ConnStats mirrors struct conn_stats from network.c (conn_stats_map value).
type ConnStats struct {
	State       uint32
	Retransmits uint32
	FirstSeenNs uint64
	LastSeenNs  uint64
}

// TcpEvent mirrors struct tcp_event from network.c (ring buffer).
type TcpEvent struct {
	CgroupID uint64
	TsNs     uint64
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Family   uint16
	Pad      uint16
	OldState int32
	NewState int32
	SaddrV6  [16]byte
	DaddrV6  [16]byte
}

// ─── syscall.c ────────────────────────────────────────────────────────────────

// SyscallKey mirrors struct syscall_key from syscall.c (syscall_stats_map key).
type SyscallKey struct {
	CgroupID  uint64
	SyscallID uint32
	Pad       uint32
}

// SyscallStats mirrors struct syscall_stats from syscall.c (syscall_stats_map value).
type SyscallStats struct {
	Count          uint64
	Failures       uint64
	TotalLatencyNs uint64
}

// SlowSyscallEvent mirrors struct slow_syscall_event from syscall.c (ring buffer).
type SlowSyscallEvent struct {
	CgroupID  uint64
	PID       uint32
	SyscallID uint32
	LatencyNs uint64
	Comm      [16]byte
}

// ─── Size documentation ──────────────────────────────────────────────────────
// Expected sizes (must match C struct layouts):
//   CpuStats:     32 bytes  (8+8+8+4+4)
//   IoStats:      48 bytes  (6×8)
//   ConnKey:      24 bytes  (8+4+4+2+2+4)
//   ConnStats:    24 bytes  (4+4+8+8)
//   SyscallKey:   16 bytes  (8+4+4)
//   SyscallStats: 24 bytes  (3×8)
