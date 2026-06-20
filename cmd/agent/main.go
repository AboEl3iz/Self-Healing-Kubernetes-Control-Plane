// cmd/agent — SelfHeal-CP eBPF Agent
//
// The agent is deployed as a DaemonSet (one pod per node).
// It loads eBPF probes, observes kernel-level signals, resolves cgroup_ids
// to Kubernetes pod metadata, and publishes enriched SignalEvents to NATS.
//
// Required capabilities: CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON
// Must run as root (UID 0) or with the above capabilities.
//
// Usage:
//
//	selfheal-agent [flags]
//	  --cpu-bpf     path to cpu.o
//	  --mem-bpf     path to memory.o
//	  --io-bpf      path to io.o
//	  --net-bpf     path to network.o
//	  --sys-bpf     path to syscall.o
//	  --kubernetes  enable Kubernetes pod metadata resolution
//	  --nats-url    NATS server URL (default: nats://localhost:4222)
//	  --dry-run     publish events but take no actions (Phase 1-2 default)
//	  --log-level   debug|info|warn|error (default: info)
//	  --metrics-addr Prometheus metrics address (default: :8080)

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/karim-aboelaiz/selfheal-cp/internal/ebpf"
)

func main() {
	// ─── CLI flags ────────────────────────────────────────────────────────────
	cpuBPF := flag.String("cpu-bpf", "ebpf/probes/cpu.o", "CPU BPF object")
	memBPF := flag.String("mem-bpf", "ebpf/probes/memory.o", "Memory BPF object")
	ioBPF := flag.String("io-bpf", "ebpf/probes/io.o", "I/O BPF object")
	netBPF := flag.String("net-bpf", "ebpf/probes/network.o", "Network BPF object")
	sysBPF := flag.String("sys-bpf", "ebpf/probes/syscall.o", "Syscall BPF object")
	natsURL := flag.String("nats-url", "nats://localhost:4222", "NATS server URL")
	k8s := flag.Bool("kubernetes", false, "Enable Kubernetes pod resolution")
	dryRun := flag.Bool("dry-run", true, "Publish events only, no healing actions")
	logLevel := flag.String("log-level", "info", "Log level: debug|info|warn|error")
	metricsAddr := flag.String("metrics-addr", ":8080", "Prometheus metrics address")
	flag.Parse()

	// ─── Logger ───────────────────────────────────────────────────────────────
	var level slog.Level
	_ = level.UnmarshalText([]byte(*logLevel))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("selfheal-agent starting",
		"dry_run", *dryRun,
		"kubernetes", *k8s,
		"nats_url", *natsURL,
	)

	// ─── Context with graceful shutdown ───────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ─── Node name ────────────────────────────────────────────────────────────
	nodeName, _ := os.Hostname()
	if n := os.Getenv("NODE_NAME"); n != "" {
		nodeName = n // prefer downward API injection in k8s
	}

	// ─── Mapper (PID → Pod) ───────────────────────────────────────────────────
	mapper := ebpf.NewMapper(nodeName, logger)
	if *k8s {
		go func() {
			if err := mapper.Start(ctx); err != nil && err != context.Canceled {
				logger.Error("mapper stopped unexpectedly", "error", err)
				cancel()
			}
		}()
	}

	// ─── Publisher (→ NATS) — skipped in dry-run mode ────────────────────────
	var publisher *ebpf.Publisher
	if !*dryRun {
		var err error
		publisher, err = ebpf.NewPublisher(ebpf.PublisherConfig{
			NATSUrl:  *natsURL,
			NodeName: nodeName,
		}, logger)
		if err != nil {
			logger.Error("failed to create publisher", "error", err)
			os.Exit(1)
		}
		defer publisher.Close()
	} else {
		logger.Info("dry-run mode: events will be logged but NOT published to NATS")
	}

	// ─── eBPF Loader ─────────────────────────────────────────────────────────
	loader := ebpf.NewLoader(ebpf.ProbeConfig{
		CPUObj:     *cpuBPF,
		MemoryObj:  *memBPF,
		IOObj:      *ioBPF,
		NetworkObj: *netBPF,
		SyscallObj: *sysBPF,
	}, mapper, logger)

	// Wire the publisher into the loader (nil = dry-run / log-only).
	loader.SetPublisher(publisher)

	probes, err := loader.LoadCoreProbes(ctx)
	if err != nil {
		logger.Error("failed to load eBPF probes", "error", err)
		os.Exit(1)
	}
	defer probes.Close()

	logger.Info("eBPF probes loaded — entering event loop",
		"node", nodeName,
		"dry_run", *dryRun,
	)

	// ─── Prometheus metrics server ────────────────────────────────────────────
	go ebpf.ServeMetrics(*metricsAddr, logger)

	// ─── Main poll loop ───────────────────────────────────────────────────────
	if err := loader.PollStatsMaps(ctx, probes); err != nil && err != context.Canceled {
		logger.Error("poll loop error", "error", err)
		os.Exit(1)
	}

	logger.Info("selfheal-agent stopped gracefully")
}
