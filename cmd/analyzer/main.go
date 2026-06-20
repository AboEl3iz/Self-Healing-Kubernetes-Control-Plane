// cmd/analyzer — SelfHeal-CP Heuristics Engine
//
// The analyzer subscribes to NATS `selfheal.signals.*`, maintains per-pod
// sliding window state, evaluates detection rules, correlates multi-signal
// anomalies, and publishes AnomalyEvents to `selfheal.anomalies.<namespace>`.
//
// Usage:
//
//	selfheal-analyzer [flags]
//	  --nats-url      NATS server URL (default: nats://localhost:4222)
//	  --rules-file    path to config/rules.yaml
//	  --dry-run       log anomalies without publishing (for testing)
//	  --metrics-addr  Prometheus metrics address (default: :8081)
//	  --log-level     debug|info|warn|error

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/karim-aboelaiz/selfheal-cp/internal/analyzer"
	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
	"github.com/karim-aboelaiz/selfheal-cp/internal/telemetry"
)

func main() {
	natsURL := flag.String("nats-url", "nats://localhost:4222", "NATS server URL")
	rulesFile := flag.String("rules-file", "config/rules.yaml", "Detection rules config")
	dryRun := flag.Bool("dry-run", true, "Log anomalies only, no publishing")
	metricsAddr := flag.String("metrics-addr", ":8081", "Prometheus metrics address")
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	var level slog.Level
	_ = level.UnmarshalText([]byte(*logLevel))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("selfheal-analyzer starting",
		"rules", *rulesFile,
		"nats_url", *natsURL,
		"dry_run", *dryRun,
		"metrics", *metricsAddr,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// 1. Load rules
	rules, rulesCfg, err := analyzer.LoadRules(*rulesFile)
	if err != nil {
		logger.Error("failed to load rules", "error", err)
		os.Exit(1)
	}
	logger.Info("loaded rules", "count", len(rules))

	// 2. Initialize publisher
	publisherCfg := bus.PublisherConfig{NATSUrl: *natsURL}
	publisher, err := bus.NewPublisher(publisherCfg, logger)
	if err != nil {
		logger.Error("failed to initialize publisher", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()

	// 3. Initialize engine
	engine := analyzer.NewEngine(rules, rulesCfg, publisher, *dryRun, logger)

	// 4. Initialize subscriber
	subscriberCfg := bus.SubscriberConfig{
		NATSUrl:    *natsURL,
		StreamName: "SELFHEAL",
	}
	subscriber, err := bus.NewSubscriber(subscriberCfg, logger)
	if err != nil {
		logger.Error("failed to initialize subscriber", "error", err)
		os.Exit(1)
	}
	defer subscriber.Close()

	// 5. Start Prometheus metrics server
	go telemetry.ServeMetrics(*metricsAddr, logger)

	// 6. Start processing signals
	logger.Info("analyzer event loop started")
	err = subscriber.SubscribeSignals(ctx, func(data []byte) error {
		return engine.ProcessSignal(ctx, data)
	})

	if err != nil && err != context.Canceled {
		logger.Error("subscriber error", "error", err)
		os.Exit(1)
	}

	logger.Info("selfheal-analyzer stopped gracefully")
}
