// cmd/controller — SelfHeal-CP Kubernetes Controller
//
// The controller subscribes to NATS `selfheal.anomalies.*`, applies the
// guardrails policy, executes healing actions against the Kubernetes API,
// observes outcomes, and publishes OutcomeEvents to `selfheal.outcomes.*`.
//
// Usage:
//
//	selfheal-controller [flags]
//	  --nats-url         NATS server URL (default: nats://localhost:4222)
//	  --guardrails-file  path to config/guardrails.yaml
//	  --kubeconfig       path to kubeconfig (empty = in-cluster config)
//	  --dry-run          evaluate but do not modify cluster state
//	  --metrics-addr     Prometheus metrics address (default: :8082)
//	  --log-level        debug|info|warn|error

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/karim-aboelaiz/selfheal-cp/internal/bus"
	controller "github.com/karim-aboelaiz/selfheal-cp/internal/controller"
	"github.com/karim-aboelaiz/selfheal-cp/internal/controller/guardrails"
	"github.com/karim-aboelaiz/selfheal-cp/internal/telemetry"
)

func main() {
	natsURL := flag.String("nats-url", "nats://localhost:4222", "NATS server URL")
	guardrailsFile := flag.String("guardrails-file", "config/guardrails.yaml", "Guardrails policy config")
	kubeconfig := flag.String("kubeconfig", "", "Kubeconfig path (empty = in-cluster)")
	dryRun := flag.Bool("dry-run", false, "Evaluate but do not modify cluster")
	metricsAddr := flag.String("metrics-addr", ":8082", "Prometheus metrics address")
	logLevel := flag.String("log-level", "info", "Log level: debug|info|warn|error")
	flag.Parse()

	// ── Logger ─────────────────────────────────────────────────────────────────
	var level slog.Level
	_ = level.UnmarshalText([]byte(*logLevel))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("selfheal-controller starting",
		"guardrails", *guardrailsFile,
		"nats_url", *natsURL,
		"kubeconfig", *kubeconfig,
		"dry_run", *dryRun,
		"metrics", *metricsAddr,
	)

	// ── Signal context ─────────────────────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Guardrails policy ──────────────────────────────────────────────────────
	policy, err := guardrails.LoadPolicy(*guardrailsFile)
	if err != nil {
		logger.Error("failed to load guardrails policy", "file", *guardrailsFile, "error", err)
		os.Exit(1)
	}
	logger.Info("guardrails policy loaded",
		"protected_namespaces", policy.Guardrails.ProtectedNamespaces,
		"dry_run", policy.IsDryRun(),
	)

	// ── Kubernetes client ──────────────────────────────────────────────────────
	k8sClient, err := buildK8sClient(*kubeconfig)
	if err != nil {
		logger.Error("failed to build Kubernetes client", "error", err)
		os.Exit(1)
	}
	logger.Info("Kubernetes client initialised")

	// ── NATS subscriber ────────────────────────────────────────────────────────
	subscriber, err := bus.NewSubscriber(bus.SubscriberConfig{
		NATSUrl:    *natsURL,
		StreamName: "SELFHEAL",
	}, logger)
	if err != nil {
		logger.Error("failed to connect NATS subscriber", "error", err)
		os.Exit(1)
	}
	defer subscriber.Close()

	// ── NATS publisher ─────────────────────────────────────────────────────────
	publisher, err := bus.NewPublisher(bus.PublisherConfig{
		NATSUrl: *natsURL,
	}, logger)
	if err != nil {
		logger.Error("failed to connect NATS publisher", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()

	// ── Telemetry ──────────────────────────────────────────────────────────────
	metrics := telemetry.Register()
	audit := telemetry.NewAuditLog(k8sClient, logger)
	go telemetry.ServeMetrics(*metricsAddr, logger)

	// ── Reconciler ─────────────────────────────────────────────────────────────
	reconciler := controller.NewReconciler(controller.ReconcilerConfig{
		K8s:        k8sClient,
		Subscriber: subscriber,
		Publisher:  publisher,
		Policy:     policy,
		Audit:      audit,
		Metrics:    metrics,
		DryRun:     *dryRun,
		Logger:     logger,
	})

	// ── Run ────────────────────────────────────────────────────────────────────
	if err := reconciler.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("reconciler exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("selfheal-controller stopped gracefully")
}

// buildK8sClient creates a Kubernetes client using in-cluster config if
// kubeconfig is empty, or from the provided kubeconfig file path.
func buildK8sClient(kubeconfigPath string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error

	if kubeconfigPath == "" {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			// Fallback to KUBECONFIG env var / default ~/.kube/config for local dev.
			cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
			if err != nil {
				return nil, err
			}
		}
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(cfg)
}
