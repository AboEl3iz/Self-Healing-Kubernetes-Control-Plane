// Package bus provides NATS JetStream publisher for the SelfHeal-CP event pipeline.
//
// Topic structure:
//
//	selfheal.signals.<node>         ← agent publishes here
//	selfheal.anomalies.<namespace>  ← analyzer publishes here
//	selfheal.actions.<namespace>    ← controller publishes here
//	selfheal.outcomes.<namespace>   ← controller publishes here
//	selfheal.incidents.<namespace>  ← intelligence reasoner publishes here
//	selfheal.audit                  ← immutable audit trail
//
// All messages are serialized as JSON for phase 1-3.
// Call EnsureStream before any publish or subscribe operations.

package bus

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// SelfHealStreamName is the single JetStream stream that carries all selfheal topics.
const SelfHealStreamName = "SELFHEAL"

// EnsureStream idempotently creates (or updates) the SELFHEAL JetStream stream.
//
// This MUST be called once before any publisher or subscriber is used.
// The stream covers all selfheal.> subjects so that consumers can be bound to it.
//
// Retry policy: NATS may not be fully ready immediately after startup, and the
// analyzer + controller can race to create the stream. We retry up to 10 times
// with exponential back-off before giving up.
func EnsureStream(ctx context.Context, js jetstream.JetStream, logger *slog.Logger) error {
	cfg := jetstream.StreamConfig{
		Name: SelfHealStreamName,
		// Wildcard covers all selfheal topics published by every component.
		Subjects: []string{"selfheal.>"},
		// Retain messages for 24 hours — enough for replay and DLQ inspection.
		MaxAge: 24 * time.Hour,
		// File storage so messages survive NATS restarts.
		Storage: jetstream.FileStorage,
		// NOTE: Do NOT set Replicas here. On a non-clustered (single-node) NATS
		// deployment, an explicit Replicas value is treated as a cluster config
		// and causes err_code=10052 (JSStreamInvalidConfig). Let NATS default it.
		//
		// Discard old messages when the stream is full.
		Discard: jetstream.DiscardOld,
		// Keep up to 10 M messages (prevents unbounded growth).
		MaxMsgs: 10_000_000,
	}

	const maxAttempts = 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		stream, err := js.CreateOrUpdateStream(ctx, cfg)
		if err == nil {
			info := stream.CachedInfo()
			logger.Info("bus: SELFHEAL stream ready",
				"stream", info.Config.Name,
				"subjects", info.Config.Subjects,
				"messages", info.State.Msgs,
				"attempt", attempt,
			)
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Exponential back-off: 500ms, 1s, 2s, 4s … capped at 10s.
		wait := time.Duration(500<<uint(attempt-1)) * time.Millisecond
		if wait > 10*time.Second {
			wait = 10 * time.Second
		}
		logger.Warn("bus: EnsureStream attempt failed, retrying",
			"attempt", attempt,
			"max", maxAttempts,
			"wait", wait,
			"error", err,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}

	return fmt.Errorf("bus: ensure stream %q: exceeded %d attempts", SelfHealStreamName, maxAttempts)
}


// Publisher publishes events to NATS JetStream.
type Publisher struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	logger *slog.Logger
}

// PublisherConfig holds NATS connection and topic configuration.
type PublisherConfig struct {
	NATSUrl string // e.g., "nats://localhost:4222"
}

// NewPublisher creates a new bus Publisher.
func NewPublisher(cfg PublisherConfig, logger *slog.Logger) (*Publisher, error) {
	nc, err := nats.Connect(cfg.NATSUrl,
		nats.Name("selfheal-publisher"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1), // retry forever
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS publisher disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("NATS publisher reconnected", "url", nc.ConnectedUrl())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("publisher: NATS connect to %s: %w", cfg.NATSUrl, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("publisher: JetStream init: %w", err)
	}

	p := &Publisher{
		nc:     nc,
		js:     js,
		logger: logger,
	}

	logger.Info("publisher: connected to NATS", "url", cfg.NATSUrl)
	return p, nil
}

// JetStream returns the underlying JetStream context.
// Used by EnsureStream to set up the stream before consuming or publishing.
func (p *Publisher) JetStream() jetstream.JetStream { return p.js }

// PublishSignal publishes a SignalEvent to selfheal.signals.<node>.
func (p *Publisher) PublishSignal(ctx context.Context, node string, data []byte) error {
	topic := fmt.Sprintf("selfheal.signals.%s", node)
	if _, err := p.js.PublishAsync(topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", topic, err)
	}
	return nil
}

// PublishAnomaly publishes an AnomalyEvent to selfheal.anomalies.<namespace>.
// Used by the Analyzer to trigger the Controller.
func (p *Publisher) PublishAnomaly(ctx context.Context, namespace string, data []byte) error {
	topic := fmt.Sprintf("selfheal.anomalies.%s", namespace)
	if _, err := p.js.PublishAsync(topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", topic, err)
	}
	return nil
}

// PublishAction publishes an ActionEvent to selfheal.actions.<namespace>.
func (p *Publisher) PublishAction(ctx context.Context, namespace string, data []byte) error {
	topic := fmt.Sprintf("selfheal.actions.%s", namespace)
	if _, err := p.js.PublishAsync(topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", topic, err)
	}
	return nil
}

// PublishOutcome publishes an OutcomeEvent to selfheal.outcomes.<namespace>.
func (p *Publisher) PublishOutcome(ctx context.Context, namespace string, data []byte) error {
	topic := fmt.Sprintf("selfheal.outcomes.%s", namespace)
	if _, err := p.js.PublishAsync(topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", topic, err)
	}
	return nil
}

// PublishIncident publishes an IncidentEvent to selfheal.incidents.<namespace>.
// Used by the intelligence.Reasoner; consumed by the Phase 3 controller for
// node-level actions (cordon_node).
func (p *Publisher) PublishIncident(ctx context.Context, namespace string, data []byte) error {
	topic := fmt.Sprintf("selfheal.incidents.%s", namespace)
	if _, err := p.js.PublishAsync(topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", topic, err)
	}
	return nil
}

// Close drains the NATS connection gracefully.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}
