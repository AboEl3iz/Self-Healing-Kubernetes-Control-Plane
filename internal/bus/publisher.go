// Package bus provides NATS JetStream publisher for the SelfHeal-CP event pipeline.
//
// Topic structure:
//   selfheal.signals.<node>         ← agent publishes here
//   selfheal.anomalies.<namespace>  ← analyzer publishes here
//   selfheal.actions.<namespace>    ← controller publishes here
//   selfheal.outcomes.<namespace>   ← controller publishes here
//   selfheal.incidents.<namespace>  ← intelligence reasoner publishes here
//   selfheal.audit                  ← immutable audit trail
//
// All messages are serialized as JSON for phase 1-3.
// JetStream stream "SELFHEAL" must be created before publishing.

package bus

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

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
