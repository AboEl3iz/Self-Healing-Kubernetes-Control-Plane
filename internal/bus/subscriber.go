// Package bus — subscriber.go consumes events from NATS JetStream.
//
// Uses a durable pull consumer (not push) so that:
//   - Multiple analyzer replicas can share the workload (competing consumers)
//   - Messages are replayed on restart (durable, ack-wait based retry)
//   - Poison messages (3 consecutive failures) go to the DLQ subject
//
// Consumer names:
//   signals    → "selfheal-analyzer-signals"
//   anomalies  → "selfheal-controller-anomalies"
//   outcomes   → "selfheal-analyzer-outcomes"

package bus

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// SubscriberConfig holds NATS connection settings.
type SubscriberConfig struct {
	NATSUrl    string
	StreamName string // default: "SELFHEAL"
	BatchSize  int    // messages to fetch per pull (default: 100)
	MaxWait    time.Duration
}

// MessageHandler is called for each received message.
// Return nil to ACK, return error to NAK (message will be redelivered).
type MessageHandler func(data []byte) error

// Subscriber consumes events from NATS JetStream via pull consumers.
type Subscriber struct {
	cfg    SubscriberConfig
	nc     *nats.Conn
	js     jetstream.JetStream
	logger *slog.Logger
}

// NewSubscriber connects to NATS and returns a ready Subscriber.
func NewSubscriber(cfg SubscriberConfig, logger *slog.Logger) (*Subscriber, error) {
	if cfg.StreamName == "" {
		cfg.StreamName = "SELFHEAL"
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 5 * time.Second
	}

	nc, err := nats.Connect(cfg.NATSUrl,
		nats.Name("selfheal-analyzer-sub"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS subscriber disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("NATS subscriber reconnected", "url", nc.ConnectedUrl())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("subscriber: NATS connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("subscriber: JetStream init: %w", err)
	}

	return &Subscriber{cfg: cfg, nc: nc, js: js, logger: logger}, nil
}

// SubscribeSignals subscribes to selfheal.signals.* using a durable pull consumer.
// Calls handler for every message. Blocks until ctx is cancelled.
func (s *Subscriber) SubscribeSignals(ctx context.Context, handler MessageHandler) error {
	return s.consume(ctx, "selfheal.signals.*", "selfheal-analyzer-signals", handler)
}

// SubscribeAnomalies subscribes to selfheal.anomalies.* (used by the controller).
func (s *Subscriber) SubscribeAnomalies(ctx context.Context, handler MessageHandler) error {
	return s.consume(ctx, "selfheal.anomalies.*", "selfheal-controller-anomalies", handler)
}

// SubscribeOutcomes subscribes to selfheal.outcomes.* (feedback loop for analyzer).
func (s *Subscriber) SubscribeOutcomes(ctx context.Context, handler MessageHandler) error {
	return s.consume(ctx, "selfheal.outcomes.*", "selfheal-analyzer-outcomes", handler)
}

// SubscribeIncidents subscribes to selfheal.incidents.* (intelligence → controller).
// The controller uses this to trigger node-level actions (cordon_node).
func (s *Subscriber) SubscribeIncidents(ctx context.Context, handler MessageHandler) error {
	return s.consume(ctx, "selfheal.incidents.*", "selfheal-controller-incidents", handler)
}

// SubscribeAnomaliesIntelligence subscribes to selfheal.anomalies.* for the
// intelligence aggregator (separate consumer group from the controller's consumer).
func (s *Subscriber) SubscribeAnomaliesIntelligence(ctx context.Context, handler MessageHandler) error {
	return s.consume(ctx, "selfheal.anomalies.*", "selfheal-intelligence-anomalies", handler)
}

// consume is the shared pull-consumer loop.
func (s *Subscriber) consume(ctx context.Context, subject, consumerName string, handler MessageHandler) error {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, s.cfg.StreamName, jetstream.ConsumerConfig{
		Name:          consumerName,
		Durable:       consumerName,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    3, // after 3 failures → no more redelivery (DLQ TBD)
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		return fmt.Errorf("subscriber: create consumer %s: %w", consumerName, err)
	}

	s.logger.Info("subscriber: consuming", "subject", subject, "consumer", consumerName)

	consecutiveFails := 0

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		batch, err := cons.Fetch(s.cfg.BatchSize, jetstream.FetchMaxWait(s.cfg.MaxWait))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			consecutiveFails++
			s.logger.Warn("subscriber: fetch error", "consumer", consumerName, "error", err, "fails", consecutiveFails)
			// Exponential backoff up to 10s.
			wait := time.Duration(consecutiveFails) * time.Second
			if wait > 10*time.Second {
				wait = 10 * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		consecutiveFails = 0

		for msg := range batch.Messages() {
			if err := handler(msg.Data()); err != nil {
				s.logger.Warn("subscriber: handler error — NAKing message",
					"consumer", consumerName,
					"error", err,
				)
				_ = msg.Nak()
			} else {
				_ = msg.Ack()
			}
		}

		if batchErr := batch.Error(); batchErr != nil && ctx.Err() == nil {
			s.logger.Warn("subscriber: batch error", "consumer", consumerName, "error", batchErr)
		}
	}
}

// Close drains the NATS connection.
func (s *Subscriber) Close() {
	if s.nc != nil {
		s.nc.Drain() //nolint:errcheck
	}
}
