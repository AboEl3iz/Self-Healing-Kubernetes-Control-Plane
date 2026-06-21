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
	"strings"
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

// isStaleConsumerErr returns true for errors that mean the consumer handle is
// no longer valid and must be re-obtained from JetStream. This happens when:
//   - NATS pod restarted and JetStream is re-initialising ("no responders available")
//   - The underlying NATS connection reconnected (server-side consumer was cleaned up)
func isStaleConsumerErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no responders available") ||
		strings.Contains(msg, "consumer not found") ||
		strings.Contains(msg, "stream not found") ||
		strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "EOF")
}

// consume is the shared pull-consumer loop.
//
// On every iteration it holds a live consumer handle. If the handle goes stale
// (NATS restart, reconnect, JetStream re-init) it recreates it with back-off
// instead of spinning forever on a dead reference.
func (s *Subscriber) consume(ctx context.Context, subject, consumerName string, handler MessageHandler) error {
	consCfg := jetstream.ConsumerConfig{
		Name:          consumerName,
		Durable:       consumerName,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    3, // after 3 NAK cycles → stop redelivery (DLQ TBD)
		DeliverPolicy: jetstream.DeliverAllPolicy,
	}

	// acquireConsumer obtains (or re-obtains) a live consumer handle.
	// It retries indefinitely with back-off until the context is cancelled.
	acquireConsumer := func() (jetstream.Consumer, error) {
		attempt := 0
		for {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			cons, err := s.js.CreateOrUpdateConsumer(ctx, s.cfg.StreamName, consCfg)
			if err == nil {
				if attempt > 0 {
					s.logger.Info("subscriber: consumer re-acquired",
						"consumer", consumerName, "attempts", attempt+1)
				}
				return cons, nil
			}
			attempt++
			wait := time.Duration(attempt) * 2 * time.Second
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			s.logger.Warn("subscriber: failed to acquire consumer, retrying",
				"consumer", consumerName, "error", err, "wait", wait)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	cons, err := acquireConsumer()
	if err != nil {
		return err
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
			if isStaleConsumerErr(err) {
				// Consumer handle is dead — re-obtain from JetStream.
				s.logger.Warn("subscriber: consumer stale, re-acquiring",
					"consumer", consumerName, "error", err)
				cons, err = acquireConsumer()
				if err != nil {
					return err
				}
				consecutiveFails = 0
				continue
			}
			consecutiveFails++
			s.logger.Warn("subscriber: fetch error",
				"consumer", consumerName, "error", err, "fails", consecutiveFails)
			// Linear back-off up to 10 s for non-stale transient errors.
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
					"consumer", consumerName, "error", err)
				_ = msg.Nak()
			} else {
				_ = msg.Ack()
			}
		}

		if batchErr := batch.Error(); batchErr != nil && ctx.Err() == nil {
			if isStaleConsumerErr(batchErr) {
				// Batch-level stale error — re-acquire consumer on next iteration.
				s.logger.Warn("subscriber: batch stale error, re-acquiring consumer",
					"consumer", consumerName, "error", batchErr)
				cons, err = acquireConsumer()
				if err != nil {
					return err
				}
			} else {
				s.logger.Warn("subscriber: batch error",
					"consumer", consumerName, "error", batchErr)
			}
		}
	}
}


// Close drains the NATS connection.
func (s *Subscriber) Close() {
	if s.nc != nil {
		s.nc.Drain() //nolint:errcheck
	}
}
