// Package ebpf — publisher.go sends enriched SignalEvents to NATS JetStream.
//
// Pipeline: eBPF map/ring buf → Mapper.Resolve() → Publisher.PublishSignal()
//
// NATS stream "SELFHEAL" is created/verified on startup. All messages are
// serialized as JSON (avoids protoc dependency at run time; proto can replace
// this in Phase 5). Delivery guarantee: JetStream at-least-once with async ACK.
//
// If NATS is unavailable at startup, the publisher retries indefinitely with
// backoff. Events during reconnection are dropped (ring buffer is the buffer).

package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// PublisherConfig holds NATS connection and topic configuration.
type PublisherConfig struct {
	NATSUrl    string // e.g., "nats://localhost:4222"
	NodeName   string // used to build topic: selfheal.signals.<node>
	StreamName string // JetStream stream name (default: "SELFHEAL")
}

// Publisher publishes SignalEvents to NATS JetStream.
type Publisher struct {
	cfg    PublisherConfig
	nc     *nats.Conn
	js     jetstream.JetStream
	topic  string
	logger *slog.Logger
}

// SignalEvent is the JSON-serialisable signal emitted per observation window.
// Field names match signal.proto for easy proto migration later.
type SignalEvent struct {
	Version    string  `json:"version"`
	Node       string  `json:"node"`
	Pod        string  `json:"pod"`
	Namespace  string  `json:"namespace"`
	Deployment string  `json:"deployment"`
	Container  string  `json:"container"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit"`
	DurationMs int64   `json:"duration_ms"`
	Timestamp  int64   `json:"timestamp"` // Unix ms
	CgroupID   uint64  `json:"cgroup_id"`
	PID        int32   `json:"pid,omitempty"`
}

// NewPublisher creates a Publisher and connects to NATS with automatic reconnect.
// Returns an error only if the initial TCP connection cannot be established.
func NewPublisher(cfg PublisherConfig, logger *slog.Logger) (*Publisher, error) {
	if cfg.StreamName == "" {
		cfg.StreamName = "SELFHEAL"
	}

	nc, err := nats.Connect(cfg.NATSUrl,
		nats.Name("selfheal-agent"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1), // retry forever
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("NATS reconnected", "url", nc.ConnectedUrl())
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

	topic := fmt.Sprintf("selfheal.signals.%s", cfg.NodeName)

	p := &Publisher{
		cfg:    cfg,
		nc:     nc,
		js:     js,
		topic:  topic,
		logger: logger,
	}

	if err := p.ensureStream(context.Background()); err != nil {
		// Log but don't fail — stream may be created by another agent.
		logger.Warn("publisher: stream setup warning", "error", err)
	}

	logger.Info("publisher: connected to NATS",
		"url", cfg.NATSUrl,
		"stream", cfg.StreamName,
		"topic", topic,
	)
	return p, nil
}

// ensureStream creates the SELFHEAL JetStream stream if it doesn't exist.
// Subjects cover all 4 event types for the full pipeline.
func (p *Publisher) ensureStream(ctx context.Context) error {
	_, err := p.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: p.cfg.StreamName,
		Subjects: []string{
			"selfheal.signals.*",
			"selfheal.anomalies.*",
			"selfheal.actions.*",
			"selfheal.outcomes.*",
			"selfheal.audit",
		},
		Retention: jetstream.WorkQueuePolicy, // consumed-once
		MaxAge:    24 * time.Hour,            // replay window
		Storage:   jetstream.FileStorage,
		Replicas:  1,
		Discard:   jetstream.DiscardOld,
		MaxMsgs:   5_000_000,
	})
	return err
}

// PublishSignal encodes a SignalEvent as JSON and publishes it asynchronously.
func (p *Publisher) PublishSignal(ctx context.Context, event *SignalEvent) error {
	event.Version = "1.0"
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("publisher: marshal: %w", err)
	}

	// PublishAsync returns immediately; acks are batched by the NATS client.
	if _, err := p.js.PublishAsync(p.topic, data); err != nil {
		return fmt.Errorf("publisher: publish to %s: %w", p.topic, err)
	}
	return nil
}

// Close drains the NATS connection gracefully (flushes pending publishes).
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}
