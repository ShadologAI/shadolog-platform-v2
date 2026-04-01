// Package store provides data sink implementations for the Gateway pipeline.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/nats-io/nats.go"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// NATSSink publishes events to NATS JetStream.
// Events are published to shadolog.events.{tenant_id}.{event_type}.
type NATSSink struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	logger *slog.Logger
	closed atomic.Bool
}

// NewNATSSink connects to NATS and initializes JetStream.
func NewNATSSink(url string, logger *slog.Logger) (*NATSSink, error) {
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(60),
		nats.ReconnectWait(nats.DefaultReconnectWait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("NATS disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats jetstream: %w", err)
	}

	// Ensure the EVENTS stream exists (idempotent).
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "EVENTS",
		Subjects: []string{"shadolog.events.>"},
		Storage:  nats.FileStorage,
		MaxAge:   72 * 3600_000_000_000, // 72 hours retention
	})
	if err != nil {
		logger.Warn("NATS stream creation skipped (may already exist)", "error", err)
	}

	return &NATSSink{nc: nc, js: js, logger: logger}, nil
}

// Flush publishes a batch of events to NATS JetStream.
// Each event is published to shadolog.events.{tenant_id}.{event_type}.
func (s *NATSSink) Flush(ctx context.Context, events []*models.Event) error {
	if s.closed.Load() {
		return fmt.Errorf("nats sink closed")
	}

	for _, event := range events {
		subject := fmt.Sprintf("shadolog.events.%s.%s", event.TenantID, event.EventType)

		data, err := json.Marshal(event)
		if err != nil {
			s.logger.Warn("failed to marshal event for NATS", "event_id", event.EventID, "error", err)
			continue
		}

		_, err = s.js.Publish(subject, data, nats.Context(ctx))
		if err != nil {
			s.logger.Warn("failed to publish event to NATS", "event_id", event.EventID, "subject", subject, "error", err)
			continue
		}
	}

	s.logger.Debug("NATS flush", "count", len(events))
	return nil
}

// IsConnected returns true if the NATS connection is active.
func (s *NATSSink) IsConnected() bool {
	return s.nc.IsConnected()
}

// Close shuts down the NATS connection.
func (s *NATSSink) Close() {
	s.closed.Store(true)
	s.nc.Close()
}
