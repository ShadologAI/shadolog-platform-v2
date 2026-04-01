package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// ClickHouseSink batch-inserts event metadata into ClickHouse.
type ClickHouseSink struct {
	conn   clickhouse.Conn
	logger *slog.Logger
}

// NewClickHouseSink connects to ClickHouse.
func NewClickHouseSink(addr string, logger *slog.Logger) (*ClickHouseSink, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
		},
		DialTimeout:     5 * time.Second,
		ConnMaxLifetime: 1 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	return &ClickHouseSink{conn: conn, logger: logger}, nil
}

// Flush batch-inserts events into the ClickHouse events table.
func (s *ClickHouseSink) Flush(ctx context.Context, events []*models.Event) error {
	if len(events) == 0 {
		return nil
	}

	batch, err := s.conn.PrepareBatch(ctx, `INSERT INTO events (
		event_id, tenant_id, timestamp, event_type, ai_tool, ai_model,
		direction, user_id, session_id, content_hash, content_length,
		agent_type, agent_id, source_ip, url, hostname
	)`)
	if err != nil {
		return fmt.Errorf("clickhouse prepare batch: %w", err)
	}

	for _, e := range events {
		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		err := batch.Append(
			e.EventID, e.TenantID, ts, e.EventType, e.AITool, e.AIModel,
			e.Direction, e.UserID, e.SessionID, e.ContentHash, e.ContentLength,
			e.AgentType, e.AgentID, e.SourceIP, e.URL, e.Hostname,
		)
		if err != nil {
			s.logger.Warn("clickhouse append failed", "event_id", e.EventID, "error", err)
			continue
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("clickhouse batch send: %w", err)
	}

	s.logger.Debug("ClickHouse flush", "count", len(events))
	return nil
}

// Close shuts down the ClickHouse connection.
func (s *ClickHouseSink) Close() {
	s.conn.Close()
}
