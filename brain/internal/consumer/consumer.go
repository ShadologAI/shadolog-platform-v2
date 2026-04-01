// Package consumer provides the NATS JetStream consumer for the Brain service.
// It subscribes to events published by Gateway, runs them through the detector
// pipeline, and writes findings to PostgreSQL and ClickHouse.
//
// Key design: AckExplicit with max 100 in-flight. Each event individually acked
// after detection completes. If Brain crashes, only unacked events reprocess.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/shadologai/shadolog/v2/brain/internal/detector"
	"github.com/shadologai/shadolog/v2/brain/internal/entity"
	"github.com/shadologai/shadolog/v2/shared/models"
)

const (
	// MaxInFlight limits concurrent unacked messages.
	// AckExplicit ensures each event is individually acknowledged.
	MaxInFlight = 100

	// Subject pattern for event consumption.
	SubjectPattern = "shadolog.events.>"
)

// Consumer subscribes to NATS JetStream and processes events through detectors.
type Consumer struct {
	registry *detector.Registry
	resolver *entity.Resolver
	logger   *slog.Logger
	stopCh   chan struct{}
	natsURL  string
	nc       *nats.Conn
	sub      *nats.Subscription
	pgPool   *pgxpool.Pool
	chConn   chdriver.Conn
}

// New creates a new NATS consumer.
func New(registry *detector.Registry, logger *slog.Logger, natsURL string, pgPool *pgxpool.Pool, chConn chdriver.Conn) *Consumer {
	var resolver *entity.Resolver
	if pgPool != nil {
		store := entity.NewStore(pgPool, logger)
		resolver = entity.NewResolver(store, logger)
		logger.Info("entity resolver enabled")
	}

	return &Consumer{
		registry: registry,
		resolver: resolver,
		logger:   logger,
		stopCh:   make(chan struct{}),
		natsURL:  natsURL,
		pgPool:   pgPool,
		chConn:   chConn,
	}
}

// Start begins consuming events from NATS JetStream.
// Blocks until context is cancelled or Stop is called.
func (c *Consumer) Start(ctx context.Context) {
	c.logger.Info("consumer starting",
		"subject", SubjectPattern,
		"max_inflight", MaxInFlight,
		"ack_policy", "explicit",
		"nats_url", c.natsURL,
	)

	// Connect to NATS
	nc, err := nats.Connect(c.natsURL,
		nats.Name("brain-v4"),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			c.logger.Warn("NATS disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			c.logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		c.logger.Error("failed to connect to NATS", "error", err, "url", c.natsURL)
		return
	}
	c.nc = nc

	// Get JetStream context
	js, err := nc.JetStream(nats.PublishAsyncMaxPending(256))
	if err != nil {
		c.logger.Error("failed to get JetStream context", "error", err)
		return
	}

	// Subscribe with AckExplicit, durable consumer
	sub, err := js.Subscribe(SubjectPattern, func(msg *nats.Msg) {
		processErr := c.processEvent(ctx, msg.Data)
		if processErr != nil {
			c.logger.Warn("event processing failed, nacking",
				"error", processErr,
				"subject", msg.Subject,
			)
			msg.Nak()
			return
		}
		msg.Ack()
	},
		nats.AckExplicit(),
		nats.MaxAckPending(MaxInFlight),
		nats.Durable("brain-v4"),
	)
	if err != nil {
		c.logger.Error("failed to subscribe to JetStream", "error", err, "subject", SubjectPattern)
		return
	}
	c.sub = sub

	c.logger.Info("NATS JetStream subscription active",
		"subject", SubjectPattern,
		"durable", "brain-v4",
	)

	// Block until shutdown
	select {
	case <-ctx.Done():
		c.logger.Info("consumer stopping (context cancelled)")
	case <-c.stopCh:
		c.logger.Info("consumer stopping (stop signal)")
	}
}

// Stop signals the consumer to shut down and drains the subscription.
func (c *Consumer) Stop() {
	close(c.stopCh)

	if c.sub != nil {
		if err := c.sub.Drain(); err != nil {
			c.logger.Warn("failed to drain subscription", "error", err)
		}
	}
	if c.nc != nil {
		c.nc.Close()
	}
}

// processEvent runs a single event through the detector pipeline.
// Called by the NATS message handler for each received event.
func (c *Consumer) processEvent(ctx context.Context, eventData []byte) error {
	var event models.Event
	if err := json.Unmarshal(eventData, &event); err != nil {
		c.logger.Warn("failed to unmarshal event", "error", err)
		return err
	}

	// Handle ARGUS inventory events (entity creation, skip detection pipeline)
	if c.resolver != nil && c.resolver.ProcessInventoryEvent(ctx, &event) {
		c.logger.Debug("inventory event processed", "event_id", event.EventID, "type", event.EventType)
		return nil
	}

	// Run all detectors in priority order
	results := c.registry.RunAll(ctx, &event, event.RawContent)

	// Aggregate findings
	var allFindings []models.Finding
	for _, r := range results {
		if r.Error != nil {
			// Log detector errors but don't stop pipeline
			// ML/behavioral failures are expected and non-fatal
			c.logger.Warn("detector error",
				"detector", r.DetectorID,
				"error", r.Error,
				"latency", r.Latency,
			)
			continue
		}
		allFindings = append(allFindings, r.Findings...)

		c.logger.Debug("detector completed",
			"detector", r.DetectorID,
			"findings", len(r.Findings),
			"latency", r.Latency,
		)
	}

	// Resolve entities from event (builds correlation chain: User→Agent→Tool→Provider)
	if c.resolver != nil {
		c.resolver.ResolveFromEvent(ctx, &event, allFindings)
	}

	if len(allFindings) > 0 {
		c.logger.Info("findings detected",
			"event_id", event.EventID,
			"tenant_id", event.TenantID,
			"finding_count", len(allFindings),
		)

		// Persist findings to PostgreSQL
		if c.pgPool != nil {
			persisted, err := c.persistFindings(ctx, allFindings)
			if err != nil {
				c.logger.Error("failed to persist findings to PG",
					"error", err,
					"event_id", event.EventID,
				)
			} else {
				c.logger.Info("findings persisted",
					"count", persisted,
					"event_id", event.EventID,
				)
			}
		}

		// Dual-write findings to ClickHouse for analytics
		if c.chConn != nil {
			if err := c.persistFindingsCH(ctx, allFindings); err != nil {
				c.logger.Warn("failed to persist findings to CH", "error", err)
			}
		}
	}

	return nil
}

// persistFindings inserts findings into the PostgreSQL findings table.
func (c *Consumer) persistFindings(ctx context.Context, findings []models.Finding) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}

	// Build a batch insert for efficiency
	const baseCols = `finding_id, event_id, tenant_id, detected_at, rule_id, severity,
		category, detector, confidence, action_taken, narrative, owasp_ids,
		mitre_ids, redacted_preview, user_id, ai_tool`
	const placeholderGroup = `($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)`

	var (
		values  []string
		args    []any
		paramN  int
	)

	for _, f := range findings {
		paramN++
		base := (paramN - 1) * 16
		values = append(values, fmt.Sprintf(placeholderGroup,
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
			base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16,
		))

		args = append(args,
			f.FindingID, f.EventID, f.TenantID, f.Timestamp,
			f.RuleID, f.Severity, f.Category, f.Detector,
			f.Confidence, f.ActionTaken, f.Narrative, f.OwaspIDs,
			f.MitreIDs, f.RedactedPreview, f.UserID, f.AITool,
		)
	}

	query := fmt.Sprintf(`INSERT INTO findings_v2 (%s) VALUES %s ON CONFLICT (finding_id) DO NOTHING`,
		baseCols, strings.Join(values, ", "))

	_, err := c.pgPool.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("insert findings: %w", err)
	}

	return len(findings), nil
}

// persistFindingsCH writes findings to ClickHouse for analytics queries.
func (c *Consumer) persistFindingsCH(ctx context.Context, findings []models.Finding) error {
	batch, err := c.chConn.PrepareBatch(ctx,
		`INSERT INTO findings (finding_id, event_id, tenant_id, timestamp, rule_id, severity,
		 category, detector, confidence, framework, control_id, redacted_preview, user_id, ai_tool, action_taken)`)
	if err != nil {
		return fmt.Errorf("prepare CH batch: %w", err)
	}

	for _, f := range findings {
		if err := batch.Append(
			f.FindingID, f.EventID, f.TenantID, f.Timestamp,
			f.RuleID, f.Severity, f.Category, f.Detector,
			f.Confidence, f.Framework, f.ControlID,
			f.RedactedPreview, f.UserID, f.AITool, f.ActionTaken,
		); err != nil {
			return fmt.Errorf("append CH row: %w", err)
		}
	}

	return batch.Send()
}
