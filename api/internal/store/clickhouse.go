package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// CHStore provides read-only access to ClickHouse event and finding data.
type CHStore struct {
	conn driver.Conn
}

// NewCHStore connects to ClickHouse and verifies connectivity.
func NewCHStore(addr string) (*CHStore, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 30,
		},
		DialTimeout:     5 * time.Second,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	slog.Info("clickhouse connected", "addr", addr)
	return &CHStore{conn: conn}, nil
}

// Close shuts down the ClickHouse connection.
func (s *CHStore) Close() error {
	return s.conn.Close()
}

// Ping checks ClickHouse connectivity.
func (s *CHStore) Ping(ctx context.Context) error {
	return s.conn.Ping(ctx)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// ListEvents returns events matching the filter, always scoped to tenant_id.
func (s *CHStore) ListEvents(ctx context.Context, f EventFilter) ([]Event, int, error) {
	// Count query
	countWhere, countArgs := buildEventWhere(f)
	var total uint64
	if err := s.conn.QueryRow(ctx,
		"SELECT count() FROM events "+countWhere, countArgs...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	// Data query
	where, args := buildEventWhere(f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, uint64(limit), uint64(f.Offset))

	query := fmt.Sprintf(
		`SELECT event_id, tenant_id, timestamp, event_type, ai_tool, ai_model,
		        direction, content_length, user_id, session_id, agent_id, agent_type,
		        url, hostname, ingested_at
		 FROM events %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.EventID, &e.TenantID, &e.Timestamp, &e.EventType, &e.AITool, &e.AIModel,
			&e.Direction, &e.ContentLength, &e.UserID, &e.SessionID, &e.AgentID, &e.AgentType,
			&e.SourceURL, &e.Hostname, &e.IngestedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, int(total), rows.Err()
}

// CountEvents returns the total number of events for a tenant.
func (s *CHStore) CountEvents(ctx context.Context, tenantID string) (uint64, error) {
	var count uint64
	err := s.conn.QueryRow(ctx,
		"SELECT count() FROM events WHERE tenant_id = ?", tenantID,
	).Scan(&count)
	return count, err
}

// EventTimeline returns event counts bucketed by hour for the given tenant and time range.
func (s *CHStore) EventTimeline(ctx context.Context, tenantID string, since, until time.Time) ([]TimelinePoint, error) {
	rows, err := s.conn.Query(ctx,
		`SELECT toStartOfHour(timestamp) AS bucket, count() AS cnt
		 FROM events
		 WHERE tenant_id = ? AND timestamp >= ? AND timestamp <= ?
		 GROUP BY bucket ORDER BY bucket`, tenantID, since, until)
	if err != nil {
		return nil, fmt.Errorf("event timeline: %w", err)
	}
	defer rows.Close()

	var points []TimelinePoint
	for rows.Next() {
		var bucket time.Time
		var count uint64
		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, fmt.Errorf("scan timeline point: %w", err)
		}
		points = append(points, TimelinePoint{
			Bucket: bucket.Format(time.RFC3339),
			Count:  count,
		})
	}
	return points, rows.Err()
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// ListFindings returns findings matching the filter, always scoped to tenant_id.
func (s *CHStore) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int, error) {
	countWhere, countArgs := buildFindingWhere(f)
	var total uint64
	if err := s.conn.QueryRow(ctx,
		"SELECT count() FROM findings "+countWhere, countArgs...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count findings: %w", err)
	}

	where, args := buildFindingWhere(f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, uint64(limit), uint64(f.Offset))

	query := fmt.Sprintf(
		`SELECT finding_id, event_id, tenant_id, timestamp, rule_id, severity,
		        category, detector, confidence, framework, control_id,
		        redacted_preview, user_id, ai_tool, action_taken
		 FROM findings %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)

	rows, err := s.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(
			&f.FindingID, &f.EventID, &f.TenantID, &f.Timestamp, &f.RuleID, &f.Severity,
			&f.Category, &f.Detector, &f.Confidence, &f.Framework, &f.ControlID,
			&f.RedactedPreview, &f.UserID, &f.AITool, &f.ActionTaken,
		); err != nil {
			return nil, 0, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, int(total), rows.Err()
}

// CountFindings returns the total number of findings for a tenant.
func (s *CHStore) CountFindings(ctx context.Context, tenantID string) (uint64, error) {
	var count uint64
	err := s.conn.QueryRow(ctx,
		"SELECT count() FROM findings WHERE tenant_id = ?", tenantID,
	).Scan(&count)
	return count, err
}

// FindingsBySeverity returns finding counts grouped by severity for a tenant.
func (s *CHStore) FindingsBySeverity(ctx context.Context, tenantID string) ([]SeverityCount, error) {
	rows, err := s.conn.Query(ctx,
		`SELECT severity, count() AS cnt
		 FROM findings WHERE tenant_id = ?
		 GROUP BY severity ORDER BY cnt DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("findings by severity: %w", err)
	}
	defer rows.Close()

	var counts []SeverityCount
	for rows.Next() {
		var sc SeverityCount
		if err := rows.Scan(&sc.Severity, &sc.Count); err != nil {
			return nil, fmt.Errorf("scan severity count: %w", err)
		}
		counts = append(counts, sc)
	}
	return counts, rows.Err()
}

// CountEventsSince returns the number of events for a tenant since a given time.
func (s *CHStore) CountEventsSince(ctx context.Context, tenantID string, since time.Time) (uint64, error) {
	var count uint64
	err := s.conn.QueryRow(ctx,
		"SELECT count() FROM events WHERE tenant_id = ? AND timestamp >= ?", tenantID, since,
	).Scan(&count)
	return count, err
}

// CountFindingsSince returns the number of findings for a tenant since a given time.
func (s *CHStore) CountFindingsSince(ctx context.Context, tenantID string, since time.Time) (uint64, error) {
	var count uint64
	err := s.conn.QueryRow(ctx,
		"SELECT count() FROM findings WHERE tenant_id = ? AND timestamp >= ?", tenantID, since,
	).Scan(&count)
	return count, err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildEventWhere(f EventFilter) (string, []any) {
	clauses := []string{"tenant_id = ?"}
	args := []any{f.TenantID}

	if f.EventType != nil {
		clauses = append(clauses, "event_type = ?")
		args = append(args, *f.EventType)
	}
	if f.AITool != nil {
		clauses = append(clauses, "ai_tool = ?")
		args = append(args, *f.AITool)
	}
	if f.UserID != nil {
		clauses = append(clauses, "user_id = ?")
		args = append(args, *f.UserID)
	}
	if f.Since != nil {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, *f.Until)
	}

	return "WHERE " + strings.Join(clauses, " AND "), args
}

func buildFindingWhere(f FindingFilter) (string, []any) {
	clauses := []string{"tenant_id = ?"}
	args := []any{f.TenantID}

	if f.Severity != nil {
		clauses = append(clauses, "severity = ?")
		args = append(args, *f.Severity)
	}
	if f.Category != nil {
		clauses = append(clauses, "category = ?")
		args = append(args, *f.Category)
	}
	if f.RuleID != nil {
		clauses = append(clauses, "rule_id = ?")
		args = append(args, *f.RuleID)
	}
	if f.UserID != nil {
		clauses = append(clauses, "user_id = ?")
		args = append(args, *f.UserID)
	}
	if f.Since != nil {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, *f.Until)
	}

	return "WHERE " + strings.Join(clauses, " AND "), args
}
