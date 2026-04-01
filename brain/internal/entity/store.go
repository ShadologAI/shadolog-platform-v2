// Package entity provides entity and relationship persistence for the Brain service.
// Entities (user, agent, tool, mcp_server, ai_provider) and their relationships
// power the Map view's correlation chain visualization.
package entity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists entities and relationships to PostgreSQL.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewStore creates a new entity store.
func NewStore(pool *pgxpool.Pool, logger *slog.Logger) *Store {
	return &Store{pool: pool, logger: logger}
}

// UpsertEntity creates or updates a unified entity, returning the entity_id.
func (s *Store) UpsertEntity(ctx context.Context, tenantID, entityType, name string, metadata map[string]any, riskScore int16, sourcePlane string) (string, error) {
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}

	var entityID string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO entities (tenant_id, type, name, metadata, risk_score, status, source_plane)
		 VALUES ($1, $2, $3, $4, $5, 'active', $6)
		 ON CONFLICT (tenant_id, type, name) DO UPDATE SET
		     metadata = EXCLUDED.metadata,
		     risk_score = CASE WHEN EXCLUDED.risk_score > entities.risk_score THEN EXCLUDED.risk_score ELSE entities.risk_score END,
		     source_plane = EXCLUDED.source_plane,
		     last_seen_at = now()
		 RETURNING entity_id::text`,
		tenantID, entityType, name, metaJSON, riskScore, sourcePlane,
	).Scan(&entityID)
	if err != nil {
		return "", fmt.Errorf("upsert entity (%s/%s): %w", entityType, name, err)
	}
	return entityID, nil
}

// UpsertRelationship creates or updates a relationship between two entities.
func (s *Store) UpsertRelationship(ctx context.Context, tenantID, sourceID, targetID, relType, riskLevel string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO relationships (tenant_id, source_id, target_id, type, risk_level, metadata, request_count)
		 VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, 1)
		 ON CONFLICT (tenant_id, source_id, target_id, type) DO UPDATE SET
		     risk_level = CASE
		         WHEN EXCLUDED.risk_level = 'critical' THEN 'critical'
		         WHEN EXCLUDED.risk_level = 'high' AND relationships.risk_level NOT IN ('critical') THEN 'high'
		         ELSE relationships.risk_level
		     END,
		     metadata = relationships.metadata || EXCLUDED.metadata,
		     request_count = relationships.request_count + 1,
		     last_seen_at = now()`,
		tenantID, sourceID, targetID, relType, riskLevel, metaJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert relationship: %w", err)
	}
	return nil
}

// ClassifyAITool categorizes a tool name into a type for display.
func ClassifyAITool(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "copilot") || strings.Contains(n, "cursor") || strings.Contains(n, "continue"):
		return "ide_extension"
	case strings.Contains(n, "chatgpt") || strings.Contains(n, "claude.ai") || strings.Contains(n, "gemini") || strings.Contains(n, "perplexity"):
		return "web_app"
	case strings.Contains(n, "claude_code") || strings.Contains(n, "codex"):
		return "cli_tool"
	case strings.Contains(n, "ollama") || strings.Contains(n, "lmstudio"):
		return "local_model"
	case strings.Contains(n, "vscode"):
		return "ide"
	default:
		return "unknown"
	}
}

// ExtractProvider maps domain names to provider names.
func ExtractProvider(urlOrDomain string) string {
	providers := map[string]string{
		"openai.com":              "openai",
		"anthropic.com":           "anthropic",
		"googleapis.com":          "google",
		"github.com":              "github",
		"githubcopilot.com":       "github",
		"cursor.sh":               "cursor",
		"mistral.ai":              "mistral",
		"deepseek.com":            "deepseek",
		"cohere.ai":               "cohere",
		"together.xyz":            "together",
		"fireworks.ai":            "fireworks",
		"groq.com":                "groq",
		"perplexity.ai":           "perplexity",
		"amazonaws.com":           "aws_bedrock",
		"claude.ai":               "anthropic",
		"chat.openai.com":         "openai",
		"chatgpt.com":             "openai",
		"gemini.google.com":       "google",
		"copilot.microsoft.com":   "openai",
	}

	for domain, provider := range providers {
		if strings.Contains(urlOrDomain, domain) {
			return provider
		}
	}
	return ""
}

// ExtractDataSink identifies data sink destinations from network connections.
// Returns sink name and risk score, or empty string if not a known data sink.
func ExtractDataSink(urlOrDomain string) (string, int16) {
	sinks := map[string]struct {
		name  string
		risk  int16
	}{
		"pastebin.com":        {"External Pastebin", 80},
		"hastebin.com":        {"External Pastebin", 80},
		"gist.github.com":     {"GitHub Gists", 40},
		"github.com":          {"GitHub Repos", 20},
		"gitlab.com":          {"GitLab Repos", 20},
		"bitbucket.org":       {"Bitbucket Repos", 20},
		"slack.com":           {"Slack", 30},
		"discord.com":         {"Discord", 50},
		"webhook.site":        {"Webhook Testing", 70},
		"pipedream.com":       {"Pipedream Webhook", 60},
		"requestbin.com":      {"Request Bin", 70},
		"s3.amazonaws.com":    {"AWS S3", 30},
		"blob.core.windows.net": {"Azure Blob", 30},
		"storage.googleapis.com": {"GCS", 30},
		"notion.so":           {"Notion", 20},
		"airtable.com":        {"Airtable", 30},
		"docs.google.com":     {"Google Docs", 20},
		"drive.google.com":    {"Google Drive", 20},
	}

	for domain, sink := range sinks {
		if strings.Contains(urlOrDomain, domain) {
			return sink.name, sink.risk
		}
	}
	return "", 0
}

// MCPSourceToAgentKey maps MCP discovery source strings to agent keys.
func MCPSourceToAgentKey(source string) string {
	mapping := map[string]string{
		"claude_code_user":    "claude_code",
		"claude_code_project": "claude_code",
		"claude_desktop":      "claude_desktop",
		"cursor_global":       "cursor",
		"windsurf_global":     "windsurf",
		"vscode_user":         "vscode",
		"vscode_workspace":    "vscode",
		"roo_workspace":       "vscode",
		"project_root":        "project",
		"gemini_cli":          "gemini_cli",
		"generic_home":        "unknown",
	}
	if key, ok := mapping[source]; ok {
		return key
	}
	return ""
}
