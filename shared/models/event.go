// Package models defines canonical data types shared across all v2 services.
package models

import (
	"encoding/json"
	"time"
)

// Event is the canonical event type for the v2 platform.
// Published by Gateway, consumed by Brain, stored in ClickHouse.
type Event struct {
	EventID       string          `json:"event_id"`
	TenantID      string          `json:"tenant_id"`
	Timestamp     time.Time       `json:"timestamp"`
	EventType     string          `json:"event_type"`
	AITool        string          `json:"ai_tool"`
	AIModel       string          `json:"ai_model"`
	Direction     string          `json:"direction"` // prompt, response, unknown
	UserID        string          `json:"user_id"`
	SessionID     string          `json:"session_id"`
	ContentHash   string          `json:"content_hash"`
	ContentLength uint32          `json:"content_length"`
	AgentType     string          `json:"agent_type"`
	AgentID       string          `json:"agent_id"`
	SourceIP      string          `json:"source_ip,omitempty"`
	URL           string          `json:"url,omitempty"`
	Hostname      string          `json:"hostname,omitempty"`
	EntityID      string          `json:"entity_id,omitempty"`
	EntityType    string          `json:"entity_type,omitempty"`
	MCPServerURL  string          `json:"mcp_server_url,omitempty"`
	MCPToolName   string          `json:"mcp_tool_name,omitempty"`
	MCPMethod     string          `json:"mcp_method,omitempty"`
	SecrecyLabel  string          `json:"secrecy_label,omitempty"`
	IntegrityLabel string         `json:"integrity_label,omitempty"`
	DataCategories []string       `json:"data_categories,omitempty"`
	SourcePlane   string          `json:"source_plane,omitempty"`
	HookTool      string          `json:"hook_tool,omitempty"`
	HookEvent     string          `json:"hook_event,omitempty"`
	RawContent    string          `json:"raw_content,omitempty"` // Never persisted; in-memory only
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// Finding is the canonical finding type for the v2 platform.
type Finding struct {
	FindingID       string          `json:"finding_id"`
	EventID         string          `json:"event_id"`
	TenantID        string          `json:"tenant_id"`
	Timestamp       time.Time       `json:"timestamp"`
	RuleID          string          `json:"rule_id"`
	Severity        string          `json:"severity"` // critical, high, medium, low, info
	Category        string          `json:"category"` // pii, credential, injection, anomaly, etc.
	Detector        string          `json:"detector"`
	Confidence      float32         `json:"confidence"`
	ActionTaken     string          `json:"action_taken"` // allow, block, redact, log
	Narrative       string          `json:"narrative,omitempty"`
	ImpactSummary   string          `json:"impact_summary,omitempty"`
	Recommendation  string          `json:"recommendation,omitempty"`
	Framework       string          `json:"framework,omitempty"`
	ControlID       string          `json:"control_id,omitempty"`
	OwaspIDs        []string        `json:"owasp_ids,omitempty"`
	MitreIDs        []string        `json:"mitre_ids,omitempty"`
	EntityID        string          `json:"entity_id,omitempty"`
	AgentID         string          `json:"agent_id,omitempty"`
	RedactedPreview string          `json:"redacted_preview,omitempty"`
	UserID          string          `json:"user_id,omitempty"`
	AITool          string          `json:"ai_tool,omitempty"`
	DataCategories  []string        `json:"data_categories,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
}

// Entity is the canonical unified entity type.
type Entity struct {
	EntityID    string          `json:"entity_id"`
	TenantID    string          `json:"tenant_id"`
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Metadata    json.RawMessage `json:"metadata"`
	RiskScore   int16           `json:"risk_score"`
	Status      string          `json:"status"`
	SourcePlane string          `json:"source_plane,omitempty"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
}

// Receipt is the canonical Ed25519-signed audit receipt.
type Receipt struct {
	ReceiptID    string          `json:"receipt_id"`
	TenantID     string          `json:"tenant_id"`
	FindingID    string          `json:"finding_id,omitempty"`
	EventID      string          `json:"event_id"`
	Decision     string          `json:"decision"`
	RuleID       string          `json:"rule_id,omitempty"`
	PrevHash     string          `json:"prev_hash"`
	ReceiptHash  string          `json:"receipt_hash"`
	SequenceNum  int64           `json:"sequence_num"`
	Signature    []byte          `json:"signature"`
	SigningKeyID string          `json:"signing_key_id"`
	SignedPayload json.RawMessage `json:"signed_payload"`
	CreatedAt    time.Time       `json:"created_at"`
}
