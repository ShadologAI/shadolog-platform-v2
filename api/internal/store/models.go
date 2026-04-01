// Package store provides data access for the v4 API service.
package store

import (
	"encoding/json"
	"time"
)

// --- Postgres-backed models ---

// Tenant represents a tenant row from PostgreSQL.
type Tenant struct {
	TenantID          string    `json:"tenant_id"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	Tier              string    `json:"tier"`
	CloudProvider     *string   `json:"cloud_provider,omitempty"`
	Region            *string   `json:"region,omitempty"`
	Status            string    `json:"status"`
	DataPlaneStatus   string    `json:"data_plane_status"`
	DataPlaneEndpoint *string   `json:"data_plane_endpoint,omitempty"`
	EnforcementMode   string    `json:"enforcement_mode"`
	EnabledPacks      []string  `json:"enabled_packs"`
	OnboardingStep    int       `json:"onboarding_step"`
	FirebaseUID       *string   `json:"firebase_uid,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateTenantRequest is the body for POST /api/tenants.
type CreateTenantRequest struct {
	Slug          string   `json:"slug"`
	Name          string   `json:"name"`
	Tier          string   `json:"tier"`
	CloudProvider *string  `json:"cloud_provider,omitempty"`
	Region        *string  `json:"region,omitempty"`
	EnabledPacks  []string `json:"enabled_packs,omitempty"`
	FirebaseUID   *string  `json:"firebase_uid,omitempty"`
}

// --- ClickHouse-backed models ---

// Event represents a row from the ClickHouse events table.
type Event struct {
	EventID       string    `json:"event_id"`
	TenantID      string    `json:"tenant_id"`
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	AITool        string    `json:"ai_tool"`
	AIModel       string    `json:"ai_model"`
	Direction     string    `json:"direction"`
	ContentLength uint32    `json:"content_length"`
	UserID        string    `json:"user_id"`
	SessionID     string    `json:"session_id"`
	AgentID       string    `json:"agent_id"`
	AgentType     string    `json:"agent_type"`
	SourceURL     string    `json:"source_url,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	IngestedAt    time.Time `json:"ingested_at"`
}

// EventFilter holds query parameters for listing events.
type EventFilter struct {
	TenantID  string
	EventType *string
	AITool    *string
	UserID    *string
	Since     *time.Time
	Until     *time.Time
	Limit     int
	Offset    int
}

// Finding represents a row from the ClickHouse findings table.
type Finding struct {
	FindingID       string    `json:"finding_id"`
	EventID         string    `json:"event_id"`
	TenantID        string    `json:"tenant_id"`
	Timestamp       time.Time `json:"timestamp"`
	RuleID          string    `json:"rule_id"`
	Severity        string    `json:"severity"`
	Category        string    `json:"category"`
	Detector        string    `json:"detector"`
	Confidence      float32   `json:"confidence"`
	Framework       string    `json:"framework,omitempty"`
	ControlID       string    `json:"control_id,omitempty"`
	RedactedPreview string    `json:"redacted_preview,omitempty"`
	UserID          string    `json:"user_id"`
	AITool          string    `json:"ai_tool"`
	ActionTaken     string    `json:"action_taken"`
}

// FindingFilter holds query parameters for listing findings.
type FindingFilter struct {
	TenantID string
	Severity *string
	Category *string
	RuleID   *string
	UserID   *string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

// SeverityCount is a severity label + count pair.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    uint64 `json:"count"`
}

// TimelinePoint is a time bucket + count pair.
type TimelinePoint struct {
	Bucket string `json:"bucket"`
	Count  uint64 `json:"count"`
}

// --- Unified entity models ---

// Entity represents a unified entity in the graph.
type Entity struct {
	EntityID    string          `json:"entity_id"`
	TenantID    string          `json:"tenant_id"`
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Metadata    json.RawMessage `json:"metadata"`
	RiskScore   int16           `json:"risk_score"`
	Status      string          `json:"status"`
	SourcePlane *string         `json:"source_plane,omitempty"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
}

// EntityFilter holds query parameters for listing entities.
type EntityFilter struct {
	TenantID    string
	Type        *string
	Status      *string
	SourcePlane *string
	MinRisk     *int16
	Limit       int
	Offset      int
}

// Relationship represents a directed edge between two entities.
type Relationship struct {
	RelationshipID string          `json:"relationship_id"`
	TenantID       string          `json:"tenant_id"`
	SourceID       string          `json:"source_id"`
	TargetID       string          `json:"target_id"`
	Type           string          `json:"type"`
	Metadata       json.RawMessage `json:"metadata"`
	RequestCount   int64           `json:"request_count"`
	RiskLevel      string          `json:"risk_level"`
	FirstSeenAt    time.Time       `json:"first_seen_at"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
}

// RelationshipFilter holds query parameters for listing relationships.
type RelationshipFilter struct {
	TenantID  string
	SourceID  *string
	TargetID  *string
	EntityID  *string // matches either source_id or target_id
	Type      *string
	RiskLevel *string
	Limit     int
	Offset    int
}

// --- Graph response models (backward compat with v3 dashboard) ---

// GraphResponse is the combined response for GET /api/graph.
type GraphResponse struct {
	Entities      []Entity       `json:"entities"`
	Relationships []Relationship `json:"relationships"`
}

// --- Policy models ---

// Policy represents a tenant policy row from PostgreSQL.
type Policy struct {
	PolicyID    string          `json:"policy_id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	PolicyType  string          `json:"policy_type"`
	Enforcement string          `json:"enforcement"`
	Rules       json.RawMessage `json:"rules"`
	Severity    string          `json:"severity"`
	Enabled     bool            `json:"enabled"`
	OwaspIDs    []string        `json:"owasp_ids"`
	MitreIDs    []string        `json:"mitre_ids"`
	CreatedBy   *string         `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// PolicyFilter holds query parameters for listing policies.
type PolicyFilter struct {
	TenantID    string
	PolicyType  *string
	Enforcement *string
	Severity    *string
	Enabled     *bool
	Limit       int
	Offset      int
}

// CreatePolicyRequest is the body for POST /api/policies.
type CreatePolicyRequest struct {
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	PolicyType  string          `json:"policy_type"`
	Enforcement string          `json:"enforcement"`
	Rules       json.RawMessage `json:"rules"`
	Severity    string          `json:"severity,omitempty"`
	OwaspIDs    []string        `json:"owasp_ids,omitempty"`
	MitreIDs    []string        `json:"mitre_ids,omitempty"`
}

// UpdatePolicyRequest is the body for PATCH /api/policies/{id}.
type UpdatePolicyRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Enforcement *string         `json:"enforcement,omitempty"`
	Rules       json.RawMessage `json:"rules,omitempty"`
	Severity    *string         `json:"severity,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
	OwaspIDs    []string        `json:"owasp_ids,omitempty"`
	MitreIDs    []string        `json:"mitre_ids,omitempty"`
}

// PolicyVersion represents a snapshot of a policy at a point in time.
type PolicyVersion struct {
	VersionID     string          `json:"version_id"`
	PolicyID      string          `json:"policy_id"`
	TenantID      string          `json:"tenant_id"`
	VersionNumber int             `json:"version_number"`
	Name          string          `json:"name"`
	Description   *string         `json:"description,omitempty"`
	PolicyType    string          `json:"policy_type"`
	Enforcement   string          `json:"enforcement"`
	Rules         json.RawMessage `json:"rules"`
	Severity      string          `json:"severity"`
	Enabled       bool            `json:"enabled"`
	OwaspIDs      []string        `json:"owasp_ids"`
	MitreIDs      []string        `json:"mitre_ids"`
	ChangeSummary *string         `json:"change_summary,omitempty"`
	ChangedBy     *string         `json:"changed_by,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// --- Audit / PROVE models ---

// Receipt represents an Ed25519-signed audit receipt in the hash chain.
type Receipt struct {
	ReceiptID    string    `json:"receipt_id"`
	TenantID     string    `json:"tenant_id"`
	EventID      string    `json:"event_id"`
	Decision     string    `json:"decision"`
	RuleID       string    `json:"rule_id"`
	PrevHash     string    `json:"prev_hash"`
	ReceiptHash  string    `json:"receipt_hash"`
	Signature    []byte    `json:"signature"`
	SigningKeyID string    `json:"signing_key_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// ReceiptFilter holds query parameters for listing receipts.
type ReceiptFilter struct {
	TenantID string
	EventID  *string
	Decision *string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

// ChainBreak records a detected integrity break in the receipt chain.
type ChainBreak struct {
	ReceiptID        string    `json:"receipt_id"`
	ExpectedPrevHash string    `json:"expected_prev_hash"`
	ActualPrevHash   string    `json:"actual_prev_hash"`
	DetectedAt       time.Time `json:"detected_at"`
}

// VerifyResult is the response for chain verification.
type VerifyResult struct {
	ChainValid      bool         `json:"chain_valid"`
	ReceiptsChecked int64        `json:"receipts_checked"`
	ReceiptsValid   int64        `json:"receipts_valid"`
	Breaks          []ChainBreak `json:"breaks,omitempty"`
}

// ComplianceReport represents a generated compliance report.
type ComplianceReport struct {
	ReportID    string    `json:"report_id"`
	TenantID    string    `json:"tenant_id"`
	ReportType  string    `json:"report_type"`
	Framework   string    `json:"framework"`
	Status      string    `json:"status"`
	Summary     *string   `json:"summary,omitempty"`
	GeneratedBy *string   `json:"generated_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// --- Envelope ---

// ListResponse is a generic paginated list response.
type ListResponse[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
}
