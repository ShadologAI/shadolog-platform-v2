package pipeline

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// IngestRequest is the JSON body for POST /v1/events.
type IngestRequest struct {
	EventID   string                 `json:"event_id"`
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Provider  string                 `json:"provider"`
	EventType string                 `json:"event_type"`
	TenantID  string                 `json:"tenant_id"`
	SessionID string                 `json:"session_id"`
	Content   map[string]interface{} `json:"content"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// BatchRequest wraps multiple events.
type BatchRequest struct {
	Events []IngestRequest `json:"events"`
}

// ValidEventTypes lists allowed event_type values matching ClickHouse Enum8.
var ValidEventTypes = map[string]bool{
	"ai_interaction":  true,
	"process_exec":    true,
	"network_connect": true,
	"file_access":     true,
	"ssl_intercept":   true,
	"hook_bridge":     true,
	"dns_query":       true,
}

// ARGUSEventTypes are ARGUS inventory event types that get transformed to
// ai_interaction for ClickHouse but retain their original type in NATS
// metadata for Brain entity resolution.
var ARGUSEventTypes = map[string]bool{
	"endpoint_inventory":        true,
	"endpoint_forensic_session": true,
	"endpoint_mcp_inventory":    true,
	"endpoint_permission_map":   true,
	"endpoint_browser_history":     true,
	"endpoint_forensic_browser":    true,
	"endpoint_forensic_permission": true,
	"endpoint_session_summary":     true,
	"endpoint_telemetry":              true,
	"endpoint_desktop_conversation":   true,
}

// Validate checks required fields on an ingest request and returns a normalized Event.
func Validate(req *IngestRequest, tenantID string) (*models.Event, error) {
	if req.EventID == "" {
		req.EventID = newUUID()
	}

	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		ts = time.Now().UTC()
	}

	eventType := req.EventType
	if eventType == "" {
		eventType = "ai_interaction"
	}
	if !ValidEventTypes[eventType] {
		return nil, fmt.Errorf("invalid event_type: %s", eventType)
	}

	direction := "unknown"
	if req.Content != nil {
		if _, ok := req.Content["prompt"]; ok {
			direction = "prompt"
		} else if _, ok := req.Content["response"]; ok {
			direction = "response"
		}
	}

	aiTool := ""
	aiModel := ""
	if req.Provider != "" {
		aiTool = req.Provider
	}
	if req.Content != nil {
		if m, ok := req.Content["model"].(string); ok {
			aiModel = m
		}
	}

	// Serialize content map for DLP scanning downstream.
	var rawContent string
	if req.Content != nil {
		if b, err := json.Marshal(req.Content); err == nil {
			rawContent = string(b)
		}
	}

	var contentLen uint32
	if rawContent != "" {
		contentLen = uint32(len(rawContent))
	}

	// Extract user_id from metadata (extension sends actor.user_id, hooks send user_id)
	userID := ""
	if req.Metadata != nil {
		if actor, ok := req.Metadata["actor"].(map[string]any); ok {
			if uid, ok := actor["user_id"].(string); ok && uid != "" {
				userID = uid
			}
		}
		if userID == "" {
			if uid, ok := req.Metadata["user_id"].(string); ok && uid != "" {
				userID = uid
			}
		}
	}

	// Extract URL from metadata
	eventURL := ""
	if req.Metadata != nil {
		if u, ok := req.Metadata["url"].(string); ok && u != "" {
			eventURL = u
		}
	}

	// Extract agent_id from metadata
	agentID := ""
	if req.Metadata != nil {
		if aid, ok := req.Metadata["agent_id"].(string); ok && aid != "" {
			agentID = aid
		}
		if agentID == "" {
			if fp, ok := req.Metadata["device_fingerprint"].(string); ok && fp != "" {
				agentID = fp
			}
		}
	}

	// Serialize metadata for downstream processing (entity resolver reads original_event_type)
	var metadataJSON json.RawMessage
	if req.Metadata != nil {
		if b, err := json.Marshal(req.Metadata); err == nil {
			metadataJSON = b
		}
	}

	return &models.Event{
		EventID:       req.EventID,
		TenantID:      tenantID,
		Timestamp:     ts,
		EventType:     eventType,
		AITool:        aiTool,
		AIModel:       aiModel,
		Direction:     direction,
		UserID:        userID,
		SessionID:     req.SessionID,
		ContentHash:   "",
		ContentLength: contentLen,
		AgentType:     req.Source,
		AgentID:       agentID,
		SourceIP:      "",
		URL:           eventURL,
		RawContent:    rawContent,
		Metadata:      metadataJSON,
	}, nil
}

// newUUID generates a v4 UUID using crypto/rand (no external dependency).
func newUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
