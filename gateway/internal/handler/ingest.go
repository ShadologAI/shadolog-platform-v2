// Package handler provides HTTP handlers for the v4 Gateway event ingestion.
//
// Three endpoints:
//   - POST /v1/events       -- single event ingestion
//   - POST /v1/events/batch -- batch ingestion (max 100 events, 5MB payload)
//   - POST /v1/argus/events -- ARGUS sensor events (transforms to canonical format)
//
// All endpoints are protected by API key middleware. Auth is fail-closed:
// if pgPool is nil and dev mode is off, the middleware rejects all requests.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/shadologai/shadolog/v2/gateway/internal/auth"
	"github.com/shadologai/shadolog/v2/gateway/internal/pipeline"
)

const (
	maxBatchSize   = 100
	maxPayloadSize = 5 * 1024 * 1024 // 5MB
)

// IngestHandler holds dependencies for event ingestion endpoints.
type IngestHandler struct {
	batcher *pipeline.Batcher
	logger  *slog.Logger
}

// NewIngestHandler creates a handler wired to the given batcher.
func NewIngestHandler(batcher *pipeline.Batcher, logger *slog.Logger) *IngestHandler {
	return &IngestHandler{batcher: batcher, logger: logger}
}

// HandleEvent handles POST /v1/events -- single event ingestion.
func (h *IngestHandler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		http.Error(w, `{"error":"tenant_id is required"}`, http.StatusBadRequest)
		return
	}

	// Enforce 5MB payload limit
	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadSize)

	var req pipeline.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	event, err := pipeline.Validate(&req, tenantID)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Capture source IP from request
	event.SourceIP = r.RemoteAddr

	h.batcher.Add(event)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "accepted",
		"event_id": event.EventID,
	})
}

// HandleBatch handles POST /v1/events/batch -- batch event ingestion.
// Validates batch size <= 100 and payload <= 5MB (fixes v3 O4).
func (h *IngestHandler) HandleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		http.Error(w, `{"error":"tenant_id is required"}`, http.StatusBadRequest)
		return
	}

	// Enforce 5MB payload limit (fixes O4)
	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadSize)

	var req pipeline.BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON or payload exceeds 5MB"}`, http.StatusBadRequest)
		return
	}

	// Enforce batch size limit (fixes O4)
	if len(req.Events) > maxBatchSize {
		http.Error(w, `{"error":"batch size exceeds 100"}`, http.StatusBadRequest)
		return
	}

	accepted := 0
	for i := range req.Events {
		event, err := pipeline.Validate(&req.Events[i], tenantID)
		if err != nil {
			h.logger.Warn("skip invalid event in batch", "index", i, "error", err)
			continue
		}
		event.SourceIP = r.RemoteAddr
		h.batcher.Add(event)
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "accepted",
		"accepted": accepted,
		"rejected": len(req.Events) - accepted,
	})
}

// HandleARGUS handles POST /v1/argus/events -- ARGUS sensor event ingestion.
// Transforms ARGUS-specific event structure to canonical Gateway format.
func (h *IngestHandler) HandleARGUS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		http.Error(w, `{"error":"tenant_id is required"}`, http.StatusBadRequest)
		return
	}

	// Enforce 5MB payload limit
	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadSize)

	var argusPayload struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&argusPayload); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	accepted := 0
	for _, raw := range argusPayload.Events {
		var argusEvent struct {
			EventID     string `json:"event_id"`
			SourcePlane string `json:"source_plane"`
			EventType   string `json:"event_type"`
			Timestamp   string `json:"timestamp"`
			Actor       struct {
				UserID    string `json:"user_id"`
				ActorType string `json:"actor_type"`
			} `json:"actor"`
			AI struct {
				Service string `json:"service"`
				Model   string `json:"model"`
			} `json:"ai"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(raw, &argusEvent); err != nil {
			h.logger.Warn("skip invalid ARGUS event", "error", err)
			continue
		}

		// Determine ClickHouse event_type: ARGUS inventory types -> ai_interaction
		chEventType := argusEvent.EventType
		originalType := argusEvent.EventType
		if pipeline.ARGUSEventTypes[chEventType] {
			chEventType = "ai_interaction"
		}

		// Build content map from raw JSON
		var contentMap map[string]interface{}
		if argusEvent.Content != nil {
			json.Unmarshal(argusEvent.Content, &contentMap)
		}
		if contentMap == nil {
			contentMap = make(map[string]interface{})
		}

		// Transform to canonical IngestRequest format
		req := &pipeline.IngestRequest{
			EventID:   argusEvent.EventID,
			Timestamp: argusEvent.Timestamp,
			Source:    argusEvent.SourcePlane,
			Provider:  argusEvent.AI.Service,
			EventType: chEventType,
			SessionID: "",
			Content:   contentMap,
			Metadata: map[string]interface{}{
				"actor": map[string]interface{}{
					"user_id":    argusEvent.Actor.UserID,
					"actor_type": argusEvent.Actor.ActorType,
				},
				"original_event_type": originalType,
				"ai_service":          argusEvent.AI.Service,
				"ai_model":            argusEvent.AI.Model,
				"source_plane":        argusEvent.SourcePlane,
			},
		}

		event, err := pipeline.Validate(req, tenantID)
		if err != nil {
			h.logger.Warn("skip invalid ARGUS event", "event_type", originalType, "error", err)
			continue
		}

		// Override fields the validator couldn't extract from the flat format
		if event.AITool == "" && argusEvent.AI.Service != "" {
			event.AITool = argusEvent.AI.Service
		}
		if event.AIModel == "" && argusEvent.AI.Model != "" {
			event.AIModel = argusEvent.AI.Model
		}
		if event.UserID == "" && argusEvent.Actor.UserID != "" {
			event.UserID = argusEvent.Actor.UserID
		}
		if event.AgentType == "" && argusEvent.SourcePlane != "" {
			event.AgentType = argusEvent.SourcePlane
		}
		event.SourceIP = r.RemoteAddr

		h.batcher.Add(event)
		accepted++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "accepted",
		"accepted": accepted,
		"total":    len(argusPayload.Events),
	})
}
