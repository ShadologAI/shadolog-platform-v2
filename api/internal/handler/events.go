package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// EventHandler proxies event queries to ClickHouse.
type EventHandler struct {
	ch *store.CHStore
}

// NewEventHandler creates an EventHandler.
func NewEventHandler(ch *store.CHStore) *EventHandler {
	return &EventHandler{ch: ch}
}

// List handles GET /api/events.
func (h *EventHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := store.EventFilter{
		TenantID: tenantID,
	}

	if v := r.URL.Query().Get("event_type"); v != "" {
		f.EventType = &v
	}
	if v := r.URL.Query().Get("ai_tool"); v != "" {
		f.AITool = &v
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		f.UserID = &v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	events, total, err := h.ch.ListEvents(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []store.Event{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Event]{Data: events, Total: total})
}

// FindingHandler proxies finding queries to ClickHouse.
type FindingHandler struct {
	ch *store.CHStore
}

// NewFindingHandler creates a FindingHandler.
func NewFindingHandler(ch *store.CHStore) *FindingHandler {
	return &FindingHandler{ch: ch}
}

// List handles GET /api/findings.
func (h *FindingHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := store.FindingFilter{
		TenantID: tenantID,
	}

	if v := r.URL.Query().Get("severity"); v != "" {
		f.Severity = &v
	}
	if v := r.URL.Query().Get("category"); v != "" {
		f.Category = &v
	}
	if v := r.URL.Query().Get("rule_id"); v != "" {
		f.RuleID = &v
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		f.UserID = &v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	findings, total, err := h.ch.ListFindings(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if findings == nil {
		findings = []store.Finding{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Finding]{Data: findings, Total: total})
}

// BySeverity handles GET /api/findings/by-severity.
func (h *FindingHandler) BySeverity(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	counts, err := h.ch.FindingsBySeverity(r.Context(), tenantID)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if counts == nil {
		counts = []store.SeverityCount{}
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"data": counts})
}
