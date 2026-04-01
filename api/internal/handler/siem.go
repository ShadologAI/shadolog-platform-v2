package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// SIEMHandler exports findings in SIEM-native formats.
type SIEMHandler struct {
	ch *store.CHStore
}

// NewSIEMHandler creates a SIEMHandler.
func NewSIEMHandler(ch *store.CHStore) *SIEMHandler {
	return &SIEMHandler{ch: ch}
}

// parseSIEMFilter extracts common query params for SIEM export endpoints.
func parseSIEMFilter(r *http.Request, tenantID string) store.FindingFilter {
	f := store.FindingFilter{
		TenantID: tenantID,
	}

	if v := r.URL.Query().Get("severity"); v != "" {
		f.Severity = &v
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

	f.Limit = 1000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
			f.Limit = n
		}
	}

	return f
}

// Splunk handles GET /api/siem/splunk.
// Returns findings formatted as Splunk HTTP Event Collector (HEC) JSON events.
func (h *SIEMHandler) Splunk(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := parseSIEMFilter(r, tenantID)
	findings, _, err := h.ch.ListFindings(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	events := make([]map[string]any, 0, len(findings))
	for _, fd := range findings {
		events = append(events, map[string]any{
			"time":       fd.Timestamp.Unix(),
			"sourcetype": "shadolog:finding",
			"source":     "shadolog-api",
			"host":       "shadolog",
			"event": map[string]any{
				"finding_id":       fd.FindingID,
				"event_id":         fd.EventID,
				"tenant_id":        fd.TenantID,
				"rule_id":          fd.RuleID,
				"severity":         fd.Severity,
				"category":         fd.Category,
				"detector":         fd.Detector,
				"confidence":       fd.Confidence,
				"framework":        fd.Framework,
				"control_id":       fd.ControlID,
				"redacted_preview": fd.RedactedPreview,
				"user_id":          fd.UserID,
				"ai_tool":          fd.AITool,
				"action_taken":     fd.ActionTaken,
			},
		})
	}

	auth.WriteJSON(w, http.StatusOK, events)
}

// Sentinel handles GET /api/siem/sentinel.
// Returns findings formatted as Microsoft Sentinel Log Analytics custom log records.
func (h *SIEMHandler) Sentinel(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := parseSIEMFilter(r, tenantID)
	findings, _, err := h.ch.ListFindings(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	records := make([]map[string]any, 0, len(findings))
	for _, fd := range findings {
		records = append(records, map[string]any{
			"TimeGenerated":   fd.Timestamp.Format(time.RFC3339),
			"Severity":        fd.Severity,
			"Category":        fd.Category,
			"FindingID":       fd.FindingID,
			"EventID":         fd.EventID,
			"TenantID":        fd.TenantID,
			"RuleID":          fd.RuleID,
			"Detector":        fd.Detector,
			"Confidence":      fd.Confidence,
			"Framework":       fd.Framework,
			"ControlID":       fd.ControlID,
			"RedactedPreview": fd.RedactedPreview,
			"UserID":          fd.UserID,
			"AITool":          fd.AITool,
			"ActionTaken":     fd.ActionTaken,
			"SourceSystem":    "Shadolog",
		})
	}

	auth.WriteJSON(w, http.StatusOK, records)
}
