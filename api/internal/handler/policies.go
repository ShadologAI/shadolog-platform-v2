package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// PolicyHandler serves CRUD for tenant detection/enforcement policies.
type PolicyHandler struct {
	pg *store.PGStore
}

// NewPolicyHandler creates a PolicyHandler.
func NewPolicyHandler(pg *store.PGStore) *PolicyHandler {
	return &PolicyHandler{pg: pg}
}

// List handles GET /api/policies — list policies with filters (tenant scoped).
func (h *PolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := store.PolicyFilter{
		TenantID: tenantID,
	}
	if v := r.URL.Query().Get("policy_type"); v != "" {
		f.PolicyType = &v
	}
	if v := r.URL.Query().Get("enforcement"); v != "" {
		f.Enforcement = &v
	}
	if v := r.URL.Query().Get("enabled"); v != "" {
		b := v == "true"
		f.Enabled = &b
	}
	if v := r.URL.Query().Get("severity"); v != "" {
		f.Severity = &v
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	policies, total, err := h.pg.ListPolicies(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if policies == nil {
		policies = []store.Policy{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Policy]{Data: policies, Total: total})
}

// Get handles GET /api/policies/{id}.
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	policyID := chi.URLParam(r, "id")
	policy, err := h.pg.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if policy == nil {
		auth.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
		return
	}
	auth.WriteJSON(w, http.StatusOK, policy)
}

// Create handles POST /api/policies.
func (h *PolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	var req store.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" || req.PolicyType == "" || req.Enforcement == "" {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "name, policy_type, and enforcement are required"})
		return
	}

	userID := auth.UserFromContext(r.Context())
	policy, err := h.pg.CreatePolicy(r.Context(), tenantID, &req, userID)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusCreated, policy)
}

// Update handles PATCH /api/policies/{id}.
func (h *PolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	policyID := chi.URLParam(r, "id")
	var req store.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if err := h.pg.UpdatePolicy(r.Context(), tenantID, policyID, &req); err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// Delete handles DELETE /api/policies/{id}.
func (h *PolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	policyID := chi.URLParam(r, "id")
	if err := h.pg.DeletePolicy(r.Context(), tenantID, policyID); err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Versions handles GET /api/policies/versions — policy version history.
func (h *PolicyHandler) Versions(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	versions, total, err := h.pg.ListPolicyVersions(r.Context(), tenantID, policyID, limit, offset)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if versions == nil {
		versions = []store.PolicyVersion{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.PolicyVersion]{Data: versions, Total: total})
}

// DLPLibrary handles GET /api/policies/dlp-library — returns built-in DLP entity types.
func (h *PolicyHandler) DLPLibrary(w http.ResponseWriter, r *http.Request) {
	library := []map[string]any{
		{"id": "pii_email", "name": "Email Address", "category": "pii", "severity": "medium", "pattern": `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
		{"id": "pii_ssn", "name": "Social Security Number", "category": "pii", "severity": "critical", "pattern": `\b\d{3}-\d{2}-\d{4}\b`},
		{"id": "pii_phone", "name": "Phone Number", "category": "pii", "severity": "medium", "pattern": `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`},
		{"id": "cred_api_key", "name": "API Key", "category": "credentials", "severity": "critical", "pattern": `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9_-]{20,}`},
		{"id": "cred_jwt", "name": "JWT Token", "category": "credentials", "severity": "high", "pattern": `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`},
		{"id": "cred_aws_key", "name": "AWS Access Key", "category": "credentials", "severity": "critical", "pattern": `AKIA[0-9A-Z]{16}`},
		{"id": "cred_private_key", "name": "Private Key", "category": "credentials", "severity": "critical", "pattern": `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`},
		{"id": "fin_credit_card", "name": "Credit Card Number", "category": "financial", "severity": "critical", "pattern": `\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b`},
		{"id": "fin_iban", "name": "IBAN", "category": "financial", "severity": "high", "pattern": `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b`},
		{"id": "health_mrn", "name": "Medical Record Number", "category": "health", "severity": "critical", "pattern": `(?i)MRN\s*[:=]?\s*\d{6,10}`},
		{"id": "code_connection_string", "name": "Connection String", "category": "credentials", "severity": "critical", "pattern": `(?i)(postgres|mysql|mongodb|redis)://[^\s]+`},
		{"id": "internal_ip", "name": "Internal IP Address", "category": "internal", "severity": "low", "pattern": `\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`},
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"library": library, "total": len(library)})
}

// DLPTest handles POST /api/policies/dlp-test — validates a regex pattern against sample text.
func (h *PolicyHandler) DLPTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
		Text    string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Pattern == "" {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "pattern is required"})
		return
	}

	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid regex: %v", err)})
		return
	}

	matches := re.FindAllString(req.Text, 50)
	if matches == nil {
		matches = []string{}
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{
		"valid":   true,
		"matches": matches,
		"count":   len(matches),
	})
}
