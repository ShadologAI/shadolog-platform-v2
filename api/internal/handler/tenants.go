package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// TenantHandler handles tenant CRUD endpoints.
type TenantHandler struct {
	pg *store.PGStore
}

// NewTenantHandler creates a TenantHandler.
func NewTenantHandler(pg *store.PGStore) *TenantHandler {
	return &TenantHandler{pg: pg}
}

// Me handles GET /api/tenants/me — returns the current tenant from JWT context.
func (h *TenantHandler) Me(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	tenant, err := h.pg.GetTenant(r.Context(), tenantID)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tenant == nil {
		auth.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	}
	auth.WriteJSON(w, http.StatusOK, tenant)
}

// List handles GET /api/tenants — admin list of all tenants.
func (h *TenantHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	tenants, total, err := h.pg.ListTenants(r.Context(), limit, offset)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tenants == nil {
		tenants = []store.Tenant{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Tenant]{Data: tenants, Total: total})
}

// Get handles GET /api/tenants/{tenantId}.
func (h *TenantHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	tenant, err := h.pg.GetTenant(r.Context(), tenantID)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tenant == nil {
		auth.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	}
	auth.WriteJSON(w, http.StatusOK, tenant)
}

// Create handles POST /api/tenants — admin creates a new tenant.
func (h *TenantHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req store.CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Slug == "" || req.Name == "" {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "slug and name are required"})
		return
	}
	if req.Tier == "" {
		req.Tier = "community"
	}

	tenant, err := h.pg.CreateTenant(r.Context(), req)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusCreated, tenant)
}
