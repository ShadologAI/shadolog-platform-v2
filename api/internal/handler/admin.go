package handler

import (
	"net/http"
	"strconv"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// AdminHandler serves admin/platform-level endpoints.
type AdminHandler struct {
	pg *store.PGStore
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(pg *store.PGStore) *AdminHandler {
	return &AdminHandler{pg: pg}
}

// Overview handles GET /api/admin/overview — platform-wide stats.
func (h *AdminHandler) Overview(w http.ResponseWriter, r *http.Request) {
	overview, err := h.pg.GetAdminOverview(r.Context())
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusOK, overview)
}

// Tenants handles GET /api/admin/tenants — tenant list with usage stats.
func (h *AdminHandler) Tenants(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	tenants, total, err := h.pg.ListTenantsWithStats(r.Context(), limit, offset)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if tenants == nil {
		tenants = []map[string]any{}
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"data": tenants, "total": total})
}
