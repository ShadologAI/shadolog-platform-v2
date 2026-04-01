package handler

import (
	"net/http"
	"strconv"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// GraphHandler serves the graph entity endpoints.
type GraphHandler struct {
	pg *store.PGStore
}

// NewGraphHandler creates a GraphHandler.
func NewGraphHandler(pg *store.PGStore) *GraphHandler {
	return &GraphHandler{pg: pg}
}

// Graph handles GET /api/graph — returns the full entity graph with relationships.
func (h *GraphHandler) Graph(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	entities, _, err := h.pg.ListEntities(r.Context(), store.EntityFilter{
		TenantID: tenantID,
		Limit:    500,
	})
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	rels, _, err := h.pg.ListRelationships(r.Context(), store.RelationshipFilter{
		TenantID: tenantID,
		Limit:    500,
	})
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if entities == nil {
		entities = []store.Entity{}
	}
	if rels == nil {
		rels = []store.Relationship{}
	}

	auth.WriteJSON(w, http.StatusOK, store.GraphResponse{
		Entities:      entities,
		Relationships: rels,
	})
}

// ListEntities handles GET /api/entities — entity list with filters.
func (h *GraphHandler) ListEntities(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := store.EntityFilter{
		TenantID: tenantID,
	}

	if v := r.URL.Query().Get("type"); v != "" {
		f.Type = &v
	}
	if v := r.URL.Query().Get("status"); v != "" {
		f.Status = &v
	}
	if v := r.URL.Query().Get("source_plane"); v != "" {
		f.SourcePlane = &v
	}
	if v := r.URL.Query().Get("min_risk"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 16); err == nil {
			risk := int16(n)
			f.MinRisk = &risk
		}
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	entities, total, err := h.pg.ListEntities(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if entities == nil {
		entities = []store.Entity{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Entity]{Data: entities, Total: total})
}
