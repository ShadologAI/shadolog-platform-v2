package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/shadologai/shadolog/v2/shared/auth"
)

// SCIMHandler implements SCIM 2.0 endpoints for identity provisioning.
type SCIMHandler struct {
	pg *pgxpool.Pool
}

// NewSCIMHandler creates a SCIMHandler.
func NewSCIMHandler(pg *pgxpool.Pool) *SCIMHandler {
	return &SCIMHandler{pg: pg}
}

// --- SCIM schema URIs ---

const (
	scimUserSchema      = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema     = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema     = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// --- SCIM response types ---

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	Resources    []any    `json:"Resources"`
}

type scimUser struct {
	Schemas  []string     `json:"schemas"`
	ID       string       `json:"id"`
	UserName string       `json:"userName"`
	Name     scimName     `json:"name"`
	Active   bool         `json:"active"`
	Meta     *scimMeta    `json:"meta,omitempty"`
}

type scimName struct {
	Formatted string `json:"formatted"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location"`
}

type scimGroup struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
}

type scimError struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
}

func writeSCIMError(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(scimError{
		Schemas: []string{scimErrorSchema},
		Status:  fmt.Sprintf("%d", code),
		Detail:  detail,
	})
}

func writeSCIMJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Users handles requests to /scim/v2/Users.
// GET returns a SCIM ListResponse of users; POST creates a new user.
func (h *SCIMHandler) Users(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listUsers(w, r)
	case http.MethodPost:
		h.createUser(w, r)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Groups handles GET /scim/v2/Groups.
func (h *SCIMHandler) Groups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	roles := []string{"viewer", "analyst", "admin", "superadmin"}
	resources := make([]any, 0, len(roles))
	for _, role := range roles {
		resources = append(resources, scimGroup{
			Schemas:     []string{scimGroupSchema},
			ID:          role,
			DisplayName: role,
		})
	}

	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(resources),
		Resources:    resources,
	})
}

// listUsers returns all users for the tenant in SCIM format.
func (h *SCIMHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		writeSCIMError(w, http.StatusUnauthorized, "missing tenant context")
		return
	}

	rows, err := h.pg.Query(r.Context(),
		`SELECT user_id, email, display_name, status FROM users WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		slog.Error("scim list users query failed", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "failed to query users")
		return
	}
	defer rows.Close()

	var resources []any
	for rows.Next() {
		var userID, email, displayName, status string
		if err := rows.Scan(&userID, &email, &displayName, &status); err != nil {
			slog.Error("scim list users scan failed", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "failed to read user")
			return
		}
		resources = append(resources, scimUser{
			Schemas:  []string{scimUserSchema},
			ID:       userID,
			UserName: email,
			Name:     scimName{Formatted: displayName},
			Active:   status == "active",
		})
	}
	if err := rows.Err(); err != nil {
		slog.Error("scim list users iteration failed", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "failed to iterate users")
		return
	}

	if resources == nil {
		resources = []any{}
	}

	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(resources),
		Resources:    resources,
	})
}

// scimCreateUserRequest is the expected inbound SCIM User resource for POST.
type scimCreateUserRequest struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Name     struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Password string `json:"password"`
}

// createUser creates a new user from a SCIM User resource.
func (h *SCIMHandler) createUser(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		writeSCIMError(w, http.StatusUnauthorized, "missing tenant context")
		return
	}

	var req scimCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid SCIM User resource")
		return
	}

	if req.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	if len(req.Password) < 8 {
		writeSCIMError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Check for duplicate within tenant.
	var existing string
	err := h.pg.QueryRow(r.Context(),
		"SELECT user_id FROM users WHERE tenant_id = $1 AND email = $2",
		tenantID, req.UserName,
	).Scan(&existing)
	if err == nil && existing != "" {
		writeSCIMError(w, http.StatusConflict, "userName already exists")
		return
	}

	// Hash password with bcrypt (same approach as AuthHandler.Signup).
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("scim create user: bcrypt failed", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "internal error")
		return
	}

	userID := uuid.New().String()
	displayName := req.Name.Formatted
	if displayName == "" {
		displayName = req.UserName
	}
	role := "viewer" // SCIM-provisioned users start as viewer

	_, err = h.pg.Exec(r.Context(),
		`INSERT INTO users (user_id, tenant_id, email, display_name, password_hash, role, auth_method, status)
		 VALUES ($1, $2, $3, $4, $5, $6, 'scim', 'active')`,
		userID, tenantID, req.UserName, displayName, string(hash), role,
	)
	if err != nil {
		slog.Error("scim create user: insert failed", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	writeSCIMJSON(w, http.StatusCreated, scimUser{
		Schemas:  []string{scimUserSchema},
		ID:       userID,
		UserName: req.UserName,
		Name:     scimName{Formatted: displayName},
		Active:   true,
		Meta: &scimMeta{
			ResourceType: "User",
			Location:     fmt.Sprintf("/scim/v2/Users/%s", userID),
		},
	})
}
