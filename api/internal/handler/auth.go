// Package handler implements HTTP handlers for the v4 API service.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/shadologai/shadolog/v2/shared/auth"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	pg        *pgxpool.Pool
	jwtSecret string
	jwtIssuer string
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(pg *pgxpool.Pool, jwtSecret, jwtIssuer string) *AuthHandler {
	return &AuthHandler{pg: pg, jwtSecret: jwtSecret, jwtIssuer: jwtIssuer}
}

// LoginRequest is the POST /api/auth/login body.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	Token        string   `json:"token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresAt    string   `json:"expires_at"`
	User         AuthUser `json:"user"`
}

// AuthUser is the user object embedded in login/refresh responses.
type AuthUser struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
}

// SignupRequest is the POST /api/auth/signup body.
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// Login handles POST /api/auth/login.
// Dev-mode only: accepts bootstrap credentials when SHADOLOG_DEV_MODE=true.
// Production deployments must use OIDC.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("SHADOLOG_DEV_MODE") != "true" {
		auth.WriteJSON(w, http.StatusNotFound, map[string]string{
			"error": "endpoint disabled — use OIDC login in production",
		})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Dev bootstrap credentials only.
	if req.Username != "admin" || req.Password != "shadolog_admin" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid credentials",
		})
		return
	}

	tenantID := "00000000-0000-0000-0000-000000000001"

	// Try to resolve tenant from PG if available.
	if h.pg != nil {
		var tid string
		err := h.pg.QueryRow(r.Context(),
			"SELECT tenant_id FROM tenants ORDER BY created_at ASC LIMIT 1",
		).Scan(&tid)
		if err == nil && tid != "" {
			tenantID = tid
		}
	}

	accessToken, expiresAt, err := h.issueToken(tenantID, "admin-user-001", "admin", 24*time.Hour)
	if err != nil {
		slog.Error("failed to sign access JWT", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate token",
		})
		return
	}

	refreshToken, _, err := h.issueToken(tenantID, "admin-user-001", "admin", 7*24*time.Hour)
	if err != nil {
		slog.Error("failed to sign refresh JWT", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate refresh token",
		})
		return
	}

	auth.WriteJSON(w, http.StatusOK, LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: AuthUser{
			UserID:   "admin-user-001",
			Username: "admin",
			Role:     "admin",
			TenantID: tenantID,
		},
	})
}

// Signup handles POST /api/auth/signup.
// Creates a new user with local (bcrypt) authentication and returns tokens.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Validate required fields.
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "email is required",
		})
		return
	}
	if len(req.Password) < 8 {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "password must be at least 8 characters",
		})
		return
	}

	// Hash password with bcrypt.
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("failed to hash password", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "internal error",
		})
		return
	}

	// Resolve tenant: use default tenant for self-signup.
	tenantID := "00000000-0000-0000-0000-000000000001"
	if h.pg != nil {
		var tid string
		err := h.pg.QueryRow(r.Context(),
			"SELECT tenant_id FROM tenants ORDER BY created_at ASC LIMIT 1",
		).Scan(&tid)
		if err == nil && tid != "" {
			tenantID = tid
		}
	}

	// Check for duplicate email within tenant.
	if h.pg != nil {
		var existing string
		err := h.pg.QueryRow(r.Context(),
			"SELECT user_id FROM users WHERE tenant_id = $1 AND email = $2",
			tenantID, req.Email,
		).Scan(&existing)
		if err == nil && existing != "" {
			auth.WriteJSON(w, http.StatusConflict, map[string]string{
				"error": "email already registered",
			})
			return
		}
	}

	// Insert user into PostgreSQL.
	userID := uuid.New().String()
	displayName := req.Name
	if displayName == "" {
		displayName = req.Email
	}
	role := "viewer" // default role for self-signup

	if h.pg != nil {
		_, err = h.pg.Exec(r.Context(),
			`INSERT INTO users (user_id, tenant_id, email, display_name, password_hash, role, auth_method, status)
			 VALUES ($1, $2, $3, $4, $5, $6, 'local', 'active')`,
			userID, tenantID, req.Email, displayName, string(hash), role,
		)
		if err != nil {
			slog.Error("failed to insert user", "error", err)
			auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "failed to create user",
			})
			return
		}
	}

	// Issue tokens (reuse the same token generation as Login).
	accessToken, expiresAt, err := h.issueToken(tenantID, userID, role, 24*time.Hour)
	if err != nil {
		slog.Error("failed to sign access JWT", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate token",
		})
		return
	}

	refreshToken, _, err := h.issueToken(tenantID, userID, role, 7*24*time.Hour)
	if err != nil {
		slog.Error("failed to sign refresh JWT", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate refresh token",
		})
		return
	}

	auth.WriteJSON(w, http.StatusCreated, LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: AuthUser{
			UserID:   userID,
			Username: req.Email,
			Role:     role,
			TenantID: tenantID,
		},
	})
}

// Refresh handles POST /api/auth/refresh.
// Validates the refresh token and issues a new access + refresh token pair.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		auth.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body — refresh_token required",
		})
		return
	}

	// Validate the refresh token.
	claims := &auth.JWTClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(h.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid or expired refresh token",
		})
		return
	}

	if claims.TenantID == "" || claims.Subject == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "malformed refresh token",
		})
		return
	}

	// Issue fresh tokens.
	accessToken, expiresAt, err := h.issueToken(claims.TenantID, claims.Subject, claims.Role, 24*time.Hour)
	if err != nil {
		slog.Error("failed to sign access JWT on refresh", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate token",
		})
		return
	}

	refreshToken, _, err := h.issueToken(claims.TenantID, claims.Subject, claims.Role, 7*24*time.Hour)
	if err != nil {
		slog.Error("failed to sign refresh JWT on refresh", "error", err)
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate refresh token",
		})
		return
	}

	auth.WriteJSON(w, http.StatusOK, LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		User: AuthUser{
			UserID:   claims.Subject,
			Username: claims.Subject,
			Role:     claims.Role,
			TenantID: claims.TenantID,
		},
	})
}

// issueToken creates a signed JWT with the given claims and duration.
func (h *AuthHandler) issueToken(tenantID, userID, role string, ttl time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(ttl)
	claims := auth.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    h.jwtIssuer,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		TenantID: tenantID,
		Role:     role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(h.jwtSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}
