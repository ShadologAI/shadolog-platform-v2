// Package auth provides shared authentication and authorization primitives
// for all v4 services.
package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ctxTenantID contextKey = "tenant_id"
	ctxUserID   contextKey = "user_id"
	ctxRole     contextKey = "role"
)

// TenantFromContext extracts the tenant ID injected by JWT middleware.
func TenantFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxTenantID).(string)
	return v
}

// UserFromContext extracts the user ID (JWT subject) injected by JWT middleware.
func UserFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

// RoleFromContext extracts the role injected by JWT middleware.
func RoleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRole).(string)
	return v
}

// InjectClaims sets tenant_id, user_id, and role into the context.
func InjectClaims(ctx context.Context, tenantID, userID, role string) context.Context {
	ctx = context.WithValue(ctx, ctxTenantID, tenantID)
	ctx = context.WithValue(ctx, ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxRole, role)
	return ctx
}

// JWTClaims defines the claims embedded in Shadolog JWTs.
type JWTClaims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
