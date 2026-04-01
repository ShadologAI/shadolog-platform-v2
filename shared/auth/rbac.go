package auth

import (
	"net/http"
	"strings"
)

// RoleHierarchy maps roles to numeric privilege levels.
// Higher number = more privileged.
var RoleHierarchy = map[string]int{
	"viewer":    1,
	"analyst":   3,
	"admin":     5,
	"superadmin": 7,
}

// RequireRole returns middleware that blocks requests unless the user's role
// is one of the allowed roles. Roles are extracted from the JWT by JWTAuth.
//
// Usage:
//
//	r.With(RequireRole("admin", "superadmin")).Post("/api/tenants", ...)
func RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedRoles))
	for _, r := range allowedRoles {
		allowed[strings.ToLower(r)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := RoleFromContext(r.Context())
			if role == "" {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error": "no role in token",
				})
				return
			}

			if !allowed[strings.ToLower(role)] {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error":         "insufficient permissions",
					"current_role":  role,
					"required_role": strings.Join(allowedRoles, " | "),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoleLevel returns middleware that blocks requests unless the user's
// role level is at or above the specified minimum role.
//
// Usage:
//
//	r.With(RequireRoleLevel("analyst")).Get("/api/findings", ...)
func RequireRoleLevel(minRole string) func(http.Handler) http.Handler {
	minLevel := RoleHierarchy[strings.ToLower(minRole)]

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := RoleFromContext(r.Context())
			currentLevel := RoleHierarchy[strings.ToLower(role)]

			if currentLevel < minLevel {
				WriteJSON(w, http.StatusForbidden, map[string]string{
					"error":        "insufficient permissions",
					"current_role": role,
					"minimum_role": minRole,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
