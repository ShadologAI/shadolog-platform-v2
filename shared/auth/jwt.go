package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuth returns middleware that validates JWT bearer tokens and injects
// tenant_id, user_id, and role into the request context.
//
// Security invariants (A1 fix):
//   - Token MUST be in Authorization header — URL params are NEVER accepted
//   - Every protected route requires a valid, non-expired JWT
//   - tenant_id comes exclusively from the token — no override from query/path
//   - Missing tenant_id claim is a hard 401 reject
func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "missing authorization header",
				})
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "invalid authorization header format — expected: Bearer <token>",
				})
				return
			}

			tokenString := parts[1]

			claims := &JWTClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return []byte(secret), nil
			})
			if err != nil || !token.Valid {
				WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "invalid or expired token",
				})
				return
			}

			if claims.TenantID == "" {
				WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "token missing tenant_id claim",
				})
				return
			}

			if claims.Subject == "" {
				WriteJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "token missing subject claim",
				})
				return
			}

			ctx := InjectClaims(r.Context(), claims.TenantID, claims.Subject, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
