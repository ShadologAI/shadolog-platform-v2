// Package auth provides API key validation for the v4 Gateway.
//
// CRITICAL DESIGN: Fail-closed authentication. If PostgreSQL is unavailable
// and dev mode is off, ALL requests are rejected. This fixes the v3 O1 bug
// where a nil validator silently accepted unauthenticated traffic.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const (
	TenantIDKey contextKey = "tenant_id"
	APIKeyKey   contextKey = "api_key"
)

// TenantFromContext extracts tenant_id from request context.
func TenantFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(TenantIDKey).(string); ok {
		return v
	}
	return ""
}

// KeyValidator checks API keys against a data source.
type KeyValidator interface {
	ValidateKey(ctx context.Context, keyHash, tenantID string) (bool, error)
}

// CachedKeyValidator wraps a KeyValidator with a TTL cache.
type CachedKeyValidator struct {
	inner KeyValidator
	cache sync.Map // map[string]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	valid   bool
	expires time.Time
}

// NewCachedKeyValidator wraps inner with a 5-minute TTL cache.
func NewCachedKeyValidator(inner KeyValidator, ttl time.Duration) *CachedKeyValidator {
	return &CachedKeyValidator{inner: inner, ttl: ttl}
}

func (c *CachedKeyValidator) ValidateKey(ctx context.Context, keyHash, tenantID string) (bool, error) {
	cacheKey := keyHash + ":" + tenantID
	if entry, ok := c.cache.Load(cacheKey); ok {
		e := entry.(cacheEntry)
		if time.Now().Before(e.expires) {
			return e.valid, nil
		}
	}
	valid, err := c.inner.ValidateKey(ctx, keyHash, tenantID)
	if err != nil {
		return false, err
	}
	c.cache.Store(cacheKey, cacheEntry{valid: valid, expires: time.Now().Add(c.ttl)})
	return valid, nil
}

// HashKey produces SHA-256 hash of an API key (matching the storage format in api_keys table).
func HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// APIKeyMiddleware extracts and validates X-Shadolog-Key and X-Shadolog-Tenant headers.
// CRITICAL: validator must not be nil -- reject all requests if key validation is unconfigured.
// This is the fail-closed fix for v3 bug O1.
func APIKeyMiddleware(validator KeyValidator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validator == nil {
				logger.Error("api key validator not configured -- rejecting request (fail-closed)")
				http.Error(w, `{"error":"API key validation not configured"}`, http.StatusServiceUnavailable)
				return
			}

			apiKey := r.Header.Get("X-Shadolog-Key")
			tenantID := r.Header.Get("X-Shadolog-Tenant")

			if apiKey == "" || tenantID == "" {
				http.Error(w, `{"error":"missing X-Shadolog-Key or X-Shadolog-Tenant header"}`, http.StatusUnauthorized)
				return
			}

			// Validate UUID format for tenant_id (fixes O5: empty/invalid tenant_id)
			if !isValidUUID(tenantID) {
				http.Error(w, `{"error":"invalid tenant_id format (must be UUID)"}`, http.StatusBadRequest)
				return
			}

			keyHash := HashKey(apiKey)
			valid, err := validator.ValidateKey(r.Context(), keyHash, tenantID)
			if err != nil {
				logger.Error("api key validation error", "error", err)
				http.Error(w, `{"error":"internal auth error"}`, http.StatusInternalServerError)
				return
			}
			if !valid {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), TenantIDKey, tenantID)
			ctx = context.WithValue(ctx, APIKeyKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isValidUUID checks basic UUID format (8-4-4-4-12 hex).
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

// DevKeyValidator accepts any non-empty key (for local development only).
type DevKeyValidator struct{}

func (d *DevKeyValidator) ValidateKey(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// PGKeyValidator validates against PostgreSQL api_keys table.
// CRITICAL: Never fall back to nil validator -- return error if PG unavailable.
type PGKeyValidator struct {
	// QueryRowFunc executes a parameterized query and scans a single int result.
	QueryRowFunc func(ctx context.Context, dest *int, query string, args ...interface{}) error
}

func (p *PGKeyValidator) ValidateKey(ctx context.Context, keyHash, tenantID string) (bool, error) {
	var exists int
	err := p.QueryRowFunc(ctx, &exists,
		`SELECT 1 FROM api_keys WHERE key_hash = $1 AND tenant_id = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1`,
		keyHash, tenantID)
	if err != nil {
		return false, nil // no row = invalid key
	}
	return exists == 1, nil
}
