// API is the consolidated control plane for Shadolog v4.
// It serves the management API, dashboard backend, audit chain (PROVE),
// and SIEM export connectors in a single service.
//
// Key design decisions (from CEO + Eng review):
//   - ONE auth model: JWT with tenant_id claim, no URL param override
//   - No optional auth: every protected endpoint requires valid JWT
//   - Audit chain: Ed25519 signatures cover ALL finding fields (including ruleID)
//   - Row-level locking (SELECT FOR UPDATE) on receipt chain appends
//   - Tenant-specific genesis hash: hash(tenant_id + creation_timestamp)
//   - Contract caching in Redis (5-min TTL) to avoid N+1 per-request queries
//   - SpiceDB fail-closed: reject if authz service is unavailable
//
// Consolidates: mgmt-api + PROVE + siem-connectors (v3)
// Port: 8100 (REST + /healthz + /metrics)
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shadologai/shadolog/v2/api/internal/handler"
	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/metrics"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("api", 8100)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)
	metrics.RegisterAPI()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Data stores ────────────────────────────────────────────────
	pgPool, err := pgxpool.New(ctx, cfg.PostgresURL)
	if err != nil {
		logger.Error("FATAL: PostgreSQL connection failed", "error", err)
		os.Exit(1)
	}
	defer pgPool.Close()
	logger.Info("PostgreSQL connected")

	chStoreReal, err := store.NewCHStore(cfg.ClickHouseAddr)
	if err != nil {
		logger.Error("FATAL: ClickHouse connection failed", "error", err)
		os.Exit(1)
	}
	defer chStoreReal.Close()
	logger.Info("ClickHouse connected")

	redisClient, err := connectRedis(cfg.RedisURL)
	if err != nil {
		logger.Warn("Redis unavailable — contract caching disabled", "error", err)
	}

	devMode := os.Getenv("SHADOLOG_DEV_MODE") == "true"
	spiceDB, err := connectSpiceDB(cfg.SpiceDBAddr, cfg.SpiceDBToken)
	if err != nil && !devMode {
		logger.Error("FATAL: SpiceDB unavailable in production mode", "error", err)
		os.Exit(1)
	}
	if err != nil {
		logger.Warn("SpiceDB unavailable — using RBAC fallback (dev mode)", "error", err)
	}

	natsConn, err := connectNATS(cfg.NATSURLs)
	if err != nil {
		logger.Warn("NATS unavailable — SSE streaming disabled", "error", err)
	}

	// Suppress unused variable warnings for stores wired in future handlers.
	_ = redisClient
	_ = spiceDB
	_ = natsConn

	// ── Data stores (v4) ──────────────────────────────────────────
	pgStore := store.NewPGStore(pgPool)

	// ── Handlers ───────────────────────────────────────────────────
	authH := handler.NewAuthHandler(pgPool, cfg.JWTSecret, cfg.JWTIssuer)
	tenantH := handler.NewTenantHandler(pgStore)
	eventH := handler.NewEventHandler(chStoreReal)
	findingH := handler.NewFindingHandler(chStoreReal)
	graphH := handler.NewGraphHandler(pgStore)
	adminH := handler.NewAdminHandler(pgStore)
	policyH := handler.NewPolicyHandler(pgStore)
	auditH := handler.NewAuditHandler(pgStore)
	siemH := handler.NewSIEMHandler(chStoreReal)
	scimH := handler.NewSCIMHandler(pgPool)

	// ── HTTP router (chi) ──────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Health + metrics (unauthenticated)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","service":"api"}`)
	})
	r.Handle("/metrics", metricsHandler())

	// Auth endpoints (unauthenticated)
	r.Post("/api/auth/login", authH.Login)
	r.Post("/api/auth/refresh", authH.Refresh)
	r.Post("/api/auth/signup", authH.Signup)

	// ── Protected routes (JWT required) ────────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(auth.JWTAuth(cfg.JWTSecret))

		// Tenant endpoints (any authenticated user)
		r.Get("/api/tenants/me", tenantH.Me)

		// Events + findings (analyst+)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRoleLevel("analyst"))
			r.Get("/api/events", eventH.List)
			r.Get("/api/findings", findingH.List)
			r.Get("/api/findings/by-severity", findingH.BySeverity)
		})

		// Policies (analyst+ for read, admin+ for write)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRoleLevel("analyst"))
			r.Get("/api/policies", policyH.List)
			r.Get("/api/policies/versions", policyH.Versions)
			r.Get("/api/policies/dlp-library", policyH.DLPLibrary)
			r.Post("/api/policies/dlp-test", policyH.DLPTest)
			r.Get("/api/policies/{id}", policyH.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRoleLevel("admin"))
			r.Post("/api/policies", policyH.Create)
			r.Patch("/api/policies/{id}", policyH.Update)
			r.Delete("/api/policies/{id}", policyH.Delete)
		})

		// Graph entities (viewer+)
		r.Get("/api/graph", graphH.Graph)
		r.Get("/api/entities", graphH.ListEntities)

		// Audit chain — PROVE endpoints (admin+, Command tier)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRoleLevel("admin"))
			r.Get("/api/audit/receipts", auditH.ListReceipts)
			r.Get("/api/audit/chain/verify", auditH.VerifyChain)
			r.Get("/api/audit/reports", auditH.Reports)
		})

		// SIEM export (admin+)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRoleLevel("admin"))
			r.Get("/api/siem/splunk", siemH.Splunk)
			r.Get("/api/siem/sentinel", siemH.Sentinel)
		})

		// Admin endpoints (admin or superadmin)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin", "superadmin"))
			r.Get("/api/tenants", tenantH.List)
			r.Post("/api/tenants", tenantH.Create)
			r.Get("/api/admin/tenants", adminH.Tenants)
			r.Get("/api/admin/overview", adminH.Overview)
		})

		// SCIM provisioning (admin+)
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole("admin", "superadmin"))
			r.HandleFunc("/scim/v2/Users", scimH.Users)
			r.Get("/scim/v2/Groups", scimH.Groups)
		})
	})

	srv := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	logger.Info("api started",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
		"dev_mode", devMode,
	)

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	srv.Shutdown(shutdownCtx)
	logger.Info("api stopped")
}

// ── Stubs ──────────────────────────────────────────────────────

func stubHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"stub":"%s","status":"not_implemented"}`, name)
	}
}

type redisClientType struct{}

func connectRedis(url string) (*redisClientType, error) { return &redisClientType{}, nil }

type spiceDBClient struct{}

func connectSpiceDB(addr, token string) (*spiceDBClient, error) { return &spiceDBClient{}, nil }

type natsConnType struct{}

func connectNATS(url string) (*natsConnType, error) { return &natsConnType{}, nil }
func (n *natsConnType) Close()                      {}

func metricsHandler() http.Handler {
	return metrics.Handler()
}
