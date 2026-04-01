// Gateway is the unified event ingestion service for Shadolog v4.
// It receives events from browser extensions, ARGUS sensors, hook bridges,
// and the ENFORCE proxy, then publishes them to NATS JetStream for downstream
// processing by Brain.
//
// Key design decisions (from CEO + Eng review):
//   - NATS-first: events go to JetStream before full validation (durable buffer)
//   - Auth fail-closed: if PG is down, reject events (don't accept unauthenticated)
//   - Tenant validation: empty tenant_id is always rejected
//   - Batch limits: max 100 events per batch, cumulative 5MB payload cap
//   - Prometheus /metrics endpoint for observability
//
// Consolidates: OBSERVE (v3)
// Ports: 8090 (REST), 50052 (gRPC), 8090 (/healthz, /metrics)
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shadologai/shadolog/v2/gateway/internal/auth"
	"github.com/shadologai/shadolog/v2/gateway/internal/handler"
	"github.com/shadologai/shadolog/v2/gateway/internal/pipeline"
	"github.com/shadologai/shadolog/v2/gateway/internal/store"
	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/metrics"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("gateway", 8090)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)
	metrics.RegisterGateway()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Data stores ────────────────────────────────────────────────
	// NATS JetStream: durable event buffer. Brain consumes from here.
	// CRITICAL: Gateway cannot operate without NATS — fail startup if unavailable.
	natsSink, err := store.NewNATSSink(cfg.NATSURLs, logger)
	if err != nil {
		logger.Error("FATAL: NATS connection failed — gateway cannot operate without event bus", "error", err)
		os.Exit(1)
	}
	defer natsSink.Close()
	logger.Info("NATS connected", "url", cfg.NATSURLs)

	// ClickHouse: event metadata storage (non-blocking — events still flow via NATS).
	var sinks []pipeline.Sink
	sinks = append(sinks, natsSink)

	chSink, err := store.NewClickHouseSink(cfg.ClickHouseAddr, logger)
	if err != nil {
		logger.Warn("ClickHouse unavailable — events will flow via NATS only", "error", err)
	} else {
		sinks = append(sinks, chSink)
	}

	// PostgreSQL: API key validation store.
	// FAIL-CLOSED: In production, if PG is unavailable, reject all events.
	// This prevents the v3 bug where nil validator accepted everything.
	var validator auth.KeyValidator
	devMode := os.Getenv("SHADOLOG_DEV_MODE") == "true"
	if devMode {
		logger.Info("DEV MODE: API key validation disabled")
		validator = &auth.DevKeyValidator{}
	} else {
		pgPool, pgErr := pgxpool.New(ctx, cfg.PostgresURL)
		if pgErr != nil {
			logger.Error("FATAL: PostgreSQL unavailable — cannot validate API keys (fail-closed)", "error", pgErr)
			os.Exit(1)
		}
		defer pgPool.Close()
		logger.Info("PostgreSQL connected (API key validation active)")

		pgValidator := &auth.PGKeyValidator{
			QueryRowFunc: func(ctx context.Context, dest *int, query string, args ...interface{}) error {
				return pgPool.QueryRow(ctx, query, args...).Scan(dest)
			},
		}
		validator = auth.NewCachedKeyValidator(pgValidator, 5*time.Minute)
	}

	// ── Pipeline ───────────────────────────────────────────────────
	batcher := pipeline.NewBatcher(1000, 1*time.Second, logger, sinks...)
	batcher.Start()

	// ── HTTP Server ────────────────────────────────────────────────
	ingestH := handler.NewIngestHandler(batcher, logger)
	authMW := auth.APIKeyMiddleware(validator, logger)

	mux := http.NewServeMux()

	// Health check (unauthenticated)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !natsSink.IsConnected() {
			metrics.GatewayNATSConnected.Set(0)
			http.Error(w, `{"status":"unhealthy","reason":"nats_disconnected"}`, http.StatusServiceUnavailable)
			return
		}
		metrics.GatewayNATSConnected.Set(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","service":"gateway","pending":%d}`, batcher.Pending())
	})

	// Prometheus metrics (unauthenticated)
	mux.Handle("/metrics", metrics.Handler())

	// Authenticated event ingestion endpoints
	mux.Handle("/v1/events", authMW(http.HandlerFunc(ingestH.HandleEvent)))
	mux.Handle("/v1/events/batch", authMW(http.HandlerFunc(ingestH.HandleBatch)))
	mux.Handle("/v1/argus/events", authMW(http.HandlerFunc(ingestH.HandleARGUS)))
	mux.Handle("/v1/events/argus", authMW(http.HandlerFunc(ingestH.HandleARGUS))) // legacy route used by ARGUS agent

	srv := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	logger.Info("gateway started",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
		"dev_mode", devMode,
	)

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}

	// Graceful shutdown (15s timeout)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	batcher.Stop()
	srv.Shutdown(shutdownCtx)
	logger.Info("gateway stopped")
}

