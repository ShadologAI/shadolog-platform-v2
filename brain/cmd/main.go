// Brain is the unified detection engine for Shadolog v4.
// It consumes events from NATS JetStream, runs them through a plugin-based
// detection pipeline (DLP, rules, ML, behavioral, entity resolution), and
// publishes findings to PostgreSQL and ClickHouse.
//
// Key design decisions (from CEO + Eng review):
//   - Rule load failure is FATAL (don't start with no rules)
//   - DLP returns empty slice, never nil (prevents nil dereference)
//   - AckExplicit with max 100 in-flight (correctness over throughput)
//   - Plugin priority ordering: Blocking (DLP) → High (rules) → Normal (ML) → Low (behavioral)
//   - MITRE ATLAS + OWASP LLM Top 10 mapping on all findings
//
// Consolidates: LEARN (v3)
// Ports: 8091 (health + metrics), 50053 (gRPC PolicyService)
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shadologai/shadolog/v2/brain/internal/consumer"
	"github.com/shadologai/shadolog/v2/brain/internal/detector"
	"github.com/shadologai/shadolog/v2/brain/internal/detector/dlp"
	"github.com/shadologai/shadolog/v2/brain/internal/detector/rules"
	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/metrics"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("brain", 8091)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)
	metrics.RegisterBrain()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Detection rule engine ──────────────────────────────────────
	// FATAL if rules fail to load. Brain without rules is useless.
	rulesDir := os.Getenv("RULES_DIR")
	if rulesDir == "" {
		rulesDir = "/app/detections/rules"
	}
	ruleCount, err := loadRules(rulesDir)
	if err != nil {
		logger.Error("FATAL: failed to load detection rules", "error", err, "dir", rulesDir)
		os.Exit(1)
	}
	logger.Info("detection rules loaded", "count", ruleCount, "dir", rulesDir)

	// ── Plugin registry ────────────────────────────────────────────
	registry := detector.NewRegistry()

	// Register built-in detectors (priority order: blocking → high → normal → low).
	dlpScanner := dlp.New()
	if err := dlpScanner.Init(ctx, nil); err != nil {
		logger.Error("FATAL: failed to initialize DLP scanner", "error", err)
		os.Exit(1)
	}
	registry.Register(dlpScanner)

	// Rule engine detector (PriorityHigh)
	ruleEngine := rules.New(rulesDir, logger)
	if err := ruleEngine.Init(ctx, nil); err != nil {
		logger.Error("FATAL: failed to initialize rule engine", "error", err)
		os.Exit(1)
	}
	registry.Register(ruleEngine)

	// TODO: Register remaining detectors:
	//   registry.Register(ml.New())          // PriorityNormal (optional)
	//   registry.Register(behavioral.New())  // PriorityLow
	//   registry.Register(entity.New())      // PriorityLow
	logger.Info("detector registry initialized", "detectors", registry.Count())

	// ── PostgreSQL connection pool ─────────────────────────────────
	pgPool, err := pgxpool.New(ctx, cfg.PostgresURL)
	if err != nil {
		logger.Error("FATAL: failed to connect to PostgreSQL", "error", err, "url", cfg.PostgresURL)
		os.Exit(1)
	}
	defer pgPool.Close()
	logger.Info("PostgreSQL connected", "url", cfg.PostgresURL)

	// ── ClickHouse connection (findings dual-write) ─────────────────
	chConn, chErr := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.ClickHouseAddr},
		Auth: clickhouse.Auth{Database: "default"},
		Settings: clickhouse.Settings{"max_execution_time": 30},
	})
	if chErr != nil {
		logger.Warn("ClickHouse unavailable — findings will only persist to PostgreSQL", "error", chErr)
	} else {
		if pingErr := chConn.Ping(ctx); pingErr != nil {
			logger.Warn("ClickHouse ping failed — findings will only persist to PostgreSQL", "error", pingErr)
			chConn = nil
		} else {
			logger.Info("ClickHouse connected (findings dual-write enabled)", "addr", cfg.ClickHouseAddr)
		}
	}

	// ── NATS JetStream consumer ────────────────────────────────────
	cons := consumer.New(registry, logger, cfg.NATSURLs, pgPool, chConn)
	go cons.Start(ctx)
	logger.Info("NATS consumer started")

	// ── HTTP server (health + metrics) ─────────────────────────────
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","service":"brain","rules":%d,"detectors":%d}`, ruleCount, registry.Count())
	})

	mux.Handle("/metrics", metricsHandler())

	srv := &http.Server{
		Addr:    cfg.Addr(),
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	logger.Info("brain started",
		"health_port", cfg.ServicePort,
		"tier", cfg.Tier,
		"rules", ruleCount,
		"detectors", registry.Count(),
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

	cons.Stop()
	registry.Shutdown(shutdownCtx)
	srv.Shutdown(shutdownCtx)
	logger.Info("brain stopped")
}

// loadRules reads all *.yaml rule files from the given directory and returns
// the count of enabled rules. Returns error if the directory is unreadable
// or any rule file has invalid YAML or regex patterns.
func loadRules(dir string) (int, error) {
	return rules.CountRulesInDir(dir)
}

// Suppress unused import warning for slog
var _ = slog.LevelInfo

func metricsHandler() http.Handler {
	return metrics.Handler()
}
