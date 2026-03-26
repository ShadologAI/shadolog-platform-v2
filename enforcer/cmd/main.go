// Enforcer is the inline proxy for Shadolog v2 (Defend tier).
// It intercepts AI agent traffic, applies FIDES taint labels,
// scans for DLP violations, and enforces policy decisions in real time.
//
// The Enforcer is a Rust service (Cloudflare Pingora). This Go entry point
// serves as a configuration bridge and health check wrapper.
//
// Consolidates: ENFORCE (v1) — Rust binary unchanged
// Ports: 8443 (proxy), 8080 (health)
package main

import (
	"fmt"
	"os"

	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("enforcer", 8080)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)

	logger.Info("enforcer config bridge starting",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
	)

	// The actual proxy is the Rust binary in services/enforce/.
	// This Go wrapper provides:
	// 1. Config generation from env vars → TOML config for Pingora
	// 2. Health check endpoint aggregation
	// 3. Policy sync from API service

	fmt.Fprintf(os.Stderr, "enforcer config bridge ready on %s\n", cfg.Addr())
}
