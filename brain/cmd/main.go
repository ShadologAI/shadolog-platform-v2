// Brain is the unified detection engine for Shadolog v2.
// It consumes events from NATS, runs them through a plugin-based detection
// pipeline (DLP, rules, ML, behavioral), and publishes findings.
//
// Consolidates: LEARN (v1)
// Ports: 8091 (health), 50053 (gRPC PolicyService)
package main

import (
	"fmt"
	"os"

	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("brain", 8091)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)

	logger.Info("brain starting",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
	)

	// TODO: Initialize brain.Registry, register built-in detectors, start NATS consumer
	// Uses the plugin interface from services/learn/internal/brain/

	fmt.Fprintf(os.Stderr, "brain scaffold ready on %s\n", cfg.Addr())
}
