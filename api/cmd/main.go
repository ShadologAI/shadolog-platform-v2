// API is the consolidated control plane for Shadolog v2.
// It serves the management API, dashboard backend, audit chain (PROVE),
// and SIEM export connectors in a single service.
//
// Consolidates: mgmt-api + PROVE + siem-connectors (v1)
// Port: 8100
package main

import (
	"fmt"
	"os"

	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("api", 8100)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)

	logger.Info("api starting",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
	)

	// TODO: Initialize PG/CH stores, mount all route groups, start HTTP server
	// Merges mgmt-api routes + PROVE audit endpoints + SIEM connector endpoints

	fmt.Fprintf(os.Stderr, "api scaffold ready on %s\n", cfg.Addr())
}
