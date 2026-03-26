// Gateway is the unified event ingestion service for Shadolog v2.
// It receives events from browser extensions, ARGUS sensors, hook bridges,
// and the ENFORCE proxy, then publishes them to NATS for downstream processing.
//
// Consolidates: OBSERVE (v1)
// Ports: 8090 (REST), 50052 (gRPC)
package main

import (
	"fmt"
	"os"

	"github.com/shadologai/shadolog/v2/shared/config"
	"github.com/shadologai/shadolog/v2/shared/telemetry"
)

func main() {
	cfg := config.LoadBase("gateway", 8090)
	logger := telemetry.NewLogger(cfg.ServiceName, cfg.LogLevel)

	logger.Info("gateway starting",
		"port", cfg.ServicePort,
		"tier", cfg.Tier,
	)

	// TODO: Initialize stores, NATS publisher, HTTP/gRPC server
	// This is a scaffold — full implementation follows in subsequent tickets.

	fmt.Fprintf(os.Stderr, "gateway scaffold ready on %s\n", cfg.Addr())
}
