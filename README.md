# Shadolog v2 — Consolidated Platform

This directory contains the v2 consolidated architecture, merging 6 services into 4:

| v1 Services | v2 Service | Description |
|-------------|------------|-------------|
| OBSERVE | **Gateway** | Unified ingestion (REST + gRPC + hooks + extension) |
| LEARN | **Brain** | Plugin-based detection engine (DLP + rules + ML + behavioral) |
| ENFORCE | **Enforcer** | Inline proxy (Rust/Pingora) — unchanged |
| mgmt-api + PROVE + siem-connectors | **API** | Control plane + audit + export |

## Structure

```
v2/
├── gateway/          # Go — unified event ingestion
│   ├── cmd/          # CLI entry point
│   └── internal/     # Handlers, NATS publisher, validation
├── brain/            # Go — plugin-based detection
│   ├── cmd/          # CLI entry point
│   └── internal/     # Plugin registry, pipeline, detectors
├── enforcer/         # Rust — inline proxy (symlink to services/enforce)
│   ├── cmd/          # CLI entry point (wrapper)
│   └── internal/     # Config bridge
├── api/              # Go — consolidated control plane
│   ├── cmd/          # CLI entry point
│   └── internal/     # Handlers, store, auth, audit
└── shared/           # Go — shared libraries
    ├── models/       # Canonical event, finding, entity models
    ├── config/       # Shared config loading
    └── telemetry/    # OpenTelemetry, structured logging
```

## Migration Path

The v2 services coexist with v1 during migration:
1. v2 API reads from the same PG + CH databases
2. v2 Gateway publishes to the same NATS subjects
3. v2 Brain consumes the same NATS subjects
4. v1 services are gradually deprecated as v2 reaches parity

## Running

```bash
# Build all v2 services
cd v2 && go build ./...

# Start v2 with Docker Compose (future)
docker compose -f docker-compose.v2.yml up -d
```
