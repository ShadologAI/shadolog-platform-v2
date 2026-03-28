// Package config provides shared configuration loading for v2 services.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Base holds configuration common to all v2 services.
type Base struct {
	// Service identity
	ServiceName string
	ServicePort int

	// Data stores
	PostgresURL  string
	ClickHouseAddr string
	RedisURL     string
	NATSURLs     string

	// Auth
	JWTSecret string
	JWTIssuer string

	// SpiceDB
	SpiceDBAddr  string
	SpiceDBToken string

	// Observability
	LogLevel     string
	OTLPEndpoint string

	// Tier
	Tier string // protect, defend, command
}

// LoadBase loads common configuration from environment variables.
func LoadBase(serviceName string, defaultPort int) *Base {
	return &Base{
		ServiceName:    serviceName,
		ServicePort:    envInt("PORT", defaultPort),
		PostgresURL:    envStr("DATABASE_URL", "postgres://shadolog:shadolog@localhost:5432/shadolog?sslmode=disable"),
		ClickHouseAddr: envStr("CLICKHOUSE_ADDR", "localhost:9000"),
		RedisURL:       envStr("REDIS_URL", "redis://localhost:6379"),
		NATSURLs:       envStr("NATS_URL", "nats://localhost:4222"),
		JWTSecret:      jwtSecretOrDevDefault(),
		JWTIssuer:      envStr("JWT_ISSUER", "shadolog"),
		SpiceDBAddr:    envStr("SPICEDB_ADDR", "localhost:50051"),
		SpiceDBToken:   envStr("SPICEDB_TOKEN", ""),
		LogLevel:       envStr("LOG_LEVEL", "info"),
		OTLPEndpoint:   envStr("OTLP_ENDPOINT", ""),
		Tier:           envStr("SHADOLOG_TIER", "protect"),
	}
}

// Addr returns the service listen address.
func (c *Base) Addr() string {
	return fmt.Sprintf(":%d", c.ServicePort)
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func jwtSecretOrDevDefault() string {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v
	}
	if os.Getenv("SHADOLOG_DEV_MODE") == "true" {
		return "shadolog-dev-secret-do-not-use-in-production"
	}
	// In production without JWT_SECRET set, return empty — callers must validate.
	return ""
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
