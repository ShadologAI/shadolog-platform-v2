// Package telemetry provides shared observability primitives for v2 services.
package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a structured JSON logger for production services.
func NewLogger(serviceName, level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})

	return slog.New(handler).With(
		"service", serviceName,
	)
}
