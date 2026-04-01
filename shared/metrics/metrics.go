// Package metrics provides shared Prometheus metric definitions for V4 services.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Gateway metrics
var (
	GatewayEventsAccepted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_events_accepted_total",
			Help: "Total events accepted by the gateway",
		},
		[]string{"tenant_id", "event_type"},
	)
	GatewayEventsRejected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_events_rejected_total",
			Help: "Total events rejected by the gateway",
		},
		[]string{"reason"},
	)
	GatewayNATSConnected = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_nats_connected",
			Help: "Whether the gateway is connected to NATS (1=yes, 0=no)",
		},
	)
)

// Brain metrics
var (
	BrainFindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "brain_findings_total",
			Help: "Total findings produced by brain detectors",
		},
		[]string{"detector", "severity"},
	)
	BrainPluginDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "brain_plugin_duration_seconds",
			Help:    "Duration of brain detector plugin execution",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"detector"},
	)
)

// API metrics
var (
	APIRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "Total HTTP requests to the API",
		},
		[]string{"method", "path", "status"},
	)
	APIAuthFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_auth_failures_total",
			Help: "Total authentication failures",
		},
		[]string{"reason"},
	)
)

// RegisterGateway registers gateway metrics with the default prometheus registry.
func RegisterGateway() {
	prometheus.MustRegister(GatewayEventsAccepted, GatewayEventsRejected, GatewayNATSConnected)
}

// RegisterBrain registers brain metrics with the default prometheus registry.
func RegisterBrain() {
	prometheus.MustRegister(BrainFindingsTotal, BrainPluginDuration)
}

// RegisterAPI registers API metrics with the default prometheus registry.
func RegisterAPI() {
	prometheus.MustRegister(APIRequestsTotal, APIAuthFailures)
}

// Handler returns the prometheus HTTP handler for /metrics.
func Handler() http.Handler {
	return promhttp.Handler()
}
