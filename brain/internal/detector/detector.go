// Package detector defines the plugin interface for the Brain detection engine.
// All detection modules (DLP, rules, ML, behavioral) implement the Detector interface.
//
// Pipeline execution order (priority-based):
//
//   Event
//     │
//     ├─▶ DLP Scanner      (PriorityBlocking=0)   — inline, blocks pipeline
//     ├─▶ Rule Engine       (PriorityHigh=100)     — YAML rules, OWASP/MITRE mapped
//     ├─▶ ML Classifier     (PriorityNormal=200)   — optional, fails gracefully
//     ├─▶ Behavioral        (PriorityLow=300)      — anomaly detection, async-safe
//     └─▶ Entity Resolver   (PriorityLow=300)      — graph entity creation/update
//           │
//           ▼
//       Findings []  (always non-nil, may be empty)
package detector

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shadologai/shadolog/v2/shared/models"
)

// Priority determines execution order. Lower runs first.
type Priority int

const (
	PriorityBlocking   Priority = 0
	PriorityHigh       Priority = 100
	PriorityNormal     Priority = 200
	PriorityLow        Priority = 300
	PriorityBackground Priority = 400
)

// Info describes a registered detector.
type Info struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Priority    Priority `json:"priority"`
	Enabled     bool     `json:"enabled"`
	Blocking    bool     `json:"blocking"`
	Categories  []string `json:"categories"`
	Frameworks  []string `json:"frameworks"`
}

// Result holds the output of a single detector run.
type Result struct {
	Findings   []models.Finding
	Latency    time.Duration
	DetectorID string
	Error      error
}

// Detector is the core plugin interface.
type Detector interface {
	Info() Info
	Init(ctx context.Context, config map[string]any) error
	Detect(ctx context.Context, event *models.Event, content string) ([]models.Finding, error)
	Shutdown(ctx context.Context) error
}

// Registry manages detector registration and pipeline execution.
type Registry struct {
	mu        sync.RWMutex
	detectors []Detector
}

// NewRegistry creates an empty detector registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a detector to the registry, maintaining priority order.
func (r *Registry) Register(d Detector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detectors = append(r.detectors, d)
	sort.Slice(r.detectors, func(i, j int) bool {
		return r.detectors[i].Info().Priority < r.detectors[j].Info().Priority
	})
}

// Count returns the number of registered detectors.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.detectors)
}

// RunAll executes all detectors in priority order against an event.
// Returns all findings aggregated across detectors.
// Key design decisions:
//   - Always returns non-nil slice (never nil — fixes v3 DLP nil bug)
//   - ML/behavioral errors are logged but don't stop the pipeline
//   - Blocking detectors (DLP) run synchronously; low-priority can be parallel
func (r *Registry) RunAll(ctx context.Context, event *models.Event, content string) []Result {
	r.mu.RLock()
	detectors := make([]Detector, len(r.detectors))
	copy(detectors, r.detectors)
	r.mu.RUnlock()

	results := make([]Result, 0, len(detectors))
	for _, d := range detectors {
		info := d.Info()
		if !info.Enabled {
			continue
		}

		start := time.Now()
		findings, err := d.Detect(ctx, event, content)
		latency := time.Since(start)

		// Never return nil findings — always empty slice
		if findings == nil {
			findings = []models.Finding{}
		}

		results = append(results, Result{
			Findings:   findings,
			Latency:    latency,
			DetectorID: info.ID,
			Error:      err,
		})
	}

	return results
}

// Shutdown calls Shutdown on all registered detectors.
func (r *Registry) Shutdown(ctx context.Context) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.detectors {
		d.Shutdown(ctx)
	}
}
