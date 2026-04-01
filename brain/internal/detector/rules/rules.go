// Package rules implements the YAML rule engine detector plugin for the Brain service.
// It loads detection rules from YAML files, compiles regex patterns, and matches
// incoming events against rule conditions to produce findings.
//
// Each rule maps to OWASP LLM Top 10 and/or MITRE ATLAS frameworks.
// Rules are loaded once at startup; runtime reloads are not yet supported.
package rules

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/shadologai/shadolog/v2/brain/internal/detector"
	"github.com/shadologai/shadolog/v2/shared/models"
)

// RuleFile is the top-level YAML structure.
type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Rule is a single detection rule loaded from YAML.
type Rule struct {
	ID          string       `yaml:"id"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Severity    string       `yaml:"severity"`
	Enabled     bool         `yaml:"enabled"`
	RuleType    string       `yaml:"rule_type"`
	OwaspLLM    []string     `yaml:"owasp_llm"`
	MitreAtlas  *MitreRef    `yaml:"mitre_atlas"`
	Conditions  []Condition  `yaml:"conditions"`

	// compiled holds the compiled regex for content-matching conditions.
	compiled *regexp.Regexp
	// matchEventType / matchAITool hold simple string conditions extracted at load time.
	matchEventType string
	matchAITool    string
}

// MitreRef holds MITRE ATLAS tactic/technique references.
type MitreRef struct {
	Tactic    string `yaml:"tactic"`
	Technique string `yaml:"technique"`
}

// Condition is a single rule condition from YAML.
type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

// Engine is the rule engine detector implementing detector.Detector.
type Engine struct {
	rules  []Rule
	dir    string
	logger *slog.Logger
}

// New creates a new rule engine detector for the given rules directory.
func New(dir string, logger *slog.Logger) *Engine {
	return &Engine{
		dir:    dir,
		logger: logger,
	}
}

// Info returns the detector metadata.
func (e *Engine) Info() detector.Info {
	return detector.Info{
		ID:         "rules",
		Name:       "Rule Engine",
		Priority:   detector.PriorityHigh,
		Enabled:    true,
		Blocking:   false,
		Categories: []string{"injection", "shadow_ai", "exfiltration", "compliance", "anomaly"},
		Frameworks: []string{"owasp_llm", "mitre_atlas"},
	}
}

// Init loads and compiles all YAML rules from the configured directory.
func (e *Engine) Init(_ context.Context, _ map[string]any) error {
	rules, err := LoadRulesFromDir(e.dir)
	if err != nil {
		return fmt.Errorf("rule engine init: %w", err)
	}
	e.rules = rules
	e.logger.Info("rule engine initialized", "rules_loaded", len(e.rules), "dir", e.dir)
	return nil
}

// LoadRulesFromDir reads all *.yaml files from a directory and parses them as rules.
// Returns the flattened list of all enabled rules with compiled regex patterns.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %s: %w", dir, err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", path, err)
		}

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse rule file %s: %w", path, err)
		}

		for i := range rf.Rules {
			r := &rf.Rules[i]
			if !r.Enabled {
				continue
			}

			// Extract simple conditions and compile regex patterns.
			for _, cond := range r.Conditions {
				valStr, ok := cond.Value.(string)
				switch {
				case cond.Operator == "regex_match" && ok:
					compiled, err := regexp.Compile(valStr)
					if err != nil {
						return nil, fmt.Errorf("rule %s: invalid regex in condition: %w", r.ID, err)
					}
					r.compiled = compiled
				case cond.Field == "event_type" && ok:
					r.matchEventType = valStr
				case cond.Field == "ai_tool" && ok:
					r.matchAITool = valStr
				}
			}

			allRules = append(allRules, *r)
		}
	}

	return allRules, nil
}

// CountRulesInDir reads all *.yaml files from a directory and returns the count
// of enabled rules. Used by main.go for startup validation.
func CountRulesInDir(dir string) (int, error) {
	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		return 0, err
	}
	return len(rules), nil
}

// Detect checks the event against all loaded rules.
// Returns findings for any rules whose conditions match the event.
func (e *Engine) Detect(_ context.Context, event *models.Event, content string) ([]models.Finding, error) {
	findings := []models.Finding{}

	for _, r := range e.rules {
		if !e.matchesRule(&r, event, content) {
			continue
		}

		var mitreIDs []string
		if r.MitreAtlas != nil && r.MitreAtlas.Technique != "" {
			mitreIDs = []string{r.MitreAtlas.Technique}
		}

		findings = append(findings, models.Finding{
			FindingID:   uuid.New().String(),
			EventID:     event.EventID,
			TenantID:    event.TenantID,
			Timestamp:   time.Now().UTC(),
			RuleID:      r.ID,
			Severity:    r.Severity,
			Category:    r.RuleType,
			Detector:    "rules",
			Confidence:  0.90,
			ActionTaken: "log",
			Narrative:   fmt.Sprintf("Rule %s (%s) matched: %s", r.ID, r.Name, r.Description),
			OwaspIDs:    r.OwaspLLM,
			MitreIDs:    mitreIDs,
			UserID:      event.UserID,
			AITool:      event.AITool,
		})
	}

	return findings, nil
}

// matchesRule checks if all conditions of a rule are satisfied by the event.
func (e *Engine) matchesRule(r *Rule, event *models.Event, content string) bool {
	// If rule specifies event_type, it must match
	if r.matchEventType != "" && !strings.EqualFold(r.matchEventType, event.EventType) {
		return false
	}

	// If rule specifies ai_tool, it must match
	if r.matchAITool != "" && !strings.EqualFold(r.matchAITool, event.AITool) {
		return false
	}

	// If rule has a compiled regex pattern, content must match
	if r.compiled != nil {
		if content == "" || !r.compiled.MatchString(content) {
			return false
		}
	}

	return true
}

// Shutdown is a no-op for the rule engine (no resources to release).
func (e *Engine) Shutdown(_ context.Context) error {
	return nil
}

// Compile-time interface check.
var _ detector.Detector = (*Engine)(nil)
