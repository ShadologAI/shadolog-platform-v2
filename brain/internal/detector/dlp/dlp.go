// Package dlp implements a regex-based Data Loss Prevention detector plugin.
// It scans event content for PII (SSN, credit cards, emails), credentials
// (AWS keys, API keys, tokens), and secrets (private keys, connection strings).
//
// Ported from v3 services/learn DLP scanner + services/enforce Rust patterns.
// All patterns map to OWASP LLM Top 10 LLM06 (Sensitive Information Disclosure).
//
// Design decisions:
//   - Always returns empty slice, never nil (fixes v3 nil-dereference bug)
//   - Skips content > 1 MB (ReDoS protection)
//   - Each finding includes UUID, severity, category, OWASP mapping, redacted preview
package dlp

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/shadologai/shadolog/v2/brain/internal/detector"
	"github.com/shadologai/shadolog/v2/shared/models"
)

// maxScanSize is the maximum input size in bytes. Inputs exceeding this
// are skipped to prevent ReDoS and resource exhaustion.
const maxScanSize = 1024 * 1024 // 1 MB

// pattern defines a single DLP regex pattern with metadata.
type pattern struct {
	name       string
	category   string   // pii, credential, secret
	severity   string   // critical, high, medium, low
	owaspIDs   []string // OWASP LLM Top 10 IDs
	confidence float32
	regex      *regexp.Regexp
	redact     func(match string) string
}

// Scanner is the DLP detector plugin implementing detector.Detector.
type Scanner struct {
	patterns []pattern
}

// New creates a new DLP Scanner. Call Init() before use.
func New() *Scanner {
	return &Scanner{}
}

// Info returns the detector metadata.
func (s *Scanner) Info() detector.Info {
	return detector.Info{
		ID:         "dlp",
		Name:       "DLP Scanner",
		Priority:   detector.PriorityBlocking,
		Enabled:    true,
		Blocking:   true,
		Categories: []string{"pii", "credential", "secret"},
		Frameworks: []string{"owasp_llm"},
	}
}

// Init compiles all regex patterns. Must be called before Detect.
func (s *Scanner) Init(_ context.Context, _ map[string]any) error {
	s.patterns = []pattern{
		// ── PII ────────────────────────────────────────────────
		{
			name:       "ssn_us",
			category:   "pii",
			severity:   "high",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.95,
			regex:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			redact: func(m string) string {
				if len(m) >= 4 {
					return fmt.Sprintf("***-**-%s", m[len(m)-4:])
				}
				return "***-**-****"
			},
		},
		{
			name:       "credit_card",
			category:   "pii",
			severity:   "high",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.90,
			regex:      regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
			redact: func(m string) string {
				if len(m) >= 4 {
					return fmt.Sprintf("****-****-****-%s", m[len(m)-4:])
				}
				return "****-****-****-****"
			},
		},
		{
			name:       "email",
			category:   "pii",
			severity:   "medium",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.85,
			regex:      regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			redact:     func(_ string) string { return "***@***" },
		},
		// ── Credentials ───────────────────────────────────────
		{
			name:       "aws_access_key",
			category:   "credential",
			severity:   "critical",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.98,
			regex:      regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			redact:     func(_ string) string { return "AKIA****" },
		},
		{
			name:       "openai_api_key",
			category:   "credential",
			severity:   "critical",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.98,
			regex:      regexp.MustCompile(`\bsk-(?:proj-)?[a-zA-Z0-9]{20,}\b`),
			redact:     func(_ string) string { return "sk-****" },
		},
		{
			name:       "anthropic_api_key",
			category:   "credential",
			severity:   "critical",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.98,
			regex:      regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9\-]{20,}\b`),
			redact:     func(_ string) string { return "sk-ant-****" },
		},
		{
			name:       "github_token",
			category:   "credential",
			severity:   "critical",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.97,
			regex:      regexp.MustCompile(`\b(?:ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36,}\b`),
			redact: func(m string) string {
				if len(m) >= 4 {
					return fmt.Sprintf("%s****", m[:4])
				}
				return "****"
			},
		},
		{
			name:       "private_key",
			category:   "secret",
			severity:   "critical",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.99,
			regex:      regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
			redact:     func(_ string) string { return "[PRIVATE KEY REDACTED]" },
		},
		{
			name:       "connection_string",
			category:   "secret",
			severity:   "high",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.85,
			regex:      regexp.MustCompile(`(?:postgres|mysql|mongodb|redis)://[^\s"']{1,256}:[^\s"']{1,256}@[^\s"']{1,256}`),
			redact:     func(_ string) string { return "[CONNECTION STRING REDACTED]" },
		},
		{
			name:       "bearer_token",
			category:   "credential",
			severity:   "high",
			owaspIDs:   []string{"LLM06"},
			confidence: 0.85,
			regex:      regexp.MustCompile(`\b[Bb]earer\s+[a-zA-Z0-9\-._~+/]+=*\b`),
			redact:     func(_ string) string { return "Bearer ****" },
		},
	}
	return nil
}

// Detect scans the content for sensitive data patterns and returns findings.
// Returns an empty (non-nil) slice when no patterns match or content exceeds
// the 1 MB size limit.
func (s *Scanner) Detect(_ context.Context, event *models.Event, content string) ([]models.Finding, error) {
	// Always return empty slice, never nil.
	findings := []models.Finding{}

	if content == "" {
		return findings, nil
	}

	// ReDoS protection: skip oversized inputs.
	if len(content) > maxScanSize {
		return findings, nil
	}

	now := time.Now().UTC()

	for _, p := range s.patterns {
		matches := p.regex.FindAllString(content, -1)
		for _, match := range matches {
			findings = append(findings, models.Finding{
				FindingID:       uuid.New().String(),
				EventID:         event.EventID,
				TenantID:        event.TenantID,
				Timestamp:       now,
				RuleID:          fmt.Sprintf("dlp.%s", p.name),
				Severity:        p.severity,
				Category:        p.category,
				Detector:        "dlp",
				Confidence:      p.confidence,
				ActionTaken:     "log",
				Narrative:       fmt.Sprintf("DLP: detected %s in %s content", p.name, event.Direction),
				OwaspIDs:        p.owaspIDs,
				RedactedPreview: p.redact(match),
				UserID:          event.UserID,
				AITool:          event.AITool,
			})
		}
	}

	return findings, nil
}

// Shutdown is a no-op for the DLP scanner (no resources to release).
func (s *Scanner) Shutdown(_ context.Context) error {
	return nil
}

// Compile-time interface check.
var _ detector.Detector = (*Scanner)(nil)
