package dlp

import (
	"context"
	"strings"
	"testing"

	"github.com/shadologai/shadolog/v2/shared/models"
)

func newTestScanner(t *testing.T) *Scanner {
	t.Helper()
	s := New()
	if err := s.Init(context.Background(), nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return s
}

func testEvent() *models.Event {
	return &models.Event{
		EventID:   "evt-test-001",
		TenantID:  "00000000-0000-0000-0000-000000000001",
		Direction: "prompt",
		UserID:    "user-1",
		AITool:    "chatgpt",
	}
}

func TestDetect_SSN(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "My SSN is 123-45-6789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != "pii" {
		t.Errorf("expected category pii, got %s", f.Category)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
	if f.Detector != "dlp" {
		t.Errorf("expected detector dlp, got %s", f.Detector)
	}
	if f.RedactedPreview != "***-**-6789" {
		t.Errorf("expected redacted ***-**-6789, got %s", f.RedactedPreview)
	}
	if f.FindingID == "" {
		t.Error("finding_id must not be empty")
	}
	if len(f.OwaspIDs) == 0 || f.OwaspIDs[0] != "LLM06" {
		t.Errorf("expected owasp_ids [LLM06], got %v", f.OwaspIDs)
	}
}

func TestDetect_NoMatch(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "Hello, this is a safe message with no secrets.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings == nil {
		t.Fatal("findings must not be nil (must be empty slice)")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetect_EmptyContent(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings == nil {
		t.Fatal("findings must not be nil for empty content")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty content, got %d", len(findings))
	}
}

func TestDetect_OversizedContent(t *testing.T) {
	s := newTestScanner(t)
	// 1 MB + 1 byte: should be skipped
	oversized := strings.Repeat("a", maxScanSize+1)
	findings, err := s.Detect(context.Background(), testEvent(), oversized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings == nil {
		t.Fatal("findings must not be nil for oversized content")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for oversized content, got %d", len(findings))
	}
}

func TestDetect_Multiple_SSN_And_AWSKey(t *testing.T) {
	s := newTestScanner(t)
	content := "SSN: 123-45-6789, Key: AKIAIOSFODNN7EXAMPLE"
	findings, err := s.Detect(context.Background(), testEvent(), content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	categories := map[string]bool{}
	for _, f := range findings {
		categories[f.Category] = true
		if f.Detector != "dlp" {
			t.Errorf("expected detector dlp, got %s", f.Detector)
		}
	}
	if !categories["pii"] {
		t.Error("expected pii category finding")
	}
	if !categories["credential"] {
		t.Error("expected credential category finding")
	}
}

func TestDetect_CreditCard(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "Card: 4111111111111111")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RedactedPreview != "****-****-****-1111" {
		t.Errorf("expected redacted ****-****-****-1111, got %s", findings[0].RedactedPreview)
	}
}

func TestDetect_PrivateKey(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "-----BEGIN RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", findings[0].Severity)
	}
}

func TestDetect_ConnectionString(t *testing.T) {
	s := newTestScanner(t)
	findings, err := s.Detect(context.Background(), testEvent(), "postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 1 {
		t.Fatal("expected at least 1 finding for connection string")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "dlp.connection_string" {
			found = true
		}
	}
	if !found {
		t.Error("expected connection_string finding")
	}
}

func TestInfo(t *testing.T) {
	s := New()
	info := s.Info()
	if info.ID != "dlp" {
		t.Errorf("expected ID dlp, got %s", info.ID)
	}
	if info.Priority != 0 {
		t.Errorf("expected PriorityBlocking (0), got %d", info.Priority)
	}
	if !info.Blocking {
		t.Error("expected Blocking=true")
	}
	if !info.Enabled {
		t.Error("expected Enabled=true")
	}
}
