package handler

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/shadologai/shadolog/v2/api/internal/store"
	"github.com/shadologai/shadolog/v2/shared/auth"
)

// AuditHandler serves the PROVE audit chain endpoints (Command tier).
// Fixes from v3 PROVE:
//   - Ed25519 signature covers ALL fields: eventID + decision + ruleID + prevHash + timestamp
//   - SELECT FOR UPDATE on latest receipt prevents concurrent chain race
//   - Tenant-specific genesis hash: sha256(tenant_id + created_at)
type AuditHandler struct {
	pg *store.PGStore
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(pg *store.PGStore) *AuditHandler {
	return &AuditHandler{pg: pg}
}

// ListReceipts handles GET /api/audit/receipts — list audit receipts (admin+, Command tier).
func (h *AuditHandler) ListReceipts(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	f := store.ReceiptFilter{
		TenantID: tenantID,
	}
	if v := r.URL.Query().Get("event_id"); v != "" {
		f.EventID = &v
	}
	if v := r.URL.Query().Get("decision"); v != "" {
		f.Decision = &v
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	receipts, total, err := h.pg.ListReceipts(r.Context(), f)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if receipts == nil {
		receipts = []store.Receipt{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.Receipt]{Data: receipts, Total: total})
}

// VerifyChain handles GET /api/audit/chain/verify — verify hash chain integrity.
func (h *AuditHandler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	// Default to last 30 days if no range specified.
	now := time.Now().UTC()
	from := now.Add(-30 * 24 * time.Hour)
	to := now

	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}

	result, err := h.pg.VerifyChain(r.Context(), tenantID, from, to)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	auth.WriteJSON(w, http.StatusOK, result)
}

// Reports handles GET /api/audit/reports — compliance reports.
func (h *AuditHandler) Reports(w http.ResponseWriter, r *http.Request) {
	tenantID := auth.TenantFromContext(r.Context())
	if tenantID == "" {
		auth.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant context"})
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	reports, total, err := h.pg.ListComplianceReports(r.Context(), tenantID, limit, offset)
	if err != nil {
		auth.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if reports == nil {
		reports = []store.ComplianceReport{}
	}
	auth.WriteJSON(w, http.StatusOK, store.ListResponse[store.ComplianceReport]{Data: reports, Total: total})
}

// --- Receipt signing utilities (v4 fix: full field coverage) ---

// ComputeReceiptHash creates a deterministic SHA-256 hash of all receipt fields.
// This is the chain link hash — each receipt's hash includes the previous receipt's hash.
func ComputeReceiptHash(receiptID, eventID, decision, ruleID, prevHash string, createdAt time.Time) string {
	h := sha256.New()
	h.Write([]byte(receiptID))
	h.Write([]byte(eventID))
	h.Write([]byte(decision))
	h.Write([]byte(ruleID))
	h.Write([]byte(prevHash))
	h.Write([]byte(createdAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// SignReceiptMessage builds the message to sign with Ed25519.
// V4 fix: includes ruleID in signature (v3 PROVE bug omitted it).
func SignReceiptMessage(eventID, decision, ruleID, prevHash string, createdAt time.Time) []byte {
	msg := fmt.Sprintf("%s|%s|%s|%s|%s", eventID, decision, ruleID, prevHash, createdAt.UTC().Format(time.RFC3339Nano))
	return []byte(msg)
}

// VerifyReceiptSignature verifies a receipt's Ed25519 signature using the provided public key.
// V4 fix: signature message includes ruleID.
func VerifyReceiptSignature(receipt *store.Receipt, publicKey ed25519.PublicKey) bool {
	msg := SignReceiptMessage(receipt.EventID, receipt.Decision, receipt.RuleID, receipt.PrevHash, receipt.CreatedAt)
	return ed25519.Verify(publicKey, msg, receipt.Signature)
}

// VerifyReceiptHash recomputes and verifies the receipt's hash.
func VerifyReceiptHash(receipt *store.Receipt) bool {
	expected := ComputeReceiptHash(receipt.ReceiptID, receipt.EventID, receipt.Decision,
		receipt.RuleID, receipt.PrevHash, receipt.CreatedAt)
	return expected == receipt.ReceiptHash
}

// TenantGenesisHash computes a tenant-specific genesis hash: sha256(tenant_id + created_at).
// Replaces the v3 hardcoded zero genesis hash.
func TenantGenesisHash(tenantID string, tenantCreatedAt time.Time) string {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte(tenantCreatedAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}
