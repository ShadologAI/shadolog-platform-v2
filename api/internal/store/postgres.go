package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore provides tenant-scoped access to the PostgreSQL database.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PGStore from an existing connection pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// Pool returns the underlying connection pool.
func (s *PGStore) Pool() *pgxpool.Pool { return s.pool }

// Ping checks database connectivity.
func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

const tenantColumns = `tenant_id, slug, name, tier, cloud_provider, region,
	status, data_plane_status, data_plane_endpoint, enforcement_mode,
	enabled_packs, onboarding_step, firebase_uid, created_at, updated_at`

func scanTenant(row pgx.Row) (*Tenant, error) {
	var t Tenant
	err := row.Scan(
		&t.TenantID, &t.Slug, &t.Name, &t.Tier, &t.CloudProvider, &t.Region,
		&t.Status, &t.DataPlaneStatus, &t.DataPlaneEndpoint, &t.EnforcementMode,
		&t.EnabledPacks, &t.OnboardingStep, &t.FirebaseUID, &t.CreatedAt, &t.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTenants returns paginated tenants.
func (s *PGStore) ListTenants(ctx context.Context, limit, offset int) ([]Tenant, int, error) {
	var total int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		fmt.Sprintf("SELECT %s FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2", tenantColumns),
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(
			&t.TenantID, &t.Slug, &t.Name, &t.Tier, &t.CloudProvider, &t.Region,
			&t.Status, &t.DataPlaneStatus, &t.DataPlaneEndpoint, &t.EnforcementMode,
			&t.EnabledPacks, &t.OnboardingStep, &t.FirebaseUID, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, total, rows.Err()
}

// GetTenant returns a single tenant by ID.
func (s *PGStore) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf("SELECT %s FROM tenants WHERE tenant_id = $1", tenantColumns),
		tenantID)
	return scanTenant(row)
}

// CreateTenant inserts a new tenant.
func (s *PGStore) CreateTenant(ctx context.Context, req CreateTenantRequest) (*Tenant, error) {
	packs := req.EnabledPacks
	if packs == nil {
		packs = []string{}
	}
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO tenants (slug, name, tier, cloud_provider, region, enabled_packs, firebase_uid)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING %s`, tenantColumns),
		req.Slug, req.Name, req.Tier, req.CloudProvider, req.Region, packs, req.FirebaseUID,
	)
	return scanTenant(row)
}

// ---------------------------------------------------------------------------
// Entities (unified graph model)
// ---------------------------------------------------------------------------

// ListEntities returns paginated entities for a tenant.
func (s *PGStore) ListEntities(ctx context.Context, f EntityFilter) ([]Entity, int, error) {
	clauses := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.Type != nil {
		clauses = append(clauses, fmt.Sprintf("type = $%d", idx))
		args = append(args, *f.Type)
		idx++
	}
	if f.Status != nil {
		clauses = append(clauses, fmt.Sprintf("status = $%d", idx))
		args = append(args, *f.Status)
		idx++
	}
	if f.SourcePlane != nil {
		clauses = append(clauses, fmt.Sprintf("source_plane = $%d", idx))
		args = append(args, *f.SourcePlane)
		idx++
	}
	if f.MinRisk != nil {
		clauses = append(clauses, fmt.Sprintf("risk_score >= $%d", idx))
		args = append(args, *f.MinRisk)
		idx++
	}

	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM entities "+where, args...,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count entities: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	query := fmt.Sprintf(
		`SELECT entity_id, tenant_id, type, name, metadata, risk_score, status,
		        source_plane, first_seen_at, last_seen_at
		 FROM entities %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		where, idx, idx+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list entities: %w", err)
	}
	defer rows.Close()

	var entities []Entity
	for rows.Next() {
		var e Entity
		if err := rows.Scan(
			&e.EntityID, &e.TenantID, &e.Type, &e.Name, &e.Metadata, &e.RiskScore,
			&e.Status, &e.SourcePlane, &e.FirstSeenAt, &e.LastSeenAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan entity: %w", err)
		}
		entities = append(entities, e)
	}
	return entities, total, rows.Err()
}

// ---------------------------------------------------------------------------
// Relationships (unified graph model)
// ---------------------------------------------------------------------------

// ListRelationships returns paginated relationships for a tenant.
func (s *PGStore) ListRelationships(ctx context.Context, f RelationshipFilter) ([]Relationship, int, error) {
	clauses := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.SourceID != nil {
		clauses = append(clauses, fmt.Sprintf("source_id = $%d", idx))
		args = append(args, *f.SourceID)
		idx++
	}
	if f.TargetID != nil {
		clauses = append(clauses, fmt.Sprintf("target_id = $%d", idx))
		args = append(args, *f.TargetID)
		idx++
	}
	if f.EntityID != nil {
		clauses = append(clauses, fmt.Sprintf("(source_id = $%d OR target_id = $%d)", idx, idx+1))
		args = append(args, *f.EntityID, *f.EntityID)
		idx += 2
	}
	if f.Type != nil {
		clauses = append(clauses, fmt.Sprintf("type = $%d", idx))
		args = append(args, *f.Type)
		idx++
	}
	if f.RiskLevel != nil {
		clauses = append(clauses, fmt.Sprintf("risk_level = $%d", idx))
		args = append(args, *f.RiskLevel)
		idx++
	}

	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM relationships "+where, args...,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count relationships: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	query := fmt.Sprintf(
		`SELECT relationship_id, tenant_id, source_id, target_id, type,
		        metadata, request_count, risk_level, first_seen_at, last_seen_at
		 FROM relationships %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		where, idx, idx+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list relationships: %w", err)
	}
	defer rows.Close()

	var rels []Relationship
	for rows.Next() {
		var r Relationship
		if err := rows.Scan(
			&r.RelationshipID, &r.TenantID, &r.SourceID, &r.TargetID, &r.Type,
			&r.Metadata, &r.RequestCount, &r.RiskLevel, &r.FirstSeenAt, &r.LastSeenAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan relationship: %w", err)
		}
		rels = append(rels, r)
	}
	return rels, total, rows.Err()
}

// ---------------------------------------------------------------------------
// Admin overview
// ---------------------------------------------------------------------------

// AdminOverview holds aggregate stats for GET /api/admin/overview.
type AdminOverview struct {
	TotalTenants  int `json:"total_tenants"`
	ActiveTenants int `json:"active_tenants"`
	TotalAgents   int `json:"total_agents"`
	TotalEntities int `json:"total_entities"`
}

// GetAdminOverview returns platform-wide stats.
func (s *PGStore) GetAdminOverview(ctx context.Context) (*AdminOverview, error) {
	o := &AdminOverview{}

	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&o.TotalTenants)
	if err != nil {
		return nil, fmt.Errorf("count tenants: %w", err)
	}

	err = s.pool.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE status = 'active'").Scan(&o.ActiveTenants)
	if err != nil {
		return nil, fmt.Errorf("count active tenants: %w", err)
	}

	// Agents count — graceful if table doesn't exist yet.
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM agents").Scan(&o.TotalAgents)

	// Entities count — graceful if table doesn't exist yet.
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM entities").Scan(&o.TotalEntities)

	return o, nil
}

// ListTenantsWithStats returns tenants with aggregate usage counts for admin views.
func (s *PGStore) ListTenantsWithStats(ctx context.Context, limit, offset int) ([]map[string]any, int, error) {
	var total int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT t.tenant_id, t.slug, t.name, t.tier, t.status,
		        t.enforcement_mode, t.created_at,
		        COALESCE((SELECT count(*) FROM agents a WHERE a.tenant_id = t.tenant_id), 0) AS agent_count,
		        COALESCE((SELECT count(*) FROM entities e WHERE e.tenant_id = t.tenant_id), 0) AS entity_count
		 FROM tenants t
		 ORDER BY t.created_at DESC
		 LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants with stats: %w", err)
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var tenantID, slug, name, tier, status, enfMode string
		var createdAt interface{}
		var agentCount, entityCount int
		if err := rows.Scan(&tenantID, &slug, &name, &tier, &status, &enfMode, &createdAt,
			&agentCount, &entityCount); err != nil {
			return nil, 0, fmt.Errorf("scan tenant stats: %w", err)
		}
		results = append(results, map[string]any{
			"tenant_id":        tenantID,
			"slug":             slug,
			"name":             name,
			"tier":             tier,
			"status":           status,
			"enforcement_mode": enfMode,
			"created_at":       createdAt,
			"agent_count":      agentCount,
			"entity_count":     entityCount,
		})
	}
	return results, total, rows.Err()
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

const policyColumns = `policy_id, tenant_id, name, description, policy_type, enforcement,
	rules, severity, enabled, owasp_ids, mitre_ids, created_by, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var rulesJSON []byte
	err := row.Scan(
		&p.PolicyID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Enforcement,
		&rulesJSON, &p.Severity, &p.Enabled, &p.OwaspIDs, &p.MitreIDs,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Rules = rulesJSON
	return &p, nil
}

// ListPolicies returns filtered, paginated policies for a tenant.
func (s *PGStore) ListPolicies(ctx context.Context, f PolicyFilter) ([]Policy, int, error) {
	clauses := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.PolicyType != nil {
		clauses = append(clauses, fmt.Sprintf("policy_type = $%d", idx))
		args = append(args, *f.PolicyType)
		idx++
	}
	if f.Enforcement != nil {
		clauses = append(clauses, fmt.Sprintf("enforcement = $%d", idx))
		args = append(args, *f.Enforcement)
		idx++
	}
	if f.Severity != nil {
		clauses = append(clauses, fmt.Sprintf("severity = $%d", idx))
		args = append(args, *f.Severity)
		idx++
	}
	if f.Enabled != nil {
		clauses = append(clauses, fmt.Sprintf("enabled = $%d", idx))
		args = append(args, *f.Enabled)
		idx++
	}

	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM policies "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count policies: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	query := fmt.Sprintf(
		`SELECT %s FROM policies %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		policyColumns, where, idx, idx+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		var rulesJSON []byte
		if err := rows.Scan(
			&p.PolicyID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Enforcement,
			&rulesJSON, &p.Severity, &p.Enabled, &p.OwaspIDs, &p.MitreIDs,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan policy: %w", err)
		}
		p.Rules = rulesJSON
		policies = append(policies, p)
	}
	return policies, total, rows.Err()
}

// GetPolicy returns a single policy by ID (tenant-scoped).
func (s *PGStore) GetPolicy(ctx context.Context, tenantID, policyID string) (*Policy, error) {
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf("SELECT %s FROM policies WHERE tenant_id = $1 AND policy_id = $2", policyColumns),
		tenantID, policyID)
	return scanPolicy(row)
}

// CreatePolicy inserts a new policy and returns the created row.
func (s *PGStore) CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*Policy, error) {
	rulesJSON := req.Rules
	if rulesJSON == nil {
		rulesJSON = []byte("[]")
	}

	severity := req.Severity
	if severity == "" {
		severity = "medium"
	}

	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`INSERT INTO policies (tenant_id, name, description, policy_type, enforcement, rules, severity, owasp_ids, mitre_ids, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING %s`, policyColumns),
		tenantID, req.Name, req.Description, req.PolicyType, req.Enforcement, rulesJSON,
		severity, req.OwaspIDs, req.MitreIDs, createdBy,
	)
	return scanPolicy(row)
}

// UpdatePolicy applies a partial update to a policy.
func (s *PGStore) UpdatePolicy(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest) error {
	var rulesJSON []byte
	if req.Rules != nil {
		rulesJSON = req.Rules
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE policies SET
			name = COALESCE($3, name),
			description = COALESCE($4, description),
			enforcement = COALESCE($5, enforcement),
			rules = COALESCE($6, rules),
			severity = COALESCE($7, severity),
			enabled = COALESCE($8, enabled),
			updated_at = NOW()
		WHERE tenant_id = $1 AND policy_id = $2`,
		tenantID, policyID, req.Name, req.Description, req.Enforcement, rulesJSON, req.Severity, req.Enabled)
	return err
}

// DeletePolicy removes a policy by ID (tenant-scoped).
func (s *PGStore) DeletePolicy(ctx context.Context, tenantID, policyID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM policies WHERE tenant_id = $1 AND policy_id = $2`, tenantID, policyID)
	return err
}

// ListPolicyVersions returns version history for policies (optionally filtered by policy_id).
func (s *PGStore) ListPolicyVersions(ctx context.Context, tenantID, policyID string, limit, offset int) ([]PolicyVersion, int, error) {
	clauses := []string{"tenant_id = $1"}
	args := []any{tenantID}
	idx := 2

	if policyID != "" {
		clauses = append(clauses, fmt.Sprintf("policy_id = $%d", idx))
		args = append(args, policyID)
		idx++
	}

	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM policy_versions "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count policy versions: %w", err)
	}

	args = append(args, limit, offset)

	query := fmt.Sprintf(
		`SELECT version_id, policy_id, tenant_id, version_number, name, description,
		        policy_type, enforcement, rules, severity, enabled, owasp_ids, mitre_ids,
		        change_summary, changed_by, created_at
		 FROM policy_versions %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, idx, idx+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list policy versions: %w", err)
	}
	defer rows.Close()

	var versions []PolicyVersion
	for rows.Next() {
		var v PolicyVersion
		var rulesJSON []byte
		if err := rows.Scan(
			&v.VersionID, &v.PolicyID, &v.TenantID, &v.VersionNumber, &v.Name, &v.Description,
			&v.PolicyType, &v.Enforcement, &rulesJSON, &v.Severity, &v.Enabled, &v.OwaspIDs, &v.MitreIDs,
			&v.ChangeSummary, &v.ChangedBy, &v.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan policy version: %w", err)
		}
		v.Rules = rulesJSON
		versions = append(versions, v)
	}
	return versions, total, rows.Err()
}

// ---------------------------------------------------------------------------
// Audit Receipts (PROVE chain)
// ---------------------------------------------------------------------------

// ListReceipts returns filtered, paginated audit receipts for a tenant.
func (s *PGStore) ListReceipts(ctx context.Context, f ReceiptFilter) ([]Receipt, int, error) {
	clauses := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.EventID != nil {
		clauses = append(clauses, fmt.Sprintf("event_id = $%d", idx))
		args = append(args, *f.EventID)
		idx++
	}
	if f.Decision != nil {
		clauses = append(clauses, fmt.Sprintf("decision = $%d", idx))
		args = append(args, *f.Decision)
		idx++
	}
	if f.Since != nil {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *f.Since)
		idx++
	}
	if f.Until != nil {
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *f.Until)
		idx++
	}

	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM audit_receipts "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count receipts: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	query := fmt.Sprintf(
		`SELECT receipt_id, tenant_id, event_id, decision, rule_id,
		        prev_hash, receipt_hash, signature, signing_key_id, created_at
		 FROM audit_receipts %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, idx, idx+1)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list receipts: %w", err)
	}
	defer rows.Close()

	var receipts []Receipt
	for rows.Next() {
		var r Receipt
		if err := rows.Scan(
			&r.ReceiptID, &r.TenantID, &r.EventID, &r.Decision, &r.RuleID,
			&r.PrevHash, &r.ReceiptHash, &r.Signature, &r.SigningKeyID, &r.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan receipt: %w", err)
		}
		receipts = append(receipts, r)
	}
	return receipts, total, rows.Err()
}

// GetLatestReceipt returns the latest receipt for a tenant using SELECT FOR UPDATE
// to prevent concurrent chain race conditions.
func (s *PGStore) GetLatestReceipt(ctx context.Context, tx pgx.Tx, tenantID string) (*Receipt, error) {
	var r Receipt
	err := tx.QueryRow(ctx, `
		SELECT receipt_id, tenant_id, event_id, decision, rule_id,
		       prev_hash, receipt_hash, signature, signing_key_id, created_at
		FROM audit_receipts
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE`, tenantID).Scan(
		&r.ReceiptID, &r.TenantID, &r.EventID, &r.Decision, &r.RuleID,
		&r.PrevHash, &r.ReceiptHash, &r.Signature, &r.SigningKeyID, &r.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest receipt: %w", err)
	}
	return &r, nil
}

// InsertReceipt inserts a new audit receipt within an existing transaction.
func (s *PGStore) InsertReceipt(ctx context.Context, tx pgx.Tx, r *Receipt) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_receipts (receipt_id, tenant_id, event_id, decision, rule_id,
		                            prev_hash, receipt_hash, signature, signing_key_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.ReceiptID, r.TenantID, r.EventID, r.Decision, r.RuleID,
		r.PrevHash, r.ReceiptHash, r.Signature, r.SigningKeyID, r.CreatedAt,
	)
	return err
}

// BeginTx starts a new database transaction.
func (s *PGStore) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.pool.Begin(ctx)
}

// VerifyChain walks the receipt chain for a tenant within a time range,
// verifying hash linkage and receipt hash integrity.
func (s *PGStore) VerifyChain(ctx context.Context, tenantID string, from, to time.Time) (*VerifyResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT receipt_id, tenant_id, event_id, decision, rule_id,
		       prev_hash, receipt_hash, signature, signing_key_id, created_at
		FROM audit_receipts
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY created_at ASC`, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query receipts for verification: %w", err)
	}
	defer rows.Close()

	var receipts []Receipt
	for rows.Next() {
		var r Receipt
		if err := rows.Scan(
			&r.ReceiptID, &r.TenantID, &r.EventID, &r.Decision, &r.RuleID,
			&r.PrevHash, &r.ReceiptHash, &r.Signature, &r.SigningKeyID, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan receipt for verification: %w", err)
		}
		receipts = append(receipts, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &VerifyResult{
		ReceiptsChecked: int64(len(receipts)),
	}

	var prevHash string
	for i, r := range receipts {
		valid := true

		// Verify hash linkage (skip first — it links to whatever came before our window).
		if i > 0 && r.PrevHash != prevHash {
			valid = false
			result.Breaks = append(result.Breaks, ChainBreak{
				ReceiptID:        r.ReceiptID,
				ExpectedPrevHash: prevHash,
				ActualPrevHash:   r.PrevHash,
				DetectedAt:       time.Now().UTC(),
			})
		}

		// Verify receipt hash integrity by recomputing.
		expectedHash := computeReceiptHash(r.ReceiptID, r.EventID, r.Decision, r.RuleID, r.PrevHash, r.CreatedAt)
		if expectedHash != r.ReceiptHash {
			valid = false
			result.Breaks = append(result.Breaks, ChainBreak{
				ReceiptID:        r.ReceiptID,
				ExpectedPrevHash: "HASH_MISMATCH",
				ActualPrevHash:   r.ReceiptHash,
				DetectedAt:       time.Now().UTC(),
			})
		}

		if valid {
			result.ReceiptsValid++
		}
		prevHash = r.ReceiptHash
	}

	result.ChainValid = len(result.Breaks) == 0
	return result, nil
}

// computeReceiptHash creates a deterministic SHA-256 hash of all receipt fields.
func computeReceiptHash(receiptID, eventID, decision, ruleID, prevHash string, createdAt time.Time) string {
	h := sha256.New()
	h.Write([]byte(receiptID))
	h.Write([]byte(eventID))
	h.Write([]byte(decision))
	h.Write([]byte(ruleID))
	h.Write([]byte(prevHash))
	h.Write([]byte(createdAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Compliance Reports
// ---------------------------------------------------------------------------

// ListComplianceReports returns paginated compliance reports for a tenant.
func (s *PGStore) ListComplianceReports(ctx context.Context, tenantID string, limit, offset int) ([]ComplianceReport, int, error) {
	var total int
	err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM compliance_reports WHERE tenant_id = $1", tenantID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count compliance reports: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT report_id, tenant_id, report_type, framework, status, summary, generated_by, created_at
		FROM compliance_reports
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list compliance reports: %w", err)
	}
	defer rows.Close()

	var reports []ComplianceReport
	for rows.Next() {
		var r ComplianceReport
		if err := rows.Scan(
			&r.ReportID, &r.TenantID, &r.ReportType, &r.Framework, &r.Status,
			&r.Summary, &r.GeneratedBy, &r.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan compliance report: %w", err)
		}
		reports = append(reports, r)
	}
	return reports, total, rows.Err()
}
