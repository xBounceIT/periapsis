package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/worker/internal/auditoperations"
)

const (
	claimTenantAuditExportSQL = `SELECT job_id,tenant_id,normalized_filter,projection_version,format,object_key,expires_at,lease_expires_at
FROM app.claim_tenant_audit_export_v1($1,$2,$3,$4)`
	claimPlatformAuditExportSQL = `SELECT job_id,normalized_filter,projection_version,format,object_key,expires_at,lease_expires_at
FROM app.claim_platform_audit_export_v1($1,$2,$3,$4)`
	readTenantAuditExportSQL              = `SELECT sequence,document FROM app.read_tenant_audit_export_page_v1($1,$2,$3,$4,$5)`
	readPlatformAuditExportSQL            = `SELECT sequence,document FROM app.read_platform_audit_export_page_v1($1,$2,$3,$4,$5)`
	finalizeTenantAuditExportSQL          = `SELECT app.finalize_tenant_audit_export_v1($1,$2,$3,$4,$5,$6,$7,$8)`
	finalizePlatformAuditExportSQL        = `SELECT app.finalize_platform_audit_export_v1($1,$2,$3,$4,$5,$6,$7,$8)`
	listTenantAuditRetentionCandidatesSQL = `SELECT tenant_id FROM app.list_tenant_audit_retention_candidates_v1($1,$2)`
	getTenantAuditRetentionWorkSQL        = `SELECT segment_id,tenant_id,state,revision,start_sequence,end_sequence,previous_hash,end_hash,event_count,object_key,digest,bytes,signing_key_id,signature
FROM app.get_tenant_audit_retention_work_v1($1,$2)`
	getPlatformAuditRetentionWorkSQL = `SELECT segment_id,state,revision,start_sequence,end_sequence,previous_hash,end_hash,event_count,object_key,digest,bytes,signing_key_id,signature
FROM app.get_platform_audit_retention_work_v1($1)`
	closeTenantAuditSegmentSQL = `SELECT segment_id,tenant_id,start_sequence,end_sequence,previous_hash,end_hash,event_count,object_key
FROM app.close_tenant_audit_segment_v1($1,$2,$3,$4,$5)`
	closePlatformAuditSegmentSQL = `SELECT segment_id,start_sequence,end_sequence,previous_hash,end_hash,event_count,object_key
FROM app.close_platform_audit_segment_v1($1,$2,$3,$4)`
	readTenantAuditSegmentSQL       = `SELECT sequence,document FROM app.read_tenant_audit_segment_page_v1($1,$2,$3,$4,$5)`
	readPlatformAuditSegmentSQL     = `SELECT sequence,document FROM app.read_platform_audit_segment_page_v1($1,$2,$3,$4)`
	preserveTenantAuditSegmentSQL   = `SELECT app.preserve_tenant_audit_segment_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	preservePlatformAuditSegmentSQL = `SELECT app.preserve_platform_audit_segment_v1($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	pruneTenantAuditSegmentSQL      = `SELECT app.prune_tenant_audit_segment_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	prunePlatformAuditSegmentSQL    = `SELECT app.prune_platform_audit_segment_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	pruneTenantAuditReceiptsSQL     = `SELECT app.prune_tenant_audit_operation_receipts_v1($1,$2,$3,$4,$5)`
	prunePlatformAuditReceiptsSQL   = `SELECT app.prune_platform_audit_operation_receipts_v1($1,$2,$3,$4)`
)

type auditOperationsQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type AuditOperationsRepository struct {
	pool auditOperationsQuerier
}

func NewAuditOperationsRepository(pool auditOperationsQuerier) *AuditOperationsRepository {
	return &AuditOperationsRepository{pool: pool}
}

func (repository *AuditOperationsRepository) ClaimExport(ctx context.Context, stream auditoperations.Stream,
	workerID uuid.UUID, fence [32]byte, lease time.Duration, auditID uuid.UUID) (auditoperations.ExportClaim, bool, error) {
	if repository == nil || repository.pool == nil {
		return auditoperations.ExportClaim{}, false, auditoperations.ErrUnavailable
	}
	seconds := int32(lease / time.Second)
	claim := auditoperations.ExportClaim{Stream: stream, WorkerID: workerID, Fence: fence}
	var filter []byte
	var err error
	if stream == auditoperations.TenantStream {
		err = repository.pool.QueryRow(ctx, claimTenantAuditExportSQL, workerID, fence[:], seconds, auditID).Scan(
			&claim.JobID, &claim.TenantID, &filter, &claim.ProjectionVersion, &claim.Format,
			&claim.ObjectKey, &claim.ExpiresAt, &claim.LeaseExpiresAt,
		)
	} else if stream == auditoperations.PlatformStream {
		err = repository.pool.QueryRow(ctx, claimPlatformAuditExportSQL, workerID, fence[:], seconds, auditID).Scan(
			&claim.JobID, &filter, &claim.ProjectionVersion, &claim.Format,
			&claim.ObjectKey, &claim.ExpiresAt, &claim.LeaseExpiresAt,
		)
	} else {
		return auditoperations.ExportClaim{}, false, auditoperations.ErrInvalidInput
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auditoperations.ExportClaim{}, false, nil
	}
	if err != nil {
		return auditoperations.ExportClaim{}, false, err
	}
	claim.NormalizedFilter = append(json.RawMessage(nil), filter...)
	return claim, true, nil
}

func (repository *AuditOperationsRepository) ReadExportPage(ctx context.Context, claim auditoperations.ExportClaim,
	after int64, limit int) ([]auditoperations.PageRow, error) {
	query := readTenantAuditExportSQL
	arguments := []any{claim.WorkerID, claim.JobID, claim.Fence[:], after, int32(limit)}
	if claim.Stream == auditoperations.PlatformStream {
		query = readPlatformAuditExportSQL
	}
	return repository.readPage(ctx, query, arguments...)
}

func (repository *AuditOperationsRepository) FinalizeExport(ctx context.Context, claim auditoperations.ExportClaim,
	artifactID uuid.UUID, digest [32]byte, rows, bytes int64, auditID uuid.UUID) (auditoperations.ExportFinalization, error) {
	query := finalizeTenantAuditExportSQL
	if claim.Stream == auditoperations.PlatformStream {
		query = finalizePlatformAuditExportSQL
	}
	var document []byte
	err := repository.pool.QueryRow(ctx, query, claim.WorkerID, claim.JobID, claim.Fence[:],
		artifactID, digest[:], rows, bytes, auditID).Scan(&document)
	if err != nil {
		return auditoperations.ExportFinalization{}, err
	}
	var result struct {
		State string `json:"state"`
	}
	if len(document) > 64*1024 || json.Unmarshal(document, &result) != nil || result.State == "" {
		return auditoperations.ExportFinalization{}, auditoperations.ErrInvalidProjection
	}
	return auditoperations.ExportFinalization{State: result.State}, nil
}

func (repository *AuditOperationsRepository) ListTenantRetentionCandidates(ctx context.Context,
	workerID uuid.UUID, limit int) ([]uuid.UUID, error) {
	rows, err := repository.pool.Query(ctx, listTenantAuditRetentionCandidatesSQL, workerID, int32(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0, limit)
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		result = append(result, tenantID)
	}
	return result, rows.Err()
}

func (repository *AuditOperationsRepository) GetRetentionWork(ctx context.Context, stream auditoperations.Stream,
	tenantID, workerID uuid.UUID) (auditoperations.Segment, bool, error) {
	segment := auditoperations.Segment{Stream: stream, TenantID: tenantID}
	var digest []byte
	var signature []byte
	var size pgtype.Int8
	var keyID pgtype.Text
	var err error
	if stream == auditoperations.TenantStream {
		err = repository.pool.QueryRow(ctx, getTenantAuditRetentionWorkSQL, workerID, tenantID).Scan(
			&segment.ID, &segment.TenantID, &segment.State, &segment.Revision, &segment.Start,
			&segment.End, &segment.PreviousHash, &segment.EndHash, &segment.EventCount,
			&segment.ObjectKey, &digest, &size, &keyID, &signature,
		)
	} else if stream == auditoperations.PlatformStream {
		err = repository.pool.QueryRow(ctx, getPlatformAuditRetentionWorkSQL, workerID).Scan(
			&segment.ID, &segment.State, &segment.Revision, &segment.Start, &segment.End,
			&segment.PreviousHash, &segment.EndHash, &segment.EventCount, &segment.ObjectKey,
			&digest, &size, &keyID, &signature,
		)
	} else {
		return auditoperations.Segment{}, false, auditoperations.ErrInvalidInput
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auditoperations.Segment{}, false, nil
	}
	if err != nil {
		return auditoperations.Segment{}, false, err
	}
	if len(digest) != 0 {
		copy(segment.Digest[:], digest)
	}
	if len(signature) != 0 {
		copy(segment.Signature[:], signature)
	}
	if size.Valid {
		segment.Bytes = size.Int64
	}
	if keyID.Valid {
		segment.SigningKeyID = keyID.String
	}
	return segment, true, nil
}

func (repository *AuditOperationsRepository) CloseRetentionSegment(ctx context.Context, stream auditoperations.Stream,
	tenantID, workerID uuid.UUID, maximum int, reason string, auditID uuid.UUID) (auditoperations.Segment, bool, error) {
	segment := auditoperations.Segment{Stream: stream, TenantID: tenantID, State: "closed", Revision: 1}
	var err error
	if stream == auditoperations.TenantStream {
		err = repository.pool.QueryRow(ctx, closeTenantAuditSegmentSQL,
			workerID, tenantID, int32(maximum), reason, auditID).Scan(
			&segment.ID, &segment.TenantID, &segment.Start, &segment.End,
			&segment.PreviousHash, &segment.EndHash, &segment.EventCount, &segment.ObjectKey,
		)
	} else if stream == auditoperations.PlatformStream {
		err = repository.pool.QueryRow(ctx, closePlatformAuditSegmentSQL,
			workerID, int32(maximum), reason, auditID).Scan(
			&segment.ID, &segment.Start, &segment.End, &segment.PreviousHash,
			&segment.EndHash, &segment.EventCount, &segment.ObjectKey,
		)
	} else {
		return auditoperations.Segment{}, false, auditoperations.ErrInvalidInput
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auditoperations.Segment{}, false, nil
	}
	if err != nil {
		return auditoperations.Segment{}, false, err
	}
	return segment, true, nil
}

func (repository *AuditOperationsRepository) ReadRetentionPage(ctx context.Context, segment auditoperations.Segment,
	workerID uuid.UUID, after int64, limit int) ([]auditoperations.PageRow, error) {
	if segment.Stream == auditoperations.TenantStream {
		return repository.readPage(ctx, readTenantAuditSegmentSQL,
			workerID, segment.TenantID, segment.ID, after, int32(limit))
	}
	return repository.readPage(ctx, readPlatformAuditSegmentSQL,
		workerID, segment.ID, after, int32(limit))
}

func (repository *AuditOperationsRepository) PreserveRetentionSegment(ctx context.Context,
	segment auditoperations.Segment, workerID uuid.UUID, digest [32]byte, bytes int64,
	keyID string, signature [64]byte, reason string, auditID uuid.UUID) error {
	query := preserveTenantAuditSegmentSQL
	arguments := []any{workerID, segment.TenantID, segment.ID, int64(1), digest[:], bytes, keyID, signature[:], reason, auditID}
	if segment.Stream == auditoperations.PlatformStream {
		query = preservePlatformAuditSegmentSQL
		arguments = []any{workerID, segment.ID, int64(1), digest[:], bytes, keyID, signature[:], reason, auditID}
	}
	return repository.scanMutation(ctx, query, "preserved", 2, arguments...)
}

func (repository *AuditOperationsRepository) PruneRetentionSegment(ctx context.Context,
	segment auditoperations.Segment, workerID uuid.UUID, artifact auditoperations.Artifact,
	reason string, auditID uuid.UUID) error {
	query := pruneTenantAuditSegmentSQL
	arguments := []any{workerID, segment.TenantID, segment.ID, int64(2), artifact.ObjectKey,
		artifact.Digest[:], artifact.Bytes, artifact.SigningKeyID, artifact.Signature[:], true, reason, auditID}
	if segment.Stream == auditoperations.PlatformStream {
		query = prunePlatformAuditSegmentSQL
		arguments = []any{workerID, segment.ID, int64(2), artifact.ObjectKey, artifact.Digest[:],
			artifact.Bytes, artifact.SigningKeyID, artifact.Signature[:], true, reason, auditID}
	}
	return repository.scanMutation(ctx, query, "pruned", 3, arguments...)
}

func (repository *AuditOperationsRepository) PruneTenantReceipts(ctx context.Context, tenantID, workerID uuid.UUID,
	limit int, reason string, auditID uuid.UUID) (int, error) {
	var count int32
	err := repository.pool.QueryRow(ctx, pruneTenantAuditReceiptsSQL,
		workerID, tenantID, int32(limit), reason, auditID).Scan(&count)
	return int(count), err
}

func (repository *AuditOperationsRepository) PrunePlatformReceipts(ctx context.Context, workerID uuid.UUID,
	limit int, reason string, auditID uuid.UUID) (int, error) {
	var count int32
	err := repository.pool.QueryRow(ctx, prunePlatformAuditReceiptsSQL,
		workerID, int32(limit), reason, auditID).Scan(&count)
	return int(count), err
}

func (repository *AuditOperationsRepository) readPage(ctx context.Context, query string,
	arguments ...any) ([]auditoperations.PageRow, error) {
	rows, err := repository.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]auditoperations.PageRow, 0)
	for rows.Next() {
		var row auditoperations.PageRow
		var document []byte
		if err := rows.Scan(&row.Sequence, &document); err != nil {
			return nil, err
		}
		row.Document = append(json.RawMessage(nil), document...)
		result = append(result, row)
	}
	return result, rows.Err()
}

func (repository *AuditOperationsRepository) scanMutation(ctx context.Context, query, expectedState string,
	expectedRevision int64, arguments ...any) error {
	var document []byte
	if err := repository.pool.QueryRow(ctx, query, arguments...).Scan(&document); err != nil {
		return err
	}
	var result struct {
		State    string `json:"state"`
		Revision int64  `json:"revision"`
	}
	if len(document) > 64*1024 || json.Unmarshal(document, &result) != nil ||
		result.State != expectedState || result.Revision != expectedRevision {
		return auditoperations.ErrInvalidProjection
	}
	return nil
}

var _ auditoperations.Repository = (*AuditOperationsRepository)(nil)
