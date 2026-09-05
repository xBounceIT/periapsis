package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/periapsis-im/periapsis/services/worker/internal/dfircleanup"
	"github.com/periapsis-im/periapsis/services/worker/internal/telemetry"
)

const claimDFIROrphanUploadsQuery = `
SELECT tenant_id, storage_object_id, cleanup_fence, bucket, object_key,
       expected_size_bytes, upload_expires_at, cleanup_lease_expires_at
FROM app.claim_dfir_orphan_uploads_v1($1, $2, $3)
`

type dfirCleanupPool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

type DFIRCleanupRepository struct {
	pool dfirCleanupPool
}

func NewDFIRCleanupRepository(pool dfirCleanupPool) *DFIRCleanupRepository {
	if pool == nil {
		return nil
	}
	return &DFIRCleanupRepository{pool: pool}
}

var _ dfircleanup.Repository = (*DFIRCleanupRepository)(nil)

func (repository *DFIRCleanupRepository) Check(ctx context.Context) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("check DFIR cleanup runtime")
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, `SELECT app.dfir_storage_scan_runtime_ready_v1()`).Scan(&ready); err != nil || !ready {
		return errors.New("check DFIR cleanup runtime")
	}
	return nil
}

func (repository *DFIRCleanupRepository) Claim(
	ctx context.Context,
	limit int,
	lease time.Duration,
	now time.Time,
) ([]dfircleanup.Claim, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		limit < 1 || limit > dfircleanup.MaximumBatchSize || lease < 30*time.Second || lease > 15*time.Minute ||
		lease%time.Second != 0 || now.IsZero() {
		return nil, errors.New("claim DFIR orphan uploads")
	}
	rows, err := repository.pool.Query(ctx, claimDFIROrphanUploadsQuery, limit, int(lease/time.Second), now)
	if err != nil {
		return nil, errors.New("claim DFIR orphan uploads")
	}
	defer rows.Close()
	claims := make([]dfircleanup.Claim, 0, limit)
	for rows.Next() {
		var claim dfircleanup.Claim
		if err := rows.Scan(
			&claim.TenantID, &claim.StorageID, &claim.Fence,
			&claim.Bucket, &claim.ObjectKey, &claim.ExpectedSize,
			&claim.UploadExpires, &claim.LeaseExpiresAt,
		); err != nil {
			return nil, errors.New("decode DFIR orphan cleanup claim")
		}
		claims = append(claims, claim)
	}
	if rows.Err() != nil || len(claims) > limit {
		return nil, errors.New("iterate DFIR orphan cleanup claims")
	}
	return claims, nil
}

func (repository *DFIRCleanupRepository) Retry(
	ctx context.Context,
	storageID uuid.UUID,
	fence int64,
	failureCode string,
	failedAt time.Time,
	retryAt time.Time,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("retry DFIR orphan cleanup")
	}
	var alreadyDeleted bool
	err := repository.pool.QueryRow(ctx, `
		SELECT app.retry_dfir_orphan_upload_cleanup_v1($1, $2, $3, $4, $5)
	`, storageID, fence, failureCode, failedAt, retryAt).Scan(&alreadyDeleted)
	if err != nil {
		return errors.New("retry DFIR orphan cleanup")
	}
	_ = alreadyDeleted
	return nil
}

func (repository *DFIRCleanupRepository) Finalize(
	ctx context.Context,
	input dfircleanup.FinalizeInput,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("finalize DFIR orphan cleanup")
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return errors.New("begin DFIR orphan cleanup finalize")
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := installWorkerPersistedTraceContext(ctx, tx); err != nil {
		return err
	}
	var storageID uuid.UUID
	var version int64
	var replayed bool
	err = tx.QueryRow(ctx, `
		SELECT storage_object_id, storage_version, replayed
		FROM app.finalize_dfir_orphan_upload_cleanup_v2(
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`, input.StorageID, input.Fence, input.DeletedAt, input.OperationID,
		input.AuditID, input.OutboxID, input.RequestID, input.CorrelationID,
	).Scan(&storageID, &version, &replayed)
	if err != nil || storageID != input.StorageID || version < 2 {
		return errors.New("finalize DFIR orphan cleanup")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit DFIR orphan cleanup finalize")
	}
	_ = replayed
	return nil
}

func installWorkerPersistedTraceContext(ctx context.Context, tx pgx.Tx) error {
	traceparent, tracestate := "", ""
	if persisted, ok := telemetry.PersistedSpanContextFromContext(ctx); ok {
		traceparent = persisted.TraceParent
		if persisted.TraceState != nil {
			tracestate = *persisted.TraceState
		}
	}
	var installedParent, installedState string
	if err := tx.QueryRow(ctx, `
		SELECT set_config('app.traceparent', $1, true),
		       set_config('app.tracestate', $2, true)
	`, traceparent, tracestate).Scan(&installedParent, &installedState); err != nil {
		return errors.New("install DFIR cleanup trace context")
	}
	if installedParent != traceparent || installedState != tracestate {
		return errors.New("verify DFIR cleanup trace context")
	}
	return nil
}
