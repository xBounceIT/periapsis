package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfirscan"
)

const claimDFIRStorageScanQuery = `
SELECT event_id, tenant_id, storage_object_id, correlation_id,
       lease_token, attempt, maximum_attempts, execute_attempt, lease_until,
       declared_mime, bucket, object_key, original_filename,
       classification, expected_size_bytes, upload_expires_at,
       created_by_membership_id, created_at, updated_at, state,
       content_sha256, size_bytes, detected_mime, verified_at,
       retention_until, legal_hold, storage_version
FROM app.claim_dfir_storage_scan_v1($1, $2, $3, $4)
`

type dfirScanPool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}

type DFIRScanRepository struct{ pool dfirScanPool }

func NewDFIRScanRepository(pool dfirScanPool) *DFIRScanRepository {
	if pool == nil {
		return nil
	}
	return &DFIRScanRepository{pool: pool}
}

func (repository *DFIRScanRepository) Check(ctx context.Context) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return dfirscan.ErrUnavailable
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, `SELECT app.dfir_storage_scan_runtime_ready_v1()`).Scan(&ready); err != nil || !ready {
		return dfirscan.ErrUnavailable
	}
	return nil
}

func (repository *DFIRScanRepository) Claim(
	ctx context.Context,
	workerID uuid.UUID,
	limit int,
	lease time.Duration,
	now time.Time,
) ([]dfirscan.Claim, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		workerID.Version() != 7 || limit < 1 || limit > dfirscan.MaximumBatchSize ||
		lease < 30*time.Second || lease > 30*time.Minute || lease%time.Second != 0 || now.IsZero() {
		return nil, dfirscan.ErrUnavailable
	}
	rows, err := repository.pool.Query(ctx, claimDFIRStorageScanQuery, workerID, limit, int(lease/time.Second), now)
	if err != nil {
		return nil, classifyDFIRScanDatabaseError(err)
	}
	defer rows.Close()
	claims := make([]dfirscan.Claim, 0, limit)
	for rows.Next() {
		claim, decodeErr := scanDFIRStorageClaim(rows)
		if decodeErr != nil {
			return nil, decodeErr
		}
		claims = append(claims, claim)
	}
	if rows.Err() != nil || len(claims) > limit {
		return nil, dfirscan.ErrUnavailable
	}
	return claims, nil
}

func (repository *DFIRScanRepository) Transition(
	ctx context.Context,
	input dfirscan.TransitionInput,
) (kernel.StorageObject, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return kernel.StorageObject{}, dfirscan.ErrUnavailable
	}
	current, updated := input.Current.Snapshot(), input.Updated.Snapshot()
	var digest any
	if updated.ContentSHA256 != "" {
		decoded, err := hex.DecodeString(updated.ContentSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return kernel.StorageObject{}, dfirscan.ErrInvalidClaim
		}
		digest = decoded
	}
	var size any
	var detected any
	if updated.SizeBytes > 0 {
		if updated.VerifiedAt == nil {
			return kernel.StorageObject{}, dfirscan.ErrInvalidClaim
		}
		size, detected = updated.SizeBytes, updated.DetectedMIME
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return kernel.StorageObject{}, dfirscan.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err = installWorkerPersistedTraceContext(ctx, tx); err != nil {
		return kernel.StorageObject{}, dfirscan.ErrUnavailable
	}
	row := tx.QueryRow(ctx, `
		SELECT storage_object_id, tenant_id, bucket, object_key, original_filename,
		       classification, expected_size_bytes, upload_expires_at,
		       created_by_membership_id, created_at, updated_at, state,
		       content_sha256, size_bytes, detected_mime, verified_at,
		       retention_until, legal_hold, storage_version
		FROM app.advance_dfir_storage_scan_job_v1(
			$1, $2, $3, $4, $5::public.dfir_scan_state,
			$6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`,
		input.Fence.EventID, input.Fence.LeaseToken, uuid.UUID(current.ID.Bytes()), int64(current.Version),
		string(updated.State), digest, size, detected, input.TransitionedAt,
		input.IDs.OperationID, input.IDs.RequestID, input.IDs.AuditID, input.IDs.OutboxID,
		nullableFailureCategory(input.FailureCategory), input.CompleteJob,
		nullableFailureCategory(input.FileTypeClass), nullableFailureCategory(input.FileTypeReason),
	)
	stored, err := scanDFIRStorageObject(row)
	if err != nil {
		return kernel.StorageObject{}, classifyDFIRScanDatabaseError(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return kernel.StorageObject{}, dfirscan.ErrUnavailable
	}
	return stored, nil
}

func (repository *DFIRScanRepository) Complete(ctx context.Context, input dfirscan.CompleteInput) error {
	return repository.booleanCommand(ctx, `SELECT app.complete_dfir_storage_scan_job_v1($1, $2, $3, $4, $5)`,
		input.Fence.EventID, input.Fence.LeaseToken, input.CompletedAt,
		nullableFailureCategory(input.FailureCategory), input.DeadLetter,
	)
}

func (repository *DFIRScanRepository) Retry(ctx context.Context, input dfirscan.RetryInput) error {
	return repository.booleanCommand(ctx, `SELECT app.retry_dfir_storage_scan_job_v1($1, $2, $3, $4, $5)`,
		input.Fence.EventID, input.Fence.LeaseToken, input.FailedAt, input.RetryAt, input.FailureCategory,
	)
}

func (repository *DFIRScanRepository) WaitForUpload(ctx context.Context, input dfirscan.WaitInput) error {
	return repository.booleanCommand(ctx, `SELECT app.wait_dfir_storage_scan_job_v1($1, $2, $3, $4)`,
		input.Fence.EventID, input.Fence.LeaseToken, input.ObservedAt, input.AvailableAt,
	)
}

func (repository *DFIRScanRepository) booleanCommand(ctx context.Context, query string, args ...any) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return dfirscan.ErrUnavailable
	}
	var applied bool
	if err := repository.pool.QueryRow(ctx, query, args...).Scan(&applied); err != nil {
		return classifyDFIRScanDatabaseError(err)
	}
	if !applied {
		return dfirscan.ErrUnavailable
	}
	return nil
}

type rowScanner interface{ Scan(...any) error }

func scanDFIRStorageClaim(row rowScanner) (dfirscan.Claim, error) {
	var claim dfirscan.Claim
	var bucket, key, filename, classification, state string
	var createdBy uuid.UUID
	var expectedSize, version int64
	var size *int64
	var createdAt, updatedAt, uploadExpires time.Time
	var digest []byte
	var detected *string
	var verifiedAt, retentionUntil *time.Time
	var legalHold bool
	if err := row.Scan(
		&claim.EventID, &claim.TenantID, &claim.StorageID, &claim.CorrelationID,
		&claim.LeaseToken, &claim.Attempt, &claim.MaximumAttempts, &claim.ExecuteAttempt, &claim.LeaseUntil,
		&claim.DeclaredMIME, &bucket, &key, &filename, &classification, &expectedSize, &uploadExpires,
		&createdBy, &createdAt, &updatedAt, &state, &digest, &size, &detected, &verifiedAt,
		&retentionUntil, &legalHold, &version,
	); err != nil {
		return dfirscan.Claim{}, dfirscan.ErrUnavailable
	}
	storage, err := restoreDFIRStorageObject(
		claim.StorageID, claim.TenantID, bucket, key, filename, classification, expectedSize,
		uploadExpires, createdBy, createdAt, updatedAt, state, digest, valueOrZero(size), detected,
		verifiedAt, retentionUntil, legalHold, version,
	)
	if err != nil {
		return dfirscan.Claim{}, err
	}
	claim.Storage = storage
	return claim, nil
}

func scanDFIRStorageObject(row rowScanner) (kernel.StorageObject, error) {
	var storageID, tenantID, createdBy uuid.UUID
	var bucket, key, filename, classification, state string
	var expectedSize, version int64
	var size *int64
	var uploadExpires, createdAt, updatedAt time.Time
	var digest []byte
	var detected *string
	var verifiedAt, retentionUntil *time.Time
	var legalHold bool
	if err := row.Scan(
		&storageID, &tenantID, &bucket, &key, &filename, &classification, &expectedSize, &uploadExpires,
		&createdBy, &createdAt, &updatedAt, &state, &digest, &size, &detected, &verifiedAt,
		&retentionUntil, &legalHold, &version,
	); err != nil {
		return kernel.StorageObject{}, err
	}
	return restoreDFIRStorageObject(
		storageID, tenantID, bucket, key, filename, classification, expectedSize, uploadExpires,
		createdBy, createdAt, updatedAt, state, digest, valueOrZero(size), detected, verifiedAt, retentionUntil,
		legalHold, version,
	)
}

func restoreDFIRStorageObject(
	storageID, tenantID uuid.UUID,
	bucket, key, filename, classification string,
	expectedSize int64,
	uploadExpires time.Time,
	createdBy uuid.UUID,
	createdAt, updatedAt time.Time,
	state string,
	digest []byte,
	size int64,
	detected *string,
	verifiedAt, retentionUntil *time.Time,
	legalHold bool,
	version int64,
) (kernel.StorageObject, error) {
	storageEntityID, storageErr := kernel.NewEntityID([16]byte(storageID))
	tenantEntityID, tenantErr := kernel.NewEntityID([16]byte(tenantID))
	creatorEntityID, creatorErr := kernel.NewEntityID([16]byte(createdBy))
	if storageErr != nil || tenantErr != nil || creatorErr != nil || version < 1 {
		return kernel.StorageObject{}, dfirscan.ErrInvalidClaim
	}
	contentSHA256 := ""
	if digest != nil {
		if len(digest) != sha256.Size {
			return kernel.StorageObject{}, dfirscan.ErrInvalidClaim
		}
		contentSHA256 = hex.EncodeToString(digest)
	}
	detectedMIME := ""
	if detected != nil {
		detectedMIME = *detected
	}
	object, err := kernel.RestoreStorageObject(kernel.StorageObjectState{
		ID: storageEntityID, TenantID: tenantEntityID, Bucket: bucket, ObjectKey: key,
		OriginalFilename: filename, Classification: kernel.EvidenceClassification(classification),
		ExpectedSizeBytes: expectedSize, UploadExpiresAt: uploadExpires, CreatedBy: creatorEntityID,
		CreatedAt: createdAt, UpdatedAt: updatedAt, State: kernel.ScanState(state),
		ContentSHA256: contentSHA256, SizeBytes: size, DetectedMIME: detectedMIME,
		VerifiedAt: verifiedAt, RetentionUntil: retentionUntil, LegalHold: legalHold, Version: uint64(version),
	})
	if err != nil {
		return kernel.StorageObject{}, dfirscan.ErrInvalidClaim
	}
	return object, nil
}

func nullableFailureCategory(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func classifyDFIRScanDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "40001":
			return dfirscan.ErrFenceLost
		case "P5401":
			return dfirscan.ErrEvidenceCustodyLimit
		}
	}
	return dfirscan.ErrUnavailable
}

var _ dfirscan.Repository = (*DFIRScanRepository)(nil)
