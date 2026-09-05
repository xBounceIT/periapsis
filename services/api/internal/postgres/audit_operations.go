package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/auditoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const maximumAuditOperationDocumentBytes = 64 * 1024

// AuditOperationsRepository adapts only the guarded 0213 human ABI. Every
// operation is read-write because status, download, and retention reads append
// access evidence in the same transaction.
type AuditOperationsRepository struct {
	begin transactionBeginner
}

func NewAuditOperationsRepository(pool *pgxpool.Pool) *AuditOperationsRepository {
	return &AuditOperationsRepository{begin: poolTransactionBeginner(pool)}
}

var _ auditoperations.Repository = (*AuditOperationsRepository)(nil)

func (repository *AuditOperationsRepository) CreateTenantExport(
	ctx context.Context,
	params auditoperations.CreateExportParams,
) (auditoperations.ExportMutationResult, error) {
	return createAuditExport(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) CreatePlatformExport(
	ctx context.Context,
	params auditoperations.CreateExportParams,
) (auditoperations.ExportMutationResult, error) {
	return createAuditExport(ctx, repository, params, false)
}

func createAuditExport(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.CreateExportParams,
	tenant bool,
) (auditoperations.ExportMutationResult, error) {
	event, err := eventArguments(params.Envelope.Event)
	if err != nil || params.ValidateResult == nil || len(params.FilterJSON) < 2 ||
		len(params.FilterJSON) > maximumAuditOperationDocumentBytes || !json.Valid(params.FilterJSON) ||
		!authorizationUUIDv7(params.JobID) || !authorizationUUIDv7(params.Envelope.AuditID) ||
		params.Envelope.KeyDigest == ([sha256.Size]byte{}) {
		return auditoperations.ExportMutationResult{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.ExportMutationResult, error) {
			arguments := auditExportCreateArgumentsValue(params, event)
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.CreateTenantAuditExportOperation(ctx, dbsql.CreateTenantAuditExportOperationParams(arguments))
			} else {
				document, queryErr = queries.CreatePlatformAuditExportOperation(ctx, dbsql.CreatePlatformAuditExportOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.ExportMutationResult{}, queryErr
			}
			result, decodeErr := decodeAuditOperationDocument[auditoperations.ExportMutationResult](document)
			if decodeErr != nil {
				return auditoperations.ExportMutationResult{}, decodeErr
			}
			return params.ValidateResult(result)
		})
}

type auditExportCreateArgs dbsql.CreateTenantAuditExportOperationParams

func auditExportCreateArgumentsValue(
	params auditoperations.CreateExportParams,
	event auditArguments,
) auditExportCreateArgs {
	return auditExportCreateArgs{
		SessionID:            toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
		IdempotencyKeyDigest: bytes.Clone(params.Envelope.KeyDigest[:]),
		NormalizedFilter:     bytes.Clone(params.FilterJSON), RetentionSeconds: params.RetentionSeconds,
		Reason: params.Reason, JobID: toDatabaseUUID(params.JobID),
		AuditID: toDatabaseUUID(params.Envelope.AuditID), RequestID: event.requestID,
		CorrelationID: event.correlationID, IpAddress: params.Envelope.Event.RemoteAddress.Unmap(),
		UserAgent: params.Envelope.Event.UserAgent,
	}
}

func (repository *AuditOperationsRepository) GetTenantExport(
	ctx context.Context,
	params auditoperations.ReadExportParams,
) (auditoperations.ExportJob, error) {
	return getAuditExport(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) GetPlatformExport(
	ctx context.Context,
	params auditoperations.ReadExportParams,
) (auditoperations.ExportJob, error) {
	return getAuditExport(ctx, repository, params, false)
}

func getAuditExport(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.ReadExportParams,
	tenant bool,
) (auditoperations.ExportJob, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.ValidateJob == nil || !authorizationUUIDv7(params.ExportID) ||
		!authorizationUUIDv7(params.AuditID) {
		return auditoperations.ExportJob{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.ExportJob, error) {
			arguments := dbsql.GetTenantAuditExportOperationParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				ExportID:  toDatabaseUUID(params.ExportID), AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.GetTenantAuditExportOperation(ctx, arguments)
			} else {
				document, queryErr = queries.GetPlatformAuditExportOperation(ctx, dbsql.GetPlatformAuditExportOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.ExportJob{}, queryErr
			}
			job, decodeErr := decodeAuditOperationDocument[auditoperations.ExportJob](document)
			if decodeErr != nil {
				return auditoperations.ExportJob{}, decodeErr
			}
			return params.ValidateJob(job)
		})
}

func (repository *AuditOperationsRepository) CancelTenantExport(
	ctx context.Context,
	params auditoperations.CancelExportParams,
) (auditoperations.ExportMutationResult, error) {
	return cancelAuditExport(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) CancelPlatformExport(
	ctx context.Context,
	params auditoperations.CancelExportParams,
) (auditoperations.ExportMutationResult, error) {
	return cancelAuditExport(ctx, repository, params, false)
}

func cancelAuditExport(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.CancelExportParams,
	tenant bool,
) (auditoperations.ExportMutationResult, error) {
	event, err := eventArguments(params.Envelope.Event)
	if err != nil || params.ValidateResult == nil || !authorizationUUIDv7(params.ExportID) ||
		!authorizationUUIDv7(params.Envelope.AuditID) || params.Envelope.KeyDigest == ([sha256.Size]byte{}) {
		return auditoperations.ExportMutationResult{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.ExportMutationResult, error) {
			arguments := dbsql.CancelTenantAuditExportOperationParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				ExportID:  toDatabaseUUID(params.ExportID), ExpectedRevision: params.ExpectedRevision,
				IdempotencyKeyDigest: bytes.Clone(params.Envelope.KeyDigest[:]), Reason: params.Reason,
				AuditID: toDatabaseUUID(params.Envelope.AuditID), RequestID: event.requestID,
				CorrelationID: event.correlationID, IpAddress: params.Envelope.Event.RemoteAddress.Unmap(),
				UserAgent: params.Envelope.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.CancelTenantAuditExportOperation(ctx, arguments)
			} else {
				document, queryErr = queries.CancelPlatformAuditExportOperation(ctx, dbsql.CancelPlatformAuditExportOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.ExportMutationResult{}, queryErr
			}
			result, decodeErr := decodeAuditOperationDocument[auditoperations.ExportMutationResult](document)
			if decodeErr != nil {
				return auditoperations.ExportMutationResult{}, decodeErr
			}
			return params.ValidateResult(result)
		})
}

func (repository *AuditOperationsRepository) AuthorizeTenantDownload(
	ctx context.Context,
	params auditoperations.ReadExportParams,
) (auditoperations.ArtifactLocation, error) {
	return authorizeAuditExportDownload(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) AuthorizePlatformDownload(
	ctx context.Context,
	params auditoperations.ReadExportParams,
) (auditoperations.ArtifactLocation, error) {
	return authorizeAuditExportDownload(ctx, repository, params, false)
}

func authorizeAuditExportDownload(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.ReadExportParams,
	tenant bool,
) (auditoperations.ArtifactLocation, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.ValidateLocation == nil || !authorizationUUIDv7(params.ExportID) ||
		!authorizationUUIDv7(params.AuditID) {
		return auditoperations.ArtifactLocation{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.ArtifactLocation, error) {
			arguments := dbsql.AuthorizeTenantAuditExportDownloadParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				ExportID:  toDatabaseUUID(params.ExportID), AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			}
			var artifactIDValue [16]byte
			var objectKey, filename string
			var digest []byte
			var rows, size int64
			var expiresAtValue time.Time
			if tenant {
				row, queryErr := queries.AuthorizeTenantAuditExportDownload(ctx, arguments)
				if queryErr != nil {
					return auditoperations.ArtifactLocation{}, queryErr
				}
				artifactIDValue, objectKey, digest, rows, size, filename = row.ArtifactID.Bytes, row.ObjectKey, row.Digest, row.Rows, row.Bytes, row.Filename
				if !row.ExpiresAt.Valid {
					return auditoperations.ArtifactLocation{}, errors.New("database returned null audit export expiry")
				}
				expiresAtValue = row.ExpiresAt.Time.UTC()
			} else {
				row, queryErr := queries.AuthorizePlatformAuditExportDownload(ctx, dbsql.AuthorizePlatformAuditExportDownloadParams(arguments))
				if queryErr != nil {
					return auditoperations.ArtifactLocation{}, queryErr
				}
				artifactIDValue, objectKey, digest, rows, size, filename = row.ArtifactID.Bytes, row.ObjectKey, row.Digest, row.Rows, row.Bytes, row.Filename
				if !row.ExpiresAt.Valid {
					return auditoperations.ArtifactLocation{}, errors.New("database returned null audit export expiry")
				}
				expiresAtValue = row.ExpiresAt.Time.UTC()
			}
			if len(digest) != sha256.Size {
				return auditoperations.ArtifactLocation{}, errors.New("database returned malformed audit export digest")
			}
			location := auditoperations.ArtifactLocation{
				Stream: auditoperations.StreamPlatform, ExportID: params.ExportID,
				ArtifactID: uuid.UUID(artifactIDValue), ObjectKey: objectKey,
				Rows: rows, Bytes: size, ExpiresAt: expiresAtValue, Filename: filename,
			}
			copy(location.Digest[:], digest)
			if tenant {
				location.Stream = auditoperations.StreamTenant
				identifier := params.TenantSession.TenantID
				location.TenantID = &identifier
			}
			return params.ValidateLocation(location)
		})
}

func (repository *AuditOperationsRepository) GetTenantRetention(
	ctx context.Context,
	params auditoperations.ReadRetentionParams,
) (auditoperations.RetentionState, error) {
	return getAuditRetention(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) GetPlatformRetention(
	ctx context.Context,
	params auditoperations.ReadRetentionParams,
) (auditoperations.RetentionState, error) {
	return getAuditRetention(ctx, repository, params, false)
}

func getAuditRetention(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.ReadRetentionParams,
	tenant bool,
) (auditoperations.RetentionState, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.ValidateState == nil || !authorizationUUIDv7(params.AuditID) {
		return auditoperations.RetentionState{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.RetentionState, error) {
			arguments := dbsql.GetTenantAuditRetentionOperationParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				AuditID:   toDatabaseUUID(params.AuditID), RequestID: event.requestID,
				CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress.Unmap(),
				UserAgent: params.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.GetTenantAuditRetentionOperation(ctx, arguments)
			} else {
				document, queryErr = queries.GetPlatformAuditRetentionOperation(ctx, dbsql.GetPlatformAuditRetentionOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.RetentionState{}, queryErr
			}
			state, decodeErr := decodeAuditOperationDocument[auditoperations.RetentionState](document)
			if decodeErr != nil {
				return auditoperations.RetentionState{}, decodeErr
			}
			return params.ValidateState(state)
		})
}

func (repository *AuditOperationsRepository) UpdateTenantRetention(
	ctx context.Context,
	params auditoperations.UpdateRetentionParams,
) (auditoperations.RetentionMutationResult, error) {
	return updateAuditRetention(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) UpdatePlatformRetention(
	ctx context.Context,
	params auditoperations.UpdateRetentionParams,
) (auditoperations.RetentionMutationResult, error) {
	return updateAuditRetention(ctx, repository, params, false)
}

func updateAuditRetention(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.UpdateRetentionParams,
	tenant bool,
) (auditoperations.RetentionMutationResult, error) {
	event, err := eventArguments(params.Envelope.Event)
	if err != nil || params.ValidateResult == nil || !authorizationUUIDv7(params.Envelope.AuditID) ||
		params.Envelope.KeyDigest == ([sha256.Size]byte{}) {
		return auditoperations.RetentionMutationResult{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.RetentionMutationResult, error) {
			arguments := dbsql.UpdateTenantAuditRetentionOperationParams{
				SessionID:        toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				ExpectedRevision: params.ExpectedRevision, RetentionDays: params.RetentionDays,
				IdempotencyKeyDigest: bytes.Clone(params.Envelope.KeyDigest[:]), Reason: params.Reason,
				AuditID: toDatabaseUUID(params.Envelope.AuditID), RequestID: event.requestID,
				CorrelationID: event.correlationID, IpAddress: params.Envelope.Event.RemoteAddress.Unmap(),
				UserAgent: params.Envelope.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.UpdateTenantAuditRetentionOperation(ctx, arguments)
			} else {
				document, queryErr = queries.UpdatePlatformAuditRetentionOperation(ctx, dbsql.UpdatePlatformAuditRetentionOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.RetentionMutationResult{}, queryErr
			}
			result, decodeErr := decodeAuditOperationDocument[auditoperations.RetentionMutationResult](document)
			if decodeErr != nil {
				return auditoperations.RetentionMutationResult{}, decodeErr
			}
			return params.ValidateResult(result)
		})
}

func (repository *AuditOperationsRepository) PlaceTenantLegalHold(
	ctx context.Context,
	params auditoperations.PlaceLegalHoldParams,
) (auditoperations.LegalHoldMutationResult, error) {
	return placeAuditLegalHold(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) PlacePlatformLegalHold(
	ctx context.Context,
	params auditoperations.PlaceLegalHoldParams,
) (auditoperations.LegalHoldMutationResult, error) {
	return placeAuditLegalHold(ctx, repository, params, false)
}

func placeAuditLegalHold(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.PlaceLegalHoldParams,
	tenant bool,
) (auditoperations.LegalHoldMutationResult, error) {
	event, err := eventArguments(params.Envelope.Event)
	if err != nil || params.ValidateResult == nil || !authorizationUUIDv7(params.HoldID) ||
		!authorizationUUIDv7(params.Envelope.AuditID) || params.Envelope.KeyDigest == ([sha256.Size]byte{}) {
		return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.LegalHoldMutationResult, error) {
			arguments := dbsql.PlaceTenantAuditLegalHoldOperationParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				HoldID:    toDatabaseUUID(params.HoldID), IdempotencyKeyDigest: bytes.Clone(params.Envelope.KeyDigest[:]),
				Reason: params.Reason, AuditID: toDatabaseUUID(params.Envelope.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Envelope.Event.RemoteAddress.Unmap(), UserAgent: params.Envelope.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.PlaceTenantAuditLegalHoldOperation(ctx, arguments)
			} else {
				document, queryErr = queries.PlacePlatformAuditLegalHoldOperation(ctx, dbsql.PlacePlatformAuditLegalHoldOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.LegalHoldMutationResult{}, queryErr
			}
			result, decodeErr := decodeAuditOperationDocument[auditoperations.LegalHoldMutationResult](document)
			if decodeErr != nil {
				return auditoperations.LegalHoldMutationResult{}, decodeErr
			}
			return params.ValidateResult(result)
		})
}

func (repository *AuditOperationsRepository) ReleaseTenantLegalHold(
	ctx context.Context,
	params auditoperations.ReleaseLegalHoldParams,
) (auditoperations.LegalHoldMutationResult, error) {
	return releaseAuditLegalHold(ctx, repository, params, true)
}

func (repository *AuditOperationsRepository) ReleasePlatformLegalHold(
	ctx context.Context,
	params auditoperations.ReleaseLegalHoldParams,
) (auditoperations.LegalHoldMutationResult, error) {
	return releaseAuditLegalHold(ctx, repository, params, false)
}

func releaseAuditLegalHold(
	ctx context.Context,
	repository *AuditOperationsRepository,
	params auditoperations.ReleaseLegalHoldParams,
	tenant bool,
) (auditoperations.LegalHoldMutationResult, error) {
	event, err := eventArguments(params.Envelope.Event)
	if err != nil || params.ValidateResult == nil || !authorizationUUIDv7(params.HoldID) ||
		!authorizationUUIDv7(params.Envelope.AuditID) || params.Envelope.KeyDigest == ([sha256.Size]byte{}) {
		return auditoperations.LegalHoldMutationResult{}, auditoperations.ErrInvalidInput
	}
	return withAuditOperationsTransaction(ctx, repository, params.TenantSession, params.PlatformSession, tenant,
		func(queries *dbsql.Queries) (auditoperations.LegalHoldMutationResult, error) {
			arguments := dbsql.ReleaseTenantAuditLegalHoldOperationParams{
				SessionID: toDatabaseUUID(operationSessionID(params.TenantSession, params.PlatformSession)),
				HoldID:    toDatabaseUUID(params.HoldID), ExpectedRevision: params.ExpectedRevision,
				IdempotencyKeyDigest: bytes.Clone(params.Envelope.KeyDigest[:]), Reason: params.Reason,
				AuditID: toDatabaseUUID(params.Envelope.AuditID), RequestID: event.requestID,
				CorrelationID: event.correlationID, IpAddress: params.Envelope.Event.RemoteAddress.Unmap(),
				UserAgent: params.Envelope.Event.UserAgent,
			}
			var document []byte
			var queryErr error
			if tenant {
				document, queryErr = queries.ReleaseTenantAuditLegalHoldOperation(ctx, arguments)
			} else {
				document, queryErr = queries.ReleasePlatformAuditLegalHoldOperation(ctx, dbsql.ReleasePlatformAuditLegalHoldOperationParams(arguments))
			}
			if queryErr != nil {
				return auditoperations.LegalHoldMutationResult{}, queryErr
			}
			result, decodeErr := decodeAuditOperationDocument[auditoperations.LegalHoldMutationResult](document)
			if decodeErr != nil {
				return auditoperations.LegalHoldMutationResult{}, decodeErr
			}
			return params.ValidateResult(result)
		})
}

func withAuditOperationsTransaction[T any](
	ctx context.Context,
	repository *AuditOperationsRepository,
	tenantSession *auditoperations.TenantSessionParams,
	platformSession *auditoperations.PlatformSessionParams,
	tenant bool,
	work func(*dbsql.Queries) (T, error),
) (T, error) {
	var zero T
	if repository == nil || repository.begin == nil || work == nil || ctx == nil ||
		tenant && (tenantSession == nil || platformSession != nil) ||
		!tenant && (platformSession == nil || tenantSession != nil) {
		return zero, auditoperations.ErrInvalidInput
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := dbsql.New(tx)
		if tenant {
			if !validAuthorizationRepositoryActor(tenantSession.Actor, tenantSession.TenantID) ||
				tenantSession.Session.ID != tenantSession.Actor.SessionID ||
				tenantSession.Session.User.ID != tenantSession.Actor.UserID {
				return zero, auditoperations.ErrForbidden
			}
			installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantSession.TenantID), UserID: toDatabaseUUID(tenantSession.Actor.UserID),
			})
			if installErr != nil || installed == nil || installed.TenantID != tenantSession.TenantID.String() ||
				installed.UserID != tenantSession.Actor.UserID.String() {
				return zero, auditoperations.ErrUnavailable
			}
		} else {
			if !authorizationUUIDv7(platformSession.Session.ID) || !authorizationUUIDv7(platformSession.Session.User.ID) {
				return zero, auditoperations.ErrForbidden
			}
			installed, installErr := queries.SetUserContext(ctx, dbsql.SetUserContextParams{
				UserID: toDatabaseUUID(platformSession.Session.User.ID),
			})
			if installErr != nil || installed != platformSession.Session.User.ID.String() {
				return zero, auditoperations.ErrUnavailable
			}
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, auditoperations.ErrUnavailable
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapAuditOperationsDatabaseError(err)
	}
	return result, nil
}

func operationSessionID(
	tenant *auditoperations.TenantSessionParams,
	platform *auditoperations.PlatformSessionParams,
) uuid.UUID {
	if tenant != nil {
		return tenant.Session.ID
	}
	if platform != nil {
		return platform.Session.ID
	}
	return uuid.Nil
}

func decodeAuditOperationDocument[T any](document []byte) (T, error) {
	var zero T
	if len(document) < 2 || len(document) > maximumAuditOperationDocumentBytes || !json.Valid(document) {
		return zero, errors.New("database returned malformed audit operation document")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, fmt.Errorf("decode audit operation document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return zero, errors.New("database returned trailing audit operation document")
	}
	return value, nil
}

func mapAuditOperationsDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	switch postgresCode(err) {
	case "22023", "23514":
		return auditoperations.ErrInvalidInput
	case "42501":
		return auditoperations.ErrForbidden
	case "P0002":
		return auditoperations.ErrNotFound
	case "40001":
		return auditoperations.ErrPrecondition
	case "23505", "55000":
		return auditoperations.ErrConflict
	default:
		if errors.Is(err, auditoperations.ErrInvalidInput) || errors.Is(err, auditoperations.ErrForbidden) ||
			errors.Is(err, auditoperations.ErrNotFound) || errors.Is(err, auditoperations.ErrConflict) ||
			errors.Is(err, auditoperations.ErrPrecondition) || errors.Is(err, auditoperations.ErrUnavailable) {
			return err
		}
		if strings.Contains(err.Error(), "context canceled") {
			return err
		}
		return auditoperations.ErrUnavailable
	}
}
