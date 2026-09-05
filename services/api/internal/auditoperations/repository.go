package auditoperations

import (
	"context"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// Repository exposes only the guarded 0213 ABI. Implementations must install
// transaction-local actor context and validate complete returned documents
// before committing their audit event and idempotency receipt.
type Repository interface {
	CreateTenantExport(context.Context, CreateExportParams) (ExportMutationResult, error)
	CreatePlatformExport(context.Context, CreateExportParams) (ExportMutationResult, error)
	GetTenantExport(context.Context, ReadExportParams) (ExportJob, error)
	GetPlatformExport(context.Context, ReadExportParams) (ExportJob, error)
	CancelTenantExport(context.Context, CancelExportParams) (ExportMutationResult, error)
	CancelPlatformExport(context.Context, CancelExportParams) (ExportMutationResult, error)
	AuthorizeTenantDownload(context.Context, ReadExportParams) (ArtifactLocation, error)
	AuthorizePlatformDownload(context.Context, ReadExportParams) (ArtifactLocation, error)
	GetTenantRetention(context.Context, ReadRetentionParams) (RetentionState, error)
	GetPlatformRetention(context.Context, ReadRetentionParams) (RetentionState, error)
	UpdateTenantRetention(context.Context, UpdateRetentionParams) (RetentionMutationResult, error)
	UpdatePlatformRetention(context.Context, UpdateRetentionParams) (RetentionMutationResult, error)
	PlaceTenantLegalHold(context.Context, PlaceLegalHoldParams) (LegalHoldMutationResult, error)
	PlacePlatformLegalHold(context.Context, PlaceLegalHoldParams) (LegalHoldMutationResult, error)
	ReleaseTenantLegalHold(context.Context, ReleaseLegalHoldParams) (LegalHoldMutationResult, error)
	ReleasePlatformLegalHold(context.Context, ReleaseLegalHoldParams) (LegalHoldMutationResult, error)
}

type TenantAuthorityResolver interface {
	ResolveAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
}

type ArtifactStorage interface {
	OpenAuditExport(context.Context, ArtifactLocation) (ArtifactReader, error)
}
