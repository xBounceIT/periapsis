package identityprovider

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// AdministrationRepository is the protected persistence boundary for tenant
// LDAP bindings and mapping rules. Implementations must re-install the exact
// tenant and human membership context and use only the security-definer ABI.
// Network operations and planner evaluation never occur inside these methods.
type AdministrationRepository interface {
	ListBindings(context.Context, ListBindingParams) ([]Binding, error)
	GetBinding(context.Context, GetBindingParams) (Binding, error)
	CreateBinding(context.Context, CreateBindingParams) (BindingMutationResult, error)
	UpdateBinding(context.Context, UpdateBindingParams) (Binding, error)
	ArchiveBinding(context.Context, ArchiveBindingParams) (int64, error)

	ListMappings(context.Context, ListMappingParams) ([]Mapping, error)
	GetMapping(context.Context, GetMappingParams) (Mapping, error)
	CreateMapping(context.Context, CreateMappingParams) (MappingMutationResult, error)
	UpdateMapping(context.Context, UpdateMappingParams) (Mapping, error)
	ArchiveMapping(context.Context, ArchiveMappingParams) (int64, error)
}

// SyncAdministrationRepository is intentionally separate from
// AdministrationRepository. Deployments rolling the sync ABI can keep the
// established binding and mapping administration surface available while the
// service fails closed for sync operations until all four bounded functions
// are installed.
type SyncAdministrationRepository interface {
	GetSyncStatus(context.Context, GetSyncStatusParams) (SyncStatus, error)
	ListSyncRuns(context.Context, ListSyncRunParams) ([]SyncRun, error)
	GetSyncRun(context.Context, GetSyncRunParams) (SyncRun, error)
	StartManualSync(context.Context, StartManualSyncParams) (SyncRunMutationResult, error)
}

type BindingMutationResult struct {
	Binding  Binding
	Replayed bool
}

type MappingMutationResult struct {
	Mapping  Mapping
	Replayed bool
}

type SyncRunMutationResult struct {
	Run      SyncRun
	Replayed bool
}

type ListBindingParams struct {
	HumanParams
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type GetBindingParams struct {
	HumanParams
	BindingID uuid.UUID
}

type CreateBindingParams struct {
	HumanParams
	Audit                authorization.AuditContext
	OccurredAt           time.Time
	AuditEventID         uuid.UUID
	IdempotencyKeyDigest [32]byte
	ProviderID           uuid.UUID
	LoginKey             string
	Enabled              bool
	ProfilePriority      int
}

type UpdateBindingParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	BindingID       uuid.UUID
	ExpectedVersion int64
	LoginKey        string
	Enabled         bool
	ProfilePriority int
}

type ArchiveBindingParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	BindingID       uuid.UUID
	ExpectedVersion int64
	Reason          string
}

type ListMappingParams struct {
	HumanParams
	After           *MappingCursor
	Limit           int32
	IncludeArchived bool
	BindingID       *uuid.UUID
}

type GetMappingParams struct {
	HumanParams
	MappingID uuid.UUID
}

type CreateMappingParams struct {
	HumanParams
	Audit                authorization.AuditContext
	OccurredAt           time.Time
	AuditEventID         uuid.UUID
	IdempotencyKeyDigest [32]byte
	BindingID            uuid.UUID
	Matcher              MappingMatcher
	Priority             int
	Target               MappingTarget
	ReconciliationMode   ReconciliationMode
	Notes                string
	Reason               string
}

type UpdateMappingParams struct {
	HumanParams
	Audit              authorization.AuditContext
	OccurredAt         time.Time
	AuditEventID       uuid.UUID
	MappingID          uuid.UUID
	ExpectedVersion    int64
	Matcher            MappingMatcher
	Priority           int
	Target             MappingTarget
	ReconciliationMode ReconciliationMode
	Enabled            bool
	Notes              string
	Reason             string
}

type ArchiveMappingParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	AuditEventID    uuid.UUID
	MappingID       uuid.UUID
	ExpectedVersion int64
	Reason          string
}

type GetSyncStatusParams struct {
	HumanParams
	BindingID uuid.UUID
}

type ListSyncRunParams struct {
	HumanParams
	BindingID uuid.UUID
	After     *uuid.UUID
	Limit     int32
}

type GetSyncRunParams struct {
	HumanParams
	BindingID uuid.UUID
	RunID     uuid.UUID
}

type StartManualSyncParams struct {
	HumanParams
	Audit                authorization.AuditContext
	OccurredAt           time.Time
	RunID                uuid.UUID
	AuditEventID         uuid.UUID
	BindingID            uuid.UUID
	ExpectedVersion      int64
	Reason               string
	IdempotencyKeyDigest [32]byte
	RequestDigest        [32]byte
}
