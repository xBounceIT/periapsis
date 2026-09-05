package identityprovider

import (
	"context"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// DirectoryOperationKind is the closed database and application vocabulary
// for bounded service-bind directory inspection. Mapping dry runs deliberately
// reuse SearchUser: the committed binding/rule pins distinguish that stronger
// operation from a provider-only administrative lookup.
type DirectoryOperationKind string

const (
	DirectoryOperationSearchUser  DirectoryOperationKind = "search_user"
	DirectoryOperationFilterUser  DirectoryOperationKind = "filter_user"
	DirectoryOperationFilterGroup DirectoryOperationKind = "filter_group"
)

// DirectoryOperationSnapshot is the immutable, committed network snapshot
// returned before an LDAP request starts. It may contain encrypted bind
// material, so it must never cross the application boundary or be logged.
type DirectoryOperationSnapshot struct {
	OperationRunID         uuid.UUID
	TenantID               uuid.UUID
	ProviderID             uuid.UUID
	OperationKind          DirectoryOperationKind
	ProviderVersion        int64
	ConfigurationVersion   int64
	EndpointSnapshotDigest [32]byte
	Configuration          Configuration
	Endpoints              []Endpoint
	SecretVersion          int64
	Secret                 EncryptedBindSecret
	BindingID              *uuid.UUID
	BindingVersion         *int64
	BindingAuthRevision    *int
	BindingAccessEpochID   *uuid.UUID
	RuleSetRevision        *int64
	AuthorizationRevision  *int64
	MappingRevisions       []PinnedMappingRevision
	StartedAt              time.Time
	ExpiresAt              time.Time
}

// DirectoryInspectionRepository owns the protected two-transaction database
// lifecycle around a provider-only LDAP inspection. No implementation may
// retain a transaction while network work runs.
type DirectoryInspectionRepository interface {
	BeginAdministrativeDirectoryInspection(
		context.Context,
		BeginAdministrativeDirectoryInspectionParams,
	) (DirectoryOperationSnapshot, error)
	CompleteDirectoryInspection(
		context.Context,
		CompleteDirectoryInspectionParams,
	) (DirectoryInspectionCompletion, error)
}

type BeginAdministrativeDirectoryInspectionParams struct {
	HumanParams
	Audit          authorization.AuditContext
	OccurredAt     time.Time
	OperationRunID uuid.UUID
	AuditEventID   uuid.UUID
	ProviderID     uuid.UUID
	OperationKind  DirectoryOperationKind
	Reason         string
}

// MappingDryRunRepository owns the two committed database snapshots around
// service-bound directory observation. BeginMappingDryRun pins network and
// authorization state before any LDAP request. GetMappingDryRunPlanningSnapshot
// is a short, post-network, digest-only read that fails when any pin drifted.
type MappingDryRunRepository interface {
	BeginMappingDryRun(
		context.Context,
		BeginMappingDryRunParams,
	) (DirectoryOperationSnapshot, error)
	GetMappingDryRunPlanningSnapshot(
		context.Context,
		GetMappingDryRunPlanningSnapshotParams,
	) (MappingDryRunPlanningSnapshot, error)
}

type BeginMappingDryRunParams struct {
	HumanParams
	Audit                     authorization.AuditContext
	OccurredAt                time.Time
	OperationRunID            uuid.UUID
	AuditEventID              uuid.UUID
	BindingID                 uuid.UUID
	IncludeDisabledMappingIDs []uuid.UUID
	Reason                    string
}

type GetMappingDryRunPlanningSnapshotParams struct {
	HumanParams
	OperationRunID uuid.UUID
	SubjectAliases []identity.SubjectAlias
}

// MappingDryRunPlanningSnapshot keeps the database-returned pins adjacent to
// the domain planner input so the application can compare both phases before
// evaluating. It contains no immutable subject, DN, attribute, or group value.
type MappingDryRunPlanningSnapshot struct {
	OperationRunID        uuid.UUID
	ProviderID            uuid.UUID
	ProviderVersion       int64
	BindingID             uuid.UUID
	BindingVersion        int64
	BindingAuthRevision   int
	BindingAccessEpochID  uuid.UUID
	ConfigurationRevision int64
	RuleSetRevision       int64
	AuthorizationRevision int64
	Planning              identity.LDAPPlanningSnapshot
}

type CompleteDirectoryInspectionParams struct {
	HumanParams
	Audit             authorization.AuditContext
	OccurredAt        time.Time
	OperationRunID    uuid.UUID
	AuditEventID      uuid.UUID
	ReportedOutcome   TestOutcome
	ReportedCategory  TestCategory
	EndpointPriority  *int
	Duration          time.Duration
	MatchedEntryCount int
	Truncated         bool
}

// DirectoryInspectionCompletion contains only the sanitized final state
// selected by the database. Configuration drift or expiry can override all
// caller-reported result metadata.
type DirectoryInspectionCompletion struct {
	Diagnostic        TestResult
	MatchedEntryCount int
	Truncated         bool
}
