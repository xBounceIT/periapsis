package identityprovider

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// Repository is the bounded tenant LDAP-provider persistence surface. Every
// implementation must install tenant/user context and call only the protected
// database ABI. BeginTest and CompleteTest are deliberately separate committed
// transactions; callers perform network work only between them.
type Repository interface {
	ResolveHumanAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)

	List(context.Context, ListParams) ([]ProviderSummary, error)
	Get(context.Context, GetParams) (Provider, error)
	Create(context.Context, CreateParams) (CreateResult, error)
	Update(context.Context, UpdateParams) (int64, error)
	Archive(context.Context, ArchiveParams) (int64, error)

	GetBindSecretID(context.Context, GetBindSecretIDParams) (*uuid.UUID, error)
	RotateBindSecret(context.Context, RotateBindSecretParams) (int64, error)
	ClearBindSecret(context.Context, ClearBindSecretParams) (int64, error)

	BeginTest(context.Context, BeginTestParams) (TestSnapshot, error)
	CompleteTest(context.Context, CompleteTestParams) (TestResult, error)
}

type HumanParams struct {
	Actor        authorization.Actor
	MembershipID uuid.UUID
	TenantID     uuid.UUID
}

type ListParams struct {
	HumanParams
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type GetParams struct {
	HumanParams
	ProviderID uuid.UUID
}

type CreateParams struct {
	HumanParams
	Audit                authorization.AuditContext
	OccurredAt           time.Time
	ProviderID           uuid.UUID
	IdempotencyKeyDigest [32]byte
	Key                  string
	DisplayName          string
	Description          string
	Configuration        Configuration
	Endpoints            []Endpoint
}

type UpdateParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Key             string
	DisplayName     string
	Description     string
	Enabled         bool
	Configuration   Configuration
	Endpoints       []Endpoint
}

type ArchiveParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
}

type GetBindSecretIDParams struct {
	HumanParams
	ProviderID uuid.UUID
}

type RotateBindSecretParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Secret          EncryptedBindSecret
}

type ClearBindSecretParams struct {
	HumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
}

type BeginTestParams struct {
	HumanParams
	Audit      authorization.AuditContext
	OccurredAt time.Time
	TestRunID  uuid.UUID
	ProviderID uuid.UUID
	Kind       TestKind
}

type CompleteTestParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	TestRunID        uuid.UUID
	ReportedOutcome  TestOutcome
	ReportedCategory TestCategory
	EndpointPriority *int
	Duration         time.Duration
}
