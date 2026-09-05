package ticketnumbering

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type TenantAuthorityResolver interface {
	GetTenantAuthority(context.Context, authorization.Actor, uuid.UUID) (authorization.TenantAuthority, error)
}

type ReadParams struct {
	Actor    authorization.Actor
	TenantID uuid.UUID
	Kind     kernel.AggregateKind
}

type PolicyPlanBuilder func(kernel.NumberingPolicy) (kernel.NumberingPolicyPlan, error)
type ReplaceResultValidator func(ReplaceResult) error

type ReplaceParams struct {
	Actor           authorization.Actor
	TenantID        uuid.UUID
	Kind            kernel.AggregateKind
	ExpectedVersion uint64
	Command         CommandBinding
	Reason          string
	Audit           authentication.EventContext
	BuildPlan       PolicyPlanBuilder
	ValidateResult  ReplaceResultValidator
}

func (ReadParams) String() string            { return "ticketnumbering.ReadParams{redacted}" }
func (value ReadParams) GoString() string    { return value.String() }
func (ReplaceParams) String() string         { return "ticketnumbering.ReplaceParams{redacted}" }
func (value ReplaceParams) GoString() string { return value.String() }

// Repository is the persistence and transaction boundary for numbering policy
// administration.
//
// Current must install the exact actor/tenant context and rely on forced RLS in
// addition to application predicates. Replace must start one transaction,
// revalidate the live session, membership, settings.read and settings.manage
// grants, then look up the actor-scoped Command before policy CAS. An exact
// command replay returns the original immutable policy with Replayed=true and
// does not invoke BuildPlan. Divergent key reuse fails with
// ErrRepositoryConflict. A stale current version is reported separately as
// ErrRepositoryPrecondition so the HTTP boundary can preserve 409 versus 412.
//
// For a fresh command Replace locks the tenant+kind current-policy coordinate,
// invokes BuildPlan exactly once with that row, compares ExpectedVersion,
// appends the returned immutable version, advances the current pointer, and
// writes minimized audit, activity/outbox, and command-result records in the
// same transaction. Existing policy-version rows are never updated or deleted.
// ValidateResult must be invoked exactly once after constructing the outward
// result and before commit; any validation error rolls the transaction back.
type Repository interface {
	Current(context.Context, ReadParams) (kernel.NumberingPolicy, error)
	Replace(context.Context, ReplaceParams) (ReplaceResult, error)
}
