package webhookurlpolicy

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type TenantAuthorityResolver interface {
	GetTenantAuthority(context.Context, authorization.Actor, uuid.UUID) (authorization.TenantAuthority, error)
}

type ReadParams struct {
	Actor    authorization.Actor
	TenantID uuid.UUID
}

type PolicyPlanBuilder func(*Policy) (PolicyPlan, error)
type PublishResultValidator func(PublishResult) error

type PublishParams struct {
	Actor                 authorization.Actor
	PublisherMembershipID uuid.UUID
	TenantID              uuid.UUID
	ExpectedVersion       int64
	Command               CommandBinding
	Reason                string
	Audit                 authentication.EventContext
	BuildPlan             PolicyPlanBuilder
	ValidateResult        PublishResultValidator
}

func (ReadParams) String() string            { return "webhookurlpolicy.ReadParams{redacted}" }
func (value ReadParams) GoString() string    { return value.String() }
func (PublishParams) String() string         { return "webhookurlpolicy.PublishParams{redacted}" }
func (value PublishParams) GoString() string { return value.String() }

// Repository is the transaction and persistence boundary for webhook URL
// policy administration. Every operation must install the exact actor/tenant
// context and depend on forced RLS in addition to explicit tenant predicates.
//
// Publish revalidates the live session, membership and notification.manage
// inside its transaction. It looks up the actor+membership-
// scoped command before taking the policy CAS lock. An exact replay returns the
// original immutable policy with Replayed=true; divergent key reuse returns
// ErrRepositoryConflict. A concurrent caller may already have invoked its pure
// BuildPlan once before losing the command insert race. In that case it returns
// the stored winner as an exact replay and must not persist its losing plan.
//
// For a fresh command, Publish locks the tenant current-policy coordinate,
// passes nil to BuildPlan only when no policy exists, invokes it at most once,
// compares ExpectedVersion, appends the new version, advances the pointer, and
// writes the redacted audit and command-result records atomically. Existing
// versions are never updated or deleted. ValidateResult is called exactly once
// before commit and any error rolls the entire transaction back.
type Repository interface {
	Current(context.Context, ReadParams) (Policy, error)
	Publish(context.Context, PublishParams) (PublishResult, error)
}
