// Package mfapolicy implements protected platform and tenant MFA-policy
// administration without owning HTTP or PostgreSQL transport details.
package mfapolicy

import (
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	DefaultPageSize     = 50
	MaximumPageSize     = 100
	MaximumSafeRevision = int64(9_007_199_254_740_991)
)

type Cursor struct {
	ID       uuid.UUID
	Revision int64
}

type ListInput struct {
	After          *Cursor
	Limit          int
	IncludeRetired bool
}

type Page struct {
	Items      []mfa.PolicyDocument
	NextCursor *Cursor
}

type SimulationInput struct {
	Operation        mfa.PolicyChangeOperation
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID *uuid.UUID
	Requirement      *mfa.PolicyRequirement
	Context          *mfa.PolicySimulationContext
}

type PublishInput struct {
	CommandID        uuid.UUID
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID *uuid.UUID
	Requirement      mfa.PolicyRequirement
	Reason           string
	Event            authentication.EventContext
}

type RetireInput struct {
	CommandID        uuid.UUID
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID uuid.UUID
	Reason           string
	Event            authentication.EventContext
}

type MutationResult struct {
	Policy   mfa.PolicyDocument
	Replayed bool
}

type SessionParams struct {
	ActorID              uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

type ListParams struct {
	SessionParams
	TenantID       uuid.UUID
	After          *Cursor
	Limit          int32
	IncludeRetired bool
}

type GetParams struct {
	SessionParams
	TenantID uuid.UUID
	PolicyID uuid.UUID
	Revision int64
}

type SimulationParams struct {
	SessionParams
	TenantID         uuid.UUID
	Operation        mfa.PolicyChangeOperation
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID *uuid.UUID
	Requirement      *mfa.PolicyRequirement
	Context          *mfa.PolicySimulationContext
}

type CommandAudit struct {
	EventID uuid.UUID
	Event   authentication.EventContext
}

type MutationResultValidator func(MutationResult) (MutationResult, error)

type PublishParams struct {
	SessionParams
	TenantID         uuid.UUID
	CommandID        uuid.UUID
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID *uuid.UUID
	Requirement      mfa.PolicyRequirement
	Reason           string
	Audit            CommandAudit
	ValidateResult   MutationResultValidator
}

type RetireParams struct {
	SessionParams
	TenantID         uuid.UUID
	CommandID        uuid.UUID
	Target           mfa.AdministrationTarget
	ExpectedRevision int64
	ExpectedPolicyID uuid.UUID
	Reason           string
	Audit            CommandAudit
	ValidateResult   MutationResultValidator
}

func cloneRequirement(value mfa.PolicyRequirement) mfa.PolicyRequirement {
	if value.EnrollmentDeadline != nil {
		deadline := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &deadline
	}
	return value
}

func cloneSimulationContext(value *mfa.PolicySimulationContext) *mfa.PolicySimulationContext {
	if value == nil {
		return nil
	}
	result := *value
	result.RoleIDs = append([]identity.EntityID(nil), value.RoleIDs...)
	result.SecurityGroupIDs = append([]identity.EntityID(nil), value.SecurityGroupIDs...)
	return &result
}

func cloneInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
