package operatorteam

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type IdempotentCreateResult[T any] struct {
	Value    T
	Replayed bool
}

type PlatformActor struct {
	UserID               uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

// Repository is the persistence boundary for operator teams. CreateOperatorTeam,
// StartTenantAssignment, and AddRosterEntry bind the actor, operation,
// idempotency key, and complete normalized payload. A key reused for a different
// payload returns ErrConflict. An exact replay returns the current representation
// of the original resource without repeating state or audit; in particular,
// replaying StartTenantAssignment never reopens an ended epoch. Every mutation
// implementation must recheck its authorization and version predicates in the
// same transaction as state and append-only audit changes. Start/end assignment
// operations cross the platform/tenant boundary and must append both events
// with the same Audit command/correlation identity atomically. EndAssignment,
// AddRosterEntry, and RevokeRosterEntry must also transactionally re-resolve
// role.grant and reject every forbidden authorization consequence. Archive must
// return ErrConflict if any active assignment exists. Start must insert the
// supplied fresh epoch and never reactivate an old one. Every roster query and
// mutation must constrain tenant, global team, and assignment epoch together.
type Repository interface {
	ResolveAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)

	ListOperatorTeams(context.Context, ListOperatorTeamsParams) ([]OperatorTeam, error)
	GetOperatorTeam(context.Context, GetOperatorTeamParams) (OperatorTeam, error)
	CreateOperatorTeam(context.Context, CreateOperatorTeamParams) (IdempotentCreateResult[OperatorTeam], error)
	PatchOperatorTeam(context.Context, PatchOperatorTeamParams) (OperatorTeam, error)
	ArchiveOperatorTeam(context.Context, ArchiveOperatorTeamParams) error

	ListTenantAssignments(context.Context, ListTenantAssignmentsParams) ([]TenantAssignment, error)
	GetTenantAssignment(context.Context, GetTenantAssignmentParams) (TenantAssignment, error)
	StartTenantAssignment(context.Context, StartTenantAssignmentParams) (IdempotentCreateResult[TenantAssignment], error)
	EndTenantAssignment(context.Context, EndTenantAssignmentParams) error

	ListRosterEntries(context.Context, ListRosterEntriesParams) ([]RosterEntry, error)
	GetRosterEntry(context.Context, GetRosterEntryParams) (RosterEntry, error)
	AddRosterEntry(context.Context, AddRosterEntryParams) (IdempotentCreateResult[RosterEntry], error)
	RevokeRosterEntry(context.Context, RevokeRosterEntryParams) error
}

type ListOperatorTeamsParams struct {
	Actor           PlatformActor
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type GetOperatorTeamParams struct {
	Actor          PlatformActor
	OperatorTeamID uuid.UUID
}

type CreateOperatorTeamParams struct {
	Actor          PlatformActor
	Audit          authorization.AuditContext
	OccurredAt     time.Time
	OperatorTeamID uuid.UUID
	Key            string
	Name           string
	Description    string
	IdempotencyKey string
}

type PatchOperatorTeamParams struct {
	Actor           PlatformActor
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	OperatorTeamID  uuid.UUID
	Name            *string
	Description     *string
	ExpectedVersion int64
}

type ArchiveOperatorTeamParams struct {
	Actor           PlatformActor
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	OperatorTeamID  uuid.UUID
	Reason          string
	ExpectedVersion int64
}

type ListTenantAssignmentsParams struct {
	Actor        authorization.Actor
	TenantID     uuid.UUID
	After        *uuid.UUID
	Limit        int32
	IncludeEnded bool
}

type GetTenantAssignmentParams struct {
	Actor          authorization.Actor
	TenantID       uuid.UUID
	OperatorTeamID uuid.UUID
	EpochID        uuid.UUID
}

type StartTenantAssignmentParams struct {
	Actor          authorization.Actor
	Audit          authorization.AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	OperatorTeamID uuid.UUID
	EpochID        uuid.UUID
	Reason         string
	IdempotencyKey string
}

type EndTenantAssignmentParams struct {
	Actor           authorization.Actor
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	OperatorTeamID  uuid.UUID
	EpochID         uuid.UUID
	Reason          string
	ExpectedVersion int64
}

type ListRosterEntriesParams struct {
	Actor             authorization.Actor
	TenantID          uuid.UUID
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
	After             *uuid.UUID
	Limit             int32
	IncludeRevoked    bool
}

type GetRosterEntryParams struct {
	Actor             authorization.Actor
	TenantID          uuid.UUID
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
	RosterEntryID     uuid.UUID
}

type AddRosterEntryParams struct {
	Actor             authorization.Actor
	Audit             authorization.AuditContext
	OccurredAt        time.Time
	TenantID          uuid.UUID
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
	RosterEntryID     uuid.UUID
	MembershipID      uuid.UUID
	Reason            string
	ExpiresAt         *time.Time
	IdempotencyKey    string
}

type RevokeRosterEntryParams struct {
	Actor             authorization.Actor
	Audit             authorization.AuditContext
	OccurredAt        time.Time
	TenantID          uuid.UUID
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
	RosterEntryID     uuid.UUID
	Reason            string
	ExpectedEntityTag string
}
