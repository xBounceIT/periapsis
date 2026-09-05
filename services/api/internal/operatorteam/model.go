// Package operatorteam implements the global operator-team identity and its
// tenant-owned assignment-epoch and exact-epoch roster use cases.
package operatorteam

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type OperatorTeamState string

const (
	OperatorTeamStateActive   OperatorTeamState = "active"
	OperatorTeamStateArchived OperatorTeamState = "archived"
)

type OperatorTeamSummary struct {
	ID    uuid.UUID
	Key   string
	Name  string
	State OperatorTeamState
}

// OperatorTeam is a platform-owned global identity. It conveys no tenant
// authority by itself.
type OperatorTeam struct {
	OperatorTeamSummary
	Description           string
	CreatedByUserID       *uuid.UUID
	ArchivedAt            *time.Time
	ArchivedByUserID      *uuid.UUID
	ArchiveReason         *string
	ActiveAssignmentCount int64
	Version               int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type OperatorTeamPage struct {
	Items      []OperatorTeam
	NextCursor *uuid.UUID
}

type AssignmentState string

const (
	AssignmentStateActive AssignmentState = "active"
	AssignmentStateEnded  AssignmentState = "ended"
)

// TenantAssignment is one immutable tenant/team relationship epoch. A later
// relationship between the same tenant and team receives a fresh EpochID.
type TenantAssignment struct {
	EpochID         uuid.UUID
	TenantID        uuid.UUID
	OperatorTeam    OperatorTeamSummary
	State           AssignmentState
	StartedAt       time.Time
	StartedByUserID uuid.UUID
	StartReason     string
	EndedAt         *time.Time
	EndedByUserID   *uuid.UUID
	EndReason       *string
	Version         int64
	UpdatedAt       time.Time
}

type TenantAssignmentPage struct {
	Items      []TenantAssignment
	NextCursor *uuid.UUID
}

// TenantMember identifies the active tenant membership, rather than only the
// global user, to which an exact-epoch roster entry is bound.
type TenantMember struct {
	MembershipID uuid.UUID
	UserID       uuid.UUID
	DisplayName  string
	Status       authorization.MembershipStatus
}

type RosterEntryState string

const (
	RosterEntryStateActive  RosterEntryState = "active"
	RosterEntryStateExpired RosterEntryState = "expired"
	RosterEntryStateRevoked RosterEntryState = "revoked"
)

// RosterEntry contributes an operator-team relationship only while both this
// entry and its exact AssignmentEpochID remain live in the same tenant.
type RosterEntry struct {
	ID                       uuid.UUID
	TenantID                 uuid.UUID
	AssignmentEpochID        uuid.UUID
	OperatorTeamID           uuid.UUID
	Member                   TenantMember
	Provenance               authorization.AuthorizationEdgeProvenance
	State                    RosterEntryState
	RevokedAt                *time.Time
	RevokedByUserID          *uuid.UUID
	RevokeReason             *string
	Version                  int64
	UpdatedAt                time.Time
	ManagedByOperatorTeamAPI bool
}

type RosterEntryPage struct {
	Items      []RosterEntry
	NextCursor *uuid.UUID
}

type PageInput struct {
	After *uuid.UUID
	Limit int
}

type ListOperatorTeamsInput struct {
	PageInput
	IncludeArchived bool
}

type CreateOperatorTeamInput struct {
	Key            string
	Name           string
	Description    string
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type PatchOperatorTeamInput struct {
	Name            *string
	Description     *string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type ArchiveOperatorTeamInput struct {
	Reason          string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type ListTenantAssignmentsInput struct {
	PageInput
	IncludeEnded bool
}

type StartTenantAssignmentInput struct {
	Reason         string
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type EndTenantAssignmentInput struct {
	Reason          string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type ListRosterEntriesInput struct {
	PageInput
	IncludeRevoked bool
}

type AddRosterEntryInput struct {
	MembershipID   uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type RevokeRosterEntryInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}
