package authorization

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// IdempotentCreateResult distinguishes a newly persisted resource from the
// current representation returned by an exact command replay.
type IdempotentCreateResult[T any] struct {
	Value    T
	Replayed bool
}

// Repository is the persistence boundary for tenant authorization. Mutation
// implementations must re-resolve authority, recheck protected invariants, and
// append audit state atomically rather than trusting the service precheck.
type Repository interface {
	ResolveAuthority(context.Context, ResolveAuthorityParams) (TenantAuthority, error)
	ListTenantPermissions(context.Context, ListTenantPermissionsParams) ([]TenantPermissionDefinition, error)
	ListTenantRoles(context.Context, ListTenantRolesParams) ([]TenantRoleSummary, error)
	CreateTenantRole(context.Context, CreateTenantRoleParams) (IdempotentCreateResult[TenantRole], error)
	GetTenantRole(context.Context, GetTenantRoleParams) (TenantRole, error)
	UpdateTenantRole(context.Context, UpdateTenantRoleParams) (TenantRole, error)
	ArchiveTenantRole(context.Context, ArchiveTenantRoleParams) error
	ReplaceTenantRolePolicy(context.Context, ReplaceTenantRolePolicyParams) (TenantRole, error)
	ListTenantUsers(context.Context, ListTenantUsersParams) ([]TenantUserSummary, error)
	ChangeTenantMembershipLifecycle(context.Context, ChangeTenantMembershipLifecycleParams) (TenantMembershipLifecycleReceipt, error)
	ListUserRoleGrants(context.Context, ListUserRoleGrantsParams) ([]DirectUserRoleGrant, error)
	GetUserRoleGrant(context.Context, GetUserRoleGrantParams) (DirectUserRoleGrant, error)
	GrantUserRole(context.Context, GrantUserRoleParams) (IdempotentCreateResult[DirectUserRoleGrant], error)
	RevokeRoleGrant(context.Context, RevokeRoleGrantParams) error
	ListTenantSecurityGroups(context.Context, ListTenantSecurityGroupsParams) ([]TenantSecurityGroup, error)
	CreateTenantSecurityGroup(context.Context, CreateTenantSecurityGroupParams) (IdempotentCreateResult[TenantSecurityGroup], error)
	GetTenantSecurityGroup(context.Context, GetTenantSecurityGroupParams) (TenantSecurityGroup, error)
	UpdateTenantSecurityGroup(context.Context, UpdateTenantSecurityGroupParams) (TenantSecurityGroup, error)
	ArchiveTenantSecurityGroup(context.Context, ArchiveTenantSecurityGroupParams) error
	ListTenantSecurityGroupMemberships(context.Context, ListTenantSecurityGroupMembershipsParams) ([]TenantSecurityGroupMembership, error)
	GetTenantSecurityGroupMembership(context.Context, GetTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error)
	AddTenantSecurityGroupMembership(context.Context, AddTenantSecurityGroupMembershipParams) (IdempotentCreateResult[TenantSecurityGroupMembership], error)
	RevokeTenantSecurityGroupMembership(context.Context, RevokeTenantSecurityGroupMembershipParams) error
	ListTenantSecurityGroupRoleGrants(context.Context, ListTenantSecurityGroupRoleGrantsParams) ([]TenantSecurityGroupRoleGrant, error)
	GetTenantSecurityGroupRoleGrant(context.Context, GetTenantSecurityGroupRoleGrantParams) (TenantSecurityGroupRoleGrant, error)
	GrantTenantSecurityGroupRole(context.Context, GrantTenantSecurityGroupRoleParams) (IdempotentCreateResult[TenantSecurityGroupRoleGrant], error)
	RevokeTenantSecurityGroupRoleGrant(context.Context, RevokeTenantSecurityGroupRoleGrantParams) error
}

type ResolveAuthorityParams struct {
	Actor    Actor
	TenantID uuid.UUID
}

type ListTenantPermissionsParams struct {
	Actor    Actor
	TenantID uuid.UUID
	After    *uuid.UUID
	Limit    int32
}

type ListTenantRolesParams struct {
	Actor           Actor
	TenantID        uuid.UUID
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type CreateTenantRoleParams struct {
	Actor          Actor
	Audit          AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	RoleID         uuid.UUID
	Key            string
	Name           string
	Description    string
	Policy         TenantRolePolicy
	IdempotencyKey string
}

type GetTenantRoleParams struct {
	Actor    Actor
	TenantID uuid.UUID
	RoleID   uuid.UUID
}

type UpdateTenantRoleParams struct {
	Actor           Actor
	Audit           AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	RoleID          uuid.UUID
	Name            *string
	Description     *string
	ExpectedVersion int64
}

type ArchiveTenantRoleParams struct {
	Actor           Actor
	Audit           AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	RoleID          uuid.UUID
	ExpectedVersion int64
}

type ReplaceTenantRolePolicyParams struct {
	Actor           Actor
	Audit           AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	RoleID          uuid.UUID
	Policy          TenantRolePolicy
	ExpectedVersion int64
}

type ListTenantUsersParams struct {
	Actor    Actor
	TenantID uuid.UUID
	After    *uuid.UUID
	Limit    int32
}

type ChangeTenantMembershipLifecycleParams struct {
	Actor            Actor
	Audit            AuditContext
	OccurredAt       time.Time
	TenantID         uuid.UUID
	UserID           uuid.UUID
	TargetStatus     MembershipStatus
	ExpectedRevision int64
	Reason           string
	IdempotencyKey   string
}

type ListUserRoleGrantsParams struct {
	Actor          Actor
	TenantID       uuid.UUID
	UserID         uuid.UUID
	After          *uuid.UUID
	Limit          int32
	IncludeRevoked bool
}

type GetUserRoleGrantParams struct {
	Actor    Actor
	TenantID uuid.UUID
	GrantID  uuid.UUID
}

type GrantUserRoleParams struct {
	Actor          Actor
	Audit          AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	GrantID        uuid.UUID
	UserID         uuid.UUID
	RoleID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
}

type RevokeRoleGrantParams struct {
	Actor             Actor
	Audit             AuditContext
	OccurredAt        time.Time
	TenantID          uuid.UUID
	GrantID           uuid.UUID
	Reason            string
	ExpectedEntityTag string
}

type ListTenantSecurityGroupsParams struct {
	Actor           Actor
	TenantID        uuid.UUID
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type CreateTenantSecurityGroupParams struct {
	Actor          Actor
	Audit          AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	GroupID        uuid.UUID
	Key            string
	Name           string
	Description    string
	IdempotencyKey string
}

type GetTenantSecurityGroupParams struct {
	Actor    Actor
	TenantID uuid.UUID
	GroupID  uuid.UUID
}

type UpdateTenantSecurityGroupParams struct {
	Actor           Actor
	Audit           AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	GroupID         uuid.UUID
	Name            *string
	Description     *string
	ExpectedVersion int64
}

type ArchiveTenantSecurityGroupParams struct {
	Actor           Actor
	Audit           AuditContext
	OccurredAt      time.Time
	TenantID        uuid.UUID
	GroupID         uuid.UUID
	ExpectedVersion int64
}

type ListTenantSecurityGroupMembershipsParams struct {
	Actor          Actor
	TenantID       uuid.UUID
	GroupID        uuid.UUID
	After          *uuid.UUID
	Limit          int32
	IncludeRevoked bool
}

type GetTenantSecurityGroupMembershipParams struct {
	Actor        Actor
	TenantID     uuid.UUID
	GroupID      uuid.UUID
	MembershipID uuid.UUID
}

type AddTenantSecurityGroupMembershipParams struct {
	Actor          Actor
	Audit          AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	GroupID        uuid.UUID
	MembershipID   uuid.UUID
	UserID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
}

type RevokeTenantSecurityGroupMembershipParams struct {
	Actor             Actor
	Audit             AuditContext
	OccurredAt        time.Time
	TenantID          uuid.UUID
	GroupID           uuid.UUID
	MembershipID      uuid.UUID
	Reason            string
	ExpectedEntityTag string
}

type ListTenantSecurityGroupRoleGrantsParams struct {
	Actor          Actor
	TenantID       uuid.UUID
	GroupID        uuid.UUID
	After          *uuid.UUID
	Limit          int32
	IncludeRevoked bool
}

type GetTenantSecurityGroupRoleGrantParams struct {
	Actor    Actor
	TenantID uuid.UUID
	GroupID  uuid.UUID
	GrantID  uuid.UUID
}

type GrantTenantSecurityGroupRoleParams struct {
	Actor          Actor
	Audit          AuditContext
	OccurredAt     time.Time
	TenantID       uuid.UUID
	GroupID        uuid.UUID
	GrantID        uuid.UUID
	RoleID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
}

type RevokeTenantSecurityGroupRoleGrantParams struct {
	Actor             Actor
	Audit             AuditContext
	OccurredAt        time.Time
	TenantID          uuid.UUID
	GroupID           uuid.UUID
	GrantID           uuid.UUID
	Reason            string
	ExpectedEntityTag string
}
