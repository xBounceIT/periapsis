package authorization

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Actor is the narrow authenticated-session projection needed by tenant
// authorization. HTTP handlers map authentication.Session into this type.
type Actor struct {
	UserID               uuid.UUID
	SessionID            uuid.UUID
	ActiveTenantID       uuid.UUID
	AuthenticationMethod string
}

// AuditContext contains bounded request metadata forwarded to transactional
// mutation procedures. Zero-valued optional fields represent unavailable data.
type AuditContext struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	RemoteAddress netip.Addr
	UserAgent     string
}

type MembershipStatus string

const (
	MembershipStatusInvited   MembershipStatus = "invited"
	MembershipStatusActive    MembershipStatus = "active"
	MembershipStatusSuspended MembershipStatus = "suspended"
)

type LegacyMembershipRole string

const (
	LegacyMembershipRoleTenantAdmin     LegacyMembershipRole = "tenant_admin"
	LegacyMembershipRoleSOCManager      LegacyMembershipRole = "soc_manager"
	LegacyMembershipRoleSeniorAnalyst   LegacyMembershipRole = "senior_analyst"
	LegacyMembershipRoleAnalyst         LegacyMembershipRole = "analyst"
	LegacyMembershipRoleCustomerManager LegacyMembershipRole = "customer_manager"
	LegacyMembershipRoleCustomerUser    LegacyMembershipRole = "customer_user"
	LegacyMembershipRoleReadOnly        LegacyMembershipRole = "read_only"
)

type RoleGrantSourceType string

const (
	RoleGrantSourceDirect           RoleGrantSourceType = "direct"
	RoleGrantSourceGroup            RoleGrantSourceType = "group"
	RoleGrantSourceIdentityProvider RoleGrantSourceType = "identity_provider"
	RoleGrantSourceSystem           RoleGrantSourceType = "system"
)

// AuthorizationSourceKind identifies the owner category of one independently
// revocable authorization edge. It is deliberately separate from how an
// effective permission reaches a principal.
type AuthorizationSourceKind string

const (
	AuthorizationSourceSystem           AuthorizationSourceKind = "system"
	AuthorizationSourceTenantCreation   AuthorizationSourceKind = "tenant_creation"
	AuthorizationSourceManual           AuthorizationSourceKind = "manual"
	AuthorizationSourceIdentityMapping  AuthorizationSourceKind = "identity_mapping"
	AuthorizationSourcePlatformRecovery AuthorizationSourceKind = "platform_recovery"
)

type RoleGrantPathType string

const (
	RoleGrantPathDirect RoleGrantPathType = "direct"
	RoleGrantPathGroup  RoleGrantPathType = "group"
)

type RoleGrantProvenance struct {
	SourceType      RoleGrantSourceType
	SourceKind      AuthorizationSourceKind
	SourceID        *uuid.UUID
	Authoritative   bool
	RetiredAt       *time.Time
	GrantedByUserID *uuid.UUID
	GrantedAt       time.Time
	Reason          string
	ExpiresAt       *time.Time
}

type AuthorizationEdgeProvenance struct {
	SourceKind      AuthorizationSourceKind
	SourceID        *uuid.UUID
	Authoritative   bool
	RetiredAt       *time.Time
	GrantedByUserID *uuid.UUID
	GrantedAt       time.Time
	Reason          string
	ExpiresAt       *time.Time
}

type DirectTenantRoleAuthorityPath struct {
	GrantID    uuid.UUID
	Provenance RoleGrantProvenance
}

type TenantSecurityGroupAuthorityEdge struct {
	ID         uuid.UUID
	Provenance AuthorizationEdgeProvenance
}

type GroupTenantRoleAuthorityPath struct {
	Group          TenantSecurityGroupAuthoritySummary
	MembershipEdge TenantSecurityGroupAuthorityEdge
	RoleGrantEdge  TenantSecurityGroupAuthorityEdge
}

type TenantSecurityGroupAuthoritySummary struct {
	ID   uuid.UUID
	Key  string
	Name string
}

type EffectiveTenantRoleAuthorityPath struct {
	PathType RoleGrantPathType
	Direct   *DirectTenantRoleAuthorityPath
	Group    *GroupTenantRoleAuthorityPath
}

type EffectiveTenantRoleGrant struct {
	GrantID            uuid.UUID
	RoleID             uuid.UUID
	RoleKey            string
	RoleName           string
	Provenance         RoleGrantProvenance
	Path               EffectiveTenantRoleAuthorityPath
	EffectiveExpiresAt *time.Time
}

type TenantPermissionDefinition struct {
	ID             uuid.UUID
	Key            TenantPermission
	Name           string
	Description    string
	AllowedScopes  []Scope
	PrincipalKinds []PrincipalKind
}

type TenantPermissionPage struct {
	Items      []TenantPermissionDefinition
	NextCursor *uuid.UUID
}

type TenantRolePolicy struct {
	Permissions       []ScopedPermission
	DelegationCeiling []ScopedPermission
}

type TenantRoleSummary struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	Key           string
	Name          string
	Description   string
	PrincipalKind PrincipalKind
	System        bool
	Archived      bool
	ArchivedAt    *time.Time
	Version       int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type TenantRole struct {
	TenantRoleSummary
	Policy TenantRolePolicy
}

type TenantRolePage struct {
	Items      []TenantRoleSummary
	NextCursor *uuid.UUID
}

type TenantUserProfile struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
	Active      bool
}

type TenantUserSummary struct {
	TenantID             uuid.UUID
	MembershipID         uuid.UUID
	User                 TenantUserProfile
	MembershipStatus     MembershipStatus
	LegacyMembershipRole LegacyMembershipRole
	LifecycleRevision    int64
	EntityTag            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type TenantUserPage struct {
	Items      []TenantUserSummary
	NextCursor *uuid.UUID
}

// TenantMembershipLifecycleInput is one payload-bound suspend/reactivate
// command. ExpectedRevision must also be carried by the exact strong If-Match
// header at the transport boundary.
type TenantMembershipLifecycleInput struct {
	ExpectedRevision *int64
	Reason           string
	IdempotencyKey   string
	Audit            AuditContext
}

// TenantMembershipLifecycleReceipt is the durable result of one atomic
// membership transition and its security consequences.
type TenantMembershipLifecycleReceipt struct {
	TenantID                 uuid.UUID
	MembershipID             uuid.UUID
	UserID                   uuid.UUID
	PreviousStatus           MembershipStatus
	Status                   MembershipStatus
	LifecycleRevision        int64
	EntityTag                string
	UpdatedAt                time.Time
	RevokedSessionCount      int64
	RevokedContinuationCount int64
	Replayed                 bool
}

type DirectRoleGrantState string

const (
	DirectRoleGrantStateActive  DirectRoleGrantState = "active"
	DirectRoleGrantStateExpired DirectRoleGrantState = "expired"
	DirectRoleGrantStateRevoked DirectRoleGrantState = "revoked"
)

type DirectUserRoleGrant struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	UserID          uuid.UUID
	Role            TenantRoleSummary
	Provenance      RoleGrantProvenance
	PathType        RoleGrantPathType
	State           DirectRoleGrantState
	RevokedAt       *time.Time
	RevokedByUserID *uuid.UUID
	RevokeReason    *string
	Version         int64
	UpdatedAt       time.Time
	// ManagedByAuthorizationAPI is a repository-derived ownership fact. Callers
	// must never infer it from the public provenance projection.
	ManagedByAuthorizationAPI bool
}

type TenantSecurityGroup struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Key         string
	Name        string
	Description string
	Archived    bool
	ArchivedAt  *time.Time
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type TenantSecurityGroupPage struct {
	Items      []TenantSecurityGroup
	NextCursor *uuid.UUID
}

type AuthorizationEdgeState string

const (
	AuthorizationEdgeStateActive  AuthorizationEdgeState = "active"
	AuthorizationEdgeStateExpired AuthorizationEdgeState = "expired"
	AuthorizationEdgeStateRevoked AuthorizationEdgeState = "revoked"
)

type TenantSecurityGroupMembership struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	Group           TenantSecurityGroup
	Member          TenantUserSummary
	Provenance      AuthorizationEdgeProvenance
	State           AuthorizationEdgeState
	RevokedAt       *time.Time
	RevokedByUserID *uuid.UUID
	RevokeReason    *string
	Version         int64
	UpdatedAt       time.Time
	// ManagedByAuthorizationAPI is a repository-derived ownership fact. Callers
	// must never infer it from the public provenance projection.
	ManagedByAuthorizationAPI bool
}

type TenantSecurityGroupMembershipPage struct {
	Items      []TenantSecurityGroupMembership
	NextCursor *uuid.UUID
}

type TenantSecurityGroupRoleGrant struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	Group           TenantSecurityGroup
	Role            TenantRoleSummary
	Provenance      AuthorizationEdgeProvenance
	State           AuthorizationEdgeState
	RevokedAt       *time.Time
	RevokedByUserID *uuid.UUID
	RevokeReason    *string
	Version         int64
	UpdatedAt       time.Time
	// ManagedByAuthorizationAPI is a repository-derived ownership fact. Callers
	// must never infer it from the public provenance projection.
	ManagedByAuthorizationAPI bool
}

type TenantSecurityGroupRoleGrantPage struct {
	Items      []TenantSecurityGroupRoleGrant
	NextCursor *uuid.UUID
}

type DirectUserRoleGrantPage struct {
	Items      []DirectUserRoleGrant
	NextCursor *uuid.UUID
}

type PageInput struct {
	After *uuid.UUID
	Limit int
}

type ListTenantRolesInput struct {
	PageInput
	IncludeArchived bool
}

type CreateTenantRoleInput struct {
	Key            string
	Name           string
	Description    string
	Policy         TenantRolePolicy
	IdempotencyKey string
	Audit          AuditContext
}

type UpdateTenantRoleInput struct {
	Name            *string
	Description     *string
	ExpectedVersion *int64
	Audit           AuditContext
}

type ArchiveTenantRoleInput struct {
	ExpectedVersion *int64
	Audit           AuditContext
}

type ReplaceTenantRolePolicyInput struct {
	Policy          TenantRolePolicy
	ExpectedVersion *int64
	Audit           AuditContext
}

type ListUserRoleGrantsInput struct {
	PageInput
	IncludeRevoked bool
}

type GrantUserRoleInput struct {
	RoleID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
	Audit          AuditContext
}

type RevokeRoleGrantInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             AuditContext
}

type ListTenantSecurityGroupsInput struct {
	PageInput
	IncludeArchived bool
}

type CreateTenantSecurityGroupInput struct {
	Key            string
	Name           string
	Description    string
	IdempotencyKey string
	Audit          AuditContext
}

type UpdateTenantSecurityGroupInput struct {
	Name            *string
	Description     *string
	ExpectedVersion *int64
	Audit           AuditContext
}

type ArchiveTenantSecurityGroupInput struct {
	ExpectedVersion *int64
	Audit           AuditContext
}

type ListTenantSecurityGroupEdgesInput struct {
	PageInput
	IncludeRevoked bool
}

type AddTenantSecurityGroupMembershipInput struct {
	UserID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
	Audit          AuditContext
}

type RevokeTenantSecurityGroupMembershipInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             AuditContext
}

type GrantTenantSecurityGroupRoleInput struct {
	RoleID         uuid.UUID
	Reason         string
	ExpiresAt      *time.Time
	IdempotencyKey string
	Audit          AuditContext
}

type RevokeTenantSecurityGroupRoleGrantInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             AuditContext
}
