package serviceaccount

import (
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type AccountState string

const (
	AccountStateActive   AccountState = "active"
	AccountStateArchived AccountState = "archived"
)

type Account struct {
	ID                     uuid.UUID
	TenantID               uuid.UUID
	Key                    string
	DisplayName            string
	Description            string
	State                  AccountState
	CreatedByMembershipID  uuid.UUID
	ArchivedAt             *time.Time
	ArchivedByMembershipID *uuid.UUID
	ArchiveReason          *string
	Version                int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type AccountPage struct {
	Items      []Account
	NextCursor *uuid.UUID
}

type RoleSummary struct {
	ID          uuid.UUID
	Key         string
	DisplayName string
	System      bool
}

type RoleGrantState string

const (
	RoleGrantStateActive  RoleGrantState = "active"
	RoleGrantStateExpired RoleGrantState = "expired"
	RoleGrantStateRevoked RoleGrantState = "revoked"
)

type RoleGrant struct {
	ID                         uuid.UUID
	TenantID                   uuid.UUID
	ServiceAccountID           uuid.UUID
	Role                       RoleSummary
	SourceID                   uuid.UUID
	SourceKind                 authorization.AuthorizationSourceKind
	SourceKey                  string
	SourceAuthoritative        bool
	SourceRetiredAt            *time.Time
	GrantedByMembershipID      uuid.UUID
	GrantedByUserID            uuid.UUID
	GrantReason                string
	GrantedAt                  time.Time
	ExpiresAt                  *time.Time
	State                      RoleGrantState
	RevokedAt                  *time.Time
	RevokedByMembershipID      *uuid.UUID
	RevokedByUserID            *uuid.UUID
	RevokeReason               *string
	Version                    int64
	UpdatedAt                  time.Time
	ManagedByServiceAccountAPI bool
}

type RoleGrantPage struct {
	Items      []RoleGrant
	NextCursor *uuid.UUID
}

type CredentialState string

const (
	CredentialStateActive  CredentialState = "active"
	CredentialStateExpired CredentialState = "expired"
	CredentialStateRevoked CredentialState = "revoked"
)

// CredentialMetadata is the only credential representation allowed in list,
// detail, audit, logs, and caches. It deliberately excludes locator and digest
// in addition to the bearer secret.
type CredentialMetadata struct {
	ID                      uuid.UUID
	TenantID                uuid.UUID
	ServiceAccountID        uuid.UUID
	Label                   string
	FormatVersion           int16
	KeyVersion              int16
	Permissions             []authorization.ScopedPermission
	Networks                []netip.Prefix
	IssuedByMembershipID    uuid.UUID
	IssuedAt                time.Time
	ExpiresAt               time.Time
	RotatedFromCredentialID *uuid.UUID
	State                   CredentialState
	RevokedAt               *time.Time
	RevokedByMembershipID   *uuid.UUID
	RevokedByUserID         *uuid.UUID
	RevokeReason            *string
	LastUsedAt              *time.Time
	LastUsedIP              *netip.Addr
	Version                 int64
	UpdatedAt               time.Time
}

type CredentialPage struct {
	Items      []CredentialMetadata
	NextCursor *uuid.UUID
}

// CredentialSecret is a one-time mutation result. Callers must keep Token out
// of query caches, browser storage, URLs, telemetry, logs, and toast text.
type CredentialSecret struct {
	Credential CredentialMetadata
	Token      string
}

type PageInput struct {
	After *uuid.UUID
	Limit int
}

type ListAccountsInput struct {
	PageInput
	IncludeArchived bool
}

type CreateAccountInput struct {
	Key         string
	DisplayName string
	Description string
	Audit       authorization.AuditContext
}

type UpdateAccountInput struct {
	DisplayName     *string
	Description     *string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type ArchiveAccountInput struct {
	Reason          string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type ListRoleGrantsInput struct {
	PageInput
	IncludeRevoked bool
}

type GrantRoleInput struct {
	RoleID    uuid.UUID
	Reason    string
	ExpiresAt *time.Time
	Audit     authorization.AuditContext
}

type RevokeRoleGrantInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type ListCredentialsInput struct {
	PageInput
	IncludeRevoked bool
}

type IssueCredentialInput struct {
	Label          string
	ExpiresAt      time.Time
	Permissions    []authorization.ScopedPermission
	Networks       []netip.Prefix
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type RotateCredentialInput struct {
	Label           string
	ExpiresAt       time.Time
	Permissions     []authorization.ScopedPermission
	Networks        []netip.Prefix
	Reason          string
	IdempotencyKey  string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}

type RevokeCredentialInput struct {
	Reason          string
	ExpectedVersion *int64
	Audit           authorization.AuditContext
}
