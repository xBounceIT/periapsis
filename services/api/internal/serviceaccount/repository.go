package serviceaccount

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type CredentialMutationResult struct {
	Credential CredentialMetadata
	Replayed   bool
}

// Repository is the bounded persistence boundary for tenant machine
// principals. Every method re-resolves the human actor and authorization in the
// same transaction as its read or mutation. Credential mutations receive only
// derived bearer material; raw bearer tokens must never cross this interface.
type Repository interface {
	ResolveHumanAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)

	ListAccounts(context.Context, ListAccountsParams) ([]Account, error)
	GetAccount(context.Context, GetAccountParams) (Account, error)
	CreateAccount(context.Context, CreateAccountParams) (Account, error)
	UpdateAccount(context.Context, UpdateAccountParams) (Account, error)
	ArchiveAccount(context.Context, ArchiveAccountParams) error

	ListRoleGrants(context.Context, ListRoleGrantsParams) ([]RoleGrant, error)
	GetRoleGrant(context.Context, GetRoleGrantParams) (RoleGrant, error)
	GrantRole(context.Context, GrantRoleParams) (RoleGrant, error)
	RevokeRoleGrant(context.Context, RevokeRoleGrantParams) error

	ListCredentials(context.Context, ListCredentialsParams) ([]CredentialMetadata, error)
	GetCredential(context.Context, GetCredentialParams) (CredentialMetadata, error)
	IssueCredential(context.Context, IssueCredentialParams) (CredentialMutationResult, error)
	RotateCredential(context.Context, RotateCredentialParams) (CredentialMutationResult, error)
	RevokeCredential(context.Context, RevokeCredentialParams) error
}

type HumanParams struct {
	Actor        authorization.Actor
	MembershipID uuid.UUID
	TenantID     uuid.UUID
}

type ListAccountsParams struct {
	HumanParams
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type GetAccountParams struct {
	HumanParams
	ServiceAccountID uuid.UUID
}

type CreateAccountParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	Key              string
	DisplayName      string
	Description      string
}

type UpdateAccountParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	DisplayName      *string
	Description      *string
	ExpectedVersion  int64
}

type ArchiveAccountParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	Reason           string
	ExpectedVersion  int64
}

type ListRoleGrantsParams struct {
	HumanParams
	ServiceAccountID uuid.UUID
	After            *uuid.UUID
	Limit            int32
	IncludeRevoked   bool
}

type GetRoleGrantParams struct {
	HumanParams
	ServiceAccountID uuid.UUID
	GrantID          uuid.UUID
}

type GrantRoleParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	GrantID          uuid.UUID
	RoleID           uuid.UUID
	Reason           string
	ExpiresAt        *time.Time
}

type RevokeRoleGrantParams struct {
	HumanParams
	Audit             authorization.AuditContext
	OccurredAt        time.Time
	ServiceAccountID  uuid.UUID
	GrantID           uuid.UUID
	Reason            string
	ExpectedEntityTag string
}

type ListCredentialsParams struct {
	HumanParams
	ServiceAccountID uuid.UUID
	After            *uuid.UUID
	Limit            int32
	IncludeRevoked   bool
}

type GetCredentialParams struct {
	HumanParams
	ServiceAccountID uuid.UUID
	CredentialID     uuid.UUID
}

type CredentialWrite struct {
	CredentialID  uuid.UUID
	Label         string
	FormatVersion int16
	Material      PresentedCredential
	ExpiresAt     time.Time
	Permissions   []authorization.ScopedPermission
	Networks      []netip.Prefix
	KeyDigest     [32]byte
	RequestDigest [32]byte
}

type IssueCredentialParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	Write            CredentialWrite
}

type RotateCredentialParams struct {
	HumanParams
	Audit                authorization.AuditContext
	OccurredAt           time.Time
	ServiceAccountID     uuid.UUID
	PreviousCredentialID uuid.UUID
	ExpectedVersion      int64
	Reason               string
	Write                CredentialWrite
}

type RevokeCredentialParams struct {
	HumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ServiceAccountID uuid.UUID
	CredentialID     uuid.UUID
	Reason           string
	ExpectedVersion  int64
}
