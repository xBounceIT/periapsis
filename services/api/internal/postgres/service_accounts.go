package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

const (
	serviceAccountPageLimit = int32(101)

	serviceAccountVersionConflictMessage           = "tenant service account version conflict"
	serviceAccountRoleGrantVersionConflictMessage  = "tenant service-account role grant version conflict"
	serviceAccountCredentialVersionConflictMessage = "tenant API credential version conflict"
)

type serviceAccountQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	ListTenantServiceAccounts(context.Context, dbsql.ListTenantServiceAccountsParams) ([]*dbsql.ListTenantServiceAccountsRow, error)
	GetTenantServiceAccount(context.Context, dbsql.GetTenantServiceAccountParams) (*dbsql.GetTenantServiceAccountRow, error)
	CreateTenantServiceAccount(context.Context, dbsql.CreateTenantServiceAccountParams) (*dbsql.CreateTenantServiceAccountRow, error)
	UpdateTenantServiceAccount(context.Context, dbsql.UpdateTenantServiceAccountParams) (int32, error)
	ArchiveTenantServiceAccount(context.Context, dbsql.ArchiveTenantServiceAccountParams) (int32, error)
	ListTenantServiceAccountRoleGrants(context.Context, dbsql.ListTenantServiceAccountRoleGrantsParams) ([]*dbsql.ListTenantServiceAccountRoleGrantsRow, error)
	GetTenantServiceAccountRoleGrant(context.Context, dbsql.GetTenantServiceAccountRoleGrantParams) (*dbsql.GetTenantServiceAccountRoleGrantRow, error)
	GrantTenantServiceAccountRole(context.Context, dbsql.GrantTenantServiceAccountRoleParams) (*dbsql.GrantTenantServiceAccountRoleRow, error)
	RevokeTenantServiceAccountRoleGrant(context.Context, dbsql.RevokeTenantServiceAccountRoleGrantParams) (int32, error)
	ListTenantAPICredentials(context.Context, dbsql.ListTenantAPICredentialsParams) ([]*dbsql.ListTenantAPICredentialsRow, error)
	GetTenantAPICredential(context.Context, dbsql.GetTenantAPICredentialParams) (*dbsql.GetTenantAPICredentialRow, error)
	IssueTenantAPICredential(context.Context, dbsql.IssueTenantAPICredentialParams) (*dbsql.IssueTenantAPICredentialRow, error)
	RotateTenantAPICredential(context.Context, dbsql.RotateTenantAPICredentialParams) (*dbsql.RotateTenantAPICredentialRow, error)
	RevokeTenantAPICredential(context.Context, dbsql.RevokeTenantAPICredentialParams) (int32, error)
}

// ServiceAccountRepository keeps human context installation, authorization,
// redacted reads, and mutations inside the bounded database ABI.
type ServiceAccountRepository struct {
	begin        transactionBeginner
	queryFactory func(databaseTransaction) serviceAccountQueries
	authority    *AuthorizationRepository
}

func NewServiceAccountRepository(pool *pgxpool.Pool) *ServiceAccountRepository {
	return &ServiceAccountRepository{
		begin: poolTransactionBeginner(pool),
		queryFactory: func(tx databaseTransaction) serviceAccountQueries {
			return dbsql.New(tx)
		},
		authority: NewAuthorizationRepository(pool),
	}
}

var _ serviceaccount.Repository = (*ServiceAccountRepository)(nil)

func (r *ServiceAccountRepository) ResolveHumanAuthority(
	ctx context.Context,
	params authorization.ResolveAuthorityParams,
) (authorization.TenantAuthority, error) {
	if r == nil || r.authority == nil {
		return authorization.TenantAuthority{}, fmt.Errorf("%w: authorization repository is required", serviceaccount.ErrUnavailable)
	}
	return r.authority.ResolveAuthority(ctx, params)
}

func (r *ServiceAccountRepository) ListAccounts(
	ctx context.Context,
	params serviceaccount.ListAccountsParams,
) ([]serviceaccount.Account, error) {
	if !validServiceAccountHuman(params.HumanParams) ||
		!validServiceAccountPage(params.After, params.Limit) {
		return nil, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) ([]serviceaccount.Account, error) {
			rows, err := queries.ListTenantServiceAccounts(ctx, dbsql.ListTenantServiceAccountsParams{
				AfterID: optionalDatabaseUUID(params.After), IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapServiceAccountDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidServiceAccountProjection("oversized service-account page")
			}
			items := make([]serviceaccount.Account, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				account, mapErr := mapListedServiceAccount(params.TenantID, row)
				if mapErr != nil || previous != uuid.Nil && compareUUID(account.ID, previous) <= 0 {
					if mapErr != nil {
						return nil, mapErr
					}
					return nil, invalidServiceAccountProjection("non-monotonic service-account page")
				}
				if !params.IncludeArchived && account.State == serviceaccount.AccountStateArchived {
					return nil, invalidServiceAccountProjection("archived account in live-only page")
				}
				previous = account.ID
				items = append(items, account)
			}
			return items, nil
		},
	)
}

func (r *ServiceAccountRepository) GetAccount(
	ctx context.Context,
	params serviceaccount.GetAccountParams,
) (serviceaccount.Account, error) {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) {
		return serviceaccount.Account{}, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.Account, error) {
			return getServiceAccount(ctx, queries, params.TenantID, params.ServiceAccountID)
		},
	)
}

func (r *ServiceAccountRepository) CreateAccount(
	ctx context.Context,
	params serviceaccount.CreateAccountParams,
) (serviceaccount.Account, error) {
	if !validCreateServiceAccountParams(params) {
		return serviceaccount.Account{}, serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.Account, error) {
			result, queryErr := queries.CreateTenantServiceAccount(ctx, dbsql.CreateTenantServiceAccountParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), AccountKey: params.Key,
				DisplayName: params.DisplayName, Description: params.Description,
				RequestID: audit.requestID, CorrelationID: audit.correlationID,
				IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
				AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return serviceaccount.Account{}, mapServiceAccountDatabaseError(queryErr)
			}
			resultID, mapErr := serviceAccountMutationResult(result)
			if mapErr != nil || resultID != params.ServiceAccountID || result.ResultVersion != 1 {
				return serviceaccount.Account{}, invalidServiceAccountProjection("unexpected service-account create result")
			}
			account, mapErr := getServiceAccount(ctx, queries, params.TenantID, resultID)
			if mapErr != nil {
				return serviceaccount.Account{}, mapErr
			}
			if account.Version != int64(result.ResultVersion) || account.State != serviceaccount.AccountStateActive ||
				account.CreatedByMembershipID != params.MembershipID || account.Key != params.Key ||
				account.DisplayName != params.DisplayName || account.Description != params.Description ||
				!account.UpdatedAt.Equal(account.CreatedAt) {
				return serviceaccount.Account{}, invalidServiceAccountProjection("service-account create representation mismatch")
			}
			return account, nil
		},
	)
}

func (r *ServiceAccountRepository) UpdateAccount(
	ctx context.Context,
	params serviceaccount.UpdateAccountParams,
) (serviceaccount.Account, error) {
	version, err := serviceAccountDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validUpdateServiceAccountParams(params) {
		return serviceaccount.Account{}, serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.Account, error) {
			updatedVersion, queryErr := queries.UpdateTenantServiceAccount(ctx, dbsql.UpdateTenantServiceAccountParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), ExpectedVersion: version,
				DisplayName: cloneString(params.DisplayName), Description: cloneString(params.Description),
				RequestID: audit.requestID, CorrelationID: audit.correlationID,
				IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
				AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return serviceaccount.Account{}, mapServiceAccountDatabaseError(queryErr)
			}
			if int64(updatedVersion) != int64(version)+1 {
				return serviceaccount.Account{}, invalidServiceAccountProjection("unexpected service-account update version")
			}
			account, mapErr := getServiceAccount(ctx, queries, params.TenantID, params.ServiceAccountID)
			if mapErr != nil {
				return serviceaccount.Account{}, mapErr
			}
			if account.Version != int64(updatedVersion) || account.State != serviceaccount.AccountStateActive ||
				params.DisplayName != nil && account.DisplayName != *params.DisplayName ||
				params.Description != nil && account.Description != *params.Description {
				return serviceaccount.Account{}, invalidServiceAccountProjection("service-account update representation mismatch")
			}
			return account, nil
		},
	)
}

func (r *ServiceAccountRepository) ArchiveAccount(
	ctx context.Context,
	params serviceaccount.ArchiveAccountParams,
) error {
	version, err := serviceAccountDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validArchiveServiceAccountParams(params) {
		return serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return err
	}
	_, err = withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.ArchiveTenantServiceAccount(ctx, dbsql.ArchiveTenantServiceAccountParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), ExpectedVersion: version,
				Reason: params.Reason, RequestID: audit.requestID, CorrelationID: audit.correlationID,
				IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
				AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return struct{}{}, mapServiceAccountDatabaseError(queryErr)
			}
			if int64(updatedVersion) != int64(version)+1 {
				return struct{}{}, invalidServiceAccountProjection("unexpected service-account archive version")
			}
			account, mapErr := getServiceAccount(ctx, queries, params.TenantID, params.ServiceAccountID)
			if mapErr != nil {
				return struct{}{}, mapErr
			}
			if account.Version != int64(updatedVersion) || account.State != serviceaccount.AccountStateArchived ||
				account.ArchivedByMembershipID == nil || *account.ArchivedByMembershipID != params.MembershipID ||
				account.ArchiveReason == nil || *account.ArchiveReason != params.Reason {
				return struct{}{}, invalidServiceAccountProjection("service-account archive representation mismatch")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *ServiceAccountRepository) ListRoleGrants(
	ctx context.Context,
	params serviceaccount.ListRoleGrantsParams,
) ([]serviceaccount.RoleGrant, error) {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		!validServiceAccountPage(params.After, params.Limit) {
		return nil, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) ([]serviceaccount.RoleGrant, error) {
			rows, err := queries.ListTenantServiceAccountRoleGrants(ctx, dbsql.ListTenantServiceAccountRoleGrantsParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), AfterID: optionalDatabaseUUID(params.After),
				IncludeRevoked: params.IncludeRevoked, PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapServiceAccountDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidServiceAccountProjection("oversized service-account role-grant page")
			}
			items := make([]serviceaccount.RoleGrant, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				grant, mapErr := mapListedServiceAccountRoleGrant(params.TenantID, params.ServiceAccountID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				if previous != uuid.Nil && compareUUID(grant.ID, previous) <= 0 {
					return nil, invalidServiceAccountProjection("non-monotonic service-account role-grant page")
				}
				if !params.IncludeRevoked && grant.State == serviceaccount.RoleGrantStateRevoked {
					return nil, invalidServiceAccountProjection("revoked grant in live-only page")
				}
				previous = grant.ID
				items = append(items, grant)
			}
			return items, nil
		},
	)
}

func (r *ServiceAccountRepository) GetRoleGrant(
	ctx context.Context,
	params serviceaccount.GetRoleGrantParams,
) (serviceaccount.RoleGrant, error) {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		!serviceAccountUUIDv7(params.GrantID) {
		return serviceaccount.RoleGrant{}, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.RoleGrant, error) {
			return getServiceAccountRoleGrant(ctx, queries, params.TenantID, params.ServiceAccountID, params.GrantID)
		},
	)
}

func (r *ServiceAccountRepository) GrantRole(
	ctx context.Context,
	params serviceaccount.GrantRoleParams,
) (serviceaccount.RoleGrant, error) {
	if !validGrantServiceAccountRoleParams(params) {
		return serviceaccount.RoleGrant{}, serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.RoleGrant, error) {
			result, queryErr := queries.GrantTenantServiceAccountRole(ctx, dbsql.GrantTenantServiceAccountRoleParams{
				GrantID: toDatabaseUUID(params.GrantID), ServiceAccountID: toDatabaseUUID(params.ServiceAccountID),
				RoleID: toDatabaseUUID(params.RoleID), Reason: params.Reason,
				ExpiresAt: databaseOptionalTime(params.ExpiresAt), RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return serviceaccount.RoleGrant{}, mapServiceAccountDatabaseError(queryErr)
			}
			resultID, mapErr := serviceAccountRoleGrantMutationResult(result)
			if mapErr != nil || resultID != params.GrantID || result.ResultVersion != 1 {
				return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("unexpected service-account role-grant result")
			}
			grant, mapErr := getServiceAccountRoleGrant(ctx, queries, params.TenantID, params.ServiceAccountID, resultID)
			if mapErr != nil {
				return serviceaccount.RoleGrant{}, mapErr
			}
			if grant.Version != int64(result.ResultVersion) || grant.Role.ID != params.RoleID ||
				grant.GrantedByMembershipID != params.MembershipID || grant.GrantedByUserID != params.Actor.UserID ||
				grant.GrantReason != params.Reason ||
				!sameServiceAccountTime(grant.ExpiresAt, params.ExpiresAt) ||
				grant.State != serviceaccount.RoleGrantStateActive || !grant.ManagedByServiceAccountAPI ||
				!grant.UpdatedAt.Equal(grant.GrantedAt) {
				return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("service-account role-grant representation mismatch")
			}
			return grant, nil
		},
	)
}

func (r *ServiceAccountRepository) RevokeRoleGrant(
	ctx context.Context,
	params serviceaccount.RevokeRoleGrantParams,
) error {
	parsedVersion, err := authorization.ParseEdgeEntityTag(params.ExpectedEntityTag)
	if err != nil || !validRevokeServiceAccountRoleGrantParams(params) {
		return serviceaccount.ErrInvalidInput
	}
	version, err := serviceAccountDatabaseVersion(parsedVersion)
	if err != nil {
		return serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return err
	}
	_, err = withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.Serializable,
		func(queries serviceAccountQueries) (struct{}, error) {
			current, getErr := getServiceAccountRoleGrant(
				ctx, queries, params.TenantID, params.ServiceAccountID, params.GrantID,
			)
			if getErr != nil {
				return struct{}{}, getErr
			}
			currentEntityTag, tagErr := serviceaccount.RoleGrantEntityTag(current)
			if tagErr != nil {
				return struct{}{}, invalidServiceAccountProjection("cannot derive current role-grant validator")
			}
			if currentEntityTag != params.ExpectedEntityTag || current.Version != parsedVersion {
				return struct{}{}, serviceaccount.ErrPreconditionFailed
			}
			if current.State != serviceaccount.RoleGrantStateActive || !current.ManagedByServiceAccountAPI {
				return struct{}{}, serviceaccount.ErrConflict
			}
			updatedVersion, queryErr := queries.RevokeTenantServiceAccountRoleGrant(
				ctx,
				dbsql.RevokeTenantServiceAccountRoleGrantParams{
					ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), GrantID: toDatabaseUUID(params.GrantID),
					ExpectedVersion: version, Reason: params.Reason, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapServiceAccountDatabaseError(queryErr)
			}
			if int64(updatedVersion) != int64(version)+1 {
				return struct{}{}, invalidServiceAccountProjection("unexpected service-account role-grant revoke version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *ServiceAccountRepository) ListCredentials(
	ctx context.Context,
	params serviceaccount.ListCredentialsParams,
) ([]serviceaccount.CredentialMetadata, error) {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		!validServiceAccountPage(params.After, params.Limit) {
		return nil, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) ([]serviceaccount.CredentialMetadata, error) {
			rows, err := queries.ListTenantAPICredentials(ctx, dbsql.ListTenantAPICredentialsParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), AfterID: optionalDatabaseUUID(params.After),
				IncludeRevoked: params.IncludeRevoked, PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapServiceAccountDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidServiceAccountProjection("oversized API credential page")
			}
			items := make([]serviceaccount.CredentialMetadata, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				credential, mapErr := mapListedServiceAccountCredential(params.TenantID, params.ServiceAccountID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				if previous != uuid.Nil && compareUUID(credential.ID, previous) <= 0 {
					return nil, invalidServiceAccountProjection("non-monotonic API credential page")
				}
				if !params.IncludeRevoked && credential.State == serviceaccount.CredentialStateRevoked {
					return nil, invalidServiceAccountProjection("revoked API credential in live-only page")
				}
				previous = credential.ID
				items = append(items, credential)
			}
			return items, nil
		},
	)
}

func (r *ServiceAccountRepository) GetCredential(
	ctx context.Context,
	params serviceaccount.GetCredentialParams,
) (serviceaccount.CredentialMetadata, error) {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		!serviceAccountUUIDv7(params.CredentialID) {
		return serviceaccount.CredentialMetadata{}, serviceaccount.ErrInvalidInput
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.CredentialMetadata, error) {
			return getServiceAccountCredential(ctx, queries, params.TenantID, params.ServiceAccountID, params.CredentialID)
		},
	)
}

func (r *ServiceAccountRepository) IssueCredential(
	ctx context.Context,
	params serviceaccount.IssueCredentialParams,
) (serviceaccount.CredentialMutationResult, error) {
	defer clear(params.Write.Material.Digest[:])
	write, err := databaseServiceAccountCredentialWrite(&params.Write)
	if err != nil {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	defer clear(write.secretDigest)
	if !validServiceAccountCredentialMutationHuman(params.HumanParams, params.Audit, params.OccurredAt, params.ServiceAccountID) {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	if !validServiceAccountCredentialExpiry(params.OccurredAt, params.Write.ExpiresAt) {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return serviceaccount.CredentialMutationResult{}, err
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.CredentialMutationResult, error) {
			result, queryErr := queries.IssueTenantAPICredential(ctx, dbsql.IssueTenantAPICredentialParams{
				CredentialID: toDatabaseUUID(params.Write.CredentialID), ServiceAccountID: toDatabaseUUID(params.ServiceAccountID),
				KeyDigest: write.keyDigest, RequestDigest: write.requestDigest, Label: params.Write.Label,
				FormatVersion: int32(params.Write.FormatVersion), Locator: write.locator,
				KeyVersion: int32(params.Write.Material.KeyVersion), SecretDigest: write.secretDigest,
				ExpiresAt: databaseTime(params.Write.ExpiresAt), PermissionKeys: write.permissionKeys,
				PermissionScopes: write.permissionScopes, Networks: write.networks,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return serviceaccount.CredentialMutationResult{}, mapServiceAccountDatabaseError(queryErr)
			}
			resultID, resultVersion, replayed, mapErr := serviceAccountCredentialMutationResult(result)
			if mapErr != nil || !replayed && resultID != params.Write.CredentialID {
				return serviceaccount.CredentialMutationResult{}, invalidServiceAccountProjection("unexpected API credential issue result")
			}
			credential, mapErr := getServiceAccountCredential(ctx, queries, params.TenantID, params.ServiceAccountID, resultID)
			if mapErr != nil {
				return serviceaccount.CredentialMutationResult{}, mapErr
			}
			if !replayed && (credential.Version != int64(resultVersion) || resultVersion != 1 ||
				credential.ID != params.Write.CredentialID || credential.IssuedByMembershipID != params.MembershipID ||
				credential.LastUsedAt != nil || credential.LastUsedIP != nil ||
				!credential.UpdatedAt.Equal(credential.IssuedAt)) {
				return serviceaccount.CredentialMutationResult{}, invalidServiceAccountProjection("API credential issue representation mismatch")
			}
			return serviceaccount.CredentialMutationResult{Credential: credential, Replayed: replayed}, nil
		},
	)
}

func (r *ServiceAccountRepository) RotateCredential(
	ctx context.Context,
	params serviceaccount.RotateCredentialParams,
) (serviceaccount.CredentialMutationResult, error) {
	defer clear(params.Write.Material.Digest[:])
	version, err := serviceAccountDatabaseVersion(params.ExpectedVersion)
	if err != nil || !serviceAccountUUIDv7(params.PreviousCredentialID) ||
		!serviceAccountText(params.Reason, 1, 500) {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	write, err := databaseServiceAccountCredentialWrite(&params.Write)
	if err != nil {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	defer clear(write.secretDigest)
	if params.Write.CredentialID == params.PreviousCredentialID ||
		!validServiceAccountCredentialMutationHuman(params.HumanParams, params.Audit, params.OccurredAt, params.ServiceAccountID) {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	if !validServiceAccountCredentialExpiry(params.OccurredAt, params.Write.ExpiresAt) {
		return serviceaccount.CredentialMutationResult{}, serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return serviceaccount.CredentialMutationResult{}, err
	}
	return withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (serviceaccount.CredentialMutationResult, error) {
			result, queryErr := queries.RotateTenantAPICredential(ctx, dbsql.RotateTenantAPICredentialParams{
				ReplacementCredentialID: toDatabaseUUID(params.Write.CredentialID),
				ServiceAccountID:        toDatabaseUUID(params.ServiceAccountID),
				RotatedFromCredentialID: toDatabaseUUID(params.PreviousCredentialID), ExpectedVersion: version,
				KeyDigest: write.keyDigest, RequestDigest: write.requestDigest, Label: params.Write.Label,
				FormatVersion: int32(params.Write.FormatVersion), Locator: write.locator,
				KeyVersion: int32(params.Write.Material.KeyVersion), SecretDigest: write.secretDigest,
				ExpiresAt: databaseTime(params.Write.ExpiresAt), PermissionKeys: write.permissionKeys,
				PermissionScopes: write.permissionScopes, Networks: write.networks, RotationReason: params.Reason,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return serviceaccount.CredentialMutationResult{}, mapServiceAccountDatabaseError(queryErr)
			}
			resultID, resultVersion, replayed, mapErr := serviceAccountRotationResult(result)
			if mapErr != nil || !replayed && resultID != params.Write.CredentialID {
				return serviceaccount.CredentialMutationResult{}, invalidServiceAccountProjection("unexpected API credential rotation result")
			}
			credential, mapErr := getServiceAccountCredential(ctx, queries, params.TenantID, params.ServiceAccountID, resultID)
			if mapErr != nil {
				return serviceaccount.CredentialMutationResult{}, mapErr
			}
			if !replayed && (credential.Version != int64(resultVersion) || resultVersion != 1 ||
				credential.ID != params.Write.CredentialID || credential.RotatedFromCredentialID == nil ||
				*credential.RotatedFromCredentialID != params.PreviousCredentialID ||
				credential.IssuedByMembershipID != params.MembershipID || credential.LastUsedAt != nil ||
				credential.LastUsedIP != nil || !credential.UpdatedAt.Equal(credential.IssuedAt)) {
				return serviceaccount.CredentialMutationResult{}, invalidServiceAccountProjection("API credential rotation representation mismatch")
			}
			return serviceaccount.CredentialMutationResult{Credential: credential, Replayed: replayed}, nil
		},
	)
}

func (r *ServiceAccountRepository) RevokeCredential(
	ctx context.Context,
	params serviceaccount.RevokeCredentialParams,
) error {
	version, err := serviceAccountDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validServiceAccountCredentialMutationHuman(params.HumanParams, params.Audit, params.OccurredAt, params.ServiceAccountID) ||
		!serviceAccountUUIDv7(params.CredentialID) || !serviceAccountText(params.Reason, 1, 500) {
		return serviceaccount.ErrInvalidInput
	}
	audit, err := serviceAccountAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return err
	}
	_, err = withServiceAccountHumanTransaction(ctx, r, params.HumanParams, pgx.ReadCommitted,
		func(queries serviceAccountQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.RevokeTenantAPICredential(ctx, dbsql.RevokeTenantAPICredentialParams{
				ServiceAccountID: toDatabaseUUID(params.ServiceAccountID), CredentialID: toDatabaseUUID(params.CredentialID),
				ExpectedVersion: version, Reason: params.Reason, RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return struct{}{}, mapServiceAccountDatabaseError(queryErr)
			}
			if int64(updatedVersion) != int64(version)+1 {
				return struct{}{}, invalidServiceAccountProjection("unexpected API credential revoke version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func getServiceAccount(
	ctx context.Context,
	queries serviceAccountQueries,
	tenantID, serviceAccountID uuid.UUID,
) (serviceaccount.Account, error) {
	row, err := queries.GetTenantServiceAccount(ctx, dbsql.GetTenantServiceAccountParams{
		ServiceAccountID: toDatabaseUUID(serviceAccountID),
	})
	if err != nil {
		return serviceaccount.Account{}, mapServiceAccountDatabaseError(err)
	}
	account, err := mapGotServiceAccount(tenantID, row)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	if account.ID != serviceAccountID {
		return serviceaccount.Account{}, invalidServiceAccountProjection("unexpected service-account identifier")
	}
	return account, nil
}

func getServiceAccountRoleGrant(
	ctx context.Context,
	queries serviceAccountQueries,
	tenantID, serviceAccountID, grantID uuid.UUID,
) (serviceaccount.RoleGrant, error) {
	row, err := queries.GetTenantServiceAccountRoleGrant(ctx, dbsql.GetTenantServiceAccountRoleGrantParams{
		ServiceAccountID: toDatabaseUUID(serviceAccountID), GrantID: toDatabaseUUID(grantID),
	})
	if err != nil {
		return serviceaccount.RoleGrant{}, mapServiceAccountDatabaseError(err)
	}
	grant, err := mapGotServiceAccountRoleGrant(tenantID, serviceAccountID, row)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	if grant.ID != grantID {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("unexpected service-account role-grant identifier")
	}
	return grant, nil
}

func getServiceAccountCredential(
	ctx context.Context,
	queries serviceAccountQueries,
	tenantID, serviceAccountID, credentialID uuid.UUID,
) (serviceaccount.CredentialMetadata, error) {
	row, err := queries.GetTenantAPICredential(ctx, dbsql.GetTenantAPICredentialParams{
		ServiceAccountID: toDatabaseUUID(serviceAccountID), CredentialID: toDatabaseUUID(credentialID),
	})
	if err != nil {
		return serviceaccount.CredentialMetadata{}, mapServiceAccountDatabaseError(err)
	}
	credential, err := mapGotServiceAccountCredential(tenantID, serviceAccountID, row)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	if credential.ID != credentialID {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("unexpected API credential identifier")
	}
	return credential, nil
}

func withServiceAccountHumanTransaction[T any](
	ctx context.Context,
	repository *ServiceAccountRepository,
	human serviceaccount.HumanParams,
	isolation pgx.TxIsoLevel,
	work func(serviceAccountQueries) (T, error),
) (T, error) {
	var zero T
	if !validServiceAccountHuman(human) {
		return zero, serviceaccount.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: service-account repository dependencies are required", serviceaccount.ErrUnavailable)
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: isolation},
		func(tx databaseTransaction) (T, error) {
			queries := repository.queryFactory(tx)
			if queries == nil {
				return zero, fmt.Errorf("%w: service-account query surface is required", serviceaccount.ErrUnavailable)
			}
			installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID),
			})
			if installErr != nil {
				return zero, mapServiceAccountDatabaseError(installErr)
			}
			if installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
				return zero, invalidServiceAccountProjection("database installed an unexpected human context")
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapServiceAccountDatabaseError(err)
	}
	return result, nil
}

type serviceAccountAuditArguments struct {
	requestID            pgtype.UUID
	correlationID        pgtype.UUID
	remoteAddress        netip.Addr
	userAgent            string
	authenticationMethod string
}

func serviceAccountAuditArgumentsFor(
	audit authorization.AuditContext,
	occurredAt time.Time,
	authenticationMethod string,
) (serviceAccountAuditArguments, error) {
	if !validServiceAccountAudit(audit) || !validServiceAccountOccurrence(occurredAt) ||
		!serviceAccountText(authenticationMethod, 1, 64) {
		return serviceAccountAuditArguments{}, serviceaccount.ErrInvalidInput
	}
	remoteAddress := audit.RemoteAddress
	if remoteAddress.IsValid() {
		remoteAddress = remoteAddress.Unmap()
	}
	return serviceAccountAuditArguments{
		requestID: toDatabaseUUID(audit.RequestID), correlationID: toDatabaseUUID(audit.CorrelationID),
		remoteAddress: remoteAddress, userAgent: audit.UserAgent,
		authenticationMethod: authenticationMethod,
	}, nil
}

func validServiceAccountHuman(params serviceaccount.HumanParams) bool {
	return serviceAccountUUIDv7(params.TenantID) && serviceAccountUUIDv7(params.MembershipID) &&
		serviceAccountUUIDv7(params.Actor.UserID) && serviceAccountUUIDv7(params.Actor.SessionID) &&
		params.Actor.ActiveTenantID == params.TenantID &&
		serviceAccountText(params.Actor.AuthenticationMethod, 1, 64)
}

func validServiceAccountPage(after *uuid.UUID, limit int32) bool {
	return limit >= 1 && limit <= serviceAccountPageLimit &&
		(after == nil || serviceAccountUUIDv7(*after))
}

func validCreateServiceAccountParams(params serviceaccount.CreateAccountParams) bool {
	return validServiceAccountHuman(params.HumanParams) && serviceAccountUUIDv7(params.ServiceAccountID) &&
		serviceAccountKeyPattern.MatchString(params.Key) &&
		params.DisplayName == strings.TrimSpace(params.DisplayName) &&
		params.Description == strings.TrimSpace(params.Description) &&
		serviceAccountText(params.DisplayName, 1, 120) && serviceAccountText(params.Description, 0, 500) &&
		validServiceAccountAudit(params.Audit) && validServiceAccountOccurrence(params.OccurredAt)
}

func validUpdateServiceAccountParams(params serviceaccount.UpdateAccountParams) bool {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		params.DisplayName == nil && params.Description == nil || !validServiceAccountAudit(params.Audit) ||
		!validServiceAccountOccurrence(params.OccurredAt) {
		return false
	}
	return (params.DisplayName == nil || *params.DisplayName == strings.TrimSpace(*params.DisplayName) &&
		serviceAccountText(*params.DisplayName, 1, 120)) &&
		(params.Description == nil || *params.Description == strings.TrimSpace(*params.Description) &&
			serviceAccountText(*params.Description, 0, 500))
}

func validArchiveServiceAccountParams(params serviceaccount.ArchiveAccountParams) bool {
	return validServiceAccountHuman(params.HumanParams) && serviceAccountUUIDv7(params.ServiceAccountID) &&
		params.Reason == strings.TrimSpace(params.Reason) && serviceAccountText(params.Reason, 1, 500) &&
		validServiceAccountAudit(params.Audit) && validServiceAccountOccurrence(params.OccurredAt)
}

func validGrantServiceAccountRoleParams(params serviceaccount.GrantRoleParams) bool {
	if !validServiceAccountHuman(params.HumanParams) || !serviceAccountUUIDv7(params.ServiceAccountID) ||
		!serviceAccountUUIDv7(params.GrantID) || !serviceAccountUUIDv7(params.RoleID) ||
		params.Reason != strings.TrimSpace(params.Reason) || !serviceAccountText(params.Reason, 1, 500) ||
		!validServiceAccountAudit(params.Audit) || !validServiceAccountOccurrence(params.OccurredAt) {
		return false
	}
	return params.ExpiresAt == nil || validServiceAccountInstant(*params.ExpiresAt) && params.ExpiresAt.After(params.OccurredAt)
}

func validRevokeServiceAccountRoleGrantParams(params serviceaccount.RevokeRoleGrantParams) bool {
	return validServiceAccountHuman(params.HumanParams) && serviceAccountUUIDv7(params.ServiceAccountID) &&
		serviceAccountUUIDv7(params.GrantID) && params.ExpectedEntityTag != "" &&
		params.Reason == strings.TrimSpace(params.Reason) && serviceAccountText(params.Reason, 1, 500) &&
		validServiceAccountAudit(params.Audit) && validServiceAccountOccurrence(params.OccurredAt)
}

func validServiceAccountCredentialMutationHuman(
	human serviceaccount.HumanParams,
	audit authorization.AuditContext,
	occurredAt time.Time,
	serviceAccountID uuid.UUID,
) bool {
	return validServiceAccountHuman(human) && serviceAccountUUIDv7(serviceAccountID) &&
		validServiceAccountAudit(audit) && validServiceAccountOccurrence(occurredAt)
}

func validServiceAccountCredentialExpiry(issuedAt, expiresAt time.Time) bool {
	return expiresAt.After(issuedAt) && !expiresAt.After(issuedAt.Add(maximumCredentialAge))
}

func validServiceAccountAudit(audit authorization.AuditContext) bool {
	if audit.RequestID != uuid.Nil && audit.RequestID.Variant() != uuid.RFC4122 ||
		audit.CorrelationID != uuid.Nil && audit.CorrelationID.Variant() != uuid.RFC4122 ||
		audit.RemoteAddress.IsValid() && (audit.RemoteAddress.Zone() != "" || audit.RemoteAddress.Is4In6()) {
		return false
	}
	return serviceAccountText(audit.UserAgent, 0, 1024)
}

func validServiceAccountOccurrence(value time.Time) bool {
	return validServiceAccountInstant(value)
}

func validServiceAccountInstant(value time.Time) bool {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.UTC().MarshalJSON()
	return err == nil
}

func serviceAccountDatabaseVersion(value int64) (int32, error) {
	if value < 1 || value > math.MaxInt32 {
		return 0, serviceaccount.ErrInvalidInput
	}
	return int32(value), nil
}

func databaseOptionalTime(value *time.Time) pgtype.Timestamptz {
	if value == nil {
		return pgtype.Timestamptz{}
	}
	return databaseTime(*value)
}

func sameServiceAccountTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

type databaseCredentialWrite struct {
	locator          []byte
	secretDigest     []byte
	keyDigest        []byte
	requestDigest    []byte
	permissionKeys   []string
	permissionScopes []string
	networks         []netip.Prefix
}

func databaseServiceAccountCredentialWrite(write *serviceaccount.CredentialWrite) (databaseCredentialWrite, error) {
	if write == nil {
		return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
	}
	if !serviceAccountUUIDv7(write.CredentialID) || write.Label != strings.TrimSpace(write.Label) ||
		!serviceAccountText(write.Label, 1, 120) || write.FormatVersion != 1 ||
		write.Material.KeyVersion < 1 || !validServiceAccountInstant(write.ExpiresAt) ||
		len(write.Permissions) == 0 || len(write.Permissions) > 100 || len(write.Networks) > 32 {
		return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
	}
	permissionKeys := make([]string, len(write.Permissions))
	permissionScopes := make([]string, len(write.Permissions))
	var previousPermission string
	for index, permission := range write.Permissions {
		if permission.Permission != authorization.TenantPermissionAlertCreate || permission.Scope != authorization.ScopeTenant {
			return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
		}
		identity := string(permission.Permission) + "\x00" + string(permission.Scope)
		if index > 0 && strings.Compare(previousPermission, identity) >= 0 {
			return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
		}
		previousPermission = identity
		permissionKeys[index] = string(permission.Permission)
		permissionScopes[index] = string(permission.Scope)
	}
	networks := make([]netip.Prefix, len(write.Networks))
	for index, network := range write.Networks {
		if !network.IsValid() || network.Addr().Is4In6() || network != network.Masked() {
			return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
		}
		if index > 0 && serviceaccount.CompareCredentialNetworks(write.Networks[index-1], network) >= 0 {
			return databaseCredentialWrite{}, serviceaccount.ErrInvalidInput
		}
		networks[index] = network
	}
	return databaseCredentialWrite{
		locator:        append([]byte(nil), write.Material.Locator[:]...),
		secretDigest:   write.Material.Digest[:],
		keyDigest:      append([]byte(nil), write.KeyDigest[:]...),
		requestDigest:  append([]byte(nil), write.RequestDigest[:]...),
		permissionKeys: permissionKeys, permissionScopes: permissionScopes, networks: networks,
	}, nil
}

func serviceAccountMutationResult(row *dbsql.CreateTenantServiceAccountRow) (uuid.UUID, error) {
	if row == nil || row.ResultVersion < 1 {
		return uuid.Nil, invalidServiceAccountProjection("invalid service-account mutation result")
	}
	return serviceAccountDatabaseUUID(row.ResultResourceID)
}

func serviceAccountRoleGrantMutationResult(row *dbsql.GrantTenantServiceAccountRoleRow) (uuid.UUID, error) {
	if row == nil || row.ResultVersion < 1 {
		return uuid.Nil, invalidServiceAccountProjection("invalid service-account role-grant mutation result")
	}
	return serviceAccountDatabaseUUID(row.ResultResourceID)
}

func serviceAccountCredentialMutationResult(
	row *dbsql.IssueTenantAPICredentialRow,
) (uuid.UUID, int32, bool, error) {
	if row == nil || row.ResultVersion < 1 {
		return uuid.Nil, 0, false, invalidServiceAccountProjection("invalid API credential issue result")
	}
	identifier, err := serviceAccountDatabaseUUID(row.ResultCredentialID)
	return identifier, row.ResultVersion, row.Replayed, err
}

func serviceAccountRotationResult(
	row *dbsql.RotateTenantAPICredentialRow,
) (uuid.UUID, int32, bool, error) {
	if row == nil || row.ResultVersion < 1 {
		return uuid.Nil, 0, false, invalidServiceAccountProjection("invalid API credential rotation result")
	}
	identifier, err := serviceAccountDatabaseUUID(row.ResultCredentialID)
	return identifier, row.ResultVersion, row.Replayed, err
}

func mapServiceAccountDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, serviceaccount.ErrInvalidInput) || errors.Is(err, serviceaccount.ErrForbidden) ||
		errors.Is(err, serviceaccount.ErrNotFound) || errors.Is(err, serviceaccount.ErrConflict) ||
		errors.Is(err, serviceaccount.ErrPreconditionRequired) ||
		errors.Is(err, serviceaccount.ErrPreconditionFailed) || errors.Is(err, serviceaccount.ErrUnavailable) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return serviceaccount.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02":
		return serviceaccount.ErrInvalidInput
	case "42501":
		return serviceaccount.ErrForbidden
	case "P0002":
		return serviceaccount.ErrNotFound
	case "40001":
		if isServiceAccountVersionConflict(err) {
			return serviceaccount.ErrPreconditionFailed
		}
		return serviceaccount.ErrUnavailable
	case "23503", "23505", "23514", "55000":
		return serviceaccount.ErrConflict
	default:
		return err
	}
}

func isServiceAccountVersionConflict(err error) bool {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		return false
	}
	switch databaseError.Message {
	case serviceAccountVersionConflictMessage,
		serviceAccountRoleGrantVersionConflictMessage,
		serviceAccountCredentialVersionConflictMessage:
		return true
	default:
		return false
	}
}

func mapListedServiceAccount(
	tenantID uuid.UUID,
	row *dbsql.ListTenantServiceAccountsRow,
) (serviceaccount.Account, error) {
	if row == nil {
		return serviceaccount.Account{}, invalidServiceAccountProjection("null service account")
	}
	return mapServiceAccount(tenantID, serviceAccountRecord{
		id: row.ServiceAccountID, key: row.AccountKey, displayName: row.DisplayName,
		description: row.Description, createdByMembershipID: row.CreatedByMembershipID,
		createdByUserID: row.CreatedByUserID, archivedAt: row.ArchivedAt,
		archivedByMembershipID: row.ArchivedByMembershipID, archivedByUserID: row.ArchivedByUserID,
		archiveReason: row.ArchiveReason, version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapGotServiceAccount(
	tenantID uuid.UUID,
	row *dbsql.GetTenantServiceAccountRow,
) (serviceaccount.Account, error) {
	if row == nil {
		return serviceaccount.Account{}, invalidServiceAccountProjection("null service account")
	}
	return mapServiceAccount(tenantID, serviceAccountRecord{
		id: row.ServiceAccountID, key: row.AccountKey, displayName: row.DisplayName,
		description: row.Description, createdByMembershipID: row.CreatedByMembershipID,
		createdByUserID: row.CreatedByUserID, archivedAt: row.ArchivedAt,
		archivedByMembershipID: row.ArchivedByMembershipID, archivedByUserID: row.ArchivedByUserID,
		archiveReason: row.ArchiveReason, version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapListedServiceAccountRoleGrant(
	tenantID, serviceAccountID uuid.UUID,
	row *dbsql.ListTenantServiceAccountRoleGrantsRow,
) (serviceaccount.RoleGrant, error) {
	if row == nil {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("null service-account role grant")
	}
	return mapServiceAccountRoleGrant(tenantID, serviceAccountID, serviceAccountRoleGrantRecord{
		id: row.GrantID, serviceAccountID: row.ServiceAccountID, roleID: row.RoleID,
		roleKey: row.RoleKey, roleDisplayName: row.RoleDisplayName, roleSystem: row.RoleSystem,
		sourceID: row.SourceID, sourceKind: row.SourceKind, sourceKey: row.SourceKey,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		grantedByMembershipID: row.GrantedByMembershipID, grantedByUserID: row.GrantedByUserID,
		grantReason: row.GrantReason, grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt,
		revokedAt: row.RevokedAt, revokedByMembershipID: row.RevokedByMembershipID,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
	})
}

func mapGotServiceAccountRoleGrant(
	tenantID, serviceAccountID uuid.UUID,
	row *dbsql.GetTenantServiceAccountRoleGrantRow,
) (serviceaccount.RoleGrant, error) {
	if row == nil {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("null service-account role grant")
	}
	return mapServiceAccountRoleGrant(tenantID, serviceAccountID, serviceAccountRoleGrantRecord{
		id: row.GrantID, serviceAccountID: row.ServiceAccountID, roleID: row.RoleID,
		roleKey: row.RoleKey, roleDisplayName: row.RoleDisplayName, roleSystem: row.RoleSystem,
		sourceID: row.SourceID, sourceKind: row.SourceKind, sourceKey: row.SourceKey,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		grantedByMembershipID: row.GrantedByMembershipID, grantedByUserID: row.GrantedByUserID,
		grantReason: row.GrantReason, grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt,
		revokedAt: row.RevokedAt, revokedByMembershipID: row.RevokedByMembershipID,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
	})
}

func mapListedServiceAccountCredential(
	tenantID, serviceAccountID uuid.UUID,
	row *dbsql.ListTenantAPICredentialsRow,
) (serviceaccount.CredentialMetadata, error) {
	if row == nil {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("null API credential")
	}
	return mapServiceAccountCredential(tenantID, serviceAccountID, serviceAccountCredentialRecord{
		id: row.CredentialID, serviceAccountID: row.ServiceAccountID, label: row.Label,
		formatVersion: row.FormatVersion, keyVersion: row.KeyVersion,
		issuedByMembershipID: row.IssuedByMembershipID, issuedByUserID: row.IssuedByUserID,
		issuedAt: row.IssuedAt, expiresAt: row.ExpiresAt,
		rotatedFromCredentialID: row.RotatedFromCredentialID, revokedAt: row.RevokedAt,
		revokedByMembershipID: row.RevokedByMembershipID, revokedByUserID: row.RevokedByUserID,
		revokeReason: row.RevokeReason, lastUsedAt: row.LastUsedAt, lastUsedIP: optionalNetipAddress(row.LastUsedIp),
		state: row.CredentialState, version: row.Version, updatedAt: row.UpdatedAt,
		permissionKeys: row.PermissionKeys, permissionScopes: row.PermissionScopes, networks: row.Networks,
	})
}

func mapGotServiceAccountCredential(
	tenantID, serviceAccountID uuid.UUID,
	row *dbsql.GetTenantAPICredentialRow,
) (serviceaccount.CredentialMetadata, error) {
	if row == nil {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("null API credential")
	}
	return mapServiceAccountCredential(tenantID, serviceAccountID, serviceAccountCredentialRecord{
		id: row.CredentialID, serviceAccountID: row.ServiceAccountID, label: row.Label,
		formatVersion: row.FormatVersion, keyVersion: row.KeyVersion,
		issuedByMembershipID: row.IssuedByMembershipID, issuedByUserID: row.IssuedByUserID,
		issuedAt: row.IssuedAt, expiresAt: row.ExpiresAt,
		rotatedFromCredentialID: row.RotatedFromCredentialID, revokedAt: row.RevokedAt,
		revokedByMembershipID: row.RevokedByMembershipID, revokedByUserID: row.RevokedByUserID,
		revokeReason: row.RevokeReason, lastUsedAt: row.LastUsedAt, lastUsedIP: optionalNetipAddress(row.LastUsedIp),
		state: row.CredentialState, version: row.Version, updatedAt: row.UpdatedAt,
		permissionKeys: row.PermissionKeys, permissionScopes: row.PermissionScopes, networks: row.Networks,
	})
}

func optionalNetipAddress(value netip.Addr) *netip.Addr {
	if !value.IsValid() {
		return nil
	}
	return &value
}
