package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	authorizationHydrationLimit           int32 = 101
	authorizationPermissionHydrationLimit int32 = authorization.MaximumHydratedPermissionTuples + 1
	authorizationRolePathHydrationLimit   int32 = 201
	operatorTeamHydrationLimit            int32 = 201

	authorizationRoleVersionConflictMessage                 = "tenant role version conflict"
	authorizationRoleGrantVersionConflictMessage            = "tenant role grant version conflict"
	authorizationSecurityGroupVersionConflictMessage        = "tenant security group version conflict"
	authorizationGroupMembershipVersionConflictMessage      = "tenant security group membership version conflict"
	authorizationGroupRoleGrantVersionConflictMessage       = "tenant security group role grant version conflict"
	authorizationMembershipLifecycleRevisionConflictMessage = "tenant membership lifecycle revision conflict"
)

type authorizationQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	GetCurrentTenantAuthorizationContext(context.Context) (*dbsql.GetCurrentTenantAuthorizationContextRow, error)
	ResolveCurrentTenantHumanAuthority(context.Context, dbsql.ResolveCurrentTenantHumanAuthorityParams) ([]*dbsql.ResolveCurrentTenantHumanAuthorityRow, error)
	ResolveCurrentTenantOperatorTeams(context.Context, dbsql.ResolveCurrentTenantOperatorTeamsParams) ([]*dbsql.ResolveCurrentTenantOperatorTeamsRow, error)
	ResolveCurrentTenantHumanRoleGrantPaths(context.Context, dbsql.ResolveCurrentTenantHumanRoleGrantPathsParams) ([]*dbsql.ResolveCurrentTenantHumanRoleGrantPathsRow, error)
	ListTenantPermissionCatalog(context.Context, dbsql.ListTenantPermissionCatalogParams) ([]*dbsql.ListTenantPermissionCatalogRow, error)
	ListTenantAuthorizationRoles(context.Context, dbsql.ListTenantAuthorizationRolesParams) ([]*dbsql.ListTenantAuthorizationRolesRow, error)
	GetTenantAuthorizationRole(context.Context, dbsql.GetTenantAuthorizationRoleParams) (*dbsql.GetTenantAuthorizationRoleRow, error)
	GetTenantAuthorizationRolePolicy(context.Context, dbsql.GetTenantAuthorizationRolePolicyParams) ([]*dbsql.GetTenantAuthorizationRolePolicyRow, error)
	ListTenantAuthorizationUsers(context.Context, dbsql.ListTenantAuthorizationUsersParams) ([]*dbsql.ListTenantAuthorizationUsersRow, error)
	ChangeTenantMembershipLifecycle(context.Context, dbsql.ChangeTenantMembershipLifecycleParams) (*dbsql.ChangeTenantMembershipLifecycleRow, error)
	ListTenantMembershipRoleGrants(context.Context, dbsql.ListTenantMembershipRoleGrantsParams) ([]*dbsql.ListTenantMembershipRoleGrantsRow, error)
	GetTenantMembershipRoleGrant(context.Context, dbsql.GetTenantMembershipRoleGrantParams) (*dbsql.GetTenantMembershipRoleGrantRow, error)
	CreateTenantAuthorizationRole(context.Context, dbsql.CreateTenantAuthorizationRoleParams) (*dbsql.CreateTenantAuthorizationRoleRow, error)
	UpdateTenantAuthorizationRoleMetadata(context.Context, dbsql.UpdateTenantAuthorizationRoleMetadataParams) (int32, error)
	ReplaceTenantAuthorizationRolePolicy(context.Context, dbsql.ReplaceTenantAuthorizationRolePolicyParams) (*dbsql.ReplaceTenantAuthorizationRolePolicyRow, error)
	ArchiveTenantAuthorizationRole(context.Context, dbsql.ArchiveTenantAuthorizationRoleParams) (int32, error)
	GrantTenantUserRole(context.Context, dbsql.GrantTenantUserRoleParams) (*dbsql.GrantTenantUserRoleRow, error)
	RevokeTenantUserRoleGrant(context.Context, dbsql.RevokeTenantUserRoleGrantParams) (int32, error)
	ListTenantAuthorizationSecurityGroups(context.Context, dbsql.ListTenantAuthorizationSecurityGroupsParams) ([]*dbsql.ListTenantAuthorizationSecurityGroupsRow, error)
	GetTenantAuthorizationSecurityGroup(context.Context, dbsql.GetTenantAuthorizationSecurityGroupParams) (*dbsql.GetTenantAuthorizationSecurityGroupRow, error)
	CreateTenantAuthorizationSecurityGroup(context.Context, dbsql.CreateTenantAuthorizationSecurityGroupParams) (*dbsql.CreateTenantAuthorizationSecurityGroupRow, error)
	UpdateTenantAuthorizationSecurityGroupMetadata(context.Context, dbsql.UpdateTenantAuthorizationSecurityGroupMetadataParams) (int32, error)
	ArchiveTenantAuthorizationSecurityGroup(context.Context, dbsql.ArchiveTenantAuthorizationSecurityGroupParams) (int32, error)
	ListTenantAuthorizationSecurityGroupMemberships(context.Context, dbsql.ListTenantAuthorizationSecurityGroupMembershipsParams) ([]*dbsql.ListTenantAuthorizationSecurityGroupMembershipsRow, error)
	GetTenantAuthorizationSecurityGroupMembership(context.Context, dbsql.GetTenantAuthorizationSecurityGroupMembershipParams) (*dbsql.GetTenantAuthorizationSecurityGroupMembershipRow, error)
	AddTenantAuthorizationSecurityGroupMember(context.Context, dbsql.AddTenantAuthorizationSecurityGroupMemberParams) (*dbsql.AddTenantAuthorizationSecurityGroupMemberRow, error)
	RevokeTenantAuthorizationSecurityGroupMembership(context.Context, dbsql.RevokeTenantAuthorizationSecurityGroupMembershipParams) (int32, error)
	ListTenantAuthorizationSecurityGroupRoleGrants(context.Context, dbsql.ListTenantAuthorizationSecurityGroupRoleGrantsParams) ([]*dbsql.ListTenantAuthorizationSecurityGroupRoleGrantsRow, error)
	GetTenantAuthorizationSecurityGroupRoleGrant(context.Context, dbsql.GetTenantAuthorizationSecurityGroupRoleGrantParams) (*dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow, error)
	GrantTenantAuthorizationSecurityGroupRole(context.Context, dbsql.GrantTenantAuthorizationSecurityGroupRoleParams) (*dbsql.GrantTenantAuthorizationSecurityGroupRoleRow, error)
	RevokeTenantAuthorizationSecurityGroupRoleGrant(context.Context, dbsql.RevokeTenantAuthorizationSecurityGroupRoleGrantParams) (int32, error)
}

// AuthorizationRepository implements tenant RBAC through the narrow
// SECURITY DEFINER surface. Every operation installs transaction-local tenant
// and actor context before resolving authority or touching tenant data.
type AuthorizationRepository struct {
	begin        transactionBeginner
	queryFactory func(databaseTransaction) authorizationQueries
	newID        func() (uuid.UUID, error)
}

func NewAuthorizationRepository(pool *pgxpool.Pool) *AuthorizationRepository {
	return &AuthorizationRepository{
		begin: poolTransactionBeginner(pool),
		queryFactory: func(tx databaseTransaction) authorizationQueries {
			return dbsql.New(tx)
		},
		newID: uuid.NewV7,
	}
}

func (r *AuthorizationRepository) ResolveAuthority(
	ctx context.Context,
	params authorization.ResolveAuthorityParams,
) (authorization.TenantAuthority, error) {
	return withAuthorizationReadTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantAuthority, error) {
			contextRow, err := queries.GetCurrentTenantAuthorizationContext(ctx)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return authorization.TenantAuthority{}, authorization.ErrForbidden
				}
				return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
			}
			authorityRows, err := queries.ResolveCurrentTenantHumanAuthority(
				ctx,
				dbsql.ResolveCurrentTenantHumanAuthorityParams{PageSize: authorizationPermissionHydrationLimit},
			)
			if err != nil {
				return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
			}
			operatorTeamRows, err := queries.ResolveCurrentTenantOperatorTeams(
				ctx,
				dbsql.ResolveCurrentTenantOperatorTeamsParams{PageSize: operatorTeamHydrationLimit},
			)
			if err != nil {
				return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
			}
			roleGrantRows, err := queries.ResolveCurrentTenantHumanRoleGrantPaths(
				ctx,
				dbsql.ResolveCurrentTenantHumanRoleGrantPathsParams{PageSize: authorizationRolePathHydrationLimit},
			)
			if err != nil {
				return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
			}
			return mapResolvedTenantAuthority(
				params.Actor, params.TenantID, contextRow, authorityRows, operatorTeamRows,
				roleGrantRows,
			)
		},
	)
}

func (r *AuthorizationRepository) ListTenantPermissions(
	ctx context.Context,
	params authorization.ListTenantPermissionsParams,
) ([]authorization.TenantPermissionDefinition, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil {
		return nil, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantPermissionDefinition, error) {
			rows, err := queries.ListTenantPermissionCatalog(ctx, dbsql.ListTenantPermissionCatalogParams{
				AfterID: optionalDatabaseUUID(params.After), PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantPermissionDefinition, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapTenantPermissionDefinition(row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) ListTenantRoles(
	ctx context.Context,
	params authorization.ListTenantRolesParams,
) ([]authorization.TenantRoleSummary, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil {
		return nil, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantRoleSummary, error) {
			rows, err := queries.ListTenantAuthorizationRoles(ctx, dbsql.ListTenantAuthorizationRolesParams{
				AfterID: optionalDatabaseUUID(params.After), IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantRoleSummary, 0, len(rows))
			for _, row := range rows {
				if row == nil {
					return nil, errors.New("database returned a null tenant role row")
				}
				item, mapErr := mapAuthorizationRoleSummary(
					params.TenantID, row.RoleID, row.RoleKey, row.DisplayName, row.Description,
					row.PrincipalKind, row.SystemRole, row.ProtectedRole, row.Version, row.ArchivedAt,
					row.CreatedAt, row.UpdatedAt,
				)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) CreateTenantRole(
	ctx context.Context,
	params authorization.CreateTenantRoleParams,
) (authorization.IdempotentCreateResult[authorization.TenantRole], error) {
	permissionKeys, scopes, delegationKeys, delegationScopes, err :=
		databaseAuthorizationPolicy(params.Policy)
	if err != nil || !authorizationUUIDv7(params.RoleID) || params.IdempotencyKey == "" {
		return authorization.IdempotentCreateResult[authorization.TenantRole]{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantRole]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.IdempotentCreateResult[authorization.TenantRole], error) {
			result, queryErr := queries.CreateTenantAuthorizationRole(ctx, dbsql.CreateTenantAuthorizationRoleParams{
				RoleID: toDatabaseUUID(params.RoleID), IdempotencyKeyDigest: digest[:],
				RoleKey: params.Key, RoleName: params.Name, RoleDescription: params.Description,
				PermissionKeys: permissionKeys, PermissionScopes: scopes,
				DelegationPermissionKeys: delegationKeys, DelegationScopes: delegationScopes,
				AuditID: audit.auditID, RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantRole]{}, mapAuthorizationDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return authorization.IdempotentCreateResult[authorization.TenantRole]{}, errors.New("database returned an invalid tenant role creation result")
			}
			resultID, mapErr := domainUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.RoleID {
				return authorization.IdempotentCreateResult[authorization.TenantRole]{}, errors.New("database returned an unexpected tenant role creation result")
			}
			role, mapErr := getAuthorizationRole(ctx, queries, params.TenantID, resultID)
			if mapErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantRole]{}, mapErr
			}
			if !authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, role.Version) {
				return authorization.IdempotentCreateResult[authorization.TenantRole]{}, authorization.ErrConflict
			}
			return authorization.IdempotentCreateResult[authorization.TenantRole]{
				Value: role, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *AuthorizationRepository) GetTenantRole(
	ctx context.Context,
	params authorization.GetTenantRoleParams,
) (authorization.TenantRole, error) {
	if !authorizationUUIDv7(params.RoleID) {
		return authorization.TenantRole{}, authorization.ErrInvalidInput
	}
	return withAuthorizationReadTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantRole, error) {
			return getAuthorizationRole(ctx, queries, params.TenantID, params.RoleID)
		},
	)
}

func (r *AuthorizationRepository) UpdateTenantRole(
	ctx context.Context,
	params authorization.UpdateTenantRoleParams,
) (authorization.TenantRole, error) {
	version, err := databaseAuthorizationVersion(params.ExpectedVersion)
	if err != nil || !authorizationUUIDv7(params.RoleID) || params.Name == nil && params.Description == nil {
		return authorization.TenantRole{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.TenantRole{}, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantRole, error) {
			updatedVersion, queryErr := queries.UpdateTenantAuthorizationRoleMetadata(
				ctx,
				dbsql.UpdateTenantAuthorizationRoleMetadataParams{
					RoleID: toDatabaseUUID(params.RoleID), ExpectedVersion: version,
					RoleName: params.Name, RoleDescription: params.Description,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.TenantRole{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return authorization.TenantRole{}, errors.New("database returned an unexpected tenant role version")
			}
			role, mapErr := getAuthorizationRole(ctx, queries, params.TenantID, params.RoleID)
			if mapErr != nil {
				return authorization.TenantRole{}, mapErr
			}
			if role.Version != int64(updatedVersion) {
				return authorization.TenantRole{}, errors.New("database returned inconsistent tenant role metadata")
			}
			return role, nil
		},
	)
}

func (r *AuthorizationRepository) ArchiveTenantRole(
	ctx context.Context,
	params authorization.ArchiveTenantRoleParams,
) error {
	version, err := databaseAuthorizationVersion(params.ExpectedVersion)
	if err != nil || !authorizationUUIDv7(params.RoleID) {
		return authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.ArchiveTenantAuthorizationRole(
				ctx,
				dbsql.ArchiveTenantAuthorizationRoleParams{
					RoleID: toDatabaseUUID(params.RoleID), ExpectedVersion: version,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, errors.New("database returned an unexpected archived tenant role version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *AuthorizationRepository) ReplaceTenantRolePolicy(
	ctx context.Context,
	params authorization.ReplaceTenantRolePolicyParams,
) (authorization.TenantRole, error) {
	version, err := databaseAuthorizationVersion(params.ExpectedVersion)
	if err != nil || !authorizationUUIDv7(params.RoleID) {
		return authorization.TenantRole{}, authorization.ErrInvalidInput
	}
	permissionKeys, scopes, delegationKeys, delegationScopes, err :=
		databaseAuthorizationPolicy(params.Policy)
	if err != nil {
		return authorization.TenantRole{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.TenantRole{}, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantRole, error) {
			row, queryErr := queries.ReplaceTenantAuthorizationRolePolicy(
				ctx,
				dbsql.ReplaceTenantAuthorizationRolePolicyParams{
					RoleID: toDatabaseUUID(params.RoleID), ExpectedVersion: version,
					PermissionKeys: permissionKeys, PermissionScopes: scopes,
					DelegationPermissionKeys: delegationKeys, DelegationScopes: delegationScopes,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.TenantRole{}, mapAuthorizationDatabaseError(queryErr)
			}
			if row == nil {
				return authorization.TenantRole{}, errors.New("database returned a null tenant role policy mutation result")
			}
			if row.Version != version+1 {
				return authorization.TenantRole{}, errors.New("database returned an unexpected tenant role policy version")
			}
			summary, mapErr := mapAuthorizationRoleSummary(
				params.TenantID, row.RoleID, row.RoleKey, row.DisplayName, row.Description,
				string(authorization.PrincipalKindHuman), row.SystemRole, row.ProtectedRole, row.Version, row.ArchivedAt,
				row.CreatedAt, row.UpdatedAt,
			)
			if mapErr != nil {
				return authorization.TenantRole{}, mapErr
			}
			if summary.ID != params.RoleID {
				return authorization.TenantRole{}, errors.New("database returned an unexpected tenant role policy mutation result")
			}
			policy, mapErr := mapAuthorizationRolePolicyArrays(
				row.PermissionKeys, row.PermissionScopes,
				row.DelegationPermissionKeys, row.DelegationScopes,
			)
			if mapErr != nil {
				return authorization.TenantRole{}, mapErr
			}
			return authorization.TenantRole{TenantRoleSummary: summary, Policy: policy}, nil
		},
	)
}

func (r *AuthorizationRepository) ListTenantUsers(
	ctx context.Context,
	params authorization.ListTenantUsersParams,
) ([]authorization.TenantUserSummary, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil {
		return nil, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantUserSummary, error) {
			rows, err := queries.ListTenantAuthorizationUsers(ctx, dbsql.ListTenantAuthorizationUsersParams{
				AfterMembershipID: optionalDatabaseUUID(params.After), PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantUserSummary, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapTenantAuthorizationUser(params.TenantID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) ChangeTenantMembershipLifecycle(
	ctx context.Context,
	params authorization.ChangeTenantMembershipLifecycleParams,
) (authorization.TenantMembershipLifecycleReceipt, error) {
	version, err := databaseAuthorizationVersion(params.ExpectedRevision)
	if err != nil || version >= math.MaxInt32 || !authorizationUUIDv7(params.UserID) ||
		(params.TargetStatus != authorization.MembershipStatusActive &&
			params.TargetStatus != authorization.MembershipStatusSuspended) ||
		params.Reason == "" || params.IdempotencyKey == "" {
		return authorization.TenantMembershipLifecycleReceipt{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.TenantMembershipLifecycleReceipt{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantMembershipLifecycleReceipt, error) {
			row, queryErr := queries.ChangeTenantMembershipLifecycle(
				ctx,
				dbsql.ChangeTenantMembershipLifecycleParams{
					ActorSessionID: toDatabaseUUID(params.Actor.SessionID),
					TargetUserID:   toDatabaseUUID(params.UserID),
					TargetStatus:   string(params.TargetStatus), ExpectedRevision: version,
					Reason: params.Reason, IdempotencyKeyDigest: digest[:],
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent:            audit.userAgent,
					AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.TenantMembershipLifecycleReceipt{}, mapAuthorizationDatabaseError(queryErr)
			}
			return mapTenantMembershipLifecycleReceipt(params, row)
		},
	)
}

func (r *AuthorizationRepository) ListUserRoleGrants(
	ctx context.Context,
	params authorization.ListUserRoleGrantsParams,
) ([]authorization.DirectUserRoleGrant, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil ||
		!authorizationUUIDv7(params.UserID) {
		return nil, authorization.ErrInvalidInput
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.DirectUserRoleGrant, error) {
			rows, err := queries.ListTenantMembershipRoleGrants(ctx, dbsql.ListTenantMembershipRoleGrantsParams{
				TargetUserID: toDatabaseUUID(params.UserID), AfterGrantID: optionalDatabaseUUID(params.After),
				IncludeRevoked: params.IncludeRevoked, PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.DirectUserRoleGrant, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapListedDirectAuthorizationGrant(params.TenantID, params.UserID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) GetUserRoleGrant(
	ctx context.Context,
	params authorization.GetUserRoleGrantParams,
) (authorization.DirectUserRoleGrant, error) {
	if !authorizationUUIDv7(params.GrantID) {
		return authorization.DirectUserRoleGrant{}, authorization.ErrInvalidInput
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.DirectUserRoleGrant, error) {
			return getDirectAuthorizationGrant(ctx, queries, params.TenantID, params.GrantID)
		},
	)
}

func (r *AuthorizationRepository) GrantUserRole(
	ctx context.Context,
	params authorization.GrantUserRoleParams,
) (authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant], error) {
	if !authorizationUUIDv7(params.GrantID) || !authorizationUUIDv7(params.UserID) ||
		!authorizationUUIDv7(params.RoleID) || params.IdempotencyKey == "" {
		return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, authorization.ErrInvalidInput
	}
	expiresAt, err := optionalDatabaseTime(params.ExpiresAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, err
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant], error) {
			result, queryErr := queries.GrantTenantUserRole(ctx, dbsql.GrantTenantUserRoleParams{
				GrantID: toDatabaseUUID(params.GrantID), IdempotencyKeyDigest: digest[:],
				TargetUserID: toDatabaseUUID(params.UserID), RoleID: toDatabaseUUID(params.RoleID),
				Reason: params.Reason, ExpiresAt: expiresAt,
				AuditID: audit.auditID, RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, mapAuthorizationDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, errors.New("database returned an invalid direct role-grant result")
			}
			resultID, mapErr := domainUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.GrantID {
				return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, errors.New("database returned an unexpected direct role-grant result")
			}
			grant, mapErr := getDirectAuthorizationGrant(ctx, queries, params.TenantID, resultID)
			if mapErr != nil {
				return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, mapErr
			}
			if !authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, grant.Version) {
				return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{}, authorization.ErrConflict
			}
			return authorization.IdempotentCreateResult[authorization.DirectUserRoleGrant]{
				Value: grant, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *AuthorizationRepository) RevokeRoleGrant(
	ctx context.Context,
	params authorization.RevokeRoleGrantParams,
) error {
	parsedVersion, err := authorization.ParseEdgeEntityTag(params.ExpectedEntityTag)
	if err != nil {
		return authorization.ErrInvalidInput
	}
	version, err := databaseAuthorizationVersion(parsedVersion)
	if err != nil || !authorizationUUIDv7(params.GrantID) {
		return authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withAuthorizationTransactionIsolation(
		ctx, r, params.Actor, params.TenantID, pgx.Serializable,
		func(queries authorizationQueries) (struct{}, error) {
			current, getErr := getDirectAuthorizationGrant(ctx, queries, params.TenantID, params.GrantID)
			if getErr != nil {
				return struct{}{}, getErr
			}
			currentEntityTag, tagErr := authorization.DirectUserRoleGrantEntityTag(current)
			if tagErr != nil {
				return struct{}{}, tagErr
			}
			if currentEntityTag != params.ExpectedEntityTag {
				return struct{}{}, authorization.ErrPreconditionFailed
			}
			updatedVersion, queryErr := queries.RevokeTenantUserRoleGrant(
				ctx,
				dbsql.RevokeTenantUserRoleGrantParams{
					GrantID: toDatabaseUUID(params.GrantID), ExpectedVersion: version,
					Reason: params.Reason, AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, errors.New("database returned an unexpected revoked role-grant version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *AuthorizationRepository) ListTenantSecurityGroups(
	ctx context.Context,
	params authorization.ListTenantSecurityGroupsParams,
) ([]authorization.TenantSecurityGroup, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil {
		return nil, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantSecurityGroup, error) {
			rows, err := queries.ListTenantAuthorizationSecurityGroups(
				ctx,
				dbsql.ListTenantAuthorizationSecurityGroupsParams{
					AfterGroupID:    optionalDatabaseUUID(params.After),
					IncludeArchived: params.IncludeArchived, PageSize: params.Limit,
				},
			)
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantSecurityGroup, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapListedAuthorizationSecurityGroup(params.TenantID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) CreateTenantSecurityGroup(
	ctx context.Context,
	params authorization.CreateTenantSecurityGroupParams,
) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroup], error) {
	if !authorizationUUIDv7(params.GroupID) || params.IdempotencyKey == "" {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroup], error) {
			result, queryErr := queries.CreateTenantAuthorizationSecurityGroup(
				ctx,
				dbsql.CreateTenantAuthorizationSecurityGroupParams{
					GroupID: toDatabaseUUID(params.GroupID), IdempotencyKeyDigest: digest[:],
					GroupKey: params.Key, GroupName: params.Name, GroupDescription: params.Description,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, mapAuthorizationDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, errors.New("database returned an invalid tenant security group creation result")
			}
			resultID, mapErr := domainUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.GroupID {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, errors.New("database returned an unexpected tenant security group creation result")
			}
			group, mapErr := getAuthorizationSecurityGroup(ctx, queries, params.TenantID, resultID)
			if mapErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, mapErr
			}
			if !authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, group.Version) {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{}, authorization.ErrConflict
			}
			return authorization.IdempotentCreateResult[authorization.TenantSecurityGroup]{
				Value: group, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *AuthorizationRepository) GetTenantSecurityGroup(
	ctx context.Context,
	params authorization.GetTenantSecurityGroupParams,
) (authorization.TenantSecurityGroup, error) {
	if !authorizationUUIDv7(params.GroupID) {
		return authorization.TenantSecurityGroup{}, authorization.ErrInvalidInput
	}
	return withAuthorizationReadTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantSecurityGroup, error) {
			return getAuthorizationSecurityGroup(ctx, queries, params.TenantID, params.GroupID)
		},
	)
}

func (r *AuthorizationRepository) UpdateTenantSecurityGroup(
	ctx context.Context,
	params authorization.UpdateTenantSecurityGroupParams,
) (authorization.TenantSecurityGroup, error) {
	version, err := databaseAuthorizationVersion(params.ExpectedVersion)
	if err != nil || !authorizationUUIDv7(params.GroupID) || params.Name == nil && params.Description == nil {
		return authorization.TenantSecurityGroup{}, authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.TenantSecurityGroup{}, err
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantSecurityGroup, error) {
			updatedVersion, queryErr := queries.UpdateTenantAuthorizationSecurityGroupMetadata(
				ctx,
				dbsql.UpdateTenantAuthorizationSecurityGroupMetadataParams{
					GroupID: toDatabaseUUID(params.GroupID), ExpectedVersion: version,
					GroupName: params.Name, GroupDescription: params.Description,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.TenantSecurityGroup{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return authorization.TenantSecurityGroup{}, errors.New("database returned an unexpected tenant security group version")
			}
			group, mapErr := getAuthorizationSecurityGroup(ctx, queries, params.TenantID, params.GroupID)
			if mapErr != nil {
				return authorization.TenantSecurityGroup{}, mapErr
			}
			if group.Version != int64(updatedVersion) {
				return authorization.TenantSecurityGroup{}, errors.New("database returned inconsistent tenant security group metadata")
			}
			return group, nil
		},
	)
}

func (r *AuthorizationRepository) ArchiveTenantSecurityGroup(
	ctx context.Context,
	params authorization.ArchiveTenantSecurityGroupParams,
) error {
	version, err := databaseAuthorizationVersion(params.ExpectedVersion)
	if err != nil || !authorizationUUIDv7(params.GroupID) {
		return authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.ArchiveTenantAuthorizationSecurityGroup(
				ctx,
				dbsql.ArchiveTenantAuthorizationSecurityGroupParams{
					GroupID: toDatabaseUUID(params.GroupID), ExpectedVersion: version,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, errors.New("database returned an unexpected archived tenant security group version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *AuthorizationRepository) ListTenantSecurityGroupMemberships(
	ctx context.Context,
	params authorization.ListTenantSecurityGroupMembershipsParams,
) ([]authorization.TenantSecurityGroupMembership, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil ||
		!authorizationUUIDv7(params.GroupID) {
		return nil, authorization.ErrInvalidInput
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantSecurityGroupMembership, error) {
			rows, err := queries.ListTenantAuthorizationSecurityGroupMemberships(
				ctx,
				dbsql.ListTenantAuthorizationSecurityGroupMembershipsParams{
					GroupID:                toDatabaseUUID(params.GroupID),
					AfterGroupMembershipID: optionalDatabaseUUID(params.After),
					IncludeRevoked:         params.IncludeRevoked, PageSize: params.Limit,
				},
			)
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantSecurityGroupMembership, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapListedAuthorizationSecurityGroupMembership(
					params.TenantID, params.GroupID, row,
				)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) GetTenantSecurityGroupMembership(
	ctx context.Context,
	params authorization.GetTenantSecurityGroupMembershipParams,
) (authorization.TenantSecurityGroupMembership, error) {
	if !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.MembershipID) {
		return authorization.TenantSecurityGroupMembership{}, authorization.ErrInvalidInput
	}
	return withAuthorizationReadTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantSecurityGroupMembership, error) {
			return getAuthorizationSecurityGroupMembership(
				ctx, queries, params.TenantID, params.GroupID, params.MembershipID,
			)
		},
	)
}

func (r *AuthorizationRepository) AddTenantSecurityGroupMembership(
	ctx context.Context,
	params authorization.AddTenantSecurityGroupMembershipParams,
) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership], error) {
	if !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.MembershipID) ||
		!authorizationUUIDv7(params.UserID) || params.IdempotencyKey == "" {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, authorization.ErrInvalidInput
	}
	expiresAt, err := optionalDatabaseTime(params.ExpiresAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, err
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership], error) {
			result, queryErr := queries.AddTenantAuthorizationSecurityGroupMember(
				ctx,
				dbsql.AddTenantAuthorizationSecurityGroupMemberParams{
					GroupMembershipID:    toDatabaseUUID(params.MembershipID),
					IdempotencyKeyDigest: digest[:], GroupID: toDatabaseUUID(params.GroupID),
					TargetUserID: toDatabaseUUID(params.UserID), Reason: params.Reason,
					ExpiresAt: expiresAt,
					AuditID:   audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, mapAuthorizationDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, errors.New("database returned an invalid security group membership result")
			}
			resultID, mapErr := domainUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.MembershipID {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, errors.New("database returned an unexpected security group membership result")
			}
			edge, mapErr := getAuthorizationSecurityGroupMembership(
				ctx, queries, params.TenantID, params.GroupID, resultID,
			)
			if mapErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, mapErr
			}
			if !authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, edge.Version) {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{}, authorization.ErrConflict
			}
			return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupMembership]{
				Value: edge, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *AuthorizationRepository) RevokeTenantSecurityGroupMembership(
	ctx context.Context,
	params authorization.RevokeTenantSecurityGroupMembershipParams,
) error {
	parsedVersion, err := authorization.ParseEdgeEntityTag(params.ExpectedEntityTag)
	if err != nil {
		return authorization.ErrInvalidInput
	}
	version, err := databaseAuthorizationVersion(parsedVersion)
	if err != nil || !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.MembershipID) {
		return authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withAuthorizationTransactionIsolation(
		ctx, r, params.Actor, params.TenantID, pgx.Serializable,
		func(queries authorizationQueries) (struct{}, error) {
			current, getErr := getAuthorizationSecurityGroupMembership(
				ctx, queries, params.TenantID, params.GroupID, params.MembershipID,
			)
			if getErr != nil {
				return struct{}{}, getErr
			}
			currentEntityTag, tagErr := authorization.TenantSecurityGroupMembershipEntityTag(current)
			if tagErr != nil {
				return struct{}{}, tagErr
			}
			if currentEntityTag != params.ExpectedEntityTag {
				return struct{}{}, authorization.ErrPreconditionFailed
			}
			updatedVersion, queryErr := queries.RevokeTenantAuthorizationSecurityGroupMembership(
				ctx,
				dbsql.RevokeTenantAuthorizationSecurityGroupMembershipParams{
					GroupID: toDatabaseUUID(params.GroupID), GroupMembershipID: toDatabaseUUID(params.MembershipID),
					ExpectedVersion: version, Reason: params.Reason,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, errors.New("database returned an unexpected revoked security group membership version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *AuthorizationRepository) ListTenantSecurityGroupRoleGrants(
	ctx context.Context,
	params authorization.ListTenantSecurityGroupRoleGrantsParams,
) ([]authorization.TenantSecurityGroupRoleGrant, error) {
	if err := validateAuthorizationPage(params.After, params.Limit); err != nil ||
		!authorizationUUIDv7(params.GroupID) {
		return nil, authorization.ErrInvalidInput
	}
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) ([]authorization.TenantSecurityGroupRoleGrant, error) {
			rows, err := queries.ListTenantAuthorizationSecurityGroupRoleGrants(
				ctx,
				dbsql.ListTenantAuthorizationSecurityGroupRoleGrantsParams{
					GroupID:               toDatabaseUUID(params.GroupID),
					AfterGroupRoleGrantID: optionalDatabaseUUID(params.After),
					IncludeRevoked:        params.IncludeRevoked, PageSize: params.Limit,
				},
			)
			if err != nil {
				return nil, mapAuthorizationDatabaseError(err)
			}
			items := make([]authorization.TenantSecurityGroupRoleGrant, 0, len(rows))
			for _, row := range rows {
				item, mapErr := mapListedAuthorizationSecurityGroupRoleGrant(
					params.TenantID, params.GroupID, row,
				)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, item)
			}
			return items, nil
		},
	)
}

func (r *AuthorizationRepository) GetTenantSecurityGroupRoleGrant(
	ctx context.Context,
	params authorization.GetTenantSecurityGroupRoleGrantParams,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	if !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.GrantID) {
		return authorization.TenantSecurityGroupRoleGrant{}, authorization.ErrInvalidInput
	}
	return withAuthorizationReadTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.TenantSecurityGroupRoleGrant, error) {
			return getAuthorizationSecurityGroupRoleGrant(
				ctx, queries, params.TenantID, params.GroupID, params.GrantID,
			)
		},
	)
}

func (r *AuthorizationRepository) GrantTenantSecurityGroupRole(
	ctx context.Context,
	params authorization.GrantTenantSecurityGroupRoleParams,
) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant], error) {
	if !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.GrantID) ||
		!authorizationUUIDv7(params.RoleID) || params.IdempotencyKey == "" {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, authorization.ErrInvalidInput
	}
	expiresAt, err := optionalDatabaseTime(params.ExpiresAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, err
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withAuthorizationTransaction(ctx, r, params.Actor, params.TenantID,
		func(queries authorizationQueries) (authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant], error) {
			result, queryErr := queries.GrantTenantAuthorizationSecurityGroupRole(
				ctx,
				dbsql.GrantTenantAuthorizationSecurityGroupRoleParams{
					GroupRoleGrantID:     toDatabaseUUID(params.GrantID),
					IdempotencyKeyDigest: digest[:], GroupID: toDatabaseUUID(params.GroupID),
					RoleID: toDatabaseUUID(params.RoleID), Reason: params.Reason,
					ExpiresAt: expiresAt,
					AuditID:   audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, mapAuthorizationDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, errors.New("database returned an invalid security group role-grant result")
			}
			resultID, mapErr := domainUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.GrantID {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, errors.New("database returned an unexpected security group role-grant result")
			}
			edge, mapErr := getAuthorizationSecurityGroupRoleGrant(
				ctx, queries, params.TenantID, params.GroupID, resultID,
			)
			if mapErr != nil {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, mapErr
			}
			if !authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, edge.Version) {
				return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{}, authorization.ErrConflict
			}
			return authorization.IdempotentCreateResult[authorization.TenantSecurityGroupRoleGrant]{
				Value: edge, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *AuthorizationRepository) RevokeTenantSecurityGroupRoleGrant(
	ctx context.Context,
	params authorization.RevokeTenantSecurityGroupRoleGrantParams,
) error {
	parsedVersion, err := authorization.ParseEdgeEntityTag(params.ExpectedEntityTag)
	if err != nil {
		return authorization.ErrInvalidInput
	}
	version, err := databaseAuthorizationVersion(parsedVersion)
	if err != nil || !authorizationUUIDv7(params.GroupID) || !authorizationUUIDv7(params.GrantID) {
		return authorization.ErrInvalidInput
	}
	audit, err := r.authorizationAudit(params.Actor, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withAuthorizationTransactionIsolation(
		ctx, r, params.Actor, params.TenantID, pgx.Serializable,
		func(queries authorizationQueries) (struct{}, error) {
			current, getErr := getAuthorizationSecurityGroupRoleGrant(
				ctx, queries, params.TenantID, params.GroupID, params.GrantID,
			)
			if getErr != nil {
				return struct{}{}, getErr
			}
			currentEntityTag, tagErr := authorization.TenantSecurityGroupRoleGrantEntityTag(current)
			if tagErr != nil {
				return struct{}{}, tagErr
			}
			if currentEntityTag != params.ExpectedEntityTag {
				return struct{}{}, authorization.ErrPreconditionFailed
			}
			updatedVersion, queryErr := queries.RevokeTenantAuthorizationSecurityGroupRoleGrant(
				ctx,
				dbsql.RevokeTenantAuthorizationSecurityGroupRoleGrantParams{
					GroupID: toDatabaseUUID(params.GroupID), GroupRoleGrantID: toDatabaseUUID(params.GrantID),
					ExpectedVersion: version, Reason: params.Reason,
					AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapAuthorizationDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, errors.New("database returned an unexpected revoked security group role-grant version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

type authorizationAuditArguments struct {
	auditID              pgtype.UUID
	requestID            pgtype.UUID
	correlationID        pgtype.UUID
	remoteAddress        netip.Addr
	userAgent            string
	authenticationMethod string
}

func (r *AuthorizationRepository) authorizationAudit(
	actor authorization.Actor,
	audit authorization.AuditContext,
	occurredAt time.Time,
) (authorizationAuditArguments, error) {
	if occurredAt.IsZero() || r == nil || r.newID == nil {
		return authorizationAuditArguments{}, authorization.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return authorizationAuditArguments{}, err
	}
	if !authorizationUUIDv7(auditID) {
		return authorizationAuditArguments{}, errors.New("authorization audit ID generator returned an invalid identifier")
	}
	return authorizationAuditArguments{
		auditID: toDatabaseUUID(auditID), requestID: toDatabaseUUID(audit.RequestID),
		correlationID: toDatabaseUUID(audit.CorrelationID), remoteAddress: audit.RemoteAddress,
		userAgent: audit.UserAgent, authenticationMethod: actor.AuthenticationMethod,
	}, nil
}

func withAuthorizationTransaction[T any](
	ctx context.Context,
	repository *AuthorizationRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	work func(authorizationQueries) (T, error),
) (T, error) {
	return withAuthorizationTransactionIsolation(
		ctx, repository, actor, tenantID, pgx.ReadCommitted, work,
	)
}

func withAuthorizationReadTransaction[T any](
	ctx context.Context,
	repository *AuthorizationRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	work func(authorizationQueries) (T, error),
) (T, error) {
	return withAuthorizationTransactionIsolation(
		ctx, repository, actor, tenantID, pgx.RepeatableRead, work,
	)
}

func withAuthorizationTransactionIsolation[T any](
	ctx context.Context,
	repository *AuthorizationRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	isolation pgx.TxIsoLevel,
	work func(authorizationQueries) (T, error),
) (T, error) {
	var zero T
	if !authorizationUUIDv7(tenantID) {
		return zero, authorization.ErrInvalidInput
	}
	if !validAuthorizationRepositoryActor(actor, tenantID) {
		return zero, authorization.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, errors.New("authorization repository transaction dependencies are required")
	}
	result, err := withinTransactionWithOptions(
		ctx,
		repository.begin,
		pgx.TxOptions{IsoLevel: isolation},
		func(tx databaseTransaction) (T, error) {
			queries := repository.queryFactory(tx)
			if queries == nil {
				return zero, errors.New("authorization query surface is required")
			}
			installed, err := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
			})
			if err != nil {
				return zero, mapAuthorizationDatabaseError(err)
			}
			if installed == nil || installed.TenantID != tenantID.String() ||
				installed.UserID != actor.UserID.String() {
				return zero, errors.New("database installed an unexpected tenant authorization context")
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapAuthorizationDatabaseError(err)
	}
	return result, nil
}

func validAuthorizationRepositoryActor(actor authorization.Actor, tenantID uuid.UUID) bool {
	if !authorizationUUIDv7(actor.UserID) || !authorizationUUIDv7(actor.SessionID) ||
		actor.ActiveTenantID != tenantID || !utf8.ValidString(actor.AuthenticationMethod) ||
		len(actor.AuthenticationMethod) < 1 || len(actor.AuthenticationMethod) > 64 {
		return false
	}
	for _, character := range actor.AuthenticationMethod {
		if unicode.IsControl(character) {
			return false
		}
	}
	return strings.TrimSpace(actor.AuthenticationMethod) != ""
}

func authorizationUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validateAuthorizationPage(after *uuid.UUID, limit int32) error {
	if limit < 1 || limit > authorizationHydrationLimit ||
		after != nil && !authorizationUUIDv7(*after) {
		return authorization.ErrInvalidInput
	}
	return nil
}

func databaseAuthorizationVersion(version int64) (int32, error) {
	if version < 1 || version > math.MaxInt32 {
		return 0, authorization.ErrInvalidInput
	}
	return int32(version), nil
}

func optionalDatabaseTime(value *time.Time) (pgtype.Timestamptz, error) {
	normalized, err := authorization.NormalizeWritableExpiry(value)
	if err != nil {
		return pgtype.Timestamptz{}, err
	}
	if normalized == nil {
		return pgtype.Timestamptz{}, nil
	}
	timestamp := databaseTime(*normalized)
	if !timestamp.Valid {
		return pgtype.Timestamptz{}, authorization.ErrInvalidInput
	}
	return timestamp, nil
}

func mapAuthorizationDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authorization.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02":
		return authorization.ErrInvalidInput
	case "42501":
		return authorization.ErrForbidden
	case "P0002":
		return authorization.ErrNotFound
	case "40001":
		if isAuthorizationVersionConflict(err) {
			return authorization.ErrPreconditionFailed
		}
		return authorization.ErrUnavailable
	case "23503", "23505", "23514", "54000", "55000":
		return authorization.ErrConflict
	default:
		return err
	}
}

// PostgreSQL also uses 40001 for retryable transaction aborts, so only the
// messages raised explicitly by authorization mutations represent stale ETags.
func isAuthorizationVersionConflict(err error) bool {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		return false
	}
	switch databaseError.Message {
	case authorizationRoleVersionConflictMessage,
		authorizationRoleGrantVersionConflictMessage,
		authorizationSecurityGroupVersionConflictMessage,
		authorizationGroupMembershipVersionConflictMessage,
		authorizationGroupRoleGrantVersionConflictMessage,
		authorizationMembershipLifecycleRevisionConflictMessage:
		return true
	default:
		return false
	}
}

func getAuthorizationRole(
	ctx context.Context,
	queries authorizationQueries,
	tenantID uuid.UUID,
	roleID uuid.UUID,
) (authorization.TenantRole, error) {
	row, err := queries.GetTenantAuthorizationRole(ctx, dbsql.GetTenantAuthorizationRoleParams{
		RoleID: toDatabaseUUID(roleID),
	})
	if err != nil {
		return authorization.TenantRole{}, mapAuthorizationDatabaseError(err)
	}
	if row == nil {
		return authorization.TenantRole{}, errors.New("database returned a null tenant role")
	}
	summary, err := mapAuthorizationRoleSummary(
		tenantID, row.RoleID, row.RoleKey, row.DisplayName, row.Description,
		row.PrincipalKind, row.SystemRole, row.ProtectedRole, row.Version, row.ArchivedAt,
		row.CreatedAt, row.UpdatedAt,
	)
	if err != nil {
		return authorization.TenantRole{}, err
	}
	if summary.ID != roleID {
		return authorization.TenantRole{}, errors.New("database returned an unexpected tenant role")
	}
	rows, err := queries.GetTenantAuthorizationRolePolicy(
		ctx,
		dbsql.GetTenantAuthorizationRolePolicyParams{RoleID: toDatabaseUUID(roleID)},
	)
	if err != nil {
		return authorization.TenantRole{}, mapAuthorizationDatabaseError(err)
	}
	if len(rows) > int(authorizationPermissionHydrationLimit-1) {
		return authorization.TenantRole{}, errors.New("database returned an oversized tenant role policy")
	}
	policy, err := mapAuthorizationRolePolicy(rows)
	if err != nil {
		return authorization.TenantRole{}, err
	}
	return authorization.TenantRole{TenantRoleSummary: summary, Policy: policy}, nil
}

func mapResolvedTenantAuthority(
	actor authorization.Actor,
	tenantID uuid.UUID,
	contextRow *dbsql.GetCurrentTenantAuthorizationContextRow,
	authorityRows []*dbsql.ResolveCurrentTenantHumanAuthorityRow,
	operatorTeamRows []*dbsql.ResolveCurrentTenantOperatorTeamsRow,
	roleGrantRows []*dbsql.ResolveCurrentTenantHumanRoleGrantPathsRow,
) (authorization.TenantAuthority, error) {
	if contextRow == nil || len(authorityRows) > int(authorizationPermissionHydrationLimit-1) ||
		len(operatorTeamRows) > int(operatorTeamHydrationLimit-1) ||
		len(roleGrantRows) > int(authorizationRolePathHydrationLimit-1) || contextRow.AuthorizationRevision < 1 {
		return authorization.TenantAuthority{}, errors.New("database returned an invalid tenant authority projection")
	}
	resolvedTenantID, err := domainUUID(contextRow.TenantID)
	if err != nil || resolvedTenantID != tenantID {
		return authorization.TenantAuthority{}, errors.New("database returned authority for an unexpected tenant")
	}
	membershipID, err := domainUUID(contextRow.MembershipID)
	if err != nil {
		return authorization.TenantAuthority{}, err
	}
	evaluatedAt, err := domainTime(contextRow.EvaluatedAt)
	if err != nil {
		return authorization.TenantAuthority{}, err
	}
	result := authorization.TenantAuthority{
		TenantID:     tenantID,
		Principal:    authorization.TenantPrincipal{ID: actor.UserID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatus(contextRow.MembershipStatus),
		LegacyRole:                authorization.LegacyMembershipRole(contextRow.CompatibilityRole),
		RoleGrants:                make([]authorization.EffectiveTenantRoleGrant, 0, len(roleGrantRows)),
		Permissions:               make([]authorization.ScopedPermission, 0, len(authorityRows)),
		DelegationCeiling:         make([]authorization.DelegationGrant, 0, len(authorityRows)),
		OperatorTeamRelationships: make([]authorization.OperatorTeamRelationship, 0, len(operatorTeamRows)),
		EvaluatedAt:               evaluatedAt,
	}
	seenOperatorTeams := make(map[uuid.UUID]struct{}, len(operatorTeamRows))
	seenAssignmentEpochs := make(map[uuid.UUID]struct{}, len(operatorTeamRows))
	for _, row := range operatorTeamRows {
		if row == nil {
			return authorization.TenantAuthority{}, errors.New("database returned a null operator-team relationship")
		}
		operatorTeamID, mapErr := domainUUID(row.OperatorTeamID)
		if mapErr != nil || !authorizationUUIDv7(operatorTeamID) {
			return authorization.TenantAuthority{}, errors.New("database returned an invalid operator-team relationship")
		}
		assignmentEpochID, mapErr := domainUUID(row.AssignmentEpochID)
		if mapErr != nil || !authorizationUUIDv7(assignmentEpochID) {
			return authorization.TenantAuthority{}, errors.New("database returned an invalid operator-team assignment epoch")
		}
		if _, duplicate := seenOperatorTeams[operatorTeamID]; duplicate {
			return authorization.TenantAuthority{}, errors.New("database returned a duplicate operator-team relationship")
		}
		if _, duplicate := seenAssignmentEpochs[assignmentEpochID]; duplicate {
			return authorization.TenantAuthority{}, errors.New("database returned a duplicate operator-team assignment epoch")
		}
		seenOperatorTeams[operatorTeamID] = struct{}{}
		seenAssignmentEpochs[assignmentEpochID] = struct{}{}
		result.OperatorTeamRelationships = append(
			result.OperatorTeamRelationships,
			authorization.OperatorTeamRelationship{
				OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID,
			},
		)
	}
	for _, row := range authorityRows {
		if row == nil || !row.Delegable && row.DelegationExpiresAt.Valid {
			return authorization.TenantAuthority{}, errors.New("database returned an invalid effective tenant permission")
		}
		permission, mapErr := domainTenantPermission(row.PermissionKey)
		if mapErr != nil {
			return authorization.TenantAuthority{}, mapErr
		}
		scope, mapErr := domainAuthorizationScope(row.Scope)
		if mapErr != nil {
			return authorization.TenantAuthority{}, mapErr
		}
		tuple := authorization.ScopedPermission{Permission: permission, Scope: scope}
		result.Permissions = append(result.Permissions, tuple)
		if row.Delegable {
			expiresAt, expiryErr := optionalAuthorizationTime(row.DelegationExpiresAt)
			if expiryErr != nil {
				return authorization.TenantAuthority{}, expiryErr
			}
			result.DelegationCeiling = append(result.DelegationCeiling, authorization.DelegationGrant{
				ScopedPermission: tuple, ExpiresAt: expiresAt,
			})
		}
	}
	for _, row := range roleGrantRows {
		grant, mapErr := mapEffectiveAuthorizationGrant(row)
		if mapErr != nil {
			return authorization.TenantAuthority{}, mapErr
		}
		result.RoleGrants = append(result.RoleGrants, grant)
	}
	return result, nil
}

func mapEffectiveAuthorizationGrant(
	row *dbsql.ResolveCurrentTenantHumanRoleGrantPathsRow,
) (authorization.EffectiveTenantRoleGrant, error) {
	if row == nil || row.RoleGrantVersion < 1 {
		return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned an invalid effective tenant role grant")
	}
	grantID, err := domainUUID(row.RoleGrantID)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	roleID, err := domainUUID(row.RoleID)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	sourceID, err := optionalAuthorizationUUID(row.RoleSourceID)
	if err != nil || sourceID == nil {
		return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned an invalid effective role-grant source")
	}
	sourceKind, err := domainAuthorizationSourceKind(row.RoleSourceKind)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	retiredAt, err := optionalAuthorizationTime(row.RoleSourceRetiredAt)
	if err != nil || retiredAt != nil {
		return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned a retired effective role-grant source")
	}
	grantedBy, err := optionalAuthorizationUUID(row.RoleGrantedByUserID)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	grantedAt, err := domainTime(row.RoleGrantedAt)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	expiresAt, err := optionalAuthorizationTime(row.RoleGrantExpiresAt)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	effectiveExpiresAt, err := optionalAuthorizationTime(row.EffectiveExpiresAt)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	sourceType, err := domainRoleGrantSource(row.SourceType)
	if err != nil {
		return authorization.EffectiveTenantRoleGrant{}, err
	}
	provenance := authorization.RoleGrantProvenance{
		SourceType: sourceType, SourceKind: sourceKind, SourceID: sourceID,
		Authoritative: row.RoleSourceAuthoritative, RetiredAt: retiredAt,
		GrantedByUserID: grantedBy, GrantedAt: grantedAt,
		Reason: row.RoleGrantReason, ExpiresAt: expiresAt,
	}
	grant := authorization.EffectiveTenantRoleGrant{
		GrantID: grantID, RoleID: roleID, RoleKey: row.RoleKey, RoleName: row.RoleName,
		Provenance: provenance, EffectiveExpiresAt: effectiveExpiresAt,
	}

	pathType := authorization.RoleGrantPathType(row.PathType)
	switch pathType {
	case authorization.RoleGrantPathDirect:
		if sourceType == authorization.RoleGrantSourceGroup || row.GroupID.Valid ||
			row.GroupKey != "" || row.GroupName != "" || row.GroupMembershipID.Valid ||
			row.MembershipSourceID.Valid || row.MembershipSourceKind != "" ||
			row.MembershipSourceAuthoritative || row.MembershipSourceRetiredAt.Valid ||
			row.MembershipGrantedByUserID.Valid || row.MembershipGrantReason != "" ||
			row.MembershipGrantedAt.Valid || row.MembershipExpiresAt.Valid || row.MembershipVersion != 0 {
			return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned a malformed direct role authority path")
		}
		grant.Path = authorization.EffectiveTenantRoleAuthorityPath{
			PathType: pathType,
			Direct: &authorization.DirectTenantRoleAuthorityPath{
				GrantID: grantID, Provenance: provenance,
			},
		}
	case authorization.RoleGrantPathGroup:
		if sourceType != authorization.RoleGrantSourceGroup || row.MembershipVersion < 1 {
			return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned an invalid group role authority path")
		}
		groupID, mapErr := domainUUID(row.GroupID)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		membershipID, mapErr := domainUUID(row.GroupMembershipID)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		membershipSourceID, mapErr := optionalAuthorizationUUID(row.MembershipSourceID)
		if mapErr != nil || membershipSourceID == nil {
			return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned an invalid group-membership source")
		}
		membershipSourceKind, mapErr := domainAuthorizationSourceKind(row.MembershipSourceKind)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		membershipRetiredAt, mapErr := optionalAuthorizationTime(row.MembershipSourceRetiredAt)
		if mapErr != nil || membershipRetiredAt != nil {
			return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned a retired effective group-membership source")
		}
		membershipGrantedBy, mapErr := optionalAuthorizationUUID(row.MembershipGrantedByUserID)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		membershipGrantedAt, mapErr := domainTime(row.MembershipGrantedAt)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		membershipExpiresAt, mapErr := optionalAuthorizationTime(row.MembershipExpiresAt)
		if mapErr != nil {
			return authorization.EffectiveTenantRoleGrant{}, mapErr
		}
		roleEdgeProvenance := authorization.AuthorizationEdgeProvenance{
			SourceKind: sourceKind, SourceID: sourceID,
			Authoritative: row.RoleSourceAuthoritative, RetiredAt: retiredAt,
			GrantedByUserID: grantedBy, GrantedAt: grantedAt,
			Reason: row.RoleGrantReason, ExpiresAt: expiresAt,
		}
		membershipProvenance := authorization.AuthorizationEdgeProvenance{
			SourceKind: membershipSourceKind, SourceID: membershipSourceID,
			Authoritative: row.MembershipSourceAuthoritative, RetiredAt: membershipRetiredAt,
			GrantedByUserID: membershipGrantedBy, GrantedAt: membershipGrantedAt,
			Reason: row.MembershipGrantReason, ExpiresAt: membershipExpiresAt,
		}
		grant.Path = authorization.EffectiveTenantRoleAuthorityPath{
			PathType: pathType,
			Group: &authorization.GroupTenantRoleAuthorityPath{
				Group: authorization.TenantSecurityGroupAuthoritySummary{
					ID: groupID, Key: row.GroupKey, Name: row.GroupName,
				},
				MembershipEdge: authorization.TenantSecurityGroupAuthorityEdge{
					ID: membershipID, Provenance: membershipProvenance,
				},
				RoleGrantEdge: authorization.TenantSecurityGroupAuthorityEdge{
					ID: grantID, Provenance: roleEdgeProvenance,
				},
			},
		}
	default:
		return authorization.EffectiveTenantRoleGrant{}, errors.New("database returned an unknown tenant role authority path")
	}
	return grant, nil
}

func mapTenantPermissionDefinition(
	row *dbsql.ListTenantPermissionCatalogRow,
) (authorization.TenantPermissionDefinition, error) {
	if row == nil {
		return authorization.TenantPermissionDefinition{}, errors.New("database returned a null tenant permission row")
	}
	identifier, err := domainUUID(row.PermissionID)
	if err != nil {
		return authorization.TenantPermissionDefinition{}, err
	}
	permission, err := domainTenantPermission(row.PermissionKey)
	if err != nil {
		return authorization.TenantPermissionDefinition{}, err
	}
	scopes := make([]authorization.Scope, 0, len(row.AllowedScopes))
	for _, value := range row.AllowedScopes {
		scope, mapErr := domainAuthorizationScope(value)
		if mapErr != nil {
			return authorization.TenantPermissionDefinition{}, mapErr
		}
		scopes = append(scopes, scope)
	}
	principalKinds := make([]authorization.PrincipalKind, 0, len(row.PrincipalKinds))
	for _, value := range row.PrincipalKinds {
		kind, mapErr := domainPrincipalKind(value)
		if mapErr != nil {
			return authorization.TenantPermissionDefinition{}, mapErr
		}
		principalKinds = append(principalKinds, kind)
	}
	return authorization.TenantPermissionDefinition{
		ID: identifier, Key: permission, Name: row.DisplayName, Description: row.Description,
		AllowedScopes: scopes, PrincipalKinds: principalKinds,
	}, nil
}

func mapTenantAuthorizationUser(
	tenantID uuid.UUID,
	row *dbsql.ListTenantAuthorizationUsersRow,
) (authorization.TenantUserSummary, error) {
	if row == nil {
		return authorization.TenantUserSummary{}, errors.New("database returned a null tenant user row")
	}
	membershipID, err := domainUUID(row.MembershipID)
	if err != nil {
		return authorization.TenantUserSummary{}, err
	}
	userID, err := domainUUID(row.UserID)
	if err != nil {
		return authorization.TenantUserSummary{}, err
	}
	createdAt, err := domainTime(row.CreatedAt)
	if err != nil {
		return authorization.TenantUserSummary{}, err
	}
	updatedAt, err := domainTime(row.UpdatedAt)
	if err != nil {
		return authorization.TenantUserSummary{}, err
	}
	entityTag, err := authorization.TenantMembershipLifecycleEntityTag(int64(row.LifecycleRevision))
	if err != nil {
		return authorization.TenantUserSummary{}, err
	}
	return authorization.TenantUserSummary{
		TenantID: tenantID, MembershipID: membershipID,
		User: authorization.TenantUserProfile{
			ID: userID, Email: row.Email, DisplayName: row.DisplayName, Active: row.UserActive,
		},
		MembershipStatus:     authorization.MembershipStatus(row.MembershipStatus),
		LegacyMembershipRole: authorization.LegacyMembershipRole(row.CompatibilityRole),
		LifecycleRevision:    int64(row.LifecycleRevision), EntityTag: entityTag,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

func mapTenantMembershipLifecycleReceipt(
	params authorization.ChangeTenantMembershipLifecycleParams,
	row *dbsql.ChangeTenantMembershipLifecycleRow,
) (authorization.TenantMembershipLifecycleReceipt, error) {
	if row == nil || row.LifecycleRevision < 1 || row.RevokedSessionCount < 0 ||
		row.RevokedContinuationCount < 0 {
		return authorization.TenantMembershipLifecycleReceipt{}, errors.New("database returned an invalid tenant membership lifecycle receipt")
	}
	tenantID, err := domainUUID(row.TenantID)
	if err != nil || tenantID != params.TenantID {
		return authorization.TenantMembershipLifecycleReceipt{}, errors.New("database returned membership lifecycle receipt for an unexpected tenant")
	}
	membershipID, err := domainUUID(row.MembershipID)
	if err != nil {
		return authorization.TenantMembershipLifecycleReceipt{}, err
	}
	userID, err := domainUUID(row.TargetUserID)
	if err != nil || userID != params.UserID {
		return authorization.TenantMembershipLifecycleReceipt{}, errors.New("database returned membership lifecycle receipt for an unexpected user")
	}
	updatedAt, err := domainTime(row.UpdatedAt)
	if err != nil {
		return authorization.TenantMembershipLifecycleReceipt{}, err
	}
	entityTag, err := authorization.TenantMembershipLifecycleEntityTag(int64(row.LifecycleRevision))
	if err != nil {
		return authorization.TenantMembershipLifecycleReceipt{}, err
	}
	return authorization.TenantMembershipLifecycleReceipt{
		TenantID: tenantID, MembershipID: membershipID, UserID: userID,
		PreviousStatus:    authorization.MembershipStatus(row.PreviousStatus),
		Status:            authorization.MembershipStatus(row.Status),
		LifecycleRevision: int64(row.LifecycleRevision), EntityTag: entityTag,
		UpdatedAt: updatedAt, RevokedSessionCount: int64(row.RevokedSessionCount),
		RevokedContinuationCount: int64(row.RevokedContinuationCount),
		Replayed:                 row.Replayed,
	}, nil
}

func mapListedDirectAuthorizationGrant(
	tenantID uuid.UUID,
	userID uuid.UUID,
	row *dbsql.ListTenantMembershipRoleGrantsRow,
) (authorization.DirectUserRoleGrant, error) {
	if row == nil {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned a null direct tenant role-grant row")
	}
	return mapDirectAuthorizationGrant(tenantID, userID, authorizationGrantRow{
		grantID: row.GrantID, roleID: row.RoleID, roleKey: row.RoleKey, roleName: row.RoleName,
		roleDescription: row.RoleDescription, roleSystem: row.RoleSystem,
		roleArchivedAt: row.RoleArchivedAt, roleVersion: row.RoleVersion,
		roleCreatedAt: row.RoleCreatedAt, roleUpdatedAt: row.RoleUpdatedAt,
		sourceID: row.SourceID, sourceKind: row.SourceKind,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
		sourceType:                row.SourceType,
		grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
		grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		grantState: row.GrantState,
		version:    row.Version, updatedAt: row.UpdatedAt,
	})
}

func getDirectAuthorizationGrant(
	ctx context.Context,
	queries authorizationQueries,
	tenantID uuid.UUID,
	grantID uuid.UUID,
) (authorization.DirectUserRoleGrant, error) {
	row, err := queries.GetTenantMembershipRoleGrant(ctx, dbsql.GetTenantMembershipRoleGrantParams{
		GrantID: toDatabaseUUID(grantID),
	})
	if err != nil {
		return authorization.DirectUserRoleGrant{}, mapAuthorizationDatabaseError(err)
	}
	if row == nil {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned a null direct tenant role grant")
	}
	userID, err := domainUUID(row.TargetUserID)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	grant, err := mapDirectAuthorizationGrant(tenantID, userID, authorizationGrantRow{
		grantID: row.GrantID, roleID: row.RoleID, roleKey: row.RoleKey, roleName: row.RoleName,
		roleDescription: row.RoleDescription, roleSystem: row.RoleSystem,
		roleArchivedAt: row.RoleArchivedAt, roleVersion: row.RoleVersion,
		roleCreatedAt: row.RoleCreatedAt, roleUpdatedAt: row.RoleUpdatedAt,
		sourceID: row.SourceID, sourceKind: row.SourceKind,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
		sourceType:                row.SourceType,
		grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
		grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		grantState: row.GrantState,
		version:    row.Version, updatedAt: row.UpdatedAt,
	})
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	if grant.ID != grantID {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an unexpected direct tenant role grant")
	}
	return grant, nil
}

func getAuthorizationSecurityGroup(
	ctx context.Context,
	queries authorizationQueries,
	tenantID uuid.UUID,
	groupID uuid.UUID,
) (authorization.TenantSecurityGroup, error) {
	row, err := queries.GetTenantAuthorizationSecurityGroup(
		ctx,
		dbsql.GetTenantAuthorizationSecurityGroupParams{GroupID: toDatabaseUUID(groupID)},
	)
	if err != nil {
		return authorization.TenantSecurityGroup{}, mapAuthorizationDatabaseError(err)
	}
	group, err := mapGotAuthorizationSecurityGroup(tenantID, row)
	if err != nil {
		return authorization.TenantSecurityGroup{}, err
	}
	if group.ID != groupID {
		return authorization.TenantSecurityGroup{}, errors.New("database returned an unexpected tenant security group")
	}
	return group, nil
}

func getAuthorizationSecurityGroupMembership(
	ctx context.Context,
	queries authorizationQueries,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	membershipID uuid.UUID,
) (authorization.TenantSecurityGroupMembership, error) {
	row, err := queries.GetTenantAuthorizationSecurityGroupMembership(
		ctx,
		dbsql.GetTenantAuthorizationSecurityGroupMembershipParams{
			GroupID: toDatabaseUUID(groupID), GroupMembershipID: toDatabaseUUID(membershipID),
		},
	)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, mapAuthorizationDatabaseError(err)
	}
	edge, err := mapGotAuthorizationSecurityGroupMembership(tenantID, groupID, row)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	if edge.ID != membershipID {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned an unexpected security group membership")
	}
	return edge, nil
}

func getAuthorizationSecurityGroupRoleGrant(
	ctx context.Context,
	queries authorizationQueries,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	grantID uuid.UUID,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	row, err := queries.GetTenantAuthorizationSecurityGroupRoleGrant(
		ctx,
		dbsql.GetTenantAuthorizationSecurityGroupRoleGrantParams{
			GroupID: toDatabaseUUID(groupID), GroupRoleGrantID: toDatabaseUUID(grantID),
		},
	)
	if err != nil {
		return authorization.TenantSecurityGroupRoleGrant{}, mapAuthorizationDatabaseError(err)
	}
	edge, err := mapGotAuthorizationSecurityGroupRoleGrant(tenantID, groupID, row)
	if err != nil {
		return authorization.TenantSecurityGroupRoleGrant{}, err
	}
	if edge.ID != grantID {
		return authorization.TenantSecurityGroupRoleGrant{}, errors.New("database returned an unexpected security group role grant")
	}
	return edge, nil
}

func authorizationCommandVersionMatches(createdVersion int32, replayed bool, currentVersion int64) bool {
	if createdVersion < 1 || currentVersion < 1 {
		return false
	}
	if replayed {
		return currentVersion >= int64(createdVersion)
	}
	return currentVersion == int64(createdVersion)
}

var _ authorization.Repository = (*AuthorizationRepository)(nil)
