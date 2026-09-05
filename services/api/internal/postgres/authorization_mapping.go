package postgres

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func databaseAuthorizationPolicy(
	policy authorization.TenantRolePolicy,
) ([]string, []string, []string, []string, error) {
	permissionKeys := make([]string, len(policy.Permissions))
	permissionScopes := make([]string, len(policy.Permissions))
	for index, permission := range policy.Permissions {
		scope, err := databaseAuthorizationScope(permission.Scope)
		if err != nil || permission.Permission == "" {
			return nil, nil, nil, nil, errors.New("tenant role policy contains an invalid permission")
		}
		permissionKeys[index] = string(permission.Permission)
		permissionScopes[index] = scope
	}
	delegationKeys := make([]string, len(policy.DelegationCeiling))
	delegationScopes := make([]string, len(policy.DelegationCeiling))
	for index, permission := range policy.DelegationCeiling {
		scope, err := databaseAuthorizationScope(permission.Scope)
		if err != nil || permission.Permission == "" {
			return nil, nil, nil, nil, errors.New("tenant role policy contains an invalid delegation ceiling")
		}
		delegationKeys[index] = string(permission.Permission)
		delegationScopes[index] = scope
	}
	return permissionKeys, permissionScopes, delegationKeys, delegationScopes, nil
}

func databaseAuthorizationScope(scope authorization.Scope) (string, error) {
	switch scope {
	case authorization.ScopeOwn,
		authorization.ScopeAssigned,
		authorization.ScopeOperatorTeam,
		authorization.ScopeTenant,
		authorization.ScopePlatform:
		return string(scope), nil
	default:
		return "", fmt.Errorf("unknown tenant authorization scope %q", scope)
	}
}

func domainAuthorizationScope(value string) (authorization.Scope, error) {
	scope := authorization.Scope(value)
	switch scope {
	case authorization.ScopeOwn,
		authorization.ScopeAssigned,
		authorization.ScopeOperatorTeam,
		authorization.ScopeTenant,
		authorization.ScopePlatform:
		return scope, nil
	default:
		return "", fmt.Errorf("database returned unknown tenant authorization scope %q", value)
	}
}

func domainTenantPermission(value string) (authorization.TenantPermission, error) {
	permission := authorization.TenantPermission(value)
	switch permission {
	case authorization.TenantPermissionPermissionRead,
		authorization.TenantPermissionRoleRead,
		authorization.TenantPermissionRoleManage,
		authorization.TenantPermissionRoleGrant,
		authorization.TenantPermissionUserRead,
		authorization.TenantPermissionMembershipManage,
		authorization.TenantPermissionGroupRead,
		authorization.TenantPermissionGroupManage,
		authorization.TenantPermissionGroupMembershipManage,
		authorization.TenantPermissionOperatorTeamRead,
		authorization.TenantPermissionOperatorTeamManage,
		authorization.TenantPermissionOperatorTeamRosterManage,
		authorization.TenantPermissionServiceAccountRead,
		authorization.TenantPermissionServiceAccountManage,
		authorization.TenantPermissionServiceAccountCredentialManage,
		authorization.TenantPermissionAlertCreate,
		authorization.TenantPermissionIdentityProviderRead,
		authorization.TenantPermissionIdentityProviderManage,
		authorization.TenantPermissionIdentityProviderTest,
		authorization.TenantPermissionIdentityMappingRead,
		authorization.TenantPermissionIdentityMappingManage,
		authorization.TenantPermissionIdentitySyncRun,
		authorization.TenantPermissionIdentityPolicyRead,
		authorization.TenantPermissionIdentityPolicyManage,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
		authorization.TenantPermissionNotificationManage,
		authorization.TenantPermissionAuditRead,
		authorization.TenantPermissionAuditExport,
		authorization.TenantPermissionAuditRetentionManage,
		authorization.TenantPermissionSLARead,
		authorization.TenantPermissionSLAManage,
		authorization.TenantPermissionSLASimulate,
		authorization.TenantPermissionWorkflowRead,
		authorization.TenantPermissionWorkflowManage,
		authorization.TenantPermissionAlertSLAOverride,
		authorization.TenantPermissionCaseSLAOverride,
		authorization.TenantPermissionAlertRead,
		authorization.TenantPermissionAlertActivityRead,
		authorization.TenantPermissionAlertCommentRead,
		authorization.TenantPermissionAlertLinkRead,
		authorization.TenantPermissionAlertUpdate,
		authorization.TenantPermissionAlertDelete,
		authorization.TenantPermissionAlertAssign,
		authorization.TenantPermissionAlertClaim,
		authorization.TenantPermissionAlertEscalate,
		authorization.TenantPermissionAlertCommentPublic,
		authorization.TenantPermissionAlertCommentPrivate,
		authorization.TenantPermissionCaseRead,
		authorization.TenantPermissionCaseActivityRead,
		authorization.TenantPermissionCaseCommentRead,
		authorization.TenantPermissionCaseLinkRead,
		authorization.TenantPermissionCaseCreate,
		authorization.TenantPermissionCaseUpdate,
		authorization.TenantPermissionCaseClaim,
		authorization.TenantPermissionCaseTransfer,
		authorization.TenantPermissionCaseTransition,
		authorization.TenantPermissionCaseCommentPublic,
		authorization.TenantPermissionCaseCommentPrivate,
		authorization.TenantPermissionContactRead,
		authorization.TenantPermissionContactManage,
		authorization.TenantPermissionContactPreferenceManage,
		authorization.TenantPermissionContactGroupRead,
		authorization.TenantPermissionContactGroupManage,
		authorization.TenantPermissionPortalAlertRead,
		authorization.TenantPermissionPortalCaseRead,
		authorization.TenantPermissionPortalCommentPublic,
		authorization.TenantPermissionPortalAttachmentRead,
		authorization.TenantPermissionPortalContactPreferenceManage,
		authorization.TenantPermissionCustomFieldRead,
		authorization.TenantPermissionCustomFieldManage,
		authorization.TenantPermissionDFIRIOCRead,
		authorization.TenantPermissionDFIRIOCManage,
		authorization.TenantPermissionDFIRAssetRead,
		authorization.TenantPermissionDFIRAssetManage,
		authorization.TenantPermissionDFIREvidenceRead,
		authorization.TenantPermissionDFIREvidenceManage,
		authorization.TenantPermissionDFIRTimelineRead,
		authorization.TenantPermissionDFIRTimelineManage,
		authorization.TenantPermissionDFIRTaskRead,
		authorization.TenantPermissionDFIRTaskManage,
		authorization.TenantPermissionDFIRAttachmentRead,
		authorization.TenantPermissionDFIRAttachmentManage,
		authorization.TenantPermissionDFIRRelationshipRead,
		authorization.TenantPermissionDFIRRelationshipManage:
		return permission, nil
	default:
		return "", fmt.Errorf("database returned unknown tenant permission %q", value)
	}
}

func domainPrincipalKind(value string) (authorization.PrincipalKind, error) {
	kind := authorization.PrincipalKind(value)
	switch kind {
	case authorization.PrincipalKindHuman, authorization.PrincipalKindServiceAccount:
		return kind, nil
	default:
		return "", fmt.Errorf("database returned unknown tenant principal kind %q", value)
	}
}

func domainRoleGrantSource(value string) (authorization.RoleGrantSourceType, error) {
	source := authorization.RoleGrantSourceType(value)
	switch source {
	case authorization.RoleGrantSourceDirect,
		authorization.RoleGrantSourceGroup,
		authorization.RoleGrantSourceIdentityProvider,
		authorization.RoleGrantSourceSystem:
		return source, nil
	default:
		return "", fmt.Errorf("database returned unknown tenant role-grant source %q", value)
	}
}

func domainAuthorizationSourceKind(value string) (authorization.AuthorizationSourceKind, error) {
	source := authorization.AuthorizationSourceKind(value)
	switch source {
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourceManual,
		authorization.AuthorizationSourceIdentityMapping,
		authorization.AuthorizationSourcePlatformRecovery:
		return source, nil
	default:
		return "", fmt.Errorf("database returned unknown authorization source kind %q", value)
	}
}

func optionalAuthorizationUUID(value pgtype.UUID) (*uuid.UUID, error) {
	if !value.Valid {
		return nil, nil
	}
	identifier, err := domainUUID(value)
	if err != nil {
		return nil, err
	}
	return &identifier, nil
}

func optionalAuthorizationTime(value pgtype.Timestamptz) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	timestamp, err := domainTime(value)
	if err != nil {
		return nil, err
	}
	return &timestamp, nil
}

func mapAuthorizationRoleSummary(
	tenantID uuid.UUID,
	roleID pgtype.UUID,
	key string,
	name string,
	description string,
	principalKindValue string,
	system bool,
	protected bool,
	version int32,
	archivedValue pgtype.Timestamptz,
	createdValue pgtype.Timestamptz,
	updatedValue pgtype.Timestamptz,
) (authorization.TenantRoleSummary, error) {
	identifier, err := domainUUID(roleID)
	if err != nil {
		return authorization.TenantRoleSummary{}, err
	}
	createdAt, err := domainTime(createdValue)
	if err != nil {
		return authorization.TenantRoleSummary{}, err
	}
	updatedAt, err := domainTime(updatedValue)
	if err != nil {
		return authorization.TenantRoleSummary{}, err
	}
	archivedAt, err := optionalAuthorizationTime(archivedValue)
	if err != nil {
		return authorization.TenantRoleSummary{}, err
	}
	principalKind, err := domainPrincipalKind(principalKindValue)
	if err != nil || protected && (!system || principalKind != authorization.PrincipalKindHuman) || version < 1 {
		return authorization.TenantRoleSummary{}, errors.New("database returned an invalid tenant role")
	}
	return authorization.TenantRoleSummary{
		ID: identifier, TenantID: tenantID, Key: key, Name: name,
		Description: description, PrincipalKind: principalKind, System: system, Archived: archivedAt != nil,
		ArchivedAt: archivedAt, Version: int64(version), CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

func mapAuthorizationRolePolicy(
	rows []*dbsql.GetTenantAuthorizationRolePolicyRow,
) (authorization.TenantRolePolicy, error) {
	permissionKeys := make([]string, 0, len(rows))
	permissionScopes := make([]string, 0, len(rows))
	delegationKeys := make([]string, 0, len(rows))
	delegationScopes := make([]string, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			return authorization.TenantRolePolicy{}, errors.New("database returned a null tenant role policy row")
		}
		permissionKeys = append(permissionKeys, row.PermissionKey)
		permissionScopes = append(permissionScopes, row.Scope)
		if row.Delegable {
			delegationKeys = append(delegationKeys, row.PermissionKey)
			delegationScopes = append(delegationScopes, row.Scope)
		}
	}
	return mapAuthorizationRolePolicyArrays(
		permissionKeys, permissionScopes, delegationKeys, delegationScopes,
	)
}

func mapAuthorizationRolePolicyArrays(
	permissionKeys []string,
	permissionScopes []string,
	delegationKeys []string,
	delegationScopes []string,
) (authorization.TenantRolePolicy, error) {
	if len(permissionKeys) > int(authorizationPermissionHydrationLimit-1) ||
		len(delegationKeys) > int(authorizationPermissionHydrationLimit-1) {
		return authorization.TenantRolePolicy{}, errors.New("database returned an oversized tenant role policy")
	}
	permissions, permissionSet, err := mapAuthorizationScopedPermissionArrays(
		permissionKeys, permissionScopes,
	)
	if err != nil {
		return authorization.TenantRolePolicy{}, err
	}
	delegationCeiling, _, err := mapAuthorizationScopedPermissionArrays(
		delegationKeys, delegationScopes,
	)
	if err != nil {
		return authorization.TenantRolePolicy{}, err
	}
	for _, tuple := range delegationCeiling {
		if _, granted := permissionSet[tuple]; !granted {
			return authorization.TenantRolePolicy{}, errors.New("database returned a delegation ceiling outside the tenant role policy")
		}
	}
	return authorization.TenantRolePolicy{
		Permissions: permissions, DelegationCeiling: delegationCeiling,
	}, nil
}

func mapAuthorizationScopedPermissionArrays(
	keys []string,
	scopes []string,
) ([]authorization.ScopedPermission, map[authorization.ScopedPermission]struct{}, error) {
	if len(keys) != len(scopes) {
		return nil, nil, errors.New("database returned mismatched tenant role policy arrays")
	}
	tuples := make([]authorization.ScopedPermission, len(keys))
	seen := make(map[authorization.ScopedPermission]struct{}, len(keys))
	for index, key := range keys {
		permission, err := domainTenantPermission(key)
		if err != nil {
			return nil, nil, err
		}
		scope, err := domainAuthorizationScope(scopes[index])
		if err != nil {
			return nil, nil, err
		}
		tuple := authorization.ScopedPermission{Permission: permission, Scope: scope}
		if _, duplicate := seen[tuple]; duplicate {
			return nil, nil, errors.New("database returned a duplicate tenant role policy tuple")
		}
		tuples[index] = tuple
		seen[tuple] = struct{}{}
	}
	return tuples, seen, nil
}

type authorizationGrantRow struct {
	grantID                   pgtype.UUID
	roleID                    pgtype.UUID
	roleKey                   string
	roleName                  string
	roleDescription           string
	roleSystem                bool
	roleArchivedAt            pgtype.Timestamptz
	roleVersion               int32
	roleCreatedAt             pgtype.Timestamptz
	roleUpdatedAt             pgtype.Timestamptz
	sourceID                  pgtype.UUID
	sourceKind                string
	sourceAuthoritative       bool
	sourceRetiredAt           pgtype.Timestamptz
	managedByAuthorizationAPI bool
	sourceType                string
	grantedByUserID           pgtype.UUID
	grantReason               string
	grantedAt                 pgtype.Timestamptz
	expiresAt                 pgtype.Timestamptz
	revokedAt                 pgtype.Timestamptz
	revokedByUserID           pgtype.UUID
	revokeReason              string
	grantState                string
	version                   int32
	updatedAt                 pgtype.Timestamptz
}

func mapDirectAuthorizationGrant(
	tenantID uuid.UUID,
	userID uuid.UUID,
	row authorizationGrantRow,
) (authorization.DirectUserRoleGrant, error) {
	grantID, err := domainUUID(row.grantID)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	role, err := mapAuthorizationRoleSummary(
		tenantID, row.roleID, row.roleKey, row.roleName, row.roleDescription,
		string(authorization.PrincipalKindHuman), row.roleSystem, false, row.roleVersion, row.roleArchivedAt,
		row.roleCreatedAt, row.roleUpdatedAt,
	)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	sourceKind, err := domainAuthorizationSourceKind(row.sourceKind)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	sourceType, err := domainRoleGrantSource(row.sourceType)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	expectedSourceType := authorization.RoleGrantSourceSystem
	switch sourceKind {
	case authorization.AuthorizationSourceManual:
		expectedSourceType = authorization.RoleGrantSourceDirect
	case authorization.AuthorizationSourceIdentityMapping:
		expectedSourceType = authorization.RoleGrantSourceIdentityProvider
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourcePlatformRecovery:
	default:
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an unsupported direct tenant role-grant owner")
	}
	if sourceType != expectedSourceType {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an incoherent direct tenant role-grant source")
	}
	sourceID, err := optionalAuthorizationUUID(row.sourceID)
	if err != nil || sourceID == nil || !authorizationUUIDv7(*sourceID) {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an invalid direct tenant role-grant source ID")
	}
	retiredAt, err := optionalAuthorizationTime(row.sourceRetiredAt)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an invalid direct tenant role-grant source retirement")
	}
	if row.managedByAuthorizationAPI &&
		(sourceKind != authorization.AuthorizationSourceManual || retiredAt != nil) {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an invalid direct tenant role-grant owner")
	}
	grantedBy, err := optionalAuthorizationUUID(row.grantedByUserID)
	if err != nil || grantedBy != nil && !authorizationUUIDv7(*grantedBy) ||
		sourceKind == authorization.AuthorizationSourceManual && grantedBy == nil {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an invalid direct tenant role-grant grantor")
	}
	grantedAt, err := domainTime(row.grantedAt)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	expiresAt, err := optionalAuthorizationTime(row.expiresAt)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	revokedAt, err := optionalAuthorizationTime(row.revokedAt)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	revokedBy, err := optionalAuthorizationUUID(row.revokedByUserID)
	if err != nil {
		return authorization.DirectUserRoleGrant{}, err
	}
	var revokeReason *string
	if row.revokeReason != "" {
		value := row.revokeReason
		revokeReason = &value
	}
	switch authorization.DirectRoleGrantState(row.grantState) {
	case authorization.DirectRoleGrantStateActive:
		if revokedAt != nil || revokedBy != nil || revokeReason != nil {
			return authorization.DirectUserRoleGrant{}, errors.New("database returned revocation metadata for an active direct tenant role grant")
		}
	case authorization.DirectRoleGrantStateExpired:
		if expiresAt == nil || revokedAt != nil || revokedBy != nil || revokeReason != nil {
			return authorization.DirectUserRoleGrant{}, errors.New("database returned invalid expired direct tenant role-grant metadata")
		}
	case authorization.DirectRoleGrantStateRevoked:
		if revokedAt == nil || revokedBy == nil || revokeReason == nil {
			return authorization.DirectUserRoleGrant{}, errors.New("database returned incomplete direct tenant role-grant revocation metadata")
		}
	default:
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an unknown direct tenant role-grant state")
	}
	updatedAt, err := domainTime(row.updatedAt)
	if err != nil || row.version < 1 {
		return authorization.DirectUserRoleGrant{}, errors.New("database returned an invalid direct tenant role-grant version")
	}
	return authorization.DirectUserRoleGrant{
		ID: grantID, TenantID: tenantID, UserID: userID, Role: role,
		ManagedByAuthorizationAPI: row.managedByAuthorizationAPI,
		Provenance: authorization.RoleGrantProvenance{
			SourceType: sourceType, SourceKind: sourceKind,
			SourceID: sourceID, Authoritative: row.sourceAuthoritative, RetiredAt: retiredAt,
			GrantedByUserID: grantedBy,
			GrantedAt:       grantedAt, Reason: row.grantReason, ExpiresAt: expiresAt,
		},
		PathType: authorization.RoleGrantPathDirect,
		State:    authorization.DirectRoleGrantState(row.grantState), RevokedAt: revokedAt,
		RevokedByUserID: revokedBy, RevokeReason: revokeReason,
		Version: int64(row.version), UpdatedAt: updatedAt,
	}, nil
}

type authorizationSecurityGroupRow struct {
	groupID          pgtype.UUID
	groupKey         string
	groupName        string
	groupDescription string
	archivedAt       pgtype.Timestamptz
	version          int32
	createdAt        pgtype.Timestamptz
	updatedAt        pgtype.Timestamptz
}

func mapAuthorizationSecurityGroup(
	tenantID uuid.UUID,
	row authorizationSecurityGroupRow,
) (authorization.TenantSecurityGroup, error) {
	groupID, err := domainUUID(row.groupID)
	if err != nil || !authorizationUUIDv7(groupID) {
		return authorization.TenantSecurityGroup{}, errors.New("database returned an invalid tenant security group ID")
	}
	createdAt, err := domainTime(row.createdAt)
	if err != nil {
		return authorization.TenantSecurityGroup{}, err
	}
	updatedAt, err := domainTime(row.updatedAt)
	if err != nil || updatedAt.Before(createdAt) || row.version < 1 {
		return authorization.TenantSecurityGroup{}, errors.New("database returned invalid tenant security group lifecycle metadata")
	}
	archivedAt, err := optionalAuthorizationTime(row.archivedAt)
	if err != nil || archivedAt != nil && archivedAt.Before(createdAt) {
		return authorization.TenantSecurityGroup{}, errors.New("database returned an invalid tenant security group archive timestamp")
	}
	return authorization.TenantSecurityGroup{
		ID: groupID, TenantID: tenantID, Key: row.groupKey, Name: row.groupName,
		Description: row.groupDescription, Archived: archivedAt != nil, ArchivedAt: archivedAt,
		Version: int64(row.version), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

type authorizationEdgeRow struct {
	sourceID                  pgtype.UUID
	sourceKind                string
	sourceAuthoritative       bool
	sourceRetiredAt           pgtype.Timestamptz
	managedByAuthorizationAPI bool
	grantedByUserID           pgtype.UUID
	grantReason               string
	grantedAt                 pgtype.Timestamptz
	expiresAt                 pgtype.Timestamptz
	revokedAt                 pgtype.Timestamptz
	revokedByUserID           pgtype.UUID
	revokeReason              string
	state                     string
	version                   int32
	updatedAt                 pgtype.Timestamptz
}

type mappedAuthorizationEdge struct {
	provenance                authorization.AuthorizationEdgeProvenance
	managedByAuthorizationAPI bool
	state                     authorization.AuthorizationEdgeState
	revokedAt                 *time.Time
	revokedByUserID           *uuid.UUID
	revokeReason              *string
	version                   int64
	updatedAt                 time.Time
}

func mapAuthorizationEdge(row authorizationEdgeRow) (mappedAuthorizationEdge, error) {
	sourceID, err := optionalAuthorizationUUID(row.sourceID)
	if err != nil || sourceID == nil || !authorizationUUIDv7(*sourceID) {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge source ID")
	}
	sourceKind, err := domainAuthorizationSourceKind(row.sourceKind)
	if err != nil {
		return mappedAuthorizationEdge{}, err
	}
	retiredAt, err := optionalAuthorizationTime(row.sourceRetiredAt)
	if err != nil {
		return mappedAuthorizationEdge{}, err
	}
	if row.managedByAuthorizationAPI &&
		(sourceKind != authorization.AuthorizationSourceManual || retiredAt != nil) {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge owner")
	}
	grantedBy, err := optionalAuthorizationUUID(row.grantedByUserID)
	if err != nil || grantedBy != nil && !authorizationUUIDv7(*grantedBy) ||
		sourceKind == authorization.AuthorizationSourceManual && grantedBy == nil {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge grantor")
	}
	grantedAt, err := domainTime(row.grantedAt)
	if err != nil {
		return mappedAuthorizationEdge{}, err
	}
	expiresAt, err := optionalAuthorizationTime(row.expiresAt)
	if err != nil || expiresAt != nil && !expiresAt.After(grantedAt) {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge expiry")
	}
	revokedAt, err := optionalAuthorizationTime(row.revokedAt)
	if err != nil || revokedAt != nil && revokedAt.Before(grantedAt) {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge revocation timestamp")
	}
	revokedBy, err := optionalAuthorizationUUID(row.revokedByUserID)
	if err != nil || revokedBy != nil && !authorizationUUIDv7(*revokedBy) {
		return mappedAuthorizationEdge{}, errors.New("database returned an invalid authorization edge revoker")
	}
	updatedAt, err := domainTime(row.updatedAt)
	if err != nil || updatedAt.Before(grantedAt) || row.version < 1 {
		return mappedAuthorizationEdge{}, errors.New("database returned invalid authorization edge lifecycle metadata")
	}
	state, err := domainAuthorizationEdgeState(row.state)
	if err != nil {
		return mappedAuthorizationEdge{}, err
	}
	var revokeReason *string
	if row.revokeReason != "" {
		value := row.revokeReason
		revokeReason = &value
	}
	switch state {
	case authorization.AuthorizationEdgeStateActive:
		if revokedAt != nil || revokedBy != nil || revokeReason != nil {
			return mappedAuthorizationEdge{}, errors.New("database returned revocation metadata for an active authorization edge")
		}
	case authorization.AuthorizationEdgeStateExpired:
		if expiresAt == nil || revokedAt != nil || revokedBy != nil || revokeReason != nil {
			return mappedAuthorizationEdge{}, errors.New("database returned invalid expired authorization edge metadata")
		}
	case authorization.AuthorizationEdgeStateRevoked:
		if revokedAt == nil || revokedBy == nil || revokeReason == nil {
			return mappedAuthorizationEdge{}, errors.New("database returned incomplete authorization edge revocation metadata")
		}
	}
	return mappedAuthorizationEdge{
		provenance: authorization.AuthorizationEdgeProvenance{
			SourceKind: sourceKind, SourceID: sourceID, Authoritative: row.sourceAuthoritative,
			RetiredAt: retiredAt, GrantedByUserID: grantedBy, GrantedAt: grantedAt,
			Reason: row.grantReason, ExpiresAt: expiresAt,
		},
		managedByAuthorizationAPI: row.managedByAuthorizationAPI,
		state:                     state, revokedAt: revokedAt, revokedByUserID: revokedBy,
		revokeReason: revokeReason, version: int64(row.version), updatedAt: updatedAt,
	}, nil
}

func domainAuthorizationEdgeState(value string) (authorization.AuthorizationEdgeState, error) {
	state := authorization.AuthorizationEdgeState(value)
	switch state {
	case authorization.AuthorizationEdgeStateActive,
		authorization.AuthorizationEdgeStateExpired,
		authorization.AuthorizationEdgeStateRevoked:
		return state, nil
	default:
		return "", fmt.Errorf("database returned unknown authorization edge state %q", value)
	}
}

type authorizationSecurityGroupMembershipRow struct {
	edgeID                      pgtype.UUID
	group                       authorizationSecurityGroupRow
	membershipID                pgtype.UUID
	targetUserID                pgtype.UUID
	email                       string
	displayName                 string
	membershipStatus            string
	compatibilityRole           string
	userActive                  bool
	membershipCreatedAt         pgtype.Timestamptz
	membershipUpdatedAt         pgtype.Timestamptz
	membershipLifecycleRevision int32
	authorizationEdgeRow        authorizationEdgeRow
}

func mapAuthorizationSecurityGroupMembership(
	tenantID uuid.UUID,
	expectedGroupID uuid.UUID,
	row authorizationSecurityGroupMembershipRow,
) (authorization.TenantSecurityGroupMembership, error) {
	edgeID, err := domainUUID(row.edgeID)
	if err != nil || !authorizationUUIDv7(edgeID) {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned an invalid security group membership ID")
	}
	group, err := mapAuthorizationSecurityGroup(tenantID, row.group)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	if group.ID != expectedGroupID {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned a security group membership for an unexpected group")
	}
	membershipID, err := domainUUID(row.membershipID)
	if err != nil || !authorizationUUIDv7(membershipID) {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned an invalid target tenant membership ID")
	}
	userID, err := domainUUID(row.targetUserID)
	if err != nil || !authorizationUUIDv7(userID) {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned an invalid security group member user ID")
	}
	membershipStatus, err := domainMembershipStatus(row.membershipStatus)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	compatibilityRole, err := domainLegacyMembershipRole(row.compatibilityRole)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	membershipCreatedAt, err := domainTime(row.membershipCreatedAt)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	membershipUpdatedAt, err := domainTime(row.membershipUpdatedAt)
	if err != nil || membershipUpdatedAt.Before(membershipCreatedAt) {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned invalid target tenant membership timestamps")
	}
	membershipEntityTag, err := authorization.TenantMembershipLifecycleEntityTag(int64(row.membershipLifecycleRevision))
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	edge, err := mapAuthorizationEdge(row.authorizationEdgeRow)
	if err != nil {
		return authorization.TenantSecurityGroupMembership{}, err
	}
	return authorization.TenantSecurityGroupMembership{
		ID: edgeID, TenantID: tenantID, Group: group,
		Member: authorization.TenantUserSummary{
			TenantID: tenantID, MembershipID: membershipID,
			User: authorization.TenantUserProfile{
				ID: userID, Email: row.email, DisplayName: row.displayName, Active: row.userActive,
			},
			MembershipStatus: membershipStatus, LegacyMembershipRole: compatibilityRole,
			LifecycleRevision: int64(row.membershipLifecycleRevision), EntityTag: membershipEntityTag,
			CreatedAt: membershipCreatedAt, UpdatedAt: membershipUpdatedAt,
		},
		Provenance: edge.provenance, State: edge.state, RevokedAt: edge.revokedAt,
		RevokedByUserID: edge.revokedByUserID, RevokeReason: edge.revokeReason,
		Version: edge.version, UpdatedAt: edge.updatedAt,
		ManagedByAuthorizationAPI: edge.managedByAuthorizationAPI,
	}, nil
}

type authorizationSecurityGroupRoleGrantRow struct {
	edgeID               pgtype.UUID
	group                authorizationSecurityGroupRow
	roleID               pgtype.UUID
	roleKey              string
	roleName             string
	roleDescription      string
	roleSystem           bool
	roleProtected        bool
	roleArchivedAt       pgtype.Timestamptz
	roleVersion          int32
	roleCreatedAt        pgtype.Timestamptz
	roleUpdatedAt        pgtype.Timestamptz
	authorizationEdgeRow authorizationEdgeRow
}

func mapAuthorizationSecurityGroupRoleGrant(
	tenantID uuid.UUID,
	expectedGroupID uuid.UUID,
	row authorizationSecurityGroupRoleGrantRow,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	edgeID, err := domainUUID(row.edgeID)
	if err != nil || !authorizationUUIDv7(edgeID) {
		return authorization.TenantSecurityGroupRoleGrant{}, errors.New("database returned an invalid security group role-grant ID")
	}
	group, err := mapAuthorizationSecurityGroup(tenantID, row.group)
	if err != nil {
		return authorization.TenantSecurityGroupRoleGrant{}, err
	}
	if group.ID != expectedGroupID {
		return authorization.TenantSecurityGroupRoleGrant{}, errors.New("database returned a role grant for an unexpected security group")
	}
	role, err := mapAuthorizationRoleSummary(
		tenantID, row.roleID, row.roleKey, row.roleName, row.roleDescription,
		string(authorization.PrincipalKindHuman), row.roleSystem, row.roleProtected, row.roleVersion, row.roleArchivedAt,
		row.roleCreatedAt, row.roleUpdatedAt,
	)
	if err != nil {
		return authorization.TenantSecurityGroupRoleGrant{}, err
	}
	edge, err := mapAuthorizationEdge(row.authorizationEdgeRow)
	if err != nil {
		return authorization.TenantSecurityGroupRoleGrant{}, err
	}
	return authorization.TenantSecurityGroupRoleGrant{
		ID: edgeID, TenantID: tenantID, Group: group, Role: role,
		Provenance: edge.provenance, State: edge.state, RevokedAt: edge.revokedAt,
		RevokedByUserID: edge.revokedByUserID, RevokeReason: edge.revokeReason,
		Version: edge.version, UpdatedAt: edge.updatedAt,
		ManagedByAuthorizationAPI: edge.managedByAuthorizationAPI,
	}, nil
}

func domainMembershipStatus(value string) (authorization.MembershipStatus, error) {
	status := authorization.MembershipStatus(value)
	switch status {
	case authorization.MembershipStatusInvited,
		authorization.MembershipStatusActive,
		authorization.MembershipStatusSuspended:
		return status, nil
	default:
		return "", fmt.Errorf("database returned unknown tenant membership status %q", value)
	}
}

func domainLegacyMembershipRole(value string) (authorization.LegacyMembershipRole, error) {
	role := authorization.LegacyMembershipRole(value)
	switch role {
	case authorization.LegacyMembershipRoleTenantAdmin,
		authorization.LegacyMembershipRoleSOCManager,
		authorization.LegacyMembershipRoleSeniorAnalyst,
		authorization.LegacyMembershipRoleAnalyst,
		authorization.LegacyMembershipRoleCustomerManager,
		authorization.LegacyMembershipRoleCustomerUser,
		authorization.LegacyMembershipRoleReadOnly:
		return role, nil
	default:
		return "", fmt.Errorf("database returned unknown compatibility membership role %q", value)
	}
}

func mapListedAuthorizationSecurityGroup(
	tenantID uuid.UUID,
	row *dbsql.ListTenantAuthorizationSecurityGroupsRow,
) (authorization.TenantSecurityGroup, error) {
	if row == nil {
		return authorization.TenantSecurityGroup{}, errors.New("database returned a null tenant security group row")
	}
	return mapAuthorizationSecurityGroup(tenantID, authorizationSecurityGroupRow{
		groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
		groupDescription: row.GroupDescription, archivedAt: row.ArchivedAt,
		version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapGotAuthorizationSecurityGroup(
	tenantID uuid.UUID,
	row *dbsql.GetTenantAuthorizationSecurityGroupRow,
) (authorization.TenantSecurityGroup, error) {
	if row == nil {
		return authorization.TenantSecurityGroup{}, errors.New("database returned a null tenant security group")
	}
	return mapAuthorizationSecurityGroup(tenantID, authorizationSecurityGroupRow{
		groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
		groupDescription: row.GroupDescription, archivedAt: row.ArchivedAt,
		version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapListedAuthorizationSecurityGroupMembership(
	tenantID uuid.UUID,
	groupID uuid.UUID,
	row *dbsql.ListTenantAuthorizationSecurityGroupMembershipsRow,
) (authorization.TenantSecurityGroupMembership, error) {
	if row == nil {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned a null security group membership row")
	}
	return mapAuthorizationSecurityGroupMembership(
		tenantID,
		groupID,
		authorizationSecurityGroupMembershipRow{
			edgeID: row.GroupMembershipID,
			group: authorizationSecurityGroupRow{
				groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
				groupDescription: row.GroupDescription, archivedAt: row.GroupArchivedAt,
				version: row.GroupVersion, createdAt: row.GroupCreatedAt, updatedAt: row.GroupUpdatedAt,
			},
			membershipID: row.MembershipID, targetUserID: row.TargetUserID,
			email: row.Email, displayName: row.DisplayName,
			membershipStatus: row.MembershipStatus, compatibilityRole: row.CompatibilityRole,
			userActive: row.UserActive, membershipCreatedAt: row.MembershipCreatedAt,
			membershipUpdatedAt: row.MembershipUpdatedAt, membershipLifecycleRevision: row.MembershipLifecycleRevision,
			authorizationEdgeRow: authorizationEdgeRow{
				sourceID: row.SourceID, sourceKind: row.SourceKind,
				sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
				managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
				grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
				grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
				revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
				state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
			},
		},
	)
}

func mapGotAuthorizationSecurityGroupMembership(
	tenantID uuid.UUID,
	groupID uuid.UUID,
	row *dbsql.GetTenantAuthorizationSecurityGroupMembershipRow,
) (authorization.TenantSecurityGroupMembership, error) {
	if row == nil {
		return authorization.TenantSecurityGroupMembership{}, errors.New("database returned a null security group membership")
	}
	return mapAuthorizationSecurityGroupMembership(
		tenantID,
		groupID,
		authorizationSecurityGroupMembershipRow{
			edgeID: row.GroupMembershipID,
			group: authorizationSecurityGroupRow{
				groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
				groupDescription: row.GroupDescription, archivedAt: row.GroupArchivedAt,
				version: row.GroupVersion, createdAt: row.GroupCreatedAt, updatedAt: row.GroupUpdatedAt,
			},
			membershipID: row.MembershipID, targetUserID: row.TargetUserID,
			email: row.Email, displayName: row.DisplayName,
			membershipStatus: row.MembershipStatus, compatibilityRole: row.CompatibilityRole,
			userActive: row.UserActive, membershipCreatedAt: row.MembershipCreatedAt,
			membershipUpdatedAt: row.MembershipUpdatedAt, membershipLifecycleRevision: row.MembershipLifecycleRevision,
			authorizationEdgeRow: authorizationEdgeRow{
				sourceID: row.SourceID, sourceKind: row.SourceKind,
				sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
				managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
				grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
				grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
				revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
				state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
			},
		},
	)
}

func mapListedAuthorizationSecurityGroupRoleGrant(
	tenantID uuid.UUID,
	groupID uuid.UUID,
	row *dbsql.ListTenantAuthorizationSecurityGroupRoleGrantsRow,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	if row == nil {
		return authorization.TenantSecurityGroupRoleGrant{}, errors.New("database returned a null security group role-grant row")
	}
	return mapAuthorizationSecurityGroupRoleGrant(
		tenantID,
		groupID,
		authorizationSecurityGroupRoleGrantRow{
			edgeID: row.GroupRoleGrantID,
			group: authorizationSecurityGroupRow{
				groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
				groupDescription: row.GroupDescription, archivedAt: row.GroupArchivedAt,
				version: row.GroupVersion, createdAt: row.GroupCreatedAt, updatedAt: row.GroupUpdatedAt,
			},
			roleID: row.RoleID, roleKey: row.RoleKey, roleName: row.RoleName,
			roleDescription: row.RoleDescription, roleSystem: row.RoleSystem,
			roleProtected: row.RoleProtected, roleArchivedAt: row.RoleArchivedAt,
			roleVersion: row.RoleVersion, roleCreatedAt: row.RoleCreatedAt,
			roleUpdatedAt: row.RoleUpdatedAt,
			authorizationEdgeRow: authorizationEdgeRow{
				sourceID: row.SourceID, sourceKind: row.SourceKind,
				sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
				managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
				grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
				grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
				revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
				state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
			},
		},
	)
}

func mapGotAuthorizationSecurityGroupRoleGrant(
	tenantID uuid.UUID,
	groupID uuid.UUID,
	row *dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	if row == nil {
		return authorization.TenantSecurityGroupRoleGrant{}, errors.New("database returned a null security group role grant")
	}
	return mapAuthorizationSecurityGroupRoleGrant(
		tenantID,
		groupID,
		authorizationSecurityGroupRoleGrantRow{
			edgeID: row.GroupRoleGrantID,
			group: authorizationSecurityGroupRow{
				groupID: row.GroupID, groupKey: row.GroupKey, groupName: row.GroupName,
				groupDescription: row.GroupDescription, archivedAt: row.GroupArchivedAt,
				version: row.GroupVersion, createdAt: row.GroupCreatedAt, updatedAt: row.GroupUpdatedAt,
			},
			roleID: row.RoleID, roleKey: row.RoleKey, roleName: row.RoleName,
			roleDescription: row.RoleDescription, roleSystem: row.RoleSystem,
			roleProtected: row.RoleProtected, roleArchivedAt: row.RoleArchivedAt,
			roleVersion: row.RoleVersion, roleCreatedAt: row.RoleCreatedAt,
			roleUpdatedAt: row.RoleUpdatedAt,
			authorizationEdgeRow: authorizationEdgeRow{
				sourceID: row.SourceID, sourceKind: row.SourceKind,
				sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
				managedByAuthorizationAPI: row.ManagedByAuthorizationApi,
				grantedByUserID:           row.GrantedByUserID, grantReason: row.GrantReason,
				grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt, revokedAt: row.RevokedAt,
				revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
				state: row.GrantState, version: row.Version, updatedAt: row.UpdatedAt,
			},
		},
	)
}
