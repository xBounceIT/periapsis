package httpserver

import (
	"errors"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func mapTenantAuthority(value authorization.TenantAuthority) (contract.TenantAuthority, error) {
	status := contract.TenantAuthorityMembershipStatus(value.MembershipStatus)
	legacyRole := contract.LegacyTenantMembershipRole(value.LegacyRole)
	if !status.Valid() || !legacyRole.Valid() {
		return contract.TenantAuthority{}, errors.New("unsupported tenant authority membership")
	}
	roleGrants := make([]contract.EffectiveTenantRoleGrant, 0, len(value.RoleGrants))
	for _, grant := range value.RoleGrants {
		provenance, err := mapEffectiveRoleGrantProvenance(grant.Provenance)
		if err != nil {
			return contract.TenantAuthority{}, err
		}
		path, err := mapEffectiveTenantRoleAuthorityPath(grant.Path)
		if err != nil {
			return contract.TenantAuthority{}, err
		}
		roleGrants = append(roleGrants, contract.EffectiveTenantRoleGrant{
			GrantId: grant.GrantID, RoleId: grant.RoleID, RoleKey: grant.RoleKey,
			RoleName: grant.RoleName, Provenance: provenance, Path: path,
			EffectiveExpiresAt: grant.EffectiveExpiresAt,
		})
	}
	permissions, err := mapScopedPermissions(value.Permissions)
	if err != nil {
		return contract.TenantAuthority{}, err
	}
	ceiling := make([]contract.EffectiveTenantDelegation, 0, len(value.DelegationCeiling))
	for _, delegation := range value.DelegationCeiling {
		permission, err := mapScopedPermission(delegation.ScopedPermission)
		if err != nil {
			return contract.TenantAuthority{}, err
		}
		ceiling = append(ceiling, contract.EffectiveTenantDelegation{
			PermissionKey: permission.PermissionKey, Scope: permission.Scope,
			DelegableUntil: delegation.ExpiresAt,
		})
	}
	operatorTeamRelationships := make(
		[]contract.TenantOperatorTeamRelationship,
		0,
		len(value.OperatorTeamRelationships),
	)
	for _, relationship := range value.OperatorTeamRelationships {
		operatorTeamRelationships = append(
			operatorTeamRelationships,
			contract.TenantOperatorTeamRelationship{
				OperatorTeamId:    relationship.OperatorTeamID,
				AssignmentEpochId: relationship.AssignmentEpochID,
			},
		)
	}
	return contract.TenantAuthority{
		TenantId: value.TenantID, UserId: value.Principal.ID,
		MembershipId: value.MembershipID, MembershipStatus: status,
		LegacyMembershipRole: legacyRole, RoleGrants: roleGrants,
		Permissions: permissions, DelegationCeiling: ceiling,
		OperatorTeamRelationships: operatorTeamRelationships,
		EvaluatedAt:               value.EvaluatedAt,
	}, nil
}

func mapTenantPermission(value authorization.TenantPermissionDefinition) (contract.TenantPermission, error) {
	key := contract.TenantPermissionKey(value.Key)
	if !key.Valid() {
		return contract.TenantPermission{}, errors.New("unsupported tenant permission")
	}
	scopes := make([]contract.TenantAuthorizationScope, 0, len(value.AllowedScopes))
	for _, valueScope := range value.AllowedScopes {
		scope := contract.TenantAuthorizationScope(valueScope)
		if !scope.Valid() {
			return contract.TenantPermission{}, errors.New("unsupported tenant authorization scope")
		}
		scopes = append(scopes, scope)
	}
	principalTypes := make([]contract.TenantPrincipalType, 0, len(value.PrincipalKinds))
	for _, valueKind := range value.PrincipalKinds {
		principalType := contract.TenantPrincipalType(valueKind)
		if !principalType.Valid() {
			return contract.TenantPermission{}, errors.New("unsupported tenant principal type")
		}
		principalTypes = append(principalTypes, principalType)
	}
	return contract.TenantPermission{
		Id: value.ID, Key: key, Name: value.Name, Description: value.Description,
		AllowedScopes: scopes, PrincipalTypes: principalTypes,
	}, nil
}

func mapTenantRoleSummary(value authorization.TenantRoleSummary) contract.TenantRoleSummary {
	var description *string
	if value.Description != "" {
		descriptionValue := value.Description
		description = &descriptionValue
	}
	return contract.TenantRoleSummary{
		Id: value.ID, TenantId: value.TenantID, Key: value.Key, Name: value.Name,
		PrincipalKind: contract.TenantPrincipalType(value.PrincipalKind),
		Description:   description, System: value.System, Archived: value.Archived,
		ArchivedAt: value.ArchivedAt, Version: value.Version,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func mapTenantRole(value authorization.TenantRole) (contract.TenantRole, error) {
	policy, err := mapTenantRolePolicy(value.Policy)
	if err != nil {
		return contract.TenantRole{}, err
	}
	summary := mapTenantRoleSummary(value.TenantRoleSummary)
	return contract.TenantRole{
		Id: summary.Id, TenantId: summary.TenantId, Key: summary.Key,
		Name: summary.Name, Description: summary.Description, System: summary.System,
		PrincipalKind: summary.PrincipalKind,
		Archived:      summary.Archived, ArchivedAt: summary.ArchivedAt,
		Version: summary.Version, CreatedAt: summary.CreatedAt,
		UpdatedAt: summary.UpdatedAt, Policy: policy,
	}, nil
}

func mapTenantRolePolicy(value authorization.TenantRolePolicy) (contract.TenantRoleReadPolicy, error) {
	permissions, err := mapScopedPermissions(value.Permissions)
	if err != nil {
		return contract.TenantRoleReadPolicy{}, err
	}
	ceiling, err := mapScopedPermissions(value.DelegationCeiling)
	if err != nil {
		return contract.TenantRoleReadPolicy{}, err
	}
	return contract.TenantRoleReadPolicy{Permissions: permissions, DelegationCeiling: ceiling}, nil
}

func mapScopedPermissions(values []authorization.ScopedPermission) ([]contract.TenantPermissionGrant, error) {
	mapped := make([]contract.TenantPermissionGrant, 0, len(values))
	for _, value := range values {
		permission, err := mapScopedPermission(value)
		if err != nil {
			return nil, err
		}
		mapped = append(mapped, permission)
	}
	return mapped, nil
}

func mapScopedPermission(value authorization.ScopedPermission) (contract.TenantPermissionGrant, error) {
	key := contract.TenantPermissionKey(value.Permission)
	scope := contract.TenantAuthorizationScope(value.Scope)
	if !key.Valid() || !scope.Valid() {
		return contract.TenantPermissionGrant{}, errors.New("unsupported scoped tenant permission")
	}
	return contract.TenantPermissionGrant{PermissionKey: key, Scope: scope}, nil
}

func tenantRolePolicyInput(value contract.TenantRolePolicy) (authorization.TenantRolePolicy, error) {
	permissions, err := scopedPermissionInputs(value.Permissions)
	if err != nil {
		return authorization.TenantRolePolicy{}, err
	}
	ceiling, err := scopedPermissionInputs(value.DelegationCeiling)
	if err != nil {
		return authorization.TenantRolePolicy{}, err
	}
	return authorization.TenantRolePolicy{Permissions: permissions, DelegationCeiling: ceiling}, nil
}

func scopedPermissionInputs(values []contract.TenantPermissionGrant) ([]authorization.ScopedPermission, error) {
	mapped := make([]authorization.ScopedPermission, 0, len(values))
	for _, value := range values {
		if !value.PermissionKey.Valid() || !value.Scope.Valid() {
			return nil, errors.New("unsupported scoped tenant permission")
		}
		mapped = append(mapped, authorization.ScopedPermission{
			Permission: authorization.TenantPermission(value.PermissionKey),
			Scope:      authorization.Scope(value.Scope),
		})
	}
	return mapped, nil
}

func mapTenantUser(value authorization.TenantUserSummary) (contract.TenantUserSummary, error) {
	status := contract.TenantUserSummaryMembershipStatus(value.MembershipStatus)
	legacyRole := contract.LegacyTenantMembershipRole(value.LegacyMembershipRole)
	if !status.Valid() || !legacyRole.Valid() {
		return contract.TenantUserSummary{}, errors.New("unsupported tenant user membership")
	}
	return contract.TenantUserSummary{
		TenantId: value.TenantID, MembershipId: value.MembershipID,
		MembershipStatus: status, LegacyMembershipRole: legacyRole,
		User: contract.TenantUserProfile{
			Id: value.User.ID, Email: openapi_types.Email(value.User.Email),
			DisplayName: value.User.DisplayName, Active: value.User.Active,
		},
		LifecycleRevision: value.LifecycleRevision,
		Etag:              contract.StrongEntityTag(value.EntityTag),
		CreatedAt:         value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapTenantMembershipLifecycleReceipt(
	value authorization.TenantMembershipLifecycleReceipt,
) (contract.TenantMembershipLifecycleReceipt, error) {
	previous := contract.TenantMembershipLifecycleReceiptPreviousStatus(value.PreviousStatus)
	status := contract.TenantMembershipLifecycleReceiptStatus(value.Status)
	expectedTag, err := authorization.TenantMembershipLifecycleEntityTag(value.LifecycleRevision)
	if err != nil || !previous.Valid() || !status.Valid() || value.EntityTag != expectedTag ||
		previous == contract.TenantMembershipLifecycleReceiptPreviousStatusActive &&
			status != contract.TenantMembershipLifecycleReceiptStatusSuspended ||
		previous == contract.TenantMembershipLifecycleReceiptPreviousStatusSuspended &&
			status != contract.TenantMembershipLifecycleReceiptStatusActive {
		return contract.TenantMembershipLifecycleReceipt{}, errors.New("invalid tenant membership lifecycle receipt")
	}
	return contract.TenantMembershipLifecycleReceipt{
		TenantId: value.TenantID, MembershipId: value.MembershipID, UserId: value.UserID,
		PreviousStatus: previous, Status: status,
		LifecycleRevision: value.LifecycleRevision,
		Etag:              contract.StrongEntityTag(value.EntityTag), UpdatedAt: value.UpdatedAt,
		RevokedSessionCount:      int(value.RevokedSessionCount),
		RevokedContinuationCount: int(value.RevokedContinuationCount),
		Replayed:                 value.Replayed,
	}, nil
}

func mapDirectRoleGrant(value authorization.DirectUserRoleGrant) (contract.DirectUserRoleGrant, error) {
	state := contract.DirectRoleGrantState(value.State)
	if !state.Valid() {
		return contract.DirectUserRoleGrant{}, errors.New("unsupported direct role grant state")
	}
	if !validDirectRoleGrantLifecycle(value) {
		return contract.DirectUserRoleGrant{}, errors.New("invalid direct role grant revocation lifecycle")
	}
	provenance, err := mapRoleGrantProvenance(value.Provenance)
	if err != nil {
		return contract.DirectUserRoleGrant{}, err
	}
	entityTag, err := authorization.DirectUserRoleGrantEntityTag(value)
	if err != nil {
		return contract.DirectUserRoleGrant{}, err
	}
	return contract.DirectUserRoleGrant{
		Id: value.ID, TenantId: value.TenantID, UserId: value.UserID, Etag: entityTag,
		Role: mapTenantRoleSummary(value.Role), Provenance: provenance,
		ManagedByAuthorizationApi: authorizationAPIOwnershipPointer(value.ManagedByAuthorizationAPI),
		PathType:                  contract.DirectUserRoleGrantPathTypeDirect,
		State:                     state, RevokedAt: value.RevokedAt,
		RevokedByUserId: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version:   value.Version,
		UpdatedAt: value.UpdatedAt,
	}, nil
}

func authorizationAPIOwnershipPointer(value bool) *bool {
	return &value
}

func validDirectRoleGrantLifecycle(value authorization.DirectUserRoleGrant) bool {
	switch value.State {
	case authorization.DirectRoleGrantStateActive:
		return value.RevokedAt == nil && value.RevokedByUserID == nil && value.RevokeReason == nil
	case authorization.DirectRoleGrantStateExpired:
		return value.Provenance.ExpiresAt != nil && value.RevokedAt == nil &&
			value.RevokedByUserID == nil && value.RevokeReason == nil
	case authorization.DirectRoleGrantStateRevoked:
		return value.RevokedAt != nil && value.RevokedByUserID != nil && value.RevokeReason != nil
	default:
		return false
	}
}

func mapRoleGrantProvenance(value authorization.RoleGrantProvenance) (contract.RoleGrantProvenance, error) {
	sourceType := contract.RoleGrantSourceType(value.SourceType)
	sourceKind := contract.AuthorizationSourceKind(value.SourceKind)
	if !sourceType.Valid() || !sourceKind.Valid() || value.SourceID == nil {
		return contract.RoleGrantProvenance{}, errors.New("unsupported role grant source")
	}
	return contract.RoleGrantProvenance{
		SourceType: sourceType, SourceKind: sourceKind, SourceId: *value.SourceID,
		Authoritative: value.Authoritative, RetiredAt: value.RetiredAt,
		GrantedByUserId: value.GrantedByUserID, GrantedAt: value.GrantedAt,
		Reason: value.Reason, ExpiresAt: value.ExpiresAt,
	}, nil
}

func mapEffectiveRoleGrantProvenance(
	value authorization.RoleGrantProvenance,
) (contract.EffectiveRoleGrantProvenance, error) {
	mapped, err := mapRoleGrantProvenance(value)
	if err != nil {
		return contract.EffectiveRoleGrantProvenance{}, err
	}
	if mapped.RetiredAt != nil {
		return contract.EffectiveRoleGrantProvenance{}, errors.New("retired source cannot contribute live role authority")
	}
	return contract.EffectiveRoleGrantProvenance{
		SourceType: mapped.SourceType, SourceKind: mapped.SourceKind, SourceId: mapped.SourceId,
		Authoritative: mapped.Authoritative, GrantedByUserId: mapped.GrantedByUserId,
		GrantedAt: mapped.GrantedAt, Reason: mapped.Reason, ExpiresAt: mapped.ExpiresAt,
	}, nil
}

func mapEffectiveTenantRoleAuthorityPath(
	value authorization.EffectiveTenantRoleAuthorityPath,
) (contract.EffectiveTenantRoleAuthorityPath, error) {
	var mapped contract.EffectiveTenantRoleAuthorityPath
	switch value.PathType {
	case authorization.RoleGrantPathDirect:
		if value.Direct == nil || value.Group != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, errors.New("invalid direct authority path")
		}
		provenance, err := mapEffectiveRoleGrantProvenance(value.Direct.Provenance)
		if err != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, err
		}
		if err := mapped.FromDirectEffectiveTenantRoleAuthorityPath(
			contract.DirectEffectiveTenantRoleAuthorityPath{
				PathType: contract.DirectEffectiveTenantRoleAuthorityPathPathTypeDirect,
				Direct: contract.DirectTenantRoleAuthorityPath{
					GrantId: value.Direct.GrantID, Provenance: provenance,
				},
			},
		); err != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, err
		}
	case authorization.RoleGrantPathGroup:
		if value.Direct != nil || value.Group == nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, errors.New("invalid group authority path")
		}
		membership, err := mapEffectiveAuthorizationEdgeProvenance(value.Group.MembershipEdge.Provenance)
		if err != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, err
		}
		roleGrant, err := mapEffectiveAuthorizationEdgeProvenance(value.Group.RoleGrantEdge.Provenance)
		if err != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, err
		}
		if err := mapped.FromGroupEffectiveTenantRoleAuthorityPath(
			contract.GroupEffectiveTenantRoleAuthorityPath{
				PathType: contract.GroupEffectiveTenantRoleAuthorityPathPathTypeGroup,
				Group: contract.GroupTenantRoleAuthorityPath{
					Group: contract.TenantSecurityGroupAuthoritySummary{
						Id: value.Group.Group.ID, Key: value.Group.Group.Key, Name: value.Group.Group.Name,
					},
					MembershipEdge: contract.TenantSecurityGroupMembershipPathEdge{
						Id: value.Group.MembershipEdge.ID, Provenance: membership,
					},
					RoleGrantEdge: contract.TenantSecurityGroupRoleGrantPathEdge{
						Id: value.Group.RoleGrantEdge.ID, Provenance: roleGrant,
					},
				},
			},
		); err != nil {
			return contract.EffectiveTenantRoleAuthorityPath{}, err
		}
	default:
		return contract.EffectiveTenantRoleAuthorityPath{}, errors.New("unsupported authority path")
	}
	return mapped, nil
}

func mapAuthorizationEdgeProvenance(
	value authorization.AuthorizationEdgeProvenance,
) (contract.AuthorizationEdgeProvenance, error) {
	sourceKind := contract.AuthorizationSourceKind(value.SourceKind)
	if !sourceKind.Valid() || value.SourceID == nil {
		return contract.AuthorizationEdgeProvenance{}, errors.New("unsupported authorization source")
	}
	return contract.AuthorizationEdgeProvenance{
		SourceKind: sourceKind, SourceId: *value.SourceID,
		Authoritative: value.Authoritative, RetiredAt: value.RetiredAt,
		GrantedByUserId: value.GrantedByUserID, GrantedAt: value.GrantedAt,
		Reason: value.Reason, ExpiresAt: value.ExpiresAt,
	}, nil
}

func mapEffectiveAuthorizationEdgeProvenance(
	value authorization.AuthorizationEdgeProvenance,
) (contract.EffectiveAuthorizationEdgeProvenance, error) {
	mapped, err := mapAuthorizationEdgeProvenance(value)
	if err != nil {
		return contract.EffectiveAuthorizationEdgeProvenance{}, err
	}
	if mapped.RetiredAt != nil {
		return contract.EffectiveAuthorizationEdgeProvenance{}, errors.New("retired source cannot contribute live edge authority")
	}
	return contract.EffectiveAuthorizationEdgeProvenance{
		SourceKind: mapped.SourceKind, SourceId: mapped.SourceId,
		Authoritative: mapped.Authoritative, GrantedByUserId: mapped.GrantedByUserId,
		GrantedAt: mapped.GrantedAt, Reason: mapped.Reason, ExpiresAt: mapped.ExpiresAt,
	}, nil
}
