// Package authorization provides the central deny-by-default policy evaluator.
package authorization

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Permission is a stable backend authorization key.
type Permission string

const (
	PermissionPlatformTenantRead             Permission = "platform.tenant.read"
	PermissionPlatformTenantCreate           Permission = "platform.tenant.create"
	PermissionPlatformTenantManage           Permission = "platform.tenant.manage"
	PermissionPlatformTenantAccess           Permission = "platform.tenant.access"
	PermissionPlatformOperatorTeamRead       Permission = "platform.operator_team.read"
	PermissionPlatformOperatorTeamManage     Permission = "platform.operator_team.manage"
	PermissionPlatformIdentityProviderRead   Permission = "platform.identity_provider.read"
	PermissionPlatformIdentityProviderManage Permission = "platform.identity_provider.manage"
	PermissionPlatformIdentityProviderTest   Permission = "platform.identity_provider.test"
	PermissionPlatformIdentityBindingRead    Permission = "platform.identity_binding.read"
	PermissionPlatformIdentityBindingManage  Permission = "platform.identity_binding.manage"
	PermissionPlatformIdentityPolicyRead     Permission = "platform.identity_policy.read"
	PermissionPlatformIdentityPolicyManage   Permission = "platform.identity_policy.manage"
	PermissionPlatformIdentityAccountRead    Permission = "platform.identity_account.read"
	PermissionPlatformIdentityAccountManage  Permission = "platform.identity_account.manage"
	PermissionPlatformNotificationManage     Permission = "platform.notification.manage"
	PermissionPlatformAuditRead              Permission = "platform.audit.read"
	PermissionPlatformAuditExport            Permission = "platform.audit.export"
	PermissionPlatformAuditRetentionManage   Permission = "platform.audit.retention.manage"
	PermissionPlatformUserRead               Permission = "platform.user.read"
	PermissionPlatformOperationsRead         Permission = "platform.operations.read"
	PermissionPlatformSettingsRead           Permission = "platform.settings.read"
	PermissionPlatformSettingsManage         Permission = "platform.settings.manage"
	PermissionPlatformFeatureFlagRead        Permission = "platform.feature_flag.read"
	PermissionPlatformFeatureFlagManage      Permission = "platform.feature_flag.manage"
)

var knownPermissions = map[Permission]struct{}{
	PermissionPlatformTenantRead:             {},
	PermissionPlatformTenantCreate:           {},
	PermissionPlatformTenantManage:           {},
	PermissionPlatformTenantAccess:           {},
	PermissionPlatformOperatorTeamRead:       {},
	PermissionPlatformOperatorTeamManage:     {},
	PermissionPlatformIdentityProviderRead:   {},
	PermissionPlatformIdentityProviderManage: {},
	PermissionPlatformIdentityProviderTest:   {},
	PermissionPlatformIdentityBindingRead:    {},
	PermissionPlatformIdentityBindingManage:  {},
	PermissionPlatformIdentityPolicyRead:     {},
	PermissionPlatformIdentityPolicyManage:   {},
	PermissionPlatformIdentityAccountRead:    {},
	PermissionPlatformIdentityAccountManage:  {},
	PermissionPlatformNotificationManage:     {},
	PermissionPlatformAuditRead:              {},
	PermissionPlatformAuditExport:            {},
	PermissionPlatformAuditRetentionManage:   {},
	PermissionPlatformUserRead:               {},
	PermissionPlatformOperationsRead:         {},
	PermissionPlatformSettingsRead:           {},
	PermissionPlatformSettingsManage:         {},
	PermissionPlatformFeatureFlagRead:        {},
	PermissionPlatformFeatureFlagManage:      {},
}

// ErrDenied is returned for missing and unknown authority alike.
var ErrDenied = errors.New("authorization denied")

// Evaluator checks live server-side grants and denies unknown permissions.
// Its zero value uses the built-in permission catalog.
type Evaluator struct {
	tenantPermissions map[TenantPermission]tenantPermissionMetadata
}

// Require returns nil only when the requested permission is known and explicitly granted.
func (Evaluator) Require(grants []Permission, requested Permission) error {
	if _, known := knownPermissions[requested]; !known {
		return ErrDenied
	}
	for _, grant := range grants {
		if grant == requested {
			return nil
		}
	}
	return ErrDenied
}

type tenantPermissionMetadata struct {
	principalKinds map[PrincipalKind]struct{}
	scopes         map[Scope]struct{}
}

var tenantAdministrativePermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeTenant),
}

var tenantOperatorTeamReadPermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeTenant, ScopeOperatorTeam),
}

var tenantOperatorTeamRosterPermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeTenant, ScopeOperatorTeam),
}

var tenantAlertCreatePermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman, PrincipalKindServiceAccount),
	scopes:         setOf(ScopeTenant),
}

var tenantTicketReadPermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes: setOf(
		ScopeOwn, ScopeAssigned, ScopeOperatorTeam, ScopeTenant,
	),
}

var tenantTicketOperatorMutationPermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeAssigned, ScopeOperatorTeam, ScopeTenant),
}

var tenantTicketOverridePermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes: setOf(
		ScopeOwn, ScopeAssigned, ScopeOperatorTeam, ScopeTenant,
	),
}

var tenantCaseCreatePermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeTenant),
}

var tenantPortalPermission = tenantPermissionMetadata{
	principalKinds: setOf(PrincipalKindHuman),
	scopes:         setOf(ScopeOwn),
}

var initialTenantPermissions = map[TenantPermission]tenantPermissionMetadata{
	TenantPermissionPermissionRead:                 tenantAdministrativePermission,
	TenantPermissionRoleRead:                       tenantAdministrativePermission,
	TenantPermissionRoleManage:                     tenantAdministrativePermission,
	TenantPermissionRoleGrant:                      tenantAdministrativePermission,
	TenantPermissionUserRead:                       tenantAdministrativePermission,
	TenantPermissionMembershipManage:               tenantAdministrativePermission,
	TenantPermissionGroupRead:                      tenantAdministrativePermission,
	TenantPermissionGroupManage:                    tenantAdministrativePermission,
	TenantPermissionGroupMembershipManage:          tenantAdministrativePermission,
	TenantPermissionOperatorTeamRead:               tenantOperatorTeamReadPermission,
	TenantPermissionOperatorTeamManage:             tenantAdministrativePermission,
	TenantPermissionOperatorTeamRosterManage:       tenantOperatorTeamRosterPermission,
	TenantPermissionServiceAccountRead:             tenantAdministrativePermission,
	TenantPermissionServiceAccountManage:           tenantAdministrativePermission,
	TenantPermissionServiceAccountCredentialManage: tenantAdministrativePermission,
	TenantPermissionAlertCreate:                    tenantAlertCreatePermission,
	TenantPermissionAlertRead:                      tenantTicketReadPermission,
	TenantPermissionAlertActivityRead:              tenantTicketReadPermission,
	TenantPermissionAlertCommentRead:               tenantTicketReadPermission,
	TenantPermissionAlertLinkRead:                  tenantTicketReadPermission,
	TenantPermissionAlertUpdate:                    tenantTicketReadPermission,
	TenantPermissionAlertDelete:                    tenantTicketOperatorMutationPermission,
	TenantPermissionAlertAssign:                    tenantTicketOperatorMutationPermission,
	TenantPermissionAlertClaim:                     tenantTicketReadPermission,
	TenantPermissionAlertEscalate:                  tenantTicketOperatorMutationPermission,
	TenantPermissionAlertCommentPublic:             tenantTicketReadPermission,
	TenantPermissionAlertCommentPrivate:            tenantTicketOperatorMutationPermission,
	TenantPermissionCaseRead:                       tenantTicketReadPermission,
	TenantPermissionCaseActivityRead:               tenantTicketReadPermission,
	TenantPermissionCaseCommentRead:                tenantTicketReadPermission,
	TenantPermissionCaseLinkRead:                   tenantTicketReadPermission,
	TenantPermissionCaseCreate:                     tenantCaseCreatePermission,
	TenantPermissionCaseUpdate:                     tenantTicketOperatorMutationPermission,
	TenantPermissionCaseClaim:                      tenantTicketReadPermission,
	TenantPermissionCaseTransfer:                   tenantTicketOperatorMutationPermission,
	TenantPermissionCaseTransition:                 tenantTicketOperatorMutationPermission,
	TenantPermissionCaseCommentPublic:              tenantTicketReadPermission,
	TenantPermissionCaseCommentPrivate:             tenantTicketOperatorMutationPermission,
	TenantPermissionIdentityProviderRead:           tenantAdministrativePermission,
	TenantPermissionIdentityProviderManage:         tenantAdministrativePermission,
	TenantPermissionIdentityProviderTest:           tenantAdministrativePermission,
	TenantPermissionIdentityMappingRead:            tenantAdministrativePermission,
	TenantPermissionIdentityMappingManage:          tenantAdministrativePermission,
	TenantPermissionIdentitySyncRun:                tenantAdministrativePermission,
	TenantPermissionIdentityPolicyRead:             tenantAdministrativePermission,
	TenantPermissionIdentityPolicyManage:           tenantAdministrativePermission,
	TenantPermissionSettingsRead:                   tenantAdministrativePermission,
	TenantPermissionSettingsManage:                 tenantAdministrativePermission,
	TenantPermissionNotificationManage:             tenantAdministrativePermission,
	TenantPermissionAuditRead:                      tenantAdministrativePermission,
	TenantPermissionAuditExport:                    tenantAdministrativePermission,
	TenantPermissionAuditRetentionManage:           tenantAdministrativePermission,
	TenantPermissionSLARead:                        tenantAdministrativePermission,
	TenantPermissionSLAManage:                      tenantAdministrativePermission,
	TenantPermissionSLASimulate:                    tenantAdministrativePermission,
	TenantPermissionWorkflowRead:                   tenantAdministrativePermission,
	TenantPermissionWorkflowManage:                 tenantAdministrativePermission,
	TenantPermissionAlertSLAOverride:               tenantTicketOverridePermission,
	TenantPermissionCaseSLAOverride:                tenantTicketOverridePermission,
	TenantPermissionContactRead:                    tenantAdministrativePermission,
	TenantPermissionContactManage:                  tenantAdministrativePermission,
	TenantPermissionContactPreferenceManage:        tenantAdministrativePermission,
	TenantPermissionContactGroupRead:               tenantAdministrativePermission,
	TenantPermissionContactGroupManage:             tenantAdministrativePermission,
	TenantPermissionPortalAlertRead:                tenantPortalPermission,
	TenantPermissionPortalCaseRead:                 tenantPortalPermission,
	TenantPermissionPortalCommentPublic:            tenantPortalPermission,
	TenantPermissionPortalAttachmentRead:           tenantPortalPermission,
	TenantPermissionPortalContactPreferenceManage:  tenantPortalPermission,
	TenantPermissionCustomFieldRead:                tenantAdministrativePermission,
	TenantPermissionCustomFieldManage:              tenantAdministrativePermission,
	TenantPermissionDFIRIOCRead:                    tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRIOCManage:                  tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRAssetRead:                  tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRAssetManage:                tenantTicketOperatorMutationPermission,
	TenantPermissionDFIREvidenceRead:               tenantTicketOperatorMutationPermission,
	TenantPermissionDFIREvidenceManage:             tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRTimelineRead:               tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRTimelineManage:             tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRTaskRead:                   tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRTaskManage:                 tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRAttachmentRead:             tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRAttachmentManage:           tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRRelationshipRead:           tenantTicketOperatorMutationPermission,
	TenantPermissionDFIRRelationshipManage:         tenantTicketOperatorMutationPermission,
}

// RequireTenant returns nil only when a live tenant authority contains an
// explicit, known permission whose scope covers the server-resolved resource.
// Human authority is valid only for an active, server-resolved membership.
// Tenant evaluation never accepts or derives platform scope.
func (e Evaluator) RequireTenant(
	authority TenantAuthority,
	requested TenantPermission,
	resource ResourceContext,
) error {
	if !e.validTenantAuthority(authority) || !validResourceContext(resource) ||
		authority.TenantID != resource.TenantID {
		return ErrDenied
	}
	metadata, known := e.tenantPermissionMetadata(requested)
	if !known || !contains(metadata.principalKinds, authority.Principal.Kind) {
		return ErrDenied
	}

	for _, grant := range authority.Permissions {
		if grant.Permission != requested {
			continue
		}
		if scopeCovers(authority, grant.Scope, resource) {
			return nil
		}
	}
	return ErrDenied
}

// RequireDelegablePolicy verifies that every tuple in a role policy appears
// exactly in the principal's currently live delegation ceiling. Role policies
// do not have a lifetime, so a temporary ceiling may define an exact tuple.
func (e Evaluator) RequireDelegablePolicy(
	authority TenantAuthority,
	requested []ScopedPermission,
	now time.Time,
) error {
	if !e.validDelegatingAuthority(authority, now) {
		return ErrDenied
	}

	for _, permission := range requested {
		if !e.validScopedPermission(permission, authority.Principal.Kind) ||
			!hasLiveExactCeiling(authority.DelegationCeiling, permission, now) {
			return ErrDenied
		}
	}
	return nil
}

// RequireDelegation verifies an actual role grant. Every requested tuple must
// appear exactly in the principal's active delegation ceiling, and one matching
// ceiling must cover the requested grant lifetime. A tenant-scoped ceiling does
// not imply any leaf scope, and a temporary ceiling cannot create a longer-lived
// or non-expiring grant.
func (e Evaluator) RequireDelegation(
	authority TenantAuthority,
	requested []DelegationRequest,
	now time.Time,
) error {
	if !e.validDelegatingAuthority(authority, now) {
		return ErrDenied
	}

	for _, request := range requested {
		if !e.validScopedPermission(request.ScopedPermission, authority.Principal.Kind) ||
			request.ExpiresAt != nil && !request.ExpiresAt.After(now) {
			return ErrDenied
		}

		covered := false
		for _, ceiling := range authority.DelegationCeiling {
			if !isLiveExactCeiling(ceiling, request.ScopedPermission, now) {
				continue
			}
			if delegationLifetimeCovered(ceiling.ExpiresAt, request.ExpiresAt) {
				covered = true
				break
			}
		}
		if !covered {
			return ErrDenied
		}
	}
	return nil
}

func (e Evaluator) validDelegatingAuthority(authority TenantAuthority, now time.Time) bool {
	return !now.IsZero() && e.validTenantAuthority(authority) &&
		authority.Principal.Kind == PrincipalKindHuman
}

func (e Evaluator) validTenantAuthority(authority TenantAuthority) bool {
	if authority.TenantID == uuid.Nil || !validUUIDv7(authority.Principal.ID) ||
		!knownPrincipalKind(authority.Principal.Kind) || authority.EvaluatedAt.IsZero() {
		return false
	}
	switch authority.Principal.Kind {
	case PrincipalKindHuman:
		if !validUUIDv7(authority.MembershipID) ||
			authority.MembershipStatus != MembershipStatusActive ||
			!knownLegacyMembershipRole(authority.LegacyRole) {
			return false
		}
	case PrincipalKindServiceAccount:
		if authority.MembershipID != uuid.Nil || authority.MembershipStatus != "" || authority.LegacyRole != "" {
			return false
		}
	}

	permissionSet := make(map[ScopedPermission]struct{}, len(authority.Permissions))
	for _, grant := range authority.Permissions {
		if !e.validScopedPermission(grant, authority.Principal.Kind) {
			return false
		}
		permissionSet[grant] = struct{}{}
	}
	for _, ceiling := range authority.DelegationCeiling {
		if !e.validScopedPermission(ceiling.ScopedPermission, authority.Principal.Kind) {
			return false
		}
		if _, backedByPermission := permissionSet[ceiling.ScopedPermission]; !backedByPermission {
			return false
		}
	}
	operatorTeams := make(map[uuid.UUID]struct{}, len(authority.OperatorTeamRelationships))
	assignmentEpochs := make(map[uuid.UUID]struct{}, len(authority.OperatorTeamRelationships))
	for _, relationship := range authority.OperatorTeamRelationships {
		if !validUUIDv7(relationship.OperatorTeamID) ||
			!validUUIDv7(relationship.AssignmentEpochID) {
			return false
		}
		if _, duplicate := operatorTeams[relationship.OperatorTeamID]; duplicate {
			return false
		}
		if _, duplicate := assignmentEpochs[relationship.AssignmentEpochID]; duplicate {
			return false
		}
		operatorTeams[relationship.OperatorTeamID] = struct{}{}
		assignmentEpochs[relationship.AssignmentEpochID] = struct{}{}
	}
	return true
}

func (e Evaluator) validScopedPermission(grant ScopedPermission, principalKind PrincipalKind) bool {
	metadata, known := e.tenantPermissionMetadata(grant.Permission)
	if !known || !knownScope(grant.Scope) || grant.Scope == ScopePlatform ||
		!contains(metadata.scopes, grant.Scope) ||
		!contains(metadata.principalKinds, principalKind) {
		return false
	}
	return true
}

func validResourceContext(resource ResourceContext) bool {
	if resource.TenantID == uuid.Nil {
		return false
	}
	for _, relation := range []*uuid.UUID{
		resource.OwnerID,
		resource.AssigneeID,
	} {
		if relation != nil && *relation == uuid.Nil {
			return false
		}
	}
	if relationship := resource.OperatorTeamRelationship; relationship != nil &&
		(!validUUIDv7(relationship.OperatorTeamID) ||
			!validUUIDv7(relationship.AssignmentEpochID)) {
		return false
	}
	return true
}

func knownPrincipalKind(kind PrincipalKind) bool {
	return kind == PrincipalKindHuman || kind == PrincipalKindServiceAccount
}

func knownScope(scope Scope) bool {
	switch scope {
	case ScopeOwn, ScopeAssigned, ScopeOperatorTeam, ScopeTenant, ScopePlatform:
		return true
	default:
		return false
	}
}

func (e Evaluator) tenantPermissionMetadata(permission TenantPermission) (tenantPermissionMetadata, bool) {
	catalog := e.tenantPermissions
	if catalog == nil {
		catalog = initialTenantPermissions
	}
	metadata, known := catalog[permission]
	return metadata, known
}

func scopeCovers(authority TenantAuthority, scope Scope, resource ResourceContext) bool {
	switch scope {
	case ScopeTenant:
		return true
	case ScopeOwn:
		return resource.OwnerID != nil && *resource.OwnerID == authority.Principal.ID
	case ScopeAssigned:
		return resource.AssigneeID != nil && *resource.AssigneeID == authority.Principal.ID
	case ScopeOperatorTeam:
		if resource.OperatorTeamRelationship == nil {
			return false
		}
		for _, relationship := range authority.OperatorTeamRelationships {
			if relationship == *resource.OperatorTeamRelationship {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func hasLiveExactCeiling(ceilings []DelegationGrant, requested ScopedPermission, now time.Time) bool {
	for _, ceiling := range ceilings {
		if isLiveExactCeiling(ceiling, requested, now) {
			return true
		}
	}
	return false
}

func isLiveExactCeiling(ceiling DelegationGrant, requested ScopedPermission, now time.Time) bool {
	return ceiling.ScopedPermission == requested &&
		(ceiling.ExpiresAt == nil || ceiling.ExpiresAt.After(now))
}

func delegationLifetimeCovered(ceiling, requested *time.Time) bool {
	if ceiling == nil {
		return true
	}
	return requested != nil && !requested.After(*ceiling)
}

func setOf[T comparable](values ...T) map[T]struct{} {
	result := make(map[T]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func contains[T comparable](values map[T]struct{}, value T) bool {
	_, exists := values[value]
	return exists
}
