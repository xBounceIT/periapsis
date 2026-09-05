package authorization

import (
	"time"

	"github.com/google/uuid"
)

// TenantPermission is a stable tenant-scoped backend authorization key.
// Platform permissions intentionally use Permission instead.
type TenantPermission string

const (
	TenantPermissionPermissionRead                 TenantPermission = "permission.read"
	TenantPermissionRoleRead                       TenantPermission = "role.read"
	TenantPermissionRoleManage                     TenantPermission = "role.manage"
	TenantPermissionRoleGrant                      TenantPermission = "role.grant"
	TenantPermissionUserRead                       TenantPermission = "user.read"
	TenantPermissionMembershipManage               TenantPermission = "membership.manage"
	TenantPermissionGroupRead                      TenantPermission = "group.read"
	TenantPermissionGroupManage                    TenantPermission = "group.manage"
	TenantPermissionGroupMembershipManage          TenantPermission = "group.membership.manage"
	TenantPermissionOperatorTeamRead               TenantPermission = "operator_team.read"
	TenantPermissionOperatorTeamManage             TenantPermission = "operator_team.manage"
	TenantPermissionOperatorTeamRosterManage       TenantPermission = "operator_team.roster.manage"
	TenantPermissionServiceAccountRead             TenantPermission = "service_account.read"
	TenantPermissionServiceAccountManage           TenantPermission = "service_account.manage"
	TenantPermissionServiceAccountCredentialManage TenantPermission = "service_account.credential.manage"
	TenantPermissionAlertCreate                    TenantPermission = "alert.create"
	TenantPermissionAlertRead                      TenantPermission = "alert.read"
	TenantPermissionAlertActivityRead              TenantPermission = "alert.activity.read"
	TenantPermissionAlertCommentRead               TenantPermission = "alert.comment.read"
	TenantPermissionAlertLinkRead                  TenantPermission = "alert.link.read"
	TenantPermissionAlertUpdate                    TenantPermission = "alert.update"
	TenantPermissionAlertDelete                    TenantPermission = "alert.delete"
	TenantPermissionAlertAssign                    TenantPermission = "alert.assign"
	TenantPermissionAlertClaim                     TenantPermission = "alert.claim"
	TenantPermissionAlertEscalate                  TenantPermission = "alert.escalate"
	TenantPermissionAlertCommentPublic             TenantPermission = "alert.comment.public"
	TenantPermissionAlertCommentPrivate            TenantPermission = "alert.comment.private"
	TenantPermissionCaseRead                       TenantPermission = "case.read"
	TenantPermissionCaseActivityRead               TenantPermission = "case.activity.read"
	TenantPermissionCaseCommentRead                TenantPermission = "case.comment.read"
	TenantPermissionCaseLinkRead                   TenantPermission = "case.link.read"
	TenantPermissionCaseCreate                     TenantPermission = "case.create"
	TenantPermissionCaseUpdate                     TenantPermission = "case.update"
	TenantPermissionCaseClaim                      TenantPermission = "case.claim"
	TenantPermissionCaseTransfer                   TenantPermission = "case.transfer"
	TenantPermissionCaseTransition                 TenantPermission = "case.transition"
	TenantPermissionCaseCommentPublic              TenantPermission = "case.comment.public"
	TenantPermissionCaseCommentPrivate             TenantPermission = "case.comment.private"
	TenantPermissionContactRead                    TenantPermission = "contact.read"
	TenantPermissionContactManage                  TenantPermission = "contact.manage"
	TenantPermissionContactPreferenceManage        TenantPermission = "contact.preference.manage"
	TenantPermissionContactGroupRead               TenantPermission = "contact_group.read"
	TenantPermissionContactGroupManage             TenantPermission = "contact_group.manage"
	TenantPermissionPortalAlertRead                TenantPermission = "portal.alert.read"
	TenantPermissionPortalCaseRead                 TenantPermission = "portal.case.read"
	TenantPermissionPortalCommentPublic            TenantPermission = "portal.comment.public"
	TenantPermissionPortalAttachmentRead           TenantPermission = "portal.attachment.read"
	TenantPermissionPortalContactPreferenceManage  TenantPermission = "portal.contact.preference.manage"
	TenantPermissionIdentityProviderRead           TenantPermission = "identity_provider.read"
	TenantPermissionIdentityProviderManage         TenantPermission = "identity_provider.manage"
	TenantPermissionIdentityProviderTest           TenantPermission = "identity_provider.test"
	TenantPermissionIdentityMappingRead            TenantPermission = "identity_mapping.read"
	TenantPermissionIdentityMappingManage          TenantPermission = "identity_mapping.manage"
	TenantPermissionIdentitySyncRun                TenantPermission = "identity_sync.run"
	TenantPermissionIdentityPolicyRead             TenantPermission = "identity_policy.read"
	TenantPermissionIdentityPolicyManage           TenantPermission = "identity_policy.manage"
	TenantPermissionSettingsRead                   TenantPermission = "settings.read"
	TenantPermissionSettingsManage                 TenantPermission = "settings.manage"
	TenantPermissionNotificationManage             TenantPermission = "notification.manage"
	TenantPermissionAuditRead                      TenantPermission = "audit.read"
	TenantPermissionAuditExport                    TenantPermission = "audit.export"
	TenantPermissionAuditRetentionManage           TenantPermission = "audit.retention.manage"
	TenantPermissionSLARead                        TenantPermission = "sla.read"
	TenantPermissionSLAManage                      TenantPermission = "sla.manage"
	TenantPermissionSLASimulate                    TenantPermission = "sla.simulate"
	TenantPermissionWorkflowRead                   TenantPermission = "workflow.read"
	TenantPermissionWorkflowManage                 TenantPermission = "workflow.manage"
	TenantPermissionAlertSLAOverride               TenantPermission = "alert.sla.override"
	TenantPermissionCaseSLAOverride                TenantPermission = "case.sla.override"
	TenantPermissionCustomFieldRead                TenantPermission = "custom_field.read"
	TenantPermissionCustomFieldManage              TenantPermission = "custom_field.manage"
	TenantPermissionDFIRIOCRead                    TenantPermission = "dfir.ioc.read"
	TenantPermissionDFIRIOCManage                  TenantPermission = "dfir.ioc.manage"
	TenantPermissionDFIRAssetRead                  TenantPermission = "dfir.asset.read"
	TenantPermissionDFIRAssetManage                TenantPermission = "dfir.asset.manage"
	TenantPermissionDFIREvidenceRead               TenantPermission = "dfir.evidence.read"
	TenantPermissionDFIREvidenceManage             TenantPermission = "dfir.evidence.manage"
	TenantPermissionDFIRTimelineRead               TenantPermission = "dfir.timeline.read"
	TenantPermissionDFIRTimelineManage             TenantPermission = "dfir.timeline.manage"
	TenantPermissionDFIRTaskRead                   TenantPermission = "dfir.task.read"
	TenantPermissionDFIRTaskManage                 TenantPermission = "dfir.task.manage"
	TenantPermissionDFIRAttachmentRead             TenantPermission = "dfir.attachment.read"
	TenantPermissionDFIRAttachmentManage           TenantPermission = "dfir.attachment.manage"
	TenantPermissionDFIRRelationshipRead           TenantPermission = "dfir.relationship.read"
	TenantPermissionDFIRRelationshipManage         TenantPermission = "dfir.relationship.manage"
)

// Scope describes the resource relationship covered by a tenant permission.
type Scope string

const (
	ScopeOwn          Scope = "own"
	ScopeAssigned     Scope = "assigned"
	ScopeOperatorTeam Scope = "operator_team"
	ScopeTenant       Scope = "tenant"
	ScopePlatform     Scope = "platform"
)

// PrincipalKind distinguishes human actors from non-human tenant principals.
type PrincipalKind string

const (
	PrincipalKindHuman          PrincipalKind = "human"
	PrincipalKindServiceAccount PrincipalKind = "service_account"
)

// TenantPrincipal identifies the effective principal evaluated inside one tenant.
type TenantPrincipal struct {
	ID   uuid.UUID
	Kind PrincipalKind
}

// ScopedPermission is one exact permission and scope tuple. Leaf scopes are
// deliberately not interchangeable.
type ScopedPermission struct {
	Permission TenantPermission
	Scope      Scope
}

// DelegationGrant is one exact tuple the principal may delegate. ExpiresAt is
// nil only when the delegation ceiling is non-expiring.
type DelegationGrant struct {
	ScopedPermission
	ExpiresAt *time.Time
}

// DelegationRequest describes authority to be granted and its requested
// lifetime. ExpiresAt nil means a non-expiring grant.
type DelegationRequest struct {
	ScopedPermission
	ExpiresAt *time.Time
}

// OperatorTeamRelationship identifies one immutable tenant-assignment epoch.
// Team identity alone is insufficient because a team can be assigned to the
// same tenant again after a previous epoch ends.
type OperatorTeamRelationship struct {
	OperatorTeamID    uuid.UUID
	AssignmentEpochID uuid.UUID
}

// TenantAuthority is a live, server-resolved projection of tenant authority.
// Callers must resolve it again for each request rather than persist it in a
// browser credential or session cookie.
type TenantAuthority struct {
	TenantID          uuid.UUID
	Principal         TenantPrincipal
	MembershipID      uuid.UUID
	MembershipStatus  MembershipStatus
	LegacyRole        LegacyMembershipRole
	RoleGrants        []EffectiveTenantRoleGrant
	Permissions       []ScopedPermission
	DelegationCeiling []DelegationGrant
	// OperatorTeamRelationships contains only exact epochs for which the
	// principal has both a live tenant assignment and a live roster entry.
	OperatorTeamRelationships []OperatorTeamRelationship
	EvaluatedAt               time.Time
}

// ResourceContext contains only server-resolved relationships used by scope
// evaluation. Nil relationship pointers mean that relationship is absent.
type ResourceContext struct {
	TenantID                 uuid.UUID
	OwnerID                  *uuid.UUID
	AssigneeID               *uuid.UUID
	OperatorTeamRelationship *OperatorTeamRelationship
}
