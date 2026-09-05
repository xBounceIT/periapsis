import type {
  AuthorizationEdgeProvenance,
  AuthorizationEdgeRevokeRequest,
  AuthorizationEdgeState,
  DirectUserRoleGrant,
  DirectUserRoleGrantRequest,
  EffectiveTenantDelegation,
  EffectiveTenantRoleGrant,
  OperatorTeam,
  OperatorTeamArchiveRequest,
  OperatorTeamAssignmentEpoch,
  OperatorTeamAssignmentEpochEndRequest,
  OperatorTeamAssignmentEpochStartRequest,
  OperatorTeamCreateRequest,
  OperatorTeamList,
  OperatorTeamPatchRequest,
  OperatorTeamRosterEntry,
  OperatorTeamRosterEntryCreateRequest,
  OperatorTeamRosterEntryList,
  PlatformAuthProvider,
  PlatformAuthProviderAccount,
  PlatformAuthProviderAccountList,
  PlatformAuthProviderAccountPrelinkRequestWritable,
  PlatformAuthProviderActivationRequest,
  PlatformAuthProviderArchiveRequest,
  PlatformAuthProviderCreateRequest,
  PlatformAuthProviderDeactivationRequest,
  PlatformOidcDirectLoginCommandRequest,
  PlatformAuthProviderList,
  PlatformAuthProviderSummary,
  PlatformAuthProviderTenantBinding,
  PlatformAuthProviderTenantBindingActivationRequest,
  PlatformAuthProviderTenantBindingArchiveRequest,
  PlatformAuthProviderTenantBindingCreateRequest,
  PlatformAuthProviderTenantBindingDeactivationRequest,
  PlatformAuthProviderTenantBindingList,
  PlatformAuthProviderTenantBindingPatchRequest,
  PlatformAuthProviderUpdateRequest,
  PlatformLdapAuthProvider,
  PlatformLdapAuthProviderUpdateRequest,
  PlatformLdapBindSecretWriteRequestWritable,
  PlatformLdapDiagnostic,
  PlatformLdapLoginStateRequest,
  PlatformLdapMappingWriteRequest,
  PlatformLdapTestRequest,
  PlatformLocalAccount,
  PlatformLocalAccountActivateRequestWritable,
  PlatformLocalAccountInviteRequest,
  PlatformLocalAccountList,
  PlatformLocalAccountPasswordRotationRequestWritable,
  PlatformOidcClientSecretReplaceRequestWritable,
  PlatformSamlMetadataReplaceRequestWritable,
  PlatformSamlspKeyClearRequest,
  PlatformSamlspKeyReplaceRequestWritable,
  RoleGrantRevokeRequest,
  ServiceAccount,
  ServiceAccountArchiveRequest,
  ServiceAccountCreateRequest,
  ServiceAccountCredential,
  ServiceAccountCredentialIssueRequest,
  ServiceAccountCredentialList,
  ServiceAccountCredentialRevokeRequest,
  ServiceAccountCredentialRotateRequest,
  ServiceAccountCredentialSecret,
  ServiceAccountList,
  ServiceAccountPatchRequest,
  ServiceAccountRoleGrant,
  ServiceAccountRoleGrantList,
  ServiceAccountRoleGrantRequest,
  ServiceAccountRoleGrantRevokeRequest,
  TenantAuthority,
  TenantAuthorizationScope,
  TenantLdapAuthProvider,
  TenantLdapAuthProviderArchiveRequest,
  TenantLdapAuthProviderBinding,
  TenantLdapAuthProviderBindingArchiveRequest,
  TenantLdapAuthProviderBindingCreateRequest,
  TenantLdapAuthProviderBindingList,
  TenantLdapAuthProviderBindingUpdateRequest,
  TenantLdapAuthProviderConfiguration,
  TenantLdapAuthProviderCreateRequest,
  TenantLdapAuthProviderDiagnostic,
  TenantLdapAuthProviderEndpoint,
  TenantLdapAuthProviderList,
  TenantLdapAuthProviderSummary,
  TenantLdapAuthProviderUpdateRequest,
  TenantLdapBindSecretClearRequest,
  TenantLdapBindSecretWriteRequest,
  TenantLdapFilterTestRequest,
  TenantLdapFilterTestResult,
  TenantLdapManualSyncRequest,
  TenantLdapMapping,
  TenantLdapMappingArchiveRequest,
  TenantLdapMappingCreateRequest,
  TenantLdapMappingDryRunRequest,
  TenantLdapMappingDryRunResult,
  TenantLdapMappingList,
  TenantLdapMappingUpdateRequest,
  TenantLdapSyncRun,
  TenantLdapSyncRunList,
  TenantLdapSyncStatus,
  TenantLdapUserSearchTestRequest,
  TenantLdapUserSearchTestResult,
  TenantMembershipLifecycleReceipt,
  TenantMembershipLifecycleRequest,
  TenantPermission,
  TenantPermissionKey,
  TenantPermissionList,
  TenantRole,
  TenantRoleCreateRequest,
  TenantRoleList,
  TenantRolePatchRequest,
  TenantRolePolicy,
  TenantRoleReadPolicy,
  TenantRoleSummary,
  TenantSecurityGroup,
  TenantSecurityGroupCreateRequest,
  TenantSecurityGroupList,
  TenantSecurityGroupMembership,
  TenantSecurityGroupMembershipCreateRequest,
  TenantSecurityGroupPatchRequest,
  TenantSecurityGroupRoleGrant,
  TenantSecurityGroupRoleGrantRequest,
  TenantUserList,
  TenantUserSummary,
} from "@periapsis/contracts";

export const platformPermissionKeys = [
  "platform.tenant.read",
  "platform.tenant.create",
  "platform.tenant.manage",
  "platform.tenant.access",
  "platform.operator_team.read",
  "platform.operator_team.manage",
  "platform.identity_provider.read",
  "platform.identity_provider.manage",
  "platform.identity_provider.test",
  "platform.identity_binding.read",
  "platform.identity_binding.manage",
  "platform.identity_policy.read",
  "platform.identity_policy.manage",
  "platform.identity_account.read",
  "platform.identity_account.manage",
  "platform.notification.manage",
  "platform.audit.read",
  "platform.audit.export",
  "platform.audit.retention.manage",
  "platform.user.read",
  "platform.operations.read",
  "platform.settings.read",
  "platform.settings.manage",
  "platform.feature_flag.read",
  "platform.feature_flag.manage",
] as const;

export type PlatformPermissionKeyView = (typeof platformPermissionKeys)[number];

export const platformTenantReadPermission = "platform.tenant.read";
export const platformTenantCreatePermission = "platform.tenant.create";
export const platformTenantManagePermission = "platform.tenant.manage";
export const platformTenantAccessPermission = "platform.tenant.access";
export const platformOperatorTeamReadPermission = "platform.operator_team.read";
export const platformOperatorTeamManagePermission =
  "platform.operator_team.manage";
export const platformIdentityProviderReadPermission =
  "platform.identity_provider.read";
export const platformIdentityProviderManagePermission =
  "platform.identity_provider.manage";
export const platformIdentityProviderTestPermission =
  "platform.identity_provider.test";
export const platformIdentityBindingReadPermission =
  "platform.identity_binding.read";
export const platformIdentityBindingManagePermission =
  "platform.identity_binding.manage";
export const platformIdentityPolicyReadPermission =
  "platform.identity_policy.read";
export const platformIdentityPolicyManagePermission =
  "platform.identity_policy.manage";
export const platformIdentityAccountReadPermission =
  "platform.identity_account.read";
export const platformIdentityAccountManagePermission =
  "platform.identity_account.manage";
export const platformNotificationManagePermission =
  "platform.notification.manage";
export const platformAuditReadPermission = "platform.audit.read";
export const platformAuditExportPermission = "platform.audit.export";
export const platformAuditRetentionManagePermission =
  "platform.audit.retention.manage";
export const platformUserReadPermission = "platform.user.read";
export const platformOperationsReadPermission = "platform.operations.read";
export const platformSettingsReadPermission = "platform.settings.read";
export const platformSettingsManagePermission = "platform.settings.manage";
export const platformFeatureFlagReadPermission = "platform.feature_flag.read";
export const platformFeatureFlagManagePermission =
  "platform.feature_flag.manage";

export const tenantPermissionKeys = [
  "permission.read",
  "role.read",
  "role.manage",
  "role.grant",
  "user.read",
  "membership.manage",
  "group.read",
  "group.manage",
  "group.membership.manage",
  "operator_team.read",
  "operator_team.manage",
  "operator_team.roster.manage",
  "service_account.read",
  "service_account.manage",
  "service_account.credential.manage",
  "identity_provider.read",
  "identity_provider.manage",
  "identity_provider.test",
  "identity_mapping.read",
  "identity_mapping.manage",
  "identity_sync.run",
  "identity_policy.read",
  "identity_policy.manage",
  "settings.read",
  "settings.manage",
  "audit.read",
  "audit.export",
  "audit.retention.manage",
  "sla.read",
  "sla.manage",
  "sla.simulate",
  "workflow.read",
  "workflow.manage",
  "alert.create",
  "alert.read",
  "alert.activity.read",
  "alert.comment.read",
  "alert.link.read",
  "alert.update",
  "alert.delete",
  "alert.assign",
  "alert.claim",
  "alert.escalate",
  "alert.sla.override",
  "alert.comment.public",
  "alert.comment.private",
  "case.create",
  "case.read",
  "case.activity.read",
  "case.comment.read",
  "case.link.read",
  "case.update",
  "case.claim",
  "case.transfer",
  "case.transition",
  "case.sla.override",
  "case.comment.public",
  "case.comment.private",
  "custom_field.read",
  "custom_field.manage",
  "dfir.ioc.read",
  "dfir.ioc.manage",
  "dfir.asset.read",
  "dfir.asset.manage",
  "dfir.evidence.read",
  "dfir.evidence.manage",
  "dfir.timeline.read",
  "dfir.timeline.manage",
  "dfir.task.read",
  "dfir.task.manage",
  "dfir.attachment.read",
  "dfir.attachment.manage",
  "dfir.relationship.read",
  "dfir.relationship.manage",
  "contact.read",
  "contact.manage",
  "contact.preference.manage",
  "contact_group.read",
  "contact_group.manage",
  "portal.alert.read",
  "portal.case.read",
  "portal.comment.public",
  "portal.attachment.read",
  "portal.contact.preference.manage",
  "notification.manage",
] as const satisfies readonly TenantPermissionKey[];

type TenantPermissionCatalogCoverage =
  Exclude<
    TenantPermissionKey,
    (typeof tenantPermissionKeys)[number]
  > extends never
    ? true
    : never;

// This value intentionally turns a generated-contract expansion into a local
// compile error until the role matrix catalog is updated.
export const tenantPermissionCatalogIsExhaustive: TenantPermissionCatalogCoverage = true;

export const tenantAuthorizationScopes = [
  "own",
  "assigned",
  "operator_team",
  "tenant",
] as const satisfies readonly TenantAuthorizationScope[];

type TenantAuthorizationScopeCoverage =
  Exclude<
    TenantAuthorizationScope,
    (typeof tenantAuthorizationScopes)[number]
  > extends never
    ? true
    : never;

export const tenantAuthorizationScopeCatalogIsExhaustive: TenantAuthorizationScopeCoverage = true;

export type TenantPermissionKeyView = TenantPermissionKey;
export type TenantAuthorizationScopeView = TenantAuthorizationScope;
export type TenantPermissionView = TenantPermission;
export type TenantPermissionPageView = TenantPermissionList;
export type EffectiveTenantDelegationView = EffectiveTenantDelegation;
export type TenantRolePolicyView = TenantRoleReadPolicy;
export type TenantRolePolicyInput = TenantRolePolicy;
export type TenantRoleSummaryView = TenantRoleSummary;
export type TenantRoleView = TenantRole;
export type TenantRolePageView = TenantRoleList;
export type TenantRoleCreateInput = TenantRoleCreateRequest;
export type TenantRolePatchInput = TenantRolePatchRequest;
export type TenantAuthorityView = TenantAuthority;
export type TenantUserSummaryView = TenantUserSummary;
export type TenantUserPageView = TenantUserList;
export type TenantMembershipLifecycleInput = TenantMembershipLifecycleRequest;
export type TenantMembershipLifecycleReceiptView =
  TenantMembershipLifecycleReceipt;
type AuthorizationAPIManagedView<T> = Omit<T, "managedByAuthorizationApi"> & {
  managedByAuthorizationApi: boolean;
};

export type DirectUserRoleGrantView =
  AuthorizationAPIManagedView<DirectUserRoleGrant>;
export type DirectUserRoleGrantInput = DirectUserRoleGrantRequest;
export type RoleGrantRevokeInput = RoleGrantRevokeRequest;
export type EffectiveTenantRoleGrantView = EffectiveTenantRoleGrant;
export type TenantSecurityGroupView = TenantSecurityGroup;
export type TenantSecurityGroupPageView = TenantSecurityGroupList;
export type TenantSecurityGroupCreateInput = TenantSecurityGroupCreateRequest;
export type TenantSecurityGroupPatchInput = TenantSecurityGroupPatchRequest;
export type TenantSecurityGroupMembershipView =
  AuthorizationAPIManagedView<TenantSecurityGroupMembership>;
export type TenantSecurityGroupMembershipCreateInput =
  TenantSecurityGroupMembershipCreateRequest;
export type TenantSecurityGroupRoleGrantView =
  AuthorizationAPIManagedView<TenantSecurityGroupRoleGrant>;
export type TenantSecurityGroupRoleGrantInput =
  TenantSecurityGroupRoleGrantRequest;
export type AuthorizationEdgeRevokeInput = AuthorizationEdgeRevokeRequest;
export type AuthorizationEdgeProvenanceView = AuthorizationEdgeProvenance;
export type AuthorizationEdgeStateView = AuthorizationEdgeState;
export type OperatorTeamView = OperatorTeam;
export type OperatorTeamPageView = OperatorTeamList;
export type OperatorTeamCreateInput = OperatorTeamCreateRequest;
export type OperatorTeamPatchInput = OperatorTeamPatchRequest;
export type OperatorTeamArchiveInput = OperatorTeamArchiveRequest;
export type OperatorTeamAssignmentEpochView = OperatorTeamAssignmentEpoch;
export type OperatorTeamAssignmentEpochStartInput =
  OperatorTeamAssignmentEpochStartRequest;
export type OperatorTeamAssignmentEpochEndInput =
  OperatorTeamAssignmentEpochEndRequest;
export type OperatorTeamRosterEntryView = OperatorTeamRosterEntry;
export type OperatorTeamRosterEntryCreateInput =
  OperatorTeamRosterEntryCreateRequest;
export type ServiceAccountView = ServiceAccount;
export type ServiceAccountPageView = ServiceAccountList;
export type ServiceAccountCreateInput = ServiceAccountCreateRequest;
export type ServiceAccountPatchInput = ServiceAccountPatchRequest;
export type ServiceAccountArchiveInput = ServiceAccountArchiveRequest;
export type ServiceAccountRoleGrantView = ServiceAccountRoleGrant;
export type ServiceAccountRoleGrantInput = ServiceAccountRoleGrantRequest;
export type ServiceAccountRoleGrantRevokeInput =
  ServiceAccountRoleGrantRevokeRequest;
export type ServiceAccountCredentialView = ServiceAccountCredential;
export type ServiceAccountCredentialIssueInput =
  ServiceAccountCredentialIssueRequest;
export type ServiceAccountCredentialRotateInput =
  ServiceAccountCredentialRotateRequest;
export type ServiceAccountCredentialRevokeInput =
  ServiceAccountCredentialRevokeRequest;
export type ServiceAccountCredentialSecretView = ServiceAccountCredentialSecret;
export type TenantLdapAuthProviderView = TenantLdapAuthProvider;
export type TenantLdapAuthProviderSummaryView = TenantLdapAuthProviderSummary;
export type TenantLdapAuthProviderPageView = TenantLdapAuthProviderList;
export type TenantLdapAuthProviderConfigurationView =
  TenantLdapAuthProviderConfiguration;
export type TenantLdapAuthProviderEndpointView = TenantLdapAuthProviderEndpoint;
export type TenantLdapAuthProviderCreateInput =
  TenantLdapAuthProviderCreateRequest;
export type TenantLdapAuthProviderUpdateInput =
  TenantLdapAuthProviderUpdateRequest;
export type TenantLdapAuthProviderArchiveInput =
  TenantLdapAuthProviderArchiveRequest;
export type TenantLdapBindSecretWriteInput = TenantLdapBindSecretWriteRequest;
export type TenantLdapBindSecretClearInput = TenantLdapBindSecretClearRequest;
export type TenantLdapAuthProviderDiagnosticView =
  TenantLdapAuthProviderDiagnostic;
export type TenantLdapAuthProviderBindingView = TenantLdapAuthProviderBinding;
export type TenantLdapAuthProviderBindingPageView =
  TenantLdapAuthProviderBindingList;
export type TenantLdapAuthProviderBindingCreateInput =
  TenantLdapAuthProviderBindingCreateRequest;
export type TenantLdapAuthProviderBindingUpdateInput =
  TenantLdapAuthProviderBindingUpdateRequest;
export type TenantLdapAuthProviderBindingArchiveInput =
  TenantLdapAuthProviderBindingArchiveRequest;
export type TenantLdapUserSearchTestInput = TenantLdapUserSearchTestRequest;
export type TenantLdapUserSearchTestResultView = TenantLdapUserSearchTestResult;
export type TenantLdapFilterTestInput = TenantLdapFilterTestRequest;
export type TenantLdapFilterTestResultView = TenantLdapFilterTestResult;
export type TenantLdapMappingView = TenantLdapMapping;
export type TenantLdapMappingPageView = TenantLdapMappingList;
export type TenantLdapMappingCreateInput = TenantLdapMappingCreateRequest;
export type TenantLdapMappingUpdateInput = TenantLdapMappingUpdateRequest;
export type TenantLdapMappingArchiveInput = TenantLdapMappingArchiveRequest;
export type TenantLdapMappingDryRunInput = TenantLdapMappingDryRunRequest;
export type TenantLdapMappingDryRunResultView = TenantLdapMappingDryRunResult;
export type TenantLdapManualSyncInput = TenantLdapManualSyncRequest;
export type TenantLdapSyncStatusView = TenantLdapSyncStatus;
export type TenantLdapSyncRunView = TenantLdapSyncRun;
export type TenantLdapSyncRunPageView = TenantLdapSyncRunList;

export type PlatformAuthProviderView = PlatformAuthProvider;
export type PlatformAuthProviderSummaryView = PlatformAuthProviderSummary;
export type PlatformAuthProviderPageView = PlatformAuthProviderList;
export type PlatformAuthProviderAccountView = PlatformAuthProviderAccount;
export type PlatformAuthProviderAccountPageView =
  PlatformAuthProviderAccountList;
export type PlatformAuthProviderAccountPrelinkInput =
  PlatformAuthProviderAccountPrelinkRequestWritable;
export type PlatformAuthProviderCreateInput = PlatformAuthProviderCreateRequest;
export type PlatformAuthProviderUpdateInput = PlatformAuthProviderUpdateRequest;
export type PlatformLdapAuthProviderView = PlatformLdapAuthProvider;
export type PlatformLdapAuthProviderUpdateInput =
  PlatformLdapAuthProviderUpdateRequest;
export type PlatformLdapBindSecretWriteInput =
  PlatformLdapBindSecretWriteRequestWritable;
export type PlatformLdapMappingWriteInput = PlatformLdapMappingWriteRequest;
export type PlatformLdapLoginStateInput = PlatformLdapLoginStateRequest;
export type PlatformLdapTestInput = PlatformLdapTestRequest;
export type PlatformLdapDiagnosticView = PlatformLdapDiagnostic;
export type PlatformAuthProviderActivationInput =
  PlatformAuthProviderActivationRequest;
export type PlatformAuthProviderDeactivationInput =
  PlatformAuthProviderDeactivationRequest;
export type PlatformOidcDirectLoginCommandInput =
  PlatformOidcDirectLoginCommandRequest;
export type PlatformAuthProviderArchiveInput =
  PlatformAuthProviderArchiveRequest;
export type PlatformAuthProviderTenantBindingView =
  PlatformAuthProviderTenantBinding;
export type PlatformAuthProviderTenantBindingPageView =
  PlatformAuthProviderTenantBindingList;
export type PlatformAuthProviderTenantBindingCreateInput =
  PlatformAuthProviderTenantBindingCreateRequest;
export type PlatformAuthProviderTenantBindingUpdateInput =
  PlatformAuthProviderTenantBindingPatchRequest;
export type PlatformAuthProviderTenantBindingActivationInput =
  PlatformAuthProviderTenantBindingActivationRequest;
export type PlatformAuthProviderTenantBindingDeactivationInput =
  PlatformAuthProviderTenantBindingDeactivationRequest;
export type PlatformAuthProviderTenantBindingArchiveInput =
  PlatformAuthProviderTenantBindingArchiveRequest;
export type PlatformOidcClientSecretReplaceInput =
  PlatformOidcClientSecretReplaceRequestWritable;
export type PlatformSamlMetadataReplaceInput =
  PlatformSamlMetadataReplaceRequestWritable;
export type PlatformSamlSpKeyReplaceInput =
  PlatformSamlspKeyReplaceRequestWritable;
export type PlatformSamlSpKeyClearInput = PlatformSamlspKeyClearRequest;
export type PlatformLocalAccountView = PlatformLocalAccount;
export type PlatformLocalAccountPageView = PlatformLocalAccountList;
export type PlatformLocalAccountInviteInput = PlatformLocalAccountInviteRequest;
export type PlatformLocalAccountActivationInput = Omit<
  PlatformLocalAccountActivateRequestWritable,
  "expectedRevision"
>;
export type PlatformLocalAccountPasswordRotationInput = Omit<
  PlatformLocalAccountPasswordRotationRequestWritable,
  "expectedRevision"
>;

export interface PlatformLocalAccountTOTPEnrollmentView {
  provisioningUri: string;
  secret: string;
}

export interface PlatformLocalAccountMutationView {
  account: VersionedView<PlatformLocalAccountView>;
  ceremonyToken?: string;
  replayed: boolean;
  totpEnrollment?: PlatformLocalAccountTOTPEnrollmentView;
}

export interface PlatformLocalAccountInvitationView extends PlatformLocalAccountMutationView {
  location: string;
}

export interface PlatformSamlMaterialMutationView {
  etag: string;
  materialRevision: number;
}

export interface CreatedVersionedView<T> extends VersionedView<T> {
  location: string;
}

export interface OperatorTeamAssignmentEpochPageView {
  items: readonly OperatorTeamAssignmentEpochView[];
  nextCursor?: string;
}

export interface OperatorTeamRosterEntryPageView extends Omit<
  OperatorTeamRosterEntryList,
  "items"
> {
  items: readonly OperatorTeamRosterEntryView[];
}

export interface DirectUserRoleGrantPageView {
  items: readonly DirectUserRoleGrantView[];
  nextCursor?: string;
}

export interface TenantSecurityGroupMembershipPageView {
  items: readonly TenantSecurityGroupMembershipView[];
  nextCursor?: string;
}

export interface TenantSecurityGroupRoleGrantPageView {
  items: readonly TenantSecurityGroupRoleGrantView[];
  nextCursor?: string;
}

export interface ServiceAccountRoleGrantPageView extends Omit<
  ServiceAccountRoleGrantList,
  "items"
> {
  items: readonly ServiceAccountRoleGrantView[];
}

export interface ServiceAccountCredentialPageView extends Omit<
  ServiceAccountCredentialList,
  "items"
> {
  items: readonly ServiceAccountCredentialView[];
}

export interface VersionedView<T> {
  etag: string;
  value: T;
}

export interface CreatedResourceLocation {
  location: string;
}

export type MfaMethod = "recovery_code" | "totp";
export type AuthenticationMethod =
  | "bootstrap_totp"
  | "ldap"
  | "oidc"
  | "passkey"
  | "recovery_code"
  | "saml"
  | "totp";

export interface UserView {
  displayName: string;
  email?: string;
  id: string;
}

export interface SessionView {
  activeTenantId?: string;
  absoluteExpiresAt: string;
  csrfToken: string;
  id: string;
  idleExpiresAt: string;
  permissions: readonly string[];
  user: UserView;
}

export interface LogoutResultView {
  continuationUrl: string;
}

export interface BootstrapEnrollmentView {
  enrollmentToken: string;
  expiresAt: string;
  totpSecret: string;
  totpUri: string;
}

export interface BootstrapConfirmationView {
  recoveryCodes: readonly string[];
  session: SessionView;
}

export interface LoginChallengeView {
  challengeToken: string;
  expiresAt: string;
  methods: readonly MfaMethod[];
}

export interface SessionSummaryView {
  absoluteExpiresAt: string;
  authenticationMethod: AuthenticationMethod;
  createdAt: string;
  current: boolean;
  id: string;
  idleExpiresAt: string;
  lastSeenAt: string;
  revokedAt?: string;
}

export interface SessionPageView {
  items: readonly SessionSummaryView[];
  nextCursor?: string;
}

export interface TenantMembershipView {
  membershipId: string;
  role: string;
  tenantId: string;
  tenantName: string;
  tenantSlug: string;
}

export interface TenantMembershipPageView {
  items: readonly TenantMembershipView[];
  nextCursor?: string;
}

export interface TenantView {
  createdAt: string;
  id: string;
  locale: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  timezone: string;
  updatedAt: string;
  version?: number;
}

export interface TenantPageView {
  items: readonly TenantView[];
  nextCursor?: string;
}

export interface CreateTenantInput {
  locale: string;
  name: string;
  slug: string;
  timezone: string;
}

export type TenantLifecycleAction = "reactivate" | "suspend";

export interface TenantLifecycleReceiptView {
  previousStatus: "active" | "suspended";
  replayed: boolean;
  status: "active" | "suspended";
  tenantId: string;
  updatedAt: string;
  version: number;
}

export interface TenantLifecycleChangeInput {
  expectedVersion: number;
  reason: string;
}

export interface PlatformTenantAccessReceiptView {
  authorizationRevision: string;
  authorizedAt: string;
  membershipId: string;
  membershipRevision: number;
  replayed: boolean;
  tenantId: string;
  tenantVersion: number;
  userId: string;
}

export interface PlatformTenantAccessInput {
  expectedVersion: number;
  reason: string;
}

export interface PhaseTwoApi {
  activatePlatformLocalAccount(
    csrfToken: string,
    accountId: string,
    current: VersionedView<PlatformLocalAccountView>,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformLocalAccountActivationInput,
  ): Promise<PlatformLocalAccountMutationView>;
  activatePlatformOidcDirectLogin(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformOidcDirectLoginCommandInput,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  activatePlatformAuthProvider(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformAuthProviderActivationInput,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  activatePlatformAuthProviderTenantBinding(
    csrfToken: string,
    providerId: string,
    bindingId: string,
    current: VersionedView<PlatformAuthProviderTenantBindingView>,
    auditReason: string,
    input: PlatformAuthProviderTenantBindingActivationInput,
  ): Promise<VersionedView<PlatformAuthProviderTenantBindingView>>;
  addOperatorTeamRosterEntry(
    csrfToken: string,
    tenantId: string,
    operatorTeamId: string,
    assignmentEpochId: string,
    idempotencyKey: string,
    input: OperatorTeamRosterEntryCreateInput,
  ): Promise<VersionedView<OperatorTeamRosterEntryView>>;
  archivePlatformAuthProvider(
    csrfToken: string,
    providerId: string,
    etag: string,
    auditReason: string,
    input: PlatformAuthProviderArchiveInput,
  ): Promise<string>;
  archivePlatformAuthProviderTenantBinding(
    csrfToken: string,
    providerId: string,
    bindingId: string,
    etag: string,
    auditReason: string,
    input: PlatformAuthProviderTenantBindingArchiveInput,
  ): Promise<string>;
  archivePlatformOperatorTeam(
    csrfToken: string,
    operatorTeamId: string,
    etag: string,
    input: OperatorTeamArchiveInput,
  ): Promise<void>;
  disablePlatformLocalAccount(
    csrfToken: string,
    accountId: string,
    current: VersionedView<PlatformLocalAccountView>,
    idempotencyKey: string,
    auditReason: string,
  ): Promise<PlatformLocalAccountMutationView>;
  enablePlatformLocalAccount(
    csrfToken: string,
    accountId: string,
    current: VersionedView<PlatformLocalAccountView>,
    idempotencyKey: string,
    auditReason: string,
  ): Promise<PlatformLocalAccountMutationView>;
  archiveTenantServiceAccount(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    etag: string,
    input: ServiceAccountArchiveInput,
  ): Promise<void>;
  archiveTenantLdapAuthProvider(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantLdapAuthProviderArchiveInput,
  ): Promise<string>;
  archiveTenantLdapAuthProviderBinding(
    csrfToken: string,
    tenantId: string,
    bindingId: string,
    etag: string,
    input: TenantLdapAuthProviderBindingArchiveInput,
  ): Promise<string>;
  archiveTenantLdapMapping(
    csrfToken: string,
    tenantId: string,
    mappingId: string,
    etag: string,
    input: TenantLdapMappingArchiveInput,
  ): Promise<string>;
  completeMfa(input: {
    challengeToken: string;
    code: string;
    method: MfaMethod;
  }): Promise<SessionView>;
  confirmBootstrap(input: {
    bootstrapToken: string;
    code: string;
    displayName: string;
    email: string;
    enrollmentToken: string;
    password: string;
  }): Promise<BootstrapConfirmationView>;
  createTenant(
    csrfToken: string,
    input: CreateTenantInput,
  ): Promise<TenantView>;
  authorizePlatformTenantAccess(
    csrfToken: string,
    tenantId: string,
    etag: string,
    idempotencyKey: string,
    input: PlatformTenantAccessInput,
  ): Promise<PlatformTenantAccessReceiptView>;
  reactivateTenant(
    csrfToken: string,
    tenantId: string,
    etag: string,
    input: TenantLifecycleChangeInput,
  ): Promise<VersionedView<TenantLifecycleReceiptView>>;
  createPlatformOperatorTeam(
    csrfToken: string,
    idempotencyKey: string,
    input: OperatorTeamCreateInput,
  ): Promise<VersionedView<OperatorTeamView>>;
  createPlatformAuthProvider(
    csrfToken: string,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformAuthProviderCreateInput,
  ): Promise<CreatedVersionedView<PlatformAuthProviderView>>;
  replacePlatformLdapBindSecret(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformLdapAuthProviderView>,
    auditReason: string,
    input: PlatformLdapBindSecretWriteInput,
  ): Promise<string>;
  putPlatformLdapMapping(
    csrfToken: string,
    providerId: string,
    mappingId: string,
    current: VersionedView<PlatformLdapAuthProviderView>,
    auditReason: string,
    input: PlatformLdapMappingWriteInput,
  ): Promise<VersionedView<PlatformLdapAuthProviderView>>;
  createPlatformAuthProviderTenantBinding(
    csrfToken: string,
    providerId: string,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformAuthProviderTenantBindingCreateInput,
  ): Promise<CreatedVersionedView<PlatformAuthProviderTenantBindingView>>;
  createTenantRole(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantRoleCreateInput,
  ): Promise<VersionedView<TenantRoleView>>;
  createTenantSecurityGroup(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantSecurityGroupCreateInput,
  ): Promise<VersionedView<TenantSecurityGroupView>>;
  createTenantSecurityGroupMembership(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    idempotencyKey: string,
    input: TenantSecurityGroupMembershipCreateInput,
  ): Promise<VersionedView<TenantSecurityGroupMembershipView>>;
  createTenantServiceAccount(
    csrfToken: string,
    tenantId: string,
    input: ServiceAccountCreateInput,
  ): Promise<VersionedView<ServiceAccountView>>;
  createTenantLdapAuthProvider(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantLdapAuthProviderCreateInput,
  ): Promise<CreatedResourceLocation>;
  createTenantLdapAuthProviderBinding(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantLdapAuthProviderBindingCreateInput,
  ): Promise<CreatedVersionedView<TenantLdapAuthProviderBindingView>>;
  createTenantLdapMapping(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantLdapMappingCreateInput,
  ): Promise<CreatedVersionedView<TenantLdapMappingView>>;
  dryRunTenantLdapMappings(
    csrfToken: string,
    tenantId: string,
    input: TenantLdapMappingDryRunInput,
    signal?: AbortSignal,
  ): Promise<TenantLdapMappingDryRunResultView>;
  enrollBootstrap(input: {
    bootstrapToken: string;
    email: string;
  }): Promise<BootstrapEnrollmentView>;
  deactivatePlatformAuthProvider(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformAuthProviderDeactivationInput,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  deactivatePlatformOidcDirectLogin(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformOidcDirectLoginCommandInput,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  deactivatePlatformAuthProviderTenantBinding(
    csrfToken: string,
    providerId: string,
    bindingId: string,
    current: VersionedView<PlatformAuthProviderTenantBindingView>,
    auditReason: string,
    input: PlatformAuthProviderTenantBindingDeactivationInput,
  ): Promise<VersionedView<PlatformAuthProviderTenantBindingView>>;
  replacePlatformSamlMetadata(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformSamlMetadataReplaceInput,
  ): Promise<PlatformSamlMaterialMutationView>;
  replacePlatformSamlSpKey(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformSamlSpKeyReplaceInput,
  ): Promise<PlatformSamlMaterialMutationView>;
  clearPlatformSamlSpKey(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformSamlSpKeyClearInput,
  ): Promise<PlatformSamlMaterialMutationView>;
  getBootstrapStatus(): Promise<{ available: boolean }>;
  getOperatorTeamAssignmentEpoch(
    tenantId: string,
    operatorTeamId: string,
    assignmentEpochId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<OperatorTeamAssignmentEpochView>>;
  getPlatformOperatorTeam(
    operatorTeamId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<OperatorTeamView>>;
  getPlatformAuthProvider(
    providerId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  getPlatformAuthProviderAccount(
    providerId: string,
    accountId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<PlatformAuthProviderAccountView>>;
  getPlatformAuthProviderTenantBinding(
    providerId: string,
    bindingId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<PlatformAuthProviderTenantBindingView>>;
  getPlatformLocalAccount(
    accountId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<PlatformLocalAccountView>>;
  getSession(): Promise<SessionView | null>;
  getTenantAuthority(
    tenantId: string,
    signal?: AbortSignal,
  ): Promise<TenantAuthorityView>;
  getTenantRole(
    tenantId: string,
    roleId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantRoleView>>;
  getTenantSecurityGroup(
    tenantId: string,
    groupId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantSecurityGroupView>>;
  getTenantServiceAccount(
    tenantId: string,
    serviceAccountId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<ServiceAccountView>>;
  getTenantLdapAuthProvider(
    tenantId: string,
    providerId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantLdapAuthProviderView>>;
  getTenantLdapAuthProviderBinding(
    tenantId: string,
    bindingId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantLdapAuthProviderBindingView>>;
  getTenantLdapMapping(
    tenantId: string,
    mappingId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantLdapMappingView>>;
  getTenantLdapSyncRun(
    tenantId: string,
    bindingId: string,
    syncRunId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantLdapSyncRunView>>;
  getTenantLdapSyncStatus(
    tenantId: string,
    bindingId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<TenantLdapSyncStatusView>>;
  getTenantServiceAccountCredential(
    tenantId: string,
    serviceAccountId: string,
    credentialId: string,
    signal?: AbortSignal,
  ): Promise<VersionedView<ServiceAccountCredentialView>>;
  grantTenantSecurityGroupRole(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    idempotencyKey: string,
    input: TenantSecurityGroupRoleGrantInput,
  ): Promise<VersionedView<TenantSecurityGroupRoleGrantView>>;
  grantTenantServiceAccountRole(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    input: ServiceAccountRoleGrantInput,
  ): Promise<VersionedView<ServiceAccountRoleGrantView>>;
  grantUserRole(
    csrfToken: string,
    tenantId: string,
    userId: string,
    idempotencyKey: string,
    input: DirectUserRoleGrantInput,
  ): Promise<VersionedView<DirectUserRoleGrantView>>;
  listMemberships(after?: string): Promise<TenantMembershipPageView>;
  listOperatorTeamRosterEntries(
    tenantId: string,
    operatorTeamId: string,
    assignmentEpochId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<OperatorTeamRosterEntryPageView>;
  listPlatformOperatorTeams(options?: {
    after?: string;
    includeArchived?: boolean;
    signal?: AbortSignal;
  }): Promise<OperatorTeamPageView>;
  listPlatformAuthProviders(options?: {
    after?: string;
    includeArchived?: boolean;
    signal?: AbortSignal;
  }): Promise<PlatformAuthProviderPageView>;
  listPlatformAuthProviderAccounts(
    providerId: string,
    options?: {
      after?: string;
      includeRetired?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<PlatformAuthProviderAccountPageView>;
  listPlatformAuthProviderTenantBindings(
    providerId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<PlatformAuthProviderTenantBindingPageView>;
  listPlatformLocalAccounts(options?: {
    after?: string;
    includeDisabled?: boolean;
    signal?: AbortSignal;
  }): Promise<PlatformLocalAccountPageView>;
  listSessions(after?: string): Promise<SessionPageView>;
  listTenantPermissions(
    tenantId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<TenantPermissionPageView>;
  listTenantOperatorTeamAssignmentEpochs(
    tenantId: string,
    options?: {
      after?: string;
      includeEnded?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<OperatorTeamAssignmentEpochPageView>;
  listTenantRoles(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantRolePageView>;
  listTenantSecurityGroupMemberships(
    tenantId: string,
    groupId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantSecurityGroupMembershipPageView>;
  listTenantSecurityGroupRoleGrants(
    tenantId: string,
    groupId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantSecurityGroupRoleGrantPageView>;
  listTenantSecurityGroups(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantSecurityGroupPageView>;
  listTenantServiceAccountCredentials(
    tenantId: string,
    serviceAccountId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<ServiceAccountCredentialPageView>;
  listTenantServiceAccountRoleGrants(
    tenantId: string,
    serviceAccountId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<ServiceAccountRoleGrantPageView>;
  listTenantServiceAccounts(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<ServiceAccountPageView>;
  listTenantLdapAuthProviders(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantLdapAuthProviderPageView>;
  listTenantLdapAuthProviderBindings(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantLdapAuthProviderBindingPageView>;
  listTenantLdapMappings(
    tenantId: string,
    options?: {
      after?: string;
      bindingId?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantLdapMappingPageView>;
  listTenantLdapSyncRuns(
    tenantId: string,
    bindingId: string,
    options?: { after?: string; signal?: AbortSignal },
  ): Promise<TenantLdapSyncRunPageView>;
  listTenantUsers(
    tenantId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<TenantUserPageView>;
  changeTenantMembershipLifecycle(
    csrfToken: string,
    tenantId: string,
    userId: string,
    targetStatus: "active" | "suspended",
    current: Pick<TenantUserSummaryView, "etag" | "lifecycleRevision">,
    idempotencyKey: string,
    reason: string,
  ): Promise<TenantMembershipLifecycleReceiptView>;
  listTenants(after?: string): Promise<TenantPageView>;
  listUserRoleGrants(
    tenantId: string,
    userId: string,
    options?: {
      after?: string;
      includeRevoked?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<DirectUserRoleGrantPageView>;
  login(input: {
    email: string;
    password: string;
  }): Promise<LoginChallengeView>;
  logout(csrfToken: string): Promise<LogoutResultView | null>;
  issueTenantServiceAccountCredential(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    idempotencyKey: string,
    input: ServiceAccountCredentialIssueInput,
  ): Promise<ServiceAccountCredentialSecretView>;
  revokeSession(csrfToken: string, sessionId: string): Promise<void>;
  suspendTenant(
    csrfToken: string,
    tenantId: string,
    etag: string,
    input: TenantLifecycleChangeInput,
  ): Promise<VersionedView<TenantLifecycleReceiptView>>;
  archiveTenantRole(
    csrfToken: string,
    tenantId: string,
    roleId: string,
    etag: string,
  ): Promise<void>;
  replaceTenantRolePolicy(
    csrfToken: string,
    tenantId: string,
    roleId: string,
    etag: string,
    policy: TenantRolePolicyInput,
  ): Promise<VersionedView<TenantRoleView>>;
  replacePlatformOidcAuthProviderClientSecret(
    csrfToken: string,
    providerId: string,
    etag: string,
    auditReason: string,
    input: PlatformOidcClientSecretReplaceInput,
  ): Promise<string>;
  prelinkPlatformAuthProviderAccount(
    csrfToken: string,
    providerId: string,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformAuthProviderAccountPrelinkInput,
  ): Promise<CreatedVersionedView<PlatformAuthProviderAccountView>>;
  invitePlatformLocalAccount(
    csrfToken: string,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformLocalAccountInviteInput,
  ): Promise<PlatformLocalAccountInvitationView>;
  recoverPlatformLocalAccount(
    csrfToken: string,
    accountId: string,
    current: VersionedView<PlatformLocalAccountView>,
    idempotencyKey: string,
    auditReason: string,
  ): Promise<PlatformLocalAccountMutationView>;
  retirePlatformAuthProviderAccount(
    csrfToken: string,
    providerId: string,
    accountId: string,
    current: VersionedView<PlatformAuthProviderAccountView>,
    auditReason: string,
  ): Promise<VersionedView<PlatformAuthProviderAccountView>>;
  rotatePlatformLocalAccountPassword(
    csrfToken: string,
    accountId: string,
    current: VersionedView<PlatformLocalAccountView>,
    idempotencyKey: string,
    auditReason: string,
    input: PlatformLocalAccountPasswordRotationInput,
  ): Promise<PlatformLocalAccountMutationView>;
  archiveTenantSecurityGroup(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    etag: string,
  ): Promise<void>;
  revokeTenantSecurityGroupMembership(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    membershipId: string,
    etag: string,
    input: AuthorizationEdgeRevokeInput,
  ): Promise<void>;
  revokeTenantSecurityGroupRoleGrant(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    grantId: string,
    etag: string,
    input: AuthorizationEdgeRevokeInput,
  ): Promise<void>;
  revokeTenantServiceAccountCredential(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    credentialId: string,
    etag: string,
    input: ServiceAccountCredentialRevokeInput,
  ): Promise<void>;
  revokeTenantServiceAccountRoleGrant(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    grantId: string,
    etag: string,
    input: ServiceAccountRoleGrantRevokeInput,
  ): Promise<void>;
  rotateTenantServiceAccountCredential(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    credentialId: string,
    etag: string,
    idempotencyKey: string,
    input: ServiceAccountCredentialRotateInput,
  ): Promise<ServiceAccountCredentialSecretView>;
  revokeRoleGrant(
    csrfToken: string,
    tenantId: string,
    grantId: string,
    etag: string,
    input: RoleGrantRevokeInput,
  ): Promise<void>;
  revokeOperatorTeamRosterEntry(
    csrfToken: string,
    tenantId: string,
    operatorTeamId: string,
    assignmentEpochId: string,
    rosterEntryId: string,
    etag: string,
    input: AuthorizationEdgeRevokeInput,
  ): Promise<void>;
  startOperatorTeamAssignmentEpoch(
    csrfToken: string,
    tenantId: string,
    operatorTeamId: string,
    idempotencyKey: string,
    input: OperatorTeamAssignmentEpochStartInput,
  ): Promise<VersionedView<OperatorTeamAssignmentEpochView>>;
  endOperatorTeamAssignmentEpoch(
    csrfToken: string,
    tenantId: string,
    operatorTeamId: string,
    assignmentEpochId: string,
    etag: string,
    input: OperatorTeamAssignmentEpochEndInput,
  ): Promise<void>;
  switchTenant(csrfToken: string, tenantId: string): Promise<SessionView>;
  setTenantLdapAuthProviderBindSecret(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantLdapBindSecretWriteInput,
  ): Promise<string>;
  searchTenantLdapAuthProviderUser(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    input: TenantLdapUserSearchTestInput,
    signal?: AbortSignal,
  ): Promise<TenantLdapUserSearchTestResultView>;
  clearTenantLdapAuthProviderBindSecret(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantLdapBindSecretClearInput,
  ): Promise<string>;
  testTenantLdapAuthProviderConnection(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    signal?: AbortSignal,
  ): Promise<TenantLdapAuthProviderDiagnosticView>;
  testTenantLdapAuthProviderBind(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    signal?: AbortSignal,
  ): Promise<TenantLdapAuthProviderDiagnosticView>;
  testPlatformLdapProvider(
    csrfToken: string,
    providerId: string,
    auditReason: string,
    input: PlatformLdapTestInput,
    signal?: AbortSignal,
  ): Promise<PlatformLdapDiagnosticView>;
  testTenantLdapAuthProviderFilter(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    input: TenantLdapFilterTestInput,
    signal?: AbortSignal,
  ): Promise<TenantLdapFilterTestResultView>;
  startTenantLdapManualSync(
    csrfToken: string,
    tenantId: string,
    bindingId: string,
    etag: string,
    idempotencyKey: string,
    input: TenantLdapManualSyncInput,
  ): Promise<CreatedVersionedView<TenantLdapSyncRunView>>;
  updateTenantRole(
    csrfToken: string,
    tenantId: string,
    roleId: string,
    etag: string,
    input: TenantRolePatchInput,
  ): Promise<VersionedView<TenantRoleView>>;
  updateTenantSecurityGroup(
    csrfToken: string,
    tenantId: string,
    groupId: string,
    etag: string,
    input: TenantSecurityGroupPatchInput,
  ): Promise<VersionedView<TenantSecurityGroupView>>;
  updateTenantServiceAccount(
    csrfToken: string,
    tenantId: string,
    serviceAccountId: string,
    etag: string,
    input: ServiceAccountPatchInput,
  ): Promise<VersionedView<ServiceAccountView>>;
  updateTenantLdapAuthProvider(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantLdapAuthProviderUpdateInput,
  ): Promise<string>;
  updateTenantLdapAuthProviderBinding(
    csrfToken: string,
    tenantId: string,
    bindingId: string,
    etag: string,
    input: TenantLdapAuthProviderBindingUpdateInput,
  ): Promise<VersionedView<TenantLdapAuthProviderBindingView>>;
  updateTenantLdapMapping(
    csrfToken: string,
    tenantId: string,
    mappingId: string,
    etag: string,
    input: TenantLdapMappingUpdateInput,
  ): Promise<VersionedView<TenantLdapMappingView>>;
  updatePlatformOperatorTeam(
    csrfToken: string,
    operatorTeamId: string,
    etag: string,
    input: OperatorTeamPatchInput,
  ): Promise<VersionedView<OperatorTeamView>>;
  updatePlatformAuthProvider(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformAuthProviderView>,
    auditReason: string,
    input: PlatformAuthProviderUpdateInput,
  ): Promise<VersionedView<PlatformAuthProviderView>>;
  updatePlatformLdapAuthProvider(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformLdapAuthProviderView>,
    auditReason: string,
    input: PlatformLdapAuthProviderUpdateInput,
  ): Promise<VersionedView<PlatformLdapAuthProviderView>>;
  setPlatformLdapLoginState(
    csrfToken: string,
    providerId: string,
    current: VersionedView<PlatformLdapAuthProviderView>,
    auditReason: string,
    input: PlatformLdapLoginStateInput,
  ): Promise<VersionedView<PlatformLdapAuthProviderView>>;
  updatePlatformAuthProviderTenantBinding(
    csrfToken: string,
    providerId: string,
    bindingId: string,
    current: VersionedView<PlatformAuthProviderTenantBindingView>,
    auditReason: string,
    input: PlatformAuthProviderTenantBindingUpdateInput,
  ): Promise<VersionedView<PlatformAuthProviderTenantBindingView>>;
}

export class PhaseTwoApiError extends Error {
  readonly code: string | undefined;
  readonly credentialId: string | undefined;
  readonly location: string | undefined;
  readonly status: number | undefined;

  constructor(
    message: string,
    status?: number,
    metadata?: {
      code?: string;
      credentialId?: string;
      location?: string;
    },
  ) {
    super(message);
    this.name = "PhaseTwoApiError";
    this.status = status;
    this.code = metadata?.code;
    this.credentialId = metadata?.credentialId;
    this.location = metadata?.location;
  }
}

export const tenantProjectionMismatchCode = "tenant_projection_mismatch";

export function hasPermission(
  session: SessionView,
  permission: string,
): boolean {
  return session.permissions.includes(permission);
}

export function hasTenantPermission(
  authority: TenantAuthorityView,
  permissionKey: TenantPermissionKeyView,
  scope: TenantAuthorizationScopeView = "tenant",
): boolean {
  return authority.permissions.some(
    (grant) => grant.permissionKey === permissionKey && grant.scope === scope,
  );
}

export function etagForVersion(version: number): string {
  return `"v${version}"`;
}

export function describePhaseTwoError(
  error: unknown,
  fallback: string,
): string {
  if (error instanceof PhaseTwoApiError && error.message.trim() !== "") {
    return error.message;
  }
  return fallback;
}
