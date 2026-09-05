import {
  addOperatorTeamRosterEntry,
  activatePlatformLocalAccount,
  activatePlatformOidcDirectLogin as activatePlatformOidcDirectLoginRequest,
  activatePlatformAuthProviderTenantBinding,
  activatePlatformAuthProviderTenantExecution,
  archivePlatformAuthProvider,
  archivePlatformAuthProviderTenantBinding,
  archivePlatformOperatorTeam,
  archiveTenantLdapAuthProvider,
  archiveTenantLdapAuthProviderBinding,
  archiveTenantLdapMapping,
  archiveTenantSecurityGroup,
  archiveTenantRole,
  archiveTenantServiceAccount,
  authorizePlatformTenantAccess,
  completeMfaChallenge,
  confirmBootstrap,
  createPlatformOperatorTeam,
  createPlatformAuthProvider,
  createPlatformAuthProviderTenantBinding,
  createPlatformTenant,
  createTenantLdapAuthProvider,
  createTenantLdapAuthProviderBinding,
  createTenantLdapMapping,
  createTenantSecurityGroup,
  createTenantSecurityGroupMembership,
  createTenantRole,
  createTenantServiceAccount,
  clearPlatformSamlAuthProviderSpKey,
  deactivatePlatformAuthProviderTenantBinding,
  deactivatePlatformAuthProviderTenantExecution,
  deactivatePlatformOidcDirectLogin as deactivatePlatformOidcDirectLoginRequest,
  disablePlatformLocalAccount,
  dryRunTenantLdapMappings,
  enablePlatformLocalAccount,
  getBootstrapStatus,
  getCurrentSession,
  getOperatorTeamAssignmentEpoch,
  getPlatformOperatorTeam,
  getPlatformAuthProvider,
  getPlatformAuthProviderAccount,
  getPlatformAuthProviderTenantBinding,
  getPlatformLocalAccount,
  getTenantAuthority,
  getTenantLdapAuthProvider,
  getTenantLdapAuthProviderBinding,
  getTenantLdapMapping,
  getTenantLdapSyncRun,
  getTenantLdapSyncStatus,
  getTenantSecurityGroup,
  getTenantRole,
  getTenantServiceAccount,
  getTenantServiceAccountCredential,
  grantTenantSecurityGroupRole,
  grantTenantServiceAccountRole,
  grantUserRole,
  listOperatorTeamRosterEntries,
  listPlatformOperatorTeams,
  listPlatformAuthProviderAccounts,
  listPlatformAuthProviders,
  listPlatformAuthProviderTenantBindings,
  listPlatformLocalAccounts,
  listPlatformTenants,
  listSessions,
  listTenantMemberships,
  listTenantOperatorTeamAssignmentEpochs,
  listTenantPermissions,
  listTenantLdapAuthProviders,
  listTenantLdapAuthProviderBindings,
  listTenantLdapMappings,
  listTenantLdapSyncRuns,
  listTenantRoles,
  listTenantServiceAccountCredentials,
  listTenantServiceAccountRoleGrants,
  listTenantServiceAccounts,
  listTenantSecurityGroupMemberships,
  listTenantSecurityGroupRoleGrants,
  listTenantSecurityGroups,
  listTenantUsers,
  listUserRoleGrants,
  logoutCurrentSession,
  issueTenantServiceAccountCredential,
  invitePlatformLocalAccount,
  replaceTenantRolePolicy,
  replacePlatformLdapBindSecret,
  replacePlatformOidcAuthProviderClientSecret,
  replacePlatformSamlAuthProviderMetadata,
  replacePlatformSamlAuthProviderSpKey,
  prelinkPlatformAuthProviderAccount,
  putPlatformLdapMapping,
  reactivatePlatformTenant,
  reactivateTenantMembership,
  recoverPlatformLocalAccount,
  revokeOperatorTeamRosterEntry,
  revokeRoleGrant,
  retirePlatformAuthProviderAccount,
  revokeSession,
  revokeTenantSecurityGroupMembership,
  revokeTenantSecurityGroupRoleGrant,
  revokeTenantServiceAccountCredential,
  revokeTenantServiceAccountRoleGrant,
  rotateTenantServiceAccountCredential,
  rotatePlatformLocalAccountPassword,
  searchTenantLdapAuthProviderUser,
  setPlatformLdapLoginState,
  setTenantLdapAuthProviderBindSecret,
  clearTenantLdapAuthProviderBindSecret,
  startBootstrapEnrollment,
  startOperatorTeamAssignmentEpoch,
  startPasswordLogin,
  startTenantLdapManualSync,
  switchActiveTenant,
  suspendPlatformTenant,
  suspendTenantMembership,
  testPlatformLdapProvider,
  testTenantLdapAuthProviderBind,
  testTenantLdapAuthProviderConnection,
  testTenantLdapAuthProviderFilter,
  endOperatorTeamAssignmentEpoch,
  updatePlatformOperatorTeam,
  updatePlatformAuthProvider,
  updatePlatformLdapAuthProvider,
  updatePlatformAuthProviderTenantBinding,
  updateTenantRole,
  updateTenantSecurityGroup,
  updateTenantServiceAccount,
  updateTenantLdapAuthProvider,
  updateTenantLdapAuthProviderBinding,
  updateTenantLdapMapping,
  type AuthorizationEdgeProvenance,
  type BootstrapEnrollment,
  type BootstrapResult,
  type DirectUserRoleGrant,
  type DirectUserRoleGrantList,
  type EffectiveTenantRoleGrant,
  type MfaChallenge,
  type OperatorTeam,
  type OperatorTeamAssignmentEpoch,
  type OperatorTeamAssignmentEpochList,
  type OperatorTeamList,
  type OperatorTeamRosterEntry,
  type OperatorTeamRosterEntryList,
  type PlatformAuthProvider,
  type PlatformAuthProviderAccount,
  type PlatformAuthProviderAccountList,
  type PlatformAuthProviderList,
  type PlatformAuthProviderSummary,
  type PlatformAuthProviderTenantBinding,
  type PlatformAuthProviderTenantBindingList,
  type PlatformLdapAuthProvider,
  type PlatformLdapDiagnostic,
  type PlatformLocalAccount,
  type PlatformLocalAccountList,
  type PlatformLocalAccountMutationResult,
  type PlatformTenantAccessReceipt,
  type Session,
  type SessionList,
  type ServiceAccount,
  type ServiceAccountCredential,
  type ServiceAccountCredentialList,
  type ServiceAccountCredentialSecret,
  type ServiceAccountList,
  type ServiceAccountRoleGrant,
  type ServiceAccountRoleGrantList,
  type TenantAuthority,
  type TenantList,
  type TenantLifecycleReceipt,
  type TenantLdapAuthProvider,
  type TenantLdapAuthProviderBinding,
  type TenantLdapAuthProviderBindingList,
  type TenantLdapAuthProviderDiagnostic,
  type TenantLdapAuthProviderList,
  type TenantLdapAuthProviderSummary,
  type TenantLdapFilterTestResult,
  type TenantLdapMapping,
  type TenantLdapMappingDryRunResult,
  type TenantLdapMappingList,
  type TenantLdapSyncRun,
  type TenantLdapSyncRunList,
  type TenantLdapSyncStatus,
  type TenantLdapUserSearchTestResult,
  type TenantMembershipList,
  type TenantMembershipLifecycleReceipt,
  type TenantPermission,
  type TenantPermissionList,
  type TenantRole,
  type TenantRoleList,
  type TenantRoleSummary,
  type TenantSecurityGroup,
  type TenantSecurityGroupList,
  type TenantSecurityGroupMembership,
  type TenantSecurityGroupMembershipList,
  type TenantSecurityGroupRoleGrant,
  type TenantSecurityGroupRoleGrantList,
  type TenantSummary,
  type TenantUserList,
  type TenantUserSummary,
} from "@periapsis/contracts";

import {
  PhaseTwoApiError,
  tenantAuthorizationScopes,
  tenantPermissionKeys,
  tenantProjectionMismatchCode,
  type PhaseTwoApi,
  type DirectUserRoleGrantPageView,
  type DirectUserRoleGrantView,
  type EffectiveTenantRoleGrantView,
  type SessionView,
  type OperatorTeamAssignmentEpochPageView,
  type OperatorTeamAssignmentEpochView,
  type OperatorTeamPageView,
  type OperatorTeamRosterEntryPageView,
  type OperatorTeamRosterEntryView,
  type OperatorTeamView,
  type PlatformAuthProviderPageView,
  type PlatformAuthProviderAccountPageView,
  type PlatformAuthProviderAccountView,
  type PlatformAuthProviderCreateInput,
  type PlatformAuthProviderSummaryView,
  type PlatformAuthProviderTenantBindingPageView,
  type PlatformAuthProviderTenantBindingView,
  type PlatformAuthProviderUpdateInput,
  type PlatformAuthProviderView,
  type PlatformLdapAuthProviderUpdateInput,
  type PlatformLdapAuthProviderView,
  type PlatformLdapDiagnosticView,
  type PlatformLocalAccountMutationView,
  type PlatformLocalAccountPageView,
  type PlatformLocalAccountView,
  type PlatformTenantAccessReceiptView,
  type PlatformSamlMaterialMutationView,
  type TenantAuthorityView,
  type TenantLdapAuthProviderDiagnosticView,
  type TenantLdapAuthProviderBindingPageView,
  type TenantLdapAuthProviderBindingView,
  type TenantLdapAuthProviderPageView,
  type TenantLdapAuthProviderSummaryView,
  type TenantLdapAuthProviderView,
  type TenantLdapFilterTestResultView,
  type TenantLdapMappingDryRunResultView,
  type TenantLdapMappingPageView,
  type TenantLdapMappingView,
  type TenantLdapSyncRunPageView,
  type TenantLdapSyncRunView,
  type TenantLdapSyncStatusView,
  type TenantLdapUserSearchTestResultView,
  type TenantLifecycleReceiptView,
  type LogoutResultView,
  type TenantMembershipLifecycleReceiptView,
  type TenantPageView,
  type TenantPermissionPageView,
  type TenantPermissionView,
  type TenantRolePageView,
  type TenantRoleView,
  type TenantSecurityGroupMembershipPageView,
  type TenantSecurityGroupMembershipView,
  type TenantSecurityGroupPageView,
  type TenantSecurityGroupRoleGrantPageView,
  type TenantSecurityGroupRoleGrantView,
  type TenantSecurityGroupView,
  type ServiceAccountCredentialPageView,
  type ServiceAccountCredentialSecretView,
  type ServiceAccountCredentialView,
  type ServiceAccountPageView,
  type ServiceAccountRoleGrantPageView,
  type ServiceAccountRoleGrantView,
  type ServiceAccountView,
  type TenantUserPageView,
  type TenantUserSummaryView,
  type TenantView,
  type VersionedView,
} from "./phase-two-types";
import {
  derivePlatformAuthProviderDeploymentEndpoints,
  isCanonicalPlatformText,
  isPlatformAuditReasonHeader,
  isPlatformAbsoluteUri,
  isPlatformHttpsUri as isContractPlatformHttpsUri,
  isPlatformOidcClientId,
  isPlatformOidcExtraScopes,
  isPlatformProviderKey,
  isPlatformUnicodeScalarText,
  isPlatformXml10Text,
  platformUtf8ByteLength,
} from "./platform-auth-provider-validation";
import { parseRfc3339Instant } from "./rfc3339-instant";
import { sessionAwareFetch } from "./session-transition-transport";
import { canonicalizeServiceAccountCredentialNetworks } from "./service-account-networks";
import { isCanonicalUuidV7 } from "./uuid-v7";

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const tenantPermissionKeySet = new Set<string>(tenantPermissionKeys);
const tenantAuthorizationScopeSet = new Set<string>(tenantAuthorizationScopes);
const resourceStrongEntityTagPattern =
  /^"v([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])"$/;
const platformAuthProviderAccountStrongEntityTagPattern =
  /^"v([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])-u([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])"$/;
const platformLocalAccountStrongEntityTagPattern = /^"v([1-9]\d{0,15})"$/;
const platformAuthProviderTenantBindingStrongEntityTagPattern =
  /^"v([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])-t([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])"$/;
// A 32-byte unpadded base64url digest has 42 full characters and a final
// character whose unused low two bits are zero. Restricting that final sextet
// makes the textual representation canonical, matching the Go parser.
const edgeStrongEntityTagPattern =
  /^"v([1-9]\d{0,8}|1\d{9}|20\d{8}|21[0-3]\d{7}|214[0-6]\d{6}|2147[0-3]\d{5}|21474[0-7]\d{4}|214748[0-2]\d{3}|2147483[0-5]\d{2}|21474836[0-3]\d|214748364[0-7])-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"$/;
const maximumResourceVersion = 2_147_483_647;
const directRoleSourceTypeByKind: Readonly<Record<string, string>> = {
  identity_mapping: "identity_provider",
  manual: "direct",
  platform_recovery: "system",
  system: "system",
  tenant_creation: "system",
};

export const phaseTwoApi: PhaseTwoApi = {
  async getBootstrapStatus() {
    const result = await getBootstrapStatus(sameOrigin);
    return unwrap(result);
  },

  async enrollBootstrap(input) {
    const result = await startBootstrapEnrollment({
      ...sameOrigin,
      body: { email: input.email },
      headers: {
        "X-Periapsis-Bootstrap-Token": input.bootstrapToken,
      },
    });
    return toBootstrapEnrollment(unwrap(result));
  },

  async confirmBootstrap(input) {
    const result = await confirmBootstrap({
      ...sameOrigin,
      body: {
        code: input.code,
        displayName: input.displayName,
        email: input.email,
        enrollmentToken: input.enrollmentToken,
        password: input.password,
      },
      headers: {
        "X-Periapsis-Bootstrap-Token": input.bootstrapToken,
      },
    });
    return toBootstrapResult(unwrap(result));
  },

  async login(input) {
    const result = await startPasswordLogin({
      ...sameOrigin,
      body: input,
    });
    return toLoginChallenge(unwrap(result));
  },

  async completeMfa(input) {
    const result = await completeMfaChallenge({
      ...sameOrigin,
      body: input,
    });
    return toSessionView(unwrap(result));
  },

  async getSession() {
    const result = await getCurrentSession(sameOrigin);
    if (result.response?.status === 401) {
      return null;
    }
    return toSessionView(unwrap(result));
  },

  async logout(csrfToken) {
    const result = await logoutCurrentSession({
      ...sameOrigin,
      headers: csrfHeaders(csrfToken),
    });
    return unwrapLogoutResult(result);
  },

  async listMemberships(after) {
    const result = await listTenantMemberships({
      ...sameOrigin,
      query: { ...(after ? { after } : {}), limit: 50 },
    });
    return toMemberships(unwrap(result));
  },

  async listSessions(after) {
    const result = await listSessions({
      ...sameOrigin,
      query: { ...(after ? { after } : {}), limit: 50 },
    });
    return toSessions(unwrap(result));
  },

  async revokeSession(csrfToken, sessionId) {
    const result = await revokeSession({
      ...sameOrigin,
      headers: csrfHeaders(csrfToken),
      path: { sessionId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async switchTenant(csrfToken, tenantId) {
    const result = await switchActiveTenant({
      ...sameOrigin,
      body: { tenantId },
      headers: csrfHeaders(csrfToken),
    });
    return toSessionView(unwrap(result));
  },

  async listTenants(after) {
    const result = await listPlatformTenants({
      ...sameOrigin,
      query: {
        limit: 50,
        ...(after ? { after } : {}),
      },
    });
    return toTenantPage(unwrap(result));
  },

  async createTenant(csrfToken, input) {
    const result = await createPlatformTenant({
      ...sameOrigin,
      body: input,
      headers: csrfHeaders(csrfToken),
    });
    return toTenantView(unwrap(result));
  },

  async authorizePlatformTenantAccess(
    csrfToken,
    tenantId,
    etag,
    idempotencyKey,
    input,
  ) {
    const result = await authorizePlatformTenantAccess({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
      },
      path: { tenantId },
    });
    return unwrapPlatformTenantAccessMutation(
      result,
      tenantId,
      input.expectedVersion,
    );
  },

  async suspendTenant(csrfToken, tenantId, etag, input) {
    const result = await suspendPlatformTenant({
      ...sameOrigin,
      body: input,
      headers: { ...csrfHeaders(csrfToken), "If-Match": etag },
      path: { tenantId },
    });
    return unwrapTenantLifecycleMutation(
      result,
      tenantId,
      input.expectedVersion,
      "active",
      "suspended",
    );
  },

  async reactivateTenant(csrfToken, tenantId, etag, input) {
    const result = await reactivatePlatformTenant({
      ...sameOrigin,
      body: input,
      headers: { ...csrfHeaders(csrfToken), "If-Match": etag },
      path: { tenantId },
    });
    return unwrapTenantLifecycleMutation(
      result,
      tenantId,
      input.expectedVersion,
      "suspended",
      "active",
    );
  },

  async listPlatformLocalAccounts(options) {
    const result = await listPlatformLocalAccounts({
      ...sameOrigin,
      cache: "no-store",
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeDisabled === undefined
          ? {}
          : { includeDisabled: options.includeDisabled }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertPlatformLocalAccountSuccessStatus(result.response, 200, "list");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    return toPlatformLocalAccountPage(
      unwrap(result),
      options?.after,
      options?.includeDisabled === true,
    );
  },

  async getPlatformLocalAccount(accountId, signal) {
    const result = await getPlatformLocalAccount({
      ...sameOrigin,
      cache: "no-store",
      path: { localAccountId: accountId },
      ...(signal ? { signal } : {}),
    });
    assertPlatformLocalAccountSuccessStatus(result.response, 200, "detail");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const account = unwrapPlatformLocalAccountVersioned(result);
    if (account.value.id !== accountId) throw tenantProjectionError();
    return account;
  },

  async invitePlatformLocalAccount(
    csrfToken,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformLocalAccountInviteInput(input);
    assertPlatformLocalAccountMutationHeaders(idempotencyKey, auditReason);
    const result = await invitePlatformLocalAccount({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "X-Audit-Reason": auditReason,
      },
    });
    assertPlatformLocalAccountSuccessStatus(result.response, 201, "invite");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const mutation = unwrapPlatformLocalAccountMutation(result, true);
    const location = result.response?.headers.get("Location");
    if (
      mutation.account.value.status !== "invited" ||
      mutation.account.value.revision !== 1 ||
      mutation.account.value.identityEpoch !== 1 ||
      mutation.account.value.displayName !== input.displayName ||
      mutation.account.value.loginIdentifier !== input.loginIdentifier ||
      mutation.account.value.protectedRecoveryPrincipal !==
        input.protectedRecoveryPrincipal ||
      location !==
        `/api/v1/platform/local-accounts/${mutation.account.value.id}`
    ) {
      throw tenantProjectionError();
    }
    return { ...mutation, location };
  },

  async activatePlatformLocalAccount(
    csrfToken,
    accountId,
    current,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformLocalAccountActivationInput(input);
    assertPlatformLocalAccountMutationContext(
      accountId,
      current,
      idempotencyKey,
      auditReason,
    );
    const result = await activatePlatformLocalAccount({
      ...sameOrigin,
      body: { ...input, expectedRevision: current.value.revision },
      cache: "no-store",
      headers: platformLocalAccountHeaders(
        csrfToken,
        current.etag,
        idempotencyKey,
        auditReason,
      ),
      path: { localAccountId: accountId },
    });
    return finishPlatformLocalAccountMutation(
      result,
      accountId,
      current,
      false,
      "activate",
    );
  },

  async disablePlatformLocalAccount(
    csrfToken,
    accountId,
    current,
    idempotencyKey,
    auditReason,
  ) {
    assertPlatformLocalAccountMutationContext(
      accountId,
      current,
      idempotencyKey,
      auditReason,
    );
    const result = await disablePlatformLocalAccount({
      ...sameOrigin,
      body: { expectedRevision: current.value.revision },
      cache: "no-store",
      headers: platformLocalAccountHeaders(
        csrfToken,
        current.etag,
        idempotencyKey,
        auditReason,
      ),
      path: { localAccountId: accountId },
    });
    return finishPlatformLocalAccountMutation(
      result,
      accountId,
      current,
      false,
      "disable",
    );
  },

  async enablePlatformLocalAccount(
    csrfToken,
    accountId,
    current,
    idempotencyKey,
    auditReason,
  ) {
    assertPlatformLocalAccountMutationContext(
      accountId,
      current,
      idempotencyKey,
      auditReason,
    );
    const result = await enablePlatformLocalAccount({
      ...sameOrigin,
      body: { expectedRevision: current.value.revision },
      cache: "no-store",
      headers: platformLocalAccountHeaders(
        csrfToken,
        current.etag,
        idempotencyKey,
        auditReason,
      ),
      path: { localAccountId: accountId },
    });
    return finishPlatformLocalAccountMutation(
      result,
      accountId,
      current,
      false,
      "enable",
    );
  },

  async recoverPlatformLocalAccount(
    csrfToken,
    accountId,
    current,
    idempotencyKey,
    auditReason,
  ) {
    assertPlatformLocalAccountMutationContext(
      accountId,
      current,
      idempotencyKey,
      auditReason,
    );
    const result = await recoverPlatformLocalAccount({
      ...sameOrigin,
      body: { expectedRevision: current.value.revision },
      cache: "no-store",
      headers: platformLocalAccountHeaders(
        csrfToken,
        current.etag,
        idempotencyKey,
        auditReason,
      ),
      path: { localAccountId: accountId },
    });
    return finishPlatformLocalAccountMutation(
      result,
      accountId,
      current,
      true,
      "recover",
    );
  },

  async rotatePlatformLocalAccountPassword(
    csrfToken,
    accountId,
    current,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformLocalAccountPasswordInput(input);
    assertPlatformLocalAccountMutationContext(
      accountId,
      current,
      idempotencyKey,
      auditReason,
    );
    const result = await rotatePlatformLocalAccountPassword({
      ...sameOrigin,
      body: { ...input, expectedRevision: current.value.revision },
      cache: "no-store",
      headers: platformLocalAccountHeaders(
        csrfToken,
        current.etag,
        idempotencyKey,
        auditReason,
      ),
      path: { localAccountId: accountId },
    });
    return finishPlatformLocalAccountMutation(
      result,
      accountId,
      current,
      false,
      "password rotation",
    );
  },

  async listPlatformAuthProviders(options) {
    const result = await listPlatformAuthProviders({
      ...sameOrigin,
      cache: "no-store",
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "list");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    return toPlatformAuthProviderPage(unwrap(result), options?.after);
  },

  async listPlatformAuthProviderAccounts(providerId, options) {
    const result = await listPlatformAuthProviderAccounts({
      ...sameOrigin,
      cache: "no-store",
      path: { providerId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRetired === undefined
          ? {}
          : { includeRetired: options.includeRetired }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertPlatformAuthProviderAccountSuccessStatus(
      result.response,
      200,
      "list",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    return toPlatformAuthProviderAccountPage(
      unwrap(result),
      providerId,
      options?.after,
      options?.includeRetired === true,
    );
  },

  async listPlatformAuthProviderTenantBindings(providerId, options) {
    const result = await listPlatformAuthProviderTenantBindings({
      ...sameOrigin,
      cache: "no-store",
      path: { providerId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertPlatformAuthProviderBindingSuccessStatus(
      result.response,
      200,
      "list",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    return toPlatformAuthProviderTenantBindingPage(
      unwrap(result),
      providerId,
      options?.after,
    );
  },

  async createPlatformAuthProvider(
    csrfToken,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    assertPlatformAuthProviderCreateConfiguration(input);
    const result = await createPlatformAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "X-Audit-Reason": auditReason,
      },
    });
    const created = unwrapCreatedPlatformAuthProvider(result);
    // An idempotent replay returns the provider's current live projection. Its
    // mutable key may therefore differ from the version-1 create request, while
    // the response Location remains bound to the immutable provider id.
    if (
      created.value.kind !== input.kind ||
      (created.value.version === 1 &&
        !matchesPlatformAuthProviderInitialCreate(created.value, input))
    ) {
      throw tenantProjectionError();
    }
    return created;
  },

  async createPlatformAuthProviderTenantBinding(
    csrfToken,
    providerId,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await createPlatformAuthProviderTenantBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    const created = unwrapCreatedPlatformAuthProviderTenantBinding(
      result,
      providerId,
    );
    if (
      created.value.tenant.id !== input.tenantId ||
      created.value.providerId !== providerId ||
      (created.value.version === 1 &&
        (created.value.loginKey !== input.loginKey ||
          created.value.profilePriority !== input.profilePriority ||
          created.value.enabled ||
          created.value.activationAvailable ||
          created.value.currentAccessEpochId !== null ||
          created.value.jitMode !== "disabled" ||
          created.value.noMatchPolicy !== "deny" ||
          created.value.archivedAt !== null ||
          created.value.authRevision !== 1 ||
          created.value.mappingRevision !== 1 ||
          parseRfc3339Instant(created.value.createdAt) !==
            parseRfc3339Instant(created.value.updatedAt)))
    ) {
      throw tenantProjectionError();
    }
    return created;
  },

  async prelinkPlatformAuthProviderAccount(
    csrfToken,
    providerId,
    idempotencyKey,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await prelinkPlatformAuthProviderAccount({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    const created = unwrapCreatedPlatformAuthProviderAccount(
      result,
      providerId,
    );
    if (created.value.user.id !== input.userId) {
      throw tenantProjectionError();
    }
    return created;
  },

  async getPlatformAuthProvider(providerId, signal) {
    const result = await getPlatformAuthProvider({
      ...sameOrigin,
      cache: "no-store",
      path: { providerId },
      ...(signal ? { signal } : {}),
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "detail");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertResourceId(provider.value.id, providerId);
    return provider;
  },

  async updatePlatformLdapAuthProvider(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformLdapMutationPrecondition(
      current,
      providerId,
      input.expectedVersion,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await updatePlatformLdapAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "update");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformLdapAuthProvider);
    assertPlatformLdapConfigurationMutationProjection(
      provider,
      current.value,
      providerId,
      input,
    );
    return provider;
  },

  async replacePlatformLdapBindSecret(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformLdapMutationPrecondition(
      current,
      providerId,
      input.expectedVersion,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await replacePlatformLdapBindSecret({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    const etag = unwrapBodylessPlatformAuthProviderMutationEtag(
      result,
      current.etag,
      input.expectedVersion,
      "The API returned payload data from the write-only platform LDAP bind-secret endpoint.",
    );
    const rawSecretRevision = result.response?.headers.get(
      "X-Periapsis-LDAP-Secret-Revision",
    );
    if (!rawSecretRevision || !/^[1-9][0-9]{0,15}$/u.test(rawSecretRevision)) {
      throw tenantProjectionError();
    }
    const secretRevision = Number(rawSecretRevision);
    if (
      !Number.isSafeInteger(secretRevision) ||
      secretRevision < 2 ||
      secretRevision > maximumResourceVersion
    ) {
      throw tenantProjectionError();
    }
    return etag;
  },

  async putPlatformLdapMapping(
    csrfToken,
    providerId,
    mappingId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformLdapCurrentProjection(current, providerId);
    if (!canonicalUuidV7Pattern.test(mappingId)) throw tenantProjectionError();
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await putPlatformLdapMapping({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "X-Audit-Reason": auditReason,
      },
      path: { mappingId, providerId },
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "update");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformLdapAuthProvider);
    assertPlatformLdapMappingMutationProjection(
      provider,
      current.value,
      providerId,
      mappingId,
      input,
    );
    return provider;
  },

  async setPlatformLdapLoginState(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformLdapMutationPrecondition(
      current,
      providerId,
      input.expectedVersion,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await setPlatformLdapLoginState({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "update");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformLdapAuthProvider);
    assertPlatformLdapLoginStateProjection(
      provider,
      current.value,
      providerId,
      input.enabled,
    );
    return provider;
  },

  async testPlatformLdapProvider(
    csrfToken,
    providerId,
    auditReason,
    input,
    signal,
  ) {
    if (!canonicalUuidV7Pattern.test(providerId)) throw tenantProjectionError();
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await testPlatformLdapProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
      ...(signal ? { signal } : {}),
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "update");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    return toPlatformLdapDiagnostic(unwrap(result));
  },

  async getPlatformAuthProviderAccount(providerId, accountId, signal) {
    const result = await getPlatformAuthProviderAccount({
      ...sameOrigin,
      cache: "no-store",
      path: { accountId, providerId },
      ...(signal ? { signal } : {}),
    });
    assertPlatformAuthProviderAccountSuccessStatus(
      result.response,
      200,
      "detail",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const account = unwrapPlatformAuthProviderAccountVersioned(result);
    assertPlatformAuthProviderAccountPath(account.value, providerId, accountId);
    return account;
  },

  async getPlatformAuthProviderTenantBinding(providerId, bindingId, signal) {
    const result = await getPlatformAuthProviderTenantBinding({
      ...sameOrigin,
      cache: "no-store",
      path: { bindingId, providerId },
      ...(signal ? { signal } : {}),
    });
    assertPlatformAuthProviderBindingSuccessStatus(
      result.response,
      200,
      "detail",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const binding = unwrapPlatformAuthProviderTenantBindingVersioned(result);
    assertPlatformAuthProviderTenantBindingProjection(
      binding.value,
      providerId,
      bindingId,
    );
    return binding;
  },

  async activatePlatformOidcDirectLogin(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderDirectLoginPrecondition(
      current,
      providerId,
      input.expectedVersion,
      "activate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await activatePlatformOidcDirectLoginRequest({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(
      result.response,
      200,
      "direct-login activation",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertPlatformAuthProviderDirectLoginProjection(
      provider,
      current.value,
      providerId,
      input.expectedVersion,
      true,
    );
    return provider;
  },

  async activatePlatformAuthProvider(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderLifecyclePrecondition(
      current,
      providerId,
      input.expectedVersion,
      "activate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await activatePlatformAuthProviderTenantExecution({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "activation");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertPlatformAuthProviderLifecycleProjection(
      provider,
      current.value,
      providerId,
      input.expectedVersion,
    );
    if (
      !provider.value.enabled ||
      provider.value.activationAvailable ||
      provider.value.platformLoginEnabled !==
        current.value.platformLoginEnabled ||
      provider.value.accountMode !== input.accountMode ||
      provider.value.archivedAt !== null
    ) {
      throw tenantProjectionError();
    }
    return provider;
  },

  async deactivatePlatformAuthProvider(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderLifecyclePrecondition(
      current,
      providerId,
      input.expectedVersion,
      "deactivate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await deactivatePlatformAuthProviderTenantExecution({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(
      result.response,
      200,
      "deactivation",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertPlatformAuthProviderLifecycleProjection(
      provider,
      current.value,
      providerId,
      input.expectedVersion,
    );
    if (
      provider.value.enabled ||
      provider.value.platformLoginEnabled !==
        current.value.platformLoginEnabled ||
      provider.value.accountMode !== "disabled" ||
      provider.value.archivedAt !== null
    ) {
      throw tenantProjectionError();
    }
    return provider;
  },

  async deactivatePlatformOidcDirectLogin(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderDirectLoginPrecondition(
      current,
      providerId,
      input.expectedVersion,
      "deactivate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await deactivatePlatformOidcDirectLoginRequest({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(
      result.response,
      200,
      "direct-login deactivation",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertPlatformAuthProviderDirectLoginProjection(
      provider,
      current.value,
      providerId,
      input.expectedVersion,
      false,
    );
    return provider;
  },

  async activatePlatformAuthProviderTenantBinding(
    csrfToken,
    providerId,
    bindingId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderTenantBindingLifecyclePrecondition(
      current,
      providerId,
      bindingId,
      input.expectedVersion,
      input.expectedTenantVersion,
      "activate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await activatePlatformAuthProviderTenantBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { bindingId, providerId },
    });
    assertPlatformAuthProviderBindingSuccessStatus(
      result.response,
      200,
      "activation",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const binding = unwrapPlatformAuthProviderTenantBindingVersioned(result);
    assertPlatformAuthProviderTenantBindingLifecycleProjection(
      binding,
      current.value,
      providerId,
      bindingId,
      input.expectedVersion,
      input.expectedTenantVersion,
    );
    if (
      !binding.value.enabled ||
      binding.value.activationAvailable ||
      binding.value.currentAccessEpochId === null ||
      binding.value.authRevision !== current.value.authRevision + 1 ||
      binding.value.mappingRevision !== current.value.mappingRevision + 1 ||
      binding.value.jitMode !== input.jitMode ||
      binding.value.noMatchPolicy !== input.noMatchPolicy ||
      binding.value.loginKey !== current.value.loginKey ||
      binding.value.profilePriority !== current.value.profilePriority
    ) {
      throw tenantProjectionError();
    }
    return binding;
  },

  async deactivatePlatformAuthProviderTenantBinding(
    csrfToken,
    providerId,
    bindingId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderTenantBindingLifecyclePrecondition(
      current,
      providerId,
      bindingId,
      input.expectedVersion,
      input.expectedTenantVersion,
      "deactivate",
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await deactivatePlatformAuthProviderTenantBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { bindingId, providerId },
    });
    assertPlatformAuthProviderBindingSuccessStatus(
      result.response,
      200,
      "deactivation",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const binding = unwrapPlatformAuthProviderTenantBindingVersioned(result);
    assertPlatformAuthProviderTenantBindingLifecycleProjection(
      binding,
      current.value,
      providerId,
      bindingId,
      input.expectedVersion,
      input.expectedTenantVersion,
    );
    if (
      binding.value.enabled ||
      binding.value.currentAccessEpochId !== null ||
      binding.value.authRevision !== current.value.authRevision + 1 ||
      binding.value.mappingRevision !== current.value.mappingRevision ||
      binding.value.jitMode !== "disabled" ||
      binding.value.noMatchPolicy !== "deny" ||
      binding.value.loginKey !== current.value.loginKey ||
      binding.value.profilePriority !== current.value.profilePriority
    ) {
      throw tenantProjectionError();
    }
    return binding;
  },

  async updatePlatformAuthProvider(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderMutationPrecondition(
      current.etag,
      input.expectedVersion,
    );
    if (
      current.value.id !== providerId ||
      current.value.version !== input.expectedVersion ||
      input.key !== current.value.key ||
      current.value.archivedAt !== null
    ) {
      throw tenantProjectionError();
    }
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await updatePlatformAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    assertPlatformAuthProviderSuccessStatus(result.response, 200, "update");
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toPlatformAuthProvider);
    assertPlatformAuthProviderMetadataProjection(
      provider,
      current.value,
      providerId,
      input,
    );
    return provider;
  },

  async updatePlatformAuthProviderTenantBinding(
    csrfToken,
    providerId,
    bindingId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderTenantBindingMutationPrecondition(
      current.etag,
      input.expectedVersion,
      input.expectedTenantVersion,
    );
    assertPlatformAuthProviderTenantBindingProjection(
      current.value,
      providerId,
      bindingId,
    );
    if (
      current.value.version !== input.expectedVersion ||
      current.value.tenant.version !== input.expectedTenantVersion ||
      current.value.archivedAt !== null ||
      current.value.enabled
    ) {
      throw tenantProjectionError();
    }
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await updatePlatformAuthProviderTenantBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { bindingId, providerId },
    });
    assertPlatformAuthProviderBindingSuccessStatus(
      result.response,
      200,
      "update",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const binding = unwrapPlatformAuthProviderTenantBindingVersioned(result);
    assertPlatformAuthProviderTenantBindingMutationProjection(
      binding,
      providerId,
      bindingId,
      input.expectedVersion,
      input.expectedTenantVersion,
      current.value,
    );
    if (
      binding.value.loginKey !== input.loginKey ||
      binding.value.profilePriority !== input.profilePriority
    ) {
      throw new Error(
        "The API returned tenant-binding metadata that does not match the accepted update.",
      );
    }
    return binding;
  },

  async archivePlatformAuthProvider(
    csrfToken,
    providerId,
    etag,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderMutationPrecondition(etag, input.expectedVersion);
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await archivePlatformAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    return unwrapBodylessPlatformAuthProviderMutationEtag(
      result,
      etag,
      input.expectedVersion,
      "The API returned payload data from the bodyless platform identity-provider archive endpoint.",
    );
  },

  async archivePlatformAuthProviderTenantBinding(
    csrfToken,
    providerId,
    bindingId,
    etag,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderTenantBindingMutationPrecondition(
      etag,
      input.expectedVersion,
      input.expectedTenantVersion,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await archivePlatformAuthProviderTenantBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
        "X-Audit-Reason": auditReason,
      },
      path: { bindingId, providerId },
    });
    return unwrapBodylessPlatformAuthProviderTenantBindingMutationEtag(
      result,
      etag,
      input.expectedVersion,
      input.expectedTenantVersion,
      "The API returned payload data from the bodyless platform identity-provider tenant-binding archive endpoint.",
    );
  },

  async replacePlatformOidcAuthProviderClientSecret(
    csrfToken,
    providerId,
    etag,
    auditReason,
    input,
  ) {
    assertPlatformAuthProviderMutationPrecondition(etag, input.expectedVersion);
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await replacePlatformOidcAuthProviderClientSecret({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    return unwrapBodylessPlatformAuthProviderMutationEtag(
      result,
      etag,
      input.expectedVersion,
      "The API returned payload data from the write-only platform identity-provider secret endpoint.",
    );
  },

  async replacePlatformSamlMetadata(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformSAMLMaterialPrecondition(
      current,
      providerId,
      input.expectedVersion,
      "metadata",
      false,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await replacePlatformSamlAuthProviderMetadata({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    return unwrapPlatformSAMLMaterialMutation(
      result,
      current,
      "metadata",
      "The SAML metadata endpoint returned an invalid bodyless mutation receipt.",
    );
  },

  async replacePlatformSamlSpKey(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformSAMLMaterialPrecondition(
      current,
      providerId,
      input.expectedVersion,
      "sp-key",
      false,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await replacePlatformSamlAuthProviderSpKey({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    return unwrapPlatformSAMLMaterialMutation(
      result,
      current,
      "sp-key",
      "The SAML SP-key endpoint returned an invalid bodyless mutation receipt.",
    );
  },

  async clearPlatformSamlSpKey(
    csrfToken,
    providerId,
    current,
    auditReason,
    input,
  ) {
    assertPlatformSAMLMaterialPrecondition(
      current,
      providerId,
      input.expectedVersion,
      "sp-key",
      true,
    );
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await clearPlatformSamlAuthProviderSpKey({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { providerId },
    });
    return unwrapPlatformSAMLMaterialMutation(
      result,
      current,
      "sp-key",
      "The SAML SP-key clear endpoint returned an invalid bodyless mutation receipt.",
    );
  },

  async retirePlatformAuthProviderAccount(
    csrfToken,
    providerId,
    accountId,
    current,
    auditReason,
  ) {
    assertPlatformAuthProviderAccountPath(current.value, providerId, accountId);
    assertPlatformAuthProviderAccountEntityTag(
      current.etag,
      current.value.version,
      current.value.user.version,
    );
    if (current.value.version >= maximumResourceVersion) {
      throw new PhaseTwoApiError(
        "The platform identity-account version cannot be incremented safely.",
      );
    }
    assertPlatformAuthProviderAuditReasonHeader(auditReason);
    const result = await retirePlatformAuthProviderAccount({
      ...sameOrigin,
      body: { expectedVersion: current.value.version },
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": current.etag,
        "X-Audit-Reason": auditReason,
      },
      path: { accountId, providerId },
    });
    assertPlatformAuthProviderAccountSuccessStatus(
      result.response,
      200,
      "retire",
    );
    assertPlatformAuthProviderNoStoreResponse(result.response);
    const retired = unwrapPlatformAuthProviderAccountVersioned(result);
    assertPlatformAuthProviderAccountRetirement(current.value, retired.value);
    return retired;
  },

  async listPlatformOperatorTeams(options) {
    const result = await listPlatformOperatorTeams({
      ...sameOrigin,
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    return toOperatorTeamPage(unwrap(result));
  },

  async createPlatformOperatorTeam(csrfToken, idempotencyKey, input) {
    const result = await createPlatformOperatorTeam({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
    });
    const team = unwrapVersioned(result, toOperatorTeam);
    assertResourceId(team.value.key, input.key);
    return team;
  },

  async getPlatformOperatorTeam(operatorTeamId, signal) {
    const result = await getPlatformOperatorTeam({
      ...sameOrigin,
      path: { operatorTeamId },
      ...(signal ? { signal } : {}),
    });
    const team = unwrapVersioned(result, toOperatorTeam);
    assertResourceId(team.value.id, operatorTeamId);
    return team;
  },

  async updatePlatformOperatorTeam(csrfToken, operatorTeamId, etag, input) {
    const result = await updatePlatformOperatorTeam({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { operatorTeamId },
    });
    const team = unwrapVersioned(result, toOperatorTeam);
    assertResourceId(team.value.id, operatorTeamId);
    return team;
  },

  async archivePlatformOperatorTeam(csrfToken, operatorTeamId, etag, input) {
    const result = await archivePlatformOperatorTeam({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { operatorTeamId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async getTenantAuthority(tenantId, signal) {
    const result = await getTenantAuthority({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    const authority = toTenantAuthority(unwrap(result));
    assertTenantId(authority.tenantId, tenantId);
    return authority;
  },

  async listTenantOperatorTeamAssignmentEpochs(tenantId, options) {
    const result = await listTenantOperatorTeamAssignmentEpochs({
      ...sameOrigin,
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeEnded === undefined
          ? {}
          : { includeEnded: options.includeEnded }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toOperatorTeamAssignmentEpochPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async startOperatorTeamAssignmentEpoch(
    csrfToken,
    tenantId,
    operatorTeamId,
    idempotencyKey,
    input,
  ) {
    const result = await startOperatorTeamAssignmentEpoch({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { operatorTeamId, tenantId },
    });
    const epoch = unwrapVersioned(result, toOperatorTeamAssignmentEpoch);
    assertOperatorTeamEpochProjection(epoch.value, tenantId, operatorTeamId);
    return epoch;
  },

  async getOperatorTeamAssignmentEpoch(
    tenantId,
    operatorTeamId,
    assignmentEpochId,
    signal,
  ) {
    const result = await getOperatorTeamAssignmentEpoch({
      ...sameOrigin,
      path: { assignmentEpochId, operatorTeamId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const epoch = unwrapVersioned(result, toOperatorTeamAssignmentEpoch);
    assertOperatorTeamEpochProjection(
      epoch.value,
      tenantId,
      operatorTeamId,
      assignmentEpochId,
    );
    return epoch;
  },

  async endOperatorTeamAssignmentEpoch(
    csrfToken,
    tenantId,
    operatorTeamId,
    assignmentEpochId,
    etag,
    input,
  ) {
    const result = await endOperatorTeamAssignmentEpoch({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { assignmentEpochId, operatorTeamId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listOperatorTeamRosterEntries(
    tenantId,
    operatorTeamId,
    assignmentEpochId,
    options,
  ) {
    const result = await listOperatorTeamRosterEntries({
      ...sameOrigin,
      path: { assignmentEpochId, operatorTeamId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toOperatorTeamRosterEntryPage(unwrap(result));
    assertOperatorTeamRosterProjection(
      page.items,
      tenantId,
      operatorTeamId,
      assignmentEpochId,
    );
    return page;
  },

  async addOperatorTeamRosterEntry(
    csrfToken,
    tenantId,
    operatorTeamId,
    assignmentEpochId,
    idempotencyKey,
    input,
  ) {
    const result = await addOperatorTeamRosterEntry({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { assignmentEpochId, operatorTeamId, tenantId },
    });
    const entry = unwrapEdgeVersioned(result, toOperatorTeamRosterEntry);
    assertOperatorTeamRosterProjection(
      [entry.value],
      tenantId,
      operatorTeamId,
      assignmentEpochId,
    );
    assertResourceId(entry.value.member.membershipId, input.membershipId);
    return entry;
  },

  async revokeOperatorTeamRosterEntry(
    csrfToken,
    tenantId,
    operatorTeamId,
    assignmentEpochId,
    rosterEntryId,
    etag,
    input,
  ) {
    const result = await revokeOperatorTeamRosterEntry({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: {
        assignmentEpochId,
        operatorTeamId,
        rosterEntryId,
        tenantId,
      },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantPermissions(tenantId, after, signal) {
    const result = await listTenantPermissions({
      ...sameOrigin,
      path: { tenantId },
      query: { ...(after ? { after } : {}), limit: 50 },
      ...(signal ? { signal } : {}),
    });
    return toTenantPermissionPage(unwrap(result));
  },

  async listTenantRoles(tenantId, options) {
    const result = await listTenantRoles({
      ...sameOrigin,
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toTenantRolePage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async createTenantRole(csrfToken, tenantId, idempotencyKey, input) {
    const result = await createTenantRole({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId },
    });
    const role = unwrapVersioned(result, toTenantRole);
    assertTenantId(role.value.tenantId, tenantId);
    if (role.value.key !== input.key) {
      throw tenantProjectionError();
    }
    return role;
  },

  async listTenantSecurityGroups(tenantId, options) {
    const result = await listTenantSecurityGroups({
      ...sameOrigin,
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toTenantSecurityGroupPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async createTenantSecurityGroup(csrfToken, tenantId, idempotencyKey, input) {
    const result = await createTenantSecurityGroup({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId },
    });
    const group = unwrapVersioned(result, toTenantSecurityGroup);
    assertTenantId(group.value.tenantId, tenantId);
    if (group.value.key !== input.key) {
      throw tenantProjectionError();
    }
    return group;
  },

  async getTenantSecurityGroup(tenantId, groupId, signal) {
    const result = await getTenantSecurityGroup({
      ...sameOrigin,
      path: { groupId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const group = unwrapVersioned(result, toTenantSecurityGroup);
    assertTenantId(group.value.tenantId, tenantId);
    if (group.value.id !== groupId) {
      throw tenantProjectionError();
    }
    return group;
  },

  async updateTenantSecurityGroup(csrfToken, tenantId, groupId, etag, input) {
    const result = await updateTenantSecurityGroup({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { groupId, tenantId },
    });
    const group = unwrapVersioned(result, toTenantSecurityGroup);
    assertTenantId(group.value.tenantId, tenantId);
    if (group.value.id !== groupId) {
      throw tenantProjectionError();
    }
    return group;
  },

  async archiveTenantSecurityGroup(csrfToken, tenantId, groupId, etag) {
    const result = await archiveTenantSecurityGroup({
      ...sameOrigin,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { groupId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantSecurityGroupMemberships(tenantId, groupId, options) {
    const result = await listTenantSecurityGroupMemberships({
      ...sameOrigin,
      path: { groupId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toTenantSecurityGroupMembershipPage(unwrap(result));
    assertMembershipEdges(page.items, tenantId, groupId);
    return page;
  },

  async createTenantSecurityGroupMembership(
    csrfToken,
    tenantId,
    groupId,
    idempotencyKey,
    input,
  ) {
    const result = await createTenantSecurityGroupMembership({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { groupId, tenantId },
    });
    const edge = unwrapEdgeVersioned(result, toTenantSecurityGroupMembership);
    assertMembershipEdges([edge.value], tenantId, groupId);
    assertResourceId(edge.value.member.user.id, input.userId);
    return edge;
  },

  async revokeTenantSecurityGroupMembership(
    csrfToken,
    tenantId,
    groupId,
    membershipId,
    etag,
    input,
  ) {
    const result = await revokeTenantSecurityGroupMembership({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { groupId, membershipId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantSecurityGroupRoleGrants(tenantId, groupId, options) {
    const result = await listTenantSecurityGroupRoleGrants({
      ...sameOrigin,
      path: { groupId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toTenantSecurityGroupRoleGrantPage(unwrap(result));
    assertGroupRoleEdges(page.items, tenantId, groupId);
    return page;
  },

  async grantTenantSecurityGroupRole(
    csrfToken,
    tenantId,
    groupId,
    idempotencyKey,
    input,
  ) {
    const result = await grantTenantSecurityGroupRole({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { groupId, tenantId },
    });
    const edge = unwrapEdgeVersioned(result, toTenantSecurityGroupRoleGrant);
    assertGroupRoleEdges([edge.value], tenantId, groupId);
    assertResourceId(edge.value.role.id, input.roleId);
    return edge;
  },

  async revokeTenantSecurityGroupRoleGrant(
    csrfToken,
    tenantId,
    groupId,
    grantId,
    etag,
    input,
  ) {
    const result = await revokeTenantSecurityGroupRoleGrant({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { grantId, groupId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async getTenantRole(tenantId, roleId, signal) {
    const result = await getTenantRole({
      ...sameOrigin,
      path: { roleId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const role = unwrapVersioned(result, toTenantRole);
    assertTenantId(role.value.tenantId, tenantId);
    assertResourceId(role.value.id, roleId);
    return role;
  },

  async updateTenantRole(csrfToken, tenantId, roleId, etag, input) {
    const result = await updateTenantRole({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { roleId, tenantId },
    });
    const role = unwrapVersioned(result, toTenantRole);
    assertTenantId(role.value.tenantId, tenantId);
    assertResourceId(role.value.id, roleId);
    return role;
  },

  async replaceTenantRolePolicy(csrfToken, tenantId, roleId, etag, policy) {
    const result = await replaceTenantRolePolicy({
      ...sameOrigin,
      body: policy,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { roleId, tenantId },
    });
    const role = unwrapVersioned(result, toTenantRole);
    assertTenantId(role.value.tenantId, tenantId);
    assertResourceId(role.value.id, roleId);
    return role;
  },

  async archiveTenantRole(csrfToken, tenantId, roleId, etag) {
    const result = await archiveTenantRole({
      ...sameOrigin,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { roleId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantLdapAuthProviders(tenantId, options) {
    const result = await listTenantLdapAuthProviders({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const page = toTenantLdapAuthProviderPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async createTenantLdapAuthProvider(
    csrfToken,
    tenantId,
    idempotencyKey,
    input,
  ) {
    const result = await createTenantLdapAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId },
    });
    assertLdapNoStoreResponse(result.response);
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
    return {
      location: assertTenantLdapProviderLocation(
        result.response.headers.get("Location"),
        tenantId,
      ),
    };
  },

  async getTenantLdapAuthProvider(tenantId, providerId, signal) {
    const result = await getTenantLdapAuthProvider({
      ...sameOrigin,
      cache: "no-store",
      path: { providerId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const provider = unwrapVersioned(result, toTenantLdapAuthProvider);
    assertTenantLdapProviderProjection(provider.value, tenantId, providerId);
    return provider;
  },

  async updateTenantLdapAuthProvider(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
  ) {
    const result = await updateTenantLdapAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { providerId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async archiveTenantLdapAuthProvider(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
  ) {
    const result = await archiveTenantLdapAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { providerId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async setTenantLdapAuthProviderBindSecret(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
  ) {
    const result = await setTenantLdapAuthProviderBindSecret({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { providerId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async clearTenantLdapAuthProviderBindSecret(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
  ) {
    const result = await clearTenantLdapAuthProviderBindSecret({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { providerId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async testTenantLdapAuthProviderConnection(
    csrfToken,
    tenantId,
    providerId,
    signal,
  ) {
    const result = await testTenantLdapAuthProviderConnection({
      ...sameOrigin,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { providerId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    return toTenantLdapAuthProviderDiagnostic(unwrap(result));
  },

  async testTenantLdapAuthProviderBind(
    csrfToken,
    tenantId,
    providerId,
    signal,
  ) {
    const result = await testTenantLdapAuthProviderBind({
      ...sameOrigin,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { providerId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    return toTenantLdapAuthProviderDiagnostic(unwrap(result));
  },

  async searchTenantLdapAuthProviderUser(
    csrfToken,
    tenantId,
    providerId,
    input,
    signal,
  ) {
    const result = await searchTenantLdapAuthProviderUser({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { providerId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    return toTenantLdapUserSearchTestResult(unwrap(result));
  },

  async testTenantLdapAuthProviderFilter(
    csrfToken,
    tenantId,
    providerId,
    input,
    signal,
  ) {
    const result = await testTenantLdapAuthProviderFilter({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { providerId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    return toTenantLdapFilterTestResult(unwrap(result));
  },

  async listTenantLdapAuthProviderBindings(tenantId, options) {
    const result = await listTenantLdapAuthProviderBindings({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const page = toTenantLdapAuthProviderBindingPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async createTenantLdapAuthProviderBinding(
    csrfToken,
    tenantId,
    idempotencyKey,
    input,
  ) {
    const result = await createTenantLdapAuthProviderBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId },
    });
    const created = unwrapCreatedLdapVersioned(
      result,
      toTenantLdapAuthProviderBinding,
      `/api/v1/tenants/${tenantId}/auth-provider-bindings/`,
    );
    assertTenantLdapBindingProjection(
      created.value,
      tenantId,
      created.value.id,
      input.providerId,
    );
    return created;
  },

  async getTenantLdapAuthProviderBinding(tenantId, bindingId, signal) {
    const result = await getTenantLdapAuthProviderBinding({
      ...sameOrigin,
      cache: "no-store",
      path: { bindingId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const binding = unwrapVersioned(result, toTenantLdapAuthProviderBinding);
    assertTenantLdapBindingProjection(binding.value, tenantId, bindingId);
    return binding;
  },

  async updateTenantLdapAuthProviderBinding(
    csrfToken,
    tenantId,
    bindingId,
    etag,
    input,
  ) {
    const result = await updateTenantLdapAuthProviderBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { bindingId, tenantId },
    });
    assertLdapNoStoreResponse(result.response);
    const binding = unwrapVersioned(result, toTenantLdapAuthProviderBinding);
    assertTenantLdapBindingProjection(binding.value, tenantId, bindingId);
    return binding;
  },

  async archiveTenantLdapAuthProviderBinding(
    csrfToken,
    tenantId,
    bindingId,
    etag,
    input,
  ) {
    const result = await archiveTenantLdapAuthProviderBinding({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { bindingId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async listTenantLdapMappings(tenantId, options) {
    const result = await listTenantLdapMappings({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.bindingId ? { bindingId: options.bindingId } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const page = toTenantLdapMappingPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    if (
      options?.bindingId &&
      page.items.some((mapping) => mapping.bindingId !== options.bindingId)
    ) {
      throw tenantProjectionError();
    }
    return page;
  },

  async createTenantLdapMapping(csrfToken, tenantId, idempotencyKey, input) {
    const result = await createTenantLdapMapping({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId },
    });
    const created = unwrapCreatedLdapVersioned(
      result,
      toTenantLdapMapping,
      `/api/v1/tenants/${tenantId}/ldap-mappings/`,
    );
    assertTenantLdapMappingProjection(
      created.value,
      tenantId,
      created.value.id,
      input.bindingId,
    );
    return created;
  },

  async dryRunTenantLdapMappings(csrfToken, tenantId, input, signal) {
    const result = await dryRunTenantLdapMappings({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const dryRun = toTenantLdapMappingDryRunResult(unwrap(result));
    assertResourceId(dryRun.snapshot.bindingId, input.bindingId);
    return dryRun;
  },

  async getTenantLdapMapping(tenantId, mappingId, signal) {
    const result = await getTenantLdapMapping({
      ...sameOrigin,
      cache: "no-store",
      path: { mappingId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const mapping = unwrapVersioned(result, toTenantLdapMapping);
    assertTenantLdapMappingProjection(mapping.value, tenantId, mappingId);
    return mapping;
  },

  async updateTenantLdapMapping(csrfToken, tenantId, mappingId, etag, input) {
    const result = await updateTenantLdapMapping({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { mappingId, tenantId },
    });
    assertLdapNoStoreResponse(result.response);
    const mapping = unwrapVersioned(result, toTenantLdapMapping);
    assertTenantLdapMappingProjection(mapping.value, tenantId, mappingId);
    return mapping;
  },

  async archiveTenantLdapMapping(csrfToken, tenantId, mappingId, etag, input) {
    const result = await archiveTenantLdapMapping({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { mappingId, tenantId },
    });
    return unwrapLdapMutationEtag(result, etag);
  },

  async getTenantLdapSyncStatus(tenantId, bindingId, signal) {
    const result = await getTenantLdapSyncStatus({
      ...sameOrigin,
      cache: "no-store",
      path: { bindingId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const status = unwrapVersioned(result, toTenantLdapSyncStatus);
    assertResourceId(status.value.bindingId, bindingId);
    return status;
  },

  async listTenantLdapSyncRuns(tenantId, bindingId, options) {
    const result = await listTenantLdapSyncRuns({
      ...sameOrigin,
      cache: "no-store",
      path: { bindingId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const page = toTenantLdapSyncRunPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    if (page.items.some((run) => run.bindingId !== bindingId)) {
      throw tenantProjectionError();
    }
    return page;
  },

  async startTenantLdapManualSync(
    csrfToken,
    tenantId,
    bindingId,
    etag,
    idempotencyKey,
    input,
  ) {
    const result = await startTenantLdapManualSync({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
      },
      path: { bindingId, tenantId },
    });
    const created = unwrapCreatedLdapVersioned(
      result,
      toTenantLdapSyncRun,
      `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}/sync-runs/`,
    );
    assertTenantLdapSyncRunProjection(created.value, tenantId, bindingId);
    return created;
  },

  async getTenantLdapSyncRun(tenantId, bindingId, syncRunId, signal) {
    const result = await getTenantLdapSyncRun({
      ...sameOrigin,
      cache: "no-store",
      path: { bindingId, syncRunId, tenantId },
      ...(signal ? { signal } : {}),
    });
    assertLdapNoStoreResponse(result.response);
    const run = unwrapVersioned(result, toTenantLdapSyncRun);
    assertTenantLdapSyncRunProjection(
      run.value,
      tenantId,
      bindingId,
      syncRunId,
    );
    return run;
  },

  async listTenantServiceAccounts(tenantId, options) {
    const result = await listTenantServiceAccounts({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toServiceAccountPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async createTenantServiceAccount(csrfToken, tenantId, input) {
    const result = await createTenantServiceAccount({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { tenantId },
    });
    const account = unwrapVersioned(result, toServiceAccount);
    assertTenantId(account.value.tenantId, tenantId);
    assertResourceId(account.value.key, input.key);
    return account;
  },

  async getTenantServiceAccount(tenantId, serviceAccountId, signal) {
    const result = await getTenantServiceAccount({
      ...sameOrigin,
      cache: "no-store",
      path: { serviceAccountId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const account = unwrapVersioned(result, toServiceAccount);
    assertServiceAccountProjection(account.value, tenantId, serviceAccountId);
    return account;
  },

  async updateTenantServiceAccount(
    csrfToken,
    tenantId,
    serviceAccountId,
    etag,
    input,
  ) {
    const result = await updateTenantServiceAccount({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { serviceAccountId, tenantId },
    });
    const account = unwrapVersioned(result, toServiceAccount);
    assertServiceAccountProjection(account.value, tenantId, serviceAccountId);
    return account;
  },

  async archiveTenantServiceAccount(
    csrfToken,
    tenantId,
    serviceAccountId,
    etag,
    input,
  ) {
    const result = await archiveTenantServiceAccount({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { serviceAccountId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantServiceAccountRoleGrants(
    tenantId,
    serviceAccountId,
    options,
  ) {
    const result = await listTenantServiceAccountRoleGrants({
      ...sameOrigin,
      cache: "no-store",
      path: { serviceAccountId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toServiceAccountRoleGrantPage(unwrap(result));
    assertServiceAccountChildProjection(page.items, tenantId, serviceAccountId);
    return page;
  },

  async grantTenantServiceAccountRole(
    csrfToken,
    tenantId,
    serviceAccountId,
    input,
  ) {
    const result = await grantTenantServiceAccountRole({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: csrfHeaders(csrfToken),
      path: { serviceAccountId, tenantId },
    });
    const grant = unwrapEdgeVersioned(result, toServiceAccountRoleGrant);
    assertServiceAccountChildProjection(
      [grant.value],
      tenantId,
      serviceAccountId,
    );
    assertResourceId(grant.value.role.id, input.roleId);
    return grant;
  },

  async revokeTenantServiceAccountRoleGrant(
    csrfToken,
    tenantId,
    serviceAccountId,
    grantId,
    etag,
    input,
  ) {
    const result = await revokeTenantServiceAccountRoleGrant({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { grantId, serviceAccountId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async listTenantServiceAccountCredentials(
    tenantId,
    serviceAccountId,
    options,
  ) {
    const result = await listTenantServiceAccountCredentials({
      ...sameOrigin,
      cache: "no-store",
      path: { serviceAccountId, tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toServiceAccountCredentialPage(unwrap(result));
    assertServiceAccountChildProjection(page.items, tenantId, serviceAccountId);
    return page;
  },

  async issueTenantServiceAccountCredential(
    csrfToken,
    tenantId,
    serviceAccountId,
    idempotencyKey,
    input,
  ) {
    const result = await issueTenantServiceAccountCredential({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { serviceAccountId, tenantId },
    });
    assertNoStoreResponse(result.response);
    const secret = unwrapCredentialSecret(result);
    assertServiceAccountChildProjection(
      [secret.credential],
      tenantId,
      serviceAccountId,
    );
    return secret;
  },

  async getTenantServiceAccountCredential(
    tenantId,
    serviceAccountId,
    credentialId,
    signal,
  ) {
    const result = await getTenantServiceAccountCredential({
      ...sameOrigin,
      cache: "no-store",
      path: { credentialId, serviceAccountId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const credential = unwrapVersioned(result, toServiceAccountCredential);
    assertServiceAccountChildProjection(
      [credential.value],
      tenantId,
      serviceAccountId,
    );
    assertResourceId(credential.value.id, credentialId);
    return credential;
  },

  async revokeTenantServiceAccountCredential(
    csrfToken,
    tenantId,
    serviceAccountId,
    credentialId,
    etag,
    input,
  ) {
    const result = await revokeTenantServiceAccountCredential({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { credentialId, serviceAccountId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },

  async rotateTenantServiceAccountCredential(
    csrfToken,
    tenantId,
    serviceAccountId,
    credentialId,
    etag,
    idempotencyKey,
    input,
  ) {
    const result = await rotateTenantServiceAccountCredential({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
      },
      path: { credentialId, serviceAccountId, tenantId },
    });
    assertNoStoreResponse(result.response);
    const secret = unwrapCredentialSecret(result);
    assertServiceAccountChildProjection(
      [secret.credential],
      tenantId,
      serviceAccountId,
    );
    assertResourceId(
      secret.credential.rotatedFromCredentialId ?? "",
      credentialId,
    );
    return secret;
  },

  async listTenantUsers(tenantId, after, signal) {
    const result = await listTenantUsers({
      ...sameOrigin,
      path: { tenantId },
      query: { ...(after ? { after } : {}), limit: 50 },
      ...(signal ? { signal } : {}),
    });
    const page = toTenantUserPage(unwrap(result));
    assertTenantItems(page.items, tenantId);
    return page;
  },

  async changeTenantMembershipLifecycle(
    csrfToken,
    tenantId,
    userId,
    targetStatus,
    current,
    idempotencyKey,
    reason,
  ) {
    assertTenantMembershipEntityTag(current.etag, current.lifecycleRevision);
    const options = {
      ...sameOrigin,
      body: { expectedRevision: current.lifecycleRevision, reason },
      cache: "no-store" as const,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
        "If-Match": current.etag,
      },
      path: { tenantId, userId },
    };
    const result =
      targetStatus === "suspended"
        ? await suspendTenantMembership(options)
        : await reactivateTenantMembership(options);
    return unwrapTenantMembershipLifecycleMutation(
      result,
      tenantId,
      userId,
      targetStatus,
      current.lifecycleRevision,
    );
  },

  async listUserRoleGrants(tenantId, userId, options) {
    const result = await listUserRoleGrants({
      ...sameOrigin,
      path: { tenantId, userId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeRevoked === undefined
          ? {}
          : { includeRevoked: options.includeRevoked }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = toDirectGrantPage(unwrap(result));
    assertDirectGrantTenantProjection(page.items, tenantId);
    if (page.items.some((grant) => grant.userId !== userId)) {
      throw tenantProjectionError();
    }
    return page;
  },

  async grantUserRole(csrfToken, tenantId, userId, idempotencyKey, input) {
    const result = await grantUserRole({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "Idempotency-Key": idempotencyKey,
      },
      path: { tenantId, userId },
    });
    const grant = unwrapEdgeVersioned(result, toDirectGrant);
    assertDirectGrantTenantProjection([grant.value], tenantId);
    if (grant.value.userId !== userId) {
      throw tenantProjectionError();
    }
    assertResourceId(grant.value.role.id, input.roleId);
    return grant;
  },

  async revokeRoleGrant(csrfToken, tenantId, grantId, etag, input) {
    const result = await revokeRoleGrant({
      ...sameOrigin,
      body: input,
      headers: {
        ...csrfHeaders(csrfToken),
        "If-Match": etag,
      },
      path: { grantId, tenantId },
    });
    if (!result.response?.ok) {
      throw toApiError(result.error, result.response);
    }
  },
};

interface GeneratedResult<T> {
  data: T | undefined;
  error?: unknown;
  response?: Response;
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) {
    return result.data;
  }
  throw toApiError(result.error, result.response);
}

function unwrapVersioned<TGenerated, TView extends { version: number }>(
  result: GeneratedResult<TGenerated>,
  map: (value: TGenerated) => TView,
): VersionedView<TView> {
  const value = unwrap(result);
  const etag = result.response?.headers.get("ETag");
  const match = etag ? resourceStrongEntityTagPattern.exec(etag) : null;
  if (!etag || !match) {
    throw new PhaseTwoApiError(
      "The API did not return the required strong resource version.",
    );
  }
  const mapped = map(value);
  assertResourceVersion(mapped.version);
  if (match[1] !== String(mapped.version)) {
    throw tenantProjectionError();
  }
  return { etag, value: mapped };
}

function unwrapPlatformAuthProviderTenantBindingVersioned(
  result: GeneratedResult<PlatformAuthProviderTenantBinding>,
): VersionedView<PlatformAuthProviderTenantBindingView> {
  const value = unwrap(result);
  const etag = result.response?.headers.get("ETag");
  const match = etag
    ? platformAuthProviderTenantBindingStrongEntityTagPattern.exec(etag)
    : null;
  if (!etag || !match) {
    throw new PhaseTwoApiError(
      "The API did not return the required strong tenant-binding representation version.",
    );
  }
  const mapped = toPlatformAuthProviderTenantBinding(value);
  if (
    match[1] !== String(mapped.version) ||
    match[2] !== String(mapped.tenant.version)
  ) {
    throw tenantProjectionError();
  }
  return { etag, value: mapped };
}

function unwrapPlatformAuthProviderAccountVersioned(
  result: GeneratedResult<PlatformAuthProviderAccount>,
): VersionedView<PlatformAuthProviderAccountView> {
  const value = toPlatformAuthProviderAccount(unwrap(result));
  const etag = result.response?.headers.get("ETag");
  if (!etag) {
    throw new PhaseTwoApiError(
      "The API did not return the required strong platform identity-account version.",
    );
  }
  assertPlatformAuthProviderAccountEntityTag(
    etag,
    value.version,
    value.user.version,
  );
  return { etag, value };
}

function unwrapPlatformLocalAccountVersioned(
  result: GeneratedResult<PlatformLocalAccount>,
): VersionedView<PlatformLocalAccountView> {
  const value = toPlatformLocalAccount(unwrap(result));
  const etag = result.response?.headers.get("ETag");
  assertPlatformLocalAccountEntityTag(etag, value.revision);
  return { etag, value };
}

function unwrapPlatformLocalAccountMutation(
  result: GeneratedResult<PlatformLocalAccountMutationResult>,
  allowsCeremonyToken: boolean,
): PlatformLocalAccountMutationView {
  const payload = unwrap(result);
  assertProjectionObject(payload);
  const hasToken = payload.ceremonyToken !== undefined;
  const hasEnrollment = payload.totpEnrollment !== undefined;
  assertExactOwnKeys(
    payload,
    !hasToken && !hasEnrollment
      ? ["account", "replayed"]
      : ["account", "ceremonyToken", "replayed", "totpEnrollment"],
  );
  const account = toPlatformLocalAccount(payload.account);
  const etag = result.response?.headers.get("ETag");
  assertPlatformLocalAccountEntityTag(etag, account.revision);
  if (
    typeof payload.replayed !== "boolean" ||
    hasToken !== hasEnrollment ||
    hasToken !== (allowsCeremonyToken && !payload.replayed) ||
    (hasToken && !isCanonicalPlatformLocalAccountToken(payload.ceremonyToken))
  ) {
    throw tenantProjectionError();
  }
  const totpEnrollment = hasEnrollment
    ? toPlatformLocalAccountTOTPEnrollment(payload.totpEnrollment, account.id)
    : undefined;
  return {
    account: { etag, value: account },
    replayed: payload.replayed,
    ...(payload.ceremonyToken === undefined
      ? {}
      : { ceremonyToken: payload.ceremonyToken }),
    ...(totpEnrollment === undefined ? {} : { totpEnrollment }),
  };
}

function toPlatformLocalAccountTOTPEnrollment(
  input: unknown,
  accountId: string,
): { provisioningUri: string; secret: string } {
  assertProjectionObject(input);
  assertExactOwnKeys(input, ["provisioningUri", "secret"]);
  const secret = input.secret;
  const provisioningUri = input.provisioningUri;
  if (
    typeof secret !== "string" ||
    secret.length < 16 ||
    secret.length > 256 ||
    !/^[A-Z2-7]+$/.test(secret) ||
    /^A+$/.test(secret) ||
    [1, 3, 6].includes(secret.length % 8) ||
    typeof provisioningUri !== "string" ||
    platformUtf8ByteLength(provisioningUri) > 2048 ||
    provisioningUri.trim() !== provisioningUri
  ) {
    throw tenantProjectionError();
  }
  let parsed: URL;
  try {
    parsed = new URL(provisioningUri);
  } catch {
    throw tenantProjectionError();
  }
  const entries = [...parsed.searchParams.entries()];
  const keys = entries.map(([key]) => key);
  const allowedKeys = new Set([
    "algorithm",
    "digits",
    "issuer",
    "period",
    "secret",
  ]);
  const canonicalQuery = new URLSearchParams(
    entries.toSorted(([first], [second]) => first.localeCompare(second)),
  ).toString();
  if (
    parsed.protocol !== "otpauth:" ||
    parsed.hostname !== "totp" ||
    parsed.port !== "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== `/Periapsis:${accountId}` ||
    parsed.hash !== "" ||
    parsed.search.length < 2 ||
    parsed.search.slice(1) !== canonicalQuery ||
    entries.length < 2 ||
    new Set(keys).size !== keys.length ||
    keys.some((key) => !allowedKeys.has(key)) ||
    parsed.searchParams.get("issuer") !== "Periapsis" ||
    parsed.searchParams.get("secret") !== secret ||
    !optionalExactQueryValue(parsed.searchParams, "algorithm", "SHA1") ||
    !optionalExactQueryValue(parsed.searchParams, "digits", "6") ||
    !optionalExactQueryValue(parsed.searchParams, "period", "30") ||
    parsed.href !== provisioningUri
  ) {
    throw tenantProjectionError();
  }
  return { provisioningUri, secret };
}

function optionalExactQueryValue(
  query: URLSearchParams,
  key: string,
  expected: string,
): boolean {
  return !query.has(key) || query.get(key) === expected;
}

function isCanonicalPlatformLocalAccountToken(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value) &&
    value !== "A".repeat(43)
  );
}

function finishPlatformLocalAccountMutation(
  result: GeneratedResult<PlatformLocalAccountMutationResult>,
  accountId: string,
  current: VersionedView<PlatformLocalAccountView>,
  allowsCeremonyToken: boolean,
  operation:
    "activate" | "disable" | "enable" | "password rotation" | "recover",
): PlatformLocalAccountMutationView {
  assertPlatformLocalAccountSuccessStatus(result.response, 200, operation);
  assertPlatformAuthProviderNoStoreResponse(result.response);
  const mutation = unwrapPlatformLocalAccountMutation(
    result,
    allowsCeremonyToken,
  );
  if (mutation.account.value.id !== accountId) throw tenantProjectionError();
  const expectedStatus = {
    activate: "active",
    disable: "disabled",
    enable: "active",
    "password rotation": "active",
    recover: "recovery_restricted",
  }[operation];
  if (
    mutation.account.value.revision !== current.value.revision + 1 ||
    mutation.account.value.identityEpoch !== current.value.identityEpoch + 1 ||
    mutation.account.value.status !== expectedStatus
  ) {
    throw tenantProjectionError();
  }
  return mutation;
}

function assertPlatformLocalAccountMutationContext(
  accountId: string,
  current: VersionedView<PlatformLocalAccountView>,
  idempotencyKey: string,
  auditReason: string,
): void {
  const validated = toPlatformLocalAccount(current.value);
  if (
    accountId !== validated.id ||
    validated.revision >= Number.MAX_SAFE_INTEGER
  ) {
    throw tenantProjectionError();
  }
  assertPlatformLocalAccountEntityTag(current.etag, validated.revision);
  assertPlatformLocalAccountMutationHeaders(idempotencyKey, auditReason);
}

function platformLocalAccountHeaders(
  csrfToken: string,
  etag: string,
  idempotencyKey: string,
  auditReason: string,
) {
  return {
    ...csrfHeaders(csrfToken),
    "Idempotency-Key": idempotencyKey,
    "If-Match": etag,
    "X-Audit-Reason": auditReason,
  };
}

function assertPlatformLocalAccountMutationHeaders(
  idempotencyKey: string,
  auditReason: string,
): void {
  if (
    !/^[A-Za-z0-9._~-]{16,128}$/.test(idempotencyKey) ||
    auditReason.length < 1 ||
    auditReason.length > 500 ||
    auditReason.trim() !== auditReason ||
    !/^[\x21-\x2B\x2D-\x7E](?:[\x20-\x2B\x2D-\x7E]*[\x21-\x2B\x2D-\x7E])?$/.test(
      auditReason,
    )
  ) {
    throw new PhaseTwoApiError(
      "The local-account command headers are invalid.",
    );
  }
}

function assertPlatformAuthProviderCreateConfiguration(
  input: PlatformAuthProviderCreateInput,
): void {
  if (input.kind === "oidc") {
    if (
      !isPlatformOidcClientId(input.configuration.clientId) ||
      !isPlatformOidcExtraScopes(
        input.configuration.extraScopes,
        input.configuration.allowRefreshToken,
      )
    ) {
      throw new PhaseTwoApiError("The platform OIDC configuration is invalid.");
    }
    return;
  }
  if (input.kind !== "saml") return;

  const configuration = input.configuration;
  const xmlValues = [
    configuration.expectedEntityId,
    configuration.spEntityId,
    configuration.acsUrl,
    ...configuration.requestedAuthnContexts,
  ];
  if (configuration.subjectSource === "immutable_attribute") {
    xmlValues.push(
      configuration.subjectAttributeName,
      configuration.subjectAttributeNameFormat,
    );
  }
  if (
    configuration.expectedEntityId === configuration.spEntityId ||
    xmlValues.some((value) => !isPlatformXml10Text(value))
  ) {
    throw new PhaseTwoApiError("The platform SAML configuration is invalid.");
  }
}

function assertPlatformLocalAccountInviteInput(input: unknown): void {
  assertPlatformLocalAccountInputKeys(input, [
    "displayName",
    "loginIdentifier",
    "protectedRecoveryPrincipal",
  ]);
  const value = input;
  if (
    !isCanonicalPlatformText(value.displayName, 1, 160, 160) ||
    !isCanonicalPlatformText(value.loginIdentifier, 3, 320, 320) ||
    value.loginIdentifier !== value.loginIdentifier.toLowerCase() ||
    !/^[^@\s]+@[^@\s]+$/.test(value.loginIdentifier) ||
    typeof value.protectedRecoveryPrincipal !== "boolean"
  ) {
    throw platformLocalAccountInputError();
  }
}

function assertPlatformLocalAccountActivationInput(input: unknown): void {
  assertPlatformLocalAccountInputKeys(input, [
    "ceremonyToken",
    "factorProof",
    "newPassword",
  ]);
  const value = input;
  if (
    !isCanonicalPlatformLocalAccountToken(value.ceremonyToken) ||
    typeof value.factorProof !== "string" ||
    !/^(?:\d{6}|\d{8})$/.test(value.factorProof) ||
    !isPlatformLocalAccountPassword(value.newPassword)
  ) {
    throw platformLocalAccountInputError();
  }
}

function assertPlatformLocalAccountPasswordInput(input: unknown): void {
  assertPlatformLocalAccountInputKeys(input, ["newPassword"]);
  const value = input;
  if (!isPlatformLocalAccountPassword(value.newPassword)) {
    throw platformLocalAccountInputError();
  }
}

function assertPlatformLocalAccountInputKeys(
  input: unknown,
  expected: readonly string[],
): asserts input is Record<PropertyKey, unknown> {
  try {
    assertProjectionObject(input);
    assertExactOwnKeys(input, expected);
  } catch {
    throw platformLocalAccountInputError();
  }
}

function isPlatformLocalAccountPassword(value: unknown): value is string {
  if (typeof value !== "string" || !isPlatformUnicodeScalarText(value)) {
    return false;
  }
  const length = platformUtf8ByteLength(value);
  return length >= 14 && length <= 1024;
}

function platformLocalAccountInputError(): PhaseTwoApiError {
  return new PhaseTwoApiError("The local recovery account command is invalid.");
}

function assertPlatformLocalAccountEntityTag(
  etag: string | null | undefined,
  revision: number,
): asserts etag is string {
  const match = etag
    ? platformLocalAccountStrongEntityTagPattern.exec(etag)
    : null;
  if (
    !match ||
    !Number.isSafeInteger(revision) ||
    revision < 1 ||
    match[1] !== String(revision)
  ) {
    throw tenantProjectionError();
  }
}

function unwrapTenantLifecycleMutation(
  result: GeneratedResult<TenantLifecycleReceipt>,
  tenantId: string,
  expectedVersion: number,
  previousStatus: TenantLifecycleReceiptView["previousStatus"],
  status: TenantLifecycleReceiptView["status"],
): VersionedView<TenantLifecycleReceiptView> {
  if (result.response?.ok) {
    const directives = result.response.headers
      .get("Cache-Control")
      ?.split(",")
      .map((directive) => directive.trim().toLowerCase());
    if (!directives?.includes("no-store")) {
      throw new PhaseTwoApiError(
        "The API did not mark the tenant lifecycle receipt as no-store.",
        result.response.status,
      );
    }
  }
  const receipt = unwrapVersioned(result, toTenantLifecycleReceipt);
  if (
    receipt.value.tenantId !== tenantId ||
    receipt.value.previousStatus !== previousStatus ||
    receipt.value.status !== status ||
    !Number.isSafeInteger(expectedVersion) ||
    expectedVersion < 1 ||
    expectedVersion >= maximumResourceVersion ||
    receipt.value.version !== expectedVersion + 1
  ) {
    throw tenantProjectionError();
  }
  return receipt;
}

function unwrapPlatformTenantAccessMutation(
  result: GeneratedResult<PlatformTenantAccessReceipt>,
  tenantId: string,
  expectedVersion: number,
): PlatformTenantAccessReceiptView {
  assertNoStoreResponse(result.response);
  const status = result.response?.status;
  if (status !== 200 && status !== 201) {
    throw toApiError(result.error, result.response);
  }
  const receipt = toPlatformTenantAccessReceipt(unwrap(result));
  const etag = result.response?.headers.get("ETag");
  const match = etag ? resourceStrongEntityTagPattern.exec(etag) : null;
  if (
    !match ||
    receipt.tenantId !== tenantId ||
    receipt.tenantVersion !== expectedVersion ||
    match[1] !== String(receipt.tenantVersion) ||
    receipt.membershipRevision !== 1 ||
    (status === 200) !== receipt.replayed
  ) {
    throw tenantProjectionError();
  }
  return receipt;
}

function unwrapTenantMembershipLifecycleMutation(
  result: GeneratedResult<TenantMembershipLifecycleReceipt>,
  tenantId: string,
  userId: string,
  status: "active" | "suspended",
  expectedRevision: number,
): TenantMembershipLifecycleReceiptView {
  assertNoStoreResponse(result.response);
  const receipt = unwrap(result);
  const etag = result.response?.headers.get("ETag");
  const previousStatus = status === "suspended" ? "active" : "suspended";
  if (
    receipt.tenantId !== tenantId ||
    receipt.userId !== userId ||
    receipt.status !== status ||
    receipt.previousStatus !== previousStatus ||
    !canonicalUuidPattern.test(receipt.membershipId) ||
    !isBoundedInteger(expectedRevision, 1, maximumResourceVersion - 1) ||
    receipt.lifecycleRevision !== expectedRevision + 1 ||
    !isBoundedInteger(receipt.revokedSessionCount, 0, 2_147_483_647) ||
    !isBoundedInteger(receipt.revokedContinuationCount, 0, 2_147_483_647) ||
    (status === "active" &&
      (receipt.revokedSessionCount !== 0 ||
        receipt.revokedContinuationCount !== 0)) ||
    typeof receipt.replayed !== "boolean" ||
    parseRfc3339Instant(receipt.updatedAt) === undefined ||
    etag !== receipt.etag
  ) {
    throw tenantProjectionError();
  }
  assertTenantMembershipEntityTag(receipt.etag, receipt.lifecycleRevision);
  return { ...receipt };
}

function assertTenantMembershipEntityTag(
  etag: unknown,
  revision: unknown,
): asserts etag is string {
  const match =
    typeof etag === "string" ? resourceStrongEntityTagPattern.exec(etag) : null;
  if (
    !match ||
    !isBoundedInteger(revision, 1, maximumResourceVersion) ||
    match[1] !== String(revision)
  ) {
    throw tenantProjectionError();
  }
}

function unwrapEdgeVersioned<TGenerated, TView extends { etag: string }>(
  result: GeneratedResult<TGenerated>,
  map: (value: TGenerated) => TView,
): VersionedView<TView> {
  const value = unwrap(result);
  const etag = result.response?.headers.get("ETag");
  if (!etag || !edgeStrongEntityTagPattern.test(etag)) {
    throw new PhaseTwoApiError(
      "The API did not return the required strong edge representation validator.",
    );
  }
  const mapped = map(value);
  if (mapped.etag !== etag) {
    throw tenantProjectionError();
  }
  return { etag, value: mapped };
}

function unwrapCredentialSecret(
  result: GeneratedResult<ServiceAccountCredentialSecret>,
): ServiceAccountCredentialSecretView {
  const secret = unwrap(result);
  const credential = toServiceAccountCredential(secret.credential);
  const etag = result.response?.headers.get("ETag");
  if (
    !etag ||
    credential.etag !== etag ||
    typeof secret.bearerToken !== "string" ||
    secret.bearerToken.length < 64 ||
    secret.bearerToken.length > 512 ||
    !/^[A-Za-z0-9._~-]+$/.test(secret.bearerToken)
  ) {
    throw tenantProjectionError();
  }
  return { bearerToken: secret.bearerToken, credential };
}

function assertNoStoreResponse(response: Response | undefined): void {
  if (response && !response.ok && response.status !== 409) return;
  const directives = response?.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (!directives?.includes("no-store")) {
    throw new PhaseTwoApiError(
      "The API did not mark the one-time credential response as no-store.",
      response?.status,
    );
  }
}

function assertLdapNoStoreResponse(response: Response | undefined): void {
  if (!response) return;
  const directives = response.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (!directives?.includes("no-store")) {
    throw new PhaseTwoApiError(
      "The API did not mark the LDAP provider response as no-store.",
      response.status,
    );
  }
}

function assertPlatformAuthProviderNoStoreResponse(
  response: Response | undefined,
): void {
  if (!response) return;
  if (response.headers.get("Cache-Control") !== "no-store") {
    throw new PhaseTwoApiError(
      "The API did not mark the platform identity-provider response as no-store.",
      response.status,
    );
  }
}

function assertPlatformAuthProviderSuccessStatus(
  response: Response | undefined,
  expectedStatus: 200 | 201,
  operation:
    | "activation"
    | "create"
    | "deactivation"
    | "detail"
    | "direct-login activation"
    | "direct-login deactivation"
    | "list"
    | "update",
): void {
  if (!response) {
    throw new PhaseTwoApiError(
      `The API did not return a response for the platform identity-provider ${operation} endpoint.`,
    );
  }
  if (response.ok && response.status !== expectedStatus) {
    throw new PhaseTwoApiError(
      `The API returned an unexpected success status for the platform identity-provider ${operation} endpoint.`,
      response.status,
    );
  }
}

function assertPlatformAuthProviderAccountSuccessStatus(
  response: Response | undefined,
  expectedStatus: 200 | 201,
  operation: "detail" | "list" | "prelink" | "retire",
): void {
  if (!response) {
    throw new PhaseTwoApiError(
      `The API did not return a response for the platform identity-account ${operation} endpoint.`,
    );
  }
  if (response.ok && response.status !== expectedStatus) {
    throw new PhaseTwoApiError(
      `The API returned an unexpected success status for the platform identity-account ${operation} endpoint.`,
      response.status,
    );
  }
}

function assertPlatformLocalAccountSuccessStatus(
  response: Response | undefined,
  expectedStatus: 200 | 201,
  operation:
    | "activate"
    | "detail"
    | "disable"
    | "enable"
    | "invite"
    | "list"
    | "password rotation"
    | "recover",
): void {
  if (!response) {
    throw new PhaseTwoApiError(
      `The API did not return a response for the platform local-account ${operation} endpoint.`,
    );
  }
  if (response.ok && response.status !== expectedStatus) {
    throw new PhaseTwoApiError(
      `The API returned an unexpected success status for the platform local-account ${operation} endpoint.`,
      response.status,
    );
  }
}

function assertPlatformAuthProviderBindingSuccessStatus(
  response: Response | undefined,
  expectedStatus: 200 | 201,
  operation:
    "activation" | "create" | "deactivation" | "detail" | "list" | "update",
): void {
  if (!response) {
    throw new PhaseTwoApiError(
      `The API did not return a response for the platform identity-provider tenant-binding ${operation} endpoint.`,
    );
  }
  if (response.ok && response.status !== expectedStatus) {
    throw new PhaseTwoApiError(
      `The API returned an unexpected success status for the platform identity-provider tenant-binding ${operation} endpoint.`,
      response.status,
    );
  }
}

function assertPlatformAuthProviderMutationPrecondition(
  etag: string,
  expectedVersion: number,
): void {
  assertResourceVersion(expectedVersion);
  const match = resourceStrongEntityTagPattern.exec(etag);
  if (
    expectedVersion >= maximumResourceVersion ||
    !match ||
    match[1] !== String(expectedVersion)
  ) {
    throw new PhaseTwoApiError(
      "The platform identity-provider version does not match its strong validator.",
    );
  }
}

function assertPlatformAuthProviderTenantBindingMutationPrecondition(
  etag: string,
  expectedVersion: number,
  expectedTenantVersion: number,
): void {
  assertResourceVersion(expectedVersion);
  assertResourceVersion(expectedTenantVersion);
  const match =
    platformAuthProviderTenantBindingStrongEntityTagPattern.exec(etag);
  if (
    expectedVersion >= maximumResourceVersion ||
    !match ||
    match[1] !== String(expectedVersion) ||
    match[2] !== String(expectedTenantVersion)
  ) {
    throw new PhaseTwoApiError(
      "The platform identity-provider tenant-binding and live tenant versions do not match their strong validator.",
    );
  }
}

function assertPlatformAuthProviderLifecyclePrecondition(
  current: VersionedView<PlatformAuthProviderView>,
  providerId: string,
  expectedVersion: number,
  transition: "activate" | "deactivate",
): void {
  assertPlatformAuthProviderMutationPrecondition(current.etag, expectedVersion);
  const provider = current.value;
  if (
    provider.id !== providerId ||
    provider.version !== expectedVersion ||
    provider.archivedAt !== null ||
    (transition === "activate" &&
      (provider.enabled ||
        !provider.activationAvailable ||
        provider.accountMode !== "disabled")) ||
    (transition === "deactivate" &&
      (!provider.enabled ||
        provider.platformLoginEnabled ||
        provider.activationAvailable ||
        provider.accountMode === "disabled"))
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderDirectLoginPrecondition(
  current: VersionedView<PlatformAuthProviderView>,
  providerId: string,
  expectedVersion: number,
  transition: "activate" | "deactivate",
): void {
  assertPlatformAuthProviderMutationPrecondition(current.etag, expectedVersion);
  const provider = current.value;
  if (
    provider.id !== providerId ||
    provider.version !== expectedVersion ||
    provider.archivedAt !== null ||
    !provider.enabled ||
    provider.activationAvailable ||
    provider.accountMode === "disabled" ||
    !provider.configured ||
    !provider.secretPresent ||
    (transition === "activate"
      ? provider.platformLoginEnabled ||
        !provider.platformLoginActivationAvailable
      : !provider.platformLoginEnabled)
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformSAMLMaterialPrecondition(
  current: VersionedView<PlatformAuthProviderView>,
  providerId: string,
  expectedVersion: number,
  material: "metadata" | "sp-key",
  requirePresent: boolean,
): void {
  assertPlatformAuthProviderMutationPrecondition(current.etag, expectedVersion);
  if (
    current.value.id !== providerId ||
    current.value.version !== expectedVersion ||
    current.value.kind !== "saml" ||
    current.value.archivedAt !== null
  ) {
    throw tenantProjectionError();
  }
  const configuration = current.value.configuration;
  const revision =
    material === "metadata"
      ? configuration.metadataRevision
      : configuration.spKeyRevision;
  if (
    revision < 1 ||
    revision >= maximumResourceVersion ||
    (requirePresent && !configuration.spKeyPresent)
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderTenantBindingLifecyclePrecondition(
  current: VersionedView<PlatformAuthProviderTenantBindingView>,
  providerId: string,
  bindingId: string,
  expectedVersion: number,
  expectedTenantVersion: number,
  transition: "activate" | "deactivate",
): void {
  assertPlatformAuthProviderTenantBindingMutationPrecondition(
    current.etag,
    expectedVersion,
    expectedTenantVersion,
  );
  assertPlatformAuthProviderTenantBindingProjection(
    current.value,
    providerId,
    bindingId,
  );
  const binding = current.value;
  if (
    binding.version !== expectedVersion ||
    binding.tenant.version !== expectedTenantVersion ||
    binding.archivedAt !== null ||
    (transition === "activate" &&
      (binding.enabled ||
        !binding.activationAvailable ||
        binding.currentAccessEpochId !== null)) ||
    (transition === "deactivate" &&
      (!binding.enabled ||
        binding.activationAvailable ||
        binding.currentAccessEpochId === null))
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderAuditReasonHeader(
  auditReason: string,
): void {
  if (!isPlatformAuditReasonHeader(auditReason)) {
    throw new PhaseTwoApiError(
      "The platform identity-provider audit reason is not safe for an HTTP header.",
    );
  }
}

function unwrapPlatformAuthProviderMutationEtag(
  result: GeneratedResult<unknown>,
  previousEtag: string,
  expectedVersion: number,
): string {
  assertPlatformAuthProviderNoStoreResponse(result.response);
  if (!result.response?.ok) {
    throw toApiError(result.error, result.response);
  }
  const etag = result.response.headers.get("ETag");
  const match = etag ? resourceStrongEntityTagPattern.exec(etag) : null;
  if (
    !etag ||
    !match ||
    etag === previousEtag ||
    expectedVersion >= maximumResourceVersion ||
    match[1] !== String(expectedVersion + 1)
  ) {
    throw new PhaseTwoApiError(
      "The API did not return the next strong platform identity-provider version.",
      result.response.status,
    );
  }
  return etag;
}

function unwrapBodylessPlatformAuthProviderMutationEtag(
  result: GeneratedResult<unknown>,
  previousEtag: string,
  expectedVersion: number,
  projectionErrorMessage: string,
): string {
  const response = result.response;
  assertPlatformAuthProviderNoStoreResponse(response);
  if (!response?.ok) {
    throw toApiError(result.error, response);
  }
  const contentLength = response?.headers.get("Content-Length");
  if (
    !response ||
    response.status !== 204 ||
    response.body !== null ||
    (result.data !== undefined && result.data !== response.body) ||
    result.error !== undefined ||
    response.headers.has("Content-Type") ||
    (contentLength !== null && contentLength !== "0")
  ) {
    throw new PhaseTwoApiError(projectionErrorMessage, response.status);
  }
  return unwrapPlatformAuthProviderMutationEtag(
    result,
    previousEtag,
    expectedVersion,
  );
}

function unwrapPlatformSAMLMaterialMutation(
  result: GeneratedResult<unknown>,
  current: VersionedView<PlatformAuthProviderView>,
  material: "metadata" | "sp-key",
  projectionErrorMessage: string,
): PlatformSamlMaterialMutationView {
  const etag = unwrapBodylessPlatformAuthProviderMutationEtag(
    result,
    current.etag,
    current.value.version,
    projectionErrorMessage,
  );
  if (current.value.kind !== "saml" || !result.response) {
    throw tenantProjectionError();
  }
  const rawRevision = result.response.headers.get(
    "X-Periapsis-SAML-Material-Revision",
  );
  const previousRevision =
    material === "metadata"
      ? current.value.configuration.metadataRevision
      : current.value.configuration.spKeyRevision;
  if (!rawRevision || !/^[1-9][0-9]{0,9}$/u.test(rawRevision)) {
    throw new PhaseTwoApiError(
      "The API did not return a canonical SAML material revision.",
      result.response.status,
    );
  }
  const materialRevision = Number(rawRevision);
  if (
    !Number.isSafeInteger(materialRevision) ||
    materialRevision !== previousRevision + 1 ||
    materialRevision > maximumResourceVersion
  ) {
    throw new PhaseTwoApiError(
      "The API did not return the next SAML material revision.",
      result.response.status,
    );
  }
  return { etag, materialRevision };
}

function unwrapBodylessPlatformAuthProviderTenantBindingMutationEtag(
  result: GeneratedResult<unknown>,
  previousEtag: string,
  expectedVersion: number,
  expectedTenantVersion: number,
  projectionErrorMessage: string,
): string {
  const response = result.response;
  assertPlatformAuthProviderNoStoreResponse(response);
  if (!response?.ok) {
    throw toApiError(result.error, response);
  }
  const contentLength = response.headers.get("Content-Length");
  if (
    response.status !== 204 ||
    response.body !== null ||
    (result.data !== undefined && result.data !== response.body) ||
    result.error !== undefined ||
    response.headers.has("Content-Type") ||
    (contentLength !== null && contentLength !== "0")
  ) {
    throw new PhaseTwoApiError(projectionErrorMessage, response.status);
  }
  const etag = response.headers.get("ETag");
  const match = etag
    ? platformAuthProviderTenantBindingStrongEntityTagPattern.exec(etag)
    : null;
  if (
    !etag ||
    !match ||
    etag === previousEtag ||
    expectedVersion >= maximumResourceVersion ||
    match[1] !== String(expectedVersion + 1) ||
    match[2] !== String(expectedTenantVersion)
  ) {
    throw new PhaseTwoApiError(
      "The API did not return the next strong tenant-binding representation version.",
      response.status,
    );
  }
  return etag;
}

function unwrapCreatedPlatformAuthProvider(
  result: GeneratedResult<PlatformAuthProvider>,
): VersionedView<PlatformAuthProviderView> & { location: string } {
  assertPlatformAuthProviderSuccessStatus(result.response, 201, "create");
  assertPlatformAuthProviderNoStoreResponse(result.response);
  const created = unwrapVersioned(result, toPlatformAuthProvider);
  const location = assertPlatformAuthProviderLocation(
    result.response?.headers.get("Location") ?? null,
    created.value.id,
  );
  return { ...created, location };
}

function unwrapCreatedPlatformAuthProviderAccount(
  result: GeneratedResult<PlatformAuthProviderAccount>,
  providerId: string,
): VersionedView<PlatformAuthProviderAccountView> & { location: string } {
  assertPlatformAuthProviderAccountSuccessStatus(
    result.response,
    201,
    "prelink",
  );
  assertPlatformAuthProviderNoStoreResponse(result.response);
  const created = unwrapPlatformAuthProviderAccountVersioned(result);
  assertPlatformAuthProviderAccountPath(
    created.value,
    providerId,
    created.value.id,
  );
  const location = assertPlatformAuthProviderAccountLocation(
    result.response?.headers.get("Location") ?? null,
    providerId,
    created.value.id,
  );
  return { ...created, location };
}

function unwrapCreatedPlatformAuthProviderTenantBinding(
  result: GeneratedResult<PlatformAuthProviderTenantBinding>,
  providerId: string,
): VersionedView<PlatformAuthProviderTenantBindingView> & {
  location: string;
} {
  assertPlatformAuthProviderBindingSuccessStatus(
    result.response,
    201,
    "create",
  );
  assertPlatformAuthProviderNoStoreResponse(result.response);
  const created = unwrapPlatformAuthProviderTenantBindingVersioned(result);
  assertPlatformAuthProviderTenantBindingProjection(
    created.value,
    providerId,
    created.value.id,
  );
  const location = assertPlatformAuthProviderTenantBindingLocation(
    result.response?.headers.get("Location") ?? null,
    providerId,
    created.value.id,
  );
  return { ...created, location };
}

function assertPlatformAuthProviderLocation(
  location: string | null,
  providerId: string,
): string {
  if (!location) {
    throw new PhaseTwoApiError(
      "The API did not return the created platform identity-provider location.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw tenantProjectionError();
  }
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== `/api/v1/platform/auth-providers/${providerId}` ||
    !canonicalUuidV7Pattern.test(providerId)
  ) {
    throw tenantProjectionError();
  }
  return location;
}

function assertPlatformAuthProviderAccountLocation(
  location: string | null,
  providerId: string,
  accountId: string,
): string {
  if (!location) {
    throw new PhaseTwoApiError(
      "The API did not return the created platform identity-account location.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw tenantProjectionError();
  }
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !==
      `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}` ||
    !canonicalUuidV7Pattern.test(providerId) ||
    !canonicalUuidV7Pattern.test(accountId)
  ) {
    throw tenantProjectionError();
  }
  return location;
}

function assertPlatformAuthProviderTenantBindingLocation(
  location: string | null,
  providerId: string,
  bindingId: string,
): string {
  if (!location) {
    throw new PhaseTwoApiError(
      "The API did not return the created platform identity-provider tenant-binding location.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw tenantProjectionError();
  }
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !==
      `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}` ||
    !canonicalUuidV7Pattern.test(providerId) ||
    !canonicalUuidV7Pattern.test(bindingId)
  ) {
    throw tenantProjectionError();
  }
  return location;
}

function assertPlatformAuthProviderMutationProjection(
  provider: VersionedView<PlatformAuthProviderView>,
  providerId: string,
  expectedVersion: number,
): void {
  if (
    provider.value.id !== providerId ||
    expectedVersion >= maximumResourceVersion ||
    provider.value.version !== expectedVersion + 1
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderLifecycleProjection(
  provider: VersionedView<PlatformAuthProviderView>,
  previous: PlatformAuthProviderView,
  providerId: string,
  expectedVersion: number,
): void {
  assertPlatformAuthProviderMutationProjection(
    provider,
    providerId,
    expectedVersion,
  );
  const next = provider.value;
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const updatedAt = parseRfc3339Instant(next.updatedAt);
  if (
    next.kind !== previous.kind ||
    next.key !== previous.key ||
    next.displayName !== previous.displayName ||
    next.description !== previous.description ||
    next.configured !== previous.configured ||
    next.secretPresent !== previous.secretPresent ||
    next.platformLoginEnabled !== previous.platformLoginEnabled ||
    next.createdAt !== previous.createdAt ||
    next.archivedAt !== previous.archivedAt ||
    next.configurationRevision !== previous.configurationRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision ||
    next.securityRevision !== previous.securityRevision + 1 ||
    next.planRevision !== previous.planRevision + 1 ||
    !samePlatformAuthProviderConfiguration(next, previous) ||
    previousUpdatedAt === undefined ||
    updatedAt === undefined ||
    updatedAt < previousUpdatedAt
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderDirectLoginProjection(
  provider: VersionedView<PlatformAuthProviderView>,
  previous: PlatformAuthProviderView,
  providerId: string,
  expectedVersion: number,
  enabled: boolean,
): void {
  assertPlatformAuthProviderMutationProjection(
    provider,
    providerId,
    expectedVersion,
  );
  const next = provider.value;
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const updatedAt = parseRfc3339Instant(next.updatedAt);
  if (
    next.kind !== previous.kind ||
    next.platformLoginEnabled !== enabled ||
    next.enabled !== previous.enabled ||
    next.activationAvailable !== previous.activationAvailable ||
    next.accountMode !== previous.accountMode ||
    next.key !== previous.key ||
    next.displayName !== previous.displayName ||
    next.description !== previous.description ||
    next.configured !== previous.configured ||
    next.secretPresent !== previous.secretPresent ||
    next.createdAt !== previous.createdAt ||
    next.archivedAt !== previous.archivedAt ||
    next.configurationRevision !== previous.configurationRevision ||
    next.securityRevision !== previous.securityRevision ||
    next.planRevision !== previous.planRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision ||
    !samePlatformAuthProviderConfiguration(next, previous) ||
    previousUpdatedAt === undefined ||
    updatedAt === undefined ||
    updatedAt < previousUpdatedAt
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderMetadataProjection(
  provider: VersionedView<PlatformAuthProviderView>,
  previous: PlatformAuthProviderView,
  providerId: string,
  input: PlatformAuthProviderUpdateInput,
): void {
  assertPlatformAuthProviderMutationProjection(
    provider,
    providerId,
    input.expectedVersion,
  );
  const next = provider.value;
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const updatedAt = parseRfc3339Instant(next.updatedAt);
  if (
    next.kind !== previous.kind ||
    next.key !== previous.key ||
    input.key !== previous.key ||
    next.displayName !== input.displayName ||
    next.description !== input.description ||
    next.enabled !== previous.enabled ||
    next.platformLoginEnabled !== previous.platformLoginEnabled ||
    next.activationAvailable !== previous.activationAvailable ||
    next.configured !== previous.configured ||
    next.secretPresent !== previous.secretPresent ||
    next.archivedAt !== previous.archivedAt ||
    next.createdAt !== previous.createdAt ||
    next.configurationRevision !== previous.configurationRevision ||
    next.securityRevision !== previous.securityRevision ||
    next.planRevision !== previous.planRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision ||
    next.accountMode !== previous.accountMode ||
    !samePlatformAuthProviderConfiguration(next, previous) ||
    previousUpdatedAt === undefined ||
    updatedAt === undefined ||
    updatedAt < previousUpdatedAt
  ) {
    throw tenantProjectionError();
  }
}

function matchesPlatformAuthProviderInitialCreate(
  provider: PlatformAuthProviderView,
  input: PlatformAuthProviderCreateInput,
): boolean {
  if (
    provider.kind !== input.kind ||
    provider.key !== input.key ||
    provider.displayName !== input.displayName ||
    provider.description !== (input.description ?? "") ||
    provider.enabled ||
    provider.platformLoginEnabled ||
    provider.platformLoginActivationAvailable ||
    provider.activationAvailable ||
    !provider.configured ||
    provider.secretPresent ||
    provider.archivedAt !== null ||
    provider.accountMode !== "disabled" ||
    provider.configurationRevision !== 1 ||
    provider.securityRevision !== 1 ||
    provider.planRevision !== 1 ||
    provider.assurancePolicyRevision !== 1 ||
    provider.createdAt !== provider.updatedAt
  ) {
    return false;
  }
  if (provider.kind === "oidc" && input.kind === "oidc") {
    const configuration = provider.configuration;
    const requested = input.configuration;
    return (
      configuration.issuer === requested.issuer &&
      configuration.clientId === requested.clientId &&
      configuration.redirectUri === requested.redirectUri &&
      configuration.tenantRedirectUri === requested.tenantRedirectUri &&
      configuration.postLogoutRedirectUri === requested.postLogoutRedirectUri &&
      configuration.allowRefreshToken === requested.allowRefreshToken &&
      configuration.useUserInfo === requested.useUserInfo &&
      !configuration.clientSecretPresent &&
      configuration.clientSecretRevision === 1 &&
      configuration.discoveryRevision === 1 &&
      configuration.jwksRevision === 1 &&
      configuration.extraScopes.length === requested.extraScopes.length &&
      configuration.extraScopes.every(
        (scope, index) => scope === requested.extraScopes[index],
      )
    );
  }
  if (provider.kind === "ldap" && input.kind === "ldap") {
    return (
      ldapConfigurationKeys.every(
        (key) => provider.configuration[key] === input.configuration[key],
      ) &&
      provider.endpoints.length === input.endpoints.length &&
      provider.endpoints.every((endpoint, index) => {
        const requested = input.endpoints[index];
        return (
          requested !== undefined &&
          endpoint.priority === requested.priority &&
          endpoint.host === requested.host &&
          endpoint.port === requested.port &&
          endpoint.transport === requested.transport &&
          endpoint.tlsServerName === requested.tlsServerName &&
          endpoint.referralAllowed === requested.referralAllowed &&
          endpoint.enabled === requested.enabled
        );
      }) &&
      provider.mappings.length === 0
    );
  }
  if (provider.kind !== "saml" || input.kind !== "saml") return false;
  const configuration = provider.configuration;
  const requested = input.configuration;
  return (
    configuration.expectedEntityId === requested.expectedEntityId &&
    configuration.spEntityId === requested.spEntityId &&
    configuration.acsUrl === requested.acsUrl &&
    configuration.redirectSignatureAlgorithm ===
      requested.redirectSignatureAlgorithm &&
    configuration.signaturePolicy === requested.signaturePolicy &&
    configuration.encryptionPolicy === requested.encryptionPolicy &&
    configuration.clockSkewNanoseconds === requested.clockSkewNanoseconds &&
    configuration.maxAuthenticationAgeNanoseconds ===
      requested.maxAuthenticationAgeNanoseconds &&
    configuration.subjectSource === requested.subjectSource &&
    !configuration.spKeyPresent &&
    configuration.spKeyRevision === 1 &&
    configuration.metadataRevision === 1 &&
    configuration.requestedAuthnContexts.length ===
      requested.requestedAuthnContexts.length &&
    configuration.requestedAuthnContexts.every(
      (context, index) => context === requested.requestedAuthnContexts[index],
    ) &&
    (configuration.subjectSource !== "immutable_attribute" ||
      (requested.subjectSource === "immutable_attribute" &&
        configuration.subjectAttributeName === requested.subjectAttributeName &&
        configuration.subjectAttributeNameFormat ===
          requested.subjectAttributeNameFormat))
  );
}

function samePlatformAuthProviderConfiguration(
  next: PlatformAuthProviderView,
  previous: PlatformAuthProviderView,
): boolean {
  if (next.kind !== previous.kind) return false;
  if (next.kind === "oidc" && previous.kind === "oidc") {
    const nextConfiguration = next.configuration;
    const previousConfiguration = previous.configuration;
    return (
      nextConfiguration.allowRefreshToken ===
        previousConfiguration.allowRefreshToken &&
      nextConfiguration.clientId === previousConfiguration.clientId &&
      nextConfiguration.clientSecretPresent ===
        previousConfiguration.clientSecretPresent &&
      nextConfiguration.clientSecretRevision ===
        previousConfiguration.clientSecretRevision &&
      nextConfiguration.discoveryRevision ===
        previousConfiguration.discoveryRevision &&
      nextConfiguration.issuer === previousConfiguration.issuer &&
      nextConfiguration.jwksRevision === previousConfiguration.jwksRevision &&
      nextConfiguration.postLogoutRedirectUri ===
        previousConfiguration.postLogoutRedirectUri &&
      nextConfiguration.redirectUri === previousConfiguration.redirectUri &&
      nextConfiguration.tenantRedirectUri ===
        previousConfiguration.tenantRedirectUri &&
      nextConfiguration.useUserInfo === previousConfiguration.useUserInfo &&
      nextConfiguration.extraScopes.length ===
        previousConfiguration.extraScopes.length &&
      nextConfiguration.extraScopes.every(
        (scope, index) => scope === previousConfiguration.extraScopes[index],
      )
    );
  }
  if (next.kind === "ldap" && previous.kind === "ldap") {
    return ldapConfigurationKeys.every(
      (key) => next.configuration[key] === previous.configuration[key],
    );
  }
  if (next.kind !== "saml" || previous.kind !== "saml") return false;
  const nextConfiguration = next.configuration;
  const previousConfiguration = previous.configuration;
  return (
    nextConfiguration.acsUrl === previousConfiguration.acsUrl &&
    nextConfiguration.clockSkewNanoseconds ===
      previousConfiguration.clockSkewNanoseconds &&
    nextConfiguration.encryptionPolicy ===
      previousConfiguration.encryptionPolicy &&
    nextConfiguration.expectedEntityId ===
      previousConfiguration.expectedEntityId &&
    nextConfiguration.maxAuthenticationAgeNanoseconds ===
      previousConfiguration.maxAuthenticationAgeNanoseconds &&
    nextConfiguration.metadataRevision ===
      previousConfiguration.metadataRevision &&
    nextConfiguration.redirectSignatureAlgorithm ===
      previousConfiguration.redirectSignatureAlgorithm &&
    nextConfiguration.signaturePolicy ===
      previousConfiguration.signaturePolicy &&
    nextConfiguration.spEntityId === previousConfiguration.spEntityId &&
    nextConfiguration.spKeyPresent === previousConfiguration.spKeyPresent &&
    nextConfiguration.spKeyRevision === previousConfiguration.spKeyRevision &&
    nextConfiguration.subjectSource === previousConfiguration.subjectSource &&
    nextConfiguration.requestedAuthnContexts.length ===
      previousConfiguration.requestedAuthnContexts.length &&
    nextConfiguration.requestedAuthnContexts.every(
      (context, index) =>
        context === previousConfiguration.requestedAuthnContexts[index],
    ) &&
    (nextConfiguration.subjectSource !== "immutable_attribute" ||
      (previousConfiguration.subjectSource === "immutable_attribute" &&
        nextConfiguration.subjectAttributeName ===
          previousConfiguration.subjectAttributeName &&
        nextConfiguration.subjectAttributeNameFormat ===
          previousConfiguration.subjectAttributeNameFormat))
  );
}

function assertPlatformLdapCurrentProjection(
  current: VersionedView<PlatformLdapAuthProviderView>,
  providerId: string,
): void {
  assertPlatformAuthProviderMutationPrecondition(
    current.etag,
    current.value.version,
  );
  if (
    current.value.id !== providerId ||
    current.value.kind !== "ldap" ||
    current.value.archivedAt !== null
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformLdapMutationPrecondition(
  current: VersionedView<PlatformLdapAuthProviderView>,
  providerId: string,
  expectedVersion: number,
): void {
  assertPlatformLdapCurrentProjection(current, providerId);
  if (current.value.version !== expectedVersion) throw tenantProjectionError();
}

function assertPlatformLdapBaseMutationProjection(
  provider: VersionedView<PlatformLdapAuthProviderView>,
  previous: PlatformLdapAuthProviderView,
  providerId: string,
  allowConcurrentVersion = false,
): void {
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const nextUpdatedAt = parseRfc3339Instant(provider.value.updatedAt);
  if (
    provider.value.id !== providerId ||
    provider.value.kind !== "ldap" ||
    previous.version >= maximumResourceVersion ||
    (allowConcurrentVersion
      ? provider.value.version <= previous.version
      : provider.value.version !== previous.version + 1) ||
    provider.value.createdAt !== previous.createdAt ||
    provider.value.archivedAt !== previous.archivedAt ||
    previousUpdatedAt === undefined ||
    nextUpdatedAt === undefined ||
    nextUpdatedAt < previousUpdatedAt
  ) {
    throw tenantProjectionError();
  }
}

function samePlatformLdapEndpoints(
  endpoints: readonly PlatformLdapAuthProviderView["endpoints"][number][],
  requested: readonly PlatformLdapAuthProviderUpdateInput["endpoints"][number][],
): boolean {
  return (
    endpoints.length === requested.length &&
    endpoints.every((endpoint, index) => {
      const value = requested[index];
      return (
        value !== undefined &&
        endpoint.id === value.id &&
        endpoint.priority === value.priority &&
        endpoint.host === value.host &&
        endpoint.port === value.port &&
        endpoint.transport === value.transport &&
        endpoint.tlsServerName === value.tlsServerName &&
        endpoint.referralAllowed === value.referralAllowed &&
        endpoint.enabled === value.enabled
      );
    })
  );
}

function samePlatformLdapMappings(
  left: readonly PlatformLdapAuthProviderView["mappings"][number][],
  right: readonly PlatformLdapAuthProviderView["mappings"][number][],
): boolean {
  return (
    left.length === right.length &&
    left.every((mapping, index) => {
      const previous = right[index];
      return (
        previous !== undefined &&
        mapping.id === previous.id &&
        mapping.matcherType === previous.matcherType &&
        mapping.matcherValue === previous.matcherValue &&
        mapping.caseSensitive === previous.caseSensitive &&
        mapping.priority === previous.priority &&
        mapping.platformRoleId === previous.platformRoleId &&
        mapping.reconciliationMode === previous.reconciliationMode &&
        mapping.enabled === previous.enabled &&
        mapping.notes === previous.notes &&
        mapping.lastMatchedAt === previous.lastMatchedAt &&
        mapping.archivedAt === previous.archivedAt &&
        mapping.version === previous.version
      );
    })
  );
}

function assertPlatformLdapConfigurationMutationProjection(
  provider: VersionedView<PlatformLdapAuthProviderView>,
  previous: PlatformLdapAuthProviderView,
  providerId: string,
  input: PlatformLdapAuthProviderUpdateInput,
): void {
  assertPlatformLdapBaseMutationProjection(provider, previous, providerId);
  const next = provider.value;
  if (
    next.key !== input.key ||
    next.displayName !== input.displayName ||
    next.description !== input.description ||
    next.configurationRevision !== previous.configurationRevision + 1 ||
    next.securityRevision !== previous.securityRevision + 1 ||
    next.planRevision !== previous.planRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision ||
    next.enabled !== previous.enabled ||
    next.platformLoginEnabled !== previous.platformLoginEnabled ||
    next.secretPresent !== previous.secretPresent ||
    !ldapConfigurationKeys.every(
      (key) => next.configuration[key] === input.configuration[key],
    ) ||
    !samePlatformLdapEndpoints(next.endpoints, input.endpoints) ||
    !samePlatformLdapMappings(next.mappings, previous.mappings)
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformLdapMappingMutationProjection(
  provider: VersionedView<PlatformLdapAuthProviderView>,
  previous: PlatformLdapAuthProviderView,
  providerId: string,
  mappingId: string,
  input: Parameters<PhaseTwoApi["putPlatformLdapMapping"]>[5],
): void {
  assertPlatformLdapBaseMutationProjection(
    provider,
    previous,
    providerId,
    true,
  );
  const next = provider.value;
  const mapping = next.mappings.find((candidate) => candidate.id === mappingId);
  const expectedMappingVersion = (input.expectedVersion ?? 0) + 1;
  if (
    mapping === undefined ||
    mapping.version !== expectedMappingVersion ||
    mapping.archivedAt !== null ||
    mapping.matcherType !== input.matcherType ||
    mapping.matcherValue !== input.matcherValue.trim() ||
    mapping.caseSensitive !== input.caseSensitive ||
    mapping.priority !== input.priority ||
    mapping.platformRoleId !== input.platformRoleId ||
    mapping.reconciliationMode !== input.reconciliationMode ||
    mapping.enabled !== input.enabled ||
    mapping.notes !== input.notes.trim() ||
    next.configurationRevision !== previous.configurationRevision ||
    next.securityRevision !== previous.securityRevision ||
    next.planRevision <= previous.planRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformLdapLoginStateProjection(
  provider: VersionedView<PlatformLdapAuthProviderView>,
  previous: PlatformLdapAuthProviderView,
  providerId: string,
  enabled: boolean,
): void {
  assertPlatformLdapBaseMutationProjection(provider, previous, providerId);
  const next = provider.value;
  if (
    next.enabled !== enabled ||
    next.platformLoginEnabled !== enabled ||
    next.accountMode !== (enabled ? "existing_identity" : "disabled") ||
    next.configurationRevision !== previous.configurationRevision ||
    next.securityRevision !== previous.securityRevision + 1 ||
    next.planRevision !== previous.planRevision ||
    next.assurancePolicyRevision !== previous.assurancePolicyRevision ||
    next.key !== previous.key ||
    next.displayName !== previous.displayName ||
    next.description !== previous.description ||
    next.secretPresent !== previous.secretPresent ||
    !samePlatformAuthProviderConfiguration(next, previous)
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderTenantBindingMutationProjection(
  binding: VersionedView<PlatformAuthProviderTenantBindingView>,
  providerId: string,
  bindingId: string,
  expectedVersion: number,
  expectedTenantVersion: number,
  previous: PlatformAuthProviderTenantBindingView,
): void {
  assertPlatformAuthProviderTenantBindingLifecycleProjection(
    binding,
    previous,
    providerId,
    bindingId,
    expectedVersion,
    expectedTenantVersion,
  );
  if (
    binding.value.authRevision !== previous.authRevision ||
    binding.value.mappingRevision !== previous.mappingRevision ||
    binding.value.enabled !== previous.enabled ||
    binding.value.activationAvailable !== previous.activationAvailable ||
    binding.value.currentAccessEpochId !== previous.currentAccessEpochId ||
    binding.value.jitMode !== previous.jitMode ||
    binding.value.noMatchPolicy !== previous.noMatchPolicy
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderTenantBindingLifecycleProjection(
  binding: VersionedView<PlatformAuthProviderTenantBindingView>,
  previous: PlatformAuthProviderTenantBindingView,
  providerId: string,
  bindingId: string,
  expectedVersion: number,
  expectedTenantVersion: number,
): void {
  assertPlatformAuthProviderTenantBindingProjection(
    binding.value,
    providerId,
    bindingId,
  );
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const updatedAt = parseRfc3339Instant(binding.value.updatedAt);
  if (
    expectedVersion >= maximumResourceVersion ||
    binding.value.version !== expectedVersion + 1 ||
    binding.value.tenant.version !== expectedTenantVersion ||
    binding.value.archivedAt !== null ||
    binding.value.createdAt !== previous.createdAt ||
    binding.value.origin !== previous.origin ||
    binding.value.tenant.id !== previous.tenant.id ||
    binding.value.tenant.name !== previous.tenant.name ||
    binding.value.tenant.slug !== previous.tenant.slug ||
    binding.value.tenant.status !== previous.tenant.status ||
    binding.value.tenant.version !== previous.tenant.version ||
    previousUpdatedAt === undefined ||
    updatedAt === undefined ||
    updatedAt < previousUpdatedAt
  ) {
    throw tenantProjectionError();
  }
}

function unwrapLdapMutationEtag(
  result: GeneratedResult<unknown>,
  previousEtag: string,
): string {
  if (!result.response?.ok) {
    assertLdapNoStoreResponse(result.response);
    throw toApiError(result.error, result.response);
  }
  assertLdapNoStoreResponse(result.response);
  const etag = result.response.headers.get("ETag");
  if (
    !etag ||
    !resourceStrongEntityTagPattern.test(etag) ||
    etag === previousEtag
  ) {
    throw new PhaseTwoApiError(
      "The API did not return the new strong LDAP provider version.",
      result.response.status,
    );
  }
  return etag;
}

function unwrapCreatedLdapVersioned<
  TGenerated,
  TView extends { id: string; version: number },
>(
  result: GeneratedResult<TGenerated>,
  map: (value: TGenerated) => TView,
  locationPrefix: string,
): VersionedView<TView> & { location: string } {
  assertLdapNoStoreResponse(result.response);
  const created = unwrapVersioned(result, map);
  const location = assertTenantScopedResourceLocation(
    result.response?.headers.get("Location") ?? null,
    locationPrefix,
    created.value.id,
  );
  return { ...created, location };
}

function assertTenantScopedResourceLocation(
  location: string | null,
  pathPrefix: string,
  resourceId: string,
): string {
  if (!location) {
    throw new PhaseTwoApiError(
      "The API did not return the created LDAP resource location.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw tenantProjectionError();
  }
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== `${pathPrefix}${resourceId}` ||
    !canonicalUuidPattern.test(resourceId)
  ) {
    throw tenantProjectionError();
  }
  return location;
}

function assertTenantLdapProviderLocation(
  location: string | null,
  tenantId: string,
): string {
  if (!location) {
    throw new PhaseTwoApiError(
      "The API did not return the created LDAP provider location.",
    );
  }
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw tenantProjectionError();
  }
  const prefix = `/api/v1/tenants/${tenantId}/auth-providers/`;
  const providerId = parsed.pathname.startsWith(prefix)
    ? parsed.pathname.slice(prefix.length)
    : "";
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    !canonicalUuidPattern.test(providerId) ||
    parsed.pathname !== `${prefix}${providerId}`
  ) {
    throw tenantProjectionError();
  }
  return location;
}

function csrfHeaders(csrfToken: string): Record<"X-CSRF-Token", string> {
  return { "X-CSRF-Token": csrfToken };
}

function assertTenantId(actual: string, expected: string): void {
  if (actual !== expected) {
    throw tenantProjectionError();
  }
}

function assertResourceId(actual: string, expected: string): void {
  if (actual !== expected) {
    throw tenantProjectionError();
  }
}

function assertTenantItems(
  items: readonly { tenantId: string }[],
  expectedTenantId: string,
): void {
  if (items.some((item) => item.tenantId !== expectedTenantId)) {
    throw tenantProjectionError();
  }
}

const canonicalUuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const canonicalUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const platformAuthProviderSummaryKeys = [
  "activationAvailable",
  "archivedAt",
  "configured",
  "createdAt",
  "description",
  "displayName",
  "enabled",
  "id",
  "key",
  "kind",
  "platformLoginActivationAvailable",
  "platformLoginEnabled",
  "secretPresent",
  "updatedAt",
  "version",
] as const;

const platformAuthProviderDetailKeys = [
  "accountMode",
  "activationAvailable",
  "archivedAt",
  "assurancePolicyRevision",
  "configuration",
  "configurationRevision",
  "configured",
  "createdAt",
  "description",
  "displayName",
  "enabled",
  "id",
  "key",
  "kind",
  "planRevision",
  "platformLoginActivationAvailable",
  "platformLoginEnabled",
  "secretPresent",
  "securityRevision",
  "updatedAt",
  "version",
] as const;

const platformLdapAuthProviderDetailKeys = [
  ...platformAuthProviderDetailKeys,
  "endpoints",
  "mappings",
] as const;

const platformLdapEndpointKeys = [
  "enabled",
  "host",
  "id",
  "port",
  "priority",
  "referralAllowed",
  "tlsServerName",
  "transport",
] as const;

const platformLdapMappingKeys = [
  "archivedAt",
  "caseSensitive",
  "enabled",
  "id",
  "lastMatchedAt",
  "matcherType",
  "matcherValue",
  "notes",
  "platformRoleId",
  "priority",
  "reconciliationMode",
  "version",
] as const;

const platformAuthProviderTenantBindingKeys = [
  "activationAvailable",
  "archivedAt",
  "authRevision",
  "createdAt",
  "currentAccessEpochId",
  "enabled",
  "id",
  "jitMode",
  "loginKey",
  "mappingRevision",
  "noMatchPolicy",
  "origin",
  "profilePriority",
  "providerId",
  "tenant",
  "updatedAt",
  "version",
] as const;

const platformOidcConfigurationKeys = [
  "allowRefreshToken",
  "clientId",
  "clientSecretPresent",
  "clientSecretRevision",
  "discoveryRevision",
  "extraScopes",
  "issuer",
  "jwksRevision",
  "postLogoutRedirectUri",
  "redirectUri",
  "tenantRedirectUri",
  "useUserInfo",
] as const;

const platformSamlConfigurationBaseKeys = [
  "acsUrl",
  "clockSkewNanoseconds",
  "encryptionPolicy",
  "expectedEntityId",
  "maxAuthenticationAgeNanoseconds",
  "metadataRevision",
  "redirectSignatureAlgorithm",
  "requestedAuthnContexts",
  "signaturePolicy",
  "spEntityId",
  "spKeyPresent",
  "spKeyRevision",
  "subjectSource",
] as const;

const platformSamlRedirectSignatureAlgorithms = [
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
] as const;

const ldapSummaryKeys = [
  "archivedAt",
  "bindSecretConfigured",
  "createdAt",
  "description",
  "displayName",
  "enabled",
  "enabledEndpointCount",
  "id",
  "key",
  "kind",
  "template",
  "tenantId",
  "updatedAt",
  "version",
] as const;

const ldapProviderKeys = [
  "archiveReason",
  "archivedAt",
  "bindSecretConfigured",
  "bindSecretRotatedAt",
  "configuration",
  "createdAt",
  "description",
  "displayName",
  "enabled",
  "enabledEndpointCount",
  "endpoints",
  "id",
  "key",
  "kind",
  "template",
  "tenantId",
  "updatedAt",
  "version",
] as const;

const ldapConfigurationKeys = [
  "accountDisabledValue",
  "accountStatusAttribute",
  "accountStatusMode",
  "alternateUsernameAttribute",
  "bindDn",
  "connectTimeoutMs",
  "customCaPem",
  "deprovisionGraceSeconds",
  "deprovisionMode",
  "displayNameAttribute",
  "emailAttribute",
  "firstNameAttribute",
  "groupBaseDn",
  "groupMembershipAttribute",
  "groupSearchFilter",
  "immutableSubjectAttribute",
  "immutableSubjectFormat",
  "jitMode",
  "lastNameAttribute",
  "maxEntries",
  "maxGroups",
  "maxNestedGroupDepth",
  "maxPages",
  "maxReferralHops",
  "maxResponseBytes",
  "nestedGroupMode",
  "noMatchPolicy",
  "operationTimeoutMs",
  "pageSize",
  "posixGidNumberAttribute",
  "posixMemberUidAttribute",
  "referralMode",
  "syncIntervalSeconds",
  "template",
  "userBaseDn",
  "userDnTemplate",
  "userSearchFilter",
  "usernameAttribute",
  "verifyCertificate",
] as const;

function toPlatformAuthProviderPage(
  page: PlatformAuthProviderList,
  after?: string,
): PlatformAuthProviderPageView {
  assertProjectionObject(page);
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    (page.nextCursor !== undefined &&
      !canonicalUuidV7Pattern.test(page.nextCursor))
  ) {
    throw tenantProjectionError();
  }
  const items = page.items.map(toPlatformAuthProviderSummary);
  if (
    items.some(
      (provider, index) =>
        (after !== undefined && provider.id <= after) ||
        (index > 0 && provider.id <= items[index - 1]!.id),
    ) ||
    new Set(items.map((provider) => provider.key)).size !== items.length ||
    (page.nextCursor !== undefined &&
      (items.length === 0 || page.nextCursor !== items.at(-1)?.id))
  ) {
    throw tenantProjectionError();
  }
  return {
    items,
    ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
  };
}

function toPlatformLocalAccountPage(
  page: PlatformLocalAccountList,
  after?: string,
  includeDisabled = false,
): PlatformLocalAccountPageView {
  assertProjectionObject(page);
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    (page.nextCursor !== undefined &&
      !canonicalUuidV7Pattern.test(page.nextCursor))
  ) {
    throw tenantProjectionError();
  }
  const items = page.items.map(toPlatformLocalAccount);
  if (
    items.some(
      (account, index) =>
        (!includeDisabled && account.status === "disabled") ||
        (after !== undefined && account.id <= after) ||
        (index > 0 && account.id <= items[index - 1]!.id),
    ) ||
    (page.nextCursor !== undefined &&
      (items.length === 0 || page.nextCursor !== items.at(-1)?.id))
  ) {
    throw tenantProjectionError();
  }
  return {
    items,
    ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
  };
}

function toPlatformLocalAccount(
  account: PlatformLocalAccount,
): PlatformLocalAccountView {
  assertProjectionObject(account);
  assertExactOwnKeys(account, [
    "activatedAt",
    "confirmedAcceptableFactors",
    "credentialStatus",
    "credentialVersion",
    "disabledAt",
    "displayName",
    "id",
    "identityEpoch",
    "invitedAt",
    "loginIdentifier",
    "loginIdentifierStatus",
    "protectedRecoveryPrincipal",
    "recoveryStartedAt",
    "revision",
    "status",
    "updatedAt",
    "userId",
  ]);
  const invitedAt = parseRfc3339Instant(account.invitedAt);
  const updatedAt = parseRfc3339Instant(account.updatedAt);
  const activatedAt =
    account.activatedAt === null
      ? undefined
      : parseRfc3339Instant(account.activatedAt);
  const disabledAt =
    account.disabledAt === null
      ? undefined
      : parseRfc3339Instant(account.disabledAt);
  const recoveryStartedAt =
    account.recoveryStartedAt === null
      ? undefined
      : parseRfc3339Instant(account.recoveryStartedAt);
  const validOptionalInstant = (value: bigint | undefined): boolean =>
    value === undefined ||
    (invitedAt !== undefined &&
      updatedAt !== undefined &&
      value >= invitedAt &&
      value <= updatedAt);
  const commonValid =
    canonicalUuidV7Pattern.test(account.id) &&
    canonicalUuidV7Pattern.test(account.userId) &&
    account.id !== account.userId &&
    isSafePlatformText(account.displayName, 1, 160) &&
    isSafePlatformText(account.loginIdentifier, 3, 320) &&
    account.loginIdentifier === account.loginIdentifier.toLowerCase() &&
    account.loginIdentifier.indexOf("@") > 0 &&
    ["invited", "active", "disabled", "recovery_restricted"].includes(
      account.status,
    ) &&
    ["pending", "verified", "disabled"].includes(
      account.loginIdentifierStatus,
    ) &&
    ["pending", "active", "disabled"].includes(account.credentialStatus) &&
    Number.isSafeInteger(account.credentialVersion) &&
    account.credentialVersion >= 0 &&
    Number.isSafeInteger(account.confirmedAcceptableFactors) &&
    account.confirmedAcceptableFactors >= 0 &&
    account.confirmedAcceptableFactors <= 65_535 &&
    typeof account.protectedRecoveryPrincipal === "boolean" &&
    Number.isSafeInteger(account.revision) &&
    account.revision >= 1 &&
    Number.isSafeInteger(account.identityEpoch) &&
    account.identityEpoch >= 1 &&
    invitedAt !== undefined &&
    updatedAt !== undefined &&
    updatedAt >= invitedAt &&
    validOptionalInstant(activatedAt) &&
    validOptionalInstant(disabledAt) &&
    validOptionalInstant(recoveryStartedAt);
  const stateValid =
    (account.status === "invited" &&
      account.loginIdentifierStatus === "pending" &&
      account.credentialStatus === "pending" &&
      account.credentialVersion === 0 &&
      account.confirmedAcceptableFactors === 0 &&
      account.activatedAt === null &&
      account.disabledAt === null &&
      account.recoveryStartedAt === null) ||
    (account.status === "active" &&
      account.loginIdentifierStatus === "verified" &&
      account.credentialStatus === "active" &&
      account.credentialVersion > 0 &&
      account.confirmedAcceptableFactors > 0 &&
      account.activatedAt !== null &&
      account.disabledAt === null) ||
    (account.status === "disabled" &&
      account.loginIdentifierStatus !== "pending" &&
      account.credentialStatus === "disabled" &&
      account.credentialVersion > 0 &&
      account.activatedAt !== null &&
      account.disabledAt !== null) ||
    (account.status === "recovery_restricted" &&
      account.loginIdentifierStatus === "verified" &&
      account.credentialStatus === "pending" &&
      account.credentialVersion > 0 &&
      account.confirmedAcceptableFactors === 0 &&
      account.activatedAt !== null &&
      account.recoveryStartedAt !== null &&
      account.disabledAt === null);
  if (!commonValid || !stateValid) throw tenantProjectionError();
  return { ...account };
}

function toPlatformAuthProviderAccountPage(
  page: PlatformAuthProviderAccountList,
  providerId: string,
  after?: string,
  includeRetired = false,
): PlatformAuthProviderAccountPageView {
  assertProjectionObject(page);
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (
    !canonicalUuidV7Pattern.test(providerId) ||
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    (page.nextCursor !== undefined &&
      !canonicalUuidV7Pattern.test(page.nextCursor))
  ) {
    throw tenantProjectionError();
  }
  const items = page.items.map(toPlatformAuthProviderAccount);
  if (
    items.some(
      (account, index) =>
        account.providerId !== providerId ||
        (!includeRetired && account.state === "retired") ||
        (after !== undefined && account.id <= after) ||
        (index > 0 && account.id <= items[index - 1]!.id),
    ) ||
    (page.nextCursor !== undefined &&
      (items.length === 0 || page.nextCursor !== items.at(-1)?.id))
  ) {
    throw tenantProjectionError();
  }
  return {
    items,
    ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
  };
}

function toPlatformAuthProviderAccount(
  account: PlatformAuthProviderAccount,
): PlatformAuthProviderAccountView {
  assertExactOwnKeys(account, [
    "admittedConfigurationRevision",
    "admittedSecurityRevision",
    "createdAt",
    "id",
    "lastObservationState",
    "lastObservedAt",
    "providerId",
    "retiredAt",
    "state",
    "updatedAt",
    "user",
    "version",
  ]);
  assertExactOwnKeys(account.user, [
    "active",
    "displayName",
    "email",
    "id",
    "version",
  ]);
  const createdAt = parseRfc3339Instant(account.createdAt);
  const updatedAt = parseRfc3339Instant(account.updatedAt);
  const lastObservedAt =
    account.lastObservedAt === null
      ? undefined
      : parseRfc3339Instant(account.lastObservedAt);
  const retiredAt =
    account.retiredAt === null
      ? undefined
      : parseRfc3339Instant(account.retiredAt);
  assertResourceVersion(account.version);
  assertResourceVersion(account.user.version);
  assertPlatformAuthProviderRevision(account.admittedConfigurationRevision);
  assertPlatformAuthProviderRevision(account.admittedSecurityRevision);
  const hasKnownObservation =
    account.lastObservationState === "known" &&
    account.lastObservedAt !== null &&
    lastObservedAt !== undefined;
  const hasLegacyUnknownObservation =
    account.lastObservationState === "legacy_unknown" &&
    account.state === "retired" &&
    account.lastObservedAt === null &&
    account.version === 1;
  if (
    !canonicalUuidV7Pattern.test(account.id) ||
    !canonicalUuidV7Pattern.test(account.providerId) ||
    !canonicalUuidV7Pattern.test(account.user.id) ||
    !isSafePlatformText(account.user.displayName, 1, 160) ||
    typeof account.user.active !== "boolean" ||
    (account.user.email !== null &&
      (!isSafePlatformText(account.user.email, 3, 320) ||
        account.user.email !== account.user.email.toLowerCase() ||
        account.user.email.indexOf("@") <= 0)) ||
    !["active", "retired"].includes(account.state) ||
    createdAt === undefined ||
    updatedAt === undefined ||
    (!hasKnownObservation && !hasLegacyUnknownObservation) ||
    updatedAt < createdAt ||
    (hasKnownObservation &&
      (lastObservedAt < createdAt || lastObservedAt > updatedAt)) ||
    (account.state === "active" && account.retiredAt !== null) ||
    (account.state === "retired" &&
      (retiredAt === undefined ||
        retiredAt < createdAt ||
        (hasKnownObservation && retiredAt < lastObservedAt) ||
        retiredAt > updatedAt))
  ) {
    throw tenantProjectionError();
  }
  return {
    ...account,
    user: { ...account.user },
  };
}

function assertPlatformAuthProviderAccountPath(
  account: PlatformAuthProviderAccountView,
  providerId: string,
  accountId: string,
): void {
  if (account.providerId !== providerId || account.id !== accountId) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderAccountEntityTag(
  etag: string,
  expectedVersion: number,
  expectedUserVersion: number,
): void {
  const match = platformAuthProviderAccountStrongEntityTagPattern.exec(etag);
  if (
    !match ||
    match[1] !== String(expectedVersion) ||
    match[2] !== String(expectedUserVersion)
  ) {
    throw tenantProjectionError();
  }
}

function assertPlatformAuthProviderAccountRetirement(
  previous: PlatformAuthProviderAccountView,
  next: PlatformAuthProviderAccountView,
): void {
  assertPlatformAuthProviderAccountPath(next, previous.providerId, previous.id);
  const previousUpdatedAt = parseRfc3339Instant(previous.updatedAt);
  const nextUpdatedAt = parseRfc3339Instant(next.updatedAt);
  const previousLastObservedAt =
    previous.lastObservedAt === null
      ? undefined
      : parseRfc3339Instant(previous.lastObservedAt);
  const nextLastObservedAt =
    next.lastObservedAt === null
      ? undefined
      : parseRfc3339Instant(next.lastObservedAt);
  const nextRetiredAt =
    next.retiredAt === null ? undefined : parseRfc3339Instant(next.retiredAt);
  if (
    previous.state !== "active" ||
    previous.version >= maximumResourceVersion ||
    next.state !== "retired" ||
    next.retiredAt === null ||
    next.version !== previous.version + 1 ||
    next.createdAt !== previous.createdAt ||
    next.admittedConfigurationRevision !==
      previous.admittedConfigurationRevision ||
    next.admittedSecurityRevision !== previous.admittedSecurityRevision ||
    previous.lastObservationState !== "known" ||
    next.lastObservationState !== previous.lastObservationState ||
    next.lastObservedAt !== previous.lastObservedAt ||
    next.user.id !== previous.user.id ||
    next.user.version !== previous.user.version ||
    next.user.displayName !== previous.user.displayName ||
    next.user.email !== previous.user.email ||
    next.user.active !== previous.user.active ||
    previousUpdatedAt === undefined ||
    nextUpdatedAt === undefined ||
    nextUpdatedAt < previousUpdatedAt ||
    previousLastObservedAt === undefined ||
    nextLastObservedAt === undefined ||
    nextLastObservedAt !== previousLastObservedAt ||
    nextRetiredAt === undefined ||
    nextRetiredAt < previousUpdatedAt ||
    nextRetiredAt < previousLastObservedAt
  ) {
    throw tenantProjectionError();
  }
}

function toPlatformAuthProviderTenantBindingPage(
  page: PlatformAuthProviderTenantBindingList,
  providerId: string,
  after?: string,
): PlatformAuthProviderTenantBindingPageView {
  assertProjectionObject(page);
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    (page.nextCursor !== undefined &&
      !canonicalUuidV7Pattern.test(page.nextCursor))
  ) {
    throw tenantProjectionError();
  }
  const items = page.items.map(toPlatformAuthProviderTenantBinding);
  if (
    items.some(
      (binding, index) =>
        binding.providerId !== providerId ||
        (after !== undefined && binding.id <= after) ||
        (index > 0 && binding.id <= items[index - 1]!.id),
    ) ||
    new Set(items.map((binding) => binding.tenant.id)).size !== items.length ||
    (page.nextCursor !== undefined &&
      (items.length === 0 || page.nextCursor !== items.at(-1)?.id))
  ) {
    throw tenantProjectionError();
  }
  return {
    items,
    ...(page.nextCursor === undefined ? {} : { nextCursor: page.nextCursor }),
  };
}

function toPlatformAuthProviderTenantBinding(
  binding: PlatformAuthProviderTenantBinding,
): PlatformAuthProviderTenantBindingView {
  assertExactOwnKeys(binding, platformAuthProviderTenantBindingKeys);
  assertExactOwnKeys(binding.tenant, [
    "id",
    "name",
    "slug",
    "status",
    "version",
  ]);
  assertResourceVersion(binding.version);
  assertPlatformAuthProviderRevision(binding.authRevision);
  assertPlatformAuthProviderRevision(binding.mappingRevision);
  assertResourceVersion(binding.tenant.version);
  const createdAt = parseRfc3339Instant(binding.createdAt);
  const updatedAt = parseRfc3339Instant(binding.updatedAt);
  const archivedAt =
    binding.archivedAt === null
      ? undefined
      : parseRfc3339Instant(binding.archivedAt);
  if (
    !canonicalUuidV7Pattern.test(binding.id) ||
    !canonicalUuidV7Pattern.test(binding.providerId) ||
    !canonicalUuidV7Pattern.test(binding.tenant.id) ||
    typeof binding.tenant.slug !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(binding.tenant.slug) ||
    !isSafePlatformText(binding.tenant.name, 1, 160) ||
    !["active", "suspended"].includes(binding.tenant.status) ||
    binding.origin !== "platform" ||
    !isPlatformProviderKey(binding.loginKey) ||
    !isBoundedInteger(binding.profilePriority, 0, 1_000_000) ||
    !["disabled", "create"].includes(binding.jitMode) ||
    !["deny", "provider_access_only"].includes(binding.noMatchPolicy) ||
    typeof binding.enabled !== "boolean" ||
    typeof binding.activationAvailable !== "boolean" ||
    (!binding.enabled &&
      (binding.jitMode !== "disabled" || binding.noMatchPolicy !== "deny")) ||
    (binding.currentAccessEpochId !== null &&
      !canonicalUuidV7Pattern.test(binding.currentAccessEpochId)) ||
    binding.enabled !== (binding.currentAccessEpochId !== null) ||
    (binding.enabled && binding.activationAvailable) ||
    (binding.activationAvailable && binding.tenant.status !== "active") ||
    (binding.activationAvailable && binding.archivedAt !== null) ||
    (binding.archivedAt !== null &&
      (binding.enabled ||
        binding.activationAvailable ||
        binding.currentAccessEpochId !== null)) ||
    createdAt === undefined ||
    updatedAt === undefined ||
    updatedAt < createdAt ||
    (binding.archivedAt !== null && archivedAt === undefined) ||
    (archivedAt !== undefined &&
      (archivedAt < createdAt || archivedAt > updatedAt))
  ) {
    throw tenantProjectionError();
  }
  return {
    activationAvailable: binding.activationAvailable,
    archivedAt: binding.archivedAt,
    authRevision: binding.authRevision,
    createdAt: binding.createdAt,
    currentAccessEpochId: binding.currentAccessEpochId,
    enabled: binding.enabled,
    id: binding.id,
    jitMode: binding.jitMode,
    loginKey: binding.loginKey,
    mappingRevision: binding.mappingRevision,
    noMatchPolicy: binding.noMatchPolicy,
    origin: "platform",
    profilePriority: binding.profilePriority,
    providerId: binding.providerId,
    tenant: { ...binding.tenant },
    updatedAt: binding.updatedAt,
    version: binding.version,
  };
}

function assertPlatformAuthProviderTenantBindingProjection(
  binding: PlatformAuthProviderTenantBindingView,
  providerId: string,
  bindingId: string,
): void {
  if (binding.providerId !== providerId || binding.id !== bindingId) {
    throw tenantProjectionError();
  }
}

function toPlatformAuthProviderSummary(
  provider: PlatformAuthProviderSummary,
): PlatformAuthProviderSummaryView {
  assertExactOwnKeys(provider, platformAuthProviderSummaryKeys);
  return toPlatformAuthProviderCommon(provider);
}

function toPlatformAuthProvider(
  provider: PlatformAuthProvider,
): PlatformAuthProviderView {
  assertProjectionObject(provider);
  assertExactOwnKeys(
    provider,
    provider.kind === "ldap"
      ? platformLdapAuthProviderDetailKeys
      : platformAuthProviderDetailKeys,
  );
  const common = toPlatformAuthProviderCommon(provider);
  assertPlatformAuthProviderRevision(provider.configurationRevision);
  assertPlatformAuthProviderRevision(provider.securityRevision);
  assertPlatformAuthProviderRevision(provider.planRevision);
  assertPlatformAuthProviderRevision(provider.assurancePolicyRevision);
  const deploymentEndpoints = derivePlatformAuthProviderDeploymentEndpoints(
    typeof globalThis.location === "undefined"
      ? null
      : globalThis.location.origin,
    provider.key,
  );

  if (provider.kind === "ldap") {
    assertLdapConfiguration(provider.configuration, "existing_identity");
    const endpoints = provider.endpoints.map(toPlatformLdapEndpoint);
    const mappings = provider.mappings.map(toPlatformLdapMapping);
    const endpointPriorities = new Set<number>();
    const endpointIdentities = new Set<string>();
    for (const endpoint of endpoints) {
      const identity = `${endpoint.transport}\u0000${endpoint.host}\u0000${endpoint.port}`;
      if (
        endpointPriorities.has(endpoint.priority) ||
        endpointIdentities.has(identity)
      ) {
        throw tenantProjectionError();
      }
      endpointPriorities.add(endpoint.priority);
      endpointIdentities.add(identity);
    }
    if (
      provider.activationAvailable ||
      !provider.configured ||
      provider.accountMode !==
        (provider.platformLoginEnabled ? "existing_identity" : "disabled") ||
      endpoints.length < 1 ||
      endpoints.length > 8 ||
      endpoints.some(
        (endpoint, index) =>
          index > 0 && endpoint.priority <= endpoints[index - 1]!.priority,
      ) ||
      mappings.some(
        (mapping, index) =>
          index > 0 &&
          (mapping.priority < mappings[index - 1]!.priority ||
            (mapping.priority === mappings[index - 1]!.priority &&
              mapping.id <= mappings[index - 1]!.id)),
      )
    ) {
      throw tenantProjectionError();
    }
    return {
      ...common,
      accountMode: provider.accountMode,
      activationAvailable: false,
      assurancePolicyRevision: provider.assurancePolicyRevision,
      configuration: { ...provider.configuration },
      configurationRevision: provider.configurationRevision,
      endpoints,
      configured: true,
      kind: "ldap",
      mappings,
      planRevision: provider.planRevision,
      securityRevision: provider.securityRevision,
    };
  }

  if (deploymentEndpoints === null) throw tenantProjectionError();

  if (provider.kind === "oidc") {
    const configuration = provider.configuration;
    assertExactOwnKeys(configuration, platformOidcConfigurationKeys);
    assertPlatformAuthProviderRevision(configuration.clientSecretRevision);
    assertPlatformAuthProviderRevision(configuration.discoveryRevision);
    assertPlatformAuthProviderRevision(configuration.jwksRevision);
    if (
      !isHttpsPlatformUri(configuration.issuer, false, 2048) ||
      !isPlatformOidcClientId(configuration.clientId) ||
      !isHttpsPlatformUri(configuration.redirectUri, true) ||
      !isHttpsPlatformUri(configuration.tenantRedirectUri, true) ||
      !isHttpsPlatformUri(configuration.postLogoutRedirectUri, true) ||
      configuration.redirectUri !== deploymentEndpoints.oidcRedirectUri ||
      configuration.tenantRedirectUri !==
        deploymentEndpoints.oidcTenantRedirectUri ||
      configuration.postLogoutRedirectUri !==
        deploymentEndpoints.oidcPostLogoutRedirectUri ||
      !isPlatformOidcExtraScopes(
        configuration.extraScopes,
        configuration.allowRefreshToken,
      ) ||
      typeof configuration.useUserInfo !== "boolean" ||
      (configuration.useUserInfo &&
        (provider.platformLoginActivationAvailable ||
          provider.platformLoginEnabled)) ||
      typeof configuration.clientSecretPresent !== "boolean" ||
      (configuration.clientSecretPresent &&
        configuration.clientSecretRevision < 2) ||
      common.secretPresent !== configuration.clientSecretPresent ||
      (provider.enabled
        ? !["existing_identity", "create"].includes(provider.accountMode)
        : provider.accountMode !== "disabled")
    ) {
      throw tenantProjectionError();
    }
    return {
      ...common,
      accountMode: provider.accountMode,
      assurancePolicyRevision: provider.assurancePolicyRevision,
      configuration: {
        allowRefreshToken: configuration.allowRefreshToken,
        clientId: configuration.clientId,
        clientSecretPresent: configuration.clientSecretPresent,
        clientSecretRevision: configuration.clientSecretRevision,
        discoveryRevision: configuration.discoveryRevision,
        extraScopes: [...configuration.extraScopes],
        issuer: configuration.issuer,
        jwksRevision: configuration.jwksRevision,
        postLogoutRedirectUri: configuration.postLogoutRedirectUri,
        redirectUri: configuration.redirectUri,
        tenantRedirectUri: configuration.tenantRedirectUri,
        useUserInfo: configuration.useUserInfo,
      },
      configurationRevision: provider.configurationRevision,
      kind: "oidc",
      planRevision: provider.planRevision,
      securityRevision: provider.securityRevision,
    };
  }

  const configuration = provider.configuration;
  assertProjectionObject(configuration);
  if (
    configuration.subjectSource !== "persistent_nameid" &&
    configuration.subjectSource !== "immutable_attribute"
  ) {
    throw tenantProjectionError();
  }
  const attributeSubject =
    configuration.subjectSource === "immutable_attribute";
  assertExactOwnKeys(
    configuration,
    attributeSubject
      ? [
          ...platformSamlConfigurationBaseKeys,
          "subjectAttributeName",
          "subjectAttributeNameFormat",
        ]
      : platformSamlConfigurationBaseKeys,
  );
  assertPlatformAuthProviderRevision(configuration.spKeyRevision);
  assertPlatformAuthProviderRevision(configuration.metadataRevision);
  if (
    typeof configuration.spKeyPresent !== "boolean" ||
    (configuration.spKeyPresent && configuration.spKeyRevision < 2) ||
    common.secretPresent !== configuration.spKeyPresent ||
    (provider.enabled
      ? !["existing_identity", "create"].includes(provider.accountMode)
      : provider.accountMode !== "disabled") ||
    !isPlatformUri(configuration.expectedEntityId, 2048) ||
    !isPlatformXml10Text(configuration.expectedEntityId) ||
    !isPlatformUri(configuration.spEntityId, 2048) ||
    !isPlatformXml10Text(configuration.spEntityId) ||
    configuration.expectedEntityId === configuration.spEntityId ||
    !isHttpsPlatformUri(configuration.acsUrl, true) ||
    configuration.spEntityId !== deploymentEndpoints.samlSpEntityId ||
    configuration.acsUrl !== deploymentEndpoints.samlAcsUrl ||
    !platformSamlRedirectSignatureAlgorithms.includes(
      configuration.redirectSignatureAlgorithm,
    ) ||
    !["signed_assertion", "signed_response", "both"].includes(
      configuration.signaturePolicy,
    ) ||
    !["disabled", "optional", "required"].includes(
      configuration.encryptionPolicy,
    ) ||
    !isUniquePlatformStringList(
      configuration.requestedAuthnContexts,
      1,
      32,
      (context) => isPlatformUri(context, 2048) && isPlatformXml10Text(context),
    ) ||
    !Number.isSafeInteger(configuration.clockSkewNanoseconds) ||
    configuration.clockSkewNanoseconds < 0 ||
    configuration.clockSkewNanoseconds > 300_000_000_000 ||
    !Number.isSafeInteger(configuration.maxAuthenticationAgeNanoseconds) ||
    configuration.maxAuthenticationAgeNanoseconds < 60_000_000_000 ||
    configuration.maxAuthenticationAgeNanoseconds > 86_400_000_000_000
  ) {
    throw tenantProjectionError();
  }

  const projectedConfiguration =
    configuration.subjectSource === "immutable_attribute"
      ? (() => {
          if (
            !isSafePlatformText(
              configuration.subjectAttributeName,
              1,
              512,
              512,
            ) ||
            !isPlatformXml10Text(configuration.subjectAttributeName) ||
            !isPlatformUri(configuration.subjectAttributeNameFormat, 512) ||
            !isPlatformXml10Text(configuration.subjectAttributeNameFormat)
          ) {
            throw tenantProjectionError();
          }
          return {
            acsUrl: configuration.acsUrl,
            clockSkewNanoseconds: configuration.clockSkewNanoseconds,
            encryptionPolicy: configuration.encryptionPolicy,
            expectedEntityId: configuration.expectedEntityId,
            maxAuthenticationAgeNanoseconds:
              configuration.maxAuthenticationAgeNanoseconds,
            metadataRevision: configuration.metadataRevision,
            redirectSignatureAlgorithm:
              configuration.redirectSignatureAlgorithm,
            requestedAuthnContexts: [...configuration.requestedAuthnContexts],
            signaturePolicy: configuration.signaturePolicy,
            spEntityId: configuration.spEntityId,
            spKeyPresent: configuration.spKeyPresent,
            spKeyRevision: configuration.spKeyRevision,
            subjectAttributeName: configuration.subjectAttributeName,
            subjectAttributeNameFormat:
              configuration.subjectAttributeNameFormat,
            subjectSource: "immutable_attribute" as const,
          };
        })()
      : {
          acsUrl: configuration.acsUrl,
          clockSkewNanoseconds: configuration.clockSkewNanoseconds,
          encryptionPolicy: configuration.encryptionPolicy,
          expectedEntityId: configuration.expectedEntityId,
          maxAuthenticationAgeNanoseconds:
            configuration.maxAuthenticationAgeNanoseconds,
          metadataRevision: configuration.metadataRevision,
          redirectSignatureAlgorithm: configuration.redirectSignatureAlgorithm,
          requestedAuthnContexts: [...configuration.requestedAuthnContexts],
          signaturePolicy: configuration.signaturePolicy,
          spEntityId: configuration.spEntityId,
          spKeyPresent: configuration.spKeyPresent,
          spKeyRevision: configuration.spKeyRevision,
          subjectSource: "persistent_nameid" as const,
        };
  return {
    ...common,
    accountMode: provider.accountMode,
    assurancePolicyRevision: provider.assurancePolicyRevision,
    configuration: projectedConfiguration,
    configurationRevision: provider.configurationRevision,
    kind: "saml",
    planRevision: provider.planRevision,
    securityRevision: provider.securityRevision,
  };
}

function toPlatformLdapAuthProvider(
  provider: PlatformLdapAuthProvider,
): PlatformLdapAuthProviderView {
  const projected = toPlatformAuthProvider(provider);
  if (projected.kind !== "ldap") throw tenantProjectionError();
  return projected;
}

function toPlatformAuthProviderCommon(
  provider: PlatformAuthProviderSummary,
): PlatformAuthProviderSummaryView {
  assertResourceVersion(provider.version);
  const createdAt = parseRfc3339Instant(provider.createdAt);
  const updatedAt = parseRfc3339Instant(provider.updatedAt);
  const archivedAt =
    provider.archivedAt === null
      ? undefined
      : parseRfc3339Instant(provider.archivedAt);
  const ldapStateValid =
    provider.kind === "ldap" &&
    !provider.activationAvailable &&
    provider.configured &&
    provider.platformLoginEnabled === provider.enabled &&
    (!provider.platformLoginActivationAvailable ||
      (!provider.enabled &&
        provider.secretPresent &&
        provider.archivedAt === null)) &&
    (!provider.enabled ||
      (provider.secretPresent && provider.archivedAt === null));
  const federationStateValid =
    (provider.kind === "oidc" || provider.kind === "saml") &&
    (!provider.platformLoginActivationAvailable ||
      (provider.enabled &&
        !provider.platformLoginEnabled &&
        provider.configured &&
        provider.secretPresent &&
        provider.archivedAt === null)) &&
    (!provider.platformLoginEnabled ||
      (provider.enabled &&
        provider.configured &&
        provider.secretPresent &&
        provider.archivedAt === null)) &&
    !(provider.enabled && provider.activationAvailable) &&
    (!(provider.enabled || provider.activationAvailable) ||
      (provider.configured && provider.secretPresent));
  if (
    !canonicalUuidV7Pattern.test(provider.id) ||
    !isPlatformProviderKey(provider.key) ||
    !isSafePlatformText(provider.displayName, 1, 120) ||
    !isSafePlatformText(provider.description, 0, 1000) ||
    !["ldap", "oidc", "saml"].includes(provider.kind) ||
    typeof provider.enabled !== "boolean" ||
    typeof provider.platformLoginActivationAvailable !== "boolean" ||
    typeof provider.platformLoginEnabled !== "boolean" ||
    typeof provider.activationAvailable !== "boolean" ||
    typeof provider.configured !== "boolean" ||
    typeof provider.secretPresent !== "boolean" ||
    (!ldapStateValid && !federationStateValid) ||
    (provider.archivedAt !== null &&
      (provider.enabled ||
        provider.platformLoginActivationAvailable ||
        provider.platformLoginEnabled ||
        provider.activationAvailable)) ||
    createdAt === undefined ||
    updatedAt === undefined ||
    updatedAt < createdAt ||
    (provider.archivedAt !== null && archivedAt === undefined) ||
    (archivedAt !== undefined &&
      (archivedAt < createdAt || archivedAt > updatedAt))
  ) {
    throw tenantProjectionError();
  }
  return {
    activationAvailable: provider.activationAvailable,
    archivedAt: provider.archivedAt,
    configured: provider.configured,
    createdAt: provider.createdAt,
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    id: provider.id,
    key: provider.key,
    kind: provider.kind,
    platformLoginActivationAvailable: provider.platformLoginActivationAvailable,
    platformLoginEnabled: provider.platformLoginEnabled,
    secretPresent: provider.secretPresent,
    updatedAt: provider.updatedAt,
    version: provider.version,
  };
}

function assertPlatformAuthProviderRevision(revision: unknown): void {
  if (
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 1
  ) {
    throw tenantProjectionError();
  }
}

function isSafePlatformText(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  maximumUtf8Bytes?: number,
): value is string {
  return isCanonicalPlatformText(
    value,
    minimumLength,
    maximumLength,
    maximumUtf8Bytes,
  );
}

function isPlatformUri(
  value: unknown,
  maximumUtf8Bytes: number,
): value is string {
  return isPlatformAbsoluteUri(value, maximumUtf8Bytes);
}

function isHttpsPlatformUri(
  value: unknown,
  allowQuery: boolean,
  maximumUtf8Bytes = 4096,
): value is string {
  return isContractPlatformHttpsUri(value, allowQuery, maximumUtf8Bytes);
}

function isUniquePlatformStringList(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  isValidItem: (item: string) => boolean,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length >= minimumLength &&
    value.length <= maximumLength &&
    value.every((item) => typeof item === "string" && isValidItem(item)) &&
    new Set(value).size === value.length
  );
}

function toTenantLdapAuthProviderPage(
  page: TenantLdapAuthProviderList,
): TenantLdapAuthProviderPageView {
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (!Array.isArray(page.items)) throw tenantProjectionError();
  return {
    items: page.items.map(toTenantLdapAuthProviderSummary),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantLdapAuthProviderSummary(
  summary: TenantLdapAuthProviderSummary,
): TenantLdapAuthProviderSummaryView {
  assertExactOwnKeys(summary, ldapSummaryKeys);
  assertLdapProviderIdentity(summary);
  if (
    !["active_directory", "openldap", "posix", "custom"].includes(
      summary.template,
    ) ||
    typeof summary.bindSecretConfigured !== "boolean" ||
    !Number.isSafeInteger(summary.enabledEndpointCount) ||
    summary.enabledEndpointCount < 0 ||
    summary.enabledEndpointCount > 8 ||
    (summary.archivedAt !== null &&
      parseRfc3339Instant(summary.archivedAt) === undefined) ||
    (summary.archivedAt !== null && summary.enabled)
  ) {
    throw tenantProjectionError();
  }
  return { ...summary };
}

function toTenantLdapAuthProvider(
  provider: TenantLdapAuthProvider,
): TenantLdapAuthProviderView {
  assertExactOwnKeys(provider, ldapProviderKeys);
  assertLdapProviderIdentity(provider);
  assertLdapConfiguration(provider.configuration);
  const endpoints = provider.endpoints.map(toTenantLdapEndpoint);
  const endpointPriorities = new Set<number>();
  const endpointIdentities = new Set<string>();
  for (const endpoint of endpoints) {
    if (
      endpointPriorities.has(endpoint.priority) ||
      endpointIdentities.has(
        `${endpoint.transport}\u0000${endpoint.host}\u0000${endpoint.port}`,
      )
    ) {
      throw tenantProjectionError();
    }
    endpointPriorities.add(endpoint.priority);
    endpointIdentities.add(
      `${endpoint.transport}\u0000${endpoint.host}\u0000${endpoint.port}`,
    );
  }
  const enabledEndpointCount = endpoints.filter(
    (endpoint) => endpoint.enabled,
  ).length;
  const archived = provider.archivedAt !== null;
  if (
    provider.template !== provider.configuration.template ||
    provider.enabledEndpointCount !== enabledEndpointCount ||
    endpoints.some(
      (endpoint, index) =>
        index > 0 && endpoint.priority <= endpoints[index - 1]!.priority,
    ) ||
    archived !== (provider.archiveReason !== null) ||
    (archived && provider.enabled) ||
    (provider.archivedAt !== null &&
      parseRfc3339Instant(provider.archivedAt) === undefined) ||
    (provider.bindSecretRotatedAt !== null &&
      parseRfc3339Instant(provider.bindSecretRotatedAt) === undefined) ||
    provider.bindSecretConfigured !== (provider.bindSecretRotatedAt !== null)
  ) {
    throw tenantProjectionError();
  }
  return {
    ...provider,
    configuration: { ...provider.configuration },
    endpoints,
  };
}

function assertTenantLdapProviderProjection(
  provider: TenantLdapAuthProviderView,
  tenantId: string,
  providerId: string,
): void {
  assertTenantId(provider.tenantId, tenantId);
  assertResourceId(provider.id, providerId);
}

function assertLdapProviderIdentity(
  provider: Pick<
    TenantLdapAuthProviderSummary,
    | "createdAt"
    | "displayName"
    | "enabled"
    | "id"
    | "key"
    | "kind"
    | "tenantId"
    | "updatedAt"
    | "version"
  >,
): void {
  assertResourceVersion(provider.version);
  if (
    provider.kind !== "ldap" ||
    !canonicalUuidPattern.test(provider.id) ||
    !canonicalUuidPattern.test(provider.tenantId) ||
    provider.key.trim() !== provider.key ||
    provider.displayName.trim() !== provider.displayName ||
    typeof provider.enabled !== "boolean" ||
    parseRfc3339Instant(provider.createdAt) === undefined ||
    parseRfc3339Instant(provider.updatedAt) === undefined
  ) {
    throw tenantProjectionError();
  }
}

function assertLdapConfiguration(
  configuration: TenantLdapAuthProvider["configuration"],
  jitMode: "disabled" | "existing_identity" = "disabled",
): void {
  assertExactOwnKeys(configuration, ldapConfigurationKeys);
  const accountModeValid =
    (configuration.accountStatusMode === "none" &&
      configuration.accountStatusAttribute === null &&
      configuration.accountDisabledValue === null) ||
    (configuration.accountStatusMode === "active_directory_uac" &&
      typeof configuration.accountStatusAttribute === "string" &&
      configuration.accountStatusAttribute !== "" &&
      configuration.accountDisabledValue === null) ||
    (configuration.accountStatusMode === "attribute_equals" &&
      typeof configuration.accountStatusAttribute === "string" &&
      configuration.accountStatusAttribute !== "" &&
      typeof configuration.accountDisabledValue === "string" &&
      configuration.accountDisabledValue !== "");
  if (
    !configuration.verifyCertificate ||
    configuration.jitMode !== jitMode ||
    configuration.noMatchPolicy !== "deny" ||
    configuration.deprovisionMode !== "retain" ||
    configuration.deprovisionGraceSeconds !== 0 ||
    configuration.syncIntervalSeconds !== null ||
    !accountModeValid
  ) {
    throw tenantProjectionError();
  }
}

function toPlatformLdapEndpoint(
  endpoint: PlatformLdapAuthProvider["endpoints"][number],
): PlatformLdapAuthProviderView["endpoints"][number] {
  assertExactOwnKeys(endpoint, platformLdapEndpointKeys);
  if (
    !canonicalUuidV7Pattern.test(endpoint.id) ||
    !Number.isSafeInteger(endpoint.priority) ||
    endpoint.priority < 1 ||
    endpoint.priority > 8 ||
    !Number.isSafeInteger(endpoint.port) ||
    endpoint.port < 1 ||
    endpoint.port > 65_535 ||
    !["ldaps", "starttls"].includes(endpoint.transport) ||
    !isSafePlatformText(endpoint.host, 1, 253, 253) ||
    endpoint.host !== endpoint.host.toLowerCase() ||
    !isSafePlatformText(endpoint.tlsServerName, 1, 253, 253) ||
    endpoint.tlsServerName !== endpoint.tlsServerName.toLowerCase() ||
    typeof endpoint.enabled !== "boolean" ||
    typeof endpoint.referralAllowed !== "boolean"
  ) {
    throw tenantProjectionError();
  }
  return { ...endpoint };
}

function toPlatformLdapMapping(
  mapping: PlatformLdapAuthProvider["mappings"][number],
): PlatformLdapAuthProviderView["mappings"][number] {
  assertExactOwnKeys(mapping, platformLdapMappingKeys);
  assertResourceVersion(mapping.version);
  const archivedAt =
    mapping.archivedAt === null
      ? undefined
      : parseRfc3339Instant(mapping.archivedAt);
  const lastMatchedAt =
    mapping.lastMatchedAt === null
      ? undefined
      : parseRfc3339Instant(mapping.lastMatchedAt);
  if (
    !canonicalUuidV7Pattern.test(mapping.id) ||
    !canonicalUuidV7Pattern.test(mapping.platformRoleId) ||
    !["exact_dn", "exact_cn", "regex"].includes(mapping.matcherType) ||
    !isSafePlatformText(mapping.matcherValue, 1, 2048) ||
    typeof mapping.caseSensitive !== "boolean" ||
    !isBoundedInteger(mapping.priority, 0, 1_000_000) ||
    !["authoritative", "additive"].includes(mapping.reconciliationMode) ||
    typeof mapping.enabled !== "boolean" ||
    !isSafePlatformText(mapping.notes, 0, 1000) ||
    (mapping.archivedAt !== null && archivedAt === undefined) ||
    (mapping.lastMatchedAt !== null && lastMatchedAt === undefined) ||
    (mapping.archivedAt !== null && mapping.enabled)
  ) {
    throw tenantProjectionError();
  }
  return { ...mapping };
}

function toPlatformLdapDiagnostic(
  diagnostic: PlatformLdapDiagnostic,
): PlatformLdapDiagnosticView {
  const expectedKeys = [
    "attributes",
    "category",
    "durationMs",
    ...(Object.hasOwn(diagnostic, "endpointPriority")
      ? ["endpointPriority"]
      : []),
    "kind",
    ...(Object.hasOwn(diagnostic, "matchedEntryCount")
      ? ["matchedEntryCount"]
      : []),
    "outcome",
    "testId",
  ];
  assertExactOwnKeys(diagnostic, expectedKeys);
  const priority = diagnostic.endpointPriority;
  const matchedCount = diagnostic.matchedEntryCount;
  const attributesValid =
    Array.isArray(diagnostic.attributes) &&
    diagnostic.attributes.length <= 128 &&
    diagnostic.attributes.every(
      (attribute, index) =>
        /^[a-z][a-z0-9;._-]{0,127}$/.test(attribute) &&
        (index === 0 || diagnostic.attributes[index - 1]! < attribute),
    );
  if (
    !canonicalUuidV7Pattern.test(diagnostic.testId) ||
    ![
      "connection",
      "bind",
      "search_user",
      "filter",
      "mapping_dry_run",
    ].includes(diagnostic.kind) ||
    !["success", "failure"].includes(diagnostic.outcome) ||
    ![
      "ok",
      "connection_failed",
      "tls_rejected",
      "bind_rejected",
      "search_rejected",
      "no_match",
      "ambiguous_match",
      "mapping_denied",
      "timeout",
    ].includes(diagnostic.category) ||
    (diagnostic.outcome === "success") !== (diagnostic.category === "ok") ||
    !isBoundedInteger(diagnostic.durationMs, 0, 120_000) ||
    (priority !== undefined &&
      priority !== null &&
      !isBoundedInteger(priority, 1, 8)) ||
    (matchedCount !== undefined &&
      matchedCount !== null &&
      !isBoundedInteger(matchedCount, 0, 100_000)) ||
    !attributesValid
  ) {
    throw tenantProjectionError();
  }
  return { ...diagnostic, attributes: [...diagnostic.attributes] };
}

function toTenantLdapEndpoint(
  endpoint: TenantLdapAuthProvider["endpoints"][number],
) {
  assertExactOwnKeys(endpoint, [
    "enabled",
    "host",
    "port",
    "priority",
    "referralAllowed",
    "tlsServerName",
    "transport",
  ]);
  if (
    !Number.isSafeInteger(endpoint.priority) ||
    endpoint.priority < 1 ||
    endpoint.priority > 8 ||
    !Number.isSafeInteger(endpoint.port) ||
    endpoint.port < 1 ||
    endpoint.port > 65_535 ||
    !["ldaps", "starttls"].includes(endpoint.transport) ||
    endpoint.host === "" ||
    endpoint.host !== endpoint.host.toLowerCase() ||
    endpoint.tlsServerName === "" ||
    endpoint.tlsServerName !== endpoint.tlsServerName.toLowerCase() ||
    typeof endpoint.enabled !== "boolean" ||
    typeof endpoint.referralAllowed !== "boolean"
  ) {
    throw tenantProjectionError();
  }
  return { ...endpoint };
}

function toTenantLdapAuthProviderDiagnostic(
  diagnostic: TenantLdapAuthProviderDiagnostic,
): TenantLdapAuthProviderDiagnosticView {
  assertExactOwnKeys(diagnostic, [
    "category",
    "completedAt",
    "durationMs",
    "endpointPriority",
    "outcome",
    "stale",
    "testRunId",
  ]);
  const priorityIsBounded =
    Number.isSafeInteger(diagnostic.endpointPriority) &&
    diagnostic.endpointPriority !== null &&
    diagnostic.endpointPriority >= 1 &&
    diagnostic.endpointPriority <= 8;
  const validBranch =
    (diagnostic.outcome === "success" &&
      diagnostic.category === "success" &&
      !diagnostic.stale &&
      priorityIsBounded) ||
    (diagnostic.outcome === "inconclusive" &&
      diagnostic.category === "stale_configuration" &&
      diagnostic.stale &&
      (diagnostic.endpointPriority === null || priorityIsBounded)) ||
    (diagnostic.outcome === "failure" &&
      diagnostic.category === "cancelled" &&
      !diagnostic.stale &&
      diagnostic.endpointPriority === null) ||
    (diagnostic.outcome === "failure" &&
      [
        "bind_rejected",
        "certificate_rejected",
        "connect_failed",
        "connect_timeout",
        "destination_blocked",
        "dns_failed",
        "protocol_failed",
        "tls_failed",
      ].includes(diagnostic.category) &&
      !diagnostic.stale &&
      priorityIsBounded);
  if (
    !canonicalUuidPattern.test(diagnostic.testRunId) ||
    !Number.isSafeInteger(diagnostic.durationMs) ||
    diagnostic.durationMs < 0 ||
    diagnostic.durationMs > 120_000 ||
    parseRfc3339Instant(diagnostic.completedAt) === undefined ||
    !validBranch
  ) {
    throw tenantProjectionError();
  }
  return { ...diagnostic };
}

const ldapBindingKeys = [
  "archivedAt",
  "authRevision",
  "createdAt",
  "currentAccessEpochId",
  "enabled",
  "id",
  "loginKey",
  "profilePriority",
  "providerId",
  "tenantId",
  "updatedAt",
  "version",
] as const;

function toTenantLdapAuthProviderBindingPage(
  page: TenantLdapAuthProviderBindingList,
): TenantLdapAuthProviderBindingPageView {
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (!Array.isArray(page.items)) throw tenantProjectionError();
  return {
    items: page.items.map(toTenantLdapAuthProviderBinding),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantLdapAuthProviderBinding(
  binding: TenantLdapAuthProviderBinding,
): TenantLdapAuthProviderBindingView {
  assertExactOwnKeys(binding, ldapBindingKeys);
  assertResourceVersion(binding.version);
  if (
    !canonicalUuidPattern.test(binding.id) ||
    !canonicalUuidPattern.test(binding.tenantId) ||
    !canonicalUuidPattern.test(binding.providerId) ||
    !/^[a-z][a-z0-9_-]{2,63}$/.test(binding.loginKey) ||
    !isBoundedInteger(binding.profilePriority, 0, 1_000_000) ||
    !isBoundedInteger(binding.authRevision, 1, maximumResourceVersion) ||
    parseRfc3339Instant(binding.createdAt) === undefined ||
    parseRfc3339Instant(binding.updatedAt) === undefined ||
    (binding.archivedAt !== null &&
      parseRfc3339Instant(binding.archivedAt) === undefined) ||
    (binding.currentAccessEpochId !== null &&
      !canonicalUuidPattern.test(binding.currentAccessEpochId)) ||
    binding.enabled !== (binding.currentAccessEpochId !== null) ||
    (binding.archivedAt !== null && binding.enabled)
  ) {
    throw tenantProjectionError();
  }
  return { ...binding };
}

function assertTenantLdapBindingProjection(
  binding: TenantLdapAuthProviderBindingView,
  tenantId: string,
  bindingId: string,
  providerId?: string,
): void {
  assertTenantId(binding.tenantId, tenantId);
  assertResourceId(binding.id, bindingId);
  if (providerId !== undefined)
    assertResourceId(binding.providerId, providerId);
}

const ldapMappingKeys = [
  "archivedAt",
  "bindingId",
  "createdAt",
  "currentSourceEpoch",
  "enabled",
  "id",
  "lastMatchedAt",
  "matcher",
  "notes",
  "priority",
  "reconciliationMode",
  "target",
  "tenantId",
  "updatedAt",
  "version",
] as const;

function toTenantLdapMappingPage(
  page: TenantLdapMappingList,
): TenantLdapMappingPageView {
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (!Array.isArray(page.items)) throw tenantProjectionError();
  return {
    items: page.items.map(toTenantLdapMapping),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantLdapMapping(
  mapping: TenantLdapMapping,
): TenantLdapMappingView {
  assertExactOwnKeys(mapping, ldapMappingKeys);
  assertResourceVersion(mapping.version);
  assertTenantLdapMatcher(mapping.matcher);
  assertExactOwnKeys(mapping.target, [
    "operatorTeamAssignment",
    "roleIds",
    "tenantSecurityGroupId",
  ]);
  if (
    !canonicalUuidPattern.test(mapping.id) ||
    !canonicalUuidPattern.test(mapping.tenantId) ||
    !canonicalUuidPattern.test(mapping.bindingId) ||
    !isBoundedInteger(mapping.priority, 0, 1_000_000) ||
    !["additive", "authoritative"].includes(mapping.reconciliationMode) ||
    !canonicalUuidPattern.test(mapping.target.tenantSecurityGroupId) ||
    !Array.isArray(mapping.target.roleIds) ||
    mapping.target.roleIds.length < 1 ||
    mapping.target.roleIds.length > 32 ||
    mapping.target.roleIds.some((id) => !canonicalUuidPattern.test(id)) ||
    new Set(mapping.target.roleIds).size !== mapping.target.roleIds.length ||
    typeof mapping.notes !== "string" ||
    mapping.notes.length > 2_000 ||
    parseRfc3339Instant(mapping.createdAt) === undefined ||
    parseRfc3339Instant(mapping.updatedAt) === undefined ||
    (mapping.lastMatchedAt !== null &&
      parseRfc3339Instant(mapping.lastMatchedAt) === undefined) ||
    (mapping.archivedAt !== null &&
      parseRfc3339Instant(mapping.archivedAt) === undefined) ||
    mapping.enabled !== (mapping.currentSourceEpoch !== null) ||
    (mapping.archivedAt !== null && mapping.enabled)
  ) {
    throw tenantProjectionError();
  }
  if (mapping.target.operatorTeamAssignment !== null) {
    assertExactOwnKeys(mapping.target.operatorTeamAssignment, [
      "assignmentEpochId",
      "operatorTeamId",
    ]);
    if (
      !canonicalUuidPattern.test(
        mapping.target.operatorTeamAssignment.operatorTeamId,
      ) ||
      !canonicalUuidPattern.test(
        mapping.target.operatorTeamAssignment.assignmentEpochId,
      )
    ) {
      throw tenantProjectionError();
    }
  }
  if (mapping.currentSourceEpoch !== null) {
    assertExactOwnKeys(mapping.currentSourceEpoch, [
      "activatedAt",
      "id",
      "reconciliationMode",
      "sequence",
    ]);
    if (
      !canonicalUuidPattern.test(mapping.currentSourceEpoch.id) ||
      !isBoundedInteger(
        mapping.currentSourceEpoch.sequence,
        1,
        maximumResourceVersion,
      ) ||
      mapping.currentSourceEpoch.reconciliationMode !==
        mapping.reconciliationMode ||
      parseRfc3339Instant(mapping.currentSourceEpoch.activatedAt) === undefined
    ) {
      throw tenantProjectionError();
    }
  }
  return {
    ...mapping,
    matcher: { ...mapping.matcher },
    target: {
      ...mapping.target,
      roleIds: [...mapping.target.roleIds],
      operatorTeamAssignment: mapping.target.operatorTeamAssignment
        ? { ...mapping.target.operatorTeamAssignment }
        : null,
    },
    currentSourceEpoch: mapping.currentSourceEpoch
      ? { ...mapping.currentSourceEpoch }
      : null,
  };
}

function assertTenantLdapMatcher(matcher: TenantLdapMapping["matcher"]): void {
  if (!["sensitive", "insensitive"].includes(matcher.caseMode)) {
    throw tenantProjectionError();
  }
  if (matcher.type === "exact_dn") {
    assertExactOwnKeys(matcher, ["caseMode", "dn", "type"]);
    if (
      matcher.dn.trim() !== matcher.dn ||
      matcher.dn.length < 1 ||
      matcher.dn.length > 2_048 ||
      new TextEncoder().encode(matcher.dn).length > 8_192
    ) {
      throw tenantProjectionError();
    }
    return;
  }
  if (matcher.type === "exact_cn") {
    assertExactOwnKeys(matcher, ["caseMode", "cn", "type"]);
    if (
      matcher.cn.trim() !== matcher.cn ||
      matcher.cn.length < 1 ||
      matcher.cn.length > 512
    ) {
      throw tenantProjectionError();
    }
    return;
  }
  if (matcher.type === "regex") {
    assertExactOwnKeys(matcher, ["caseMode", "pattern", "type"]);
    if (matcher.pattern.length < 1 || matcher.pattern.length > 512) {
      throw tenantProjectionError();
    }
    return;
  }
  throw tenantProjectionError();
}

function assertTenantLdapMappingProjection(
  mapping: TenantLdapMappingView,
  tenantId: string,
  mappingId: string,
  bindingId?: string,
): void {
  assertTenantId(mapping.tenantId, tenantId);
  assertResourceId(mapping.id, mappingId);
  if (bindingId !== undefined) assertResourceId(mapping.bindingId, bindingId);
}

function toTenantLdapUserSearchTestResult(
  result: TenantLdapUserSearchTestResult,
): TenantLdapUserSearchTestResultView {
  return toTenantLdapDirectoryTestResult(result);
}

function toTenantLdapFilterTestResult(
  result: TenantLdapFilterTestResult,
): TenantLdapFilterTestResultView {
  return toTenantLdapDirectoryTestResult(result);
}

function toTenantLdapDirectoryTestResult<
  T extends TenantLdapUserSearchTestResult | TenantLdapFilterTestResult,
>(result: T): T {
  assertExactOwnKeys(result, [
    "diagnostic",
    "entries",
    "matchedEntryCount",
    "truncated",
  ]);
  const diagnostic = toTenantLdapAuthProviderDiagnostic(result.diagnostic);
  if (
    !Array.isArray(result.entries) ||
    !isBoundedInteger(result.matchedEntryCount, 0, 100) ||
    typeof result.truncated !== "boolean"
  ) {
    throw tenantProjectionError();
  }
  const entries = result.entries.map((entry, index) => {
    assertExactOwnKeys(entry, [
      "attributes",
      "dnPresent",
      "groupValueCount",
      "immutableSubjectRedacted",
      "ordinal",
    ]);
    if (
      entry.ordinal !== index + 1 ||
      typeof entry.dnPresent !== "boolean" ||
      !entry.immutableSubjectRedacted ||
      !isBoundedInteger(entry.groupValueCount, 0, 100_000) ||
      !Array.isArray(entry.attributes)
    ) {
      throw tenantProjectionError();
    }
    const attributes = entry.attributes.map((attribute) => {
      assertExactOwnKeys(attribute, [
        "name",
        "truncated",
        "valueCount",
        "valuesRedacted",
      ]);
      if (
        attribute.name.trim() !== attribute.name ||
        attribute.name.length < 1 ||
        attribute.name.length > 128 ||
        !isBoundedInteger(attribute.valueCount, 0, 100_000) ||
        typeof attribute.truncated !== "boolean" ||
        !attribute.valuesRedacted
      ) {
        throw tenantProjectionError();
      }
      return { ...attribute };
    });
    return { ...entry, attributes };
  });
  return { ...result, diagnostic, entries };
}

function toTenantLdapMappingDryRunResult(
  result: TenantLdapMappingDryRunResult,
): TenantLdapMappingDryRunResultView {
  assertExactOwnKeys(result, [
    "decision",
    "denialReasons",
    "dryRunId",
    "generatedAt",
    "identityDisposition",
    "matchedMappingIds",
    "observationComplete",
    "outcome",
    "plan",
    "snapshot",
  ]);
  assertLdapPlannerSnapshot(result.snapshot);
  assertExactOwnKeys(result.plan, [
    "groupActions",
    "operatorTeamActions",
    "profileAction",
    "providerAccessAction",
    "roleActions",
  ]);
  const actions = ["add", "refresh", "retain", "revoke", "none"];
  if (
    !canonicalUuidPattern.test(result.dryRunId) ||
    !["success", "failure", "inconclusive"].includes(result.outcome) ||
    !["allow", "deny"].includes(result.decision) ||
    !["existing_identity", "create", "deny", "unresolved"].includes(
      result.identityDisposition,
    ) ||
    typeof result.observationComplete !== "boolean" ||
    !Array.isArray(result.denialReasons) ||
    !Array.isArray(result.matchedMappingIds) ||
    result.matchedMappingIds.some((id) => !canonicalUuidPattern.test(id)) ||
    parseRfc3339Instant(result.generatedAt) === undefined ||
    !["none", "create", "link", "update"].includes(result.plan.profileAction) ||
    !actions.includes(result.plan.providerAccessAction)
  ) {
    throw tenantProjectionError();
  }
  for (const action of result.plan.groupActions) {
    assertExactOwnKeys(action, [
      "action",
      "sourceMappingIds",
      "tenantSecurityGroupId",
    ]);
    assertLdapPlanAction(
      action.tenantSecurityGroupId,
      action.action,
      action.sourceMappingIds,
      actions,
    );
  }
  for (const action of result.plan.roleActions) {
    assertExactOwnKeys(action, ["action", "roleId", "sourceMappingIds"]);
    assertLdapPlanAction(
      action.roleId,
      action.action,
      action.sourceMappingIds,
      actions,
    );
  }
  for (const action of result.plan.operatorTeamActions) {
    assertExactOwnKeys(action, [
      "action",
      "assignmentEpochId",
      "operatorTeamId",
      "sourceMappingIds",
    ]);
    assertLdapPlanAction(
      action.operatorTeamId,
      action.action,
      action.sourceMappingIds,
      actions,
    );
    if (!canonicalUuidPattern.test(action.assignmentEpochId)) {
      throw tenantProjectionError();
    }
  }
  return {
    ...result,
    denialReasons: [...result.denialReasons],
    matchedMappingIds: [...result.matchedMappingIds],
    snapshot: {
      ...result.snapshot,
      mappingRevisions: result.snapshot.mappingRevisions.map((item) => ({
        ...item,
      })),
    },
    plan: {
      ...result.plan,
      groupActions: result.plan.groupActions.map((item) => ({
        ...item,
        sourceMappingIds: [...item.sourceMappingIds],
      })),
      roleActions: result.plan.roleActions.map((item) => ({
        ...item,
        sourceMappingIds: [...item.sourceMappingIds],
      })),
      operatorTeamActions: result.plan.operatorTeamActions.map((item) => ({
        ...item,
        sourceMappingIds: [...item.sourceMappingIds],
      })),
    },
  };
}

function assertLdapPlanAction(
  targetId: string,
  action: string,
  sourceMappingIds: readonly string[],
  actions: readonly string[],
): void {
  if (
    !canonicalUuidPattern.test(targetId) ||
    !actions.includes(action) ||
    !Array.isArray(sourceMappingIds) ||
    sourceMappingIds.some((id) => !canonicalUuidPattern.test(id))
  ) {
    throw tenantProjectionError();
  }
}

function assertLdapPlannerSnapshot(
  snapshot: TenantLdapMappingDryRunResult["snapshot"],
): void {
  assertExactOwnKeys(snapshot, [
    "accessEpochId",
    "bindingId",
    "bindingVersion",
    "configurationRevision",
    "mappingRevisions",
    "providerId",
    "providerVersion",
  ]);
  if (
    !canonicalUuidPattern.test(snapshot.providerId) ||
    !canonicalUuidPattern.test(snapshot.bindingId) ||
    !canonicalUuidPattern.test(snapshot.accessEpochId) ||
    !isBoundedInteger(snapshot.configurationRevision, 1, maximumResourceVersion)
  ) {
    throw tenantProjectionError();
  }
  assertResourceVersion(snapshot.providerVersion);
  assertResourceVersion(snapshot.bindingVersion);
  for (const revision of snapshot.mappingRevisions) {
    assertExactOwnKeys(revision, [
      "mappingId",
      "mappingVersion",
      "sourceEpochId",
      "sourceEpochSequence",
    ]);
    if (
      !canonicalUuidPattern.test(revision.mappingId) ||
      (revision.sourceEpochId !== null &&
        !canonicalUuidPattern.test(revision.sourceEpochId)) ||
      (revision.sourceEpochId === null) !==
        (revision.sourceEpochSequence === null)
    ) {
      throw tenantProjectionError();
    }
    assertResourceVersion(revision.mappingVersion);
    if (
      revision.sourceEpochSequence !== null &&
      !isBoundedInteger(revision.sourceEpochSequence, 1, maximumResourceVersion)
    ) {
      throw tenantProjectionError();
    }
  }
}

function toTenantLdapSyncRunPage(
  page: TenantLdapSyncRunList,
): TenantLdapSyncRunPageView {
  assertExactOwnKeys(
    page,
    page.nextCursor === undefined ? ["items"] : ["items", "nextCursor"],
  );
  if (!Array.isArray(page.items)) throw tenantProjectionError();
  return {
    items: page.items.map(toTenantLdapSyncRun),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantLdapSyncRun(run: TenantLdapSyncRun): TenantLdapSyncRunView {
  assertExactOwnKeys(run, [
    "bindingId",
    "completedAt",
    "counters",
    "createdAt",
    "enumeration",
    "id",
    "manualReason",
    "providerId",
    "runErrorCategory",
    "snapshot",
    "startedAt",
    "state",
    "tenantId",
    "trigger",
    "updatedAt",
    "version",
  ]);
  assertResourceVersion(run.version);
  assertLdapPlannerSnapshot(run.snapshot);
  assertLdapSyncEnumeration(run.enumeration);
  assertExactOwnKeys(run.counters, [
    "failed",
    "groupEdgesAdded",
    "groupEdgesRefreshed",
    "groupEdgesRevoked",
    "identitiesCreated",
    "identitiesLinked",
    "observed",
    "providerAccessAdded",
    "providerAccessSuspended",
    "roleEdgesAdded",
    "roleEdgesRefreshed",
    "roleEdgesRevoked",
    "rosterEdgesAdded",
    "rosterEdgesRefreshed",
    "rosterEdgesRevoked",
    "staged",
  ]);
  if (
    Object.values(run.counters).some(
      (value) => !isBoundedInteger(value, 0, Number.MAX_SAFE_INTEGER),
    ) ||
    !canonicalUuidPattern.test(run.id) ||
    !canonicalUuidPattern.test(run.tenantId) ||
    !canonicalUuidPattern.test(run.bindingId) ||
    !canonicalUuidPattern.test(run.providerId) ||
    run.snapshot.bindingId !== run.bindingId ||
    run.snapshot.providerId !== run.providerId ||
    !["manual", "scheduled"].includes(run.trigger) ||
    (run.trigger === "manual") !== (run.manualReason !== null) ||
    (run.manualReason !== null &&
      (run.manualReason.length < 1 || run.manualReason.length > 500)) ||
    ![
      "queued",
      "enumerating",
      "applying",
      "succeeded",
      "failed",
      "cancelled",
      "stale",
    ].includes(run.state) ||
    parseRfc3339Instant(run.createdAt) === undefined ||
    parseRfc3339Instant(run.updatedAt) === undefined ||
    (run.startedAt !== null &&
      parseRfc3339Instant(run.startedAt) === undefined) ||
    (run.completedAt !== null &&
      parseRfc3339Instant(run.completedAt) === undefined)
  ) {
    throw tenantProjectionError();
  }
  return {
    ...run,
    snapshot: {
      ...run.snapshot,
      mappingRevisions: run.snapshot.mappingRevisions.map((item) => ({
        ...item,
      })),
    },
    enumeration: { ...run.enumeration },
    counters: { ...run.counters },
  };
}

function assertLdapSyncEnumeration(
  enumeration: TenantLdapSyncRun["enumeration"],
): void {
  assertExactOwnKeys(enumeration, [
    "absenceBasedRevocationAllowed",
    "complete",
    "cursorState",
    "entryCount",
    "errorCategory",
    "pageCount",
    "responseBytes",
    "state",
    "truncated",
  ]);
  const validState =
    (enumeration.state === "not_started" &&
      !enumeration.complete &&
      !enumeration.truncated &&
      !enumeration.absenceBasedRevocationAllowed) ||
    (enumeration.state === "enumerating" &&
      !enumeration.complete &&
      !enumeration.truncated &&
      !enumeration.absenceBasedRevocationAllowed) ||
    (enumeration.state === "complete" &&
      enumeration.complete &&
      !enumeration.truncated &&
      enumeration.cursorState === "terminal") ||
    (enumeration.state === "truncated" &&
      !enumeration.complete &&
      enumeration.truncated &&
      !enumeration.absenceBasedRevocationAllowed) ||
    (enumeration.state === "incomplete" &&
      !enumeration.complete &&
      !enumeration.truncated &&
      !enumeration.absenceBasedRevocationAllowed);
  if (
    !validState ||
    !isBoundedInteger(enumeration.entryCount, 0, Number.MAX_SAFE_INTEGER) ||
    !isBoundedInteger(enumeration.pageCount, 0, Number.MAX_SAFE_INTEGER) ||
    !isBoundedInteger(enumeration.responseBytes, 0, Number.MAX_SAFE_INTEGER) ||
    !["none", "present", "terminal", "discarded"].includes(
      enumeration.cursorState,
    )
  ) {
    throw tenantProjectionError();
  }
}

function toTenantLdapSyncStatus(
  status: TenantLdapSyncStatus,
): TenantLdapSyncStatusView {
  assertExactOwnKeys(status, [
    "activeRunId",
    "bindingId",
    "lastCompletedAt",
    "lastRunId",
    "lastRunState",
    "nextScheduledAt",
    "scheduleState",
    "syncIntervalSeconds",
    "updatedAt",
    "version",
  ]);
  assertResourceVersion(status.version);
  if (
    !canonicalUuidPattern.test(status.bindingId) ||
    !["disabled", "idle", "queued", "running", "backoff"].includes(
      status.scheduleState,
    ) ||
    (status.syncIntervalSeconds !== null &&
      !isBoundedInteger(status.syncIntervalSeconds, 300, 604_800)) ||
    (status.activeRunId !== null &&
      !canonicalUuidPattern.test(status.activeRunId)) ||
    (status.lastRunId !== null &&
      !canonicalUuidPattern.test(status.lastRunId)) ||
    (status.lastRunId === null) !== (status.lastRunState === null) ||
    (status.lastCompletedAt !== null &&
      parseRfc3339Instant(status.lastCompletedAt) === undefined) ||
    (status.nextScheduledAt !== null &&
      parseRfc3339Instant(status.nextScheduledAt) === undefined) ||
    parseRfc3339Instant(status.updatedAt) === undefined
  ) {
    throw tenantProjectionError();
  }
  return { ...status };
}

function assertTenantLdapSyncRunProjection(
  run: TenantLdapSyncRunView,
  tenantId: string,
  bindingId: string,
  runId?: string,
): void {
  assertTenantId(run.tenantId, tenantId);
  assertResourceId(run.bindingId, bindingId);
  if (runId !== undefined) assertResourceId(run.id, runId);
}

function isBoundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function assertProjectionObject(
  value: unknown,
): asserts value is Record<PropertyKey, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw tenantProjectionError();
  }
}

function assertExactOwnKeys(value: unknown, expected: readonly string[]): void {
  assertProjectionObject(value);
  const actual = Object.keys(value).toSorted();
  const wanted = [...expected].toSorted();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw tenantProjectionError();
  }
}

function assertOperatorTeamEpochProjection(
  epoch: OperatorTeamAssignmentEpochView,
  tenantId: string,
  operatorTeamId: string,
  assignmentEpochId?: string,
): void {
  if (
    epoch.tenantId !== tenantId ||
    epoch.operatorTeam.id !== operatorTeamId ||
    (assignmentEpochId !== undefined && epoch.epochId !== assignmentEpochId)
  ) {
    throw tenantProjectionError();
  }
}

function assertOperatorTeamRosterProjection(
  entries: readonly OperatorTeamRosterEntryView[],
  tenantId: string,
  operatorTeamId: string,
  assignmentEpochId: string,
): void {
  if (
    entries.some(
      (entry) =>
        entry.tenantId !== tenantId ||
        entry.operatorTeamId !== operatorTeamId ||
        entry.assignmentEpochId !== assignmentEpochId,
    )
  ) {
    throw tenantProjectionError();
  }
}

function assertDirectGrantTenantProjection(
  items: readonly DirectUserRoleGrantView[],
  expectedTenantId: string,
): void {
  assertTenantItems(items, expectedTenantId);
  if (items.some((item) => item.role.tenantId !== expectedTenantId)) {
    throw tenantProjectionError();
  }
}

function assertGroupEdges(
  items: readonly {
    group: { id: string; tenantId: string };
    tenantId: string;
  }[],
  tenantId: string,
  groupId: string,
): void {
  if (
    items.some(
      (item) =>
        item.tenantId !== tenantId ||
        item.group.tenantId !== tenantId ||
        item.group.id !== groupId,
    )
  ) {
    throw tenantProjectionError();
  }
}

function assertMembershipEdges(
  items: readonly TenantSecurityGroupMembershipView[],
  tenantId: string,
  groupId: string,
): void {
  assertGroupEdges(items, tenantId, groupId);
  if (items.some((item) => item.member.tenantId !== tenantId)) {
    throw tenantProjectionError();
  }
}

function assertGroupRoleEdges(
  items: readonly TenantSecurityGroupRoleGrantView[],
  tenantId: string,
  groupId: string,
): void {
  assertGroupEdges(items, tenantId, groupId);
  if (items.some((item) => item.role.tenantId !== tenantId)) {
    throw tenantProjectionError();
  }
}

function toServiceAccountPage(
  page: ServiceAccountList,
): ServiceAccountPageView {
  return {
    items: page.items.map(toServiceAccount),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toServiceAccount(account: ServiceAccount): ServiceAccountView {
  assertResourceVersion(account.version);
  const hasCompleteArchive =
    typeof account.archivedAt === "string" &&
    typeof account.archivedByMembershipId === "string" &&
    typeof account.archiveReason === "string";
  const hasAnyArchive =
    Object.hasOwn(account, "archivedAt") ||
    Object.hasOwn(account, "archivedByMembershipId") ||
    Object.hasOwn(account, "archiveReason");
  if (
    account.principalType !== "service_account" ||
    !["active", "archived"].includes(account.state) ||
    (account.state === "archived" && !hasCompleteArchive) ||
    (account.state === "active" && hasAnyArchive) ||
    account.key.trim() !== account.key ||
    account.displayName.trim() !== account.displayName ||
    parseRfc3339Instant(account.createdAt) === undefined ||
    parseRfc3339Instant(account.updatedAt) === undefined ||
    (account.archivedAt !== undefined &&
      parseRfc3339Instant(account.archivedAt) === undefined)
  ) {
    throw tenantProjectionError();
  }
  return { ...account };
}

function assertServiceAccountProjection(
  account: ServiceAccountView,
  tenantId: string,
  serviceAccountId: string,
): void {
  assertTenantId(account.tenantId, tenantId);
  assertResourceId(account.id, serviceAccountId);
}

function toServiceAccountRoleGrantPage(
  page: ServiceAccountRoleGrantList,
): ServiceAccountRoleGrantPageView {
  return {
    items: page.items.map(toServiceAccountRoleGrant),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toServiceAccountRoleGrant(
  grant: ServiceAccountRoleGrant,
): ServiceAccountRoleGrantView {
  assertEdgeEntityTag(grant.etag, grant.version);
  assertServiceAccountEdgeLifecycle(grant);
  assertManualProvenanceGrantor(grant.provenance);
  if (
    grant.role.principalKind !== "service_account" ||
    typeof grant.managedByServiceAccountApi !== "boolean" ||
    (grant.managedByServiceAccountApi &&
      (grant.state !== "active" || grant.provenance.sourceKind !== "manual"))
  ) {
    throw tenantProjectionError();
  }
  return {
    ...grant,
    provenance: { ...grant.provenance },
    role: { ...grant.role },
  };
}

function assertServiceAccountEdgeLifecycle(
  grant: ServiceAccountRoleGrant,
): void {
  const hasCompleteRevocation =
    typeof grant.revokedAt === "string" &&
    typeof grant.revokedByUserId === "string" &&
    typeof grant.revokeReason === "string";
  const hasAnyRevocation =
    Object.hasOwn(grant, "revokedAt") ||
    Object.hasOwn(grant, "revokedByUserId") ||
    Object.hasOwn(grant, "revokeReason");
  if (
    !["active", "expired", "revoked"].includes(grant.state) ||
    (grant.state === "revoked" && !hasCompleteRevocation) ||
    (grant.state !== "revoked" && hasAnyRevocation) ||
    (grant.revokedAt !== undefined &&
      parseRfc3339Instant(grant.revokedAt) === undefined) ||
    (grant.provenance.retiredAt !== undefined &&
      parseRfc3339Instant(grant.provenance.retiredAt) === undefined) ||
    parseRfc3339Instant(grant.updatedAt) === undefined
  ) {
    throw tenantProjectionError();
  }
}

function toServiceAccountCredentialPage(
  page: ServiceAccountCredentialList,
): ServiceAccountCredentialPageView {
  return {
    items: page.items.map(toServiceAccountCredential),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toServiceAccountCredential(
  credential: ServiceAccountCredential,
): ServiceAccountCredentialView {
  assertResourceVersion(credential.version);
  const etagMatch =
    typeof credential.etag === "string"
      ? resourceStrongEntityTagPattern.exec(credential.etag)
      : null;
  const hasCompleteRevocation =
    typeof credential.revokedAt === "string" &&
    typeof credential.revokedByUserId === "string" &&
    typeof credential.revokeReason === "string";
  const hasAnyRevocation =
    Object.hasOwn(credential, "revokedAt") ||
    Object.hasOwn(credential, "revokedByUserId") ||
    Object.hasOwn(credential, "revokeReason");
  const hasLastUsedAt = Object.hasOwn(credential, "lastUsedAt");
  const hasLastUsedIp = Object.hasOwn(credential, "lastUsedIp");
  const networks = credential.allowedNetworks;
  const canonicalNetworks =
    canonicalizeServiceAccountCredentialNetworks(networks);
  const issuedAt = parseRfc3339Instant(credential.issuedAt);
  const expiresAt = parseRfc3339Instant(credential.expiresAt);
  const updatedAt = parseRfc3339Instant(credential.updatedAt);
  const lastUsedAt = hasLastUsedAt
    ? parseRfc3339Instant(credential.lastUsedAt)
    : undefined;
  const revokedAt =
    credential.revokedAt === undefined
      ? undefined
      : parseRfc3339Instant(credential.revokedAt);
  if (
    !etagMatch ||
    etagMatch[1] !== String(credential.version) ||
    !["active", "expired", "revoked"].includes(credential.state) ||
    (credential.state === "revoked" && !hasCompleteRevocation) ||
    (credential.state !== "revoked" && hasAnyRevocation) ||
    hasLastUsedAt !== hasLastUsedIp ||
    (hasLastUsedAt &&
      (lastUsedAt === undefined ||
        typeof credential.lastUsedIp !== "string")) ||
    credential.permissions.length !== 1 ||
    credential.permissions[0]?.permissionKey !== "alert.create" ||
    credential.permissions[0]?.scope !== "tenant" ||
    !canonicalNetworks ||
    canonicalNetworks.some((network, index) => network !== networks[index]) ||
    credential.label.trim() !== credential.label ||
    issuedAt === undefined ||
    expiresAt === undefined ||
    updatedAt === undefined ||
    issuedAt > updatedAt ||
    issuedAt > expiresAt ||
    (lastUsedAt !== undefined &&
      (lastUsedAt < issuedAt ||
        lastUsedAt > updatedAt ||
        lastUsedAt > expiresAt)) ||
    (credential.revokedAt !== undefined &&
      (revokedAt === undefined ||
        revokedAt < issuedAt ||
        revokedAt > updatedAt)) ||
    containsCredentialSecretField(credential)
  ) {
    throw tenantProjectionError();
  }
  return {
    ...credential,
    allowedNetworks: canonicalNetworks,
    permissions: [{ ...credential.permissions[0] }],
  };
}

function containsCredentialSecretField(value: object): boolean {
  return ["bearerToken", "digest", "locator", "secret", "token"].some((key) =>
    Object.hasOwn(value, key),
  );
}

function assertServiceAccountChildProjection(
  items: readonly { serviceAccountId: string; tenantId: string }[],
  tenantId: string,
  serviceAccountId: string,
): void {
  if (
    items.some(
      (item) =>
        item.tenantId !== tenantId ||
        item.serviceAccountId !== serviceAccountId,
    )
  ) {
    throw tenantProjectionError();
  }
}

function tenantProjectionError(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API response did not match the requested tenant projection.",
    undefined,
    { code: tenantProjectionMismatchCode },
  );
}

function toApiError(error: unknown, response?: Response): PhaseTwoApiError {
  const status = response?.status;
  if (status === 429) {
    const retryAfter = response?.headers.get("Retry-After");
    return new PhaseTwoApiError(
      retryAfter
        ? `Too many attempts. Try again in ${retryAfter} seconds.`
        : "Too many attempts. Wait before trying again.",
      status,
    );
  }

  const problem = asProblem(error);
  const message =
    problem?.detail ?? problem?.title ?? fallbackForStatus(status);
  return new PhaseTwoApiError(message.slice(0, 320), status, {
    ...(problem?.code ? { code: problem.code } : {}),
    ...(problem?.credentialId ? { credentialId: problem.credentialId } : {}),
    ...(problem?.location ? { location: problem.location } : {}),
  });
}

interface SafeProblem {
  code?: string;
  credentialId?: string;
  detail?: string;
  location?: string;
  title: string;
}

function asProblem(value: unknown): SafeProblem | null {
  if (
    typeof value !== "object" ||
    value === null ||
    !("title" in value) ||
    typeof value.title !== "string"
  ) {
    return null;
  }
  const detail =
    "detail" in value && typeof value.detail === "string"
      ? value.detail
      : undefined;
  const code =
    "code" in value && typeof value.code === "string" ? value.code : undefined;
  const credentialId =
    "credentialId" in value && typeof value.credentialId === "string"
      ? value.credentialId
      : undefined;
  const location =
    "location" in value && typeof value.location === "string"
      ? value.location
      : undefined;
  return {
    title: value.title,
    ...(code ? { code } : {}),
    ...(credentialId ? { credentialId } : {}),
    ...(detail ? { detail } : {}),
    ...(location ? { location } : {}),
  };
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The request was not accepted.";
    case 401:
      return "The credentials or session were not accepted.";
    case 403:
      return "The server denied this action.";
    case 409:
      return "The request conflicts with current server state.";
    case 404:
      return "The requested tenant resource was not found.";
    case 412:
      return "This resource changed on the server. Review the latest version before retrying.";
    case 428:
      return "The server requires the current resource version for this action.";
    case 503:
      return "A required platform dependency is unavailable.";
    default:
      return "The API request could not be completed.";
  }
}

function toBootstrapEnrollment(
  enrollment: BootstrapEnrollment,
): BootstrapEnrollment {
  return enrollment;
}

function toBootstrapResult(result: BootstrapResult) {
  return {
    recoveryCodes: result.recoveryCodes,
    session: toSessionView(result.session),
  };
}

function toLoginChallenge(challenge: MfaChallenge) {
  return {
    challengeToken: challenge.challengeToken,
    expiresAt: challenge.expiresAt,
    methods: challenge.methods,
  };
}

function toSessionView(session: Session): SessionView {
  return {
    ...(session.activeTenantId
      ? { activeTenantId: session.activeTenantId }
      : {}),
    absoluteExpiresAt: session.absoluteExpiresAt,
    csrfToken: session.csrfToken,
    id: session.id,
    idleExpiresAt: session.idleExpiresAt,
    permissions: session.permissions,
    user: session.user,
  };
}

function unwrapLogoutResult(
  result: GeneratedResult<unknown>,
): LogoutResultView | null {
  const response = result.response;
  if (!response?.ok) {
    throw toApiError(result.error, response);
  }
  if (
    response.headers.get("Cache-Control") !== "no-store" ||
    response.headers.get("Referrer-Policy") !== "no-referrer"
  ) {
    throw invalidLogoutProjection();
  }
  if (response.status === 204) {
    return null;
  }
  if (
    response.status !== 200 ||
    response.headers.get("Content-Type")?.split(";", 1)[0]?.trim() !==
      "application/json"
  ) {
    throw invalidLogoutProjection();
  }
  const value = result.data;
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.hasOwn(value, "continuationUrl") ||
    !("continuationUrl" in value)
  ) {
    throw invalidLogoutProjection();
  }
  const continuationUrl = value.continuationUrl;
  const prefix = "/api/v1/auth/logout/continuations/";
  if (
    typeof continuationUrl !== "string" ||
    continuationUrl.length !== prefix.length + 36 ||
    !continuationUrl.startsWith(prefix) ||
    !isCanonicalUuidV7(continuationUrl.slice(prefix.length))
  ) {
    throw invalidLogoutProjection();
  }
  return { continuationUrl };
}

function invalidLogoutProjection(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API returned an invalid logout continuation. The browser stayed on this origin.",
  );
}

function toMemberships(list: TenantMembershipList) {
  return {
    items: list.items.map((membership) => ({
      membershipId: membership.membershipId,
      role: membership.role,
      tenantId: membership.tenant.id,
      tenantName: membership.tenant.name,
      tenantSlug: membership.tenant.slug,
    })),
    ...(list.nextCursor ? { nextCursor: list.nextCursor } : {}),
  };
}

function toSessions(list: SessionList) {
  return {
    items: list.items.map((session) => ({
      absoluteExpiresAt: session.absoluteExpiresAt,
      authenticationMethod: session.authenticationMethod,
      createdAt: session.createdAt,
      current: session.current,
      id: session.id,
      idleExpiresAt: session.idleExpiresAt,
      lastSeenAt: session.lastSeenAt,
      ...(session.revokedAt ? { revokedAt: session.revokedAt } : {}),
    })),
    ...(list.nextCursor ? { nextCursor: list.nextCursor } : {}),
  };
}

function toTenantPage(page: TenantList): TenantPageView {
  return {
    items: page.items.map(toTenantView),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toOperatorTeamPage(page: OperatorTeamList): OperatorTeamPageView {
  return {
    items: page.items.map(toOperatorTeam),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toOperatorTeam(team: OperatorTeam): OperatorTeamView {
  assertResourceVersion(team.version);
  if (
    !["active", "archived"].includes(team.state) ||
    !Number.isSafeInteger(team.activeAssignmentCount) ||
    team.activeAssignmentCount < 0 ||
    (team.state === "archived") !== (team.archivedAt !== undefined)
  ) {
    throw tenantProjectionError();
  }
  return { ...team };
}

function toOperatorTeamAssignmentEpochPage(
  page: OperatorTeamAssignmentEpochList,
): OperatorTeamAssignmentEpochPageView {
  return {
    items: page.items.map(toOperatorTeamAssignmentEpoch),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toOperatorTeamAssignmentEpoch(
  epoch: OperatorTeamAssignmentEpoch,
): OperatorTeamAssignmentEpochView {
  assertResourceVersion(epoch.version);
  const hasCompleteEnd =
    epoch.endedAt !== undefined &&
    epoch.endedByUserId !== undefined &&
    epoch.endReason !== undefined;
  const hasAnyEnd =
    epoch.endedAt !== undefined ||
    epoch.endedByUserId !== undefined ||
    epoch.endReason !== undefined;
  if (
    !["active", "ended"].includes(epoch.state) ||
    (epoch.state === "active" && hasAnyEnd) ||
    (epoch.state === "ended" && !hasCompleteEnd)
  ) {
    throw tenantProjectionError();
  }
  return { ...epoch, operatorTeam: { ...epoch.operatorTeam } };
}

function toOperatorTeamRosterEntryPage(
  page: OperatorTeamRosterEntryList,
): OperatorTeamRosterEntryPageView {
  return {
    items: page.items.map(toOperatorTeamRosterEntry),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toOperatorTeamRosterEntry(
  entry: OperatorTeamRosterEntry,
): OperatorTeamRosterEntryView {
  assertEdgeEntityTag(entry.etag, entry.version);
  assertRosterEntryLifecycle(entry);
  assertManualProvenanceGrantor(entry.provenance);
  return {
    ...entry,
    managedByOperatorTeamApi: toAuthorizationAPIOwnership(
      entry.managedByOperatorTeamApi,
      entry.provenance,
    ),
    member: { ...entry.member },
    provenance: { ...entry.provenance },
  };
}

function toTenantView(tenant: TenantSummary): TenantView {
  const createdAt = parseRfc3339Instant(tenant.createdAt);
  const updatedAt = parseRfc3339Instant(tenant.updatedAt);
  if (
    !canonicalUuidV7Pattern.test(tenant.id) ||
    createdAt === undefined ||
    updatedAt === undefined ||
    updatedAt < createdAt ||
    !["active", "suspended"].includes(tenant.status)
  ) {
    throw tenantProjectionError();
  }
  if (tenant.version !== undefined) {
    assertResourceVersion(tenant.version);
  }
  return {
    createdAt: tenant.createdAt,
    id: tenant.id,
    locale: tenant.locale,
    name: tenant.name,
    slug: tenant.slug,
    status: tenant.status,
    timezone: tenant.timezone,
    updatedAt: tenant.updatedAt,
    ...(tenant.version === undefined ? {} : { version: tenant.version }),
  };
}

function toTenantLifecycleReceipt(
  receipt: TenantLifecycleReceipt,
): TenantLifecycleReceiptView {
  assertExactOwnKeys(receipt, [
    "previousStatus",
    "replayed",
    "status",
    "tenantId",
    "updatedAt",
    "version",
  ]);
  assertResourceVersion(receipt.version);
  if (
    !canonicalUuidV7Pattern.test(receipt.tenantId) ||
    parseRfc3339Instant(receipt.updatedAt) === undefined ||
    typeof receipt.replayed !== "boolean" ||
    !(
      (receipt.previousStatus === "active" && receipt.status === "suspended") ||
      (receipt.previousStatus === "suspended" && receipt.status === "active")
    )
  ) {
    throw tenantProjectionError();
  }
  return { ...receipt };
}

function toPlatformTenantAccessReceipt(
  receipt: PlatformTenantAccessReceipt,
): PlatformTenantAccessReceiptView {
  assertExactOwnKeys(receipt, [
    "authorizationRevision",
    "authorizedAt",
    "membershipId",
    "membershipRevision",
    "replayed",
    "tenantId",
    "tenantVersion",
    "userId",
  ]);
  assertResourceVersion(receipt.tenantVersion);
  assertResourceVersion(receipt.membershipRevision);
  if (
    !canonicalUuidV7Pattern.test(receipt.tenantId) ||
    !canonicalUuidV7Pattern.test(receipt.membershipId) ||
    !canonicalUuidV7Pattern.test(receipt.userId) ||
    !/^[1-9][0-9]{0,18}$/.test(receipt.authorizationRevision) ||
    parseRfc3339Instant(receipt.authorizedAt) === undefined ||
    typeof receipt.replayed !== "boolean"
  ) {
    throw tenantProjectionError();
  }
  return { ...receipt };
}

function toTenantAuthority(authority: TenantAuthority): TenantAuthorityView {
  assertHydratedPermissionTuples(authority);
  const evaluatedAt = parseRfc3339Instant(authority.evaluatedAt);
  if (
    evaluatedAt === undefined ||
    !Array.isArray(authority.operatorTeamRelationships)
  ) {
    throw tenantProjectionError();
  }
  const operatorTeamIds = new Set<string>();
  const assignmentEpochIds = new Set<string>();
  const operatorTeamRelationships = authority.operatorTeamRelationships.map(
    (relationship) => {
      if (
        !canonicalUuidPattern.test(relationship.operatorTeamId) ||
        !canonicalUuidPattern.test(relationship.assignmentEpochId) ||
        operatorTeamIds.has(relationship.operatorTeamId) ||
        assignmentEpochIds.has(relationship.assignmentEpochId)
      ) {
        throw tenantProjectionError();
      }
      operatorTeamIds.add(relationship.operatorTeamId);
      assignmentEpochIds.add(relationship.assignmentEpochId);
      return { ...relationship };
    },
  );
  return {
    ...authority,
    delegationCeiling: authority.delegationCeiling.map((entry) => {
      if (entry.delegableUntil !== undefined) {
        const delegableUntil = parseRfc3339Instant(entry.delegableUntil);
        if (delegableUntil === undefined || delegableUntil <= evaluatedAt) {
          throw tenantProjectionError();
        }
      }
      return { ...entry };
    }),
    operatorTeamRelationships,
    permissions: authority.permissions.map((permission) => ({ ...permission })),
    roleGrants: authority.roleGrants.map((grant) =>
      toEffectiveTenantRoleGrant(grant, evaluatedAt),
    ),
  };
}

function toEffectiveTenantRoleGrant(
  grant: EffectiveTenantRoleGrant,
  evaluatedAt: bigint,
): EffectiveTenantRoleGrantView {
  const path = grant.path;
  assertManualProvenanceGrantor(grant.provenance);
  if (path.pathType === "direct") {
    if (
      !("direct" in path) ||
      !path.direct ||
      "group" in path ||
      path.direct.grantId !== grant.grantId ||
      hasRetiredSource(grant.provenance) ||
      hasRetiredSource(path.direct.provenance)
    ) {
      throw tenantProjectionError();
    }
    assertManualProvenanceGrantor(path.direct.provenance);
    assertDirectRoleGrantSource(grant.provenance);
    assertDirectRoleGrantSource(path.direct.provenance);
    assertRoleGrantProvenanceMatches(grant.provenance, path.direct.provenance);
    assertEffectiveExpiry(
      grant.effectiveExpiresAt,
      [path.direct.provenance.expiresAt],
      evaluatedAt,
    );
    return {
      ...grant,
      provenance: { ...grant.provenance },
      path: {
        direct: {
          ...path.direct,
          provenance: { ...path.direct.provenance },
        },
        pathType: "direct",
      },
    };
  }
  if (
    path.pathType !== "group" ||
    !("group" in path) ||
    !path.group ||
    "direct" in path ||
    path.group.roleGrantEdge.id !== grant.grantId ||
    hasRetiredSource(grant.provenance) ||
    hasRetiredSource(path.group.membershipEdge.provenance) ||
    hasRetiredSource(path.group.roleGrantEdge.provenance)
  ) {
    throw tenantProjectionError();
  }
  assertManualProvenanceGrantor(path.group.membershipEdge.provenance);
  assertManualProvenanceGrantor(path.group.roleGrantEdge.provenance);
  if (grant.provenance.sourceType !== "group") {
    throw tenantProjectionError();
  }
  assertProvenanceMatches(
    grant.provenance,
    path.group.roleGrantEdge.provenance,
  );
  assertEffectiveExpiry(
    grant.effectiveExpiresAt,
    [
      path.group.membershipEdge.provenance.expiresAt,
      path.group.roleGrantEdge.provenance.expiresAt,
    ],
    evaluatedAt,
  );
  return {
    ...grant,
    provenance: { ...grant.provenance },
    path: {
      group: {
        group: { ...path.group.group },
        membershipEdge: {
          ...path.group.membershipEdge,
          provenance: {
            ...path.group.membershipEdge.provenance,
          },
        },
        roleGrantEdge: {
          ...path.group.roleGrantEdge,
          provenance: {
            ...path.group.roleGrantEdge.provenance,
          },
        },
      },
      pathType: "group",
    },
  };
}

function hasRetiredSource(provenance: unknown): boolean {
  return (
    typeof provenance !== "object" ||
    provenance === null ||
    Object.prototype.hasOwnProperty.call(provenance, "retiredAt")
  );
}

function toTenantPermissionPage(
  page: TenantPermissionList,
): TenantPermissionPageView {
  return {
    items: page.items.map(toTenantPermission),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantPermission(
  permission: TenantPermission,
): TenantPermissionView {
  return {
    ...permission,
    allowedScopes: [...permission.allowedScopes],
    principalTypes: [...permission.principalTypes],
  };
}

function toTenantRolePage(page: TenantRoleList): TenantRolePageView {
  return {
    items: page.items.map(toTenantRoleSummary),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantRoleSummary(role: TenantRoleSummary): TenantRoleSummary {
  assertResourceVersion(role.version);
  return { ...role };
}

function toTenantRole(role: TenantRole): TenantRoleView {
  assertResourceVersion(role.version);
  assertHydratedPermissionTuples(role.policy);
  return {
    ...role,
    policy: {
      delegationCeiling: role.policy.delegationCeiling.map((grant) => ({
        ...grant,
      })),
      permissions: role.policy.permissions.map((grant) => ({ ...grant })),
    },
  };
}

function assertHydratedPermissionTuples(policy: unknown): void {
  if (
    typeof policy !== "object" ||
    policy === null ||
    !("permissions" in policy) ||
    !("delegationCeiling" in policy) ||
    !Array.isArray(policy.permissions) ||
    !Array.isArray(policy.delegationCeiling) ||
    policy.permissions.length > 500 ||
    policy.delegationCeiling.length > 500
  ) {
    throw tenantProjectionError();
  }
  const permissions = hydratedPermissionTupleKeys(policy.permissions);
  const delegationCeiling = hydratedPermissionTupleKeys(
    policy.delegationCeiling,
  );
  for (const tuple of delegationCeiling) {
    if (!permissions.has(tuple)) {
      throw tenantProjectionError();
    }
  }
}

function hydratedPermissionTupleKeys(tuples: readonly unknown[]): Set<string> {
  const keys = new Set<string>();
  for (const tuple of tuples) {
    // Scope/principal eligibility for a particular permission stays server-owned.
    if (
      typeof tuple !== "object" ||
      tuple === null ||
      Array.isArray(tuple) ||
      !("permissionKey" in tuple) ||
      !("scope" in tuple) ||
      typeof tuple.permissionKey !== "string" ||
      typeof tuple.scope !== "string" ||
      !tenantPermissionKeySet.has(tuple.permissionKey) ||
      !tenantAuthorizationScopeSet.has(tuple.scope)
    ) {
      throw tenantProjectionError();
    }
    const key = `${tuple.permissionKey}@${tuple.scope}`;
    if (keys.has(key)) {
      throw tenantProjectionError();
    }
    keys.add(key);
  }
  return keys;
}

function toTenantSecurityGroupPage(
  page: TenantSecurityGroupList,
): TenantSecurityGroupPageView {
  return {
    items: page.items.map(toTenantSecurityGroup),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantSecurityGroup(
  group: TenantSecurityGroup,
): TenantSecurityGroupView {
  assertResourceVersion(group.version);
  return { ...group };
}

function toTenantSecurityGroupMembershipPage(
  page: TenantSecurityGroupMembershipList,
): TenantSecurityGroupMembershipPageView {
  return {
    items: page.items.map(toTenantSecurityGroupMembership),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantSecurityGroupMembership(
  edge: TenantSecurityGroupMembership,
): TenantSecurityGroupMembershipView {
  assertEdgeEntityTag(edge.etag, edge.version);
  assertAuthorizationEdgeLifecycle(edge);
  const provenance = toAuthorizationEdgeProvenance(edge.provenance);
  return {
    ...edge,
    group: toTenantSecurityGroup(edge.group),
    managedByAuthorizationApi: toAuthorizationAPIOwnership(
      edge.managedByAuthorizationApi,
      provenance,
    ),
    member: toTenantUser(edge.member),
    provenance,
  };
}

function toTenantSecurityGroupRoleGrantPage(
  page: TenantSecurityGroupRoleGrantList,
): TenantSecurityGroupRoleGrantPageView {
  return {
    items: page.items.map(toTenantSecurityGroupRoleGrant),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantSecurityGroupRoleGrant(
  edge: TenantSecurityGroupRoleGrant,
): TenantSecurityGroupRoleGrantView {
  assertEdgeEntityTag(edge.etag, edge.version);
  assertAuthorizationEdgeLifecycle(edge);
  const provenance = toAuthorizationEdgeProvenance(edge.provenance);
  return {
    ...edge,
    group: toTenantSecurityGroup(edge.group),
    managedByAuthorizationApi: toAuthorizationAPIOwnership(
      edge.managedByAuthorizationApi,
      provenance,
    ),
    provenance,
    role: toTenantRoleSummary(edge.role),
  };
}

function toAuthorizationEdgeProvenance(
  provenance: AuthorizationEdgeProvenance,
): AuthorizationEdgeProvenance {
  assertManualProvenanceGrantor(provenance);
  return { ...provenance };
}

function toTenantUserPage(page: TenantUserList): TenantUserPageView {
  return {
    items: page.items.map(toTenantUser),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toTenantUser(user: TenantUserSummary): TenantUserSummaryView {
  assertTenantMembershipEntityTag(user.etag, user.lifecycleRevision);
  if (
    !canonicalUuidPattern.test(user.tenantId) ||
    !canonicalUuidPattern.test(user.membershipId) ||
    !canonicalUuidPattern.test(user.user.id) ||
    !["invited", "active", "suspended"].includes(user.membershipStatus) ||
    parseRfc3339Instant(user.createdAt) === undefined ||
    parseRfc3339Instant(user.updatedAt) === undefined
  ) {
    throw tenantProjectionError();
  }
  return { ...user, user: { ...user.user } };
}

function toDirectGrantPage(
  page: DirectUserRoleGrantList,
): DirectUserRoleGrantPageView {
  return {
    items: page.items.map(toDirectGrant),
    ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
  };
}

function toDirectGrant(grant: DirectUserRoleGrant): DirectUserRoleGrantView {
  assertEdgeEntityTag(grant.etag, grant.version);
  assertAuthorizationEdgeLifecycle(grant);
  assertManualProvenanceGrantor(grant.provenance);
  assertDirectRoleGrantSource(grant.provenance);
  return {
    ...grant,
    managedByAuthorizationApi: toAuthorizationAPIOwnership(
      grant.managedByAuthorizationApi,
      grant.provenance,
    ),
    provenance: { ...grant.provenance },
    role: toTenantRoleSummary(grant.role),
  };
}

function toAuthorizationAPIOwnership(
  value: unknown,
  provenance: { readonly retiredAt?: string; readonly sourceKind: string },
): boolean {
  if (value !== true) {
    return false;
  }
  if (
    provenance.sourceKind !== "manual" ||
    provenance.retiredAt !== undefined
  ) {
    throw tenantProjectionError();
  }
  return true;
}

function assertEdgeEntityTag(etag: unknown, version: unknown): void {
  assertResourceVersion(version);
  const match =
    typeof etag === "string" ? edgeStrongEntityTagPattern.exec(etag) : null;
  if (!match || match[1] !== String(version)) {
    throw tenantProjectionError();
  }
}

function assertResourceVersion(version: unknown): void {
  if (
    typeof version !== "number" ||
    !Number.isSafeInteger(version) ||
    version < 1 ||
    version > maximumResourceVersion
  ) {
    throw tenantProjectionError();
  }
}

interface ProvenanceProjection {
  authoritative: boolean;
  expiresAt?: string;
  grantedAt: string;
  grantedByUserId?: string;
  reason: string;
  sourceId: string;
  sourceKind: string;
}

interface RoleGrantProvenanceProjection extends ProvenanceProjection {
  sourceType: string;
}

interface AuthorizationEdgeLifecycleProjection {
  provenance: ProvenanceProjection;
  revokedAt?: string;
  revokedByUserId?: string;
  revokeReason?: string;
  state: string;
}

function assertAuthorizationEdgeLifecycle(
  edge: AuthorizationEdgeLifecycleProjection,
): void {
  const hasRevocation =
    typeof edge.revokedAt === "string" &&
    typeof edge.revokedByUserId === "string" &&
    typeof edge.revokeReason === "string";
  const hasAnyRevocationField =
    Object.prototype.hasOwnProperty.call(edge, "revokedAt") ||
    Object.prototype.hasOwnProperty.call(edge, "revokedByUserId") ||
    Object.prototype.hasOwnProperty.call(edge, "revokeReason");
  const expiresAt = edge.provenance.expiresAt;

  if (
    (edge.state === "revoked" && !hasRevocation) ||
    (edge.state !== "revoked" && hasAnyRevocationField) ||
    (edge.state === "expired" && expiresAt === undefined) ||
    (expiresAt !== undefined && parseRfc3339Instant(expiresAt) === undefined) ||
    !["active", "expired", "revoked"].includes(edge.state)
  ) {
    throw tenantProjectionError();
  }
}

function assertRosterEntryLifecycle(entry: OperatorTeamRosterEntry): void {
  const hasRevocation =
    typeof entry.revokedAt === "string" &&
    typeof entry.revokedByUserId === "string" &&
    typeof entry.revokeReason === "string";
  const hasAnyRevocationField =
    Object.prototype.hasOwnProperty.call(entry, "revokedAt") ||
    Object.prototype.hasOwnProperty.call(entry, "revokedByUserId") ||
    Object.prototype.hasOwnProperty.call(entry, "revokeReason");
  if (
    !["active", "expired", "revoked"].includes(entry.state) ||
    (entry.state === "revoked" && !hasRevocation) ||
    (entry.state !== "revoked" && hasAnyRevocationField) ||
    (entry.provenance.expiresAt !== undefined &&
      parseRfc3339Instant(entry.provenance.expiresAt) === undefined) ||
    (entry.provenance.retiredAt !== undefined &&
      parseRfc3339Instant(entry.provenance.retiredAt) === undefined)
  ) {
    throw tenantProjectionError();
  }
}

function assertManualProvenanceGrantor(provenance: ProvenanceProjection): void {
  const grantor = provenance.grantedByUserId;
  if (
    directRoleSourceTypeForKind(provenance.sourceKind) === undefined ||
    (grantor !== undefined &&
      (typeof grantor !== "string" || grantor.length === 0)) ||
    (provenance.sourceKind === "manual" && grantor === undefined)
  ) {
    throw tenantProjectionError();
  }
}

function assertDirectRoleGrantSource(
  provenance: RoleGrantProvenanceProjection,
): void {
  const expectedSourceType = directRoleSourceTypeForKind(provenance.sourceKind);
  if (!expectedSourceType || provenance.sourceType !== expectedSourceType) {
    throw tenantProjectionError();
  }
}

function directRoleSourceTypeForKind(sourceKind: string): string | undefined {
  return Object.hasOwn(directRoleSourceTypeByKind, sourceKind)
    ? directRoleSourceTypeByKind[sourceKind]
    : undefined;
}

function assertRoleGrantProvenanceMatches(
  left: RoleGrantProvenanceProjection,
  right: RoleGrantProvenanceProjection,
): void {
  if (left.sourceType !== right.sourceType) {
    throw tenantProjectionError();
  }
  assertProvenanceMatches(left, right);
}

function assertProvenanceMatches(
  left: ProvenanceProjection,
  right: ProvenanceProjection,
): void {
  if (
    typeof left.authoritative !== "boolean" ||
    typeof right.authoritative !== "boolean" ||
    left.authoritative !== right.authoritative ||
    typeof left.sourceKind !== "string" ||
    typeof right.sourceKind !== "string" ||
    left.sourceKind !== right.sourceKind ||
    typeof left.sourceId !== "string" ||
    typeof right.sourceId !== "string" ||
    left.sourceId !== right.sourceId ||
    !sameOptionalString(left.grantedByUserId, right.grantedByUserId) ||
    !sameInstant(left.grantedAt, right.grantedAt) ||
    typeof left.reason !== "string" ||
    typeof right.reason !== "string" ||
    left.reason !== right.reason ||
    !sameOptionalInstant(left.expiresAt, right.expiresAt)
  ) {
    throw tenantProjectionError();
  }
}

function sameOptionalString(left: unknown, right: unknown): boolean {
  if (left === undefined || right === undefined) {
    return left === undefined && right === undefined;
  }
  return (
    typeof left === "string" && typeof right === "string" && left === right
  );
}

function sameInstant(left: unknown, right: unknown): boolean {
  const leftInstant = parseRfc3339Instant(left);
  const rightInstant = parseRfc3339Instant(right);
  return (
    leftInstant !== undefined &&
    rightInstant !== undefined &&
    leftInstant === rightInstant
  );
}

function sameOptionalInstant(left: unknown, right: unknown): boolean {
  if (left === undefined || right === undefined) {
    return left === undefined && right === undefined;
  }
  return sameInstant(left, right);
}

function assertEffectiveExpiry(
  actual: unknown,
  pathExpiries: readonly unknown[],
  evaluatedAt: bigint,
): void {
  let earliest: bigint | undefined;
  for (const expiry of pathExpiries) {
    if (expiry === undefined) continue;
    const instant = parseRfc3339Instant(expiry);
    if (instant === undefined) {
      throw tenantProjectionError();
    }
    if (earliest === undefined || instant < earliest) {
      earliest = instant;
    }
  }
  if (earliest === undefined) {
    if (actual !== undefined) {
      throw tenantProjectionError();
    }
    return;
  }
  const actualInstant = parseRfc3339Instant(actual);
  if (
    actualInstant === undefined ||
    actualInstant !== earliest ||
    actualInstant <= evaluatedAt
  ) {
    throw tenantProjectionError();
  }
}
