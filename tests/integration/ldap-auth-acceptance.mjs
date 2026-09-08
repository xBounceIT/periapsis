import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const baseUrl =
  process.env.PERIAPSIS_LDAP_ACCEPTANCE_BASE_URL ??
  process.env.PERIAPSIS_SMOKE_BASE_URL ??
  "https://localhost:8443";
const browserOrigin =
  process.env.PERIAPSIS_LDAP_ACCEPTANCE_BROWSER_ORIGIN ??
  new URL(baseUrl).origin;
const bootstrapToken = requiredEnvironment("PERIAPSIS_BOOTSTRAP_TOKEN");
const administratorPassword = requiredEnvironment(
  "PERIAPSIS_SMOKE_ADMIN_PASSWORD",
);
const ldapAdministratorPassword = requiredEnvironment(
  "PERIAPSIS_LDAP_ADMIN_PASSWORD",
);
const ldapUserPassword = requiredEnvironment(
  "PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD",
);
const ldapSecondUserPassword = requiredEnvironment(
  "PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD",
);
const ldapCustomerPassword = requiredEnvironment(
  "PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD",
);
const ldapIsolationPassword = requiredEnvironment(
  "PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD",
);
const ldapCAFile = requiredEnvironment("PERIAPSIS_LDAP_ACCEPTANCE_CA_FILE");
const idpPort = environmentPort("PERIAPSIS_IDP_PORT", 18090);
const idpBaseUrl = `https://idp.localhost:${idpPort}`;
const idpRealm = "periapsis-test";
const composeFile =
  process.env.PERIAPSIS_LDAP_ACCEPTANCE_COMPOSE_FILE ??
  "deploy/compose/compose.yaml";
const composeProfile =
  process.env.PERIAPSIS_LDAP_ACCEPTANCE_COMPOSE_PROFILE ?? "auth-test";
const ldapCAPEM = readFileSync(ldapCAFile, "utf8");

assert(
  ldapCAPEM.includes("-----BEGIN CERTIFICATE-----") &&
    !ldapCAPEM.includes("PRIVATE KEY"),
  "LDAP acceptance CA file must contain public certificate material only",
);

const administrator = {
  email: "ldap-acceptance-admin@periapsis.example",
  displayName: "LDAP Acceptance Administrator",
  password: administratorPassword,
};
const directoryUser = {
  username: "soc-l2-user",
  email: "soc-l2-user@periapsis.test",
  displayName: "SOC L2 Analyst",
};
const directorySecondOperator = {
  username: "soc-l2-user-two",
  email: "soc-l2-user-two@periapsis.test",
  displayName: "SOC L2 Analyst Two",
};
const directoryCustomer = {
  username: "customer-user",
  email: "customer-user@periapsis.test",
  displayName: "Acme Customer",
};
const directoryIsolationUser = {
  username: "globex-user",
  email: "globex-user@periapsis.test",
  displayName: "Globex Isolation User",
};

runDirectoryFixture("provision");

let administratorCookie;
let administratorCSRF;

const enrollment = await request("/api/v1/bootstrap/enroll", {
  method: "POST",
  headers: bootstrapHeaders(),
  json: { email: administrator.email },
});
expectStatus(enrollment, 201, "bootstrap enrollment");
assertString(enrollment.body?.enrollmentToken, "bootstrap enrollment token");
assertString(enrollment.body?.totpSecret, "bootstrap TOTP secret");

await avoidTotpBoundary();
const bootstrap = await request("/api/v1/bootstrap/confirm", {
  method: "POST",
  headers: bootstrapHeaders(),
  json: {
    enrollmentToken: enrollment.body.enrollmentToken,
    email: administrator.email,
    displayName: administrator.displayName,
    password: administrator.password,
    code: totp(enrollment.body.totpSecret),
  },
});
expectStatus(bootstrap, 201, "bootstrap confirmation");
administratorCookie = issuedCookie(bootstrap, "bootstrap confirmation");
administratorCSRF = requiredSessionCSRF(bootstrap.body?.session);
let administratorAssuranceAt = Date.now();

const uniqueSuffix = randomUUID().slice(0, 8);
const tenantSlug = `ldap-acceptance-${uniqueSuffix}`;
const createdTenant = await administratorRequest("/api/v1/platform/tenants", {
  method: "POST",
  json: {
    slug: tenantSlug,
    name: "LDAP Acceptance Tenant",
    timezone: "Europe/Rome",
    locale: "it-IT",
  },
});
expectStatus(createdTenant, 201, "tenant creation");
const tenantId = requiredIdentifier(createdTenant.body?.id, "tenant ID");

const switched = await administratorRequest("/api/v1/auth/session/tenant", {
  method: "PUT",
  json: { tenantId },
});
expectStatus(switched, 200, "administrator tenant switch");
administratorCookie = refreshedCookie(switched, administratorCookie);
administratorCSRF = requiredSessionCSRF(switched.body);

await publishAcceptanceBaseline(tenantId);

const seniorAnalystRoleId = await resolveBuiltInRole("senior_analyst", "human");
const roleId = await createAcceptanceRole("operator", [
  "alert.read",
  "alert.activity.read",
  "alert.comment.read",
  "alert.link.read",
  "alert.update",
  "alert.assign",
  "alert.claim",
  "alert.escalate",
  "alert.comment.public",
  "alert.comment.private",
  "case.create",
  "case.read",
  "case.activity.read",
  "case.comment.read",
  "case.link.read",
  "case.update",
  "case.comment.public",
  "case.comment.private",
  "contact.read",
  "contact.manage",
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
  "audit.read",
  "sla.read",
  "sla.manage",
  "sla.simulate",
  "notification.manage",
]);
const customerRoleId = await resolveBuiltInRole("customer_user", "human");
const customerAccessRoleId = await createAcceptanceRole(
  "customer",
  [
    "portal.alert.read",
    "portal.case.read",
    "portal.comment.public",
    "portal.attachment.read",
    "portal.contact.preference.manage",
  ],
  "own",
);
const serviceAccountRoleId = await resolveBuiltInRole(
  "service_account",
  "service_account",
);

const securityGroup = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("group"),
    json: {
      key: "ldap_soc_l2",
      name: "LDAP SOC-L2",
      description: "Acceptance security group managed by LDAP mapping",
    },
  },
);
expectStatus(securityGroup, 201, "tenant security-group creation");
const securityGroupId = requiredIdentifier(
  securityGroup.body?.id,
  "tenant security-group ID",
);

const customerSecurityGroup = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("customer-group"),
    json: {
      key: "ldap_customer",
      name: "LDAP customer",
      description: "Acceptance customer group managed by LDAP mapping",
    },
  },
);
expectStatus(customerSecurityGroup, 201, "customer security-group creation");
const customerSecurityGroupId = requiredIdentifier(
  customerSecurityGroup.body?.id,
  "customer security-group ID",
);

const operatorTeam = await administratorRequest(
  "/api/v1/platform/operator-teams",
  {
    method: "POST",
    idempotencyKey: acceptanceKey("team"),
    json: {
      key: `ldap_soc_l2_${uniqueSuffix}`,
      name: "LDAP SOC-L2 Acceptance",
      description: "Ephemeral composed LDAP acceptance team",
    },
  },
);
expectStatus(operatorTeam, 201, "platform operator-team creation");
const operatorTeamId = requiredIdentifier(
  operatorTeam.body?.id,
  "operator-team ID",
);

const assignmentEpoch = await administratorRequest(
  `/api/v1/tenants/${tenantId}/operator-teams/${operatorTeamId}/assignment-epochs`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("team-assignment"),
    json: { reason: "Composed LDAP acceptance assignment" },
  },
);
expectStatus(assignmentEpoch, 201, "operator-team assignment");
const assignmentEpochId = requiredIdentifier(
  assignmentEpoch.body?.epochId,
  "operator-team assignment epoch ID",
);

const providerConfiguration = {
  template: "openldap",
  verifyCertificate: true,
  customCaPem: ldapCAPEM,
  connectTimeoutMs: 1000,
  operationTimeoutMs: 3000,
  bindDn: "uid=admin,DC=periapsis,DC=test",
  userBaseDn: "ou=people,DC=periapsis,DC=test",
  groupBaseDn: "ou=groups,DC=periapsis,DC=test",
  userSearchFilter: "(uid={username})",
  groupSearchFilter: "(member={userDn})",
  userDnTemplate: null,
  pageSize: 100,
  maxPages: 10,
  maxEntries: 1000,
  maxResponseBytes: 1048576,
  referralMode: "disabled",
  maxReferralHops: 0,
  nestedGroupMode: "reverse_search",
  maxNestedGroupDepth: 1,
  maxGroups: 100,
  firstNameAttribute: "givenName",
  lastNameAttribute: "sn",
  displayNameAttribute: "displayName",
  usernameAttribute: "uid",
  alternateUsernameAttribute: null,
  emailAttribute: "mail",
  immutableSubjectAttribute: "entryUUID",
  immutableSubjectFormat: "entry_uuid",
  groupMembershipAttribute: null,
  posixMemberUidAttribute: null,
  posixGidNumberAttribute: null,
  accountStatusMode: "none",
  accountStatusAttribute: null,
  accountDisabledValue: null,
  jitMode: "create",
  noMatchPolicy: "deny",
  deprovisionMode: "immediate",
  deprovisionGraceSeconds: 0,
  syncIntervalSeconds: null,
};
const providerEndpoints = [
  {
    priority: 1,
    host: "openldap",
    port: 1636,
    transport: "ldaps",
    tlsServerName: "openldap",
    referralAllowed: false,
    enabled: true,
  },
];

const providerCreate = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-providers`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("provider"),
    json: {
      kind: "ldap",
      key: "acceptance_openldap",
      displayName: "Acceptance OpenLDAP",
      description: "Ephemeral composed authentication acceptance provider",
      configuration: providerConfiguration,
      endpoints: providerEndpoints,
    },
  },
);
expectStatus(providerCreate, 201, "LDAP provider creation");
const providerLocation = requiredHeader(
  providerCreate,
  "location",
  "LDAP provider creation Location",
);
const providerId = identifierFromLocation(providerLocation, "LDAP provider ID");

const providerRead = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-providers/${providerId}`,
);
expectStatus(providerRead, 200, "LDAP provider read");
let providerETag = requiredHeader(providerRead, "etag", "LDAP provider ETag");
assert(
  providerRead.body?.bindSecretConfigured === false &&
    providerRead.body?.enabled === false,
  "new LDAP provider must be disabled without a bind secret",
);

const bindSecret = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-providers/${providerId}/bind-secret`,
  {
    method: "PUT",
    ifMatch: providerETag,
    json: { secret: ldapAdministratorPassword },
  },
);
expectStatus(bindSecret, 204, "LDAP bind-secret rotation");
providerETag = requiredHeader(bindSecret, "etag", "bind-secret ETag");

const providerEnable = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-providers/${providerId}`,
  {
    method: "PUT",
    ifMatch: providerETag,
    json: {
      key: "acceptance_openldap",
      displayName: "Acceptance OpenLDAP",
      description: "Ephemeral composed authentication acceptance provider",
      enabled: true,
      configuration: providerConfiguration,
      endpoints: providerEndpoints,
    },
  },
);
expectStatus(providerEnable, 204, "LDAP provider enablement");

const bindingCreate = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-provider-bindings`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("binding"),
    json: {
      providerId,
      loginKey: "soc_l2",
      enabled: false,
      profilePriority: 20,
    },
  },
);
expectStatus(bindingCreate, 201, "LDAP binding creation");
const bindingId = requiredIdentifier(bindingCreate.body?.id, "LDAP binding ID");
let bindingETag = requiredHeader(bindingCreate, "etag", "LDAP binding ETag");

const bindingEnable = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}`,
  {
    method: "PUT",
    ifMatch: bindingETag,
    json: { loginKey: "soc_l2", enabled: true, profilePriority: 20 },
  },
);
expectStatus(bindingEnable, 200, "LDAP binding enablement");
bindingETag = requiredHeader(
  bindingEnable,
  "etag",
  "enabled LDAP binding ETag",
);

const mappingTarget = {
  tenantSecurityGroupId: securityGroupId,
  roleIds: [seniorAnalystRoleId, roleId],
  operatorTeamAssignment: { operatorTeamId, assignmentEpochId },
};
const mappingMatcher = {
  type: "exact_cn",
  cn: "SOC-L2",
  caseMode: "insensitive",
};
const mappingCreate = await administratorRequest(
  `/api/v1/tenants/${tenantId}/ldap-mappings`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("mapping"),
    json: {
      bindingId,
      matcher: mappingMatcher,
      priority: 10,
      target: mappingTarget,
      reconciliationMode: "authoritative",
      notes: "Real OpenLDAP SOC-L2 acceptance mapping",
      reason: "Acceptance mapping staged for dry-run",
    },
  },
);
expectStatus(mappingCreate, 201, "LDAP mapping creation");
const mappingId = requiredIdentifier(mappingCreate.body?.id, "LDAP mapping ID");
let mappingETag = requiredHeader(mappingCreate, "etag", "LDAP mapping ETag");

const mappingEnable = await administratorRequest(
  `/api/v1/tenants/${tenantId}/ldap-mappings/${mappingId}`,
  {
    method: "PUT",
    ifMatch: mappingETag,
    json: {
      matcher: mappingMatcher,
      priority: 10,
      target: mappingTarget,
      reconciliationMode: "authoritative",
      enabled: true,
      notes: "Real OpenLDAP SOC-L2 acceptance mapping",
      reason: "Acceptance dry-run reviewed",
    },
  },
);
expectStatus(mappingEnable, 200, "LDAP mapping enablement");

const customerMapping = await administratorRequest(
  `/api/v1/tenants/${tenantId}/ldap-mappings`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("customer-mapping"),
    json: {
      bindingId,
      matcher: {
        type: "exact_cn",
        cn: "CUSTOMER",
        caseMode: "insensitive",
      },
      priority: 20,
      target: {
        tenantSecurityGroupId: customerSecurityGroupId,
        roleIds: [customerRoleId, customerAccessRoleId],
        operatorTeamAssignment: null,
      },
      reconciliationMode: "authoritative",
      notes: "Real OpenLDAP customer acceptance mapping",
      reason: "Acceptance customer mapping enabled",
    },
  },
);
expectStatus(customerMapping, 201, "LDAP customer mapping creation");
const customerMappingId = requiredIdentifier(
  customerMapping.body?.id,
  "LDAP customer mapping ID",
);
const customerMappingEnabled = await administratorRequest(
  `/api/v1/tenants/${tenantId}/ldap-mappings/${customerMappingId}`,
  {
    method: "PUT",
    ifMatch: requiredHeader(
      customerMapping,
      "etag",
      "LDAP customer mapping ETag",
    ),
    json: {
      matcher: {
        type: "exact_cn",
        cn: "CUSTOMER",
        caseMode: "insensitive",
      },
      priority: 20,
      target: {
        tenantSecurityGroupId: customerSecurityGroupId,
        roleIds: [customerRoleId, customerAccessRoleId],
        operatorTeamAssignment: null,
      },
      reconciliationMode: "authoritative",
      enabled: true,
      notes: "Real OpenLDAP customer acceptance mapping",
      reason: "Acceptance customer mapping reviewed",
    },
  },
);
expectStatus(customerMappingEnabled, 200, "LDAP customer mapping enablement");

const beforeLogin = await dryRun(directoryUser.username);
assert(
  beforeLogin.body?.outcome === "success" &&
    beforeLogin.body?.decision === "allow" &&
    beforeLogin.body?.identityDisposition === "create" &&
    beforeLogin.body?.observationComplete === true,
  "pre-login dry-run must allow a complete JIT identity observation",
);
assert(
  beforeLogin.body?.matchedMappingIds?.includes(mappingId),
  "pre-login dry-run must match the enabled SOC-L2 mapping",
);
assertDryRunAction(
  beforeLogin.body?.plan?.groupActions,
  "tenantSecurityGroupId",
  securityGroupId,
  "add",
);
assertDryRunAction(
  beforeLogin.body?.plan?.roleActions,
  "roleId",
  seniorAnalystRoleId,
  "add",
);
assertDryRunAction(
  beforeLogin.body?.plan?.roleActions,
  "roleId",
  roleId,
  "add",
);
assertDryRunAction(
  beforeLogin.body?.plan?.operatorTeamActions,
  "operatorTeamId",
  operatorTeamId,
  "add",
);
assert(
  beforeLogin.body?.plan?.profileAction === "create" &&
    beforeLogin.body?.plan?.providerAccessAction === "add",
  "pre-login dry-run must plan profile and provider-access creation",
);

const ldapLogin = await request(`/api/v1/auth/ldap/${tenantSlug}/soc_l2`, {
  method: "POST",
  origin: browserOrigin,
  form: {
    username: directoryUser.username,
    password: ldapUserPassword,
    returnPath: "/",
  },
});
expectStatus(ldapLogin, 303, "real LDAP login");
assert(
  ldapLogin.response.headers.get("location") === "/",
  "LDAP login must preserve the validated return path",
);
let ldapCookie = issuedCookie(ldapLogin, "real LDAP login");

const ldapSession = await request("/api/v1/auth/session", {
  cookie: ldapCookie,
});
expectStatus(ldapSession, 200, "LDAP session resolution");
assert(
  ldapSession.body?.authenticationMethod === "ldap" &&
    ldapSession.body?.activeTenantId === tenantId,
  "LDAP login must issue a tenant-selected LDAP session",
);
const ldapUserId = requiredIdentifier(
  ldapSession.body?.user?.id,
  "LDAP user ID",
);

const ldapAuthority = await request(
  `/api/v1/tenants/${tenantId}/me/authority`,
  { cookie: ldapCookie },
);
expectStatus(ldapAuthority, 200, "LDAP user authority");
assert(
  ldapAuthority.body?.roleGrants?.some((grant) => grant.roleId === roleId) &&
    ldapAuthority.body?.roleGrants?.some(
      (grant) => grant.roleId === seniorAnalystRoleId,
    ),
  "LDAP authority must contain the mapped built-in and scoped tenant roles",
);
assert(
  ldapAuthority.body?.permissions?.some(
    (permission) =>
      permission.permissionKey === "alert.read" &&
      permission.scope === "tenant",
  ),
  "LDAP authority must contain the mapped role permission",
);
assert(
  ldapAuthority.body?.operatorTeamRelationships?.some(
    (relationship) =>
      relationship.operatorTeamId === operatorTeamId &&
      relationship.assignmentEpochId === assignmentEpochId,
  ),
  "LDAP authority must contain the exact mapped operator-team assignment epoch",
);

const secondOperatorLogin = await request(
  `/api/v1/auth/ldap/${tenantSlug}/soc_l2`,
  {
    method: "POST",
    origin: browserOrigin,
    form: {
      username: directorySecondOperator.username,
      password: ldapSecondUserPassword,
      returnPath: "/",
    },
  },
);
expectStatus(secondOperatorLogin, 303, "second real LDAP operator login");
let secondOperatorCookie = issuedCookie(
  secondOperatorLogin,
  "second real LDAP operator login",
);
const secondOperatorSession = await request("/api/v1/auth/session", {
  cookie: secondOperatorCookie,
});
expectStatus(
  secondOperatorSession,
  200,
  "second LDAP operator session resolution",
);
assert(
  secondOperatorSession.body?.authenticationMethod === "ldap" &&
    secondOperatorSession.body?.activeTenantId === tenantId,
  "second LDAP operator must be independently imported into the same tenant",
);
const secondOperatorUserId = requiredIdentifier(
  secondOperatorSession.body?.user?.id,
  "second LDAP operator user ID",
);
const secondOperatorAuthority = await request(
  `/api/v1/tenants/${tenantId}/me/authority`,
  { cookie: secondOperatorCookie },
);
expectStatus(secondOperatorAuthority, 200, "second LDAP operator authority");
assert(
  secondOperatorAuthority.body?.roleGrants?.some(
    (grant) => grant.roleId === roleId,
  ) &&
    secondOperatorAuthority.body?.operatorTeamRelationships?.some(
      (relationship) =>
        relationship.operatorTeamId === operatorTeamId &&
        relationship.assignmentEpochId === assignmentEpochId,
    ),
  "second LDAP operator must receive the exact mapped role and team epoch",
);

const importedUsers = await administratorRequest(
  `/api/v1/tenants/${tenantId}/users?limit=100`,
);
expectStatus(importedUsers, 200, "tenant user projection");
assertImportedLDAPProfile(importedUsers.body?.items, ldapUserId, directoryUser);
assertImportedLDAPProfile(
  importedUsers.body?.items,
  secondOperatorUserId,
  directorySecondOperator,
);

const groupMemberships = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups/${securityGroupId}/memberships?includeRevoked=true&limit=100`,
);
expectStatus(groupMemberships, 200, "LDAP group membership projection");
assert(
  groupMemberships.body?.items?.some(
    (edge) => edge.member?.user?.id === ldapUserId && edge.state === "active",
  ),
  "LDAP login must create the mapped active security-group edge",
);

const roleGrants = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups/${securityGroupId}/role-grants?includeRevoked=true&limit=100`,
);
expectStatus(roleGrants, 200, "LDAP group role-grant projection");
assert(
  [roleId, seniorAnalystRoleId].every((expectedRoleId) =>
    roleGrants.body?.items?.some(
      (edge) => edge.role?.id === expectedRoleId && edge.state === "active",
    ),
  ),
  "LDAP login must create both mapped active group-to-role edges",
);

const roster = await administratorRequest(
  `/api/v1/tenants/${tenantId}/operator-teams/${operatorTeamId}/assignment-epochs/${assignmentEpochId}/roster?includeRevoked=true&limit=100`,
);
expectStatus(roster, 200, "LDAP operator-team roster projection");
assert(
  roster.body?.items?.some(
    (edge) => edge.member?.userId === ldapUserId && edge.state === "active",
  ),
  "LDAP login must create the mapped active exact-epoch roster edge",
);

const customerDryRun = await dryRun(directoryCustomer.username);
assert(
  customerDryRun.body?.decision === "allow" &&
    customerDryRun.body?.identityDisposition === "create" &&
    customerDryRun.body?.matchedMappingIds?.includes(customerMappingId),
  "customer dry-run must select the exact CUSTOMER mapping",
);
assertDryRunAction(
  customerDryRun.body?.plan?.roleActions,
  "roleId",
  customerRoleId,
  "add",
);
assertDryRunAction(
  customerDryRun.body?.plan?.roleActions,
  "roleId",
  customerAccessRoleId,
  "add",
);

const customerLogin = await request(`/api/v1/auth/ldap/${tenantSlug}/soc_l2`, {
  method: "POST",
  origin: browserOrigin,
  form: {
    username: directoryCustomer.username,
    password: ldapCustomerPassword,
    returnPath: "/portal",
  },
});
expectStatus(customerLogin, 303, "real LDAP customer login");
const customerCookie = issuedCookie(customerLogin, "real LDAP customer login");
const customerSession = await request("/api/v1/auth/session", {
  cookie: customerCookie,
});
expectStatus(customerSession, 200, "LDAP customer session resolution");
assert(
  customerSession.body?.authenticationMethod === "ldap" &&
    customerSession.body?.activeTenantId === tenantId,
  "LDAP customer session must select the intended tenant",
);
const customerUserId = requiredIdentifier(
  customerSession.body?.user?.id,
  "LDAP customer user ID",
);
const customerProfiles = await administratorRequest(
  `/api/v1/tenants/${tenantId}/users?limit=100`,
);
expectStatus(customerProfiles, 200, "LDAP customer tenant profile");
assertImportedLDAPProfile(
  customerProfiles.body?.items,
  customerUserId,
  directoryCustomer,
);
const customerAuthority = await request(
  `/api/v1/tenants/${tenantId}/me/authority`,
  { cookie: customerCookie },
);
expectStatus(customerAuthority, 200, "LDAP customer authority");
assert(
  customerAuthority.body?.roleGrants?.some(
    (grant) => grant.roleId === customerRoleId,
  ) &&
    customerAuthority.body?.roleGrants?.some(
      (grant) => grant.roleId === customerAccessRoleId,
    ) &&
    customerAuthority.body?.permissions?.some(
      (permission) => permission.permissionKey === "portal.comment.public",
    ),
  "LDAP customer must receive the customer_user role and portal authority",
);
const usersWithCustomer = await administratorRequest(
  `/api/v1/tenants/${tenantId}/users?limit=100`,
);
expectStatus(usersWithCustomer, 200, "customer tenant user projection");
const customerProfile = usersWithCustomer.body?.items?.find(
  (item) => item.user?.id === customerUserId,
);
const customerMembershipId = requiredIdentifier(
  customerProfile?.membershipId,
  "LDAP customer membership ID",
);

const loginAudit = await listLDAPAudit();
assertAuditActions(loginAudit, [
  "tenant.identity.ldap_jit_started",
  "tenant.identity.ldap_plan_applied",
  "tenant.identity.ldap_session_created",
]);

if (process.env.PERIAPSIS_LDAP_ACCEPTANCE_RUN_LIVE_PLAYWRIGHT === "1") {
  await runLivePhaseThreeAcceptance({
    cookie: ldapCookie,
    csrfToken: requiredSessionCSRF(ldapSession.body),
    operatorUserId: ldapUserId,
    secondOperator: {
      cookie: secondOperatorCookie,
      csrfToken: requiredSessionCSRF(secondOperatorSession.body),
      userId: secondOperatorUserId,
    },
    operatorTeamId,
    tenantId,
    customer: {
      cookie: customerCookie,
      csrfToken: requiredSessionCSRF(customerSession.body),
      membershipId: customerMembershipId,
      userId: customerUserId,
    },
    serviceAccountRoleId,
  });
}

// Reauthenticate both existing identities, then refresh their authorization pins.
// Deprovisioning must reject sessions proven live immediately before removal.
ldapCookie = await loginExistingLDAPPrincipal(
  directoryUser.username,
  ldapUserPassword,
  ldapUserId,
);
secondOperatorCookie = await loginExistingLDAPPrincipal(
  directorySecondOperator.username,
  ldapSecondUserPassword,
  secondOperatorUserId,
);
({ cookie: ldapCookie } = await refreshLDAPSession(
  ldapCookie,
  ldapUserId,
  tenantId,
));
({ cookie: secondOperatorCookie } = await refreshLDAPSession(
  secondOperatorCookie,
  secondOperatorUserId,
  tenantId,
));

runDirectoryFixture("remove-group");

const afterRemoval = await dryRun(directoryUser.username);
assert(
  afterRemoval.body?.outcome === "success" &&
    afterRemoval.body?.decision === "deny" &&
    afterRemoval.body?.observationComplete === true &&
    afterRemoval.body?.denialReasons?.includes("no_mapping_match"),
  "post-removal dry-run must completely observe and deny the now-unmapped identity",
);
assertDryRunAction(
  afterRemoval.body?.plan?.groupActions,
  "tenantSecurityGroupId",
  securityGroupId,
  "revoke",
);
assertDryRunAction(
  afterRemoval.body?.plan?.roleActions,
  "roleId",
  roleId,
  "revoke",
);
assertDryRunAction(
  afterRemoval.body?.plan?.operatorTeamActions,
  "operatorTeamId",
  operatorTeamId,
  "revoke",
);
assert(
  afterRemoval.body?.plan?.providerAccessAction === "none",
  "denied dry-run must not claim provider-access authority before apply",
);

const syncStart = await administratorRequest(
  `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}/sync-runs`,
  {
    method: "POST",
    idempotencyKey: acceptanceKey("sync"),
    ifMatch: bindingETag,
    json: { reason: "SOC-L2 group removal acceptance revalidation" },
  },
);
expectStatus(syncStart, 202, "LDAP manual sync scheduling");
const syncRunId = requiredIdentifier(syncStart.body?.id, "LDAP sync-run ID");
const syncRun = await waitForSyncRun(bindingId, syncRunId);
assert(
  syncRun.enumeration?.complete === true &&
    syncRun.enumeration?.truncated === false &&
    syncRun.enumeration?.absenceBasedRevocationAllowed === true,
  "LDAP sync must use a complete authoritative observation before revocation",
);
const revokedSession = await request("/api/v1/auth/session", {
  cookie: ldapCookie,
});
expectStatus(
  revokedSession,
  401,
  "LDAP session revalidation after deprovision",
);
const revokedSecondOperatorSession = await request("/api/v1/auth/session", {
  cookie: secondOperatorCookie,
});
expectStatus(
  revokedSecondOperatorSession,
  401,
  "second LDAP session revalidation after deprovision",
);

const deniedLogin = await request(`/api/v1/auth/ldap/${tenantSlug}/soc_l2`, {
  method: "POST",
  origin: browserOrigin,
  form: {
    username: directoryUser.username,
    password: ldapUserPassword,
    returnPath: "/",
  },
});
expectStatus(deniedLogin, 401, "LDAP login after authoritative group removal");

const revokedGroupMemberships = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups/${securityGroupId}/memberships?includeRevoked=true&limit=100`,
);
expectStatus(
  revokedGroupMemberships,
  200,
  "revoked LDAP group membership projection",
);
assert(
  revokedGroupMemberships.body?.items?.some(
    (edge) => edge.member?.user?.id === ldapUserId && edge.state !== "active",
  ),
  "authoritative sync must retire the mapped security-group edge",
);

const revokedRoleGrants = await administratorRequest(
  `/api/v1/tenants/${tenantId}/groups/${securityGroupId}/role-grants?includeRevoked=true&limit=100`,
);
expectStatus(
  revokedRoleGrants,
  200,
  "retained LDAP group role-grant projection",
);
assert(
  revokedRoleGrants.body?.items?.some(
    (edge) => edge.role?.id === roleId && edge.state === "active",
  ),
  "user deprovision must retain the mapping-global group-to-role edge",
);

const revokedRoster = await administratorRequest(
  `/api/v1/tenants/${tenantId}/operator-teams/${operatorTeamId}/assignment-epochs/${assignmentEpochId}/roster?includeRevoked=true&limit=100`,
);
expectStatus(revokedRoster, 200, "revoked LDAP roster projection");
assert(
  revokedRoster.body?.items?.some(
    (edge) => edge.member?.userId === ldapUserId && edge.state !== "active",
  ),
  "authoritative sync must retire the mapped exact-epoch roster edge",
);

const deprovisionedUsers = await administratorRequest(
  `/api/v1/tenants/${tenantId}/users?limit=100`,
);
expectStatus(deprovisionedUsers, 200, "deprovisioned tenant user projection");
const deprovisionedProfile = deprovisionedUsers.body?.items?.find(
  (item) => item.user?.id === ldapUserId,
);
assert(
  deprovisionedProfile?.membershipStatus === "suspended",
  "immediate LDAP deprovision must suspend the provider-owned membership",
);

const syncAudit = await listLDAPAudit();
assertAuditActions(syncAudit, [
  "tenant.identity.ldap_sync_queued",
  "tenant.identity.ldap_sync_enumeration_completed",
  "tenant.identity.ldap_plan_denied",
  "tenant.identity.ldap_sync_completed",
]);

process.stdout.write(
  "Composed OpenLDAP login, mapping, sync, revalidation, and revocation acceptance passed\n",
);

async function refreshLDAPSession(cookie, userId, liveTenantId) {
  let session = await request("/api/v1/auth/session", { cookie });
  if (
    session.response.status === 401 &&
    session.body?.code === "session_rotated"
  ) {
    cookie = issuedCookie(session, "LDAP authorization rotation");
    session = await request("/api/v1/auth/session", { cookie });
  }
  expectStatus(session, 200, "current LDAP acceptance session");
  assert(
    session.body?.authenticationMethod === "ldap" &&
      session.body?.activeTenantId === liveTenantId &&
      session.body?.user?.id === userId,
    "LDAP session refresh must retain its exact tenant and user",
  );
  return { cookie, csrfToken: requiredSessionCSRF(session.body) };
}

async function loginExistingLDAPPrincipal(username, password, userId) {
  const login = await request(`/api/v1/auth/ldap/${tenantSlug}/soc_l2`, {
    method: "POST",
    origin: browserOrigin,
    form: { username, password, returnPath: "/" },
  });
  expectStatus(login, 303, "existing LDAP identity login");
  const current = await refreshLDAPSession(
    issuedCookie(login, "existing LDAP identity login"),
    userId,
    tenantId,
  );
  return current.cookie;
}

async function runLivePhaseThreeAcceptance({
  cookie,
  csrfToken,
  operatorUserId,
  secondOperator,
  operatorTeamId: assignedOperatorTeamId,
  tenantId: liveTenantId,
  customer,
  serviceAccountRoleId: machineRoleId,
}) {
  const observedAt = new Date().toISOString();
  ({ cookie, csrfToken } = await refreshLDAPSession(
    cookie,
    operatorUserId,
    liveTenantId,
  ));
  const liveBaseUrl = new URL(baseUrl).origin;
  const servedOpenAPI = await request("/openapi.json");
  expectStatus(servedOpenAPI, 200, "served generated OpenAPI contract");
  const generatedOpenAPI = JSON.parse(
    readFileSync(
      new URL(
        "../../services/api/internal/contract/openapi.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert(
    JSON.stringify(servedOpenAPI.body) === JSON.stringify(generatedOpenAPI),
    "served Swagger contract must exactly match the committed generated OpenAPI document",
  );
  const customFieldDefinition = {
    key: "host",
    label: "Host",
    description: "Endpoint hostname selected by the live browser acceptance.",
    dataType: "short_text",
    required: false,
    nullable: false,
    constraints: { minimumLength: 1, maximumLength: 253 },
    visibility: { customer: false, operator: true },
    editPolicy: {
      customerCreate: false,
      customerUpdate: false,
      operatorCreate: true,
      operatorUpdate: true,
    },
    placement: {
      showInCreate: true,
      showInDetail: true,
      showInList: true,
      showInExport: true,
    },
    requiredOnTransitions: [],
    searchable: true,
    filterable: true,
    sortable: true,
    allowStructuredJson: false,
  };
  const definitionId = uuidv7();
  const definition = await request(
    `/api/v1/tenants/${liveTenantId}/custom-field-definitions`,
    {
      method: "POST",
      cookie,
      csrfToken,
      origin: browserOrigin,
      idempotencyKey: acceptanceKey("live-custom-field"),
      json: {
        definitionId,
        definition: {
          ...customFieldDefinition,
          objectType: "alert",
        },
      },
    },
  );
  expectStatus(definition, 201, "live Alert custom-field definition creation");
  const caseDefinition = await request(
    `/api/v1/tenants/${liveTenantId}/custom-field-definitions`,
    {
      method: "POST",
      cookie,
      csrfToken,
      origin: browserOrigin,
      idempotencyKey: acceptanceKey("live-case-custom-field"),
      json: {
        definitionId: uuidv7(),
        definition: {
          ...customFieldDefinition,
          objectType: "case",
          placement: {
            ...customFieldDefinition.placement,
            showInCreate: false,
          },
          editPolicy: {
            ...customFieldDefinition.editPolicy,
            operatorCreate: false,
          },
        },
      },
    },
  );
  expectStatus(
    caseDefinition,
    201,
    "live Case custom-field definition creation",
  );

  const notifications = await prepareNotificationAcceptance(
    liveTenantId,
    operatorUserId,
    customer.userId,
  );
  const sla = await prepareSLAAcceptance(
    liveTenantId,
    notifications.smtpConfigurationId,
  );
  const alertTitle = `Live service-account alert ${uniqueSuffix}`;
  const createdAlert = await createServiceAccountAlert({
    assignedOperatorTeamId,
    liveTenantId,
    machineRoleId,
    observedAt,
    title: alertTitle,
  });
  const alertId = requiredIdentifier(
    createdAlert.alert.body?.id,
    "live Alert ID",
  );
  ({ cookie, csrfToken } = await refreshLDAPSession(
    cookie,
    operatorUserId,
    liveTenantId,
  ));
  secondOperator = {
    ...secondOperator,
    ...(await refreshLDAPSession(
      secondOperator.cookie,
      secondOperator.userId,
      liveTenantId,
    )),
  };

  await proveConcurrentClaim({
    expectedVersion: createdAlert.claimRaceVersion,
    alertId: requiredIdentifier(
      createdAlert.claimRaceAlert.body?.id,
      "claim-race Alert ID",
    ),
    liveTenantId,
    operator: { cookie, csrfToken, userId: operatorUserId },
    secondOperator,
  });
  await waitForAlertSLA(liveTenantId, alertId, cookie);
  await verifyLiveSLATriggers({
    alertId,
    cookie,
    liveTenantId,
    warningSubject: notifications.slaWarningSubject,
  });

  const customerContact = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/contacts`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("live-customer-contact"),
      json: {
        firstName: "Acme",
        lastName: "Customer",
        email: directoryCustomer.email,
        function: "Security contact",
        language: "it-IT",
        timezone: "Europe/Rome",
        escalationPriority: 10,
        contactClass: "primary",
        notificationCategories: ["security"],
        notificationWindows: [],
        emailAllowed: true,
        active: true,
        tags: ["live-e2e"],
        linkedAccount: {
          membershipId: customer.membershipId,
          userId: customer.userId,
        },
      },
    },
  );
  expectStatus(customerContact, 201, "live customer-contact creation");
  const customerContactId = requiredIdentifier(
    customerContact.body?.id,
    "live customer contact ID",
  );
  const alertBeforeContactLink = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}`,
    { cookie },
  );
  expectStatus(alertBeforeContactLink, 200, "Alert contact-link precondition");
  const linkedContact = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/contacts`,
    {
      method: "POST",
      cookie,
      csrfToken,
      origin: browserOrigin,
      ifMatch: requiredHeader(
        alertBeforeContactLink,
        "etag",
        "Alert version before linking contact",
      ),
      idempotencyKey: acceptanceKey("live-contact-link"),
      json: { contactId: customerContactId, role: "primary" },
    },
  );
  expectStatus(linkedContact, 201, "live Alert customer-contact link");

  const indicatorId = uuidv7();
  const createdIndicator = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/dfir/iocs`,
    {
      method: "POST",
      cookie,
      csrfToken,
      origin: browserOrigin,
      idempotencyKey: acceptanceKey("live-ioc"),
      json: {
        indicatorId,
        indicator: {
          type: "ipv4",
          value: "198.51.100.42",
          description: "Documentation-range IOC for live acceptance.",
          source: "openldap-acceptance",
          confidence: 95,
          tlp: "amber",
          firstSeen: observedAt,
          lastSeen: observedAt,
          malicious: "suspicious",
          tags: ["live-e2e"],
        },
      },
    },
  );
  expectStatus(createdIndicator, 201, "live Alert IOC creation");

  const assetId = uuidv7();
  const createdAsset = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/dfir/assets`,
    {
      method: "POST",
      cookie,
      csrfToken,
      origin: browserOrigin,
      idempotencyKey: acceptanceKey("live-asset"),
      json: {
        assetId,
        asset: {
          hostname: "live-e2e-host",
          fqdn: "live-e2e-host.periapsis.test",
          ipAddresses: ["198.51.100.42"],
          macAddresses: [],
          assetType: "workstation",
          operatingSystem: "Linux",
          owner: "SOC acceptance",
          businessUnit: "security",
          criticality: "high",
          environment: "test",
          externalId: `live-e2e-${uniqueSuffix}`,
          tags: ["live-e2e"],
          firstSeen: observedAt,
          lastSeen: observedAt,
        },
      },
    },
  );
  expectStatus(createdAsset, 201, "live Alert asset creation");

  const currentAlert = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}`,
    { cookie },
  );
  expectStatus(currentAlert, 200, "live Alert state before browser acceptance");
  const alertVersion = requiredPositiveInteger(
    currentAlert.body?.version,
    "live Alert version",
  );

  const secondTenantSlug = `globex-${uniqueSuffix}`;
  const secondTenant = await administratorRequest("/api/v1/platform/tenants", {
    method: "POST",
    json: {
      slug: secondTenantSlug,
      name: "Globex acceptance",
      timezone: "Europe/Rome",
      locale: "it-IT",
    },
  });
  expectStatus(secondTenant, 201, "second tenant creation");
  const secondTenantId = requiredIdentifier(
    secondTenant.body?.id,
    "second tenant ID",
  );
  const temporaryRoot = mkdtempSync(join(tmpdir(), "periapsis-live-e2e-"));
  const stateFile = join(temporaryRoot, "browser-state.json");
  let browserAcceptanceError;
  let oidcAcceptance;
  let administratorSwitchedToSecondTenant = false;
  let administratorReturnedToTenant = false;
  try {
    oidcAcceptance = await prepareTenantOIDCAcceptance({
      liveBaseUrl,
      liveTenantId,
    });

    const switchToSecondTenant = await administratorRequest(
      "/api/v1/auth/session/tenant",
      {
        method: "PUT",
        json: { tenantId: secondTenantId },
      },
    );
    expectStatus(switchToSecondTenant, 200, "administrator switch to Globex");
    administratorSwitchedToSecondTenant = true;
    administratorCookie = refreshedCookie(
      switchToSecondTenant,
      administratorCookie,
    );
    administratorCSRF = requiredSessionCSRF(switchToSecondTenant.body);
    const globexPrincipal = await prepareIsolationLDAPPrincipal({
      liveTenantId: secondTenantId,
      liveTenantSlug: secondTenantSlug,
    });
    const globexCookie = globexPrincipal.cookie;
    const globexCSRF = globexPrincipal.csrfToken;

    proveTenantRLSIsolation(
      liveTenantId,
      secondTenantId,
      alertId,
      globexPrincipal.userId,
    );
    ({ cookie, csrfToken } = await refreshLDAPSession(
      cookie,
      operatorUserId,
      liveTenantId,
    ));
    customer = {
      ...customer,
      ...(await refreshLDAPSession(
        customer.cookie,
        customer.userId,
        liveTenantId,
      )),
    };
    const cookieSeparator = cookie.indexOf("=");
    assert(
      cookieSeparator > 0,
      "live acceptance cookie must be a name/value pair",
    );
    writeFileSync(
      stateFile,
      JSON.stringify({
        baseUrl: liveBaseUrl,
        cookieName: cookie.slice(0, cookieSeparator),
        cookieValue: cookie.slice(cookieSeparator + 1),
        csrfToken,
        tenantId: liveTenantId,
        operatorUserId,
        alertId,
        alertTitle,
        alertVersion,
        caseTitle: `Live investigation ${uniqueSuffix}`,
        indicatorId,
        assetId,
        customerCookieValue: cookieValue(customer.cookie),
        customerCSRFToken: customer.csrfToken,
        customerUserId: customer.userId,
        customerPublicComment: `Public customer update ${uniqueSuffix}`,
        operatorPrivateComment: `Private operator note ${uniqueSuffix}`,
        operatorPublicComment: `Public operator update ${uniqueSuffix}`,
        globexCookieValue: cookieValue(globexCookie),
        globexCSRFToken: globexCSRF,
        globexTenantId: secondTenantId,
        notificationPublicSubject: notifications.publicSubject,
        notificationPrivateSubject: notifications.privateSubject,
        notificationOperatorSubject: notifications.operatorSubject,
        slaPolicyId: sla.policyId,
        oidcMappedRoleId: oidcAcceptance.roleId,
        oidcSecurityGroupId: oidcAcceptance.securityGroupId,
      }),
      { encoding: "utf8", mode: 0o600 },
    );
    const outputDirectory = join(temporaryRoot, "playwright-results");
    const command = process.platform === "win32" ? "corepack.cmd" : "corepack";
    const result = spawnSync(
      command,
      [
        "pnpm",
        "--filter",
        "@periapsis/web",
        "exec",
        "playwright",
        "test",
        "--config",
        "../../tests/e2e/playwright.live.config.ts",
      ],
      {
        cwd: process.cwd(),
        env: livePlaywrightEnvironment(
          liveBaseUrl,
          outputDirectory,
          stateFile,
          oidcAcceptance,
        ),
        stdio: "inherit",
        timeout: 900_000,
      },
    );
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error("live API/database Playwright acceptance failed");
    }
  } catch (error) {
    browserAcceptanceError = error;
  } finally {
    const resolvedTemporaryRoot = resolve(temporaryRoot);
    const resolvedSystemTemp = resolve(tmpdir());
    assert(
      resolvedTemporaryRoot.startsWith(resolvedSystemTemp + sep) &&
        basename(resolvedTemporaryRoot).startsWith("periapsis-live-e2e-"),
      "refusing to remove an unexpected live acceptance temporary directory",
    );
    rmSync(resolvedTemporaryRoot, { recursive: true, force: true });
  }

  try {
    if (administratorSwitchedToSecondTenant) {
      const switchBack = await administratorRequest(
        "/api/v1/auth/session/tenant",
        {
          method: "PUT",
          json: { tenantId: liveTenantId },
        },
      );
      expectStatus(switchBack, 200, "administrator switch back to Acme");
      administratorCookie = refreshedCookie(switchBack, administratorCookie);
      administratorCSRF = requiredSessionCSRF(switchBack.body);
    }
    administratorReturnedToTenant = true;
    if (!browserAcceptanceError && oidcAcceptance) {
      await verifyMailpitCommentPrivacy(liveTenantId, notifications);
      await verifyTenantOIDCJITAcceptance(liveTenantId, oidcAcceptance);
    }
  } catch (error) {
    browserAcceptanceError = appendFailure(browserAcceptanceError, error);
  } finally {
    if (oidcAcceptance) {
      try {
        await cleanupTenantOIDCAcceptance(
          liveTenantId,
          oidcAcceptance,
          administratorReturnedToTenant,
        );
      } catch (error) {
        browserAcceptanceError = appendFailure(browserAcceptanceError, error);
      }
    }
  }
  if (browserAcceptanceError) throw browserAcceptanceError;

  const deliveries = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-deliveries?status=delivered&limit=100`,
  );
  expectStatus(deliveries, 200, "delivered notification listing");
  const deliveryItems = deliveries.body?.items ?? [];
  assert(
    deliveryItems.some(
      (delivery) =>
        delivery.channel === "email" && delivery.audience === "customer",
    ) &&
      deliveryItems.some(
        (delivery) =>
          delivery.channel === "email" && delivery.audience === "operator",
      ),
    "recorded delivery history must contain customer and operator Mailpit deliveries",
  );
  assert(
    !JSON.stringify(deliveryItems).includes(directoryCustomer.email),
    "notification delivery history must redact the complete customer destination",
  );

  const auditItems = await listAllTenantAudit(liveTenantId);
  assertAuditContainsResourceActions(auditItems, [
    "alert",
    "comment",
    "dfir.",
    "notification.",
    "service_account",
    "sla.",
  ]);
  const serializedAudit = JSON.stringify(auditItems);
  for (const protectedValue of [
    ldapUserPassword,
    ldapSecondUserPassword,
    ldapCustomerPassword,
    ldapIsolationPassword,
    oidcAcceptance.clientSecret,
    oidcAcceptance.trusted.password,
    oidcAcceptance.fallback.password,
    `Private operator note ${uniqueSuffix}`,
  ]) {
    assert(
      !serializedAudit.includes(protectedValue),
      "audit projection must redact credentials and private comment bodies",
    );
  }
  const verifiedAudit = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/audit-events/verify`,
    { method: "POST" },
  );
  expectStatus(verifiedAudit, 200, "tenant audit chain verification");
  assert(
    verifiedAudit.body?.valid === true &&
      verifiedAudit.body?.headValid === true &&
      verifiedAudit.body?.eventCount > 0,
    "tenant audit chain must verify after live mutations",
  );
}

async function ensureRecentAdministratorAssurance(liveTenantId) {
  if (Date.now() - administratorAssuranceAt < 120_000) return;
  const challenge = await request("/api/v1/auth/login", {
    method: "POST",
    json: { email: administrator.email, password: administrator.password },
  });
  expectStatus(challenge, 202, "administrator password reauthentication");
  assertString(challenge.body?.challengeToken, "administrator MFA challenge");
  await avoidTotpBoundary();
  const completed = await request("/api/v1/auth/mfa", {
    method: "POST",
    json: {
      challengeToken: challenge.body.challengeToken,
      method: "totp",
      code: totp(enrollment.body.totpSecret),
    },
  });
  expectStatus(completed, 200, "administrator fresh local MFA");
  administratorCookie = issuedCookie(
    completed,
    "administrator reauthentication",
  );
  administratorCSRF = requiredSessionCSRF(completed.body);
  administratorAssuranceAt = Date.now();
  const selected = await administratorRequest("/api/v1/auth/session/tenant", {
    method: "PUT",
    json: { tenantId: liveTenantId },
  });
  expectStatus(selected, 200, "administrator tenant selection after MFA");
  administratorCookie = refreshedCookie(selected, administratorCookie);
  administratorCSRF = requiredSessionCSRF(selected.body);
}

function assertImportedLDAPProfile(items, userId, directoryIdentity) {
  // ADR 0009 keeps imported contact data in the tenant profile, separate from
  // the platform identity returned by the authentication session endpoint.
  const profile = items?.find((item) => item.user?.id === userId);
  assert(
    profile?.membershipStatus === "active" &&
      profile?.user?.email === directoryIdentity.email &&
      profile?.user?.displayName === directoryIdentity.displayName,
    "tenant user projection must contain the active imported LDAP profile",
  );
}

async function publishAcceptanceBaseline(liveTenantId) {
  await ensureRecentAdministratorAssurance(liveTenantId);
  const published = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/mfa-policies`,
    {
      method: "POST",
      headers: {
        "X-Audit-Reason": "Explicit disposable LDAP acceptance baseline",
      },
      idempotencyKey: uuidv7(),
      json: {
        target: { scope: "tenant_baseline" },
        expectedRevision: 0,
        requirement: {
          level: "primary",
          localRequired: false,
          freshnessSeconds: 0,
          enrollmentDeadline: null,
        },
      },
    },
  );
  expectStatus(published, 201, "LDAP acceptance baseline publication");
  assert(
    published.body?.policy?.status === "live" &&
      published.body?.policy?.revision === 1 &&
      published.body?.policy?.target?.scope === "tenant_baseline" &&
      published.body?.policy?.target?.tenantId === liveTenantId &&
      published.body?.policy?.requirement?.level === "primary",
    "LDAP acceptance must publish its explicit tenant baseline before login",
  );
}

async function prepareTenantOIDCAcceptance({ liveBaseUrl, liveTenantId }) {
  await ensureRecentAdministratorAssurance(liveTenantId);
  const oidcRoleId = await createAcceptanceRole("oidc", ["alert.read"]);
  const oidcSecurityGroup = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/groups`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("oidc-group"),
      json: {
        key: `oidc_live_${uniqueSuffix}`,
        name: "OIDC live acceptance",
        description: "Disposable Keycloak claim-mapping target",
      },
    },
  );
  expectStatus(oidcSecurityGroup, 201, "OIDC security-group creation");
  const oidcSecurityGroupId = requiredIdentifier(
    oidcSecurityGroup.body?.id,
    "OIDC security-group ID",
  );

  const mfaPolicy = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/mfa-policies`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": "Live OIDC MFA acceptance" },
      idempotencyKey: uuidv7(),
      json: {
        target: { scope: "role", roleId: oidcRoleId },
        expectedRevision: 0,
        requirement: {
          level: "mfa",
          localRequired: false,
          freshnessSeconds: 3600,
          enrollmentDeadline: new Date(Date.now() + 60 * 60_000).toISOString(),
        },
      },
    },
  );
  expectStatus(mfaPolicy, 201, "OIDC role-scoped MFA policy publication");
  const mfaPolicyId = requiredIdentifier(
    mfaPolicy.body?.policy?.id,
    "OIDC MFA policy ID",
  );
  assert(
    mfaPolicy.body?.policy?.status === "live" &&
      mfaPolicy.body?.policy?.target?.tenantId === liveTenantId &&
      mfaPolicy.body?.policy?.target?.roleId === oidcRoleId &&
      mfaPolicy.body?.policy?.requirement?.level === "mfa" &&
      mfaPolicy.body?.policy?.requirement?.localRequired === false,
    "OIDC MFA policy must require MFA for exactly the mapped tenant role",
  );

  let keycloak;
  try {
    keycloak = await provisionKeycloakOIDCAcceptance(liveBaseUrl);
    const provider = await configureTenantOIDCAcceptance({
      clientId: keycloak.clientId,
      clientSecret: keycloak.clientSecret,
      issuer: `${idpBaseUrl}/realms/${idpRealm}`,
      liveBaseUrl,
      liveTenantId,
      realmRole: keycloak.realmRole,
      mappedRoleId: oidcRoleId,
      mappedSecurityGroupId: oidcSecurityGroupId,
    });
    return {
      ...keycloak,
      ...provider,
      liveBaseUrl,
      mfaPolicyId,
      roleId: oidcRoleId,
      securityGroupId: oidcSecurityGroupId,
    };
  } catch (error) {
    if (keycloak) {
      try {
        await cleanupKeycloakOIDCAcceptance(keycloak);
      } catch (cleanupError) {
        throw new Error(
          `OIDC setup failed (${errorMessage(error)}) and Keycloak rollback also failed`,
          { cause: cleanupError },
        );
      }
    }
    throw error;
  }
}

async function configureTenantOIDCAcceptance({
  clientId,
  clientSecret,
  issuer,
  liveBaseUrl,
  liveTenantId,
  realmRole,
  mappedRoleId,
  mappedSecurityGroupId,
}) {
  const key = `live_oidc_${uniqueSuffix}`;
  const loginKey = `live_oidc_${uniqueSuffix}`;
  const configuration = {
    issuer,
    clientId,
    postLogoutRedirectUri: `${liveBaseUrl}/`,
    extraScopes: ["email", "profile", "roles"],
    allowRefreshToken: false,
    useUserInfo: false,
  };
  const providerDocument = {
    kind: "oidc",
    displayName: "Live Keycloak OIDC",
    description: "Disposable composed Keycloak acceptance provider",
    jitMode: "create",
    noMatchPolicy: "deny",
    reason: "Create live Keycloak acceptance provider",
    configuration,
  };
  const created = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/federated-auth-providers`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("oidc-provider"),
      json: { ...providerDocument, key, loginKey },
    },
  );
  expectStatus(created, 201, "tenant OIDC provider creation");
  const oidcProviderId = requiredIdentifier(
    created.body?.id,
    "tenant OIDC provider ID",
  );
  try {
    let oidcProviderETag = requiredStrongETag(created, "OIDC provider ETag");
    assert(
      created.body?.enabled === false &&
        created.body?.binding?.enabled === false &&
        created.body?.configuration?.clientSecretPresent === false,
      "new tenant OIDC provider must start disabled and without a credential",
    );

    const secret = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/oidc/client-secret`,
      {
        method: "PUT",
        ifMatch: oidcProviderETag,
        json: {
          clientSecret,
          reason: "Install disposable Keycloak client credential",
        },
      },
    );
    expectStatus(secret, 204, "tenant OIDC client-secret installation");
    oidcProviderETag = requiredStrongETag(secret, "OIDC secret ETag");
    requiredRevisionHeader(
      secret,
      "x-periapsis-secret-revision",
      "OIDC client-secret revision",
    );

    const trust = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/oidc/trust-documents`,
      {
        method: "PUT",
        ifMatch: oidcProviderETag,
        json: {
          reason: "Pin live Keycloak discovery and JWKS",
          clientAuthentication: "client_secret_basic",
          signingAlgorithms: ["RS256"],
        },
      },
    );
    expectStatus(trust, 204, "tenant OIDC discovery and JWKS refresh");
    oidcProviderETag = requiredStrongETag(trust, "OIDC trust ETag");
    requiredRevisionHeader(
      trust,
      "x-periapsis-oidc-discovery-revision",
      "OIDC discovery revision",
    );
    requiredRevisionHeader(
      trust,
      "x-periapsis-oidc-jwks-revision",
      "OIDC JWKS revision",
    );
    requiredRevisionHeader(
      trust,
      "x-periapsis-oidc-jwks-key-count",
      "OIDC JWKS key count",
    );

    const oidcClaimRules = [
      {
        source: "id_token",
        kind: "profile",
        claimName: "preferred_username",
        profileField: "username",
        required: true,
      },
      {
        source: "id_token",
        kind: "profile",
        claimName: "email",
        profileField: "email",
        required: true,
      },
      {
        source: "id_token",
        kind: "groups",
        claimName: "groups",
        required: false,
      },
      {
        source: "id_token",
        kind: "scalar",
        claimName: "roles",
        required: true,
      },
      {
        source: "id_token",
        kind: "acr",
        claimName: "acr",
        required: false,
      },
      {
        source: "id_token",
        kind: "amr",
        claimName: "amr",
        required: false,
      },
    ];
    const mappingRule = {
      ruleId: uuidv7(),
      priority: 100,
      matcherKind: "scalar_equals",
      claimName: "roles",
      matcherValue: realmRole,
      reconciliationMode: "additive",
      tenantSecurityGroupId: mappedSecurityGroupId,
      roleIds: [mappedRoleId],
      enabled: true,
    };
    const mapping = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/mapping-policy`,
      {
        method: "PUT",
        ifMatch: oidcProviderETag,
        json: {
          kind: "oidc",
          reason: "Map the disposable Keycloak role",
          oidcClaimRules,
          rules: [mappingRule],
        },
      },
    );
    expectStatus(mapping, 204, "tenant OIDC mapping-policy publication");
    oidcProviderETag = requiredStrongETag(mapping, "OIDC mapping ETag");
    const mappingRevision = requiredRevisionHeader(
      mapping,
      "x-periapsis-mapping-revision",
      "OIDC mapping revision",
    );

    const assuranceRule = {
      ruleId: uuidv7(),
      enabled: true,
      level: "mfa",
      exactValue: null,
      requiredValues: ["otp", "pwd"],
      maximumAuthenticationAgeSeconds: 3600,
    };
    const assurance = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/assurance-policy`,
      {
        method: "PUT",
        ifMatch: oidcProviderETag,
        json: {
          kind: "oidc",
          reason: "Trust only Keycloak password plus OTP",
          rules: [assuranceRule],
        },
      },
    );
    expectStatus(assurance, 204, "tenant OIDC assurance-policy publication");
    oidcProviderETag = requiredStrongETag(
      assurance,
      "OIDC assurance-policy ETag",
    );
    const assuranceRevision = requiredRevisionHeader(
      assurance,
      "x-periapsis-assurance-policy-revision",
      "OIDC assurance-policy revision",
    );

    const mappingReadback = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/mapping-policy`,
    );
    expectStatus(mappingReadback, 200, "tenant OIDC mapping-policy readback");
    assert(
      requiredStrongETag(mappingReadback, "OIDC mapping readback ETag") ===
        oidcProviderETag,
      "OIDC mapping readback must expose the current provider ETag",
    );
    assert(
      requiredRevisionHeader(
        mappingReadback,
        "x-periapsis-mapping-revision",
        "OIDC mapping readback revision",
      ) === mappingRevision,
      "OIDC mapping readback revision must match the published epoch",
    );
    assertExactObjectKeys(
      mappingReadback.body,
      [
        "providerId",
        "tenantId",
        "kind",
        "providerVersion",
        "mappingRevision",
        "oidcClaimRules",
        "rules",
      ],
      "OIDC mapping-policy readback",
    );
    assert(
      mappingReadback.body?.providerId === oidcProviderId &&
        mappingReadback.body?.tenantId === liveTenantId &&
        mappingReadback.body?.kind === "oidc" &&
        mappingReadback.body?.providerVersion ===
          versionFromStrongETag(oidcProviderETag, "OIDC provider version") &&
        mappingReadback.body?.mappingRevision === mappingRevision,
      "OIDC mapping-policy readback must identify the exact provider and epochs",
    );
    assertExactJSON(
      mappingReadback.body?.oidcClaimRules,
      oidcClaimRules,
      "OIDC extraction rules",
    );
    assertExactJSON(
      mappingReadback.body?.rules,
      [mappingRule],
      "OIDC mapping rules",
    );

    const assuranceReadback = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}/assurance-policy`,
    );
    expectStatus(
      assuranceReadback,
      200,
      "tenant OIDC assurance-policy readback",
    );
    assert(
      requiredStrongETag(assuranceReadback, "OIDC assurance readback ETag") ===
        oidcProviderETag,
      "OIDC assurance readback must expose the current provider ETag",
    );
    assert(
      requiredRevisionHeader(
        assuranceReadback,
        "x-periapsis-assurance-policy-revision",
        "OIDC assurance readback revision",
      ) === assuranceRevision,
      "OIDC assurance readback revision must match the published epoch",
    );
    assertExactObjectKeys(
      assuranceReadback.body,
      [
        "providerId",
        "tenantId",
        "kind",
        "providerVersion",
        "assurancePolicyRevision",
        "rules",
      ],
      "OIDC assurance-policy readback",
    );
    assert(
      assuranceReadback.body?.providerId === oidcProviderId &&
        assuranceReadback.body?.tenantId === liveTenantId &&
        assuranceReadback.body?.kind === "oidc" &&
        assuranceReadback.body?.providerVersion ===
          versionFromStrongETag(oidcProviderETag, "OIDC provider version") &&
        assuranceReadback.body?.assurancePolicyRevision === assuranceRevision,
      "OIDC assurance-policy readback must identify the exact provider and epochs",
    );
    assertExactJSON(
      assuranceReadback.body?.rules,
      [assuranceRule],
      "OIDC assurance rules",
    );

    const enabled = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}`,
      {
        method: "PUT",
        ifMatch: oidcProviderETag,
        json: { ...providerDocument, enabled: true },
      },
    );
    expectStatus(enabled, 200, "tenant OIDC provider enablement");
    const enabledETag = requiredStrongETag(
      enabled,
      "enabled OIDC provider ETag",
    );
    assertConfiguredTenantOIDCProvider(enabled.body, {
      clientId,
      clientSecret,
      issuer,
      key,
      liveBaseUrl,
      liveTenantId,
      loginKey,
      oidcProviderId,
    });
    const persisted = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${oidcProviderId}`,
    );
    expectStatus(persisted, 200, "persisted OIDC provider readback");
    assert(
      requiredStrongETag(persisted, "persisted OIDC provider ETag") ===
        enabledETag,
      "persisted OIDC provider ETag must match the completed CAS mutation",
    );
    assertConfiguredTenantOIDCProvider(persisted.body, {
      clientId,
      clientSecret,
      issuer,
      key,
      liveBaseUrl,
      liveTenantId,
      loginKey,
      oidcProviderId,
    });
    return {
      configuration,
      loginKey,
      providerDocument,
      providerId: oidcProviderId,
    };
  } catch (error) {
    let failure = error;
    try {
      await cleanupTenantOIDCProvider(liveTenantId, {
        providerDocument,
        providerId: oidcProviderId,
      });
    } catch (cleanupError) {
      failure = appendFailure(failure, cleanupError);
    }
    throw failure;
  }
}

function assertConfiguredTenantOIDCProvider(body, expected) {
  const configuration = body?.configuration;
  assert(
    body?.id === expected.oidcProviderId &&
      body?.tenantId === expected.liveTenantId &&
      body?.kind === "oidc" &&
      body?.key === expected.key &&
      body?.enabled === true &&
      body?.configured === true &&
      body?.jitMode === "create" &&
      body?.noMatchPolicy === "deny" &&
      body?.binding?.loginKey === expected.loginKey &&
      body?.binding?.enabled === true &&
      configuration?.issuer === expected.issuer &&
      configuration?.clientId === expected.clientId &&
      configuration?.redirectUri ===
        `${expected.liveBaseUrl}/api/v1/auth/federated/oidc/callback` &&
      configuration?.postLogoutRedirectUri === `${expected.liveBaseUrl}/` &&
      configuration?.clientSecretPresent === true &&
      configuration?.allowRefreshToken === false &&
      configuration?.useUserInfo === false &&
      ["email", "profile", "roles"].every((scope) =>
        configuration?.extraScopes?.includes(scope),
      ) &&
      Number.isSafeInteger(configuration?.clientSecretRevision) &&
      configuration.clientSecretRevision > 0 &&
      Number.isSafeInteger(configuration?.discoveryRevision) &&
      configuration.discoveryRevision > 0 &&
      Number.isSafeInteger(configuration?.jwksRevision) &&
      configuration.jwksRevision > 0 &&
      Number.isSafeInteger(body?.assurancePolicyRevision) &&
      body.assurancePolicyRevision > 0 &&
      !JSON.stringify(body).includes(expected.clientSecret),
    "enabled OIDC provider must persist exact safe configuration without secret readback",
  );
}

async function provisionKeycloakOIDCAcceptance(liveBaseUrl) {
  const realmRole = `periapsis_live_${uniqueSuffix}`;
  const clientId = `periapsis-live-${uniqueSuffix}`;
  const trusted = keycloakAcceptanceUser("trusted");
  const fallback = keycloakAcceptanceUser("fallback");
  const resources = {
    authenticationConfigIds: [],
    clientInternalId: undefined,
    realmRole,
    users: [],
  };
  try {
    const token = await keycloakAdminToken();
    const roleCreated = await keycloakAdminRequest(
      token,
      `/admin/realms/${idpRealm}/roles`,
      { method: "POST", json: { name: realmRole } },
    );
    expectStatus(roleCreated, 201, "Keycloak acceptance realm-role creation");
    const role = await keycloakAdminRequest(
      token,
      `/admin/realms/${idpRealm}/roles/${encodeURIComponent(realmRole)}`,
    );
    expectStatus(role, 200, "Keycloak acceptance realm-role lookup");
    await configureKeycloakAuthenticationMethodReferences(token, resources);

    const clientCreated = await keycloakAdminRequest(
      token,
      `/admin/realms/${idpRealm}/clients`,
      {
        method: "POST",
        json: {
          clientId,
          name: "Periapsis live OIDC acceptance",
          enabled: true,
          protocol: "openid-connect",
          clientAuthenticatorType: "client-secret",
          publicClient: false,
          bearerOnly: false,
          consentRequired: false,
          standardFlowEnabled: true,
          implicitFlowEnabled: false,
          directAccessGrantsEnabled: false,
          serviceAccountsEnabled: false,
          redirectUris: [`${liveBaseUrl}/api/v1/auth/federated/oidc/callback`],
          webOrigins: [liveBaseUrl],
          attributes: {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": `${liveBaseUrl}/*`,
          },
          defaultClientScopes: ["profile", "email", "roles", "web-origins"],
          protocolMappers: [
            keycloakUserAttributeMapper(
              "Periapsis role",
              "periapsis_role",
              "roles",
              false,
            ),
            keycloakAMRMapper(),
          ],
        },
      },
    );
    expectStatus(clientCreated, 201, "Keycloak acceptance client creation");
    resources.clientInternalId = keycloakLocationIdentifier(
      clientCreated,
      "Keycloak acceptance client ID",
    );
    const generatedSecret = await keycloakAdminRequest(
      token,
      `/admin/realms/${idpRealm}/clients/${resources.clientInternalId}/client-secret`,
      { method: "POST" },
    );
    expectStatus(generatedSecret, 200, "Keycloak client-secret generation");
    const clientSecret = requiredBoundedSecret(
      generatedSecret.body?.value,
      "Keycloak client secret",
    );

    const userProvisioning = await Promise.allSettled(
      [trusted, fallback].map(async (user) => {
        const created = await keycloakAdminRequest(
          token,
          `/admin/realms/${idpRealm}/users`,
          {
            method: "POST",
            json: {
              username: user.username,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              emailVerified: true,
              enabled: true,
              credentials: [
                { type: "password", value: user.password, temporary: false },
              ],
              requiredActions:
                user.label === "trusted" ? ["CONFIGURE_TOTP"] : [],
              attributes: {
                periapsis_role: [realmRole],
              },
            },
          },
        );
        expectStatus(created, 201, `Keycloak ${user.label} user creation`);
        const userId = keycloakLocationIdentifier(
          created,
          `Keycloak ${user.label} user ID`,
        );
        resources.users.push(userId);
        const assigned = await keycloakAdminRequest(
          token,
          `/admin/realms/${idpRealm}/users/${userId}/role-mappings/realm`,
          { method: "POST", json: [role.body] },
        );
        expectStatus(assigned, 204, `Keycloak ${user.label} role assignment`);
      }),
    );
    const userFailures = userProvisioning
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (userFailures.length > 0) {
      throw new AggregateError(
        userFailures,
        "one or more Keycloak users could not be provisioned",
      );
    }
    return {
      ...resources,
      clientId,
      clientSecret,
      fallback,
      trusted,
    };
  } catch (error) {
    try {
      await cleanupKeycloakOIDCAcceptance(resources);
    } catch (cleanupError) {
      throw new Error(
        `Keycloak provisioning failed (${errorMessage(error)}) and rollback also failed`,
        { cause: cleanupError },
      );
    }
    throw error;
  }
}

function keycloakAcceptanceUser(label) {
  const title = label === "trusted" ? "Trusted" : "Fallback";
  return {
    email: `oidc-${label}-${uniqueSuffix}@periapsis.test`,
    firstName: title,
    label,
    lastName: "OIDC Acceptance",
    password: randomBytes(32).toString("base64url"),
    username: `oidc-${label}-${uniqueSuffix}`,
  };
}

function keycloakAMRMapper() {
  return {
    name: "Periapsis authentication methods",
    protocol: "openid-connect",
    protocolMapper: "oidc-amr-mapper",
    consentRequired: false,
    config: {
      "id.token.claim": "true",
      "access.token.claim": "true",
    },
  };
}

async function configureKeycloakAuthenticationMethodReferences(
  token,
  resources,
) {
  const executions = await keycloakAdminRequest(
    token,
    `/admin/realms/${idpRealm}/authentication/flows/browser/executions`,
  );
  expectStatus(executions, 200, "Keycloak browser-flow execution listing");
  const references = new Map([
    ["auth-username-password-form", "pwd"],
    ["auth-otp-form", "otp"],
  ]);
  for (const [authenticatorProviderId, reference] of references) {
    const matches = (executions.body ?? []).filter(
      (execution) => execution?.providerId === authenticatorProviderId,
    );
    assert(
      matches.length === 1 &&
        typeof matches[0]?.id === "string" &&
        !matches[0]?.authenticationConfig,
      `Keycloak browser flow must expose one unconfigured ${authenticatorProviderId} execution`,
    );
    // eslint-disable-next-line no-await-in-loop -- shared-flow mutations are tracked one at a time for reliable rollback.
    const configured = await keycloakAdminRequest(
      token,
      `/admin/realms/${idpRealm}/authentication/executions/${matches[0].id}/config`,
      {
        method: "POST",
        json: {
          alias: `periapsis-live-${reference}-${uniqueSuffix}`,
          config: {
            "default.reference.value": reference,
            "default.reference.maxAge": "3600",
          },
        },
      },
    );
    expectStatus(
      configured,
      201,
      `Keycloak ${reference} authentication-method reference configuration`,
    );
    resources.authenticationConfigIds.push(
      keycloakLocationIdentifier(
        configured,
        `Keycloak ${reference} authentication configuration ID`,
      ),
    );
  }
}

function keycloakUserAttributeMapper(
  name,
  userAttribute,
  claimName,
  multivalued,
) {
  return {
    name,
    protocol: "openid-connect",
    protocolMapper: "oidc-usermodel-attribute-mapper",
    consentRequired: false,
    config: {
      "aggregate.attrs": "false",
      multivalued: String(multivalued),
      "userinfo.token.claim": "false",
      "user.attribute": userAttribute,
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": claimName,
      "jsonType.label": "String",
    },
  };
}

async function keycloakAdminToken() {
  const result = await request(
    `${idpBaseUrl}/realms/master/protocol/openid-connect/token`,
    {
      method: "POST",
      form: {
        client_id: "admin-cli",
        grant_type: "password",
        username: requiredEnvironment("PERIAPSIS_IDP_ADMIN_USERNAME"),
        password: requiredEnvironment("PERIAPSIS_IDP_ADMIN_PASSWORD"),
      },
    },
  );
  expectStatus(result, 200, "Keycloak administrator token exchange");
  return requiredBoundedSecret(
    result.body?.access_token,
    "Keycloak administrator access token",
  );
}

function keycloakAdminRequest(token, path, options = {}) {
  return request(`${idpBaseUrl}${path}`, {
    ...options,
    authorization: `Bearer ${token}`,
  });
}

function keycloakLocationIdentifier(result, label) {
  const location = requiredHeader(result, "location", `${label} Location`);
  const value = new URL(location, idpBaseUrl).pathname.split("/").at(-1);
  assert(
    typeof value === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        value,
      ),
    `${label} must be a canonical Keycloak UUID`,
  );
  return value;
}

async function verifyTenantOIDCJITAcceptance(liveTenantId, acceptance) {
  const users = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/users?limit=100`,
  );
  expectStatus(users, 200, "OIDC JIT user listing");
  const expectedEmails = new Set([
    acceptance.trusted.email,
    acceptance.fallback.email,
  ]);
  const oidcImportedUsers = (users.body?.items ?? []).filter((item) =>
    expectedEmails.has(item.user?.email),
  );
  assert(
    oidcImportedUsers.length === 2 &&
      oidcImportedUsers.every(
        (item) =>
          item.membershipStatus === "active" && item.user?.active === true,
      ) &&
      new Set(oidcImportedUsers.map((item) => item.user?.id)).size === 2,
    "both Keycloak subjects must be distinct active JIT tenant users",
  );
  const importedUserIds = new Set(
    oidcImportedUsers.map((item) => item.user.id),
  );

  const memberships = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/groups/${acceptance.securityGroupId}/memberships?includeRevoked=true&limit=100`,
  );
  expectStatus(memberships, 200, "OIDC mapped group memberships");
  assert(
    [...importedUserIds].every((userId) =>
      memberships.body?.items?.some(
        (edge) => edge.member?.user?.id === userId && edge.state === "active",
      ),
    ),
    "both OIDC users must receive the configured active group membership",
  );
  const oidcRoleGrants = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/groups/${acceptance.securityGroupId}/role-grants?includeRevoked=true&limit=100`,
  );
  expectStatus(oidcRoleGrants, 200, "OIDC mapped group role grants");
  assert(
    oidcRoleGrants.body?.items?.some(
      (edge) => edge.role?.id === acceptance.roleId && edge.state === "active",
    ),
    "OIDC mapping must create the configured active group-to-role edge",
  );

  const [
    providerAudit,
    mappingAudit,
    policyAudit,
    federatedLoginAudit,
    mfaAudit,
  ] = await Promise.all(
    [
      "tenant.identity_provider",
      "tenant.identity_mapping.federated",
      "tenant.identity_policy.federated",
      "tenant.identity.federated_login_completed",
      "mfa.totp_enrolled",
    ].map((actionPrefix) =>
      administratorRequest(
        `/api/v1/tenants/${liveTenantId}/audit-events?actionPrefix=${encodeURIComponent(actionPrefix)}&limit=100`,
      ),
    ),
  );
  for (const [result, label] of [
    [providerAudit, "provider"],
    [mappingAudit, "mapping"],
    [policyAudit, "policy"],
    [federatedLoginAudit, "login"],
    [mfaAudit, "local-MFA"],
  ]) {
    expectStatus(result, 200, `OIDC ${label} audit listing`);
  }
  assertAuditActions(providerAudit.body?.items ?? [], [
    "tenant.identity_provider.federated.created",
    "tenant.identity_provider.oidc_secret.replaced",
    "tenant.identity_provider.oidc_trust.refreshed",
    "tenant.identity_provider.federated.updated",
  ]);
  assertAuditActions(mappingAudit.body?.items ?? [], [
    "tenant.identity_mapping.federated.replaced",
  ]);
  assertAuditActions(policyAudit.body?.items ?? [], [
    "tenant.identity_policy.federated.replaced",
  ]);
  assertAuditActions(federatedLoginAudit.body?.items ?? [], [
    "tenant.identity.federated_login_completed",
  ]);
  assertAuditActions(mfaAudit.body?.items ?? [], ["mfa.totp_enrolled"]);
}

async function cleanupTenantOIDCAcceptance(
  liveTenantId,
  acceptance,
  canManageTenant,
) {
  let cleanupError;
  if (canManageTenant) {
    try {
      await cleanupTenantOIDCProvider(liveTenantId, acceptance);
    } catch (error) {
      cleanupError = error;
    }
  }
  try {
    await cleanupKeycloakOIDCAcceptance(acceptance);
  } catch (error) {
    cleanupError = appendFailure(cleanupError, error);
  }
  if (cleanupError) throw cleanupError;
}

async function cleanupTenantOIDCProvider(liveTenantId, acceptance) {
  const path = `/api/v1/tenants/${liveTenantId}/federated-auth-providers/${acceptance.providerId}`;
  const current = await administratorRequest(path);
  if (current.response.status === 404) return;
  expectStatus(current, 200, "OIDC provider cleanup lookup");
  let etag = requiredStrongETag(current, "OIDC cleanup ETag");
  if (current.body?.enabled === true) {
    const disabled = await administratorRequest(path, {
      method: "PUT",
      ifMatch: etag,
      json: {
        ...acceptance.providerDocument,
        enabled: false,
        reason: "Disable completed live OIDC acceptance provider",
      },
    });
    expectStatus(disabled, 200, "OIDC provider cleanup disablement");
    etag = requiredStrongETag(disabled, "disabled OIDC provider ETag");
  }
  const archived = await administratorRequest(path, {
    method: "DELETE",
    ifMatch: etag,
    json: { reason: "Archive completed live OIDC acceptance provider" },
  });
  expectStatus(archived, 204, "OIDC provider cleanup archive");
}

async function cleanupKeycloakOIDCAcceptance(resources) {
  const token = await keycloakAdminToken();
  const failures = [];
  await Promise.all(
    [...(resources.users ?? [])].toReversed().map(async (userId) => {
      try {
        await keycloakDelete(
          token,
          `/admin/realms/${idpRealm}/users/${userId}`,
          "Keycloak acceptance user cleanup",
        );
      } catch (error) {
        failures.push(error);
      }
    }),
  );
  if (resources.clientInternalId) {
    try {
      await keycloakDelete(
        token,
        `/admin/realms/${idpRealm}/clients/${resources.clientInternalId}`,
        "Keycloak acceptance client cleanup",
      );
    } catch (error) {
      failures.push(error);
    }
  }
  if (resources.realmRole) {
    try {
      await keycloakDelete(
        token,
        `/admin/realms/${idpRealm}/roles/${encodeURIComponent(resources.realmRole)}`,
        "Keycloak acceptance role cleanup",
      );
    } catch (error) {
      failures.push(error);
    }
  }
  await Promise.all(
    [...(resources.authenticationConfigIds ?? [])]
      .toReversed()
      .map(async (configurationId) => {
        try {
          await keycloakDelete(
            token,
            `/admin/realms/${idpRealm}/authentication/config/${configurationId}`,
            "Keycloak authentication-method reference cleanup",
          );
        } catch (error) {
          failures.push(error);
        }
      }),
  );
  if (failures.length > 0) {
    throw new AggregateError(failures, "one or more Keycloak cleanups failed");
  }
}

async function keycloakDelete(token, path, operation) {
  const result = await keycloakAdminRequest(token, path, { method: "DELETE" });
  assert(
    result.response.status === 204 || result.response.status === 404,
    `${operation} returned ${result.response.status}; expected 204 or 404`,
  );
}

async function prepareIsolationLDAPPrincipal({ liveTenantId, liveTenantSlug }) {
  await publishAcceptanceBaseline(liveTenantId);
  const tenantAdminRoleId = await resolveBuiltInRole(
    "tenant_admin",
    "human",
    liveTenantId,
  );
  const group = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/groups`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("globex-group"),
      json: {
        key: `globex_isolation_${uniqueSuffix}`,
        name: "Globex isolation",
        description: "Disposable second-tenant isolation principal",
      },
    },
  );
  expectStatus(group, 201, "Globex isolation group creation");
  const groupId = requiredIdentifier(
    group.body?.id,
    "Globex isolation group ID",
  );

  const providerDocument = {
    kind: "ldap",
    key: `acceptance_globex_${uniqueSuffix}`,
    displayName: "Globex acceptance OpenLDAP",
    description: "Disposable second-tenant isolation provider",
    configuration: providerConfiguration,
    endpoints: providerEndpoints,
  };
  const provider = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-providers`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("globex-provider"),
      json: providerDocument,
    },
  );
  expectStatus(provider, 201, "Globex LDAP provider creation");
  const isolationProviderId = identifierFromLocation(
    requiredHeader(provider, "location", "Globex LDAP provider Location"),
    "Globex LDAP provider ID",
  );
  const isolationProviderRead = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-providers/${isolationProviderId}`,
  );
  expectStatus(isolationProviderRead, 200, "Globex LDAP provider read");
  let isolationProviderETag = requiredStrongETag(
    isolationProviderRead,
    "Globex LDAP provider ETag",
  );
  const secret = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-providers/${isolationProviderId}/bind-secret`,
    {
      method: "PUT",
      ifMatch: isolationProviderETag,
      json: { secret: ldapAdministratorPassword },
    },
  );
  expectStatus(secret, 204, "Globex LDAP bind-secret rotation");
  isolationProviderETag = requiredStrongETag(secret, "Globex LDAP secret ETag");
  const enabled = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-providers/${isolationProviderId}`,
    {
      method: "PUT",
      ifMatch: isolationProviderETag,
      json: { ...providerDocument, enabled: true },
    },
  );
  expectStatus(enabled, 204, "Globex LDAP provider enablement");

  const loginKey = "globex_isolation";
  const binding = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-provider-bindings`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("globex-binding"),
      json: {
        providerId: isolationProviderId,
        loginKey,
        enabled: false,
        profilePriority: 20,
      },
    },
  );
  expectStatus(binding, 201, "Globex LDAP binding creation");
  const isolationBindingId = requiredIdentifier(
    binding.body?.id,
    "Globex LDAP binding ID",
  );
  const bindingEnabled = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/auth-provider-bindings/${isolationBindingId}`,
    {
      method: "PUT",
      ifMatch: requiredStrongETag(binding, "Globex LDAP binding ETag"),
      json: { loginKey, enabled: true, profilePriority: 20 },
    },
  );
  expectStatus(bindingEnabled, 200, "Globex LDAP binding enablement");

  const matcher = {
    type: "exact_cn",
    cn: "GLOBEX",
    caseMode: "insensitive",
  };
  const target = {
    tenantSecurityGroupId: groupId,
    roleIds: [tenantAdminRoleId],
    operatorTeamAssignment: null,
  };
  const mapping = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/ldap-mappings`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("globex-mapping"),
      json: {
        bindingId: isolationBindingId,
        matcher,
        priority: 10,
        target,
        reconciliationMode: "authoritative",
        notes: "Real OpenLDAP second-tenant isolation mapping",
        reason: "Enable the disposable Globex-only principal",
      },
    },
  );
  expectStatus(mapping, 201, "Globex LDAP mapping creation");
  const isolationMappingId = requiredIdentifier(
    mapping.body?.id,
    "Globex LDAP mapping ID",
  );
  const mappingEnabled = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/ldap-mappings/${isolationMappingId}`,
    {
      method: "PUT",
      ifMatch: requiredStrongETag(mapping, "Globex LDAP mapping ETag"),
      json: {
        matcher,
        priority: 10,
        target,
        reconciliationMode: "authoritative",
        enabled: true,
        notes: "Real OpenLDAP second-tenant isolation mapping",
        reason: "Globex isolation mapping reviewed",
      },
    },
  );
  expectStatus(mappingEnabled, 200, "Globex LDAP mapping enablement");

  const isolationDryRun = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/ldap-mappings/dry-run`,
    {
      method: "POST",
      json: {
        bindingId: isolationBindingId,
        username: directoryIsolationUser.username,
        includeDisabledMappingIds: [],
      },
    },
  );
  expectStatus(isolationDryRun, 200, "Globex LDAP isolation dry-run");
  assert(
    isolationDryRun.body?.outcome === "success" &&
      isolationDryRun.body?.decision === "allow" &&
      isolationDryRun.body?.identityDisposition === "create" &&
      isolationDryRun.body?.matchedMappingIds?.includes(isolationMappingId),
    "Globex isolation dry-run must create only the explicitly mapped identity",
  );

  const login = await request(
    `/api/v1/auth/ldap/${liveTenantSlug}/${loginKey}`,
    {
      method: "POST",
      origin: browserOrigin,
      form: {
        username: directoryIsolationUser.username,
        password: ldapIsolationPassword,
        returnPath: "/",
      },
    },
  );
  expectStatus(login, 303, "real Globex LDAP isolation login");
  const cookie = issuedCookie(login, "real Globex LDAP isolation login");
  const session = await request("/api/v1/auth/session", { cookie });
  expectStatus(session, 200, "Globex LDAP isolation session");
  const userId = requiredIdentifier(
    session.body?.user?.id,
    "Globex LDAP isolation user ID",
  );
  assert(
    session.body?.activeTenantId === liveTenantId &&
      session.body?.authenticationMethod === "ldap",
    "Globex isolation session must belong to the dedicated LDAP identity",
  );
  const profiles = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/users?limit=100`,
  );
  expectStatus(profiles, 200, "Globex LDAP tenant profile");
  assertImportedLDAPProfile(
    profiles.body?.items,
    userId,
    directoryIsolationUser,
  );
  const memberships = await request(
    "/api/v1/auth/tenant-memberships?limit=100",
    {
      cookie,
    },
  );
  expectStatus(memberships, 200, "Globex LDAP tenant-membership listing");
  assert(
    memberships.body?.items?.length === 1 &&
      memberships.body.items[0]?.tenant?.id === liveTenantId,
    "Globex isolation user must have no Acme tenant membership",
  );
  const authority = await request(
    `/api/v1/tenants/${liveTenantId}/me/authority`,
    { cookie },
  );
  expectStatus(authority, 200, "Globex LDAP isolation authority");
  assert(
    authority.body?.roleGrants?.some(
      (grant) => grant.roleId === tenantAdminRoleId,
    ) &&
      authority.body?.permissions?.some(
        (permission) => permission.permissionKey === "alert.read",
      ),
    "Globex isolation user must receive the mapped tenant-local authority",
  );
  return {
    cookie,
    csrfToken: requiredSessionCSRF(session.body),
    userId,
  };
}

async function resolveBuiltInRole(key, principalKind, roleTenantId = tenantId) {
  const roles = await administratorRequest(
    `/api/v1/tenants/${roleTenantId}/roles?limit=100`,
  );
  expectStatus(roles, 200, `built-in ${key} role lookup`);
  const role = roles.body?.items?.find(
    (candidate) =>
      candidate?.key === key &&
      candidate?.system === true &&
      candidate?.principalKind === principalKind &&
      candidate?.archived === false,
  );
  return requiredIdentifier(role?.id, `built-in ${key} role ID`);
}

async function createAcceptanceRole(label, permissionKeys, scope = "tenant") {
  const role = await administratorRequest(`/api/v1/tenants/${tenantId}/roles`, {
    method: "POST",
    idempotencyKey: acceptanceKey(`${label}-role`),
    json: {
      key: `live_${label}_${uniqueSuffix}`,
      name: `Live acceptance ${label}`,
      description: `Disposable ${label} role for composed acceptance`,
      policy: {
        permissions: permissionKeys.map((permissionKey) => ({
          permissionKey,
          scope,
        })),
        delegationCeiling: [],
      },
    },
  });
  expectStatus(role, 201, `live ${label} role creation`);
  const createdRoleId = requiredIdentifier(
    role.body?.id,
    `live ${label} role ID`,
  );
  assert(
    role.body?.system === false &&
      role.body?.principalKind === "human" &&
      new Set(
        role.body?.policy?.permissions?.map(
          (permission) => `${permission.permissionKey}@${permission.scope}`,
        ),
      ).size === permissionKeys.length &&
      permissionKeys.every((permissionKey) =>
        role.body?.policy?.permissions?.some(
          (permission) =>
            permission.permissionKey === permissionKey &&
            permission.scope === scope,
        ),
      ),
    `live ${label} role must expose the exact requested permissions and scope`,
  );
  return createdRoleId;
}

async function createServiceAccountAlert({
  assignedOperatorTeamId,
  liveTenantId,
  machineRoleId,
  observedAt,
  title,
}) {
  const account = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/service-accounts`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("service-account"),
      json: {
        key: `alert_ingest_${uniqueSuffix}`,
        displayName: "Live Alert ingestion",
        description: "Disposable acceptance machine principal",
      },
    },
  );
  expectStatus(account, 201, "live service-account creation");
  const serviceAccountId = requiredIdentifier(
    account.body?.id,
    "live service-account ID",
  );
  const grant = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/service-accounts/${serviceAccountId}/role-grants`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("service-account-role"),
      json: {
        roleId: machineRoleId,
        reason: "Live acceptance Alert ingestion authority",
      },
    },
  );
  expectStatus(grant, 201, "live service-account role grant");
  const credential = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/service-accounts/${serviceAccountId}/credentials`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("service-account-credential"),
      json: {
        label: "Live acceptance bearer",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
        allowedNetworks: [],
      },
    },
  );
  expectStatus(credential, 201, "live service-account credential issue");
  assertString(
    credential.body?.bearerToken,
    "live service-account one-time bearer token",
  );

  const idempotencyKey = acceptanceKey("service-account-alert");
  const body = {
    title,
    description:
      "Real bearer API, browser, isolation, comment, escalation, and DFIR acceptance.",
    severity: "high",
    priority: "urgent",
    category: "endpoint",
    source: "service-account-acceptance",
    sourceType: "api",
    externalId: `service-alert-${uniqueSuffix}`,
    deduplicationKey: `service-alert-${uniqueSuffix}`,
    rawPayload: {
      producer: "live-acceptance",
      event: { kind: "endpoint", sequence: 1 },
    },
    detectedAt: observedAt,
    customerVisible: true,
    tags: ["api", "live-e2e"],
    customFields: { host: "live-e2e-host" },
  };
  const authorization = `Bearer ${credential.body.bearerToken}`;
  const first = await request(`/api/v1/tenants/${liveTenantId}/alerts`, {
    method: "POST",
    authorization,
    idempotencyKey,
    json: body,
  });
  expectStatus(first, 201, "service-account Alert creation");
  assert(
    first.body?.creator?.principalType === "service_account" &&
      first.body?.creator?.serviceAccountId === serviceAccountId &&
      first.body?.customFields?.host === "live-e2e-host" &&
      first.body?.rawPayload?.producer === "live-acceptance",
    "service-account Alert must retain creator, custom field, and raw payload",
  );
  const replay = await request(`/api/v1/tenants/${liveTenantId}/alerts`, {
    method: "POST",
    authorization,
    idempotencyKey,
    json: body,
  });
  expectStatus(replay, 201, "service-account Alert exact replay");
  assert(
    JSON.stringify(replay.body) === JSON.stringify(first.body) &&
      requiredHeader(replay, "location", "Alert replay Location") ===
        requiredHeader(first, "location", "Alert creation Location") &&
      requiredHeader(replay, "etag", "Alert replay ETag") ===
        requiredHeader(first, "etag", "Alert creation ETag"),
    "service-account idempotency replay must preserve the exact Alert response",
  );
  const fieldsPath = `/api/v1/tenants/${liveTenantId}/objects/alert/${first.body.id}/custom-fields`;
  const fieldProjection = await administratorRequest(
    `${fieldsPath}?surface=detail`,
  );
  expectStatus(fieldProjection, 200, "ingested Alert custom-field projection");
  const fieldETag = requiredHeader(
    fieldProjection,
    "etag",
    "custom-field version",
  );
  const fieldsCommitted = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/custom-field-imports`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("ingested-alert-fields"),
      json: {
        objectType: "alert",
        mode: "commit",
        rows: [
          {
            targetId: first.body.id,
            expectedVersion: versionFromStrongETag(
              fieldETag,
              "custom-field version",
            ),
            fields: [{ key: "host", value: "live-e2e-host" }],
          },
        ],
      },
    },
  );
  expectStatus(
    fieldsCommitted,
    202,
    "operator validation of ingested custom fields",
  );
  const importId = requiredIdentifier(
    fieldsCommitted.body?.job?.id,
    "custom-field import job",
  );
  const importDeadline = Date.now() + 60_000;
  async function waitForFields() {
    const result = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/custom-field-imports/${importId}?objectType=alert`,
    );
    expectStatus(result, 200, "custom-field import progress");
    if (result.body?.state === "completed") {
      assert(
        result.body?.progress?.succeeded === 1 &&
          result.body?.progress?.processed === 1,
        "typed custom-field import must commit its only row",
      );
      return;
    }
    assert(
      ["pending", "running"].includes(result.body?.state),
      "typed custom-field import must remain actionable",
    );
    assert(
      Date.now() < importDeadline,
      "typed custom-field import did not complete",
    );
    await delay(250);
    return waitForFields();
  }
  await waitForFields();
  const projected = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/alerts?search=${encodeURIComponent(title)}&customFieldKey=host&customFieldValue=live-e2e-host`,
  );
  expectStatus(projected, 200, "service-account Alert search projection");
  assert(
    projected.body?.items?.filter((item) => item?.id === first.body?.id)
      .length === 1,
    "service-account replay must leave exactly one searchable Alert",
  );
  const claimRaceAlert = await request(
    `/api/v1/tenants/${liveTenantId}/alerts`,
    {
      method: "POST",
      authorization,
      idempotencyKey: acceptanceKey("claim-race-alert"),
      json: {
        title: `Concurrent claim ${uniqueSuffix}`,
        severity: "medium",
        source: "live-acceptance",
        sourceType: "api",
        detectedAt: observedAt,
      },
    },
  );
  expectStatus(
    claimRaceAlert,
    201,
    "service-account claim-race Alert creation",
  );
  assert(
    claimRaceAlert.body?.id !== first.body?.id &&
      claimRaceAlert.body?.creator?.serviceAccountId === serviceAccountId,
    "claim race must use a separate Alert created by the ingestion principal",
  );
  const assignCreatedAlert = async (created, attempt = 0) => {
    const alertId = requiredIdentifier(created.body?.id, "created Alert ID");
    const current = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/alerts/${alertId}`,
    );
    expectStatus(current, 200, "ingested Alert assignment precondition");
    const entityTag = requiredHeader(current, "etag", "created Alert version");
    const expectedVersion = versionFromStrongETag(
      entityTag,
      "created Alert version",
    );
    const assigned = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/assign`,
      {
        method: "POST",
        ifMatch: entityTag,
        json: {
          expectedVersion,
          assignedTeamId: assignedOperatorTeamId,
          reason: "Route the ingested Alert to the acceptance operator team",
        },
      },
    );
    // The SLA worker may lock or advance the ticket between GET and POST.
    // Retry the setup with a fresh precondition; the claim race below remains
    // simultaneous and must still produce exactly one committed winner.
    if ([409, 412].includes(assigned.response.status) && attempt < 5) {
      await delay(250 * (attempt + 1));
      return assignCreatedAlert(created, attempt + 1);
    }
    expectStatus(assigned, 200, "operator assignment of ingested Alert");
    const assignedVersion = versionFromStrongETag(
      requiredHeader(assigned, "etag", "assigned Alert version"),
      "assigned Alert version",
    );
    assert(
      assignedVersion === expectedVersion + 1,
      "Alert assignment must advance exactly one version",
    );
    return assignedVersion;
  };
  await assignCreatedAlert(first);
  const claimRaceVersion = await assignCreatedAlert(claimRaceAlert);
  return { alert: first, claimRaceAlert, claimRaceVersion };
}

async function proveConcurrentClaim({
  expectedVersion,
  alertId,
  liveTenantId,
  operator,
  secondOperator,
}) {
  const path = `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/claim`;
  const [operatorClaim, secondOperatorClaim] = await Promise.all([
    request(path, {
      method: "POST",
      cookie: operator.cookie,
      csrfToken: operator.csrfToken,
      origin: browserOrigin,
      ifMatch: `"v${expectedVersion}"`,
      json: { expectedVersion, reason: "Simultaneous operator claim" },
    }),
    request(path, {
      method: "POST",
      cookie: secondOperator.cookie,
      csrfToken: secondOperator.csrfToken,
      origin: browserOrigin,
      ifMatch: `"v${expectedVersion}"`,
      json: {
        expectedVersion,
        reason: "Simultaneous second-operator claim",
      },
    }),
  ]);
  const statuses = [
    operatorClaim.response.status,
    secondOperatorClaim.response.status,
  ].toSorted((left, right) => left - right);
  assert(
    statuses[0] === 200 && [409, 412].includes(statuses[1]),
    `claim race must produce one winner and one conflict or stale precondition, received ${statuses.join("/")}`,
  );
  const winner =
    operatorClaim.response.status === 200 ? operatorClaim : secondOperatorClaim;
  assert(
    [operator.userId, secondOperator.userId].includes(
      winner.body?.winner?.claimedBy,
    ) && winner.body?.winner?.version === expectedVersion + 1,
    "claim race must persist exactly one participating operator at the next version",
  );
  const activity = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/activities?limit=100`,
    { cookie: operator.cookie },
  );
  expectStatus(activity, 200, "claim-race activity listing");
  assert(
    activity.body?.items?.filter((item) => item?.kind === "claimed").length ===
      1,
    "claim race must append exactly one claimed activity",
  );
  const audit = await listAllTenantAudit(liveTenantId);
  assert(
    audit.some(
      (event) =>
        JSON.stringify(event).includes(alertId) &&
        event?.action?.includes("claim"),
    ),
    "claim race winner must be represented in the tenant audit stream",
  );
  const claimedSLA = await waitForAlertSLA(
    liveTenantId,
    alertId,
    operator.cookie,
    expectedVersion + 1,
  );
  assert(
    claimedSLA.aggregateVersion >= expectedVersion + 1 &&
      claimedSLA.metrics?.length > 0,
    "claim race must advance the SLA projection; timer events may advance it further",
  );
}

async function waitForAlertSLA(
  liveTenantId,
  alertId,
  cookie,
  expectedAggregateVersion = 1,
) {
  const deadline = Date.now() + 30_000;
  return poll();

  async function poll() {
    const result = await request(
      `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/sla`,
      { cookie },
    );
    if (
      result.response.status === 200 &&
      result.body?.aggregateVersion >= expectedAggregateVersion
    ) {
      assert(
        result.body?.metrics?.length === 3 &&
          ["first_response", "resolution", "acceptance_clock"].every((key) =>
            result.body.metrics.some((metric) => metric?.key === key),
          ),
        "live Alert SLA projection must expose the two release metrics and the disposable runtime clock",
      );
      return result.body;
    }
    assert(
      result.response.status === 200 ||
        result.response.status === 404 ||
        result.response.status === 503,
      `live Alert SLA polling returned ${result.response.status}`,
    );
    if (Date.now() >= deadline) {
      throw new Error("live Alert SLA assignment did not become visible");
    }
    await delay(250);
    return poll();
  }
}

async function prepareSLAAcceptance(liveTenantId, smtpConfigurationId) {
  const calendarId = uuidv7();
  const weeklySchedules = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
  ].map((weekday) => ({
    weekday,
    intervals: [{ startMinute: 540, endMinute: 1080 }],
  }));
  const calendar = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/business-calendars`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("sla-calendar"),
      json: {
        id: calendarId,
        key: "rome_business_hours",
        label: "Rome business hours",
        timezone: "Europe/Rome",
        weeklySchedules,
        exceptions: [{ date: "2026-12-25", closed: true, intervals: [] }],
      },
    },
  );
  expectStatus(calendar, 201, "SLA business-calendar creation");

  const firstResponseMetricId = uuidv7();
  const resolutionMetricId = uuidv7();
  const acceptanceMetricId = uuidv7();
  const policyId = uuidv7();
  const policy = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/sla-policies`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("sla-policy"),
      json: {
        id: policyId,
        key: "live_alert_sla",
        name: "Live Alert SLA",
        description:
          "30 minute response and eight Rome business-hour resolution",
        priority: 100,
        objectTypes: ["alert"],
        matchRule: { kind: "all", children: [] },
        effectiveFrom: "2026-01-01T00:00:00Z",
        enabled: true,
        applyToSlaEngineSource: true,
        metrics: [
          {
            id: firstResponseMetricId,
            key: "first_response",
            label: "First response",
            description: "Initial public operator response",
            durationMicros: 1_800_000_000,
            clock: "elapsed",
            startEvent: "ticket.created",
            completionEvent: "response.first",
            resetPolicy: "ignore",
            warning: {
              kind: "remaining_duration",
              remainingMicros: 900_000_000,
            },
            breachGraceMicros: 0,
            displayFormat: "duration",
            customerVisible: true,
            apiVisible: true,
          },
          {
            id: resolutionMetricId,
            key: "resolution",
            label: "Resolution",
            description: "Eight working hours excluding customer wait time",
            durationMicros: 28_800_000_000,
            clock: "business",
            calendarId,
            calendarVersion: 1,
            startEvent: "ticket.created",
            pauseEvent: "ticket.pending_customer",
            resumeEvent: "ticket.customer_replied",
            completionEvent: "ticket.resolved",
            resetPolicy: "ignore",
            warning: { kind: "none" },
            breachGraceMicros: 0,
            displayFormat: "duration",
            customerVisible: true,
            apiVisible: true,
          },
          {
            id: acceptanceMetricId,
            key: "acceptance_clock",
            label: "Disposable acceptance clock",
            description:
              "Short elapsed metric used only to exercise the composed worker and notifier",
            durationMicros: 12_000_000,
            clock: "elapsed",
            startEvent: "ticket.created",
            completionEvent: "acceptance.completed",
            resetPolicy: "ignore",
            warning: {
              kind: "remaining_duration",
              remainingMicros: 8_000_000,
            },
            breachGraceMicros: 0,
            displayFormat: "duration",
            customerVisible: false,
            apiVisible: true,
          },
        ],
        triggers: [
          {
            id: uuidv7(),
            key: "first_response_warning_alert",
            metricDefinitionId: firstResponseMetricId,
            kind: "remaining_duration",
            remainingMicros: 900_000_000,
            action: {
              kind: "create_system_alert",
              value: "sla_warning",
              allowRecursiveSla: false,
            },
          },
          {
            id: uuidv7(),
            key: "acceptance_warning_email",
            metricDefinitionId: acceptanceMetricId,
            kind: "remaining_duration",
            remainingMicros: 8_000_000,
            action: {
              kind: "email",
              configurationId: smtpConfigurationId,
            },
          },
          {
            id: uuidv7(),
            key: "acceptance_due_system_alert",
            metricDefinitionId: acceptanceMetricId,
            kind: "due",
            action: {
              kind: "create_system_alert",
              value: "acceptance_sla_due",
              allowRecursiveSla: false,
            },
          },
        ],
      },
    },
  );
  expectStatus(policy, 201, "SLA policy creation");

  await Promise.all(
    [
      {
        id: uuidv7(),
        key: "first_response_due",
        label: "First response due",
        metricDefinitionId: firstResponseMetricId,
        calculation: "due_at",
        format: "datetime",
        position: 10,
      },
      {
        id: uuidv7(),
        key: "resolution_remaining",
        label: "Resolution remaining",
        metricDefinitionId: resolutionMetricId,
        calculation: "remaining_seconds",
        format: "duration",
        position: 20,
      },
    ].map(async (column) => {
      const created = await administratorRequest(
        `/api/v1/tenants/${liveTenantId}/sla-columns`,
        {
          method: "POST",
          idempotencyKey: acceptanceKey(`sla-column-${column.key}`),
          json: {
            ...column,
            sortable: true,
            filterable: true,
            customerVisible: true,
            visibleRoleKeys: ["senior_analyst"],
            styleRules: [],
          },
        },
      );
      expectStatus(created, 201, `SLA ${column.key} column creation`);
    }),
  );

  const simulationCoordinates = {
    policyVersion: 1,
    snapshot: {
      objectType: "alert",
      evaluatedAt: "2026-12-24T15:00:00Z",
      timezone: "Europe/Rome",
      facts: [],
    },
    slaInstanceId: uuidv7(),
    objectId: uuidv7(),
    createdAt: "2026-12-24T15:00:00Z",
    metricBindings: [
      { metricDefinitionId: firstResponseMetricId, metricInstanceId: uuidv7() },
      { metricDefinitionId: resolutionMetricId, metricInstanceId: uuidv7() },
      { metricDefinitionId: acceptanceMetricId, metricInstanceId: uuidv7() },
    ],
  };
  const baseline = await simulateSLA(liveTenantId, policyId, {
    ...simulationCoordinates,
    evaluateAt: "2026-12-24T15:00:00Z",
    events: [
      {
        eventId: uuidv7(),
        key: "ticket.created",
        occurredAt: "2026-12-24T15:00:00Z",
      },
    ],
  });
  const baselineFirst = metricByKey(baseline, "first_response");
  const baselineResolution = metricByKey(baseline, "resolution");
  assert(
    sameInstant(baselineFirst.dueAt, "2026-12-24T15:30:00Z") &&
      sameInstant(baselineResolution.dueAt, "2026-12-28T14:00:00Z"),
    "SLA simulation must honor the 30-minute target and Rome holiday/weekend",
  );

  const pausedEvents = [
    {
      eventId: uuidv7(),
      key: "ticket.created",
      occurredAt: "2026-12-24T15:00:00Z",
    },
    {
      eventId: uuidv7(),
      key: "ticket.pending_customer",
      occurredAt: "2026-12-24T15:30:00Z",
    },
  ];
  const paused = await simulateSLA(liveTenantId, policyId, {
    ...simulationCoordinates,
    evaluateAt: "2026-12-24T15:45:00Z",
    events: pausedEvents,
  });
  assert(
    metricByKey(paused, "resolution").state === "paused",
    "resolution SLA must pause while the Alert is pending customer",
  );
  const resumed = await simulateSLA(liveTenantId, policyId, {
    ...simulationCoordinates,
    evaluateAt: "2026-12-28T08:00:00Z",
    events: [
      ...pausedEvents,
      {
        eventId: uuidv7(),
        key: "ticket.customer_replied",
        occurredAt: "2026-12-28T08:00:00Z",
      },
    ],
  });
  assert(
    sameInstant(
      metricByKey(resumed, "resolution").dueAt,
      "2026-12-28T15:30:00Z",
    ),
    "resumed SLA must extend the business deadline by the paused interval",
  );
  return { policyId };
}

async function verifyLiveSLATriggers({
  alertId,
  cookie,
  liveTenantId,
  warningSubject,
}) {
  const deadline = Date.now() + 60_000;
  const activityItems = await pollSLAEffects();

  async function pollSLAEffects() {
    const [activity, sla] = await Promise.all([
      request(
        `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/activities?limit=100`,
        { cookie },
      ),
      request(`/api/v1/tenants/${liveTenantId}/alerts/${alertId}/sla`, {
        cookie,
      }),
    ]);
    expectStatus(activity, 200, "live SLA trigger activity polling");
    expectStatus(sla, 200, "live SLA breach projection polling");
    const actions = (activity.body?.items ?? []).filter(
      (item) => item?.kind === "sla.action.executed",
    );
    const runtimeMetric = sla.body?.metrics?.find(
      (metric) => metric?.key === "acceptance_clock",
    );
    if (
      runtimeMetric?.state === "breached" &&
      actions.some((item) => item?.details?.actionKind === "email") &&
      actions.some(
        (item) => item?.details?.actionKind === "create_system_alert",
      )
    ) {
      return actions;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        "the composed worker did not cross the disposable SLA warning and due boundaries",
      );
    }
    await delay(250);
    return pollSLAEffects();
  }

  const emailActions = activityItems.filter(
    (item) => item?.details?.actionKind === "email",
  );
  const systemAlertActions = activityItems.filter(
    (item) => item?.details?.actionKind === "create_system_alert",
  );
  assert(
    emailActions.length === 1 && systemAlertActions.length === 1,
    "each disposable SLA action must execute exactly once",
  );
  const emailOccurrenceId = requiredIdentifier(
    emailActions[0]?.details?.occurrenceId,
    "SLA email occurrence ID",
  );
  const systemAlertOccurrenceId = requiredIdentifier(
    systemAlertActions[0]?.details?.occurrenceId,
    "SLA system-Alert occurrence ID",
  );
  const systemAlertId = requiredIdentifier(
    systemAlertActions[0]?.details?.effectId,
    "SLA system-Alert effect ID",
  );

  const capturedWarning = await waitForMailpitSubject(warningSubject);
  assert(
    capturedWarning.html.includes(warningSubject) &&
      capturedWarning.text.includes(warningSubject),
    "the SLA warning must traverse the notifier and reach Mailpit",
  );
  const systemAlert = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${systemAlertId}`,
    { cookie },
  );
  expectStatus(systemAlert, 200, "SLA-created system Alert read");
  assert(
    systemAlert.body?.title === "SLA system alert: acceptance_sla_due" &&
      systemAlert.body?.source === "sla-engine" &&
      systemAlert.body?.sourceType === "system" &&
      systemAlert.body?.category === "acceptance_sla_due" &&
      systemAlert.body?.customerVisible === false &&
      systemAlert.body?.creator?.principalType === "service_account" &&
      ["sla", "system"].every((tag) => systemAlert.body?.tags?.includes(tag)),
    "the due action must create the expected private system Alert",
  );

  const systemAlertSLA = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${systemAlertId}/sla`,
    { cookie },
  );
  expectStatus(
    systemAlertSLA,
    404,
    "non-recursive SLA system Alert projection",
  );
  const actionAudit = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/audit-events?actionPrefix=tenant.sla.action&limit=100`,
  );
  expectStatus(actionAudit, 200, "SLA trigger-action audit listing");
  const serializedAudit = JSON.stringify(actionAudit.body?.items ?? []);
  for (const occurrenceId of [emailOccurrenceId, systemAlertOccurrenceId]) {
    assert(
      serializedAudit.includes(occurrenceId),
      `SLA trigger occurrence ${occurrenceId} must be represented in audit`,
    );
  }
  assert(
    serializedAudit.includes("tenant.sla.action.executed") &&
      serializedAudit.includes('"actionKind":"email"') &&
      serializedAudit.includes('"actionKind":"create_system_alert"'),
    "the warning and breach-side effect must be recorded by the tamper-evident audit stream",
  );

  await delay(5_000);
  const stableActivity = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${alertId}/activities?limit=100`,
    { cookie },
  );
  expectStatus(stableActivity, 200, "SLA action idempotency activity read");
  for (const occurrenceId of [emailOccurrenceId, systemAlertOccurrenceId]) {
    assert(
      stableActivity.body?.items?.filter(
        (item) => item?.details?.occurrenceId === occurrenceId,
      ).length === 1,
      `SLA occurrence ${occurrenceId} must remain exactly-once after another worker interval`,
    );
  }
  const stableSystemAlertSLA = await request(
    `/api/v1/tenants/${liveTenantId}/alerts/${systemAlertId}/sla`,
    { cookie },
  );
  expectStatus(
    stableSystemAlertSLA,
    404,
    "stable non-recursive SLA system Alert projection",
  );
}

async function simulateSLA(liveTenantId, policyId, json) {
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/sla-policies/${policyId}/simulate`,
    { method: "POST", json },
  );
  expectStatus(result, 200, "SLA policy simulation");
  return result.body;
}

function metricByKey(simulation, key) {
  const metric = simulation?.metrics?.find(
    (candidate) => candidate.metricKey === key,
  );
  assert(metric, `SLA simulation must return the ${key} metric`);
  return metric;
}

function sameInstant(actual, expected) {
  return (
    typeof actual === "string" &&
    Number.isFinite(Date.parse(actual)) &&
    Date.parse(actual) === Date.parse(expected)
  );
}

async function prepareNotificationAcceptance(
  liveTenantId,
  operatorUserId,
  customerActorUserId,
) {
  const smtp = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/smtp-configuration`,
    {
      method: "PUT",
      idempotencyKey: acceptanceKey("smtp"),
      json: {
        name: "Compose Mailpit",
        host: "mailpit",
        port: 1025,
        security: "plain_local",
        username: null,
        clearPassword: false,
        fromName: "Periapsis acceptance",
        fromEmail: "periapsis@acceptance.invalid",
        replyToEmail: null,
        timeoutMs: 5_000,
        maximumConnections: 4,
        maximumMessagesPerConnection: 100,
        rateLimitPerSecond: 20,
        clearDkim: false,
        enabled: true,
      },
    },
  );
  expectStatus(smtp, 201, "tenant Mailpit SMTP configuration");
  const smtpConfigurationId = requiredIdentifier(
    smtp.body?.id,
    "tenant Mailpit SMTP configuration ID",
  );

  const context = {
    customer: {
      case: {
        number: "CASE-42",
        title: "Endpoint investigation",
        customFields: { host: "live-e2e-host" },
      },
      contact: { firstName: "Acme", email: directoryCustomer.email },
      sla: { state: "at_risk", dueAt: "2026-12-24T15:30:00Z" },
    },
  };
  const richTemplate = {
    key: `live_case_update_${uniqueSuffix}`,
    name: "Live Case update",
    language: "en",
    subject:
      "Case {{case.number}} for {{contact.firstName}} {{sla.state}} {{case.customFields.host}}",
    html: '<div class="case" onclick="steal()"><strong>{{case.title}}</strong><script>steal()</script><span>{{contact.email}}</span><span>{{sla.dueAt}}</span><span>{{case.customFields.host}}</span></div>',
    plainText:
      "Case {{case.number}} for {{contact.firstName}} is {{sla.state}} at {{case.customFields.host}}",
    css: ".case { color: #123456; font-weight: 600; }",
    sampleData: context,
  };
  const preview = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-templates/preview`,
    {
      method: "POST",
      json: { audience: "customer", template: richTemplate, context },
    },
  );
  expectStatus(preview, 200, "notification template preview");
  assert(
    preview.body?.subject?.includes("CASE-42") &&
      preview.body?.subject?.includes("Acme") &&
      preview.body?.html?.includes("live-e2e-host") &&
      preview.body?.html?.includes("#123456") &&
      /font-weight:\s*600/u.test(preview.body?.html ?? "") &&
      preview.body?.plainText?.includes("at_risk") &&
      !/<\s*script\b|\sonclick\s*=/iu.test(preview.body?.html ?? ""),
    "notification preview must render all domains and strip executable markup",
  );
  const createdRichTemplate = await createNotificationTemplate(
    liveTenantId,
    richTemplate,
    "rich",
  );
  const testRecipient = `release-${uniqueSuffix}@example.invalid`;
  const testSend = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-templates/${createdRichTemplate.id}/test-send`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("template-test-send"),
      json: {
        version: 1,
        recipient: testRecipient,
        audience: "customer",
        context,
        reason: "Composed Mailpit release acceptance",
      },
    },
  );
  expectStatus(testSend, 202, "notification template Mailpit test send");
  const renderedSubject = `Case CASE-42 for Acme at_risk live-e2e-host`;
  const captured = await waitForMailpitSubject(renderedSubject, testRecipient);
  assert(
    captured.html.includes("live-e2e-host") &&
      captured.html.includes("#123456") &&
      /font-weight:\s*600/u.test(captured.html) &&
      captured.text.includes("CASE-42") &&
      !/<\s*script\b|\sonclick\s*=/iu.test(captured.html),
    "Mailpit must capture sanitized HTML and generated plain text",
  );

  const publicSubject = `PUBLIC-COMMENT-${uniqueSuffix}`;
  const privateSubject = `PRIVATE-COMMENT-${uniqueSuffix}`;
  const operatorSubject = `OPERATOR-COMMENT-${uniqueSuffix}`;
  const slaWarningSubject = `SLA-WARNING-${uniqueSuffix}`;
  const publicTemplate = await createNotificationTemplate(
    liveTenantId,
    {
      key: `public_comment_${uniqueSuffix}`,
      name: "Public comment acceptance",
      language: "en",
      subject: publicSubject,
      html: `<p>${publicSubject}</p>`,
      plainText: publicSubject,
      sampleData: {},
    },
    "public-comment",
  );
  const privateTemplate = await createNotificationTemplate(
    liveTenantId,
    {
      key: `private_comment_${uniqueSuffix}`,
      name: "Private comment acceptance",
      language: "en",
      subject: privateSubject,
      html: `<p>${privateSubject}</p>`,
      plainText: privateSubject,
      sampleData: {},
    },
    "private-comment",
  );
  const operatorTemplate = await createNotificationTemplate(
    liveTenantId,
    {
      key: `operator_comment_${uniqueSuffix}`,
      name: "Operator comment acceptance",
      language: "en",
      subject: operatorSubject,
      html: `<p>${operatorSubject}</p>`,
      plainText: operatorSubject,
      sampleData: {},
    },
    "operator-comment",
  );
  const slaWarningTemplate = await createNotificationTemplate(
    liveTenantId,
    {
      key: `sla_warning_${uniqueSuffix}`,
      name: "SLA warning acceptance",
      language: "en",
      subject: slaWarningSubject,
      html: `<p>${slaWarningSubject}</p>`,
      plainText: slaWarningSubject,
      sampleData: {},
    },
    "sla-warning",
  );
  await createCustomerCommentRule(
    liveTenantId,
    "comment.public_added",
    publicTemplate.id,
    "public",
    operatorUserId,
  );
  await rejectCustomerPrivateCommentRule(liveTenantId, privateTemplate.id);
  await rejectCustomerPrivateCommentWebhook(liveTenantId);
  await createCommentNotificationRule(
    liveTenantId,
    "comment.public_added",
    operatorTemplate.id,
    [{ kind: "tenant_admin", audience: "operator" }],
    "operator",
    customerActorUserId,
  );
  await createSLANotificationRule(liveTenantId, slaWarningTemplate.id);
  return {
    operatorSubject,
    privateSubject,
    publicSubject,
    slaWarningSubject,
    smtpConfigurationId,
  };
}

async function createNotificationTemplate(liveTenantId, json, scope) {
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-templates`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey(`template-${scope}`),
      json,
    },
  );
  expectStatus(result, 201, `${scope} notification template creation`);
  return {
    id: requiredIdentifier(result.body?.id, `${scope} template ID`),
  };
}

async function createCustomerCommentRule(
  liveTenantId,
  eventType,
  templateId,
  scope,
  actorUserId,
) {
  return createCommentNotificationRule(
    liveTenantId,
    eventType,
    templateId,
    [{ kind: "customer_contacts", audience: "customer" }],
    scope,
    actorUserId,
  );
}

async function rejectCustomerPrivateCommentRule(liveTenantId, templateId) {
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-rules`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("rule-private-customer-rejected"),
      json: commentNotificationRuleBody(
        "comment.private_added",
        templateId,
        [{ kind: "customer_contacts", audience: "customer" }],
        "private-customer-rejected",
      ),
    },
  );
  expectStatus(result, 400, "private-comment customer rule rejection");
}

async function rejectCustomerPrivateCommentWebhook(liveTenantId) {
  const signingKey = randomBytes(32).toString("base64url");
  const name = "Private customer comment rejection";
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/webhooks`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("webhook-private-customer-rejected"),
      json: {
        name,
        endpointUrl: "https://hooks.example.invalid/private-comments",
        eventTypes: ["comment.private_added"],
        audience: "customer",
        signingKey,
        timeoutMs: 5_000,
        enabled: true,
      },
    },
  );
  expectStatus(result, 400, "private-comment customer webhook rejection");
  assert(
    result.body?.status === 400 && result.body?.code === "invalid_request",
    "customer delivery of an operator-only private comment must fail as RFC 9457 invalid_request",
  );
  const webhooks = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/webhooks?limit=100`,
  );
  expectStatus(webhooks, 200, "webhook rejection persistence check");
  assert(
    !webhooks.body?.items?.some((webhook) => webhook?.name === name),
    "the rejected customer-private webhook must not persist a configuration",
  );
}

async function createCommentNotificationRule(
  liveTenantId,
  eventType,
  templateId,
  recipients,
  scope,
  actorUserId,
) {
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-rules`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey(`rule-${scope}`),
      json: commentNotificationRuleBody(
        eventType,
        templateId,
        recipients,
        scope,
        actorUserId,
      ),
    },
  );
  expectStatus(result, 201, `${scope} customer comment rule creation`);
}

async function createSLANotificationRule(liveTenantId, templateId) {
  const result = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-rules`,
    {
      method: "POST",
      idempotencyKey: acceptanceKey("rule-sla-warning"),
      json: {
        name: "SLA warning acceptance",
        description:
          "Routes the disposable runtime warning through the real notifier",
        eventType: "sla.warning",
        objectType: "alert",
        condition: {
          kind: "predicate",
          path: "event.type",
          operator: "equals",
          values: ["sla.warning"],
        },
        recipients: [
          {
            kind: "explicit_email",
            value: administrator.email,
            authorized: true,
            audience: "operator",
          },
        ],
        templateId,
        templateVersion: 1,
        channel: "email",
        priority: 100,
        delayMs: 0,
        deduplicationWindowMs: 0,
        grouping: { mode: "none" },
        retry: {
          maximumAttempts: 3,
          initialDelayMs: 1_000,
          maximumDelayMs: 10_000,
          multiplier: 2,
          jitterPercent: 0,
        },
        enabled: true,
        effectiveFrom: new Date(Date.now() - 60_000).toISOString(),
      },
    },
  );
  expectStatus(result, 201, "SLA warning notification rule creation");
}

function commentNotificationRuleBody(
  eventType,
  templateId,
  recipients,
  scope,
  actorUserId,
) {
  return {
    name: `${scope} comment acceptance`,
    description: "Proves the customer notification privacy boundary",
    eventType,
    objectType: "alert",
    condition: actorUserId
      ? {
          kind: "predicate",
          path: "actor.id",
          operator: "equals",
          values: [actorUserId],
        }
      : {
          kind: "predicate",
          path: "comment.visibility",
          operator: "exists",
        },
    recipients,
    templateId,
    templateVersion: 1,
    channel: "email",
    priority: 100,
    delayMs: 0,
    deduplicationWindowMs: 0,
    grouping: { mode: "none" },
    retry: {
      maximumAttempts: 3,
      initialDelayMs: 1_000,
      maximumDelayMs: 10_000,
      multiplier: 2,
      jitterPercent: 0,
    },
    enabled: true,
    effectiveFrom: new Date(Date.now() - 60_000).toISOString(),
  };
}

async function waitForMailpitSubject(
  subject,
  expectedRecipient,
  deadline = Date.now() + 45_000,
) {
  const messages = await listMailpitMessages();
  const summary = messages.find((message) => message.Subject === subject);
  if (summary) {
    const response = await fetch(
      `${mailpitOrigin()}/api/v1/message/${encodeURIComponent(summary.ID)}`,
      { signal: AbortSignal.timeout(5_000) },
    );
    assert(response.ok, "Mailpit detail request must succeed");
    const detail = await response.json();
    assert(
      detail?.Subject === subject &&
        (expectedRecipient === undefined ||
          detail?.To?.some(
            (recipient) => recipient?.Address === expectedRecipient,
          )) &&
        typeof detail.HTML === "string" &&
        typeof detail.Text === "string",
      "Mailpit detail response must contain the expected message",
    );
    return { html: detail.HTML, text: detail.Text };
  }
  if (Date.now() >= deadline) {
    throw new Error(`Mailpit did not capture subject ${subject}`);
  }
  await delay(250);
  return waitForMailpitSubject(subject, expectedRecipient, deadline);
}

async function listMailpitMessages() {
  const response = await fetch(
    `${mailpitOrigin()}/api/v1/messages?start=0&limit=100`,
    { signal: AbortSignal.timeout(5_000) },
  );
  assert(response.ok, "Mailpit list request must succeed");
  const body = await response.json();
  assert(Array.isArray(body?.messages), "Mailpit list response is malformed");
  return body.messages.filter(
    (message) =>
      typeof message?.ID === "string" && typeof message?.Subject === "string",
  );
}

function mailpitOrigin() {
  const port = Number.parseInt(
    process.env.PERIAPSIS_MAILPIT_PORT ?? "18025",
    10,
  );
  assert(
    Number.isInteger(port) && port > 0 && port <= 65_535,
    "PERIAPSIS_MAILPIT_PORT must be a TCP port",
  );
  return `http://127.0.0.1:${port}`;
}

async function verifyMailpitCommentPrivacy(
  liveTenantId,
  { operatorSubject, privateSubject, publicSubject },
) {
  await Promise.all([
    waitForMailpitSubject(publicSubject, directoryCustomer.email),
    waitForMailpitSubject(operatorSubject, administrator.email),
  ]);
  await delay(2_000);
  const messages = await listMailpitMessages();
  assert(
    !messages.some((message) => message.Subject === privateSubject),
    "private comment notification must not fan out to customer contacts",
  );
  const webhookDeliveries = await administratorRequest(
    `/api/v1/tenants/${liveTenantId}/notification-deliveries?limit=100`,
  );
  expectStatus(
    webhookDeliveries,
    200,
    "private-comment webhook delivery listing",
  );
  assert(
    !webhookDeliveries.body?.items?.some(
      (delivery) => delivery?.channel === "webhook",
    ),
    "rejected customer-private webhook configuration must produce no webhook deliveries",
  );
}

function proveTenantRLSIsolation(
  sourceTenantId,
  activeTenantId,
  alertId,
  activeUserId,
) {
  const environment = {
    ...process.env,
    PGPASSWORD: requiredEnvironment("PERIAPSIS_API_DATABASE_PASSWORD"),
  };
  const sql = [
    "WITH context AS MATERIALIZED (",
    "SELECT set_config('app.tenant_id', :'tenant_id', false),",
    "set_config('app.user_id', :'user_id', false)",
    ") SELECT count(*) FROM context CROSS JOIN public.alerts",
    "WHERE alerts.id = :'alert_id'::uuid;",
  ].join(" ");
  const result = spawnSync(
    "docker",
    [
      "compose",
      "--file",
      composeFile,
      "--profile",
      composeProfile,
      "exec",
      "-T",
      "-e",
      "PGPASSWORD",
      "postgres",
      "psql",
      "-X",
      "-A",
      "-t",
      "-v",
      "ON_ERROR_STOP=1",
      "-v",
      `tenant_id=${activeTenantId}`,
      "-v",
      `user_id=${activeUserId}`,
      "-v",
      `alert_id=${alertId}`,
      "-U",
      "periapsis_api_login",
      "-d",
      "periapsis",
      "-c",
      sql,
    ],
    { cwd: process.cwd(), env: environment, encoding: "utf8" },
  );
  if (result.error) throw result.error;
  assert(
    result.status === 0 && result.stdout.trim() === "0",
    `RLS wrong-context probe failed for ${sourceTenantId}`,
  );
}

function cookieValue(cookie) {
  const separator = cookie.indexOf("=");
  assert(separator > 0, "session cookie must be a name/value pair");
  const value = cookie.slice(separator + 1);
  assert(
    /^[A-Za-z0-9_-]{43}$/u.test(value),
    "session cookie value must be an opaque 256-bit token",
  );
  return value;
}

function assertAuditContainsResourceActions(events, fragments) {
  const actions = events.map((event) => event?.action).filter(Boolean);
  for (const fragment of fragments) {
    assert(
      actions.some((action) => action.includes(fragment)),
      `tenant audit stream must contain an action for ${fragment}`,
    );
  }
}

async function listAllTenantAudit(liveTenantId, actionPrefix = "") {
  const items = [];
  const sequences = new Set();
  let afterSequence = 0;
  for (let page = 0; page < 50; page += 1) {
    // eslint-disable-next-line no-await-in-loop -- each page cursor comes from the prior response.
    const result = await administratorRequest(
      `/api/v1/tenants/${liveTenantId}/audit-events?limit=100&afterSequence=${afterSequence}${actionPrefix ? `&actionPrefix=${encodeURIComponent(actionPrefix)}` : ""}`,
    );
    expectStatus(result, 200, "live acceptance audit page listing");
    for (const event of result.body?.items ?? []) {
      assert(
        Number.isSafeInteger(event?.sequence) &&
          event.sequence > afterSequence &&
          !sequences.has(event.sequence),
        "live acceptance audit pagination must remain strictly increasing and unique",
      );
      sequences.add(event.sequence);
      items.push(event);
    }
    if (result.body?.nextSequence === undefined) return items;
    assert(
      Number.isSafeInteger(result.body.nextSequence) &&
        result.body.nextSequence > afterSequence,
      "live acceptance audit cursor must advance",
    );
    afterSequence = result.body.nextSequence;
  }
  throw new Error("live acceptance audit pagination exceeded 50 pages");
}

function livePlaywrightEnvironment(
  liveBaseUrl,
  outputDirectory,
  stateFile,
  oidcAcceptance,
) {
  const environment = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (!name.toUpperCase().startsWith("PERIAPSIS_")) {
      environment[name] = value;
    }
  }
  return {
    ...environment,
    PERIAPSIS_LIVE_E2E_BASE_URL: liveBaseUrl,
    PERIAPSIS_LIVE_E2E_OIDC_CLIENT_ID: oidcAcceptance.clientId,
    PERIAPSIS_LIVE_E2E_OIDC_FALLBACK_PASSWORD: oidcAcceptance.fallback.password,
    PERIAPSIS_LIVE_E2E_OIDC_FALLBACK_USERNAME: oidcAcceptance.fallback.username,
    PERIAPSIS_LIVE_E2E_OIDC_ISSUER: `${idpBaseUrl}/realms/${idpRealm}`,
    PERIAPSIS_LIVE_E2E_OIDC_LOGIN_KEY: oidcAcceptance.loginKey,
    PERIAPSIS_LIVE_E2E_OIDC_TENANT_SLUG: tenantSlug,
    PERIAPSIS_LIVE_E2E_OIDC_TRUSTED_PASSWORD: oidcAcceptance.trusted.password,
    PERIAPSIS_LIVE_E2E_OIDC_TRUSTED_USERNAME: oidcAcceptance.trusted.username,
    PERIAPSIS_LIVE_E2E_OUTPUT_DIR: outputDirectory,
    PERIAPSIS_LIVE_E2E_STATE_FILE: stateFile,
  };
}

async function dryRun(username) {
  const result = await administratorRequest(
    `/api/v1/tenants/${tenantId}/ldap-mappings/dry-run`,
    {
      method: "POST",
      json: { bindingId, username, includeDisabledMappingIds: [] },
    },
  );
  expectStatus(result, 200, "LDAP mapping dry-run");
  return result;
}

async function listLDAPAudit() {
  // The API matches complete dot-separated action components. LDAP actions
  // use ldap_* within tenant.identity, so filter that namespace after paging.
  const events = await listAllTenantAudit(tenantId, "tenant.identity");
  return events.filter((event) =>
    event.action.startsWith("tenant.identity.ldap_"),
  );
}

async function waitForSyncRun(expectedBindingId, expectedSyncRunId) {
  const deadline = Date.now() + 120_000;
  return pollSyncRun();

  async function pollSyncRun() {
    if (Date.now() >= deadline) {
      throw new Error(
        "LDAP sync did not reach a terminal state within 120 seconds",
      );
    }
    const result = await administratorRequest(
      `/api/v1/tenants/${tenantId}/auth-provider-bindings/${expectedBindingId}/sync-runs/${expectedSyncRunId}`,
    );
    expectStatus(result, 200, "LDAP sync-run polling");
    if (result.body?.state === "succeeded") return result.body;
    if (["failed", "cancelled", "stale"].includes(result.body?.state)) {
      throw new Error(
        `LDAP sync terminated as ${result.body.state} (${result.body.runErrorCategory ?? "uncategorized"})`,
      );
    }
    await delay(500);
    return pollSyncRun();
  }
}

async function administratorRequest(path, options = {}) {
  return request(path, {
    ...options,
    cookie: administratorCookie,
    csrfToken:
      options.method && options.method !== "GET"
        ? administratorCSRF
        : undefined,
    origin:
      options.method && options.method !== "GET" ? browserOrigin : undefined,
  });
}

async function request(
  path,
  {
    method = "GET",
    headers = {},
    json,
    form,
    cookie,
    csrfToken,
    origin,
    authorization,
    idempotencyKey,
    ifMatch,
  } = {},
) {
  assert(
    !(json !== undefined && form !== undefined),
    "request body cannot be both JSON and form data",
  );
  const requestHeaders = new Headers({
    Accept: "application/json",
    ...headers,
  });
  let body;
  if (json !== undefined) {
    requestHeaders.set("Content-Type", "application/json");
    body = JSON.stringify(json);
  } else if (form !== undefined) {
    requestHeaders.set("Content-Type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(form).toString();
  }
  if (cookie) requestHeaders.set("Cookie", cookie);
  if (authorization) requestHeaders.set("Authorization", authorization);
  if (csrfToken) requestHeaders.set("X-CSRF-Token", csrfToken);
  if (origin) requestHeaders.set("Origin", origin);
  if (idempotencyKey) requestHeaders.set("Idempotency-Key", idempotencyKey);
  if (ifMatch) requestHeaders.set("If-Match", ifMatch);

  const fetchOptions = {
    method,
    headers: requestHeaders,
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
  };
  if (body !== undefined) fetchOptions.body = body;
  const response = await fetch(new URL(path, baseUrl), fetchOptions);
  const responseText = await response.text();
  let parsedBody;
  if (responseText !== "") {
    try {
      parsedBody = JSON.parse(responseText);
    } catch {
      parsedBody = undefined;
    }
  }
  return { response, body: parsedBody, text: responseText };
}

function runDirectoryFixture(action) {
  const fixtureEnvironment =
    action === "provision"
      ? [
          "-e",
          "PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD",
          "-e",
          "PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD",
          "-e",
          "PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD",
          "-e",
          "PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD",
        ]
      : [];
  const result = spawnSync(
    "docker",
    [
      "compose",
      "--file",
      composeFile,
      "--profile",
      composeProfile,
      "exec",
      "-T",
      ...fixtureEnvironment,
      "openldap",
      "sh",
      "/opt/ldifs/periapsis-acceptance-fixture.sh",
      action,
    ],
    { cwd: process.cwd(), env: process.env, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`OpenLDAP acceptance fixture ${action} failed`);
  }
}

function assertDryRunAction(actions, identifierKey, identifier, action) {
  assert(
    actions?.some(
      (item) => item?.[identifierKey] === identifier && item.action === action,
    ),
    `LDAP dry-run must plan ${action} for ${identifierKey}`,
  );
}

function assertAuditActions(events, requiredActions) {
  const actions = new Set(events.map((event) => event.action));
  for (const action of requiredActions) {
    assert(actions.has(action), `tenant audit stream must contain ${action}`);
  }
}

function bootstrapHeaders() {
  return { "X-Periapsis-Bootstrap-Token": bootstrapToken };
}

function acceptanceKey(scope) {
  return `ldap-acceptance-${scope}-${randomUUID()}`;
}

function expectStatus(result, expected, operation) {
  if (result.response.status !== expected) {
    const code =
      typeof result.body?.code === "string" ? ` (${result.body.code})` : "";
    throw new Error(
      `${operation} returned ${result.response.status}${code}; expected ${expected}`,
    );
  }
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required for composed LDAP acceptance`);
  }
  return value;
}

function environmentPort(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  assert(/^\d{1,5}$/u.test(raw), `${name} must be a decimal TCP port`);
  const value = Number(raw);
  assert(
    Number.isSafeInteger(value) && value >= 1024 && value <= 65_535,
    `${name} must be between 1024 and 65535`,
  );
  return value;
}

function requiredBoundedSecret(value, label) {
  assert(
    typeof value === "string" && value.length >= 16 && value.length <= 8192,
    `${label} must be a bounded non-empty secret`,
  );
  return value;
}

function appendFailure(current, next) {
  if (!current) return next;
  return new AggregateError([current, next], "multiple acceptance failures");
}

function errorMessage(value) {
  return value instanceof Error ? value.message : "unknown cleanup failure";
}

function requiredIdentifier(value, label) {
  assertString(value, label);
  assert(
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    ),
    `${label} must be a UUIDv7`,
  );
  return value;
}

function requiredPositiveInteger(value, label) {
  assert(
    Number.isSafeInteger(value) && value > 0,
    `${label} must be a positive safe integer`,
  );
  return value;
}

function identifierFromLocation(location, label) {
  const segments = new URL(location, baseUrl).pathname.split("/");
  return requiredIdentifier(segments.at(-1), label);
}

function requiredHeader(result, name, label) {
  const value = result.response.headers.get(name);
  assertString(value, label);
  return value;
}

function requiredStrongETag(result, label) {
  const value = requiredHeader(result, "etag", label);
  assert(
    /^"v[1-9]\d*"$/u.test(value),
    `${label} must be a strong version ETag`,
  );
  return value;
}

function versionFromStrongETag(entityTag, label) {
  return requiredPositiveInteger(Number(entityTag.slice(2, -1)), label);
}

function requiredRevisionHeader(result, name, label) {
  const value = requiredHeader(result, name, label);
  assert(/^\d+$/u.test(value), `${label} must be a decimal integer`);
  return requiredPositiveInteger(Number(value), label);
}

function assertExactObjectKeys(value, expectedKeys, label) {
  assert(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} must be an object`,
  );
  const actual = Object.keys(value).toSorted();
  const expected = expectedKeys.toSorted();
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${label} must expose only its documented sanitized fields`,
  );
}

function assertExactJSON(actual, expected, label) {
  assert(
    JSON.stringify(canonicalJSON(actual)) ===
      JSON.stringify(canonicalJSON(expected)),
    `${label} must round-trip exactly`,
  );
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return value.map(canonicalJSON);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .toSorted()
      .map((key) => [key, canonicalJSON(value[key])]),
  );
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertString(value, label) {
  assert(
    typeof value === "string" && value.length > 0,
    `${label} must be a non-empty string`,
  );
}

function issuedCookie(result, operation) {
  const secureOrigin = new URL(baseUrl).protocol === "https:";
  const expectedName = secureOrigin
    ? "__Host-periapsis_session"
    : "periapsis_session";
  const sessionCookies = result.response.headers
    .getSetCookie()
    .filter((value) => value.startsWith(`${expectedName}=`));
  assert(
    sessionCookies.length === 1,
    `${operation} must issue exactly one session cookie`,
  );
  const setCookie = sessionCookies[0];
  assertString(setCookie, `${operation} Set-Cookie`);
  const cookie = setCookie.split(";", 1)[0];
  const cookieSeparator = cookie.indexOf("=");
  assert(cookieSeparator > 0, `${operation} cookie must be a name/value pair`);
  const cookieName = cookie.slice(0, cookieSeparator);
  assert(
    /;\s*HttpOnly(?:;|$)/iu.test(setCookie) &&
      /;\s*SameSite=Strict(?:;|$)/iu.test(setCookie) &&
      /;\s*Path=\/(?:;|$)/iu.test(setCookie) &&
      (secureOrigin
        ? /;\s*Secure(?:;|$)/iu.test(setCookie) &&
          cookieName === "__Host-periapsis_session"
        : !/;\s*Secure(?:;|$)/iu.test(setCookie) &&
          !cookieName.startsWith("__Host-")),
    `${operation} must issue the hardened session cookie policy`,
  );
  return cookie;
}

function refreshedCookie(result, previous) {
  return result.response.headers.getSetCookie().length > 0
    ? issuedCookie(result, "session rotation")
    : previous;
}

function requiredSessionCSRF(session) {
  assertString(session?.csrfToken, "session CSRF token");
  return session.csrfToken;
}

async function avoidTotpBoundary() {
  const remaining = 30_000 - (Date.now() % 30_000);
  if (remaining < 8_000) await delay(remaining + 250);
}

function uuidv7() {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function totp(base32Secret) {
  const key = decodeBase32(base32Secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest.at(-1) & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.toUpperCase().replace(/=+$/u, "");
  let accumulator = 0;
  let bitCount = 0;
  const bytes = [];
  for (const character of normalized) {
    const digit = alphabet.indexOf(character);
    if (digit < 0)
      throw new Error("server returned an invalid Base32 TOTP secret");
    accumulator = (accumulator << 5) | digit;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((accumulator >>> bitCount) & 0xff);
      accumulator &= (1 << bitCount) - 1;
    }
  }
  return Buffer.from(bytes);
}
