import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const integration = readFileSync(
  new URL("../integration/ldap-auth-acceptance.mjs", import.meta.url),
  "utf8",
);
const specification = readFileSync(
  new URL("phase-three-live.spec.ts", import.meta.url),
  "utf8",
);
const configuration = readFileSync(
  new URL("playwright.live.config.ts", import.meta.url),
  "utf8",
);
const workflow = readFileSync(
  new URL("../../.github/workflows/ci.yml", import.meta.url),
  "utf8",
);
const packageManifest = readFileSync(
  new URL("../../package.json", import.meta.url),
  "utf8",
);
const ldapFixture = readFileSync(
  new URL(
    "../../deploy/compose/auth/openldap-acceptance-fixture.sh",
    import.meta.url,
  ),
  "utf8",
);

test("live Phase 3 acceptance uses the composed API and database without interception", () => {
  assert.doesNotMatch(specification, /\.(?:route|routeFromHAR)\s*\(/u);
  assert.doesNotMatch(
    specification,
    /\broute\.(?:fulfill|abort|continue)\s*\(/u,
  );
  const manualContexts = [
    ...specification.matchAll(/browser\.newContext\(\{(?<options>[^}]*)\}\)/gu),
  ];
  assert.equal(manualContexts.length, 5);
  for (const context of manualContexts) {
    assert.match(
      context.groups?.options ?? "",
      /baseURL:\s*state\.baseUrl/u,
      "manually created contexts must carry the live HTTPS base URL",
    );
  }
  assert.match(configuration, /phase-three-live\.spec\.ts/u);
  assert.doesNotMatch(configuration, /\bwebServer\s*:/u);
  assert.match(configuration, /PERIAPSIS_LIVE_E2E_BASE_URL/u);
  assert.match(configuration, /PERIAPSIS_LIVE_E2E_OUTPUT_DIR/u);
  assert.match(integration, /playwright\.live\.config\.ts/u);
  assert.match(integration, /PERIAPSIS_LIVE_E2E_OUTPUT_DIR/u);
  assert.match(integration, /mode:\s*0o600/u);
  assert.match(workflow, /PERIAPSIS_LDAP_ACCEPTANCE_RUN_LIVE_PLAYWRIGHT=1/u);
});

test("CI transpiles the live spec and provisions its isolated browser runner", () => {
  assert.match(packageManifest, /"test:e2e:live:list"/u);
  assert.match(workflowJob("javascript"), /pnpm test:e2e:live:list/u);
  const containersJob = workflowJob("containers");
  assert.match(containersJob, /pnpm\/action-setup@/u);
  assert.match(containersJob, /pnpm install --frozen-lockfile/u);
  assert.match(containersJob, /playwright install --with-deps chromium/u);
  assert.match(
    containersJob,
    /--profile minimal down --volumes --remove-orphans/u,
  );
});

test("live Phase 3 acceptance proves claim, selected copies, and exact replay", () => {
  for (const permission of [
    "alert.claim",
    "alert.escalate",
    "case.create",
    "custom_field.manage",
    "dfir.ioc.manage",
    "dfir.asset.manage",
  ]) {
    assert.match(integration, new RegExp(`"${permission}"`, "u"));
  }
  assert.match(specification, /button", \{ name: "Claim"/u);
  assert.match(specification, /claimResponse\.status\(\)\)\.toBe\(200\)/u);
  assert.match(specification, /claimedBy: state\.operatorUserId/u);
  assert.match(
    specification,
    /caseBody\.customFields\)\.toEqual\(\{ host: "live-e2e-host" \}\)/u,
  );
  assert.match(specification, /state\.indicatorId/u);
  assert.match(specification, /state\.assetId/u);
  assert.match(specification, /Idempotency-Key/u);
  assert.match(
    specification,
    /expect\(replay\.body\)\.toEqual\(escalationBody\)/u,
  );
});

test("required live acceptance drives isolation, service accounts, customer privacy, DFIR, SLA, and delivery infrastructure", () => {
  for (const executableBoundary of [
    "/service-accounts",
    "authorization = `Bearer",
    "Promise.all([",
    "PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD",
    "PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD",
    "prepareIsolationLDAPPrincipal",
    "Globex isolation user must have no Acme tenant membership",
    "Simultaneous second-operator claim",
    "claim race must advance the SLA projection",
    "/sla-policies/${policyId}/simulate",
    "/notification-templates/preview",
    "/notification-deliveries?status=delivered",
    "/audit-events/verify",
    "services/api/internal/contract/openapi.json",
    "served Swagger contract must exactly match the committed generated OpenAPI document",
    "periapsis_api_login",
    "waitForMailpitSubject",
    "waitForMailpitSubject(publicSubject, directoryCustomer.email)",
    "waitForMailpitSubject(operatorSubject, administrator.email)",
    'key: "acceptance_clock"',
    'kind: "create_system_alert"',
    "verifyLiveSLATriggers",
    'item?.kind === "sla.action.executed"',
    'item?.details?.actionKind === "email"',
    'item?.details?.actionKind === "create_system_alert"',
    "/alerts/${systemAlertId}/sla",
    "tenant.sla.action.executed",
    "rejectCustomerPrivateCommentWebhook",
    'eventTypes: ["comment.private_added"]',
    'result.body?.code === "invalid_request"',
    "webhook rejection persistence check",
    'delivery?.channel === "webhook"',
    'path: "actor.id"',
    "values: [actorUserId]",
  ]) {
    assert.match(
      integration,
      new RegExp(escapeRegExp(executableBoundary), "u"),
    );
  }
  for (const executableBoundary of [
    "/openapi.json",
    "/ticket-exports",
    "/prepare-download?kind=alert",
    'credentials: "omit"',
    "artifactSha256",
    "/portal/alerts/${state.alertId}/export",
    "/comments",
    "/attachments/prepare-upload",
    "consumedUploadReplay.status).toBe(409)",
    "historicalEvidenceReplay.body).toEqual(evidence.body)",
    '"sharedResources"',
    'page.locator(".dfir-related-tickets")',
    "fetch(url",
    "/evidence/${evidenceId}/custody",
    "/timeline-events",
    "/tasks",
    "/relationships",
    "/linked-cases",
    "/linked-alerts",
    "/cases/${caseId}/contacts?limit=100",
    "createDfirBundle(page, state, {",
    "root: `/api/v1/tenants/${state.tenantId}/cases/${caseId}/dfir`",
    '"dfir.evidence.collected"',
    '"dfir.evidence.custody_appended"',
    '"dfir.timeline.created"',
    '"dfir.task.created"',
    '"dfir.relationship.created"',
    'name: "Case evidence room"',
    "Access was denied by the server",
    "tenant.alert.escalated",
    "tenant.case.created",
  ]) {
    assert.match(
      specification,
      new RegExp(escapeRegExp(executableBoundary), "u"),
    );
  }
  assert.match(workflow, /--profile full up --detach --no-build --wait/u);
  assert.match(
    workflow,
    /build api worker web migration ldap-tls openldap identity-provider minio minio-provision/u,
  );
  assert.match(
    workflow,
    /edge openldap identity-provider worker notifier mailpit/u,
  );
  assert.match(workflow, /ps --quiet identity-provider/u);
  assert.match(workflow, /\.HostConfig\.ReadonlyRootfs/u);
  assert.match(workflow, /identity_user%%:\*/u);
  assert.match(workflow, /PERIAPSIS_LDAP_ACCEPTANCE_COMPOSE_PROFILE=full/u);
  assert.match(workflow, /cannot mutate append-only tenant audit rows/u);
  assert.match(ldapFixture, /PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD/u);
  assert.match(ldapFixture, /ldap_status.*-eq 32/u);
  assert.match(ldapFixture, /LDAP lookup failed/u);
  assert.match(ldapFixture, /isolation_group_dn/u);
});

test("required live acceptance drives real Keycloak OIDC, JIT mapping, external MFA trust, and local TOTP fallback", () => {
  for (const executableBoundary of [
    "/realms/master/protocol/openid-connect/token",
    "/admin/realms/${idpRealm}/clients",
    "/admin/realms/${idpRealm}/users",
    "/oidc/trust-documents",
    "/mapping-policy",
    "/assurance-policy",
    'kind: "oidc"',
    "exactValue: null",
    "x-periapsis-secret-revision",
    "x-periapsis-oidc-discovery-revision",
    "x-periapsis-oidc-jwks-revision",
    "x-periapsis-oidc-jwks-key-count",
    "x-periapsis-mapping-revision",
    "x-periapsis-assurance-policy-revision",
    "persisted OIDC provider readback",
    "tenant OIDC mapping-policy readback",
    "tenant OIDC assurance-policy readback",
    "assertExactObjectKeys",
    "mappingReadback.body?.tenantId === liveTenantId",
    "assuranceReadback.body?.tenantId === liveTenantId",
    'claimName: "roles"',
    'matcherKind: "scalar_equals"',
    'requiredValues: ["otp", "pwd"]',
    "localRequired: false",
    "tenant.identity.federated_login_completed",
    "mfa.totp_enrolled",
    'protocolMapper: "oidc-amr-mapper"',
    '"auth-username-password-form"',
    '"auth-otp-form"',
    '"default.reference.value"',
    '"CONFIGURE_TOTP"',
  ]) {
    assert.match(
      integration,
      new RegExp(escapeRegExp(executableBoundary), "u"),
    );
  }
  for (const executableBoundary of [
    'name: "Continue with OIDC"',
    'locator("#kc-form-login")',
    'locator("#kc-login")',
    'locator("#kc-totp-settings-form")',
    'locator("#kc-otp-login-form")',
    'locator("#kc-totp-secret-key")',
    'code_challenge_method: "S256"',
    'for (const name of ["code_challenge", "nonce", "state"])',
    'name: "Complete local MFA."',
    "expect(beforeEnrollment.status).toBe(401)",
    '"/api/v1/auth/federated/mfa/continuation"',
    "expect(abandoned.status).toBe(204)",
    'name: "Set up an authenticator"',
    'name: "Confirm authenticator"',
    "expect(afterEnrollment.status).toBe(401)",
    'name: "Use local verification"',
    'name: "Verify and create session"',
    'authenticationMethod: "oidc"',
    "browserTotp(secret)",
    "requireBrowserTotpSecret",
    "state.oidcSecurityGroupId",
  ]) {
    assert.match(
      specification,
      new RegExp(escapeRegExp(executableBoundary), "u"),
    );
  }
  assert.match(workflow, /build[^\n]*identity-provider/u);
  assert.match(workflow, /up[^\n]*identity-provider/u);
  assert.match(workflow, /Health\.Status[^\n]*identity/u);
  assert.doesNotMatch(integration, /periapsis_amr/u);
});

test("ephemeral browser authority is never committed as a fixture", () => {
  assert.match(integration, /mkdtempSync/u);
  assert.match(integration, /rmSync\(resolvedTemporaryRoot/u);
  assert.match(
    integration,
    /!name\.toUpperCase\(\)\.startsWith\("PERIAPSIS_"\)/u,
  );
  assert.match(integration, /__Host-periapsis_session/u);
  assert.match(integration, /;\\s\*Secure/u);
  assert.match(specification, /__Host-periapsis_session/u);
  assert.doesNotMatch(specification, /\.allHeaders\s*\(/u);
  assert.doesNotMatch(specification, /console\.(?:log|info|debug|error)/u);
  assert.doesNotMatch(integration, /cookieValue[^\n]*stdout/u);
  assert.doesNotMatch(specification, /expect\(secret\)/u);
  assert.match(configuration, /screenshot:\s*"off"/u);
  assert.match(configuration, /trace:\s*"off"/u);
  assert.match(configuration, /video:\s*"off"/u);
  assert.doesNotMatch(configuration, /only-on-failure|retain-on-failure/u);
});

function workflowJob(name) {
  const marker = `\n  ${name}:\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `workflow job ${name} must exist`);
  const bodyStart = start + marker.length;
  const remainder = workflow.slice(bodyStart);
  const nextJob = remainder.search(/\n  [a-z][a-z0-9-]*:\n/u);
  return nextJob === -1 ? remainder : remainder.slice(0, nextJob);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
