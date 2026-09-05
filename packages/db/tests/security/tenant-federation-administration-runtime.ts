import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonValue = boolean | number | string | null | JsonObject | JsonValue[];
type JsonObject = { [key: string]: JsonValue };

type FederationFunction =
  | "archive_tenant_federated_auth_provider_v1"
  | "begin_tenant_oidc_authentication_v1"
  | "begin_tenant_saml_authentication_v1"
  | "clear_tenant_oidc_client_secret_v1"
  | "clear_tenant_saml_sp_credential_v1"
  | "commit_tenant_oidc_trust_documents_v1"
  | "create_tenant_federated_auth_provider_v1"
  | "get_tenant_federated_assurance_policy_v1"
  | "get_tenant_federated_auth_provider_v1"
  | "get_tenant_federated_mapping_policy_v1"
  | "get_tenant_saml_sp_metadata_v1"
  | "load_oidc_client_secret_envelope_v1"
  | "load_saml_sp_key_envelope_v1"
  | "prepare_tenant_oidc_client_secret_v1"
  | "prepare_tenant_oidc_trust_documents_v1"
  | "prepare_tenant_saml_metadata_v1"
  | "prepare_tenant_saml_sp_credential_v1"
  | "replace_tenant_federated_assurance_policy_v1"
  | "replace_tenant_federated_mapping_policy_v1"
  | "replace_tenant_oidc_client_secret_v1"
  | "replace_tenant_saml_metadata_v1"
  | "replace_tenant_saml_sp_credential_v1"
  | "update_tenant_federated_auth_provider_v1";

const databaseUrl =
  process.env.PERIAPSIS_TENANT_FEDERATION_ADMIN_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_FEDERATION_ADMIN_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a09e00-1000-7000-8000-000000000001",
  foreignTenant: "01a09e00-1000-7000-8000-000000000002",
  adminUser: "01a09e00-1000-7000-8000-000000000101",
  scopedUser: "01a09e00-1000-7000-8000-000000000102",
  foreignUser: "01a09e00-1000-7000-8000-000000000103",
  sessionUser: "01a09e00-1000-7000-8000-000000000104",
  adminMembership: "01a09e00-1000-7000-8000-000000000201",
  scopedMembership: "01a09e00-1000-7000-8000-000000000202",
  foreignMembership: "01a09e00-1000-7000-8000-000000000203",
  sessionMembership: "01a09e00-1000-7000-8000-000000000204",
  command: "01a09e00-1000-7000-8000-000000000301",
  replayCommand: "01a09e00-1000-7000-8000-000000000302",
  provider: "01a09e00-1000-7000-8000-000000000303",
  replayProvider: "01a09e00-1000-7000-8000-000000000304",
  binding: "01a09e00-1000-7000-8000-000000000305",
  replayBinding: "01a09e00-1000-7000-8000-000000000306",
  secret: "01a09e00-1000-7000-8000-000000000307",
  scopedRole: "01a09e00-1000-7000-8000-000000000308",
  targetRole: "01a09e00-1000-7000-8000-000000000309",
  scopedRoleGrant: "01a09e00-1000-7000-8000-00000000030a",
  securityGroup: "01a09e00-1000-7000-8000-00000000030b",
  mappingRule: "01a09e00-1000-7000-8000-00000000030c",
  trustRule: "01a09e00-1000-7000-8000-00000000030d",
  operatorTeam: "01a09e00-1000-7000-8000-00000000030e",
  assignmentEpoch: "01a09e00-1000-7000-8000-00000000030f",
  rosterEntry: "01a09e00-1000-7000-8000-000000000310",
  externalIdentity: "01a09e00-1000-7000-8000-000000000311",
  session: "01a09e00-1000-7000-8000-000000000312",
  sessionFamily: "01a09e00-1000-7000-8000-000000000313",
  accessSource: "01a09e00-1000-7000-8000-000000000314",
  accessEpoch: "01a09e00-1000-7000-8000-000000000315",
  keyringAlias: "01a09e00-1000-7000-8000-000000000316",
  begin: "01a09e00-1000-7000-8000-000000000317",
  oidcLogout: "01a09e00-1000-7000-8000-000000000318",
  oidcLifecycleSession: "01a09e00-1000-7000-8000-000000000319",
  oidcLifecycleFamily: "01a09e00-1000-7000-8000-00000000031a",
  oidcLifecycleApplication: "01a09e00-1000-7000-8000-00000000031b",
  oidcLogoutContinuation: "01a09e00-1000-7000-8000-00000000031c",
  oidcScrub: "01a09e00-1000-7000-8000-00000000031d",
  oidcLogoutReplay: "01a09e00-1000-7000-8000-00000000031e",
  oidcLogoutReplayContinuation: "01a09e00-1000-7000-8000-00000000031f",
  oidcLifecycleSiblingSession: "01a09e00-1000-7000-8000-000000000320",
  platformOidcRefreshProvider: "01a09e00-1000-7000-8000-000000000321",
  platformOidcRefreshIdentity: "01a09e00-1000-7000-8000-000000000322",
  platformOidcRefreshSession: "01a09e00-1000-7000-8000-000000000323",
  platformOidcRefreshFamily: "01a09e00-1000-7000-8000-000000000324",
  platformOidcRefreshMaterial: "01a09e00-1000-7000-8000-000000000325",
  platformOidcRefreshApplication: "01a09e00-1000-7000-8000-000000000326",
  platformOidcRefreshFloor: "01a09e00-1000-7000-8000-000000000327",
} as const;

const sql = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
const now = new Date();
const later = new Date(now.getTime() + 60 * 60 * 1000);

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function setAPIContext(
  transaction: TransactionSql,
  tenantID: string = fixture.tenant,
  userID: string = fixture.adminUser,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantID}, true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function call(
  functionName: FederationFunction,
  request: JsonObject,
  tenantID: string = fixture.tenant,
  userID: string = fixture.adminUser,
): Promise<JsonObject> {
  return sql.begin(async (transaction) => {
    await setAPIContext(transaction, tenantID, userID);
    return callInTransaction(transaction, functionName, request);
  });
}

async function callInTransaction(
  transaction: TransactionSql,
  functionName: FederationFunction,
  request: JsonObject,
): Promise<JsonObject> {
  const response = await callNullableInTransaction(
    transaction,
    functionName,
    request,
  );
  assert(response, `${functionName} returned no JSON object`);
  return response;
}

async function callNullableInTransaction(
  transaction: TransactionSql,
  functionName: FederationFunction,
  request: JsonObject,
): Promise<JsonObject | null> {
  const [row] = await transaction<{ response: JsonObject | null }[]>`
    SELECT ${transaction(`app.${functionName}`)}(
      ${transaction.json(request)}::jsonb
    ) AS response
  `;
  assert(row, `${functionName} returned no row`);
  return row.response;
}

async function listProvidersInTransaction(
  transaction: TransactionSql,
): Promise<JsonObject[]> {
  const [row] = await transaction<{ response: JsonValue }[]>`
    SELECT app.list_tenant_federated_auth_providers_v1(
      ${transaction.json({ after: null, limit: 100, includeArchived: false })}::jsonb
    ) AS response
  `;
  return arrayValue(row?.response, "tenant federation provider list").map(
    (provider) => objectValue(provider, "listed tenant federation provider"),
  );
}

async function assertNotReadyCannotEnable(
  providerId: string,
  updateRequest: JsonObject,
  mutateTrustMaterial: (transaction: TransactionSql) => Promise<void>,
): Promise<void> {
  const rollbackProbe = new Error(
    "rollback tenant federation unready enable probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await mutateTrustMaterial(transaction);
      await setAPIContext(transaction);
      const [projection] = await transaction<{ response: JsonObject }[]>`
        SELECT app.get_tenant_federated_auth_provider_v1(
          ${transaction.json({ providerId })}::jsonb
        ) AS response
      `;
      assert.equal(
        projection?.response.configured,
        false,
        "unready tenant federation material remained configured",
      );
      try {
        await transaction`
          SELECT app.update_tenant_federated_auth_provider_v1(
            ${transaction.json(updateRequest)}::jsonb
          )
        `;
      } catch (error: unknown) {
        assertSqlState(error, "55000");
        throw rollbackProbe;
      }
      assert.fail("an unready tenant federation provider was enabled");
    }),
    (error: unknown) => error === rollbackProbe,
  );
}

async function assertTenantFederationRetainedKeyRequired(
  isolateMaterial?: (transaction: TransactionSql) => Promise<void>,
): Promise<void> {
  const verifierOne = Buffer.alloc(32, 0x71);
  const verifierTwo = Buffer.alloc(32, 0x72);
  const rollbackProbe = new Error(
    "rollback tenant federation retained-key readiness probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await rotateActiveIdentityKeyRetainingPreviousVersion(transaction);
      if (isolateMaterial !== undefined) {
        await isolateMaterial(transaction);
      }
      const [omitted] = await transaction<{ verified: boolean }[]>`
        SELECT app.verify_identity_keyring_v3(
          ARRAY[2]::integer[], ARRAY[${verifierTwo}::bytea], 2
        ) AS verified
      `;
      assert.equal(
        omitted?.verified,
        false,
        "readiness accepted an omitted live tenant federation key version",
      );
      const [retained] = await transaction<{ verified: boolean }[]>`
        SELECT app.verify_identity_keyring_v3(
          ARRAY[1, 2]::integer[],
          ARRAY[${verifierOne}::bytea, ${verifierTwo}::bytea],
          2
        ) AS verified
      `;
      assert.equal(
        retained?.verified,
        true,
        "readiness rejected the complete tenant federation retained-key set",
      );
      throw rollbackProbe;
    }),
    (error: unknown) => error === rollbackProbe,
  );
}

async function rotateActiveIdentityKeyRetainingPreviousVersion(
  transaction: TransactionSql,
): Promise<void> {
  const verifierTwo = Buffer.alloc(32, 0x72);
  await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
  await transaction`
    UPDATE public.identity_keyring_versions
    SET is_active = false
    WHERE key_version = 1
  `;
  await transaction`
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, is_active
    ) VALUES (2, ${verifierTwo}, true)
  `;
  const versions = await transaction<
    { is_active: boolean; key_version: number; retired_at: Date | null }[]
  >`
    SELECT key_version, is_active, retired_at
    FROM public.identity_keyring_versions
    WHERE key_version IN (1, 2)
    ORDER BY key_version
  `;
  assert.deepEqual(
    Array.from(versions, (version) => ({ ...version })),
    [
      { key_version: 1, is_active: false, retired_at: null },
      { key_version: 2, is_active: true, retired_at: null },
    ],
  );
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("base64");
}

function authenticationBeginLookup(
  operationRunId: string,
  loginKey: string,
): JsonObject {
  return {
    begin: {
      operationRunId,
      receiptDigest: digest(`${loginKey}:retained-key:receipt`),
      networkDigest: digest(`${loginKey}:retained-key:network`),
      accountDigest: digest(`${loginKey}:retained-key:account`),
      providerDigest: digest(`${loginKey}:retained-key:provider`),
    },
    tenantSlug: "federation-admin-runtime",
    loginKey,
  };
}

function objectValue(
  value: JsonValue | undefined,
  description: string,
): JsonObject {
  assert(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${description} must be an object`,
  );
  return value;
}

function arrayValue(
  value: JsonValue | undefined,
  description: string,
): JsonValue[] {
  assert(Array.isArray(value), `${description} must be an array`);
  return value;
}

function audit(suffix: string): JsonObject {
  return {
    requestId: `01a09e00-1000-7000-8000-00000000${suffix.padStart(4, "0")}`,
    correlationId: "01a09e00-1000-7000-8000-000000000401",
    remoteAddress: "192.0.2.81",
    userAgent: "Periapsis tenant federation administration runtime",
    authenticationMethod: "totp",
  };
}

function mutationEnvelope(
  membershipId: string,
  suffix: string,
): { audit: JsonObject; membershipId: string; occurredAt: string } {
  return { audit: audit(suffix), membershipId, occurredAt: now.toISOString() };
}

const oidcIssuer = "https://idp.example.invalid/realms/tenant";
const oidc: JsonObject = {
  issuer: oidcIssuer,
  clientId: "tenant-federation-runtime",
  postLogoutRedirectUri: "https://soc.example.invalid/signed-out",
  extraScopes: ["email", "offline_access", "profile", "roles"],
  allowRefreshToken: true,
  useUserInfo: false,
};

const createRequest: JsonObject = {
  ...mutationEnvelope(fixture.adminMembership, "0402"),
  commandId: fixture.command,
  providerId: fixture.provider,
  bindingId: fixture.binding,
  idempotencyDigest: digest("tenant-federation-administration-idempotency"),
  requestDigest: digest("tenant-federation-administration-semantic-request"),
  kind: "oidc",
  key: "runtime_oidc",
  loginKey: "runtime-oidc",
  displayName: "Runtime OIDC",
  description: "Tenant federation administration runtime proof.",
  jitMode: "create",
  noMatchPolicy: "deny",
  oidc,
  saml: null,
  oidcRedirectUri:
    "https://soc.example.invalid/api/v1/auth/federated/oidc/callback",
  samlAcsUrl: "https://soc.example.invalid/api/v1/auth/federated/saml/acs",
  samlSpMetadataBaseUrl:
    "https://soc.example.invalid/api/v1/auth/federated/saml",
  reason: "create the runtime proof provider",
};

const oidcClaimRules: JsonValue[] = [
  {
    source: "id_token",
    kind: "profile",
    claimName: "preferred_username",
    profileField: "username",
    required: true,
  },
  {
    source: "id_token",
    kind: "scalar",
    claimName: "roles",
    profileField: null,
    required: false,
  },
  {
    source: "id_token",
    kind: "amr",
    claimName: "amr",
    profileField: null,
    required: false,
  },
];

try {
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, 'federation-admin-runtime', 'Federation administration runtime'),
        (${fixture.foreignTenant}::uuid, 'federation-admin-foreign', 'Federation administration foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES
        (${fixture.adminUser}::uuid, 'federation-admin@example.invalid', 'Federation admin'),
        (${fixture.scopedUser}::uuid, 'federation-scoped@example.invalid', 'Federation scoped manager'),
        (${fixture.foreignUser}::uuid, 'federation-foreign@example.invalid', 'Federation foreign admin'),
        (${fixture.sessionUser}::uuid, 'federation-session@example.invalid', 'Federated session user')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.scopedMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.scopedUser}::uuid, 'read_only', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.sessionMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.sessionUser}::uuid, 'read_only', 'active')
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id, user_id, webauthn_user_handle, identity_epoch,
        session_invalidation_epoch, version, created_at, updated_at
      ) VALUES (${fixture.tenant}::uuid, ${fixture.sessionUser}::uuid,
        ${Buffer.alloc(32, 0x73)}::bytea, 1, 1, 1, ${now}, ${now})
    `;
    await transaction`SELECT app.seed_tenant_authorization(${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid)`;
    await transaction`SELECT app.seed_tenant_authorization(${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid)`;
    await transaction`
      INSERT INTO public.identity_keyring_versions (key_version, verifier, is_active)
      VALUES (1, decode(repeat('71', 32), 'hex'), true)
    `;
    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES
        (${fixture.scopedRole}::uuid, ${fixture.tenant}::uuid, 'federation_policy_manager', 'Federation policy manager', 'Exact authority proof.', ${fixture.adminMembership}::uuid),
        (${fixture.targetRole}::uuid, ${fixture.tenant}::uuid, 'federation_mapped_role', 'Federation mapped role', 'Permission-free mapping target.', ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES (${fixture.securityGroup}::uuid, ${fixture.tenant}::uuid,
        'federation_runtime_group', 'Federation runtime group', 'Mapping target proof.', ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES (${fixture.operatorTeam}::uuid, 'federation_runtime_team',
        'Federation runtime team', 'Exact tenant relationship proof.', ${fixture.adminUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id, assignment_reason
      ) VALUES (${fixture.assignmentEpoch}::uuid, ${fixture.tenant}::uuid,
        ${fixture.operatorTeam}::uuid, ${fixture.adminMembership}::uuid, 'Federation mapping proof.')
    `;
    const [manual] = await transaction<{ id: string }[]>`
      SELECT id FROM public.tenant_authorization_sources
      WHERE tenant_id = ${fixture.tenant}::uuid AND kind = 'manual' AND key = 'manual'
    `;
    assert(manual, "manual authorization source is missing");
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (${fixture.scopedRoleGrant}::uuid, ${fixture.tenant}::uuid,
        ${fixture.scopedMembership}::uuid, ${fixture.scopedRole}::uuid,
        ${manual.id}::uuid, ${fixture.adminMembership}::uuid, 'Federation policy authority proof.')
    `;
  });

  await assert.rejects(
    sql.begin(async (transaction) => {
      await setAPIContext(transaction);
      await transaction`SELECT ciphertext FROM public.tenant_oidc_client_secrets`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const created = await call(
    "create_tenant_federated_auth_provider_v1",
    createRequest,
  );
  assert.equal(created.replayed, false);
  assert.equal(
    objectValue(created.provider, "created provider").tenantId,
    fixture.tenant,
  );
  assert.equal(
    objectValue(created.provider, "created provider").configured,
    false,
  );

  const replayed = await call("create_tenant_federated_auth_provider_v1", {
    ...createRequest,
    ...mutationEnvelope(fixture.adminMembership, "0403"),
    commandId: fixture.replayCommand,
    providerId: fixture.replayProvider,
    bindingId: fixture.replayBinding,
  });
  assert.equal(replayed.replayed, true);
  assert.equal(
    objectValue(replayed.provider, "replayed provider").id,
    fixture.provider,
  );
  await assert.rejects(
    call("create_tenant_federated_auth_provider_v1", {
      ...createRequest,
      ...mutationEnvelope(fixture.adminMembership, "0404"),
      commandId: fixture.replayCommand,
      providerId: fixture.replayProvider,
      bindingId: fixture.replayBinding,
      requestDigest: digest("different semantic request"),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  await assert.rejects(
    call(
      "get_tenant_federated_auth_provider_v1",
      { providerId: fixture.provider },
      fixture.foreignTenant,
      fixture.foreignUser,
    ),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const updateBase: JsonObject = {
    ...mutationEnvelope(fixture.adminMembership, "0405"),
    providerId: fixture.provider,
    expectedVersion: 1,
    displayName: "Runtime OIDC",
    description: "Tenant federation administration runtime proof.",
    enabled: true,
    jitMode: "create",
    noMatchPolicy: "deny",
    oidc,
    saml: null,
    oidcRedirectUri:
      "https://soc.example.invalid/api/v1/auth/federated/oidc/callback",
    samlAcsUrl: "https://soc.example.invalid/api/v1/auth/federated/saml/acs",
    samlSpMetadataBaseUrl:
      "https://soc.example.invalid/api/v1/auth/federated/saml",
    reason: "enable after readiness",
  };
  await assert.rejects(
    call("update_tenant_federated_auth_provider_v1", updateBase),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const secretPreparation = await call("prepare_tenant_oidc_client_secret_v1", {
    membershipId: fixture.adminMembership,
    providerId: fixture.provider,
    expectedVersion: 1,
  });
  assert.equal(secretPreparation.tenantId, fixture.tenant);
  assert.equal(secretPreparation.nextSecretRevision, 2);
  await call("replace_tenant_oidc_client_secret_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0406"),
    providerId: fixture.provider,
    bindingId: fixture.binding,
    expectedVersion: 1,
    expectedRevision: 2,
    secretId: fixture.secret,
    keyVersion: 1,
    nonce: Buffer.alloc(12, 0x72).toString("base64"),
    ciphertext: Buffer.alloc(32, 0x73).toString("base64"),
    reason: "install encrypted OIDC client secret",
  });

  const trustPreparation = await call(
    "prepare_tenant_oidc_trust_documents_v1",
    {
      membershipId: fixture.adminMembership,
      providerId: fixture.provider,
      expectedVersion: 2,
    },
  );
  assert.equal(trustPreparation.nextDiscoveryRevision, 2);
  assert.equal(trustPreparation.nextJwksRevision, 2);
  const discoveryDocument = Buffer.from(
    JSON.stringify({
      issuer: oidcIssuer,
      authorization_endpoint: `${oidcIssuer}/authorize`,
      token_endpoint: `${oidcIssuer}/token`,
      jwks_uri: `${oidcIssuer}/jwks`,
      revocation_endpoint: `${oidcIssuer}/revoke`,
      end_session_endpoint: `${oidcIssuer}/logout`,
    }),
    "utf8",
  );
  const jwksDocument = Buffer.from('{"keys":[]}', "utf8");
  const trustCommitRequest: JsonObject = {
    ...mutationEnvelope(fixture.adminMembership, "0407"),
    providerId: fixture.provider,
    expectedVersion: 2,
    issuer: oidcIssuer,
    discoveryRevision: 2,
    jwksRevision: 2,
    discoveryDocument: discoveryDocument.toString("base64"),
    discoveryDigest: createHash("sha256")
      .update(discoveryDocument)
      .digest("base64"),
    discoveryCache: {
      retrievedAt: now.toISOString(),
      freshUntil: later.toISOString(),
      cacheable: true,
      mustRevalidate: false,
    },
    jwksDocument: jwksDocument.toString("base64"),
    jwksDigest: createHash("sha256").update(jwksDocument).digest("base64"),
    jwksCache: {
      retrievedAt: now.toISOString(),
      freshUntil: later.toISOString(),
      cacheable: true,
      mustRevalidate: false,
    },
    clientAuthentication: "client_secret_basic",
    signingAlgorithms: ["RS256"],
    keyCount: 1,
    reason: "pin validated OIDC public trust documents",
  };
  await assert.rejects(
    call("commit_tenant_oidc_trust_documents_v1", {
      ...trustCommitRequest,
      keyCount: 33,
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await call("commit_tenant_oidc_trust_documents_v1", trustCommitRequest);
  await assertTenantFederationRetainedKeyRequired();

  const mappingRequest = (
    membershipId: string,
    suffix: string,
  ): JsonObject => ({
    ...mutationEnvelope(membershipId, suffix),
    providerId: fixture.provider,
    expectedVersion: 3,
    kind: "oidc",
    oidcClaimRules,
    samlAttributeRules: [],
    rules: [
      {
        ruleId: fixture.mappingRule,
        priority: 10,
        matcherKind: "scalar_equals",
        claimName: "roles",
        matcherValue: "incident_manager",
        reconciliationMode: "authoritative",
        tenantSecurityGroupId: fixture.securityGroup,
        roleIds: [fixture.targetRole],
        operatorTeamId: fixture.operatorTeam,
        operatorTeamAssignmentEpochId: fixture.assignmentEpoch,
        enabled: true,
      },
    ],
    reason: "replace exact OIDC role mapping",
  });

  await assert.rejects(
    call(
      "replace_tenant_federated_mapping_policy_v1",
      mappingRequest(fixture.scopedMembership, "0408"),
      fixture.tenant,
      fixture.scopedUser,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      ) SELECT ${fixture.tenant}::uuid, ${fixture.scopedRole}::uuid,
          permission.id, 'tenant'::public.authorization_scope, ${fixture.adminMembership}::uuid
        FROM public.tenant_permissions AS permission
        WHERE permission.key = 'identity_mapping.manage'
    `;
  });
  await assert.rejects(
    call(
      "replace_tenant_federated_mapping_policy_v1",
      mappingRequest(fixture.scopedMembership, "0409"),
      fixture.tenant,
      fixture.scopedUser,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      ) SELECT ${fixture.tenant}::uuid, ${fixture.scopedRole}::uuid,
          permission.id, 'tenant'::public.authorization_scope, ${fixture.adminMembership}::uuid
        FROM public.tenant_permissions AS permission
        WHERE permission.key = 'role.grant'
    `;
  });
  await assert.rejects(
    call(
      "replace_tenant_federated_mapping_policy_v1",
      mappingRequest(fixture.scopedMembership, "0410"),
      fixture.tenant,
      fixture.scopedUser,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      ) SELECT ${fixture.tenant}::uuid, ${fixture.scopedRole}::uuid,
          permission.id, 'operator_team'::public.authorization_scope, ${fixture.adminMembership}::uuid
        FROM public.tenant_permissions AS permission
        WHERE permission.key = 'operator_team.roster.manage'
    `;
  });
  await assert.rejects(
    call(
      "replace_tenant_federated_mapping_policy_v1",
      mappingRequest(fixture.scopedMembership, "0411"),
      fixture.tenant,
      fixture.scopedUser,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    const [manual] = await transaction<{ id: string }[]>`
      SELECT id FROM public.tenant_authorization_sources
      WHERE tenant_id = ${fixture.tenant}::uuid AND kind = 'manual' AND key = 'manual'
    `;
    assert(manual);
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (${fixture.rosterEntry}::uuid, ${fixture.tenant}::uuid,
        ${fixture.assignmentEpoch}::uuid, ${fixture.scopedMembership}::uuid,
        ${manual.id}::uuid, ${fixture.adminMembership}::uuid, 'Exact federation relationship proof.')
    `;
  });

  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_federated_provider_policies
      SET enabled = true, updated_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid AND provider_id = ${fixture.provider}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identities (
        id, tenant_id, provider_id, binding_id, user_id, subject_format,
        subject_ciphertext, subject_nonce, key_version,
        admitted_configuration_revision, last_observed_at, version,
        created_at, updated_at
      ) VALUES (${fixture.externalIdentity}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.binding}::uuid, ${fixture.sessionUser}::uuid,
        'utf8_exact', ${Buffer.alloc(32, 0x74)}::bytea,
        ${Buffer.alloc(12, 0x75)}::bytea, 1, 3, ${now}, 1, ${now}, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, last_seen_at,
        idle_expires_at, absolute_expires_at, created_at
      ) VALUES (${fixture.session}::uuid, ${fixture.sessionUser}::uuid,
        ${fixture.sessionFamily}::uuid, ${fixture.tenant}::uuid,
        ${Buffer.alloc(32, 0x76)}::bytea, ${Buffer.alloc(32, 0x77)}::bytea,
        'oidc', ${now}, ${later}, ${later}, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id, tenant_id, user_id, session_version, identity_epoch,
        recovery_restricted, audience, primary_kind, session_invalidation_epoch, issued_at
      ) VALUES (${fixture.session}::uuid, ${fixture.tenant}::uuid,
        ${fixture.sessionUser}::uuid, 1, 1, false, 'api', 'tenant_provider', 1, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id, session_id, user_id, primary_kind, authentication_method,
        provider_id, binding_id, provider_kind, external_identity_id,
        external_identity_revision, trust_rule_revision, authenticated_at
      ) VALUES (${fixture.tenant}::uuid, ${fixture.session}::uuid,
        ${fixture.sessionUser}::uuid, 'tenant_provider', 'oidc',
        ${fixture.provider}::uuid, ${fixture.binding}::uuid, 'oidc',
        ${fixture.externalIdentity}::uuid, 1, 3, ${now})
    `;
  });

  const mappingReceipt = await call(
    "replace_tenant_federated_mapping_policy_v1",
    mappingRequest(fixture.scopedMembership, "0412"),
    fixture.tenant,
    fixture.scopedUser,
  );
  assert.equal(mappingReceipt.providerVersion, 4);
  assert.equal(mappingReceipt.mappingRevision, 2);
  const [revoked] = await sql<{ revoked_at: Date | null }[]>`
    SELECT revoked_at FROM public.auth_sessions WHERE id = ${fixture.session}::uuid
  `;
  assert(
    revoked?.revoked_at,
    "mapping replacement did not revoke a federated session",
  );

  await assert.rejects(
    call("replace_tenant_federated_mapping_policy_v1", {
      ...mappingRequest(fixture.adminMembership, "0413"),
      expectedVersion: 3,
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const assuranceReceipt = await call(
    "replace_tenant_federated_assurance_policy_v1",
    {
      ...mutationEnvelope(fixture.adminMembership, "0414"),
      providerId: fixture.provider,
      expectedVersion: 4,
      kind: "oidc",
      rules: [
        {
          ruleId: fixture.trustRule,
          enabled: true,
          level: "mfa",
          exactValue: null,
          requiredValues: ["otp", "pwd"],
          maximumAuthenticationAgeSeconds: 3600,
        },
      ],
      reason: "trust exact upstream MFA evidence",
    },
  );
  assert.equal(assuranceReceipt.providerVersion, 5);
  assert.equal(assuranceReceipt.assurancePolicyRevision, 2);

  const mapping = await call("get_tenant_federated_mapping_policy_v1", {
    providerId: fixture.provider,
  });
  const assurance = await call("get_tenant_federated_assurance_policy_v1", {
    providerId: fixture.provider,
  });
  assert.equal(mapping.tenantId, fixture.tenant);
  assert.equal(mapping.providerId, fixture.provider);
  assert.equal(arrayValue(mapping.rules, "mapping rules").length, 1);
  assert.equal(assurance.tenantId, fixture.tenant);
  assert.equal(arrayValue(assurance.rules, "assurance rules").length, 1);
  for (const projection of [mapping, assurance]) {
    const serialized = JSON.stringify(projection).toLowerCase();
    assert(!serialized.includes("document"));
    assert(!serialized.includes("ciphertext"));
    assert(!serialized.includes("secret"));
  }

  const zeroMapping = await call("replace_tenant_federated_mapping_policy_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0415"),
    providerId: fixture.provider,
    expectedVersion: 5,
    kind: "oidc",
    oidcClaimRules,
    samlAttributeRules: [],
    rules: [],
    reason: "revoke every mapping-derived role",
  });
  assert.equal(zeroMapping.providerVersion, 6);
  const zeroReadback = await call("get_tenant_federated_mapping_policy_v1", {
    providerId: fixture.provider,
  });
  assert.deepEqual(zeroReadback.rules, []);
  const [openEpochs] = await sql<{ count: string }[]>`
    SELECT count(*)::text AS count
    FROM public.tenant_federated_mapping_rule_epochs
    WHERE tenant_id = ${fixture.tenant}::uuid AND provider_id = ${fixture.provider}::uuid
      AND ended_at IS NULL
  `;
  assert.equal(openEpochs?.count, "0");

  await assertNotReadyCannotEnable(
    fixture.provider,
    {
      ...updateBase,
      ...mutationEnvelope(fixture.adminMembership, "0601"),
      expectedVersion: 6,
      jitMode: "disabled",
      reason: "reject OIDC enable with stale discovery metadata",
    },
    async (transaction) => {
      await transaction`
        UPDATE public.tenant_oidc_discovery_snapshots
        SET retrieved_at = statement_timestamp() - interval '2 hours',
            fresh_until = statement_timestamp() - interval '1 hour'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND revision = 2
      `;
    },
  );
  await assertNotReadyCannotEnable(
    fixture.provider,
    {
      ...updateBase,
      ...mutationEnvelope(fixture.adminMembership, "0602"),
      expectedVersion: 6,
      jitMode: "disabled",
      reason: "reject OIDC enable with stale JWKS metadata",
    },
    async (transaction) => {
      await transaction`
        UPDATE public.tenant_oidc_jwks_snapshots
        SET retrieved_at = statement_timestamp() - interval '2 hours',
            fresh_until = statement_timestamp() - interval '1 hour'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND revision = 2
      `;
    },
  );
  await assertNotReadyCannotEnable(
    fixture.provider,
    {
      ...updateBase,
      ...mutationEnvelope(fixture.adminMembership, "0603"),
      expectedVersion: 6,
      jitMode: "disabled",
      reason: "reject OIDC enable with a retired envelope key",
    },
    async (transaction) => {
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = false, retired_at = statement_timestamp()
        WHERE key_version = 1
      `;
    },
  );

  const enabled = await call("update_tenant_federated_auth_provider_v1", {
    ...updateBase,
    ...mutationEnvelope(fixture.adminMembership, "0416"),
    expectedVersion: 6,
    jitMode: "disabled",
  });
  assert.equal(enabled.enabled, true);
  assert.equal(objectValue(enabled.binding, "enabled binding").enabled, true);
  assert.equal(enabled.configured, true);

  const oidcBeginLookup = authenticationBeginLookup(
    fixture.begin,
    "runtime-oidc",
  );
  const oidcProviderIdentity: JsonObject = {
    scope: "tenant",
    tenantId: fixture.tenant,
    providerId: fixture.provider,
    bindingId: fixture.binding,
  };
  const oidcSecretLookup: JsonObject = {
    provider: oidcProviderIdentity,
    revision: 2,
  };
  const oidcRuntimeBeforeRotation = await call(
    "begin_tenant_oidc_authentication_v1",
    oidcBeginLookup,
  );
  const oidcSecretBeforeRotation = await call(
    "load_oidc_client_secret_envelope_v1",
    oidcSecretLookup,
  );
  assert.equal(oidcSecretBeforeRotation.keyVersion, 1);

  const cleanupObservedAt = new Date();
  const accessExpiry = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    const [row] = await transaction<
      { response: JsonObject; transactionId: string }[]
    >`
      SELECT txid_current()::text AS "transactionId",
        app.expire_oidc_access_lease_v1(
          ${transaction.json({
            kind: "access_expiry",
            observedAt: cleanupObservedAt.toISOString(),
          })}::jsonb
        ) AS response
    `;
    assert(row, "access-expiry phase returned no receipt");
    assert.equal(row.response.kind, "access_expiry");
    assert.equal(typeof row.response.expired, "boolean");
    return row;
  });
  const runFederatedCleanup = async (
    kind: "consumed_refresh" | "logout_continuation" | "saml_material",
  ): Promise<{ response: JsonObject; transactionId: string }> =>
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      const [row] = await transaction<
        { response: JsonObject; transactionId: string }[]
      >`
        SELECT txid_current()::text AS "transactionId",
          app.cleanup_federated_maintenance_retention_v1(
            ${transaction.json({
              kind,
              observedAt: cleanupObservedAt.toISOString(),
            })}::jsonb
          ) AS response
      `;
      assert(row, `${kind} cleanup returned no receipt`);
      assert.equal(row.response.kind, kind);
      return row;
    });
  const continuationCleanup = await runFederatedCleanup("logout_continuation");
  const consumedCleanup = await runFederatedCleanup("consumed_refresh");
  const samlCleanup = await runFederatedCleanup("saml_material");
  let claimTransactionId = "";
  const rollbackSeparatedClaim = new Error(
    "rollback separate federated maintenance claim",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      const [row] = await transaction<
        { response: JsonObject | null; transactionId: string }[]
      >`
        SELECT txid_current()::text AS "transactionId",
          app.claim_due_oidc_maintenance_v1(
            ${transaction.json({
              kind: "logout_retry",
              observedAt: cleanupObservedAt.toISOString(),
            })}::jsonb
          ) AS response
      `;
      assert(row, "separated OIDC maintenance claim returned no row");
      claimTransactionId = row.transactionId;
      throw rollbackSeparatedClaim;
    }),
    (error: unknown) => error === rollbackSeparatedClaim,
  );
  assert.equal(
    new Set([
      accessExpiry.transactionId,
      continuationCleanup.transactionId,
      consumedCleanup.transactionId,
      samlCleanup.transactionId,
      claimTransactionId,
    ]).size,
    5,
    "access expiry, cleanup classes, and claim must use five independent transactions",
  );

  const rollbackOIDCLifecycle = new Error(
    "rollback OIDC session lifecycle runtime proof",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [lifecycleClock] = await transaction<{ value: Date }[]>`
        SELECT date_trunc('milliseconds', transaction_timestamp())
                 - interval '1 second' AS value
      `;
      assert(lifecycleClock, "OIDC lifecycle fixture clock returned no row");
      const lifecycleNow = lifecycleClock.value;
      const authenticationExpiresAt = new Date(
        lifecycleNow.getTime() + 10 * 60_000,
      );
      const refreshClaimedAt = new Date(lifecycleNow.getTime() + 1_000);
      const refreshCompletedAt = new Date(lifecycleNow.getTime() + 2_000);
      const logoutRequestedAt = new Date(lifecycleNow.getTime() + 3_000);
      const continuationClaimedAt = new Date(lifecycleNow.getTime() + 4_000);
      const retryClaimedAt = new Date(lifecycleNow.getTime() + 5_000);
      const retryReclaimedAt = new Date(retryClaimedAt.getTime() + 120_000);
      const retryTerminalAt = new Date(retryReclaimedAt.getTime() + 120_000);
      const scrubbedAt = new Date(retryTerminalAt.getTime() + 1_000);
      const f55ClaimedAt = new Date(lifecycleNow.getTime() + 30_000);
      const f55LiveLeasePollAt = new Date(lifecycleNow.getTime() + 50_000);
      const f55CompletedAt = new Date(lifecycleNow.getTime() + 51_000);
      const f55SecondClaimedAt = new Date(lifecycleNow.getTime() + 70_000);
      const f55SuccessorAccessExpiresAt = new Date(
        lifecycleNow.getTime() + 80_000,
      );
      const f55ExpiredLeasePollAt = new Date(
        f55SecondClaimedAt.getTime() + 121_000,
      );
      const f55OldCompletionAt = new Date(
        f55ExpiredLeasePollAt.getTime() + 1_000,
      );
      const continuationExpiresAt = new Date(
        logoutRequestedAt.getTime() + 90_000,
      );
      const accessExpiresAt = new Date(lifecycleNow.getTime() + 10 * 60_000);
      const sessionTokenDigest = Buffer.alloc(32, 0x87);
      const sessionCsrfDigest = Buffer.alloc(32, 0x88);
      const refreshDigestOne = Buffer.alloc(32, 0x81);
      const refreshDigestTwo = Buffer.alloc(32, 0x82);
      const refreshDigestThree = Buffer.alloc(32, 0x8c);
      const idTokenDigest = Buffer.alloc(32, 0x80);
      const continuationDigest = Buffer.alloc(32, 0x89);
      const idEnvelope = Buffer.alloc(48, 0x83);
      const refreshEnvelopeOne = Buffer.alloc(48, 0x84);
      const refreshEnvelopeTwo = Buffer.alloc(48, 0x85);
      const refreshEnvelopeThree = Buffer.alloc(48, 0x8d);

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.tenant_federated_authentication_transactions (
          transaction_id,tenant_id,provider_id,binding_id,provider_kind,
          protocol,operation_run_id,operation_digest,receipt_digest,
          network_digest,account_digest,provider_digest,state_digest,
          browser_digest,nonce_digest,provider_revision,binding_revision,
          configuration_revision,security_revision,plan_revision,
          mapping_revision,authorization_revision,assurance_policy_revision,
          client_secret_revision,discovery_revision,discovery_digest,
          jwks_revision,jwks_digest,verifier_key_version,verifier_ciphertext,
          client_id,redirect_uri,post_logout_redirect_uri,scopes,
          allow_refresh_token,use_user_info,return_path,state,version,
          claim_attempt_id,created_at,expires_at,claimed_at,completed_at
        ) VALUES (
          ${Buffer.alloc(32, 0x7a)}::bytea,${fixture.tenant}::uuid,
          ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc','oidc',
          ${fixture.begin}::uuid,${Buffer.alloc(32, 0x7b)}::bytea,
          ${Buffer.alloc(32, 0x7c)}::bytea,${Buffer.alloc(32, 0x7d)}::bytea,
          ${Buffer.alloc(32, 0x7e)}::bytea,${Buffer.alloc(32, 0x7f)}::bytea,
          ${Buffer.alloc(32, 0x70)}::bytea,${Buffer.alloc(32, 0x71)}::bytea,
          ${Buffer.alloc(32, 0x72)}::bytea,1,1,1,1,1,1,1,1,2,1,
          ${Buffer.alloc(32, 0x73)}::bytea,1,${Buffer.alloc(32, 0x74)}::bytea,
          1,${Buffer.alloc(32, 0x75)}::bytea,'tenant-federation-runtime',
          'https://soc.example.invalid/api/v1/auth/federated/oidc/callback',
          'https://soc.example.invalid/signed-out',
          ARRAY['openid','email','offline_access','profile','roles']::text[],
          true,false,'/portal','completed',3,
          ${Buffer.alloc(32, 0x86)}::bytea,${lifecycleNow},
          ${authenticationExpiresAt},${lifecycleNow},${lifecycleNow}
        )
      `;
      await transaction`
        INSERT INTO public.auth_sessions (
          id,user_id,rotation_family_id,active_tenant_id,token_digest,
          csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
          idle_expires_at,absolute_expires_at,created_at
        ) VALUES (
          ${fixture.oidcLifecycleSession}::uuid,${fixture.sessionUser}::uuid,
          ${fixture.oidcLifecycleFamily}::uuid,${fixture.tenant}::uuid,
          ${sessionTokenDigest}::bytea,${sessionCsrfDigest}::bytea,
          'oidc',${lifecycleNow},${lifecycleNow},${later},${later},${lifecycleNow}
        )
      `;
      await transaction`
        INSERT INTO public.auth_session_mfa_states (
          session_id,tenant_id,user_id,session_version,identity_epoch,
          recovery_restricted,audience,primary_kind,
          session_invalidation_epoch,issued_at
        ) VALUES (
          ${fixture.oidcLifecycleSession}::uuid,${fixture.tenant}::uuid,
          ${fixture.sessionUser}::uuid,1,1,false,'api','tenant_provider',1,
          ${lifecycleNow}
        )
      `;
      await transaction`
        INSERT INTO public.auth_session_federated_provenance (
          tenant_id,session_id,user_id,primary_kind,authentication_method,
          provider_id,binding_id,provider_kind,external_identity_id,
          external_identity_revision,trust_rule_revision,authenticated_at
        ) VALUES (
          ${fixture.tenant}::uuid,${fixture.oidcLifecycleSession}::uuid,
          ${fixture.sessionUser}::uuid,'tenant_provider','oidc',
          ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc',
          ${fixture.externalIdentity}::uuid,1,3,${lifecycleNow}
        )
      `;
      await transaction`
        INSERT INTO public.tenant_federated_authentication_applications (
          id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
          binding_id,provider_kind,category,primary_kind,user_id,session_id,
          request_snapshot,result_snapshot,applied_at
        ) SELECT
          ${fixture.oidcLifecycleApplication}::uuid,transaction.tenant_id,'oidc',
          transaction.transaction_id,${Buffer.alloc(32, 0x8a)}::bytea,
          transaction.provider_id,transaction.binding_id,transaction.provider_kind,
          'success','tenant_provider',${fixture.sessionUser}::uuid,
          ${fixture.oidcLifecycleSession}::uuid,
          ${transaction.json({
            authentication: { validUntil: later.toISOString() },
          })}::jsonb,
          ${transaction.json({ category: "success" })}::jsonb,${lifecycleNow}
        FROM public.tenant_federated_authentication_transactions AS transaction
        WHERE transaction.tenant_id = ${fixture.tenant}::uuid
          AND transaction.operation_run_id = ${fixture.begin}::uuid
          AND transaction.protocol = 'oidc'
      `;
      await transaction`
        INSERT INTO public.tenant_oidc_session_materials (
          id,tenant_id,authority,session_id,rotation_family_id,user_id,provider_id,
          binding_id,provider_kind,external_identity_id,aad_version,
          id_token_key_version,id_token_ciphertext,id_token_digest,
          refresh_token_key_version,refresh_token_ciphertext,refresh_token_digest,refresh_generation,
          refresh_state,refresh_version,access_expires_at,
          expires_at,
          client_secret_revision,client_authentication,client_id,token_endpoint,
          revocation_endpoint,end_session_endpoint,post_logout_redirect_uri,
          logout_disposition,created_at,updated_at
        ) VALUES (
          ${fixture.begin}::uuid,${fixture.tenant}::uuid,'tenant_provider',
          ${fixture.oidcLifecycleSession}::uuid,
          ${fixture.oidcLifecycleFamily}::uuid,${fixture.sessionUser}::uuid,
          ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc',
          ${fixture.externalIdentity}::uuid,1,1,${idEnvelope}::bytea,
          ${idTokenDigest}::bytea,1,
          ${refreshEnvelopeOne}::bytea,${refreshDigestOne}::bytea,1,'ready',1,
          ${accessExpiresAt},${later},2,'client_secret_basic','tenant-federation-runtime',
          ${`${oidcIssuer}/token`},${`${oidcIssuer}/revoke`},
          ${`${oidcIssuer}/logout`},'https://soc.example.invalid/signed-out',
          'available',${lifecycleNow},${lifecycleNow}
        )
      `;
      await transaction`
        UPDATE public.tenant_federated_provider_policies
        SET enabled = false,updated_at = transaction_timestamp()
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND binding_id = ${fixture.binding}::uuid
      `;
      await transaction`
        UPDATE public.tenant_oidc_client_secrets
        SET retired_at = transaction_timestamp()
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND revision = 2
      `;

      await setAPIContext(transaction, fixture.tenant, fixture.sessionUser);
      const [readiness] = await transaction<{ ready: boolean }[]>`
        SELECT app.tenant_oidc_session_lifecycle_schema_readiness_v1() AS ready
      `;
      assert.equal(readiness?.ready, true, "OIDC lifecycle readiness is false");
      const [acl] = await transaction<
        {
          api_refresh: boolean;
          api_secret: boolean;
          api_access_expiry: boolean;
          material_access: boolean;
          worker_continuation: boolean;
          worker_access_expiry: boolean;
          worker_refresh: boolean;
          worker_retry: boolean;
          worker_secret: boolean;
        }[]
      >`
        SELECT has_table_privilege(
          'periapsis_api','public.tenant_oidc_session_materials','SELECT,INSERT,UPDATE,DELETE'
        ) AS material_access,
        has_function_privilege(
          'periapsis_worker','app.claim_tenant_oidc_logout_retry_v1(jsonb)','EXECUTE'
        ) AS worker_retry,
        has_function_privilege(
          'periapsis_worker','app.claim_tenant_oidc_refresh_rotation_v1(jsonb)','EXECUTE'
        ) AS worker_refresh,
        has_function_privilege(
          'periapsis_api','app.claim_tenant_oidc_refresh_rotation_v1(jsonb)','EXECUTE'
        ) AS api_refresh,
        has_function_privilege(
          'periapsis_worker','app.expire_oidc_access_lease_v1(jsonb)','EXECUTE'
        ) AS worker_access_expiry,
        has_function_privilege(
          'periapsis_api','app.expire_oidc_access_lease_v1(jsonb)','EXECUTE'
        ) AS api_access_expiry,
        has_function_privilege(
          'periapsis_worker','app.claim_session_logout_continuation_v1(jsonb)','EXECUTE'
        ) AS worker_continuation,
        has_function_privilege(
          'periapsis_worker','app.load_oidc_maintenance_client_secret_envelope_v1(jsonb)','EXECUTE'
        ) AS worker_secret,
        has_function_privilege(
          'periapsis_api','app.load_oidc_maintenance_client_secret_envelope_v1(jsonb)','EXECUTE'
        ) AS api_secret
      `;
      assert.deepEqual(acl, {
        api_access_expiry: false,
        api_refresh: false,
        api_secret: false,
        material_access: false,
        worker_continuation: false,
        worker_access_expiry: true,
        worker_refresh: true,
        worker_retry: true,
        worker_secret: true,
      });

      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.sessionUser}, true)
      `;
      const secretLookup: JsonObject = {
        provider: {
          scope: "tenant",
          tenantId: fixture.tenant,
          providerId: fixture.provider,
          bindingId: fixture.binding,
        },
        bindingId: fixture.binding,
        revision: 2,
      };
      const [unclaimedSecret] = await transaction<
        {
          response: JsonObject | null;
        }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json({
            ...secretLookup,
            kind: "refresh",
            materialId: fixture.begin,
            sessionFamilyId: fixture.oidcLifecycleFamily,
            claimVersion: 1,
            refreshGeneration: 1,
          })}::jsonb
        ) AS response
      `;
      assert.equal(
        unclaimedSecret?.response,
        null,
        "maintenance secret loaded without a live claim proof",
      );
      const [randomMismatch] = await transaction<{ response: JsonObject }[]>`
        SELECT app.claim_tenant_oidc_refresh_rotation_v1(
          ${transaction.json({
            sessionFamilyId: fixture.oidcLifecycleFamily,
            expectedGeneration: 1,
            expectedDigest: Buffer.alloc(32, 0x8b).toString("base64"),
            claimedAt: refreshClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert.equal(randomMismatch?.response.category, "stale");

      const [claim] = await transaction<{ response: JsonObject }[]>`
        SELECT app.claim_tenant_oidc_refresh_rotation_v1(
          ${transaction.json({
            sessionFamilyId: fixture.oidcLifecycleFamily,
            expectedGeneration: 1,
            expectedDigest: refreshDigestOne.toString("base64"),
            claimedAt: refreshClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert(claim?.response, "OIDC refresh claim returned no snapshot");
      assert.equal(claim?.response.category, "claimed");
      assert.equal(claim?.response.tenantId, fixture.tenant);
      assert.equal(claim?.response.materialId, fixture.begin);
      const absoluteSessionExpiry = claim.response.absoluteSessionExpiry;
      assert.equal(typeof absoluteSessionExpiry, "string");
      if (typeof absoluteSessionExpiry !== "string") {
        assert.fail("OIDC refresh claim expiry is not a string");
      }
      assert.equal(
        new Date(absoluteSessionExpiry).toISOString(),
        later.toISOString(),
      );
      assert.equal(
        objectValue(claim?.response.token, "claimed refresh token").ciphertext,
        refreshEnvelopeOne.toString("base64"),
      );
      const refreshClaimVersion = claim.response.version;
      const refreshGeneration = claim.response.generation;
      assert.equal(typeof refreshClaimVersion, "number");
      assert.equal(typeof refreshGeneration, "number");
      if (
        typeof refreshClaimVersion !== "number" ||
        typeof refreshGeneration !== "number"
      ) {
        assert.fail("OIDC refresh claim proof counters are not numbers");
      }
      const refreshSecretLookup: JsonObject = {
        ...secretLookup,
        kind: "refresh",
        materialId: fixture.begin,
        sessionFamilyId: fixture.oidcLifecycleFamily,
        claimVersion: refreshClaimVersion,
        refreshGeneration,
      };
      const [maintenanceSecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(refreshSecretLookup)}::jsonb
        ) AS response
      `;
      assert(
        maintenanceSecret?.response,
        "pinned OIDC secret was not loadable for its live refresh claim",
      );
      assert.deepEqual(maintenanceSecret.response.lookup, refreshSecretLookup);
      assert.equal(maintenanceSecret.response.secretId, fixture.secret);
      assert.equal(maintenanceSecret.response.keyVersion, 1);
      assert.equal(
        maintenanceSecret.response.nonce,
        Buffer.alloc(12, 0x72).toString("base64"),
      );
      assert.equal(
        maintenanceSecret.response.ciphertext,
        Buffer.alloc(32, 0x73).toString("base64"),
      );
      const [substitutedClaimSecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json({
            ...refreshSecretLookup,
            claimVersion: refreshClaimVersion + 1,
          })}::jsonb
        ) AS response
      `;
      assert.equal(
        substitutedClaimSecret?.response,
        null,
        "maintenance secret ignored refresh claim-version substitution",
      );
      await Promise.all(
        (
          [
            [
              "refresh generation",
              { refreshGeneration: refreshGeneration + 1 },
            ],
            ["pinned secret revision", { revision: 3 }],
            [
              "provider",
              {
                provider: {
                  scope: "tenant",
                  tenantId: fixture.tenant,
                  providerId: fixture.replayProvider,
                  bindingId: fixture.binding,
                },
              },
            ],
            [
              "binding",
              {
                provider: {
                  scope: "tenant",
                  tenantId: fixture.tenant,
                  providerId: fixture.provider,
                  bindingId: fixture.replayBinding,
                },
                bindingId: fixture.replayBinding,
              },
            ],
          ] satisfies [string, JsonObject][]
        ).map(async ([label, substitution]) => {
          const [substitutedSecret] = await transaction<
            { response: JsonObject | null }[]
          >`
              SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
                ${transaction.json({
                  ...refreshSecretLookup,
                  ...substitution,
                })}::jsonb
              ) AS response
            `;
          assert.equal(
            substitutedSecret?.response,
            null,
            `maintenance secret ignored ${label} substitution`,
          );
        }),
      );

      const rollbackInflightReuse = new Error(
        "rollback in-flight refresh reuse",
      );
      await assert.rejects(
        transaction.savepoint(async (nested) => {
          const [duplicate] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                sessionFamilyId: fixture.oidcLifecycleFamily,
                expectedGeneration: 1,
                expectedDigest: refreshDigestOne.toString("base64"),
                claimedAt: refreshClaimedAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(duplicate?.response.category, "busy");
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [reusedSession] = await nested<{ revoked: boolean }[]>`
            SELECT revoked_at IS NOT NULL AS revoked
            FROM public.auth_sessions
            WHERE id = ${fixture.oidcLifecycleSession}::uuid
          `;
          assert.equal(reusedSession?.revoked, false);
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          throw rollbackInflightReuse;
        }),
        (error: unknown) => error === rollbackInflightReuse,
      );

      const [completed] = await transaction<{ applied: boolean }[]>`
        SELECT app.complete_tenant_oidc_refresh_rotation_v1(
          ${transaction.json({
            tenantId: fixture.tenant,
            effectiveTenantId: fixture.tenant,
            materialId: fixture.begin,
            sessionFamilyId: fixture.oidcLifecycleFamily,
            expectedVersion: 2,
            expectedGeneration: 1,
            outcome: "rotated",
            successorGeneration: 2,
            successorDigest: refreshDigestTwo.toString("base64"),
            successorToken: {
              keyVersion: 1,
              ciphertext: refreshEnvelopeTwo.toString("base64"),
            },
            accessExpiresAt: accessExpiresAt.toISOString(),
            completedAt: refreshCompletedAt.toISOString(),
          })}::jsonb
        ) AS applied
      `;
      assert.equal(
        completed?.applied,
        true,
        "OIDC refresh rotation did not commit",
      );
      const [consumedClaimSecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(refreshSecretLookup)}::jsonb
        ) AS response
      `;
      assert.equal(
        consumedClaimSecret?.response,
        null,
        "maintenance secret replayed after refresh claim completion",
      );

      const rollbackAccessLeaseBoundary = new Error(
        "rollback OIDC access/claim lease boundary",
      );
      await assert.rejects(
        transaction.savepoint(async (nested) => {
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          await nested`
            UPDATE public.tenant_oidc_session_materials
            SET access_expires_at = date_trunc(
                  'microseconds',transaction_timestamp()
                ) + interval '40 seconds',
                updated_at = date_trunc(
                  'microseconds',transaction_timestamp()
                )
            WHERE id = ${fixture.begin}::uuid
          `;
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          await nested`
            SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
                   set_config('app.user_id', ${fixture.sessionUser}, true)
          `;
          const [boundaryClaim] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                sessionFamilyId: fixture.oidcLifecycleFamily,
                expectedGeneration: 2,
                expectedDigest: refreshDigestTwo.toString("base64"),
                claimedAt: f55ClaimedAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(boundaryClaim?.response.category, "claimed");
          assert.equal(boundaryClaim?.response.version, 4);

          const [liveLeasePoll] = await nested<
            {
              response: JsonObject | null;
            }[]
          >`
            SELECT app.claim_due_oidc_maintenance_v1(
              ${nested.json({
                kind: "refresh",
                observedAt: f55LiveLeasePollAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(
            liveLeasePoll?.response,
            null,
            "maintenance revoked a credential-bearing request in flight",
          );
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [stillClaimed] = await nested<
            { refresh_state: string; revoked: boolean }[]
          >`
            SELECT material.refresh_state,
              session.revoked_at IS NOT NULL AS revoked
            FROM public.tenant_oidc_session_materials AS material
            JOIN public.auth_sessions AS session
              ON session.id = material.session_id
            WHERE material.id = ${fixture.begin}::uuid
          `;
          assert.deepEqual(stillClaimed, {
            refresh_state: "claimed",
            revoked: false,
          });

          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          const [boundaryCompletion] = await nested<{ applied: boolean }[]>`
            SELECT app.complete_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                tenantId: fixture.tenant,
                effectiveTenantId: fixture.tenant,
                materialId: fixture.begin,
                sessionFamilyId: fixture.oidcLifecycleFamily,
                expectedVersion: 4,
                expectedGeneration: 2,
                outcome: "rotated",
                successorGeneration: 3,
                successorDigest: refreshDigestThree.toString("base64"),
                successorToken: {
                  keyVersion: 1,
                  ciphertext: refreshEnvelopeThree.toString("base64"),
                },
                accessExpiresAt: f55SuccessorAccessExpiresAt.toISOString(),
                completedAt: f55CompletedAt.toISOString(),
              })}::jsonb
            ) AS applied
          `;
          assert.equal(
            boundaryCompletion?.applied,
            true,
            "live refresh lease could not complete after access expiry",
          );

          const [staleLeaseClaim] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                sessionFamilyId: fixture.oidcLifecycleFamily,
                expectedGeneration: 3,
                expectedDigest: refreshDigestThree.toString("base64"),
                claimedAt: f55SecondClaimedAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(staleLeaseClaim?.response.category, "claimed");
          assert.equal(staleLeaseClaim?.response.version, 6);

          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          await nested`
            UPDATE public.tenant_oidc_session_materials
            SET access_expires_at = date_trunc(
                  'microseconds',transaction_timestamp()
                ),
                refresh_claimed_at = date_trunc(
                  'microseconds',transaction_timestamp()
                ) - interval '1 second',
                refresh_claim_expires_at = date_trunc(
                  'microseconds',transaction_timestamp()
                ),
                updated_at = date_trunc(
                  'microseconds',transaction_timestamp()
                )
            WHERE id = ${fixture.begin}::uuid
          `;
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');

          const [expiredLease] = await nested<
            {
              response: JsonObject;
            }[]
          >`
            SELECT app.expire_oidc_access_lease_v1(
              ${nested.json({
                kind: "access_expiry",
                observedAt: f55ExpiredLeasePollAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(expiredLease?.response.kind, "access_expiry");
          assert.equal(expiredLease?.response.expired, true);
          const [expiredLeasePoll] = await nested<
            {
              response: JsonObject | null;
            }[]
          >`
            SELECT app.claim_due_oidc_maintenance_v1(
              ${nested.json({
                kind: "scrub",
                observedAt: f55ExpiredLeasePollAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.equal(expiredLeasePoll?.response?.kind, "scrub");
          const [oldRefreshCompletion] = await nested<{ applied: boolean }[]>`
            SELECT app.complete_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                tenantId: fixture.tenant,
                effectiveTenantId: fixture.tenant,
                materialId: fixture.begin,
                sessionFamilyId: fixture.oidcLifecycleFamily,
                expectedVersion: 6,
                expectedGeneration: 3,
                outcome: "ambiguous",
                completedAt: f55OldCompletionAt.toISOString(),
              })}::jsonb
            ) AS applied
          `;
          assert.equal(
            oldRefreshCompletion?.applied,
            false,
            "expired refresh worker won CAS after maintenance revocation",
          );
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [expiredState] = await nested<
            { refresh_state: string; revoked: boolean }[]
          >`
            SELECT material.refresh_state,
              session.revoked_at IS NOT NULL AS revoked
            FROM public.tenant_oidc_session_materials AS material
            JOIN public.auth_sessions AS session
              ON session.id = material.session_id
            WHERE material.id = ${fixture.begin}::uuid
          `;
          assert.deepEqual(expiredState, {
            refresh_state: "scrubbed",
            revoked: true,
          });
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          throw rollbackAccessLeaseBoundary;
        }),
        (error: unknown) => error === rollbackAccessLeaseBoundary,
      );

      const rollbackConsumedReuse = new Error(
        "rollback consumed refresh reuse",
      );
      const consumedReuseCommand = {
        sessionFamilyId: fixture.oidcLifecycleFamily,
        expectedGeneration: 1,
        expectedDigest: refreshDigestOne.toString("base64"),
        claimedAt: refreshCompletedAt.toISOString(),
      };
      await assert.rejects(
        transaction.savepoint(async (nested) => {
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          await nested`
            INSERT INTO public.auth_sessions (
              id,user_id,rotation_family_id,active_tenant_id,token_digest,
              csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
              idle_expires_at,absolute_expires_at,created_at
            ) VALUES (
              ${fixture.oidcLifecycleSiblingSession}::uuid,
              ${fixture.sessionUser}::uuid,${fixture.oidcLifecycleFamily}::uuid,
              ${fixture.tenant}::uuid,${Buffer.alloc(32, 0x91)}::bytea,
              ${Buffer.alloc(32, 0x92)}::bytea,'oidc',${lifecycleNow},
              ${lifecycleNow},${later},${later},${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.auth_session_mfa_states (
              session_id,tenant_id,user_id,session_version,identity_epoch,
              recovery_restricted,audience,primary_kind,
              session_invalidation_epoch,issued_at
            ) VALUES (
              ${fixture.oidcLifecycleSiblingSession}::uuid,
              ${fixture.tenant}::uuid,${fixture.sessionUser}::uuid,
              1,1,false,'api','tenant_provider',1,${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.auth_session_federated_provenance (
              tenant_id,session_id,user_id,primary_kind,authentication_method,
              provider_id,binding_id,provider_kind,external_identity_id,
              external_identity_revision,trust_rule_revision,authenticated_at
            ) VALUES (
              ${fixture.tenant}::uuid,
              ${fixture.oidcLifecycleSiblingSession}::uuid,
              ${fixture.sessionUser}::uuid,'tenant_provider','oidc',
              ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc',
              ${fixture.externalIdentity}::uuid,1,3,${lifecycleNow}
            )
          `;
          await nested`
            UPDATE public.tenant_oidc_session_materials
            SET refresh_state = 'claimed',
                refresh_claimed_at = ${refreshCompletedAt},
                refresh_claim_expires_at = ${new Date(
                  refreshCompletedAt.getTime() + 60_000,
                )},
                updated_at = ${refreshCompletedAt}
            WHERE id = ${fixture.begin}::uuid
          `;
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          const [replay] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json(consumedReuseCommand)}::jsonb
            ) AS response
          `;
          assert.equal(replay?.response.category, "reuse");
          assert.equal(replay?.response.tenantId, fixture.tenant);
          assert.equal(replay?.response.effectiveTenantId, fixture.tenant);
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [consumed] = await nested<{ count: string }[]>`
            SELECT count(*)::text AS count
            FROM public.tenant_oidc_consumed_refresh_tokens
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND material_id = ${fixture.begin}::uuid
              AND generation = 1
              AND token_digest = ${refreshDigestOne}::bytea
          `;
          assert.equal(consumed?.count, "1");
          const [familyState] = await nested<
            { reuseRevokedCount: number; sessionCount: number }[]
          >`
            SELECT count(*)::integer AS "sessionCount",
              count(*) FILTER (
                WHERE revoked_at IS NOT NULL
                  AND revoke_reason = 'oidc_refresh_reuse'
              )::integer AS "reuseRevokedCount"
            FROM public.auth_sessions
            WHERE user_id = ${fixture.sessionUser}::uuid
              AND rotation_family_id = ${fixture.oidcLifecycleFamily}::uuid
          `;
          assert.deepEqual(familyState, {
            reuseRevokedCount: 2,
            sessionCount: 2,
          });
          const [materialState] = await nested<
            {
              claimCleared: boolean;
              leaseCleared: boolean;
              refreshState: string;
            }[]
          >`
            SELECT refresh_state AS "refreshState",
              refresh_claimed_at IS NULL AS "claimCleared",
              refresh_claim_expires_at IS NULL AS "leaseCleared"
            FROM public.tenant_oidc_session_materials
            WHERE id = ${fixture.begin}::uuid
          `;
          assert.deepEqual(materialState, {
            claimCleared: true,
            leaseCleared: true,
            refreshState: "revoked",
          });
          const [reuseAudit] = await nested<
            {
              auditCount: number;
              actorType: string;
              actorUserId: string | null;
              authenticationMethod: string;
              outcome: string;
              resourceId: string | null;
            }[]
          >`
            SELECT count(*) OVER ()::integer AS "auditCount",
              actor_type AS "actorType",
              actor_user_id::text AS "actorUserId",
              authentication_method AS "authenticationMethod",
              outcome,resource_id::text AS "resourceId"
            FROM public.audit_events
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND action = 'tenant.identity.oidc_refresh_reuse'
            ORDER BY sequence DESC
            LIMIT 1
          `;
          assert.deepEqual(reuseAudit, {
            auditCount: 1,
            actorType: "system",
            actorUserId: null,
            authenticationMethod: "oidc",
            outcome: "success",
            resourceId: fixture.oidcLifecycleSession,
          });
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          const [secondReplay] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json(consumedReuseCommand)}::jsonb
            ) AS response
          `;
          assert.equal(secondReplay?.response.category, "stale");
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [auditAfterSecondReplay] = await nested<{ count: number }[]>`
            SELECT count(*)::integer AS count
            FROM public.audit_events
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND action = 'tenant.identity.oidc_refresh_reuse'
          `;
          assert.equal(auditAfterSecondReplay?.count, 1);
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          throw rollbackConsumedReuse;
        }),
        (error: unknown) => error === rollbackConsumedReuse,
      );

      const rollbackPlatformConsumedReuse = new Error(
        "rollback direct platform consumed refresh reuse",
      );
      const platformRefreshDigest = Buffer.alloc(32, 0xa1);
      const platformRefreshClaimedAt = refreshCompletedAt;
      const platformRefreshAccessExpiresAt = new Date(
        lifecycleNow.getTime() + 5 * 60_000,
      );
      const platformRefreshExpiresAt = authenticationExpiresAt;
      const platformIssuer = "https://platform-refresh.example.invalid";
      const platformTransactionDigest = Buffer.alloc(32, 0xa2);
      await assert.rejects(
        transaction.savepoint(async (nested) => {
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          await nested`
            SELECT set_config(
              'app.mfa_policy_write_v1',
              ${`insert:${fixture.platformOidcRefreshFloor}:1`},true
            )
          `;
          await nested`
            INSERT INTO public.mfa_policy_revisions (
              id,revision,tenant_id,scope,level,local_required,
              freshness_nanoseconds,created_at
            ) VALUES (
              ${fixture.platformOidcRefreshFloor}::uuid,1,NULL,
              'platform_floor','primary',false,0,${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.platform_auth_providers (
              id,key,display_name,description,kind,enabled,
              created_by_user_id,updated_by_user_id,created_at,updated_at
            ) VALUES (
              ${fixture.platformOidcRefreshProvider}::uuid,
              'platform_refresh_runtime','Platform refresh runtime',
              'Direct platform refresh-reuse routing proof.','oidc',false,
              ${fixture.sessionUser}::uuid,${fixture.sessionUser}::uuid,
              ${lifecycleNow},${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.platform_federated_provider_policies (
              provider_id,provider_kind,configuration_revision,
              security_revision,plan_revision,assurance_policy_revision,
              account_mode,platform_login_enabled,enabled,created_at,updated_at
            ) VALUES (
              ${fixture.platformOidcRefreshProvider}::uuid,'oidc',1,1,1,1,
              'disabled',false,false,${lifecycleNow},${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.platform_oidc_provider_configurations (
              provider_id,provider_kind,issuer,client_id,redirect_uri,
              tenant_redirect_uri,post_logout_redirect_uri,extra_scopes,
              allow_refresh_token,use_user_info,client_secret_revision,
              discovery_revision,jwks_revision,version,created_at,updated_at
            ) VALUES (
              ${fixture.platformOidcRefreshProvider}::uuid,'oidc',
              ${platformIssuer},'platform-refresh-runtime',
              'https://platform-refresh.example.invalid/api/v1/auth/platform/oidc/callback',
              'https://platform-refresh.example.invalid/api/v1/auth/federated/oidc/callback',
              'https://platform-refresh.example.invalid/signed-out',
              ARRAY['offline_access']::text[],true,false,1,1,1,1,
              ${lifecycleNow},${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.platform_oidc_login_policies (provider_id)
            VALUES (${fixture.platformOidcRefreshProvider}::uuid)
          `;
          await nested`
            INSERT INTO public.platform_federated_external_identities (
              id,platform_provider_id,provider_kind,user_id,subject_format,
              subject_ciphertext,subject_nonce,key_version,
              admitted_configuration_revision,admitted_security_revision,
              last_observed_at
            ) VALUES (
              ${fixture.platformOidcRefreshIdentity}::uuid,
              ${fixture.platformOidcRefreshProvider}::uuid,'oidc',
              ${fixture.sessionUser}::uuid,'utf8_exact',
              ${Buffer.alloc(32, 0xa3)}::bytea,${Buffer.alloc(12, 0xa4)}::bytea,
              1,1,1,transaction_timestamp()
            )
          `;
          await nested`
            INSERT INTO public.auth_sessions (
              id,user_id,rotation_family_id,active_tenant_id,token_digest,
              csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
              idle_expires_at,absolute_expires_at,created_at
            ) VALUES (
              ${fixture.platformOidcRefreshSession}::uuid,
              ${fixture.sessionUser}::uuid,${fixture.platformOidcRefreshFamily}::uuid,
              NULL,${Buffer.alloc(32, 0xa5)}::bytea,
              ${Buffer.alloc(32, 0xa6)}::bytea,'oidc',NULL,${lifecycleNow},
              ${platformRefreshExpiresAt},${platformRefreshExpiresAt},${lifecycleNow}
            )
          `;
          await nested`
            SELECT set_config('app.platform_oidc_runtime_write_v1','on',true)
          `;
          await nested`
            INSERT INTO public.auth_session_platform_oidc_states (
              session_id,user_id,session_version,user_authentication_revision,
              recovery_restricted,audience,primary_kind,issued_at
            ) VALUES (
              ${fixture.platformOidcRefreshSession}::uuid,
              ${fixture.sessionUser}::uuid,1,1,false,'api','platform_provider',
              ${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.auth_session_platform_oidc_provenance (
              session_id,user_id,primary_kind,platform_provider_id,
              external_identity_id,provider_revision,login_policy_revision,
              security_revision,user_authentication_revision,identity_version,
              alias_key_version,assurance_policy_revision,platform_floor_policy_id,
              platform_floor_policy_revision,trust_rule_id,trust_rule_revision,
              authenticated_at
            ) VALUES (
              ${fixture.platformOidcRefreshSession}::uuid,
              ${fixture.sessionUser}::uuid,'platform_provider',
              ${fixture.platformOidcRefreshProvider}::uuid,
              ${fixture.platformOidcRefreshIdentity}::uuid,1,1,1,1,1,1,1,
              ${fixture.platformOidcRefreshFloor}::uuid,1,NULL,NULL,${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.platform_oidc_authentication_transactions (
              transaction_id,platform_provider_id,provider_kind,protocol,
              operation_run_id,operation_digest,receipt_digest,network_digest,
              account_digest,provider_digest,state_digest,browser_digest,
              browser_capability_digest,nonce_digest,code_challenge_method,
              provider_revision,login_policy_revision,configuration_revision,
              security_revision,plan_revision,assurance_policy_revision,
              platform_floor_policy_id,platform_floor_policy_revision,
              client_secret_revision,discovery_revision,discovery_digest,
              jwks_revision,jwks_digest,verifier_key_version,verifier_ciphertext,
              client_id,redirect_uri,post_logout_redirect_uri,scopes,
              allow_refresh_token,use_user_info,return_path,state,version,
              created_at,expires_at
            ) VALUES (
              ${platformTransactionDigest}::bytea,
              ${fixture.platformOidcRefreshProvider}::uuid,'oidc','oidc',
              ${fixture.platformOidcRefreshMaterial}::uuid,
              ${Buffer.alloc(32, 0xa7)}::bytea,${Buffer.alloc(32, 0xa8)}::bytea,
              ${Buffer.alloc(32, 0xa9)}::bytea,${Buffer.alloc(32, 0xaa)}::bytea,
              ${Buffer.alloc(32, 0xab)}::bytea,${Buffer.alloc(32, 0xac)}::bytea,
              ${Buffer.alloc(32, 0xad)}::bytea,${Buffer.alloc(32, 0xae)}::bytea,
              ${Buffer.alloc(32, 0xaf)}::bytea,'S256',1,1,1,1,1,1,
              ${fixture.platformOidcRefreshFloor}::uuid,1,1,1,
              ${Buffer.alloc(32, 0xb0)}::bytea,1,${Buffer.alloc(32, 0xb1)}::bytea,
              1,${Buffer.alloc(32, 0xb2)}::bytea,'platform-refresh-runtime',
              'https://platform-refresh.example.invalid/api/v1/auth/platform/oidc/callback',
              'https://platform-refresh.example.invalid/signed-out',
              ARRAY['openid','offline_access']::text[],true,false,'/platform',
              'pending',1,${lifecycleNow},${platformRefreshExpiresAt}
            )
          `;
          await nested`
            UPDATE public.platform_oidc_authentication_transactions
            SET state = 'claimed',version = 2,
                claim_attempt_id = ${Buffer.alloc(32, 0xb3)}::bytea,
                authorization_code_digest = ${Buffer.alloc(32, 0xb4)}::bytea,
                claimed_at = ${lifecycleNow}
            WHERE transaction_id = ${platformTransactionDigest}::bytea
          `;
          await nested`
            UPDATE public.platform_oidc_authentication_transactions
            SET state = 'completed',version = 3,completed_at = ${lifecycleNow}
            WHERE transaction_id = ${platformTransactionDigest}::bytea
          `;
          await nested`
            INSERT INTO public.platform_oidc_authentication_applications (
              id,transaction_id,operation_digest,platform_provider_id,
              external_identity_id,category,primary_kind,user_id,session_id,
              continuation_id,request_snapshot,result_snapshot,applied_at
            ) VALUES (
              ${fixture.platformOidcRefreshApplication}::uuid,
              ${platformTransactionDigest}::bytea,${Buffer.alloc(32, 0xb5)}::bytea,
              ${fixture.platformOidcRefreshProvider}::uuid,
              ${fixture.platformOidcRefreshIdentity}::uuid,'success',
              'platform_provider',${fixture.sessionUser}::uuid,
              ${fixture.platformOidcRefreshSession}::uuid,NULL,
              '{}'::jsonb,'{"category":"success"}'::jsonb,${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.tenant_oidc_session_materials (
              id,tenant_id,authority,session_id,continuation_id,
              rotation_family_id,user_id,provider_id,binding_id,provider_kind,
              external_identity_id,aad_version,id_token_key_version,
              id_token_ciphertext,id_token_digest,refresh_token_key_version,
              refresh_token_ciphertext,refresh_token_digest,refresh_generation,
              refresh_state,refresh_version,access_expires_at,expires_at,
              client_secret_revision,client_authentication,client_id,
              token_endpoint,revocation_endpoint,end_session_endpoint,
              post_logout_redirect_uri,logout_disposition,created_at,updated_at
            ) VALUES (
              ${fixture.platformOidcRefreshMaterial}::uuid,NULL,
              'platform_provider',${fixture.platformOidcRefreshSession}::uuid,NULL,
              ${fixture.platformOidcRefreshFamily}::uuid,
              ${fixture.sessionUser}::uuid,
              ${fixture.platformOidcRefreshProvider}::uuid,NULL,'oidc',
              ${fixture.platformOidcRefreshIdentity}::uuid,1,NULL,NULL,NULL,1,
              ${Buffer.alloc(48, 0xb6)}::bytea,${platformRefreshDigest}::bytea,
              1,'ready',1,${platformRefreshAccessExpiresAt},
              ${platformRefreshExpiresAt},1,'client_secret_basic',
              'platform-refresh-runtime',${`${platformIssuer}/token`},NULL,NULL,
              'https://platform-refresh.example.invalid/signed-out',
              'not_configured',${lifecycleNow},${lifecycleNow}
            )
          `;
          await nested`
            INSERT INTO public.tenant_oidc_consumed_refresh_tokens (
              tenant_id,authority,material_id,session_family_id,generation,
              token_digest,consumed_at,retain_until
            ) VALUES (
              NULL,'platform_provider',${fixture.platformOidcRefreshMaterial}::uuid,
              ${fixture.platformOidcRefreshFamily}::uuid,1,
              ${platformRefreshDigest}::bytea,${platformRefreshClaimedAt},
              ${platformRefreshExpiresAt}
            )
          `;
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          await nested`
            SELECT set_config('app.tenant_id','',true),
                   set_config('app.user_id',${fixture.sessionUser},true)
          `;
          const [platformReplay] = await nested<{ response: JsonObject }[]>`
            SELECT app.claim_tenant_oidc_refresh_rotation_v1(
              ${nested.json({
                sessionFamilyId: fixture.platformOidcRefreshFamily,
                expectedGeneration: 1,
                expectedDigest: platformRefreshDigest.toString("base64"),
                claimedAt: platformRefreshClaimedAt.toISOString(),
              })}::jsonb
            ) AS response
          `;
          assert.deepEqual(platformReplay?.response, {
            category: "reuse",
            effectiveTenantId: null,
            materialId: fixture.platformOidcRefreshMaterial,
            sessionFamilyId: fixture.platformOidcRefreshFamily,
            tenantId: null,
          });
          await nested.unsafe('SET LOCAL ROLE "periapsis_migrator"');
          const [platformReuseAudit] = await nested<
            {
              action: string;
              actorType: string;
              actorUserId: string | null;
              auditCount: number;
              authenticationMethod: string;
              outcome: string;
              resourceId: string | null;
              resourceType: string;
            }[]
          >`
            SELECT count(*) OVER ()::integer AS "auditCount",
              actor_type AS "actorType",actor_user_id::text AS "actorUserId",
              action,resource_type AS "resourceType",
              resource_id::text AS "resourceId",
              authentication_method AS "authenticationMethod",outcome
            FROM public.platform_audit_events
            WHERE action = 'platform.identity.oidc_refresh_reuse'
              AND resource_id = ${fixture.platformOidcRefreshSession}::uuid
          `;
          assert.deepEqual(platformReuseAudit, {
            action: "platform.identity.oidc_refresh_reuse",
            actorType: "system",
            actorUserId: null,
            auditCount: 1,
            authenticationMethod: "oidc",
            outcome: "success",
            resourceId: fixture.platformOidcRefreshSession,
            resourceType: "auth_session",
          });
          await nested.unsafe('SET LOCAL ROLE "periapsis_worker"');
          throw rollbackPlatformConsumedReuse;
        }),
        (error: unknown) => error === rollbackPlatformConsumedReuse,
      );

      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.foreignTenant}, true)
      `;
      const [crossTenant] = await transaction<{ response: JsonObject }[]>`
        SELECT app.claim_tenant_oidc_refresh_rotation_v1(
          ${transaction.json({
            sessionFamilyId: fixture.oidcLifecycleFamily,
            expectedGeneration: 2,
            expectedDigest: refreshDigestTwo.toString("base64"),
            claimedAt: refreshCompletedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert.equal(crossTenant?.response.category, "stale");

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.users
        SET active = false,updated_at = ${logoutRequestedAt}
        WHERE id = ${fixture.sessionUser}::uuid
      `;
      await transaction`
        UPDATE public.auth_session_mfa_states
        SET session_version = 9000000000000000
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND session_id = ${fixture.oidcLifecycleSession}::uuid
          AND user_id = ${fixture.sessionUser}::uuid
      `;
      await setAPIContext(transaction, fixture.tenant, fixture.sessionUser);
      const [credential] = await transaction<{ response: JsonObject | null }[]>`
        SELECT app.resolve_session_for_logout_v1(
          ${sessionTokenDigest}::bytea
        ) AS response
      `;
      assert.deepEqual(credential?.response, {
        csrfDigest: sessionCsrfDigest.toString("base64"),
        sessionId: fixture.oidcLifecycleSession,
        tenantId: fixture.tenant,
        tokenDigest: sessionTokenDigest.toString("base64"),
        userId: fixture.sessionUser,
      });

      const [logout] = await transaction<{ response: JsonObject | null }[]>`
        SELECT app.revoke_local_session_for_logout_v1(
          ${transaction.json({
            operationRunId: fixture.oidcLogout,
            sessionId: fixture.oidcLifecycleSession,
            userId: fixture.sessionUser,
            tenantId: fixture.tenant,
            tokenDigest: sessionTokenDigest.toString("base64"),
            requestDigest: digest("OIDC lifecycle local logout"),
            requestUpstream: true,
            requestedAt: logoutRequestedAt.toISOString(),
            continuationId: fixture.oidcLogoutContinuation,
            continuationDigest: continuationDigest.toString("base64"),
            continuationExpiresAt: continuationExpiresAt.toISOString(),
            audit: {
              requestId: fixture.command,
              correlationId: fixture.replayCommand,
              remoteAddress: "203.0.113.10",
              userAgent: "periapsis-db-runtime/oidc-logout",
            },
          })}::jsonb
        ) AS response
      `;
      assert(logout?.response, "OIDC local logout returned no response");
      assert.equal(logout.response.category, "logout_continuation");
      assert.equal(
        logout.response.continuationId,
        fixture.oidcLogoutContinuation,
      );
      assert.equal(logout.response.sessionId, fixture.oidcLifecycleSession);
      assert.equal(logout.response.previousVersion, 9000000000000000);
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      const [saturatedLogout] = await transaction<
        { revoked: boolean; session_version: string }[]
      >`
        SELECT session.revoked_at IS NOT NULL AS revoked,
          state.session_version::text
        FROM public.auth_sessions AS session
        JOIN public.auth_session_mfa_states AS state
          ON state.session_id = session.id
         AND state.tenant_id = session.active_tenant_id
         AND state.user_id = session.user_id
        WHERE session.id = ${fixture.oidcLifecycleSession}::uuid
      `;
      assert.deepEqual(saturatedLogout, {
        revoked: true,
        session_version: "9000000000000000",
      });

      await setAPIContext(transaction, fixture.tenant, fixture.sessionUser);
      const [replayedLogout] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.revoke_local_session_for_logout_v1(
          ${transaction.json({
            operationRunId: fixture.oidcLogoutReplay,
            sessionId: fixture.oidcLifecycleSession,
            userId: fixture.sessionUser,
            tenantId: fixture.tenant,
            tokenDigest: sessionTokenDigest.toString("base64"),
            requestDigest: digest("OIDC lifecycle replayed local logout"),
            requestUpstream: true,
            requestedAt: logoutRequestedAt.toISOString(),
            continuationId: fixture.oidcLogoutReplayContinuation,
            continuationDigest: digest(
              "OIDC lifecycle replayed logout continuation",
            ),
            continuationExpiresAt: continuationExpiresAt.toISOString(),
            audit: {
              requestId: fixture.replayCommand,
              correlationId: fixture.command,
              remoteAddress: "203.0.113.11",
              userAgent: "periapsis-db-runtime/oidc-logout-replay",
            },
          })}::jsonb
        ) AS response
      `;
      assert(
        replayedLogout?.response,
        "replayed local logout returned no response",
      );
      assert.equal(replayedLogout.response.category, "revoked_local_only");
      assert.equal(
        replayedLogout.response.operationRunId,
        fixture.oidcLogoutReplay,
      );
      assert.equal(replayedLogout.response.continuationId, undefined);

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      const [deduplicatedLogout] = await transaction<
        { audits: string; commands: string; continuations: string }[]
      >`
        SELECT
          (SELECT count(*)::text
           FROM public.tenant_oidc_logout_commands AS command
           WHERE command.session_id = ${fixture.oidcLifecycleSession}::uuid)
            AS commands,
          (SELECT count(*)::text
           FROM public.session_logout_continuations AS continuation
           WHERE continuation.session_id = ${fixture.oidcLifecycleSession}::uuid)
            AS continuations,
          (SELECT count(*)::text
           FROM public.audit_events AS event
           WHERE event.tenant_id = ${fixture.tenant}::uuid
             AND event.resource_id = ${fixture.oidcLifecycleSession}::uuid
             AND event.action = 'tenant.identity.session_local_logout') AS audits
      `;
      assert.deepEqual(deduplicatedLogout, {
        audits: "1",
        commands: "1",
        continuations: "1",
      });

      await setAPIContext(transaction, fixture.tenant, fixture.sessionUser);
      const serializedLogout = JSON.stringify(logout.response);
      assert(
        !/ciphertext|keyVersion|tokenDigest|csrfDigest|endpoint/i.test(
          serializedLogout,
        ),
      );

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      const [ledger] = await transaction<
        {
          audit_metadata: JsonObject;
          request_snapshot: JsonObject;
          result_snapshot: JsonObject;
        }[]
      >`
        SELECT command.request_snapshot,command.result_snapshot,
          event.metadata AS audit_metadata
        FROM public.tenant_oidc_logout_commands AS command
        JOIN public.audit_events AS event
          ON event.tenant_id = command.tenant_id
         AND event.resource_id = command.session_id
         AND event.action = 'tenant.identity.session_local_logout'
         AND event.occurred_at = command.applied_at
        WHERE command.operation_run_id = ${fixture.oidcLogout}::uuid
      `;
      assert(ledger, "OIDC logout ledger was not written");
      const serializedLedger = JSON.stringify(ledger);
      assert(
        !/ciphertext|keyVersion|tokenDigest|csrfDigest|idToken|refreshToken|secret|endpoint/i.test(
          serializedLedger,
        ),
      );

      await setAPIContext(transaction, fixture.tenant, fixture.sessionUser);
      const [continuation] = await transaction<
        {
          response: JsonObject | null;
        }[]
      >`
        SELECT app.claim_session_logout_continuation_v1(
          ${transaction.json({
            continuationId: fixture.oidcLogoutContinuation,
            tokenDigest: continuationDigest.toString("base64"),
            claimedAt: continuationClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert(
        continuation?.response,
        "OIDC logout continuation was not claimable",
      );
      assert.equal(continuation.response.category, "oidc_end_session");
      assert.equal(continuation.response.materialId, fixture.begin);
      assert.equal(
        continuation.response.endSessionEndpoint,
        `${oidcIssuer}/logout`,
      );
      assert.equal(
        continuation.response.postLogoutRedirectUri,
        "https://soc.example.invalid/signed-out",
      );
      const continuationRequestedClaimedAt =
        continuation.response.requestedClaimedAt;
      assert.equal(typeof continuationRequestedClaimedAt, "string");
      if (typeof continuationRequestedClaimedAt !== "string") {
        assert.fail("OIDC continuation claim timestamp is not canonical");
      }
      assert.equal(
        Date.parse(continuationRequestedClaimedAt),
        continuationClaimedAt.getTime(),
      );
      assert.equal(typeof continuation.response.observedAt, "string");
      const continuationResponseExpiresAt = continuation.response.expiresAt;
      const continuationResponseRevokedAt = continuation.response.revokedAt;
      assert.equal(typeof continuationResponseExpiresAt, "string");
      assert.equal(typeof continuationResponseRevokedAt, "string");
      if (
        typeof continuationResponseExpiresAt !== "string" ||
        typeof continuationResponseRevokedAt !== "string"
      ) {
        assert.fail("OIDC continuation clock projection is not canonical");
      }
      assert.equal(
        new Date(continuationResponseExpiresAt).getTime() -
          new Date(continuationResponseRevokedAt).getTime(),
        90_000,
      );
      const continuationMaterialExpiresAt =
        continuation.response.materialExpiresAt;
      assert.equal(typeof continuationMaterialExpiresAt, "string");
      if (typeof continuationMaterialExpiresAt !== "string") {
        assert.fail("OIDC continuation material expiry is not canonical");
      }
      assert.equal(Date.parse(continuationMaterialExpiresAt), later.getTime());
      assert.equal(
        objectValue(
          continuation.response.protectedIdToken,
          "OIDC protected ID token",
        ).ciphertext,
        idEnvelope.toString("base64"),
      );
      assert.equal(
        continuation.response.idTokenDigest,
        idTokenDigest.toString("base64"),
      );
      const retryJobId = continuation.response.logoutRetryJobId;
      assert.equal(typeof retryJobId, "string");
      if (typeof retryJobId !== "string") {
        assert.fail("OIDC logout retry job ID is not a string");
      }

      const [usedContinuation] = await transaction<
        {
          response: JsonObject | null;
        }[]
      >`
        SELECT app.claim_session_logout_continuation_v1(
          ${transaction.json({
            continuationId: fixture.oidcLogoutContinuation,
            tokenDigest: continuationDigest.toString("base64"),
            claimedAt: continuationClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert.equal(usedContinuation?.response, null);

      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      const [retry] = await transaction<{ response: JsonObject | null }[]>`
        SELECT app.claim_due_oidc_maintenance_v1(
          ${transaction.json({
            kind: "logout_retry",
            observedAt: retryClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert(retry?.response, "OIDC logout retry was not claimable");
      assert.equal(retry.response.kind, "logout_retry");
      assert.equal(retry.response.jobId, retryJobId);
      assert.equal(retry.response.materialId, fixture.begin);
      assert.equal(retry.response.attempt, 1);
      assert.equal(retry.response.claimVersion, 2);
      const retryClaimVersion = retry.response.claimVersion;
      const retryGeneration = retry.response.refreshGeneration;
      const retryAttempt = retry.response.attempt;
      assert.equal(typeof retryClaimVersion, "number");
      assert.equal(typeof retryGeneration, "number");
      assert.equal(typeof retryAttempt, "number");
      if (
        typeof retryClaimVersion !== "number" ||
        typeof retryGeneration !== "number" ||
        typeof retryAttempt !== "number"
      ) {
        assert.fail("OIDC logout retry proof counters are not numbers");
      }
      assert.equal(
        objectValue(retry.response.opaqueReference, "OIDC retry reference")
          .ciphertext,
        refreshEnvelopeTwo.toString("base64"),
      );
      const retrySecretLookup: JsonObject = {
        ...secretLookup,
        kind: "logout_retry",
        materialId: fixture.begin,
        sessionFamilyId: fixture.oidcLifecycleFamily,
        claimVersion: retryClaimVersion,
        refreshGeneration: retryGeneration,
        jobId: retryJobId,
        attempt: retryAttempt,
      };
      const [retrySecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(retrySecretLookup)}::jsonb
        ) AS response
      `;
      assert(
        retrySecret?.response,
        "pinned OIDC secret was not loadable for its live logout claim",
      );
      assert.deepEqual(retrySecret.response.lookup, retrySecretLookup);

      const [concurrentClaim] = await transaction<
        {
          response: JsonObject | null;
        }[]
      >`
        SELECT app.claim_due_oidc_maintenance_v1(
          ${transaction.json({
            kind: "logout_retry",
            observedAt: retryClaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert.equal(concurrentClaim?.response, null);

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_oidc_logout_retry_jobs
        SET claimed_at = date_trunc(
              'microseconds',transaction_timestamp()
            ) - interval '1 second',
            claim_expires_at = date_trunc(
              'microseconds',transaction_timestamp()
            ),
            updated_at = date_trunc(
              'microseconds',transaction_timestamp()
            )
        WHERE id = ${retryJobId}::uuid
          AND state = 'claimed'
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');

      const [reclaimed] = await transaction<{ response: JsonObject | null }[]>`
        SELECT app.claim_due_oidc_maintenance_v1(
          ${transaction.json({
            kind: "logout_retry",
            observedAt: retryReclaimedAt.toISOString(),
          })}::jsonb
        ) AS response
      `;
      assert(
        reclaimed?.response,
        "stale OIDC logout retry lease was not reclaimed",
      );
      assert.equal(reclaimed.response.kind, "logout_retry");
      assert.equal(reclaimed.response.attempt, 2);
      assert.equal(reclaimed.response.claimVersion, 3);
      const [staleRetrySecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(retrySecretLookup)}::jsonb
        ) AS response
      `;
      assert.equal(
        staleRetrySecret?.response,
        null,
        "maintenance secret replayed after logout claim was reclaimed",
      );
      const reclaimedRetrySecretLookup: JsonObject = {
        ...retrySecretLookup,
        claimVersion: reclaimed.response.claimVersion,
        attempt: reclaimed.response.attempt,
      };
      const [reclaimedRetrySecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(reclaimedRetrySecretLookup)}::jsonb
        ) AS response
      `;
      assert(
        reclaimedRetrySecret?.response,
        "reclaimed logout lease could not load its pinned secret",
      );

      const [oldCompletion] = await transaction<{ applied: boolean }[]>`
        SELECT app.complete_tenant_oidc_logout_retry_v1(
          ${transaction.json({
            jobId: retryJobId,
            attempt: 1,
            expectedVersion: 2,
            outcome: "succeeded",
            completedAt: retryReclaimedAt.toISOString(),
          })}::jsonb
        ) AS applied
      `;
      assert.equal(
        oldCompletion?.applied,
        false,
        "stale retry completion won ABA",
      );

      const [terminalCompletion] = await transaction<{ applied: boolean }[]>`
        SELECT app.complete_tenant_oidc_logout_retry_v1(
          ${transaction.json({
            jobId: retryJobId,
            attempt: 2,
            expectedVersion: 3,
            outcome: "ambiguous",
            completedAt: retryTerminalAt.toISOString(),
          })}::jsonb
        ) AS applied
      `;
      assert.equal(
        terminalCompletion?.applied,
        true,
        "terminal ambiguous outcome was lost after lease expiry",
      );
      const [terminalRetrySecret] = await transaction<
        { response: JsonObject | null }[]
      >`
        SELECT app.load_oidc_maintenance_client_secret_envelope_v1(
          ${transaction.json(reclaimedRetrySecretLookup)}::jsonb
        ) AS response
      `;
      assert.equal(
        terminalRetrySecret?.response,
        null,
        "maintenance secret replayed after logout claim completion",
      );

      const [scrubbed] = await transaction<{ applied: boolean }[]>`
        SELECT app.scrub_oidc_session_material_v1(
          ${transaction.json({
            materialId: fixture.begin,
            operationRunId: fixture.oidcScrub,
            observedAt: scrubbedAt.toISOString(),
          })}::jsonb
        ) AS applied
      `;
      assert.equal(
        scrubbed?.applied,
        true,
        "OIDC material scrub did not commit",
      );

      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      const [lifecycle] = await transaction<
        {
          id_token_key_version: number | null;
          job_state: string;
          logout_disposition: string;
          refresh_generation: string;
          refresh_token_key_version: number | null;
          refresh_state: string;
          revoked: boolean;
          scrubbed: boolean;
        }[]
      >`
        SELECT material.logout_disposition,
          material.refresh_generation::text,
          material.refresh_state,
          material.id_token_key_version,
          material.refresh_token_key_version,
          material.scrubbed_at IS NOT NULL AS scrubbed,
          session.revoked_at IS NOT NULL AS revoked,
          job.state AS job_state
        FROM public.tenant_oidc_session_materials AS material
        JOIN public.auth_sessions AS session ON session.id = material.session_id
        JOIN public.tenant_oidc_logout_retry_jobs AS job
          ON job.tenant_id = material.tenant_id AND job.material_id = material.id
        WHERE material.tenant_id = ${fixture.tenant}::uuid
          AND material.id = ${fixture.begin}::uuid
      `;
      assert.deepEqual(lifecycle, {
        id_token_key_version: null,
        job_state: "dead_letter",
        logout_disposition: "claimed",
        refresh_generation: "2",
        refresh_state: "scrubbed",
        refresh_token_key_version: null,
        revoked: true,
        scrubbed: true,
      });
      throw rollbackOIDCLifecycle;
    }),
    (error: unknown) => error === rollbackOIDCLifecycle,
  );

  const immediatelyStaleCache: JsonObject = {
    retrievedAt: now.toISOString(),
    freshUntil: now.toISOString(),
    cacheable: false,
    mustRevalidate: true,
  };
  const assertOIDCProviderUnchanged = async (): Promise<void> => {
    const provider = await call("get_tenant_federated_auth_provider_v1", {
      providerId: fixture.provider,
    });
    assert.equal(provider.version, 7);
    assert.equal(provider.enabled, true);
    assert.equal(provider.configured, true);
    const configuration = objectValue(
      provider.oidc,
      "OIDC configuration after rejected trust refresh",
    );
    assert.equal(configuration.discoveryRevision, 2);
    assert.equal(configuration.jwksRevision, 2);
    assert.deepEqual(
      await call("begin_tenant_oidc_authentication_v1", oidcBeginLookup),
      oidcRuntimeBeforeRotation,
    );
  };
  await assert.rejects(
    call("commit_tenant_oidc_trust_documents_v1", {
      ...trustCommitRequest,
      ...mutationEnvelope(fixture.adminMembership, "0611"),
      expectedVersion: 7,
      discoveryRevision: 3,
      jwksRevision: 3,
      discoveryCache: immediatelyStaleCache,
      reason: "reject no-cache OIDC discovery on an enabled provider",
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assertOIDCProviderUnchanged();
  await assert.rejects(
    call("commit_tenant_oidc_trust_documents_v1", {
      ...trustCommitRequest,
      ...mutationEnvelope(fixture.adminMembership, "0612"),
      expectedVersion: 7,
      discoveryRevision: 3,
      jwksRevision: 3,
      jwksCache: immediatelyStaleCache,
      reason: "reject no-store OIDC JWKS on an enabled provider",
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assertOIDCProviderUnchanged();
  const rollbackOIDCRetainedKeyRotation = new Error(
    "rollback OIDC retained-key rotation probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await rotateActiveIdentityKeyRetainingPreviousVersion(transaction);
      await setAPIContext(transaction);
      const rotatedProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: fixture.provider },
      );
      assert.equal(
        rotatedProvider.configured,
        true,
        "OIDC configuration stopped being ready after a retained-key rotation",
      );
      assert.deepEqual(
        await callInTransaction(
          transaction,
          "begin_tenant_oidc_authentication_v1",
          oidcBeginLookup,
        ),
        oidcRuntimeBeforeRotation,
      );
      assert.deepEqual(
        await callInTransaction(
          transaction,
          "load_oidc_client_secret_envelope_v1",
          oidcSecretLookup,
        ),
        oidcSecretBeforeRotation,
      );
      throw rollbackOIDCRetainedKeyRotation;
    }),
    (error: unknown) => error === rollbackOIDCRetainedKeyRotation,
  );

  const rollbackExpiredOIDCTrustProbe = new Error(
    "rollback enabled OIDC trust refresh probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_oidc_discovery_snapshots
        SET retrieved_at = statement_timestamp() - interval '2 hours',
            fresh_until = statement_timestamp() - interval '1 hour'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND revision = 2
      `;
      await transaction`
        UPDATE public.tenant_oidc_jwks_snapshots
        SET retrieved_at = statement_timestamp() - interval '2 hours',
            fresh_until = statement_timestamp() - interval '1 hour'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${fixture.provider}::uuid
          AND revision = 2
      `;
      await setAPIContext(transaction);
      const expiredProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: fixture.provider },
      );
      assert.equal(expiredProvider.enabled, true);
      assert.equal(expiredProvider.configured, false);
      const listedExpiredProvider = (
        await listProvidersInTransaction(transaction)
      ).find((provider) => provider.id === fixture.provider);
      assert(
        listedExpiredProvider,
        "expired OIDC provider was omitted from list",
      );
      assert.equal(listedExpiredProvider.enabled, true);
      assert.equal(listedExpiredProvider.configured, false);

      const recoveredTrust = await callInTransaction(
        transaction,
        "commit_tenant_oidc_trust_documents_v1",
        {
          ...trustCommitRequest,
          ...mutationEnvelope(fixture.adminMembership, "0610"),
          expectedVersion: 7,
          discoveryRevision: 3,
          jwksRevision: 3,
          reason: "recover an enabled OIDC provider after trust expiry",
        },
      );
      assert.deepEqual(recoveredTrust, {
        providerId: fixture.provider,
        providerVersion: 8,
        discoveryRevision: 3,
        jwksRevision: 3,
        keyCount: 1,
      });
      const recoveredProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: fixture.provider },
      );
      assert.equal(recoveredProvider.enabled, true);
      assert.equal(recoveredProvider.configured, true);
      throw rollbackExpiredOIDCTrustProbe;
    }),
    (error: unknown) => error === rollbackExpiredOIDCTrustProbe,
  );

  const disabled = await call("update_tenant_federated_auth_provider_v1", {
    ...updateBase,
    ...mutationEnvelope(fixture.adminMembership, "0417"),
    expectedVersion: 7,
    enabled: false,
    jitMode: "disabled",
    reason: "disable before protected material retirement",
  });
  assert.equal(disabled.version, 8);
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected, created_at
      ) VALUES (${fixture.accessSource}::uuid, ${fixture.tenant}::uuid,
        'identity_provider_access',
        ${`identity_provider_access:${fixture.binding}:2`}, true, false,
        statement_timestamp())
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs (
        id, tenant_id, binding_id, provider_id, source_id, sequence,
        started_by_membership_id, started_at, version
      ) VALUES (${fixture.accessEpoch}::uuid, ${fixture.tenant}::uuid,
        ${fixture.binding}::uuid, ${fixture.provider}::uuid,
        ${fixture.accessSource}::uuid, 2, ${fixture.adminMembership}::uuid,
        statement_timestamp(), 1)
    `;
    await transaction`
      UPDATE public.tenant_auth_provider_bindings
      SET enabled = true, current_access_epoch_id = ${fixture.accessEpoch}::uuid,
          updated_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${fixture.binding}::uuid
    `;
  });
  await assert.rejects(
    call("clear_tenant_oidc_client_secret_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0418"),
      providerId: fixture.provider,
      expectedVersion: 8,
      expectedRevision: 3,
      reason: "must fail while binding remains enabled",
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    call("update_tenant_federated_auth_provider_v1", {
      ...updateBase,
      ...mutationEnvelope(fixture.adminMembership, "0419"),
      expectedVersion: 8,
      enabled: false,
      jitMode: "disabled",
      description: "A configuration change while the binding is live.",
      oidc: {
        ...oidc,
        clientId: "tenant-federation-runtime-rotated",
      },
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  // SAML_ADMINISTRATION_RUNTIME_APPEND_BOUNDARY

  const samlFixture = {
    command: "01a09e00-1000-7000-8000-000000000501",
    provider: "01a09e00-1000-7000-8000-000000000502",
    binding: "01a09e00-1000-7000-8000-000000000503",
    key: "01a09e00-1000-7000-8000-000000000504",
    blockedKey: "01a09e00-1000-7000-8000-000000000505",
    externalIdentity: "01a09e00-1000-7000-8000-000000000506",
    session: "01a09e00-1000-7000-8000-000000000507",
    sessionFamily: "01a09e00-1000-7000-8000-000000000508",
    accessSource: "01a09e00-1000-7000-8000-000000000509",
    accessEpoch: "01a09e00-1000-7000-8000-00000000050a",
    begin: "01a09e00-1000-7000-8000-00000000050b",
  } as const;
  const samlConfiguration: JsonObject = {
    expectedEntityId: "https://idp.example.invalid/tenant-saml",
    redirectSignatureAlgorithm:
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    signaturePolicy: "both",
    encryptionPolicy: "disabled",
    requestedAuthnContexts: [
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    ],
    subjectSource: "persistent_nameid",
    subjectAttributeName: null,
    subjectAttributeNameFormat: null,
    clockSkewSeconds: 120,
    maxAuthenticationAgeSeconds: 3600,
  };
  const samlCreateRequest: JsonObject = {
    ...mutationEnvelope(fixture.adminMembership, "0501"),
    commandId: samlFixture.command,
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
    idempotencyDigest: digest("tenant-saml-administration-idempotency"),
    requestDigest: digest("tenant-saml-administration-semantic-request"),
    kind: "saml",
    key: "runtime_saml",
    loginKey: "runtime-saml",
    displayName: "Runtime SAML",
    description: "Tenant SAML administration runtime proof.",
    jitMode: "create",
    noMatchPolicy: "deny",
    oidc: null,
    saml: samlConfiguration,
    oidcRedirectUri:
      "https://soc.example.invalid/api/v1/auth/federated/oidc/callback",
    samlAcsUrl: "https://soc.example.invalid/api/v1/auth/federated/saml/acs",
    samlSpMetadataBaseUrl:
      "https://soc.example.invalid/api/v1/auth/federated/saml",
    reason: "create the tenant SAML runtime proof provider",
  };
  const samlCreated = await call(
    "create_tenant_federated_auth_provider_v1",
    samlCreateRequest,
  );
  assert.equal(samlCreated.replayed, false);
  assert.equal(
    objectValue(samlCreated.provider, "created SAML provider").configured,
    false,
  );
  assert.equal(
    objectValue(samlCreated.provider, "created SAML provider").kind,
    "saml",
  );
  const [samlReplayStateBefore] = await sql<
    {
      audit_events: string;
      certificate_rows: string;
      key_rows: string;
      metadata_rows: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND resource_id = ${samlFixture.provider}::uuid) AS audit_events,
      (SELECT count(*)::text FROM public.tenant_saml_metadata_snapshots
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND provider_id = ${samlFixture.provider}::uuid) AS metadata_rows,
      (SELECT count(*)::text FROM public.tenant_saml_sp_keys
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND provider_id = ${samlFixture.provider}::uuid) AS key_rows,
      (SELECT count(*)::text
       FROM public.tenant_saml_sp_certificates AS certificate
       JOIN public.tenant_saml_sp_keys AS sp_key
         ON sp_key.tenant_id = certificate.tenant_id
        AND sp_key.id = certificate.key_id
       WHERE sp_key.tenant_id = ${fixture.tenant}::uuid
         AND sp_key.provider_id = ${samlFixture.provider}::uuid) AS certificate_rows
  `;
  const samlReplayed = await call(
    "create_tenant_federated_auth_provider_v1",
    samlCreateRequest,
  );
  assert.equal(samlReplayed.replayed, true);
  const samlCreatedProvider = objectValue(
    samlCreated.provider,
    "created SAML provider",
  );
  const samlReplayedProvider = objectValue(
    samlReplayed.provider,
    "replayed SAML provider",
  );
  assert.equal(samlReplayedProvider.id, samlFixture.provider);
  assert.equal(samlReplayedProvider.version, samlCreatedProvider.version);
  const samlCreatedBinding = objectValue(
    samlCreatedProvider.binding,
    "created SAML binding",
  );
  const samlReplayedBinding = objectValue(
    samlReplayedProvider.binding,
    "replayed SAML binding",
  );
  assert.equal(samlReplayedBinding.id, samlFixture.binding);
  assert.equal(samlReplayedBinding.version, samlCreatedBinding.version);
  const [samlReplayStateAfter] = await sql<
    {
      audit_events: string;
      certificate_rows: string;
      key_rows: string;
      metadata_rows: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND resource_id = ${samlFixture.provider}::uuid) AS audit_events,
      (SELECT count(*)::text FROM public.tenant_saml_metadata_snapshots
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND provider_id = ${samlFixture.provider}::uuid) AS metadata_rows,
      (SELECT count(*)::text FROM public.tenant_saml_sp_keys
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND provider_id = ${samlFixture.provider}::uuid) AS key_rows,
      (SELECT count(*)::text
       FROM public.tenant_saml_sp_certificates AS certificate
       JOIN public.tenant_saml_sp_keys AS sp_key
         ON sp_key.tenant_id = certificate.tenant_id
        AND sp_key.id = certificate.key_id
       WHERE sp_key.tenant_id = ${fixture.tenant}::uuid
         AND sp_key.provider_id = ${samlFixture.provider}::uuid) AS certificate_rows
  `;
  assert.deepEqual(samlReplayStateAfter, samlReplayStateBefore);

  await assert.rejects(
    call(
      "prepare_tenant_saml_metadata_v1",
      {
        membershipId: fixture.foreignMembership,
        providerId: samlFixture.provider,
        expectedVersion: 1,
      },
      fixture.foreignTenant,
      fixture.foreignUser,
    ),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    call("prepare_tenant_saml_metadata_v1", {
      membershipId: fixture.foreignMembership,
      providerId: samlFixture.provider,
      expectedVersion: 1,
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    call("prepare_tenant_saml_metadata_v1", {
      membershipId: fixture.adminMembership,
      providerId: fixture.provider,
      expectedVersion: 1,
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await setAPIContext(transaction);
      await transaction`SELECT ciphertext FROM public.tenant_saml_sp_keys`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const metadataOne = Buffer.from(
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.invalid/tenant-saml"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.invalid/SingleLogoutService/callback"/></md:IDPSSODescriptor></md:EntityDescriptor>',
    "utf8",
  );
  const metadataTwo = Buffer.from(
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.invalid/tenant-saml"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.invalid/logout"/></md:IDPSSODescriptor></md:EntityDescriptor>',
    "utf8",
  );
  const metadataOneDigest = createHash("sha256")
    .update(metadataOne)
    .digest("base64");
  const metadataOneDigestHex = createHash("sha256")
    .update(metadataOne)
    .digest("hex");
  const metadataTwoDigest = createHash("sha256")
    .update(metadataTwo)
    .digest("base64");
  const metadataTwoDigestHex = createHash("sha256")
    .update(metadataTwo)
    .digest("hex");
  const metadataPreparation = await call("prepare_tenant_saml_metadata_v1", {
    membershipId: fixture.adminMembership,
    providerId: samlFixture.provider,
    expectedVersion: 1,
  });
  assert.equal(metadataPreparation.tenantId, fixture.tenant);
  assert.equal(metadataPreparation.providerId, samlFixture.provider);
  assert.equal(metadataPreparation.bindingId, samlFixture.binding);
  assert.equal(metadataPreparation.currentMetadataRevision, 1);
  assert.equal(metadataPreparation.current, null);

  const expiredRetrievedAt = new Date(now.getTime() - 2 * 60 * 60 * 1000);
  const expiredMaximumValidUntil = new Date(now.getTime() - 60 * 60 * 1000);
  await assert.rejects(
    call("replace_tenant_saml_metadata_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0599"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 1,
      expectedRevision: 2,
      document: metadataOne.toString("base64"),
      digest: metadataOneDigest,
      retrievedAt: expiredRetrievedAt.toISOString(),
      maximumValidUntil: expiredMaximumValidUntil.toISOString(),
      protectedApproval: false,
      reason: "reject already expired tenant SAML metadata",
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    call("replace_tenant_saml_metadata_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0598"),
      providerId: samlFixture.provider,
      bindingId: fixture.binding,
      expectedVersion: 1,
      expectedRevision: 2,
      document: metadataOne.toString("base64"),
      digest: metadataOneDigest,
      retrievedAt: now.toISOString(),
      maximumValidUntil: later.toISOString(),
      protectedApproval: false,
      reason: "reject a substituted tenant SAML binding",
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const metadataReceipt = await call("replace_tenant_saml_metadata_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0502"),
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
    expectedVersion: 1,
    expectedRevision: 2,
    document: metadataOne.toString("base64"),
    digest: metadataOneDigest,
    retrievedAt: now.toISOString(),
    maximumValidUntil: later.toISOString(),
    protectedApproval: false,
    reason: "pin validated tenant SAML metadata",
  });
  assert.deepEqual(metadataReceipt, {
    providerId: samlFixture.provider,
    providerVersion: 2,
    materialRevision: 2,
  });
  await assert.rejects(
    call("replace_tenant_saml_metadata_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0503"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 1,
      expectedRevision: 3,
      document: metadataTwo.toString("base64"),
      digest: metadataTwoDigest,
      retrievedAt: now.toISOString(),
      maximumValidUntil: later.toISOString(),
      protectedApproval: true,
      reason: "reject stale tenant SAML metadata CAS",
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    call("replace_tenant_saml_metadata_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0504"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 2,
      expectedRevision: 3,
      document: metadataTwo.toString("base64"),
      digest: Buffer.alloc(32, 0x7f).toString("base64"),
      retrievedAt: now.toISOString(),
      maximumValidUntil: later.toISOString(),
      protectedApproval: true,
      reason: "reject tampered tenant SAML metadata digest",
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const credentialPreparation = await call(
    "prepare_tenant_saml_sp_credential_v1",
    {
      membershipId: fixture.adminMembership,
      providerId: samlFixture.provider,
      expectedVersion: 2,
    },
  );
  assert.equal(credentialPreparation.currentCredentialRevision, 1);
  assert.equal(credentialPreparation.credentialPresent, false);
  assert.equal(credentialPreparation.providerEnabled, false);
  assert.equal(credentialPreparation.bindingEnabled, false);
  assert.equal(
    credentialPreparation.spEntityId,
    "https://soc.example.invalid/api/v1/auth/federated/saml/federation-admin-runtime/runtime-saml/metadata",
  );
  const certificate = Buffer.from(
    "tenant-saml-public-certificate-der-runtime-proof",
    "utf8",
  );
  const credentialEnvelope = Buffer.alloc(64, 0x73);
  const credentialRequest = (
    expectedVersion: number,
    keyId: string,
    suffix: string,
  ): JsonObject => ({
    ...mutationEnvelope(fixture.adminMembership, suffix),
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
    expectedVersion,
    expectedRevision: 2,
    keyId,
    keyVersion: 1,
    envelopeCiphertext: credentialEnvelope.toString("base64"),
    certificateDer: [certificate.toString("base64")],
    certificateValidity: [
      { notBefore: now.toISOString(), notAfter: later.toISOString() },
    ],
    reason: "install server-generated tenant SAML SP credential",
  });
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", {
      ...credentialRequest(2, samlFixture.key, "0505"),
      envelopeCiphertext: Buffer.alloc(28, 0x73).toString("base64"),
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", {
      ...credentialRequest(2, samlFixture.key, "0597"),
      bindingId: fixture.binding,
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", {
      ...credentialRequest(2, samlFixture.key, "0506"),
      certificateDer: [
        certificate.toString("base64"),
        certificate.toString("base64"),
      ],
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const credentialReceipt = await call(
    "replace_tenant_saml_sp_credential_v1",
    credentialRequest(2, samlFixture.key, "0507"),
  );
  assert.deepEqual(credentialReceipt, {
    providerId: samlFixture.provider,
    providerVersion: 3,
    materialRevision: 2,
  });
  const samlWithoutLogout = await call(
    "get_tenant_federated_auth_provider_v1",
    { providerId: samlFixture.provider },
  );
  assert.equal(
    objectValue(samlWithoutLogout.saml, "SAML configuration without logout")
      .singleLogoutConfigured,
    false,
    "a URL containing SingleLogoutService produced a false-positive element match",
  );
  const malformedLogoutProbe = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    const [row] = await transaction<{ configured: boolean }[]>`
      SELECT app.private_tenant_saml_single_logout_configured_v1(
        ${Buffer.from([0xff])}::bytea
      ) AS configured
    `;
    return row?.configured;
  });
  assert.equal(
    malformedLogoutProbe,
    false,
    "invalid UTF-8 SAML metadata did not fail closed",
  );
  await assertTenantFederationRetainedKeyRequired(async (transaction) => {
    await transaction`
      UPDATE public.tenant_oidc_client_secrets
      SET retired_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND provider_id = ${fixture.provider}::uuid
        AND retired_at IS NULL
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identity_aliases (
        id, tenant_id, provider_id, external_identity_id,
        key_version, subject_digest
      ) VALUES (
        ${fixture.keyringAlias}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.externalIdentity}::uuid,
        2, ${Buffer.alloc(32, 0x73)}
      )
    `;
    await transaction`
      UPDATE public.tenant_federated_external_identities
      SET key_version = 2,
          retired_at = statement_timestamp(),
          updated_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.externalIdentity}::uuid
    `;
  });

  const loadPublicSAMLMetadata = async (
    tenantSlug: string,
    loginKey: string,
  ): Promise<JsonObject> =>
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [row] = await transaction<{ response: JsonObject }[]>`
        SELECT app.get_tenant_saml_sp_metadata_v1(
          ${transaction.json({ tenantSlug, loginKey })}::jsonb
        ) AS response
      `;
      assert(row?.response, "tenant SAML public metadata returned no object");
      return row.response;
    });
  assert.deepEqual(
    await loadPublicSAMLMetadata("federation-admin-runtime", "runtime-saml"),
    { found: false },
  );
  assert.deepEqual(
    await loadPublicSAMLMetadata("federation-admin-runtime", "missing-saml"),
    { found: false },
  );
  assert.deepEqual(
    await loadPublicSAMLMetadata("federation-admin-foreign", "runtime-saml"),
    { found: false },
  );

  const samlUpdateBase: JsonObject = {
    ...mutationEnvelope(fixture.adminMembership, "0508"),
    providerId: samlFixture.provider,
    expectedVersion: 3,
    displayName: "Runtime SAML",
    description: "Tenant SAML administration runtime proof.",
    enabled: true,
    jitMode: "disabled",
    noMatchPolicy: "deny",
    oidc: null,
    saml: samlConfiguration,
    oidcRedirectUri:
      "https://soc.example.invalid/api/v1/auth/federated/oidc/callback",
    samlAcsUrl: "https://soc.example.invalid/api/v1/auth/federated/saml/acs",
    samlSpMetadataBaseUrl:
      "https://soc.example.invalid/api/v1/auth/federated/saml",
    reason: "enable fully configured tenant SAML provider",
  };
  await assertNotReadyCannotEnable(
    samlFixture.provider,
    {
      ...samlUpdateBase,
      ...mutationEnvelope(fixture.adminMembership, "0604"),
      reason: "reject SAML enable with a retired envelope key",
    },
    async (transaction) => {
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = false, retired_at = statement_timestamp()
        WHERE key_version = 1
      `;
    },
  );
  const samlEnabled = await call(
    "update_tenant_federated_auth_provider_v1",
    samlUpdateBase,
  );
  assert.equal(samlEnabled.version, 4);
  assert.equal(samlEnabled.enabled, true);
  assert.equal(
    objectValue(samlEnabled.binding, "enabled SAML binding").enabled,
    true,
  );
  assert.equal(samlEnabled.configured, true);

  const publicMetadata = await loadPublicSAMLMetadata(
    "federation-admin-runtime",
    "runtime-saml",
  );
  assert.equal(publicMetadata.found, true);
  const publicProjection = objectValue(
    publicMetadata.projection,
    "public SAML metadata projection",
  );
  assert.equal(publicProjection.tenantId, fixture.tenant);
  assert.equal(publicProjection.providerId, samlFixture.provider);
  assert.equal(publicProjection.bindingId, samlFixture.binding);
  assert.equal(publicProjection.spKeyRevision, 2);
  const publicCertificates = arrayValue(
    publicProjection.certificates,
    "public SAML certificates",
  ).map((entry) => objectValue(entry, "public SAML certificate"));
  assert.equal(publicCertificates.length, 1);
  assert.equal(publicCertificates[0]?.certificateSequence, 0);
  assert.equal(
    publicCertificates[0]?.certificateDer,
    certificate.toString("base64"),
  );
  const publicSerialized = JSON.stringify(publicMetadata).toLowerCase();
  assert(!publicSerialized.includes("ciphertext"));
  assert(!publicSerialized.includes("private"));
  assert(!publicSerialized.includes("envelope"));
  assert(
    !publicSerialized.includes(
      credentialEnvelope.toString("base64").toLowerCase(),
    ),
  );

  const samlBeginLookup = authenticationBeginLookup(
    samlFixture.begin,
    "runtime-saml",
  );
  const samlProviderIdentity: JsonObject = {
    scope: "tenant",
    tenantId: fixture.tenant,
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
  };
  const samlKeyLookup: JsonObject = {
    provider: samlProviderIdentity,
    revision: 2,
  };
  const samlRuntimeBeforeRotation = await call(
    "begin_tenant_saml_authentication_v1",
    samlBeginLookup,
  );
  const samlKeyBeforeRotation = await call(
    "load_saml_sp_key_envelope_v1",
    samlKeyLookup,
  );
  assert.equal(samlKeyBeforeRotation.envelopeKeyVersion, 1);
  const stablePublicMetadataBeforeRotation: JsonObject = {
    ...publicMetadata,
    projection: { ...publicProjection },
  };
  delete objectValue(
    stablePublicMetadataBeforeRotation.projection,
    "stable public SAML metadata projection",
  ).observedAt;
  const rollbackSAMLRetainedKeyRotation = new Error(
    "rollback SAML retained-key rotation probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await rotateActiveIdentityKeyRetainingPreviousVersion(transaction);
      await setAPIContext(transaction);
      const rotatedProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: samlFixture.provider },
      );
      assert.equal(
        rotatedProvider.configured,
        true,
        "SAML configuration stopped being ready after a retained-key rotation",
      );
      assert.deepEqual(
        await callInTransaction(
          transaction,
          "begin_tenant_saml_authentication_v1",
          samlBeginLookup,
        ),
        samlRuntimeBeforeRotation,
      );
      assert.deepEqual(
        await callInTransaction(
          transaction,
          "load_saml_sp_key_envelope_v1",
          samlKeyLookup,
        ),
        samlKeyBeforeRotation,
      );
      const publicMetadataDuringRotation = await callInTransaction(
        transaction,
        "get_tenant_saml_sp_metadata_v1",
        { tenantSlug: "federation-admin-runtime", loginKey: "runtime-saml" },
      );
      const stablePublicMetadataDuringRotation: JsonObject = {
        ...publicMetadataDuringRotation,
        projection: {
          ...objectValue(
            publicMetadataDuringRotation.projection,
            "rotated public SAML metadata projection",
          ),
        },
      };
      delete objectValue(
        stablePublicMetadataDuringRotation.projection,
        "stable rotated public SAML metadata projection",
      ).observedAt;
      assert.deepEqual(
        stablePublicMetadataDuringRotation,
        stablePublicMetadataBeforeRotation,
      );
      throw rollbackSAMLRetainedKeyRotation;
    }),
    (error: unknown) => error === rollbackSAMLRetainedKeyRotation,
  );

  const rollbackExpiredMetadataProbe = new Error(
    "rollback tenant SAML expired metadata probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.tenant_saml_metadata_snapshots (
          tenant_id, provider_id, revision, document, document_digest,
          retrieved_at, maximum_valid_until
        ) VALUES (
          ${fixture.tenant}::uuid, ${samlFixture.provider}::uuid, 3,
          ${metadataOne}, ${Buffer.from(metadataOneDigest, "base64")},
          ${expiredRetrievedAt.toISOString()}::timestamptz,
          ${expiredMaximumValidUntil.toISOString()}::timestamptz
        )
      `;
      await transaction`
        UPDATE public.tenant_saml_provider_configurations
        SET metadata_revision = 3
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND provider_id = ${samlFixture.provider}::uuid
      `;
      await setAPIContext(transaction);
      const expiredProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: samlFixture.provider },
      );
      assert.equal(expiredProvider.enabled, true);
      assert.equal(expiredProvider.configured, false);
      const listedExpiredProvider = (
        await listProvidersInTransaction(transaction)
      ).find((provider) => provider.id === samlFixture.provider);
      assert(
        listedExpiredProvider,
        "expired SAML provider was omitted from list",
      );
      assert.equal(listedExpiredProvider.enabled, true);
      assert.equal(listedExpiredProvider.configured, false);
      const [expiredProjection] = await transaction<{ response: JsonObject }[]>`
        SELECT app.get_tenant_saml_sp_metadata_v1(
          ${transaction.json({
            tenantSlug: "federation-admin-runtime",
            loginKey: "runtime-saml",
          })}::jsonb
        ) AS response
      `;
      assert.deepEqual(expiredProjection?.response, { found: false });

      const [expiredPreparation] = await transaction<
        { response: JsonObject }[]
      >`
        SELECT app.prepare_tenant_saml_metadata_v1(
          ${transaction.json({
            membershipId: fixture.adminMembership,
            providerId: samlFixture.provider,
            expectedVersion: 4,
          })}::jsonb
        ) AS response
      `;
      assert.equal(expiredPreparation?.response.currentMetadataRevision, 3);
      const expiredCurrent = objectValue(
        expiredPreparation?.response.current,
        "expired current SAML metadata",
      );
      assert.equal(expiredCurrent.revision, 3);
      assert.equal(expiredCurrent.digest, metadataOneDigest);

      const [recoveredMetadata] = await transaction<{ response: JsonObject }[]>`
        SELECT app.replace_tenant_saml_metadata_v1(
          ${transaction.json({
            ...mutationEnvelope(fixture.adminMembership, "0596"),
            providerId: samlFixture.provider,
            bindingId: samlFixture.binding,
            expectedVersion: 4,
            expectedRevision: 4,
            document: metadataTwo.toString("base64"),
            digest: metadataTwoDigest,
            retrievedAt: now.toISOString(),
            maximumValidUntil: later.toISOString(),
            protectedApproval: true,
            reason: "recover an expired tenant SAML metadata snapshot",
          })}::jsonb
        ) AS response
      `;
      assert.deepEqual(recoveredMetadata?.response, {
        providerId: samlFixture.provider,
        providerVersion: 5,
        materialRevision: 4,
      });
      const [recoveredProjection] = await transaction<
        { response: JsonObject }[]
      >`
        SELECT app.get_tenant_saml_sp_metadata_v1(
          ${transaction.json({
            tenantSlug: "federation-admin-runtime",
            loginKey: "runtime-saml",
          })}::jsonb
        ) AS response
      `;
      assert.equal(recoveredProjection?.response.found, true);
      const recoveredProvider = await callInTransaction(
        transaction,
        "get_tenant_federated_auth_provider_v1",
        { providerId: samlFixture.provider },
      );
      assert.equal(recoveredProvider.enabled, true);
      assert.equal(recoveredProvider.configured, true);
      throw rollbackExpiredMetadataProbe;
    }),
    (error: unknown) => error === rollbackExpiredMetadataProbe,
  );

  const enabledCredentialRequest = {
    ...credentialRequest(4, samlFixture.blockedKey, "0509"),
    expectedRevision: 3,
  };
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", enabledCredentialRequest),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    call("clear_tenant_saml_sp_credential_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0510"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 4,
      expectedRevision: 3,
      reason: "reject clearing a live tenant SAML credential",
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_federated_external_identities (
        id, tenant_id, provider_id, binding_id, user_id, subject_format,
        subject_ciphertext, subject_nonce, key_version,
        admitted_configuration_revision, last_observed_at, version,
        created_at, updated_at
      ) VALUES (${samlFixture.externalIdentity}::uuid, ${fixture.tenant}::uuid,
        ${samlFixture.provider}::uuid, ${samlFixture.binding}::uuid,
        ${fixture.sessionUser}::uuid, 'utf8_exact', ${Buffer.alloc(32, 0x81)}::bytea,
        ${Buffer.alloc(12, 0x82)}::bytea, 1, 3, ${now}, 1, ${now}, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, last_seen_at,
        idle_expires_at, absolute_expires_at, created_at
      ) VALUES (${samlFixture.session}::uuid, ${fixture.sessionUser}::uuid,
        ${samlFixture.sessionFamily}::uuid, ${fixture.tenant}::uuid,
        ${Buffer.alloc(32, 0x83)}::bytea, ${Buffer.alloc(32, 0x84)}::bytea,
        'saml', ${now}, ${later}, ${later}, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id, tenant_id, user_id, session_version, identity_epoch,
        recovery_restricted, audience, primary_kind,
        session_invalidation_epoch, issued_at
      ) VALUES (${samlFixture.session}::uuid, ${fixture.tenant}::uuid,
        ${fixture.sessionUser}::uuid, 1, 1, false, 'api', 'tenant_provider', 1, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id, session_id, user_id, primary_kind, authentication_method,
        provider_id, binding_id, provider_kind, external_identity_id,
        external_identity_revision, trust_rule_revision, authenticated_at
      ) VALUES (${fixture.tenant}::uuid, ${samlFixture.session}::uuid,
        ${fixture.sessionUser}::uuid, 'tenant_provider', 'saml',
        ${samlFixture.provider}::uuid, ${samlFixture.binding}::uuid, 'saml',
        ${samlFixture.externalIdentity}::uuid, 1, 4, ${now})
    `;
  });

  const rolloverReceipt = await call("replace_tenant_saml_metadata_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0511"),
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
    expectedVersion: 4,
    expectedRevision: 3,
    document: metadataTwo.toString("base64"),
    digest: metadataTwoDigest,
    retrievedAt: now.toISOString(),
    maximumValidUntil: later.toISOString(),
    protectedApproval: true,
    reason: "approve protected tenant SAML trust reset",
  });
  assert.equal(rolloverReceipt.providerVersion, 5);
  assert.equal(rolloverReceipt.materialRevision, 3);
  const samlWithLogout = await call("get_tenant_federated_auth_provider_v1", {
    providerId: samlFixture.provider,
  });
  assert.equal(
    objectValue(samlWithLogout.saml, "SAML configuration with logout")
      .singleLogoutConfigured,
    true,
    "a namespaced SAML SingleLogoutService element was not detected",
  );
  const [revokedSAMLSession] = await sql<{ revoked_at: Date | null }[]>`
    SELECT revoked_at FROM public.auth_sessions
    WHERE id = ${samlFixture.session}::uuid
  `;
  assert(
    revokedSAMLSession?.revoked_at,
    "SAML metadata trust replacement did not revoke dependent sessions",
  );

  const samlDisabled = await call("update_tenant_federated_auth_provider_v1", {
    ...samlUpdateBase,
    ...mutationEnvelope(fixture.adminMembership, "0512"),
    expectedVersion: 5,
    enabled: false,
    reason: "disable before tenant SAML credential retirement",
  });
  assert.equal(samlDisabled.version, 6);
  assert.deepEqual(
    await loadPublicSAMLMetadata("federation-admin-runtime", "runtime-saml"),
    { found: false },
  );

  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected, created_at
      ) VALUES (${samlFixture.accessSource}::uuid, ${fixture.tenant}::uuid,
        'identity_provider_access',
        ${`identity_provider_access:${samlFixture.binding}:2`}, true, false,
        statement_timestamp())
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs (
        id, tenant_id, binding_id, provider_id, source_id, sequence,
        started_by_membership_id, started_at, version
      ) VALUES (${samlFixture.accessEpoch}::uuid, ${fixture.tenant}::uuid,
        ${samlFixture.binding}::uuid, ${samlFixture.provider}::uuid,
        ${samlFixture.accessSource}::uuid, 2, ${fixture.adminMembership}::uuid,
        statement_timestamp(), 1)
    `;
    await transaction`
      UPDATE public.tenant_auth_provider_bindings
      SET enabled = true,
          current_access_epoch_id = ${samlFixture.accessEpoch}::uuid,
          updated_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${samlFixture.binding}::uuid
    `;
  });
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", {
      ...enabledCredentialRequest,
      ...mutationEnvelope(fixture.adminMembership, "0513"),
      expectedVersion: 6,
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    call("clear_tenant_saml_sp_credential_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0514"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 6,
      expectedRevision: 3,
      reason: "reject clear while only the binding is enabled",
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_auth_provider_bindings
      SET enabled = false, current_access_epoch_id = NULL,
          updated_at = statement_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${samlFixture.binding}::uuid
    `;
    await transaction`
      UPDATE public.tenant_auth_providers SET enabled = true
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${samlFixture.provider}::uuid
    `;
  });
  await assert.rejects(
    call("replace_tenant_saml_sp_credential_v1", {
      ...enabledCredentialRequest,
      ...mutationEnvelope(fixture.adminMembership, "0515"),
      expectedVersion: 6,
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    call("clear_tenant_saml_sp_credential_v1", {
      ...mutationEnvelope(fixture.adminMembership, "0516"),
      providerId: samlFixture.provider,
      bindingId: samlFixture.binding,
      expectedVersion: 6,
      expectedRevision: 3,
      reason: "reject clear while only the provider is enabled",
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_auth_providers SET enabled = false
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${samlFixture.provider}::uuid
    `;
  });

  const clearReceipt = await call("clear_tenant_saml_sp_credential_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0517"),
    providerId: samlFixture.provider,
    bindingId: samlFixture.binding,
    expectedVersion: 6,
    expectedRevision: 3,
    reason: "retire the disabled tenant SAML credential",
  });
  assert.deepEqual(clearReceipt, {
    providerId: samlFixture.provider,
    providerVersion: 7,
    materialRevision: 3,
  });
  const archived = await call("archive_tenant_federated_auth_provider_v1", {
    ...mutationEnvelope(fixture.adminMembership, "0518"),
    providerId: samlFixture.provider,
    expectedVersion: 7,
    reason: "archive the disabled tenant SAML provider",
  });
  assert.equal(archived.version, 8);
  assert.deepEqual(
    await loadPublicSAMLMetadata("federation-admin-runtime", "runtime-saml"),
    { found: false },
  );

  const [materialState] = await sql<
    {
      metadata_revision: string;
      sp_key_revision: string;
      configuration_version: string;
      policy_configuration_revision: string;
      current_keys: string;
      retired_keys: string;
    }[]
  >`
    SELECT configuration.metadata_revision::text,
      configuration.sp_key_revision::text,
      configuration.version::text AS configuration_version,
      policy.configuration_revision::text AS policy_configuration_revision,
      (SELECT count(*)::text FROM public.tenant_saml_sp_keys AS current_key
       WHERE current_key.tenant_id = configuration.tenant_id
         AND current_key.provider_id = configuration.provider_id
         AND current_key.retired_at IS NULL) AS current_keys,
      (SELECT count(*)::text FROM public.tenant_saml_sp_keys AS retired_key
       WHERE retired_key.tenant_id = configuration.tenant_id
         AND retired_key.provider_id = configuration.provider_id
         AND retired_key.retired_at IS NOT NULL) AS retired_keys
    FROM public.tenant_saml_provider_configurations AS configuration
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = configuration.tenant_id
     AND policy.provider_id = configuration.provider_id
    WHERE configuration.tenant_id = ${fixture.tenant}::uuid
      AND configuration.provider_id = ${samlFixture.provider}::uuid
  `;
  assert.deepEqual(materialState, {
    metadata_revision: "3",
    sp_key_revision: "3",
    configuration_version: "5",
    policy_configuration_revision: "5",
    current_keys: "0",
    retired_keys: "1",
  });

  const materialCanaries = [
    metadataOne.toString("base64"),
    metadataTwo.toString("base64"),
    credentialEnvelope.toString("base64"),
    certificate.toString("base64"),
  ];
  const materialAudits = await sql<
    {
      action: string;
      before: JsonValue;
      after: JsonValue;
      metadata: JsonValue;
    }[]
  >`
    SELECT action, before, after, metadata
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND resource_id = ${samlFixture.provider}::uuid
      AND action IN (
        'tenant.identity_provider.saml_metadata.replaced',
        'tenant.identity_provider.saml_sp_credential.replaced',
        'tenant.identity_provider.saml_sp_credential.cleared'
      )
    ORDER BY sequence
  `;
  assert.equal(materialAudits.length, 4);
  assert.equal(
    materialAudits.filter(
      (event) =>
        event.action === "tenant.identity_provider.saml_metadata.replaced",
    ).length,
    2,
  );
  const auditTranscript = JSON.stringify(materialAudits);
  for (const canary of materialCanaries) {
    assert(!auditTranscript.includes(canary), "SAML audit leaked raw material");
  }
  assert(!auditTranscript.toLowerCase().includes("ciphertext"));
  assert(!auditTranscript.toLowerCase().includes("certificate_der"));
  assert(auditTranscript.includes(metadataOneDigestHex));
  assert(auditTranscript.includes(metadataTwoDigestHex));

  const samlFunctions = [
    "app.prepare_tenant_saml_metadata_v1(jsonb)",
    "app.replace_tenant_saml_metadata_v1(jsonb)",
    "app.prepare_tenant_saml_sp_credential_v1(jsonb)",
    "app.replace_tenant_saml_sp_credential_v1(jsonb)",
    "app.clear_tenant_saml_sp_credential_v1(jsonb)",
    "app.get_tenant_saml_sp_metadata_v1(jsonb)",
  ];
  const samlFunctionACLs = await Promise.all(
    samlFunctions.map(async (signature) => {
      const [functionACL] = await sql<
        {
          owner: string;
          security_definer: boolean;
          api_execute: boolean;
          forbidden_execute: boolean;
          public_execute: boolean;
        }[]
      >`
      SELECT pg_get_userbyid(procedure.proowner) AS owner,
        procedure.prosecdef AS security_definer,
        has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE') AS api_execute,
        has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE')
          OR has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE')
          OR has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
          AS forbidden_execute,
        EXISTS (
          SELECT 1
          FROM aclexplode(coalesce(procedure.proacl, acldefault('f', procedure.proowner))) AS acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) AS public_execute
      FROM pg_proc AS procedure
      WHERE procedure.oid = to_regprocedure(${signature})
    `;
      return { functionACL, signature };
    }),
  );
  for (const { functionACL, signature } of samlFunctionACLs) {
    assert.deepEqual(
      functionACL,
      {
        owner: "periapsis_migrator",
        security_definer: true,
        api_execute: true,
        forbidden_execute: false,
        public_execute: false,
      },
      `${signature} must remain API-only and migrator-owned`,
    );
  }

  // eslint-disable-next-line no-console
  console.log(
    "tenant federation administration runtime security checks passed",
  );
} finally {
  await sql.end({ timeout: 5 });
}
