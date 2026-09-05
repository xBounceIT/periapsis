import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type RuntimeRole = "periapsis_api" | "periapsis_worker";
type JsonRecord = Record<string, postgres.JSONValue>;
type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_OIDC_BINDING_AUTH_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_OIDC_BINDING_AUTH_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d5c70-7000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;

const fixture = {
  operator: uuid(1),
  operatorGrant: uuid(2),
  operatorSession: uuid(3),
  operatorFamily: uuid(4),
  tenant: uuid(10),
  operatorMembership: uuid(11),
  otherTenant: uuid(12),
  otherOperatorMembership: uuid(13),
  tenantMfaPolicy: uuid(14),
  provider: uuid(20),
  providerCommand: uuid(21),
  providerSecret: uuid(22),
  binding: uuid(30),
  bindingCommand: uuid(31),
} as const;

const keyVersion = 32_767;
const retainedSecretKeyVersion = 32_766;
const inactiveKeyVersion = 32_765;
const tenantSlug = "platform-oidc-runtime";
const loginKey = "workforce";
const issuer = "https://platform-runtime-idp.example.invalid";
const tenantRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback";
const directRedirectUri =
  "https://periapsis.example.invalid/auth/platform/oidc/callback";
const postLogoutRedirectUri = "https://periapsis.example.invalid/login";
const clientId = "periapsis-platform-tenant-runtime";
let sequence = 1_000;

function nextUuid(): string {
  sequence += 1;
  return uuid(sequence);
}

function bytes(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-oidc-binding-auth-runtime:${label}`)
    .digest();
}

function b64(label: string): string {
  return bytes(label).toString("base64");
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function object(value: unknown, label: string): JsonRecord {
  if (!isJsonRecord(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function stringField(value: JsonRecord, key: string): string {
  const field = value[key];
  if (typeof field !== "string") {
    throw new TypeError(`${key} must be a string`);
  }
  return field;
}

function numberField(value: JsonRecord, key: string): number {
  const field = value[key];
  if (typeof field !== "number") {
    throw new TypeError(`${key} must be a number`);
  }
  return field;
}

function jsonField(value: JsonRecord, key: string): postgres.JSONValue {
  const field = value[key];
  if (field === undefined) {
    throw new TypeError(`${key} is required`);
  }
  return field;
}

function stringArrayField(value: JsonRecord, key: string): string[] {
  const field = jsonField(value, key);
  if (
    !Array.isArray(field) ||
    !field.every((item) => typeof item === "string")
  ) {
    throw new TypeError(`${key} must be an array of strings`);
  }
  return field;
}

async function withMfaPolicyRevisionWrite<T>(
  transaction: postgres.TransactionSql,
  operation: "insert" | "retire",
  policyId: string,
  revision: number,
  mutation: () => Promise<T>,
): Promise<T> {
  await transaction`
    SELECT set_config(
      'app.mfa_policy_write_v1',
      ${`${operation}:${policyId}:${revision}`},
      true
    )
  `;
  const result = await mutation();
  await transaction`
    SELECT set_config('app.mfa_policy_write_v1','',true)
  `;
  return result;
}

async function asRole<T>(
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  userId = "",
  tenantId = "",
): Promise<T> {
  const wrapped = await admin.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantId}, true),
             set_config('app.user_id', ${userId}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

function trace(): {
  auditId: string;
  tenantAuditId: string;
  requestId: string;
  correlationId: string;
} {
  return {
    auditId: nextUuid(),
    tenantAuditId: nextUuid(),
    requestId: nextUuid(),
    correlationId: nextUuid(),
  };
}

async function tenantVersion(): Promise<number> {
  const [row] = await admin<{ version: number }[]>`
    SELECT version::integer AS version
    FROM public.tenants WHERE id = ${fixture.tenant}::uuid
  `;
  assert(row);
  return row.version;
}

async function bindingVersion(): Promise<number> {
  const [row] = await admin<{ version: number }[]>`
    SELECT version::integer AS version
    FROM public.tenant_platform_auth_provider_bindings
    WHERE id = ${fixture.binding}::uuid
  `;
  assert(row);
  return row.version;
}

async function providerVersion(): Promise<number> {
  const [row] = await admin<{ version: number }[]>`
    SELECT version::integer AS version
    FROM public.platform_auth_providers
    WHERE id = ${fixture.provider}::uuid
  `;
  assert(row);
  return row.version;
}

async function activateBinding(
  jitMode: "create" | "disabled",
  noMatchPolicy: "provider_access_only" | "deny",
): Promise<number> {
  const event = trace();
  const expectedBindingVersion = await bindingVersion();
  const expectedTenantVersion = await tenantVersion();
  const [row] = await asRole(
    "periapsis_api",
    async (transaction) => transaction<{ version: number }[]>`
      SELECT activated.version::integer AS version
      FROM app.activate_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.binding}::uuid, ${expectedBindingVersion}::bigint,
        ${expectedTenantVersion}::integer, ${jitMode}::text,
        ${noMatchPolicy}::text,
        ${event.tenantAuditId}::uuid, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Activate tenant platform OIDC binding'::text
      ) AS activated
    `,
    fixture.operator,
  );
  assert(row);
  return row.version;
}

async function deactivateBinding(): Promise<number> {
  const event = trace();
  const expectedBindingVersion = await bindingVersion();
  const expectedTenantVersion = await tenantVersion();
  const [row] = await asRole(
    "periapsis_api",
    async (transaction) => transaction<{ version: number }[]>`
      SELECT deactivated.version::integer AS version
      FROM app.deactivate_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.binding}::uuid, ${expectedBindingVersion}::bigint,
        ${expectedTenantVersion}::integer, ${event.tenantAuditId}::uuid,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Deactivate tenant platform OIDC binding'::text
      ) AS deactivated
    `,
    fixture.operator,
  );
  assert(row);
  return row.version;
}

async function updatePresentationOnlyMetadata(): Promise<void> {
  let event = trace();
  const expectedProviderVersion = await providerVersion();
  const [provider] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT updated.version::integer AS version
      FROM app.update_platform_auth_provider_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${expectedProviderVersion}::bigint, 'platform_oidc_runtime'::text,
        'Renamed platform OIDC runtime'::text,
        'Tenant-bound platform OIDC runtime proof'::text,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Rename platform OIDC provider'::text
      ) AS updated
    `,
    fixture.operator,
  );
  assert.equal(provider?.version, expectedProviderVersion + 1);

  const bindingUpdateSnapshot = await mutationSnapshot();
  event = trace();
  const expectedBindingVersion = await bindingVersion();
  const expectedTenantVersion = await tenantVersion();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
        SELECT updated.version
        FROM app.update_tenant_platform_auth_provider_binding_v1(
          ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
          ${fixture.binding}::uuid, ${expectedBindingVersion}::bigint,
          ${expectedTenantVersion}::integer, 'renamed-workforce'::text,
          101::integer, ${event.tenantAuditId}::uuid,
          ${event.auditId}::uuid, ${event.requestId}::uuid,
          ${event.correlationId}::uuid, '198.51.100.61'::inet,
          'Periapsis platform OIDC authentication runtime proof'::text,
          'totp'::text, 'Rename active tenant platform OIDC binding'::text
        ) AS updated
      `,
      fixture.operator,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "23514");
      assert.equal(
        error.message,
        "tenant platform binding metadata transition is invalid",
      );
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), bindingUpdateSnapshot);
}

async function seedLifecycle(): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 3_600_000);
  await admin`
    INSERT INTO public.users (id, email, display_name)
    VALUES (${fixture.operator}::uuid,
      'platform-oidc-runtime-operator@example.invalid',
      'Platform OIDC runtime operator')
  `;
  await admin`
    INSERT INTO public.user_platform_roles (
      id, user_id, role_id, granted_by_user_id, granted_at
    )
    SELECT ${fixture.operatorGrant}::uuid, ${fixture.operator}::uuid,
           role.id, ${fixture.operator}::uuid, ${now}
    FROM public.platform_roles AS role
    WHERE role.key = 'platform_super_admin'
  `;
  await admin`
    INSERT INTO public.auth_sessions (
      id, user_id, rotation_family_id, active_tenant_id, token_digest,
      csrf_secret_digest, authentication_method, mfa_satisfied_at,
      last_seen_at, idle_expires_at, absolute_expires_at, created_at
    ) VALUES (
      ${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
      ${fixture.operatorFamily}::uuid, NULL,
      ${bytes("operator-token")}::bytea, ${bytes("operator-csrf")}::bytea,
      'totp', ${now}, ${now}, ${expires}, ${expires}, ${now}
    )
  `;
  await admin`
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, is_active
    ) VALUES
      (${inactiveKeyVersion}, ${bytes("inactive-key")}::bytea, false),
      (${retainedSecretKeyVersion}, ${bytes("retained-secret-key")}::bytea, true)
  `;

  let event = trace();
  await asRole(
    "periapsis_api",
    (transaction) => transaction`
      SELECT id FROM app.create_platform_tenant(
        ${fixture.tenant}::uuid, ${fixture.operatorMembership}::uuid,
        ${tenantSlug}::text, 'Platform OIDC runtime tenant'::text,
        'Europe/Rome'::text, 'en'::text, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text
      )
    `,
    fixture.operator,
  );

  await assert.rejects(
    admin`
      INSERT INTO public.mfa_policy_revisions (
        id, revision, tenant_id, scope, level, local_required,
        freshness_nanoseconds, created_at
      ) VALUES (
        ${fixture.tenantMfaPolicy}::uuid, 1, ${fixture.tenant}::uuid,
        'tenant_baseline', 'primary', false, 0, ${now}
      )
    `,
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "42501");
      assert.equal(
        error.message,
        "MFA policy revision writer capability is required",
      );
      return true;
    },
    "a tenant MFA policy fixture write bypassed the revision capability",
  );
  await admin.begin((transaction) =>
    withMfaPolicyRevisionWrite(
      transaction,
      "insert",
      fixture.tenantMfaPolicy,
      1,
      async () => {
        await transaction`
          INSERT INTO public.mfa_policy_revisions (
            id, revision, tenant_id, scope, level, local_required,
            freshness_nanoseconds, created_at
          ) VALUES (
            ${fixture.tenantMfaPolicy}::uuid, 1, ${fixture.tenant}::uuid,
            'tenant_baseline', 'primary', false, 0, ${now}
          )
        `;
      },
    ),
  );

  event = trace();
  await asRole(
    "periapsis_api",
    (transaction) => transaction`
      SELECT id FROM app.create_platform_tenant(
        ${fixture.otherTenant}::uuid,
        ${fixture.otherOperatorMembership}::uuid,
        'platform-oidc-switch-target'::text,
        'Platform OIDC switch target tenant'::text,
        'Europe/Rome'::text, 'en'::text, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text
      )
    `,
    fixture.operator,
  );

  event = trace();
  const configuration = {
    issuer,
    clientId,
    redirectUri: directRedirectUri,
    postLogoutRedirectUri,
    extraScopes: ["groups"],
    allowRefreshToken: false,
    useUserInfo: true,
  };
  const [createdProvider] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT created.version::integer AS version
      FROM app.create_platform_oidc_auth_provider_v3(
        ${fixture.operatorSession}::uuid, ${fixture.providerCommand}::uuid,
        ${fixture.provider}::uuid, 'platform_oidc_runtime'::text,
        'Platform OIDC runtime'::text,
        'Tenant-bound platform OIDC runtime proof'::text,
        ${transaction.json(configuration)}::jsonb, ${tenantRedirectUri}::text,
        ${bytes("provider-idempotency")}::bytea,
        ${bytes("provider-request")}::bytea, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Create disabled platform OIDC provider'::text
      ) AS created
    `,
    fixture.operator,
  );
  assert.equal(createdProvider?.version, 1);

  event = trace();
  await asRole(
    "periapsis_api",
    (transaction) => transaction`
      SELECT created.binding_id
      FROM app.create_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${fixture.bindingCommand}::uuid,
        ${fixture.binding}::uuid, ${fixture.provider}::uuid,
        ${fixture.tenant}::uuid, ${loginKey}::text, 100::integer,
        ${bytes("binding-idempotency")}::bytea,
        ${bytes("binding-request")}::bytea, ${event.tenantAuditId}::uuid,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Create disabled tenant platform OIDC binding'::text
      ) AS created
    `,
    fixture.operator,
  );

  event = trace();
  const [rotated] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT rotated.version::integer AS version
      FROM app.replace_platform_oidc_client_secret_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.providerSecret}::uuid, 1::bigint,
        ${retainedSecretKeyVersion}::integer,
        ${Buffer.alloc(12, 0x61)}::bytea,
        ${Buffer.from("platform-runtime-encrypted-secret", "utf8")}::bytea,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Install encrypted platform OIDC secret'::text
      ) AS rotated
    `,
    fixture.operator,
  );
  assert.equal(rotated?.version, 2);

  const retrievedAt = new Date();
  const freshUntil = new Date(retrievedAt.getTime() + 24 * 60 * 60_000);
  const discoveryDocument = Buffer.from(
    JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }),
  );
  const jwksDocument = Buffer.from(JSON.stringify({ keys: [] }));
  event = trace();
  const publication = {
    providerId: fixture.provider,
    expectedProviderVersion: 2,
    expectedConfigurationRevision: 2,
    discovery: {
      revision: 1,
      issuer,
      document: discoveryDocument.toString("base64"),
      digest: createHash("sha256").update(discoveryDocument).digest("base64"),
      retrievedAt: retrievedAt.toISOString(),
      freshUntil: freshUntil.toISOString(),
      cacheable: true,
      mustRevalidate: false,
      clientAuthentication: "client_secret_basic",
      signingAlgorithms: ["RS256"],
    },
    jwks: {
      revision: 1,
      document: jwksDocument.toString("base64"),
      digest: createHash("sha256").update(jwksDocument).digest("base64"),
      retrievedAt: retrievedAt.toISOString(),
      freshUntil: freshUntil.toISOString(),
      cacheable: true,
      mustRevalidate: false,
    },
    auditEventId: event.auditId,
    requestId: event.requestId,
    correlationId: event.correlationId,
    reason: "Publish fresh OIDC discovery and JWKS",
  };
  const [published] = await asRole(
    "periapsis_worker",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.publish_platform_oidc_trust_snapshot_v1(
        ${transaction.json(publication)}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    numberField(object(published?.value, "publication"), "providerVersion"),
    3,
  );

  event = trace();
  const [activated] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT activated.version::integer AS version
      FROM app.activate_platform_auth_provider_tenant_execution_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        3::bigint, 'create'::text, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Activate platform OIDC tenant execution'::text
      ) AS activated
    `,
    fixture.operator,
  );
  assert.equal(activated?.version, 4);

  event = trace();
  const [deactivated] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT deactivated.version::integer AS version
      FROM app.deactivate_platform_auth_provider_tenant_execution_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        4::bigint, ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Stage identity key promotion'::text
      ) AS deactivated
    `,
    fixture.operator,
  );
  assert.equal(deactivated?.version, 5);

  const [installed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ ready: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[${inactiveKeyVersion},${retainedSecretKeyVersion},${keyVersion}]::integer[],
        ARRAY[${bytes("inactive-key")},${bytes("retained-secret-key")},
          ${bytes("promoted-active-key")}]::bytea[],
        ${retainedSecretKeyVersion}::integer
      ) AS ready
    `,
  );
  assert.equal(installed?.ready, true);
  await admin`
    SELECT app.promote_identity_keyring_version_v1(
      ${retainedSecretKeyVersion}::integer, ${keyVersion}::integer
    )
  `;

  event = trace();
  const [reactivated] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT activated.version::integer AS version
      FROM app.activate_platform_auth_provider_tenant_execution_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        5::bigint, 'create'::text, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.61'::inet,
        'Periapsis platform OIDC authentication runtime proof'::text,
        'totp'::text, 'Reactivate with retained client-secret key'::text
      ) AS activated
    `,
    fixture.operator,
  );
  assert.equal(reactivated?.version, 6);
  const [keyState] = await admin<
    {
      retainedActive: boolean;
      retainedRetired: boolean;
      promotedActive: boolean;
    }[]
  >`
    SELECT
      (SELECT is_active FROM public.identity_keyring_versions
       WHERE key_version = ${retainedSecretKeyVersion}) AS "retainedActive",
      (SELECT retired_at IS NOT NULL FROM public.identity_keyring_versions
       WHERE key_version = ${retainedSecretKeyVersion}) AS "retainedRetired",
      (SELECT is_active FROM public.identity_keyring_versions
       WHERE key_version = ${keyVersion}) AS "promotedActive"
  `;
  assert.deepEqual(keyState, {
    retainedActive: false,
    retainedRetired: false,
    promotedActive: true,
  });
  assert.equal(await activateBinding("create", "provider_access_only"), 2);
}

type Attempt = {
  label: string;
  aliases: JsonRecord[];
  operationRunId: string;
  transactionId: string;
  pins: JsonRecord;
  planning: JsonRecord;
};

async function prepareAttempt(
  label: string,
  aliases: JsonRecord[],
  afterClaim?: () => Promise<void>,
  verifierKeyVersion = keyVersion,
  afterCreate?: () => Promise<void>,
): Promise<Attempt> {
  const beginEnvelope = {
    operationRunId: nextUuid(),
    receiptDigest: b64(`${label}:receipt`),
    networkDigest: b64(`${label}:network`),
    accountDigest: b64(`${label}:account`),
    providerDigest: b64(`${label}:provider`),
  };
  const [begun] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.begin_tenant_oidc_authentication_v1(
        ${transaction.json({
          begin: beginEnvelope,
          tenantSlug,
          loginKey,
        })}::jsonb
      ) AS value
    `,
  );
  const beginProjection = object(begun?.value, `${label} begin`);
  const authorization = object(
    beginProjection.authorization,
    `${label} authorization`,
  );
  const pins: JsonRecord = {
    provider: jsonField(authorization, "provider"),
    admission: jsonField(authorization, "admission"),
    providerRevision: jsonField(authorization, "providerRevision"),
    bindingRevision: jsonField(authorization, "bindingRevision"),
    configurationRevision: jsonField(authorization, "configurationRevision"),
    securityRevision: jsonField(authorization, "securityRevision"),
    mappingRevision: jsonField(authorization, "mappingRevision"),
    authorizationRevision: jsonField(authorization, "authorizationRevision"),
    assurancePolicyRevision: jsonField(
      authorization,
      "assurancePolicyRevision",
    ),
    clientSecretRevision: jsonField(authorization, "clientSecretRevision"),
    discoveryRevision: jsonField(beginProjection, "discoveryRevision"),
    discoveryDigest: jsonField(beginProjection, "discoveryDigest"),
    jwksRevision: jsonField(beginProjection, "jwksRevision"),
    jwksDigest: jsonField(beginProjection, "jwksDigest"),
  };
  const createdAt = new Date(Date.now() - 2_000);
  const transactionId = b64(`${label}:transaction`);
  const stateDigest = b64(`${label}:state`);
  const browserDigest = b64(`${label}:browser`);
  const request = {
    begin: beginEnvelope,
    current: {
      id: transactionId,
      stateDigest,
      browserDigest,
      nonceDigest: b64(`${label}:nonce`),
      verifierKeyVersion,
      verifierCiphertext: Buffer.alloc(32, 0x76).toString("base64"),
      pins,
      clientId: authorization.clientId,
      redirectUri: authorization.redirectUri,
      postLogoutRedirectUri: authorization.postLogoutRedirectUri,
      returnPath: "/portal",
      scopes: ["openid", ...stringArrayField(authorization, "extraScopes")],
      allowRefreshToken: authorization.allowRefreshToken,
      useUserInfo: authorization.useUserInfo,
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + 10 * 60_000).toISOString(),
      state: "pending",
      version: 1,
    },
  };
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.create_oidc_authentication_transaction_v1(
        ${transaction.json(request)}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    numberField(object(created?.value, `${label} create`), "version"),
    1,
  );
  const [operationPin] = await admin<{ operationRunId: string }[]>`
    SELECT transaction_row.operation_run_id::text AS "operationRunId"
    FROM public.tenant_platform_oidc_authentication_transactions AS transaction_row
    WHERE transaction_row.tenant_id = ${fixture.tenant}::uuid
      AND transaction_row.transaction_id = ${Buffer.from(transactionId, "base64")}::bytea
      AND transaction_row.protocol = 'oidc'
  `;
  assert.equal(
    operationPin?.operationRunId,
    beginEnvelope.operationRunId,
    `${label} transaction did not retain its material authority identifier`,
  );
  await afterCreate?.();

  const [claimed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.claim_oidc_authentication_transaction_v1(
        ${transaction.json({
          attemptId: b64(`${label}:attempt`),
          stateDigest,
          browserDigest,
          claimedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  const claimProjection = object(claimed?.value, `${label} claim`);
  assert.equal(numberField(claimProjection, "version"), 2);
  assert.equal(stringField(claimProjection, "state"), "claimed");
  await afterClaim?.();

  const [resolved] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.resolve_tenant_oidc_authentication_v1(
        ${transaction.json({
          transactionId,
          expectedVersion: 2,
          pins,
        })}::jsonb
      ) AS value
    `,
  );
  assert(
    resolved !== undefined && resolved.value !== null,
    `${label} resolve failed`,
  );
  const resolvedProjection = object(resolved.value, `${label} resolve`);
  const resolvedAuthorization = object(
    resolvedProjection.authorization,
    `${label} resolved authorization`,
  );
  assert.equal(
    jsonField(resolvedAuthorization, "providerRevision"),
    jsonField(pins, "providerRevision"),
  );

  const [planned] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_authentication_planning_state_v1(
        ${transaction.json({
          protocol: "oidc",
          tenantId: fixture.tenant,
          provider: pins.provider,
          admission: pins.admission,
          subjectFormat: "utf8_exact",
          subjectAliases: aliases,
          providerRevision: pins.providerRevision,
          bindingRevision: pins.bindingRevision,
          configurationRevision: pins.configurationRevision,
          securityRevision: pins.securityRevision,
          mappingRevision: pins.mappingRevision,
          authorizationRevision: pins.authorizationRevision,
          assurancePolicyRevision: pins.assurancePolicyRevision,
        })}::jsonb
      ) AS value
    `,
  );
  const planning = object(planned?.value, `${label} planning`);
  return {
    label,
    aliases,
    operationRunId: beginEnvelope.operationRunId,
    transactionId,
    pins,
    planning,
  };
}

async function verifyKeyringWithoutInactive(): Promise<boolean> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ ready: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[${retainedSecretKeyVersion},${keyVersion}]::integer[],
        ARRAY[${bytes("retained-secret-key")},${bytes("promoted-active-key")}]::bytea[],
        ${keyVersion}::integer
      ) AS ready
    `,
  );
  assert(row);
  return row.ready;
}

async function verifyKeyringWithoutRetainedSecret(): Promise<boolean> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ ready: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[${inactiveKeyVersion},${keyVersion}]::integer[],
        ARRAY[${bytes("inactive-key")},${bytes("promoted-active-key")}]::bytea[],
        ${keyVersion}::integer
      ) AS ready
    `,
  );
  assert(row);
  return row.ready;
}

type ApplyOptions = {
  identityAction: "no_change" | "create_user_and_external_identity";
  accessAction: "ensure" | "no_change";
  identityEpoch?: number;
  sessionId?: string;
  continuation?: {
    id: string;
    receiptDigest: string;
    expiresAt: string;
    assurance: "step_up_required" | "enrollment_only";
  };
  profile?: JsonRecord[];
  commandSink?: (command: JsonRecord) => void;
};

function absentProfile(): JsonRecord[] {
  return [
    "first_name",
    "last_name",
    "display_name",
    "username",
    "alternate_username",
    "email",
  ].map((field) => ({ field, present: false }));
}

async function submitApplyCommand(
  label: string,
  command: JsonRecord,
): Promise<JsonRecord> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_authentication_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  return object(row?.value, `${label} apply`);
}

async function applyAttempt(
  attempt: Attempt,
  options: ApplyOptions,
): Promise<JsonRecord> {
  const appliedAt = new Date();
  const validUntil = new Date(appliedAt.getTime() + 10 * 60_000);
  const sessionId = options.sessionId ?? nextUuid();
  const familyId = nextUuid();
  const artifactId = options.continuation?.id ?? sessionId;
  const plan = {
    planRevision: attempt.planning.planRevision,
    tenantId: fixture.tenant,
    userId: attempt.planning.userId,
    identityEpoch:
      options.identityEpoch ?? numberField(attempt.planning, "identityEpoch"),
    providerRevision: attempt.pins.providerRevision,
    bindingRevision: attempt.pins.bindingRevision,
    configurationRevision: attempt.pins.configurationRevision,
    securityRevision: attempt.pins.securityRevision,
    mappingRevision: attempt.pins.mappingRevision,
    authorizationRevision: attempt.pins.authorizationRevision,
    policyRevision: attempt.pins.assurancePolicyRevision,
    roleIds: [],
    securityGroupIds: [],
    subject: {
      externalIdentityId: attempt.planning.externalIdentityId,
      aliases: attempt.aliases,
      envelope: {
        keyVersion,
        format: "utf8_exact",
        nonce: Buffer.alloc(12, 0x6e).toString("base64"),
        ciphertext: Buffer.from(
          `protected-subject-${attempt.label}`.padEnd(32, "x"),
        ).toString("base64"),
      },
    },
    mapping: {
      disposition: "admitted",
      reason: "provider_access_only",
      identityAction: options.identityAction,
      accessAction: options.accessAction,
      matchedRuleIds: [],
      securityGroupIds: [],
      roleIds: [],
      operatorTeams: [],
      changes: [],
      profile: options.profile ?? absentProfile(),
    },
    requirement: attempt.planning.requirement,
    hasEnrollableFactor: attempt.planning.hasEnrollableFactor,
  };
  const apply: JsonRecord = {
    authentication: {
      protocol: "oidc",
      method: "oidc",
      tenantId: fixture.tenant,
      admission: attempt.pins.admission,
      authenticatedAt: appliedAt.toISOString(),
      validUntil: validUntil.toISOString(),
      evidence: [
        {
          level: "primary",
          kind: "factor",
          local: false,
          providerId: fixture.provider,
          bindingId: fixture.binding,
          authenticatedAt: appliedAt.toISOString(),
          expiresAt: validUntil.toISOString(),
          factorRevision: null,
          trustRuleRevision: attempt.pins.securityRevision,
        },
      ],
      oidc: {
        transactionId: attempt.transactionId,
        expectedVersion: 2,
        pins: attempt.pins,
        completedAt: appliedAt.toISOString(),
        returnPath: "/portal",
        materialId: attempt.operationRunId,
      },
    },
    plan,
    disposition:
      options.continuation === undefined ? "session" : "continuation",
    assurance: options.continuation?.assurance ?? "satisfied",
    appliedAt: appliedAt.toISOString(),
  };
  if (options.continuation === undefined) {
    apply.session = {
      sessionId,
      familyId,
      tokenDigest: b64(`${attempt.label}:${sessionId}:token`),
      csrfDigest: b64(`${attempt.label}:${sessionId}:csrf`),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(appliedAt.getTime() + 30 * 60_000).toISOString(),
      absoluteExpiresAt: new Date(
        appliedAt.getTime() + 8 * 60 * 60_000,
      ).toISOString(),
    };
  } else {
    apply.continuation = {
      continuationId: options.continuation.id,
      receiptDigest: options.continuation.receiptDigest,
      expiresAt: options.continuation.expiresAt,
    };
  }
  const command = {
    operationDigest: b64(`${attempt.label}:${artifactId}:operation`),
    apply,
  };
  options.commandSink?.(command);
  return submitApplyCommand(attempt.label, command);
}

async function mutationSnapshot(): Promise<postgres.JSONValue> {
  const [row] = await admin<{ snapshot: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'users',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.users AS t),
      'identities',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.platform_federated_external_identities AS t),
      'aliases',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.platform_federated_external_identity_aliases AS t),
      'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_memberships AS t),
      'mfaSubjects',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.tenant_id,t.user_id),'[]') FROM public.tenant_mfa_subjects AS t),
      'grants',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_platform_federated_provider_access_grants AS t),
      'profiles',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_platform_federated_provider_profile_contributions AS t),
      'materializedProfiles',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.tenant_id,t.user_id),'[]') FROM public.tenant_user_profiles AS t),
      'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.auth_sessions AS t),
      'mfaStates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.session_id),'[]') FROM public.auth_session_mfa_states AS t),
      'provenance',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.session_id),'[]') FROM public.auth_session_tenant_platform_federated_provenance AS t),
      'evidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.auth_session_tenant_platform_federated_evidence AS t),
      'continuations',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_post_primary_continuations AS t),
      'continuationProvenance',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.continuation_id),'[]') FROM public.tenant_post_primary_platform_federated_provenance AS t),
      'continuationEvidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_post_primary_platform_federated_evidence AS t),
      'mfaAnchors',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_mfa_authority_anchors AS t),
      'mfaAnchorEvidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_mfa_authority_evidence AS t),
      'mfaAnchorPlatformEvidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_mfa_authority_platform_federated_evidence AS t),
      'mfaChallenges',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_mfa_step_up_challenges AS t),
      'totpFactors',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_totp_factors AS t),
      'identityKeyring',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.key_version),'[]') FROM public.identity_keyring_versions AS t),
      'applications',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.tenant_platform_oidc_authentication_applications AS t),
      'transactions',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.transaction_id),'[]') FROM public.tenant_platform_oidc_authentication_transactions AS t),
      'revalidationCommands',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.tenant_id,t.session_id,t.expected_version),'[]') FROM public.tenant_platform_federated_session_revalidation_commands AS t),
      'tenantAudit',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.audit_events AS t),
      'platformAudit',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]') FROM public.platform_audit_events AS t)
    ) AS snapshot
  `;
  assert(row);
  return row.snapshot;
}

async function assertRollback(
  category: "denied" | "stale" | "identity_collision",
  operation: () => Promise<JsonRecord>,
): Promise<void> {
  const before = await mutationSnapshot();
  const result = await operation();
  assert.equal(result.category, category);
  assert.deepEqual(
    await mutationSnapshot(),
    before,
    `${category} mutated state`,
  );
}

async function loadRevalidation(sessionId: string): Promise<JsonRecord | null> {
  const [session] = await admin<{ authenticationMethod: string }[]>`
    SELECT authentication_method AS "authenticationMethod"
    FROM public.auth_sessions
    WHERE id = ${sessionId}::uuid
  `;
  assert.equal(
    session?.authenticationMethod,
    "oidc",
    "platform OIDC revalidation requires an OIDC session",
  );
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_session_revalidation_v1(
        ${transaction.json({
          sessionId,
          tenantId: fixture.tenant,
          audience: "api",
          authenticationMethod: "oidc",
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  return row?.value === null ? null : object(row?.value, "revalidation");
}

async function applyRevalidation(mutation: JsonRecord): Promise<JsonRecord> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_session_revalidation_v1(
        ${transaction.json(mutation)}::jsonb
      ) AS value
    `,
  );
  return object(row?.value, "revalidation mutation");
}

async function assertNoOidcMaterialForOwners(
  label: string,
  ownerIds: readonly string[],
): Promise<void> {
  const [material] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_oidc_session_materials
    WHERE authority = 'tenant_platform_provider'
      AND (
        session_id = ANY(${ownerIds}::uuid[])
        OR continuation_id = ANY(${ownerIds}::uuid[])
      )
  `;
  assert.equal(
    material?.count,
    0,
    `${label} unexpectedly persisted tenant-platform OIDC material`,
  );
}

async function assertRequiredOidcMaterialFailsClosed(
  attempt: Attempt,
  mutation: JsonRecord,
): Promise<void> {
  const before = await mutationSnapshot();
  await assert.rejects(
    admin.begin(async (transaction) => {
      // The production ledger is immutable. This rollback-only adversarial
      // mutation synthesizes a discordant historical requirement so the
      // owner-change path must fail closed when its material is absent.
      await transaction.unsafe("SET LOCAL session_replication_role = replica");
      const updated = await transaction`
        UPDATE public.tenant_platform_oidc_authentication_transactions
        SET allow_refresh_token = true
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND transaction_id = ${Buffer.from(attempt.transactionId, "base64")}::bytea
          AND operation_run_id = ${attempt.operationRunId}::uuid
          AND state = 'completed'
        RETURNING transaction_id
      `;
      assert.equal(
        updated.length,
        1,
        "required-material lineage was not exact",
      );
      await transaction.unsafe("SET LOCAL session_replication_role = origin");
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', '', true),
               set_config('app.service_account_id', '', true)
      `;
      await transaction`
        SELECT app.apply_federated_session_revalidation_v1(
          ${transaction.json(mutation)}::jsonb
        )
      `;
    }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "40001");
      assert.equal(
        error.message,
        "tenant-platform OIDC material ownership is stale",
      );
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    before,
    "required-material fail-closed proof escaped its rollback boundary",
  );
}

function mfaBinding(authority: JsonRecord): JsonRecord {
  return {
    flow: stringField(authority, "flow"),
    tenantId: stringField(authority, "tenantId"),
    userId: stringField(authority, "userId"),
    identityEpoch: numberField(authority, "identityEpoch"),
    continuationId: stringField(authority, "continuationId"),
    anchorVersion: numberField(authority, "anchorVersion"),
    anchorExpiresAt: stringField(authority, "anchorExpiresAt"),
    anchorRecoveryRestricted: authority.anchorRecoveryRestricted ?? false,
    action: stringField(authority, "action"),
    audience: stringField(authority, "audience"),
    requirement: jsonField(authority, "requirement"),
    baselineEvidence: jsonField(authority, "baselineEvidence"),
  };
}

async function resolveContinuationAuthority(
  continuationId: string,
  receiptDigest: Buffer,
  evaluatedAt: Date,
): Promise<JsonRecord> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${continuationId}::uuid,'continuation','session.create','api',
        ${evaluatedAt},${receiptDigest}::bytea
      ) AS value
    `,
  );
  return object(row?.value, "continuation MFA authority");
}

async function createAndClaimTotpChallenge(
  authority: JsonRecord,
  receiptDigest: string,
  label: string,
  liveDrift?: { disable: () => Promise<void>; restore: () => Promise<void> },
): Promise<{ binding: JsonRecord; challengeId: Buffer; completedAt: Date }> {
  const binding = mfaBinding(authority);
  const challengeId = bytes(`${label}:challenge`);
  const browserDigest = bytes(`${label}:browser`);
  const createdAt = new Date();
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: boolean }[]>`
      SELECT app.create_mfa_step_up_challenge_v1(
        ${transaction.json({
          id: challengeId.toString("base64"),
          browserDigest: browserDigest.toString("base64"),
          binding,
          continuationReceiptDigest: receiptDigest,
          allowedFactors: ["totp"],
          createdAt: createdAt.toISOString(),
          expiresAt: new Date(createdAt.getTime() + 5 * 60_000).toISOString(),
          state: "pending",
          version: 1,
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(created?.value, true);
  const lockOrderSnapshot = await mutationSnapshot();
  await admin.begin(async (locker) => {
    await locker`
      SELECT 1
      FROM public.tenant_post_primary_continuations
      WHERE id = ${stringField(authority, "continuationId")}::uuid
      FOR UPDATE
    `;
    await assert.rejects(
      asRole("periapsis_api", async (transaction) => {
        await transaction.unsafe("SET LOCAL lock_timeout = '250ms'");
        return transaction`
          SELECT app.claim_mfa_step_up_challenge_v2(
            ${challengeId}::bytea,${browserDigest}::bytea,'totp',${new Date()},
            ${Buffer.from(receiptDigest, "base64")}::bytea
          )
        `;
      }),
      (error: unknown) => {
        assert(error instanceof Error);
        assert.equal((error as ErrorWithCode).code, "40001");
        return true;
      },
    );
  });
  assert.deepEqual(
    await mutationSnapshot(),
    lockOrderSnapshot,
    "bounded continuation contention mutated the MFA artifact",
  );
  if (liveDrift !== undefined) {
    await liveDrift.disable();
    const driftedSnapshot = await mutationSnapshot();
    await assert.rejects(
      asRole(
        "periapsis_api",
        (transaction) => transaction`
        SELECT app.claim_mfa_step_up_challenge_v2(
          ${challengeId}::bytea,${browserDigest}::bytea,'totp',
          ${new Date()},
          ${Buffer.from(receiptDigest, "base64")}::bytea
        )
      `,
      ),
      (error: unknown) => {
        assert(error instanceof Error);
        assert(
          ["40001", "42501"].includes((error as ErrorWithCode).code ?? ""),
        );
        return true;
      },
    );
    assert.deepEqual(
      await mutationSnapshot(),
      driftedSnapshot,
      "stale live authority claimed an MFA artifact",
    );
    await liveDrift.restore();
  }
  const preClaimSnapshot = await mutationSnapshot();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.claim_mfa_step_up_challenge_v2(
        ${challengeId}::bytea,${browserDigest}::bytea,'totp',
        ${new Date()},${bytes(`${label}:wrong-receipt`)}::bytea
      )
    `,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "42501");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), preClaimSnapshot);
  const [claimed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.claim_mfa_step_up_challenge_v2(
        ${challengeId}::bytea,${browserDigest}::bytea,'totp',
        ${new Date()},
        ${Buffer.from(receiptDigest, "base64")}::bytea
      ) AS value
    `,
  );
  assert.equal(claimed?.value.state, "claimed");
  assert.equal(claimed?.value.version, 2);
  return {
    binding,
    challengeId,
    completedAt: new Date(),
  };
}

async function enrollTotpAndRetainContinuation(
  authority: JsonRecord,
  receiptDigest: string,
  label: string,
  liveDrift?: { disable: () => Promise<void>; restore: () => Promise<void> },
): Promise<{ authority: JsonRecord; factorId: string }> {
  const binding = mfaBinding(authority);
  const requirement = object(authority.requirement, `${label} requirement`);
  const policyRevisions = jsonField(requirement, "policyRevisions");
  assert(Array.isArray(policyRevisions));
  const enrollmentId = nextUuid();
  const factorId = nextUuid();
  const browserDigest = bytes(`${label}:browser`);
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 5 * 60_000);
  const [started] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: boolean }[]>`
      SELECT app.start_totp_enrollment_v1(
        ${transaction.json({
          enrollmentId,
          factorId,
          browserDigest: browserDigest.toString("base64"),
          binding,
          continuationReceiptDigest: receiptDigest,
          policyPins: policyRevisions.map((revision) => ({
            scope: "tenant_baseline",
            policyId: object(revision, `${label} policy revision`).policyId,
            revision: object(revision, `${label} policy revision`).revision,
          })),
          keyVersion,
          secretEnvelope: Buffer.alloc(32, 0x65).toString("base64"),
          createdAt: createdAt.toISOString(),
          expiresAt: expiresAt.toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(started?.value, true);
  const claimedAt = new Date();
  const [claimed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.claim_totp_enrollment_v2(
        ${enrollmentId}::uuid,${browserDigest}::bytea,${claimedAt},
        ${Buffer.from(receiptDigest, "base64")}::bytea
      ) AS value
    `,
  );
  assert.equal(claimed?.value.version, 2);
  const completedAt = new Date();
  const completionRequest = {
    enrollmentId,
    expectedVersion: 2,
    factorId,
    binding: claimed?.value.binding,
    acceptedCounter: 0,
    completedAt: completedAt.toISOString(),
    audit: {
      kind: "mfa.totp_enrolled",
      tenantId: authority.tenantId,
      userId: authority.userId,
      action: authority.action,
      occurredAt: completedAt.toISOString(),
      policyRevisions,
    },
    session: {
      mutation: "retain_continuation",
      expectedContinuationId: authority.continuationId,
      expectedAnchorVersion: authority.anchorVersion,
      expectedIdentityEpoch: authority.identityEpoch,
      expectedAnchorExpiry: authority.anchorExpiresAt,
      audience: authority.audience,
      requirement: authority.requirement,
      recoveryRestricted: false,
      continuationReceiptDigest: receiptDigest,
    },
  };
  if (liveDrift !== undefined) {
    await liveDrift.disable();
    const driftedSnapshot = await mutationSnapshot();
    await assert.rejects(
      asRole(
        "periapsis_api",
        (transaction) => transaction`
        SELECT app.complete_totp_enrollment_v1(
          ${transaction.json(completionRequest)}::jsonb
        )
      `,
      ),
      (error: unknown) => {
        assert(error instanceof Error);
        assert(
          ["40001", "42501"].includes((error as ErrorWithCode).code ?? ""),
        );
        return true;
      },
    );
    assert.deepEqual(
      await mutationSnapshot(),
      driftedSnapshot,
      "stale live authority retained a continuation or consumed its artifact",
    );
    await liveDrift.restore();
  }
  const [completed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.complete_totp_enrollment_v1(
        ${transaction.json(completionRequest)}::jsonb
      ) AS value
    `,
  );
  assert.equal(completed?.value.mutation, "retain_continuation");
  assert.equal(
    completed?.value.sessionVersion,
    numberField(authority, "anchorVersion") + 1,
  );
  const staleAnchorSnapshot = await mutationSnapshot();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.create_mfa_step_up_challenge_v1(
        ${transaction.json({
          id: b64(`${label}:stale-anchor`),
          browserDigest: b64(`${label}:stale-browser`),
          binding,
          continuationReceiptDigest: receiptDigest,
          allowedFactors: ["totp"],
          createdAt: completedAt.toISOString(),
          expiresAt: new Date(completedAt.getTime() + 5 * 60_000).toISOString(),
          state: "pending",
          version: 1,
        })}::jsonb
      )
    `,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert(["40001", "42501"].includes((error as ErrorWithCode).code ?? ""));
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), staleAnchorSnapshot);
  return {
    authority: await resolveContinuationAuthority(
      stringField(authority, "continuationId"),
      Buffer.from(receiptDigest, "base64"),
      new Date(),
    ),
    factorId,
  };
}

async function loadClientSecret(pins: JsonRecord): Promise<JsonRecord | null> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_oidc_client_secret_envelope_v1(
        ${transaction.json({
          provider: pins.provider,
          admission: pins.admission,
          revision: pins.clientSecretRevision,
        })}::jsonb
      ) AS value
    `,
  );
  return row?.value === null ? null : object(row?.value, "client secret");
}

async function assertRetiredSecretFailsClosed(attempt: Attempt): Promise<void> {
  const rollbackMessage = "rollback retired client-secret key proof";
  try {
    await admin.begin(async (transaction) => {
      await transaction`
        UPDATE public.identity_keyring_versions
        SET retired_at = transaction_timestamp()
        WHERE key_version = ${retainedSecretKeyVersion}
      `;
      const [configuration] = await transaction<
        {
          value: postgres.JSONValue | null;
        }[]
      >`
        SELECT app.private_tenant_platform_oidc_configuration_record_v1(
          ${fixture.tenant}::uuid,${fixture.provider}::uuid,
          ${fixture.binding}::uuid,${transaction.json(attempt.pins)}::jsonb
        ) AS value
      `;
      assert.equal(configuration?.value, null);
      const [secret] = await transaction<
        { value: postgres.JSONValue | null }[]
      >`
        SELECT app.load_tenant_platform_oidc_client_secret_v1(
          ${transaction.json({
            provider: attempt.pins.provider,
            admission: attempt.pins.admission,
            revision: attempt.pins.clientSecretRevision,
          })}::jsonb
        ) AS value
      `;
      assert.equal(secret?.value, null);
      const [begun] = await transaction<{ value: postgres.JSONValue | null }[]>`
        SELECT app.begin_tenant_oidc_authentication_v1(
          ${transaction.json({
            begin: {
              operationRunId: nextUuid(),
              receiptDigest: b64("retired-secret:receipt"),
              networkDigest: b64("retired-secret:network"),
              accountDigest: b64("retired-secret:account"),
              providerDigest: b64("retired-secret:provider"),
            },
            tenantSlug,
            loginKey,
          })}::jsonb
        ) AS value
      `;
      assert.equal(begun?.value, null);
      throw new Error(rollbackMessage);
    });
    assert.fail("retired client-secret key proof unexpectedly committed");
  } catch (error) {
    assert(error instanceof Error);
    assert.equal(error.message, rollbackMessage);
  }
}

try {
  const [version] = await admin<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(version?.version.startsWith("18."));
  const [fresh] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.users
  `;
  assert.equal(fresh?.count, 0, "runtime proof requires a fresh database");

  await seedLifecycle();
  const retainedCiphertextSnapshot = await mutationSnapshot();
  assert.equal(
    await verifyKeyringWithoutRetainedSecret(),
    false,
    "a live client-secret envelope did not block retirement of its retained key",
  );
  assert.deepEqual(await mutationSnapshot(), retainedCiphertextSnapshot);
  await admin.begin(async (writer) => {
    await writer`
      LOCK TABLE public.tenant_platform_oidc_authentication_transactions
      IN ROW EXCLUSIVE MODE
    `;
    const startedAt = Date.now();
    const ready = await verifyKeyringWithoutInactive();
    assert.equal(
      ready,
      false,
      "NOWAIT keyring inventory waited through a writer lock",
    );
    assert(
      Date.now() - startedAt < 5_000,
      "NOWAIT keyring inventory did not fail promptly",
    );
    await writer`
      LOCK TABLE public.platform_federated_external_identities
      IN ROW EXCLUSIVE MODE NOWAIT
    `;
  });
  const aliases = [{ keyVersion, digest: b64("subject") }];
  const secondSubjectAliases = [{ keyVersion, digest: b64("second-subject") }];
  const rotatedAliases = [
    { keyVersion: inactiveKeyVersion, digest: b64("subject-previous-key") },
    ...aliases,
  ];

  const first = await prepareAttempt("first", aliases);
  const retainedSecret = await loadClientSecret(first.pins);
  assert(retainedSecret);
  assert.equal(
    numberField(retainedSecret, "keyVersion"),
    retainedSecretKeyVersion,
  );
  await assertRetiredSecretFailsClosed(first);
  assert.equal(
    numberField(
      object(await loadClientSecret(first.pins), "retained secret"),
      "keyVersion",
    ),
    retainedSecretKeyVersion,
  );
  assert.equal(first.planning.userId, null);
  assert.equal(first.planning.identityEpoch, 0);
  const firstSession = nextUuid();
  let firstCommand: JsonRecord | undefined;
  const firstResult = await applyAttempt(first, {
    identityAction: "create_user_and_external_identity",
    accessAction: "ensure",
    sessionId: firstSession,
    profile: [
      { field: "first_name", present: false },
      { field: "last_name", present: false },
      { field: "display_name", present: true, value: "Provider Display" },
      { field: "username", present: false },
      { field: "alternate_username", present: false },
      { field: "email", present: true, value: "provider@example.invalid" },
    ],
    commandSink: (command) => {
      firstCommand = command;
    },
  });
  assert.equal(firstResult.category, "success");
  assert.equal(firstResult.replayed, false);
  const userId = stringField(firstResult, "userId");
  const [jitMfaSubject] = await admin<
    { handleBytes: number; nonzeroHandle: boolean }[]
  >`
    SELECT octet_length(subject.webauthn_user_handle)::integer
             AS "handleBytes",
           subject.webauthn_user_handle <> decode(repeat('00', 32), 'hex')
             AS "nonzeroHandle"
    FROM public.tenant_mfa_subjects AS subject
    WHERE subject.tenant_id = ${fixture.tenant}::uuid
      AND subject.user_id = ${userId}::uuid
  `;
  assert.deepEqual(
    jitMfaSubject,
    { handleBytes: 32, nonzeroHandle: true },
    "federated JIT did not persist a core-generated 32-byte MFA handle",
  );
  const [firstProfile] = await admin<
    {
      identityKeyVersion: number;
      userDisplayName: string;
      contributionDisplayName: string;
      contributionEmail: string;
      effectiveDisplayName: string;
      effectiveEmail: string;
    }[]
  >`
    SELECT identity.key_version AS "identityKeyVersion",
           local_user.display_name AS "userDisplayName",
           contribution.display_name AS "contributionDisplayName",
           contribution.email AS "contributionEmail",
           profile.display_name AS "effectiveDisplayName",
           profile.email AS "effectiveEmail"
    FROM public.platform_federated_external_identities AS identity
    JOIN public.users AS local_user ON local_user.id = identity.user_id
    JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.platform_provider_id = identity.platform_provider_id
     AND grant_row.external_identity_id = identity.id
     AND grant_row.tenant_id = ${fixture.tenant}::uuid
     AND grant_row.ended_at IS NULL
    JOIN public.tenant_platform_federated_provider_profile_contributions AS contribution
      ON contribution.tenant_id = grant_row.tenant_id
     AND contribution.access_grant_id = grant_row.id
     AND contribution.retired_at IS NULL
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id = grant_row.tenant_id
     AND profile.membership_id = grant_row.membership_id
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.user_id = ${userId}::uuid
  `;
  assert.deepEqual(firstProfile, {
    identityKeyVersion: keyVersion,
    userDisplayName: "Federated user",
    contributionDisplayName: "Provider Display",
    contributionEmail: "provider@example.invalid",
    effectiveDisplayName: "Provider Display",
    effectiveEmail: "provider@example.invalid",
  });
  assert(firstCommand);
  const exactReplaySnapshot = await mutationSnapshot();
  const exactReplay = await submitApplyCommand(
    "first exact replay",
    firstCommand,
  );
  assert.equal(exactReplay.category, "success");
  assert.equal(exactReplay.replayed, true);
  assert.equal(exactReplay.sessionId, firstSession);
  assert.deepEqual(
    await mutationSnapshot(),
    exactReplaySnapshot,
    "exact apply replay advanced persisted state",
  );

  const assertInactiveVerifierBlocksRetirement = async (): Promise<void> => {
    const before = await mutationSnapshot();
    assert.equal(await verifyKeyringWithoutInactive(), false);
    assert.deepEqual(
      await mutationSnapshot(),
      before,
      "keyring verifier changed state while an omitted verifier was live",
    );
  };
  const historicalVerifierTransaction = bytes("keyring-verifier:transaction");
  const historicalVerifierState = bytes("keyring-verifier:state");
  const historicalVerifierBrowser = bytes("keyring-verifier:browser");
  const historicalVerifierCreatedAt = new Date(Date.now() - 2_000);
  await admin`
    INSERT INTO public.tenant_platform_oidc_authentication_transactions (
      transaction_id,tenant_id,platform_provider_id,binding_id,provider_kind,
      protocol,access_epoch_id,access_source_id,operation_run_id,
      operation_digest,receipt_digest,network_digest,account_digest,
      provider_digest,state_digest,browser_digest,nonce_digest,
      provider_revision,binding_revision,configuration_revision,
      security_revision,plan_revision,mapping_revision,authorization_revision,
      assurance_policy_revision,client_secret_revision,discovery_revision,
      discovery_digest,jwks_revision,jwks_digest,verifier_key_version,
      verifier_ciphertext,client_id,tenant_redirect_uri,
      post_logout_redirect_uri,scopes,allow_refresh_token,use_user_info,
      return_path,state,version,claim_attempt_id,created_at,expires_at,
      claimed_at,completed_at,failure_reason
    )
    SELECT ${historicalVerifierTransaction}::bytea,source.tenant_id,
      source.platform_provider_id,source.binding_id,source.provider_kind,
      source.protocol,source.access_epoch_id,source.access_source_id,
      ${nextUuid()}::uuid,${bytes("keyring-verifier:operation")}::bytea,
      ${bytes("keyring-verifier:receipt")}::bytea,
      ${bytes("keyring-verifier:network")}::bytea,
      ${bytes("keyring-verifier:account")}::bytea,
      ${bytes("keyring-verifier:provider")}::bytea,
      ${historicalVerifierState}::bytea,${historicalVerifierBrowser}::bytea,
      ${bytes("keyring-verifier:nonce")}::bytea,source.provider_revision,
      source.binding_revision,source.configuration_revision,
      source.security_revision,source.plan_revision,source.mapping_revision,
      source.authorization_revision,source.assurance_policy_revision,
      source.client_secret_revision,source.discovery_revision,
      source.discovery_digest,source.jwks_revision,source.jwks_digest,
      ${inactiveKeyVersion}::integer,source.verifier_ciphertext,
      source.client_id,source.tenant_redirect_uri,
      source.post_logout_redirect_uri,source.scopes,
      source.allow_refresh_token,source.use_user_info,source.return_path,
      'pending',1,NULL,${historicalVerifierCreatedAt},
      ${new Date(historicalVerifierCreatedAt.getTime() + 10 * 60_000)},
      NULL,NULL,NULL
    FROM ONLY public.tenant_platform_oidc_authentication_transactions AS source
    WHERE source.tenant_id = ${fixture.tenant}::uuid
      AND source.transaction_id = ${bytes("first:transaction")}::bytea
  `;
  await assertInactiveVerifierBlocksRetirement();
  const [historicalVerifierClaim] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.claim_oidc_authentication_transaction_v1(
        ${transaction.json({
          attemptId: b64("keyring-verifier:attempt"),
          stateDigest: historicalVerifierState.toString("base64"),
          browserDigest: historicalVerifierBrowser.toString("base64"),
          claimedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(historicalVerifierClaim?.value.state, "claimed");
  await assertInactiveVerifierBlocksRetirement();
  await admin`
    UPDATE ONLY public.tenant_platform_oidc_authentication_transactions
    SET state = 'expired',version = 3,completed_at = transaction_timestamp(),
        failure_reason = 'expired'
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND transaction_id = ${historicalVerifierTransaction}::bytea
      AND state = 'claimed' AND version = 2
  `;
  assert.equal(
    await verifyKeyringWithoutInactive(),
    true,
    "terminal verifier transaction still blocked safe key retirement",
  );

  await admin`
    INSERT INTO public.tenant_memberships (
      id,tenant_id,user_id,role,status
    ) VALUES (
      ${nextUuid()}::uuid,${fixture.otherTenant}::uuid,${userId}::uuid,
      'read_only','active'
    )
  `;
  const switchSnapshot = await mutationSnapshot();
  const switchEvent = trace();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
        SELECT app.rotate_auth_session_tenant(
          ${bytes(`first:${firstSession}:token`)}::bytea,${nextUuid()}::uuid,
          ${bytes("federated-switch-token")}::bytea,
          ${bytes("federated-switch-csrf")}::bytea,
          ${fixture.otherTenant}::uuid,
          ${new Date(Date.now() + 20 * 60_000)},
          ${new Date(Date.now() + 7 * 60 * 60_000)},
          ${switchEvent.auditId}::uuid,${switchEvent.requestId}::uuid,
          ${switchEvent.correlationId}::uuid,'198.51.100.61'::inet,
          'Periapsis platform OIDC authentication runtime proof'::text
        )
      `,
      userId,
      fixture.tenant,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "42501");
      assert.equal(
        error.message,
        "typed-provenance session tenant switch requires provenance-aware rotation",
      );
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), switchSnapshot);

  const repeat = await prepareAttempt(
    "repeat",
    aliases,
    updatePresentationOnlyMetadata,
  );
  assert.equal(repeat.planning.userId, userId);
  let repeatCommand: JsonRecord | undefined;
  const repeatResult = await applyAttempt(repeat, {
    identityAction: "no_change",
    accessAction: "no_change",
    commandSink: (command) => {
      repeatCommand = command;
    },
  });
  assert.equal(repeatResult.category, "success");
  assert.equal(repeatResult.userId, userId);
  const [clearedProfile] = await admin<
    {
      totalContributions: number;
      liveContributions: number;
      retiredContributions: number;
      effectiveDisplayName: string;
      effectiveEmail: string | null;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_platform_federated_provider_profile_contributions AS contribution
       JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
         ON grant_row.tenant_id = contribution.tenant_id
        AND grant_row.id = contribution.access_grant_id
       WHERE grant_row.user_id = ${userId}::uuid) AS "totalContributions",
      (SELECT count(*)::integer
       FROM public.tenant_platform_federated_provider_profile_contributions AS contribution
       JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
         ON grant_row.tenant_id = contribution.tenant_id
        AND grant_row.id = contribution.access_grant_id
       WHERE grant_row.user_id = ${userId}::uuid
         AND contribution.retired_at IS NULL) AS "liveContributions",
      (SELECT count(*)::integer
       FROM public.tenant_platform_federated_provider_profile_contributions AS contribution
       JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
         ON grant_row.tenant_id = contribution.tenant_id
        AND grant_row.id = contribution.access_grant_id
       WHERE grant_row.user_id = ${userId}::uuid
         AND contribution.retired_at IS NOT NULL) AS "retiredContributions",
      profile.display_name AS "effectiveDisplayName",
      profile.email AS "effectiveEmail"
    FROM public.tenant_user_profiles AS profile
    WHERE profile.tenant_id = ${fixture.tenant}::uuid
      AND profile.user_id = ${userId}::uuid
  `;
  assert.deepEqual(clearedProfile, {
    totalContributions: 1,
    liveContributions: 0,
    retiredContributions: 1,
    effectiveDisplayName: "Federated user",
    effectiveEmail: null,
  });
  assert(repeatCommand);
  const clearedReplaySnapshot = await mutationSnapshot();
  assert.deepEqual(
    await submitApplyCommand("repeat exact replay", repeatCommand),
    { ...repeatResult, replayed: true },
  );
  assert.deepEqual(await mutationSnapshot(), clearedReplaySnapshot);

  const secondFirst = await prepareAttempt(
    "second-subject-first",
    secondSubjectAliases,
  );
  assert.equal(secondFirst.planning.userId, null);
  const secondFirstResult = await applyAttempt(secondFirst, {
    identityAction: "create_user_and_external_identity",
    accessAction: "ensure",
  });
  assert.equal(secondFirstResult.category, "success");
  const secondUserId = stringField(secondFirstResult, "userId");
  assert.notEqual(secondUserId, userId);

  const rotated = await prepareAttempt(
    "first-subject-rotated-alias",
    rotatedAliases,
  );
  assert.equal(rotated.planning.userId, userId);
  const rotatedSession = nextUuid();
  const rotatedResult = await applyAttempt(rotated, {
    identityAction: "no_change",
    accessAction: "no_change",
    sessionId: rotatedSession,
  });
  assert.equal(rotatedResult.category, "success");
  assert.equal(rotatedResult.userId, userId);
  await assertNoOidcMaterialForOwners("initial material-less session", [
    rotatedSession,
  ]);

  const secondRepeat = await prepareAttempt(
    "second-subject-repeat",
    secondSubjectAliases,
  );
  assert.equal(secondRepeat.planning.userId, secondUserId);
  const secondRepeatSession = nextUuid();
  const secondRepeatResult = await applyAttempt(secondRepeat, {
    identityAction: "no_change",
    accessAction: "no_change",
    sessionId: secondRepeatSession,
  });
  assert.equal(secondRepeatResult.category, "success");
  assert.equal(secondRepeatResult.userId, secondUserId);

  const [liveCounts] = await admin<
    {
      identities: number;
      aliases: number;
      memberships: number;
      grants: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.platform_federated_external_identities
       WHERE platform_provider_id = ${fixture.provider}::uuid) AS identities,
      (SELECT count(*)::integer FROM public.platform_federated_external_identity_aliases
       WHERE platform_provider_id = ${fixture.provider}::uuid
         AND retired_at IS NULL) AS aliases,
      (SELECT count(*)::integer FROM public.tenant_memberships
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND user_id IN (${userId}::uuid,${secondUserId}::uuid)) AS memberships,
      (SELECT count(*)::integer FROM public.tenant_platform_federated_provider_access_grants
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND user_id IN (${userId}::uuid,${secondUserId}::uuid)
         AND ended_at IS NULL) AS grants
  `;
  assert.deepEqual(liveCounts, {
    identities: 2,
    aliases: 3,
    memberships: 2,
    grants: 2,
  });

  const [firstSessionAfterRepeat] = await admin<{ live: boolean }[]>`
    SELECT session.revoked_at IS NULL AS live
    FROM public.auth_sessions AS session
    WHERE session.id = ${firstSession}::uuid
  `;
  assert.equal(firstSessionAfterRepeat?.live, true);

  await Promise.all(
    [rotatedSession, secondRepeatSession].map(async (authoritativeSession) => {
      const authority = await loadRevalidation(authoritativeSession);
      assert(authority);
      assert.equal(
        object(authority.live, "authoritative live").primaryActive,
        true,
      );
    }),
  );

  const rotationState = await loadRevalidation(rotatedSession);
  assert(rotationState);
  const rotationSnapshot = object(rotationState.snapshot, "rotation snapshot");
  const rotationLive = object(rotationState.live, "rotation live");
  const [rotationSource] = await admin<
    {
      familyId: string;
      absoluteExpiresAt: string;
      extendedAbsoluteExpiresAt: string;
    }[]
  >`
    SELECT rotation_family_id::text AS "familyId",
           to_char(absolute_expires_at AT TIME ZONE 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "absoluteExpiresAt",
           to_char((absolute_expires_at + interval '1 microsecond') AT TIME ZONE 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "extendedAbsoluteExpiresAt"
    FROM public.auth_sessions WHERE id = ${rotatedSession}::uuid
  `;
  assert(rotationSource);
  const rotationObservedAt = new Date();
  const rotationBase = {
    tenantId: fixture.tenant,
    sessionId: rotatedSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(rotationSnapshot, "version"),
    observedAt: rotationObservedAt.toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(rotationLive, "requirement"),
  } as const;
  const extendedRotation: JsonRecord = {
    ...rotationBase,
    session: {
      sessionId: nextUuid(),
      familyId: rotationSource.familyId,
      tokenDigest: b64("extended-rotation-token"),
      csrfDigest: b64("extended-rotation-csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(
        rotationObservedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: rotationSource.extendedAbsoluteExpiresAt,
    },
  };
  const rotationDenialSnapshot = await mutationSnapshot();
  await assert.rejects(
    applyRevalidation(extendedRotation),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "22023");
      assert.equal(
        error.message,
        "invalid federated session revalidation mutation",
      );
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), rotationDenialSnapshot);

  const rotatedSuccessor = nextUuid();
  const exactRotation: JsonRecord = {
    ...rotationBase,
    session: {
      sessionId: rotatedSuccessor,
      familyId: rotationSource.familyId,
      tokenDigest: b64("exact-rotation-token"),
      csrfDigest: b64("exact-rotation-csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(
        rotationObservedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: rotationSource.absoluteExpiresAt,
    },
  };
  const exactRotationResult = await applyRevalidation(exactRotation);
  assert.equal(exactRotationResult.decision, "rotate");
  assert.equal(exactRotationResult.newSessionId, rotatedSuccessor);
  const exactRotationReplaySnapshot = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(exactRotation), exactRotationResult);
  assert.deepEqual(await mutationSnapshot(), exactRotationReplaySnapshot);
  const rotatedSuccessorAuthority = await loadRevalidation(rotatedSuccessor);
  assert(rotatedSuccessorAuthority);
  assert.equal(
    object(rotatedSuccessorAuthority.live, "rotated successor live")
      .primaryActive,
    true,
  );
  await assertNoOidcMaterialForOwners("material-less rotation", [
    rotatedSession,
    rotatedSuccessor,
  ]);

  const secondRotationSnapshot = object(
    rotatedSuccessorAuthority.snapshot,
    "second rotation snapshot",
  );
  const secondRotationLive = object(
    rotatedSuccessorAuthority.live,
    "second rotation live",
  );
  const secondRotationObservedAt = new Date();
  const secondRotatedSuccessor = nextUuid();
  const secondRotation: JsonRecord = {
    tenantId: fixture.tenant,
    sessionId: rotatedSuccessor,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(secondRotationSnapshot, "version"),
    observedAt: secondRotationObservedAt.toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(secondRotationLive, "requirement"),
    session: {
      sessionId: secondRotatedSuccessor,
      familyId: rotationSource.familyId,
      tokenDigest: b64("second-exact-rotation-token"),
      csrfDigest: b64("second-exact-rotation-csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(
        secondRotationObservedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: rotationSource.absoluteExpiresAt,
    },
  };
  const secondRotationResult = await applyRevalidation(secondRotation);
  assert.equal(secondRotationResult.decision, "rotate");
  assert.equal(secondRotationResult.newSessionId, secondRotatedSuccessor);
  await assertNoOidcMaterialForOwners("second material-less family rotation", [
    rotatedSession,
    rotatedSuccessor,
    secondRotatedSuccessor,
  ]);

  const secondRotatedAuthority = await loadRevalidation(secondRotatedSuccessor);
  assert(secondRotatedAuthority);
  const requiredMaterialObservedAt = new Date();
  await assertRequiredOidcMaterialFailsClosed(rotated, {
    tenantId: fixture.tenant,
    sessionId: secondRotatedSuccessor,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(
      object(secondRotatedAuthority.snapshot, "required material snapshot"),
      "version",
    ),
    observedAt: requiredMaterialObservedAt.toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(
      object(secondRotatedAuthority.live, "required material live"),
      "requirement",
    ),
    session: {
      sessionId: nextUuid(),
      familyId: rotationSource.familyId,
      tokenDigest: b64("missing-material-rotation-token"),
      csrfDigest: b64("missing-material-rotation-csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(
        requiredMaterialObservedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: rotationSource.absoluteExpiresAt,
    },
  });

  const materialAttempt = await prepareAttempt(
    "material-present-owner-transfer",
    aliases,
  );
  assert.equal(materialAttempt.planning.userId, userId);
  const materialSourceSession = nextUuid();
  const materialSourceResult = await applyAttempt(materialAttempt, {
    identityAction: "no_change",
    accessAction: "no_change",
    sessionId: materialSourceSession,
  });
  assert.equal(materialSourceResult.category, "success");
  const [materialSource] = await admin<
    { absoluteExpiresAt: string; familyId: string }[]
  >`
    SELECT rotation_family_id::text AS "familyId",
           to_char(absolute_expires_at AT TIME ZONE 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "absoluteExpiresAt"
    FROM public.auth_sessions
    WHERE id = ${materialSourceSession}::uuid
  `;
  assert(materialSource);
  const materialCreatedAt = new Date();
  const materialExpiresAt = new Date(materialCreatedAt.getTime() + 4 * 60_000);
  await admin`
    INSERT INTO public.tenant_oidc_session_materials (
      id,tenant_id,authority,session_id,rotation_family_id,user_id,provider_id,
      binding_id,provider_kind,external_identity_id,aad_version,
      refresh_generation,refresh_state,refresh_version,expires_at,client_id,
      post_logout_redirect_uri,logout_disposition,created_at,updated_at
    ) VALUES (
      ${materialAttempt.operationRunId}::uuid,${fixture.tenant}::uuid,
      'tenant_platform_provider',${materialSourceSession}::uuid,
      ${materialSource.familyId}::uuid,${userId}::uuid,${fixture.provider}::uuid,
      ${fixture.binding}::uuid,'oidc',
      ${stringField(materialAttempt.planning, "externalIdentityId")}::uuid,
      1,0,'unavailable',1,${materialExpiresAt},${clientId},
      ${postLogoutRedirectUri},'not_configured',${materialCreatedAt},
      ${materialCreatedAt}
    )
  `;
  const [materialBefore] = await admin<
    { invariant: postgres.JSONValue; sessionId: string }[]
  >`
    SELECT to_jsonb(material) - 'session_id' - 'updated_at' AS invariant,
           material.session_id::text AS "sessionId"
    FROM public.tenant_oidc_session_materials AS material
    WHERE material.id = ${materialAttempt.operationRunId}::uuid
  `;
  assert(materialBefore);
  assert.equal(materialBefore.sessionId, materialSourceSession);
  const materialRotationAuthority = await loadRevalidation(
    materialSourceSession,
  );
  assert(materialRotationAuthority);
  const materialRotationObservedAt = new Date();
  const materialSuccessorSession = nextUuid();
  const materialRotationResult = await applyRevalidation({
    tenantId: fixture.tenant,
    sessionId: materialSourceSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(
      object(materialRotationAuthority.snapshot, "material rotation snapshot"),
      "version",
    ),
    observedAt: materialRotationObservedAt.toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(
      object(materialRotationAuthority.live, "material rotation live"),
      "requirement",
    ),
    session: {
      sessionId: materialSuccessorSession,
      familyId: materialSource.familyId,
      tokenDigest: b64("material-present-rotation-token"),
      csrfDigest: b64("material-present-rotation-csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(
        materialRotationObservedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: materialSource.absoluteExpiresAt,
    },
  });
  assert.equal(materialRotationResult.newSessionId, materialSuccessorSession);
  const [materialAfter] = await admin<
    { invariant: postgres.JSONValue; sessionId: string }[]
  >`
    SELECT to_jsonb(material) - 'session_id' - 'updated_at' AS invariant,
           material.session_id::text AS "sessionId"
    FROM public.tenant_oidc_session_materials AS material
    WHERE material.id = ${materialAttempt.operationRunId}::uuid
  `;
  assert(materialAfter);
  assert.equal(materialAfter.sessionId, materialSuccessorSession);
  assert.deepEqual(
    materialAfter.invariant,
    materialBefore.invariant,
    "material-present rotation changed immutable material",
  );

  const tombstoneAliases = [
    { keyVersion: inactiveKeyVersion, digest: b64("keyring-tombstone-old") },
    { keyVersion, digest: b64("keyring-tombstone-current") },
  ];
  const tombstoneAttempt = await prepareAttempt(
    "keyring-retired-identity-tombstone",
    tombstoneAliases,
  );
  const tombstoneResult = await applyAttempt(tombstoneAttempt, {
    identityAction: "create_user_and_external_identity",
    accessAction: "ensure",
    sessionId: nextUuid(),
  });
  assert.equal(tombstoneResult.category, "success");
  const tombstoneUserId = stringField(tombstoneResult, "userId");
  await admin.begin(async (transaction) => {
    await transaction`
      UPDATE public.platform_federated_external_identities AS identity
      SET retired_at = transaction_timestamp(),
          last_observed_at = transaction_timestamp(),
          updated_at = transaction_timestamp(),
          version = identity.version + 1
      WHERE identity.platform_provider_id = ${fixture.provider}::uuid
        AND identity.user_id = ${tombstoneUserId}::uuid
    `;
    await transaction`
      UPDATE public.platform_federated_external_identity_aliases AS alias
      SET retired_at = transaction_timestamp()
      WHERE alias.platform_provider_id = ${fixture.provider}::uuid
        AND alias.external_identity_id = (
          SELECT identity.id
          FROM public.platform_federated_external_identities AS identity
          WHERE identity.platform_provider_id = ${fixture.provider}::uuid
            AND identity.user_id = ${tombstoneUserId}::uuid
        )
        AND alias.key_version = ${keyVersion}
        AND alias.retired_at IS NULL
    `;
  });
  assert.equal(
    await verifyKeyringWithoutInactive(),
    true,
    "a retained-key retired alias did not preserve an identity tombstone",
  );
  const soleOmittedTombstoneSnapshot = await mutationSnapshot();
  try {
    await admin.begin(async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_federated_external_identity_aliases
        DISABLE TRIGGER platform_federated_external_identity_aliases_guard_v1
      `;
      await transaction`
        DELETE FROM public.platform_federated_external_identity_aliases AS alias
        WHERE alias.platform_provider_id = ${fixture.provider}::uuid
          AND alias.external_identity_id = (
            SELECT identity.id
            FROM public.platform_federated_external_identities AS identity
            WHERE identity.platform_provider_id = ${fixture.provider}::uuid
              AND identity.user_id = ${tombstoneUserId}::uuid
          )
          AND alias.key_version = ${keyVersion}
      `;
      const [row] = await transaction<{ ready: boolean }[]>`
        SELECT app.verify_identity_keyring_v3(
          ARRAY[${retainedSecretKeyVersion},${keyVersion}]::integer[],
          ARRAY[${bytes("retained-secret-key")},${bytes("promoted-active-key")}]::bytea[],
          ${keyVersion}::integer
        ) AS ready
      `;
      assert.equal(
        row?.ready,
        false,
        "a sole omitted-key identity tombstone was accepted",
      );
      throw new Error("rollback sole omitted-key tombstone proof");
    });
  } catch (error) {
    assert(error instanceof Error);
    assert.equal(error.message, "rollback sole omitted-key tombstone proof");
  }
  assert.deepEqual(await mutationSnapshot(), soleOmittedTombstoneSnapshot);

  await admin`
    UPDATE public.platform_federated_external_identity_aliases
    SET retired_at = transaction_timestamp()
    WHERE platform_provider_id = ${fixture.provider}::uuid
      AND key_version = ${keyVersion}
      AND subject_digest = ${bytes("second-subject")}::bytea
  `;
  const liveIdentityRetiredAliasSnapshot = await mutationSnapshot();
  assert.equal(
    await verifyKeyringWithoutInactive(),
    false,
    "a live identity with only retired retained aliases allowed key retirement",
  );
  assert.deepEqual(await mutationSnapshot(), liveIdentityRetiredAliasSnapshot);
  const retiredAlias = await prepareAttempt(
    "retired-alias-collision",
    secondSubjectAliases,
  );
  assert.equal(retiredAlias.planning.userId, null);
  await assertRollback("identity_collision", () =>
    applyAttempt(retiredAlias, {
      identityAction: "create_user_and_external_identity",
      accessAction: "ensure",
    }),
  );

  const retiredIdentityAliases = [
    { keyVersion, digest: b64("retired-identity-subject") },
  ];
  const retiredIdentityFirst = await prepareAttempt(
    "retired-identity-first",
    retiredIdentityAliases,
  );
  const retiredIdentityResult = await applyAttempt(retiredIdentityFirst, {
    identityAction: "create_user_and_external_identity",
    accessAction: "ensure",
  });
  assert.equal(retiredIdentityResult.category, "success");
  const retiredIdentityUserId = stringField(retiredIdentityResult, "userId");
  await admin`
    UPDATE public.platform_federated_external_identities AS identity
    SET retired_at = transaction_timestamp(),
        last_observed_at = transaction_timestamp(),
        updated_at = transaction_timestamp(),
        version = identity.version + 1
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.user_id = ${retiredIdentityUserId}::uuid
  `;
  const retiredIdentity = await prepareAttempt(
    "retired-identity-collision",
    retiredIdentityAliases,
  );
  assert.equal(retiredIdentity.planning.userId, null);
  await assertRollback("identity_collision", () =>
    applyAttempt(retiredIdentity, {
      identityAction: "create_user_and_external_identity",
      accessAction: "ensure",
    }),
  );

  const revalidation = await loadRevalidation(firstSession);
  assert(revalidation);
  const revalidationSnapshot = object(revalidation.snapshot, "snapshot");
  const revalidationLive = object(revalidation.live, "live");
  const revalidated = await applyRevalidation({
    tenantId: fixture.tenant,
    sessionId: firstSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(revalidationSnapshot, "version"),
    observedAt: new Date().toISOString(),
    decision: "usable",
    reason: "current",
    requirement: jsonField(revalidationLive, "requirement"),
  });
  assert.equal(revalidated.decision, "usable");

  const stale = await prepareAttempt("stale-after-mutation", aliases);
  await assertRollback("stale", () =>
    applyAttempt(stale, {
      identityAction: "no_change",
      accessAction: "no_change",
      identityEpoch: numberField(stale.planning, "identityEpoch") + 1,
    }),
  );

  const collision = await prepareAttempt("collision-after-mutation", aliases);
  await assertRollback("identity_collision", () =>
    applyAttempt(collision, {
      identityAction: "no_change",
      accessAction: "no_change",
      sessionId: firstSession,
    }),
  );

  await deactivateBinding();
  const [solePath] = await admin<
    {
      membershipStatus: string;
      userActive: boolean;
      identityRetired: boolean;
      liveGrants: number;
    }[]
  >`
    SELECT membership.status AS "membershipStatus",
           local_user.active AS "userActive",
           identity.retired_at IS NOT NULL AS "identityRetired",
           (SELECT count(*)::integer
            FROM public.tenant_platform_federated_provider_access_grants AS grant_row
            WHERE grant_row.tenant_id = ${fixture.tenant}::uuid
              AND grant_row.user_id = ${userId}::uuid
              AND grant_row.ended_at IS NULL) AS "liveGrants"
    FROM public.tenant_memberships AS membership
    JOIN public.users AS local_user ON local_user.id = membership.user_id
    JOIN public.platform_federated_external_identities AS identity
      ON identity.user_id = membership.user_id
     AND identity.platform_provider_id = ${fixture.provider}::uuid
    WHERE membership.tenant_id = ${fixture.tenant}::uuid
      AND membership.user_id = ${userId}::uuid
  `;
  assert.deepEqual(solePath, {
    membershipStatus: "suspended",
    userActive: true,
    identityRetired: false,
    liveGrants: 0,
  });
  const drifted = await loadRevalidation(firstSession);
  assert(drifted);
  const driftedSnapshot = object(drifted.snapshot, "drifted snapshot");
  const driftedLive = object(drifted.live, "drifted live");
  assert.equal(driftedLive.primaryActive, false);
  const revokeMutation: JsonRecord = {
    tenantId: fixture.tenant,
    sessionId: firstSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(driftedSnapshot, "version"),
    observedAt: new Date().toISOString(),
    decision: "revoke",
    reason: "primary_drift",
    requirement: jsonField(driftedLive, "requirement"),
  };
  const revoked = await applyRevalidation(revokeMutation);
  assert.equal(revoked.decision, "revoke");
  const [revokedSession] = await admin<{ revoked: boolean }[]>`
    SELECT revoked_at IS NOT NULL AS revoked
    FROM public.auth_sessions WHERE id = ${firstSession}::uuid
  `;
  assert.equal(revokedSession?.revoked, true);
  const terminalRevalidationSnapshot = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(revokeMutation), revoked);
  assert.deepEqual(await mutationSnapshot(), terminalRevalidationSnapshot);

  await assert.rejects(
    applyRevalidation({ ...revokeMutation, reason: "lifecycle" }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "40001");
      assert.equal(error.message, "tenant platform session replay mismatch");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), terminalRevalidationSnapshot);

  await assert.rejects(
    applyRevalidation({
      ...revokeMutation,
      expectedVersion: numberField(driftedSnapshot, "version") + 1,
    }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "40001");
      assert.equal(error.message, "tenant platform session command lost CAS");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), terminalRevalidationSnapshot);

  await activateBinding("create", "provider_access_only");
  await admin`
    UPDATE public.tenant_memberships
    SET status = 'active', updated_at = transaction_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid AND user_id = ${userId}::uuid
  `;
  const noGrant = await prepareAttempt("no-change-without-live-grant", aliases);
  await assertRollback("stale", () =>
    applyAttempt(noGrant, {
      identityAction: "no_change",
      accessAction: "no_change",
    }),
  );
  const restored = await applyAttempt(noGrant, {
    identityAction: "no_change",
    accessAction: "ensure",
  });
  assert.equal(restored.category, "success");

  const evidenceCapAllowedAttempt = await prepareAttempt(
    "platform-mfa-evidence-cap-1023",
    aliases,
  );
  const evidenceCapAllowedSession = nextUuid();
  const evidenceCapAllowedResult = await applyAttempt(
    evidenceCapAllowedAttempt,
    {
      identityAction: "no_change",
      accessAction: "no_change",
      sessionId: evidenceCapAllowedSession,
    },
  );
  assert.equal(evidenceCapAllowedResult.category, "success");
  const evidenceCapDeniedAttempt = await prepareAttempt(
    "platform-mfa-evidence-cap-1024",
    aliases,
  );
  const evidenceCapDeniedSession = nextUuid();
  const evidenceCapDeniedResult = await applyAttempt(evidenceCapDeniedAttempt, {
    identityAction: "no_change",
    accessAction: "no_change",
    sessionId: evidenceCapDeniedSession,
  });
  assert.equal(evidenceCapDeniedResult.category, "success");

  const mfaPolicyAt = new Date();
  const platformFactorId = nextUuid();
  await admin.begin(async (transaction) => {
    await withMfaPolicyRevisionWrite(
      transaction,
      "retire",
      fixture.tenantMfaPolicy,
      1,
      async () => {
        await transaction`
          UPDATE public.mfa_policy_revisions
          SET retired_at = ${mfaPolicyAt}
          WHERE id = ${fixture.tenantMfaPolicy}::uuid AND revision = 1
            AND retired_at IS NULL
        `;
      },
    );
    await withMfaPolicyRevisionWrite(
      transaction,
      "insert",
      fixture.tenantMfaPolicy,
      2,
      async () => {
        await transaction`
          INSERT INTO public.mfa_policy_revisions (
            id,revision,tenant_id,scope,level,local_required,
            freshness_nanoseconds,created_at
          ) VALUES (
            ${fixture.tenantMfaPolicy}::uuid,2,${fixture.tenant}::uuid,
            'tenant_baseline','mfa',true,0,${mfaPolicyAt}
          )
        `;
      },
    );
    await transaction`
      INSERT INTO public.tenant_totp_factors (
        id,tenant_id,user_id,secret_envelope,key_version,otp_algorithm,
        digits,period_seconds,last_accepted_counter,record_version,
        security_revision,status,confirmed_at,created_at,updated_at
      ) VALUES (
        ${platformFactorId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        ${Buffer.alloc(32, 0x73)}::bytea,${keyVersion},'SHA1',6,30,-1,1,1,
        'active',${mfaPolicyAt},${mfaPolicyAt},${mfaPolicyAt}
      )
    `;
  });

  await admin`
    INSERT INTO public.auth_session_tenant_platform_federated_evidence (
      id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,
      trust_rule_revision
    )
    SELECT uuidv7(),evidence.tenant_id,evidence.session_id,evidence.user_id,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.external_identity_id,evidence.level,evidence.authenticated_at,
      evidence.expires_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    CROSS JOIN generate_series(1,1022)
    WHERE evidence.session_id = ${evidenceCapAllowedSession}::uuid
  `;
  await admin`
    INSERT INTO public.auth_session_tenant_platform_federated_evidence (
      id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,
      trust_rule_revision
    )
    SELECT uuidv7(),evidence.tenant_id,evidence.session_id,evidence.user_id,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.external_identity_id,evidence.level,evidence.authenticated_at,
      evidence.expires_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    CROSS JOIN generate_series(1,1023)
    WHERE evidence.session_id = ${evidenceCapDeniedSession}::uuid
  `;
  const evidenceCapAllowedAuthority = await loadRevalidation(
    evidenceCapAllowedSession,
  );
  assert(evidenceCapAllowedAuthority);
  const evidenceCapAllowedSnapshot = object(
    evidenceCapAllowedAuthority.snapshot,
    "1023 evidence snapshot",
  );
  const evidenceCapAllowedLive = object(
    evidenceCapAllowedAuthority.live,
    "1023 evidence live authority",
  );
  const evidenceCapAllowedContinuation = nextUuid();
  const evidenceCapAllowedApplied = await applyRevalidation({
    tenantId: fixture.tenant,
    sessionId: evidenceCapAllowedSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(evidenceCapAllowedSnapshot, "version"),
    observedAt: new Date().toISOString(),
    decision: "step_up",
    reason: "assurance_insufficient",
    requirement: jsonField(evidenceCapAllowedLive, "requirement"),
    continuation: {
      continuationId: evidenceCapAllowedContinuation,
      receiptDigest: b64("platform-mfa-evidence-cap-1023:receipt"),
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    },
  });
  assert.equal(
    evidenceCapAllowedApplied.continuationId,
    evidenceCapAllowedContinuation,
  );
  const [evidenceCapAllowedProof] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_post_primary_platform_federated_evidence
    WHERE continuation_id = ${evidenceCapAllowedContinuation}::uuid
  `;
  assert.equal(evidenceCapAllowedProof?.count, 1023);

  const evidenceCapDeniedAuthority = await loadRevalidation(
    evidenceCapDeniedSession,
  );
  assert(evidenceCapDeniedAuthority);
  const evidenceCapDeniedSnapshot = object(
    evidenceCapDeniedAuthority.snapshot,
    "1024 evidence snapshot",
  );
  const evidenceCapDeniedLive = object(
    evidenceCapDeniedAuthority.live,
    "1024 evidence live authority",
  );
  const evidenceCapDeniedContinuation = nextUuid();
  const evidenceCapDeniedBefore = await mutationSnapshot();
  await assert.rejects(
    applyRevalidation({
      tenantId: fixture.tenant,
      sessionId: evidenceCapDeniedSession,
      userId,
      audience: "api",
      authenticationMethod: "oidc",
      expectedVersion: jsonField(evidenceCapDeniedSnapshot, "version"),
      observedAt: new Date().toISOString(),
      decision: "step_up",
      reason: "assurance_insufficient",
      requirement: jsonField(evidenceCapDeniedLive, "requirement"),
      continuation: {
        continuationId: evidenceCapDeniedContinuation,
        receiptDigest: b64("platform-mfa-evidence-cap-1024:receipt"),
        expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
      },
    }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "22023");
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    evidenceCapDeniedBefore,
    "1024 baseline evidence stranded a continuation or command",
  );

  const continuationAttempt = await prepareAttempt(
    "platform-mfa-continuation",
    aliases,
  );
  assert.equal(continuationAttempt.planning.hasEnrollableFactor, true);
  const continuationId = nextUuid();
  const continuationReceipt = b64("platform-mfa-continuation:receipt");
  const continuationExpiresAt = new Date(Date.now() + 10 * 60_000);
  const continuationResult = await applyAttempt(continuationAttempt, {
    identityAction: "no_change",
    accessAction: "no_change",
    continuation: {
      id: continuationId,
      receiptDigest: continuationReceipt,
      expiresAt: continuationExpiresAt.toISOString(),
      assurance: "step_up_required",
    },
  });
  assert.equal(continuationResult.category, "success");
  assert.equal(continuationResult.continuationId, continuationId);
  await assertNoOidcMaterialForOwners("material-less initial continuation", [
    continuationId,
  ]);

  const wrongResolveSnapshot = await mutationSnapshot();
  await assert.rejects(
    resolveContinuationAuthority(
      continuationId,
      bytes("platform-mfa-continuation:wrong"),
      new Date(),
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "42501");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), wrongResolveSnapshot);

  const continuationAuthority = await resolveContinuationAuthority(
    continuationId,
    bytes("platform-mfa-continuation:receipt"),
    new Date(),
  );
  assert.equal(continuationAuthority.continuationOrigin, "initial_login");
  assert.equal(
    continuationAuthority.continuationReceiptDigest,
    continuationReceipt,
  );
  const continuationBinding = mfaBinding(continuationAuthority);
  const invalidChallengeBase = {
    id: b64("platform-mfa-continuation:invalid-challenge"),
    browserDigest: b64("platform-mfa-continuation:invalid-browser"),
    binding: continuationBinding,
    allowedFactors: ["totp"],
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    state: "pending",
    version: 1,
  };
  await Promise.all(
    [undefined, b64("platform-mfa-continuation:wrong")].map(
      async (invalidReceipt) => {
        const startSnapshot = await mutationSnapshot();
        await assert.rejects(
          asRole(
            "periapsis_api",
            (transaction) => transaction`
        SELECT app.create_mfa_step_up_challenge_v1(
          ${transaction.json({
            ...invalidChallengeBase,
            ...(invalidReceipt === undefined
              ? {}
              : {
                  continuationReceiptDigest: invalidReceipt,
                }),
          })}::jsonb
        )
      `,
          ),
          (error: unknown) => {
            assert(error instanceof Error);
            assert(
              ["22023", "42501"].includes((error as ErrorWithCode).code ?? ""),
            );
            return true;
          },
        );
        assert.deepEqual(await mutationSnapshot(), startSnapshot);
      },
    ),
  );

  const initialChallenge = await createAndClaimTotpChallenge(
    continuationAuthority,
    continuationReceipt,
    "platform-mfa-continuation",
    {
      disable: async () => {
        await admin`UPDATE public.users SET active = false WHERE id = ${userId}::uuid`;
      },
      restore: async () => {
        await admin`UPDATE public.users SET active = true WHERE id = ${userId}::uuid`;
      },
    },
  );
  const [initialAnchor] = await admin<{ anchorId: string }[]>`
    SELECT authority_anchor_id::text AS "anchorId"
    FROM public.tenant_mfa_step_up_challenges
    WHERE id = ${initialChallenge.challengeId}::bytea
  `;
  assert(initialAnchor);
  const [anchorProjectionBefore] = await admin<{ value: postgres.JSONValue }[]>`
    SELECT app.private_mfa_evidence_projection_v1(
      ${fixture.tenant}::uuid,'anchor',${initialAnchor.anchorId}::uuid
    ) AS value
  `;
  const [sourceEvidence] = await admin<
    {
      platformProviderId: string;
      bindingId: string;
      externalIdentityId: string;
      level: string;
      authenticatedAt: Date;
      expiresAt: Date;
      trustRuleRevision: number;
    }[]
  >`
    SELECT platform_provider_id::text AS "platformProviderId",
      binding_id::text AS "bindingId",external_identity_id::text AS "externalIdentityId",
      level,authenticated_at AS "authenticatedAt",expires_at AS "expiresAt",
      trust_rule_revision::integer AS "trustRuleRevision"
    FROM public.tenant_post_primary_platform_federated_evidence
    WHERE continuation_id = ${continuationId}::uuid LIMIT 1
  `;
  assert(sourceEvidence);
  await admin`
    INSERT INTO public.tenant_post_primary_platform_federated_evidence (
      id,tenant_id,continuation_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      ${nextUuid()}::uuid,${fixture.tenant}::uuid,${continuationId}::uuid,
      ${userId}::uuid,${sourceEvidence.platformProviderId}::uuid,
      ${sourceEvidence.bindingId}::uuid,${sourceEvidence.externalIdentityId}::uuid,
      ${sourceEvidence.level},${new Date(sourceEvidence.authenticatedAt.getTime() + 1)},
      ${sourceEvidence.expiresAt},${sourceEvidence.trustRuleRevision}
    )
  `;
  const [anchorProjectionAfter] = await admin<{ value: postgres.JSONValue }[]>`
    SELECT app.private_mfa_evidence_projection_v1(
      ${fixture.tenant}::uuid,'anchor',${initialAnchor.anchorId}::uuid
    ) AS value
  `;
  assert.deepEqual(anchorProjectionAfter?.value, anchorProjectionBefore?.value);

  const initialMfaSession = nextUuid();
  const initialMfaFamily = nextUuid();
  const initialCompletedAt = initialChallenge.completedAt;
  const initialCompletion = {
    challengeId: initialChallenge.challengeId.toString("base64"),
    expectedChallengeVersion: 2,
    binding: initialChallenge.binding,
    factorId: platformFactorId,
    expectedFactorVersion: 1,
    expectedSecurityRevision: 1,
    counter: 0,
    completedAt: initialCompletedAt.toISOString(),
    sessionMutation: "consume_continuation",
    auditKind: "mfa.totp_step_up_completed",
    recoveryRestricted: false,
    session: {
      sessionId: initialMfaSession,
      familyId: initialMfaFamily,
      tokenDigest: b64("platform-mfa-continuation:token"),
      csrfDigest: b64("platform-mfa-continuation:csrf"),
      authenticationMethod: "totp",
      idleExpiresAt: new Date(
        initialCompletedAt.getTime() + 30 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: new Date(
        initialCompletedAt.getTime() + 8 * 60 * 60_000,
      ).toISOString(),
    },
    continuationReceiptDigest: continuationReceipt,
  };
  const invalidCompletionSnapshot = await mutationSnapshot();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${transaction.json({
          ...initialCompletion,
          continuationReceiptDigest: b64("platform-mfa-continuation:wrong"),
        })}::jsonb
      )
    `,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "40001");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), invalidCompletionSnapshot);
  const [initialCompletionResult] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${transaction.json(initialCompletion)}::jsonb
      ) AS value
    `,
  );
  assert.equal(initialCompletionResult?.value.newSessionId, initialMfaSession);
  const completedReplaySnapshot = await mutationSnapshot();
  const [initialReplay] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${transaction.json(initialCompletion)}::jsonb
      ) AS value
    `,
  );
  assert.deepEqual(initialReplay?.value, initialCompletionResult?.value);
  assert.deepEqual(await mutationSnapshot(), completedReplaySnapshot);
  const [initialSessionProof] = await admin<
    {
      authenticationMethod: string;
      primaryKind: string;
      continuationState: string;
    }[]
  >`
    SELECT session.authentication_method AS "authenticationMethod",
      state.primary_kind AS "primaryKind",continuation.state AS "continuationState"
    FROM public.auth_sessions AS session
    JOIN public.auth_session_mfa_states AS state ON state.session_id = session.id
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id = ${continuationId}::uuid
    WHERE session.id = ${initialMfaSession}::uuid
  `;
  assert.deepEqual(initialSessionProof, {
    authenticationMethod: "oidc",
    primaryKind: "tenant_platform_provider",
    continuationState: "consumed",
  });
  await assertNoOidcMaterialForOwners(
    "material-less initial continuation promotion",
    [continuationId, initialMfaSession],
  );
  const [promotedLineage] = await admin<{ attested: boolean }[]>`
    SELECT app.private_tenant_platform_oidc_material_absence_attested_v1(
      ${fixture.tenant}::uuid,${initialMfaSession}::uuid,NULL
    ) AS attested
  `;
  assert.equal(
    promotedLineage?.attested,
    true,
    "material-less revalidation must retain the frozen MFA session baseline despite later continuation evidence",
  );

  // Policy freshness has whole-second precision. Expire the completed factor
  // explicitly before exercising the mandatory revalidation continuation.
  await new Promise((resolve) =>
    setTimeout(
      resolve,
      Math.max(0, initialCompletedAt.getTime() + 1_100 - Date.now()),
    ),
  );
  const freshnessAt = new Date();
  await admin.begin(async (transaction) => {
    await withMfaPolicyRevisionWrite(
      transaction,
      "retire",
      fixture.tenantMfaPolicy,
      2,
      async () => {
        await transaction`
          UPDATE public.mfa_policy_revisions SET retired_at = ${freshnessAt}
          WHERE id = ${fixture.tenantMfaPolicy}::uuid AND revision = 2
            AND retired_at IS NULL
        `;
      },
    );
    await withMfaPolicyRevisionWrite(
      transaction,
      "insert",
      fixture.tenantMfaPolicy,
      3,
      async () => {
        await transaction`
          INSERT INTO public.mfa_policy_revisions (
            id,revision,tenant_id,scope,level,local_required,
            freshness_nanoseconds,created_at
          ) VALUES (
            ${fixture.tenantMfaPolicy}::uuid,3,${fixture.tenant}::uuid,
            'tenant_baseline','mfa',true,1000000000,${freshnessAt}
          )
        `;
      },
    );
  });
  const sourceRevalidation = await loadRevalidation(initialMfaSession);
  assert(sourceRevalidation);
  const sourceRevalidationSnapshot = object(
    sourceRevalidation.snapshot,
    "platform MFA source snapshot",
  );
  const sourceRevalidationLive = object(
    sourceRevalidation.live,
    "platform MFA source live",
  );
  const revalidationContinuationId = nextUuid();
  const revalidationReceipt = b64("platform-mfa-revalidation:receipt");
  const revalidationExpiresAt = new Date(Date.now() + 10 * 60_000);
  const revalidationContinuation = await applyRevalidation({
    tenantId: fixture.tenant,
    sessionId: initialMfaSession,
    userId,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(sourceRevalidationSnapshot, "version"),
    observedAt: new Date().toISOString(),
    decision: "step_up",
    reason: "assurance_insufficient",
    requirement: jsonField(sourceRevalidationLive, "requirement"),
    continuation: {
      continuationId: revalidationContinuationId,
      receiptDigest: revalidationReceipt,
      expiresAt: revalidationExpiresAt.toISOString(),
    },
  });
  assert.equal(
    revalidationContinuation.continuationId,
    revalidationContinuationId,
  );
  await assertNoOidcMaterialForOwners("material-less step-up continuation", [
    initialMfaSession,
    revalidationContinuationId,
  ]);
  let revalidationAuthority = await resolveContinuationAuthority(
    revalidationContinuationId,
    bytes("platform-mfa-revalidation:receipt"),
    new Date(),
  );
  assert.equal(
    revalidationAuthority.continuationOrigin,
    "session_revalidation",
  );
  assert.equal(revalidationAuthority.sourceSessionId, initialMfaSession);
  assert.equal(revalidationAuthority.sourceSessionFamilyId, initialMfaFamily);
  const firstRetained = await enrollTotpAndRetainContinuation(
    revalidationAuthority,
    revalidationReceipt,
    "platform-mfa-retain-1",
    {
      disable: async () => {
        await admin`
          UPDATE public.platform_federated_provider_policies AS policy
          SET enabled = false,updated_at = transaction_timestamp()
          WHERE policy.provider_id = ${fixture.provider}::uuid
        `;
      },
      restore: async () => {
        await admin`
          UPDATE public.platform_federated_provider_policies AS policy
          SET enabled = true,updated_at = transaction_timestamp()
          WHERE policy.provider_id = ${fixture.provider}::uuid
        `;
      },
    },
  );
  revalidationAuthority = firstRetained.authority;
  assert.equal(revalidationAuthority.anchorVersion, 2);
  const secondRetained = await enrollTotpAndRetainContinuation(
    revalidationAuthority,
    revalidationReceipt,
    "platform-mfa-retain-2",
  );
  revalidationAuthority = secondRetained.authority;
  assert.equal(revalidationAuthority.anchorVersion, 3);
  const revalidationChallenge = await createAndClaimTotpChallenge(
    revalidationAuthority,
    revalidationReceipt,
    "platform-mfa-revalidation",
  );
  const [sourceDeadline] = await admin<
    {
      familyId: string;
      absoluteExpiresAt: Date;
    }[]
  >`
    SELECT rotation_family_id::text AS "familyId",
      absolute_expires_at AS "absoluteExpiresAt"
    FROM public.auth_sessions WHERE id = ${initialMfaSession}::uuid
  `;
  assert(sourceDeadline);
  const revalidationCompletedAt = revalidationChallenge.completedAt;
  const revalidationSuccessor = nextUuid();
  const revalidationCompletion = {
    challengeId: revalidationChallenge.challengeId.toString("base64"),
    expectedChallengeVersion: 2,
    binding: revalidationChallenge.binding,
    factorId: platformFactorId,
    expectedFactorVersion: 2,
    expectedSecurityRevision: 1,
    counter: 1,
    completedAt: revalidationCompletedAt.toISOString(),
    sessionMutation: "consume_continuation",
    auditKind: "mfa.totp_step_up_completed",
    recoveryRestricted: false,
    session: {
      sessionId: revalidationSuccessor,
      familyId: sourceDeadline.familyId,
      tokenDigest: b64("platform-mfa-revalidation:token"),
      csrfDigest: b64("platform-mfa-revalidation:csrf"),
      authenticationMethod: "totp",
      idleExpiresAt: new Date(
        revalidationCompletedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: sourceDeadline.absoluteExpiresAt.toISOString(),
    },
    continuationReceiptDigest: revalidationReceipt,
  };
  const extendedDeadlineSnapshot = await mutationSnapshot();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${transaction.json({
          ...revalidationCompletion,
          session: {
            ...revalidationCompletion.session,
            absoluteExpiresAt: new Date(
              sourceDeadline.absoluteExpiresAt.getTime() + 1,
            ).toISOString(),
          },
        })}::jsonb
      )
    `,
    ),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "22023");
      return true;
    },
  );
  assert.deepEqual(await mutationSnapshot(), extendedDeadlineSnapshot);
  const [revalidationCompletionResult] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: JsonRecord }[]>`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${transaction.json(revalidationCompletion)}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    revalidationCompletionResult?.value.newSessionId,
    revalidationSuccessor,
  );
  const [rotationProof] = await admin<
    {
      oldRevoked: boolean;
      familyPreserved: boolean;
      deadlinePreserved: boolean;
      authenticationMethod: string;
    }[]
  >`
    SELECT source.revoked_at IS NOT NULL AS "oldRevoked",
      successor.rotation_family_id = source.rotation_family_id AS "familyPreserved",
      successor.absolute_expires_at = source.absolute_expires_at AS "deadlinePreserved",
      successor.authentication_method AS "authenticationMethod"
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor ON successor.id = ${revalidationSuccessor}::uuid
    WHERE source.id = ${initialMfaSession}::uuid
  `;
  assert.deepEqual(rotationProof, {
    oldRevoked: true,
    familyPreserved: true,
    deadlinePreserved: true,
    authenticationMethod: "oidc",
  });
  await assertNoOidcMaterialForOwners(
    "material-less step-up continuation promotion",
    [initialMfaSession, revalidationContinuationId, revalidationSuccessor],
  );
  assert(await loadRevalidation(revalidationSuccessor));

  await admin`
    INSERT INTO public.user_login_identifiers (
      id,user_id,kind,canonical_value,verified_at
    ) VALUES (
      ${nextUuid()}::uuid, ${userId}::uuid, 'local_email',
      'preserved-platform-user@example.invalid', transaction_timestamp()
    )
  `;
  await deactivateBinding();
  const [preserved] = await admin<{ status: string }[]>`
    SELECT status FROM public.tenant_memberships
    WHERE tenant_id = ${fixture.tenant}::uuid AND user_id = ${userId}::uuid
  `;
  assert.equal(preserved?.status, "active");

  await activateBinding("disabled", "deny");
  const denied = await prepareAttempt("disabled-jit-denied", aliases);
  await assertRollback("denied", () =>
    applyAttempt(denied, {
      identityAction: "no_change",
      accessAction: "ensure",
    }),
  );

  const [finalCounts] = await admin<
    {
      liveGrants: number;
      applications: number;
      completedTransactions: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_platform_federated_provider_access_grants
       WHERE tenant_id = ${fixture.tenant}::uuid AND ended_at IS NULL) AS "liveGrants",
      (SELECT count(*)::integer
       FROM public.tenant_platform_oidc_authentication_applications
       WHERE tenant_id = ${fixture.tenant}::uuid) AS applications,
      (SELECT count(*)::integer
       FROM public.tenant_platform_oidc_authentication_transactions
       WHERE tenant_id = ${fixture.tenant}::uuid AND state = 'completed') AS "completedTransactions"
  `;
  assert.deepEqual(finalCounts, {
    liveGrants: 0,
    applications: 12,
    completedTransactions: 12,
  });
} finally {
  await admin.end();
}
