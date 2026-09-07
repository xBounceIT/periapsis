import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonRecord = Record<string, postgres.JSONValue>;
type RuntimeRole = "periapsis_api" | "periapsis_worker";

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_OIDC_DIRECT_AUTH_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_OIDC_DIRECT_AUTH_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d6eb0-a000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;

const fixture = {
  operator: uuid(1),
  operatorGrant: uuid(2),
  operatorSession: uuid(3),
  operatorFamily: uuid(4),
  platformFloor: uuid(5),
  unauthorizedUser: uuid(6),
  unauthorizedSession: uuid(7),
  unauthorizedFamily: uuid(8),
  provider: uuid(10),
  providerCommand: uuid(11),
  providerSecret: uuid(12),
  account: uuid(13),
  accountCommand: uuid(14),
  accountAudit: uuid(15),
  accountTotp: uuid(16),
} as const;

const keyVersion = 32_767;
const loginKey = "platform_oidc_direct";
const issuer = "https://platform-direct-runtime-idp.example.invalid";
const directRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback";
const tenantRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback";
const postLogoutRedirectUri = "https://periapsis.example.invalid/login";
const clientId = "periapsis-platform-direct-runtime";
let sequence = 1_000;

function nextUuid(): string {
  sequence += 1;
  return uuid(sequence);
}

function bytes(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-oidc-direct-auth-runtime:${label}`)
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

function booleanField(value: JsonRecord, key: string): boolean {
  const field = value[key];
  if (typeof field !== "boolean") {
    throw new TypeError(`${key} must be a boolean`);
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

function assertSqlState(error: unknown, code: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, code, error.message);
  return true;
}

async function asRole<T>(
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  userId = "",
): Promise<T> {
  const wrapped = await admin.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', '', true),
             set_config('app.user_id', ${userId}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

function trace(): {
  auditId: string;
  requestId: string;
  correlationId: string;
} {
  return {
    auditId: nextUuid(),
    requestId: nextUuid(),
    correlationId: nextUuid(),
  };
}

function audit(reason: string): JsonRecord {
  return {
    eventId: nextUuid(),
    requestId: nextUuid(),
    correlationId: nextUuid(),
    ipAddress: "198.51.100.78",
    userAgent: "Periapsis direct platform OIDC runtime proof",
    authenticationMethod: "oidc",
    reason,
  };
}

async function directReadiness(role: RuntimeRole): Promise<boolean> {
  const [row] = await asRole(role, (transaction) =>
    role === "periapsis_api"
      ? transaction<{ ready: boolean }[]>`
            SELECT app.platform_oidc_direct_runtime_schema_readiness_v54() AS ready
          `
      : transaction<{ ready: boolean }[]>`
            SELECT app.release_runtime_schema_readiness_v54() AS ready
          `,
  );
  assert(row);
  return row.ready;
}

async function beginDirect(): Promise<postgres.JSONValue | null> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.begin_platform_oidc_authentication_v1(
        ${transaction.json({ loginKey })}::jsonb
      ) AS value
    `,
  );
  assert(row);
  return row.value;
}

async function getProviderDocument(): Promise<JsonRecord> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ document: postgres.JSONValue }[]>`
      SELECT app.get_platform_auth_provider_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        'totp'::text
      ) AS document
    `,
    fixture.operator,
  );
  return object(row?.document, "platform provider document");
}

async function listProviderDocument(): Promise<JsonRecord> {
  const rows = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ document: postgres.JSONValue }[]>`
      SELECT listed.document
      FROM app.list_platform_auth_providers_v1(
        ${fixture.operatorSession}::uuid, 'totp'::text, NULL::uuid,
        50::integer, false::boolean
      ) AS listed(document)
      WHERE listed.document ->> 'id' = ${fixture.provider}
    `,
    fixture.operator,
  );
  assert.equal(rows.length, 1, "provider list projection was not unique");
  return object(rows[0]?.document, "listed platform provider document");
}

async function seedLifecycle(): Promise<void> {
  const createdAt = new Date(Date.now() - 60_000);
  const expiresAt = new Date(Date.now() + 3_600_000);
  await admin`
    INSERT INTO public.users (id, email, display_name)
    VALUES (
      ${fixture.operator}::uuid,
      'platform-oidc-direct-runtime-operator@example.invalid',
      'Platform OIDC direct runtime operator'
    )
  `;
  await admin`
    INSERT INTO public.user_platform_roles (
      id, user_id, role_id, granted_by_user_id, granted_at
    )
    SELECT ${fixture.operatorGrant}::uuid, ${fixture.operator}::uuid,
           role.id, ${fixture.operator}::uuid, ${createdAt}
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
      'totp', ${createdAt}, ${createdAt}, ${expiresAt}, ${expiresAt},
      ${createdAt}
    )
  `;
  await admin`
    INSERT INTO public.users (id, email, display_name)
    VALUES (
      ${fixture.unauthorizedUser}::uuid,
      'platform-oidc-direct-runtime-unauthorized@example.invalid',
      'Unauthorized platform OIDC direct runtime actor'
    )
  `;
  await admin`
    INSERT INTO public.auth_sessions (
      id, user_id, rotation_family_id, active_tenant_id, token_digest,
      csrf_secret_digest, authentication_method, mfa_satisfied_at,
      last_seen_at, idle_expires_at, absolute_expires_at, created_at
    ) VALUES (
      ${fixture.unauthorizedSession}::uuid, ${fixture.unauthorizedUser}::uuid,
      ${fixture.unauthorizedFamily}::uuid, NULL,
      ${bytes("unauthorized-token")}::bytea,
      ${bytes("unauthorized-csrf")}::bytea,
      'totp', ${createdAt}, ${createdAt}, ${expiresAt}, ${expiresAt},
      ${createdAt}
    )
  `;
  await admin`
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, is_active
    ) VALUES (
      ${keyVersion}, ${bytes("active-key")}::bytea, true
    )
  `;
  await admin`
    INSERT INTO public.totp_credentials (
      id,user_id,secret_ciphertext,secret_nonce,secret_aad,key_version,
      encryption_algorithm,otp_algorithm,digits,period_seconds,confirmed_at,
      last_accepted_counter,security_revision,created_at,updated_at
    ) VALUES (
      ${fixture.accountTotp}::uuid,${fixture.unauthorizedUser}::uuid,
      ${Buffer.alloc(32, 0x74)}::bytea,${Buffer.alloc(12, 0x6e)}::bytea,
      ${bytes("account-totp-aad")}::bytea,${keyVersion}::integer,
      'aes-256-gcm','SHA1',6,30,${createdAt},41,1,${createdAt},${createdAt}
    )
  `;
  await admin.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.platformFloor}:1`},
        true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id, revision, tenant_id, scope, level, local_required,
        freshness_nanoseconds, created_at
      ) VALUES (
        ${fixture.platformFloor}::uuid, 1, NULL, 'platform_floor',
        'primary', false, 0, ${createdAt}
      )
    `;
  });

  let event = trace();
  const configuration = {
    issuer,
    clientId,
    redirectUri: directRedirectUri,
    postLogoutRedirectUri,
    extraScopes: ["groups"],
    allowRefreshToken: false,
    useUserInfo: false,
  };
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      { providerId: string; version: number; replayed: boolean }[]
    >`
      SELECT created.provider_id::text AS "providerId",
             created.version::integer AS version,
             created.replayed
      FROM app.create_platform_oidc_auth_provider_v3(
        ${fixture.operatorSession}::uuid, ${fixture.providerCommand}::uuid,
        ${fixture.provider}::uuid, ${loginKey}::text,
        'Platform direct OIDC runtime'::text,
        'Direct platform OIDC runtime security proof'::text,
        ${transaction.json(configuration)}::jsonb, ${tenantRedirectUri}::text,
        ${bytes("provider-idempotency")}::bytea,
        ${bytes("provider-request")}::bytea, ${event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.78'::inet,
        'Periapsis direct platform OIDC runtime proof'::text,
        'totp'::text, 'Create dormant direct platform OIDC provider'::text
      ) AS created
    `,
    fixture.operator,
  );
  assert.deepEqual(created, {
    providerId: fixture.provider,
    version: 1,
    replayed: false,
  });

  event = trace();
  const [rotated] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT rotated.version::integer AS version
      FROM app.replace_platform_oidc_client_secret_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.providerSecret}::uuid, 1::bigint, ${keyVersion}::integer,
        ${Buffer.alloc(12, 0x71)}::bytea,
        ${Buffer.from("platform-direct-runtime-encrypted-secret", "utf8")}::bytea,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.78'::inet,
        'Periapsis direct platform OIDC runtime proof'::text,
        'totp'::text, 'Install encrypted direct OIDC secret'::text
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
    reason: "Publish direct OIDC discovery and JWKS",
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
    numberField(
      object(published?.value, "trust publication"),
      "providerVersion",
    ),
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
        '198.51.100.78'::inet,
        'Periapsis direct platform OIDC runtime proof'::text,
        'totp'::text, 'Activate provider while direct login stays dormant'::text
      ) AS activated
    `,
    fixture.operator,
  );
  assert.equal(activated?.version, 4);

  const [state] = await admin<
    {
      providerEnabled: boolean;
      runtimeEnabled: boolean;
      platformLoginEnabled: boolean;
      accountMode: string;
      directEnabled: boolean;
      directRevision: number;
    }[]
  >`
    SELECT provider.enabled AS "providerEnabled",
           runtime_policy.enabled AS "runtimeEnabled",
           runtime_policy.platform_login_enabled AS "platformLoginEnabled",
           login_policy.account_mode AS "accountMode",
           login_policy.enabled AS "directEnabled",
           login_policy.revision::integer AS "directRevision"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
    JOIN public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    WHERE provider.id = ${fixture.provider}::uuid
  `;
  assert.deepEqual(state, {
    providerEnabled: true,
    runtimeEnabled: true,
    platformLoginEnabled: false,
    accountMode: "disabled",
    directEnabled: false,
    directRevision: 1,
  });
}

async function setDirectPolicy(
  enabled: boolean,
  expectedVersion: number,
  sessionId = fixture.operatorSession,
  actorId = fixture.operator,
): Promise<{ version: number; document: JsonRecord }> {
  const event = trace();
  const [result] = await asRole(
    "periapsis_api",
    (transaction) =>
      enabled
        ? transaction<{ version: number; document: postgres.JSONValue }[]>`
            SELECT activated.version::integer AS version,
                   activated.document
            FROM app.activate_platform_oidc_direct_login_v1(
              ${sessionId}::uuid, ${fixture.provider}::uuid,
              ${expectedVersion}::bigint, ${event.auditId}::uuid,
              ${event.requestId}::uuid, ${event.correlationId}::uuid,
              '198.51.100.78'::inet,
              'Periapsis direct platform OIDC runtime proof'::text,
              'totp'::text, 'Activate direct platform OIDC login'::text
            ) AS activated
          `
        : transaction<{ version: number; document: postgres.JSONValue }[]>`
            SELECT deactivated.version::integer AS version,
                   deactivated.document
            FROM app.deactivate_platform_oidc_direct_login_v1(
              ${sessionId}::uuid, ${fixture.provider}::uuid,
              ${expectedVersion}::bigint, ${event.auditId}::uuid,
              ${event.requestId}::uuid, ${event.correlationId}::uuid,
              '198.51.100.78'::inet,
              'Periapsis direct platform OIDC runtime proof'::text,
              'totp'::text, 'Deactivate direct platform OIDC login'::text
            ) AS deactivated
          `,
    actorId,
  );
  assert(result, "direct lifecycle mutation returned no row");
  return {
    version: result.version,
    document: object(result.document, "direct lifecycle document"),
  };
}

async function prelinkDirectAccount(): Promise<void> {
  const event = trace();
  const [receipt] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      { accountId: string; version: number; replayed: boolean }[]
    >`
      SELECT result.account_id::text AS "accountId",
             result.version::integer AS version,result.replayed
      FROM app.prelink_platform_identity_account_v2(
        ${fixture.operatorSession}::uuid,${fixture.accountCommand}::uuid,
        ${fixture.account}::uuid,${fixture.provider}::uuid,
        ${fixture.unauthorizedUser}::uuid,${issuer},
        'utf8_exact'::public.identity_subject_format,
        ${Buffer.alloc(32, 0x73)}::bytea,${Buffer.alloc(12, 0x6e)}::bytea,
        ${keyVersion}::integer,ARRAY[${keyVersion}]::integer[],
        ARRAY[${bytes("direct-subject")}]::bytea[],
        ${bytes("direct-account-key")}::bytea,
        ${bytes("direct-account-request")}::bytea,
        ${fixture.accountAudit}::uuid,${event.requestId}::uuid,
        ${event.correlationId}::uuid,'198.51.100.78'::inet,
        'Periapsis direct platform OIDC runtime proof'::text,
        'totp'::text,'Prelink direct platform OIDC runtime account'::text
      ) AS result
    `,
    fixture.operator,
  );
  assert.deepEqual(receipt, {
    accountId: fixture.account,
    version: 1,
    replayed: false,
  });
}

type DirectAttempt = {
  label: string;
  operationRunId: string;
  transactionId: string;
  claimAttemptId: string;
  browserCapabilityDigest: string;
  pins: JsonRecord;
  returnPath: string;
};

type DirectContinuation = DirectAttempt & {
  continuationId: string;
  receiptDigest: string;
  expiresAt: string;
  userId: string;
  externalIdentityId: string;
};

async function prepareDirectAttempt(label: string): Promise<DirectAttempt> {
  const begun = object(await beginDirect(), `${label} begin`);
  const authorization = object(begun.authorization, `${label} authorization`);
  const pins = object(begun.pins, `${label} pins`);
  const operationRunId = nextUuid();
  const transactionId = b64(`${label}:transaction`);
  const stateDigest = b64(`${label}:state`);
  const browserDigest = b64(`${label}:browser`);
  const browserCapabilityDigest = b64(`${label}:browser-capability`);
  const claimAttemptId = b64(`${label}:claim-attempt`);
  const createdAt = new Date(Date.now() - 2_000);
  const returnPath = "/platform";
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.create_platform_oidc_authentication_transaction_v1(
        ${transaction.json({
          begin: {
            operationRunId,
            receiptDigest: b64(`${label}:receipt`),
            networkDigest: b64(`${label}:network`),
            accountDigest: b64(`${label}:account`),
            providerDigest: b64(`${label}:provider`),
          },
          current: {
            id: transactionId,
            stateDigest,
            browserDigest,
            nonceDigest: b64(`${label}:nonce`),
            codeChallengeMethod: "S256",
            verifierKeyVersion: keyVersion,
            verifierCiphertext: Buffer.alloc(32, 0x76).toString("base64"),
            pins,
            clientId: authorization.clientId,
            redirectUri: authorization.redirectUri,
            postLogoutRedirectUri: authorization.postLogoutRedirectUri,
            returnPath,
            scopes: [
              "openid",
              ...stringArrayField(authorization, "extraScopes"),
            ],
            allowRefreshToken: authorization.allowRefreshToken,
            useUserInfo: authorization.useUserInfo,
            createdAt: createdAt.toISOString(),
            expiresAt: new Date(
              createdAt.getTime() + 10 * 60_000,
            ).toISOString(),
            state: "pending",
            version: 1,
          },
          browserCapabilityDigest,
          audit: audit(`Start ${label} direct platform OIDC login`),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    numberField(object(created?.value, `${label} create`), "version"),
    1,
  );
  const [claimed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.claim_platform_oidc_authentication_transaction_v1(
        ${transaction.json({
          stateDigest,
          browserDigest,
          authorizationCodeDigest: b64(`${label}:authorization-code`),
          claimAttemptId,
          claimedAt: new Date().toISOString(),
          expectedVersion: 1,
          audit: audit(`Claim ${label} direct platform OIDC callback`),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    numberField(object(claimed?.value, `${label} claim`), "version"),
    2,
  );
  return {
    label,
    operationRunId,
    transactionId,
    claimAttemptId,
    browserCapabilityDigest,
    pins,
    returnPath,
  };
}

async function applyDirectInitialContinuation(
  attempt: DirectAttempt,
): Promise<DirectContinuation> {
  const resolvedAt = new Date();
  const subjectAlias = {
    keyVersion,
    digest: b64("direct-subject"),
  };
  const [resolved] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.resolve_platform_oidc_authentication_v1(
        ${transaction.json({
          transactionId: attempt.transactionId,
          claimAttemptId: attempt.claimAttemptId,
          provider: attempt.pins.provider,
          subjectAlias,
          observedAt: resolvedAt.toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  const identity = object(resolved?.value, `${attempt.label} identity`);
  const [planned] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_platform_oidc_planning_state_v1(
        ${transaction.json({
          transactionId: attempt.transactionId,
          claimAttemptId: attempt.claimAttemptId,
          externalIdentityId: identity.externalIdentityId,
          userId: identity.userId,
          identityVersion: identity.identityVersion,
          aliasKeyVersion: identity.aliasKeyVersion,
          userAuthenticationRevision: identity.userAuthenticationRevision,
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  const planning = object(planned?.value, `${attempt.label} planning`);
  const platformFloor = object(
    planning.platformFloor,
    `${attempt.label} platform floor`,
  );
  const selectedTotp = object(
    planning.selectedTotp,
    `${attempt.label} selected TOTP`,
  );
  assert.equal(stringField(selectedTotp, "id"), fixture.accountTotp);
  const observedAt = new Date();
  const validUntil = new Date(observedAt.getTime() + 10 * 60_000);
  const continuationId = nextUuid();
  const receiptDigest = b64(`${attempt.label}:continuation-receipt`);
  const expiresAt = new Date(observedAt.getTime() + 9 * 60_000);
  const command = {
    transactionId: attempt.transactionId,
    claimAttemptId: attempt.claimAttemptId,
    expectedVersion: 2,
    operationDigest: b64(`${attempt.label}:apply-operation`),
    browserCapabilityDigest: attempt.browserCapabilityDigest,
    returnPath: attempt.returnPath,
    subject: {
      providerId: fixture.provider,
      userId: identity.userId,
      externalIdentityId: identity.externalIdentityId,
      providerRevision: planning.providerRevision,
      securityRevision: planning.securityRevision,
      loginPolicyRevision: planning.loginPolicyRevision,
      userAuthenticationRevision: planning.userAuthenticationRevision,
      identityVersion: planning.identityVersion,
      aliasKeyVersion: planning.aliasKeyVersion,
      assurancePolicyRevision: planning.assurancePolicyRevision,
      platformFloorPolicyId: platformFloor.id,
      platformFloorPolicyRevision: platformFloor.revision,
      totpCredentialId: selectedTotp.id,
      totpSecurityRevision: selectedTotp.securityRevision,
    },
    observation: {
      externalIdentityId: identity.externalIdentityId,
      format: "utf8_exact",
      envelope: {
        keyVersion,
        format: "utf8_exact",
        nonce: Buffer.alloc(12, 0x6e).toString("base64"),
        ciphertext: Buffer.alloc(32, 0x73).toString("base64"),
      },
      aliases: [subjectAlias],
    },
    assurance: {
      level: "primary",
      authenticatedAt: observedAt.toISOString(),
    },
    disposition: "continuation",
    continuation: {
      id: continuationId,
      receiptDigest,
      audience: "api",
      expiresAt: expiresAt.toISOString(),
    },
    observedAt: observedAt.toISOString(),
    audit: audit(`Apply ${attempt.label} direct platform OIDC continuation`),
    materialId: attempt.operationRunId,
    validUntil: validUntil.toISOString(),
  };
  const [applied] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_platform_oidc_authentication_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  const result = object(applied?.value, `${attempt.label} apply`);
  assert.equal(result.category, "success");
  assert.equal(result.continuationId, continuationId);
  return {
    ...attempt,
    continuationId,
    receiptDigest,
    expiresAt: expiresAt.toISOString(),
    userId: stringField(identity, "userId"),
    externalIdentityId: stringField(identity, "externalIdentityId"),
  };
}

async function assertNoDirectOidcMaterialForOwners(
  label: string,
  ownerIds: readonly string[],
): Promise<void> {
  const [material] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_oidc_session_materials
    WHERE authority = 'platform_provider'
      AND (
        session_id = ANY(${ownerIds}::uuid[])
        OR continuation_id = ANY(${ownerIds}::uuid[])
      )
  `;
  assert.equal(
    material?.count,
    0,
    `${label} unexpectedly persisted direct-platform OIDC material`,
  );
}

type DirectSessionCoordinates = {
  sessionId: string;
  familyId: string;
  absoluteExpiresAt: string;
};

async function completeDirectTotp(
  continuation:
    | DirectContinuation
    | {
        continuationId: string;
        receiptDigest: string;
        expiresAt: string;
        userId: string;
        externalIdentityId: string;
      },
  label: string,
  acceptedCounter: number,
  source?: DirectSessionCoordinates,
): Promise<DirectSessionCoordinates> {
  const challengeId = b64(`${label}:challenge`);
  const browserDigest = b64(`${label}:challenge-browser`);
  const startedAt = new Date();
  const [started] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.begin_platform_post_primary_totp_v1(
        ${transaction.json({
          continuationId: continuation.continuationId,
          receiptDigest: continuation.receiptDigest,
          expectedVersion: 1,
          challenge: {
            id: challengeId,
            browserDigest,
            createdAt: startedAt.toISOString(),
            expiresAt: new Date(
              Math.min(
                startedAt.getTime() + 5 * 60_000,
                Date.parse(continuation.expiresAt),
              ),
            ).toISOString(),
          },
          observedAt: startedAt.toISOString(),
          audit: audit(`Begin ${label} direct platform TOTP`),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    numberField(object(started?.value, `${label} TOTP begin`), "version"),
    1,
  );
  const [loaded] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_platform_post_primary_totp_v1(
        ${transaction.json({
          challengeId,
          browserDigest,
          continuationId: continuation.continuationId,
          receiptDigest: continuation.receiptDigest,
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  const authority = object(loaded?.value, `${label} TOTP authority`);
  assert.equal(authority.totpCredentialId, fixture.accountTotp);
  const completedAt = new Date();
  const sessionId = nextUuid();
  const familyId = source?.familyId ?? nextUuid();
  const absoluteExpiresAt =
    source?.absoluteExpiresAt ??
    new Date(completedAt.getTime() + 8 * 60 * 60_000).toISOString();
  const completionCommand: JsonRecord = {
    challengeId,
    browserDigest,
    continuationId: continuation.continuationId,
    receiptDigest: continuation.receiptDigest,
    expectedVersion: 1,
    acceptedCounter,
    completionRequestDigest: b64(`${label}:completion-request`),
    session: {
      id: sessionId,
      rotationFamilyId: familyId,
      tokenDigest: b64(`${label}:session-token`),
      csrfSecretDigest: b64(`${label}:session-csrf`),
      audience: "api",
      idleExpiresAt: new Date(
        completedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt,
      sessionVersion: 1,
    },
    observedAt: completedAt.toISOString(),
    audit: audit(`Complete ${label} direct platform TOTP`),
  };
  if (label === "material-less-initial" && "transactionId" in continuation) {
    await assertDirectRequiredMaterialFailsClosed(
      continuation,
      completionCommand,
      "post_primary_totp",
    );
    await assertRevokedDirectTotpFailsClosed(completionCommand);
  }
  const completed = await applyDirectTotpCommand(completionCommand);
  const result = object(completed?.value, `${label} TOTP completion`);
  assert.equal(result.category, "success");
  assert.equal(result.sessionId, sessionId);
  const [proof] = await admin<
    {
      authenticationMethod: string;
      continuationConsumed: boolean;
      familyId: string;
    }[]
  >`
    SELECT session.authentication_method AS "authenticationMethod",
           continuation.state = 'consumed'
             AND continuation.consumed_at = session.created_at
             AS "continuationConsumed",
           session.rotation_family_id::text AS "familyId"
    FROM public.auth_sessions AS session
    JOIN public.platform_post_primary_continuations AS continuation
      ON continuation.id = ${continuation.continuationId}::uuid
    WHERE session.id = ${sessionId}::uuid
  `;
  assert.deepEqual(proof, {
    authenticationMethod: "oidc",
    continuationConsumed: true,
    familyId,
  });
  const replayBefore = await runtimeSnapshot();
  assert.deepEqual(await applyDirectTotpCommand(completionCommand), completed);
  assert.deepEqual(
    await runtimeSnapshot(),
    replayBefore,
    "TOTP replay mutated state",
  );
  return { sessionId, familyId, absoluteExpiresAt };
}

async function applyDirectTotpCommand(
  command: JsonRecord,
): Promise<{ value: postgres.JSONValue }> {
  const [result] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_platform_post_primary_totp_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  assert(result);
  return result;
}

async function assertRevokedDirectTotpFailsClosed(
  command: JsonRecord,
): Promise<void> {
  const before = await runtimeSnapshot();
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL session_replication_role = replica");
      const disabled = await transaction`
        UPDATE public.totp_credentials SET disabled_at = transaction_timestamp()
        WHERE id = ${fixture.accountTotp}::uuid RETURNING id
      `;
      assert.equal(disabled.length, 1);
      await transaction.unsafe("SET LOCAL session_replication_role = origin");
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [result] = await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.apply_platform_post_primary_totp_v1(
          ${transaction.json(command)}::jsonb
        ) AS value
      `;
      assert.deepEqual(result?.value, { applied: false, category: "stale" });
      throw new RollbackAclTamper("rollback revoked TOTP proof");
    }),
    RollbackAclTamper,
  );
  assert.deepEqual(await runtimeSnapshot(), before);
}

async function loadDirectRevalidation(sessionId: string): Promise<JsonRecord> {
  const [loaded] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_platform_oidc_session_revalidation_v1(
        ${transaction.json({
          sessionId,
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  return object(loaded?.value, "direct platform revalidation authority");
}

async function applyDirectRevalidation(
  command: JsonRecord,
): Promise<JsonRecord> {
  const [applied] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_platform_oidc_session_revalidation_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  return object(applied?.value, "direct platform revalidation result");
}

async function buildDirectRotation(
  source: DirectSessionCoordinates,
  label: string,
): Promise<{ command: JsonRecord; successorId: string }> {
  const authority = await loadDirectRevalidation(source.sessionId);
  const sessionAuthority = object(authority.session, `${label} session`);
  const observedAt = new Date();
  const successorId = nextUuid();
  return {
    successorId,
    command: {
      sessionId: source.sessionId,
      expectedVersion: numberField(sessionAuthority, "currentVersion"),
      requestDigest: b64(`${label}:request`),
      decision: "rotate",
      reason: "policy_refresh",
      observedAt: observedAt.toISOString(),
      session: {
        id: successorId,
        rotationFamilyId: source.familyId,
        tokenDigest: b64(`${label}:token`),
        csrfSecretDigest: b64(`${label}:csrf`),
        audience: "api",
        idleExpiresAt: new Date(
          observedAt.getTime() + 20 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: source.absoluteExpiresAt,
        sessionVersion: 1,
      },
    },
  };
}

async function rotateDirectSession(
  source: DirectSessionCoordinates,
  label: string,
): Promise<DirectSessionCoordinates> {
  const rotation = await buildDirectRotation(source, label);
  const result = await applyDirectRevalidation(rotation.command);
  assert.equal(result.decision, "rotate");
  assert.equal(result.newSessionId, rotation.successorId);
  return {
    sessionId: rotation.successorId,
    familyId: source.familyId,
    absoluteExpiresAt: source.absoluteExpiresAt,
  };
}

async function beginDirectStepUp(
  source: DirectSessionCoordinates,
  label: string,
): Promise<
  DirectSessionCoordinates & {
    continuationId: string;
    receiptDigest: string;
    expiresAt: string;
    userId: string;
    externalIdentityId: string;
  }
> {
  const authority = await loadDirectRevalidation(source.sessionId);
  const sessionAuthority = object(authority.session, `${label} session`);
  const liveAuthority = object(authority.authority, `${label} authority`);
  const observedAt = new Date();
  const continuationId = nextUuid();
  const receiptDigest = b64(`${label}:continuation-receipt`);
  const expiresAt = new Date(observedAt.getTime() + 5 * 60_000).toISOString();
  const result = await applyDirectRevalidation({
    sessionId: source.sessionId,
    expectedVersion: numberField(sessionAuthority, "currentVersion"),
    requestDigest: b64(`${label}:request`),
    decision: "step_up",
    reason: "assurance_insufficient",
    observedAt: observedAt.toISOString(),
    continuation: {
      id: continuationId,
      receiptDigest,
      audience: "api",
      expiresAt,
    },
  });
  assert.equal(result.decision, "step_up");
  assert.equal(result.continuationId, continuationId);
  return {
    ...source,
    continuationId,
    receiptDigest,
    expiresAt,
    userId: stringField(sessionAuthority, "userId"),
    externalIdentityId: stringField(liveAuthority, "externalIdentityId"),
  };
}

type DirectMaterialSnapshot = {
  continuationId: string | null;
  invariant: postgres.JSONValue;
  rotationFamilyId: string | null;
  sessionId: string | null;
};

async function loadDirectMaterial(
  materialId: string,
): Promise<DirectMaterialSnapshot> {
  const [material] = await admin<DirectMaterialSnapshot[]>`
    SELECT material.session_id::text AS "sessionId",
           material.continuation_id::text AS "continuationId",
           material.rotation_family_id::text AS "rotationFamilyId",
           to_jsonb(material) - ARRAY[
             'session_id','continuation_id','rotation_family_id','updated_at'
           ]::text[] AS invariant
    FROM public.tenant_oidc_session_materials AS material
    WHERE material.id = ${materialId}::uuid
      AND material.authority = 'platform_provider'
  `;
  assert(material, "direct-platform OIDC material was not found");
  return material;
}

async function insertDirectMaterial(
  continuation: DirectContinuation,
): Promise<DirectMaterialSnapshot> {
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 4 * 60_000);
  await admin`
    INSERT INTO public.tenant_oidc_session_materials (
      id,tenant_id,authority,continuation_id,rotation_family_id,user_id,
      provider_id,binding_id,provider_kind,external_identity_id,aad_version,
      refresh_generation,refresh_state,refresh_version,expires_at,client_id,
      post_logout_redirect_uri,logout_disposition,created_at,updated_at
    ) VALUES (
      ${continuation.operationRunId}::uuid,NULL,'platform_provider',
      ${continuation.continuationId}::uuid,NULL,
      ${continuation.userId}::uuid,${fixture.provider}::uuid,NULL,'oidc',
      ${continuation.externalIdentityId}::uuid,1,0,'unavailable',1,
      ${expiresAt},${clientId},${postLogoutRedirectUri},'not_configured',
      ${createdAt},${createdAt}
    )
  `;
  return loadDirectMaterial(continuation.operationRunId);
}

function assertDirectMaterialTransferred(
  before: DirectMaterialSnapshot,
  after: DirectMaterialSnapshot,
  owner: {
    continuationId: string | null;
    rotationFamilyId: string | null;
    sessionId: string | null;
  },
): void {
  assert.deepEqual(
    {
      continuationId: after.continuationId,
      rotationFamilyId: after.rotationFamilyId,
      sessionId: after.sessionId,
    },
    owner,
  );
  assert.deepEqual(
    after.invariant,
    before.invariant,
    "owner transfer changed immutable direct-platform OIDC material",
  );
}

async function assertDirectRequiredMaterialFailsClosed(
  attempt: DirectAttempt,
  mutation: JsonRecord,
  operation:
    "session_revalidation" | "post_primary_totp" = "session_revalidation",
): Promise<void> {
  const before = await runtimeSnapshot();
  await assert.rejects(
    admin.begin(async (transaction) => {
      // Synthesize a discordant immutable lineage only inside this rollback:
      // the completed login now requires material which does not exist.
      await transaction.unsafe("SET LOCAL session_replication_role = replica");
      const updated = await transaction`
        UPDATE public.platform_oidc_authentication_transactions
        SET allow_refresh_token = true
        WHERE transaction_id = ${Buffer.from(attempt.transactionId, "base64")}::bytea
          AND operation_run_id = ${attempt.operationRunId}::uuid
          AND state = 'completed'
        RETURNING transaction_id
      `;
      assert.equal(
        updated.length,
        1,
        "direct required-material lineage was not exact",
      );
      await transaction.unsafe("SET LOCAL session_replication_role = origin");
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', '', true),
               set_config('app.user_id', '', true),
               set_config('app.service_account_id', '', true)
      `;
      if (operation === "post_primary_totp") {
        await transaction`
          SELECT app.apply_platform_post_primary_totp_v1(
            ${transaction.json(mutation)}::jsonb
          )
        `;
      } else {
        await transaction`
          SELECT app.apply_platform_oidc_session_revalidation_v1(
            ${transaction.json(mutation)}::jsonb
          )
        `;
      }
    }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal((error as ErrorWithCode).code, "40001");
      assert.equal(
        error.message,
        "direct-platform OIDC material ownership is stale",
      );
      return true;
    },
  );
  assert.deepEqual(
    await runtimeSnapshot(),
    before,
    "direct required-material proof escaped its rollback boundary",
  );
}

const directRelations: string[] = [
  "auth_session_platform_oidc_evidence",
  "auth_session_platform_oidc_policy_pins",
  "auth_session_platform_oidc_provenance",
  "auth_session_platform_oidc_states",
  "platform_oidc_authentication_applications",
  "platform_oidc_authentication_transactions",
  "platform_oidc_login_policies",
  "platform_oidc_session_revalidation_commands",
  "platform_oidc_tenant_switch_commands",
  "platform_post_primary_continuation_evidence",
  "platform_post_primary_continuation_policy_pins",
  "platform_post_primary_continuations",
  "platform_post_primary_totp_challenges",
];

async function assertDirectDmlDenied(): Promise<void> {
  await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).map(async (role) => {
      const [privileges] = await admin<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM unnest(${directRelations}::text[]) AS relation(name)
        CROSS JOIN unnest(ARRAY['INSERT','UPDATE','DELETE']::text[])
          AS privilege(name)
        WHERE has_table_privilege(
          ${role}, format('public.%I',relation.name), privilege.name
        )
      `;
      assert.equal(privileges?.count, 0, `${role} has direct-table DML`);
      await assert.rejects(
        asRole(role, (transaction) =>
          transaction.unsafe(
            "UPDATE ONLY public.platform_oidc_authentication_transactions SET state = state WHERE false",
          ),
        ),
        (error: unknown) => assertSqlState(error, "42501"),
      );
      await assert.rejects(
        asRole(role, (transaction) =>
          transaction.unsafe(
            "DELETE FROM ONLY public.platform_oidc_authentication_transactions WHERE false",
          ),
        ),
        (error: unknown) => assertSqlState(error, "42501"),
      );
      await assert.rejects(
        asRole(
          role,
          (transaction) => transaction`
            INSERT INTO public.platform_oidc_login_policies (
              provider_id, provider_kind, account_mode, enabled, revision
            ) VALUES (
              ${fixture.provider}::uuid, 'oidc', 'disabled', false, 1
            )
          `,
        ),
        (error: unknown) => assertSqlState(error, "42501"),
      );
    }),
  );
}

async function assertCallbackAcl(): Promise<void> {
  const [acl] = await admin<
    {
      api: boolean;
      worker: boolean;
      notifier: boolean;
      auditor: boolean;
      migrator: boolean;
      publicExecute: boolean;
    }[]
  >`
    SELECT
      has_function_privilege(
        'periapsis_api',
        'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure,
        'EXECUTE'
      ) AS api,
      has_function_privilege(
        'periapsis_worker',
        'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure,
        'EXECUTE'
      ) AS worker,
      has_function_privilege(
        'periapsis_notifier',
        'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure,
        'EXECUTE'
      ) AS notifier,
      has_function_privilege(
        'periapsis_auditor',
        'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure,
        'EXECUTE'
      ) AS auditor,
      has_function_privilege(
        'periapsis_migrator',
        'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure,
        'EXECUTE'
      ) AS migrator,
      EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS function_row
        CROSS JOIN LATERAL pg_catalog.aclexplode(function_row.proacl) AS acl_row
        WHERE function_row.oid =
          'app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'::regprocedure
          AND acl_row.grantee = 0 AND acl_row.privilege_type = 'EXECUTE'
      ) AS "publicExecute"
  `;
  assert.deepEqual(acl, {
    api: true,
    worker: false,
    notifier: false,
    auditor: false,
    migrator: true,
    publicExecute: false,
  });
  await assert.rejects(
    asRole("periapsis_worker", (transaction) =>
      transaction.unsafe(
        "SELECT app.resolve_platform_oidc_authentication_configuration_v1('{}'::jsonb)",
      ),
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function assertAdministrationAcl(): Promise<void> {
  const publicFunctions = [
    "app.activate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.deactivate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.lookup_platform_oidc_tenant_switch_replay_v1(jsonb)",
  ];
  const privateFunctions = [
    "app.private_platform_oidc_direct_activation_available_v1(uuid)",
    "app.set_platform_oidc_direct_login_activation_v1(uuid,uuid,bigint,boolean,uuid,uuid,uuid,inet,text,text,text)",
  ];
  const publicAcls = await Promise.all(
    publicFunctions.map(async (functionName) => {
      const [acl] = await admin<
        {
          api: boolean;
          worker: boolean;
          publicExecute: boolean;
        }[]
      >`
        SELECT has_function_privilege(
                 'periapsis_api', ${functionName}::regprocedure, 'EXECUTE'
               ) AS api,
               has_function_privilege(
                 'periapsis_worker', ${functionName}::regprocedure, 'EXECUTE'
               ) AS worker,
               EXISTS (
                 SELECT 1
                 FROM pg_catalog.pg_proc AS function_row
                 CROSS JOIN LATERAL pg_catalog.aclexplode(function_row.proacl)
                   AS acl_row
                 WHERE function_row.oid = ${functionName}::regprocedure
                   AND acl_row.grantee = 0
                   AND acl_row.privilege_type = 'EXECUTE'
               ) AS "publicExecute"
      `;
      return acl;
    }),
  );
  for (const acl of publicAcls) {
    assert.deepEqual(acl, {
      api: true,
      worker: false,
      publicExecute: false,
    });
  }
  const privateAcls = await Promise.all(
    privateFunctions.map(async (functionName) => {
      const [acl] = await admin<{ api: boolean; worker: boolean }[]>`
        SELECT has_function_privilege(
                 'periapsis_api', ${functionName}::regprocedure, 'EXECUTE'
               ) AS api,
               has_function_privilege(
                 'periapsis_worker', ${functionName}::regprocedure, 'EXECUTE'
               ) AS worker
      `;
      return acl;
    }),
  );
  for (const acl of privateAcls) {
    assert.deepEqual(acl, { api: false, worker: false });
  }
}

async function runtimeSnapshot(): Promise<postgres.JSONValue> {
  const [row] = await admin<{ snapshot: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'transactions',(
        SELECT coalesce(jsonb_agg(to_jsonb(transaction)
          ORDER BY transaction.transaction_id),'[]'::jsonb)
        FROM ONLY public.platform_oidc_authentication_transactions AS transaction
      ),
      'auditCount',(
        SELECT count(*) FROM public.platform_audit_events
      ),
      'authorityState',(
        SELECT md5(coalesce(jsonb_agg(entry.payload ORDER BY entry.kind,entry.key),'[]'::jsonb)::text)
        FROM (
          SELECT 'session' AS kind,id::text AS key,to_jsonb(session) AS payload
          FROM ONLY public.auth_sessions AS session
          UNION ALL
          SELECT 'continuation',id::text,to_jsonb(continuation)
          FROM ONLY public.platform_post_primary_continuations AS continuation
          UNION ALL
          SELECT 'challenge',encode(id,'hex'),to_jsonb(challenge)
          FROM ONLY public.platform_post_primary_totp_challenges AS challenge
          UNION ALL
          SELECT 'factor',id::text,to_jsonb(factor)
          FROM ONLY public.totp_credentials AS factor
          UNION ALL
          SELECT 'material',id::text,to_jsonb(material)
          FROM ONLY public.tenant_oidc_session_materials AS material
          UNION ALL
          SELECT 'state',session_id::text,to_jsonb(state)
          FROM ONLY public.auth_session_platform_oidc_states AS state
          UNION ALL
          SELECT 'provenance',session_id::text,to_jsonb(provenance)
          FROM ONLY public.auth_session_platform_oidc_provenance AS provenance
          UNION ALL
          SELECT 'evidence',id::text,to_jsonb(evidence)
          FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
        ) AS entry
      ),
      'rateLimits',(
        SELECT coalesce(jsonb_agg(to_jsonb(rate_limit)
          ORDER BY rate_limit.scope,rate_limit.key_digest),'[]'::jsonb)
        FROM ONLY public.auth_rate_limits AS rate_limit
        WHERE rate_limit.scope IN (
          'platform_oidc_network','platform_oidc_account','platform_oidc_provider'
        )
      )
    ) AS snapshot
  `;
  assert(row);
  return row.snapshot;
}

class RollbackAclTamper extends Error {}

async function assertUserInfoActivationFailsClosed(): Promise<void> {
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL session_replication_role = replica");
      await transaction`
        UPDATE public.platform_oidc_provider_configurations
        SET use_user_info = true
        WHERE provider_id = ${fixture.provider}::uuid
      `;
      await transaction.unsafe("SET LOCAL session_replication_role = origin");
      const [unsupported] = await transaction<{ available: boolean }[]>`
        SELECT app.private_platform_oidc_direct_activation_available_v1(
          ${fixture.provider}::uuid
        ) AS available
      `;
      assert.equal(unsupported?.available, false);
      throw new RollbackAclTamper(
        "rollback unsupported direct UserInfo fixture",
      );
    }),
    RollbackAclTamper,
  );
}

async function assertAclTamperFailsClosed(): Promise<void> {
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe(
        "GRANT EXECUTE ON FUNCTION app.resolve_platform_oidc_authentication_configuration_v1(jsonb) TO periapsis_worker",
      );
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.platform_oidc_direct_runtime_schema_readiness_v54() AS ready
      `;
      assert.equal(tampered?.ready, false);
      throw new RollbackAclTamper("rollback callback ACL tamper");
    }),
    RollbackAclTamper,
  );
  await assertCallbackAcl();
  assert.equal(await directReadiness("periapsis_api"), true);
  assert.equal(await directReadiness("periapsis_worker"), true);
}

try {
  assert.equal(await directReadiness("periapsis_api"), true);
  assert.equal(await directReadiness("periapsis_worker"), true);
  await assertCallbackAcl();
  await assertAdministrationAcl();
  await seedLifecycle();
  await assertDirectDmlDenied();
  await assertUserInfoActivationFailsClosed();

  assert.equal(
    await beginDirect(),
    null,
    "disabled direct policy was not dormant",
  );
  assert.equal(await directReadiness("periapsis_api"), true);
  const dormantProviderDocument = await getProviderDocument();
  const dormantListDocument = await listProviderDocument();
  for (const document of [dormantProviderDocument, dormantListDocument]) {
    assert.equal(booleanField(document, "platformLoginEnabled"), false);
    assert.equal(
      booleanField(document, "platformLoginActivationAvailable"),
      true,
    );
  }
  assert.equal(stringField(dormantProviderDocument, "accountMode"), "create");

  await assert.rejects(
    setDirectPolicy(
      true,
      4,
      fixture.unauthorizedSession,
      fixture.unauthorizedUser,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const activationAttempts = await Promise.allSettled([
    setDirectPolicy(true, 4),
    setDirectPolicy(true, 4),
  ]);
  const activatedAttempts = activationAttempts.filter(
    (
      attempt,
    ): attempt is PromiseFulfilledResult<{
      version: number;
      document: JsonRecord;
    }> => attempt.status === "fulfilled",
  );
  const staleActivationAttempts = activationAttempts.filter(
    (attempt): attempt is PromiseRejectedResult =>
      attempt.status === "rejected",
  );
  assert.equal(activatedAttempts.length, 1);
  assert.equal(staleActivationAttempts.length, 1);
  assertSqlState(staleActivationAttempts[0]?.reason, "40001");
  const activated = activatedAttempts[0]?.value;
  assert(activated);
  assert.equal(activated.version, 5);
  assert.equal(booleanField(activated.document, "platformLoginEnabled"), true);
  assert.equal(
    booleanField(activated.document, "platformLoginActivationAvailable"),
    false,
  );
  assert.equal(stringField(activated.document, "accountMode"), "create");
  assert.equal(await directReadiness("periapsis_api"), true);
  assert.equal(await directReadiness("periapsis_worker"), true);
  await prelinkDirectAccount();

  const [activatedState] = await admin<
    {
      providerVersion: number;
      runtimeEnabled: boolean;
      legacyDirectEnabled: boolean;
      directEnabled: boolean;
      directAccountMode: string;
      directRevision: number;
    }[]
  >`
    SELECT provider.version::integer AS "providerVersion",
           runtime_policy.enabled AS "runtimeEnabled",
           runtime_policy.platform_login_enabled AS "legacyDirectEnabled",
           login_policy.enabled AS "directEnabled",
           login_policy.account_mode AS "directAccountMode",
           login_policy.revision::integer AS "directRevision"
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
    JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    WHERE provider.id = ${fixture.provider}::uuid
  `;
  assert.deepEqual(activatedState, {
    providerVersion: 5,
    runtimeEnabled: true,
    legacyDirectEnabled: false,
    directEnabled: true,
    directAccountMode: "existing_identity",
    directRevision: 2,
  });
  const [activationAudit] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_audit_events
    WHERE action = 'platform.identity_provider.direct_login.activated'
      AND resource_id = ${fixture.provider}::uuid
  `;
  assert.equal(activationAudit?.count, 1);

  const tenantDeactivationTrace = trace();
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) => transaction`
        SELECT *
        FROM app.deactivate_platform_auth_provider_tenant_execution_v1(
          ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
          5::bigint, ${tenantDeactivationTrace.auditId}::uuid,
          ${tenantDeactivationTrace.requestId}::uuid,
          ${tenantDeactivationTrace.correlationId}::uuid,
          '198.51.100.78'::inet,
          'Periapsis direct platform OIDC runtime proof'::text,
          'totp'::text,
          'Reject tenant runtime deactivation while direct login is active'::text
        )
      `,
      fixture.operator,
    ),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  assert.deepEqual(await getProviderDocument(), activated.document);

  const begun = object(await beginDirect(), "direct begin");
  const authorization = object(begun.authorization, "direct authorization");
  const pins = object(begun.pins, "direct pins");
  assert.deepEqual(authorization.provider, {
    scope: "platform",
    providerId: fixture.provider,
  });
  assert.equal(numberField(pins, "loginPolicyRevision"), 2);
  assert.equal(stringField(authorization, "clientId"), clientId);
  assert.equal(stringField(authorization, "redirectUri"), directRedirectUri);
  assert.equal(booleanField(authorization, "allowRefreshToken"), false);
  assert.deepEqual(object(begun.runtimeAdmissionPolicy, "admission policy"), {
    accountMode: "existing_identity",
  });

  const begin = {
    operationRunId: nextUuid(),
    receiptDigest: b64("receipt"),
    networkDigest: b64("network"),
    accountDigest: b64("account"),
    providerDigest: b64("provider"),
  };
  const transactionId = b64("transaction");
  const stateDigest = b64("state");
  const browserDigest = b64("browser");
  const browserCapabilityDigest = b64("browser-capability");
  const nonceDigest = b64("nonce");
  assert.notEqual(browserDigest, browserCapabilityDigest);
  const createdAt = new Date(Date.now() - 2_000);
  const current = {
    id: transactionId,
    stateDigest,
    browserDigest,
    nonceDigest,
    codeChallengeMethod: "S256",
    verifierKeyVersion: keyVersion,
    verifierCiphertext: Buffer.alloc(32, 0x76).toString("base64"),
    pins,
    clientId: authorization.clientId,
    redirectUri: authorization.redirectUri,
    postLogoutRedirectUri: authorization.postLogoutRedirectUri,
    returnPath: "/platform",
    scopes: ["openid", ...stringArrayField(authorization, "extraScopes")],
    allowRefreshToken: authorization.allowRefreshToken,
    useUserInfo: authorization.useUserInfo,
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + 10 * 60_000).toISOString(),
    state: "pending",
    version: 1,
  };
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.create_platform_oidc_authentication_transaction_v1(
        ${transaction.json({
          begin,
          current,
          browserCapabilityDigest,
          audit: audit("Start direct platform OIDC login"),
        })}::jsonb
      ) AS value
    `,
  );
  const createProjection = object(created?.value, "direct create");
  assert.equal(numberField(createProjection, "version"), 1);
  assert.equal(stringField(createProjection, "state"), "pending");
  assert.equal(stringField(createProjection, "browserDigest"), browserDigest);
  assert.deepEqual(createProjection.pins, pins);
  assert.equal(createProjection.browserCapabilityDigest, undefined);

  const [stored] = await admin<
    {
      browserDigest: string;
      browserCapabilityDigest: string;
    }[]
  >`
    SELECT replace(encode(browser_digest,'base64'),E'\\n','') AS "browserDigest",
           replace(encode(browser_capability_digest,'base64'),E'\\n','')
             AS "browserCapabilityDigest"
    FROM ONLY public.platform_oidc_authentication_transactions
    WHERE transaction_id = ${bytes("transaction")}::bytea
  `;
  assert.deepEqual(stored, { browserDigest, browserCapabilityDigest });

  const rateLimits = await admin<
    { scope: string; keyDigest: string; attemptCount: number }[]
  >`
    SELECT scope::text AS scope,
           replace(encode(key_digest,'base64'),E'\\n','') AS "keyDigest",
           attempt_count AS "attemptCount"
    FROM ONLY public.auth_rate_limits
    WHERE scope IN (
      'platform_oidc_network','platform_oidc_account','platform_oidc_provider'
    )
    ORDER BY scope
  `;
  assert.deepEqual(Array.from(rateLimits), [
    {
      scope: "platform_oidc_account",
      keyDigest: begin.accountDigest,
      attemptCount: 1,
    },
    {
      scope: "platform_oidc_network",
      keyDigest: begin.networkDigest,
      attemptCount: 1,
    },
    {
      scope: "platform_oidc_provider",
      keyDigest: begin.providerDigest,
      attemptCount: 1,
    },
  ]);
  const [startedAudit] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.platform_audit_events
    WHERE action = 'platform.oidc.login.started'
      AND resource_id = ${fixture.provider}::uuid
  `;
  assert.equal(startedAudit?.count, 1);

  const beforeWrongBrowser = await runtimeSnapshot();
  const [wrongBrowserClaim] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.claim_platform_oidc_authentication_transaction_v1(
        ${transaction.json({
          stateDigest,
          browserDigest: b64("wrong-browser"),
          authorizationCodeDigest: b64("authorization-code"),
          claimAttemptId: b64("claim-attempt"),
          claimedAt: new Date().toISOString(),
          expectedVersion: 1,
          audit: audit("Reject mismatched direct OIDC browser"),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(wrongBrowserClaim?.value, null);
  assert.deepEqual(await runtimeSnapshot(), beforeWrongBrowser);

  const authorizationCodeDigest = b64("authorization-code");
  const claimAttemptId = b64("claim-attempt");
  const claimRequest = {
    stateDigest,
    browserDigest,
    authorizationCodeDigest,
    claimAttemptId,
    claimedAt: new Date().toISOString(),
    expectedVersion: 1,
    audit: audit("Claim direct platform OIDC callback"),
  };
  const concurrentClaims = await Promise.all(
    [0, 1].map(() =>
      asRole(
        "periapsis_api",
        (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
          SELECT app.claim_platform_oidc_authentication_transaction_v1(
            ${transaction.json(claimRequest)}::jsonb
          ) AS value
        `,
      ),
    ),
  );
  const claimProjections = concurrentClaims.map(([claimed]) =>
    object(claimed?.value, "concurrent direct claim"),
  );
  const [claimProjection, replayedClaimProjection] = claimProjections;
  assert(claimProjection);
  assert(replayedClaimProjection);
  assert.deepEqual(replayedClaimProjection, claimProjection);
  assert.equal(numberField(claimProjection, "version"), 2);
  assert.equal(stringField(claimProjection, "state"), "claimed");
  assert.equal(
    stringField(claimProjection, "authorizationCodeDigest"),
    authorizationCodeDigest,
  );
  assert.equal(stringField(claimProjection, "claimAttemptId"), claimAttemptId);
  const [storedClaim] = await admin<
    {
      state: string;
      version: number;
      stateDigest: string;
      browserDigest: string;
      authorizationCodeDigest: string;
    }[]
  >`
    SELECT state, version::integer AS version,
           replace(encode(state_digest,'base64'),E'\\n','') AS "stateDigest",
           replace(encode(browser_digest,'base64'),E'\\n','') AS "browserDigest",
           replace(encode(authorization_code_digest,'base64'),E'\\n','')
             AS "authorizationCodeDigest"
    FROM ONLY public.platform_oidc_authentication_transactions
    WHERE transaction_id = ${bytes("transaction")}::bytea
  `;
  assert.deepEqual(storedClaim, {
    state: "claimed",
    version: 2,
    stateDigest,
    browserDigest,
    authorizationCodeDigest,
  });
  const [claimedAudit] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.platform_audit_events
    WHERE action = 'platform.oidc.login.claimed'
      AND resource_id = ${fixture.provider}::uuid
  `;
  assert.equal(claimedAudit?.count, 1);

  const callbackLookup = {
    transactionId,
    expectedVersion: 2,
    pins,
    browserCapabilityDigest,
  };
  const [resolved] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.resolve_platform_oidc_authentication_configuration_v1(
        ${transaction.json(callbackLookup)}::jsonb
      ) AS value
    `,
  );
  const callback = object(resolved?.value, "callback configuration");
  assert.equal(stringField(callback, "returnPath"), "/platform");
  assert.deepEqual(callback.pins, pins);
  const callbackConfiguration = object(
    callback.configuration,
    "callback live configuration",
  );
  assert.deepEqual(callbackConfiguration.pins, pins);
  assert.equal(stringField(callbackConfiguration, "issuer"), issuer);

  const [loadedSecret] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_platform_oidc_client_secret_v1(
        ${transaction.json({ provider: pins.provider, pins })}::jsonb
      ) AS value
    `,
  );
  const secret = object(loadedSecret?.value, "direct client secret");
  assert.equal(stringField(secret, "secretId"), fixture.providerSecret);
  assert.equal(numberField(secret, "keyVersion"), keyVersion);
  assert.deepEqual(secret.pins, pins);

  const materialLessAttempt: DirectAttempt = {
    label: "material-less",
    operationRunId: begin.operationRunId,
    transactionId,
    claimAttemptId,
    browserCapabilityDigest,
    pins,
    returnPath: current.returnPath,
  };
  const materialLessContinuation =
    await applyDirectInitialContinuation(materialLessAttempt);
  await assertNoDirectOidcMaterialForOwners(
    "material-less initial continuation",
    [materialLessContinuation.continuationId],
  );
  const materialLessInitialSession = await completeDirectTotp(
    materialLessContinuation,
    "material-less-initial",
    42,
  );
  await assertNoDirectOidcMaterialForOwners(
    "material-less initial continuation promotion",
    [
      materialLessContinuation.continuationId,
      materialLessInitialSession.sessionId,
    ],
  );
  const materialLessFirstRotation = await rotateDirectSession(
    materialLessInitialSession,
    "material-less-rotation-1",
  );
  const materialLessSecondRotation = await rotateDirectSession(
    materialLessFirstRotation,
    "material-less-rotation-2",
  );
  await assertNoDirectOidcMaterialForOwners(
    "material-less second family rotation",
    [
      materialLessInitialSession.sessionId,
      materialLessFirstRotation.sessionId,
      materialLessSecondRotation.sessionId,
    ],
  );
  const materialLessStepUp = await beginDirectStepUp(
    materialLessSecondRotation,
    "material-less-step-up",
  );
  await assertNoDirectOidcMaterialForOwners(
    "material-less step-up continuation",
    [materialLessSecondRotation.sessionId, materialLessStepUp.continuationId],
  );
  const materialLessStepUpSession = await completeDirectTotp(
    materialLessStepUp,
    "material-less-step-up",
    43,
    materialLessSecondRotation,
  );
  await assertNoDirectOidcMaterialForOwners(
    "material-less step-up continuation promotion",
    [
      materialLessSecondRotation.sessionId,
      materialLessStepUp.continuationId,
      materialLessStepUpSession.sessionId,
    ],
  );
  const missingMaterialRotation = await buildDirectRotation(
    materialLessStepUpSession,
    "required-material-missing",
  );
  await assertDirectRequiredMaterialFailsClosed(
    materialLessAttempt,
    missingMaterialRotation.command,
  );

  const materialPresentAttempt = await prepareDirectAttempt("material-present");
  const materialPresentContinuation = await applyDirectInitialContinuation(
    materialPresentAttempt,
  );
  const initialMaterial = await insertDirectMaterial(
    materialPresentContinuation,
  );
  assertDirectMaterialTransferred(initialMaterial, initialMaterial, {
    continuationId: materialPresentContinuation.continuationId,
    rotationFamilyId: null,
    sessionId: null,
  });
  const materialPresentInitialSession = await completeDirectTotp(
    materialPresentContinuation,
    "material-present-initial",
    44,
  );
  const afterInitialPromotion = await loadDirectMaterial(
    materialPresentAttempt.operationRunId,
  );
  assertDirectMaterialTransferred(initialMaterial, afterInitialPromotion, {
    continuationId: null,
    rotationFamilyId: materialPresentInitialSession.familyId,
    sessionId: materialPresentInitialSession.sessionId,
  });
  const materialPresentRotation = await rotateDirectSession(
    materialPresentInitialSession,
    "material-present-rotation",
  );
  const afterMaterialRotation = await loadDirectMaterial(
    materialPresentAttempt.operationRunId,
  );
  assertDirectMaterialTransferred(initialMaterial, afterMaterialRotation, {
    continuationId: null,
    rotationFamilyId: materialPresentRotation.familyId,
    sessionId: materialPresentRotation.sessionId,
  });
  const materialPresentStepUp = await beginDirectStepUp(
    materialPresentRotation,
    "material-present-step-up",
  );
  const afterMaterialStepUp = await loadDirectMaterial(
    materialPresentAttempt.operationRunId,
  );
  assertDirectMaterialTransferred(initialMaterial, afterMaterialStepUp, {
    continuationId: materialPresentStepUp.continuationId,
    rotationFamilyId: null,
    sessionId: null,
  });
  const materialPresentStepUpSession = await completeDirectTotp(
    materialPresentStepUp,
    "material-present-step-up",
    45,
    materialPresentRotation,
  );
  const afterMaterialStepUpPromotion = await loadDirectMaterial(
    materialPresentAttempt.operationRunId,
  );
  assertDirectMaterialTransferred(
    initialMaterial,
    afterMaterialStepUpPromotion,
    {
      continuationId: null,
      rotationFamilyId: materialPresentStepUpSession.familyId,
      sessionId: materialPresentStepUpSession.sessionId,
    },
  );

  const beforeSwappedCapability = await runtimeSnapshot();
  const [swappedCapability] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.resolve_platform_oidc_authentication_configuration_v1(
        ${transaction.json({
          ...callbackLookup,
          browserCapabilityDigest: b64("swapped-browser-capability"),
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(swappedCapability?.value, null);
  assert.deepEqual(await runtimeSnapshot(), beforeSwappedCapability);

  const deactivationAttempts = await Promise.allSettled([
    setDirectPolicy(false, 5),
    setDirectPolicy(false, 5),
  ]);
  const deactivatedAttempts = deactivationAttempts.filter(
    (
      attempt,
    ): attempt is PromiseFulfilledResult<{
      version: number;
      document: JsonRecord;
    }> => attempt.status === "fulfilled",
  );
  const staleDeactivationAttempts = deactivationAttempts.filter(
    (attempt): attempt is PromiseRejectedResult =>
      attempt.status === "rejected",
  );
  assert.equal(deactivatedAttempts.length, 1);
  assert.equal(staleDeactivationAttempts.length, 1);
  assertSqlState(staleDeactivationAttempts[0]?.reason, "40001");
  const deactivated = deactivatedAttempts[0]?.value;
  assert(deactivated);
  assert.equal(deactivated.version, 6);
  assert.equal(
    booleanField(deactivated.document, "platformLoginEnabled"),
    false,
  );
  assert.equal(
    booleanField(deactivated.document, "platformLoginActivationAvailable"),
    true,
  );
  assert.equal(stringField(deactivated.document, "accountMode"), "create");
  const [deactivatedState] = await admin<
    {
      providerVersion: number;
      runtimeEnabled: boolean;
      legacyDirectEnabled: boolean;
      directEnabled: boolean;
      directAccountMode: string;
      directRevision: number;
    }[]
  >`
    SELECT provider.version::integer AS "providerVersion",
           runtime_policy.enabled AS "runtimeEnabled",
           runtime_policy.platform_login_enabled AS "legacyDirectEnabled",
           login_policy.enabled AS "directEnabled",
           login_policy.account_mode AS "directAccountMode",
           login_policy.revision::integer AS "directRevision"
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
    JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    WHERE provider.id = ${fixture.provider}::uuid
  `;
  assert.deepEqual(deactivatedState, {
    providerVersion: 6,
    runtimeEnabled: true,
    legacyDirectEnabled: false,
    directEnabled: false,
    directAccountMode: "disabled",
    directRevision: 3,
  });
  const [deactivationAudit] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_audit_events
    WHERE action = 'platform.identity_provider.direct_login.deactivated'
      AND resource_id = ${fixture.provider}::uuid
  `;
  assert.equal(deactivationAudit?.count, 1);
  const [invalidatedCallback] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.resolve_platform_oidc_authentication_configuration_v1(
        ${transaction.json(callbackLookup)}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    invalidatedCallback?.value,
    null,
    "deactivation did not invalidate the pinned callback transaction",
  );
  assert.equal(await beginDirect(), null);
  assert.equal(await directReadiness("periapsis_api"), true);
  assert.equal(await directReadiness("periapsis_worker"), true);
  await assertAclTamperFailsClosed();

  process.stdout.write(
    "platform OIDC direct authentication runtime fixture passed\n",
  );
} finally {
  await admin.end({ timeout: 5 });
}
