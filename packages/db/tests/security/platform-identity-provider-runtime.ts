import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql } from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker";
type ProviderKind = "oidc" | "saml";
type JsonObject = { readonly [key: string]: postgres.JSONValue };
type CreateReceipt = {
  provider_id: string;
  version: number;
  replayed: boolean;
  document: ProviderProjection;
};
type ProviderProjection = Readonly<Record<string, unknown>>;

const configuredDatabaseUrl =
  process.env.PERIAPSIS_PLATFORM_IDENTITY_PROVIDER_TEST_DATABASE_URL;
if (
  configuredDatabaseUrl === undefined ||
  configuredDatabaseUrl.trim() === ""
) {
  throw new Error(
    "PERIAPSIS_PLATFORM_IDENTITY_PROVIDER_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}
const databaseUrl = configuredDatabaseUrl;

const admin = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d3b20-6000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;

const fixture = {
  operator: uuid(1),
  deniedOperator: uuid(2),
  operatorGrant: uuid(3),
  operatorSession: uuid(4),
  deniedSession: uuid(5),
  operatorFamily: uuid(6),
  deniedFamily: uuid(7),
  tenant: uuid(8),
  tenantMembership: uuid(9),
  tenantSession: uuid(10),
  tenantFamily: uuid(11),
  tenantOperator: uuid(12),
  tenantOperatorGrant: uuid(13),
  tenantOperatorMembership: uuid(14),
  tenantOperatorSession: uuid(15),
  tenantOperatorFamily: uuid(16),
  resumedTenantOperatorSession: uuid(17),
  resumedTenantOperatorFamily: uuid(18),
  oidcProvider: uuid(20),
  samlProvider: uuid(21),
  replayProvider: uuid(22),
  conflictProvider: uuid(23),
  oidcCommand: uuid(30),
  oidcReplayCommand: uuid(31),
  oidcConflictCommand: uuid(32),
  deniedCommand: uuid(36),
  wrongSubtypeCommand: uuid(37),
  secret: uuid(40),
  staleSecret: uuid(41),
  readDeniedProvider: uuid(42),
  readDeniedCommand: uuid(43),
  expiryProvider: uuid(44),
  expiryCommand: uuid(45),
  expiryReplayCommand: uuid(46),
} as const;

const protectedTables = [
  "platform_auth_providers",
  "platform_federated_provider_policies",
  "platform_federated_trust_rules",
  "platform_identity_provider_commands",
  "platform_identity_provider_test_runs",
  "platform_oidc_claim_rules",
  "platform_oidc_client_secrets",
  "platform_oidc_discovery_snapshots",
  "platform_oidc_jwks_snapshots",
  "platform_oidc_provider_configurations",
  "platform_saml_attribute_rules",
  "platform_saml_metadata_snapshots",
  "platform_saml_provider_configurations",
  "platform_saml_sp_certificates",
  "platform_saml_sp_keys",
] as const;

const protectedFunctions = [
  "app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)",
  "app.get_platform_auth_provider_v1(uuid,uuid,text)",
  "app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
  "app.update_platform_auth_provider_v1(uuid,uuid,bigint,text,text,text,uuid,uuid,uuid,inet,text,text,text)",
  "app.archive_platform_auth_provider_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
  "app.replace_platform_oidc_client_secret_v1(uuid,uuid,uuid,bigint,integer,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
] as const;

const retiredRuntimeFunctions = [
  "app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
  "app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
] as const;

const keyringFunction =
  "app.verify_identity_keyring_v3(integer[],bytea[],integer)";

const legacyKeyringFunctions = [
  "app.verify_identity_keyring_v1(integer[],bytea[],integer)",
  "app.verify_identity_keyring_v2(integer[],bytea[],integer)",
] as const;

const platformRuntimeRoles = [
  "periapsis_api",
  "periapsis_worker",
  "periapsis_notifier",
  "periapsis_auditor",
  "periapsis_audit_reader_owner",
  "periapsis_notification_dispatch_owner",
  "periapsis_sla_api_owner",
  "periapsis_sla_worker_owner",
  "periapsis_sla_readiness_owner",
  "periapsis_ticket_saved_view_owner",
  "periapsis_ticket_attribution_owner",
  "periapsis_ticket_sla_projection_owner",
] as const;

const identityPermissions = [
  "platform.identity_provider.read",
  "platform.identity_provider.manage",
  "platform.identity_provider.test",
  "platform.identity_binding.read",
  "platform.identity_binding.manage",
  "platform.identity_policy.read",
  "platform.identity_policy.manage",
  "platform.identity_account.read",
  "platform.identity_account.manage",
] as const;

const oidcConfiguration = {
  issuer: "https://platform-idp.example.invalid",
  clientId: "periapsis-platform-runtime",
  redirectUri: "https://periapsis.example.invalid/auth/platform/oidc/callback",
  postLogoutRedirectUri: "https://periapsis.example.invalid/login",
  extraScopes: ["groups"],
  allowRefreshToken: false,
  useUserInfo: true,
} as const;

const tenantOidcRedirectUri =
  "https://tenant.periapsis.example.invalid/api/v1/auth/federated/oidc/callback";

const samlConfiguration = {
  expectedEntityId: "https://platform-saml.example.invalid/metadata",
  spEntityId: "https://periapsis.example.invalid/auth/platform/saml/metadata",
  acsUrl: "https://periapsis.example.invalid/auth/platform/saml/acs",
  redirectSignatureAlgorithm:
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  signaturePolicy: "signed_assertion",
  encryptionPolicy: "disabled",
  decryptionKeyVersions: [],
  requestedAuthnContexts: [
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  ],
  subjectSource: "persistent_nameid",
  clockSkewNanoseconds: 30_000_000_000,
  maxAuthenticationAgeNanoseconds: 3_600_000_000_000,
} as const;

const secretCiphertext = Buffer.from(
  "platform-oidc-secret-runtime-marker",
  "utf8",
);
const secretNonce = Buffer.alloc(12, 0xa6);
const keyVersion = 32_766;
const inactiveKeyVersion = 32_765;
let envelopeSequence = 100;

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-identity-provider-runtime:${label}`)
    .digest();
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function envelope(): {
  auditId: string;
  requestId: string;
  correlationId: string;
} {
  envelopeSequence += 3;
  return {
    auditId: uuid(envelopeSequence - 2),
    requestId: uuid(envelopeSequence - 1),
    correlationId: uuid(envelopeSequence),
  };
}

function assertSqlState(error: unknown, expected: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

// The V50 release root attests the current catalog and ACL state. Provider data
// invariants outside that catalog surface use explicit probes below.
async function assertReadinessRejectsTransactionalCatalogMutation(
  label: string,
  mutation: (transaction: postgres.TransactionSql) => Promise<unknown>,
): Promise<void> {
  const rollback = new Error(`rollback platform provider proof: ${label}`);
  await assert.rejects(
    admin.begin(async (transaction) => {
      await mutation(transaction);
      const [state] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v50() AS ready
      `;
      assert.equal(state?.ready, false, `readiness accepted ${label}`);
      throw rollback;
    }),
    (error: unknown) => error === rollback,
  );

  const [restored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(
    restored?.ready,
    true,
    `readiness did not recover after rolling back ${label}`,
  );
}

async function asRole<T>(
  client: Sql,
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  userId?: string,
  tenantId?: string,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantId ?? ""}, true),
             set_config('app.user_id', ${userId ?? ""}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function createOidcProvider(input: {
  actor?: string;
  session?: string;
  commandId: string;
  providerId: string;
  key: string;
  displayName: string;
  description?: string;
  configuration: JsonObject;
  tenantRedirectUri?: string;
  keyDigest: Buffer;
  requestDigest: Buffer;
  reason?: string;
  requestId?: string;
  correlationId?: string;
  userAgent?: string;
}): Promise<CreateReceipt> {
  const trace = envelope();
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [receipt] = await transaction<CreateReceipt[]>`
        SELECT result.provider_id, result.version::integer AS version,
               result.replayed, result.document
        FROM app.create_platform_oidc_auth_provider_v3(
          ${input.session ?? fixture.operatorSession}::uuid,
          ${input.commandId}::uuid, ${input.providerId}::uuid,
          ${input.key}::text, ${input.displayName}::text,
          ${input.description ?? "Platform provider runtime security proof"}::text,
          ${transaction.json(input.configuration)}::jsonb,
          ${input.tenantRedirectUri ?? tenantOidcRedirectUri}::text,
          ${input.keyDigest}::bytea, ${input.requestDigest}::bytea,
          ${trace.auditId}::uuid, ${input.requestId ?? trace.requestId}::uuid,
          ${input.correlationId ?? trace.correlationId}::uuid,
          '198.51.100.42'::inet,
          ${input.userAgent ?? "Periapsis platform identity-provider runtime proof"}::text,
          'totp'::text,
          ${input.reason ?? "Create OIDC provider"}::text
        ) AS result
      `;
      assert(receipt, "platform provider create returned no receipt");
      return receipt;
    },
    input.actor ?? fixture.operator,
  );
}

async function seedSamlProviderFixture(): Promise<ProviderProjection> {
  // Frozen v35 intentionally exposes no runtime SAML-create ABI. Seed this
  // storage fixture as the migrator so read/update and table invariants remain
  // covered without reviving create_platform_auth_provider_v1.
  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.platform_auth_providers (
        id, key, display_name, description, kind, enabled,
        created_by_user_id, updated_by_user_id, version
      ) VALUES (
        ${fixture.samlProvider}::uuid, 'platform_saml_runtime',
        'Platform SAML runtime',
        'Platform provider runtime security proof', 'saml', false,
        ${fixture.operator}::uuid, ${fixture.operator}::uuid, 1
      )
    `;
    await transaction`
      INSERT INTO public.platform_federated_provider_policies (
        provider_id, provider_kind, configuration_revision,
        security_revision, plan_revision, assurance_policy_revision,
        account_mode, platform_login_enabled, enabled
      ) VALUES (
        ${fixture.samlProvider}::uuid, 'saml', 1, 1, 1, 1,
        'disabled', false, false
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_provider_configurations (
        provider_id, expected_entity_id, sp_entity_id, acs_url,
        sp_key_revision, metadata_revision, redirect_signature_algorithm,
        signature_policy, encryption_policy, decryption_key_versions,
        requested_authn_contexts, subject_source, subject_attribute_name,
        subject_attribute_name_format, clock_skew_nanoseconds,
        max_authentication_age_nanoseconds
      ) VALUES (
        ${fixture.samlProvider}::uuid,
        ${samlConfiguration.expectedEntityId},
        ${samlConfiguration.spEntityId}, ${samlConfiguration.acsUrl}, 1, 1,
        ${samlConfiguration.redirectSignatureAlgorithm},
        ${samlConfiguration.signaturePolicy},
        ${samlConfiguration.encryptionPolicy}, ARRAY[]::integer[],
        ${samlConfiguration.requestedAuthnContexts}::text[],
        ${samlConfiguration.subjectSource}, NULL, NULL,
        ${samlConfiguration.clockSkewNanoseconds}::bigint,
        ${samlConfiguration.maxAuthenticationAgeNanoseconds}::bigint
      )
    `;
  });
  return getProvider(fixture.samlProvider);
}

async function listProviders(
  includeArchived = false,
): Promise<ProviderProjection[]> {
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const rows = await transaction<{ document: ProviderProjection }[]>`
        SELECT document
        FROM app.list_platform_auth_providers_v1(
          ${fixture.operatorSession}::uuid, 'totp'::text, NULL::uuid,
          50::integer, ${includeArchived}::boolean
        )
      `;
      return rows.map((row) => row.document);
    },
    fixture.operator,
  );
}

async function getProvider(providerId: string): Promise<ProviderProjection> {
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ document: ProviderProjection }[]>`
        SELECT app.get_platform_auth_provider_v1(
          ${fixture.operatorSession}::uuid, ${providerId}::uuid, 'totp'::text
        ) AS document
      `;
      assert(row, "platform provider get returned no row");
      return row.document;
    },
    fixture.operator,
  );
}

async function withoutPlatformProviderReadGrant<T>(
  operation: () => Promise<T>,
): Promise<T> {
  const [removed] = await admin<{ roleId: string; permissionId: string }[]>`
    DELETE FROM public.platform_role_permissions AS grant_row
    USING public.platform_roles AS role,
          public.platform_permissions AS permission
    WHERE grant_row.role_id = role.id
      AND grant_row.permission_id = permission.id
      AND role.key = 'platform_super_admin'
      AND permission.key = 'platform.identity_provider.read'
    RETURNING grant_row.role_id AS "roleId",
              grant_row.permission_id AS "permissionId"
  `;
  assert(removed, "platform provider read grant was not present");
  try {
    return await operation();
  } finally {
    await admin`
      INSERT INTO public.platform_role_permissions (role_id, permission_id)
      VALUES (${removed.roleId}::uuid, ${removed.permissionId}::uuid)
      ON CONFLICT DO NOTHING
    `;
  }
}

async function updateOidcProvider(
  expectedVersion: number,
): Promise<{ version: number; document: ProviderProjection }> {
  return updateProviderMetadata({
    providerId: fixture.oidcProvider,
    expectedVersion,
    sessionId: fixture.operatorSession,
    key: "platform_oidc_runtime",
    displayName: "Platform OIDC runtime updated",
    description: "Updated without enabling login",
  });
}

async function updateProviderMetadata(input: {
  providerId: string;
  expectedVersion: number;
  sessionId: string;
  key: string;
  displayName: string;
  description: string;
}): Promise<{ version: number; document: ProviderProjection }> {
  const trace = envelope();
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<
        { version: number; document: ProviderProjection }[]
      >`
        SELECT result.version::integer AS version, result.document
        FROM app.update_platform_auth_provider_v1(
          ${input.sessionId}::uuid, ${input.providerId}::uuid,
          ${input.expectedVersion}::bigint, ${input.key}::text,
          ${input.displayName}::text, ${input.description}::text,
          ${trace.auditId}::uuid, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text, 'Update safe provider metadata'::text
        ) AS result
      `;
      assert(row);
      return row;
    },
    fixture.operator,
  );
}

async function rotateOidcSecret(
  expectedVersion: number,
  secretId: string,
  encryptionKeyVersion = keyVersion,
  providerId = fixture.oidcProvider,
): Promise<{ version: number; secretRevision: number }> {
  const trace = envelope();
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<
        { version: number; secretRevision: number }[]
      >`
        SELECT result.version::integer AS version,
               result.secret_revision::integer AS "secretRevision"
        FROM app.replace_platform_oidc_client_secret_v1(
          ${fixture.operatorSession}::uuid, ${providerId}::uuid,
          ${secretId}::uuid, ${expectedVersion}::bigint,
          ${encryptionKeyVersion}::integer, ${secretNonce}::bytea,
          ${secretCiphertext}::bytea, ${trace.auditId}::uuid,
          ${trace.requestId}::uuid, ${trace.correlationId}::uuid,
          '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text, 'Rotate encrypted OIDC client secret'::text
        ) AS result
      `;
      assert(row, "OIDC secret rotation returned no row");
      return row;
    },
    fixture.operator,
  );
}

async function archiveOidcProvider(expectedVersion: number): Promise<number> {
  const trace = envelope();
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ version: number }[]>`
        SELECT app.archive_platform_auth_provider_v1(
          ${fixture.operatorSession}::uuid, ${fixture.oidcProvider}::uuid,
          ${expectedVersion}::bigint, ${trace.auditId}::uuid,
          ${trace.requestId}::uuid, ${trace.correlationId}::uuid,
          '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text, 'Archive unused platform OIDC provider'::text
        )::integer AS version
      `;
      assert(row);
      return row.version;
    },
    fixture.operator,
  );
}

function assertSafeProjection(document: ProviderProjection): void {
  const serialized = JSON.stringify(document);
  const forbiddenKeys = /"(?:nonce|ciphertext|certificateDer|privateKey)"/i;
  assert.doesNotMatch(serialized, forbiddenKeys);
  assert(!serialized.includes(secretCiphertext.toString("utf8")));
  assert(!serialized.includes(secretCiphertext.toString("hex")));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
};

function deferred<T>(): Deferred<T> {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  assert(resolvePromise);
  return { promise, resolve: resolvePromise };
}

async function waitForDatabaseBlocker(
  waitingPid: number,
  blockingPid: number,
  label: string,
  deadline = Date.now() + 5_000,
): Promise<void> {
  const [state] = await admin<{ blocked: boolean }[]>`
    SELECT ${blockingPid}::integer = ANY (
      pg_catalog.pg_blocking_pids(${waitingPid}::integer)
    ) AS blocked
  `;
  if (state?.blocked) {
    return;
  }
  if (Date.now() >= deadline) {
    throw new Error(`${label} did not reach the expected database lock`);
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
  await waitForDatabaseBlocker(waitingPid, blockingPid, label, deadline);
}

async function updateTenantScopedSamlProvider(
  client: Sql,
  expectedVersion: number,
  label: string,
  onStarted?: (pid: number) => void,
  sessionId = fixture.tenantOperatorSession,
): Promise<{ version: number; document: ProviderProjection }> {
  const trace = envelope();
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [backend] = await transaction<{ pid: number }[]>`
        SELECT pg_catalog.pg_backend_pid() AS pid
      `;
      assert(backend);
      onStarted?.(backend.pid);
      const [row] = await transaction<
        { version: number; document: ProviderProjection }[]
      >`
        SELECT result.version::integer AS version, result.document
        FROM app.update_platform_auth_provider_v1(
          ${sessionId}::uuid,
          ${fixture.samlProvider}::uuid, ${expectedVersion}::bigint,
          'platform_saml_runtime'::text,
          ${`Platform SAML ${label}`}::text,
          'Tenant authorization serialization proof'::text,
          ${trace.auditId}::uuid, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text, 'Verify tenant authorization serialization'::text
        ) AS result
      `;
      assert(row);
      return row;
    },
    fixture.tenantOperator,
  );
}

async function changeRuntimeTenantLifecycle(
  client: Sql,
  target: "active" | "suspended",
  expectedVersion: number,
  onStarted?: (pid: number) => void,
): Promise<number> {
  const trace = envelope();
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [backend] = await transaction<{ pid: number }[]>`
        SELECT pg_catalog.pg_backend_pid() AS pid
      `;
      assert(backend);
      onStarted?.(backend.pid);
      const [row] = await transaction<{ version: number }[]>`
        SELECT result.version
        FROM app.change_platform_tenant_lifecycle(
          ${fixture.operatorSession}::uuid, ${fixture.tenant}::uuid,
          ${target}::public.tenant_status, ${expectedVersion}::integer,
          ${target === "suspended" ? "Suspend runtime tenant" : "Reactivate runtime tenant"}::text,
          ${trace.auditId}::uuid, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text
        ) AS result
      `;
      assert(row);
      return row.version;
    },
    fixture.operator,
  );
}

async function seedFixture(): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 60 * 60_000);
  await admin.begin(async (transaction) => {
    const [existing] = await transaction<{ count: number }[]>`
      SELECT (
        (SELECT count(*) FROM public.users
         WHERE id IN (
           ${fixture.operator}::uuid, ${fixture.deniedOperator}::uuid,
           ${fixture.tenantOperator}::uuid
         ))
        +
        (SELECT count(*) FROM public.platform_auth_providers
         WHERE key IN ('platform_oidc_runtime', 'platform_saml_runtime'))
      )::integer AS count
    `;
    assert.equal(
      existing?.count,
      0,
      "platform identity-provider runtime proof requires a fresh disposable database",
    );

    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.operator}::uuid,
         'platform-provider.operator@example.invalid',
         'Platform provider operator'),
        (${fixture.deniedOperator}::uuid,
         'platform-provider.denied@example.invalid',
         'Denied platform provider operator'),
        (${fixture.tenantOperator}::uuid,
         'platform-provider.tenant-operator@example.invalid',
         'Tenant-scoped platform provider operator')
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id, granted_at
      )
      SELECT ${fixture.operatorGrant}::uuid, ${fixture.operator}::uuid,
             role.id, ${fixture.operator}::uuid, ${now}
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id, granted_at
      )
      SELECT ${fixture.tenantOperatorGrant}::uuid,
             ${fixture.tenantOperator}::uuid, role.id,
             ${fixture.operator}::uuid, ${now}
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES
        (
          ${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
          ${fixture.operatorFamily}::uuid, NULL, ${digest("operator-token")}::bytea,
          ${digest("operator-csrf")}::bytea, 'totp', ${now}, ${now},
          ${expires}, ${expires}, ${now}
        ),
        (
          ${fixture.deniedSession}::uuid, ${fixture.deniedOperator}::uuid,
          ${fixture.deniedFamily}::uuid, NULL, ${digest("denied-token")}::bytea,
          ${digest("denied-csrf")}::bytea, 'totp', ${now}, ${now},
          ${expires}, ${expires}, ${now}
        )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES
        (${keyVersion}, ${digest("keyring-verifier")}::bytea, true),
        (${inactiveKeyVersion}, ${digest("inactive-keyring-verifier")}::bytea, false)
    `;
  });

  const tenantTrace = envelope();
  await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      await transaction`
        SELECT id
        FROM app.create_platform_tenant(
          ${fixture.tenant}::uuid, ${fixture.tenantMembership}::uuid,
          'platform-provider-runtime'::text,
          'Platform provider runtime tenant'::text,
          'Europe/Rome'::text, 'en'::text,
          ${tenantTrace.auditId}::uuid, ${tenantTrace.requestId}::uuid,
          ${tenantTrace.correlationId}::uuid, '198.51.100.42'::inet,
          'Periapsis platform identity-provider runtime proof'::text,
          'totp'::text
        )
      `;
    },
    fixture.operator,
  );
  await admin`
    INSERT INTO public.tenant_memberships (
      id, tenant_id, user_id, role, status
    ) VALUES (
      ${fixture.tenantOperatorMembership}::uuid, ${fixture.tenant}::uuid,
      ${fixture.tenantOperator}::uuid, 'analyst', 'active'
    )
  `;
  await admin`
    INSERT INTO public.auth_sessions (
      id, user_id, rotation_family_id, active_tenant_id, token_digest,
      csrf_secret_digest, authentication_method, mfa_satisfied_at,
      last_seen_at, idle_expires_at, absolute_expires_at, created_at
    ) VALUES
      (
        ${fixture.tenantSession}::uuid, ${fixture.operator}::uuid,
        ${fixture.tenantFamily}::uuid, ${fixture.tenant}::uuid,
        ${digest("operator-tenant-session-token")}::bytea,
        ${digest("operator-tenant-session-csrf")}::bytea,
        'totp', ${now}, ${now}, ${expires}, ${expires}, ${now}
      ),
      (
        ${fixture.tenantOperatorSession}::uuid,
        ${fixture.tenantOperator}::uuid,
        ${fixture.tenantOperatorFamily}::uuid, ${fixture.tenant}::uuid,
        ${digest("tenant-session-token")}::bytea,
        ${digest("tenant-session-csrf")}::bytea, 'totp', ${now}, ${now},
        ${expires}, ${expires}, ${now}
      )
  `;
}

async function verifyCompatibilityAndBoundary(): Promise<void> {
  // V50 is the only live oracle. Historical projections are observed only to
  // prove their exact fail-closed result.
  const [compatibility] = await admin<
    {
      currentCount: number;
      currentLatest: string;
      currentHash: string;
      currentFingerprint: string;
      predecessorCount: number;
      predecessorLatest: string;
      predecessorHash: string;
      predecessorFingerprint: string;
      legacyCount: number;
      legacyLatest: string;
      legacyHash: string;
      legacyFingerprint: string;
      ready: boolean;
      oidcReady: boolean;
      samlReady: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS "currentCount",
           current_projection.latest_created_at::text AS "currentLatest",
           current_projection.latest_hash AS "currentHash",
           current_projection.migration_fingerprint AS "currentFingerprint",
           predecessor_projection.applied_count::integer AS "predecessorCount",
           predecessor_projection.latest_created_at::text AS "predecessorLatest",
           predecessor_projection.latest_hash AS "predecessorHash",
           predecessor_projection.migration_fingerprint AS "predecessorFingerprint",
           legacy_projection.applied_count::integer AS "legacyCount",
           legacy_projection.latest_created_at::text AS "legacyLatest",
           legacy_projection.latest_hash AS "legacyHash",
           legacy_projection.migration_fingerprint AS "legacyFingerprint",
           app.release_runtime_schema_readiness_v50() AS ready,
           app.platform_oidc_direct_runtime_schema_readiness_v50()
             AS "oidcReady",
           app.platform_saml_direct_runtime_schema_readiness_v50()
             AS "samlReady"
    FROM app.schema_compatibility_v50() AS current_projection
    CROSS JOIN app.schema_compatibility_v48() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v40() AS legacy_projection
  `;
  assert.deepEqual(compatibility, {
    currentCount: expectedMigrationCount,
    currentLatest: String(expectedMigrationCreatedAt),
    currentHash: expectedMigrationHash,
    currentFingerprint: expectedMigrationFingerprint,
    predecessorCount: 0,
    predecessorLatest: "0",
    predecessorHash: "UNSUPPORTED",
    predecessorFingerprint: "UNSUPPORTED",
    legacyCount: 0,
    legacyLatest: "0",
    legacyHash: "UNSUPPORTED",
    legacyFingerprint: "UNSUPPORTED",
    ready: true,
    oidcReady: true,
    samlReady: true,
  });

  try {
    await admin`
      ALTER TABLE public.platform_identity_provider_commands
      ALTER COLUMN expires_at SET DEFAULT (now() + interval '7 days')
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a changed idempotency expiry default",
    );
  } finally {
    await admin`
      ALTER TABLE public.platform_identity_provider_commands
      ALTER COLUMN expires_at SET DEFAULT (now() + interval '24 hours')
    `;
  }
  const [defaultRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(
    defaultRestored?.ready,
    true,
    "readiness did not recover after the idempotency expiry default was restored",
  );

  try {
    await admin`ALTER ROLE periapsis_migrator LOGIN`;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a login-capable migrator",
    );
  } finally {
    await admin`ALTER ROLE periapsis_migrator NOLOGIN`;
  }
  const [migratorLoginRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(migratorLoginRestored?.ready, true);

  try {
    await admin`ALTER ROLE periapsis_migrator SUPERUSER`;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a superuser migrator",
    );
  } finally {
    await admin`ALTER ROLE periapsis_migrator NOSUPERUSER`;
  }
  const [migratorSuperuserRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(migratorSuperuserRestored?.ready, true);

  try {
    await admin`ALTER ROLE periapsis_ldap_administration_owner LOGIN`;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a login-capable trusted helper owner",
    );
  } finally {
    await admin`ALTER ROLE periapsis_ldap_administration_owner NOLOGIN`;
  }
  const [helperLoginRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(helperLoginRestored?.ready, true);

  try {
    await admin`
      ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator
      GRANT EXECUTE ON FUNCTIONS TO PUBLIC
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted the global PUBLIC routine default",
    );
  } finally {
    await admin`
      ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator
      REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC
    `;
  }
  const [globalDefaultAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(globalDefaultAclRestored?.ready, true);

  try {
    await admin`
      ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator IN SCHEMA public
      GRANT SELECT ON TABLES TO periapsis_api
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a runtime table default grant",
    );
  } finally {
    await admin`
      ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator IN SCHEMA public
      REVOKE SELECT ON TABLES FROM periapsis_api
    `;
  }
  const [schemaDefaultAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(schemaDefaultAclRestored?.ready, true);

  try {
    await admin`
      GRANT periapsis_migrator TO periapsis_api
      WITH INHERIT FALSE, SET TRUE
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a settable migrator membership",
    );
  } finally {
    await admin`REVOKE periapsis_migrator FROM periapsis_api`;
  }
  const [migratorMembershipRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(migratorMembershipRestored?.ready, true);

  await admin`
    CREATE ROLE periapsis_platform_identity_review_probe
    NOLOGIN SUPERUSER
  `;
  try {
    await admin`
      GRANT periapsis_platform_identity_review_probe TO periapsis_api
      WITH INHERIT FALSE, SET TRUE
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a SET-only superuser edge for a runtime role",
    );
  } finally {
    await admin`
      REVOKE periapsis_platform_identity_review_probe FROM periapsis_api
    `;
    await admin`DROP ROLE periapsis_platform_identity_review_probe`;
  }
  const [runtimeMembershipRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(runtimeMembershipRestored?.ready, true);

  const [apiLoginRolePresence] = await admin<{ present: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'periapsis_api_login'
    ) AS present
  `;
  const createdApiLoginRole = !apiLoginRolePresence?.present;
  if (createdApiLoginRole) {
    await admin`
      CREATE ROLE periapsis_api_login
      LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS
    `;
    await admin`GRANT periapsis_api TO periapsis_api_login`;
  }
  await admin`
    CREATE ROLE periapsis_platform_identity_login_edge_probe NOLOGIN
  `;
  try {
    await admin`
      GRANT periapsis_api_login
      TO periapsis_platform_identity_login_edge_probe
      WITH INHERIT FALSE, SET TRUE
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a SET-only inbound edge through a runtime login",
    );
  } finally {
    await admin`
      REVOKE periapsis_api_login
      FROM periapsis_platform_identity_login_edge_probe
    `;
    await admin`DROP ROLE periapsis_platform_identity_login_edge_probe`;
    if (createdApiLoginRole) {
      await admin`REVOKE periapsis_api FROM periapsis_api_login`;
      await admin`DROP ROLE periapsis_api_login`;
    }
  }
  const [runtimeLoginMembershipRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(runtimeLoginMembershipRestored?.ready, true);

  try {
    await admin`GRANT CREATE ON SCHEMA public TO periapsis_api`;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a direct runtime CREATE grant on public",
    );
  } finally {
    await admin`REVOKE CREATE ON SCHEMA public FROM periapsis_api`;
  }
  const [directSchemaAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(directSchemaAclRestored?.ready, true);

  const [publicSchemaBoundary] = await admin<
    { ownerName: string; publicCanCreate: boolean; apiCanCreate: boolean }[]
  >`
    SELECT owner.rolname AS "ownerName",
           has_schema_privilege('public', 'public', 'CREATE')
             AS "publicCanCreate",
           has_schema_privilege('periapsis_api', 'public', 'CREATE')
             AS "apiCanCreate"
    FROM pg_catalog.pg_namespace AS namespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = namespace.nspowner
    WHERE namespace.nspname = 'public'
  `;
  assert.deepEqual(publicSchemaBoundary, {
    ownerName: "periapsis_migrator",
    publicCanCreate: false,
    apiCanCreate: false,
  });

  await admin`
    CREATE ROLE periapsis_platform_identity_schema_acl_probe NOLOGIN
  `;
  try {
    await admin`
      GRANT CREATE ON SCHEMA app
      TO periapsis_platform_identity_schema_acl_probe
    `;
    const [helperTampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      helperTampered?.ready,
      false,
      "readiness accepted an unexpected helper CREATE grant on app",
    );

    await admin`
      GRANT periapsis_platform_identity_schema_acl_probe TO periapsis_api
      WITH INHERIT FALSE, SET TRUE
    `;
    const [inheritedTampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      inheritedTampered?.ready,
      false,
      "readiness accepted a settable helper with CREATE on app",
    );
  } finally {
    await admin`
      REVOKE periapsis_platform_identity_schema_acl_probe FROM periapsis_api
    `;
    await admin`
      REVOKE CREATE ON SCHEMA app
      FROM periapsis_platform_identity_schema_acl_probe
    `;
    await admin`DROP ROLE periapsis_platform_identity_schema_acl_probe`;
  }
  const [inheritedSchemaAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(inheritedSchemaAclRestored?.ready, true);

  const [databaseIdentity] = await admin<
    { databaseName: string; ownerName: string }[]
  >`
    SELECT current_database() AS "databaseName",
           pg_catalog.pg_get_userbyid(database.datdba) AS "ownerName"
    FROM pg_catalog.pg_database AS database
    WHERE database.datname = current_database()
  `;
  assert(databaseIdentity);
  try {
    await admin.unsafe(
      `GRANT CREATE ON DATABASE ${quoteIdentifier(databaseIdentity.databaseName)} TO periapsis_api`,
    );
    const [tampered] = await admin<{ apiCanCreate: boolean; ready: boolean }[]>`
      SELECT has_database_privilege(
               'periapsis_api', current_database(), 'CREATE'
             ) AS "apiCanCreate",
             app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(tampered?.apiCanCreate, true);
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a runtime CREATE grant on the database",
    );
  } finally {
    await admin.unsafe(
      `REVOKE CREATE ON DATABASE ${quoteIdentifier(databaseIdentity.databaseName)} FROM periapsis_api`,
    );
  }
  const [databaseCreateRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(databaseCreateRestored?.ready, true);

  try {
    await admin.unsafe(
      `ALTER DATABASE ${quoteIdentifier(databaseIdentity.databaseName)} OWNER TO periapsis_api`,
    );
    const [tampered] = await admin<{ apiCanCreate: boolean; ready: boolean }[]>`
      SELECT has_schema_privilege(
               'periapsis_api', 'public', 'CREATE'
             ) AS "apiCanCreate",
             app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.apiCanCreate,
      false,
      "database ownership unexpectedly conferred public CREATE through pg_database_owner",
    );
    await assert.rejects(
      asRole(
        admin,
        "periapsis_api",
        (transaction) =>
          transaction.unsafe(
            "CREATE VIEW public.platform_identity_database_owner_probe AS SELECT 1 AS value",
          ),
        fixture.operator,
      ),
      (error: unknown) => assertSqlState(error, "42501"),
    );
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a runtime role as the database owner",
    );
  } finally {
    await admin.unsafe(
      `ALTER DATABASE ${quoteIdentifier(databaseIdentity.databaseName)} OWNER TO ${quoteIdentifier(databaseIdentity.ownerName)}`,
    );
  }
  const [databaseOwnerRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(databaseOwnerRestored?.ready, true);

  const [compatibilityAcl] = await admin<
    {
      apiV50: boolean;
      workerV50: boolean;
      apiV48: boolean;
      workerV48: boolean;
      apiLegacyV40: boolean;
      workerLegacyV40: boolean;
      apiReadiness: boolean;
      workerReadiness: boolean;
    }[]
  >`
    SELECT
      has_function_privilege(
        'periapsis_api', 'app.schema_compatibility_v50()'::regprocedure,
        'EXECUTE'
      ) AS "apiV50",
      has_function_privilege(
        'periapsis_worker', 'app.schema_compatibility_v50()'::regprocedure,
        'EXECUTE'
      ) AS "workerV50",
      has_function_privilege(
        'periapsis_api', 'app.schema_compatibility_v48()'::regprocedure,
        'EXECUTE'
      ) AS "apiV48",
      has_function_privilege(
        'periapsis_worker', 'app.schema_compatibility_v48()'::regprocedure,
        'EXECUTE'
      ) AS "workerV48",
      has_function_privilege(
        'periapsis_api', 'app.schema_compatibility_v40()'::regprocedure,
        'EXECUTE'
      ) AS "apiLegacyV40",
      has_function_privilege(
        'periapsis_worker', 'app.schema_compatibility_v40()'::regprocedure,
        'EXECUTE'
      ) AS "workerLegacyV40",
      has_function_privilege(
        'periapsis_api',
        'app.release_runtime_schema_readiness_v50()'::regprocedure,
        'EXECUTE'
      ) AS "apiReadiness",
      has_function_privilege(
        'periapsis_worker',
        'app.release_runtime_schema_readiness_v50()'::regprocedure,
        'EXECUTE'
      ) AS "workerReadiness"
  `;
  assert.deepEqual(compatibilityAcl, {
    apiV50: true,
    workerV50: true,
    apiV48: false,
    workerV48: false,
    apiLegacyV40: true,
    workerLegacyV40: true,
    apiReadiness: true,
    workerReadiness: true,
  });

  // V40 retains its legacy runtime grant, but must remain semantically retired.
  const runtimeCompatibility = await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).map(async (role) =>
      asRole(admin, role, async (transaction) => {
        const [row] = await transaction<
          {
            currentCount: number;
            currentLatest: string;
            currentHash: string;
            currentFingerprint: string;
            legacyCount: number;
            legacyLatest: string;
            legacyHash: string;
            legacyFingerprint: string;
            ready: boolean;
          }[]
        >`
          SELECT current_projection.applied_count::integer AS "currentCount",
                 current_projection.latest_created_at::text AS "currentLatest",
                 current_projection.latest_hash AS "currentHash",
                 current_projection.migration_fingerprint AS "currentFingerprint",
                 legacy_projection.applied_count::integer AS "legacyCount",
                 legacy_projection.latest_created_at::text AS "legacyLatest",
                 legacy_projection.latest_hash AS "legacyHash",
                 legacy_projection.migration_fingerprint AS "legacyFingerprint",
                 app.release_runtime_schema_readiness_v50() AS ready
          FROM app.schema_compatibility_v50() AS current_projection
          CROSS JOIN app.schema_compatibility_v40() AS legacy_projection
        `;
        return { role, ...row };
      }),
    ),
  );
  const expectedRuntimeProjection = {
    currentCount: expectedMigrationCount,
    currentLatest: String(expectedMigrationCreatedAt),
    currentHash: expectedMigrationHash,
    currentFingerprint: expectedMigrationFingerprint,
    legacyCount: 0,
    legacyLatest: "0",
    legacyHash: "UNSUPPORTED",
    legacyFingerprint: "UNSUPPORTED",
    ready: true,
  };
  assert.deepEqual(runtimeCompatibility, [
    { role: "periapsis_api", ...expectedRuntimeProjection },
    { role: "periapsis_worker", ...expectedRuntimeProjection },
  ]);

  const catalog = await admin<
    {
      tableName: string;
      rls: boolean;
      forced: boolean;
      owner: string;
    }[]
  >`
    SELECT class.relname AS "tableName", class.relrowsecurity AS rls,
           class.relforcerowsecurity AS forced, owner.rolname AS owner
    FROM pg_catalog.pg_class AS class
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = class.relnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = class.relowner
    WHERE namespace.nspname = 'public'
      AND class.relname = ANY (${protectedTables}::name[])
    ORDER BY class.relname
  `;
  assert.deepEqual(
    catalog.map((row) => row.tableName),
    protectedTables.toSorted(),
  );
  for (const row of catalog) {
    assert.deepEqual(
      { rls: row.rls, forced: row.forced, owner: row.owner },
      { rls: true, forced: true, owner: "periapsis_migrator" },
    );
  }

  const leakedPrivileges = await admin<
    { roleName: string; tableName: string }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
           protected_table.table_name AS "tableName"
    FROM unnest(${platformRuntimeRoles}::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${protectedTables}::text[])
      AS protected_table(table_name)
    WHERE has_table_privilege(
      runtime_role.role_name,
      format('public.%I', protected_table.table_name),
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
  `;
  assert.deepEqual(Array.from(leakedPrivileges), []);

  const functionAclMismatches = await admin<
    { roleName: string; signature: string; actual: boolean }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
           protected_function.signature,
           has_function_privilege(
             runtime_role.role_name,
             protected_function.signature::regprocedure,
             'EXECUTE'
           ) AS actual
    FROM unnest(${platformRuntimeRoles}::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${protectedFunctions}::text[])
      AS protected_function(signature)
    WHERE has_function_privilege(
      runtime_role.role_name,
      protected_function.signature::regprocedure,
      'EXECUTE'
    ) IS DISTINCT FROM (runtime_role.role_name = 'periapsis_api')
  `;
  assert.deepEqual(Array.from(functionAclMismatches), []);

  const retiredFunctionAclLeaks = await admin<
    { roleName: string; signature: string }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
           retired_function.signature
    FROM unnest(${platformRuntimeRoles}::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${retiredRuntimeFunctions}::text[])
      AS retired_function(signature)
    WHERE has_function_privilege(
      runtime_role.role_name,
      retired_function.signature::regprocedure,
      'EXECUTE'
    )
  `;
  assert.deepEqual(Array.from(retiredFunctionAclLeaks), []);

  const keyringAclMismatches = await admin<
    { roleName: string; actual: boolean }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
           has_function_privilege(
             runtime_role.role_name, ${keyringFunction}::regprocedure,
             'EXECUTE'
           ) AS actual
    FROM unnest(${platformRuntimeRoles}::text[]) AS runtime_role(role_name)
    WHERE has_function_privilege(
      runtime_role.role_name, ${keyringFunction}::regprocedure, 'EXECUTE'
    ) IS DISTINCT FROM (
      runtime_role.role_name IN ('periapsis_api', 'periapsis_worker')
    )
  `;
  assert.deepEqual(Array.from(keyringAclMismatches), []);

  const legacyKeyringAclMismatches = await admin<
    { roleName: string; signature: string }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
           legacy_verifier.signature
    FROM unnest(${platformRuntimeRoles}::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${legacyKeyringFunctions}::text[])
      AS legacy_verifier(signature)
    WHERE has_function_privilege(
      runtime_role.role_name,
      legacy_verifier.signature::regprocedure,
      'EXECUTE'
    )
  `;
  assert.deepEqual(Array.from(legacyKeyringAclMismatches), []);

  const keyringAcl = await admin<{ roleName: string; grantable: boolean }[]>`
    SELECT grantee.rolname AS "roleName",
           function_acl.is_grantable AS grantable
    FROM pg_catalog.pg_proc AS function
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        function.proacl,
        pg_catalog.acldefault('f', function.proowner)
      )
    ) AS function_acl
    JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = function_acl.grantee
    WHERE function.oid = ${keyringFunction}::regprocedure
      AND function_acl.privilege_type = 'EXECUTE'
    ORDER BY grantee.rolname
  `;
  assert.deepEqual(Array.from(keyringAcl), [
    { roleName: "periapsis_api", grantable: false },
    { roleName: "periapsis_migrator", grantable: false },
    { roleName: "periapsis_worker", grantable: false },
  ]);

  const legacyKeyringAcl = await admin<
    { signature: string; roleName: string; grantable: boolean }[]
  >`
    SELECT function.oid::regprocedure::text AS signature,
           grantee.rolname AS "roleName",
           function_acl.is_grantable AS grantable
    FROM pg_catalog.pg_proc AS function
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        function.proacl,
        pg_catalog.acldefault('f', function.proowner)
      )
    ) AS function_acl
    JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = function_acl.grantee
    WHERE function.oid = ANY (${legacyKeyringFunctions}::regprocedure[])
      AND function_acl.privilege_type = 'EXECUTE'
    ORDER BY signature
  `;
  assert.deepEqual(
    legacyKeyringAcl.map(({ roleName, grantable }) => ({
      roleName,
      grantable,
    })),
    [
      { roleName: "periapsis_migrator", grantable: false },
      { roleName: "periapsis_migrator", grantable: false },
    ],
  );

  await admin.unsafe(
    "ALTER FUNCTION app.get_platform_auth_provider_v1(uuid, uuid, text) SET app.user_id = ''",
  );
  try {
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted an additional ABI-local GUC override",
    );
  } finally {
    await admin.unsafe(
      "ALTER FUNCTION app.get_platform_auth_provider_v1(uuid, uuid, text) RESET app.user_id",
    );
  }
  const [functionConfigurationRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(functionConfigurationRestored?.ready, true);

  await admin`GRANT periapsis_worker TO periapsis_notifier`;
  try {
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted inherited keyring-verifier execution",
    );
  } finally {
    await admin`REVOKE periapsis_worker FROM periapsis_notifier`;
  }
  const [keyringInheritanceRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(keyringInheritanceRestored?.ready, true);

  try {
    await admin.unsafe(
      `GRANT EXECUTE ON FUNCTION ${legacyKeyringFunctions[0]} TO periapsis_api`,
    );
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted direct execution of a legacy keyring verifier",
    );
  } finally {
    await admin.unsafe(
      `REVOKE EXECUTE ON FUNCTION ${legacyKeyringFunctions[0]} FROM periapsis_api`,
    );
  }
  const [legacyKeyringAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(legacyKeyringAclRestored?.ready, true);

  const tamperedFunction = protectedFunctions[1];
  try {
    await admin.unsafe(
      `GRANT EXECUTE ON FUNCTION ${tamperedFunction} TO periapsis_worker`,
    );
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a worker ABI grant",
    );
  } finally {
    await admin.unsafe(
      `REVOKE EXECUTE ON FUNCTION ${tamperedFunction} FROM periapsis_worker`,
    );
  }
  const [functionAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(
    functionAclRestored?.ready,
    true,
    "readiness did not recover after ACL restore",
  );

  try {
    await admin`
      GRANT SELECT ON TABLE public.platform_auth_providers
      TO periapsis_sla_api_owner
    `;
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a protected-table grant to an auxiliary runtime role",
    );
  } finally {
    await admin`
      REVOKE SELECT ON TABLE public.platform_auth_providers
      FROM periapsis_sla_api_owner
    `;
  }
  const [restored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(
    restored?.ready,
    true,
    "readiness did not recover after table ACL restore",
  );

  await admin`
    ALTER TABLE public.platform_auth_providers OWNER TO periapsis_api
  `;
  try {
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a non-migrator protected-table owner",
    );
  } finally {
    await admin`
      ALTER TABLE public.platform_auth_providers OWNER TO periapsis_migrator
    `;
  }

  await admin`
    REVOKE EXECUTE ON FUNCTION app.private_platform_auth_provider_document_v1(uuid)
    FROM periapsis_migrator
  `;
  try {
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted missing private-helper execute for the owner",
    );
  } finally {
    await admin`
      GRANT EXECUTE ON FUNCTION app.private_platform_auth_provider_document_v1(uuid)
      TO periapsis_migrator
    `;
  }
  await admin`
    REVOKE SELECT ON TABLE public.platform_auth_providers
    FROM periapsis_migrator
  `;
  try {
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted missing protected-table access for the owner",
    );
  } finally {
    await admin`
      GRANT SELECT ON TABLE public.platform_auth_providers
      TO periapsis_migrator
    `;
  }

  const [loginRole] = await admin<{ present: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname = 'periapsis_api_login'
    ) AS present
  `;
  const createdLoginRole = !loginRole?.present;
  if (createdLoginRole) {
    await admin.unsafe("CREATE ROLE periapsis_api_login NOLOGIN");
  }
  try {
    await admin.unsafe(
      "GRANT EXECUTE ON FUNCTION app.private_platform_identity_text_is_safe_v1(text, boolean) TO periapsis_api_login",
    );
    const [tampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "readiness accepted a direct private-helper grant to a runtime login",
    );
    await admin.unsafe(
      "REVOKE EXECUTE ON FUNCTION app.private_platform_identity_text_is_safe_v1(text, boolean) FROM periapsis_api_login",
    );
    await admin.unsafe(
      `GRANT EXECUTE ON FUNCTION ${keyringFunction} TO periapsis_api_login`,
    );
    const [keyringTampered] = await admin<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v50() AS ready
    `;
    assert.equal(
      keyringTampered?.ready,
      false,
      "readiness accepted an unexpected keyring-verifier executor",
    );
  } finally {
    await admin.unsafe(
      "REVOKE EXECUTE ON FUNCTION app.private_platform_identity_text_is_safe_v1(text, boolean) FROM periapsis_api_login",
    );
    await admin.unsafe(
      `REVOKE EXECUTE ON FUNCTION ${keyringFunction} FROM periapsis_api_login`,
    );
    if (createdLoginRole) {
      await admin.unsafe("DROP ROLE periapsis_api_login");
    }
  }
  const [exactAclRestored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.equal(exactAclRestored?.ready, true);

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`SELECT count(*) FROM public.platform_auth_providers`.then(
          () => undefined,
        ),
      fixture.operator,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`
          INSERT INTO public.platform_auth_providers (
            id, key, display_name, kind, created_by_user_id, updated_by_user_id
          ) VALUES (
            ${fixture.replayProvider}::uuid, 'direct_write_denied',
            'Direct write denied', 'oidc', ${fixture.operator}::uuid,
            ${fixture.operator}::uuid
          )
        `.then(() => undefined),
      fixture.operator,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function verifyAdversarialCatalogBoundaries(): Promise<void> {
  await assertReadinessRejectsTransactionalCatalogMutation(
    "an unlogged protected table",
    (transaction) =>
      transaction`
        ALTER TABLE public.platform_identity_provider_test_runs SET UNLOGGED
      `,
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "protected-table storage options",
    (transaction) =>
      transaction`
        ALTER TABLE public.platform_identity_provider_test_runs
        SET (fillfactor = 70)
      `,
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a noncanonical replica identity",
    (transaction) =>
      transaction`
        ALTER TABLE public.platform_identity_provider_test_runs
        REPLICA IDENTITY FULL
      `,
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a noncanonical column collation",
    (transaction) =>
      transaction`
        ALTER TABLE public.platform_auth_providers
        ALTER COLUMN description TYPE text COLLATE "C"
        USING description::text
      `,
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "an identity-backed protected column",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_identity_provider_commands
        ALTER COLUMN result_version ADD GENERATED ALWAYS AS IDENTITY
      `;
    },
  );

  await assertReadinessRejectsTransactionalCatalogMutation(
    "a child inheriting from a protected table",
    (transaction) =>
      transaction`
        CREATE TABLE public.platform_auth_providers_runtime_child (
          runtime_probe text
        ) INHERITS (public.platform_auth_providers)
      `,
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a protected table inheriting from an injected parent",
    async (transaction) => {
      await transaction`
        CREATE TABLE public.platform_auth_providers_runtime_parent
        (LIKE public.platform_auth_providers INCLUDING ALL)
      `;
      await transaction`
        ALTER TABLE public.platform_auth_providers
        INHERIT public.platform_auth_providers_runtime_parent
      `;
    },
  );

  await assertReadinessRejectsTransactionalCatalogMutation(
    "an API-readable view over provider secret material",
    async (transaction) => {
      await transaction`
        CREATE VIEW public.platform_identity_runtime_secret_view
        WITH (security_barrier = true) AS
        SELECT provider_id, ciphertext
        FROM public.platform_oidc_client_secrets
      `;
      await transaction`
        ALTER VIEW public.platform_identity_runtime_secret_view
        OWNER TO periapsis_migrator
      `;
      await transaction`
        REVOKE ALL ON public.platform_identity_runtime_secret_view FROM PUBLIC
      `;
      await transaction`
        GRANT SELECT ON public.platform_identity_runtime_secret_view
        TO periapsis_api
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "an API-executable SECURITY DEFINER secret reader",
    async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION app.platform_identity_runtime_secret_reader()
        RETURNS text
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, app
        AS $function$
          SELECT encode(secret.ciphertext, 'hex')
          FROM ONLY public.platform_oidc_client_secrets AS secret
          ORDER BY secret.id
          LIMIT 1
        $function$
      `);
      await transaction`
        ALTER FUNCTION app.platform_identity_runtime_secret_reader()
        OWNER TO periapsis_migrator
      `;
      await transaction`
        REVOKE ALL ON FUNCTION app.platform_identity_runtime_secret_reader()
        FROM PUBLIC
      `;
      await transaction`
        GRANT EXECUTE
        ON FUNCTION app.platform_identity_runtime_secret_reader()
        TO periapsis_api
      `;
    },
  );

  await assertReadinessRejectsTransactionalCatalogMutation(
    "a custom operator in the public trust namespace",
    async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION public.platform_identity_runtime_text_equal(text, text)
        RETURNS boolean
        LANGUAGE sql
        IMMUTABLE
        STRICT
        AS $function$ SELECT $1 = $2 $function$
      `);
      await transaction`
        REVOKE ALL
        ON FUNCTION public.platform_identity_runtime_text_equal(text, text)
        FROM PUBLIC
      `;
      await transaction.unsafe(`
        CREATE OPERATOR public.=== (
          LEFTARG = text,
          RIGHTARG = text,
          FUNCTION = public.platform_identity_runtime_text_equal
        )
      `);
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a cast involving an application-owned type",
    async (transaction) => {
      await transaction`
        CREATE TYPE public.platform_identity_runtime_cast_probe
        AS ENUM ('probe')
      `;
      await transaction.unsafe(`
        CREATE CAST (public.platform_identity_runtime_cast_probe AS text)
        WITH INOUT AS ASSIGNMENT
      `);
    },
  );

  const permissionRollback = new Error(
    "rollback equal-count identity-permission substitution proof",
  );
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction`
        UPDATE public.platform_permissions
        SET key = 'platform.identity_provider.shadow_read'
        WHERE key = 'platform.identity_provider.read'
      `;
      const tamperedPermissions = await transaction<{ permission: string }[]>`
        SELECT permission.key AS permission
        FROM public.platform_permissions AS permission
        WHERE permission.key LIKE 'platform.identity!_%' ESCAPE '!'
        ORDER BY permission.key
      `;
      assert.deepEqual(
        tamperedPermissions.map((row) => row.permission),
        identityPermissions
          .map((permission) =>
            permission === "platform.identity_provider.read"
              ? "platform.identity_provider.shadow_read"
              : permission,
          )
          .toSorted(),
        "equal-count identity-permission substitution was not observed",
      );
      throw permissionRollback;
    }),
    (error: unknown) => error === permissionRollback,
  );
  const restoredPermissions = await admin<{ permission: string }[]>`
    SELECT permission.key AS permission
    FROM public.platform_permissions AS permission
    WHERE permission.key LIKE 'platform.identity!_%' ESCAPE '!'
    ORDER BY permission.key
  `;
  assert.deepEqual(
    restoredPermissions.map((row) => row.permission),
    identityPermissions.toSorted(),
    "identity-permission catalog did not recover after rollback",
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a replaced trusted validator body",
    (transaction) =>
      transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_platform_identity_text_is_safe_v1(
            p_value text,
            p_require_trimmed boolean
          )
        RETURNS boolean
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog, app
        AS $function$ SELECT true $function$
      `),
  );
}

async function verifyPermissionCatalogAndDenials(): Promise<void> {
  const permissions = await admin<{ permission: string; roles: string[] }[]>`
    SELECT permission.key AS permission,
           coalesce(array_agg(role.key ORDER BY role.key)
             FILTER (WHERE role.id IS NOT NULL), ARRAY[]::text[]) AS roles
    FROM public.platform_permissions AS permission
    LEFT JOIN public.platform_role_permissions AS grant_row
      ON grant_row.permission_id = permission.id
    LEFT JOIN public.platform_roles AS role ON role.id = grant_row.role_id
    WHERE permission.key = ANY (${identityPermissions}::text[])
    GROUP BY permission.key
    ORDER BY permission.key
  `;
  assert.deepEqual(
    permissions.map((row) => row.permission),
    identityPermissions.toSorted(),
  );
  for (const permission of permissions) {
    assert.deepEqual(permission.roles, ["platform_super_admin"]);
  }

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`
          SELECT document FROM app.list_platform_auth_providers_v1(
            ${fixture.deniedSession}::uuid, 'totp', NULL, 50, false
          )
        `.then(() => undefined),
      fixture.deniedOperator,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    createOidcProvider({
      actor: fixture.deniedOperator,
      session: fixture.deniedSession,
      commandId: fixture.deniedCommand,
      providerId: fixture.replayProvider,
      key: "denied_oidc",
      displayName: "Denied OIDC",
      configuration: oidcConfiguration,
      keyDigest: digest("denied-key"),
      requestDigest: digest("denied-request"),
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function verifyCreateRequiresCoupledReadAuthority(): Promise<void> {
  const [before] = await admin<
    { audits: number; providers: number; commands: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action = 'platform.identity_provider.created') AS audits,
      (SELECT count(*)::integer FROM public.platform_auth_providers
       WHERE id = ${fixture.readDeniedProvider}::uuid) AS providers,
      (SELECT count(*)::integer FROM public.platform_identity_provider_commands
       WHERE id = ${fixture.readDeniedCommand}::uuid) AS commands
  `;
  await withoutPlatformProviderReadGrant(async () => {
    await assert.rejects(
      createOidcProvider({
        commandId: fixture.readDeniedCommand,
        providerId: fixture.readDeniedProvider,
        key: "read_denied_oidc",
        displayName: "Read denied OIDC",
        configuration: oidcConfiguration,
        keyDigest: digest("read-denied-key"),
        requestDigest: digest("read-denied-request"),
      }),
      (error: unknown) => assertSqlState(error, "42501"),
    );
  });
  const [after] = await admin<
    { audits: number; providers: number; commands: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action = 'platform.identity_provider.created') AS audits,
      (SELECT count(*)::integer FROM public.platform_auth_providers
       WHERE id = ${fixture.readDeniedProvider}::uuid) AS providers,
      (SELECT count(*)::integer FROM public.platform_identity_provider_commands
       WHERE id = ${fixture.readDeniedCommand}::uuid) AS commands
  `;
  assert.deepEqual(
    after,
    before,
    "read-denied create left partial state or audit",
  );
}

async function verifyMalformedDirectCallsRollback(): Promise<void> {
  const malformedCases: {
    name: string;
    configuration?: JsonObject;
    tenantRedirectUri?: string;
    key?: string;
    displayName?: string;
    description?: string;
    reason?: string;
    requestId?: string;
    correlationId?: string;
    userAgent?: string;
  }[] = [
    {
      name: "OIDC HTTP issuer",
      configuration: {
        ...oidcConfiguration,
        issuer: "http://id.example.invalid",
      },
    },
    {
      name: "OIDC issuer query",
      configuration: {
        ...oidcConfiguration,
        issuer: "https://id.example.invalid?tenant=platform",
      },
    },
    {
      name: "OIDC terminal percent escape",
      configuration: {
        ...oidcConfiguration,
        issuer: "https://id.example.invalid/%",
      },
    },
    {
      name: "OIDC redirect fragment",
      configuration: {
        ...oidcConfiguration,
        redirectUri: "https://periapsis.example.invalid/callback#fragment",
      },
    },
    {
      name: "OIDC redirect userinfo",
      configuration: {
        ...oidcConfiguration,
        redirectUri: "https://user@periapsis.example.invalid/callback",
      },
    },
    {
      name: "OIDC noncanonical host",
      configuration: {
        ...oidcConfiguration,
        issuer: "https://Platform-IDP.example.invalid",
      },
    },
    {
      name: "OIDC duplicate scope",
      configuration: {
        ...oidcConfiguration,
        extraScopes: ["groups", "groups"],
      },
    },
    {
      name: "OIDC unsorted scopes",
      configuration: {
        ...oidcConfiguration,
        extraScopes: ["profile", "email"],
      },
    },
    {
      name: "OIDC implicit openid scope",
      configuration: { ...oidcConfiguration, extraScopes: ["openid"] },
    },
    {
      name: "OIDC invalid scope",
      configuration: { ...oidcConfiguration, extraScopes: ["!profile"] },
    },
    {
      name: "OIDC excessive scopes",
      configuration: {
        ...oidcConfiguration,
        extraScopes: Array.from({ length: 33 }, (_, index) => `scope${index}`),
      },
    },
    {
      name: "OIDC padded client ID",
      configuration: { ...oidcConfiguration, clientId: " client-id" },
    },
    {
      name: "OIDC missing boolean",
      configuration: Object.fromEntries(
        Object.entries(oidcConfiguration).filter(
          ([key]) => key !== "useUserInfo",
        ),
      ),
    },
    {
      name: "OIDC unknown property",
      configuration: { ...oidcConfiguration, token: "forbidden" },
    },
    {
      name: "tenant OIDC redirect does not use the federated callback",
      tenantRedirectUri: "https://tenant.periapsis.example.invalid/callback",
    },
    {
      name: "tenant OIDC redirect uses HTTP",
      tenantRedirectUri:
        "http://tenant.periapsis.example.invalid/api/v1/auth/federated/oidc/callback",
    },
    { name: "noncanonical key", key: "Malformed_Key" },
    { name: "padded display name", displayName: " Malformed provider" },
    { name: "control in description", description: "bad\ndescription" },
    { name: "unsafe reason", reason: "secret=abcdefghijklmnop" },
    { name: "control in user agent", userAgent: "bad\nagent" },
    { name: "format control in user agent", userAgent: "bad\u202eagent" },
    {
      name: "non-v7 request ID",
      requestId: "00000000-0000-4000-8000-000000000001",
    },
    {
      name: "non-v7 correlation ID",
      correlationId: "00000000-0000-4000-8000-000000000002",
    },
  ];

  const [before] = await admin<{ audits: number }[]>`
    SELECT count(*)::integer AS audits
    FROM public.platform_audit_events
    WHERE action = 'platform.identity_provider.created'
  `;
  await Promise.all(
    malformedCases.map(async (malformed, index) => {
      await assert.rejects(
        createOidcProvider({
          commandId: uuid(2_000 + index * 2),
          providerId: uuid(2_001 + index * 2),
          key: malformed.key ?? `malformed_${index}`,
          displayName: malformed.displayName ?? `Malformed provider ${index}`,
          configuration: malformed.configuration ?? oidcConfiguration,
          keyDigest: digest(`malformed-key-${index}`),
          requestDigest: digest(`malformed-request-${index}`),
          ...(malformed.tenantRedirectUri === undefined
            ? {}
            : { tenantRedirectUri: malformed.tenantRedirectUri }),
          ...(malformed.description === undefined
            ? {}
            : { description: malformed.description }),
          ...(malformed.reason === undefined
            ? {}
            : { reason: malformed.reason }),
          ...(malformed.requestId === undefined
            ? {}
            : { requestId: malformed.requestId }),
          ...(malformed.correlationId === undefined
            ? {}
            : { correlationId: malformed.correlationId }),
          ...(malformed.userAgent === undefined
            ? {}
            : { userAgent: malformed.userAgent }),
        }),
        (error: unknown) => assertSqlState(error, "22023"),
        malformed.name,
      );
    }),
  );
  const [after] = await admin<
    { audits: number; providers: number; commands: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action = 'platform.identity_provider.created') AS audits,
      (SELECT count(*)::integer FROM public.platform_auth_providers
       WHERE key LIKE 'malformed_%') AS providers,
      (SELECT count(*)::integer FROM public.platform_identity_provider_commands
       WHERE id >= ${uuid(2_000)}::uuid AND id <= ${uuid(2_100)}::uuid) AS commands
  `;
  assert.equal(after?.audits, before?.audits);
  assert.equal(after?.providers, 0);
  assert.equal(after?.commands, 0);
}

async function createAndVerifyProviders(): Promise<void> {
  const oidcKeyDigest = digest("oidc-idempotency-key");
  const oidcRequestDigest = digest("oidc-request");
  const oidc = await createOidcProvider({
    commandId: fixture.oidcCommand,
    providerId: fixture.oidcProvider,
    key: "platform_oidc_runtime",
    displayName: "Platform OIDC runtime",
    configuration: oidcConfiguration,
    keyDigest: oidcKeyDigest,
    requestDigest: oidcRequestDigest,
  });
  assert.equal(oidc.provider_id, fixture.oidcProvider);
  assert.equal(oidc.version, 1);
  assert.equal(oidc.replayed, false);
  assert.equal(oidc.document.id, fixture.oidcProvider);
  assert.equal(oidc.document.version, 1);
  assertSafeProjection(oidc.document);
  const oidcReplay = await createOidcProvider({
    commandId: fixture.oidcReplayCommand,
    providerId: fixture.replayProvider,
    key: "platform_oidc_runtime",
    displayName: "Platform OIDC runtime",
    configuration: oidcConfiguration,
    keyDigest: oidcKeyDigest,
    requestDigest: oidcRequestDigest,
  });
  assert.deepEqual(oidcReplay, { ...oidc, replayed: true });
  await assert.rejects(
    createOidcProvider({
      commandId: fixture.oidcConflictCommand,
      providerId: fixture.conflictProvider,
      key: "platform_oidc_conflict",
      displayName: "Platform OIDC conflict",
      configuration: oidcConfiguration,
      keyDigest: oidcKeyDigest,
      requestDigest: digest("oidc-conflicting-request"),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  const saml = await seedSamlProviderFixture();
  assert.equal(saml.id, fixture.samlProvider);
  assert.equal(saml.version, 1);
  assertSafeProjection(saml);
  await assert.rejects(
    createOidcProvider({
      commandId: fixture.wrongSubtypeCommand,
      providerId: fixture.replayProvider,
      key: "wrong_subtype",
      displayName: "Wrong subtype",
      configuration: samlConfiguration,
      keyDigest: digest("wrong-subtype-key"),
      requestDigest: digest("wrong-subtype-request"),
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const subtypeRows = await admin<
    {
      id: string;
      kind: ProviderKind;
      enabled: boolean;
      policyEnabled: boolean;
      platformLoginEnabled: boolean;
      oidcConfiguration: boolean;
      samlConfiguration: boolean;
    }[]
  >`
    SELECT provider.id, provider.kind, provider.enabled,
           policy.enabled AS "policyEnabled",
           policy.platform_login_enabled AS "platformLoginEnabled",
           oidc.provider_id IS NOT NULL AS "oidcConfiguration",
           saml.provider_id IS NOT NULL AS "samlConfiguration"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id
    LEFT JOIN public.platform_oidc_provider_configurations AS oidc
      ON oidc.provider_id = provider.id
    LEFT JOIN public.platform_saml_provider_configurations AS saml
      ON saml.provider_id = provider.id
    WHERE provider.id IN (
      ${fixture.oidcProvider}::uuid, ${fixture.samlProvider}::uuid
    )
    ORDER BY provider.id
  `;
  assert.deepEqual(Array.from(subtypeRows), [
    {
      id: fixture.oidcProvider,
      kind: "oidc",
      enabled: false,
      policyEnabled: false,
      platformLoginEnabled: false,
      oidcConfiguration: true,
      samlConfiguration: false,
    },
    {
      id: fixture.samlProvider,
      kind: "saml",
      enabled: false,
      policyEnabled: false,
      platformLoginEnabled: false,
      oidcConfiguration: false,
      samlConfiguration: true,
    },
  ]);
  await assert.rejects(
    admin`
      INSERT INTO public.platform_oidc_claim_rules (
        provider_id, source, sequence, kind, claim_name, profile_field, required
      ) VALUES (
        ${fixture.oidcProvider}::uuid, 'id_token', 999, 'profile',
        'email', NULL, true
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      INSERT INTO public.platform_saml_attribute_rules (
        provider_id, sequence, kind, attribute_name, attribute_name_format,
        profile_field, required
      ) VALUES (
        ${fixture.samlProvider}::uuid, 999, 'profile',
        'urn:oid:0.9.2342.19200300.100.1.3',
        'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', NULL, true
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      UPDATE public.platform_saml_provider_configurations
      SET subject_source = 'immutable_attribute',
          subject_attribute_name = NULL,
          subject_attribute_name_format = NULL
      WHERE provider_id = ${fixture.samlProvider}::uuid
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      INSERT INTO public.platform_oidc_discovery_snapshots (
        provider_id, revision, issuer, document, document_digest,
        retrieved_at, fresh_until, cacheable, must_revalidate,
        client_authentication, signing_algorithms
      ) VALUES (
        ${fixture.oidcProvider}::uuid, 1,
        ${oidcConfiguration.issuer}, decode('7b7d', 'hex'),
        ${digest("nullable-discovery-document")}::bytea,
        transaction_timestamp(), transaction_timestamp(), false, true,
        'client_secret_basic', ARRAY[NULL]::text[]
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      INSERT INTO public.platform_federated_trust_rules (
        id, provider_id, provider_kind, revision, enabled, level,
        exact_value, required_values, maximum_authentication_age_seconds
      ) VALUES (
        ${uuid(6_100)}::uuid, ${fixture.oidcProvider}::uuid, 'oidc', 1,
        false, 'mfa', NULL, ARRAY[NULL]::text[], 3600
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  const [nullableConstraintState] = await admin<
    {
      oidcRules: number;
      samlRules: number;
      discoverySnapshots: number;
      trustRules: number;
      subjectSource: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.platform_oidc_claim_rules
       WHERE provider_id = ${fixture.oidcProvider}::uuid) AS "oidcRules",
      (SELECT count(*)::integer
       FROM public.platform_saml_attribute_rules
       WHERE provider_id = ${fixture.samlProvider}::uuid) AS "samlRules",
      (SELECT count(*)::integer
       FROM public.platform_oidc_discovery_snapshots
       WHERE provider_id = ${fixture.oidcProvider}::uuid) AS "discoverySnapshots",
      (SELECT count(*)::integer
       FROM public.platform_federated_trust_rules
       WHERE provider_id = ${fixture.oidcProvider}::uuid) AS "trustRules",
      (SELECT subject_source
       FROM public.platform_saml_provider_configurations
       WHERE provider_id = ${fixture.samlProvider}::uuid) AS "subjectSource"
  `;
  assert.deepEqual(nullableConstraintState, {
    oidcRules: 0,
    samlRules: 0,
    discoverySnapshots: 0,
    trustRules: 0,
    subjectSource: "persistent_nameid",
  });
  await assert.rejects(
    admin`
      INSERT INTO public.platform_identity_provider_test_runs (
        id, provider_id, actor_user_id, provider_version,
        configuration_revision, kind, status, correlation_id
      ) VALUES (
        ${uuid(5_000)}::uuid, ${fixture.oidcProvider}::uuid,
        ${fixture.operator}::uuid, 1, 1, 'configuration', 'completed',
        ${uuid(5_001)}::uuid
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      INSERT INTO public.platform_identity_provider_test_runs (
        id, provider_id, actor_user_id, provider_version,
        configuration_revision, kind, status, outcome, category,
        correlation_id, completed_at
      ) VALUES (
        ${uuid(5_002)}::uuid, ${fixture.oidcProvider}::uuid,
        ${fixture.operator}::uuid, 1, 1, 'connection', 'completed',
        'success', 'tls_failed', ${uuid(5_003)}::uuid,
        transaction_timestamp()
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  const [malformedTestRuns] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_identity_provider_test_runs
    WHERE id IN (${uuid(5_000)}::uuid, ${uuid(5_002)}::uuid)
  `;
  assert.equal(malformedTestRuns?.count, 0);
  const createAudits = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_audit_events
    WHERE action = 'platform.identity_provider.created'
  `;
  assert.equal(
    createAudits[0]?.count,
    1,
    "the OIDC replay must not append an audit",
  );

  const listed = await listProviders();
  assert.equal(listed.length, 2);
  for (const document of listed) {
    assertSafeProjection(document);
    assert.equal(document.enabled, false);
    assert.equal(document.platformLoginEnabled, false);
    assert.equal(document.secretPresent, false);
  }
  const oidcDocument = await getProvider(fixture.oidcProvider);
  const samlDocument = await getProvider(fixture.samlProvider);
  assertSafeProjection(oidcDocument);
  assertSafeProjection(samlDocument);
  assert(isObject(oidcDocument.configuration));
  assert.equal(oidcDocument.configuration.clientSecretPresent, false);
  assert(isObject(samlDocument.configuration));
  assert.equal(samlDocument.configuration.spKeyPresent, false);
  assert.equal(
    Object.hasOwn(samlDocument.configuration, "subjectAttributeName"),
    false,
  );
  assert.equal(
    Object.hasOwn(samlDocument.configuration, "subjectAttributeNameFormat"),
    false,
  );

  try {
    await admin`
      INSERT INTO public.platform_oidc_client_secrets (
        id, provider_id, revision, key_version, nonce, ciphertext
      ) VALUES (
        ${uuid(6_199)}::uuid, ${fixture.oidcProvider}::uuid, 1,
        ${keyVersion}, decode(repeat('ab', 12), 'hex'),
        decode(repeat('cd', 17), 'hex')
      )
    `;
    const [tampered] = await admin<{ compatible: boolean }[]>`
      SELECT NOT EXISTS (
        SELECT 1
        FROM ONLY public.platform_oidc_provider_configurations AS configuration
        JOIN ONLY public.platform_oidc_client_secrets AS secret
          ON secret.provider_id = configuration.provider_id
        WHERE configuration.provider_id = ${fixture.oidcProvider}::uuid
          AND configuration.client_secret_revision = 1
          AND secret.revision = 1
          AND secret.retired_at IS NULL
      ) AS compatible
    `;
    assert.equal(
      tampered?.compatible,
      false,
      "direct invariant accepted an impossible revision-1 live OIDC secret",
    );
  } finally {
    await admin`
      DELETE FROM public.platform_oidc_client_secrets
      WHERE id = ${uuid(6_199)}::uuid
    `;
  }
  const [oidcSecretStateRestored] = await admin<{ compatible: boolean }[]>`
    SELECT NOT EXISTS (
      SELECT 1
      FROM ONLY public.platform_oidc_provider_configurations AS configuration
      JOIN ONLY public.platform_oidc_client_secrets AS secret
        ON secret.provider_id = configuration.provider_id
      WHERE configuration.provider_id = ${fixture.oidcProvider}::uuid
        AND configuration.client_secret_revision = 1
        AND secret.revision = 1
        AND secret.retired_at IS NULL
    ) AS compatible
  `;
  assert.equal(oidcSecretStateRestored?.compatible, true);

  try {
    await admin`
      INSERT INTO public.platform_saml_sp_keys (
        id, provider_id, revision, key_version, nonce, ciphertext
      ) VALUES (
        ${uuid(6_200)}::uuid, ${fixture.samlProvider}::uuid, 1,
        ${keyVersion}, decode(repeat('bc', 12), 'hex'),
        decode(repeat('ab', 17), 'hex')
      )
    `;
    const [tampered] = await admin<{ compatible: boolean }[]>`
      SELECT NOT EXISTS (
        SELECT 1
        FROM ONLY public.platform_saml_sp_keys AS sp_key
        WHERE sp_key.retired_at IS NULL
      ) AS compatible
    `;
    assert.equal(
      tampered?.compatible,
      false,
      "direct invariant accepted a live SAML SP key before the SP-key lifecycle exists",
    );
  } finally {
    await admin`
      DELETE FROM public.platform_saml_sp_keys
      WHERE id = ${uuid(6_200)}::uuid
    `;
  }
  const [samlKeyStateRestored] = await admin<{ compatible: boolean }[]>`
    SELECT NOT EXISTS (
      SELECT 1
      FROM ONLY public.platform_saml_sp_keys AS sp_key
      WHERE sp_key.retired_at IS NULL
    ) AS compatible
  `;
  assert.equal(samlKeyStateRestored?.compatible, true);

  try {
    await admin`
      UPDATE public.platform_federated_provider_policies
      SET account_mode = 'existing_identity'
      WHERE provider_id = ${fixture.oidcProvider}::uuid
    `;
    const [allowed] = await admin<
      { accountMode: string; platformLoginEnabled: boolean; ready: boolean }[]
    >`
      SELECT policy.account_mode AS "accountMode",
             policy.platform_login_enabled AS "platformLoginEnabled",
             app.release_runtime_schema_readiness_v50() AS ready
      FROM public.platform_federated_provider_policies AS policy
      WHERE policy.provider_id = ${fixture.oidcProvider}::uuid
    `;
    assert.deepEqual(allowed, {
      accountMode: "existing_identity",
      platformLoginEnabled: false,
      ready: true,
    });

    await assert.rejects(
      admin`
        UPDATE public.platform_federated_provider_policies
        SET enabled = true, platform_login_enabled = true
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `,
      (error: unknown) => assertSqlState(error, "23514"),
    );
    const [platformLoginRejected] = await admin<
      { platformLoginEnabled: boolean; ready: boolean }[]
    >`
      SELECT policy.platform_login_enabled AS "platformLoginEnabled",
             app.release_runtime_schema_readiness_v50() AS ready
      FROM public.platform_federated_provider_policies AS policy
      WHERE policy.provider_id = ${fixture.oidcProvider}::uuid
    `;
    assert.deepEqual(platformLoginRejected, {
      platformLoginEnabled: false,
      ready: true,
    });
  } finally {
    await admin`
      UPDATE public.platform_federated_provider_policies
      SET enabled = false, platform_login_enabled = false,
          account_mode = 'disabled'
      WHERE provider_id = ${fixture.oidcProvider}::uuid
    `;
  }
  const [accountModeRestored] = await admin<
    { accountMode: string; platformLoginEnabled: boolean; ready: boolean }[]
  >`
    SELECT policy.account_mode AS "accountMode",
           policy.platform_login_enabled AS "platformLoginEnabled",
           app.release_runtime_schema_readiness_v50() AS ready
    FROM public.platform_federated_provider_policies AS policy
    WHERE policy.provider_id = ${fixture.oidcProvider}::uuid
  `;
  assert.deepEqual(accountModeRestored, {
    accountMode: "disabled",
    platformLoginEnabled: false,
    ready: true,
  });
}

async function verifySemanticProjectionBoundaries(): Promise<void> {
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a provider version outside the Go projection range",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_auth_providers
        DROP CONSTRAINT platform_auth_providers_lifecycle_check
      `;
      await transaction`
        UPDATE ONLY public.platform_auth_providers
        SET version = 2147483648
        WHERE id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "an infinite provider timestamp",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_auth_providers
        DROP CONSTRAINT platform_auth_providers_lifecycle_check
      `;
      await transaction`
        UPDATE ONLY public.platform_auth_providers
        SET updated_at = 'infinity'::timestamptz
        WHERE id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a noncanonical provider display name",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_auth_providers
        DROP CONSTRAINT platform_auth_providers_display_name_check
      `;
      await transaction`
        UPDATE ONLY public.platform_auth_providers
        SET display_name = ' Platform OIDC runtime'
        WHERE id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a persisted revision outside JSON's exact-integer range",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_oidc_provider_configurations
        DROP CONSTRAINT platform_oidc_provider_configurations_revision_check
      `;
      await transaction`
        UPDATE ONLY public.platform_oidc_provider_configurations
        SET version = 9007199254740992
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a non-unit idempotency result version",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_identity_provider_commands
        DROP CONSTRAINT platform_identity_provider_commands_result_check
      `;
      await transaction`
        UPDATE ONLY public.platform_identity_provider_commands
        SET result_version = 2
        WHERE id = ${fixture.oidcCommand}::uuid
      `;
    },
  );

  await assertReadinessRejectsTransactionalCatalogMutation(
    "an HTTP OIDC issuer",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_oidc_provider_configurations
        DROP CONSTRAINT platform_oidc_provider_configurations_text_check
      `;
      await transaction`
        UPDATE ONLY public.platform_oidc_provider_configurations
        SET issuer = 'http://platform-idp.example.invalid'
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "duplicate and non-C-sorted OIDC scopes",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_oidc_provider_configurations
        DROP CONSTRAINT platform_oidc_provider_configurations_scope_check
      `;
      await transaction`
        ALTER TABLE public.platform_oidc_provider_configurations
        DROP CONSTRAINT platform_oidc_provider_configurations_canonical_v1_check
      `;
      await transaction`
        UPDATE ONLY public.platform_oidc_provider_configurations
        SET extra_scopes = ARRAY['zeta', 'alpha', 'alpha']::text[]
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "a noncanonical SAML SP URI",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_saml_provider_configurations
        DROP CONSTRAINT platform_saml_provider_configurations_text_check
      `;
      await transaction`
        UPDATE ONLY public.platform_saml_provider_configurations
        SET sp_entity_id = 'http://periapsis.example.invalid/saml/metadata'
        WHERE provider_id = ${fixture.samlProvider}::uuid
      `;
    },
  );
  await assertReadinessRejectsTransactionalCatalogMutation(
    "duplicate SAML authentication contexts",
    async (transaction) => {
      await transaction`
        ALTER TABLE public.platform_saml_provider_configurations
        DROP CONSTRAINT platform_saml_provider_configurations_policy_check
      `;
      await transaction`
        UPDATE ONLY public.platform_saml_provider_configurations
        SET requested_authn_contexts = ARRAY[
          'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
          'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        ]::text[]
        WHERE provider_id = ${fixture.samlProvider}::uuid
      `;
    },
  );
}

async function verifyExpiryReuseAndBoundedCleanup(): Promise<void> {
  const createdAt = new Date(Date.now() - 3 * 24 * 60 * 60_000);
  const expiresAt = new Date(Date.now() - 2 * 24 * 60 * 60_000);
  const cleanupRows = Array.from({ length: 70 }, (_, index) => ({
    id: uuid(3_000 + index),
    keyDigest: digest(`cleanup-key-${index}`).toString("hex"),
    requestDigest: digest(`cleanup-request-${index}`).toString("hex"),
  }));
  await admin.begin(async (transaction) => {
    await transaction`
      UPDATE public.platform_identity_provider_commands
      SET created_at = ${new Date(Date.now() - 2 * 24 * 60 * 60_000)},
          expires_at = ${new Date(Date.now() - 24 * 60 * 60_000)}
      WHERE actor_user_id = ${fixture.operator}::uuid
        AND operation = 'provider.create'
        AND key_digest = ${digest("oidc-idempotency-key")}::bytea
    `;
    await transaction`
      INSERT INTO public.platform_identity_provider_commands (
        id, actor_user_id, operation, key_digest, request_digest,
        result_provider_id, result_version, created_at, expires_at
      )
      SELECT input.id::uuid, ${fixture.operator}::uuid, 'provider.create',
             decode(input.key_digest, 'hex'), decode(input.request_digest, 'hex'),
             ${fixture.oidcProvider}::uuid, 1, ${createdAt}, ${expiresAt}
      FROM unnest(
        ${cleanupRows.map((row) => row.id)}::text[],
        ${cleanupRows.map((row) => row.keyDigest)}::text[],
        ${cleanupRows.map((row) => row.requestDigest)}::text[]
      ) AS input(id, key_digest, request_digest)
    `;
  });

  const expiryKeyDigest = digest("oidc-idempotency-key");
  const expiryRequestDigest = digest("expired-key-reused-for-oidc");
  const created = await createOidcProvider({
    commandId: fixture.expiryCommand,
    providerId: fixture.expiryProvider,
    key: "platform_expiry_reuse",
    displayName: "Platform expiry reuse",
    configuration: oidcConfiguration,
    keyDigest: expiryKeyDigest,
    requestDigest: expiryRequestDigest,
  });
  assert.equal(created.replayed, false);
  assert.equal(created.provider_id, fixture.expiryProvider);
  assert.equal(created.document.kind, "oidc");
  assertSafeProjection(created.document);

  const [afterFirstCleanup] = await admin<
    { expired: number; activeKeyRows: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.platform_identity_provider_commands
       WHERE expires_at <= transaction_timestamp()) AS expired,
      (SELECT count(*)::integer
       FROM public.platform_identity_provider_commands
       WHERE actor_user_id = ${fixture.operator}::uuid
         AND operation = 'provider.create'
         AND key_digest = ${expiryKeyDigest}::bytea
         AND expires_at > transaction_timestamp()) AS "activeKeyRows"
  `;
  assert.deepEqual(afterFirstCleanup, { expired: 6, activeKeyRows: 1 });

  const replay = await createOidcProvider({
    commandId: fixture.expiryReplayCommand,
    providerId: uuid(47),
    key: "platform_expiry_reuse",
    displayName: "Platform expiry reuse",
    configuration: oidcConfiguration,
    keyDigest: expiryKeyDigest,
    requestDigest: expiryRequestDigest,
  });
  assert.deepEqual(replay, { ...created, replayed: true });
  const [afterSecondCleanup] = await admin<
    { expired: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.platform_identity_provider_commands
       WHERE expires_at <= transaction_timestamp()) AS expired,
      (SELECT count(*)::integer
       FROM public.platform_audit_events
       WHERE resource_id = ${fixture.expiryProvider}::uuid
         AND action = 'platform.identity_provider.created') AS audits
  `;
  assert.deepEqual(afterSecondCleanup, { expired: 0, audits: 1 });
}

async function verifyTenantAuthoritySerialization(): Promise<void> {
  const membershipClient = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  const membershipProviderClient = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  const releaseMembership = deferred<void>();
  const membershipChanged = deferred<number>();
  try {
    const trace = envelope();
    const membershipTask = asRole(
      membershipClient,
      "periapsis_api",
      async (transaction) => {
        const [backend] = await transaction<{ pid: number }[]>`
          SELECT pg_catalog.pg_backend_pid() AS pid
        `;
        assert(backend);
        const [changed] = await transaction<{ membershipId: string }[]>`
          SELECT membership_id AS "membershipId"
          FROM app.change_tenant_membership_lifecycle_v1(
            ${fixture.tenantSession}::uuid, ${fixture.tenantOperator}::uuid,
            'suspended'::public.membership_status, 1,
            'Suspend membership for the provider serialization proof.',
            ${digest("tenant-membership-suspension")}::bytea,
            ${trace.auditId}::uuid, ${trace.requestId}::uuid,
            ${trace.correlationId}::uuid, '198.51.100.42'::inet,
            'Periapsis platform identity-provider runtime proof'::text,
            'totp'::text
          )
        `;
        assert.equal(changed?.membershipId, fixture.tenantOperatorMembership);
        membershipChanged.resolve(backend.pid);
        await releaseMembership.promise;
      },
      fixture.operator,
      fixture.tenant,
    );
    const membershipPid = await membershipChanged.promise;

    const providerStarted = deferred<number>();
    const providerTask = updateTenantScopedSamlProvider(
      membershipProviderClient,
      1,
      "membership race",
      providerStarted.resolve,
    );
    const providerRejected = assert.rejects(providerTask, (error: unknown) =>
      assertSqlState(error, "42501"),
    );
    const providerPid = await providerStarted.promise;
    await waitForDatabaseBlocker(
      providerPid,
      membershipPid,
      "provider mutation behind membership suspension",
    );
    releaseMembership.resolve(undefined);
    await membershipTask;
    await providerRejected;

    const [unchanged] = await admin<{ version: number; audits: number }[]>`
      SELECT provider.version::integer AS version,
             (SELECT count(*)::integer
              FROM public.platform_audit_events AS audit
              WHERE audit.resource_id = provider.id
                AND audit.action = 'platform.identity_provider.updated') AS audits
      FROM public.platform_auth_providers AS provider
      WHERE provider.id = ${fixture.samlProvider}::uuid
    `;
    assert.deepEqual(unchanged, { version: 1, audits: 0 });
  } finally {
    releaseMembership.resolve(undefined);
    await Promise.all([membershipClient.end(), membershipProviderClient.end()]);
    await admin.begin(async (transaction) => {
      await transaction`
        SELECT authorization_state.revision
        FROM public.tenant_authorization_states AS authorization_state
        WHERE authorization_state.tenant_id = ${fixture.tenant}::uuid
        FOR UPDATE
      `;
      await transaction`
        UPDATE public.tenant_memberships
        SET status = 'active', updated_at = transaction_timestamp()
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND user_id = ${fixture.tenantOperator}::uuid
      `;
      await transaction`
        INSERT INTO public.auth_sessions (
          id,user_id,rotation_family_id,active_tenant_id,token_digest,
          csrf_secret_digest,authentication_method,mfa_satisfied_at,
          last_seen_at,idle_expires_at,absolute_expires_at,created_at
        ) VALUES (
          ${fixture.resumedTenantOperatorSession}::uuid,
          ${fixture.tenantOperator}::uuid,
          ${fixture.resumedTenantOperatorFamily}::uuid,${fixture.tenant}::uuid,
          ${digest("resumed-tenant-session-token")}::bytea,
          ${digest("resumed-tenant-session-csrf")}::bytea,'totp',
          transaction_timestamp(),transaction_timestamp(),
          date_trunc('milliseconds',transaction_timestamp() + interval '1 hour'),
          date_trunc('milliseconds',transaction_timestamp() + interval '1 hour'),
          transaction_timestamp()
        )
      `;
    });
  }

  const lockClient = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  const tenantProviderClient = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  const lifecycleClient = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  const releaseProviderRow = deferred<void>();
  const providerRowLocked = deferred<number>();
  try {
    const blockerTask = lockClient.begin(async (transaction) => {
      const [backend] = await transaction<{ pid: number }[]>`
        SELECT pg_catalog.pg_backend_pid() AS pid
      `;
      assert(backend);
      await transaction`
        SELECT provider.id
        FROM public.platform_auth_providers AS provider
        WHERE provider.id = ${fixture.samlProvider}::uuid
        FOR UPDATE
      `;
      providerRowLocked.resolve(backend.pid);
      await releaseProviderRow.promise;
    });
    const blockerPid = await providerRowLocked.promise;

    const providerStarted = deferred<number>();
    const providerTask = updateTenantScopedSamlProvider(
      tenantProviderClient,
      1,
      "tenant race",
      providerStarted.resolve,
      fixture.resumedTenantOperatorSession,
    );
    const providerPid = await providerStarted.promise;
    await waitForDatabaseBlocker(
      providerPid,
      blockerPid,
      "provider mutation behind provider row lock",
    );

    const lifecycleStarted = deferred<number>();
    const lifecycleTask = changeRuntimeTenantLifecycle(
      lifecycleClient,
      "suspended",
      1,
      lifecycleStarted.resolve,
    );
    const lifecyclePid = await lifecycleStarted.promise;
    await waitForDatabaseBlocker(
      lifecyclePid,
      providerPid,
      "tenant suspension behind provider authorization fence",
    );

    releaseProviderRow.resolve(undefined);
    const updated = await providerTask;
    assert.equal(updated.version, 2);
    assert.equal(await lifecycleTask, 2);
    await blockerTask;

    await assert.rejects(
      updateTenantScopedSamlProvider(admin, 2, "after tenant suspension"),
      (error: unknown) => assertSqlState(error, "42501"),
    );
    assert.equal(await changeRuntimeTenantLifecycle(admin, "active", 2), 3);
  } finally {
    releaseProviderRow.resolve(undefined);
    await Promise.all([
      lockClient.end(),
      tenantProviderClient.end(),
      lifecycleClient.end(),
    ]);
  }
}

async function verifyCasSecretAndArchive(): Promise<void> {
  const [beforeReadDeniedUpdate] = await admin<
    { version: number; auditCount: number }[]
  >`
    SELECT provider.version::integer AS version,
           (SELECT count(*)::integer
            FROM public.platform_audit_events AS audit
            WHERE audit.resource_id = provider.id
              AND audit.action = 'platform.identity_provider.updated') AS "auditCount"
    FROM public.platform_auth_providers AS provider
    WHERE provider.id = ${fixture.oidcProvider}::uuid
  `;
  await withoutPlatformProviderReadGrant(async () => {
    await assert.rejects(updateOidcProvider(1), (error: unknown) =>
      assertSqlState(error, "42501"),
    );
  });
  const [afterReadDeniedUpdate] = await admin<
    { version: number; auditCount: number }[]
  >`
    SELECT provider.version::integer AS version,
           (SELECT count(*)::integer
            FROM public.platform_audit_events AS audit
            WHERE audit.resource_id = provider.id
              AND audit.action = 'platform.identity_provider.updated') AS "auditCount"
    FROM public.platform_auth_providers AS provider
    WHERE provider.id = ${fixture.oidcProvider}::uuid
  `;
  assert.deepEqual(
    afterReadDeniedUpdate,
    beforeReadDeniedUpdate,
    "read-denied update changed provider state or audit",
  );

  const update = await updateOidcProvider(1);
  assert.equal(update.version, 2);
  assert.equal(update.document.id, fixture.oidcProvider);
  assert.equal(update.document.version, 2);
  assert.equal(update.document.displayName, "Platform OIDC runtime updated");
  assertSafeProjection(update.document);

  const updatedReplay = await createOidcProvider({
    commandId: uuid(6_000),
    providerId: uuid(6_001),
    key: "platform_oidc_runtime",
    displayName: "Platform OIDC runtime",
    configuration: oidcConfiguration,
    keyDigest: digest("oidc-idempotency-key"),
    requestDigest: digest("oidc-request"),
  });
  assert.equal(updatedReplay.provider_id, fixture.oidcProvider);
  assert.equal(
    updatedReplay.version,
    1,
    "create replay must preserve the stable receipt version",
  );
  assert.equal(updatedReplay.replayed, true);
  assert.equal(
    updatedReplay.document.version,
    2,
    "create replay must project current provider state under the ABI lock",
  );
  assert.equal(
    updatedReplay.document.displayName,
    "Platform OIDC runtime updated",
  );
  assertSafeProjection(updatedReplay.document);
  const [updatedReplayAudits] = await admin<
    { creates: number; updates: number }[]
  >`
    SELECT
      count(*) FILTER (
        WHERE action = 'platform.identity_provider.created'
      )::integer AS creates,
      count(*) FILTER (
        WHERE action = 'platform.identity_provider.updated'
      )::integer AS updates
    FROM public.platform_audit_events
    WHERE resource_id = ${fixture.oidcProvider}::uuid
  `;
  assert.deepEqual(updatedReplayAudits, { creates: 1, updates: 1 });
  await assert.rejects(updateOidcProvider(1), (error: unknown) =>
    assertSqlState(error, "40001"),
  );
  await assert.rejects(updateOidcProvider(2_147_483_647), (error: unknown) =>
    assertSqlState(error, "22023"),
  );
  await assert.rejects(
    rotateOidcSecret(1, uuid(6_200), keyVersion, fixture.samlProvider),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    rotateOidcSecret(2, uuid(6_200), keyVersion, fixture.samlProvider),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const [beforeInactiveKeyRotation] = await admin<
    {
      version: number;
      secretRevision: number;
      activeSecrets: number;
      auditCount: number;
    }[]
  >`
    SELECT provider.version::integer AS version,
           configuration.client_secret_revision::integer AS "secretRevision",
           (SELECT count(*)::integer
            FROM public.platform_oidc_client_secrets AS secret
            WHERE secret.provider_id = provider.id
              AND secret.retired_at IS NULL) AS "activeSecrets",
           (SELECT count(*)::integer
            FROM public.platform_audit_events AS audit
            WHERE audit.resource_id = provider.id
              AND audit.action = 'platform.identity_provider.oidc_secret_replaced')
             AS "auditCount"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
    WHERE provider.id = ${fixture.oidcProvider}::uuid
  `;
  await assert.rejects(
    rotateOidcSecret(2, fixture.staleSecret, inactiveKeyVersion),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  const [afterInactiveKeyRotation] = await admin<
    {
      version: number;
      secretRevision: number;
      activeSecrets: number;
      auditCount: number;
    }[]
  >`
    SELECT provider.version::integer AS version,
           configuration.client_secret_revision::integer AS "secretRevision",
           (SELECT count(*)::integer
            FROM public.platform_oidc_client_secrets AS secret
            WHERE secret.provider_id = provider.id
              AND secret.retired_at IS NULL) AS "activeSecrets",
           (SELECT count(*)::integer
            FROM public.platform_audit_events AS audit
            WHERE audit.resource_id = provider.id
              AND audit.action = 'platform.identity_provider.oidc_secret_replaced')
             AS "auditCount"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
    WHERE provider.id = ${fixture.oidcProvider}::uuid
  `;
  assert.deepEqual(
    afterInactiveKeyRotation,
    beforeInactiveKeyRotation,
    "inactive key rotation changed provider state or audit",
  );

  type OidcMutationState = {
    version: number;
    configurationVersion: string;
    secretRevision: string;
    configurationRevision: string;
    securityRevision: string;
    activeSecrets: number;
    auditCount: number;
  };
  const readOidcMutationState = async (): Promise<OidcMutationState> => {
    const [state] = await admin<OidcMutationState[]>`
      SELECT provider.version::integer AS version,
             configuration.version::text AS "configurationVersion",
             configuration.client_secret_revision::text AS "secretRevision",
             policy.configuration_revision::text AS "configurationRevision",
             policy.security_revision::text AS "securityRevision",
             (SELECT count(*)::integer
              FROM public.platform_oidc_client_secrets AS secret
              WHERE secret.provider_id = provider.id
                AND secret.retired_at IS NULL) AS "activeSecrets",
             (SELECT count(*)::integer
              FROM public.platform_audit_events AS audit
              WHERE audit.resource_id = provider.id
                AND audit.action = 'platform.identity_provider.oidc_secret_replaced')
               AS "auditCount"
      FROM public.platform_auth_providers AS provider
      JOIN public.platform_oidc_provider_configurations AS configuration
        ON configuration.provider_id = provider.id
      JOIN public.platform_federated_provider_policies AS policy
        ON policy.provider_id = provider.id
      WHERE provider.id = ${fixture.oidcProvider}::uuid
    `;
    assert(state, "OIDC mutation state is unavailable");
    return state;
  };
  const baselineOidcMutationState = await readOidcMutationState();
  const maximumSafeRevision = "9007199254740991";
  const verifySaturatedSecretRevision = async (
    name: string,
    secretId: string,
    saturate: () => Promise<void>,
    restore: () => Promise<void>,
  ): Promise<void> => {
    await saturate();
    const saturatedState = await readOidcMutationState();
    try {
      await assert.rejects(rotateOidcSecret(2, secretId), (error: unknown) =>
        assertSqlState(error, "55000"),
      );
      assert.deepEqual(
        await readOidcMutationState(),
        saturatedState,
        `${name} saturation allowed a partial secret mutation or audit`,
      );
    } finally {
      await restore();
    }
    assert.deepEqual(
      await readOidcMutationState(),
      baselineOidcMutationState,
      `${name} saturation fixture did not restore cleanly`,
    );
  };

  await verifySaturatedSecretRevision(
    "client-secret revision",
    uuid(6_210),
    async () => {
      await admin`
        UPDATE public.platform_oidc_provider_configurations
        SET client_secret_revision = ${maximumSafeRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
    async () => {
      await admin`
        UPDATE public.platform_oidc_provider_configurations
        SET client_secret_revision = ${baselineOidcMutationState.secretRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await verifySaturatedSecretRevision(
    "configuration row revision",
    uuid(6_211),
    async () => {
      await admin`
        UPDATE public.platform_oidc_provider_configurations
        SET version = ${maximumSafeRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
    async () => {
      await admin`
        UPDATE public.platform_oidc_provider_configurations
        SET version = ${baselineOidcMutationState.configurationVersion}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await verifySaturatedSecretRevision(
    "policy configuration revision",
    uuid(6_212),
    async () => {
      await admin`
        UPDATE public.platform_federated_provider_policies
        SET configuration_revision = ${maximumSafeRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
    async () => {
      await admin`
        UPDATE public.platform_federated_provider_policies
        SET configuration_revision = ${baselineOidcMutationState.configurationRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );
  await verifySaturatedSecretRevision(
    "policy security revision",
    uuid(6_213),
    async () => {
      await admin`
        UPDATE public.platform_federated_provider_policies
        SET security_revision = ${maximumSafeRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
    async () => {
      await admin`
        UPDATE public.platform_federated_provider_policies
        SET security_revision = ${baselineOidcMutationState.securityRevision}::bigint
        WHERE provider_id = ${fixture.oidcProvider}::uuid
      `;
    },
  );

  const rotation = await rotateOidcSecret(2, fixture.secret);
  assert.deepEqual(rotation, { version: 3, secretRevision: 2 });
  await assert.rejects(
    rotateOidcSecret(2, fixture.staleSecret),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const [storedSecret] = await admin<
    { count: number; ciphertextMatches: boolean; nonceBytes: number }[]
  >`
    SELECT count(*)::integer AS count,
           bool_and(ciphertext = ${secretCiphertext}::bytea) AS "ciphertextMatches",
           min(octet_length(nonce))::integer AS "nonceBytes"
    FROM public.platform_oidc_client_secrets
    WHERE provider_id = ${fixture.oidcProvider}::uuid
      AND retired_at IS NULL
  `;
  assert.deepEqual(storedSecret, {
    count: 1,
    ciphertextMatches: true,
    nonceBytes: 12,
  });

  await admin.begin(async (transaction) => {
    await transaction`
      UPDATE public.identity_keyring_versions
      SET is_active = false
      WHERE key_version = ${keyVersion}
    `;
    await transaction`
      UPDATE public.identity_keyring_versions
      SET is_active = true
      WHERE key_version = ${inactiveKeyVersion}
    `;
  });
  try {
    const [omittedLiveKey] = await asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction<{ verified: boolean }[]>`
          SELECT app.verify_identity_keyring_v3(
            ARRAY[${inactiveKeyVersion}]::integer[],
            ARRAY[${digest("inactive-keyring-verifier")}::bytea]::bytea[],
            ${inactiveKeyVersion}::integer
          ) AS verified
        `,
      fixture.operator,
    );
    assert.equal(
      omittedLiveKey?.verified,
      false,
      "keyring readiness omitted a live platform OIDC envelope key",
    );
    const [completeInventory] = await asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction<{ verified: boolean }[]>`
          SELECT app.verify_identity_keyring_v3(
            ARRAY[${inactiveKeyVersion}, ${keyVersion}]::integer[],
            ARRAY[
              ${digest("inactive-keyring-verifier")}::bytea,
              ${digest("keyring-verifier")}::bytea
            ]::bytea[],
            ${inactiveKeyVersion}::integer
          ) AS verified
        `,
      fixture.operator,
    );
    assert.equal(completeInventory?.verified, true);
  } finally {
    await admin.begin(async (transaction) => {
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = false
        WHERE key_version = ${inactiveKeyVersion}
      `;
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = true
        WHERE key_version = ${keyVersion}
      `;
    });
  }

  const projections = [
    ...(await listProviders()),
    await getProvider(fixture.oidcProvider),
  ];
  for (const document of projections) {
    assertSafeProjection(document);
  }
  const oidcListDocument = projections.find(
    (document) => document.id === fixture.oidcProvider,
  );
  assert(oidcListDocument);
  assert.equal(oidcListDocument.secretPresent, true);
  const oidcGetDocument = projections.at(-1);
  assert(oidcGetDocument);
  assert(isObject(oidcGetDocument.configuration));
  assert.equal(oidcGetDocument.configuration.clientSecretPresent, true);

  const auditRows = await admin<
    { action: string; reason: string | null; metadata: JsonObject }[]
  >`
    SELECT action, reason, metadata
    FROM public.platform_audit_events
    WHERE resource_id = ${fixture.oidcProvider}::uuid
    ORDER BY sequence
  `;
  const serializedAudit = JSON.stringify(auditRows);
  assert(!serializedAudit.includes(secretCiphertext.toString("utf8")));
  assert(!serializedAudit.includes(secretCiphertext.toString("hex")));
  const secretAudit = auditRows.find(
    (row) => row.action === "platform.identity_provider.oidc_secret_replaced",
  );
  assert(secretAudit);
  assert.deepEqual(secretAudit.metadata, {
    kind: "oidc",
    previous_version: 2,
    version: 3,
    secret_version: 2,
    secret_material_included: true,
    platform_login_enabled: false,
  });

  await admin`
    UPDATE public.platform_auth_providers
    SET enabled = true
    WHERE id = ${fixture.oidcProvider}::uuid
  `;
  await assert.rejects(archiveOidcProvider(3), (error: unknown) =>
    assertSqlState(error, "55000"),
  );
  await admin`
    UPDATE public.platform_auth_providers
    SET enabled = false
    WHERE id = ${fixture.oidcProvider}::uuid
  `;
  await admin`
    UPDATE public.platform_federated_provider_policies
    SET enabled = true
    WHERE provider_id = ${fixture.oidcProvider}::uuid
  `;
  await assert.rejects(archiveOidcProvider(3), (error: unknown) =>
    assertSqlState(error, "55000"),
  );
  await admin`
    UPDATE public.platform_federated_provider_policies
    SET platform_login_enabled = false, enabled = false
    WHERE provider_id = ${fixture.oidcProvider}::uuid
  `;
  type ArchiveMutationState = {
    version: number;
    archivedAt: string | null;
    securityRevision: string;
    activeSecrets: number;
    auditCount: number;
  };
  const readArchiveMutationState = async (): Promise<ArchiveMutationState> => {
    const [state] = await admin<ArchiveMutationState[]>`
      SELECT provider.version::integer AS version,
             provider.archived_at::text AS "archivedAt",
             policy.security_revision::text AS "securityRevision",
             (SELECT count(*)::integer
              FROM public.platform_oidc_client_secrets AS secret
              WHERE secret.provider_id = provider.id
                AND secret.retired_at IS NULL) AS "activeSecrets",
             (SELECT count(*)::integer
              FROM public.platform_audit_events AS audit
              WHERE audit.resource_id = provider.id
                AND audit.action = 'platform.identity_provider.archived')
               AS "auditCount"
      FROM public.platform_auth_providers AS provider
      JOIN public.platform_federated_provider_policies AS policy
        ON policy.provider_id = provider.id
      WHERE provider.id = ${fixture.oidcProvider}::uuid
    `;
    assert(state, "archive mutation state is unavailable");
    return state;
  };
  const baselineArchiveMutationState = await readArchiveMutationState();
  await admin`
    UPDATE public.platform_federated_provider_policies
    SET security_revision = ${maximumSafeRevision}::bigint
    WHERE provider_id = ${fixture.oidcProvider}::uuid
  `;
  const saturatedArchiveMutationState = await readArchiveMutationState();
  try {
    await assert.rejects(archiveOidcProvider(3), (error: unknown) =>
      assertSqlState(error, "55000"),
    );
    assert.deepEqual(
      await readArchiveMutationState(),
      saturatedArchiveMutationState,
      "security-revision saturation allowed a partial archive or audit",
    );
  } finally {
    await admin`
      UPDATE public.platform_federated_provider_policies
      SET security_revision = ${baselineArchiveMutationState.securityRevision}::bigint
      WHERE provider_id = ${fixture.oidcProvider}::uuid
    `;
  }
  assert.deepEqual(
    await readArchiveMutationState(),
    baselineArchiveMutationState,
    "archive saturation fixture did not restore cleanly",
  );
  const [blockedArchiveState] = await admin<
    { version: number; auditCount: number }[]
  >`
    SELECT provider.version::integer AS version,
           (SELECT count(*)::integer
            FROM public.platform_audit_events AS audit
            WHERE audit.resource_id = provider.id
              AND audit.action = 'platform.identity_provider.archived') AS "auditCount"
    FROM public.platform_auth_providers AS provider
    WHERE provider.id = ${fixture.oidcProvider}::uuid
  `;
  assert.deepEqual(blockedArchiveState, { version: 3, auditCount: 0 });

  assert.equal(await archiveOidcProvider(3), 4);
  await assert.rejects(archiveOidcProvider(3), (error: unknown) =>
    assertSqlState(error, "40001"),
  );
  await assert.rejects(archiveOidcProvider(4), (error: unknown) =>
    assertSqlState(error, "55000"),
  );
  await assert.rejects(updateOidcProvider(3), (error: unknown) =>
    assertSqlState(error, "40001"),
  );
  await assert.rejects(updateOidcProvider(4), (error: unknown) =>
    assertSqlState(error, "55000"),
  );
  await assert.rejects(
    rotateOidcSecret(3, fixture.staleSecret),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    rotateOidcSecret(4, fixture.staleSecret),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  assert.equal((await listProviders()).length, 1);
  const archived = await listProviders(true);
  assert.equal(archived.length, 2);
  const archivedOidc = archived.find(
    (document) => document.id === fixture.oidcProvider,
  );
  assert(archivedOidc?.archivedAt);
  assert.equal(archivedOidc.secretPresent, false);
  const archivedOidcDetail = await getProvider(fixture.oidcProvider);
  assert(isObject(archivedOidcDetail.configuration));
  assert.equal(archivedOidcDetail.configuration.clientSecretPresent, false);
  const [retiredEnvelopeState] = await admin<
    { liveSecrets: number; ready: boolean }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.platform_oidc_client_secrets AS secret
       WHERE secret.provider_id = ${fixture.oidcProvider}::uuid
         AND secret.retired_at IS NULL) AS "liveSecrets",
      app.release_runtime_schema_readiness_v50() AS ready
  `;
  assert.deepEqual(retiredEnvelopeState, { liveSecrets: 0, ready: true });

  await admin.begin(async (transaction) => {
    await transaction`
      UPDATE public.identity_keyring_versions
      SET is_active = false
      WHERE key_version = ${keyVersion}
    `;
    await transaction`
      UPDATE public.identity_keyring_versions
      SET is_active = true
      WHERE key_version = ${inactiveKeyVersion}
    `;
  });
  try {
    const [retiredKeyOmitted] = await asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction<{ verified: boolean }[]>`
          SELECT app.verify_identity_keyring_v3(
            ARRAY[${inactiveKeyVersion}]::integer[],
            ARRAY[${digest("inactive-keyring-verifier")}::bytea]::bytea[],
            ${inactiveKeyVersion}::integer
          ) AS verified
        `,
      fixture.operator,
    );
    assert.equal(
      retiredKeyOmitted?.verified,
      true,
      "archived provider kept a retired envelope key in live inventory",
    );
  } finally {
    await admin.begin(async (transaction) => {
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = false
        WHERE key_version = ${inactiveKeyVersion}
      `;
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = true
        WHERE key_version = ${keyVersion}
      `;
    });
  }

  const [unsafeState] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id
    WHERE provider.id IN (
      ${fixture.oidcProvider}::uuid, ${fixture.samlProvider}::uuid
    ) AND (
      provider.enabled OR policy.enabled OR policy.platform_login_enabled
    )
  `;
  assert.equal(
    unsafeState?.count,
    0,
    "expand-only providers must stay disabled",
  );

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`
          SELECT ciphertext FROM public.platform_oidc_client_secrets
          WHERE provider_id = ${fixture.oidcProvider}::uuid
        `.then(() => undefined),
      fixture.operator,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function verifyConcurrentExpiredKeyReuse(): Promise<void> {
  const keyDigest = digest("concurrent-expired-key");
  const requestDigest = digest("concurrent-expired-request");
  await admin`
    INSERT INTO public.platform_identity_provider_commands (
      id, actor_user_id, operation, key_digest, request_digest,
      result_provider_id, result_version, created_at, expires_at
    ) VALUES (
      ${uuid(4_000)}::uuid, ${fixture.operator}::uuid, 'provider.create',
      ${keyDigest}::bytea, ${digest("concurrent-old-request")}::bytea,
      ${fixture.samlProvider}::uuid, 1,
      ${new Date(Date.now() - 2 * 24 * 60 * 60_000)},
      ${new Date(Date.now() - 24 * 60 * 60_000)}
    )
  `;

  const receipts = await Promise.all(
    [0, 1].map((index) =>
      createOidcProvider({
        commandId: uuid(4_001 + index),
        providerId: uuid(4_010 + index),
        key: "concurrent_expiry_reuse",
        displayName: "Concurrent expiry reuse",
        configuration: oidcConfiguration,
        keyDigest,
        requestDigest,
      }),
    ),
  );
  assert.deepEqual(
    receipts
      .map((receipt) => receipt.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );
  const firstReceipt = receipts[0];
  const secondReceipt = receipts[1];
  assert(firstReceipt);
  assert(secondReceipt);
  assert.equal(firstReceipt.provider_id, secondReceipt.provider_id);
  const [state] = await admin<
    { providers: number; commands: number; audits: number; expired: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.platform_auth_providers
       WHERE key = 'concurrent_expiry_reuse') AS providers,
      (SELECT count(*)::integer FROM public.platform_identity_provider_commands
       WHERE actor_user_id = ${fixture.operator}::uuid
         AND operation = 'provider.create'
         AND key_digest = ${keyDigest}::bytea) AS commands,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action = 'platform.identity_provider.created'
         AND resource_id = ${firstReceipt.provider_id}::uuid) AS audits,
      (SELECT count(*)::integer FROM public.platform_identity_provider_commands
       WHERE expires_at <= transaction_timestamp()) AS expired
  `;
  assert.deepEqual(state, { providers: 1, commands: 1, audits: 1, expired: 0 });
}

async function main(): Promise<void> {
  await seedFixture();
  await verifyCompatibilityAndBoundary();
  await verifyAdversarialCatalogBoundaries();
  await verifyPermissionCatalogAndDenials();
  await verifyCreateRequiresCoupledReadAuthority();
  await verifyMalformedDirectCallsRollback();
  await createAndVerifyProviders();
  await verifySemanticProjectionBoundaries();
  await verifyTenantAuthoritySerialization();
  await verifyCasSecretAndArchive();
  await verifyExpiryReuseAndBoundedCleanup();
  await verifyConcurrentExpiredKeyReuse();

  const readiness = await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).map(async (role) => ({
      role,
      ready: await asRole(admin, role, async (transaction) => {
        const [row] = await transaction<{ ready: boolean }[]>`
          SELECT app.release_runtime_schema_readiness_v50() AS ready
        `;
        return row?.ready;
      }),
    })),
  );
  for (const { role, ready } of readiness) {
    assert.equal(ready, true, `${role} platform provider readiness failed`);
  }
}

try {
  await main();
  process.stdout.write("platform identity-provider runtime proof passed\n");
} finally {
  await admin.end();
}
