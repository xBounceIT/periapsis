import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker";
type Projection = Readonly<Record<string, unknown>>;
type PrelinkReceipt = {
  account_id: string;
  version: number;
  replayed: boolean;
  document: Projection;
};
type RetireReceipt = {
  account_id: string;
  version: number;
  document: Projection;
};
type SubjectAlias = { keyVersion: number; digest: Buffer };

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_IDENTITY_ACCOUNT_TEST_DATABASE_URL?.trim() ||
  process.env.DATABASE_URL?.trim();
if (databaseUrl === undefined || databaseUrl === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_IDENTITY_ACCOUNT_TEST_DATABASE_URL or DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d6d80-7000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;

const fixture = {
  operator: uuid(1),
  denied: uuid(2),
  accountUser: uuid(3),
  unrelatedUser: uuid(4),
  operatorGrant: uuid(5),
  operatorSession: uuid(6),
  deniedSession: uuid(7),
  operatorFamily: uuid(8),
  deniedFamily: uuid(9),
  provider: uuid(20),
  providerCommand: uuid(21),
  providerSecret: uuid(22),
  tenant: uuid(30),
  operatorMembership: uuid(31),
  accountMembership: uuid(32),
  binding: uuid(40),
  bindingCommand: uuid(41),
  account: uuid(50),
  accountCommand: uuid(51),
  accountAudit: uuid(52),
  unrelatedAccount: uuid(53),
  unrelatedCommand: uuid(54),
  unrelatedAudit: uuid(55),
  grant: uuid(60),
  contribution: uuid(61),
  sourceSession: uuid(62),
  siblingSession: uuid(63),
  unrelatedSession: uuid(64),
  sourceFamily: uuid(65),
  unrelatedFamily: uuid(66),
  sessionEvidence: uuid(67),
  continuation: uuid(68),
  continuationEvidence: uuid(69),
  replaySourceSession: uuid(70),
  replayRotatedSession: uuid(71),
  replayFamily: uuid(72),
  replaySourceEvidence: uuid(73),
  replayRotatedEvidence: uuid(74),
  replayAudit: uuid(75),
  replayRequest: uuid(76),
  replayCorrelation: uuid(77),
  replayPlatformFloor: uuid(78),
} as const;

const issuer = "https://platform-account-runtime-idp.example.invalid";
const tenantRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback";
const directRedirectUri =
  "https://periapsis.example.invalid/auth/platform/oidc/callback";
const postLogoutRedirectUri = "https://periapsis.example.invalid/login";
const activeKeyVersion = 32_767;
const inactiveKeyVersion = 32_766;
let sequence = 1_000;

const protectedTables = [
  "platform_federated_external_identities",
  "platform_federated_external_identity_aliases",
  "platform_identity_account_commands",
] as const;

const publicFunctions = [
  "app.list_platform_identity_accounts_v2(uuid,text,uuid,uuid,integer,boolean)",
  "app.get_platform_identity_account_v2(uuid,uuid,uuid,text)",
  "app.prelink_platform_identity_account_v2(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
  "app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
] as const;
const revokedFunctions = [
  "app.private_platform_identity_account_document_v1(uuid,uuid)",
  "app.private_platform_identity_account_document_v2(uuid,uuid)",
  "app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)",
  "app.get_platform_identity_account_v1(uuid,uuid,uuid,text)",
  "app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
  "app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
  "app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
] as const;

const oidcConfiguration = {
  issuer,
  clientId: "periapsis-platform-account-runtime",
  redirectUri: directRedirectUri,
  postLogoutRedirectUri,
  extraScopes: ["groups"],
  allowRefreshToken: false,
  useUserInfo: true,
} as const;

function nextUuid(): string {
  sequence += 1;
  return uuid(sequence);
}

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-identity-account-runtime:${label}`)
    .digest();
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

function assertSqlState(
  error: unknown,
  expectedCode: string,
  expectedMessage?: string,
): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expectedCode, error.message);
  if (expectedMessage !== undefined) {
    assert.equal(error.message, expectedMessage);
  }
  return true;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function compositeRepresentationValidator(document: Projection): string {
  const user = object(document.user, "account document user");
  assert.equal(typeof document.version, "number");
  assert.equal(typeof user.version, "number");
  return `"v${String(document.version)}-u${String(user.version)}"`;
}

async function asRole<T>(
  client: Sql,
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  userId = fixture.operator,
  tenantId = "",
): Promise<T> {
  const wrapped = await client.begin(async (transaction) => {
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

async function withoutPermission<T>(
  permission:
    "platform.identity_account.read" | "platform.identity_account.manage",
  operation: () => Promise<T>,
): Promise<T> {
  const [removed] = await admin<{ roleId: string; permissionId: string }[]>`
    DELETE FROM public.platform_role_permissions AS grant_row
    USING public.platform_roles AS role,
          public.platform_permissions AS permission
    WHERE grant_row.role_id = role.id
      AND grant_row.permission_id = permission.id
      AND role.key = 'platform_super_admin'
      AND permission.key = ${permission}
    RETURNING grant_row.role_id AS "roleId",
              grant_row.permission_id AS "permissionId"
  `;
  assert(removed, `${permission} was not granted to platform_super_admin`);
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

async function createProvider(): Promise<void> {
  const event = trace();
  const [created] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT result.version::integer AS version
      FROM app.create_platform_oidc_auth_provider_v3(
        ${fixture.operatorSession}::uuid, ${fixture.providerCommand}::uuid,
        ${fixture.provider}::uuid, 'platform_account_runtime'::text,
        'Platform account runtime'::text,
        'Disabled provider for platform account administration proof'::text,
        ${transaction.json(oidcConfiguration)}::jsonb,
        ${tenantRedirectUri}::text,
        ${digest("provider-key")}::bytea,
        ${digest("provider-request")}::bytea,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.72'::inet,
        'Periapsis platform identity-account runtime proof'::text,
        'totp'::text, 'Create disabled OIDC provider'::text
      ) AS result
    `,
  );
  assert.equal(created?.version, 1);
}

type PrelinkInput = {
  commandId: string;
  accountId: string;
  userId: string;
  aliases: readonly SubjectAlias[];
  keyDigest: Buffer;
  publicRequestDigest: Buffer;
  auditEventId?: string;
  issuerValue?: string;
  subjectCiphertext?: Buffer;
  subjectNonce?: Buffer;
  sessionId?: string;
};

async function prelinkInTransaction(
  transaction: postgres.TransactionSql,
  input: PrelinkInput,
): Promise<PrelinkReceipt> {
  const event = trace();
  const aliasVersions = input.aliases.map((alias) => alias.keyVersion);
  const aliasDigests = input.aliases.map((alias) =>
    alias.digest.toString("base64"),
  );
  const [receipt] = await transaction<PrelinkReceipt[]>`
      SELECT result.account_id, result.version::integer AS version,
             result.replayed, result.document
      FROM app.prelink_platform_identity_account_v2(
        ${input.sessionId ?? fixture.operatorSession}::uuid,
        ${input.commandId}::uuid, ${input.accountId}::uuid,
        ${fixture.provider}::uuid, ${input.userId}::uuid,
        ${input.issuerValue ?? issuer}::text, 'utf8_exact'::public.identity_subject_format,
        ${input.subjectCiphertext ?? Buffer.alloc(32, 0x73)}::bytea,
        ${input.subjectNonce ?? Buffer.alloc(12, 0x6e)}::bytea,
        ${activeKeyVersion}::integer,
        (SELECT array_agg(item.value::integer ORDER BY item.ordinality)
         FROM jsonb_array_elements_text(
           ${transaction.json(aliasVersions)}::jsonb
         ) WITH ORDINALITY AS item(value, ordinality)),
        (SELECT array_agg(decode(item.value, 'base64') ORDER BY item.ordinality)
         FROM jsonb_array_elements_text(
           ${transaction.json(aliasDigests)}::jsonb
         ) WITH ORDINALITY AS item(value, ordinality)),
        ${input.keyDigest}::bytea, ${input.publicRequestDigest}::bytea,
        ${input.auditEventId ?? event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.72'::inet,
        'Periapsis platform identity-account runtime proof'::text,
        'totp'::text, 'Prelink platform identity account'::text
      ) AS result
    `;
  assert(receipt, "platform identity-account prelink returned no receipt");
  return receipt;
}

async function prelink(input: PrelinkInput): Promise<PrelinkReceipt> {
  return asRole(admin, "periapsis_api", (transaction) =>
    prelinkInTransaction(transaction, input),
  );
}

async function getAccount(accountId: string): Promise<Projection> {
  return asRole(admin, "periapsis_api", async (transaction) => {
    const [row] = await transaction<{ document: Projection }[]>`
      SELECT app.get_platform_identity_account_v2(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${accountId}::uuid, 'totp'::text
      ) AS document
    `;
    assert(row, "platform identity-account get returned no row");
    return row.document;
  });
}

async function listAccounts(includeRetired: boolean): Promise<Projection[]> {
  return asRole(admin, "periapsis_api", async (transaction) => {
    const rows = await transaction<{ document: Projection }[]>`
      SELECT document
      FROM app.list_platform_identity_accounts_v2(
        ${fixture.operatorSession}::uuid, 'totp'::text,
        ${fixture.provider}::uuid, NULL::uuid, 101::integer,
        ${includeRetired}::boolean
      )
    `;
    return Array.from(rows, (row) => row.document);
  });
}

async function retireAccount(input: {
  accountId?: string;
  expectedVersion: number;
  expectedUserVersion: number;
  auditEventId?: string;
}): Promise<RetireReceipt> {
  const event = trace();
  return asRole(admin, "periapsis_api", async (transaction) => {
    const [receipt] = await transaction<RetireReceipt[]>`
      SELECT result.account_id, result.version::integer AS version,
             result.document
      FROM app.retire_platform_identity_account_v4(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${input.accountId ?? fixture.account}::uuid,
        ${input.expectedVersion}::bigint,
        ${input.expectedUserVersion}::bigint,
        ${input.auditEventId ?? event.auditId}::uuid,
        ${event.requestId}::uuid, ${event.correlationId}::uuid,
        '198.51.100.72'::inet,
        'Periapsis platform identity-account runtime proof'::text,
        'totp'::text, 'Retire platform identity account'::text
      ) AS result
    `;
    assert(receipt, "platform identity-account retirement returned no receipt");
    return receipt;
  });
}

async function prelinkSnapshot(): Promise<unknown> {
  const [snapshot] = await admin`
    SELECT
      identity.version, identity.resource_version,
      identity.last_observed_at, identity.updated_at,
      identity.retired_at,
      (SELECT count(*)::integer
       FROM public.platform_federated_external_identity_aliases AS alias
       WHERE alias.platform_provider_id = identity.platform_provider_id
         AND alias.external_identity_id = identity.id) AS aliases,
      (SELECT count(*)::integer
       FROM public.platform_identity_account_commands AS command
       WHERE command.platform_provider_id = identity.platform_provider_id
         AND command.result_account_id = identity.id) AS commands,
      (SELECT count(*)::integer
       FROM public.platform_audit_events AS audit
       WHERE audit.resource_type = 'platform_identity_account'
         AND audit.resource_id = identity.id
         AND audit.action = 'platform.identity_account.prelinked') AS audits
    FROM public.platform_federated_external_identities AS identity
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.id = ${fixture.account}::uuid
  `;
  assert(snapshot, "prelink snapshot account was not found");
  return snapshot;
}

async function transactionPrelinkSnapshot(
  transaction: postgres.TransactionSql,
): Promise<unknown> {
  const [snapshot] = await transaction`
    SELECT
      identity.version, identity.resource_version,
      identity.last_observed_at, identity.updated_at,
      identity.retired_at,
      (SELECT count(*)::integer
       FROM public.platform_federated_external_identity_aliases AS alias
       WHERE alias.platform_provider_id = identity.platform_provider_id
         AND alias.external_identity_id = identity.id) AS aliases,
      (SELECT count(*)::integer
       FROM public.platform_identity_account_commands AS command
       WHERE command.platform_provider_id = identity.platform_provider_id
         AND command.result_account_id = identity.id) AS commands,
      (SELECT count(*)::integer
       FROM public.platform_audit_events AS audit
       WHERE audit.resource_type = 'platform_identity_account'
         AND audit.resource_id = identity.id
         AND audit.action = 'platform.identity_account.prelinked') AS audits
    FROM public.platform_federated_external_identities AS identity
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.id = ${fixture.account}::uuid
  `;
  assert(snapshot, "transactional prelink snapshot account was not found");
  return snapshot;
}

async function seedBase(): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 60 * 60_000);
  const [fresh] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.users
  `;
  assert.equal(
    fresh?.count,
    0,
    "platform identity-account runtime proof requires a fresh database",
  );
  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.operator}::uuid,
         'platform-account.operator@example.invalid',
         'Platform account operator'),
        (${fixture.denied}::uuid,
         'platform-account.denied@example.invalid',
         'Denied platform account operator'),
        (${fixture.accountUser}::uuid,
         'platform-account.user@example.invalid',
         'Local account user'),
        (${fixture.unrelatedUser}::uuid,
         'platform-account.unrelated@example.invalid',
         'Unrelated account user')
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
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES
        (${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
         ${fixture.operatorFamily}::uuid, NULL,
         ${digest("operator-token")}::bytea,
         ${digest("operator-csrf")}::bytea, 'totp', ${now}, ${now},
         ${expires}, ${expires}, ${now}),
        (${fixture.deniedSession}::uuid, ${fixture.denied}::uuid,
         ${fixture.deniedFamily}::uuid, NULL,
         ${digest("denied-token")}::bytea,
         ${digest("denied-csrf")}::bytea, 'totp', ${now}, ${now},
         ${expires}, ${expires}, ${now})
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES
        (${inactiveKeyVersion}, ${digest("inactive-key")}::bytea, false),
        (${activeKeyVersion}, ${digest("active-key")}::bytea, true)
    `;
  });
  await createProvider();
}

async function verifyAclAndRls(): Promise<void> {
  const catalog = await admin<
    {
      tableName: string;
      rls: boolean;
      forceRls: boolean;
      owner: string;
      policies: number;
    }[]
  >`
    SELECT relation.relname AS "tableName",
           relation.relrowsecurity AS rls,
           relation.relforcerowsecurity AS "forceRls",
           owner.rolname AS owner,
           (SELECT count(*)::integer FROM pg_catalog.pg_policy AS policy
            WHERE policy.polrelid = relation.oid) AS policies
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY (${protectedTables}::text[])
    ORDER BY relation.relname
  `;
  assert.deepEqual(
    Array.from(catalog),
    protectedTables.toSorted().map((tableName) => ({
      tableName,
      rls: true,
      forceRls: true,
      owner: "periapsis_migrator",
      policies: 0,
    })),
  );

  const tableAclLeaks = await admin<{ roleName: string; tableName: string }[]>`
    SELECT runtime_role.role_name AS "roleName",
           protected_table.table_name AS "tableName"
    FROM unnest(ARRAY[
      'periapsis_api','periapsis_worker','periapsis_notifier','periapsis_auditor'
    ]::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${protectedTables}::text[])
      AS protected_table(table_name)
    WHERE has_table_privilege(
      runtime_role.role_name,
      format('public.%I', protected_table.table_name),
      'SELECT,INSERT,UPDATE,DELETE'
    )
    ORDER BY runtime_role.role_name, protected_table.table_name
  `;
  assert.deepEqual(Array.from(tableAclLeaks), []);

  const functionAcls = await admin<
    {
      signature: string;
      api: boolean;
      worker: boolean;
      notifier: boolean;
      auditor: boolean;
    }[]
  >`
    SELECT signature,
      has_function_privilege('periapsis_api', signature, 'EXECUTE') AS api,
      has_function_privilege('periapsis_worker', signature, 'EXECUTE') AS worker,
      has_function_privilege('periapsis_notifier', signature, 'EXECUTE') AS notifier,
      has_function_privilege('periapsis_auditor', signature, 'EXECUTE') AS auditor
    FROM unnest(${publicFunctions}::text[]) AS routine(signature)
    ORDER BY signature
  `;
  assert.deepEqual(
    Array.from(functionAcls, ({ signature: _signature, ...acl }) => acl),
    publicFunctions.map(() => ({
      api: true,
      worker: false,
      notifier: false,
      auditor: false,
    })),
  );

  const revokedFunctionAcls = await admin<
    {
      signature: string;
      api: boolean;
      worker: boolean;
      notifier: boolean;
      auditor: boolean;
    }[]
  >`
    SELECT signature,
      has_function_privilege('periapsis_api', signature, 'EXECUTE') AS api,
      has_function_privilege('periapsis_worker', signature, 'EXECUTE') AS worker,
      has_function_privilege('periapsis_notifier', signature, 'EXECUTE') AS notifier,
      has_function_privilege('periapsis_auditor', signature, 'EXECUTE') AS auditor
    FROM unnest(${revokedFunctions}::text[]) AS routine(signature)
    ORDER BY signature
  `;
  assert.deepEqual(
    Array.from(revokedFunctionAcls, ({ signature: _signature, ...acl }) => acl),
    revokedFunctions.map(() => ({
      api: false,
      worker: false,
      notifier: false,
      auditor: false,
    })),
  );

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) => transaction`
      SELECT count(*) FROM public.platform_identity_account_commands
    `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.private_platform_identity_account_document_v2(
        ${fixture.provider}::uuid, ${fixture.account}::uuid
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function verifyPrelinkReplayAndAuthorization(): Promise<void> {
  const providerState = await admin<
    { enabled: boolean; accountMode: string }[]
  >`
    SELECT provider.enabled, policy.account_mode AS "accountMode"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id
    WHERE provider.id = ${fixture.provider}::uuid
  `;
  assert.deepEqual(providerState[0], {
    enabled: false,
    accountMode: "disabled",
  });

  const primaryAlias = {
    keyVersion: activeKeyVersion,
    digest: digest("subject-primary"),
  } as const;
  const first = await prelink({
    commandId: fixture.accountCommand,
    accountId: fixture.account,
    userId: fixture.accountUser,
    aliases: [primaryAlias],
    keyDigest: digest("account-key"),
    publicRequestDigest: digest("account-request"),
    auditEventId: fixture.accountAudit,
  });
  assert.equal(first.account_id, fixture.account);
  assert.equal(first.version, 1);
  assert.equal(first.replayed, false);

  const document = object(first.document, "prelink document");
  assert.deepEqual(Object.keys(document).toSorted(), [
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
  assert.deepEqual(
    Object.keys(object(document.user, "account user")).toSorted(),
    ["active", "displayName", "email", "id", "version"],
  );
  assert.equal(document.state, "active");
  assert.equal(document.lastObservationState, "known");
  assert.equal(typeof document.lastObservedAt, "string");
  assert.equal(compositeRepresentationValidator(document), '"v1-u1"');
  const serialized = JSON.stringify(document);
  for (const forbidden of [
    "issuer",
    "subject",
    "ciphertext",
    "nonce",
    "keyVersion",
    "digest",
  ]) {
    assert.equal(serialized.includes(forbidden), false, `${forbidden} leaked`);
  }

  const exactSnapshot = await prelinkSnapshot();
  const [prelinkAudit] = await admin<{ metadata: unknown }[]>`
    SELECT audit.metadata
    FROM public.platform_audit_events AS audit
    WHERE audit.id = ${fixture.accountAudit}::uuid
      AND audit.action = 'platform.identity_account.prelinked'
      AND audit.resource_id = ${fixture.account}::uuid
  `;
  assert(prelinkAudit, "platform identity-account prelink audit was not found");
  assert.deepEqual(prelinkAudit.metadata, {
    provider_id: fixture.provider,
    user_id: fixture.accountUser,
    version: 1,
    admitted_configuration_revision: document.admittedConfigurationRevision,
    admitted_security_revision: document.admittedSecurityRevision,
    subject_material_included: false,
    replayed: false,
  });

  await assert.rejects(
    admin`
      UPDATE public.platform_identity_account_commands
      SET expires_at = expires_at + interval '1 second'
      WHERE id = ${fixture.accountCommand}::uuid
    `,
    (error: unknown) =>
      assertSqlState(
        error,
        "55000",
        "platform identity account commands are immutable",
      ),
  );
  await assert.rejects(
    admin`
      DELETE FROM public.platform_identity_account_commands
      WHERE id = ${fixture.accountCommand}::uuid
    `,
    (error: unknown) =>
      assertSqlState(
        error,
        "55000",
        "live platform identity account command cannot be deleted",
      ),
  );
  assert.deepEqual(
    await prelinkSnapshot(),
    exactSnapshot,
    "command guard mutated the live replay receipt",
  );

  const replay = await prelink({
    commandId: nextUuid(),
    accountId: nextUuid(),
    userId: fixture.accountUser,
    aliases: [primaryAlias],
    keyDigest: digest("account-key"),
    publicRequestDigest: digest("account-request"),
  });
  assert.equal(replay.account_id, fixture.account);
  assert.equal(replay.version, 1);
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.document, first.document);
  assert.deepEqual(
    await prelinkSnapshot(),
    exactSnapshot,
    "exact replay advanced audit or account timestamps",
  );

  const assertLifecycleIndependentReplay = async (
    label: string,
    mutateLifecycle: (transaction: postgres.TransactionSql) => Promise<void>,
  ): Promise<void> => {
    const rollback = new Error(`${label} rollback`);
    await assert.rejects(
      admin.begin(async (transaction) => {
        await mutateLifecycle(transaction);
        const beforeReplay = await transactionPrelinkSnapshot(transaction);

        await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
        await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
        await transaction`
          SELECT set_config('app.tenant_id', '', true),
                 set_config('app.user_id', ${fixture.operator}, true),
                 set_config('app.service_account_id', '', true)
        `;
        const lifecycleReplay = await prelinkInTransaction(transaction, {
          commandId: nextUuid(),
          accountId: nextUuid(),
          userId: fixture.accountUser,
          aliases: [primaryAlias],
          keyDigest: digest("account-key"),
          publicRequestDigest: digest("account-request"),
        });
        assert.equal(lifecycleReplay.account_id, fixture.account, label);
        assert.equal(lifecycleReplay.version, 1, label);
        assert.equal(lifecycleReplay.replayed, true, label);
        assert.deepEqual(lifecycleReplay.document, first.document, label);

        await transaction.unsafe("RESET ROLE");
        assert.deepEqual(
          await transactionPrelinkSnapshot(transaction),
          beforeReplay,
          `${label} mutated account, command, timestamp, alias, or audit state`,
        );
        throw rollback;
      }),
      (error: unknown) => error === rollback,
    );
    assert.deepEqual(
      await prelinkSnapshot(),
      exactSnapshot,
      `${label} fixture rollback was incomplete`,
    );
  };

  await assertLifecycleIndependentReplay(
    "exact replay after provider archive",
    async (transaction) => {
      const archived = await transaction<{ id: string }[]>`
        UPDATE ONLY public.platform_auth_providers AS provider
        SET enabled = false,
            archived_at = transaction_timestamp(),
            archived_by_user_id = ${fixture.operator}::uuid,
            archive_reason = 'Replay lifecycle regression'::text,
            version = provider.version + 1,
            updated_at = transaction_timestamp()
        WHERE provider.id = ${fixture.provider}::uuid
        RETURNING provider.id
      `;
      assert.equal(archived.length, 1);
    },
  );
  await assertLifecycleIndependentReplay(
    "exact replay after subject key retirement",
    async (transaction) => {
      const retired = await transaction<{ keyVersion: number }[]>`
        UPDATE ONLY public.identity_keyring_versions AS keyring
        SET is_active = false, retired_at = transaction_timestamp()
        WHERE keyring.key_version = ${activeKeyVersion}
        RETURNING keyring.key_version AS "keyVersion"
      `;
      assert.deepEqual(Array.from(retired), [{ keyVersion: activeKeyVersion }]);
    },
  );

  const assertReplayConflict = async (attempt: {
    label: string;
    aliases: readonly SubjectAlias[];
    publicRequestDigest: Buffer;
    issuerValue?: string;
  }): Promise<void> => {
    await assert.rejects(
      prelink({
        commandId: nextUuid(),
        accountId: nextUuid(),
        userId: fixture.accountUser,
        aliases: attempt.aliases,
        keyDigest: digest("account-key"),
        publicRequestDigest: attempt.publicRequestDigest,
        ...(attempt.issuerValue === undefined
          ? {}
          : { issuerValue: attempt.issuerValue }),
      }),
      (error: unknown) => assertSqlState(error, "23505"),
      attempt.label,
    );
    assert.deepEqual(await prelinkSnapshot(), exactSnapshot);
  };
  await assertReplayConflict({
    label: "changed public payload",
    aliases: [primaryAlias],
    publicRequestDigest: digest("changed-account-request"),
  });
  await assertReplayConflict({
    label: "changed issuer payload",
    aliases: [primaryAlias],
    publicRequestDigest: digest("changed-issuer-account-request"),
    issuerValue: "https://changed-platform-account-runtime-idp.example.invalid",
  });
  await assertReplayConflict({
    label: "changed subject",
    aliases: [
      { keyVersion: activeKeyVersion, digest: digest("changed-subject") },
    ],
    publicRequestDigest: digest("account-request"),
  });
  await assertReplayConflict({
    label: "missing persisted alias",
    aliases: [
      {
        keyVersion: inactiveKeyVersion,
        digest: digest("missing-subject-alias"),
      },
      primaryAlias,
    ],
    publicRequestDigest: digest("account-request"),
  });

  await assert.rejects(
    prelink({
      commandId: nextUuid(),
      accountId: nextUuid(),
      userId: fixture.accountUser,
      aliases: [primaryAlias],
      keyDigest: digest("fresh-key-same-subject"),
      publicRequestDigest: digest("fresh-request-same-subject"),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const list = await listAccounts(false);
  assert.equal(list.length, 1);
  assert.deepEqual(list[0], await getAccount(fixture.account));
  const [emptyList] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM app.list_platform_identity_accounts_v2(
        ${fixture.operatorSession}::uuid, 'totp'::text,
        ${nextUuid()}::uuid, NULL::uuid, 50::integer, false::boolean
      )
    `,
  );
  assert.equal(emptyList?.count, 0);

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) => transaction`
        SELECT app.get_platform_identity_account_v2(
          ${fixture.deniedSession}::uuid, ${fixture.provider}::uuid,
          ${fixture.account}::uuid, 'totp'::text
        )
      `,
      fixture.denied,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await withoutPermission("platform.identity_account.manage", async () => {
    assert.deepEqual(await getAccount(fixture.account), first.document);
    await assert.rejects(
      prelink({
        commandId: nextUuid(),
        accountId: nextUuid(),
        userId: fixture.unrelatedUser,
        aliases: [
          { keyVersion: activeKeyVersion, digest: digest("manage-denied") },
        ],
        keyDigest: digest("manage-denied-key"),
        publicRequestDigest: digest("manage-denied-request"),
      }),
      (error: unknown) => assertSqlState(error, "42501"),
    );
  });
  await withoutPermission("platform.identity_account.read", async () => {
    await assert.rejects(getAccount(fixture.account), (error: unknown) =>
      assertSqlState(error, "42501"),
    );
    await assert.rejects(
      prelink({
        commandId: nextUuid(),
        accountId: nextUuid(),
        userId: fixture.unrelatedUser,
        aliases: [
          { keyVersion: activeKeyVersion, digest: digest("read-denied") },
        ],
        keyDigest: digest("read-denied-key"),
        publicRequestDigest: digest("read-denied-request"),
      }),
      (error: unknown) => assertSqlState(error, "42501"),
    );
  });

  const unrelated = await prelink({
    commandId: fixture.unrelatedCommand,
    accountId: fixture.unrelatedAccount,
    userId: fixture.unrelatedUser,
    aliases: [
      { keyVersion: activeKeyVersion, digest: digest("unrelated-subject") },
    ],
    keyDigest: digest("unrelated-account-key"),
    publicRequestDigest: digest("unrelated-account-request"),
    auditEventId: fixture.unrelatedAudit,
  });
  assert.equal(unrelated.replayed, false);
}

async function createTenantAndActivateProvider(): Promise<void> {
  let event = trace();
  await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction`
    SELECT id
    FROM app.create_platform_tenant(
      ${fixture.tenant}::uuid, ${fixture.operatorMembership}::uuid,
      'platform-account-runtime'::text,
      'Platform account runtime tenant'::text,
      'Europe/Rome'::text, 'en'::text, ${event.auditId}::uuid,
      ${event.requestId}::uuid, ${event.correlationId}::uuid,
      '198.51.100.72'::inet,
      'Periapsis platform identity-account runtime proof'::text,
      'totp'::text
    )
  `,
  );

  event = trace();
  await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction`
    SELECT result.binding_id
    FROM app.create_tenant_platform_auth_provider_binding_v1(
      ${fixture.operatorSession}::uuid, ${fixture.bindingCommand}::uuid,
      ${fixture.binding}::uuid, ${fixture.provider}::uuid,
      ${fixture.tenant}::uuid, 'workforce'::text, 100::integer,
      ${digest("binding-key")}::bytea, ${digest("binding-request")}::bytea,
      ${event.tenantAuditId}::uuid, ${event.auditId}::uuid,
      ${event.requestId}::uuid, ${event.correlationId}::uuid,
      '198.51.100.72'::inet,
      'Periapsis platform identity-account runtime proof'::text,
      'totp'::text, 'Create disabled tenant platform binding'::text
    ) AS result
  `,
  );

  event = trace();
  const [rotated] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ version: number }[]>`
      SELECT result.version::integer AS version
      FROM app.replace_platform_oidc_client_secret_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.providerSecret}::uuid, 1::bigint,
        ${activeKeyVersion}::integer, ${Buffer.alloc(12, 0x61)}::bytea,
        ${Buffer.from("platform-account-runtime-encrypted-secret", "utf8")}::bytea,
        ${event.auditId}::uuid, ${event.requestId}::uuid,
        ${event.correlationId}::uuid, '198.51.100.72'::inet,
        'Periapsis platform identity-account runtime proof'::text,
        'totp'::text, 'Install OIDC client secret'::text
      ) AS result
    `,
  );
  assert.equal(rotated?.version, 2);

  const retrievedAt = new Date();
  const freshUntil = new Date(retrievedAt.getTime() + 24 * 60 * 60_000);
  const discoveryDocument = Buffer.from(
    JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks` }),
  );
  const jwksDocument = Buffer.from(JSON.stringify({ keys: [] }));
  const [providerPins] = await admin<
    { version: number; configurationRevision: number }[]
  >`
    SELECT provider.version::integer AS version,
           policy.configuration_revision::integer AS "configurationRevision"
    FROM public.platform_auth_providers AS provider
    JOIN public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id
    WHERE provider.id = ${fixture.provider}::uuid
  `;
  assert(providerPins);
  event = trace();
  const publication = {
    providerId: fixture.provider,
    expectedProviderVersion: providerPins.version,
    expectedConfigurationRevision: providerPins.configurationRevision,
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
    reason: "Publish OIDC discovery and JWKS",
  };
  await asRole(
    admin,
    "periapsis_worker",
    (transaction) => transaction`
    SELECT app.publish_platform_oidc_trust_snapshot_v1(
      ${transaction.json(publication)}::jsonb
    )
  `,
  );

  const [providerBeforeActivation] = await admin<{ version: number }[]>`
    SELECT version::integer AS version
    FROM public.platform_auth_providers
    WHERE id = ${fixture.provider}::uuid
  `;
  assert(providerBeforeActivation);
  event = trace();
  await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction`
    SELECT result.version
    FROM app.activate_platform_auth_provider_tenant_execution_v1(
      ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
      ${providerBeforeActivation.version}::bigint, 'create'::text,
      ${event.auditId}::uuid, ${event.requestId}::uuid,
      ${event.correlationId}::uuid, '198.51.100.72'::inet,
      'Periapsis platform identity-account runtime proof'::text,
      'totp'::text, 'Activate tenant OIDC execution'::text
    ) AS result
  `,
  );

  const [bindingState] = await admin<
    { bindingVersion: number; tenantVersion: number }[]
  >`
    SELECT binding.version::integer AS "bindingVersion",
           tenant.version::integer AS "tenantVersion"
    FROM public.tenant_platform_auth_provider_bindings AS binding
    JOIN public.tenants AS tenant ON tenant.id = binding.tenant_id
    WHERE binding.id = ${fixture.binding}::uuid
  `;
  assert(bindingState);
  event = trace();
  await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction`
    SELECT result.version
    FROM app.activate_tenant_platform_auth_provider_binding_v1(
      ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
      ${fixture.binding}::uuid, ${bindingState.bindingVersion}::bigint,
      ${bindingState.tenantVersion}::integer, 'create'::text,
      'provider_access_only'::text, ${event.tenantAuditId}::uuid,
      ${event.auditId}::uuid, ${event.requestId}::uuid,
      ${event.correlationId}::uuid, '198.51.100.72'::inet,
      'Periapsis platform identity-account runtime proof'::text,
      'totp'::text, 'Activate tenant platform OIDC binding'::text
    ) AS result
  `,
  );
}

async function seedRetirementDependencies(): Promise<void> {
  await createTenantAndActivateProvider();
  const now = new Date(Date.now() - 30_000);
  const expires = new Date(Date.now() + 60 * 60_000);
  const [pins] = await admin<
    {
      accessEpochId: string;
      sourceId: string;
      providerRevision: number;
      bindingRevision: number;
      securityRevision: number;
      mappingRevision: number;
      authorizationRevision: number;
    }[]
  >`
    SELECT binding.current_access_epoch_id AS "accessEpochId",
           epoch.source_id AS "sourceId",
           provider.version::integer AS "providerRevision",
           binding.version::integer AS "bindingRevision",
           policy.security_revision::integer AS "securityRevision",
           binding.mapping_revision::integer AS "mappingRevision",
           authorization_state.revision::integer AS "authorizationRevision"
    FROM public.tenant_platform_auth_provider_bindings AS binding
    JOIN public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
    JOIN public.platform_auth_providers AS provider
      ON provider.id = binding.platform_provider_id
    JOIN public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id = binding.tenant_id
    WHERE binding.tenant_id = ${fixture.tenant}::uuid
      AND binding.id = ${fixture.binding}::uuid
  `;
  assert(pins);
  assert(pins.authorizationRevision > 0);

  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status, created_at, updated_at
      ) VALUES (
        ${fixture.accountMembership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.accountUser}::uuid, 'read_only', 'active', ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id, user_id, webauthn_user_handle, identity_epoch,
        session_invalidation_epoch, version, created_at, updated_at
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.accountUser}::uuid,
        ${digest("account-user-handle")}::bytea, 7, 11, 3, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_platform_federated_provider_access_grants (
        id, tenant_id, platform_provider_id, binding_id, access_epoch_id,
        source_id, external_identity_id, membership_id, user_id,
        owns_membership, started_at, last_observed_at, version
      ) VALUES (
        ${fixture.grant}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.binding}::uuid,
        ${pins.accessEpochId}::uuid, ${pins.sourceId}::uuid,
        ${fixture.account}::uuid, ${fixture.accountMembership}::uuid,
        ${fixture.accountUser}::uuid, true, ${now}, ${now}, 1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_platform_federated_provider_profile_contributions (
        id, tenant_id, access_grant_id, display_name, email,
        mapping_revision, observed_at, version
      ) VALUES (
        ${fixture.contribution}::uuid, ${fixture.tenant}::uuid,
        ${fixture.grant}::uuid, 'Provider account user',
        'provider-account-user@example.invalid',
        ${pins.mappingRevision}::bigint, ${now}, 1
      )
    `;
    await transaction`
      SELECT app.private_materialize_tenant_user_profile_v1(
        ${fixture.tenant}::uuid, ${fixture.accountMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES
        (${fixture.sourceSession}::uuid, ${fixture.accountUser}::uuid,
         ${fixture.sourceFamily}::uuid, ${fixture.tenant}::uuid,
         ${digest("source-session-token")}::bytea,
         ${digest("source-session-csrf")}::bytea, 'oidc', NULL,
         ${now}, ${expires}, ${expires}, ${now}),
        (${fixture.siblingSession}::uuid, ${fixture.accountUser}::uuid,
         ${fixture.sourceFamily}::uuid, ${fixture.tenant}::uuid,
         ${digest("sibling-session-token")}::bytea,
         ${digest("sibling-session-csrf")}::bytea, 'oidc', NULL,
         ${now}, ${expires}, ${expires}, ${now}),
        (${fixture.unrelatedSession}::uuid, ${fixture.accountUser}::uuid,
         ${fixture.unrelatedFamily}::uuid, ${fixture.tenant}::uuid,
         ${digest("unrelated-session-token")}::bytea,
         ${digest("unrelated-session-csrf")}::bytea, 'oidc', NULL,
         ${now}, ${expires}, ${expires}, ${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id, tenant_id, user_id, session_version, identity_epoch,
        recovery_restricted, audience, primary_kind,
        session_invalidation_epoch, issued_at
      ) VALUES (
        ${fixture.sourceSession}::uuid, ${fixture.tenant}::uuid,
        ${fixture.accountUser}::uuid, 1, 7, false, 'api',
        'tenant_platform_provider', 11, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_tenant_platform_federated_provenance (
        tenant_id, session_id, user_id, primary_kind, authentication_method,
        platform_provider_id, binding_id, access_epoch_id, access_source_id,
        access_grant_id, membership_id, external_identity_id,
        external_identity_revision, provider_revision, binding_revision,
        security_revision, mapping_revision, authorization_revision,
        subject_alias_key_version, trust_rule_revision, authenticated_at
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.sourceSession}::uuid,
        ${fixture.accountUser}::uuid, 'tenant_platform_provider', 'oidc',
        ${fixture.provider}::uuid, ${fixture.binding}::uuid,
        ${pins.accessEpochId}::uuid, ${pins.sourceId}::uuid,
        ${fixture.grant}::uuid, ${fixture.accountMembership}::uuid,
        ${fixture.account}::uuid, 1, ${pins.providerRevision}::bigint,
        ${pins.bindingRevision}::bigint, ${pins.securityRevision}::bigint,
        ${pins.mappingRevision}::bigint,
        ${pins.authorizationRevision}::bigint,
        ${activeKeyVersion}::integer, ${pins.securityRevision}::bigint, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_tenant_platform_federated_evidence (
        id, tenant_id, session_id, user_id, platform_provider_id, binding_id,
        external_identity_id, level, authenticated_at, expires_at,
        trust_rule_revision
      ) VALUES (
        ${fixture.sessionEvidence}::uuid, ${fixture.tenant}::uuid,
        ${fixture.sourceSession}::uuid, ${fixture.accountUser}::uuid,
        ${fixture.provider}::uuid, ${fixture.binding}::uuid,
        ${fixture.account}::uuid, 'primary', ${now}, ${expires},
        ${pins.securityRevision}::bigint
      )
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id, tenant_id, user_id, receipt_digest, identity_epoch, action,
        audience, primary_kind, platform_provider_id, binding_id,
        provider_kind, external_identity_id, primary_revision,
        session_invalidation_epoch, state, version, created_at, expires_at
      ) VALUES (
        ${fixture.continuation}::uuid, ${fixture.tenant}::uuid,
        ${fixture.accountUser}::uuid, ${digest("continuation-receipt")}::bytea,
        7, 'tenant.login', 'api', 'tenant_platform_provider',
        ${fixture.provider}::uuid, ${fixture.binding}::uuid, 'oidc',
        ${fixture.account}::uuid, 1, 11, 'pending', 1, ${now}, ${expires}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_platform_federated_evidence (
        id, tenant_id, continuation_id, user_id, platform_provider_id,
        binding_id, external_identity_id, level, authenticated_at,
        expires_at, trust_rule_revision
      ) VALUES (
        ${fixture.continuationEvidence}::uuid, ${fixture.tenant}::uuid,
        ${fixture.continuation}::uuid, ${fixture.accountUser}::uuid,
        ${fixture.provider}::uuid, ${fixture.binding}::uuid,
        ${fixture.account}::uuid, 'primary', ${now}, ${expires},
        ${pins.securityRevision}::bigint
      )
    `;
  });
}

async function verifyTenantSwitchReplayLookup(): Promise<void> {
  await assert.rejects(
    admin`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds
      ) VALUES (
        ${fixture.replayPlatformFloor}::uuid,1,NULL,'platform_floor',
        'primary',false,0
      )
    `,
    (error: unknown) =>
      assertSqlState(
        error,
        "42501",
        "MFA policy revision writer capability is required",
      ),
    "a platform-floor fixture write bypassed the MFA policy capability",
  );
  await admin.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.replayPlatformFloor}:1`},
        true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds
      ) VALUES (
        ${fixture.replayPlatformFloor}::uuid,1,NULL,'platform_floor',
        'primary',false,0
      )
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1','',true)
    `;
  });
  const [pins] = await admin<
    {
      tenantVersion: number;
      membershipId: string;
      identityEpoch: number;
      sessionInvalidationEpoch: number;
      bindingId: string;
      bindingVersion: number;
      mappingRevision: number;
      authorizationRevision: number;
      accessEpochId: string;
      accessEpochVersion: number;
      accessSourceId: string;
      accessGrantId: string;
      accessGrantVersion: number;
      providerRevision: number;
      securityRevision: number;
      assurancePolicyRevision: number;
      loginPolicyRevision: number;
      identityVersion: number;
      userAuthenticationRevision: number;
      aliasKeyVersion: number;
      platformFloorId: string;
      platformFloorRevision: number;
    }[]
  >`
    SELECT tenant.version::integer AS "tenantVersion",
           membership.id::text AS "membershipId",
           subject.identity_epoch::integer AS "identityEpoch",
           subject.session_invalidation_epoch::integer
             AS "sessionInvalidationEpoch",
           binding.id::text AS "bindingId",
           binding.version::integer AS "bindingVersion",
           binding.mapping_revision::integer AS "mappingRevision",
           authorization_state.revision::integer AS "authorizationRevision",
           epoch.id::text AS "accessEpochId",
           epoch.version::integer AS "accessEpochVersion",
           epoch.source_id::text AS "accessSourceId",
           grant_row.id::text AS "accessGrantId",
           grant_row.version::integer AS "accessGrantVersion",
           provider.version::integer AS "providerRevision",
           runtime_policy.security_revision::integer AS "securityRevision",
           runtime_policy.assurance_policy_revision::integer
             AS "assurancePolicyRevision",
           login_policy.revision::integer AS "loginPolicyRevision",
           identity.version::integer AS "identityVersion",
           local_user.authentication_revision::integer
             AS "userAuthenticationRevision",
           alias.key_version AS "aliasKeyVersion",
           platform_floor.id::text AS "platformFloorId",
           platform_floor.revision::integer AS "platformFloorRevision"
    FROM public.tenants AS tenant
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = tenant.id
     AND membership.id = ${fixture.accountMembership}::uuid
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = tenant.id
     AND subject.user_id = membership.user_id
    JOIN public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = tenant.id
     AND binding.id = ${fixture.binding}::uuid
    JOIN public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = tenant.id
     AND epoch.id = binding.current_access_epoch_id
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id = tenant.id
    JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.tenant_id = tenant.id
     AND grant_row.id = ${fixture.grant}::uuid
     AND grant_row.access_epoch_id = epoch.id
    JOIN public.platform_auth_providers AS provider
      ON provider.id = binding.platform_provider_id
    JOIN public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
    JOIN public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    JOIN public.platform_federated_external_identities AS identity
      ON identity.id = grant_row.external_identity_id
    JOIN public.users AS local_user ON local_user.id = identity.user_id
    JOIN public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider.id
     AND alias.external_identity_id = identity.id
     AND alias.retired_at IS NULL
    JOIN public.mfa_policy_revisions AS platform_floor
      ON platform_floor.scope = 'platform_floor'
     AND platform_floor.tenant_id IS NULL
     AND platform_floor.retired_at IS NULL
    WHERE tenant.id = ${fixture.tenant}::uuid
  `;
  assert(pins, "tenant-switch replay pins were not found");

  const expectedVersion = 7;
  const occurredAt = new Date();
  const authenticatedAt = new Date(occurredAt.getTime() - 60_000);
  const idleExpiresAt = new Date(occurredAt.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(occurredAt.getTime() + 2 * 60 * 60_000);
  const sourceTokenDigest = digest("replay-source-token");
  const newTokenDigest = digest("replay-new-token");
  const csrfSecretDigest = digest("replay-new-csrf");
  const logoutMaterialId = nextUuid();
  const logoutTransactionId = digest("switched-logout-transaction");
  const logoutApplicationId = nextUuid();
  const logoutOperationId = nextUuid();
  const logoutRetryJobId = nextUuid();
  const logoutClaimExpiresAt = new Date(occurredAt.getTime() + 2 * 60_000);
  const replayResult = {
    applied: true,
    decision: "rotated",
    sourceSessionId: fixture.replaySourceSession,
    sessionId: fixture.replayRotatedSession,
    targetTenantId: fixture.tenant,
    sessionVersion: expectedVersion + 1,
  } as const;
  const replayAudit = {
    eventId: fixture.replayAudit,
    requestId: fixture.replayRequest,
    correlationId: fixture.replayCorrelation,
    ipAddress: "198.51.100.73",
    userAgent: "Periapsis tenant-switch response-loss replay proof",
    authenticationMethod: "oidc",
    reason: "Recover a committed tenant-switch response",
  } as const;

  await admin.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.platform_oidc_runtime_write_v1','on',true)
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,revoked_at,revoke_reason,
        rotated_from_session_id,created_at
      ) VALUES
        (${fixture.replaySourceSession}::uuid,${fixture.accountUser}::uuid,
         ${fixture.replayFamily}::uuid,NULL,${sourceTokenDigest}::bytea,
         ${digest("replay-source-csrf")}::bytea,'oidc',NULL,
         ${authenticatedAt},${idleExpiresAt},${absoluteExpiresAt},${occurredAt},
         'platform_oidc_tenant_switch_rotated',NULL,${authenticatedAt}),
        (${fixture.replayRotatedSession}::uuid,${fixture.accountUser}::uuid,
         ${fixture.replayFamily}::uuid,${fixture.tenant}::uuid,
         ${newTokenDigest}::bytea,${csrfSecretDigest}::bytea,'oidc',NULL,
         ${occurredAt},${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,
         ${fixture.replaySourceSession}::uuid,${occurredAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_platform_oidc_states (
        session_id,user_id,session_version,user_authentication_revision,
        recovery_restricted,audience,primary_kind,issued_at
      ) VALUES (
        ${fixture.replaySourceSession}::uuid,${fixture.accountUser}::uuid,
        ${expectedVersion},${pins.userAuthenticationRevision}::bigint,
        false,'api','platform_provider',${authenticatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_platform_oidc_provenance (
        session_id,user_id,primary_kind,platform_provider_id,
        external_identity_id,provider_revision,login_policy_revision,
        security_revision,user_authentication_revision,identity_version,
        alias_key_version,assurance_policy_revision,platform_floor_policy_id,
        platform_floor_policy_revision,trust_rule_id,trust_rule_revision,
        authenticated_at
      ) VALUES (
        ${fixture.replaySourceSession}::uuid,${fixture.accountUser}::uuid,
        'platform_provider',${fixture.provider}::uuid,${fixture.account}::uuid,
        ${pins.providerRevision}::bigint,${pins.loginPolicyRevision}::bigint,
        ${pins.securityRevision}::bigint,
        ${pins.userAuthenticationRevision}::bigint,
        ${pins.identityVersion}::bigint,${pins.aliasKeyVersion}::integer,
        ${pins.assurancePolicyRevision}::bigint,
        ${pins.platformFloorId}::uuid,${pins.platformFloorRevision}::bigint,
        NULL,NULL,${authenticatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_platform_oidc_evidence (
        id,session_id,user_id,kind,level,platform_provider_id,
        external_identity_id,authenticated_at,expires_at
      ) VALUES (
        ${fixture.replaySourceEvidence}::uuid,
        ${fixture.replaySourceSession}::uuid,${fixture.accountUser}::uuid,
        'platform_provider','primary',${fixture.provider}::uuid,
        ${fixture.account}::uuid,${authenticatedAt},${absoluteExpiresAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,
        session_invalidation_epoch,issued_at
      ) VALUES (
        ${fixture.replayRotatedSession}::uuid,${fixture.tenant}::uuid,
        ${fixture.accountUser}::uuid,${expectedVersion + 1},
        ${pins.identityEpoch}::bigint,false,'api','tenant_platform_provider',
        ${pins.sessionInvalidationEpoch}::bigint,${occurredAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_tenant_platform_federated_provenance (
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        platform_provider_id,binding_id,access_epoch_id,access_source_id,
        access_grant_id,membership_id,external_identity_id,
        external_identity_revision,provider_revision,binding_revision,
        security_revision,mapping_revision,authorization_revision,
        subject_alias_key_version,trust_rule_revision,authenticated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${fixture.replayRotatedSession}::uuid,
        ${fixture.accountUser}::uuid,'tenant_platform_provider','oidc',
        ${fixture.provider}::uuid,${pins.bindingId}::uuid,
        ${pins.accessEpochId}::uuid,${pins.accessSourceId}::uuid,
        ${pins.accessGrantId}::uuid,${pins.membershipId}::uuid,
        ${fixture.account}::uuid,${pins.identityVersion}::bigint,
        ${pins.providerRevision}::bigint,${pins.bindingVersion}::bigint,
        ${pins.securityRevision}::bigint,${pins.mappingRevision}::bigint,
        ${pins.authorizationRevision}::bigint,
        ${pins.aliasKeyVersion}::integer,${pins.securityRevision}::bigint,
        ${authenticatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_tenant_platform_federated_evidence (
        id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
        external_identity_id,level,authenticated_at,expires_at,
        trust_rule_revision
      ) VALUES (
        ${fixture.replayRotatedEvidence}::uuid,${fixture.tenant}::uuid,
        ${fixture.replayRotatedSession}::uuid,${fixture.accountUser}::uuid,
        ${fixture.provider}::uuid,${pins.bindingId}::uuid,
        ${fixture.account}::uuid,'primary',${authenticatedAt},
        ${absoluteExpiresAt},${pins.securityRevision}::bigint
      )
    `;
    await transaction`
      INSERT INTO public.platform_oidc_tenant_switch_commands (
        source_session_id,expected_version,target_tenant_id,
        target_tenant_version,membership_id,binding_id,binding_version,
        mapping_revision,authorization_revision,access_epoch_id,
        access_epoch_version,access_source_id,access_grant_id,
        access_grant_version,request_digest,decision,rotated_session_id,
        result_snapshot,applied_at
      ) VALUES (
        ${fixture.replaySourceSession}::uuid,${expectedVersion},
        ${fixture.tenant}::uuid,${pins.tenantVersion}::bigint,
        ${pins.membershipId}::uuid,${pins.bindingId}::uuid,
        ${pins.bindingVersion}::bigint,${pins.mappingRevision}::bigint,
        ${pins.authorizationRevision}::bigint,${pins.accessEpochId}::uuid,
        ${pins.accessEpochVersion}::bigint,${pins.accessSourceId}::uuid,
        ${pins.accessGrantId}::uuid,${pins.accessGrantVersion}::bigint,
        ${digest("replay-command")}::bytea,'rotated',
        ${fixture.replayRotatedSession}::uuid,
        ${transaction.json(replayResult)}::jsonb,${occurredAt}
      )
    `;
    await transaction`
      SELECT app.append_platform_audit_event(
        ${fixture.replayAudit}::uuid,'system'::public.audit_actor_type,NULL::uuid,
        'platform.oidc.session.tenant_switched'::text,'auth_session'::text,
        ${fixture.replaySourceSession}::uuid,${fixture.replayRequest}::uuid,
        ${fixture.replayCorrelation}::uuid,${replayAudit.ipAddress}::inet,
        ${replayAudit.userAgent}::text,'oidc'::text,
        'success'::public.audit_outcome,${replayAudit.reason}::text,
        jsonb_build_object(
          'provider_id',${fixture.provider}::uuid,
          'user_id',${fixture.accountUser}::uuid,
          'target_tenant_id',${fixture.tenant}::uuid,
          'decision','rotated','expected_version',${expectedVersion}::bigint
        )
      )
    `;

    // Material remains sealed to its direct-platform origin after the tenant
    // switch. Seed a completed historical source receipt, then exercise the
    // retry completion against the effective tenant owner. Keep this terminal
    // failure proof rollback-isolated so it cannot revoke the replay family or
    // retain historical material beyond the assertion.
    await transaction.unsafe("SAVEPOINT switched_logout_retry_audit");
    await transaction`
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
        ${logoutTransactionId}::bytea,${fixture.provider}::uuid,'oidc','oidc',
        ${logoutMaterialId}::uuid,${digest("switched-logout-operation")}::bytea,
        ${digest("switched-logout-receipt")}::bytea,
        ${digest("switched-logout-network")}::bytea,
        ${digest("switched-logout-account")}::bytea,
        ${digest("switched-logout-provider")}::bytea,
        ${digest("switched-logout-state")}::bytea,
        ${digest("switched-logout-browser")}::bytea,
        ${digest("switched-logout-browser-capability")}::bytea,
        ${digest("switched-logout-nonce")}::bytea,'S256',
        ${pins.providerRevision}::bigint,${pins.loginPolicyRevision}::bigint,
        1,${pins.securityRevision}::bigint,1,
        ${pins.assurancePolicyRevision}::bigint,
        ${pins.platformFloorId}::uuid,${pins.platformFloorRevision}::bigint,
        1,1,${digest("switched-logout-discovery")}::bytea,
        1,${digest("switched-logout-jwks")}::bytea,
        ${activeKeyVersion},${Buffer.alloc(32, 0x71)}::bytea,
        ${oidcConfiguration.clientId},
        'https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback',
        ${postLogoutRedirectUri},ARRAY['openid','offline_access']::text[],
        true,false,'/platform','pending',1,${authenticatedAt},
        ${new Date(authenticatedAt.getTime() + 10 * 60_000)}
      )
    `;
    await transaction`
      UPDATE public.platform_oidc_authentication_transactions
      SET state = 'claimed',version = 2,
          claim_attempt_id = ${digest("switched-logout-claim")}::bytea,
          authorization_code_digest =
            ${digest("switched-logout-authorization-code")}::bytea,
          claimed_at = ${occurredAt}
      WHERE transaction_id = ${logoutTransactionId}::bytea
    `;
    await transaction`
      UPDATE public.platform_oidc_authentication_transactions
      SET state = 'completed',version = 3,completed_at = ${occurredAt}
      WHERE transaction_id = ${logoutTransactionId}::bytea
    `;
    await transaction`
      INSERT INTO public.platform_oidc_authentication_applications (
        id,transaction_id,operation_digest,platform_provider_id,
        external_identity_id,category,primary_kind,user_id,session_id,
        continuation_id,request_snapshot,result_snapshot,applied_at
      ) VALUES (
        ${logoutApplicationId}::uuid,${logoutTransactionId}::bytea,
        ${digest("switched-logout-application")}::bytea,
        ${fixture.provider}::uuid,${fixture.account}::uuid,'success',
        'platform_provider',${fixture.accountUser}::uuid,
        ${fixture.replaySourceSession}::uuid,NULL,
        '{"category":"historical_direct_login"}'::jsonb,
        '{"category":"success"}'::jsonb,${occurredAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_session_materials (
        id,tenant_id,authority,session_id,continuation_id,
        rotation_family_id,user_id,provider_id,binding_id,provider_kind,
        external_identity_id,aad_version,id_token_key_version,
        id_token_ciphertext,id_token_digest,refresh_token_key_version,
        refresh_token_ciphertext,refresh_token_digest,refresh_generation,
        refresh_state,refresh_version,refresh_retry_attempt,
        access_expires_at,expires_at,client_secret_revision,
        client_authentication,client_id,token_endpoint,revocation_endpoint,
        end_session_endpoint,post_logout_redirect_uri,logout_disposition,
        logout_operation_run_id,logout_claimed_at,created_at,updated_at
      ) VALUES (
        ${logoutMaterialId}::uuid,NULL,'platform_provider',
        ${fixture.replaySourceSession}::uuid,NULL,${fixture.replayFamily}::uuid,
        ${fixture.accountUser}::uuid,${fixture.provider}::uuid,NULL,'oidc',
        ${fixture.account}::uuid,1,NULL,NULL,NULL,${activeKeyVersion},
        ${Buffer.alloc(48, 0x72)}::bytea,
        ${digest("switched-logout-refresh-token")}::bytea,1,'revoked',1,0,
        ${new Date(occurredAt.getTime() + 30 * 60_000)},${absoluteExpiresAt},
        1,'client_secret_basic',${oidcConfiguration.clientId},
        ${`${issuer}/token`},${`${issuer}/revoke`},NULL,
        ${postLogoutRedirectUri},'skipped',${logoutOperationId}::uuid,
        ${occurredAt},${occurredAt},${occurredAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_logout_commands (
        tenant_id,authority,operation_run_id,session_id,expected_version,
        request_upstream,material_id,request_digest,request_snapshot,
        result_snapshot,applied_at
      ) VALUES (
        ${fixture.tenant}::uuid,'tenant_platform_provider',
        ${logoutOperationId}::uuid,${fixture.replayRotatedSession}::uuid,
        ${expectedVersion + 1},true,${logoutMaterialId}::uuid,
        ${digest("switched-logout-command")}::bytea,
        '{"category":"local_logout"}'::jsonb,
        '{"category":"revoked_local_only"}'::jsonb,${occurredAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_logout_retry_jobs (
        id,tenant_id,authority,operation_run_id,material_id,
        session_family_id,state,attempt,maximum_attempts,not_before,
        claimed_at,claim_expires_at,completed_at,version,created_at,updated_at
      ) VALUES (
        ${logoutRetryJobId}::uuid,NULL,'platform_provider',
        ${logoutOperationId}::uuid,${logoutMaterialId}::uuid,
        ${fixture.replayFamily}::uuid,'claimed',1,8,${occurredAt},
        ${occurredAt},${logoutClaimExpiresAt},NULL,2,${occurredAt},${occurredAt}
      )
    `;
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    const [terminalRetry] = await transaction<{ completed: boolean }[]>`
      SELECT app.complete_tenant_oidc_logout_retry_v1(
        ${transaction.json({
          jobId: logoutRetryJobId,
          attempt: 1,
          expectedVersion: 2,
          outcome: "ambiguous",
          completedAt: new Date().toISOString(),
        })}::jsonb
      ) AS completed
    `;
    assert.equal(terminalRetry?.completed, true);
    await transaction.unsafe("RESET ROLE");
    const [terminalAudit] = await transaction<
      { tenantAudits: number; platformAudits: number; targetRevoked: boolean }[]
    >`
      SELECT
        (SELECT count(*)::integer FROM public.audit_events AS audit
         WHERE audit.tenant_id = ${fixture.tenant}::uuid
           AND audit.action = 'tenant.identity.oidc_logout_retry_terminal'
           AND audit.resource_id = ${fixture.replayRotatedSession}::uuid
           AND audit.metadata ->> 'material_id' = ${logoutMaterialId})
          AS "tenantAudits",
        (SELECT count(*)::integer FROM public.platform_audit_events AS audit
         WHERE audit.action = 'platform.identity.oidc_logout_retry_terminal'
           AND audit.resource_id = ${fixture.replaySourceSession}::uuid)
          AS "platformAudits",
        EXISTS (
          SELECT 1 FROM public.auth_sessions AS session
          WHERE session.id = ${fixture.replayRotatedSession}::uuid
            AND session.revoked_at IS NOT NULL
        ) AS "targetRevoked"
    `;
    assert.deepEqual(terminalAudit, {
      tenantAudits: 1,
      platformAudits: 0,
      targetRevoked: true,
    });
    await transaction.unsafe(
      "ROLLBACK TO SAVEPOINT switched_logout_retry_audit",
    );
    await transaction.unsafe("RELEASE SAVEPOINT switched_logout_retry_audit");
  });

  const lookup = {
    sourceSessionId: fixture.replaySourceSession,
    targetTenantId: fixture.tenant,
    newSessionId: fixture.replayRotatedSession,
    rotationFamilyId: fixture.replayFamily,
    sourceTokenDigest: sourceTokenDigest.toString("base64"),
    newTokenDigest: newTokenDigest.toString("base64"),
    csrfSecretDigest: csrfSecretDigest.toString("base64"),
    occurredAt: occurredAt.toISOString(),
    idleExpiresAt: idleExpiresAt.toISOString(),
    absoluteExpiresAt: absoluteExpiresAt.toISOString(),
    audit: replayAudit,
  } as const;
  const [matched] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ value: unknown }[]>`
      SELECT app.lookup_platform_oidc_tenant_switch_replay_v1(
        ${transaction.json(lookup)}::jsonb
      ) AS value
    `,
  );
  assert.deepEqual(matched?.value, { matched: true, result: replayResult });

  const [mismatched] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ value: unknown }[]>`
      SELECT app.lookup_platform_oidc_tenant_switch_replay_v1(
        ${transaction.json({
          ...lookup,
          newTokenDigest: digest("replay-wrong-token").toString("base64"),
        })}::jsonb
      ) AS value
    `,
  );
  assert.deepEqual(mismatched?.value, { matched: false });
  await assert.rejects(
    asRole(
      admin,
      "periapsis_worker",
      (transaction) => transaction`
      SELECT app.lookup_platform_oidc_tenant_switch_replay_v1(
        ${transaction.json(lookup)}::jsonb
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await admin`
    UPDATE ONLY public.auth_sessions
    SET revoked_at = transaction_timestamp(),
        revoke_reason = 'tenant_switch_replay_fixture_complete'
    WHERE id = ${fixture.replayRotatedSession}::uuid
      AND revoked_at IS NULL
  `;
}

async function representationPins(): Promise<{
  securityRevision: number;
  resourceVersion: number;
  userVersion: number;
  provenanceRevision: number;
  sourceSessionLive: boolean;
}> {
  const [pins] = await admin<
    {
      securityRevision: number;
      resourceVersion: number;
      userVersion: number;
      provenanceRevision: number;
      sourceSessionLive: boolean;
    }[]
  >`
    SELECT identity.version::integer AS "securityRevision",
           identity.resource_version::integer AS "resourceVersion",
           local_user.version::integer AS "userVersion",
           provenance.external_identity_revision::integer
             AS "provenanceRevision",
           session.revoked_at IS NULL
             AND identity.retired_at IS NULL
             AND identity.version = provenance.external_identity_revision
             AS "sourceSessionLive"
    FROM public.platform_federated_external_identities AS identity
    JOIN public.users AS local_user ON local_user.id = identity.user_id
    JOIN public.auth_session_tenant_platform_federated_provenance AS provenance
      ON provenance.platform_provider_id = identity.platform_provider_id
     AND provenance.external_identity_id = identity.id
     AND provenance.user_id = identity.user_id
    JOIN public.auth_sessions AS session ON session.id = provenance.session_id
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.id = ${fixture.account}::uuid
      AND provenance.session_id = ${fixture.sourceSession}::uuid
  `;
  assert(pins, "representation/provenance pins were not found");
  return pins;
}

async function verifyRepresentationVersioning(): Promise<void> {
  const initialDocument = await getAccount(fixture.account);
  assert.equal(compositeRepresentationValidator(initialDocument), '"v1-u1"');
  assert.equal(initialDocument.lastObservationState, "known");
  assert.equal(typeof initialDocument.lastObservedAt, "string");

  await assert.rejects(
    admin`
      UPDATE ONLY public.platform_federated_external_identities AS identity
      SET last_observation_state = 'legacy_unknown',
          updated_at = transaction_timestamp()
      WHERE identity.platform_provider_id = ${fixture.provider}::uuid
        AND identity.id = ${fixture.account}::uuid
    `,
    (error: unknown) =>
      assertSqlState(
        error,
        "23514",
        "platform federated identity transition is invalid",
      ),
  );
  assert.deepEqual(await getAccount(fixture.account), initialDocument);

  const [observed] = await admin<
    { securityRevision: number; resourceVersion: number }[]
  >`
    UPDATE ONLY public.platform_federated_external_identities AS identity
    SET last_observed_at = transaction_timestamp(),
        updated_at = transaction_timestamp()
    WHERE identity.platform_provider_id = ${fixture.provider}::uuid
      AND identity.id = ${fixture.account}::uuid
    RETURNING identity.version::integer AS "securityRevision",
              identity.resource_version::integer AS "resourceVersion"
  `;
  assert.deepEqual(observed, { securityRevision: 1, resourceVersion: 2 });

  const observedDocument = await getAccount(fixture.account);
  assert.equal(
    compositeRepresentationValidator(observedDocument),
    '"v2-u1"',
    "observation changed the representation validator",
  );
  assert.notEqual(
    observedDocument.lastObservedAt,
    initialDocument.lastObservedAt,
  );
  assert.equal(observedDocument.lastObservationState, "known");
  assert.equal(typeof observedDocument.lastObservedAt, "string");
  assert.deepEqual(await representationPins(), {
    securityRevision: 1,
    resourceVersion: 2,
    userVersion: 1,
    provenanceRevision: 1,
    sourceSessionLive: true,
  });

  const [updatedUser] = await admin<{ version: number }[]>`
    UPDATE ONLY public.users AS local_user
    SET display_name = 'Local account user refreshed'
    WHERE local_user.id = ${fixture.accountUser}::uuid
    RETURNING local_user.version::integer AS version
  `;
  assert.equal(updatedUser?.version, 2);

  const userUpdatedDocument = await getAccount(fixture.account);
  assert.equal(
    compositeRepresentationValidator(userUpdatedDocument),
    '"v2-u2"',
    "user projection changed the representation validator",
  );
  assert.equal(userUpdatedDocument.version, observedDocument.version);
  assert.deepEqual(object(userUpdatedDocument.user, "updated account user"), {
    id: fixture.accountUser,
    displayName: "Local account user refreshed",
    email: "platform-account.user@example.invalid",
    active: true,
    version: 2,
  });
  assert.deepEqual(
    await representationPins(),
    {
      securityRevision: 1,
      resourceVersion: 2,
      userVersion: 2,
      provenanceRevision: 1,
      sourceSessionLive: true,
    },
    "observation invalidated security provenance",
  );

  const [noOpUser] = await admin<{ version: number }[]>`
    UPDATE ONLY public.users AS local_user
    SET display_name = local_user.display_name
    WHERE local_user.id = ${fixture.accountUser}::uuid
    RETURNING local_user.version::integer AS version
  `;
  assert.equal(noOpUser?.version, 2);
  await assert.rejects(
    admin`
      UPDATE ONLY public.users AS local_user
      SET version = local_user.version + 1
      WHERE local_user.id = ${fixture.accountUser}::uuid
    `,
    (error: unknown) =>
      assertSqlState(
        error,
        "23514",
        "user projection version changed without its representation",
      ),
  );
  assert.deepEqual(await getAccount(fixture.account), userUpdatedDocument);
}

async function retirementSnapshot(): Promise<unknown> {
  const [snapshot] = await admin`
    SELECT
      (SELECT jsonb_build_object(
         'securityRevision', identity.version,
         'resourceVersion', identity.resource_version,
         'userVersion', (SELECT local_user.version
           FROM public.users AS local_user
           WHERE local_user.id = identity.user_id),
         'retiredAt', identity.retired_at,
         'lastObservationState', identity.last_observation_state,
         'lastObservedAt', identity.last_observed_at,
         'updatedAt', identity.updated_at)
       FROM public.platform_federated_external_identities AS identity
       WHERE identity.id = ${fixture.account}::uuid) AS account,
      (SELECT jsonb_agg(jsonb_build_object(
         'id', session.id, 'revokedAt', session.revoked_at,
         'reason', session.revoke_reason) ORDER BY session.id)
       FROM public.auth_sessions AS session
       WHERE session.id IN (
         ${fixture.sourceSession}::uuid, ${fixture.siblingSession}::uuid,
         ${fixture.unrelatedSession}::uuid
       )) AS sessions,
      (SELECT jsonb_build_object('state', continuation.state,
         'version', continuation.version, 'revokedAt', continuation.revoked_at)
       FROM public.tenant_post_primary_continuations AS continuation
       WHERE continuation.id = ${fixture.continuation}::uuid) AS continuation,
      (SELECT jsonb_build_object('version', grant_row.version,
         'endedAt', grant_row.ended_at)
       FROM public.tenant_platform_federated_provider_access_grants AS grant_row
       WHERE grant_row.id = ${fixture.grant}::uuid) AS grant,
      (SELECT jsonb_build_object('version', contribution.version,
         'retiredAt', contribution.retired_at)
       FROM public.tenant_platform_federated_provider_profile_contributions
         AS contribution
       WHERE contribution.id = ${fixture.contribution}::uuid) AS contribution,
      (SELECT jsonb_build_object('identityEpoch', subject.identity_epoch,
         'sessionInvalidationEpoch', subject.session_invalidation_epoch,
         'version', subject.version)
       FROM public.tenant_mfa_subjects AS subject
       WHERE subject.tenant_id = ${fixture.tenant}::uuid
         AND subject.user_id = ${fixture.accountUser}::uuid) AS subject,
      (SELECT membership.status
       FROM public.tenant_memberships AS membership
       WHERE membership.id = ${fixture.accountMembership}::uuid) AS membership,
      (SELECT jsonb_build_object('displayName', profile.display_name,
         'email', profile.email, 'version', profile.version)
       FROM public.tenant_user_profiles AS profile
       WHERE profile.tenant_id = ${fixture.tenant}::uuid
         AND profile.membership_id = ${fixture.accountMembership}::uuid) AS profile,
      (SELECT count(*)::integer
       FROM public.audit_events AS audit
       WHERE audit.resource_id = ${fixture.account}::uuid
         AND audit.action = 'tenant.platform_identity_account.retired')
        AS "tenantAudits",
      (SELECT count(*)::integer
       FROM public.platform_audit_events AS audit
       WHERE audit.resource_id = ${fixture.account}::uuid
         AND audit.action = 'platform.identity_account.retired')
        AS "platformAudits"
  `;
  assert(snapshot);
  return snapshot;
}

async function verifyRetirement(): Promise<void> {
  await seedRetirementDependencies();
  await verifyTenantSwitchReplayLookup();
  await verifyRepresentationVersioning();
  const baseline = await retirementSnapshot();
  const baselineAccount = object(
    object(baseline, "retirement baseline").account,
    "retirement baseline account",
  );

  await assert.rejects(
    retireAccount({ expectedVersion: 1, expectedUserVersion: 2 }),
    (error: unknown) =>
      assertSqlState(
        error,
        "40001",
        "platform identity account revision conflict",
      ),
  );
  assert.deepEqual(await retirementSnapshot(), baseline);

  await assert.rejects(
    retireAccount({ expectedVersion: 2, expectedUserVersion: 1 }),
    (error: unknown) =>
      assertSqlState(
        error,
        "40001",
        "platform identity account revision conflict",
      ),
  );
  assert.deepEqual(await retirementSnapshot(), baseline);

  await assert.rejects(
    retireAccount({
      accountId: nextUuid(),
      expectedVersion: 2,
      expectedUserVersion: 2,
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  assert.deepEqual(await retirementSnapshot(), baseline);

  await assert.rejects(
    retireAccount({
      expectedVersion: 2,
      expectedUserVersion: 2,
      auditEventId: fixture.accountAudit,
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  assert.deepEqual(
    await retirementSnapshot(),
    baseline,
    "failed final audit append did not roll back dependent invalidation",
  );

  const retired = await retireAccount({
    expectedVersion: 2,
    expectedUserVersion: 2,
  });
  assert.equal(retired.account_id, fixture.account);
  assert.equal(retired.version, 3);
  assert.equal(retired.document.state, "retired");
  assert.equal(retired.document.version, 3);
  assert.equal(retired.document.lastObservationState, "known");
  assert.equal(compositeRepresentationValidator(retired.document), '"v3-u2"');
  assert.equal(
    retired.document.lastObservedAt,
    baselineAccount.lastObservedAt,
    "retirement must preserve the last successful provider observation",
  );
  assert.equal(
    retired.document.lastObservationState,
    baselineAccount.lastObservationState,
    "retirement must preserve observation provenance",
  );
  assert.notEqual(retired.document.updatedAt, baselineAccount.updatedAt);

  const [effects] = await admin<
    {
      accountSecurityRevision: number;
      accountResourceVersion: number;
      userVersion: number;
      accountRetired: boolean;
      retiredAliases: number;
      sourceRevoked: boolean;
      siblingRevoked: boolean;
      unrelatedLive: boolean;
      continuationState: string;
      continuationVersion: number;
      grantEnded: boolean;
      grantVersion: number;
      contributionRetired: boolean;
      contributionVersion: number;
      identityEpoch: number;
      sessionInvalidationEpoch: number;
      subjectVersion: number;
      membershipStatus: string;
      profileDisplayName: string;
      profileEmail: string | null;
      provenanceRows: number;
      sessionEvidenceRows: number;
      continuationEvidenceRows: number;
      tenantAudits: number;
      platformAudits: number;
      unrelatedAccountLive: boolean;
    }[]
  >`
    SELECT
      identity.version::integer AS "accountSecurityRevision",
      identity.resource_version::integer AS "accountResourceVersion",
      local_user.version::integer AS "userVersion",
      identity.retired_at IS NOT NULL AS "accountRetired",
      (SELECT count(*)::integer
       FROM public.platform_federated_external_identity_aliases AS alias
       WHERE alias.external_identity_id = identity.id
         AND alias.retired_at IS NOT NULL) AS "retiredAliases",
      (SELECT revoked_at IS NOT NULL FROM public.auth_sessions
       WHERE id = ${fixture.sourceSession}::uuid) AS "sourceRevoked",
      (SELECT revoked_at IS NOT NULL FROM public.auth_sessions
       WHERE id = ${fixture.siblingSession}::uuid) AS "siblingRevoked",
      (SELECT revoked_at IS NULL FROM public.auth_sessions
       WHERE id = ${fixture.unrelatedSession}::uuid) AS "unrelatedLive",
      continuation.state AS "continuationState",
      continuation.version::integer AS "continuationVersion",
      grant_row.ended_at IS NOT NULL AS "grantEnded",
      grant_row.version::integer AS "grantVersion",
      contribution.retired_at IS NOT NULL AS "contributionRetired",
      contribution.version::integer AS "contributionVersion",
      subject.identity_epoch::integer AS "identityEpoch",
      subject.session_invalidation_epoch::integer AS "sessionInvalidationEpoch",
      subject.version::integer AS "subjectVersion",
      membership.status AS "membershipStatus",
      profile.display_name AS "profileDisplayName",
      profile.email AS "profileEmail",
      (SELECT count(*)::integer
       FROM public.auth_session_tenant_platform_federated_provenance
       WHERE session_id = ${fixture.sourceSession}::uuid) AS "provenanceRows",
      (SELECT count(*)::integer
       FROM public.auth_session_tenant_platform_federated_evidence
       WHERE id = ${fixture.sessionEvidence}::uuid) AS "sessionEvidenceRows",
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_platform_federated_evidence
       WHERE id = ${fixture.continuationEvidence}::uuid)
        AS "continuationEvidenceRows",
      (SELECT count(*)::integer FROM public.audit_events AS audit
       WHERE audit.resource_id = identity.id
         AND audit.action = 'tenant.platform_identity_account.retired')
        AS "tenantAudits",
      (SELECT count(*)::integer FROM public.platform_audit_events AS audit
       WHERE audit.resource_id = identity.id
         AND audit.action = 'platform.identity_account.retired')
        AS "platformAudits",
      (SELECT retired_at IS NULL
       FROM public.platform_federated_external_identities
       WHERE id = ${fixture.unrelatedAccount}::uuid) AS "unrelatedAccountLive"
    FROM public.platform_federated_external_identities AS identity
    JOIN public.users AS local_user ON local_user.id = identity.user_id
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id = ${fixture.continuation}::uuid
    JOIN public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.id = ${fixture.grant}::uuid
    JOIN public.tenant_platform_federated_provider_profile_contributions
      AS contribution ON contribution.id = ${fixture.contribution}::uuid
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = ${fixture.tenant}::uuid
     AND subject.user_id = ${fixture.accountUser}::uuid
    JOIN public.tenant_memberships AS membership
      ON membership.id = ${fixture.accountMembership}::uuid
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id = membership.tenant_id
     AND profile.membership_id = membership.id
    WHERE identity.id = ${fixture.account}::uuid
  `;
  assert.deepEqual(effects, {
    accountSecurityRevision: 2,
    accountResourceVersion: 3,
    userVersion: 2,
    accountRetired: true,
    retiredAliases: 1,
    sourceRevoked: true,
    siblingRevoked: true,
    unrelatedLive: true,
    continuationState: "revoked",
    continuationVersion: 2,
    grantEnded: true,
    grantVersion: 2,
    contributionRetired: true,
    contributionVersion: 2,
    identityEpoch: 8,
    sessionInvalidationEpoch: 12,
    subjectVersion: 4,
    membershipStatus: "suspended",
    profileDisplayName: "Local account user refreshed",
    profileEmail: "platform-account.user@example.invalid",
    provenanceRows: 1,
    sessionEvidenceRows: 1,
    continuationEvidenceRows: 1,
    tenantAudits: 1,
    platformAudits: 1,
    unrelatedAccountLive: true,
  });

  const [auditSafety] = await admin<
    {
      tenantActorType: string;
      tenantActorUserId: string | null;
      linkedPlatformAudit: string;
      platformActorUserId: string;
      tenantSubjectLeak: boolean;
      platformSubjectLeak: boolean;
      tenantBefore: unknown;
      tenantAfter: unknown;
      tenantMetadata: unknown;
      platformMetadata: unknown;
    }[]
  >`
    SELECT tenant_audit.actor_type AS "tenantActorType",
           tenant_audit.actor_user_id::text AS "tenantActorUserId",
           tenant_audit.metadata->>'platform_audit_event_id'
             AS "linkedPlatformAudit",
           platform_audit.actor_user_id::text AS "platformActorUserId",
           (tenant_audit.before::text || tenant_audit.after::text ||
             tenant_audit.metadata::text) ~*
             '(subject|ciphertext|nonce|digest)' AS "tenantSubjectLeak",
           platform_audit.metadata::text ~*
              '(subject_ciphertext|subject_nonce|subject_digest)'
              AS "platformSubjectLeak",
           tenant_audit.before AS "tenantBefore",
           tenant_audit.after AS "tenantAfter",
           tenant_audit.metadata AS "tenantMetadata",
           platform_audit.metadata AS "platformMetadata"
    FROM public.audit_events AS tenant_audit
    JOIN public.platform_audit_events AS platform_audit
      ON platform_audit.id =
         (tenant_audit.metadata->>'platform_audit_event_id')::uuid
    WHERE tenant_audit.resource_id = ${fixture.account}::uuid
      AND tenant_audit.action = 'tenant.platform_identity_account.retired'
  `;
  assert(auditSafety);
  assert.equal(auditSafety.tenantActorType, "system");
  assert.equal(auditSafety.tenantActorUserId, null);
  assert.equal(auditSafety.platformActorUserId, fixture.operator);
  assert.equal(auditSafety.tenantSubjectLeak, false);
  assert.equal(auditSafety.platformSubjectLeak, false);
  assert.deepEqual(auditSafety.tenantBefore, {
    account_id: fixture.account,
    provider_id: fixture.provider,
    state: "active",
  });
  assert.deepEqual(auditSafety.tenantAfter, {
    account_id: fixture.account,
    provider_id: fixture.provider,
    state: "retired",
    ended_access_grant_count: 1,
  });
  assert.deepEqual(auditSafety.tenantMetadata, {
    platform_actor_user_id: fixture.operator,
    platform_audit_event_id: auditSafety.linkedPlatformAudit,
    platform_provider_id: fixture.provider,
  });
  assert.deepEqual(auditSafety.platformMetadata, {
    provider_id: fixture.provider,
    user_id: fixture.accountUser,
    previous_version: 2,
    version: 3,
    user_version: 2,
    previous_security_revision: 1,
    security_revision: 2,
    affected_tenant_count: 1,
    ended_access_grant_count: 1,
    revoked_session_count: 2,
    revoked_continuation_count: 1,
    subject_material_included: false,
  });

  assert.equal((await getAccount(fixture.account)).state, "retired");
  assert.deepEqual(
    (await listAccounts(false)).map((document) => document.id),
    [fixture.unrelatedAccount],
  );
  assert.deepEqual(
    (await listAccounts(true))
      .map((document) => document.id)
      .toSorted((left, right) => String(left).localeCompare(String(right))),
    [fixture.account, fixture.unrelatedAccount].toSorted((left, right) =>
      left.localeCompare(right),
    ),
  );

  const retiredSnapshot = await retirementSnapshot();
  const replay = await prelink({
    commandId: nextUuid(),
    accountId: nextUuid(),
    userId: fixture.accountUser,
    aliases: [
      { keyVersion: activeKeyVersion, digest: digest("subject-primary") },
    ],
    keyDigest: digest("account-key"),
    publicRequestDigest: digest("account-request"),
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.version, 1);
  assert.equal(replay.document.state, "retired");
  assert.equal(replay.document.version, 3);
  assert.equal(compositeRepresentationValidator(replay.document), '"v3-u2"');
  assert.deepEqual(await retirementSnapshot(), retiredSnapshot);

  await assert.rejects(
    retireAccount({ expectedVersion: 2, expectedUserVersion: 2 }),
    (error: unknown) =>
      assertSqlState(
        error,
        "40001",
        "platform identity account revision conflict",
      ),
  );
  await assert.rejects(
    retireAccount({ expectedVersion: 3, expectedUserVersion: 2 }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  assert.deepEqual(await retirementSnapshot(), retiredSnapshot);

  const [updatedRetiredUser] = await admin<{ version: number }[]>`
    UPDATE ONLY public.users AS local_user
    SET email = 'platform-account.user-refreshed@example.invalid'
    WHERE local_user.id = ${fixture.accountUser}::uuid
    RETURNING local_user.version::integer AS version
  `;
  assert.equal(updatedRetiredUser?.version, 3);
  const retiredUserDocument = await getAccount(fixture.account);
  assert.equal(retiredUserDocument.state, "retired");
  assert.equal(retiredUserDocument.version, 3);
  assert.equal(
    object(retiredUserDocument.user, "retired account user").email,
    "platform-account.user-refreshed@example.invalid",
  );
  assert.equal(
    compositeRepresentationValidator(retiredUserDocument),
    '"v3-u3"',
  );
  const [retiredVersions] = await admin<
    { securityRevision: number; resourceVersion: number; userVersion: number }[]
  >`
    SELECT identity.version::integer AS "securityRevision",
           identity.resource_version::integer AS "resourceVersion",
           local_user.version::integer AS "userVersion"
    FROM public.platform_federated_external_identities AS identity
    JOIN public.users AS local_user ON local_user.id = identity.user_id
    WHERE identity.id = ${fixture.account}::uuid
  `;
  assert.deepEqual(retiredVersions, {
    securityRevision: 2,
    resourceVersion: 3,
    userVersion: 3,
  });
}

try {
  const [version] = await admin<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(version?.version.startsWith("18."));
  await seedBase();
  await verifyAclAndRls();
  await verifyPrelinkReplayAndAuthorization();
  await verifyRetirement();
  process.stdout.write("platform identity-account runtime proof passed\n");
} finally {
  await admin.end();
}
