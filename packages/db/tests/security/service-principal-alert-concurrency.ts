import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";
import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & {
  code?: string;
  constraint_name?: string;
};

type AccountMutation = {
  result_resource_id: string;
  result_version: number;
};

type CredentialMutation = {
  result_credential_id: string;
  result_version: number;
  replayed: boolean;
};

type AlertResult = {
  id: string;
  external_id: string | null;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  created_by_user_id: string | null;
  created_by_membership_id: string | null;
  created_by_service_account_id: string | null;
  created_at: Date | string;
  updated_at: Date | string;
  version: number;
  replayed: boolean;
};

type CredentialProof = {
  accountID: string;
  credentialID: string;
  label: string;
  locator: Buffer;
  keyVersion: number;
  secretDigest: Buffer;
  expiresAt: Date;
  permissionKeys: string[];
  scopes: string[];
  networks: string[];
};

function uuid(sequence: number): string {
  return `01994120-0000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
}

const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  peerAdminUser: uuid(102),
  limitedUser: uuid(103),
  foreignAdminUser: uuid(104),
  adminMembership: uuid(201),
  peerAdminMembership: uuid(202),
  limitedMembership: uuid(203),
  foreignAdminMembership: uuid(204),
  peerAdminGrant: uuid(301),
  machineHumanGrantAttempt: uuid(302),
  primaryAccount: uuid(1001),
  peerAccount: uuid(1002),
  grantLossAccount: uuid(1003),
  sourceLossAccount: uuid(1004),
  archiveLossAccount: uuid(1005),
  policyLossAccount: uuid(1006),
  suspensionLossAccount: uuid(1007),
  revokeRaceAccount: uuid(1008),
  archiveRaceAccount: uuid(1009),
  expiredAccount: uuid(1010),
  cidrAccount: uuid(1011),
  foreignAccount: uuid(1012),
  cidrOrderAccount: uuid(1013),
  supersessionAuditAccount: uuid(1014),
  primaryGrant: uuid(1101),
  peerGrant: uuid(1102),
  grantLossGrant: uuid(1103),
  sourceLossGrant: uuid(1104),
  archiveLossGrant: uuid(1105),
  policyLossGrant: uuid(1106),
  suspensionLossGrant: uuid(1107),
  revokeRaceGrant: uuid(1108),
  archiveRaceGrant: uuid(1109),
  expiredGrant: uuid(1110),
  cidrGrant: uuid(1111),
  foreignGrant: uuid(1112),
  cidrOrderGrant: uuid(1113),
  supersededAuditGrant: uuid(1114),
  replacementAuditGrant: uuid(1115),
  sourceLossSource: uuid(1201),
  primaryCredential: uuid(2001),
  primaryCredentialReplayAttempt: uuid(2002),
  primaryReplacementCredential: uuid(2003),
  primaryReplacementReplayAttempt: uuid(2004),
  peerCredential: uuid(2005),
  grantLossCredential: uuid(2006),
  sourceLossCredential: uuid(2007),
  archiveLossCredential: uuid(2008),
  policyLossCredential: uuid(2009),
  suspensionLossCredential: uuid(2010),
  revokeRaceCredential: uuid(2011),
  archiveRaceCredential: uuid(2012),
  expiredCredential: uuid(2013),
  cidrCredential: uuid(2014),
  foreignCredential: uuid(2015),
  cidrOrderCredential: uuid(2016),
  cidrOrderReplacementCredential: uuid(2017),
  rollbackHumanAuditMarker: uuid(3001),
  rollbackBearerAuditMarker: uuid(3002),
} as const;

const humanTraceParent =
  "00-11111111111111111111111111111111-2222222222222222-01";
const bearerTraceParent =
  "00-33333333333333333333333333333333-4444444444444444-01";
const persistedTraceState = "vendor=value";

const fixtureNames = {
  tenantSlug: "service-principal-alert-live-c7",
  foreignTenantSlug: "service-principal-alert-foreign-c7",
  emailPattern: "service-principal-c7.%@example.invalid",
  accountKeyPattern: "sp_c7_%",
  sourceKey: "identity.service_principal_c7",
} as const;

function digest(byte: number): Buffer {
  return Buffer.alloc(32, byte);
}

function locator(byte: number): Buffer {
  return Buffer.alloc(16, byte);
}

let requestSequence = 10_000;

function requestContext(): {
  requestID: string;
  correlationID: string;
} {
  requestSequence += 2;
  return {
    requestID: uuid(requestSequence - 1),
    correlationID: uuid(requestSequence),
  };
}

function assertSqlState(
  error: unknown,
  expected: string,
  expectedConstraint?: string,
  expectedMessage?: RegExp,
): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  const sqlError = error as ErrorWithCode;
  assert.equal(sqlError.code, expected, sqlError.message);
  if (expectedConstraint !== undefined) {
    assert.equal(sqlError.constraint_name, expectedConstraint);
  }
  if (expectedMessage !== undefined) {
    assert.match(sqlError.message, expectedMessage);
  }
  return true;
}

function withTimeout<T>(
  promise: Promise<T>,
  message: string,
  timeoutMilliseconds = 20_000,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(message)),
      timeoutMilliseconds,
    );
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function setApiRole(transaction: postgres.TransactionSql): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction.unsafe("SET LOCAL lock_timeout = '12s'");
}

async function setApiContext(
  transaction: postgres.TransactionSql,
  userID: string,
  tenantID: string = fixture.tenant,
): Promise<void> {
  await setApiRole(transaction);
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantID}, true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function backendPID(
  transaction: postgres.TransactionSql,
): Promise<number> {
  const [backend] = await transaction<{ pid: number }[]>`
    SELECT pg_catalog.pg_backend_pid() AS pid
  `;
  assert(backend, "transaction has no PostgreSQL backend PID");
  return backend.pid;
}

async function waitForRowLock(sql: Sql, processID: number): Promise<void> {
  const deadline = Date.now() + 12_000;
  const poll = async (): Promise<void> => {
    const [activity] = await sql<
      {
        state: string;
        wait_event_type: string | null;
        wait_event: string | null;
      }[]
    >`
      SELECT state, wait_event_type, wait_event
      FROM pg_catalog.pg_stat_activity
      WHERE pid = ${processID}
    `;
    if (activity?.wait_event_type === "Lock") {
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(`backend ${processID} did not wait on a PostgreSQL lock`);
    }
    await delay(20);
    return poll();
  };
  return poll();
}

async function createAccount(
  transaction: postgres.TransactionSql,
  accountID: string,
  key: string,
  displayName: string,
): Promise<AccountMutation> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<AccountMutation[]>`
    SELECT *
    FROM app.create_tenant_service_account_v1(
      ${accountID}::uuid,
      ${key},
      ${displayName},
      'Executable PostgreSQL 18.6 service-principal security proof.',
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    )
  `;
  assert(result, "create_tenant_service_account_v1 returned no result");
  return result;
}

async function grantMachineRole(
  transaction: postgres.TransactionSql,
  grantID: string,
  accountID: string,
  roleID: string,
): Promise<AccountMutation> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<AccountMutation[]>`
    SELECT *
    FROM app.grant_tenant_service_account_role_v1(
      ${grantID}::uuid,
      ${accountID}::uuid,
      ${roleID}::uuid,
      'Executable exact machine-role authority proof.',
      NULL,
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    )
  `;
  assert(result, "grant_tenant_service_account_role_v1 returned no result");
  return result;
}

async function issueCredential(
  transaction: postgres.TransactionSql,
  proof: CredentialProof,
  keyDigest: Buffer,
  requestDigest: Buffer,
): Promise<CredentialMutation> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<CredentialMutation[]>`
    SELECT *
    FROM app.issue_tenant_api_credential_v1(
      ${proof.credentialID}::uuid,
      ${proof.accountID}::uuid,
      ${keyDigest}::bytea,
      ${requestDigest}::bytea,
      ${proof.label},
      1,
      ${proof.locator}::bytea,
      ${proof.keyVersion},
      ${proof.secretDigest}::bytea,
      ${proof.expiresAt}::timestamptz,
      ${proof.permissionKeys}::text[],
      ${proof.scopes}::public.authorization_scope[],
      ${proof.networks}::cidr[],
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    )
  `;
  assert(result, "issue_tenant_api_credential_v1 returned no result");
  return result;
}

async function rotateCredential(
  transaction: postgres.TransactionSql,
  replacement: CredentialProof,
  predecessorID: string,
  predecessorVersion: number,
  keyDigest: Buffer,
  requestDigest: Buffer,
): Promise<CredentialMutation> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<CredentialMutation[]>`
    SELECT *
    FROM app.rotate_tenant_api_credential_v1(
      ${replacement.credentialID}::uuid,
      ${replacement.accountID}::uuid,
      ${predecessorID}::uuid,
      ${predecessorVersion},
      ${keyDigest}::bytea,
      ${requestDigest}::bytea,
      ${replacement.label},
      1,
      ${replacement.locator}::bytea,
      ${replacement.keyVersion},
      ${replacement.secretDigest}::bytea,
      ${replacement.expiresAt}::timestamptz,
      ${replacement.permissionKeys}::text[],
      ${replacement.scopes}::public.authorization_scope[],
      ${replacement.networks}::cidr[],
      'Rotate after one-time issuance proof.',
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    )
  `;
  assert(result, "rotate_tenant_api_credential_v1 returned no result");
  return result;
}

async function revokeCredential(
  transaction: postgres.TransactionSql,
  accountID: string,
  credentialID: string,
  expectedVersion: number,
  reason: string,
): Promise<number> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.revoke_tenant_api_credential_v1(
      ${accountID}::uuid,
      ${credentialID}::uuid,
      ${expectedVersion},
      ${reason},
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    ) AS version
  `;
  assert(result, "revoke_tenant_api_credential_v1 returned no result");
  return result.version;
}

async function revokeMachineGrant(
  transaction: postgres.TransactionSql,
  accountID: string,
  grantID: string,
  expectedVersion: number,
): Promise<number> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.revoke_tenant_service_account_role_grant_v1(
      ${accountID}::uuid,
      ${grantID}::uuid,
      ${expectedVersion},
      'Withdraw live service-account authority.',
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    ) AS version
  `;
  assert(
    result,
    "revoke_tenant_service_account_role_grant_v1 returned no result",
  );
  return result.version;
}

async function archiveAccount(
  transaction: postgres.TransactionSql,
  accountID: string,
  expectedVersion: number,
): Promise<number> {
  const { requestID, correlationID } = requestContext();
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.archive_tenant_service_account_v1(
      ${accountID}::uuid,
      ${expectedVersion},
      'Archive permanently withdraws machine authority.',
      ${requestID}::uuid,
      ${correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp'
    ) AS version
  `;
  assert(result, "archive_tenant_service_account_v1 returned no result");
  return result.version;
}

async function createHumanAlert(
  transaction: postgres.TransactionSql,
  title: string,
  description: string | null,
  externalID: string | null,
  severity: string,
  keyDigest: Buffer,
  requestDigest: Buffer,
  requestID?: string,
): Promise<AlertResult> {
  const context = requestContext();
  const [result] = await transaction<AlertResult[]>`
    SELECT *
    FROM app.create_tenant_alert_as_human_v3(
      ${title},
      ${description},
      ${externalID},
      ${severity}::public.alert_severity,
      'security_proof',
      'service_principal_security',
      NULL,
      '{}'::jsonb,
      'medium',
      'general',
      NULL,
      NULL,
      false,
      ARRAY[]::text[],
      '{}'::jsonb,
      NULL,
      NULL,
      NULL,
      ${keyDigest}::bytea,
      ${requestDigest}::bytea,
      ${requestID ?? context.requestID}::uuid,
      ${context.correlationID}::uuid,
      '192.0.2.80'::inet,
      'Periapsis service-principal concurrency proof',
      'totp',
      ${humanTraceParent},
      ${persistedTraceState}
    )
  `;
  assert(result, "create_tenant_alert_as_human_v3 returned no result");
  return result;
}

async function createBearerAlert(
  transaction: postgres.TransactionSql,
  proof: CredentialProof,
  title: string,
  description: string | null,
  externalID: string | null,
  severity: string,
  keyDigest: Buffer,
  requestDigest: Buffer,
  clientAddress = "192.0.2.80",
  requestID?: string,
  userAgent = "Periapsis service-principal concurrency proof",
  tenantID?: string,
): Promise<AlertResult> {
  const context = requestContext();
  const [result] = await transaction<AlertResult[]>`
    SELECT *
    FROM app.create_tenant_alert_as_service_account_v3(
      ${
        tenantID ??
        (proof.accountID === fixture.foreignAccount
          ? fixture.foreignTenant
          : fixture.tenant)
      }::uuid,
      ${proof.locator}::bytea,
      ${proof.keyVersion},
      ${proof.secretDigest}::bytea,
      ${clientAddress}::inet,
      ${title},
      ${description},
      ${externalID},
      ${severity}::public.alert_severity,
      'service_account',
      'service_principal_security',
      NULL,
      '{}'::jsonb,
      'medium',
      'general',
      NULL,
      NULL,
      false,
      ARRAY[]::text[],
      '{}'::jsonb,
      NULL,
      NULL,
      NULL,
      ${keyDigest}::bytea,
      ${requestDigest}::bytea,
      ${requestID ?? context.requestID}::uuid,
      ${context.correlationID}::uuid,
      ${userAgent},
      ${bearerTraceParent},
      ${persistedTraceState}
    )
  `;
  assert(
    result,
    "create_tenant_alert_as_service_account_v3 returned no result",
  );
  return result;
}

function liveCredential(
  accountID: string,
  credentialID: string,
  byte: number,
  keyVersion: number,
  label: string,
  networks: string[] = [],
): CredentialProof {
  return {
    accountID,
    credentialID,
    label,
    locator: locator(byte),
    keyVersion,
    secretDigest: digest(byte),
    expiresAt: new Date(Date.now() + 60 * 60 * 1_000),
    permissionKeys: ["alert.create"],
    scopes: ["tenant"],
    networks,
  };
}

async function getCredentialVersion(
  sql: Sql,
  userID: string,
  accountID: string,
  credentialID: string,
  tenantID: string = fixture.tenant,
): Promise<number> {
  return sql.begin(async (transaction) => {
    await setApiContext(transaction, userID, tenantID);
    const [credential] = await transaction<{ version: number }[]>`
      SELECT version
      FROM app.get_tenant_api_credential_v1(
        ${accountID}::uuid,
        ${credentialID}::uuid
      )
    `;
    assert(credential, "redacted credential metadata is missing");
    return credential.version;
  });
}

async function assertBearerRejected(
  sql: Sql,
  proof: CredentialProof,
  expectedState: string,
  keyByte: number,
  tenantID?: string,
): Promise<void> {
  await assert.rejects(
    sql.begin(async (transaction) => {
      await setApiRole(transaction);
      await createBearerAlert(
        transaction,
        proof,
        "Rejected bearer Alert",
        null,
        null,
        "high",
        digest(keyByte),
        digest(keyByte + 1),
        "192.0.2.80",
        undefined,
        "Periapsis rejected bearer proof",
        tenantID,
      );
    }),
    (error: unknown) => assertSqlState(error, expectedState),
  );
}

const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const observer = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const heldReleases = new Set<() => void>();

try {
  const [server] = await admin<
    { server_version: string; server_version_num: number }[]
  >`
    SELECT current_setting('server_version') AS server_version,
           current_setting('server_version_num')::integer AS server_version_num
  `;
  assert(server, "PostgreSQL version probe returned no row");
  assert.equal(server.server_version, "18.6");
  assert.equal(server.server_version_num, 180_006);

  const [journal] = await admin<
    {
      applied_count: number | string;
      latest_created_at: number | string;
      latest_hash: string;
      latest_rows: number | string;
      migration_fingerprint: string;
    }[]
  >`
    SELECT count(*)::bigint AS applied_count,
           max(migration.created_at)::bigint AS latest_created_at,
           count(*) FILTER (
             WHERE migration.created_at = latest.value
           )::bigint AS latest_rows,
           (
             SELECT lower(last_migration.hash::text)
             FROM drizzle.__drizzle_migrations AS last_migration
             ORDER BY last_migration.created_at DESC, last_migration.id DESC
             LIMIT 1
           ) AS latest_hash,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at, migration.id
           ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
    CROSS JOIN LATERAL (
      SELECT max(candidate.created_at)::bigint AS value
      FROM drizzle.__drizzle_migrations AS candidate
    ) AS latest
  `;
  assert(journal, "migration journal returned no row");
  assert.equal(Number(journal.applied_count), expectedMigrationCount);
  assert.equal(Number(journal.latest_created_at), expectedMigrationCreatedAt);
  assert.equal(Number(journal.latest_rows), 1);
  assert.equal(journal.latest_hash, expectedMigrationHash);
  assert.equal(journal.migration_fingerprint, expectedMigrationFingerprint);

  const currentCompatibility = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    const [result] = await transaction<
      {
        applied_count: number | string;
        latest_created_at: number | string;
        latest_hash: string;
        migration_fingerprint: string;
      }[]
    >`SELECT * FROM app.schema_compatibility_v50()`;
    assert(result, "schema_compatibility_v50 returned no row");
    return result;
  });
  assert.deepEqual(
    {
      applied_count: Number(currentCompatibility.applied_count),
      latest_created_at: Number(currentCompatibility.latest_created_at),
      latest_hash: currentCompatibility.latest_hash,
      migration_fingerprint: currentCompatibility.migration_fingerprint,
    },
    {
      applied_count: expectedMigrationCount,
      latest_created_at: expectedMigrationCreatedAt,
      latest_hash: expectedMigrationHash,
      migration_fingerprint: expectedMigrationFingerprint,
    },
    "the API runtime must observe the exact sealed V50 manifest",
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`SELECT * FROM app.schema_compatibility_v48()`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
    "the retired V48 predecessor must not remain executable by the API runtime",
  );

  const [collision] = await admin<{ count: number }[]>`
    SELECT (
      (SELECT count(*) FROM public.tenants
       WHERE id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
          OR slug IN (${fixtureNames.tenantSlug}, ${fixtureNames.foreignTenantSlug}))
      +
      (SELECT count(*) FROM public.users
       WHERE id IN (
         ${fixture.adminUser}::uuid,
         ${fixture.peerAdminUser}::uuid,
         ${fixture.limitedUser}::uuid,
         ${fixture.foreignAdminUser}::uuid
       ) OR email LIKE ${fixtureNames.emailPattern})
      +
      (SELECT count(*) FROM public.tenant_service_accounts
       WHERE id BETWEEN ${fixture.primaryAccount}::uuid AND ${fixture.supersessionAuditAccount}::uuid
          OR key LIKE ${fixtureNames.accountKeyPattern})
    )::integer AS count
  `;
  assert.equal(
    collision?.count,
    0,
    "service-principal proof requires a fresh disposable database",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction.unsafe("SET LOCAL statement_timeout = '30s'");
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.tenant}::uuid, ${fixtureNames.tenantSlug}, 'Service-principal Alert proof'),
        (${fixture.foreignTenant}::uuid, ${fixtureNames.foreignTenantSlug}, 'Foreign service-principal proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active)
      VALUES
        (${fixture.adminUser}::uuid, 'service-principal-c7.admin@example.invalid', 'Service principal administrator', true),
        (${fixture.peerAdminUser}::uuid, 'service-principal-c7.peer@example.invalid', 'Peer Alert administrator', true),
        (${fixture.limitedUser}::uuid, 'service-principal-c7.limited@example.invalid', 'Human without machine administration', true),
        (${fixture.foreignAdminUser}::uuid, 'service-principal-c7.foreign@example.invalid', 'Foreign service principal administrator', true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.peerAdminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.peerAdminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.limitedMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.limitedUser}::uuid, 'analyst', 'active'),
        (${fixture.foreignAdminMembership}::uuid, ${fixture.foreignTenant}::uuid, ${fixture.foreignAdminUser}::uuid, 'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,
        ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,
        ${fixture.foreignAdminMembership}::uuid
      )
    `;

    const [mainAuthority] = await transaction<
      { manual_source_id: string; admin_role_id: string }[]
    >`
      SELECT source.id AS manual_source_id, role.id AS admin_role_id
      FROM public.tenant_authorization_sources AS source
      CROSS JOIN public.tenant_roles AS role
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.key = 'manual'
        AND role.tenant_id = source.tenant_id
        AND role.key = 'tenant_admin'
        AND role.principal_kind = 'human'
    `;
    assert(mainAuthority, "main tenant authorization seed is incomplete");
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.peerAdminGrant}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.peerAdminMembership}::uuid,
        ${mainAuthority.admin_role_id}::uuid,
        ${mainAuthority.manual_source_id}::uuid,
        ${fixture.adminMembership}::uuid,
        'Independent human principal Alert idempotency proof.'
      )
    `;
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await transaction`SELECT app.context_tenant_id()`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await transaction`SELECT set_config('app.tenant_id', 'not-a-uuid', true)`;
      await transaction`SELECT app.context_tenant_id()`;
    }),
    (error: unknown) => assertSqlState(error, "22P02"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(
        transaction,
        fixture.adminUser,
        fixture.foreignTenant,
      );
      await transaction`SELECT app.current_tenant_membership_id()`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [activeContext] = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return transaction<{ membership_id: string }[]>`
      SELECT app.current_tenant_membership_id() AS membership_id
    `;
  });
  assert.equal(activeContext?.membership_id, fixture.adminMembership);

  const { mainMachineRoleID } = await setupServicePrincipalFixtures();

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_service_account_role_grants (
        id, tenant_id, service_account_id, role_id, role_principal_kind,
        source_id, granted_by_membership_id, grant_reason, granted_at,
        expires_at, version
      )
      SELECT
        ${fixture.supersededAuditGrant}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.supersessionAuditAccount}::uuid,
        ${mainMachineRoleID}::uuid,
        'service_account',
        source.id,
        ${fixture.adminMembership}::uuid,
        'Expired predecessor used to prove complete supersession audit.',
        transaction_timestamp() - interval '2 minutes',
        transaction_timestamp() - interval '1 minute',
        7
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.key = 'manual'
        AND source.kind = 'manual'
        AND source.protected
        AND source.retired_at IS NULL
    `;
  });

  const replacementAuditGrant = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return grantMachineRole(
      transaction,
      fixture.replacementAuditGrant,
      fixture.supersessionAuditAccount,
      mainMachineRoleID,
    );
  });
  assert.deepEqual(replacementAuditGrant, {
    result_resource_id: fixture.replacementAuditGrant,
    result_version: 1,
  });

  const [supersededAuditGrant] = await admin<
    { version: number; revoked: boolean; revoke_reason: string | null }[]
  >`
    SELECT version,
           revoked_at IS NOT NULL AS revoked,
           revoke_reason
    FROM public.tenant_service_account_role_grants
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.supersededAuditGrant}::uuid
  `;
  assert.deepEqual(supersededAuditGrant, {
    version: 8,
    revoked: true,
    revoke_reason:
      "Superseded after the prior manual service-account role grant expired.",
  });

  const supersessionAudits = await admin<{ superseded_role_grants: unknown }[]>`
    SELECT metadata -> 'superseded_role_grants' AS superseded_role_grants
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'tenant.service_account.role_granted'
      AND resource_id = ${fixture.replacementAuditGrant}::uuid
  `;
  assert.equal(supersessionAudits.length, 1);
  assert.deepEqual(supersessionAudits[0]?.superseded_role_grants, [
    {
      role_grant_id: fixture.supersededAuditGrant,
      prior_version: 7,
      result_version: 8,
    },
  ]);

  const primaryCredential = liveCredential(
    fixture.primaryAccount,
    fixture.primaryCredential,
    0x41,
    41,
    "Primary collector v1",
  );
  const primaryReplacement = liveCredential(
    fixture.primaryAccount,
    fixture.primaryReplacementCredential,
    0x42,
    42,
    "Primary collector v2",
  );
  const peerCredential = liveCredential(
    fixture.peerAccount,
    fixture.peerCredential,
    0x43,
    43,
    "Peer collector",
  );
  const grantLossCredential = liveCredential(
    fixture.grantLossAccount,
    fixture.grantLossCredential,
    0x44,
    44,
    "Grant loss",
  );
  const sourceLossCredential = liveCredential(
    fixture.sourceLossAccount,
    fixture.sourceLossCredential,
    0x45,
    45,
    "Source loss",
  );
  const archiveLossCredential = liveCredential(
    fixture.archiveLossAccount,
    fixture.archiveLossCredential,
    0x46,
    46,
    "Archive loss",
  );
  const policyLossCredential = liveCredential(
    fixture.policyLossAccount,
    fixture.policyLossCredential,
    0x47,
    47,
    "Policy loss",
  );
  const suspensionLossCredential = liveCredential(
    fixture.suspensionLossAccount,
    fixture.suspensionLossCredential,
    0x48,
    48,
    "Tenant suspension",
  );
  const revokeRaceCredential = liveCredential(
    fixture.revokeRaceAccount,
    fixture.revokeRaceCredential,
    0x49,
    49,
    "Credential revoke race",
  );
  const archiveRaceCredential = liveCredential(
    fixture.archiveRaceAccount,
    fixture.archiveRaceCredential,
    0x4a,
    50,
    "Account archive race",
  );
  const cidrCredential = liveCredential(
    fixture.cidrAccount,
    fixture.cidrCredential,
    0x4b,
    51,
    "CIDR restricted collector",
    ["192.0.2.0/24"],
  );
  const cidrOrderCredential = liveCredential(
    fixture.cidrOrderAccount,
    fixture.cidrOrderCredential,
    0xd1,
    53,
    "Native CIDR order v1",
    [
      "2.0.0.0/8",
      "10.0.0.0/8",
      "10.0.0.0/9",
      "10.128.0.0/9",
      "2001:db8::/32",
      "2001:db8::/48",
      "2001:db8:1::/48",
    ],
  );
  const cidrOrderReplacementCredential = liveCredential(
    fixture.cidrOrderAccount,
    fixture.cidrOrderReplacementCredential,
    0xd2,
    54,
    "Native CIDR order v2",
    [
      "2.0.0.0/8",
      "10.0.0.0/8",
      "10.0.0.0/9",
      "10.128.0.0/9",
      "2001:db8::/32",
      "2001:db8::/48",
      "2001:db8:1::/48",
    ],
  );
  const foreignCredential = liveCredential(
    fixture.foreignAccount,
    fixture.foreignCredential,
    0x4c,
    52,
    "Foreign collector",
  );

  const invalidHumanOnlyAllowlist = {
    ...liveCredential(
      fixture.primaryAccount,
      uuid(2090),
      0x50,
      60,
      "Invalid human-only allowlist",
    ),
    permissionKeys: ["service_account.read"],
    scopes: ["tenant"],
  };
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await issueCredential(
        transaction,
        invalidHumanOnlyAllowlist,
        digest(0x50),
        digest(0x51),
      );
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const invalidScopeAllowlist = {
    ...liveCredential(
      fixture.primaryAccount,
      uuid(2091),
      0x51,
      61,
      "Invalid wider scope",
    ),
    scopes: ["assigned"],
  };
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await issueCredential(
        transaction,
        invalidScopeAllowlist,
        digest(0x52),
        digest(0x53),
      );
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await issueCredential(
        transaction,
        { ...foreignCredential, accountID: fixture.foreignAccount },
        digest(0x54),
        digest(0x55),
      );
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const issuedCidrOrder = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return issueCredential(
      transaction,
      cidrOrderCredential,
      digest(0x80),
      digest(0x81),
    );
  });
  assert.deepEqual(issuedCidrOrder, {
    result_credential_id: fixture.cidrOrderCredential,
    result_version: 1,
    replayed: false,
  });

  const rotatedCidrOrder = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return rotateCredential(
      transaction,
      cidrOrderReplacementCredential,
      fixture.cidrOrderCredential,
      1,
      digest(0x82),
      digest(0x83),
    );
  });
  assert.deepEqual(rotatedCidrOrder, {
    result_credential_id: fixture.cidrOrderReplacementCredential,
    result_version: 1,
    replayed: false,
  });

  const cidrOrderShapes = await admin<
    { credential_id: string; networks: unknown }[]
  >`
    SELECT credential_id,
           jsonb_agg(network::text ORDER BY network) AS networks
    FROM public.tenant_api_credential_networks
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND credential_id IN (
        ${fixture.cidrOrderCredential}::uuid,
        ${fixture.cidrOrderReplacementCredential}::uuid
      )
    GROUP BY credential_id
    ORDER BY credential_id
  `;
  assert.deepEqual(
    [...cidrOrderShapes],
    [
      {
        credential_id: fixture.cidrOrderCredential,
        networks: [
          "2.0.0.0/8",
          "10.0.0.0/8",
          "10.0.0.0/9",
          "10.128.0.0/9",
          "2001:db8::/32",
          "2001:db8::/48",
          "2001:db8:1::/48",
        ],
      },
      {
        credential_id: fixture.cidrOrderReplacementCredential,
        networks: [
          "2.0.0.0/8",
          "10.0.0.0/8",
          "10.0.0.0/9",
          "10.128.0.0/9",
          "2001:db8::/32",
          "2001:db8::/48",
          "2001:db8:1::/48",
        ],
      },
    ],
  );

  const issueKeyDigest = digest(0x61);
  const issueRequestDigest = digest(0x62);
  const issuedPrimary = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return issueCredential(
      transaction,
      primaryCredential,
      issueKeyDigest,
      issueRequestDigest,
    );
  });
  assert.deepEqual(issuedPrimary, {
    result_credential_id: fixture.primaryCredential,
    result_version: 1,
    replayed: false,
  });

  const issueReplay = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return issueCredential(
      transaction,
      {
        ...primaryCredential,
        credentialID: fixture.primaryCredentialReplayAttempt,
        locator: locator(0x52),
        secretDigest: digest(0x52),
      },
      issueKeyDigest,
      issueRequestDigest,
    );
  });
  assert.deepEqual(issueReplay, {
    result_credential_id: fixture.primaryCredential,
    result_version: 1,
    replayed: true,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await issueCredential(
        transaction,
        {
          ...primaryCredential,
          credentialID: fixture.primaryCredentialReplayAttempt,
          locator: locator(0x53),
          secretDigest: digest(0x53),
        },
        issueKeyDigest,
        digest(0x63),
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "tenant_api_credential_commands_replay_key",
      ),
  );

  const [issueState] = await admin<
    { credentials: number; commands: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_api_credentials
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND service_account_id = ${fixture.primaryAccount}::uuid) AS credentials,
      (SELECT count(*)::integer
       FROM public.tenant_api_credential_commands
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND service_account_id = ${fixture.primaryAccount}::uuid
         AND operation = 'service_account.credential.issue') AS commands,
      (SELECT count(*)::integer
       FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND action = 'tenant.service_account.credential_issued'
         AND resource_id = ${fixture.primaryCredential}::uuid) AS audits
  `;
  assert.deepEqual(issueState, { credentials: 1, commands: 1, audits: 1 });

  const rotateKeyDigest = digest(0x64);
  const rotateRequestDigest = digest(0x65);
  const rotatedPrimary = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return rotateCredential(
      transaction,
      primaryReplacement,
      fixture.primaryCredential,
      1,
      rotateKeyDigest,
      rotateRequestDigest,
    );
  });
  assert.deepEqual(rotatedPrimary, {
    result_credential_id: fixture.primaryReplacementCredential,
    result_version: 1,
    replayed: false,
  });

  const rotationReplay = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return rotateCredential(
      transaction,
      {
        ...primaryReplacement,
        credentialID: fixture.primaryReplacementReplayAttempt,
        locator: locator(0x54),
        secretDigest: digest(0x54),
      },
      fixture.primaryCredential,
      1,
      rotateKeyDigest,
      rotateRequestDigest,
    );
  });
  assert.deepEqual(rotationReplay, {
    result_credential_id: fixture.primaryReplacementCredential,
    result_version: 1,
    replayed: true,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await rotateCredential(
        transaction,
        {
          ...primaryReplacement,
          credentialID: fixture.primaryReplacementReplayAttempt,
          locator: locator(0x55),
          secretDigest: digest(0x55),
        },
        fixture.primaryCredential,
        1,
        rotateKeyDigest,
        digest(0x66),
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "tenant_api_credential_commands_replay_key",
      ),
  );

  const [rotationState] = await admin<
    {
      predecessor_revoked: boolean;
      predecessor_version: number;
      replacements: number;
      commands: number;
      audits: number;
    }[]
  >`
    SELECT
      predecessor.revoked_at IS NOT NULL AS predecessor_revoked,
      predecessor.version AS predecessor_version,
      (SELECT count(*)::integer
       FROM public.tenant_api_credentials AS replacement
       WHERE replacement.tenant_id = predecessor.tenant_id
         AND replacement.service_account_id = predecessor.service_account_id
         AND replacement.rotated_from_credential_id = predecessor.id) AS replacements,
      (SELECT count(*)::integer
       FROM public.tenant_api_credential_commands AS command
       WHERE command.tenant_id = predecessor.tenant_id
         AND command.service_account_id = predecessor.service_account_id
         AND command.operation = 'service_account.credential.rotate') AS commands,
      (SELECT count(*)::integer
       FROM public.audit_events AS event
       WHERE event.tenant_id = predecessor.tenant_id
         AND event.action = 'tenant.service_account.credential_rotated'
         AND event.resource_id = ${fixture.primaryReplacementCredential}::uuid) AS audits
    FROM public.tenant_api_credentials AS predecessor
    WHERE predecessor.id = ${fixture.primaryCredential}::uuid
  `;
  assert.deepEqual(rotationState, {
    predecessor_revoked: true,
    predecessor_version: 2,
    replacements: 1,
    commands: 1,
    audits: 1,
  });

  const ordinaryCredentials = [
    [peerCredential, 0x67, 0x68],
    [grantLossCredential, 0x69, 0x6a],
    [sourceLossCredential, 0x6b, 0x6c],
    [archiveLossCredential, 0x6d, 0x6e],
    [policyLossCredential, 0x6f, 0x70],
    [suspensionLossCredential, 0x71, 0x72],
    [revokeRaceCredential, 0x73, 0x74],
    [archiveRaceCredential, 0x75, 0x76],
    [cidrCredential, 0x77, 0x78],
  ] as const;
  await Promise.all(
    ordinaryCredentials.map(async ([proof, keyByte, requestByte]) => {
      const issued = await winner.begin(async (transaction) => {
        await setApiContext(transaction, fixture.adminUser);
        return issueCredential(
          transaction,
          proof,
          digest(keyByte),
          digest(requestByte),
        );
      });
      assert.deepEqual(issued, {
        result_credential_id: proof.credentialID,
        result_version: 1,
        replayed: false,
      });
    }),
  );

  const foreignIssued = await winner.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignAdminUser,
      fixture.foreignTenant,
    );
    return issueCredential(
      transaction,
      foreignCredential,
      digest(0x79),
      digest(0x7a),
    );
  });
  assert.deepEqual(foreignIssued, {
    result_credential_id: fixture.foreignCredential,
    result_version: 1,
    replayed: false,
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_api_credentials (
        id, tenant_id, service_account_id, label, format_version,
        locator, key_version, secret_digest, issued_by_membership_id,
        issued_at, expires_at, updated_at
      ) VALUES (
        ${fixture.expiredCredential}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.expiredAccount}::uuid,
        'Already expired collector',
        1,
        ${locator(0x4d)}::bytea,
        53,
        ${digest(0x4d)}::bytea,
        ${fixture.adminMembership}::uuid,
        transaction_timestamp() - interval '2 hours',
        transaction_timestamp() - interval '1 hour',
        transaction_timestamp() - interval '1 hour'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_api_credential_permissions (
        tenant_id, credential_id, permission_id,
        permission_service_account_allowed, scope
      )
      SELECT ${fixture.tenant}::uuid,
             ${fixture.expiredCredential}::uuid,
             permission.id,
             true,
             'tenant'::public.authorization_scope
      FROM public.tenant_permissions AS permission
      WHERE permission.key = 'alert.create'
    `;
  });

  const expiredCredential: CredentialProof = {
    accountID: fixture.expiredAccount,
    credentialID: fixture.expiredCredential,
    label: "Already expired collector",
    locator: locator(0x4d),
    keyVersion: 53,
    secretDigest: digest(0x4d),
    expiresAt: new Date(Date.now() - 60 * 60 * 1_000),
    permissionKeys: ["alert.create"],
    scopes: ["tenant"],
    networks: [],
  };

  await assertBearerRejected(winner, primaryCredential, "28000", 0x7b);
  await assertBearerRejected(winner, expiredCredential, "28000", 0x7d);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await createBearerAlert(
        transaction,
        {
          ...primaryReplacement,
          keyVersion: primaryReplacement.keyVersion + 1,
        },
        "Wrong key version",
        null,
        null,
        "high",
        digest(0x7f),
        digest(0x80),
        "192.0.2.80",
        undefined,
        "Periapsis key-version rejection proof",
      );
    }),
    (error: unknown) => assertSqlState(error, "28000"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await createBearerAlert(
        transaction,
        { ...primaryReplacement, secretDigest: digest(0x7e) },
        "Wrong keyed digest",
        null,
        null,
        "high",
        digest(0x81),
        digest(0x82),
        "192.0.2.80",
        undefined,
        "Periapsis keyed-digest rejection proof",
      );
    }),
    (error: unknown) => assertSqlState(error, "28000"),
  );

  await assertBearerRejected(
    winner,
    primaryReplacement,
    "28000",
    0x83,
    fixture.foreignTenant,
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await createBearerAlert(
        transaction,
        cidrCredential,
        "Disallowed CIDR Alert",
        null,
        null,
        "high",
        digest(0x85),
        digest(0x86),
        "198.51.100.10",
        undefined,
        "Periapsis CIDR denial proof",
      );
    }),
    (error: unknown) => assertSqlState(error, "28000"),
  );

  const cidrAllowedAlert = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      cidrCredential,
      "CIDR-authorized Alert",
      "The canonical host address is inside the credential network.",
      "cidr-c7-1",
      "medium",
      digest(0x87),
      digest(0x88),
      "192.0.2.81",
    );
  });
  assert.equal(cidrAllowedAlert.replayed, false);
  assert.equal(
    cidrAllowedAlert.created_by_service_account_id,
    fixture.cidrAccount,
  );

  const readinessAs = async (role: "periapsis_api" | "periapsis_worker") =>
    admin.begin(async (transaction) => {
      await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      const rows = await transaction<{ key_version: number }[]>`
        SELECT * FROM app.list_live_api_credential_key_versions_v1(101)
      `;
      return rows.map((row) => row.key_version);
    });

  const initiallyLiveKeyVersions = [
    42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54,
  ];
  assert.deepEqual(
    await readinessAs("periapsis_api"),
    initiallyLiveKeyVersions,
  );
  assert.deepEqual(
    await readinessAs("periapsis_worker"),
    initiallyLiveKeyVersions,
  );

  const protectedRelations = [
    "tenant_service_accounts",
    "tenant_service_account_role_grants",
    "tenant_api_credentials",
    "tenant_api_credential_permissions",
    "tenant_api_credential_networks",
    "tenant_api_credential_commands",
    "alert_activities",
    "alert_commands",
  ] as const;

  const privilegeRows = await admin<
    {
      relation_name: string;
      can_select: boolean;
      can_insert: boolean;
      can_update: boolean;
      can_delete: boolean;
      row_security: boolean;
      force_row_security: boolean;
    }[]
  >`
    SELECT relation.relname AS relation_name,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'SELECT'
           ) AS can_select,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'INSERT'
           ) AS can_insert,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'UPDATE'
           ) AS can_update,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'DELETE'
           ) AS can_delete,
           relation.relrowsecurity AS row_security,
           relation.relforcerowsecurity AS force_row_security
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY(${[...protectedRelations]}::text[])
    ORDER BY relation.relname
  `;
  assert.equal(privilegeRows.length, protectedRelations.length);
  for (const privilege of privilegeRows) {
    assert.deepEqual(
      {
        select: privilege.can_select,
        insert: privilege.can_insert,
        update: privilege.can_update,
        delete: privilege.can_delete,
        rls: privilege.row_security,
        forceRLS: privilege.force_row_security,
      },
      {
        select: false,
        insert: false,
        update: false,
        delete: false,
        rls: true,
        forceRLS: true,
      },
      `unexpected runtime privilege on public.${privilege.relation_name}`,
    );
  }

  await Promise.all(
    protectedRelations.flatMap((relation) =>
      [
        `SELECT count(*) FROM public."${relation}"`,
        `INSERT INTO public."${relation}" DEFAULT VALUES`,
        `UPDATE public."${relation}" SET tenant_id = tenant_id WHERE false`,
        `DELETE FROM public."${relation}" WHERE false`,
      ].map((statement) =>
        assert.rejects(
          winner.begin(async (transaction) => {
            await setApiContext(transaction, fixture.adminUser);
            await transaction.unsafe(statement);
          }),
          (error: unknown) => assertSqlState(error, "42501"),
        ),
      ),
    ),
  );

  const alertSideEffectPrivileges = await admin<
    {
      relation_name: string;
      can_insert: boolean;
      can_update: boolean;
      can_delete: boolean;
      can_insert_columns: boolean;
      can_update_columns: boolean;
    }[]
  >`
    SELECT relation.relname AS relation_name,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'INSERT'
           ) AS can_insert,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'UPDATE'
           ) AS can_update,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'DELETE'
           ) AS can_delete,
           pg_catalog.has_any_column_privilege(
             'periapsis_api', relation.oid, 'INSERT'
           ) AS can_insert_columns,
           pg_catalog.has_any_column_privilege(
             'periapsis_api', relation.oid, 'UPDATE'
           ) AS can_update_columns
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN ('alerts', 'audit_events', 'outbox_events')
    ORDER BY relation.relname
  `;
  assert.equal(alertSideEffectPrivileges.length, 3);
  for (const privilege of alertSideEffectPrivileges) {
    assert.deepEqual(
      {
        insert: privilege.can_insert,
        update: privilege.can_update,
        delete: privilege.can_delete,
        insertColumns: privilege.can_insert_columns,
        updateColumns: privilege.can_update_columns,
      },
      {
        insert: false,
        update: false,
        delete: false,
        insertColumns: false,
        updateColumns: false,
      },
      `unexpected Alert side-effect privilege on ${privilege.relation_name}`,
    );
  }

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        INSERT INTO public.alerts (
          tenant_id, title, status, severity,
          created_by, created_by_membership_id
        ) VALUES (
          ${fixture.tenant}::uuid,
          'Direct DML must fail',
          'new',
          'high',
          ${fixture.adminUser}::uuid,
          ${fixture.adminMembership}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const visibleTenantAlerts = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count FROM public.alerts
    `;
    return result?.count;
  });
  assert.equal(visibleTenantAlerts, 1);

  const [privatePrivilege] = await admin<
    {
      api_authenticator: boolean;
      worker_authenticator: boolean;
      public_authenticator: boolean;
      api_locator: boolean;
    }[]
  >`
    SELECT
      pg_catalog.has_function_privilege(
        'periapsis_api',
        'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)'::regprocedure,
        'EXECUTE'
      ) AS api_authenticator,
      pg_catalog.has_function_privilege(
        'periapsis_worker',
        'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)'::regprocedure,
        'EXECUTE'
      ) AS worker_authenticator,
      pg_catalog.has_function_privilege(
        'public',
        'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)'::regprocedure,
        'EXECUTE'
      ) AS public_authenticator,
      pg_catalog.has_function_privilege(
        'periapsis_api',
        'app.private_resolve_tenant_api_credential_locator_v1(uuid,bytea)'::regprocedure,
        'EXECUTE'
      ) AS api_locator
  `;
  assert.deepEqual(privatePrivilege, {
    api_authenticator: false,
    worker_authenticator: false,
    public_authenticator: false,
    api_locator: false,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await transaction`
        SELECT *
        FROM app.authenticate_tenant_api_credential_v1(
          ${fixture.tenant}::uuid,
          ${primaryReplacement.locator}::bytea,
          ${primaryReplacement.keyVersion},
          ${primaryReplacement.secretDigest}::bytea,
          '192.0.2.80'::inet,
          'alert.create',
          'tenant'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const redactedInventory = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [credential] = await transaction<Record<string, unknown>[]>`
      SELECT *
      FROM app.get_tenant_api_credential_v1(
        ${fixture.primaryAccount}::uuid,
        ${fixture.primaryReplacementCredential}::uuid
      )
    `;
    assert(credential, "primary replacement inventory row is missing");
    return credential;
  });
  for (const forbiddenKey of [
    "locator",
    "secret_digest",
    "key_digest",
    "request_digest",
    "token",
    "secret",
  ]) {
    assert.equal(
      Object.hasOwn(redactedInventory, forbiddenKey),
      false,
      `redacted inventory exposed ${forbiddenKey}`,
    );
  }
  assert.deepEqual(redactedInventory.permission_keys, ["alert.create"]);
  assert.deepEqual(redactedInventory.permission_scopes, ["tenant"]);

  const sharedAlertKey = digest(0x91);
  const humanRequestDigest = digest(0x92);
  const humanAlert = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return createHumanAlert(
      transaction,
      "Human-created Alert",
      "Canonical human command payload.",
      "human-c7-1",
      "high",
      sharedAlertKey,
      humanRequestDigest,
    );
  });
  assert.equal(humanAlert.replayed, false);
  assert.equal(humanAlert.created_by_user_id, fixture.adminUser);
  assert.equal(humanAlert.created_by_membership_id, fixture.adminMembership);
  assert.equal(humanAlert.created_by_service_account_id, null);

  const humanReplay = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return createHumanAlert(
      transaction,
      "Human-created Alert",
      "Canonical human command payload.",
      "human-c7-1",
      "high",
      sharedAlertKey,
      humanRequestDigest,
    );
  });
  assert.equal(humanReplay.id, humanAlert.id);
  assert.equal(humanReplay.replayed, true);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await createHumanAlert(
        transaction,
        "Human-created Alert with drift",
        "Canonical human command payload.",
        "human-c7-1",
        "high",
        sharedAlertKey,
        digest(0x93),
      );
    }),
    (error: unknown) =>
      assertSqlState(error, "23505", "alert_commands_human_replay_key"),
  );

  const peerHumanAlert = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.peerAdminUser);
    return createHumanAlert(
      transaction,
      "Peer human Alert",
      null,
      null,
      "medium",
      sharedAlertKey,
      digest(0x94),
    );
  });
  assert.equal(peerHumanAlert.replayed, false);
  assert.equal(peerHumanAlert.created_by_user_id, fixture.peerAdminUser);
  assert.notEqual(peerHumanAlert.id, humanAlert.id);

  const bearerRequestDigest = digest(0x95);
  const bearerAlert = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      primaryReplacement,
      "Machine-created Alert",
      "Canonical bearer command payload.",
      "machine-c7-1",
      "critical",
      sharedAlertKey,
      bearerRequestDigest,
      "192.0.2.80",
      undefined,
      "",
    );
  });
  assert.equal(bearerAlert.replayed, false);
  assert.equal(bearerAlert.created_by_user_id, null);
  assert.equal(bearerAlert.created_by_membership_id, null);
  assert.equal(
    bearerAlert.created_by_service_account_id,
    fixture.primaryAccount,
  );

  const bearerReplay = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      primaryReplacement,
      "Machine-created Alert",
      "Canonical bearer command payload.",
      "machine-c7-1",
      "critical",
      sharedAlertKey,
      bearerRequestDigest,
      "192.0.2.80",
      undefined,
      "",
    );
  });
  assert.equal(bearerReplay.id, bearerAlert.id);
  assert.equal(bearerReplay.replayed, true);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      await createBearerAlert(
        transaction,
        primaryReplacement,
        "Machine-created Alert with drift",
        "Canonical bearer command payload.",
        "machine-c7-1",
        "critical",
        sharedAlertKey,
        digest(0x96),
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "alert_commands_service_account_replay_key",
      ),
  );

  const peerBearerAlert = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      peerCredential,
      "Peer machine Alert",
      null,
      null,
      "low",
      sharedAlertKey,
      digest(0x97),
    );
  });
  assert.equal(peerBearerAlert.replayed, false);
  assert.equal(
    peerBearerAlert.created_by_service_account_id,
    fixture.peerAccount,
  );

  const foreignBearerAlert = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      foreignCredential,
      "Foreign machine Alert",
      null,
      "foreign-c7-1",
      "informational",
      sharedAlertKey,
      digest(0x98),
    );
  });
  assert.equal(foreignBearerAlert.replayed, false);
  assert.equal(
    foreignBearerAlert.created_by_service_account_id,
    fixture.foreignAccount,
  );

  assert.equal(
    new Set([
      humanAlert.id,
      peerHumanAlert.id,
      bearerAlert.id,
      peerBearerAlert.id,
      foreignBearerAlert.id,
    ]).size,
    5,
    "the same external idempotency key leaked across principals or tenants",
  );

  const [sharedKeySideEffects] = await admin<
    {
      alerts: number;
      activities: number;
      audits: number;
      outbox: number;
      commands: number;
    }[]
  >`
    WITH selected_alerts AS (
      SELECT unnest(ARRAY[
        ${humanAlert.id}::uuid,
        ${peerHumanAlert.id}::uuid,
        ${bearerAlert.id}::uuid,
        ${peerBearerAlert.id}::uuid
      ]) AS alert_id
    )
    SELECT
      (SELECT count(*)::integer
       FROM public.alerts AS alert
       JOIN selected_alerts ON selected_alerts.alert_id = alert.id
       WHERE alert.tenant_id = ${fixture.tenant}::uuid) AS alerts,
      (SELECT count(*)::integer
       FROM public.alert_activities AS activity
       JOIN selected_alerts ON selected_alerts.alert_id = activity.alert_id
       WHERE activity.tenant_id = ${fixture.tenant}::uuid) AS activities,
      (SELECT count(*)::integer
       FROM public.audit_events AS event
       JOIN selected_alerts ON selected_alerts.alert_id = event.resource_id
       WHERE event.tenant_id = ${fixture.tenant}::uuid
         AND event.action = 'tenant.alert.created') AS audits,
      (SELECT count(*)::integer
       FROM public.outbox_events AS event
       JOIN selected_alerts ON selected_alerts.alert_id = event.aggregate_id
       WHERE event.tenant_id = ${fixture.tenant}::uuid
         AND event.event_type = 'alert.created') AS outbox,
      (SELECT count(*)::integer
       FROM public.alert_commands AS command
       JOIN selected_alerts ON selected_alerts.alert_id = command.result_alert_id
       WHERE command.tenant_id = ${fixture.tenant}::uuid) AS commands
  `;
  assert.deepEqual(sharedKeySideEffects, {
    alerts: 4,
    activities: 4,
    audits: 4,
    outbox: 4,
    commands: 4,
  });

  const notificationTraces = await admin<
    {
      aggregate_id: string;
      actor_kind: string;
      projected_alert_id: string;
      schema_version: number;
      traceparent: string;
      tracestate: string;
    }[]
  >`
    SELECT aggregate_id, actor_kind, schema_version,
           payload #>> '{operatorContext,alert,id}' AS projected_alert_id,
           traceparent, tracestate
    FROM public.outbox_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND event_type = 'notification.alert.created'
      AND aggregate_id IN (${humanAlert.id}::uuid, ${bearerAlert.id}::uuid)
    ORDER BY aggregate_id
  `;
  assert.equal(notificationTraces.length, 2);
  assert.deepEqual(
    new Map(notificationTraces.map((event) => [event.aggregate_id, event])),
    new Map([
      [
        humanAlert.id,
        {
          aggregate_id: humanAlert.id,
          actor_kind: "human",
          projected_alert_id: humanAlert.id,
          schema_version: 2,
          traceparent: humanTraceParent,
          tracestate: persistedTraceState,
        },
      ],
      [
        bearerAlert.id,
        {
          aggregate_id: bearerAlert.id,
          actor_kind: "service_account",
          projected_alert_id: bearerAlert.id,
          schema_version: 2,
          traceparent: bearerTraceParent,
          tracestate: persistedTraceState,
        },
      ],
    ]),
  );

  let rolledBackHumanAlertID: string | undefined;
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      const result = await createHumanAlert(
        transaction,
        "Rolled-back human Alert",
        null,
        null,
        "high",
        digest(0x99),
        digest(0x9a),
        fixture.rollbackHumanAuditMarker,
      );
      rolledBackHumanAlertID = result.id;
      await transaction.unsafe("SELECT 1 / 0");
    }),
    (error: unknown) => assertSqlState(error, "22012"),
  );
  assert(rolledBackHumanAlertID, "human rollback did not reach Alert creation");

  const bearerVersionBeforeRollback = await getCredentialVersion(
    winner,
    fixture.adminUser,
    fixture.primaryAccount,
    fixture.primaryReplacementCredential,
  );
  let rolledBackBearerAlertID: string | undefined;
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiRole(transaction);
      const result = await createBearerAlert(
        transaction,
        primaryReplacement,
        "Rolled-back bearer Alert",
        null,
        null,
        "high",
        digest(0x9b),
        digest(0x9c),
        "192.0.2.80",
        fixture.rollbackBearerAuditMarker,
      );
      rolledBackBearerAlertID = result.id;
      await transaction.unsafe("SELECT 1 / 0");
    }),
    (error: unknown) => assertSqlState(error, "22012"),
  );
  assert(
    rolledBackBearerAlertID,
    "bearer rollback did not reach Alert creation",
  );
  assert.equal(
    await getCredentialVersion(
      winner,
      fixture.adminUser,
      fixture.primaryAccount,
      fixture.primaryReplacementCredential,
    ),
    bearerVersionBeforeRollback,
    "rolled-back bearer authentication advanced credential telemetry",
  );

  const [rollbackState] = await admin<
    {
      alerts: number;
      activities: number;
      audits: number;
      outbox: number;
      commands: number;
    }[]
  >`
    WITH rolled_back AS (
      SELECT unnest(ARRAY[
        ${rolledBackHumanAlertID}::uuid,
        ${rolledBackBearerAlertID}::uuid
      ]) AS alert_id
    )
    SELECT
      (SELECT count(*)::integer FROM public.alerts AS alert
       JOIN rolled_back ON rolled_back.alert_id = alert.id) AS alerts,
      (SELECT count(*)::integer FROM public.alert_activities AS activity
       JOIN rolled_back ON rolled_back.alert_id = activity.alert_id) AS activities,
      (SELECT count(*)::integer FROM public.audit_events AS event
       JOIN rolled_back ON rolled_back.alert_id = event.resource_id) AS audits,
      (SELECT count(*)::integer FROM public.outbox_events AS event
       JOIN rolled_back ON rolled_back.alert_id = event.aggregate_id) AS outbox,
      (SELECT count(*)::integer FROM public.alert_commands AS command
       JOIN rolled_back ON rolled_back.alert_id = command.result_alert_id) AS commands
  `;
  assert.deepEqual(rollbackState, {
    alerts: 0,
    activities: 0,
    audits: 0,
    outbox: 0,
    commands: 0,
  });

  const grantLossPrecondition = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      grantLossCredential,
      "Grant-loss precondition",
      null,
      null,
      "low",
      digest(0xa0),
      digest(0xa1),
    );
  });
  assert.equal(grantLossPrecondition.replayed, false);
  const revokedGrantVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return revokeMachineGrant(
      transaction,
      fixture.grantLossAccount,
      fixture.grantLossGrant,
      1,
    );
  });
  assert.equal(revokedGrantVersion, 2);
  await assertBearerRejected(winner, grantLossCredential, "42501", 0xa2);

  const sourceLossPrecondition = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      sourceLossCredential,
      "Source-loss precondition",
      null,
      null,
      "low",
      digest(0xa4),
      digest(0xa5),
    );
  });
  assert.equal(sourceLossPrecondition.replayed, false);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_authorization_sources
      SET retired_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.sourceLossSource}::uuid
    `;
  });
  await assertBearerRejected(winner, sourceLossCredential, "42501", 0xa6);

  const archiveLossPrecondition = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      archiveLossCredential,
      "Archive-loss precondition",
      null,
      null,
      "low",
      digest(0xa8),
      digest(0xa9),
    );
  });
  assert.equal(archiveLossPrecondition.replayed, false);
  const archivedAccountVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return archiveAccount(transaction, fixture.archiveLossAccount, 1);
  });
  assert.equal(archivedAccountVersion, 2);
  await assertBearerRejected(winner, archiveLossCredential, "28000", 0xaa);

  const policyLossPrecondition = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      policyLossCredential,
      "Policy-loss precondition",
      null,
      null,
      "low",
      digest(0xac),
      digest(0xad),
    );
  });
  assert.equal(policyLossPrecondition.replayed, false);
  const [alertPermission] = await admin<{ id: string }[]>`
    SELECT id
    FROM public.tenant_permissions
    WHERE key = 'alert.create'
  `;
  assert(alertPermission, "alert.create permission is missing");
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      DELETE FROM public.tenant_role_permissions
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND role_id = ${mainMachineRoleID}::uuid
        AND permission_id = ${alertPermission.id}::uuid
        AND scope = 'tenant'
    `;
  });
  await assertBearerRejected(winner, policyLossCredential, "42501", 0xae);
  const policyLossAuthority = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return transaction<{ permission_key: string }[]>`
      SELECT *
      FROM app.resolve_tenant_service_account_authority_v1(
        ${fixture.policyLossAccount}::uuid,
        201
      )
    `;
  });
  assert.deepEqual([...policyLossAuthority], []);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      ) VALUES (
        ${fixture.tenant}::uuid,
        ${mainMachineRoleID}::uuid,
        ${alertPermission.id}::uuid,
        'tenant',
        NULL
      )
    `;
  });
  const restoredPolicyAuthority = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return transaction<{ permission_key: string; scope: string }[]>`
      SELECT permission_key, scope::text
      FROM app.resolve_tenant_service_account_authority_v1(
        ${fixture.policyLossAccount}::uuid,
        201
      )
    `;
  });
  assert.deepEqual(
    [...restoredPolicyAuthority],
    [{ permission_key: "alert.create", scope: "tenant" }],
  );

  const suspensionPrecondition = await winner.begin(async (transaction) => {
    await setApiRole(transaction);
    return createBearerAlert(
      transaction,
      suspensionLossCredential,
      "Suspension precondition",
      null,
      null,
      "medium",
      digest(0xb0),
      digest(0xb1),
    );
  });
  assert.equal(suspensionPrecondition.replayed, false);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenants
      SET status = 'suspended',
          version = version + 1,
          updated_at = transaction_timestamp()
      WHERE id = ${fixture.tenant}::uuid
    `;
  });
  await assertBearerRejected(winner, suspensionLossCredential, "42501", 0xb2);
  assert.deepEqual(await readinessAs("periapsis_api"), [52]);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenants
      SET status = 'active',
          version = version + 1,
          updated_at = transaction_timestamp()
      WHERE id = ${fixture.tenant}::uuid
    `;
  });

  const inactiveAuthorities = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return transaction<{ account_id: string; authority_count: number }[]>`
      SELECT requested.account_id,
             (
               SELECT count(*)::integer
               FROM app.resolve_tenant_service_account_authority_v1(
                 requested.account_id,
                 201
               )
             ) AS authority_count
      FROM unnest(ARRAY[
        ${fixture.grantLossAccount}::uuid,
        ${fixture.sourceLossAccount}::uuid,
        ${fixture.archiveLossAccount}::uuid
      ]) AS requested(account_id)
      ORDER BY requested.account_id
    `;
  });
  assert.equal(inactiveAuthorities.length, 3);
  assert(inactiveAuthorities.every((row) => row.authority_count === 0));

  const concurrentKeyDigest = digest(0xb4);
  const concurrentRequestDigest = digest(0xb5);
  const concurrentReady = Promise.withResolvers<void>();
  const releaseConcurrent = Promise.withResolvers<void>();
  const releaseConcurrentTransaction = (): void => releaseConcurrent.resolve();
  heldReleases.add(releaseConcurrentTransaction);
  const concurrentWinner = winner.begin(async (transaction) => {
    await setApiRole(transaction);
    const result = await createBearerAlert(
      transaction,
      primaryReplacement,
      "Concurrent singleton Alert",
      "Only one complete side-effect set may commit.",
      "concurrent-c7-1",
      "high",
      concurrentKeyDigest,
      concurrentRequestDigest,
    );
    concurrentReady.resolve();
    await releaseConcurrent.promise;
    return result;
  });
  const concurrentWinnerOutcome = concurrentWinner.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    concurrentReady.promise,
    "concurrent Alert winner did not reach its commit barrier",
  );
  const concurrentPID = Promise.withResolvers<number>();
  const concurrentContender = contender.begin(async (transaction) => {
    await setApiRole(transaction);
    concurrentPID.resolve(await backendPID(transaction));
    return createBearerAlert(
      transaction,
      primaryReplacement,
      "Concurrent singleton Alert",
      "Only one complete side-effect set may commit.",
      "concurrent-c7-1",
      "high",
      concurrentKeyDigest,
      concurrentRequestDigest,
    );
  });
  const concurrentContenderOutcome = concurrentContender.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      observer,
      await withTimeout(
        concurrentPID.promise,
        "concurrent Alert contender did not start",
      ),
    );
  } finally {
    releaseConcurrent.resolve();
    heldReleases.delete(releaseConcurrentTransaction);
  }
  const concurrentFirst = await withTimeout(
    concurrentWinnerOutcome,
    "concurrent Alert winner did not commit",
  );
  const concurrentSecond = await withTimeout(
    concurrentContenderOutcome,
    "concurrent Alert contender did not finish",
  );
  assert("result" in concurrentFirst, "concurrent Alert winner failed");
  assert("result" in concurrentSecond, "concurrent Alert contender failed");
  assert.equal(concurrentFirst.result.replayed, false);
  assert.equal(concurrentSecond.result.replayed, true);
  assert.equal(concurrentSecond.result.id, concurrentFirst.result.id);

  const [concurrentSideEffects] = await admin<
    {
      alerts: number;
      activities: number;
      audits: number;
      outbox: number;
      commands: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alerts
       WHERE id = ${concurrentFirst.result.id}::uuid) AS alerts,
      (SELECT count(*)::integer FROM public.alert_activities
       WHERE alert_id = ${concurrentFirst.result.id}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE resource_id = ${concurrentFirst.result.id}::uuid
         AND action = 'tenant.alert.created') AS audits,
      (SELECT count(*)::integer FROM public.outbox_events
       WHERE aggregate_id = ${concurrentFirst.result.id}::uuid
         AND event_type = 'alert.created') AS outbox,
      (SELECT count(*)::integer FROM public.alert_commands
       WHERE result_alert_id = ${concurrentFirst.result.id}::uuid) AS commands
  `;
  assert.deepEqual(concurrentSideEffects, {
    alerts: 1,
    activities: 1,
    audits: 1,
    outbox: 1,
    commands: 1,
  });

  const revokeReady = Promise.withResolvers<void>();
  const releaseRevoke = Promise.withResolvers<void>();
  const releaseRevokeTransaction = (): void => releaseRevoke.resolve();
  heldReleases.add(releaseRevokeTransaction);
  const revoking = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const version = await revokeCredential(
      transaction,
      fixture.revokeRaceAccount,
      fixture.revokeRaceCredential,
      1,
      "Credential revocation wins before concurrent use.",
    );
    revokeReady.resolve();
    await releaseRevoke.promise;
    return version;
  });
  const revokingOutcome = revoking.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    revokeReady.promise,
    "credential revoke winner did not reach its commit barrier",
  );
  const revokeUsePID = Promise.withResolvers<number>();
  const revokeUse = contender.begin(async (transaction) => {
    await setApiRole(transaction);
    revokeUsePID.resolve(await backendPID(transaction));
    return createBearerAlert(
      transaction,
      revokeRaceCredential,
      "Revoked credential race Alert",
      null,
      null,
      "critical",
      digest(0xb6),
      digest(0xb7),
    );
  });
  const revokeUseOutcome = revokeUse.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      observer,
      await withTimeout(
        revokeUsePID.promise,
        "credential revoke contender did not start",
      ),
    );
  } finally {
    releaseRevoke.resolve();
    heldReleases.delete(releaseRevokeTransaction);
  }
  const revoked = await withTimeout(
    revokingOutcome,
    "credential revoke winner did not commit",
  );
  const revokedUse = await withTimeout(
    revokeUseOutcome,
    "credential revoke contender did not finish",
  );
  assert("result" in revoked, "credential revoke winner failed");
  assert.equal(revoked.result, 2);
  assert("error" in revokedUse, "revoked credential created an Alert");
  assertSqlState(revokedUse.error, "28000");

  const archiveReady = Promise.withResolvers<void>();
  const releaseArchive = Promise.withResolvers<void>();
  const releaseArchiveTransaction = (): void => releaseArchive.resolve();
  heldReleases.add(releaseArchiveTransaction);
  const archiving = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const version = await archiveAccount(
      transaction,
      fixture.archiveRaceAccount,
      1,
    );
    archiveReady.resolve();
    await releaseArchive.promise;
    return version;
  });
  const archivingOutcome = archiving.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    archiveReady.promise,
    "account archive winner did not reach its commit barrier",
  );
  const archiveUsePID = Promise.withResolvers<number>();
  const archiveUse = contender.begin(async (transaction) => {
    await setApiRole(transaction);
    archiveUsePID.resolve(await backendPID(transaction));
    return createBearerAlert(
      transaction,
      archiveRaceCredential,
      "Archived account race Alert",
      null,
      null,
      "critical",
      digest(0xb8),
      digest(0xb9),
    );
  });
  const archiveUseOutcome = archiveUse.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      observer,
      await withTimeout(
        archiveUsePID.promise,
        "account archive contender did not start",
      ),
    );
  } finally {
    releaseArchive.resolve();
    heldReleases.delete(releaseArchiveTransaction);
  }
  const archived = await withTimeout(
    archivingOutcome,
    "account archive winner did not commit",
  );
  const archivedUse = await withTimeout(
    archiveUseOutcome,
    "account archive contender did not finish",
  );
  assert("result" in archived, "account archive winner failed");
  assert.equal(archived.result, 2);
  assert("error" in archivedUse, "archived account created an Alert");
  assertSqlState(archivedUse.error, "28000");

  const [raceFailureState] = await admin<
    { alerts: number; commands: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.alerts
       WHERE title IN (
         'Revoked credential race Alert',
         'Archived account race Alert'
       )) AS alerts,
      (SELECT count(*)::integer
       FROM public.alert_commands
       WHERE key_digest IN (${digest(0xb6)}::bytea, ${digest(0xb8)}::bytea)) AS commands,
      (SELECT count(*)::integer
       FROM public.audit_events
       WHERE action = 'tenant.alert.created'
         AND resource_id IN (
           SELECT id FROM public.alerts
           WHERE title IN (
             'Revoked credential race Alert',
             'Archived account race Alert'
           )
         )) AS audits
  `;
  assert.deepEqual(raceFailureState, { alerts: 0, commands: 0, audits: 0 });

  assert.deepEqual(
    await readinessAs("periapsis_api"),
    [42, 43, 44, 45, 47, 48, 51, 52, 54],
  );
  assert.deepEqual(
    await readinessAs("periapsis_worker"),
    [42, 43, 44, 45, 47, 48, 51, 52, 54],
  );

  const [exclusiveAttribution] = await admin<
    {
      invalid_alerts: number;
      invalid_activities: number;
      invalid_commands: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.alerts AS alert
       WHERE alert.tenant_id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
         AND NOT (
           (alert.created_by IS NOT NULL
             AND alert.created_by_membership_id IS NOT NULL
             AND alert.created_by_service_account_id IS NULL)
           OR
           (alert.created_by IS NULL
             AND alert.created_by_membership_id IS NULL
             AND alert.created_by_service_account_id IS NOT NULL)
         )) AS invalid_alerts,
      (SELECT count(*)::integer
       FROM public.alert_activities AS activity
       WHERE activity.tenant_id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
         AND NOT (
           (activity.actor_principal_kind = 'human'
             AND activity.actor_membership_id IS NOT NULL
             AND activity.actor_service_account_id IS NULL)
           OR
           (activity.actor_principal_kind = 'service_account'
             AND activity.actor_membership_id IS NULL
             AND activity.actor_service_account_id IS NOT NULL)
         )) AS invalid_activities,
      (SELECT count(*)::integer
       FROM public.alert_commands AS command
       WHERE command.tenant_id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
         AND NOT (
           (command.principal_kind = 'human'
             AND command.actor_membership_id IS NOT NULL
             AND command.actor_service_account_id IS NULL)
           OR
           (command.principal_kind = 'service_account'
             AND command.actor_membership_id IS NULL
             AND command.actor_service_account_id IS NOT NULL)
         )) AS invalid_commands
  `;
  assert.deepEqual(exclusiveAttribution, {
    invalid_alerts: 0,
    invalid_activities: 0,
    invalid_commands: 0,
  });

  const auditProjection = await admin<
    {
      actor_type: string;
      actor_service_account_id: string | null;
      payload_has_service_account_actor: boolean;
      before_text: string;
      after_text: string;
      metadata_text: string;
      authentication_method: string;
    }[]
  >`
    SELECT event.actor_type::text,
           event.actor_service_account_id,
           app.audit_event_payload(event) ? 'actor_service_account_id'
             AS payload_has_service_account_actor,
           coalesce(event.before::text, '') AS before_text,
           coalesce(event.after::text, '') AS after_text,
           event.metadata::text AS metadata_text,
           event.authentication_method
    FROM public.audit_events AS event
    WHERE event.tenant_id = ${fixture.tenant}::uuid
      AND event.action = 'tenant.alert.created'
    ORDER BY event.sequence
  `;
  assert(auditProjection.length >= 10);
  assert(
    auditProjection.some(
      (event) =>
        event.actor_type === "user" &&
        event.actor_service_account_id === null &&
        !event.payload_has_service_account_actor,
    ),
    "human audit payload retained the additive null machine actor key",
  );
  assert(
    auditProjection.some(
      (event) =>
        event.actor_type === "service_account" &&
        event.actor_service_account_id !== null &&
        event.payload_has_service_account_actor &&
        event.authentication_method === "api_credential",
    ),
    "service-account audit attribution is missing",
  );

  const redactedAuditText = auditProjection
    .map(
      (event) =>
        `${event.before_text}:${event.after_text}:${event.metadata_text}`,
    )
    .join(":");
  const [allAuditPayloads] = await admin<{ serialized: string }[]>`
    SELECT coalesce(
             string_agg(
               coalesce(event.before::text, '') || ':' ||
               coalesce(event.after::text, '') || ':' ||
               event.metadata::text,
               ':' ORDER BY event.sequence
             ),
             ''
           ) AS serialized
    FROM public.audit_events AS event
    WHERE event.tenant_id = ${fixture.tenant}::uuid
  `;
  assert(allAuditPayloads, "tenant audit serialization returned no row");
  const allRedactedAuditText =
    redactedAuditText + ":" + allAuditPayloads.serialized;
  for (const forbiddenValue of [
    primaryCredential.locator.toString("hex"),
    primaryCredential.secretDigest.toString("hex"),
    primaryReplacement.locator.toString("hex"),
    primaryReplacement.secretDigest.toString("hex"),
    issueKeyDigest.toString("hex"),
    issueRequestDigest.toString("hex"),
    "Canonical bearer command payload.",
    "machine-c7-1",
  ]) {
    assert.equal(
      allRedactedAuditText.includes(forbiddenValue),
      false,
      `audit payload exposed sensitive/content value ${forbiddenValue}`,
    );
  }
  assert(
    auditProjection.every((event) =>
      event.metadata_text.includes('"content_redacted": true'),
    ),
    "Alert audit metadata did not mark content as redacted",
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        UPDATE public.audit_events
        SET reason = 'tampered'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND action = 'tenant.alert.created'
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await Promise.all(
    [fixture.tenant, fixture.foreignTenant].map(async (tenantID) => {
      const chain = await admin.begin(async (transaction) => {
        await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
        await transaction`
          SELECT set_config('app.tenant_id', ${tenantID}, true)
        `;
        return transaction<{ valid: boolean }[]>`
          SELECT valid FROM app.verify_audit_chain(${tenantID}::uuid)
        `;
      });
      assert(chain.length > 0, `audit chain ${tenantID} is empty`);
      assert(
        chain.every((event) => event.valid),
        `audit chain ${tenantID} is invalid`,
      );
    }),
  );

  const [finalCounts] = await admin<
    {
      credential_replay_attempts: number;
      failed_alerts: number;
      one_time_commands: number;
      one_time_audits: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_api_credentials
       WHERE id IN (
         ${fixture.primaryCredentialReplayAttempt}::uuid,
         ${fixture.primaryReplacementReplayAttempt}::uuid
       )) AS credential_replay_attempts,
      (SELECT count(*)::integer
       FROM public.alerts
       WHERE title LIKE '%with drift'
          OR title LIKE 'Rejected bearer%'
          OR title LIKE '%race Alert') AS failed_alerts,
      (SELECT count(*)::integer
       FROM public.tenant_api_credential_commands
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND service_account_id = ${fixture.primaryAccount}::uuid) AS one_time_commands,
      (SELECT count(*)::integer
       FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND resource_id IN (
           ${fixture.primaryCredential}::uuid,
           ${fixture.primaryReplacementCredential}::uuid
         )
         AND action IN (
           'tenant.service_account.credential_issued',
           'tenant.service_account.credential_rotated'
         )) AS one_time_audits
  `;
  assert.deepEqual(finalCounts, {
    credential_replay_attempts: 0,
    failed_alerts: 0,
    one_time_commands: 2,
    one_time_audits: 2,
  });

  process.stdout.write(
    "service-principal RLS, exact authority, one-time credentials, atomic Alert, audit, readiness, and concurrency checks passed\n",
  );
} finally {
  for (const release of heldReleases) {
    release();
  }
  await Promise.allSettled([
    admin.end(),
    winner.end(),
    contender.end(),
    observer.end(),
  ]);
}

async function setupServicePrincipalFixtures(): Promise<{
  mainMachineRoleID: string;
}> {
  const [catalogInvariant] = await admin<
    {
      machine_permissions: string[];
      administration_permissions: string[];
    }[]
  >`
    SELECT
      array_agg(permission.key ORDER BY permission.key)
        FILTER (WHERE permission.service_account_allowed)
        AS machine_permissions,
      array_agg(permission.key ORDER BY permission.key)
        FILTER (WHERE permission.key LIKE 'service_account.%')
        AS administration_permissions
    FROM public.tenant_permissions AS permission
  `;
  assert.deepEqual(catalogInvariant, {
    machine_permissions: ["alert.create"],
    administration_permissions: [
      "service_account.credential.manage",
      "service_account.manage",
      "service_account.read",
    ],
  });

  const roles = await admin<
    {
      tenant_id: string;
      machine_role_id: string;
      principal_kind: string;
      policy_keys: string[];
      policy_scopes: string[];
      ceiling_count: number;
    }[]
  >`
    SELECT role.tenant_id,
           role.id AS machine_role_id,
           role.principal_kind::text,
           array_agg(permission.key ORDER BY permission.key, policy.scope)
             AS policy_keys,
           array_agg(policy.scope::text ORDER BY permission.key, policy.scope)
             AS policy_scopes,
           (
             SELECT count(*)::integer
             FROM public.tenant_role_delegation_ceilings AS ceiling
             WHERE ceiling.tenant_id = role.tenant_id
               AND ceiling.role_id = role.id
           ) AS ceiling_count
    FROM public.tenant_roles AS role
    JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id
     AND policy.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE role.tenant_id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
      AND role.key = 'service_account'
    GROUP BY role.tenant_id, role.id, role.principal_kind
    ORDER BY role.tenant_id
  `;
  assert.equal(roles.length, 2);
  for (const role of roles) {
    assert.equal(role.principal_kind, "service_account");
    assert.deepEqual(role.policy_keys, ["alert.create"]);
    assert.deepEqual(role.policy_scopes, ["tenant"]);
    assert.equal(role.ceiling_count, 0);
  }
  const mainMachineRole = roles.find(
    (role) => role.tenant_id === fixture.tenant,
  );
  const foreignMachineRole = roles.find(
    (role) => role.tenant_id === fixture.foreignTenant,
  );
  assert(mainMachineRole, "main machine role is missing");
  assert(foreignMachineRole, "foreign machine role is missing");
  const mainMachineRoleID = mainMachineRole.machine_role_id;
  const foreignMachineRoleID = foreignMachineRole.machine_role_id;

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      const { requestID, correlationID } = requestContext();
      await transaction`
        SELECT *
        FROM app.grant_tenant_user_role(
          ${fixture.machineHumanGrantAttempt}::uuid,
          ${digest(0x31)}::bytea,
          ${fixture.limitedUser}::uuid,
          ${mainMachineRoleID}::uuid,
          'A human must never receive a machine-only role.',
          NULL,
          ${uuid(12_001)}::uuid,
          ${requestID}::uuid,
          ${correlationID}::uuid,
          '192.0.2.80'::inet,
          'Periapsis machine-role kind proof',
          'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.limitedUser);
      await transaction`
        SELECT * FROM app.list_tenant_service_accounts_v1(NULL, false, 10)
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const mainAccounts = [
    [fixture.primaryAccount, "sp_c7_primary", "Primary collector"],
    [fixture.peerAccount, "sp_c7_peer", "Peer collector"],
    [fixture.grantLossAccount, "sp_c7_grant_loss", "Grant loss collector"],
    [fixture.sourceLossAccount, "sp_c7_source_loss", "Source loss collector"],
    [
      fixture.archiveLossAccount,
      "sp_c7_archive_loss",
      "Archive loss collector",
    ],
    [fixture.policyLossAccount, "sp_c7_policy_loss", "Policy loss collector"],
    [
      fixture.suspensionLossAccount,
      "sp_c7_suspension_loss",
      "Tenant suspension collector",
    ],
    [fixture.revokeRaceAccount, "sp_c7_revoke_race", "Revoke race collector"],
    [
      fixture.archiveRaceAccount,
      "sp_c7_archive_race",
      "Archive race collector",
    ],
    [fixture.expiredAccount, "sp_c7_expired", "Expired credential collector"],
    [fixture.cidrAccount, "sp_c7_cidr", "CIDR collector"],
    [
      fixture.cidrOrderAccount,
      "sp_c7_cidr_order",
      "Native CIDR order collector",
    ],
    [
      fixture.supersessionAuditAccount,
      "sp_c7_supersession_audit",
      "Role supersession audit collector",
    ],
  ] as const;

  await Promise.all(
    mainAccounts.map(async ([accountID, key, displayName]) => {
      const created = await winner.begin(async (transaction) => {
        await setApiContext(transaction, fixture.adminUser);
        return createAccount(transaction, accountID, key, displayName);
      });
      assert.deepEqual(created, {
        result_resource_id: accountID,
        result_version: 1,
      });
    }),
  );

  const foreignCreated = await winner.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignAdminUser,
      fixture.foreignTenant,
    );
    return createAccount(
      transaction,
      fixture.foreignAccount,
      "sp_c7_foreign",
      "Foreign tenant collector",
    );
  });
  assert.deepEqual(foreignCreated, {
    result_resource_id: fixture.foreignAccount,
    result_version: 1,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT *
        FROM app.get_tenant_service_account_v1(
          ${fixture.foreignAccount}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.primaryAccount);
      await transaction`
        SELECT * FROM app.list_tenant_service_accounts_v1(NULL, false, 10)
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const accountGrantPairs = [
    [fixture.primaryAccount, fixture.primaryGrant],
    [fixture.peerAccount, fixture.peerGrant],
    [fixture.grantLossAccount, fixture.grantLossGrant],
    [fixture.archiveLossAccount, fixture.archiveLossGrant],
    [fixture.policyLossAccount, fixture.policyLossGrant],
    [fixture.suspensionLossAccount, fixture.suspensionLossGrant],
    [fixture.revokeRaceAccount, fixture.revokeRaceGrant],
    [fixture.archiveRaceAccount, fixture.archiveRaceGrant],
    [fixture.expiredAccount, fixture.expiredGrant],
    [fixture.cidrAccount, fixture.cidrGrant],
    [fixture.cidrOrderAccount, fixture.cidrOrderGrant],
  ] as const;
  await Promise.all(
    accountGrantPairs.map(async ([accountID, grantID]) => {
      const granted: AccountMutation = await winner.begin(
        async (transaction) => {
          await setApiContext(transaction, fixture.adminUser);
          return grantMachineRole(
            transaction,
            grantID,
            accountID,
            mainMachineRoleID,
          );
        },
      );
      assert.deepEqual(granted, {
        result_resource_id: grantID,
        result_version: 1,
      });
    }),
  );
  const foreignGranted = await winner.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignAdminUser,
      fixture.foreignTenant,
    );
    return grantMachineRole(
      transaction,
      fixture.foreignGrant,
      fixture.foreignAccount,
      foreignMachineRoleID,
    );
  });
  assert.deepEqual(foreignGranted, {
    result_resource_id: fixture.foreignGrant,
    result_version: 1,
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.sourceLossSource}::uuid,
        ${fixture.tenant}::uuid,
        'identity_mapping',
        ${fixtureNames.sourceKey},
        true,
        false
      )
    `;
    await transaction`
      INSERT INTO public.tenant_service_account_role_grants (
        id, tenant_id, service_account_id, role_id,
        role_principal_kind, source_id, granted_by_membership_id,
        grant_reason
      ) VALUES (
        ${fixture.sourceLossGrant}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.sourceLossAccount}::uuid,
        ${mainMachineRoleID}::uuid,
        'service_account',
        ${fixture.sourceLossSource}::uuid,
        ${fixture.adminMembership}::uuid,
        'Authoritative-source retirement proof.'
      )
  `;
  });

  return { mainMachineRoleID };
}
