import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import postgres, { type Sql } from "postgres";

import {
  expectedAPIRuntimeReadinessV62SourceHash,
  expectedFederatedAuthenticationReadinessV62SourceHash,
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedPlatformLocalAccountRuntimeReadinessV62SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV62SourceHash,
  expectedPlatformSAMLDirectRuntimeReadinessV62SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV62SourceHash,
  expectedPrivateReleaseRuntimeReadinessV62SourceHash,
  expectedPrivateRotateSLAReadinessV48SourceHash,
  expectedPrivateSchemaCompatibilityJournalV62SourceHash,
  expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash,
  expectedReleaseRuntimeReadinessV62SourceHash,
  expectedRetiredSchemaCompatibilityV49SourceHash,
  expectedRetiredSchemaCompatibilityV50SourceHash,
  expectedRetiredSchemaCompatibilityV51SourceHash,
  expectedRetiredSchemaCompatibilityV52SourceHash,
  expectedRetiredSchemaCompatibilityV53SourceHash,
  expectedRetiredSchemaCompatibilityV54SourceHash,
  expectedRetiredSchemaCompatibilityV55SourceHash,
  expectedRetiredSchemaCompatibilityV56SourceHash,
  expectedRetiredSchemaCompatibilityV57SourceHash,
  expectedRetiredSchemaCompatibilityV58SourceHash,
  expectedRetiredSchemaCompatibilityV59SourceHash,
  expectedRetiredSchemaCompatibilityV60SourceHash,
  expectedRetiredSchemaCompatibilityV61SourceHash,
  expectedSchemaCompatibilityV62SourceHash,
  expectedSLAObjectEventIngressReadinessV62SourceHash,
  expectedSLATriggerActionRuntimeReadinessV62SourceHash,
  expectedTicketBulkRuntimeReadinessV62SourceHash,
  expectedTicketExportRuntimeReadinessV62SourceHash,
  expectedTicketMetadataRuntimeReadinessV62SourceHash,
  expectedWorkerRuntimeReadinessV62SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import {
  assertServiceReadinessAggregation,
  type ServiceReadinessHealthRow as LiveHealthRow,
} from "../helpers/service-readiness-aggregation.js";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker";
type Projection = Readonly<Record<string, unknown>>;
type BindingReceipt = {
  binding_id: string;
  version: number;
  replayed: boolean;
  document: Projection;
};
const commonHealthSourceHashes = [
  expectedSchemaCompatibilityV62SourceHash,
  expectedRetiredSchemaCompatibilityV49SourceHash,
  expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash,
  expectedPrivateSchemaCompatibilityJournalV62SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV62SourceHash,
  expectedPrivateReleaseRuntimeReadinessV62SourceHash,
  expectedReleaseRuntimeReadinessV62SourceHash,
] as const;
const apiHealthSourceHashes = [
  ...commonHealthSourceHashes,
  expectedFederatedAuthenticationReadinessV62SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV62SourceHash,
  expectedPlatformSAMLDirectRuntimeReadinessV62SourceHash,
  expectedPlatformLocalAccountRuntimeReadinessV62SourceHash,
  expectedTicketBulkRuntimeReadinessV62SourceHash,
  expectedTicketExportRuntimeReadinessV62SourceHash,
  expectedTicketMetadataRuntimeReadinessV62SourceHash,
  expectedPrivateRotateSLAReadinessV48SourceHash,
  expectedRetiredSchemaCompatibilityV50SourceHash,
  expectedRetiredSchemaCompatibilityV51SourceHash,
  expectedAPIRuntimeReadinessV62SourceHash,
  expectedRetiredSchemaCompatibilityV52SourceHash,
  expectedRetiredSchemaCompatibilityV53SourceHash,
  expectedRetiredSchemaCompatibilityV54SourceHash,
  expectedRetiredSchemaCompatibilityV55SourceHash,
  expectedRetiredSchemaCompatibilityV56SourceHash,
  expectedRetiredSchemaCompatibilityV57SourceHash,
  expectedRetiredSchemaCompatibilityV58SourceHash,
  expectedRetiredSchemaCompatibilityV59SourceHash,
  expectedRetiredSchemaCompatibilityV60SourceHash,
  expectedRetiredSchemaCompatibilityV61SourceHash,
] as const;
const workerHealthSourceHashes = [
  ...commonHealthSourceHashes,
  expectedSLATriggerActionRuntimeReadinessV62SourceHash,
  expectedSLAObjectEventIngressReadinessV62SourceHash,
  expectedTicketBulkRuntimeReadinessV62SourceHash,
  expectedTicketExportRuntimeReadinessV62SourceHash,
  expectedPrivateRotateSLAReadinessV48SourceHash,
  expectedRetiredSchemaCompatibilityV50SourceHash,
  expectedRetiredSchemaCompatibilityV51SourceHash,
  expectedWorkerRuntimeReadinessV62SourceHash,
  expectedRetiredSchemaCompatibilityV52SourceHash,
  expectedRetiredSchemaCompatibilityV53SourceHash,
  expectedRetiredSchemaCompatibilityV54SourceHash,
  expectedRetiredSchemaCompatibilityV55SourceHash,
  expectedRetiredSchemaCompatibilityV56SourceHash,
  expectedRetiredSchemaCompatibilityV57SourceHash,
  expectedRetiredSchemaCompatibilityV58SourceHash,
  expectedRetiredSchemaCompatibilityV59SourceHash,
  expectedRetiredSchemaCompatibilityV60SourceHash,
  expectedRetiredSchemaCompatibilityV61SourceHash,
] as const;
type KeyringEvidenceRow = {
  key_version: number;
  verifier: Buffer;
  is_active: boolean;
};

const configuredDatabaseUrl =
  process.env.PERIAPSIS_PLATFORM_IDENTITY_BINDING_TEST_DATABASE_URL;
if (
  configuredDatabaseUrl === undefined ||
  configuredDatabaseUrl.trim() === ""
) {
  throw new Error(
    "PERIAPSIS_PLATFORM_IDENTITY_BINDING_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(configuredDatabaseUrl, {
  max: 8,
  onnotice: () => undefined,
});
const raceA = postgres(configuredDatabaseUrl, {
  max: 1,
  onnotice: () => undefined,
});
const raceB = postgres(configuredDatabaseUrl, {
  max: 1,
  onnotice: () => undefined,
});

const uuid = (sequence: number): string =>
  `019d4b90-7000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;

const fixture = {
  operator: uuid(1),
  denied: uuid(2),
  operatorGrant: uuid(3),
  operatorSession: uuid(4),
  deniedSession: uuid(5),
  operatorFamily: uuid(6),
  deniedFamily: uuid(7),
  provider: uuid(20),
  providerCommand: uuid(21),
  secondaryProvider: uuid(22),
  secondaryProviderCommand: uuid(23),
  mainTenant: uuid(30),
  suspendedTenant: uuid(31),
  createRaceTenant: uuid(32),
  renameRaceTenant: uuid(33),
  reservationRaceTenant: uuid(34),
  replayScopeTenant: uuid(35),
  mainMembership: uuid(40),
  suspendedMembership: uuid(41),
  createRaceMembership: uuid(42),
  renameRaceMembership: uuid(43),
  reservationRaceMembership: uuid(44),
  replayScopeMembership: uuid(45),
  createRaceNativeProvider: uuid(50),
  renameRaceNativeProvider: uuid(51),
  mainBinding: uuid(60),
  createRacePlatformBinding: uuid(61),
  createRaceNativeBinding: uuid(62),
  renameRacePlatformBinding: uuid(63),
  renameRaceNativeBinding: uuid(64),
  expiryBinding: uuid(65),
  expiredSamePairRetryBinding: uuid(66),
  reservationRaceCommittedBinding: uuid(67),
  reservationRaceCompetingBinding: uuid(68),
  replayScopeBinding: uuid(69),
  mainCommand: uuid(70),
  renameRaceCommand: uuid(71),
  expiryCommand: uuid(72),
  expiredSamePairCommand: uuid(73),
  expiredSamePairRetryCommand: uuid(74),
  reservationRaceCommittedCommand: uuid(75),
  reservationRaceCompetingCommand: uuid(76),
  reservationRaceCompetingTenantAudit: uuid(77),
  reservationRaceCompetingPlatformAudit: uuid(78),
  replayScopeCommand: uuid(79),
  replayScopeTenantAudit: uuid(80),
  replayScopePlatformAudit: uuid(81),
} as const;

const oidcConfiguration = {
  issuer: "https://binding-runtime-idp.example.invalid",
  clientId: "periapsis-binding-runtime",
  redirectUri: "https://periapsis.example.invalid/auth/platform/oidc/callback",
  postLogoutRedirectUri: "https://periapsis.example.invalid/login",
  extraScopes: ["groups"],
  allowRefreshToken: false,
  useUserInfo: true,
} as const;

const protectedTables = [
  "tenant_auth_provider_login_keys",
  "tenant_platform_auth_provider_bindings",
  "tenant_platform_identity_provider_access_epochs",
  "tenant_platform_identity_binding_commands",
] as const;

const protectedFunctionNames = [
  "activate_tenant_platform_auth_provider_binding_v1",
  "archive_tenant_platform_auth_provider_binding_v1",
  "create_tenant_platform_auth_provider_binding_v1",
  "deactivate_tenant_platform_auth_provider_binding_v1",
  "get_tenant_platform_auth_provider_binding_v1",
  "list_tenant_platform_auth_provider_bindings_v1",
  "update_tenant_platform_auth_provider_binding_v1",
] as const;

function goHealthQuery(path: string): string {
  const source = readFileSync(path, "utf8");
  const marker = "const schemaCompatibilityQuery = ";
  const start = source.indexOf(marker);
  const end = source.indexOf(
    "\n\nvar expectedTrustedFunctionSourceHashes",
    start,
  );
  assert(
    start >= 0 && end > start,
    `missing schemaCompatibilityQuery in ${path}`,
  );

  const constants = new Map(
    [...source.matchAll(/^\s*(\w+)\s*=\s*`([\s\S]*?)`/gm)].map(
      ([, name, value]) => [name, value] as const,
    ),
  );
  const expression = source.slice(start + marker.length, end).trim();
  assert(
    expression.startsWith("`") && expression.endsWith("`"),
    `invalid schemaCompatibilityQuery expression in ${path}`,
  );
  return expression
    .slice(1, -1)
    .replace(
      /`\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*`/g,
      (_segment, name: string) => {
        const value = constants.get(name);
        assert(value !== undefined, `missing ${name} in ${path}`);
        return value;
      },
    );
}

function assertLiveHealthRow(
  row: LiveHealthRow | undefined,
  role: RuntimeRole,
): void {
  assert(row, `${role} health returned no row`);
  assert.equal(Number(row.applied_count), expectedMigrationCount);
  assert.equal(
    String(row.latest_created_at),
    String(expectedMigrationCreatedAt),
  );
  assert.equal(row.latest_hash, expectedMigrationHash);
  assert.equal(row.migration_fingerprint, expectedMigrationFingerprint);
  assert.equal(row.array.length, role === "periapsis_api" ? 8 : 5);
  assert.equal(row.array.every(Boolean), true);
  assert.deepEqual(
    row.source_hashes,
    role === "periapsis_api"
      ? [...apiHealthSourceHashes]
      : [...workerHealthSourceHashes],
  );
  assert.equal(row.catalog_ready, true);
  const expectedColumns = [
    "applied_count",
    "latest_created_at",
    "latest_hash",
    "migration_fingerprint",
    "array",
    "source_hashes",
    "catalog_ready",
  ];
  if (role === "periapsis_worker") {
    expectedColumns.splice(4, 0, "verify_identity_keyring_v3");
  }
  assert.deepEqual(
    Object.keys(row),
    expectedColumns,
    `${role} health projection order changed`,
  );
  if (role === "periapsis_worker") {
    assert.equal(row.verify_identity_keyring_v3, true);
  } else {
    assert.equal("verify_identity_keyring_v3" in row, false);
  }
}

function postgresByteaArray(values: readonly Uint8Array[]): string {
  return `{${values
    .map((value) => `"\\\\x${Buffer.from(value).toString("hex")}"`)
    .join(",")}}`;
}

const apiHealthQuery = goHealthQuery(
  resolve(
    import.meta.dirname,
    "../../../../services/api/internal/postgres/health.go",
  ),
);
const workerHealthQuery = goHealthQuery(
  resolve(
    import.meta.dirname,
    "../../../../services/worker/internal/postgres/health.go",
  ),
);

let envelopeSequence = 1_000;

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-identity-binding-runtime:${label}`)
    .digest();
}

function envelope(): {
  tenantAuditId: string;
  platformAuditId: string;
  requestId: string;
  correlationId: string;
} {
  envelopeSequence += 4;
  return {
    tenantAuditId: uuid(envelopeSequence - 3),
    platformAuditId: uuid(envelopeSequence - 2),
    requestId: uuid(envelopeSequence - 1),
    correlationId: uuid(envelopeSequence),
  };
}

function assertSqlState(error: unknown, expected: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function withTimeout<T>(
  promise: Promise<T>,
  message: string,
  timeoutMilliseconds = 15_000,
): Promise<T> {
  return new Promise<T>((resolvePromise, rejectPromise) => {
    const timeout = setTimeout(
      () => rejectPromise(new Error(message)),
      timeoutMilliseconds,
    );
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolvePromise(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        rejectPromise(error);
      },
    );
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function projectionTenantStatus(document: Projection): unknown {
  assert(isObject(document.tenant), "projection tenant must be an object");
  return document.tenant.status;
}

function projectionTenantVersion(document: Projection): unknown {
  assert(isObject(document.tenant), "projection tenant must be an object");
  return document.tenant.version;
}

async function asRole<T>(
  client: Sql,
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  userId = fixture.operator,
  tenantId?: string,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantId ?? ""}, true),
             set_config('app.user_id', ${userId}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function backendPid(
  transaction: postgres.TransactionSql,
): Promise<number> {
  const [backend] = await transaction<{ pid: number }[]>`
    SELECT pg_catalog.pg_backend_pid() AS pid
  `;
  assert(backend, "transaction has no PostgreSQL backend PID");
  return backend.pid;
}

async function waitForDatabaseBlocker(
  waitingPid: number,
  blockingPid: number,
  label: string,
  expectedLockType?: string,
  deadline = Date.now() + 5_000,
): Promise<void> {
  const [state] = await admin<{ blocked: boolean; expectedLock: boolean }[]>`
    SELECT ${blockingPid}::integer = ANY (
             pg_catalog.pg_blocking_pids(${waitingPid}::integer)
           ) AS blocked,
           (${expectedLockType === undefined}::boolean OR EXISTS (
             SELECT 1
             FROM pg_catalog.pg_locks AS waiting_lock
             WHERE waiting_lock.pid = ${waitingPid}::integer
               AND waiting_lock.locktype = ${expectedLockType ?? ""}::text
               AND NOT waiting_lock.granted
           )) AS "expectedLock"
  `;
  if (state?.blocked && state.expectedLock) {
    return;
  }
  if (Date.now() >= deadline) {
    throw new Error(`${label} did not reach the expected database lock`);
  }
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  await waitForDatabaseBlocker(
    waitingPid,
    blockingPid,
    label,
    expectedLockType,
    deadline,
  );
}

async function expectReadinessTamperRejected(
  label: string,
  mutate: (transaction: postgres.TransactionSql) => Promise<unknown>,
): Promise<void> {
  const rollbackProof = new Error(`${label} rollback proof`);
  await assert.rejects(
    admin.begin(async (transaction) => {
      await mutate(transaction);
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62()
                 AS ready
      `;
      assert.equal(
        tampered?.ready,
        false,
        `${label} was accepted by the current readiness root`,
      );
      throw rollbackProof;
    }),
    (error: unknown) => error === rollbackProof,
  );

  const [restored] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v62() AS ready
  `;
  assert.equal(restored?.ready, true);
}

async function createProvider(
  providerId: string,
  commandId: string,
  key: string,
): Promise<void> {
  const trace = envelope();
  await asRole(admin, "periapsis_api", async (transaction) => {
    const [created] = await transaction<{ providerId: string }[]>`
      SELECT result.provider_id AS "providerId"
      FROM app.create_platform_oidc_auth_provider_v3(
        ${fixture.operatorSession}::uuid, ${commandId}::uuid,
        ${providerId}::uuid, ${key}::text, ${`Binding runtime ${key}`}::text,
        'Disabled provider for tenant-binding security proof'::text,
        ${transaction.json(oidcConfiguration)}::jsonb,
        'https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback'::text,
        ${digest(`${key}:idempotency`)}::bytea,
        ${digest(`${key}:request`)}::bytea,
        ${trace.platformAuditId}::uuid, ${trace.requestId}::uuid,
        ${trace.correlationId}::uuid, '198.51.100.44'::inet,
        'Periapsis platform identity-binding runtime proof'::text,
        'totp'::text, 'Create disabled platform identity provider'::text
      ) AS result
    `;
    assert.equal(created?.providerId, providerId);
  });
}

async function createTenant(
  tenantId: string,
  membershipId: string,
  slug: string,
): Promise<void> {
  const trace = envelope();
  await asRole(admin, "periapsis_api", async (transaction) => {
    const [created] = await transaction<{ id: string }[]>`
      SELECT result.id
      FROM app.create_platform_tenant(
        ${tenantId}::uuid, ${membershipId}::uuid, ${slug}::text,
        ${`Binding runtime ${slug}`}::text, 'Europe/Rome'::text, 'en'::text,
        ${trace.platformAuditId}::uuid, ${trace.requestId}::uuid,
        ${trace.correlationId}::uuid, '198.51.100.44'::inet,
        'Periapsis platform identity-binding runtime proof'::text,
        'totp'::text
      ) AS result
    `;
    assert.equal(created?.id, tenantId);
  });
}

async function changeTenantLifecycle(
  tenantId: string,
  status: "active" | "suspended",
  expectedVersion: number,
  options: {
    client?: Sql;
    onStarted?: (pid: number) => void;
  } = {},
): Promise<number> {
  const trace = envelope();
  return asRole(
    options.client ?? admin,
    "periapsis_api",
    async (transaction) => {
      options.onStarted?.(await backendPid(transaction));
      const [changed] = await transaction<{ version: number }[]>`
      SELECT result.version::integer AS version
      FROM app.change_platform_tenant_lifecycle(
        ${fixture.operatorSession}::uuid, ${tenantId}::uuid,
        ${status}::public.tenant_status, ${expectedVersion}::integer,
        ${status === "suspended" ? "Suspend binding runtime tenant" : "Reactivate binding runtime tenant"}::text,
        ${trace.platformAuditId}::uuid, ${trace.requestId}::uuid,
        ${trace.correlationId}::uuid, '198.51.100.44'::inet,
        'Periapsis platform identity-binding runtime proof'::text,
        'totp'::text
      ) AS result
    `;
      assert(changed);
      return changed.version;
    },
  );
}

type CreateBindingInput = {
  client?: Sql;
  commandId: string;
  bindingId: string;
  providerId?: string;
  tenantId: string;
  key: string;
  priority?: number;
  keyDigest: Buffer;
  requestDigest: Buffer;
  tenantAuditId?: string;
  platformAuditId?: string;
  ipAddress?: string | null;
  userAgent?: string;
  onStarted?: (pid: number) => void;
  beforeCommit?: () => Promise<void>;
};

async function createBinding(
  input: CreateBindingInput,
): Promise<BindingReceipt> {
  const trace = envelope();
  return asRole(input.client ?? admin, "periapsis_api", async (transaction) => {
    input.onStarted?.(await backendPid(transaction));
    const tenantAuditId = input.tenantAuditId ?? trace.tenantAuditId;
    const [receipt] = await transaction<BindingReceipt[]>`
      SELECT result.binding_id, result.version::integer AS version,
             result.replayed, result.document
      FROM app.create_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${input.commandId}::uuid,
        ${input.bindingId}::uuid, ${input.providerId ?? fixture.provider}::uuid,
        ${input.tenantId}::uuid, ${input.key}::text,
        ${input.priority ?? 100}::integer, ${input.keyDigest}::bytea,
        ${input.requestDigest}::bytea, ${tenantAuditId}::uuid,
        ${input.platformAuditId ?? trace.platformAuditId}::uuid,
        ${trace.requestId}::uuid, ${trace.correlationId}::uuid,
        ${input.ipAddress === undefined ? "198.51.100.44" : input.ipAddress}::inet,
        ${input.userAgent ?? "Periapsis platform identity-binding runtime proof"}::text,
        'totp'::text, 'Create disabled tenant platform binding'::text
      ) AS result
    `;
    assert(receipt, "binding create returned no receipt");
    await input.beforeCommit?.();
    return receipt;
  });
}

type UpdateBindingInput = {
  client?: Sql;
  bindingId: string;
  providerId?: string;
  expectedVersion: number;
  expectedTenantVersion: number;
  key: string;
  priority?: number;
  tenantAuditId?: string;
  platformAuditId?: string;
  ipAddress?: string | null;
  userAgent?: string;
};

async function updateBinding(
  input: UpdateBindingInput,
): Promise<{ version: number; document: Projection }> {
  const trace = envelope();
  return asRole(input.client ?? admin, "periapsis_api", async (transaction) => {
    const tenantAuditId = input.tenantAuditId ?? trace.tenantAuditId;
    const [updated] = await transaction<
      { version: number; document: Projection }[]
    >`
      SELECT result.version::integer AS version, result.document
      FROM app.update_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${input.providerId ?? fixture.provider}::uuid,
        ${input.bindingId}::uuid, ${input.expectedVersion}::bigint,
        ${input.expectedTenantVersion}::integer,
        ${input.key}::text, ${input.priority ?? 100}::integer,
        ${tenantAuditId}::uuid,
        ${input.platformAuditId ?? trace.platformAuditId}::uuid,
        ${trace.requestId}::uuid, ${trace.correlationId}::uuid,
        ${input.ipAddress === undefined ? "198.51.100.44" : input.ipAddress}::inet,
        ${input.userAgent ?? "Periapsis platform identity-binding runtime proof"}::text,
        'totp'::text, 'Update disabled tenant platform binding'::text
      ) AS result
    `;
    assert(updated, "binding update returned no row");
    return updated;
  });
}

type ArchiveBindingInput = {
  client?: Sql;
  bindingId: string;
  providerId?: string;
  expectedVersion: number;
  expectedTenantVersion: number;
  tenantAuditId?: string;
  platformAuditId?: string;
  ipAddress?: string | null;
  userAgent?: string;
};

async function archiveBinding(
  input: ArchiveBindingInput,
): Promise<{ version: number; tenantVersion: number }> {
  const trace = envelope();
  return asRole(input.client ?? admin, "periapsis_api", async (transaction) => {
    const tenantAuditId = input.tenantAuditId ?? trace.tenantAuditId;
    const [archived] = await transaction<
      { version: number; tenantVersion: number }[]
    >`
      SELECT result.version::integer AS version,
             result.tenant_version::integer AS "tenantVersion"
      FROM app.archive_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${input.providerId ?? fixture.provider}::uuid,
        ${input.bindingId}::uuid, ${input.expectedVersion}::bigint,
        ${input.expectedTenantVersion}::integer,
        ${tenantAuditId}::uuid,
        ${input.platformAuditId ?? trace.platformAuditId}::uuid,
        ${trace.requestId}::uuid, ${trace.correlationId}::uuid,
        ${input.ipAddress === undefined ? "198.51.100.44" : input.ipAddress}::inet,
        ${input.userAgent ?? "Periapsis platform identity-binding runtime proof"}::text,
        'totp'::text, 'Archive disabled tenant platform binding'::text
      ) AS result
    `;
    assert(archived, "binding archive returned no row");
    return archived;
  });
}

async function createNativeBinding(
  client: Sql,
  tenantId: string,
  bindingId: string,
  providerId: string,
  key: string,
): Promise<number> {
  const trace = envelope();
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [created] = await transaction<{ version: number }[]>`
        SELECT result.binding_version::integer AS version
        FROM app.create_tenant_auth_provider_binding_v1(
          ${bindingId}::uuid, ${providerId}::uuid, ${key}::text,
          false::boolean, 100::integer, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.45'::inet,
          'Periapsis cross-family binding runtime proof'::text, 'totp'::text
        ) AS result
      `;
      assert(created);
      return created.version;
    },
    fixture.operator,
    tenantId,
  );
}

async function updateNativeBinding(
  client: Sql,
  tenantId: string,
  bindingId: string,
  key: string,
): Promise<number> {
  const trace = envelope();
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [updated] = await transaction<{ version: number }[]>`
        SELECT app.update_tenant_auth_provider_binding_v1(
          ${bindingId}::uuid, 1::integer, ${key}::text, false::boolean,
          100::integer, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.45'::inet,
          'Periapsis cross-family binding runtime proof'::text, 'totp'::text
        )::integer AS version
      `;
      assert(updated);
      return updated.version;
    },
    fixture.operator,
    tenantId,
  );
}

async function mutationCounts(): Promise<{
  bindings: number;
  commands: number;
  tenantAudits: number;
  platformAudits: number;
}> {
  const [counts] = await admin<
    {
      bindings: number;
      commands: number;
      tenantAudits: number;
      platformAudits: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_platform_auth_provider_bindings) AS bindings,
      (SELECT count(*)::integer FROM public.tenant_platform_identity_binding_commands) AS commands,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE action LIKE 'tenant.platform_identity_binding.%') AS "tenantAudits",
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action LIKE 'platform.identity_binding.%') AS "platformAudits"
  `;
  assert(counts);
  return counts;
}

async function seedFixture(): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 3_600_000);
  const [existing] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.users
    WHERE id IN (${fixture.operator}::uuid, ${fixture.denied}::uuid)
  `;
  assert.equal(
    existing?.count,
    0,
    "binding runtime proof needs a fresh database",
  );

  await admin`
    INSERT INTO public.users (id, email, display_name)
    VALUES
      (${fixture.operator}::uuid, 'binding.operator@example.invalid',
       'Platform binding operator'),
      (${fixture.denied}::uuid, 'binding.denied@example.invalid',
       'Denied platform binding operator')
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
    ) VALUES
      (${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
       ${fixture.operatorFamily}::uuid, NULL, ${digest("operator-token")}::bytea,
       ${digest("operator-csrf")}::bytea, 'totp', ${now}, ${now},
       ${expires}, ${expires}, ${now}),
      (${fixture.deniedSession}::uuid, ${fixture.denied}::uuid,
       ${fixture.deniedFamily}::uuid, NULL, ${digest("denied-token")}::bytea,
       ${digest("denied-csrf")}::bytea, 'totp', ${now}, ${now},
       ${expires}, ${expires}, ${now})
  `;

  await createProvider(
    fixture.provider,
    fixture.providerCommand,
    "binding_runtime_primary",
  );
  await createProvider(
    fixture.secondaryProvider,
    fixture.secondaryProviderCommand,
    "binding_runtime_secondary",
  );
  await createTenant(
    fixture.mainTenant,
    fixture.mainMembership,
    "binding-main",
  );
  await createTenant(
    fixture.suspendedTenant,
    fixture.suspendedMembership,
    "binding-suspended",
  );
  await createTenant(
    fixture.createRaceTenant,
    fixture.createRaceMembership,
    "binding-create-race",
  );
  await createTenant(
    fixture.renameRaceTenant,
    fixture.renameRaceMembership,
    "binding-rename-race",
  );
  await createTenant(
    fixture.reservationRaceTenant,
    fixture.reservationRaceMembership,
    "binding-reservation-race",
  );
  await createTenant(
    fixture.replayScopeTenant,
    fixture.replayScopeMembership,
    "binding-replay-scope",
  );

  await admin`
    INSERT INTO public.tenant_auth_providers (
      id, tenant_id, key, display_name, description, kind, enabled,
      created_by_membership_id, updated_by_membership_id
    ) VALUES
      (${fixture.createRaceNativeProvider}::uuid,
       ${fixture.createRaceTenant}::uuid, 'race_native_create'::text,
       'Native create race provider'::text, ''::text, 'ldap'::public.auth_provider_kind,
       false, ${fixture.createRaceMembership}::uuid,
       ${fixture.createRaceMembership}::uuid),
      (${fixture.renameRaceNativeProvider}::uuid,
       ${fixture.renameRaceTenant}::uuid, 'race_native_rename'::text,
       'Native rename race provider'::text, ''::text, 'ldap'::public.auth_provider_kind,
       false, ${fixture.renameRaceMembership}::uuid,
       ${fixture.renameRaceMembership}::uuid)
  `;
}

async function verifyCompatibilityAndAcl(): Promise<void> {
  const [compatibility] = await admin<
    {
      v62: number;
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
    }[]
  >`
    SELECT
      current.applied_count::integer AS v62,
      current.latest_created_at::text AS "currentLatest",
      current.latest_hash AS "currentHash",
      current.migration_fingerprint AS "currentFingerprint",
      predecessor.applied_count::integer AS "predecessorCount",
      predecessor.latest_created_at::text AS "predecessorLatest",
      predecessor.latest_hash AS "predecessorHash",
      predecessor.migration_fingerprint AS "predecessorFingerprint",
      legacy.applied_count::integer AS "legacyCount",
      legacy.latest_created_at::text AS "legacyLatest",
      legacy.latest_hash AS "legacyHash",
      legacy.migration_fingerprint AS "legacyFingerprint",
      app.release_runtime_schema_readiness_v62() AS ready,
      app.platform_oidc_direct_runtime_schema_readiness_v62() AS "oidcReady"
    FROM app.schema_compatibility_v62() AS current
    CROSS JOIN app.schema_compatibility_v48() AS predecessor
    CROSS JOIN app.schema_compatibility_v40() AS legacy
  `;
  assert.deepEqual(compatibility, {
    v62: expectedMigrationCount,
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
  });

  const configuredKeyring = await admin<KeyringEvidenceRow[]>`
    SELECT keyring.key_version, keyring.verifier, keyring.is_active
    FROM public.identity_keyring_versions AS keyring
    WHERE keyring.retired_at IS NULL
    ORDER BY keyring.key_version
  `;
  const activeKeyring = configuredKeyring.filter((entry) => entry.is_active);
  assert.ok(
    configuredKeyring.length === 0 || activeKeyring.length === 1,
    "configured keyring has no unique active version",
  );
  const workerKeyVersions =
    configuredKeyring.length === 0
      ? [1]
      : configuredKeyring.map((entry) => entry.key_version);
  const workerKeyVerifiers =
    configuredKeyring.length === 0
      ? [Buffer.alloc(32, 0x9b)]
      : configuredKeyring.map((entry) => entry.verifier);
  const workerActiveKeyVersion =
    activeKeyring[0]?.key_version ?? workerKeyVersions[0];
  assert(workerActiveKeyVersion !== undefined);

  const liveHealthQueries = await Promise.all([
    asRole(admin, "periapsis_api", async (transaction) => {
      const rows = await transaction.unsafe<LiveHealthRow[]>(apiHealthQuery, [
        expectedMigrationFingerprint,
      ]);
      return { role: "periapsis_api", rows } as const;
    }),
    asRole(admin, "periapsis_worker", async (transaction) => {
      const rows = await transaction.unsafe<LiveHealthRow[]>(
        workerHealthQuery,
        [
          workerKeyVersions,
          postgresByteaArray(workerKeyVerifiers),
          workerActiveKeyVersion,
          expectedMigrationFingerprint,
        ],
      );
      return { role: "periapsis_worker", rows } as const;
    }),
  ]);
  for (const result of liveHealthQueries) {
    assert.equal(
      result.rows.length,
      1,
      `${result.role} health returned no row`,
    );
    assertLiveHealthRow(result.rows[0], result.role);
  }

  await assertServiceReadinessAggregation({
    admin,
    userId: fixture.operator,
    api: {
      query: apiHealthQuery,
      parameters: [expectedMigrationFingerprint],
      assertReady: (row) => assertLiveHealthRow(row, "periapsis_api"),
    },
    worker: {
      query: workerHealthQuery,
      parameters: [
        workerKeyVersions,
        postgresByteaArray(workerKeyVerifiers),
        workerActiveKeyVersion,
        expectedMigrationFingerprint,
      ],
      assertReady: (row) => assertLiveHealthRow(row, "periapsis_worker"),
    },
  });

  const rollbackReadinessProof = new Error("rollback readiness ACL proof");
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction`
        REVOKE EXECUTE ON FUNCTION
          app.get_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, text)
        FROM periapsis_api
      `;
      const [revoked] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62() AS ready
      `;
      assert.equal(revoked?.ready, false);
      throw rollbackReadinessProof;
    }),
    (error: unknown) => error === rollbackReadinessProof,
  );
  const [restoredReadiness] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v62() AS ready
  `;
  assert.equal(restoredReadiness?.ready, true);

  await expectReadinessTamperRejected(
    "binding surface helper body drift",
    (transaction) =>
      transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_tenant_platform_identity_binding_surface_hash_v1()
        RETURNS text
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, app
        AS $function$
          SELECT
            'e6d030f84e156818247ea24720c7fc56a326b8a612c55cc4766027c4d6f0752a'::text;
        $function$
      `),
  );

  await expectReadinessTamperRejected(
    "raw binding readiness body drift",
    (transaction) =>
      transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.tenant_platform_identity_binding_schema_readiness_v1()
        RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, app
        AS $function$
        BEGIN
          RETURN true;
        END;
        $function$
      `),
  );

  await expectReadinessTamperRejected(
    "public binding readiness body drift",
    (transaction) =>
      transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.tenant_platform_identity_binding_schema_readiness_v2()
        RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, app
        AS $function$
        BEGIN
          RETURN true;
        END;
        $function$
      `),
  );

  await expectReadinessTamperRejected(
    "retired compatibility body drift",
    (transaction) =>
      transaction.unsafe(`
        CREATE OR REPLACE FUNCTION app.schema_compatibility_v32()
        RETURNS TABLE(
          applied_count bigint,
          latest_created_at bigint,
          latest_hash text,
          migration_fingerprint text
        )
        LANGUAGE plpgsql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        SET app.schema_compatibility_fingerprint = 'RETIRED'
        AS $function$
        BEGIN
          RETURN QUERY SELECT 0::bigint, 0::bigint,
                              'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
        END;
        $function$
      `),
  );

  await expectReadinessTamperRejected(
    "binding readiness grant option drift",
    (transaction) =>
      transaction.unsafe(`
        GRANT EXECUTE ON FUNCTION
          app.tenant_platform_identity_binding_schema_readiness_v2()
        TO periapsis_api WITH GRANT OPTION
      `),
  );

  await expectReadinessTamperRejected(
    "binding readiness PUBLIC grant drift",
    (transaction) =>
      transaction.unsafe(`
        GRANT EXECUTE ON FUNCTION
          app.tenant_platform_identity_binding_schema_readiness_v2()
        TO PUBLIC
      `),
  );

  await expectReadinessTamperRejected(
    "binding readiness unlisted grant drift",
    async (transaction) => {
      await transaction.unsafe(`
        CREATE ROLE periapsis_binding_readiness_acl_probe NOLOGIN
      `);
      await transaction.unsafe(`
        GRANT EXECUTE ON FUNCTION
          app.tenant_platform_identity_binding_schema_readiness_v2()
        TO periapsis_binding_readiness_acl_probe
      `);
    },
  );

  await expectReadinessTamperRejected(
    "retired v34 compatibility config drift",
    (transaction) =>
      transaction.unsafe(`
        ALTER FUNCTION app.schema_compatibility_v34()
          SET app.unexpected_compatibility_setting = 'drift'
      `),
  );

  await expectReadinessTamperRejected(
    "retired v34 compatibility grant option drift",
    (transaction) =>
      transaction.unsafe(`
        GRANT EXECUTE ON FUNCTION app.schema_compatibility_v34()
        TO periapsis_api WITH GRANT OPTION
      `),
  );

  await expectReadinessTamperRejected(
    "protected relation rule drift",
    (transaction) =>
      transaction.unsafe(`
        CREATE RULE tenant_platform_binding_delete_bypass_probe AS
        ON DELETE TO public.tenant_platform_identity_binding_commands
        DO INSTEAD NOTHING
      `),
  );

  await expectReadinessTamperRejected(
    "tenant projection version trigger drift",
    (transaction) =>
      transaction.unsafe(`
        ALTER TABLE public.tenants
          DISABLE TRIGGER tenants_identity_projection_version_guard_v1
      `),
  );

  const rollbackKeyProof = new Error("rollback cross-family key proof");
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction`
        ALTER TABLE public.tenant_auth_provider_login_keys
        DROP CONSTRAINT tenant_auth_provider_login_keys_pkey
      `;
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62() AS ready
      `;
      assert.equal(tampered?.ready, false);
      throw rollbackKeyProof;
    }),
    (error: unknown) => error === rollbackKeyProof,
  );
  const [restoredKeyReadiness] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v62() AS ready
  `;
  assert.equal(restoredKeyReadiness?.ready, true);

  const rollbackPersistenceProof = new Error(
    "rollback protected persistence proof",
  );
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction`
        ALTER TABLE public.tenant_platform_identity_binding_commands
        SET UNLOGGED
      `;
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62() AS ready
      `;
      assert.equal(tampered?.ready, false);
      throw rollbackPersistenceProof;
    }),
    (error: unknown) => error === rollbackPersistenceProof,
  );
  const [restoredPersistenceReadiness] = await admin<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v62() AS ready
  `;
  assert.equal(restoredPersistenceReadiness?.ready, true);

  const executable = await admin<{ name: string }[]>`
    SELECT function.proname AS name
    FROM pg_catalog.pg_proc AS function
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function.pronamespace
    WHERE namespace.nspname = 'app'
      AND function.proname LIKE '%tenant_platform_auth_provider_binding%'
      AND has_function_privilege(
        'periapsis_api', function.oid, 'EXECUTE'
      )
    ORDER BY function.proname
  `;
  assert.deepEqual(
    executable.map((row) => row.name),
    [...protectedFunctionNames],
  );

  const [workerAcl] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM pg_catalog.pg_proc AS function
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function.pronamespace
    WHERE namespace.nspname = 'app'
      AND function.proname LIKE '%tenant_platform_auth_provider_binding%'
      AND has_function_privilege('periapsis_worker', function.oid, 'EXECUTE')
  `;
  assert.equal(workerAcl?.count, 0);

  await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).flatMap((role) =>
      protectedTables.map(async (table) => {
        const [privilege] = await admin<{ allowed: boolean }[]>`
        SELECT has_table_privilege(
          ${role}, ${`public.${table}`},
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        ) AS allowed
      `;
        assert.equal(privilege?.allowed, false, `${role} can mutate ${table}`);
      }),
    ),
  );

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`SELECT * FROM public.tenant_platform_auth_provider_bindings`,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`
        SELECT app.private_tenant_platform_auth_provider_binding_document_v1(
          ${fixture.mainBinding}::uuid
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
}

async function verifyInvalidCreateEnvelopes(): Promise<void> {
  const before = await mutationCounts();
  const cases = [
    { ipAddress: null, userAgent: "valid-agent" },
    { ipAddress: "198.51.100.44", userAgent: "control\u0001agent" },
    { ipAddress: "198.51.100.44", userAgent: "format\u200bagent" },
    { ipAddress: "198.51.100.44", userAgent: "a".repeat(513) },
  ] as const;
  await Promise.all(
    cases.map((invalid, index) =>
      assert.rejects(
        createBinding({
          commandId: uuid(200 + index * 2),
          bindingId: uuid(201 + index * 2),
          tenantId: fixture.suspendedTenant,
          key: `invalid_create_${index}`,
          keyDigest: digest(`invalid-create-key-${index}`),
          requestDigest: digest(`invalid-create-request-${index}`),
          ...invalid,
        }),
        (error: unknown) => assertSqlState(error, "22023"),
      ),
    ),
  );
  const sameAudit = uuid(220);
  await assert.rejects(
    createBinding({
      commandId: uuid(221),
      bindingId: uuid(222),
      tenantId: fixture.suspendedTenant,
      key: "invalid_create_audit",
      keyDigest: digest("invalid-create-audit-key"),
      requestDigest: digest("invalid-create-audit-request"),
      tenantAuditId: sameAudit,
      platformAuditId: sameAudit,
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  assert.deepEqual(await mutationCounts(), before);
}

async function verifyCreateLifecycleReservationSerialization(): Promise<void> {
  const before = await mutationCounts();
  const firstStarted = Promise.withResolvers<number>();
  const firstReady = Promise.withResolvers<void>();
  const releaseFirst = Promise.withResolvers<void>();
  const firstCreate = createBinding({
    client: raceA,
    commandId: fixture.reservationRaceCommittedCommand,
    bindingId: fixture.reservationRaceCommittedBinding,
    tenantId: fixture.reservationRaceTenant,
    key: "reservation_race_committed",
    keyDigest: digest("reservation-race-committed-key"),
    requestDigest: digest("reservation-race-committed-request"),
    onStarted: firstStarted.resolve,
    beforeCommit: async () => {
      firstReady.resolve();
      await releaseFirst.promise;
    },
  });
  const firstOutcome = firstCreate.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );

  let suspensionOutcome:
    Promise<{ result: number } | { error: unknown }> | undefined;
  let competingOutcome:
    Promise<{ result: BindingReceipt } | { error: unknown }> | undefined;
  try {
    const firstPid = await withTimeout(
      firstStarted.promise,
      "reservation winner did not start",
    );
    await withTimeout(
      firstReady.promise,
      "reservation winner did not hold its uncommitted create",
    );

    const suspensionStarted = Promise.withResolvers<number>();
    const suspension = changeTenantLifecycle(
      fixture.reservationRaceTenant,
      "suspended",
      1,
      { client: raceB, onStarted: suspensionStarted.resolve },
    );
    suspensionOutcome = suspension.then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );
    const suspensionPid = await withTimeout(
      suspensionStarted.promise,
      "queued tenant suspension did not start",
    );
    await waitForDatabaseBlocker(suspensionPid, firstPid, "tenant suspension");

    const competingStarted = Promise.withResolvers<number>();
    const competing = createBinding({
      client: admin,
      commandId: fixture.reservationRaceCompetingCommand,
      bindingId: fixture.reservationRaceCompetingBinding,
      tenantId: fixture.reservationRaceTenant,
      key: "reservation_race_competing",
      keyDigest: digest("reservation-race-competing-key"),
      requestDigest: digest("reservation-race-competing-request"),
      tenantAuditId: fixture.reservationRaceCompetingTenantAudit,
      platformAuditId: fixture.reservationRaceCompetingPlatformAudit,
      onStarted: competingStarted.resolve,
    });
    competingOutcome = competing.then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );
    const competingPid = await withTimeout(
      competingStarted.promise,
      "competing reservation did not start",
    );
    await waitForDatabaseBlocker(
      competingPid,
      firstPid,
      "competing provider/tenant reservation",
      "advisory",
    );
  } finally {
    releaseFirst.resolve();
  }

  const committed = await withTimeout(
    firstOutcome,
    "reservation winner did not commit",
  );
  assert(suspensionOutcome, "queued tenant suspension was not started");
  const suspended = await withTimeout(
    suspensionOutcome,
    "queued tenant suspension did not finish",
  );
  assert(competingOutcome, "competing reservation was not started");
  const competing = await withTimeout(
    competingOutcome,
    "competing reservation did not finish",
  );

  assert("result" in committed, "reservation winner failed");
  assert.equal(
    committed.result.binding_id,
    fixture.reservationRaceCommittedBinding,
  );
  assert.equal(committed.result.replayed, false);
  assert("result" in suspended, "queued tenant suspension failed");
  assert.equal(suspended.result, 2);
  assert("error" in competing, "competing reservation unexpectedly succeeded");
  assertSqlState(competing.error, "55000");
  assert(competing.error instanceof Error);
  assert.equal(
    competing.error.message,
    "tenant platform identity binding already exists",
  );

  assert.deepEqual(await mutationCounts(), {
    bindings: before.bindings + 1,
    commands: before.commands + 1,
    tenantAudits: before.tenantAudits + 1,
    platformAudits: before.platformAudits + 1,
  });
  const [state] = await admin<
    {
      tenantStatus: string;
      tenantVersion: number;
      committedBindings: number;
      competingBindings: number;
      committedCommands: number;
      competingCommands: number;
      committedClaims: number;
      competingClaims: number;
      competingTenantAudits: number;
      competingPlatformAudits: number;
    }[]
  >`
    SELECT
      (SELECT tenant.status::text FROM public.tenants AS tenant
       WHERE tenant.id = ${fixture.reservationRaceTenant}::uuid) AS "tenantStatus",
      (SELECT tenant.version::integer FROM public.tenants AS tenant
       WHERE tenant.id = ${fixture.reservationRaceTenant}::uuid) AS "tenantVersion",
      (SELECT count(*)::integer
       FROM public.tenant_platform_auth_provider_bindings AS binding
       WHERE binding.id = ${fixture.reservationRaceCommittedBinding}::uuid) AS "committedBindings",
      (SELECT count(*)::integer
       FROM public.tenant_platform_auth_provider_bindings AS binding
       WHERE binding.id = ${fixture.reservationRaceCompetingBinding}::uuid) AS "competingBindings",
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_binding_commands AS command
       WHERE command.id = ${fixture.reservationRaceCommittedCommand}::uuid) AS "committedCommands",
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_binding_commands AS command
       WHERE command.id = ${fixture.reservationRaceCompetingCommand}::uuid) AS "competingCommands",
      (SELECT count(*)::integer
       FROM public.tenant_auth_provider_login_keys AS login_key
       WHERE login_key.tenant_id = ${fixture.reservationRaceTenant}::uuid
         AND login_key.key = 'reservation_race_committed') AS "committedClaims",
      (SELECT count(*)::integer
       FROM public.tenant_auth_provider_login_keys AS login_key
       WHERE login_key.tenant_id = ${fixture.reservationRaceTenant}::uuid
         AND login_key.key = 'reservation_race_competing') AS "competingClaims",
      (SELECT count(*)::integer FROM public.audit_events AS event
       WHERE event.id = ${fixture.reservationRaceCompetingTenantAudit}::uuid) AS "competingTenantAudits",
      (SELECT count(*)::integer FROM public.platform_audit_events AS event
       WHERE event.id = ${fixture.reservationRaceCompetingPlatformAudit}::uuid) AS "competingPlatformAudits"
  `;
  assert.deepEqual(state, {
    tenantStatus: "suspended",
    tenantVersion: 2,
    committedBindings: 1,
    competingBindings: 0,
    committedCommands: 1,
    competingCommands: 0,
    committedClaims: 1,
    competingClaims: 0,
    competingTenantAudits: 0,
    competingPlatformAudits: 0,
  });
}

async function verifyMainLifecycle(): Promise<void> {
  const receipt = await createBinding({
    commandId: fixture.mainCommand,
    bindingId: fixture.mainBinding,
    tenantId: fixture.mainTenant,
    key: "main_platform_login",
    priority: 120,
    keyDigest: digest("main-key"),
    requestDigest: digest("main-request"),
  });
  assert.equal(receipt.binding_id, fixture.mainBinding);
  assert.equal(receipt.version, 1);
  assert.equal(receipt.replayed, false);
  assert.equal(receipt.document.version, 1);
  assert.equal(receipt.document.enabled, false);
  assert.equal(receipt.document.activationAvailable, false);
  assert.equal(receipt.document.currentAccessEpochId, null);
  assert.equal(receipt.document.authRevision, 1);
  assert.equal(receipt.document.mappingRevision, 1);
  assert.equal(projectionTenantVersion(receipt.document), 1);

  await assert.rejects(
    createBinding({
      commandId: fixture.replayScopeCommand,
      bindingId: fixture.replayScopeBinding,
      tenantId: fixture.replayScopeTenant,
      key: "main_platform_login",
      priority: 120,
      keyDigest: digest("main-key"),
      requestDigest: digest("main-request"),
      tenantAuditId: fixture.replayScopeTenantAudit,
      platformAuditId: fixture.replayScopePlatformAudit,
    }),
    (error: unknown) => {
      assertSqlState(error, "23505");
      assert(error instanceof Error);
      assert.equal(
        error.message,
        "tenant platform identity binding idempotency key was reused with different input",
      );
      return true;
    },
  );
  const [crossTenantReplayState] = await admin<
    {
      tenantStatus: string;
      tenantVersion: number;
      competingBindings: number;
      competingClaims: number;
      replayCommands: number;
      originalCommands: number;
      competingTenantAudits: number;
      competingPlatformAudits: number;
    }[]
  >`
    SELECT
      (SELECT tenant.status::text FROM public.tenants AS tenant
       WHERE tenant.id = ${fixture.replayScopeTenant}::uuid) AS "tenantStatus",
      (SELECT tenant.version::integer FROM public.tenants AS tenant
       WHERE tenant.id = ${fixture.replayScopeTenant}::uuid) AS "tenantVersion",
      (SELECT count(*)::integer
       FROM public.tenant_platform_auth_provider_bindings AS binding
       WHERE binding.tenant_id = ${fixture.replayScopeTenant}::uuid
         AND binding.platform_provider_id = ${fixture.provider}::uuid)
        AS "competingBindings",
      (SELECT count(*)::integer
       FROM public.tenant_auth_provider_login_keys AS login_key
       WHERE login_key.tenant_id = ${fixture.replayScopeTenant}::uuid
         AND login_key.key = 'main_platform_login') AS "competingClaims",
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_binding_commands AS command
       WHERE command.actor_user_id = ${fixture.operator}::uuid
         AND command.operation = 'binding.create'
         AND command.key_digest = ${digest("main-key")}::bytea)
        AS "replayCommands",
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_binding_commands AS command
       WHERE command.id = ${fixture.mainCommand}::uuid
         AND command.tenant_id = ${fixture.mainTenant}::uuid)
        AS "originalCommands",
      (SELECT count(*)::integer FROM public.audit_events AS event
       WHERE event.id = ${fixture.replayScopeTenantAudit}::uuid)
        AS "competingTenantAudits",
      (SELECT count(*)::integer FROM public.platform_audit_events AS event
       WHERE event.id = ${fixture.replayScopePlatformAudit}::uuid)
        AS "competingPlatformAudits"
  `;
  assert.deepEqual(crossTenantReplayState, {
    tenantStatus: "active",
    tenantVersion: 1,
    competingBindings: 0,
    competingClaims: 0,
    replayCommands: 1,
    originalCommands: 1,
    competingTenantAudits: 0,
    competingPlatformAudits: 0,
  });

  const [commandRetention] = await admin<{ exact: boolean }[]>`
    SELECT command.expires_at - command.created_at = interval '24 hours'
             AS exact
    FROM public.tenant_platform_identity_binding_commands AS command
    WHERE command.id = ${fixture.mainCommand}::uuid
  `;
  assert.equal(
    commandRetention?.exact,
    true,
    "binding-create idempotency receipts must expire exactly 24 hours after creation",
  );

  const expiryKeyDigest = digest("expired-binding-key");
  await admin`
    INSERT INTO public.tenant_platform_identity_binding_commands (
      id, tenant_id, actor_user_id, operation, key_digest, request_digest,
      result_binding_id, result_version, created_at, expires_at
    ) VALUES (
      ${fixture.expiryCommand}::uuid, ${fixture.mainTenant}::uuid,
      ${fixture.operator}::uuid, 'binding.create', ${expiryKeyDigest}::bytea,
      ${digest("expired-binding-request")}::bytea,
      ${fixture.mainBinding}::uuid, 1::bigint,
      transaction_timestamp() - interval '24 hours',
      transaction_timestamp()
    )
  `;
  const replacementAfterExpiry = await createBinding({
    commandId: fixture.expiryCommand,
    bindingId: fixture.expiryBinding,
    providerId: fixture.secondaryProvider,
    tenantId: fixture.mainTenant,
    key: "expiry_replacement_login",
    keyDigest: expiryKeyDigest,
    requestDigest: digest("replacement-after-24-hours"),
  });
  assert.equal(replacementAfterExpiry.replayed, false);
  assert.equal(replacementAfterExpiry.binding_id, fixture.expiryBinding);
  const [replacementCommand] = await admin<
    { resultBindingId: string; exactRetention: boolean }[]
  >`
    SELECT command.result_binding_id AS "resultBindingId",
           command.expires_at - command.created_at = interval '24 hours'
             AS "exactRetention"
    FROM public.tenant_platform_identity_binding_commands AS command
    WHERE command.id = ${fixture.expiryCommand}::uuid
  `;
  assert.deepEqual(replacementCommand, {
    resultBindingId: fixture.expiryBinding,
    exactRetention: true,
  });

  await assert.rejects(
    admin`
      UPDATE public.tenants AS tenant
      SET status = 'suspended'
      WHERE tenant.id = ${fixture.mainTenant}::uuid
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    admin`
      UPDATE public.tenants AS tenant
      SET version = tenant.version + 2
      WHERE tenant.id = ${fixture.mainTenant}::uuid
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) => transaction`
        SELECT app.get_tenant_platform_auth_provider_binding_v1(
          ${fixture.deniedSession}::uuid, ${fixture.provider}::uuid,
          ${fixture.mainBinding}::uuid, 'totp'::text
        )
      `,
      fixture.denied,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) => transaction`
      SELECT app.get_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${uuid(999_900)}::uuid,
        ${uuid(999_901)}::uuid, 'totp'::text
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const invalidBefore = await mutationCounts();
  const invalidAgents = [
    { ipAddress: null, userAgent: "valid-agent" },
    { ipAddress: "198.51.100.44", userAgent: "control\u0001agent" },
    { ipAddress: "198.51.100.44", userAgent: "format\u200bagent" },
    { ipAddress: "198.51.100.44", userAgent: "a".repeat(513) },
  ] as const;
  await Promise.all(
    invalidAgents.flatMap((invalid) => [
      assert.rejects(
        updateBinding({
          bindingId: fixture.mainBinding,
          expectedVersion: 1,
          expectedTenantVersion: 1,
          key: "main_platform_login",
          ...invalid,
        }),
        (error: unknown) => assertSqlState(error, "22023"),
      ),
      assert.rejects(
        archiveBinding({
          bindingId: fixture.mainBinding,
          expectedVersion: 1,
          expectedTenantVersion: 1,
          ...invalid,
        }),
        (error: unknown) => assertSqlState(error, "22023"),
      ),
    ]),
  );
  await Promise.all(
    (["update", "archive"] as const).map((operation) => {
      const sameAudit = uuid(operation === "update" ? 230 : 231);
      const invocation =
        operation === "update"
          ? updateBinding({
              bindingId: fixture.mainBinding,
              expectedVersion: 1,
              expectedTenantVersion: 1,
              key: "main_platform_login",
              tenantAuditId: sameAudit,
              platformAuditId: sameAudit,
            })
          : archiveBinding({
              bindingId: fixture.mainBinding,
              expectedVersion: 1,
              expectedTenantVersion: 1,
              tenantAuditId: sameAudit,
              platformAuditId: sameAudit,
            });
      return assert.rejects(invocation, (error: unknown) =>
        assertSqlState(error, "22023"),
      );
    }),
  );
  await assert.rejects(
    updateBinding({
      bindingId: fixture.mainBinding,
      expectedVersion: 2_147_483_647,
      expectedTenantVersion: 1,
      key: "main_platform_login",
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    archiveBinding({
      bindingId: fixture.mainBinding,
      expectedVersion: 2_147_483_647,
      expectedTenantVersion: 1,
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  assert.deepEqual(await mutationCounts(), invalidBefore);

  await assert.rejects(
    asRole(admin, "periapsis_api", async (transaction) => {
      const trace = envelope();
      await transaction`
        SELECT app.archive_platform_auth_provider_v1(
          ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
          1::bigint, ${trace.platformAuditId}::uuid, ${trace.requestId}::uuid,
          ${trace.correlationId}::uuid, '198.51.100.44'::inet,
          'Periapsis platform identity-binding runtime proof'::text,
          'totp'::text, 'Archive provider with live tenant binding'::text
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    admin`DELETE FROM public.platform_auth_providers WHERE id = ${fixture.provider}::uuid`,
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const updated = await updateBinding({
    bindingId: fixture.mainBinding,
    expectedVersion: 1,
    expectedTenantVersion: 1,
    key: "main_platform_login_v2",
    priority: 121,
  });
  assert.equal(updated.version, 2);
  assert.equal(updated.document.version, 2);
  assert.equal(updated.document.loginKey, "main_platform_login_v2");
  assert.equal(updated.document.mappingRevision, 1);
  assert.equal(projectionTenantVersion(updated.document), 1);

  await assert.rejects(
    updateBinding({
      bindingId: fixture.mainBinding,
      expectedVersion: 1,
      expectedTenantVersion: 1,
      key: "main_platform_login_v3",
    }),
    (error: unknown) => {
      assertSqlState(error, "40001");
      assert(error instanceof Error);
      assert.equal(
        error.message,
        "tenant platform identity binding revision conflict",
      );
      return true;
    },
  );

  const replayAfterUpdate = await createBinding({
    commandId: fixture.mainCommand,
    bindingId: fixture.mainBinding,
    tenantId: fixture.mainTenant,
    key: "main_platform_login",
    priority: 120,
    keyDigest: digest("main-key"),
    requestDigest: digest("main-request"),
  });
  assert.equal(replayAfterUpdate.replayed, true);
  assert.equal(replayAfterUpdate.version, 1);
  assert.equal(replayAfterUpdate.document.version, 2);
  assert.equal(replayAfterUpdate.document.loginKey, "main_platform_login_v2");
  assert.equal(projectionTenantVersion(replayAfterUpdate.document), 1);

  await assert.rejects(
    createBinding({
      commandId: fixture.mainCommand,
      bindingId: fixture.mainBinding,
      tenantId: fixture.mainTenant,
      key: "main_platform_login",
      priority: 120,
      keyDigest: digest("main-key"),
      requestDigest: digest("main-request-conflict"),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const forgedReplayBefore = await mutationCounts();
  await assert.rejects(
    createBinding({
      commandId: uuid(230),
      bindingId: uuid(231),
      tenantId: fixture.mainTenant,
      key: "forged_replay_login",
      priority: 999,
      keyDigest: digest("main-key"),
      requestDigest: digest("main-request"),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  assert.deepEqual(
    await mutationCounts(),
    forgedReplayBefore,
    "reusing the caller digest with a changed payload must not mutate or audit",
  );

  const lifecycleRaceBefore = await mutationCounts();
  const [lifecycleRace, bindingRace] = await Promise.allSettled([
    changeTenantLifecycle(fixture.mainTenant, "suspended", 1),
    updateBinding({
      client: raceA,
      bindingId: fixture.mainBinding,
      expectedVersion: 2,
      expectedTenantVersion: 1,
      key: "main_platform_login_v3",
      priority: 122,
    }),
  ]);
  assert.equal(lifecycleRace.status, "fulfilled");
  if (lifecycleRace.status === "fulfilled") {
    assert.equal(lifecycleRace.value, 2);
  }
  let currentBindingVersion = 2;
  if (bindingRace.status === "fulfilled") {
    currentBindingVersion = 3;
    assert.equal(bindingRace.value.version, 3);
    assert.equal(projectionTenantVersion(bindingRace.value.document), 1);
  } else {
    assertSqlState(bindingRace.reason, "40001");
  }
  const lifecycleRaceAfter = await mutationCounts();
  const successfulBindingMutation = bindingRace.status === "fulfilled" ? 1 : 0;
  assert.equal(
    lifecycleRaceAfter.tenantAudits,
    lifecycleRaceBefore.tenantAudits + successfulBindingMutation,
  );
  assert.equal(
    lifecycleRaceAfter.platformAudits,
    lifecycleRaceBefore.platformAudits + successfulBindingMutation,
  );
  const [historical] = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ document: Projection }[]>`
      SELECT app.get_tenant_platform_auth_provider_binding_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.mainBinding}::uuid, 'totp'::text
      ) AS document
    `,
  );
  assert(historical);
  assert.equal(projectionTenantStatus(historical.document), "suspended");
  assert.equal(projectionTenantVersion(historical.document), 2);
  assert.equal(historical.document.version, currentBindingVersion);

  const staleTenantBefore = await mutationCounts();
  await Promise.all(
    [
      () =>
        updateBinding({
          bindingId: fixture.mainBinding,
          expectedVersion: currentBindingVersion,
          expectedTenantVersion: 1,
          key: "stale_tenant_update",
        }),
      () =>
        archiveBinding({
          bindingId: fixture.mainBinding,
          expectedVersion: currentBindingVersion,
          expectedTenantVersion: 1,
        }),
    ].map((staleMutation) =>
      assert.rejects(staleMutation(), (error: unknown) => {
        assertSqlState(error, "40001");
        assert(error instanceof Error);
        assert.equal(
          error.message,
          "tenant platform identity binding revision conflict",
        );
        return true;
      }),
    ),
  );
  assert.deepEqual(
    await mutationCounts(),
    staleTenantBefore,
    "a stale tenant component must not mutate the binding or either audit chain",
  );

  const suspendedTenantVersion = await changeTenantLifecycle(
    fixture.suspendedTenant,
    "suspended",
    1,
  );
  assert.equal(suspendedTenantVersion, 2);

  const suspendedBefore = await mutationCounts();
  await assert.rejects(
    createBinding({
      commandId: uuid(240),
      bindingId: uuid(241),
      tenantId: fixture.suspendedTenant,
      key: "suspended_new_login",
      keyDigest: digest("suspended-new-key"),
      requestDigest: digest("suspended-new-request"),
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  assert.deepEqual(await mutationCounts(), suspendedBefore);

  const auditBeforeArchive = await mutationCounts();
  const archiveReceipt = await archiveBinding({
    bindingId: fixture.mainBinding,
    expectedVersion: currentBindingVersion,
    expectedTenantVersion: 2,
  });
  assert.deepEqual(archiveReceipt, {
    version: currentBindingVersion + 1,
    tenantVersion: 2,
  });

  const expiredSamePairKeyDigest = digest("expired-same-pair-key");
  await admin`
    INSERT INTO public.tenant_platform_identity_binding_commands (
      id, tenant_id, actor_user_id, operation, key_digest, request_digest,
      result_binding_id, result_version, created_at, expires_at
    ) VALUES (
      ${fixture.expiredSamePairCommand}::uuid, ${fixture.mainTenant}::uuid,
      ${fixture.operator}::uuid, 'binding.create',
      ${expiredSamePairKeyDigest}::bytea,
      ${digest("expired-same-pair-request")}::bytea,
      ${fixture.mainBinding}::uuid, 1::bigint,
      transaction_timestamp() - interval '24 hours',
      transaction_timestamp()
    )
  `;
  const expiredSamePairBefore = await mutationCounts();
  await assert.rejects(
    createBinding({
      commandId: fixture.expiredSamePairRetryCommand,
      bindingId: fixture.expiredSamePairRetryBinding,
      tenantId: fixture.mainTenant,
      key: "expired_same_pair_retry",
      keyDigest: expiredSamePairKeyDigest,
      requestDigest: digest("expired-same-pair-retry-request"),
    }),
    (error: unknown) => {
      assertSqlState(error, "55000");
      assert(error instanceof Error);
      assert.equal(
        error.message,
        "tenant platform identity binding already exists",
      );
      return true;
    },
  );
  assert.deepEqual(
    await mutationCounts(),
    expiredSamePairBefore,
    "an expired same-pair retry must not mutate bindings, commands, or audit chains",
  );
  const [expiredSamePairState] = await admin<
    { expiredCommands: number; pairBindings: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_binding_commands AS command
       WHERE command.id = ${fixture.expiredSamePairCommand}::uuid
         AND command.expires_at <= transaction_timestamp()) AS "expiredCommands",
      (SELECT count(*)::integer
       FROM public.tenant_platform_auth_provider_bindings AS binding
       WHERE binding.tenant_id = ${fixture.mainTenant}::uuid
         AND binding.platform_provider_id = ${fixture.provider}::uuid) AS "pairBindings"
  `;
  assert.deepEqual(expiredSamePairState, {
    expiredCommands: 1,
    pairBindings: 1,
  });

  const replayAfterArchive = await createBinding({
    commandId: fixture.mainCommand,
    bindingId: fixture.mainBinding,
    tenantId: fixture.mainTenant,
    key: "main_platform_login",
    priority: 120,
    keyDigest: digest("main-key"),
    requestDigest: digest("main-request"),
  });
  assert.equal(replayAfterArchive.version, 1);
  assert.equal(replayAfterArchive.replayed, true);
  assert.equal(replayAfterArchive.document.version, currentBindingVersion + 1);
  assert.equal(projectionTenantVersion(replayAfterArchive.document), 2);
  assert.notEqual(replayAfterArchive.document.archivedAt, null);
  const auditAfterReplay = await mutationCounts();
  assert.equal(
    auditAfterReplay.tenantAudits,
    auditBeforeArchive.tenantAudits + 1,
  );
  assert.equal(
    auditAfterReplay.platformAudits,
    auditBeforeArchive.platformAudits + 1,
  );

  const visible = await asRole(
    admin,
    "periapsis_api",
    (transaction) => transaction<{ document: Projection }[]>`
      SELECT document
      FROM app.list_tenant_platform_auth_provider_bindings_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        'totp'::text, NULL::uuid, 50::integer, true::boolean
      )
    `,
  );
  assert(
    visible.some(
      (row) =>
        row.document.id === fixture.mainBinding &&
        projectionTenantStatus(row.document) === "suspended",
    ),
  );
}

async function verifyCrossFamilyConcurrency(): Promise<void> {
  const createResults = await Promise.allSettled([
    createBinding({
      client: raceA,
      commandId: uuid(250),
      bindingId: fixture.createRacePlatformBinding,
      tenantId: fixture.createRaceTenant,
      key: "cross_family_create",
      keyDigest: digest("cross-create-platform-key"),
      requestDigest: digest("cross-create-platform-request"),
    }),
    createNativeBinding(
      raceB,
      fixture.createRaceTenant,
      fixture.createRaceNativeBinding,
      fixture.createRaceNativeProvider,
      "cross_family_create",
    ),
  ]);
  assert.equal(
    createResults.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const createFailure = createResults.find(
    (result) => result.status === "rejected",
  );
  assert(createFailure && createFailure.status === "rejected");
  assertSqlState(createFailure.reason, "23505");
  const [createdClaim] = await admin<{ claims: number; children: number }[]>`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_auth_provider_login_keys
       WHERE tenant_id = ${fixture.createRaceTenant}::uuid
         AND key = 'cross_family_create') AS claims,
      ((SELECT count(*) FROM public.tenant_auth_provider_bindings
        WHERE tenant_id = ${fixture.createRaceTenant}::uuid
          AND key = 'cross_family_create') +
       (SELECT count(*) FROM public.tenant_platform_auth_provider_bindings
        WHERE tenant_id = ${fixture.createRaceTenant}::uuid
          AND key = 'cross_family_create'))::integer AS children
  `;
  assert.deepEqual(createdClaim, { claims: 1, children: 1 });

  await createBinding({
    commandId: fixture.renameRaceCommand,
    bindingId: fixture.renameRacePlatformBinding,
    tenantId: fixture.renameRaceTenant,
    key: "platform_rename_old",
    keyDigest: digest("rename-platform-key"),
    requestDigest: digest("rename-platform-request"),
  });
  await createNativeBinding(
    admin,
    fixture.renameRaceTenant,
    fixture.renameRaceNativeBinding,
    fixture.renameRaceNativeProvider,
    "native_rename_old",
  );

  const renameResults = await Promise.allSettled([
    updateBinding({
      client: raceA,
      bindingId: fixture.renameRacePlatformBinding,
      expectedVersion: 1,
      expectedTenantVersion: 1,
      key: "cross_family_rename",
    }),
    updateNativeBinding(
      raceB,
      fixture.renameRaceTenant,
      fixture.renameRaceNativeBinding,
      "cross_family_rename",
    ),
  ]);
  assert.equal(
    renameResults.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const renameFailure = renameResults.find(
    (result) => result.status === "rejected",
  );
  assert(renameFailure && renameFailure.status === "rejected");
  assertSqlState(renameFailure.reason, "23505");
  const [renamed] = await admin<
    { claims: number; children: number; mappingRevision: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_auth_provider_login_keys
       WHERE tenant_id = ${fixture.renameRaceTenant}::uuid
         AND key = 'cross_family_rename') AS claims,
      ((SELECT count(*) FROM public.tenant_auth_provider_bindings
        WHERE tenant_id = ${fixture.renameRaceTenant}::uuid
          AND key = 'cross_family_rename') +
       (SELECT count(*) FROM public.tenant_platform_auth_provider_bindings
        WHERE tenant_id = ${fixture.renameRaceTenant}::uuid
          AND key = 'cross_family_rename'))::integer AS children,
      (SELECT mapping_revision::integer
       FROM public.tenant_auth_provider_bindings
       WHERE tenant_id = ${fixture.renameRaceTenant}::uuid
         AND id = ${fixture.renameRaceNativeBinding}::uuid) AS "mappingRevision"
  `;
  assert.deepEqual(renamed, { claims: 1, children: 1, mappingRevision: 1 });
}

async function verifyEpochLedgerAndAudit(): Promise<void> {
  const [epochCount] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_platform_identity_provider_access_epochs
  `;
  assert.equal(epochCount?.count, 0);
  await assert.rejects(
    admin`
      INSERT INTO public.tenant_platform_identity_provider_access_epochs (
        id, tenant_id, binding_id, platform_provider_id, source_id, sequence,
        started_by_user_id
      ) VALUES (
        ${uuid(300)}::uuid, ${fixture.mainTenant}::uuid,
        ${fixture.mainBinding}::uuid, ${fixture.provider}::uuid,
        ${uuid(301)}::uuid, 1, ${fixture.operator}::uuid
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );

  await assert.rejects(
    admin`
      INSERT INTO public.tenant_platform_identity_binding_commands (
        id, tenant_id, actor_user_id, operation, key_digest, request_digest,
        result_binding_id, result_version
      ) VALUES (
        ${uuid(302)}::uuid, ${fixture.mainTenant}::uuid,
        ${fixture.operator}::uuid, 'binding.create',
        ${digest("invalid-receipt-key")}::bytea,
        ${digest("invalid-receipt-request")}::bytea,
        ${fixture.mainBinding}::uuid, 2
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );

  const createdAt = new Date(Date.now() - 7_200_000);
  const expiresAt = new Date(Date.now() - 3_600_000);
  await Promise.all(
    Array.from(
      { length: 70 },
      (_, index) => admin`
        INSERT INTO public.tenant_platform_identity_binding_commands (
          id, tenant_id, actor_user_id, operation, key_digest, request_digest,
          result_binding_id, result_version, created_at, expires_at
        ) VALUES (
          ${uuid(400 + index)}::uuid, ${fixture.mainTenant}::uuid,
          ${fixture.operator}::uuid, 'binding.create',
          ${digest(`expired-key-${index}`)}::bytea,
          ${digest(`expired-request-${index}`)}::bytea,
          ${fixture.mainBinding}::uuid, 1, ${createdAt}, ${expiresAt}
        )
      `,
    ),
  );
  await createBinding({
    commandId: fixture.mainCommand,
    bindingId: fixture.mainBinding,
    tenantId: fixture.mainTenant,
    key: "main_platform_login",
    priority: 120,
    keyDigest: digest("main-key"),
    requestDigest: digest("main-request"),
  });
  const [expired] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_platform_identity_binding_commands
    WHERE expires_at <= transaction_timestamp()
  `;
  assert.equal(
    expired?.count,
    6,
    "bounded cleanup must remove exactly 64 rows",
  );

  const auditPairs = await admin<
    {
      tenantId: string;
      tenantActorType: string;
      tenantActorUserId: string | null;
      platformId: string;
      platformActorType: string;
      platformActorUserId: string;
      reverseTenantId: string;
    }[]
  >`
    SELECT tenant_event.id AS "tenantId",
           tenant_event.actor_type::text AS "tenantActorType",
           tenant_event.actor_user_id AS "tenantActorUserId",
           platform_event.id AS "platformId",
           platform_event.actor_type::text AS "platformActorType",
           platform_event.actor_user_id AS "platformActorUserId",
           platform_event.metadata ->> 'tenant_audit_event_id' AS "reverseTenantId"
    FROM public.audit_events AS tenant_event
    JOIN public.platform_audit_events AS platform_event
      ON platform_event.id::text = tenant_event.metadata ->> 'platform_audit_event_id'
    WHERE tenant_event.action LIKE 'tenant.platform_identity_binding.%'
  `;
  assert(auditPairs.length >= 3);
  for (const pair of auditPairs) {
    assert.equal(pair.tenantActorType, "system");
    assert.equal(pair.tenantActorUserId, null);
    assert.equal(pair.platformActorType, "user");
    assert.equal(pair.platformActorUserId, fixture.operator);
    assert.equal(pair.reverseTenantId, pair.tenantId);
    assert.notEqual(pair.platformId, pair.tenantId);
  }

  const [tenantAudit] = await admin<{ id: string }[]>`
    SELECT id FROM public.audit_events
    WHERE action LIKE 'tenant.platform_identity_binding.%'
    ORDER BY occurred_at LIMIT 1
  `;
  const [platformAudit] = await admin<{ id: string }[]>`
    SELECT id FROM public.platform_audit_events
    WHERE action LIKE 'platform.identity_binding.%'
    ORDER BY occurred_at LIMIT 1
  `;
  assert(tenantAudit && platformAudit);
  await assert.rejects(
    admin`
      UPDATE public.audit_events SET reason = 'tampered'
      WHERE id = ${tenantAudit.id}::uuid
    `,
    (error: unknown) => assertSqlState(error, "55000"),
  );
  await assert.rejects(
    admin`
      DELETE FROM public.platform_audit_events
      WHERE id = ${platformAudit.id}::uuid
    `,
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const [finalState] = await admin<
    {
      epochs: number;
      ready: boolean;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_platform_identity_provider_access_epochs) AS epochs,
      app.release_runtime_schema_readiness_v62() AS ready
  `;
  assert.deepEqual(finalState, {
    epochs: 0,
    ready: true,
  });
}

try {
  await seedFixture();
  await verifyCompatibilityAndAcl();
  await verifyInvalidCreateEnvelopes();
  await verifyCreateLifecycleReservationSerialization();
  await verifyMainLifecycle();
  await verifyCrossFamilyConcurrency();
  await verifyEpochLedgerAndAudit();
  process.stdout.write(
    "platform identity-binding runtime security proof passed (v40, ACL/RLS, non-oracle, envelope validation, CAS/idempotency, reservation/lifecycle and cross-family concurrency, audit, epoch and bounded ledger invariants)\n",
  );
} finally {
  await Promise.all([admin.end(), raceA.end(), raceB.end()]);
}
