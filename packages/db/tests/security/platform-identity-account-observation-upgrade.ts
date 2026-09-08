import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
  expectedPlatformIdentityRuntimeReadinessV4SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash,
  expectedSchemaCompatibilityV38SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import { migrateSchema } from "../../src/admin/schema-migration.js";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker";
type Projection = Readonly<Record<string, unknown>>;
type JournalEntry = {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
};
type Journal = {
  version: string;
  dialect: string;
  entries: JournalEntry[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return (
    isRecord(value) &&
    Number.isSafeInteger(value.idx) &&
    typeof value.version === "string" &&
    Number.isSafeInteger(value.when) &&
    typeof value.tag === "string" &&
    typeof value.breakpoints === "boolean"
  );
}

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    typeof value.dialect !== "string" ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isJournalEntry)
  ) {
    throw new Error("Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

function assertSqlState(error: unknown, code: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, code, error.message);
  return true;
}

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_IDENTITY_ACCOUNT_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_IDENTITY_ACCOUNT_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d6e90-7000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  operator: uuid(1),
  legacyUser: uuid(2),
  knownUser: uuid(3),
  operatorGrant: uuid(4),
  operatorSession: uuid(5),
  operatorFamily: uuid(6),
  provider: uuid(10),
  providerCommand: uuid(11),
  providerAudit: uuid(12),
  legacyAccount: uuid(20),
  legacyCommand: uuid(21),
  legacyAudit: uuid(22),
  knownAccount: uuid(30),
  knownCommand: uuid(31),
  knownAudit: uuid(32),
} as const;

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const v36Index = 169;
const v37Index = 173;
const v36Entries = journal.entries.slice(0, v36Index + 1);
const v37Entries = journal.entries.slice(0, v37Index + 1);
assert.equal(v36Entries.length, 170);
assert.equal(
  v36Entries.at(-1)?.tag,
  "0169_platform_identity_account_compatibility",
);
assert.equal(v37Entries.length, 174);
assert.equal(
  v37Entries.at(-1)?.tag,
  "0173_platform_identity_account_representation_compatibility",
);
assert.equal(expectedMigrationCount, expectedMigrations.length);
assert.equal(
  expectedMigrations
    .map((entry) => `${entry.createdAt}@${entry.hash}`)
    .join(":"),
  expectedMigrationFingerprint,
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-platform-account-observation-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const activeKeyVersion = 32_767;
const issuer = "https://platform-account-upgrade-idp.example.invalid";
const directRedirectUri =
  "https://periapsis.example.invalid/auth/platform/oidc/callback";
const tenantRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback";
let sequence = 1_000;

function nextUuid(): string {
  sequence += 1;
  return uuid(sequence);
}

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-identity-account-observation-upgrade:${label}`)
    .digest();
}

async function writeStage(entries: JournalEntry[]): Promise<void> {
  await mkdir(resolve(stageRoot, "meta"), { recursive: true });
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );
}

async function asRole<T>(
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const wrapped = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', '', true),
             set_config('app.user_id', ${fixture.operator}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

async function createProvider(): Promise<void> {
  const configuration = {
    issuer,
    clientId: "periapsis-platform-account-upgrade",
    redirectUri: directRedirectUri,
    postLogoutRedirectUri: "https://periapsis.example.invalid/login",
    extraScopes: ["groups"],
    allowRefreshToken: false,
    useUserInfo: true,
  } as const;
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ providerId: string; version: number }[]>`
      SELECT result.provider_id AS "providerId",
             result.version::integer AS version
      FROM app.create_platform_oidc_auth_provider_v2(
        ${fixture.operatorSession}::uuid, ${fixture.providerCommand}::uuid,
        ${fixture.provider}::uuid, 'account_observation_upgrade'::text,
        'Account observation upgrade'::text,
        'Rolling-upgrade observation provenance fixture'::text,
        ${JSON.stringify(configuration)}::jsonb,
        ${tenantRedirectUri}::text,
        ${digest("provider-key")}::bytea,
        ${digest("provider-request")}::bytea,
        ${fixture.providerAudit}::uuid, ${nextUuid()}::uuid,
        ${nextUuid()}::uuid, '198.51.100.91'::inet,
        'Periapsis platform account observation upgrade proof'::text,
        'totp'::text, 'Create observation upgrade provider'::text
      ) AS result
    `,
  );
  assert.deepEqual(created, { providerId: fixture.provider, version: 1 });
}

async function prelinkV1(input: {
  accountId: string;
  auditId: string;
  commandId: string;
  label: string;
  userId: string;
}): Promise<Projection> {
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      {
        accountId: string;
        version: number;
        replayed: boolean;
        document: Projection;
      }[]
    >`
      SELECT result.account_id AS "accountId",
             result.version::integer AS version,
             result.replayed,
             result.document
      FROM app.prelink_platform_identity_account_v1(
        ${fixture.operatorSession}::uuid, ${input.commandId}::uuid,
        ${input.accountId}::uuid, ${fixture.provider}::uuid,
        ${input.userId}::uuid, ${issuer}::text,
        'utf8_exact'::public.identity_subject_format,
        ${Buffer.alloc(32, 0x63)}::bytea, ${Buffer.alloc(12, 0x6e)}::bytea,
        ${activeKeyVersion}::integer, ARRAY[${activeKeyVersion}]::integer[],
        ARRAY[${digest(`${input.label}-subject`)}::bytea]::bytea[],
        ${digest(`${input.label}-key`)}::bytea,
        ${digest(`${input.label}-request`)}::bytea,
        ${input.auditId}::uuid, ${nextUuid()}::uuid, ${nextUuid()}::uuid,
        '198.51.100.91'::inet,
        'Periapsis platform account observation upgrade proof'::text,
        'totp'::text, 'Prelink observation upgrade account'::text
      ) AS result
    `,
  );
  assert(created, "platform identity-account prelink returned no row");
  assert.equal(created.accountId, input.accountId);
  assert.equal(created.version, 1);
  assert.equal(created.replayed, false);
  return created.document;
}

async function getV2(accountId: string): Promise<Projection> {
  const [result] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ document: Projection }[]>`
      SELECT app.get_platform_identity_account_v2(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${accountId}::uuid, 'totp'::text
      ) AS document
    `,
  );
  assert(result, "platform identity-account projection returned no row");
  return result.document;
}

async function publicReadiness(role: RuntimeRole): Promise<boolean> {
  const [result] = await asRole(
    role,
    (transaction) => transaction<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v62() AS ready
    `,
  );
  assert(result, `${role} readiness returned no row`);
  return result.ready;
}

async function assertRuntimeCatalog(): Promise<void> {
  const signatures = [
    "app.schema_compatibility_v38()",
    "app.private_platform_identity_dependency_surface_hash_v4()",
    "app.private_platform_identity_runtime_schema_readiness_v4()",
    "app.platform_identity_runtime_schema_readiness_v4()",
  ] as const;
  const expectedHashes = [
    expectedSchemaCompatibilityV38SourceHash,
    expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
    expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash,
    expectedPlatformIdentityRuntimeReadinessV4SourceHash,
  ];
  const catalog = await sql<
    { signature: string; owner: string; sourceHash: string }[]
  >`
    SELECT expected.signature,
           owner.rolname AS owner,
           encode(sha256(convert_to(function.prosrc, 'UTF8')), 'hex')
             AS "sourceHash"
    FROM unnest(${signatures}::text[]) WITH ORDINALITY
      AS expected(signature, ordinal)
    JOIN pg_catalog.pg_proc AS function
      ON function.oid = to_regprocedure(expected.signature)
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
    ORDER BY expected.ordinal
  `;
  assert.deepEqual(
    Array.from(catalog),
    signatures.map((signature, index) => ({
      signature,
      owner: "periapsis_migrator",
      sourceHash: expectedHashes[index],
    })),
  );
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(server?.version.startsWith("18.6"));

  await writeStage(v36Entries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [v36Journal] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count,
           max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(v36Journal, {
    count: 170,
    latest: String(expectedMigrations[v36Index]?.createdAt),
  });

  const now = new Date(Date.now() - 60_000).toISOString();
  const expires = new Date(Date.now() + 60 * 60_000).toISOString();
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.operator}::uuid,
         'account-observation-upgrade.operator@example.invalid',
         'Account observation upgrade operator'),
        (${fixture.legacyUser}::uuid,
         'account-observation-upgrade.legacy@example.invalid',
         'Legacy unknown account'),
        (${fixture.knownUser}::uuid,
         'account-observation-upgrade.known@example.invalid',
         'Known observation account')
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
      ) VALUES (
        ${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
        ${fixture.operatorFamily}::uuid, NULL,
        ${digest("operator-token")}::bytea,
        ${digest("operator-csrf")}::bytea, 'totp', ${now}, ${now},
        ${expires}, ${expires}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES (
        ${activeKeyVersion}, ${digest("active-key")}::bytea, true
      )
    `;
  });
  await createProvider();

  const legacyPrelink = await prelinkV1({
    accountId: fixture.legacyAccount,
    auditId: fixture.legacyAudit,
    commandId: fixture.legacyCommand,
    label: "legacy",
    userId: fixture.legacyUser,
  });
  assert.equal(legacyPrelink.state, "active");
  assert.equal(typeof legacyPrelink.lastObservedAt, "string");
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
  const [legacyRetired] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      { accountId: string; version: number; document: Projection }[]
    >`
      SELECT result.account_id AS "accountId",
             result.version::integer AS version,
             result.document
      FROM app.retire_platform_identity_account_v1(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.legacyAccount}::uuid, 1::bigint, ${nextUuid()}::uuid,
        ${nextUuid()}::uuid, ${nextUuid()}::uuid, '198.51.100.91'::inet,
        'Periapsis platform account observation upgrade proof'::text,
        'totp'::text, 'Retire legacy observation account'::text
      ) AS result
    `,
  );
  assert.deepEqual(
    { accountId: legacyRetired?.accountId, version: legacyRetired?.version },
    { accountId: fixture.legacyAccount, version: 2 },
  );
  const [legacyV36Physical] = await sql<
    { lastObservedAt: string; retiredAt: string; version: number }[]
  >`
    SELECT last_observed_at::text AS "lastObservedAt",
           retired_at::text AS "retiredAt", version::integer AS version
    FROM ONLY public.platform_federated_external_identities
    WHERE id = ${fixture.legacyAccount}::uuid
  `;
  assert(legacyV36Physical, "legacy v36 account was not persisted");
  assert.equal(legacyV36Physical.version, 2);
  assert.equal(legacyV36Physical.lastObservedAt, legacyV36Physical.retiredAt);
  assert.notEqual(
    legacyV36Physical.lastObservedAt,
    legacyPrelink.lastObservedAt,
    "v36 retirement must demonstrate the overwritten observation",
  );

  await writeStage(v37Entries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [legacyV37Physical] = await sql<
    { resourceVersion: number; securityRevision: number }[]
  >`
    SELECT resource_version::integer AS "resourceVersion",
           version::integer AS "securityRevision"
    FROM ONLY public.platform_federated_external_identities
    WHERE id = ${fixture.legacyAccount}::uuid
  `;
  assert.deepEqual(legacyV37Physical, {
    resourceVersion: 1,
    securityRevision: 2,
  });

  await prelinkV1({
    accountId: fixture.knownAccount,
    auditId: fixture.knownAudit,
    commandId: fixture.knownCommand,
    label: "known",
    userId: fixture.knownUser,
  });
  const knownRetirement = await sql.begin(async (transaction) => {
    const [observed] = await transaction<
      { resourceVersion: number; observedAt: string }[]
    >`
      UPDATE ONLY public.platform_federated_external_identities AS identity
      SET last_observed_at = transaction_timestamp(),
          updated_at = transaction_timestamp()
      WHERE identity.id = ${fixture.knownAccount}::uuid
      RETURNING identity.resource_version::integer AS "resourceVersion",
                identity.last_observed_at::text AS "observedAt"
    `;
    assert.deepEqual(observed?.resourceVersion, 2);

    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', '', true),
             set_config('app.user_id', ${fixture.operator}, true),
             set_config('app.service_account_id', '', true)
    `;
    const [retired] = await transaction<
      { version: number; document: Projection }[]
    >`
      SELECT result.version::integer AS version, result.document
      FROM app.retire_platform_identity_account_v2(
        ${fixture.operatorSession}::uuid, ${fixture.provider}::uuid,
        ${fixture.knownAccount}::uuid, 2::bigint, 1::bigint,
        ${nextUuid()}::uuid, ${nextUuid()}::uuid, ${nextUuid()}::uuid,
        '198.51.100.91'::inet,
        'Periapsis platform account observation upgrade proof'::text,
        'totp'::text, 'Retire known coincident observation account'::text
      ) AS result
    `;
    assert(retired, "v37 retirement returned no row");
    return { observedAt: observed?.observedAt, ...retired };
  });
  assert.equal(knownRetirement.version, 3);
  const [knownV37Physical] = await sql<
    { lastObservedAt: string; retiredAt: string; resourceVersion: number }[]
  >`
    SELECT last_observed_at::text AS "lastObservedAt",
           retired_at::text AS "retiredAt",
           resource_version::integer AS "resourceVersion"
    FROM ONLY public.platform_federated_external_identities
    WHERE id = ${fixture.knownAccount}::uuid
  `;
  assert.deepEqual(knownV37Physical, {
    lastObservedAt: knownRetirement.observedAt,
    retiredAt: knownRetirement.observedAt,
    resourceVersion: 3,
  });

  await migrateSchema(sql, migrationsRoot);
  assert.equal(await publicReadiness("periapsis_api"), true);
  assert.equal(await publicReadiness("periapsis_worker"), true);
  await assertRuntimeCatalog();

  const legacyDocument = await getV2(fixture.legacyAccount);
  assert.equal(legacyDocument.state, "retired");
  assert.equal(legacyDocument.version, 1);
  assert.equal(legacyDocument.lastObservationState, "legacy_unknown");
  assert.equal(legacyDocument.lastObservedAt, null);
  assert.equal(typeof legacyDocument.retiredAt, "string");

  const knownDocument = await getV2(fixture.knownAccount);
  assert.equal(knownDocument.state, "retired");
  assert.equal(knownDocument.version, 3);
  assert.equal(knownDocument.lastObservationState, "known");
  assert.equal(knownDocument.lastObservedAt, knownDocument.retiredAt);
  assert.equal(
    Date.parse(String(knownDocument.lastObservedAt)),
    Date.parse(knownRetirement.observedAt),
  );

  const [classification] = await sql<
    {
      legacyState: string;
      legacyResourceVersion: number;
      knownState: string;
      knownResourceVersion: number;
    }[]
  >`
    SELECT legacy.last_observation_state AS "legacyState",
           legacy.resource_version::integer AS "legacyResourceVersion",
           known.last_observation_state AS "knownState",
           known.resource_version::integer AS "knownResourceVersion"
    FROM ONLY public.platform_federated_external_identities AS legacy
    CROSS JOIN ONLY public.platform_federated_external_identities AS known
    WHERE legacy.id = ${fixture.legacyAccount}::uuid
      AND known.id = ${fixture.knownAccount}::uuid
  `;
  assert.deepEqual(classification, {
    legacyState: "legacy_unknown",
    legacyResourceVersion: 1,
    knownState: "known",
    knownResourceVersion: 3,
  });
  await assert.rejects(
    sql`
      UPDATE ONLY public.platform_federated_external_identities AS identity
      SET last_observation_state = 'known',
          updated_at = transaction_timestamp()
      WHERE identity.id = ${fixture.legacyAccount}::uuid
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );
  assert.deepEqual(await getV2(fixture.legacyAccount), legacyDocument);

  const currentFunctions = [
    "app.list_platform_identity_accounts_v2(uuid,text,uuid,uuid,integer,boolean)",
    "app.get_platform_identity_account_v2(uuid,uuid,uuid,text)",
    "app.prelink_platform_identity_account_v2(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.schema_compatibility_v62()",
    "app.release_runtime_schema_readiness_v62()",
  ] as const;
  const retiredFunctions = [
    "app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)",
    "app.get_platform_identity_account_v1(uuid,uuid,uuid,text)",
    "app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
    "app.schema_compatibility_v38()",
    "app.platform_identity_runtime_schema_readiness_v4()",
    "app.schema_compatibility_v37()",
    "app.platform_identity_runtime_schema_readiness_v3()",
  ] as const;
  const [acl] = await sql<
    { currentApi: boolean; retiredApi: boolean; retiredWorker: boolean }[]
  >`
    SELECT bool_and(has_function_privilege(
             'periapsis_api', current.signature, 'EXECUTE'
           )) AS "currentApi",
           NOT bool_or(has_function_privilege(
             'periapsis_api', retired.signature, 'EXECUTE'
           )) AS "retiredApi",
           NOT bool_or(has_function_privilege(
             'periapsis_worker', retired.signature, 'EXECUTE'
           )) AS "retiredWorker"
    FROM unnest(${currentFunctions}::text[]) AS current(signature)
    CROSS JOIN unnest(${retiredFunctions}::text[]) AS retired(signature)
  `;
  assert.deepEqual(acl, {
    currentApi: true,
    retiredApi: true,
    retiredWorker: true,
  });

  const [compatibility] = await sql<
    {
      count: number;
      latestCreatedAt: string;
      latestHash: string;
      fingerprint: string;
    }[]
  >`
    SELECT applied_count::integer AS count,
           latest_created_at::text AS "latestCreatedAt",
           latest_hash AS "latestHash",
           migration_fingerprint AS fingerprint
    FROM app.schema_compatibility_v62()
  `;
  assert.deepEqual(compatibility, {
    count: expectedMigrationCount,
    latestCreatedAt: String(expectedMigrationCreatedAt),
    latestHash: expectedMigrationHash,
    fingerprint: expectedMigrationFingerprint,
  });

  const alteredLatestHash = `${expectedMigrationHash[0] === "0" ? "1" : "0"}${expectedMigrationHash.slice(1)}`;
  await assert.rejects(
    sql`
      SELECT app.seal_schema_compatibility_manifest(
        ${expectedMigrationCount}::bigint,
        ${expectedMigrationCreatedAt}::bigint,
        ${alteredLatestHash}::text,
        ${expectedMigrationFingerprint}::text
      )
    `,
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const rollbackMarker = { kind: "readiness rollback" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        DELETE FROM drizzle.__drizzle_migrations
        WHERE created_at = ${expectedMigrationCreatedAt}
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [downgraded] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62() AS ready
      `;
      assert.equal(downgraded?.ready, false);
      throw rollbackMarker;
    }),
    (error: unknown) => error === rollbackMarker,
  );
  assert.equal(await publicReadiness("periapsis_api"), true);

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(
        "ALTER FUNCTION app.private_platform_identity_account_document_v2(uuid, uuid) VOLATILE",
      );
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v62() AS ready
      `;
      assert.equal(tampered?.ready, false);
      throw rollbackMarker;
    }),
    (error: unknown) => error === rollbackMarker,
  );
  assert.equal(await publicReadiness("periapsis_api"), true);

  const beforeIdempotence = {
    legacy: await getV2(fixture.legacyAccount),
    known: await getV2(fixture.knownAccount),
  };
  await migrateSchema(sql, migrationsRoot);
  const [journalState] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM drizzle.__drizzle_migrations
  `;
  assert.equal(journalState?.count, expectedMigrationCount);
  assert.deepEqual(
    await getV2(fixture.legacyAccount),
    beforeIdempotence.legacy,
  );
  assert.deepEqual(await getV2(fixture.knownAccount), beforeIdempotence.known);
  assert.equal(await publicReadiness("periapsis_api"), true);

  process.stdout.write(
    "platform identity-account observation rolling-upgrade proof passed\n",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
