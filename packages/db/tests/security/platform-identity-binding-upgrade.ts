import assert from "node:assert/strict";
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
  expectedPlatformIdentityProviderReadinessSourceHash,
  expectedPlatformTenantLifecycleReadinessSourceHash,
  expectedSchemaCompatibilityV33SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

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

type FrozenHealthRole = "periapsis_api" | "periapsis_worker";

type FrozenHealthRow = {
  ready: boolean;
};

type CompatibilityCatalogRow = {
  v32Source: string;
  v32Config: string[];
  v33Source: string;
  v33Config: string[];
  providerSource: string;
  providerConfig: string[];
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

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_IDENTITY_BINDING_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_IDENTITY_BINDING_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d4b91-7000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  liveProvider: uuid(4),
  archivedProvider: uuid(5),
  liveBinding: uuid(6),
  archivedBinding: uuid(7),
} as const;

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 158;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
const targetIndex = 162;
const targetEntries = journal.entries.slice(0, targetIndex + 1);
const target = expectedMigrations[targetIndex];
assert.equal(predecessorEntries.length, 159);
assert.equal(predecessor?.tag, "0158_platform_identity_provider_compatibility");
assert.equal(predecessor.createdAt, 1_787_929_625_096);
assert.equal(targetEntries.length, 163);
assert.equal(
  target?.tag,
  "0162_tenant_platform_identity_binding_compatibility",
);
const prefixFingerprint = expectedMigrations
  .slice(0, predecessorIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
const computedCurrentFingerprint = expectedMigrations
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
assert.equal(computedCurrentFingerprint, expectedMigrationFingerprint);
assert.equal(expectedMigrationCount, 232);
assert.equal(expectedMigrationCreatedAt, 1788650095675);
assert.equal(expectedMigrationCount, expectedMigrations.length);
assert.equal(expectedMigrationHash, expectedMigrations.at(-1)?.hash);
const targetFingerprint = expectedMigrations
  .slice(0, targetIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");

const frozenWorkerVerifier = Buffer.alloc(32, 0x9b);
const frozen0158HealthQuery = `
with expected_trusted_function(
  function_key, signature, expected_language, expected_config,
  expected_result, expected_acl_roles, expected_source_hash
) as (
  values
    ('predecessor', 'app.schema_compatibility_v33()',
     'plpgsql', array['search_path=pg_catalog']::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     array['periapsis_api', 'periapsis_migrator', 'periapsis_worker']::text[],
     $4::text),
    ('tenant', 'app.platform_tenant_lifecycle_schema_readiness_v1()',
     'plpgsql', array['search_path=pg_catalog, app']::text[], 'boolean',
     array['periapsis_api', 'periapsis_migrator', 'periapsis_worker']::text[],
     $5::text),
    ('provider', 'app.platform_identity_provider_schema_readiness_v1()',
     'plpgsql', array['search_path=pg_catalog, app']::text[], 'boolean',
     array['periapsis_api', 'periapsis_migrator', 'periapsis_worker']::text[],
     $6::text)
),
actual_trusted_function as (
  select expected.function_key,
         encode(pg_catalog.sha256(pg_catalog.convert_to(function.prosrc, 'UTF8')),
                'hex') as source_hash,
         function.oid is not null
           and owner.rolname = 'periapsis_migrator'
           and language.lanname = expected.expected_language
           and function.prokind = 'f'
           and function.provolatile = 's'
           and function.prosecdef
           and not function.proisstrict
           and not function.proleakproof
           and function.proparallel = 'u'
           and function.pronargs = 0
           and function.proconfig is not distinct from expected.expected_config
           and pg_catalog.pg_get_function_result(function.oid) =
               expected.expected_result
           and encode(pg_catalog.sha256(
                 pg_catalog.convert_to(function.prosrc, 'UTF8')
               ), 'hex') = expected.expected_source_hash
           and case when function.oid is null then false else (
             select count(*) = cardinality(expected.expected_acl_roles)
                and array_agg(
                  coalesce(grantee.rolname::text, 'PUBLIC')
                  order by coalesce(grantee.rolname::text, 'PUBLIC')
                ) is not distinct from expected.expected_acl_roles
                and coalesce(bool_and(
                  function_acl.grantor = function.proowner
                  and function_acl.privilege_type = 'EXECUTE'
                  and not function_acl.is_grantable
                ), false)
             from pg_catalog.aclexplode(coalesce(
               function.proacl,
               pg_catalog.acldefault('f', function.proowner)
             )) as function_acl
             left join pg_catalog.pg_roles as grantee
               on grantee.oid = function_acl.grantee
           ) end as catalog_ready
  from expected_trusted_function as expected
  left join pg_catalog.pg_proc as function
    on function.oid = pg_catalog.to_regprocedure(expected.signature)
  left join pg_catalog.pg_roles as owner on owner.oid = function.proowner
  left join pg_catalog.pg_language as language
    on language.oid = function.prolang
),
trusted_function_state as (
  select count(*) = 3 and coalesce(bool_and(catalog_ready), false)
           as catalog_ready
  from actual_trusted_function
)
select coalesce(
  compatibility.applied_count = 159
  and compatibility.latest_created_at = $2::bigint
  and compatibility.latest_hash = $3::text
  and compatibility.migration_fingerprint = $1::text
  and app.platform_tenant_lifecycle_schema_readiness_v1()
  and app.platform_identity_provider_schema_readiness_v1()
  and case when $7::boolean then app.verify_identity_keyring_v3(
        array[1]::integer[], array[$8::bytea]::bytea[], 1
      ) else true end
  and trusted.catalog_ready,
  false
) as ready
from app.schema_compatibility_v33() as compatibility
cross join trusted_function_state as trusted
`;

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-platform-binding-rolling-0158-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

async function readFrozen0158Health(
  transaction: postgres.TransactionSql,
  role: FrozenHealthRole,
): Promise<boolean> {
  const roleIdentifier =
    role === "periapsis_api" ? '"periapsis_api"' : '"periapsis_worker"';
  await transaction.unsafe(`SET LOCAL ROLE ${roleIdentifier}`);
  const [row] = await transaction.unsafe<FrozenHealthRow[]>(
    frozen0158HealthQuery,
    [
      prefixFingerprint,
      String(predecessor.createdAt),
      predecessor.hash,
      expectedSchemaCompatibilityV33SourceHash,
      expectedPlatformTenantLifecycleReadinessSourceHash,
      expectedPlatformIdentityProviderReadinessSourceHash,
      role === "periapsis_worker",
      frozenWorkerVerifier,
    ],
  );
  assert(row, `frozen 0158 ${role} health returned no row`);
  return row.ready;
}

async function frozen0158ReadyAs(role: FrozenHealthRole): Promise<boolean> {
  return sql.begin((transaction) => readFrozen0158Health(transaction, role));
}

async function readCompatibilityCatalog(): Promise<CompatibilityCatalogRow> {
  const [row] = await sql<CompatibilityCatalogRow[]>`
    SELECT v32.prosrc AS "v32Source", v32.proconfig AS "v32Config",
           v33.prosrc AS "v33Source", v33.proconfig AS "v33Config",
           provider.prosrc AS "providerSource",
           provider.proconfig AS "providerConfig"
    FROM pg_catalog.pg_proc AS v32
    CROSS JOIN pg_catalog.pg_proc AS v33
    CROSS JOIN pg_catalog.pg_proc AS provider
    WHERE v32.oid = 'app.schema_compatibility_v32()'::regprocedure
      AND v33.oid = 'app.schema_compatibility_v33()'::regprocedure
      AND provider.oid =
        'app.platform_identity_provider_schema_readiness_v1()'::regprocedure
  `;
  assert(row, "compatibility catalog snapshot returned no row");
  return row;
}

async function assertJournalSuffixRemovalFailsFrozenHealth(
  role: FrozenHealthRole,
): Promise<void> {
  const rollbackMarker = { role };
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        DELETE FROM drizzle.__drizzle_migrations AS migration
        WHERE migration.id IN (
          SELECT suffix.id
          FROM drizzle.__drizzle_migrations AS suffix
          ORDER BY suffix.created_at, suffix.id
          OFFSET 159
        )
      `;
      const [journalState] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM drizzle.__drizzle_migrations
      `;
      assert.equal(journalState?.count, 159);
      assert.equal(await readFrozen0158Health(transaction, role), false);
      throw rollbackMarker;
    }),
    (error: unknown) => error === rollbackMarker,
  );
  assert.equal(await frozen0158ReadyAs(role), true);
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(server?.version.startsWith("18.6"));

  await mkdir(resolve(stageRoot, "meta"));
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: predecessorEntries }, null, 2)}\n`,
  );
  await Promise.all(
    predecessorEntries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );

  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [prefix] = await sql<
    {
      count: number;
      latestCreatedAt: string;
      latestHash: string;
      namespacePresent: boolean;
    }[]
  >`
    SELECT count(*)::integer AS count,
           max(migration.created_at)::text AS "latestCreatedAt",
           (array_agg(lower(migration.hash::text)
              ORDER BY migration.created_at DESC, migration.id DESC))[1]
             AS "latestHash",
           to_regclass('public.tenant_auth_provider_login_keys') IS NOT NULL
             AS "namespacePresent"
    FROM drizzle.__drizzle_migrations AS migration
  `;
  assert.deepEqual(prefix, {
    count: 159,
    latestCreatedAt: String(predecessor.createdAt),
    latestHash: predecessor.hash,
    namespacePresent: false,
  });

  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      159::bigint,
      ${predecessor.createdAt}::bigint,
      ${predecessor.hash}::text,
      ${prefixFingerprint}::text
    )
  `;
  const prefixCatalog = await readCompatibilityCatalog();
  assert.deepEqual(prefixCatalog.v32Config, [
    "search_path=pg_catalog",
    `app.schema_compatibility_fingerprint=${prefixFingerprint}`,
  ]);
  assert.deepEqual(prefixCatalog.v33Config, ["search_path=pg_catalog"]);
  assert.deepEqual(prefixCatalog.providerConfig, [
    "search_path=pg_catalog, app",
  ]);
  const [prefixCompatibility] = await sql<
    { currentCount: number; predecessorCount: number }[]
  >`
    SELECT v33.applied_count::integer AS "currentCount",
           v32.applied_count::integer AS "predecessorCount"
    FROM app.schema_compatibility_v33() AS v33
    CROSS JOIN app.schema_compatibility_v32() AS v32
  `;
  assert.deepEqual(prefixCompatibility, {
    currentCount: 159,
    predecessorCount: 155,
  });

  const now = new Date(Date.now() - 120_000).toISOString();
  const archivedAt = new Date(Date.now() - 60_000).toISOString();
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES (${fixture.user}::uuid, 'binding.upgrade@example.invalid',
              'Binding rolling-upgrade owner')
    `;
    await transaction`
      INSERT INTO public.tenants (id, slug, name, status, version)
      VALUES (${fixture.tenant}::uuid, 'binding-upgrade',
              'Binding rolling-upgrade tenant', 'active', 1)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status, created_at, updated_at
      ) VALUES (
        ${fixture.membership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.user}::uuid, 'tenant_admin', 'active',
        ${now}::timestamptz, ${now}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id,
        archived_at, archived_by_membership_id, archive_reason,
        created_at, updated_at
      ) VALUES
        (${fixture.liveProvider}::uuid, ${fixture.tenant}::uuid,
         'upgrade_live_provider', 'Upgrade live provider', '', 'ldap', false,
         ${fixture.membership}::uuid, ${fixture.membership}::uuid,
         NULL, NULL, NULL, ${now}::timestamptz, ${now}::timestamptz),
        (${fixture.archivedProvider}::uuid, ${fixture.tenant}::uuid,
         'upgrade_archived_provider', 'Upgrade archived provider', '', 'ldap', false,
         ${fixture.membership}::uuid, ${fixture.membership}::uuid,
         ${archivedAt}::timestamptz, ${fixture.membership}::uuid,
         'Archived before 9B', ${now}::timestamptz,
         ${archivedAt}::timestamptz)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_bindings (
        id, tenant_id, provider_id, key, enabled, profile_priority,
        auth_revision, mapping_revision, current_access_epoch_id,
        created_by_membership_id, updated_by_membership_id,
        archived_at, archived_by_membership_id, archive_reason,
        version, created_at, updated_at
      ) VALUES
        (${fixture.liveBinding}::uuid, ${fixture.tenant}::uuid,
         ${fixture.liveProvider}::uuid, 'upgrade_live_login', false, 100,
         1, 7, NULL, ${fixture.membership}::uuid,
         ${fixture.membership}::uuid, NULL, NULL, NULL, 1,
         ${now}::timestamptz, ${now}::timestamptz),
        (${fixture.archivedBinding}::uuid, ${fixture.tenant}::uuid,
         ${fixture.archivedProvider}::uuid, 'upgrade_archived_login', false, 200,
         2, 9, NULL, ${fixture.membership}::uuid,
         ${fixture.membership}::uuid, ${archivedAt}::timestamptz,
         ${fixture.membership}::uuid, 'Archived before 9B', 2,
         ${now}::timestamptz, ${archivedAt}::timestamptz)
    `;
  });

  assert.equal(await frozen0158ReadyAs("periapsis_api"), true);
  assert.equal(await frozen0158ReadyAs("periapsis_worker"), true);

  assert.deepEqual(
    expectedMigrations
      .slice(predecessorIndex + 1, targetIndex + 1)
      .map((entry) => entry.tag),
    [
      "0159_material_talkback",
      "0160_tenant_platform_identity_binding_security",
      "0161_lazy_shiver_man",
      "0162_tenant_platform_identity_binding_compatibility",
    ],
  );

  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: targetEntries }, null, 2)}\n`,
  );
  await Promise.all(
    targetEntries
      .slice(predecessorEntries.length)
      .map((entry) =>
        copyFile(
          resolve(migrationsRoot, `${entry.tag}.sql`),
          resolve(stageRoot, `${entry.tag}.sql`),
        ),
      ),
  );
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  assert.equal(await frozen0158ReadyAs("periapsis_api"), false);
  assert.equal(await frozen0158ReadyAs("periapsis_worker"), false);
  const [unsealed] = await sql<{ currentCount: number; config: string[] }[]>`
    SELECT compatibility.applied_count::integer AS "currentCount",
           function.proconfig AS config
    FROM app.schema_compatibility_v34() AS compatibility
    CROSS JOIN pg_catalog.pg_proc AS function
    WHERE function.oid = 'app.schema_compatibility_v34()'::regprocedure
  `;
  assert.deepEqual(unsealed, {
    currentCount: 0,
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=UNSEALED",
    ],
  });

  const tamperedEntries = expectedMigrations
    .slice(0, targetIndex + 1)
    .map((entry) => `${entry.createdAt}@${entry.hash}`);
  const internalIndex = predecessorIndex + 1;
  const internalEntry = expectedMigrations[internalIndex];
  assert(internalEntry, "current manifest has no 9B suffix entry");
  const alteredInternalHash = `${internalEntry.hash[0] === "0" ? "1" : "0"}${internalEntry.hash.slice(1)}`;
  tamperedEntries[internalIndex] =
    `${internalEntry.createdAt}@${alteredInternalHash}`;
  const tamperedFingerprint = tamperedEntries.join(":");
  assert.match(
    tamperedFingerprint,
    /^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$/,
  );
  assert.equal(tamperedEntries.length, targetEntries.length);
  assert.equal(tamperedEntries.at(-1), targetFingerprint.split(":").at(-1));
  await assert.rejects(
    sql`
      SELECT app.seal_schema_compatibility_manifest(
        ${targetEntries.length}::bigint,
        ${target.createdAt}::bigint,
        ${target.hash}::text,
        ${tamperedFingerprint}::text
      )
    `,
    (error: unknown) => isRecord(error) && error.code === "55000",
  );
  const [rolledBackSeal] = await sql<{ config: string[] }[]>`
    SELECT function.proconfig AS config
    FROM pg_catalog.pg_proc AS function
    WHERE function.oid = 'app.schema_compatibility_v34()'::regprocedure
  `;
  assert.deepEqual(rolledBackSeal?.config, [
    "search_path=pg_catalog",
    "app.schema_compatibility_fingerprint=UNSEALED",
  ]);
  assert.equal(await frozen0158ReadyAs("periapsis_api"), false);
  assert.equal(await frozen0158ReadyAs("periapsis_worker"), false);

  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${targetEntries.length}::bigint,
      ${target.createdAt}::bigint,
      ${target.hash}::text,
      ${targetFingerprint}::text
    )
  `;

  const [upgraded] = await sql<
    {
      count: number;
      currentLatest: string;
      currentHash: string;
      currentFingerprint: string;
      predecessorCount: number;
      retiredCount: number;
      bindingReady: boolean;
      bindingV2Ready: boolean;
      wrapperReady: boolean;
      runtimeSurface: string;
      currentConfig: string[];
      retiredOwnerOnlyAcl: boolean;
      claimCount: number;
      archivedClaimCount: number;
      exactClaimCount: number;
      validatedFkCount: number;
      mappingRevisions: number[];
      epochCount: number;
      receiptConstraint: string;
      tenantProjectionGuardCount: number;
      compositeMutationFunctionCount: number;
      archiveResult: string;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS count,
           current_projection.latest_created_at::text AS "currentLatest",
           current_projection.latest_hash AS "currentHash",
           current_projection.migration_fingerprint AS "currentFingerprint",
           predecessor_projection.applied_count::integer AS "predecessorCount",
           retired_projection.applied_count::integer AS "retiredCount",
           app.tenant_platform_identity_binding_schema_readiness_v1()
             AS "bindingReady",
           app.tenant_platform_identity_binding_schema_readiness_v2()
             AS "bindingV2Ready",
           app.platform_identity_provider_schema_readiness_v1()
             AS "wrapperReady",
           app.private_runtime_accessible_surface_hash_v1()
             AS "runtimeSurface",
           (SELECT function.proconfig
            FROM pg_catalog.pg_proc AS function
            WHERE function.oid =
              'app.schema_compatibility_v34()'::regprocedure)
             AS "currentConfig",
           (SELECT count(*) = 1 AND coalesce(bool_and(
                     function_acl.grantor = function.proowner
                     AND function_acl.grantee = function.proowner
                     AND function_acl.privilege_type = 'EXECUTE'
                     AND NOT function_acl.is_grantable
                   ), false)
            FROM pg_catalog.pg_proc AS function
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
              function.proacl,
              pg_catalog.acldefault('f', function.proowner)
            )) AS function_acl
            WHERE function.oid =
              'app.schema_compatibility_v32()'::regprocedure)
             AS "retiredOwnerOnlyAcl",
           (SELECT count(*)::integer
            FROM public.tenant_auth_provider_login_keys) AS "claimCount",
           (SELECT count(*)::integer
            FROM public.tenant_auth_provider_login_keys AS claim
            JOIN public.tenant_auth_provider_bindings AS binding
              ON binding.tenant_id = claim.tenant_id
             AND binding.id = claim.binding_id
             AND binding.archived_at IS NOT NULL) AS "archivedClaimCount",
           (SELECT count(*)::integer
            FROM public.tenant_auth_provider_login_keys AS claim
            JOIN public.tenant_auth_provider_bindings AS binding
              ON binding.tenant_id = claim.tenant_id
             AND binding.binding_family = claim.binding_family
             AND binding.id = claim.binding_id AND binding.key = claim.key)
             AS "exactClaimCount",
           (SELECT count(*)::integer FROM pg_catalog.pg_constraint
            WHERE conname IN (
              'tenant_auth_provider_bindings_login_claim_fk',
              'tenant_platform_auth_provider_bindings_login_claim_fk',
              'tenant_platform_auth_provider_bindings_current_epoch_fk'
            ) AND convalidated) AS "validatedFkCount",
           (SELECT array_agg(mapping_revision::integer ORDER BY id)
            FROM public.tenant_auth_provider_bindings) AS "mappingRevisions",
           (SELECT count(*)::integer
            FROM public.tenant_platform_identity_provider_access_epochs)
             AS "epochCount",
           (SELECT pg_get_constraintdef(oid)
            FROM pg_catalog.pg_constraint
            WHERE conname =
              'tenant_platform_identity_binding_commands_result_check')
             AS "receiptConstraint",
           (SELECT count(*)::integer
            FROM pg_catalog.pg_trigger AS trigger_row
            JOIN pg_catalog.pg_class AS relation
              ON relation.oid = trigger_row.tgrelid
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'tenants'
              AND trigger_row.tgname =
                'tenants_identity_projection_version_guard_v1'
              AND NOT trigger_row.tgisinternal
              AND trigger_row.tgenabled = 'O')
             AS "tenantProjectionGuardCount",
           (SELECT count(*)::integer
            FROM pg_catalog.pg_proc AS function
            WHERE function.oid IN (
              'app.update_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure,
              'app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
            )) AS "compositeMutationFunctionCount",
           pg_catalog.pg_get_function_result(
             'app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
           ) AS "archiveResult"
    FROM app.schema_compatibility_v34() AS current_projection
    CROSS JOIN app.schema_compatibility_v33() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v32() AS retired_projection
  `;
  assert.deepEqual(upgraded, {
    count: targetEntries.length,
    currentLatest: String(target.createdAt),
    currentHash: target.hash,
    currentFingerprint: targetFingerprint,
    predecessorCount: 159,
    retiredCount: 0,
    bindingReady: true,
    bindingV2Ready: true,
    wrapperReady: true,
    runtimeSurface:
      "1499f4b4a551afc3d0845735970dafb0c445fdb135867ef7b0a7df595950f710",
    currentConfig: [
      "search_path=pg_catalog",
      `app.schema_compatibility_fingerprint=${targetFingerprint}`,
    ],
    retiredOwnerOnlyAcl: true,
    claimCount: 2,
    archivedClaimCount: 1,
    exactClaimCount: 2,
    validatedFkCount: 3,
    mappingRevisions: [7, 9],
    epochCount: 0,
    receiptConstraint: "CHECK ((result_version = 1))",
    tenantProjectionGuardCount: 1,
    compositeMutationFunctionCount: 2,
    archiveResult: "TABLE(version bigint, tenant_version integer)",
  });

  const upgradedCatalog = await readCompatibilityCatalog();
  assert.equal(upgradedCatalog.v32Source, prefixCatalog.v32Source);
  assert.deepEqual(upgradedCatalog.v32Config, [
    "search_path=pg_catalog",
    "app.schema_compatibility_fingerprint=RETIRED",
  ]);
  assert.equal(upgradedCatalog.v33Source, prefixCatalog.v33Source);
  assert.deepEqual(upgradedCatalog.v33Config, prefixCatalog.v33Config);
  assert.equal(upgradedCatalog.providerSource, prefixCatalog.providerSource);
  assert.deepEqual(
    upgradedCatalog.providerConfig,
    prefixCatalog.providerConfig,
  );
  assert.equal(await frozen0158ReadyAs("periapsis_api"), true);
  assert.equal(await frozen0158ReadyAs("periapsis_worker"), true);

  await assertJournalSuffixRemovalFailsFrozenHealth("periapsis_api");
  await assertJournalSuffixRemovalFailsFrozenHealth("periapsis_worker");

  process.stdout.write(
    "platform identity-binding rolling upgrade 0158->0162 passed (frozen 0158 API/worker health, seal rollback, archived backfill, generated FK closure, v34/v33 compatibility and readiness)\n",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
