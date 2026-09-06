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
  expectedMigrations,
  expectedSealSchemaCompatibilityManifestV48SourceHash,
  expectedSealSchemaCompatibilityManifestV49SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type CompatibilityRow = {
  applied_count: number | string;
  latest_created_at: number | string;
  latest_hash: string;
  migration_fingerprint: string;
};

type Journal = {
  dialect: string;
  entries: JournalEntry[];
  version: string;
};

type JournalEntry = {
  breakpoints: boolean;
  idx: number;
  tag: string;
  version: string;
  when: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return (
    isRecord(value) &&
    typeof value.breakpoints === "boolean" &&
    Number.isSafeInteger(value.idx) &&
    typeof value.tag === "string" &&
    typeof value.version === "string" &&
    Number.isSafeInteger(value.when)
  );
}

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    typeof value.dialect !== "string" ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isJournalEntry) ||
    typeof value.version !== "string"
  ) {
    throw new Error("Drizzle migration journal is malformed");
  }
  return {
    dialect: value.dialect,
    entries: value.entries,
    version: value.version,
  };
}

const databaseUrl =
  process.env.PERIAPSIS_SCHEMA_COMPATIBILITY_V49_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SCHEMA_COMPATIBILITY_V49_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 UTF8 C/C database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const v48MigrationCount = 219;
const v48Entries = journal.entries.slice(0, v48MigrationCount);
const v48Manifest = expectedMigrations.slice(0, v48MigrationCount);
const v48Latest = v48Manifest.at(-1);
assert.equal(v48Entries.length, v48MigrationCount);
assert.equal(v48Manifest.length, v48MigrationCount);
assert.deepEqual(v48Latest, {
  createdAt: 1_788_276_517_454,
  hash: "d6a20868f2707d3ff199cccbb2f6c1afc66d068f8f9bc41660482c010317a50a",
  tag: "0218_v48_compatibility",
});
const v49MigrationCount = 230;
const v49Entries = journal.entries.slice(0, v49MigrationCount);
const v49Manifest = expectedMigrations.slice(0, v49MigrationCount);
const v49Latest = v49Manifest.at(-1);
assert.equal(v49Entries.length, v49MigrationCount);
assert.equal(v49Entries.at(-1)?.tag, "0229_v49_compatibility");
assert(v49Latest);
assert.equal(v49Latest.tag, "0229_v49_compatibility");
const v49Fingerprint = v49Manifest
  .map((migration) => `${migration.createdAt}@${migration.hash}`)
  .join(":");

const v48Fingerprint = v48Manifest
  .map((migration) => `${migration.createdAt}@${migration.hash}`)
  .join(":");
const v49MigrationSource = await readFile(
  resolve(migrationsRoot, "0229_v49_compatibility.sql"),
  "utf8",
);
const expectedV49CatalogDigest =
  /private_release_runtime_dependency_surface_hash_v49\(\)<>\s*'([0-9a-f]{64})'/u.exec(
    v49MigrationSource,
  )?.[1];
assert(
  expectedV49CatalogDigest,
  "0229 must pin the exact V49 release catalog digest",
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-schema-v49-rolling-v48-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

async function stagePrefix(entries: JournalEntry[]): Promise<void> {
  await mkdir(resolve(stageRoot, "meta"), { recursive: true });
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map(async (entry, index) => {
      const expected = expectedMigrations[index];
      assert(expected);
      assert.equal(entry.idx, index);
      assert.equal(entry.tag, expected.tag);
      assert.equal(entry.when, expected.createdAt);
      const path = resolve(migrationsRoot, `${entry.tag}.sql`);
      assert.equal(
        createHash("sha256")
          .update(await readFile(path))
          .digest("hex"),
        expected.hash,
      );
      await copyFile(path, resolve(stageRoot, `${entry.tag}.sql`));
    }),
  );
}

try {
  const [server] = await sql<
    {
      character_type: string;
      collation: string;
      encoding: string;
      version: string;
      version_num: number;
    }[]
  >`
    SELECT current_setting('server_version') AS version,
           current_setting('server_version_num')::integer AS version_num,
           pg_catalog.pg_encoding_to_char(database.encoding) AS encoding,
           database.datcollate AS collation,
           database.datctype AS character_type
    FROM pg_catalog.pg_database AS database
    WHERE database.datname=pg_catalog.current_database()
  `;
  assert.deepEqual(server, {
    character_type: "C",
    collation: "C",
    encoding: "UTF8",
    version: "18.6",
    version_num: 180_006,
  });

  await stagePrefix(v48Entries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });

  const [unsealedV48] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v48()
  `;
  assert.deepEqual(unsealedV48, {
    applied_count: "0",
    latest_created_at: "0",
    latest_hash: "UNSUPPORTED",
    migration_fingerprint: "UNSUPPORTED",
  });

  async function sealHistoricalManifest(
    count: number,
    sourceHash: string,
  ): Promise<void> {
    const manifest = expectedMigrations.slice(0, count);
    const latest = manifest.at(-1);
    assert(latest);
    assert.equal(manifest.length, count);
    const fingerprint = manifest
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":");
    const [sealerAttestation] = await sql<{ value: boolean }[]>`
    SELECT count(*) = 1 AND coalesce(bool_and(
      owner.rolname = 'periapsis_migrator'
      AND language.lanname = 'plpgsql'
      AND procedure.prokind = 'f'
      AND procedure.provolatile = 'v'
      AND procedure.prosecdef
      AND NOT procedure.proisstrict
      AND NOT procedure.proleakproof
      AND procedure.proparallel = 'u'
      AND procedure.pronargs = 4
      AND procedure.pronargdefaults = 0
      AND procedure.proargtypes = '20 20 25 25'::oidvector
      AND procedure.proargnames = ARRAY[
        'p_expected_count', 'p_expected_latest_created_at',
        'p_expected_latest_hash', 'p_expected_migration_fingerprint'
      ]::text[]
      AND procedure.proargmodes IS NULL
      AND NOT procedure.proretset
      AND procedure.prorettype = 'void'::regtype
      AND procedure.proconfig IS NOT DISTINCT FROM
        ARRAY['search_path=pg_catalog, public, app']::text[]
      AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
        ${sourceHash}
      AND (
        SELECT count(*) = 1 AND coalesce(bool_and(
          privilege.grantor = procedure.proowner
          AND privilege.grantee = procedure.proowner
          AND privilege.privilege_type = 'EXECUTE'
          AND NOT privilege.is_grantable
        ), false)
        FROM aclexplode(coalesce(
          procedure.proacl,
          acldefault('f', procedure.proowner)
        )) AS privilege
      )
    ), false) AS value
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
    WHERE procedure.oid = to_regprocedure(
      'app.seal_schema_compatibility_manifest(bigint,bigint,text,text)'
    )
  `;
    assert.equal(sealerAttestation?.value, true);

    await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${count}::bigint,
      ${latest.createdAt}::bigint,
      ${latest.hash}::text,
      ${fingerprint}::text
    )
  `;
    await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${count}::bigint,
      ${latest.createdAt}::bigint,
      ${latest.hash}::text,
      ${fingerprint}::text
    )
  `;
  }
  await sealHistoricalManifest(
    v48MigrationCount,
    expectedSealSchemaCompatibilityManifestV48SourceHash,
  );
  const [sealedV48] = await sql<
    (CompatibilityRow & {
      catalog_digest: string;
      release_ready: boolean;
    })[]
  >`
    SELECT compatibility.*,
           app.private_release_runtime_dependency_surface_hash_v48()
             AS catalog_digest,
           app.release_runtime_schema_readiness_v48() AS release_ready
    FROM app.schema_compatibility_v48() AS compatibility
  `;
  assert.deepEqual(sealedV48, {
    applied_count: String(v48MigrationCount),
    catalog_digest:
      "c22f7bce63c255e7447dd4eb3454da4a14de5afc6fc317f4c8fcb63732a912e3",
    latest_created_at: String(v48Latest.createdAt),
    latest_hash: v48Latest.hash,
    migration_fingerprint: v48Fingerprint,
    release_ready: true,
  });

  await stagePrefix(v49Entries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  await sealHistoricalManifest(
    v49MigrationCount,
    expectedSealSchemaCompatibilityManifestV49SourceHash,
  );

  const [sealedV49] = await sql<
    (CompatibilityRow & {
      catalog_digest: string;
      alert_dfir_ready: boolean;
      notification_schema_ready: boolean;
      notification_v4_runtime_grants: number;
      retired_alert_dfir_v1_runtime_grants: number;
      release_ready: boolean;
      retired_v48_config: string[];
      retired_v48_runtime_grants: number;
    })[]
  >`
    SELECT compatibility.*,
           app.private_release_runtime_dependency_surface_hash_v49()
             AS catalog_digest,
           app.alert_dfir_runtime_schema_readiness_v2()
             AS alert_dfir_ready,
           (SELECT readiness.schema_safe
            FROM app.notification_dispatch_readiness_v49() AS readiness)
             AS notification_schema_ready,
           app.release_runtime_schema_readiness_v49() AS release_ready,
           retired.proconfig AS retired_v48_config,
           (
             SELECT count(*)::integer
             FROM pg_catalog.aclexplode(coalesce(
               retired.proacl,
               pg_catalog.acldefault('f', retired.proowner)
             )) AS privilege
             JOIN pg_catalog.pg_roles AS grantee
               ON grantee.oid = privilege.grantee
             WHERE privilege.privilege_type = 'EXECUTE'
               AND grantee.rolname = ANY(ARRAY[
                 'periapsis_api', 'periapsis_worker',
                 'periapsis_notifier', 'periapsis_auditor'
               ]::text[])
           ) AS retired_v48_runtime_grants,
           (
             SELECT count(*)::integer
             FROM (VALUES
               ('periapsis_api'), ('periapsis_worker'),
               ('periapsis_notifier'), ('periapsis_auditor')
             ) AS runtime_role(name)
             WHERE has_function_privilege(
               runtime_role.name,
               'app.alert_dfir_runtime_schema_readiness_v1()',
               'EXECUTE'
             )
           ) AS retired_alert_dfir_v1_runtime_grants
           ,(
             SELECT count(*)::integer
             FROM (VALUES
               ('periapsis_api'), ('periapsis_worker'),
               ('periapsis_notifier'), ('periapsis_auditor')
             ) AS runtime_role(name)
             WHERE has_function_privilege(
               runtime_role.name,
               'app.notification_dispatch_readiness_v4()',
               'EXECUTE'
             )
           ) AS notification_v4_runtime_grants
    FROM app.schema_compatibility_v49() AS compatibility
    CROSS JOIN pg_catalog.pg_proc AS retired
    WHERE retired.oid = 'app.schema_compatibility_v48()'::regprocedure
  `;
  assert.deepEqual(sealedV49, {
    applied_count: String(v49MigrationCount),
    alert_dfir_ready: true,
    catalog_digest: expectedV49CatalogDigest,
    latest_created_at: String(v49Latest.createdAt),
    latest_hash: v49Latest.hash,
    migration_fingerprint: v49Fingerprint,
    notification_schema_ready: true,
    notification_v4_runtime_grants: 0,
    release_ready: true,
    retired_v48_config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
    retired_alert_dfir_v1_runtime_grants: 0,
    retired_v48_runtime_grants: 0,
  });

  const [absentLoginState] = await sql<
    { catalog_digest: string; release_ready: boolean }[]
  >`
    SELECT app.private_release_runtime_dependency_surface_hash_v49()
             AS catalog_digest,
           app.release_runtime_schema_readiness_v49() AS release_ready
  `;
  assert.deepEqual(absentLoginState, {
    catalog_digest: expectedV49CatalogDigest,
    release_ready: true,
  });

  await sql.unsafe(`
    CREATE ROLE periapsis_api_login NOSUPERUSER NOCREATEDB NOCREATEROLE
      INHERIT NOREPLICATION NOBYPASSRLS NOLOGIN CONNECTION LIMIT 40;
    CREATE ROLE periapsis_worker_login NOSUPERUSER NOCREATEDB NOCREATEROLE
      INHERIT NOREPLICATION NOBYPASSRLS NOLOGIN CONNECTION LIMIT 20;
    CREATE ROLE periapsis_notifier_login NOSUPERUSER NOCREATEDB NOCREATEROLE
      INHERIT NOREPLICATION NOBYPASSRLS NOLOGIN CONNECTION LIMIT 20;
    CREATE ROLE periapsis_auditor_login NOSUPERUSER NOCREATEDB NOCREATEROLE
      INHERIT NOREPLICATION NOBYPASSRLS NOLOGIN CONNECTION LIMIT -1;
    GRANT periapsis_api TO periapsis_api_login
      WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
    GRANT periapsis_worker TO periapsis_worker_login
      WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
    GRANT periapsis_notifier TO periapsis_notifier_login
      WITH ADMIN FALSE, INHERIT TRUE, SET TRUE;
    GRANT periapsis_auditor TO periapsis_auditor_login
      WITH ADMIN FALSE, INHERIT TRUE, SET TRUE
  `);
  const [offlineLoginState] = await sql<
    { catalog_digest: string; release_ready: boolean }[]
  >`
    SELECT app.private_release_runtime_dependency_surface_hash_v49()
             AS catalog_digest,
           app.release_runtime_schema_readiness_v49() AS release_ready
  `;
  assert.deepEqual(offlineLoginState, absentLoginState);

  await sql.unsafe(`
    SET password_encryption='scram-sha-256';
    ALTER ROLE periapsis_api_login LOGIN
      PASSWORD 'v49-api-upgrade-probe';
    ALTER ROLE periapsis_worker_login LOGIN
      PASSWORD 'v49-worker-upgrade-probe';
    ALTER ROLE periapsis_notifier_login LOGIN
      PASSWORD 'v49-notifier-upgrade-probe';
    ALTER ROLE periapsis_auditor_login LOGIN
      PASSWORD 'v49-auditor-upgrade-probe'
  `);
  const [onlineLoginState] = await sql<
    { catalog_digest: string; release_ready: boolean }[]
  >`
    SELECT app.private_release_runtime_dependency_surface_hash_v49()
             AS catalog_digest,
           app.release_runtime_schema_readiness_v49() AS release_ready
  `;
  assert.deepEqual(onlineLoginState, absentLoginState);

  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  await sealHistoricalManifest(
    v49MigrationCount,
    expectedSealSchemaCompatibilityManifestV49SourceHash,
  );
  const [restart] = await sql<
    (CompatibilityRow & { catalog_digest: string; release_ready: boolean })[]
  >`
    SELECT compatibility.*,
           app.private_release_runtime_dependency_surface_hash_v49()
             AS catalog_digest,
           app.release_runtime_schema_readiness_v49() AS release_ready
    FROM app.schema_compatibility_v49() AS compatibility
  `;
  assert.deepEqual(restart, {
    applied_count: String(v49MigrationCount),
    catalog_digest: expectedV49CatalogDigest,
    latest_created_at: String(v49Latest.createdAt),
    latest_hash: v49Latest.hash,
    migration_fingerprint: v49Fingerprint,
    release_ready: true,
  });
} finally {
  await sql.end();
  await rm(stageRoot, { force: true, recursive: true });
}
