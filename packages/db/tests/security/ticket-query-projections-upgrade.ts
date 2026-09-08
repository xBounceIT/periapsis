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
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import { migrateSchema } from "../../src/admin/schema-migration.js";

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
    throw new Error("The Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

const databaseUrl =
  process.env.PERIAPSIS_TICKET_QUERY_PROJECTION_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_QUERY_PROJECTION_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18 database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 138;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
assert.equal(predecessorEntries.length, 139);
assert.equal(predecessor?.tag, "0138_saved_ticket_views_abi_readiness");
assert.equal(predecessor.createdAt, 1787741355171);
assert.equal(
  predecessor.hash,
  "89a75840127b58a16350a341265a945c22513607bb809cb4e7b28e7a91e18ac4",
);
assert.equal(expectedMigrationCount, 248);
assert.equal(expectedMigrationCreatedAt, 1788818321637);
const predecessorFingerprint = expectedMigrations
  .slice(0, predecessorIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-ticket-query-projections-rolling-0138-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18."),
    "upgrade harness requires PostgreSQL 18",
  );

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
      latest_created_at: string;
      latest_hash: string;
      migration_fingerprint: string;
    }[]
  >`
    SELECT count(*)::integer AS count,
           max(created_at)::text AS latest_created_at,
           (array_agg(lower(hash::text)
              ORDER BY created_at DESC, id DESC))[1] AS latest_hash,
           string_agg(
             created_at::text || '@' || lower(hash::text), ':'
             ORDER BY created_at, id
           ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(prefix, {
    count: 139,
    latest_created_at: String(predecessor.createdAt),
    latest_hash: predecessor.hash,
    migration_fingerprint: predecessorFingerprint,
  });

  await migrateSchema(sql, migrationsRoot);
  const [compatibility] = await sql<
    {
      current_count: number;
      current_latest: string;
      current_hash: string;
      current_fingerprint: string;
      predecessor_count: number;
      predecessor_latest: string;
      predecessor_hash: string;
      predecessor_fingerprint: string;
      retired_count: number;
      release_ready: boolean;
      projections_ready: boolean;
      saved_views_ready: boolean;
      sla_ready: boolean;
      federation_ready: boolean;
      identity_ready: boolean;
      device_ready: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS current_count,
           current_projection.latest_created_at::text AS current_latest,
           current_projection.latest_hash AS current_hash,
           current_projection.migration_fingerprint AS current_fingerprint,
           predecessor_projection.applied_count::integer AS predecessor_count,
           predecessor_projection.latest_created_at::text AS predecessor_latest,
           predecessor_projection.latest_hash AS predecessor_hash,
           predecessor_projection.migration_fingerprint AS predecessor_fingerprint,
           retired_projection.applied_count::integer AS retired_count,
           app.release_runtime_schema_readiness_v58() AS release_ready,
           app.ticket_query_projections_readiness_v1() AS projections_ready,
           app.ticket_saved_views_schema_readiness_v1() AS saved_views_ready,
           app.sla_schema_readiness_v1() AS sla_ready,
           app.federated_authentication_schema_readiness_v1() AS federation_ready,
           app.identity_mfa_schema_readiness_v1() AS identity_ready,
           app.identity_mfa_device_management_readiness_v1() AS device_ready
    FROM app.schema_compatibility_v58() AS current_projection
    CROSS JOIN app.schema_compatibility_v29() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v28() AS retired_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: expectedMigrationCount,
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    predecessor_count: 0,
    predecessor_latest: "0",
    predecessor_hash: "UNSUPPORTED",
    predecessor_fingerprint: "UNSUPPORTED",
    retired_count: 0,
    release_ready: true,
    projections_ready: false,
    saved_views_ready: false,
    sla_ready: false,
    federation_ready: false,
    identity_ready: false,
    device_ready: false,
  });

  const [acl] = await sql<
    {
      api_attribution: boolean;
      api_sla_revision: boolean;
      api_source: boolean;
      worker_projection: boolean;
      api_readiness: boolean;
      worker_readiness: boolean;
    }[]
  >`
    SELECT has_table_privilege(
             'periapsis_api',
             'app.ticket_service_account_attributions_v1', 'SELECT'
           ) AS api_attribution,
           has_table_privilege(
             'periapsis_api',
             'app.ticket_sla_column_revisions_v1', 'SELECT'
           ) AS api_sla_revision,
           has_any_column_privilege(
             'periapsis_api',
             'public.sla_materialized_column_values', 'SELECT'
           ) AS api_source,
           has_table_privilege(
             'periapsis_worker',
             'app.ticket_sla_materialized_values_v1', 'SELECT'
           ) AS worker_projection,
           has_function_privilege(
             'periapsis_api',
             'app.ticket_query_projections_readiness_v1()', 'EXECUTE'
           ) AS api_readiness,
           has_function_privilege(
             'periapsis_worker',
             'app.ticket_query_projections_readiness_v1()', 'EXECUTE'
           ) AS worker_readiness
  `;
  assert.deepEqual(acl, {
    api_attribution: true,
    api_sla_revision: true,
    api_source: false,
    worker_projection: false,
    api_readiness: true,
    worker_readiness: false,
  });
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
