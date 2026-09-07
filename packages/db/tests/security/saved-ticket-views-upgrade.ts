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

const databaseUrl = process.env.PERIAPSIS_SAVED_VIEWS_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SAVED_VIEWS_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18 database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 135;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
assert.equal(predecessorEntries.length, 136);
assert.equal(predecessor?.tag, "0135_sla_queue_metrics_abi");
assert.equal(predecessor.createdAt, 1787737707040);
assert.equal(
  predecessor.hash,
  "3f4ccd0e67f21c3e3b72ab76b1cbe0c7265a9fa8d872af8c4a8f00047cd976aa",
);
assert.equal(expectedMigrationCount, 240);
assert.equal(expectedMigrationCreatedAt, 1788796577322);
const predecessorFingerprint = expectedMigrations
  .slice(0, predecessorIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-saved-ticket-views-rolling-0135-"),
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
    count: 136,
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
           app.release_runtime_schema_readiness_v54() AS release_ready,
           app.ticket_saved_views_schema_readiness_v1() AS saved_views_ready,
           app.sla_schema_readiness_v1() AS sla_ready,
           app.federated_authentication_schema_readiness_v1() AS federation_ready,
           app.identity_mfa_schema_readiness_v1() AS identity_ready,
           app.identity_mfa_device_management_readiness_v1() AS device_ready
    FROM app.schema_compatibility_v54() AS current_projection
    CROSS JOIN app.schema_compatibility_v28() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v27() AS retired_projection
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
    saved_views_ready: false,
    sla_ready: false,
    federation_ready: false,
    identity_ready: false,
    device_ready: false,
  });

  const [acl] = await sql<
    { api_table: boolean; api_commit: boolean; worker_commit: boolean }[]
  >`
    SELECT has_table_privilege(
             'periapsis_api', 'public.ticket_saved_views', 'SELECT'
           ) AS api_table,
           has_function_privilege(
             'periapsis_api',
             'app.commit_ticket_saved_view_v1(jsonb)', 'EXECUTE'
           ) AS api_commit,
           has_function_privilege(
             'periapsis_worker',
             'app.commit_ticket_saved_view_v1(jsonb)', 'EXECUTE'
           ) AS worker_commit
  `;
  assert.deepEqual(acl, {
    api_table: false,
    api_commit: true,
    worker_commit: false,
  });
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
