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
  return typeof value === "object" && value !== null;
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
  process.env.PERIAPSIS_FEDERATED_AUTH_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_FEDERATED_AUTH_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18 database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 125;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
assert.equal(predecessorEntries.length, 126);
assert.equal(predecessor?.tag, "0125_identity_mfa_device_management_readiness");
assert.equal(predecessor.createdAt, 1787723203494);
assert.equal(
  predecessor.hash,
  "211491eec9cf3e475db463fd815d31a98c2e80263e3c3957cf0eef7a5434a9d8",
);
assert.equal(expectedMigrationCount, 234);
assert.equal(expectedMigrationCreatedAt, 1788650095675);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-federated-auth-rolling-0125-"),
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
    { count: number; latest_created_at: string; latest_hash: string }[]
  >`
    SELECT count(*)::integer AS count,
           max(created_at)::text AS latest_created_at,
           (array_agg(lower(hash::text) ORDER BY created_at DESC, id DESC))[1]
             AS latest_hash
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(prefix, {
    count: 126,
    latest_created_at: String(predecessor.createdAt),
    latest_hash: predecessor.hash,
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
      retired_count: number;
      federation_ready: boolean;
      release_ready: boolean;
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
           retired_projection.applied_count::integer AS retired_count,
           app.federated_authentication_schema_readiness_v51()
             AS federation_ready,
           app.release_runtime_schema_readiness_v51() AS release_ready,
           app.identity_mfa_schema_readiness_v1() AS identity_ready,
           app.identity_mfa_device_management_readiness_v1() AS device_ready
    FROM app.schema_compatibility_v51() AS current_projection
    CROSS JOIN app.schema_compatibility_v27() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v26() AS retired_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: expectedMigrationCount,
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    predecessor_count: 0,
    predecessor_latest: "0",
    predecessor_hash: "UNSUPPORTED",
    retired_count: 0,
    federation_ready: true,
    release_ready: true,
    identity_ready: false,
    device_ready: false,
  });
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
