import { readMigrationFiles, type MigrationMeta } from "drizzle-orm/migrator";
import { PgDialect } from "drizzle-orm/pg-core";
import { PostgresJsSession } from "drizzle-orm/postgres-js";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import type { ReservedSql, Sql } from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
  expectedSealSchemaCompatibilityManifestV61SourceHash,
  supportedLegacyV45MigrationCount,
  supportedLegacyV45MigrationReplacements,
} from "./schema-compatibility-manifest.gen.js";

const migrationAdvisoryLock = {
  namespace: 1_346_720_329,
  resource: 1_095_783_241,
} as const;

export type AppliedMigration = {
  createdAt: string;
  hash: string;
};

export function latestMigrationIsReleaseCompatibilitySeal(
  migrations: readonly { tag: string }[] = expectedMigrations,
): boolean {
  const latest = migrations.at(-1);
  return latest !== undefined && /^\d{4}_v\d+_compatibility$/u.test(latest.tag);
}

type BooleanResult = {
  value: boolean;
};

type DatabaseLocale = {
  collation: string;
  characterType: string;
  encoding: string;
  migrationRoleSuperuser: boolean;
  serverVersionNumber: number;
};

type MigrationConvergenceSurface = {
  attestationTableExists: boolean;
  v46ReadinessExists: boolean;
  v47ReadinessExists: boolean;
};

type MigrationJournal = {
  entries: readonly {
    tag: string;
    when: number;
  }[];
};

const enumValueAddition = /\bALTER\s+TYPE\b[\s\S]*\bADD\s+VALUE\b/iu;

export function partitionMigrationsAtEnumCommitBoundaries(
  migrations: readonly MigrationMeta[],
): MigrationMeta[][] {
  const batches: MigrationMeta[][] = [];
  let pending: MigrationMeta[] = [];

  for (const migration of migrations) {
    pending.push(migration);
    if (migration.sql.some((statement) => enumValueAddition.test(statement))) {
      batches.push(pending);
      pending = [];
    }
  }
  if (pending.length > 0) {
    batches.push(pending);
  }
  return batches;
}

export async function executeMigrationBatches(
  batches: readonly MigrationMeta[][],
  migrateBatch: (batch: MigrationMeta[]) => Promise<void>,
  index = 0,
): Promise<void> {
  const batch = batches[index];
  if (batch === undefined) {
    return;
  }
  await migrateBatch(batch);
  return executeMigrationBatches(batches, migrateBatch, index + 1);
}

async function migrateVerifiedBundle(
  connection: ReservedSql,
  migrationsFolder: string,
): Promise<void> {
  const config = { migrationsFolder };
  const migrations = readMigrationFiles(config);
  const dialect = new PgDialect();
  const session = new PostgresJsSession<
    ReservedSql,
    Record<string, never>,
    Record<string, never>
  >(connection, dialect, undefined);

  // PostgreSQL forbids using an enum value added to a pre-existing type until
  // the transaction that added it commits. Each batch is still atomic, while
  // the session advisory lock protects the complete multi-batch upgrade. A
  // crash therefore leaves an exact, restartable migration prefix.
  await executeMigrationBatches(
    partitionMigrationsAtEnumCommitBoundaries(migrations),
    (batch) => dialect.migrate(batch, session, config),
  );
}

function protocolError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

export async function assertSupportedDatabaseLocale(
  sql: ReservedSql,
): Promise<void> {
  const [database] = await sql<DatabaseLocale[]>`
    SELECT pg_catalog.pg_encoding_to_char(database.encoding) AS encoding,
           database.datcollate AS collation,
           database.datctype AS "characterType",
           pg_catalog.current_setting('server_version_num')::integer
             AS "serverVersionNumber",
           migration_role.rolsuper AS "migrationRoleSuperuser"
    FROM pg_catalog.pg_database AS database
    JOIN pg_catalog.pg_roles AS migration_role
      ON migration_role.rolname = CURRENT_USER
    WHERE database.datname = pg_catalog.current_database()
  `;
  if (
    database === undefined ||
    database.serverVersionNumber < 180_000 ||
    database.serverVersionNumber >= 190_000
  ) {
    throw protocolError(
      "MIGRATION_DATABASE_VERSION_UNSUPPORTED",
      "Periapsis migrations require PostgreSQL 18.x",
    );
  }
  if (!database.migrationRoleSuperuser) {
    throw protocolError(
      "MIGRATION_DATABASE_ADMIN_UNSUPPORTED",
      "Periapsis migrations require a superuser sealer for role and credential-state attestation",
    );
  }
  if (
    database.encoding !== "UTF8" ||
    database.collation !== "C" ||
    database.characterType !== "C"
  ) {
    throw protocolError(
      "MIGRATION_DATABASE_LOCALE_UNSUPPORTED",
      "Periapsis migrations require a UTF8 database with LC_COLLATE=C and LC_CTYPE=C",
    );
  }
}

type TransactionControlStatement = "BEGIN" | "COMMIT" | "ROLLBACK";

export async function executeWithCleanup<T>(
  operation: () => Promise<T>,
  cleanup: () => Promise<void>,
  aggregateMessage: string,
): Promise<T> {
  let outcome: { ok: true; value: T } | { error: unknown; ok: false };
  try {
    outcome = { ok: true, value: await operation() };
  } catch (error) {
    outcome = { error, ok: false };
  }

  let cleanupFailure: { error: unknown } | undefined;
  try {
    await cleanup();
  } catch (error) {
    cleanupFailure = { error };
  }

  if (!outcome.ok && cleanupFailure) {
    throw new AggregateError(
      [outcome.error, cleanupFailure.error],
      aggregateMessage,
      { cause: cleanupFailure.error },
    );
  }
  if (!outcome.ok) {
    throw outcome.error;
  }
  if (cleanupFailure) {
    throw cleanupFailure.error;
  }
  return outcome.value;
}

export async function executeReservedTransaction<T>(
  execute: (statement: TransactionControlStatement) => Promise<unknown>,
  operation: () => Promise<T>,
): Promise<T> {
  await execute("BEGIN");
  try {
    const result = await operation();
    await execute("COMMIT");
    return result;
  } catch (error) {
    try {
      await execute("ROLLBACK");
    } catch (rollbackError) {
      throw new AggregateError(
        [error, rollbackError],
        "schema migration transaction and rollback both failed",
        { cause: rollbackError },
      );
    }
    throw error;
  }
}

function attachDrizzleClientMetadata(
  client: Sql,
  connection: ReservedSql,
): void {
  // postgres.js types ReservedSql as Sql, but 3.4 omits this metadata at
  // runtime. Drizzle reads it only while constructing its reserved-session
  // adapter; the parsers and serializers remain owned by the parent client.
  if (Reflect.get(connection, "options") === undefined) {
    const attached = Reflect.defineProperty(connection, "options", {
      configurable: true,
      value: client.options,
    });
    if (!attached) {
      throw protocolError(
        "MIGRATION_CLIENT_INCOMPATIBLE",
        "the reserved database connection rejected Drizzle parser metadata",
      );
    }
  }
  if (Reflect.get(connection, "begin") === undefined) {
    const attached = Reflect.defineProperty(connection, "begin", {
      configurable: true,
      value: <T>(
        callback: (transaction: ReservedSql) => Promise<T>,
      ): Promise<T> =>
        executeReservedTransaction(
          (statement) => connection.unsafe(statement),
          () => callback(connection),
        ),
    });
    if (!attached) {
      throw protocolError(
        "MIGRATION_CLIENT_INCOMPATIBLE",
        "the reserved database connection rejected the transaction adapter",
      );
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseMigrationJournal(source: string): MigrationJournal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    !Array.isArray(value.entries) ||
    !value.entries.every(
      (entry) =>
        isRecord(entry) &&
        typeof entry.tag === "string" &&
        Number.isSafeInteger(entry.when),
    )
  ) {
    throw protocolError(
      "MIGRATION_BUNDLE_DIVERGED",
      "the packaged Drizzle migration journal is malformed",
    );
  }
  return { entries: value.entries as MigrationJournal["entries"] };
}

export async function assertExactMigrationBundle(
  migrationsFolder: string,
): Promise<void> {
  try {
    const [journalSource, directoryEntries] = await Promise.all([
      readFile(resolve(migrationsFolder, "meta/_journal.json"), "utf8"),
      readdir(migrationsFolder, { withFileTypes: true }),
    ]);
    const journal = parseMigrationJournal(journalSource);
    const expectedFiles = expectedMigrations.map(
      (migration) => `${migration.tag}.sql`,
    );
    const actualFiles = directoryEntries
      .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
      .map((entry) => entry.name)
      .toSorted();

    if (
      journal.entries.length !== expectedMigrations.length ||
      JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)
    ) {
      throw protocolError(
        "MIGRATION_BUNDLE_DIVERGED",
        "the packaged migration inventory differs from the generated manifest",
      );
    }

    await Promise.all(
      expectedMigrations.map(async (expected, index) => {
        const journalEntry = journal.entries[index];
        const source = await readFile(
          resolve(migrationsFolder, `${expected.tag}.sql`),
        );
        const hash = createHash("sha256").update(source).digest("hex");
        if (
          journalEntry?.tag !== expected.tag ||
          journalEntry.when !== expected.createdAt ||
          hash !== expected.hash
        ) {
          throw protocolError(
            "MIGRATION_BUNDLE_DIVERGED",
            `the packaged migration bundle diverges at ordinal ${index + 1}`,
          );
        }
      }),
    );
  } catch (error) {
    if (isRecord(error) && error.code === "MIGRATION_BUNDLE_DIVERGED") {
      throw error;
    }
    throw Object.assign(
      new Error("the packaged migration bundle could not be verified", {
        cause: error,
      }),
      { code: "MIGRATION_BUNDLE_DIVERGED" },
    );
  }
}

export function assertExactMigrationPrefix(
  appliedMigrations: readonly AppliedMigration[],
  options: { convergenceAttested?: boolean } = {},
): void {
  if (appliedMigrations.length > expectedMigrations.length) {
    throw protocolError(
      "MIGRATION_JOURNAL_DIVERGED",
      "the applied migration journal is newer than this migration manifest",
    );
  }

  const replacementByIndex = new Map<
    number,
    (typeof supportedLegacyV45MigrationReplacements)[number]
  >(
    supportedLegacyV45MigrationReplacements.map((replacement) => [
      replacement.index,
      replacement,
    ]),
  );
  const exactUnattestedLegacyPredecessor =
    !options.convergenceAttested &&
    appliedMigrations.length === supportedLegacyV45MigrationCount &&
    appliedMigrations.every((applied, index) => {
      const expected = expectedMigrations[index];
      const replacement = replacementByIndex.get(index);
      return (
        expected !== undefined &&
        applied.createdAt === String(expected.createdAt) &&
        applied.hash === (replacement?.legacyHash ?? expected.hash)
      );
    });
  if (exactUnattestedLegacyPredecessor) {
    return;
  }

  const predecessorReplacements = supportedLegacyV45MigrationReplacements.map(
    (replacement) => appliedMigrations[replacement.index]?.hash,
  );
  const predecessorIsCanonical = predecessorReplacements.every(
    (hash, index) =>
      hash === supportedLegacyV45MigrationReplacements[index]?.canonicalHash,
  );
  const predecessorIsLegacy = predecessorReplacements.every(
    (hash, index) =>
      hash === supportedLegacyV45MigrationReplacements[index]?.legacyHash,
  );
  const canNormalizeLegacy =
    options.convergenceAttested === true && predecessorIsLegacy;

  for (const [index, applied] of appliedMigrations.entries()) {
    const expected = expectedMigrations[index];
    const replacement = replacementByIndex.get(index);
    const appliedHash =
      canNormalizeLegacy && replacement !== undefined
        ? replacement.canonicalHash
        : applied.hash;
    if (
      expected === undefined ||
      applied.createdAt !== String(expected.createdAt) ||
      appliedHash !== expected.hash ||
      (options.convergenceAttested === true &&
        appliedMigrations.length >= supportedLegacyV45MigrationCount &&
        !predecessorIsCanonical &&
        !predecessorIsLegacy)
    ) {
      throw protocolError(
        "MIGRATION_JOURNAL_DIVERGED",
        `the applied migration journal diverges at ordinal ${index + 1}`,
      );
    }
  }
}

export function isStrictlyPartialV46RestartJournal(
  appliedMigrations: readonly AppliedMigration[],
): boolean {
  const v47CompatibilityIndex = expectedMigrations.findIndex(
    (migration) => migration.tag === "0208_v47_compatibility",
  );
  return (
    v47CompatibilityIndex >= 0 &&
    appliedMigrations.length >= supportedLegacyV45MigrationCount &&
    appliedMigrations.length <= v47CompatibilityIndex
  );
}

async function readMigrationConvergenceAttestation(
  sql: ReservedSql,
  appliedMigrations: readonly AppliedMigration[],
): Promise<boolean> {
  const [surface] = await sql<MigrationConvergenceSurface[]>`
    SELECT
      to_regclass(
        'drizzle.__periapsis_migration_convergence_attestations'
      ) IS NOT NULL AS "attestationTableExists",
      to_regprocedure(
        'app.private_v46_migration_convergence_schema_readiness_v1()'
      ) IS NOT NULL AS "v46ReadinessExists",
      to_regprocedure(
        'app.private_v47_migration_convergence_schema_readiness_v1()'
      ) IS NOT NULL AS "v47ReadinessExists"
  `;
  if (surface?.v47ReadinessExists === true) {
    const [readiness] = await sql<BooleanResult[]>`
      SELECT app.private_v47_migration_convergence_schema_readiness_v1()
        AS value
    `;
    return readiness?.value === true;
  }
  if (surface?.v46ReadinessExists === true) {
    const [readiness] = await sql<BooleanResult[]>`
      SELECT app.private_v46_migration_convergence_schema_readiness_v1()
        AS value
    `;
    if (readiness?.value === true) {
      return true;
    }
  }
  if (
    surface?.attestationTableExists !== true ||
    !isStrictlyPartialV46RestartJournal(appliedMigrations)
  ) {
    return false;
  }

  const replacementByIndex = new Map<
    number,
    (typeof supportedLegacyV45MigrationReplacements)[number]
  >(
    supportedLegacyV45MigrationReplacements.map((replacement) => [
      replacement.index,
      replacement,
    ]),
  );
  const predecessor = appliedMigrations.slice(
    0,
    supportedLegacyV45MigrationCount,
  );
  const canonical = predecessor.every((migration, index) => {
    const expected = expectedMigrations[index];
    return (
      expected !== undefined &&
      migration.createdAt === String(expected.createdAt) &&
      migration.hash === expected.hash
    );
  });
  const legacy = predecessor.every((migration, index) => {
    const expected = expectedMigrations[index];
    const replacement = replacementByIndex.get(index);
    return (
      expected !== undefined &&
      migration.createdAt === String(expected.createdAt) &&
      migration.hash === (replacement?.legacyHash ?? expected.hash)
    );
  });
  if (!canonical && !legacy) {
    return false;
  }

  const rawFingerprint = predecessor
    .map((migration) => `${migration.createdAt}@${migration.hash}`)
    .join(":");
  const normalizedFingerprint = predecessor
    .map((migration, index) => {
      const replacement = replacementByIndex.get(index);
      return `${migration.createdAt}@${replacement?.canonicalHash ?? migration.hash}`;
    })
    .join(":");
  const metadataReplacement = supportedLegacyV45MigrationReplacements[0];
  const compatibilityReplacement = supportedLegacyV45MigrationReplacements[1];
  const metadataHash =
    metadataReplacement === undefined
      ? undefined
      : predecessor[metadataReplacement.index]?.hash;
  const compatibilityHash =
    compatibilityReplacement === undefined
      ? undefined
      : predecessor[compatibilityReplacement.index]?.hash;
  if (metadataHash === undefined || compatibilityHash === undefined) {
    return false;
  }

  // The V46 readiness function deliberately binds the then-current catalog,
  // so it becomes false as later migrations replace capability roots. During
  // a restart before 0208, verify the immutable convergence record itself and
  // its protection surface instead. A journal that already contains 0208 (or
  // anything newer) must have a live current convergence root and may never
  // fall back to this predecessor evidence.
  const [attestation] = await sql<BooleanResult[]>`
    SELECT
      (SELECT count(*) = 1
       FROM drizzle.__periapsis_migration_convergence_attestations)
      AND EXISTS (
        SELECT 1
        FROM drizzle.__periapsis_migration_convergence_attestations AS evidence
        WHERE evidence.convergence_version = 46
          AND evidence.source_variant = ${legacy ? "legacy-v45" : "canonical-v45"}
          AND evidence.metadata_original_hash = ${metadataHash}
          AND evidence.compatibility_original_hash = ${compatibilityHash}
          AND evidence.raw_v45_fingerprint = ${rawFingerprint}
          AND evidence.normalized_v45_fingerprint = ${normalizedFingerprint}
          AND evidence.canonical_catalog_digest =
            '1b1310c2a1350590629ebfb71eb58d837900d376a3bdf8c7ccbff3e9aad3d2a3'
          AND uuid_extract_version(evidence.attestation_id) = 7
          AND evidence.attested_at IS NOT NULL
      )
      AND EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
        WHERE relation.oid =
          'drizzle.__periapsis_migration_convergence_attestations'::regclass
          AND relation.relkind = 'r'
          AND relation.relpersistence = 'p'
          AND NOT relation.relrowsecurity
          AND NOT relation.relforcerowsecurity
          AND owner.rolname = 'periapsis_migrator'
      )
      AND (
        SELECT count(*) = 2
        FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid =
          'drizzle.__periapsis_migration_convergence_attestations'::regclass
          AND NOT trigger.tgisinternal
          AND trigger.tgenabled = 'O'
          AND trigger.tgfoid =
            'app.guard_migration_convergence_attestation_v1()'::regprocedure
          AND ROW(trigger.tgname, trigger.tgtype) IN (
            ROW('migration_convergence_immutable'::name, 27::smallint),
            ROW('migration_convergence_truncate_immutable'::name, 34::smallint)
          )
      )
      AND NOT EXISTS (
        SELECT 1
        FROM (VALUES
          ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
          ('periapsis_auditor')
        ) AS runtime_role(name)
        CROSS JOIN (VALUES
          ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
          ('REFERENCES'), ('TRIGGER'), ('MAINTAIN')
        ) AS privilege(name)
        WHERE has_table_privilege(
          runtime_role.name,
          'drizzle.__periapsis_migration_convergence_attestations',
          privilege.name
        )
      ) AS value
  `;
  return attestation?.value === true;
}

async function readAppliedMigrations(
  sql: ReservedSql,
): Promise<AppliedMigration[]> {
  const [state] = await sql<BooleanResult[]>`
    SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS value
  `;
  if (state === undefined) {
    throw protocolError(
      "MIGRATION_JOURNAL_UNAVAILABLE",
      "the migration journal existence check returned no result",
    );
  }
  if (!state.value) {
    return [];
  }

  return sql<AppliedMigration[]>`
    SELECT created_at::text AS "createdAt",
           lower(hash::text) AS hash
    FROM drizzle.__drizzle_migrations
    ORDER BY created_at, id
  `;
}

export async function sealSchemaCompatibilityManifest(
  sql: ReservedSql,
): Promise<void> {
  const [attestation] = await sql<BooleanResult[]>`
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
        ${expectedSealSchemaCompatibilityManifestV61SourceHash}
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
  if (attestation?.value !== true) {
    throw protocolError(
      "MIGRATION_SEALER_DIVERGED",
      "the V61 schema compatibility sealer failed source and catalog attestation",
    );
  }
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${expectedMigrationCount}::bigint,
      ${expectedMigrationCreatedAt}::bigint,
      ${expectedMigrationHash}::text,
      ${expectedMigrationFingerprint}::text
    )
  `;
  // Routine privilege invalidations become visible to stable readiness
  // functions only after a PostgreSQL command boundary. The first call rotates
  // the catalog; the second call source-identically verifies every public root.
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${expectedMigrationCount}::bigint,
      ${expectedMigrationCreatedAt}::bigint,
      ${expectedMigrationHash}::text,
      ${expectedMigrationFingerprint}::text
    )
  `;
}

async function acquireMigrationLock(sql: ReservedSql): Promise<void> {
  const [result] = await sql<BooleanResult[]>`
    SELECT pg_try_advisory_lock(
      ${migrationAdvisoryLock.namespace},
      ${migrationAdvisoryLock.resource}
    ) AS value
  `;
  if (result?.value !== true) {
    throw protocolError(
      "MIGRATION_LOCK_UNAVAILABLE",
      "another schema migration job already holds the Periapsis migration lock",
    );
  }
}

async function releaseMigrationLock(sql: ReservedSql): Promise<void> {
  const [result] = await sql<BooleanResult[]>`
    SELECT pg_advisory_unlock(
      ${migrationAdvisoryLock.namespace},
      ${migrationAdvisoryLock.resource}
    ) AS value
  `;
  if (result?.value !== true) {
    throw protocolError(
      "MIGRATION_LOCK_LOST",
      "the Periapsis schema migration lock was not held during release",
    );
  }
}

export async function migrateSchema(
  client: Sql,
  migrationsFolder: string,
): Promise<void> {
  const connection = await client.reserve();
  let lockAcquired = false;
  let operationFailed = false;
  let operationError: unknown;

  try {
    attachDrizzleClientMetadata(client, connection);
    await acquireMigrationLock(connection);
    lockAcquired = true;

    await connection`set timezone to 'UTC'`;
    await connection`select set_config('search_path', 'public', false)`;
    await assertSupportedDatabaseLocale(connection);

    await assertExactMigrationBundle(migrationsFolder);
    const appliedMigrations = await readAppliedMigrations(connection);
    const convergenceAttested = await readMigrationConvergenceAttestation(
      connection,
      appliedMigrations,
    );
    assertExactMigrationPrefix(appliedMigrations, { convergenceAttested });

    await migrateVerifiedBundle(connection, migrationsFolder);
    const migratedMigrations = await readAppliedMigrations(connection);
    const migratedConvergenceAttested =
      await readMigrationConvergenceAttestation(connection, migratedMigrations);
    assertExactMigrationPrefix(migratedMigrations, {
      convergenceAttested: migratedConvergenceAttested,
    });
    if (!migratedConvergenceAttested) {
      throw protocolError(
        "MIGRATION_JOURNAL_DIVERGED",
        "the migrated journal has no exact supported convergence attestation",
      );
    }
    // An additive schema slice deliberately leaves the preceding public
    // compatibility root fail-closed. Only a release compatibility migration
    // is allowed to invoke and rotate the generic sealer.
    if (latestMigrationIsReleaseCompatibilitySeal()) {
      await sealSchemaCompatibilityManifest(connection);
    }
  } catch (error) {
    operationFailed = true;
    operationError = error;
  }

  const errors: unknown[] = [];
  if (operationFailed) {
    errors.push(operationError);
  }
  if (lockAcquired) {
    try {
      await releaseMigrationLock(connection);
    } catch (error) {
      errors.push(error);
    }
  }
  try {
    connection.release();
  } catch (error) {
    errors.push(error);
  }

  if (errors.length === 1) {
    throw errors[0];
  }
  if (errors.length > 1) {
    throw new AggregateError(
      errors,
      "schema migration operation and cleanup reported multiple failures",
      { cause: errors.at(-1) },
    );
  }
}
