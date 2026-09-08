import { appendFile, cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { readMigrationFiles } from "drizzle-orm/migrator";
import { describe, expect, it, vi } from "vitest";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
  expectedSealSchemaCompatibilityManifestV62SourceHash,
  supportedLegacyV45MigrationCount,
  supportedLegacyV45MigrationReplacements,
} from "../src/admin/schema-compatibility-manifest.gen.js";
import {
  assertExactMigrationBundle,
  assertExactMigrationPrefix,
  assertSupportedDatabaseLocale,
  executeMigrationBatches,
  executeReservedTransaction,
  executeWithCleanup,
  isStrictlyPartialV46RestartJournal,
  latestMigrationIsReleaseCompatibilitySeal,
  migrateSchema,
  partitionMigrationsAtEnumCommitBoundaries,
  sealSchemaCompatibilityManifest,
  type AppliedMigration,
} from "../src/admin/schema-migration.js";

const migrationsRoot = resolve(import.meta.dirname, "../migrations");

function appliedManifest(): AppliedMigration[] {
  return expectedMigrations.map((migration) => ({
    createdAt: String(migration.createdAt),
    hash: migration.hash,
  }));
}

function legacyV45Manifest(): AppliedMigration[] {
  const applied = appliedManifest().slice(0, supportedLegacyV45MigrationCount);
  for (const replacement of supportedLegacyV45MigrationReplacements) {
    applied[replacement.index] = {
      createdAt: String(replacement.createdAt),
      hash: replacement.legacyHash,
    };
  }
  return applied;
}

function expectDivergence(applied: AppliedMigration[]): void {
  try {
    assertExactMigrationPrefix(applied);
  } catch (error) {
    expect(error).toMatchObject({ code: "MIGRATION_JOURNAL_DIVERGED" });
    return;
  }
  throw new Error("expected the migration prefix check to reject divergence");
}

describe("canonical schema migration preflight", () => {
  it("accepts only the source-attested C locale database boundary", async () => {
    const supported = vi.fn(async () => [
      {
        characterType: "C",
        collation: "C",
        encoding: "UTF8",
        migrationRoleSuperuser: true,
        serverVersionNumber: 180_006,
      },
    ]);
    const unsupported = vi.fn(async () => [
      {
        characterType: "Italian_Italy.1252",
        collation: "Italian_Italy.1252",
        encoding: "UTF8",
        migrationRoleSuperuser: true,
        serverVersionNumber: 180_006,
      },
    ]);

    await expect(
      // @ts-expect-error Focused tagged-template double for the locale query.
      assertSupportedDatabaseLocale(supported),
    ).resolves.toBeUndefined();
    await expect(
      // @ts-expect-error Focused tagged-template double for the locale query.
      assertSupportedDatabaseLocale(unsupported),
    ).rejects.toMatchObject({
      code: "MIGRATION_DATABASE_LOCALE_UNSUPPORTED",
    });
  });

  it("rejects non-18 servers before entering the migration chain", async () => {
    const unsupported = vi.fn(async () => [
      {
        characterType: "C",
        collation: "C",
        encoding: "UTF8",
        migrationRoleSuperuser: true,
        serverVersionNumber: 170_007,
      },
    ]);

    await expect(
      // @ts-expect-error Focused tagged-template double for the preflight query.
      assertSupportedDatabaseLocale(unsupported),
    ).rejects.toMatchObject({
      code: "MIGRATION_DATABASE_VERSION_UNSUPPORTED",
    });
  });

  it("rejects a migration identity that cannot attest runtime credentials", async () => {
    const unsupported = vi.fn(async () => [
      {
        characterType: "C",
        collation: "C",
        encoding: "UTF8",
        migrationRoleSuperuser: false,
        serverVersionNumber: 180_006,
      },
    ]);

    await expect(
      // @ts-expect-error Focused tagged-template double for the preflight query.
      assertSupportedDatabaseLocale(unsupported),
    ).rejects.toMatchObject({
      code: "MIGRATION_DATABASE_ADMIN_UNSUPPORTED",
    });
  });

  it("seals only bundles ending in an explicit release compatibility migration", () => {
    expect(latestMigrationIsReleaseCompatibilitySeal()).toBe(true);
    expect(
      latestMigrationIsReleaseCompatibilitySeal(
        expectedMigrations.slice(0, -1),
      ),
    ).toBe(false);
    expect(
      latestMigrationIsReleaseCompatibilitySeal([
        { tag: "0218_v48_compatibility" },
      ]),
    ).toBe(true);
    expect(
      latestMigrationIsReleaseCompatibilitySeal([
        { tag: "0183_mfa_policy_administration_compatibility" },
      ]),
    ).toBe(false);
    expect(latestMigrationIsReleaseCompatibilitySeal([])).toBe(false);
  });

  it("source-attests the exact V62 sealer before invoking it", async () => {
    const statements: { text: string; values: unknown[] }[] = [];
    const sql = vi.fn(
      async (strings: TemplateStringsArray, ...values: unknown[]) => {
        statements.push({ text: strings.join("?"), values });
        return statements.length === 1 ? [{ value: true }] : [];
      },
    );

    // @ts-expect-error The focused tagged-template double implements only the calls under test.
    await sealSchemaCompatibilityManifest(sql);

    expect(sql).toHaveBeenCalledTimes(3);
    expect(statements[0]?.text).toContain("procedure.provolatile = 'v'");
    expect(statements[0]?.text).toContain(
      "procedure.proargtypes = '20 20 25 25'::oidvector",
    );
    expect(statements[0]?.text).toContain(
      "procedure.proconfig IS NOT DISTINCT FROM",
    );
    expect(statements[0]?.values).toEqual([
      expectedSealSchemaCompatibilityManifestV62SourceHash,
    ]);
    expect(statements[1]?.text).toContain(
      "app.seal_schema_compatibility_manifest",
    );
    expect(statements[1]?.values).toEqual([
      expectedMigrationCount,
      expectedMigrationCreatedAt,
      expectedMigrationHash,
      expectedMigrationFingerprint,
    ]);
    expect(statements[2]).toEqual(statements[1]);
  });

  it("fails closed without invoking a drifted V62 sealer", async () => {
    const sql = vi.fn(async () => [{ value: false }]);

    await expect(
      // @ts-expect-error The focused tagged-template double implements only the attestation call.
      sealSchemaCompatibilityManifest(sql),
    ).rejects.toMatchObject({ code: "MIGRATION_SEALER_DIVERGED" });
    expect(sql).toHaveBeenCalledOnce();
  });

  it("preserves an operation failure when outer cleanup also fails", async () => {
    const operationError = new Error("operation failed");
    const cleanupError = new Error("cleanup failed");

    await expect(
      executeWithCleanup(
        async () => {
          throw operationError;
        },
        async () => {
          throw cleanupError;
        },
        "operation and cleanup both failed",
      ),
    ).rejects.toMatchObject({
      cause: cleanupError,
      errors: [operationError, cleanupError],
      message: "operation and cleanup both failed",
    });
  });

  it("preserves a thrown undefined before a restoration failure", async () => {
    const restorationError = new Error("restoration failed");
    const restore = vi.fn(async () => {
      throw restorationError;
    });

    await expect(
      executeWithCleanup(
        async () => {
          throw undefined;
        },
        restore,
        "operation and restoration both failed",
      ),
    ).rejects.toMatchObject({
      cause: restorationError,
      errors: [undefined, restorationError],
      message: "operation and restoration both failed",
    });
    expect(restore).toHaveBeenCalledOnce();
  });

  it("returns the operation result after successful cleanup", async () => {
    const cleanup = vi.fn(async () => undefined);

    await expect(
      executeWithCleanup(
        async () => "completed",
        cleanup,
        "operation and cleanup both failed",
      ),
    ).resolves.toBe("completed");
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("releases an incompatible reserved connection", async () => {
    const release = vi.fn();
    const connection = Object.assign(() => Promise.resolve([]), { release });
    Object.preventExtensions(connection);
    const client = {
      options: {},
      reserve: vi.fn().mockResolvedValue(connection),
    };

    // @ts-expect-error This deliberately incomplete client fails before any SQL executes.
    await expect(migrateSchema(client, migrationsRoot)).rejects.toMatchObject({
      code: "MIGRATION_CLIENT_INCOMPATIBLE",
    });
    expect(release).toHaveBeenCalledOnce();
  });

  it("preserves a migration error when advisory-lock release also fails", async () => {
    const release = vi.fn();
    const connection = Object.assign(
      vi.fn(async (strings: TemplateStringsArray) => {
        const statement = strings.join(" ");
        if (statement.includes("pg_try_advisory_lock")) {
          return [{ value: true }];
        }
        if (statement.includes("pg_advisory_unlock")) {
          return [{ value: false }];
        }
        if (statement.includes("pg_catalog.pg_database")) {
          return [
            {
              characterType: "C",
              collation: "C",
              encoding: "UTF8",
              migrationRoleSuperuser: true,
              serverVersionNumber: 180_006,
            },
          ];
        }
        return [];
      }),
      { begin: vi.fn(), options: {}, release },
    );
    const client = {
      options: {},
      reserve: vi.fn().mockResolvedValue(connection),
    };

    let caught: unknown;
    try {
      // @ts-expect-error This deliberately incomplete client fails before migration execution.
      await migrateSchema(client, resolve(migrationsRoot, "missing"));
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AggregateError);
    expect(caught).toMatchObject({
      errors: [
        { code: "MIGRATION_BUNDLE_DIVERGED" },
        { code: "MIGRATION_LOCK_LOST" },
      ],
    });
    expect(release).toHaveBeenCalledOnce();
  });

  it("commits Drizzle's migration work on the reserved session", async () => {
    const events: string[] = [];

    const result = await executeReservedTransaction(
      async (statement) => {
        events.push(statement);
      },
      async () => {
        events.push("migration");
        return "committed";
      },
    );

    expect(result).toBe("committed");
    expect(events).toEqual(["BEGIN", "migration", "COMMIT"]);
  });

  it("rolls back the reserved session and preserves migration failures", async () => {
    const events: string[] = [];
    const migrationError = new Error("migration failed");

    await expect(
      executeReservedTransaction(
        async (statement) => {
          events.push(statement);
        },
        async () => {
          events.push("migration");
          throw migrationError;
        },
      ),
    ).rejects.toBe(migrationError);
    expect(events).toEqual(["BEGIN", "migration", "ROLLBACK"]);
  });

  it("reports both migration and rollback failures", async () => {
    const migrationError = new Error("migration failed");
    const rollbackError = new Error("rollback failed");

    await expect(
      executeReservedTransaction(
        async (statement) => {
          if (statement === "ROLLBACK") {
            throw rollbackError;
          }
        },
        async () => {
          throw migrationError;
        },
      ),
    ).rejects.toMatchObject({
      errors: [migrationError, rollbackError],
    });
  });

  it("accepts only the exact packaged migration bundle", async () => {
    await expect(assertExactMigrationBundle(migrationsRoot)).resolves.toBe(
      undefined,
    );

    const scratchRoot = await mkdtemp(
      join(tmpdir(), "periapsis-migration-bundle-"),
    );
    try {
      await cp(migrationsRoot, scratchRoot, { recursive: true });
      await appendFile(
        resolve(scratchRoot, `${expectedMigrations.at(-1)!.tag}.sql`),
        "\n-- divergent packaged migration\n",
      );
      await expect(
        assertExactMigrationBundle(scratchRoot),
      ).rejects.toMatchObject({ code: "MIGRATION_BUNDLE_DIVERGED" });
    } finally {
      await rm(scratchRoot, { recursive: true, force: true });
    }
  }, 15_000);

  it("commits verified migration batches after every enum value addition", () => {
    const migrations = readMigrationFiles({ migrationsFolder: migrationsRoot });
    const batches = partitionMigrationsAtEnumCommitBoundaries(migrations);
    let lastIndex = -1;
    const boundaryTags = batches.map((batch) => {
      lastIndex += batch.length;
      return expectedMigrations[lastIndex]?.tag;
    });

    expect(boundaryTags).toEqual([
      "0051_complex_the_santerians",
      "0070_late_ozymandias",
      "0177_aspiring_mojo",
      "0184_platform_saml_direct_runtime",
      "0199_ticket_watcher_runtime",
      "0220_api_request_rate_limits",
      "0255_v62_compatibility",
    ]);
    expect(batches.flat()).toEqual(migrations);
  });

  it("stops on a failed migration batch and resumes from durable prefixes", async () => {
    const migrations = readMigrationFiles({ migrationsFolder: migrationsRoot });
    const batches = partitionMigrationsAtEnumCommitBoundaries(migrations);
    const durableBatches = new Set<number>();
    const failure = new Error("simulated enum-boundary successor failure");
    let failOnce = true;
    const migrateBatch = vi.fn(async (batch: (typeof batches)[number]) => {
      const index = batches.indexOf(batch);
      if (durableBatches.has(index)) {
        return;
      }
      if (index === 2 && failOnce) {
        failOnce = false;
        throw failure;
      }
      durableBatches.add(index);
    });

    await expect(executeMigrationBatches(batches, migrateBatch)).rejects.toBe(
      failure,
    );
    expect([...durableBatches]).toEqual([0, 1]);

    await executeMigrationBatches(batches, migrateBatch);
    expect([...durableBatches].toSorted((left, right) => left - right)).toEqual(
      batches.map((_, index) => index),
    );
    expect(migrateBatch).toHaveBeenCalledTimes(3 + batches.length);
  });

  it("accepts the empty journal and every exact manifest prefix", () => {
    const applied = appliedManifest();

    for (let count = 0; count <= applied.length; count += 1) {
      expect(() =>
        assertExactMigrationPrefix(applied.slice(0, count)),
      ).not.toThrow();
    }
  });

  it("normalizes only the exact attested V45 predecessor pair", () => {
    const legacy = legacyV45Manifest();
    const rawLegacyHashes = legacy.map((migration) => migration.hash);

    expect(() => assertExactMigrationPrefix(legacy)).not.toThrow();
    expect(() =>
      assertExactMigrationPrefix(
        [...legacy, ...appliedManifest().slice(legacy.length)],
        { convergenceAttested: true },
      ),
    ).not.toThrow();
    expect(legacy.map((migration) => migration.hash)).toEqual(rawLegacyHashes);

    const unsupported = structuredClone(legacy);
    unsupported[supportedLegacyV45MigrationReplacements[0].index] = {
      ...unsupported[supportedLegacyV45MigrationReplacements[0].index]!,
      hash: "a".repeat(64),
    };
    expect(() =>
      assertExactMigrationPrefix(unsupported, { convergenceAttested: true }),
    ).toThrowError(
      expect.objectContaining({ code: "MIGRATION_JOURNAL_DIVERGED" }),
    );

    const mixed = structuredClone(legacy);
    const canonicalReplacement = supportedLegacyV45MigrationReplacements[0];
    mixed[canonicalReplacement.index] = {
      createdAt: String(canonicalReplacement.createdAt),
      hash: canonicalReplacement.canonicalHash,
    };
    expect(() =>
      assertExactMigrationPrefix(mixed, { convergenceAttested: true }),
    ).toThrowError(
      expect.objectContaining({ code: "MIGRATION_JOURNAL_DIVERGED" }),
    );
  });

  it("allows V46 convergence evidence only before the V47 migration", () => {
    const applied = appliedManifest();
    const v47CompatibilityIndex = expectedMigrations.findIndex(
      (migration) => migration.tag === "0208_v47_compatibility",
    );

    expect(v47CompatibilityIndex).toBeGreaterThanOrEqual(
      supportedLegacyV45MigrationCount,
    );
    expect(
      isStrictlyPartialV46RestartJournal(
        applied.slice(0, supportedLegacyV45MigrationCount - 1),
      ),
    ).toBe(false);
    expect(
      isStrictlyPartialV46RestartJournal(
        applied.slice(0, supportedLegacyV45MigrationCount),
      ),
    ).toBe(true);
    expect(
      isStrictlyPartialV46RestartJournal(
        applied.slice(0, v47CompatibilityIndex),
      ),
    ).toBe(true);
    expect(
      isStrictlyPartialV46RestartJournal(
        applied.slice(0, v47CompatibilityIndex + 1),
      ),
    ).toBe(false);
    expect(isStrictlyPartialV46RestartJournal(applied)).toBe(false);
  });

  it("rejects an unsealed suffix after the legacy V45 predecessor", () => {
    const legacyWithSuffix = [
      ...legacyV45Manifest(),
      appliedManifest()[supportedLegacyV45MigrationCount]!,
    ];
    expect(() => assertExactMigrationPrefix(legacyWithSuffix)).toThrowError(
      expect.objectContaining({ code: "MIGRATION_JOURNAL_DIVERGED" }),
    );
  });

  it("rejects changed hashes, timestamps, ordering, duplicates, and newer rows", () => {
    const applied = appliedManifest();
    const middle = Math.floor(applied.length / 2);

    const changedHash = structuredClone(applied);
    changedHash[middle] = {
      ...changedHash[middle]!,
      hash: "0".repeat(64),
    };
    expectDivergence(changedHash);

    const changedTimestamp = structuredClone(applied);
    changedTimestamp[middle] = {
      ...changedTimestamp[middle]!,
      createdAt: String(Number(changedTimestamp[middle]!.createdAt) + 1),
    };
    expectDivergence(changedTimestamp);

    const reordered = structuredClone(applied);
    [reordered[middle], reordered[middle + 1]] = [
      reordered[middle + 1]!,
      reordered[middle]!,
    ];
    expectDivergence(reordered);

    expectDivergence([...applied, applied.at(-1)!]);
    expectDivergence([...applied, { createdAt: "999", hash: "f".repeat(64) }]);
  });
});
