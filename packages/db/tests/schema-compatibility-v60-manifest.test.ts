import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const metaRoot = resolve(migrationsRoot, "meta");
const repairTag = "0250_ticket_export_authority";
const sealTag = "0251_v60_compatibility";
const expectedCount = 252;
const currentRoots = [
  ["schema_compatibility", "SchemaCompatibility"],
  ["release_runtime_schema_readiness", "ReleaseRuntimeReadiness"],
  [
    "federated_authentication_schema_readiness",
    "FederatedAuthenticationReadiness",
  ],
  [
    "platform_oidc_direct_runtime_schema_readiness",
    "PlatformOIDCDirectRuntimeReadiness",
  ],
  [
    "platform_saml_direct_runtime_schema_readiness",
    "PlatformSAMLDirectRuntimeReadiness",
  ],
  [
    "platform_local_account_runtime_schema_readiness",
    "PlatformLocalAccountRuntimeReadiness",
  ],
  [
    "sla_trigger_action_runtime_schema_readiness",
    "SLATriggerActionRuntimeReadiness",
  ],
  [
    "sla_object_event_ingress_schema_readiness",
    "SLAObjectEventIngressReadiness",
  ],
  ["ticket_bulk_runtime_schema_readiness", "TicketBulkRuntimeReadiness"],
  ["ticket_export_runtime_schema_readiness", "TicketExportRuntimeReadiness"],
  [
    "ticket_metadata_runtime_schema_readiness",
    "TicketMetadataRuntimeReadiness",
  ],
  ["notification_dispatch_readiness", "NotificationDispatchReadiness"],
  ["private_schema_compatibility_journal", "PrivateSchemaCompatibilityJournal"],
  [
    "private_release_runtime_dependency_surface_hash",
    "PrivateReleaseRuntimeDependencySurfaceHash",
  ],
  [
    "private_release_runtime_schema_readiness",
    "PrivateReleaseRuntimeReadiness",
  ],
] as const;
type JournalEntry = {
  idx: number;
  when: number;
  tag: string;
  version: string;
  breakpoints: boolean;
};
type Routine = { declaration: string; body: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readJournal(): JournalEntry[] {
  const value: unknown = JSON.parse(
    readFileSync(resolve(metaRoot, "_journal.json"), "utf8"),
  );
  if (
    !isRecord(value) ||
    !Array.isArray(value.entries) ||
    !value.entries.every(
      (entry): entry is JournalEntry =>
        isRecord(entry) &&
        Number.isSafeInteger(entry.idx) &&
        Number.isSafeInteger(entry.when) &&
        typeof entry.tag === "string" &&
        typeof entry.version === "string" &&
        typeof entry.breakpoints === "boolean",
    )
  ) {
    throw new Error("Drizzle migration journal is malformed");
  }
  return value.entries;
}

function source(path: string): string {
  return readFileSync(resolve(repositoryRoot, path), "utf8").replaceAll(
    "\r\n",
    "\n",
  );
}

function migration(tag: string): string {
  // Preserve source bytes for PostgreSQL prosrc hashes.
  return readFileSync(resolve(migrationsRoot, `${tag}.sql`), "utf8");
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function readRoutine(sql: string, name: string): Routine {
  const definition = [
    ...sql.matchAll(
      new RegExp(
        `(CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\([\\s\\S]*?AS \\$function\\$)([\\s\\S]*?)\\$function\\$;`,
        "gu",
      ),
    ),
  ].at(-1);
  if (definition?.[1] === undefined || definition[2] === undefined) {
    throw new Error(`Expected exact app.${name} routine definition`);
  }
  return { declaration: definition[1], body: definition[2] };
}

function readCTE(sql: string, name: string): string {
  const match = new RegExp(
    `${name}\\(function_oid[^)]*\\) AS \\(([\\s\\S]*?)\\n\\),`,
    "u",
  ).exec(sql);
  if (match?.[1] === undefined)
    throw new Error(`Missing exact OID CTE ${name}`);
  return match[1];
}

function cteRows(sql: string, name: string): [string, string[]][] {
  return [
    ...readCTE(sql, name).matchAll(
      /\('([^']+)'::regprocedure,\s*ARRAY\[([^\]]+)\]::text\[\]\)/gu,
    ),
  ].map((match) => [
    match[1]!,
    [...match[2]!.matchAll(/'([0-9a-f]{64})'/gu)].map((hash) => hash[1]!),
  ]);
}

function replaceOnce(value: string, from: string, to: string): string {
  expect(value.split(from), `Exact source occurrence: ${from}`).toHaveLength(2);
  return value.replace(from, to);
}

describe("schema compatibility V60 manifest", () => {
  it("pins the exact complete 0000-0251 inventory and every packaged SQL byte hash", () => {
    const journal = readJournal();
    expect(manifest.expectedMigrationCount).toBe(expectedCount);
    expect(manifest.expectedMigrations).toHaveLength(expectedCount);
    expect(journal).toHaveLength(expectedCount);
    expect(
      readdirSync(migrationsRoot)
        .filter((name) => name.endsWith(".sql"))
        .toSorted(),
    ).toEqual(manifest.expectedMigrations.map((entry) => `${entry.tag}.sql`));
    expect(journal.slice(-2)).toEqual([
      {
        idx: 250,
        version: "7",
        when: 1_788_877_870_160,
        tag: repairTag,
        breakpoints: true,
      },
      {
        idx: 251,
        version: "7",
        when: 1_788_877_946_518,
        tag: sealTag,
        breakpoints: true,
      },
    ]);
    expect(manifest.expectedMigrations.slice(-2)).toEqual([
      {
        tag: repairTag,
        createdAt: 1_788_877_870_160,
        hash: "f98949780fd64f49e37a434c5b3df7491a00f8888942ede3d875848e3dfa8caa",
      },
      {
        tag: sealTag,
        createdAt: 1_788_877_946_518,
        hash: "252672500ce8e1a9f100203a8dfad41a40e36ff1476fb0ed30fdf8564a08399e",
      },
    ]);
    expect(journal.map(({ idx, when, tag }) => ({ idx, when, tag }))).toEqual(
      manifest.expectedMigrations.map((entry, idx) => ({
        idx,
        when: entry.createdAt,
        tag: entry.tag,
      })),
    );
    expect(
      journal.every(
        (entry, index) =>
          entry.idx === index &&
          (index === 0 || entry.when > journal[index - 1]!.when),
      ),
    ).toBe(true);
    for (const entry of manifest.expectedMigrations) {
      expect(
        sha256(readFileSync(resolve(migrationsRoot, `${entry.tag}.sql`))),
        entry.tag,
      ).toBe(entry.hash);
    }
    const latest = manifest.expectedMigrations.at(-1);
    expect(latest?.tag).toBe(sealTag);
    expect(manifest.expectedMigrationCreatedAt).toBe(1_788_877_946_518);
    expect(manifest.expectedMigrationHash).toBe(latest?.hash);
    expect(manifest.expectedMigrationFingerprint).toBe(
      manifest.expectedMigrations
        .map((entry) => `${entry.createdAt}@${entry.hash}`)
        .join(":"),
    );
    expect(manifest.expectedMigrationFingerprint.split(":")).toHaveLength(
      expectedCount,
    );
  });

  it("pins the same current catalog in both upgrade paths and the runtime suite", () => {
    const catalogDigest =
      /private_release_runtime_dependency_surface_hash_v60\(\)<>\s*'([a-f0-9]{64})'/u.exec(
        migration(sealTag),
      )?.[1];
    assert(catalogDigest !== undefined);
    expect(catalogDigest).not.toBe("0".repeat(64));
    for (const name of [
      "schema-compatibility-v59-upgrade.ts",
      "schema-compatibility-v60-upgrade.ts",
      "schema-compatibility-v60-runtime.ts",
    ]) {
      const runtimeSource = readFileSync(
        resolve(repositoryRoot, "packages/db/tests/security", name),
        "utf8",
      );
      const pinned =
        /assert\.equal\(\s*(?:v60CatalogDigest|expectedCatalogDigest),\s*"([a-f0-9]{64})",\s*\)/u.exec(
          runtimeSource,
        )?.[1];
      expect(pinned, name).toBe(catalogDigest);
    }
  });

  it("keeps both custom migration snapshots structurally identical to V59", () => {
    const snapshots = ["0249", "0250", "0251"].map((version) => {
      const value: unknown = JSON.parse(
        readFileSync(resolve(metaRoot, `${version}_snapshot.json`), "utf8"),
      );
      if (
        !isRecord(value) ||
        typeof value.id !== "string" ||
        typeof value.prevId !== "string"
      ) {
        throw new Error(`Malformed Drizzle ${version} snapshot`);
      }
      return value;
    });
    for (let index = 1; index < snapshots.length; index++) {
      const { id: oldId, prevId: _oldPrev, ...oldBody } = snapshots[index - 1]!;
      const { id: newId, prevId: newPrev, ...newBody } = snapshots[index]!;
      expect(newId).not.toBe(oldId);
      expect(newPrev).toBe(oldId);
      expect(newBody).toEqual(oldBody);
    }
  });

  it("source-attests every V60 root and refuses an unsealed zero dependency digest", () => {
    const seal = migration(sealTag);
    for (const [name, constant] of currentRoots) {
      expect(manifest).toHaveProperty(
        `expected${constant}V60SourceHash`,
        sha256(readRoutine(seal, `${name}_v60`).body),
      );
    }
    const sealer = readRoutine(seal, "seal_schema_compatibility_manifest");
    expect(manifest.expectedSealSchemaCompatibilityManifestV60SourceHash).toBe(
      sha256(sealer.body),
    );
    expect(sealer.body).toContain("p_expected_count IS DISTINCT FROM 252");
    expect(sealer.body).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788877946518",
    );
    expect(sealer.body).toContain("(:[0-9]+@[0-9a-f]{64}){251}$");
    const readiness = readRoutine(
      seal,
      "private_release_runtime_schema_readiness_v60",
    );
    const digest =
      /app\.private_release_runtime_dependency_surface_hash_v60\(\)<>\s*'([0-9a-f]{64})'/u.exec(
        readiness.body,
      )?.[1];
    expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(digest).not.toBe("0".repeat(64));
    expect(readiness.body).toContain(
      "current_setting('session_replication_role')<>'origin'",
    );
    expect(readiness.body).toContain("current_setting('row_security')<>'on'");
    expect(readiness.body).toContain(
      "app.private_v47_migration_convergence_schema_readiness_v1()",
    );
    expect(readiness.body).toContain(
      "app.alert_dfir_runtime_schema_readiness_v2()",
    );
  });

  it("preserves the complete catalog transcript except exact V59 retirement rows and four named self exclusions", () => {
    const predecessor = readRoutine(
      migration("0249_v59_compatibility"),
      "private_release_runtime_dependency_surface_hash_v59",
    ).body;
    const current = readRoutine(
      migration(sealTag),
      "private_release_runtime_dependency_surface_hash_v60",
    ).body;
    let normalized = current;
    for (const [name] of currentRoots) {
      normalized = normalized.replaceAll(
        `app.${name}_v60()`,
        `app.${name}_v59()`,
      );
    }
    for (const name of ["rotated_acl_function", "rotated_config_function"]) {
      normalized = replaceOnce(
        normalized,
        readCTE(normalized, name),
        readCTE(predecessor, name),
      );
    }
    // Whole-body equality also preserves V49's credential probe, every older
    // source normalization and catalog ABI/ACL/RLS/trigger/publication boundary.
    expect(normalized).toBe(predecessor);
    expect(readCTE(current, "historical_source_function")).toBe(
      readCTE(predecessor, "historical_source_function"),
    );
    expect(
      [
        ...readCTE(current, "self_excluded_function").matchAll(
          /pg_catalog\.to_regprocedure\('([^']+)'\)/gu,
        ),
      ].map((match) => match[1]),
    ).toEqual([
      "app.schema_compatibility_v60()",
      "app.private_release_runtime_dependency_surface_hash_v60()",
      "app.private_release_runtime_schema_readiness_v60()",
      "app.seal_schema_compatibility_manifest(bigint,bigint,text,text)",
    ]);
    expect(current).not.toMatch(/proname\s*(?:NOT LIKE|<>)/u);
  });

  it("normalizes only the fourteen exact V59 ACL pairs and three actual V59 root configuration states", () => {
    const predecessor = migration("0249_v59_compatibility");
    const seal = migration(sealTag);
    const oldACL = cteRows(predecessor, "rotated_acl_function");
    const newACL = cteRows(seal, "rotated_acl_function");
    expect(newACL.slice(0, oldACL.length)).toEqual(oldACL);
    const migrator = "periapsis_migrator";
    const notifierOwner = "periapsis_notification_readiness_owner";
    const grants: string[][] = [
      ["periapsis_api", "periapsis_worker"],
      ["periapsis_api", "periapsis_worker", notifierOwner],
      ["periapsis_api"],
      ["periapsis_api"],
      ["periapsis_api"],
      ["periapsis_api"],
      ["periapsis_worker"],
      ["periapsis_worker"],
      ["periapsis_api", "periapsis_worker"],
      ["periapsis_api", "periapsis_worker"],
      ["periapsis_api"],
      [migrator, "periapsis_notifier"],
      ["periapsis_api"],
      ["periapsis_worker"],
    ];
    const aclHash = (owner: string, grantees: string[]) =>
      sha256(
        [...new Set([owner, ...grantees])]
          .toSorted()
          .map((grantee) => `${owner}>${grantee}:EXECUTE:false`)
          .join(","),
      );
    expect(newACL.slice(oldACL.length)).toEqual(
      [
        ...currentRoots.slice(0, 12),
        ["api_runtime_schema_readiness"],
        ["worker_runtime_schema_readiness"],
      ].map(([name], index) => {
        const owner = index === 11 ? notifierOwner : migrator;
        return [
          `app.${name}_v59()`,
          [
            aclHash(owner, grants[index]!),
            aclHash(owner, index === 11 ? [migrator] : []),
          ],
        ];
      }),
    );
    const oldConfig = cteRows(predecessor, "rotated_config_function");
    const newConfig = cteRows(seal, "rotated_config_function");
    expect(newConfig.slice(0, oldConfig.length)).toEqual(oldConfig);
    const fingerprint = manifest.expectedMigrations
      .slice(0, 250)
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":");
    expect(sha256(fingerprint)).toBe(
      "f9fa6e746282a72bbc40aa091c656c48e95f08a2b75915a81bd4eacb685b31a1",
    );
    expect(newConfig.slice(oldConfig.length)).toEqual([
      [
        "app.schema_compatibility_v59()",
        ["UNSEALED", fingerprint, "RETIRED"].map((value) =>
          sha256(
            `{search_path=pg_catalog,app.schema_compatibility_fingerprint=${value}}`,
          ),
        ),
      ],
    ]);
    expect(seal).toMatch(
      /ALTER FUNCTION app\.schema_compatibility_v59\(\)\s+SET app\.schema_compatibility_fingerprint='RETIRED'/u,
    );
    expect(seal).not.toMatch(
      /DROP FUNCTION app\.[a-z_]+_v(?:49|5[012345678])\(/u,
    );
    const release = readRoutine(
      seal,
      "release_runtime_schema_readiness_v60",
    ).body;
    expect(release).toContain("SELECT count(*)=16 AND coalesce(bool_and(");
    for (let version = 44; version <= 58; version++) {
      expect(release).toContain(
        `'app.schema_compatibility_v${version}()'::regprocedure`,
      );
    }
    expect(manifest.expectedRetiredSchemaCompatibilityV59SourceHash).toBe(
      sha256(readRoutine(predecessor, "schema_compatibility_v59").body),
    );
  });

  it("wires the serving API, worker, notifier and canonical migration runner to V60", () => {
    expect(source("scripts/deploy/compose-runtime-provisioning.mjs")).toContain(
      "SELECT app.release_runtime_schema_readiness_v60() AS ready",
    );
    for (const path of [
      "services/api/internal/postgres/health.go",
      "services/worker/internal/postgres/health.go",
    ]) {
      const serving = source(path);
      expect(serving, path).toContain("from app.schema_compatibility_v60()");
      expect(serving, path).toContain(
        "expectedSchemaCompatibilityV60SourceHash",
      );
      expect(serving, path).not.toContain(
        "from app.schema_compatibility_v59()",
      );
    }
    const notifier = source("services/notifier/src/postgres-repository.ts");
    expect(notifier).toContain(
      "FROM app.notification_dispatch_readiness_v60() AS readiness",
    );
    expect(notifier).toContain("expectedSchemaCompatibilityV60SourceHash");
    expect(notifier).not.toContain(
      "FROM app.notification_dispatch_readiness_v59() AS readiness",
    );
    const runner = source("packages/db/src/admin/schema-migration.ts");
    expect(runner).toContain(
      "expectedSealSchemaCompatibilityManifestV60SourceHash",
    );
    expect(runner).not.toContain(
      "expectedSealSchemaCompatibilityManifestV59SourceHash",
    );
  });

  it("keeps the selected non-upgrade runtime proofs anchored to the current V60 root", () => {
    const databasePackage: unknown = JSON.parse(
      source("packages/db/package.json"),
    );
    if (!isRecord(databasePackage) || !isRecord(databasePackage.scripts)) {
      throw new Error("Database package scripts are malformed");
    }
    const scripts = databasePackage.scripts;
    const aggregate = scripts["test:security"];
    if (typeof aggregate !== "string") {
      throw new Error("Database security aggregate is missing");
    }
    const selectedScripts = aggregate.split(/\s*&&\s*/u).map((command) => {
      const match = /^corepack pnpm run (test:security:[a-z0-9-]+)$/u.exec(
        command,
      );
      if (match?.[1] === undefined) {
        throw new Error(
          "Database security aggregate has an unrecognized command",
        );
      }
      return match[1];
    });
    expect(selectedScripts).toContain("test:security:schema-compatibility-v60");
    expect(selectedScripts).not.toContain(
      "test:security:schema-compatibility-v59",
    );
    const files = selectedScripts
      .map((script) => {
        const command = scripts[script];
        if (typeof command !== "string") {
          throw new Error(
            `Selected database security script is missing: ${script}`,
          );
        }
        const match = /^tsx (tests\/security\/[a-z0-9-]+\.ts)$/u.exec(command);
        if (match?.[1] === undefined) {
          throw new Error(
            `Selected database security source is unrecognized: ${script}`,
          );
        }
        return match[1];
      })
      .filter((name) => !name.endsWith("-upgrade.ts"))
      .toSorted();
    expect(files).toContain(
      "tests/security/schema-compatibility-v60-runtime.ts",
    );
    for (const file of files) {
      const runtime = source(`packages/db/${file}`);
      const historicalCalls = [
        ...runtime.matchAll(/app\.schema_compatibility_v([0-9]+)\(\)/gu),
      ].filter((match) => Number(match[1]) < 55);
      if (historicalCalls.length === 0) continue;
      expect(runtime, file).toContain("app.schema_compatibility_v60()");
      expect(runtime, file).not.toMatch(
        /FROM\s+app\.schema_compatibility_v(?:[0-4]?[0-9]|5[012345678])\(\)\s+AS\s+current(?:_projection)?\b/iu,
      );
      expect(runtime, file).not.toMatch(
        /SELECT\s+applied_count[\s\S]{0,160}?FROM\s+app\.schema_compatibility_v(?:[0-4]?[0-9]|5[012345678])\(\)/iu,
      );
    }
  });
});
