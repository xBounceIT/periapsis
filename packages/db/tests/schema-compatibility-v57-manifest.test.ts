import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const metaRoot = resolve(migrationsRoot, "meta");
const repairTag = "0244_sla_authority_epochs";
const sealTag = "0245_v57_compatibility";
const expectedCount = 246;
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

describe("schema compatibility V57 manifest", () => {
  it("pins the exact complete 0000-0245 inventory and every packaged SQL byte hash", () => {
    const journal = readJournal().slice(0, expectedCount);
    const prefix = manifest.expectedMigrations.slice(0, expectedCount);
    expect(manifest.expectedMigrationCount).toBeGreaterThanOrEqual(
      expectedCount,
    );
    expect(prefix).toHaveLength(expectedCount);
    expect(journal).toHaveLength(expectedCount);
    expect(
      readdirSync(migrationsRoot)
        .filter((name) => name.endsWith(".sql"))
        .toSorted()
        .slice(0, expectedCount),
    ).toEqual(prefix.map((entry) => `${entry.tag}.sql`));
    expect(journal.slice(-2)).toEqual([
      {
        idx: 244,
        version: "7",
        when: 1_788_810_602_581,
        tag: repairTag,
        breakpoints: true,
      },
      {
        idx: 245,
        version: "7",
        when: 1_788_810_622_327,
        tag: sealTag,
        breakpoints: true,
      },
    ]);
    expect(prefix.slice(-2)).toEqual([
      {
        tag: repairTag,
        createdAt: 1_788_810_602_581,
        hash: "a7d38147407e13c8ec4570de62d941db3baa6536041ae509cf84c54271964652",
      },
      {
        tag: sealTag,
        createdAt: 1_788_810_622_327,
        hash: "2da4ce118db9d75b49cb5a1887510b8a8b6afacf74895f6bd9e62bda9caa4283",
      },
    ]);
    expect(journal.map(({ idx, when, tag }) => ({ idx, when, tag }))).toEqual(
      prefix.map((entry, idx) => ({
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
    for (const entry of prefix) {
      expect(
        sha256(readFileSync(resolve(migrationsRoot, `${entry.tag}.sql`))),
        entry.tag,
      ).toBe(entry.hash);
    }
    const latest = prefix.at(-1);
    expect(latest?.tag).toBe(sealTag);
    expect(latest?.createdAt).toBe(1_788_810_622_327);
    expect(latest?.hash).toBe(
      "2da4ce118db9d75b49cb5a1887510b8a8b6afacf74895f6bd9e62bda9caa4283",
    );
    expect(
      sha256(
        prefix.map((entry) => `${entry.createdAt}@${entry.hash}`).join(":"),
      ),
    ).toBe("8690084851ba1b39b6ca7c4eeb5bdb380385f2857d9156f75aa312af89de2a23");
  });

  it("keeps both custom migration snapshots structurally identical to V56", () => {
    const snapshots = ["0243", "0244", "0245"].map((version) => {
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

  it("source-attests every V57 root and refuses an unsealed zero dependency digest", () => {
    const seal = migration(sealTag);
    for (const [name, constant] of currentRoots) {
      expect(manifest).toHaveProperty(
        `expected${constant}V57SourceHash`,
        sha256(readRoutine(seal, `${name}_v57`).body),
      );
    }
    const sealer = readRoutine(seal, "seal_schema_compatibility_manifest");
    expect(manifest.expectedSealSchemaCompatibilityManifestV57SourceHash).toBe(
      sha256(sealer.body),
    );
    expect(sealer.body).toContain("p_expected_count IS DISTINCT FROM 246");
    expect(sealer.body).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788810622327",
    );
    expect(sealer.body).toContain("(:[0-9]+@[0-9a-f]{64}){245}$");
    const readiness = readRoutine(
      seal,
      "private_release_runtime_schema_readiness_v57",
    );
    const digest =
      /app\.private_release_runtime_dependency_surface_hash_v57\(\)<>\s*'([0-9a-f]{64})'/u.exec(
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

  it("preserves the complete catalog transcript except exact V56 retirement rows and four named self exclusions", () => {
    const predecessor = readRoutine(
      migration("0243_v56_compatibility"),
      "private_release_runtime_dependency_surface_hash_v56",
    ).body;
    const current = readRoutine(
      migration(sealTag),
      "private_release_runtime_dependency_surface_hash_v57",
    ).body;
    let normalized = current;
    for (const [name] of currentRoots) {
      normalized = normalized.replaceAll(
        `app.${name}_v57()`,
        `app.${name}_v56()`,
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
      "app.schema_compatibility_v57()",
      "app.private_release_runtime_dependency_surface_hash_v57()",
      "app.private_release_runtime_schema_readiness_v57()",
      "app.seal_schema_compatibility_manifest(bigint,bigint,text,text)",
    ]);
    expect(current).not.toMatch(/proname\s*(?:NOT LIKE|<>)/u);
  });

  it("normalizes only the fourteen exact V56 ACL pairs and three actual V56 root configuration states", () => {
    const predecessor = migration("0243_v56_compatibility");
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
          `app.${name}_v56()`,
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
      .slice(0, 244)
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":");
    expect(sha256(fingerprint)).toBe(
      "ed71b71b8a1155b258b9effe94ae2a679b8ec8334db0c45be6db8c8cd7a6a88c",
    );
    expect(newConfig.slice(oldConfig.length)).toEqual([
      [
        "app.schema_compatibility_v56()",
        ["UNSEALED", fingerprint, "RETIRED"].map((value) =>
          sha256(
            `{search_path=pg_catalog,app.schema_compatibility_fingerprint=${value}}`,
          ),
        ),
      ],
    ]);
    expect(seal).toMatch(
      /ALTER FUNCTION app\.schema_compatibility_v56\(\)\s+SET app\.schema_compatibility_fingerprint='RETIRED'/u,
    );
    expect(seal).not.toMatch(/DROP FUNCTION app\.[a-z_]+_v(?:49|5[012345])\(/u);
    const release = readRoutine(
      seal,
      "release_runtime_schema_readiness_v57",
    ).body;
    expect(release).toContain("SELECT count(*)=13 AND coalesce(bool_and(");
    for (let version = 44; version <= 55; version++) {
      expect(release).toContain(
        `'app.schema_compatibility_v${version}()'::regprocedure`,
      );
    }
    expect(manifest.expectedRetiredSchemaCompatibilityV56SourceHash).toBe(
      sha256(readRoutine(predecessor, "schema_compatibility_v56").body),
    );
  });
});
