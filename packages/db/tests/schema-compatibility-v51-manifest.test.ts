import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const metaRoot = resolve(migrationsRoot, "meta");
const repairTag = "0232_platform_saml_admission_provenance";
const sealTag = "0233_v51_compatibility";
const expectedCount = 234;
const wrapperName = "assert_auth_session_mfa_provenance_v1";
const planningName = "load_platform_saml_planning_state_v1";
const applyName = "apply_platform_saml_authentication_v1";
const sessionLookupName = "load_platform_saml_session_revalidation_v1";
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
const preservedHelpers = [
  {
    label: "authority",
    signature:
      "private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)",
    hash: "9ed40684de93fcfb7a92725f02a3201ef8e600ece5623a6597845a4c6b9e9afa",
  },
  {
    label: "load",
    signature: "load_tenant_platform_federated_session_revalidation_v1(jsonb)",
    hash: "e8e9d3a466b8bbc17160b5b41ca5f6ab2ee378aefb6290a6e41e41066b7db80d",
  },
  {
    label: "apply",
    signature: "apply_tenant_platform_federated_session_revalidation_v1(jsonb)",
    hash: "d2a81b178c1769e2018ac22281799731e96a9ac450c3bd7be2d2f965aa582227",
  },
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

function readDo(sql: string, name: string): string {
  const match = new RegExp(
    `DO \\$${name}\\$([\\s\\S]*?)\\$${name}\\$;`,
    "u",
  ).exec(sql);
  if (match?.[1] === undefined)
    throw new Error(`Missing assertion block ${name}`);
  return match[1];
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

function quiescenceConditions(sql: string): string[] {
  return [
    ...sql.matchAll(
      /IF EXISTS \((\s*WITH RECURSIVE writer_principal\(role_oid\) AS \([\s\S]*?)\n  \) THEN/gu,
    ),
  ].map((match) => match[1]!.replace(/\s+/gu, " ").trim());
}

function replaceOnce(value: string, from: string, to: string): string {
  expect(value.split(from), `Exact source occurrence: ${from}`).toHaveLength(2);
  return value.replace(from, to);
}

type SQLArgument = { start: number; end: number; raw: string };
type SQLFunctionArguments = {
  args: SQLArgument[];
  separators: number[];
  close: number;
};
type SQLObjectCall = SQLFunctionArguments & {
  start: number;
  open: number;
  keys: string[];
};

// Count SQL arguments while preserving quoted strings, comments, nested calls
// and array subscripts; commas in those constructs are not argument separators.
function quotedEnd(text: string, start: number): number {
  const quote = text[start];
  const escapeString =
    quote === "'" &&
    /[eE]/u.test(text[start - 1] ?? "") &&
    !/[a-zA-Z0-9_$]/u.test(text[start - 2] ?? "");
  for (let index = start + 1; index < text.length; index++) {
    if (escapeString && text[index] === "\\") {
      index++;
      continue;
    }
    if (text[index] !== quote) continue;
    if (text[index + 1] === quote) {
      index++;
      continue;
    }
    return index + 1;
  }
  throw new Error("Unterminated SQL quoted token");
}
function ignoredEnd(text: string, index: number): number {
  if (text[index] === "'" || text[index] === '"') return quotedEnd(text, index);
  if (text.startsWith("--", index)) {
    const end = text.indexOf("\n", index + 2);
    return end < 0 ? text.length : end + 1;
  }
  if (text.startsWith("/*", index)) {
    let depth = 1;
    for (let cursor = index + 2; cursor < text.length; cursor++) {
      if (text.startsWith("/*", cursor)) {
        depth++;
        cursor++;
      } else if (text.startsWith("*/", cursor)) {
        depth--;
        cursor++;
        if (depth === 0) return cursor + 1;
      }
    }
    throw new Error("Unterminated SQL block comment");
  }
  if (text[index] === "$") {
    const marker = /^\$(?:[a-zA-Z_][a-zA-Z_0-9]*)?\$/u.exec(
      text.slice(index),
    )?.[0];
    if (marker !== undefined) {
      const end = text.indexOf(marker, index + marker.length);
      assert(end >= 0, "Unterminated SQL dollar quote");
      return end + marker.length;
    }
  }
  return index;
}
function argumentsAt(text: string, open: number): SQLFunctionArguments {
  let depth = 0;
  let bracketDepth = 0;
  let start = open + 1;
  const args: SQLArgument[] = [];
  const separators: number[] = [];
  for (let index = start; index < text.length; index++) {
    const skipped = ignoredEnd(text, index);
    if (skipped !== index) {
      index = skipped - 1;
      continue;
    }
    const char = text[index];
    if (char === "(") depth++;
    else if (char === "[") bracketDepth++;
    else if (char === "]") bracketDepth--;
    else if (char === ")") {
      if (depth > 0) {
        depth--;
        continue;
      }
      assert.equal(bracketDepth, 0);
      args.push({ start, end: index, raw: text.slice(start, index) });
      return { args, separators, close: index };
    } else if (char === "," && depth === 0 && bracketDepth === 0) {
      args.push({ start, end: index, raw: text.slice(start, index) });
      separators.push(index);
      start = index + 1;
    }
    assert(depth >= 0 && bracketDepth >= 0, "Unbalanced SQL call");
  }
  throw new Error("Unterminated SQL function call");
}
function objectCalls(text: string): SQLObjectCall[] {
  const calls: SQLObjectCall[] = [];
  const marker = "jsonb_build_object";
  for (let index = 0; index < text.length; index++) {
    const skipped = ignoredEnd(text, index);
    if (skipped !== index) {
      index = skipped - 1;
      continue;
    }
    if (
      !text.startsWith(marker, index) ||
      /[a-zA-Z0-9_$]/u.test(text[index - 1] ?? "")
    )
      continue;
    let open = index + marker.length;
    while (/\s/u.test(text[open] ?? "")) open++;
    if (text[open] !== "(") continue;
    const parsed = argumentsAt(text, open);
    assert.equal(parsed.args.length % 2, 0, "Odd JSON object arguments");
    const keys = parsed.args
      .filter((_, argIndex) => argIndex % 2 === 0)
      .map((arg) => {
        const key = /^'((?:[^']|'')*)'$/u.exec(arg.raw.trim())?.[1];
        assert(key !== undefined, "Nonliteral JSON key");
        return key.replaceAll("''", "'");
      });
    assert.equal(new Set(keys).size, keys.length, "Duplicate JSON object keys");
    calls.push({ start: index, open, ...parsed, keys });
  }
  return calls;
}

describe("schema compatibility V51 manifest", () => {
  it("pins the exact complete 0000-0233 inventory and every packaged SQL byte hash", () => {
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
        idx: 232,
        version: "7",
        when: 1_788_695_882_058,
        tag: repairTag,
        breakpoints: true,
      },
      {
        idx: 233,
        version: "7",
        when: 1_788_695_899_106,
        tag: sealTag,
        breakpoints: true,
      },
    ]);
    expect(manifest.expectedMigrations.slice(-2)).toEqual([
      {
        tag: repairTag,
        createdAt: 1_788_695_882_058,
        hash: "b878811ea8fa5c85d7cbda2db68fd6603606655dbc1683fcc34c2238a6c79ce6",
      },
      {
        tag: sealTag,
        createdAt: 1_788_695_899_106,
        hash: "f7e8ed84278168bbf5989325bd86a5cbd9f69bc4489910aa544968f2326bfa64",
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
    expect(manifest.expectedMigrationCreatedAt).toBe(1_788_695_899_106);
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
      /private_release_runtime_dependency_surface_hash_v51\(\)<>\s*'([a-f0-9]{64})'/u.exec(
        migration(sealTag),
      )?.[1];
    assert(catalogDigest !== undefined);
    expect(catalogDigest).not.toBe("0".repeat(64));
    for (const name of [
      "schema-compatibility-v50-upgrade.ts",
      "schema-compatibility-v51-upgrade.ts",
      "schema-compatibility-v51-runtime.ts",
    ]) {
      const runtimeSource = readFileSync(
        resolve(repositoryRoot, "packages/db/tests/security", name),
        "utf8",
      );
      const pinned =
        /assert\.equal\(\s*(?:v51CatalogDigest|expectedCatalogDigest),\s*"([a-f0-9]{64})",\s*\)/u.exec(
          runtimeSource,
        )?.[1];
      expect(pinned, name).toBe(catalogDigest);
    }
  });

  it("keeps both custom migration snapshots structurally identical to V50", () => {
    const snapshots = ["0231", "0232", "0233"].map((version) => {
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

  it("source-attests every V51 root and refuses an unsealed zero dependency digest", () => {
    const seal = migration(sealTag);
    for (const [name, constant] of currentRoots) {
      expect(manifest).toHaveProperty(
        `expected${constant}V51SourceHash`,
        sha256(readRoutine(seal, `${name}_v51`).body),
      );
    }
    const sealer = readRoutine(seal, "seal_schema_compatibility_manifest");
    expect(manifest.expectedSealSchemaCompatibilityManifestV51SourceHash).toBe(
      sha256(sealer.body),
    );
    expect(sealer.body).toContain("p_expected_count IS DISTINCT FROM 234");
    expect(sealer.body).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788695899106",
    );
    expect(sealer.body).toContain("(:[0-9]+@[0-9a-f]{64}){233}$");
    const readiness = readRoutine(
      seal,
      "private_release_runtime_schema_readiness_v51",
    );
    const digest =
      /app\.private_release_runtime_dependency_surface_hash_v51\(\)<>\s*'([0-9a-f]{64})'/u.exec(
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

  it("preserves the complete catalog transcript except exact V50 retirement rows and four named self exclusions", () => {
    const predecessor = readRoutine(
      migration("0231_v50_compatibility"),
      "private_release_runtime_dependency_surface_hash_v50",
    ).body;
    const current = readRoutine(
      migration(sealTag),
      "private_release_runtime_dependency_surface_hash_v51",
    ).body;
    let normalized = current;
    for (const [name] of currentRoots) {
      normalized = normalized.replaceAll(
        `app.${name}_v51()`,
        `app.${name}_v50()`,
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
      "app.schema_compatibility_v51()",
      "app.private_release_runtime_dependency_surface_hash_v51()",
      "app.private_release_runtime_schema_readiness_v51()",
      "app.seal_schema_compatibility_manifest(bigint,bigint,text,text)",
    ]);
    expect(current).not.toMatch(/proname\s*(?:NOT LIKE|<>)/u);
  });

  it("normalizes only the twelve exact V50 ACL pairs and three actual V50 root configuration states", () => {
    const predecessor = migration("0231_v50_compatibility");
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
    ];
    const aclHash = (owner: string, grantees: string[]) =>
      sha256(
        [...new Set([owner, ...grantees])]
          .toSorted()
          .map((grantee) => `${owner}>${grantee}:EXECUTE:false`)
          .join(","),
      );
    expect(newACL.slice(oldACL.length)).toEqual(
      currentRoots.slice(0, 12).map(([name], index) => {
        const owner = index === 11 ? notifierOwner : migrator;
        return [
          `app.${name}_v50()`,
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
      .slice(0, 232)
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":");
    expect(sha256(fingerprint)).toBe(
      "2582058c69473465ab50b0c8e4aa8e447a841f7dea3bce94446c5563fe47902b",
    );
    expect(newConfig.slice(oldConfig.length)).toEqual([
      [
        "app.schema_compatibility_v50()",
        ["UNSEALED", fingerprint, "RETIRED"].map((value) =>
          sha256(
            `{search_path=pg_catalog,app.schema_compatibility_fingerprint=${value}}`,
          ),
        ),
      ],
    ]);
    expect(seal).toMatch(
      /ALTER FUNCTION app\.schema_compatibility_v50\(\)\s+SET app\.schema_compatibility_fingerprint='RETIRED'/u,
    );
    expect(seal).not.toMatch(/DROP FUNCTION app\.[a-z_]+_v(?:49|50)\(/u);
    const release = readRoutine(
      seal,
      "release_runtime_schema_readiness_v51",
    ).body;
    expect(release).toContain("SELECT count(*)=7 AND coalesce(bool_and(");
    for (let version = 44; version <= 50; version++) {
      expect(release).toContain(
        `'app.schema_compatibility_v${version}()'::regprocedure`,
      );
    }
    expect(manifest.expectedRetiredSchemaCompatibilityV50SourceHash).toBe(
      sha256(readRoutine(predecessor, "schema_compatibility_v50").body),
    );
  });

  it("requires inherited writer NOLOGIN and drained sessions before all four SAML function replacements", () => {
    const repair = migration(repairTag);
    const conditions = quiescenceConditions(repair);
    expect(conditions).toHaveLength(2);
    expect(conditions).toEqual(
      quiescenceConditions(migration("0165_platform_oidc_binding_runtime")),
    );
    const guardEnd = repair.indexOf("$v51_saml_provenance_quiesced_cutover$;");
    expect(guardEnd).toBeGreaterThan(0);
    for (const name of [
      wrapperName,
      planningName,
      applyName,
      sessionLookupName,
    ]) {
      expect(guardEnd).toBeLessThan(
        repair.indexOf(`CREATE OR REPLACE FUNCTION app.${name}(`),
      );
    }
    expect(
      [
        ...repair.matchAll(
          /CREATE(?: OR REPLACE)? FUNCTION app\.([a-z0-9_]+)\(/gu,
        ),
      ].map((match) => match[1]),
    ).toEqual([wrapperName, planningName, applyName, sessionLookupName]);
    expect(repair).not.toMatch(
      /\b(?:GRANT|REVOKE|ALTER FUNCTION|DROP FUNCTION|DISABLE TRIGGER)\b/u,
    );
  });

  it("preserves the final 0228 authority/load/apply implementations and owner-only ACLs before and after repair", () => {
    const repair = migration(repairTag);
    for (const helper of preservedHelpers) {
      for (const phase of ["predecessor", "successor"]) {
        const assertion = readDo(repair, `assert_v51_${helper.label}_${phase}`);
        expect(assertion).toContain(
          `'app.${helper.signature}'::pg_catalog.regprocedure`,
        );
        expect(assertion).toContain(`,'hex')='${helper.hash}'`);
        expect(assertion).toContain("owner.rolname='periapsis_migrator'");
        expect(assertion).toContain("routine.prosecdef");
        expect(assertion).toContain(
          "NOT routine.proisstrict AND NOT routine.proleakproof",
        );
        expect(assertion).toContain(
          "routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']",
        );
        expect(assertion).toContain("SELECT count(*)=1");
        expect(assertion).toContain(
          "acl.grantor=routine.proowner AND acl.grantee=routine.proowner",
        );
        expect(assertion).toContain(
          "acl.privilege_type='EXECUTE' AND NOT acl.is_grantable",
        );
      }
    }
  });

  it("changes only the SAML branch and two locals while preserving the entire prior LDAP/OIDC wrapper byte-for-byte", () => {
    const predecessor = readRoutine(
      migration("0210_ldap_denied_reconciliation"),
      wrapperName,
    );
    const repaired = readRoutine(migration(repairTag), wrapperName);
    expect(sha256(predecessor.body)).toBe(
      "af0dc8cb0913052a8688a614c5931f21c82b76cd8871ac89767d7e2f99ed65ec",
    );
    expect(sha256(repaired.body)).toBe(
      "71c6155df39b10327a247a04143e302f298996e930a7e5f852cacc8f646199e3",
    );
    expect(repaired.declaration).toBe(predecessor.declaration);
    const oldBodyStart =
      "  SELECT state AS mfa_state,session.authentication_method AS method\n";
    const branchStart = repaired.body.indexOf("BEGIN\n") + "BEGIN\n".length;
    const branchEnd = repaired.body.indexOf(oldBodyStart);
    expect(branchEnd).toBeGreaterThan(branchStart);
    const withoutBranch =
      repaired.body.slice(0, branchStart) + repaired.body.slice(branchEnd);
    expect(
      replaceOnce(
        withoutBranch,
        "  v_saml_count integer;\n  v_saml_revoked boolean;\n",
        "",
      ),
    ).toBe(predecessor.body);
    for (const [phase, routine] of [
      ["predecessor", predecessor],
      ["successor", repaired],
    ] as const) {
      const assertion = readDo(
        migration(repairTag),
        `assert_v51_wrapper_${phase}`,
      );
      expect(assertion).toContain(`,'hex')='${sha256(routine.body)}'`);
      expect(assertion).toContain("routine.provolatile='v'");
      expect(assertion).toContain("routine.pronargs=2");
      expect(assertion).toContain(
        "routine.prorettype='pg_catalog.void'::pg_catalog.regtype",
      );
      expect(assertion).toContain("SELECT count(*)=1");
      expect(assertion).toContain(
        "acl.grantor=routine.proowner AND acl.grantee=routine.proowner",
      );
    }
  });

  it("enforces raw exclusive typed SAML lineage and a structural historical graph before the live-only authority gate", () => {
    const body = readRoutine(migration(repairTag), wrapperName).body;
    const branch = body.slice(
      body.indexOf("BEGIN\n"),
      body.indexOf(
        "  SELECT state AS mfa_state,session.authentication_method AS method",
      ),
    );
    for (const coordinate of [
      "session.authentication_method='saml'",
      "provenance.authentication_method='saml'",
      "provider.kind::text='saml'",
      "policy.provider_kind::text='saml'",
      "identity.provider_kind::text='saml'",
    ])
      expect(branch).toContain(coordinate);
    expect(branch).toContain(
      "IF NOT FOUND OR v_state.primary_kind<>'tenant_platform_provider' THEN",
    );
    expect(branch).toContain("IF v_saml_count<>1 OR v_other_count<>0 THEN");
    for (const family of [
      "local_credential",
      "passkey",
      "federated",
      "ldap",
      "platform_oidc",
      "platform_saml",
    ]) {
      expect(branch).toContain(
        `(SELECT count(*) FROM ONLY public.auth_session_${family}_provenance\n        WHERE session_id=p_session_id)`,
      );
    }
    for (const relationship of [
      "session.active_tenant_id=provenance.tenant_id",
      "session.authentication_method=provenance.authentication_method",
      "provider.kind::text=provenance.authentication_method",
      "policy.provider_kind::text=provenance.authentication_method",
      "identity.provider_kind::text=provenance.authentication_method",
      "identity.user_id=provenance.user_id",
      "binding.platform_provider_id=provenance.platform_provider_id",
      "epoch.source_id=provenance.access_source_id",
      "source.kind='identity_provider_access'",
      "source.key=format('identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence)",
      "membership.user_id=provenance.user_id",
      "grant_record.platform_provider_id=provenance.platform_provider_id",
      "grant_record.external_identity_id=provenance.external_identity_id",
      "grant_record.membership_id=provenance.membership_id",
      "grant_record.user_id=provenance.user_id",
    ])
      expect(branch).toContain(relationship);
    for (const revision of ["external_identity", "provider", "binding"]) {
      expect(branch).toContain(
        `provenance.${revision}_revision BETWEEN 1 AND 2147483647`,
      );
    }
    for (const revision of [
      "security",
      "mapping",
      "authorization",
      "trust_rule",
    ]) {
      expect(branch).toContain(
        `provenance.${revision}_revision BETWEEN 1 AND 9007199254740991`,
      );
    }
    expect(branch).toContain(
      "provenance.subject_alias_key_version BETWEEN 1 AND 32767",
    );
    expect(branch).toMatch(
      /IF v_saml_count<>1 THEN[\s\S]*?ERRCODE='23514';\s*END IF;\s*SELECT session\.revoked_at IS NOT NULL INTO STRICT v_saml_revoked/u,
    );
    expect(branch).toMatch(
      /IF NOT v_saml_revoked AND NOT\s+app\.private_tenant_platform_session_authority_live_v1\(\s*p_tenant_id,p_session_id,transaction_timestamp\(\)\s*\) THEN[\s\S]*?ERRCODE='23514';\s*END IF;\s*RETURN;\s*END IF;/u,
    );
    expect(branch).not.toMatch(/\bUPDATE\b|\bDELETE\b|\bINSERT\b/u);
  });

  it("retains the deferred constraint path that checks typed provenance after revoke and logout", () => {
    const original = migration("0118_identity_mfa_security");
    const tenantPlatform = migration("0165_platform_oidc_binding_runtime");
    expect(original).toContain(
      "CREATE CONSTRAINT TRIGGER auth_session_mfa_states_provenance_v1\nAFTER INSERT OR UPDATE ON public.auth_session_mfa_states\nDEFERRABLE INITIALLY DEFERRED\nFOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();",
    );
    expect(tenantPlatform).toContain(
      "CREATE CONSTRAINT TRIGGER auth_session_tenant_platform_federated_provenance_parent_v1\nAFTER INSERT OR UPDATE OR DELETE\nON public.auth_session_tenant_platform_federated_provenance\nDEFERRABLE INITIALLY DEFERRED\nFOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();",
    );
    expect(
      readRoutine(original, "enforce_auth_session_mfa_provenance_v1").body,
    ).toContain(
      "PERFORM app.assert_auth_session_mfa_provenance_v1(\n    coalesce(NEW.tenant_id, OLD.tenant_id),\n    coalesce(NEW.session_id, OLD.session_id)\n  );",
    );
    for (const tag of [repairTag, sealTag]) {
      expect(migration(tag)).not.toMatch(
        /\b(?:CREATE|DROP|ALTER)\s+(?:CONSTRAINT\s+)?TRIGGER\b|SET\s+CONSTRAINTS/iu,
      );
    }
  });

  it("repairs exactly the two planning aliases without changing the declaration or any other source byte", () => {
    const original = readRoutine(
      migration("0184_platform_saml_direct_runtime"),
      planningName,
    );
    const conflictRepairTag = "0188_platform_saml_metadata_projection_fix";
    expect(
      sha256(readFileSync(resolve(migrationsRoot, `${conflictRepairTag}.sql`))),
    ).toBe("06330a7e20ca14d528bf3cf2834d77ff4382da767b98c130c795085074dc20c9");
    const conflictRepair = readDo(
      migration(conflictRepairTag),
      "repair_platform_saml_variable_conflicts_v1",
    );
    expect(conflictRepair).toContain(
      "'app.load_platform_saml_planning_state_v1(jsonb)'",
    );
    expect(conflictRepair).toContain(`'${sha256(original.body)}',true)`);
    expect(conflictRepair).toContain(
      "'AS $function$' || chr(10) || '#variable_conflict use_variable' ||",
    );
    const predecessor = {
      ...original,
      body: replaceOnce(
        original.body,
        "\nDECLARE\n",
        "\n#variable_conflict use_variable\nDECLARE\n",
      ),
    };
    expect(sha256(predecessor.body)).toBe(
      "7c278fe227151c76f58f8f08c8b302819da295f2663f54e3a0b4453c7e4901d2",
    );
    const repaired = readRoutine(migration(repairTag), planningName);
    expect(sha256(repaired.body)).toBe(
      "fa533493ecf308ff8ead14bf98c7fd8aa04f5d30947b8c8fe433140871412936",
    );
    let expected = replaceOnce(
      predecessor.body,
      "SELECT identity.*,identity_alias.key_version,identity_alias.subject_digest,",
      "SELECT identity.*,identity_alias.key_version AS subject_alias_key_version,identity_alias.subject_digest,",
    );
    expected = replaceOnce(
      expected,
      "'keyVersion',matched.key_version,",
      "'keyVersion',matched.subject_alias_key_version,",
    );
    expect(repaired.body).toBe(expected);
    expect(repaired.declaration.replace("CREATE OR REPLACE", "CREATE")).toBe(
      predecessor.declaration,
    );
    for (const [phase, routine] of [
      ["predecessor", predecessor],
      ["successor", repaired],
    ] as const) {
      const assertion = readDo(
        migration(repairTag),
        `assert_v51_saml_planning_${phase}`,
      );
      expect(assertion).toContain(`,'hex')='${sha256(routine.body)}'`);
      expect(assertion).toContain("routine.provolatile='s'");
      expect(assertion).toContain("routine.pronargs=1");
      expect(assertion).toContain(
        "routine.proargtypes='3802'::pg_catalog.oidvector",
      );
      expect(assertion).toContain(
        "routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype",
      );
      expect(assertion).toContain("SELECT count(*)=2");
      expect(assertion).toContain(
        "acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)",
      );
      expect(assertion).toContain(
        "acl.privilege_type='EXECUTE' AND NOT acl.is_grantable",
      );
    }
  });

  it("repairs only the alias creation clock in the effective 0184 + 0188 + 0228 apply", () => {
    const original = readRoutine(
      migration("0184_platform_saml_direct_runtime"),
      applyName,
    );
    expect(sha256(original.body)).toBe(
      "007e4feec0a6caf9995c5a6e0621eeb6566ae875fbfc604725c3f57c28fc9113",
    );
    const oldObservation =
      "last_observed_at=observed_at,last_observation_state='known',updated_at=observed_at";
    const newObservation =
      "last_observed_at=transaction_timestamp(),last_observation_state='known',updated_at=transaction_timestamp()";
    const observationRepair = readDo(
      migration("0188_platform_saml_metadata_projection_fix"),
      "repair_platform_saml_identity_observation_v1",
    );
    expect(observationRepair).toContain(
      "'app.apply_platform_saml_authentication_v1(jsonb)'::regprocedure",
    );
    expect(observationRepair).toContain(sha256(original.body));
    let effective = replaceOnce(original.body, oldObservation, newObservation);
    expect(sha256(effective)).toBe(
      "592517f0af2255b31457ab4f5a8b4103c12e8c8384d261733e9ddfe40bb238e6",
    );
    const logoutRepair = readDo(
      migration("0228_tenant_federation_administration"),
      "platform_saml_logout_configuration_apply_v1",
    );
    const oldLogout = /v_old text := \$old\$([\s\S]*?)\$old\$;/u.exec(
      logoutRepair,
    )?.[1];
    const newLogout = /v_new text := \$new\$([\s\S]*?)\$new\$;/u.exec(
      logoutRepair,
    )?.[1];
    if (oldLogout === undefined || newLogout === undefined) {
      throw new Error(
        "Missing the exact historical SAML logout configuration amendment",
      );
    }
    effective = replaceOnce(effective, oldLogout, newLogout);
    expect(sha256(effective)).toBe(
      "5d12a306bc233d65a032459fe26aef4797ef123e8e81723d34243c8d57295109",
    );
    const oldClock =
      "app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32),observed_at";
    const newClock =
      "app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32),transaction_timestamp()";
    const repaired = readRoutine(migration(repairTag), applyName);
    expect(repaired.body).toBe(replaceOnce(effective, oldClock, newClock));
    expect(replaceOnce(repaired.body, newClock, oldClock)).toBe(effective);
    expect(repaired.declaration.replace("CREATE OR REPLACE", "CREATE")).toBe(
      original.declaration,
    );
    expect(sha256(repaired.body)).toBe(
      "0a283b3ab1a520a5daff1f57ac5038ac0f014bc71ef847d41b7cdab8f94fa40a",
    );
    expect(repaired.body).toContain("#variable_conflict use_variable\nDECLARE");
    expect(repaired.body).toContain(newObservation);
    expect(repaired.body).toContain(newLogout);
    expect(repaired.body).toContain(
      "observed_at:=(p_command->>'appliedAt')::timestamptz;",
    );
    expect(repaired.body).toContain(
      "'returnPath',authority->>'returnPath','appliedAt',to_jsonb(observed_at)",
    );
  });

  it("source-attests the apply ABI and preserves the strict owner-only alias guard on both sides", () => {
    const repair = migration(repairTag);
    const guard = readRoutine(
      migration("0165_platform_oidc_binding_runtime"),
      "guard_platform_federated_alias_v1",
    );
    const guardHash =
      "002acc80cdaedd5198d01bb2370b709fa88ed19bde5b0fc2aa8bef9bbf4f2309";
    expect(sha256(guard.body)).toBe(guardHash);
    expect(guard.body).toContain(
      "NEW.created_at IS DISTINCT FROM transaction_timestamp()",
    );
    expect(repair).not.toMatch(
      /CREATE(?: OR REPLACE)? FUNCTION app\.guard_platform_federated_alias_v1\(/u,
    );
    for (const isGuard of [false, true]) {
      for (const phase of ["predecessor", "successor"]) {
        const label = isGuard ? "alias_guard" : "apply";
        const assertion = readDo(
          repair,
          "assert_v51_saml_" + label + "_" + phase,
        );
        const name = isGuard
          ? "guard_platform_federated_alias_v1()"
          : applyName + "(jsonb)";
        const hash = isGuard
          ? guardHash
          : phase === "predecessor"
            ? "5d12a306bc233d65a032459fe26aef4797ef123e8e81723d34243c8d57295109"
            : "0a283b3ab1a520a5daff1f57ac5038ac0f014bc71ef847d41b7cdab8f94fa40a";
        expect(assertion).toContain(
          "routine.oid='app." + name + "'::pg_catalog.regprocedure",
        );
        expect(assertion).toContain(",'hex')='" + hash + "'");
        for (const boundary of [
          "owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'",
          "routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef",
          "NOT routine.proisstrict AND NOT routine.proleakproof",
          "routine.proparallel='u'",
          "routine.pronargdefaults=0",
          "NOT routine.proretset AND routine.proallargtypes IS NULL",
          "routine.proargmodes IS NULL",
          "routine.provariadic=0 AND routine.prosupport=0",
          "routine.protrftypes IS NULL AND routine.proargdefaults IS NULL",
          "routine.probin IS NULL AND routine.prosqlbody IS NULL",
          "routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']",
          "acl.grantor=routine.proowner",
          "acl.privilege_type='EXECUTE' AND NOT acl.is_grantable",
        ])
          expect(assertion).toContain(boundary);
        expect(assertion).toContain(
          "routine.pronargs=" + (isGuard ? "0" : "1"),
        );
        expect(assertion).toContain(
          "routine.proargtypes='" +
            (isGuard ? "" : "3802") +
            "'::pg_catalog.oidvector",
        );
        expect(assertion).toContain(
          "routine.prorettype='pg_catalog." +
            (isGuard ? "trigger" : "jsonb") +
            "'::pg_catalog.regtype",
        );
        expect(assertion).toContain(
          isGuard
            ? "routine.proargnames IS NULL"
            : "routine.proargnames IS NOT DISTINCT FROM ARRAY['p_command']::pg_catalog.text[]",
        );
        expect(assertion).toContain("SELECT count(*)=" + (isGuard ? "1" : "2"));
        expect(assertion).toContain(
          isGuard
            ? "acl.grantee=routine.proowner"
            : "acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)",
        );
        const assertionStart = repair.indexOf(
          "DO $assert_v51_saml_" + label + "_" + phase + "$",
        );
        const applyStart = repair.indexOf(
          "CREATE OR REPLACE FUNCTION app." + applyName + "(",
        );
        if (phase === "predecessor")
          expect(assertionStart).toBeLessThan(applyStart);
        else expect(assertionStart).toBeGreaterThan(applyStart);
      }
    }
  });

  it("qualifies the requested session and reconstructs exact 0185 source after reversing the bounded JSON split", () => {
    const predecessorTag = "0185_platform_saml_direct_compatibility";
    expect(
      sha256(readFileSync(resolve(migrationsRoot, predecessorTag + ".sql"))),
    ).toBe("7fe4b0e8e30edf0ceae38f6368557369afd681e07d20d2d64271a2ff664fbbab");
    const predecessor = readRoutine(
      migration(predecessorTag),
      sessionLookupName,
    );
    const repaired = readRoutine(migration(repairTag), sessionLookupName);
    expect(sha256(predecessor.body)).toBe(
      "124dc03bc7c1d21f6c50db1f09daa7c68aefdce030d86c73994f516576421d5b",
    );
    const declarationBefore = "\nDECLARE session_id uuid;";
    const declarationAfter =
      "\n<<saml_session_lookup>>\nDECLARE session_id uuid;";
    const lookupBefore = "    WHERE session.id=session_id\n";
    const lookupAfter = "    WHERE session.id=saml_session_lookup.session_id\n";
    const qualified = replaceOnce(
      replaceOnce(predecessor.body, declarationBefore, declarationAfter),
      lookupBefore,
      lookupAfter,
    );
    expect(sha256(qualified)).toBe(
      "469f276d46439b1840f1b9aad693255ec41805a7903016fef03b06e8470be421",
    );
    const authority = objectCalls(qualified).find(
      (call) => call.args.length > 100,
    );
    assert(
      authority !== undefined,
      "Expected the original oversized authority object",
    );
    const splitKeyIndex = authority.keys.indexOf("providerEnabled");
    expect(splitKeyIndex).toBe(42);
    const separator = authority.separators[splitKeyIndex * 2 - 1];
    assert(separator !== undefined);
    const beforeExpression = qualified.slice(
      authority.start,
      authority.close + 1,
    );
    const afterExpression =
      "(" +
      qualified.slice(authority.start, separator) +
      ") || jsonb_build_object(" +
      qualified.slice(separator + 1, authority.close) +
      "))";
    expect(repaired.body).toBe(
      replaceOnce(qualified, beforeExpression, afterExpression),
    );
    const withoutSplit = replaceOnce(
      repaired.body,
      afterExpression,
      beforeExpression,
    );
    expect(
      replaceOnce(
        replaceOnce(withoutSplit, lookupAfter, lookupBefore),
        declarationAfter,
        declarationBefore,
      ),
    ).toBe(predecessor.body);
    expect(repaired.declaration.replace("CREATE OR REPLACE", "CREATE")).toBe(
      predecessor.declaration,
    );
    expect(sha256(repaired.body)).toBe(
      "b2c5075c04f6cf2238f710c273ebece45b9c00968f9c444e7e2eb1bac19d4077",
    );
    expect(predecessor.body).not.toContain("#variable_conflict");
    expect(repaired.body).not.toContain("#variable_conflict");
    expect(repaired.body).toContain(
      "session_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'sessionId');",
    );
    expect(repaired.body).toContain("ON state.session_id=session.id");
    expect(repaired.body).toContain("ON provenance.session_id=session.id");
    expect(repaired.body).not.toContain(lookupBefore);
  });

  it("preserves all 58 unique authority key/value expressions and bounds every loader object call to 100 arguments", () => {
    const predecessor = readRoutine(
      migration("0185_platform_saml_direct_compatibility"),
      sessionLookupName,
    );
    const repaired = readRoutine(migration(repairTag), sessionLookupName);
    const before = objectCalls(predecessor.body);
    const after = objectCalls(repaired.body);
    expect(before.map((call) => call.args.length)).toEqual([
      12, 44, 116, 10, 4, 4, 24, 16, 18, 6,
    ]);
    expect(after.map((call) => call.args.length)).toEqual([
      12, 44, 84, 32, 10, 4, 4, 24, 16, 18, 6,
    ]);
    expect(after.every((call) => call.args.length <= 100)).toBe(true);
    const authority = before[2]!;
    const first = after[2]!;
    const second = after[3]!;
    expect(authority.keys).toHaveLength(58);
    expect(new Set(authority.keys).size).toBe(58);
    expect(first.keys).toHaveLength(42);
    expect(second.keys).toHaveLength(16);
    expect(first.keys.at(-1)).toBe("currentPlatformFloorRevision");
    expect(second.keys[0]).toBe("providerEnabled");
    expect([...first.keys, ...second.keys]).toEqual(authority.keys);
    // Raw arguments include whitespace and each complete nested SQL expression.
    // This equality also preserves null/coalesce behavior and field order.
    expect([...first.args, ...second.args].map((arg) => arg.raw)).toEqual(
      authority.args.map((arg) => arg.raw),
    );
    for (const call of after) {
      expect(new Set(call.keys).size).toBe(call.keys.length);
    }
    for (let index = 3; index < before.length; index++) {
      expect(after[index + 1]!.args.map((arg) => arg.raw)).toEqual(
        before[index]!.args.map((arg) => arg.raw),
      );
    }
    expect(after[1]!.args.map((arg) => arg.raw)).toEqual(
      before[1]!.args.map((arg) => arg.raw),
    );
    expect(after[0]!.keys).toEqual(before[0]!.keys);
    // The root object differs only in its authority value, which is checked above.
    expect(
      after[0]!.args.filter((_, index) => index !== 3).map((arg) => arg.raw),
    ).toEqual(
      before[0]!.args.filter((_, index) => index !== 3).map((arg) => arg.raw),
    );
  });

  it("source-attests the stable session lookup ABI and exact owner/API execution grants", () => {
    const repair = migration(repairTag);
    for (const phase of ["predecessor", "successor"]) {
      const assertion = readDo(
        repair,
        "assert_v51_saml_session_lookup_" + phase,
      );
      const hash =
        phase === "predecessor"
          ? "124dc03bc7c1d21f6c50db1f09daa7c68aefdce030d86c73994f516576421d5b"
          : "b2c5075c04f6cf2238f710c273ebece45b9c00968f9c444e7e2eb1bac19d4077";
      expect(assertion).toContain(
        "routine.oid='app.load_platform_saml_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure",
      );
      expect(assertion).toContain(",'hex')='" + hash + "'");
      for (const boundary of [
        "owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'",
        "routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef",
        "NOT routine.proisstrict AND NOT routine.proleakproof",
        "routine.proparallel='u' AND routine.pronargs=1",
        "routine.pronargdefaults=0",
        "routine.proargtypes='3802'::pg_catalog.oidvector",
        "routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype",
        "NOT routine.proretset AND routine.proallargtypes IS NULL",
        "routine.proargmodes IS NULL",
        "routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]",
        "routine.provariadic=0 AND routine.prosupport=0",
        "routine.protrftypes IS NULL AND routine.proargdefaults IS NULL",
        "routine.probin IS NULL AND routine.prosqlbody IS NULL",
        "routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']",
        "SELECT count(*)=2",
        "acl.grantor=routine.proowner",
        "acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)",
        "acl.privilege_type='EXECUTE' AND NOT acl.is_grantable",
      ])
        expect(assertion).toContain(boundary);
      const assertionStart = repair.indexOf(
        "DO $assert_v51_saml_session_lookup_" + phase + "$",
      );
      const loaderStart = repair.indexOf(
        "CREATE OR REPLACE FUNCTION app." + sessionLookupName + "(",
      );
      if (phase === "predecessor")
        expect(assertionStart).toBeLessThan(loaderStart);
      else expect(assertionStart).toBeGreaterThan(loaderStart);
    }
  });

  it("wires the serving API, worker, notifier and canonical migration runner to V51", () => {
    for (const path of [
      "services/api/internal/postgres/health.go",
      "services/worker/internal/postgres/health.go",
    ]) {
      const serving = source(path);
      expect(serving, path).toContain("from app.schema_compatibility_v51()");
      expect(serving, path).toContain(
        "expectedSchemaCompatibilityV51SourceHash",
      );
      expect(serving, path).not.toContain(
        "from app.schema_compatibility_v50()",
      );
    }
    const notifier = source("services/notifier/src/postgres-repository.ts");
    expect(notifier).toContain(
      "FROM app.notification_dispatch_readiness_v51() AS readiness",
    );
    expect(notifier).toContain("expectedSchemaCompatibilityV51SourceHash");
    expect(notifier).not.toContain(
      "FROM app.notification_dispatch_readiness_v50() AS readiness",
    );
    const runner = source("packages/db/src/admin/schema-migration.ts");
    expect(runner).toContain(
      "expectedSealSchemaCompatibilityManifestV51SourceHash",
    );
    expect(runner).not.toContain(
      "expectedSealSchemaCompatibilityManifestV50SourceHash",
    );
  });

  it("keeps the selected non-upgrade runtime proofs anchored to the current V51 root", () => {
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
    expect(selectedScripts).toContain("test:security:schema-compatibility-v51");
    expect(selectedScripts).not.toContain(
      "test:security:schema-compatibility-v50",
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
      "tests/security/schema-compatibility-v51-runtime.ts",
    );
    for (const file of files) {
      const runtime = source(`packages/db/${file}`);
      const historicalCalls = [
        ...runtime.matchAll(/app\.schema_compatibility_v([0-9]+)\(\)/gu),
      ].filter((match) => Number(match[1]) < 51);
      if (historicalCalls.length === 0) continue;
      expect(runtime, file).toContain("app.schema_compatibility_v51()");
      expect(runtime, file).not.toMatch(
        /FROM\s+app\.schema_compatibility_v(?:[0-4]?[0-9]|50)\(\)\s+AS\s+current(?:_projection)?\b/iu,
      );
      expect(runtime, file).not.toMatch(
        /SELECT\s+applied_count[\s\S]{0,160}?FROM\s+app\.schema_compatibility_v(?:[0-4]?[0-9]|50)\(\)/iu,
      );
    }
  });
});
