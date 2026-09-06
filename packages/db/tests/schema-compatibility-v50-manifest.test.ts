import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const metaRoot = resolve(migrationsRoot, "meta");
const repairTag = "0230_session_logout_nullable_tenant";
const sealTag = "0231_v50_compatibility";
const expectedCount = 232;
const logoutName = "revoke_local_session_for_logout_v1";
const envelopeKeys = [
  "operationRunId",
  "sessionId",
  "userId",
  "tenantId",
  "tokenDigest",
  "requestDigest",
  "requestUpstream",
  "requestedAt",
  "continuationId",
  "continuationDigest",
  "continuationExpiresAt",
  "audit",
] as const;
const publicV50Roots = [
  "schema_compatibility_v50",
  "release_runtime_schema_readiness_v50",
  "federated_authentication_schema_readiness_v50",
  "platform_oidc_direct_runtime_schema_readiness_v50",
  "platform_saml_direct_runtime_schema_readiness_v50",
  "platform_local_account_runtime_schema_readiness_v50",
  "sla_trigger_action_runtime_schema_readiness_v50",
  "sla_object_event_ingress_schema_readiness_v50",
  "ticket_bulk_runtime_schema_readiness_v50",
  "ticket_export_runtime_schema_readiness_v50",
  "ticket_metadata_runtime_schema_readiness_v50",
  "notification_dispatch_readiness_v50",
] as const;

type JournalEntry = { idx: number; when: number; tag: string };
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
        typeof entry.tag === "string",
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
  return source(`packages/db/migrations/${tag}.sql`);
}

function readRoutine(sql: string, name: string): Routine {
  const definitions = [
    ...sql.matchAll(
      new RegExp(
        `(CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\([\\s\\S]*?AS \\$function\\$)([\\s\\S]*?)\\$function\\$;`,
        "gu",
      ),
    ),
  ];
  const definition = definitions.at(-1);
  if (definition?.[1] === undefined || definition[2] === undefined) {
    throw new Error(`Expected the exact app.${name} routine definition`);
  }
  return { declaration: definition[1], body: definition[2] };
}

function readLogoutEnvelope(body: string): {
  statement: string;
  allowed: string;
  required: string;
} {
  const match =
    /PERFORM app\.private_mfa_assert_json_object_v1\(\s*p_command,\s*ARRAY\[([\s\S]*?)\],\s*ARRAY\[([\s\S]*?)\],\s*32768\s*\);/u.exec(
      body,
    );
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new Error("Expected the bounded logout command envelope");
  }
  return { statement: match[0], allowed: match[1], required: match[2] };
}

function quotedKeys(array: string): string[] {
  return [...array.matchAll(/'([^']+)'/gu)].map((match) => match[1]!);
}

function quiescenceConditions(sql: string): string[] {
  return [
    ...sql.matchAll(
      /IF EXISTS \((\s*WITH RECURSIVE writer_principal\(role_oid\) AS \([\s\S]*?)\n  \) THEN/gu,
    ),
  ].map((match) => match[1]!.replace(/\s+/gu, " ").trim());
}

describe("schema compatibility V50 manifest", () => {
  it("pins the immutable complete 0000-0231 prefix and every historical SQL hash", () => {
    const journal = readJournal().slice(0, expectedCount);
    const prefix = manifest.expectedMigrations.slice(0, expectedCount);
    const files = readdirSync(migrationsRoot)
      .filter((name) => name.endsWith(".sql"))
      .toSorted()
      .slice(0, expectedCount);
    expect(manifest.expectedMigrationCount).toBeGreaterThanOrEqual(
      expectedCount,
    );
    expect(prefix).toHaveLength(expectedCount);
    expect(journal).toHaveLength(expectedCount);
    expect(files).toEqual(prefix.map((entry) => `${entry.tag}.sql`));
    expect(journal.slice(-2).map(({ idx, tag }) => ({ idx, tag }))).toEqual([
      { idx: 230, tag: repairTag },
      { idx: 231, tag: sealTag },
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
        createHash("sha256")
          .update(readFileSync(resolve(migrationsRoot, `${entry.tag}.sql`)))
          .digest("hex"),
        entry.tag,
      ).toBe(entry.hash);
    }
    expect(prefix.at(-1)).toEqual({
      tag: sealTag,
      createdAt: 1_788_650_095_675,
      hash: "807fc8896bfde860a40b9d7782288f49f0a72ab34ce1634c22d886fba4cdc0a2",
    });
    const fingerprint = prefix
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":");
    expect(fingerprint.split(":")).toHaveLength(expectedCount);
    expect(createHash("sha256").update(fingerprint).digest("hex")).toBe(
      "2582058c69473465ab50b0c8e4aa8e447a841f7dea3bce94446c5563fe47902b",
    );
  });

  it("keeps both custom migrations structurally identical to the V49 Drizzle snapshot", () => {
    const snapshots = ["0229", "0230", "0231"].map((version) => {
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
      const predecessor = snapshots[index - 1]!;
      const current = snapshots[index]!;
      const { id: oldID, prevId: _oldPrev, ...oldBody } = predecessor;
      const { id: newID, prevId: newPrev, ...newBody } = current;
      expect(newID).not.toBe(oldID);
      expect(newPrev).toBe(oldID);
      expect(newBody).toEqual(oldBody);
    }
  });

  it("changes only tenantId's required-non-null membership in the exact logout body", () => {
    const predecessor = readRoutine(
      migration("0228_tenant_federation_administration"),
      logoutName,
    );
    const repaired = readRoutine(migration(repairTag), logoutName);
    const oldEnvelope = readLogoutEnvelope(predecessor.body);
    const newEnvelope = readLogoutEnvelope(repaired.body);
    expect(quotedKeys(oldEnvelope.allowed)).toEqual(envelopeKeys);
    expect(quotedKeys(oldEnvelope.required)).toEqual(envelopeKeys);
    expect(quotedKeys(newEnvelope.allowed)).toEqual(envelopeKeys);
    expect(quotedKeys(newEnvelope.required)).toEqual(
      envelopeKeys.filter((key) => key !== "tenantId"),
    );
    // Equality outside this statement protects authority, revocation, replay,
    // audit and continuation logic from incidental changes in the forward fix.
    expect(
      repaired.body.replace(newEnvelope.statement, "<LOGOUT-ENVELOPE>"),
    ).toBe(
      predecessor.body.replace(oldEnvelope.statement, "<LOGOUT-ENVELOPE>"),
    );
    expect(repaired.declaration.replace("CREATE OR REPLACE", "CREATE")).toBe(
      predecessor.declaration.replace("CREATE OR REPLACE", "CREATE"),
    );
  });

  it("preserves the null platform branch while an omitted tenantId still reaches the null-denying UUID parser", () => {
    const repaired = readRoutine(migration(repairTag), logoutName);
    expect(repaired.body).toMatch(
      /IF jsonb_typeof\(p_command -> 'tenantId'\) = 'null' THEN\s*v_tenant_id := NULL;\s*ELSE\s*v_tenant_id := app\.private_mfa_require_uuidv7_v1\(\s*p_command ->> 'tenantId'\s*\);\s*END IF;/u,
    );
    const historical = migration("0119_identity_mfa_abi");
    const parser = readRoutine(historical, "private_mfa_require_uuidv7_v1");
    expect(parser.declaration).not.toMatch(/\bSTRICT\b/u);
    expect(parser.body).toContain("parsed := p_value::uuid;");
    expect(parser.body).toMatch(
      /IF parsed IS NULL OR NOT \(\(uuid_extract_version\(parsed\) = 7\) IS TRUE\) THEN\s*RAISE EXCEPTION 'invalid MFA identifier' USING ERRCODE = '22023';/u,
    );
    const envelope = readRoutine(
      historical,
      "private_mfa_assert_json_object_v1",
    );
    expect(envelope.body).toContain(
      "WHERE NOT (p_payload ? key.value) OR p_payload -> key.value = 'null'::jsonb",
    );
    expect(
      createHash("sha256")
        .update(
          readFileSync(resolve(migrationsRoot, "0119_identity_mfa_abi.sql")),
        )
        .digest("hex"),
    ).toBe("e76d07daf9c4fff3eb90a8671bc8975e7dc5af1e0e8e85945808b41370c1d0bb");
    for (const tag of [repairTag, sealTag]) {
      expect(migration(tag)).not.toMatch(
        /CREATE(?: OR REPLACE)? FUNCTION app\.private_mfa_(?:assert_json_object|require_uuidv7)_v1\(/u,
      );
    }
  });

  it("retains both transitive NOLOGIN and drained-session cutover conditions before replacing logout", () => {
    const repair = migration(repairTag);
    const conditions = quiescenceConditions(repair);
    expect(conditions).toHaveLength(2);
    expect(conditions).toEqual(
      quiescenceConditions(migration("0165_platform_oidc_binding_runtime")),
    );
    expect(repair.indexOf("WITH RECURSIVE writer_principal")).toBeLessThan(
      repair.indexOf(`FUNCTION app.${logoutName}(`),
    );
  });

  it("retains historical V50 roots, V49 retirement, and source-attested V50 sealer", () => {
    const seal = migration(sealTag);
    for (const name of [
      ...publicV50Roots,
      "private_schema_compatibility_journal_v50",
      "private_release_runtime_dependency_surface_hash_v50",
      "private_release_runtime_schema_readiness_v50",
    ]) {
      expect(readRoutine(seal, name).body.length, name).toBeGreaterThan(0);
    }
    expect(seal).toMatch(
      /ALTER FUNCTION app\.schema_compatibility_v49\(\)\s+SET app\.schema_compatibility_fingerprint='RETIRED'/u,
    );
    expect(seal).not.toMatch(/DROP FUNCTION app\.[a-z_]+_v49\(/u);
    const sealer = readRoutine(seal, "seal_schema_compatibility_manifest");
    expect(sealer.body).toContain("p_expected_count IS DISTINCT FROM 232");
    expect(sealer.body).toContain("(:[0-9]+@[0-9a-f]{64}){231}$");
    expect(seal).not.toContain("function_row.proname NOT LIKE '%\\_v50'");
    for (const constant of [
      "SchemaCompatibilityV50",
      "RetiredSchemaCompatibilityV49",
      "PrivateSchemaCompatibilityJournalV50",
      "PrivateReleaseRuntimeDependencySurfaceHashV50",
      "PrivateReleaseRuntimeReadinessV50",
      "ReleaseRuntimeReadinessV50",
      "NotificationDispatchReadinessV50",
      "SealSchemaCompatibilityManifestV50",
    ]) {
      expect(manifest).toHaveProperty(
        `expected${constant}SourceHash`,
        expect.stringMatching(/^[0-9a-f]{64}$/u),
      );
    }
  });
});
