import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migrationsRoot = resolve(repositoryRoot, "packages/db/migrations");
const metaRoot = resolve(migrationsRoot, "meta");
const v49MigrationCount = 230;
const v49MigrationIndex = v49MigrationCount - 1;
const v49Tag = "0229_v49_compatibility";
const v49CreatedAt = 1_788_520_217_531;
const v49MigrationHash =
  "a69775fe655ff7795b0aad4688925789d20d59d2bc9c06eb38e79f3a40cf7554";
const v49FingerprintHash =
  "74414ecac852f087d4aa256e14f943f58cf29e1d168fe96dac8d4532bc426a90";
const historicalRotatedRoots = [
  "schema_compatibility_v44",
  "schema_compatibility_v45",
  "schema_compatibility_v46",
  "schema_compatibility_v47",
  "mfa_policy_administration_schema_readiness_v4",
  "mfa_policy_administration_schema_readiness_v6",
  "platform_identity_runtime_schema_readiness_v10",
  "platform_identity_runtime_schema_readiness_v12",
  "platform_oidc_direct_runtime_schema_readiness_v6",
  "platform_oidc_direct_runtime_schema_readiness_v8",
  "platform_saml_direct_runtime_schema_readiness_v3",
  "platform_saml_direct_runtime_schema_readiness_v5",
  "platform_tenant_lifecycle_schema_readiness_v1",
  "platform_identity_runtime_schema_readiness_v13",
  "platform_oidc_direct_runtime_schema_readiness_v9",
  "platform_saml_direct_runtime_schema_readiness_v6",
  "mfa_policy_administration_schema_readiness_v7",
  "ticket_mutation_runtime_schema_readiness_v2",
  "sla_trigger_action_runtime_schema_readiness_v1",
  "sla_object_event_ingress_schema_readiness_v1",
  "platform_local_account_runtime_schema_readiness_v1",
  "ticket_bulk_runtime_schema_readiness_v2",
  "ticket_export_runtime_schema_readiness_v2",
  "alert_dfir_runtime_schema_readiness_v1",
  "ticket_metadata_runtime_schema_readiness_v1",
  "notification_dispatch_readiness_v4",
  "ticket_watcher_runtime_schema_readiness_v2",
  "contacts_portal_schema_readiness_v2",
  "notification_schema_readiness_v4",
  "tenant_ldap_interactive_auth_schema_readiness_v1",
  "ticket_comment_runtime_repair_schema_readiness_v1",
  "platform_global_ldap_runtime_schema_readiness_v1",
  "federated_authentication_schema_readiness_v1",
  "platform_oidc_direct_runtime_schema_readiness_v1",
  "platform_saml_direct_runtime_schema_readiness_v2",
] as const;
const retiredV48Roots = [
  "schema_compatibility_v48",
  "release_runtime_schema_readiness_v48",
  "federated_authentication_schema_readiness_v48",
  "platform_oidc_direct_runtime_schema_readiness_v48",
  "platform_saml_direct_runtime_schema_readiness_v48",
  "platform_local_account_runtime_schema_readiness_v48",
  "sla_trigger_action_runtime_schema_readiness_v48",
  "sla_object_event_ingress_schema_readiness_v48",
  "ticket_bulk_runtime_schema_readiness_v48",
  "ticket_export_runtime_schema_readiness_v48",
  "ticket_metadata_runtime_schema_readiness_v48",
] as const;
const historicalSourceNormalizationSignatures = [
  "app.private_mfa_policy_administration_schema_readiness_v5()",
  "app.private_platform_identity_runtime_schema_readiness_v11()",
  "app.private_platform_oidc_direct_runtime_schema_readiness_v7()",
  "app.private_platform_saml_direct_runtime_schema_readiness_v4()",
] as const;
const rotatedConfigSignatures = [
  "app.schema_compatibility_v44()",
  "app.schema_compatibility_v45()",
  "app.schema_compatibility_v46()",
  "app.schema_compatibility_v47()",
  "app.schema_compatibility_v48()",
] as const;
const selfExcludedV49Signatures = [
  "app.schema_compatibility_v49()",
  "app.private_release_runtime_dependency_surface_hash_v49()",
  "app.private_release_runtime_schema_readiness_v49()",
  "app.seal_schema_compatibility_manifest(bigint,bigint,text,text)",
] as const;

type JournalEntry = {
  idx: number;
  when: number;
  tag: string;
};

type Snapshot = {
  id: string;
  prevId: string;
  [key: string]: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return (
    isRecord(value) &&
    Number.isSafeInteger(value.idx) &&
    Number.isSafeInteger(value.when) &&
    typeof value.tag === "string"
  );
}

function readJournal(path: string): { entries: JournalEntry[] } {
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  const entries = isRecord(value) ? value.entries : undefined;
  if (!Array.isArray(entries) || !entries.every(isJournalEntry)) {
    throw new Error("Drizzle migration journal is malformed");
  }
  return { entries };
}

function readSnapshot(path: string): Snapshot {
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.prevId !== "string"
  ) {
    throw new Error("Drizzle migration snapshot is malformed");
  }
  return { ...value, id: value.id, prevId: value.prevId };
}

function readRegprocedureValues(migration: string, cteName: string): string[] {
  const escapedName = cteName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const block = new RegExp(
    `(?:WITH|,)\\s*${escapedName}\\(function_oid(?:,[^)]+)?\\) AS \\(\\s*VALUES([\\s\\S]*?)\\n\\s*\\),`,
    "u",
  ).exec(migration)?.[1];
  expect(block, `${cteName} must use exact routine OIDs`).toBeDefined();
  return Array.from(
    block?.matchAll(/\('([^']+)'::regprocedure(?:,|\))/gu) ?? [],
    (match) => match[1]!,
  );
}

function readToRegprocedureValues(
  migration: string,
  cteName: string,
): string[] {
  const escapedName = cteName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const block = new RegExp(
    `(?:WITH|,)\\s*${escapedName}\\(function_oid\\) AS \\(\\s*VALUES([\\s\\S]*?)\\n\\s*\\),`,
    "u",
  ).exec(migration)?.[1];
  expect(block, `${cteName} must resolve exact routine OIDs`).toBeDefined();
  return Array.from(
    block?.matchAll(/pg_catalog\.to_regprocedure\('([^']+)'\)/gu) ?? [],
    (match) => match[1]!,
  );
}

describe("schema compatibility V49 manifest", () => {
  it("pins the immutable complete 0000-0229 prefix inside the current bundle", () => {
    const journal = readJournal(resolve(metaRoot, "_journal.json"));
    const sqlFiles = readdirSync(migrationsRoot)
      .filter((name) => name.endsWith(".sql"))
      .toSorted();
    const migrationPath = resolve(migrationsRoot, `${v49Tag}.sql`);

    const expectedPrefix = manifest.expectedMigrations.slice(
      0,
      v49MigrationCount,
    );
    const journalPrefix = journal.entries.slice(0, v49MigrationCount);
    const sqlPrefix = sqlFiles.slice(0, v49MigrationCount);
    expect(manifest.expectedMigrationCount).toBeGreaterThanOrEqual(
      v49MigrationCount,
    );
    expect(expectedPrefix).toHaveLength(v49MigrationCount);
    expect(journalPrefix).toHaveLength(v49MigrationCount);
    expect(sqlPrefix).toHaveLength(v49MigrationCount);
    expect(journalPrefix.at(-1)).toMatchObject({
      idx: v49MigrationIndex,
      tag: v49Tag,
      when: v49CreatedAt,
    });
    expect(expectedPrefix.at(-1)).toEqual({
      tag: v49Tag,
      createdAt: v49CreatedAt,
      hash: v49MigrationHash,
    });
    expect(
      journalPrefix.every(
        (entry, index) =>
          entry.idx === index &&
          (index === 0 || entry.when > journalPrefix[index - 1]!.when),
      ),
    ).toBe(true);
    expect(sqlPrefix).toEqual(
      expectedPrefix.map((migration) => `${migration.tag}.sql`),
    );
    expect(
      journalPrefix.map(({ idx, when, tag }) => ({ idx, when, tag })),
    ).toEqual(
      expectedPrefix.map((migration, idx) => ({
        idx,
        when: migration.createdAt,
        tag: migration.tag,
      })),
    );
    expect(existsSync(migrationPath)).toBe(true);
    if (!existsSync(migrationPath)) return;

    const migrationHash = createHash("sha256")
      .update(readFileSync(migrationPath))
      .digest("hex");
    const fingerprint = expectedPrefix
      .map((migration) => `${migration.createdAt}@${migration.hash}`)
      .join(":");
    expect(migrationHash).toBe(v49MigrationHash);
    expect(fingerprint.split(":")).toHaveLength(v49MigrationCount);
    expect(createHash("sha256").update(fingerprint).digest("hex")).toBe(
      v49FingerprintHash,
    );
  });

  it("retains a zero-structure-diff Drizzle snapshot for the custom seal", () => {
    const predecessorPath = resolve(metaRoot, "0228_snapshot.json");
    const sealPath = resolve(metaRoot, "0229_snapshot.json");
    expect(existsSync(predecessorPath)).toBe(true);
    expect(existsSync(sealPath)).toBe(true);
    if (!existsSync(predecessorPath) || !existsSync(sealPath)) return;

    const predecessor = readSnapshot(predecessorPath);
    const seal = readSnapshot(sealPath);
    const {
      id: predecessorId,
      prevId: _predecessorPrev,
      ...predecessorBody
    } = predecessor;
    const { id: sealId, prevId: sealPrev, ...sealBody } = seal;

    expect(sealId).not.toBe(predecessorId);
    expect(sealPrev).toBe(predecessorId);
    expect(sealBody).toEqual(predecessorBody);
  });

  it("defines and source-attests the V49 roots while retiring V48", () => {
    const migrationPath = resolve(migrationsRoot, `${v49Tag}.sql`);
    expect(existsSync(migrationPath)).toBe(true);
    if (!existsSync(migrationPath)) return;

    const migration = readFileSync(migrationPath, "utf8");
    const generator = readFileSync(
      resolve(repositoryRoot, "scripts/generate-schema-compatibility.mjs"),
      "utf8",
    );
    for (const functionName of [
      "private_schema_compatibility_journal_v49",
      "schema_compatibility_v49",
      "private_release_runtime_dependency_surface_hash_v49",
      "private_release_runtime_schema_readiness_v49",
      "release_runtime_schema_readiness_v49",
      "federated_authentication_schema_readiness_v49",
      "platform_oidc_direct_runtime_schema_readiness_v49",
      "platform_saml_direct_runtime_schema_readiness_v49",
      "platform_local_account_runtime_schema_readiness_v49",
      "sla_trigger_action_runtime_schema_readiness_v49",
      "sla_object_event_ingress_schema_readiness_v49",
      "ticket_bulk_runtime_schema_readiness_v49",
      "ticket_export_runtime_schema_readiness_v49",
      "ticket_metadata_runtime_schema_readiness_v49",
      "notification_dispatch_readiness_v49",
    ]) {
      expect(migration).toContain(`FUNCTION app.${functionName}()`);
    }
    expect(migration).toContain(
      "CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(",
    );
    expect(migration).toContain(
      "CREATE FUNCTION app.private_runtime_login_credential_state_v49()",
    );
    expect(migration).toContain("JOIN pg_catalog.pg_authid AS credential");
    expect(migration).toContain(
      "credential.rolpassword LIKE 'SCRAM-SHA-256$%'",
    );
    expect(migration).toContain("owner.rolsuper");
    expect(migration).toContain("'<V49-SEALER-SUPERUSER>'");
    expect(migration).toContain(
      "'app.private_runtime_login_credential_state_v49()'::regprocedure",
    );
    expect(migration).toContain(
      "'9b37955d6346860e7759f0ecdf4ac6113c5e0887d7fa95b072228e35d7351a97'",
    );
    expect(migration).toContain(
      "'f064d2874523976d14529a4ac239f4a6c892b6e50b212c6b126c90b8a5d2d022'",
    );
    expect(migration).toContain(
      "pg_catalog.sha256(pg_catalog.uuid_send(pg_catalog.gen_random_uuid()) || pg_catalog.uuid_send(pg_catalog.gen_random_uuid()))",
    );
    expect(migration).toContain(
      "ALTER FUNCTION app.schema_compatibility_v48()\n      SET app.schema_compatibility_fingerprint='RETIRED'",
    );
    expect(migration).not.toContain(
      "function_row.proname NOT LIKE '%\\_v49' ESCAPE '\\'",
    );
    expect(migration).not.toContain(
      "function_row.proname<>'seal_schema_compatibility_manifest'",
    );
    expect(migration).toContain("app.alert_dfir_runtime_schema_readiness_v2()");
    expect(migration).toContain("p_expected_count IS DISTINCT FROM 230");
    expect(migration).toContain("(:[0-9]+@[0-9a-f]{64}){229}$");

    expect(readRegprocedureValues(migration, "rotated_acl_function")).toEqual(
      [...historicalRotatedRoots, ...retiredV48Roots].map(
        (functionName) => `app.${functionName}()`,
      ),
    );
    expect(
      readRegprocedureValues(migration, "historical_source_function"),
    ).toEqual(historicalSourceNormalizationSignatures);
    expect(
      readRegprocedureValues(migration, "rotated_config_function"),
    ).toEqual(rotatedConfigSignatures);
    expect(
      readToRegprocedureValues(migration, "self_excluded_function"),
    ).toEqual(selfExcludedV49Signatures);
    expect(migration).toContain(
      "LEFT JOIN rotated_acl_function AS rotated_acl ON rotated_acl.function_oid=function_row.oid",
    );
    expect(migration).toContain(
      "LEFT JOIN historical_source_function AS historical_source ON historical_source.function_oid=function_row.oid",
    );
    expect(migration).toContain(
      "LEFT JOIN rotated_config_function AS rotated_config ON rotated_config.function_oid=function_row.oid",
    );
    expect(migration).toContain(
      "LEFT JOIN self_excluded_function AS self_excluded ON self_excluded.function_oid=function_row.oid",
    );
    expect(migration).toContain("=ANY(rotated_acl.acl_hashes)");
    expect(migration).toContain("=ANY(rotated_config.config_hashes)");
    expect(migration).toContain("=ANY(historical_source.source_hashes)");
    expect(migration).toContain(
      "ELSE pg_catalog.pg_get_functiondef(function_row.oid) END",
    );
    expect(migration).toContain("function_row.prosupport=0");
    expect(migration).toContain("function_row.protrftypes");
    expect(migration).not.toContain("function_row.provariadic::text");
    expect(migration).toContain(
      "pg_catalog.format_type(function_row.provariadic,NULL)",
    );
    expect(migration).toContain("AND 1=(\n          SELECT count(*)");
    expect(migration).not.toContain("grantor.rolname='postgres'");
    expect(
      migration.match(/AS grantor ON grantor\.oid=acl\.grantor/gu),
    ).toHaveLength(8);
    expect(migration).not.toContain("attribute.attacl::text");
    expect(migration).toContain(
      "FROM pg_catalog.aclexplode(attribute.attacl) AS acl",
    );
    expect(migration).toContain("membership.inherit_option::text");
    expect(migration).toContain("membership.set_option::text");
    expect(migration).toContain("role.rolvaliduntil AT TIME ZONE 'UTC'");
    expect(migration).toContain("role.rolvaliduntil='infinity'::timestamptz");
    expect(migration).toContain(
      "credential.credential_state IN ('absent','scram')",
    );
    expect(migration).toContain(
      "role.rolcanlogin AND credential.credential_state='scram'",
    );
    expect(migration).toContain(
      "SELECT 'type',namespace.nspname || '.' || type_row.typname",
    );
    expect(migration).toContain("pg_catalog.acldefault('T',type_row.typowner)");
    expect(migration).toContain(
      "SELECT 'rewrite',namespace.nspname || '.' || relation.relname",
    );
    expect(migration).toContain("pg_catalog.pg_get_ruledef(rewrite.oid,true)");
    expect(migration).toContain(
      "constraint_trigger.tgconstraint=constraint_row.oid",
    );
    expect(migration).toContain("relation.relispartition::text");
    expect(migration).toContain("relation.relhassubclass::text");
    expect(migration).toContain("SELECT 'inheritance',");
    expect(migration).toContain("FROM pg_catalog.pg_inherits AS inheritance");
    expect(migration).toContain("inheritance.inhdetachpending::text");
    expect(migration).toContain("SELECT 'cast',");
    expect(migration).toContain("cast_row.castcontext::text");
    expect(migration).toContain("cast_row.castmethod::text");
    expect(migration).toContain("SELECT 'operator',");
    expect(migration).toContain("FROM pg_catalog.pg_operator AS operator");
    expect(migration).toContain("operator.oprcanmerge::text");
    expect(migration).toContain("operator.oprcanhash::text");
    expect(migration).toContain("operator.oprcode");
    expect(migration).toContain("operator.oprcom");
    expect(migration).toContain("operator.oprnegate");
    expect(migration).toContain("operator.oprrest");
    expect(migration).toContain("operator.oprjoin");
    expect(migration).toContain("SELECT 'domain_constraint',");
    expect(migration).toContain("WHERE constraint_row.conrelid=0");
    expect(migration).toContain("SELECT 'event_trigger',event_trigger.evtname");
    expect(migration).toContain("FROM pg_catalog.pg_event_trigger");
    expect(migration).toContain("event_trigger.evttags IS NULL");
    expect(migration).toContain(
      "WHERE namespace.nspname IN ('public','app')\n    AND self_excluded.function_oid IS NULL",
    );
    expect(migration).toContain("SELECT 'runtime_setting',setting.name");
    expect(migration).toContain("current_setting('session_replication_role')");
    expect(migration).toContain("current_setting('row_security')");
    expect(migration).toContain(
      "OR current_setting('session_replication_role')<>'origin'",
    );
    expect(migration).toContain("OR current_setting('row_security')<>'on'");
    expect(migration).toContain("SELECT 'publication',publication.pubname");
    expect(migration).toContain("publication.puballtables::text");
    expect(migration).toContain("publication.pubgencols::text");
    expect(migration).toContain("SELECT 'publication_namespace',");
    expect(migration).toContain("FROM pg_catalog.pg_publication_namespace");
    expect(migration).toContain("SELECT 'publication_relation',");
    expect(migration).toContain("publication_relation.prattrs::smallint[]");
    expect(migration).toContain("publication_relation.prqual");
    expect(migration).toContain("SELECT 'subscription',subscription.subname");
    expect(migration).toContain("FROM pg_catalog.pg_subscription");
    expect(migration).toContain("subscription.subenabled::text");
    expect(migration).toContain("subscription.subpublications");
    expect(migration).not.toContain("subscription.subconninfo");
    expect(
      migration.match(/nspname IN \('public','app'\)/gu)?.length,
    ).toBeGreaterThanOrEqual(10);
    expect(migration).toContain("SELECT 'database'::text,'current'::text");
    expect(migration).toContain("database.datcollate,database.datctype");
    expect(migration).toContain("database.datallowconn::text");
    expect(migration).toContain("database.datconnlimit::text");
    expect(migration).toContain("'<DATABASE-OWNER-SUPERUSER>'");
    expect(migration).toContain("database_owner.rolsuper");
    expect(migration).toContain(
      "database_owner.rolname NOT LIKE 'periapsis\\_%'",
    );
    expect(migration).toContain("SELECT 'parameter_acl',parameter.parname");
    expect(migration).toContain("FROM pg_catalog.pg_parameter_acl");
    expect(migration).toContain("'<PARAMETER-ADMIN-SUPERUSER>'");
    expect(migration).toContain(
      "relevant_grantee.rolname LIKE 'periapsis\\_%'",
    );
    expect(migration).toContain(
      "relevant_grantor.rolname LIKE 'periapsis\\_%'",
    );
    expect(migration).toContain("SELECT 'database_setting',");
    expect(migration).toContain(
      "CASE WHEN setting.setdatabase=0 THEN '*' ELSE 'current' END",
    );
    expect(migration).toContain("setting.setrole=0");
    expect(migration).toContain(
      "schema_safe := app.release_runtime_schema_readiness_v49()",
    );

    for (const functionName of retiredV48Roots) {
      expect(migration).toMatch(
        new RegExp(
          `REVOKE ALL ON FUNCTION[\\s\\S]*?app\\.${functionName}\\(\\)`,
          "u",
        ),
      );
    }
    expect(generator).toContain('constant: "SchemaCompatibilityV49"');
    expect(generator).toContain('constant: "RetiredSchemaCompatibilityV48"');
    expect(generator).toContain(
      'constant: "SealSchemaCompatibilityManifestV49"',
    );
    expect(generator).toContain('constant: "NotificationDispatchReadinessV49"');
    expect(generator).toContain(
      '"services/notifier/src/schema-compatibility.gen.ts"',
    );
    expect(generator).toContain(
      '"PrivateReleaseRuntimeDependencySurfaceHashV49"',
    );

    for (const constant of [
      "expectedSchemaCompatibilityV49SourceHash",
      "expectedRetiredSchemaCompatibilityV48SourceHash",
      "expectedPrivateSchemaCompatibilityJournalV49SourceHash",
      "expectedPrivateReleaseRuntimeDependencySurfaceHashV49SourceHash",
      "expectedPrivateReleaseRuntimeReadinessV49SourceHash",
      "expectedReleaseRuntimeReadinessV49SourceHash",
      "expectedNotificationDispatchReadinessV49SourceHash",
      "expectedSealSchemaCompatibilityManifestV49SourceHash",
    ]) {
      expect(manifest).toHaveProperty(
        constant,
        expect.stringMatching(/^[0-9a-f]{64}$/u),
      );
    }
  });
});
