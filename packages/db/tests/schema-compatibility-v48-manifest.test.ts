import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { expectedMigrations } from "../src/admin/schema-compatibility-manifest.gen.js";

const migrationsRoot = resolve(import.meta.dirname, "../migrations");
const metaRoot = resolve(migrationsRoot, "meta");

type JournalEntry = {
  idx: number;
  when: number;
  tag: string;
};

type Snapshot = {
  id: string;
  prevId: string;
  tables: Record<string, unknown>;
  enums: Record<string, unknown>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const readJson = (path: string): unknown => {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  return parsed;
};

const readJournal = (): { entries: JournalEntry[] } => {
  const value = readJson(resolve(metaRoot, "_journal.json"));
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
  return { entries: value.entries };
};

const readSnapshot = (version: string): Snapshot => {
  const value = readJson(resolve(metaRoot, `${version}_snapshot.json`));
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.prevId !== "string" ||
    !isRecord(value.tables) ||
    !isRecord(value.enums)
  ) {
    throw new Error(`Drizzle ${version} snapshot is malformed`);
  }
  return {
    id: value.id,
    prevId: value.prevId,
    tables: value.tables,
    enums: value.enums,
  };
};

const stageVersions = [
  "0209",
  "0210",
  "0211",
  "0212",
  "0213",
  "0214",
  "0215",
  "0216",
  "0217",
  "0218",
  "0219",
  "0220",
] as const;

const v48SealMigrationCount = 219;
const v48SealCreatedAt = 1_788_276_517_454;
const v48SealHash =
  "d6a20868f2707d3ff199cccbb2f6c1afc66d068f8f9bc41660482c010317a50a";

const expectedTableAdditions: Record<(typeof stageVersions)[number], string[]> =
  {
    "0209": [],
    "0210": [
      "public.tenant_ldap_jit_authority_issuance_receipts",
      "public.tenant_mfa_ldap_recovery_replacement_capabilities",
    ],
    "0211": [
      "public.platform_ldap_authentication_runs",
      "public.platform_ldap_bind_secrets",
      "public.platform_ldap_external_identities",
      "public.platform_ldap_external_identity_aliases",
      "public.platform_ldap_mapping_rules",
      "public.platform_ldap_provider_configurations",
      "public.platform_ldap_provider_endpoints",
      "public.platform_ldap_role_grants",
      "public.platform_ldap_session_provenance",
      "public.platform_ldap_test_runs",
    ],
    "0212": ["public.tenant_membership_lifecycle_commands"],
    "0213": [
      "public.platform_audit_export_jobs",
      "public.platform_audit_export_manifests",
      "public.platform_audit_legal_holds",
      "public.platform_audit_operation_receipts",
      "public.platform_audit_retention_anchor",
      "public.platform_audit_retention_policy",
      "public.platform_audit_segments",
      "public.platform_user_authorization_epochs",
      "public.tenant_audit_export_jobs",
      "public.tenant_audit_export_manifests",
      "public.tenant_audit_legal_holds",
      "public.tenant_audit_operation_receipts",
      "public.tenant_audit_retention_anchors",
      "public.tenant_audit_retention_policies",
      "public.tenant_audit_retention_prune_capabilities",
      "public.tenant_audit_segments",
    ],
    "0214": ["public.tenant_settings"],
    "0215": [],
    "0216": [
      "public.platform_feature_flags",
      "public.platform_global_settings",
    ],
    "0217": ["public.alert_case_link_retractions"],
    "0218": [],
    "0219": [],
    "0220": [],
  };

describe("schema compatibility V48 manifest", () => {
  it("pins the immutable V48 seal prefix inside the current bundle", () => {
    const journal = readJournal();
    const sqlFiles = readdirSync(migrationsRoot)
      .filter((name) => name.endsWith(".sql"))
      .toSorted();

    const expectedPrefix = expectedMigrations.slice(0, v48SealMigrationCount);
    const journalPrefix = journal.entries.slice(0, v48SealMigrationCount);
    const sqlPrefix = sqlFiles.slice(0, v48SealMigrationCount);
    const fingerprint = expectedPrefix
      .map((migration) => `${migration.createdAt}@${migration.hash}`)
      .join(":");

    expect(expectedMigrations.length).toBeGreaterThanOrEqual(
      v48SealMigrationCount,
    );
    expect(journal.entries.length).toBeGreaterThanOrEqual(
      v48SealMigrationCount,
    );
    expect(sqlFiles.length).toBeGreaterThanOrEqual(v48SealMigrationCount);
    expect(expectedPrefix).toHaveLength(v48SealMigrationCount);
    expect(expectedPrefix.at(-1)).toEqual({
      tag: "0218_v48_compatibility",
      createdAt: v48SealCreatedAt,
      hash: v48SealHash,
    });
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
    expect(
      journalPrefix.every(
        (entry, index) =>
          index === 0 || entry.when > journalPrefix[index - 1]!.when,
      ),
    ).toBe(true);
    expect(fingerprint.split(":")).toHaveLength(v48SealMigrationCount);
    expect(fingerprint).toMatch(
      new RegExp(`${v48SealCreatedAt}@${v48SealHash}$`, "u"),
    );
  });

  it("introduces each post-V47 table at its owning migration ordinal", () => {
    let previous = readSnapshot("0208");

    for (const version of stageVersions) {
      const current = readSnapshot(version);
      const previousTables = new Set(Object.keys(previous.tables));
      const currentTables = new Set(Object.keys(current.tables));
      const addedTables = [...currentTables]
        .filter((table) => !previousTables.has(table))
        .toSorted();
      const removedTables = [...previousTables]
        .filter((table) => !currentTables.has(table))
        .toSorted();
      const previousEnums = new Set(Object.keys(previous.enums));
      const currentEnums = new Set(Object.keys(current.enums));

      expect(current.prevId, `${version} snapshot predecessor`).toBe(
        previous.id,
      );
      expect(addedTables, `${version} table additions`).toEqual(
        expectedTableAdditions[version],
      );
      expect(removedTables, `${version} table removals`).toEqual([]);
      expect(
        [...currentEnums].filter((name) => !previousEnums.has(name)),
        `${version} enum additions`,
      ).toEqual([]);
      expect(
        [...previousEnums].filter((name) => !currentEnums.has(name)),
        `${version} enum removals`,
      ).toEqual([]);

      previous = current;
    }

    const rateLimitScope = previous.enums["public.auth_rate_limit_scope"];
    expect(isRecord(rateLimitScope) && rateLimitScope.values).toEqual([
      "api_network",
      "api_credential",
      "api_tenant_subject",
      "bootstrap_totp",
      "local_login",
      "ldap_network",
      "ldap_account",
      "ldap_provider",
      "platform_oidc_network",
      "platform_oidc_account",
      "platform_oidc_provider",
      "platform_saml_network",
      "platform_saml_account",
      "platform_saml_provider",
      "mfa_challenge",
      "recovery_code",
      "tenant_switch",
    ]);
  });
});
