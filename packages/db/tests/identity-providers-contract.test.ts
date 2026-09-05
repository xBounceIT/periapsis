import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import { localBreakGlassCredentials } from "../src/schema/authentication.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
  tenantLdapProviderConfigs,
  tenantLdapProviderSecrets,
  tenantLdapProviderTestRuns,
  tenantLdapProviderUrls,
} from "../src/schema/identity-providers.js";
import {
  tenantUserProfiles,
  userLoginIdentifiers,
  users,
} from "../src/schema/identity.js";

const packageRoot = resolve(import.meta.dirname, "..");

function readRequiredMigration(fileName: string): string {
  const source = readFileSync(
    resolve(packageRoot, "migrations", fileName),
    "utf8",
  );
  if (source.trim().length === 0) {
    throw new Error(`Migration ${fileName} must not be empty`);
  }
  return source;
}

function functionBodyFrom(source: string, name: string): string {
  const markers = [
    `CREATE OR REPLACE FUNCTION app.${name}`,
    `CREATE FUNCTION app.${name}`,
    `CREATE OR REPLACE FUNCTION "app"."${name}"`,
    `CREATE FUNCTION "app"."${name}"`,
  ];
  const start = Math.max(...markers.map((marker) => source.indexOf(marker)));
  if (start === -1) {
    throw new Error(`Missing database function ${name}`);
  }
  const end = source.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`Unterminated database function ${name}`);
  }
  return source.slice(start, end);
}

function columnNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  return getTableConfig(table).columns.map((column) => column.name);
}

function foreignKeyNames(
  table: Parameters<typeof getTableConfig>[0],
): string[] {
  return getTableConfig(table).foreignKeys.map((foreignKey) =>
    foreignKey.getName(),
  );
}

function checkNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  return getTableConfig(table).checks.map((constraint) => constraint.name);
}

const preflight = readRequiredMigration("0040_identity_provider_preflight.sql");
const additive = readRequiredMigration("0041_identity_provider_additive.sql");
const backfill = readRequiredMigration("0042_identity_provider_backfill.sql");
const finalStructural = readRequiredMigration(
  "0043_identity_provider_final.sql",
);
const security = readRequiredMigration("0044_identity_provider_security.sql");
const crud = readRequiredMigration("0045_identity_provider_crud.sql");
const profileCompatibility = readRequiredMigration(
  "0046_identity_profile_compatibility.sql",
);
const testRuns = readRequiredMigration("0047_identity_provider_test_runs.sql");
const testSecurity = readRequiredMigration(
  "0048_identity_provider_test_security.sql",
);
const keyringActive = readRequiredMigration(
  "0049_identity_provider_keyring_active.sql",
);
const readiness = readRequiredMigration(
  "0050_identity_provider_readiness_v7.sql",
);

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

interface MigrationJournal {
  entries: JournalEntry[];
}

function parseMigrationJournal(source: string): MigrationJournal {
  const parsed: unknown = JSON.parse(source);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("entries" in parsed) ||
    !Array.isArray(parsed.entries) ||
    !parsed.entries.every(
      (entry: unknown): entry is JournalEntry =>
        typeof entry === "object" &&
        entry !== null &&
        "idx" in entry &&
        typeof entry.idx === "number" &&
        "tag" in entry &&
        typeof entry.tag === "string" &&
        "when" in entry &&
        typeof entry.when === "number",
    )
  ) {
    throw new Error("Migration journal has an invalid contract-test shape");
  }
  return { entries: parsed.entries };
}

const journal = parseMigrationJournal(
  readFileSync(resolve(packageRoot, "migrations/meta/_journal.json"), "utf8"),
);

const identityProviderTables = [
  tenantAuthProviders,
  tenantLdapProviderConfigs,
  tenantLdapProviderUrls,
  tenantLdapProviderSecrets,
] as const;

describe("LDAP identity-provider structural database contract", () => {
  it("keeps the preflight, additive, backfill, final, and security stages ordered", () => {
    const entries = journal.entries.slice(40, 51);

    expect(entries.map((entry) => [entry.idx, entry.tag])).toEqual([
      [40, "0040_identity_provider_preflight"],
      [41, "0041_identity_provider_additive"],
      [42, "0042_identity_provider_backfill"],
      [43, "0043_identity_provider_final"],
      [44, "0044_identity_provider_security"],
      [45, "0045_identity_provider_crud"],
      [46, "0046_identity_profile_compatibility"],
      [47, "0047_identity_provider_test_runs"],
      [48, "0048_identity_provider_test_security"],
      [49, "0049_identity_provider_keyring_active"],
      [50, "0050_identity_provider_readiness_v7"],
    ]);
    expect(entries.map((entry) => entry.when)).toEqual(
      [...entries]
        .map((entry) => entry.when)
        .toSorted((left, right) => left - right),
    );

    expect(additive).toContain(
      'ALTER TABLE "users" ALTER COLUMN "email" DROP NOT NULL',
    );
    expect(additive).toContain(
      'ALTER TABLE "local_break_glass_credentials" ADD COLUMN "login_identifier_id" uuid',
    );
    expect(finalStructural.trim()).toBe(
      'ALTER TABLE "local_break_glass_credentials" ALTER COLUMN "login_identifier_id" SET NOT NULL;',
    );
  });

  it("fails closed before making legacy email optional", () => {
    for (const tableName of [
      "users",
      "local_break_glass_credentials",
      "tenant_memberships",
      "tenant_permissions",
      "tenant_authorization_sources",
    ]) {
      expect(preflight).toContain(
        `LOCK TABLE "public"."${tableName}" IN SHARE ROW EXCLUSIVE MODE`,
      );
    }

    expect(preflight).toContain(
      "FROM public.local_break_glass_credentials AS credential",
    );
    expect(preflight).toContain("identity.email IS NULL");
    for (const permission of [
      "identity_mapping.manage",
      "identity_mapping.read",
      "identity_provider.manage",
      "identity_provider.read",
      "identity_provider.test",
      "identity_sync.run",
    ]) {
      expect(preflight).toContain(`'${permission}'`);
    }
    expect(preflight).toContain("source.key LIKE 'identity_provider_access:%'");
    expect(preflight).toContain("source.key LIKE 'identity_mapping_rule:%'");
  });

  it("separates optional global email from a required local login identifier", () => {
    const userEmail = getTableConfig(users).columns.find(
      (column) => column.name === "email",
    );
    const identifierConfig = getTableConfig(userLoginIdentifiers);
    const credentialConfig = getTableConfig(localBreakGlassCredentials);
    const loginIdentifier = credentialConfig.columns.find(
      (column) => column.name === "login_identifier_id",
    );

    expect(userEmail?.notNull).toBe(false);
    expect(checkNames(users)).toEqual(
      expect.arrayContaining([
        "users_email_canonical_check",
        "users_email_shape_check",
      ]),
    );
    for (const columnName of ["user_id", "kind", "canonical_value"]) {
      expect(
        identifierConfig.columns.find((column) => column.name === columnName)
          ?.notNull,
      ).toBe(true);
    }
    expect(identifierConfig.enableRLS).toBe(true);
    expect(identifierConfig.policies).toHaveLength(0);
    expect(
      identifierConfig.uniqueConstraints.map((constraint) => constraint.name),
    ).toEqual(
      expect.arrayContaining([
        "user_login_identifiers_id_user_key",
        "user_login_identifiers_kind_value_key",
      ]),
    );
    expect(
      identifierConfig.indexes.some(
        (index) =>
          index.config.name === "user_login_identifiers_user_active_kind_key" &&
          index.config.unique &&
          index.config.where !== undefined,
      ),
    ).toBe(true);
    expect(checkNames(userLoginIdentifiers)).toEqual(
      expect.arrayContaining([
        "user_login_identifiers_local_email_check",
        "user_login_identifiers_retirement_check",
        "user_login_identifiers_timestamps_check",
      ]),
    );
    expect(loginIdentifier?.notNull).toBe(true);
    expect(foreignKeyNames(localBreakGlassCredentials)).toContain(
      "local_break_glass_credentials_login_identifier_fk",
    );
  });

  it("stores a tenant-bound effective profile tied to the exact membership user", () => {
    const config = getTableConfig(tenantUserProfiles);

    for (const columnName of ["tenant_id", "membership_id", "user_id"]) {
      expect(
        config.columns.find((column) => column.name === columnName)?.notNull,
      ).toBe(true);
    }
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(foreignKeyNames(tenantUserProfiles)).toContain(
      "tenant_user_profiles_membership_fk",
    );
    expect(additive).toContain(
      'FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id")',
    );
    expect(checkNames(tenantUserProfiles)).toEqual(
      expect.arrayContaining([
        "tenant_user_profiles_display_name_check",
        "tenant_user_profiles_username_check",
        "tenant_user_profiles_email_check",
        "tenant_user_profiles_version_check",
      ]),
    );
  });

  it("backfills only local credentials and materializes each membership profile", () => {
    const identifierInsert = backfill.slice(
      backfill.indexOf("INSERT INTO public.user_login_identifiers"),
      backfill.indexOf("UPDATE public.local_break_glass_credentials"),
    );

    expect(identifierInsert).toContain(
      "FROM public.local_break_glass_credentials AS credential",
    );
    expect(identifierInsert).toContain(
      "JOIN public.users AS identity ON identity.id = credential.user_id",
    );
    expect(identifierInsert).not.toContain("FROM public.users AS identity");
    expect(backfill).toContain("SET login_identifier_id = identifier.id");
    expect(backfill).toContain("identifier.kind = 'local_email'");
    expect(backfill).toContain("identifier.verified_at IS NOT NULL");
    expect(backfill).toContain("identifier.retired_at IS NULL");
    expect(backfill).toContain("FROM public.tenant_memberships AS membership");
    expect(backfill).toContain(
      "CREATE TRIGGER local_break_glass_credentials_bind_identifier",
    );

    const lookup = functionBodyFrom(
      backfill,
      "get_local_break_glass_credential",
    );
    expect(lookup).toContain("public.user_login_identifiers AS identifier");
    expect(lookup).toContain("credential.login_identifier_id = identifier.id");
    expect(lookup).toContain(
      "identifier.canonical_value = lower(btrim(p_email))",
    );
    expect(lookup).not.toContain("identity.email =");
  });

  it("keeps platform tenant creation and its local profile projection transactional", () => {
    const wrapper = functionBodyFrom(
      profileCompatibility,
      "create_platform_tenant",
    );
    const delegatedCreate = wrapper.indexOf(
      "app.create_platform_tenant_identity_profile_compatibility_impl",
    );
    const profileInsert = wrapper.indexOf(
      "INSERT INTO public.tenant_user_profiles",
    );

    expect(delegatedCreate).toBeGreaterThan(-1);
    expect(profileInsert).toBeGreaterThan(delegatedCreate);
    expect(wrapper).toContain("SECURITY DEFINER");
    expect(wrapper).toContain("SET search_path = pg_catalog, public, app");
    expect(wrapper).toContain("login_identifier.kind = 'local_email'");
    expect(wrapper).toContain("login_identifier.verified_at IS NOT NULL");
    expect(wrapper).toContain("login_identifier.retired_at IS NULL");
    expect(wrapper).toContain(
      "coalesce(login_identifier.canonical_value, identity.email)",
    );
    expect(wrapper).toContain("identity.display_name");
    expect(wrapper).toContain(
      "platform tenant creator has no verified local profile identity",
    );
    expect(profileCompatibility).toContain(
      "REVOKE ALL ON FUNCTION app.create_platform_tenant_identity_profile_compatibility_impl(",
    );
    expect(profileCompatibility).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.create_platform_tenant_identity_profile_compatibility_impl/,
    );
    expect(profileCompatibility).toContain(
      "GRANT EXECUTE ON FUNCTION app.create_platform_tenant(",
    );
    expect(profileCompatibility).toContain(") TO periapsis_api;");
  });

  it("keeps every provider row tenant-bound, RLS-only, and tenant-consistent", () => {
    for (const table of identityProviderTables) {
      const config = getTableConfig(table);
      expect(
        config.columns.find((column) => column.name === "tenant_id")?.notNull,
        `${config.name}.tenant_id must be NOT NULL`,
      ).toBe(true);
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies,
        `${config.name} must have no direct policy`,
      ).toHaveLength(0);
    }

    expect(foreignKeyNames(tenantAuthProviders)).toEqual(
      expect.arrayContaining([
        "tenant_auth_providers_creator_membership_fk",
        "tenant_auth_providers_updater_membership_fk",
        "tenant_auth_providers_archiver_membership_fk",
      ]),
    );
    expect(foreignKeyNames(tenantLdapProviderConfigs)).toEqual(
      expect.arrayContaining([
        "tenant_ldap_provider_configs_provider_fk",
        "tenant_ldap_provider_configs_updater_fk",
      ]),
    );
    expect(foreignKeyNames(tenantLdapProviderUrls)).toContain(
      "tenant_ldap_provider_urls_provider_fk",
    );
    expect(foreignKeyNames(tenantLdapProviderSecrets)).toEqual(
      expect.arrayContaining([
        "tenant_ldap_provider_secrets_provider_fk",
        "tenant_ldap_provider_secrets_rotator_fk",
      ]),
    );
    for (const constraintName of [
      "tenant_ldap_provider_configs_provider_fk",
      "tenant_ldap_provider_urls_provider_fk",
      "tenant_ldap_provider_secrets_provider_fk",
    ]) {
      expect(additive).toContain(
        `CONSTRAINT "${constraintName}" FOREIGN KEY ("tenant_id","provider_id","provider_kind")`,
      );
    }
  });

  it("fails closed to LDAP while future provider enum values remain reserved", () => {
    expect(additive).toContain(
      `CREATE TYPE "public"."auth_provider_kind" AS ENUM('ldap', 'oidc', 'saml')`,
    );
    expect(checkNames(tenantAuthProviders)).toContain(
      "tenant_auth_providers_implemented_kind_check",
    );
    expect(additive).toContain(
      'CONSTRAINT "tenant_auth_providers_implemented_kind_check" CHECK ("tenant_auth_providers"."kind" = \'ldap\')',
    );
    for (const table of [
      tenantLdapProviderConfigs,
      tenantLdapProviderUrls,
      tenantLdapProviderSecrets,
    ]) {
      expect(checkNames(table)).toContain(
        `${getTableConfig(table).name}_kind_check`,
      );
    }
  });

  it("stores only bounded AES-GCM bind-secret envelopes with immutable row identity", () => {
    const config = getTableConfig(tenantLdapProviderSecrets);
    const columns = columnNames(tenantLdapProviderSecrets);

    expect(columns).toEqual(
      expect.arrayContaining([
        "id",
        "secret_ciphertext",
        "secret_nonce",
        "key_version",
        "encryption_algorithm",
      ]),
    );
    expect(columns).not.toEqual(
      expect.arrayContaining([
        "bind_password",
        "password",
        "plaintext",
        "secret",
        "secret_aad",
      ]),
    );
    expect(config.columns.find((column) => column.name === "id")?.notNull).toBe(
      true,
    );
    expect(
      config.uniqueConstraints.map((constraint) => constraint.name),
    ).toContain("tenant_ldap_provider_secrets_tenant_id_id_unique");
    expect(checkNames(tenantLdapProviderSecrets)).toEqual(
      expect.arrayContaining([
        "tenant_ldap_provider_secrets_id_uuidv7_check",
        "tenant_ldap_provider_secrets_ciphertext_check",
        "tenant_ldap_provider_secrets_algorithm_check",
      ]),
    );
    expect(
      config.foreignKeys.some((foreignKey) =>
        foreignKey
          .getName()
          .includes("key_version_identity_keyring_versions_key_version_fk"),
      ),
    ).toBe(true);
    expect(additive).toContain(
      '(uuid_extract_version("tenant_ldap_provider_secrets"."id") = 7) is true',
    );
    expect(additive).toContain(
      'octet_length("tenant_ldap_provider_secrets"."secret_nonce") = 12',
    );
    expect(additive).toContain(
      'octet_length("tenant_ldap_provider_secrets"."secret_ciphertext") between 17 and 8192',
    );
    expect(additive).toContain(
      '"tenant_ldap_provider_secrets"."encryption_algorithm" = \'aes-256-gcm\'',
    );
    expect(additive).not.toContain('"secret_aad"');
  });

  it("models redacted, revision-pinned LDAP test runs as tenant-owned rows", () => {
    const config = getTableConfig(tenantLdapProviderTestRuns);
    const columns = columnNames(tenantLdapProviderTestRuns);

    expect(
      config.columns.find((column) => column.name === "tenant_id")?.notNull,
    ).toBe(true);
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(columns).toEqual(
      expect.arrayContaining([
        "provider_id",
        "test_kind",
        "status",
        "outcome",
        "category",
        "endpoint_priority",
        "duration_ms",
        "provider_version",
        "configuration_version",
        "secret_version",
        "started_by_membership_id",
        "completed_by_membership_id",
        "request_id",
        "correlation_id",
        "version",
      ]),
    );
    expect(columns).not.toEqual(
      expect.arrayContaining([
        "detail",
        "diagnostic",
        "error",
        "message",
        "secret_ciphertext",
        "secret_nonce",
      ]),
    );
    expect(foreignKeyNames(tenantLdapProviderTestRuns)).toEqual(
      expect.arrayContaining([
        "tenant_ldap_provider_test_runs_provider_fk",
        "tenant_ldap_provider_test_runs_starter_fk",
        "tenant_ldap_provider_test_runs_completer_fk",
      ]),
    );
    expect(checkNames(tenantLdapProviderTestRuns)).toEqual(
      expect.arrayContaining([
        "tenant_ldap_provider_test_runs_id_uuidv7_check",
        "tenant_ldap_provider_test_runs_kind_check",
        "tenant_ldap_provider_test_runs_revision_check",
        "tenant_ldap_provider_test_runs_secret_check",
        "tenant_ldap_provider_test_runs_result_bounds_check",
        "tenant_ldap_provider_test_runs_result_semantics_check",
        "tenant_ldap_provider_test_runs_lifecycle_check",
      ]),
    );
    expect(testRuns).toContain(
      `CREATE TYPE "public"."ldap_provider_test_category" AS ENUM('success', 'dns_failed', 'destination_blocked', 'connect_timeout', 'connect_failed', 'tls_failed', 'certificate_rejected', 'bind_rejected', 'protocol_failed', 'cancelled', 'stale_configuration')`,
    );
    expect(testRuns).toContain(
      `CREATE TYPE "public"."ldap_provider_test_kind" AS ENUM('connection', 'bind')`,
    );
    expect(testRuns).toContain(
      'FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind")',
    );
    expect(keyringActive).toContain(
      '"tenant_ldap_provider_test_runs"."category" = \'success\'',
    );
    expect(keyringActive).toContain(
      '"tenant_ldap_provider_test_runs"."endpoint_priority" is not null',
    );
    expect(keyringActive).toContain(
      '"tenant_ldap_provider_test_runs"."category" = \'cancelled\' or "tenant_ldap_provider_test_runs"."endpoint_priority" is not null',
    );
    expect(keyringActive).toContain(
      '"tenant_ldap_provider_test_runs"."test_kind" = \'bind\' or "tenant_ldap_provider_test_runs"."category" <> \'bind_rejected\'',
    );
  });
});

describe("LDAP identity-provider database security contract", () => {
  it("forces RLS and denies every runtime role direct table access", () => {
    const protectedTables = [
      userLoginIdentifiers,
      tenantUserProfiles,
      identityKeyringVersions,
      ...identityProviderTables,
    ];

    for (const table of protectedTables) {
      const tableName = getTableConfig(table).name;
      expect(security).toContain(
        `ALTER TABLE public.${tableName} OWNER TO periapsis_migrator`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${tableName} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `REVOKE ALL ON TABLE public.${tableName} FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
      );
    }
    expect(security).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]*ON TABLE public\.(?:identity_keyring_versions|tenant_auth_providers|tenant_ldap_provider_)/,
    );
  });

  it("seeds tenant-scoped, human-only permissions for existing and future tenants", () => {
    const permissions = [
      "identity_provider.read",
      "identity_provider.manage",
      "identity_provider.test",
      "identity_mapping.read",
      "identity_mapping.manage",
      "identity_sync.run",
    ];

    for (const permission of permissions) {
      expect(security).toContain(`'${permission}'`);
      expect(security).toContain(`(uuidv7(), '${permission}'`);
    }
    expect(security).toContain("'tenant'::public.authorization_scope");
    expect(security).toContain("permission.service_account_allowed");
    expect(security).toContain("role.principal_kind = 'human'");
    expect(security).toContain(
      "PERFORM app.private_seed_tenant_identity_authorization_v1(tenant_record.id)",
    );
    expect(functionBodyFrom(security, "seed_tenant_authorization")).toContain(
      "PERFORM app.private_seed_tenant_identity_authorization_v1(p_tenant_id)",
    );
  });

  it("protects LDAP test runs as force-RLS, complete-once records", () => {
    const guard = functionBodyFrom(
      testSecurity,
      "guard_tenant_ldap_provider_test_run_v1",
    );

    expect(testSecurity).toContain(
      "ALTER TABLE public.tenant_ldap_provider_test_runs OWNER TO periapsis_migrator",
    );
    expect(testSecurity).toContain(
      "ALTER TABLE public.tenant_ldap_provider_test_runs FORCE ROW LEVEL SECURITY",
    );
    expect(testSecurity).toContain(
      "REVOKE ALL ON TABLE public.tenant_ldap_provider_test_runs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
    expect(testSecurity).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]*ON TABLE public\.tenant_ldap_provider_test_runs/,
    );
    expect(guard).toContain("IF TG_OP = 'DELETE' THEN");
    expect(guard).toContain("OLD.status <> 'started'");
    expect(guard).toContain("NEW.status <> 'completed'");
    expect(guard).toContain("NEW.version <> 2");
    expect(guard).toContain("to_jsonb(NEW) - ARRAY[");
    expect(guard).toContain("to_jsonb(OLD) - ARRAY[");
    expect(testSecurity).toContain(
      "CREATE TRIGGER tenant_ldap_provider_test_runs_guard_update_delete",
    );
    expect(testSecurity).toContain(
      "BEFORE UPDATE OR DELETE ON public.tenant_ldap_provider_test_runs",
    );
  });

  it("begins a bounded revision-pinned test without exposing bind material to connection tests", () => {
    const begin = functionBodyFrom(
      testSecurity,
      "begin_tenant_ldap_provider_test_v1",
    );

    expect(begin).toContain("'identity_provider.test', 'tenant'");
    expect(begin).toContain(
      "PERFORM app.lock_current_tenant_authorization_state()",
    );
    expect(begin).toContain(
      "(uuid_extract_version(p_test_run_id) = 7) IS NOT TRUE",
    );
    expect(begin).toContain(
      "locked_provider public.tenant_auth_providers%ROWTYPE",
    );
    expect(begin).toContain(
      "locked_configuration public.tenant_ldap_provider_configs%ROWTYPE",
    );
    expect(begin).toContain(
      "locked_secret public.tenant_ldap_provider_secrets%ROWTYPE",
    );
    expect(begin).toContain("p_test_kind = 'bind'");
    expect(begin).toContain(
      "recent_test.started_at >= test_started_at - interval '1 minute'",
    );
    expect(begin).toContain("recent_test.status IN ('started', 'completed')");
    expect(begin).toContain("recent_actor_provider_test_count >= 5");
    expect(begin).toContain("recent_provider_test_count >= 20");
    expect(begin).toContain("recent_tenant_test_count >= 50");
    expect(begin).toContain(
      "INSERT INTO public.tenant_ldap_provider_test_runs",
    );
    expect(begin).toContain("locked_provider.version");
    expect(begin).toContain("locked_configuration.version");
    expect(begin).toContain(
      "CASE WHEN p_test_kind = 'bind' THEN locked_secret.version ELSE NULL END",
    );
    for (const secretField of [
      "id",
      "secret_ciphertext",
      "secret_nonce",
      "key_version",
      "encryption_algorithm",
    ]) {
      expect(begin).toContain(
        `CASE WHEN p_test_kind = 'bind' THEN locked_secret.${secretField} ELSE NULL END`,
      );
    }
    const beginAudit = begin.slice(
      begin.indexOf("PERFORM app.append_tenant_authorization_audit("),
      begin.indexOf("RETURN QUERY"),
    );
    expect(beginAudit).toContain("tenant.identity_provider.test_started");
    expect(beginAudit).not.toMatch(
      /secret_(?:ciphertext|nonce)|locked_secret\.(?:id|key_version)/,
    );
  });

  it("completes only the actor-correlated snapshot and overrides stale results", () => {
    const complete = functionBodyFrom(
      testSecurity,
      "complete_tenant_ldap_provider_test_v1",
    );

    expect(complete).toContain("'identity_provider.test', 'tenant'");
    expect(complete).toContain("p_duration_ms NOT BETWEEN 0 AND 120000");
    expect(complete).toContain("p_endpoint_priority NOT BETWEEN 1 AND 8");
    expect(complete).toContain(
      "p_reported_category <> 'cancelled' AND p_endpoint_priority IS NULL",
    );
    expect(complete).toContain("FOR UPDATE");
    expect(complete).toContain("locked_run.status <> 'started'");
    expect(complete).toContain(
      "locked_run.started_by_membership_id <> actor_membership",
    );
    expect(complete).toContain(
      "locked_run.request_id IS DISTINCT FROM p_request_id",
    );
    expect(complete).toContain(
      "locked_run.correlation_id IS DISTINCT FROM p_correlation_id",
    );
    expect(complete).toContain("locked_run.test_kind = 'connection'");
    expect(complete).toContain("p_reported_category = 'bind_rejected'");
    expect(complete).toContain(
      "current_provider_version IS DISTINCT FROM locked_run.provider_version",
    );
    expect(complete).toContain(
      "current_configuration_version IS DISTINCT FROM locked_run.configuration_version",
    );
    expect(complete).toContain(
      "current_secret_version IS DISTINCT FROM locked_run.secret_version",
    );
    expect(complete).toContain("IF NOT result_is_stale");
    expect(complete).toContain("endpoint.priority = p_endpoint_priority");
    expect(complete).toContain("AND endpoint.enabled");
    expect(complete).toContain(
      "test endpoint is not in the current enabled configuration",
    );
    expect(complete).toContain("effective_outcome := 'inconclusive'");
    expect(complete).toContain("effective_category := 'stale_configuration'");
    expect(complete).toContain(
      "test_completed_at > locked_run.started_at + interval '2 minutes'",
    );
    expect(complete).toContain("effective_outcome := 'failure'");
    expect(complete).toContain("effective_category := 'cancelled'");
    expect(complete).toContain("SET status = 'completed'");
    expect(complete).toContain("version = 2");
    expect(complete).toContain("tenant.identity_provider.test_completed");
    expect(complete).toContain("'stale_configuration', result_is_stale");
    expect(complete).toContain("'expired_test', result_is_expired");
    expect(complete).not.toMatch(/secret_(?:ciphertext|nonce)/);
  });

  it("grants test execution only through the API definer functions", () => {
    const functions = [
      [
        "begin_tenant_ldap_provider_test_v1",
        "uuid, uuid, public.ldap_provider_test_kind, uuid, uuid, inet, text, text",
      ],
      [
        "complete_tenant_ldap_provider_test_v1",
        "uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, uuid, uuid, inet, text, text",
      ],
    ] as const;

    for (const [name, signature] of functions) {
      expect(testSecurity).toContain(
        `REVOKE ALL ON FUNCTION app.${name}(${signature}) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
      );
      expect(testSecurity).toContain(
        `GRANT EXECUTE ON FUNCTION app.${name}(${signature}) TO periapsis_api`,
      );
      expect(testSecurity).not.toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION app\\.${name}\\([^;]+ TO (?:periapsis_worker|periapsis_notifier|periapsis_auditor)`,
        ),
      );
    }
    expect(testSecurity).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.guard_tenant_ldap_provider_test_run_v1/,
    );
  });

  it("binds each identity key version to exact material and covers all live ciphertext", () => {
    const keyring = getTableConfig(identityKeyringVersions);
    const verify = functionBodyFrom(readiness, "verify_identity_keyring_v1");

    expect(keyring.enableRLS).toBe(true);
    expect(keyring.policies).toHaveLength(0);
    expect(columnNames(identityKeyringVersions)).toEqual([
      "key_version",
      "verifier",
      "is_active",
      "bound_at",
      "retired_at",
    ]);
    expect(
      keyring.indexes.some(
        (index) =>
          index.config.name === "identity_keyring_versions_single_active_key" &&
          index.config.unique &&
          index.config.where !== undefined,
      ),
    ).toBe(true);
    expect(checkNames(identityKeyringVersions)).toEqual(
      expect.arrayContaining([
        "identity_keyring_versions_version_check",
        "identity_keyring_versions_verifier_check",
        "identity_keyring_versions_retirement_check",
      ]),
    );
    expect(verify).toContain("RETURNS boolean");
    expect(verify).toContain("item_count < 1 OR item_count > 16");
    expect(verify).toContain("coalesce(array_ndims(p_versions), 0) <> 1");
    expect(verify).toContain("array_lower(p_versions, 1) <> 1");
    expect(verify).toContain(
      "p_versions[item_index - 1] >= p_versions[item_index]",
    );
    expect(verify).toContain("count(DISTINCT verifier)::integer");
    expect(verify).toContain(
      "LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE",
    );
    expect(verify).toContain("ON CONFLICT DO NOTHING");
    expect(verify).toContain(
      "existing_verifier IS DISTINCT FROM p_verifiers[item_index]",
    );
    expect(verify).toContain("existing_retired_at IS NOT NULL");
    expect(verify).toContain("WHERE keyring.is_active");
    expect(verify).toContain(
      "bound_active_version IS DISTINCT FROM p_active_version",
    );
    expect(verify).toContain("WHERE NOT secret.key_version = ANY(p_versions)");
    expect(verify).toContain("installed_key.retired_at IS NOT NULL");
    expect(verify).toContain("active_key.is_active");
    expect(verify).toContain("active_key.verifier = p_verifiers[");
    expect(keyringActive).toContain(
      'ADD COLUMN "is_active" boolean DEFAULT false NOT NULL',
    );
    expect(keyringActive).toContain(
      'CREATE UNIQUE INDEX "identity_keyring_versions_single_active_key"',
    );
    expect(readiness).toContain(
      "GRANT EXECUTE ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer) TO periapsis_api, periapsis_worker",
    );
    expect(readiness).toContain(
      "REVOKE ALL ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer) FROM PUBLIC, periapsis_notifier, periapsis_auditor",
    );
  });

  it("promotes the singleton active key only through a migration-owned compare-and-swap", () => {
    const promote = functionBodyFrom(
      readiness,
      "promote_identity_keyring_version_v1",
    );

    expect(promote).toContain(
      "p_next_active_version <= p_expected_active_version",
    );
    expect(promote).toContain(
      "LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE",
    );
    expect(promote).toContain(
      "bound_active_version IS DISTINCT FROM p_expected_active_version",
    );
    expect(promote).toContain("next_key.retired_at IS NULL");
    expect(promote).toContain("SET is_active = false");
    expect(promote).toContain("SET is_active = true");
    expect(readiness).toContain(
      "REVOKE ALL ON FUNCTION app.promote_identity_keyring_version_v1(integer, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
    expect(readiness).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.promote_identity_keyring_version_v1/,
    );
  });

  it("exposes only redacted provider reads through the API role", () => {
    const list = functionBodyFrom(crud, "list_tenant_ldap_providers_v1");
    const get = functionBodyFrom(crud, "get_tenant_ldap_provider_v1");

    for (const body of [list, get]) {
      expect(body).toContain("'identity_provider.read', 'tenant'");
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(body).not.toMatch(
        /secret\.(?:secret_ciphertext|secret_nonce|secret_aad|key_version|encryption_algorithm)/,
      );
    }
    expect(list).toContain("bind_secret_configured boolean");
    expect(get).toContain("bind_secret_configured boolean");
    expect(get).toContain("bind_secret_rotated_at timestamp with time zone");
    expect(get).toContain("secret.provider_id IS NOT NULL");
    expect(get).toContain("secret.rotated_at");
  });

  it("keeps secret row-ID management and retires the unpinned envelope read", () => {
    const idLookup = functionBodyFrom(
      crud,
      "get_tenant_ldap_bind_secret_id_v1",
    );

    expect(idLookup).toContain("RETURNS uuid");
    expect(idLookup).toContain("'identity_provider.manage', 'tenant'");
    expect(idLookup).toContain("secret.tenant_id = context_tenant");
    expect(idLookup).toContain("secret.provider_id = p_provider_id");
    expect(testSecurity).toContain(
      "REVOKE ALL ON FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
    expect(testSecurity).toContain(
      "DROP FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid)",
    );
    expect(testSecurity).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.get_tenant_ldap_bind_secret_envelope_v1/,
    );
  });

  it("binds create idempotency to tenant, actor, operation, request, resource, and version", () => {
    const guard = functionBodyFrom(crud, "guard_tenant_authorization_command");
    const create = functionBodyFrom(crud, "create_tenant_ldap_provider_v1");

    expect(additive).toContain("'identity_provider.create'");
    expect(guard).toContain("NEW.operation = 'identity_provider.create'");
    expect(guard).toContain("resource.tenant_id = NEW.tenant_id");
    expect(guard).toContain("resource.id = NEW.result_resource_id");
    expect(guard).toContain("resource.version = NEW.result_version");
    expect(create).toContain("sha256(convert_to(jsonb_build_object(");
    for (const predicate of [
      "command.tenant_id = context_tenant",
      "command.actor_membership_id = actor_membership",
      "command.operation = 'identity_provider.create'",
      "command.key_digest = p_idempotency_key_digest",
    ]) {
      expect(create).toContain(predicate);
    }
    expect(create).toContain(
      "existing_command.request_digest IS DISTINCT FROM canonical_request_digest",
    );
    expect(create).toContain("existing_command.result_resource_id");
    expect(create).toContain("existing_command.result_version");
    expect(
      create.indexOf("INSERT INTO public.tenant_auth_providers"),
    ).toBeLessThan(
      create.indexOf("INSERT INTO public.tenant_authorization_commands"),
    );
    expect(create).toContain("RETURN QUERY SELECT p_provider_id, 1, false");
  });

  it("locks, versions, and audits every provider mutation without secret material", () => {
    const mutations = [
      ["update_tenant_ldap_provider_v1", "tenant.identity_provider.updated"],
      [
        "rotate_tenant_ldap_bind_secret_v1",
        "tenant.identity_provider.bind_secret_rotated",
      ],
      [
        "clear_tenant_ldap_bind_secret_v1",
        "tenant.identity_provider.bind_secret_cleared",
      ],
      ["archive_tenant_ldap_provider_v1", "tenant.identity_provider.archived"],
    ] as const;

    for (const [name, auditAction] of mutations) {
      const body = functionBodyFrom(
        name === "rotate_tenant_ldap_bind_secret_v1" ? readiness : crud,
        name,
      );
      expect(body).toContain("'identity_provider.manage', 'tenant'");
      expect(body).toContain("FOR UPDATE");
      expect(body).toContain("p_expected_version <> locked_provider.version");
      expect(body).toContain("locked_provider.version >= 2147483647");
      expect(body).toContain("next_version := locked_provider.version + 1");
      expect(body).toContain("PERFORM app.append_tenant_authorization_audit(");
      expect(body).toContain(`'${auditAction}'`);
      expect(body).toContain("'version', locked_provider.version");
      expect(body).toContain("'version', next_version");
    }

    const update = functionBodyFrom(crud, "update_tenant_ldap_provider_v1");
    expect(update).toContain("requires a bind secret before enablement");
    expect(update).toContain("requires an enabled endpoint");

    const rotate = functionBodyFrom(
      readiness,
      "rotate_tenant_ldap_bind_secret_v1",
    );
    expect(rotate).toContain("keyring.retired_at IS NULL");
    expect(rotate).toContain("keyring.is_active");
    expect(rotate).toContain(
      "identity key version is not the verified active version",
    );
    expect(rotate).toContain("p_secret_id uuid");
    expect(rotate).toContain(
      "id, tenant_id, provider_id, provider_kind, secret_ciphertext",
    );
    expect(rotate).toContain(
      "p_secret_id, context_tenant, p_provider_id, 'ldap', p_secret_ciphertext",
    );
    expect(rotate).toContain("existing_secret_id <> p_secret_id");
    expect(rotate).toContain(
      "tenant LDAP bind-secret row identity cannot change",
    );
    expect(rotate).toContain("existing_secret_version >= 2147483647");
    const secretUpsert = rotate.slice(
      rotate.indexOf("INSERT INTO public.tenant_ldap_provider_secrets"),
      rotate.indexOf("next_version := locked_provider.version + 1"),
    );
    expect(secretUpsert).not.toMatch(/SET[\s\S]*\bid\s*=/);
    const rotateAudit = rotate.slice(
      rotate.indexOf("PERFORM app.append_tenant_authorization_audit("),
    );
    expect(rotateAudit).not.toMatch(
      /p_secret_(?:ciphertext|nonce)|secret_(?:ciphertext|nonce)/,
    );

    const clear = functionBodyFrom(crud, "clear_tenant_ldap_bind_secret_v1");
    expect(clear).toContain("IF locked_provider.enabled THEN");
    expect(clear).toContain("jsonb_build_object('reason', p_reason)");

    const archive = functionBodyFrom(crud, "archive_tenant_ldap_provider_v1");
    expect(archive).toContain("SET enabled = false");
    expect(archive).toContain("archive_reason = p_reason");
  });

  it("keeps private helpers private and grants each public CRUD ABI only to API", () => {
    const publicFunctions = [
      ["list_tenant_ldap_providers_v1", "uuid, boolean, integer"],
      ["get_tenant_ldap_provider_v1", "uuid"],
      ["get_tenant_ldap_bind_secret_id_v1", "uuid"],
      [
        "create_tenant_ldap_provider_v1",
        "uuid, bytea, text, text, text, jsonb, jsonb, uuid, uuid, inet, text, text",
      ],
      [
        "update_tenant_ldap_provider_v1",
        "uuid, integer, text, text, text, boolean, jsonb, jsonb, uuid, uuid, inet, text, text",
      ],
      [
        "rotate_tenant_ldap_bind_secret_v1",
        "uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text",
      ],
      [
        "clear_tenant_ldap_bind_secret_v1",
        "uuid, integer, text, uuid, uuid, inet, text, text",
      ],
      [
        "archive_tenant_ldap_provider_v1",
        "uuid, integer, text, uuid, uuid, inet, text, text",
      ],
    ] as const;

    for (const [name, signature] of publicFunctions) {
      const aclSource =
        name === "rotate_tenant_ldap_bind_secret_v1" ? readiness : crud;
      expect(aclSource).toContain(
        `REVOKE ALL ON FUNCTION app.${name}(${signature}) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
      );
      expect(aclSource).toContain(
        `GRANT EXECUTE ON FUNCTION app.${name}(${signature}) TO periapsis_api`,
      );
      expect(aclSource).not.toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION app\\.${name}\\([^;]+ TO (?:periapsis_worker|periapsis_notifier|periapsis_auditor)`,
        ),
      );
    }

    expect(crud).toContain(
      "REVOKE ALL ON FUNCTION app.private_replace_tenant_ldap_configuration_v1(uuid, uuid, uuid, jsonb, jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
    expect(crud).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.private_replace_tenant_ldap_configuration_v1/,
    );
  });

  it("seals the exact ABI, storage ACL, constraints, indexes, and permission catalog", () => {
    expect(readiness).toContain("DO $identity_provider_readiness_assertions$");
    expect(readiness).toContain("pg_catalog.sha256(");
    expect(readiness).toContain(
      "actual_owner IS DISTINCT FROM 'periapsis_migrator'",
    );
    expect(readiness).toContain(
      "ARRAY['search_path=pg_catalog, public, app']::text[]",
    );
    expect(readiness).toContain(
      ") IS DISTINCT FROM 22 OR pg_catalog.to_regprocedure(",
    );
    expect(readiness).toContain(
      "'app.get_tenant_ldap_bind_secret_envelope_v1(uuid)'",
    );
    expect(readiness).toContain(
      "pg_catalog.pg_get_function_result(function_oid)",
    );
    for (const scalarResult of [
      "'app.archive_tenant_ldap_provider_v1(uuid,integer,text,uuid,uuid,inet,text,text)', 'integer'",
      "'app.bind_local_login_identifier_v1()', 'trigger'",
      "'app.get_tenant_ldap_bind_secret_id_v1(uuid)', 'uuid'",
      "'app.private_replace_tenant_ldap_configuration_v1(uuid,uuid,uuid,jsonb,jsonb)', 'void'",
      "'app.verify_identity_keyring_v1(integer[],bytea[],integer)', 'boolean'",
    ]) {
      expect(readiness).toContain(scalarResult);
    }
    expect(readiness).toContain("relation.relforcerowsecurity");
    expect(readiness).toContain("pg_catalog.pg_policy AS policy");
    expect(readiness).toContain("pg_catalog.has_table_privilege(");
    expect(readiness).toContain("pg_catalog.has_any_column_privilege(");
    expect(readiness).toContain(
      "constraint_record.conrelid = pg_catalog.to_regclass(",
    );
    expect(readiness).toContain("constraint_record.convalidated");
    expect(readiness).toContain(
      'constraint_record.contype = expected.constraint_type::"char"',
    );
    expect(readiness).toContain("NOT constraint_record.condeferrable");
    expect(readiness).toContain(
      "pg_catalog.pg_get_constraintdef(constraint_record.oid, true)",
    );
    expect(readiness).toContain(
      "pg_catalog.pg_get_indexdef(index_record.indexrelid)",
    );
    expect(readiness).toContain("identity_keyring_versions_single_active_key");
    expect(readiness).toContain(
      "tenant_ldap_provider_test_runs_status_started_idx",
    );
    expect(readiness).toContain("permission.service_account_allowed");
    expect(readiness).toContain("FROM public.tenants AS tenant");
    expect(readiness).toContain("role.principal_kind = 'human'");
    expect(readiness).toContain(
      "public.tenant_role_delegation_ceilings AS ceiling",
    );
    expect(readiness).toContain(
      "trigger_record.tgname = expected.trigger_name",
    );
    expect(readiness).toContain(
      "trigger_record.tgtype = expected.trigger_type",
    );
    expect(readiness).toContain(
      "trigger_record.tgattr::text = expected.trigger_attributes",
    );
    expect(readiness).toContain("tenant_authorization_commands_guard");
    expect(readiness).toContain("app.guard_tenant_ldap_provider_test_run_v1()");
    expect(readiness).toContain("role.rolbypassrls");
    expect(readiness).toContain("NOT role.rolsuper");
    expect(readiness).toContain("tenant_auth_providers_archive_check");
    expect(readiness).toContain("tenant_ldap_provider_configs_pkey");
    expect(readiness).toContain("tenant_ldap_provider_urls_provider_fk");
    expect(readiness).toContain("tenant_ldap_provider_secrets_pkey");
    expect(readiness).toContain("tenant_ldap_provider_test_runs_completer_fk");
    expect(readiness).toContain(
      "tenant LDAP provider lifecycle projection is incomplete",
    );
    expect(readiness).toContain("configuration.provider_id IS NULL");
    expect(readiness).toContain("provider.archived_at IS NOT NULL");
  });

  it("publishes a 51-row v7 journal, seals the 40-row v6 bridge, and retires v5", () => {
    const current = functionBodyFrom(readiness, "schema_compatibility_v7");
    const predecessor = functionBodyFrom(readiness, "schema_compatibility_v6");
    const retired = functionBodyFrom(readiness, "schema_compatibility_v5");
    const seal = functionBodyFrom(
      readiness,
      "seal_schema_compatibility_manifest",
    );

    expect(current).toContain("journal_count = 51");
    expect(current).toContain("journal_latest_created_at = 1787637795761");
    expect(current).toContain("migration_0050_rows = 1");
    expect(current).toContain(
      "migration.created_at::text || '@' || lower(migration.hash::text)",
    );
    expect(readiness).toContain(
      "GRANT EXECUTE ON FUNCTION app.schema_compatibility_v7() TO periapsis_api, periapsis_worker",
    );

    expect(predecessor).toContain(
      "FROM app.schema_compatibility_v7() AS compatibility",
    );
    expect(predecessor).toContain("journal_count = 51");
    expect(predecessor).toContain("migration_0039_rows = 1");
    expect(predecessor).toContain("migration_0050_rows = 1");
    expect(predecessor).toContain("migration.migration_ordinal = 40");
    expect(predecessor).toContain("migration.migration_ordinal <= 40");
    expect(predecessor).toContain("WHERE identity.email IS NULL");
    expect(predecessor).toContain("identifier.verified_at IS NULL");
    expect(predecessor).toContain("profile.membership_id IS NULL");
    expect(predecessor).toContain("configuration.jit_mode <> 'disabled'");
    expect(predecessor).toContain("configuration.deprovision_mode <> 'retain'");
    expect(predecessor).toContain(
      "configuration.sync_interval_seconds IS NOT NULL",
    );

    expect(retired).toContain("0::bigint");
    expect(retired.match(/'UNSUPPORTED'::text/g)).toHaveLength(2);

    expect(seal).toContain("p_expected_count IS DISTINCT FROM 51");
    expect(seal).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 51",
    );
    expect(seal).toContain("fingerprint_entries[51] IS DISTINCT FROM");
    expect(seal).toContain(
      "FROM app.schema_compatibility_v7() AS compatibility",
    );
    expect(seal).toContain("ALTER FUNCTION app.schema_compatibility_v6()");
    expect(seal).toContain("fingerprint_entries[40]");
    expect(seal).toContain("predecessor_count IS DISTINCT FROM 40");
    expect(seal).toContain(
      "FROM app.schema_compatibility_v5() AS compatibility",
    );
    expect(readiness).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.seal_schema_compatibility_manifest/,
    );
  });

  it("requires verified TLS and keeps JIT, deprovisioning, and sync disabled until their invariants exist", () => {
    const replace = functionBodyFrom(
      crud,
      "private_replace_tenant_ldap_configuration_v1",
    );

    expect(replace).toContain(
      "actual_configuration_keys IS DISTINCT FROM expected_configuration_keys",
    );
    expect(replace).toContain(
      "p_configuration->'verifyCertificate' IS DISTINCT FROM 'true'::jsonb",
    );
    expect(replace).toContain("p_configuration->>'jitMode' <> 'disabled'");
    expect(replace).toContain("p_configuration->>'noMatchPolicy' <> 'deny'");
    expect(replace).toContain(
      "p_configuration->>'deprovisionMode' <> 'retain'",
    );
    expect(replace).toContain(
      "p_configuration->'deprovisionGraceSeconds' <> '0'::jsonb",
    );
    expect(replace).toContain(
      "p_configuration->'syncIntervalSeconds' <> 'null'::jsonb",
    );
    expect(replace).toContain("USING ERRCODE = '0A000'");
    expect(readiness).toContain("WHERE NOT configuration.verify_certificate");
  });
});
