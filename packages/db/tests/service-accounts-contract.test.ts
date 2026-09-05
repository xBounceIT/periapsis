import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import { tenantPermissions, tenantRoles } from "../src/schema/authorization.js";
import {
  tenantApiCredentialCommands,
  tenantApiCredentialNetworks,
  tenantApiCredentialPermissions,
  tenantApiCredentials,
  tenantServiceAccountRoleGrants,
  tenantServiceAccounts,
} from "../src/schema/service-accounts.js";

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

function readGeneratedMigration(prefix: string): {
  fileName: string;
  source: string;
} {
  const matches = readdirSync(resolve(packageRoot, "migrations")).filter(
    (fileName) => new RegExp(`^${prefix}_[a-z0-9_]+[.]sql$`).test(fileName),
  );
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one generated ${prefix} migration, found ${matches.length}`,
    );
  }
  return {
    fileName: matches[0]!,
    source: readRequiredMigration(matches[0]!),
  };
}

const preflight = readRequiredMigration("0033_service_principal_preflight.sql");
const additive = readGeneratedMigration("0034");
const finalStructural = readGeneratedMigration("0036");
const structural = `${additive.source}\n${finalStructural.source}`;

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

describe("service-account structural database contract", () => {
  it("fails closed before changing legacy principal and audit attribution", () => {
    for (const table of [
      "audit_events",
      "alerts",
      "tenant_roles",
      "tenant_permissions",
    ]) {
      expect(preflight).toContain(
        `LOCK TABLE "public"."${table}" IN SHARE ROW EXCLUSIVE MODE`,
      );
    }

    expect(preflight).toContain("event.actor_type = 'service_account'");
    expect(preflight).toContain("role.key = 'service_account'");
    expect(preflight).toContain("role.system_role IS DISTINCT FROM true");
    expect(preflight).toContain("role.archived_at IS NOT NULL");
    for (const permission of [
      "alert.create",
      "service_account.credential.manage",
      "service_account.manage",
      "service_account.read",
    ]) {
      expect(preflight).toContain(`'${permission}'`);
    }
    expect(preflight).toContain("membership.tenant_id = alert.tenant_id");
    expect(preflight).toContain("membership.user_id = alert.created_by");
    expect(
      preflight.match(/USING ERRCODE = '/g)?.length,
    ).toBeGreaterThanOrEqual(4);
  });

  it("adds an enforced human-or-service-account role kind", () => {
    const roleConfig = getTableConfig(tenantRoles);
    const principalKind = roleConfig.columns.find(
      (column) => column.name === "principal_kind",
    );

    expect(principalKind?.notNull).toBe(true);
    expect(roleConfig.uniqueConstraints.map((item) => item.name)).toContain(
      "tenant_roles_tenant_id_principal_kind_key",
    );
    expect(roleConfig.checks.map((item) => item.name)).toContain(
      "tenant_roles_protected_principal_kind_check",
    );
    expect(additive.source).toContain(
      `CREATE TYPE "public"."tenant_principal_kind" AS ENUM('human', 'service_account')`,
    );
    expect(additive.source).toContain(
      '"principal_kind" "tenant_principal_kind"',
    );
    expect(additive.source).not.toMatch(
      /CREATE TABLE "tenant_service_accounts"|INSERT INTO public\.tenant_permissions/,
    );
  });

  it("keeps every service-principal row tenant-bound and behind forced-RLS preparation", () => {
    const tenantTables = [
      tenantServiceAccounts,
      tenantServiceAccountRoleGrants,
      tenantApiCredentials,
      tenantApiCredentialPermissions,
      tenantApiCredentialNetworks,
      tenantApiCredentialCommands,
    ];

    for (const table of tenantTables) {
      const config = getTableConfig(table);
      expect(
        config.columns.find((column) => column.name === "tenant_id")?.notNull,
      ).toBe(true);
      const id = config.columns.find((column) => column.name === "id");
      if (id !== undefined) {
        expect(id.notNull).toBe(true);
      }
      expect(config.enableRLS).toBe(true);
      const policyNames = config.policies.map((policy) => policy.name);
      if (config.name === "tenant_service_accounts") {
        expect(policyNames).toEqual([
          "tenant_service_accounts_ticket_attribution",
        ]);
      } else {
        expect(policyNames).toHaveLength(0);
      }
      expect(finalStructural.source).toContain(`CREATE TABLE "${config.name}"`);
      expect(finalStructural.source).toContain(
        `ALTER TABLE "${config.name}" ENABLE ROW LEVEL SECURITY`,
      );
    }

    expect(finalStructural.source).not.toMatch(
      /FORCE ROW LEVEL SECURITY|CREATE POLICY|CREATE FUNCTION|GRANT |INSERT INTO/,
    );
  });

  it("models permanent account and role-grant lifecycles with tenant-leading foreign keys", () => {
    const accountConfig = getTableConfig(tenantServiceAccounts);
    expect(columnNames(tenantServiceAccounts)).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "created_by_membership_id",
        "archived_at",
        "archived_by_membership_id",
        "archive_reason",
        "version",
      ]),
    );
    expect(accountConfig.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "tenant_service_accounts_archive_check",
        "tenant_service_accounts_version_check",
        "tenant_service_accounts_updated_check",
      ]),
    );
    expect(foreignKeyNames(tenantServiceAccounts)).toEqual(
      expect.arrayContaining([
        "tenant_service_accounts_creator_membership_fk",
        "tenant_service_accounts_archiver_membership_fk",
      ]),
    );

    const grantConfig = getTableConfig(tenantServiceAccountRoleGrants);
    expect(
      grantConfig.indexes.some(
        (item) => item.config.unique && item.config.where,
      ),
    ).toBe(true);
    expect(grantConfig.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "tenant_service_account_role_grants_role_kind_check",
        "tenant_service_account_role_grants_expiry_check",
        "tenant_service_account_role_grants_revocation_check",
        "tenant_service_account_role_grants_version_check",
      ]),
    );
    expect(foreignKeyNames(tenantServiceAccountRoleGrants)).toEqual(
      expect.arrayContaining([
        "tenant_service_account_role_grants_account_fk",
        "tenant_service_account_role_grants_role_principal_fk",
        "tenant_service_account_role_grants_source_fk",
        "tenant_service_account_role_grants_grantor_fk",
        "tenant_service_account_role_grants_revoker_fk",
      ]),
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","role_id","role_principal_kind") REFERENCES "public"."tenant_roles"("tenant_id","id","principal_kind")',
    );
  });

  it("uses tenant-leading composite keys for every tenant-owned principal edge", () => {
    const tenantLeadingForeignKeys = [
      [
        "tenant_service_accounts_creator_membership_fk",
        '"tenant_id","created_by_membership_id"',
      ],
      [
        "tenant_service_account_role_grants_account_fk",
        '"tenant_id","service_account_id"',
      ],
      [
        "tenant_service_account_role_grants_source_fk",
        '"tenant_id","source_id"',
      ],
      ["tenant_api_credentials_account_fk", '"tenant_id","service_account_id"'],
      [
        "tenant_api_credentials_issuer_fk",
        '"tenant_id","issued_by_membership_id"',
      ],
      [
        "tenant_api_credential_permissions_credential_fk",
        '"tenant_id","credential_id"',
      ],
      [
        "tenant_api_credential_networks_credential_fk",
        '"tenant_id","credential_id"',
      ],
      [
        "tenant_api_credential_commands_result_fk",
        '"tenant_id","service_account_id","result_credential_id"',
      ],
    ] as const;

    for (const [constraint, columns] of tenantLeadingForeignKeys) {
      expect(finalStructural.source).toContain(
        `CONSTRAINT "${constraint}" FOREIGN KEY (${columns})`,
      );
    }
  });

  it("stores a bounded locator and keyed digest but no bearer secret", () => {
    const credentialConfig = getTableConfig(tenantApiCredentials);
    const credentialColumns = columnNames(tenantApiCredentials);

    expect(credentialColumns).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "service_account_id",
        "format_version",
        "locator",
        "key_version",
        "secret_digest",
        "expires_at",
        "revoked_at",
        "last_used_at",
        "version",
      ]),
    );
    expect(credentialColumns).not.toEqual(
      expect.arrayContaining(["secret", "token", "plaintext", "token_hash"]),
    );
    expect(credentialConfig.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "tenant_api_credentials_secret_material_check",
        "tenant_api_credentials_expiry_check",
        "tenant_api_credentials_revocation_check",
      ]),
    );
    expect(structural).toContain(
      'octet_length("tenant_api_credentials"."locator") = 16',
    );
    expect(structural).toContain(
      'octet_length("tenant_api_credentials"."secret_digest") = 32',
    );
    expect(structural).toContain("interval '90 days'");
    expect(structural).not.toMatch(
      /"(?:bearer_)?(?:plain_?)?(?:token|secret)"\s+(?:text|bytea)/i,
    );
  });

  it("enforces an exact service-account permission allowlist and native CIDRs structurally", () => {
    const permissionConfig = getTableConfig(tenantApiCredentialPermissions);
    const allowedColumn = permissionConfig.columns.find(
      (column) => column.name === "permission_service_account_allowed",
    );
    expect(allowedColumn?.notNull).toBe(true);
    expect(foreignKeyNames(tenantApiCredentialPermissions)).toEqual(
      expect.arrayContaining([
        "tenant_api_credential_permissions_credential_fk",
        "tenant_api_credential_permissions_catalog_fk",
        "tenant_api_credential_permissions_scope_fk",
      ]),
    );
    expect(permissionConfig.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "tenant_api_credential_permissions_allowed_check",
        "tenant_api_credential_permissions_not_platform_check",
      ]),
    );
    expect(
      getTableConfig(tenantPermissions).uniqueConstraints.map(
        (constraint) => constraint.name,
      ),
    ).toContain("tenant_permissions_id_service_account_allowed_key");
    expect(structural).toContain(
      'FOREIGN KEY ("permission_id","permission_service_account_allowed") REFERENCES "public"."tenant_permissions"("id","service_account_allowed")',
    );

    const network = getTableConfig(tenantApiCredentialNetworks).columns.find(
      (column) => column.name === "network",
    );
    expect(network?.notNull).toBe(true);
    expect(network?.getSQLType()).toBe("cidr");
    expect(foreignKeyNames(tenantApiCredentialNetworks)).toContain(
      "tenant_api_credential_networks_credential_fk",
    );
  });

  it("keeps one-time issue and rotation tombstones permanent and result-bound", () => {
    const commandConfig = getTableConfig(tenantApiCredentialCommands);
    const commandColumns = columnNames(tenantApiCredentialCommands);

    expect(commandColumns).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "service_account_id",
        "actor_membership_id",
        "operation",
        "key_digest",
        "request_digest",
        "result_credential_id",
        "result_version",
      ]),
    );
    expect(commandColumns).not.toContain("expires_at");
    expect(commandConfig.uniqueConstraints.map((item) => item.name)).toContain(
      "tenant_api_credential_commands_replay_key",
    );
    expect(commandConfig.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "tenant_api_credential_commands_operation_check",
        "tenant_api_credential_commands_digest_check",
        "tenant_api_credential_commands_result_version_check",
      ]),
    );
    expect(foreignKeyNames(tenantApiCredentialCommands)).toEqual(
      expect.arrayContaining([
        "tenant_api_credential_commands_account_fk",
        "tenant_api_credential_commands_actor_fk",
        "tenant_api_credential_commands_result_fk",
      ]),
    );
    expect(structural).toContain("'service_account.credential.issue'");
    expect(structural).toContain("'service_account.credential.rotate'");
  });
});
