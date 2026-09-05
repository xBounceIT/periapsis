import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  alerts,
  authChallenges,
  authRateLimits,
  authSessions,
  auditChainHeads,
  auditEvents,
  localBreakGlassCredentials,
  outboxEvents,
  operatorTeamAssignmentEpochs,
  operatorTeamRosterEntries,
  operatorTeams,
  platformAuditChainHead,
  platformAuditEvents,
  platformBootstrapEnrollments,
  platformBootstrapState,
  platformPermissions,
  platformRolePermissions,
  platformRoles,
  platformCommands,
  recoveryCodes,
  tenantAuthorizationCommands,
  tenantAuthorizationSources,
  tenantAuthorizationStates,
  tenantMembershipRoleGrants,
  tenantMemberships,
  tenantPermissionScopes,
  tenantPermissions,
  tenantRoleDelegationCeilings,
  tenantRolePermissions,
  tenantRoles,
  tenantSecurityGroupMemberships,
  tenantSecurityGroupRoleGrants,
  tenantSecurityGroups,
  tenants,
  tenantsApiCurrentSelectPolicy,
  totpCredentials,
  userPlatformRoles,
  users,
  usersApiTenantSelectPolicy,
} from "../src/schema/index.js";

const tenantOwnedTables = [
  tenantMemberships,
  alerts,
  auditEvents,
  auditChainHeads,
  outboxEvents,
] as const;

describe("canonical tenant schema", () => {
  it("defines every UUIDv7 check with fail-closed three-valued logic", () => {
    const schemaDirectory = resolve(import.meta.dirname, "../src/schema");
    const source = readdirSync(schemaDirectory)
      .filter((fileName) => fileName.endsWith(".ts"))
      .map((fileName) =>
        readFileSync(resolve(schemaDirectory, fileName), "utf8"),
      )
      .join("\n");

    const uuidChecks = source.match(/uuid_extract_version/g) ?? [];
    const failClosedChecks =
      source.match(/uuid_extract_version\([^)]*\) = 7\) is true/g) ?? [];

    expect(uuidChecks.length).toBeGreaterThan(7);
    expect(failClosedChecks).toHaveLength(uuidChecks.length);
  });

  it("keeps every customer-owned row tenant-bound and RLS-enabled", () => {
    for (const table of tenantOwnedTables) {
      const config = getTableConfig(table);
      const tenantColumn = config.columns.find(
        (column) => column.name === "tenant_id",
      );

      expect(tenantColumn, `${config.name} must have tenant_id`).toBeDefined();
      expect(
        tenantColumn?.notNull,
        `${config.name}.tenant_id must be NOT NULL`,
      ).toBe(true);
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies.length,
        `${config.name} must define an explicit policy`,
      ).toBeGreaterThan(0);
    }
  });

  it("keeps platform identities separate from memberships", () => {
    const userColumns = getTableConfig(users).columns.map(
      (column) => column.name,
    );
    const membershipColumns = getTableConfig(tenantMemberships).columns.map(
      (column) => column.name,
    );

    expect(userColumns).not.toContain("tenant_id");
    expect(membershipColumns).toEqual(
      expect.arrayContaining(["tenant_id", "user_id", "role", "status"]),
    );
  });

  it("models the root tenant and global user tables with RLS", () => {
    for (const table of [tenants, users]) {
      const config = getTableConfig(table);
      expect(config.enableRLS).toBe(true);
    }

    expect(tenantsApiCurrentSelectPolicy.name).toBe(
      "tenants_api_select_current",
    );
    expect(usersApiTenantSelectPolicy.name).toBe("users_api_tenant_select");
  });

  it("uses tenant-consistent creator membership on alerts", () => {
    const foreignKeyNames = getTableConfig(alerts).foreignKeys.map(
      (foreignKey) => foreignKey.getName(),
    );

    expect(foreignKeyNames).toContain("alerts_creator_membership_fk");
  });

  it("has no runtime policy granting audit mutation", () => {
    const policyNames = getTableConfig(auditEvents).policies.map(
      (policy) => policy.name,
    );

    expect(policyNames).toEqual(
      expect.arrayContaining([
        "audit_events_api_tenant",
        "audit_events_worker_access",
        "audit_events_notifier_access",
        "audit_events_auditor_select",
      ]),
    );
  });

  it("keeps authentication and platform authority tables behind forced migration grants", () => {
    const protectedTables = [
      localBreakGlassCredentials,
      totpCredentials,
      recoveryCodes,
      authChallenges,
      authSessions,
      authRateLimits,
      platformBootstrapEnrollments,
      platformBootstrapState,
      platformPermissions,
      platformRoles,
      platformRolePermissions,
      userPlatformRoles,
      operatorTeams,
      platformCommands,
    ] as const;

    for (const table of protectedTables) {
      const config = getTableConfig(table);
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies,
        `${config.name} must not expose runtime rows`,
      ).toHaveLength(0);
    }

    for (const table of [
      platformAuditEvents,
      platformAuditChainHead,
    ] as const) {
      const config = getTableConfig(table);
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies,
        `${config.name} must expose only the bounded reader`,
      ).toHaveLength(1);
      expect(config.policies[0]?.name).toMatch(/_reader_select$/);
    }
  });

  it("keeps the tenant authorization catalog and tenant-owned policy rows behind definer functions", () => {
    const protectedAuthorizationTables = [
      tenantPermissions,
      tenantPermissionScopes,
      tenantAuthorizationSources,
      tenantAuthorizationStates,
      tenantAuthorizationCommands,
      tenantRoles,
      tenantRolePermissions,
      tenantRoleDelegationCeilings,
      tenantMembershipRoleGrants,
      tenantSecurityGroups,
      tenantSecurityGroupMemberships,
      tenantSecurityGroupRoleGrants,
      operatorTeamAssignmentEpochs,
      operatorTeamRosterEntries,
    ] as const;
    const tenantBoundAuthorizationTables = [
      tenantAuthorizationSources,
      tenantAuthorizationStates,
      tenantAuthorizationCommands,
      tenantRoles,
      tenantRolePermissions,
      tenantRoleDelegationCeilings,
      tenantMembershipRoleGrants,
      tenantSecurityGroups,
      tenantSecurityGroupMemberships,
      tenantSecurityGroupRoleGrants,
      operatorTeamAssignmentEpochs,
      operatorTeamRosterEntries,
    ] as const;

    for (const table of protectedAuthorizationTables) {
      const config = getTableConfig(table);
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies,
        `${config.name} must not expose direct runtime access`,
      ).toHaveLength(0);
    }

    for (const table of tenantBoundAuthorizationTables) {
      const config = getTableConfig(table);
      const tenantColumn = config.columns.find(
        (column) => column.name === "tenant_id",
      );
      expect(tenantColumn, `${config.name} must have tenant_id`).toBeDefined();
      expect(tenantColumn?.notNull).toBe(true);
    }
  });

  it("uses tenant-consistent membership references throughout authorization", () => {
    const membershipConstraintNames = getTableConfig(
      tenantMemberships,
    ).uniqueConstraints.map((constraint) => constraint.name);
    expect(membershipConstraintNames).toContain(
      "tenant_memberships_tenant_id_key",
    );

    expect(
      getTableConfig(tenantAuthorizationCommands).foreignKeys.map(
        (foreignKey) => foreignKey.getName(),
      ),
    ).toContain("tenant_authorization_commands_actor_fk");
    expect(
      getTableConfig(tenantRoles).foreignKeys.map((foreignKey) =>
        foreignKey.getName(),
      ),
    ).toContain("tenant_roles_creator_membership_fk");
    expect(
      getTableConfig(tenantRolePermissions).foreignKeys.map((foreignKey) =>
        foreignKey.getName(),
      ),
    ).toContain("tenant_role_permissions_creator_fk");
    expect(
      getTableConfig(tenantRoleDelegationCeilings).foreignKeys.map(
        (foreignKey) => foreignKey.getName(),
      ),
    ).toContain("tenant_role_delegation_creator_fk");
    expect(
      getTableConfig(tenantMembershipRoleGrants).foreignKeys.map((foreignKey) =>
        foreignKey.getName(),
      ),
    ).toEqual(
      expect.arrayContaining([
        "tenant_membership_role_grants_membership_fk",
        "tenant_membership_role_grants_grantor_fk",
        "tenant_membership_role_grants_revoker_fk",
      ]),
    );
    expect(
      getTableConfig(tenantSecurityGroups).foreignKeys.map((foreignKey) =>
        foreignKey.getName(),
      ),
    ).toContain("tenant_security_groups_creator_membership_fk");
    expect(
      getTableConfig(tenantSecurityGroupMemberships).foreignKeys.map(
        (foreignKey) => foreignKey.getName(),
      ),
    ).toEqual(
      expect.arrayContaining([
        "tenant_security_group_memberships_group_fk",
        "tenant_security_group_memberships_membership_fk",
        "tenant_security_group_memberships_source_fk",
        "tenant_security_group_memberships_grantor_fk",
        "tenant_security_group_memberships_revoker_fk",
      ]),
    );
    expect(
      getTableConfig(tenantSecurityGroupRoleGrants).foreignKeys.map(
        (foreignKey) => foreignKey.getName(),
      ),
    ).toEqual(
      expect.arrayContaining([
        "tenant_security_group_role_grants_group_fk",
        "tenant_security_group_role_grants_role_fk",
        "tenant_security_group_role_grants_source_fk",
        "tenant_security_group_role_grants_grantor_fk",
        "tenant_security_group_role_grants_revoker_fk",
      ]),
    );
    expect(
      getTableConfig(operatorTeamAssignmentEpochs).foreignKeys.map(
        (foreignKey) => foreignKey.getName(),
      ),
    ).toEqual(
      expect.arrayContaining([
        "operator_team_assignment_epochs_assigner_fk",
        "operator_team_assignment_epochs_ender_fk",
      ]),
    );
    expect(
      getTableConfig(operatorTeamRosterEntries).foreignKeys.map((foreignKey) =>
        foreignKey.getName(),
      ),
    ).toEqual(
      expect.arrayContaining([
        "operator_team_roster_entries_epoch_fk",
        "operator_team_roster_entries_membership_fk",
        "operator_team_roster_entries_source_fk",
        "operator_team_roster_entries_grantor_fk",
        "operator_team_roster_entries_revoker_fk",
      ]),
    );
  });

  it("stores only bounded idempotency digests and a versioned result reference", () => {
    const config = getTableConfig(tenantAuthorizationCommands);
    const columnNames = config.columns.map((column) => column.name);
    const checkNames = config.checks.map((constraint) => constraint.name);

    expect(columnNames).toEqual(
      expect.arrayContaining([
        "key_digest",
        "request_digest",
        "result_resource_id",
        "result_version",
        "expires_at",
      ]),
    );
    expect(columnNames).not.toContain("idempotency_key");
    expect(checkNames).toEqual(
      expect.arrayContaining([
        "tenant_authorization_commands_digest_check",
        "tenant_authorization_commands_retention_check",
      ]),
    );
  });

  it("requires complete role-grant revocation provenance", () => {
    const authorizationSource = readFileSync(
      resolve(import.meta.dirname, "../src/schema/authorization.ts"),
      "utf8",
    );

    expect(authorizationSource).toMatch(
      /tenant_membership_role_grants_revocation_check[\s\S]+?revokedAt\} is not null[\s\S]+?revokedByMembershipId\} is not null[\s\S]+?revokeReason\} is not null/,
    );
  });

  it("stores only a versioned Argon2 PHC password representation", () => {
    const columns = getTableConfig(localBreakGlassCredentials).columns.map(
      (column) => column.name,
    );

    expect(columns).toEqual(
      expect.arrayContaining([
        "password_phc",
        "password_algorithm",
        "password_version",
      ]),
    );
    expect(columns).not.toEqual(
      expect.arrayContaining(["password", "password_plaintext"]),
    );
  });

  it("binds one live MFA challenge and bootstrap enrollment to proof meters", () => {
    const challengeConfig = getTableConfig(authChallenges);
    const challengeColumns = challengeConfig.columns.map(
      (column) => column.name,
    );
    const enrollmentColumns = getTableConfig(
      platformBootstrapEnrollments,
    ).columns.map((column) => column.name);
    const unconsumedIndex = challengeConfig.indexes.find(
      (index) => index.config.name === "auth_challenges_user_unconsumed_key",
    );

    expect(challengeColumns).toEqual(
      expect.arrayContaining([
        "challenge_rate_key_digest",
        "mfa_rate_key_digest",
        "login_account_rate_key_digest",
      ]),
    );
    expect(enrollmentColumns).toContain("enrollment_rate_key_digest");
    expect(unconsumedIndex?.config.unique).toBe(true);
    expect(unconsumedIndex?.config.where).toBeDefined();
  });

  it("stores only a non-secret verifier for master-key consistency", () => {
    const stateConfig = getTableConfig(platformBootstrapState);
    const stateColumns = stateConfig.columns.map((column) => column.name);

    expect(stateColumns).toEqual(
      expect.arrayContaining([
        "master_key_verifier",
        "master_key_verifier_bound_at",
      ]),
    );
    expect(stateColumns).not.toContain("master_key");
    expect(stateConfig.checks.map((constraint) => constraint.name)).toContain(
      "platform_bootstrap_state_protected_configuration_check",
    );
  });

  it("requires every session to retain its rotation family", () => {
    const familyColumn = getTableConfig(authSessions).columns.find(
      (column) => column.name === "rotation_family_id",
    );

    expect(familyColumn?.notNull).toBe(true);
  });
});
