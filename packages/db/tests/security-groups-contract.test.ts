import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const structural = readFileSync(
  resolve(packageRoot, "migrations/0018_polite_boom_boom.sql"),
  "utf8",
);
const commandContract = readFileSync(
  resolve(packageRoot, "migrations/0019_colossal_naoko.sql"),
  "utf8",
);
const tenantRbacSecurity = readFileSync(
  resolve(packageRoot, "migrations/0011_phase_2b_tenant_rbac_security.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(packageRoot, "migrations/0020_phase_2b_security_groups_security.sql"),
  "utf8",
);
const compatibility = readFileSync(
  resolve(
    packageRoot,
    "migrations/0025_authorization_compatibility_and_ownership.sql",
  ),
  "utf8",
);

function functionBody(name: string): string {
  const start = security.indexOf(`CREATE FUNCTION "app"."${name}"`);
  const replaceStart = security.indexOf(
    `CREATE OR REPLACE FUNCTION "app"."${name}"`,
  );
  const effectiveStart = start === -1 ? replaceStart : start;
  if (effectiveStart === -1) {
    throw new Error(`Missing security-group function ${name}`);
  }
  const end = security.indexOf("$function$;", effectiveStart);
  return security.slice(effectiveStart, end);
}

function compatibilityFunctionBody(name: string): string {
  const start = compatibility.indexOf(`CREATE FUNCTION "app"."${name}"`);
  if (start === -1) {
    throw new Error(`Missing compatibility function ${name}`);
  }
  const end = compatibility.indexOf("$function$;", start);
  return compatibility.slice(start, end);
}

describe("Phase 2B.2a tenant security-group database contract", () => {
  it("models tenant-bound groups and provenance-bearing edges canonically", () => {
    for (const table of [
      "tenant_security_groups",
      "tenant_security_group_memberships",
      "tenant_security_group_role_grants",
    ]) {
      expect(structural).toContain(`CREATE TABLE "${table}"`);
      expect(structural).toMatch(
        new RegExp(
          `CREATE TABLE "${table}"[\\s\\S]+?"tenant_id" uuid NOT NULL`,
        ),
      );
      expect(structural).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(`REVOKE ALL ON TABLE "public"."${table}"`);
    }

    expect(structural).toContain(
      'CONSTRAINT "tenant_security_group_memberships_membership_fk" FOREIGN KEY ("tenant_id","membership_id")',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_security_group_role_grants_role_fk" FOREIGN KEY ("tenant_id","role_id")',
    );
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_security_group_memberships_active_key"',
    );
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_security_group_role_grants_active_key"',
    );
    expect(structural.match(/"source_id" uuid NOT NULL/g)).toHaveLength(2);
  });

  it("adds exactly the staged human group permissions", () => {
    for (const permission of [
      "group.read",
      "group.manage",
      "group.membership.manage",
    ]) {
      expect(security).toContain(`'${permission}'`);
    }
    expect(security).not.toContain("operator_team.read");
    expect(security).not.toContain("operator_team.roster.manage");
    expect(security).toContain("permission.service_account_allowed IS FALSE");
    expect(security).toContain("permission_scope.scope <> 'tenant'");
  });

  it("backfills existing tenant-admin policy as one strong-version change", () => {
    expect(security).toContain("GET DIAGNOSTICS policy_rows_added = ROW_COUNT");
    expect(security).toContain(
      "GET DIAGNOSTICS ceiling_rows_added = ROW_COUNT",
    );
    expect(security).toContain("result_version := target_role.version + 1");
    expect(security).toContain("SET version = result_version");
    expect(security).toContain(
      "tenant_admin role version is exhausted during security-group backfill",
    );
    expect(security).toContain("'prior_version', target_role.version");
    expect(security).toContain("'result_version', result_version");
  });

  it("extends payload-bound command replay validation for every new create", () => {
    for (const operation of [
      "tenant_security_group.create",
      "tenant_security_group_membership.create",
      "tenant_security_group_role_grant.create",
    ]) {
      expect(commandContract).toContain(`'${operation}'`);
      expect(security).toContain(`NEW.operation = '${operation}'`);
      expect(security).toContain(`command.operation = '${operation}'`);
    }
    expect(security.match(/canonical_request_digest/g)).toHaveLength(12);
    expect(security).toContain(
      "idempotency key was already used for a different request",
    );

    const membershipCreate = functionBody("add_tenant_security_group_member");
    expect(membershipCreate.indexOf("IF FOUND THEN")).toBeLessThan(
      membershipCreate.indexOf(
        "security group membership expiry must be in the future",
      ),
    );
  });

  it("unions direct and group authority while preserving both source owners", () => {
    const permissionResolver = functionBody(
      "resolve_current_tenant_human_authority",
    );
    const rolePathResolver = functionBody(
      "resolve_current_tenant_human_role_grant_paths",
    );

    expect(permissionResolver).toContain(
      "public.tenant_membership_role_grants AS direct_grant",
    );
    expect(permissionResolver).toContain(
      "public.tenant_security_group_memberships AS group_member",
    );
    expect(permissionResolver).toContain(
      "public.tenant_security_group_role_grants AS group_grant",
    );
    expect(permissionResolver).toContain("member_source.retired_at IS NULL");
    expect(permissionResolver).toContain("grant_source.retired_at IS NULL");
    expect(permissionResolver).toContain("security_group.archived_at IS NULL");
    expect(permissionResolver).toContain("GROUP BY effective.permission_key");

    for (const column of [
      "role_source_id",
      "role_source_kind",
      "role_source_authoritative",
      "role_source_retired_at",
      "group_membership_id",
      "membership_source_id",
      "membership_source_kind",
      "membership_source_authoritative",
      "membership_source_retired_at",
      "effective_expires_at",
    ]) {
      expect(rolePathResolver).toContain(column);
    }
    expect(rolePathResolver).toContain("LIMIT p_limit");
    expect(rolePathResolver).not.toContain("tenant_role_permissions");
  });

  it("serializes all authority-changing group rows on the tenant revision", () => {
    for (const trigger of [
      "tenant_security_groups_touch",
      "tenant_security_group_memberships_touch",
      "tenant_security_group_role_grants_touch",
    ]) {
      expect(security).toContain(`CREATE TRIGGER "${trigger}"`);
    }
    expect(security.match(/touch_tenant_authorization_row/g)?.length).toBe(3);
    expect(
      security.match(/lock_current_tenant_authorization_state/g)?.length,
    ).toBeGreaterThanOrEqual(9);
  });

  it("requires exact lifetime consequence checks on every live path mutation", () => {
    for (const name of [
      "add_tenant_security_group_member",
      "revoke_tenant_security_group_membership",
      "grant_tenant_security_group_role",
      "revoke_tenant_security_group_role_grant",
      "archive_tenant_security_group",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("role.grant");
      expect(body).toMatch(
        /assert_actor_can_(?:grant_role|change_security_group)/,
      );
    }

    const statusMutation = functionBody("set_tenant_user_membership_status");
    expect(statusMutation).toContain(
      "public.tenant_security_group_memberships AS group_member",
    );
    expect(statusMutation).toContain("earliest_authorization_expiry");
    expect(statusMutation).toContain("group_member.expires_at");
    expect(statusMutation).toContain("group_grant.expires_at");
    expect(statusMutation).toContain("LIMIT 501");

    const rolePolicyMutation = functionBody("replace_tenant_role_policy");
    expect(rolePolicyMutation).toContain(
      "public.tenant_security_group_role_grants AS group_grant",
    );
    expect(rolePolicyMutation).toContain("SELECT group_grant.expires_at");
    expect(rolePolicyMutation).toContain("max(live_grants.expires_at)");
    expect(rolePolicyMutation).toContain(
      "WHEN has_live_grants THEN maximum_grant_expiry",
    );

    const groupRoleGrant = functionBody("grant_tenant_security_group_role");
    expect(groupRoleGrant).toContain(
      "app.assert_actor_can_grant_role(p_role_id, p_expires_at)",
    );
    expect(tenantRbacSecurity).toContain(
      "p_expires_at <= transaction_timestamp()",
    );
    expect(tenantRbacSecurity).toContain(
      "RAISE EXCEPTION 'role grant expiry must be in the future'",
    );
    expect(tenantRbacSecurity).toContain("USING ERRCODE = '22023'");

    const groupRoleRevoke = functionBody(
      "revoke_tenant_security_group_role_grant",
    );
    expect(groupRoleRevoke).toContain(
      "security_group.archived_at AS group_archived_at",
    );
    expect(groupRoleRevoke).toContain("role.archived_at AS role_archived_at");
    expect(groupRoleRevoke).toContain("target_grant.group_archived_at IS NULL");
    expect(groupRoleRevoke).toContain("target_grant.role_archived_at IS NULL");
  });

  it("binds nested resources to the requested group inside getters and revokes", () => {
    for (const name of [
      "get_tenant_security_group_membership",
      "revoke_tenant_security_group_membership",
      "get_tenant_security_group_role_grant",
      "revoke_tenant_security_group_role_grant",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("p_group_id uuid");
      expect(body).toContain("group_id = p_group_id");
    }
  });

  it("keeps edge source ownership exact and source retirement immediately effective", () => {
    for (const name of [
      "revoke_tenant_security_group_membership",
      "revoke_tenant_security_group_role_grant",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("source.kind = 'manual'");
      expect(body).toContain("source.key = 'manual'");
      expect(body).toContain("source.protected");
      expect(body).toContain("source.retired_at IS NULL");
    }
    expect(security).toContain("member_source.retired_at IS NULL");
    expect(security).toContain("grant_source.retired_at IS NULL");
  });

  it("preserves the four legacy group-edge ABIs and exposes exact ownership through v2", () => {
    const functions = [
      {
        legacy: "list_tenant_security_group_memberships",
        current: "list_tenant_security_group_memberships_v2",
      },
      {
        legacy: "get_tenant_security_group_membership",
        current: "get_tenant_security_group_membership_v2",
      },
      {
        legacy: "list_tenant_security_group_role_grants",
        current: "list_tenant_security_group_role_grants_v2",
      },
      {
        legacy: "get_tenant_security_group_role_grant",
        current: "get_tenant_security_group_role_grant_v2",
      },
    ];

    for (const { legacy, current } of functions) {
      expect(compatibility).not.toMatch(
        new RegExp(
          `CREATE(?: OR REPLACE)? FUNCTION "app"\\."${legacy}"\\s*\\(`,
        ),
      );
      expect(compatibility).not.toContain(`DROP FUNCTION "app"."${legacy}"`);

      const body = compatibilityFunctionBody(current);
      expect(body).toContain(`app.${legacy}(`);
      expect(body).toContain("managed_by_authorization_api boolean");
      expect(body).toContain("source.key = 'manual'");
      expect(body).toContain("source.kind = 'manual'");
      expect(body).toContain("source.protected");
      expect(body).toContain("source.retired_at IS NULL");
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(compatibility).toContain(
        `GRANT EXECUTE ON FUNCTION "app"."${current}"`,
      );
    }
  });

  it("audits visible and automatic group mutations without losing superseded IDs", () => {
    for (const action of [
      "tenant.security_group.created",
      "tenant.security_group.metadata_updated",
      "tenant.security_group.archived",
      "tenant.security_group.membership_added",
      "tenant.security_group.membership_revoked",
      "tenant.security_group.role_grant_created",
      "tenant.security_group.role_grant_revoked",
    ]) {
      expect(security).toContain(`'${action}'`);
    }
    expect(security).toContain("superseded_memberships");
    expect(security).toContain("superseded_role_grants");
    expect(security).toContain("prior_version");
    expect(security).toContain("result_version");
  });

  it("keeps recovery direct-only and retires the incomplete role resolver", () => {
    expect(security).not.toContain(
      'CREATE CONSTRAINT TRIGGER "tenant_security_group_recovery_guard"',
    );
    expect(security).toContain(
      'DROP FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer)',
    );
    expect(security).not.toContain(
      'GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grants"',
    );
    expect(security).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) TO "periapsis_api"',
    );
  });

  it("keeps every exposed routine fixed-search-path, bounded, and explicitly granted", () => {
    for (const name of [
      "resolve_current_tenant_human_role_grant_paths",
      "list_tenant_security_groups",
      "get_tenant_security_group",
      "create_tenant_security_group",
      "update_tenant_security_group_metadata",
      "archive_tenant_security_group",
      "list_tenant_security_group_memberships",
      "get_tenant_security_group_membership",
      "add_tenant_security_group_member",
      "revoke_tenant_security_group_membership",
      "list_tenant_security_group_role_grants",
      "get_tenant_security_group_role_grant",
      "grant_tenant_security_group_role",
      "revoke_tenant_security_group_role_grant",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(security).toContain(`GRANT EXECUTE ON FUNCTION "app"."${name}"`);
    }
    expect(security).toContain("NOT BETWEEN 1 AND 101");
    expect(security).toContain("NOT BETWEEN 1 AND 201");
    expect(security).toContain("LIMIT 501");
  });
});
