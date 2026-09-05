import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const structural = readFileSync(
  resolve(packageRoot, "migrations/0027_flimsy_bloodscream.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(packageRoot, "migrations/0028_phase_2b_operator_teams_security.sql"),
  "utf8",
);
const authorizationSecurity = readFileSync(
  resolve(packageRoot, "migrations/0011_phase_2b_tenant_rbac_security.sql"),
  "utf8",
);
const mutationResult = readFileSync(
  resolve(
    packageRoot,
    "migrations/0022_tenant_role_policy_mutation_result.sql",
  ),
  "utf8",
);

function functionBodyFrom(source: string, name: string): string {
  const create = source.indexOf(`CREATE FUNCTION "app"."${name}"`);
  const replace = source.indexOf(`CREATE OR REPLACE FUNCTION "app"."${name}"`);
  const start = create === -1 ? replace : create;
  if (start === -1) {
    throw new Error(`Missing operator-team function ${name}`);
  }
  const end = source.indexOf("$function$;", start);
  return source.slice(start, end);
}

function functionBody(name: string): string {
  return functionBodyFrom(security, name);
}

describe("Phase 2B.2b operator-team security database contract", () => {
  it("hardens all four tables without exposing a table-level runtime boundary", () => {
    for (const table of [
      "operator_teams",
      "platform_commands",
      "operator_team_assignment_epochs",
      "operator_team_roster_entries",
    ]) {
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" OWNER TO "periapsis_migrator"`,
      );
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `REVOKE ALL ON TABLE "public"."${table}" FROM PUBLIC, "periapsis_api"`,
      );
      expect(security).not.toMatch(
        new RegExp(`GRANT [^;]+ ON TABLE "public"[.]"${table}"`),
      );
      expect(security).not.toContain(`CREATE POLICY "${table}`);
    }
  });

  it("installs exact human platform and tenant catalogs with one role version bump", () => {
    for (const permission of [
      "platform.operator_team.read",
      "platform.operator_team.manage",
      "operator_team.read",
      "operator_team.manage",
      "operator_team.roster.manage",
    ]) {
      expect(security).toContain(`'${permission}'`);
    }
    expect(security).toContain("permission.service_account_allowed IS FALSE");
    expect(security).toContain(
      "('operator_team.read'::text, 'operator_team'::public.authorization_scope)",
    );
    expect(security).toContain(
      "('operator_team.roster.manage'::text, 'operator_team'::public.authorization_scope)",
    );
    expect(security).toContain("role.key = 'platform_super_admin'");
    expect(security).toContain("result_version := target_role.version + 1");
    expect(security).toContain("SET version = result_version");
    expect(security).toContain("'tenant.authorization.operator_teams_enabled'");
    expect(security).toContain("'prior_version', target_role.version");
    expect(security).toContain("'result_version', result_version");
  });

  it("keeps future-tenant seed catalog-driven while legacy authority stays filtered", () => {
    const seed = functionBodyFrom(
      authorizationSecurity,
      "seed_tenant_authorization",
    );
    expect(seed).toContain(
      "FROM public.tenant_permission_scopes AS permission_scope",
    );
    expect(seed).toContain("JOIN public.tenant_permissions AS permission");
    expect(seed).not.toContain("permission.key IN");
    expect(seed).not.toContain("operator_team.read");

    const legacy = functionBody("resolve_current_tenant_human_authority");
    const current = functionBody("resolve_current_tenant_human_authority_v2");
    expect(legacy).toContain("permission_key NOT IN");
    expect(legacy).toContain("'operator_team.read'");
    expect(legacy).toContain("'operator_team.manage'");
    expect(legacy).toContain("'operator_team.roster.manage'");
    expect(current).not.toContain("permission_key NOT IN");
  });

  it("keeps predecessor authorization ABIs blind to exactly the new keys", () => {
    for (const name of [
      "get_auth_session",
      "resolve_current_tenant_human_authority",
      "list_tenant_permission_catalog",
      "get_tenant_role_policy",
    ]) {
      expect(functionBody(name)).toContain("NOT IN (");
    }
    expect(functionBody("get_auth_session")).toContain(
      "'platform.operator_team.read'",
    );
    expect(functionBody("get_auth_session")).toContain(
      "'platform.operator_team.manage'",
    );
    for (const name of [
      "resolve_current_tenant_human_authority",
      "list_tenant_permission_catalog",
      "get_tenant_role_policy",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("'operator_team.read'");
      expect(body).toContain("'operator_team.manage'");
      expect(body).toContain("'operator_team.roster.manage'");
    }

    for (const name of [
      "get_auth_session_v2",
      "resolve_current_tenant_human_authority_v2",
      "list_tenant_permission_catalog_v2",
      "get_tenant_role_policy_v2",
    ]) {
      expect(functionBody(name)).not.toContain("permission_key NOT IN");
      expect(security).toContain(`GRANT EXECUTE ON FUNCTION "app"."${name}"`);
    }
  });

  it("fails closed through the old role-policy ABI and preserves full v2 tuples", () => {
    const legacy = functionBody("replace_tenant_role_policy");
    const current = functionBody("replace_tenant_role_policy_v2");
    const currentResult = functionBody(
      "replace_tenant_role_policy_with_result_v2",
    );

    expect(legacy).toContain("app.lock_current_tenant_authorization_state()");
    expect(legacy).toContain(
      "legacy role-policy ABI cannot represent operator-team tuples",
    );
    expect(legacy).toContain("public.tenant_role_permissions AS policy");
    expect(legacy).toContain(
      "public.tenant_role_delegation_ceilings AS ceiling",
    );
    expect(legacy).toContain("app.replace_tenant_role_policy_v2(");
    expect(mutationResult).toContain("app.replace_tenant_role_policy(");

    expect(current).toContain("public.operator_team_roster_entries AS roster");
    expect(current).toContain(
      "public.operator_team_assignment_epochs AS assignment",
    );
    expect(current).toContain("assignment.ended_at IS NULL");
    expect(current).toContain("operator_team.archived_at IS NULL");
    expect(current).toContain("app.earliest_authorization_expiry(");
    expect(
      current.match(/group_member\.expires_at, group_grant\.expires_at/g),
    ).toHaveLength(2);
    expect(currentResult).toContain("app.replace_tenant_role_policy_v2(");
    expect(currentResult).toContain("permission_keys text[]");
  });

  it("keeps global CRUD human-only, payload-bound, serialized, and audited", () => {
    const list = functionBody("list_platform_operator_teams");
    const get = functionBody("get_platform_operator_team");
    const create = functionBody("create_platform_operator_team");
    const update = functionBody("update_platform_operator_team_metadata");
    const archive = functionBody("archive_platform_operator_team");

    expect(list).toContain("platform.operator_team.read");
    expect(list).toContain("active_assignment_count bigint");
    expect(list).toContain("assignment.ended_at IS NULL");
    expect(get).toContain("platform.operator_team.read");
    expect(get).toContain("platform.operator_team.manage");
    expect(get).toContain("active_assignment_count bigint");

    expect(create).toContain("canonical_request_digest");
    expect(create).toContain("public.platform_commands AS command");
    expect(create).toContain("command.operation = 'operator_team.create'");
    expect(create).toContain("replay.request_digest IS DISTINCT FROM");
    expect(create).toContain("FROM public.users AS actor");
    expect(create).toContain("FOR UPDATE");
    expect(create.indexOf("FROM public.users AS actor")).toBeLessThan(
      create.indexOf("DELETE FROM public.platform_commands AS command"),
    );
    expect(create).toContain("'platform.operator_team.created'");
    expect(update).toContain("target_team.version IS DISTINCT FROM");
    expect(update).toContain("'platform.operator_team.metadata_updated'");

    expect(archive).toContain("FOR UPDATE");
    expect(archive).toContain("assignment.ended_at IS NULL");
    expect(archive).toContain("USING ERRCODE = '23503'");
    expect(archive).toContain("'platform.operator_team.archived'");
    expect(archive).toContain("p_reason IS NULL OR btrim(p_reason) = ''");
  });

  it("serializes assignment lifecycle and atomically correlates both audits", () => {
    const start = functionBody("start_tenant_operator_team_assignment");
    const end = functionBody("end_tenant_operator_team_assignment");

    for (const body of [start, end]) {
      expect(body).toContain("app.lock_current_tenant_authorization_state()");
      expect(body).toContain("app.append_tenant_authorization_audit(");
      expect(body).toContain("app.append_platform_audit_event(");
      expect(body).toContain("p_request_id");
      expect(body).toContain("p_correlation_id");
      expect(body).toContain("p_tenant_audit_event_id");
      expect(body).toContain("p_platform_audit_event_id");
      expect(body).toContain("'tenant_audit_event_id'");
      expect(body).toContain("'platform_audit_event_id'");
    }

    expect(start).toContain("FROM public.operator_teams AS operator_team");
    expect(start).toContain("FOR UPDATE");
    expect(start).toContain("operator_team.archived_at IS NULL");
    expect(start).toContain("'operator_team_assignment.create'");
    expect(end).toContain("'role.grant', 'tenant'");
    expect(end).toContain("app.assert_actor_can_change_operator_team_roster(");
    expect(end).toContain("LIMIT 501");
  });

  it("binds every roster query to tenant, team, epoch, and entry", () => {
    for (const name of [
      "get_tenant_operator_team_roster_entry",
      "revoke_tenant_operator_team_roster_entry",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("assignment.tenant_id = context_tenant");
      expect(body).toContain(
        "assignment.operator_team_id = p_operator_team_id",
      );
      expect(body).toContain("assignment.id = p_assignment_epoch_id");
      expect(body).toContain("roster.tenant_id = context_tenant");
      expect(body).toContain(
        "roster.assignment_epoch_id = p_assignment_epoch_id",
      );
      expect(body).toContain("roster.id = p_roster_entry_id");
    }

    const add = functionBody("add_tenant_operator_team_roster_entry");
    expect(add).toContain("assignment.tenant_id = context_tenant");
    expect(add).toContain("assignment.operator_team_id = p_operator_team_id");
    expect(add).toContain("assignment.id = p_assignment_epoch_id");
    expect(add).toContain("assignment.ended_at IS NULL");
  });

  it("requires user read for roster inventory and exact live relationship management", () => {
    const list = functionBody("list_tenant_operator_team_roster_entries");
    const manage = functionBody(
      "current_tenant_can_manage_operator_team_roster",
    );
    const relationship = functionBody(
      "current_tenant_has_live_operator_team_relationship",
    );

    expect(list).toContain("app.current_tenant_can_read_operator_team(");
    expect(list).toContain("'user.read', 'tenant'");
    expect(manage).toContain("'operator_team.roster.manage', 'tenant'");
    expect(manage).toContain("'operator_team.roster.manage', 'operator_team'");
    expect(manage).toContain(
      "app.current_tenant_has_live_operator_team_relationship(",
    );
    expect(relationship).toContain(
      "assignment.operator_team_id = p_operator_team_id",
    );
    expect(relationship).toContain("assignment.id = p_assignment_epoch_id");
    expect(relationship).toContain("assignment.ended_at IS NULL");
    expect(relationship).toContain("roster.revoked_at IS NULL");
    expect(relationship).toContain("source.retired_at IS NULL");
  });

  it("rechecks only operator-team tuples at the exact effective horizon", () => {
    const consequence = functionBody(
      "assert_actor_can_change_operator_team_roster",
    );
    for (const mutation of [
      "add_tenant_operator_team_roster_entry",
      "revoke_tenant_operator_team_roster_entry",
      "end_tenant_operator_team_assignment",
    ]) {
      const body = functionBody(mutation);
      expect(body).toContain("'role.grant', 'tenant'");
      expect(body).toContain(
        "app.assert_actor_can_change_operator_team_roster(",
      );
    }
    expect(consequence).toContain("policy.scope = 'operator_team'");
    expect(consequence).toContain("app.earliest_authorization_expiry(");
    expect(consequence).toContain("role_path.expires_at, p_roster_expires_at");
    expect(consequence).toContain("LIMIT 501");
    expect(consequence).not.toContain("policy.scope = 'tenant'");
  });

  it("keeps manual ownership, expired supersession, and payload replay exact", () => {
    const add = functionBody("add_tenant_operator_team_roster_entry");
    const revoke = functionBody("revoke_tenant_operator_team_roster_entry");

    for (const body of [add, revoke]) {
      expect(body).toContain("source.kind = 'manual'");
      expect(body).toContain("source.key = 'manual'");
      expect(body).toContain("source.protected");
      expect(body).toContain("source.retired_at IS NULL");
    }
    expect(add).toContain("superseded_entries");
    expect(add).toContain(
      "Superseded after the prior manual roster entry expired.",
    );
    expect(add).toContain("'operator_team_roster_entry.create'");
    expect(add.indexOf("IF FOUND THEN")).toBeLessThan(
      add.indexOf("operator-team roster expiry must be in the future"),
    );
    expect(revoke).toContain("operator-team roster entry is not live");
    expect(revoke).toContain("target_entry.assignment_ended_at IS NOT NULL");
  });

  it("projects only contract-valid roster states", () => {
    for (const name of [
      "list_tenant_operator_team_roster_entries",
      "get_tenant_operator_team_roster_entry",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("THEN 'revoked'");
      expect(body).toContain("THEN 'expired'");
      expect(body).toContain("ELSE 'active'");
      expect(body).toContain("source.retired_at IS NOT NULL");
      expect(body).toContain("assignment.ended_at IS NOT NULL");
      expect(body).toContain("operator_team.archived_at IS NOT NULL");
      expect(body).toContain("membership.status <> 'active'");
      expect(body).toContain("NOT identity.active");
      expect(body).toContain("tenant.status <> 'active'");
      expect(body).not.toContain("THEN 'source_retired'");
      expect(body).not.toContain("THEN 'assignment_ended'");
      expect(body).not.toContain("THEN 'team_archived'");
    }
  });

  it("deduplicates exact live epoch relationships so stale rosters never revive", () => {
    const resolver = functionBody("resolve_current_tenant_operator_teams");
    expect(resolver).toContain(
      "RETURNS TABLE (\n  operator_team_id uuid,\n  assignment_epoch_id uuid\n)",
    );
    expect(resolver).toContain("SELECT DISTINCT assignment.operator_team_id");
    expect(resolver).toContain("assignment.id");
    expect(resolver).toContain("assignment.ended_at IS NULL");
    expect(resolver).toContain("roster.assignment_epoch_id = assignment.id");
    expect(resolver).toContain("roster.membership_id = context_membership");
    expect(resolver).toContain("roster.revoked_at IS NULL");
    expect(resolver).toContain("source.retired_at IS NULL");
    expect(resolver).toContain("operator_team.archived_at IS NULL");
    expect(resolver).toContain("membership.status = 'active'");
    expect(resolver).toContain("identity.active");
    expect(resolver).toContain("tenant.status = 'active'");
    expect(resolver).toContain("LIMIT p_limit");
  });

  it("guards both command logs and advances the shared tenant revision", () => {
    expect(security).toContain(
      'CREATE TRIGGER "operator_team_assignment_epochs_touch"',
    );
    expect(security).toContain(
      'CREATE TRIGGER "operator_team_roster_entries_touch"',
    );
    expect(security.match(/touch_tenant_authorization_row/g)).toHaveLength(2);

    const tenantGuard = functionBody("guard_tenant_authorization_command");
    expect(tenantGuard).toContain(
      "NEW.operation = 'operator_team_assignment.create'",
    );
    expect(tenantGuard).toContain(
      "NEW.operation = 'operator_team_roster_entry.create'",
    );
    expect(tenantGuard).toContain("resource.tenant_id = NEW.tenant_id");
    expect(tenantGuard).toContain("resource.version = NEW.result_version");

    const platformGuard = functionBody("guard_platform_command");
    expect(platformGuard).toContain("platform command rows are append-only");
    expect(platformGuard).toContain(
      "unexpired platform commands cannot be pruned",
    );
    expect(platformGuard).toContain("NEW.operation <> 'operator_team.create'");
    expect(platformGuard).toContain("resource.id = NEW.result_resource_id");
    expect(security).toContain('CREATE TRIGGER "platform_commands_guard"');
  });

  it("keeps every exposed entry point fixed-path, bounded, owned, and function-only", () => {
    const exposed = [
      "get_auth_session_v2",
      "resolve_current_tenant_human_authority_v2",
      "list_tenant_permission_catalog_v2",
      "get_tenant_role_policy_v2",
      "resolve_current_tenant_operator_teams",
      "list_platform_operator_teams",
      "get_platform_operator_team",
      "create_platform_operator_team",
      "update_platform_operator_team_metadata",
      "archive_platform_operator_team",
      "list_tenant_operator_team_assignment_epochs",
      "get_tenant_operator_team_assignment_epoch",
      "start_tenant_operator_team_assignment",
      "end_tenant_operator_team_assignment",
      "list_tenant_operator_team_roster_entries",
      "get_tenant_operator_team_roster_entry",
      "add_tenant_operator_team_roster_entry",
      "revoke_tenant_operator_team_roster_entry",
      "replace_tenant_role_policy_v2",
      "replace_tenant_role_policy_with_result_v2",
    ];

    for (const name of exposed) {
      const body = functionBody(name);
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(security).toContain(`ALTER FUNCTION "app"."${name}"`);
      expect(security).toContain(`REVOKE ALL ON FUNCTION "app"."${name}"`);
      expect(security).toContain(`GRANT EXECUTE ON FUNCTION "app"."${name}"`);
    }

    expect(security).toContain("NOT BETWEEN 1 AND 101");
    expect(security).toContain("NOT BETWEEN 1 AND 201");
    expect(security).toContain("NOT BETWEEN 1 AND 501");
    expect(structural).toContain(
      'ALTER TABLE "operator_team_assignment_epochs" ENABLE ROW LEVEL SECURITY',
    );
    expect(structural).toContain(
      'ALTER TABLE "operator_team_roster_entries" ENABLE ROW LEVEL SECURITY',
    );
  });
});
