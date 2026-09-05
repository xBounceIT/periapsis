import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const baseSecurity = readFileSync(
  resolve(packageRoot, "migrations/0028_phase_2b_operator_teams_security.sql"),
  "utf8",
);
const hardening = readFileSync(
  resolve(packageRoot, "migrations/0031_operator_team_hardening_security.sql"),
  "utf8",
);

function functionBody(name: string): string {
  const marker = `CREATE OR REPLACE FUNCTION "app"."${name}"`;
  const createMarker = `CREATE FUNCTION "app"."${name}"`;
  const replace = hardening.indexOf(marker);
  const create = hardening.indexOf(createMarker);
  const start = replace === -1 ? create : replace;
  if (start === -1) {
    throw new Error(`Missing hardening function ${name}`);
  }
  const end = hardening.indexOf("$function$;", start);
  return hardening.slice(start, end);
}

describe("operator-team database hardening", () => {
  it("keeps the unreleased backfill on state-before-role lock ordering", () => {
    const backfillStart = baseSecurity.indexOf(
      "-- Existing initialized tenant",
    );
    const backfillEnd = baseSecurity.indexOf("$block$;", backfillStart);
    const backfill = baseSecurity.slice(backfillStart, backfillEnd);

    expect(backfill).toContain(
      "FROM public.tenant_authorization_states AS state",
    );
    expect(backfill).toContain("ORDER BY state.tenant_id\n    FOR UPDATE");
    expect(backfill).toContain("role.tenant_id = target_state.tenant_id");
    expect(backfill.indexOf("FOR target_state IN")).toBeLessThan(
      backfill.indexOf("FOR target_role IN"),
    );
  });

  it("makes assignment identity and the completed end history immutable", () => {
    const guard = functionBody(
      "guard_operator_team_assignment_epoch_immutability",
    );

    expect(hardening).toContain(
      'CREATE TRIGGER "operator_team_assignment_epochs_immutable_guard"\nBEFORE UPDATE',
    );
    for (const field of [
      "id",
      "tenant_id",
      "operator_team_id",
      "assigned_by_membership_id",
      "assignment_reason",
      "assigned_at",
    ]) {
      expect(guard).toContain(`OLD.${field} IS DISTINCT FROM NEW.${field}`);
    }
    expect(guard).toContain("IF OLD.ended_at IS NULL THEN");
    expect(guard).toContain("NEW.ended_at IS NOT NULL");
    expect(guard).toContain("NEW.ended_by_membership_id IS NOT NULL");
    expect(guard).toContain("NEW.end_reason IS NOT NULL");
    expect(guard).toContain("OLD.ended_at IS DISTINCT FROM NEW.ended_at");
    expect(guard).toContain(
      "OLD.ended_by_membership_id IS DISTINCT FROM NEW.ended_by_membership_id",
    );
    expect(guard).toContain("OLD.end_reason IS DISTINCT FROM NEW.end_reason");
    expect(guard.match(/USING ERRCODE = '55000'/g)).toHaveLength(3);
    expect(hardening).toContain(
      'ALTER FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"() OWNER TO "periapsis_migrator"',
    );
    expect(hardening).toContain(
      'REVOKE ALL ON FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor"',
    );
    expect(hardening).not.toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."guard_operator_team_assignment_epoch_immutability"/,
    );
  });

  it("ends arbitrarily large rosters through a permission-catalog aggregate", () => {
    const end = functionBody("end_tenant_operator_team_assignment");

    expect(end).toContain("roster_entries_checked bigint");
    expect(end).toContain("WITH live_roster AS MATERIALIZED");
    expect(end).toContain("GROUP BY scoped_path.permission_key");
    expect(end).toContain("bool_or(scoped_path.effective_expires_at IS NULL)");
    expect(end).toContain("app.tenant_user_can_delegate_exact_permission(");
    expect(end).not.toContain("LIMIT 501");
    expect(end).not.toContain(
      "app.assert_actor_can_change_operator_team_roster(",
    );
    expect(end).toContain("tenant_assignment.tenant_id = context_tenant");
    expect(end).toContain("tenant_assignment.id = p_assignment_epoch_id");
    expect(
      end.indexOf("FROM public.operator_teams AS operator_team"),
    ).toBeLessThan(
      end.indexOf("FROM public.operator_team_assignment_epochs AS assignment"),
    );
  });

  it("enforces the 200 exact-relationship cap atomically and provenance-safe", () => {
    const guard = functionBody("guard_operator_team_relationship_capacity");

    expect(hardening).toContain(
      'CREATE TRIGGER "operator_team_roster_entries_capacity_guard"',
    );
    expect(hardening).toContain(
      'BEFORE INSERT OR UPDATE OF\n  "tenant_id",\n  "assignment_epoch_id",\n  "membership_id",\n  "source_id",\n  "expires_at",\n  "revoked_at"',
    );
    expect(guard).toContain("FROM public.tenant_authorization_states AS state");
    expect(guard).toContain("OLD.tenant_id IS DISTINCT FROM NEW.tenant_id");
    expect(guard).toContain("operator-team roster tenant is immutable");
    expect(guard).toContain("WHERE state.tenant_id = NEW.tenant_id");
    expect(guard).toContain("FOR UPDATE");
    expect(guard).toContain("roster.id <> excluded_roster_id");
    expect(guard).toContain("SELECT DISTINCT assignment.id");
    expect(guard).toContain(
      "existing.assignment_epoch_id = NEW.assignment_epoch_id",
    );
    expect(guard).toContain("existing.id <> excluded_roster_id");
    expect(guard).toContain("existing_source.retired_at IS NULL");
    expect(guard.indexOf("IF EXISTS (")).toBeLessThan(
      guard.indexOf("WITH live_relationships AS ("),
    );
    expect(guard).toContain("relationship_count >= 200");
    expect(guard).toContain("USING ERRCODE = '55000'");
    expect(guard).not.toContain("membership.status");
    expect(guard).not.toContain("identity.active");
    expect(guard).not.toContain("tenant.status");
    expect(hardening).toContain("count(DISTINCT assignment.id) > 200");
  });

  it("binds strong team and assignment versions to joined representations", () => {
    const touch = functionBody("touch_operator_team_assignment_representation");
    const touchSummaries = functionBody(
      "touch_operator_team_assignment_summaries",
    );
    const update = functionBody("update_platform_operator_team_metadata");
    const archive = functionBody("archive_platform_operator_team");

    expect(touch).toContain("OLD.ended_at IS NOT DISTINCT FROM NEW.ended_at");
    expect(touch).toContain("SET version = operator_team.version + 1");
    expect(hardening).toContain('AFTER INSERT OR UPDATE OF "ended_at"');
    expect(touchSummaries).toContain(
      "OLD.display_name IS NOT DISTINCT FROM NEW.display_name",
    );
    expect(touchSummaries).toContain(
      "OLD.archived_at IS NOT DISTINCT FROM NEW.archived_at",
    );
    expect(touchSummaries).toContain("ORDER BY state.tenant_id");
    expect(touchSummaries).toContain("FOR UPDATE NOWAIT");
    expect(touchSummaries).toContain("EXCEPTION WHEN lock_not_available");
    expect(touchSummaries).toContain("USING ERRCODE = '40001'");
    expect(touchSummaries).toContain(
      "UPDATE public.operator_team_assignment_epochs AS assignment",
    );
    expect(hardening).toContain(
      'AFTER UPDATE OF "display_name", "archived_at"',
    );
    expect(hardening).toContain(
      'ALTER FUNCTION "app"."touch_operator_team_assignment_summaries"() OWNER TO "periapsis_migrator"',
    );
    expect(hardening).toContain(
      'REVOKE ALL ON FUNCTION "app"."touch_operator_team_assignment_summaries"() FROM PUBLIC',
    );
    for (const mutation of [update, archive]) {
      expect(mutation).toContain(
        "app.lock_operator_team_assignment_states(p_operator_team_id)",
      );
      expect(mutation).not.toContain(
        "UPDATE public.operator_team_assignment_epochs AS assignment",
      );
      expect(
        mutation.indexOf("lock_operator_team_assignment_states"),
      ).toBeLessThan(
        mutation.indexOf("FROM public.operator_teams AS operator_team"),
      );
    }
    expect(update).toContain("assignment_representation_changed");
    expect(archive).toContain("assignment_versions_advanced");

    const invalidationStart = hardening.indexOf(
      "-- Strong ETags emitted before this migration",
    );
    const invalidationEnd = hardening.indexOf("$block$;", invalidationStart);
    const invalidation = hardening.slice(invalidationStart, invalidationEnd);
    expect(invalidationStart).toBeGreaterThan(-1);
    expect(invalidation).toContain(
      "FROM public.tenant_authorization_states AS state",
    );
    expect(invalidation).toContain("ORDER BY state.tenant_id");
    expect(invalidation).toContain(
      "UPDATE public.operator_teams AS operator_team",
    );
    expect(invalidation).toContain(
      "UPDATE public.operator_team_assignment_epochs AS assignment",
    );
    expect(invalidation.indexOf("FOR target_state IN")).toBeLessThan(
      invalidation.indexOf("FOR target_team IN"),
    );
    expect(invalidation.indexOf("FOR target_team IN")).toBeLessThan(
      invalidation.indexOf("FOR target_assignment IN"),
    );
  });

  it("exposes only a bounded worker command pruner", () => {
    const pruner = functionBody("prune_expired_authorization_commands");

    expect(pruner).toContain("p_per_class_batch_size NOT BETWEEN 1 AND 1000");
    expect(pruner.match(/LIMIT p_per_class_batch_size/g)).toHaveLength(2);
    expect(pruner.match(/FOR UPDATE SKIP LOCKED/g)).toHaveLength(2);
    expect(pruner).toContain("public.platform_commands AS stale");
    expect(pruner).toContain("public.tenant_authorization_commands AS stale");
    expect(hardening).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."prune_expired_authorization_commands"(integer) TO "periapsis_worker"',
    );
    expect(hardening).not.toContain(
      'GRANT EXECUTE ON FUNCTION "app"."prune_expired_authorization_commands"(integer) TO "periapsis_api"',
    );
    expect(hardening).not.toMatch(/GRANT [^;]+ ON TABLE/);
  });
});
