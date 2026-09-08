import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrations = resolve(import.meta.dirname, "../migrations");
const structural = readFileSync(
  resolve(migrations, "0055_lazy_taskmaster.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(migrations, "0056_identity_mapping_security.sql"),
  "utf8",
);
const readiness = readFileSync(
  resolve(migrations, "0058_identity_mapping_readiness_v9.sql"),
  "utf8",
);
const bindingIdempotency = readFileSync(
  resolve(migrations, "0057_identity_provider_binding_idempotency_v2.sql"),
  "utf8",
);
const apiHealth = readFileSync(
  resolve(
    import.meta.dirname,
    "../../../services/api/internal/postgres/health.go",
  ),
  "utf8",
);
const workerHealth = readFileSync(
  resolve(
    import.meta.dirname,
    "../../../services/worker/internal/postgres/health.go",
  ),
  "utf8",
);
const identityProviderQueries = readFileSync(
  resolve(
    import.meta.dirname,
    "../../../services/api/internal/postgres/queries/identity_providers.sql",
  ),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const start = Math.max(
    source.indexOf(`CREATE FUNCTION app.${name}`),
    source.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`),
  );
  expect(start, `${name} declaration`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("$function$;", start);
  expect(end, `${name} terminator`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("tenant LDAP identity-mapping canonical schema", () => {
  it("keeps every mapping relation tenant-scoped with forced-RLS staging", () => {
    for (const table of [
      "tenant_ldap_mapping_rules",
      "tenant_ldap_mapping_rule_epochs",
      "tenant_ldap_mapping_rule_role_targets",
    ]) {
      const start = structural.indexOf(`CREATE TABLE "${table}"`);
      const next = structural.indexOf("CREATE TABLE ", start + 1);
      const body = structural.slice(
        start,
        next === -1 ? structural.length : next,
      );
      expect(start, table).toBeGreaterThanOrEqual(0);
      expect(body).toContain('"tenant_id" uuid NOT NULL');
      expect(structural).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `REVOKE ALL ON TABLE public.${table} FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
      );
    }
  });

  it("pins exact tenant roles and team assignments without platform targets", () => {
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","role_id","role_principal_kind") REFERENCES "public"."tenant_roles"("tenant_id","id","principal_kind")',
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","operator_team_assignment_epoch_id","operator_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id")',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_ldap_mapping_rule_role_targets_human_check" CHECK',
    );
    expect(structural).not.toMatch(/platform_role|platform_group/);
  });

  it("retains complete scalar epochs and revision-pinned role history", () => {
    expect(structural).toContain(
      'CONSTRAINT "tenant_ldap_mapping_rule_epochs_rule_sequence_key" UNIQUE("tenant_id","mapping_rule_id","sequence")',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_ldap_mapping_rule_epochs_source_key" UNIQUE("tenant_id","source_id")',
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","current_source_epoch_id","id","binding_id","configuration_revision")',
    );
    const epoch = structural.slice(
      structural.indexOf('CREATE TABLE "tenant_ldap_mapping_rule_epochs"'),
      structural.indexOf(
        'CREATE TABLE "tenant_ldap_mapping_rule_role_targets"',
      ),
    );
    for (const field of [
      '"matcher_type"',
      '"matcher_value"',
      '"case_mode"',
      '"priority"',
      '"tenant_security_group_id"',
      '"reconciliation_mode"',
      '"operator_team_assignment_epoch_id"',
    ]) {
      expect(epoch).toContain(field);
    }
  });
});

describe("tenant LDAP identity-mapping protected ABI", () => {
  it("lists all bindings when the optional binding filter is null", () => {
    const list = functionBody(security, "list_tenant_ldap_mapping_rules_v1");
    expect(list).toContain(
      "p_binding_id IS NULL OR rule.binding_id = p_binding_id",
    );
    expect(list).not.toContain("IF p_binding_id IS NULL");
    expect(list).toContain("current_source_epoch_activated_at timestamptz");
    expect(list).toContain("epoch.activated_at");
    const get = functionBody(security, "get_tenant_ldap_mapping_rule_v1");
    expect(get).toContain("current_source_epoch_activated_at timestamptz");
    expect(get).toContain("epoch.activated_at");
  });

  it("validates every target consequence and the exact team epoch", () => {
    const validate = functionBody(
      security,
      "private_validate_tenant_ldap_mapping_targets_v1",
    );
    expect(validate).toContain(
      "app.assert_actor_can_change_security_group_member",
    );
    expect(validate).toContain("app.assert_actor_can_grant_role");
    expect(validate).toContain(
      "app.current_tenant_can_manage_operator_team_roster",
    );
    expect(validate).toContain(
      "assignment.operator_team_id = p_operator_team_id",
    );
    expect(validate).toContain("role.principal_kind = 'human'");
  });

  it("opens a fresh immutable source epoch for enable and semantic changes", () => {
    const update = functionBody(security, "update_tenant_ldap_mapping_rule_v1");
    expect(update).toContain("semantic_change");
    expect(update).toContain(
      "p_enabled AND (NOT locked_rule.enabled OR semantic_change)",
    );
    expect(update).toContain("'identity_mapping'");
    expect(update).toContain(
      "INSERT INTO public.tenant_ldap_mapping_rule_epochs",
    );
    expect(update).toContain("app.private_close_tenant_ldap_mapping_epoch_v1");
    const close = functionBody(
      security,
      "private_close_tenant_ldap_mapping_epoch_v1",
    );
    expect(close).toContain("UPDATE public.tenant_authorization_sources");
    expect(close).not.toMatch(
      /UPDATE public\.(tenant_membership_role_grants|tenant_security_group_memberships|tenant_security_group_role_grants|operator_team_roster_entries)/,
    );
  });

  it("binds idempotency to the exact mapping kind and redacts matcher values", () => {
    const commandGuard = functionBody(
      security,
      "guard_tenant_authorization_command",
    );
    expect(commandGuard).toContain("NEW.operation = 'identity_mapping.create'");
    expect(commandGuard).toContain(
      "r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id",
    );
    const create = functionBody(security, "create_tenant_ldap_mapping_rule_v1");
    expect(create).toContain("pg_advisory_xact_lock");
    expect(create).toContain(
      "replay.request_digest <> canonical_request_digest",
    );
    const auditStart = create.indexOf(
      "PERFORM app.append_tenant_authorization_audit",
    );
    expect(create.slice(auditStart)).not.toContain("'matcher_value'");
    expect(create.slice(auditStart)).not.toContain("'notes'");
  });

  it("provides payload-bound DB-generated binding creation in ABI v2", () => {
    const create = functionBody(
      bindingIdempotency,
      "create_tenant_auth_provider_binding_v2",
    );
    expect(create).toContain("new_binding_id := uuidv7()");
    expect(create).toContain("pg_advisory_xact_lock");
    expect(create).toContain(
      "command.operation = 'identity_provider_binding.create'",
    );
    expect(create).toContain(
      "replay.request_digest <> canonical_request_digest",
    );
    expect(create).toContain("SELECT binding.version INTO current_version");
    expect(create).toContain(
      "p_audit_event_id, 'tenant.identity_provider_binding.created'",
    );
    expect(bindingIdempotency).toContain(
      "GRANT EXECUTE ON FUNCTION app.create_tenant_auth_provider_binding_v2",
    );
  });

  it("publishes a pure planner snapshot without mutation statements", () => {
    const snapshot = functionBody(
      security,
      "snapshot_tenant_ldap_mapping_rules_v1",
    );
    expect(snapshot).toContain("rule.tenant_id = app.context_tenant_id()");
    expect(snapshot).toContain("binding.auth_revision");
    expect(snapshot).toContain("epoch.source_id");
    expect(snapshot).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/);
    expect(security).toContain(
      "GRANT EXECUTE ON FUNCTION app.snapshot_tenant_ldap_mapping_rules_v1(uuid) TO periapsis_api, periapsis_worker",
    );
  });

  it("preserves exact v9 readiness while runtime uses v59", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v9()",
    );
    expect(readiness).toContain("journal_count = 59");
    expect(readiness).toContain("1787648225321");
    expect(readiness).toContain("fingerprint_entries[1:54]");
    expect(readiness).toContain("schema compatibility v7 must be retired");
    expect(readiness).toContain("relation.relforcerowsecurity");
    expect(readiness).toContain("source.kind = 'identity_mapping'");
    expect(apiHealth).toContain("from app.schema_compatibility_v59()");
    expect(workerHealth).toContain("from app.schema_compatibility_v59()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v51()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v51()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v49()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v49()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v47()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v47()");
    expect(workerHealth).toContain("app.verify_identity_keyring_v3(");
    expect(identityProviderQueries).toContain(
      "SELECT app.verify_identity_keyring_v3(",
    );
  });
});
