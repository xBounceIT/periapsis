import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const schema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/platform-operations.ts"),
  "utf8",
);
const roles = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/roles.ts"),
  "utf8",
);
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0216_platform_operations_administration.sql",
  ),
  "utf8",
);

function functionBody(name: string): string {
  const marker = `CREATE FUNCTION app.${name}`;
  const start = migration.indexOf(marker);
  if (start < 0) throw new Error(`missing platform operation function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0)
    throw new Error(`unterminated platform operation function ${name}`);
  return migration.slice(start, end);
}

describe("platform operations administration contract", () => {
  it("keeps typed singleton settings and a closed feature catalog behind a NOLOGIN owner", () => {
    expect(schema).toContain('"platform_global_settings"');
    expect(schema).toContain('"platform_feature_flags"');
    expect(schema).not.toContain("jsonb(");
    expect(schema).toContain("platform_failed_notifications_view");
    expect(schema).toContain("platform_global_settings_updater_check");
    expect(schema).toContain("platform_feature_flags_updater_check");
    expect(roles).toContain("periapsis_platform_operations_owner");
    expect(migration).toMatch(/NOLOGIN[^;]*NOBYPASSRLS/);
    expect(migration).toContain(
      "ALTER TABLE public.platform_global_settings FORCE ROW LEVEL SECURITY",
    );
    expect(migration).toContain(
      "ALTER TABLE public.platform_feature_flags FORCE ROW LEVEL SECURITY",
    );
  });

  it("grants six independent permissions only to the system super-admin", () => {
    for (const permission of [
      "platform.user.read",
      "platform.operations.read",
      "platform.settings.read",
      "platform.settings.manage",
      "platform.feature_flag.read",
      "platform.feature_flag.manage",
    ]) {
      expect(migration).toContain(`'${permission}'`);
    }
    expect(migration).toContain(
      "role.key = 'platform_super_admin' AND role.system",
    );
    expect(migration).toContain("AND role.key <> 'platform_super_admin'");
    expect(migration).not.toMatch(
      /role\.key\s+IN\s+\([^)]*platform_auditor[^)]*\)/,
    );
  });

  it("fences every ABI on one live tenantless non-recovery session and the shared permission epoch", () => {
    const helper = functionBody("private_require_platform_operations_actor_v1");
    expect(helper).toContain("context_tenant IS NOT NULL");
    expect(helper).toContain("session.id = p_session_id");
    expect(helper).toContain("session.user_id = context_user");
    expect(helper).toContain("session.active_tenant_id IS NULL");
    expect(helper).toContain("session.revoked_at IS NULL");
    expect(helper).toContain("FOR SHARE OF session, identity");
    expect(helper).not.toContain("'recovery_code'");
    expect(helper).toContain("transaction_timestamp() - interval '15 minutes'");
    expect(helper).toContain("platform_user_authorization_epochs");
    expect(helper).toContain("role.key = 'platform_super_admin'");
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.private_require_platform_operations_actor_v1(uuid, text, boolean)\nTO periapsis_platform_operations_owner",
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.private_require_platform_operations_actor_v1[^;]*TO periapsis_api/s,
    );
  });

  it("rejects nullable or non-v7 audit envelopes without a STRICT null bypass", () => {
    const helper = functionBody(
      "private_validate_platform_operations_trace_v1",
    );
    expect(helper).not.toMatch(/\nSTRICT\n/);
    for (const guard of [
      "p_audit_event_id IS NULL",
      "uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7",
      "p_request_id IS NULL",
      "uuid_extract_version(p_request_id) IS DISTINCT FROM 7",
      "p_correlation_id IS NULL",
      "uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7",
      "p_ip_address IS NULL",
      "p_user_agent IS NULL",
    ]) {
      expect(helper).toContain(guard);
    }
  });

  it("returns a finite, content-free queue projection and reclaims stale leases", () => {
    const body = functionBody("private_platform_queue_metrics_v1");
    for (const key of [
      "outbox",
      "notification_delivery",
      "ticket_bulk",
      "ticket_export",
      "ticket_export_cleanup",
      "tenant_audit_export",
      "platform_audit_export",
      "sla_evaluation",
      "sla_trigger_action",
      "sla_event_ingress",
      "dfir_evidence_scan",
      "dfir_evidence_cleanup",
      "ldap_sync",
    ]) {
      expect(body).toContain(`'${key}'`);
    }
    expect(body).not.toMatch(
      /last_error|recipient|destination_redacted|provider_receipt|payload|object_key|reason/i,
    );
    expect(body).toContain("delivery.lease_until <= observed.checked_at");
    expect(body).toContain("job.lease_expires_at <= observed.checked_at");
    expect(body).toContain("execution.lease_expires_at <= observed.checked_at");
    expect(body).toContain("ingress.lease_expires_at <= observed.checked_at");
    expect(body).toContain("run.claim_expires_at <= observed.checked_at");
    expect(body).toContain("'checkedAt', observed.checked_at");
  });

  it("publishes only the explicitly redacted failed-notification fields behind the real flag", () => {
    const body = functionBody("list_platform_failed_notifications_v1");
    expect(body).toContain("p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100");
    for (const field of [
      "'id'",
      "'tenantId'",
      "'channel'",
      "'failureClass'",
      "'failureCode'",
      "WHEN page.failure_code IN (",
      "'configuration_revoked','tenant_suspended'",
      "ELSE 'unknown'",
      "'failureAt'",
      "'createdAt'",
      "'updatedAt'",
      "'attemptCount'",
    ]) {
      expect(body).toContain(field);
    }
    expect(body).not.toMatch(
      /recipient|destination_redacted|template_snapshot|webhook_payload|provider_receipt|context/i,
    );
    expect(body).toContain("platform_failed_notifications_view");
    expect(body).toContain("feature_enabled IS DISTINCT FROM true");
    expect(functionBody("list_platform_feature_flags_v1")).not.toContain(
      "feature_enabled",
    );
  });

  it("keeps both platform inventories bounded when a direct ABI caller supplies NULL", () => {
    expect(functionBody("list_platform_users_v1")).toContain(
      "p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100",
    );
    expect(functionBody("list_platform_failed_notifications_v1")).toContain(
      "p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100",
    );
  });

  it("uses exact CAS, safe reasons, fresh MFA, IANA timezone validation, and atomic audit for mutations", () => {
    const settings = functionBody("update_platform_global_settings_v1");
    const flag = functionBody("update_platform_feature_flag_v1");
    for (const body of [settings, flag]) {
      expect(body).toContain("private_platform_operations_reason_is_valid_v1");
      expect(body).toContain("true\n  );");
      expect(body).toContain("FOR UPDATE");
      expect(body).toContain("version conflict");
      expect(body).toContain("append_platform_audit_event");
    }
    expect(settings).toContain("pg_catalog.pg_timezone_names");
    expect(settings).toContain(
      "settings_record.version IS DISTINCT FROM p_expected_version",
    );
    expect(settings).toContain("p_support_url !~ '^https://");
    expect(settings).not.toMatch(/http_get|curl|fetch|dblink/i);
    expect(flag).toContain(
      "p_flag_key IS DISTINCT FROM 'platform_failed_notifications_view'",
    );
    expect(flag).toContain(
      "flag_record.version IS DISTINCT FROM p_expected_version",
    );
  });

  it("never grants source-table access or private helpers to runtime roles", () => {
    expect(migration).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*ON TABLE[^;]*TO periapsis_(?:api|worker|notifier|auditor)/s,
    );
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE public\.platform_global_settings,[\s\S]*?FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;/,
    );
  });
});
