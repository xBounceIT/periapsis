import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");
const source = (path: string): string =>
  readFileSync(resolve(repositoryRoot, path), "utf8");

const structural = migration("0150_high_blob.sql");
const security = migration("0151_platform_tenant_lifecycle_security.sql");
const readiness = migration("0152_platform_tenant_lifecycle_readiness.sql");
const generated = migration("0153_lovely_sprite.sql");
const compatibility = migration(
  "0154_platform_tenant_lifecycle_compatibility.sql",
);

describe("platform tenant lifecycle security contract", () => {
  it("uses one UTF-8 byte boundary from persistence through the audit reader", () => {
    expect(structural).toContain(
      'octet_length("platform_audit_events"."reason") between 1 and 2048',
    );
    expect(security).toContain("octet_length(p_reason) BETWEEN 1 AND 2048");
    expect(source("services/api/internal/securityaudit/service.go")).toContain(
      "validOptionalAuditReason(event.Reason)",
    );
    expect(source("packages/contracts/openapi/openapi.yaml")).toContain(
      "Mandatory non-secret, already-redacted operator reason",
    );
    expect(source("apps/web/src/pages/platform-tenants.tsx")).toContain(
      "do not include secrets, tokens, credentials, or customer data",
    );
  });

  it("publishes the permission without exposing it to predecessor sessions", () => {
    const v3 = security.indexOf("CREATE FUNCTION app.get_auth_session_v3");
    const v2 = security.indexOf(
      "CREATE OR REPLACE FUNCTION app.get_auth_session_v2",
    );
    const permission = security.indexOf("'platform.tenant.manage'");
    expect(v3).toBeGreaterThan(-1);
    expect(v2).toBeGreaterThan(v3);
    expect(permission).toBeGreaterThan(v2);
    expect(security).toContain("FROM app.get_auth_session_v3(p_token_digest)");
    expect(security).toContain(
      "WHERE permission_key <> 'platform.tenant.manage'",
    );
    expect(security).toContain("role.key = 'platform_super_admin'");
    expect(
      source("services/api/internal/postgres/queries/authentication.sql"),
    ).toContain("app.get_auth_session_v3");
  });

  it("linearizes the transition on live session, permission, authorization state, and tenant locks", () => {
    expect(security).toContain("p_target IS NULL");
    expect(security).toContain("p_reason IS NULL");
    expect(security).toContain("p_authentication_method IS NULL");
    expect(security).toContain("session.id = p_session_id");
    expect(security).toContain("FOR SHARE OF session, actor");
    expect(security).toContain(
      "FOR SHARE OF user_role, role_permission, permission",
    );
    const stateLock = security.indexOf(
      "FROM public.tenant_authorization_states AS authorization_state",
      security.indexOf("CREATE FUNCTION app.change_platform_tenant_lifecycle"),
    );
    const tenantLock = security.indexOf(
      "FROM public.tenants AS tenant",
      stateLock,
    );
    expect(stateLock).toBeGreaterThan(-1);
    expect(tenantLock).toBeGreaterThan(stateLock);
    expect(security).toContain("SET revision = authorization_revision + 1");
    expect(security).toContain("USING ERRCODE = 'P0002'");
    expect(security).toContain("USING ERRCODE = '55000'");
    expect(security).toContain("USING ERRCODE = '40001'");
  });

  it("fences only unreserved notification work and every live SLA job", () => {
    expect(security).toContain("outcome = 'fenced'");
    expect(security).toContain("failure_class = 'security'");
    expect(security).toContain("failure_code = 'tenant_suspended'");
    expect(security.match(/delivery\.stable_message_id IS NULL/g)).toHaveLength(
      2,
    );
    expect(security.match(/delivery\.reserved_at IS NULL/g)).toHaveLength(2);
    expect(security).not.toMatch(
      /delivery\.status IN \([^)]*'reserved'[^)]*\)/,
    );
    expect(security).toContain(
      "job.status IN ('queued', 'retry_scheduled', 'leased')",
    );
    expect(security).toContain("dead_lettered_at = changed_at");
    expect(security).toContain("'notification_deliveries_fenced'");
    expect(security).toContain("'sla_jobs_fenced'");
  });

  it("closes every alternate RLS and ticket-write route on suspension", () => {
    expect(security).toContain("CREATE FUNCTION app.tenant_is_active_v1");
    expect(security).toContain("tenant.status = 'active'");
    expect(readiness).toContain(
      "notification_dispatch_owner_delivery_claim_global_v1",
    );
    expect(readiness).toContain("sla_evaluation_jobs_sla_worker_owner_v1");
    expect(readiness).toContain(
      "CREATE FUNCTION app.guard_active_tenant_ticket_write_v1",
    );
    expect(readiness).toContain("FOR KEY SHARE");
    expect(readiness).toContain("alerts_active_tenant_write_v1");
    expect(readiness).toContain("cases_active_tenant_write_v1");
    for (const policy of [
      'ALTER POLICY "alerts_api_tenant"',
      'ALTER POLICY "cases_api_tenant"',
      'ALTER POLICY "users_api_tenant_select"',
      'ALTER POLICY "tenant_notification_deliveries_notifier_tenant"',
      'ALTER POLICY "tenant_notification_delivery_attempts_notifier_tenant"',
      'ALTER POLICY "sla_evaluation_jobs_worker_tenant"',
    ]) {
      const position = generated.indexOf(policy);
      expect(position).toBeGreaterThan(-1);
      expect(generated.slice(position, position + 1_500)).toContain(
        "app.tenant_is_active_v1",
      );
    }
  });

  it("requires semantic readiness and seals V32 with the exact V31 prefix", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.platform_tenant_lifecycle_schema_readiness_v1",
    );
    expect(readiness).toContain("platform_audit_events_reason_check");
    expect(readiness).toContain("tenant_is_active_v1");
    expect(readiness).toContain("guard_active_tenant_ticket_write_v1");
    expect(compatibility).toContain(
      "CREATE FUNCTION app.schema_compatibility_v32",
    );
    expect(compatibility).toContain("journal_count = 155");
    expect(compatibility).toContain(
      "journal_latest_created_at = 1787852085088",
    );
    expect(compatibility).toContain("fingerprint_entries[151:155]");
    expect(compatibility).toMatch(/WHERE\s+prefix\.migration_ordinal = 150/);
    expect(compatibility).toContain(
      "0f5a388806ac70eb58aa11782575b57ff66bc650df981b36fd3a065dfa713c6a",
    );
    expect(compatibility).toContain(
      "current_count = 155 AND predecessor_count = 150",
    );
    expect(compatibility).toContain(
      "app.platform_tenant_lifecycle_schema_readiness_v1()",
    );
    expect(compatibility).toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v30",
    );
  });
});
