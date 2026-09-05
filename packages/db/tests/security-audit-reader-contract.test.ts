import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0103_crazy_scarlet_witch.sql",
  ),
  "utf8",
);
const auditSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/audit.ts"),
  "utf8",
);
const platformSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/platform.ts"),
  "utf8",
);
const repository = readFileSync(
  resolve(repositoryRoot, "services/api/internal/postgres/security_audit.go"),
  "utf8",
);
const openapi = readFileSync(
  resolve(repositoryRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);

function functionBody(name: string): string {
  const created = migration.indexOf(`CREATE FUNCTION app.${name}`);
  const replaced = migration.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`);
  const start = created < 0 ? replaced : created;
  if (start < 0) throw new Error(`missing function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated function ${name}`);
  return migration.slice(start, end);
}

describe("security audit reader contract", () => {
  it("keeps the runtime API behind four bounded, self-auditing entry points", () => {
    expect(migration).toContain(
      "ALTER ROLE periapsis_audit_reader_owner\n  WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
    );
    expect(migration).toContain(
      "REVOKE ALL ON TABLE public.audit_events, public.audit_chain_heads,\n  public.platform_audit_events, public.platform_audit_chain_head\nFROM periapsis_api",
    );
    expect(migration).toContain(
      "GRANT SELECT ON TABLE public.audit_events, public.audit_chain_heads,\n  public.platform_audit_events, public.platform_audit_chain_head\nTO periapsis_audit_reader_owner",
    );
    expect(migration).toContain("app.audit_event_payload(public.audit_events)");
    expect(migration).toContain(
      "app.platform_audit_event_payload(public.platform_audit_events)",
    );

    for (const name of [
      "list_tenant_audit_events_v1(",
      "list_platform_audit_events_v1(",
      "verify_tenant_audit_chain_v1(",
      "verify_platform_audit_chain_v1(",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("VOLATILE");
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("p_access_audit_id");
      expect(body).toMatch(/audit\.(?:accessed|chain_verified)/);
    }

    expect(repository).toContain("AccessMode: pgx.ReadWrite");
    expect(repository).toContain("SetTenantContext");
    expect(repository).toContain("SetUserContext");
    expect(repository).toContain("installPersistedTraceContext");
    for (const entryPoint of [
      "app.list_tenant_audit_events_v1",
      "app.list_platform_audit_events_v1",
      "app.verify_tenant_audit_chain_v1",
      "app.verify_platform_audit_chain_v1",
    ]) {
      expect(repository).toContain(entryPoint);
    }
    expect(repository).not.toMatch(
      /FROM public\.(?:audit_events|platform_audit_events)/,
    );
  });

  it("rechecks a live MFA session and exact current authority inside PostgreSQL", () => {
    const session = functionBody("require_live_audit_session_v1(");
    for (const invariant of [
      "session.user_id = app.context_user_id()",
      "session.revoked_at IS NULL",
      "session.idle_expires_at > transaction_timestamp()",
      "session.absolute_expires_at > transaction_timestamp()",
      "session.mfa_satisfied_at IS NOT NULL",
      "identity.active",
      "session.active_tenant_id = p_expected_tenant_id",
      "tenant.status = 'active'",
      "membership.status = 'active'",
    ]) {
      expect(session).toContain(invariant);
    }

    const tenantList = functionBody("list_tenant_audit_events_v1(");
    expect(tenantList).toContain("p_limit NOT BETWEEN 1 AND 101");
    expect(tenantList).toContain(
      "app.current_tenant_human_has_exact_permission_v3(\n    'audit.read', 'tenant'",
    );
    expect(tenantList).toContain("ORDER BY event.sequence\n  LIMIT p_limit");
    expect(tenantList).toContain("'filtersApplied', filters_applied");
    expect(tenantList).not.toContain("'search', p_search");

    const platformList = functionBody("list_platform_audit_events_v1(");
    expect(platformList).toContain(
      "app.platform_user_has_permission(actor_id, 'platform.audit.read')",
    );
    expect(platformList).toContain("p_actor_type = 'service_account'");
  });

  it("verifies the pre-access snapshot and recursively rejects secret-bearing JSON", () => {
    for (const name of [
      "verify_tenant_audit_chain_v1(",
      "verify_platform_audit_chain_v1(",
    ]) {
      const body = functionBody(name);
      const summary = body.indexOf("WITH ordered AS");
      const append = body.indexOf("PERFORM app.append_");
      const returned = body.indexOf("RETURN QUERY SELECT");
      expect(summary).toBeGreaterThan(0);
      expect(append).toBeGreaterThan(summary);
      expect(returned).toBeGreaterThan(append);
      expect(body).toContain("result_event_count = result_last_sequence");
      expect(body).toContain("result_first_invalid_sequence IS NULL");
    }

    const documentGuard = functionBody("audit_json_document_safe_v1(");
    expect(documentGuard).toContain("WITH RECURSIVE nodes");
    expect(documentGuard).toContain("node_count <= 8192");
    expect(documentGuard).toContain("deepest <= 32");
    expect(documentGuard).toContain("app.audit_json_key_value_safe_v1");
    expect(migration).toContain("DO $historical_audit_redaction$");
    expect(migration).toContain(
      "CREATE TRIGGER audit_events_json_documents_guard_v1",
    );
    expect(migration).toContain(
      "CREATE TRIGGER platform_audit_events_json_documents_guard_v1",
    );
  });

  it("keeps reader policies provider-scoped and exposes the canonical HTTP contract", () => {
    expect(auditSchema).toContain('pgPolicy("audit_events_reader_select"');
    expect(auditSchema).toContain(
      "app.current_tenant_human_has_exact_permission_v3('audit.read', 'tenant')",
    );
    expect(platformSchema).toContain(
      'pgPolicy("platform_audit_events_reader_select"',
    );
    expect(platformSchema).toContain(
      "app.platform_user_has_permission(app.context_user_id(), 'platform.audit.read')",
    );
    for (const path of [
      "/api/v1/tenants/{tenantId}/audit-events:",
      "/api/v1/tenants/{tenantId}/audit-events/verify:",
      "/api/v1/platform/audit:",
      "/api/v1/platform/audit/verify:",
    ]) {
      expect(openapi).toContain(path);
    }
    expect(openapi).toContain("operationId: listTenantAuditEvents");
    expect(openapi).toContain("operationId: verifyTenantAuditChain");
    expect(openapi).toContain("operationId: listPlatformAuditEvents");
    expect(openapi).toContain("operationId: verifyPlatformAuditChain");
  });

  it("advances one exact compatibility window and publishes fail-closed readiness", () => {
    const current = functionBody("schema_compatibility_v20()");
    const predecessor = functionBody("schema_compatibility_v19()");
    const retired = functionBody("schema_compatibility_v18()");
    const readiness = functionBody("audit_reader_schema_readiness_v1()");
    expect(current).toContain("journal_count = 104");
    expect(current).toContain("journal_latest_created_at = 1787693815749");
    expect(predecessor).toContain("FROM app.schema_compatibility_v20()");
    expect(predecessor).toContain("migration.migration_ordinal <= 103");
    expect(retired).toContain("'UNSUPPORTED'::text");
    expect(readiness).toContain("current_count = 104");
    expect(readiness).toContain("predecessor_count = 103");
    expect(readiness).toContain("retired_count = 0");
    expect(readiness).toContain("table_row.relforcerowsecurity");
    expect(readiness).toContain("procedure.prosecdef");
    expect(readiness).toContain("procedure.provolatile <> 'v'");
    expect(readiness).toContain("periapsis_audit_reader_owner");
    expect(readiness).toContain("app.require_live_audit_session_v1(uuid,uuid)");
  });
});
