import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const source = (path: string): string =>
  readFileSync(resolve(repositoryRoot, path), "utf8");

const schema = source("packages/db/src/schema/tenant-settings.ts");
const migration = source(
  "packages/db/migrations/0214_tenant_branding_settings.sql",
);
const openapi = source("packages/contracts/openapi/openapi.yaml");

describe("tenant settings security contract", () => {
  it("keeps one typed tenant-owned row behind forced RLS and a non-login owner", () => {
    expect(schema).toContain('"tenant_settings"');
    expect(schema).toContain('tenantId: uuid("tenant_id")');
    expect(schema).toContain(".primaryKey()");
    expect(schema).not.toContain("jsonb(");
    expect(schema).not.toContain("logoUrl");
    expect(migration).toContain(
      'ALTER TABLE "tenant_settings" FORCE ROW LEVEL SECURITY',
    );
    expect(migration).toContain(
      "ALTER TABLE public.tenant_settings OWNER TO periapsis_tenant_settings_owner",
    );
    expect(migration).toContain(
      "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
    );
    expect(migration).toContain(
      "has_table_privilege('periapsis_api', 'public.tenant_settings', 'SELECT')",
    );
  });

  it("authorizes read and write against one live session and exact tenant permissions", () => {
    expect(migration).toContain(
      "app.require_live_audit_session_v1(p_session_id, context_tenant)",
    );
    expect(migration).toContain(
      "app.current_tenant_human_has_exact_permission_v3(\n       'settings.read', 'tenant'",
    );
    expect(migration).toContain(
      "app.current_tenant_human_has_exact_permission_v3(\n       'settings.manage', 'tenant'",
    );
    expect(migration).toContain(
      "app.lock_current_tenant_authorization_state()",
    );
    expect(migration).toContain("FOR UPDATE;");
    expect(migration).toContain(
      "settings_record.version IS DISTINCT FROM p_expected_version",
    );
  });

  it("commits safe presentation, regional values, and a redacted audit event atomically", () => {
    expect(migration).toContain("private_default_tenant_brand_name_v1");
    expect(migration).toContain("\\202A-\\202E\\2060-\\206F");
    expect(migration).toContain(
      "tenant_record.timezone IS DISTINCT FROM p_timezone",
    );
    expect(migration).toContain("'tenant.settings.update', 'tenant_settings'");
    expect(migration).toContain("before_projection, after_projection");
    expect(migration).toContain(
      "tenant settings update must change at least one field",
    );
  });

  it("publishes only the exact versioned API representation", () => {
    const route = openapi.slice(
      openapi.indexOf("/api/v1/tenants/{tenantId}/settings:"),
      openapi.indexOf("/api/v1/tenants/{tenantId}/settings:") + 4_500,
    );
    expect(route).toContain("permission: settings.read");
    expect(route).toContain("permissions: [settings.read, settings.manage]");
    expect(route).toContain("If-Match");
    expect(route).toContain("TenantSettingsAuditReason");
    expect(openapi).toContain("name: X-Audit-Reason");
    expect(route).not.toContain("logoUrl");
    expect(source("apps/web/src/settings/model.ts")).toContain(
      '"accentColor",\n  "brandMark",\n  "brandName"',
    );
  });
});
