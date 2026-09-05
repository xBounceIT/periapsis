import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const migration = readFileSync(
  resolve(packageRoot, "migrations/0215_platform_tenant_access.sql"),
  "utf8",
);
const schema = readFileSync(
  resolve(packageRoot, "src/schema/operator-teams.ts"),
  "utf8",
);
const openapi = readFileSync(
  resolve(repositoryRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);
const repository = readFileSync(
  resolve(repositoryRoot, "services/api/internal/postgres/platform.go"),
  "utf8",
);
const query = readFileSync(
  resolve(
    repositoryRoot,
    "services/api/internal/postgres/queries/platform.sql",
  ),
  "utf8",
);

describe("explicit platform tenant-access database contract", () => {
  it("publishes one dedicated permission only through the system super-admin role", () => {
    expect(migration).toContain("'platform.tenant.access'");
    expect(migration).toContain("role.key='platform_super_admin'");
    expect(migration).toContain("AND role.system");
    expect(migration).toContain("permission.key='platform.tenant.access'");
    expect(migration).toContain(
      "app.platform_user_has_permission(actor_id,'platform.tenant.access')",
    );
    expect(schema).toContain(
      "'operator_team.create', 'platform.tenant_access.authorize'",
    );
  });

  it("binds the command to one live non-recovery session with MFA no older than fifteen minutes", () => {
    expect(migration).toContain("session.id=p_session_id");
    expect(migration).toContain("session.user_id=actor_id");
    expect(migration).toContain(
      "session.authentication_method=p_authentication_method",
    );
    expect(migration).toContain("session.revoked_at IS NULL");
    expect(migration).toContain(
      "session.idle_expires_at>transaction_timestamp()",
    );
    expect(migration).toContain(
      "session.absolute_expires_at>transaction_timestamp()",
    );
    expect(migration).toMatch(
      /session\.mfa_satisfied_at BETWEEN\s+transaction_timestamp\(\)-interval '15 minutes'\s+AND transaction_timestamp\(\)/,
    );
    expect(migration).not.toMatch(
      /p_authentication_method NOT IN \([\s\S]*?'recovery_code'/,
    );
    expect(migration).toContain("FOR SHARE OF session FOR UPDATE OF actor");
  });

  it("rechecks the exact active tenant version on first apply and replay", () => {
    expect(migration).toContain("tenant_record.status<>'active'");
    expect(migration).toContain(
      "tenant_record.version<>p_expected_tenant_version",
    );
    expect(migration).toContain("tenant.status='active'");
    expect(migration).toContain("tenant.version=p_expected_tenant_version");
    expect(migration).toContain(
      "the platform actor already has a tenant membership",
    );
    expect(migration).toContain(
      "CONSTRAINT='tenant_memberships_tenant_user_key'",
    );
  });

  it("creates only an ordinary tenant-admin membership with exact historical provenance", () => {
    expect(migration).toContain(
      "p_membership_id,p_tenant_id,actor_id,'tenant_admin','active',1",
    );
    expect(migration).toContain(
      "p_role_grant_id,p_tenant_id,p_membership_id,tenant_admin_role_id,source_id",
    );
    expect(migration).toContain(
      "p_tenant_id,'manual','platform_super_admin_access',false,true",
    );
    expect(migration.match(/AND NOT source\.authoritative/g)?.length).toBe(4);
    expect(migration).toContain(
      "ON CONFLICT ON CONSTRAINT tenant_authorization_sources_tenant_key_key",
    );
    expect(migration).not.toContain("ON CONFLICT (tenant_id,key)");
    expect(migration).toContain("membership.user_id=NEW.actor_user_id");
    expect(migration).not.toMatch(
      /UPDATE public\.auth_sessions[\s\S]*active_tenant_id/,
    );
  });

  it("couples the tenant audit, platform audit, and replay receipt atomically", () => {
    const tenantAudit = migration.indexOf("INSERT INTO public.audit_events(");
    const platformAudit = migration.indexOf(
      "PERFORM app.append_platform_audit_event(",
      tenantAudit,
    );
    const receipt = migration.indexOf(
      "INSERT INTO public.platform_commands(",
      platformAudit,
    );
    expect(tenantAudit).toBeGreaterThan(-1);
    expect(platformAudit).toBeGreaterThan(tenantAudit);
    expect(receipt).toBeGreaterThan(platformAudit);
    expect(migration).toContain("'tenant.access.authorized'");
    expect(migration).toContain("'platform.tenant_access.authorized'");
    expect(migration).toContain("p_request_id,p_correlation_id");
    expect(migration).toContain(
      "'tenant_audit_event_id',p_tenant_audit_event_id",
    );
  });

  it("uses payload-bound actor-scoped replay and rejects key reuse", () => {
    expect(migration).toContain("'tenant_id',p_tenant_id");
    expect(migration).toContain(
      "'expected_tenant_version',p_expected_tenant_version",
    );
    expect(migration).toContain("'reason',p_reason");
    expect(migration).toContain("command.actor_user_id=actor_id");
    expect(migration).toContain(
      "command.operation='platform.tenant_access.authorize'",
    );
    expect(migration).toContain("command.key_digest=p_idempotency_key_digest");
    expect(migration).toContain(
      "replay.request_digest IS DISTINCT FROM canonical_request_digest",
    );
    expect(migration).toContain("CONSTRAINT='platform_commands_replay_key'");
  });

  it("adds a historical attribution trigger without replacing the existing seal", () => {
    expect(migration).not.toContain(
      "CREATE OR REPLACE FUNCTION app.seal_audit_event()",
    );
    expect(migration).toContain(
      "CREATE FUNCTION app.attribute_platform_tenant_access_audit_v1()",
    );
    expect(migration).toContain(
      "CREATE TRIGGER audit_events_platform_access_attribution_before_insert",
    );
    expect(
      migration.indexOf(
        "CREATE TRIGGER audit_events_platform_access_attribution_before_insert",
      ),
    ).toBeGreaterThan(-1);
    expect(migration).toContain("NEW.actor_type='user'");
    expect(migration).toContain("NEW.impersonated_by_user_id IS NULL");
    expect(migration).toContain("NEW.actor_user_id=context_user");
    expect(migration).toContain("Provenance is intentionally historical");
    const attribution = migration.slice(
      migration.indexOf(
        "CREATE FUNCTION app.attribute_platform_tenant_access_audit_v1()",
      ),
    );
    expect(attribution).not.toContain("membership.status='active'");
    expect(attribution).not.toContain("role_grant.revoked_at IS NULL");
    expect(attribution).not.toContain("source.retired_at IS NULL");
  });

  it("keeps the HTTP and repository boundary aligned with normal audited switching", () => {
    expect(openapi).toContain("/api/v1/platform/tenants/{tenantId}/access:");
    expect(openapi).toContain("freshMfaSeconds: 900");
    expect(openapi).toContain(
      "must still be selected through the normal audited tenant-switch endpoint",
    );
    expect(repository).toContain(
      "validPlatformTenantAccessAuthenticationMethod",
    );
    expect(query).toContain("app.authorize_platform_tenant_access_v1");
  });
});
