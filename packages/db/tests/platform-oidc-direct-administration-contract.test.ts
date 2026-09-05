import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const source = (path: string): string =>
  readFileSync(resolve(packageRoot, path), "utf8");

const runtime = source(
  "migrations/0180_platform_oidc_direct_administration.sql",
);
const compatibility = source(
  "migrations/0181_platform_oidc_direct_administration_compatibility.sql",
);
const federationSchema = source("src/schema/identity-platform-federation.ts");
const directSchema = source("src/schema/identity-platform-login.ts");

const compact = (value: string): string => value.replace(/\s+/gu, " ");

describe("direct platform OIDC administration V40 contract", () => {
  it("publishes the two exact lifecycle ABIs and keeps direct mode fixed", () => {
    for (const name of ["activate", "deactivate"]) {
      expect(compact(runtime)).toContain(
        compact(`CREATE FUNCTION app.${name}_platform_oidc_direct_login_v1(
          p_session_id uuid,
          p_provider_id uuid,
          p_expected_version bigint,
          p_audit_event_id uuid,
          p_request_id uuid,
          p_correlation_id uuid,
          p_ip_address inet,
          p_user_agent text,
          p_authentication_method text,
          p_reason text
        ) RETURNS TABLE (version bigint, document jsonb)`),
      );
    }
    expect(runtime).toContain("THEN 'existing_identity' ELSE 'disabled' END");
    expect(runtime).not.toContain("account_mode = runtime_policy.account_mode");
    expect(runtime).not.toContain("create_identity");
  });

  it("authorizes read and manage, locks both revisions, and audits atomically", () => {
    expect(runtime).toContain(
      "p_session_id, 'platform.identity_provider.manage', p_authentication_method",
    );
    expect(runtime).toContain(
      "p_session_id, 'platform.identity_provider.read', p_authentication_method",
    );
    expect(runtime).toContain("provider.version = p_expected_version");
    expect(runtime).toContain(
      "login_policy.revision = login_policy_record.revision",
    );
    expect(runtime).toContain("version = provider.version + 1");
    expect(runtime).toContain("revision = login_policy.revision + 1");
    expect(runtime).toContain(
      "platform.identity_provider.direct_login.activated",
    );
    expect(runtime).toContain(
      "platform.identity_provider.direct_login.deactivated",
    );
    expect(runtime).toContain("PERFORM app.append_platform_audit_event(");
  });

  it("uses a transaction-local capability and preserves tenant execution", () => {
    expect(runtime).toContain("app.platform_oidc_direct_login_write_v1");
    expect(compact(runtime)).toContain(
      "format( '%s:%s:%s', p_provider_id, login_policy_record.revision, transition )",
    );
    expect(runtime).toContain(
      "direct platform OIDC policy requires its protected ABI",
    );
    expect(runtime).toContain(
      "active direct login requires its tenant-execution runtime",
    );
    expect(runtime).toContain("OR NOT runtime_policy_record.enabled");
    expect(runtime).not.toMatch(/SET[\s\S]{0,180}platform_login_enabled\s*=/u);
  });

  it("projects direct state and activation readiness without exposing secrets", () => {
    expect(
      runtime.match(/platform_oidc_login_policies AS login_policy/gu)?.length,
    ).toBeGreaterThanOrEqual(2);
    expect(
      runtime.match(
        /WHEN 'oidc' THEN coalesce\(login_policy\.enabled, false\)/gu,
      ),
    ).toHaveLength(2);
    expect(runtime.match(/ELSE false END/gu)?.length).toBeGreaterThanOrEqual(2);
    expect(runtime.match(/'platformLoginActivationAvailable'/gu)).toHaveLength(
      2,
    );
    expect(
      runtime.match(
        /app\.private_platform_oidc_direct_activation_available_v1\(provider\.id\)/gu,
      ),
    ).toHaveLength(2);
    expect(runtime).toContain("AND NOT login_policy.enabled");
    expect(runtime).toContain("AND login_policy.account_mode = 'disabled'");
    expect(federationSchema).toContain(
      "platformLoginEnabled sentinel is permanently false",
    );
    expect(directSchema).toContain(
      "Direct platform login is an independently administered, prelinked-only",
    );
  });

  it("requires an already-live, snapshot-ready tenant OIDC runtime", () => {
    for (const fragment of [
      "runtime_policy.enabled",
      "NOT runtime_policy.platform_login_enabled",
      "NOT configuration.allow_refresh_token",
      "secret.retired_at IS NULL",
      "secret_key.retired_at IS NULL",
      "discovery.cacheable",
      "discovery.fresh_until > statement_timestamp()",
      "jwks.cacheable",
      "jwks.fresh_until > statement_timestamp()",
      "platform_floor.scope = 'platform_floor'",
    ]) {
      expect(runtime).toContain(fragment);
    }
    expect(compact(runtime)).toContain(
      "app.private_platform_oidc_direct_configuration_v1( p_provider_id, NULL ) IS NULL",
    );
  });

  it("provides only a full-proof read-only tenant-switch replay lookup", () => {
    expect(runtime).toContain(
      "CREATE FUNCTION app.lookup_platform_oidc_tenant_switch_replay_v1(",
    );
    expect(runtime).toContain("LANGUAGE plpgsql\nSTABLE\nSECURITY DEFINER");
    for (const field of [
      "sourceTokenDigest",
      "newTokenDigest",
      "csrfSecretDigest",
      "rotationFamilyId",
      "occurredAt",
      "idleExpiresAt",
      "absoluteExpiresAt",
    ]) {
      expect(runtime).toContain(`'${field}'`);
    }
    for (const fragment of [
      "source_session.revoke_reason =",
      "rotated_session.token_digest = new_token_digest",
      "rotated_state.primary_kind = 'tenant_platform_provider'",
      "rotated_provenance.access_grant_id = command.access_grant_id",
      "audit_event.action = 'platform.oidc.session.tenant_switched'",
      "audit_event.metadata = jsonb_build_object(",
      "RETURN jsonb_build_object('matched',false)",
      "RETURN jsonb_build_object('matched',true,'result',matched_result)",
    ]) {
      expect(runtime).toContain(fragment);
    }
    expect(runtime).not.toMatch(
      /FUNCTION app\.lookup_platform_oidc_tenant_switch_replay_v1[\s\S]*?\b(?:INSERT|UPDATE|DELETE)\b[\s\S]*?\$function\$/u,
    );
  });

  it("seals only the versioned V40 roots and retires immutable predecessors", () => {
    expect(compatibility).toContain("coordinated cutover");
    expect(compatibility).toContain("migration-to-seal interval is");
    expect(compatibility).not.toContain("rolling edge");
    for (const root of [
      "schema_compatibility_v40",
      "private_platform_identity_dependency_surface_hash_v6",
      "private_platform_identity_runtime_schema_readiness_v6",
      "platform_identity_runtime_schema_readiness_v6",
      "private_platform_oidc_direct_dependency_surface_hash_v2",
      "private_platform_oidc_direct_runtime_schema_readiness_v2",
      "platform_oidc_direct_runtime_schema_readiness_v2",
    ]) {
      expect(compatibility).toContain(root);
    }
    expect(compatibility).toContain("p_expected_count IS DISTINCT FROM 182");
    expect(compatibility).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788085744122",
    );
    expect(compatibility).toContain(
      "ALTER FUNCTION app.schema_compatibility_v39()",
    );
    expect(compatibility).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()",
    );
    expect(compatibility).toContain(
      "REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()",
    );
    expect(compatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v39",
    );
    expect(compatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.platform_identity_runtime_schema_readiness_v5",
    );
    expect(compatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1",
    );
  });
});
