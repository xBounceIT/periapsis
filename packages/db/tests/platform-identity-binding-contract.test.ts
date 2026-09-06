import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectedPlatformIdentityProviderReadinessSourceHash,
  expectedPlatformTenantLifecycleReadinessSourceHash,
  expectedSchemaCompatibilityV33SourceHash,
  expectedSchemaCompatibilityV34SourceHash,
  expectedTenantPlatformIdentityBindingReadinessV1SourceHash,
  expectedTenantPlatformIdentityBindingReadinessV2SourceHash,
  expectedTenantPlatformIdentityBindingSurfaceHashSourceHash,
} from "../src/admin/schema-compatibility-manifest.gen.js";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");
const schema = readFileSync(
  resolve(packageRoot, "src/schema/identity-platform-bindings.ts"),
  "utf8",
);
const tenantSchema = readFileSync(
  resolve(packageRoot, "src/schema/identity-access.ts"),
  "utf8",
);
const structural = migration("0159_material_talkback.sql");
const security = migration(
  "0160_tenant_platform_identity_binding_security.sql",
);
const generatedClosure = migration("0161_lazy_shiver_man.sql");
const compatibility = migration(
  "0162_tenant_platform_identity_binding_compatibility.sql",
);
const lifecycle = migration("0164_platform_oidc_binding_lifecycle.sql");
const generator = readFileSync(
  resolve(packageRoot, "../../scripts/generate-schema-compatibility.mjs"),
  "utf8",
);
const querySource = readFileSync(
  resolve(
    packageRoot,
    "../../services/api/internal/postgres/queries/platform_identity_bindings.sql",
  ),
  "utf8",
);

function functionBody(name: string): string {
  const start = security.indexOf(`CREATE FUNCTION app.${name}`);
  expect(start).toBeGreaterThan(-1);
  const end = security.indexOf("$function$;", start);
  expect(end).toBeGreaterThan(start);
  return security.slice(start, end);
}

const protectedTables = [
  "tenant_auth_provider_login_keys",
  "tenant_platform_auth_provider_bindings",
  "tenant_platform_identity_provider_access_epochs",
  "tenant_platform_identity_binding_commands",
] as const;

const protectedFunctions = [
  "list_tenant_platform_auth_provider_bindings_v1",
  "get_tenant_platform_auth_provider_binding_v1",
  "create_tenant_platform_auth_provider_binding_v1",
  "update_tenant_platform_auth_provider_binding_v1",
  "archive_tenant_platform_auth_provider_binding_v1",
] as const;

describe("tenant platform identity binding database contract", () => {
  it("models one cross-family login namespace and physically separate provenance", () => {
    expect(schema).toContain('"tenant_auth_provider_login_keys"');
    expect(schema).toContain("'tenant_provider', 'platform_provider'");
    expect(schema).toContain(
      'primaryKey({\n      name: "tenant_auth_provider_login_keys_pkey"',
    );
    expect(schema).toContain(
      '"tenant_platform_identity_provider_access_epochs"',
    );
    expect(schema).toContain(
      '"tenant_platform_auth_provider_bindings_activation_check"',
    );
    expect(schema).toContain(
      "sql`${table.enabled} = (${table.currentAccessEpochId} is not null)`",
    );
    expect(tenantSchema).toContain(
      'name: "tenant_auth_provider_bindings_login_claim_fk"',
    );
    expect(schema).toContain(
      'name: "tenant_platform_auth_provider_bindings_login_claim_fk"',
    );
    expect(schema).toContain(
      'name: "tenant_platform_auth_provider_bindings_current_epoch_fk"',
    );
    expect(generatedClosure).toContain(
      'ADD CONSTRAINT "tenant_auth_provider_bindings_login_claim_fk"',
    );
    expect(generatedClosure).toContain(
      'ADD CONSTRAINT "tenant_platform_auth_provider_bindings_login_claim_fk"',
    );
  });

  it("keeps all four tables owner-only behind forced RLS", () => {
    for (const table of protectedTables) {
      expect(structural).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(`public.${table}`);
    }
    expect(security).toContain("REVOKE ALL ON TABLE");
    expect(security).toContain("FROM PUBLIC, periapsis_api, periapsis_worker");
    expect(compatibility).toContain("policy_count = 0");
    expect(compatibility).toContain("direct_table_privilege_count = 0");
    expect(compatibility).toContain(
      "private_tenant_platform_identity_binding_surface_hash_v1",
    );
    expect(compatibility).toContain(
      "e6d030f84e156818247ea24720c7fc56a326b8a612c55cc4766027c4d6f0752a",
    );
  });

  it("backfills archived tenant bindings and guards the namespace in both directions", () => {
    const backfillStart = security.indexOf(
      "INSERT INTO public.tenant_auth_provider_login_keys",
    );
    const backfillEnd = security.indexOf(
      "--> statement-breakpoint",
      backfillStart,
    );
    expect(backfillStart).toBeGreaterThan(-1);
    expect(backfillEnd).toBeGreaterThan(backfillStart);
    const backfill = security.slice(backfillStart, backfillEnd);
    expect(backfill).toContain(
      "FROM ONLY public.tenant_auth_provider_bindings AS binding",
    );
    expect(backfill).not.toContain("binding.archived_at IS NULL");
    expect(security).toContain(
      "CREATE CONSTRAINT TRIGGER tenant_auth_provider_login_keys_child_guard_v1",
    );
    expect(security).toContain("DEFERRABLE INITIALLY DEFERRED");
    expect(security).toContain(
      "tenant auth-provider login claim has no exact tenant binding",
    );
    expect(security).toContain(
      "tenant auth-provider login claim has no exact platform binding",
    );
    expect(security).toContain(
      "private_create_tenant_auth_provider_login_claim_v1",
    );
    expect(security).toContain(
      "private_rename_tenant_auth_provider_login_claim_v1",
    );
    expect(security).toContain(
      "CREATE OR REPLACE FUNCTION app.create_tenant_auth_provider_binding_v2",
    );
    expect(security).toContain(
      "CREATE OR REPLACE FUNCTION app.update_tenant_auth_provider_binding_v1",
    );
  });

  it("exposes permission-checked administration ABIs with truthful activation projections", () => {
    for (const name of protectedFunctions) {
      expect(security).toContain(`CREATE FUNCTION app.${name}`);
    }
    expect(security).toContain("'platform.identity_binding.read'");
    expect(security).toContain("'platform.identity_binding.manage'");
    expect(security).toContain("NOT provider.enabled");
    expect(security).toContain("tenant.status = 'active'");
    expect(lifecycle).toContain("'activationAvailable'");
    expect(lifecycle).toContain("binding.current_access_epoch_id IS NULL");
    expect(lifecycle).toContain(
      "CREATE FUNCTION app.activate_tenant_platform_auth_provider_binding_v1(",
    );
    expect(lifecycle).toContain(
      "CREATE FUNCTION app.deactivate_tenant_platform_auth_provider_binding_v1(",
    );
    expect(lifecycle).toContain("p_expected_tenant_version integer");
    expect(lifecycle).toContain("source.authoritative");
    expect(lifecycle).toContain("NOT source.protected");
    expect(lifecycle).toContain(
      "'identity_provider_access:%s:%s', binding_record.id, next_sequence",
    );
    expect(security).toContain(
      "tenant platform identity binding revision conflict",
    );
    expect(
      security.match(/p_expected_version NOT BETWEEN 1 AND 2147483646/g),
    ).toHaveLength(2);
    expect(security).toContain("USING ERRCODE = '40001'");
    expect(security).not.toMatch(
      /(?:INSERT|UPDATE|DELETE)[\s\S]{0,80}user_platform_roles/i,
    );
  });

  it("uses a tenant-aware composite CAS in lifecycle-compatible lock order", () => {
    expect(security).toContain("'version', tenant.version");
    expect(security).toContain(
      "CREATE FUNCTION app.guard_tenant_platform_identity_binding_tenant_projection_v1()",
    );
    expect(security).toContain(
      "CREATE TRIGGER tenants_identity_projection_version_guard_v1",
    );
    expect(security).toContain("NEW.version IS DISTINCT FROM OLD.version + 1");
    expect(security).toContain("NEW.version IS NOT DISTINCT FROM OLD.version");
    expect(security).toContain(
      "CONSTRAINT = 'tenants_identity_projection_version_check'",
    );
    expect(security.match(/p_expected_tenant_version integer/g)).toHaveLength(
      2,
    );

    for (const name of [
      "update_tenant_platform_auth_provider_binding_v1(",
      "archive_tenant_platform_auth_provider_binding_v1(",
    ]) {
      const body = functionBody(name);
      const stateLock = body.indexOf(
        "FROM ONLY public.tenant_authorization_states AS authorization_state",
      );
      const tenantLock = body.indexOf("FROM ONLY public.tenants AS tenant");
      const bindingLock = body.indexOf(
        "FROM ONLY public.tenant_platform_auth_provider_bindings AS binding",
        tenantLock,
      );
      expect(stateLock).toBeGreaterThan(-1);
      expect(tenantLock).toBeGreaterThan(stateLock);
      expect(bindingLock).toBeGreaterThan(tenantLock);
      expect(body.slice(stateLock, tenantLock)).toContain("FOR SHARE");
      expect(body.slice(tenantLock, bindingLock)).toContain("FOR SHARE");
      expect(body.slice(bindingLock)).toContain("FOR UPDATE");
      expect(body).toContain(
        "tenant_record.version <> p_expected_tenant_version",
      );
      expect(body).toContain(
        "tenant platform identity binding revision conflict",
      );
    }

    expect(security).toContain(
      "RETURNS TABLE (version bigint, tenant_version integer)",
    );
    expect(security).toContain(
      "RETURN QUERY SELECT next_version, tenant_record.version",
    );
    expect(
      querySource.match(/sqlc\.arg\(expected_tenant_version\)/g),
    ).toHaveLength(4);
    expect(querySource).toContain(
      "result.tenant_version::integer AS tenant_version",
    );
  });

  it("binds idempotency to the original receipt while replaying the current document", () => {
    expect(schema).toMatch(
      /unique\("tenant_platform_identity_binding_commands_replay_key"\)\.on\(\s*table\.actorUserId,\s*table\.operation,\s*table\.keyDigest,\s*\)/,
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_platform_identity_binding_commands_replay_key" UNIQUE("actor_user_id","operation","key_digest")',
    );
    expect(structural).not.toContain(
      '"tenant_platform_identity_binding_commands_replay_key" UNIQUE("tenant_id"',
    );
    expect(security).toContain(
      "replay_command.request_digest <> canonical_request_digest",
    );
    expect(security).toContain(
      "p_request_digest || convert_to(jsonb_build_array(",
    );
    expect(security).toContain(
      "'periapsis/platform-identity-provider-tenant-binding-create/v1'",
    );
    expect(security).toContain(
      "p_platform_provider_id::text, p_tenant_id::text, p_key",
    );
    expect(security).toContain("canonical_request_digest, p_binding_id, 1");
    expect(security).toContain("replay_command.result_version, true");
    expect(schema).toContain("sql`${table.resultVersion} = 1`");
    expect(security).toContain(
      "private_tenant_platform_auth_provider_binding_document_v1(binding.id)",
    );
    expect(security).toContain(
      "tenant platform identity binding idempotency key was reused with different input",
    );
    expect(security).toContain(
      "tenant_platform_identity_binding_commands:expiry-cleanup:v1",
    );
    expect(security).toContain("LIMIT 64");
    expect(security).toContain("FOR UPDATE SKIP LOCKED");
    expect(schema).toContain("now() + interval '24 hours'");

    const createBody = functionBody(
      "create_tenant_platform_auth_provider_binding_v1(",
    );
    const commandSerialization = createBody.indexOf(
      "tenant_platform_identity_binding_commands:binding.create:v1:",
    );
    const expiredCleanup = createBody.indexOf(
      "DELETE FROM ONLY public.tenant_platform_identity_binding_commands AS command",
    );
    const replayLookup = createBody.indexOf(
      "SELECT command.* INTO replay_command",
    );
    const replayReturn = createBody.indexOf(
      "RETURN QUERY SELECT replay_command.result_binding_id",
    );
    const pairSerialization = createBody.indexOf("1346978353");
    const existingReservation = createBody.indexOf(
      "tenant platform identity binding already exists",
    );
    const providerEligibility = createBody.indexOf(
      "FROM ONLY public.platform_auth_providers AS provider",
    );
    const tenantEligibility = createBody.indexOf(
      "FROM ONLY public.tenant_authorization_states AS state",
    );
    expect(commandSerialization).toBeGreaterThan(-1);
    expect(expiredCleanup).toBeGreaterThan(commandSerialization);
    expect(replayLookup).toBeGreaterThan(expiredCleanup);
    expect(replayReturn).toBeGreaterThan(replayLookup);
    expect(pairSerialization).toBeGreaterThan(replayReturn);
    expect(existingReservation).toBeGreaterThan(pairSerialization);
    expect(providerEligibility).toBeGreaterThan(existingReservation);
    expect(tenantEligibility).toBeGreaterThan(providerEligibility);
    expect(createBody).toMatch(
      /PERFORM pg_advisory_xact_lock\(hashtextextended\(\s*'tenant_platform_identity_binding_commands:binding\.create:v1:' \|\|\s*actor_id::text \|\| ':' \|\| encode\(p_key_digest, 'hex'\), 0\s*\)\)/,
    );
    expect(createBody).toMatch(
      /PERFORM pg_advisory_xact_lock\(\s*1346978353,\s*hashtext\(p_platform_provider_id::text \|\| ':' \|\| p_tenant_id::text\)\s*\)/,
    );
    const targetedCleanup = createBody.slice(
      expiredCleanup,
      createBody.indexOf("IF pg_try_advisory_xact_lock", expiredCleanup),
    );
    const replayProbe = createBody.slice(
      replayLookup,
      createBody.indexOf("IF FOUND THEN", replayLookup),
    );
    for (const commandProbe of [targetedCleanup, replayProbe]) {
      expect(commandProbe).toContain("command.actor_user_id = actor_id");
      expect(commandProbe).toContain("command.operation = 'binding.create'");
      expect(commandProbe).toContain("command.key_digest = p_key_digest");
    }
    expect(targetedCleanup).not.toContain("command.tenant_id");
    expect(replayProbe).not.toContain("command.tenant_id");
    expect(createBody).toContain(
      "id, tenant_id, actor_user_id, operation, key_digest, request_digest",
    );
    expect(
      createBody.match(/tenant platform identity binding already exists/g),
    ).toHaveLength(1);
  });

  it("requires two distinct, safe audit envelopes and correlates both append-only chains", () => {
    expect(security).toContain(
      "p_tenant_audit_event_id = p_platform_audit_event_id",
    );
    expect(security).toContain("p_ip_address IS NULL");
    expect(security).toContain(
      "octet_length(p_user_agent) NOT BETWEEN 1 AND 512",
    );
    expect(security).toContain(
      "private_platform_identity_text_is_safe_v1(p_user_agent, false)",
    );
    expect(security).toContain("'system', NULL");
    expect(security).toContain("'platform_actor_user_id'");
    expect(security).toContain("'platform_audit_event_id'");
    expect(security).toContain("'tenant_audit_event_id'");
    expect(compatibility).toContain(
      "tenant_event.metadata ->> 'platform_audit_event_id'",
    );
    expect(compatibility).toContain(
      "platform_event.metadata ->> 'tenant_audit_event_id'",
    );
  });

  it("seals v34/current, v33/predecessor and retires v32", () => {
    expect(compatibility).toContain(
      "CREATE FUNCTION app.schema_compatibility_v34()",
    );
    expect(compatibility).toContain("journal_count = 163");
    expect(compatibility).toContain("fingerprint_entries[1:159]");
    expect(compatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v33()",
    );
    expect(compatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v32()",
    );
    expect(compatibility).toContain(
      "SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(compatibility).toContain(
      "ALTER FUNCTION app.schema_compatibility_v34()",
    );
    expect(compatibility).not.toContain(
      "ALTER FUNCTION app.schema_compatibility_v33()\n      SET app.schema_compatibility_fingerprint",
    );
    expect(compatibility).toContain(
      "CREATE FUNCTION app.tenant_platform_identity_binding_schema_readiness_v1()",
    );
    expect(compatibility).toContain(
      "CREATE FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()",
    );
    expect(compatibility).not.toContain(
      "DROP FUNCTION app.platform_identity_provider_schema_readiness_v1()",
    );
    expect(compatibility).toContain("JOIN pg_catalog.pg_rewrite AS rule_row");
    expect(compatibility).toContain("JOIN pg_catalog.pg_policy AS policy_row");
    expect(compatibility).toContain(
      "JOIN pg_catalog.pg_inherits AS inheritance",
    );
    expect(compatibility).toContain(
      "schema compatibility v34 trusted roots are not exact",
    );
    for (const sourceHash of [
      expectedSchemaCompatibilityV34SourceHash,
      expectedSchemaCompatibilityV33SourceHash,
      expectedPlatformTenantLifecycleReadinessSourceHash,
      expectedPlatformIdentityProviderReadinessSourceHash,
      expectedTenantPlatformIdentityBindingSurfaceHashSourceHash,
      expectedTenantPlatformIdentityBindingReadinessV1SourceHash,
      expectedTenantPlatformIdentityBindingReadinessV2SourceHash,
    ]) {
      expect(compatibility).toContain(sourceHash);
    }
    expect(generator).toContain('constant: "SchemaCompatibilityV34"');
    expect(generator).toContain('constant: "SchemaCompatibilityV33"');
    expect(generator).toContain(
      'constant: "TenantPlatformIdentityBindingReadinessV2"',
    );
    expect(generator).toContain(
      'migration: "0162_tenant_platform_identity_binding_compatibility.sql"',
    );
  });
});
