import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const source = (path: string): string =>
  readFileSync(resolve(packageRoot, path), "utf8");
const compact = (value: string): string => value.replace(/\s+/gu, " ");

const runtime = source("migrations/0182_mfa_policy_administration.sql");
const compatibility = source(
  "migrations/0183_mfa_policy_administration_compatibility.sql",
);
const schema = source("src/schema/identity-mfa.ts");
const queries = source(
  "../../services/api/internal/postgres/queries/mfa_policy_administration.sql",
);

describe("MFA policy administration V41 contract", () => {
  it("keeps revisions immutable and JS-safe with append-only replay receipts", () => {
    expect(schema).toContain("export const mfaPolicyCommands");
    expect(schema).toContain("between 1 and 9007199254740991");
    expect(schema).toContain("between 0 and 31536000000000000");
    expect(runtime).toContain("MFA policy revisions are immutable");
    expect(runtime).toContain("MFA policy command receipts are append-only");
    expect(runtime).toContain("MFA policy command replay payload mismatch");
    expect(runtime).toContain("USING ERRCODE = '23505'");
    expect(compact(runtime)).toContain(
      "date_trunc( 'milliseconds',transaction_timestamp() )",
    );
  });

  it("publishes the ten exact protected projection and mutation ABIs", () => {
    for (const signature of [
      "list_platform_mfa_policies_v1(uuid,text,uuid,bigint,integer,boolean)",
      "list_tenant_mfa_policies_v1(uuid,uuid,text,uuid,bigint,integer,boolean)",
      "get_platform_mfa_policy_v1(uuid,text,uuid,bigint)",
      "get_tenant_mfa_policy_v1(uuid,uuid,text,uuid,bigint)",
      "simulate_platform_mfa_policy_change_v1(uuid,text,jsonb)",
      "simulate_tenant_mfa_policy_change_v1(uuid,uuid,text,jsonb)",
      "publish_platform_mfa_policy_v1(uuid,text,jsonb)",
      "retire_platform_mfa_policy_v1(uuid,text,jsonb)",
      "publish_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)",
      "retire_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)",
    ]) {
      expect(compact(runtime)).toContain(`app.${signature}`);
      expect(compact(compatibility)).toContain(`'app.${signature}'`);
    }
    for (const query of [
      "ListPlatformMFAPolicies",
      "ListTenantMFAPolicies",
      "GetPlatformMFAPolicy",
      "GetTenantMFAPolicy",
      "SimulatePlatformMFAPolicyChange",
      "SimulateTenantMFAPolicyChange",
      "PublishPlatformMFAPolicy",
      "RetirePlatformMFAPolicy",
      "PublishTenantMFAPolicy",
      "RetireTenantMFAPolicy",
    ]) {
      expect(queries).toContain(`-- name: ${query}`);
    }
  });

  it("freezes the canonical bounded command and simulation shapes", () => {
    for (const field of [
      "'scope'",
      "'tenantId'",
      "'roleId'",
      "'securityGroupId'",
      "'action'",
      "'level'",
      "'localRequired'",
      "'freshnessSeconds'",
      "'enrollmentDeadline'",
      "'eligibleDirectAdministrators'",
      "'readyDirectAdministrators'",
      "'reasonCodes'",
    ]) {
      expect(runtime).toContain(field);
    }
    expect(runtime).toContain("p_limit NOT BETWEEN 1 AND 101");
    expect(runtime).toContain(
      "jsonb_array_length(p_context -> 'roleIds') > 512",
    );
    expect(runtime).toContain(
      "jsonb_array_length(p_context -> 'securityGroupIds') > 512",
    );
    expect(runtime).toContain(
      "tenant MFA simulation context omits changed target",
    );
    expect(runtime).toContain("WHEN 'security_group' THEN 3");
    expect(runtime).toContain("WHEN 'role' THEN 4");
    expect(runtime).toContain("WHEN 'action' THEN 5");
  });

  it("binds replay only to semantics and preserves the first audit envelope", () => {
    const digestStart = runtime.indexOf(
      "semantic_command := jsonb_build_object(",
    );
    const digest = runtime.slice(
      digestStart,
      runtime.indexOf(
        "target_value := app.private_mfa_policy_target_v1(",
        digestStart,
      ),
    );
    expect(digest).toContain("actor_id::text");
    expect(digest).toContain("p_tenant_id::text");
    expect(digest).toContain("p_operation");
    expect(digest).toContain("p_command -> 'target'");
    expect(digest).toContain("expected_revision");
    expect(digest).toContain("p_command -> 'requirement'");
    expect(digest).toContain("reason_value");
    expect(digest).not.toContain("audit_value");
    expect(runtime.indexOf("SELECT command.* INTO receipt")).toBeLessThan(
      runtime.indexOf("audit_value := app.private_mfa_policy_audit_v1"),
    );
  });

  it("requires exact local step-up and locks the recovery proof", () => {
    expect(runtime).not.toMatch(
      /private_require_recent_local_mfa_policy_session_v1[\s\S]*?'recovery_code'/u,
    );
    for (const fragment of [
      "NOT state.recovery_restricted",
      "evidence.kind IN ('totp','webauthn')",
      "evidence.kind = 'totp'",
      "factor.security_revision = evidence.factor_revision",
      "factor.confirmed_at IS NOT NULL",
      "FOR SHARE OF session,local_user",
      "FOR SHARE OF role_grant,role,identity",
      "FOR SHARE OF role_grant,source,role,membership,identity",
      "FOR SHARE OF group_member,member_source,security_group",
      "no_ready_local_mfa",
      "no_ready_local_phishing_resistant",
      "no_ready_local_primary",
    ]) {
      expect(runtime).toContain(fragment);
    }
  });

  it("seals V41/V7/V3 and retires all predecessor runtime ACLs", () => {
    for (const root of [
      "schema_compatibility_v41",
      "private_mfa_policy_administration_dependency_surface_hash_v1",
      "private_mfa_policy_administration_schema_readiness_v1",
      "mfa_policy_administration_schema_readiness_v1",
      "private_platform_identity_dependency_surface_hash_v7",
      "private_platform_identity_runtime_schema_readiness_v7",
      "platform_identity_runtime_schema_readiness_v7",
      "private_platform_oidc_direct_dependency_surface_hash_v3",
      "private_platform_oidc_direct_runtime_schema_readiness_v3",
      "platform_oidc_direct_runtime_schema_readiness_v3",
    ]) {
      expect(compatibility).toContain(root);
    }
    expect(compatibility).toContain("p_expected_count IS DISTINCT FROM 184");
    expect(compatibility).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788094095501",
    );
    for (const predecessor of [
      "schema_compatibility_v40",
      "platform_identity_runtime_schema_readiness_v6",
      "platform_oidc_direct_runtime_schema_readiness_v2",
      "schema_compatibility_v39",
      "platform_identity_runtime_schema_readiness_v5",
      "platform_oidc_direct_runtime_schema_readiness_v1",
    ]) {
      expect(compatibility).toContain(
        `REVOKE ALL ON FUNCTION app.${predecessor}()`,
      );
    }

    for (const trustedSetting of [
      "SET quote_all_identifiers = off",
      "SET TimeZone = 'UTC'",
      "SET DateStyle = 'ISO, YMD'",
      "SET IntervalStyle = 'postgres'",
      "SET extra_float_digits = 3",
      "SET bytea_output = 'hex'",
      "SET standard_conforming_strings = on",
      "SET lc_numeric = 'C'",
    ]) {
      expect(compatibility).toContain(trustedSetting);
    }
  });
});
