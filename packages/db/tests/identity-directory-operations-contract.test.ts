import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrations = resolve(import.meta.dirname, "../migrations");
const structural = readFileSync(
  resolve(migrations, "0059_certain_psynapse.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(migrations, "0060_identity_directory_operation_security.sql"),
  "utf8",
);
const bigintCorrection = readFileSync(
  resolve(migrations, "0061_tired_prima.sql"),
  "utf8",
);
const abi = readFileSync(
  resolve(migrations, "0062_identity_directory_operation_abi.sql"),
  "utf8",
);
const tenantLeadingIndex = readFileSync(
  resolve(migrations, "0063_serious_pixie.sql"),
  "utf8",
);
const readiness = readFileSync(
  resolve(migrations, "0064_identity_directory_operation_readiness_v10.sql"),
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

describe("tenant LDAP bounded directory-operation schema", () => {
  it("keeps both relations tenant-scoped, forced-RLS and runtime opaque", () => {
    for (const table of [
      "tenant_ldap_directory_operation_runs",
      "tenant_ldap_directory_run_mappings",
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
      expect(security).toMatch(
        new RegExp(
          `REVOKE ALL ON TABLE public\\.${table}\\s+FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
        ),
      );
    }
    expect(readiness).toContain("relation.relforcerowsecurity");
    expect(readiness).toContain("policy.polrelid = relation_oid");
  });

  it("pins exact composite provider, binding, access and mapping identities", () => {
    for (const constraint of [
      "tenant_ldap_directory_runs_provider_fk",
      "tenant_ldap_directory_runs_binding_fk",
      "tenant_ldap_directory_runs_access_epoch_fk",
      "tenant_ldap_directory_run_mappings_run_fk",
      "tenant_ldap_directory_run_mappings_rule_fk",
      "tenant_ldap_directory_run_mappings_epoch_fk",
    ]) {
      expect(structural).toContain(`CONSTRAINT "${constraint}"`);
      expect(readiness).toContain(`'${constraint}'`);
    }
    expect(bigintCorrection).toContain(
      'ALTER COLUMN "mapping_revision" SET DATA TYPE bigint',
    );
    expect(tenantLeadingIndex).toContain(
      '("tenant_id","bind_secret_key_version","status","expires_at")',
    );
    expect(readiness).toContain(
      "pg_catalog.pg_get_indexdef(index_oid, 1, true)",
    );
  });

  it("stores only revision pins, sanitized result metadata and a bounded reason", () => {
    const runs = structural.slice(
      structural.indexOf('CREATE TABLE "tenant_ldap_directory_operation_runs"'),
      structural.indexOf('CREATE TABLE "tenant_ldap_directory_run_mappings"'),
    );
    expect(runs).toContain('"endpoint_snapshot_digest" "bytea" NOT NULL');
    expect(runs).toContain('"bind_secret_key_version" integer NOT NULL');
    expect(runs).toContain('"matched_entry_count" integer');
    expect(runs).toContain('"result_truncated" boolean');
    expect(runs).not.toMatch(
      /username|subject_digest|directory_value|raw_filter/,
    );
    expect(structural).toContain(
      "CREATE TYPE \"public\".\"ldap_directory_operation_kind\" AS ENUM('search_user', 'filter_user', 'filter_group')",
    );
    expect(structural).toContain(
      'char_length("tenant_ldap_directory_operation_runs"."reason") <= 500',
    );
  });
});

describe("tenant LDAP bounded directory-operation ABI", () => {
  it("serializes one shared DB-backed 5/20/50 admission budget", () => {
    const begin = functionBody(
      abi,
      "private_begin_tenant_ldap_directory_operation_v1",
    );
    expect(begin).toContain("pg_advisory_xact_lock");
    expect(begin).toContain("tenant_ldap_directory_rate:");
    expect(begin).toContain("recent_actor_provider_count >= 5");
    expect(begin).toContain("recent_provider_count >= 20");
    expect(begin).toContain("recent_tenant_count >= 50");
    expect(begin).toContain("ERRCODE = '53300'");
    for (const wrapper of [
      "begin_tenant_ldap_administrative_search_v1",
      "begin_tenant_ldap_mapping_dry_run_v1",
    ]) {
      expect(functionBody(abi, wrapper)).toContain(
        "app.private_begin_tenant_ldap_directory_operation_v1",
      );
    }
  });

  it("commits a secret-bearing network snapshot but never audits secret material", () => {
    const begin = functionBody(
      abi,
      "private_begin_tenant_ldap_directory_operation_v1",
    );
    expect(begin).toContain("bind_secret_ciphertext bytea");
    expect(begin).toContain("bind_secret_nonce bytea");
    expect(begin).toContain("bind_secret_key_version integer");
    const admin = functionBody(
      abi,
      "begin_tenant_ldap_administrative_search_v1",
    );
    const auditStart = admin.indexOf("app.append_tenant_authorization_audit");
    const audit = admin.slice(
      auditStart,
      admin.indexOf("RETURN QUERY", auditStart),
    );
    expect(audit).toContain("'bind_secret_version'");
    expect(audit).toContain("'bind_secret_key_version'");
    expect(audit).not.toMatch(/ciphertext|nonce|bind_dn|custom_ca|filter/i);
    expect(audit).toContain("jsonb_build_object('reason', p_reason)");
  });

  it("normalizes stale and expired completion without endpoint evidence", () => {
    const complete = functionBody(
      abi,
      "complete_tenant_ldap_directory_operation_v1",
    );
    expect(complete).toContain("effective_endpoint_priority := NULL");
    expect(complete).toContain("effective_category := 'stale_configuration'");
    expect(complete).toContain("effective_category := 'cancelled'");
    expect(complete).toContain(
      "endpoint_priority = effective_endpoint_priority",
    );
    expect(security).toContain("NEW.endpoint_priority IS NULL");
    expect(security).toContain("NEW.category <> 'cancelled'");
  });

  it("acquires a pure digest-only planner snapshot with explicit lifecycle", () => {
    const planner = functionBody(
      abi,
      "get_tenant_ldap_dry_run_planning_snapshot_v1",
    );
    expect(planner).toContain("p_digest_key_versions integer[]");
    expect(planner).toContain("p_subject_digests bytea[]");
    expect(planner).toContain("user_active boolean");
    expect(planner).toContain("tenant_membership_active boolean");
    expect(planner).toContain("AND found_user_active");
    expect(planner).toContain("AND found_membership_active");
    expect(planner).toContain("rules jsonb");
    expect(planner).toContain("security_groups jsonb");
    expect(planner).toContain("role_policies jsonb");
    expect(planner).toContain("delegation jsonb");
    expect(planner).toContain("live_owned_edges jsonb");
    expect(planner).not.toMatch(/\b(?:INSERT|UPDATE|DELETE)\b/);
    expect(planner).not.toMatch(/subject_ciphertext|canonical_subject/);
  });

  it("returns manage-authorized mutation rows and fixes non-empty create notes", () => {
    const create = functionBody(abi, "create_tenant_ldap_mapping_rule_v2");
    expect(create).toContain("FROM app.create_tenant_ldap_mapping_rule_v1");
    expect(create).toContain("SET notes = p_notes");
    expect(create).toContain("IF NOT created.replayed");
    expect(create).toContain("current_result.updated_at, created.replayed");
    expect(
      functionBody(abi, "get_tenant_auth_provider_binding_mutation_result_v1"),
    ).toContain("'identity_provider.manage'");
    expect(
      functionBody(abi, "get_tenant_ldap_mapping_rule_mutation_result_v1"),
    ).toContain("'identity_mapping.manage'");
    expect(abi).toMatch(
      /REVOKE EXECUTE ON FUNCTION app\.create_tenant_ldap_mapping_rule_v1[\s\S]*FROM periapsis_api/,
    );
  });

  it("extends key inventory to transient committed operation snapshots", () => {
    const verifier = functionBody(abi, "verify_identity_keyring_v3");
    expect(verifier).toContain("public.tenant_ldap_directory_operation_runs");
    expect(verifier).toContain("operation.status = 'started'");
    expect(verifier).toContain(
      "operation.expires_at > transaction_timestamp()",
    );
    expect(verifier).toContain("app.verify_identity_keyring_v2");
    expect(abi).toMatch(
      /REVOKE EXECUTE ON FUNCTION app\.verify_identity_keyring_v2[\s\S]*FROM periapsis_api, periapsis_worker/,
    );
  });
});

describe("tenant LDAP directory-operation readiness", () => {
  it("seals exact v10 and only its v9 predecessor", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v10()",
    );
    expect(readiness).toContain("journal_count = 65");
    expect(readiness).toContain("1787650730983");
    expect(readiness).toContain("fingerprint_entries[1:59]");
    expect(readiness).toContain("schema compatibility v8 must be retired");
    expect(readiness).toContain("app.verify_identity_keyring_v3");
    expect(readiness).toContain("app.create_tenant_ldap_mapping_rule_v2");
  });
});
