import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = readFileSync(
  resolve(packageRoot, "migrations/0090_early_madelyne_pryor.sql"),
  "utf8",
);
const authorizationSchema = readFileSync(
  resolve(packageRoot, "src/schema/authorization.ts"),
  "utf8",
);

function functionBody(name: string): string {
  const create = migration.indexOf(`CREATE FUNCTION app.${name}`);
  const replace = migration.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`);
  const start = create === -1 ? replace : create;
  if (start === -1) {
    throw new Error(`missing LDAP administration function ${name}`);
  }
  const end = migration.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`unterminated LDAP administration function ${name}`);
  }
  return migration.slice(start, end);
}

describe("LDAP synchronization administration database contract", () => {
  it("adds the manual-sync command to the canonical generated constraint", () => {
    expect(authorizationSchema).toContain("'identity_sync.run'");
    expect(migration).toContain(
      'ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check"',
    );
    expect(migration).toContain("'identity_sync.run'");
  });

  it("uses a tenant-scoped non-login and non-BYPASSRLS owner", () => {
    expect(migration).toContain(
      "CREATE ROLE periapsis_ldap_administration_owner",
    );
    expect(migration).toContain(
      "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
    );
    expect(migration).toContain("NOREPLICATION NOBYPASSRLS");
    expect(migration.match(/CREATE POLICY ldap_admin_owner_/g)).toHaveLength(8);
    expect(migration).toContain("tenant_id = app.context_tenant_id()");
    expect(migration).toContain(
      "actor_membership_id = app.current_tenant_membership_id()",
    );
  });

  it("publishes bounded permission-gated redacted reads", () => {
    for (const name of [
      "list_tenant_ldap_sync_runs_v1(",
      "get_tenant_ldap_sync_run_v1(",
      "get_tenant_ldap_sync_status_v1(",
    ]) {
      const body = functionBody(name);
      expect(body).toContain(
        "app.current_tenant_human_has_exact_permission_v3",
      );
      expect(body).toContain("'identity_provider.read', 'tenant'");
    }

    const list = functionBody("list_tenant_ldap_sync_runs_v1(");
    expect(list).toContain("p_page_size NOT BETWEEN 1 AND 101");
    expect(list).toContain("uuid_extract_version(p_after_run_id) = 7");

    const projection = functionBody(
      "private_tenant_ldap_sync_run_projection_v1(",
    );
    expect(projection).toContain("coalesce(pins.mapping_revisions");
    expect(projection).not.toMatch(
      /ciphertext|bind_secret|raw_ldap|subject_digest|cursor_digest[^\s]*\s+AS/,
    );
  });

  it("makes manual start CAS and response-loss safe", () => {
    const body = functionBody("begin_tenant_ldap_manual_sync_run_v2(");
    expect(body).toContain("octet_length(p_idempotency_key_digest) <> 32");
    expect(body).toContain("octet_length(p_request_digest) <> 32");
    expect(body).toContain("pg_advisory_xact_lock");
    expect(body).toContain("command_row.request_digest IS DISTINCT FROM");
    expect(body).toContain("command_row.result_version IS DISTINCT FROM 1");
    expect(body).toContain("existing_run.version < command_row.result_version");
    expect(body).toContain(
      "current_binding_version IS DISTINCT FROM p_expected_binding_version",
    );
    expect(body).toContain("app.begin_tenant_ldap_manual_sync_run_v1(");
    expect(body).toContain("RETURN QUERY SELECT existing_run.id, true");
    expect(migration).toContain(
      "REVOKE EXECUTE ON FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(",
    );
  });

  it("seals only v14 as the v15 rolling predecessor", () => {
    const current = functionBody("schema_compatibility_v15()");
    expect(current).toContain("journal_count = 91");
    expect(current).toContain("journal_latest_created_at = 1787673489517");
    expect(current).toContain("migration_0090_rows = 1");

    const predecessor = functionBody("schema_compatibility_v14()");
    expect(predecessor).toContain("FROM app.schema_compatibility_v15()");
    expect(predecessor).toContain("migration.migration_ordinal <= 90");
    expect(predecessor).toContain("migration_ordinal = 90");
    expect(predecessor).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );

    expect(functionBody("schema_compatibility_v13()")).toContain(
      "'UNSUPPORTED'::text",
    );
    const sealer = functionBody("seal_schema_compatibility_manifest(");
    expect(sealer).toContain("p_expected_count IS DISTINCT FROM 91");
    expect(sealer).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 91",
    );
    expect(sealer).toContain("fingerprint_entries[90]");
    expect(sealer).toContain("FROM app.schema_compatibility_v14()");
    expect(sealer).toContain("schema compatibility v13 must be retired");
  });

  it("self-checks RLS, runtime ACLs, owner privilege, and ABI readiness", () => {
    const readiness = functionBody("ldap_administration_schema_readiness_v1()");
    expect(readiness).toContain("class.relrowsecurity");
    expect(readiness).toContain("class.relforcerowsecurity");
    expect(readiness).toContain("attribute.attnotnull");
    expect(readiness).toContain("has_table_privilege(");
    expect(readiness).toContain("has_function_privilege(");
    expect(readiness).toContain("identity_sync.run");
    expect(migration).toContain(
      "IF NOT app.ldap_administration_schema_readiness_v1() THEN",
    );
  });
});
