import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");

function readRequiredMigration(fileName: string): string {
  const source = readFileSync(
    resolve(packageRoot, "migrations", fileName),
    "utf8",
  );
  if (source.trim().length === 0) {
    throw new Error(`Migration ${fileName} must not be empty`);
  }
  return source;
}

const security = readRequiredMigration(
  "0037_service_principal_alert_security.sql",
);
const readiness = readRequiredMigration(
  "0039_service_principal_audit_readiness.sql",
);
const initialReadiness = readRequiredMigration(
  "0038_service_principal_readiness_v6.sql",
);

function functionBodyFrom(source: string, name: string): string {
  const markers = [
    `CREATE OR REPLACE FUNCTION "app"."${name}"`,
    `CREATE FUNCTION "app"."${name}"`,
  ];
  const start = Math.max(...markers.map((marker) => source.indexOf(marker)));
  if (start === -1) {
    throw new Error(`Missing readiness function ${name}`);
  }
  const end = source.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`Unterminated readiness function ${name}`);
  }
  return source.slice(start, end);
}

describe("service-account keyring and schema-readiness contract", () => {
  it("publishes the complete timestamp-bound 40-row journal through v6", () => {
    const current = functionBodyFrom(readiness, "schema_compatibility_v6");

    expect(current).toContain(
      "migration.created_at::text || '@' || lower(migration.hash::text)",
    );
    expect(readiness).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v6"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(readiness).toContain("journal_count = 40");
    expect(readiness).toContain("migration_0039_rows = 1");
  });

  it("keeps v5 as the exact sealed 33-row predecessor prefix", () => {
    const predecessor = functionBodyFrom(readiness, "schema_compatibility_v5");

    expect(predecessor).toContain(
      "FROM app.schema_compatibility_v6() AS compatibility",
    );
    expect(predecessor).toContain("journal_count = 40");
    expect(predecessor).toContain("migration_0039_rows = 1");
    expect(predecessor).toContain("migration.migration_ordinal = 33");
    expect(predecessor).toContain("migration.migration_ordinal <= 33");
    expect(predecessor).toContain(
      "migration.created_at::text || '@' || migration.migration_hash",
    );
    expect(predecessor).toContain("'UNSUPPORTED'::text");
    expect(readiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v5()\n      SET app.schema_compatibility_fingerprint FROM CURRENT",
    );
  });

  it("retires the two-release-old v4 projection explicitly", () => {
    const retired = functionBodyFrom(
      initialReadiness,
      "schema_compatibility_v4",
    );

    expect(retired).toContain("0::bigint");
    expect(retired.match(/'UNSUPPORTED'::text/g)).toHaveLength(2);
    expect(initialReadiness).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v4"() TO "periapsis_api", "periapsis_worker"',
    );
  });

  it("audits every expired service-account role grant superseded by create", () => {
    const grant = functionBodyFrom(
      readiness,
      "grant_tenant_service_account_role_v1",
    );
    const capture = grant.indexOf("INTO superseded_role_grants");
    const mutation = grant.indexOf(
      "UPDATE public.tenant_service_account_role_grants AS expired_grant",
    );

    expect(capture).toBeGreaterThan(-1);
    expect(mutation).toBeGreaterThan(capture);
    expect(grant).toContain("'role_grant_id', expired_grant.id");
    expect(grant).toContain("'prior_version', expired_grant.version");
    expect(grant).toContain("'result_version', expired_grant.version + 1");
    expect(grant).toContain("'superseded_role_grants', superseded_role_grants");
  });

  it("returns only bounded sorted key versions for currently live credentials", () => {
    const inventory = functionBodyFrom(
      security,
      "list_live_api_credential_key_versions_v1",
    );
    const declaration = inventory.slice(0, inventory.indexOf("AS $function$"));

    expect(declaration).toContain("p_limit integer");
    expect(declaration).toMatch(/RETURNS TABLE \(\s*key_version integer\s*\)/);
    expect(declaration).not.toMatch(/locator|digest|secret|credential_id/);
    expect(inventory).toMatch(/p_limit IS NULL|p_limit NOT BETWEEN/);
    expect(inventory).toMatch(/NOT BETWEEN 1 AND [0-9]+/);
    expect(inventory).toContain("SELECT DISTINCT credential.key_version");
    expect(inventory).toContain("public.tenant_api_credentials AS credential");
    expect(inventory).toContain(
      "public.tenant_service_accounts AS service_account",
    );
    expect(inventory).toContain("public.tenants AS tenant");
    expect(inventory).toContain("credential.revoked_at IS NULL");
    expect(inventory).toContain(
      "credential.expires_at > transaction_timestamp()",
    );
    expect(inventory).toContain("service_account.archived_at IS NULL");
    expect(inventory).toContain("tenant.status = 'active'");
    expect(inventory).toContain("ORDER BY credential.key_version");
    expect(inventory).toContain("LIMIT p_limit");
  });

  it("grants the bounded inventory without exposing credential material", () => {
    expect(security).toContain(
      'ALTER FUNCTION "app"."list_live_api_credential_key_versions_v1"',
    );
    expect(security).toMatch(
      /REVOKE ALL ON FUNCTION "app"\."list_live_api_credential_key_versions_v1"[^;]* FROM PUBLIC[^;]*"periapsis_api"/,
    );
    expect(security).toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."list_live_api_credential_key_versions_v1"[^;]* TO "periapsis_api"/,
    );
    expect(security).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*ON TABLE "public"\."tenant_api_credentials"/,
    );
  });

  it("seals only an exact v6 manifest and binds the seal to v5", () => {
    const seal = functionBodyFrom(
      readiness,
      "seal_schema_compatibility_manifest",
    );

    expect(seal).toContain(
      "FROM app.schema_compatibility_v6() AS compatibility",
    );
    expect(seal).toContain(
      "p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}",
    );
    expect(seal).toContain("ALTER FUNCTION app.schema_compatibility_v5()");
    expect(readiness).toMatch(
      /REVOKE ALL ON FUNCTION "app"\."seal_schema_compatibility_manifest"[^;]*"periapsis_api"/,
    );
    expect(readiness).not.toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."seal_schema_compatibility_manifest"/,
    );
  });
});
