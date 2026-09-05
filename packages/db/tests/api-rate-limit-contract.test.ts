import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");

describe("shared API rate-limit schema contract", () => {
  it("adds only purpose-separated API scopes after the stable V48 bundle", () => {
    const sql = migration("0220_api_request_rate_limits.sql");

    expect(sql.match(/ALTER TYPE/g)).toHaveLength(3);
    expect(sql).toContain(`ADD VALUE 'api_network' BEFORE 'bootstrap_totp'`);
    expect(sql).toContain(`ADD VALUE 'api_credential' BEFORE 'bootstrap_totp'`);
    expect(sql).toContain(
      `ADD VALUE 'api_tenant_subject' BEFORE 'bootstrap_totp'`,
    );
    expect(sql).not.toMatch(/CREATE\s+(?:TABLE|POLICY)/iu);
    expect(
      sql.match(/CREATE FUNCTION app\.admit_api_request_v1/gu),
    ).toHaveLength(1);
    expect(sql).not.toMatch(/DROP\s+/iu);
  });

  it("reuses the locked definer ABI without granting rate-limit table access", () => {
    const security = migration("0009_phase_2a_security.sql");
    const admission = migration("0016_fix_auth_admission_null.sql");

    expect(admission).toContain(
      'CREATE OR REPLACE FUNCTION "app"."admit_auth_attempts"',
    );
    expect(admission).toContain("SECURITY DEFINER");
    expect(admission).toContain("SET search_path = pg_catalog, public, app");
    expect(admission).toContain("ORDER BY rule.scope::text, rule.key_digest");
    expect(admission).toContain("octet_length(rule.key_digest) <> 32");
    expect(admission).toContain("rule.max_attempts NOT BETWEEN 1 AND 100");
    expect(admission).toContain("introduced_rate_limit_ids");
    expect(admission).toContain("WHERE id = ANY(introduced_rate_limit_ids)");
    expect(security).toContain(
      'ALTER TABLE "public"."auth_rate_limits" FORCE ROW LEVEL SECURITY',
    );
    expect(security).toContain(
      'REVOKE ALL ON TABLE "public"."auth_rate_limits" FROM PUBLIC',
    );
    expect(security).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."admit_auth_attempts"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[]) TO "periapsis_api"',
    );
    expect(security).not.toMatch(
      /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]+auth_rate_limits[^;]+periapsis_(?:api|worker|notifier|auditor)/iu,
    );
  });

  it("adapts high-churn API traffic without weakening the admission boundary", () => {
    const sql = migration("0220_api_request_rate_limits.sql");

    expect(sql).toContain("SECURITY DEFINER");
    expect(sql).toContain("SET search_path = pg_catalog, public, app");
    expect(sql).toContain("FROM app.admit_auth_attempts(");
    expect(sql).toContain("rule_count NOT BETWEEN 1 AND 3");
    expect(sql).toContain("HAVING count(*) > 1");
    expect(sql).toContain("LIMIT rule_count");
    expect(sql).toContain("FOR UPDATE SKIP LOCKED");
    expect(sql).toContain("DELETE FROM public.auth_rate_limits AS meter");
    expect(sql).toContain("FROM PUBLIC, periapsis_api, periapsis_worker");
    expect(sql).toContain("TO periapsis_api;");
    expect(sql).not.toMatch(
      /GRANT EXECUTE[^;]+admit_api_request_v1[^;]+TO\s+(?:PUBLIC|periapsis_worker|periapsis_notifier|periapsis_auditor)/iu,
    );
  });
});
