import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0032_operator_team_readiness_v5.sql",
  ),
  "utf8",
);
const apiHealth = readFileSync(
  resolve(repositoryRoot, "services/api/internal/postgres/health.go"),
  "utf8",
);
const workerHealth = readFileSync(
  resolve(repositoryRoot, "services/worker/internal/postgres/health.go"),
  "utf8",
);

describe("Phase 2B.2b hardening schema-readiness rotation", () => {
  it("publishes the complete timestamp-bound journal through v5", () => {
    expect(migration).toContain(
      'CREATE FUNCTION "app"."schema_compatibility_v5"()',
    );
    expect(migration).toContain(
      "migration.created_at::text || '@' || lower(migration.hash::text)",
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v5"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(apiHealth).toContain("from app.schema_compatibility_v62()");
    expect(workerHealth).toContain("from app.schema_compatibility_v62()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v51()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v51()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v49()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v49()");
    expect(apiHealth).not.toContain("from app.schema_compatibility_v47()");
    expect(workerHealth).not.toContain("from app.schema_compatibility_v47()");
  });

  it("exposes the exact 30-row v4 predecessor only for the sealed 33-row edge", () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v4"()',
    );
    expect(migration).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );
    expect(migration).toContain("journal_count = 33");
    expect(migration).toContain("journal_latest_created_at = 1787592230466");
    expect(migration).toContain("migration_0032_rows = 1");
    expect(migration).toContain("migration.migration_ordinal = 30");
    expect(migration).toContain("migration.migration_ordinal <= 30");
    expect(migration).toContain(
      "migration.created_at::text || '@' || migration.migration_hash",
    );
    expect(migration).toContain("'UNSUPPORTED'::text");
  });

  it("retires the two-release-old v3 projection with an impossible sentinel", () => {
    expect(migration).toContain(
      'CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v3"()',
    );
    expect(migration).toContain(
      'ALTER FUNCTION "app"."schema_compatibility_v3"() OWNER TO "periapsis_migrator"',
    );
    expect(migration).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v3"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(migration.match(/'UNSUPPORTED'::text/g)).toHaveLength(4);
  });

  it("seals only an exact v5 manifest and binds that seal to v4", () => {
    expect(migration).toContain(
      "FROM app.schema_compatibility_v5() AS compatibility",
    );
    expect(migration).toContain(
      "p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}",
    );
    expect(migration).toContain(
      "ALTER FUNCTION app.schema_compatibility_v4()\n      SET app.schema_compatibility_fingerprint FROM CURRENT",
    );
    expect(migration).toContain(
      'REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"',
    );
  });
});
