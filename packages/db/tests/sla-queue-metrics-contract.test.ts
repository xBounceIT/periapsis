import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migration = readFileSync(
  resolve(import.meta.dirname, "../migrations/0135_sla_queue_metrics_abi.sql"),
  "utf8",
);

function functionBody(name: string): string {
  const declaration = new RegExp(
    `CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\(`,
  ).exec(migration);
  if (declaration?.index === undefined) {
    throw new Error(`Missing function app.${name}`);
  }
  const start = declaration.index;
  const bodyStart = migration.indexOf("AS $function$", start);
  const bodyEnd = migration.indexOf("$function$;", bodyStart + 13);
  if (bodyStart < 0 || bodyEnd < 0) {
    throw new Error(`Incomplete function app.${name}`);
  }
  return migration.slice(start, bodyEnd + "$function$;".length);
}

describe("SLA queue metrics ABI", () => {
  it("uses one database-owned instant and two index-shaped eligible scans", () => {
    const body = functionBody("read_sla_evaluation_queue_metrics_v1");

    expect(body).toContain("RETURNS TABLE(");
    expect(body).toContain("observed_at timestamp with time zone");
    expect(body).toContain("pending_jobs bigint");
    expect(body).toContain("oldest_pending_micros bigint");
    expect(body).toContain("WITH observed AS MATERIALIZED");
    expect(body).toContain("ROWS 1");
    expect(body.match(/clock_timestamp\(\)/g)).toHaveLength(1);
    expect(body.match(/FROM public\.sla_evaluation_jobs AS job/g)).toHaveLength(
      2,
    );
    expect(body).toContain("UNION ALL");
    expect(body).toContain("'queued'::public.sla_job_status");
    expect(body).toContain("'retry_scheduled'::public.sla_job_status");
    expect(body).toContain("job.available_at <= observed.observed_at");
    expect(body).toContain("'leased'::public.sla_job_status");
    expect(body).toContain("job.lease_expires_at <= observed.observed_at");
    expect(body).toContain("count(*)::bigint AS pending_jobs");
    expect(body).toContain("min(eligible.ready_at) AS oldest_ready_at");
    expect(body).toContain(
      "WHEN metrics.oldest_ready_at IS NULL THEN 0::bigint",
    );
    expect(body).toContain("greatest(");
    expect(body).toContain("* 1000000");
    expect(body).not.toMatch(
      /(current_setting|statement_timestamp|transaction_timestamp|\bnow\s*\()/,
    );
    expect(body).not.toContain("tenant_id");
  });

  it("grants the global aggregate only to the worker runtime", () => {
    expect(migration).toContain(
      "ALTER FUNCTION app.read_sla_evaluation_queue_metrics_v1()\n  OWNER TO periapsis_sla_worker_owner",
    );
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.read_sla_evaluation_queue_metrics_v1()\nTO periapsis_worker",
    );
    expect(migration).toContain(
      "REVOKE ALL ON FUNCTION app.read_sla_evaluation_queue_metrics_v1()\nFROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier",
    );
    expect(migration).not.toContain(
      "GRANT EXECUTE ON FUNCTION app.read_sla_evaluation_queue_metrics_v1()\nTO periapsis_api",
    );
  });

  it("makes readiness verify the ABI, ACL, source, and both partial indexes", () => {
    const readiness = functionBody("sla_schema_readiness_v1");

    expect(readiness).toContain("'app.read_sla_evaluation_queue_metrics_v1()'");
    expect(readiness).toContain("'periapsis_sla_worker_owner'");
    expect(readiness).toContain("function_volatility IS DISTINCT FROM 'v'");
    expect(readiness).toContain("function_rows IS DISTINCT FROM 1::real");
    expect(readiness).toContain(
      "ARRAY['search_path=pg_catalog, public, app']::text[]",
    );
    expect(readiness).toContain(
      "TABLE(observed_at timestamp with time zone, pending_jobs bigint, oldest_pending_micros bigint)",
    );
    expect(readiness).toContain("regexp_count(function_definition");
    expect(readiness).toContain(
      "seed_tenant_authorization_workflow_compatibility_impl",
    );
    expect(readiness).toContain("private_seed_tenant_sla_authorization_v1");
    expect(readiness).toContain("'sla_evaluation_jobs_claim_idx'");
    expect(readiness).toContain("'sla_evaluation_jobs_reclaim_idx'");
    expect(readiness).toContain("index_row.indnkeyatts = 3");
    expect(readiness).toContain("pg_get_expr(index_row.indpred");
    expect(readiness).toContain("'periapsis_migrator'");
    expect(readiness).toContain("'periapsis_sla_readiness_owner'");
  });

  it("rotates one exact rolling predecessor and rebinds live readiness", () => {
    expect(functionBody("schema_compatibility_v28")).toContain(
      "journal_count = 136",
    );
    const predecessor = functionBody("schema_compatibility_v27");
    expect(predecessor).toContain("FROM app.schema_compatibility_v28()");
    expect(predecessor).toContain("migration.migration_ordinal <= 135");
    expect(functionBody("schema_compatibility_v26")).toContain(
      "'UNSUPPORTED'::text",
    );
    expect(migration).toContain(
      "c324d64aee82f94fe3912370c910174dc08b9c4a0241f346ef69c5a2d596b2ba",
    );
    expect(migration).toContain(
      "'app.federated_authentication_schema_readiness_v1()'::regprocedure",
    );
    expect(migration).toContain(
      "'app.identity_mfa_device_management_readiness_v1()'::regprocedure",
    );
    expect(migration).toContain(
      "'app.identity_mfa_schema_readiness_v1()'::regprocedure",
    );
    expect(migration).toContain(
      "current_count = 136 AND predecessor_count = 135",
    );
  });
});
