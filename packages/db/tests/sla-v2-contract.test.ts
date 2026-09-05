import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrationsRoot = resolve(import.meta.dirname, "../migrations");

function migration(name: string): string {
  return readFileSync(resolve(migrationsRoot, name), "utf8");
}

function functionBody(source: string, name: string): string {
  const start = source.indexOf(`FUNCTION app.${name}(`);
  if (start < 0) throw new Error(`Missing function app.${name}`);
  const bodyStart = source.indexOf("AS $function$", start);
  const bodyEnd = source.indexOf("$function$;", bodyStart + 13);
  if (bodyStart < 0 || bodyEnd < 0) {
    throw new Error(`Incomplete function app.${name}`);
  }
  return source.slice(start, bodyEnd + "$function$;".length);
}

describe("SLA v2 database boundary", () => {
  const foundation = migration("0104_dazzling_morph.sql");
  const configuration = migration("0113_sla_configuration_v2.sql");
  const runtime = migration("0114_sla_runtime_v2.sql");
  const readiness = migration("0115_sla_v23_readiness.sql");

  it("returns a complete current representation while retiring incomplete writes", () => {
    for (const kind of ["calendar", "policy", "column"]) {
      const body = functionBody(configuration, `publish_sla_${kind}_v2`);
      expect(body).toContain(`app.publish_sla_${kind}_v1`);
      expect(body).toContain("app.private_sla_configuration_document_v2");
    }
    expect(configuration).toContain(
      "REVOKE EXECUTE ON FUNCTION app.publish_sla_calendar_v1",
    );
    expect(configuration).toContain(
      "REVOKE EXECUTE ON FUNCTION app.read_sla_configuration_v1",
    );
    expect(foundation).toContain("\"action_kind\" = 'create_task'");
    expect(foundation).toContain(
      'octet_length("sla_trigger_definitions"."action_value") <= 2048',
    );
  });

  it("keeps event and override replay ahead of mutable planner projection", () => {
    const event = functionBody(runtime, "begin_sla_object_event_v2");
    expect(event.indexOf("FROM public.sla_object_event_ledger")).toBeLessThan(
      event.indexOf("app.read_sla_runtime_state_v2"),
    );
    expect(event).toContain("existing.request_digest IS DISTINCT FROM");
    expect(event).toContain("private_sla_context_allows_v1");

    const override = functionBody(runtime, "begin_sla_override_v2");
    expect(override.indexOf("FROM public.sla_overrides")).toBeLessThan(
      override.indexOf("FROM public.sla_instances"),
    );
    expect(override).toContain("p_expected_metric_version");
    expect(override).toContain("p_expected_aggregate_version");
    expect(override).toContain("p_simulation_digest");
  });

  it("pins worker metrics to policy, calendar, and materialized column revisions", () => {
    const metric = functionBody(
      runtime,
      "private_sla_worker_metric_document_v2",
    );
    expect(metric).toContain("definition.policy_id = metric.policy_id");
    expect(metric).toContain(
      "definition.policy_version = metric.policy_version",
    );
    expect(metric).toContain(
      "column_version.version = materialized.column_version",
    );
    expect(metric).toContain(
      "calendar_version.version = definition.calendar_version",
    );
    expect(runtime).toContain(
      "REVOKE EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v1",
    );
  });

  it("seals exactly v23 with only the contacts-sealed v22 predecessor", () => {
    const current = functionBody(readiness, "schema_compatibility_v23");
    const predecessor = functionBody(readiness, "schema_compatibility_v22");
    const retired = functionBody(readiness, "schema_compatibility_v21");
    const sealer = functionBody(
      readiness,
      "seal_schema_compatibility_manifest",
    );
    expect(current).toContain("journal_count = 116");
    expect(current).toContain("1787707726069");
    expect(predecessor).toContain("FROM app.schema_compatibility_v23()");
    expect(predecessor).toContain("migration.migration_ordinal <= 113");
    expect(retired).toContain("'UNSUPPORTED'::text");
    expect(sealer).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 116",
    );
    expect(sealer).toContain(
      "abe24f55b98a9a74e9eab4e7c360d029d697d12f807ae5c3bb67906dc3509099",
    );
    expect(readiness).toContain(
      "sla_business_calendars_sla_worker_owner_read_v2",
    );
  });
});
