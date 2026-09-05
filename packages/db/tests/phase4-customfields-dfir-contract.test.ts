import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const customFieldSchema = readFileSync(
  resolve(packageRoot, "src/schema/customfields.ts"),
  "utf8",
);
const dfirSchema = readFileSync(
  resolve(packageRoot, "src/schema/dfir.ts"),
  "utf8",
);
const structural = readFileSync(
  resolve(packageRoot, "migrations/0087_optimal_loa.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(packageRoot, "migrations/0088_phase4_tenant_security.sql"),
  "utf8",
);
const journal = readFileSync(
  resolve(packageRoot, "migrations/0089_phase4_transaction_journal.sql"),
  "utf8",
);
const closure = readFileSync(
  resolve(packageRoot, "migrations/0100_easy_stark_industries.sql"),
  "utf8",
);
const currentRelease = readFileSync(
  resolve(packageRoot, "migrations/0228_tenant_federation_administration.sql"),
  "utf8",
);

const phase4CustomFieldTables = [
  "custom_field_definition_revisions",
  "custom_field_definitions",
  "custom_field_layouts",
  "custom_field_migrations",
  "custom_field_options",
  "custom_field_permissions",
  "custom_field_values",
] as const;

const phase4DfirTables = [
  "dfir_activities",
  "dfir_asset_links",
  "dfir_assets",
  "dfir_attachments",
  "dfir_custody_events",
  "dfir_evidence",
  "dfir_ioc_links",
  "dfir_iocs",
  "dfir_relationships",
  "dfir_storage_objects",
  "dfir_tasks",
  "dfir_timeline_asset_links",
  "dfir_timeline_events",
  "dfir_timeline_evidence_links",
  "dfir_timeline_ioc_links",
] as const;

const phase4Tables = [...phase4CustomFieldTables, ...phase4DfirTables] as const;

function schemaTableBody(source: string, table: string): string {
  const tableName = `\n  "${table}",`;
  const tableNameStart = source.indexOf(tableName);
  if (tableNameStart === -1) {
    throw new Error(`Missing Phase 4 schema table ${table}`);
  }

  const start = source.lastIndexOf("pgTable(", tableNameStart);
  const end = source.indexOf(").enableRLS();", tableNameStart);
  if (start === -1 || end === -1) {
    throw new Error(`Unterminated Phase 4 schema table ${table}`);
  }
  return source.slice(start, end);
}

function functionBody(source: string, name: string): string {
  const created = source.indexOf(`CREATE FUNCTION app.${name}`);
  const replaced = source.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`);
  const start = created === -1 ? replaced : created;
  if (start === -1) {
    throw new Error(`Missing Phase 4 function ${name}`);
  }
  const end = source.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`Unterminated Phase 4 function ${name}`);
  }
  return source.slice(start, end);
}

describe("Phase 4 custom-field and DFIR database contract", () => {
  it("keeps every customer-owned table tenant-bound, API-authorized, and FORCE-RLS protected", () => {
    for (const table of phase4Tables) {
      expect(structural).toMatch(
        new RegExp(
          `CREATE TABLE "${table}" \\([\\s\\S]*?"tenant_id" uuid NOT NULL`,
        ),
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} OWNER TO periapsis_migrator;`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY;`,
      );
    }

    for (const table of phase4CustomFieldTables) {
      const definition = schemaTableBody(customFieldSchema, table);
      expect(definition).toContain('tenantId: uuid("tenant_id")');
      expect(definition).toContain("activeActorMembershipFor(table.tenantId)");
    }
    for (const table of phase4DfirTables) {
      const definition = schemaTableBody(dfirSchema, table);
      expect(definition).toContain('tenantId: uuid("tenant_id")');
      expect(definition).toContain("activeActorMembershipFor(table.tenantId)");
    }
  });

  it("keeps runtime access least-privileged and reserves object transitions for the worker ABI", () => {
    const workerGrantEnd = security.indexOf("TO periapsis_worker;");
    const workerSelectGrant = security.slice(
      security.lastIndexOf("GRANT SELECT ON TABLE", workerGrantEnd),
      workerGrantEnd,
    );

    expect(security).toContain(
      "REVOKE ALL ON TABLE\n  public.custom_field_definition_revisions,",
    );
    expect(security).toContain(
      "FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;",
    );
    expect(security).toContain(
      "GRANT SELECT ON TABLE\n  public.dfir_activities,\n  public.dfir_custody_events,\n  public.dfir_evidence,\n  public.dfir_storage_objects\nTO periapsis_worker;",
    );
    expect(workerSelectGrant).not.toContain("public.dfir_attachments");
    expect(journal).toContain(
      "GRANT EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v1",
    );
    expect(journal).toContain("TO periapsis_worker;");
    expect(journal).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.(?:create_dfir_evidence|append_dfir_custody_event)_v1[^;]+TO periapsis_worker/,
    );
  });

  it("stores only object metadata and SHA-256 evidence digests, never file bodies", () => {
    const storageTable = structural.slice(
      structural.indexOf('CREATE TABLE "dfir_storage_objects"'),
      structural.indexOf('CREATE TABLE "dfir_tasks"'),
    );
    const evidenceTable = structural.slice(
      structural.indexOf('CREATE TABLE "dfir_evidence"'),
      structural.indexOf('CREATE TABLE "dfir_ioc_links"'),
    );

    expect(storageTable).toContain('"object_key" text NOT NULL');
    expect(storageTable).toContain('"content_sha256" "bytea"');
    expect(evidenceTable).toContain('"content_sha256" "bytea" NOT NULL');
    expect(storageTable + evidenceTable).not.toMatch(
      /(?:file|object|content|payload)_(?:body|bytes|blob|data)/i,
    );
    expect(structural).not.toMatch(/\b(?:blob|large object|lo_oid)\b/i);
  });

  it("keeps every mutable bigint DFIR resource revision JSON-safe", () => {
    for (const table of [
      "dfir_iocs",
      "dfir_assets",
      "dfir_storage_objects",
      "dfir_timeline_events",
      "dfir_tasks",
      "dfir_relationships",
    ]) {
      const definition = schemaTableBody(dfirSchema, table);
      expect(definition).toContain(
        "${table.version} between 1 and 9007199254740991",
      );
    }
    expect(schemaTableBody(dfirSchema, "dfir_evidence")).toContain(
      "${table.version} = ${table.custodyCount} and ${table.version} between 1 and 1000",
    );
    expect(schemaTableBody(dfirSchema, "dfir_custody_events")).toContain(
      "${table.sequence} between 1 and 1000",
    );
  });

  it("keeps generic DFIR replay snapshots expiring but caller identities permanent", () => {
    const resourceIds = schemaTableBody(
      dfirSchema,
      "dfir_mutation_resource_ids",
    );
    const replayKeys = schemaTableBody(dfirSchema, "dfir_mutation_replay_keys");
    const commands = schemaTableBody(dfirSchema, "dfir_mutation_commands");
    const results = schemaTableBody(
      dfirSchema,
      "dfir_mutation_command_results",
    );

    expect(resourceIds).toContain("dfir_mutation_resource_ids_pkey");
    expect(resourceIds).toContain("'relationship_retraction'");
    expect(resourceIds).toContain("'checklist_item'");
    expect(replayKeys).toContain("table.actorUserId");
    expect(replayKeys).toContain("table.operation");
    expect(replayKeys).not.toContain(
      "table.actorMembershipId,\n        table.operation",
    );
    expect(replayKeys).toContain("case.dfir.task.comments.replace");
    expect(replayKeys).toContain("dfir.alert.task.comments.replace");
    expect(commands).toContain("interval '24 hours'");
    expect(commands).toContain("interval '7 days'");
    expect(results).not.toContain('timestamp("expires_at"');
    expect(results).not.toContain('uuid("secondary_resource_id"');
    expect(results).toContain('.onDelete("cascade")');
    expect(results).toContain("when 'evidence' then 16777216");

    const reserve = functionBody(
      currentRelease,
      "reserve_dfir_mutation_command_v1(",
    );
    expect(reserve).toContain(
      "resource_found AND resource_archived_at IS NOT NULL",
    );
    expect(reserve).toContain("LIMIT 65");
    expect(reserve).toContain("linked_root_count>64");
    expect(reserve).toContain(
      "app.private_dfir_mutation_snapshot_valid_v1(\n      stored_snapshot",
    );
    expect(reserve).toContain(") IS NOT TRUE THEN");

    const store = functionBody(
      currentRelease,
      "store_dfir_mutation_command_result_v1(",
    );
    expect(store).toContain(") IS NOT TRUE THEN");
  });

  it("fails closed legacy DFIR mutation ABIs at the exact JSON revision ceiling", () => {
    const custody = functionBody(
      currentRelease,
      "append_dfir_custody_event_v1(",
    );
    expect(custody).toContain("p_expected_version NOT BETWEEN 1 AND 999");
    expect(custody).toContain("target.version NOT BETWEEN 1 AND 1000");
    expect(custody).toContain(
      "storage_record.version NOT BETWEEN 1 AND 9007199254740990",
    );
    expect(custody).toContain(
      "attachment_record.version NOT BETWEEN 1 AND 9007199254740990",
    );

    const cleanup = functionBody(
      currentRelease,
      "finalize_dfir_orphan_upload_cleanup_v2(",
    );
    expect(cleanup).toContain(
      "target.version NOT BETWEEN 1 AND 9007199254740990",
    );
    expect(currentRelease).toContain(
      "REVOKE EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v2(",
    );
    expect(currentRelease).toContain(
      "REVOKE EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v3(",
    );
  });

  it("preserves security-sensitive regex escapes through Drizzle generation", () => {
    expect(structural).toContain(
      String.raw`'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' and "dfir_storage_objects"."bucket" !~ '\.\.'`,
    );
    expect(structural).toContain(
      String.raw`"dfir_storage_objects"."object_key" !~ '(^|/)\.\.?(/|$)'`,
    );
    expect(structural).toContain(
      String.raw`"dfir_storage_objects"."original_filename" !~ '[/\\[:cntrl:]]'`,
    );
    expect(structural).toContain(
      String.raw`"dfir_attachments"."original_filename" !~ '[/\\[:cntrl:]]'`,
    );
    expect(structural).toContain(
      String.raw`"custom_field_definitions"."minimum_number" ~ '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$'`,
    );
    expect(structural).toContain(
      String.raw`"dfir_activities"."action" ~ '^dfir\.[a-z][a-z0-9_.-]{1,63}$'`,
    );
    expect(structural).not.toContain(`"dfir_storage_objects"."bucket" !~ '..'`);
  });

  it("guards immutable identities, revision snapshots, and append-only forensic history", () => {
    for (const trigger of [
      "custom_field_definitions_identity_v1",
      "custom_field_definition_revisions_immutable_v1",
      "custom_field_definition_revisions_validate_v1",
      "custom_field_options_identity_v1",
      "custom_field_migrations_identity_v1",
      "custom_field_values_validate_v1",
      "custom_field_values_identity_v1",
      "dfir_relationships_validate_v1",
      "dfir_storage_objects_identity_v1",
      "dfir_attachments_validate_v1",
      "dfir_tasks_assignment_validate_v1",
      "dfir_evidence_identity_v1",
      "dfir_custody_events_immutable_v1",
      "dfir_activities_immutable_v1",
    ]) {
      expect(security).toContain(`CREATE TRIGGER ${trigger}`);
      expect(journal).toContain(`'${trigger}'`);
    }
    expect(functionBody(security, "guard_phase4_append_only_v1()")).toContain(
      "append-only phase 4 record cannot be changed",
    );
    expect(
      functionBody(security, "validate_custom_field_revision_v1()"),
    ).toContain("NEW.snapshot ?& ARRAY[");
  });

  it("couples DFIR mutations to redacted activity, audit, and outbox rows", () => {
    const effects = functionBody(journal, "append_phase4_mutation_effects_v1(");
    expect(effects).toContain(
      "app.current_tenant_human_has_exact_permission_v3",
    );
    expect(effects).toContain("app.private_current_dfir_scope_allows_v1");
    expect(effects).toContain("INSERT INTO public.dfir_activities");
    expect(effects).toContain("app.append_tenant_authorization_audit");
    expect(effects).toContain("INSERT INTO public.outbox_events");
    expect(effects).toContain("jsonb_build_object(");
    expect(effects).not.toMatch(
      /original_filename|object_key|content_sha256|custody_reason|p_reason/,
    );

    for (const mutation of [
      "create_dfir_evidence_v1(",
      "append_dfir_custody_event_v1(",
    ]) {
      const body = functionBody(journal, mutation);
      expect(body).toContain("app.append_phase4_mutation_effects_v1(");
      expect(body).toContain("FOR UPDATE");
    }
  });

  it("binds evidence replay to the complete immutable request and verifies custody continuity", () => {
    const create = functionBody(journal, "create_dfir_evidence_v1(");
    expect(create).toContain("p_event_hash");
    expect(create).toContain("p_anchor_hash");
    expect(create).toContain(
      "DFIR evidence replay payload conflicts with existing evidence",
    );
    expect(create).toContain(
      "existing_event.previous_hash IS DISTINCT FROM p_anchor_hash",
    );
    expect(create).toContain(
      "existing_event.event_hash IS DISTINCT FROM p_event_hash",
    );

    const append = functionBody(journal, "append_dfir_custody_event_v1(");
    expect(append).toContain(
      "target.custody_head_hash IS DISTINCT FROM p_previous_hash",
    );
    expect(structural).toContain(
      'CONSTRAINT "dfir_evidence_version_check" CHECK ("dfir_evidence"."version" = "dfir_evidence"."custody_count"',
    );
    expect(append).toContain("p_occurred_at < previous_occurred_at");
    expect(append).toContain("storage and evidence projections have drifted");
  });

  it("keeps customer-contact references fail-closed until an exact tenant integration exists", () => {
    const values = functionBody(security, "validate_custom_field_value_v1()");
    expect(values).toContain("ELSIF NEW.data_type = 'customer_contact' THEN");
    expect(values).toContain(
      "customer contact reference integration is unavailable",
    );
    expect(values).toContain("USING ERRCODE = '55000'");
  });

  it("self-checks exact tables, tenant columns, grants, triggers, permissions, and function ACLs", () => {
    const readiness = functionBody(journal, "phase4_schema_readiness_v1()");
    expect(readiness.match(/^    '[a-z_]+',?$/gm)).toHaveLength(22);
    expect(readiness).toContain("attribute.attnotnull");
    expect(readiness).toContain("class.relrowsecurity");
    expect(readiness).toContain("class.relforcerowsecurity");
    expect(readiness).toContain("has_table_privilege('periapsis_api'");
    expect(readiness).toContain("has_function_privilege('periapsis_worker'");
    expect(readiness).toContain(") <> 16 THEN");
    expect(readiness).toContain(") <> 14 THEN");
    expect(journal).toContain("IF NOT app.phase4_schema_readiness_v1() THEN");
  });

  it("advances schema compatibility to v14 with exactly one sealed predecessor", () => {
    const current = functionBody(journal, "schema_compatibility_v14()");
    expect(current).toContain("journal_count = 90");
    expect(current).toContain("journal_latest_created_at = 1787672134042");
    expect(current).toContain("migration_0089_rows = 1");

    const predecessor = functionBody(journal, "schema_compatibility_v13()");
    expect(predecessor).toContain("FROM app.schema_compatibility_v14()");
    expect(predecessor).toContain("migration.migration_ordinal <= 82");
    expect(predecessor).toContain("migration_ordinal = 82");
    expect(predecessor).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );

    const retired = functionBody(journal, "schema_compatibility_v12()");
    expect(retired).toContain("'UNSUPPORTED'::text");

    const sealer = functionBody(journal, "seal_schema_compatibility_manifest(");
    expect(sealer).toContain("p_expected_count IS DISTINCT FROM 90");
    expect(sealer).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 90",
    );
    expect(sealer).toContain("fingerprint_entries[82]");
    expect(sealer).toContain("FROM app.schema_compatibility_v13()");
    expect(sealer).toContain("FROM app.schema_compatibility_v12()");
    expect(sealer).toContain("schema compatibility v12 must be retired");

    expect(journal).toContain(
      "GRANT EXECUTE ON FUNCTION app.schema_compatibility_v14()\n  TO periapsis_api, periapsis_worker;",
    );
    expect(journal).toContain(
      "'app.seal_schema_compatibility_manifest(bigint,bigint,text,text)', false, false",
    );
  });

  it("makes the signed exact upload size authoritative and payload-binds prepare replay", () => {
    expect(dfirSchema).toContain('bigint("expected_size_bytes"');
    expect(dfirSchema).toContain('timestamp("upload_expires_at"');
    expect(dfirSchema).toContain("between 1 and 5000000000");
    expect(closure).toContain(
      "ELSIF NEW.operation = 'dfir.attachment.prepare' THEN",
    );
    const reserve = functionBody(
      closure,
      "reserve_dfir_attachment_prepare_v1(",
    );
    expect(reserve).toContain(
      "INSERT INTO public.tenant_authorization_commands",
    );
    expect(reserve).toContain(
      "command_record.request_digest IS DISTINCT FROM p_request_digest",
    );
    expect(reserve).toContain(
      "command_record.result_resource_id IS DISTINCT FROM p_storage_object_id",
    );

    const transition = functionBody(
      closure,
      "advance_dfir_storage_object_as_worker_v2(",
    );
    expect(transition).toContain(
      "p_size_bytes IS DISTINCT FROM target.expected_size_bytes",
    );
    expect(closure).toContain(
      "REVOKE EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v1",
    );
  });

  it("uses a worker-only lease and fence before tombstoning orphan uploads", () => {
    const claim = functionBody(closure, "claim_dfir_orphan_uploads_v1(");
    expect(claim).toContain(
      "upload_expires_at + interval '5 minutes' <= p_now",
    );
    expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    expect(claim).toContain("cleanup_fence = storage.cleanup_fence + 1");
    expect(claim).toContain("claimed.bucket, claimed.object_key");

    const finalize = functionBody(
      closure,
      "finalize_dfir_orphan_upload_cleanup_v1(",
    );
    expect(finalize).toContain(
      "target.cleanup_fence IS DISTINCT FROM p_cleanup_fence",
    );
    expect(finalize).toContain("SET state = 'deleted'");
    expect(finalize).toContain("SET scan_state = 'deleted'");
    expect(finalize).toContain("objectLocationRedacted', true");
    expect(finalize).not.toMatch(
      /jsonb_build_object\([^)]*(?:bucket|object_key)/s,
    );

    expect(closure).toContain(
      "GRANT EXECUTE ON FUNCTION app.claim_dfir_orphan_uploads_v1(\n  integer, integer, timestamp with time zone\n) TO periapsis_worker;",
    );
    expect(closure).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.claim_dfir_orphan_uploads_v1[^;]+TO periapsis_api/,
    );
  });

  it("publishes exact v17 compatibility and keeps only v16 as rolling predecessor", () => {
    const current = functionBody(closure, "schema_compatibility_v17()");
    expect(current).toContain("journal_count = 101");
    expect(current).toContain("journal_latest_created_at = 1787686749137");
    const predecessor = functionBody(closure, "schema_compatibility_v16()");
    expect(predecessor).toContain("migration.migration_ordinal <= 100");
    expect(predecessor).toContain("migration_ordinal = 100");
    expect(functionBody(closure, "schema_compatibility_v15()")).toContain(
      "'UNSUPPORTED'::text",
    );
    const sealer = functionBody(closure, "seal_schema_compatibility_manifest(");
    expect(sealer).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 101",
    );
    expect(sealer).toContain(
      "invalid schema compatibility v17 timestamp sequence",
    );
    expect(functionBody(closure, "phase4_schema_readiness_v2()")).toContain(
      "pg_get_functiondef",
    );
  });
});
