import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrationDirectory = resolve(import.meta.dirname, "../migrations");
const abi = readFileSync(
  resolve(migrationDirectory, "0122_workflow_administration_abi.sql"),
  "utf8",
);
const readiness = readFileSync(
  resolve(migrationDirectory, "0123_workflow_administration_readiness.sql"),
  "utf8",
);

describe("workflow administration database ABI", () => {
  it("keeps tenant storage behind forced RLS and the command ledger private", () => {
    for (const table of [
      "ticket_workflows",
      "ticket_workflow_versions",
      "ticket_workflow_commands",
    ]) {
      expect(abi).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
    }

    expect(abi).toContain(
      "REVOKE ALL ON TABLE public.ticket_workflow_commands FROM periapsis_api",
    );
    expect(abi).not.toMatch(
      /GRANT\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE)[^;]+ticket_workflow_commands[^;]+periapsis_api/i,
    );
    expect(abi).toContain("ticket_workflow_commands_immutable_v1");
    expect(abi).toContain("workflow.read', 'tenant'");
    expect(abi).toContain("workflow.manage', 'tenant'");
  });

  it("validates one canonical, bounded workflow graph inside the database", () => {
    expect(abi).toContain("private_workflow_json_exact_keys_v1");
    expect(abi).toContain("private_workflow_effect_plan_valid_v1");
    expect(abi).toContain("private_workflow_condition_node_count_v1");
    expect(abi).toContain("private_ticket_workflow_definition_valid_v1");
    expect(abi).toContain("p_depth NOT BETWEEN 1 AND 8");
    expect(abi).toContain("total_count > 128");
    expect(abi).toContain("jsonb_array_length(p_states) NOT BETWEEN 2 AND 64");
    expect(abi).toContain(
      "jsonb_array_length(p_transitions) NOT BETWEEN 1 AND 256",
    );
    expect(abi).toContain(
      "RETURN cardinality(seen_keys) = cardinality(state_keys)",
    );
    expect(abi).toContain("AND to_key = initial_state");
  });

  it("serializes immutable idempotency before applying lifecycle mutations", () => {
    const advisoryLock = abi.indexOf("PERFORM pg_advisory_xact_lock");
    const replayRead = abi.indexOf("SELECT command.* INTO command_record");
    const createMutation = abi.indexOf(
      "INSERT INTO public.ticket_workflows (",
      replayRead,
    );
    const ledgerWrite = abi.indexOf(
      "INSERT INTO public.ticket_workflow_commands (",
      createMutation,
    );

    expect(advisoryLock).toBeGreaterThan(-1);
    expect(replayRead).toBeGreaterThan(advisoryLock);
    expect(createMutation).toBeGreaterThan(replayRead);
    expect(ledgerWrite).toBeGreaterThan(createMutation);
    expect(abi).toContain("workflow idempotency lineage conflicts");
    expect(abi).toContain("changed_at + interval '24 hours'");
    expect(abi).toContain("pg_column_size(snapshot) > 524288");
  });

  it("implements CAS lifecycle changes and serializes default displacement", () => {
    expect(abi).toContain("p_next_revision <> p_expected_revision + 1");
    expect(abi).toContain("workflow revision precondition failed");
    expect(abi).toContain(":workflow-default:");
    expect(abi).toContain("FOR UPDATE;");

    for (const action of [
      "create",
      "publish",
      "update_metadata",
      "set_default",
      "archive",
      "restore",
    ]) {
      expect(abi).toContain(`p_action = '${action}'`);
    }

    expect(abi).toContain(
      "p_displaced_next_revision <> p_displaced_expected_revision + 1",
    );
    expect(abi).toContain("workflow default precondition failed");
  });

  it("emits redacted audit and a narrow transactional outbox event", () => {
    expect(abi).toContain("app.append_tenant_authorization_audit(");
    expect(abi).toContain("'content_redacted', true");
    expect(abi).toContain("INSERT INTO public.outbox_events (");
    expect(abi).toContain("'api.workflow', 'operator'");
    expect(abi).not.toMatch(
      /outbox_payload\s*:=\s*[\s\S]*?(?:states|transitions|description)/,
    );
  });

  it("seals exact current and predecessor compatibility plus runtime readiness", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v25()",
    );
    expect(readiness).toContain("journal_count = 124");
    expect(readiness).toContain("migration.migration_ordinal <= 121");
    expect(readiness).toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v23()",
    );
    expect(readiness).toContain("'UNSUPPORTED'::text");
    expect(readiness).toContain(
      "CREATE FUNCTION app.workflow_administration_schema_readiness_v1()",
    );
    expect(readiness).toContain("relforcerowsecurity");
    expect(readiness).toContain("has_table_privilege(");
    expect(readiness).toContain("has_function_privilege(");
    expect(readiness).toContain("workflow.manage");
    expect(readiness).toContain("current_count = 124");
    expect(readiness).toContain("predecessor_count = 121");
    expect(readiness).toContain("retired_count = 0");
  });
});
