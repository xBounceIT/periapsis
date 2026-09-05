import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0228_tenant_federation_administration.sql",
  ),
  "utf8",
);
const dfirSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/dfir.ts"),
  "utf8",
);
const ticketingSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/ticketing.ts"),
  "utf8",
);
const workerCleanup = readFileSync(
  resolve(repositoryRoot, "services/worker/internal/postgres/auth_cleanup.go"),
  "utf8",
);
const workerMain = readFileSync(
  resolve(repositoryRoot, "services/worker/cmd/worker/main.go"),
  "utf8",
);
const packageManifest = readFileSync(
  resolve(repositoryRoot, "packages/db/package.json"),
  "utf8",
);
const continuousIntegration = readFileSync(
  resolve(repositoryRoot, ".github/workflows/ci.yml"),
  "utf8",
);

function latestFunctionBody(name: string): string {
  const markers = [
    `CREATE FUNCTION app.${name}`,
    `CREATE OR REPLACE FUNCTION app.${name}`,
  ];
  const start = Math.max(
    ...markers.map((marker) => migration.lastIndexOf(marker)),
  );
  if (start < 0) throw new Error(`missing retention function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated retention function ${name}`);
  return migration.slice(start, end);
}

describe("DFIR mutation receipt retention contract", () => {
  it("models bounded receipts and permanent user/key plus resource tombstones", () => {
    expect(dfirSchema).toContain("dfirMutationResourceIds");
    expect(dfirSchema).toContain("dfirMutationReplayKeys");
    expect(dfirSchema).toContain("dfirTicketCommandRetentions");
    expect(dfirSchema).toContain(
      'expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })',
    );
    expect(dfirSchema).toContain(
      "${table.expiresAt} >= ${table.createdAt} + interval '24 hours'",
    );
    expect(dfirSchema).toContain(
      "${table.expiresAt} <= ${table.createdAt} + interval '7 days'",
    );
    expect(dfirSchema).toContain(
      "${table.receiptExpiresAt} >= ${table.firstUsedAt} + interval '24 hours'",
    );
    expect(dfirSchema).toContain(
      "${table.receiptExpiresAt} <= ${table.firstUsedAt} + interval '7 days'",
    );
    expect(dfirSchema).toMatch(
      /dfir_mutation_replay_keys_pkey[\s\S]*?table\.tenantId,[\s\S]*?table\.actorUserId,[\s\S]*?table\.operation,[\s\S]*?table\.keyDigest/,
    );
    const replayPrimaryKey = dfirSchema.match(
      /name: "dfir_mutation_replay_keys_pkey",\s*columns: \[([\s\S]*?)\]/,
    )?.[1];
    expect(replayPrimaryKey).toBeDefined();
    expect(replayPrimaryKey).not.toContain("table.actorMembershipId");
    for (const kind of [
      "task",
      "checklist_item",
      "relationship_retraction",
      "shared_link_event",
      "storage_object",
      "attachment",
    ]) {
      expect(dfirSchema).toContain(`'${kind}'`);
    }
    for (const operation of [
      "case.dfir.task.comments.replace",
      "dfir.alert.task.comments.replace",
      "dfir.relationship.retract",
      "dfir.ioc.link",
      "dfir.ioc.unlink",
      "dfir.asset.link",
      "dfir.asset.unlink",
    ]) {
      expect(dfirSchema).toContain(`'${operation}'`);
    }
    expect(dfirSchema).not.toContain("'dfir.task.comments.replace'");
    expect(ticketingSchema).toContain(
      "ticket_commands_dfir_retention_coordinate_key",
    );
    expect(ticketingSchema).toContain("ticket_commands_dfir_user_replay_key");
  });

  it("backfills every legacy family before exposing cleanup", () => {
    const cleanupGrant = migration.indexOf(
      "GRANT EXECUTE ON FUNCTION app.prune_expired_dfir_mutation_commands_v1(integer)",
    );
    expect(cleanupGrant).toBeGreaterThan(-1);
    for (const source of [
      "public.alert_dfir_resource_commands",
      "public.alert_dfir_resource_command_results",
      "public.ticket_commands",
      "public.dfir_tasks",
      "public.dfir_relationship_retractions",
      "public.dfir_shared_resource_link_events",
    ]) {
      const backfill = migration.indexOf(source);
      expect(backfill).toBeGreaterThan(-1);
      expect(backfill).toBeLessThan(cleanupGrant);
    }
    expect(migration).toContain("public.dfir_mutation_replay_keys");
    expect(migration).toContain("public.dfir_mutation_resource_ids");
    expect(migration).toContain("public.dfir_ticket_command_retentions");
    expect(migration).toContain("jsonb_array_elements");
    expect(migration).toContain("custodyEvents");
    expect(migration).toContain("checklist");
    expect(migration).toContain("retractions");
  });

  it("fails closed for expired or cross-membership legacy replay", () => {
    for (const name of [
      "reserve_case_dfir_command_v1",
      "reserve_alert_investigation_command_v1",
    ]) {
      const reserve = latestFunctionBody(name);
      expect(reserve).toContain("dfir_mutation_replay_keys");
      expect(reserve).toContain("actor_user_id");
      expect(reserve).toContain("actor_membership_id");
      expect(reserve).toContain("receipt_expires_at");
      expect(reserve).toContain("transaction_timestamp()");
      expect(reserve).toContain("pg_advisory_xact_lock");
      expect(reserve).toContain("p_result_version IS NULL");
      expect(reserve).toContain("ERRCODE='23505'");
    }
    expect(latestFunctionBody("reserve_case_dfir_command_v1")).toContain(
      "context_tenant,'task',p_resource_id",
    );
  });

  it("reserves new task, checklist, and retraction identifiers at DML time", () => {
    const guard = latestFunctionBody("guard_dfir_task_checklist_ids_v1");
    expect(guard).toContain("jsonb_array_elements(NEW.checklist)");
    expect(guard).toContain("jsonb_array_elements(OLD.checklist)");
    expect(guard).toContain("'checklist_item'");
    expect(migration).toContain("dfir_tasks_resource_id_v1");
    expect(migration).toContain("dfir_tasks_checklist_resource_ids_v1");
    expect(migration).toContain("dfir_relationship_retractions_resource_id_v1");
    expect(migration).toContain(
      "app.guard_dfir_mutation_resource_id_v1('task')",
    );
    expect(migration).toMatch(
      /app\.guard_dfir_mutation_resource_id_v1\(\s*'relationship_retraction'\s*\)/,
    );
  });

  it("prunes all receipt families in bounded skip-locked passes", () => {
    const prune = latestFunctionBody("prune_expired_dfir_mutation_commands_v1");
    expect(prune).toContain(
      "p_batch_size IS NULL OR p_batch_size NOT BETWEEN 1 AND 1000",
    );
    expect(prune).toContain("expires_at <= transaction_timestamp()");
    expect(
      prune.match(/LIMIT p_batch_size/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(3);
    expect(
      prune.match(/FOR UPDATE(?: OF [^\n]+)? SKIP LOCKED/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(3);
    expect(prune).toContain("public.dfir_mutation_command_results");
    expect(prune).toContain("public.dfir_mutation_commands");
    expect(prune).toContain("public.alert_dfir_resource_command_results");
    expect(prune).toContain("public.alert_dfir_resource_commands");
    expect(prune).toContain("public.dfir_ticket_command_retentions");
    expect(prune).toContain("public.ticket_commands");
    expect(prune.indexOf("dfir_mutation_command_results")).toBeLessThan(
      prune.lastIndexOf("dfir_mutation_commands"),
    );
    expect(prune.indexOf("alert_dfir_resource_command_results")).toBeLessThan(
      prune.lastIndexOf("alert_dfir_resource_commands"),
    );
    expect(prune).not.toMatch(
      /DELETE FROM public\.(audit_events|dfir_activities|outbox_events)/,
    );
    expect(prune).not.toMatch(
      /DELETE FROM public\.dfir_mutation_(resource_ids|replay_keys)/,
    );
  });

  it("keeps receipt tables RLS-closed and exposes only the worker pruner", () => {
    for (const table of [
      "dfir_mutation_resource_ids",
      "dfir_mutation_replay_keys",
      "dfir_mutation_commands",
      "dfir_mutation_command_results",
      "alert_dfir_resource_commands",
      "alert_dfir_resource_command_results",
      "dfir_ticket_command_retentions",
    ]) {
      expect(migration).toMatch(
        new RegExp(`ALTER TABLE public\\.${table}\\s+FORCE ROW LEVEL SECURITY`),
      );
    }
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.prune_expired_dfir_mutation_commands_v1\(integer\)\s+TO periapsis_worker/,
    );
    expect(migration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.prune_expired_dfir_mutation_commands_v1\(integer\)\s+TO periapsis_api/,
    );
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION app\.reserve_alert_dfir_resource_command_v1\([\s\S]*?FROM PUBLIC,[\s\S]*?periapsis_api/,
    );
  });

  it("wires the worker, standalone PostgreSQL proof, and fresh CI database", () => {
    expect(workerCleanup).toContain(
      "app.prune_expired_dfir_mutation_commands_v1($1)",
    );
    expect(workerCleanup).toContain("DFIRMutationCommandResults");
    expect(workerCleanup).toContain("DFIRMutationCommands");
    expect(workerMain).toContain("dfir_mutation_command_results_deleted");
    expect(workerMain).toContain("dfir_mutation_commands_deleted");
    expect(packageManifest).toContain(
      '"test:security:dfir-mutation-retention"',
    );
    expect(packageManifest).toContain(
      "tests/security/dfir-mutation-retention-runtime.ts",
    );
    expect(continuousIntegration).toContain(
      "PERIAPSIS_DFIR_MUTATION_RETENTION_TEST_DATABASE_URL",
    );
    expect(continuousIntegration).toContain(
      "periapsis_dfir_mutation_retention",
    );
  });
});
