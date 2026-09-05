import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0205_sla_object_event_ingress.sql",
  ),
  "utf8",
);
const ticketTransactionAbi = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0086_ticketing_transaction_abi.sql",
  ),
  "utf8",
);
const outboxSchema = readFileSync(
  resolve(import.meta.dirname, "../src/schema/outbox.ts"),
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

describe("production SLA object-event ingress", () => {
  it("maps only the approved immutable ticket sources", () => {
    const enqueue = functionBody("private_enqueue_sla_object_event_v1");

    expect(enqueue).toContain("mapped_event_key := 'ticket.created'");
    expect(enqueue).toContain(
      "mapped_event_key := CASE WHEN mapped_terminal THEN 'ticket.resolved'",
    );
    expect(enqueue).toContain("ELSE 'ticket.' || mapped_state_key END");
    expect(enqueue).toContain("comment_row.visibility <> 'public'");
    expect(enqueue).toContain(
      "comment_row.origin IN ('system', 'escalation_copy')",
    );
    expect(enqueue).toContain("comment_row.origin = 'api'");
    expect(enqueue).toContain("comment_row.author_membership_id IS NOT NULL");
    expect(enqueue).toContain("comment_row.author_user_id IS NOT NULL");
    expect(enqueue).toContain("mapped_event_key := 'response.first'");
    expect(enqueue).toContain("comment_row.origin = 'customer_portal'");
    expect(enqueue).toContain("mapped_event_key := 'ticket.customer_replied'");
    expect(enqueue).toContain("p_source.aggregate_type || '.commented'");
    expect(enqueue).not.toContain("comment_edited");

    for (const action of ["assigned", "claimed", "released", "transferred"]) {
      expect(enqueue).toContain(`'sla.alert.${action}'`);
      expect(enqueue).toContain(`'sla.case.${action}'`);
      expect(migration).toContain(`'sla.alert.${action}'`);
      expect(migration).toContain(`'sla.case.${action}'`);
      expect(outboxSchema).toContain(`'sla.alert.${action}'`);
      expect(outboxSchema).toContain(`'sla.case.${action}'`);
    }
    expect(enqueue).toContain(
      "mapped_event_key := 'ticket.' || (p_source.payload ->> 'action')",
    );
    expect(enqueue).toContain(
      "p_source.event_type IS DISTINCT FROM\n            'sla.' || p_source.aggregate_type || '.'",
    );
    expect(enqueue).not.toContain("p_source.payload ->> 'event_key'");
    expect(enqueue).not.toContain("'sla.alert.linked'");
    expect(enqueue).not.toContain("'sla.case.linked'");
    expect(outboxSchema).toContain(
      'pgPolicy("outbox_events_sla_event_owner_read_v1"',
    );

    for (const [command, eventAction] of [
      ["assign", "assigned"],
      ["claim", "claimed"],
      ["release", "released"],
      ["transfer", "transferred"],
    ]) {
      expect(ticketTransactionAbi).toContain(
        `WHEN '${command}' THEN '${eventAction}'`,
      );
    }
    expect(ticketTransactionAbi).toContain("'sla.' || event_type");
  });

  it("freezes assignment configuration at source insert and never at claim", () => {
    const snapshot = functionBody("private_sla_event_assignment_snapshot_v1");
    const enqueue = functionBody("private_enqueue_sla_object_event_v1");
    const claim = functionBody("claim_sla_object_events_v1");

    expect(snapshot).toContain("FROM public.alerts AS alert");
    expect(snapshot).toContain("FROM public.cases AS case_row");
    expect(snapshot).toContain("FROM public.sla_policies AS shell");
    expect(snapshot).toContain("FROM public.sla_business_calendars AS shell");
    expect(snapshot).toContain("FROM public.sla_columns AS shell");
    expect(enqueue).toContain(
      "snapshot := app.private_sla_event_assignment_snapshot_v1(",
    );
    expect(enqueue).toContain("assignment_snapshot_digest");
    expect(claim).toContain("state_document := claimed.assignment_snapshot");
    expect(claim).not.toContain("FROM public.sla_policies");
    expect(claim).not.toContain("FROM public.sla_business_calendars");
    expect(claim).not.toContain("FROM public.sla_columns");
  });

  it("attests semantic source fields while excluding delivery mutations", () => {
    const sourceDigest = functionBody("private_sla_event_source_digest_v1");

    for (const field of [
      "'aggregate_version', p_source.aggregate_version",
      "'event_type', p_source.event_type",
      "'schema_version', p_source.schema_version",
      "'payload', p_source.payload",
      "'deduplication_key', p_source.deduplication_key",
      "'occurred_at', p_source.occurred_at",
      "'object_sequence', p_object_sequence",
      "'event_key', p_event_key",
      "'assignment_snapshot_digest'",
    ]) {
      expect(sourceDigest).toContain(field);
    }
    for (const mutable of [
      "attempts",
      "locked_at",
      "locked_by",
      "lease_token",
      "lease_until",
      "processed_at",
      "last_error",
      "failure_category",
      "dead_lettered_at",
      "fanout_commit_digest",
    ]) {
      expect(sourceDigest).not.toContain(mutable);
    }
    expect(sourceDigest).toContain("pg_catalog.sha256(");
    expect(sourceDigest).toContain("'\\x00'::bytea");
    expect(migration).not.toMatch(/\bdigest\s*\(/);
    expect(migration).not.toMatch(/chr\s*\(\s*0\s*\)/);
  });

  it("serializes each object and fences lease, retry, and dead-letter writes", () => {
    const enqueue = functionBody("private_enqueue_sla_object_event_v1");
    const claim = functionBody("claim_sla_object_events_v1");
    const commit = functionBody("commit_sla_object_event_ingress_v1");
    const fail = functionBody("fail_sla_object_event_ingress_v1");

    expect(enqueue).toContain("PERFORM pg_advisory_xact_lock(");
    expect(enqueue).toContain("coalesce(max(ingress.object_sequence), 0) + 1");
    for (const body of [claim, commit]) {
      expect(body).toContain("predecessor.object_sequence <");
      expect(body).toContain("predecessor.status <> 'completed'");
    }
    expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    expect(claim).toContain("fence = ingress.fence + 1");
    expect(claim).toContain("attempt = ingress.attempt + 1");
    expect(commit).toContain("ingress.worker_id IS DISTINCT FROM p_worker_id");
    expect(commit).toContain("ingress.fence IS DISTINCT FROM p_fence");
    expect(commit).toContain("computed_receipt_digest");
    expect(fail).toContain("p_permanent OR ingress.attempt >=");
    expect(fail).toContain("'dead_lettered'");
    expect(fail).toContain("'retry_scheduled'");
  });

  it("blocks timer claims behind every incomplete object ingress event", () => {
    const timerClaim = functionBody("claim_sla_evaluation_jobs_v3");
    const rollingWrapper = functionBody("claim_sla_evaluation_jobs_v2");

    expect(timerClaim).toContain("public.sla_object_event_ingress");
    expect(timerClaim).toContain("ingress.status <> 'completed'");
    expect(timerClaim).toContain("ingress.object_type = instance.object_type");
    expect(timerClaim).toContain("ingress.object_id = instance.object_id");
    expect(rollingWrapper).toContain("app.claim_sla_evaluation_jobs_v3(");
  });

  it("limits ledger authority to the exact receipt columns and gates readiness", () => {
    const insertGrant =
      /GRANT INSERT \(([\s\S]*?)\) ON TABLE public\.sla_object_event_ledger\s+TO periapsis_sla_worker_owner;/.exec(
        migration,
      );
    expect(insertGrant).not.toBeNull();
    const insertColumns = insertGrant?.[1]
      ?.split(",")
      .map((column) => column.trim())
      .filter(Boolean);
    expect(insertColumns).toEqual([
      "tenant_id",
      "event_id",
      "object_type",
      "object_id",
      "origin",
      "origin_id",
      "key_digest",
      "request_digest",
      "outcome",
      "sla_instance_id",
      "aggregate_version",
      "policy_id",
      "policy_version",
      "occurred_at",
      "committed_at",
    ]);
    expect(insertColumns).not.toContain("id");
    expect(migration).not.toMatch(
      /GRANT INSERT ON TABLE public\.sla_object_event_ledger\s+TO periapsis_sla_worker_owner/,
    );

    const readiness = functionBody(
      "sla_object_event_ingress_schema_readiness_v1",
    );
    expect(readiness).toContain("required_ledger_insert_columns");
    expect(readiness).toContain("NOT has_column_privilege(");
    expect(readiness).toContain("attribute.attname = ANY(");
    expect(readiness).toContain("ledger_table, ledger_column, 'INSERT'");
    expect(readiness).toContain(
      "pg_get_expr(policy.polwithcheck, policy.polrelid), 'app.', ''",
    );
    expect(readiness).toContain("LIKE '%tenant_id = context_tenant_id()%'");
    expect(readiness).toContain(
      "sla_object_event_ledger_sla_event_owner_insert_v1",
    );
  });

  it("keeps the runtime behind worker ABIs and a NOLOGIN owner", () => {
    expect(migration).toContain(
      "ALTER TABLE public.sla_object_event_ingress FORCE ROW LEVEL SECURITY",
    );
    expect(migration).toContain(
      "GRANT SELECT, INSERT, UPDATE ON TABLE public.sla_object_event_ingress\nTO periapsis_sla_worker_owner",
    );
    expect(migration).toContain(
      "REVOKE ALL ON TABLE public.sla_object_event_ingress\nFROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier",
    );
    expect(migration).toContain("expected_role.rolcanlogin");
    expect(migration).toContain("expected_role.rolsuper");
    expect(migration).toContain("expected_role.rolbypassrls");
    expect(migration).toContain("expected_role.rolinherit");
    expect(migration).toContain("FOREACH table_privilege IN ARRAY ARRAY[");
    expect(migration).toContain("'TRUNCATE', 'REFERENCES', 'TRIGGER'");
    expect(migration).toContain("actor_type = 'system'");
    expect(migration).toContain("'tenant.sla.event.ingested'");
    expect(migration).not.toContain("actor_type = 'human'");
  });
});
