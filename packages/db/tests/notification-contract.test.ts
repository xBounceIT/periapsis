import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");
const foundation = migration("0091_spooky_hellfire_club.sql");
const security = migration("0092_phase6_notification_security.sql");
const fanout = migration("0093_phase6_notification_dispatch_abi.sql");
const planning = migration("0094_phase6_notification_planning_abi.sql");
const delivery = migration("0095_phase6_notification_delivery_abi.sql");
const administration = migration(
  "0096_phase6_notification_administration_abi.sql",
);
const trace = migration("0098_phase6_notification_trace_and_test_abi.sql");
const traceConstraint = migration("0099_common_purple_man.sql");
const outboxSchema = readFileSync(
  resolve(packageRoot, "src/schema/outbox.ts"),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const create = source.indexOf(`CREATE FUNCTION app.${name}`);
  const replace = source.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`);
  const start = create === -1 ? replace : create;
  if (start === -1) throw new Error(`missing notification function ${name}`);
  const end = source.indexOf("$function$;", start);
  if (end === -1) throw new Error(`unterminated notification function ${name}`);
  return source.slice(start, end);
}

describe("notification persistence and dispatch contract", () => {
  it("models both delivery channels under forced tenant RLS", () => {
    expect(foundation).toContain(
      `CREATE TYPE "public"."notification_channel" AS ENUM('email', 'webhook')`,
    );
    for (const table of [
      "tenant_notification_deliveries",
      "tenant_notification_delivery_attempts",
      "tenant_notification_fanout_snapshots",
      "tenant_notification_secret_versions",
      "tenant_notification_smtp_configurations",
      "tenant_notification_webhook_configurations",
    ]) {
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
    }
    expect(security).toContain("NOREPLICATION NOBYPASSRLS");
    expect(security).toContain("notification.%");
    expect(security).toContain(
      "app.current_tenant_membership_id()\nTO periapsis_api",
    );
  });

  it("pins deterministic fanout inputs and collision-checks both channels", () => {
    const load = functionBody(planning, "load_notification_fanout_inputs_v1(");
    expect(load).toContain("webhook_configuration_pins");
    expect(load).toContain(
      "'scope', selected_snapshot.smtp_configuration_scope",
    );
    const commit = functionBody(planning, "commit_notification_fanout_v1(");
    expect(commit).toContain("emailCount");
    expect(commit).toContain("webhookCount");
    expect(commit).toContain("notification webhook delivery key collision");
    expect(commit).toContain("notification delivery key collision");
    expect(fanout).toContain("FOR UPDATE SKIP LOCKED");
  });

  it("starts attempts at claim and fences expired workers before reclaim", () => {
    const emailClaim = functionBody(
      trace,
      "claim_notification_delivery_batch_v1(",
    );
    const webhookClaim = functionBody(
      trace,
      "claim_notification_webhook_delivery_batch_v1(",
    );
    for (const claim of [emailClaim, webhookClaim]) {
      expect(claim).toContain("outcome = 'fenced'");
      expect(claim).toContain(
        "INSERT INTO public.tenant_notification_delivery_attempts",
      );
      expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    }
    for (const name of [
      "complete_notification_delivery_v2(",
      "retry_notification_delivery_v2(",
      "dead_letter_notification_delivery_v2(",
    ]) {
      const body = functionBody(delivery, name);
      expect(body).toContain(
        "UPDATE public.tenant_notification_delivery_attempts",
      );
      expect(body).not.toContain(
        "INSERT INTO public.tenant_notification_delivery_attempts",
      );
    }
    expect(
      functionBody(delivery, "complete_notification_delivery_v2("),
    ).toContain("p_response ->> 'responseClass' <> '2'");
  });

  it("uses one consumer-compatible canonical trace validator everywhere", () => {
    const validator = functionBody(
      trace,
      "private_notification_trace_context_is_safe_v1(",
    );
    expect(validator).toContain("octet_length(p_tracestate) BETWEEN 1 AND 512");
    expect(validator).toContain("char_length(key) > 256");
    expect(validator).toContain(
      "octet_length(member_value) <> char_length(member_value)",
    );
    expect(outboxSchema).toContain(
      "app.private_notification_trace_context_is_safe_v1(",
    );
    expect(traceConstraint).toContain(
      "app.private_notification_trace_context_is_safe_v1(",
    );
  });

  it("binds human and bearer Alert ingest to explicit trace successors", () => {
    for (const name of [
      "create_tenant_alert_as_human_v3(",
      "create_tenant_alert_as_service_account_v3(",
    ]) {
      const body = functionBody(trace, name);
      expect(body).toContain(
        "app.private_notification_trace_context_is_safe_v1(",
      );
      expect(body).toContain("set_config('app.traceparent'");
      expect(body).toContain("set_config('app.tracestate'");
      expect(body).toContain("IF NOT created.replayed THEN");
      expect(body).toContain(
        "app.private_append_tenant_notification_event_v3(",
      );
    }
    const legacyTrigger = functionBody(
      trace,
      "append_alert_ticketing_create_effects_v1(",
    );
    expect(legacyTrigger).toContain("'sla.alert.created'");
    expect(legacyTrigger).not.toContain("'notification.alert.created'");
    expect(trace).toContain(
      "REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_human_v2(",
    );
    expect(trace).toContain(
      "REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_service_account_v2(",
    );
  });

  it("exposes bounded key inventory, schema readiness, and oldest pending age", () => {
    expect(administration).toContain("notification_live_key_versions_v1");
    const readiness = functionBody(
      trace,
      "notification_dispatch_readiness_v2(",
    );
    expect(readiness).toContain(
      "transaction_timestamp() - min(event.occurred_at)",
    );
    expect(readiness).toContain("event.event_type LIKE 'notification.%'");
    expect(readiness).toContain("event.dead_lettered_at IS NULL");
    expect(readiness).toContain("event.lease_until <= transaction_timestamp()");
    expect(readiness).toContain("0::bigint");
    expect(functionBody(trace, "notification_schema_readiness_v1(")).toContain(
      "current_count = 100 AND predecessor_count = 91",
    );
  });
});
