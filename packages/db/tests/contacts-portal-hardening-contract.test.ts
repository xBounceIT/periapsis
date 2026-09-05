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

describe("contacts and customer portal hardening", () => {
  const generatedSnapshot =
    migration("0107_nasty_revanche.sql") +
    migration("0108_remarkable_slipstream.sql");
  const security = migration("0109_contacts_portal_security.sql");
  const fanout = migration("0110_contacts_portal_fanout.sql");
  const abi = migration("0111_contacts_portal_abi.sql");
  const readiness = migration("0112_contacts_portal_readiness.sql");

  it("stores bounded operation-shaped replay snapshots with a customer allowlist", () => {
    expect(generatedSnapshot).toContain("pg_column_size");
    expect(generatedSnapshot).toContain("<= 524288");
    expect(generatedSnapshot).toContain("jsonb_path_query_array");
    expect(generatedSnapshot).toContain("= 13");
    expect(generatedSnapshot).toContain("= 20");
    expect(generatedSnapshot).toContain("= 11");
    expect(generatedSnapshot).toContain("= 10");
    expect(generatedSnapshot).toContain("'legacy.unavailable'");

    const capture = functionBody(
      abi,
      "capture_customer_contact_command_result_v1",
    );
    const customerStart = capture.indexOf(
      "NEW.operation = 'portal.preference.replace' THEN",
    );
    const customerBranch = capture.slice(
      customerStart,
      capture.indexOf("ELSE", customerStart),
    );
    expect(customerBranch).toContain("'notificationCategories'");
    expect(customerBranch).toContain("'notificationWindows'");
    expect(customerBranch).not.toContain("'escalationPriority'");
    expect(customerBranch).not.toContain("'contactClass'");
    expect(customerBranch).not.toContain("'tags'");
    expect(customerBranch).not.toContain("linkedMembershipId");
    expect(customerBranch).not.toContain("linkedUserId");
  });

  it("derives route intent and author audience without legacy role labels", () => {
    expect(security).toContain("contact_group.manage");
    expect(security).not.toContain("membership.role");
    expect(security).toContain("NEW.origin = 'customer_portal'");
    expect(security).toContain("customer_contact_commands_immutable_v1");

    for (const name of [
      "replay_customer_contact_command_v1",
      "commit_customer_contact_v1",
      "commit_customer_contact_group_v1",
      "commit_ticket_customer_contact_v1",
      "create_customer_portal_ticket_comment_v1",
    ]) {
      expect(functionBody(abi, name)).not.toContain("membership.role");
    }
    expect(functionBody(abi, "commit_customer_contact_v1")).toContain(
      "'portal.contact.preference.manage', 'own'",
    );
    expect(functionBody(abi, "commit_customer_contact_group_v1")).toContain(
      "'contact_group.manage', 'tenant'",
    );
    expect(functionBody(abi, "commit_ticket_customer_contact_v1")).toContain(
      "'contact.read', 'tenant'",
    );
  });

  it("replays exact snapshots after live authorization and before each CAS", () => {
    for (const name of [
      "commit_customer_contact_v1",
      "commit_customer_contact_group_v1",
      "commit_ticket_customer_contact_v1",
    ]) {
      const body = functionBody(abi, name);
      const authorization = body.indexOf(
        "current_tenant_human_has_exact_permission_v3",
      );
      const replay = body.indexOf("replay_customer_contact_command_v1");
      const cas = body.indexOf("FOR UPDATE");
      expect(authorization).toBeGreaterThan(0);
      expect(replay).toBeGreaterThan(authorization);
      expect(cas).toBeGreaterThan(replay);
    }
    const replay = functionBody(abi, "replay_customer_contact_command_v1");
    expect(replay).toContain(
      "request_digest IS DISTINCT FROM p_request_digest",
    );
    expect(replay).toContain("result_snapshot #>> '{resource,ticketKind}'");
    expect(replay).toContain("result_snapshot #>> '{resource,ticketId}'");
    expect(replay).toContain("expires_at > transaction_timestamp()");
    expect(replay).toContain("projection' = 'unavailable'");
  });

  it("re-authorizes fanout by exact capability and keeps customer delivery linked", () => {
    const candidates = functionBody(
      fanout,
      "private_notification_operator_candidates_v1",
    );
    const loader = functionBody(fanout, "load_notification_fanout_inputs_v2");
    expect(candidates).toContain("tenant_human_has_exact_permission_v3");
    expect(candidates).toContain("read_tenant");
    expect(candidates).toContain("read_assigned");
    expect(candidates).toContain("read_team");
    expect(candidates).not.toContain("membership.role");
    expect(fanout).toContain(
      "GRANT EXECUTE ON FUNCTION app.context_tenant_id()",
    );
    expect(fanout).toContain("public.operator_team_assignment_epochs");
    expect(fanout).toContain("public.ticket_workflow_versions");
    expect(fanout).toContain("contacts_fanout_dispatch_team_epochs_v1");
    expect(fanout).toContain("contacts_fanout_dispatch_workflow_versions_v1");
    expect(loader).toContain(
      "private_notification_ticket_is_customer_projectable_v1",
    );
    expect(loader).toContain("contact.linked_membership_id");
    expect(loader).toContain("contact.linked_user_id");
    expect(loader).toContain("link.archived_at IS NULL");
    expect(loader).not.toContain("membership.role");
  });

  it("keeps v20 rolling while sealing v22 and checks the exact predecessor", () => {
    expect(readiness).toContain("schema_compatibility_v22");
    expect(readiness).toContain("full_count = 113");
    expect(readiness).toContain("predecessor_count IS DISTINCT FROM 107");
    expect(readiness).toContain("legacy_count IS DISTINCT FROM 104");
    expect(readiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v20()",
    );
    expect(readiness).toContain(
      "08415f4562df5ff64cb71895e9189f7223fd68b4b061125da3fa6ca1f8b9a667",
    );
    expect(readiness).toContain("HAVING count(*) <> 1");
    expect(readiness).toContain("membership.role");
  });
});
