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

describe("customer-contact notification recipient fanout", () => {
  const foundation = migration("0101_contacts_portal_foundation.sql");
  const migrationSource = migration(
    "0222_customer_contact_recipient_fanout.sql",
  );
  const loader = functionBody(
    migrationSource,
    "load_notification_fanout_inputs_v3",
  );
  const customerStart = loader.indexOf("), customer_candidates AS (");
  const customerEnd = loader.indexOf("), all_candidates AS (", customerStart);
  if (customerStart < 0 || customerEnd < 0) {
    throw new Error("Missing customer candidate branch");
  }
  const customerCandidates = loader.slice(customerStart, customerEnd);
  const contactEligibility = customerCandidates.slice(
    customerCandidates.indexOf("WHERE contact.tenant_id = context_tenant"),
  );

  it("treats the contact as the recipient and adds only a live account principal", () => {
    expect(customerCandidates).toContain("'principalId', live_account.user_id");
    expect(customerCandidates).not.toContain(
      "'principalId', contact.linked_user_id",
    );
    expect(customerCandidates).toMatch(
      /LEFT JOIN LATERAL \(\s+SELECT membership\.user_id\s+FROM public\.tenant_memberships AS membership\s+JOIN public\.users AS identity\s+ON identity\.id = membership\.user_id\s+WHERE contact\.linked_membership_id IS NOT NULL\s+AND contact\.linked_user_id IS NOT NULL\s+AND membership\.tenant_id = contact\.tenant_id\s+AND membership\.id = contact\.linked_membership_id\s+AND membership\.user_id = contact\.linked_user_id\s+AND membership\.status = 'active'\s+AND identity\.active\s+LIMIT 1\s+\) AS live_account ON true/su,
    );
    expect(contactEligibility).not.toMatch(
      /contact\.linked_(?:membership|user)_id/u,
    );
  });

  it("preserves contact validity, preferences, windows, and customer-safe scope", () => {
    expect(contactEligibility).toContain("contact.tenant_id = context_tenant");
    expect(contactEligibility).toContain(
      "source_event.maximum_audience = 'customer'",
    );
    expect(contactEligibility).toContain(
      "contact.active AND contact.archived_at IS NULL",
    );
    expect(contactEligibility).toContain("contact.email_allowed");
    expect(contactEligibility).toContain("contact.notification_categories @>");
    expect(contactEligibility).toContain(
      "public.customer_contact_notification_windows",
    );
    expect(contactEligibility).toContain(
      "private_notification_ticket_is_customer_projectable_v1",
    );
    expect(contactEligibility).toContain("link.tenant_id = context_tenant");
    expect(contactEligibility).toContain("link.contact_id = contact.id");
    expect(contactEligibility).toContain("link.archived_at IS NULL");
  });

  it("collapses group and tag selectors into one deterministic contact candidate", () => {
    expect(customerCandidates).toContain(
      'array_agg(group_row.key ORDER BY group_row.key COLLATE "C")',
    );
    expect(customerCandidates).toContain(
      "jsonb_build_array('customer_contacts')",
    );
    expect(customerCandidates).toContain("jsonb_build_array('contact_group')");
    expect(customerCandidates).toContain("jsonb_build_array('contact_tag')");
    expect(customerCandidates).toContain("app.private_contact_rule_matches_v1");
    expect(
      customerCandidates.match(/FROM public\.customer_contacts AS contact/gu),
    ).toHaveLength(1);
  });

  it("retains the pair-shape and tenant-coherent account-link constraints", () => {
    expect(foundation).toContain("customer_contacts_link_shape_check");
    expect(foundation).toContain(
      '("customer_contacts"."linked_membership_id" is null) = ("customer_contacts"."linked_user_id" is null)',
    );
    expect(foundation).toContain("customer_contacts_linked_membership_fk");
    expect(foundation).toContain(
      'FOREIGN KEY ("tenant_id","linked_membership_id","linked_user_id")',
    );
    expect(migrationSource).not.toMatch(/\b(?:ALTER|DROP)\s+TABLE\b/iu);
  });

  it("keeps the active loader least-privilege ABI", () => {
    expect(loader).toContain("SECURITY DEFINER");
    expect(loader).toContain("SET search_path = pg_catalog, public, app");
    expect(loader).toContain("private_notification_operator_candidates_v2");
    expect(loader).toContain("'mentioned'");
    expect(migrationSource).toContain(
      "OWNER TO periapsis_notification_dispatch_owner",
    );
    expect(migrationSource).toContain(
      "FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,",
    );
    expect(migrationSource).toContain("TO periapsis_notifier");
  });
});
