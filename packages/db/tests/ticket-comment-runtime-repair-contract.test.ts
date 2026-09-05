import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0209_ticket_comment_aggregate_guard_v48.sql",
  ),
  "utf8",
);
const downstreamMigration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0204_ticket_comment_downstream.sql",
  ),
  "utf8",
);

function functionBodyFrom(source: string, name: string): string {
  const declaration = new RegExp(
    `CREATE(?: OR REPLACE)? FUNCTION app\\.${name.replaceAll(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    )}\\(`,
  );
  const start = source.search(declaration);
  expect(start, `missing app.${name}`).toBeGreaterThanOrEqual(0);
  const suffix = source.slice(start);
  const marker = suffix.match(/AS \$([A-Za-z0-9_]*)\$/);
  expect(marker?.index, `missing body marker for app.${name}`).toBeTypeOf(
    "number",
  );
  const bodyStart = (marker?.index ?? 0) + (marker?.[0].length ?? 0);
  const bodyEnd = suffix.indexOf(`$${marker?.[1] ?? ""}$;`, bodyStart);
  expect(bodyEnd, `unterminated app.${name}`).toBeGreaterThan(bodyStart);
  return suffix.slice(bodyStart, bodyEnd);
}

function functionBody(name: string): string {
  return functionBodyFrom(migration, name);
}

function sourceHash(name: string): string {
  return createHash("sha256").update(functionBody(name)).digest("hex");
}

describe("ticket comment PostgreSQL 18 runtime repairs", () => {
  it("dispatches every aggregate relation before touching table-shaped records", () => {
    const source = functionBody("guard_ticket_comment_aggregate_v1");
    for (const table of [
      "ticket_comments",
      "ticket_comment_revisions",
      "ticket_comment_author_snapshots",
      "ticket_comment_escalation_sources",
      "ticket_comment_revision_attachments",
      "ticket_comment_revision_mentions",
    ]) {
      expect(source).toContain(`TG_TABLE_NAME = '${table}'`);
    }
    expect(source).toContain("IF TG_OP = 'DELETE' THEN");
    expect(source).toContain("OLD.copied_comment_id");
    expect(source).toContain("NEW.copied_comment_id");
    expect(source).not.toMatch(/CASE\s+TG_TABLE_NAME/u);
    expect(source).not.toMatch(/coalesce\(NEW\./u);
    expect(source).toContain(
      "RAISE EXCEPTION 'ticket comment aggregate guard rejected relation %.%'",
    );
    expect(sourceHash("guard_ticket_comment_aggregate_v1")).toBe(
      "1a8784d7831eb3eb2ac471967e2251546bfb009d16a06edf2e24d8b86df533e7",
    );
  });

  it("repairs both UUID page cursors without casts or UUID aggregates", () => {
    expect(migration).toContain(
      "'c7f102189bd2fb0ae6084d82a437164d87bcec38db176aa9c1a976450fe064a0'",
    );
    expect(migration).toContain(
      "'793ae58572424af2c14b63419179b20e0264ec160969f7f53093f7ec2fa7967b'",
    );
    expect(migration).toContain(
      "(SELECT id FROM page ORDER BY id DESC LIMIT 1)",
    );
    expect(migration).not.toMatch(/::text\s+ORDER BY\s+id/u);
    expect(migration).not.toMatch(/max\(id\)(?! FROM page\)'\s*;)/u);
    expect(migration).toContain(
      "'6aa816195c40e630cb337c8af0ba161b305f9db7478012c8b09e3937a7d89106'",
    );
    expect(migration).toContain(
      "'ff5e75cfa0a78df943963fc48bcd64704642dd5647f924f2ca5c04b032e5f5e4'",
    );
  });

  it("keeps the legacy export entry point delegated and repairs its V2 target", () => {
    expect(migration).toContain(
      "'f2a3acb742662362357692566247c7eaeff6d332b028d989d71eaf8b3fed3052'",
    );
    expect(migration).toContain(
      "'5707314bf8bd446e49f100a1635929bcde46dd8ac02ff98795d3c693abf9bdf0'",
    );
    const source = functionBody("private_ticket_export_require_human_v2");
    expect(source).toContain(
      "SELECT count(*),(array_agg(contact.id ORDER BY contact.id))[1]",
    );
    expect(source).toContain("INTO contact_count,customer_contact_id");
    expect(
      source.match(/FROM public\.customer_contacts AS contact/gu),
    ).toHaveLength(1);
    expect(source).not.toMatch(/(?:min|max)\(contact\.id\)/u);
    expect(sourceHash("private_ticket_export_require_human_v2")).toBe(
      "fee31ac38c6d410b9dcfa39bf1327acfaea350c2c429aa4ad20f9cc647bd9d29",
    );
    const legacyPrivateWrapper = functionBodyFrom(
      downstreamMigration,
      "private_ticket_export_require_human_v1",
    );
    expect(legacyPrivateWrapper).toContain(
      "SELECT * FROM app.private_ticket_export_require_human_v2(",
    );
    expect(
      createHash("sha256").update(legacyPrivateWrapper).digest("hex"),
    ).toBe("f2a3acb742662362357692566247c7eaeff6d332b028d989d71eaf8b3fed3052");
    expect(
      functionBodyFrom(downstreamMigration, "resolve_ticket_export_access_v2"),
    ).toContain("SELECT * FROM app.resolve_ticket_export_access_v1(request)");
  });

  it("attests all repaired functions, six deferred triggers, and closed ACLs", () => {
    const source = functionBody(
      "ticket_comment_runtime_repair_schema_readiness_v1",
    );
    for (const hash of [
      "1a8784d7831eb3eb2ac471967e2251546bfb009d16a06edf2e24d8b86df533e7",
      "6aa816195c40e630cb337c8af0ba161b305f9db7478012c8b09e3937a7d89106",
      "ff5e75cfa0a78df943963fc48bcd64704642dd5647f924f2ca5c04b032e5f5e4",
      "f2a3acb742662362357692566247c7eaeff6d332b028d989d71eaf8b3fed3052",
      "fee31ac38c6d410b9dcfa39bf1327acfaea350c2c429aa4ad20f9cc647bd9d29",
    ]) {
      expect(source).toContain(hash);
    }
    expect(source.match(/_consistency_v1'/gu)).toHaveLength(6);
    expect(source).toContain("trigger_row.tgtype = 29");
    expect(source).toContain("trigger_row.tgdeferrable");
    expect(source).toContain("trigger_row.tginitdeferred");
    expect(source).toContain("privilege.grantee = function_row.proowner");
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION app\.guard_ticket_comment_aggregate_v1\(\)[\s\S]*?periapsis_ticket_runtime_owner;/u,
    );
  });
});
