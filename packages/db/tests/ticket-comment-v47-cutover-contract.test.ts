import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const persistence = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0202_ticket_comment_persistence.sql",
  ),
  "utf8",
);
const runtime = readFileSync(
  resolve(import.meta.dirname, "../migrations/0203_ticket_comment_runtime.sql"),
  "utf8",
);
const downstream = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0204_ticket_comment_downstream.sql",
  ),
  "utf8",
);
const migration = `${runtime}\n${downstream}`;

function canonicalSql(value: string): string {
  return value
    .toLowerCase()
    .replaceAll('"', "")
    .replaceAll("ticket_comments.", "")
    .replaceAll(/\s+/g, " ")
    .replaceAll(/\s*([(),=])\s*/g, "$1")
    .trim();
}

function revokeStatements(value: string): string[] {
  return value.match(/REVOKE\s+ALL\s+ON\s+TABLE[\s\S]*?;/gi) ?? [];
}

describe("ticket comment V47 atomic runtime cutover", () => {
  const sql = canonicalSql(migration);
  const cutover = sql.indexOf(
    "drop policy ticket_comments_api_tenant on public.ticket_comments",
  );

  it("installs every application ABI before closing predecessor table reads", () => {
    expect(cutover).toBeGreaterThanOrEqual(0);
    for (const name of [
      "list_tenant_ticket_comments_v2",
      "list_customer_portal_ticket_comments_v2",
      "preview_tenant_ticket_comment_v1",
      "preview_customer_portal_ticket_comment_v1",
      "list_tenant_ticket_comment_mention_candidates_v1",
      "list_tenant_ticket_comment_revisions_v1",
      "list_customer_portal_ticket_comment_revisions_v1",
      "get_tenant_ticket_comment_edit_state_v1",
      "get_customer_portal_ticket_comment_edit_state_v1",
      "create_tenant_ticket_comment_v2",
      "create_customer_portal_ticket_comment_v2",
      "edit_tenant_ticket_comment_v2",
      "edit_customer_portal_ticket_comment_v2",
    ]) {
      const installed = sql.indexOf(`create function app.${name}(`);
      expect(installed, `missing app.${name}`).toBeGreaterThanOrEqual(0);
      expect(
        installed,
        `app.${name} must precede the table cutover`,
      ).toBeLessThan(cutover);
    }
  });

  it("closes both legacy projection tables behind forced owner-only RLS", () => {
    expect(sql).toContain(
      "drop policy ticket_comments_api_tenant on public.ticket_comments",
    );
    expect(sql).toContain(
      "drop policy ticket_comment_author_snapshots_api_tenant on public.ticket_comment_author_snapshots",
    );
    for (const [table, policy] of [
      ["ticket_comments", "ticket_comments_owner_access"],
      [
        "ticket_comment_author_snapshots",
        "ticket_comment_author_snapshots_owner_access",
      ],
    ]) {
      expect(sql).toContain(
        `alter table public.${table} force row level security`,
      );
      expect(sql).toContain(
        `alter table public.${table} owner to periapsis_ticket_runtime_owner`,
      );
      expect(sql).toMatch(
        new RegExp(
          `create policy ${policy} on public\\.${table} (as permissive )?for all to periapsis_ticket_runtime_owner using\\(true\\)with check\\(true\\)`,
        ),
      );
    }

    const revokes = revokeStatements(migration).map(canonicalSql);
    for (const table of [
      "public.ticket_comments",
      "public.ticket_comment_author_snapshots",
    ]) {
      const statement = revokes.find((candidate) => candidate.includes(table));
      expect(statement, `missing ACL closure for ${table}`).toBeDefined();
      for (const role of [
        "public",
        "periapsis_api",
        "periapsis_worker",
        "periapsis_notifier",
        "periapsis_auditor",
      ]) {
        expect(statement).toContain(role);
      }
    }
  });

  it("replaces every permissive legacy comment constraint with the V47 invariant", () => {
    for (const name of [
      "ticket_comments_body_check",
      "ticket_comments_origin_check",
      "ticket_comments_origin_visibility_check",
      "ticket_comments_revision_check",
      "ticket_comments_mentions_check",
      "ticket_comments_timestamps_check",
    ]) {
      expect(sql).toContain(
        `alter table public.ticket_comments drop constraint if exists ${name}`,
      );
      expect(sql).toContain(
        `alter table public.ticket_comments add constraint ${name}`,
      );
    }
    expect(sql).toContain(
      "app.private_ticket_comment_markdown_valid_v1(body_markdown)",
    );
    expect(sql).toContain(
      "app.private_ticket_comment_html_valid_v1(body_html)",
    );
    expect(sql).toContain("revision between 1 and 2147483647");
    expect(sql).toContain(
      "app.private_ticket_comment_uuid_array_valid_v1(mentioned_user_ids,50)",
    );
    expect(sql).toContain(
      "origin not in('customer_portal','escalation_copy')or visibility='public'",
    );
    expect(sql).toContain(
      "app.private_ticket_comment_timestamp_valid_v1(created_at)",
    );
    expect(sql).toContain(
      "app.private_ticket_comment_timestamp_valid_v1(updated_at)",
    );
  });

  it("suspends and restores the immutable snapshot guard around the cutover repair", () => {
    const snapshotRepair = sql.indexOf(
      "update public.ticket_comment_author_snapshots as snapshot set origin='system'",
    );
    const guardDrop = sql.indexOf(
      "drop trigger ticket_comment_author_snapshots_write_guard_v1 on public.ticket_comment_author_snapshots",
    );
    const guardDisable = sql.indexOf(
      "alter table public.ticket_comment_author_snapshots disable trigger ticket_comment_author_snapshots_write_guard_v1",
    );
    const guardCreate = sql.indexOf(
      "create trigger ticket_comment_author_snapshots_write_guard_v1 before insert or update or delete on public.ticket_comment_author_snapshots",
      snapshotRepair,
    );
    const guardEnable = sql.indexOf(
      "alter table public.ticket_comment_author_snapshots enable trigger ticket_comment_author_snapshots_write_guard_v1",
      snapshotRepair,
    );

    expect(snapshotRepair).toBeGreaterThanOrEqual(0);
    expect(Math.max(guardDrop, guardDisable)).toBeGreaterThanOrEqual(0);
    expect(Math.max(guardDrop, guardDisable)).toBeLessThan(snapshotRepair);
    expect(Math.max(guardCreate, guardEnable)).toBeGreaterThan(snapshotRepair);
  });

  it("retires the compatibility writer and legacy public write entry points", () => {
    expect(sql).toContain(
      "drop trigger ticket_comments_capture_v47_compat_v1 on public.ticket_comments",
    );
    expect(sql).toContain(
      "drop trigger ticket_comments_immutable_v1 on public.ticket_comments",
    );
    expect(sql).toMatch(
      /create trigger ticket_comments_[a-z0-9_]+ before update or delete on public\.ticket_comments/,
    );

    for (const predecessor of [
      "create_tenant_ticket_comment_v1",
      "create_customer_portal_ticket_comment_v1",
    ]) {
      expect(sql).toMatch(
        new RegExp(
          `revoke (all|execute) on function [^;]*app\\.${predecessor}\\([^;]+?from [^;]*periapsis_api`,
        ),
      );
    }
  });

  it("keeps trigger records table-shaped across action, watcher, and comment commands", () => {
    const trigger = canonicalSql(persistence);
    expect(trigger).toContain(
      "if tg_table_name='ticket_commands' then source_kind :='ticket_action'; operation :=new.operation;",
    );
    expect(trigger).toContain(
      "elsif tg_table_name='ticket_comment_commands' then source_kind :='comment'; operation :=new.operation;",
    );
    expect(trigger).toContain(
      "elsif tg_table_name='ticket_watcher_commands' then source_kind :='watcher';",
    );
    expect(trigger).not.toContain("operation :=case tg_table_name");
  });

  it("locks live authorization before asynchronous private export decisions", () => {
    for (const name of [
      "private_ticket_export_require_human_v2",
      "private_ticket_export_requester_live_v2",
    ]) {
      const start = sql.indexOf(`create function app.${name}(`);
      const end = sql.indexOf("$function$;", start);
      expect(start, `missing app.${name}`).toBeGreaterThanOrEqual(0);
      expect(end, `unterminated app.${name}`).toBeGreaterThan(start);
      const body = sql.slice(start, end);
      expect(body).toContain(
        "perform app.lock_current_tenant_authorization_state();",
      );
    }
  });

  it("does not dereference an unassigned edit record on comment creation", () => {
    const runtimeSql = canonicalSql(runtime);
    expect(runtimeSql).toContain(
      "effective_visibility public.ticket_comment_visibility :=p_visibility;",
    );
    expect(runtimeSql).toContain(
      "effective_visibility :=comment_row.visibility;",
    );
    expect(runtimeSql).not.toContain(
      "coalesce(p_visibility,comment_row.visibility)",
    );
  });

  it("replaces readiness roots that intentionally reject retired V1 ABIs", () => {
    for (const [successor, predecessor] of [
      [
        "contacts_portal_schema_readiness_v2",
        "contacts_portal_schema_readiness_v1",
      ],
      [
        "ticket_bulk_runtime_schema_readiness_v2",
        "ticket_bulk_runtime_schema_readiness_v1",
      ],
      [
        "ticket_export_runtime_schema_readiness_v2",
        "ticket_export_runtime_schema_readiness_v1",
      ],
    ]) {
      const installed = sql.indexOf(`create function app.${successor}(`);
      const retired = sql.indexOf(
        `revoke execute on function app.${predecessor}()`,
      );
      expect(installed, `missing app.${successor}`).toBeGreaterThanOrEqual(0);
      expect(
        retired,
        `missing retirement for app.${predecessor}`,
      ).toBeGreaterThan(installed);
    }
  });
});
