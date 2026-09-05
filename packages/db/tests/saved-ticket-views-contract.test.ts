import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const generated = readFileSync(
  resolve(packageRoot, "migrations/0136_white_misty_knight.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(packageRoot, "migrations/0137_saved_ticket_views_security.sql"),
  "utf8",
);
const abi = readFileSync(
  resolve(packageRoot, "migrations/0138_saved_ticket_views_abi_readiness.sql"),
  "utf8",
);
const schema = readFileSync(
  resolve(packageRoot, "src/schema/ticket-saved-views.ts"),
  "utf8",
);
const customFields = readFileSync(
  resolve(packageRoot, "src/schema/customfields.ts"),
  "utf8",
);
const queryAdapter = readFileSync(
  resolve(
    packageRoot,
    "../../services/api/internal/postgres/ticketing_saved_view_query.go",
  ),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const declaration = new RegExp(
    `CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\(`,
  ).exec(source);
  if (declaration?.index === undefined) {
    throw new Error(`Missing function app.${name}`);
  }
  const end = source.indexOf("$function$;", declaration.index);
  if (end < 0) {
    throw new Error(`Incomplete function app.${name}`);
  }
  return source.slice(declaration.index, end + "$function$;".length);
}

describe("saved ticket views database boundary", () => {
  it("stores exact canonical bytes behind a dedicated forced-RLS owner", () => {
    expect(schema).toContain("dataType() {\n    return 'text COLLATE \"C\"';");
    expect(schema).toContain('"ticket_saved_views"');
    expect(schema).toContain('"ticket_saved_view_commands"');
    expect(generated).toContain(
      'CREATE ROLE "periapsis_ticket_saved_view_owner" WITH NOINHERIT',
    );
    expect(security).toContain(
      "ALTER TABLE public.ticket_saved_views FORCE ROW LEVEL SECURITY",
    );
    expect(security).toContain(
      "ALTER TABLE public.ticket_saved_view_commands FORCE ROW LEVEL SECURITY",
    );
    expect(security).toContain(
      "REVOKE ALL ON TABLE public.ticket_saved_views,",
    );
    expect(security).not.toContain(
      "GRANT SELECT ON TABLE public.ticket_saved_views TO periapsis_api",
    );
    expect(generated).toContain(
      '"ticket_saved_view_commands_replay_key" UNIQUE("tenant_id","actor_user_id","owner_membership_id","aggregate_kind","action","idempotency_key_digest")',
    );
    expect(generated).toContain('"ticket_saved_view_commands_retention_check"');
  });

  it("authorizes by route intent and live capability, never a legacy role label", () => {
    const authority = functionBody(
      security,
      "private_ticket_saved_view_assert_authority_v1",
    );
    expect(authority).toContain("app.context_tenant_id()");
    expect(authority).toContain("app.context_user_id()");
    expect(authority).toContain("app.current_tenant_membership_id()");
    expect(authority).toContain("membership.status = 'active'");
    expect(authority).toContain("identity.active");
    expect(authority).toContain("FROM public.customer_contacts AS contact");
    expect(authority).toContain("contact.linked_membership_id");
    expect(authority).toContain("contact.linked_user_id");
    expect(authority).toContain("contact.active");
    expect(authority).toContain("contact.archived_at IS NULL");
    expect(authority).toContain(
      "app.current_tenant_human_has_exact_permission_v3(permission_key, 'own')",
    );
    expect(authority).toContain("'assigned'");
    expect(authority).toContain("'operator_team'");
    expect(authority).toContain("'tenant'");
    expect(authority).not.toMatch(/membership\.role\s*(?:=|IN|::)/i);
    expect(authority).not.toContain("LegacyRole");
  });

  it("keeps canonical resolution bounded, current-pinned, and extension-free", () => {
    const resolver = functionBody(
      security,
      "private_resolve_ticket_saved_view_spec_v1",
    );
    expect(resolver).toContain("pg_column_size(p_request) > 262144");
    expect(resolver).toContain("jsonb_array_length(filters -> 'custom') > 8");
    expect(resolver).toContain("item_count NOT BETWEEN 1 AND 64");
    expect(resolver).toContain("scalar_bytes > 196608");
    expect(resolver).toContain("saved-view dynamic sort is not projected");
    expect(resolver).toContain("private_ticket_saved_view_custom_pin_v1");
    expect(resolver).toContain("private_ticket_saved_view_sla_pin_v1");
    expect(resolver).toContain("pg_catalog.sha256(convert_to(canonical");
    expect(resolver).not.toMatch(/\bdigest\s*\(/);
    expect(security).not.toContain("CREATE EXTENSION");
  });

  it("re-authorizes before replay or resource lookup and preserves exact snapshots", () => {
    for (const name of [
      "get_ticket_saved_view_v1",
      "lookup_ticket_saved_view_replay_v1",
      "commit_ticket_saved_view_v1",
    ]) {
      const body = functionBody(abi, name);
      const authorization = body.indexOf(
        "private_ticket_saved_view_assert_authority_v1",
      );
      expect(authorization).toBeGreaterThan(0);
      const firstResourceRead = Math.min(
        ...[
          body.indexOf("FROM public.ticket_saved_views"),
          body.indexOf("FROM public.ticket_saved_view_commands"),
        ].filter((index) => index >= 0),
      );
      expect(authorization).toBeLessThan(firstResourceRead);
    }
    const replay = functionBody(abi, "lookup_ticket_saved_view_replay_v1");
    expect(replay).toContain("command_row.expires_at > clock_timestamp()");
    expect(replay).toContain("command_row.actor_user_id = actor_id");
    expect(replay).toContain(
      "command_row.owner_membership_id = owner_membership_id",
    );
    expect(replay).toContain(
      "private_ticket_saved_view_command_record_v1(command_record)",
    );
  });

  it("serializes idempotency before CAS and keeps stale archive fail-safe", () => {
    const commit = functionBody(abi, "commit_ticket_saved_view_v1");
    expect(commit).toContain("pg_advisory_xact_lock");
    expect(commit).toContain("saved-view idempotency key was reused");
    expect(commit).toContain("request_fingerprint_digest");
    expect(commit).toContain("current_view.revision <> expected_revision");
    expect(commit).toContain("USING ERRCODE = '40001'");
    const archiveBranch = commit.slice(
      commit.indexOf("ELSIF action_value = 'archive'"),
      commit.indexOf("ELSE", commit.indexOf("ELSIF action_value = 'archive'")),
    );
    expect(archiveBranch).not.toContain(
      "private_ticket_saved_view_spec_pins_current_v1",
    );
    const restoreBranch = commit.slice(
      commit.indexOf("ELSE", commit.indexOf("ELSIF action_value = 'archive'")),
    );
    expect(restoreBranch).toContain(
      "private_ticket_saved_view_spec_pins_current_v1",
    );
    expect(security).toContain(
      "unexpired saved-view command evidence is immutable",
    );
    expect(security).toContain("OLD.expires_at <= clock_timestamp()");
  });

  it("emits only redacted operation-shaped audit and outbox documents", () => {
    const effects = functionBody(
      security,
      "private_append_ticket_saved_view_effects_v1",
    );
    expect(effects).toContain("'content_redacted', true");
    expect(effects).toContain("'view_id', p_view_id");
    expect(effects).toContain("'aggregate_kind', p_aggregate_kind");
    expect(effects).toContain("'status', p_status");
    expect(effects).toContain("'revision', p_revision");
    expect(effects).toContain("uuid_extract_version(p_request_id) = 7");
    expect(effects).toContain("uuid_extract_version(p_correlation_id) = 7");
    expect(effects).not.toMatch(
      /'(?:spec_canonical|spec_digest|idempotency_key|request_fingerprint|search|filter)'/i,
    );
  });

  it("materializes every accepted dynamic custom sort with an exact typed index", () => {
    const expected = [
      "boolean",
      "date",
      "ip",
      "cidr",
      "reference",
      "single_select",
    ];
    for (const type of expected) {
      expect(customFields).toContain(
        `custom_field_values_saved_sort_${type}_idx`,
      );
      expect(generated).toContain(`custom_field_values_saved_sort_${type}_idx`);
      expect(abi).toContain(`custom_field_values_saved_sort_${type}_idx`);
    }
    expect(generated).toContain('("option_keys"[1])');
    expect(abi).toContain("pg_get_indexdef");
  });

  it("publishes five narrow JSONB functions and one exact rolling predecessor", () => {
    for (const name of [
      "resolve_ticket_saved_view_spec_v1",
      "list_ticket_saved_views_v1",
      "get_ticket_saved_view_v1",
      "lookup_ticket_saved_view_replay_v1",
      "commit_ticket_saved_view_v1",
    ]) {
      const body = functionBody(abi, name);
      expect(body).toContain("RETURNS TABLE(response jsonb)");
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("ROWS 1");
      expect(abi).toContain(
        `GRANT EXECUTE ON FUNCTION app.${name}(jsonb)\nTO periapsis_api`,
      );
    }
    expect(functionBody(abi, "schema_compatibility_v29")).toContain(
      "journal_count = 139",
    );
    expect(functionBody(abi, "schema_compatibility_v28")).toContain(
      "migration.migration_ordinal <= 136",
    );
    expect(functionBody(abi, "schema_compatibility_v27")).toContain(
      "'UNSUPPORTED'::text",
    );
    expect(abi).toContain(
      "3f4ccd0e67f21c3e3b72ab76b1cbe0c7265a9fa8d872af8c4a8f00047cd976aa",
    );
  });

  it("uses the canonical custom-field schema version in query plans", () => {
    expect(queryAdapter).toContain(
      "WHERE tenant_id = $1 AND id = $2 AND schema_version = $3",
    );
    expect(queryAdapter).not.toContain("active_schema_version");
  });
});
