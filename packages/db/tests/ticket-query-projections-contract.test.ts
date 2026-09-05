import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const read = (path: string): string =>
  readFileSync(resolve(packageRoot, path), "utf8");

const roles = read("src/schema/roles.ts");
const alerts = read("src/schema/alerts.ts");
const cases = read("src/schema/ticketing.ts");
const serviceAccounts = read("src/schema/service-accounts.ts");
const sla = read("src/schema/sla.ts");
const generated = read("migrations/0139_tricky_hawkeye.sql");
const security = read("migrations/0140_ticket_query_projections_security.sql");
const readiness = read(
  "migrations/0141_ticket_query_projections_readiness.sql",
);
const ticketRepository = read(
  "../../services/api/internal/postgres/ticketing_repository.go",
);
const savedViewQuery = read(
  "../../services/api/internal/postgres/ticketing_saved_view_query.go",
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

describe("ticket query projection database boundary", () => {
  it("generates the alert default-order index and keeps the case peer exact", () => {
    const indexShape = ["table.tenantId", "table.updatedAt", "table.id"];
    expect(alerts).toContain('index("alerts_tenant_updated_idx").on(');
    expect(cases).toContain('index("cases_tenant_updated_idx").on(');
    for (const column of indexShape) {
      expect(alerts).toContain(column);
      expect(cases).toContain(column);
    }
    expect(generated).toContain(
      'CREATE INDEX "alerts_tenant_updated_idx" ON "alerts" USING btree ("tenant_id","updated_at","id")',
    );
    expect(generated).not.toContain("cases_tenant_updated_idx");
    for (const [index, valueColumn] of [
      ["sla_materialized_projection_instant_sort_idx", "instant_value"],
      [
        "sla_materialized_projection_duration_sort_idx",
        "duration_micros_value",
      ],
      ["sla_materialized_projection_percent_sort_idx", "percentage_value"],
      ["sla_materialized_projection_state_sort_idx", "state_value"],
    ] as const) {
      expect(sla).toContain(index);
      expect(generated).toContain(`CREATE INDEX "${index}"`);
      expect(generated).toContain(`"${valueColumn}" is not null`);
      expect(readiness).toContain(index);
      expect(readiness).toContain(`WHERE (${valueColumn} IS NOT NULL)`);
    }
  });

  it("uses two dedicated no-inherit owners with exact source RLS", () => {
    for (const role of [
      "periapsis_ticket_attribution_owner",
      "periapsis_ticket_sla_projection_owner",
    ]) {
      expect(roles).toMatch(
        new RegExp(`pgRole\\(\\s*"${role}",\\s*\\{ inherit: false \\}`),
      );
      expect(generated).toContain(`CREATE ROLE "${role}" WITH NOINHERIT`);
      expect(security).toContain(`ALTER ROLE ${role}`);
      expect(security).toContain("NOBYPASSRLS NOINHERIT");
    }
    expect(security).toContain(
      "REVOKE periapsis_ticket_attribution_owner,\n  periapsis_ticket_sla_projection_owner",
    );
    expect(readiness).toContain(
      "pg_has_role(runtime_role, expected_role, 'MEMBER')",
    );
    expect(serviceAccounts).toContain(
      '"tenant_service_accounts_ticket_attribution"',
    );
    expect(serviceAccounts).toContain("app.context_tenant_id()");
    expect(serviceAccounts).toContain(
      "app.current_tenant_membership_id() is not null",
    );
    expect(sla).toContain('"sla_column_versions_ticket_projection"');
    expect(sla).toContain('"sla_materialized_columns_ticket_projection"');
    expect(generated).toContain(
      'CREATE POLICY "tenant_service_accounts_ticket_attribution"',
    );
    expect(generated).toContain(
      'CREATE POLICY "sla_column_versions_ticket_projection"',
    );
    expect(generated).toContain(
      'CREATE POLICY "sla_materialized_columns_ticket_projection"',
    );
  });

  it("publishes only security-barrier, definer-rights allowlists", () => {
    for (const view of [
      "ticket_service_account_attributions_v1",
      "ticket_sla_column_revisions_v1",
      "ticket_sla_materialized_values_v1",
      "ticket_sla_instant_sort_values_v1",
      "ticket_sla_duration_sort_values_v1",
      "ticket_sla_percentage_sort_values_v1",
      "ticket_sla_state_sort_values_v1",
    ]) {
      expect(security).toContain(`CREATE VIEW app.${view}`);
      expect(security).toContain(
        "WITH (security_barrier = true, security_invoker = false)",
      );
      expect(security).toContain(`GRANT SELECT ON TABLE app.${view}`);
    }
    expect(security).toContain(
      "SELECT account.tenant_id, account.id, account.display_name",
    );
    expect(security).not.toMatch(
      /SELECT account\.(?:key|description|archive_reason|version)/,
    );
    expect(security).toContain("value.column_version, revision.format,");
    expect(security).not.toContain("revision.calculation");
    expect(security).not.toContain("revision.style_rules");
    expect(security).not.toContain("value.next_refresh_at");
    for (const [view, format, value] of [
      ["ticket_sla_instant_sort_values_v1", "datetime", "instant_value"],
      [
        "ticket_sla_duration_sort_values_v1",
        "duration",
        "duration_micros_value",
      ],
      [
        "ticket_sla_percentage_sort_values_v1",
        "percentage",
        "percentage_value",
      ],
      ["ticket_sla_state_sort_values_v1", "state_badge", "state_value"],
    ]) {
      const start = security.indexOf(`CREATE VIEW app.${view}`);
      const end = security.indexOf("--> statement-breakpoint", start);
      const body = security.slice(start, end);
      expect(body).toContain(`revision.format = '${format}'`);
      expect(body).toContain(`value.${value} IS NOT NULL`);
    }
    expect(security).toContain("Table-level revocation does not remove");
    expect(security).not.toMatch(
      /GRANT SELECT ON TABLE public\.(?:tenant_service_accounts|sla_column_versions|sla_materialized_column_values)\s+TO periapsis_api/,
    );
  });

  it("routes every production read through its narrow projection", () => {
    expect(
      ticketRepository.match(/ticket_service_account_attributions_v1/g),
    ).toHaveLength(2);
    expect(ticketRepository).not.toContain(
      "JOIN public.tenant_service_accounts",
    );
    expect(
      savedViewQuery.match(/ticket_sla_materialized_values_v1/g),
    ).toHaveLength(1);
    expect(
      savedViewQuery.match(/ticket_sla_column_revisions_v1/g),
    ).toHaveLength(1);
    for (const projection of [
      "ticket_sla_instant_sort_values_v1",
      "ticket_sla_duration_sort_values_v1",
      "ticket_sla_percentage_sort_values_v1",
      "ticket_sla_state_sort_values_v1",
    ]) {
      expect(savedViewQuery.match(new RegExp(projection, "g"))).toHaveLength(1);
    }
    expect(savedViewQuery).not.toContain("public.sla_column_versions");
    expect(savedViewQuery).not.toContain(
      "public.sla_materialized_column_values",
    );
  });

  it("readiness pins owner, ACL, RLS, view shape, indexes, and v29 rolling", () => {
    const body = functionBody(
      readiness,
      "ticket_query_projections_readiness_v1",
    );
    expect(body).toContain("relforcerowsecurity");
    expect(body).toContain("has_any_column_privilege");
    expect(body).toContain("security_barrier=true");
    expect(body).toContain("security_invoker=false");
    expect(body).toContain("alerts_tenant_updated_idx");
    expect(body).toContain("cases_tenant_updated_idx");
    expect(body).toContain("current_count = 142");
    expect(body).toContain("predecessor_count = 139");
    expect(functionBody(readiness, "schema_compatibility_v30")).toContain(
      "journal_count = 142",
    );
    expect(functionBody(readiness, "schema_compatibility_v29")).toContain(
      "migration.migration_ordinal <= 139",
    );
    expect(functionBody(readiness, "schema_compatibility_v28")).toContain(
      "'UNSUPPORTED'::text",
    );
    expect(readiness).toContain(
      "89a75840127b58a16350a341265a945c22513607bb809cb4e7b28e7a91e18ac4",
    );
    expect(readiness).toContain(
      "GRANT EXECUTE ON FUNCTION app.ticket_query_projections_readiness_v1()\nTO periapsis_api",
    );
  });
});
