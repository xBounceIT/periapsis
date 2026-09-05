import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(repositoryRoot, "packages/db/migrations/0102_hard_warbound.sql"),
  "utf8",
);
const alertSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/alerts.ts"),
  "utf8",
);
const ticketSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/ticketing.ts"),
  "utf8",
);
const ticketRepository = readFileSync(
  resolve(
    repositoryRoot,
    "services/api/internal/postgres/ticketing_repository.go",
  ),
  "utf8",
);

function indexDefinition(source: string, name: string): string {
  const start = source.indexOf(`index("${name}")`);
  if (start < 0) throw new Error(`missing index ${name}`);
  const end = source.indexOf("),", start);
  if (end < 0) throw new Error(`unterminated index ${name}`);
  return source.slice(start, end + 2);
}

function functionBody(name: string): string {
  const start = migration.indexOf(name);
  if (start < 0) throw new Error(`missing function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated function ${name}`);
  return migration.slice(start, end);
}

describe("ticket full-text search contract", () => {
  it("indexes only the customer-safe number, title, and description fields", () => {
    for (const definition of [
      indexDefinition(alertSchema, "alerts_ticket_search_idx"),
      indexDefinition(ticketSchema, "cases_ticket_search_idx"),
    ]) {
      expect(definition).toContain(".using(");
      expect(definition).toContain('"gin"');
      expect(definition).toContain("to_tsvector('simple'::regconfig");
      expect(definition).toContain("table.number");
      expect(definition).toContain("table.title");
      expect(definition).toContain("table.description");
      expect(definition).not.toMatch(
        /rawPayload|customFields|customerCustomFields|summary|classification|tags/,
      );
    }

    const repositoryExpression = ticketRepository.slice(
      ticketRepository.indexOf("const ticketSearchDocument"),
      ticketRepository.indexOf("// TicketingRepository"),
    );
    expect(repositoryExpression).toContain("to_tsvector('simple'::regconfig");
    expect(repositoryExpression).toContain("ticket.number");
    expect(repositoryExpression).toContain("ticket.title");
    expect(repositoryExpression).toContain("ticket.description");
    expect(repositoryExpression).not.toMatch(
      /raw_payload|custom_fields|customer_custom_fields|summary|classification|tags/,
    );
  });

  it("creates valid GIN indexes and publishes a fail-closed readiness check", () => {
    expect(migration).toContain(
      'CREATE INDEX "alerts_ticket_search_idx" ON "alerts" USING gin',
    );
    expect(migration).toContain(
      'CREATE INDEX "cases_ticket_search_idx" ON "cases" USING gin',
    );
    const readiness = functionBody("app.ticket_search_schema_readiness_v1");
    expect(readiness).toContain("index_row.indisvalid");
    expect(readiness).toContain("index_row.indisready");
    expect(readiness).toContain("index_row.indislive");
    expect(readiness).toContain("access_method.amname = 'gin'");
    expect(readiness).toContain("current_count = 103");
    expect(readiness).toContain("predecessor_count = 102");
    expect(readiness).toContain("retired_count = 0");
    expect(readiness).toContain("pg_get_functiondef");
    expect(readiness).toContain(
      "seed_tenant_authorization_contacts_compatibility_impl",
    );
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.ticket_search_schema_readiness_v1()\n  TO periapsis_api, periapsis_worker",
    );
  });

  it("repairs the 0101 authorization seed wrapper without rewriting history", () => {
    const seed = functionBody("app.seed_tenant_authorization(");
    expect(seed).toContain(
      "app.seed_tenant_authorization_contacts_compatibility_impl(",
    );
    expect(seed).toContain(
      "app.private_seed_tenant_contact_authorization_v1(p_tenant_id)",
    );
    expect(seed).not.toMatch(
      /PERFORM app\.seed_tenant_authorization\(\s*p_tenant_id/,
    );
  });

  it("advances compatibility to v19 with one exact rolling predecessor", () => {
    const current = functionBody("app.schema_compatibility_v19");
    const predecessor = functionBody("app.schema_compatibility_v18");
    const retired = functionBody("app.schema_compatibility_v17");
    const sealer = functionBody("app.seal_schema_compatibility_manifest");

    expect(current).toContain("journal_count = 103");
    expect(current).toContain("journal_latest_created_at = 1787692062461");
    expect(predecessor).toContain("FROM app.schema_compatibility_v19()");
    expect(predecessor).toContain("migration.migration_ordinal <= 102");
    expect(predecessor).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );
    expect(retired).toContain("'UNSUPPORTED'::text");
    expect(sealer).toContain(
      "cardinality(fingerprint_entries) IS DISTINCT FROM 103",
    );
    expect(sealer).toContain("FROM app.schema_compatibility_v18()");
    expect(sealer).toContain("schema compatibility v17 must be retired");
  });
});
