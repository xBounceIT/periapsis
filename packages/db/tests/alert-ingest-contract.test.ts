import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  alertActivities,
  alertCommands,
  alerts,
} from "../src/schema/alerts.js";
import { auditEvents } from "../src/schema/audit.js";

const packageRoot = resolve(import.meta.dirname, "..");

function readGeneratedMigration(prefix: string): {
  fileName: string;
  source: string;
} {
  const matches = readdirSync(resolve(packageRoot, "migrations")).filter(
    (fileName) => new RegExp(`^${prefix}_[a-z0-9_]+[.]sql$`).test(fileName),
  );
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one generated ${prefix} migration, found ${matches.length}`,
    );
  }
  const source = readFileSync(
    resolve(packageRoot, "migrations", matches[0]!),
    "utf8",
  );
  if (source.trim().length === 0) {
    throw new Error(`Migration ${matches[0]} must not be empty`);
  }
  return { fileName: matches[0]!, source };
}

const additive = readGeneratedMigration("0034");
const finalStructural = readGeneratedMigration("0036");
const structural = `${additive.source}\n${finalStructural.source}`;
const security = (() => {
  const source = readFileSync(
    resolve(
      packageRoot,
      "migrations/0037_service_principal_alert_security.sql",
    ),
    "utf8",
  );
  if (source.trim().length === 0) {
    throw new Error(
      "Migration 0037_service_principal_alert_security.sql must not be empty",
    );
  }
  return source;
})();

function functionBody(name: string): string {
  const markers = [
    `CREATE OR REPLACE FUNCTION "app"."${name}"`,
    `CREATE FUNCTION "app"."${name}"`,
  ];
  const start = Math.max(...markers.map((marker) => security.indexOf(marker)));
  if (start === -1) {
    throw new Error(`Missing Alert function ${name}`);
  }
  const end = security.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`Unterminated Alert function ${name}`);
  }
  return security.slice(start, end);
}

function columnNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  return getTableConfig(table).columns.map((column) => column.name);
}

function foreignKeyNames(
  table: Parameters<typeof getTableConfig>[0],
): string[] {
  return getTableConfig(table).foreignKeys.map((foreignKey) =>
    foreignKey.getName(),
  );
}

describe("idempotent Alert-ingest structural database contract", () => {
  it("keeps the generated finalization structural and non-empty", () => {
    expect(finalStructural.fileName).toMatch(/^0036_[a-z0-9_]+[.]sql$/);
    expect(finalStructural.source).toMatch(
      /ALTER TABLE "(?:alerts|audit_events)"/,
    );
    expect(finalStructural.source).not.toMatch(
      /CREATE FUNCTION|SECURITY DEFINER|FORCE ROW LEVEL SECURITY|GRANT |INSERT INTO/,
    );
  });

  it("enforces exclusive tenant-leading human-or-service-account Alert creation", () => {
    const config = getTableConfig(alerts);
    const columns = new Map(
      config.columns.map((column) => [column.name, column] as const),
    );

    expect(columns.get("tenant_id")?.notNull).toBe(true);
    expect(columns.get("created_by")?.notNull).toBe(false);
    expect(columns.get("created_by_membership_id")?.notNull).toBe(false);
    expect(columns.get("created_by_service_account_id")?.notNull).toBe(false);
    expect(config.uniqueConstraints.map((item) => item.name)).toContain(
      "alerts_tenant_id_key",
    );
    expect(config.checks.map((item) => item.name)).toContain(
      "alerts_creator_attribution_check",
    );
    expect(foreignKeyNames(alerts)).toEqual(
      expect.arrayContaining([
        "alerts_creator_membership_id_fk",
        "alerts_creator_human_attribution_fk",
        "alerts_creator_service_account_fk",
      ]),
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","created_by_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id")',
    );
    expect(structural).toMatch(
      /"created_by_membership_id" is not null[\s\S]{0,500}"created_by_service_account_id" is null[\s\S]{0,500}or[\s\S]{0,500}"created_by_membership_id" is null[\s\S]{0,500}"created_by_service_account_id" is not null/i,
    );
  });

  it("records a tenant-bound domain activity with the same exclusive actor truth table", () => {
    const config = getTableConfig(alertActivities);
    const columns = new Map(
      config.columns.map((column) => [column.name, column] as const),
    );

    expect(columns.get("tenant_id")?.notNull).toBe(true);
    expect(columns.get("alert_id")?.notNull).toBe(true);
    expect(columns.get("actor_principal_kind")?.notNull).toBe(true);
    expect(columns.get("actor_membership_id")?.notNull).toBe(false);
    expect(columns.get("actor_service_account_id")?.notNull).toBe(false);
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(config.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "alert_activities_sequence_check",
        "alert_activities_actor_check",
        "alert_activities_metadata_object_check",
      ]),
    );
    expect(foreignKeyNames(alertActivities)).toEqual(
      expect.arrayContaining([
        "alert_activities_alert_fk",
        "alert_activities_actor_membership_fk",
        "alert_activities_actor_service_account_fk",
      ]),
    );
  });

  it("makes Alert command replay principal-specific, payload-bound, and permanent", () => {
    const config = getTableConfig(alertCommands);
    const columns = columnNames(alertCommands);

    expect(columns).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "operation",
        "principal_kind",
        "actor_membership_id",
        "actor_service_account_id",
        "key_digest",
        "request_digest",
        "result_alert_id",
        "result_version",
      ]),
    );
    expect(columns).not.toContain("expires_at");
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(
      config.indexes.filter((item) => item.config.unique && item.config.where),
    ).toHaveLength(2);
    expect(config.indexes.map((item) => item.config.name)).toEqual(
      expect.arrayContaining([
        "alert_commands_human_replay_key",
        "alert_commands_service_account_replay_key",
      ]),
    );
    expect(config.checks.map((item) => item.name)).toEqual(
      expect.arrayContaining([
        "alert_commands_operation_check",
        "alert_commands_actor_check",
        "alert_commands_digest_check",
        "alert_commands_result_version_check",
      ]),
    );
    expect(foreignKeyNames(alertCommands)).toEqual(
      expect.arrayContaining([
        "alert_commands_actor_membership_fk",
        "alert_commands_actor_service_account_fk",
        "alert_commands_result_fk",
      ]),
    );
    expect(structural).toContain("'alert.create'");
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","result_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict',
    );
  });

  it("extends append-only audit attribution with a complete actor XOR", () => {
    const config = getTableConfig(auditEvents);
    const actorServiceAccount = config.columns.find(
      (column) => column.name === "actor_service_account_id",
    );

    expect(actorServiceAccount?.notNull).toBe(false);
    expect(foreignKeyNames(auditEvents)).toContain(
      "audit_events_actor_service_account_fk",
    );
    expect(config.checks.map((item) => item.name)).toContain(
      "audit_events_actor_consistency_check",
    );
    expect(structural).toMatch(
      /actor_type" = 'user'[\s\S]{0,700}actor_service_account_id" is null[\s\S]{0,700}actor_type" = 'service_account'[\s\S]{0,700}actor_service_account_id" is not null[\s\S]{0,700}actor_type" = 'system'/i,
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id")',
    );
  });

  it("keeps human and bearer Alert commands distinct but side-effect complete", () => {
    const human = functionBody("create_tenant_alert_as_human_v1");
    const bearer = functionBody("create_tenant_alert_as_service_account_v1");

    for (const body of [human, bearer]) {
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(body).toContain("'alert.create'");
      expect(body).toContain("public.alert_commands");
      expect(body).toContain("request_digest IS DISTINCT FROM");
      expect(body).toContain("INSERT INTO public.alerts");
      expect(body).toContain("INSERT INTO public.alert_activities");
      expect(body).toMatch(/app\.append_[a-z0-9_]*audit[a-z0-9_]*\(/);
      expect(body).toContain("INSERT INTO public.outbox_events");
      expect(body).toContain("replayed");
    }

    expect(human).toContain("app.current_tenant_membership_id()");
    expect(human).not.toMatch(/p_(?:membership|user)_id uuid/);

    expect(bearer).toContain("app.authenticate_tenant_api_credential_v1(");
    expect(bearer).not.toMatch(
      /current_tenant_membership_id|current_tenant_has_exact_permission/,
    );
  });

  it("bounds the first Alert payload and never accepts placeholder JSON surfaces", () => {
    for (const name of [
      "create_tenant_alert_as_human_v1",
      "create_tenant_alert_as_service_account_v1",
    ]) {
      const body = functionBody(name);
      const declarationEnd = body.indexOf("RETURNS TABLE");
      const declaration = body.slice(0, declarationEnd);

      for (const parameter of [
        "p_title text",
        "p_description text",
        "p_external_id text",
        'p_severity "public"."alert_severity"',
        "p_key_digest bytea",
        "p_request_digest bytea",
      ]) {
        expect(declaration).toContain(parameter);
      }
      expect(declaration).not.toMatch(/jsonb|raw_payload|custom_field|tags/);
      expect(body).toContain("char_length(p_title)");
      expect(body).toContain("char_length(p_description)");
      expect(body).toContain("char_length(p_external_id)");
      expect(body).toContain("octet_length(p_key_digest) = 32");
      expect(body).toContain("octet_length(p_request_digest) = 32");
    }
  });

  it("guards append-only activity and replay rows from ordinary mutation", () => {
    for (const table of ["alert_activities", "alert_commands"]) {
      expect(security).toMatch(
        new RegExp(`CREATE TRIGGER "${table}_[^"]*(?:immutable|guard)[^"]*"`),
      );
    }
    expect(security).toContain("alert activity rows are append-only");
    expect(security).toContain("alert command rows are append-only");
    expect(security).not.toMatch(
      /GRANT (?:INSERT|UPDATE|DELETE)[^;]*ON TABLE "public"\."(?:alert_activities|alert_commands)"/,
    );
  });
});
