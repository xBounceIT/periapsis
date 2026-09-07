import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const source = (path: string): string =>
  readFileSync(resolve(repositoryRoot, path), "utf8");
const migration = source(
  "packages/db/migrations/0206_smtp_runtime_assurance.sql",
);
const v49Migration = source(
  "packages/db/migrations/0229_v49_compatibility.sql",
);
const v51Migration = source(
  "packages/db/migrations/0233_v51_compatibility.sql",
);
const v55Migration = source(
  "packages/db/migrations/0241_v55_compatibility.sql",
);
const notifierRepository = source(
  "services/notifier/src/postgres-repository.ts",
);
const notifierHttp = source("services/notifier/src/http.ts");
const apiRepository = source(
  "services/api/internal/postgres/notification_repository.go",
);
const compose = source("deploy/compose/compose.base.yaml");
const workflow = source(".github/workflows/ci.yml");

function functionBody(name: string): string {
  const created = migration.indexOf(`CREATE FUNCTION app.${name}(`);
  const replaced = migration.indexOf(`CREATE OR REPLACE FUNCTION app.${name}(`);
  const start = created === -1 ? replaced : created;
  if (start === -1) throw new Error(`missing SMTP function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end === -1) throw new Error(`unterminated SMTP function ${name}`);
  return migration.slice(start, end);
}

describe("SMTP runtime assurance contract", () => {
  it("splits preflight, exact-pin loading, and health execution across deny-default roles", () => {
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.load_pinned_smtp_configuration_v2(uuid, text, uuid, integer)\nTO periapsis_notifier",
    );
    expect(migration).toContain(
      ") TO periapsis_api;\n--> statement-breakpoint\n\n-- The notifier no longer has a direct audit-table write surface",
    );
    for (const name of [
      "test_tenant_notification_smtp_v2",
      "test_platform_notification_smtp_v2",
    ]) {
      expect(migration).toMatch(
        new RegExp(
          `REVOKE ALL ON FUNCTION app\\.${name}\\([\\s\\S]*?\\) FROM PUBLIC,[\\s\\S]*?periapsis_notifier`,
        ),
      );
    }
    expect(functionBody("load_pinned_smtp_configuration_v2")).toContain(
      "pinned.version = p_configuration_version",
    );
    expect(functionBody("load_pinned_smtp_configuration_v2")).toContain(
      "configuration.revoked_at IS NULL",
    );
    expect(notifierHttp).toContain('case "/internal/v1/smtp-health":');
    expect(notifierHttp).toContain("dependencies.smtpHealth.probe(");
    expect(notifierHttp).toContain("lifecycle.signal");
    expect(apiRepository).toContain("app.test_tenant_notification_smtp_v2(");
    expect(apiRepository).toContain("app.test_platform_notification_smtp_v2(");
  });

  it("couples the exact fenced email completion and receipt-only audit atomically", () => {
    const complete = functionBody("complete_notification_delivery_v3");
    const audit = functionBody(
      "private_append_notification_email_delivery_audit_v1",
    );
    expect(complete).toContain("FOR UPDATE");
    expect(complete).toContain(
      "selected.fence_token IS DISTINCT FROM p_fence_token",
    );
    expect(complete).toContain("attempt.fence_token = p_fence_token");
    expect(complete).toContain(
      "jsonb_typeof(p_response -> 'acceptedCount') <> 'number'",
    );
    expect(complete).toContain(
      "app.private_append_notification_email_delivery_audit_v1(",
    );
    expect(audit).toContain("pg_advisory_xact_lock");
    expect(audit).toContain("attempt.outcome = 'delivered'");
    expect(audit).toContain(
      "attempt.provider_receipt = delivery.provider_receipt",
    );
    expect(audit).toContain(
      "jsonb_build_object('receiptDigest', p_receipt_digest)",
    );
    expect(audit).not.toMatch(/recipient|subject|body|password|banner/iu);
    expect(migration).toContain(
      "DROP POLICY IF EXISTS audit_events_notifier_access ON public.audit_events",
    );
    expect(migration).not.toContain("audit_events_sequence_seq");
  });

  it("keeps notifier code-first and migration-first partial rollout paths safe", () => {
    expect(notifierRepository).toContain(
      "FROM app.load_pinned_smtp_configuration_v2(",
    );
    expect(notifierRepository).toContain(
      "FROM app.load_pinned_smtp_configuration_v1(",
    );
    expect(notifierRepository).toContain(
      "FROM app.notification_dispatch_readiness_v55()",
    );
    expect(notifierRepository).not.toContain(
      "FROM app.notification_dispatch_readiness_v51()",
    );
    expect(notifierRepository).not.toContain(
      "FROM app.notification_dispatch_readiness_v49()",
    );
    expect(notifierRepository).toContain(
      "FROM app.notification_dispatch_readiness_v4()",
    );
    expect(notifierRepository).toContain(
      "SELECT app.complete_notification_delivery_v3(",
    );
    expect(notifierRepository).toContain(
      "SELECT app.complete_notification_delivery_v2(",
    );
    expect(functionBody("complete_notification_delivery_v2")).toContain(
      "app.complete_notification_delivery_v3(",
    );
    expect(functionBody("complete_notification_delivery_replay_v2")).toContain(
      "app.private_append_notification_email_delivery_audit_v1(",
    );
  });

  it("roots readiness in exact owner, ACL, RLS, and direct-audit revocation checks", () => {
    const readiness = functionBody("notification_schema_readiness_v4");
    expect(readiness).toContain("app.notification_schema_readiness_v3()");
    expect(readiness).toContain("expected.expected_owner");
    expect(readiness).toContain("expected.api_execute");
    expect(readiness).toContain("expected.notifier_execute");
    expect(readiness).toContain("has_any_column_privilege(");
    expect(readiness).toContain("audit_events_notifier_access");
    expect(readiness).toContain("audit_events_notification_delivery_insert_v1");
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v4()\nTO periapsis_notifier",
    );
    expect(v49Migration).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.notification_dispatch_readiness_v49\(\)\s+TO periapsis_migrator,periapsis_notifier;/,
    );
    expect(v49Migration).toContain(
      "schema_safe := app.release_runtime_schema_readiness_v49();",
    );
    expect(v51Migration).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.notification_dispatch_readiness_v51\(\)\s+TO periapsis_migrator,periapsis_notifier;/,
    );
    expect(v51Migration).toContain(
      "schema_safe := app.release_runtime_schema_readiness_v51();",
    );
    expect(v55Migration).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.notification_dispatch_readiness_v55\(\)\s+TO periapsis_migrator,periapsis_notifier;/,
    );
    expect(v55Migration).toContain(
      "schema_safe := app.release_runtime_schema_readiness_v55();",
    );
  });

  it("runs a real loopback-only Mailpit probe and delivery in CI", () => {
    expect(compose).toContain(
      "127.0.0.1:${PERIAPSIS_MAILPIT_SMTP_PORT:-11025}:1025",
    );
    expect(workflow).toContain("smtp-mailpit-acceptance:");
    expect(workflow).toContain("--profile full up --detach --wait mailpit");
    expect(workflow).toContain(
      "pnpm --filter @periapsis/notifier test:mailpit",
    );
  });
});
