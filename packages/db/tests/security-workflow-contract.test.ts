import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

type PackageManifest = {
  scripts?: Record<string, string>;
};

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const parsedManifest: unknown = JSON.parse(
  readFileSync(resolve(packageRoot, "package.json"), "utf8"),
);
if (!isPackageManifest(parsedManifest)) {
  throw new Error("@periapsis/db package.json has an invalid scripts object");
}
const manifest = parsedManifest;
const workflow = readFileSync(
  resolve(repositoryRoot, ".github/workflows/ci.yml"),
  "utf8",
);

function aggregateSecurityCommands(): string[] {
  const aggregate = manifest.scripts?.["test:security"];
  if (aggregate === undefined) {
    throw new Error("@periapsis/db must define test:security");
  }
  return Array.from(
    aggregate.matchAll(/pnpm run (test:security:[a-z0-9-]+)/gu),
    (match) => match[1]!,
  );
}

function isPackageManifest(value: unknown): value is PackageManifest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const scripts = Reflect.get(value, "scripts");
  return (
    scripts === undefined ||
    (scripts !== null && typeof scripts === "object" && !Array.isArray(scripts))
  );
}

function requiredEnvironment(command: string): string[] {
  const script = manifest.scripts?.[command];
  const sourcePath = /tsx ([^ ]+\.ts)$/u.exec(script ?? "")?.[1];
  if (sourcePath === undefined) {
    return [];
  }
  const source = readFileSync(resolve(packageRoot, sourcePath), "utf8");
  return Array.from(
    new Set(
      Array.from(
        source.matchAll(/process\.env\.([A-Z][A-Z0-9_]+)/gu),
        (match) => match[1]!,
      ),
    ),
  ).toSorted();
}

describe("PostgreSQL security CI wiring", () => {
  it("exports every explicit environment required by the aggregate harness", () => {
    const required = aggregateSecurityCommands().flatMap(requiredEnvironment);
    expect(required.length).toBeGreaterThan(0);
    for (const name of required) {
      expect(workflow, `${name} is not wired in CI`).toContain(`${name}:`);
    }
  });

  it("keeps login-lifecycle readiness on an unprovisioned PostgreSQL cluster", () => {
    expect(workflow).toContain("readiness-postgres:");
    expect(workflow).toMatch(
      /Apply migrations to the isolated readiness database[\s\S]*?DATABASE_URL: [^\n]*:5433\/periapsis\?sslmode=disable/u,
    );
    expect(workflow).toMatch(
      /PERIAPSIS_PLATFORM_OIDC_BINDING_READINESS_TEST_DATABASE_URL: [^\n]*:5433\/periapsis\?sslmode=disable/u,
    );
    expect(workflow).toMatch(
      /Provision least-privileged runtime logins[\s\S]*?DATABASE_URL: [^\n]*:5432\/periapsis\?sslmode=disable/u,
    );
  });

  it("gives every stateful runtime harness its own freshly migrated database", () => {
    const databaseByEnvironment = new Map<string, string>([
      [
        "PERIAPSIS_IDENTITY_MAPPING_TEST_DATABASE_URL",
        "periapsis_identity_mapping",
      ],
      [
        "PERIAPSIS_IDENTITY_DIRECTORY_OPERATION_TEST_DATABASE_URL",
        "periapsis_identity_directory",
      ],
      [
        "PERIAPSIS_IDENTITY_JIT_SYNC_TEST_DATABASE_URL",
        "periapsis_identity_jit",
      ],
      [
        "PERIAPSIS_INTERACTIVE_LDAP_AUTH_TEST_DATABASE_URL",
        "periapsis_interactive_ldap_auth",
      ],
      [
        "PERIAPSIS_IDENTITY_MFA_SECURITY_TEST_DATABASE_URL",
        "periapsis_identity_mfa",
      ],
      [
        "PERIAPSIS_PASSKEY_REVALIDATION_TEST_DATABASE_URL",
        "periapsis_passkey_revalidation",
      ],
      [
        "PERIAPSIS_TENANT_LIFECYCLE_TEST_DATABASE_URL",
        "periapsis_tenant_lifecycle",
      ],
      [
        "PERIAPSIS_PLATFORM_IDENTITY_PROVIDER_TEST_DATABASE_URL",
        "periapsis_platform_provider",
      ],
      [
        "PERIAPSIS_PLATFORM_IDENTITY_BINDING_TEST_DATABASE_URL",
        "periapsis_platform_binding",
      ],
      [
        "PERIAPSIS_PLATFORM_IDENTITY_ACCOUNT_TEST_DATABASE_URL",
        "periapsis_platform_identity_account",
      ],
      [
        "PERIAPSIS_PLATFORM_OIDC_BINDING_AUTH_TEST_DATABASE_URL",
        "periapsis_platform_oidc_auth",
      ],
      [
        "PERIAPSIS_TICKET_WATCHER_SECURITY_TEST_DATABASE_URL",
        "periapsis_ticket_watchers",
      ],
      [
        "PERIAPSIS_ALERT_RELATION_TEST_DATABASE_URL",
        "periapsis_alert_relations",
      ],
      ["PERIAPSIS_CASE_DFIR_SECURITY_TEST_DATABASE_URL", "periapsis_case_dfir"],
      [
        "PERIAPSIS_DFIR_GENERIC_RELATIONSHIP_SECURITY_TEST_DATABASE_URL",
        "periapsis_dfir_generic_relationships",
      ],
      [
        "PERIAPSIS_SHARED_DFIR_SECURITY_TEST_DATABASE_URL",
        "periapsis_shared_dfir",
      ],
      [
        "PERIAPSIS_DFIR_MUTATION_RETENTION_TEST_DATABASE_URL",
        "periapsis_dfir_mutation_retention",
      ],
      [
        "PERIAPSIS_DFIR_STORAGE_SCAN_SECURITY_TEST_DATABASE_URL",
        "periapsis_dfir_storage_scan",
      ],
      [
        "PERIAPSIS_NOTIFICATION_SECURITY_TEST_DATABASE_URL",
        "periapsis_notifications",
      ],
      ["PERIAPSIS_SLA_RUNTIME_TEST_DATABASE_URL", "periapsis_sla_runtime"],
      [
        "PERIAPSIS_SLA_EVENT_INGRESS_TEST_DATABASE_URL",
        "periapsis_sla_event_ingress",
      ],
      [
        "PERIAPSIS_NOTIFICATION_INBOX_TEST_DATABASE_URL",
        "periapsis_notification_inbox",
      ],
      [
        "PERIAPSIS_WEBHOOK_URL_POLICY_TEST_DATABASE_URL",
        "periapsis_webhook_url_policy",
      ],
      [
        "PERIAPSIS_TENANT_PROVIDER_MFA_TEST_DATABASE_URL",
        "periapsis_tenant_provider_mfa",
      ],
    ]);
    expect(new Set(databaseByEnvironment.values()).size).toBe(
      databaseByEnvironment.size,
    );
    expect(workflow).toContain(
      'createdb -U postgres -T periapsis "${database}"',
    );
    for (const [environment, database] of databaseByEnvironment) {
      expect(workflow).toContain(`            ${database}`);
      expect(workflow).toMatch(
        new RegExp(
          `${environment}: [^\\n]*/${database}\\?sslmode=disable`,
          "u",
        ),
      );
    }
  });

  it("isolates the aggregate, direct RLS, and Go authorization state machines", () => {
    for (const database of [
      "periapsis_core_security",
      "periapsis_rls",
      "periapsis_go_authorization",
    ]) {
      expect(workflow).toContain(`            ${database}`);
    }
    expect(workflow).toMatch(
      /Prove atomic protected-configuration binding[\s\S]*?DATABASE_URL: [^\n]*\/periapsis_core_security\?sslmode=disable/u,
    );
    expect(workflow).toContain(
      "-U postgres -d periapsis_rls < tests/security/rls.sql",
    );
    expect(workflow).toMatch(
      /PERIAPSIS_AUTHORIZATION_TEST_DATABASE_URL: [^\n]*\/periapsis_go_authorization\?sslmode=disable/u,
    );
  });

  it("runs the incompatible v35 upgrade through the isolated upgrade matrix", () => {
    expect(workflow).toContain("postgres-security-upgrades:");
    expect(workflow).toMatch(
      /- name: tenant-provider MFA continuation\s+script: test:security:tenant-provider-mfa-continuation-upgrade\s+database_env: PERIAPSIS_TENANT_PROVIDER_MFA_UPGRADE_TEST_DATABASE_URL/u,
    );
    expect(workflow).toContain("DATABASE_ENV: ${{ matrix.database_env }}");
    expect(workflow).toContain("UPGRADE_SCRIPT: ${{ matrix.script }}");
    expect(workflow).toContain(
      'pnpm --filter @periapsis/db run "${UPGRADE_SCRIPT}"',
    );
    expect(workflow).toMatch(
      /- name: webhook URL policy\s+script: test:security:webhook-url-policy-upgrade\s+database_env: PERIAPSIS_WEBHOOK_URL_POLICY_UPGRADE_TEST_DATABASE_URL/u,
    );
    expect(workflow).toMatch(
      /- name: Alert DFIR completion\s+script: test:security:alert-dfir-upgrade\s+database_env: PERIAPSIS_ALERT_DFIR_UPGRADE_TEST_DATABASE_URL\s+second_database_env: PERIAPSIS_ALERT_DFIR_INVALID_UPGRADE_TEST_DATABASE_URL\s+second_database_name: periapsis_alert_dfir_invalid/u,
    );
    expect(workflow).toMatch(
      /- name: V49 compatibility seal\s+script: test:security:schema-compatibility-v49-upgrade\s+database_env: PERIAPSIS_SCHEMA_COMPATIBILITY_V49_UPGRADE_TEST_DATABASE_URL/u,
    );
    expect(workflow).toContain(
      "SECOND_DATABASE_ENV: ${{ matrix.second_database_env }}",
    );
    expect(workflow).toContain(
      'export "${SECOND_DATABASE_ENV}=${second_database_url}"',
    );
    expect(workflow).toContain(
      "POSTGRES_INITDB_ARGS: --locale=C --encoding=UTF8",
    );
  });

  it("runs notification security through the exact provisioned login roles", () => {
    expect(workflow).toMatch(
      /PERIAPSIS_NOTIFICATION_SECURITY_NOTIFIER_DATABASE_URL: postgresql:\/\/periapsis_notifier_login:[^\n]*:5432\/periapsis_notifications\?sslmode=disable/u,
    );
    expect(workflow).toMatch(
      /PERIAPSIS_NOTIFICATION_SECURITY_API_DATABASE_URL: postgresql:\/\/periapsis_api_login:[^\n]*:5432\/periapsis_notifications\?sslmode=disable/u,
    );
    expect(workflow).toMatch(
      /PERIAPSIS_WEBHOOK_URL_POLICY_NOTIFIER_DATABASE_URL: postgresql:\/\/periapsis_notifier_login:[^\n]*:5432\/periapsis_webhook_url_policy\?sslmode=disable/u,
    );
    expect(workflow).toMatch(
      /PERIAPSIS_WEBHOOK_URL_POLICY_API_DATABASE_URL: postgresql:\/\/periapsis_api_login:[^\n]*:5432\/periapsis_webhook_url_policy\?sslmode=disable/u,
    );
  });
});
