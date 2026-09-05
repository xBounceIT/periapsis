import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrations = resolve(import.meta.dirname, "../migrations");
const structural = readFileSync(
  resolve(migrations, "0051_complex_the_santerians.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(migrations, "0052_identity_access_security.sql"),
  "utf8",
);
const readiness = readFileSync(
  resolve(migrations, "0053_identity_access_readiness_v8.sql"),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const marker = `CREATE FUNCTION app.${name}`;
  const replacementMarker = `CREATE OR REPLACE FUNCTION app.${name}`;
  const start = Math.max(
    source.indexOf(marker),
    source.indexOf(replacementMarker),
  );
  expect(start, `${name} declaration`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("$function$;", start);
  expect(end, `${name} terminator`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("tenant LDAP identity/access schema", () => {
  it("adds the provider-access source without widening the provider scope", () => {
    expect(structural).toContain(
      `ALTER TYPE "public"."authorization_source_kind" ADD VALUE 'identity_provider_access' BEFORE 'identity_mapping'`,
    );
    expect(structural).not.toMatch(/CREATE TABLE "platform_/);
    expect(structural).not.toMatch(/CREATE TABLE "[^"\n]*mapping/);
  });

  it("creates every package-A tenant table with a non-null tenant key and RLS", () => {
    const tables = [
      "tenant_auth_provider_bindings",
      "tenant_identity_provider_access_epochs",
      "tenant_ldap_external_identities",
      "tenant_ldap_external_identity_subject_aliases",
      "tenant_ldap_provider_access_grants",
      "tenant_ldap_provider_profile_contributions",
      "tenant_user_manual_profile_overrides",
    ];
    for (const table of tables) {
      const create = structural.indexOf(`CREATE TABLE "${table}"`);
      const next = structural.indexOf("CREATE TABLE ", create + 1);
      const body = structural.slice(
        create,
        next === -1 ? structural.length : next,
      );
      expect(create, table).toBeGreaterThanOrEqual(0);
      expect(body).toContain('"tenant_id" uuid NOT NULL');
      expect(structural).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
    }
  });

  it("binds login codes and exact access epochs with tenant-consistent keys", () => {
    expect(structural).toContain(
      'CONSTRAINT "tenant_auth_provider_bindings_tenant_provider_key" UNIQUE("tenant_id","provider_id")',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_auth_provider_bindings_tenant_login_key" UNIQUE("tenant_id","key")',
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","current_access_epoch_id","id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id")',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_identity_provider_access_epochs_source_key" UNIQUE("tenant_id","source_id")',
    );
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_identity_provider_access_epochs_live_binding_key"',
    );
  });

  it("stores only encrypted immutable subjects and versioned provider aliases", () => {
    expect(structural).toContain('"subject_ciphertext" "bytea" NOT NULL');
    expect(structural).toContain('"subject_nonce" "bytea" NOT NULL');
    expect(structural).toContain(
      '"subject_format" "identity_subject_format" NOT NULL',
    );
    expect(structural).toContain(
      'octet_length("tenant_ldap_external_identities"."subject_ciphertext") between 17 and 4112',
    );
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_ldap_external_identity_subject_aliases_live_digest_key"',
    );
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_ldap_external_identity_subject_aliases_live_version_key"',
    );
    const identityTable = structural.slice(
      structural.indexOf('CREATE TABLE "tenant_ldap_external_identities"'),
      structural.indexOf(
        'CREATE TABLE "tenant_ldap_external_identity_subject_aliases"',
      ),
    );
    expect(identityTable).not.toMatch(/email|username|\bdn\b/i);
  });

  it("ties provider access grants to an exact epoch/source and exact User membership", () => {
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","access_epoch_id","binding_id","provider_id","source_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id","source_id")',
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","provider_id","id","user_id")',
    );
    expect(structural).toContain(
      'FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id")',
    );
  });

  it("keeps manual overrides separate from source-owned provider contributions", () => {
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_ldap_provider_profile_contributions_live_grant_key"',
    );
    expect(structural).toContain(
      'CONSTRAINT "tenant_user_manual_profile_overrides_pkey" PRIMARY KEY("tenant_id","membership_id")',
    );
    expect(structural).not.toContain(
      'ALTER TABLE "users" ALTER COLUMN "email" SET NOT NULL',
    );
  });
});

describe("tenant LDAP identity/access security ABI", () => {
  it("forces RLS and grants no direct runtime table access", () => {
    const tables = [
      "tenant_auth_provider_bindings",
      "tenant_identity_provider_access_epochs",
      "tenant_ldap_external_identities",
      "tenant_ldap_external_identity_subject_aliases",
      "tenant_ldap_provider_access_grants",
      "tenant_ldap_provider_profile_contributions",
      "tenant_user_manual_profile_overrides",
    ];
    for (const table of tables) {
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `REVOKE ALL ON TABLE public.${table} FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
      );
      expect(security).not.toMatch(
        new RegExp(
          `GRANT (?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]*ON TABLE public\\.${table}`,
        ),
      );
    }
  });

  it("creates a fresh authoritative source epoch for every enable transition", () => {
    const create = functionBody(
      security,
      "create_tenant_auth_provider_binding_v1",
    );
    const update = functionBody(
      security,
      "update_tenant_auth_provider_binding_v1",
    );
    for (const body of [create, update]) {
      expect(body).toContain("'identity_provider_access'");
      expect(body).toContain("true, false");
      expect(body).toContain(
        "INSERT INTO public.tenant_identity_provider_access_epochs",
      );
      expect(body).toContain("current_access_epoch_id");
    }
    expect(update).toContain("coalesce(max(epoch.sequence), 0) + 1");
    expect(update).toContain(
      "app.private_close_tenant_identity_access_epoch_v1",
    );
  });

  it("closes only exact provider-owned grants and rematerializes profiles", () => {
    const close = functionBody(
      security,
      "private_close_tenant_identity_access_epoch_v1",
    );
    expect(close).toContain(
      "UPDATE public.tenant_ldap_provider_profile_contributions",
    );
    expect(close).toContain("UPDATE public.tenant_ldap_provider_access_grants");
    expect(close).toContain("UPDATE public.tenant_authorization_sources");
    expect(close).toContain("app.private_materialize_tenant_user_profile_v1");
    expect(close).not.toContain("UPDATE public.tenant_memberships");
    expect(close).toContain(
      "SELECT array_agg(DISTINCT access_grant.membership_id)",
    );
  });

  it("admits encrypted identities and profile contributions only on live LDAP paths", () => {
    const identityGuard = functionBody(
      security,
      "guard_tenant_ldap_external_identity_v1",
    );
    expect(identityGuard).toContain("provider.kind = 'ldap'");
    expect(identityGuard).toContain("provider.enabled");
    expect(identityGuard).toContain("keyring.is_active");

    const contributionGuard = functionBody(
      security,
      "guard_tenant_ldap_provider_profile_contribution_v1",
    );
    expect(contributionGuard).toContain("access_grant.ended_at IS NULL");
    expect(contributionGuard).toContain(
      "binding.current_access_epoch_id = access_grant.access_epoch_id",
    );
    expect(contributionGuard).toContain(
      "source.kind = 'identity_provider_access'",
    );
    expect(security).toContain(
      "BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_provider_profile_contributions",
    );
  });

  it("materializes manual fields first and provider fields deterministically", () => {
    const materialize = functionBody(
      security,
      "private_materialize_tenant_user_profile_v1",
    );
    for (const field of [
      "display_name",
      "first_name",
      "last_name",
      "username",
      "email",
    ]) {
      expect(materialize).toContain(`manual.${field}`);
      expect(materialize).toContain(`contribution.${field}`);
    }
    expect(materialize).toContain(
      "ORDER BY binding.profile_priority, binding.id",
    );
    expect(materialize).toContain("source.kind = 'identity_provider_access'");
    expect(materialize).not.toContain("user_login_identifiers");
  });

  it("inventories external ciphertext and aliases in keyring readiness v2", () => {
    const verify = functionBody(security, "verify_identity_keyring_v2");
    expect(verify).toContain("tenant_ldap_provider_secrets");
    expect(verify).toContain("tenant_ldap_external_identities");
    expect(verify).toContain("tenant_ldap_external_identity_subject_aliases");
    expect(verify).toContain("NOT alias.digest_key_version = ANY(p_versions)");
  });

  it("publishes exact v8 readiness and retains only the v7 predecessor", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v8()",
    );
    expect(readiness).toContain("journal_count = 54");
    expect(readiness).toContain("p_expected_count IS DISTINCT FROM 54");
    expect(readiness).toContain("fingerprint_entries[1:51]");
    expect(readiness).toContain(
      "global user email must remain nullable before federated admission",
    );
    expect(readiness).toContain(
      "external-subject keyring dependency inventory is incomplete",
    );
    expect(readiness).toContain(
      "app.private_materialize_tenant_user_profile_v1(uuid,uuid)",
    );
    expect(readiness).toContain(
      "api_can_execute IS DISTINCT FROM expected_function.api_execute",
    );
    expect(readiness).toContain(
      "worker_can_execute IS DISTINCT FROM expected_function.worker_execute",
    );
  });
});
