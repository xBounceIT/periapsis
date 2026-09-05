import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const migration = readFileSync(
  resolve(packageRoot, "migrations/0228_tenant_federation_administration.sql"),
  "utf8",
);
const auditGuard = readFileSync(
  resolve(packageRoot, "migrations/0103_crazy_scarlet_witch.sql"),
  "utf8",
);
const runtime = readFileSync(
  resolve(
    packageRoot,
    "tests/security/tenant-federation-administration-runtime.ts",
  ),
  "utf8",
);
const manifest = readFileSync(resolve(packageRoot, "package.json"), "utf8");
const workflow = readFileSync(
  resolve(repositoryRoot, ".github/workflows/ci.yml"),
  "utf8",
);

function functionDefinition(name: string): string {
  const start = migration.indexOf(`CREATE FUNCTION app.${name}(`);
  expect(start, `${name} must exist in migration 0228`).toBeGreaterThanOrEqual(
    0,
  );
  const end = migration.indexOf("\n--> statement-breakpoint", start);
  expect(end, `${name} must have a statement boundary`).toBeGreaterThan(start);
  return migration.slice(start, end);
}

function auditGuardArray(name: string): string[] {
  const match = new RegExp(
    `${name} constant text\\[\\] := ARRAY\\[([\\s\\S]*?)\\];`,
    "u",
  ).exec(auditGuard);
  expect(match, `${name} must remain source-attested`).not.toBeNull();
  const source = match?.[1] ?? "";
  return Array.from(source.matchAll(/'([^']+)'/gu), (item) =>
    item[1]!.toLowerCase(),
  );
}

function auditObjectKeys(): string[] {
  const calls = Array.from(
    migration.matchAll(
      /PERFORM app\.private_tenant_federation_append_audit_v1\(([\s\S]*?)\n {2}\);/gu,
    ),
    (match) => match[1]!,
  );
  expect(calls.length).toBeGreaterThan(0);
  return Array.from(
    new Set(
      calls.flatMap((call) =>
        Array.from(
          call.matchAll(/'([a-z][a-z0-9_]*)'\s*,/gu),
          (match) => match[1]!,
        ),
      ),
    ),
  ).toSorted();
}

describe("tenant SAML administration database contract", () => {
  it("keeps the assurance rule limit unambiguous for PL/pgSQL", () => {
    const replace = functionDefinition(
      "replace_tenant_federated_assurance_policy_v1",
    );

    expect(replace).toContain(
      "jsonb_array_length(p_request -> 'rules') NOT BETWEEN 0 AND\n       (CASE WHEN p_request ->> 'kind' = 'saml' THEN 64 ELSE 128 END) THEN",
    );
  });

  it("keeps every 0228 audit object key within the recursive redaction guard", () => {
    const explicitlySafe = new Set(
      [
        "safe_boolean_keys",
        "safe_identifier_keys",
        "safe_integer_keys",
        "safe_kind_keys",
      ].flatMap(auditGuardArray),
    );
    const prohibited = new Set(auditGuardArray("prohibited_keys"));
    const sensitiveFragments = auditGuardArray("sensitive_fragments");
    const unsafe = auditObjectKeys().filter((key) => {
      const canonical = key.toLowerCase().replaceAll(/[^a-z0-9]/gu, "");
      return (
        !explicitlySafe.has(canonical) &&
        (prohibited.has(canonical) ||
          sensitiveFragments.some((fragment) => canonical.includes(fragment)))
      );
    });
    expect(unsafe).toEqual([]);
  });

  it("keeps all material mutations tenant-authorized, CAS-bound, and redacted", () => {
    const metadata = functionDefinition("replace_tenant_saml_metadata_v1");
    const credential = functionDefinition(
      "replace_tenant_saml_sp_credential_v1",
    );
    const clear = functionDefinition("clear_tenant_saml_sp_credential_v1");

    for (const writer of [metadata, credential, clear]) {
      expect(writer).toContain(
        "context_tenant uuid := app.context_tenant_id()",
      );
      expect(writer).toContain("app.lock_current_tenant_authorization_state()");
      expect(writer).toContain("'identity_provider.manage'");
      expect(writer).toContain("provider.version <> expected_version");
      expect(writer).toContain("binding.id <> target_binding_id");
      expect(writer).toContain(
        "policy.configuration_revision <> configuration.version",
      );
      expect(writer).toContain(
        "app.private_revoke_tenant_federated_provider_sessions_v1",
      );
      expect(writer).toContain("app.private_tenant_federation_append_audit_v1");
      expect(writer).not.toMatch(
        /privateKey|private_key|certificate_der'\s*,/u,
      );
    }
    expect(metadata).toContain("sha256(document) <> document_digest");
    expect(metadata).toContain("maximum_valid_until <= statement_timestamp()");
    expect(metadata).toContain("'metadata_digest_sha256'");
    expect(credential).toContain("IF provider.enabled OR binding.enabled THEN");
    expect(credential).toContain(
      "jsonb_array_length(certificate_values) NOT BETWEEN 1 AND 8",
    );
    expect(credential).toContain("'certificate_digests_sha256'");
    expect(clear).toContain(
      "provider.archived_at IS NOT NULL OR provider.enabled",
    );
    expect(clear).toContain(
      "binding.id <> target_binding_id OR binding.enabled",
    );
  });

  it("publishes only an exact, live, current, certificate-only projection", () => {
    const lookup = functionDefinition("get_tenant_saml_sp_metadata_v1");
    for (const predicate of [
      "tenant.status = 'active'",
      "provider.kind = 'saml'",
      "provider.enabled",
      "provider.archived_at IS NULL",
      "binding.enabled",
      "binding.archived_at IS NULL",
      "policy.enabled",
      "configuration.version = policy.configuration_revision",
      "metadata.revision = configuration.metadata_revision",
      "metadata.maximum_valid_until > statement_timestamp()",
      "sp_key.revision = configuration.sp_key_revision",
      "sp_key.retired_at IS NULL",
      "access_epoch.ended_at IS NULL",
    ]) {
      expect(lookup).toContain(predicate);
    }
    expect(lookup).toContain("'certificateDer'");
    expect(lookup).toContain("ORDER BY certificate.sequence");
    expect(lookup).toContain("RETURN jsonb_build_object('found', false)");
    expect(lookup).not.toMatch(/ciphertext|private[_A-Z]?key/iu);
  });

  it("exposes every SAML ABI only through the API role", () => {
    for (const name of [
      "prepare_tenant_saml_metadata_v1(jsonb)",
      "replace_tenant_saml_metadata_v1(jsonb)",
      "prepare_tenant_saml_sp_credential_v1(jsonb)",
      "replace_tenant_saml_sp_credential_v1(jsonb)",
      "clear_tenant_saml_sp_credential_v1(jsonb)",
      "get_tenant_saml_sp_metadata_v1(jsonb)",
    ]) {
      expect(migration).toContain(`'app.${name}'`);
    }
    expect(migration).toContain(
      "REVOKE ALL ON FUNCTION %s FROM periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION %s TO periapsis_api",
    );
  });

  it("keeps the SAML PostgreSQL proof in the isolated federation runtime gate", () => {
    expect(manifest).toContain(
      '"test:security:tenant-federation-administration": "tsx tests/security/tenant-federation-administration-runtime.ts"',
    );
    expect(workflow).toContain("periapsis_tenant_federation_admin");
    expect(workflow).toContain(
      "PERIAPSIS_TENANT_FEDERATION_ADMIN_TEST_DATABASE_URL:",
    );
    for (const proof of [
      "prepare_tenant_saml_metadata_v1",
      "replace_tenant_saml_metadata_v1",
      "prepare_tenant_saml_sp_credential_v1",
      "replace_tenant_saml_sp_credential_v1",
      "clear_tenant_saml_sp_credential_v1",
      "get_tenant_saml_sp_metadata_v1",
      "rollback tenant SAML expired metadata probe",
    ]) {
      expect(runtime).toContain(proof);
    }
  });
});
