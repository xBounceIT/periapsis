import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectedAlertDFIRRuntimeReadinessV1SourceHash,
  expectedMFAPolicyAdministrationReadinessV4SourceHash,
  expectedMigrations,
  expectedPlatformIdentityRuntimeReadinessV10SourceHash,
  expectedPlatformLocalAccountRuntimeReadinessV1SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV6SourceHash,
  expectedPlatformSAMLDirectRuntimeReadinessV3SourceHash,
  expectedPrivateMFAPolicyAdministrationDependencySurfaceHashV4SourceHash,
  expectedPrivateMFAPolicyAdministrationReadinessV4SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV10SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV10SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV6SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV6SourceHash,
  expectedPrivatePlatformSAMLDirectDependencySurfaceHashV3SourceHash,
  expectedPrivatePlatformSAMLDirectRuntimeReadinessV3SourceHash,
  expectedSchemaCompatibilityV44SourceHash,
  expectedSLATriggerActionRuntimeReadinessV1SourceHash,
  expectedTicketBulkRuntimeReadinessV1SourceHash,
  expectedTicketExportRuntimeReadinessV1SourceHash,
  expectedTicketMutationRuntimeReadinessV1SourceHash,
} from "../src/admin/schema-compatibility-manifest.gen.js";

const packageRoot = resolve(import.meta.dirname, "..");
const runtime = readFileSync(
  resolve(packageRoot, "migrations/0184_platform_saml_direct_runtime.sql"),
  "utf8",
);
const revalidation = readFileSync(
  resolve(
    packageRoot,
    "migrations/0185_platform_saml_direct_compatibility.sql",
  ),
  "utf8",
);
const successor = readFileSync(
  resolve(
    packageRoot,
    "migrations/0186_platform_saml_direct_runtime_successor.sql",
  ),
  "utf8",
);
const compatibility = readFileSync(
  resolve(
    packageRoot,
    "migrations/0187_platform_saml_direct_compatibility.sql",
  ),
  "utf8",
);
const projectionFix = readFileSync(
  resolve(
    packageRoot,
    "migrations/0188_platform_saml_metadata_projection_fix.sql",
  ),
  "utf8",
);
const v43Compatibility = readFileSync(
  resolve(
    packageRoot,
    "migrations/0189_platform_saml_metadata_projection_compatibility.sql",
  ),
  "utf8",
);
const v44Compatibility = readFileSync(
  resolve(packageRoot, "migrations/0196_v44_compatibility.sql"),
  "utf8",
);
const schema = readFileSync(
  resolve(packageRoot, "src/schema/identity-platform-saml-login.ts"),
  "utf8",
);

function functionBodyFrom(source: string, name: string): string {
  const declaration = new RegExp(
    `^CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\(`,
    "mu",
  ).exec(source);
  if (declaration?.index === undefined) {
    throw new Error(`Missing function ${name}`);
  }
  const tail = source.slice(declaration.index);
  const start = /AS \$([A-Za-z0-9_]*)\$/u.exec(tail);
  if (start?.index === undefined) {
    throw new Error(`Missing function body ${name}`);
  }
  const marker = `$${start[1]}$;`;
  const bodyStart = start.index + start[0].length;
  const bodyEnd = tail.indexOf(marker, bodyStart);
  if (bodyEnd < 0) {
    throw new Error(`Unterminated function body ${name}`);
  }
  return tail.slice(bodyStart, bodyEnd);
}

describe("direct platform SAML database contract", () => {
  it("keeps SAML runtime state physically separate from OIDC state", () => {
    for (const table of [
      "platform_saml_authentication_transactions",
      "platform_saml_post_primary_continuations",
      "platform_saml_post_primary_totp_challenges",
      "platform_saml_session_materials",
      "platform_saml_session_revalidation_commands",
      "auth_session_platform_saml_states",
      "auth_session_platform_saml_provenance",
      "auth_session_platform_saml_evidence",
      "platform_saml_tenant_switch_commands",
    ]) {
      expect(`${runtime}\n${successor}`).toContain(table);
      expect(schema).toContain(`"${table}"`);
    }
    const applySwitch = functionBodyFrom(
      successor,
      "apply_platform_saml_tenant_switch_v1",
    );
    expect(applySwitch).toContain("auth_session_platform_saml_states");
    expect(applySwitch).toContain("p_command->>'authenticationMethod'<>'saml'");
    expect(applySwitch).not.toContain("auth_session_platform_oidc_states");
    expect(applySwitch).not.toContain("platform_oidc_tenant_switch_commands");
  });

  it("closes every successor ABI ACL in the migration that creates it", () => {
    for (const name of [
      "private_platform_saml_tenant_switch_assurance_v1",
      "lookup_platform_saml_tenant_switch_replay_v1",
      "apply_platform_saml_tenant_switch_v1",
      "load_platform_saml_tenant_switch_revalidation_v1",
      "load_platform_saml_tenant_switch_v1",
      "private_platform_saml_totp_completion_fence_v1",
      "cleanup_platform_saml_post_primary_totp_apply_v1",
      "begin_platform_post_primary_totp_v2",
    ]) {
      expect(successor).toContain(`'${name}'`);
    }
    expect(successor).toContain(
      "REVOKE ALL PRIVILEGES ON TABLE public.platform_saml_tenant_switch_commands",
    );
    expect(successor).toContain(
      "REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC",
    );
  });

  it("supports restart after a lost OIDC or SAML TOTP browser ceremony", () => {
    expect(successor).toContain(
      "platform_post_primary_totp_challenges_live_continuation_key",
    );
    expect(successor).toContain(
      `"platform_post_primary_totp_challenges"."state" = 'pending'`,
    );
    const oidcBegin = functionBodyFrom(
      successor,
      "begin_platform_post_primary_totp_v2",
    );
    expect(oidcBegin).toMatch(/SET state\s*=\s*'abandoned'/u);
    const samlBegin = functionBodyFrom(
      runtime,
      "begin_platform_saml_post_primary_totp_v1",
    );
    expect(samlBegin).toMatch(/SET state\s*=\s*'abandoned'/u);
  });

  it("keeps encrypted SAML session material fenced during TOTP completion", () => {
    const completionFence = functionBodyFrom(
      successor,
      "private_platform_saml_totp_completion_fence_v1",
    );
    expect(completionFence).toContain("platform_saml_session_materials");
    expect(completionFence).toContain("UPDATE ONLY public.auth_sessions");
    expect(runtime).toContain('"ciphertext" "bytea" NOT NULL');
    expect(runtime).toContain('"nonce" "bytea" NOT NULL');
    expect(runtime).not.toMatch(/private[_ ]key\s+(?:text|bytea)/iu);
  });

  it("exposes admin material writers without returning raw private material", () => {
    for (const name of [
      "load_platform_saml_metadata_admin_v1",
      "replace_platform_saml_metadata_v1",
      "replace_platform_saml_sp_key_v1",
      "clear_platform_saml_sp_key_v1",
    ]) {
      expect(runtime).toContain(`FUNCTION app.${name}`);
    }
    const replaceKey = functionBodyFrom(
      runtime,
      "replace_platform_saml_sp_key_v1",
    );
    expect(replaceKey).toContain("sp_key_revision");
    expect(replaceKey).toContain("platform_login_enabled=false");
    expect(replaceKey).not.toContain("'ciphertext',");
  });

  it("repairs the sealed v42 metadata and PL/pgSQL defects append-only", () => {
    expect(projectionFix).toContain(
      "CREATE OR REPLACE FUNCTION app.load_platform_saml_metadata_projection_v1",
    );
    expect(projectionFix).toContain(
      "c4562f984383ee7ad2116b4a66c1ec5401b8a19ccd79bc63264c184e81608c4a",
    );
    expect(projectionFix).toContain(
      "direct platform SAML metadata predecessor drifted",
    );
    expect(projectionFix).toContain("selected_provider_id uuid");
    expect(projectionFix).toContain("provider.id=selected_provider_id");
    expect(projectionFix).toContain("#variable_conflict use_variable");
    expect(projectionFix).toContain("last_observed_at=transaction_timestamp()");
    expect(projectionFix).toContain(
      "REVOKE ALL PRIVILEGES ON FUNCTION\n  app.load_platform_saml_metadata_projection_v1(text)",
    );
    expect(projectionFix).toContain("source_hash<>object_record.source_hash");
    expect(projectionFix).toContain(
      "007e4feec0a6caf9995c5a6e0621eeb6566ae875fbfc604725c3f57c28fc9113",
    );
  });

  it("retains the fail-closed v42 to v44 evidence after the v48 cutover", () => {
    expect(expectedMigrations[218]).toMatchObject({
      tag: "0218_v48_compatibility",
      createdAt: 1_788_276_517_454,
    });
    expect(compatibility).toContain("FUNCTION app.schema_compatibility_v42()");
    expect(v43Compatibility).toContain(
      "FUNCTION app.schema_compatibility_v43()",
    );
    expect(v44Compatibility).toContain(
      "FUNCTION app.schema_compatibility_v44()",
    );
    expect(v44Compatibility).toContain(
      "FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()",
    );
    for (const predecessor of [
      "schema_compatibility_v43",
      "platform_identity_runtime_schema_readiness_v9",
      "platform_oidc_direct_runtime_schema_readiness_v5",
      "platform_saml_direct_runtime_schema_readiness_v2",
      "mfa_policy_administration_schema_readiness_v3",
    ]) {
      expect(v44Compatibility).toContain(
        `REVOKE ALL ON FUNCTION app.${predecessor}()`,
      );
    }
    expect(revalidation).toContain(
      "recover_platform_saml_session_revalidation_apply_v1",
    );
    for (const hash of [
      expectedSchemaCompatibilityV44SourceHash,
      expectedPrivatePlatformIdentityDependencySurfaceHashV10SourceHash,
      expectedPrivatePlatformIdentityRuntimeReadinessV10SourceHash,
      expectedPlatformIdentityRuntimeReadinessV10SourceHash,
      expectedPrivatePlatformOIDCDirectDependencySurfaceHashV6SourceHash,
      expectedPrivatePlatformOIDCDirectRuntimeReadinessV6SourceHash,
      expectedPlatformOIDCDirectRuntimeReadinessV6SourceHash,
      expectedPrivatePlatformSAMLDirectDependencySurfaceHashV3SourceHash,
      expectedPrivatePlatformSAMLDirectRuntimeReadinessV3SourceHash,
      expectedPlatformSAMLDirectRuntimeReadinessV3SourceHash,
      expectedPrivateMFAPolicyAdministrationDependencySurfaceHashV4SourceHash,
      expectedPrivateMFAPolicyAdministrationReadinessV4SourceHash,
      expectedMFAPolicyAdministrationReadinessV4SourceHash,
      expectedTicketMutationRuntimeReadinessV1SourceHash,
      expectedSLATriggerActionRuntimeReadinessV1SourceHash,
      expectedPlatformLocalAccountRuntimeReadinessV1SourceHash,
      expectedTicketBulkRuntimeReadinessV1SourceHash,
      expectedTicketExportRuntimeReadinessV1SourceHash,
      expectedAlertDFIRRuntimeReadinessV1SourceHash,
    ]) {
      expect(hash).toMatch(/^[0-9a-f]{64}$/u);
    }
  });
});
