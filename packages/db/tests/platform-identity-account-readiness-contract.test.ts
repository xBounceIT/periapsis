import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectedMigrations,
  expectedPlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPlatformIdentityRuntimeReadinessV5SourceHash,
  expectedPlatformIdentityRuntimeReadinessV4SourceHash,
  expectedPlatformIdentityRuntimeReadinessV3SourceHash,
  expectedPlatformIdentityRuntimeReadinessV2SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV1SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV5SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV3SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV2SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV5SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV3SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV2SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV1SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV1SourceHash,
  expectedRetiredSchemaCompatibilityV39SourceHash,
  expectedRetiredSchemaCompatibilityV38SourceHash,
  expectedRetiredSchemaCompatibilityV37SourceHash,
  expectedRetiredSchemaCompatibilityV36SourceHash,
  expectedRetiredSchemaCompatibilityV35SourceHash,
  expectedSchemaCompatibilityV39SourceHash,
  expectedSchemaCompatibilityV40SourceHash,
  expectedSchemaCompatibilityV38SourceHash,
  expectedSchemaCompatibilityV37SourceHash,
  expectedSchemaCompatibilityV36SourceHash,
} from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const predecessorReadiness = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0169_platform_identity_account_compatibility.sql",
  ),
  "utf8",
);
const representationReadiness = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0173_platform_identity_account_representation_compatibility.sql",
  ),
  "utf8",
);
const readiness = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0176_platform_identity_account_observation_compatibility.sql",
  ),
  "utf8",
);
const directReadiness = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0179_platform_oidc_direct_compatibility.sql",
  ),
  "utf8",
);
const directAdministrationReadiness = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0181_platform_oidc_direct_administration_compatibility.sql",
  ),
  "utf8",
);
const generator = readFileSync(
  resolve(repositoryRoot, "scripts/generate-schema-compatibility.mjs"),
  "utf8",
);
const apiHealth = readFileSync(
  resolve(repositoryRoot, "services/api/internal/postgres/health.go"),
  "utf8",
);
const workerHealth = readFileSync(
  resolve(repositoryRoot, "services/worker/internal/postgres/health.go"),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const start = source.indexOf(`FUNCTION app.${name}()`);
  const bodyStart = source.indexOf("AS $function$", start);
  const end = source.indexOf("$function$;", bodyStart);
  expect(start, name).toBeGreaterThanOrEqual(0);
  expect(bodyStart, name).toBeGreaterThan(start);
  expect(end, name).toBeGreaterThan(bodyStart);
  return source.slice(bodyStart, end);
}

describe("platform identity-account v36 compatibility predecessor", () => {
  it("retires v35 and freezes the v36 compatibility root", () => {
    expect(predecessorReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v35()\n  SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(predecessorReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v35()",
    );
    expect(predecessorReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()",
    );
    expect(predecessorReadiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v36()",
    );
    expect(predecessorReadiness).toContain("journal_count = 170");
    expect(predecessorReadiness).toContain(
      "journal_latest_created_at = 1788062677386",
    );
    expect(predecessorReadiness).toContain("(:[0-9]+@[0-9a-f]{64}){169}$");
    expect(expectedSchemaCompatibilityV36SourceHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(expectedRetiredSchemaCompatibilityV35SourceHash).toBe(
      "93f361ab0c2c6e8b9c946995c99ae9927d8681dee0f1a3caa781ea4239fea6d4",
    );
  });

  it("derives the canonical transcript only from the frozen v35 helper", () => {
    expect(predecessorReadiness).toContain(
      "'7ef3708e7225a7b643f114a26f96812fb2b1e0e187e467b9fed82350c0096d0f'",
    );
    for (const name of [
      "private_platform_identity_dependency_surface_hash_v2",
      "private_platform_identity_runtime_schema_readiness_v2",
      "platform_identity_runtime_schema_readiness_v2",
      "schema_compatibility_v36",
    ]) {
      expect(predecessorReadiness).toContain(name);
      expect(generator).toContain(name);
    }
    expect(predecessorReadiness).toContain(
      "'dbe197debc5813ff66b9d7ad38c1cf273537f587d9d2612dea829e0709c3dfa9'",
    );
    expect(
      expectedPrivatePlatformIdentityDependencySurfaceHashV2SourceHash,
    ).toBe("6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852");
    expect(generator).toContain("sourceTransforms");
    expect(generator).toContain("source.replaceAll(from, to)");
  });

  it("pins the account relation, cursor, ACL and provider-specific ABI", () => {
    const privateReadiness = functionBody(
      predecessorReadiness,
      "private_platform_identity_runtime_schema_readiness_v2",
    );
    for (const invariant of [
      "platform_identity_account_commands",
      "relation_row.relrowsecurity AND relation_row.relforcerowsecurity",
      "count(*) = 10",
      "count(*) = 20",
      "count(*) = 4",
      "count(*) = 11",
      "platform_federated_external_identities_live_provider_cursor_idx",
      "app.create_platform_oidc_auth_provider_v2(",
      "app.create_platform_saml_auth_provider_v2(",
      "app.list_platform_identity_accounts_v1(",
      "app.get_platform_identity_account_v1(",
      "app.prelink_platform_identity_account_v1(",
      "app.retire_platform_identity_account_v1(",
      "app.create_platform_auth_provider_v1(",
      "ARRAY['periapsis_api','periapsis_migrator']::text[]",
      "ARRAY['periapsis_migrator']::text[]",
    ]) {
      expect(privateReadiness).toContain(invariant);
    }
    expect(privateReadiness).toContain("'MAINTAIN'");
    expect(privateReadiness).toContain("matched_alias_count <> alias_count");
    expect(privateReadiness).toContain("affected_families");
    expect(privateReadiness).toContain(
      "session_invalidation_epoch = subject.session_invalidation_epoch + 1",
    );
    expect(privateReadiness).toContain(
      "identity_epoch = subject.identity_epoch + 1",
    );
  });

  it("keeps forward repairs and live data invariants inside readiness", () => {
    const privateReadiness = functionBody(
      predecessorReadiness,
      "private_platform_identity_runtime_schema_readiness_v2",
    );
    for (const invariant of [
      "policy.platform_login_enabled",
      "binding.current_access_epoch_id",
      "source.retired_at IS DISTINCT FROM epoch.ended_at",
      "alias.key_version = identity.key_version",
      "jsonb_strip_nulls(jsonb_build_object(",
      "IF FOUND AND v_primary_credential_id = v_credential_id THEN",
      "private_append_platform_identity_account_tenant_audit_v1(",
      "platform.identity_account.retired",
    ]) {
      expect(privateReadiness).toContain(invariant);
    }
    expect(privateReadiness).not.toContain("V36_DEPENDENCY_SURFACE_HASH");
  });

  it("keeps the generated predecessor source attestations", () => {
    expect(expectedPrivatePlatformIdentityRuntimeReadinessV2SourceHash).toMatch(
      /^[0-9a-f]{64}$/u,
    );
    expect(expectedPlatformIdentityRuntimeReadinessV2SourceHash).toMatch(
      /^[0-9a-f]{64}$/u,
    );
  });
});

describe("platform identity-account v37 representation checkpoint", () => {
  it("seals the self-including 174-entry transcript and retires v36", () => {
    expect(representationReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v36()\n  SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(representationReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v36()",
    );
    expect(representationReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v2()",
    );
    expect(representationReadiness).toContain(
      "'journal_count = 170','journal_count = 174'",
    );
    expect(representationReadiness).toContain(
      "'1788062677386','1788067083196'",
    );
    expect(representationReadiness).toContain(
      "p_expected_migration_fingerprint !~\n       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){173}$'",
    );
    expect(representationReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v37() SET app.schema_compatibility_fingerprint = %L",
    );
    expect(representationReadiness).toContain(
      "OR NOT app.private_platform_identity_runtime_schema_readiness_v3()",
    );
    expect(representationReadiness).toContain(
      "OR NOT app.platform_identity_runtime_schema_readiness_v3()",
    );
    expect(expectedSchemaCompatibilityV37SourceHash).toBe(
      "cbfac359101b7b16f12c96cbb19a6697a47f48cf1f63b342ed9d1c503265bae5",
    );
    expect(expectedRetiredSchemaCompatibilityV36SourceHash).toBe(
      "565cd14cde70a795cb2e4a118eed68a1585c3496255edfaea08788e42e135989",
    );
  });

  it("attests both representation counters, their local guards, and retire v2", () => {
    for (const invariant of [
      "('public.users'::regclass,'version'::name)",
      "'resource_version'::name",
      "platform_federated_external_identities_guard_v3",
      "users_platform_identity_projection_insert_guard_v1",
      "users_platform_identity_projection_update_guard_v1",
      "''version'', identity.resource_version",
      "''version'', local_user.version",
      "identity_record.resource_version <> p_expected_version",
      "user_record.version <> p_expected_user_version",
      "SELECT count(*) = 14",
      "979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473",
    ]) {
      expect(representationReadiness).toContain(invariant);
    }
    expect(
      expectedPrivatePlatformIdentityDependencySurfaceHashV3SourceHash,
    ).toBe("3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04");
    expect(expectedPrivatePlatformIdentityRuntimeReadinessV3SourceHash).toBe(
      "06e01a9db32d73fa077a05b4729fb8e75178d0b2f0933e0cbdd4be4102356a4b",
    );
    expect(expectedPlatformIdentityRuntimeReadinessV3SourceHash).toBe(
      "b5a2b9da53785a7daeff1f6c0c35cc5e376d934f149ca35f8bdff27b6fd8e36a",
    );
    for (const name of [
      "SchemaCompatibilityV37",
      "PrivatePlatformIdentityDependencySurfaceHashV3",
      "PrivatePlatformIdentityRuntimeReadinessV3",
      "PlatformIdentityRuntimeReadinessV3",
    ]) {
      expect(generator).toContain(name);
    }
  });
});

describe("platform identity-account v38 observation checkpoint", () => {
  it("seals the self-including 177-entry transcript and retires v37", () => {
    expect(readiness).toContain("journal_count = 177");
    expect(readiness).toContain("1788069336676");
    expect(readiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v37()\n  SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(readiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v37()",
    );
    expect(readiness).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v3()",
    );
    expect(readiness).toContain(
      "derived_definition,'journal_count = 174','journal_count = 177'",
    );
    expect(readiness).toContain(
      "derived_definition,'1788067083196','1788069336676'",
    );
    expect(readiness).toContain(
      "'^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){176}$'",
    );
    expect(readiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v38() SET app.schema_compatibility_fingerprint = %L",
    );
    expect(readiness).toContain(
      "OR NOT app.private_platform_identity_runtime_schema_readiness_v4()",
    );
    expect(readiness).toContain(
      "OR NOT app.platform_identity_runtime_schema_readiness_v4()",
    );
    expect(expectedSchemaCompatibilityV38SourceHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(expectedRetiredSchemaCompatibilityV37SourceHash).toBe(
      expectedSchemaCompatibilityV37SourceHash,
    );
  });

  it("attests observation provenance, replacement ABI, and retired ABI ACL", () => {
    for (const invariant of [
      "last_observation_state",
      "platform_federated_external_identities_observation_state_check",
      "identity.resource_version = 1",
      "identity.last_observation_state <> 'legacy_unknown'",
      "''lastObservationState'', identity.last_observation_state",
      "WHEN identity.last_observation_state = ''known''",
      "NEW.last_observation_state <> ''known''",
      "NEW.last_observation_state := OLD.last_observation_state",
      "app.list_platform_identity_accounts_v2(",
      "app.get_platform_identity_account_v2(",
      "app.prelink_platform_identity_account_v2(",
      "app.retire_platform_identity_account_v3(",
      "app.list_platform_identity_accounts_v1(",
      "app.get_platform_identity_account_v1(",
      "app.prelink_platform_identity_account_v1(",
      "app.retire_platform_identity_account_v2(",
      "SELECT count(*) = 20",
    ]) {
      expect(readiness).toContain(invariant);
    }
    expect(readiness).toContain(
      "'periapsis_api','app.schema_compatibility_v37()'::regprocedure,'EXECUTE'",
    );
    expect(readiness).toContain(
      "'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure",
    );
    expect(
      expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
    ).toMatch(/^[0-9a-f]{64}$/u);
    expect(expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash).toMatch(
      /^[0-9a-f]{64}$/u,
    );
    expect(expectedPlatformIdentityRuntimeReadinessV4SourceHash).toMatch(
      /^[0-9a-f]{64}$/u,
    );
    for (const name of [
      "SchemaCompatibilityV38",
      "RetiredSchemaCompatibilityV37",
      "PrivatePlatformIdentityDependencySurfaceHashV4",
      "PrivatePlatformIdentityRuntimeReadinessV4",
      "PlatformIdentityRuntimeReadinessV4",
    ]) {
      expect(generator).toContain(name);
    }
  });

  it("is retained as predecessor evidence after the v58 cutover", () => {
    for (const health of [apiHealth, workerHealth]) {
      expect(health).toContain("from app.schema_compatibility_v58()");
      expect(health).toContain(
        "app.private_release_runtime_schema_readiness_v58()",
      );
      expect(health).toContain("app.release_runtime_schema_readiness_v58()");
      expect(health).toContain(
        "(2, 'retired', 'app.schema_compatibility_v49()'",
      );
      expect(health).toContain(
        "'retired_v51', 'app.schema_compatibility_v51()'",
      );
      expect(health).not.toContain("from app.schema_compatibility_v51()");
      expect(health).not.toContain("from app.schema_compatibility_v49()");
      expect(health).not.toContain("from app.schema_compatibility_v48()");
      expect(health).not.toContain(
        "app.platform_identity_runtime_schema_readiness_v13()",
      );
    }
  });
});

describe("platform direct OIDC v39 compatibility checkpoint", () => {
  it("preserves the immutable 180-entry predecessor evidence", () => {
    expect(directReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v38()\n  SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(directReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v38()",
    );
    expect(directReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v4()",
    );
    expect(directReadiness).toContain(
      "derived_definition,'journal_count = 177','journal_count = 180'",
    );
    expect(directReadiness).toContain(
      "derived_definition,'1788069336676','1788077000000'",
    );
    expect(directReadiness).toContain(
      "'^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){179}$'",
    );
    expect(directReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v39() SET app.schema_compatibility_fingerprint = %L",
    );
    expect(directReadiness).toContain(
      "OR NOT app.private_platform_identity_runtime_schema_readiness_v5()",
    );
    expect(directReadiness).toContain(
      "OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v1()",
    );
    expect(directReadiness).toContain(
      "OR NOT app.platform_oidc_direct_runtime_schema_readiness_v1()",
    );
    expect(expectedSchemaCompatibilityV39SourceHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(expectedRetiredSchemaCompatibilityV38SourceHash).toBe(
      expectedSchemaCompatibilityV38SourceHash,
    );
  });

  it("publishes and attests both identity-v5 and direct-v1 readiness roots", () => {
    for (const sourceHash of [
      expectedPrivatePlatformIdentityDependencySurfaceHashV5SourceHash,
      expectedPrivatePlatformIdentityRuntimeReadinessV5SourceHash,
      expectedPlatformIdentityRuntimeReadinessV5SourceHash,
      expectedPrivatePlatformOIDCDirectDependencySurfaceHashV1SourceHash,
      expectedPrivatePlatformOIDCDirectRuntimeReadinessV1SourceHash,
      expectedPlatformOIDCDirectRuntimeReadinessV1SourceHash,
    ]) {
      expect(sourceHash).toMatch(/^[0-9a-f]{64}$/u);
    }
    for (const trustedRoot of [
      "PrivatePlatformIdentityDependencySurfaceHashV5",
      "PrivatePlatformIdentityRuntimeReadinessV5",
      "PlatformIdentityRuntimeReadinessV5",
      "PrivatePlatformOIDCDirectDependencySurfaceHashV1",
      "PrivatePlatformOIDCDirectRuntimeReadinessV1",
      "PlatformOIDCDirectRuntimeReadinessV1",
    ]) {
      expect(generator).toContain(`constant: "${trustedRoot}"`);
    }
  });
});

describe("platform direct OIDC v40 compatibility checkpoint", () => {
  it("keeps the v40 seal as predecessor evidence under the v48 manifest", () => {
    expect(expectedMigrations[218]).toMatchObject({
      tag: "0218_v48_compatibility",
      createdAt: 1_788_276_517_454,
    });
    expect(directAdministrationReadiness).toContain(
      "derived_definition,'journal_count = 180','journal_count = 182'",
    );
    expect(directAdministrationReadiness).toContain(
      "derived_definition,'1788077000000','1788085744122'",
    );
    expect(directAdministrationReadiness).toContain(
      "'^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){181}$'",
    );
    expect(directAdministrationReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v39()\n      SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(directAdministrationReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v39()",
    );
    expect(directAdministrationReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()",
    );
    expect(expectedSchemaCompatibilityV40SourceHash).toMatch(/^[0-9a-f]{64}$/u);
    expect(expectedRetiredSchemaCompatibilityV39SourceHash).toBe(
      expectedSchemaCompatibilityV39SourceHash,
    );
  });

  it("preserves identity-v6 and direct-v2 predecessor attestations", () => {
    for (const sourceHash of [
      expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
      expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
      expectedPlatformIdentityRuntimeReadinessV6SourceHash,
      expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
      expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
      expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
    ]) {
      expect(sourceHash).toMatch(/^[0-9a-f]{64}$/u);
    }
    for (const trustedRoot of [
      "PrivatePlatformIdentityDependencySurfaceHashV6",
      "PrivatePlatformIdentityRuntimeReadinessV6",
      "PlatformIdentityRuntimeReadinessV6",
      "PrivatePlatformOIDCDirectDependencySurfaceHashV2",
      "PrivatePlatformOIDCDirectRuntimeReadinessV2",
      "PlatformOIDCDirectRuntimeReadinessV2",
    ]) {
      expect(generator).toContain(`constant: "${trustedRoot}"`);
    }
  });
});
