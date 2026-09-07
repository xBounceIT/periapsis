import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");
const schema = readFileSync(
  resolve(packageRoot, "src/schema/identity-platform-federation.ts"),
  "utf8",
);
const tenantLifecycleSecurity = migration(
  "0152_platform_tenant_lifecycle_readiness.sql",
);
const generatorSource = readFileSync(
  resolve(packageRoot, "../../scripts/generate-schema-compatibility.mjs"),
  "utf8",
);
const apiHealthSource = readFileSync(
  resolve(packageRoot, "../../services/api/internal/postgres/health.go"),
  "utf8",
);
const workerHealthSource = readFileSync(
  resolve(packageRoot, "../../services/worker/internal/postgres/health.go"),
  "utf8",
);
const querySource = readFileSync(
  resolve(
    packageRoot,
    "../../services/api/internal/postgres/queries/platform_identity_providers.sql",
  ),
  "utf8",
);

const structural = [
  migration("0155_jazzy_felicia_hardy.sql"),
  migration("0156_panoramic_blackheart.sql"),
].join("\n");
const security = migration("0157_platform_identity_provider_security.sql");
const compatibility = migration(
  "0158_platform_identity_provider_compatibility.sql",
);
const currentCompatibility = migration(
  "0162_tenant_platform_identity_binding_compatibility.sql",
);

const protectedTables = [
  "platform_auth_providers",
  "platform_federated_provider_policies",
  "platform_federated_trust_rules",
  "platform_identity_provider_commands",
  "platform_identity_provider_test_runs",
  "platform_oidc_claim_rules",
  "platform_oidc_client_secrets",
  "platform_oidc_discovery_snapshots",
  "platform_oidc_jwks_snapshots",
  "platform_oidc_provider_configurations",
  "platform_saml_attribute_rules",
  "platform_saml_metadata_snapshots",
  "platform_saml_provider_configurations",
  "platform_saml_sp_certificates",
  "platform_saml_sp_keys",
] as const;

const functionBody = (name: string, nextName: string): string => {
  const start = security.indexOf(`CREATE FUNCTION app.${name}`);
  const nextFunction = security.indexOf(
    `CREATE FUNCTION app.${nextName}`,
    start + 1,
  );
  const end =
    nextFunction >= 0
      ? nextFunction
      : security.indexOf("\n--> statement-breakpoint", start + 1);
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return security.slice(start, end);
};

describe("platform identity-provider database contract", () => {
  it("keeps the platform provider family physically separate and deny-by-default", () => {
    expect(schema).not.toContain('"tenant_id"');
    for (const table of protectedTables) {
      expect(structural).toContain(`CREATE TABLE "${table}"`);
      expect(structural).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(`public.${table}`);
    }
    expect(security).toContain(
      "FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor",
    );
  });

  it("publishes the identity permission families only to platform super-admin", () => {
    expect(security).toContain("role.key = 'platform_super_admin'");
    for (const family of [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
      "platform.identity_provider.test",
      "platform.identity_binding.read",
      "platform.identity_binding.manage",
      "platform.identity_policy.read",
      "platform.identity_policy.manage",
      "platform.identity_account.read",
      "platform.identity_account.manage",
    ]) {
      expect(security).toContain(`'${family}'`);
      expect(compatibility).toContain(`'${family}'`);
    }
    expect(compatibility).toContain(
      "WITH expected_permission(permission_key) AS",
    );
    expect(compatibility).toContain(
      "WITH expected_grant(role_key, permission_key) AS",
    );
    expect(compatibility).toContain(
      "('platform_super_admin', 'platform.identity_provider.manage')",
    );
    expect(compatibility).toContain("actual_grant(role_key, permission_key)");
    expect(compatibility).toContain(
      "permission.key LIKE 'platform.identity\\_%' ESCAPE '\\'",
    );
  });

  it("pins every trusted identity function to a public-free search path", () => {
    for (const source of [tenantLifecycleSecurity, security, compatibility]) {
      expect(source).not.toContain("search_path = pg_catalog, public");
      expect(source).not.toContain("search_path=pg_catalog, public");
    }
    expect(
      tenantLifecycleSecurity.match(/SET search_path = pg_catalog, app/g),
    ).toHaveLength(2);
    expect(security.match(/SET search_path = pg_catalog, app/g)).toHaveLength(
      11,
    );
    expect(compatibility).toContain(
      "CREATE FUNCTION app.platform_identity_provider_schema_readiness_v1()",
    );
    expect(compatibility).toContain("SET search_path = pg_catalog, app");
    expect(compatibility).toContain(
      "ARRAY['search_path=pg_catalog, app']::text[]",
    );
    for (const healthSource of [apiHealthSource, workerHealthSource]) {
      expect(healthSource).toContain(
        "array['search_path=pg_catalog, public, app']::text[]",
      );
      expect(healthSource).toMatch(
        /pg_catalog\.encode\(\s*pg_catalog\.sha256\(pg_catalog\.convert_to\(function\.prosrc, 'UTF8'\)\),\s*'hex'\s*\)/u,
      );
      for (const currentRoot of [
        "app.schema_compatibility_v53()",
        "app.schema_compatibility_v51()",
        "app.schema_compatibility_v50()",
        "app.schema_compatibility_v49()",
        "app.private_v47_migration_convergence_schema_readiness_v1()",
        "app.private_schema_compatibility_journal_v53()",
        "app.private_release_runtime_dependency_surface_hash_v53()",
        "app.private_release_runtime_schema_readiness_v53()",
        "app.release_runtime_schema_readiness_v53()",
        "app.private_rotate_sla_readiness_v48()",
      ]) {
        expect(healthSource).toContain(currentRoot);
      }
      for (const currentSourceHash of [
        "expectedSchemaCompatibilityV53SourceHash",
        "expectedRetiredSchemaCompatibilityV51SourceHash",
        "expectedRetiredSchemaCompatibilityV50SourceHash",
        "expectedRetiredSchemaCompatibilityV49SourceHash",
        "expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash",
        "expectedPrivateSchemaCompatibilityJournalV53SourceHash",
        "expectedPrivateReleaseRuntimeDependencySurfaceHashV53SourceHash",
        "expectedPrivateReleaseRuntimeReadinessV53SourceHash",
        "expectedReleaseRuntimeReadinessV53SourceHash",
        "expectedPrivateRotateSLAReadinessV48SourceHash",
      ]) {
        expect(healthSource).toContain(currentSourceHash);
      }
      expect(healthSource).not.toContain(
        "platformIdentityProviderSourceHash.String == expectedPlatformIdentityProviderReadinessSourceHash",
      );
    }
    for (const trustedSource of [
      "SchemaCompatibilityV34",
      "SchemaCompatibilityV33",
      "PlatformTenantLifecycleReadiness",
      "PlatformIdentityProviderReadiness",
      "TenantPlatformIdentityBindingSurfaceHash",
      "TenantPlatformIdentityBindingReadinessV1",
      "TenantPlatformIdentityBindingReadinessV2",
      "SchemaCompatibilityV41",
      "RetiredSchemaCompatibilityV40",
      "PrivatePlatformIdentityDependencySurfaceHashV7",
      "PrivatePlatformIdentityRuntimeReadinessV7",
      "PlatformIdentityRuntimeReadinessV7",
      "PrivatePlatformOIDCDirectDependencySurfaceHashV3",
      "PrivatePlatformOIDCDirectRuntimeReadinessV3",
      "PlatformOIDCDirectRuntimeReadinessV3",
      "PrivateMFAPolicyAdministrationDependencySurfaceHashV1",
      "PrivateMFAPolicyAdministrationReadinessV1",
      "MFAPolicyAdministrationReadinessV1",
      "SchemaCompatibilityV40",
      "RetiredSchemaCompatibilityV39",
      "PrivatePlatformIdentityDependencySurfaceHashV6",
      "PrivatePlatformIdentityRuntimeReadinessV6",
      "PlatformIdentityRuntimeReadinessV6",
      "PrivatePlatformOIDCDirectDependencySurfaceHashV2",
      "PrivatePlatformOIDCDirectRuntimeReadinessV2",
      "PlatformOIDCDirectRuntimeReadinessV2",
      "SchemaCompatibilityV39",
      "RetiredSchemaCompatibilityV38",
      "PrivatePlatformIdentityDependencySurfaceHashV5",
      "PrivatePlatformIdentityRuntimeReadinessV5",
      "PlatformIdentityRuntimeReadinessV5",
      "PrivatePlatformOIDCDirectDependencySurfaceHashV1",
      "PrivatePlatformOIDCDirectRuntimeReadinessV1",
      "PlatformOIDCDirectRuntimeReadinessV1",
      "SchemaCompatibilityV38",
      "RetiredSchemaCompatibilityV37",
      "PrivatePlatformIdentityDependencySurfaceHashV4",
      "PrivatePlatformIdentityRuntimeReadinessV4",
      "PlatformIdentityRuntimeReadinessV4",
    ]) {
      expect(generatorSource).toContain(`constant: "${trustedSource}"`);
    }
    expect(generatorSource).toContain(
      'name: "platform_identity_provider_schema_readiness_v1"',
    );
  });

  it("exposes only permission-checked SECURITY DEFINER administration functions", () => {
    for (const name of [
      "list_platform_auth_providers_v1",
      "get_platform_auth_provider_v1",
      "create_platform_auth_provider_v1",
      "update_platform_auth_provider_v1",
      "archive_platform_auth_provider_v1",
      "replace_platform_oidc_client_secret_v1",
    ]) {
      expect(security).toContain(`CREATE FUNCTION app.${name}`);
    }
    expect(security.match(/SECURITY DEFINER/g)?.length).toBeGreaterThanOrEqual(
      7,
    );
    expect(security).toContain(
      "private_require_platform_identity_permission_v1",
    );
    expect(security).toContain("TO periapsis_api;");
    expect(security).not.toContain("TO periapsis_worker;");
    expect(compatibility).toContain("protected_function_count = 6");
    expect(compatibility).toContain("private_function_count = 1");
    expect(compatibility).toContain("protected_acl_mismatch_count = 0");
    expect(compatibility).toContain("private_acl_mismatch_count = 0");
  });

  it("holds the active-tenant authorization fence through provider operations", () => {
    const authorize = functionBody(
      "private_require_platform_identity_permission_v1",
      "list_platform_auth_providers_v1",
    );
    const stateLock = authorize.indexOf(
      "FROM public.tenant_authorization_states AS authorization_state",
    );
    const tenantLock = authorize.indexOf("FROM public.tenants AS tenant");
    const membershipLock = authorize.indexOf(
      "FROM public.tenant_memberships AS membership",
    );
    expect(authorize).not.toContain("app.session_tenant_allowed(");
    expect(stateLock).toBeGreaterThan(-1);
    expect(tenantLock).toBeGreaterThan(stateLock);
    expect(membershipLock).toBeGreaterThan(tenantLock);
    expect(authorize).toContain(
      "authorization_state.tenant_id = session_tenant_id",
    );
    expect(authorize).toContain("tenant.status = 'active'");
    expect(authorize).toContain("membership.status = 'active'");
    expect(authorize.match(/FOR SHARE;/g)).toHaveLength(3);
    expect(compatibility).toContain(
      "permission_function_definition NOT LIKE '%tenant_authorization_states%'",
    );
  });

  it("creates exactly one OIDC or SAML subtype and records replay conflicts", () => {
    const create = functionBody(
      "create_platform_auth_provider_v1",
      "update_platform_auth_provider_v1",
    );
    expect(create).toContain("p_kind NOT IN ('oidc', 'saml')");
    expect(create).toContain("operation_name := 'provider.create'");
    expect(schema).toContain("sql`${table.operation} = 'provider.create'`");
    expect(create).toContain(
      "IF replay_record.request_digest <> p_request_digest",
    );
    expect(create).toContain("USING ERRCODE = '23505'");
    expect(create).toContain(
      "RETURN QUERY SELECT replay_record.result_provider_id",
    );
    expect(create).toContain(
      "INSERT INTO public.platform_oidc_provider_configurations",
    );
    expect(create).toContain(
      "INSERT INTO public.platform_saml_provider_configurations",
    );
    expect(create).toContain("platform_login_enabled, enabled");
    expect(create).toContain("'disabled', false, false");
    expect(create).toContain("command.expires_at <= transaction_timestamp()");
    expect(create).toContain("LIMIT 64");
    expect(create).toContain("FOR UPDATE SKIP LOCKED");
    expect(schema).toContain(
      "platform_identity_provider_test_runs_value_check",
    );
    expect(schema).toContain("and ${table.outcome} is not null");
    expect(schema).toContain("and ${table.category} is not null");
    expect(schema).toContain("))) is true`");
  });

  it("revalidates canonical typed configuration inside the protected ABI", () => {
    const create = functionBody(
      "create_platform_auth_provider_v1",
      "update_platform_auth_provider_v1",
    );
    expect(security).toContain("private_platform_identity_uri_is_canonical_v1");
    expect(security).toContain("OR p_value ~ '%$'");
    expect(create).toContain("scope.value = 'openid'");
    expect(create).toContain("count(DISTINCT scope.value)");
    expect(create).toContain('ORDER BY scope.value COLLATE "C"');
    expect(create).toContain(
      "p_configuration->>'encryptionPolicy' <> 'disabled'",
    );
    expect(create).toContain(
      "jsonb_array_length(p_configuration->'decryptionKeyVersions') <> 0",
    );
    expect(create).toContain("count(DISTINCT context.value)");
    expect(create).toContain("'persistent_nameid', 'immutable_attribute'");
    expect(create).toContain("NOT BETWEEN 0 AND 300000000000");
    expect(create).toContain("NOT BETWEEN 60000000000 AND 86400000000000");
    expect(create).toContain(
      "private_platform_lifecycle_reason_is_valid_v1(p_reason)",
    );
    expect(create).toContain(
      "private_platform_identity_text_is_safe_v1(p_user_agent, false)",
    );
    expect(
      schema.match(/and \$\{table\.profileField\} is not null/g),
    ).toHaveLength(2);
    expect(schema).toContain("and ${table.subjectAttributeName} is not null");
    expect(schema).toContain(
      "and ${table.subjectAttributeNameFormat} is not null",
    );
    for (const constraint of [
      "platform_oidc_claim_rules_value_check",
      "platform_oidc_discovery_snapshots_value_check",
      "platform_saml_provider_configurations_subject_check",
      "platform_saml_attribute_rules_value_check",
      "platform_federated_trust_rules_value_check",
    ]) {
      expect(security).toContain(`DROP CONSTRAINT ${constraint}`);
      expect(security).toContain(`ADD CONSTRAINT ${constraint}`);
    }
  });

  it("holds manage and read authority while returning transaction-local projections", () => {
    const create = functionBody(
      "create_platform_auth_provider_v1",
      "update_platform_auth_provider_v1",
    );
    const update = functionBody(
      "update_platform_auth_provider_v1",
      "archive_platform_auth_provider_v1",
    );
    for (const mutation of [create, update]) {
      expect(mutation).toContain("'platform.identity_provider.manage'");
      expect(mutation).toContain("'platform.identity_provider.read'");
      expect(mutation).toContain("private_platform_auth_provider_document_v1");
      expect(mutation).toContain("document jsonb");
    }
    expect(querySource).toContain("result.document::jsonb AS document");
    expect(querySource).toContain(
      "AS result(provider_id, version, replayed, document)",
    );
    expect(querySource).toContain("AS result(version, document)");
    expect(querySource).toContain(
      "FROM app.create_platform_oidc_auth_provider_v2(",
    );
    expect(querySource).toContain("sqlc.arg(tenant_redirect_uri)::text");
    expect(querySource).toContain(
      "FROM app.create_platform_saml_auth_provider_v2(",
    );
    expect(querySource).not.toContain(
      "FROM app.create_platform_auth_provider_v1(",
    );
  });

  it("returns safe projections and never exposes secret envelopes", () => {
    const list = functionBody(
      "list_platform_auth_providers_v1",
      "get_platform_auth_provider_v1",
    );
    const get = functionBody(
      "get_platform_auth_provider_v1",
      "create_platform_auth_provider_v1",
    );
    const privateDocument = functionBody(
      "private_platform_auth_provider_document_v1",
      "create_platform_auth_provider_v1",
    );
    for (const read of [list, get, privateDocument]) {
      expect(read).toContain("secret");
      expect(read).not.toContain("secret.nonce");
      expect(read).not.toContain("secret.ciphertext");
      expect(read).not.toContain("sp_key.ciphertext");
      expect(read).not.toContain("certificate_der");
    }
    expect(list).toContain("'configured'");
    expect(list).toContain("'secretPresent'");
    expect(list).toMatch(
      /'secretPresent', CASE provider\.kind[\s\S]*?WHEN 'saml' THEN false/,
    );
    expect(list).toContain("'secretPresent'");
    expect(get).toContain("'clientSecretPresent'");
    expect(get).toContain("'spKeyPresent'");
  });

  it("uses ONLY for every protected-table read, update, and delete", () => {
    for (const table of protectedTables) {
      for (const source of [security, compatibility]) {
        expect(source).not.toMatch(
          new RegExp(`\\bFROM\\s+public\\.${table}\\b`),
        );
        expect(source).not.toMatch(
          new RegExp(`\\bJOIN\\s+public\\.${table}\\b`),
        );
        expect(source).not.toMatch(
          new RegExp(`\\bUPDATE\\s+public\\.${table}\\b`),
        );
        expect(source).not.toMatch(
          new RegExp(`\\bDELETE\\s+FROM\\s+public\\.${table}\\b`),
        );
      }
    }
    expect(security).toContain(
      "FROM ONLY public.platform_auth_providers AS provider",
    );
    expect(security).toContain(
      "JOIN ONLY public.platform_federated_provider_policies AS policy",
    );
    expect(security).toContain(
      "DELETE FROM ONLY public.platform_identity_provider_commands AS command",
    );
    expect(security).toContain(
      "UPDATE ONLY public.platform_oidc_client_secrets AS secret",
    );
    expect(compatibility).toContain(
      "FROM ONLY public.platform_saml_sp_keys AS sp_key",
    );
  });

  it("uses CAS for updates, archives, and redacted OIDC secret rotation", () => {
    expect(
      security.match(/provider_record\.version <> p_expected_version/g),
    ).toHaveLength(3);
    expect(security.match(/USING ERRCODE = '40001'/g)).toHaveLength(3);
    expect(
      security.match(/p_expected_version NOT BETWEEN 1 AND 2147483646/g),
    ).toHaveLength(3);

    const update = functionBody(
      "update_platform_auth_provider_v1",
      "archive_platform_auth_provider_v1",
    );
    const archive = functionBody(
      "archive_platform_auth_provider_v1",
      "replace_platform_oidc_client_secret_v1",
    );
    const replaceSecret = functionBody(
      "replace_platform_oidc_client_secret_v1",
      "list_platform_auth_providers_v1",
    );
    expect(
      update.indexOf("provider_record.version <> p_expected_version"),
    ).toBeLessThan(update.indexOf("provider_record.archived_at IS NOT NULL"));
    expect(
      archive.indexOf("provider_record.version <> p_expected_version"),
    ).toBeLessThan(archive.indexOf("provider_record.archived_at IS NOT NULL"));
    expect(
      replaceSecret.indexOf("provider_record.version <> p_expected_version"),
    ).toBeLessThan(replaceSecret.indexOf("provider_record.kind <> 'oidc'"));
    expect(archive).toContain(
      "policy_record.security_revision >= 9007199254740991",
    );
    expect(replaceSecret).toContain(
      "configuration_record.client_secret_revision >= 9007199254740991",
    );
    expect(replaceSecret).toContain(
      "configuration_record.version >= 9007199254740991",
    );
    expect(replaceSecret).toContain(
      "policy_record.configuration_revision >= 9007199254740991",
    );
    expect(replaceSecret).toContain(
      "policy_record.security_revision >= 9007199254740991",
    );
    expect(
      replaceSecret.indexOf("SELECT policy.* INTO policy_record"),
    ).toBeLessThan(
      replaceSecret.indexOf("SELECT configuration.* INTO configuration_record"),
    );
    expect(archive).toContain(
      "platform identity provider revision is exhausted",
    );
    expect(replaceSecret).toContain(
      "platform identity provider revision is exhausted",
    );
    expect(archive).toContain(
      "UPDATE ONLY public.platform_oidc_client_secrets AS secret",
    );
    expect(archive).toContain(
      "UPDATE ONLY public.platform_saml_sp_keys AS sp_key",
    );
    expect(archive.match(/SET retired_at = changed_at/g)).toHaveLength(2);
    expect(security).toContain("SET retired_at = changed_at");
    expect(security).toContain("'secret_material_included', true");
    expect(security).toContain("'secret_version', next_secret_revision");
    expect(security).not.toContain("'secret_present'");
    expect(security).not.toContain("'secret_revision'");
    expect(security).not.toContain("'ciphertext', p_ciphertext");
    expect(security).not.toContain("'nonce', p_nonce");
    expect(security).toContain("AND keyring.is_active");
    expect(security).toContain(
      "CREATE OR REPLACE FUNCTION app.verify_identity_keyring_v3",
    );
    expect(security).toContain(
      "LOCK TABLE public.identity_keyring_versions IN EXCLUSIVE MODE",
    );
    expect(security).toContain(
      "FROM ONLY public.platform_oidc_client_secrets AS secret",
    );
    expect(security).toContain(
      "FROM ONLY public.platform_saml_sp_keys AS sp_key",
    );
    expect(security).toContain("DO $platform_keyring_acl_reset$");
    expect(security).toContain("DO $platform_legacy_keyring_acl_reset$");
    expect(security).toContain(
      "REVOKE ALL ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer)",
    );
    expect(security).toContain(
      "REVOKE ALL ON FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer)",
    );
    expect(security).toContain(
      "TO periapsis_migrator, periapsis_api, periapsis_worker",
    );
    expect(security).toContain("OR policy_record.enabled");
    expect(security).toContain("OR policy_record.platform_login_enabled");
    expect(security).toContain(
      "platform identity provider must be disabled before archive",
    );
    expect(security).toContain("platform_login_enabled = false");
    expect(security).toContain("enabled = false");
    expect(compatibility).toContain("provider.archived_at IS NOT NULL");
    expect(compatibility).toContain("secret.retired_at IS NULL");
    expect(compatibility).toContain("sp_key.retired_at IS NULL");
    expect(compatibility).toContain("secret_state.live_count <> 1");
    expect(compatibility).toContain("secret_state.maximum_revision, 1");
    expect(compatibility).toContain("configuration.client_secret_revision");
    expect(compatibility).toMatch(
      /AND NOT EXISTS \(\s+SELECT 1\s+FROM ONLY public\.platform_saml_sp_keys AS sp_key\s+WHERE sp_key\.retired_at IS NULL\s+\)/,
    );
  });

  it("fails readiness closed over the exact provider catalog manifest", () => {
    for (const manifest of ["column", "constraint", "index"]) {
      expect(compatibility).toContain(`expected_catalog_${manifest}`);
      expect(compatibility).toContain(`actual_catalog_${manifest}`);
      expect(compatibility).toContain(
        `catalog_${manifest}_mismatch_count IS DISTINCT FROM 0`,
      );
      expect(compatibility).toContain(`catalog_${manifest}_mismatch_count = 0`);
    }

    expect(compatibility.match(/\n\s+EXCEPT\n/g)).toHaveLength(20);
    expect(compatibility).toContain("pg_catalog.format_type(");
    expect(compatibility).toContain("column_row.attnotnull");
    expect(compatibility).toContain("default_expression");
    expect(compatibility).toContain(
      "LEFT JOIN pg_catalog.pg_attrdef AS default_row",
    );
    expect(compatibility).toContain("pg_catalog.pg_get_expr(");
    expect(compatibility).toContain("uses_type_collation");
    expect(compatibility).toContain("uses_type_storage");
    expect(compatibility).toContain("uses_default_compression");
    expect(compatibility).toContain("identity_kind");
    expect(compatibility).toContain("generated_kind");
    expect(compatibility).toContain("declared_dimensions");
    expect(compatibility).toContain("inheritance_count");
    expect(compatibility).toContain("is_local");
    expect(compatibility).toContain(
      "column_row.attcollation = column_type.typcollation",
    );
    expect(compatibility).toContain(
      "column_row.attstorage = column_type.typstorage",
    );
    expect(compatibility).toContain(`column_row.attcompression = ''::"char"`);
    expect(compatibility).toContain("column_row.attidentity::text");
    expect(compatibility).toContain("column_row.attgenerated::text");
    expect(compatibility).toContain("column_row.attndims");
    expect(compatibility).toContain("column_row.attinhcount");
    expect(compatibility).toContain("column_row.attislocal");
    expect(compatibility).toContain(
      "CASE WHEN base.data_type LIKE '%[]' THEN 1 ELSE 0 END",
    );
    expect(compatibility).toContain(
      "('platform_identity_provider_commands', 'expires_at', $default$now() + '24:00:00'::interval$default$)",
    );
    expect(compatibility).toContain(
      "('platform_auth_providers', 'version', 'bigint', true)",
    );
    expect(compatibility).toContain(
      "('platform_identity_provider_commands', 'result_version', 'bigint', true)",
    );
    expect(compatibility).toContain(
      "('platform_identity_provider_test_runs', 'provider_version', 'bigint', true)",
    );
    expect(compatibility).toContain(
      "('platform_oidc_client_secrets', 'key_version', 'integer', true)",
    );
    expect(compatibility).toContain(
      "('platform_saml_provider_configurations', 'subject_attribute_name', 'text', false)",
    );

    expect(compatibility).toContain(
      "constraint_row.contype IN ('c', 'f', 'p', 'u')",
    );
    expect(compatibility).toContain(
      "pg_catalog.pg_get_constraintdef(constraint_row.oid, true)",
    );
    expect(compatibility).toContain(
      "platform_auth_providers_lifecycle_check', 'c', 'CHECK (version >= 1 AND version <= 2147483647 AND isfinite(created_at) AND isfinite(updated_at)",
    );
    expect(compatibility).toContain(
      "platform_identity_provider_commands_result_check', 'c', 'CHECK (result_version = 1)",
    );
    expect(compatibility).toContain(
      "platform_identity_provider_test_runs_revision_check', 'c', 'CHECK (provider_version >= 1 AND provider_version <= 2147483647 AND configuration_revision >= 1 AND configuration_revision <= ''9007199254740991''::bigint)",
    );
    expect(compatibility).toContain(
      "platform_federated_provider_policies_revision_check', 'c', 'CHECK (configuration_revision >= 1 AND configuration_revision <= ''9007199254740991''::bigint",
    );
    expect(compatibility).toContain(
      "platform_oidc_provider_configurations_scope_check', 'c', 'CHECK (cardinality(extra_scopes) <= 32",
    );
    expect(compatibility).toContain(
      "platform_oidc_provider_configurations_text_check', 'c', 'CHECK (issuer = btrim(issuer) AND issuer ~ ''^https://",
    );
    expect(compatibility).toContain(
      "platform_saml_provider_configurations_revision_check', 'c', 'CHECK (sp_key_revision >= 1 AND sp_key_revision <= ''9007199254740991''::bigint",
    );
    expect(compatibility).toContain(
      "platform_saml_provider_configurations_text_check', 'c', 'CHECK (expected_entity_id = btrim(expected_entity_id)",
    );
    expect(compatibility).toContain(
      "platform_federated_provider_policies_provider_fk', 'f', 'FOREIGN KEY",
    );
    expect(compatibility).toContain(
      "platform_identity_provider_commands_replay_key', 'u', 'UNIQUE",
    );

    expect(compatibility).toContain(
      "pg_catalog.pg_get_indexdef(index_class.oid, 0, true)",
    );
    for (const state of [
      "index_row.indisunique",
      "index_row.indisvalid",
      "index_row.indisready",
      "index_row.indislive",
    ]) {
      expect(compatibility).toContain(state);
    }
    expect(compatibility).toContain(
      "CREATE UNIQUE INDEX platform_auth_providers_active_display_key ON platform_auth_providers USING btree (display_name) WHERE archived_at IS NULL",
    );
    expect(compatibility).toContain(
      "CREATE INDEX platform_identity_provider_test_runs_provider_idx ON platform_identity_provider_test_runs USING btree (provider_id, started_at, id)",
    );
  });

  it("rejects physical table, inheritance, TOAST, operator, and cast drift", () => {
    for (const catalogInvariant of [
      "table_row.relkind = 'r'",
      "table_row.relpersistence = 'p'",
      "table_row.relreplident = 'd'",
      "NOT table_row.relispartition",
      "table_row.relpartbound IS NULL",
      "table_row.reloptions IS NULL",
      "access_method.amname = 'heap'",
      "table_row.relrowsecurity",
      "table_row.relforcerowsecurity",
      "owner.rolname = 'periapsis_migrator'",
    ]) {
      expect(compatibility).toContain(catalogInvariant);
    }
    expect(compatibility).toContain(
      "SELECT count(*)::integer INTO protected_inheritance_count",
    );
    expect(compatibility).toContain(
      "FROM pg_catalog.pg_inherits AS inheritance",
    );
    expect(compatibility).toContain("child.oid = inheritance.inhrelid");
    expect(compatibility).toContain("parent.oid = inheritance.inhparent");
    expect(compatibility).toContain(
      "SELECT count(*)::integer INTO protected_toast_mismatch_count",
    );
    for (const toastInvariant of [
      "toast_row.oid IS NULL",
      "toast_row.relkind <> 't'",
      "toast_row.relpersistence <> 'p'",
      "toast_row.reloptions IS NOT NULL",
      "toast_owner.rolname <> 'periapsis_migrator'",
    ]) {
      expect(compatibility).toContain(toastInvariant);
    }
    expect(compatibility).toContain("FROM pg_catalog.pg_operator AS operator");
    expect(compatibility).toContain("namespace.nspname IN ('app', 'public')");
    expect(compatibility).toContain("FROM pg_catalog.pg_cast AS cast_row");
    expect(compatibility).toContain(
      "source_namespace.nspname IN ('app', 'public')",
    );
    expect(compatibility).toContain(
      "target_namespace.nspname IN ('app', 'public')",
    );
    expect(compatibility).toContain("protected_trigger_count = 0");
    expect(compatibility).toContain("protected_trigger_count = 1");
    for (const exactZero of [
      "protected_rule_count",
      "protected_policy_count",
      "protected_inheritance_count",
      "protected_toast_mismatch_count",
      "custom_operator_count",
      "provider_cast_count",
    ]) {
      expect(compatibility).toContain(`${exactZero} IS DISTINCT FROM 0`);
      expect(compatibility).toContain(`${exactZero} = 0`);
    }
  });

  it("seals the exact runtime-accessible database surface", () => {
    expect(compatibility).toContain(
      "CREATE FUNCTION app.private_runtime_accessible_surface_hash_v1()",
    );
    expect(compatibility).toContain("LANGUAGE sql");
    expect(compatibility).toContain("STABLE");
    expect(compatibility).toContain("SECURITY DEFINER");
    expect(compatibility).toContain(
      "ALTER FUNCTION app.private_runtime_accessible_surface_hash_v1()",
    );
    expect(compatibility).toContain("OWNER TO periapsis_migrator");
    expect(compatibility).toContain(
      "REVOKE ALL ON FUNCTION app.private_runtime_accessible_surface_hash_v1()",
    );
    for (const fingerprintedCatalog of [
      "relation_object_entry",
      "sequence_object_entry",
      "routine_object_entry",
      "relation_privilege_entry",
      "column_privilege_entry",
      "sequence_privilege_entry",
      "routine_privilege_entry",
    ]) {
      expect(compatibility).toContain(fingerprintedCatalog);
    }
    expect(compatibility).toContain(
      "SELECT encode(\n  sha256(convert_to(string_agg(entry, E'\\n' ORDER BY entry), 'UTF8')),\n  'hex'\n)",
    );
    expect(compatibility).toContain(
      "('app.private_runtime_accessible_surface_hash_v1()', '2b33d560d29651dd2c9f2a538f0675f13327486ff0ffce1200504ec88fc71137')",
    );
    expect(compatibility).toContain(
      "runtime_accessible_surface_hash =\n      '764fb60e6903f76c4978c521509cd061b9f714103f15fb26c886659be2a6f799'",
    );
    expect(compatibility).toContain(
      "runtime_accessible_surface_hash =\n      '1499f4b4a551afc3d0845735970dafb0c445fdb135867ef7b0a7df595950f710'",
    );
    expect(compatibility).toContain("runtime_surface_function_count = 1");
    expect(compatibility).toContain("private_owner_function_count = 5");
  });

  it("rejects persisted values outside Go-safe bounds or canonical form", () => {
    for (const boundedProjection of [
      "provider.version NOT BETWEEN 1 AND 2147483647",
      "persisted_revision.revision NOT BETWEEN 1 AND 9007199254740991",
      "command.result_version <> 1",
      "test_run.provider_version NOT BETWEEN 1 AND 2147483647",
    ]) {
      expect(compatibility).toContain(boundedProjection);
    }
    expect(compatibility).toContain("NOT isfinite(provider.created_at)");
    expect(compatibility).toContain(
      "provider.created_at < '1970-01-01 00:00:00+00'::timestamptz",
    );
    expect(compatibility).toContain(
      "provider.created_at >= '10000-01-01 00:00:00+00'::timestamptz",
    );
    expect(compatibility).toContain(
      "NOT app.private_platform_identity_text_is_safe_v1(\n            provider.display_name, true",
    );
    expect(compatibility).toContain("configuration.issuer, true, false, 4096");
    expect(compatibility).toContain(
      "configuration.redirect_uri, true, true, 4096",
    );
    expect(compatibility).toContain(
      "scope.value !~\n                    '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'",
    );
    expect(compatibility).toContain("scope.value = 'openid'");
    expect(compatibility).toContain('count(DISTINCT scope.value COLLATE "C")');
    expect(compatibility).toContain('ORDER BY scope.value COLLATE "C"');
    expect(compatibility).toContain(
      "cardinality(configuration.decryption_key_versions) <> 0",
    );
    expect(compatibility).toContain(
      "cardinality(configuration.requested_authn_contexts)\n               NOT BETWEEN 1 AND 32",
    );
    expect(compatibility).toContain(
      'count(DISTINCT context.value COLLATE "C")',
    );
    expect(compatibility).toContain('ORDER BY context.value COLLATE "C"');
    expect(compatibility).toContain(
      "configuration.subject_attribute_name_format,\n              false, true, 512",
    );
  });

  it("fails readiness closed over security role attributes and migrator membership", () => {
    expect(compatibility).toContain("expected_security_role");
    expect(compatibility).toContain("('periapsis_migrator', true, true)");
    expect(compatibility).toContain(
      "('periapsis_ldap_administration_owner', false, false)",
    );
    expect(compatibility).toContain(
      "('periapsis_notification_admin_owner', false, false)",
    );
    expect(compatibility).toContain(
      "('periapsis_notification_readiness_owner', false, false)",
    );
    expect(compatibility).toContain("security_role_mismatch_count");
    for (const attribute of [
      "role.rolsuper",
      "role.rolinherit",
      "role.rolcreaterole",
      "role.rolcreatedb",
      "role.rolcanlogin",
      "role.rolreplication",
      "role.rolbypassrls",
    ]) {
      expect(compatibility).toContain(attribute);
    }
    expect(compatibility).toContain("security_role_membership_mismatch_count");
    expect(compatibility).toContain("runtime_login_role_mismatch_count");
    expect(compatibility).toContain("pg_catalog.pg_auth_members AS membership");
    expect(compatibility).toContain("membership.admin_option");
    expect(compatibility).toContain("membership.inherit_option");
    expect(compatibility).toContain("membership.set_option");
    expect(compatibility).toContain("('periapsis_api_login', 'periapsis_api')");
    expect(compatibility).toContain(
      "granted_role.rolname IN (SELECT role_name FROM runtime_login)",
    );
  });

  it("fails readiness closed over the exact public and app schema ACLs", () => {
    expect(compatibility).toContain(
      "ALTER SCHEMA public OWNER TO periapsis_migrator",
    );
    expect(compatibility).toContain(
      "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    );
    expect(compatibility).toContain("expected_schema_usage_role");
    expect(compatibility).toContain("expected_schema_acl");
    expect(compatibility).toContain("actual_schema_acl");
    expect(compatibility).toContain("schema_acl_mismatch_count");
    expect(compatibility).toContain("protected_schema_principal");
    expect(compatibility).toContain("schema_effective_create_mismatch");
    expect(compatibility).toContain("has_schema_privilege(");
    expect(compatibility).toContain("database_effective_create_mismatch");
    expect(compatibility).toContain("has_database_privilege(");
    expect(compatibility).toContain("pg_catalog.pg_namespace AS namespace");
    expect(compatibility).toContain("pg_catalog.aclexplode(");
    expect(compatibility).toContain("pg_catalog.acldefault('n'");
    expect(compatibility).toContain(
      "('app', 'periapsis_migrator', 'periapsis_migrator', 'CREATE', false)",
    );
    expect(compatibility).toContain(
      "('public', 'periapsis_migrator', 'periapsis_migrator', 'CREATE', false)",
    );
    expect(compatibility).toContain(
      "('public', 'periapsis_migrator', 'PUBLIC', 'USAGE', false)",
    );
    expect(compatibility).toContain(
      "schema_acl_mismatch_count IS DISTINCT FROM 0",
    );
    expect(compatibility).toContain("schema_acl_mismatch_count = 0");
    expect(compatibility).toContain(
      "schema_effective_create_mismatch_count IS DISTINCT FROM 0",
    );
    expect(compatibility).toContain(
      "schema_effective_create_mismatch_count = 0",
    );
    expect(compatibility).toContain(
      "database_effective_create_mismatch_count IS DISTINCT FROM 0",
    );
    expect(compatibility).toContain(
      "database_effective_create_mismatch_count = 0",
    );
  });

  it("removes the global routine default and seals migrator default ACLs", () => {
    expect(compatibility).toContain(
      "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_migrator",
    );
    expect(compatibility).toContain("REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC");
    expect(compatibility).toContain("expected_default_acl");
    expect(compatibility).toContain("actual_default_acl");
    expect(compatibility).toContain("pg_catalog.pg_default_acl");
    expect(compatibility).toContain("'periapsis_migrator', '<global>', 'f'");
    expect(compatibility).toContain("default_acl_mismatch_count");
    expect(compatibility).toContain("default_acl_row_count");
    expect(compatibility).toContain(
      "default_acl_mismatch_count IS DISTINCT FROM 0",
    );
    expect(compatibility).toContain("default_acl_row_count IS DISTINCT FROM 1");
    expect(compatibility).toContain("default_acl_mismatch_count = 0");
    expect(compatibility).toContain("default_acl_row_count = 1");
  });

  it("normalizes legacy runtime routine owners before resealing readiness", () => {
    const runtimeSurfaceDeclaration = compatibility.indexOf(
      "CREATE FUNCTION app.private_runtime_accessible_surface_hash_v1()",
    );
    expect(runtimeSurfaceDeclaration).toBeGreaterThan(-1);

    for (const signature of [
      "app.private_complete_mfa_factor_v1(jsonb, text)",
      "app.private_webauthn_ceremony_projection_v1(bytea)",
      "app.private_webauthn_credential_projection_v1(uuid)",
    ]) {
      const ownerNormalization = compatibility.indexOf(
        `ALTER FUNCTION ${signature}\n  OWNER TO periapsis_migrator;`,
      );
      expect(ownerNormalization).toBeGreaterThan(-1);
      expect(ownerNormalization).toBeLessThan(runtimeSurfaceDeclaration);
      expect(currentCompatibility).not.toContain(
        `ALTER FUNCTION ${signature}\n  OWNER TO periapsis_migrator;`,
      );
    }
  });

  it("seals V34, preserves exact V33, retires V32, and requires semantic readiness", () => {
    expect(currentCompatibility).toContain(
      "CREATE FUNCTION app.schema_compatibility_v34",
    );
    expect(currentCompatibility).toContain("journal_count = 163");
    expect(compatibility).toContain("WHERE migration.migration_ordinal <= 159");
    expect(currentCompatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v33",
    );
    expect(currentCompatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.schema_compatibility_v32",
    );
    expect(currentCompatibility).toContain(
      "SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(currentCompatibility).not.toContain(
      "CREATE OR REPLACE FUNCTION app.platform_identity_provider_schema_readiness_v1()",
    );
    expect(compatibility).toContain(
      "('app.platform_identity_provider_schema_readiness_v1()')",
    );
    expect(compatibility).toContain(
      "app.tenant_platform_identity_binding_schema_readiness_v2()",
    );
    expect(currentCompatibility).toContain(
      "CREATE FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()",
    );
    expect(currentCompatibility).toContain(
      "schema compatibility v34 trusted roots are not exact",
    );
    expect(compatibility).toContain("rolling_catalog_state_ready := (");
    expect(compatibility).toContain("predecessor_count = 155");
    expect(compatibility).toContain("predecessor_count = 0");
    expect(compatibility).toContain("AND protected_table_count = 15");
    expect(compatibility).toContain("OR policy.account_mode <> 'disabled'");
    expect(compatibility).toContain("owner.rolname = 'periapsis_migrator'");
    expect(compatibility).not.toContain("function.proconfig @>");
    expect(compatibility).toContain("function.proconfig IS NOT DISTINCT FROM");
    expect(compatibility).toContain("pg_catalog.aclexplode");
    expect(compatibility).toContain("column_row.attacl IS NOT NULL");
    expect(compatibility).toContain("protected_owner_function_count = 6");
    expect(compatibility).toContain("private_owner_function_count = 5");
    expect(compatibility).toContain("protected_owner_table_count = 15");
    expect(compatibility).toContain("keyring_function_count = 1");
    expect(compatibility).toContain("keyring_acl_mismatch_count = 0");
    expect(compatibility).toContain("keyring_runtime_acl_mismatch_count = 0");
    expect(compatibility).toContain("keyring_acl_entry_count = 3");
    expect(compatibility).toContain("legacy_keyring_acl_mismatch_count = 0");
    expect(compatibility).toContain(
      "'app.verify_identity_keyring_v1(integer[],bytea[],integer)'::regprocedure",
    );
    expect(compatibility).toContain(
      "'app.verify_identity_keyring_v2(integer[],bytea[],integer)'::regprocedure",
    );
    expect(compatibility).toContain(
      "app.platform_identity_provider_schema_readiness_v1()",
    );
  });
});
