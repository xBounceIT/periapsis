import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const source = (path: string): string =>
  readFileSync(resolve(packageRoot, path), "utf8");

const runtimeSchema = source("src/schema/identity-platform-runtime.ts");
const providerSchema = source("src/schema/identity-platform-federation.ts");
const lifecycle = source("migrations/0164_platform_oidc_binding_lifecycle.sql");
const runtime = source("migrations/0165_platform_oidc_binding_runtime.sql");
const readiness = source("migrations/0166_platform_oidc_binding_readiness.sql");
const protocolAwareSuccessor = source(
  "migrations/0228_tenant_federation_administration.sql",
);
const mfaSchema = source("src/schema/identity-mfa.ts");
const v35JournalCreatedAt = Number(
  /"when":\s*(\d+),\s*"tag":\s*"0166_platform_oidc_binding_readiness"/u.exec(
    source("migrations/meta/_journal.json"),
  )?.[1],
);

const functionBodyFrom = (sql: string, name: string): string => {
  const marker = new RegExp(
    `CREATE (?:OR REPLACE )?FUNCTION app\\.${name}\\(`,
  ).exec(sql);
  expect(marker).not.toBeNull();
  const end = sql.indexOf("$function$;", marker!.index);
  expect(end).toBeGreaterThan(marker!.index);
  return sql.slice(marker!.index, end + "$function$;".length);
};

const schemaTableFrom = (schema: string, exportName: string): string => {
  const start = schema.indexOf(`export const ${exportName} = pgTable(`);
  expect(start, `${exportName} must exist`).toBeGreaterThanOrEqual(0);
  const end = schema.indexOf(").enableRLS();", start);
  expect(end, `${exportName} must enable RLS`).toBeGreaterThan(start);
  return schema.slice(start, end);
};

const runtimeTables = [
  "platform_federated_external_identities",
  "platform_federated_external_identity_aliases",
  "platform_identity_account_commands",
  "tenant_platform_federated_provider_access_grants",
  "tenant_platform_federated_provider_profile_contributions",
  "tenant_platform_oidc_authentication_transactions",
  "tenant_platform_oidc_authentication_applications",
  "auth_session_tenant_platform_federated_provenance",
  "auth_session_tenant_platform_federated_evidence",
  "tenant_post_primary_platform_federated_evidence",
  "tenant_platform_federated_session_revalidation_commands",
  "tenant_mfa_authority_platform_federated_evidence",
  "tenant_post_primary_platform_federated_provenance",
] as const;

describe("tenant-bound platform OIDC database runtime contract", () => {
  it("keeps platform identity, access, transaction and session state physically separate", () => {
    for (const table of runtimeTables) {
      expect(runtimeSchema).toContain(`"${table}"`);
    }
    expect(runtimeSchema.match(/\.enableRLS\(\)/g)).toHaveLength(
      runtimeTables.length,
    );
    expect(runtimeSchema).toContain(
      '"tenant_platform_oidc_authentication_applications_identity_fk"',
    );
    expect(runtimeSchema).toContain(
      '"tenant_post_primary_platform_federated_evidence_identity_fk"',
    );
    expect(runtime).toContain(
      "CREATE TRIGGER tenant_platform_oidc_applications_continuation_guard_v1",
    );
    expect(runtime).toContain(
      "CREATE TRIGGER tenant_post_primary_platform_evidence_continuation_guard_v1",
    );
  });

  it("pins a dedicated tenant callback without enabling direct platform login", () => {
    expect(providerSchema).toContain(
      'tenantRedirectUri: text("tenant_redirect_uri")',
    );
    expect(providerSchema).toContain(
      '"platform_oidc_provider_configurations_text_check"',
    );
    expect(providerSchema).toContain(
      "${table.tenantRedirectUri} ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'",
    );
    expect(lifecycle).toContain(
      "NEW.tenant_redirect_uri := configured_redirect",
    );
    expect(lifecycle).toContain("'app.platform_tenant_oidc_redirect_uri'");
    expect(runtime).toContain("'redirectUri', projected.tenant_redirect_uri");
    expect(runtime).toContain("NOT policy.platform_login_enabled");
    expect(readiness).toContain("WHERE policy.platform_login_enabled");
  });

  it("projects truthful activation and couples binding activation to an exact access source", () => {
    expect(lifecycle).toContain(
      "private_platform_oidc_provider_activation_available_v1",
    );
    expect(lifecycle).toContain(
      "private_tenant_platform_binding_activation_available_v1",
    );
    expect(lifecycle).toContain("'activationAvailable'");
    expect(lifecycle).toContain("'identity_provider_access:%s:%s'");
    expect(lifecycle).toContain(
      "source.authoritative AND NOT source.protected",
    );
    expect(lifecycle).toContain(
      "SET enabled = false, jit_mode = 'disabled', no_match_policy = 'deny'",
    );
    expect(lifecycle).toContain(
      "private_materialize_tenant_user_profile_v1(\n        binding_record.tenant_id, affected_membership_id",
    );
    expect(lifecycle).toContain("grant_record.owns_membership");
    expect(lifecycle).toContain(
      "UPDATE ONLY public.tenant_memberships AS membership",
    );
    for (const accessFamily of [
      "tenant_platform_federated_provider_access_grants",
      "tenant_ldap_provider_access_grants",
      "tenant_federated_provider_access_grants",
      "user_login_identifiers",
    ]) {
      expect(lifecycle).toContain(accessFamily);
    }
    expect(lifecycle).toContain(
      "CREATE FUNCTION app.activate_tenant_platform_auth_provider_binding_v1(",
    );
    expect(lifecycle).toContain("p_expected_binding_version bigint");
    expect(lifecycle).toContain("p_expected_tenant_version integer");
    expect(lifecycle).not.toContain("p_expected_provider_version");
  });

  it("dispatches the existing OIDC family ABI while preserving explicit platform admission", () => {
    for (const name of [
      "begin_tenant_oidc_authentication_v1",
      "resolve_tenant_oidc_authentication_v1",
      "create_oidc_authentication_transaction_v1",
      "claim_oidc_authentication_transaction_v1",
      "fail_oidc_authentication_transaction_v1",
      "apply_federated_authentication_v1",
      "load_federated_authentication_planning_state_v1",
      "load_oidc_trust_snapshot_v1",
      "load_oidc_client_secret_envelope_v1",
      "load_federated_session_revalidation_v1",
      "apply_federated_session_revalidation_v1",
    ]) {
      expect(runtime).toMatch(
        new RegExp(`CREATE OR REPLACE FUNCTION app\\.${name}\\(`),
      );
    }
    expect(runtime).toContain("'admission', jsonb_build_object(");
    expect(runtime).toContain("'tenantId', live.tenant_id::text");
    expect(runtime).toContain("'bindingId', live.binding_id::text");
    expect(runtime).toContain("private_platform_oidc_claim_policy_v1");
  });

  it("allows a repeat provider-access-only login but rejects authorization mapping", () => {
    expect(runtime).not.toContain("2162688");
    expect(runtime).toContain("ARRAY['operationDigest','apply'], 2097152");
    expect(runtime).toContain("publication_provider_id uuid");
    expect(runtime).toContain("policy.provider_id = publication_provider_id");
    expect(runtime.match(/#variable_conflict use_variable/g)).toHaveLength(12);
    for (const functionName of [
      "create_tenant_platform_oidc_authentication_transaction_v1",
      "load_tenant_platform_federated_session_revalidation_v1",
      "apply_tenant_platform_federated_session_revalidation_v1",
      "publish_platform_oidc_trust_snapshot_v1",
      "apply_tenant_platform_oidc_authentication_v1",
      "claim_tenant_platform_oidc_authentication_transaction_v1",
      "resolve_tenant_platform_oidc_authentication_v1",
      "fail_tenant_platform_oidc_authentication_transaction_v1",
      "load_tenant_platform_oidc_client_secret_v1",
      "load_tenant_platform_federated_planning_state_v1",
      "load_tenant_platform_oidc_trust_snapshot_v1",
      "private_mfa_apply_tenant_platform_federated_session_v1",
    ]) {
      expect(functionBodyFrom(runtime, functionName)).toContain(
        "#variable_conflict use_variable",
      );
    }
    for (const genericDispatcher of [
      "create_oidc_authentication_transaction_v1",
      "claim_oidc_authentication_transaction_v1",
      "fail_oidc_authentication_transaction_v1",
      "load_federated_session_revalidation_v1",
      "apply_federated_session_revalidation_v1",
    ]) {
      expect(functionBodyFrom(runtime, genericDispatcher)).not.toContain(
        "#variable_conflict",
      );
    }
    expect(runtime).toContain(
      "mapping_request ->> 'reason' <> 'provider_access_only'",
    );
    expect(runtime).toContain(
      "mapping_request ->> 'accessAction' NOT IN ('ensure','no_change')",
    );
    for (const field of [
      "matchedRuleIds",
      "securityGroupIds",
      "roleIds",
      "operatorTeams",
      "changes",
    ]) {
      expect(runtime).toContain(
        `jsonb_array_length(mapping_request -> '${field}') <> 0`,
      );
    }
    expect(runtime).toContain(
      "platform provider mapping attempted authorization changes",
    );
    expect(runtime).toContain("binding_record.jit_mode <> 'create'");
    expect(runtime).toContain(
      "binding_record.no_match_policy <> 'provider_access_only'",
    );
    expect(runtime).toContain("mapping_request ->> 'accessAction' <> 'ensure'");
    expect(runtime).toContain(
      "binding_record.no_match_policy <> 'provider_access_only'",
    );
    expect(runtime).toContain(
      "tenant platform OIDC access grant is denied by policy",
    );
    expect(runtime).toContain(
      "mapping_request ->> 'accessAction' = 'no_change'",
    );
    expect(runtime).toContain(
      "grant_record.access_epoch_id = transaction_record.access_epoch_id",
    );
    expect(runtime).toContain(
      "grant_record.source_id = transaction_record.access_source_id",
    );
  });

  it("recomputes tenant MFA at apply and stores platform-only policy evidence", () => {
    expect(runtime).toContain("private_mfa_policy_snapshot_v1(");
    expect(runtime).toContain("private_federated_assurance_decision_v1(");
    expect(runtime).toContain(
      "auth_session_tenant_platform_federated_evidence",
    );
    expect(runtime).toContain(
      "tenant_post_primary_platform_federated_evidence",
    );
    expect(runtime).toContain("auth_session_mfa_policy_pins");
    expect(runtime).toContain("tenant_post_primary_continuation_policy_pins");
    expect(runtime).not.toMatch(
      /INSERT INTO public\.auth_session_mfa_evidence[\s\S]{0,500}platform_provider/,
    );
  });

  it("keeps repeated observations separate from immutable identity and session epochs", () => {
    const guard = functionBodyFrom(
      runtime,
      "guard_platform_federated_external_identity_v1",
    );
    const apply = functionBodyFrom(
      runtime,
      "apply_tenant_platform_oidc_authentication_v1",
    );
    const planner = functionBodyFrom(
      runtime,
      "load_tenant_platform_federated_planning_state_v1",
    );
    const assurance = functionBodyFrom(
      runtime,
      "private_federated_assurance_decision_v1",
    );
    const existingIdentityUpdate = apply.slice(
      apply.indexOf(
        "UPDATE ONLY public.platform_federated_external_identities AS identity",
      ),
      apply.indexOf(
        "ELSE",
        apply.indexOf(
          "UPDATE ONLY public.platform_federated_external_identities AS identity",
        ),
      ),
    );

    expect(guard).toContain("NEW.version = OLD.version");
    expect(existingIdentityUpdate).toContain(
      "SET last_observed_at = transaction_timestamp()",
    );
    expect(existingIdentityUpdate).not.toContain(
      "version = identity.version + 1",
    );
    expect(existingIdentityUpdate).not.toContain("subject_ciphertext =");
    expect(apply).toContain(
      "uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())",
    );
    expect(runtime).not.toContain("gen_random_bytes(32)");
    expect(apply).toContain("array_agg(DISTINCT matches.user_id");
    expect(planner).toContain("array_agg(DISTINCT matches.user_id");
    expect(apply).toContain("'system', NULL");
    expect(assurance).toContain("p_requirement ? 'enrollmentDeadline'");
    expect(assurance).toContain("v_proof ?& ARRAY[");
    expect(readiness).toContain("%array_agg(DISTINCT matches.user_id%");
    expect(readiness).toContain("%NEW.version = OLD.version%");
  });

  it("keeps terminal revalidation replayable without reopening state CAS", () => {
    const applyRevalidation = functionBodyFrom(
      runtime,
      "apply_tenant_platform_federated_session_revalidation_v1",
    );
    expect(applyRevalidation).toContain(
      "ELSIF decision IN ('revoke','deny') THEN",
    );
    expect(applyRevalidation).toContain(
      "tenant_platform_federated_session_revalidation_commands",
    );
    expect(applyRevalidation).toContain(
      "tenant platform session replay mismatch",
    );
    expect(applyRevalidation).toContain(
      "tenant platform session command lost CAS",
    );
    expect(readiness).toContain(
      "%ELSIF decision IN (''revoke'',''deny'') THEN%",
    );
  });

  it("aligns protocol-aware provider enums with constrained text provenance", () => {
    const start = protocolAwareSuccessor.indexOf(
      "DO $tenant_platform_protocol_aware_revalidation_v1$",
    );
    const end = protocolAwareSuccessor.indexOf(
      "$tenant_platform_protocol_aware_revalidation_v1$;",
      start + 1,
    );
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const patch = protocolAwareSuccessor.slice(start, end);
    const provenance = schemaTableFrom(
      runtimeSchema,
      "authSessionTenantPlatformFederatedProvenance",
    );
    const continuation = schemaTableFrom(
      mfaSchema,
      "tenantPostPrimaryContinuations",
    );

    expect(provenance).toContain(
      'authenticationMethod: text("authentication_method")',
    );
    expect(provenance).toContain(
      `\${table.authenticationMethod} in ('oidc','saml')`,
    );
    expect(continuation).toContain(
      'providerKind: authProviderKind("provider_kind")',
    );
    for (const comparison of [
      "provider.kind::text = provenance.authentication_method",
      "policy.provider_kind::text = provenance.authentication_method",
      "session.authentication_method = provenance.authentication_method",
      "provider.kind::text = provenance_record.authentication_method",
      "provider.kind::text = source_provenance.authentication_method",
      "policy.provider_kind::text = source_provenance.authentication_method",
    ]) {
      expect(patch).toContain(comparison);
    }
    expect(
      patch.match(
        /policy\.provider_kind::text = provenance_record\.authentication_method/g,
      ),
    ).toHaveLength(2);
    expect(
      patch.match(
        /rule\.provider_kind::text = provenance_record\.authentication_method/g,
      ),
    ).toHaveLength(2);
    expect(patch).toContain(
      "provenance_record.binding_id,provenance_record.authentication_method::public.auth_provider_kind,provenance_record.external_identity_id",
    );
    expect(patch).toContain(
      "source_provenance.authentication_method := continuation_record.provider_kind::text",
    );
    expect(patch).toContain(
      "'tenant_platform_provider',source_provenance.authentication_method,",
    );
    expect(patch).not.toMatch(
      /'(?:provider\.kind|policy\.provider_kind|rule\.provider_kind) = (?:provenance|provenance_record|source_provenance)\.authentication_method'/u,
    );
  });

  it("separates ceremony ETags from exact live session security provenance", () => {
    const apply = functionBodyFrom(
      runtime,
      "apply_tenant_platform_oidc_authentication_v1",
    );
    const authority = functionBodyFrom(
      runtime,
      "private_tenant_platform_session_authority_live_v1",
    );
    const revalidation = functionBodyFrom(
      runtime,
      "load_tenant_platform_federated_session_revalidation_v1",
    );
    const configuration = functionBodyFrom(
      runtime,
      "private_tenant_platform_oidc_configuration_record_v1",
    );
    for (const predicate of [
      "identity.version = provenance_record.external_identity_revision",
      "binding.version = provenance_record.binding_revision",
      "binding.mapping_revision = provenance_record.mapping_revision",
      "binding.auth_revision = provenance_record.authorization_revision",
      "binding.current_access_epoch_id = provenance_record.access_epoch_id",
      "policy.security_revision = provenance_record.security_revision",
    ]) {
      expect(revalidation).toContain(predicate);
    }
    expect(authority).not.toContain(
      "provider.version = provenance.provider_revision",
    );
    expect(revalidation).not.toContain(
      "provider.version = provenance_record.provider_revision",
    );
    expect(apply).not.toContain(
      "provider.version = transaction_record.provider_revision",
    );
    expect(apply).toContain(
      "binding.version = transaction_record.binding_revision",
    );
    expect(configuration).toContain("'providerRevision', CASE");
    expect(configuration).toContain("p_expected_pins ->> 'providerRevision'");
    expect(configuration).toContain("projected.pins = p_expected_pins");
    expect(runtime).toContain(
      "private_tenant_platform_session_authority_live_v1",
    );
    expect(runtime).toContain("federated session authority unavailable");
    expect(runtime).toContain(
      "private_unprovenanced_rotate_auth_session_tenant_v1",
    );
    expect(runtime).toContain(
      "typed-provenance session tenant switch requires provenance-aware rotation",
    );
    expect(runtime).toContain(
      "auth_session_tenant_platform_federated_provenance",
    );
    expect(runtime).toMatch(
      /session\.absolute_expires_at > transaction_timestamp\(\)[\s\S]{0,80}FOR UPDATE/,
    );
    expect(runtime).toMatch(
      /FROM ONLY public\.auth_session_mfa_states AS state[\s\S]{0,120}state\.session_id = old_session_id/,
    );
    expect(runtime).not.toMatch(
      /state\.session_id = old_session_id[\s\S]{0,100}state\.primary_kind IN/,
    );
    expect(readiness).toContain("protected_function_count = 31");
  });

  it("registers the complete protected runtime surface and seals only v35", () => {
    expect(readiness).toContain("protected_relation_count = 14");
    expect(readiness).toContain("constraint_count = 49");
    expect(readiness).toContain("index_count = 12");
    expect(readiness).toContain("trigger_count = 31");
    expect(readiness).toContain("protected_function_count = 31");
    expect(readiness).toContain("private_function_count = 86");
    expect(readiness).toContain("tenant_post_primary_passkey_provenance");
    expect(readiness).toContain(
      "tenant_mfa_webauthn_evidence_copy_capabilities",
    );
    expect(readiness).toContain("trusted_root_catalog_ready");
    for (const shape of [
      "function_row.pronargdefaults = 0",
      "function_row.proargtypes = ''::pg_catalog.oidvector",
      "function_row.proargdefaults IS NULL",
      "function_row.provariadic = 0",
      "function_row.prosupport = 0",
      "function_row.proretset = (actual.signature IN (",
      "function_row.procost = 100::real",
      "function_row.prorows = CASE WHEN function_row.proretset",
      "function_row.protrftypes IS NULL",
      "function_row.probin IS NULL",
      "function_row.prosqlbody IS NULL",
      "function_row.proallargtypes IS NOT DISTINCT FROM ARRAY[",
      "function_row.proargmodes IS NOT DISTINCT FROM",
      "function_row.proargnames IS NOT DISTINCT FROM ARRAY[",
    ]) {
      expect(readiness).toContain(shape);
    }
    expect(readiness).toContain(
      "tenant_platform_oidc_authentication_applications_identity_fk",
    );
    expect(readiness).toContain(
      "tenant_post_primary_platform_evidence_continuation_guard_v1",
    );
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v35()",
    );
    expect(readiness).toContain("RETURN QUERY SELECT 0::bigint,0::bigint");
    expect(readiness).toContain("'UNSUPPORTED'::text,'UNSUPPORTED'::text");
    expect(readiness).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v34()",
    );
    const publicReadiness = functionBodyFrom(
      readiness,
      "tenant_platform_oidc_runtime_schema_readiness_v1",
    );
    expect(publicReadiness).toContain("app.schema_compatibility_v35()");
    expect(publicReadiness).toContain(
      "app.private_tenant_platform_oidc_runtime_schema_readiness_v1()",
    );
    expect(publicReadiness).not.toContain(
      "FROM app.schema_compatibility_v34()",
    );
    expect(readiness).toContain(
      `journal_latest_created_at = ${v35JournalCreatedAt}`,
    );
    expect(readiness).toContain(
      `p_expected_latest_created_at IS DISTINCT FROM ${v35JournalCreatedAt}`,
    );
    expect(readiness).not.toContain("UNSEALED_DEPENDENCY_");
  });

  it("hashes a canonical portable dependency transcript", () => {
    const digest = functionBodyFrom(
      readiness,
      "private_tenant_platform_oidc_dependency_surface_hash_v1",
    );

    for (const token of [
      "WITH RECURSIVE",
      "pg_catalog.pg_auth_members",
      "pg_catalog.pg_db_role_setting",
      "pg_catalog.pg_parameter_acl",
      "database_row.datlocprovider",
      "database_row.datlocale",
      "database_row.datcollversion",
      "'owner_is_reachable_runtime_role'",
      "constraint_row.contypid",
      "constraint_row.conenforced",
      "constraint_row.conpfeqop",
      "constraint_row.conppeqop",
      "constraint_row.conffeqop",
      "constraint_row.conexclop",
      "index_relation.relowner",
      "index_relation.reltablespace",
      "toast_relation(oid,base_identity)",
      "toast_index_catalog(base_identity,index_oid,definition)",
      'ORDER BY definition::text COLLATE "C",index_oid',
      "SELECT 'toast-index'",
      "SELECT 'toast-column'",
      "'statistics_target',column_row.attstattarget",
      "trigger_row.tgisinternal",
      "trigger_row.tgconstrindid",
      "'qualifier_present'",
      "pg_catalog.pg_get_triggerdef",
      "column_row.attidentity",
      "column_row.attgenerated",
      "column_row.attcompression",
      "pg_catalog.pg_sequence",
      "pg_catalog.pg_depend",
      "pg_catalog.jsonb_build_object",
      "pg_catalog.octet_length",
      'ORDER BY entry COLLATE "C"',
      "SET quote_all_identifiers = off",
      "SET standard_conforming_strings = on",
      "SET lc_numeric = 'C'",
      "pg_catalog.cardinality(object_acl.acl)",
      "NULL::pg_catalog.aclitem[]",
    ]) {
      expect(digest).toContain(token);
    }
    expect(digest).not.toContain("'owner',owner.rolname,\n        'encoding'");
    expect(digest).toContain("'<database-owner>'");
    expect(digest).toContain("'database',pg_catalog.jsonb_build_object(");
    expect(digest).not.toMatch(
      /pg_catalog\.pg_get_expr\(\s*trigger_row\.tgqual/,
    );
    expect(digest).not.toContain("column_row.attmissingval");
  });

  it("normalizes managed login lifecycle state without hiding unsafe topology", () => {
    const digest = functionBodyFrom(
      readiness,
      "private_tenant_platform_oidc_dependency_surface_hash_v1",
    );
    const privateReadiness = functionBodyFrom(
      readiness,
      "private_tenant_platform_oidc_runtime_schema_readiness_v1",
    );

    for (const login of [
      "periapsis_api_login",
      "periapsis_worker_login",
      "periapsis_notifier_login",
      "periapsis_auditor_login",
    ]) {
      expect(digest).toContain(login);
      expect(privateReadiness).toContain(login);
    }
    expect(digest).toContain("managed_runtime_login_role(oid)");
    for (const endpoint of [
      "membership.roleid",
      "membership.member",
      "membership.grantor",
    ]) {
      expect(digest).toContain(
        `${endpoint} NOT IN (\n        SELECT login_role.oid FROM managed_runtime_login_role AS login_role`,
      );
    }
    expect(privateReadiness).toContain("login_role.rolcanlogin");
    expect(privateReadiness).toContain(
      "SELECT * FROM actual_edge EXCEPT SELECT * FROM allowed_edge",
    );
    expect(privateReadiness).toContain(
      "role.rolvaliduntil <> 'infinity'::timestamptz",
    );
    expect(privateReadiness).toContain(
      "role.rolconnlimit <> -1 AND role.rolconnlimit <= 0",
    );
    for (const counter of [
      "runtime_login_role_mismatch_count",
      "runtime_login_membership_mismatch_count",
      "runtime_login_setting_mismatch_count",
      "runtime_login_parameter_acl_mismatch_count",
      "runtime_login_default_acl_mismatch_count",
    ]) {
      expect(privateReadiness).toContain(`${counter} = 0`);
    }
    expect(privateReadiness).toContain("pg_catalog.pg_parameter_acl");
    expect(privateReadiness).toContain("pg_catalog.pg_default_acl");
    expect(privateReadiness).toContain(
      "LEFT JOIN LATERAL pg_catalog.aclexplode(CASE",
    );
  });

  it("pins exactly the current receipt-aware MFA ABI and retires stale paths", () => {
    const privateReadiness = functionBodyFrom(
      readiness,
      "private_tenant_platform_oidc_runtime_schema_readiness_v1",
    );
    const publicReadiness = functionBodyFrom(
      readiness,
      "tenant_platform_oidc_runtime_schema_readiness_v1",
    );

    for (const signature of [
      "app.start_totp_enrollment_v1(jsonb)",
      "app.create_mfa_step_up_challenge_v1(jsonb)",
      "app.create_webauthn_ceremony_v1(jsonb)",
      "app.claim_totp_enrollment_v2(uuid,bytea,timestamp with time zone,bytea)",
      "app.claim_mfa_step_up_challenge_v2(bytea,bytea,text,timestamp with time zone,bytea)",
      "app.claim_webauthn_ceremony_v2(bytea,bytea,timestamp with time zone,bytea)",
      "app.resolve_mfa_authority_v2(uuid,text,text,text,timestamp with time zone,bytea)",
      "app.private_mfa_evidence_projection_v1(uuid,text,uuid)",
      "app.private_mfa_apply_tenant_platform_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)",
      "app.private_mfa_apply_session_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)",
    ]) {
      expect(privateReadiness).toContain(signature);
    }
    for (const staleSignature of [
      "app.claim_totp_enrollment_v1(uuid,bytea,timestamp with time zone)",
      "app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamp with time zone)",
      "app.claim_webauthn_ceremony_v1(bytea,bytea,timestamp with time zone)",
      "app.private_unbound_start_totp_enrollment_v1(jsonb)",
      "app.private_unbound_create_mfa_step_up_challenge_v1(jsonb)",
      "app.private_unbound_create_webauthn_ceremony_v1(jsonb)",
    ]) {
      expect(privateReadiness).toContain(staleSignature);
    }
    expect(privateReadiness).toContain("SELECT count(*) = 5");
    expect(privateReadiness).not.toContain(
      "app.platform_identity_provider_schema_readiness_v1()",
    );
    expect(privateReadiness).not.toContain(
      "app.tenant_platform_identity_binding_schema_readiness_v2()",
    );
    expect(publicReadiness).not.toMatch(
      /FROM\s+app\.schema_compatibility_v34\(\)/,
    );
  });

  it("prepares completion tickets without claiming or projecting a false factor", () => {
    const resolver = functionBodyFrom(
      runtime,
      "resolve_mfa_completion_artifact_v1",
    );
    const claim = functionBodyFrom(runtime, "claim_mfa_step_up_challenge_v2");

    for (const artifactKind of [
      "totp_enrollment",
      "step_up_challenge",
      "webauthn_registration",
      "webauthn_authentication",
    ]) {
      expect(resolver).toContain(`'${artifactKind}'`);
    }
    for (const projectedKey of [
      "loadedAt",
      "artifactKind",
      "artifactId",
      "browserDigest",
      "factorKind",
      "factorId",
      "flow",
      "tenantId",
      "userId",
      "identityEpoch",
      "resolvedUserId",
      "resolvedIdentityEpoch",
      "sessionId",
      "sessionFamilyId",
      "continuationId",
      "anchorVersion",
      "anchorExpiresAt",
      "action",
      "audience",
      "continuationReceiptDigest",
      "reservationDisposition",
      "reservationAuthenticationMethod",
      "resultAuthenticationMethod",
      "sourceSessionId",
      "sourceSessionFamilyId",
      "sourceSessionVersion",
      "sourceAbsoluteExpiresAt",
    ]) {
      expect(resolver).toContain(`'${projectedKey}'`);
    }
    expect(resolver).not.toContain("'claimedFactorKind'");
    expect(resolver).toContain("v_reservation_disposition := 'none'");
    expect(resolver).toContain("v_reservation_disposition := 'create'");
    expect(resolver).toContain("v_reservation_disposition := 'rotate'");
    expect(resolver).toContain(
      "public.tenant_webauthn_ceremony_credentials AS allowed",
    );
    expect(resolver).toContain("v_artifact_mode = 'known_user'");
    expect(resolver).toContain("v_artifact_mode = 'discoverable'");
    expect(resolver).toContain(
      "v_selected_credential_discoverable IS DISTINCT FROM true",
    );
    expect(resolver).toContain("v_artifact_purpose = 'primary_authentication'");
    expect(resolver).toContain("v_artifact_purpose = 'step_up_authentication'");
    expect(resolver).toContain(
      "v_artifact_purpose = 'continuation_authentication'",
    );
    expect(resolver).toContain(
      "v_result_authentication_method NOT IN (\n              'bootstrap_totp','totp','recovery_code'",
    );
    expect(claim).toContain(
      "claimed_at = v_effective_at,claimed_factor_kind = p_factor_kind",
    );
    expect(claim).not.toContain(
      "private_unbound_claim_mfa_step_up_challenge_v1(",
    );
    expect(runtime).toContain(
      "ALTER FUNCTION app.resolve_mfa_completion_artifact_v1(jsonb)",
    );
    expect(runtime).toContain("app.resolve_mfa_completion_artifact_v1(jsonb),");
  });
});
