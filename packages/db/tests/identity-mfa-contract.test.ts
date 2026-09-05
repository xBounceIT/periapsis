import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  authSessionMfaEvidence,
  authSessionMfaPolicyPins,
  authSessionLocalCredentialProvenance,
  authSessionMfaStates,
  authSessionPasskeyProvenance,
  mfaPolicyRevisions,
  tenantMfaAuthorityAnchors,
  tenantMfaAuthorityEvidence,
  tenantMfaAuthorityPolicyPins,
  tenantMfaWebauthnEvidenceCopyCapabilities,
  tenantMfaStepUpChallenges,
  tenantMfaSubjects,
  tenantPostPrimaryContinuationEvidence,
  tenantPostPrimaryPasskeyProvenance,
  tenantPostPrimaryContinuationPolicyPins,
  tenantPostPrimaryContinuations,
  tenantRecoveryCodes,
  tenantRecoveryCodeSets,
  tenantTotpEnrollments,
  tenantTotpFactors,
  tenantWebauthnCeremonies,
  tenantWebauthnCeremonyCredentials,
  tenantWebauthnCredentials,
  tenantWebauthnCredentialTransports,
} from "../src/schema/identity-mfa.js";

const source = readFileSync(
  resolve(import.meta.dirname, "../src/schema/identity-mfa.ts"),
  "utf8",
);
const foundationMigration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0117_identity_mfa_foundation.sql",
  ),
  "utf8",
);
const securityMigration = readFileSync(
  resolve(import.meta.dirname, "../migrations/0118_identity_mfa_security.sql"),
  "utf8",
);
const abiMigration = readFileSync(
  resolve(import.meta.dirname, "../migrations/0119_identity_mfa_abi.sql"),
  "utf8",
);
const readinessMigration = readFileSync(
  resolve(import.meta.dirname, "../migrations/0120_identity_mfa_readiness.sql"),
  "utf8",
);
const passkeyRuntimeMigration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0165_platform_oidc_binding_runtime.sql",
  ),
  "utf8",
);

const tenantTables = [
  tenantMfaSubjects,
  tenantTotpFactors,
  tenantRecoveryCodeSets,
  tenantRecoveryCodes,
  tenantPostPrimaryContinuations,
  tenantPostPrimaryPasskeyProvenance,
  tenantPostPrimaryContinuationEvidence,
  tenantPostPrimaryContinuationPolicyPins,
  tenantMfaAuthorityAnchors,
  tenantMfaAuthorityPolicyPins,
  tenantMfaAuthorityEvidence,
  tenantMfaWebauthnEvidenceCopyCapabilities,
  tenantMfaStepUpChallenges,
  tenantTotpEnrollments,
  tenantWebauthnCeremonies,
  tenantWebauthnCeremonyCredentials,
  tenantWebauthnCredentials,
  tenantWebauthnCredentialTransports,
  authSessionMfaStates,
  authSessionLocalCredentialProvenance,
  authSessionPasskeyProvenance,
  authSessionMfaEvidence,
  authSessionMfaPolicyPins,
] as const;

function checkNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  return getTableConfig(table).checks.map((constraint) => constraint.name);
}

function uniqueNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  const config = getTableConfig(table);
  return [
    ...config.uniqueConstraints.flatMap((constraint) =>
      constraint.name === undefined ? [] : [constraint.name],
    ),
    ...config.indexes
      .filter((index) => index.config.unique)
      .flatMap((index) =>
        index.config.name === undefined ? [] : [index.config.name],
      ),
  ];
}

function indexNames(table: Parameters<typeof getTableConfig>[0]): string[] {
  return getTableConfig(table).indexes.flatMap((index) =>
    index.config.name === undefined ? [] : [index.config.name],
  );
}

function uniqueShape(
  table: Parameters<typeof getTableConfig>[0],
  name: string,
): string[] {
  const constraint = getTableConfig(table).uniqueConstraints.find(
    (candidate) => candidate.name === name,
  );
  if (constraint === undefined) {
    throw new Error(`missing unique constraint ${name}`);
  }
  return constraint.columns.map((column) => column.name);
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

function foreignKeyShape(
  table: Parameters<typeof getTableConfig>[0],
  name: string,
): { columns: string[]; foreignTable: string; foreignColumns: string[] } {
  const foreignKey = getTableConfig(table).foreignKeys.find(
    (candidate) => candidate.getName() === name,
  );
  if (foreignKey === undefined) {
    throw new Error(`missing foreign key ${name}`);
  }
  const reference = foreignKey.reference();
  return {
    columns: reference.columns.map((column) => column.name),
    foreignTable: getTableConfig(reference.foreignTable).name,
    foreignColumns: reference.foreignColumns.map((column) => column.name),
  };
}

describe("MFA and WebAuthn canonical storage model", () => {
  it("tenant-qualifies every customer-owned record and enables deny-all RLS", () => {
    for (const table of tenantTables) {
      const config = getTableConfig(table);
      const tenant = config.columns.find(
        (column) => column.name === "tenant_id",
      );

      expect(tenant, `${config.name} must have tenant_id`).toBeDefined();
      expect(tenant?.notNull, `${config.name}.tenant_id must be required`).toBe(
        true,
      );
      expect(config.enableRLS, `${config.name} must enable RLS`).toBe(true);
      expect(
        config.policies,
        `${config.name} must expose no broad table policy`,
      ).toHaveLength(0);
    }
  });

  it("stores one-time continuations, challenges, enrollments, and ceremonies as closed state machines", () => {
    expect(checkNames(tenantPostPrimaryContinuations)).toContain(
      "tenant_post_primary_continuations_lifecycle_check",
    );
    expect(checkNames(tenantMfaStepUpChallenges)).toContain(
      "tenant_mfa_step_up_challenges_lifecycle_check",
    );
    expect(
      getTableConfig(tenantMfaStepUpChallenges).columns.map(
        (column) => column.name,
      ),
    ).toContain("claimed_factor_kind");
    expect(checkNames(tenantMfaStepUpChallenges)).toContain(
      "tenant_mfa_step_up_challenges_claimed_factor_check",
    );
    expect(checkNames(tenantMfaStepUpChallenges)).toContain(
      "tenant_mfa_step_up_challenges_claimed_factor_live_check",
    );
    expect(checkNames(tenantTotpEnrollments)).toContain(
      "tenant_totp_enrollments_lifecycle_check",
    );
    expect(checkNames(tenantWebauthnCeremonies)).toContain(
      "tenant_webauthn_ceremonies_lifecycle_check",
    );
    expect(source).toContain("and ${table.version} = 1");
    expect(source).toContain("and ${table.version} >= 2");
  });

  it("keeps credentials globally unambiguous and recovery material digest-only", () => {
    expect(uniqueNames(tenantWebauthnCredentials)).toContain(
      "tenant_webauthn_credentials_credential_id_key",
    );
    expect(uniqueNames(tenantMfaSubjects)).toContain(
      "tenant_mfa_subjects_user_handle_key",
    );
    expect(uniqueNames(tenantRecoveryCodes)).toContain(
      "tenant_recovery_codes_set_digest_key",
    );
    expect(
      getTableConfig(tenantWebauthnCredentials).columns.map(
        (column) => column.name,
      ),
    ).toEqual(expect.arrayContaining(["display_name", "security_revision"]));
    expect(checkNames(tenantWebauthnCredentials)).toContain(
      "tenant_webauthn_credentials_display_name_check",
    );
    expect(source).toContain(
      "${table.securityRevision} between 1 and 9007199254740991",
    );
    expect(source).toContain("${table.securityRevision} <= ${table.version}");

    const recoveryColumns = getTableConfig(tenantRecoveryCodes).columns.map(
      (column) => column.name,
    );
    expect(recoveryColumns).toContain("code_digest");
    expect(recoveryColumns).not.toEqual(
      expect.arrayContaining(["code", "plaintext", "secret"]),
    );
  });

  it("physically separates exact session provenance from assurance state", () => {
    expect(getTableConfig(authSessionMfaStates).name).toBe(
      "auth_session_mfa_states",
    );
    expect(getTableConfig(authSessionLocalCredentialProvenance).name).toBe(
      "auth_session_local_credential_provenance",
    );
    expect(getTableConfig(authSessionPasskeyProvenance).name).toBe(
      "auth_session_passkey_provenance",
    );
    expect(getTableConfig(authSessionMfaEvidence).name).toBe(
      "auth_session_mfa_evidence",
    );
    expect(getTableConfig(authSessionMfaPolicyPins).name).toBe(
      "auth_session_mfa_policy_pins",
    );
    expect(checkNames(authSessionMfaStates)).toEqual(
      expect.arrayContaining([
        "auth_session_mfa_states_version_check",
        "auth_session_mfa_states_primary_kind_check",
      ]),
    );
    expect(foreignKeyNames(authSessionLocalCredentialProvenance)).toEqual(
      expect.arrayContaining([
        "auth_session_local_credential_provenance_credential_fk",
        "auth_session_local_credential_provenance_state_fk",
      ]),
    );
    expect(foreignKeyNames(authSessionPasskeyProvenance)).toEqual(
      expect.arrayContaining([
        "auth_session_passkey_provenance_state_fk",
        "auth_session_passkey_provenance_credential_fk",
      ]),
    );
    expect(
      foreignKeyShape(
        authSessionPasskeyProvenance,
        "auth_session_passkey_provenance_credential_fk",
      ),
    ).toEqual({
      columns: ["tenant_id", "user_id", "credential_id"],
      foreignTable: "tenant_webauthn_credentials",
      foreignColumns: ["tenant_id", "user_id", "id"],
    });
    expect(columnNames(authSessionMfaStates)).not.toEqual(
      expect.arrayContaining([
        "primary_id",
        "provider_id",
        "provider_binding_id",
        "external_identity_id",
      ]),
    );
    expect(columnNames(tenantPostPrimaryContinuations)).toEqual(
      expect.arrayContaining(["local_credential_id", "passkey_credential_id"]),
    );
    expect(columnNames(tenantPostPrimaryContinuations)).not.toContain(
      "primary_id",
    );
    expect(foreignKeyNames(tenantPostPrimaryContinuations)).toEqual(
      expect.arrayContaining([
        "tenant_post_primary_continuations_local_credential_fk",
        "tenant_post_primary_continuations_passkey_fk",
      ]),
    );
    expect(uniqueNames(tenantPostPrimaryContinuations)).toContain(
      "tenant_post_primary_continuations_exact_passkey_key",
    );
    expect(
      uniqueShape(
        tenantPostPrimaryContinuations,
        "tenant_post_primary_continuations_exact_passkey_key",
      ),
    ).toEqual(["tenant_id", "id", "user_id", "passkey_credential_id"]);
  });

  it("pins passkey continuation authority in a typed exact child", () => {
    expect(getTableConfig(tenantPostPrimaryPasskeyProvenance).name).toBe(
      "tenant_post_primary_passkey_provenance",
    );
    expect(columnNames(tenantPostPrimaryPasskeyProvenance)).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "continuation_id",
        "user_id",
        "origin",
        "primary_kind",
        "authentication_method",
        "credential_id",
        "credential_revision",
        "authenticated_at",
        "source_session_id",
        "source_session_family_id",
        "source_session_version",
        "source_absolute_expires_at",
      ]),
    );
    expect(columnNames(tenantPostPrimaryPasskeyProvenance)).not.toEqual(
      expect.arrayContaining([
        "provider_id",
        "platform_provider_id",
        "binding_id",
        "external_identity_id",
      ]),
    );
    expect(checkNames(tenantPostPrimaryPasskeyProvenance)).toContain(
      "tenant_post_primary_passkey_provenance_value_check",
    );
    expect(indexNames(tenantPostPrimaryPasskeyProvenance)).toEqual(
      expect.arrayContaining([
        "tenant_post_primary_passkey_provenance_credential_idx",
        "tenant_post_primary_passkey_provenance_source_session_idx",
      ]),
    );
    expect(
      foreignKeyShape(
        tenantPostPrimaryPasskeyProvenance,
        "tenant_post_primary_passkey_provenance_continuation_fk",
      ),
    ).toEqual({
      columns: ["tenant_id", "continuation_id", "user_id", "credential_id"],
      foreignTable: "tenant_post_primary_continuations",
      foreignColumns: ["tenant_id", "id", "user_id", "passkey_credential_id"],
    });
    expect(
      foreignKeyShape(
        tenantPostPrimaryPasskeyProvenance,
        "tenant_post_primary_passkey_provenance_credential_fk",
      ),
    ).toEqual({
      columns: ["tenant_id", "user_id", "credential_id"],
      foreignTable: "tenant_webauthn_credentials",
      foreignColumns: ["tenant_id", "user_id", "id"],
    });
    expect(source).toContain("${table.origin} = 'initial_login'");
    expect(source).toContain("${table.origin} = 'session_revalidation'");
    expect(source).toContain(
      "${table.sourceAbsoluteExpiresAt} > ${table.authenticatedAt}",
    );
  });

  it("forces and revokes direct passkey provenance table access", () => {
    expect(passkeyRuntimeMigration).toContain(
      "ALTER TABLE public.tenant_post_primary_passkey_provenance\n  OWNER TO periapsis_migrator",
    );
    expect(passkeyRuntimeMigration).toContain(
      "ALTER TABLE public.tenant_post_primary_passkey_provenance\n  FORCE ROW LEVEL SECURITY",
    );
    expect(passkeyRuntimeMigration).toContain(
      "REVOKE ALL ON TABLE public.tenant_post_primary_passkey_provenance",
    );
    expect(passkeyRuntimeMigration).not.toContain(
      "GRANT SELECT ON TABLE public.tenant_post_primary_passkey_provenance",
    );
  });

  it("drains every pre-v35 MFA writer without waiting on opposing lock orders", () => {
    const cutover = passkeyRuntimeMigration.indexOf(
      "DO $v35_mfa_quiesced_cutover$",
    );
    const firstSchemaMutation = passkeyRuntimeMigration.indexOf(
      "ALTER TABLE public.tenant_post_primary_passkey_provenance",
    );
    expect(cutover).toBeGreaterThanOrEqual(0);
    expect(cutover).toBeLessThan(firstSchemaMutation);
    for (const role of [
      "periapsis_api_login",
      "periapsis_worker_login",
      "periapsis_notifier_login",
    ]) {
      expect(
        passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
      ).toContain(`'${role}'`);
    }
    expect(
      passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
    ).toContain("role.rolcanlogin");
    expect(
      passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
    ).toContain("WITH RECURSIVE writer_principal(role_oid)");
    expect(
      passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
    ).toContain("pg_catalog.pg_auth_members AS membership");
    expect(
      passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
    ).toContain("pg_catalog.pg_stat_activity");
    expect(
      passkeyRuntimeMigration.slice(cutover, firstSchemaMutation),
    ).toContain("activity.pid <> pg_backend_pid()");

    for (const table of [
      "tenant_webauthn_ceremonies",
      "tenant_webauthn_credentials",
      "tenant_totp_enrollments",
      "tenant_mfa_step_up_challenges",
      "tenant_post_primary_continuations",
      "auth_sessions",
      "auth_session_mfa_states",
      "auth_session_local_credential_provenance",
      "auth_session_passkey_provenance",
      "auth_session_federated_provenance",
      "auth_session_tenant_platform_federated_provenance",
    ]) {
      expect(passkeyRuntimeMigration).toContain(
        `LOCK TABLE ONLY public.${table}`,
      );
      const lockStart = passkeyRuntimeMigration.indexOf(
        `LOCK TABLE ONLY public.${table}`,
      );
      expect(lockStart).toBeGreaterThanOrEqual(0);
      expect(
        passkeyRuntimeMigration.slice(lockStart, lockStart + 180),
      ).toContain("IN EXCLUSIVE MODE NOWAIT");
    }
    expect(passkeyRuntimeMigration).toContain(
      "any in-flight writer makes\n-- this migration transaction fail for an outer retry",
    );
  });

  it("scopes WebAuthn evidence-copy capabilities to one backend transaction", () => {
    expect(getTableConfig(tenantMfaWebauthnEvidenceCopyCapabilities).name).toBe(
      "tenant_mfa_webauthn_evidence_copy_capabilities",
    );
    expect(columnNames(tenantMfaWebauthnEvidenceCopyCapabilities)).toEqual(
      expect.arrayContaining([
        "tenant_id",
        "source_anchor_id",
        "source_evidence_id",
        "destination_session_id",
        "backend_pid",
        "transaction_id",
        "user_id",
        "factor_kind",
        "credential_id",
        "source_revision",
        "target_revision",
        "source_level",
        "target_level",
        "source_authenticated_at",
        "source_expires_at",
        "target_authenticated_at",
        "consumed_evidence_id",
        "consumed_at",
      ]),
    );
    expect(checkNames(tenantMfaWebauthnEvidenceCopyCapabilities)).toContain(
      "tenant_mfa_webauthn_evidence_copy_capabilities_value_check",
    );
    expect(uniqueNames(tenantMfaWebauthnEvidenceCopyCapabilities)).toContain(
      "tenant_mfa_webauthn_evidence_copy_capabilities_destination_key",
    );
    expect(
      foreignKeyShape(
        tenantMfaWebauthnEvidenceCopyCapabilities,
        "tenant_mfa_webauthn_evidence_copy_capabilities_source_fk",
      ),
    ).toEqual({
      columns: ["tenant_id", "source_anchor_id", "source_evidence_id"],
      foreignTable: "tenant_mfa_authority_evidence",
      foreignColumns: ["tenant_id", "anchor_id", "id"],
    });
    expect(
      foreignKeyShape(
        tenantMfaWebauthnEvidenceCopyCapabilities,
        "tenant_mfa_webauthn_evidence_copy_capabilities_credential_fk",
      ),
    ).toEqual({
      columns: ["tenant_id", "user_id", "credential_id"],
      foreignTable: "tenant_webauthn_credentials",
      foreignColumns: ["tenant_id", "user_id", "id"],
    });
    expect(passkeyRuntimeMigration).toContain(
      "ALTER TABLE public.tenant_mfa_webauthn_evidence_copy_capabilities\n  FORCE ROW LEVEL SECURITY",
    );
    expect(passkeyRuntimeMigration).toContain(
      "REVOKE ALL ON TABLE\n  public.tenant_mfa_webauthn_evidence_copy_capabilities",
    );
    expect(passkeyRuntimeMigration).not.toMatch(
      /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)[^;]+tenant_mfa_webauthn_evidence_copy_capabilities/i,
    );
  });

  it("uses typed local assurance references and an exact provider binding", () => {
    const typedEvidence = [
      [
        tenantPostPrimaryContinuationEvidence,
        "tenant_post_primary_continuation_evidence_value_check",
        "tenant_post_primary_continuation_evidence",
      ],
      [
        tenantMfaAuthorityEvidence,
        "tenant_mfa_authority_evidence_level_kind_check",
        "tenant_mfa_authority_evidence",
      ],
      [
        authSessionMfaEvidence,
        "auth_session_mfa_evidence_typed_source_check",
        "auth_session_mfa_evidence",
      ],
    ] as const;

    for (const [table, checkName, prefix] of typedEvidence) {
      expect(columnNames(table)).toEqual(
        expect.arrayContaining([
          "local_credential_id",
          "totp_factor_id",
          "webauthn_credential_id",
          "recovery_code_set_id",
          "provider_id",
          "binding_id",
        ]),
      );
      expect(columnNames(table)).not.toEqual(
        expect.arrayContaining(["factor_id", "source_kind"]),
      );
      expect(checkNames(table)).toContain(checkName);
      expect(foreignKeyNames(table)).toEqual(
        expect.arrayContaining([
          `${prefix}_local_credential_fk`,
          `${prefix}_totp_fk`,
          `${prefix}_webauthn_fk`,
          `${prefix}_recovery_fk`,
          `${prefix}_provider_binding_fk`,
        ]),
      );
      expect(foreignKeyShape(table, `${prefix}_local_credential_fk`)).toEqual({
        columns: ["local_credential_id"],
        foreignTable: "local_break_glass_credentials",
        foreignColumns: ["id"],
      });
      expect(foreignKeyShape(table, `${prefix}_totp_fk`)).toEqual({
        columns: ["tenant_id", "totp_factor_id"],
        foreignTable: "tenant_totp_factors",
        foreignColumns: ["tenant_id", "id"],
      });
      expect(foreignKeyShape(table, `${prefix}_webauthn_fk`)).toEqual({
        columns: ["tenant_id", "webauthn_credential_id"],
        foreignTable: "tenant_webauthn_credentials",
        foreignColumns: ["tenant_id", "id"],
      });
      expect(foreignKeyShape(table, `${prefix}_recovery_fk`)).toEqual({
        columns: ["tenant_id", "recovery_code_set_id"],
        foreignTable: "tenant_recovery_code_sets",
        foreignColumns: ["tenant_id", "id"],
      });
      expect(foreignKeyShape(table, `${prefix}_provider_binding_fk`)).toEqual({
        columns: ["tenant_id", "binding_id", "provider_id"],
        foreignTable: "tenant_auth_provider_bindings",
        foreignColumns: ["tenant_id", "id", "provider_id"],
      });
    }
    expect(source.split("and ${table.level} = 'primary'")).toHaveLength(4);
    expect(source.split("and ${table.level} = 'mfa'")).toHaveLength(7);
  });

  it("separates role and security-group policy targets with exact foreign keys", () => {
    for (const table of [tenantMfaAuthorityPolicyPins, mfaPolicyRevisions]) {
      expect(columnNames(table)).toEqual(
        expect.arrayContaining(["role_id", "security_group_id"]),
      );
      expect(columnNames(table)).not.toContain("target_id");
    }
    expect(foreignKeyNames(tenantMfaAuthorityPolicyPins)).toEqual(
      expect.arrayContaining([
        "tenant_mfa_authority_policy_pins_role_fk",
        "tenant_mfa_authority_policy_pins_security_group_fk",
      ]),
    );
    expect(foreignKeyNames(mfaPolicyRevisions)).toEqual(
      expect.arrayContaining([
        "mfa_policy_revisions_role_fk",
        "mfa_policy_revisions_security_group_fk",
      ]),
    );
    expect(checkNames(mfaPolicyRevisions)).toContain(
      "mfa_policy_revisions_scope_check",
    );
    expect(source).not.toContain('uuid("target_id")');
  });

  it("never models raw recovery, TOTP, browser, or assertion values", () => {
    expect(source).not.toMatch(/password|assertion|client_data|signature/i);
    expect(source).not.toMatch(/recovery_code[^\n]*(plaintext|value)/i);
    expect(source).not.toMatch(/browser_handle/i);
    expect(source).toContain('bytea("receipt_digest")');
    expect(source).toContain('bytea("browser_digest")');
    expect(source).toContain('bytea("secret_envelope")');
  });

  it("generates typed storage and a deny-all runtime table boundary", () => {
    expect(foundationMigration.match(/^CREATE TABLE /gm)).toHaveLength(22);
    expect(foundationMigration).toContain(
      'CONSTRAINT "mfa_policy_revisions_role_fk" FOREIGN KEY ("tenant_id","role_id")',
    );
    expect(foundationMigration).toContain(
      'CONSTRAINT "mfa_policy_revisions_security_group_fk" FOREIGN KEY ("tenant_id","security_group_id")',
    );
    expect(securityMigration).toContain(
      "FOREACH relation_name IN ARRAY ARRAY[",
    );
    expect(securityMigration).toContain(
      "ALTER TABLE public.%I FORCE ROW LEVEL SECURITY",
    );
    expect(securityMigration).toContain(
      "REVOKE ALL ON TABLE public.%I FROM PUBLIC, periapsis_api",
    );
    expect(securityMigration).not.toMatch(
      /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)[^;]+tenant_(?:mfa|webauthn)/i,
    );
    expect(securityMigration).toContain(
      "CREATE CONSTRAINT TRIGGER auth_session_mfa_states_provenance_v1",
    );
    expect(securityMigration).toContain(
      "CREATE TRIGGER auth_session_mfa_evidence_subject_v1",
    );
  });

  it("exposes only bounded lifecycle functions and persists replay-safe session material", () => {
    for (const signature of [
      "resolve_mfa_authority_v1",
      "admit_mfa_operation_v1",
      "complete_totp_enrollment_v1",
      "replace_mfa_recovery_codes_v1",
      "complete_mfa_totp_step_up_v1",
      "complete_mfa_recovery_step_up_v1",
      "complete_mfa_passkey_registration_v1",
      "complete_mfa_passkey_authentication_v1",
    ]) {
      expect(abiMigration).toContain(`CREATE FUNCTION app.${signature}`);
    }
    expect(abiMigration).toContain(
      "CREATE FUNCTION app.private_mfa_apply_session_v1(",
    );
    expect(abiMigration).toContain(
      "app.private_mfa_decode_base64_v1(v_reservation ->> 'tokenDigest', 32, 32)",
    );
    expect(abiMigration).toContain("v_idle_expires_at > v_absolute_expires_at");
    expect(abiMigration).toContain(
      "v_idle_expires_at > p_completed_at + interval '24 hours'",
    );
    expect(abiMigration).toContain(
      "v_absolute_expires_at > p_completed_at + interval '31 days'",
    );
    expect(abiMigration).toContain("v_token_digest = v_csrf_digest");
    expect(abiMigration).toContain("pg_advisory_xact_lock");
    expect(abiMigration).toContain("active TOTP factor limit reached");
    expect(abiMigration).toContain("active passkey limit reached");
    expect(abiMigration).toContain("MFA evidence snapshot limit reached");
    expect(abiMigration).toContain(
      "completion_request_digest = v_request_digest, result_snapshot = v_result",
    );
    expect(abiMigration).toContain(
      "'requirement', v_policy_snapshot -> 'requirement'",
    );
    expect(abiMigration).toContain(
      "v_snapshot -> 'baselineEvidence' IS DISTINCT FROM p_binding -> 'baselineEvidence'",
    );
    expect(abiMigration).toContain(
      "OR v_user_id IS DISTINCT FROM p_expected_user_id",
    );
    expect(abiMigration).toContain(
      "set_config('app.user_id', p_expected_user_id::text, true)",
    );
    expect(abiMigration).toContain(
      "sha256(convert_to(p_request::text, 'UTF8'))",
    );
    expect(abiMigration).not.toMatch(/\bdigest\s*\([^)]*,\s*'sha256'/i);
    expect(abiMigration).not.toMatch(
      /token(?:Value|Secret)|csrf(?:Value|Secret)/i,
    );
    expect(abiMigration).toContain(
      "REVOKE ALL ON FUNCTION %s FROM PUBLIC, periapsis_api",
    );
    expect(abiMigration).toContain(
      "GRANT EXECUTE ON FUNCTION app.complete_mfa_passkey_authentication_v1(jsonb) TO periapsis_api",
    );
    expect(abiMigration).toContain(
      "CREATE FUNCTION app.private_mfa_complete_webauthn_registration_v1",
    );
    expect(abiMigration).not.toContain("app.mfa_passkey_display_name");
    expect(abiMigration).toContain(
      "CREATE FUNCTION app.private_mfa_complete_webauthn_authentication_v1",
    );
    expect(abiMigration).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.private_mfa_complete_webauthn_(?:registration|authentication)_v1/i,
    );
    expect(abiMigration).not.toMatch(
      /CREATE FUNCTION app\.complete_webauthn_(?:registration|authentication)_v1/i,
    );
  });

  it("rotates exact compatibility and makes MFA readiness substantive", () => {
    expect(readinessMigration).toContain(
      "CREATE FUNCTION app.schema_compatibility_v24()",
    );
    expect(readinessMigration).toContain("journal_count = 121");
    expect(readinessMigration).toContain(
      "journal_latest_created_at = 1787716104120",
    );
    expect(readinessMigration).toContain(
      "WHERE prefix.migration_ordinal = 117",
    );
    expect(readinessMigration).toContain(
      "predecessor_latest_created_at IS DISTINCT FROM 1787711774160",
    );
    expect(readinessMigration).toContain(
      "428a381a9463bb2c4358d0c5dba2465e5acd72326d5296dbfb895c806e2fb159",
    );
    expect(readinessMigration).toContain(
      "CREATE FUNCTION app.identity_mfa_schema_readiness_v1()",
    );
    expect(readinessMigration).toContain(
      "AND class.relrowsecurity\n        AND class.relforcerowsecurity",
    );
    expect(readinessMigration).toContain(
      "has_function_privilege('periapsis_api', function_oid, 'EXECUTE')",
    );
    expect(readinessMigration).toContain(
      "procedure.proname LIKE 'private_mfa_%'",
    );
    expect(readinessMigration).toContain(
      "to_regprocedure('app.complete_webauthn_registration_v1(jsonb)') IS NOT NULL",
    );
    expect(readinessMigration).toContain(
      "RETURN current_count = 121 AND predecessor_count = 117",
    );
  });
});
