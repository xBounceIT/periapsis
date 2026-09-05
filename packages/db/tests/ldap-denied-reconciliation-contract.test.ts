import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migration = readFileSync(
  resolve(
    import.meta.dirname,
    "../migrations/0210_ldap_denied_reconciliation.sql",
  ),
  "utf8",
);
const identitySyncSchema = readFileSync(
  resolve(import.meta.dirname, "../src/schema/identity-sync.ts"),
  "utf8",
);
const ldapAuthSchema = readFileSync(
  resolve(import.meta.dirname, "../src/schema/identity-ldap-auth.ts"),
  "utf8",
);
const identityMfaSchema = readFileSync(
  resolve(import.meta.dirname, "../src/schema/identity-mfa.ts"),
  "utf8",
);
const workerRepository = readFileSync(
  resolve(
    import.meta.dirname,
    "../../../services/worker/internal/postgres/ldap_sync.go",
  ),
  "utf8",
);
const worker = readFileSync(
  resolve(
    import.meta.dirname,
    "../../../services/worker/internal/identitysync/worker.go",
  ),
  "utf8",
);

function functionBody(name: string): string {
  const declaration = new RegExp(
    `CREATE(?: OR REPLACE)? FUNCTION app\\.${name}\\(`,
  ).exec(migration);
  if (declaration?.index === undefined) {
    throw new Error(`Missing function app.${name}`);
  }
  const bodyStart = migration.indexOf("AS $function$", declaration.index);
  const bodyEnd = migration.indexOf("$function$;", bodyStart + 13);
  if (bodyStart < 0 || bodyEnd < 0) {
    throw new Error(`Incomplete function app.${name}`);
  }
  return migration.slice(declaration.index, bodyEnd + "$function$;".length);
}

describe("LDAP denied reconciliation and session lineage", () => {
  it("permits denied applications to record only source-owned revocations", () => {
    expect(migration).toContain(
      "DROP CONSTRAINT tenant_ldap_identity_plan_applications_decision_check",
    );
    expect(migration).toContain(
      "decision='denied' AND denial_category IS NOT NULL",
    );
    expect(migration).toContain("AND ensured_edge_count=0");
    expect(migration).not.toContain(
      "decision='denied' AND denial_category IS NOT NULL\n      AND revoked_edge_count=0",
    );
    expect(identitySyncSchema).toMatch(
      /\$\{table\.decision\} = 'denied'\s+and \$\{table\.denialCategory\} is not null/,
    );
    expect(identitySyncSchema).not.toContain(
      "${table.decision} = 'denied' and ${table.revokedEdgeCount} = 0",
    );
  });

  it("re-derives exact per-user revocations and never revokes a mapping-global role grant", () => {
    const apply = functionBody("apply_tenant_ldap_sync_identity_plan_v3");

    expect(apply).toContain("p_denial_category <> 'no_mapping'");
    expect(apply).toContain("expected_revocation_epochs");
    expect(apply).toContain("tenant_security_group_memberships");
    expect(apply).toContain("operator_team_roster_entries");
    expect(apply).not.toContain(
      "UPDATE public.tenant_security_group_role_grants",
    );
    expect(worker).toContain("LDAPSecurityGroupRoleGrantEdge:");
    expect(workerRepository).toContain(
      "from app.apply_tenant_ldap_sync_identity_plan_v3(",
    );
    expect(migration).toContain(
      "REVOKE EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(",
    );
  });

  it("pins denied replay to every planning and authority input", () => {
    const apply = functionBody("apply_tenant_ldap_sync_identity_plan_v3");

    for (const comparison of [
      "existing_application.provider_id IS DISTINCT FROM locked_run.provider_id",
      "existing_application.provider_version IS DISTINCT FROM p_provider_version",
      "existing_application.configuration_version IS DISTINCT FROM p_configuration_version",
      "existing_application.binding_version IS DISTINCT FROM p_binding_version",
      "existing_application.binding_auth_revision IS DISTINCT FROM p_binding_auth_revision",
      "existing_application.binding_access_epoch_id IS DISTINCT FROM p_access_epoch_id",
      "existing_application.rule_set_revision IS DISTINCT FROM p_rule_set_revision",
      "existing_application.authorization_revision IS DISTINCT FROM p_authorization_revision",
      "existing_application.observed_at IS DISTINCT FROM p_observed_at",
    ]) {
      expect(apply).toContain(comparison);
    }
    expect(apply).toContain("reconciliation_digest");
    expect(apply).toContain("LDAP denied reconciliation replay differs");
  });

  it("preserves consecutive no-match grace and starts a new clock after recovery", () => {
    const complete = functionBody("complete_tenant_ldap_sync_enumeration_v3");
    const absence = functionBody("apply_tenant_ldap_sync_absence_chunk_v3");
    const apply = functionBody("apply_tenant_ldap_sync_identity_plan_v3");

    expect(complete).toContain("absence.latest_missing_run_id=p_sync_run_id");
    expect(complete).toContain("SET status='pending',resolved_at=NULL");
    expect(complete).toContain("observation.applied_at IS NULL");
    expect(apply).toContain(
      "SET status='cleared',resolved_at=transaction_timestamp()",
    );
    expect(absence).toContain("absence.status='cleared'");
    expect(absence).toContain("first_missing_at=transaction_timestamp()");
    expect(absence).toContain(
      "apply_after=transaction_timestamp()+make_interval(",
    );
  });

  it("retires typed LDAP authority before complete-inventory access", () => {
    const absence = functionBody("apply_tenant_ldap_sync_absence_chunk_v3");

    expect(absence).toContain("UPDATE public.auth_sessions AS session");
    expect(absence).toContain(
      "UPDATE public.tenant_post_primary_continuations AS continuation",
    );
    expect(absence).toContain(
      "session_invalidation_epoch=subject.session_invalidation_epoch+1",
    );
    expect(absence).toContain(
      "revoke_reason='ldap_identity_sync_authoritative_absence'",
    );
    expect(
      absence.indexOf("UPDATE public.auth_sessions AS session"),
    ).toBeLessThan(
      absence.lastIndexOf("FROM app.apply_tenant_ldap_sync_absence_chunk_v2("),
    );
    expect(migration).toContain(
      "FROM public.tenant_federated_provider_access_grants AS other",
    );
    expect(migration).toContain(
      "FROM public.tenant_platform_federated_provider_access_grants AS other",
    );
    expect(migration).toContain(
      "LDAP absence shared-membership patch point is ambiguous",
    );
    expect(migration).toContain(
      "LDAP continuation terminal patch point is ambiguous",
    );
  });

  it("stores immutable root and source lineage for LDAP rotate and step-up", () => {
    const apply = functionBody("private_apply_ldap_session_revalidation_v1");
    const validator = functionBody("validate_ldap_primary_provenance_v1");

    for (const field of [
      'rootJitRunId: uuid("root_jit_run_id").notNull()',
      'sourceSessionId: uuid("source_session_id")',
      'sourceSessionFamilyId: uuid("source_session_family_id")',
      'sourceSessionVersion: bigint("source_session_version"',
      'sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at"',
    ]) {
      expect(ldapAuthSchema).toContain(field);
    }
    expect(validator).toContain(
      "source_provenance.root_jit_run_id=NEW.root_jit_run_id",
    );
    expect(validator).toContain(
      "source_state.session_version=NEW.source_session_version",
    );
    expect(apply).toContain("ELSIF v_decision='rotate' THEN");
    expect(apply).toContain("revoke_reason='ldap_session_rotated'");
    expect(apply).toContain(
      "INSERT INTO public.auth_session_ldap_provenance (",
    );
    expect(apply).toContain("ELSIF v_decision='step_up' THEN");
    expect(apply).toContain(
      "INSERT INTO public.tenant_post_primary_ldap_provenance(",
    );
    expect(apply).toContain("'newSessionId',v_new_session_id::text");
    expect(apply).toContain("'continuationId',v_continuation_id::text");
  });

  it("makes delivery retry a zero-write exact successor lookup", () => {
    const apply = functionBody("private_apply_ldap_session_revalidation_v1");

    expect(apply.indexOf("IF FOUND THEN")).toBeLessThan(
      apply.indexOf("private_lock_ldap_primary_authority_v1"),
    );
    expect(apply).toContain(
      "v_existing.result_snapshot->>'newSessionId' IS DISTINCT FROM",
    );
    expect(apply).toContain(
      "v_existing.result_snapshot->>'continuationId' IS DISTINCT FROM",
    );
    expect(apply).toContain("provenance.source_session_id=v_session_id");
    expect(apply).toContain(
      "provenance.source_session_version=v_expected_version+1",
    );
  });

  it("keeps recovery replacement authority typed, internal, and one-shot", () => {
    const prepare = functionBody(
      "private_prepare_ldap_recovery_replacement_v1",
    );
    const prepareNonLdap = functionBody(
      "private_prepare_non_ldap_recovery_replacement_v1",
    );
    const finishNonLdap = functionBody(
      "private_finish_non_ldap_recovery_replacement_v1",
    );
    const apply = functionBody("private_apply_ldap_mfa_session_v1");

    expect(identityMfaSchema).toContain(
      '"tenant_mfa_ldap_recovery_replacement_capabilities"',
    );
    expect(prepare).toContain(
      "FROM public.auth_session_ldap_provenance AS provenance",
    );
    expect(prepare).toContain("provenance.session_id=v_anchor.session_id");
    expect(prepare).toContain("provenance.primary_kind='tenant_provider'");
    expect(prepare).toContain("provenance.authentication_method='ldap'");
    expect(prepare).toContain("THEN\n    RETURN;");
    expect(prepareNonLdap).toContain(
      "FROM public.auth_session_local_credential_provenance AS provenance",
    );
    expect(prepareNonLdap).toContain(
      "FROM public.auth_session_federated_provenance AS provenance",
    );
    expect(prepareNonLdap).toContain(
      "provenance.authentication_method IN ('oidc','saml')",
    );
    expect(prepareNonLdap).toContain("v_primary_count<>1");
    expect(finishNonLdap).toContain(
      "DELETE FROM public.tenant_mfa_ldap_recovery_replacement_capabilities",
    );
    expect(apply).toContain(
      "DELETE FROM public.tenant_mfa_ldap_recovery_replacement_capabilities",
    );
    expect(migration).toContain("capability.source_evidence_id=evidence.id");
    expect(migration).toContain(
      "private_finish_non_ldap_recovery_replacement_v1",
    );
    expect(migration).toContain(
      "tenant_mfa_ldap_recovery_replacement_capabilities_migrator_v1",
    );
    expect(migration).toContain(
      "'app.private_mfa_apply_passkey_session_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'::regprocedure",
    );
    expect(migration).toContain(
      "passkey recovery replacement evidence patch is ambiguous",
    );
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE\s+public\.tenant_mfa_ldap_recovery_replacement_capabilities/,
    );
  });
});
