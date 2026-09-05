import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const schema = readFileSync(
  resolve(packageRoot, "src/schema/identity-federation.ts"),
  "utf8",
);
const platformSamlSchema = readFileSync(
  resolve(packageRoot, "src/schema/identity-platform-saml-login.ts"),
  "utf8",
);
const migration = readFileSync(
  resolve(packageRoot, "migrations/0228_tenant_federation_administration.sql"),
  "utf8",
);
const ldapMigration = readFileSync(
  resolve(packageRoot, "migrations/0210_ldap_denied_reconciliation.sql"),
  "utf8",
);
const familyRouterMigration = readFileSync(
  resolve(packageRoot, "migrations/0165_platform_oidc_binding_runtime.sql"),
  "utf8",
);

function finalSqlBody(name: string, source = migration): string {
  const starts = [
    source.lastIndexOf(`CREATE FUNCTION app.${name}`),
    source.lastIndexOf(`CREATE OR REPLACE FUNCTION app.${name}`),
  ];
  const start = Math.max(...starts);
  expect(start, `${name} must exist`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("--> statement-breakpoint", start);
  expect(end, `${name} must have a migration boundary`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("OIDC session material and logout lifecycle", () => {
  it("models a tri-scope, expiring envelope vault without access tokens", () => {
    const start = migration.indexOf(
      "CREATE TABLE public.tenant_oidc_session_materials",
    );
    const end = migration.indexOf(
      "CREATE TABLE public.tenant_oidc_logout_commands",
      start,
    );
    const table = migration.slice(start, end);

    expect(schema).toContain("export const tenantOidcSessionMaterials");
    expect(schema).toContain('authority: text("authority").notNull()');
    expect(schema).toContain('expiresAt: timestamp("expires_at"');
    expect(schema).toContain('idTokenDigest: bytea("id_token_digest")');
    expect(schema).toContain(
      'refreshClaimExpiresAt: timestamp("refresh_claim_expires_at"',
    );
    expect(schema).toContain(
      "tenant_oidc_session_materials_id_token_keyring_fk",
    );
    expect(schema).toContain(
      "tenant_oidc_session_materials_refresh_keyring_fk",
    );
    expect(table).toContain("id_token_ciphertext bytea");
    expect(table).toContain("refresh_token_ciphertext bytea");
    expect(table).toContain("refresh_claim_expires_at timestamptz");
    expect(migration).toContain(
      "octet_length(id_token_ciphertext) BETWEEN 29 AND 262172",
    );
    expect(migration).toContain(
      "octet_length(refresh_token_ciphertext) BETWEEN 29 AND 262172",
    );
    expect(migration).toContain(
      "authority IN ('tenant_provider','tenant_platform_provider')",
    );
    expect(migration).toContain(
      "authority = 'platform_provider'\n        AND tenant_id IS NULL AND binding_id IS NULL",
    );
    expect(migration).not.toMatch(/access_token/i);
  });

  it("atomically persists optional material in all three OIDC apply paths", () => {
    const generic = finalSqlBody(
      "apply_federated_authentication_v1(p_command jsonb)",
    );
    const tenantPlatform = finalSqlBody(
      "private_apply_tenant_platform_oidc_material_v1(\n  p_command jsonb",
    );
    const direct = finalSqlBody(
      "apply_platform_oidc_authentication_v1(p_command jsonb)",
    );

    for (const body of [generic, tenantPlatform, direct]) {
      expect(body).toContain(
        "INSERT INTO public.tenant_oidc_session_materials",
      );
      expect(body).toContain("v_has_material IS DISTINCT FROM (");
      expect(body).toContain("allow_refresh_token");
      expect(body).toContain("end_session_endpoint");
      expect(body).toContain("id_token_digest");
      expect(body).not.toMatch(/accessToken|access_token/);
    }
    expect(generic).toContain(
      "RETURN app.private_apply_tenant_platform_oidc_material_v1(p_command)",
    );
    expect(direct).toContain("'materialId','oidcSession','validUntil'");
    expect(direct).toContain("v_expires_at > v_valid_until");
    expect(direct).toContain(
      "p_command - 'materialId' - 'oidcSession' - 'validUntil'",
    );
  });

  it("compares plaintext digests on replay and keeps owner moves unambiguous", () => {
    expect(migration).toContain(
      "v_existing.id_token_digest IS DISTINCT FROM v_id_digest",
    );
    expect(migration).toContain(
      "v_existing.refresh_token_digest IS DISTINCT FROM v_refresh_digest",
    );
    expect(migration).not.toContain(
      "v_existing.id_token_ciphertext IS DISTINCT FROM v_id_cipher",
    );
    expect(migration).not.toContain(
      "v_existing.refresh_token_ciphertext IS DISTINCT FROM v_refresh_cipher",
    );
    expect(migration).toContain(
      "continuation_id = (p_mutation #>> '{continuation,continuationId}')::uuid",
    );
    expect(migration).toContain(
      "session_id = (p_command #>> '{session,id}')::uuid",
    );
    expect(migration).toContain(
      "session_id = (p_request #>> '{session,id}')::uuid",
    );
    expect(migration).toContain(
      "session_id = (reservation ->> 'sessionId')::uuid",
    );
    expect(migration).not.toMatch(
      /SET\s+session_id\s*=\s*NULL\s*,\s*continuation_id\s*=\s*continuation_id/i,
    );
    expect(migration).not.toMatch(
      /SET\s+session_id\s*=\s*session_id\s*,\s*continuation_id\s*=\s*NULL/i,
    );
  });

  it("attests material-less owner changes through exact immutable lineage", () => {
    const direct = finalSqlBody(
      "private_direct_platform_oidc_material_absence_attested_v1(\n  p_session_id uuid",
    );
    const tenant = finalSqlBody(
      "private_tenant_platform_oidc_material_absence_attested_v1(\n  p_tenant_id uuid",
    );
    const correctionStart = migration.indexOf(
      "-- Correct the six owner-transfer paths installed above.",
    );
    const correctionEnd = migration.indexOf(
      "-- The tenant-platform session ABI was introduced by the OIDC slice",
      correctionStart,
    );
    const corrections = migration.slice(correctionStart, correctionEnd);

    for (const body of [direct, tenant]) {
      expect(body).toContain("LANGUAGE sql\nSTABLE\nSECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(body).toContain(
        "JOIN ONLY public.platform_oidc_discovery_snapshots",
      );
      expect(body).toContain("transaction.state = 'completed'");
      expect(body).toContain("transaction.completed_at =");
      expect(body).toContain("transaction.allow_refresh_token OR nullif(");
      expect(body).toContain("->> 'end_session_endpoint',''");
      expect(body).toContain("count(*) >= 1 AND bool_and(");
      expect(body).toContain("EXCEPT ALL");
    }
    expect(direct).toContain("WITH RECURSIVE current_session AS MATERIALIZED");
    expect(direct).toContain("parent.id = ancestry.rotated_from_session_id");
    expect(direct).toContain(
      "parent.rotation_family_id = current.rotation_family_id",
    );
    expect(direct).toContain("application.session_id = origin_session.id");
    expect(direct).toContain(
      "public.platform_post_primary_continuations AS continuation",
    );
    expect(direct).toContain("continuation.origin = 'initial_login'");
    expect(direct).toContain(
      "public.platform_post_primary_continuation_evidence AS evidence",
    );
    expect(direct).toContain("continuation.state = 'consumed'");
    expect(direct).toContain(
      "continuation.consumed_at = family_root.created_at",
    );
    expect(direct).toContain(
      "public.platform_oidc_authentication_transactions AS transaction",
    );

    expect(tenant).toContain(
      "public.tenant_platform_oidc_authentication_applications",
    );
    expect(tenant).toContain(
      "public.tenant_platform_oidc_authentication_transactions",
    );
    expect(tenant).toContain(
      "public.tenant_post_primary_platform_federated_provenance",
    );
    expect(tenant).toContain(
      "public.tenant_post_primary_platform_federated_evidence",
    );
    expect(tenant).toContain(
      "application.continuation_id = p_initial_continuation_id",
    );
    expect(tenant).toContain("continuation_owner.state = 'consumed'");
    expect(tenant).toContain(
      "continuation_owner.consumed_at = family_root.created_at",
    );
    expect(tenant).toContain(
      "successor.created_at = continuation_owner.consumed_at",
    );
    expect(tenant).toContain(
      "public.platform_oidc_tenant_switch_commands AS switch",
    );
    expect(tenant).toContain("switch.rotated_session_id = ancestry.session_id");
    expect(tenant).toContain(
      "app.private_direct_platform_oidc_material_absence_attested_v1(\n             switch.source_session_id",
    );
    expect(tenant).toContain(
      "NOT (\n    EXISTS (SELECT 1 FROM tenant_candidates)\n    AND EXISTS (SELECT 1 FROM switch_candidates)",
    );
    expect(tenant).toContain("(SELECT count(*) FROM switch_candidates) <= 1");

    expect(corrections).toContain("length(v_owner_old) <> 2");
    expect(corrections).toContain("length(v_old) <> 2");
    expect(
      corrections.match(
        /private_tenant_platform_oidc_material_absence_attested_v1\(/g,
      ),
    ).toHaveLength(2);
    expect(
      corrections.match(
        /private_direct_platform_oidc_material_absence_attested_v1\(/g,
      ),
    ).toHaveLength(2);
    expect(corrections).toContain("tenant_id,session_id,NULL");
    expect(corrections).toContain(
      "CASE WHEN source_bound THEN source_session.id\n         ELSE (reservation ->> 'sessionId')::uuid END",
    );
    expect(corrections).toContain(
      "CASE WHEN source_bound THEN NULL ELSE anchor_record.continuation_id END",
    );
    expect(corrections).toContain("(p_command ->> 'sessionId')::uuid");
    expect(corrections).toContain("(p_request #>> '{session,id}')::uuid");
    expect(corrections).toContain("IF NOT FOUND AND NOT EXISTS (");
    expect(corrections).toContain(
      "app.private_oidc_material_effective_session_v1(origin.id)",
    );
    expect(corrections).not.toMatch(
      /GRANT EXECUTE ON FUNCTION\s+app\.private_(?:direct|tenant)_platform_oidc_material_absence_attested_v1/u,
    );
    expect(migration).toContain(
      "ALTER FUNCTION app.private_direct_platform_oidc_material_absence_attested_v1(uuid)\n  OWNER TO periapsis_migrator",
    );
    expect(migration).toContain(
      "app.private_tenant_platform_oidc_material_absence_attested_v1(uuid,uuid,uuid)\n  OWNER TO periapsis_migrator",
    );
  });

  it("detects refresh reuse and uses ABA-safe bounded worker leases", () => {
    const claim = finalSqlBody(
      "claim_tenant_oidc_refresh_rotation_v1(\n  p_command jsonb",
    );
    const complete = finalSqlBody(
      "complete_tenant_oidc_refresh_rotation_v1(\n  p_command jsonb",
    );

    expect(schema).toContain("export const tenantOidcConsumedRefreshTokens");
    expect(claim).toContain(
      "FROM public.tenant_oidc_consumed_refresh_tokens AS consumed",
    );
    expect(claim).toContain("OR consumed.token_digest = v_expected_digest");
    expect(claim).toContain("v_material.refresh_state = 'claimed'");
    expect(claim).toContain("'category','reuse'");
    const reuseStart = claim.indexOf("IF v_reuse THEN");
    const reuseEnd = claim.indexOf(
      "IF v_material.refresh_state <> 'ready'",
      reuseStart,
    );
    const reuse = claim.slice(reuseStart, reuseEnd);
    expect(reuseStart).toBeGreaterThan(-1);
    expect(reuseEnd).toBeGreaterThan(reuseStart);
    expect(reuse).toContain(
      "uuidv7(),v_effective_tenant_id,0,v_claimed_at,'system',NULL",
    );
    expect(reuse).toContain(
      "uuidv7(),'system',NULL,'platform.identity.oidc_refresh_reuse'",
    );
    expect(reuse).not.toContain("'user',v_material.user_id");
    expect(claim).toContain("refresh_claim_expires_at <= v_claimed_at");
    expect(claim).toContain("v_claimed_at + interval '2 minutes'");
    expect(claim).toContain("'version',v_material.refresh_version");
    expect(complete).toContain(
      "'rotated','safe_to_retry','local_dependency_unavailable'",
    );
    expect(complete).toContain("'ambiguous','rejected'");
    expect(complete).toContain("material.refresh_version = v_expected_version");
    expect(complete).toContain(
      "v_outcome IN ('ambiguous','rejected')\n      OR material.refresh_claim_expires_at > v_completed_at",
    );
    expect(complete).toContain(
      "least(v_session.absolute_expires_at,v_material.expires_at)",
    );
    expect(claim).toContain("v_expected_generation >= 9000000000000000");
    expect(claim).toContain("v_material.refresh_version >= 8999999999999998");
    expect(claim).toContain("'oidc_refresh_version_exhausted'");
    expect(complete).toContain("v_expected_version >= 8999999999999999");
    expect(complete).toContain("v_successor_generation >= 9000000000000000");
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION\n  app.claim_tenant_oidc_refresh_rotation_v1(jsonb)",
    );
    expect(migration).toContain("TO periapsis_worker;");
  });

  it("revokes locally through a content-free one-use continuation", () => {
    const revoke = finalSqlBody(
      "revoke_local_session_for_logout_v1(p_command jsonb)",
    );
    const claim = finalSqlBody(
      "claim_session_logout_continuation_v1(p_request jsonb)",
    );

    expect(migration).toContain(
      "CREATE OR REPLACE FUNCTION app.resolve_session_for_logout_v1(\n  p_token_digest bytea",
    );
    expect(revoke).not.toContain("expectedVersion");
    expect(revoke).toContain("session.token_digest = v_token_digest");
    expect(revoke).toContain("'category','revoked_local_only'");
    expect(revoke).toContain("'category','logout_continuation'");
    expect(revoke).toContain("IF v_session.revoked_at IS NOT NULL THEN");
    expect(
      revoke.indexOf("IF v_session.revoked_at IS NOT NULL THEN"),
    ).toBeLessThan(revoke.indexOf("SELECT material.* INTO v_oidc"));
    expect(revoke).toContain("INSERT INTO public.session_logout_continuations");
    expect(revoke).toContain(
      "pg_advisory_xact_lock(hashtextextended(v_family_id::text,90174213))",
    );
    expect(revoke.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      revoke.indexOf("FOR UPDATE;"),
    );
    expect(revoke).toContain(
      "v_continuation_expires_at > v_requested_at + interval '2 minutes'",
    );
    expect(revoke).not.toMatch(
      /membership\.status|local_user\.active|tenant\.status/,
    );
    expect(claim).toContain("SET consumed_at = v_claimed_at");
    expect(claim.indexOf("SET consumed_at = v_claimed_at")).toBeLessThan(
      claim.indexOf("id_token_ciphertext"),
    );
    expect(claim).toContain("'category','oidc_end_session'");
    expect(claim).toContain(
      "'postLogoutRedirectUri',v_oidc.post_logout_redirect_uri",
    );
    expect(claim).toContain("material.post_logout_redirect_uri IS NOT NULL");
    expect(claim).toContain("'category','saml_logout'");
    expect(claim).toContain("'expiresAt',to_jsonb(v_continuation.expires_at)");
    expect(claim).toContain("v_platform_saml.logout_configuration");
    expect(claim).toContain(
      "v_platform_saml.nonce || v_platform_saml.ciphertext",
    );
    expect(claim).toContain("'bindingId',NULL");
    expect(platformSamlSchema).toContain(
      'logoutConfiguration: jsonb("logout_configuration")',
    );

    const constraintStart = migration.lastIndexOf(
      "ADD CONSTRAINT tenant_oidc_logout_commands_value_check CHECK",
    );
    const ledger = migration.slice(
      constraintStart,
      migration.indexOf("--> statement-breakpoint", constraintStart),
    );
    expect(ledger).toContain("request_snapshot::text !~*");
    expect(ledger).toContain("result_snapshot::text !~*");
    expect(ledger).toContain(
      "ciphertext|keyVersion|idToken|refreshToken|secret",
    );
  });

  it("reclaims leases through exact bounded maintenance phases", () => {
    const claimRetry = finalSqlBody(
      "claim_tenant_oidc_logout_retry_v1(\n  p_request jsonb",
    );
    const completeRetry = finalSqlBody(
      "complete_tenant_oidc_logout_retry_v1(\n  p_request jsonb",
    );
    const maintenance = finalSqlBody(
      "claim_due_oidc_maintenance_v1(p_request jsonb)",
    );
    const accessExpiry = finalSqlBody(
      "expire_oidc_access_lease_v1(p_request jsonb)",
    );
    const cleanup = finalSqlBody(
      "cleanup_federated_maintenance_retention_v1(\n  p_request jsonb",
    );
    const prune = finalSqlBody(
      "prune_expired_auth_state(\n  p_per_class_batch_size integer",
    );

    expect(claimRetry).toContain(
      "v_job.state = 'claimed' AND v_job.claim_expires_at > v_observed_at",
    );
    expect(claimRetry).toContain("'claimVersion',v_job.version");
    expect(claimRetry).toContain(
      "'leaseExpiresAt',to_jsonb(v_job.claim_expires_at)",
    );
    expect(claimRetry).toContain("'tokenDigest'");
    expect(claimRetry).toContain("v_job.version >= 8999999999999998");
    expect(claimRetry.indexOf("SELECT job.session_family_id")).toBeLessThan(
      claimRetry.indexOf("pg_advisory_xact_lock"),
    );
    expect(claimRetry.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      claimRetry.indexOf("SELECT job.* INTO v_job"),
    );
    expect(completeRetry).toContain(
      "'succeeded','safe_to_retry','local_dependency_unavailable'",
    );
    expect(completeRetry).toContain("'ambiguous','rejected'");
    expect(completeRetry).toContain("job.version = v_expected_version");
    expect(completeRetry).toContain("v_expected_version >= 8999999999999999");
    expect(completeRetry).toContain(
      "AND v_completed_at >= v_job.claim_expires_at",
    );
    for (const projection of [
      "effective.session_id AS effective_session_id",
      "effective.tenant_id AS effective_tenant_id",
      "effective.authority AS effective_authority",
      "effective.binding_id AS effective_binding_id",
    ]) {
      expect(completeRetry).toContain(projection);
    }
    expect(completeRetry).toContain(
      "IF v_effective_tenant_id IS NOT NULL THEN",
    );
    expect(completeRetry).toContain(
      "uuidv7(),v_effective_tenant_id,0,v_completed_at,'system',NULL",
    );
    expect(completeRetry).toContain("v_effective_session_id,'oidc','failure'");
    expect(completeRetry).not.toContain(
      "uuidv7(),v_job.tenant_id,0,v_completed_at,'system',NULL",
    );
    expect(completeRetry.indexOf("SELECT job.session_family_id")).toBeLessThan(
      completeRetry.indexOf("pg_advisory_xact_lock"),
    );
    expect(completeRetry.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      completeRetry.indexOf("SELECT job.* INTO v_job"),
    );
    expect(maintenance).not.toContain("FOR UPDATE OF job SKIP LOCKED LIMIT 1");
    expect(maintenance).toContain("FOR UPDATE OF material SKIP LOCKED LIMIT 1");
    expect(maintenance).toContain(
      "AND material.refresh_claim_expires_at <= v_observed_at",
    );
    expect(maintenance).not.toContain("oidc_access_lease_expired");
    expect(maintenance).toContain("'kind','logout_retry'");
    expect(maintenance).toContain("'kind','refresh'");
    expect(maintenance).toContain("'kind','scrub'");
    expect(maintenance).not.toContain(
      "DELETE FROM public.tenant_oidc_consumed_refresh_tokens",
    );
    expect(maintenance).not.toContain(
      "cleanup_session_logout_continuations_v1",
    );
    expect(maintenance).not.toContain(
      "private_cleanup_expired_saml_materials_v1",
    );
    expect(cleanup).toContain(
      "v_kind NOT IN ('logout_continuation','consumed_refresh','saml_material')",
    );
    expect(cleanup).toContain("IF v_kind = 'logout_continuation' THEN");
    expect(cleanup).toContain("ELSIF v_kind = 'consumed_refresh' THEN");
    expect(cleanup).toContain(
      "v_removed := app.private_cleanup_expired_saml_materials_v1",
    );
    expect(cleanup).not.toContain("pg_advisory_xact_lock");
    expect(cleanup).not.toContain("FROM public.auth_sessions");
    expect(migration).toContain(
      "app.cleanup_federated_maintenance_retention_v1(jsonb),\n  app.expire_oidc_access_lease_v1(jsonb),\n  app.cleanup_session_logout_continuations_v1(jsonb)",
    );
    expect(accessExpiry).toContain("v_kind <> 'access_expiry'");
    expect(accessExpiry).toContain("v_observed_at := date_trunc(");
    expect(accessExpiry).toContain("transaction_timestamp()");
    expect(accessExpiry).toContain("'kind',v_kind");
    expect(accessExpiry).toContain("'observedAt',to_jsonb(v_observed_at)");
    expect(accessExpiry).toContain("'expired',v_expired");
    expect(migration).toContain(
      "'periapsis_worker','app.expire_oidc_access_lease_v1(jsonb)','EXECUTE'",
    );
    expect(migration).toContain(
      "'periapsis_api','app.expire_oidc_access_lease_v1(jsonb)','EXECUTE'",
    );

    const logoutDispatchStart = maintenance.indexOf(
      "IF v_kind = 'logout_retry' THEN",
    );
    const logoutDispatchEnd = maintenance.indexOf(
      "IF v_kind = 'refresh' THEN",
      logoutDispatchStart,
    );
    const logoutDispatch = maintenance.slice(
      logoutDispatchStart,
      logoutDispatchEnd,
    );
    expect(logoutDispatchStart).toBeGreaterThan(-1);
    expect(logoutDispatchEnd).toBeGreaterThan(logoutDispatchStart);
    expect(logoutDispatch).not.toContain("FOR UPDATE");
    expect(logoutDispatch).toContain("claim_tenant_oidc_logout_retry_v1");

    expect(accessExpiry).toContain(
      "pg_advisory_xact_lock(hashtextextended(\n      v_candidate_family_id::text,90174213",
    );
    expect(accessExpiry.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      accessExpiry.indexOf("FOR UPDATE OF session"),
    );
    expect(accessExpiry.indexOf("FOR UPDATE OF session")).toBeLessThan(
      accessExpiry.indexOf("FOR UPDATE OF material"),
    );
    expect(accessExpiry).not.toContain("FOR UPDATE OF material,session");

    const refreshDispatchStart = maintenance.indexOf(
      "IF v_kind = 'refresh' THEN",
    );
    const refreshDispatchEnd = maintenance.indexOf(
      "SELECT material.* INTO v_material",
      maintenance.indexOf("RETURN NULL;", refreshDispatchStart) + 1,
    );
    const refreshDispatch = maintenance.slice(
      refreshDispatchStart,
      refreshDispatchEnd,
    );
    expect(refreshDispatchStart).toBeGreaterThan(-1);
    expect(refreshDispatchEnd).toBeGreaterThan(refreshDispatchStart);
    expect(refreshDispatch).toContain(
      "SELECT material.id,material.rotation_family_id\n      INTO v_candidate_material_id,v_candidate_family_id",
    );
    expect(refreshDispatch).toContain(
      "pg_advisory_xact_lock(hashtextextended(\n        v_candidate_family_id::text,90174213",
    );
    expect(refreshDispatch.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      refreshDispatch.indexOf("claim_tenant_oidc_refresh_rotation_v1"),
    );
    expect(refreshDispatch).not.toContain("FOR UPDATE OF material");

    const pruneFamilies = prune.slice(
      prune.indexOf("-- Batch in rotation-family units"),
    );
    expect(migration).toContain(
      "GRANT SELECT (requester_session_id)\n  ON TABLE public.tenant_audit_export_jobs, public.platform_audit_export_jobs\n  TO periapsis_migrator",
    );
    expect(migration).not.toMatch(
      /GRANT SELECT ON TABLE public\.tenant_audit_export_jobs/i,
    );
    expect(
      pruneFamilies.match(/job\.state IN \('pending','claimed'\)/g),
    ).toHaveLength(2);
    expect(
      pruneFamilies.indexOf("job.state IN ('pending','claimed')"),
    ).toBeLessThan(pruneFamilies.indexOf("pg_advisory_xact_lock"));
    expect(
      pruneFamilies.lastIndexOf("job.state IN ('pending','claimed')"),
    ).toBeGreaterThan(pruneFamilies.indexOf("pg_advisory_xact_lock"));
    expect(pruneFamilies.indexOf("pg_advisory_xact_lock")).toBeLessThan(
      pruneFamilies.indexOf("FOR UPDATE"),
    );
  });

  it("loads composite material projections through one record target", () => {
    const claimRetry = finalSqlBody(
      "claim_tenant_oidc_logout_retry_v1(\n  p_request jsonb",
    );
    const completeRetry = finalSqlBody(
      "complete_tenant_oidc_logout_retry_v1(\n  p_request jsonb",
    );
    const maintenance = finalSqlBody(
      "claim_due_oidc_maintenance_v1(p_request jsonb)",
    );

    expect(migration).not.toMatch(
      /SELECT\s+material\s*,[^;]*?\bINTO\s+v_material\s*,/u,
    );
    expect(migration).not.toMatch(
      /SELECT\s+material\.\*\s*,[^;]*?\bINTO\s+v_material\s*,/u,
    );

    for (const body of [claimRetry, completeRetry]) {
      const lookup = body.indexOf("SELECT material AS material,");
      const capture = body.indexOf("v_material_found := FOUND;", lookup);
      const guard = body.indexOf("IF v_material_found THEN", capture);
      const assignment = body.indexOf(
        "v_material := v_material_lookup.material;",
        guard,
      );

      expect(body).toContain("v_material_lookup record;");
      expect(body).toContain("v_material_found boolean;");
      expect(body).toContain("INTO v_material_lookup");
      expect(body).not.toMatch(/INTO v_material\s*,/u);
      expect(lookup).toBeGreaterThan(-1);
      expect(capture).toBeGreaterThan(lookup);
      expect(guard).toBeGreaterThan(capture);
      expect(assignment).toBeGreaterThan(guard);
      expect(body).toContain("IF NOT v_material_found OR");
    }
    expect(claimRetry).toContain(
      "least(material.expires_at,session.absolute_expires_at) AS deadline",
    );
    expect(claimRetry).toContain("FOR SHARE;");
    expect(completeRetry).toContain(
      "least(material.expires_at,session.absolute_expires_at) AS deadline",
    );
    expect(completeRetry).toContain("FOR UPDATE OF material,session;");
    expect(completeRetry).toContain(
      "v_effective_session_id := v_material_lookup.effective_session_id;",
    );
    expect(completeRetry).toContain(
      "v_effective_tenant_id := v_material_lookup.effective_tenant_id;",
    );

    const advisory = maintenance.indexOf("PERFORM pg_advisory_xact_lock");
    const lookup = maintenance.indexOf("SELECT material AS material,");
    const capture = maintenance.indexOf("v_refresh_found := FOUND;", lookup);
    const guard = maintenance.indexOf("IF v_refresh_found THEN", capture);
    const assignment = maintenance.indexOf(
      "v_material := v_refresh_lookup.material;",
      guard,
    );
    expect(maintenance).toContain("v_refresh_lookup record;");
    expect(maintenance).toContain("v_refresh_found boolean;");
    expect(maintenance).toContain("INTO v_refresh_lookup");
    expect(advisory).toBeGreaterThan(-1);
    expect(lookup).toBeGreaterThan(advisory);
    expect(capture).toBeGreaterThan(lookup);
    expect(guard).toBeGreaterThan(capture);
    expect(assignment).toBeGreaterThan(guard);
    expect(maintenance.slice(lookup, capture)).not.toMatch(
      /\bFOR\s+(?:UPDATE|SHARE)\b/u,
    );
    expect(maintenance).toContain(
      "v_effective_tenant_id := v_refresh_lookup.effective_tenant_id;",
    );
  });

  it("patches the private tenant-provider implementation and preserves routing", () => {
    const materialGuard = finalSqlBody("guard_oidc_session_material_v1()");
    const ownerDispatchStart = materialGuard.indexOf(
      "IF NEW.session_id IS NOT NULL THEN",
    );
    const tenantProviderOwnerStart = materialGuard.indexOf(
      "IF NEW.authority = 'tenant_provider' THEN",
      ownerDispatchStart,
    );
    const tenantPlatformOwnerStart = materialGuard.indexOf(
      "ELSIF NEW.authority = 'tenant_platform_provider' THEN",
      tenantProviderOwnerStart,
    );
    const tenantProviderOwner = materialGuard.slice(
      tenantProviderOwnerStart,
      tenantPlatformOwnerStart,
    );
    const stepUpStart = migration.indexOf(
      "DO $oidc_step_up_material_transfer_v1$",
    );
    const stepUpEnd = migration.indexOf(
      "$oidc_step_up_material_transfer_v1$;",
      stepUpStart + 1,
    );
    const rotationStart = migration.indexOf(
      "DO $oidc_revalidation_rotation_transfer_v1$",
    );
    const rotationEnd = migration.indexOf(
      "$oidc_revalidation_rotation_transfer_v1$;",
      rotationStart + 1,
    );
    const mfaOwnerStart = migration.indexOf("DO $oidc_mfa_owner_transfer_v1$");
    const mfaOwnerEnd = migration.indexOf(
      "$oidc_mfa_owner_transfer_v1$;",
      mfaOwnerStart + 1,
    );
    const mfaMethodStart = migration.indexOf(
      "DO $oidc_mfa_primary_method_order_v1$",
    );
    const mfaMethodEnd = migration.indexOf(
      "$oidc_mfa_primary_method_order_v1$;",
      mfaMethodStart + 1,
    );
    const stepUpPatch = migration.slice(stepUpStart, stepUpEnd);
    const rotationPatch = migration.slice(rotationStart, rotationEnd);
    const mfaOwnerPatch = migration.slice(mfaOwnerStart, mfaOwnerEnd);
    const mfaMethodPatch = migration.slice(mfaMethodStart, mfaMethodEnd);
    const familyRouter = finalSqlBody(
      "apply_federated_session_revalidation_v1(\n  p_mutation jsonb",
      familyRouterMigration,
    );
    const ldapRouter = finalSqlBody(
      "apply_federated_session_revalidation_v1(p_mutation jsonb)",
      ldapMigration,
    );

    expect(stepUpStart).toBeGreaterThan(-1);
    expect(rotationStart).toBeGreaterThan(-1);
    expect(mfaOwnerStart).toBeGreaterThan(-1);
    expect(mfaMethodStart).toBeGreaterThan(mfaOwnerEnd);
    expect(ownerDispatchStart).toBeGreaterThan(-1);
    expect(tenantProviderOwnerStart).toBeGreaterThan(ownerDispatchStart);
    expect(tenantPlatformOwnerStart).toBeGreaterThan(tenantProviderOwnerStart);
    expect(tenantProviderOwner).toContain(
      "AND session.authentication_method = 'oidc'",
    );
    expect(stepUpPatch).toContain(
      "'app.private_v34_apply_federated_session_revalidation_v1(jsonb)'::regprocedure",
    );
    expect(rotationPatch).toContain(
      "'app.private_v34_apply_federated_session_revalidation_v1(jsonb)'::regprocedure",
    );
    for (const patch of [stepUpPatch, rotationPatch]) {
      expect(patch).not.toContain(
        "'app.apply_federated_session_revalidation_pre_ldap_v1(jsonb)'::regprocedure",
      );
      expect(patch).not.toContain(
        "'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure",
      );
    }
    expect(mfaOwnerPatch).toContain(
      "UPDATE public.tenant_oidc_session_materials AS material",
    );
    const primaryMethodUpdate = mfaMethodPatch.indexOf(
      "SET authentication_method = v_provider_authentication_method",
    );
    const firstMaterialTransfer = mfaMethodPatch.indexOf(
      "UPDATE public.tenant_saml_session_materials AS material",
      primaryMethodUpdate,
    );
    expect(primaryMethodUpdate).toBeGreaterThan(-1);
    expect(firstMaterialTransfer).toBeGreaterThan(primaryMethodUpdate);
    expect(mfaMethodPatch).toContain(
      "federated MFA successor primary method is unavailable",
    );
    expect(familyRouterMigration).toContain(
      "ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)\n  RENAME TO private_v34_apply_federated_session_revalidation_v1",
    );
    expect(familyRouter).toContain("IF primary_kind = 'tenant_provider' THEN");
    expect(familyRouter).toContain(
      "result := app.private_v34_apply_federated_session_revalidation_v1(",
    );
    expect(familyRouter).toContain(
      "ELSIF primary_kind = 'tenant_platform_provider' THEN",
    );
    expect(familyRouter).toContain(
      "RETURN app.apply_tenant_platform_federated_session_revalidation_v1(",
    );
    expect(ldapRouter).toContain("IF v_method='ldap' THEN");
    expect(ldapRouter).toContain(
      "RETURN app.private_apply_ldap_session_revalidation_v1(p_mutation);",
    );
    expect(ldapRouter).toContain(
      "RETURN app.apply_federated_session_revalidation_pre_ldap_v1(p_mutation);",
    );
  });

  it("indexes both SAML cleanup scans by their exact partial order", () => {
    expect(schema).toContain(
      'index("tenant_saml_session_materials_cleanup_idx")',
    );
    expect(schema).toContain(
      ".on(table.createdAt, table.id)\n      .where(sql`${table.scrubbedAt} is null`)",
    );
    expect(platformSamlSchema).toContain(
      'index("platform_saml_session_materials_cleanup_idx")',
    );
    expect(platformSamlSchema).toContain(
      ".on(table.createdAt, table.id)\n      .where(sql`${table.scrubbedAt} is null`)",
    );
    expect(migration).toContain(
      "CREATE INDEX tenant_saml_session_materials_cleanup_idx\n  ON public.tenant_saml_session_materials (created_at,id)\n  WHERE scrubbed_at IS NULL",
    );
    expect(migration).toContain(
      "CREATE INDEX platform_saml_session_materials_cleanup_idx\n  ON public.platform_saml_session_materials (created_at,id)\n  WHERE scrubbed_at IS NULL",
    );
  });

  it("loads each pinned maintenance secret without live-provider readiness", () => {
    const loadSecret = finalSqlBody(
      "load_oidc_maintenance_client_secret_envelope_v1(\n  p_lookup jsonb",
    );
    const claimRefresh = finalSqlBody(
      "claim_tenant_oidc_refresh_rotation_v1(\n  p_command jsonb",
    );

    expect(loadSecret).toContain(
      "LANGUAGE plpgsql\nVOLATILE\nSECURITY DEFINER",
    );
    expect(loadSecret).toContain(
      "'sessionFamilyId','claimVersion','refreshGeneration','jobId','attempt'",
    );
    expect(loadSecret).toContain("v_kind NOT IN ('refresh','logout_retry')");
    expect(loadSecret).toContain("material.id = v_material_id");
    expect(loadSecret).toContain("material.rotation_family_id = v_family_id");
    expect(loadSecret).toContain("material.provider_id = v_provider_id");
    expect(loadSecret).toContain(
      "material.client_secret_revision = v_revision",
    );
    expect(loadSecret).toContain("material.refresh_version = v_claim_version");
    expect(loadSecret).toContain(
      "material.refresh_generation = v_refresh_generation",
    );
    expect(loadSecret).toContain(
      "material.refresh_claim_expires_at > v_observed_at",
    );
    expect(loadSecret).toContain("job.id = v_job_id");
    expect(loadSecret).toContain("job.state = 'claimed'");
    expect(loadSecret).toContain("job.attempt = v_attempt");
    expect(loadSecret).toContain("job.version = v_claim_version");
    expect(loadSecret).toContain("job.material_id = material.id");
    expect(loadSecret).toContain(
      "job.session_family_id = material.rotation_family_id",
    );
    expect(loadSecret).toContain("job.claim_expires_at > v_observed_at");
    expect(loadSecret.indexOf("SELECT job.* INTO v_job")).toBeLessThan(
      loadSecret.indexOf("SELECT material.* INTO v_material"),
    );
    expect(loadSecret).toContain(
      "FOR SHARE;\n    IF NOT FOUND THEN RETURN NULL",
    );
    expect(loadSecret).toContain("IF v_scope = 'tenant' THEN");
    expect(loadSecret).toContain("ELSIF v_scope = 'platform' THEN");
    expect(loadSecret).toContain("material.authority = 'tenant_provider'");
    expect(loadSecret).toContain("material.authority = 'platform_provider'");
    expect(loadSecret).toContain(
      "material.authority = 'tenant_platform_provider'",
    );
    expect(loadSecret).toContain("material.binding_id = v_binding_id");
    expect(loadSecret).toContain(
      "FROM ONLY public.tenant_oidc_client_secrets AS secret",
    );
    expect(loadSecret).toContain(
      "FROM ONLY public.platform_oidc_client_secrets AS secret",
    );
    expect(loadSecret).toContain("keyring.retired_at IS NULL");
    expect(loadSecret).toContain(
      "secret.revision = v_material.client_secret_revision",
    );
    expect(claimRefresh).toContain(
      "v_expected_digest := app.private_mfa_decode_base64_v1(",
    );
    expect(claimRefresh).toContain(
      "v_material.refresh_token_digest IS DISTINCT FROM v_expected_digest",
    );
    expect(loadSecret).not.toMatch(
      /provider\.enabled|binding\.enabled|archived_at|secret\.retired_at|tenant_federated_provider_policies/,
    );
    expect(loadSecret).toContain("'lookup',p_lookup");
    expect(migration).toContain(
      "app.load_oidc_maintenance_client_secret_envelope_v1(jsonb)\nTO periapsis_worker",
    );
    expect(migration).toContain(
      "'periapsis_api',\n      'app.load_oidc_maintenance_client_secret_envelope_v1(jsonb)','EXECUTE'",
    );
  });

  it("uses database-owned clocks and saturating terminal session versions", () => {
    const revoke = finalSqlBody(
      "revoke_local_session_for_logout_v1(p_command jsonb)",
    );
    const claim = finalSqlBody(
      "claim_session_logout_continuation_v1(p_request jsonb)",
    );
    const complete = finalSqlBody(
      "complete_tenant_oidc_refresh_rotation_v1(\n  p_command jsonb",
    );

    expect(revoke).toContain(
      "v_requested_at := (p_command ->> 'requestedAt')::timestamptz",
    );
    expect(revoke).toContain(
      "v_database_now := date_trunc('microseconds',transaction_timestamp())",
    );
    expect(revoke).toContain("v_requested_at := v_database_now");
    expect(revoke).toContain(
      "'requestedAt',v_request_snapshot -> 'requestedAt'",
    );
    expect(revoke).toContain("'observedAt',to_jsonb(v_requested_at)");
    expect(claim).toContain(
      "v_claimed_at := date_trunc('microseconds',transaction_timestamp())",
    );
    expect(claim).toContain(
      "'requestedClaimedAt',to_jsonb(v_requested_claimed_at)",
    );
    expect(claim).toContain("'observedAt',to_jsonb(v_claimed_at)");
    expect(revoke).toContain(
      "WHEN state.session_version < 9000000000000000\n            THEN state.session_version + 1",
    );
    expect(revoke).toContain(
      "WHEN state.session_version < 2147483647\n            THEN state.session_version + 1",
    );
    expect(complete).toContain(
      "WHEN material.refresh_version < 8999999999999999",
    );
  });

  it("scrubs the sole envelope copy and keeps every lifecycle table private", () => {
    const scrub = finalSqlBody(
      "scrub_oidc_session_material_v1(p_request jsonb)",
    );
    expect(scrub).toContain(
      "id_token_key_version = NULL,id_token_ciphertext = NULL",
    );
    expect(scrub).toContain("id_token_digest = NULL");
    expect(scrub).toContain("refresh_token_key_version = NULL");
    expect(scrub).toContain("refresh_token_digest = NULL");
    expect(scrub).toContain("client_secret_revision = NULL");
    expect(migration).toContain(
      "NOT material.id_token_key_version = ANY(p_versions)",
    );
    expect(migration).toContain(
      "NOT material.refresh_token_key_version = ANY(p_versions)",
    );
    for (const table of [
      "tenant_oidc_session_materials",
      "tenant_oidc_consumed_refresh_tokens",
      "tenant_oidc_logout_commands",
      "tenant_oidc_logout_retry_jobs",
      "session_logout_continuations",
    ]) {
      expect(migration).toContain(
        `ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`,
      );
    }
    expect(migration).toContain(
      "ALTER TABLE public.%I FORCE ROW LEVEL SECURITY",
    );
    expect(migration).toContain(
      "CREATE OR REPLACE FUNCTION app.tenant_oidc_session_lifecycle_schema_readiness_v1()",
    );
  });
});
