import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");

const security = migration("0128_federated_authentication_security.sql");
const transactions = migration(
  "0129_federated_authentication_transaction_abi.sql",
);
const reads = migration("0130_federated_authentication_read_abi.sql");
const apply = migration("0131_federated_authentication_apply_abi.sql");
const mfa = migration("0132_federated_authentication_mfa_compatibility.sql");
const sessions = migration("0133_federated_authentication_session_abi.sql");
const readiness = migration("0134_federated_authentication_readiness.sql");

describe("federated authentication database contract", () => {
  it("keeps every federation relation behind FORCE RLS and a narrow ABI", () => {
    expect(security).toContain(
      "ALTER TABLE public.%I FORCE ROW LEVEL SECURITY",
    );
    expect(security).toContain("REVOKE ALL ON TABLE public.%I FROM PUBLIC");
    expect(readiness).toContain("AND class.relforcerowsecurity");
    expect(readiness).toContain("FROM pg_policy AS policy");
    expect(readiness).toContain("IS DISTINCT FROM 16");
    expect(readiness).toContain("TO periapsis_api;");
    expect(readiness).not.toContain("TO periapsis_notifier");
  });

  it("binds federated provenance and continuations to live exact authority", () => {
    expect(security).toContain("identity.binding_id = provenance.binding_id");
    expect(security).toContain("access_grant.membership_id = membership.id");
    expect(security).toContain(
      "access_grant.access_epoch_id = binding.current_access_epoch_id",
    );
    expect(security).toContain("access_source.retired_at IS NULL");
    expect(security).toContain(
      "access_grant.started_at <= transaction_timestamp()",
    );
    expect(security).toContain(
      "access_epoch.started_at <= transaction_timestamp()",
    );
    expect(security).not.toContain(
      "session.authentication_method = provenance.authentication_method",
    );
    expect(security).toContain(
      "OLD.protocol = 'oidc' AND OLD.state = 'pending'",
    );
    expect(security).toContain(
      "OLD.protocol = 'saml' AND OLD.state = 'pending'",
    );
  });

  it("reauthorizes start replay and uses database-bounded time", () => {
    const oidcReplay = transactions.indexOf("IF v_replay THEN");
    const oidcLive = transactions.indexOf("FOR SHARE;");
    expect(oidcReplay).toBeGreaterThan(oidcLive);
    expect(transactions.match(/IF v_replay THEN/g)).toHaveLength(2);
    expect(
      transactions.match(/v_created_at NOT BETWEEN statement_timestamp\(\)/g),
    ).toHaveLength(2);
    expect(transactions).toContain(
      "v_transaction.expires_at <= statement_timestamp()",
    );
    expect(transactions).toContain(
      "statement_timestamp() >= v_transaction.expires_at",
    );
  });

  it("loads only live tenant and safe mapping authority", () => {
    expect(reads).toContain("!~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'");
    expect(
      reads.match(/tenant.status = 'active'/g)?.length,
    ).toBeGreaterThanOrEqual(6);
    expect(reads).toContain("SELECT subject.identity_epoch INTO STRICT");
    expect(reads).toContain("epoch_source.retired_at IS NULL");
    expect(reads).toContain(
      "grant_source.id IS NOT NULL AND role.id IS NOT NULL",
    );
    expect(reads).toContain("forbidden.scope = 'platform'");
    expect(reads).toContain("team.tenant_id = assignment.tenant_id");
  });

  it("rechecks mapping and identity CAS before issuing authority", () => {
    expect(apply).toContain("federated identity epoch drifted");
    expect(apply).toContain("FOR SHARE OF epoch, source, security_group");
    expect(apply).toContain("FOR SHARE OF assignment, team");
    expect(apply).toContain("federated matched mapping rule authority drifted");
    expect(apply.indexOf("SET retired_at = p_applied_at")).toBeLessThan(
      apply.indexOf("IF v_profile_present > 0 THEN"),
    );
    expect(apply).toContain("alias.retired_at IS NULL");
    expect(apply).toContain("identity.binding_id = p_binding_id");
    expect(apply).toContain("tenant.status = 'active'");
    expect(apply).toContain(
      "grant_row.access_epoch_id = binding.current_access_epoch_id",
    );
    expect(apply).toContain("policy.provider_kind = p_provider_kind");
    expect(apply).toContain("access_epoch.started_at <= p_evaluated_at");
    expect(apply).toContain("grant_row.started_at <= p_evaluated_at");
    expect(apply).toContain("access_source.retired_at IS NULL");
    expect(apply).toContain(
      "provenance.external_identity_id = p_external_identity_id",
    );
    expect(apply).toContain(
      "continuation.external_identity_id = p_external_identity_id",
    );
  });

  it("keeps MFA/session successors membership-bound, CAS-safe, and oracle-free", () => {
    expect(mfa).toContain("access_grant.membership_id = v_membership_id");
    expect(mfa).toContain("access_grant.started_at <= p_completed_at");
    expect(mfa).toContain("access_epoch.started_at <= p_completed_at");
    expect(mfa).toContain(
      "DROP FUNCTION IF EXISTS app.private_mfa_apply_session_v1(",
    );
    expect(sessions).toContain("access_grant.membership_id = v_membership_id");
    expect(sessions).toContain(
      "access_grant.started_at <= transaction_timestamp()",
    );
    expect(sessions).toContain("access_grant.started_at <= v_observed_at");
    expect(
      sessions.match(/access_epoch.started_at <=/g)?.length,
    ).toBeGreaterThanOrEqual(2);
    expect(sessions).toContain(
      "policy.security_revision = evidence.trust_rule_revision",
    );
    expect(sessions).toContain(
      "policy.provider_kind = v_provenance.provider_kind",
    );
    expect(
      sessions.match(/federated session command lost CAS/g)?.length,
    ).toBeGreaterThanOrEqual(3);
    expect(sessions).toContain("federated session authority unavailable");
    expect(sessions).not.toContain("'applied',false");
  });

  it("preserves only the exact sealed 0125 rolling predecessor", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v27()",
    );
    expect(readiness).toContain("WHERE migration.migration_ordinal <= 126");
    expect(readiness).toContain(
      "'211491eec9cf3e475db463fd815d31a98c2e80263e3c3957cf0eef7a5434a9d8'",
    );
    expect(readiness).toContain(
      "legacy schema compatibility v25 remains active",
    );
    expect(readiness).toContain(
      "RETURN current_count = 135 AND predecessor_count = 126",
    );
    expect(readiness).toContain(
      "CREATE OR REPLACE FUNCTION app.identity_mfa_schema_readiness_v1()",
    );
    expect(readiness).toContain(
      "CREATE OR REPLACE FUNCTION app.identity_mfa_device_management_readiness_v1()",
    );
  });
});
