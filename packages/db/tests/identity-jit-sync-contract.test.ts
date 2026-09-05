import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const migrations = resolve(import.meta.dirname, "../migrations");
const schema = resolve(import.meta.dirname, "../src/schema");
const structural = readFileSync(
  resolve(migrations, "0065_sweet_richard_fisk.sql"),
  "utf8",
);
const lifecycleSecurity = readFileSync(
  resolve(migrations, "0066_identity_jit_sync_security.sql"),
  "utf8",
);
const applyAbi = readFileSync(
  resolve(migrations, "0067_identity_jit_sync_abi.sql"),
  "utf8",
);
const syncAbi = readFileSync(
  resolve(migrations, "0068_identity_sync_lifecycle_abi.sql"),
  "utf8",
);
const jitStructural = readFileSync(
  resolve(migrations, "0070_late_ozymandias.sql"),
  "utf8",
);
const jitSecurity = readFileSync(
  resolve(migrations, "0071_identity_jit_preauth_security.sql"),
  "utf8",
);
const jitAbi = readFileSync(
  resolve(migrations, "0072_identity_jit_preauth_abi.sql"),
  "utf8",
);
const syncSecretPins = readFileSync(
  resolve(migrations, "0073_bright_proudstar.sql"),
  "utf8",
);
const workerAbi = readFileSync(
  resolve(migrations, "0074_identity_sync_worker_claim_abi.sql"),
  "utf8",
);
const readiness = readFileSync(
  resolve(migrations, "0075_identity_jit_sync_readiness_v11.sql"),
  "utf8",
);
const fencedStructural = readFileSync(
  resolve(migrations, "0076_thin_korath.sql"),
  "utf8",
);
const fencedAbi = readFileSync(
  resolve(migrations, "0077_identity_sync_fenced_worker_abi_v2.sql"),
  "utf8",
);
const fencedConstraints = readFileSync(
  resolve(migrations, "0078_condemned_hardball.sql"),
  "utf8",
);
const fencedReadiness = readFileSync(
  resolve(migrations, "0079_identity_sync_fenced_readiness_v12.sql"),
  "utf8",
);
const accessGrantPlanningAbi = readFileSync(
  resolve(migrations, "0080_identity_sync_access_grant_planning_v3.sql"),
  "utf8",
);
const accessGrantReadiness = readFileSync(
  resolve(migrations, "0081_identity_sync_readiness_v13.sql"),
  "utf8",
);
const jitSchema = readFileSync(resolve(schema, "identity-jit.ts"), "utf8");
const syncSchema = readFileSync(resolve(schema, "identity-sync.ts"), "utf8");
const enumSchema = readFileSync(resolve(schema, "enums.ts"), "utf8");

function functionBody(source: string, name: string): string {
  const start = Math.max(
    source.indexOf(`CREATE FUNCTION app.${name}`),
    source.indexOf(`CREATE OR REPLACE FUNCTION app.${name}`),
  );
  expect(start, `${name} declaration`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("$function$;", start);
  expect(end, `${name} terminator`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("tenant LDAP JIT and synchronization durable model", () => {
  it("keeps every new customer row tenant-scoped, forced-RLS and runtime opaque", () => {
    const tables = [
      "tenant_ldap_identity_plan_applications",
      "tenant_ldap_sync_absences",
      "tenant_ldap_sync_run_mappings",
      "tenant_ldap_sync_runs",
      "tenant_ldap_sync_staged_observations",
      "tenant_ldap_jit_authentication_runs",
      "tenant_ldap_jit_run_mappings",
    ];
    for (const table of tables) {
      const generated = table.includes("_jit_") ? jitStructural : structural;
      const security = table.includes("_jit_")
        ? jitSecurity
        : lifecycleSecurity;
      const tableStart = generated.indexOf(`CREATE TABLE "${table}"`);
      const tableEnd = generated.indexOf("CREATE TABLE ", tableStart + 1);
      const tableBody = generated.slice(
        tableStart,
        tableEnd === -1 ? generated.length : tableEnd,
      );
      expect(tableStart, table).toBeGreaterThanOrEqual(0);
      expect(tableBody).toContain('"tenant_id" uuid NOT NULL');
      expect(generated).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toMatch(
        new RegExp(
          `REVOKE ALL ON TABLE public\\.${table}\\s+FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor`,
        ),
      );
    }
    expect(readiness).toContain("policy.polrelid = relation_oid");
    expect(readiness).toContain("count(*) FROM pg_catalog.pg_policy");
  });

  it("stores only digests, encrypted aliases, aggregate progress and exact pins", () => {
    const runTable = jitStructural.slice(
      jitStructural.indexOf(
        'CREATE TABLE "tenant_ldap_jit_authentication_runs"',
      ),
      jitStructural.indexOf('CREATE TABLE "tenant_ldap_jit_run_mappings"'),
    );
    expect(runTable).toContain('"receipt_digest" "bytea" NOT NULL');
    expect(runTable).toContain('"network_rate_key_digest" "bytea" NOT NULL');
    expect(runTable).toContain('"account_rate_key_digest" "bytea" NOT NULL');
    expect(runTable).toContain('"provider_rate_key_digest" "bytea" NOT NULL');
    expect(runTable).toContain('"bind_secret_id" uuid NOT NULL');
    expect(runTable).not.toMatch(
      /subject_value|directory_value|distinguished_name|raw_entry|raw_groups|password|bind_password|username|email/i,
    );
    for (const pin of [
      "bind_secret_id",
      "bind_secret_version",
      "bind_secret_key_version",
      "bind_secret_algorithm",
    ]) {
      expect(syncSchema).toContain(
        `${pin.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())}:`,
      );
      expect(syncSecretPins).toContain(`ADD COLUMN "${pin}"`);
    }
    expect(readiness).toContain(
      "LDAP sync bind-secret pins are absent or nullable",
    );
    expect(readiness).toContain(
      "LDAP JIT/sync durable state contains a raw directory field",
    );
  });

  it("keeps the Drizzle schema canonical for all JIT/sync enums and tables", () => {
    expect(jitSchema).toContain('"tenant_ldap_jit_authentication_runs"');
    expect(jitSchema).toContain('"tenant_ldap_jit_run_mappings"');
    expect(syncSchema).toContain('"tenant_ldap_sync_runs"');
    expect(syncSchema).toContain('"tenant_ldap_sync_staged_observations"');
    expect(enumSchema).toContain('"network_pending"');
    expect(enumSchema).toContain('"enumerating"');
    expect(enumSchema).toContain('"ldap_network"');
    expect(enumSchema).toContain('"ldap_account"');
    expect(enumSchema).toContain('"ldap_provider"');
  });
});

describe("public pre-auth LDAP JIT receipt ABI", () => {
  it("uses only the canonical tenant slug/login key locator and DB-shared meters", () => {
    const begin = functionBody(
      jitAbi,
      "begin_tenant_ldap_jit_authentication_v1",
    );
    expect(begin).toContain("p_tenant_slug text");
    expect(begin).toContain("p_login_key text");
    expect(begin).not.toContain("p_tenant_id");
    expect(begin).not.toContain("p_binding_id");
    expect(begin).toContain("binding.key = p_login_key");
    expect(begin).toContain("tenant.slug = p_tenant_slug");
    expect(begin).toContain("app.admit_auth_attempts");
    expect(begin).toContain("'ldap_network', 'ldap_account', 'ldap_provider'");
    expect(begin).toContain("pg_advisory_xact_lock");
    expect(begin).toContain("tenant_ldap_jit_begin:");
  });

  it("derives the only tenant context from an exact opaque receipt", () => {
    for (const name of [
      "private_get_tenant_ldap_jit_network_snapshot_v1",
      "claim_tenant_ldap_jit_planning_v1",
      "apply_tenant_ldap_jit_identity_plan_v1",
      "complete_tenant_ldap_jit_authentication_v1",
    ]) {
      const body = functionBody(jitAbi, name);
      expect(body).toContain("run.receipt_digest = p_receipt_digest");
      expect(body).toContain("set_config('app.tenant_id'");
      expect(body).not.toContain("p_tenant_id");
    }
    expect(jitStructural).toContain(
      'CONSTRAINT "tenant_ldap_jit_runs_receipt_key" UNIQUE("receipt_digest")',
    );
    expect(jitStructural).toContain(
      'octet_length("tenant_ldap_jit_authentication_runs"."receipt_digest") = 32',
    );
  });

  it("claims planning once, rechecks every pin and never looks up raw subjects", () => {
    const claim = functionBody(jitAbi, "claim_tenant_ldap_jit_planning_v1");
    expect(claim).toContain("FOR UPDATE");
    expect(claim).toContain("locked_run.status <> 'network_pending'");
    expect(claim).toContain("SET status = 'planning'");
    expect(claim).toContain("p_subject_digests bytea[]");
    expect(claim).toContain("p_digest_key_versions integer[]");
    expect(claim).toContain("tenant_ldap_external_identity_subject_aliases");
    expect(claim).not.toMatch(
      /subject_ciphertext|canonical_subject|subject_value/,
    );
    expect(
      functionBody(jitAbi, "private_tenant_ldap_jit_run_is_current_v1"),
    ).toContain("secret.version = run.bind_secret_version");
  });

  it("terminalizes failures without materializing identity/profile state", () => {
    const complete = functionBody(
      jitAbi,
      "complete_tenant_ldap_jit_authentication_v1",
    );
    expect(complete).toContain("'invalid_credentials'");
    expect(complete).toContain("'network_error'");
    expect(complete).toContain("'account_disabled'");
    expect(complete).toContain("terminal_audit_event_id");
    expect(complete).not.toMatch(
      /INSERT INTO public\.(?:users|tenant_memberships|tenant_ldap_external_identities|tenant_ldap_provider_access_grants)/,
    );
    expect(jitSecurity).toContain("NEW.receipt_digest");
    expect(jitSecurity).toContain(
      "tenant LDAP JIT authentication transition is invalid",
    );
  });
});

describe("atomic LDAP identity plan apply", () => {
  it("records deny plans without any identity, membership, access or edge material", () => {
    const apply = functionBody(applyAbi, "apply_tenant_ldap_identity_plan_v1");
    expect(apply).toContain(
      "denied LDAP plan must not carry identity or access material",
    );
    expect(apply).toContain("cardinality(p_matched_mapping_epoch_ids) <> 0");
    expect(apply).toContain("external_identity_id, user_id, membership_id");
    expect(apply).toContain(
      "NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, 0, 0, false",
    );
    expect(readiness).toContain("application.decision = 'denied'");
    expect(readiness).toContain("application.ensured_edge_count <> 0");
  });

  it("rejects platform scope, platform super-admin and non-human targets", () => {
    const apply = functionBody(applyAbi, "apply_tenant_ldap_identity_plan_v1");
    expect(apply).toContain("role.principal_kind <> 'human'");
    expect(apply).toContain("role.key = 'platform_super_admin'");
    expect(apply).toContain("policy.scope = 'platform'");
    expect(apply).toContain("tenant_security_group_role_grants");
    expect(readiness).toContain("LDAP JIT/sync privilege or denial invariant");
  });

  it("mutates only provider and pinned mapping-owned access edges", () => {
    const apply = functionBody(applyAbi, "apply_tenant_ldap_identity_plan_v1");
    expect(apply).toContain("tenant_ldap_provider_access_grants");
    expect(apply).toContain("tenant_ldap_provider_profile_contributions");
    expect(apply).toContain("tenant_security_group_memberships");
    expect(apply).toContain("operator_team_roster_entries");
    expect(apply).toContain("member.source_id = eligible.source_id");
    expect(apply).toContain("roster.source_id = eligible.source_id");
    expect(apply).toContain("app.private_materialize_tenant_user_profile_v1");
  });
});

describe("scheduled/manual LDAP synchronization lifecycle ABI", () => {
  it("allows only one live run per binding and pins every mutable dependency", () => {
    expect(structural).toContain(
      'CREATE UNIQUE INDEX "tenant_ldap_sync_runs_live_binding_key"',
    );
    expect(structural).toContain(
      "status\" in ('queued', 'enumerating', 'applying')",
    );
    const begin = functionBody(
      syncAbi,
      "private_begin_tenant_ldap_sync_run_v1",
    );
    expect(begin).toContain("pg_advisory_xact_lock");
    expect(begin).toContain("locked_binding.mapping_revision");
    expect(begin).toContain("current_authorization_revision");
    expect(begin).toContain("locked_secret.key_version");
    expect(begin).toContain("endpoint_digest");
  });

  it("claims queued work globally with SKIP LOCKED and a complete worker snapshot", () => {
    const claim = functionBody(workerAbi, "claim_next_tenant_ldap_sync_run_v1");
    expect(claim).toContain("WHERE run.status = 'queued'");
    expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    expect(claim).toContain("SET status = 'enumerating'");
    expect(claim).toContain(
      "set_config('app.tenant_id', locked_run.tenant_id::text",
    );
    expect(claim).toContain("secret.secret_ciphertext");
    expect(claim).toContain("secret.secret_nonce");
    expect(claim).toContain("mapping_revisions jsonb");
    expect(claim).not.toContain("p_tenant_id");
    expect(workerAbi).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.claim_next_tenant_ldap_sync_run_v1\(text\)\s+TO periapsis_worker/,
    );
  });

  it("makes stage, terminal completion and worker failure retries exact", () => {
    expect(
      functionBody(syncAbi, "stage_tenant_ldap_sync_observation_v1"),
    ).toContain("tenant LDAP sync observation replay differs");
    expect(
      functionBody(syncAbi, "complete_tenant_ldap_sync_enumeration_v1"),
    ).toContain(
      "audit.action = 'tenant.identity.ldap_sync_enumeration_completed'",
    );
    expect(functionBody(syncAbi, "complete_tenant_ldap_sync_run_v1")).toContain(
      "audit.action = 'tenant.identity.ldap_sync_completed'",
    );
    const fail = functionBody(workerAbi, "fail_tenant_ldap_sync_run_v1");
    expect(fail).toContain(
      "'network_error', 'directory_error', 'planning_error'",
    );
    expect(fail).toContain(
      "locked_run.status IN ('failed', 'cancelled', 'stale')",
    );
    expect(fail).toContain("replayed boolean");
  });

  it("never revokes for partial/truncated enumeration and bounds absence work", () => {
    const enumerate = functionBody(
      syncAbi,
      "complete_tenant_ldap_sync_enumeration_v1",
    );
    expect(enumerate).toContain(
      "p_enumeration_complete AND NOT p_result_truncated",
    );
    expect(enumerate).toContain("effective_status := 'applying'");
    const absence = functionBody(
      syncAbi,
      "apply_tenant_ldap_sync_absence_chunk_v1",
    );
    expect(absence).toContain("p_limit NOT BETWEEN 1 AND 200");
    expect(absence).toContain("NOT run_record.enumeration_complete");
    expect(absence).toContain("run_record.result_truncated");
    expect(absence).toContain("epoch.reconciliation_mode = 'authoritative'");
    expect(absence).toContain("member.source_id = pinned.source_id");
    expect(absence).toContain("roster.source_id = pinned.source_id");
    expect(absence).toContain("candidate.owns_membership");
  });
});

describe("LDAP JIT/sync readiness v11", () => {
  it("seals the exact 76-row bundle and retains only v10 as predecessor", () => {
    expect(readiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v11()",
    );
    expect(readiness).toContain("journal_count = 76");
    expect(readiness).toContain("1787655824109");
    expect(readiness).toContain("fingerprint_entries[1:65]");
    expect(readiness).toContain("schema compatibility v9 must be retired");
    expect(readiness).toContain("app.claim_next_tenant_ldap_sync_run_v1(text)");
    expect(readiness).toContain("app.fail_tenant_ldap_sync_run_v1");
  });
});

describe("fenced LDAP sync worker ABI v2", () => {
  it("models opaque one-time claims, bounded leases and monotonic fences canonically", () => {
    for (const field of [
      "claimId",
      "claimReceiptDigest",
      "claimFence",
      "claimAcquiredAt",
      "claimExpiresAt",
    ]) {
      expect(syncSchema).toContain(`${field}:`);
    }
    expect(fencedStructural).toContain('ADD COLUMN "claim_receipt_digest"');
    expect(fencedStructural).toContain(
      'CREATE UNIQUE INDEX "tenant_ldap_sync_runs_claim_id_key"',
    );
    expect(fencedConstraints).toContain(
      'CONSTRAINT "tenant_ldap_sync_runs_claim_check"',
    );
    expect(fencedConstraints).toContain('"claim_fence" > 0');
    expect(fencedConstraints).toContain(
      'octet_length("tenant_ldap_sync_runs"."claim_receipt_digest") = 32',
    );
  });

  it("recovers a committed response and reclaims only expired live work", () => {
    const claim = functionBody(fencedAbi, "claim_next_tenant_ldap_sync_run_v2");
    expect(claim).toContain("run.claim_id = p_claim_id");
    expect(claim).toContain(
      "locked_run.claim_receipt_digest IS DISTINCT FROM p_claim_receipt_digest",
    );
    expect(claim).toContain("greatest(");
    expect(claim).toContain("run.claim_fence + 1");
    expect(claim).toContain("run.claim_expires_at <= transaction_timestamp()");
    expect(claim).toContain("FOR UPDATE SKIP LOCKED");
    expect(claim).toContain("staged_observations jsonb");
    expect(claim).not.toContain("p_tenant_id");
  });

  it("derives planning state from the fenced run without persisting LDAP values", () => {
    const planning = functionBody(
      fencedAbi,
      "claim_tenant_ldap_sync_observation_planning_v2",
    );
    expect(planning).toContain("private_lock_tenant_ldap_sync_claim_v2");
    expect(planning).toContain("planning_fence = p_claim_fence");
    expect(planning).toContain("p_subject_digests bytea[]");
    expect(planning).toContain("tenant_ldap_external_identity_subject_aliases");
    expect(planning).toContain("security_groups jsonb");
    expect(planning).toContain("live_assignments jsonb");
    expect(planning).toContain("role_policies jsonb");
    expect(planning).toContain("delegation jsonb");
    expect(planning).toContain("live_owned_edges jsonb");
    expect(planning).not.toMatch(
      /INSERT INTO public\.[^(]+\([^)]*(?:subject_value|directory_value|distinguished_name|raw_entry)/i,
    );
  });

  it("fences every mutation and retires all unfenced worker entry points", () => {
    for (const name of [
      "stage_tenant_ldap_sync_observation_v2",
      "complete_tenant_ldap_sync_enumeration_v2",
      "apply_tenant_ldap_sync_identity_plan_v2",
      "apply_tenant_ldap_sync_absence_chunk_v2",
      "complete_tenant_ldap_sync_run_v2",
      "fail_tenant_ldap_sync_run_v2",
    ]) {
      expect(functionBody(fencedAbi, name)).toContain(
        "private_lock_tenant_ldap_sync_claim_v2",
      );
    }
    expect(
      functionBody(fencedAbi, "apply_tenant_ldap_sync_identity_plan_v2"),
    ).toContain("observation.planning_fence = p_claim_fence");
    expect(fencedAbi).toContain(
      "REVOKE EXECUTE ON FUNCTION app.claim_next_tenant_ldap_sync_run_v1(text) FROM periapsis_worker",
    );
    expect(fencedAbi).toContain("FROM periapsis_api, periapsis_worker;");
  });

  it("seals v12 and exposes only the exact v11 predecessor", () => {
    expect(fencedReadiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v12()",
    );
    expect(fencedReadiness).toContain("journal_count = 80");
    expect(fencedReadiness).toContain("1787658434202");
    expect(fencedReadiness).toContain("fingerprint_entries[1:76]");
    expect(fencedReadiness).toContain(
      "schema compatibility v10 must be retired",
    );
    expect(fencedReadiness).toContain(
      "an unfenced LDAP sync mutation surface remains executable",
    );
  });
});

describe("LDAP sync access-grant planning ABI v3 and readiness v13", () => {
  it("returns only the exact live access grant required by atomic apply", () => {
    const planning = functionBody(
      accessGrantPlanningAbi,
      "claim_tenant_ldap_sync_observation_planning_v3",
    );
    expect(planning).toContain("access_grant_id uuid");
    expect(planning).toContain("planning.access_grant_live IS DISTINCT FROM");
    expect(planning).toContain("matched_access_grant_id IS NOT NULL");
    for (const predicate of [
      "access_grant.tenant_id = planning.tenant_id",
      "access_grant.provider_id = planning.provider_id",
      "access_grant.binding_id = planning.binding_id",
      "access_grant.access_epoch_id = planning.binding_access_epoch_id",
      "access_grant.source_id = planning.provider_access_source_id",
      "access_grant.external_identity_id = planning.external_identity_id",
      "access_grant.membership_id = planning.membership_id",
      "access_grant.user_id = planning.user_id",
      "access_grant.ended_at IS NULL",
    ]) {
      expect(planning).toContain(predicate);
    }
    expect(planning).toContain("cardinality(matched_access_grant_ids), 0) > 1");
  });

  it("retires the mutating v2 projection and seals only v12 as predecessor", () => {
    expect(accessGrantPlanningAbi).toContain(
      "REVOKE ALL ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2",
    );
    expect(accessGrantReadiness).toContain(
      "CREATE FUNCTION app.schema_compatibility_v13()",
    );
    expect(accessGrantReadiness).toContain("journal_count = 82");
    expect(accessGrantReadiness).toContain("1787659623982");
    expect(accessGrantReadiness).toContain("fingerprint_entries[1:80]");
    expect(accessGrantReadiness).toContain(
      "schema compatibility v11 must be retired",
    );
    expect(accessGrantReadiness).toContain(
      "claim_tenant_ldap_sync_observation_planning_v2(uuid,uuid,uuid,bytea,bigint,integer[],bytea[])', false",
    );
    expect(accessGrantReadiness).toContain(
      "claim_tenant_ldap_sync_observation_planning_v3(uuid,uuid,uuid,bytea,bigint,integer[],bytea[])', true",
    );
  });
});
