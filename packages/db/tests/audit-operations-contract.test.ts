import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0213_audit_export_retention.sql",
  ),
  "utf8",
);
const v49PredecessorRepair = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0228_tenant_federation_administration.sql",
  ),
  "utf8",
);
const schema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/audit-operations.ts"),
  "utf8",
);

function functionBody(name: string): string {
  const createMarker = `CREATE FUNCTION app.${name}`;
  const replaceMarker = `CREATE OR REPLACE FUNCTION app.${name}`;
  const createStart = migration.indexOf(createMarker);
  const replaceStart = migration.indexOf(replaceMarker);
  const start = createStart >= 0 ? createStart : replaceStart;
  if (start < 0) throw new Error(`missing audit operation function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated audit operation function ${name}`);
  return migration.slice(start, end);
}

describe("audit export and retention contract", () => {
  it("models separate tenant and platform jobs behind forced RLS", () => {
    for (const relation of [
      "tenant_audit_export_jobs",
      "platform_audit_export_jobs",
      "tenant_audit_export_manifests",
      "platform_audit_export_manifests",
      "tenant_audit_retention_policies",
      "platform_audit_retention_policy",
      "tenant_audit_legal_holds",
      "platform_audit_legal_holds",
      "tenant_audit_segments",
      "platform_audit_segments",
      "tenant_audit_retention_anchors",
      "platform_audit_retention_anchor",
    ]) {
      expect(migration).toContain(`public.${relation}`);
      expect(schema).toContain(`"${relation}"`);
    }
    expect(migration).toContain("ENABLE ROW LEVEL SECURITY");
    expect(migration).toContain("FORCE ROW LEVEL SECURITY");
    expect(migration).toMatch(/NOLOGIN[^;]*NOBYPASSRLS/);
    expect(migration).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE)[^;]*ON TABLE[^;]*audit_export[^;]*TO periapsis_(?:api|worker|notifier|auditor)/s,
    );
  });

  it("pins request authority and serializes payload-bound idempotency", () => {
    for (const name of [
      "create_tenant_audit_export_v1",
      "create_platform_audit_export_v1",
      "cancel_tenant_audit_export_v1",
      "cancel_platform_audit_export_v1",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("pg_advisory_xact_lock");
      expect(body).toContain("payload_digest");
      expect(body).toContain("idempotency key was reused");
      expect(body.indexOf("pg_advisory_xact_lock")).toBeLessThan(
        body.indexOf("SELECT * INTO existing_receipt"),
      );
    }
    expect(schema).toContain("requesterMembershipId");
    expect(schema).toContain("membershipLifecycleRevision");
    expect(schema).toContain("requesterSessionId");
    expect(schema).toContain("permissionEpoch");
    expect(migration).toContain(
      "bump_platform_authorization_epoch_on_role_permission_v1",
    );
    expect(migration).toContain(
      "AFTER INSERT OR UPDATE OR DELETE ON public.platform_role_permissions",
    );
  });

  it("keeps the NOLOGIN owner's row-lock privilege mutation-inert", () => {
    expect(migration).toContain(
      "GRANT UPDATE ON TABLE public.auth_sessions,public.tenant_memberships,\n  public.tenant_authorization_states TO periapsis_audit_operations_owner;",
    );
    for (const relation of [
      "auth_sessions",
      "tenant_memberships",
      "tenant_authorization_states",
    ]) {
      expect(migration).not.toMatch(
        new RegExp(
          `CREATE POLICY [^;]+ ON public\\.${relation}\\s+FOR UPDATE TO periapsis_audit_operations_owner`,
        ),
      );
    }
    expect(migration).not.toMatch(
      /GRANT UPDATE ON TABLE public\.auth_sessions,public\.tenant_memberships,[^;]*TO periapsis_(?:api|worker|notifier|auditor)/,
    );
    expect(migration).toContain(
      "GRANT SELECT,INSERT,UPDATE ON TABLE public.platform_user_authorization_epochs\nTO periapsis_migrator;",
    );
    expect(migration).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE)[^;]*ON TABLE public\.platform_user_authorization_epochs[^;]*TO periapsis_(?:api|worker|notifier|auditor)/,
    );
    for (const signature of [
      "app.private_require_tenant_audit_operation_actor_v1(uuid,text,boolean)",
      "app.private_require_platform_audit_operation_actor_v1(uuid,text,boolean)",
    ]) {
      expect(migration).toContain(
        `ALTER FUNCTION ${signature}\n  OWNER TO periapsis_migrator;`,
      );
      expect(migration).toContain(
        `GRANT EXECUTE ON FUNCTION ${signature}\nTO periapsis_audit_operations_owner;`,
      );
      expect(migration).not.toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION ${signature.replaceAll(".", "\\.")}[^;]*TO periapsis_api`,
        ),
      );
    }
    const tenantHelper = functionBody(
      "private_require_tenant_audit_operation_actor_v1",
    );
    expect(tenantHelper).toContain(
      "p_permission NOT IN ('audit.export','audit.retention.manage')",
    );
    expect(tenantHelper).toContain("membership.status = 'active'");
    expect(tenantHelper).toContain("tenant.status = 'active'");
    expect(tenantHelper).toContain("session.user_id = context_user");
    expect(tenantHelper).toContain("session.active_tenant_id = context_tenant");
    for (const signature of [
      "app.private_lock_tenant_audit_retention_chain_v1(uuid)",
      "app.private_lock_platform_audit_retention_chain_v1()",
    ]) {
      expect(migration).toContain(
        `ALTER FUNCTION ${signature}\n  OWNER TO periapsis_migrator;`,
      );
      expect(migration).toContain(
        `GRANT EXECUTE ON FUNCTION ${signature}\nTO periapsis_audit_operations_owner;`,
      );
    }
    expect(functionBody("close_tenant_audit_segment_v1")).toContain(
      "private_lock_tenant_audit_retention_chain_v1(p_tenant_id)",
    );
    expect(functionBody("close_platform_audit_segment_v1")).toContain(
      "private_lock_platform_audit_retention_chain_v1()",
    );
  });

  it("reauthorizes every worker page and publishes only a scoped redacted artifact", () => {
    const tenantPage = functionBody("read_tenant_audit_export_page_v1");
    const platformPage = functionBody("read_platform_audit_export_page_v1");
    const tenantFinalize = functionBody("finalize_tenant_audit_export_v1");
    const platformFinalize = functionBody("finalize_platform_audit_export_v1");
    expect(tenantPage).toContain(
      "private_tenant_audit_export_job_authorized_v1",
    );
    expect(platformPage).toContain(
      "private_platform_audit_export_job_authorized_v1",
    );
    for (const body of [tenantPage, platformPage]) {
      expect(body).toContain("'projectionVersion',1");
      expect(body).not.toContain("SELECT event.*");
      expect(body).not.toMatch(
        /password|ciphertext|token_digest|csrf_secret_digest/i,
      );
    }
    expect(tenantFinalize).toContain(
      "'tenants/'||locked_job.tenant_id::text||'/audit/exports/'",
    );
    expect(platformFinalize).toContain("'platform/audit/exports/'");
    expect(tenantFinalize).toContain(
      "octet_length(p_digest) IS DISTINCT FROM 32",
    );
    expect(platformFinalize).toContain(
      "artifact_rows=p_rows,artifact_bytes=p_bytes",
    );
  });

  it("never returns a raw object URL and freshly authorizes download", () => {
    for (const name of [
      "authorize_tenant_audit_export_download_v1",
      "authorize_platform_audit_export_download_v1",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("private_require_");
      expect(body).toContain("object_key");
      expect(body).toContain("digest");
      expect(body).toContain(
        "permission_epoch IS DISTINCT FROM actor.permission_epoch",
      );
      expect(body).not.toMatch(/https?:\/\//);
      expect(body).not.toMatch(/presign|redirect/i);
    }
    expect(functionBody("authorize_tenant_audit_export_download_v1")).toContain(
      "membership_lifecycle_revision IS DISTINCT FROM actor.membership_lifecycle_revision",
    );
  });

  it("requires signed preserved contiguous prefixes and blocks legal holds", () => {
    for (const name of [
      "prune_tenant_audit_segment_v1",
      "prune_platform_audit_segment_v1",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("p_signature_verified IS NOT TRUE");
      expect(body).toContain("p_observed_object_key");
      expect(body).toContain("p_observed_signature");
      expect(body).toContain("does not extend the protected anchor");
      expect(body).toContain("database prefix is not exact");
      expect(body).toContain("legal hold");
      expect(body).toContain("prefix_pruned");
      expect(body.indexOf("DELETE FROM public.")).toBeLessThan(
        body.indexOf("retained_through_sequence="),
      );
    }
    expect(migration).toContain(
      "octet_length(p_signature) IS DISTINCT FROM 64",
    );
    expect(migration).toContain(
      "signing_key_id ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$'",
    );
  });

  it("prunes JIT only when terminal, fully covered, and provenance-free", () => {
    const eligibility = functionBody(
      "private_ldap_jit_run_is_retention_eligible_v1",
    );
    expect(eligibility).toContain(
      "run.status IN ('denied','failed','stale','expired')",
    );
    expect(eligibility).toContain("begin_event.sequence BETWEEN");
    expect(eligibility).toContain("terminal_event.sequence BETWEEN");
    expect(eligibility).toContain("auth_session_ldap_provenance");
    expect(eligibility).toContain("tenant_post_primary_ldap_provenance");
    expect(eligibility).toContain(
      "tenant_ldap_jit_authority_issuance_receipts",
    );
    expect(migration).toContain("tenant_audit_retention_prune_capabilities");
    expect(migration).not.toMatch(
      /GRANT DELETE ON TABLE public\.tenant_ldap_jit_[^;]+TO periapsis_(?:api|worker|notifier|auditor)/s,
    );
  });

  it("lets only the migrator-owned JIT guards invoke retention eligibility", () => {
    const signature =
      "app.private_ldap_jit_run_is_retention_eligible_v1(uuid,uuid)";
    expect(v49PredecessorRepair).toContain(
      `GRANT EXECUTE ON FUNCTION ${signature}\nTO periapsis_migrator;`,
    );
    expect(v49PredecessorRepair).not.toMatch(
      /GRANT EXECUTE ON FUNCTION app\.private_ldap_jit_run_is_retention_eligible_v1\(uuid,uuid\)[^;]*TO (?:PUBLIC|periapsis_(?:api|worker|notifier|auditor))\s*;/u,
    );
  });

  it("keeps zero-anchor verification compatible and exposes the retained prefix", () => {
    for (const name of [
      "verify_tenant_audit_chain_v2",
      "verify_platform_audit_chain_v2",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("anchor_sequence bigint:=0");
      expect(body).toContain("anchor_hash character(64):=repeat('0',64)");
      expect(body).toContain("anchor_sequence+row_number()");
      expect(body).toContain("lag(event.event_hash,1,anchor_hash)");
      expect(body).toContain("retainedThroughSequence");
    }
  });

  it("bounds receipt pruning behind worker-only ABIs", () => {
    for (const name of [
      "prune_tenant_audit_operation_receipts_v1",
      "prune_platform_audit_operation_receipts_v1",
    ]) {
      const body = functionBody(name);
      expect(body).toContain("p_limit NOT BETWEEN 1 AND 1000");
      expect(body).toContain("expires_at<=transaction_timestamp()");
      expect(body).toContain("FOR UPDATE SKIP LOCKED LIMIT p_limit");
      expect(migration).toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION app\\.${name}\\([\\s\\S]*?TO periapsis_worker`,
        ),
      );
    }
  });

  it("schedules retention without exposing tenant relations or duplicating an anchored segment", () => {
    const tenantCandidates = functionBody(
      "list_tenant_audit_retention_candidates_v1",
    );
    const tenantWork = functionBody("get_tenant_audit_retention_work_v1");
    const platformWork = functionBody("get_platform_audit_retention_work_v1");
    expect(tenantCandidates).toContain("p_limit NOT BETWEEN 1 AND 1000");
    expect(tenantCandidates).toContain("tenant_audit_retention_policies");
    expect(tenantCandidates).toContain("tenant_audit_operation_receipts");
    expect(tenantWork).toContain("segment.start_sequence=anchor_sequence+1");
    expect(platformWork).toContain("segment.start_sequence=anchor_sequence+1");
    expect(tenantWork).toContain("tenant_audit_legal_holds");
    expect(platformWork).toContain("platform_audit_legal_holds");
    expect(functionBody("close_tenant_audit_segment_v1")).toContain(
      "segment.state IN ('closed','preserved')",
    );
    expect(functionBody("close_platform_audit_segment_v1")).toContain(
      "segment.state IN ('closed','preserved')",
    );
    for (const name of [
      "list_tenant_audit_retention_candidates_v1",
      "get_tenant_audit_retention_work_v1",
      "get_platform_audit_retention_work_v1",
    ]) {
      expect(migration).toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION app\\.${name}\\([\\s\\S]*?TO periapsis_worker`,
        ),
      );
    }
  });
});
