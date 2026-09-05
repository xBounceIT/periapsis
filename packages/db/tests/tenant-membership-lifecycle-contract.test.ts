import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0212_tenant_membership_lifecycle.sql",
  ),
  "utf8",
);
const identitySchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/identity.ts"),
  "utf8",
);
const commandSchema = readFileSync(
  resolve(repositoryRoot, "packages/db/src/schema/membership-lifecycle.ts"),
  "utf8",
);
const openapi = readFileSync(
  resolve(repositoryRoot, "packages/contracts/openapi/openapi.yaml"),
  "utf8",
);
const workerCleanup = readFileSync(
  resolve(repositoryRoot, "services/worker/internal/postgres/auth_cleanup.go"),
  "utf8",
);

function functionBody(name: string): string {
  const marker = `CREATE FUNCTION app.${name}`;
  const start = migration.indexOf(marker);
  if (start < 0) throw new Error(`missing lifecycle function ${name}`);
  const end = migration.indexOf("$function$;", start);
  if (end < 0) throw new Error(`unterminated lifecycle function ${name}`);
  return migration.slice(start, end);
}

describe("tenant membership lifecycle contract", () => {
  it("models monotonic lifecycle state and an RLS-closed receipt ledger", () => {
    expect(identitySchema).toContain(
      'lifecycleRevision: integer("lifecycle_revision")',
    );
    expect(commandSchema).toContain("tenantMembershipLifecycleCommands");
    expect(commandSchema).toContain(
      "tenant_membership_lifecycle_commands_replay_key",
    );
    expect(commandSchema).toContain(
      "tenant_membership_lifecycle_commands_target_fk",
    );
    expect(commandSchema).toContain(".enableRLS()");
    expect(migration).toContain(
      "ALTER TABLE public.tenant_membership_lifecycle_commands FORCE ROW LEVEL SECURITY",
    );
    expect(migration).toContain(
      "ALTER TABLE public.tenant_membership_lifecycle_commands\n  OWNER TO periapsis_migrator",
    );
    expect(migration).toMatch(
      /REVOKE ALL ON TABLE public\.tenant_membership_lifecycle_commands\s+FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor/,
    );
    expect(migration).not.toMatch(
      /GRANT [^;]+ ON TABLE public\.tenant_membership_lifecycle_commands/,
    );
  });

  it("serializes payload-bound replay before reading or mutating state", () => {
    const command = functionBody("change_tenant_membership_lifecycle_v1");
    const advisory = command.indexOf("pg_advisory_xact_lock");
    const prune = command.indexOf(
      "DELETE FROM public.tenant_membership_lifecycle_commands",
    );
    const replay = command.indexOf("SELECT command.* INTO replay");
    const target = command.indexOf(
      "SELECT membership.* INTO target_membership",
    );

    expect(command).toContain("encode(p_idempotency_key_digest,'hex')");
    expect(command).toContain("canonical_request_digest := sha256");
    expect(advisory).toBeGreaterThan(-1);
    expect(advisory).toBeLessThan(prune);
    expect(prune).toBeLessThan(replay);
    expect(replay).toBeLessThan(target);
    expect(command).toContain(
      "idempotency key was already used for a different membership lifecycle request",
    );
  });

  it("couples safe first-class audit, revision, and targeted consequences", () => {
    const command = functionBody("change_tenant_membership_lifecycle_v1");
    const audit = functionBody("append_tenant_membership_lifecycle_audit_v1");

    expect(command).toContain("current_tenant_human_has_exact_permission_v3(");
    expect(command).toContain("'membership.manage','tenant'");
    expect(command).toContain(
      "app.private_platform_lifecycle_reason_is_valid_v1(p_reason)",
    );
    expect(audit).toContain("outcome,reason,before,after,metadata");
    expect(audit).toContain("'success',p_reason,p_before,p_after");
    expect(
      command.indexOf("append_tenant_membership_lifecycle_audit_v1"),
    ).toBeLessThan(
      command.indexOf("UPDATE public.tenant_memberships AS membership"),
    );
    expect(command).toContain("session.active_tenant_id = context_tenant");
    expect(command).toContain("continuation.tenant_id = context_tenant");
    expect(command).toContain(
      "session_invalidation_epoch = subject.session_invalidation_epoch + 1",
    );
    expect(command).toContain(
      "target_membership.id IS DISTINCT FROM actor_membership",
    );
    expect(command).not.toMatch(
      /p_target_status = 'active'[\s\S]*?SET revoked_at = NULL/,
    );
    expect(migration).toContain(
      "REVOKE ALL ON FUNCTION app.set_tenant_user_membership_status(",
    );
  });

  it("fences every live tenant session and uses a post-lock monotonic timestamp", () => {
    const guard = functionBody("guard_live_tenant_session_subject_v1");
    const command = functionBody("change_tenant_membership_lifecycle_v1");
    const localRotate = functionBody("rotate_auth_session(");
    const tenantRotate = functionBody("rotate_auth_session_tenant(");

    expect(guard).toContain("app.lock_live_tenant_session_subject_v1(");
    expect(migration).toContain(
      "BEFORE INSERT OR UPDATE ON public.auth_sessions",
    );
    expect(migration).toContain(
      "BEFORE INSERT OR UPDATE ON public.tenant_post_primary_continuations",
    );
    expect(
      localRotate.indexOf("lock_live_tenant_session_subject_v1"),
    ).toBeLessThan(
      localRotate.indexOf("private_unfenced_rotate_auth_session_v1"),
    );
    expect(
      tenantRotate.indexOf("lock_live_tenant_session_subject_v1"),
    ).toBeLessThan(
      tenantRotate.indexOf("private_unfenced_rotate_auth_session_tenant_v2"),
    );
    expect(command).toContain(
      "changed_at := greatest(clock_timestamp(),target_membership.updated_at)",
    );
    expect(command).toContain(
      "revoked_at = greatest(changed_at,session.created_at)",
    );
    expect(command).toContain(
      "revoked_at = greatest(changed_at,continuation.created_at)",
    );
    expect(command).toContain(
      "updated_at = greatest(changed_at,subject.updated_at)",
    );
  });

  it("repairs nominal upgrade zombies and exposes only a bounded worker pruner", () => {
    expect(migration).toContain(
      "revoke_reason = 'inactive_tenant_membership_fence_upgrade'",
    );
    expect(migration).toContain(
      "revoke_reason = 'untyped_tenant_session_membership_fence_upgrade'",
    );
    const pruner = functionBody(
      "prune_expired_tenant_membership_lifecycle_commands_v1",
    );
    expect(pruner).toContain("p_batch_size NOT BETWEEN 1 AND 1000");
    expect(pruner).toContain("command.expires_at <= transaction_timestamp()");
    expect(pruner).toContain("LIMIT p_batch_size");
    expect(pruner).toContain("FOR UPDATE SKIP LOCKED");
    expect(pruner).toContain("command.tenant_id = candidates.tenant_id");
    expect(migration).toContain(
      "GRANT EXECUTE ON FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)\n  TO periapsis_worker",
    );
    expect(migration).not.toContain(
      "GRANT EXECUTE ON FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)\n  TO periapsis_api",
    );
    expect(workerCleanup).toContain(
      "app.prune_expired_tenant_membership_lifecycle_commands_v1($1)",
    );
  });

  it("publishes exact human CSRF endpoints and preconditions", () => {
    for (const operation of [
      "suspendTenantMembership",
      "reactivateTenantMembership",
    ]) {
      const start = openapi.indexOf(`operationId: ${operation}`);
      const end = openapi.indexOf("operationId:", start + 20);
      const block = openapi.slice(start, end < 0 ? undefined : end);
      expect(block).toContain("sessionCookie: []");
      expect(block).toContain("csrfToken: []");
      expect(block).toContain("permission: membership.manage");
      expect(block).toContain('$ref: "#/components/parameters/IfMatch"');
      expect(block).toContain('$ref: "#/components/parameters/IdempotencyKey"');
      expect(block).toContain("Cache-Control:");
    }
  });
});
