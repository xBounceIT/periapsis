import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const structural = readFileSync(
  resolve(packageRoot, "migrations/0010_phase_2b_tenant_rbac.sql"),
  "utf8",
);
const security = readFileSync(
  resolve(packageRoot, "migrations/0011_phase_2b_tenant_rbac_security.sql"),
  "utf8",
);
const roleLimits = readFileSync(
  resolve(packageRoot, "migrations/0012_youthful_the_initiative.sql"),
  "utf8",
);
const roleKeyContract = readFileSync(
  resolve(packageRoot, "migrations/0013_smooth_molecule_man.sql"),
  "utf8",
);
const permissionTextContract = readFileSync(
  resolve(packageRoot, "migrations/0014_lumpy_chat.sql"),
  "utf8",
);
const rolePolicyAliasFix = readFileSync(
  resolve(packageRoot, "migrations/0015_fix_tenant_role_policy_alias.sql"),
  "utf8",
);
const directGrantSupersessionAudit = readFileSync(
  resolve(packageRoot, "migrations/0021_direct_grant_supersession_audit.sql"),
  "utf8",
);
const rolePolicyMutationResult = readFileSync(
  resolve(
    packageRoot,
    "migrations/0022_tenant_role_policy_mutation_result.sql",
  ),
  "utf8",
);
const archivedRoleDirectGrantRevoke = readFileSync(
  resolve(packageRoot, "migrations/0023_archived_role_direct_grant_revoke.sql"),
  "utf8",
);
const directGrantInventoryBoundaryHardening = readFileSync(
  resolve(
    packageRoot,
    "migrations/0024_direct_grant_inventory_boundary_hardening.sql",
  ),
  "utf8",
);
const authorizationCompatibilityAndOwnership = readFileSync(
  resolve(
    packageRoot,
    "migrations/0025_authorization_compatibility_and_ownership.sql",
  ),
  "utf8",
);

const permissionKeys = [
  "permission.read",
  "role.read",
  "role.manage",
  "role.grant",
  "user.read",
  "membership.manage",
] as const;
const builtInRoleKeys = [
  "tenant_admin",
  "soc_manager",
  "senior_analyst",
  "analyst",
  "customer_manager",
  "customer_user",
  "read_only",
  "service_account",
] as const;

describe("Phase 2B.1 tenant authorization contract", () => {
  it("keeps canonical role keys identical across storage and API validation", () => {
    expect(roleKeyContract).toContain("^[a-z][a-z0-9_]{2,63}$");
    expect(roleKeyContract).not.toContain("^[a-z][a-z0-9_]{0,62}[a-z0-9]$");
  });

  it("keeps permission descriptions control-free at the storage boundary", () => {
    expect(permissionTextContract).toContain(
      '"tenant_permissions"."description" !~ \'[[:cntrl:]]\'',
    );
  });

  it("repairs role-policy replacement without colliding with the PL/pgSQL record variable", () => {
    expect(rolePolicyAliasFix).toContain(
      'CREATE OR REPLACE FUNCTION "app"."replace_tenant_role_policy"',
    );
    expect(rolePolicyAliasFix).toContain(
      "AS policy_input(permission_key, scope)",
    );
    expect(rolePolicyAliasFix).toContain(
      "AS ceiling_input(permission_key, scope)",
    );
    expect(rolePolicyAliasFix).not.toContain(
      "AS requested(permission_key, scope)",
    );
  });

  it("returns self-demoting role-policy mutations without a second caller-authorized read", () => {
    expect(rolePolicyMutationResult).toContain(
      'CREATE FUNCTION "app"."replace_tenant_role_policy_with_result"',
    );
    expect(rolePolicyMutationResult).toContain(
      "mutated_version := app.replace_tenant_role_policy(",
    );
    expect(rolePolicyMutationResult).toContain("SECURITY DEFINER");
    expect(rolePolicyMutationResult).toContain(
      "SET search_path = pg_catalog, public, app",
    );
    expect(rolePolicyMutationResult).toContain(
      ') OWNER TO "periapsis_migrator"',
    );
    expect(rolePolicyMutationResult).toContain(') TO "periapsis_api"');
    expect(rolePolicyMutationResult).toContain(
      "WHERE policy.tenant_id = context_tenant",
    );
    expect(rolePolicyMutationResult).toContain(
      "AND role.version = mutated_version",
    );
    expect(rolePolicyMutationResult).not.toMatch(
      /TO "periapsis_(?:worker|notifier|auditor)"/,
    );
    expect(
      rolePolicyMutationResult.indexOf(
        "mutated_version := app.replace_tenant_role_policy(",
      ),
    ).toBeLessThan(
      rolePolicyMutationResult.indexOf("FROM public.tenant_roles AS role"),
    );
  });

  it("generates the structural authorization model and dependency-ordered tenant FKs", () => {
    for (const table of [
      "tenant_permissions",
      "tenant_permission_scopes",
      "tenant_authorization_sources",
      "tenant_authorization_states",
      "tenant_authorization_commands",
      "tenant_roles",
      "tenant_role_permissions",
      "tenant_role_delegation_ceilings",
      "tenant_membership_role_grants",
    ]) {
      expect(structural).toContain(`CREATE TABLE "${table}"`);
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(`REVOKE ALL ON TABLE "public"."${table}"`);
    }

    expect(structural).toContain(
      'CONSTRAINT "tenant_memberships_tenant_id_key" UNIQUE("tenant_id","id")',
    );
    expect(
      security.match(
        /REFERENCES "public"\."tenant_memberships"\("tenant_id","id"\)/g,
      ),
    ).toHaveLength(7);
  });

  it("seeds exactly the human tenant permission catalog", () => {
    for (const permissionKey of permissionKeys) {
      expect(security).toContain(`'${permissionKey}'`);
    }

    expect(security).toContain("ARRAY['human']::text[]");
    expect(security).toContain("permission.service_account_allowed");
    expect(security).toContain(
      "permission_scope.scope IS DISTINCT FROM 'tenant'",
    );
    expect(security).not.toContain("platform.tenant.authorization.initialize");
  });

  it("seeds all eight built-ins while protecting only the fully privileged tenant admin", () => {
    for (const roleKey of builtInRoleKeys) {
      expect(security).toContain(`'${roleKey}'`);
    }

    expect(security).toContain(
      "only tenant_admin may be the protected built-in tenant role",
    );
    expect(security).toContain(
      "non-admin built-in roles must remain empty in Phase 2B.1",
    );
    expect(security).toContain(
      "INSERT INTO public.tenant_role_delegation_ceilings",
    );
  });

  it("publishes the UUID-cursored aggregate permission catalog", () => {
    expect(security).toContain(
      'CREATE FUNCTION "app"."list_tenant_permission_catalog"(\n  p_after_id uuid,',
    );
    expect(security).toContain("permission_id uuid");
    expect(security).toContain("display_name text");
    expect(security).toContain(
      'allowed_scopes "public"."authorization_scope"[]',
    );
    expect(security).toContain("principal_kinds text[]");
    expect(security).toContain("ORDER BY permission.id");
  });

  it("keeps lists narrowly authorized and permits exact role getters for grant composition", () => {
    expect(security).toMatch(
      /CREATE FUNCTION "app"\."list_tenant_roles"[\s\S]+?current_tenant_has_exact_permission\('role\.read', 'tenant'\)[\s\S]+?END;\n\$function\$/,
    );
    expect(security).toMatch(
      /CREATE FUNCTION "app"\."get_tenant_role"[\s\S]+?role\.read[\s\S]+?role\.manage[\s\S]+?role\.grant[\s\S]+?END;\n\$function\$/,
    );
    expect(security).toMatch(
      /CREATE FUNCTION "app"\."get_tenant_role_policy"[\s\S]+?role\.read[\s\S]+?role\.manage[\s\S]+?role\.grant[\s\S]+?END;\n\$function\$/,
    );
    expect(security).toContain(
      'CREATE FUNCTION "app"."list_tenant_roles"(\n  p_after_id uuid,\n  p_include_archived boolean,',
    );
  });

  it("returns a coherent, de-duplicated live human authority projection", () => {
    expect(security).toContain("membership_status");
    expect(security).toContain("compatibility_role");
    expect(security).toContain(
      "membership.status, membership.role, transaction_timestamp()",
    );
    expect(security).toContain(
      "GROUP BY effective.permission_key, effective.scope",
    );
    expect(security).toContain(
      "bool_or(effective.is_delegable AND effective.expires_at IS NULL)",
    );
    expect(security).toContain("max(effective.expires_at)");
    expect(security).toContain("role.display_name");
  });

  it("keeps direct-grant resources separate from inherited authority provenance", () => {
    const directGrantFunctions = security.slice(
      security.indexOf(
        'CREATE FUNCTION "app"."list_tenant_membership_role_grants"',
      ),
      security.indexOf('CREATE FUNCTION "app"."replace_tenant_role_policy"'),
    );

    expect(directGrantFunctions.match(/source\.kind = 'manual'/g)).toHaveLength(
      2,
    );
    expect(directGrantFunctions.match(/'direct'::text/g)).toHaveLength(2);
    expect(
      security.slice(
        security.indexOf(
          'CREATE FUNCTION "app"."resolve_current_tenant_human_role_grants"',
        ),
        security.indexOf('CREATE FUNCTION "app"."create_tenant_role"'),
      ),
    ).toContain("WHEN 'identity_mapping' THEN 'identity_provider'");
  });

  it("enforces exact permission subsets and grant lifetime ceilings", () => {
    expect(security).toContain(
      "delegation ceiling must be an exact subset of role permissions",
    );
    expect(security).toContain(
      "requested role policy exceeds the exact delegation ceiling",
    );
    expect(security).toContain(
      "role grant exceeds the exact delegation ceiling or lifetime",
    );
    expect(security).toContain("requested.scope = 'platform'");
  });

  it("persists bounded, append-only, tenant-validated command replays", () => {
    expect(structural).toContain(
      'CONSTRAINT "tenant_authorization_commands_digest_check"',
    );
    expect(structural).toContain(
      'octet_length("tenant_authorization_commands"."key_digest") = 32',
    );
    expect(structural).toContain("interval '7 days'");
    expect(security).toContain(
      'CREATE FUNCTION "app"."guard_tenant_authorization_command"()',
    );
    expect(security).toContain(
      "tenant role idempotency result is not a same-tenant role version",
    );
    expect(security).toContain(
      "tenant role grant idempotency result is not a same-tenant grant version",
    );
    expect(security).toContain(
      "tenant authorization command rows are append-only",
    );
    expect(security).toContain("tenant_authorization_commands_replay_key");
    expect(security).toContain("result_version integer");
    expect(security).toContain("replayed boolean");
  });

  it("serializes authority mutations and defers the last recovery-admin invariant", () => {
    expect(security).toContain("FOR UPDATE");
    expect(security).toContain("revision = state.revision + 1");
    expect(security).toContain("DEFERRABLE INITIALLY DEFERRED");
    expect(security).toContain("tenant_last_recovery_admin_check");
    expect(security).toContain(
      "initialized tenant must retain a live direct non-expiring human tenant_admin grant",
    );
  });

  it("keeps revocation provenance complete despite SQL NULL semantics", () => {
    expect(structural).toMatch(
      /tenant_membership_role_grants_revocation_check[\s\S]+?"revoked_at" is not null[\s\S]+?"revoked_by_membership_id" is not null[\s\S]+?"revoke_reason" is not null/,
    );
  });

  it("adds direct-grant supersession provenance through a forward function replacement", () => {
    const originalDeclaration = security.match(
      /CREATE FUNCTION "app"\."grant_tenant_user_role"\([\s\S]*?\nLANGUAGE plpgsql/,
    )?.[0];
    const replacementDeclaration = directGrantSupersessionAudit.match(
      /CREATE OR REPLACE FUNCTION "app"\."grant_tenant_user_role"\([\s\S]*?\nLANGUAGE plpgsql/,
    )?.[0];

    expect(security).not.toContain("superseded_role_grants");
    expect(originalDeclaration).toBeDefined();
    expect(replacementDeclaration).toBeDefined();
    expect(replacementDeclaration?.replace("CREATE OR REPLACE", "CREATE")).toBe(
      originalDeclaration,
    );
    expect(directGrantSupersessionAudit).toContain(
      'CREATE OR REPLACE FUNCTION "app"."grant_tenant_user_role"(',
    );
    expect(directGrantSupersessionAudit).not.toContain("DROP FUNCTION");
    expect(directGrantSupersessionAudit).toContain(
      "'role_grant_id', old_grant.id",
    );
    expect(directGrantSupersessionAudit).toContain(
      "'prior_version', old_grant.version",
    );
    expect(directGrantSupersessionAudit).toContain(
      "'result_version', old_grant.version + 1",
    );
    expect(directGrantSupersessionAudit).toContain("ORDER BY old_grant.id");
    expect(directGrantSupersessionAudit).toContain(
      "'superseded_role_grants', superseded_role_grants",
    );
    expect(
      directGrantSupersessionAudit.indexOf("INTO superseded_role_grants"),
    ).toBeLessThan(
      directGrantSupersessionAudit.indexOf(
        "UPDATE public.tenant_membership_role_grants AS old_grant",
      ),
    );
    expect(directGrantSupersessionAudit).toContain("SECURITY DEFINER");
    expect(directGrantSupersessionAudit).toContain(
      "SET search_path = pg_catalog, public, app",
    );
  });

  it("keeps manual direct grants revocable after their custom role is archived", () => {
    const originalDeclaration = security.match(
      /CREATE FUNCTION "app"\."revoke_tenant_user_role_grant"\([\s\S]*?\nLANGUAGE plpgsql/,
    )?.[0];
    const replacementDeclaration = archivedRoleDirectGrantRevoke.match(
      /CREATE OR REPLACE FUNCTION "app"\."revoke_tenant_user_role_grant"\([\s\S]*?\nLANGUAGE plpgsql/,
    )?.[0];

    expect(originalDeclaration).toBeDefined();
    expect(replacementDeclaration).toBeDefined();
    expect(replacementDeclaration?.replace("CREATE OR REPLACE", "CREATE")).toBe(
      originalDeclaration,
    );
    expect(archivedRoleDirectGrantRevoke).toContain(
      "role.archived_at AS role_archived_at",
    );
    expect(archivedRoleDirectGrantRevoke).toMatch(
      /JOIN public\.tenant_roles AS role[\s\S]+?role\.id = role_grant\.role_id/,
    );
    expect(archivedRoleDirectGrantRevoke).toMatch(
      /IF target_grant\.role_archived_at IS NULL[\s\S]+?PERFORM app\.assert_actor_can_grant_role/,
    );
    expect(archivedRoleDirectGrantRevoke).toContain("SECURITY DEFINER");
    expect(archivedRoleDirectGrantRevoke).toContain(
      "SET search_path = pg_catalog, public, app",
    );
    expect(archivedRoleDirectGrantRevoke).toContain(
      ') OWNER TO "periapsis_migrator"',
    );
    expect(archivedRoleDirectGrantRevoke).toContain(') TO "periapsis_api"');
    expect(archivedRoleDirectGrantRevoke).not.toMatch(
      /TO "periapsis_(?:worker|notifier|auditor)"/,
    );
  });

  it("returns every direct-grant owner while preserving source provenance", () => {
    for (const functionName of [
      "list_tenant_membership_role_grants",
      "get_tenant_membership_role_grant",
    ]) {
      const body = directGrantInventoryBoundaryHardening.slice(
        directGrantInventoryBoundaryHardening.indexOf(
          `CREATE FUNCTION "app"."${functionName}"`,
        ),
        directGrantInventoryBoundaryHardening.indexOf(
          "$function$;",
          directGrantInventoryBoundaryHardening.indexOf(
            `CREATE FUNCTION "app"."${functionName}"`,
          ),
        ),
      );

      expect(body).toContain("source_authoritative boolean");
      expect(body).toContain("source_retired_at timestamp with time zone");
      expect(body).toContain("source.authoritative");
      expect(body).toContain("source.retired_at");
      expect(body).toContain("WHEN 'manual' THEN 'direct'");
      expect(body).toContain(
        "WHEN 'identity_mapping' THEN 'identity_provider'",
      );
      expect(body).toContain("ELSE 'system'");
      expect(body).not.toContain("source.kind = 'manual'");
    }

    expect(directGrantInventoryBoundaryHardening).toContain(
      'DROP FUNCTION "app"."list_tenant_membership_role_grants"(',
    );
    expect(directGrantInventoryBoundaryHardening).toContain(
      'DROP FUNCTION "app"."get_tenant_membership_role_grant"(uuid)',
    );
    expect(directGrantInventoryBoundaryHardening).not.toContain("CASCADE");
    expect(directGrantInventoryBoundaryHardening).not.toMatch(
      /TO "periapsis_(?:worker|notifier|auditor)"/,
    );
  });

  it("keeps the immediate 0024 database ABI while versioning ownership metadata", () => {
    for (const functionName of [
      "list_tenant_membership_role_grants",
      "get_tenant_membership_role_grant",
    ]) {
      const predecessorDeclaration =
        directGrantInventoryBoundaryHardening.match(
          new RegExp(
            `CREATE FUNCTION "app"\\."${functionName}"\\([\\s\\S]*?\\nLANGUAGE plpgsql`,
          ),
        )?.[0];
      const restoredDeclaration = authorizationCompatibilityAndOwnership.match(
        new RegExp(
          `CREATE FUNCTION "app"\\."${functionName}"\\([\\s\\S]*?\\nLANGUAGE plpgsql`,
        ),
      )?.[0];

      expect(predecessorDeclaration).toBeDefined();
      expect(restoredDeclaration).toBe(predecessorDeclaration);
      expect(authorizationCompatibilityAndOwnership).toContain(
        `CREATE FUNCTION "app"."${functionName}_v2"`,
      );
    }

    const originalResolver = security.match(
      /CREATE FUNCTION "app"\."resolve_current_tenant_human_role_grants"\([\s\S]*?\n\$function\$;/,
    )?.[0];
    const restoredResolver = authorizationCompatibilityAndOwnership.match(
      /CREATE FUNCTION "app"\."resolve_current_tenant_human_role_grants"\([\s\S]*?\n\$function\$;/,
    )?.[0];
    expect(originalResolver).toBeDefined();
    expect(restoredResolver).toBe(originalResolver);
    expect(authorizationCompatibilityAndOwnership).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer)',
    );
  });

  it("derives and enforces exact canonical direct-grant ownership", () => {
    for (const functionName of [
      "list_tenant_membership_role_grants_v2",
      "get_tenant_membership_role_grant_v2",
    ]) {
      const start = authorizationCompatibilityAndOwnership.indexOf(
        `CREATE FUNCTION "app"."${functionName}"`,
      );
      const body = authorizationCompatibilityAndOwnership.slice(
        start,
        authorizationCompatibilityAndOwnership.indexOf("$function$;", start),
      );
      expect(start).toBeGreaterThan(-1);
      expect(body).toContain("managed_by_authorization_api boolean");
      expect(body).toContain("source.key = 'manual'");
      expect(body).toContain("source.kind = 'manual'");
      expect(body).toContain("source.protected");
      expect(body).toContain("source.retired_at IS NULL");
      expect(
        body.slice(body.lastIndexOf("\n  WHERE role_grant.tenant_id")),
      ).not.toContain("source.kind = 'manual'");
    }

    const revokeStart = authorizationCompatibilityAndOwnership.indexOf(
      'CREATE OR REPLACE FUNCTION "app"."revoke_tenant_user_role_grant"',
    );
    const revokeBody = authorizationCompatibilityAndOwnership.slice(
      revokeStart,
      authorizationCompatibilityAndOwnership.indexOf(
        "$function$;",
        revokeStart,
      ),
    );
    expect(revokeBody).toContain("AND source.key = 'manual'");
    expect(revokeBody).toContain("AND source.kind = 'manual'");
    expect(revokeBody).toContain("AND source.protected");
    expect(revokeBody).toContain("AND source.retired_at IS NULL");
  });

  it("backfills one sealed redacted legacy RBAC audit for either initialization state", () => {
    const auditBackfill = authorizationCompatibilityAndOwnership.slice(
      authorizationCompatibilityAndOwnership.lastIndexOf(
        "INSERT INTO public.audit_events",
      ),
    );
    expect(auditBackfill).toContain("INSERT INTO public.audit_events");
    expect(auditBackfill).toContain("'system'");
    expect(auditBackfill).toContain("'database_migration'");
    expect(auditBackfill).toContain(
      "'tenant.authorization.migration_backfilled'",
    );
    expect(auditBackfill).toContain(
      "'authorization_initialized', state.initialized_at IS NOT NULL",
    );
    expect(auditBackfill).toContain("'recovery_grant_initialized', EXISTS (");
    expect(auditBackfill).not.toContain(
      "WHERE state.initialized_at IS NOT NULL",
    );
    expect(auditBackfill).toContain("recovery_source.key = 'tenant_creation'");
    expect(auditBackfill).toContain(
      "existing.action = 'tenant.authorization.initialized'",
    );
    expect(auditBackfill).toContain("existing.resource_id = state.tenant_id");
    expect(auditBackfill).toContain(
      "existing.action = 'tenant.authorization.migration_backfilled'",
    );
    expect(auditBackfill).toContain("existing.metadata ->> 'migration'");
    expect(auditBackfill).not.toMatch(
      /actor_user_id|impersonated_by_user_id|request_id|correlation_id|ip_address|user_agent/,
    );
  });

  it("fails closed on omitted optimistic-lock versions at every final boundary", () => {
    for (const functionName of [
      "update_tenant_role_metadata",
      "revoke_tenant_user_role_grant",
    ]) {
      const body = directGrantInventoryBoundaryHardening.slice(
        directGrantInventoryBoundaryHardening.indexOf(
          `CREATE OR REPLACE FUNCTION "app"."${functionName}"`,
        ),
        directGrantInventoryBoundaryHardening.indexOf(
          "$function$;",
          directGrantInventoryBoundaryHardening.indexOf(
            `CREATE OR REPLACE FUNCTION "app"."${functionName}"`,
          ),
        ),
      );

      expect(body).toMatch(/version IS DISTINCT FROM p_expected_version/);
      expect(body).not.toMatch(/version <> p_expected_version/);
      expect(body).toContain("ERRCODE = '40001'");
    }
  });

  it("couples all authorization mutations to fully attributed tenant audits", () => {
    expect(security).toContain("p_ip_address inet");
    expect(security).toContain("p_user_agent text");
    expect(security).toContain("p_authentication_method text");
    expect(security).toContain(
      "authorization mutation requires a live authentication method",
    );
    expect(security).toContain("length(p_user_agent) NOT BETWEEN 1 AND 1024");

    for (const action of [
      "tenant.role.created",
      "tenant.role.metadata_updated",
      "tenant.role.policy_replaced",
      "tenant.role.archived",
      "tenant.role_grant.created",
      "tenant.role_grant.revoked",
      "tenant.membership.status_changed",
    ]) {
      expect(security).toContain(`'${action}'`);
    }
  });

  it("enforces the transport-aligned role metadata limits in schema and mutators", () => {
    expect(roleLimits).toContain(
      'char_length("tenant_roles"."display_name") <= 120',
    );
    expect(roleLimits).toContain(
      'char_length("tenant_roles"."description") <= 500',
    );
    expect(security.match(/at most 120 characters/g)).toHaveLength(2);
    expect(security.match(/at most 500 characters/g)).toHaveLength(2);
  });

  it("reserves serialization failures for strong-version precondition mismatches", () => {
    expect(security.match(/ERRCODE = '40001'/g)).toHaveLength(4);

    for (const [functionName, stateMessage] of [
      [
        "update_tenant_role_metadata",
        "built-in or protected roles cannot be edited",
      ],
      [
        "replace_tenant_role_policy",
        "built-in or protected role policies cannot be replaced",
      ],
      ["archive_tenant_role", "built-in or protected roles cannot be archived"],
      [
        "revoke_tenant_user_role_grant",
        "direct tenant role grant is already revoked",
      ],
    ] as const) {
      const body = security.slice(
        security.indexOf(`CREATE FUNCTION "app"."${functionName}"`),
        security.indexOf(
          "$function$;",
          security.indexOf(`CREATE FUNCTION "app"."${functionName}"`),
        ),
      );
      expect(body.indexOf("version conflict")).toBeGreaterThan(-1);
      expect(body.indexOf("version conflict")).toBeLessThan(
        body.indexOf(stateMessage),
      );
      expect(body).toMatch(/version conflict[\s\S]+?ERRCODE = '40001'/);
      expect(body.slice(body.indexOf(stateMessage))).toContain(
        "ERRCODE = '55000'",
      );
    }
  });

  it("initializes tenant authorization atomically without adding platform permissions", () => {
    expect(security).toContain(
      'CREATE OR REPLACE FUNCTION "app"."create_platform_tenant"(',
    );
    expect(security).toContain("PERFORM app.seed_tenant_authorization(");
    expect(security).toContain("'platform.tenant.created'");
    expect(security).toContain("'tenant.authorization.initialized'");
    expect(security).toContain(
      "No analyst or arbitrary oldest member is promoted",
    );
  });
});
