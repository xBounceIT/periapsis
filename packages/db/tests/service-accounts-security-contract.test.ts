import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");

function readRequiredMigration(fileName: string): string {
  const source = readFileSync(
    resolve(packageRoot, "migrations", fileName),
    "utf8",
  );
  if (source.trim().length === 0) {
    throw new Error(`Migration ${fileName} must not be empty`);
  }
  return source;
}

const compatibility = readRequiredMigration(
  "0035_service_principal_compatibility.sql",
);
const predecessorSecurity = readRequiredMigration(
  "0028_phase_2b_operator_teams_security.sql",
);
const predecessorMutationResult = readRequiredMigration(
  "0022_tenant_role_policy_mutation_result.sql",
);
const security = readRequiredMigration(
  "0037_service_principal_alert_security.sql",
);
const ticketNumbering = readRequiredMigration(
  "0224_tenant_ticket_numbering.sql",
);
const servicePrincipalRuntime = readFileSync(
  resolve(
    packageRoot,
    "tests",
    "security",
    "service-principal-alert-concurrency.ts",
  ),
  "utf8",
);

function functionBodyFrom(source: string, name: string): string {
  const markers = [
    `CREATE OR REPLACE FUNCTION "app"."${name}"`,
    `CREATE FUNCTION "app"."${name}"`,
  ];
  const start = Math.max(...markers.map((marker) => source.indexOf(marker)));
  if (start === -1) {
    throw new Error(`Missing database function ${name}`);
  }
  const end = source.indexOf("$function$;", start);
  if (end === -1) {
    throw new Error(`Unterminated database function ${name}`);
  }
  return source.slice(start, end);
}

function functionDeclarationFrom(source: string, name: string): string {
  const body = functionBodyFrom(source, name);
  const declarationEnd = body.indexOf("AS $function$");
  if (declarationEnd === -1) {
    throw new Error(`Missing function body delimiter for ${name}`);
  }
  return body.slice(0, declarationEnd);
}

function functionBodiesFrom(source: string): Map<string, string> {
  const names = [
    ...source.matchAll(
      /CREATE(?: OR REPLACE)? FUNCTION "app"\."([a-z0-9_]+)"/g,
    ),
  ].map((match) => match[1]!);
  return new Map(names.map((name) => [name, functionBodyFrom(source, name)]));
}

const newPermissionKeys = [
  "service_account.read",
  "service_account.manage",
  "service_account.credential.manage",
  "alert.create",
];

describe("service-account authorization and database security contract", () => {
  it("exercises bearer rejection through the current public Alert ABI", () => {
    expect(ticketNumbering).toMatch(
      /REVOKE EXECUTE ON FUNCTION app\.create_tenant_alert_as_service_account_v1\([\s\S]*?\) FROM periapsis_api;/,
    );
    expect(servicePrincipalRuntime).not.toContain(
      "FROM app.create_tenant_alert_as_service_account_v1(",
    );
    expect(servicePrincipalRuntime).toContain(
      "FROM app.create_tenant_alert_as_service_account_v3(",
    );
  });

  it("hardens every human predecessor ABI before enabling machine permissions", () => {
    const predecessorFunctions = [
      "tenant_user_has_exact_permission",
      "tenant_user_can_delegate_exact_permission",
      "resolve_current_tenant_human_authority_v2",
      "list_tenant_permission_catalog_v2",
      "get_tenant_role_policy_v2",
    ];

    for (const name of predecessorFunctions) {
      const body = functionBodyFrom(compatibility, name);
      for (const permission of newPermissionKeys) {
        expect(body).toContain(`'${permission}'`);
      }
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
    }
    for (const name of [
      "tenant_user_has_exact_permission",
      "tenant_user_can_delegate_exact_permission",
      "resolve_current_tenant_human_authority_v2",
      "get_tenant_role_policy_v2",
    ]) {
      expect(functionBodyFrom(compatibility, name)).toContain(
        "role.principal_kind = 'human'",
      );
    }
    expect(
      functionBodyFrom(compatibility, "list_tenant_permission_catalog_v2"),
    ).toContain("ARRAY['human']::text[]");

    const firstHardening = compatibility.indexOf(
      'CREATE OR REPLACE FUNCTION "app"."tenant_user_has_exact_permission"',
    );
    expect(firstHardening).toBeGreaterThanOrEqual(0);
    expect(compatibility).not.toMatch(/INSERT INTO public\.tenant_permissions/);
  });

  it("publishes expanded v3 read ABIs while preserving exact v2 shapes", () => {
    const authorityV2 = functionBodyFrom(
      compatibility,
      "resolve_current_tenant_human_authority_v2",
    );
    expect(authorityV2).toContain(
      'permission_key text,\n  scope "public"."authorization_scope",\n  delegable boolean,\n  delegation_expires_at timestamp with time zone',
    );

    const authorityV3 = functionBodyFrom(
      compatibility,
      "resolve_current_tenant_human_authority_v3",
    );
    expect(authorityV3).toContain("role.principal_kind = 'human'");
    expect(authorityV3).not.toContain("permission.key NOT IN");

    const catalogV3 = functionBodyFrom(
      compatibility,
      "list_tenant_permission_catalog_v3",
    );
    expect(catalogV3).toContain("permission.service_account_allowed");
    expect(catalogV3).toContain("'service_account'");

    for (const name of ["list_tenant_roles_v3", "get_tenant_role_v3"]) {
      expect(functionBodyFrom(compatibility, name)).toContain("principal_kind");
    }
    const policyV3 = functionBodyFrom(
      compatibility,
      "get_tenant_role_policy_v3",
    );
    expect(policyV3).not.toContain("role.principal_kind = 'human'");
    expect(policyV3).not.toContain("permission.key NOT IN");
  });

  it("keeps legacy role mutation entry points human-only and blind to new tuples", () => {
    const guard = functionBodyFrom(
      compatibility,
      "assert_legacy_human_role_projection",
    );
    expect(guard).toContain("role.principal_kind");
    expect(guard).toContain("IS DISTINCT FROM 'human'");
    expect(guard).toContain("public.tenant_role_permissions");
    expect(guard).toContain("public.tenant_role_delegation_ceilings");
    for (const permission of newPermissionKeys) {
      expect(guard).toContain(`'${permission}'`);
    }

    const guardedMutations = [
      "create_tenant_role",
      "replace_tenant_role_policy_v2",
      "grant_tenant_user_role",
      "grant_tenant_security_group_role",
    ];
    for (const name of guardedMutations) {
      const body = functionBodyFrom(compatibility, name);
      expect(body).toContain("app.assert_legacy_human_role_projection(");
    }

    for (const name of [
      "create_tenant_role_legacy_human_impl",
      "replace_tenant_role_policy_v2_legacy_human_impl",
      "grant_tenant_user_role_legacy_human_impl",
      "grant_tenant_security_group_role_legacy_human_impl",
    ]) {
      expect(compatibility).toMatch(
        new RegExp(
          `REVOKE ALL ON FUNCTION "app"[.]"${name}"[^;]* FROM [^;]*"periapsis_api"`,
        ),
      );
      expect(compatibility).not.toMatch(
        new RegExp(`GRANT EXECUTE ON FUNCTION "app"[.]"${name}"`),
      );
    }

    for (const name of [
      "replace_tenant_role_policy",
      "replace_tenant_role_policy_with_result_v2",
    ]) {
      expect(functionBodyFrom(predecessorSecurity, name)).toMatch(
        /replace_tenant_role_policy(?:_with_result)?_v2\(/,
      );
    }
    expect(
      functionBodyFrom(
        predecessorMutationResult,
        "replace_tenant_role_policy_with_result",
      ),
    ).toContain("app.replace_tenant_role_policy(");
  });

  it("allows only alert.create for machine principals and keeps administration human-only", () => {
    for (const permission of newPermissionKeys) {
      expect(security).toContain(`'${permission}'`);
    }
    expect(security).toMatch(/'alert\.create'[\s\S]{0,500}(?:true|TRUE)/);
    for (const permission of [
      "service_account.read",
      "service_account.manage",
      "service_account.credential.manage",
    ]) {
      const offset = security.indexOf(`'${permission}'`);
      expect(offset).toBeGreaterThanOrEqual(0);
      expect(security.slice(offset, offset + 600)).toMatch(/(?:false|FALSE)/);
    }
    expect(security).toContain("role.key = 'service_account'");
    expect(security).toContain("role.principal_kind = 'service_account'");
    expect(security).toContain("role.key = 'tenant_admin'");
  });

  it("forces RLS and removes direct runtime access to credential state", () => {
    const privateTables = [
      "tenant_service_accounts",
      "tenant_service_account_role_grants",
      "tenant_api_credentials",
      "tenant_api_credential_permissions",
      "tenant_api_credential_networks",
      "tenant_api_credential_commands",
      "alert_activities",
      "alert_commands",
    ];

    for (const table of privateTables) {
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" OWNER TO "periapsis_migrator"`,
      );
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toMatch(
        new RegExp(
          `REVOKE ALL ON TABLE "public"[.]"${table}" FROM [^;]*"periapsis_api"`,
        ),
      );
      expect(security).not.toMatch(
        new RegExp(`GRANT [^;]+ ON TABLE "public"[.]"${table}"`),
      );
    }

    for (const table of ["alerts", "audit_events", "outbox_events"]) {
      for (const privilege of ["INSERT", "UPDATE", "DELETE"]) {
        expect(security).toMatch(
          new RegExp(
            `REVOKE (?:ALL|(?=[^;]*${privilege})[^;]+) ON TABLE "public"[.]"${table}" FROM [^;]*"periapsis_api"`,
          ),
        );
      }
    }
    expect(security).toContain('DROP POLICY IF EXISTS "alerts_api_tenant"');
  });

  it("exposes only fixed-path definers and keeps every list surface bounded", () => {
    const bodies = functionBodiesFrom(security);
    const grantedNames = [
      ...security.matchAll(
        /GRANT EXECUTE ON FUNCTION "app"\."([a-z0-9_]+)"[^;]* TO "periapsis_api"/g,
      ),
    ].map((match) => match[1]!);

    expect(grantedNames.length).toBeGreaterThanOrEqual(5);
    expect(security).not.toMatch(/GRANT EXECUTE ON FUNCTION [^;]+ TO PUBLIC/);
    for (const name of grantedNames) {
      const body = bodies.get(name);
      expect(body, `missing body for granted function ${name}`).toBeDefined();
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      if (name.startsWith("list_")) {
        expect(body).toContain("p_limit");
        expect(body).toMatch(/NOT BETWEEN 1 AND [0-9]+/);
        expect(body).toContain("LIMIT p_limit");
      }
    }

    for (const name of [
      "resolve_tenant_service_account_authority_v1",
      "list_live_api_credential_key_versions_v1",
      "create_tenant_alert_as_human_v1",
      "create_tenant_alert_as_service_account_v1",
    ]) {
      expect(grantedNames).toContain(name);
    }

    const operationSurfaces = [
      { all: ["list", "service_account"], none: ["role", "credential"] },
      { all: ["get", "service_account"], none: ["role", "credential"] },
      { all: ["create", "service_account"], none: ["role", "credential"] },
      { all: ["update", "service_account"], none: ["role", "credential"] },
      { all: ["archive", "service_account"], none: ["role", "credential"] },
      { all: ["list", "service_account", "role", "grant"], none: [] },
      { all: ["get", "service_account", "role", "grant"], none: [] },
      { all: ["grant", "service_account", "role"], none: [] },
      { all: ["revoke", "service_account", "role"], none: [] },
      { all: ["list", "credential"], none: ["key_version"] },
      { all: ["get", "credential"], none: [] },
      { all: ["issue", "credential"], none: [] },
      { all: ["rotate", "credential"], none: [] },
      { all: ["revoke", "credential"], none: [] },
    ];
    for (const surface of operationSurfaces) {
      expect(
        grantedNames.some(
          (name) =>
            surface.all.every((token) => name.includes(token)) &&
            surface.none.every((token) => !name.includes(token)),
        ),
        `missing bounded surface containing ${surface.all.join(", ")}`,
      ).toBe(true);
    }

    for (const name of bodies.keys()) {
      if (/^(?:append|assert|authenticate|guard|lock|private)_/.test(name)) {
        expect(grantedNames).not.toContain(name);
      }
    }

    const privateAuthenticator = functionBodyFrom(
      security,
      "authenticate_tenant_api_credential_v1",
    );
    expect(privateAuthenticator).toContain("SECURITY DEFINER");
    expect(security).toMatch(
      /REVOKE ALL ON FUNCTION "app"\."authenticate_tenant_api_credential_v1"[^;]* FROM [^;]*"periapsis_api"/,
    );
    expect(security).not.toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."authenticate_tenant_api_credential_v1"/,
    );
  });

  it("authenticates bearer proof without accepting principal IDs or a spoofable GUC", () => {
    const name = "create_tenant_alert_as_service_account_v1";
    const declaration = functionDeclarationFrom(security, name);
    const body = functionBodyFrom(security, name);

    for (const parameter of [
      /p_tenant_id uuid/,
      /p_locator bytea/,
      /p_envelope_key_version integer/,
      /p_secret_digest bytea/,
      /p_client_address inet/,
    ]) {
      expect(declaration).toMatch(parameter);
    }
    expect(declaration).not.toMatch(
      /p_(?:service_account|credential|membership|user)_id/,
    );
    expect(body).not.toMatch(
      /current_setting|set_config|context_tenant_id|current_tenant_membership_id/,
    );
    expect(body).toContain("app.authenticate_tenant_api_credential_v1(");

    const authenticate = functionBodyFrom(
      security,
      "authenticate_tenant_api_credential_v1",
    );
    const stateLock = authenticate.indexOf(
      "public.tenant_authorization_states",
    );
    const accountLock = authenticate.indexOf("public.tenant_service_accounts");
    const credentialLock = authenticate.indexOf(
      "public.tenant_api_credentials",
    );
    expect(stateLock).toBeGreaterThanOrEqual(0);
    expect(accountLock).toBeGreaterThan(stateLock);
    expect(credentialLock).toBeGreaterThan(accountLock);
    expect(authenticate).toContain("FOR KEY SHARE");
    expect(authenticate).toContain("credential.secret_digest");
    expect(authenticate).toContain("p_secret_digest");
    expect(authenticate).toContain("credential.key_version");
    expect(authenticate).toContain("p_envelope_key_version");
    expect(authenticate).not.toMatch(
      /current_setting|set_config|context_tenant_id|current_tenant_membership_id/,
    );
    expect(authenticate).toMatch(
      /credential_network\.network\s*(?:>>=|@>)\s*p_client_address|p_client_address\s*<<=\s*credential_network\.network/,
    );
    for (const relation of [
      "public.tenant_service_account_role_grants",
      "public.tenant_role_permissions",
      "public.tenant_permissions",
      "public.tenant_api_credential_permissions",
    ]) {
      expect(authenticate).toContain(relation);
    }
    expect(authenticate).toContain("permission.service_account_allowed");
    expect(authenticate).toContain("service_account.archived_at IS NULL");
    expect(authenticate).toContain("credential.revoked_at IS NULL");
    expect(authenticate).toContain(
      "credential.expires_at > transaction_timestamp()",
    );
  });

  it("authorizes role grant and revoke symmetrically under the shared tenant lock", () => {
    const bodies = functionBodiesFrom(security);
    const grant = [...bodies.values()].find((body) =>
      body.includes("INSERT INTO public.tenant_service_account_role_grants"),
    );
    const revoke = [...bodies.values()].find(
      (body) =>
        body.includes("UPDATE public.tenant_service_account_role_grants") &&
        body.includes("revoked_at") &&
        body.includes("'service_account.manage'"),
    );

    expect(grant).toBeDefined();
    expect(revoke).toBeDefined();
    for (const body of [grant!, revoke!]) {
      expect(body).toContain("app.lock_current_tenant_authorization_state()");
      expect(body).toContain("'service_account.manage'");
      expect(body).toContain("'role.grant'");
      expect(body).toContain("role.principal_kind = 'service_account'");

      const calledHelpers = [...body.matchAll(/app\.(assert_[a-z0-9_]+)\(/g)]
        .map((match) => match[1]!)
        .map((name) => bodies.get(name))
        .filter((candidate): candidate is string => candidate !== undefined);
      const consequence = [body, ...calledHelpers].join("\n");
      expect(consequence).toContain("public.tenant_role_permissions");
      expect(consequence).toContain("public.tenant_role_delegation_ceilings");
      expect(consequence).toMatch(
        /effective_expires_at|earliest_authorization_expiry|requested_expires_at/,
      );
    }
  });

  it("preserves historical audit hashes by omitting only a null new actor key", () => {
    const payload = functionBodyFrom(
      `${compatibility}\n${security}`,
      "audit_event_payload",
    );

    expect(payload).toContain("actor_service_account_id");
    expect(payload).toMatch(
      /-\s*(?:'actor_service_account_id'|ARRAY\[[^\]]*'actor_service_account_id'[^\]]*\])/,
    );
    expect(payload).toMatch(/actor_service_account_id IS (?:NOT )?NULL/i);
    expect(payload).toContain("jsonb_build_object");
    expect(payload).not.toContain("jsonb_strip_nulls");
  });
});
