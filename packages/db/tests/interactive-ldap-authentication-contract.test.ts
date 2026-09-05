import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const migration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0207_interactive_ldap_authentication.sql",
  ),
  "utf8",
);
const repository = readFileSync(
  resolve(
    repositoryRoot,
    "services/api/internal/postgres/ldap_authentication.go",
  ),
  "utf8",
);
const handler = readFileSync(
  resolve(
    repositoryRoot,
    "services/api/internal/httpserver/ldap_auth_handlers.go",
  ),
  "utf8",
);

describe("interactive LDAP authentication contract", () => {
  it("keeps LDAP primary provenance physically closed and tenant-RLS protected", () => {
    for (const table of [
      "auth_session_ldap_provenance",
      "tenant_post_primary_ldap_provenance",
    ]) {
      expect(migration).toContain(`CREATE TABLE public.${table}`);
      expect(migration).toContain(
        `ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY`,
      );
      expect(migration).toContain(
        `ALTER TABLE public.${table} FORCE ROW LEVEL SECURITY`,
      );
      expect(migration).toMatch(
        new RegExp(
          `REVOKE ALL ON TABLE public\\.${table}[\\s\\S]*?FROM PUBLIC, periapsis_api`,
        ),
      );
    }

    const provenanceDefinitions = migration.slice(
      migration.indexOf("CREATE TABLE public.auth_session_ldap_provenance"),
      migration.indexOf("CREATE FUNCTION app.guard_ldap_primary_provenance_v1"),
    );
    expect(provenanceDefinitions).not.toMatch(
      /\b(password|username|email|bind_dn|subject_value|raw_entry|raw_groups)\b/i,
    );
    expect(migration).toContain(
      "CREATE FUNCTION app.validate_ldap_primary_provenance_v1()",
    );
    expect(migration).toContain("LDAP primary provenance is inconsistent");
  });

  it("couples JIT reconciliation and exact session or MFA continuation authority", () => {
    expect(migration).toContain(
      "CREATE FUNCTION app.issue_tenant_ldap_jit_authority_v1(",
    );
    expect(migration).toContain(
      "FROM app.tenant_ldap_jit_assurance_snapshot_v1(",
    );
    expect(migration).toContain(
      "INSERT INTO public.auth_session_ldap_provenance",
    );
    expect(migration).toContain(
      "INSERT INTO public.tenant_post_primary_ldap_provenance",
    );
    expect(repository).toMatch(
      /withinTransaction[\s\S]*?applyLDAPIdentityPlanSQL[\s\S]*?issueLDAPAuthoritySQL/,
    );
    expect(repository).toContain("json.RawMessage(reservation)");
    expect(repository).not.toContain("Password");
  });

  it("publishes an exact fail-closed readiness and API-only function ACL", () => {
    expect(migration).toContain(
      "CREATE FUNCTION app.tenant_ldap_interactive_auth_schema_readiness_v1()",
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION[\s\S]*?tenant_ldap_jit_assurance_snapshot_v1[\s\S]*?issue_tenant_ldap_jit_authority_v1[\s\S]*?TO periapsis_api/,
    );
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION[\s\S]*?validate_ldap_primary_provenance_v1[\s\S]*?FROM PUBLIC, periapsis_api, periapsis_worker/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION app\.tenant_ldap_interactive_auth_schema_readiness_v1\(\)[\s\S]*?TO periapsis_api/,
    );
    expect(migration).not.toContain(
      "RETURN app.enforce_tenant_federated_continuation_provenance_pre_ldap_v1()",
    );
  });

  it("owns the password only in the bounded native browser adapter", () => {
    expect(handler).toContain("http.MaxBytesReader");
    expect(handler).toContain("maximumLDAPLoginBodyBytes");
    expect(handler).toContain("defer clear(command.Password)");
    expect(handler).toContain("rejectLDAPBrowserAuthority");
    expect(handler).toContain("decodeLDAPFormComponent");
    expect(handler).not.toContain("url.ParseQuery");
    expect(handler).not.toContain("json.NewDecoder");
  });
});
