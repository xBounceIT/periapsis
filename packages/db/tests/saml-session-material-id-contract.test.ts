import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migration = (name: string): string =>
  readFileSync(resolve(packageRoot, "migrations", name), "utf8");
const source = (name: string): string =>
  readFileSync(resolve(packageRoot, "src", name), "utf8");

const generated = migration("0146_amazing_magik.sql");
const abi = migration("0147_saml_session_material_id_abi.sql");
const readiness = migration("0148_saml_session_material_id_readiness.sql");
const ledgerMaterialForeignKey = migration("0149_condemned_bedlam.sql");
const mfa = migration("0132_federated_authentication_mfa_compatibility.sql");
const sessions = migration("0133_federated_authentication_session_abi.sql");
const schema = source("schema/identity-federation.ts");

describe("immutable SAML session material identity contract", () => {
  it("models one always-present identity row with an optional all-or-none envelope", () => {
    expect(schema).toContain('keyVersion: integer("key_version"),');
    expect(schema).toContain('ciphertext: bytea("ciphertext"),');
    expect(schema).toContain(
      "and (${table.keyVersion} is null) = (${table.ciphertext} is null)",
    );
    expect(generated).toContain('ALTER COLUMN "key_version" DROP NOT NULL');
    expect(generated).toContain('ALTER COLUMN "ciphertext" DROP NOT NULL');
    expect(abi).toContain("v_key_version, v_ciphertext, p_applied_at");
    expect(schema).toContain('name: "tenant_saml_logout_commands_material_fk"');
    expect(ledgerMaterialForeignKey).toContain(
      'REFERENCES "public"."tenant_saml_session_materials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade',
    );
  });

  it("binds creation and every transfer to the immutable transaction material id", () => {
    expect(abi).toContain("transaction.operation_run_id = NEW.id");
    expect(abi).toContain("transaction.state = 'pending'");
    expect(abi).toContain("transaction.operation_run_id = v_material_id");
    expect(abi).toContain(
      "v_material_id = coalesce(v_session_id, v_continuation_id)",
    );
    expect(abi).toContain(
      "SET session_id = NULL, continuation_id = v_continuation_id",
    );
    expect(abi.match(/SAML session material ownership is stale/g)).toHaveLength(
      3,
    );
    expect(abi).toContain("v_provider_kind = 'saml' AND NOT FOUND");
    expect(abi).toContain("v_provenance.provider_kind = 'saml' AND NOT FOUND");
    expect(mfa).toContain("SET session_id = v_new_session_id");
    expect(sessions).toContain("SET session_id = v_new_session_id");
    expect(abi).not.toContain("anchor_session_id");
    expect(abi).not.toContain("anchor_continuation_id");
  });

  it("uses semantic replay without comparing or replacing randomized AEAD bytes", () => {
    expect(abi).toContain("#- '{samlSession,keyVersion}'");
    expect(abi).toContain("#- '{samlSession,ciphertext}'");
    expect(abi).toContain("v_existing.operation_digest IS DISTINCT FROM");
    expect(abi).toContain("v_existing.request_snapshot");
    expect(abi).toContain("v_legacy_apply := v_existing.request_snapshot");
    expect(abi).toMatch(
      /transaction\.operation_run_id = v_material_id\s+FOR UPDATE;[\s\S]*SELECT application\.\* INTO v_existing/,
    );
    expect(abi).not.toContain("request_snapshot IS DISTINCT FROM v_apply");
    expect(abi).not.toMatch(
      /UPDATE\s+public\.tenant_federated_authentication_applications/i,
    );
  });

  it("revokes locally before optional upstream projection and records exact material id", () => {
    const revokeFamily = abi.indexOf("UPDATE public.auth_sessions AS family");
    const projectConfiguration = abi.indexOf(
      "v_configuration := app.private_saml_logout_configuration_record_v1",
    );
    expect(revokeFamily).toBeGreaterThan(-1);
    expect(projectConfiguration).toBeGreaterThan(revokeFamily);
    expect(abi).toContain(
      "IF v_request_upstream AND v_material.key_version IS NOT NULL THEN",
    );
    expect(abi).toContain(
      "EXCEPTION WHEN OTHERS THEN\n      v_configuration := NULL",
    );
    expect(abi).toContain("'materialId',v_material.id::text");
    expect(abi).toContain(
      "WHEN NOT v_request_upstream OR v_material.key_version IS NULL THEN NULL",
    );
    expect(abi).toContain("'authenticatedUserId',p_user_id::text");
    expect(abi).toContain("session.user_id = p_user_id");
    expect(abi).toContain("membership.status = 'active'");
    expect(abi).toContain("current_setting('app.tenant_id', true)");
    expect(abi).toContain("current_setting('app.user_id', true)");
    expect(abi).not.toContain("set_config('app.user_id'");
    expect(abi).toContain("app.revoke_local_saml_session_v1(uuid,jsonb)");
  });

  it("retires every active legacy anchor and exposes only narrow API functions", () => {
    expect(abi).toContain("AND material.aad_version = 1");
    expect(abi).toContain("'legacy_material_state', CASE WHEN EXISTS");
    expect(abi).toContain("THEN 'aad_v1' ELSE 'absent' END");
    expect(abi).toContain(
      "FROM public.auth_session_federated_provenance AS provenance",
    );
    expect(abi).toContain("continuation.provider_kind = 'saml'");
    expect(abi).toContain("saml_legacy_material_retired");
    expect(abi).toContain(
      "DISABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1",
    );
    expect(abi).toContain(
      "ENABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1",
    );
    expect(abi.indexOf("DISABLE TRIGGER")).toBeLessThan(
      abi.indexOf(
        "UPDATE public.tenant_post_primary_continuations AS continuation",
      ),
    );
    expect(
      abi.indexOf(
        "UPDATE public.tenant_post_primary_continuations AS continuation",
      ),
    ).toBeLessThan(abi.indexOf("ENABLE TRIGGER"));
    expect(abi).toContain(
      "DROP FUNCTION IF EXISTS app.lookup_saml_authentication_transaction_v1(jsonb)",
    );
    expect(abi).toContain(
      "DROP FUNCTION IF EXISTS app.apply_federated_authentication_v1(jsonb)",
    );
    expect(abi).toContain("SET state = 'revoked'");
    expect(abi).not.toContain("pgp_sym_decrypt");
    expect(abi).not.toContain("DecryptSAMLSessionMaterial");
    expect(abi).toContain("GRANT EXECUTE ON FUNCTION");
    expect(abi).toContain(
      "app.revoke_local_saml_session_v1(uuid,jsonb)\nTO periapsis_api",
    );
    expect(abi).not.toContain(
      "GRANT SELECT ON public.tenant_saml_session_materials",
    );
  });

  it("seals current and exact predecessor compatibility with fail-closed readiness", () => {
    expect(readiness).toContain("journal_count = 150");
    expect(readiness).toContain("journal_latest_created_at = 1787756689913");
    expect(readiness).toContain("fingerprint_entries[143:150]");
    expect(readiness).toContain(
      "current_count = 150 AND predecessor_count = 142",
    );
    expect(readiness).toContain(
      "attribute.attname IN ('key_version','ciphertext')",
    );
    expect(readiness).toContain("attribute.attnotnull");
    expect(readiness).toContain(
      "session.id IS NULL OR session.revoked_at IS NULL",
    );
    expect(readiness).toContain(
      "continuation.id IS NULL OR continuation.state = 'pending'",
    );
    expect(readiness).toContain("transaction.operation_run_id = material.id");
    expect(readiness).toContain("transaction.state = 'completed'");
    expect(readiness).toContain(
      "application.request_snapshot -> 'samlSession' ->> 'materialId'",
    );
    expect(readiness).toContain(
      "transaction.transaction_id IS NULL OR application.id IS NULL",
    );
    expect(readiness).toContain("session.revoked_at IS NULL");
    expect(readiness).toContain("IS DISTINCT FROM 1::bigint");
    expect(readiness).not.toContain(
      "application.session_id IS NOT DISTINCT FROM material.session_id",
    );
    expect(readiness).not.toContain(
      "application.continuation_id IS NOT DISTINCT FROM material.continuation_id",
    );
    expect(readiness).toContain(
      "trigger.tgrelid = expected_trigger.relation_name::regclass",
    );
    expect(readiness).toContain(
      "trigger.tgfoid = expected_trigger.function_name::regprocedure",
    );
    expect(readiness).toContain(
      "trigger.tgtype = expected_trigger.trigger_type::smallint",
    );
    expect(readiness).toContain("trigger.tgqual IS NULL");
    expect(readiness).toContain("trigger.tgnargs = 0");
    expect(readiness).toContain(
      "'tenant_post_primary_continuations_federated_provenance_v1'",
    );
    expect(readiness).toContain("privilege.grantee <> relation.relowner");
    expect(readiness).toContain("privilege.grantee <> procedure.proowner");
    expect(readiness).toContain("privilege.grantee = 'periapsis_api'::regrole");
    expect(readiness).toContain("AND NOT privilege.is_grantable");
    expect(readiness).toContain("attribute.attacl IS NOT NULL");
    expect(readiness).toContain("tenant_saml_logout_commands_material_fk");
  });
});
