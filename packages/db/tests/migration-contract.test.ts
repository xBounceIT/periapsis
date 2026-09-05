import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const packageRoot = resolve(import.meta.dirname, "..");
const migrationDirectory = resolve(packageRoot, "migrations");
const migrationMetaDirectory = resolve(migrationDirectory, "meta");
const sqlFiles = readdirSync(migrationDirectory)
  .filter((fileName) => fileName.endsWith(".sql"))
  .toSorted();
const migrationSql = new Map(
  sqlFiles.map((fileName) => [
    fileName,
    readFileSync(resolve(migrationDirectory, fileName), "utf8"),
  ]),
);

function migration(name: string): string {
  const sql = migrationSql.get(name);
  if (sql === undefined) {
    throw new Error(`Missing migration fixture: ${name}`);
  }
  return sql;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readJsonObject(fileName: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(readFileSync(fileName, "utf8"));
  if (!isJsonObject(parsed)) {
    throw new Error(`Expected a JSON object in ${fileName}`);
  }
  return parsed;
}

describe("PostgreSQL migration chain", () => {
  it("keeps generated and custom migrations in their effective order", () => {
    expect(sqlFiles).toEqual([
      "0000_little_red_shift.sql",
      "0001_security_controls.sql",
      "0002_redundant_magus.sql",
      "0003_audit_chain_concurrency.sql",
      "0004_uuidv7_fail_closed.sql",
      "0005_audit_tail_verification.sql",
      "0006_audit_attribution.sql",
      "0007_schema_compatibility.sql",
      "0008_phase_2a_auth.sql",
      "0009_phase_2a_security.sql",
      "0010_phase_2b_tenant_rbac.sql",
      "0011_phase_2b_tenant_rbac_security.sql",
      "0012_youthful_the_initiative.sql",
      "0013_smooth_molecule_man.sql",
      "0014_lumpy_chat.sql",
      "0015_fix_tenant_role_policy_alias.sql",
      "0016_fix_auth_admission_null.sql",
      "0017_audit_verifier_least_privilege.sql",
      "0018_polite_boom_boom.sql",
      "0019_colossal_naoko.sql",
      "0020_phase_2b_security_groups_security.sql",
      "0021_direct_grant_supersession_audit.sql",
      "0022_tenant_role_policy_mutation_result.sql",
      "0023_archived_role_direct_grant_revoke.sql",
      "0024_direct_grant_inventory_boundary_hardening.sql",
      "0025_authorization_compatibility_and_ownership.sql",
      "0026_schema_compatibility_fail_closed.sql",
      "0027_flimsy_bloodscream.sql",
      "0028_phase_2b_operator_teams_security.sql",
      "0029_operator_team_readiness_v4.sql",
      "0030_operator_team_hardening.sql",
      "0031_operator_team_hardening_security.sql",
      "0032_operator_team_readiness_v5.sql",
      "0033_service_principal_preflight.sql",
      "0034_service_principal_additive.sql",
      "0035_service_principal_compatibility.sql",
      "0036_service_principal_final.sql",
      "0037_service_principal_alert_security.sql",
      "0038_service_principal_readiness_v6.sql",
      "0039_service_principal_audit_readiness.sql",
      "0040_identity_provider_preflight.sql",
      "0041_identity_provider_additive.sql",
      "0042_identity_provider_backfill.sql",
      "0043_identity_provider_final.sql",
      "0044_identity_provider_security.sql",
      "0045_identity_provider_crud.sql",
      "0046_identity_profile_compatibility.sql",
      "0047_identity_provider_test_runs.sql",
      "0048_identity_provider_test_security.sql",
      "0049_identity_provider_keyring_active.sql",
      "0050_identity_provider_readiness_v7.sql",
      "0051_complex_the_santerians.sql",
      "0052_identity_access_security.sql",
      "0053_identity_access_readiness_v8.sql",
      "0054_magical_the_spike.sql",
      "0055_lazy_taskmaster.sql",
      "0056_identity_mapping_security.sql",
      "0057_identity_provider_binding_idempotency_v2.sql",
      "0058_identity_mapping_readiness_v9.sql",
      "0059_certain_psynapse.sql",
      "0060_identity_directory_operation_security.sql",
      "0061_tired_prima.sql",
      "0062_identity_directory_operation_abi.sql",
      "0063_serious_pixie.sql",
      "0064_identity_directory_operation_readiness_v10.sql",
      "0065_sweet_richard_fisk.sql",
      "0066_identity_jit_sync_security.sql",
      "0067_identity_jit_sync_abi.sql",
      "0068_identity_sync_lifecycle_abi.sql",
      "0069_productive_maverick.sql",
      "0070_late_ozymandias.sql",
      "0071_identity_jit_preauth_security.sql",
      "0072_identity_jit_preauth_abi.sql",
      "0073_bright_proudstar.sql",
      "0074_identity_sync_worker_claim_abi.sql",
      "0075_identity_jit_sync_readiness_v11.sql",
      "0076_thin_korath.sql",
      "0077_identity_sync_fenced_worker_abi_v2.sql",
      "0078_condemned_hardball.sql",
      "0079_identity_sync_fenced_readiness_v12.sql",
      "0080_identity_sync_access_grant_planning_v3.sql",
      "0081_identity_sync_readiness_v13.sql",
      "0082_ancient_hydra.sql",
      "0083_ticketing_foundation_security.sql",
      "0084_petite_sentry.sql",
      "0085_skinny_phil_sheldon.sql",
      "0086_ticketing_transaction_abi.sql",
      "0087_optimal_loa.sql",
      "0088_phase4_tenant_security.sql",
      "0089_phase4_transaction_journal.sql",
      "0090_early_madelyne_pryor.sql",
      "0091_spooky_hellfire_club.sql",
      "0092_phase6_notification_security.sql",
      "0093_phase6_notification_dispatch_abi.sql",
      "0094_phase6_notification_planning_abi.sql",
      "0095_phase6_notification_delivery_abi.sql",
      "0096_phase6_notification_administration_abi.sql",
      "0097_lowly_may_parker.sql",
      "0098_phase6_notification_trace_and_test_abi.sql",
      "0099_common_purple_man.sql",
      "0100_easy_stark_industries.sql",
      "0101_contacts_portal_foundation.sql",
      "0102_hard_warbound.sql",
      "0103_crazy_scarlet_witch.sql",
      "0104_dazzling_morph.sql",
      "0105_sla_security.sql",
      "0106_sla_abi_and_compatibility.sql",
      "0107_nasty_revanche.sql",
      "0108_remarkable_slipstream.sql",
      "0109_contacts_portal_security.sql",
      "0110_contacts_portal_fanout.sql",
      "0111_contacts_portal_abi.sql",
      "0112_contacts_portal_readiness.sql",
      "0113_sla_configuration_v2.sql",
      "0114_sla_runtime_v2.sql",
      "0115_sla_v23_readiness.sql",
      "0116_workflow_administration_foundation.sql",
      "0117_identity_mfa_foundation.sql",
      "0118_identity_mfa_security.sql",
      "0119_identity_mfa_abi.sql",
      "0120_identity_mfa_readiness.sql",
      "0121_spotty_crusher_hogan.sql",
      "0122_workflow_administration_abi.sql",
      "0123_workflow_administration_readiness.sql",
      "0124_identity_mfa_device_management_abi.sql",
      "0125_identity_mfa_device_management_readiness.sql",
      "0126_rich_pride.sql",
      "0127_rare_thaddeus_ross.sql",
      "0128_federated_authentication_security.sql",
      "0129_federated_authentication_transaction_abi.sql",
      "0130_federated_authentication_read_abi.sql",
      "0131_federated_authentication_apply_abi.sql",
      "0132_federated_authentication_mfa_compatibility.sql",
      "0133_federated_authentication_session_abi.sql",
      "0134_federated_authentication_readiness.sql",
      "0135_sla_queue_metrics_abi.sql",
      "0136_white_misty_knight.sql",
      "0137_saved_ticket_views_security.sql",
      "0138_saved_ticket_views_abi_readiness.sql",
      "0139_tricky_hawkeye.sql",
      "0140_ticket_query_projections_security.sql",
      "0141_ticket_query_projections_readiness.sql",
      "0142_burly_sage.sql",
      "0143_minor_silver_surfer.sql",
      "0144_burly_elektra.sql",
      "0145_striped_gladiator.sql",
      "0146_amazing_magik.sql",
      "0147_saml_session_material_id_abi.sql",
      "0148_saml_session_material_id_readiness.sql",
      "0149_condemned_bedlam.sql",
      "0150_high_blob.sql",
      "0151_platform_tenant_lifecycle_security.sql",
      "0152_platform_tenant_lifecycle_readiness.sql",
      "0153_lovely_sprite.sql",
      "0154_platform_tenant_lifecycle_compatibility.sql",
      "0155_jazzy_felicia_hardy.sql",
      "0156_panoramic_blackheart.sql",
      "0157_platform_identity_provider_security.sql",
      "0158_platform_identity_provider_compatibility.sql",
      "0159_material_talkback.sql",
      "0160_tenant_platform_identity_binding_security.sql",
      "0161_lazy_shiver_man.sql",
      "0162_tenant_platform_identity_binding_compatibility.sql",
      "0163_workable_hannibal_king.sql",
      "0164_platform_oidc_binding_lifecycle.sql",
      "0165_platform_oidc_binding_runtime.sql",
      "0166_platform_oidc_binding_readiness.sql",
      "0167_platform_identity_account_foundation.sql",
      "0168_platform_identity_account_security.sql",
      "0169_platform_identity_account_compatibility.sql",
      "0170_platform_identity_account_retirement_observation_fix.sql",
      "0171_platform_identity_account_resource_version.sql",
      "0172_platform_identity_account_representation_security.sql",
      "0173_platform_identity_account_representation_compatibility.sql",
      "0174_platform_identity_account_observation_state.sql",
      "0175_platform_identity_account_observation_security.sql",
      "0176_platform_identity_account_observation_compatibility.sql",
      "0177_aspiring_mojo.sql",
      "0178_platform_oidc_direct_runtime.sql",
      "0179_platform_oidc_direct_compatibility.sql",
      "0180_platform_oidc_direct_administration.sql",
      "0181_platform_oidc_direct_administration_compatibility.sql",
      "0182_mfa_policy_administration.sql",
      "0183_mfa_policy_administration_compatibility.sql",
      "0184_platform_saml_direct_runtime.sql",
      "0185_platform_saml_direct_compatibility.sql",
      "0186_platform_saml_direct_runtime_successor.sql",
      "0187_platform_saml_direct_compatibility.sql",
      "0188_platform_saml_metadata_projection_fix.sql",
      "0189_platform_saml_metadata_projection_compatibility.sql",
      "0190_alert_soft_delete_v1.sql",
      "0191_ticket_escalation_v3.sql",
      "0192_sla_trigger_action_runtime.sql",
      "0193_platform_local_account_runtime.sql",
      "0194_ticket_bulk_export_runtime.sql",
      "0195_alert_dfir_runtime.sql",
      "0196_v44_compatibility.sql",
      "0197_ticket_metadata_replace_v1.sql",
      "0198_v45_compatibility.sql",
      "0199_ticket_watcher_runtime.sql",
      "0200_v46_forward_repair.sql",
      "0201_v46_compatibility.sql",
      "0202_ticket_comment_persistence.sql",
      "0203_ticket_comment_runtime.sql",
      "0204_ticket_comment_downstream.sql",
      "0205_sla_object_event_ingress.sql",
      "0206_smtp_runtime_assurance.sql",
      "0207_interactive_ldap_authentication.sql",
      "0208_v47_compatibility.sql",
      "0209_ticket_comment_aggregate_guard_v48.sql",
      "0210_ldap_denied_reconciliation.sql",
      "0211_platform_global_ldap.sql",
      "0212_tenant_membership_lifecycle.sql",
      "0213_audit_export_retention.sql",
      "0214_tenant_branding_settings.sql",
      "0215_platform_tenant_access.sql",
      "0216_platform_operations_administration.sql",
      "0217_alert_case_link_lifecycle.sql",
      "0218_v48_compatibility.sql",
      "0219_sla_system_principal_guard_fix.sql",
      "0220_api_request_rate_limits.sql",
      "0221_alert_relations.sql",
      "0222_customer_contact_recipient_fanout.sql",
      "0223_notification_inbox.sql",
      "0224_tenant_ticket_numbering.sql",
      "0225_custom_field_bulk_import.sql",
      "0226_alert_dfir_completion.sql",
      "0227_tenant_webhook_url_policy.sql",
      "0228_tenant_federation_administration.sql",
      "0229_v49_compatibility.sql",
    ]);
  });

  it("seals the exact 199-row v45 journal and derives readiness from v44 predecessors", () => {
    const compatibility = migration("0198_v45_compatibility.sql");

    expect(compatibility).toContain("IF p_expected_count IS DISTINCT FROM 199");
    expect(compatibility).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788128702258",
    );
    expect(compatibility).toContain("(:[0-9]+@[0-9a-f]{64}){198}$");
    expect(compatibility).toContain("IF sealed_count<>199");
    expect(
      compatibility.match(
        /NOT app\.ticket_metadata_runtime_schema_readiness_v1\(\)/g,
      ),
    ).toHaveLength(2);
    for (const predecessor of [
      "private_mfa_policy_administration_schema_readiness_v4",
      "private_platform_identity_runtime_schema_readiness_v10",
      "private_platform_oidc_direct_runtime_schema_readiness_v6",
      "private_platform_saml_direct_runtime_schema_readiness_v3",
    ]) {
      expect(compatibility).toContain(`'app.${predecessor}()'::regprocedure`);
    }
    for (const [predecessor, successor] of [
      [
        "private_mfa_policy_administration_schema_readiness_v4",
        "private_mfa_policy_administration_schema_readiness_v5",
      ],
      [
        "private_platform_identity_runtime_schema_readiness_v10",
        "private_platform_identity_runtime_schema_readiness_v11",
      ],
      [
        "private_platform_oidc_direct_runtime_schema_readiness_v6",
        "private_platform_oidc_direct_runtime_schema_readiness_v7",
      ],
      [
        "private_platform_saml_direct_runtime_schema_readiness_v3",
        "private_platform_saml_direct_runtime_schema_readiness_v4",
      ],
    ]) {
      expect(compatibility).toContain(`'${predecessor}',\n    '${successor}'`);
    }
    expect(compatibility).not.toContain(
      "2425bff3d9125ffe7c33f46e0f84922e34fd00458786875d8a68394598e0bb7d",
    );
  });

  it("converges the exact V45 predecessors and seals one immutable V46 watcher root", () => {
    const watcher = migration("0199_ticket_watcher_runtime.sql");
    const repair = migration("0200_v46_forward_repair.sql");
    const compatibility = migration("0201_v46_compatibility.sql");

    expect(watcher).toContain(
      "CREATE FUNCTION app.list_tenant_ticket_watchers_v1(",
    );
    expect(watcher).toContain(
      "CREATE FUNCTION app.mutate_tenant_ticket_watcher_v1(",
    );
    expect(watcher).toContain(
      "ALTER TABLE public.ticket_watcher_events FORCE ROW LEVEL SECURITY",
    );
    expect(watcher).toContain(
      "ALTER TABLE public.ticket_watcher_commands FORCE ROW LEVEL SECURITY",
    );
    expect(watcher).toContain("IF p_action='add' THEN");
    expect(watcher).toContain("latest.display_name_snapshot AS display_name");
    expect(watcher).not.toContain(
      "coalesce(profile.display_name,latest.display_name_snapshot)",
    );
    expect(watcher).toContain(
      "JOIN public.tenant_authorization_sources AS authority_source",
    );
    expect(watcher).toContain("authority_source.retired_at IS NULL");

    expect(repair).toContain(
      "CREATE TABLE IF NOT EXISTS drizzle.__periapsis_migration_convergence_attestations",
    );
    expect(repair).toContain("CREATE SCHEMA IF NOT EXISTS drizzle");
    expect(repair).toContain("CREATE TRIGGER migration_convergence_immutable");
    expect(repair).toContain(
      "CREATE TRIGGER migration_convergence_truncate_immutable",
    );
    expect(repair).toContain(
      "CREATE OR REPLACE FUNCTION app.private_ticket_watcher_display_name_valid_v1(",
    );
    expect(repair).toContain("U&'[\\200E\\200F\\202A-\\202E\\2066-\\2069]'");
    expect(repair).toContain(
      "U&'^[\\0009-\\000D\\0020\\0085\\00A0\\1680\\2000-\\200A\\2028\\2029\\202F\\205F\\3000]|[\\0009-\\000D\\0020\\0085\\00A0\\1680\\2000-\\200A\\2028\\2029\\202F\\205F\\3000]$'",
    );
    expect(repair).toContain(
      "app.private_ticket_watcher_display_name_valid_v1(display_name_snapshot)",
    );
    expect(watcher).not.toContain(
      "private_ticket_watcher_display_name_valid_v1",
    );
    expect(repair).toContain("SELECT count(*)=17");
    expect(repair).toContain("'legacy-v45'");
    expect(repair).toContain("'canonical-v45'");
    expect(repair).not.toMatch(
      /UPDATE\s+drizzle\.__drizzle_migrations|DELETE\s+FROM\s+drizzle\.__drizzle_migrations/i,
    );

    expect(compatibility).toContain("IF p_expected_count IS DISTINCT FROM 202");
    expect(compatibility).toContain(
      "p_expected_latest_created_at IS DISTINCT FROM 1788250074583",
    );
    expect(compatibility).toContain("IF sealed_count<>202");
    expect(compatibility).toContain(
      "NOT app.private_v46_migration_convergence_schema_readiness_v1()",
    );
    expect(compatibility).toContain(
      "NOT app.ticket_watcher_runtime_schema_readiness_v1()",
    );
    expect(compatibility).toContain(
      "REVOKE ALL ON FUNCTION app.schema_compatibility_v45()",
    );
  });

  it("binds v45 bulk/export readiness to the repaired system mutation surface", () => {
    const compatibility = migration("0198_v45_compatibility.sql");

    expect(compatibility).toContain(
      "CREATE FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(",
    );
    expect(compatibility).toContain(
      "'system',NULL,'ticket-bulk-worker','operator'",
    );
    expect(compatibility).toContain(
      "THEN 'alert.status_changed'::public.notification_event_type",
    );
    expect(compatibility).toContain(
      "'routing',jsonb_strip_nulls(jsonb_build_object(",
    );
    expect(compatibility).toContain(
      "CREATE FUNCTION app.private_v45_ticket_runtime_repairs_ready(p_surface text)",
    );
    expect(compatibility).toContain(
      "app.private_v45_ticket_runtime_repairs_ready(''bulk'')",
    );
    expect(compatibility).toContain(
      "app.private_v45_ticket_runtime_repairs_ready(''export'')",
    );
    for (const dependency of [
      "app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind",
      "app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind",
      "app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb",
      "app.private_ticket_runtime_catalog_digest_v1(text)",
      "app.private_ticket_runtime_append_system_effects_v1(uuid,text,text",
      "app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)",
    ]) {
      expect(compatibility).toContain(dependency);
    }
  });

  it("keeps the Drizzle snapshot chain aligned with the migration journal", () => {
    const journal = readJsonObject(
      resolve(migrationMetaDirectory, "_journal.json"),
    );
    if (!Array.isArray(journal.entries)) {
      throw new Error("Drizzle migration journal entries must be an array");
    }
    const journalEntries = journal.entries.map((entry) => {
      if (
        entry === null ||
        typeof entry !== "object" ||
        typeof entry.idx !== "number" ||
        typeof entry.tag !== "string"
      ) {
        throw new Error("Invalid Drizzle migration journal entry");
      }
      return { idx: entry.idx, tag: entry.tag };
    });
    const snapshotFiles = readdirSync(migrationMetaDirectory)
      .filter((fileName) => /^\d{4}_snapshot\.json$/.test(fileName))
      .toSorted();
    const snapshotIndices = snapshotFiles.map((fileName) =>
      Number.parseInt(fileName.slice(0, 4), 10),
    );

    // The initial hand-authored security migration predates Drizzle's custom
    // snapshot support. Every later journal entry must carry the snapshot that
    // future schema generation uses as its immediate predecessor.
    expect(snapshotIndices).toEqual(
      journalEntries
        .filter((entry) => entry.tag !== "0001_security_controls")
        .map((entry) => entry.idx),
    );

    let previousID: string | undefined;
    for (const snapshotFile of snapshotFiles) {
      const snapshot = readJsonObject(
        resolve(migrationMetaDirectory, snapshotFile),
      );
      if (
        typeof snapshot.id !== "string" ||
        typeof snapshot.prevId !== "string"
      ) {
        throw new Error(
          `Invalid Drizzle snapshot identifiers in ${snapshotFile}`,
        );
      }
      if (previousID !== undefined) {
        expect(snapshot.prevId, snapshotFile).toBe(previousID);
      }
      previousID = snapshot.id;
    }
  }, 15_000);

  it("runs schema-drift generation in a valid Windows scratch directory", () => {
    const verifier = readFileSync(
      resolve(packageRoot, "src/admin/verify-generated.ts"),
      "utf8",
    );

    expect(verifier).toContain('out: "./migrations"');
    expect(verifier).toContain("cwd: scratchRoot");
    expect(verifier).toContain("Reference|Type|Syntax|Range");
    expect(verifier).toContain("\\bENOENT\\b");
  });

  it("keeps fresh authentication admission results non-null", () => {
    const admissionFix = migration("0016_fix_auth_admission_null.sql");

    expect(admissionFix).toContain(
      'CREATE OR REPLACE FUNCTION "app"."admit_auth_attempts"',
    );
    expect(admissionFix).toContain("rate_record.blocked_until IS NULL");
    expect(admissionFix).toContain(
      "rate_record.blocked_until <= transaction_timestamp()",
    );
    expect(admissionFix).not.toContain(
      "AND NOT (rate_record.blocked_until > transaction_timestamp())",
    );
  });

  it("exposes tenant audit verification without broad auditor table grants", () => {
    const verifier = migration("0017_audit_verifier_least_privilege.sql");

    expect(verifier).toContain(
      'CREATE OR REPLACE FUNCTION "app"."verify_audit_chain"',
    );
    expect(verifier).toContain("SECURITY DEFINER");
    expect(verifier).toContain("SET search_path = pg_catalog, public, app");
    expect(verifier).toContain("p_tenant_id IS DISTINCT FROM context_tenant");
    expect(verifier).toContain(
      "pg_catalog.pg_has_role(invoker_role, 'periapsis_auditor', 'USAGE')",
    );
    expect(verifier).toContain("membership.status = 'active'");
    expect(verifier).toContain(
      'REVOKE ALL ON TABLE "public"."tenants", "public"."audit_chain_heads" FROM "periapsis_auditor"',
    );
    expect(verifier).not.toMatch(
      /GRANT\s+(?:ALL|SELECT)[^;]+(?:tenants|audit_chain_heads)[^;]+periapsis_auditor/i,
    );
  });

  it("uses PostgreSQL 18 UUIDv7 defaults without a legacy UUID extension", () => {
    const initial = migration("0000_little_red_shift.sql");

    expect(initial.match(/DEFAULT uuidv7\(\)/g)).toHaveLength(6);
    expect(initial).not.toMatch(/gen_random_uuid|uuid_generate|uuid-ossp/i);
  });

  it("replaces every UUIDv7 constraint with a fail-closed expression", () => {
    const hardening = migration("0004_uuidv7_fail_closed.sql");

    expect(
      hardening.match(/DROP CONSTRAINT "[^"]+_uuidv7_check"/g),
    ).toHaveLength(7);
    expect(
      hardening.match(
        /ADD CONSTRAINT "[^"]+_uuidv7_check" CHECK \(\(uuid_extract_version\([^;]+?\) = 7\) is true\)/g,
      ),
    ).toHaveLength(7);
  });

  it("forces RLS and checks both tenant and actor context", () => {
    const security = migration("0001_security_controls.sql");
    const initial = migration("0000_little_red_shift.sql");

    for (const table of [
      "tenants",
      "users",
      "tenant_memberships",
      "alerts",
      "audit_events",
      "audit_chain_heads",
      "outbox_events",
    ]) {
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
    }

    expect(initial).toContain("current_setting('app.tenant_id', true)");
    expect(initial).toContain("current_setting('app.user_id', true)");
  });

  it("creates only non-login service group roles", () => {
    const initial = migration("0000_little_red_shift.sql");
    const security = migration("0001_security_controls.sql");

    for (const role of [
      "periapsis_migrator",
      "periapsis_api",
      "periapsis_worker",
      "periapsis_notifier",
      "periapsis_auditor",
    ]) {
      expect(initial).toContain(`CREATE ROLE "${role}"`);
      expect(security).toMatch(new RegExp(`ALTER ROLE "${role}"[^;]+NOLOGIN`));
    }

    expect(initial + security).not.toMatch(/PASSWORD\s+['"]/i);
  });

  it("serializes each tenant audit chain at its protected head", () => {
    const concurrency = migration("0006_audit_attribution.sql");

    expect(concurrency).toContain(
      'CREATE OR REPLACE FUNCTION "app"."seal_audit_event"',
    );
    expect(concurrency).toContain("FOR UPDATE");
    expect(concurrency).toContain("NEW.sequence := prior_sequence + 1");
    expect(concurrency).toContain("NEW.previous_hash := prior_hash");
    expect(concurrency).toContain("SET last_sequence = NEW.sequence");
  });

  it("binds user attribution to the API context without weakening the migrator", () => {
    const attribution = migration("0006_audit_attribution.sql");

    expect(attribution).toContain("current_setting('role', true)");
    expect(attribution).toContain("invoker_role := session_user::text");
    expect(attribution).toContain("invoker_role <> 'periapsis_migrator'");
    expect(attribution).toContain(
      "invoker_role NOT IN ('periapsis_api', 'periapsis_api_login')",
    );
    expect(attribution).toContain(
      "NEW.actor_user_id IS DISTINCT FROM context_user",
    );
    expect(attribution).toContain(
      "NEW.impersonated_by_user_id IS DISTINCT FROM context_user",
    );
    expect(attribution).toContain(
      "NEW.actor_user_id IS NOT NULL OR NEW.impersonated_by_user_id IS NOT NULL",
    );
  });

  it("compares the visible event tail and protected head fail-closed", () => {
    const tail = migration("0005_audit_tail_verification.sql");

    expect(tail).toContain(
      'CREATE OR REPLACE FUNCTION "app"."verify_audit_chain"',
    );
    expect(tail).toContain("LEFT JOIN latest_event");
    expect(tail).toContain("WHERE NOT EXISTS (SELECT 1 FROM visible_head)");
    expect(tail).toContain("head.last_sequence = latest.sequence");
    expect(tail).toContain("head.last_event_hash = latest.event_hash");
    expect(tail).toContain("FROM public.tenants AS tenant");
    expect(tail).toContain("head.last_sequence = 0");
    expect(tail).toContain("AND NOT EXISTS (SELECT 1 FROM latest_event)");
    expect(tail).toContain(") IS TRUE AS valid");
  });

  it("seals audit rows with core SHA-256 and rejects mutation", () => {
    const security = migration("0001_security_controls.sql");

    expect(security).toContain('CREATE FUNCTION "app"."seal_audit_event"');
    expect(security).toContain("sha256(");
    expect(security).toContain(
      'CREATE TRIGGER "audit_events_reject_update_delete"',
    );
    expect(security).not.toContain("CREATE EXTENSION");
    expect(security).not.toMatch(
      /GRANT\s+(?:ALL|UPDATE|DELETE)[^;]+audit_events[^;]+periapsis_api/i,
    );
  });

  it("provides an indexed, leaseable transactional outbox", () => {
    const initial = migration("0000_little_red_shift.sql");

    expect(initial).toContain('CREATE INDEX "outbox_events_dequeue_idx"');
    expect(initial).toContain('"processed_at" is null');
    expect(initial).toContain('"locked_at"');
    expect(initial).toContain('"deduplication_key"');
  });

  it("makes final background and auditor policies require tenant context", () => {
    const tenantPolicies = migration("0002_redundant_magus.sql");
    const notifierHardening = migration("0004_uuidv7_fail_closed.sql");

    for (const policy of [
      "audit_events_worker_access",
      "audit_events_notifier_access",
      "audit_events_auditor_select",
      "outbox_events_worker_access",
      "outbox_events_notifier_access",
    ]) {
      expect(tenantPolicies).toMatch(
        new RegExp(
          `ALTER POLICY "${policy}"[^;]+current_setting\\('app\\.tenant_id', true\\)`,
        ),
      );
    }

    expect(notifierHardening).toMatch(
      /ALTER POLICY "outbox_events_notifier_access"[^;]+current_setting\('app\.tenant_id', true\)[^;]+event_type" like 'notification\.%'/,
    );
  });

  it("preflights, migrates, and seals one locked database session", () => {
    const migrateSource = readFileSync(
      resolve(packageRoot, "src/admin/migrate.ts"),
      "utf8",
    );
    const protocolSource = readFileSync(
      resolve(packageRoot, "src/admin/schema-migration.ts"),
      "utf8",
    );
    const reserveIndex = protocolSource.indexOf("await client.reserve()");
    const metadataIndex = protocolSource.indexOf(
      "attachDrizzleClientMetadata(client, connection)",
    );
    const lockIndex = protocolSource.indexOf("await acquireMigrationLock(");
    const searchPathIndex = protocolSource.indexOf(
      "set_config('search_path', 'public', false)",
    );
    const bundleIndex = protocolSource.indexOf(
      "await assertExactMigrationBundle(migrationsFolder)",
    );
    const preflightIndex = protocolSource.indexOf(
      "assertExactMigrationPrefix(appliedMigrations, { convergenceAttested })",
    );
    const migrateIndex = protocolSource.indexOf(
      "await migrateVerifiedBundle(connection, migrationsFolder)",
    );
    const sealIndex = protocolSource.indexOf(
      "await sealSchemaCompatibilityManifest(",
    );
    const releaseIndex = protocolSource.indexOf(
      "await releaseMigrationLock(",
      sealIndex,
    );

    expect(migrateSource).toContain("await executeWithCleanup(");
    expect(migrateSource).toContain("migrateSchema(client");
    expect(migrateSource).toContain("() => client.end()");
    expect(migrateSource).toContain(
      "schema migration and database client cleanup both failed",
    );
    expect(reserveIndex).toBeGreaterThan(-1);
    expect(metadataIndex).toBeGreaterThan(reserveIndex);
    expect(lockIndex).toBeGreaterThan(metadataIndex);
    expect(migrateIndex).toBeGreaterThan(searchPathIndex);
    expect(searchPathIndex).toBeGreaterThan(lockIndex);
    expect(bundleIndex).toBeGreaterThan(searchPathIndex);
    expect(preflightIndex).toBeGreaterThan(bundleIndex);
    expect(migrateIndex).toBeGreaterThan(preflightIndex);
    expect(sealIndex).toBeGreaterThan(migrateIndex);
    expect(releaseIndex).toBeGreaterThan(sealIndex);
    expect(protocolSource).toContain("pg_try_advisory_lock");
    expect(protocolSource).toContain(
      "app.private_v47_migration_convergence_schema_readiness_v1()",
    );
    expect(protocolSource).toContain(
      "drizzle.__periapsis_migration_convergence_attestations",
    );
    expect(protocolSource).toContain(
      "readMigrationConvergenceAttestation(connection, migratedMigrations)",
    );
    expect(protocolSource).toContain(
      "evidence.normalized_v45_fingerprint = ${normalizedFingerprint}",
    );
    expect(protocolSource).toContain('await execute("BEGIN")');
    expect(protocolSource).toContain('await execute("COMMIT")');
    expect(protocolSource).toContain('await execute("ROLLBACK")');
    expect(protocolSource).not.toContain("client.begin.bind");
  });

  it("fails generated-schema parity when schema evaluation fails", () => {
    const verifier = readFileSync(
      resolve(packageRoot, "src/admin/verify-generated.ts"),
      "utf8",
    );

    expect(verifier).toContain('await import("../schema/index.js")');
    expect(verifier).toContain("reportedRuntimeFailure");
    expect(verifier).toContain("generated.error || generated.status !== 0");
    expect(verifier).toMatch(/Reference\|Type\|Syntax\|Range/);
  });

  it("exposes migration compatibility without journal access for runtime roles", () => {
    const compatibility = migration("0007_schema_compatibility.sql");

    expect(compatibility).toContain(
      'CREATE FUNCTION "app"."schema_compatibility"()',
    );
    expect(compatibility).toContain("applied_count bigint");
    expect(compatibility).toContain("latest_created_at bigint");
    expect(compatibility).toContain("latest_hash text");
    expect(compatibility).toContain("migration_fingerprint text");
    expect(compatibility).toContain("string_agg(");
    expect(compatibility).toContain("lower(migration.hash::text)");
    expect(compatibility).toContain(
      "':' ORDER BY migration.created_at, migration.id",
    );
    expect(compatibility).toContain("SECURITY DEFINER");
    expect(compatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."schema_compatibility"() FROM PUBLIC',
    );
    expect(compatibility).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(compatibility).not.toMatch(
      /GRANT SELECT ON TABLE[^;]+TO "periapsis_(?:api|worker)"/,
    );
  });

  it("allowlists the exact 0025 rolling-compatibility edge", () => {
    const compatibility = migration(
      "0025_authorization_compatibility_and_ownership.sql",
    );

    expect(compatibility).toContain(
      'CREATE FUNCTION "app"."schema_compatibility_v2"()',
    );
    expect(compatibility).toContain(
      'CREATE OR REPLACE FUNCTION "app"."schema_compatibility"()',
    );
    expect(compatibility).toContain("journal_count = 26");
    expect(compatibility).toContain(
      "journal_latest_created_at = 1787516694668",
    );
    expect(compatibility).toContain("migration_0025_rows = 1");
    expect(compatibility).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );
    expect(compatibility).toContain("journal_fingerprint = current_setting(");
    expect(compatibility).toContain(
      "row_number() OVER (\n            ORDER BY migration.created_at, migration.id",
    );
    expect(compatibility).toContain("WHERE migration.migration_ordinal <= 25");
    expect(compatibility).toContain(
      "FROM app.schema_compatibility_v2() AS compatibility",
    );
    expect(compatibility).not.toContain("created_at::text || '@'");
    expect(compatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."schema_compatibility_v2"() FROM PUBLIC',
    );
    expect(compatibility).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v2"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(compatibility).toContain(
      'CREATE FUNCTION "app"."seal_schema_compatibility_manifest"(',
    );
    expect(compatibility).toContain(
      'GRANT SET ON PARAMETER app.schema_compatibility_fingerprint TO "periapsis_migrator"',
    );
    expect(compatibility).toContain(
      "actual_migration_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint",
    );
    expect(compatibility).toContain(
      "SET app.schema_compatibility_fingerprint FROM CURRENT",
    );
    expect(compatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor"',
    );
    expect(compatibility).not.toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."seal_schema_compatibility_manifest"/,
    );
  });

  it("rotates current readiness and seals only the exact 0026 predecessor edge", () => {
    const failClosedCompatibility = migration(
      "0026_schema_compatibility_fail_closed.sql",
    );
    const compatibilityGenerator = readFileSync(
      resolve(packageRoot, "../../scripts/generate-schema-compatibility.mjs"),
      "utf8",
    );

    expect(failClosedCompatibility).toContain(
      'CREATE FUNCTION "app"."schema_compatibility_v3"()',
    );
    expect(failClosedCompatibility).toContain(
      "FROM drizzle.__drizzle_migrations AS migration",
    );
    expect(failClosedCompatibility).toContain(
      "migration.created_at::text || '@' || lower(migration.hash::text)",
    );
    expect(compatibilityGenerator).toContain(
      ".map((entry, index) => `${entry.when}@${migrationHashes[index]}`)",
    );
    expect(failClosedCompatibility).toContain(
      'ALTER FUNCTION "app"."schema_compatibility_v3"() OWNER TO "periapsis_migrator"',
    );
    expect(failClosedCompatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."schema_compatibility_v3"() FROM PUBLIC',
    );
    expect(failClosedCompatibility).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v3"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(failClosedCompatibility).toContain(
      'CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v2"()',
    );
    expect(failClosedCompatibility).toContain("journal_count = 27");
    expect(failClosedCompatibility).toContain(
      "journal_latest_created_at = 1787571776845",
    );
    expect(failClosedCompatibility).toContain("migration_0026_rows = 1");
    expect(failClosedCompatibility).toContain(
      "SET app.schema_compatibility_fingerprint = 'UNSEALED'",
    );
    expect(failClosedCompatibility).toContain(
      "journal_fingerprint = current_setting(",
    );
    expect(failClosedCompatibility).toContain(
      "WHERE migration.migration_ordinal <= 26",
    );
    expect(failClosedCompatibility).toContain(
      "FROM app.schema_compatibility_v3() AS compatibility",
    );
    expect(failClosedCompatibility).toContain(
      "string_agg(\n          migration.migration_hash,",
    );
    expect(failClosedCompatibility).toContain(
      'ALTER FUNCTION "app"."schema_compatibility_v2"() OWNER TO "periapsis_migrator"',
    );
    expect(failClosedCompatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."schema_compatibility_v2"() FROM PUBLIC',
    );
    expect(failClosedCompatibility).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v2"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(failClosedCompatibility).toContain(
      'CREATE OR REPLACE FUNCTION "app"."schema_compatibility"()',
    );
    expect(failClosedCompatibility).toContain("SELECT 0::bigint");
    expect(failClosedCompatibility).toContain("'UNSUPPORTED'::text");
    expect(failClosedCompatibility).toContain("SECURITY DEFINER");
    expect(failClosedCompatibility).toContain("SET search_path = pg_catalog");
    expect(failClosedCompatibility).toContain(
      'ALTER FUNCTION "app"."schema_compatibility"() OWNER TO "periapsis_migrator"',
    );
    expect(failClosedCompatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."schema_compatibility"() FROM PUBLIC',
    );
    expect(failClosedCompatibility).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."schema_compatibility"() TO "periapsis_api", "periapsis_worker"',
    );
    expect(failClosedCompatibility).toContain(
      'CREATE OR REPLACE FUNCTION "app"."seal_schema_compatibility_manifest"(',
    );
    expect(failClosedCompatibility).toContain(
      "p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'",
    );
    expect(failClosedCompatibility).toContain(
      "p_expected_latest_created_at::text || '@' || p_expected_latest_hash",
    );
    expect(failClosedCompatibility).toContain(
      "ALTER FUNCTION app.schema_compatibility_v2()",
    );
    expect(failClosedCompatibility).toContain(
      "SET app.schema_compatibility_fingerprint FROM CURRENT",
    );
    expect(failClosedCompatibility).toContain(
      'REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor"',
    );
    expect(failClosedCompatibility).not.toMatch(
      /GRANT EXECUTE ON FUNCTION "app"\."seal_schema_compatibility_manifest"/,
    );
  });

  it("protects all Phase 2A authority tables with forced RLS and definer-only access", () => {
    const security = migration("0009_phase_2a_security.sql");
    const protectedTables = [
      "auth_challenges",
      "auth_rate_limits",
      "auth_sessions",
      "local_break_glass_credentials",
      "recovery_codes",
      "totp_credentials",
      "platform_audit_chain_head",
      "platform_audit_events",
      "platform_bootstrap_enrollments",
      "platform_bootstrap_state",
      "platform_permissions",
      "platform_role_permissions",
      "platform_roles",
      "user_platform_roles",
    ];

    for (const table of protectedTables) {
      expect(security).toContain(
        `ALTER TABLE "public"."${table}" FORCE ROW LEVEL SECURITY`,
      );
      expect(security).toContain(
        `REVOKE ALL ON TABLE "public"."${table}" FROM PUBLIC`,
      );
    }
    expect(security).not.toMatch(
      /GRANT (?:SELECT|INSERT|UPDATE|DELETE|ALL)[^;]+(?:auth_sessions|local_break_glass_credentials|totp_credentials|recovery_codes|user_platform_roles)[^;]+periapsis_api/i,
    );
  });

  it("contains the complete Phase 2A forward schema transition before security hardening", () => {
    const schema = migration("0008_phase_2a_auth.sql");
    const requiredTables = [
      "auth_challenges",
      "auth_rate_limits",
      "auth_sessions",
      "local_break_glass_credentials",
      "recovery_codes",
      "totp_credentials",
      "platform_audit_chain_head",
      "platform_audit_events",
      "platform_bootstrap_enrollments",
      "platform_bootstrap_state",
      "platform_permissions",
      "platform_role_permissions",
      "platform_roles",
      "user_platform_roles",
    ];

    expect(schema).toContain('CREATE TYPE "public"."auth_challenge_purpose"');
    expect(schema).toContain('CREATE TYPE "public"."auth_rate_limit_scope"');
    for (const table of requiredTables) {
      expect(schema).toContain(`CREATE TABLE "${table}"`);
      expect(schema).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
    }
    expect(schema).toContain(
      'ALTER TABLE "users" DROP CONSTRAINT "users_email_canonical_check"',
    );
    expect(schema).toContain('"users"."email" = lower(btrim("users"."email"))');
    expect(schema).toContain('"attempts" integer DEFAULT 0 NOT NULL');
    expect(schema).toContain('"max_attempts" integer DEFAULT 5 NOT NULL');
    expect(schema).toContain('"invalidated_at" timestamp with time zone');
    expect(schema).toContain('"challenge_rate_key_digest" "bytea" NOT NULL');
    expect(schema).toContain('"mfa_rate_key_digest" "bytea" NOT NULL');
    expect(schema).toContain(
      '"login_account_rate_key_digest" "bytea" NOT NULL',
    );
    expect(schema).toContain('"enrollment_rate_key_digest" "bytea" NOT NULL');
    expect(schema).toContain('"master_key_verifier" "bytea"');
    expect(schema).toContain(
      '"master_key_verifier_bound_at" timestamp with time zone',
    );
    expect(schema).toContain(
      'CONSTRAINT "platform_bootstrap_state_master_key_verifier_check"',
    );
    expect(schema).toContain(
      'CONSTRAINT "platform_bootstrap_state_protected_configuration_check"',
    );
    expect(schema).toContain(
      'CREATE UNIQUE INDEX "auth_challenges_user_unconsumed_key"',
    );
    expect(schema).toContain('WHERE "auth_challenges"."consumed_at" is null');
    expect(schema).toContain('"rotation_family_id" uuid NOT NULL');
    expect(schema).toContain("'tenant_switch'");
    expect(schema).toContain("ON DELETE set null");
    expect(schema).toContain(
      "lower(split_part(\"tenants\".\"locale\", '-', 1)) <> 'und'",
    );
  });

  it("binds the one-time bootstrap to authority, enrollment, email, and ten recovery codes", () => {
    const security = migration("0009_phase_2a_security.sql");

    expect(security).toContain(
      'CREATE FUNCTION "app"."verify_protected_configuration"(',
    );
    expect(security).not.toContain('"configure_platform_bootstrap_authority"');
    expect(security).not.toContain('"verify_or_bind_master_key"');
    expect(security).not.toContain('"platform_bootstrap_status"');
    expect(security).toContain('"reserve_platform_bootstrap"');
    expect(security).toContain('"confirm_platform_bootstrap"');
    expect(security).toContain(
      "enrollment.canonical_email IS DISTINCT FROM p_canonical_email",
    );
    expect(security).toContain("recovery_count <> 10");
    expect(security).toContain("FOR UPDATE");
    expect(security).toContain("bootstrap_totp");
    expect(security).toContain("platform.bootstrap.confirmed");
    expect(security).toContain('"record_platform_bootstrap_failure"');
    expect(security).toContain(
      "enrollment.attempts >= enrollment.max_attempts",
    );
    expect(security).toContain(
      "'bootstrap_enrollment:' || p_enrollment_id::text || ':email:' || p_canonical_email",
    );
    expect(security).toContain(
      "'totp_credential:' || p_totp_credential_id::text || ':user:' || p_user_id::text",
    );
    expect(security).toContain(
      "key_digest = enrollment.enrollment_rate_key_digest",
    );
    expect(security).toContain("FOR UPDATE;");
    expect(security).toContain(
      "authority_token_digest = p_authority_token_digest",
    );
    expect(security).toContain("master_key_verifier = p_master_key_verifier");
    expect(security).toContain(
      "RAISE EXCEPTION 'protected configuration binding is incomplete'",
    );
    expect(security).toContain(
      "RAISE EXCEPTION 'invalid protected configuration' USING ERRCODE = '42501'",
    );
    expect(security).toContain(
      "master_key_verifier_bound_at = transaction_timestamp()",
    );
    expect(security).toContain(
      "master-key verifier must be bound before bootstrap enrollment",
    );
  });

  it("uses canonical platform permission keys and rechecks them inside privileged functions", () => {
    const security = migration("0009_phase_2a_security.sql");
    const seed = security.match(
      /INSERT INTO "public"\."platform_permissions"[\s\S]+?;--> statement-breakpoint/,
    )?.[0];

    expect(seed).toBeDefined();
    expect(seed?.match(/'platform\.[a-z.]+?'/g)).toEqual([
      "'platform.tenant.read'",
      "'platform.tenant.create'",
    ]);
    expect(security).not.toMatch(/'tenant\.(?:list|create)'/);
    expect(security).toContain(
      'CREATE FUNCTION "app"."list_platform_tenants"(p_after_id uuid, p_limit integer)',
    );
    expect(security).toContain("ORDER BY tenant.id");
    expect(security).toContain("LIMIT p_limit;");
    expect(security).not.toContain("LIMIT p_limit + 1");
    expect(security).not.toContain("p_limit NOT BETWEEN 1 AND 200");
    expect(security).toContain("FROM pg_catalog.pg_timezone_names AS timezone");
    expect(security).toContain(
      "INSERT INTO public.audit_chain_heads (tenant_id)",
    );
    expect(security).toContain(
      "SELECT tenant.id, tenant.slug, tenant.name, tenant.status, tenant.timezone",
    );
  });

  it("provides one-use challenge, recovery, TOTP, and session transitions", () => {
    const security = migration("0009_phase_2a_security.sql");

    expect(security).toContain('"advance_totp_counter"');
    expect(security).toContain("last_accepted_counter < p_counter");
    expect(security).toContain('"consume_recovery_code"');
    expect(security).toContain("consumed_at IS NULL");
    expect(security).toContain('"consume_auth_challenge"');
    expect(security).toContain('"complete_mfa_login"');
    expect(security).toContain('"record_mfa_challenge_failure"');
    expect(security).toContain('"rotate_auth_session"');
    expect(security).toContain('"rotate_auth_session_tenant"');
    expect(security).toContain('"list_user_tenant_memberships"');
    expect(security).toContain("rotated_from_session_id");
    expect(security).toContain("local_credential.disabled_at IS NULL");
    expect(security).toContain("credential.id = recovery.totp_credential_id");
    expect(security).toContain("identity.active = true");
    expect(security).toContain(
      '"list_user_sessions"(\n  p_current_session_id uuid,\n  p_after_session_id uuid,\n  p_limit integer',
    );
    expect(security).toContain(
      '"list_user_tenant_memberships"(\n  p_after_membership_id uuid,\n  p_limit integer',
    );
    expect(security).toContain("p_limit NOT BETWEEN 1 AND 101");
    expect(security.match(/p_limit IS NULL/g)).toHaveLength(4);
    expect(security).toContain("p_after_sequence IS NULL");
    expect(security).toContain(
      "(session.created_at, session.id)\n          < (cursor_created_at, p_after_session_id)",
    );
    expect(security).toContain("membership.id > p_after_membership_id");
    expect(security).toContain("membership.status = 'active'");
    expect(security).toContain("tenant.status = 'active'");
    expect(security).toContain("FOR UPDATE OF identity");
    expect(security).toContain("AND consumed_at IS NULL;");
    expect(security).toContain("challenge.challenge_rate_key_digest");
    expect(security).toContain("p_clear_scopes");
    expect(security).toContain("failure_recorded boolean");
    expect(security).toContain(
      "rotated session cannot extend the original absolute expiry",
    );
  });

  it("grants the API only composed authentication and exposed platform entry points", () => {
    const security = migration("0009_phase_2a_security.sql");
    const grants = security.slice(
      security.indexOf('GRANT USAGE ON TYPE "public"."auth_challenge_purpose"'),
    );

    for (const callable of [
      "verify_protected_configuration",
      "reserve_platform_bootstrap",
      "get_platform_bootstrap_enrollment",
      "confirm_platform_bootstrap",
      "admit_auth_attempts",
      "record_authentication_failure",
      "record_auth_rate_limit_failure",
      "create_auth_challenge",
      "complete_mfa_login",
      "record_mfa_challenge_failure",
      "record_platform_bootstrap_failure",
      "get_auth_session",
      "list_user_sessions",
      "list_user_tenant_memberships",
      "revoke_user_session",
      "rotate_auth_session_tenant",
      "list_platform_tenants",
      "create_platform_tenant",
    ]) {
      expect(grants).toContain(`"${callable}"`);
    }

    for (const internalOnly of [
      "configure_platform_bootstrap_authority",
      "platform_bootstrap_status",
      "verify_or_bind_master_key",
      "advance_totp_counter",
      "consume_recovery_code",
      "consume_auth_challenge",
      "create_auth_session",
      "grant_platform_role",
      "read_platform_audit_events",
      "clear_auth_rate_limit",
      "prune_expired_auth_state",
    ]) {
      expect(grants).not.toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION "app"\\."${internalOnly}"[^;]+TO "periapsis_api"`,
        ),
      );
    }
  });

  it("keeps platform audit append-only and authentication meters bounded", () => {
    const security = migration("0009_phase_2a_security.sql");

    expect(security).toContain('"platform_audit_events_seal_before_insert"');
    expect(security).toContain('"platform_audit_events_reject_update_delete"');
    expect(security).toContain("FOR UPDATE");
    expect(security).toContain(
      "least(public.auth_rate_limits.attempt_count + 1, 2147483647)",
    );
    expect(security).toContain("introduced_rate_limit_ids");
    expect(security).toContain("WHERE id = ANY(introduced_rate_limit_ids)");
    expect(security).toContain("cardinality(p_scopes)");
    expect(security).toContain("GROUP BY rule.scope, rule.key_digest");
    expect(security).toContain("OR rate.blocked_until > statement_timestamp()");
    expect(security).toContain(
      '"prune_expired_auth_state"(p_per_class_batch_size integer)',
    );
    expect(security).toContain("FOR UPDATE SKIP LOCKED");
    expect(security).toContain("interval '24 hours'");
    expect(security).toContain("interval '30 days'");
    expect(security).toContain(
      'GRANT EXECUTE ON FUNCTION "app"."prune_expired_auth_state"(integer) TO "periapsis_worker"',
    );
    expect(security).not.toContain(
      'GRANT EXECUTE ON FUNCTION "app"."prune_expired_auth_state"(integer) TO "periapsis_api"',
    );
    expect(security).toContain("WHERE NOT EXISTS (SELECT 1 FROM visible_head)");
  });
});
