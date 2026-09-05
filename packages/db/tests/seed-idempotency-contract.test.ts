import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const seed = readFileSync(
  resolve(import.meta.dirname, "../seeds/seed.ts"),
  "utf8",
);

describe("database seed re-entry contract", () => {
  it("does not re-enter the one-shot legacy authorization bootstrap", () => {
    expect(seed.match(/app\.seed_tenant_authorization\(/g)).toHaveLength(1);
    expect(seed).toContain(
      "LEFT JOIN public.tenant_authorization_states AS authorization_state",
    );
    expect(seed).toContain("authorization_state.tenant_id IS NULL");
    expect(seed).toContain("authorization_state.initialized_at IS NULL");
    expect(seed).toContain("ORDER BY seeded_tenant.tenant_id");
  });

  it("guards demo mutations with durable resource state", () => {
    expect(seed).toContain("runApiMutationIfMissing");
    expect(seed.match(/runApiMutationIfMissing\(/g)?.length).toBeGreaterThan(
      10,
    );
    expect(seed).toContain('SET LOCAL ROLE "periapsis_migrator"');

    for (const mutation of [
      "app.publish_sla_calendar_v2",
      "app.publish_sla_policy_v2",
      "app.mutate_tenant_notification_definition_v1",
      "app.create_tenant_ldap_provider_v1",
      "app.create_tenant_auth_provider_binding_v1",
      "app.create_tenant_security_group",
      "app.create_tenant_role",
      "app.create_tenant_ldap_mapping_rule_v2",
      "app.commit_customer_contact_v1",
      "app.create_tenant_case_v1",
      "app.create_dfir_evidence_v1",
      "app.create_tenant_ticket_comment_v2",
      "app.append_phase4_mutation_effects_v1",
    ]) {
      expect(
        seed,
        `${mutation} must remain on the canonical database path`,
      ).toContain(mutation);
    }
  });

  it("does not re-enter DFIR identifier guards for existing fixture rows", () => {
    for (const [table, fixture] of [
      ["dfir_iocs", "ioc.resource"],
      ["dfir_assets", "asset.resource"],
      ["dfir_storage_objects", "evidence.storageObject"],
    ] as const) {
      const start = seed.indexOf(`INSERT INTO public.${table} (`);
      const end = seed.indexOf("RETURNING id", start);
      expect(start).toBeGreaterThan(-1);
      expect(end).toBeGreaterThan(start);
      const insert = seed.slice(start, end);
      const guard = insert.slice(insert.indexOf("WHERE NOT EXISTS ("));
      expect(insert).toMatch(/\)\s+SELECT\s+/u);
      expect(guard).toContain(`SELECT 1 FROM public.${table}`);
      expect(guard).toContain("WHERE tenant_id = ${acme.id}::uuid");
      expect(guard).toContain(
        `AND id = \${phaseOneFixtures.demo.${fixture}}::uuid`,
      );
      expect(guard).toContain("ON CONFLICT (id) DO NOTHING");
    }
    expect(seed).not.toContain("DISABLE TRIGGER");
    expect(seed).not.toContain("session_replication_role");
  });

  it("seeds tenant Alerts and their effects under matching local context", () => {
    const contextHelperStart = seed.indexOf("const setTenantContext = async");
    const contextHelperEnd = seed.indexOf(
      "const runApiMutationIfMissing = async",
      contextHelperStart,
    );
    const contextHelper = seed.slice(contextHelperStart, contextHelperEnd);
    const helperStart = seed.indexOf("const seedTenantAlert = async");
    const helperEnd = seed.indexOf("const [acme] = await tx", helperStart);
    const alertHelper = seed.slice(helperStart, helperEnd);

    expect(contextHelperStart).toBeGreaterThan(-1);
    expect(contextHelperEnd).toBeGreaterThan(contextHelperStart);
    expect(contextHelper).toContain('SET LOCAL ROLE "periapsis_migrator"');
    expect(contextHelper).toContain(
      "set_config('app.tenant_id', ${tenantId}, true)",
    );
    expect(contextHelper).toContain(
      "set_config('app.user_id', ${userId}, true)",
    );
    expect(contextHelper).toContain(
      "set_config('app.service_account_id', '', true)",
    );
    expect(helperStart).toBeGreaterThan(-1);
    expect(helperEnd).toBeGreaterThan(helperStart);
    expect(alertHelper).toContain(
      "await setTenantContext(input.tenantId, input.createdBy)",
    );
    expect(alertHelper).toContain(".insert(alerts)");
    expect(alertHelper).toContain("await tx.insert(auditEvents).values({");
    expect(alertHelper).toContain("await tx.insert(outboxEvents).values({");
    expect(alertHelper.indexOf("await setTenantContext")).toBeLessThan(
      alertHelper.indexOf(".insert(alerts)"),
    );
    expect(seed.match(/await seedTenantAlert\(\{/g)).toHaveLength(2);
    expect(seed).toContain("tenantId: acme.id");
    expect(seed).toContain("tenantId: globex.id");
    expect(seed).not.toContain("const insertedAlerts = await tx");
    expect(seed).not.toContain("insertedAlerts.map");
  });

  it("keeps the example LDAP provider disabled and secret-free", () => {
    expect(seed).toContain('host: "ldap.demo.example.invalid"');
    expect(seed).toContain('tlsServerName: "ldap.demo.example.invalid"');
    expect(seed).toContain("enabled: false");
    expect(seed).not.toContain("tenant_ldap_provider_secrets");
    expect(seed).not.toMatch(
      /bindPassword|clientSecret|privateKey|secretCiphertext/,
    );
    expect(seed).not.toMatch(/\b(?:password|token|secret)\s*[:=]/i);
  });

  it("covers the complete demo catalog including both comment visibilities", () => {
    for (const catalogMarker of [
      "custom_field_definitions",
      "dfir_iocs",
      "dfir_ioc_links",
      "dfir_assets",
      "dfir_asset_links",
      "dfir_storage_objects",
      "visibility = 'public'",
      "visibility = 'private'",
    ]) {
      expect(seed).toContain(catalogMarker);
    }
  });
});
