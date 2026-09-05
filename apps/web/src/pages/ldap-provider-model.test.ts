import { describe, expect, it } from "vitest";

import {
  createLdapProviderDraft,
  diagnosticCategoryLabel,
  draftFromLdapProvider,
  providerIdFromLocation,
  toLdapProviderCreateInput,
  toLdapProviderUpdateInput,
  validateAdministrativeReason,
  validateBindSecret,
  validateLdapProviderDraft,
  type LdapTemplateKind,
} from "./ldap-provider-model";

const templates: readonly LdapTemplateKind[] = [
  "active_directory",
  "openldap",
  "posix",
];

describe("LDAP provider model", () => {
  it.each(templates)(
    "builds a complete valid editable %s template",
    (template) => {
      const draft = createLdapProviderDraft(template);

      expect(validateLdapProviderDraft(draft)).toEqual([]);
      expect(Object.keys(draft.configuration)).toHaveLength(39);
      expect(Object.keys(draft.endpoints[0] ?? {})).toHaveLength(7);
      expect(draft.enabled).toBe(false);
      expect(draft.configuration).toMatchObject({
        deprovisionGraceSeconds: 0,
        deprovisionMode: "retain",
        jitMode: "disabled",
        noMatchPolicy: "deny",
        syncIntervalSeconds: null,
        verifyCertificate: true,
      });
    },
  );

  it("emits disabled create and full replacement update documents", () => {
    const draft = createLdapProviderDraft("openldap");
    draft.endpoints.push({
      ...draft.endpoints[0]!,
      host: "backup.example.org",
      priority: 2,
      tlsServerName: "backup.example.org",
    });
    draft.enabled = true;

    const create = toLdapProviderCreateInput(draft);
    const update = toLdapProviderUpdateInput(draft);

    expect(create).not.toHaveProperty("enabled");
    expect(create.kind).toBe("ldap");
    expect(Object.keys(update).toSorted()).toEqual(
      [
        "configuration",
        "description",
        "displayName",
        "enabled",
        "endpoints",
        "key",
      ].toSorted(),
    );
    expect(update.enabled).toBe(true);
    expect(update.endpoints).not.toBe(draft.endpoints);
  });

  it("rejects duplicate destinations, invalid placeholders, and changed frozen policy", () => {
    const draft = createLdapProviderDraft("openldap");
    draft.endpoints.push({ ...draft.endpoints[0]!, priority: 2 });
    draft.configuration.userSearchFilter = "(uid={rawValue})";
    Object.defineProperty(draft.configuration, "deprovisionGraceSeconds", {
      value: 1,
    });

    expect(validateLdapProviderDraft(draft)).toEqual(
      expect.arrayContaining([
        "Endpoint transport, host, and port identities must be unique.",
        "Foundation safety policy fields cannot be changed.",
        "User search filter uses an invalid or repeated placeholder.",
      ]),
    );
  });

  it("accepts multiline PEM while rejecting non-line-break controls", () => {
    const draft = createLdapProviderDraft("openldap");
    draft.configuration.customCaPem =
      "-----BEGIN CERTIFICATE-----\r\nY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\r\n";

    expect(validateLdapProviderDraft(draft)).toEqual([]);

    draft.configuration.customCaPem =
      "-----BEGIN CERTIFICATE-----\nY2VydA==\t\n-----END CERTIFICATE-----\n";
    expect(validateLdapProviderDraft(draft)).toContain(
      "Custom CA PEM is outside its allowed PEM text bounds.",
    );
  });

  it("enforces the 8176-byte secret bound without retaining a value", () => {
    expect(validateBindSecret("secret-value")).toBeNull();
    expect(validateBindSecret("é".repeat(4088))).toBeNull();
    expect(validateBindSecret(`é${"x".repeat(8175)}`)).toMatch(
      /8176 UTF-8 bytes/,
    );
    expect(validateBindSecret("\ud800")).toMatch(/valid UTF-8/);
  });

  it("validates reasons and exposes only sanitized diagnostic copy", () => {
    expect(validateAdministrativeReason("  ")).toMatch(/audit reason/);
    expect(validateAdministrativeReason("rotation complete")).toBeNull();
    expect(
      diagnosticCategoryLabel({
        category: "certificate_rejected",
        completedAt: "2026-08-25T09:30:00Z",
        durationMs: 42,
        endpointPriority: 1,
        outcome: "failure",
        stale: false,
        testRunId: "0198c97d-cf4f-7000-8000-000000000099",
      }),
    ).toBe("Certificate rejected");
  });

  it("clones an existing provider and extracts only canonical create locations", () => {
    const draft = createLdapProviderDraft("active_directory");
    const provider = {
      ...toLdapProviderUpdateInput(draft),
      archiveReason: null,
      archivedAt: null,
      bindSecretConfigured: false,
      bindSecretRotatedAt: null,
      createdAt: "2026-08-25T09:00:00Z",
      enabledEndpointCount: 1,
      id: "0198c97d-cf4f-7000-8000-000000000088",
      kind: "ldap" as const,
      template: draft.configuration.template,
      tenantId: "0198c97d-cf4f-7000-8000-000000000010",
      updatedAt: "2026-08-25T09:00:00Z",
      version: 1,
    };

    const cloned = draftFromLdapProvider(provider);
    cloned.endpoints[0]!.host = "changed.example.com";
    expect(provider.endpoints[0]!.host).toBe("ad.example.com");
    expect(
      providerIdFromLocation(
        "/api/v1/tenants/0198c97d-cf4f-7000-8000-000000000010/auth-providers/0198c97d-cf4f-7000-8000-000000000088",
      ),
    ).toBe(provider.id);
    expect(
      providerIdFromLocation("/wrong/0198c97d-cf4f-7000-8000-000000000088"),
    ).toBeNull();
  });
});
