import { afterEach, describe, expect, it, vi } from "vitest";

import { createLdapProviderDraft } from "../pages/ldap-provider-model";
import { phaseTwoApi } from "./phase-two-api";
import type { PlatformLdapAuthProviderView } from "./phase-two-types";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi platform LDAP transport", () => {
  it("rotates the write-only bind secret with exact CAS and a canonical revision receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: {
            "Cache-Control": "no-store",
            ETag: '"v8"',
            "X-Periapsis-LDAP-Secret-Revision": "2",
          },
          status: 204,
        });
      }),
    );

    await expect(
      phaseTwoApi.replacePlatformLdapBindSecret(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: ldapProviderFixture() },
        "Rotate the workforce directory bind secret",
        { bindSecret: "write-only-bind-secret", expectedVersion: 7 },
      ),
    ).resolves.toBe('"v8"');

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("PUT");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Rotate the workforce directory bind secret",
    );
    await expect(request.json()).resolves.toEqual({
      bindSecret: "write-only-bind-secret",
      expectedVersion: 7,
    });
  });

  it.each(["02", "2e0", "9007199254740992"])(
    "rejects a non-canonical bind-secret revision receipt %s",
    async (secretRevision) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          new Response(null, {
            headers: {
              "Cache-Control": "no-store",
              ETag: '"v8"',
              "X-Periapsis-LDAP-Secret-Revision": secretRevision,
            },
            status: 204,
          }),
        ),
      );

      await expect(
        phaseTwoApi.replacePlatformLdapBindSecret(
          "csrf-memory-only",
          providerId,
          { etag: '"v7"', value: ldapProviderFixture() },
          "Rotate the workforce directory bind secret",
          { bindSecret: "write-only-bind-secret", expectedVersion: 7 },
        ),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("posts a redacted mapping dry run without accepting directory values", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(
          JSON.stringify({
            attributes: ["cn", "memberof"],
            category: "ok",
            durationMs: 19,
            endpointPriority: 1,
            kind: "mapping_dry_run",
            matchedEntryCount: 1,
            outcome: "success",
            testId: "0198c97d-cf4f-7000-8000-000000000099",
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
            },
            status: 200,
          },
        );
      }),
    );

    await expect(
      phaseTwoApi.testPlatformLdapProvider(
        "csrf-memory-only",
        providerId,
        "Validate mapping before login activation",
        { kind: "mapping_dry_run", username: "alice" },
      ),
    ).resolves.toEqual({
      attributes: ["cn", "memberof"],
      category: "ok",
      durationMs: 19,
      endpointPriority: 1,
      kind: "mapping_dry_run",
      matchedEntryCount: 1,
      outcome: "success",
      testId: "0198c97d-cf4f-7000-8000-000000000099",
    });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/ldap/tests`,
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Validate mapping before login activation",
    );
    await expect(request.json()).resolves.toEqual({
      kind: "mapping_dry_run",
      username: "alice",
    });
  });
});

function ldapProviderFixture(): PlatformLdapAuthProviderView {
  const draft = createLdapProviderDraft("active_directory");
  return {
    accountMode: "disabled",
    activationAvailable: false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      ...draft.configuration,
      jitMode: "existing_identity",
      noMatchPolicy: "deny",
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-09-02T10:00:00Z",
    description: "Corporate directory login",
    displayName: "Workforce LDAP",
    enabled: false,
    endpoints: draft.endpoints.map((endpoint) => ({
      ...endpoint,
      id: "0198c97d-cf4f-7000-8000-000000000090",
    })),
    id: providerId,
    key: "workforce_ldap",
    kind: "ldap",
    mappings: [],
    planRevision: 1,
    platformLoginActivationAvailable: false,
    platformLoginEnabled: false,
    secretPresent: false,
    securityRevision: 1,
    updatedAt: "2026-09-02T10:05:00Z",
    version: 7,
  };
}
