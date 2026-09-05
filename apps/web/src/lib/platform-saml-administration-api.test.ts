import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import type {
  PlatformAuthProviderView,
  VersionedView,
} from "./phase-two-types";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const publicOrigin = "https://soc.example.com";

beforeEach(() => {
  vi.stubGlobal("location", { origin: publicOrigin });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi protected platform SAML administration", () => {
  it("replaces URL metadata with exact CAS, audit, approval, and revision headers", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return bodylessSAMLResponse('"v8"', 2);
      }),
    );

    await expect(
      phaseTwoApi.replacePlatformSamlMetadata(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Approve reviewed IdP trust coordinates",
        {
          approveTrustReset: true,
          expectedVersion: 7,
          metadataUrl: "https://idp.example.test/metadata",
          source: "url",
        },
      ),
    ).resolves.toEqual({ etag: '"v8"', materialRevision: 2 });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("PUT");
    expect(request.cache).toBe("no-store");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/saml/metadata`,
    );
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Approve reviewed IdP trust coordinates",
    );
    expect(await request.json()).toEqual({
      approveTrustReset: true,
      expectedVersion: 7,
      metadataUrl: "https://idp.example.test/metadata",
      source: "url",
    });
  });

  it("transfers write-only SP-key material without accepting a response body", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return bodylessSAMLResponse('"v8"', 3);
      }),
    );

    await expect(
      phaseTwoApi.replacePlatformSamlSpKey(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Rotate reviewed SAML signing material",
        {
          certificates: ["Y2VydGlmaWNhdGU="],
          expectedVersion: 7,
          privateKeyPkcs8: "cHJpdmF0ZS1rZXk=",
        },
      ),
    ).resolves.toEqual({ etag: '"v8"', materialRevision: 3 });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("PUT");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/saml/sp-key`,
    );
    expect(await request.json()).toEqual({
      certificates: ["Y2VydGlmaWNhdGU="],
      expectedVersion: 7,
      privateKeyPkcs8: "cHJpdmF0ZS1rZXk=",
    });
  });

  it("clears only an existing SP key through the destructive bodyless resource", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return bodylessSAMLResponse('"v8"', 3);
      }),
    );

    await expect(
      phaseTwoApi.clearPlatformSamlSpKey(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Retire compromised SAML signing material",
        { expectedVersion: 7 },
      ),
    ).resolves.toEqual({ etag: '"v8"', materialRevision: 3 });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("DELETE");
    expect(await request.json()).toEqual({ expectedVersion: 7 });
  });

  it.each([
    { etag: '"v8"', revision: "2", label: "stale provider ETag" },
    { etag: '"v8"', revision: "02", label: "noncanonical revision" },
    { etag: '"v8"', revision: "3", label: "skipped metadata revision" },
  ])(
    "rejects $label in the bodyless mutation receipt",
    async ({ etag, revision }) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          new Response(null, {
            headers: {
              "Cache-Control": "no-store",
              ETag: etag,
              "X-Periapsis-SAML-Material-Revision": revision,
            },
            status: 204,
          }),
        ),
      );

      const current = samlProviderView();
      if (revision === "2" && etag === '"v8"') current.etag = '"v8"';
      await expect(
        phaseTwoApi.replacePlatformSamlMetadata(
          "csrf-memory-only",
          providerId,
          current,
          "Replace reviewed SAML metadata",
          {
            approveTrustReset: false,
            expectedVersion: 7,
            metadataXml: "<EntityDescriptor />",
            source: "xml",
          },
        ),
      ).rejects.toBeInstanceOf(Error);
    },
  );

  it("preserves the protected trust-approval Problem Details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "saml_trust_approval_required",
            detail: "Review the replacement trust out of band.",
            requestId: providerId,
            status: 409,
            title: "SAML trust approval required",
            type: "about:blank",
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/problem+json",
            },
            status: 409,
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.replacePlatformSamlMetadata(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Review SAML metadata rollover",
        {
          approveTrustReset: false,
          expectedVersion: 7,
          metadataXml: "<EntityDescriptor />",
          source: "xml",
        },
      ),
    ).rejects.toMatchObject({
      code: "saml_trust_approval_required",
      status: 409,
    });
  });

  it("fails closed before transport for an OIDC projection or an absent SP key", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const saml = samlProviderView();
    saml.value.configuration.spKeyPresent = false;

    await expect(
      phaseTwoApi.clearPlatformSamlSpKey(
        "csrf-memory-only",
        providerId,
        saml,
        "Clear signing material",
        { expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

function bodylessSAMLResponse(etag: string, revision: number): Response {
  return new Response(null, {
    headers: {
      "Cache-Control": "no-store",
      ETag: etag,
      "X-Periapsis-SAML-Material-Revision": String(revision),
    },
    status: 204,
  });
}

function samlProviderView(): VersionedView<
  Extract<PlatformAuthProviderView, { kind: "saml" }>
> {
  return {
    etag: '"v7"',
    value: {
      accountMode: "disabled",
      activationAvailable: false,
      archivedAt: null,
      assurancePolicyRevision: 1,
      configuration: {
        acsUrl: `${publicOrigin}/api/v1/auth/platform/saml/acs`,
        clockSkewNanoseconds: 120_000_000_000,
        encryptionPolicy: "disabled",
        expectedEntityId: "https://idp.example.test/entity",
        maxAuthenticationAgeNanoseconds: 28_800_000_000_000,
        metadataRevision: 1,
        redirectSignatureAlgorithm:
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        requestedAuthnContexts: [],
        signaturePolicy: "both",
        spEntityId: `${publicOrigin}/api/v1/auth/platform/saml/workforce_saml/metadata`,
        spKeyPresent: true,
        spKeyRevision: 2,
        subjectSource: "persistent_nameid",
      },
      configurationRevision: 1,
      configured: true,
      createdAt: "2026-08-30T10:00:00Z",
      description: "Corporate workforce federation",
      displayName: "Workforce SAML",
      enabled: false,
      id: providerId,
      key: "workforce_saml",
      kind: "saml",
      planRevision: 1,
      platformLoginActivationAvailable: false,
      platformLoginEnabled: false,
      secretPresent: true,
      securityRevision: 1,
      updatedAt: "2026-08-30T10:05:00Z",
      version: 7,
    },
  };
}
