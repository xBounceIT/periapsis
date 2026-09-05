import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import type {
  PlatformAuthProviderCreateInput,
  PlatformAuthProviderView,
} from "./phase-two-types";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const publicOrigin = "https://soc.example.com";
const issuerPrefix = "https://identity.example.com/";

function asciiIssuerWithByteLength(byteLength: number): string {
  return issuerPrefix + "a".repeat(byteLength - issuerPrefix.length);
}

function multibyteIssuerOver2048Bytes(): string {
  return (
    issuerPrefix + "é".repeat(Math.floor((2048 - issuerPrefix.length) / 2) + 1)
  );
}

beforeEach(() => {
  vi.stubGlobal("location", { origin: publicOrigin });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi platform identity-provider transport", () => {
  it("uses no-store and returns only the sanitized list projection", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { items: [providerSummaryFixture()] },
          { "Cache-Control": "no-store" },
        );
      }),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviders({ includeArchived: true }),
    ).resolves.toEqual({ items: [providerSummaryFixture()] });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("GET");
    expect(request.cache).toBe("no-store");
    expect(request.url).toContain(
      "/api/v1/platform/auth-providers?limit=50&includeArchived=true",
    );
  });

  it.each(["private, no-store", "no-store, max-age=0", "No-Store"])(
    "rejects the non-contract Cache-Control value %s",
    async (cacheControl) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              { items: [providerSummaryFixture()] },
              { "Cache-Control": cacheControl },
            ),
          ),
      );

      await expect(phaseTwoApi.listPlatformAuthProviders()).rejects.toThrow(
        "did not mark",
      );
    },
  );

  it.each([
    {
      after: providerId,
      label: "a row at or before the requested cursor",
      page: { items: [providerSummaryFixture()] },
    },
    {
      after: "0198c97d-cf4f-7000-8000-000000000087",
      label: "out-of-order rows",
      page: {
        items: [
          {
            ...providerSummaryFixture(),
            id: "0198c97d-cf4f-7000-8000-000000000089",
            key: "workforce_oidc_later",
          },
          providerSummaryFixture(),
        ],
      },
    },
    {
      after: "0198c97d-cf4f-7000-8000-000000000087",
      label: "a cursor that is not the final returned row",
      page: {
        items: [providerSummaryFixture()],
        nextCursor: "0198c97d-cf4f-7000-8000-000000000089",
      },
    },
    {
      after: "0198c97d-cf4f-7000-8000-000000000087",
      label: "duplicate stable keys",
      page: {
        items: [
          providerSummaryFixture(),
          {
            ...providerSummaryFixture(),
            id: "0198c97d-cf4f-7000-8000-000000000089",
          },
        ],
      },
    },
  ])("rejects a stable provider page with $label", async ({ after, page }) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(page, { "Cache-Control": "no-store" })),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviders({ after }),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each([
    ["enabled", 0],
    ["enabled", null],
    ["enabled", ""],
    ["platformLoginEnabled", 0],
    ["platformLoginEnabled", null],
    ["platformLoginEnabled", ""],
    ["platformLoginActivationAvailable", 0],
    ["platformLoginActivationAvailable", null],
    ["platformLoginActivationAvailable", ""],
  ] as const)(
    "rejects a list projection with non-boolean %s=%j",
    async (field, value) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            {
              items: [{ ...providerSummaryFixture(), [field]: value }],
            },
            { "Cache-Control": "no-store" },
          ),
        ),
      );

      await expect(
        phaseTwoApi.listPlatformAuthProviders(),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("rejects a list projection missing the direct-login activation availability field", async () => {
    const {
      platformLoginActivationAvailable: _omitted,
      ...missingAvailability
    } = providerSummaryFixture();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { items: [missingAvailability] },
            { "Cache-Control": "no-store" },
          ),
        ),
    );

    await expect(phaseTwoApi.listPlatformAuthProviders()).rejects.toMatchObject(
      { code: "tenant_projection_mismatch" },
    );
  });

  it("accepts an authoritative ready OIDC list projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            items: [
              {
                ...providerSummaryFixture(),
                enabled: true,
                platformLoginActivationAvailable: true,
                secretPresent: true,
              },
            ],
          },
          { "Cache-Control": "no-store" },
        ),
      ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviders(),
    ).resolves.toMatchObject({
      items: [
        {
          platformLoginActivationAvailable: true,
          platformLoginEnabled: false,
        },
      ],
    });
  });

  it("accepts a ready OIDC list projection with direct platform login active", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            items: [
              {
                ...providerSummaryFixture(),
                enabled: true,
                platformLoginEnabled: true,
                secretPresent: true,
              },
            ],
          },
          { "Cache-Control": "no-store" },
        ),
      ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviders(),
    ).resolves.toMatchObject({
      items: [
        {
          enabled: true,
          kind: "oidc",
          platformLoginEnabled: true,
        },
      ],
    });
  });

  it("binds create to idempotency and audit headers without a secret field", async () => {
    const requests: Request[] = [];
    const created = oidcProviderFixture({ version: 1 });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            ...created,
            configuration: { ...created.configuration, useUserInfo: true },
            updatedAt: "2026-08-27T10:00:00Z",
          },
          {
            "Cache-Control": "no-store",
            ETag: '"v1"',
            Location: `/api/v1/platform/auth-providers/${providerId}`,
          },
          201,
        );
      }),
    );
    const input = {
      configuration: {
        allowRefreshToken: false,
        clientId: "periapsis-platform",
        extraScopes: ["profile"],
        issuer: "https://identity.example.com",
        postLogoutRedirectUri: "https://soc.example.com/signed-out",
        redirectUri:
          "https://soc.example.com/api/v1/auth/platform/oidc/callback",
        tenantRedirectUri:
          "https://soc.example.com/api/v1/auth/federated/oidc/callback",
        useUserInfo: true,
      },
      description: "Corporate workforce federation",
      displayName: "Workforce OIDC",
      key: "workforce_oidc",
      kind: "oidc" as const,
    };

    await expect(
      phaseTwoApi.createPlatformAuthProvider(
        "csrf-memory-only",
        "0198c97d-cf4f-7000-8000-000000000099",
        "Stage the provider definition",
        input,
      ),
    ).resolves.toMatchObject({
      etag: '"v1"',
      location: `/api/v1/platform/auth-providers/${providerId}`,
      value: { id: providerId, kind: "oidc" },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Stage the provider definition",
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    const body = await request.json();
    expect(body).toEqual(input);
    expect(body).not.toHaveProperty("clientSecret");
    expect(body.configuration).not.toHaveProperty("clientSecret");
  });

  it.each([
    {
      label: "refresh without offline_access",
      mutate: (
        input: Extract<PlatformAuthProviderCreateInput, { kind: "oidc" }>,
      ) => {
        input.configuration.allowRefreshToken = true;
      },
    },
    {
      label: "offline_access without refresh",
      mutate: (
        input: Extract<PlatformAuthProviderCreateInput, { kind: "oidc" }>,
      ) => {
        input.configuration.extraScopes = ["profile", "offline_access"];
      },
    },
    {
      label: "32 extra scopes",
      mutate: (
        input: Extract<PlatformAuthProviderCreateInput, { kind: "oidc" }>,
      ) => {
        input.configuration.extraScopes = Array.from(
          { length: 32 },
          (_, index) => `scope_${index}`,
        );
      },
    },
    {
      label: "Unicode whitespace in the client ID",
      mutate: (
        input: Extract<PlatformAuthProviderCreateInput, { kind: "oidc" }>,
      ) => {
        input.configuration.clientId = "client\u2003id";
      },
    },
  ])("rejects $label before platform OIDC transport", async ({ mutate }) => {
    const input = platformOidcCreateInput();
    mutate(input);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.createPlatformAuthProvider(
        "csrf-memory-only",
        "0198c97d-cf4f-7000-8000-000000000099",
        "Stage the provider definition",
        input,
      ),
    ).rejects.toThrow(/OIDC configuration/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects XML 1.0 noncharacters before platform SAML transport", async () => {
    const input = platformSamlCreateInput();
    input.configuration.expectedEntityId += "\uffff";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.createPlatformAuthProvider(
        "csrf-memory-only",
        "0198c97d-cf4f-7000-8000-000000000099",
        "Stage the provider definition",
        input,
      ),
    ).rejects.toThrow(/SAML configuration/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an IdP entity ID equal to the derived SP entity ID before transport", async () => {
    const input = platformSamlCreateInput();
    input.configuration.expectedEntityId = input.configuration.spEntityId;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.createPlatformAuthProvider(
        "csrf-memory-only",
        "0198c97d-cf4f-7000-8000-000000000099",
        "Stage the provider definition",
        input,
      ),
    ).rejects.toThrow(/SAML configuration/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts an idempotent create replay with the provider's renamed live projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          oidcProviderFixture({ key: "renamed_workforce_oidc", version: 9 }),
          {
            "Cache-Control": "no-store",
            ETag: '"v9"',
            Location: `/api/v1/platform/auth-providers/${providerId}`,
          },
          201,
        ),
      ),
    );

    await expect(
      phaseTwoApi.createPlatformAuthProvider(
        "csrf-memory-only",
        "0198c97d-cf4f-7000-8000-000000000099",
        "Replay the original staged definition",
        {
          configuration: {
            allowRefreshToken: false,
            clientId: "periapsis-platform",
            extraScopes: ["profile"],
            issuer: "https://identity.example.com",
            postLogoutRedirectUri: "https://soc.example.com/signed-out",
            redirectUri:
              "https://soc.example.com/api/v1/auth/platform/oidc/callback",
            tenantRedirectUri:
              "https://soc.example.com/api/v1/auth/federated/oidc/callback",
            useUserInfo: true,
          },
          description: "Corporate workforce federation",
          displayName: "Workforce OIDC",
          key: "workforce_oidc",
          kind: "oidc",
        },
      ),
    ).resolves.toMatchObject({
      etag: '"v9"',
      value: { id: providerId, key: "renamed_workforce_oidc", version: 9 },
    });
  });

  it.each([
    [
      "metadata",
      (provider: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...provider,
        displayName: "Different provider",
      }),
    ],
    [
      "OIDC configuration",
      (provider: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...provider,
        configuration: {
          ...provider.configuration,
          clientId: "different-client",
        },
      }),
    ],
    [
      "initial revisions",
      (provider: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...provider,
        securityRevision: 2,
      }),
    ],
    [
      "secret state",
      (provider: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...provider,
        configuration: {
          ...provider.configuration,
          clientSecretPresent: true,
        },
        secretPresent: true,
      }),
    ],
  ] as const)(
    "rejects a version-1 create projection with mismatched %s",
    async (_label, poison) => {
      const initial = {
        ...oidcProviderFixture({ version: 1 }),
        updatedAt: "2026-08-27T10:00:00Z",
      };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            poison(initial),
            {
              "Cache-Control": "no-store",
              ETag: '"v1"',
              Location: `/api/v1/platform/auth-providers/${providerId}`,
            },
            201,
          ),
        ),
      );

      await expect(
        phaseTwoApi.createPlatformAuthProvider(
          "csrf-memory-only",
          "0198c97d-cf4f-7000-8000-000000000099",
          "Stage the provider definition",
          {
            configuration: {
              allowRefreshToken: false,
              clientId: "periapsis-platform",
              extraScopes: ["profile"],
              issuer: "https://identity.example.com",
              postLogoutRedirectUri: `${publicOrigin}/signed-out`,
              redirectUri: `${publicOrigin}/api/v1/auth/platform/oidc/callback`,
              tenantRedirectUri: `${publicOrigin}/api/v1/auth/federated/oidc/callback`,
              useUserInfo: true,
            },
            description: "Corporate workforce federation",
            displayName: "Workforce OIDC",
            key: "workforce_oidc",
            kind: "oidc",
          },
        ),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it.each([
    {
      invoke: () => phaseTwoApi.listPlatformAuthProviders(),
      label: "list",
      response: () =>
        jsonResponse(
          { items: [providerSummaryFixture()] },
          { "Cache-Control": "no-store" },
          201,
        ),
      status: 201,
    },
    {
      invoke: () => phaseTwoApi.getPlatformAuthProvider(providerId),
      label: "detail",
      response: () =>
        jsonResponse(
          oidcProviderFixture(),
          { "Cache-Control": "no-store", ETag: '"v7"' },
          202,
        ),
      status: 202,
    },
    {
      invoke: () =>
        phaseTwoApi.updatePlatformAuthProvider(
          "csrf-memory-only",
          providerId,
          { etag: '"v7"', value: oidcProviderFixture() },
          "Update provider label",
          {
            description: "Corporate workforce federation",
            displayName: "Workforce OIDC",
            expectedVersion: 7,
            key: "workforce_oidc",
          },
        ),
      label: "update",
      response: () =>
        jsonResponse(
          oidcProviderFixture({ version: 8 }),
          { "Cache-Control": "no-store", ETag: '"v8"' },
          201,
        ),
      status: 201,
    },
    {
      invoke: () =>
        phaseTwoApi.createPlatformAuthProvider(
          "csrf-memory-only",
          "0198c97d-cf4f-7000-8000-000000000099",
          "Stage the provider definition",
          {
            configuration: {
              allowRefreshToken: false,
              clientId: "periapsis-platform",
              extraScopes: ["profile"],
              issuer: "https://identity.example.com",
              postLogoutRedirectUri: `${publicOrigin}/signed-out`,
              redirectUri: `${publicOrigin}/api/v1/auth/platform/oidc/callback`,
              tenantRedirectUri: `${publicOrigin}/api/v1/auth/federated/oidc/callback`,
              useUserInfo: true,
            },
            description: "Corporate workforce federation",
            displayName: "Workforce OIDC",
            key: "workforce_oidc",
            kind: "oidc",
          },
        ),
      label: "create",
      response: () =>
        jsonResponse(
          oidcProviderFixture(),
          {
            "Cache-Control": "no-store",
            ETag: '"v7"',
            Location: `/api/v1/platform/auth-providers/${providerId}`,
          },
          202,
        ),
      status: 202,
    },
  ])(
    "rejects an unexpected $status success status from the $label endpoint",
    async ({ invoke, label, response, status }) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation(async () => response()),
      );

      await expect(invoke()).rejects.toMatchObject({
        message: `The API returned an unexpected success status for the platform identity-provider ${label} endpoint.`,
        status,
      });
    },
  );

  it.each([
    {
      invoke: () => phaseTwoApi.listPlatformAuthProviders(),
      label: "null list",
      response: () => jsonResponse(null, { "Cache-Control": "no-store" }, 200),
    },
    {
      invoke: () => phaseTwoApi.getPlatformAuthProvider(providerId),
      label: "null detail",
      response: () =>
        jsonResponse(null, { "Cache-Control": "no-store", ETag: '"v7"' }, 200),
    },
    {
      invoke: () => phaseTwoApi.getPlatformAuthProvider(providerId),
      label: "null nested OIDC configuration",
      response: () =>
        jsonResponse(
          { ...oidcProviderFixture(), configuration: null },
          { "Cache-Control": "no-store", ETag: '"v7"' },
          200,
        ),
    },
    {
      invoke: () => phaseTwoApi.getPlatformAuthProvider(providerId),
      label: "null nested SAML configuration",
      response: () =>
        jsonResponse(
          { ...samlProviderFixture("required"), configuration: null },
          { "Cache-Control": "no-store", ETag: '"v7"' },
          200,
        ),
    },
  ])("normalizes a $label projection failure", async ({ invoke, response }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => response()),
    );

    await expect(invoke()).rejects.toMatchObject({
      code: "tenant_projection_mismatch",
    });
  });

  it("refuses an If-Match/body version mismatch before issuing a mutation", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.updatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v6"', value: oidcProviderFixture() },
        "Update provider label",
        {
          description: "Corporate workforce federation",
          displayName: "Workforce OIDC",
          expectedVersion: 7,
          key: "workforce_oidc",
        },
      ),
    ).rejects.toMatchObject({
      message:
        "The platform identity-provider version does not match its strong validator.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts only the requested provider metadata while preserving operational state", async () => {
    const current = oidcProviderFixture();
    const input = {
      description: "Renamed corporate workforce federation",
      displayName: "Renamed workforce OIDC",
      expectedVersion: 7,
      key: "workforce_oidc",
    };
    const updated = {
      ...current,
      description: input.description,
      displayName: input.displayName,
      key: current.key,
      updatedAt: "2026-08-27T10:06:00Z",
      version: 8,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(updated, {
          "Cache-Control": "no-store",
          ETag: '"v8"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.updatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: current },
        "Rename the provider metadata",
        input,
      ),
    ).resolves.toEqual({ etag: '"v8"', value: updated });
  });

  it("rejects an attempt to replace the immutable provider key before fetch", async () => {
    const current = oidcProviderFixture();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.updatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: current },
        "Attempt to change the provider locator",
        {
          description: current.description,
          displayName: current.displayName,
          expectedVersion: current.version,
          key: "renamed_workforce_oidc",
        },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [
      "accepted metadata",
      (updated: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...updated,
        displayName: "Workforce OIDC",
      }),
    ],
    [
      "OIDC configuration",
      (updated: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...updated,
        configuration: {
          ...updated.configuration,
          clientId: "poisoned-client",
        },
      }),
    ],
    [
      "stable key",
      (updated: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...updated,
        key: "poisoned_workforce_oidc",
      }),
    ],
    [
      "security revision",
      (updated: Extract<PlatformAuthProviderView, { kind: "oidc" }>) => ({
        ...updated,
        securityRevision: updated.securityRevision + 1,
      }),
    ],
  ] as const)(
    "rejects a metadata update projection that changes %s",
    async (_label, poison) => {
      const current = oidcProviderFixture();
      const input = {
        description: "Renamed corporate workforce federation",
        displayName: "Renamed workforce OIDC",
        expectedVersion: 7,
        key: "workforce_oidc",
      };
      const updated = {
        ...current,
        description: input.description,
        displayName: input.displayName,
        key: current.key,
        updatedAt: "2026-08-27T10:06:00Z",
        version: 8,
      };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(poison(updated), {
            "Cache-Control": "no-store",
            ETag: '"v8"',
          }),
        ),
      );

      await expect(
        phaseTwoApi.updatePlatformAuthProvider(
          "csrf-memory-only",
          providerId,
          { etag: '"v7"', value: current },
          "Rename the provider metadata",
          input,
        ),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("rejects audit reasons that cannot be represented by the HTTP contract before fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await Promise.all(
      ["Motivazione approvata — SSO", "one,two"].map(async (auditReason) => {
        await expect(
          phaseTwoApi.updatePlatformAuthProvider(
            "csrf-memory-only",
            providerId,
            { etag: '"v7"', value: oidcProviderFixture() },
            auditReason,
            {
              description: "Corporate workforce federation",
              displayName: "Workforce OIDC",
              expectedVersion: 7,
              key: "workforce_oidc",
            },
          ),
        ).rejects.toMatchObject({
          message:
            "The platform identity-provider audit reason is not safe for an HTTP header.",
        });
      }),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("replaces a client secret with exact strong preconditions and no readback", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: { "Cache-Control": "no-store", ETag: '"v8"' },
          status: 204,
        });
      }),
    );

    await expect(
      phaseTwoApi.replacePlatformOidcAuthProviderClientSecret(
        "csrf-memory-only",
        providerId,
        '"v7"',
        "Rotate the upstream credential",
        { clientSecret: "write-only-secret", expectedVersion: 7 },
      ),
    ).resolves.toBe('"v8"');
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("PUT");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Rotate the upstream credential",
    );
    expect(await request.json()).toEqual({
      clientSecret: "write-only-secret",
      expectedVersion: 7,
    });
  });

  it("rejects a payload-bearing 200 from the write-only secret endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { clientSecret: "must-never-be-accepted" },
            { "Cache-Control": "no-store", ETag: '"v8"' },
            200,
          ),
        ),
    );

    await expect(
      phaseTwoApi.replacePlatformOidcAuthProviderClientSecret(
        "csrf-memory-only",
        providerId,
        '"v7"',
        "Rotate the upstream credential",
        { clientSecret: "write-only-secret", expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({
      message:
        "The API returned payload data from the write-only platform identity-provider secret endpoint.",
      status: 200,
    });
  });

  it("rejects response metadata that claims a body on a 204 secret mutation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(null, {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            ETag: '"v8"',
          },
          status: 204,
        }),
      ),
    );

    await expect(
      phaseTwoApi.replacePlatformOidcAuthProviderClientSecret(
        "csrf-memory-only",
        providerId,
        '"v7"',
        "Rotate the upstream credential",
        { clientSecret: "write-only-secret", expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({
      message:
        "The API returned payload data from the write-only platform identity-provider secret endpoint.",
      status: 204,
    });
  });

  it("rejects a payload-bearing 200 from the bodyless archive endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { auditReason: "must-not-be-reflected" },
            { "Cache-Control": "no-store", ETag: '"v8"' },
            200,
          ),
        ),
    );

    await expect(
      phaseTwoApi.archivePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        '"v7"',
        "Archive the retired provider",
        { expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({
      message:
        "The API returned payload data from the bodyless platform identity-provider archive endpoint.",
      status: 200,
    });
  });

  it("preserves Problem Details from failed bodyless archive and secret mutations", async () => {
    const problem = {
      code: "precondition_failed",
      detail: "The provider changed before this operation.",
      requestId: providerId,
      status: 412,
      title: "Precondition failed",
      type: "https://docs.example.test/problems/precondition-failed",
    };
    const mutations = [
      () =>
        phaseTwoApi.archivePlatformAuthProvider(
          "csrf-memory-only",
          providerId,
          '"v7"',
          "Archive the retired provider",
          { expectedVersion: 7 },
        ),
      () =>
        phaseTwoApi.replacePlatformOidcAuthProviderClientSecret(
          "csrf-memory-only",
          providerId,
          '"v7"',
          "Rotate the upstream credential",
          { clientSecret: "write-only-secret", expectedVersion: 7 },
        ),
    ];

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation(async () =>
          jsonResponse(problem, { "Cache-Control": "no-store" }, 412),
        ),
    );
    await Promise.all(
      mutations.map(async (mutate) => {
        await expect(mutate()).rejects.toMatchObject({
          code: "precondition_failed",
          message: "The provider changed before this operation.",
          status: 412,
        });
      }),
    );
  });

  it.each([
    [
      "tenant execution is disabled",
      { ...providerSummaryFixture(), platformLoginEnabled: true },
    ],
    [
      "the OIDC secret is absent",
      {
        ...providerSummaryFixture(),
        enabled: true,
        platformLoginEnabled: true,
      },
    ],
    [
      "the provider is SAML",
      {
        ...providerSummaryFixture(),
        kind: "saml",
        platformLoginEnabled: true,
      },
    ],
    [
      "the provider is SAML but activation is advertised",
      {
        ...providerSummaryFixture(),
        kind: "saml",
        platformLoginActivationAvailable: true,
      },
    ],
    [
      "direct login is already active but activation is advertised",
      {
        ...providerSummaryFixture(),
        enabled: true,
        platformLoginActivationAvailable: true,
        platformLoginEnabled: true,
        secretPresent: true,
      },
    ],
  ])("rejects direct platform login when %s", async (_label, provider) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [provider] }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(phaseTwoApi.listPlatformAuthProviders()).rejects.toMatchObject(
      { code: "tenant_projection_mismatch" },
    );
  });

  it("rejects bodyless mutation errors that omit the required no-store policy", async () => {
    const problem = {
      code: "precondition_failed",
      detail: "The provider changed before this operation.",
      requestId: providerId,
      status: 412,
      title: "Precondition failed",
      type: "https://docs.example.test/problems/precondition-failed",
    };
    const mutations = [
      () =>
        phaseTwoApi.archivePlatformAuthProvider(
          "csrf-memory-only",
          providerId,
          '"v7"',
          "Archive the retired provider",
          { expectedVersion: 7 },
        ),
      () =>
        phaseTwoApi.replacePlatformOidcAuthProviderClientSecret(
          "csrf-memory-only",
          providerId,
          '"v7"',
          "Rotate the upstream credential",
          { clientSecret: "write-only-secret", expectedVersion: 7 },
        ),
    ];

    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => jsonResponse(problem, {}, 412)),
    );
    await Promise.all(
      mutations.map(async (mutate) => {
        await expect(mutate()).rejects.toMatchObject({
          message:
            "The API did not mark the platform identity-provider response as no-store.",
          status: 412,
        });
      }),
    );
  });

  it("rejects unexpected secret readback fields even on a successful response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            ...oidcProviderFixture(),
            configuration: {
              ...oidcProviderFixture().configuration,
              clientSecret: "must-never-be-returned",
            },
          },
          { "Cache-Control": "no-store", ETag: '"v7"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).rejects.toMatchObject({
      code: "tenant_projection_mismatch",
    });
  });

  it("accepts the wider SAML detail encryption state without widening create", async () => {
    const provider = samlProviderFixture("required");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(provider, {
          "Cache-Control": "no-store",
          ETag: '"v7"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).resolves.toMatchObject({
      etag: '"v7"',
      value: {
        configuration: { encryptionPolicy: "required" },
        kind: "saml",
      },
    });
  });

  it("rejects a platform SAML projection containing XML 1.0 noncharacters", async () => {
    const provider = samlProviderFixture("required");
    provider.configuration.expectedEntityId += "\ufffe";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(provider, {
          "Cache-Control": "no-store",
          ETag: '"v7"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each([
    {
      label: "refresh without offline_access",
      mutate: (
        configuration: Extract<
          PlatformAuthProviderView,
          { kind: "oidc" }
        >["configuration"],
      ) => {
        configuration.allowRefreshToken = true;
      },
    },
    {
      label: "Unicode whitespace in clientId",
      mutate: (
        configuration: Extract<
          PlatformAuthProviderView,
          { kind: "oidc" }
        >["configuration"],
      ) => {
        configuration.clientId = "client\u00a0id";
      },
    },
  ])("rejects OIDC projection with $label", async ({ mutate }) => {
    const provider = oidcProviderFixture();
    mutate(provider.configuration);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(provider, {
          "Cache-Control": "no-store",
          ETag: '"v7"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each(["unknown", null])(
    "rejects the SAML subject-source discriminant %s",
    async (subjectSource) => {
      const provider = structuredClone(samlProviderFixture("required")) as {
        configuration: { subjectSource: unknown };
      };
      provider.configuration.subjectSource = subjectSource;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(provider, {
            "Cache-Control": "no-store",
            ETag: '"v7"',
          }),
        ),
      );

      await expect(
        phaseTwoApi.getPlatformAuthProvider(providerId),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it.each([
    ["missing", undefined],
    ["the wrong type", "false"],
  ])(
    "rejects a detail projection with %s direct-login activation availability",
    async (_label, availability) => {
      const provider = {
        ...oidcProviderFixture(),
      } as Record<string, unknown>;
      if (availability === undefined) {
        delete provider.platformLoginActivationAvailable;
      } else {
        provider.platformLoginActivationAvailable = availability;
      }
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(provider, {
            "Cache-Control": "no-store",
            ETag: '"v7"',
          }),
        ),
      );

      await expect(
        phaseTwoApi.getPlatformAuthProvider(providerId),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("rejects a successful list projection that exceeds the contract page bound", async () => {
    const items = Array.from({ length: 101 }, (_, index) => ({
      ...providerSummaryFixture(),
      id: `0198c97d-cf4f-7000-8000-${String(index).padStart(12, "0")}`,
    }));
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(phaseTwoApi.listPlatformAuthProviders()).rejects.toMatchObject(
      {
        code: "tenant_projection_mismatch",
      },
    );
  });

  it("accepts a detail projection with an ASCII issuer at exactly 2048 UTF-8 bytes", async () => {
    const fixture = oidcProviderFixture();
    const issuer = asciiIssuerWithByteLength(2048);
    const provider = {
      ...fixture,
      configuration: { ...fixture.configuration, issuer },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(provider, {
          "Cache-Control": "no-store",
          ETag: '"v7"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).resolves.toMatchObject({
      value: { configuration: { issuer } },
    });
  });

  it.each([
    ["a non-canonical issuer", { issuer: " https://identity.example.com" }],
    ["a malformed URI escape", { issuer: "https://identity.example.com/%zz" }],
    [
      "an ASCII issuer above 2048 bytes",
      { issuer: asciiIssuerWithByteLength(2049) },
    ],
    [
      "a multibyte issuer above 2048 bytes",
      { issuer: multibyteIssuerOver2048Bytes() },
    ],
    ["an oversized UTF-8 client ID", { clientId: "é".repeat(257) }],
    ["invalid Unicode text", { clientId: "broken-\ud800-client" }],
    ["a malformed OAuth scope", { extraScopes: ["profile scope"] }],
  ])("rejects a detail projection with %s", async (_label, patch) => {
    const provider = oidcProviderFixture();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            ...provider,
            configuration: { ...provider.configuration, ...patch },
          },
          { "Cache-Control": "no-store", ETag: '"v7"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProvider(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each([
    [
      "a callback on another origin",
      {
        redirectUri:
          "https://attacker.example/api/v1/auth/platform/oidc/callback",
      },
    ],
    [
      "a non-canonical callback path",
      { redirectUri: `${publicOrigin}/api/v1/auth/oidc/callback` },
    ],
    [
      "a tenant callback on another origin",
      {
        tenantRedirectUri:
          "https://attacker.example/api/v1/auth/federated/oidc/callback",
      },
    ],
    [
      "a non-canonical tenant callback path",
      {
        tenantRedirectUri: `${publicOrigin}/api/v1/auth/platform/oidc/callback`,
      },
    ],
    [
      "a post-logout URI on another origin",
      { postLogoutRedirectUri: "https://attacker.example/signed-out" },
    ],
    [
      "a non-canonical post-logout path",
      { postLogoutRedirectUri: `${publicOrigin}/logout/callback` },
    ],
  ])(
    "rejects OIDC deployment endpoint projection with %s",
    async (_label, patch) => {
      const provider = oidcProviderFixture();
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            {
              ...provider,
              configuration: { ...provider.configuration, ...patch },
            },
            { "Cache-Control": "no-store", ETag: '"v7"' },
          ),
        ),
      );

      await expect(
        phaseTwoApi.getPlatformAuthProvider(providerId),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("activates OIDC tenant execution with the exact version, account mode, audit reason, and new strong ETag", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v7"',
      value: oidcProviderFixture({
        activationAvailable: true,
        secretPresent: true,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          oidcProviderFixture({
            accountMode: "existing_identity",
            enabled: true,
            planRevision: 2,
            platformLoginActivationAvailable: true,
            secretPresent: true,
            securityRevision: 2,
            version: 8,
          }),
          { "Cache-Control": "no-store", ETag: '"v8"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.activatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        current,
        "Enable tenant-bound workforce admission",
        { accountMode: "existing_identity", expectedVersion: 7 },
      ),
    ).resolves.toMatchObject({
      etag: '"v8"',
      value: {
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable: true,
        platformLoginEnabled: false,
        version: 8,
      },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/activate`,
    );
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Enable tenant-bound workforce admission",
    );
    expect(await request.json()).toEqual({
      accountMode: "existing_identity",
      expectedVersion: 7,
    });
  });

  it("deactivates OIDC tenant execution without exposing a direct platform-login transition", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v8"',
      value: oidcProviderFixture({
        accountMode: "create",
        enabled: true,
        secretPresent: true,
        version: 8,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          oidcProviderFixture({
            activationAvailable: true,
            planRevision: 2,
            secretPresent: true,
            securityRevision: 2,
            version: 9,
          }),
          { "Cache-Control": "no-store", ETag: '"v9"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.deactivatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        current,
        "Close tenant-bound workforce admission",
        { expectedVersion: 8 },
      ),
    ).resolves.toMatchObject({
      etag: '"v9"',
      value: {
        accountMode: "disabled",
        enabled: false,
        platformLoginEnabled: false,
        version: 9,
      },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/deactivate`,
    );
    expect(request.headers.get("If-Match")).toBe('"v8"');
    expect(await request.json()).toEqual({ expectedVersion: 8 });
  });

  it("activates direct OIDC platform login with an exact body and preserves tenant execution", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v8"',
      value: oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable: true,
        secretPresent: true,
        version: 8,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          oidcProviderFixture({
            accountMode: "existing_identity",
            enabled: true,
            platformLoginActivationAvailable: false,
            platformLoginEnabled: true,
            secretPresent: true,
            version: 9,
          }),
          { "Cache-Control": "no-store", ETag: '"v9"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.activatePlatformOidcDirectLogin(
        "csrf-memory-only",
        providerId,
        current,
        "Enable pre-linked workforce platform login",
        { expectedVersion: 8 },
      ),
    ).resolves.toMatchObject({
      etag: '"v9"',
      value: {
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable: false,
        platformLoginEnabled: true,
        version: 9,
      },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/direct-login/activate`,
    );
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("If-Match")).toBe('"v8"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Enable pre-linked workforce platform login",
    );
    expect(await request.json()).toEqual({ expectedVersion: 8 });
  });

  it.each([
    ["activation-ready", true, false],
    ["active", false, true],
  ])(
    "rejects an OIDC projection that exposes %s direct login while UserInfo is enabled",
    async (_label, platformLoginActivationAvailable, platformLoginEnabled) => {
      const provider = oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable,
        platformLoginEnabled,
        secretPresent: true,
      });
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            {
              ...provider,
              configuration: {
                ...provider.configuration,
                useUserInfo: true,
              },
            },
            { "Cache-Control": "no-store", ETag: '"v7"' },
          ),
        ),
      );

      await expect(
        phaseTwoApi.getPlatformAuthProvider(providerId),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("activates ready SAML tenant execution without treating the provider kind as OIDC-only", async () => {
    const currentValue = {
      ...samlProviderFixture("disabled"),
      activationAvailable: true,
      version: 7,
    };
    const activated = {
      ...currentValue,
      accountMode: "existing_identity" as const,
      activationAvailable: false,
      enabled: true,
      planRevision: 2,
      platformLoginActivationAvailable: true,
      securityRevision: 2,
      updatedAt: "2026-08-27T10:06:00Z",
      version: 8,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(activated, {
          "Cache-Control": "no-store",
          ETag: '"v8"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.activatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: currentValue },
        "Enable SAML tenant execution",
        { accountMode: "existing_identity", expectedVersion: 7 },
      ),
    ).resolves.toMatchObject({
      etag: '"v8"',
      value: { enabled: true, kind: "saml", version: 8 },
    });
  });

  it("accepts a ready SAML provider through the legacy-named direct-login client operation", async () => {
    const currentValue = {
      ...samlProviderFixture("disabled"),
      accountMode: "existing_identity" as const,
      enabled: true,
      platformLoginActivationAvailable: true,
      version: 8,
    };
    const activated = {
      ...currentValue,
      platformLoginActivationAvailable: false,
      platformLoginEnabled: true,
      updatedAt: "2026-08-27T10:06:00Z",
      version: 9,
    };
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(activated, {
          "Cache-Control": "no-store",
          ETag: '"v9"',
        });
      }),
    );

    await expect(
      phaseTwoApi.activatePlatformOidcDirectLogin(
        "csrf-memory-only",
        providerId,
        { etag: '"v8"', value: currentValue },
        "Enable pre-linked SAML workforce login",
        { expectedVersion: 8 },
      ),
    ).resolves.toMatchObject({
      etag: '"v9"',
      value: {
        kind: "saml",
        platformLoginEnabled: true,
        version: 9,
      },
    });
    expect(new URL(requests[0]!.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/direct-login/activate`,
    );
  });

  it("deactivates direct OIDC platform login without changing tenant execution", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v9"',
      value: oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        platformLoginEnabled: true,
        secretPresent: true,
        version: 9,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          oidcProviderFixture({
            accountMode: "existing_identity",
            enabled: true,
            platformLoginActivationAvailable: true,
            platformLoginEnabled: false,
            secretPresent: true,
            version: 10,
          }),
          { "Cache-Control": "no-store", ETag: '"v10"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.deactivatePlatformOidcDirectLogin(
        "csrf-memory-only",
        providerId,
        current,
        "Disable direct workforce platform login",
        { expectedVersion: 9 },
      ),
    ).resolves.toMatchObject({
      etag: '"v10"',
      value: {
        enabled: true,
        platformLoginActivationAvailable: true,
        platformLoginEnabled: false,
        version: 10,
      },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/direct-login/deactivate`,
    );
    expect(request.headers.get("If-Match")).toBe('"v9"');
    expect(await request.json()).toEqual({ expectedVersion: 9 });
  });

  it("fails closed before transport when direct-login activation is not currently available", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const current = {
      etag: '"v8"',
      value: oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable: false,
        secretPresent: true,
        version: 8,
      }),
    };

    await expect(
      phaseTwoApi.activatePlatformOidcDirectLogin(
        "csrf-memory-only",
        providerId,
        current,
        "Attempt unavailable direct login activation",
        { expectedVersion: 8 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a direct-login projection that mutates tenant security revisions", async () => {
    const current = {
      etag: '"v8"',
      value: oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        platformLoginActivationAvailable: true,
        secretPresent: true,
        version: 8,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          oidcProviderFixture({
            accountMode: "existing_identity",
            enabled: true,
            platformLoginEnabled: true,
            secretPresent: true,
            securityRevision: 2,
            version: 9,
          }),
          { "Cache-Control": "no-store", ETag: '"v9"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.activatePlatformOidcDirectLogin(
        "csrf-memory-only",
        providerId,
        current,
        "Enable pre-linked workforce platform login",
        { expectedVersion: 8 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each([
    ["provider metadata", { displayName: "Injected provider" }],
    ["OIDC configuration", { clientId: "injected-client" }],
    ["security revision", { securityRevision: 1 }],
    ["plan revision", { planRevision: 1 }],
  ])(
    "rejects an activation projection that changes immutable %s",
    async (_label, patch) => {
      const current = {
        etag: '"v7"',
        value: oidcProviderFixture({
          activationAvailable: true,
          secretPresent: true,
        }),
      };
      const activated = oidcProviderFixture({
        accountMode: "existing_identity",
        enabled: true,
        planRevision: 2,
        secretPresent: true,
        securityRevision: 2,
        version: 8,
      });
      const response =
        "clientId" in patch
          ? {
              ...activated,
              configuration: {
                ...activated.configuration,
                clientId: patch.clientId,
              },
            }
          : { ...activated, ...patch };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(response, {
            "Cache-Control": "no-store",
            ETag: '"v8"',
          }),
        ),
      );

      await expect(
        phaseTwoApi.activatePlatformAuthProvider(
          "csrf-memory-only",
          providerId,
          current,
          "Enable tenant-bound workforce admission",
          { accountMode: "existing_identity", expectedVersion: 7 },
        ),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("fails closed before transport when a SAML or OIDC projection is not activation-ready", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.activatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: samlProviderFixture("disabled") },
        "Attempt unsupported activation",
        { accountMode: "existing_identity", expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    await expect(
      phaseTwoApi.activatePlatformAuthProvider(
        "csrf-memory-only",
        providerId,
        { etag: '"v7"', value: oidcProviderFixture() },
        "Attempt unready activation",
        { accountMode: "existing_identity", expectedVersion: 7 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [
      "an ACS URL on another origin",
      { acsUrl: "https://attacker.example/api/v1/auth/platform/saml/acs" },
    ],
    [
      "a non-canonical ACS path",
      { acsUrl: `${publicOrigin}/api/v1/auth/saml/acs` },
    ],
    [
      "an SP entity ID on another origin",
      {
        spEntityId:
          "https://attacker.example/api/v1/auth/platform/saml/workforce_saml/metadata",
      },
    ],
    [
      "a non-canonical SP metadata path",
      { spEntityId: `${publicOrigin}/saml/sp` },
    ],
    [
      "an IdP entity ID equal to the derived SP entity ID",
      {
        expectedEntityId: `${publicOrigin}/api/v1/auth/platform/saml/workforce_saml/metadata`,
      },
    ],
  ])(
    "rejects SAML deployment endpoint projection with %s",
    async (_label, patch) => {
      const provider = samlProviderFixture("required");
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            {
              ...provider,
              configuration: { ...provider.configuration, ...patch },
            },
            { "Cache-Control": "no-store", ETag: '"v7"' },
          ),
        ),
      );

      await expect(
        phaseTwoApi.getPlatformAuthProvider(providerId),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );
});

function platformOidcCreateInput(): Extract<
  PlatformAuthProviderCreateInput,
  { kind: "oidc" }
> {
  return {
    configuration: {
      allowRefreshToken: false,
      clientId: "periapsis-platform",
      extraScopes: ["profile"],
      issuer: "https://identity.example.com",
      postLogoutRedirectUri: `${publicOrigin}/signed-out`,
      redirectUri: `${publicOrigin}/api/v1/auth/platform/oidc/callback`,
      tenantRedirectUri: `${publicOrigin}/api/v1/auth/federated/oidc/callback`,
      useUserInfo: true,
    },
    description: "Corporate workforce federation",
    displayName: "Workforce OIDC",
    key: "workforce_oidc",
    kind: "oidc",
  };
}

function platformSamlCreateInput(): Extract<
  PlatformAuthProviderCreateInput,
  { kind: "saml" }
> {
  return {
    configuration: {
      acsUrl: `${publicOrigin}/api/v1/auth/platform/saml/acs`,
      clockSkewNanoseconds: 120_000_000_000,
      encryptionPolicy: "disabled",
      expectedEntityId: "https://idp.example.com/entity",
      maxAuthenticationAgeNanoseconds: 28_800_000_000_000,
      redirectSignatureAlgorithm:
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      requestedAuthnContexts: [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      signaturePolicy: "signed_assertion",
      spEntityId: `${publicOrigin}/api/v1/auth/platform/saml/workforce_saml/metadata`,
      subjectSource: "persistent_nameid",
    },
    description: "Corporate workforce federation",
    displayName: "Workforce SAML",
    key: "workforce_saml",
    kind: "saml",
  };
}

function jsonResponse(
  body: unknown,
  headers: Record<string, string> = {},
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", ...headers },
    status,
  });
}

function providerSummaryFixture() {
  const provider = oidcProviderFixture();
  return {
    activationAvailable: provider.activationAvailable,
    archivedAt: provider.archivedAt,
    configured: provider.configured,
    createdAt: provider.createdAt,
    description: provider.description,
    displayName: provider.displayName,
    enabled: false as const,
    id: provider.id,
    key: provider.key,
    kind: provider.kind,
    platformLoginActivationAvailable: provider.platformLoginActivationAvailable,
    platformLoginEnabled: false as const,
    secretPresent: provider.secretPresent,
    updatedAt: provider.updatedAt,
    version: provider.version,
  };
}

function oidcProviderFixture(
  overrides: Partial<Extract<PlatformAuthProviderView, { kind: "oidc" }>> = {},
): Extract<PlatformAuthProviderView, { kind: "oidc" }> {
  return {
    accountMode: overrides.accountMode ?? "disabled",
    activationAvailable: overrides.activationAvailable ?? false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      allowRefreshToken: false,
      clientId: "periapsis-platform",
      clientSecretPresent: overrides.secretPresent ?? false,
      clientSecretRevision: overrides.secretPresent ? 2 : 1,
      discoveryRevision: 1,
      extraScopes: ["profile"],
      issuer: "https://identity.example.com",
      jwksRevision: 1,
      postLogoutRedirectUri: "https://soc.example.com/signed-out",
      redirectUri: "https://soc.example.com/api/v1/auth/platform/oidc/callback",
      tenantRedirectUri:
        "https://soc.example.com/api/v1/auth/federated/oidc/callback",
      useUserInfo: false,
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-08-27T10:00:00Z",
    description: "Corporate workforce federation",
    displayName: "Workforce OIDC",
    enabled: overrides.enabled ?? false,
    id: providerId,
    key: overrides.key ?? "workforce_oidc",
    kind: "oidc",
    planRevision: overrides.planRevision ?? 1,
    platformLoginActivationAvailable:
      overrides.platformLoginActivationAvailable ?? false,
    platformLoginEnabled: overrides.platformLoginEnabled ?? false,
    secretPresent: overrides.secretPresent ?? false,
    securityRevision: overrides.securityRevision ?? 1,
    updatedAt: "2026-08-27T10:05:00Z",
    version: overrides.version ?? 7,
  };
}

function samlProviderFixture(
  encryptionPolicy: "disabled" | "optional" | "required",
): Extract<PlatformAuthProviderView, { kind: "saml" }> {
  return {
    accountMode: "disabled",
    activationAvailable: false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      acsUrl: "https://soc.example.com/api/v1/auth/platform/saml/acs",
      clockSkewNanoseconds: 120_000_000_000,
      encryptionPolicy,
      expectedEntityId: "https://idp.example.com/entity",
      maxAuthenticationAgeNanoseconds: 28_800_000_000_000,
      metadataRevision: 1,
      redirectSignatureAlgorithm:
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      requestedAuthnContexts: [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      signaturePolicy: "both",
      spEntityId:
        "https://soc.example.com/api/v1/auth/platform/saml/workforce_saml/metadata",
      spKeyPresent: true,
      spKeyRevision: 2,
      subjectSource: "persistent_nameid",
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-08-27T10:00:00Z",
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
    updatedAt: "2026-08-27T10:05:00Z",
    version: 7,
  };
}
