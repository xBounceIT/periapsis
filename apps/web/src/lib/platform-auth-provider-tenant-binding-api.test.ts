import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import {
  PhaseTwoApiError,
  type PlatformAuthProviderTenantBindingView,
} from "./phase-two-types";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const tenantId = "0198c97d-cf4f-7000-8000-000000000090";
const publicOrigin = "https://soc.example.com";

beforeEach(() => {
  vi.stubGlobal("location", { origin: publicOrigin });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi platform provider tenant-binding transport", () => {
  it("lists a bounded tenant-admission page with no-store transport", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { items: [bindingFixture()] },
          { "Cache-Control": "no-store" },
        );
      }),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId, {
        includeArchived: true,
      }),
    ).resolves.toEqual({ items: [bindingFixture()] });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("GET");
    expect(request.cache).toBe("no-store");
    expect(request.url).toContain(
      `/api/v1/platform/auth-providers/${providerId}/tenant-bindings?limit=50&includeArchived=true`,
    );
  });

  it("rejects an augmented Cache-Control value outside the exact contract", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { items: [bindingFixture()] },
            { "Cache-Control": "private, no-store" },
          ),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).rejects.toThrow("did not mark");
  });

  it("accepts only strictly ordered pages whose cursor is the final binding", async () => {
    const laterBinding = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      tenant: {
        ...bindingFixture().tenant,
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            items: [bindingFixture(), laterBinding],
            nextCursor: laterBinding.id,
          },
          { "Cache-Control": "no-store" },
        ),
      ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId, {
        includeArchived: true,
      }),
    ).resolves.toMatchObject({
      items: [{ id: bindingId }, { id: laterBinding.id }],
      nextCursor: laterBinding.id,
    });
  });

  it.each([
    ["equal to", bindingId],
    ["older than", "0198c97d-cf4f-7000-8000-000000000091"],
  ])(
    "rejects a continuation item %s the requested cursor",
    async (_label, after) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              { items: [bindingFixture()] },
              { "Cache-Control": "no-store" },
            ),
          ),
      );

      await expect(
        phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId, {
          after,
          includeArchived: true,
        }),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it.each([
    [
      "descending binding IDs",
      () => {
        const laterBinding = bindingFixture({
          id: "0198c97d-cf4f-7000-8000-000000000091",
          tenant: {
            ...bindingFixture().tenant,
            id: "0198c97d-cf4f-7000-8000-000000000092",
            name: "Beta SOC",
            slug: "beta",
          },
        });
        return { items: [laterBinding, bindingFixture()] };
      },
    ],
    [
      "equal binding IDs",
      () => ({
        items: [
          bindingFixture(),
          bindingFixture({
            tenant: {
              ...bindingFixture().tenant,
              id: "0198c97d-cf4f-7000-8000-000000000092",
              name: "Beta SOC",
              slug: "beta",
            },
          }),
        ],
      }),
    ],
    [
      "duplicate tenants",
      () => ({
        items: [
          bindingFixture(),
          bindingFixture({
            id: "0198c97d-cf4f-7000-8000-000000000091",
            loginKey: "workforce_beta",
          }),
        ],
      }),
    ],
    [
      "cursor unrelated to the final binding",
      () => ({
        items: [bindingFixture()],
        nextCursor: "0198c97d-cf4f-7000-8000-000000000091",
      }),
    ],
    ["cursor on an empty page", () => ({ items: [], nextCursor: bindingId })],
  ])("rejects a page with %s", async (_label, page) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(page(), { "Cache-Control": "no-store" }),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId, {
        includeArchived: true,
      }),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("accepts exactly 100 bindings and rejects 101 otherwise-valid bindings", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    fetch.mockResolvedValueOnce(
      jsonResponse(
        { items: bindingPageItems(100) },
        { "Cache-Control": "no-store" },
      ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).resolves.toMatchObject({ items: { length: 100 } });

    fetch.mockResolvedValueOnce(
      jsonResponse(
        { items: bindingPageItems(101) },
        { "Cache-Control": "no-store" },
      ),
    );
    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("creates a disabled binding with idempotency, audit, Location, and ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          bindingFixture({
            updatedAt: "2026-08-28T10:00:00Z",
            version: 1,
          }),
          {
            "Cache-Control": "no-store",
            ETag: '"v1-t11"',
            Location: bindingLocation(),
          },
          201,
        );
      }),
    );
    const input = {
      loginKey: "workforce_acme",
      profilePriority: 50,
      tenantId,
    };

    await expect(
      phaseTwoApi.createPlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        "0198c97d-cf4f-7000-8000-000000000099",
        "Reserve an explicit tenant binding",
        input,
      ),
    ).resolves.toMatchObject({
      etag: '"v1-t11"',
      location: bindingLocation(),
      value: { enabled: false, id: bindingId, providerId },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Reserve an explicit tenant binding",
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    const body = await request.json();
    expect(body).toEqual(input);
    expect(body).not.toHaveProperty("enabled");
  });

  it.each<readonly [string, Partial<PlatformAuthProviderTenantBindingView>]>([
    ["different login key", { loginKey: "workforce_wrong" }],
    ["different profile priority", { profilePriority: 51 }],
    ["archived lifecycle", { archivedAt: "2026-08-28T10:00:00Z" }],
    ["advanced authentication revision", { authRevision: 2 }],
    ["advanced mapping revision", { mappingRevision: 2 }],
    [
      "active lifecycle",
      {
        currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
        enabled: true,
      },
    ],
    ["activation-ready lifecycle", { activationAvailable: true }],
    ["advanced update timestamp", { updatedAt: "2026-08-28T10:00:01Z" }],
  ])(
    "rejects a version-1 create projection with %s",
    async (_label, overrides) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            bindingFixture({
              updatedAt: "2026-08-28T10:00:00Z",
              version: 1,
              ...overrides,
            }),
            {
              "Cache-Control": "no-store",
              ETag: '"v1-t11"',
              Location: bindingLocation(),
            },
            201,
          ),
        ),
      );

      await expect(createBindingTransportFixture()).rejects.toMatchObject({
        code: "tenant_projection_mismatch",
      });
    },
  );

  it("accepts changed metadata and archived lifecycle from a later exact replay", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          bindingFixture({
            archivedAt: "2026-08-28T11:00:00Z",
            loginKey: "workforce_acme_current",
            profilePriority: 75,
            updatedAt: "2026-08-28T11:00:00Z",
            version: 3,
          }),
          {
            "Cache-Control": "no-store",
            ETag: '"v3-t11"',
            Location: bindingLocation(),
          },
          201,
        ),
      ),
    );

    await expect(createBindingTransportFixture()).resolves.toMatchObject({
      etag: '"v3-t11"',
      value: {
        archivedAt: "2026-08-28T11:00:00Z",
        loginKey: "workforce_acme_current",
        profilePriority: 75,
        version: 3,
      },
    });
  });

  it("gets and updates the exact provider-bound resource", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        if (input instanceof Request && input.method === "PATCH") {
          return jsonResponse(
            bindingFixture({
              loginKey: "workforce_acme_next",
              profilePriority: 75,
              version: 8,
            }),
            { "Cache-Control": "no-store", ETag: '"v8-t11"' },
          );
        }
        return jsonResponse(bindingFixture(), {
          "Cache-Control": "no-store",
          ETag: '"v7-t11"',
        });
      }),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).resolves.toMatchObject({ etag: '"v7-t11"', value: { id: bindingId } });
    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).resolves.toMatchObject({
      etag: '"v8-t11"',
      value: { loginKey: "workforce_acme_next", version: 8 },
    });
    expect(requests[0]?.method).toBe("GET");
    expect(requests[1]?.method).toBe("PATCH");
    expect(requests[1]?.headers.get("If-Match")).toBe('"v7-t11"');
    expect(requests[1]?.headers.get("X-Audit-Reason")).toBe(
      "Adjust presentation precedence",
    );
    await expect(requests[1]?.json()).resolves.toEqual({
      expectedTenantVersion: 11,
      expectedVersion: 7,
      loginKey: "workforce_acme_next",
      profilePriority: 75,
    });
  });

  it("activates a ready binding with explicit JIT/no-match policy and a new composite ETag", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v7-t11"',
      value: bindingFixture({ activationAvailable: true }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          bindingFixture({
            authRevision: 2,
            currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
            enabled: true,
            jitMode: "create",
            mappingRevision: 2,
            noMatchPolicy: "provider_access_only",
            version: 8,
          }),
          { "Cache-Control": "no-store", ETag: '"v8-t11"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.activatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        current,
        "Open Acme tenant admission",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          jitMode: "create",
          noMatchPolicy: "provider_access_only",
        },
      ),
    ).resolves.toMatchObject({
      etag: '"v8-t11"',
      value: {
        enabled: true,
        jitMode: "create",
        noMatchPolicy: "provider_access_only",
        version: 8,
      },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}/activate`,
    );
    expect(request.headers.get("If-Match")).toBe('"v7-t11"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Open Acme tenant admission",
    );
    expect(await request.json()).toEqual({
      expectedTenantVersion: 11,
      expectedVersion: 7,
      jitMode: "create",
      noMatchPolicy: "provider_access_only",
    });
  });

  it("deactivates a live binding and requires the returned epoch to be closed", async () => {
    const requests: Request[] = [];
    const current = {
      etag: '"v8-t11"',
      value: bindingFixture({
        currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
        enabled: true,
        jitMode: "create",
        noMatchPolicy: "provider_access_only",
        version: 8,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          bindingFixture({
            activationAvailable: true,
            authRevision: 2,
            version: 9,
          }),
          { "Cache-Control": "no-store", ETag: '"v9-t11"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.deactivatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        current,
        "Close Acme tenant admission",
        { expectedTenantVersion: 11, expectedVersion: 8 },
      ),
    ).resolves.toMatchObject({
      etag: '"v9-t11"',
      value: { currentAccessEpochId: null, enabled: false, version: 9 },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}/deactivate`,
    );
    expect(await request.json()).toEqual({
      expectedTenantVersion: 11,
      expectedVersion: 8,
    });
  });

  it("rejects a deactivation projection that retains live admission policy", async () => {
    const current = {
      etag: '"v8-t11"',
      value: bindingFixture({
        authRevision: 2,
        currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
        enabled: true,
        jitMode: "create",
        mappingRevision: 2,
        noMatchPolicy: "provider_access_only",
        version: 8,
      }),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          bindingFixture({
            authRevision: 3,
            jitMode: "create",
            mappingRevision: 2,
            noMatchPolicy: "provider_access_only",
            version: 9,
          }),
          { "Cache-Control": "no-store", ETag: '"v9-t11"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.deactivatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        current,
        "Close Acme tenant admission",
        { expectedTenantVersion: 11, expectedVersion: 8 },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("fails closed before transport when a binding is not eligible for its lifecycle command", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.activatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Attempt unready admission",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          jitMode: "disabled",
          noMatchPolicy: "deny",
        },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("archives with exact CAS and accepts only a bodyless 204", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: { "Cache-Control": "no-store", ETag: '"v8-t11"' },
          status: 204,
        });
      }),
    );

    await expect(
      phaseTwoApi.archivePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        '"v7-t11"',
        "Retire the unused tenant binding",
        { expectedTenantVersion: 11, expectedVersion: 7 },
      ),
    ).resolves.toBe('"v8-t11"');
    expect(requests[0]?.method).toBe("DELETE");
    expect(requests[0]?.headers.get("If-Match")).toBe('"v7-t11"');
    expect(requests[0]?.headers.get("X-Audit-Reason")).toBe(
      "Retire the unused tenant binding",
    );
    await expect(requests[0]?.json()).resolves.toEqual({
      expectedTenantVersion: 11,
      expectedVersion: 7,
    });
  });

  it.each([
    [
      "a payload-bearing 200",
      () =>
        jsonResponse(
          { archived: true },
          { "Cache-Control": "no-store", ETag: '"v8-t11"' },
        ),
    ],
    [
      "Content-Type on a 204",
      () =>
        new Response(null, {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            ETag: '"v8-t11"',
          },
          status: 204,
        }),
    ],
    [
      "a nonzero Content-Length on a 204",
      () =>
        new Response(null, {
          headers: {
            "Cache-Control": "no-store",
            "Content-Length": "1",
            ETag: '"v8-t11"',
          },
          status: 204,
        }),
    ],
  ])("rejects archive success with %s", async (_label, response) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response()));

    await expect(archiveBindingFixture()).rejects.toBeInstanceOf(
      PhaseTwoApiError,
    );
  });

  it.each([
    ["missing", undefined],
    ["unchanged", '"v7-t11"'],
    ["skipped", '"v9-t11"'],
    ["tenant-drifted", '"v8-t12"'],
  ])("rejects a %s archive response ETag", async (_label, etag) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(null, {
          headers: {
            "Cache-Control": "no-store",
            ...(etag === undefined ? {} : { ETag: etag }),
          },
          status: 204,
        }),
      ),
    );

    await expect(archiveBindingFixture()).rejects.toThrow("next strong");
  });

  it("requires no-store on archive errors before preserving Problem Details", async () => {
    const problem = {
      detail: "The binding changed before archival.",
      title: "Precondition failed",
    };
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    fetch.mockResolvedValueOnce(jsonResponse(problem, {}, 412));

    await expect(archiveBindingFixture()).rejects.toThrow("did not mark");

    fetch.mockResolvedValueOnce(
      jsonResponse(problem, { "Cache-Control": "no-store" }, 412),
    );
    await expect(archiveBindingFixture()).rejects.toMatchObject({
      message: problem.detail,
      status: 412,
    });
  });

  it("rejects unexpected success statuses for every binding response shape", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    fetch.mockResolvedValueOnce(
      jsonResponse(
        { items: [bindingFixture()] },
        { "Cache-Control": "no-store" },
        201,
      ),
    );
    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).rejects.toThrow("unexpected success status");

    fetch.mockResolvedValueOnce(
      jsonResponse(
        bindingFixture(),
        {
          "Cache-Control": "no-store",
          ETag: '"v7-t11"',
          Location: bindingLocation(),
        },
        200,
      ),
    );
    await expect(
      phaseTwoApi.createPlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        "0198c97d-cf4f-7000-8000-000000000099",
        "Reserve an explicit tenant binding",
        { loginKey: "workforce_acme", profilePriority: 50, tenantId },
      ),
    ).rejects.toThrow("unexpected success status");

    fetch.mockResolvedValueOnce(
      jsonResponse(
        bindingFixture(),
        { "Cache-Control": "no-store", ETag: '"v7-t11"' },
        201,
      ),
    );
    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).rejects.toThrow("unexpected success status");

    fetch.mockResolvedValueOnce(
      jsonResponse(
        bindingFixture({
          loginKey: "workforce_acme_next",
          profilePriority: 75,
          version: 8,
        }),
        { "Cache-Control": "no-store", ETag: '"v8-t11"' },
        201,
      ),
    );
    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).rejects.toThrow("unexpected success status");
  });

  it("rejects update metadata that does not match the accepted request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(bindingFixture({ version: 8 }), {
          "Cache-Control": "no-store",
          ETag: '"v8-t11"',
        }),
      ),
    );

    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).rejects.toThrow("does not match the accepted update");
  });

  it.each([
    ["login key", { loginKey: "workforce_wrong", profilePriority: 75 }],
    [
      "profile priority",
      { loginKey: "workforce_acme_next", profilePriority: 50 },
    ],
  ])(
    "rejects an update with only the %s mismatched",
    async (_label, metadata) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(bindingFixture({ ...metadata, version: 8 }), {
            "Cache-Control": "no-store",
            ETag: '"v8-t11"',
          }),
        ),
      );

      await expect(
        phaseTwoApi.updatePlatformAuthProviderTenantBinding(
          "csrf-memory-only",
          providerId,
          bindingId,
          versionedBindingFixture(),
          "Adjust presentation precedence",
          {
            expectedTenantVersion: 11,
            expectedVersion: 7,
            loginKey: "workforce_acme_next",
            profilePriority: 75,
          },
        ),
      ).rejects.toThrow("does not match the accepted update");
    },
  );

  it("rejects an archived projection from the metadata-only update endpoint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          bindingFixture({
            archivedAt: "2026-08-28T11:00:00Z",
            loginKey: "workforce_acme_next",
            profilePriority: 75,
            updatedAt: "2026-08-28T11:00:00Z",
            version: 8,
          }),
          { "Cache-Control": "no-store", ETag: '"v8-t11"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each<readonly [string, Partial<PlatformAuthProviderTenantBindingView>]>([
    [
      "tenant identity",
      {
        tenant: {
          ...bindingFixture().tenant,
          id: "0198c97d-cf4f-7000-8000-000000000092",
          name: "Beta SOC",
          slug: "beta",
        },
      },
    ],
    ["authentication revision", { authRevision: 2 }],
    ["mapping revision", { mappingRevision: 2 }],
    ["backward update timestamp", { updatedAt: "2026-08-28T10:04:00Z" }],
  ])(
    "rejects a PATCH projection with changed %s",
    async (_label, overrides) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            bindingFixture({
              loginKey: "workforce_acme_next",
              profilePriority: 75,
              version: 8,
              ...overrides,
            }),
            { "Cache-Control": "no-store", ETag: '"v8-t11"' },
          ),
        ),
      );

      await expect(
        phaseTwoApi.updatePlatformAuthProviderTenantBinding(
          "csrf-memory-only",
          providerId,
          bindingId,
          versionedBindingFixture(),
          "Adjust presentation precedence",
          {
            expectedTenantVersion: 11,
            expectedVersion: 7,
            loginKey: "workforce_acme_next",
            profilePriority: 75,
          },
        ),
      ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    },
  );

  it("rejects a stale tenant-summary precondition before transport", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        versionedBindingFixture(),
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 12,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).rejects.toThrow("live tenant versions");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects metadata updates for an active binding before transport", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const active = bindingFixture({
      currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000093",
      enabled: true,
    });

    await expect(
      phaseTwoApi.updatePlatformAuthProviderTenantBinding(
        "csrf-memory-only",
        providerId,
        bindingId,
        { etag: '"v7-t11"', value: active },
        "Adjust presentation precedence",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          loginKey: "workforce_acme_next",
          profilePriority: 75,
        },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    ["binding version", '"v8-t11"'],
    ["weak validator", 'W/"v7-t11"'],
    ["wildcard validator", "*"],
    ["folded validators", '"v7-t11", "v7-t11"'],
    ["noncanonical version", '"v07-t11"'],
    ["overflowing version", '"v2147483648-t11"'],
  ])(
    "rejects a stale or malformed %s before update transport",
    async (_label, etag) => {
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);

      await expect(
        phaseTwoApi.updatePlatformAuthProviderTenantBinding(
          "csrf-memory-only",
          providerId,
          bindingId,
          { etag, value: bindingFixture() },
          "Adjust presentation precedence",
          {
            expectedTenantVersion: 11,
            expectedVersion: 7,
            loginKey: "workforce_acme_next",
            profilePriority: 75,
          },
        ),
      ).rejects.toBeInstanceOf(PhaseTwoApiError);
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["binding version", '"v8-t11"'],
    ["tenant version", '"v7-t12"'],
  ])("rejects a response ETag with a mismatched %s", async (_label, etag) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(bindingFixture(), {
          "Cache-Control": "no-store",
          ETag: etag,
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each([
    ["weak", 'W/"v7-t11"'],
    ["wildcard", "*"],
    ["folded", '"v7-t11", "v7-t11"'],
    ["leading-zero", '"v07-t11"'],
    ["binding-overflow", '"v2147483648-t11"'],
    ["tenant-overflow", '"v7-t2147483648"'],
  ])("rejects a %s composite response ETag", async (_label, etag) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(bindingFixture(), {
          "Cache-Control": "no-store",
          ETag: etag,
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).rejects.toThrow("required strong");
  });

  it.each<readonly [string, Record<string, unknown>]>([
    ["enabled binding without access epoch", { enabled: true }],
    [
      "disabled binding with a live access epoch",
      {
        currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
      },
    ],
    [
      "enabled binding also available for activation",
      {
        activationAvailable: true,
        currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
        enabled: true,
      },
    ],
    ["numeric enabled flag", { enabled: 0 }],
    ["null activation flag", { activationAvailable: null }],
    [
      "suspended tenant available for activation",
      {
        activationAvailable: true,
        tenant: { ...bindingFixture().tenant, status: "suspended" },
      },
    ],
    ["unknown JIT mode", { jitMode: "role_creation" }],
    ["unknown no-match policy", { noMatchPolicy: "allow" }],
    [
      "disabled binding retaining live admission policy",
      { jitMode: "create", noMatchPolicy: "provider_access_only" },
    ],
    [
      "numeric tenant slug",
      { tenant: { ...bindingFixture().tenant, slug: 123 } },
    ],
    ["wrong origin", { origin: "tenant" }],
    ["unexpected subject", { subject: "admin@example.com" }],
    ["unexpected role", { role: "platform_admin" }],
    [
      "unexpected tenant claim",
      { tenant: { ...bindingFixture().tenant, claim: "groups" } },
    ],
    ["null tenant", { tenant: null }],
    ["foreign binding", { id: "0198c97d-cf4f-7000-8000-000000000091" }],
    [
      "foreign provider",
      { providerId: "0198c97d-cf4f-7000-8000-000000000092" },
    ],
  ])("rejects a %s projection", async (_label, overrides) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { ...bindingFixture(), ...overrides },
            { "Cache-Control": "no-store", ETag: '"v7-t11"' },
          ),
        ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it.each<readonly [string, unknown]>([
    ["null item", null],
    ["invalid binding UUID", { ...bindingFixture(), id: "not-a-uuid" }],
    [
      "invalid provider UUID",
      { ...bindingFixture(), providerId: "not-a-uuid" },
    ],
    [
      "invalid tenant UUID",
      {
        ...bindingFixture(),
        tenant: { ...bindingFixture().tenant, id: "not-a-uuid" },
      },
    ],
    ["zero binding version", { ...bindingFixture(), version: 0 }],
    [
      "overflowing binding version",
      { ...bindingFixture(), version: 2_147_483_648 },
    ],
    [
      "unsafe binding version",
      { ...bindingFixture(), version: Number.MAX_SAFE_INTEGER + 1 },
    ],
    ["zero authentication revision", { ...bindingFixture(), authRevision: 0 }],
    [
      "unsafe authentication revision",
      { ...bindingFixture(), authRevision: Number.MAX_SAFE_INTEGER + 1 },
    ],
    ["zero mapping revision", { ...bindingFixture(), mappingRevision: 0 }],
    [
      "unsafe mapping revision",
      { ...bindingFixture(), mappingRevision: Number.MAX_SAFE_INTEGER + 1 },
    ],
    [
      "zero tenant version",
      {
        ...bindingFixture(),
        tenant: { ...bindingFixture().tenant, version: 0 },
      },
    ],
    [
      "overflowing tenant version",
      {
        ...bindingFixture(),
        tenant: { ...bindingFixture().tenant, version: 2_147_483_648 },
      },
    ],
    ["negative priority", { ...bindingFixture(), profilePriority: -1 }],
    [
      "overflowing priority",
      { ...bindingFixture(), profilePriority: 1_000_001 },
    ],
    ["malformed created timestamp", { ...bindingFixture(), createdAt: "soon" }],
    [
      "backward updated timestamp",
      {
        ...bindingFixture(),
        updatedAt: "2026-08-28T09:59:59Z",
      },
    ],
    [
      "malformed archived timestamp",
      { ...bindingFixture(), archivedAt: "yesterday" },
    ],
  ])("rejects a poisoned %s in a list projection", async (_label, item) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [item] }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("accepts maximum safe platform revision counters", async () => {
    const binding = bindingFixture({
      authRevision: Number.MAX_SAFE_INTEGER,
      mappingRevision: Number.MAX_SAFE_INTEGER,
    });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [binding] }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).resolves.toEqual({ items: [binding] });
  });

  it.each([
    ["null envelope", null],
    ["array envelope", []],
    ["extra envelope key", { items: [], role: "platform_admin" }],
    ["null items", { items: null }],
  ])("rejects a poisoned %s", async (_label, page) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(page, { "Cache-Control": "no-store" })),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderTenantBindings(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("rejects a success response without no-store", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(bindingFixture(), { ETag: '"v7-t11"' }),
        ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderTenantBinding(providerId, bindingId),
    ).rejects.toThrow("did not mark");
  });
});

function versionedBindingFixture(): {
  etag: string;
  value: PlatformAuthProviderTenantBindingView;
} {
  return { etag: '"v7-t11"', value: bindingFixture() };
}

function archiveBindingFixture(): Promise<string> {
  return phaseTwoApi.archivePlatformAuthProviderTenantBinding(
    "csrf-memory-only",
    providerId,
    bindingId,
    '"v7-t11"',
    "Retire the unused tenant binding",
    { expectedTenantVersion: 11, expectedVersion: 7 },
  );
}

function createBindingTransportFixture() {
  return phaseTwoApi.createPlatformAuthProviderTenantBinding(
    "csrf-memory-only",
    providerId,
    "0198c97d-cf4f-7000-8000-000000000099",
    "Reserve an explicit tenant binding",
    { loginKey: "workforce_acme", profilePriority: 50, tenantId },
  );
}

function bindingLocation(): string {
  return `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`;
}

function bindingFixture(
  overrides: Partial<PlatformAuthProviderTenantBindingView> = {},
): PlatformAuthProviderTenantBindingView {
  return {
    activationAvailable: false,
    archivedAt: null,
    authRevision: 1,
    createdAt: "2026-08-28T10:00:00Z",
    currentAccessEpochId: null,
    enabled: false,
    id: bindingId,
    jitMode: "disabled",
    loginKey: "workforce_acme",
    mappingRevision: 1,
    noMatchPolicy: "deny",
    origin: "platform",
    profilePriority: 50,
    providerId,
    tenant: {
      id: tenantId,
      name: "Acme SOC",
      slug: "acme",
      status: "active",
      version: 11,
    },
    updatedAt: "2026-08-28T10:05:00Z",
    version: 7,
    ...overrides,
  };
}

function bindingPageItems(
  count: number,
): PlatformAuthProviderTenantBindingView[] {
  return Array.from({ length: count }, (_, index) =>
    bindingFixture({
      id: uuidV7(0x100 + index),
      loginKey: `workforce_${index.toString().padStart(3, "0")}`,
      tenant: {
        ...bindingFixture().tenant,
        id: uuidV7(0x1000 + index),
        name: `Tenant ${index}`,
        slug: `tenant-${index}`,
      },
    }),
  );
}

function uuidV7(sequence: number): string {
  return `0198c97d-cf4f-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
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
