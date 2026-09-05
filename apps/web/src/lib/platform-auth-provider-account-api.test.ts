import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import type {
  PlatformAuthProviderAccountView,
  VersionedView,
} from "./phase-two-types";

const publicOrigin = "https://soc.example.com";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const accountId = "0198c97d-cf4f-7000-8000-000000000089";
const userId = "0198c97d-cf4f-7000-8000-000000000090";

beforeEach(() => {
  vi.stubGlobal("location", { origin: publicOrigin });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi platform identity-account transport", () => {
  it("loads a stable no-store page bound to the exact provider", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { items: [accountFixture()] },
          { "Cache-Control": "no-store" },
        );
      }),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId, {
        includeRetired: true,
      }),
    ).resolves.toEqual({ items: [accountFixture()] });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("GET");
    expect(request.cache).toBe("no-store");
    expect(request.url).toContain(
      `/api/v1/platform/auth-providers/${providerId}/accounts?limit=50&includeRetired=true`,
    );
  });

  it.each([
    {
      label: "a cross-provider row",
      page: {
        items: [
          {
            ...accountFixture(),
            providerId: "0198c97d-cf4f-7000-8000-000000000091",
          },
        ],
      },
    },
    {
      label: "a reflected protected subject",
      page: { items: [{ ...accountFixture(), subject: "opaque-subject" }] },
    },
    {
      label: "a cursor not bound to the final row",
      page: {
        items: [accountFixture()],
        nextCursor: "0198c97d-cf4f-7000-8000-000000000092",
      },
    },
    {
      label: "a retired row when retired accounts were not requested",
      page: {
        items: [
          accountFixture({
            retiredAt: "2026-08-30T10:05:00Z",
            state: "retired",
            updatedAt: "2026-08-30T10:05:00Z",
            version: 2,
          }),
        ],
      },
    },
  ])("rejects $label", async ({ page }) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(page, { "Cache-Control": "no-store" })),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("prelinks with write-only subject data and validates the safe location", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          accountFixture(),
          {
            "Cache-Control": "no-store",
            ETag: '"v1-u1"',
            Location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
          },
          201,
        );
      }),
    );

    const result = await phaseTwoApi.prelinkPlatformAuthProviderAccount(
      "csrf-test-value",
      providerId,
      "account-prelink-key-0001",
      "Prelink workforce identity",
      {
        issuer: "https://identity.example.com/tenant",
        subject: "exact-case-sensitive-subject",
        userId,
      },
    );

    expect(result).toMatchObject({
      etag: '"v1-u1"',
      location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
      value: { id: accountId, providerId, user: { id: userId } },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "account-prelink-key-0001",
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Prelink workforce identity",
    );
    await expect(request.json()).resolves.toEqual({
      issuer: "https://identity.example.com/tenant",
      subject: "exact-case-sensitive-subject",
      userId,
    });
  });

  it("rejects a retired account timestamped before its final observation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            items: [
              accountFixture({
                lastObservedAt: "2026-08-30T10:06:00Z",
                retiredAt: "2026-08-30T10:05:00Z",
                state: "retired",
                updatedAt: "2026-08-30T10:06:00Z",
                version: 2,
              }),
            ],
          },
          { "Cache-Control": "no-store" },
        ),
      ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId, {
        includeRetired: true,
      }),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("accepts a truthful retired legacy account with no reconstructable observation", async () => {
    const legacy = accountFixture({
      lastObservationState: "legacy_unknown",
      lastObservedAt: null,
      retiredAt: "2026-08-30T10:05:00Z",
      state: "retired",
      updatedAt: "2026-08-30T10:05:00Z",
      version: 1,
    });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [legacy] }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId, {
        includeRetired: true,
      }),
    ).resolves.toEqual({ items: [legacy] });
  });

  it.each([
    {
      account: accountFixture({ lastObservedAt: null }),
      label: "a known observation without a timestamp",
    },
    {
      account: accountFixture({
        lastObservationState: "legacy_unknown",
        retiredAt: "2026-08-30T10:05:00Z",
        state: "retired",
        updatedAt: "2026-08-30T10:05:00Z",
        version: 1,
      }),
      label: "a legacy-unknown observation with a timestamp",
    },
    {
      account: accountFixture({
        lastObservationState: "legacy_unknown",
        lastObservedAt: null,
      }),
      label: "an active legacy-unknown account",
    },
    {
      account: accountFixture({
        lastObservationState: "legacy_unknown",
        lastObservedAt: null,
        retiredAt: "2026-08-30T10:05:00Z",
        state: "retired",
        updatedAt: "2026-08-30T10:05:00Z",
        version: 2,
      }),
      label: "a legacy-unknown account with an advanced identity revision",
    },
  ])("rejects $label", async ({ account }) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [account] }, { "Cache-Control": "no-store" }),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId, {
        includeRetired: true,
      }),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("rejects an account projection without the embedded user version", async () => {
    const account = accountFixture();
    const unsafeUser = { ...account.user } as Record<string, unknown>;
    delete unsafeUser.version;

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { items: [{ ...account, user: unsafeUser }] },
            { "Cache-Control": "no-store" },
          ),
        ),
    );

    await expect(
      phaseTwoApi.listPlatformAuthProviderAccounts(providerId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("retires with exact CAS and accepts only the next immutable projection", async () => {
    const requests: Request[] = [];
    const current: VersionedView<PlatformAuthProviderAccountView> = {
      etag: '"v1-u1"',
      value: accountFixture(),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          accountFixture({
            retiredAt: "2026-08-30T10:05:00Z",
            state: "retired",
            updatedAt: "2026-08-30T10:05:00Z",
            version: 2,
          }),
          { "Cache-Control": "no-store", ETag: '"v2-u1"' },
        );
      }),
    );

    await expect(
      phaseTwoApi.retirePlatformAuthProviderAccount(
        "csrf-test-value",
        providerId,
        accountId,
        current,
        "Retire compromised identity link",
      ),
    ).resolves.toMatchObject({
      etag: '"v2-u1"',
      value: { id: accountId, state: "retired", version: 2 },
    });
    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("DELETE");
    expect(request.headers.get("If-Match")).toBe('"v1-u1"');
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Retire compromised identity link",
    );
    await expect(request.json()).resolves.toEqual({ expectedVersion: 1 });
  });

  it("does not send a retirement whose account version cannot be incremented", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const current: VersionedView<PlatformAuthProviderAccountView> = {
      etag: '"v2147483647-u1"',
      value: accountFixture({ version: 2_147_483_647 }),
    };

    await expect(
      phaseTwoApi.retirePlatformAuthProviderAccount(
        "csrf-test-value",
        providerId,
        accountId,
        current,
        "Retire version-exhausted identity link",
      ),
    ).rejects.toThrow(
      "The platform identity-account version cannot be incremented safely.",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails closed on missing cache policy or a malformed ETag", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse(accountFixture(), { ETag: '"v1-u1"' })),
    );
    await expect(
      phaseTwoApi.getPlatformAuthProviderAccount(providerId, accountId),
    ).rejects.toThrow();

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(accountFixture(), {
          "Cache-Control": "no-store",
          ETag: 'W/"v1-u1"',
        }),
      ),
    );
    await expect(
      phaseTwoApi.getPlatformAuthProviderAccount(providerId, accountId),
    ).rejects.toThrow();
  });

  it.each([
    '"v1"',
    '"v1-u2"',
    '"v2-u1"',
    '"v0-u1"',
    '"v01-u1"',
    '"v1-u0"',
    '"v2147483648-u1"',
    '"v1-u2147483648"',
    "*",
    '"v1-u1", "v2-u1"',
  ])("rejects the non-exact account validator %s", async (etag) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(accountFixture(), {
          "Cache-Control": "no-store",
          ETag: etag,
        }),
      ),
    );

    await expect(
      phaseTwoApi.getPlatformAuthProviderAccount(providerId, accountId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("rejects observation or user-projection drift in a retirement response", async () => {
    const current: VersionedView<PlatformAuthProviderAccountView> = {
      etag: '"v1-u1"',
      value: accountFixture(),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          accountFixture({
            lastObservedAt: "2026-08-30T10:04:00Z",
            retiredAt: "2026-08-30T10:05:00Z",
            state: "retired",
            updatedAt: "2026-08-30T10:05:00Z",
            user: {
              active: false,
              displayName: "Ada Current Profile",
              email: null,
              id: userId,
              version: 2,
            },
            version: 2,
          }),
          { "Cache-Control": "no-store", ETag: '"v2-u2"' },
        ),
      ),
    );
    await expect(
      phaseTwoApi.retirePlatformAuthProviderAccount(
        "csrf-test-value",
        providerId,
        accountId,
        current,
        "Retire compromised identity link",
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("rejects loss of known observation history in a retirement response", async () => {
    const current: VersionedView<PlatformAuthProviderAccountView> = {
      etag: '"v1-u1"',
      value: accountFixture(),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          accountFixture({
            lastObservationState: "legacy_unknown",
            lastObservedAt: null,
            retiredAt: "2026-08-30T10:05:00Z",
            state: "retired",
            updatedAt: "2026-08-30T10:05:00Z",
            version: 2,
          }),
          { "Cache-Control": "no-store", ETag: '"v2-u1"' },
        ),
      ),
    );

    await expect(
      phaseTwoApi.retirePlatformAuthProviderAccount(
        "csrf-test-value",
        providerId,
        accountId,
        current,
        "Retire compromised identity link",
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("rejects immutable account-pin drift in a retirement response", async () => {
    const current: VersionedView<PlatformAuthProviderAccountView> = {
      etag: '"v1-u1"',
      value: accountFixture(),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          accountFixture({
            admittedSecurityRevision: 6,
            retiredAt: "2026-08-30T10:05:00Z",
            state: "retired",
            updatedAt: "2026-08-30T10:05:00Z",
            version: 2,
          }),
          { "Cache-Control": "no-store", ETag: '"v2-u1"' },
        ),
      ),
    );
    await expect(
      phaseTwoApi.retirePlatformAuthProviderAccount(
        "csrf-test-value",
        providerId,
        accountId,
        current,
        "Retire compromised identity link",
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });
});

function accountFixture(
  patch: Partial<PlatformAuthProviderAccountView> = {},
): PlatformAuthProviderAccountView {
  return {
    admittedConfigurationRevision: 3,
    admittedSecurityRevision: 5,
    createdAt: "2026-08-30T10:00:00Z",
    id: accountId,
    lastObservationState: "known",
    lastObservedAt: "2026-08-30T10:00:00Z",
    providerId,
    retiredAt: null,
    state: "active",
    updatedAt: "2026-08-30T10:00:00Z",
    user: {
      active: true,
      displayName: "Ada Operator",
      email: "ada@example.invalid",
      id: userId,
      version: 1,
    },
    version: 1,
    ...patch,
  };
}

function jsonResponse(
  body: unknown,
  headers: Record<string, string>,
  status = 200,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
