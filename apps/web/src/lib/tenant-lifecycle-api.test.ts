import { afterEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000071";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi platform tenant lifecycle", () => {
  it("binds suspension to the exact tenant, CSRF token, and strong version", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return lifecycleResponse();
      }),
    );

    await expect(
      phaseTwoApi.suspendTenant("csrf-memory-only-value", tenantId, '"v4"', {
        expectedVersion: 4,
        reason: "Approved change SEC-2048",
      }),
    ).resolves.toEqual({
      etag: '"v5"',
      value: lifecycleReceipt(),
    });

    const request = requests[0];
    expect(request).toBeDefined();
    expect(request?.method).toBe("POST");
    expect(request?.url).toContain(
      `/api/v1/platform/tenants/${tenantId}/suspend`,
    );
    expect(request?.headers.get("If-Match")).toBe('"v4"');
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    expect(request?.credentials).toBe("same-origin");
    await expect(request?.clone().json()).resolves.toEqual({
      expectedVersion: 4,
      reason: "Approved change SEC-2048",
    });
  });

  it("binds reactivation to the opposite closed transition", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        lifecycleResponse({
          previousStatus: "suspended",
          status: "active",
        }),
      ),
    );

    await expect(
      phaseTwoApi.reactivateTenant("csrf-memory-only-value", tenantId, '"v4"', {
        expectedVersion: 4,
        reason: "Incident service restored",
      }),
    ).resolves.toMatchObject({
      etag: '"v5"',
      value: { previousStatus: "suspended", status: "active" },
    });
  });

  it.each([
    ["another tenant", { tenantId: "0198c97d-cf4f-7000-8000-000000000072" }],
    ["a non-v7 tenant", { tenantId: "0198c97d-cf4f-4000-8000-000000000071" }],
    ["the wrong transition", { previousStatus: "suspended", status: "active" }],
    ["a skipped version", { version: 6 }],
    ["a malformed instant", { updatedAt: "not-an-instant" }],
    ["a malformed replay marker", { replayed: "false" }],
    ["a reason outside the sanitized receipt", { reason: "Sensitive" }],
  ] as const)("rejects a receipt for %s", async (_name, override) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(lifecycleResponse(override)),
    );

    await expect(
      phaseTwoApi.suspendTenant("csrf-memory-only-value", tenantId, '"v4"', {
        expectedVersion: 4,
        reason: "Approved",
      }),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("rejects an ETag/body version mismatch and a cacheable receipt", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(lifecycleResponse({}, '"v6"'))
        .mockResolvedValueOnce(lifecycleResponse({}, '"v5"', false)),
    );

    const invoke = () =>
      phaseTwoApi.suspendTenant("csrf-memory-only-value", tenantId, '"v4"', {
        expectedVersion: 4,
        reason: "Approved",
      });
    await expect(invoke()).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
    await expect(invoke()).rejects.toMatchObject({
      message: "The API did not mark the tenant lifecycle receipt as no-store.",
    });
  });

  it("preserves a 412 conflict for a stale confirmation boundary", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "precondition_failed",
            detail:
              "The tenant lifecycle state changed after the supplied version was issued.",
            requestId: "0198c97d-cf4f-7000-8000-000000000073",
            status: 412,
            title: "Precondition failed",
            type: "about:blank",
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/problem+json",
            },
            status: 412,
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.suspendTenant("csrf-memory-only-value", tenantId, '"v4"', {
        expectedVersion: 4,
        reason: "Approved",
      }),
    ).rejects.toMatchObject({ code: "precondition_failed", status: 412 });
  });

  it("accepts a rolling tenant without a version but rejects an invalid version", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ items: [tenantSummary()] }), {
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ items: [{ ...tenantSummary(), version: 0 }] }),
            { headers: { "Content-Type": "application/json" } },
          ),
        ),
    );

    await expect(phaseTwoApi.listTenants()).resolves.toEqual({
      items: [tenantSummary()],
    });
    await expect(phaseTwoApi.listTenants()).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });
});

function lifecycleReceipt(
  override: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    previousStatus: "active",
    replayed: false,
    status: "suspended",
    tenantId,
    updatedAt: "2026-08-26T14:15:16.789123Z",
    version: 5,
    ...override,
  };
}

function lifecycleResponse(
  override: Record<string, unknown> = {},
  etag = '"v5"',
  noStore = true,
): Response {
  return new Response(JSON.stringify(lifecycleReceipt(override)), {
    headers: {
      ...(noStore ? { "Cache-Control": "no-store" } : {}),
      "Content-Type": "application/json",
      ETag: etag,
    },
  });
}

function tenantSummary(): Record<string, unknown> {
  return {
    createdAt: "2026-08-23T10:00:00Z",
    id: tenantId,
    locale: "en",
    name: "Acme SOC",
    slug: "acme-soc",
    status: "active",
    timezone: "UTC",
    updatedAt: "2026-08-24T10:00:00Z",
  };
}
