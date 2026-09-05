import { afterEach, describe, expect, it, vi } from "vitest";

import type { TicketNumberingPolicy } from "@periapsis/contracts";

import { ticketNumberingApi } from "./ticket-numbering-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketNumberingApi", () => {
  it("loads one exact private policy bound to tenant, kind, and ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return policyResponse(policyFixture());
      }),
    );

    await expect(ticketNumberingApi.get(tenantId, "alert")).resolves.toEqual({
      etag: '"v7"',
      value: policyFixture(),
    });
    expect(requests[0]?.method).toBe("GET");
    expect(requests[0]?.url).toContain(
      `/api/v1/tenants/${tenantId}/ticket-numbering/alert`,
    );
    expect(requests[0]?.credentials).toBe("same-origin");
    expect(requests[0]?.cache).toBe("no-store");
  });

  it("previews a normalized draft with CSRF and no allocation key", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return previewResponse();
      }),
    );
    const draft = numberingDraft();

    await expect(
      ticketNumberingApi.preview("csrf-memory-only", tenantId, "alert", draft),
    ).resolves.toMatchObject({
      example: "ALT-2026-000001",
      maximumSequence: 999_999,
      periodKey: 2026,
    });

    const request = requests[0]!;
    expect(request.method).toBe("POST");
    expect(request.url).toContain("/ticket-numbering/alert/preview");
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request.headers.has("Idempotency-Key")).toBe(false);
    await expect(request.clone().json()).resolves.toEqual(draft);
  });

  it("publishes with strong CAS, idempotency, CSRF, reason, and replay proof", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return mutationResponse(false);
      }),
    );
    const current = { etag: '"v7"', value: policyFixture() };

    await expect(
      ticketNumberingApi.update(
        "csrf-memory-only",
        tenantId,
        "alert",
        current,
        "number-policy-update-0001",
        "Approved numbering change SEC-2048",
        { ...numberingDraft(), prefix: "INC", start: 25 },
      ),
    ).resolves.toMatchObject({
      etag: '"v8"',
      replayed: false,
      value: { prefix: "INC", start: 25, version: 8 },
    });

    const request = requests[0]!;
    expect(request.method).toBe("PUT");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "number-policy-update-0001",
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Approved numbering change SEC-2048",
    );
    await expect(request.clone().json()).resolves.toEqual({
      expectedVersion: 7,
      period: "annual",
      prefix: "INC",
      separator: "-",
      start: 25,
      width: 6,
    });
  });

  it.each([
    ["wrong tenant", { tenantId: "0198c97d-cf4f-7000-8000-000000000099" }],
    ["wrong kind", { kind: "case" }],
    [
      "system publisher after v1",
      { publisher: { membershipId: null, type: "system" } },
    ],
    ["unknown field", { internalDigest: "secret" }],
  ])("rejects a %s policy projection", async (_name, override) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(policyResponse({ ...policyFixture(), ...override })),
    );
    await expect(
      ticketNumberingApi.get(tenantId, "alert"),
    ).rejects.toMatchObject({ code: "ticket_numbering_projection_mismatch" });
  });

  it("rejects incoherent preview, ETag, cache, and replay metadata", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(previewResponse({ example: "ALT-2026/000001" }))
        .mockResolvedValueOnce(policyResponse(policyFixture(), '"v6"'))
        .mockResolvedValueOnce(
          policyResponse(policyFixture(), '"v7"', "no-store"),
        )
        .mockResolvedValueOnce(mutationResponse(false, "true")),
    );
    await expect(
      ticketNumberingApi.preview(
        "csrf-memory-only",
        tenantId,
        "alert",
        numberingDraft(),
      ),
    ).rejects.toMatchObject({ code: "ticket_numbering_projection_mismatch" });
    await expect(
      ticketNumberingApi.get(tenantId, "alert"),
    ).rejects.toMatchObject({ code: "ticket_numbering_projection_mismatch" });
    await expect(ticketNumberingApi.get(tenantId, "alert")).rejects.toThrow(
      "private and no-store",
    );
    await expect(
      ticketNumberingApi.update(
        "csrf-memory-only",
        tenantId,
        "alert",
        { etag: '"v7"', value: policyFixture() },
        "number-policy-update-0001",
        "Approved",
        { ...numberingDraft(), prefix: "INC", start: 25 },
      ),
    ).rejects.toMatchObject({ code: "ticket_numbering_projection_mismatch" });
  });

  it("fails closed before transport for invalid security context", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const current = { etag: '"v7"', value: policyFixture() };
    await expect(
      ticketNumberingApi.preview("", tenantId, "alert", numberingDraft()),
    ).rejects.toThrow("CSRF");
    await expect(
      ticketNumberingApi.update(
        "csrf",
        tenantId,
        "alert",
        current,
        "short",
        "Approved",
        numberingDraft(),
      ),
    ).rejects.toThrow("command");
    await expect(
      ticketNumberingApi.update(
        "csrf",
        tenantId,
        "alert",
        { ...current, etag: 'W/"v7"' },
        "number-policy-update-0001",
        "Approved",
        numberingDraft(),
      ),
    ).rejects.toThrow("command");
    expect(fetch).not.toHaveBeenCalled();
  });
});

function numberingDraft() {
  return {
    period: "annual" as const,
    prefix: "ALT",
    separator: "-" as const,
    start: 1,
    width: 6,
  };
}

function policyFixture(
  override: Partial<TicketNumberingPolicy> = {},
): TicketNumberingPolicy {
  return {
    kind: "alert",
    period: "annual",
    prefix: "ALT",
    publishedAt: "2026-09-01T18:30:00.123456Z",
    publisher: {
      membershipId: "0198c97d-cf4f-7000-8000-000000000020",
      type: "membership",
    },
    separator: "-",
    start: 1,
    tenantId,
    version: 7,
    versionId: "0198c97d-cf4f-7000-8000-000000000092",
    width: 6,
    ...override,
  };
}

function policyResponse(
  policy: Record<string, unknown>,
  etag = '"v7"',
  cacheControl = "private, no-store",
): Response {
  return new Response(JSON.stringify(policy), {
    headers: {
      "Cache-Control": cacheControl,
      "Content-Type": "application/json",
      ETag: etag,
    },
  });
}

function previewResponse(override: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({
      ...numberingDraft(),
      at: "2026-09-03T10:30:00Z",
      example: "ALT-2026-000001",
      kind: "alert",
      maximumSequence: 999_999,
      periodKey: 2026,
      tenantId,
      ...override,
    }),
    {
      headers: {
        "Cache-Control": "private, no-store",
        "Content-Type": "application/json",
      },
    },
  );
}

function mutationResponse(
  replayed: boolean,
  replayHeader = String(replayed),
): Response {
  return new Response(
    JSON.stringify({
      policy: policyFixture({
        prefix: "INC",
        publishedAt: "2026-09-03T10:31:00Z",
        start: 25,
        version: 8,
        versionId: "0198c97d-cf4f-7000-8000-000000000093",
      }),
      replayed,
    }),
    {
      headers: {
        "Cache-Control": "private, no-store",
        "Content-Type": "application/json",
        ETag: '"v8"',
        "X-Idempotent-Replay": replayHeader,
      },
    },
  );
}
