import { afterEach, describe, expect, it, vi } from "vitest";

import { TicketWatcherApiError, ticketWatcherApi } from "./ticket-watcher-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const alertId = "0198c97d-cf4f-7000-8000-000000000002";
const caseId = "0198c97d-cf4f-7000-8000-000000000003";
const userId = "0198c97d-cf4f-7000-8000-000000000004";
const otherUserId = "0198c97d-cf4f-7000-8000-000000000005";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketWatcherApi", () => {
  it("loads an exact no-store Alert watcher page and validates its ETag", async () => {
    let request: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        request = input;
        return watcherResponse(watcherPage(4), 4);
      }),
    );

    await expect(
      ticketWatcherApi.list({
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).resolves.toEqual({ etag: '"v4"', value: watcherPage(4) });
    expect(request?.method).toBe("GET");
    expect(new URL(request!.url).pathname).toBe(
      `/api/v1/tenants/${tenantId}/alerts/${alertId}/watchers`,
    );
    expect(request?.cache).toBe("no-store");
    expect(request?.headers.get("X-CSRF-Token")).toBeNull();
  });

  it("binds add and remove to path targets, CAS, idempotency, and CSRF without a body", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        return requests.length === 1
          ? watcherResponse(watcherPage(5), 5, "false")
          : watcherResponse(watcherPage(6, []), 6, "false");
      }),
    );

    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0001",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).resolves.toMatchObject({ changed: true, replayed: false });
    await expect(
      ticketWatcherApi.mutate({
        action: "remove",
        csrfToken: "csrf-memory-only",
        etag: '"v5"',
        expectedVersion: 5,
        idempotencyKey: "watcher-case-remove-01",
        kind: "case",
        resourceId: caseId,
        tenantId,
        userId,
      }),
    ).resolves.toMatchObject({ changed: true, replayed: false });

    expect(requests.map((request) => request.method)).toEqual([
      "PUT",
      "DELETE",
    ]);
    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/api/v1/tenants/${tenantId}/alerts/${alertId}/watchers/${userId}`,
      `/api/v1/tenants/${tenantId}/cases/${caseId}/watchers/${userId}`,
    ]);
    expect(requests[0]?.headers.get("If-Match")).toBe('"v4"');
    expect(requests[0]?.headers.get("Idempotency-Key")).toBe(
      "watcher-alert-add-0001",
    );
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(requests[0]!.clone().text()).resolves.toBe("");
    await expect(requests[1]!.clone().text()).resolves.toBe("");
  });

  it("dispatches the remaining Case add and Alert remove member routes", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        return requests.length === 1
          ? watcherResponse(watcherPage(5), 5, "false")
          : watcherResponse(watcherPage(5, []), 5, "false");
      }),
    );

    await ticketWatcherApi.mutate({
      action: "add",
      csrfToken: "csrf-memory-only",
      etag: '"v4"',
      expectedVersion: 4,
      idempotencyKey: "watcher-case-add-00001",
      kind: "case",
      resourceId: caseId,
      tenantId,
      userId,
    });
    await ticketWatcherApi.mutate({
      action: "remove",
      csrfToken: "csrf-memory-only",
      etag: '"v4"',
      expectedVersion: 4,
      idempotencyKey: "watcher-alert-remove-3",
      kind: "alert",
      resourceId: alertId,
      tenantId,
      userId,
    });

    expect(requests.map((request) => request.method)).toEqual([
      "PUT",
      "DELETE",
    ]);
    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/api/v1/tenants/${tenantId}/cases/${caseId}/watchers/${userId}`,
      `/api/v1/tenants/${tenantId}/alerts/${alertId}/watchers/${userId}`,
    ]);
    await Promise.all(
      requests.map((request) =>
        expect(request.clone().text()).resolves.toBe(""),
      ),
    );
  });

  it("accepts set-idempotent no-ops and exposes immutable replay receipts", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(watcherResponse(watcherPage(4), 4, "false"))
      .mockResolvedValueOnce(watcherResponse(watcherPage(5, []), 5, "true"));
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0002",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).resolves.toMatchObject({ changed: false, etag: '"v4"', replayed: false });
    await expect(
      ticketWatcherApi.mutate({
        action: "remove",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-remove-1",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).resolves.toMatchObject({ changed: true, etag: '"v5"', replayed: true });
  });

  it("rejects extra fields, duplicate IDs, noncanonical byte order, names, headers, and versions", async () => {
    const variants = [
      watcherResponse({ ...watcherPage(4), secret: "hidden" }, 4),
      watcherResponse(
        watcherPage(4, [watcher("Analyst", userId), watcher("Zulu", userId)]),
        4,
      ),
      watcherResponse(
        watcherPage(4, [watcher("😀", userId), watcher("\uE000", otherUserId)]),
        4,
      ),
      watcherResponse(watcherPage(4, [watcher(" Analyst", userId)]), 4),
      watcherResponse(
        watcherPage(4, [watcher("Analyst\u0085Name", userId)]),
        4,
      ),
      watcherResponse(
        watcherPage(4, [
          { ...watcher("Analyst", userId), addedAt: "2026-09-01T08:06:00Z" },
        ]),
        4,
      ),
      watcherResponse(
        watcherPage(4, [
          {
            ...watcher("Analyst", userId),
            addedAt: "2026-09-01T08:00:00+00:00",
          },
        ]),
        4,
      ),
      watcherResponse(
        watcherPage(
          4,
          Array.from({ length: 1001 }, (_, index) =>
            watcher(
              `Operator ${index.toString().padStart(4, "0")}`,
              `0198c97d-cf4f-7${index.toString(16).padStart(3, "0")}-8000-${index.toString(16).padStart(12, "0")}`,
            ),
          ),
        ),
        4,
      ),
      watcherResponse(watcherPage(4), 4, undefined, {
        "Cache-Control": "private",
      }),
      watcherResponse(watcherPage(4), 5),
    ];
    const fetch = vi.fn();
    for (const response of variants) fetch.mockResolvedValueOnce(response);
    vi.stubGlobal("fetch", fetch);

    await Promise.all(
      variants.map(() =>
        expect(
          ticketWatcherApi.list({
            kind: "alert",
            resourceId: alertId,
            tenantId,
          }),
        ).rejects.toBeInstanceOf(TicketWatcherApiError),
      ),
    );
  });

  it("accepts canonical UTF-8 ordering, internal whitespace, and FEFF edges", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          watcherResponse(
            watcherPage(4, [
              watcher("A\u2003B", userId),
              watcher("\uE000", otherUserId),
              watcher(
                "\uFEFFOperator\uFEFF",
                "0198c97d-cf4f-7000-8000-000000000006",
              ),
              watcher("😀", "0198c97d-cf4f-7000-8000-000000000007"),
            ]),
            4,
          ),
        ),
    );

    await expect(
      ticketWatcherApi.list({ kind: "case", resourceId: caseId, tenantId }),
    ).resolves.toMatchObject({ value: { version: 4 } });
  });

  it("requires the replay header and membership postcondition on mutations", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(watcherResponse(watcherPage(5), 5))
      .mockResolvedValueOnce(watcherResponse(watcherPage(5, []), 5, "false"))
      .mockResolvedValueOnce(watcherResponse(watcherPage(5), 5, "false"));
    vi.stubGlobal("fetch", fetch);
    const base = {
      csrfToken: "csrf-memory-only",
      etag: '"v4"',
      expectedVersion: 4,
      kind: "alert" as const,
      resourceId: alertId,
      tenantId,
      userId,
    };

    await expect(
      ticketWatcherApi.mutate({
        ...base,
        action: "add",
        idempotencyKey: "watcher-alert-add-0003",
      }),
    ).rejects.toBeInstanceOf(TicketWatcherApiError);
    await expect(
      ticketWatcherApi.mutate({
        ...base,
        action: "add",
        idempotencyKey: "watcher-alert-add-0004",
      }),
    ).rejects.toBeInstanceOf(TicketWatcherApiError);
    await expect(
      ticketWatcherApi.mutate({
        ...base,
        action: "remove",
        idempotencyKey: "watcher-alert-remove-2",
      }),
    ).rejects.toBeInstanceOf(TicketWatcherApiError);
  });

  it("returns bounded conflict messages and rejects invalid contexts before fetch", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "sensitive storage detail" }), {
        headers: { "Cache-Control": "no-store" },
        status: 412,
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0005",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).rejects.toMatchObject({
      message:
        "The watcher list changed. Reload the latest snapshot before retrying.",
      status: 412,
    });
    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v2147483647"',
        expectedVersion: 2_147_483_647,
        idempotencyKey: "watcher-alert-add-0006",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      ticketWatcherApi.list({
        kind: "alert",
        resourceId: "0198c97d-cf4f-4000-8000-000000000002",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0007",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId: "0198c97d-cf4f-4000-8000-000000000004",
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "   ",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0008",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      ticketWatcherApi.mutate({
        action: "add",
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "watcher-alert-add-0009\n",
        kind: "alert",
        resourceId: alertId,
        tenantId,
        userId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

function watcher(displayName: string, id: string): Record<string, unknown> {
  return {
    addedAt: "2026-09-01T08:00:00Z",
    displayName,
    userId: id,
  };
}

function watcherPage(
  version: number,
  items: unknown[] = [watcher("Analyst One", userId)],
): Record<string, unknown> {
  return {
    items,
    updatedAt: "2026-09-01T08:05:00Z",
    version,
  };
}

function watcherResponse(
  value: unknown,
  version: number,
  replayed?: "false" | "true",
  extraHeaders: HeadersInit = {},
): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    ETag: `"v${version}"`,
  });
  new Headers(extraHeaders).forEach((headerValue, key) =>
    headers.set(key, headerValue),
  );
  if (replayed !== undefined) headers.set("X-Idempotent-Replay", replayed);
  return new Response(JSON.stringify(value), { headers, status: 200 });
}
