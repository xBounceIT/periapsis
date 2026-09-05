import { afterEach, describe, expect, it, vi } from "vitest";

import {
  mergeNotificationInboxPages,
  notificationInboxApi,
  NotificationInboxProjectionError,
  projectNotificationInboxPage,
  projectNotificationMarkAllReadResult,
  projectNotificationReadStateResult,
  projectNotificationUnreadState,
} from "./inbox-api";
import {
  notificationResourcePath,
  type NotificationInboxCoordinate,
  type NotificationInboxItemView,
} from "./inbox-model";

const tenantId = uuidV7(1);
const userId = uuidV7(2);
const coordinate = {
  tenantId,
  userId,
} as const satisfies NotificationInboxCoordinate;
const now = Date.parse("2026-09-02T12:00:00Z");

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("personal notification inbox projections", () => {
  it("accepts an exact newest-first page and binds its cursor to the last item", () => {
    const items = [item(20), item(19)];
    const projected = projectNotificationInboxPage(
      page(items, { nextCursor: items[1]!.id }),
      coordinate,
      { limit: 2, unreadOnly: false },
      now,
    );

    expect(projected).toEqual({
      inboxRevision: 8,
      items,
      nextCursor: items[1]!.id,
      tenantId,
      userId,
    });
    expect(projected.items).not.toBe(items);
  });

  it("accepts a bounded second page strictly below the requested UUIDv7 cursor", () => {
    const after = uuidV7(19);
    const projected = projectNotificationInboxPage(
      page([item(18), item(17)]),
      coordinate,
      { after, limit: 2, unreadOnly: false },
      now,
    );

    expect(projected.items.map(({ id }) => id)).toEqual([
      uuidV7(18),
      uuidV7(17),
    ]);
  });

  it.each([
    ["unknown field", () => ({ ...page([item(20)]), secret: "no" })],
    [
      "persistence-only item data",
      () =>
        page([
          { ...item(20), recipientEmail: "must-not-project@example.invalid" },
        ]),
    ],
    ["wrong page tenant", () => page([item(20)], { tenantId: uuidV7(90) })],
    ["wrong item user", () => page([item(20, { userId: uuidV7(90) })])],
    ["unknown audience", () => page([{ ...item(20), audience: "future" }])],
    [
      "event resource mismatch",
      () => page([item(20, { eventType: "task.assigned" })]),
    ],
    ["duplicate", () => page([item(20), item(20)])],
    ["ascending order", () => page([item(19), item(20)])],
    ["non UUIDv7 item", () => page([item(20, { id: crypto.randomUUID() })])],
    [
      "revision above shared maximum",
      () => page([item(20, { revision: 2_147_483_648 })]),
    ],
    [
      "non-UTC instant",
      () => page([item(20, { occurredAt: "2026-09-02T10:00:00+02:00" })]),
    ],
    [
      "instant beyond the notification outbox clock-skew bound",
      () => page([item(20, { occurredAt: "2026-09-02T12:01:00.000001Z" })]),
    ],
    ["control text", () => page([item(20, { title: "Unsafe\ncaption" })])],
    ["unpaired surrogate", () => page([item(20, { title: "Unsafe\ud800" })])],
  ])("rejects %s", (_label, makeInput) => {
    expect(() =>
      projectNotificationInboxPage(
        makeInput(),
        coordinate,
        { limit: 50, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
  });

  it("accepts the notification outbox future-clock-skew boundary", () => {
    const projected = projectNotificationInboxPage(
      page([item(20, { occurredAt: "2026-09-02T12:01:00Z" })]),
      coordinate,
      { limit: 50, unreadOnly: false },
      now,
    );

    expect(projected.items[0]?.occurredAt).toBe("2026-09-02T12:01:00Z");
  });

  it("rejects cursor divergence, empty cursors, and rows at or above after", () => {
    expect(() =>
      projectNotificationInboxPage(
        page([item(20), item(19)], { nextCursor: uuidV7(18) }),
        coordinate,
        { limit: 2, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationInboxPage(
        page([], { inboxRevision: 0, nextCursor: uuidV7(18) }),
        coordinate,
        { limit: 2, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationInboxPage(
        page([], { inboxRevision: 0, nextCursor: null }),
        coordinate,
        { limit: 2, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationInboxPage(
        page([item(20)]),
        coordinate,
        { after: uuidV7(20), limit: 2, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
  });

  it("rejects read rows from an unread-only page", () => {
    expect(() =>
      projectNotificationInboxPage(
        page([item(20, { readAt: "2026-09-02T10:05:00Z" })]),
        coordinate,
        { limit: 50, unreadOnly: true },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
  });

  it.each([
    "alert.watcher_added",
    "alert.watcher_removed",
    "case.watcher_added",
    "case.watcher_removed",
    "comment.private_added",
  ] as const)(
    "rejects operator-only %s for a customer audience",
    (eventType) => {
      const resourceKind = eventType.startsWith("case.") ? "case" : "alert";
      expect(() =>
        projectNotificationInboxPage(
          page(
            [item(20, { audience: "customer", eventType, resourceKind })],
            {},
          ),
          coordinate,
          { limit: 50, unreadOnly: false },
          now,
        ),
      ).toThrow(NotificationInboxProjectionError);
    },
  );

  it("requires one canonical audience across every item and page", () => {
    expect(() =>
      projectNotificationInboxPage(
        page([item(20), item(19, { audience: "customer" })]),
        coordinate,
        { limit: 50, unreadOnly: false },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);

    const operatorPage = projectNotificationInboxPage(
      page([item(20)]),
      coordinate,
      { limit: 50, unreadOnly: false },
      now,
    );
    const customerPage = projectNotificationInboxPage(
      page([item(19, { audience: "customer" })]),
      coordinate,
      { limit: 50, unreadOnly: false },
      now,
    );
    expect(
      mergeNotificationInboxPages(
        [operatorPage, customerPage],
        coordinate,
        false,
      ),
    ).toEqual({ canonical: false, items: [] });
  });

  it("rejects duplicate and non-monotonic items across projected pages", () => {
    const first = projectNotificationInboxPage(
      page([item(20)]),
      coordinate,
      { limit: 50, unreadOnly: false },
      now,
    );
    const duplicate = { ...first, items: [item(20)] };
    const ascending = { ...first, items: [item(21)] };

    expect(
      mergeNotificationInboxPages([first, duplicate], coordinate, false),
    ).toEqual({ canonical: false, items: [] });
    expect(
      mergeNotificationInboxPages([first, ascending], coordinate, false),
    ).toEqual({ canonical: false, items: [] });

    const terminalThenOlder = [
      projectNotificationInboxPage(
        page([item(20)]),
        coordinate,
        { limit: 50, unreadOnly: false },
        now,
      ),
      projectNotificationInboxPage(
        page([item(19)]),
        coordinate,
        { after: uuidV7(20), limit: 50, unreadOnly: false },
        now,
      ),
    ];
    expect(
      mergeNotificationInboxPages(terminalThenOlder, coordinate, false),
    ).toEqual({ canonical: false, items: [] });
  });

  it("validates unread and mutation CAS results against exact coordinates", () => {
    expect(
      projectNotificationUnreadState(
        { count: 2, inboxRevision: 8, tenantId, userId },
        coordinate,
      ),
    ).toMatchObject({ count: 2, inboxRevision: 8 });
    expect(
      projectNotificationReadStateResult(
        {
          changed: true,
          inboxRevision: 9,
          item: item(20, {
            readAt: "2026-09-02T10:05:00Z",
            revision: 4,
          }),
          replayed: false,
        },
        coordinate,
        {
          audience: "operator",
          expectedRevision: 3,
          itemId: uuidV7(20),
          read: true,
        },
        now,
      ),
    ).toMatchObject({ changed: true, inboxRevision: 9 });
    expect(
      projectNotificationMarkAllReadResult(
        {
          affected: 2,
          changed: true,
          inboxRevision: 9,
          replayed: false,
          tenantId,
          userId,
        },
        coordinate,
        8,
      ),
    ).toMatchObject({ affected: 2, inboxRevision: 9 });

    expect(() =>
      projectNotificationUnreadState(
        { count: 1, inboxRevision: 0, tenantId, userId },
        coordinate,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationReadStateResult(
        {
          changed: true,
          inboxRevision: 9,
          item: item(20, {
            readAt: "2026-09-02T10:05:00Z",
            revision: 3,
          }),
          replayed: false,
        },
        coordinate,
        {
          audience: "operator",
          expectedRevision: 3,
          itemId: uuidV7(20),
          read: true,
        },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationReadStateResult(
        {
          changed: true,
          inboxRevision: 9,
          item: item(20, {
            audience: "customer",
            readAt: "2026-09-02T10:05:00Z",
            revision: 4,
          }),
          replayed: false,
        },
        coordinate,
        {
          audience: "operator",
          expectedRevision: 3,
          itemId: uuidV7(20),
          read: true,
        },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationReadStateResult(
        {
          changed: false,
          inboxRevision: 9,
          item: item(20, { revision: 2_147_483_647 }),
          replayed: false,
        },
        coordinate,
        {
          audience: "operator",
          expectedRevision: 2_147_483_647,
          itemId: uuidV7(20),
          read: false,
        },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationMarkAllReadResult(
        {
          affected: 2,
          changed: false,
          inboxRevision: 8,
          replayed: false,
          tenantId,
          userId,
        },
        coordinate,
        8,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationReadStateResult(
        {
          changed: false,
          inboxRevision: 8,
          item: item(20, { tenantId: "not-a-uuid" }),
          replayed: false,
        },
        { tenantId: "not-a-uuid", userId },
        {
          audience: "operator",
          expectedRevision: 3,
          itemId: uuidV7(20),
          read: false,
        },
        now,
      ),
    ).toThrow(NotificationInboxProjectionError);
    expect(() =>
      projectNotificationMarkAllReadResult(
        {
          affected: 0,
          changed: false,
          inboxRevision: 0,
          replayed: false,
          tenantId: "not-a-uuid",
          userId,
        },
        { tenantId: "not-a-uuid", userId },
        0,
      ),
    ).toThrow(NotificationInboxProjectionError);
  });
});

describe("notification route allowlists", () => {
  it("links only Alert and Case through audience-specific canonical routes", () => {
    expect(
      notificationResourcePath({
        audience: "operator",
        resourceId: uuidV7(80),
        resourceKind: "alert",
      }),
    ).toBe(`/alerts/${uuidV7(80)}`);
    expect(
      notificationResourcePath({
        audience: "customer",
        resourceId: uuidV7(81),
        resourceKind: "case",
      }),
    ).toBe(`/portal?kind=case&ticket=${uuidV7(81)}`);
    for (const resourceKind of ["task", "evidence", "contact"] as const) {
      expect(
        notificationResourcePath({
          audience: "operator",
          resourceId: uuidV7(82),
          resourceKind,
        }),
      ).toBeUndefined();
    }
    expect(
      notificationResourcePath({
        audience: "future",
        resourceId: uuidV7(83),
        resourceKind: "alert",
      }),
    ).toBeUndefined();
  });
});

describe("notification inbox HTTP adapter", () => {
  it("uses the generated same-origin routes and binds item CAS to integrity headers", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request expected");
        requests.push(input);
        return new Response(
          JSON.stringify({
            changed: true,
            inboxRevision: 9,
            item: { revision: 4 },
            replayed: false,
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v4"',
            },
          },
        );
      }),
    );

    await notificationInboxApi.setReadState({
      csrfToken: "csrf-memory-only",
      expectedRevision: 3,
      idempotencyKey: "notification-item-read-0001",
      itemId: uuidV7(20),
      read: true,
      tenantId,
    });

    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${tenantId}/notification-inbox/${uuidV7(20)}/read-state`,
    );
    expect(request.credentials).toBe("same-origin");
    expect(request.headers.get("If-Match")).toBe('"v3"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "notification-item-read-0001",
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(request.clone().json()).resolves.toEqual({ read: true });
  });

  it("supports the v0 inbox CAS and rejects responses that shared caches may store", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request expected");
        requests.push(input);
        return new Response(
          JSON.stringify({
            affected: 0,
            changed: false,
            inboxRevision: 0,
            replayed: false,
            tenantId,
            userId,
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v0"',
            },
          },
        );
      }),
    );

    await notificationInboxApi.markAllRead({
      csrfToken: "csrf-memory-only",
      expectedRevision: 0,
      idempotencyKey: "notification-mark-all-0001",
      tenantId,
    });
    expect(requests[0]!.headers.get("If-Match")).toBe('"v0"');

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ count: 0 }), {
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await expect(
      notificationInboxApi.countUnread({ tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("does not reflect an untrusted problem detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "forbidden",
            detail: "password=server-secret",
            status: 403,
          }),
          {
            status: 403,
            headers: { "Content-Type": "application/problem+json" },
          },
        ),
      ),
    );
    await expect(
      notificationInboxApi.list({
        limit: 50,
        tenantId,
        unreadOnly: false,
      }),
    ).rejects.toMatchObject({
      code: "forbidden",
      message:
        "The personal notification inbox is not available for this tenant context.",
      status: 403,
    });
  });
});

function item(
  sequence: number,
  overrides: Partial<NotificationInboxItemView> = {},
): NotificationInboxItemView {
  return {
    audience: "operator",
    eventType: "alert.assigned",
    id: uuidV7(sequence),
    occurredAt: "2026-09-02T10:00:00Z",
    readAt: null,
    resourceId: uuidV7(500 + sequence),
    resourceKind: "alert",
    resourceVersion: 2,
    revision: 3,
    summary: "A safe notification summary",
    tenantId,
    title: `Notification ${sequence}`,
    userId,
    ...overrides,
  };
}

function page(
  items: readonly unknown[],
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    inboxRevision: 8,
    items,
    tenantId,
    userId,
    ...overrides,
  };
}

function uuidV7(sequence: number): string {
  return `0198c97d-cf4f-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
}
