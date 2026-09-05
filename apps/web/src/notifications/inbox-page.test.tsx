import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import { TenantDateTimeProvider } from "../lib/tenant-date-time-context";
import type { PhaseTwoApi, TenantAuthorityView } from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  NotificationInboxApiError,
  type NotificationInboxApi,
} from "./inbox-api";
import { NotificationInboxProvider } from "./inbox-context";
import type {
  NotificationAudience,
  NotificationInboxItemView,
} from "./inbox-model";
import { NotificationInboxPage } from "./inbox-page";

afterEach(cleanup);

const tenantId = uuidV7(101);
const secondTenantId = uuidV7(102);
const userId = sessionFixture.user.id;

describe("personal Notification Inbox page", () => {
  it("loads without admin permission, renders all five kinds, and exposes only safe routes", async () => {
    const list = vi.fn(
      async ({ unreadOnly }: Parameters<NotificationInboxApi["list"]>[0]) =>
        inboxPage(
          allResourceItems().filter(
            (item) => !unreadOnly || item.readAt === null,
          ),
        ),
    );
    const countUnread = vi.fn(async () => unreadState(4));
    renderInbox({ api: createInboxApi({ countUnread, list }) });

    expect(await screen.findByText("Alert notification")).toBeVisible();
    for (const title of [
      "Case notification",
      "Task notification",
      "Evidence notification",
      "Contact notification",
    ]) {
      expect(screen.getByText(title)).toBeVisible();
    }
    expect(list).toHaveBeenCalledWith({
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
      unreadOnly: false,
    });
    expect(countUnread).toHaveBeenCalledWith({
      signal: expect.any(AbortSignal),
      tenantId,
    });
    expect(screen.getByRole("link", { name: /Open Alert/u })).toHaveAttribute(
      "href",
      `/alerts/${uuidV7(605)}`,
    );
    expect(screen.getByRole("link", { name: /Open Case/u })).toHaveAttribute(
      "href",
      `/cases/${uuidV7(604)}`,
    );
    expect(screen.queryByRole("link", { name: /Open Task/u })).toBeNull();
    expect(screen.queryByRole("link", { name: /Open Evidence/u })).toBeNull();
    expect(screen.queryByRole("link", { name: /Open Contact/u })).toBeNull();
    expect(screen.getAllByText(/Europe\/Rome/u).length).toBeGreaterThan(0);
    expect(
      within(screen.getByLabelText("Unread notification count")).getByText("4"),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("checkbox", { name: "Unread only" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(list.mock.calls[1]?.[0]).toMatchObject({ unreadOnly: true });
    expect(screen.queryByText("Case notification")).toBeNull();
  });

  it("uses the backend customer audience independently of the display-only role", async () => {
    const list = vi.fn(async () =>
      inboxPage(
        [
          inboxItem(20, {
            audience: "customer",
            title: "Customer Alert",
          }),
        ],
        { audience: "customer" },
      ),
    );
    renderInbox({
      api: createInboxApi({ list }),
    });

    expect(await screen.findByText("Customer Alert")).toBeVisible();
    expect(screen.getByText(/personal identity/u)).toBeVisible();
    expect(screen.getByRole("link", { name: /Open Alert/u })).toHaveAttribute(
      "href",
      `/portal?kind=alert&ticket=${uuidV7(520)}`,
    );
  });

  it("reaches a strict second page with the canonical after cursor", async () => {
    const firstItems = Array.from({ length: 50 }, (_, index) =>
      inboxItem(200 - index),
    );
    const list = vi.fn(
      async ({ after }: Parameters<NotificationInboxApi["list"]>[0]) =>
        after
          ? inboxPage([inboxItem(150)])
          : inboxPage(firstItems, { nextCursor: firstItems.at(-1)!.id }),
    );
    renderInbox({ api: createInboxApi({ list }) });

    fireEvent.click(
      await screen.findByRole("button", { name: "Load older notifications" }),
    );
    expect(await screen.findByText("Notification 150")).toBeVisible();
    expect(list).toHaveBeenLastCalledWith({
      after: uuidV7(151),
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
      unreadOnly: false,
    });
  });

  it("fails closed on a malformed mounted projection", async () => {
    const list = vi.fn(async () => ({
      ...inboxPage([inboxItem(20)]),
      tenantId: secondTenantId,
    }));
    renderInbox({ api: createInboxApi({ list }) });

    expect(
      await screen.findByText("Notification inbox unavailable"),
    ).toBeVisible();
    expect(screen.queryByText("Notification 20")).toBeNull();
  });

  it("sends no inbox calls before both active tenant and live authority are ready", async () => {
    const list = vi.fn();
    const countUnread = vi.fn();
    const inactive = renderInbox({
      activeTenantId: null,
      api: createInboxApi({ countUnread, list }),
    });

    expect(
      await screen.findByRole("heading", {
        name: "Select a tenant to view notifications",
      }),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
    expect(countUnread).not.toHaveBeenCalled();
    inactive.unmount();

    const getTenantAuthority = vi.fn(
      () => new Promise<TenantAuthorityView>(() => undefined),
    );
    renderInbox({
      api: createInboxApi({ countUnread, list }),
      getTenantAuthority,
    });
    expect(await screen.findByLabelText("Loading notifications")).toBeVisible();
    expect(list).not.toHaveBeenCalled();
    expect(countUnread).not.toHaveBeenCalled();
    cleanup();

    renderInbox({
      api: createInboxApi({ countUnread, list }),
      getTenantAuthority: async () => authorityFixture(secondTenantId),
    });
    expect(
      await screen.findByRole("heading", {
        name: "Notifications are not available",
      }),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
    expect(countUnread).not.toHaveBeenCalled();
  });

  it("clears a 401 session and pauses after a 403 until an explicit recheck", async () => {
    const unauthorizedList = vi.fn(async () => {
      throw new NotificationInboxApiError(401, "Session expired");
    });
    const unauthorized = renderInbox({
      api: createInboxApi({ list: unauthorizedList }),
    });
    await waitFor(() =>
      expect(unauthorized.clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
    expect(unauthorizedList).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole("button", { name: "Recheck notifications" }),
    ).toBeNull();
    unauthorized.unmount();

    const list = vi
      .fn<NotificationInboxApi["list"]>()
      .mockRejectedValueOnce(
        new NotificationInboxApiError(403, "Membership changed"),
      )
      .mockResolvedValue(inboxPage([inboxItem(20)]));
    let countSignal: AbortSignal | undefined;
    const countUnread = vi.fn(
      ({ signal }: Parameters<NotificationInboxApi["countUnread"]>[0]) => {
        if (!countSignal) {
          countSignal = signal;
          return new Promise<unknown>((_resolve, reject) => {
            signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError")),
            );
          });
        }
        return Promise.resolve(unreadState(1));
      },
    );
    const getTenantAuthority = vi.fn(async () => authorityFixture());
    renderInbox({
      api: createInboxApi({ countUnread, list }),
      getTenantAuthority,
    });

    expect(
      await screen.findByRole("heading", {
        name: "Notification access changed",
      }),
    ).toBeVisible();
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(countSignal?.aborted).toBe(true);
    expect(list).toHaveBeenCalledTimes(1);
    fireEvent.click(
      screen.getByRole("button", { name: "Recheck notifications" }),
    );
    expect(await screen.findByText("Notification 20")).toBeVisible();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("does not let a generic list failure mask a concurrent unread-count 401", async () => {
    const list = vi.fn(async () => {
      throw new Error("list transport failed");
    });
    const countUnread = vi.fn(async () => {
      throw new NotificationInboxApiError(401, "Session expired");
    });
    const mounted = renderInbox({
      api: createInboxApi({ countUnread, list }),
    });

    await waitFor(() =>
      expect(mounted.clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
    expect(
      screen.queryByRole("button", { name: "Recheck notifications" }),
    ).toBeNull();
  });

  it("keeps item idempotency stable across an uncertain retry and suppresses double submit", async () => {
    const list = vi.fn(async () => inboxPage([inboxItem(20)]));
    const setReadState = vi
      .fn<NotificationInboxApi["setReadState"]>()
      .mockRejectedValueOnce(new Error("connection lost"))
      .mockResolvedValue(
        readResult(
          inboxItem(20, {
            readAt: "2026-08-25T22:35:00Z",
            revision: 4,
          }),
        ),
      );
    renderInbox({ api: createInboxApi({ list, setReadState }) });

    const button = await screen.findByRole("button", {
      name: "Mark Notification 20 as read",
    });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(setReadState).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/reuse its idempotency key/u)).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Mark Notification 20 as read" }),
    );
    await waitFor(() => expect(setReadState).toHaveBeenCalledTimes(2));

    const first = setReadState.mock.calls[0]?.[0];
    const second = setReadState.mock.calls[1]?.[0];
    expect(first).toMatchObject({
      expectedRevision: 3,
      itemId: uuidV7(20),
      read: true,
      tenantId,
    });
    expect(second?.idempotencyKey).toBe(first?.idempotencyKey);
  });

  it("toggles a read item back to unread with its exact item revision", async () => {
    const list = vi.fn(async () =>
      inboxPage([
        inboxItem(20, {
          readAt: "2026-08-25T22:35:00Z",
          revision: 7,
        }),
      ]),
    );
    const setReadState = vi.fn(async () =>
      readResult(inboxItem(20, { readAt: null, revision: 8 })),
    );
    renderInbox({ api: createInboxApi({ list, setReadState }) });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Mark Notification 20 as unread",
      }),
    );
    await waitFor(() => expect(setReadState).toHaveBeenCalledTimes(1));
    expect(setReadState).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedRevision: 7,
        itemId: uuidV7(20),
        read: false,
        tenantId,
      }),
    );
  });

  it("reloads after stale item CAS and binds the retry to the new revision", async () => {
    const list = vi
      .fn<NotificationInboxApi["list"]>()
      .mockResolvedValueOnce(inboxPage([inboxItem(20)]))
      .mockResolvedValue(inboxPage([inboxItem(20, { revision: 4 })]));
    const setReadState = vi
      .fn<NotificationInboxApi["setReadState"]>()
      .mockRejectedValueOnce(
        new NotificationInboxApiError(412, "Stale notification"),
      )
      .mockResolvedValue(
        readResult(
          inboxItem(20, {
            readAt: "2026-08-25T22:35:00Z",
            revision: 5,
          }),
        ),
      );
    renderInbox({ api: createInboxApi({ list, setReadState }) });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Mark Notification 20 as read",
      }),
    );
    expect(await screen.findByText(/changed elsewhere/u)).toBeVisible();
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    fireEvent.click(
      screen.getByRole("button", { name: "Mark Notification 20 as read" }),
    );
    await waitFor(() => expect(setReadState).toHaveBeenCalledTimes(2));

    expect(setReadState.mock.calls[0]?.[0].expectedRevision).toBe(3);
    expect(setReadState.mock.calls[1]?.[0].expectedRevision).toBe(4);
    expect(setReadState.mock.calls[1]?.[0].idempotencyKey).not.toBe(
      setReadState.mock.calls[0]?.[0].idempotencyKey,
    );
  });

  it("uses inbox CAS for mark-all with stable retry idempotency and no double submit", async () => {
    const markAllRead = vi
      .fn<NotificationInboxApi["markAllRead"]>()
      .mockRejectedValueOnce(new Error("connection lost"))
      .mockResolvedValue(markAllResult(1));
    renderInbox({ api: createInboxApi({ markAllRead }) });

    const button = await screen.findByRole("button", { name: "Mark all read" });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    fireEvent.click(button);
    expect(markAllRead).toHaveBeenCalledTimes(1);
    await screen.findByText(/reuse its idempotency key/u);
    fireEvent.click(screen.getByRole("button", { name: "Mark all read" }));
    await waitFor(() => expect(markAllRead).toHaveBeenCalledTimes(2));

    expect(markAllRead.mock.calls[0]?.[0]).toMatchObject({
      expectedRevision: 8,
      tenantId,
    });
    expect(markAllRead.mock.calls[1]?.[0].idempotencyKey).toBe(
      markAllRead.mock.calls[0]?.[0].idempotencyKey,
    );
  });

  it("does not issue a mutation when an item or inbox reached the CAS ceiling", async () => {
    const setReadState = vi.fn();
    const markAllRead = vi.fn();
    renderInbox({
      api: createInboxApi({
        countUnread: async () =>
          unreadState(1, { inboxRevision: 2_147_483_647 }),
        list: async () =>
          inboxPage([inboxItem(20, { revision: 2_147_483_647 })], {
            inboxRevision: 2_147_483_647,
          }),
        markAllRead,
        setReadState,
      }),
    });

    const itemButton = await screen.findByRole("button", {
      name: "Mark Notification 20 as read",
    });
    const allButton = screen.getByRole("button", { name: "Mark all read" });
    expect(itemButton).toBeDisabled();
    expect(allButton).toBeDisabled();
    fireEvent.click(itemButton);
    fireEvent.click(allButton);
    expect(setReadState).not.toHaveBeenCalled();
    expect(markAllRead).not.toHaveBeenCalled();
  });

  it("aborts and clears the old cache when the active tenant changes", async () => {
    let firstSignal: AbortSignal | undefined;
    const list = vi.fn(
      ({
        signal,
        tenantId: requestedTenant,
      }: Parameters<NotificationInboxApi["list"]>[0]) => {
        if (requestedTenant === tenantId) {
          firstSignal = signal;
          return new Promise<unknown>((_resolve, reject) => {
            signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError")),
            );
          });
        }
        return Promise.resolve(
          inboxPage([inboxItem(20, { tenantId: secondTenantId })], {
            tenantId: secondTenantId,
          }),
        );
      },
    );
    const countUnread = vi.fn(
      async ({
        tenantId: requestedTenant,
      }: Parameters<NotificationInboxApi["countUnread"]>[0]) =>
        unreadState(1, { tenantId: requestedTenant }),
    );
    const mounted = renderInbox({
      api: createInboxApi({ countUnread, list }),
    });
    await waitFor(() => expect(firstSignal).toBeDefined());

    mounted.rerenderInbox({ activeTenantId: secondTenantId });
    await waitFor(() => expect(firstSignal?.aborted).toBe(true));
    expect(await screen.findByText("Notification 20")).toBeVisible();
    expect(list).toHaveBeenLastCalledWith(
      expect.objectContaining({ tenantId: secondTenantId }),
    );
    expect(
      mounted.queryClient
        .getQueryCache()
        .getAll()
        .some((query) => JSON.stringify(query.queryKey).includes(tenantId)),
    ).toBe(false);
  });

  it("aborts and isolates cached pages when the authenticated session changes", async () => {
    const nextSessionId = uuidV7(910);
    let firstSignal: AbortSignal | undefined;
    const list = vi.fn(
      ({ signal }: Parameters<NotificationInboxApi["list"]>[0]) => {
        if (!firstSignal) {
          firstSignal = signal;
          return new Promise<unknown>((_resolve, reject) => {
            signal?.addEventListener("abort", () =>
              reject(new DOMException("Aborted", "AbortError")),
            );
          });
        }
        return Promise.resolve(inboxPage([inboxItem(20)]));
      },
    );
    const mounted = renderInbox({ api: createInboxApi({ list }) });
    await waitFor(() => expect(firstSignal).toBeDefined());

    mounted.rerenderInbox({ sessionId: nextSessionId });
    await waitFor(() => expect(firstSignal?.aborted).toBe(true));
    expect(await screen.findByText("Notification 20")).toBeVisible();
    expect(
      mounted.queryClient
        .getQueryCache()
        .getAll()
        .some((query) =>
          JSON.stringify(query.queryKey).includes(sessionFixture.id),
        ),
    ).toBe(false);
    expect(
      mounted.queryClient
        .getQueryCache()
        .getAll()
        .some((query) =>
          JSON.stringify(query.queryKey).includes(nextSessionId),
        ),
    ).toBe(true);
  });

  it("renders clear empty and server-error states", async () => {
    const empty = renderInbox({
      api: createInboxApi({
        countUnread: async () => unreadState(0, { inboxRevision: 0 }),
        list: async () => inboxPage([], { inboxRevision: 0 }),
      }),
    });
    expect(await screen.findByText("No notifications yet")).toBeVisible();
    empty.unmount();

    renderInbox({
      api: createInboxApi({
        list: async () => {
          throw new NotificationInboxApiError(503, "Inbox is restarting");
        },
      }),
    });
    expect(await screen.findByText("Inbox is restarting")).toBeVisible();
    expect(screen.getByRole("button", { name: "Retry inbox" })).toBeVisible();
  });
});

interface RenderInboxOptions {
  activeTenantId?: string | null;
  api: NotificationInboxApi;
  getTenantAuthority?: PhaseTwoApi["getTenantAuthority"];
  sessionId?: string;
}

function renderInbox(options: RenderInboxOptions): ReturnType<typeof render> & {
  clearSession: ReturnType<typeof vi.fn>;
  queryClient: QueryClient;
  rerenderInbox: (next: Partial<RenderInboxOptions>) => void;
} {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const clearSession = vi.fn();
  let current = options;
  const getTenantAuthority =
    options.getTenantAuthority ??
    (async (requestedTenantId: string) => authorityFixture(requestedTenantId));
  const phaseApi = createPhaseTwoApi({ getTenantAuthority });
  const tree = (): React.JSX.Element => (
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseApi,
          clearSession,
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: {
            ...sessionFixture,
            id: current.sessionId ?? sessionFixture.id,
            ...(current.activeTenantId === null
              ? {}
              : { activeTenantId: current.activeTenantId ?? tenantId }),
          },
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <TenantDateTimeProvider locale="it-IT" timeZone="Europe/Rome">
            <NotificationInboxProvider api={current.api}>
              <MemoryRouter>
                <NotificationInboxPage />
              </MemoryRouter>
            </NotificationInboxProvider>
          </TenantDateTimeProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>
  );
  const mounted = render(tree());
  return {
    ...mounted,
    clearSession,
    queryClient,
    rerenderInbox(next) {
      current = { ...current, ...next };
      mounted.rerender(tree());
    },
  };
}

function createInboxApi(
  overrides: Partial<NotificationInboxApi> = {},
): NotificationInboxApi {
  return {
    countUnread: async () => unreadState(1),
    list: async () => inboxPage([inboxItem(20)]),
    markAllRead: async () => markAllResult(1),
    setReadState: async () =>
      readResult(
        inboxItem(20, {
          readAt: "2026-08-25T22:35:00Z",
          revision: 4,
        }),
      ),
    ...overrides,
  };
}

function authorityFixture(activeTenantId = tenantId): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-09-02T08:00:00Z",
    legacyMembershipRole: "analyst",
    membershipId: uuidV7(30),
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [],
    roleGrants: [],
    tenantId: activeTenantId,
    userId,
  };
}

function allResourceItems(): readonly NotificationInboxItemView[] {
  return [
    inboxItem(105, {
      resourceId: uuidV7(605),
      title: "Alert notification",
    }),
    inboxItem(104, {
      eventType: "case.assigned",
      readAt: "2026-08-25T22:35:00Z",
      resourceId: uuidV7(604),
      resourceKind: "case",
      title: "Case notification",
    }),
    inboxItem(103, {
      eventType: "task.assigned",
      resourceKind: "task",
      title: "Task notification",
    }),
    inboxItem(102, {
      eventType: "evidence.added",
      resourceKind: "evidence",
      title: "Evidence notification",
    }),
    inboxItem(101, {
      eventType: "contact.changed",
      resourceKind: "contact",
      title: "Contact notification",
    }),
  ];
}

function inboxItem(
  sequence: number,
  overrides: Partial<NotificationInboxItemView> = {},
): NotificationInboxItemView {
  return {
    audience: "operator",
    eventType: "alert.assigned",
    id: uuidV7(sequence),
    occurredAt: "2026-08-25T22:30:00Z",
    readAt: null,
    resourceId: uuidV7(500 + sequence),
    resourceKind: "alert",
    resourceVersion: 4,
    revision: 3,
    summary: "A concise safe summary",
    tenantId,
    title: `Notification ${sequence}`,
    userId,
    ...overrides,
  };
}

function inboxPage(
  items: readonly NotificationInboxItemView[],
  options: {
    audience?: NotificationAudience;
    inboxRevision?: number;
    nextCursor?: string;
    tenantId?: string;
  } = {},
): Record<string, unknown> {
  const pageTenantId = options.tenantId ?? tenantId;
  return {
    inboxRevision: options.inboxRevision ?? 8,
    items: items.map((item) => ({
      ...item,
      audience: options.audience ?? item.audience,
      tenantId: pageTenantId,
    })),
    ...(options.nextCursor ? { nextCursor: options.nextCursor } : {}),
    tenantId: pageTenantId,
    userId,
  };
}

function unreadState(
  count: number,
  overrides: { inboxRevision?: number; tenantId?: string } = {},
): Record<string, unknown> {
  return {
    count,
    inboxRevision: overrides.inboxRevision ?? 8,
    tenantId: overrides.tenantId ?? tenantId,
    userId,
  };
}

function readResult(item: NotificationInboxItemView): Record<string, unknown> {
  return {
    changed: true,
    inboxRevision: 9,
    item,
    replayed: false,
  };
}

function markAllResult(affected: number): Record<string, unknown> {
  return {
    affected,
    changed: affected > 0,
    inboxRevision: affected > 0 ? 9 : 8,
    replayed: false,
    tenantId,
    userId,
  };
}

function uuidV7(sequence: number): string {
  return `0198c97d-cf4f-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
}
