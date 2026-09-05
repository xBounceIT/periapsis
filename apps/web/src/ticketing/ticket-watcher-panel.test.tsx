import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { startTransition, Suspense, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { sessionFixture } from "../test/phase-two-fixtures";
import {
  TicketWatcherApiError,
  type TicketWatcherApi,
  type TicketWatcherMutationInput,
  type TicketWatcherMutationResult,
  type VersionedTicketWatcherPage,
} from "./ticket-watcher-api";
import { TicketWatcherPanel } from "./ticket-watcher-panel";
import type { ReloadedTicketBoundary } from "./ticket-watcher-panel";
import { alertId, caseId, tenantId } from "./ticketing-test-fixtures";

const analystId = "0198c97d-cf4f-7000-8000-000000000041";
const responderId = "0198c97d-cf4f-7000-8000-000000000042";
const canonicalId = "0198c97d-cf4f-7000-8000-000000000043";
const nextSessionId = "0198c97d-cf4f-7000-8000-000000000044";
const nextTenantId = "0198c97d-cf4f-7000-8000-000000000045";

afterEach(cleanup);

describe("TicketWatcherPanel", () => {
  it("renders an accessible Alert list and submits an exact guarded add", async () => {
    const list = vi.fn<TicketWatcherApi["list"]>(async () =>
      watcherPage(1, [watcher("Analyst One", analystId)]),
    );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) =>
      mutationResult(input, 2, false, [
        watcher("Analyst One", analystId),
        watcher("Responder Two", responderId),
      ]),
    );
    const onReloadLatest = vi.fn(async () => ticketBoundary(2));
    renderPanel({ api: { list, mutate }, onReloadLatest });

    expect(
      await screen.findByRole("list", { name: "Ticket watchers" }),
    ).toBeVisible();
    expect(screen.getByText("Analyst One")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Operator user ID"), {
      target: { value: "not-a-user" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add watcher" }));
    expect(
      screen.getByText(
        "Enter the canonical UUIDv7 of an eligible tenant operator.",
      ),
    ).toBeVisible();
    expect(mutate).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Operator user ID"), {
      target: { value: responderId.toUpperCase() },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add watcher" }));

    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    expect(mutate).toHaveBeenCalledWith({
      action: "add",
      csrfToken: sessionFixture.csrfToken,
      etag: '"v1"',
      expectedVersion: 1,
      idempotencyKey: expect.any(String),
      kind: "alert",
      resourceId: alertId,
      signal: expect.any(AbortSignal),
      tenantId,
      userId: responderId,
    });
    await waitFor(() => expect(onReloadLatest).toHaveBeenCalledTimes(1));
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reload latest watcher snapshot" }),
    ).toBeVisible();
  });

  it("mounts for a Case and applies a remove no-op without a ticket reload", async () => {
    const list = vi.fn<TicketWatcherApi["list"]>(async () =>
      watcherPage(3, [watcher("Analyst One", analystId)]),
    );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) =>
      mutationResult(input, 3, false, []),
    );
    const onReloadLatest = vi.fn(async () => ticketBoundary(3));
    renderPanel({
      api: { list, mutate },
      kind: "case",
      onReloadLatest,
      resourceId: caseId,
      ticketEtag: '"v3"',
      ticketVersion: 3,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Remove Analyst One (${analystId}) from watchers`,
      }),
    );

    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    expect(mutate).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "remove",
        etag: '"v3"',
        expectedVersion: 3,
        kind: "case",
        resourceId: caseId,
        userId: analystId,
      }),
    );
    expect(onReloadLatest).not.toHaveBeenCalled();
    expect(
      await screen.findByText("No operators are watching this ticket."),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Operator user ID"), {
      target: { value: responderId },
    });
    expect(screen.getByRole("button", { name: "Add watcher" })).toBeEnabled();
  });

  it("aborts an in-flight mutation and hides controls on live update revocation", async () => {
    const pending = deferred<TicketWatcherMutationResult>();
    const list = vi.fn<TicketWatcherApi["list"]>(async () =>
      watcherPage(1, [watcher("Analyst One", analystId)]),
    );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(
      async () => pending.promise,
    );
    const view = renderPanel({ api: { list, mutate } });
    await add(responderId);
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    const signal = mutate.mock.calls[0]?.[0].signal;

    view.rerender(panel({ api: { list, mutate }, canEdit: false }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(
      await screen.findByText(
        "Watchers are read-only under the current live tenant authority.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Analyst One")).toBeVisible();

    await act(async () => {
      pending.resolve(mutationResult(mutate.mock.calls[0]![0], 2, false));
      await pending.promise;
    });
    expect(screen.queryByText("Responder Two")).not.toBeInTheDocument();
  });

  it("removes the private list immediately when live read authority is revoked", async () => {
    const api = apiFixture();
    const view = renderPanel({ api });
    expect(await screen.findByText("Analyst One")).toBeVisible();

    view.rerender(panel({ api, canEdit: false, canRead: false }));

    expect(screen.queryByText("Analyst One")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Watchers" }),
    ).not.toBeInTheDocument();
  });

  it("preserves a request across equivalent props and aborts it at a committed ETag boundary", async () => {
    const pending = deferred<TicketWatcherMutationResult>();
    const list = vi.fn<TicketWatcherApi["list"]>(async (input) =>
      watcherPage(input.resourceId === alertId ? 1 : 2),
    );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(
      async () => pending.promise,
    );
    const view = renderPanel({ api: { list, mutate } });
    await add(responderId);
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    const signal = mutate.mock.calls[0]?.[0].signal;

    view.rerender(panel({ api: { list, mutate } }));
    expect(signal?.aborted).toBe(false);
    expect(screen.getByLabelText("Operator user ID")).toHaveValue(responderId);

    view.rerender(
      panel({
        api: { list, mutate },
        ticketEtag: '"v2"',
        ticketVersion: 2,
      }),
    );
    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(screen.queryByText("Responder Two")).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve(mutationResult(mutate.mock.calls[0]![0], 2, false));
      await pending.promise;
    });
  });

  it("aborts an in-flight mutation when the committed authority epoch advances without permission drift", async () => {
    const pending = deferred<TicketWatcherMutationResult>();
    const list = vi.fn<TicketWatcherApi["list"]>(async () => watcherPage(1));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(
      async () => pending.promise,
    );
    const api = { list, mutate };
    const view = renderPanel({ api, authorityEpoch: "authority-1" });
    await add(responderId);
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    const signal = mutate.mock.calls[0]?.[0].signal;

    view.rerender(panel({ api, authorityEpoch: "authority-2" }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(await screen.findByText("Analyst One")).toBeVisible();
    expect(screen.getByLabelText("Operator user ID")).toHaveValue("");
    await act(async () => {
      pending.resolve(mutationResult(mutate.mock.calls[0]![0], 2, false));
      await pending.promise;
    });
    expect(screen.queryByText("Responder Two")).not.toBeInTheDocument();
  });

  it.each([
    { boundary: "session", next: { sessionId: nextSessionId } },
    { boundary: "tenant", next: { tenantId: nextTenantId } },
  ])(
    "aborts an in-flight mutation at a committed $boundary boundary",
    async ({ next }) => {
      const pending = deferred<TicketWatcherMutationResult>();
      const list = vi.fn<TicketWatcherApi["list"]>(async () => watcherPage(1));
      const mutate = vi.fn<TicketWatcherApi["mutate"]>(
        async () => pending.promise,
      );
      const api = { list, mutate };
      const view = renderPanel({ api });
      await add(responderId);
      await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
      const signal = mutate.mock.calls[0]?.[0].signal;

      view.rerender(panel({ api, ...next }));

      await waitFor(() => expect(signal?.aborted).toBe(true));
      await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
      await act(async () => {
        pending.resolve(mutationResult(mutate.mock.calls[0]![0], 2, false));
        await pending.promise;
      });
      expect(screen.queryByText("Responder Two")).not.toBeInTheDocument();
    },
  );

  it("ignores a late non-AbortError rejection from an aborted superseded read", async () => {
    const pending = deferred<VersionedTicketWatcherPage>();
    const firstList = vi.fn<TicketWatcherApi["list"]>(
      async () => pending.promise,
    );
    const secondList = vi.fn<TicketWatcherApi["list"]>(async () =>
      watcherPage(1, [watcher("Canonical Current", canonicalId)]),
    );
    const firstApi = { list: firstList, mutate: vi.fn() };
    const secondApi = { list: secondList, mutate: vi.fn() };
    const view = renderPanel({ api: firstApi });
    await waitFor(() => expect(firstList).toHaveBeenCalledTimes(1));
    const firstSignal = firstList.mock.calls[0]?.[0].signal;

    view.rerender(panel({ api: secondApi }));

    await waitFor(() => expect(firstSignal?.aborted).toBe(true));
    expect(await screen.findByText("Canonical Current")).toBeVisible();
    await act(async () => {
      pending.reject(new Error("late transport failure"));
      await pending.promise.catch(() => undefined);
    });
    expect(screen.getByText("Canonical Current")).toBeVisible();
    expect(
      screen.queryByText("The watcher list could not be loaded."),
    ).not.toBeInTheDocument();
  });

  it("reloads both projections after stale preconditions and keeps mutations closed until aligned", async () => {
    const list = vi
      .fn<TicketWatcherApi["list"]>()
      .mockResolvedValueOnce(watcherPage(1))
      .mockResolvedValueOnce(
        watcherPage(2, [watcher("Canonical Responder", canonicalId)]),
      )
      .mockResolvedValueOnce(
        watcherPage(3, [watcher("Converged Responder", canonicalId)]),
      );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async () => {
      throw new TicketWatcherApiError(
        "The watcher list changed. Reload the latest snapshot before retrying.",
        412,
      );
    });
    const onReloadLatest = vi.fn(async () => ticketBoundary(3));
    const api = { list, mutate };
    const view = renderPanel({ api, onReloadLatest });
    await add(responderId);

    expect(
      await screen.findByText(
        "The watcher list changed. Reload the latest snapshot before retrying.",
      ),
    ).toBeVisible();
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(onReloadLatest).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Canonical Responder")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();

    view.rerender(
      panel({
        api,
        onReloadLatest,
        ticketEtag: '"v3"',
        ticketVersion: 3,
      }),
    );
    expect(await screen.findByText("Converged Responder")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Operator user ID"), {
      target: { value: responderId },
    });
    expect(screen.getByRole("button", { name: "Add watcher" })).toBeEnabled();
  });

  it("does not reopen a rejected CAS boundary when recovery repeats the stale version", async () => {
    const list = vi
      .fn<TicketWatcherApi["list"]>()
      .mockResolvedValueOnce(watcherPage(1))
      .mockResolvedValueOnce(watcherPage(1));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async () => {
      throw new TicketWatcherApiError(
        "The watcher list changed. Reload the latest snapshot before retrying.",
        412,
      );
    });
    renderPanel({
      api: { list, mutate },
      onReloadLatest: vi.fn(async () => ticketBoundary(1)),
    });
    await add(responderId);

    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reload latest watcher snapshot" }),
    ).toBeVisible();
  });

  it("never applies a historical replay page and replaces it with a canonical GET", async () => {
    const list = vi
      .fn<TicketWatcherApi["list"]>()
      .mockResolvedValueOnce(watcherPage(4))
      .mockResolvedValueOnce(
        watcherPage(6, [watcher("Canonical Current", canonicalId)]),
      );
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) => ({
      ...mutationResult(input, 5, true, [
        watcher("Analyst One", analystId),
        watcher("Historical Replay Only", responderId),
      ]),
      replayed: true,
    }));
    const onReloadLatest = vi.fn(async () => ticketBoundary(6));
    renderPanel({
      api: { list, mutate },
      onReloadLatest,
      ticketEtag: '"v4"',
      ticketVersion: 4,
    });
    await add(responderId);

    expect(await screen.findByText("Canonical Current")).toBeVisible();
    expect(
      screen.queryByText("Historical Replay Only"),
    ).not.toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
    expect(onReloadLatest).toHaveBeenCalledTimes(1);
  });

  it("unlocks after a replayed no-op is replaced by matching canonical reads", async () => {
    const current = watcherPage(4, [
      watcher("Analyst One", analystId),
      watcher("Responder Two", responderId),
    ]);
    const list = vi
      .fn<TicketWatcherApi["list"]>()
      .mockResolvedValueOnce(current)
      .mockResolvedValueOnce(current);
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) =>
      mutationResult(input, 4, true, current.value.items),
    );
    renderPanel({
      api: { list, mutate },
      onReloadLatest: vi.fn(async () => ticketBoundary(4)),
      ticketEtag: '"v4"',
      ticketVersion: 4,
    });
    await add(responderId);

    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    fireEvent.change(screen.getByLabelText("Operator user ID"), {
      target: { value: canonicalId },
    });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Add watcher" })).toBeEnabled(),
    );
    expect(
      screen.queryByRole("button", { name: "Reload latest watcher snapshot" }),
    ).not.toBeInTheDocument();
  });

  it("locks further changes when a saved mutation cannot refresh the ticket", async () => {
    const list = vi.fn<TicketWatcherApi["list"]>(async () => watcherPage(1));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) =>
      mutationResult(input, 2, false),
    );
    renderPanel({
      api: { list, mutate },
      onReloadLatest: vi.fn(async () => null),
    });
    await add(responderId);

    expect(
      await screen.findByText(
        "The watcher change was saved, but the latest ticket snapshot could not be loaded. Reload before changing watchers again.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reload latest watcher snapshot" }),
    ).toBeVisible();
  });

  it("treats a rejected ticket refresh after commit as an uncertainty lock", async () => {
    const list = vi.fn<TicketWatcherApi["list"]>(async () => watcherPage(1));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(async (input) =>
      mutationResult(input, 2, false),
    );
    renderPanel({
      api: { list, mutate },
      onReloadLatest: vi.fn(async () => {
        throw new Error("transport unavailable");
      }),
    });
    await add(responderId);

    expect(
      await screen.findByText(
        "The watcher change was saved, but the latest ticket snapshot could not be loaded. Reload before changing watchers again.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add watcher" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reload latest watcher snapshot" }),
    ).toBeVisible();
  });

  it("does not invalidate a committed mutation from an abandoned concurrent render", async () => {
    const pending = deferred<TicketWatcherMutationResult>();
    const gate = suspensionGate();
    const list = vi.fn<TicketWatcherApi["list"]>(async () => watcherPage(1));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(
      async () => pending.promise,
    );
    render(<ConcurrentWatcherHarness api={{ list, mutate }} gate={gate} />);
    await add(analystId);
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    const signal = mutate.mock.calls[0]?.[0].signal;

    fireEvent.click(
      screen.getByRole("button", { name: "Stage suspended watcher snapshot" }),
    );
    await act(async () => Promise.resolve());
    expect(signal?.aborted).toBe(false);

    await act(async () => {
      pending.resolve(mutationResult(mutate.mock.calls[0]![0], 1, false));
      await pending.promise;
    });
    expect(screen.getByText("Analyst One")).toBeVisible();

    await act(async () => {
      gate.resolve();
      await gate.promise;
    });
  });
});

function renderPanel(overrides: PanelOverrides = {}) {
  return render(panel(overrides));
}

type PanelOverrides = Partial<{
  api: TicketWatcherApi;
  authorityEpoch: string;
  canEdit: boolean;
  canRead: boolean;
  kind: "alert" | "case";
  onReloadLatest: () => Promise<ReloadedTicketBoundary | null>;
  resourceId: string;
  sessionId: string;
  tenantId: string;
  ticketEtag: string;
  ticketVersion: number;
}>;

function panel(overrides: PanelOverrides = {}): React.JSX.Element {
  const kind = overrides.kind ?? "alert";
  return (
    <TicketWatcherPanel
      api={overrides.api ?? apiFixture()}
      authorityEpoch={overrides.authorityEpoch ?? "authority-1"}
      canEdit={overrides.canEdit ?? true}
      canRead={overrides.canRead ?? true}
      csrfToken={sessionFixture.csrfToken}
      kind={kind}
      onReloadLatest={
        overrides.onReloadLatest ??
        (async () =>
          ticketBoundary(overrides.ticketVersion ?? 1, overrides.ticketEtag))
      }
      resourceId={overrides.resourceId ?? (kind === "alert" ? alertId : caseId)}
      sessionId={overrides.sessionId ?? sessionFixture.id}
      tenantId={overrides.tenantId ?? tenantId}
      ticketEtag={overrides.ticketEtag ?? '"v1"'}
      ticketVersion={overrides.ticketVersion ?? 1}
    />
  );
}

function ticketBoundary(
  version: number,
  etag = `"v${version}"`,
): ReloadedTicketBoundary {
  return { etag, version };
}

function apiFixture(): TicketWatcherApi {
  return {
    list: vi.fn(async () => watcherPage(1)),
    mutate: vi.fn(async (input) =>
      mutationResult(input, input.expectedVersion),
    ),
  };
}

async function add(userId: string): Promise<void> {
  fireEvent.change(await screen.findByLabelText("Operator user ID"), {
    target: { value: userId },
  });
  fireEvent.click(screen.getByRole("button", { name: "Add watcher" }));
}

function watcher(displayName: string, userId: string) {
  return {
    addedAt: "2026-09-01T08:00:00Z",
    displayName,
    userId,
  };
}

function watcherPage(
  version: number,
  items: VersionedTicketWatcherPage["value"]["items"] = [
    watcher("Analyst One", analystId),
  ],
): VersionedTicketWatcherPage {
  return {
    etag: `"v${version}"`,
    value: {
      items,
      updatedAt: "2026-09-01T08:05:00Z",
      version,
    },
  };
}

function mutationResult(
  input: TicketWatcherMutationInput,
  version: number,
  replayed = false,
  items: VersionedTicketWatcherPage["value"]["items"] = input.action === "add"
    ? [
        watcher(
          input.userId === analystId ? "Analyst One" : "Responder Two",
          input.userId,
        ),
      ]
    : [],
): TicketWatcherMutationResult {
  return {
    ...watcherPage(version, items),
    changed: version === input.expectedVersion + 1,
    replayed,
  };
}

function ConcurrentWatcherHarness({
  api,
  gate,
}: {
  api: TicketWatcherApi;
  gate: SuspensionGate;
}): React.JSX.Element {
  const [candidate, setCandidate] = useState(false);
  const [suspended, setSuspended] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() =>
          startTransition(() => {
            setCandidate(true);
            setSuspended(true);
          })
        }
      >
        Stage suspended watcher snapshot
      </button>
      <Suspense fallback={<p>Candidate watcher snapshot pending</p>}>
        {panel({
          api,
          ticketEtag: candidate ? '"v2"' : '"v1"',
          ticketVersion: candidate ? 2 : 1,
        })}
        {suspended ? <SuspendUntilCommitted gate={gate} /> : null}
      </Suspense>
    </>
  );
}

interface SuspensionGate {
  promise: Promise<void>;
  resolve: () => void;
  settled: boolean;
}

function SuspendUntilCommitted({ gate }: { gate: SuspensionGate }): null {
  if (!gate.settled) throw gate.promise;
  return null;
}

function suspensionGate(): SuspensionGate {
  let accept!: () => void;
  const gate: SuspensionGate = {
    promise: new Promise<void>((resolve) => {
      accept = resolve;
    }),
    resolve: () => {
      gate.settled = true;
      accept();
    },
    settled: false,
  };
  return gate;
}

function deferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept, decline) => {
    reject = decline;
    resolve = accept;
  });
  return { promise, reject, resolve };
}
