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
  TicketMetadataApiError,
  type TicketMetadataApi,
  type TicketMetadataReplaceInput,
  type VersionedTicketMetadata,
} from "./ticket-metadata-api";
import { TicketMetadataPanel } from "./ticket-metadata-panel";
import {
  alertId,
  caseId,
  operatorAlert,
  operatorCase,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("TicketMetadataPanel", () => {
  it("normalizes and submits the exact Alert replacement without a Summary field", async () => {
    const replace = vi.fn<TicketMetadataApi["replace"]>(async (input) =>
      metadataResult(input),
    );
    const onReloadLatest = vi.fn(async () => true);
    render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    expect(screen.queryByLabelText("Summary")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "\u2003Correlated endpoint signal\u2003" },
    });
    fireEvent.change(screen.getByLabelText("Classification"), {
      target: { value: "   " },
    });
    fireEvent.change(screen.getByLabelText("Tags"), {
      target: { value: "windows, endpoint" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith({
      body: {
        category: operatorAlert.category,
        classification: null,
        customerVisible: operatorAlert.customerVisible,
        description: operatorAlert.description,
        priority: operatorAlert.priority,
        severity: operatorAlert.severity,
        tags: ["endpoint", "windows"],
        title: "Correlated endpoint signal",
      },
      csrfToken: sessionFixture.csrfToken,
      etag: '"v1"',
      expectedVersion: 1,
      idempotencyKey: expect.any(String),
      kind: "alert",
      resourceId: alertId,
      signal: expect.any(AbortSignal),
      tenantId,
    });
    await waitFor(() => expect(onReloadLatest).toHaveBeenCalledTimes(1));
    expect(
      screen.queryByRole("button", { name: "Save core details" }),
    ).not.toBeInTheDocument();
  });

  it("renders and submits the Case-only Summary field", async () => {
    const replace = vi.fn<TicketMetadataApi["replace"]>(async (input) =>
      metadataResult(input),
    );
    render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="case"
        onReloadLatest={async () => true}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorCase }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    expect(screen.getByLabelText("Summary")).toHaveValue(operatorCase.summary);
    fireEvent.change(screen.getByLabelText("Summary"), {
      target: { value: "Expanded investigation scope" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          summary: "Expanded investigation scope",
        }),
        kind: "case",
        resourceId: caseId,
      }),
    );
  });

  it("aborts and hides an in-flight editor as soon as live edit authority is revoked", async () => {
    const pending = deferred<VersionedTicketMetadata>();
    const replace = vi.fn<TicketMetadataApi["replace"]>(
      async () => pending.promise,
    );
    const onReloadLatest = vi.fn(async () => true);
    const view = render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    const signal = replace.mock.calls[0]?.[0].signal;
    expect(signal).toBeInstanceOf(AbortSignal);

    view.rerender(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit={false}
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(
      screen.getByText(
        "Core details are read-only under the current live tenant authority.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Save core details" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve(metadataResult(replace.mock.calls[0]![0]));
      await pending.promise;
    });
    expect(onReloadLatest).not.toHaveBeenCalled();
  });

  it("preserves an in-flight draft across equivalent ticket clones and resets on a new snapshot", async () => {
    const pending = deferred<VersionedTicketMetadata>();
    const replace = vi.fn<TicketMetadataApi["replace"]>(
      async () => pending.promise,
    );
    const onReloadLatest = vi.fn(async () => true);
    const view = render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "Preserved in-flight draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    const signal = replace.mock.calls[0]?.[0].signal;

    view.rerender(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: { ...operatorAlert } }}
      />,
    );

    expect(signal?.aborted).toBe(false);
    expect(screen.getByLabelText("Title")).toHaveValue(
      "Preserved in-flight draft",
    );
    expect(
      screen.getByRole("button", { name: "Saving core details…" }),
    ).toBeDisabled();

    view.rerender(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{
          etag: '"v2"',
          value: { ...operatorAlert, version: 2 },
        }}
      />,
    );

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(screen.queryByLabelText("Title")).not.toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Edit core details" }),
    ).toBeVisible();

    await act(async () => {
      pending.resolve(metadataResult(replace.mock.calls[0]![0]));
      await pending.promise;
    });
    expect(onReloadLatest).not.toHaveBeenCalled();
  });

  it("does not invalidate the committed request from an abandoned concurrent snapshot render", async () => {
    const pending = deferred<VersionedTicketMetadata>();
    const gate = suspensionGate();
    const replace = vi.fn<TicketMetadataApi["replace"]>(
      async () => pending.promise,
    );
    const onReloadLatest = vi.fn(async () => true);
    render(
      <ConcurrentMetadataHarness
        gate={gate}
        onReloadLatest={onReloadLatest}
        replace={replace}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));

    fireEvent.click(
      screen.getByRole("button", { name: "Stage suspended snapshot" }),
    );
    await act(async () => Promise.resolve());

    await act(async () => {
      pending.resolve(metadataResult(replace.mock.calls[0]![0]));
      await pending.promise;
    });
    await waitFor(() => expect(onReloadLatest).toHaveBeenCalledTimes(1));

    await act(async () => {
      gate.resolve();
      await gate.promise;
    });
  });

  it("keeps stale-snapshot editing closed while a successful save refreshes", async () => {
    const refresh = deferred<boolean>();
    const replace = vi.fn<TicketMetadataApi["replace"]>(async (input) =>
      metadataResult(input),
    );
    const onReloadLatest = vi.fn(async () => refresh.promise);
    render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));
    await waitFor(() => expect(onReloadLatest).toHaveBeenCalledTimes(1));

    expect(
      screen.queryByRole("button", { name: "Edit core details" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Save core details" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      refresh.resolve(true);
      await refresh.promise;
    });
    expect(
      await screen.findByRole("button", { name: "Edit core details" }),
    ).toBeVisible();
  });

  it("refreshes the latest snapshot after a stale precondition response", async () => {
    const replace = vi.fn<TicketMetadataApi["replace"]>(async () => {
      throw new TicketMetadataApiError(
        "This ticket changed. Reload the latest snapshot before retrying.",
        412,
      );
    });
    const onReloadLatest = vi.fn(async () => true);
    render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));

    expect(
      await screen.findByText(
        "This ticket changed. Reload the latest snapshot before retrying.",
      ),
    ).toBeVisible();
    expect(onReloadLatest).toHaveBeenCalledTimes(1);
  });

  it("locks editing after save when the refreshed snapshot cannot be loaded", async () => {
    const replace = vi.fn<TicketMetadataApi["replace"]>(async (input) =>
      metadataResult(input),
    );
    const onReloadLatest = vi.fn(async () => false);
    render(
      <TicketMetadataPanel
        api={{ replace }}
        canEdit
        csrfToken={sessionFixture.csrfToken}
        kind="alert"
        onReloadLatest={onReloadLatest}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
        ticket={{ etag: '"v1"', value: operatorAlert }}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));

    expect(
      await screen.findByText(
        "Changes were saved, but the latest ticket snapshot could not be loaded. Reload before editing again.",
      ),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Reload latest" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Edit core details" }),
    ).not.toBeInTheDocument();
  });
});

function metadataResult(
  input: TicketMetadataReplaceInput,
): VersionedTicketMetadata {
  const etag = `"v${input.expectedVersion + 1}"`;
  const updatedAt = "2026-08-31T08:30:00Z";
  const version = input.expectedVersion + 1;
  if (input.kind === "alert") {
    return {
      etag,
      value: {
        ...input.body,
        id: input.resourceId,
        kind: "alert",
        updatedAt,
        version,
      },
    };
  }
  return {
    etag,
    value: {
      ...input.body,
      id: input.resourceId,
      kind: "case",
      updatedAt,
      version,
    },
  };
}

function ConcurrentMetadataHarness({
  gate,
  onReloadLatest,
  replace,
}: {
  gate: SuspensionGate;
  onReloadLatest: () => Promise<boolean>;
  replace: TicketMetadataApi["replace"];
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
        Stage suspended snapshot
      </button>
      <Suspense fallback={<p>Candidate snapshot pending</p>}>
        <TicketMetadataPanel
          api={{ replace }}
          canEdit
          csrfToken={sessionFixture.csrfToken}
          kind="alert"
          onReloadLatest={onReloadLatest}
          sessionId={sessionFixture.id}
          tenantId={tenantId}
          ticket={
            candidate
              ? {
                  etag: '"v2"',
                  value: { ...operatorAlert, version: 2 },
                }
              : { etag: '"v1"', value: operatorAlert }
          }
        />
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
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
