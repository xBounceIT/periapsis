import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { sessionFixture } from "../test/phase-two-fixtures";
import {
  CaseContactApiError,
  type ActiveCaseContact,
  type CaseContactApi,
  type CaseContactLink,
} from "./case-contact-api";
import {
  CaseContactPanel,
  type ReloadedCaseBoundary,
} from "./case-contact-panel";
import { caseId, tenantId } from "./ticketing-test-fixtures";

const firstContactId = "0198c97d-cf4f-7000-8000-000000000020";
const secondContactId = "0198c97d-cf4f-7000-8000-000000000021";
const availableContactId = "0198c97d-cf4f-7000-8000-000000000022";
const firstLinkId = "0198c97d-cf4f-7000-8000-000000000030";
const secondLinkId = "0198c97d-cf4f-7000-8000-000000000031";

afterEach(cleanup);

describe("CaseContactPanel", () => {
  it("loads reachable second pages for relationships and active contact inventory", async () => {
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(async (input) =>
      input.after
        ? { items: [link(secondLinkId, secondContactId, "watcher")] }
        : {
            items: [link(firstLinkId, firstContactId, "primary")],
            nextCursor: "next_links",
          },
    );
    const listActiveContacts = vi.fn<CaseContactApi["listActiveContacts"]>(
      async (input) =>
        input.after
          ? { items: [contact(secondContactId, "Backup", "Owner")] }
          : {
              items: [contact(firstContactId, "Case", "Owner")],
              nextCursor: "next_contacts",
            },
    );
    renderPanel({
      api: apiFixture({ listActiveContacts, listLinks }),
      canEdit: false,
    });

    expect(await screen.findByText("Case Owner")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load more linked contacts" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Load more active contacts" }),
    );

    expect(await screen.findByText("Backup Owner")).toBeVisible();
    expect(listLinks).toHaveBeenLastCalledWith(
      expect.objectContaining({ after: "next_links", limit: 50 }),
    );
    expect(listActiveContacts).toHaveBeenLastCalledWith(
      expect.objectContaining({ after: "next_contacts", limit: 50 }),
    );
    expect(screen.queryByRole("button", { name: "Link contact" })).toBeNull();
  });

  it("fails closed when a later page repeats a relationship projection", async () => {
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(async (input) =>
      input.after
        ? { items: [link(firstLinkId, firstContactId, "primary")] }
        : {
            items: [link(firstLinkId, firstContactId, "primary")],
            nextCursor: "next_links",
          },
    );
    renderPanel({ api: apiFixture({ listLinks }) });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Load more linked contacts",
      }),
    );

    expect(
      await screen.findByText(
        "The Case contact projection was not safe to apply. Reload the current authorized snapshot.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Link contact" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Remove .* from Case/u }),
    ).not.toBeInTheDocument();
  });

  it("fails closed when distinct relationship rows repeat the same contact", async () => {
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(async (input) =>
      input.after
        ? { items: [link(secondLinkId, firstContactId, "watcher")] }
        : {
            items: [link(firstLinkId, firstContactId, "primary")],
            nextCursor: "next_links",
          },
    );
    renderPanel({ api: apiFixture({ listLinks }) });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Load more linked contacts",
      }),
    );

    expect(
      await screen.findByText(
        "The Case contact projection was not safe to apply. Reload the current authorized snapshot.",
      ),
    ).toBeVisible();
    expect(screen.queryByText("No customer contacts linked")).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Load more linked contacts" }),
    ).toBeNull();
  });

  it("makes no reads or writes without live read authority and keeps actions absent without update authority", async () => {
    const archive = vi.fn<CaseContactApi["archive"]>();
    const linkContact = vi.fn<CaseContactApi["link"]>();
    const listActiveContacts = vi.fn<CaseContactApi["listActiveContacts"]>(
      async () => ({ items: [] }),
    );
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(async () => ({
      items: [],
    }));
    const api = apiFixture({
      archive,
      link: linkContact,
      listActiveContacts,
      listLinks,
    });
    const view = renderPanel({ api, canRead: false });
    await act(async () => Promise.resolve());
    expect(listLinks).not.toHaveBeenCalled();
    expect(listActiveContacts).not.toHaveBeenCalled();
    expect(linkContact).not.toHaveBeenCalled();
    expect(archive).not.toHaveBeenCalled();

    view.rerender(panel({ api, canEdit: false, canRead: true }));
    expect(
      await screen.findByText("No customer contacts linked"),
    ).toBeVisible();
    expect(screen.queryByLabelText("Active customer contact")).toBeNull();
    expect(
      screen.queryByRole("button", { name: /Remove .* from Case/u }),
    ).toBeNull();
    expect(linkContact).not.toHaveBeenCalled();
    expect(archive).not.toHaveBeenCalled();
  });

  it("aborts an in-flight mutation and discards its completion when authority is revoked", async () => {
    const pending = deferred<CaseContactLink>();
    const linkContact = vi.fn<CaseContactApi["link"]>(
      async () => pending.promise,
    );
    const reload = vi.fn(async () => boundary(2));
    const api = apiFixture({ link: linkContact });
    const view = renderPanel({ api, onReloadLatest: reload });
    await selectAvailableContact();
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    await waitFor(() => expect(linkContact).toHaveBeenCalledTimes(1));
    const signal = linkContact.mock.calls[0]?.[0].signal;

    view.rerender(
      panel({
        api,
        authorityEpoch: "authority-revoked",
        canRead: false,
        onReloadLatest: reload,
      }),
    );
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText("Customer contacts")).toBeNull();

    await act(async () => {
      pending.resolve(link(firstLinkId, availableContactId, "primary"));
      await pending.promise;
    });
    expect(reload).not.toHaveBeenCalled();
  });

  it("aborts an in-flight mutation on Case snapshot drift without discarding the draft", async () => {
    const pending = deferred<CaseContactLink>();
    const linkContact = vi.fn<CaseContactApi["link"]>(async (input) => {
      if (input.expectedCaseVersion === 1) return pending.promise;
      return link(firstLinkId, input.contactId, input.role);
    });
    const api = apiFixture({ link: linkContact });
    const view = renderPanel({ api });
    await selectAvailableContact();
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    await waitFor(() => expect(linkContact).toHaveBeenCalledTimes(1));
    const firstCall = linkContact.mock.calls[0]?.[0];

    view.rerender(panel({ api, caseEtag: '"v2"', caseVersion: 2 }));

    expect(firstCall?.signal?.aborted).toBe(true);
    expect(screen.getByLabelText("Active customer contact")).toHaveValue(
      availableContactId,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Link contact" }),
      ).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    await waitFor(() => expect(linkContact).toHaveBeenCalledTimes(2));

    const secondCall = linkContact.mock.calls[1]?.[0];
    expect(secondCall?.expectedCaseVersion).toBe(2);
    expect(secondCall?.caseEtag).toBe('"v2"');
    expect(secondCall?.idempotencyKey).not.toBe(firstCall?.idempotencyKey);
  });

  it("reloads stale Case CAS, preserves the draft, and rotates the key only for the new version", async () => {
    const calls: Parameters<CaseContactApi["link"]>[0][] = [];
    const linkContact = vi.fn<CaseContactApi["link"]>(async (input) => {
      calls.push(input);
      if (calls.length === 1) {
        throw new CaseContactApiError("Stale Case snapshot.", 412);
      }
      return link(firstLinkId, input.contactId, input.role);
    });
    render(<StaleBoundaryHarness api={apiFixture({ link: linkContact })} />);
    await selectAvailableContact();
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));

    expect(await screen.findByText("Stale Case snapshot.")).toBeVisible();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Link contact" }),
      ).toBeEnabled(),
    );
    expect(screen.getByLabelText("Active customer contact")).toHaveValue(
      availableContactId,
    );
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    await waitFor(() => expect(linkContact).toHaveBeenCalledTimes(2));

    expect(calls.map((call) => call.expectedCaseVersion)).toEqual([1, 2]);
    expect(calls.map((call) => call.caseEtag)).toEqual(['"v1"', '"v2"']);
    expect(calls[1]?.idempotencyKey).not.toBe(calls[0]?.idempotencyKey);
  });

  it("reuses the same retry key after a transient failure with an unchanged payload", async () => {
    const calls: Parameters<CaseContactApi["link"]>[0][] = [];
    const linkContact = vi.fn<CaseContactApi["link"]>(async (input) => {
      calls.push(input);
      if (calls.length === 1) {
        throw new CaseContactApiError("Dependency unavailable.", 503);
      }
      return link(firstLinkId, input.contactId, input.role);
    });
    renderPanel({ api: apiFixture({ link: linkContact }) });
    await selectAvailableContact();
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    expect(await screen.findByText("Dependency unavailable.")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Link contact" }));
    await waitFor(() => expect(linkContact).toHaveBeenCalledTimes(2));

    expect(calls[1]?.idempotencyKey).toBe(calls[0]?.idempotencyKey);
  });
});

function StaleBoundaryHarness({
  api,
}: {
  api: CaseContactApi;
}): React.JSX.Element {
  const [version, setVersion] = useState(1);
  return (
    <PanelHarness
      api={api}
      caseEtag={`"v${version}"`}
      caseVersion={version}
      onReloadLatest={async () => {
        setVersion(2);
        return boundary(2);
      }}
    />
  );
}

function renderPanel(overrides: PanelOverrides = {}) {
  return render(panel(overrides));
}

function panel(overrides: PanelOverrides = {}): React.JSX.Element {
  return <PanelHarness {...overrides} />;
}

function PanelHarness(overrides: PanelOverrides): React.JSX.Element {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: false } },
      }),
  );
  const [fallbackApi] = useState(apiFixture);
  return (
    <QueryClientProvider client={queryClient}>
      <CaseContactPanel
        api={overrides.api ?? fallbackApi}
        authorityEpoch={overrides.authorityEpoch ?? "authority-ready"}
        canEdit={overrides.canEdit ?? true}
        canRead={overrides.canRead ?? true}
        caseEtag={overrides.caseEtag ?? '"v1"'}
        caseId={caseId}
        caseVersion={overrides.caseVersion ?? 1}
        csrfToken={sessionFixture.csrfToken}
        onReloadLatest={overrides.onReloadLatest ?? (async () => boundary(2))}
        sessionId={sessionFixture.id}
        tenantId={tenantId}
      />
    </QueryClientProvider>
  );
}

type PanelOverrides = Partial<{
  api: CaseContactApi;
  authorityEpoch: string;
  canEdit: boolean;
  canRead: boolean;
  caseEtag: string;
  caseVersion: number;
  onReloadLatest: () => Promise<ReloadedCaseBoundary | null>;
}>;

function apiFixture(overrides: Partial<CaseContactApi> = {}): CaseContactApi {
  return {
    archive: vi.fn(async (input) => ({
      ...input.link,
      archivedAt: "2026-09-02T08:05:00Z",
      version: input.link.version + 1,
    })),
    link: vi.fn(async (input) =>
      link(firstLinkId, input.contactId, input.role),
    ),
    listActiveContacts: vi.fn(async () => ({
      items: [
        contact(firstContactId, "Case", "Owner"),
        contact(availableContactId, "Incident", "Manager"),
      ],
    })),
    listLinks: vi.fn(async () => ({
      items: [link(firstLinkId, firstContactId, "primary")],
    })),
    ...overrides,
  };
}

function link(
  id: string,
  contactId: string,
  role: CaseContactLink["role"],
): CaseContactLink {
  return {
    contactId,
    createdAt: "2026-09-02T08:00:00Z",
    id,
    origin: "manual",
    resourceId: caseId,
    resourceKind: "case",
    role,
    tenantId,
    version: 1,
  };
}

function contact(
  id: string,
  firstName: string,
  lastName: string,
): ActiveCaseContact {
  return {
    active: true,
    contactClass: "customer",
    createdAt: "2026-09-01T08:00:00Z",
    email: `${firstName.toLowerCase()}@example.test`,
    emailAllowed: true,
    escalationPriority: 1,
    firstName,
    function: "Incident owner",
    id,
    language: "en",
    lastName,
    notificationCategories: ["incident"],
    notificationWindows: [],
    tags: [],
    tenantId,
    timezone: "Europe/Rome",
    updatedAt: "2026-09-01T08:00:00Z",
    version: 1,
  };
}

function boundary(version: number): ReloadedCaseBoundary {
  return { etag: `"v${version}"`, version };
}

async function selectAvailableContact(): Promise<void> {
  await screen.findByRole("option", {
    name: "Incident Manager · incident@example.test",
  });
  fireEvent.change(await screen.findByLabelText("Active customer contact"), {
    target: { value: availableContactId },
  });
  expect(screen.getByRole("button", { name: "Link contact" })).toBeEnabled();
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
