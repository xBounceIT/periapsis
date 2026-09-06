import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import type { TicketExportJobRequest } from "@periapsis/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "../app";
import { appRouteTitle } from "../app-model";
import { SessionContext } from "../auth/session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "../auth/tenant-authority-context";
import type {
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { TenantDateTimeProvider } from "../lib/tenant-date-time-context";
import type {
  TicketExportApi,
  TicketExportJobView,
} from "../lib/ticket-export-api";
import type { TicketingApi } from "../lib/ticketing-api";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { reportingRouteDescriptor } from "./reporting-model";
import { ReportingPage } from "./reporting-page";
import { mergeReportSavedViewPages } from "./reporting-page-model";
import { TicketExportApiProvider } from "./ticket-export-context";
import { TicketingApiProvider } from "./ticketing-context";
import {
  createTicketingApi,
  savedAlertView,
  teamId,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(() => {
  cleanup();
  document.title = "";
  vi.restoreAllMocks();
});

describe("operator Reports page", () => {
  it("requires an active tenant and sends no reporting calls without one", async () => {
    const listSavedTicketViews = vi.fn();
    const request = vi.fn();
    renderReports({
      activeTenantId: null,
      exportApi: createExportApi({ request }),
      permissions: ["alert.read", "case.read"],
      ticketingApi: createTicketingApi({ listSavedTicketViews }),
    });

    expect(
      await screen.findByRole("heading", {
        name: "Select a tenant before opening Reports",
      }),
    ).toBeVisible();
    expect(listSavedTicketViews).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
  });

  it("denies by default and never calls report APIs without live read authority", async () => {
    const listSavedTicketViews = vi.fn();
    const request = vi.fn();
    renderReports({
      exportApi: createExportApi({ request }),
      permissions: [],
      ticketingApi: createTicketingApi({ listSavedTicketViews }),
    });

    expect(
      await screen.findByRole("heading", { name: "Reports are not available" }),
    ).toBeVisible();
    expect(listSavedTicketViews).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Review export" })).toBeNull();
  });

  it("falls back to the only authorized Case kind without requesting Alerts", async () => {
    const listSavedTicketViews = vi.fn<TicketingApi["listSavedTicketViews"]>(
      async () => ({ items: [] }),
    );
    renderReports({
      permissions: ["case.read"],
      ticketingApi: createTicketingApi({ listSavedTicketViews }),
    });

    const kind = await screen.findByRole("combobox", { name: "Ticket type" });
    expect(kind).toHaveValue("case");
    expect(screen.getByRole("option", { name: "Cases" })).toBeVisible();
    expect(screen.queryByRole("option", { name: "Alerts" })).toBeNull();
    await waitFor(() => expect(listSavedTicketViews).toHaveBeenCalledTimes(1));
    expect(listSavedTicketViews.mock.calls[0]?.[0]).toMatchObject({
      includeArchived: false,
      kind: "case",
      tenantId,
    });
  });

  it("requires comment-read and private-comment grants at the ticket-read scope", async () => {
    renderReports({
      permissionGrants: [
        { permissionKey: "alert.read", scope: "tenant" },
        { permissionKey: "alert.comment.read", scope: "assigned" },
        { permissionKey: "alert.comment.private", scope: "tenant" },
      ],
      permissions: [],
    });
    await screen.findByRole("button", { name: "Review export" });
    expect(
      screen.queryByRole("option", { name: "Public comments" }),
    ).toBeNull();
    expect(
      screen.queryByRole("option", { name: "Public and private comments" }),
    ).toBeNull();

    cleanup();
    renderReports({
      permissionGrants: [
        { permissionKey: "alert.read", scope: "assigned" },
        { permissionKey: "alert.comment.read", scope: "assigned" },
        { permissionKey: "alert.comment.private", scope: "tenant" },
      ],
      permissions: [],
    });
    expect(
      await screen.findByRole("option", { name: "Public comments" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", { name: "Public and private comments" }),
    ).toBeNull();

    cleanup();
    renderReports({
      permissionGrants: [
        { permissionKey: "alert.read", scope: "operator_team" },
        { permissionKey: "alert.comment.read", scope: "operator_team" },
        { permissionKey: "alert.comment.private", scope: "operator_team" },
      ],
      permissions: [],
    });
    expect(
      await screen.findByRole("option", {
        name: "Public and private comments",
      }),
    ).toBeVisible();
  });

  it("makes saved-view pagination reachable and queues the exact selected pin", async () => {
    const secondView = {
      ...savedAlertView,
      id: "0198c97d-cf4f-7000-8000-000000000021",
      name: "Second-page view",
      revision: 4,
      specSha256: "d".repeat(64),
    };
    const listSavedTicketViews = vi
      .fn()
      .mockResolvedValueOnce({
        items: [savedAlertView],
        nextCursor: savedViewCursor,
      })
      .mockResolvedValueOnce({ items: [secondView] });
    let latestJob: TicketExportJobView | undefined;
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => {
        latestJob = completedExportJob(body);
        return { job: latestJob, replayed: false };
      },
    );
    const get = vi.fn(async () => latestJob!);
    renderReports({
      exportApi: createExportApi({ get, request }),
      permissions: ["alert.read"],
      ticketingApi: createTicketingApi({ listSavedTicketViews }),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more saved views" }),
    );
    expect(
      await screen.findByRole("option", { name: "Second-page view" }),
    ).toBeVisible();
    expect(listSavedTicketViews).toHaveBeenLastCalledWith(
      expect.objectContaining({
        after: savedViewCursor,
        includeArchived: false,
        kind: "alert",
        tenantId,
      }),
    );
    fireEvent.change(
      screen.getByRole("combobox", { name: "Saved-view source" }),
      { target: { value: secondView.id } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]?.[0]).toMatchObject({
      body: {
        comments: "none",
        kind: "alert",
        maximumRows: 10_000,
        retentionSeconds: 86_400,
        source: {
          savedView: {
            expectedRevision: secondView.revision,
            expectedSpecSha256: secondView.specSha256,
            id: secondView.id,
          },
          source: "saved_view",
        },
      },
      csrfToken: sessionFixture.csrfToken,
      tenantId,
    });
  });

  it("aborts saved-source loading and exposes no actions after live revocation", async () => {
    let authorityCall = 0;
    const permitted = authorityFixture(["alert.read"]);
    const revoked = authorityFixture([]);
    let inventorySignal: AbortSignal | undefined;
    const listSavedTicketViews = vi.fn(
      ({
        signal,
      }: Parameters<
        ReturnType<typeof createTicketingApi>["listSavedTicketViews"]
      >[0]) => {
        inventorySignal = signal;
        return new Promise<never>(() => undefined);
      },
    );
    const request = vi.fn();
    renderReports({
      exportApi: createExportApi({ request }),
      getTenantAuthority: async () =>
        authorityCall++ === 0 ? permitted : revoked,
      permissions: [],
      ticketingApi: createTicketingApi({ listSavedTicketViews }),
      withReloadControl: true,
    });

    await screen.findByRole("button", { name: "Review export" });
    await waitFor(() => expect(listSavedTicketViews).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    expect(
      await screen.findByRole("heading", { name: "Reports are not available" }),
    ).toBeVisible();
    expect(inventorySignal?.aborted).toBe(true);
    expect(listSavedTicketViews).toHaveBeenCalledTimes(1);
    expect(request).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Review export" })).toBeNull();
  });

  it("rejects archived, duplicate, and descending saved-view pages", () => {
    expect(
      mergeReportSavedViewPages(
        [{ items: [{ ...savedAlertView, status: "archived" }] }],
        savedViewBoundary,
      ),
    ).toEqual({ invalid: true, items: [] });
    expect(
      mergeReportSavedViewPages(
        [{ items: [savedAlertView] }, { items: [savedAlertView] }],
        savedViewBoundary,
      ),
    ).toEqual({ invalid: true, items: [] });
    expect(
      mergeReportSavedViewPages(
        [
          {
            items: [
              {
                ...savedAlertView,
                ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000099",
              },
            ],
          },
        ],
        savedViewBoundary,
      ),
    ).toEqual({ invalid: true, items: [] });
  });
});

describe("Reports route integration", () => {
  it("registers the lazy top-level route and stable title", () => {
    const mainSource = readFileSync(
      resolve(process.cwd(), "src", "main.tsx"),
      "utf8",
    );
    expect(mainSource).toContain(
      "path: childRoutePath(reportingRouteDescriptor.path)",
    );
    expect(mainSource).toContain('import("./ticketing/reporting-page")');
    expect(appRouteTitle(reportingRouteDescriptor.path)).toBe("Reports");
  });

  it("shows Reports in navigation only from live tenant ticket authority", async () => {
    renderShell(authorityFixture(["case.read"]));

    expect(
      await screen.findByRole("link", { name: "Reports" }),
    ).toHaveAttribute("href", "/reports");
    await waitFor(() => expect(document.title).toBe("Reports · Periapsis"));

    cleanup();
    renderShell(authorityFixture([]), ["case.read"]);
    await screen.findByText("Reports outlet");
    expect(screen.queryByRole("link", { name: "Reports" })).toBeNull();
  });
});

function renderReports({
  activeTenantId = tenantId,
  exportApi = createExportApi(),
  getTenantAuthority,
  permissionGrants,
  permissions,
  ticketingApi = createTicketingApi(),
  withReloadControl = false,
}: {
  activeTenantId?: string | null;
  exportApi?: TicketExportApi;
  getTenantAuthority?: () => Promise<TenantAuthorityView>;
  permissionGrants?: TenantAuthorityView["permissions"];
  permissions: readonly TenantPermissionKeyView[];
  ticketingApi?: ReturnType<typeof createTicketingApi>;
  withReloadControl?: boolean;
}): ReturnType<typeof render> {
  const authority = authorityFixture(permissions, permissionGrants);
  const phaseApi = createPhaseTwoApi({
    getTenantAuthority: async () =>
      getTenantAuthority ? getTenantAuthority() : authority,
  });
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-25T12:00:00Z",
    ...(activeTenantId ? { activeTenantId } : {}),
    idleExpiresAt: "2099-08-25T11:00:00Z",
  };
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <TenantDateTimeProvider locale="it-IT" timeZone="Europe/Rome">
            <TicketingApiProvider api={ticketingApi}>
              <TicketExportApiProvider api={exportApi}>
                <MemoryRouter>
                  <ReportingPage />
                  {withReloadControl ? <AuthorityReloadControl /> : null}
                </MemoryRouter>
              </TicketExportApiProvider>
            </TicketingApiProvider>
          </TenantDateTimeProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function renderShell(
  authority: TenantAuthorityView,
  sessionPermissions: readonly string[] = [],
): void {
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId: authority.tenantId,
    idleExpiresAt: "2099-08-23T12:00:00Z",
    permissions: sessionPermissions,
  };
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authority,
    listMemberships: async () => ({ items: [] }),
  });
  render(
    <MemoryRouter initialEntries={[reportingRouteDescriptor.path]}>
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <Routes>
          <Route element={<AppShell />}>
            <Route path="reports" element={<p>Reports outlet</p>} />
          </Route>
        </Routes>
      </SessionContext.Provider>
    </MemoryRouter>,
  );
}

function AuthorityReloadControl(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button type="button" onClick={authority.reload}>
      Reload authority
    </button>
  );
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
  permissionGrants?: TenantAuthorityView["permissions"],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-09-02T08:00:00Z",
    legacyMembershipRole: "analyst",
    membershipId: "0198c97d-cf4f-7000-8000-000000000015",
    membershipStatus: "active",
    operatorTeamRelationships: [
      {
        assignmentEpochId: "0198c97d-cf4f-7000-8000-000000000018",
        operatorTeamId: teamId,
      },
    ],
    permissions:
      permissionGrants ??
      permissions.map((permissionKey) => ({
        permissionKey,
        scope: "tenant",
      })),
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}

const unsupportedExportCall = async (): Promise<never> => {
  throw new Error("Unexpected TicketExportApi call in test");
};

const savedViewBoundary = {
  kind: "alert",
  ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000015",
  tenantId,
} as const;
const savedViewCursor = "AZjJfc9PcACAAAAAAAAAIA";

function createExportApi(
  overrides: Partial<TicketExportApi> = {},
): TicketExportApi {
  return {
    cancel: unsupportedExportCall,
    download: unsupportedExportCall,
    get: unsupportedExportCall,
    request: unsupportedExportCall,
    ...overrides,
  };
}

function completedExportJob(body: TicketExportJobRequest): TicketExportJobView {
  const savedView =
    body.source.source === "saved_view" ? body.source.savedView : undefined;
  return {
    artifact: {
      bytes: 21,
      expiresAt: "2099-08-27T18:00:00Z",
      id: "0198c97d-cf4f-7000-8000-000000000092",
      rows: 1,
      sha256: "e".repeat(64),
    },
    attempts: 1,
    availableAt: "2026-08-26T18:00:00Z",
    comments: body.comments,
    expiresAt: "2099-08-27T18:00:00Z",
    failureCode: "none",
    id: "0198c97d-cf4f-7000-8000-000000000093",
    kind: body.kind,
    maximumAttempts: 5,
    maximumBytes: body.maximumBytes ?? 67_108_864,
    maximumRows: body.maximumRows ?? 10_000,
    ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000015",
    query: {
      catalogSha256: "b".repeat(64),
      querySha256: savedView?.expectedSpecSha256 ?? "d".repeat(64),
      ...(savedView
        ? {
            savedView: {
              id: savedView.id,
              ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000015",
              revision: savedView.expectedRevision,
              specSha256: savedView.expectedSpecSha256,
            },
          }
        : {}),
      source: body.source.source,
    },
    requestedAt: "2026-08-26T18:00:00Z",
    requesterUserId: sessionFixture.user.id,
    revision: 3,
    state: "succeeded",
    tenantId,
    terminalAt: "2026-08-26T18:01:00Z",
    updatedAt: "2026-08-26T18:01:00Z",
  };
}
