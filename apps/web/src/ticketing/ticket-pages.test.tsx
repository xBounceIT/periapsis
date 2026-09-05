import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import type {
  AlertOperatorProjection,
  SavedTicketView,
} from "@periapsis/contracts";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  createAuditApiMock,
  tenantAuditEventFixture,
} from "../audit/audit-test-fixtures";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "../auth/tenant-authority-context";
import type {
  CustomFieldAdministrationApi,
  CustomFieldObjectApi,
  CustomFieldObjectProjectionView,
} from "../customfields/custom-field-api";
import type { CustomFieldDefinitionView } from "../customfields/model";
import {
  projectAlertWorkspace,
  type AlertDfirApi,
} from "../dfir/alert-dfir-api";
import { AlertDfirApiProvider } from "../dfir/alert-dfir-context";
import { boundAlertDfirWorkspaceFixture } from "../dfir/alert-dfir-test-fixtures";
import {
  caseDfirApi,
  projectWorkspace,
  type CaseDfirApi,
} from "../dfir/case-dfir-api";
import { CaseDfirApiProvider } from "../dfir/case-dfir-context";
import { alertDfirReadPermissions, dfirReadPermissions } from "../dfir/model";
import { dfirWorkspaceFixture } from "../dfir/case-dfir-test-fixtures";
import {
  ticketBulkApi,
  type TicketBulkApi,
  type TicketBulkJobView,
} from "../lib/ticket-bulk-api";
import {
  ticketExportApi,
  type TicketExportApi,
  type TicketExportJobView,
} from "../lib/ticket-export-api";
import type { TicketColumnCatalogApi } from "../lib/ticket-column-catalog-api";
import { TicketingApiError, type TicketComment } from "../lib/ticketing-api";
import type {
  TenantAuthorityView,
  TenantAuthorizationScopeView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  AlertDetailPage,
  CaseDetailPage,
  TicketDetailPage,
} from "./ticket-detail-page";
import type { CaseContactApi } from "./case-contact-api";
import type { AlertRelationApi } from "./alert-relation-api";
import { AlertCreatePage, TicketCreatePage } from "./ticket-create-page";
import { AlertListPage, CaseListPage } from "./ticket-list-page";
import { TicketBulkApiProvider } from "./ticket-bulk-context";
import { TicketColumnCatalogApiProvider } from "./ticket-column-catalog-context";
import { TicketExportApiProvider } from "./ticket-export-context";
import {
  TicketMetadataApiError,
  type TicketMetadataApi,
  type VersionedTicketMetadata,
} from "./ticket-metadata-api";
import type {
  TicketWatcherApi,
  TicketWatcherMutationResult,
} from "./ticket-watcher-api";
import { TicketingApiProvider } from "./ticketing-context";
import {
  alertId,
  caseId,
  createTicketingApi,
  customerAlert,
  membershipId,
  operatorAlert,
  operatorAlertWithDynamicColumns,
  operatorCase,
  savedAlertView,
  savedViewId,
  customDefinitionId,
  teamId,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("Phase 3 ticket pages", () => {
  it("keeps direct create routes closed without live create authority", async () => {
    renderTicketPage({
      api: createTicketingApi(),
      element: <AlertCreatePage />,
      path: "/alerts/new",
      permissions: [],
      route: "/alerts/new",
    });

    expect(
      await screen.findByText(
        "The live tenant authority does not expose this creation control. The backend remains the authorization boundary for every request.",
      ),
    ).toBeVisible();
    expect(screen.queryByLabelText("Title")).toBeNull();
  });

  it("rejects tags outside the canonical transport grammar before create", async () => {
    const createAlert = vi.fn();
    renderTicketPage({
      api: createTicketingApi({ createAlert }),
      element: <AlertCreatePage />,
      path: "/alerts/new",
      permissions: ["alert.create"],
      route: "/alerts/new",
    });

    fireEvent.change(await screen.findByLabelText("Title"), {
      target: { value: "Endpoint signal" },
    });
    fireEvent.change(screen.getByLabelText("Tags"), {
      target: { value: "valid, 🕵" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create alert" }));

    expect(await screen.findByText(/Tag .* is invalid/u)).toBeVisible();
    expect(createAlert).not.toHaveBeenCalled();
  });

  it("loads the governed custom-field schema and submits typed create values", async () => {
    const createAlert = vi.fn(async () => ({
      etag: '"v1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
      id: alertId,
      version: 1,
    }));
    const list = vi.fn<CustomFieldAdministrationApi["list"]>(async () => ({
      items: [createCustomFieldDefinition()],
    }));
    renderTicketPage({
      api: createTicketingApi({ createAlert }),
      element: (
        <TicketCreatePage
          customFieldApi={createCustomFieldApi({ list })}
          kind="alert"
        />
      ),
      path: "/alerts/new",
      permissions: ["alert.create", "custom_field.read"],
      route: "/alerts/new",
    });

    fireEvent.change(await screen.findByLabelText("Title"), {
      target: { value: "Endpoint signal" },
    });
    fireEvent.change(await screen.findByLabelText("Evidence count"), {
      target: { value: "42" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create alert" }));

    await waitFor(() => expect(createAlert).toHaveBeenCalledTimes(1));
    expect(createAlert).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({ customFields: { evidence_count: 42 } }),
        tenantId,
      }),
    );
    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({
        includeArchived: false,
        limit: 100,
        objectType: "alert",
        tenantId,
      }),
    );
  });

  it("keeps creation closed when an authorized custom-field schema fails to load", async () => {
    const createAlert = vi.fn();
    renderTicketPage({
      api: createTicketingApi({ createAlert }),
      element: (
        <TicketCreatePage
          customFieldApi={createCustomFieldApi({
            list: async () => {
              throw new Error("offline");
            },
          })}
          kind="alert"
        />
      ),
      path: "/alerts/new",
      permissions: ["alert.create", "custom_field.read"],
      route: "/alerts/new",
    });

    expect(
      await screen.findByText(
        "The governed field schema could not be loaded. Ticket creation stays closed so required values are never omitted.",
      ),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Create alert" })).toBeDisabled();
    expect(createAlert).not.toHaveBeenCalled();
  });

  it("loads cursor pages and sends trimmed server filters", async () => {
    const secondAlert = {
      ...operatorAlert,
      alertNumber: "ALT-2026-0043",
      id: "0198c97d-cf4f-7000-8000-000000000017",
      title: "Second correlated signal",
    } satisfies AlertOperatorProjection;
    const listTickets = vi.fn(
      async (_kind, _tenantId, filters: { after?: string; search?: string }) =>
        filters.after === "cursor-1"
          ? { items: [secondAlert] }
          : filters.search
            ? { items: [operatorAlert] }
            : { items: [operatorAlert], nextCursor: "cursor-1" },
    );

    renderTicketPage({
      api: createTicketingApi({ listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "alert.create"],
      route: "/alerts",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load next page" }));
    expect(
      await screen.findByRole("link", { name: /ALT-2026-0043/u }),
    ).toBeVisible();

    fireEvent.change(screen.getByPlaceholderText("Search alerts"), {
      target: { value: "  powershell  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() =>
      expect(listTickets).toHaveBeenLastCalledWith(
        "alert",
        tenantId,
        expect.objectContaining({ search: "powershell" }),
        expect.any(AbortSignal),
      ),
    );
  });

  it("supports bounded bulk selection, column controls, resize, and keyboard rows", async () => {
    const secondAlert = {
      ...operatorAlert,
      alertNumber: "ALT-2026-0043",
      id: "0198c97d-cf4f-7000-8000-000000000017",
      title: "Second correlated signal",
    } satisfies AlertOperatorProjection;
    renderTicketPage({
      api: createTicketingApi({
        listTickets: async () => ({ items: [operatorAlert, secondAlert] }),
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: "/alerts",
    });

    const firstSelection = await screen.findByRole("checkbox", {
      name: "Select ALT-2026-0042",
    });
    const secondSelection = screen.getByRole("checkbox", {
      name: "Select ALT-2026-0043",
    });
    fireEvent.click(firstSelection);
    expect(
      screen.getByRole("status", { name: "1 loaded ticket selected" }),
    ).toBeVisible();
    fireEvent.click(secondSelection, { shiftKey: true });
    expect(
      screen.getByRole("status", { name: "2 loaded tickets selected" }),
    ).toBeVisible();

    expect(
      screen.getByRole("columnheader", { name: "Ticket" }),
    ).toHaveAttribute("data-pinned", "start");
    fireEvent.click(
      screen.getByRole("button", { name: "Unpin Ticket column" }),
    );
    expect(
      screen.getByRole("columnheader", { name: "Ticket" }),
    ).not.toHaveAttribute("data-pinned");
    fireEvent.click(
      screen.getByRole("button", { name: "Pin Ticket column to end" }),
    );
    expect(
      screen.getByRole("columnheader", { name: "Ticket" }),
    ).toHaveAttribute("data-pinned", "end");

    fireEvent.click(screen.getByRole("checkbox", { name: "Show Risk column" }));
    expect(screen.queryByRole("columnheader", { name: "Risk" })).toBeNull();

    const stateResizer = screen.getByRole("separator", {
      name: "Resize State column",
    });
    expect(stateResizer).toHaveAttribute("aria-valuenow", "190");
    fireEvent.keyDown(stateResizer, { key: "ArrowRight" });
    expect(stateResizer).toHaveAttribute("aria-valuenow", "200");

    const firstRow = screen.getByRole("row", {
      name: /Open ALT-2026-0042/u,
    });
    const secondRow = screen.getByRole("row", {
      name: /Open ALT-2026-0043/u,
    });
    firstRow.focus();
    fireEvent.keyDown(firstRow, { key: "ArrowDown" });
    expect(secondRow).toHaveFocus();
  });

  it("queues a bulk mutation with the exact selected ticket version pin", async () => {
    const request = vi.fn(async ({ body }) => ({
      job: completedBulkJob(body),
      replayed: false,
    }));
    const bulkApi = createTicketBulkApi({ request });
    renderTicketPage({
      api: createTicketingApi({
        listTickets: async () => ({ items: [operatorAlert] }),
      }),
      bulkApi,
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "alert.claim"],
      route: "/alerts",
    });

    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: "Select ALT-2026-0042",
      }),
    );
    fireEvent.change(screen.getByLabelText("Action"), {
      target: { value: "release" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review operation" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue operation" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request).toHaveBeenCalledWith({
      body: {
        kind: "alert",
        mutation: { action: "release" },
        retentionSeconds: 86_400,
        selection: {
          source: "explicit",
          targets: [{ expectedVersion: 1, id: alertId }],
        },
      },
      csrfToken: sessionFixture.csrfToken,
      idempotencyKey: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
      tenantId,
    });
    await waitFor(() =>
      expect(
        screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
      ).toHaveAttribute("aria-checked", "false"),
    );
  });

  it("pins the exact Saved View revision for all-matching bulk jobs", async () => {
    const request = vi.fn(async ({ body }) => ({
      job: completedBulkJob(body),
      replayed: false,
    }));
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets: async () => ({
          appliedView: {
            id: savedViewId,
            revision: savedAlertView.revision,
            specSha256: savedAlertView.specSha256,
          },
          items: [operatorAlertWithDynamicColumns],
        }),
      }),
      bulkApi: createTicketBulkApi({ request }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "alert.claim"],
      route: `/alerts?view=${savedViewId}`,
    });

    expect(
      await screen.findByRole("columnheader", { name: "Business unit" }),
    ).toBeVisible();
    fireEvent.change(screen.getByRole("combobox", { name: "Selection" }), {
      target: { value: "query" },
    });
    fireEvent.change(screen.getByLabelText("Action"), {
      target: { value: "release" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review operation" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue operation" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]?.[0].body).toEqual({
      kind: "alert",
      mutation: { action: "release" },
      retentionSeconds: 86_400,
      selection: {
        query: {
          savedView: {
            expectedRevision: savedAlertView.revision,
            expectedSpecSha256: savedAlertView.specSha256,
            id: savedViewId,
          },
          source: "saved_view",
        },
        source: "query",
      },
    });
  });

  it("queues an exact saved-view export and gates private comments on live authority", async () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: completedExportJob(body),
        replayed: false,
      }),
    );
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets: async () => ({
          appliedView: {
            id: savedViewId,
            revision: savedAlertView.revision,
            specSha256: savedAlertView.specSha256,
          },
          items: [operatorAlertWithDynamicColumns],
        }),
      }),
      element: <AlertListPage />,
      exportApi: createTicketExportApi({ request }),
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}`,
    });

    expect(
      await screen.findByRole("columnheader", { name: "Business unit" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", { name: "Public and private comments" }),
    ).toBeNull();
    expect(
      screen.queryByRole("option", { name: "Public comments" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]![0]).toMatchObject({
      body: {
        comments: "none",
        kind: "alert",
        maximumRows: 10_000,
        retentionSeconds: 86_400,
        source: {
          savedView: {
            expectedRevision: savedAlertView.revision,
            expectedSpecSha256: savedAlertView.specSha256,
            id: savedViewId,
          },
          source: "saved_view",
        },
      },
      csrfToken: sessionFixture.csrfToken,
      tenantId,
    });
  });

  it("uses a new idempotency key for a new identical bulk job after success", async () => {
    const request = vi.fn(async ({ body }) => ({
      job: completedBulkJob(body),
      replayed: false,
    }));
    renderTicketPage({
      api: createTicketingApi({
        listTickets: async () => ({ items: [operatorAlert] }),
      }),
      bulkApi: createTicketBulkApi({ request }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "alert.claim"],
      route: "/alerts",
    });

    await screen.findByRole("link", { name: /ALT-2026-0042/u });
    fireEvent.change(screen.getByRole("combobox", { name: "Selection" }), {
      target: { value: "query" },
    });
    fireEvent.change(screen.getByRole("combobox", { name: "Action" }), {
      target: { value: "release" },
    });
    async function submitBulk(expectedCalls: number): Promise<void> {
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Review operation" }),
        ).toBeEnabled(),
      );
      fireEvent.click(screen.getByRole("button", { name: "Review operation" }));
      fireEvent.click(
        await screen.findByRole("button", { name: "Queue operation" }),
      );
      await waitFor(() => expect(request).toHaveBeenCalledTimes(expectedCalls));
    }
    await submitBulk(1);
    await submitBulk(2);

    expect(request.mock.calls[1]![0].body).toEqual(
      request.mock.calls[0]![0].body,
    );
    expect(request.mock.calls[1]![0].idempotencyKey).not.toBe(
      request.mock.calls[0]![0].idempotencyKey,
    );
  });

  it("restores a bounded fail-closed queue filter from URL state", async () => {
    const listTickets = vi.fn(async () => ({ items: [operatorAlert] }));
    renderTicketPage({
      api: createTicketingApi({ listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route:
        "/alerts?search=%20endpoint%20&severity=critical&priority=urgent&queue=unassigned&visibility=customer&sort=created_at_asc&status=investigating,new&status=DROP%20TABLE",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    expect(listTickets).toHaveBeenCalledWith(
      "alert",
      tenantId,
      {
        customerVisible: true,
        limit: 30,
        priority: ["urgent"],
        queue: "unassigned",
        search: "endpoint",
        severity: ["critical"],
        sort: "created_at_asc",
        status: ["investigating", "new"],
      },
      expect.any(AbortSignal),
    );
    expect(screen.getByLabelText("Search")).toHaveValue("endpoint");
    expect(screen.getByLabelText("Severity")).toHaveValue("critical");
  });

  it("ignores unknown queue URL values instead of forwarding them", async () => {
    const listTickets = vi.fn(async () => ({ items: [operatorAlert] }));
    renderTicketPage({
      api: createTicketingApi({ listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route:
        "/alerts?queue=all_tenants&severity=catastrophic&sort=random()&visibility=private",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    expect(listTickets).toHaveBeenCalledWith(
      "alert",
      tenantId,
      { limit: 30, sort: "updated_at_desc" },
      expect.any(AbortSignal),
    );
  });

  it("executes one URL-backed saved view and renders exact dynamic columns", async () => {
    const listTickets = vi.fn(async (_kind, _tenant, filters) => ({
      appliedView: {
        id: savedViewId,
        revision: savedAlertView.revision,
        specSha256: savedAlertView.specSha256,
      },
      items: [operatorAlertWithDynamicColumns],
      ...(filters.after ? {} : { nextCursor: "saved-cursor" }),
    }));
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets,
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}`,
    });

    expect(
      await screen.findByRole("columnheader", { name: "Business unit" }),
    ).toBeVisible();
    expect(
      screen.getByRole("columnheader", { name: "Response budget" }),
    ).toHaveAttribute("data-pinned", "end");
    expect(screen.getByText("finance")).toBeVisible();
    expect(screen.getByText("37")).toBeVisible();
    expect(listTickets).toHaveBeenCalledWith(
      "alert",
      tenantId,
      { limit: 30, viewId: savedViewId },
      expect.any(AbortSignal),
    );
  });

  it("applies the same pinned saved-view boundary to Case queues", async () => {
    const caseView = {
      ...savedAlertView,
      kind: "case",
      name: "Case response budget",
      spec: {
        ...savedAlertView.spec,
        filters: {
          ...savedAlertView.spec.filters,
          custom: savedAlertView.spec.filters.custom.map((filter) => ({
            ...filter,
            definition: { ...filter.definition, kind: "case" },
          })),
        },
        sort: {
          ...savedAlertView.spec.sort,
          definition: {
            ...savedAlertView.spec.sort.definition,
            kind: "case",
          },
        },
        columns: savedAlertView.spec.columns.map((column) =>
          column.source === "core"
            ? column
            : {
                ...column,
                definition: { ...column.definition, kind: "case" },
              },
        ),
      },
    } satisfies SavedTicketView;
    const listTickets = vi.fn(async () => ({
      appliedView: {
        id: savedViewId,
        revision: caseView.revision,
        specSha256: caseView.specSha256,
      },
      items: [
        {
          ...operatorCase,
          dynamicColumns: operatorAlertWithDynamicColumns.dynamicColumns,
        },
      ],
    }));
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${caseView.specSha256}"`,
          value: caseView,
        }),
        listSavedTicketViews: async () => ({ items: [] }),
        listTickets,
      }),
      element: <CaseListPage />,
      path: "/cases",
      permissions: ["case.read"],
      route: `/cases?view=${savedViewId}`,
    });

    expect(
      await screen.findByRole("option", { name: caseView.name }),
    ).toBeVisible();
    expect(
      await screen.findByRole("columnheader", { name: "Business unit" }),
    ).toBeVisible();
    expect(listTickets).toHaveBeenCalledWith(
      "case",
      tenantId,
      { limit: 30, viewId: savedViewId },
      expect.any(AbortSignal),
    );
  });

  it("rejects a mixed saved-view URL before issuing a ticket request", async () => {
    const listTickets = vi.fn(async () => ({ items: [operatorAlert] }));
    renderTicketPage({
      api: createTicketingApi({ listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}&search=oracle`,
    });

    expect(await screen.findByText("Saved-view link rejected")).toBeVisible();
    expect(listTickets).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Clear invalid link" }));
    await waitFor(() => expect(listTickets).toHaveBeenCalledTimes(1));
    expect(listTickets).toHaveBeenCalledWith(
      "alert",
      tenantId,
      { limit: 30, sort: "updated_at_desc" },
      expect.any(AbortSignal),
    );
  });

  it("keeps update idempotency stable across a precondition retry", async () => {
    const replaceSavedTicketView = vi
      .fn()
      .mockRejectedValue(
        new TicketingApiError(
          "This private view changed on the server.",
          412,
          "precondition_failed",
        ),
      );
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets: async () => ({
          appliedView: {
            id: savedViewId,
            revision: savedAlertView.revision,
            specSha256: savedAlertView.specSha256,
          },
          items: [operatorAlertWithDynamicColumns],
        }),
        replaceSavedTicketView,
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}`,
    });

    const update = await screen.findByRole("button", { name: "Update" });
    fireEvent.click(update);
    expect(
      await screen.findByText(
        /Reload the current version and review before retrying/u,
      ),
    ).toBeVisible();
    fireEvent.click(update);
    await waitFor(() =>
      expect(replaceSavedTicketView).toHaveBeenCalledTimes(2),
    );

    const first = replaceSavedTicketView.mock.calls[0]![0];
    const second = replaceSavedTicketView.mock.calls[1]![0];
    expect(second.idempotencyKey).toBe(first.idempotencyKey);
    expect(first).toMatchObject({
      etag: `"sha256-${savedAlertView.specSha256}"`,
      viewId: savedViewId,
      body: { expectedRevision: savedAlertView.revision },
    });
  });

  it("saves the current URL filters and table layout as a private view", async () => {
    const createSavedTicketView = vi.fn(async ({ body }) => {
      const created = {
        ...savedAlertView,
        name: body.name,
        spec: body.spec,
        specSha256: "d".repeat(64),
      } satisfies SavedTicketView;
      return {
        etag: `"sha256-${"d".repeat(64)}"`,
        replayed: false,
        value: created,
      };
    });
    const listTickets = vi.fn(async (_kind, _tenant, filters) =>
      filters.viewId
        ? {
            appliedView: {
              id: savedViewId,
              revision: savedAlertView.revision,
              specSha256: "d".repeat(64),
            },
            items: [{ ...operatorAlert, dynamicColumns: [] }],
          }
        : { items: [operatorAlert] },
    );
    renderTicketPage({
      api: createTicketingApi({ createSavedTicketView, listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: "/alerts?search=powershell&priority=urgent&queue=unassigned",
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Save current" }),
    );
    fireEvent.change(screen.getByLabelText("View name"), {
      target: { value: "  My triage  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    await waitFor(() => expect(createSavedTicketView).toHaveBeenCalledTimes(1));
    expect(createSavedTicketView).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          kind: "alert",
          name: "My triage",
          spec: expect.objectContaining({
            filters: expect.objectContaining({
              priorities: ["urgent"],
              queue: "unassigned",
              search: "powershell",
            }),
            columns: expect.arrayContaining([
              expect.objectContaining({
                coreKey: "ticket",
                pin: "start",
                visible: true,
                width: 360,
              }),
            ]),
          }),
        }),
        idempotencyKey: expect.stringMatching(/^saved-view-[0-9a-f-]{36}$/u),
      }),
    );
    await waitFor(() =>
      expect(listTickets).toHaveBeenCalledWith(
        "alert",
        tenantId,
        { limit: 30, viewId: savedViewId },
        expect.any(AbortSignal),
      ),
    );
  });

  it("loads the dynamic catalog lazily and saves the exact selected definition revision", async () => {
    const dynamicAlert = {
      ...operatorAlert,
      dynamicColumns: [
        {
          source: "custom_field" as const,
          definitionId: customDefinitionId,
          definitionVersion: 7,
          value: "Alice Analyst",
        },
      ],
    } satisfies AlertOperatorProjection;
    const listCustomFields = vi.fn(async () => ({
      items: [
        {
          definitionId: customDefinitionId,
          definitionKey: "incident_owner",
          definitionLabel: "Incident owner",
          definitionVersion: 6,
          source: "custom_field" as const,
        },
        {
          definitionId: customDefinitionId,
          definitionKey: "incident_owner",
          definitionLabel: "Incident owner",
          definitionVersion: 7,
          source: "custom_field" as const,
        },
      ],
    }));
    const createSavedTicketView = vi.fn(async ({ body }) => ({
      etag: `"sha256-${"c".repeat(64)}"`,
      replayed: false,
      value: {
        ...savedAlertView,
        name: body.name,
        spec: body.spec,
        specSha256: "c".repeat(64),
      } satisfies SavedTicketView,
    }));
    const listTickets = vi.fn(async (_kind, _tenant, filters) =>
      filters.viewId
        ? {
            appliedView: {
              id: savedViewId,
              revision: savedAlertView.revision,
              specSha256: "c".repeat(64),
            },
            items: [dynamicAlert],
          }
        : { items: [dynamicAlert] },
    );

    renderTicketPage({
      api: createTicketingApi({ createSavedTicketView, listTickets }),
      columnCatalogApi: {
        listCustomFields,
        listSlaColumns: async () => ({ items: [] }),
      },
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "custom_field.read"],
      route: "/alerts",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    expect(listCustomFields).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText("Columns"));
    const addColumn = await screen.findByRole("button", {
      name: "Add Incident owner column",
    });
    expect(listCustomFields).toHaveBeenCalledTimes(1);
    fireEvent.click(addColumn);
    expect(
      await screen.findByRole("columnheader", { name: "Incident owner" }),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Remove Incident owner column" }),
    );
    expect(
      screen.queryByRole("columnheader", { name: "Incident owner" }),
    ).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Add Incident owner column" }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Save current" }));
    fireEvent.change(screen.getByLabelText("View name"), {
      target: { value: "Incident ownership" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    await waitFor(() => expect(createSavedTicketView).toHaveBeenCalledTimes(1));
    expect(createSavedTicketView).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          spec: expect.objectContaining({
            columns: expect.arrayContaining([
              expect.objectContaining({
                definitionId: customDefinitionId,
                expectedDefinitionVersion: 7,
                source: "custom_field",
              }),
            ]),
          }),
        }),
      }),
    );
  });

  it("does not request the custom-field catalog without custom_field.read", async () => {
    const listCustomFields = vi.fn(async () => ({ items: [] }));
    const listSlaColumns = vi.fn(async () => ({ items: [] }));

    renderTicketPage({
      api: createTicketingApi({
        listTickets: async () => ({ items: [operatorAlert] }),
      }),
      columnCatalogApi: { listCustomFields, listSlaColumns },
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read", "sla.read"],
      route: "/alerts",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    fireEvent.click(screen.getByText("Columns"));

    await waitFor(() => expect(listSlaColumns).toHaveBeenCalledTimes(1));
    expect(listCustomFields).not.toHaveBeenCalled();
  });

  it("rejects a saved-view name that exceeds the backend UTF-8 byte limit", async () => {
    const createSavedTicketView = vi.fn();
    renderTicketPage({
      api: createTicketingApi({
        createSavedTicketView,
        listTickets: async () => ({ items: [operatorAlert] }),
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: "/alerts",
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Save current" }),
    );
    fireEvent.change(screen.getByLabelText("View name"), {
      target: { value: "😀".repeat(31) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    expect(await screen.findByText(/at most 120 UTF-8 bytes/u)).toBeVisible();
    expect(createSavedTicketView).not.toHaveBeenCalled();
  });

  it("archives and restores with the exact current ETag and revision", async () => {
    const archived = {
      ...savedAlertView,
      status: "archived",
      revision: 4,
      archivedAt: "2026-08-25T09:00:00Z",
      updatedAt: "2026-08-25T09:00:00Z",
      specSha256: "e".repeat(64),
    } satisfies SavedTicketView;
    const restored = {
      ...savedAlertView,
      revision: 5,
      updatedAt: "2026-08-25T09:01:00Z",
      specSha256: "f".repeat(64),
    } satisfies SavedTicketView;
    const archiveSavedTicketView = vi.fn(async () => ({
      etag: `"sha256-${"e".repeat(64)}"`,
      replayed: false,
      value: archived,
    }));
    const restoreSavedTicketView = vi.fn(async () => ({
      etag: `"sha256-${"f".repeat(64)}"`,
      replayed: false,
      value: restored,
    }));
    renderTicketPage({
      api: createTicketingApi({
        archiveSavedTicketView,
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets: async () => ({
          appliedView: {
            id: savedViewId,
            revision: savedAlertView.revision,
            specSha256: savedAlertView.specSha256,
          },
          items: [operatorAlertWithDynamicColumns],
        }),
        restoreSavedTicketView,
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}`,
    });

    fireEvent.click(await screen.findByRole("button", { name: "Archive" }));
    fireEvent.click(screen.getByRole("button", { name: "Archive view" }));
    await waitFor(() =>
      expect(archiveSavedTicketView).toHaveBeenCalledTimes(1),
    );
    expect(archiveSavedTicketView).toHaveBeenCalledWith(
      expect.objectContaining({
        body: { expectedRevision: 3, kind: "alert" },
        etag: `"sha256-${savedAlertView.specSha256}"`,
        viewId: savedViewId,
      }),
    );
    expect(
      await screen.findByText("Archived view is not executable"),
    ).toBeVisible();
    expect(screen.queryByRole("link", { name: /ALT-2026-0042/u })).toBeNull();

    fireEvent.click(await screen.findByRole("button", { name: "Restore" }));
    fireEvent.click(screen.getByRole("button", { name: "Restore view" }));
    await waitFor(() =>
      expect(restoreSavedTicketView).toHaveBeenCalledTimes(1),
    );
    expect(restoreSavedTicketView).toHaveBeenCalledWith(
      expect.objectContaining({
        body: { expectedRevision: 4, kind: "alert" },
        etag: `"sha256-${"e".repeat(64)}"`,
        viewId: savedViewId,
      }),
    );
  });

  it("rejects queue rows produced from a stale saved-view revision", async () => {
    renderTicketPage({
      api: createTicketingApi({
        getSavedTicketView: async () => ({
          etag: `"sha256-${savedAlertView.specSha256}"`,
          value: savedAlertView,
        }),
        listSavedTicketViews: async () => ({ items: [savedAlertView] }),
        listTickets: async () => ({
          appliedView: {
            id: savedViewId,
            revision: savedAlertView.revision - 1,
            specSha256: "0".repeat(64),
          },
          items: [operatorAlertWithDynamicColumns],
        }),
      }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: ["alert.read"],
      route: `/alerts?view=${savedViewId}`,
    });

    expect(await screen.findByText("Alert queue unavailable")).toBeVisible();
    expect(screen.queryByRole("link", { name: /ALT-2026-0042/u })).toBeNull();
  });

  it("keeps a saved-view deep link closed without live read authority", async () => {
    const getSavedTicketView = vi.fn();
    const listTickets = vi.fn();
    renderTicketPage({
      api: createTicketingApi({ getSavedTicketView, listTickets }),
      element: <AlertListPage />,
      path: "/alerts",
      permissions: [],
      route: `/alerts?view=${savedViewId}`,
    });

    expect(
      await screen.findByText(/Backend policy remains the authority/u),
    ).toBeVisible();
    expect(getSavedTicketView).not.toHaveBeenCalled();
    expect(listTickets).not.toHaveBeenCalled();
  });

  it("mounts the Alert core-metadata editor only under live update authority", async () => {
    const replace = vi.fn<TicketMetadataApi["replace"]>();
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: <TicketDetailPage kind="alert" metadataApi={{ replace }} />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.update"],
      route: `/alerts/${alertId}`,
    });

    expect(
      await screen.findByRole("heading", { name: "Core details" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    expect(screen.getByLabelText("Title")).toHaveValue(operatorAlert.title);
    expect(screen.queryByLabelText("Summary")).not.toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });

  it.each([
    {
      id: alertId,
      kind: "alert" as const,
      permission: "alert" as const,
      projection: operatorAlert,
      route: "/alerts/:alertId",
    },
    {
      id: caseId,
      kind: "case" as const,
      permission: "case" as const,
      projection: operatorCase,
      route: "/cases/:caseId",
    },
  ])(
    "mounts the private $kind watcher list and guarded add control",
    async (fixture) => {
      const list = vi.fn<TicketWatcherApi["list"]>(async () => ({
        etag: `"v${fixture.projection.version}"`,
        value: {
          items: [
            {
              addedAt: "2026-09-01T08:00:00Z",
              displayName: "Incident Responder",
              userId: "0198c97d-cf4f-7000-8000-000000000041",
            },
          ],
          updatedAt: "2026-09-01T08:05:00Z",
          version: fixture.projection.version,
        },
      }));
      const mutate = vi.fn<TicketWatcherApi["mutate"]>();
      renderTicketPage({
        api: createTicketingApi({
          getTicket: async () => ({
            etag: `"v${fixture.projection.version}"`,
            value: fixture.projection,
          }),
        }),
        element: (
          <TicketDetailPage kind={fixture.kind} watcherApi={{ list, mutate }} />
        ),
        path: fixture.route,
        permissions: [
          `${fixture.permission}.read`,
          `${fixture.permission}.update`,
        ],
        route: `/${fixture.kind === "alert" ? "alerts" : "cases"}/${fixture.id}`,
      });

      expect(
        await screen.findByRole("heading", { name: "Watchers" }),
      ).toBeVisible();
      expect(
        await screen.findByRole("list", { name: "Ticket watchers" }),
      ).toBeVisible();
      expect(screen.getByText("Incident Responder")).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Add watcher" }),
      ).toBeDisabled();
      expect(list).toHaveBeenCalledWith({
        kind: fixture.kind,
        resourceId: fixture.id,
        signal: expect.any(AbortSignal),
        tenantId,
      });
      expect(mutate).not.toHaveBeenCalled();
    },
  );

  it("aborts a mounted watcher mutation when live authority is re-evaluated without permission drift", async () => {
    const pending = createDeferred<TicketWatcherMutationResult>();
    const list = vi.fn<TicketWatcherApi["list"]>(async () => ({
      etag: '"v1"',
      value: {
        items: [],
        updatedAt: "2026-09-01T08:05:00Z",
        version: 1,
      },
    }));
    const mutate = vi.fn<TicketWatcherApi["mutate"]>(
      async () => pending.promise,
    );
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(["alert.read", "alert.update"]),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <>
          <AuthorityReloadControl />
          <TicketDetailPage kind="alert" watcherApi={{ list, mutate }} />
        </>
      ),
      getTenantAuthority,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.update"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.change(await screen.findByLabelText("Operator user ID"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000041" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add watcher" }));
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    const signal = mutate.mock.calls[0]?.[0].signal;

    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await act(async () => {
      pending.resolve({
        changed: true,
        etag: '"v2"',
        replayed: false,
        value: {
          items: [
            {
              addedAt: "2026-09-01T08:06:00Z",
              displayName: "Stale Mutation",
              userId: "0198c97d-cf4f-7000-8000-000000000041",
            },
          ],
          updatedAt: "2026-09-01T08:06:00Z",
          version: 2,
        },
      });
      await pending.promise;
    });
    expect(screen.queryByText("Stale Mutation")).not.toBeInTheDocument();
  });

  it("aborts the mounted metadata replacement when live Alert update authority is revoked", async () => {
    let livePermissions: readonly TenantPermissionKeyView[] = [
      "alert.read",
      "alert.update",
    ];
    const getTicket = vi.fn(async () => ({
      etag: '"v1"',
      value: operatorAlert,
    }));
    const pending = createDeferred<VersionedTicketMetadata>();
    const replace = vi.fn<TicketMetadataApi["replace"]>(
      async () => pending.promise,
    );
    renderTicketPage({
      api: createTicketingApi({ getTicket }),
      element: (
        <>
          <AuthorityReloadControl />
          <TicketDetailPage kind="alert" metadataApi={{ replace }} />
        </>
      ),
      getTenantAuthority: async () => authorityFixture(livePermissions),
      path: "/alerts/:alertId",
      permissions: livePermissions,
      route: `/alerts/${alertId}`,
    });

    await screen.findByRole("heading", { name: "Core details" });
    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    const signal = replace.mock.calls[0]?.[0].signal;
    expect(signal).toBeInstanceOf(AbortSignal);

    livePermissions = ["alert.read"];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(
      await screen.findByText(
        "Core details are read-only under the current live tenant authority.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Save core details" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve({
        etag: '"v2"',
        value: {
          category: operatorAlert.category,
          classification: null,
          customerVisible: operatorAlert.customerVisible,
          description: operatorAlert.description,
          id: alertId,
          kind: "alert",
          priority: operatorAlert.priority,
          severity: operatorAlert.severity,
          tags: [...operatorAlert.tags],
          title: operatorAlert.title,
          updatedAt: "2026-08-31T08:30:00Z",
          version: 2,
        },
      });
      await pending.promise;
    });
    expect(getTicket).toHaveBeenCalledTimes(1);
  });

  it("replaces a stale metadata draft with the freshly reloaded ticket snapshot", async () => {
    const latest = {
      ...operatorAlert,
      title: "Freshly correlated endpoint signal",
      updatedAt: "2026-08-31T08:30:00Z",
      version: 2,
    };
    const getTicket = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v1"', value: operatorAlert })
      .mockResolvedValueOnce({ etag: '"v2"', value: latest });
    const replace = vi.fn<TicketMetadataApi["replace"]>(async () => {
      throw new TicketMetadataApiError(
        "This ticket changed. Reload the latest snapshot before retrying.",
        412,
      );
    });
    renderTicketPage({
      api: createTicketingApi({ getTicket }),
      element: <TicketDetailPage kind="alert" metadataApi={{ replace }} />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.update"],
      route: `/alerts/${alertId}`,
    });

    await screen.findByRole("heading", { name: operatorAlert.title });
    fireEvent.click(screen.getByRole("button", { name: "Edit core details" }));
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "Stale local draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save core details" }));

    expect(
      await screen.findByRole("heading", { name: latest.title }),
    ).toBeVisible();
    expect(getTicket).toHaveBeenCalledTimes(2);
    expect(
      screen.queryByRole("button", { name: "Save core details" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("Stale local draft")).toBeNull();
  });

  it("loads and atomically edits the governed detail custom-field projection", async () => {
    const initial = createCustomFieldObjectProjection(4, 7);
    const updated = createCustomFieldObjectProjection(5, 42);
    const get = vi.fn<CustomFieldObjectApi["get"]>(async () => initial);
    const replace = vi.fn<CustomFieldObjectApi["replace"]>(async () => updated);
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <TicketDetailPage
          customFieldApi={createCustomFieldObjectApi({ get, replace })}
          kind="alert"
        />
      ),
      path: "/alerts/:alertId",
      permissions: ["alert.read", "custom_field.read", "custom_field.manage"],
      route: `/alerts/${alertId}`,
    });

    const input =
      await screen.findByLabelText<HTMLInputElement>("Evidence count");
    expect(input).toBeDisabled();
    expect(input).toHaveValue(7);
    expect(get).toHaveBeenCalledWith({
      objectId: alertId,
      objectType: "alert",
      signal: expect.any(AbortSignal),
      tenantId,
    });

    fireEvent.click(screen.getByRole("button", { name: "Edit custom fields" }));
    expect(screen.getByLabelText("Evidence count")).toBeEnabled();
    fireEvent.change(screen.getByLabelText("Evidence count"), {
      target: { value: "42" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save custom fields" }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith({
      csrfToken: sessionFixture.csrfToken,
      current: initial,
      idempotencyKey: expect.any(String),
      signal: expect.any(AbortSignal),
      tenantId,
      values: { evidence_count: 42 },
    });
    await waitFor(() =>
      expect(screen.getByLabelText("Evidence count")).toHaveValue(42),
    );
    expect(screen.getByLabelText("Evidence count")).toBeDisabled();
    expect(screen.getByText("Snapshot v5")).toBeVisible();
  });

  it("aborts a stale custom-field draft when a newer projection is refetched", async () => {
    const initial = createCustomFieldObjectProjection(4, 7);
    const refreshed = createCustomFieldObjectProjection(5, 9);
    const get = vi
      .fn<CustomFieldObjectApi["get"]>()
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(refreshed);
    const pending = createDeferred<CustomFieldObjectProjectionView>();
    const replace = vi.fn<CustomFieldObjectApi["replace"]>(
      async () => pending.promise,
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <>
          <CustomFieldReloadControl />
          <TicketDetailPage
            customFieldApi={createCustomFieldObjectApi({ get, replace })}
            kind="alert"
          />
        </>
      ),
      path: "/alerts/:alertId",
      permissions: ["alert.read", "custom_field.read", "custom_field.manage"],
      route: `/alerts/${alertId}`,
    });

    expect(await screen.findByLabelText("Evidence count")).toHaveValue(7);
    fireEvent.click(screen.getByRole("button", { name: "Edit custom fields" }));
    fireEvent.change(screen.getByLabelText("Evidence count"), {
      target: { value: "42" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save custom fields" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    const signal = replace.mock.calls[0]?.[0].signal;

    fireEvent.click(
      screen.getByRole("button", { name: "Reload custom-field projection" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(signal?.aborted).toBe(true));
    const refreshedField = await screen.findByLabelText("Evidence count");
    expect(refreshedField).toBeDisabled();
    expect(refreshedField).toHaveValue(9);

    await act(async () => {
      pending.resolve(createCustomFieldObjectProjection(5, 42));
      await pending.promise;
    });
    expect(refreshedField).toHaveValue(9);
  });

  it("serializes deliberate removal by omitting a visible update-editable key", async () => {
    const initial = createCustomFieldObjectProjection(4, 7);
    const removed = {
      ...createCustomFieldObjectProjection(5, 7),
      drafts: { evidence_count: { presence: "missing" as const } },
    };
    const replace = vi.fn<CustomFieldObjectApi["replace"]>(async () => removed);
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <TicketDetailPage
          customFieldApi={createCustomFieldObjectApi({
            get: async () => initial,
            replace,
          })}
          kind="alert"
        />
      ),
      path: "/alerts/:alertId",
      permissions: ["alert.read", "custom_field.read", "custom_field.manage"],
      route: `/alerts/${alertId}`,
    });

    await screen.findByLabelText("Evidence count");
    fireEvent.click(screen.getByRole("button", { name: "Edit custom fields" }));
    fireEvent.click(screen.getByLabelText("Store a value for Evidence count"));
    fireEvent.click(screen.getByRole("button", { name: "Save custom fields" }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith(
      expect.objectContaining({ current: initial, values: {} }),
    );
  });

  it("never renders cached ticket custom-field values without live custom-field read authority", async () => {
    const get = vi.fn<CustomFieldObjectApi["get"]>();
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <TicketDetailPage
          customFieldApi={createCustomFieldObjectApi({ get })}
          kind="alert"
        />
      ),
      path: "/alerts/:alertId",
      permissions: ["alert.read"],
      route: `/alerts/${alertId}`,
    });

    expect(
      await screen.findByText(
        "Custom fields stay hidden until live read authority is available.",
      ),
    ).toBeVisible();
    expect(screen.queryByText("fin-ws-04")).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });

  it("removes a cached detail projection immediately when live read authority is revoked", async () => {
    let livePermissions: readonly TenantPermissionKeyView[] = [
      "alert.read",
      "custom_field.read",
      "custom_field.manage",
    ];
    const get = vi.fn<CustomFieldObjectApi["get"]>(async () =>
      createCustomFieldObjectProjection(4, 7),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <>
          <AuthorityReloadControl />
          <TicketDetailPage
            customFieldApi={createCustomFieldObjectApi({ get })}
            kind="alert"
          />
        </>
      ),
      getTenantAuthority: async () => authorityFixture(livePermissions),
      path: "/alerts/:alertId",
      permissions: livePermissions,
      route: `/alerts/${alertId}`,
    });

    expect(await screen.findByLabelText("Evidence count")).toHaveValue(7);
    livePermissions = ["alert.read"];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    expect(
      await screen.findByText(
        "Custom fields stay hidden until live read authority is available.",
      ),
    ).toBeVisible();
    expect(screen.queryByLabelText("Evidence count")).not.toBeInTheDocument();
  });

  it("aborts an in-flight custom-field replacement when live manage authority is revoked", async () => {
    let livePermissions: readonly TenantPermissionKeyView[] = [
      "alert.read",
      "custom_field.read",
      "custom_field.manage",
    ];
    const initial = createCustomFieldObjectProjection(4, 7);
    const pending = createDeferred<CustomFieldObjectProjectionView>();
    const replace = vi.fn<CustomFieldObjectApi["replace"]>(
      async () => pending.promise,
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: (
        <>
          <AuthorityReloadControl />
          <TicketDetailPage
            customFieldApi={createCustomFieldObjectApi({
              get: async () => initial,
              replace,
            })}
            kind="alert"
          />
        </>
      ),
      getTenantAuthority: async () => authorityFixture(livePermissions),
      path: "/alerts/:alertId",
      permissions: livePermissions,
      route: `/alerts/${alertId}`,
    });

    expect(await screen.findByLabelText("Evidence count")).toHaveValue(7);
    fireEvent.click(screen.getByRole("button", { name: "Edit custom fields" }));
    fireEvent.change(screen.getByLabelText("Evidence count"), {
      target: { value: "42" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save custom fields" }));
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    const signal = replace.mock.calls[0]?.[0].signal;
    expect(signal).toBeInstanceOf(AbortSignal);

    livePermissions = ["alert.read", "custom_field.read"];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    const reloadedField = await screen.findByLabelText("Evidence count");
    expect(reloadedField).toBeDisabled();
    expect(reloadedField).toHaveValue(7);
    expect(
      screen.queryByRole("button", { name: "Edit custom fields" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve(createCustomFieldObjectProjection(5, 42));
      await pending.promise;
    });
    expect(reloadedField).toHaveValue(7);
  });

  it("keeps customer projections free of operator actions, private UI, and active HTML", async () => {
    const listComments = vi.fn(async () => ({ items: [] }));
    const view = renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v2"', value: customerAlert }),
        listComments,
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: [
        "alert.read",
        "alert.update",
        "alert.claim",
        "alert.comment.public",
        "alert.comment.private",
      ],
      route: `/alerts/${alertId}`,
    });

    expect(
      await screen.findByRole("heading", { name: customerAlert.title }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Claim" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "DFIR" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Watchers" })).toBeNull();
    expect(
      view.container.querySelector("img, script, iframe, object"),
    ).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: "Comments" }));
    expect(
      await screen.findByText(
        "Comment access is not available for this operator boundary.",
      ),
    ).toBeVisible();
    expect(listComments).not.toHaveBeenCalled();
    expect(screen.queryByText("Private operator note")).toBeNull();
    expect(
      view.container.querySelector("img, script, iframe, object"),
    ).toBeNull();
    expect(screen.queryByRole("link", { name: "unsafe" })).toBeNull();
  });

  it.each([
    {
      element: <AlertDetailPage />,
      kind: "alert" as const,
      path: "/alerts/:alertId",
      resourceId: alertId,
      route: `/alerts/${alertId}`,
      ticket: operatorAlert,
    },
    {
      element: <CaseDetailPage />,
      kind: "case" as const,
      path: "/cases/:caseId",
      resourceId: caseId,
      route: `/cases/${caseId}`,
      ticket: operatorCase,
    },
  ])(
    "mounts the $kind comment workspace and renders only accepted Markdown",
    async ({ element, kind, path, resourceId, route, ticket }) => {
      const listComments = vi.fn(async () => ({
        items: [mountedOperatorComment(kind, `Mounted ${kind} comment`)],
      }));
      const previewComment = vi.fn(async () => ({
        attachments: [],
        bodyMarkdown: "**Accepted preview** <img src=x onerror=alert(1)>",
        mentions: [],
        visibility: "public" as const,
      }));
      const view = renderTicketPage({
        api: createTicketingApi({
          getTicket: async () => ({ etag: '"v1"', value: ticket }),
          listCommentMentionCandidates: async () => [],
          listComments,
          previewComment,
        }),
        element,
        path,
        permissions: [
          `${kind}.read`,
          `${kind}.comment.read`,
          `${kind}.comment.public`,
          `${kind}.comment.private`,
        ],
        route,
      });

      fireEvent.click(await screen.findByRole("tab", { name: "Comments" }));
      expect(await screen.findByText(`Mounted ${kind} comment`)).toBeVisible();
      fireEvent.change(screen.getByLabelText("Comment"), {
        target: { value: "Preview this update" },
      });
      fireEvent.click(screen.getByRole("tab", { name: "Preview" }));

      expect(await screen.findByText(/Accepted preview/u)).toBeVisible();
      expect(
        view.container.querySelector("img, script, iframe, object"),
      ).toBeNull();
      expect(previewComment).toHaveBeenCalledWith({
        body: {
          bodyMarkdown: "Preview this update",
          visibility: "public",
        },
        csrfToken: sessionFixture.csrfToken,
        kind,
        resourceId,
        signal: expect.any(AbortSignal),
        tenantId,
      });

      fireEvent.click(screen.getByRole("tab", { name: "Write" }));
      fireEvent.change(screen.getByLabelText("Comment"), {
        target: { value: " leading whitespace" },
      });
      fireEvent.click(screen.getByRole("tab", { name: "Preview" }));
      expect(
        await screen.findByText(
          "Comments must contain at most 20000 valid Unicode characters.",
        ),
      ).toBeVisible();
      expect(previewComment).toHaveBeenCalledTimes(1);
    },
  );

  it("requires both public and private comment authority before exposing private create or edit", async () => {
    const comment = mountedOperatorComment(
      "alert",
      "Private author note",
      "private",
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listComments: async () => ({ items: [comment] }),
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: [
        "alert.read",
        "alert.comment.read",
        "alert.comment.private",
      ],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Comments" }));
    expect(await screen.findByText("Private author note")).toBeVisible();
    expect(screen.queryByText("Private operator note")).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Post comment" })).toBeNull();
  });

  it("offers operator edit only to the frozen author and recovers stale CAS from comments and history", async () => {
    const editable = mountedOperatorComment("alert", "Original author text");
    const otherAuthor = {
      ...mountedOperatorComment("alert", "Another analyst text"),
      id: "0198c97d-cf4f-7000-8000-000000000095",
      author: {
        audience: "operator" as const,
        displayName: "Other analyst",
        membershipId: "0198c97d-cf4f-7000-8000-000000000094",
      },
    };
    const latest = {
      ...editable,
      bodyMarkdown: "Concurrent server correction",
      canEdit: false,
      revision: 2,
      updatedAt: "2026-08-30T09:05:00Z",
    };
    const listComments = vi
      .fn()
      .mockResolvedValueOnce({ items: [otherAuthor, editable] })
      .mockResolvedValue({ items: [latest] });
    const listCommentRevisions = vi.fn(async () => ({ items: [] }));
    const editComment = vi.fn(async () => {
      throw new TicketingApiError(
        "The comment changed.",
        412,
        "precondition_failed",
      );
    });
    renderTicketPage({
      api: createTicketingApi({
        editComment,
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listCommentMentionCandidates: async () => [],
        listCommentRevisions,
        listComments,
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: [
        "alert.read",
        "alert.comment.read",
        "alert.comment.public",
        "alert.comment.private",
      ],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Comments" }));
    expect(await screen.findByText("Another analyst text")).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Edit" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog");
    await waitFor(() => expect(listCommentRevisions).toHaveBeenCalledTimes(1));
    fireEvent.change(within(dialog).getByLabelText("Comment"), {
      target: { value: "My correction" },
    });
    fireEvent.change(within(dialog).getByLabelText("Reason for edit"), {
      target: { value: "Clarify the verified timeline" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Save revision" }),
    );

    await waitFor(() => expect(editComment).toHaveBeenCalledTimes(1));
    expect(editComment).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          bodyMarkdown: "My correction",
          reason: "Clarify the verified timeline",
        },
        commentId: editable.id,
        etag: '"comment-r1"',
      }),
    );
    expect(
      await within(dialog).findByText(
        "This comment changed on the server. Review the latest revision before retrying.",
      ),
    ).toBeVisible();
    expect(within(dialog).getByLabelText("Comment")).toHaveValue(
      "Concurrent server correction",
    );
    expect(listComments).toHaveBeenCalledTimes(2);
    expect(listCommentRevisions).toHaveBeenCalledTimes(2);
  });

  it("bounds the mounted mention picker to the 50-member request limit", async () => {
    const candidates = Array.from({ length: 51 }, (_, index) => ({
      audience: "operator" as const,
      displayName: `Candidate ${String(index).padStart(2, "0")}`,
      membershipId: `0198c97d-cf4f-7000-8001-${index.toString(16).padStart(12, "0")}`,
    }));
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listCommentMentionCandidates: async () => candidates,
        listComments: async () => ({ items: [] }),
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.comment.read", "alert.comment.public"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Comments" }));
    const picker = await screen.findByRole("group", {
      name: "Mention ticket operators",
    });
    const candidateCheckboxes = within(picker).getAllByRole("checkbox");
    for (const checkbox of candidateCheckboxes.slice(0, 50)) {
      fireEvent.click(checkbox);
    }

    expect(
      screen.getByText("The maximum of 50 operator mentions is selected."),
    ).toBeVisible();
    expect(candidateCheckboxes[50]).toBeDisabled();
  });

  it("aborts an operator preview when live comment authority changes", async () => {
    let livePermissions: TenantPermissionKeyView[] = [
      "alert.read",
      "alert.comment.read",
      "alert.comment.public",
    ];
    const previewComment = vi.fn(
      async (
        input: Parameters<
          ReturnType<typeof createTicketingApi>["previewComment"]
        >[0],
      ) =>
        new Promise<never>((_resolve, reject) => {
          input.signal?.addEventListener(
            "abort",
            () => reject(new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        }),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listCommentMentionCandidates: async () => [],
        listComments: async () => ({ items: [] }),
        previewComment,
      }),
      element: (
        <>
          <AuthorityReloadControl />
          <AlertDetailPage />
        </>
      ),
      getTenantAuthority: async () => authorityFixture(livePermissions),
      path: "/alerts/:alertId",
      permissions: livePermissions,
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Comments" }));
    fireEvent.change(screen.getByLabelText("Comment"), {
      target: { value: "Pending preview" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Preview" }));
    await waitFor(() => expect(previewComment).toHaveBeenCalledTimes(1));
    const signal = previewComment.mock.calls[0]?.[0].signal;

    livePermissions = ["alert.read", "alert.comment.read"];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    await waitFor(() => expect(signal?.aborted).toBe(true));
    expect(screen.queryByRole("button", { name: "Post comment" })).toBeNull();
    expect(
      screen.queryByText("The server could not preview this comment."),
    ).toBeNull();

    livePermissions = [
      "alert.read",
      "alert.comment.read",
      "alert.comment.public",
    ];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));
    expect(await screen.findByLabelText("Comment")).toHaveValue("");
  });

  it("mounts the Case-only operator DFIR workspace with exact tenant and Case coordinates", async () => {
    const getWorkspace = vi.fn(async () =>
      projectWorkspace(
        dfirWorkspaceFixture(),
        "0198c97d-cf4f-7000-8000-000000000001",
        "0198c97d-cf4f-7000-8000-000000000002",
      ),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      dfirApi: createCaseDfirApi({ getWorkspace }),
      element: <CaseDetailPage />,
      path: "/cases/:caseId",
      permissions: ["case.read", ...dfirReadPermissions],
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "DFIR" }));
    expect(
      await screen.findByRole("heading", { name: "Case evidence room" }),
    ).toBeVisible();
    expect(getWorkspace).toHaveBeenCalledWith({
      caseId,
      signal: expect.any(AbortSignal),
      tenantId,
    });
  });

  it("mounts an exact-resource Case audit tab only with live tenant audit authority", async () => {
    const event = {
      ...tenantAuditEventFixture,
      tenantId,
      resourceId: caseId,
      resourceType: "case",
    };
    const listTenant = vi.fn(async () => ({ items: [event] }));
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      element: (
        <TicketDetailPage
          auditApi={createAuditApiMock({ listTenant })}
          kind="case"
        />
      ),
      path: "/cases/:caseId",
      permissions: ["case.read", "audit.read"],
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Audit" }));

    expect(await screen.findByText(event.action)).toBeVisible();
    expect(screen.getByText(event.reason!)).toBeVisible();
    expect(listTenant).toHaveBeenCalledWith({
      filters: { limit: 25, resourceId: caseId, resourceType: "case" },
      signal: expect.any(AbortSignal),
      tenantId,
    });
  });

  it("keeps the ticket audit ledger hidden without live audit authority", async () => {
    const listTenant = vi.fn(async () => ({ items: [] }));
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      element: (
        <TicketDetailPage
          auditApi={createAuditApiMock({ listTenant })}
          kind="case"
        />
      ),
      path: "/cases/:caseId",
      permissions: ["case.read"],
      route: `/cases/${caseId}`,
    });

    await screen.findByRole("heading", { name: operatorCase.title });
    expect(screen.queryByRole("tab", { name: "Audit" })).toBeNull();
    expect(listTenant).not.toHaveBeenCalled();
  });

  it("mounts the Case contact workspace only with live Case and contact read authority", async () => {
    const listActiveContacts = vi.fn<CaseContactApi["listActiveContacts"]>(
      async () => ({ items: [] }),
    );
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(async () => ({
      items: [],
    }));
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      element: (
        <TicketDetailPage
          contactApi={createCaseContactApi({
            listActiveContacts,
            listLinks,
          })}
          kind="case"
        />
      ),
      path: "/cases/:caseId",
      permissions: ["case.read", "contact.read"],
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Contacts" }));

    expect(
      await screen.findByRole("heading", { name: "Customer contacts" }),
    ).toBeVisible();
    expect(listLinks).toHaveBeenCalledWith({
      caseId,
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
    });
    expect(listActiveContacts).toHaveBeenCalledWith({
      caseId,
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
    });
    expect(screen.queryByRole("button", { name: "Link contact" })).toBeNull();
  });

  it("does not expose or call the Case contact workspace without contact read authority", async () => {
    const listActiveContacts = vi.fn<CaseContactApi["listActiveContacts"]>();
    const listLinks = vi.fn<CaseContactApi["listLinks"]>();
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      element: (
        <TicketDetailPage
          contactApi={createCaseContactApi({
            listActiveContacts,
            listLinks,
          })}
          kind="case"
        />
      ),
      path: "/cases/:caseId",
      permissions: ["case.read"],
      route: `/cases/${caseId}`,
    });

    expect(
      await screen.findByRole("heading", { name: operatorCase.title }),
    ).toBeVisible();
    expect(screen.queryByRole("tab", { name: "Contacts" })).toBeNull();
    expect(listLinks).not.toHaveBeenCalled();
    expect(listActiveContacts).not.toHaveBeenCalled();
  });

  it("closes the Case contact workspace and aborts reads after live authority revocation", async () => {
    let livePermissions: readonly TenantPermissionKeyView[] = [
      "case.read",
      "contact.read",
    ];
    const listActiveContacts = vi.fn<CaseContactApi["listActiveContacts"]>(
      async () => new Promise(() => undefined),
    );
    const listLinks = vi.fn<CaseContactApi["listLinks"]>(
      async () => new Promise(() => undefined),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      element: (
        <>
          <AuthorityReloadControl />
          <TicketDetailPage
            contactApi={createCaseContactApi({
              listActiveContacts,
              listLinks,
            })}
            kind="case"
          />
        </>
      ),
      getTenantAuthority: async () => authorityFixture(livePermissions),
      path: "/cases/:caseId",
      permissions: livePermissions,
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Contacts" }));
    await waitFor(() => {
      expect(listLinks).toHaveBeenCalledTimes(1);
      expect(listActiveContacts).toHaveBeenCalledTimes(1);
    });
    const linksSignal = listLinks.mock.calls[0]?.[0].signal;
    const contactsSignal = listActiveContacts.mock.calls[0]?.[0].signal;

    livePermissions = ["case.read"];
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));

    await waitFor(() =>
      expect(screen.queryByRole("tab", { name: "Contacts" })).toBeNull(),
    );
    expect(linksSignal?.aborted).toBe(true);
    expect(contactsSignal?.aborted).toBe(true);
    expect(
      screen.queryByRole("heading", { name: "Customer contacts" }),
    ).toBeNull();
  });

  it("keeps Case DFIR closed for the unsupported own authorization scope", async () => {
    const getWorkspace = vi.fn();
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
      }),
      dfirApi: createCaseDfirApi({ getWorkspace }),
      element: <CaseDetailPage />,
      path: "/cases/:caseId",
      permissions: ["case.read", ...dfirReadPermissions],
      permissionScope: "own",
      route: `/cases/${caseId}`,
    });

    expect(
      await screen.findByRole("heading", { name: operatorCase.title }),
    ).toBeVisible();
    expect(screen.queryByRole("tab", { name: "DFIR" })).toBeNull();
    expect(getWorkspace).not.toHaveBeenCalled();
  });

  it("mounts the bounded Alert DFIR workspace with exact tenant and Alert coordinates", async () => {
    const getWorkspace = vi.fn(async () =>
      projectAlertWorkspace(
        boundAlertDfirWorkspaceFixture(tenantId, alertId),
        tenantId,
        alertId,
      ),
    );
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      alertDfirApi: createAlertDfirApi({ getWorkspace }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", ...alertDfirReadPermissions],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "DFIR" }));
    expect(
      await screen.findByRole("heading", { name: "Alert investigation room" }),
    ).toBeVisible();
    expect(getWorkspace).toHaveBeenCalledWith({
      alertId,
      signal: expect.any(AbortSignal),
      tenantId,
    });
  });

  it("copies only explicit Alert records and binds retries to the exact selection", async () => {
    const contactId = "0198c97d-cf4f-7000-8000-000000000090";
    const publicCommentId = "0198c97d-cf4f-7000-8000-000000000091";
    const privateCommentId = "0198c97d-cf4f-7000-8000-000000000092";
    const escalationError = new Error("retryable transport failure");
    const escalateAlert = vi
      .fn()
      .mockRejectedValueOnce(escalationError)
      .mockRejectedValueOnce(escalationError)
      .mockRejectedValueOnce(escalationError);
    const workspace = projectAlertWorkspace(
      boundAlertDfirWorkspaceFixture(tenantId, alertId),
      tenantId,
      alertId,
    );
    renderTicketPage({
      api: createTicketingApi({
        escalateAlert,
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listAlertContactLinks: async () => ({
          items: [
            {
              id: "0198c97d-cf4f-7000-8000-000000000093",
              tenantId,
              resourceKind: "alert",
              resourceId: alertId,
              contactId,
              role: "primary",
              origin: "manual",
              version: 1,
              createdAt: "2026-08-30T09:00:00Z",
            },
          ],
        }),
        listComments: async () => ({
          items: [
            operatorComment(
              publicCommentId,
              "public",
              "Public escalation note",
            ),
            operatorComment(privateCommentId, "private", "Private SOC note"),
          ],
        }),
      }),
      alertDfirApi: createAlertDfirApi({ getWorkspace: async () => workspace }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.escalate"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("button", { name: "Escalate" }));
    const dialog = screen.getByRole("dialog");
    expect(
      await within(dialog).findByText(/IOCs \(1 available, 0 selected\)/u),
    ).toBeVisible();
    expect(within(dialog).queryByText("Private SOC note")).toBeNull();

    for (const name of [
      /IOCs: domain: bad\.example/u,
      /Assets: host/u,
      /Attachments: memory\.raw/u,
      new RegExp(`Linked contacts: Contact .*${contactId.slice(-5)}`, "u"),
      /Public comments: Public escalation note/u,
    ]) {
      fireEvent.click(within(dialog).getByRole("checkbox", { name }));
    }
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Promote exact triage evidence." },
    });

    const submit = within(dialog).getByRole("button", { name: "Apply action" });
    fireEvent.click(submit);
    await waitFor(() => expect(escalateAlert).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(submit).toBeEnabled());
    fireEvent.click(submit);
    await waitFor(() => expect(escalateAlert).toHaveBeenCalledTimes(2));

    const first = escalateAlert.mock.calls[0]?.[0];
    const second = escalateAlert.mock.calls[1]?.[0];
    expect(first.body.sources[0]?.copySelection).toEqual({
      assetIds: [workspace.data.assets[0]!.id],
      attachmentIds: [workspace.data.attachments[0]!.id],
      contactIds: [contactId],
      fields: [
        "category",
        "description",
        "priority",
        "severity",
        "tags",
        "title",
      ],
      iocIds: [workspace.data.iocs[0]!.id],
      publicCommentIds: [publicCommentId],
    });
    expect(first.idempotencyKey).toBe(second.idempotencyKey);
    expect(JSON.stringify(first.body)).not.toContain(privateCommentId);

    fireEvent.click(
      within(dialog).getByRole("checkbox", { name: /memory\.raw/u }),
    );
    fireEvent.click(submit);
    await waitFor(() => expect(escalateAlert).toHaveBeenCalledTimes(3));
    const third = escalateAlert.mock.calls[2]?.[0];
    expect(third.body.sources[0]?.copySelection).not.toHaveProperty(
      "attachmentIds",
    );
    expect(third.idempotencyKey).not.toBe(first.idempotencyKey);
  });

  it("unlinks from a Case through the Alert-scoped action using freshly loaded versions", async () => {
    const currentAlert = { ...operatorAlert, version: 4 };
    const currentCase = { ...operatorCase, version: 6 };
    const getTicket = vi.fn(
      async (
        kind: "alert" | "case",
        _tenantId: string,
        _resourceId: string,
        _signal?: AbortSignal,
      ) =>
        kind === "alert"
          ? { etag: '"v4"', value: currentAlert }
          : { etag: '"v6"', value: currentCase },
    );
    const unlinkAlertCase = vi.fn(async () => ({
      alertId,
      alertVersion: 5,
      caseId,
      caseVersion: 7,
      linkId: operatorAlertCaseLink().id,
      previousAlertVersion: 4,
      previousCaseVersion: 6,
      replayed: false,
      retractedAt: "2026-09-02T09:00:00Z",
      tenantId,
    }));
    renderTicketPage({
      api: createTicketingApi({
        getTicket,
        listLinks: async () => ({ items: [operatorAlertCaseLink()] }),
        unlinkAlertCase,
      }),
      element: <CaseDetailPage />,
      path: "/cases/:caseId",
      permissions: ["case.read", "case.update", "alert.escalate"],
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Linked" }));
    fireEvent.click(await screen.findByRole("button", { name: "Unlink" }));
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(/cannot be linked again after confirmation/u),
    ).toBeVisible();
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "  Superseded by a different investigation.  " },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Confirm unlink" }),
    );

    await waitFor(() => expect(unlinkAlertCase).toHaveBeenCalledTimes(1));
    expect(unlinkAlertCase).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          caseId,
          expectedCaseVersion: 6,
          expectedVersion: 4,
          reason: "Superseded by a different investigation.",
        },
        etag: '"v4"',
        resourceId: alertId,
        signal: expect.any(AbortSignal),
        tenantId,
      }),
    );
    expect(
      getTicket.mock.calls.some(
        ([kind, scopedTenant, id]) =>
          kind === "alert" && scopedTenant === tenantId && id === alertId,
      ),
    ).toBe(true);
  });

  it("hides unlink unless both live Alert and Case permissions are present", async () => {
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listLinks: async () => ({ items: [operatorAlertCaseLink()] }),
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.escalate"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Linked" }));
    expect(
      await screen.findByRole("link", { name: "Open Case" }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Unlink" })).toBeNull();
  });

  it("mounts related Alerts only in the Alert detail with one combined read/update scope", async () => {
    const listRelations = vi.fn<AlertRelationApi["list"]>(async () => ({
      items: [],
    }));
    const relationApi = createAlertRelationApi({ list: listRelations });
    const alertView = renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listLinks: async () => ({ items: [] }),
      }),
      element: <TicketDetailPage alertRelationApi={relationApi} kind="alert" />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.update"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Linked" }));
    expect(
      await screen.findByRole("heading", { name: "Related Alerts" }),
    ).toBeVisible();
    expect(listRelations).toHaveBeenCalledWith({
      alertId,
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
    });
    alertView.unmount();

    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorCase }),
        listLinks: async () => ({ items: [] }),
      }),
      element: <TicketDetailPage alertRelationApi={relationApi} kind="case" />,
      path: "/cases/:caseId",
      permissions: ["case.read", "case.update", "alert.read", "alert.update"],
      route: `/cases/${caseId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Linked" }));
    expect(
      await screen.findByRole("heading", { name: "Linked Alerts" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Related Alerts" }),
    ).toBeNull();
    expect(listRelations).toHaveBeenCalledTimes(1);
  });

  it("does not request related Alerts when read and update are split across scopes", async () => {
    const listRelations = vi.fn<AlertRelationApi["list"]>();
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listLinks: async () => ({ items: [] }),
      }),
      element: (
        <TicketDetailPage
          alertRelationApi={createAlertRelationApi({ list: listRelations })}
          kind="alert"
        />
      ),
      getTenantAuthority: async () => ({
        ...authorityFixture([]),
        permissions: [
          { permissionKey: "alert.read", scope: "own" },
          { permissionKey: "alert.update", scope: "assigned" },
        ],
      }),
      path: "/alerts/:alertId",
      permissions: [],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("tab", { name: "Linked" }));
    expect(
      await screen.findByRole("heading", { name: "Linked Cases" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Related Alerts" }),
    ).toBeNull();
    expect(listRelations).not.toHaveBeenCalled();
  });

  it("keeps escalation fail-closed and retryable when a selection inventory is unavailable", async () => {
    const escalateAlert = vi.fn();
    const listComments = vi
      .fn()
      .mockRejectedValue(new Error("backend detail must not be displayed"));
    renderTicketPage({
      api: createTicketingApi({
        escalateAlert,
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
        listAlertContactLinks: async () => ({ items: [] }),
        listComments,
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.escalate"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("button", { name: "Escalate" }));
    const dialog = screen.getByRole("dialog");
    expect(
      await within(dialog).findByText("Copy selections unavailable"),
    ).toBeVisible();
    expect(within(dialog).queryByText(/backend detail/u)).toBeNull();
    expect(
      within(dialog).getByRole("button", { name: "Apply action" }),
    ).toBeDisabled();
    expect(escalateAlert).not.toHaveBeenCalled();

    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Retry selection inventory",
      }),
    );
    await waitFor(() => expect(listComments).toHaveBeenCalledTimes(2));
    expect(escalateAlert).not.toHaveBeenCalled();
  });

  it("refreshes the version after 412 and leaves the action open for review", async () => {
    const getTicket = vi
      .fn()
      .mockResolvedValue({ etag: '"v1"', value: operatorAlert });
    const mutateTicket = vi
      .fn()
      .mockRejectedValue(
        new TicketingApiError(
          "This Alert changed on the server. Review the current version.",
          412,
          "precondition_failed",
        ),
      );
    renderTicketPage({
      api: createTicketingApi({ getTicket, mutateTicket }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.claim"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(await screen.findByRole("button", { name: "Claim" }));
    fireEvent.click(screen.getByRole("button", { name: "Apply action" }));

    expect(
      await screen.findByText(
        "This Alert changed on the server. Review the current version.",
      ),
    ).toBeVisible();
    await waitFor(() => expect(getTicket).toHaveBeenCalledTimes(2));
    expect(mutateTicket).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "claim",
        body: { expectedVersion: 1, operatorTeamId: teamId },
        etag: '"v1"',
      }),
    );
    expect(screen.getByRole("dialog")).toBeVisible();
  });

  it("requires live delete authority, a reason, and exact Alert-number confirmation", async () => {
    const deleteAlert = vi.fn(async () => ({
      alertId,
      deletedAt: "2026-08-30T18:20:00.123Z",
      previousVersion: operatorAlert.version,
      replayed: false,
      tenantId,
      tombstoneVersion: operatorAlert.version + 1,
    }));
    renderTicketPage({
      api: createTicketingApi({
        deleteAlert,
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read", "alert.delete"],
      route: `/alerts/${alertId}`,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Delete Alert" }),
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete Alert" }),
    );
    expect(
      await within(dialog).findByText(
        "Enter the reason for deleting this Alert.",
      ),
    ).toBeVisible();

    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "False positive confirmed." },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Type ALT-2026-0042 to confirm"),
      { target: { value: "ALT-2026-0041" } },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete Alert" }),
    );
    expect(
      await within(dialog).findByText(
        "Type ALT-2026-0042 exactly to confirm deletion.",
      ),
    ).toBeVisible();

    fireEvent.change(
      within(dialog).getByLabelText("Type ALT-2026-0042 to confirm"),
      { target: { value: "ALT-2026-0042" } },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Delete Alert" }),
    );

    await waitFor(() => expect(deleteAlert).toHaveBeenCalledTimes(1));
    expect(deleteAlert).toHaveBeenCalledWith({
      body: {
        expectedVersion: operatorAlert.version,
        reason: "False positive confirmed.",
      },
      csrfToken: sessionFixture.csrfToken,
      etag: '"v1"',
      idempotencyKey: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
      resourceId: alertId,
      tenantId,
    });
  });

  it("does not render Alert deletion without live alert.delete authority", async () => {
    renderTicketPage({
      api: createTicketingApi({
        getTicket: async () => ({ etag: '"v1"', value: operatorAlert }),
      }),
      element: <AlertDetailPage />,
      path: "/alerts/:alertId",
      permissions: ["alert.read"],
      route: `/alerts/${alertId}`,
    });

    expect(
      await screen.findByRole("heading", { name: operatorAlert.title }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Delete Alert" })).toBeNull();
  });
});

const unsupportedCustomFieldApi = async (): Promise<never> => {
  throw new Error("Unexpected CustomFieldAdministrationApi call in test");
};

function createCustomFieldApi(
  overrides: Partial<CustomFieldAdministrationApi> = {},
): CustomFieldAdministrationApi {
  return {
    list: async () => ({ items: [] }),
    get: unsupportedCustomFieldApi,
    create: unsupportedCustomFieldApi,
    replace: unsupportedCustomFieldApi,
    archive: unsupportedCustomFieldApi,
    ...overrides,
  };
}

const unsupportedCustomFieldObjectCall = async (): Promise<never> => {
  throw new Error("Unexpected CustomFieldObjectApi call in test");
};

function createCustomFieldObjectApi(
  overrides: Partial<CustomFieldObjectApi> = {},
): CustomFieldObjectApi {
  return {
    get: unsupportedCustomFieldObjectCall,
    replace: unsupportedCustomFieldObjectCall,
    ...overrides,
  };
}

function createCustomFieldObjectProjection(
  version: number,
  value: number,
): CustomFieldObjectProjectionView {
  return {
    definitions: [createCustomFieldDefinition()],
    drafts: { evidence_count: { presence: "present", value } },
    etag: `"v${version}"`,
    objectId: alertId,
    objectType: "alert",
    tenantId,
    version,
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

function createCustomFieldDefinition(): CustomFieldDefinitionView {
  return {
    id: "0198c97d-cf4f-7000-8000-000000000090",
    tenantId,
    objectType: "alert",
    key: "evidence_count",
    label: "Evidence count",
    description: "Confirmed evidence items.",
    dataType: "integer",
    required: true,
    nullable: false,
    archived: false,
    schemaVersion: 1,
    visibility: { customer: false, operator: true },
    editPolicy: {
      customerCreate: false,
      customerUpdate: false,
      operatorCreate: true,
      operatorUpdate: true,
    },
    placement: {
      showInCreate: true,
      showInDetail: true,
      showInList: true,
      showInExport: true,
    },
    requiredOnTransitions: [],
    searchable: false,
    filterable: true,
    sortable: true,
    allowStructuredJson: false,
  };
}

function renderTicketPage({
  api,
  alertDfirApi = createAlertDfirApi(),
  bulkApi = ticketBulkApi,
  columnCatalogApi = {
    listCustomFields: async () => ({ items: [] }),
    listSlaColumns: async () => ({ items: [] }),
  },
  element,
  dfirApi = caseDfirApi,
  exportApi = ticketExportApi,
  getTenantAuthority,
  path,
  permissions,
  permissionScope = "tenant",
  route,
}: {
  api: ReturnType<typeof createTicketingApi>;
  alertDfirApi?: AlertDfirApi;
  bulkApi?: TicketBulkApi;
  columnCatalogApi?: TicketColumnCatalogApi;
  element: React.ReactNode;
  dfirApi?: CaseDfirApi;
  exportApi?: TicketExportApi;
  getTenantAuthority?: () => Promise<TenantAuthorityView>;
  path: string;
  permissions: readonly TenantPermissionKeyView[];
  permissionScope?: TenantAuthorizationScopeView;
  route: string;
}): ReturnType<typeof render> {
  const authority = authorityFixture(permissions, permissionScope);
  const phaseApi = createPhaseTwoApi({
    getTenantAuthority: async () =>
      getTenantAuthority ? getTenantAuthority() : authority,
  });
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-25T12:00:00Z",
    activeTenantId: tenantId,
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
          <TicketingApiProvider api={api}>
            <AlertDfirApiProvider api={alertDfirApi}>
              <CaseDfirApiProvider api={dfirApi}>
                <TicketBulkApiProvider api={bulkApi}>
                  <TicketColumnCatalogApiProvider api={columnCatalogApi}>
                    <TicketExportApiProvider api={exportApi}>
                      <MemoryRouter initialEntries={[route]}>
                        <Routes>
                          <Route path={path} element={element} />
                        </Routes>
                      </MemoryRouter>
                    </TicketExportApiProvider>
                  </TicketColumnCatalogApiProvider>
                </TicketBulkApiProvider>
              </CaseDfirApiProvider>
            </AlertDfirApiProvider>
          </TicketingApiProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
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

function CustomFieldReloadControl(): React.JSX.Element {
  const queryClient = useQueryClient();
  return (
    <button
      type="button"
      onClick={() =>
        void queryClient.refetchQueries({
          exact: true,
          queryKey: ["ticket-custom-fields", "alert", tenantId, alertId],
        })
      }
    >
      Reload custom-field projection
    </button>
  );
}

function createAlertDfirApi(
  overrides: Partial<AlertDfirApi> = {},
): AlertDfirApi {
  return {
    appendCustody: async () => undefined,
    changeLink: async () => undefined,
    assignTask: async () => undefined,
    create: async () => undefined,
    getWorkspace: async () =>
      projectAlertWorkspace(
        boundAlertDfirWorkspaceFixture(tenantId, alertId),
        tenantId,
        alertId,
      ),
    prepareDownload: async () => {
      throw new Error("unexpected prepare download");
    },
    prepareUpload: async () => {
      throw new Error("unexpected prepare upload");
    },
    replaceTaskDetails: async () => undefined,
    replaceTaskChecklist: async () => undefined,
    replaceTaskComments: async () => undefined,
    replace: async () => undefined,
    rescheduleTask: async () => undefined,
    retractRelationship: async () => undefined,
    transitionTask: async () => undefined,
    upload: async () => undefined,
    ...overrides,
  };
}

function createAlertRelationApi(
  overrides: Partial<AlertRelationApi> = {},
): AlertRelationApi {
  return {
    create: unsupportedAlertRelationCallInPageTest,
    list: async () => ({ items: [] }),
    retract: unsupportedAlertRelationCallInPageTest,
    ...overrides,
  };
}

async function unsupportedAlertRelationCallInPageTest(): Promise<never> {
  throw new Error("Unexpected AlertRelationApi call in test");
}

function operatorComment(
  id: string,
  visibility: "private" | "public",
  bodyMarkdown: string,
): TicketComment {
  return {
    projection: "operator",
    id,
    tenantId,
    resourceKind: "alert",
    resourceId: alertId,
    visibility,
    bodyMarkdown,
    author: {
      audience: "operator",
      displayName: "SOC analyst",
      membershipId,
    },
    attachments: [],
    canEdit: false,
    editableUntil: "2026-08-30T09:15:00Z",
    mentions: [],
    origin: "api",
    revision: 1,
    createdAt: "2026-08-30T09:00:00Z",
    updatedAt: "2026-08-30T09:00:00Z",
  };
}

function operatorAlertCaseLink() {
  return {
    projection: "operator" as const,
    id: "0198c97d-cf4f-7000-8000-000000000097",
    tenantId,
    alertId,
    caseId,
    linkedAt: "2026-08-25T08:15:00Z",
    linkedBy: membershipId,
    relationType: "correlation" as const,
    escalationReason: "Correlated investigation",
    copySelection: {},
    copiedFieldSnapshot: {},
    sourceAlertVersion: 1,
  };
}

function mountedOperatorComment(
  kind: "alert" | "case",
  bodyMarkdown: string,
  visibility: "private" | "public" = "public",
): Extract<TicketComment, { projection: "operator" }> {
  return {
    projection: "operator",
    id: "0198c97d-cf4f-7000-8000-000000000096",
    tenantId,
    resourceKind: kind,
    resourceId: kind === "alert" ? alertId : caseId,
    visibility,
    bodyMarkdown,
    author: {
      audience: "operator",
      displayName: "SOC analyst",
      membershipId,
    },
    attachments: [],
    canEdit: true,
    editableUntil: "2099-08-30T09:15:00Z",
    mentions: [],
    origin: "api",
    revision: 1,
    createdAt: "2026-08-30T09:00:00Z",
    updatedAt: "2026-08-30T09:00:00Z",
  };
}

function createCaseDfirApi(overrides: Partial<CaseDfirApi> = {}): CaseDfirApi {
  return {
    appendCustody: async () => undefined,
    changeLink: async () => undefined,
    assignTask: async () => undefined,
    create: async () => undefined,
    getWorkspace: async () =>
      projectWorkspace(
        dfirWorkspaceFixture(),
        "0198c97d-cf4f-7000-8000-000000000001",
        "0198c97d-cf4f-7000-8000-000000000002",
      ),
    prepareDownload: async () => {
      throw new Error("unexpected prepare download");
    },
    prepareUpload: async () => {
      throw new Error("unexpected prepare upload");
    },
    replace: async () => undefined,
    replaceTaskChecklist: async () => undefined,
    replaceTaskComments: async () => undefined,
    replaceTaskDetails: async () => undefined,
    rescheduleTask: async () => undefined,
    retractRelationship: async () => undefined,
    transitionTask: async () => undefined,
    upload: async () => undefined,
    ...overrides,
  };
}

function createTicketBulkApi(
  overrides: Partial<TicketBulkApi> = {},
): TicketBulkApi {
  const fallbackBody: Parameters<TicketBulkApi["request"]>[0]["body"] = {
    kind: "alert",
    mutation: { action: "release" },
    selection: {
      source: "explicit",
      targets: [{ expectedVersion: 1, id: alertId }],
    },
  };
  const fallback = completedBulkJob(fallbackBody);
  return {
    cancel: async () => ({ job: fallback, replayed: false }),
    get: async () => fallback,
    listResults: async () => ({ items: [] }),
    request: async ({ body }) => ({
      job: completedBulkJob(body),
      replayed: false,
    }),
    ...overrides,
  };
}

function createTicketExportApi(
  overrides: Partial<TicketExportApi> = {},
): TicketExportApi {
  const fallbackBody: Parameters<TicketExportApi["request"]>[0]["body"] = {
    comments: "none",
    kind: "alert",
    source: {
      source: "inline",
      spec: {
        columns: [
          {
            coreKey: "ticket",
            pin: "start",
            source: "core",
            visible: true,
          },
        ],
        filters: {
          custom: [],
          priorities: [],
          queue: "all",
          severities: [],
          states: [],
        },
        sort: {
          coreKey: "updated_at",
          direction: "desc",
          nulls: "last",
          source: "core",
        },
      },
    },
  };
  const fallback = completedExportJob(fallbackBody);
  return {
    cancel: async () => ({ job: fallback, replayed: false }),
    download: async ({ expectedArtifact }) => ({
      artifact: expectedArtifact,
      downloadUrl: "https://storage.invalid/private.csv?signature=test",
      expiresAt: "2099-08-26T18:05:00Z",
    }),
    get: async () => fallback,
    request: async ({ body }) => ({
      job: completedExportJob(body),
      replayed: false,
    }),
    ...overrides,
  };
}

function completedExportJob(
  body: Parameters<TicketExportApi["request"]>[0]["body"],
): TicketExportJobView {
  const savedView =
    body.source.source === "saved_view" ? body.source.savedView : undefined;
  return {
    artifact: {
      bytes: 21,
      expiresAt: "2026-08-27T18:00:00Z",
      id: "0198c97d-cf4f-7000-8000-000000000092",
      rows: 1,
      sha256: "e".repeat(64),
    },
    attempts: 1,
    availableAt: "2026-08-26T18:00:00Z",
    comments: body.comments,
    expiresAt: "2026-08-27T18:00:00Z",
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

function completedBulkJob(
  body: Parameters<TicketBulkApi["request"]>[0]["body"],
): TicketBulkJobView {
  let targetCount = 1;
  let selection: TicketBulkJobView["selection"];
  if (body.selection.source === "explicit") {
    const targets = body.selection.targets;
    if (!targets) throw new TypeError("The test bulk selection needs targets.");
    targetCount = targets.length;
    selection = {
      source: "explicit",
      targetCount,
      targetSetSha256: "a".repeat(64),
    };
  } else {
    const query = body.selection.query;
    if (!query) throw new TypeError("The test bulk selection needs a query.");
    if (query.source === "saved_view") {
      const savedView = query.savedView;
      if (!savedView)
        throw new TypeError("The test bulk query needs a Saved View pin.");
      selection = {
        catalogSha256: "b".repeat(64),
        querySha256: "d".repeat(64),
        querySource: "saved_view",
        savedView: {
          id: savedView.id,
          ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000015",
          revision: savedView.expectedRevision,
          specSha256: savedView.expectedSpecSha256,
        },
        source: "query",
        targetCount,
        targetSetSha256: "a".repeat(64),
      };
    } else {
      selection = {
        catalogSha256: "b".repeat(64),
        querySha256: "d".repeat(64),
        querySource: "inline",
        source: "query",
        targetCount,
        targetSetSha256: "a".repeat(64),
      };
    }
  }
  return {
    activeBatch: false,
    availableAt: "2026-08-26T18:00:00Z",
    expiresAt: "2026-08-27T18:00:00Z",
    id: "0198c97d-cf4f-7000-8000-000000000091",
    kind: body.kind,
    mutation: body.mutation,
    ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000015",
    progress: {
      authorizationDenied: 0,
      authorizationRevoked: 0,
      cancelled: 0,
      internalFailure: 0,
      noChange: 0,
      notFoundOrHidden: 0,
      rejected: 0,
      succeeded: targetCount,
      total: targetCount,
      versionConflict: 0,
    },
    requestedAt: "2026-08-26T18:00:00Z",
    requesterUserId: sessionFixture.user.id,
    revision: 2,
    selection,
    state: "completed",
    tenantId,
    terminalAt: "2026-08-26T18:01:00Z",
    updatedAt: "2026-08-26T18:01:00Z",
  };
}

function createCaseContactApi(
  overrides: Partial<CaseContactApi> = {},
): CaseContactApi {
  return {
    archive: unexpectedCaseContactMutation,
    link: unexpectedCaseContactMutation,
    listActiveContacts: async () => ({ items: [] }),
    listLinks: async () => ({ items: [] }),
    ...overrides,
  };
}

async function unexpectedCaseContactMutation(): Promise<never> {
  throw new Error("Unexpected Case contact mutation");
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
  scope: TenantAuthorizationScopeView = "tenant",
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-25T08:00:00Z",
    legacyMembershipRole: "analyst",
    membershipId: "0198c97d-cf4f-7000-8000-000000000015",
    membershipStatus: "active",
    operatorTeamRelationships: [
      {
        assignmentEpochId: "0198c97d-cf4f-7000-8000-000000000018",
        operatorTeamId: teamId,
      },
    ],
    permissions: permissions.map((permissionKey) => ({
      permissionKey,
      scope,
    })),
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}
