import type { AlertRelation } from "@periapsis/contracts";
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

import type { TicketingApi } from "../lib/ticketing-api";
import type { AlertRelationApi } from "./alert-relation-api";
import { AlertRelationPanel } from "./alert-relation-panel";
import { flattenAlertRelationPages } from "./alert-relation-panel-model";
import { TicketingApiProvider } from "./ticketing-context";
import {
  alertId,
  createTicketingApi,
  operatorAlert,
  tenantId,
} from "./ticketing-test-fixtures";

const relatedAlertId = "0198c97d-cf4f-7000-8000-000000000021";
const secondRelatedAlertId = "0198c97d-cf4f-7000-8000-000000000022";
const relationId = "0198c97d-cf4f-7000-8000-000000000041";

async function unsupportedAlertRelationCall(): Promise<never> {
  throw new Error("Unexpected AlertRelationApi call");
}

afterEach(cleanup);

describe("AlertRelationPanel", () => {
  it("loads only with manage authority and creates from both current snapshots", async () => {
    const list = vi.fn<AlertRelationApi["list"]>(async () => ({ items: [] }));
    const create = vi.fn<AlertRelationApi["create"]>(async (input) => ({
      tenantId,
      alertId,
      relatedAlertId: input.targetAlertId,
      relationId,
      relationType: input.relationType,
      previousAlertVersion: input.expectedAlertVersion,
      alertVersion: input.expectedAlertVersion + 1,
      previousRelatedAlertVersion: input.expectedTargetVersion,
      relatedAlertVersion: input.expectedTargetVersion + 1,
      occurredAt: "2026-09-02T08:02:00Z",
      replayed: false,
    }));
    const getTicket = vi.fn<TicketingApi["getTicket"]>(
      async (_kind, _tenant, resourceId) => ({
        etag: '"v4"',
        value: {
          ...operatorAlert,
          alertNumber: "ALT-2026-0043",
          id: resourceId,
          version: 4,
        },
      }),
    );
    const reload = vi.fn(async () => ({ etag: '"v2"', version: 2 }));
    renderPanel({
      api: createRelationApi({ create, list }),
      onReloadLatest: reload,
      ticketApi: createTicketingApi({ getTicket }),
    });

    expect(
      await screen.findByRole("heading", { name: "Related Alerts" }),
    ).toBeVisible();
    expect(list).toHaveBeenCalledWith({
      alertId,
      limit: 50,
      signal: expect.any(AbortSignal),
      tenantId,
    });
    const addRelationship = screen.getByRole("button", {
      name: "Add relationship",
    });
    await waitFor(() => expect(addRelationship).toBeEnabled());
    fireEvent.click(addRelationship);
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Target Alert ID"), {
      target: { value: relatedAlertId },
    });
    fireEvent.change(within(dialog).getByLabelText("Relationship"), {
      target: { value: "duplicate_of" },
    });
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Literal <rule> match" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Record relationship" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(getTicket).toHaveBeenCalledWith(
      "alert",
      tenantId,
      relatedAlertId,
      expect.any(AbortSignal),
    );
    expect(create).toHaveBeenCalledWith({
      alertEtag: '"v1"',
      alertId,
      csrfToken: "csrf-alert-relations",
      expectedAlertVersion: 1,
      expectedTargetVersion: 4,
      idempotencyKey: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
      reason: "Literal <rule> match",
      relationType: "duplicate_of",
      signal: expect.any(AbortSignal),
      targetAlertId: relatedAlertId,
      tenantId,
    });
    expect(
      await screen.findByText(
        "Alert relationship recorded without merging either Alert.",
      ),
    ).toBeVisible();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(
      screen.getByText(
        "Reload both relationship evidence and the current Alert snapshot.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Add relationship" }),
    ).toBeDisabled();
  });

  it("appends a reasoned retraction while retaining the original evidence", async () => {
    const active = relation();
    const retracted = {
      ...active,
      status: "retracted",
      retraction: {
        reason: "Correlation disproved by endpoint ownership",
        previousSourceVersion: 10,
        sourceVersion: 11,
        previousTargetVersion: 7,
        targetVersion: 8,
        retractedAt: "2026-09-02T09:00:00Z",
      },
      relatedAlert: {
        ...active.relatedAlert,
        version: 8,
        updatedAt: "2026-09-02T09:00:00Z",
      },
    } satisfies AlertRelation;
    const list = vi
      .fn<AlertRelationApi["list"]>()
      .mockResolvedValueOnce({ items: [active] })
      .mockResolvedValue({ items: [retracted] });
    const retract = vi.fn<AlertRelationApi["retract"]>(async (input) => ({
      tenantId,
      alertId,
      relatedAlertId,
      relationId,
      relationType: "correlation",
      previousAlertVersion: input.expectedAlertVersion,
      alertVersion: input.expectedAlertVersion + 1,
      previousRelatedAlertVersion: input.expectedRelatedAlertVersion,
      relatedAlertVersion: input.expectedRelatedAlertVersion + 1,
      occurredAt: "2026-09-02T09:00:00Z",
      replayed: false,
    }));
    renderPanel({
      alertEtag: '"v10"',
      alertVersion: 10,
      api: createRelationApi({ list, retract }),
      onReloadLatest: async () => ({ etag: '"v11"', version: 11 }),
      ticketApi: createTicketingApi({
        getTicket: async () => ({
          etag: '"v7"',
          value: {
            ...operatorAlert,
            alertNumber: "ALT-2026-0043",
            id: relatedAlertId,
            version: 7,
          },
        }),
      }),
    });

    expect(await screen.findByText("Same command lineage")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Retract" }));
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(/original evidence is retained/u),
    ).toBeVisible();
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Correlation disproved by endpoint ownership" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Append retraction" }),
    );

    await waitFor(() => expect(retract).toHaveBeenCalledTimes(1));
    expect(retract).toHaveBeenCalledWith(
      expect.objectContaining({
        alertEtag: '"v10"',
        alertId,
        expectedAlertVersion: 10,
        expectedRelatedAlertVersion: 7,
        reason: "Correlation disproved by endpoint ownership",
        relation: active,
        tenantId,
      }),
    );
    expect(
      await screen.findByText(
        "Retraction appended; the original relationship remains immutable.",
      ),
    ).toBeVisible();
    expect(await screen.findByText("Same command lineage")).toBeVisible();
    expect(
      await screen.findByText("Correlation disproved by endpoint ownership"),
    ).toBeVisible();
  });

  it("does not mount or request related Alerts without the combined authority", () => {
    const list = vi.fn<AlertRelationApi["list"]>();
    renderPanel({ api: createRelationApi({ list }), canManage: false });

    expect(
      screen.queryByRole("heading", { name: "Related Alerts" }),
    ).toBeNull();
    expect(list).not.toHaveBeenCalled();
  });

  it("rejects duplicate pairs and ordering drift across loaded pages", () => {
    const first = relation();
    const second = relation({
      id: "0198c97d-cf4f-7000-8000-000000000040",
      targetAlertId: secondRelatedAlertId,
      relatedAlert: {
        ...first.relatedAlert,
        id: secondRelatedAlertId,
      },
    });
    expect(
      flattenAlertRelationPages([{ items: [first] }, { items: [second] }]),
    ).toMatchObject({ canonical: true, items: [first, second] });
    expect(
      flattenAlertRelationPages([{ items: [first] }, { items: [first] }]),
    ).toEqual({ canonical: false, items: [] });
    expect(
      flattenAlertRelationPages([{ items: [second] }, { items: [first] }]),
    ).toEqual({ canonical: false, items: [] });
  });
});

function renderPanel({
  alertEtag = '"v1"',
  alertVersion = 1,
  api = createRelationApi(),
  canManage = true,
  onReloadLatest = async () => ({ etag: '"v1"', version: 1 }),
  ticketApi = createTicketingApi(),
}: {
  alertEtag?: string;
  alertVersion?: number;
  api?: AlertRelationApi;
  canManage?: boolean;
  onReloadLatest?: () => Promise<{ etag: string; version: number } | null>;
  ticketApi?: TicketingApi;
} = {}): ReturnType<typeof render> {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <TicketingApiProvider api={ticketApi}>
        <MemoryRouter>
          <AlertRelationPanel
            alertEtag={alertEtag}
            alertId={alertId}
            alertVersion={alertVersion}
            api={api}
            authorityEpoch="tenant-authority-v1"
            canManage={canManage}
            csrfToken="csrf-alert-relations"
            onReloadLatest={onReloadLatest}
            sessionId="session-alert-relations"
            tenantId={tenantId}
          />
        </MemoryRouter>
      </TicketingApiProvider>
    </QueryClientProvider>,
  );
}

function createRelationApi(
  overrides: Partial<AlertRelationApi> = {},
): AlertRelationApi {
  return {
    create: unsupportedAlertRelationCall,
    list: async () => ({ items: [] }),
    retract: unsupportedAlertRelationCall,
    ...overrides,
  };
}

function relation(overrides: Partial<AlertRelation> = {}): AlertRelation {
  const target = overrides.targetAlertId ?? relatedAlertId;
  return {
    id: relationId,
    tenantId,
    sourceAlertId: alertId,
    targetAlertId: target,
    relationType: "correlation",
    direction: "symmetric",
    status: "active",
    reason: "Same command lineage",
    previousSourceVersion: 1,
    sourceVersion: 2,
    previousTargetVersion: 5,
    targetVersion: 6,
    linkedAt: "2026-09-02T08:00:00Z",
    relatedAlert: {
      id: target,
      number: "ALT-2026-0043",
      title: "Related endpoint signal",
      severity: "high",
      stateKey: "investigating",
      version: 7,
      updatedAt: "2026-09-02T08:01:00Z",
    },
    ...overrides,
  };
}
