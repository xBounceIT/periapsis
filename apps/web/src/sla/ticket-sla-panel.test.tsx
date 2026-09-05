import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  CustomerTicketSlaProjection,
  SlaCustomerMetricProjection,
  SlaMetricProjection,
} from "./model";
import type { SlaAdminApi } from "./sla-api";
import { TicketSlaPanel } from "./ticket-sla-panel";
import {
  createSlaApiMock,
  slaMetricInstanceId,
  slaObjectId,
  slaTenantId,
  ticketSlaFixture,
} from "./sla-test-fixtures";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TicketSlaPanel", () => {
  it("does not call the API when sla.read is absent", () => {
    const getTicketSla = vi.fn<SlaAdminApi["getTicketSla"]>();
    render(
      <TicketSlaPanel
        api={createSlaApiMock({ getTicketSla })}
        canOverride={false}
        canRead={false}
        csrfToken="csrf"
        expectedAudience="operator"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    expect(screen.getByText("SLA authority required")).toBeVisible();
    expect(getTicketSla).not.toHaveBeenCalled();
  });

  it("fails closed if a customer projection contains a private metric", async () => {
    const privateProjection = {
      ...customerProjection(),
      metrics: [customerMetric(ticketSlaFixture.metrics[0]!)],
    };
    Object.defineProperty(privateProjection.metrics[0]!, "customerVisible", {
      enumerable: true,
      value: false,
    });
    render(
      <TicketSlaPanel
        api={createSlaApiMock({
          getTicketSla: async () => ({
            etag: '"sla-object-v3"',
            value: privateProjection,
          }),
        })}
        canOverride={false}
        canRead
        csrfToken="csrf"
        expectedAudience="customer"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(
      screen.getByText("The SLA projection could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("First response")).not.toBeInTheDocument();
  });

  it("binds an operator override to ETag, aggregate version, reason, and idempotency", async () => {
    const overrideTicketSla = vi.fn<SlaAdminApi["overrideTicketSla"]>(
      async ({ body }) => ({
        projection: {
          etag: '"sla-object-v4"',
          value: {
            ...ticketSlaFixture,
            aggregateVersion: 4,
            metrics: ticketSlaFixture.metrics.map((metric) => ({
              ...metric,
              metricVersion: metric.metricVersion + 1,
            })),
          },
        },
        receipt: {
          tenantId: slaTenantId,
          objectType: "case",
          objectId: slaObjectId,
          overrideId: body.overrideId,
          kind: "extend",
          outcome: "metric_updated",
          slaInstanceId: ticketSlaFixture.slaInstanceId,
          metricInstanceId: slaMetricInstanceId,
          aggregateVersion: 4,
          policyId: ticketSlaFixture.policyId,
          policyVersion: ticketSlaFixture.policyVersion,
          previousVersion: 2,
          currentVersion: 3,
          occurredAt: "2026-08-26T08:16:00Z",
          replayed: false,
        },
      }),
    );
    render(
      <TicketSlaPanel
        api={createSlaApiMock({ overrideTicketSla })}
        canOverride
        canRead
        csrfToken="csrf-token"
        expectedAudience="operator"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Service clocks" });
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Customer approved a fifteen minute extension" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Apply governed override" }),
    );
    await waitFor(() => expect(overrideTicketSla).toHaveBeenCalledTimes(1));
    const call = overrideTicketSla.mock.calls[0]?.[0];
    expect(call).toMatchObject({
      csrfToken: "csrf-token",
      etag: '"sla-object-v3"',
      kind: "case",
      objectId: slaObjectId,
      tenantId: slaTenantId,
      body: {
        expectedMetricVersion: 2,
        extensionMicros: 900_000_000,
        kind: "extend",
        metricInstanceId: slaMetricInstanceId,
      },
    });
    expect(call?.body.overrideId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    expect(call?.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/u);
    expect(await screen.findByText(/extend recorded/u)).toBeVisible();
  });

  it("keeps the prior clock when the mutation receipt and metric projection disagree", async () => {
    render(
      <TicketSlaPanel
        api={createSlaApiMock({
          overrideTicketSla: async ({ body }) => ({
            projection: {
              etag: '"sla-object-v4"',
              value: { ...ticketSlaFixture, aggregateVersion: 4 },
            },
            receipt: {
              tenantId: slaTenantId,
              objectType: "case",
              objectId: slaObjectId,
              overrideId: body.overrideId,
              kind: "extend",
              outcome: "metric_updated",
              slaInstanceId: ticketSlaFixture.slaInstanceId,
              metricInstanceId: slaMetricInstanceId,
              aggregateVersion: 4,
              policyId: ticketSlaFixture.policyId,
              policyVersion: ticketSlaFixture.policyVersion,
              previousVersion: 2,
              currentVersion: 3,
              occurredAt: "2026-08-26T08:16:00Z",
              replayed: false,
            },
          }),
        })}
        canOverride
        canRead
        csrfToken="csrf"
        expectedAudience="operator"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Service clocks" });
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Customer approved a fifteen minute extension" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Apply governed override" }),
    );
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(screen.getByText("aggregate v3")).toBeVisible();
    expect(screen.queryByText(/extend recorded/u)).not.toBeInTheDocument();
  });

  it("never renders the privileged override form for a customer audience", async () => {
    const getTicketSla = vi.fn<SlaAdminApi["getTicketSla"]>(async () => ({
      etag: '"sla-object-v3"',
      value: customerProjection(),
    }));
    render(
      <TicketSlaPanel
        api={createSlaApiMock({ getTicketSla })}
        canOverride
        canRead
        csrfToken="csrf"
        expectedAudience="customer"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Service clocks" });
    expect(
      screen.queryByRole("heading", { name: "Override SLA" }),
    ).not.toBeInTheDocument();
    expect(getTicketSla).toHaveBeenCalledWith(
      expect.objectContaining({ audience: "customer" }),
    );
  });

  it("rejects a cross-tenant ticket clock even when its object ID matches", async () => {
    render(
      <TicketSlaPanel
        api={createSlaApiMock({
          getTicketSla: async () => ({
            etag: '"sla-object-v3"',
            value: {
              ...ticketSlaFixture,
              tenantId: "01991c20-7d5f-7000-8000-000000000099",
            },
          }),
        })}
        canOverride={false}
        canRead
        csrfToken="csrf"
        expectedAudience="operator"
        kind="case"
        objectId={slaObjectId}
        tenantId={slaTenantId}
      />,
    );
    expect(
      await screen.findByText("The SLA projection could not be loaded."),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Service clocks" }),
    ).not.toBeInTheDocument();
  });
});

function customerProjection(): CustomerTicketSlaProjection {
  return {
    audience: "customer",
    tenantId: ticketSlaFixture.tenantId,
    objectType: ticketSlaFixture.objectType,
    objectId: ticketSlaFixture.objectId,
    projectedAt: ticketSlaFixture.projectedAt,
    metrics: ticketSlaFixture.metrics.map(customerMetric),
    columns: ticketSlaFixture.columns.map((column) => ({
      key: column.key,
      label: column.label,
      calculation: column.calculation,
      format: column.format,
      state: column.state,
      ...(column.instant === undefined ? {} : { instant: column.instant }),
      ...(column.durationMicros === undefined
        ? {}
        : { durationMicros: column.durationMicros }),
      ...(column.percentage === undefined
        ? {}
        : { percentage: column.percentage }),
      ...(column.styleKey === undefined ? {} : { styleKey: column.styleKey }),
      materializedAt: column.materializedAt,
    })),
  };
}

function customerMetric(
  source: SlaMetricProjection,
): SlaCustomerMetricProjection {
  return {
    key: source.key,
    label: source.label,
    state: source.state,
    ...(source.startedAt === undefined ? {} : { startedAt: source.startedAt }),
    ...(source.dueAt === undefined ? {} : { dueAt: source.dueAt }),
    remainingSeconds: source.remainingSeconds,
    consumedPercentage: source.consumedPercentage,
    ...(source.breachedAt === undefined
      ? {}
      : { breachedAt: source.breachedAt }),
    ...(source.completedAt === undefined
      ? {}
      : { completedAt: source.completedAt }),
  };
}
