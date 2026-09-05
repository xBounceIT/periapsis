import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SlaAdminApi } from "./sla-api";
import { TenantSlaWorkspace } from "./sla-workspace";
import {
  calendarFixture,
  createSlaApiMock,
  policyFixture,
  simulationFixture,
  slaObjectId,
  slaTenantId,
} from "./sla-test-fixtures";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TenantSlaWorkspace", () => {
  it("denies by default without treating the UI as an authorization boundary", () => {
    const listPolicies = vi.fn<SlaAdminApi["listPolicies"]>();
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({ listPolicies })}
        canManage={false}
        canRead={false}
        canSimulate={false}
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    expect(screen.getByText("SLA authority required")).toBeVisible();
    expect(screen.getByText(/revalidates every mutation/u)).toBeVisible();
    expect(listPolicies).not.toHaveBeenCalled();
  });

  it("creates a calendar with a payload-stable idempotency key", async () => {
    const createCalendar = vi.fn<SlaAdminApi["createCalendar"]>(
      async ({ body }) => ({
        etag: '"sla-calendar-v1"',
        value: { ...calendarFixture, ...body },
      }),
    );
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({
          createCalendar,
          listCalendars: async () => ({ items: [] }),
        })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf-token"
        initialPanel="calendars"
        tenantId={slaTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Create calendar" }),
    );
    fireEvent.change(screen.getByLabelText("Stable key"), {
      target: { value: "rome_escalation" },
    });
    fireEvent.change(screen.getByLabelText("Label"), {
      target: { value: "Rome escalation hours" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Create calendar" }).at(-1)!,
    );
    await waitFor(() => expect(createCalendar).toHaveBeenCalledTimes(1));
    expect(createCalendar.mock.calls[0]?.[0]).toMatchObject({
      csrfToken: "csrf-token",
      tenantId: slaTenantId,
    });
    expect(createCalendar.mock.calls[0]?.[0].idempotencyKey).toMatch(
      /^[0-9a-f-]{36}$/u,
    );
    expect(createCalendar.mock.calls[0]?.[0].body).toMatchObject({
      key: "rome_escalation",
      timezone: "Europe/Rome",
    });
    expect(createCalendar.mock.calls[0]?.[0].body.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  });

  it("versions the current policy with its strong ETag", async () => {
    const versionPolicy = vi.fn<SlaAdminApi["versionPolicy"]>(
      async ({ body }) => ({
        etag: '"sla-policy-v2"',
        value: {
          ...policyFixture,
          ...body,
          metrics: body.metrics.map((metric, position) => ({
            ...metric,
            position,
          })),
          triggers: body.triggers.map((trigger, position) => ({
            ...trigger,
            position,
          })),
          version: 2,
          resourceVersion: 2,
        },
      }),
    );
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({ versionPolicy })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    await screen.findByRole("heading", { name: "Version Critical response" });
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Critical response v2" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish new version" }),
    );
    await waitFor(() => expect(versionPolicy).toHaveBeenCalledTimes(1));
    expect(versionPolicy.mock.calls[0]?.[0]).toMatchObject({
      etag: '"sla-policy-v1"',
      id: policyFixture.id,
    });
  });

  it("runs a bounded simulation without idempotency or persistence controls", async () => {
    const fallbackApi = createSlaApiMock();
    const simulatePolicy = vi.fn<SlaAdminApi["simulatePolicy"]>((input) =>
      fallbackApi.simulatePolicy(input),
    );
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({ simulatePolicy })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        initialPanel="simulator"
        tenantId={slaTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Timeline simulator" });
    fireEvent.change(screen.getByLabelText("Example object UUIDv7"), {
      target: { value: slaObjectId },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    await waitFor(() => expect(simulatePolicy).toHaveBeenCalledTimes(1));
    expect(simulatePolicy.mock.calls[0]?.[0]).toMatchObject({
      id: policyFixture.id,
      tenantId: slaTenantId,
    });
    expect(await screen.findByText("50.0%")).toBeVisible();
    expect(screen.getByText(simulationFixture.simulationDigest)).toBeVisible();
  });

  it("rejects a simulation projection that swaps a bound metric instance", async () => {
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({
          simulatePolicy: async () => ({
            ...simulationFixture,
            metrics: simulationFixture.metrics.map((metric) => ({
              ...metric,
              metricInstanceId: slaObjectId,
            })),
          }),
        })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        initialPanel="simulator"
        tenantId={slaTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Timeline simulator" });
    fireEvent.change(screen.getByLabelText("Example object UUIDv7"), {
      target: { value: slaObjectId },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run simulation" }));
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(screen.queryByText("50.0%")).not.toBeInTheDocument();
  });

  it("supports roving keyboard focus between administration sections", async () => {
    const listCalendars = vi.fn<SlaAdminApi["listCalendars"]>(async () => ({
      items: [calendarFixture],
    }));
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({ listCalendars })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    const policies = screen.getByRole("tab", { name: /Policies/u });
    fireEvent.keyDown(policies, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: /Calendars/u })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await waitFor(() => expect(listCalendars).toHaveBeenCalledTimes(1));
  });

  it("rejects a cross-tenant catalog projection before rendering it", async () => {
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({
          listPolicies: async () => ({
            items: [
              {
                ...policyFixture,
                tenantId: "01991c20-7d5f-7000-8000-000000000099",
              },
            ],
          }),
        })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(
      screen.getByText("Policy catalog could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText(policyFixture.name)).not.toBeInTheDocument();
  });

  it("refuses weak ETags before opening a version editor", async () => {
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({
          getPolicy: async () => ({
            etag: 'W/"policy-v1"',
            value: policyFixture,
          }),
        })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Version Critical response" }),
    ).not.toBeInTheDocument();
  });

  it("rejects a duplicate catalog identity returned on a later page", async () => {
    const listPolicies = vi.fn<SlaAdminApi["listPolicies"]>(
      async ({ after }) =>
        after
          ? { items: [policyFixture] }
          : { items: [policyFixture], nextCursor: "next-page" },
    );
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({ listPolicies })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(
      screen.getByText("Policy catalog could not be loaded."),
    ).toBeVisible();
    expect(screen.getAllByText(policyFixture.name)).toHaveLength(1);
  });

  it("rejects a version response that does not advance concurrency state", async () => {
    render(
      <TenantSlaWorkspace
        api={createSlaApiMock({
          versionPolicy: async ({ body }) => ({
            etag: '"sla-policy-v1"',
            value: {
              ...policyFixture,
              ...body,
              metrics: body.metrics.map((metric, position) => ({
                ...metric,
                position,
              })),
              triggers: body.triggers.map((trigger, position) => ({
                ...trigger,
                position,
              })),
            },
          }),
        })}
        canManage
        canRead
        canSimulate
        csrfToken="csrf"
        tenantId={slaTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    await screen.findByRole("heading", { name: "Version Critical response" });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish new version" }),
    );
    expect(await screen.findByText("SLA action not completed")).toBeVisible();
    expect(screen.queryByText(/version 1 is current/u)).not.toBeInTheDocument();
  });
});
