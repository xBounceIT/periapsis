import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ActivityProjection } from "@periapsis/contracts";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import { TenantDateTimeProvider } from "../lib/tenant-date-time-context";
import type {
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { GlobalActivityPage } from "./global-activity-page";
import { TicketingApiProvider } from "./ticketing-context";
import {
  createTicketingApi,
  teamId,
  tenantId,
  userId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("global tenant Activity", () => {
  it("loads only the selected live-authorized resource feed", async () => {
    const listActivityFeed = vi.fn(
      async (kind: "alert" | "case", _tenantId: string) => ({
        items: [operatorActivity(kind)],
      }),
    );
    renderActivity({
      api: createTicketingApi({ listActivityFeed }),
      permissions: [
        "alert.read",
        "alert.activity.read",
        "case.read",
        "case.activity.read",
      ],
    });

    expect(await screen.findByText("Alert assigned")).toBeVisible();
    expect(listActivityFeed).toHaveBeenCalledWith(
      "alert",
      tenantId,
      undefined,
      expect.any(AbortSignal),
    );
    fireEvent.click(screen.getByRole("button", { name: "Cases" }));
    expect(await screen.findByText("Case assigned")).toBeVisible();
    expect(listActivityFeed).toHaveBeenCalledWith(
      "case",
      tenantId,
      undefined,
      expect.any(AbortSignal),
    );
    expect(screen.getByText(/Europe\/Rome/u)).toBeVisible();
  });

  it("does not request an unauthorized Alert feed when only Case scopes exist", async () => {
    const listActivityFeed = vi.fn(async (kind: "alert" | "case") => ({
      items: [operatorActivity(kind)],
    }));
    renderActivity({
      api: createTicketingApi({ listActivityFeed }),
      permissions: ["case.read", "case.activity.read"],
    });

    expect(await screen.findByText("Case assigned")).toBeVisible();
    expect(listActivityFeed).toHaveBeenCalledTimes(1);
    expect(listActivityFeed.mock.calls[0]?.[0]).toBe("case");
    expect(screen.queryByRole("button", { name: "Alerts" })).toBeNull();
  });

  it("sends no request without an active tenant or matching compound authority", async () => {
    const listActivityFeed = vi.fn();
    const { rerender } = renderActivity({
      activeTenantId: null,
      api: createTicketingApi({ listActivityFeed }),
      permissions: [
        "alert.read",
        "alert.activity.read",
        "case.read",
        "case.activity.read",
      ],
    });

    expect(
      await screen.findByRole("heading", {
        name: "Select a tenant before opening Activity",
      }),
    ).toBeVisible();
    expect(listActivityFeed).not.toHaveBeenCalled();

    rerender(
      <TestActivityTree
        activeTenantId={tenantId}
        api={createTicketingApi({ listActivityFeed })}
        permissions={["alert.read"]}
      />,
    );
    expect(
      await screen.findByRole("heading", { name: "Activity is not available" }),
    ).toBeVisible();
    expect(listActivityFeed).not.toHaveBeenCalled();
  });

  it("does not combine ticket-read and activity-read grants from different scopes", async () => {
    const listActivityFeed = vi.fn();
    renderActivity({
      api: createTicketingApi({ listActivityFeed }),
      permissionGrants: [
        { permissionKey: "alert.read", scope: "assigned" },
        { permissionKey: "alert.activity.read", scope: "operator_team" },
      ],
      permissions: [],
    });

    expect(
      await screen.findByRole("heading", { name: "Activity is not available" }),
    ).toBeVisible();
    expect(listActivityFeed).not.toHaveBeenCalled();
  });

  it("loads the next cursor and rejects a duplicate across page boundaries", async () => {
    const first = operatorActivity("alert");
    const listActivityFeed = vi
      .fn()
      .mockResolvedValueOnce({
        items: [first],
        nextCursor: first.id,
      })
      .mockResolvedValueOnce({ items: [first] });
    renderActivity({
      api: createTicketingApi({ listActivityFeed }),
      permissions: ["alert.read", "alert.activity.read"],
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Load older activity" }),
    );
    expect(await screen.findByText("Activity feed rejected")).toBeVisible();
    expect(listActivityFeed).toHaveBeenLastCalledWith(
      "alert",
      tenantId,
      first.id,
      expect.any(AbortSignal),
    );
    expect(screen.queryByText("Alert assigned")).toBeNull();
  });
});

function renderActivity({
  activeTenantId = tenantId,
  api,
  permissionGrants,
  permissions,
}: {
  activeTenantId?: string | null;
  api: ReturnType<typeof createTicketingApi>;
  permissionGrants?: TenantAuthorityView["permissions"];
  permissions: readonly TenantPermissionKeyView[];
}): ReturnType<typeof render> {
  return render(
    <TestActivityTree
      activeTenantId={activeTenantId}
      api={api}
      {...(permissionGrants ? { permissionGrants } : {})}
      permissions={permissions}
    />,
  );
}

function TestActivityTree({
  activeTenantId,
  api,
  permissionGrants,
  permissions,
}: {
  activeTenantId: string | null;
  api: ReturnType<typeof createTicketingApi>;
  permissionGrants?: TenantAuthorityView["permissions"];
  permissions: readonly TenantPermissionKeyView[];
}): React.JSX.Element {
  const authority = authorityFixture(permissions, permissionGrants);
  const phaseApi = createPhaseTwoApi({
    getTenantAuthority: async () => authority,
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
  return (
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
            <TicketingApiProvider api={api}>
              <MemoryRouter>
                <GlobalActivityPage />
              </MemoryRouter>
            </TicketingApiProvider>
          </TenantDateTimeProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>
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

function operatorActivity(
  kind: "alert" | "case",
): Extract<ActivityProjection, { projection: "operator" }> {
  return {
    actor: {
      displayName: "Incident analyst",
      membershipId: userId,
      origin: "operator",
    },
    id:
      kind === "alert"
        ? "0198c97d-cf4f-7000-8000-000000000089"
        : "0198c97d-cf4f-7000-8000-000000000088",
    kind: "assigned",
    occurredAt: "2026-09-02T22:30:00Z",
    projection: "operator",
    resourceId:
      kind === "alert"
        ? "0198c97d-cf4f-7000-8000-000000000081"
        : "0198c97d-cf4f-7000-8000-000000000082",
    resourceKind: kind,
    summary: `${kind === "alert" ? "Alert" : "Case"} assigned`,
    tenantId,
  };
}
