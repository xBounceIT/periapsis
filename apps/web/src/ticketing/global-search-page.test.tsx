import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { GlobalSearchPage } from "./global-search-page";
import { canonicalSearch } from "./global-search-page-model";
import { TicketingApiProvider } from "./ticketing-context";
import {
  createTicketingApi,
  operatorAlert,
  operatorCase,
  teamId,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("global tenant search", () => {
  it("searches only server-authorized Alert and Case projections", async () => {
    const listTickets = vi.fn(async (kind: "alert" | "case") => ({
      items: [kind === "alert" ? operatorAlert : operatorCase],
    }));
    renderSearch({
      api: createTicketingApi({ listTickets }),
      permissions: ["alert.read", "case.read"],
      route: "/search?q=%20powershell%20",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    expect(
      await screen.findByRole("link", { name: /CASE-2026-0007/u }),
    ).toBeVisible();
    await waitFor(() => expect(listTickets).toHaveBeenCalledTimes(2));
    expect(listTickets).toHaveBeenCalledWith(
      "alert",
      tenantId,
      {
        limit: 20,
        search: "powershell",
        sort: "updated_at_desc",
      },
      expect.any(AbortSignal),
    );
    expect(listTickets).toHaveBeenCalledWith(
      "case",
      tenantId,
      {
        limit: 20,
        search: "powershell",
        sort: "updated_at_desc",
      },
      expect.any(AbortSignal),
    );
  });

  it("stores a trimmed query in the URL without retaining result data", async () => {
    const listTickets = vi.fn(async () => ({ items: [] }));
    renderSearch({
      api: createTicketingApi({ listTickets }),
      permissions: ["alert.read"],
      route: "/search",
    });

    fireEvent.change(await screen.findByLabelText("Search terms"), {
      target: { value: "  suspicious host  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Search tenant" }));

    expect(await screen.findByTestId("search-location")).toHaveTextContent(
      "?q=suspicious+host",
    );
    await waitFor(() =>
      expect(listTickets).toHaveBeenCalledWith(
        "alert",
        tenantId,
        expect.objectContaining({ search: "suspicious host" }),
        expect.any(AbortSignal),
      ),
    );
  });

  it("does not query a ticket surface missing from live authority", async () => {
    const listTickets = vi.fn(async (_kind: "alert" | "case") => ({
      items: [operatorAlert],
    }));
    renderSearch({
      api: createTicketingApi({ listTickets }),
      permissions: ["alert.read"],
      route: "/search?q=endpoint",
    });

    expect(
      await screen.findByRole("link", { name: /ALT-2026-0042/u }),
    ).toBeVisible();
    expect(screen.queryByRole("heading", { name: "Cases" })).toBeNull();
    expect(listTickets).toHaveBeenCalledTimes(1);
    expect(listTickets.mock.calls[0]?.[0]).toBe("alert");
  });

  it("sends no search request without an active tenant", async () => {
    const listTickets = vi.fn(async () => ({ items: [] }));
    renderSearch({
      activeTenantId: null,
      api: createTicketingApi({ listTickets }),
      permissions: ["alert.read", "case.read"],
      route: "/search?q=endpoint",
    });

    expect(
      await screen.findByRole("heading", {
        name: "Select a tenant before searching",
      }),
    ).toBeVisible();
    expect(listTickets).not.toHaveBeenCalled();
  });

  it("canonicalizes and bounds URL input", () => {
    expect(canonicalSearch(null)).toBe("");
    expect(canonicalSearch("  incident  ")).toBe("incident");
    expect(canonicalSearch("x".repeat(201))).toHaveLength(200);
    expect(canonicalSearch("x".repeat(199) + "🛰️")).toBe("x".repeat(199) + "🛰");
  });
});

function renderSearch({
  activeTenantId = tenantId,
  api,
  permissions,
  route,
}: {
  activeTenantId?: string | null;
  api: ReturnType<typeof createTicketingApi>;
  permissions: readonly TenantPermissionKeyView[];
  route: string;
}): ReturnType<typeof render> {
  const authority = authorityFixture(permissions);
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
            <MemoryRouter initialEntries={[route]}>
              <Routes>
                <Route
                  path="/search"
                  element={
                    <>
                      <GlobalSearchPage />
                      <LocationProbe />
                    </>
                  }
                />
              </Routes>
            </MemoryRouter>
          </TicketingApiProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function LocationProbe(): React.JSX.Element {
  const location = useLocation();
  return <output data-testid="search-location">{location.search}</output>;
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
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
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}
