import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "./app";
import { SessionContext, useSession } from "./auth/session-context";
import { TenantInstant } from "./lib/tenant-date-time-context";
import type { SessionView, TenantAuthorityView } from "./lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "./test/phase-two-fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const firstTenant = "0198c97d-cf4f-7000-8000-000000000010";
const secondTenant = "0198c97d-cf4f-7000-8000-000000000011";
const boundaryInstant = "2026-01-01T23:30:00Z";
const dateTimeApi = createPhaseTwoApi({
  getTenantAuthority: async (tenantId) => authorityFixture(tenantId),
  listMemberships: async () => ({ items: [] }),
});

describe("AppShell tenant date-time preferences", () => {
  it("rebinds operational instants when the active tenant changes", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const tenantId = url.includes(secondTenant) ? secondTenant : firstTenant;
      const second = tenantId === secondTenant;
      return new Response(
        JSON.stringify({
          accentColor: second ? "#dc6843" : "#387a94",
          brandMark: second ? "ROM" : "UTC",
          brandName: second ? "Rome Response" : "UTC Response",
          locale: second ? "it-IT" : "en-GB",
          primaryColor: second ? "#103b53" : "#102f3b",
          tenantId,
          timezone: second ? "Europe/Rome" : "UTC",
          updatedAt: "2026-01-01T12:00:00Z",
          version: 1,
        }),
        {
          headers: {
            "Cache-Control": "private, no-store",
            "Content-Type": "application/json",
            ETag: '"v1"',
          },
          status: 200,
        },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<DateTimeShellHarness />);

    expect(await screen.findByText(/01 Jan 2026/u)).toHaveTextContent("· UTC");
    fireEvent.click(screen.getByRole("button", { name: "Switch test tenant" }));
    expect(await screen.findByText(/02 gen 2026/u)).toHaveTextContent(
      "· Europe/Rome",
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(
      fetchMock.mock.calls.map(([input]) =>
        input instanceof Request ? new URL(input.url).pathname : String(input),
      ),
    ).toEqual([
      `/api/v1/tenants/${firstTenant}/settings`,
      `/api/v1/tenants/${secondTenant}/settings`,
    ]);
  });
});

function DateTimeShellHarness(): React.JSX.Element {
  const [session, setSession] = useState<SessionView>({
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId: firstTenant,
    idleExpiresAt: "2099-08-23T12:00:00Z",
    permissions: [],
  });
  return (
    <MemoryRouter>
      <SessionContext.Provider
        value={{
          api: dateTimeApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: (_expectedSessionId, next) => setSession(next),
        }}
      >
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<DateTimeSwitchProbe />} />
          </Route>
        </Routes>
      </SessionContext.Provider>
    </MemoryRouter>
  );
}

function DateTimeSwitchProbe(): React.JSX.Element {
  const { session, updateSession } = useSession();
  return (
    <div>
      <TenantInstant value={boundaryInstant} />
      <button
        type="button"
        onClick={() =>
          updateSession(session.id, {
            ...session,
            activeTenantId: secondTenant,
          })
        }
      >
        Switch test tenant
      </button>
    </div>
  );
}

function authorityFixture(tenantId: string): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-01-01T12:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [{ permissionKey: "settings.read", scope: "tenant" }],
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}
