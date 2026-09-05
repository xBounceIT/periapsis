import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { PhaseTwoApiError } from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TenantSwitcher } from "./tenant-switcher";

afterEach(cleanup);

describe("TenantSwitcher", () => {
  it("offers only server-returned memberships and sends the in-memory CSRF value", async () => {
    const switchTenant = vi.fn(
      async (_csrfToken: string, tenantId: string) => ({
        ...sessionFixture,
        activeTenantId: tenantId,
      }),
    );
    const api = createPhaseTwoApi({
      listMemberships: async () => ({
        items: [
          {
            membershipId: "0198c97d-cf4f-7000-8000-000000000020",
            role: "analyst",
            tenantId: "0198c97d-cf4f-7000-8000-000000000010",
            tenantName: "Acme SOC",
            tenantSlug: "acme-soc",
          },
          {
            membershipId: "0198c97d-cf4f-7000-8000-000000000021",
            role: "tenant_admin",
            tenantId: "0198c97d-cf4f-7000-8000-000000000011",
            tenantName: "Globex Response",
            tenantSlug: "globex-response",
          },
        ],
      }),
      switchTenant,
    });
    const updateSession = vi.fn();

    render(
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: sessionFixture,
          updateSession,
        }}
      >
        <TenantSwitcher />
      </SessionContext.Provider>,
    );

    const select = await screen.findByLabelText("Tenant context");
    expect(screen.getAllByRole("option")).toHaveLength(3);
    expect(
      screen.queryByRole("option", { name: "Unassigned Tenant" }),
    ).toBeNull();

    fireEvent.change(select, {
      target: { value: "0198c97d-cf4f-7000-8000-000000000011" },
    });
    await waitFor(() =>
      expect(switchTenant).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        "0198c97d-cf4f-7000-8000-000000000011",
      ),
    );
    expect(updateSession).toHaveBeenCalled();
  });

  it("loads later membership pages, de-duplicates overlap, and preserves an unloaded active context", async () => {
    const cursor = "0198c97d-cf4f-7000-8000-000000000030";
    const first = {
      membershipId: "0198c97d-cf4f-7000-8000-000000000031",
      role: "analyst",
      tenantId: "0198c97d-cf4f-7000-8000-000000000032",
      tenantName: "First tenant",
      tenantSlug: "first-tenant",
    } as const;
    const later = {
      membershipId: "0198c97d-cf4f-7000-8000-000000000033",
      role: "tenant_admin",
      tenantId: "0198c97d-cf4f-7000-8000-000000000034",
      tenantName: "Later tenant",
      tenantSlug: "later-tenant",
    } as const;
    const listMemberships = vi.fn(async (after?: string) =>
      after
        ? { items: [first, later] }
        : { items: [first], nextCursor: cursor },
    );
    const api = createPhaseTwoApi({ listMemberships });

    render(
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: { ...sessionFixture, activeTenantId: later.tenantId },
          updateSession: vi.fn(),
        }}
      >
        <TenantSwitcher />
      </SessionContext.Provider>,
    );

    expect(
      await screen.findByText(
        "Active tenant selected; load more to view details",
      ),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load more tenants" }));

    expect(
      await screen.findByRole("option", { name: "Later tenant" }),
    ).toBeVisible();
    expect(
      screen.getAllByRole("option", { name: "First tenant" }),
    ).toHaveLength(1);
    expect(listMemberships).toHaveBeenLastCalledWith(cursor);
  });

  it("ignores a late page 401 from the session that was rotated away", async () => {
    const cursor = "0198c97d-cf4f-7000-8000-000000000040";
    const membership = {
      membershipId: "0198c97d-cf4f-7000-8000-000000000041",
      role: "analyst",
      tenantId: "0198c97d-cf4f-7000-8000-000000000042",
      tenantName: "Generation tenant",
      tenantSlug: "generation-tenant",
    } as const;
    let rejectLater: ((reason: unknown) => void) | undefined;
    const laterPage = new Promise<never>((_resolve, reject) => {
      rejectLater = reject;
    });
    const listMemberships = vi.fn((after?: string) =>
      after
        ? laterPage
        : Promise.resolve({ items: [membership], nextCursor: cursor }),
    );
    const api = createPhaseTwoApi({ listMemberships });
    const clearSession = vi.fn();
    const replacement = {
      ...sessionFixture,
      id: "0198c97d-cf4f-7000-8000-000000000043",
    };
    const context = (session: typeof sessionFixture) => ({
      api,
      clearSession,
      membershipRevision: 0,
      refreshMemberships: vi.fn(),
      session,
      updateSession: vi.fn(),
    });
    const { rerender } = render(
      <SessionContext.Provider value={context(sessionFixture)}>
        <TenantSwitcher />
      </SessionContext.Provider>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more tenants" }),
    );
    rerender(
      <SessionContext.Provider value={context(replacement)}>
        <TenantSwitcher />
      </SessionContext.Provider>,
    );
    await waitFor(() => expect(listMemberships).toHaveBeenCalledTimes(3));
    rejectLater?.(new PhaseTwoApiError("old session", 401));

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Load more tenants" }),
      ).toBeEnabled(),
    );
    expect(clearSession).not.toHaveBeenCalled();
  });
});
