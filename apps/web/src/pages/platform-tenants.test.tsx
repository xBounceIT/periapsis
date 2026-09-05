import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  PhaseTwoApiError,
  platformSettingsReadPermission,
  platformTenantCreatePermission,
  platformTenantAccessPermission,
  platformTenantManagePermission,
  type PlatformTenantAccessReceiptView,
  type PhaseTwoApi,
  type SessionView,
  type TenantLifecycleReceiptView,
  type TenantView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { PlatformTenantsPage } from "./platform-tenants";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("PlatformTenantsPage session generation", () => {
  it("initializes create fields from live global settings and falls back safely", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              defaultLocale: "it-IT",
              defaultTimezone: "Europe/Rome",
              platformName: "Periapsis SOC",
              supportUrl: null,
              updatedAt: "2026-09-01T10:00:00Z",
              version: 2,
            }),
            {
              headers: {
                "Cache-Control": "private, no-store",
                "Content-Type": "application/json",
                ETag: '"v2"',
              },
              status: 200,
            },
          ),
        )
        .mockRejectedValueOnce(new Error("settings unavailable")),
    );
    const api = createPhaseTwoApi({
      listTenants: vi.fn().mockResolvedValue({ items: [] }),
    });
    const firstSession: SessionView = {
      ...sessionFixture,
      permissions: [
        "platform.tenant.read",
        platformTenantCreatePermission,
        platformSettingsReadPermission,
      ],
    };
    const context = (session: SessionView) => ({
      api,
      clearSession: vi.fn(),
      membershipRevision: 0,
      refreshMemberships: vi.fn(),
      session,
      updateSession: vi.fn(),
    });
    const { rerender } = render(
      <SessionContext.Provider value={context(firstSession)}>
        <PlatformTenantsPage />
      </SessionContext.Provider>,
    );

    expect(await screen.findByLabelText("IANA time zone")).toHaveValue(
      "Europe/Rome",
    );
    expect(screen.getByLabelText("Locale")).toHaveValue("it-IT");

    const secondSession = {
      ...firstSession,
      id: "0198c97d-cf4f-7000-8000-000000000099",
    };
    rerender(
      <SessionContext.Provider value={context(secondSession)}>
        <PlatformTenantsPage />
      </SessionContext.Provider>,
    );
    expect(await screen.findByLabelText("IANA time zone")).toHaveValue("UTC");
    expect(screen.getByLabelText("Locale")).toHaveValue("en");
  });

  it("does not append a late page from the session that was rotated away", async () => {
    const cursor = "0198c97d-cf4f-7000-8000-000000000050";
    const originalTenant = tenant(
      "0198c97d-cf4f-7000-8000-000000000051",
      "Original tenant",
    );
    const staleTenant = tenant(
      "0198c97d-cf4f-7000-8000-000000000052",
      "Stale tenant",
    );
    const replacementTenant = tenant(
      "0198c97d-cf4f-7000-8000-000000000053",
      "Replacement tenant",
    );
    let resolveLater:
      ((page: { items: Array<typeof staleTenant> }) => void) | undefined;
    const laterPage = new Promise<{ items: Array<typeof staleTenant> }>(
      (resolve) => {
        resolveLater = resolve;
      },
    );
    let firstPageCalls = 0;
    const listTenants = vi.fn((after?: string) => {
      if (after) {
        return laterPage;
      }
      firstPageCalls += 1;
      return Promise.resolve(
        firstPageCalls === 1
          ? { items: [originalTenant], nextCursor: cursor }
          : { items: [replacementTenant], nextCursor: cursor },
      );
    });
    const api = createPhaseTwoApi({ listTenants });
    const clearSession = vi.fn();
    const replacement = {
      ...sessionFixture,
      id: "0198c97d-cf4f-7000-8000-000000000054",
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
        <PlatformTenantsPage />
      </SessionContext.Provider>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more tenants" }),
    );
    rerender(
      <SessionContext.Provider value={context(replacement)}>
        <PlatformTenantsPage />
      </SessionContext.Provider>,
    );
    expect(await screen.findByText("Replacement tenant")).toBeVisible();
    resolveLater?.({ items: [staleTenant] });
    await laterPage;

    expect(screen.queryByText("Stale tenant")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Load more tenants" }),
    ).toBeEnabled();
    expect(clearSession).not.toHaveBeenCalled();
  });
});

describe("PlatformTenantsPage lifecycle controls", () => {
  it("renders a read-only permission state without treating UI hiding as authorization", async () => {
    const suspendTenant = vi.fn();
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
        suspendTenant,
      }),
    });

    expect(
      await screen.findByText("Lifecycle controls are read-only"),
    ).toBeVisible();
    expect(screen.getByText(/platform\.tenant\.manage/)).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Suspend Acme SOC" }),
    ).not.toBeInTheDocument();
    expect(suspendTenant).not.toHaveBeenCalled();
  });

  it("requires an accessible exact-boundary confirmation and applies the receipt", async () => {
    const pending = createDeferred<{
      etag: string;
      value: TenantLifecycleReceiptView;
    }>();
    const suspendTenant = vi.fn().mockReturnValue(pending.promise);
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
        suspendTenant,
      }),
      session: managedSession,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Suspend Acme SOC" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Suspend Acme SOC",
    });
    expect(
      within(dialog).getByLabelText(
        "Lifecycle state changes from active to suspended",
      ),
    ).toBeVisible();
    const reason = within(dialog).getByRole("textbox", {
      name: "Administrative reason",
    });
    await waitFor(() => expect(reason).toHaveFocus());

    const submit = within(dialog).getByRole("button", {
      name: "Suspend tenant",
    });
    submit.focus();
    fireEvent.click(submit);
    expect(
      within(dialog).getByText("Enter an administrative reason."),
    ).toBeVisible();
    await waitFor(() => expect(reason).toHaveFocus());
    expect(suspendTenant).not.toHaveBeenCalled();

    fireEvent.change(reason, {
      target: { value: "Approved change SEC-2048" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Suspend tenant" }),
    );
    await waitFor(() => expect(suspendTenant).toHaveBeenCalledTimes(1));
    expect(suspendTenant).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      '"v4"',
      { expectedVersion: 4, reason: "Approved change SEC-2048" },
    );
    expect(
      within(dialog).getByRole("button", {
        name: "Changing lifecycle state…",
      }),
    ).toBeDisabled();
    expect(
      within(dialog).queryByRole("button", { name: "Close" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      pending.resolve({ etag: '"v5"', value: lifecycleReceipt() });
      await pending.promise;
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const row = screen.getByRole("row", { name: /Acme SOC/ });
    expect(within(row).getByText("Suspended")).toBeVisible();
    expect(within(row).getByText("Revision 5")).toBeVisible();
    expect(screen.getByText("Lifecycle state changed")).toBeVisible();
    expect(screen.getByText(/Acme SOC was suspended/)).toBeVisible();
  });

  it("offers only reactivation for a suspended tenant", async () => {
    const reactivateTenant = vi.fn().mockResolvedValue({
      etag: '"v8"',
      value: lifecycleReceipt({
        previousStatus: "suspended",
        status: "active",
        version: 8,
      }),
    });
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [
            tenant(tenantId, "Acme SOC", {
              status: "suspended",
              version: 7,
            }),
          ],
        }),
        reactivateTenant,
      }),
      session: managedSession,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Reactivate Acme SOC" }),
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Administrative reason" }),
      { target: { value: "Service restored after incident review" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Reactivate tenant" }));

    await waitFor(() => expect(reactivateTenant).toHaveBeenCalledTimes(1));
    expect(reactivateTenant).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      '"v7"',
      {
        expectedVersion: 7,
        reason: "Service restored after incident review",
      },
    );
    expect(
      await screen.findByRole("button", { name: "Suspend Acme SOC" }),
    ).toBeEnabled();
  });

  it("fails closed when the rolling tenant projection has no version", async () => {
    const suspendTenant = vi.fn();
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC")],
        }),
        suspendTenant,
      }),
      session: managedSession,
    });

    expect(
      await screen.findByRole("button", { name: "Suspend Acme SOC" }),
    ).toBeDisabled();
    expect(
      screen.getByText("Current revision is not available."),
    ).toBeVisible();
    expect(suspendTenant).not.toHaveBeenCalled();
  });

  it("keeps a stale confirmation open until the operator reloads inventory", async () => {
    const listTenants = vi
      .fn()
      .mockResolvedValueOnce({
        items: [tenant(tenantId, "Acme SOC", { version: 4 })],
      })
      .mockResolvedValueOnce({
        items: [
          tenant(tenantId, "Acme SOC", {
            status: "suspended",
            version: 5,
          }),
        ],
      });
    renderPage({
      api: createPhaseTwoApi({
        listTenants,
        suspendTenant: vi
          .fn()
          .mockRejectedValue(new PhaseTwoApiError("Precondition failed", 412)),
      }),
      session: managedSession,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Suspend Acme SOC" }),
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Administrative reason" }),
      { target: { value: "Approved" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Suspend tenant" }));

    expect(await screen.findByText("Tenant state changed")).toBeVisible();
    expect(screen.getByText(/older tenant state/)).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Suspend tenant" }),
    ).toBeDisabled();
    fireEvent.change(
      screen.getByRole("textbox", { name: "Administrative reason" }),
      { target: { value: "Edited but still stale" } },
    );
    expect(
      screen.getByRole("button", { name: "Suspend tenant" }),
    ).toBeDisabled();
    expect(screen.getByText("Tenant state changed")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Reload tenant inventory" }),
    );

    await waitFor(() => expect(listTenants).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByRole("button", { name: "Reactivate Acme SOC" }),
    ).toBeEnabled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps the exact confirmation available after a transient API error", async () => {
    const suspendTenant = vi
      .fn()
      .mockRejectedValueOnce(
        new PhaseTwoApiError(
          "Lifecycle service is temporarily unavailable",
          503,
        ),
      )
      .mockResolvedValueOnce({ etag: '"v5"', value: lifecycleReceipt() });
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
        suspendTenant,
      }),
      session: managedSession,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Suspend Acme SOC" }),
    );
    const reason = screen.getByRole("textbox", {
      name: "Administrative reason",
    });
    fireEvent.change(reason, { target: { value: "Approved" } });
    fireEvent.click(screen.getByRole("button", { name: "Suspend tenant" }));

    expect(await screen.findByText("Lifecycle change failed")).toBeVisible();
    expect(
      screen.getByText("Lifecycle service is temporarily unavailable"),
    ).toBeVisible();
    expect(reason).toHaveValue("Approved");
    expect(
      screen.getByRole("button", { name: "Suspend tenant" }),
    ).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Suspend tenant" }));
    await waitFor(() => expect(suspendTenant).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByRole("button", { name: "Reactivate Acme SOC" }),
    ).toBeEnabled();
  });
});

describe("PlatformTenantsPage explicit elevated access", () => {
  it("hides the command without its dedicated permission", async () => {
    const authorizePlatformTenantAccess = vi.fn();
    renderPage({
      api: createPhaseTwoApi({
        authorizePlatformTenantAccess,
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
      }),
    });

    expect(
      await screen.findByText("Elevated tenant access is unavailable"),
    ).toBeVisible();
    expect(screen.getByText(/platform\.tenant\.access/)).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: "Authorize explicit access to Acme SOC",
      }),
    ).not.toBeInTheDocument();
    expect(authorizePlatformTenantAccess).not.toHaveBeenCalled();
  });

  it("requires confirmation, preserves one retry key, refreshes memberships, and never switches context", async () => {
    const receipt: PlatformTenantAccessReceiptView = {
      authorizationRevision: "27",
      authorizedAt: "2026-09-01T20:30:00.123456Z",
      membershipId: "0198c97d-cf4f-7000-8000-000000000072",
      membershipRevision: 1,
      replayed: false,
      tenantId,
      tenantVersion: 4,
      userId: sessionFixture.user.id,
    };
    const authorizePlatformTenantAccess = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("Temporary outage", 503))
      .mockResolvedValueOnce(receipt);
    const refreshMemberships = vi.fn();
    renderPage({
      api: createPhaseTwoApi({
        authorizePlatformTenantAccess,
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
        switchTenant: vi.fn(),
      }),
      refreshMemberships,
      session: accessSession,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Authorize explicit access to Acme SOC",
      }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Authorize access to Acme SOC",
    });
    expect(
      within(dialog).getByText(/does not bypass row-level security/),
    ).toBeVisible();
    expect(
      within(dialog).getByText(/does not switch automatically/),
    ).toBeVisible();
    const reason = within(dialog).getByRole("textbox", {
      name: "Access justification",
    });
    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Create tenant-admin membership",
      }),
    );
    expect(
      within(dialog).getByText("Enter an administrative reason."),
    ).toBeVisible();
    expect(authorizePlatformTenantAccess).not.toHaveBeenCalled();

    fireEvent.change(reason, {
      target: { value: "Approved investigation SEC-2048" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Create tenant-admin membership",
      }),
    );
    expect(
      await within(dialog).findByText("Tenant access failed"),
    ).toBeVisible();
    expect(reason).toHaveValue("Approved investigation SEC-2048");
    const firstKey = authorizePlatformTenantAccess.mock.calls[0]?.[3];
    expect(firstKey).toMatch(/^tenant-access-[0-9a-f-]{36}$/);

    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Create tenant-admin membership",
      }),
    );
    await waitFor(() =>
      expect(authorizePlatformTenantAccess).toHaveBeenCalledTimes(2),
    );
    expect(authorizePlatformTenantAccess.mock.calls[1]?.[3]).toBe(firstKey);
    expect(authorizePlatformTenantAccess).toHaveBeenLastCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      '"v4"',
      firstKey,
      { expectedVersion: 4, reason: "Approved investigation SEC-2048" },
    );
    await waitFor(() => expect(refreshMemberships).toHaveBeenCalledTimes(1));
    expect(screen.getByText("Tenant access authorized")).toBeVisible();
    expect(screen.getByText(/Select it in the tenant switcher/)).toBeVisible();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows and protects the already active tenant context", async () => {
    renderPage({
      api: createPhaseTwoApi({
        listTenants: vi.fn().mockResolvedValue({
          items: [tenant(tenantId, "Acme SOC", { version: 4 })],
        }),
      }),
      session: { ...accessSession, activeTenantId: tenantId },
    });

    expect(await screen.findByText("Active context")).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Authorize explicit access to Acme SOC",
      }),
    ).toBeDisabled();
    expect(
      screen.getByText("The active tenant is already visible."),
    ).toBeVisible();
  });
});

const tenantId = "0198c97d-cf4f-7000-8000-000000000071";
const managedSession: SessionView = {
  ...sessionFixture,
  permissions: [...sessionFixture.permissions, platformTenantManagePermission],
};
const accessSession: SessionView = {
  ...sessionFixture,
  permissions: [...sessionFixture.permissions, platformTenantAccessPermission],
};

function tenant(
  id: string,
  name: string,
  override: Partial<TenantView> = {},
): TenantView {
  return {
    createdAt: "2026-08-23T10:00:00Z",
    id,
    locale: "en",
    name,
    slug: name.toLowerCase().replaceAll(" ", "-"),
    status: "active",
    timezone: "UTC",
    updatedAt: "2026-08-24T10:00:00Z",
    ...override,
  };
}

function lifecycleReceipt(
  override: Partial<TenantLifecycleReceiptView> = {},
): TenantLifecycleReceiptView {
  return {
    previousStatus: "active",
    replayed: false,
    status: "suspended",
    tenantId,
    updatedAt: "2026-08-26T14:15:16.789123Z",
    version: 5,
    ...override,
  };
}

function renderPage({
  api,
  refreshMemberships = vi.fn(),
  session = sessionFixture,
}: {
  api: PhaseTwoApi;
  refreshMemberships?: () => void;
  session?: SessionView;
}): void {
  render(
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships,
        session,
        updateSession: vi.fn(),
      }}
    >
      <PlatformTenantsPage />
    </SessionContext.Provider>,
  );
}

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve: ((value: T) => void) | undefined;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return {
    promise,
    resolve(value) {
      if (!resolve) throw new Error("Deferred promise was not initialized");
      resolve(value);
    },
  };
}
