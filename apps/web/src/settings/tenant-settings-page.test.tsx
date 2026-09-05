import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TenantSettings } from "@periapsis/contracts";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import {
  PhaseTwoApiError,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import type { TenantSettingsApi } from "./model";
import { TenantSettingsPage } from "./tenant-settings-page";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(cleanup);

describe("TenantSettingsPage", () => {
  it("shows the live projection without mutation controls to a reader", async () => {
    const api = settingsApiFixture();
    renderPage(api, ["settings.read"]);

    expect(await screen.findByDisplayValue("Periapsis Labs")).toBeVisible();
    expect(screen.getByLabelText("Brand name")).toHaveAttribute("readonly");
    expect(screen.getByText("Read-only access")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Save identity" }),
    ).not.toBeInTheDocument();
  });

  it("submits one normalized, version-bound update with an audit reason", async () => {
    const update = vi.fn<TenantSettingsApi["update"]>(async () => ({
      etag: '"v8"',
      value: settingsFixture({
        accentColor: "#dc6843",
        brandMark: "ORB",
        brandName: "Orbit Response",
        primaryColor: "#103b53",
        version: 8,
      }),
    }));
    renderPage(settingsApiFixture({ update }), [
      "settings.read",
      "settings.manage",
    ]);

    const save = await screen.findByRole("button", { name: "Save identity" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Brand name"), {
      target: { value: " Orbit Response " },
    });
    fireEvent.change(screen.getByLabelText("Text mark"), {
      target: { value: "orb" },
    });
    fireEvent.change(screen.getByLabelText("Primary color"), {
      target: { value: "#103B53" },
    });
    fireEvent.change(screen.getByLabelText("Accent color"), {
      target: { value: "#DC6843" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Approved identity refresh SEC-2048" },
    });
    expect(save).toBeEnabled();
    fireEvent.click(save);

    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      { etag: '"v7"', value: settingsFixture() },
      "Approved identity refresh SEC-2048",
      {
        accentColor: "#dc6843",
        brandMark: "ORB",
        brandName: "Orbit Response",
        locale: "it-IT",
        primaryColor: "#103b53",
        timezone: "Europe/Rome",
      },
    );
    expect(await screen.findByText("Identity synchronized")).toBeVisible();
  });

  it("reloads the winning version after a failed strong precondition", async () => {
    const get = vi
      .fn<TenantSettingsApi["get"]>()
      .mockResolvedValueOnce({ etag: '"v7"', value: settingsFixture() })
      .mockResolvedValueOnce({
        etag: '"v8"',
        value: settingsFixture({
          brandName: "Concurrent Identity",
          version: 8,
        }),
      });
    const update = vi.fn<TenantSettingsApi["update"]>(async () => {
      throw new PhaseTwoApiError("Settings changed", 412, {
        code: "version_conflict",
      });
    });
    renderPage(settingsApiFixture({ get, update }), [
      "settings.read",
      "settings.manage",
    ]);

    await screen.findByDisplayValue("Periapsis Labs");
    fireEvent.change(screen.getByLabelText("Brand name"), {
      target: { value: "Candidate Identity" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Approved identity refresh SEC-2048" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save identity" }));

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByDisplayValue("Concurrent Identity"),
    ).toBeVisible();
    expect(
      screen.getByText(/Someone changed these settings first/u),
    ).toBeVisible();
  });

  it("denies the direct route before requesting settings without read authority", async () => {
    const get = vi.fn<TenantSettingsApi["get"]>(async () => ({
      etag: '"v7"',
      value: settingsFixture(),
    }));
    renderPage(settingsApiFixture({ get }), []);

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(get).not.toHaveBeenCalled();
  });
});

function renderPage(
  settingsApi: TenantSettingsApi,
  permissions: readonly TenantPermissionKeyView[],
): void {
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(permissions),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: {
            ...sessionFixture,
            absoluteExpiresAt: "2099-09-02T12:00:00Z",
            activeTenantId: tenantId,
            idleExpiresAt: "2099-09-01T12:00:00Z",
          },
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <TenantSettingsPage api={settingsApi} />
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function settingsApiFixture(
  overrides: Partial<TenantSettingsApi> = {},
): TenantSettingsApi {
  return {
    get: async () => ({ etag: '"v7"', value: settingsFixture() }),
    update: async () => ({
      etag: '"v8"',
      value: settingsFixture({ version: 8 }),
    }),
    ...overrides,
  };
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-09-01T19:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissions.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}

function settingsFixture(
  override: Partial<TenantSettings> = {},
): TenantSettings {
  return {
    accentColor: "#4ea5b5",
    brandMark: "PERI",
    brandName: "Periapsis Labs",
    locale: "it-IT",
    primaryColor: "#172230",
    tenantId,
    timezone: "Europe/Rome",
    updatedAt: "2026-09-01T18:30:00.123456Z",
    version: 7,
    ...override,
  };
}
