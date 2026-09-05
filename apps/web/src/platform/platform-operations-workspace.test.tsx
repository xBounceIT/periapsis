import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  platformSettingsChangedEvent,
  type PlatformOperationsApi,
  type PlatformOperationsAuthority,
} from "./platform-operations-model";
import { PlatformOperationsWorkspace } from "./platform-operations-workspace";

afterEach(cleanup);

describe("PlatformOperationsWorkspace", () => {
  it("keeps the flag manager reachable while the failed-notification API is gated off", async () => {
    const fixture = createApi(false);
    renderWorkspace(fixture.api);

    expect(
      await screen.findByText("Failed notification view is disabled"),
    ).toBeVisible();
    expect(fixture.listFailedNotifications).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("tab", { name: "Feature flags" }));
    expect(
      await screen.findByText("platform_failed_notifications_view"),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Enable view" })).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Users" }));
    expect(await screen.findByText("recovery_code 1")).toBeVisible();
  });

  it("fails closed without misreporting an unavailable flag as disabled", async () => {
    const fixture = createApi(false, true);
    renderWorkspace(fixture.api);

    expect(
      await screen.findByText("Feature flags could not be loaded."),
    ).toBeVisible();
    expect(
      screen.queryByText("Failed notification view is disabled"),
    ).not.toBeInTheDocument();
    expect(fixture.listFailedNotifications).not.toHaveBeenCalled();
  });

  it("shows only a safe support link and binds an explicit reason to a versioned flag change", async () => {
    const fixture = createApi(true);
    renderWorkspace(fixture.api);

    await waitFor(() =>
      expect(fixture.listFailedNotifications).toHaveBeenCalledTimes(1),
    );
    expect(
      await screen.findByText("No dead-lettered notifications."),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    const support = await screen.findByRole("link", { name: "Open support" });
    expect(support).toHaveAttribute(
      "href",
      "https://support.example.test/help",
    );
    expect(support).toHaveAttribute("rel", "noopener noreferrer");

    fireEvent.click(screen.getByRole("tab", { name: "Feature flags" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Disable view" }),
    );
    fireEvent.change(screen.getByLabelText("Operational reason"), {
      target: { value: "Pause during provider maintenance" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm versioned change" }),
    );

    await waitFor(() =>
      expect(fixture.updateFeatureFlag).toHaveBeenCalledWith({
        body: { enabled: false, expectedVersion: 3 },
        csrfToken: "csrf-memory-only",
        flagKey: "platform_failed_notifications_view",
        reason: "Pause during provider maintenance",
      }),
    );
  });

  it("publishes a shell refresh only after a confirmed settings update", async () => {
    const fixture = createApi(true);
    const refreshes: Event[] = [];
    const recordRefresh = (event: Event): void => {
      refreshes.push(event);
    };
    window.addEventListener(platformSettingsChangedEvent, recordRefresh);
    try {
      renderWorkspace(fixture.api);
      fireEvent.click(await screen.findByRole("tab", { name: "Settings" }));
      fireEvent.change(await screen.findByLabelText("Platform name"), {
        target: { value: "Periapsis Global SOC" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Review settings change" }),
      );
      fireEvent.change(screen.getByLabelText("Operational reason"), {
        target: { value: "Publish the approved global identity" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Confirm versioned change" }),
      );

      await waitFor(() =>
        expect(fixture.updateSettings).toHaveBeenCalledWith({
          body: {
            defaultLocale: "it-IT",
            defaultTimezone: "Europe/Rome",
            expectedVersion: 2,
            platformName: "Periapsis Global SOC",
            supportUrl: "https://support.example.test/help",
          },
          csrfToken: "csrf-memory-only",
          reason: "Publish the approved global identity",
        }),
      );
      await waitFor(() => expect(refreshes).toHaveLength(1));
      expect(refreshes[0]).toBeInstanceOf(CustomEvent);
    } finally {
      window.removeEventListener(platformSettingsChangedEvent, recordRefresh);
    }
  });
});

const allAuthority: PlatformOperationsAuthority = {
  canManageFeatureFlags: true,
  canManageSettings: true,
  canReadFeatureFlags: true,
  canReadOperations: true,
  canReadSettings: true,
  canReadUsers: true,
};

function renderWorkspace(api: PlatformOperationsApi): void {
  render(
    <PlatformOperationsWorkspace
      api={api}
      authority={allAuthority}
      csrfToken="csrf-memory-only"
      sessionKey="019d4d16-2160-7000-8000-000000000001"
    />,
  );
}

function createApi(
  flagEnabled: boolean,
  rejectFlags = false,
): {
  api: PlatformOperationsApi;
  listFailedNotifications: ReturnType<
    typeof vi.fn<PlatformOperationsApi["listFailedNotifications"]>
  >;
  updateFeatureFlag: ReturnType<
    typeof vi.fn<PlatformOperationsApi["updateFeatureFlag"]>
  >;
  updateSettings: ReturnType<
    typeof vi.fn<PlatformOperationsApi["updateSettings"]>
  >;
} {
  const listFailedNotifications = vi.fn<
    PlatformOperationsApi["listFailedNotifications"]
  >(async () => ({
    items: [],
    projectionVersion: 1,
  }));
  const updateFeatureFlag = vi.fn<PlatformOperationsApi["updateFeatureFlag"]>(
    async (input) => ({
      enabled: input.body.enabled,
      key: input.flagKey,
      updatedAt: "2026-09-01T10:01:00Z",
      version: input.body.expectedVersion + 1,
    }),
  );
  const updateSettings = vi.fn<PlatformOperationsApi["updateSettings"]>(
    async (input) => ({
      ...input.body,
      supportUrl: input.body.supportUrl,
      updatedAt: "2026-09-01T10:01:00Z",
      version: input.body.expectedVersion + 1,
    }),
  );
  return {
    api: {
      getHealth: vi.fn<PlatformOperationsApi["getHealth"]>(async () => ({
        checkedAt: "2026-09-01T10:00:00Z",
        checks: [
          { key: "database", status: "healthy" },
          { key: "platform_audit_chain", status: "healthy" },
          {
            key: "queue_backlog",
            oldestPendingSeconds: 0,
            pendingCount: 0,
            status: "healthy",
          },
          { failedCount: 0, key: "queue_failures", status: "healthy" },
        ],
        projectionVersion: 1,
        status: "healthy",
      })),
      getSettings: vi.fn<PlatformOperationsApi["getSettings"]>(async () => ({
        defaultLocale: "it-IT",
        defaultTimezone: "Europe/Rome",
        platformName: "Periapsis SOC",
        supportUrl: "https://support.example.test/help",
        updatedAt: "2026-09-01T10:00:00Z",
        version: 2,
      })),
      listFailedNotifications,
      listFeatureFlags: vi.fn<PlatformOperationsApi["listFeatureFlags"]>(
        async () => {
          if (rejectFlags) throw new Error("catalog unavailable");
          return [
            {
              enabled: flagEnabled,
              key: "platform_failed_notifications_view",
              updatedAt: "2026-09-01T10:00:00Z",
              version: 3,
            },
          ];
        },
      ),
      listQueues: vi.fn<PlatformOperationsApi["listQueues"]>(async () => ({
        checkedAt: "2026-09-01T10:00:00Z",
        projectionVersion: 1,
        sources: [],
      })),
      listUsers: vi.fn<PlatformOperationsApi["listUsers"]>(async () => ({
        items: [
          {
            active: true,
            activeTenantMembershipCount: 1,
            displayName: "Recovery-capable operator",
            id: "019d4d16-2160-7000-8000-000000000061",
            liveSessionsByAuthenticationMethod: [
              { liveSessionCount: 1, method: "recovery_code" },
            ],
            platformRoles: ["platform_super_admin"],
            totalTenantMembershipCount: 1,
          },
        ],
        projectionVersion: 1,
      })),
      updateFeatureFlag,
      updateSettings,
    },
    listFailedNotifications,
    updateFeatureFlag,
    updateSettings,
  };
}
