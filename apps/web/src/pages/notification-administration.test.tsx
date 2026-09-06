import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  SessionView,
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import type { NotificationAdminApi } from "../notifications";
import {
  createNotificationApiMock,
  fixtureTenantId,
} from "../notifications/notification-test-fixtures";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  PlatformNotificationSmtpPage,
  TenantNotificationAdministrationPage,
} from "./notification-administration";
import { notificationAdministrationRoutes } from "./notification-administration-routes";

afterEach(cleanup);

describe("notification administration route boundaries", () => {
  it("mounts the canonical child paths from the exported descriptors", () => {
    expect(notificationAdministrationRoutes.map((route) => route.path)).toEqual(
      ["tenant/notifications", "platform/notifications/smtp"],
    );
  });

  it("keeps a tenant deep link closed until live authority is ready", async () => {
    const authority = createDeferred<TenantAuthorityView>();
    const listRules = vi.fn<NotificationAdminApi["listRules"]>(async () => ({
      items: [],
    }));
    renderTenantPage(
      createNotificationApiMock({ listRules }),
      async () => authority.promise,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Checking notification authority…",
      }),
    ).toBeVisible();
    expect(listRules).not.toHaveBeenCalled();

    await act(async () => {
      authority.resolve(authorityFixture(["notification.manage"]));
      await authority.promise;
    });
    expect(await screen.findByText("No routing rules")).toBeVisible();
    expect(listRules).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: fixtureTenantId }),
    );
  });

  it("denies a tenant deep link when only Session.permissions claims notification.manage", async () => {
    const listRules = vi.fn<NotificationAdminApi["listRules"]>();
    renderTenantPage(
      createNotificationApiMock({ listRules }),
      async () => authorityFixture([]),
      ["notification.manage"],
    );

    expect(
      await screen.findByRole("heading", {
        name: "Notification administration is unavailable.",
      }),
    ).toBeVisible();
    expect(screen.getByText(/live tenant authority/u)).toBeVisible();
    expect(listRules).not.toHaveBeenCalled();
  });

  it("denies a platform SMTP deep link without the explicit platform capability", () => {
    const getPlatformSmtp = vi.fn<NotificationAdminApi["getPlatformSmtp"]>();
    const api = createPhaseTwoApi();
    render(
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: futureSession({ ...sessionFixture, permissions: [] }),
          updateSession: vi.fn(),
        }}
      >
        <PlatformNotificationSmtpPage
          api={createNotificationApiMock({ getPlatformSmtp })}
        />
      </SessionContext.Provider>,
    );

    expect(
      screen.getByRole("heading", {
        name: "Notification administration is unavailable.",
      }),
    ).toBeVisible();
    expect(screen.getByText(/platform\.notification\.manage/u)).toBeVisible();
    expect(getPlatformSmtp).not.toHaveBeenCalled();
  });
});

function renderTenantPage(
  notificationApi: NotificationAdminApi,
  getTenantAuthority: () => Promise<TenantAuthorityView>,
  permissions: readonly string[] = [],
): void {
  const api = createPhaseTwoApi({ getTenantAuthority });
  render(
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: futureSession({
          ...sessionFixture,
          activeTenantId: fixtureTenantId,
          permissions,
        }),
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantNotificationAdministrationPage api={notificationApi} />
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-25T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "01991c20-7d5f-7000-8000-000000000070",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissionKeys.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: fixtureTenantId,
    userId: sessionFixture.user.id,
  };
}

function futureSession(session: SessionView): SessionView {
  return {
    ...session,
    absoluteExpiresAt: "2099-08-25T12:00:00Z",
    idleExpiresAt: "2099-08-25T11:00:00Z",
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
