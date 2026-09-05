import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "./app";
import { SessionContext } from "./auth/session-context";
import { useTenantAuthority } from "./auth/tenant-authority-context";
import type {
  AuthenticationMethod,
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "./lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "./test/phase-two-fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("phase-two authentication method contract", () => {
  it("accepts passkey and federated sessions", () => {
    const methods: AuthenticationMethod[] = ["passkey", "oidc", "saml"];
    expect(methods).toEqual(["passkey", "oidc", "saml"]);
  });
});

describe("tenant administration navigation", () => {
  it("shows the personal notification inbox for every active tenant session", async () => {
    renderShell(authorityFixture([]));

    expect(
      await screen.findByRole("link", { name: "Notification center" }),
    ).toHaveAttribute("href", "/notifications");
  });

  it("shows tenant-bound self-service security without deriving server authority from the link", async () => {
    renderShell(authorityFixture([]));

    expect(
      await screen.findByRole("link", { name: "Security" }),
    ).toHaveAttribute("href", "/account/security");
  });

  it("shows Users and Roles only from the live tenant authority projection", async () => {
    renderShell(
      authorityFixture([
        "user.read",
        "role.read",
        "group.read",
        "identity_provider.read",
        "operator_team.read",
        "service_account.read",
      ]),
    );

    expect(await screen.findByRole("link", { name: "Users" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Roles" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Groups" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Operator teams" })).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Identity providers" }),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Federated providers" }),
    ).toHaveAttribute("href", "/tenant/federated-identity-providers");
    expect(
      screen.getByRole("link", { name: "Service accounts" }),
    ).toBeVisible();
  });

  it("does not treat Session.permissions as tenant authority", async () => {
    renderShell(authorityFixture([]), [
      "group.read",
      "identity_provider.read",
      "operator_team.read",
      "role.read",
      "service_account.read",
      "user.read",
    ]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Users" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Roles" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Groups" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Operator teams" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Identity providers" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Federated providers" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Service accounts" }),
    ).not.toBeInTheDocument();
  });

  it("shows the global team catalog only from the platform session capability", async () => {
    renderShell(authorityFixture([]), ["platform.operator_team.read"]);

    expect(
      await screen.findByRole("link", { name: "Platform teams" }),
    ).toBeVisible();
  });

  it("shows global identity providers only from the platform session capability", async () => {
    renderShell(authorityFixture(["identity_provider.read"]), [
      "platform.identity_provider.read",
    ]);

    expect(
      await screen.findByRole("link", { name: "Platform IdPs" }),
    ).toHaveAttribute("href", "/platform/identity-providers");
  });

  it("does not promote tenant identity-provider authority into platform navigation", async () => {
    renderShell(authorityFixture(["identity_provider.read"]), []);

    expect(
      await screen.findByRole("link", { name: "Identity providers" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Platform IdPs" }),
    ).not.toBeInTheDocument();
  });

  it("separates tenant and platform MFA-policy read capabilities", async () => {
    renderShell(authorityFixture(["identity_policy.read"]), [
      "platform.identity_policy.read",
    ]);

    expect(
      await screen.findByRole("link", { name: "MFA policies" }),
    ).toHaveAttribute("href", "/tenant/mfa-policies");
    expect(
      screen.getByRole("link", { name: "Platform MFA policy" }),
    ).toHaveAttribute("href", "/platform/mfa-policies");
  });

  it("never promotes an MFA-policy claim across authority boundaries", async () => {
    renderShell(authorityFixture(["identity_policy.read"]), [
      "identity_policy.read",
    ]);

    expect(
      await screen.findByRole("link", { name: "MFA policies" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Platform MFA policy" }),
    ).not.toBeInTheDocument();
  });

  it("shows tenant notifications only from live tenant authority", async () => {
    renderShell(authorityFixture(["notification.manage"]), [
      "platform.notification.manage",
    ]);

    expect(
      await screen.findByRole("link", { name: "Notifications" }),
    ).toHaveAttribute("href", "/tenant/notifications");
    expect(screen.getByRole("link", { name: "Platform SMTP" })).toHaveAttribute(
      "href",
      "/platform/notifications/smtp",
    );
  });

  it("shows workflow administration only from live tenant authority", async () => {
    renderShell(authorityFixture(["workflow.read"]), ["workflow.manage"]);

    expect(
      await screen.findByRole("link", { name: "Workflows" }),
    ).toHaveAttribute("href", "/tenant/workflows");
  });

  it("never treats session workflow claims as tenant authority", async () => {
    renderShell(authorityFixture([]), ["workflow.read", "workflow.manage"]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Workflows" }),
    ).not.toBeInTheDocument();
  });

  it("shows custom-field administration only from live tenant read authority", async () => {
    renderShell(authorityFixture(["custom_field.read"]), [
      "custom_field.manage",
    ]);

    expect(
      await screen.findByRole("link", { name: "Custom fields" }),
    ).toHaveAttribute("href", "/tenant/custom-fields");
  });

  it("never treats session custom-field claims as tenant authority", async () => {
    renderShell(authorityFixture([]), [
      "custom_field.read",
      "custom_field.manage",
    ]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Custom fields" }),
    ).not.toBeInTheDocument();
  });

  it("shows bulk custom-field imports only with live read and ticket-update authority", async () => {
    renderShell(authorityFixture(["custom_field.read", "alert.update"]));

    expect(
      await screen.findByRole("link", { name: "Custom-field imports" }),
    ).toHaveAttribute("href", "/tenant/custom-field-imports");
  });

  it("does not expose bulk custom-field imports from custom-field read alone", async () => {
    renderShell(authorityFixture(["custom_field.read"]), ["alert.update"]);

    await screen.findByRole("link", { name: "Custom fields" });
    expect(
      screen.queryByRole("link", { name: "Custom-field imports" }),
    ).not.toBeInTheDocument();
  });

  it("does not expose a read-only workflow route from manage authority alone", async () => {
    renderShell(authorityFixture(["workflow.manage"]));

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Workflows" }),
    ).not.toBeInTheDocument();
  });

  it("never treats session notification.manage as tenant authority", async () => {
    renderShell(authorityFixture([]), ["notification.manage"]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Notifications" }),
    ).not.toBeInTheDocument();
  });

  it("shows platform SMTP only from the platform session capability", async () => {
    renderShell(authorityFixture(["notification.manage"]), []);

    expect(
      await screen.findByRole("link", { name: "Notifications" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Platform SMTP" }),
    ).not.toBeInTheDocument();
  });

  it("shows contacts and customer portal only from their live scoped capabilities", async () => {
    const authority = authorityFixture(["contact_group.read"]);
    authority.permissions.push({
      permissionKey: "portal.alert.read",
      scope: "own",
    });
    renderShell(authority);

    expect(
      await screen.findByRole("link", { name: "Customer contacts" }),
    ).toHaveAttribute("href", "/tenant/contacts");
    expect(
      screen.getByRole("link", { name: "Customer portal" }),
    ).toHaveAttribute("href", "/portal");
  });

  it("separates tenant and platform audit navigation authorities", async () => {
    renderShell(authorityFixture(["audit.read"]), ["platform.audit.read"]);

    expect(
      await screen.findByRole("link", { name: "Tenant audit" }),
    ).toHaveAttribute("href", "/tenant/audit");
    expect(
      screen.getByRole("link", { name: "Platform audit" }),
    ).toHaveAttribute("href", "/platform/audit");
  });

  it("never crosses audit authority between session and tenant projections", async () => {
    renderShell(authorityFixture([]), ["audit.read"]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Tenant audit" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Platform audit" }),
    ).not.toBeInTheDocument();
  });

  it("shows tenant identity and applies its safe shell branding only from live tenant authority", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            accentColor: "#dc6843",
            brandMark: "ORB",
            brandName: "Orbit Response",
            locale: "it-IT",
            primaryColor: "#103b53",
            tenantId: "0198c97d-cf4f-7000-8000-000000000010",
            timezone: "Europe/Rome",
            updatedAt: "2026-09-01T19:00:00Z",
            version: 7,
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v7"',
            },
          },
        ),
      ),
    );
    renderShell(authorityFixture(["settings.read"]));

    expect(
      await screen.findByRole("link", { name: "Tenant identity" }),
    ).toHaveAttribute("href", "/tenant/settings");
    expect(
      screen.getByRole("link", { name: "Ticket numbering" }),
    ).toHaveAttribute("href", "/tenant/settings/numbering");
    expect(
      await screen.findByRole("link", { name: "Orbit Response home" }),
    ).toBeVisible();
    expect(screen.getByText("ORB")).toBeVisible();
  });

  it("never treats a session settings claim as tenant authority", async () => {
    renderShell(authorityFixture([]), ["settings.read", "settings.manage"]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Tenant identity" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Ticket numbering" }),
    ).not.toBeInTheDocument();
  });

  it("never derives contact or portal navigation from session claims", async () => {
    renderShell(authorityFixture([]), ["contact.read", "portal.alert.read"]);

    await screen.findByText("No assigned tenant");
    expect(
      screen.queryByRole("link", { name: "Customer contacts" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Customer portal" }),
    ).not.toBeInTheDocument();
  });

  it("withdraws service-account navigation as soon as live authority reloads", async () => {
    const nextAuthority = createDeferred<TenantAuthorityView>();
    const initial = authorityFixture(["service_account.read"]);
    const api = createPhaseTwoApi({
      getTenantAuthority: vi
        .fn()
        .mockResolvedValueOnce(initial)
        .mockImplementationOnce(async () => nextAuthority.promise),
      listMemberships: async () => ({ items: [] }),
    });
    const session = {
      ...sessionFixture,
      absoluteExpiresAt: "2099-08-24T12:00:00Z",
      activeTenantId: initial.tenantId,
      idleExpiresAt: "2099-08-23T12:00:00Z",
      permissions: [],
    };
    render(
      <MemoryRouter>
        <SessionContext.Provider
          value={{
            api,
            clearSession: vi.fn(),
            membershipRevision: 0,
            refreshMemberships: vi.fn(),
            session,
            updateSession: vi.fn(),
          }}
        >
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<AuthorityReload />} />
            </Route>
          </Routes>
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("link", { name: "Service accounts" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));
    expect(
      screen.queryByRole("link", { name: "Service accounts" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      nextAuthority.resolve(authorityFixture([]));
      await nextAuthority.promise;
    });
    expect(
      screen.queryByRole("link", { name: "Service accounts" }),
    ).not.toBeInTheDocument();
  });
});

function AuthorityReload(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button type="button" onClick={authority.reload}>
      Reload authority
    </button>
  );
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

function renderShell(
  authority: TenantAuthorityView,
  sessionPermissions: readonly string[] = [],
): void {
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId: authority.tenantId,
    idleExpiresAt: "2099-08-23T12:00:00Z",
    permissions: sessionPermissions,
  };
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authority,
    listMemberships: async () => ({ items: [] }),
  });
  render(
    <MemoryRouter>
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<p>Tenant home</p>} />
          </Route>
        </Routes>
      </SessionContext.Provider>
    </MemoryRouter>,
  );
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-23T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissionKeys.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: "0198c97d-cf4f-7000-8000-000000000010",
    userId: sessionFixture.user.id,
  };
}
