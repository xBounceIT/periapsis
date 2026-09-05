import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "../auth/tenant-authority-context";
import {
  PhaseTwoApiError,
  tenantProjectionMismatchCode,
  type PhaseTwoApi,
  type ServiceAccountCredentialView,
  type ServiceAccountRoleGrantView,
  type ServiceAccountView,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
  type TenantRoleSummaryView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  mergeServiceAccounts,
  TenantServiceAccountsPage,
} from "./tenant-service-accounts";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const otherTenantId = "0198c97d-cf4f-7000-8000-000000000011";
const accountId = "0198c97d-cf4f-7000-8000-000000000210";
const credentialId = "0198c97d-cf4f-7000-8000-000000000211";
const roleId = "0198c97d-cf4f-7000-8000-000000000212";
const grantId = "0198c97d-cf4f-7000-8000-000000000213";
const edgeEtag = '"v3-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';
const allPermissions: readonly TenantPermissionKeyView[] = [
  "role.grant",
  "service_account.credential.manage",
  "service_account.manage",
  "service_account.read",
];

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("TenantServiceAccountsPage", () => {
  it("keeps inventory readable while hiding every mutation behind its exact live capability", async () => {
    renderAccounts({}, ["service_account.read"]);

    const open = await screen.findByRole("button", {
      name: "Open Alert collector (alert_collector)",
    });
    expect(
      screen.queryByRole("button", { name: "Create service account" }),
    ).not.toBeInTheDocument();
    fireEvent.click(open);
    expect(await screen.findByRole("dialog")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Save account" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Machine roles" }));
    expect(
      screen.queryByRole("button", { name: "Grant machine role" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "API credentials" }));
    expect(
      screen.queryByRole("button", { name: "Issue credential" }),
    ).not.toBeInTheDocument();
  });

  it("clears the current session when the service-account inventory read returns 401", async () => {
    const clearSession = renderWithAuthority(
      baseApi({
        listTenantServiceAccounts: async () => {
          throw new PhaseTwoApiError("expired session", 401);
        },
      }),
      tenantId,
    );

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
    expect(
      screen.queryByRole("button", { name: "Create service account" }),
    ).not.toBeInTheDocument();
  });

  it("retracts all stale capability controls and refreshes authority after a credential read 403", async () => {
    const getTenantAuthority = vi
      .fn<PhaseTwoApi["getTenantAuthority"]>()
      .mockResolvedValueOnce(authorityFixture(allPermissions))
      .mockResolvedValueOnce(authorityFixture([]));
    const clearSession = renderWithAuthority(
      baseApi({
        getTenantAuthority,
        getTenantServiceAccountCredential: async () => {
          throw new PhaseTwoApiError("permission withdrawn", 403);
        },
        listTenantServiceAccountCredentials: async () => ({
          items: [credentialFixture()],
        }),
      }),
      tenantId,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);
    expect(clearSession).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Create service account" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Issue credential" }),
    ).not.toBeInTheDocument();
  });

  it("revalidates authority and retracts the create dialog after a mutation 403", async () => {
    const getTenantAuthority = vi
      .fn<PhaseTwoApi["getTenantAuthority"]>()
      .mockResolvedValueOnce(authorityFixture(allPermissions))
      .mockResolvedValueOnce(authorityFixture(["service_account.read"]));
    const createTenantServiceAccount = vi.fn(async () => {
      throw new PhaseTwoApiError("permission withdrawn", 403);
    });
    const clearSession = renderWithAuthority(
      baseApi({ createTenantServiceAccount, getTenantAuthority }),
      tenantId,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create service account" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Create service account",
    });
    fireEvent.change(
      within(dialog).getByRole("textbox", { name: "Service account key" }),
      { target: { value: "new_collector" } },
    );
    fireEvent.change(
      within(dialog).getByRole("textbox", { name: "Display name" }),
      { target: { value: "New collector" } },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Create service account" }),
    );

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(createTenantServiceAccount).toHaveBeenCalledTimes(1);
    expect(clearSession).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Create service account" }),
    ).not.toBeInTheDocument();
  });

  it("revalidates authority after a credential mutation projection mismatch", async () => {
    const getTenantAuthority = vi
      .fn<PhaseTwoApi["getTenantAuthority"]>()
      .mockResolvedValueOnce(authorityFixture(allPermissions))
      .mockResolvedValueOnce(
        authorityFixture(["service_account.manage", "service_account.read"]),
      );
    const issueTenantServiceAccountCredential = vi.fn(async () => {
      throw new PhaseTwoApiError("tenant projection mismatch", undefined, {
        code: tenantProjectionMismatchCode,
      });
    });
    const clearSession = renderWithAuthority(
      baseApi({
        getTenantAuthority,
        issueTenantServiceAccountCredential,
      }),
      tenantId,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const dialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(dialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Issue credential" }),
    );

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(issueTenantServiceAccountCredential).toHaveBeenCalledTimes(1);
    expect(clearSession).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps tenant projection mismatches fail-closed after authority revalidation", async () => {
    const revalidatedAuthority = createDeferred<TenantAuthorityView>();
    const getTenantAuthority = vi
      .fn<PhaseTwoApi["getTenantAuthority"]>()
      .mockResolvedValueOnce(authorityFixture(allPermissions))
      .mockImplementationOnce(async () => revalidatedAuthority.promise);
    const listTenantServiceAccounts = vi.fn(async () => {
      throw new PhaseTwoApiError("tenant projection mismatch", undefined, {
        code: tenantProjectionMismatchCode,
      });
    });
    const clearSession = renderWithAuthority(
      baseApi({
        getTenantAuthority,
        listTenantServiceAccounts,
      }),
      tenantId,
    );

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await act(async () => {
      revalidatedAuthority.resolve(authorityFixture(allPermissions));
      await revalidatedAuthority.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);
    expect(listTenantServiceAccounts).toHaveBeenCalledTimes(1);
    expect(clearSession).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Create service account" }),
    ).not.toBeInTheDocument();
  });

  it("retracts the detail immediately on live read-permission loss and ignores its late response", async () => {
    const deniedAuthority = createDeferred<TenantAuthorityView>();
    const delayedAccount = createDeferred<{
      etag: string;
      value: ServiceAccountView;
    }>();
    let detailSignal: AbortSignal | undefined;
    const api = baseApi({
      getTenantAuthority: vi
        .fn()
        .mockResolvedValueOnce(authorityFixture(["service_account.read"]))
        .mockImplementationOnce(async () => deniedAuthority.promise),
      getTenantServiceAccount: async (_tenantId, _accountId, signal) => {
        detailSignal = signal;
        return delayedAccount.promise;
      },
    });
    renderWithAuthority(api, tenantId, <AuthorityReload />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    await waitFor(() => expect(detailSignal).toBeDefined());
    fireEvent.click(
      screen.getByText("Reload authority", { selector: "button" }),
    );
    expect(detailSignal?.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Late collector representation"),
    ).not.toBeInTheDocument();

    await act(async () => {
      delayedAccount.resolve({
        etag: '"v3"',
        value: accountFixture({ displayName: "Late collector representation" }),
      });
      deniedAuthority.resolve(authorityFixture([]));
      await Promise.all([delayedAccount.promise, deniedAuthority.promise]);
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(
      screen.queryByText("Late collector representation"),
    ).not.toBeInTheDocument();
  });

  it("isolates a late account page after the active tenant switches", async () => {
    const latePage = createDeferred<{ items: ServiceAccountView[] }>();
    const listTenantServiceAccounts = vi.fn(
      async (requestedTenantId: string) =>
        requestedTenantId === tenantId
          ? latePage.promise
          : {
              items: [
                accountFixture({
                  displayName: "Other tenant collector",
                  id: "0198c97d-cf4f-7000-8000-000000000299",
                  key: "other_collector",
                  tenantId: otherTenantId,
                }),
              ],
            },
    );
    const api = baseApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["service_account.read"], requestedTenantId),
      listTenantServiceAccounts,
    });
    render(<TenantSwitchHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Switch service-account tenant",
      }),
    );
    expect(await screen.findByText("Other tenant collector")).toBeVisible();
    await act(async () => {
      latePage.resolve({
        items: [accountFixture({ displayName: "Late original collector" })],
      });
      await latePage.promise;
    });
    expect(
      screen.queryByText("Late original collector"),
    ).not.toBeInTheDocument();
  });

  it.each([401, 403])(
    "ignores a stale service-account read %i after the active tenant switches",
    async (status) => {
      const latePage = createDeferred<{ items: ServiceAccountView[] }>();
      const clearSession = vi.fn<(expectedSessionId: string) => void>();
      const getTenantAuthority = vi.fn(async (requestedTenantId: string) =>
        authorityFixture(allPermissions, requestedTenantId),
      );
      const api = baseApi({
        getTenantAuthority,
        listTenantServiceAccounts: async (requestedTenantId) =>
          requestedTenantId === tenantId
            ? latePage.promise
            : {
                items: [
                  accountFixture({
                    displayName: "Other tenant collector",
                    id: "0198c97d-cf4f-7000-8000-000000000299",
                    key: "other_collector",
                    tenantId: otherTenantId,
                  }),
                ],
              },
      });
      render(<TenantSwitchHarness api={api} clearSession={clearSession} />);

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Switch service-account tenant",
        }),
      );
      expect(await screen.findByText("Other tenant collector")).toBeVisible();
      await act(async () => {
        latePage.reject(new PhaseTwoApiError("stale denial", status));
        await latePage.promise.catch(() => undefined);
      });

      expect(clearSession).not.toHaveBeenCalled();
      expect(getTenantAuthority).toHaveBeenCalledTimes(2);
      expect(screen.getByText("Other tenant collector")).toBeVisible();
    },
  );

  it("loads server-side account pages with the opaque cursor", async () => {
    const second = accountFixture({
      displayName: "Backup collector",
      id: "0198c97d-cf4f-7000-8000-000000000214",
      key: "backup_collector",
    });
    const listTenantServiceAccounts = vi.fn(
      async (_tenantId: string, options?: { after?: string }) =>
        options?.after
          ? { items: [second] }
          : { items: [accountFixture()], nextCursor: "account-page-two" },
    );
    renderAccounts({ listTenantServiceAccounts });

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more service accounts" }),
    );
    expect(await screen.findByText("Backup collector")).toBeVisible();
    expect(listTenantServiceAccounts).toHaveBeenLastCalledWith(
      tenantId,
      expect.objectContaining({ after: "account-page-two" }),
    );
  });

  it("filters the role catalog to service_account principals across the grant selector", async () => {
    const humanRole = roleFixture({
      id: "0198c97d-cf4f-7000-8000-000000000215",
      key: "analyst",
      name: "Analyst",
      principalKind: "human",
    });
    const machineRole = roleFixture();
    renderAccounts(
      {
        listTenantRoles: async () => ({ items: [humanRole, machineRole] }),
      },
      allPermissions,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Machine roles" }));
    const selector = await screen.findByRole("combobox", {
      name: "Machine role",
    });
    expect(
      within(selector).getByRole("option", { name: /Service account/ }),
    ).toBeVisible();
    expect(
      within(selector).queryByRole("option", { name: /Analyst/ }),
    ).not.toBeInTheDocument();
  });

  it("withholds revoke for unmanaged and expired machine-role grants", async () => {
    const unmanaged = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000218",
      managedByServiceAccountApi: false,
      role: {
        ...grantFixture().role,
        name: "Externally managed machine role",
      },
    });
    const expired = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000219",
      role: { ...grantFixture().role, name: "Expired machine role" },
      state: "expired",
    });
    renderAccounts(
      {
        listTenantServiceAccountRoleGrants: async () => ({
          items: [unmanaged, expired],
        }),
        listTenantRoles: async () => ({ items: [roleFixture()] }),
      },
      allPermissions,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Machine roles" }));
    expect(
      await screen.findByText("Externally managed machine role"),
    ).toBeVisible();
    expect(screen.getByText("Expired machine role")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Revoke role grant" }),
    ).not.toBeInTheDocument();
  });

  it("keeps an issued token only in the one-time dialog and removes it on dismiss", async () => {
    const bearerToken = `periapsis_api_v1.${"a".repeat(80)}`;
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const historyPush = vi.spyOn(history, "pushState");
    const historyReplace = vi.spyOn(history, "replaceState");
    const issueTenantServiceAccountCredential = vi.fn(async () => ({
      bearerToken,
      credential: credentialFixture(),
    }));
    renderAccounts({ issueTenantServiceAccountCredential }, [
      "service_account.credential.manage",
      "service_account.manage",
      "service_account.read",
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );

    const secretDialog = await screen.findByRole("dialog", {
      name: /Credential issued/,
    });
    expect(within(secretDialog).getByText(bearerToken)).toBeVisible();
    expect(secretDialog).toHaveAttribute("data-cache-policy", "no-store");
    expect(storageSpy).not.toHaveBeenCalled();
    expect(historyPush).not.toHaveBeenCalled();
    expect(historyReplace).not.toHaveBeenCalled();
    fireEvent.click(
      within(secretDialog).getByRole("button", { name: "I stored the token" }),
    );
    expect(screen.queryByText(bearerToken)).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    ).toBeVisible();
  });

  it("protects a pending and visible one-time credential across dismissals and unload", async () => {
    const bearerToken = `periapsis_api_v1.${"p".repeat(80)}`;
    const pendingIssue = createDeferred<{
      bearerToken: string;
      credential: ServiceAccountCredentialView;
    }>();
    const issueTenantServiceAccountCredential = vi.fn<
      PhaseTwoApi["issueTenantServiceAccountCredential"]
    >(async () => pendingIssue.promise);
    renderAccounts({ issueTenantServiceAccountCredential }, [
      "service_account.credential.manage",
      "service_account.manage",
      "service_account.read",
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Pending collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );

    await waitFor(() =>
      expect(issueTenantServiceAccountCredential).toHaveBeenCalledTimes(1),
    );
    expect(issueDialog).toHaveAttribute("aria-busy", "true");

    fireEvent.click(within(issueDialog).getByRole("button", { name: "Close" }));
    expect(issueDialog).toBeVisible();

    fireEvent.keyDown(document, { code: "Escape", key: "Escape" });
    expect(issueDialog).toBeVisible();

    fireEvent.pointerDown(document.body);
    fireEvent.click(document.body);
    expect(issueDialog).toBeVisible();
    expect(issueTenantServiceAccountCredential).toHaveBeenCalledTimes(1);
    const pendingUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(pendingUnload)).toBe(false);
    expect(pendingUnload.defaultPrevented).toBe(true);

    await act(async () => {
      pendingIssue.resolve({
        bearerToken,
        credential: credentialFixture({ label: "Pending collector key" }),
      });
      await pendingIssue.promise;
    });

    const secretDialog = await screen.findByRole("dialog", {
      name: /Credential issued/,
    });
    expect(within(secretDialog).getByText(bearerToken)).toBeVisible();
    expect(issueTenantServiceAccountCredential).toHaveBeenCalledTimes(1);
    expect(issueTenantServiceAccountCredential.mock.calls[0]?.[3]).toMatch(
      /^[0-9a-f-]{36}$/u,
    );
    const visibleSecretUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(visibleSecretUnload)).toBe(false);
    expect(visibleSecretUnload.defaultPrevented).toBe(true);

    fireEvent.click(
      within(secretDialog).getByRole("button", { name: "I stored the token" }),
    );
    expect(screen.queryByText(bearerToken)).not.toBeInTheDocument();
    const closedUnload = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(closedUnload)).toBe(true);
    expect(closedUnload.defaultPrevented).toBe(false);
  });

  it("creates an empty machine identity and archives it with its current account ETag", async () => {
    const created = accountFixture({
      displayName: "Fresh collector",
      id: "0198c97d-cf4f-7000-8000-000000000216",
      key: "fresh_collector",
      version: 1,
    });
    const createTenantServiceAccount = vi.fn(async () => ({
      etag: '"v1"',
      value: created,
    }));
    const archiveTenantServiceAccount = vi.fn(async () => undefined);
    renderAccounts({
      archiveTenantServiceAccount,
      createTenantServiceAccount,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Create service account" }),
    );
    const createDialog = screen.getByRole("dialog", {
      name: "Create service account",
    });
    fireEvent.change(
      within(createDialog).getByRole("textbox", {
        name: "Service account key",
      }),
      { target: { value: "fresh_collector" } },
    );
    fireEvent.change(
      within(createDialog).getByRole("textbox", { name: "Display name" }),
      { target: { value: "Fresh collector" } },
    );
    fireEvent.click(
      within(createDialog).getByRole("button", {
        name: "Create service account",
      }),
    );
    await waitFor(() =>
      expect(createTenantServiceAccount).toHaveBeenCalledWith(
        expect.any(String),
        tenantId,
        {
          displayName: "Fresh collector",
          key: "fresh_collector",
        },
      ),
    );
    expect(await screen.findByText("Fresh collector")).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Archive reason" }),
      { target: { value: "Collector retired" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Archive service account" }),
    );
    await waitFor(() =>
      expect(archiveTenantServiceAccount).toHaveBeenCalledWith(
        expect.any(String),
        tenantId,
        accountId,
        '"v3"',
        { reason: "Collector retired" },
      ),
    );
  });

  it("uses the redacted credential detail ETag when revoking a credential", async () => {
    const revokeTenantServiceAccountCredential = vi.fn(async () => undefined);
    const credential = credentialFixture({ etag: '"v7"', version: 7 });
    renderAccounts({
      getTenantServiceAccountCredential: async () => ({
        etag: '"v7"',
        value: credential,
      }),
      listTenantServiceAccountCredentials: async () => ({
        items: [credential],
      }),
      revokeTenantServiceAccountCredential,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Revoke reason" }),
      { target: { value: "Credential retired" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Revoke credential" }));
    await waitFor(() =>
      expect(revokeTenantServiceAccountCredential).toHaveBeenCalledWith(
        expect.any(String),
        tenantId,
        accountId,
        credentialId,
        '"v7"',
        { reason: "Credential retired" },
      ),
    );
  });

  it("reconciles a stale rotation ETag without replacing edited input or retry identity", async () => {
    const expiresAt = new Date(
      Date.now() + 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const original = credentialFixture({ expiresAt });
    const reconciled = credentialFixture({
      etag: '"v4"',
      expiresAt,
      version: 4,
    });
    const pendingReconciliation = createDeferred<{
      etag: string;
      value: ServiceAccountCredentialView;
    }>();
    const rotatedCredential = credentialFixture({
      etag: '"v1"',
      id: "0198c97d-cf4f-7000-8000-000000000217",
      label: "Rotated collector key",
      version: 1,
    });
    const bearerToken = `periapsis_api_v1.${"b".repeat(80)}`;
    const getTenantServiceAccountCredential = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: original })
      .mockImplementationOnce(async () => pendingReconciliation.promise);
    const rotateTenantServiceAccountCredential = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale credential", 412))
      .mockResolvedValueOnce({
        bearerToken,
        credential: rotatedCredential,
      });
    renderAccounts({
      getTenantServiceAccountCredential,
      listTenantServiceAccountCredentials: async () => ({
        items: [original],
      }),
      rotateTenantServiceAccountCredential,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Rotate credential" }),
    );
    const rotationDialog = screen.getByRole("dialog", {
      name: "Rotate API credential",
    });
    fireEvent.change(
      within(rotationDialog).getByRole("textbox", {
        name: "Credential label",
      }),
      { target: { value: "Rotated collector key" } },
    );
    fireEvent.change(
      within(rotationDialog).getByRole("textbox", {
        name: "Predecessor revoke reason",
      }),
      { target: { value: "Routine rotation" } },
    );
    fireEvent.click(
      within(rotationDialog).getByRole("button", {
        name: "Rotate credential",
      }),
    );

    await waitFor(() =>
      expect(getTenantServiceAccountCredential).toHaveBeenCalledTimes(2),
    );
    expect(rotationDialog).toHaveAttribute("aria-busy", "true");
    fireEvent.keyDown(document, { code: "Escape", key: "Escape" });
    expect(rotationDialog).toBeVisible();
    await act(async () => {
      pendingReconciliation.resolve({ etag: '"v4"', value: reconciled });
      await pendingReconciliation.promise;
    });

    expect(
      await within(rotationDialog).findByText(
        /current credential ETag is loaded/i,
      ),
    ).toBeVisible();
    expect(
      within(rotationDialog).getByRole("textbox", {
        name: "Credential label",
      }),
    ).toHaveValue("Rotated collector key");
    fireEvent.click(
      within(rotationDialog).getByRole("button", {
        name: "Rotate credential",
      }),
    );

    const secretDialog = await screen.findByRole("dialog", {
      name: /Credential rotated/,
    });
    expect(within(secretDialog).getByText(bearerToken)).toBeVisible();
    expect(rotateTenantServiceAccountCredential).toHaveBeenCalledTimes(2);
    const firstCall = rotateTenantServiceAccountCredential.mock.calls[0];
    const secondCall = rotateTenantServiceAccountCredential.mock.calls[1];
    expect(firstCall?.[4]).toBe('"v3"');
    expect(secondCall?.[4]).toBe('"v4"');
    expect(secondCall?.[5]).toBe(firstCall?.[5]);
  });

  it("reconciles safe replay metadata without ever recreating a one-time token", async () => {
    const issueTenantServiceAccountCredential = vi.fn(async () => {
      throw new PhaseTwoApiError("already issued", 409, {
        code: "one_time_secret_already_issued",
        credentialId,
        location: `/api/v1/tenants/${tenantId}/service-accounts/${accountId}/credentials/${credentialId}`,
      });
    });
    const getTenantServiceAccountCredential = vi.fn(async () => ({
      etag: '"v3"',
      value: credentialFixture(),
    }));
    renderAccounts({
      getTenantServiceAccountCredential,
      issueTenantServiceAccountCredential,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );

    expect(
      await within(issueDialog).findByText(
        /bearer token cannot be shown again/i,
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(getTenantServiceAccountCredential).toHaveBeenCalledWith(
        tenantId,
        accountId,
        credentialId,
      ),
    );
    expect(screen.queryByText(/periapsis_api_v1\./)).not.toBeInTheDocument();
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Cancel" }),
    );
    expect(
      await screen.findByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    ).toBeVisible();
  });

  it("retries one ambiguous issue with the same in-memory binding and reconciles its safe replay", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const issueTenantServiceAccountCredential = vi
      .fn<PhaseTwoApi["issueTenantServiceAccountCredential"]>()
      .mockRejectedValueOnce(new PhaseTwoApiError("connection lost"))
      .mockRejectedValueOnce(
        new PhaseTwoApiError("already issued", 409, {
          code: "one_time_secret_already_issued",
          credentialId,
          location: `/api/v1/tenants/${tenantId}/service-accounts/${accountId}/credentials/${credentialId}`,
        }),
      );
    const getTenantServiceAccountCredential = vi.fn(async () => ({
      etag: '"v3"',
      value: credentialFixture(),
    }));
    renderAccounts({
      getTenantServiceAccountCredential,
      issueTenantServiceAccountCredential,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );

    expect(
      await within(issueDialog).findByText(
        /bearer token cannot be shown again/i,
      ),
    ).toBeVisible();
    expect(issueTenantServiceAccountCredential).toHaveBeenCalledTimes(2);
    const firstCall = issueTenantServiceAccountCredential.mock.calls[0];
    const retryCall = issueTenantServiceAccountCredential.mock.calls[1];
    expect(retryCall?.[3]).toBe(firstCall?.[3]);
    expect(retryCall?.[4]).toBe(firstCall?.[4]);
    await waitFor(() =>
      expect(getTenantServiceAccountCredential).toHaveBeenCalledWith(
        tenantId,
        accountId,
        credentialId,
      ),
    );
    expect(screen.queryByText(/periapsis_api_v1\./)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("dialog", { name: /Credential issued/ }),
    ).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
  });

  it("clears the current session when safe replay reconciliation returns 401", async () => {
    const issueTenantServiceAccountCredential = vi.fn(async () => {
      throw new PhaseTwoApiError("already issued", 409, {
        code: "one_time_secret_already_issued",
        credentialId,
      });
    });
    const getTenantServiceAccountCredential = vi.fn(async () => {
      throw new PhaseTwoApiError("expired session", 401);
    });
    const clearSession = renderWithAuthority(
      baseApi({
        getTenantServiceAccountCredential,
        issueTenantServiceAccountCredential,
      }),
      tenantId,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
    expect(getTenantServiceAccountCredential).toHaveBeenCalledTimes(1);
  });

  it("fails closed when stale-ETag reconciliation returns a tenant mismatch", async () => {
    const original = credentialFixture();
    const getTenantAuthority = vi
      .fn<PhaseTwoApi["getTenantAuthority"]>()
      .mockResolvedValueOnce(authorityFixture(allPermissions))
      .mockResolvedValueOnce(authorityFixture(allPermissions));
    const getTenantServiceAccountCredential = vi
      .fn<PhaseTwoApi["getTenantServiceAccountCredential"]>()
      .mockResolvedValueOnce({ etag: '"v3"', value: original })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("tenant projection mismatch", undefined, {
          code: tenantProjectionMismatchCode,
        }),
      );
    const rotateTenantServiceAccountCredential = vi.fn(async () => {
      throw new PhaseTwoApiError("stale credential", 412);
    });
    const clearSession = renderWithAuthority(
      baseApi({
        getTenantAuthority,
        getTenantServiceAccountCredential,
        listTenantServiceAccountCredentials: async () => ({
          items: [original],
        }),
        rotateTenantServiceAccountCredential,
      }),
      tenantId,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `View credential Collector key (${credentialId})`,
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Rotate credential" }),
    );
    const rotationDialog = screen.getByRole("dialog", {
      name: "Rotate API credential",
    });
    fireEvent.change(
      within(rotationDialog).getByRole("textbox", {
        name: "Predecessor revoke reason",
      }),
      { target: { value: "Routine rotation" } },
    );
    fireEvent.click(
      within(rotationDialog).getByRole("button", {
        name: "Rotate credential",
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);
    expect(getTenantServiceAccountCredential).toHaveBeenCalledTimes(2);
    expect(clearSession).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("removes an in-memory token immediately when credential authority reloads", async () => {
    const nextAuthority = createDeferred<TenantAuthorityView>();
    const bearerToken = `periapsis_api_v1.${"c".repeat(80)}`;
    const api = baseApi({
      getTenantAuthority: vi
        .fn()
        .mockResolvedValueOnce(authorityFixture(allPermissions))
        .mockImplementationOnce(async () => nextAuthority.promise),
      issueTenantServiceAccountCredential: async () => ({
        bearerToken,
        credential: credentialFixture(),
      }),
    });
    renderWithAuthority(api, tenantId, <AuthorityReload />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("tab", { name: "API credentials" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Issue credential" }));
    const issueDialog = screen.getByRole("dialog", {
      name: "Issue API credential",
    });
    fireEvent.change(
      within(issueDialog).getByRole("textbox", { name: "Credential label" }),
      { target: { value: "Collector key" } },
    );
    fireEvent.click(
      within(issueDialog).getByRole("button", { name: "Issue credential" }),
    );
    expect(await screen.findByText(bearerToken)).toBeVisible();

    fireEvent.click(
      screen.getByText("Reload authority", { selector: "button" }),
    );
    expect(screen.queryByText(bearerToken)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("dialog", { name: /Credential issued/ }),
    ).not.toBeInTheDocument();
    await act(async () => {
      nextAuthority.resolve(
        authorityFixture(["service_account.manage", "service_account.read"]),
      );
      await nextAuthority.promise;
    });
  });

  it("preserves edited metadata while reconciling a 412 to the latest account ETag", async () => {
    const getTenantServiceAccount = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: accountFixture() })
      .mockResolvedValueOnce({
        etag: '"v4"',
        value: accountFixture({ displayName: "Server name", version: 4 }),
      });
    const updateTenantServiceAccount = vi.fn(async () => {
      throw new PhaseTwoApiError("stale account", 412);
    });
    renderAccounts({ getTenantServiceAccount, updateTenantServiceAccount }, [
      "service_account.manage",
      "service_account.read",
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    const name = await screen.findByRole("textbox", { name: "Display name" });
    fireEvent.change(name, { target: { value: "My reviewed name" } });
    fireEvent.click(screen.getByRole("button", { name: "Save account" }));

    expect(await screen.findByText(/latest ETag is loading/i)).toBeVisible();
    await waitFor(() =>
      expect(getTenantServiceAccount).toHaveBeenCalledTimes(2),
    );
    expect(screen.getByRole("textbox", { name: "Display name" })).toHaveValue(
      "My reviewed name",
    );
    expect(screen.getByText('"v4"')).toBeVisible();
    expect(updateTenantServiceAccount).toHaveBeenCalledWith(
      expect.any(String),
      tenantId,
      accountId,
      '"v3"',
      expect.objectContaining({ displayName: "My reviewed name" }),
    );
  });

  it("uses the representation-bound grant ETag when revoking machine authority", async () => {
    const revokeTenantServiceAccountRoleGrant = vi.fn(async () => undefined);
    renderAccounts(
      {
        listTenantServiceAccountRoleGrants: async () => ({
          items: [grantFixture()],
        }),
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        revokeTenantServiceAccountRoleGrant,
      },
      allPermissions,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alert collector (alert_collector)",
      }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Machine roles" }));
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Revoke Service account" }),
      { target: { value: "Collector retired" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Revoke role grant" }));
    await waitFor(() =>
      expect(revokeTenantServiceAccountRoleGrant).toHaveBeenCalledWith(
        expect.any(String),
        tenantId,
        accountId,
        grantId,
        edgeEtag,
        { reason: "Collector retired" },
      ),
    );
  });
});

describe("mergeServiceAccounts", () => {
  it("keeps the newest version and rejects conflicting equal versions", () => {
    const original = accountFixture();
    const newer = accountFixture({ displayName: "New name", version: 4 });
    expect(mergeServiceAccounts([original], [newer])).toEqual([newer]);
    expect(() =>
      mergeServiceAccounts(
        [original],
        [accountFixture({ displayName: "Conflicting name" })],
      ),
    ).toThrow(/conflicting representations/i);
  });
});

function renderAccounts(
  overrides: Partial<PhaseTwoApi> = {},
  permissions: readonly TenantPermissionKeyView[] = allPermissions,
): void {
  renderWithAuthority(baseApi(overrides, permissions), tenantId);
}

function renderWithAuthority(
  api: PhaseTwoApi,
  activeTenantId: string,
  extra?: React.ReactNode,
): ReturnType<typeof vi.fn<(expectedSessionId: string) => void>> {
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId,
    idleExpiresAt: "2099-08-23T12:00:00Z",
  };
  const clearSession = vi.fn<(expectedSessionId: string) => void>();
  render(
    <SessionContext.Provider
      value={{
        api,
        clearSession,
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        {extra}
        <TenantServiceAccountsPage />
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
  return clearSession;
}

function baseApi(
  overrides: Partial<PhaseTwoApi> = {},
  permissions: readonly TenantPermissionKeyView[] = allPermissions,
): PhaseTwoApi {
  return createPhaseTwoApi({
    getTenantAuthority: async (requestedTenantId) =>
      authorityFixture(permissions, requestedTenantId),
    getTenantServiceAccount: async (requestedTenantId, requestedAccountId) => ({
      etag: '"v3"',
      value: accountFixture({
        id: requestedAccountId,
        tenantId: requestedTenantId,
      }),
    }),
    listTenantRoles: async () => ({ items: [roleFixture()] }),
    listTenantServiceAccountCredentials: async () => ({ items: [] }),
    listTenantServiceAccountRoleGrants: async () => ({ items: [] }),
    listTenantServiceAccounts: async (requestedTenantId) => ({
      items: [accountFixture({ tenantId: requestedTenantId })],
    }),
    ...overrides,
  });
}

function AuthorityReload(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button type="button" onClick={authority.reload}>
      Reload authority
    </button>
  );
}

function TenantSwitchHarness({
  api,
  clearSession = vi.fn(),
}: {
  api: PhaseTwoApi;
  clearSession?: (expectedSessionId: string) => void;
}): React.JSX.Element {
  const [session, setSession] = useState({
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId: tenantId,
    idleExpiresAt: "2099-08-23T12:00:00Z",
  });
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession,
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <button
          type="button"
          onClick={() =>
            setSession((current) => ({
              ...current,
              activeTenantId: otherTenantId,
            }))
          }
        >
          Switch service-account tenant
        </button>
        <TenantServiceAccountsPage />
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
  requestedTenantId = tenantId,
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-25T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissions.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: requestedTenantId,
    userId: sessionFixture.user.id,
  };
}

function accountFixture(
  overrides: Partial<ServiceAccountView> = {},
): ServiceAccountView {
  return {
    createdAt: "2026-08-20T10:00:00Z",
    createdByMembershipId: "0198c97d-cf4f-7000-8000-000000000020",
    description: "Creates governed alert events",
    displayName: "Alert collector",
    id: accountId,
    key: "alert_collector",
    principalType: "service_account",
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
    ...overrides,
  };
}

function roleFixture(
  overrides: Partial<TenantRoleSummaryView> = {},
): TenantRoleSummaryView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    id: roleId,
    key: "service_account",
    name: "Service account",
    principalKind: "service_account",
    system: true,
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
    ...overrides,
  };
}

function grantFixture(
  overrides: Partial<ServiceAccountRoleGrantView> = {},
): ServiceAccountRoleGrantView {
  return {
    etag: edgeEtag,
    id: grantId,
    managedByServiceAccountApi: true,
    provenance: {
      authoritative: false,
      grantedAt: "2026-08-22T10:00:00Z",
      grantedByUserId: sessionFixture.user.id,
      reason: "Collector requires alert ingest",
      sourceId: grantId,
      sourceKind: "manual",
    },
    role: {
      id: roleId,
      key: "service_account",
      name: "Service account",
      principalKind: "service_account",
      system: true,
    },
    serviceAccountId: accountId,
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
    ...overrides,
  };
}

function credentialFixture(
  overrides: Partial<ServiceAccountCredentialView> = {},
): ServiceAccountCredentialView {
  return {
    allowedNetworks: [],
    etag: '"v3"',
    expiresAt: "2026-09-20T10:00:00Z",
    id: credentialId,
    issuedAt: "2026-08-25T10:00:00Z",
    issuedByMembershipId: "0198c97d-cf4f-7000-8000-000000000020",
    label: "Collector key",
    permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
    serviceAccountId: accountId,
    state: "active",
    tenantId,
    updatedAt: "2026-08-25T10:00:00Z",
    version: 3,
    ...overrides,
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    reject = promiseReject;
    resolve = promiseResolve;
  });
  return { promise, reject, resolve };
}
