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
  type DirectUserRoleGrantView,
  type EffectiveTenantRoleGrantView,
  type TenantAuthorityView,
  type TenantRoleView,
  type TenantUserSummaryView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { InheritedGroupPaths, TenantUsersPage } from "./tenant-users";
import {
  deriveDelegableRoleChoice,
  effectiveAuthorityPathKey,
  mergeTenantUsers,
} from "./tenant-users-model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const directGrantEtag = '"v7-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';
const userId = "0198c97d-cf4f-7000-8000-000000000070";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TenantUsersPage", () => {
  it("keeps initial authority pending and clears ready user state before a read-permission loss settles", async () => {
    const user = userFixture();
    const initialAuthority = createDeferred<TenantAuthorityView>();
    const deniedAuthority = createDeferred<TenantAuthorityView>();
    const delayedPage = createDeferred<{
      items: TenantUserSummaryView[];
    }>();
    let paginationSignal: AbortSignal | undefined;
    const getTenantAuthority = vi
      .fn()
      .mockImplementationOnce(async () => initialAuthority.promise)
      .mockImplementationOnce(async () => deniedAuthority.promise);
    const listTenantUsers = vi.fn(
      async (
        _requestedTenantId: string,
        after?: string,
        signal?: AbortSignal,
      ) => {
        if (after === "user-page-two") {
          paginationSignal = signal;
          return delayedPage.promise;
        }
        return { items: [user], nextCursor: "user-page-two" };
      },
    );
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority,
        listTenantUsers,
        listUserRoleGrants: async () => ({ items: [] }),
      }),
      vi.fn(),
      true,
    );

    expect(screen.getByLabelText("Loading tenant users")).toBeVisible();
    expect(listTenantUsers).not.toHaveBeenCalled();
    await act(async () => {
      initialAuthority.resolve(authorityFixture(["user.read"]));
      await initialAuthority.promise;
    });
    const open = await screen.findByRole("button", {
      name: "Review access for Ada Target (ada-target@example.invalid)",
    });
    fireEvent.click(screen.getByRole("button", { name: "Load more users" }));
    await waitFor(() => expect(paginationSignal).toBeDefined());
    fireEvent.click(open);
    await screen.findByRole("dialog");

    fireEvent.click(screen.getByTestId("reload-user-authority"));
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(paginationSignal?.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    ).not.toBeInTheDocument();

    await act(async () => {
      delayedPage.resolve({
        items: [
          {
            ...user,
            membershipId: "0198c97d-cf4f-7000-8000-000000000199",
            user: {
              ...user.user,
              displayName: "Late user",
              email: "late-user@example.invalid",
              id: "0198c97d-cf4f-7000-8000-000000000198",
            },
          },
        ],
      });
      await delayedPage.promise;
    });
    expect(screen.queryByText("Late user")).not.toBeInTheDocument();

    await act(async () => {
      deniedAuthority.resolve(authorityFixture([]));
      await deniedAuthority.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantUsers).toHaveBeenCalledTimes(2);
  });

  it("requests a direct route and safely renders a server 403", async () => {
    const listTenantUsers = vi
      .fn()
      .mockRejectedValue(
        new PhaseTwoApiError("sensitive membership detail", 403),
      );
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers,
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantUsers).toHaveBeenCalled();
    expect(
      screen.queryByText("sensitive membership detail"),
    ).not.toBeInTheDocument();
  });

  it("qualifies duplicate user display-name actions with email", async () => {
    const first = userFixture();
    const second = {
      ...first,
      membershipId: "0198c97d-cf4f-7000-8000-000000000072",
      user: {
        ...first.user,
        email: "ada-second@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000073",
      },
    };
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [first, second] }),
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Review access for Ada Target (ada-second@example.invalid)",
      }),
    ).toBeVisible();
  });

  it("shows lifecycle controls only with membership.manage", async () => {
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: "Suspend membership for Ada Target (ada-target@example.invalid)",
      }),
    ).not.toBeInTheDocument();
  });

  it("requires an explicit reason and reuses one payload-bound key on exact suspend retry", async () => {
    let suspended = false;
    const listTenantUsers = vi.fn(async () => ({
      items: [
        suspended
          ? {
              ...userFixture(),
              etag: '"v2"',
              lifecycleRevision: 2,
              membershipStatus: "suspended" as const,
              updatedAt: "2026-08-23T10:00:00Z",
            }
          : userFixture(),
      ],
    }));
    const changeTenantMembershipLifecycle = vi
      .fn()
      .mockRejectedValueOnce(new Error("temporary transport failure"))
      .mockImplementationOnce(async () => {
        suspended = true;
        return {
          tenantId,
          membershipId: userFixture().membershipId,
          userId,
          previousStatus: "active" as const,
          status: "suspended" as const,
          lifecycleRevision: 2,
          etag: '"v2"',
          updatedAt: "2026-08-23T10:00:00Z",
          revokedSessionCount: 2,
          revokedContinuationCount: 1,
          replayed: false,
        };
      });
    renderUsers(
      createPhaseTwoApi({
        changeTenantMembershipLifecycle,
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "membership.manage"]),
        listTenantUsers,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Suspend membership for Ada Target (ada-target@example.invalid)",
      }),
    );
    expect(
      screen.getByText(
        "Active sessions and pending continuations for this user in this tenant will be revoked. Other tenants and platform sessions are not affected.",
      ),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Suspend Ada Target" }));
    expect(changeTenantMembershipLifecycle).not.toHaveBeenCalled();
    expect(screen.getByText("Enter an administrative reason.")).toBeVisible();

    const reason = screen.getByRole("textbox", {
      name: "Administrative reason",
    });
    fireEvent.change(reason, {
      target: { value: "Suspend access during offboarding review" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Suspend Ada Target" }));
    await waitFor(() =>
      expect(changeTenantMembershipLifecycle).toHaveBeenCalledTimes(1),
    );
    expect(
      await screen.findByText(
        "The membership was not suspended. Your reason is preserved.",
      ),
    ).toBeVisible();
    expect(reason).toHaveValue("Suspend access during offboarding review");

    fireEvent.click(screen.getByRole("button", { name: "Suspend Ada Target" }));
    await waitFor(() =>
      expect(changeTenantMembershipLifecycle).toHaveBeenCalledTimes(2),
    );
    const first = changeTenantMembershipLifecycle.mock.calls[0];
    const second = changeTenantMembershipLifecycle.mock.calls[1];
    expect(first?.slice(0, 5)).toEqual([
      sessionFixture.csrfToken,
      tenantId,
      userId,
      "suspended",
      userFixture(),
    ]);
    expect(first?.[5]).toEqual(second?.[5]);
    expect(first?.[6]).toBe("Suspend access during offboarding review");
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", {
          name: "Suspend tenant membership",
        }),
      ).not.toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(listTenantUsers.mock.calls.length).toBeGreaterThan(1),
    );
    expect(
      await screen.findByRole("button", {
        name: "Reactivate membership for Ada Target (ada-target@example.invalid)",
      }),
    ).toBeVisible();
  });

  it("reloads a stale direct grant, preserves its revoke draft, and retries with the current ETag", async () => {
    const staleGrant = grantFixture();
    const currentGrant = {
      ...staleGrant,
      etag: '"v8-current-direct-grant"',
      updatedAt: "2026-08-23T11:00:00Z",
      version: 8,
    };
    const listUserRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleGrant] })
      .mockResolvedValue({ items: [currentGrant] });
    const revokeRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce(undefined);
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    const reason = screen.getByRole("textbox", {
      name: "Reason for revoking direct grant for Custom triage (custom_triage)",
    });
    fireEvent.change(reason, { target: { value: "Assignment completed" } });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );

    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();
    const reloadedReason = screen.getByRole("textbox", {
      name: "Reason for revoking direct grant for Custom triage (custom_triage)",
    });
    expect(reloadedReason).toHaveValue("Assignment completed");
    expect(revokeRoleGrant).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      staleGrant.id,
      staleGrant.etag,
      { reason: "Assignment completed" },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Assignment completed" },
      ),
    );
  });

  it("moves the page origin with a newer overlapping grant representation", async () => {
    const staleGrant = grantFixture();
    const pageTwoGrant = {
      ...staleGrant,
      etag: '"v8-page-two-overlap"',
      version: 8,
    };
    const currentGrant = {
      ...staleGrant,
      etag: '"v9-page-two-current"',
      version: 9,
    };
    let current = false;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) =>
        options?.after === "grant-page-two"
          ? { items: [current ? currentGrant : pageTwoGrant] }
          : { items: [staleGrant], nextCursor: "grant-page-two" },
    );
    const revokeRoleGrant = vi.fn(async () => {
      if (!current) {
        current = true;
        throw new PhaseTwoApiError("version mismatch", 412);
      }
    });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(2));
    const roleTarget = "Custom triage (custom_triage)";
    fireEvent.click(
      screen.getByRole("button", {
        name: `Revoke direct grant for ${roleTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
      { target: { value: "Refresh overlap" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );

    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();
    expect(listUserRoleGrants).toHaveBeenNthCalledWith(
      3,
      tenantId,
      userId,
      expect.objectContaining({
        after: "grant-page-two",
        includeRevoked: true,
      }),
    );
    expect(revokeRoleGrant).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      staleGrant.id,
      pageTwoGrant.etag,
      { reason: "Refresh overlap" },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Refresh overlap" },
      ),
    );
  });

  it("keeps a refreshed grant when an older overlapping page resolves later", async () => {
    const staleGrant = grantFixture();
    const delayedGrant = {
      ...staleGrant,
      etag: '"v8-delayed-overlap"',
      version: 8,
    };
    const currentGrant = {
      ...staleGrant,
      etag: '"v9-current-after-412"',
      version: 9,
    };
    const delayedPage = createDeferred<{
      items: DirectUserRoleGrantView[];
    }>();
    let rootLoads = 0;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        if (options?.after === "grant-page-two") {
          return delayedPage.promise;
        }
        rootLoads += 1;
        return rootLoads === 1
          ? { items: [staleGrant], nextCursor: "grant-page-two" }
          : { items: [currentGrant], nextCursor: "grant-page-two" };
      },
    );
    const revokeRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce(undefined);
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    const roleTarget = "Custom triage (custom_triage)";
    fireEvent.click(
      screen.getByRole("button", {
        name: `Revoke direct grant for ${roleTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
      { target: { value: "Preserve newest refresh" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );
    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [delayedGrant] });
      await delayedPage.promise;
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );

    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Preserve newest refresh" },
      ),
    );
  });

  it("accepts a same-version role-summary ETag refresh and keeps its page origin across a delayed overlap", async () => {
    const firstPageGrant = tenantCreationGrantFixture();
    const staleGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000096",
      roleId: "0198c97d-cf4f-7000-8000-000000000056",
      roleKey: "rename_page_two",
      roleName: "Page two role before rename",
    });
    const renamedGrant = {
      ...staleGrant,
      etag: `"v7-${"A".repeat(43)}"`,
      role: { ...staleGrant.role, name: "Page two role after rename" },
      updatedAt: "2026-08-23T11:00:00Z",
    };
    const currentGrant = {
      ...renamedGrant,
      etag: `"v8-${"B".repeat(43)}"`,
      updatedAt: "2026-08-23T11:30:00Z",
      version: 8,
    };
    const delayedPage = createDeferred<{
      items: DirectUserRoleGrantView[];
    }>();
    let pageTwoLoads = 0;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        if (!options?.after) {
          return { items: [firstPageGrant], nextCursor: "grant-page-two" };
        }
        if (options.after === "grant-page-three") {
          return delayedPage.promise;
        }
        pageTwoLoads += 1;
        if (pageTwoLoads === 1) {
          return { items: [staleGrant], nextCursor: "grant-page-three" };
        }
        return {
          items: [pageTwoLoads === 2 ? renamedGrant : currentGrant],
          nextCursor: "grant-page-three",
        };
      },
    );
    const revokeRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("role renamed", 412))
      .mockRejectedValueOnce(new PhaseTwoApiError("edge advanced", 412))
      .mockResolvedValueOnce(undefined);
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    const staleTarget = "Page two role before rename (rename_page_two)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke direct grant for ${staleTarget}`,
      }),
    );
    const staleReason = screen.getByRole("textbox", {
      name: `Reason for revoking direct grant for ${staleTarget}`,
    });
    fireEvent.change(staleReason, {
      target: { value: "Preserve the page-two role rename" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Load more grant history" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${staleTarget}`,
      }),
    );

    const renamedTarget = "Page two role after rename (rename_page_two)";
    expect(
      await screen.findByRole("textbox", {
        name: `Reason for revoking direct grant for ${renamedTarget}`,
      }),
    ).toHaveValue("Preserve the page-two role rename");
    expect(revokeRoleGrant).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      staleGrant.id,
      staleGrant.etag,
      { reason: "Preserve the page-two role rename" },
    );

    await act(async () => {
      delayedPage.resolve({ items: [staleGrant] });
      await delayedPage.promise;
    });
    expect(
      screen.queryByText("More grant history could not be loaded"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Page two role after rename")).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${renamedTarget}`,
      }),
    );
    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(5));
    expect(listUserRoleGrants).toHaveBeenNthCalledWith(
      5,
      tenantId,
      userId,
      expect.objectContaining({
        after: "grant-page-two",
        includeRevoked: true,
      }),
    );
    expect(revokeRoleGrant).toHaveBeenNthCalledWith(
      2,
      sessionFixture.csrfToken,
      tenantId,
      renamedGrant.id,
      renamedGrant.etag,
      { reason: "Preserve the page-two role rename" },
    );

    await waitFor(() =>
      expect(
        screen.getByRole("button", {
          name: `Confirm revoke direct grant for ${renamedTarget}`,
        }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${renamedTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        3,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Preserve the page-two role rename" },
      ),
    );
  });

  it("keeps stale recovery gated when an equal-version third ETag wins during refresh", async () => {
    const rejectedGrant = grantFixture();
    const refreshCandidate = {
      ...rejectedGrant,
      etag: `"v8-${"C".repeat(43)}"`,
      version: 8,
    };
    const concurrentGrant = {
      ...rejectedGrant,
      etag: `"v8-${"D".repeat(43)}"`,
      version: 8,
    };
    const refreshPage = createDeferred<{
      items: DirectUserRoleGrantView[];
    }>();
    let rootLoads = 0;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        if (options?.after === "grant-page-two") {
          return { items: [concurrentGrant] };
        }
        rootLoads += 1;
        return rootLoads === 1
          ? { items: [rejectedGrant], nextCursor: "grant-page-two" }
          : refreshPage.promise;
      },
    );
    const revokeRoleGrant = vi
      .fn()
      .mockRejectedValue(new PhaseTwoApiError("version mismatch", 412));
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    const roleTarget = "Custom triage (custom_triage)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke direct grant for ${roleTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
      { target: { value: "Keep the ambiguous refresh gated" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );
    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(2));

    fireEvent.click(
      screen.getByRole("button", { name: "Load more grant history" }),
    );
    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(3));
    await act(async () => {
      refreshPage.resolve({ items: [refreshCandidate] });
      await refreshPage.promise;
    });

    expect(
      await screen.findByRole("button", {
        name: `Retry current grant refresh for ${roleTarget}`,
      }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
    ).toHaveValue("Keep the ambiguous refresh gated");
    expect(revokeRoleGrant).toHaveBeenCalledTimes(1);
  });

  it("retains the accepted entry for an unordered same-version ETag overlap", async () => {
    const grant = grantFixture();
    const conflictingGrant = {
      ...grant,
      etag: `"v7-${"E".repeat(43)}"`,
    };
    const freshGrant = {
      ...grant,
      etag: `"v8-${"G".repeat(43)}"`,
      updatedAt: "2026-08-23T12:00:00Z",
      version: 8,
    };
    let rootLoads = 0;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        if (options?.after) {
          return { items: [conflictingGrant] };
        }
        rootLoads += 1;
        return rootLoads === 1
          ? { items: [grant], nextCursor: "grant-page-two" }
          : { items: [freshGrant] };
      },
    );
    const revokeRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce(undefined);
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Load more grant history" }),
      ).not.toBeInTheDocument(),
    );
    expect(listUserRoleGrants).toHaveBeenNthCalledWith(
      2,
      tenantId,
      userId,
      expect.objectContaining({
        after: "grant-page-two",
        includeRevoked: true,
      }),
    );
    expect(
      screen.queryByText("More grant history could not be loaded"),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
      { target: { value: "Keep the coherent ETag" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );

    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        1,
        sessionFixture.csrfToken,
        tenantId,
        grant.id,
        grant.etag,
        { reason: "Keep the coherent ETag" },
      ),
    );
    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(3));
    const refreshOptions = listUserRoleGrants.mock.calls[2]?.[2];
    expect(refreshOptions).toEqual(
      expect.objectContaining({ includeRevoked: true }),
    );
    expect(refreshOptions).not.toHaveProperty("after");
    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        freshGrant.id,
        freshGrant.etag,
        { reason: "Keep the coherent ETag" },
      ),
    );
  });

  it("fails closed on a non-positive direct-grant version", async () => {
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [{ ...grantFixture(), version: 0 }],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByText("Direct role grants could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Custom triage")).not.toBeInTheDocument();
  });

  it("fails closed on a direct-grant ETag whose prefix does not match its version", async () => {
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grantFixture(),
              etag: `"v8-${"F".repeat(43)}"`,
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByText("Direct role grants could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Custom triage")).not.toBeInTheDocument();
  });

  it("fails closed on a matching-prefix direct-grant version above int32", async () => {
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grantFixture(),
              etag: `"v2147483648-${"H".repeat(43)}"`,
              version: 2_147_483_648,
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByText("Direct role grants could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Custom triage")).not.toBeInTheDocument();
  });

  it("fails closed on a malformed direct-grant expiry from an injected API", async () => {
    const grant = grantFixture();
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grant,
              provenance: {
                ...grant.provenance,
                expiresAt: "2026-08-23",
              },
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByText("Direct role grants could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Custom triage")).not.toBeInTheDocument();
  });

  it("fails closed on a direct-grant expiry finer than nanoseconds", async () => {
    const grant = grantFixture();
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grant,
              provenance: {
                ...grant.provenance,
                expiresAt: "2099-08-23T12:00:00.1234567891+02:30",
              },
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByText("Direct role grants could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Custom triage")).not.toBeInTheDocument();
  });

  it("accepts a contract-valid sub-microsecond direct-grant expiry", async () => {
    const grant = grantFixture();
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grant,
              provenance: {
                ...grant.provenance,
                expiresAt: "2099-08-23T12:00:00.1234567+02:30",
              },
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(await screen.findByText("Custom triage")).toBeVisible();
    expect(
      screen.queryByText("Direct role grants could not be loaded."),
    ).not.toBeInTheDocument();
  });

  it("accepts an offset direct-grant expiry with nonzero nanosecond digits", async () => {
    const grant = grantFixture();
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            {
              ...grant,
              provenance: {
                ...grant.provenance,
                expiresAt: "2099-08-23T12:00:00.123456789+02:30",
              },
            },
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(await screen.findByText("Custom triage")).toBeVisible();
    expect(
      screen.queryByText("Direct role grants could not be loaded."),
    ).not.toBeInTheDocument();
  });

  it("closes a stale draft when the exact refreshed grant is already revoked", async () => {
    const staleGrant = grantFixture();
    const currentGrant = {
      ...revokedGrantFixture(),
      etag: '"v8-concurrently-revoked"',
      id: staleGrant.id,
      role: staleGrant.role,
      version: 8,
    };
    const listUserRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleGrant] })
      .mockResolvedValue({ items: [currentGrant] });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant: async () => {
          throw new PhaseTwoApiError("version mismatch", 412);
        },
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
      { target: { value: "Concurrent terminal state" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );

    expect(
      await screen.findByText(
        "This grant is already revoked on the server. No further revoke is needed.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByText(/retry with the latest version/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: "Retry current grant refresh for Custom triage (custom_triage)",
      }),
    ).not.toBeInTheDocument();
  });

  it("reacquires a stale page-two grant without discarding its loaded card or revoke draft", async () => {
    const firstPageGrant = tenantCreationGrantFixture();
    const staleGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000090",
      roleId: "0198c97d-cf4f-7000-8000-000000000050",
      roleKey: "page_two_triage",
      roleName: "Page two triage",
    });
    const currentGrant = {
      ...staleGrant,
      etag: '"v8-page-two-current"',
      updatedAt: "2026-08-23T11:00:00Z",
      version: 8,
    };
    let current = false;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) =>
        options?.after
          ? { items: [current ? currentGrant : staleGrant] }
          : { items: [firstPageGrant], nextCursor: "grant-page-two" },
    );
    const revokeRoleGrant = vi.fn(async () => {
      if (!current) {
        current = true;
        throw new PhaseTwoApiError("version mismatch", 412);
      }
    });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    const roleTarget = "Page two triage (page_two_triage)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke direct grant for ${roleTarget}`,
      }),
    );
    const reason = screen.getByRole("textbox", {
      name: `Reason for revoking direct grant for ${roleTarget}`,
    });
    fireEvent.change(reason, { target: { value: "Page two stale retry" } });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );

    await waitFor(() => expect(listUserRoleGrants).toHaveBeenCalledTimes(3));
    expect(screen.getByText("Tenant administrator")).toBeVisible();
    expect(screen.getByText("Page two triage")).toBeVisible();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
    ).toHaveValue("Page two stale retry");
    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();
    expect(listUserRoleGrants).toHaveBeenNthCalledWith(
      3,
      tenantId,
      userId,
      expect.objectContaining({
        after: "grant-page-two",
        includeRevoked: true,
      }),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Page two stale retry" },
      ),
    );
  });

  it("preserves the stale page-two refresh gate through Grant role mode and explicit retry", async () => {
    const firstPageGrant = tenantCreationGrantFixture();
    const staleGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      roleId: "0198c97d-cf4f-7000-8000-000000000051",
      roleKey: "recoverable_page_two",
      roleName: "Recoverable page two",
    });
    const currentGrant = {
      ...staleGrant,
      etag: '"v8-recoverable-page-two"',
      updatedAt: "2026-08-23T11:00:00Z",
      version: 8,
    };
    let current = false;
    let failNextRefresh = true;
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        if (current && failNextRefresh) {
          failNextRefresh = false;
          throw new Error("transient refresh failure");
        }
        return options?.after
          ? { items: [current ? currentGrant : staleGrant] }
          : { items: [firstPageGrant], nextCursor: "grant-page-two" };
      },
    );
    const revokeRoleGrant = vi.fn(async () => {
      if (!current) {
        current = true;
        throw new PhaseTwoApiError("version mismatch", 412);
      }
    });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    const roleTarget = "Recoverable page two (recoverable_page_two)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke direct grant for ${roleTarget}`,
      }),
    );
    const reason = screen.getByRole("textbox", {
      name: `Reason for revoking direct grant for ${roleTarget}`,
    });
    fireEvent.change(reason, {
      target: { value: "Preserve through refresh failure" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: `Retry current grant refresh for ${roleTarget}`,
      }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    ).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Grant role" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));

    const refreshRetry = await screen.findByRole("button", {
      name: `Retry current grant refresh for ${roleTarget}`,
    });
    expect(refreshRetry).toBeEnabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
    ).toHaveValue("Preserve through refresh failure");
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    ).toBeDisabled();

    fireEvent.click(refreshRetry);
    expect(
      await screen.findByText(/We reloaded the current grant/),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: `Retry current grant refresh for ${roleTarget}`,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking direct grant for ${roleTarget}`,
      }),
    ).toHaveValue("Preserve through refresh failure");

    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${roleTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        currentGrant.id,
        currentGrant.etag,
        { reason: "Preserve through refresh failure" },
      ),
    );
  });

  it("renders the persisted revocation reason only for a revoked direct grant", async () => {
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [grantFixture(), revokedGrantFixture()],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(await screen.findByText("Assignment completed")).toBeVisible();
    expect(screen.getAllByText("Revocation reason")).toHaveLength(1);
    expect(screen.getAllByText("Primary incident rotation")).toHaveLength(2);
  });

  it("explains why retired-source and archived-role direct paths no longer grant authority", async () => {
    const retiredBase = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000088",
      roleId: "0198c97d-cf4f-7000-8000-000000000048",
      roleKey: "retired_source_triage",
      roleName: "Retired source triage",
    });
    const retiredGrant = {
      ...retiredBase,
      provenance: {
        ...retiredBase.provenance,
        retiredAt: "2026-08-23T09:00:00Z",
      },
    };
    const archivedBase = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000089",
      roleId: "0198c97d-cf4f-7000-8000-000000000049",
      roleKey: "archived_role_triage",
      roleName: "Archived role triage",
    });
    const archivedGrant = {
      ...archivedBase,
      role: {
        ...archivedBase.role,
        archived: true,
        archivedAt: "2026-08-23T09:30:00Z",
      },
    };
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [retiredGrant, archivedGrant],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    const retiredCard = (
      await screen.findByText("Retired source triage")
    ).closest("article");
    if (!(retiredCard instanceof HTMLElement)) {
      throw new Error("The retired-source direct grant was not rendered.");
    }
    expect(within(retiredCard).getByText("Source retirement")).toBeVisible();
    expect(
      within(retiredCard).getByText(
        /direct path no longer contributes authority because its source is retired/i,
      ),
    ).toBeVisible();
    expect(
      within(retiredCard).getByText(
        /active badge describes only the edge lifecycle/i,
      ),
    ).toBeVisible();

    const archivedCard = screen
      .getByText("Archived role triage")
      .closest("article");
    if (!(archivedCard instanceof HTMLElement)) {
      throw new Error("The archived-role direct grant was not rendered.");
    }
    expect(within(archivedCard).getByText("Role state")).toBeVisible();
    expect(within(archivedCard).getByText("Archived")).toBeVisible();
    expect(
      within(archivedCard).getByText(
        /direct path no longer contributes authority because its role is archived/i,
      ),
    ).toBeVisible();
    expect(
      within(archivedCard).getByText(
        /active badge describes only the edge lifecycle/i,
      ),
    ).toBeVisible();
  });

  it.each(["invited", "suspended"] as const)(
    "distinguishes an active edge from effective authority for a %s membership",
    async (membershipStatus) => {
      const user = { ...userFixture(), membershipStatus };
      renderUsers(
        createPhaseTwoApi({
          getTenantAuthority: async () => authorityFixture(["user.read"]),
          listTenantUsers: async () => ({ items: [user] }),
          listUserRoleGrants: async () => ({ items: [grantFixture()] }),
        }),
      );

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Review access for Ada Target (ada-target@example.invalid)",
        }),
      );
      const card = (await screen.findByText("Custom triage")).closest(
        "article",
      );
      if (!(card instanceof HTMLElement)) {
        throw new Error("The direct grant was not rendered.");
      }

      expect(within(card).getByText("Edge lifecycle")).toBeVisible();
      expect(within(card).getByText("Membership state")).toBeVisible();
      expect(within(card).getByText(membershipStatus)).toBeVisible();
      expect(within(card).getByText("Effective authority")).toBeVisible();
      expect(within(card).getByText("Not contributing")).toBeVisible();
      expect(
        within(card).getByText(
          new RegExp(`tenant membership is ${membershipStatus}`, "i"),
        ),
      ).toBeVisible();
      expect(
        within(card).getByText(
          /active badge describes only the edge lifecycle/i,
        ),
      ).toBeVisible();
    },
  );

  it("distinguishes an active edge from effective authority for a disabled user", async () => {
    const user = {
      ...userFixture(),
      user: { ...userFixture().user, active: false },
    };
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [user] }),
        listUserRoleGrants: async () => ({ items: [grantFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    expect(await screen.findByText("User disabled")).toBeVisible();
    const card = screen.getByText("Custom triage").closest("article");
    if (!(card instanceof HTMLElement)) {
      throw new Error("The disabled user's direct grant was not rendered.");
    }

    expect(within(card).getByText("User state")).toBeVisible();
    expect(within(card).getByText("Disabled")).toBeVisible();
    expect(within(card).getByText("Effective authority")).toBeVisible();
    expect(within(card).getByText("Not contributing")).toBeVisible();
    expect(within(card).getByText(/user is disabled/i)).toBeVisible();
    expect(
      within(card).getByText(/active badge describes only the edge lifecycle/i),
    ).toBeVisible();
  });

  it("updates effective authority when a long-horizon grant expires while open", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const day = 86_400_000;
      vi.setSystemTime(new Date("2026-08-23T10:00:00Z"));
      const grant = grantFixture();
      grant.provenance = {
        ...grant.provenance,
        expiresAt: new Date(Date.now() + 30 * day).toISOString(),
      };
      renderUsers(
        createPhaseTwoApi({
          getTenantAuthority: async () => authorityFixture(["user.read"]),
          listTenantUsers: async () => ({ items: [userFixture()] }),
          listUserRoleGrants: async () => ({ items: [grant] }),
        }),
      );

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Review access for Ada Target (ada-target@example.invalid)",
        }),
      );
      const card = (await screen.findByText("Custom triage")).closest(
        "article",
      );
      if (!(card instanceof HTMLElement)) {
        throw new Error("The expiring direct grant was not rendered.");
      }
      expect(within(card).getByText("Contributing")).toBeVisible();

      await act(() => vi.advanceTimersByTime(25 * day));
      expect(within(card).getByText("Contributing")).toBeVisible();
      await act(() => vi.advanceTimersByTime(5 * day + 1));

      expect(within(card).getByText("Not contributing")).toBeVisible();
      expect(within(card).getByText(/edge has expired/i)).toBeVisible();
    } finally {
      vi.useRealTimers();
    }
  });

  it("offers distinguishable revoke controls only for non-revoked manual-owned grants", async () => {
    const protectedGrant = tenantCreationGrantFixture();
    const manualGrant = grantFixture();
    const expiredGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000083",
      roleId: "0198c97d-cf4f-7000-8000-000000000043",
      roleKey: "expired_triage",
      roleName: "Expired triage",
      state: "expired",
    });
    const secondManualGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000084",
      roleId: "0198c97d-cf4f-7000-8000-000000000044",
      roleKey: "response_lead",
      roleName: "Response lead",
    });
    const revokedFixture = revokedGrantFixture();
    const revokedGrant = {
      ...revokedFixture,
      role: {
        ...revokedFixture.role,
        id: "0198c97d-cf4f-7000-8000-000000000045",
        key: "revoked_triage",
        name: "Revoked triage",
      },
    };
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [
            protectedGrant,
            manualGrant,
            expiredGrant,
            secondManualGrant,
            revokedGrant,
          ],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    const protectedHeading = await screen.findByText("Tenant administrator");
    const protectedCard = protectedHeading.closest("article");
    if (!(protectedCard instanceof HTMLElement)) {
      throw new Error("The tenant-created direct grant was not rendered.");
    }
    expect(protectedCard).toHaveTextContent("tenant creation");
    expect(protectedCard).toHaveTextContent("system");
    expect(protectedCard).toHaveTextContent(
      "Protected tenant recovery administrator.",
    );
    expect(
      within(protectedCard).queryByRole("button", { name: /Revoke/ }),
    ).not.toBeInTheDocument();

    const manualHeading = screen.getByText("Custom triage");
    const manualCard = manualHeading.closest("article");
    if (!(manualCard instanceof HTMLElement)) {
      throw new Error("The manual direct grant was not rendered.");
    }
    expect(manualCard).toHaveTextContent("manual");
    expect(
      within(manualCard).getByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    ).toBeVisible();

    const expiredCard = screen.getByText("Expired triage").closest("article");
    if (!(expiredCard instanceof HTMLElement)) {
      throw new Error("The expired manual direct grant was not rendered.");
    }
    expect(expiredCard).toHaveTextContent("expired");
    expect(
      within(expiredCard).getByRole("button", {
        name: "Revoke direct grant for Expired triage (expired_triage)",
      }),
    ).toBeVisible();

    const revokedCard = screen.getByText("Revoked triage").closest("article");
    if (!(revokedCard instanceof HTMLElement)) {
      throw new Error("The revoked manual direct grant was not rendered.");
    }
    expect(
      within(revokedCard).queryByRole("button", { name: /Revoke/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "Revoke direct grant for Response lead (response_lead)",
      }),
    ).toBeVisible();
    expect(
      screen.getAllByRole("button", {
        name: /^Revoke direct grant for /,
      }),
    ).toHaveLength(3);
  });

  it("uses the explicit ownership capability instead of a manual source kind for direct revocation", async () => {
    const ownedGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000188",
      roleId: "0198c97d-cf4f-7000-8000-000000000048",
      roleKey: "owned_manual",
      roleName: "Owned manual",
    });
    const nonOwnedGrant = {
      ...grantFixture({
        id: "0198c97d-cf4f-7000-8000-000000000189",
        roleId: "0198c97d-cf4f-7000-8000-000000000049",
        roleKey: "non_owned_manual",
        roleName: "Non-owned manual",
      }),
      managedByAuthorizationApi: false,
    };
    const missingOwnershipFixture = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000190",
      roleId: "0198c97d-cf4f-7000-8000-000000000050",
      roleKey: "rolling_manual",
      roleName: "Rolling manual",
    });
    expect(
      Reflect.deleteProperty(
        missingOwnershipFixture,
        "managedByAuthorizationApi",
      ),
    ).toBe(true);

    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [ownedGrant, nonOwnedGrant, missingOwnershipFixture],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Owned manual (owned_manual)",
      }),
    ).toBeVisible();
    for (const target of [
      "Non-owned manual (non_owned_manual)",
      "Rolling manual (rolling_manual)",
    ]) {
      const card = screen
        .getByText(target.split(" (")[0] ?? target)
        .closest("article");
      if (!(card instanceof HTMLElement)) {
        throw new Error(`The ${target} direct grant was not rendered.`);
      }
      expect(within(card).getByText(/^manual$/i)).toBeVisible();
      expect(
        within(card).getByText(
          /Not managed by the authorization API \(source: manual\); direct controls cannot revoke this grant/i,
        ),
      ).toBeVisible();
      expect(
        within(card).queryByRole("button", {
          name: `Revoke direct grant for ${target}`,
        }),
      ).not.toBeInTheDocument();
    }
  });

  it("keeps simultaneous revoke forms distinct when role display names match", async () => {
    const firstGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000086",
      roleId: "0198c97d-cf4f-7000-8000-000000000046",
      roleKey: "shared_triage_a",
      roleName: "Shared triage",
    });
    const secondGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000087",
      roleId: "0198c97d-cf4f-7000-8000-000000000047",
      roleKey: "shared_triage_b",
      roleName: "Shared triage",
    });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({
          items: [firstGrant, secondGrant],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );

    const firstTarget = "Shared triage (shared_triage_a)";
    const secondTarget = "Shared triage (shared_triage_b)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke direct grant for ${firstTarget}`,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Revoke direct grant for ${secondTarget}`,
      }),
    );

    for (const target of [firstTarget, secondTarget]) {
      const revokeGroup = screen.getByRole("group", {
        name: `Revoke direct grant for ${target}`,
      });
      expect(revokeGroup).toBeVisible();
      expect(
        within(revokeGroup).getByRole("textbox", {
          name: `Reason for revoking direct grant for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Confirm revoke direct grant for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Keep grant for ${target}`,
        }),
      ).toBeVisible();
    }
  });

  it("invalidates a second pending revoke when the first triggers authority reload", async () => {
    const firstGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000092",
      roleId: "0198c97d-cf4f-7000-8000-000000000052",
      roleKey: "parallel_triage_a",
      roleName: "Parallel triage A",
    });
    const secondGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000093",
      roleId: "0198c97d-cf4f-7000-8000-000000000053",
      roleKey: "parallel_triage_b",
      roleName: "Parallel triage B",
    });
    const firstMutation = createDeferred<void>();
    const secondMutation = createDeferred<void>();
    const revoked = new Set<string>();
    const listUserRoleGrants = vi.fn(async () => ({
      items: [firstGrant, secondGrant].filter(
        (grant) => !revoked.has(grant.id),
      ),
    }));
    const revokeRoleGrant = vi.fn(
      async (_csrf: string, _tenant: string, grantId: string) => {
        await (grantId === firstGrant.id
          ? firstMutation.promise
          : secondMutation.promise);
        revoked.add(grantId);
      },
    );
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    const firstTarget = "Parallel triage A (parallel_triage_a)";
    const secondTarget = "Parallel triage B (parallel_triage_b)";
    await screen.findByRole("button", {
      name: `Revoke direct grant for ${firstTarget}`,
    });
    for (const target of [firstTarget, secondTarget]) {
      fireEvent.click(
        screen.getByRole("button", {
          name: `Revoke direct grant for ${target}`,
        }),
      );
      fireEvent.change(
        screen.getByRole("textbox", {
          name: `Reason for revoking direct grant for ${target}`,
        }),
        { target: { value: `Revoke ${target}` } },
      );
    }
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${firstTarget}`,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke direct grant for ${secondTarget}`,
      }),
    );
    await waitFor(() => expect(revokeRoleGrant).toHaveBeenCalledTimes(2));

    await act(async () => {
      firstMutation.resolve(undefined);
      await firstMutation.promise;
    });
    expect(
      screen.queryByRole("heading", { name: "Access · Ada Target" }),
    ).not.toBeInTheDocument();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);

    await act(async () => {
      secondMutation.resolve(undefined);
      await secondMutation.promise;
    });
    expect(
      screen.queryByRole("heading", { name: "Access · Ada Target" }),
    ).not.toBeInTheDocument();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);
  });

  it("ignores a pending stale-grant settlement after authority reload", async () => {
    const firstGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000094",
      roleId: "0198c97d-cf4f-7000-8000-000000000054",
      roleKey: "generation_triage_a",
      roleName: "Generation triage A",
    });
    const staleSecondGrant = grantFixture({
      id: "0198c97d-cf4f-7000-8000-000000000095",
      roleId: "0198c97d-cf4f-7000-8000-000000000055",
      roleKey: "generation_triage_b",
      roleName: "Generation triage B",
    });
    const currentSecondGrant = {
      ...staleSecondGrant,
      etag: '"v8-current-generation-b"',
      version: 8,
    };
    const firstMutation = createDeferred<void>();
    const secondMutation = createDeferred<void>();
    let firstRevoked = false;
    let secondCurrent = false;
    const listUserRoleGrants = vi.fn(async () => ({
      items: firstRevoked
        ? [secondCurrent ? currentSecondGrant : staleSecondGrant]
        : [firstGrant, staleSecondGrant],
    }));
    const revokeRoleGrant = vi.fn(
      async (
        _csrf: string,
        _tenant: string,
        grantId: string,
        _etag: string,
      ) => {
        if (grantId === firstGrant.id) {
          await firstMutation.promise;
          firstRevoked = true;
          return;
        }
        if (!secondCurrent) {
          await secondMutation.promise;
          secondCurrent = true;
          throw new PhaseTwoApiError("version mismatch", 412);
        }
      },
    );
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    const firstTarget = "Generation triage A (generation_triage_a)";
    const secondTarget = "Generation triage B (generation_triage_b)";
    await screen.findByRole("button", {
      name: `Revoke direct grant for ${firstTarget}`,
    });
    for (const target of [firstTarget, secondTarget]) {
      fireEvent.click(
        screen.getByRole("button", {
          name: `Revoke direct grant for ${target}`,
        }),
      );
      fireEvent.change(
        screen.getByRole("textbox", {
          name: `Reason for revoking direct grant for ${target}`,
        }),
        { target: { value: `Generation reason for ${target}` } },
      );
      fireEvent.click(
        screen.getByRole("button", {
          name: `Confirm revoke direct grant for ${target}`,
        }),
      );
    }
    await waitFor(() => expect(revokeRoleGrant).toHaveBeenCalledTimes(2));

    await act(async () => {
      firstMutation.resolve(undefined);
      await firstMutation.promise;
    });
    expect(
      screen.queryByRole("heading", { name: "Access · Ada Target" }),
    ).not.toBeInTheDocument();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);

    await act(async () => {
      secondMutation.resolve(undefined);
      await secondMutation.promise;
    });
    expect(
      screen.queryByRole("button", {
        name: `Retry current grant refresh for ${secondTarget}`,
      }),
    ).not.toBeInTheDocument();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);
    expect(revokeRoleGrant).toHaveBeenCalledTimes(2);
  });

  it("invalidates the current session when a grant mutation returns 401", async () => {
    const clearSession = vi.fn();
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [grantFixture()] }),
        revokeRoleGrant: async () => {
          throw new PhaseTwoApiError("expired", 401);
        },
      }),
      clearSession,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
      { target: { value: "Session expired" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("does not launch stale-grant recovery after the dialog unmounts", async () => {
    const mutation = createDeferred<void>();
    const listUserRoleGrants = vi
      .fn()
      .mockResolvedValue({ items: [grantFixture()] });
    const revokeRoleGrant = vi.fn(async () => {
      await mutation.promise;
      throw new PhaseTwoApiError("version mismatch", 412);
    });
    const view = renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
      { target: { value: "Unmount while pending" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    await waitFor(() => expect(revokeRoleGrant).toHaveBeenCalledTimes(1));

    view.unmount();
    await act(async () => {
      mutation.resolve(undefined);
      await mutation.promise;
      await Promise.resolve();
    });

    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);
  });

  it("keeps invited memberships in the tenant projection", async () => {
    const invited = {
      ...userFixture(),
      membershipStatus: "invited" as const,
    };
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [invited] }),
      }),
    );

    expect(await screen.findByText("invited")).toBeVisible();
    expect(screen.getByText("ada-target@example.invalid")).toBeVisible();
  });

  it("never renders old tenant users, grants, or dialog state while the next pair loads", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const nextUsers = createDeferred<{
      items: TenantUserSummaryView[];
    }>();
    const nextUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000072",
      tenantId: nextTenantId,
      user: {
        ...userFixture().user,
        displayName: "Grace Next",
        email: "grace-next@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000073",
      },
    };
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["user.read", "role.read"], [], requestedTenantId),
      listTenantUsers: async (requestedTenantId) =>
        requestedTenantId === tenantId
          ? { items: [userFixture()] }
          : nextUsers.promise,
      listUserRoleGrants: async () => ({ items: [grantFixture()] }),
    });

    render(<SwitchingUsersHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    expect(await screen.findByText("Primary incident rotation")).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-user-tenant"));
    expect(screen.queryByText("Ada Target")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Primary incident rotation"),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("Loading tenant users")).toBeVisible();

    await act(async () => {
      nextUsers.resolve({ items: [nextUser] });
      await nextUsers.promise;
    });
    expect(await screen.findByText("Grace Next")).toBeVisible();
  });

  it("reloads live authority immediately after a successful revoke", async () => {
    const getTenantAuthority = vi
      .fn()
      .mockResolvedValue(
        authorityFixture(["user.read", "role.read", "role.grant"]),
      );
    const listUserRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({ items: [grantFixture()] })
      .mockResolvedValue({ items: [] });
    const revokeRoleGrant = vi.fn().mockResolvedValue(undefined);
    const listTenantUsers = vi.fn(async () => ({ items: [userFixture()] }));
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority,
        listTenantUsers,
        listUserRoleGrants,
        revokeRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke direct grant for Custom triage (custom_triage)",
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Reason for revoking direct grant for Custom triage (custom_triage)",
      }),
      { target: { value: "Assignment completed" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Confirm revoke direct grant for Custom triage (custom_triage)",
      }),
    );

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(listTenantUsers).toHaveBeenCalledTimes(2));
    expect(
      screen.queryByRole("heading", { name: "Access · Ada Target" }),
    ).not.toBeInTheDocument();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(1);
  });

  it("aborts an old A page across an A-to-B-to-A tenant cycle", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const oldPage = createDeferred<{
      items: TenantUserSummaryView[];
    }>();
    const originalUser = userFixture();
    const freshUser = {
      ...userFixture(),
      user: {
        ...userFixture().user,
        displayName: "Fresh A user",
      },
    };
    const staleUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000074",
      user: {
        ...userFixture().user,
        displayName: "Stale A pagination user",
        id: "0198c97d-cf4f-7000-8000-000000000075",
      },
    };
    const nextUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000076",
      tenantId: nextTenantId,
      user: {
        ...userFixture().user,
        displayName: "Tenant B user",
        id: "0198c97d-cf4f-7000-8000-000000000077",
      },
    };
    let aInitialLoads = 0;
    let oldPageSignal: AbortSignal | undefined;
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["user.read", "role.read"], [], requestedTenantId),
      listTenantUsers: async (requestedTenantId, after, signal) => {
        if (requestedTenantId === nextTenantId) {
          return { items: [nextUser] };
        }
        if (after === "cursor-a") {
          oldPageSignal = signal;
          return oldPage.promise;
        }
        aInitialLoads += 1;
        return {
          items: [aInitialLoads === 1 ? originalUser : freshUser],
          nextCursor: "cursor-a",
        };
      },
    });

    render(<SwitchingUsersHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    await waitFor(() => expect(oldPageSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("switch-user-tenant"));
    await waitFor(() => expect(oldPageSignal?.aborted).toBe(true));
    expect(await screen.findByText("Tenant B user")).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-user-original-tenant"));
    expect(await screen.findByText("Fresh A user")).toBeVisible();

    await act(async () => {
      oldPage.resolve({ items: [staleUser] });
      await oldPage.promise;
    });
    expect(
      screen.queryByText("Stale A pagination user"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Fresh A user")).toBeVisible();
  });

  it("fails closed on a non-immediate tenant-user cursor cycle", async () => {
    const secondPageUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000078",
      user: {
        ...userFixture().user,
        displayName: "Second cursor page user",
        id: "0198c97d-cf4f-7000-8000-000000000079",
      },
    };
    const listTenantUsers = vi.fn(async (_tenantId, after?: string) => {
      if (!after) {
        return { items: [userFixture()], nextCursor: "cursor-a" };
      }
      return after === "cursor-a"
        ? { items: [secondPageUser], nextCursor: "cursor-b" }
        : { items: [], nextCursor: "cursor-a" };
    });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    expect(await screen.findByText("Second cursor page user")).toBeVisible();
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );

    expect(
      await screen.findByText("More users could not be loaded"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Load more users" }),
    ).toBeEnabled();
    expect(listTenantUsers).toHaveBeenCalledTimes(3);
  });

  it("loads direct grant history incrementally through page 21 and deduplicates edges", async () => {
    const terminalGrant = {
      ...grantFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000081",
      provenance: {
        ...grantFixture().provenance,
        reason: "Page 21 grant history",
      },
      role: { ...grantFixture().role, name: "Page 21 history role" },
    };
    const listUserRoleGrants = vi.fn(
      async (
        _tenantId: string,
        _userId: string,
        options?: { after?: string },
      ) => {
        const pageNumber = options?.after
          ? Number(options.after.replace("grant-page-", "")) + 1
          : 1;
        return {
          items: pageNumber === 21 ? [terminalGrant] : [grantFixture()],
          ...(pageNumber < 21
            ? { nextCursor: `grant-page-${pageNumber}` }
            : {}),
        };
      },
    );
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    for (let expectedCalls = 2; expectedCalls <= 21; expectedCalls += 1) {
      fireEvent.click(
        // oxlint-disable-next-line no-await-in-loop -- Each click consumes the cursor returned by the preceding page.
        await screen.findByRole("button", {
          name: "Load more grant history",
        }),
      );
      // oxlint-disable-next-line no-await-in-loop -- The next cursor is unavailable until this request settles.
      await waitFor(() =>
        expect(listUserRoleGrants).toHaveBeenCalledTimes(expectedCalls),
      );
    }

    expect(await screen.findByText("Page 21 history role")).toBeVisible();
    expect(screen.getByText("Page 21 grant history")).toBeVisible();
    expect(screen.getAllByText("Primary incident rotation")).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "Load more grant history" }),
    ).not.toBeInTheDocument();
  });

  it("loads delegable role options incrementally through page 21", async () => {
    const terminalRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000041",
      key: "page_21_role",
      name: "Page 21 role option",
    };
    const listTenantRoles = vi.fn(
      async (_tenantId: string, options?: { after?: string }) => {
        const pageNumber = options?.after
          ? Number(options.after.replace("role-page-", "")) + 1
          : 1;
        return {
          items: pageNumber === 21 ? [toRoleSummary(terminalRole)] : [],
          ...(pageNumber < 21 ? { nextCursor: `role-page-${pageNumber}` } : {}),
        };
      },
    );
    const getTenantRole = vi.fn(async () => ({
      etag: '"v3"',
      value: terminalRole,
    }));
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        getTenantRole,
        listTenantRoles,
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    for (let expectedCalls = 2; expectedCalls <= 21; expectedCalls += 1) {
      fireEvent.click(
        // oxlint-disable-next-line no-await-in-loop -- Each click consumes the cursor returned by the preceding page.
        await screen.findByRole("button", { name: "Load more role options" }),
      );
      // oxlint-disable-next-line no-await-in-loop -- The next cursor is unavailable until this request settles.
      await waitFor(() =>
        expect(listTenantRoles).toHaveBeenCalledTimes(expectedCalls),
      );
    }

    fireEvent.click(await screen.findByRole("combobox", { name: "Role" }));
    expect(
      await screen.findByRole("option", {
        name: "Page 21 role option (page_21_role)",
      }),
    ).toBeVisible();
    expect(getTenantRole).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole("button", { name: "Load more role options" }),
    ).not.toBeInTheDocument();
  });

  it.each([
    {
      selectedRoleId: roleFixture().id,
      selectedRoleLabel: "Shared triage (shared_triage_primary)",
    },
    {
      selectedRoleId: "0198c97d-cf4f-7000-8000-000000000052",
      selectedRoleLabel: "Shared triage (shared_triage_secondary)",
    },
  ])(
    "submits the role ID for duplicate-name choice $selectedRoleLabel",
    async ({ selectedRoleId, selectedRoleLabel }) => {
      const firstRole = {
        ...roleFixture(),
        key: "shared_triage_primary",
        name: "Shared triage",
      };
      const secondRole = {
        ...roleFixture(),
        id: "0198c97d-cf4f-7000-8000-000000000052",
        key: "shared_triage_secondary",
        name: "Shared triage",
      };
      const roles = new Map([
        [firstRole.id, firstRole],
        [secondRole.id, secondRole],
      ]);
      const grantUserRole = vi
        .fn()
        .mockResolvedValue({ etag: '"v1"', value: grantFixture() });
      renderUsers(
        createPhaseTwoApi({
          getTenantAuthority: async () =>
            authorityFixture(["user.read", "role.read", "role.grant"]),
          getTenantRole: async (_tenantId, roleId) => ({
            etag: '"v3"',
            value: roles.get(roleId) ?? firstRole,
          }),
          grantUserRole,
          listTenantRoles: async () => ({
            items: [toRoleSummary(firstRole), toRoleSummary(secondRole)],
          }),
          listTenantUsers: async () => ({ items: [userFixture()] }),
          listUserRoleGrants: async () => ({ items: [] }),
        }),
      );

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Review access for Ada Target (ada-target@example.invalid)",
        }),
      );
      fireEvent.click(
        await screen.findByRole("button", { name: "Grant role" }),
      );
      fireEvent.click(await screen.findByRole("combobox", { name: "Role" }));

      expect(
        await screen.findByRole("option", {
          name: "Shared triage (shared_triage_primary)",
        }),
      ).toBeVisible();
      expect(
        screen.getByRole("option", {
          name: "Shared triage (shared_triage_secondary)",
        }),
      ).toBeVisible();
      fireEvent.click(screen.getByRole("option", { name: selectedRoleLabel }));
      fireEvent.change(screen.getByRole("textbox", { name: "Reason" }), {
        target: { value: "Qualified duplicate role" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Grant role" }));

      await waitFor(() =>
        expect(grantUserRole).toHaveBeenCalledWith(
          sessionFixture.csrfToken,
          tenantId,
          userId,
          expect.any(String),
          {
            reason: "Qualified duplicate role",
            roleId: selectedRoleId,
          },
        ),
      );
    },
  );

  it("omits a role archived between its list summary and detail response", async () => {
    const activeRole = roleFixture();
    const archivedRole = {
      ...activeRole,
      archived: true,
      archivedAt: "2026-08-23T10:01:00Z",
      updatedAt: "2026-08-23T10:01:00Z",
      version: activeRole.version + 1,
    };
    const getTenantRole = vi.fn(async () => ({
      etag: '"v4"',
      value: archivedRole,
    }));
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        getTenantRole,
        listTenantRoles: async () => ({
          items: [toRoleSummary(activeRole)],
        }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));

    expect(
      await screen.findByText(
        "No active role fits your live delegation ceiling.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("combobox", { name: "Role" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Grant role" })).toBeDisabled();
    expect(getTenantRole).toHaveBeenCalledTimes(1);
  });

  it("drops stale grant-history pagination across an A-to-B-to-A tenant cycle", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const nextUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000076",
      tenantId: nextTenantId,
      user: {
        ...userFixture().user,
        displayName: "Tenant B user",
        id: "0198c97d-cf4f-7000-8000-000000000077",
      },
    };
    const freshGrant = {
      ...grantFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000082",
      role: { ...grantFixture().role, name: "Fresh A grant" },
    };
    const staleGrant = {
      ...grantFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000083",
      role: { ...grantFixture().role, name: "Stale A pagination grant" },
    };
    const oldGrantPage = createDeferred<{
      items: DirectUserRoleGrantView[];
      nextCursor?: string;
    }>();
    let aInitialLoads = 0;
    let staleSignal: AbortSignal | undefined;
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["user.read", "role.read"], [], requestedTenantId),
      listTenantUsers: async (requestedTenantId) => ({
        items: [requestedTenantId === nextTenantId ? nextUser : userFixture()],
      }),
      listUserRoleGrants: async (
        requestedTenantId,
        _requestedUserId,
        options,
      ) => {
        if (requestedTenantId === nextTenantId) {
          return { items: [] };
        }
        if (options?.after === "grant-cursor-a") {
          staleSignal = options.signal;
          return oldGrantPage.promise;
        }
        aInitialLoads += 1;
        return aInitialLoads === 1
          ? { items: [grantFixture()], nextCursor: "grant-cursor-a" }
          : { items: [freshGrant] };
      },
    });

    render(<SwitchingUsersHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );
    await waitFor(() => expect(staleSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("switch-user-tenant"));
    await waitFor(() => expect(staleSignal?.aborted).toBe(true));
    expect(await screen.findByText("Tenant B user")).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-user-original-tenant"));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    expect(await screen.findByText("Fresh A grant")).toBeVisible();

    await act(async () => {
      oldGrantPage.resolve({ items: [staleGrant] });
      await oldGrantPage.promise;
    });
    expect(
      screen.queryByText("Stale A pagination grant"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Fresh A grant")).toBeVisible();
  });

  it("drops stale role-option pagination across an A-to-B-to-A tenant cycle", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const nextUser = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000076",
      tenantId: nextTenantId,
      user: {
        ...userFixture().user,
        displayName: "Tenant B user",
        id: "0198c97d-cf4f-7000-8000-000000000077",
      },
    };
    const freshRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000042",
      key: "fresh_a_role",
      name: "Fresh A role option",
    };
    const staleRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000043",
      key: "stale_a_role",
      name: "Stale A pagination role",
    };
    const oldRolePage = createDeferred<{
      items: ReturnType<typeof toRoleSummary>[];
      nextCursor?: string;
    }>();
    let aInitialLoads = 0;
    let staleSignal: AbortSignal | undefined;
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(
          ["user.read", "role.read", "role.grant"],
          [],
          requestedTenantId,
        ),
      getTenantRole: async (_requestedTenantId, roleId) => ({
        etag: '"v3"',
        value: roleId === staleRole.id ? staleRole : freshRole,
      }),
      listTenantRoles: async (requestedTenantId, options) => {
        if (requestedTenantId === nextTenantId) {
          return { items: [] };
        }
        if (options?.after === "role-cursor-a") {
          staleSignal = options.signal;
          return oldRolePage.promise;
        }
        aInitialLoads += 1;
        return aInitialLoads === 1
          ? { items: [], nextCursor: "role-cursor-a" }
          : { items: [toRoleSummary(freshRole)] };
      },
      listTenantUsers: async (requestedTenantId) => ({
        items: [requestedTenantId === nextTenantId ? nextUser : userFixture()],
      }),
      listUserRoleGrants: async () => ({ items: [] }),
    });

    render(<SwitchingUsersHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more role options" }),
    );
    await waitFor(() => expect(staleSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("switch-user-tenant"));
    await waitFor(() => expect(staleSignal?.aborted).toBe(true));
    expect(await screen.findByText("Tenant B user")).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-user-original-tenant"));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    fireEvent.click(await screen.findByRole("combobox", { name: "Role" }));
    expect(
      await screen.findByRole("option", {
        name: "Fresh A role option (fresh_a_role)",
      }),
    ).toBeVisible();

    await act(async () => {
      oldRolePage.resolve({ items: [toRoleSummary(staleRole)] });
      await oldRolePage.promise;
    });
    expect(
      screen.queryByRole("option", {
        name: "Stale A pagination role (stale_a_role)",
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("option", {
        name: "Fresh A role option (fresh_a_role)",
      }),
    ).toBeVisible();
  });

  it("fails closed on a cycling direct-grant cursor and leaves retry available", async () => {
    const listUserRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({ items: [], nextCursor: "grant-loop" })
      .mockResolvedValue({ items: [], nextCursor: "grant-loop" });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["user.read"]),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more grant history" }),
    );

    expect(
      await screen.findByText("More grant history could not be loaded"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Load more grant history" }),
    ).toBeEnabled();
    expect(listUserRoleGrants).toHaveBeenCalledTimes(2);
  });

  it("fails closed on a cycling role cursor and leaves retry available", async () => {
    const listTenantRoles = vi
      .fn()
      .mockResolvedValueOnce({ items: [], nextCursor: "role-loop" })
      .mockResolvedValue({ items: [], nextCursor: "role-loop" });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["user.read", "role.read", "role.grant"]),
        listTenantRoles,
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more role options" }),
    );

    expect(
      await screen.findByText("More role options could not be loaded"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Load more role options" }),
    ).toBeEnabled();
    expect(listTenantRoles).toHaveBeenCalledTimes(2);
  });

  it("reuses a grant key for an exact retry, rotates it after edits, and accepts the exact ceiling", async () => {
    const horizon = "2099-08-23T12:00:00Z";
    const role = roleFixture();
    role.policy = {
      delegationCeiling: [],
      permissions: [{ permissionKey: "role.read", scope: "tenant" }],
    };
    const delegation = [
      {
        delegableUntil: horizon,
        permissionKey: "role.read" as const,
        scope: "tenant" as const,
      },
    ];
    const getTenantAuthority = vi
      .fn()
      .mockResolvedValue(
        authorityFixture(["user.read", "role.read", "role.grant"], delegation),
      );
    const grantUserRole = vi
      .fn()
      .mockRejectedValueOnce(new Error("first transport failure"))
      .mockRejectedValueOnce(new Error("same retry failure"))
      .mockResolvedValueOnce({ etag: '"v1"', value: grantFixture() });
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantRole: async () => ({ etag: '"v3"', value: role }),
        grantUserRole,
        listTenantRoles: async () => ({ items: [toRoleSummary(role)] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    const roleSelect = await screen.findByRole("combobox", { name: "Role" });
    fireEvent.click(roleSelect);
    fireEvent.click(
      await screen.findByRole("option", {
        name: "Custom triage (custom_triage)",
      }),
    );
    const expiry = screen.getByLabelText("Grant expiry");
    const exactLocalCeiling = expiry.getAttribute("max");
    expect(exactLocalCeiling).toBeTruthy();
    fireEvent.change(expiry, { target: { value: exactLocalCeiling } });
    const reason = screen.getByRole("textbox", { name: "Reason" });
    fireEvent.change(reason, { target: { value: "Primary\u0085rotation" } });
    const submit = screen.getByRole("button", { name: "Grant role" });

    fireEvent.click(submit);
    expect(
      await screen.findByText("Use a reason without control characters."),
    ).toBeVisible();
    expect(grantUserRole).not.toHaveBeenCalled();

    fireEvent.change(reason, { target: { value: "Primary rotation" } });

    fireEvent.click(submit);
    await waitFor(() => expect(grantUserRole).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(submit).toBeEnabled());
    fireEvent.click(submit);
    await waitFor(() => expect(grantUserRole).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(submit).toBeEnabled());
    fireEvent.change(reason, { target: { value: "Secondary rotation" } });
    fireEvent.click(submit);
    await waitFor(() => expect(grantUserRole).toHaveBeenCalledTimes(3));

    const firstKey = grantUserRole.mock.calls[0]?.[3];
    const retryKey = grantUserRole.mock.calls[1]?.[3];
    const changedKey = grantUserRole.mock.calls[2]?.[3];
    expect(firstKey).toBe(retryKey);
    expect(changedKey).not.toBe(firstKey);
    expect(grantUserRole.mock.calls[0]?.[4]).toEqual({
      expiresAt: new Date(horizon).toISOString(),
      reason: "Primary rotation",
      roleId: role.id,
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
  });

  it("retries an exactly bound grant after its expiry but rejects an unbound past-expiry edit", async () => {
    const horizon = "2099-08-23T12:00:00Z";
    const role = roleFixture();
    role.policy = {
      delegationCeiling: [],
      permissions: [{ permissionKey: "role.read", scope: "tenant" }],
    };
    const grantUserRole = vi
      .fn()
      .mockRejectedValue(new Error("transport outcome is unknown"));
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(
            ["user.read", "role.read", "role.grant"],
            [
              {
                delegableUntil: horizon,
                permissionKey: "role.read",
                scope: "tenant",
              },
            ],
          ),
        getTenantRole: async () => ({ etag: '"v3"', value: role }),
        grantUserRole,
        listTenantRoles: async () => ({ items: [toRoleSummary(role)] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review access for Ada Target (ada-target@example.invalid)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Grant role" }));
    fireEvent.click(await screen.findByRole("combobox", { name: "Role" }));
    fireEvent.click(
      await screen.findByRole("option", {
        name: "Custom triage (custom_triage)",
      }),
    );
    const expiry = screen.getByLabelText("Grant expiry");
    fireEvent.change(expiry, { target: { value: horizon.slice(0, 19) } });
    const reason = screen.getByRole("textbox", { name: "Reason" });
    fireEvent.change(reason, { target: { value: "Bound retry" } });
    const submit = screen.getByRole("button", { name: "Grant role" });

    fireEvent.click(submit);
    await waitFor(() => expect(grantUserRole).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(submit).toBeEnabled());
    vi.spyOn(Date, "now").mockReturnValue(Date.parse(horizon) + 1_000);
    fireEvent.click(submit);
    await waitFor(() => expect(grantUserRole).toHaveBeenCalledTimes(2));

    expect(grantUserRole.mock.calls[1]?.[3]).toBe(
      grantUserRole.mock.calls[0]?.[3],
    );
    expect(grantUserRole.mock.calls[1]?.[4]).toEqual(
      grantUserRole.mock.calls[0]?.[4],
    );
    await waitFor(() => expect(submit).toBeEnabled());
    fireEvent.change(reason, { target: { value: "Unbound past edit" } });
    fireEvent.click(submit);
    expect(
      await screen.findByText("Choose a future grant expiry."),
    ).toBeVisible();
    expect(grantUserRole).toHaveBeenCalledTimes(2);
  });

  it("bounds a role grant by the earliest horizon across grants and delegation", () => {
    const role = roleFixture();
    role.policy = {
      delegationCeiling: [{ permissionKey: "user.read", scope: "tenant" }],
      permissions: [{ permissionKey: "role.read", scope: "tenant" }],
    };

    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: "2099-08-24T12:00:00Z",
          permissionKey: "role.read",
          scope: "tenant",
        },
        {
          delegableUntil: "2099-08-23T12:00:00Z",
          permissionKey: "user.read",
          scope: "tenant",
        },
      ]),
    ).toEqual({
      delegableUntil: "2099-08-23T12:00:00Z",
      role,
    });
    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: "2099-08-23T12:00:00.123456789Z",
          permissionKey: "role.read",
          scope: "tenant",
        },
        {
          delegableUntil: "2099-08-23T12:00:00.123456788Z",
          permissionKey: "user.read",
          scope: "tenant",
        },
      ]),
    ).toEqual({
      delegableUntil: "2099-08-23T12:00:00.123456788Z",
      role,
    });
    expect(
      deriveDelegableRoleChoice(role, [
        { permissionKey: "role.read", scope: "tenant" },
      ]),
    ).toBeNull();

    const nearHorizon = new Date(Date.now() + 30_000).toISOString();
    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: nearHorizon,
          permissionKey: "role.read",
          scope: "tenant",
        },
        {
          delegableUntil: nearHorizon,
          permissionKey: "user.read",
          scope: "tenant",
        },
      ]),
    ).toEqual({ delegableUntil: nearHorizon, role });
  });

  it("fails closed on malformed or expired delegation horizons and accepts exact nanosecond instants", () => {
    const role = roleFixture();
    role.policy = {
      delegationCeiling: [],
      permissions: [{ permissionKey: "role.read", scope: "tenant" }],
    };
    const valid = {
      delegableUntil: "2099-08-23T15:30:00+02:30",
      permissionKey: "role.read" as const,
      scope: "tenant" as const,
    };

    for (const malformed of [
      "2099-02-29T12:00:00Z",
      "2099-08-23T12:00:00",
      "2099-08-23T12:00:00.1234567891Z",
      "2099-08-23T12:00:00+24:00",
    ]) {
      expect(
        deriveDelegableRoleChoice(role, [
          valid,
          {
            delegableUntil: malformed,
            permissionKey: "user.read",
            scope: "tenant",
          },
        ]),
      ).toBeNull();
    }

    const now = vi
      .spyOn(Date, "now")
      .mockReturnValue(Date.parse("2099-08-23T12:00:00Z"));
    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: "2099-08-23T13:59:59+02:00",
          permissionKey: "role.read",
          scope: "tenant",
        },
      ]),
    ).toBeNull();
    expect(deriveDelegableRoleChoice(role, [valid])).toEqual({
      delegableUntil: valid.delegableUntil,
      role,
    });

    now.mockReturnValue(Date.parse("2099-08-23T12:00:00.123Z"));
    const subMillisecondHorizon = "2099-08-23T12:00:00.123000001Z";
    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: subMillisecondHorizon,
          permissionKey: "role.read",
          scope: "tenant",
        },
      ]),
    ).toEqual({ delegableUntil: subMillisecondHorizon, role });

    const nanosecondHorizon = "2099-08-23T12:00:00.123456789Z";
    expect(
      deriveDelegableRoleChoice(role, [
        {
          delegableUntil: nanosecondHorizon,
          permissionKey: "role.read",
          scope: "tenant",
        },
      ]),
    ).toEqual({ delegableUntil: nanosecondHorizon, role });
  });

  it("shows source-qualified inherited group paths for the signed-in user", async () => {
    const currentUser = {
      ...userFixture(),
      user: {
        ...userFixture().user,
        displayName: sessionFixture.user.displayName,
        email: sessionFixture.user.email,
        id: sessionFixture.user.id,
      },
    };
    const authority = authorityFixture(["user.read"]);
    authority.roleGrants = [
      {
        effectiveExpiresAt: "2099-08-24T12:00:00Z",
        grantId: "0198c97d-cf4f-7000-8000-000000000181",
        path: {
          group: {
            group: {
              id: "0198c97d-cf4f-7000-8000-000000000182",
              key: "ir_leads",
              name: "IR leads",
            },
            membershipEdge: {
              id: "0198c97d-cf4f-7000-8000-000000000183",
              provenance: {
                authoritative: false,
                grantedAt: "2026-08-22T10:00:00Z",
                reason: "Manual membership path",
                sourceId: "0198c97d-cf4f-7000-8000-000000000184",
                sourceKind: "manual",
              },
            },
            roleGrantEdge: {
              id: "0198c97d-cf4f-7000-8000-000000000185",
              provenance: {
                authoritative: true,
                grantedAt: "2026-08-22T10:00:00Z",
                reason: "Mapped role path",
                sourceId: "0198c97d-cf4f-7000-8000-000000000186",
                sourceKind: "identity_mapping",
              },
            },
          },
          pathType: "group",
        },
        provenance: {
          authoritative: true,
          grantedAt: "2026-08-22T10:00:00Z",
          reason: "Compatible group projection",
          sourceId: "0198c97d-cf4f-7000-8000-000000000182",
          sourceKind: "identity_mapping",
          sourceType: "group",
        },
        roleId: "0198c97d-cf4f-7000-8000-000000000040",
        roleKey: "custom_triage",
        roleName: "Custom triage",
      },
    ];
    renderUsers(
      createPhaseTwoApi({
        getTenantAuthority: async () => authority,
        listTenantUsers: async () => ({ items: [currentUser] }),
        listUserRoleGrants: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Review access for ${sessionFixture.user.displayName} (${sessionFixture.user.email})`,
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Security-group access paths",
      }),
    ).toBeVisible();
    expect(
      screen.getByLabelText("Two-edge access path through IR leads"),
    ).toBeVisible();
    expect(screen.getByText("Manual membership path")).toBeVisible();
    expect(screen.getByText("Mapped role path")).toBeVisible();
    expect(screen.getByText("identity mapping")).toBeVisible();
  });

  it("keys parallel source-qualified group paths by both authority edges", () => {
    const sharedRoleGrantId = "0198c97d-cf4f-7000-8000-000000000185";
    const manualPath = groupAuthorityGrantFixture({
      grantId: sharedRoleGrantId,
      membershipId: "0198c97d-cf4f-7000-8000-000000000183",
      membershipReason: "Manual membership path",
      membershipSourceId: "0198c97d-cf4f-7000-8000-000000000184",
      membershipSourceKind: "manual",
    });
    const mappedPath = groupAuthorityGrantFixture({
      grantId: sharedRoleGrantId,
      membershipId: "0198c97d-cf4f-7000-8000-000000000187",
      membershipReason: "Provider membership path",
      membershipSourceId: "0198c97d-cf4f-7000-8000-000000000188",
      membershipSourceKind: "identity_mapping",
    });
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);

    const { rerender } = render(
      <InheritedGroupPaths grants={[manualPath, mappedPath]} />,
    );

    expect(effectiveAuthorityPathKey(manualPath)).not.toBe(
      effectiveAuthorityPathKey(mappedPath),
    );
    expect(screen.getByText("Manual membership path")).toBeVisible();
    expect(screen.getByText("Provider membership path")).toBeVisible();
    expect(
      consoleError.mock.calls.some((arguments_) =>
        arguments_.join(" ").includes("same key"),
      ),
    ).toBe(false);

    rerender(<InheritedGroupPaths grants={[mappedPath]} />);

    expect(
      screen.queryByText("Manual membership path"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Provider membership path")).toBeVisible();
    expect(screen.getAllByText("Mapped role path")).toHaveLength(1);
  });

  it("deduplicates cursor pages by tenant membership id", () => {
    const original = userFixture();
    const updated = { ...original, membershipStatus: "suspended" as const };
    const second = {
      ...original,
      membershipId: "membership-two",
      user: { ...original.user, id: "user-two" },
    };

    expect(mergeTenantUsers([original], [updated, second])).toEqual([
      updated,
      second,
    ]);
  });
});

function renderUsers(
  api: ReturnType<typeof createPhaseTwoApi>,
  clearSession = vi.fn(),
  showAuthorityReload = false,
): ReturnType<typeof render> {
  const session = { ...sessionFixture, activeTenantId: tenantId };
  return render(
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
        <TenantUsersPage />
        {showAuthorityReload ? <UserAuthorityReloadControl /> : null}
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function UserAuthorityReloadControl(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button
      data-testid="reload-user-authority"
      type="button"
      onClick={authority.reload}
    >
      Reload user authority
    </button>
  );
}

function SwitchingUsersHarness({
  api,
  nextTenantId,
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
  nextTenantId: string;
}): React.JSX.Element {
  const [activeTenantId, setActiveTenantId] = useState(tenantId);
  const session = { ...sessionFixture, activeTenantId };
  return (
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
      <TenantAuthorityProvider>
        <TenantUsersPage />
        <button
          data-testid="switch-user-tenant"
          type="button"
          onClick={() => setActiveTenantId(nextTenantId)}
        >
          Switch user tenant
        </button>
        <button
          data-testid="switch-user-original-tenant"
          type="button"
          onClick={() => setActiveTenantId(tenantId)}
        >
          Switch original user tenant
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function authorityFixture(
  keys: TenantAuthorityView["permissions"][number]["permissionKey"][],
  delegation: TenantAuthorityView["delegationCeiling"] = [],
  authorityTenantId = tenantId,
): TenantAuthorityView {
  return {
    delegationCeiling: delegation,
    evaluatedAt: "2026-08-23T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: keys.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: authorityTenantId,
    userId: sessionFixture.user.id,
  };
}

function toRoleSummary(role: TenantRoleView) {
  const { policy: _policy, ...summary } = role;
  return summary;
}

function userFixture(): TenantUserSummaryView {
  return {
    createdAt: "2026-08-20T10:00:00Z",
    etag: '"v1"',
    legacyMembershipRole: "analyst",
    lifecycleRevision: 1,
    membershipId: "0198c97d-cf4f-7000-8000-000000000071",
    membershipStatus: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    user: {
      active: true,
      displayName: "Ada Target",
      email: "ada-target@example.invalid",
      id: userId,
    },
  };
}

function roleFixture(): TenantRoleView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    id: "0198c97d-cf4f-7000-8000-000000000040",
    key: "custom_triage",
    name: "Custom triage",
    policy: { delegationCeiling: [], permissions: [] },
    principalKind: "human",
    system: false,
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
  };
}

function grantFixture({
  id = "0198c97d-cf4f-7000-8000-000000000080",
  roleId,
  roleKey,
  roleName,
  state = "active",
}: {
  id?: string;
  roleId?: string;
  roleKey?: string;
  roleName?: string;
  state?: DirectUserRoleGrantView["state"];
} = {}): DirectUserRoleGrantView {
  const { policy: _policy, ...role } = roleFixture();
  return {
    etag: directGrantEtag,
    id,
    managedByAuthorizationApi: true,
    pathType: "direct",
    provenance: {
      authoritative: false,
      expiresAt:
        state === "expired" ? "2026-08-22T12:00:00Z" : "2099-08-23T12:00:00Z",
      grantedAt: "2026-08-22T10:00:00Z",
      grantedByUserId: sessionFixture.user.id,
      reason: "Primary incident rotation",
      sourceId: "0198c97d-cf4f-7000-8000-000000000080",
      sourceKind: "manual",
      sourceType: "direct",
    },
    role: {
      ...role,
      ...(roleId ? { id: roleId } : {}),
      ...(roleKey ? { key: roleKey } : {}),
      ...(roleName ? { name: roleName } : {}),
    },
    state,
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    userId,
    version: 7,
  };
}

function revokedGrantFixture(): DirectUserRoleGrantView {
  return {
    ...grantFixture(),
    etag: `"v8-${"R".repeat(43)}"`,
    id: "0198c97d-cf4f-7000-8000-000000000081",
    revokeReason: "Assignment completed",
    revokedAt: "2026-08-23T10:30:00Z",
    revokedByUserId: sessionFixture.user.id,
    state: "revoked",
    updatedAt: "2026-08-23T10:30:00Z",
    version: 8,
  };
}

function tenantCreationGrantFixture(): DirectUserRoleGrantView {
  const grant = grantFixture();
  const { expiresAt: _expiresAt, ...provenance } = grant.provenance;
  return {
    ...grant,
    id: "0198c97d-cf4f-7000-8000-000000000082",
    managedByAuthorizationApi: false,
    provenance: {
      ...provenance,
      reason: "Protected tenant recovery administrator.",
      sourceKind: "tenant_creation",
      sourceType: "system",
    },
    role: {
      ...grant.role,
      id: "0198c97d-cf4f-7000-8000-000000000042",
      key: "tenant_admin",
      name: "Tenant administrator",
      system: true,
    },
  };
}

function groupAuthorityGrantFixture({
  grantId,
  membershipId,
  membershipReason,
  membershipSourceId,
  membershipSourceKind,
}: {
  grantId: string;
  membershipId: string;
  membershipReason: string;
  membershipSourceId: string;
  membershipSourceKind: "identity_mapping" | "manual";
}): EffectiveTenantRoleGrantView {
  return {
    effectiveExpiresAt: "2099-08-24T12:00:00Z",
    grantId,
    path: {
      group: {
        group: {
          id: "0198c97d-cf4f-7000-8000-000000000182",
          key: "ir_leads",
          name: "IR leads",
        },
        membershipEdge: {
          id: membershipId,
          provenance: {
            authoritative: membershipSourceKind === "identity_mapping",
            grantedAt: "2026-08-22T10:00:00Z",
            reason: membershipReason,
            sourceId: membershipSourceId,
            sourceKind: membershipSourceKind,
          },
        },
        roleGrantEdge: {
          id: grantId,
          provenance: {
            authoritative: true,
            grantedAt: "2026-08-22T10:00:00Z",
            reason: "Mapped role path",
            sourceId: "0198c97d-cf4f-7000-8000-000000000186",
            sourceKind: "identity_mapping",
          },
        },
      },
      pathType: "group",
    },
    provenance: {
      authoritative: true,
      grantedAt: "2026-08-22T10:00:00Z",
      reason: "Compatible group projection",
      sourceId: "0198c97d-cf4f-7000-8000-000000000182",
      sourceKind: "identity_mapping",
      sourceType: "group",
    },
    roleId: roleFixture().id,
    roleKey: roleFixture().key,
    roleName: roleFixture().name,
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
