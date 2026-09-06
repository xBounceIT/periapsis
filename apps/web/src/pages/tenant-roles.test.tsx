import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
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
  type TenantAuthorityView,
  type TenantPermissionView,
  type TenantRoleSummaryView,
  type TenantRoleView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TenantRolesPage } from "./tenant-roles";
import { mergeTenantRoles } from "./tenant-roles-model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const roleId = "0198c97d-cf4f-7000-8000-000000000040";

afterEach(cleanup);

describe("TenantRolesPage", () => {
  it("keeps initial authority pending and clears ready role state before a read-permission loss settles", async () => {
    const role = roleFixture();
    const initialAuthority = createDeferred<TenantAuthorityView>();
    const deniedAuthority = createDeferred<TenantAuthorityView>();
    const delayedPage = createDeferred<{
      items: TenantRoleSummaryView[];
    }>();
    const delayedDetail = createDeferred<{
      etag: string;
      value: TenantRoleView;
    }>();
    let paginationSignal: AbortSignal | undefined;
    let detailSignal: AbortSignal | undefined;
    const getTenantAuthority = vi
      .fn()
      .mockImplementationOnce(async () => initialAuthority.promise)
      .mockImplementationOnce(async () => deniedAuthority.promise);
    const listTenantRoles = vi.fn(
      async (
        _requestedTenantId: string,
        options?: { after?: string; signal?: AbortSignal },
      ) => {
        if (options?.after === "role-page-two") {
          paginationSignal = options.signal;
          return delayedPage.promise;
        }
        return { items: [toSummary(role)], nextCursor: "role-page-two" };
      },
    );
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantRole: async (_requestedTenantId, _requestedRoleId, signal) => {
          detailSignal = signal;
          return delayedDetail.promise;
        },
        listTenantRoles,
      }),
      vi.fn(),
      true,
    );

    expect(screen.getByLabelText("Loading tenant roles")).toBeVisible();
    expect(listTenantRoles).not.toHaveBeenCalled();
    await act(async () => {
      initialAuthority.resolve(authorityFixture(["role.read"]));
      await initialAuthority.promise;
    });
    const open = await screen.findByRole("button", {
      name: "View role Custom triage (custom_triage)",
    });
    fireEvent.click(screen.getByRole("button", { name: "Load more roles" }));
    await waitFor(() => expect(paginationSignal).toBeDefined());
    fireEvent.click(open);
    await screen.findByRole("dialog");
    await waitFor(() => expect(detailSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("reload-role-authority"));
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(paginationSignal?.aborted).toBe(true);
    expect(detailSignal?.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    ).not.toBeInTheDocument();

    await act(async () => {
      delayedPage.resolve({
        items: [
          toSummary({
            ...role,
            id: "0198c97d-cf4f-7000-8000-000000000199",
            key: "late_role",
            name: "Late role",
          }),
        ],
      });
      delayedDetail.resolve({ etag: '"v3"', value: role });
      await Promise.all([delayedPage.promise, delayedDetail.promise]);
    });
    expect(screen.queryByText("Late role")).not.toBeInTheDocument();

    await act(async () => {
      deniedAuthority.resolve(authorityFixture([]));
      await deniedAuthority.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantRoles).toHaveBeenCalledTimes(2);
  });

  it("requests a direct route and safely renders a server 403", async () => {
    const listTenantRoles = vi
      .fn()
      .mockRejectedValue(
        new PhaseTwoApiError("sensitive server policy detail", 403),
      );
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["role.read"]),
        listTenantRoles,
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantRoles).toHaveBeenCalledWith(
      tenantId,
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(
      screen.queryByText("sensitive server policy detail"),
    ).not.toBeInTheDocument();
  });

  it("keeps role actions distinguishable when display names are duplicated", async () => {
    const primary = { ...roleFixture(), name: "Response coordinator" };
    const secondary = {
      ...primary,
      id: "0198c97d-cf4f-7000-8000-000000000041",
      key: "response_coordinator_secondary",
    };
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["role.read"]),
        listTenantRoles: async () => ({
          items: [toSummary(primary), toSummary(secondary)],
        }),
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: "View role Response coordinator (custom_triage)",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "View role Response coordinator (response_coordinator_secondary)",
      }),
    ).toBeVisible();
  });

  it("exposes a labelled exact-scope matrix and keeps delegation subordinate", async () => {
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        listTenantPermissions: async () => ({
          items: [
            {
              allowedScopes: ["tenant"],
              description: "Read role definitions.",
              id: "0198c97d-cf4f-7000-8000-000000000060",
              key: "role.read",
              name: "Read roles",
              principalTypes: ["human"],
            },
          ],
        }),
        listTenantRoles: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create custom role" }),
    );
    expect(
      screen.getByRole("group", { name: "Exact permission and scope policy" }),
    ).toBeVisible();
    const grant = screen.getByRole("checkbox", {
      name: "Grant role · read at tenant scope",
    });
    const delegate = screen.getByRole("checkbox", {
      name: "Delegate role · read at tenant scope",
    });
    expect(delegate).toBeDisabled();
    grant.focus();
    expect(grant).toHaveFocus();
    fireEvent.click(grant);
    expect(grant).toBeChecked();
    expect(delegate).toBeEnabled();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Create custom role" }),
      ).not.toBeInTheDocument(),
    );
  });

  it("fails closed when the bounded permission catalog enters a non-immediate cursor cycle", async () => {
    const listTenantPermissions = vi.fn(
      async (_tenantId: string, cursor?: string) => ({
        items: [roleReadPermission()],
        nextCursor:
          cursor === undefined
            ? "permission-a"
            : cursor === "permission-a"
              ? "permission-b"
              : "permission-a",
      }),
    );
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        listTenantPermissions,
        listTenantRoles: async () => ({ items: [] }),
      }),
    );

    expect(
      await screen.findByText(/permission catalog could not be loaded/i),
    ).toBeVisible();
    expect(listTenantPermissions).toHaveBeenCalledTimes(3);
    expect(listTenantPermissions.mock.calls.map((call) => call[1])).toEqual([
      undefined,
      "permission-a",
      "permission-b",
    ]);
    expect(
      screen.queryByRole("button", { name: "Create custom role" }),
    ).not.toBeInTheDocument();
  });

  it("refreshes a metadata-only 412 in place and retries the preserved draft with the current ETag", async () => {
    const role = roleFixture();
    const refreshedRole = {
      ...role,
      description: "Concurrent server description",
      name: "Server triage",
      updatedAt: "2026-08-23T10:15:00Z",
      version: 4,
    };
    const savedRole = {
      ...refreshedRole,
      name: "Edited triage",
      updatedAt: "2026-08-23T10:30:00Z",
      version: 5,
    };
    const updateTenantRole = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce({ etag: '"v5"', value: savedRole });
    const getTenantRole = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: role })
      .mockResolvedValueOnce({ etag: '"v4"', value: refreshedRole });
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole,
        listTenantPermissions: async () => ({
          items: [
            {
              allowedScopes: ["tenant"],
              description: "Read role definitions.",
              id: "0198c97d-cf4f-7000-8000-000000000060",
              key: "role.read",
              name: "Read roles",
              principalTypes: ["human"],
            },
          ],
        }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
        updateTenantRole,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    const name = screen.getByRole("textbox", { name: "Role name" });
    fireEvent.change(name, { target: { value: "Edited triage" } });
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));

    expect(
      await screen.findByText(/reloaded role and policy version 4 in place/i),
    ).toBeVisible();
    expect(name).toHaveValue("Edited triage");
    expect(updateTenantRole).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      roleId,
      '"v3"',
      { description: "Original description", name: "Edited triage" },
    );
    expect(getTenantRole).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("button", { name: "Save role" }));
    await waitFor(() =>
      expect(updateTenantRole).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        roleId,
        '"v4"',
        {
          description: "Concurrent server description",
          name: "Edited triage",
        },
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "Edited triage" }),
    ).toBeVisible();
  });

  it("invalidates the current session when a role mutation returns 401", async () => {
    const clearSession = vi.fn();
    renderRoles(
      createPhaseTwoApi({
        createTenantRole: async () => {
          throw new PhaseTwoApiError("expired", 401);
        },
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles: async () => ({ items: [] }),
      }),
      clearSession,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create custom role" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Role key" }), {
      target: { value: "expired_role" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Role name" }), {
      target: { value: "Expired session role" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("refreshes a policy-only 412 in place and retries the preserved matrix with the current ETag", async () => {
    const role = roleFixture();
    const refreshedRole = {
      ...role,
      description: "Concurrent policy base",
      updatedAt: "2026-08-23T10:15:00Z",
      version: 4,
    };
    const savedRole = {
      ...refreshedRole,
      policy: {
        delegationCeiling: [],
        permissions: [
          { permissionKey: "role.read" as const, scope: "tenant" as const },
        ],
      },
      updatedAt: "2026-08-23T10:30:00Z",
      version: 5,
    };
    const getTenantRole = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: role })
      .mockResolvedValueOnce({ etag: '"v4"', value: refreshedRole });
    const replaceTenantRolePolicy = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce({ etag: '"v5"', value: savedRole });
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole,
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
        replaceTenantRolePolicy,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    const grant = screen.getByRole("checkbox", {
      name: "Grant role · read at tenant scope",
    });
    fireEvent.click(grant);
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));

    expect(
      await screen.findByText(/reloaded role and policy version 4 in place/i),
    ).toBeVisible();
    expect(grant).toBeChecked();
    expect(replaceTenantRolePolicy).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      roleId,
      '"v3"',
      savedRole.policy,
    );

    fireEvent.click(screen.getByRole("button", { name: "Save role" }));
    await waitFor(() =>
      expect(replaceTenantRolePolicy).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        roleId,
        '"v4"',
        savedRole.policy,
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("refreshes an archive 412 in place and keeps confirmation open for a current-ETag retry", async () => {
    const role = roleFixture();
    const refreshedRole = {
      ...role,
      description: "Concurrent archive review",
      updatedAt: "2026-08-23T10:15:00Z",
      version: 4,
    };
    const getTenantRole = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: role })
      .mockResolvedValueOnce({ etag: '"v4"', value: refreshedRole });
    const archiveTenantRole = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce(undefined);
    renderRoles(
      createPhaseTwoApi({
        archiveTenantRole,
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole,
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Archive" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm archive" }));

    expect(
      await screen.findByText(/reloaded version 4 in place/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Confirm archive" }),
    ).toBeVisible();
    expect(archiveTenantRole).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      roleId,
      '"v3"',
    );

    fireEvent.click(screen.getByRole("button", { name: "Confirm archive" }));
    await waitFor(() =>
      expect(archiveTenantRole).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        roleId,
        '"v4"',
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("aborts an in-place 412 refresh and ignores its settlement after authority becomes non-ready", async () => {
    const role = roleFixture();
    const deniedAuthority = createDeferred<TenantAuthorityView>();
    const refresh = createDeferred<{ etag: string; value: TenantRoleView }>();
    let refreshSignal: AbortSignal | undefined;
    const getTenantAuthority = vi
      .fn()
      .mockResolvedValueOnce(
        authorityFixture(["role.read", "role.manage"], true),
      )
      .mockImplementationOnce(async () => deniedAuthority.promise);
    const getTenantRole = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: role })
      .mockImplementationOnce(async (_tenantId, _roleId, signal) => {
        refreshSignal = signal;
        return refresh.promise;
      });
    const updateTenantRole = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412));
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantRole,
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
        updateTenantRole,
      }),
      vi.fn(),
      true,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Role name" }), {
      target: { value: "Authority-lost draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));
    await waitFor(() => expect(refreshSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("reload-role-authority"));
    await waitFor(() => expect(refreshSignal?.aborted).toBe(true));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await act(async () => {
      refresh.resolve({
        etag: '"v4"',
        value: {
          ...role,
          name: "Late refreshed role",
          updatedAt: "2026-08-23T10:15:00Z",
          version: 4,
        },
      });
      await refresh.promise;
    });
    expect(screen.queryByText("Late refreshed role")).not.toBeInTheDocument();
    expect(updateTenantRole).toHaveBeenCalledTimes(1);

    await act(async () => {
      deniedAuthority.resolve(authorityFixture([]));
      await deniedAuthority.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
  });

  it("never renders an old tenant inventory or dialog while the next pair loads", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const nextRoles = createDeferred<{
      items: TenantRoleSummaryView[];
    }>();
    const oldRole = { ...roleFixture(), name: "Old tenant triage" };
    const nextRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000041",
      key: "next_triage",
      name: "Next tenant triage",
      tenantId: nextTenantId,
    };
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["role.read"], false, requestedTenantId),
      getTenantRole: async () => ({ etag: '"v3"', value: oldRole }),
      listTenantRoles: async (requestedTenantId) =>
        requestedTenantId === tenantId
          ? { items: [toSummary(oldRole)] }
          : nextRoles.promise,
    });

    render(<SwitchingRolesHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Old tenant triage (custom_triage)",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Old tenant triage" }),
    ).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-role-tenant"));
    expect(screen.queryByText("Old tenant triage")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Old tenant triage" }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("Loading tenant roles")).toBeVisible();

    await act(async () => {
      nextRoles.resolve({ items: [toSummary(nextRole)] });
      await nextRoles.promise;
    });
    expect(
      await screen.findByRole("button", {
        name: "View role Next tenant triage (next_triage)",
      }),
    ).toBeVisible();
  });

  it("aborts superseded and closed detail requests so late role A cannot overwrite role B", async () => {
    const firstRole = { ...roleFixture(), name: "Role alpha" };
    const secondRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000041",
      key: "role_beta",
      name: "Role beta",
    };
    const requests: Array<{
      deferred: Deferred<{ etag: string; value: TenantRoleView }>;
      roleId: string;
      signal?: AbortSignal;
    }> = [];
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["role.read"]),
        getTenantRole: (requestedTenantId, requestedRoleId, signal) => {
          expect(requestedTenantId).toBe(tenantId);
          const deferred = createDeferred<{
            etag: string;
            value: TenantRoleView;
          }>();
          requests.push({
            deferred,
            roleId: requestedRoleId,
            ...(signal ? { signal } : {}),
          });
          return deferred.promise;
        },
        listTenantRoles: async () => ({
          items: [toSummary(firstRole), toSummary(secondRole)],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Role alpha (custom_triage)",
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        hidden: true,
        name: "View role Role beta (role_beta)",
      }),
    );
    expect(requests).toHaveLength(2);
    expect(requests[0]?.signal?.aborted).toBe(true);

    await act(async () => {
      requests[0]?.deferred.resolve({ etag: '"v3"', value: firstRole });
      await Promise.resolve();
    });
    expect(
      screen.queryByRole("heading", { name: "Role alpha" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      requests[1]?.deferred.resolve({ etag: '"v3"', value: secondRole });
      await requests[1]?.deferred.promise;
    });
    expect(
      await screen.findByRole("heading", { name: "Role beta" }),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        hidden: true,
        name: "View role Role alpha (custom_triage)",
      }),
    );
    expect(requests).toHaveLength(3);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(requests[2]?.signal?.aborted).toBe(true);
  });

  it("aborts an old A page across an A-to-B-to-A tenant cycle", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const oldPage = createDeferred<{
      items: TenantRoleSummaryView[];
    }>();
    const originalRole = { ...roleFixture(), name: "Original A role" };
    const freshRole = { ...roleFixture(), name: "Fresh A role" };
    const staleRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000042",
      key: "stale_a_role",
      name: "Stale A pagination role",
    };
    const nextRole = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000043",
      key: "tenant_b_role",
      name: "Tenant B role",
      tenantId: nextTenantId,
    };
    let aInitialLoads = 0;
    let oldPageSignal: AbortSignal | undefined;
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["role.read"], false, requestedTenantId),
      listTenantRoles: async (requestedTenantId, options) => {
        if (requestedTenantId === nextTenantId) {
          return { items: [toSummary(nextRole)] };
        }
        if (options?.after === "cursor-a") {
          oldPageSignal = options.signal;
          return oldPage.promise;
        }
        aInitialLoads += 1;
        return {
          items: [toSummary(aInitialLoads === 1 ? originalRole : freshRole)],
          nextCursor: "cursor-a",
        };
      },
    });

    render(<SwitchingRolesHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more roles" }),
    );
    await waitFor(() => expect(oldPageSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("switch-role-tenant"));
    await waitFor(() => expect(oldPageSignal?.aborted).toBe(true));
    expect(await screen.findByText("Tenant B role")).toBeVisible();

    fireEvent.click(screen.getByTestId("switch-role-original-tenant"));
    expect(await screen.findByText("Fresh A role")).toBeVisible();

    await act(async () => {
      oldPage.resolve({ items: [toSummary(staleRole)] });
      await oldPage.promise;
    });
    expect(
      screen.queryByText("Stale A pagination role"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Fresh A role")).toBeVisible();
  });

  it("does not let an old create completion close a new A dialog after an A-to-B-to-A cycle", async () => {
    const nextTenantId = "0198c97d-cf4f-7000-8000-000000000011";
    const oldCreate = createDeferred<{
      etag: string;
      value: TenantRoleView;
    }>();
    const getTenantAuthority = vi.fn(async (requestedTenantId: string) =>
      authorityFixture(["role.read", "role.manage"], true, requestedTenantId),
    );
    const createTenantRole = vi.fn(() => oldCreate.promise);
    const api = createPhaseTwoApi({
      createTenantRole,
      getTenantAuthority,
      listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
      listTenantRoles: async () => ({ items: [] }),
    });

    render(<SwitchingRolesHarness api={api} nextTenantId={nextTenantId} />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Create custom role" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Role key" }), {
      target: { value: "old_pending" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Role name" }), {
      target: { value: "Old pending role" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(createTenantRole).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByTestId("switch-role-tenant"));
    await screen.findByRole("button", { name: "Create custom role" });
    fireEvent.click(screen.getByTestId("switch-role-original-tenant"));
    fireEvent.click(
      await screen.findByRole("button", { name: "Create custom role" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Role key" }), {
      target: { value: "new_pending" },
    });
    const newName = screen.getByRole("textbox", { name: "Role name" });
    fireEvent.change(newName, { target: { value: "New A draft" } });

    await act(async () => {
      oldCreate.resolve({
        etag: '"v1"',
        value: {
          ...roleFixture(),
          id: "0198c97d-cf4f-7000-8000-000000000044",
          key: "old_pending",
          name: "Old pending role",
          version: 1,
        },
      });
      await oldCreate.promise;
    });

    expect(
      screen.getByRole("heading", { name: "Create custom role" }),
    ).toBeVisible();
    expect(newName).toHaveValue("New A draft");
    expect(getTenantAuthority).toHaveBeenCalledTimes(3);
  });

  it("keeps successful metadata and its new ETag visible when the policy save fails", async () => {
    const role = roleFixture();
    const updatedRole = {
      ...role,
      name: "Edited triage",
      updatedAt: "2026-08-23T10:30:00Z",
      version: 4,
    };
    const updateTenantRole = vi.fn().mockResolvedValue({
      etag: '"v4"',
      value: updatedRole,
    });
    const replaceTenantRolePolicy = vi
      .fn()
      .mockRejectedValue(new Error("policy transport failed"));
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole: async () => ({ etag: '"v3"', value: role }),
        listTenantPermissions: async () => ({
          items: [roleReadPermission()],
        }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
        replaceTenantRolePolicy,
        updateTenantRole,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Role name" }), {
      target: { value: "Edited triage" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: "Grant role · read at tenant scope",
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));

    expect(await screen.findByText("Role partially saved")).toBeVisible();
    expect(screen.getByText(/metadata was saved as version 4/i)).toBeVisible();
    expect(replaceTenantRolePolicy).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      roleId,
      '"v4"',
      {
        delegationCeiling: [],
        permissions: [{ permissionKey: "role.read", scope: "tenant" }],
      },
    );

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(
      await screen.findByRole("heading", { name: "Edited triage" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        hidden: true,
        name: "View role Edited triage (custom_triage)",
      }),
    ).toBeInTheDocument();
  });

  it("reconciles a partially saved policy 412 atomically and retries without resaving metadata", async () => {
    const role = roleFixture();
    const metadataSavedRole = {
      ...role,
      name: "Edited triage",
      updatedAt: "2026-08-23T10:15:00Z",
      version: 4,
    };
    const refreshedRole = {
      ...metadataSavedRole,
      updatedAt: "2026-08-23T10:20:00Z",
      version: 5,
    };
    const savedRole = {
      ...refreshedRole,
      policy: {
        delegationCeiling: [],
        permissions: [
          { permissionKey: "role.read" as const, scope: "tenant" as const },
        ],
      },
      updatedAt: "2026-08-23T10:30:00Z",
      version: 6,
    };
    const getTenantRole = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: role })
      .mockResolvedValueOnce({ etag: '"v5"', value: refreshedRole });
    const updateTenantRole = vi.fn().mockResolvedValue({
      etag: '"v4"',
      value: metadataSavedRole,
    });
    const replaceTenantRolePolicy = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("version mismatch", 412))
      .mockResolvedValueOnce({ etag: '"v6"', value: savedRole });
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole,
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles: async () => ({ items: [toSummary(role)] }),
        replaceTenantRolePolicy,
        updateTenantRole,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    const name = screen.getByRole("textbox", { name: "Role name" });
    const grant = screen.getByRole("checkbox", {
      name: "Grant role · read at tenant scope",
    });
    fireEvent.change(name, { target: { value: "Edited triage" } });
    fireEvent.click(grant);
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));

    expect(await screen.findByText("Role partially saved")).toBeVisible();
    expect(
      screen.getByText(/reloaded role and policy version 5 in place/i),
    ).toBeVisible();
    expect(name).toHaveValue("Edited triage");
    expect(grant).toBeChecked();
    expect(updateTenantRole).toHaveBeenCalledTimes(1);
    expect(replaceTenantRolePolicy).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      roleId,
      '"v4"',
      savedRole.policy,
    );

    fireEvent.click(screen.getByRole("button", { name: "Save role" }));
    await waitFor(() =>
      expect(replaceTenantRolePolicy).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        roleId,
        '"v5"',
        savedRole.policy,
      ),
    );
    expect(updateTenantRole).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("binds create idempotency to canonical input, rejects control characters, and reloads authority after success", async () => {
    const getTenantAuthority = vi
      .fn()
      .mockResolvedValue(authorityFixture(["role.read", "role.manage"], true));
    const createdRole = {
      ...roleFixture(),
      description: "Operational handoff",
      key: "custom_handoff",
      name: "Handoff two",
    };
    const createTenantRole = vi
      .fn()
      .mockRejectedValueOnce(new Error("first transport failure"))
      .mockRejectedValueOnce(new Error("same retry failure"))
      .mockResolvedValueOnce({ etag: '"v3"', value: createdRole });
    renderRoles(
      createPhaseTwoApi({
        createTenantRole,
        getTenantAuthority,
        listTenantPermissions: async () => ({
          items: [roleReadPermission()],
        }),
        listTenantRoles: async () => ({ items: [] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create custom role" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Role key" }), {
      target: { value: "custom_handoff" },
    });
    const name = screen.getByRole("textbox", { name: "Role name" });
    fireEvent.change(name, { target: { value: "Handoff one" } });
    const description = screen.getByRole("textbox", { name: "Description" });
    fireEvent.change(description, {
      target: { value: "Operational\u0085handoff" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    expect(
      await screen.findByText("Use a description without control characters."),
    ).toBeVisible();
    expect(createTenantRole).not.toHaveBeenCalled();

    fireEvent.change(description, {
      target: { value: "Operational handoff" },
    });
    fireEvent.change(name, { target: { value: "Handoff\u009fone" } });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    expect(
      await screen.findByText("Use a role name without control characters."),
    ).toBeVisible();
    expect(createTenantRole).not.toHaveBeenCalled();

    fireEvent.change(name, { target: { value: "Handoff one" } });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(createTenantRole).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(createTenantRole).toHaveBeenCalledTimes(2));
    fireEvent.change(name, { target: { value: "Handoff two" } });
    fireEvent.click(screen.getByRole("button", { name: "Create role" }));
    await waitFor(() => expect(createTenantRole).toHaveBeenCalledTimes(3));

    const firstKey = createTenantRole.mock.calls[0]?.[2];
    const retryKey = createTenantRole.mock.calls[1]?.[2];
    const changedKey = createTenantRole.mock.calls[2]?.[2];
    expect(firstKey).toBe(retryKey);
    expect(changedKey).not.toBe(firstKey);
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
  });

  it("keeps a mutation-newer role when delayed pagination returns its stale summary", async () => {
    const role = roleFixture();
    const delayedPage = createDeferred<{
      items: TenantRoleSummaryView[];
    }>();
    const updated = {
      ...role,
      name: "Custom triage updated",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const listTenantRoles = vi
      .fn()
      .mockResolvedValueOnce({
        items: [toSummary(role)],
        nextCursor: "delayed-role-page",
      })
      .mockImplementationOnce(async () => delayedPage.promise);
    renderRoles(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["role.read", "role.manage"], true),
        getTenantRole: async () => ({ etag: '"v3"', value: role }),
        listTenantPermissions: async () => ({ items: [roleReadPermission()] }),
        listTenantRoles,
        updateTenantRole: async () => ({ etag: '"v4"', value: updated }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more roles" }),
    );
    await waitFor(() => expect(listTenantRoles).toHaveBeenCalledTimes(2));
    fireEvent.click(
      screen.getByRole("button", {
        name: "View role Custom triage (custom_triage)",
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Edit role" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Role name" }), {
      target: { value: updated.name },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save role" }));
    expect(
      await screen.findByRole("heading", { name: "Custom triage updated" }),
    ).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [toSummary(role)] });
      await delayedPage.promise;
    });
    expect(
      screen.getByRole("button", {
        hidden: true,
        name: "View role Custom triage updated (custom_triage)",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        hidden: true,
        name: "View role Custom triage (custom_triage)",
      }),
    ).not.toBeInTheDocument();
  });

  it("merges role inventory monotonically and fails closed on equal-version conflicts", () => {
    const original = toSummary(roleFixture());
    const newer = {
      ...original,
      name: "Newer role",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 5,
    };
    const stale = {
      ...original,
      name: "Stale role",
      updatedAt: "2026-08-23T13:00:00Z",
      version: 4,
    };

    expect(mergeTenantRoles([original], [newer, stale])).toEqual([newer]);
    expect(mergeTenantRoles([newer], [stale])).toEqual([newer]);
    expect(mergeTenantRoles([newer], [{ ...newer }])).toEqual([newer]);
    expect(() =>
      mergeTenantRoles([newer], [{ ...newer, name: "Conflicting role" }]),
    ).toThrow(/conflicting representations/i);
  });
});

function renderRoles(
  api: ReturnType<typeof createPhaseTwoApi>,
  clearSession = vi.fn(),
  showAuthorityReload = false,
): void {
  const session = { ...sessionFixture, activeTenantId: tenantId };
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
        <TenantRolesPage />
        {showAuthorityReload ? <RoleAuthorityReloadControl /> : null}
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function RoleAuthorityReloadControl(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button
      data-testid="reload-role-authority"
      type="button"
      onClick={authority.reload}
    >
      Reload role authority
    </button>
  );
}

function SwitchingRolesHarness({
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
        <TenantRolesPage />
        <button
          data-testid="switch-role-tenant"
          type="button"
          onClick={() => setActiveTenantId(nextTenantId)}
        >
          Switch role tenant
        </button>
        <button
          data-testid="switch-role-original-tenant"
          type="button"
          onClick={() => setActiveTenantId(tenantId)}
        >
          Switch original role tenant
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function authorityFixture(
  keys: TenantAuthorityView["permissions"][number]["permissionKey"][],
  delegation = false,
  authorityTenantId = tenantId,
): TenantAuthorityView {
  return {
    delegationCeiling: delegation
      ? [{ permissionKey: "role.read", scope: "tenant" }]
      : [],
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

function roleReadPermission(): TenantPermissionView {
  return {
    allowedScopes: ["tenant"],
    description: "Read role definitions.",
    id: "0198c97d-cf4f-7000-8000-000000000060",
    key: "role.read",
    name: "Read roles",
    principalTypes: ["human"],
  };
}

function roleFixture(): TenantRoleView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    description: "Original description",
    id: roleId,
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

function toSummary(role: TenantRoleView): TenantRoleSummaryView {
  const { policy: _policy, ...summary } = role;
  return summary;
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
