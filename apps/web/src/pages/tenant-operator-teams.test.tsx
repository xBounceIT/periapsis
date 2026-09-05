import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { StrictMode, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "../auth/tenant-authority-context";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type OperatorTeamAssignmentEpochView,
  type OperatorTeamRosterEntryView,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
  type TenantUserSummaryView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TenantOperatorTeamsPage } from "./tenant-operator-teams";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const otherTenantId = "0198c97d-cf4f-7000-8000-000000000011";
const teamId = "0198c97d-cf4f-7000-8000-000000000401";
const activeEpochId = "0198c97d-cf4f-7000-8000-000000000402";
const historicalEpochId = "0198c97d-cf4f-7000-8000-000000000403";
const secondTeamId = "0198c97d-cf4f-7000-8000-000000000451";
const secondEpochId = "0198c97d-cf4f-7000-8000-000000000452";
const thirdTeamId = "0198c97d-cf4f-7000-8000-000000000453";
const thirdEpochId = "0198c97d-cf4f-7000-8000-000000000454";
const epochMutationPermissions: readonly TenantPermissionKeyView[] = [
  "operator_team.manage",
  "operator_team.read",
  "operator_team.roster.manage",
  "role.grant",
  "user.read",
];

afterEach(cleanup);

describe("TenantOperatorTeamsPage", () => {
  it("keeps inventory and mutations hidden unless live tenant capabilities permit them", async () => {
    const listTenantOperatorTeamAssignmentEpochs = vi.fn();
    renderTeams(
      createPhaseTwoApi({ listTenantOperatorTeamAssignmentEpochs }),
      [],
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantOperatorTeamAssignmentEpochs).not.toHaveBeenCalled();

    cleanup();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: activeEpochFixture(),
        }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [activeEpochFixture()],
        }),
      }),
      ["operator_team.read"],
    );
    expect(
      await screen.findByRole("heading", {
        name: "Assignment epochs & roster",
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Start assignment epoch" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "End assignment epoch" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add roster member" }),
    ).not.toBeInTheDocument();
  });

  it("loads roster edges only through the selected exact epoch and marks stale history as non-current", async () => {
    const active = activeEpochFixture();
    const historical = historicalEpochFixture();
    const listOperatorTeamRosterEntries = vi.fn(
      async (
        _tenantId: string,
        _operatorTeamId: string,
        assignmentEpochId: string,
      ) => ({
        items: [
          rosterFixture(
            assignmentEpochId,
            assignmentEpochId === activeEpochId
              ? "Active Mira"
              : "Historical Nia",
            assignmentEpochId === activeEpochId ? "active" : "expired",
          ),
        ],
      }),
    );
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async (
          _tenantId,
          _teamId,
          assignmentEpochId,
        ) => ({
          etag: assignmentEpochId === activeEpochId ? '"v2"' : '"v3"',
          value: assignmentEpochId === activeEpochId ? active : historical,
        }),
        listOperatorTeamRosterEntries,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [historical, active],
        }),
      }),
      ["operator_team.read", "user.read"],
    );

    expect(await screen.findByText("Active Mira")).toBeVisible();
    expect(listOperatorTeamRosterEntries).toHaveBeenLastCalledWith(
      tenantId,
      teamId,
      activeEpochId,
      expect.objectContaining({ includeRevoked: true }),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC L1 epoch ${historicalEpochId.slice(-8)}, ended`,
      }),
    );
    expect(await screen.findByText("Historical Nia")).toBeVisible();
    expect(screen.getByText("History only")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "Historical roster" }),
    ).toBeVisible();
    expect(listOperatorTeamRosterEntries).toHaveBeenLastCalledWith(
      tenantId,
      teamId,
      historicalEpochId,
      expect.objectContaining({ includeRevoked: true }),
    );
    expect(screen.queryByText("Active Mira")).not.toBeInTheDocument();
  });

  it("requires user.read only for roster actions that compose the tenant-user inventory", async () => {
    const epoch = activeEpochFixture();
    const listTenantUsers = vi.fn(async () => ({ items: [] }));
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async () => ({
        etag: '"v2"',
        value: epoch,
      }),
      listOperatorTeamRosterEntries: async () => ({ items: [] }),
      listTenantOperatorTeamAssignmentEpochs: async () => ({ items: [epoch] }),
      listTenantUsers,
    });

    renderTeams(api, [
      "operator_team.read",
      "operator_team.roster.manage",
      "role.grant",
    ]);
    await screen.findByRole("heading", { name: "Roster · SOC L1" });
    expect(listTenantUsers).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Add roster member" }),
    ).not.toBeInTheDocument();

    cleanup();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({
          items: [
            {
              createdAt: "2026-08-20T10:00:00Z",
              etag: '"v1"',
              legacyMembershipRole: "analyst",
              lifecycleRevision: 1,
              membershipId: "0198c97d-cf4f-7000-8000-000000000420",
              membershipStatus: "active",
              tenantId,
              updatedAt: "2026-08-24T08:00:00Z",
              user: {
                active: true,
                displayName: "Ada Target",
                email: "ada-target@example.invalid",
                id: "0198c97d-cf4f-7000-8000-000000000421",
              },
            },
          ],
        }),
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
    );
    expect(
      await screen.findByRole("button", { name: "Add roster member" }),
    ).toBeVisible();
    expect(
      screen.getByRole("combobox", { name: "Tenant member" }),
    ).toBeVisible();
  });

  it("does not fan operator-team-scoped roster management across exact epochs", async () => {
    const epochs = multiEpochFixtures().slice(0, 2);
    const listTenantUsers = vi.fn(async () => ({
      items: [tenantUserFixture()],
    }));
    const listOperatorTeamRosterEntries = vi.fn(
      async (
        _requestedTenantId: string,
        requestedOperatorTeamId: string,
        assignmentEpochId: string,
      ) => ({
        items: [
          rosterFixture(
            assignmentEpochId,
            assignmentEpochId === activeEpochId
              ? "Scoped member A"
              : "Scoped member B",
            "active",
            { operatorTeamId: requestedOperatorTeamId },
          ),
        ],
      }),
    );
    const api = multiEpochMutationApi(epochs, {
      listOperatorTeamRosterEntries,
      listTenantUsers,
    });
    const tenantReadPermissions: readonly TenantPermissionKeyView[] = [
      "operator_team.read",
      "role.grant",
      "user.read",
    ];
    renderTeams(api, tenantReadPermissions, {
      getTenantAuthority: async () =>
        authorityFixture(tenantReadPermissions, tenantId, [
          "operator_team.roster.manage",
        ]),
    });

    expect(await screen.findByText("Scoped member A")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add roster member" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Revoke Scoped member A/u }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    expect(await screen.findByText("Scoped member B")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Add roster member" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Revoke Scoped member B/u }),
    ).not.toBeInTheDocument();
    expect(listTenantUsers).not.toHaveBeenCalled();

    cleanup();
    listTenantUsers.mockClear();
    renderTeams(api, [...tenantReadPermissions, "operator_team.roster.manage"]);
    expect(await screen.findByText("Scoped member A")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Add roster member" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: /Revoke Scoped member A/u }),
    ).toBeVisible();
    await waitFor(() => expect(listTenantUsers).toHaveBeenCalledTimes(1));
  });

  it("loads tenant members explicitly and closes pagination on an A-to-B-to-A cursor cycle", async () => {
    const first = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000430",
      user: {
        active: true,
        displayName: "First responder",
        email: "first@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000431",
      },
    });
    const second = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000432",
      user: {
        active: true,
        displayName: "Second responder",
        email: "second@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000433",
      },
    });
    const loop = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000434",
      user: {
        active: true,
        displayName: "Loop responder",
        email: "loop@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000435",
      },
    });
    const listTenantUsers = vi.fn(
      async (_tenantId: string, after?: string, signal?: AbortSignal) => {
        expect(signal).toBeInstanceOf(AbortSignal);
        if (!after) return { items: [first], nextCursor: "cursor-a" };
        if (after === "cursor-a")
          return { items: [second], nextCursor: "cursor-b" };
        return { items: [loop], nextCursor: "cursor-a" };
      },
    );
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers,
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
    );

    const loadMore = await screen.findByRole("button", {
      name: "Load more users",
    });
    expect(listTenantUsers).toHaveBeenCalledTimes(1);
    fireEvent.click(loadMore);
    await waitFor(() => expect(listTenantUsers).toHaveBeenCalledTimes(2));
    expect(screen.getByText(/2 eligible tenant members loaded/i)).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Load more users" }));
    expect(
      await screen.findByText(/tenant-member cursor entered a cycle/i),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Load more users" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/2 eligible tenant members loaded/i)).toBeVisible();
    expect(listTenantUsers).toHaveBeenCalledTimes(3);
  });

  it("does not offer an inactive identity as a roster member", async () => {
    const activeUser = tenantUserFixture();
    const inactiveUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000436",
      user: {
        active: false,
        displayName: "Inactive responder",
        email: "inactive@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000437",
      },
    });
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({
          items: [activeUser, inactiveUser],
        }),
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
    );

    const picker = await screen.findByRole("combobox", {
      name: "Tenant member",
    });
    await waitFor(() => expect(picker).toBeEnabled());
    fireEvent.click(picker);
    expect(
      await screen.findByRole("option", {
        name: `${activeUser.user.displayName} · ${activeUser.user.email}`,
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", {
        name: `${inactiveUser.user.displayName} · ${inactiveUser.user.email}`,
      }),
    ).not.toBeInTheDocument();
  });

  it("gives each roster revoke action a member-and-edge-specific accessible name", async () => {
    const epoch = activeEpochFixture();
    const first = rosterFixture(activeEpochId, "Mira Responder", "active");
    const second = rosterFixture(activeEpochId, "Noah Responder", "active", {
      id: "0198c97d-cf4f-7000-8000-000000000407",
      member: {
        displayName: "Noah Responder",
        membershipId: "0198c97d-cf4f-7000-8000-000000000408",
        membershipStatus: "active",
        userId: "0198c97d-cf4f-7000-8000-000000000409",
      },
    });
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({
          items: [first, second],
        }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({ items: [] }),
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
    );

    expect(
      await screen.findByRole("button", {
        name: "Revoke Mira Responder, edge 00000499",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Revoke Noah Responder, edge 00000407",
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Revoke" }),
    ).not.toBeInTheDocument();
  });

  it("rejects a tenant-member page that escapes the active tenant", async () => {
    const localUser = tenantUserFixture();
    const foreignUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000438",
      tenantId: otherTenantId,
      user: {
        active: true,
        displayName: "Foreign responder",
        email: "foreign@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000439",
      },
    });
    const listTenantUsers = vi
      .fn()
      .mockResolvedValueOnce({
        items: [localUser],
        nextCursor: "foreign-page",
      })
      .mockResolvedValueOnce({ items: [foreignUser] });
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers,
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    expect(
      await screen.findByText(/next tenant-member page could not be loaded/i),
    ).toBeVisible();
    const picker = screen.getByRole("combobox", { name: "Tenant member" });
    fireEvent.click(picker);
    expect(
      await screen.findByRole("option", {
        name: `${localUser.user.displayName} · ${localUser.user.email}`,
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", {
        name: `${foreignUser.user.displayName} · ${foreignUser.user.email}`,
      }),
    ).not.toBeInTheDocument();
  });

  it("clears the current session when tenant-member pagination returns 401", async () => {
    const clearSession = vi.fn();
    const listTenantUsers = vi
      .fn()
      .mockResolvedValueOnce({
        items: [tenantUserFixture()],
        nextCursor: "members-next",
      })
      .mockRejectedValueOnce(new PhaseTwoApiError("session expired", 401));
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers,
      }),
      [
        "operator_team.read",
        "operator_team.roster.manage",
        "role.grant",
        "user.read",
      ],
      { clearSession },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("preserves the end reason across a 412 refresh and retries with the current epoch ETag", async () => {
    const initial = activeEpochFixture();
    const current = {
      ...initial,
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    };
    const ended = historicalEpochFixture({
      endedAt: "2026-08-24T10:00:00Z",
      epochId: activeEpochId,
      version: 4,
    });
    const getOperatorTeamAssignmentEpoch = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v3"', value: current })
      .mockResolvedValue({ etag: '"v4"', value: ended });
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "operator_team.manage",
        "operator_team.read",
        "role.grant",
      ]),
    );
    const endOperatorTeamAssignmentEpoch = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale epoch", 412))
      .mockResolvedValueOnce(undefined);
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch,
        getOperatorTeamAssignmentEpoch,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [initial],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant"],
      { getTenantAuthority },
    );

    const reason = await screen.findByRole("textbox", { name: "End reason" });
    fireEvent.change(reason, { target: { value: "Coverage moved to SOC L2" } });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    expect(await screen.findByText("stale epoch")).toBeVisible();
    expect(endOperatorTeamAssignmentEpoch).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      teamId,
      activeEpochId,
      '"v2"',
      { reason: "Coverage moved to SOC L2" },
    );

    fireEvent.click(screen.getByRole("button", { name: "Load current epoch" }));
    const refreshedReason = await screen.findByRole("textbox", {
      name: "End reason",
    });
    expect(refreshedReason).toHaveValue("Coverage moved to SOC L2");
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(endOperatorTeamAssignmentEpoch).toHaveBeenNthCalledWith(
      2,
      sessionFixture.csrfToken,
      tenantId,
      teamId,
      activeEpochId,
      '"v3"',
      { reason: "Coverage moved to SOC L2" },
    );
    expect(await screen.findByText("History only")).toBeVisible();
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
  });

  it("revalidates authority when an epoch end commits but exact refresh fails", async () => {
    const epoch = activeEpochFixture();
    const getOperatorTeamAssignmentEpoch = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: epoch })
      .mockRejectedValue(new Error("exact refresh unavailable"));
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "operator_team.manage",
        "operator_team.read",
        "role.grant",
      ]),
    );
    const endOperatorTeamAssignmentEpoch = vi.fn(async () => undefined);
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch,
        getOperatorTeamAssignmentEpoch,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant"],
      { getTenantAuthority },
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Committed handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );

    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
  });

  it("revalidates authority after adding the current actor to the exact roster", async () => {
    const permissions: TenantPermissionKeyView[] = [
      "operator_team.read",
      "operator_team.roster.manage",
      "role.grant",
      "user.read",
    ];
    const authority = authorityFixture(permissions);
    const self = tenantUserFixture({
      membershipId: authority.membershipId,
      user: { active: true, ...sessionFixture.user },
    });
    const created = rosterFixture(
      activeEpochId,
      sessionFixture.user.displayName,
      "active",
      {
        member: {
          displayName: sessionFixture.user.displayName,
          membershipId: self.membershipId,
          membershipStatus: "active",
          userId: sessionFixture.user.id,
        },
      },
    );
    let roster: readonly OperatorTeamRosterEntryView[] = [];
    const addOperatorTeamRosterEntry = vi.fn(async () => {
      roster = [created];
      return { etag: created.etag, value: created };
    });
    const getTenantAuthority = vi.fn(async () => authority);
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        addOperatorTeamRosterEntry,
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: roster }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({ items: [self] }),
      }),
      permissions,
      { getTenantAuthority },
    );

    const selfPicker = await screen.findByRole("combobox", {
      name: "Tenant member",
    });
    await waitFor(() => expect(selfPicker).toBeEnabled());
    fireEvent.click(selfPicker);
    fireEvent.click(
      await screen.findByRole("option", {
        name: `${sessionFixture.user.displayName} · ${sessionFixture.user.email}`,
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Join the current on-call rotation" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));

    await waitFor(() => expect(addOperatorTeamRosterEntry).toHaveBeenCalled());
    expect(addOperatorTeamRosterEntry).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      teamId,
      activeEpochId,
      expect.any(String),
      {
        membershipId: authority.membershipId,
        reason: "Join the current on-call rotation",
      },
    );
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText(sessionFixture.user.displayName),
    ).toBeVisible();
  });

  it.each(["revoked", "expired"] as const)(
    "renders a fulfilled %s add replay as inactive and releases its payload key",
    async (state) => {
      const displayName = `${state} replay member`;
      const created = rosterFixture(activeEpochId, displayName, state);
      let committed = false;
      const addOperatorTeamRosterEntry = vi
        .fn()
        .mockRejectedValueOnce(
          new PhaseTwoApiError(`ambiguous ${state} add`, 503),
        )
        .mockImplementationOnce(async () => {
          committed = true;
          return { etag: created.etag, value: created };
        })
        .mockRejectedValueOnce(
          new PhaseTwoApiError(`fresh ${state} add cleanup`, 503),
        );
      renderTeams(
        epochMutationApi({
          addOperatorTeamRosterEntry,
          listOperatorTeamRosterEntries: async () => ({
            items: committed ? [created] : [],
          }),
        }),
        epochMutationPermissions,
      );

      await selectEpochMutationMember();
      fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
        target: { value: "Replay the exact inactive edge" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      expect(await screen.findByText(`ambiguous ${state} add`)).toBeVisible();
      const retainedKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
      );
      expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(retainedKey);
      const member = await screen.findByText(displayName, {
        selector: "strong",
      });
      const rosterItem = member.closest("li");
      expect(rosterItem).not.toBeNull();
      expect(rosterItem).toHaveAttribute("data-state", state);
      expect(within(rosterItem!).getByText(state)).toBeVisible();
      expect(within(rosterItem!).queryByText("active")).not.toBeInTheDocument();
      expect(within(rosterItem!).queryByRole("button")).not.toBeInTheDocument();

      await selectEpochMutationMember();
      fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
        target: { value: "Replay the exact inactive edge" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
      );
      expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).not.toBe(
        retainedKey,
      );
      expect(
        await screen.findByText(`fresh ${state} add cleanup`),
      ).toBeVisible();
    },
  );

  it("revalidates authority after self-revocation and removes lost roster controls", async () => {
    const fullPermissions: TenantPermissionKeyView[] = [
      "operator_team.read",
      "operator_team.roster.manage",
      "role.grant",
      "user.read",
    ];
    const selfAuthority = authorityFixture(fullPermissions);
    const readOnlyAuthority = authorityFixture([
      "operator_team.read",
      "user.read",
    ]);
    let entry = rosterFixture(
      activeEpochId,
      sessionFixture.user.displayName,
      "active",
      {
        member: {
          displayName: sessionFixture.user.displayName,
          membershipId: selfAuthority.membershipId,
          membershipStatus: "active",
          userId: sessionFixture.user.id,
        },
      },
    );
    const revokeOperatorTeamRosterEntry = vi.fn(async () => {
      entry = { ...entry, state: "revoked", version: entry.version + 1 };
    });
    const getTenantAuthority = vi
      .fn()
      .mockResolvedValueOnce(selfAuthority)
      .mockResolvedValue(readOnlyAuthority);
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [entry] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({ items: [] }),
        revokeOperatorTeamRosterEntry,
      }),
      fullPermissions,
      { getTenantAuthority },
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Revoke reason" }), {
      target: { value: "Leave the current on-call rotation" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Revoke roster edge" }));

    await waitFor(() =>
      expect(revokeOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await screen.findByRole("heading", { name: "Roster · SOC L1" });
    expect(
      screen.queryByRole("button", { name: "Add roster member" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Revoke roster edge" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    ).not.toBeInTheDocument();
  });

  it("admits one rapid epoch end and re-enables the boundary after failure", async () => {
    const pendingEnd = createDeferred<void>();
    const endOperatorTeamAssignmentEpoch = vi.fn(
      async () => pendingEnd.promise,
    );
    renderTeams(
      epochMutationApi({ endOperatorTeamAssignmentEpoch }),
      epochMutationPermissions,
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "One terminal transition" } },
    );
    const endButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    act(() => {
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });

    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    expect(
      screen.getByRole("button", { name: "Ending epoch…" }),
    ).toBeDisabled();

    await act(async () => {
      pendingEnd.reject(new PhaseTwoApiError("temporary end failure", 503));
      await expect(pendingEnd.promise).rejects.toThrow("temporary end failure");
    });
    expect(await screen.findByText("temporary end failure")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "End assignment epoch" }),
    ).toBeEnabled();
  });

  it("serializes rapid start and child mutations in both directions and releases the owner on settle", async () => {
    const rejectedStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const successfulStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const pendingEnd = createDeferred<void>();
    let startCount = 0;
    const startOperatorTeamAssignmentEpoch = vi.fn(() => {
      startCount += 1;
      return startCount === 1 ? rejectedStart.promise : successfulStart.promise;
    });
    const endOperatorTeamAssignmentEpoch = vi.fn(() => pendingEnd.promise);
    const addOperatorTeamRosterEntry = vi.fn();
    const revokeOperatorTeamRosterEntry = vi.fn();
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(epochMutationPermissions),
    );
    renderTeams(
      epochMutationApi({
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
        revokeOperatorTeamRosterEntry,
        startOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
      { getTenantAuthority },
    );

    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Blocked by start" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Blocked by start" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Revoke reason" }), {
      target: { value: "Blocked by start" },
    });
    fireEvent.change(
      screen.getByRole("textbox", { name: "Operator team ID" }),
      {
        target: { value: teamId },
      },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "One admitted start" } },
    );

    const startButton = screen.getByRole("button", {
      name: "Start assignment epoch",
    });
    const startForm = startButton.closest("form");
    const addButton = screen.getByRole("button", { name: "Add roster member" });
    const addForm = addButton.closest("form");
    const endButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    const revokeButton = screen.getByRole("button", {
      name: "Revoke roster edge",
    });
    expect(startForm).not.toBeNull();
    expect(addForm).not.toBeNull();
    act(() => {
      startForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      startForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      addForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      revokeButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });

    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    expect(addOperatorTeamRosterEntry).not.toHaveBeenCalled();
    expect(endOperatorTeamAssignmentEpoch).not.toHaveBeenCalled();
    expect(revokeOperatorTeamRosterEntry).not.toHaveBeenCalled();
    expect(addButton).toBeDisabled();
    expect(endButton).toBeDisabled();
    expect(revokeButton).toBeDisabled();

    await act(async () => {
      rejectedStart.reject(new PhaseTwoApiError("start owner rejected", 503));
      await expect(rejectedStart.promise).rejects.toThrow(
        "start owner rejected",
      );
    });
    expect(await screen.findByText("start owner rejected")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    ).toBeEnabled();
    expect(addButton).toBeEnabled();
    expect(endButton).toBeEnabled();
    expect(revokeButton).toBeEnabled();

    const retryStartForm = screen
      .getByRole("button", { name: "Start assignment epoch" })
      .closest("form");
    act(() => {
      retryStartForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      retryStartForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    await act(async () => {
      successfulStart.resolve({ etag: '"v2"', value: activeEpochFixture() });
      await successfulStart.promise;
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByRole("button", { name: "Start assignment epoch" }),
    ).toBeEnabled();

    await screen.findByRole("heading", { name: "Roster · SOC L1" });
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Child owns the parent lease" },
    });
    fireEvent.change(
      screen.getByRole("textbox", { name: "Operator team ID" }),
      {
        target: { value: teamId },
      },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Must wait for child" } },
    );
    const freshEndButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    const blockedStartForm = screen
      .getByRole("button", { name: "Start assignment epoch" })
      .closest("form");
    act(() => {
      freshEndButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      freshEndButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      blockedStartForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    ).toBeDisabled();

    await act(async () => {
      pendingEnd.reject(new PhaseTwoApiError("child owner rejected", 503));
      await expect(pendingEnd.promise).rejects.toThrow("child owner rejected");
    });
    expect(await screen.findByText("child owner rejected")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    ).toBeEnabled();
  });

  it("serializes revoke against end, admits one revoke, and re-enables after failure", async () => {
    const pendingRevoke = createDeferred<void>();
    const endOperatorTeamAssignmentEpoch = vi.fn(async () => undefined);
    const revokeOperatorTeamRosterEntry = vi.fn(
      async () => pendingRevoke.promise,
    );
    renderTeams(
      epochMutationApi({
        endOperatorTeamAssignmentEpoch,
        revokeOperatorTeamRosterEntry,
      }),
      epochMutationPermissions,
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Must wait for revoke" } },
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Revoke reason" }), {
      target: { value: "Temporary revoke failure" },
    });
    const revokeButton = screen.getByRole("button", {
      name: "Revoke roster edge",
    });
    const endButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    act(() => {
      revokeButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      revokeButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });

    await waitFor(() =>
      expect(revokeOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );
    expect(endOperatorTeamAssignmentEpoch).not.toHaveBeenCalled();
    expect(endButton).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Revoking edge…" }),
    ).toBeDisabled();

    await act(async () => {
      pendingRevoke.reject(
        new PhaseTwoApiError("temporary revoke failure", 503),
      );
      await expect(pendingRevoke.promise).rejects.toThrow(
        "temporary revoke failure",
      );
    });
    expect(await screen.findByText("temporary revoke failure")).toBeVisible();
    expect(endButton).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Revoke roster edge" }),
    ).toBeEnabled();
  });

  it("blocks add and revoke synchronously while epoch end is pending", async () => {
    const pendingEnd = createDeferred<void>();
    const addOperatorTeamRosterEntry = vi.fn();
    const endOperatorTeamAssignmentEpoch = vi.fn(
      async () => pendingEnd.promise,
    );
    const revokeOperatorTeamRosterEntry = vi.fn();
    renderTeams(
      epochMutationApi({
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
        revokeOperatorTeamRosterEntry,
      }),
      epochMutationPermissions,
    );

    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Must wait for end" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Revoke reason" }), {
      target: { value: "Must also wait for end" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Terminal transition owns the epoch" },
    });
    const addButton = screen.getByRole("button", { name: "Add roster member" });
    const addForm = addButton.closest("form");
    const revokeButton = screen.getByRole("button", {
      name: "Revoke roster edge",
    });
    const endButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    expect(addForm).not.toBeNull();
    act(() => {
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      addForm?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      revokeButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });

    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    expect(addOperatorTeamRosterEntry).not.toHaveBeenCalled();
    expect(revokeOperatorTeamRosterEntry).not.toHaveBeenCalled();
    expect(addButton).toBeDisabled();
    expect(revokeButton).toBeDisabled();
    expect(
      screen.getByRole("button", {
        name: "Revoke Ada Analyst, edge 00000499",
      }),
    ).toBeDisabled();

    await act(async () => {
      pendingEnd.reject(new PhaseTwoApiError("end rejected", 503));
      await expect(pendingEnd.promise).rejects.toThrow("end rejected");
    });
    expect(addButton).toBeEnabled();
    expect(revokeButton).toBeEnabled();
  });

  it("blocks end while add is pending and retains the add key for retry", async () => {
    const firstAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const retryAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    let addCount = 0;
    const addOperatorTeamRosterEntry = vi.fn(
      (
        ..._arguments: Parameters<PhaseTwoApi["addOperatorTeamRosterEntry"]>
      ) => {
        addCount += 1;
        return addCount === 1 ? firstAdd.promise : retryAdd.promise;
      },
    );
    const endOperatorTeamAssignmentEpoch = vi.fn(async () => undefined);
    renderTeams(
      epochMutationApi({
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
    );

    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Retry identical add" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Must wait for add" },
    });
    const addButton = screen.getByRole("button", { name: "Add roster member" });
    const endButton = screen.getByRole("button", {
      name: "End assignment epoch",
    });
    act(() => {
      addButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
      endButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );
    expect(endOperatorTeamAssignmentEpoch).not.toHaveBeenCalled();
    expect(endButton).toBeDisabled();

    await act(async () => {
      firstAdd.reject(new PhaseTwoApiError("temporary add failure", 503));
      await expect(firstAdd.promise).rejects.toThrow("temporary add failure");
    });
    expect(await screen.findByText("temporary add failure")).toBeVisible();
    expect(endButton).toBeEnabled();
    expect(addButton).toBeEnabled();

    fireEvent.click(addButton);
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(
      addOperatorTeamRosterEntry.mock.calls[0]?.[4],
    );
    await act(async () => {
      retryAdd.reject(new PhaseTwoApiError("retry still pending", 503));
      await expect(retryAdd.promise).rejects.toThrow("retry still pending");
    });
  });

  it("isolates an old epoch finally across capability loss and restoration", async () => {
    const oldEnd = createDeferred<void>();
    const freshEnd = createDeferred<void>();
    let endCount = 0;
    const endOperatorTeamAssignmentEpoch = vi.fn(() => {
      endCount += 1;
      return endCount === 1 ? oldEnd.promise : freshEnd.promise;
    });
    let authorityLoad = 0;
    const getTenantAuthority = vi.fn(async () => {
      authorityLoad += 1;
      return authorityLoad === 2
        ? authorityFixture(["operator_team.read"])
        : authorityFixture(epochMutationPermissions);
    });
    render(
      <TenantAuthorityReloadHarness
        api={epochMutationApi({
          endOperatorTeamAssignmentEpoch,
          getTenantAuthority,
        })}
      />,
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Old pending end" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "End assignment epoch" }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    const freshReason = await screen.findByRole("textbox", {
      name: "End reason",
    });
    fireEvent.change(freshReason, { target: { value: "Fresh pending end" } });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldEnd.reject(new PhaseTwoApiError("old end failed", 412));
      await expect(oldEnd.promise).rejects.toThrow("old end failed");
    });
    expect(screen.queryByText("old end failed")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Ending epoch…" }),
    ).toBeDisabled();
    expect(freshReason).toHaveValue("Fresh pending end");

    await act(async () => {
      freshEnd.reject(new PhaseTwoApiError("fresh end failed", 503));
      await expect(freshEnd.promise).rejects.toThrow("fresh end failed");
    });
    expect(await screen.findByText("fresh end failed")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "End assignment epoch" }),
    ).toBeEnabled();
  });

  it("defers a stale add commit reload behind a fresh ambiguous add and preserves the fresh retry key", async () => {
    const oldAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const freshAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const retryAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    let addCount = 0;
    const addOperatorTeamRosterEntry = vi.fn(
      (
        ..._arguments: Parameters<PhaseTwoApi["addOperatorTeamRosterEntry"]>
      ) => {
        addCount += 1;
        if (addCount === 1) return oldAdd.promise;
        if (addCount === 2) return freshAdd.promise;
        return retryAdd.promise;
      },
    );
    let authorityLoad = 0;
    const getTenantAuthority = vi.fn(async () => {
      authorityLoad += 1;
      return authorityLoad === 2
        ? authorityFixture(["operator_team.read"])
        : authorityFixture(epochMutationPermissions);
    });
    render(
      <TenantAuthorityReloadHarness
        api={epochMutationApi({
          addOperatorTeamRosterEntry,
          getTenantAuthority,
        })}
      />,
    );

    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Old add payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Add roster member" }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Fresh ambiguous payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    const oldKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];
    const freshKey = addOperatorTeamRosterEntry.mock.calls[1]?.[4];
    expect(freshKey).not.toBe(oldKey);

    await act(async () => {
      const created = rosterFixture(
        activeEpochId,
        "Old committed member",
        "active",
      );
      oldAdd.resolve({ etag: created.etag, value: created });
      await oldAdd.promise;
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(3);
    expect(
      screen.getByRole("button", { name: "Adding member…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Roster reason" })).toHaveValue(
      "Fresh ambiguous payload",
    );

    await act(async () => {
      freshAdd.reject(new PhaseTwoApiError("ambiguous fresh add", 503));
      await expect(freshAdd.promise).rejects.toThrow("ambiguous fresh add");
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(4));
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Fresh ambiguous payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).toBe(freshKey);

    await act(async () => {
      retryAdd.reject(new PhaseTwoApiError("retry cleanup", 503));
      await expect(retryAdd.promise).rejects.toThrow("retry cleanup");
    });
  });

  it("defers a stale child commit behind an ambiguous start and preserves the start retry key", async () => {
    const epochs = multiEpochFixtures();
    const oldEnd = createDeferred<void>();
    const ambiguousStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const retryStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    let startCount = 0;
    const startOperatorTeamAssignmentEpoch = vi.fn(
      (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => {
        startCount += 1;
        return startCount === 1 ? ambiguousStart.promise : retryStart.promise;
      },
    );
    const endOperatorTeamAssignmentEpoch = vi.fn(() => oldEnd.promise);
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(epochMutationPermissions),
    );
    renderTeams(
      multiEpochMutationApi(epochs, {
        endOperatorTeamAssignmentEpoch,
        startOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
      { getTenantAuthority },
    );

    await startPendingEpochEnd("SOC A", "Old child commits later");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC B" });
    fireEvent.change(
      screen.getByRole("textbox", { name: "Operator team ID" }),
      {
        target: { value: thirdTeamId },
      },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Ambiguous start payload" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    const startKey = startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3];

    await act(async () => {
      oldEnd.resolve(undefined);
      await oldEnd.promise;
      await Promise.resolve();
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Starting epoch…" }),
    ).toBeDisabled();

    await act(async () => {
      ambiguousStart.reject(new PhaseTwoApiError("ambiguous start", 503));
      await expect(ambiguousStart.promise).rejects.toThrow("ambiguous start");
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: thirdTeamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Ambiguous start payload" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3]).toBe(startKey);

    await act(async () => {
      retryStart.reject(new PhaseTwoApiError("retry cleanup", 503));
      await expect(retryStart.promise).rejects.toThrow("retry cleanup");
    });
  });

  it("keeps a same-key retry binding owned across an A-to-B-to-A stale success", async () => {
    const epochs = multiEpochFixtures();
    const oldAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const freshAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const retryAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const nextPayloadAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    let addCount = 0;
    const addOperatorTeamRosterEntry = vi.fn(
      (
        ..._arguments: Parameters<PhaseTwoApi["addOperatorTeamRosterEntry"]>
      ) => {
        addCount += 1;
        if (addCount === 1) return oldAdd.promise;
        if (addCount === 2) return freshAdd.promise;
        if (addCount === 3) return retryAdd.promise;
        return nextPayloadAdd.promise;
      },
    );
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(epochMutationPermissions),
    );
    renderTeams(
      multiEpochMutationApi(epochs, { addOperatorTeamRosterEntry }),
      epochMutationPermissions,
      { getTenantAuthority },
    );

    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Same exact-epoch payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );
    const sharedKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC B" });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC A epoch ${activeEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Same exact-epoch payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(sharedKey);

    const created = rosterFixture(activeEpochId, "Committed member", "active");
    await act(async () => {
      oldAdd.resolve({ etag: created.etag, value: created });
      await oldAdd.promise;
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Adding member…" }),
    ).toBeDisabled();

    await act(async () => {
      freshAdd.reject(new PhaseTwoApiError("ambiguous current add", 503));
      await expect(freshAdd.promise).rejects.toThrow("ambiguous current add");
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));

    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Same exact-epoch payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).toBe(sharedKey);

    await act(async () => {
      retryAdd.resolve({ etag: created.etag, value: created });
      await retryAdd.promise;
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(3));

    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "A genuinely new payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(4),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[3]?.[4]).not.toBe(sharedKey);
    expect(getTenantAuthority).toHaveBeenCalledTimes(3);

    await act(async () => {
      nextPayloadAdd.reject(new PhaseTwoApiError("new payload cleanup", 503));
      await expect(nextPayloadAdd.promise).rejects.toThrow(
        "new payload cleanup",
      );
    });
  });

  it("keeps ambiguous add bindings independent across exact epochs", async () => {
    const epochs = multiEpochFixtures();
    const addOperatorTeamRosterEntry = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("ambiguous epoch A", 503))
      .mockRejectedValueOnce(new PhaseTwoApiError("ambiguous epoch B", 503))
      .mockRejectedValueOnce(new PhaseTwoApiError("retry cleanup", 503));
    renderTeams(
      multiEpochMutationApi(epochs, { addOperatorTeamRosterEntry }),
      epochMutationPermissions,
    );

    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Ambiguous A payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    expect(await screen.findByText("ambiguous epoch A")).toBeVisible();
    const epochAKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC B" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Ambiguous B payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    expect(await screen.findByText("ambiguous epoch B")).toBeVisible();
    expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).not.toBe(epochAKey);

    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC A epoch ${activeEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC A" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Ambiguous A payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).toBe(epochAKey);
  });

  it("coalesces same-turn stale commits and preserves the current ambiguous add binding", async () => {
    const epochs = multiEpochFixtures();
    const endA = createDeferred<void>();
    const endB = createDeferred<void>();
    const endOperatorTeamAssignmentEpoch = vi.fn(
      (
        _csrfToken: string,
        _tenantId: string,
        _operatorTeamId: string,
        assignmentEpochId: string,
      ) => (assignmentEpochId === activeEpochId ? endA.promise : endB.promise),
    );
    const addOperatorTeamRosterEntry = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("ambiguous current add", 503))
      .mockRejectedValueOnce(new PhaseTwoApiError("retry cleanup", 503));
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(epochMutationPermissions),
    );
    renderTeams(
      multiEpochMutationApi(epochs, {
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
      { getTenantAuthority },
    );

    await startPendingEpochEnd("SOC A", "End A after handoff");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    await startPendingEpochEnd("SOC B", "End B after handoff");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC C epoch ${thirdEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC C" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Current ambiguous C payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    expect(await screen.findByText("ambiguous current add")).toBeVisible();
    const currentKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

    await act(async () => {
      endA.resolve(undefined);
      endB.resolve(undefined);
      await Promise.all([endA.promise, endB.promise]);
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open SOC C epoch ${thirdEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC C" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Current ambiguous C payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(currentKey);
  });

  it("queues one follow-up when a stale commit lands during a coordinated authority reload", async () => {
    const epochs = multiEpochFixtures();
    const endA = createDeferred<void>();
    const endB = createDeferred<void>();
    const firstReload = createDeferred<TenantAuthorityView>();
    const endOperatorTeamAssignmentEpoch = vi.fn(
      (
        _csrfToken: string,
        _tenantId: string,
        _operatorTeamId: string,
        assignmentEpochId: string,
      ) => (assignmentEpochId === activeEpochId ? endA.promise : endB.promise),
    );
    const addOperatorTeamRosterEntry = vi
      .fn()
      .mockRejectedValueOnce(
        new PhaseTwoApiError("ambiguous follow-up add", 503),
      )
      .mockRejectedValueOnce(new PhaseTwoApiError("retry cleanup", 503));
    let authorityLoads = 0;
    const getTenantAuthority = vi.fn(async () => {
      authorityLoads += 1;
      return authorityLoads === 2
        ? firstReload.promise
        : authorityFixture(epochMutationPermissions);
    });
    renderTeams(
      multiEpochMutationApi(epochs, {
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
      { getTenantAuthority },
    );

    await startPendingEpochEnd("SOC A", "First stale end");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC B epoch ${secondEpochId.slice(-8)}, active`,
      }),
    );
    await startPendingEpochEnd("SOC B", "Second stale end");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC C epoch ${thirdEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC C" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Follow-up C payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    expect(await screen.findByText("ambiguous follow-up add")).toBeVisible();
    const currentKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

    await act(async () => {
      endA.resolve(undefined);
      await endA.promise;
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));

    await act(async () => {
      endB.resolve(undefined);
      await endB.promise;
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);

    await act(async () => {
      firstReload.resolve(authorityFixture(epochMutationPermissions));
      await firstReload.promise;
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(3));
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(3);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open SOC C epoch ${thirdEpochId.slice(-8)}, active`,
      }),
    );
    await screen.findByRole("heading", { name: "Roster · SOC C" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Follow-up C payload" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(currentKey);
  });

  it("revalidates authority when a committed epoch mutation outlives its detail", async () => {
    const active = activeEpochFixture();
    const historical = historicalEpochFixture();
    const committed = createDeferred<void>();
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "operator_team.manage",
        "operator_team.read",
        "role.grant",
      ]),
    );
    const endOperatorTeamAssignmentEpoch = vi.fn(async () => committed.promise);
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch,
        getOperatorTeamAssignmentEpoch: async (
          _tenantId,
          _operatorTeamId,
          assignmentEpochId,
        ) => ({
          etag: assignmentEpochId === active.epochId ? '"v2"' : '"v3"',
          value: assignmentEpochId === active.epochId ? active : historical,
        }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [historical, active],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant"],
      { getTenantAuthority },
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Rotate after committed handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Open SOC L1 epoch ${historicalEpochId.slice(-8)}, ended`,
      }),
    );
    expect(await screen.findByText("History only")).toBeVisible();

    await act(async () => {
      committed.resolve(undefined);
      await committed.promise;
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
  });

  it("settles an exact-epoch mutation after the StrictMode effect remount", async () => {
    const initial = activeEpochFixture();
    const ended = historicalEpochFixture({
      endedAt: "2026-08-24T10:00:00Z",
      epochId: activeEpochId,
      version: 3,
    });
    let committed = false;
    const endOperatorTeamAssignmentEpoch = vi.fn(async () => {
      committed = true;
    });
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch,
        getOperatorTeamAssignmentEpoch: async () =>
          committed
            ? { etag: '"v3"', value: ended }
            : { etag: '"v2"', value: initial },
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [initial],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant"],
      { strict: true },
    );

    const reason = await screen.findByRole("textbox", { name: "End reason" });
    fireEvent.change(reason, { target: { value: "Strict-mode handoff" } });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );

    expect(await screen.findByText("History only")).toBeVisible();
    expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1);
  });

  it("aborts an old epoch page before a same-pair authority reload", async () => {
    const delayedPage = createDeferred<{
      items: OperatorTeamAssignmentEpochView[];
    }>();
    const refreshed = activeEpochFixture({
      operatorTeam: {
        id: teamId,
        key: "soc_refreshed",
        name: "Refreshed same-pair SOC",
        state: "active",
      },
    });
    const stale = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000470",
      operatorTeam: {
        id: "0198c97d-cf4f-7000-8000-000000000471",
        key: "stale_soc",
        name: "Stale same-pair page",
        state: "active",
      },
    });
    let initialLoads = 0;
    let pendingSignal: AbortSignal | undefined;
    const listTenantOperatorTeamAssignmentEpochs = vi.fn(
      async (
        _tenantId: string,
        options?: Parameters<
          PhaseTwoApi["listTenantOperatorTeamAssignmentEpochs"]
        >[1],
      ) => {
        if (options?.after) {
          pendingSignal = options.signal;
          return delayedPage.promise;
        }
        initialLoads += 1;
        return {
          items: [initialLoads === 1 ? activeEpochFixture() : refreshed],
          nextCursor: "epoch-cursor-a",
        };
      },
    );
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async (
        _tenantId,
        _operatorTeamId,
        assignmentEpochId,
      ) => ({
        etag: '"v2"',
        value:
          initialLoads > 1 && assignmentEpochId === refreshed.epochId
            ? refreshed
            : activeEpochFixture({ epochId: assignmentEpochId }),
      }),
      getTenantAuthority: async () => authorityFixture(["operator_team.read"]),
      listTenantOperatorTeamAssignmentEpochs,
    });
    render(<TenantAuthorityReloadHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more epochs" }),
    );
    await waitFor(() => expect(pendingSignal).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await waitFor(() => expect(pendingSignal?.aborted).toBe(true));
    expect(await screen.findByText(refreshed.operatorTeam.name)).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [stale] });
      await delayedPage.promise;
    });
    expect(screen.queryByText(stale.operatorTeam.name)).not.toBeInTheDocument();
  });

  it("clears a stale epoch pagination error when start triggers a full inventory reload", async () => {
    const initial = activeEpochFixture();
    const created = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000468",
      operatorTeam: {
        id: secondTeamId,
        key: "epoch_page_recovery",
        name: "Epoch pagination recovery",
        state: "active",
      },
      version: 1,
    });
    let inventoryLoads = 0;
    const listTenantOperatorTeamAssignmentEpochs = vi.fn(
      async (
        _tenantId: string,
        options?: Parameters<
          PhaseTwoApi["listTenantOperatorTeamAssignmentEpochs"]
        >[1],
      ) => {
        if (options?.after) {
          throw new PhaseTwoApiError("stale epoch page error", 503);
        }
        inventoryLoads += 1;
        return inventoryLoads === 1
          ? { items: [initial], nextCursor: "epoch-page-error" }
          : { items: [created] };
      },
    );
    const startOperatorTeamAssignmentEpoch = vi.fn(async () => ({
      etag: '"v1"',
      value: created,
    }));
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async (
          _tenantId,
          _operatorTeamId,
          assignmentEpochId,
        ) => ({
          etag: '"v1"',
          value: assignmentEpochId === created.epochId ? created : initial,
        }),
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs,
        startOperatorTeamAssignmentEpoch,
      }),
      ["operator_team.manage", "operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more epochs" }),
    );
    expect(await screen.findByText("stale epoch page error")).toBeVisible();

    fireEvent.change(
      screen.getByRole("textbox", { name: "Operator team ID" }),
      { target: { value: secondTeamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Recover the authoritative epoch inventory" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    expect(
      await screen.findByText(
        `${created.operatorTeam.name} started a new immutable epoch.`,
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        listTenantOperatorTeamAssignmentEpochs.mock.calls.length,
      ).toBeGreaterThanOrEqual(3),
    );
    expect(
      screen.queryByText("stale epoch page error"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Load more epochs" }),
    ).not.toBeInTheDocument();
  });

  it("unlocks epoch creation for a new tenant while an old start is pending", async () => {
    const pendingStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const startOperatorTeamAssignmentEpoch = vi.fn(
      async () => pendingStart.promise,
    );
    const permissions: TenantPermissionKeyView[] = [
      "operator_team.manage",
      "operator_team.read",
    ];
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(permissions, requestedTenantId),
      listTenantOperatorTeamAssignmentEpochs: async () => ({ items: [] }),
      startOperatorTeamAssignmentEpoch,
    });
    render(<SwitchingTenantHarness api={api} />);

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Pending handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Switch operator-team tenant" }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Start assignment epoch" }),
      ).toBeEnabled(),
    );
    expect(
      screen.getByRole("textbox", { name: "Operator team ID" }),
    ).toBeEnabled();

    await act(async () => {
      pendingStart.resolve({ etag: '"v2"', value: activeEpochFixture() });
      await pendingStart.promise;
    });
  });

  it("reuses the epoch-start idempotency key for a same-generation retry", async () => {
    const created = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000469",
      operatorTeam: {
        id: teamId,
        key: "retry_soc",
        name: "Retried SOC handoff",
        state: "active",
      },
    });
    let startCount = 0;
    const startOperatorTeamAssignmentEpoch = vi.fn(
      async (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => {
        startCount += 1;
        if (startCount === 1) {
          throw new PhaseTwoApiError("temporary start failure", 503);
        }
        return { etag: '"v2"', value: created };
      },
    );
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async () => ({
        etag: '"v2"',
        value: created,
      }),
      listTenantOperatorTeamAssignmentEpochs: async () => ({
        items: startCount >= 2 ? [created] : [],
      }),
      startOperatorTeamAssignmentEpoch,
    });
    renderTeams(api, ["operator_team.manage", "operator_team.read"]);

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Retry the same handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    expect(await screen.findByText("temporary start failure")).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3]).toBe(
      startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3],
    );
    expect(
      await screen.findByText(
        `${created.operatorTeam.name} started a new immutable epoch.`,
      ),
    ).toBeVisible();
    expect(await screen.findByText(created.operatorTeam.name)).toBeVisible();
    expect(
      await screen.findByRole("heading", {
        name: `Roster · ${created.operatorTeam.name}`,
      }),
    ).toBeVisible();
  });

  it("reports an ended fulfilled start replay as historical and releases its payload key", async () => {
    const ended = historicalEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000469",
      operatorTeam: {
        id: teamId,
        key: "ended_retry_soc",
        name: "Ended replay SOC",
        state: "active",
      },
    });
    let committed = false;
    const startOperatorTeamAssignmentEpoch = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("ambiguous ended start", 503))
      .mockImplementationOnce(async () => {
        committed = true;
        return { etag: '"v3"', value: ended };
      })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("fresh ended start cleanup", 503),
      );
    renderTeams(
      createPhaseTwoApi({
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v3"',
          value: ended,
        }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: committed ? [ended] : [],
        }),
        startOperatorTeamAssignmentEpoch,
      }),
      ["operator_team.manage", "operator_team.read"],
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Replay an ended handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    expect(await screen.findByText("ambiguous ended start")).toBeVisible();
    const retainedKey = startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3];

    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3]).toBe(
      retainedKey,
    );
    expect(
      await screen.findByText("Assignment epoch is historical"),
    ).toBeVisible();
    expect(
      screen.getByText(
        `${ended.operatorTeam.name} returned an ended historical epoch. It provides no current tenant coverage.`,
      ),
    ).toBeVisible();
    expect(
      screen.queryByText(
        `${ended.operatorTeam.name} started a new immutable epoch.`,
      ),
    ).not.toBeInTheDocument();
    expect(await screen.findByText("History only")).toBeVisible();

    fireEvent.change(
      screen.getByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Replay an ended handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(3),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[2]?.[3]).not.toBe(
      retainedKey,
    );
    expect(await screen.findByText("fresh ended start cleanup")).toBeVisible();
  });

  it("rejects an old tenant-A start completion after an A-to-B-to-A cycle", async () => {
    const oldStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const freshStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    let startCount = 0;
    const startOperatorTeamAssignmentEpoch = vi.fn(
      async (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => {
        startCount += 1;
        return startCount === 1 ? oldStart.promise : freshStart.promise;
      },
    );
    const permissions: TenantPermissionKeyView[] = [
      "operator_team.manage",
      "operator_team.read",
    ];
    const freshEpoch = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000471",
      operatorTeam: {
        id: teamId,
        key: "fresh_a",
        name: "Fresh tenant A completion",
        state: "active",
      },
    });
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async () => ({
        etag: '"v2"',
        value: freshEpoch,
      }),
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(permissions, requestedTenantId),
      listTenantOperatorTeamAssignmentEpochs: async () => ({
        items: startCount >= 2 ? [freshEpoch] : [],
      }),
      startOperatorTeamAssignmentEpoch,
    });
    render(<SwitchingTenantHarness api={api} />);

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Repeated A handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Switch operator-team tenant" }),
    );
    await screen.findByRole("textbox", { name: "Operator team ID" });
    fireEvent.click(
      screen.getByRole("button", { name: "Switch operator-team tenant" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Repeated A handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3]).not.toBe(
      startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3],
    );

    await act(async () => {
      oldStart.resolve({
        etag: '"v2"',
        value: activeEpochFixture({
          epochId: "0198c97d-cf4f-7000-8000-000000000470",
          operatorTeam: {
            id: teamId,
            key: "old_a",
            name: "Old tenant A completion",
            state: "active",
          },
        }),
      });
      await oldStart.promise;
    });

    expect(
      screen.getByRole("button", { name: "Starting epoch…" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", { name: "Operator team ID" }),
    ).toHaveValue(teamId);
    expect(
      screen.getByRole("textbox", { name: "Assignment reason" }),
    ).toHaveValue("Repeated A handoff");
    expect(
      screen.queryByText("Old tenant A completion"),
    ).not.toBeInTheDocument();

    await act(async () => {
      freshStart.resolve({ etag: '"v2"', value: freshEpoch });
      await freshStart.promise;
    });
    expect(
      await screen.findByText(
        "Fresh tenant A completion started a new immutable epoch.",
      ),
    ).toBeVisible();
    expect(await screen.findByText("Fresh tenant A completion")).toBeVisible();
    expect(
      await screen.findByRole("heading", {
        name: "Roster · Fresh tenant A completion",
      }),
    ).toBeVisible();
  });

  it("starts a fresh epoch generation after same-pair authority loss and restoration", async () => {
    const oldStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const freshStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    let startCount = 0;
    const startOperatorTeamAssignmentEpoch = vi.fn(
      async (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => {
        startCount += 1;
        return startCount === 1 ? oldStart.promise : freshStart.promise;
      },
    );
    const managePermissions: TenantPermissionKeyView[] = [
      "operator_team.manage",
      "operator_team.read",
    ];
    let authorityLoad = 0;
    const getTenantAuthority = vi.fn(async () => {
      authorityLoad += 1;
      return authorityLoad === 2
        ? authorityFixture(["operator_team.read"])
        : authorityFixture(managePermissions);
    });
    const freshEpoch = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000472",
      operatorTeam: {
        id: teamId,
        key: "fresh_authority",
        name: "Fresh authority completion",
        state: "active",
      },
    });
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async () => ({
        etag: '"v2"',
        value: freshEpoch,
      }),
      getTenantAuthority,
      listTenantOperatorTeamAssignmentEpochs: async () => ({
        items: startCount >= 2 ? [freshEpoch] : [],
      }),
      startOperatorTeamAssignmentEpoch,
    });
    render(<TenantAuthorityReloadHarness api={api} />);

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Repeated authority handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Start assignment epoch" }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    const teamInput = await screen.findByRole("textbox", {
      name: "Operator team ID",
    });
    expect(teamInput).toBeEnabled();
    fireEvent.change(teamInput, { target: { value: teamId } });
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Repeated authority handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3]).not.toBe(
      startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3],
    );

    await act(async () => {
      oldStart.reject(new PhaseTwoApiError("old authority start failed", 412));
      await expect(oldStart.promise).rejects.toThrow(
        "old authority start failed",
      );
    });
    expect(
      screen.queryByText("old authority start failed"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Starting epoch…" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", { name: "Operator team ID" }),
    ).toHaveValue(teamId);
    expect(
      screen.getByRole("textbox", { name: "Assignment reason" }),
    ).toHaveValue("Repeated authority handoff");

    await act(async () => {
      freshStart.resolve({ etag: '"v2"', value: freshEpoch });
      await freshStart.promise;
    });
    expect(
      await screen.findByText(
        "Fresh authority completion started a new immutable epoch.",
      ),
    ).toBeVisible();
    expect(await screen.findByText("Fresh authority completion")).toBeVisible();
    expect(
      await screen.findByRole("heading", {
        name: "Roster · Fresh authority completion",
      }),
    ).toBeVisible();
  });

  it("queues a stale start commit behind a fresh child without releasing the child owner", async () => {
    const oldStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const pendingEnd = createDeferred<void>();
    const staleCreated = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000473",
      operatorTeam: {
        id: thirdTeamId,
        key: "stale_start",
        name: "Stale start completion",
        state: "active",
      },
    });
    const startOperatorTeamAssignmentEpoch = vi.fn(() => oldStart.promise);
    const endOperatorTeamAssignmentEpoch = vi.fn(() => pendingEnd.promise);
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(epochMutationPermissions),
    );
    render(
      <TenantAuthorityReloadHarness
        api={epochMutationApi({
          endOperatorTeamAssignmentEpoch,
          getTenantAuthority,
          startOperatorTeamAssignmentEpoch,
        })}
      />,
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: thirdTeamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Old start becomes stale" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Reload same-pair authority" }),
    );
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await screen.findByRole("heading", { name: "Roster · SOC L1" });
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Fresh child owns the lease" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() =>
      expect(endOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    await act(async () => {
      oldStart.resolve({ etag: '"v2"', value: staleCreated });
      await oldStart.promise;
      await Promise.resolve();
    });
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", { name: "Ending epoch…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "End reason" })).toHaveValue(
      "Fresh child owns the lease",
    );
    expect(
      screen.queryByText("Stale start completion"),
    ).not.toBeInTheDocument();

    await act(async () => {
      pendingEnd.reject(new PhaseTwoApiError("fresh child rejected", 503));
      await expect(pendingEnd.promise).rejects.toThrow("fresh child rejected");
    });
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(3));
    expect(
      await screen.findByRole("button", { name: "Start assignment epoch" }),
    ).toBeEnabled();
  });

  it("discards a delayed tenant-A epoch page after switching to tenant B", async () => {
    const delayedA = createDeferred<{
      items: OperatorTeamAssignmentEpochView[];
    }>();
    const listTenantOperatorTeamAssignmentEpochs = vi.fn(
      async (requestedTenantId: string) =>
        requestedTenantId === tenantId
          ? delayedA.promise
          : {
              items: [
                activeEpochFixture({
                  epochId: "0198c97d-cf4f-7000-8000-000000000411",
                  operatorTeam: {
                    id: teamId,
                    key: "soc_l2",
                    name: "Tenant B SOC L2",
                    state: "active",
                  },
                  tenantId: otherTenantId,
                }),
              ],
            },
    );
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async (
        requestedTenantId,
        _teamId,
        assignmentEpochId,
      ) => ({
        etag: '"v2"',
        value: activeEpochFixture({
          epochId: assignmentEpochId,
          operatorTeam: {
            id: teamId,
            key: "soc_l2",
            name: "Tenant B SOC L2",
            state: "active",
          },
          tenantId: requestedTenantId,
        }),
      }),
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["operator_team.read"], requestedTenantId),
      listTenantOperatorTeamAssignmentEpochs,
    });
    render(<SwitchingTenantHarness api={api} />);

    await waitFor(() =>
      expect(listTenantOperatorTeamAssignmentEpochs).toHaveBeenCalledWith(
        tenantId,
        expect.any(Object),
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Switch operator-team tenant" }),
    );
    expect(await screen.findByText("Tenant B SOC L2")).toBeVisible();

    await act(async () => {
      delayedA.resolve({
        items: [
          activeEpochFixture({
            operatorTeam: {
              id: teamId,
              key: "late_a",
              name: "Late tenant A team",
              state: "active",
            },
          }),
        ],
      });
      await delayedA.promise;
    });
    expect(screen.queryByText("Late tenant A team")).not.toBeInTheDocument();
    expect(screen.getByText("Tenant B SOC L2")).toBeVisible();
  });

  it("aborts and isolates a pending tenant-member page across a tenant switch", async () => {
    const delayedPage = createDeferred<{
      items: TenantUserSummaryView[];
    }>();
    const tenantAUser = tenantUserFixture({
      user: {
        active: true,
        displayName: "Tenant A member",
        email: "tenant-a@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000441",
      },
    });
    const tenantBUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000442",
      tenantId: otherTenantId,
      user: {
        active: true,
        displayName: "Tenant B member",
        email: "tenant-b@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000443",
      },
    });
    const lateTenantAUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000444",
      user: {
        active: true,
        displayName: "Late tenant A member",
        email: "late-a@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000445",
      },
    });
    let pendingSignal: AbortSignal | undefined;
    const listTenantUsers = vi.fn(
      async (
        requestedTenantId: string,
        after?: string,
        signal?: AbortSignal,
      ) => {
        if (after) {
          pendingSignal = signal;
          return delayedPage.promise;
        }
        return requestedTenantId === tenantId
          ? { items: [tenantAUser], nextCursor: "tenant-a-more" }
          : { items: [tenantBUser] };
      },
    );
    const api = pairIsolationApi(listTenantUsers);
    render(<SwitchingTenantHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    await waitFor(() => expect(pendingSignal).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "Switch operator-team tenant" }),
    );
    await waitFor(() => expect(pendingSignal?.aborted).toBe(true));
    const tenantBPicker = await screen.findByRole("combobox", {
      name: "Tenant member",
    });
    await waitFor(() => expect(tenantBPicker).toBeEnabled());
    fireEvent.click(tenantBPicker);
    expect(
      await screen.findByRole("option", {
        name: "Tenant B member · tenant-b@example.invalid",
      }),
    ).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [lateTenantAUser] });
      await delayedPage.promise;
    });
    expect(
      screen.queryByRole("option", {
        name: "Late tenant A member · late-a@example.invalid",
      }),
    ).not.toBeInTheDocument();
  });

  it("aborts and isolates a pending tenant-member page across a session rotation", async () => {
    const delayedPage = createDeferred<{
      items: TenantUserSummaryView[];
    }>();
    const oldSessionUser = tenantUserFixture({
      user: {
        active: true,
        displayName: "Old session member",
        email: "old-session@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000451",
      },
    });
    const freshSessionUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000452",
      user: {
        active: true,
        displayName: "Fresh session member",
        email: "fresh-session@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000453",
      },
    });
    const lateOldSessionUser = tenantUserFixture({
      membershipId: "0198c97d-cf4f-7000-8000-000000000454",
      user: {
        active: true,
        displayName: "Late old session member",
        email: "late-session@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000455",
      },
    });
    let initialPage = 0;
    let pendingSignal: AbortSignal | undefined;
    const listTenantUsers = vi.fn(
      async (_tenantId: string, after?: string, signal?: AbortSignal) => {
        if (after) {
          pendingSignal = signal;
          return delayedPage.promise;
        }
        initialPage += 1;
        return initialPage === 1
          ? { items: [oldSessionUser], nextCursor: "old-session-more" }
          : { items: [freshSessionUser] };
      },
    );
    const api = pairIsolationApi(listTenantUsers);
    render(<SwitchingTenantHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more users" }),
    );
    await waitFor(() => expect(pendingSignal).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "Rotate operator-team session" }),
    );
    await waitFor(() => expect(pendingSignal?.aborted).toBe(true));
    const freshSessionPicker = await screen.findByRole("combobox", {
      name: "Tenant member",
    });
    await waitFor(() => expect(freshSessionPicker).toBeEnabled());
    fireEvent.click(freshSessionPicker);
    expect(
      await screen.findByRole("option", {
        name: "Fresh session member · fresh-session@example.invalid",
      }),
    ).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [lateOldSessionUser] });
      await delayedPage.promise;
    });
    expect(
      screen.queryByRole("option", {
        name: "Late old session member · late-session@example.invalid",
      }),
    ).not.toBeInTheDocument();
  });

  it("keeps a stale route start pair-bound while a remounted tenant start retains its retry key", async () => {
    const oldTenantStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const ambiguousTenantStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const retryTenantStart =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const committedTenantEpoch = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000481",
      operatorTeam: {
        id: teamId,
        key: "route_a_committed",
        name: "Route A committed epoch",
        state: "active",
      },
    });
    let startCall = 0;
    let tenantACommitted = false;
    const startOperatorTeamAssignmentEpoch = vi.fn(
      (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => {
        startCall += 1;
        if (startCall === 1) return oldTenantStart.promise;
        if (startCall === 2) return ambiguousTenantStart.promise;
        return retryTenantStart.promise;
      },
    );
    const getTenantAuthority = vi.fn(async (requestedTenantId: string) =>
      authorityFixture(
        ["operator_team.manage", "operator_team.read"],
        requestedTenantId,
      ),
    );
    const api = createPhaseTwoApi({
      getOperatorTeamAssignmentEpoch: async () => ({
        etag: '"v2"',
        value: committedTenantEpoch,
      }),
      getTenantAuthority,
      listTenantOperatorTeamAssignmentEpochs: async (requestedTenantId) => ({
        items:
          requestedTenantId === tenantId && tenantACommitted
            ? [committedTenantEpoch]
            : [],
      }),
      startOperatorTeamAssignmentEpoch,
    });
    render(<PersistentTenantRouteHarness api={api} />);

    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: teamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Old tenant A route start" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Assignment epochs & roster" }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Switch persistent operator-team tenant",
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: secondTeamId } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Assignment reason" }),
      { target: { value: "Fresh tenant B route start" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    const tenantBKey = startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3];
    const tenantBAuthorityLoads = getTenantAuthority.mock.calls.filter(
      ([requestedTenantId]) => requestedTenantId === otherTenantId,
    ).length;

    await act(async () => {
      tenantACommitted = true;
      oldTenantStart.resolve({ etag: '"v2"', value: committedTenantEpoch });
      await oldTenantStart.promise;
      await Promise.resolve();
    });
    expect(
      getTenantAuthority.mock.calls.filter(
        ([requestedTenantId]) => requestedTenantId === otherTenantId,
      ),
    ).toHaveLength(tenantBAuthorityLoads);
    expect(
      screen.getByRole("button", { name: "Starting epoch…" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", { name: "Assignment reason" }),
    ).toHaveValue("Fresh tenant B route start");
    expect(
      screen.queryByText("Route A committed epoch"),
    ).not.toBeInTheDocument();

    await act(async () => {
      ambiguousTenantStart.reject(
        new PhaseTwoApiError("ambiguous tenant B start", 503),
      );
      await expect(ambiguousTenantStart.promise).rejects.toThrow(
        "ambiguous tenant B start",
      );
    });
    expect(await screen.findByText("ambiguous tenant B start")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(3),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[2]?.[3]).toBe(
      tenantBKey,
    );
    await act(async () => {
      retryTenantStart.reject(new PhaseTwoApiError("retry cleanup", 503));
      await expect(retryTenantStart.promise).rejects.toThrow("retry cleanup");
    });

    fireEvent.click(
      screen.getByRole("button", {
        name: "Switch persistent operator-team tenant",
      }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Roster · Route A committed epoch",
      }),
    ).toBeVisible();
    expect(
      getTenantAuthority.mock.calls.filter(
        ([requestedTenantId]) => requestedTenantId === tenantId,
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it("keeps a stale route add pair-bound while a remounted tenant add retains its retry key", async () => {
    const oldTenantAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const ambiguousTenantAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const retryTenantAdd =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
      >();
    const tenantAEpoch = activeEpochFixture();
    const tenantBEpoch = activeEpochFixture({
      epochId: secondEpochId,
      operatorTeam: {
        id: secondTeamId,
        key: "tenant_b_soc",
        name: "Tenant B SOC",
        state: "active",
      },
      tenantId: otherTenantId,
    });
    const committedRosterEntry = rosterFixture(
      activeEpochId,
      "Route A committed member",
      "active",
    );
    let addCall = 0;
    let tenantARosterCommitted = false;
    const addOperatorTeamRosterEntry = vi.fn(
      (
        ..._arguments: Parameters<PhaseTwoApi["addOperatorTeamRosterEntry"]>
      ) => {
        addCall += 1;
        if (addCall === 1) return oldTenantAdd.promise;
        if (addCall === 2) return ambiguousTenantAdd.promise;
        return retryTenantAdd.promise;
      },
    );
    const getTenantAuthority = vi.fn(async (requestedTenantId: string) =>
      authorityFixture(epochMutationPermissions, requestedTenantId),
    );
    const api = createPhaseTwoApi({
      addOperatorTeamRosterEntry,
      getOperatorTeamAssignmentEpoch: async (requestedTenantId) => ({
        etag: '"v2"',
        value: requestedTenantId === tenantId ? tenantAEpoch : tenantBEpoch,
      }),
      getTenantAuthority,
      listOperatorTeamRosterEntries: async (requestedTenantId) => ({
        items:
          requestedTenantId === tenantId && tenantARosterCommitted
            ? [committedRosterEntry]
            : [],
      }),
      listTenantOperatorTeamAssignmentEpochs: async (requestedTenantId) => ({
        items: [requestedTenantId === tenantId ? tenantAEpoch : tenantBEpoch],
      }),
      listTenantUsers: async (requestedTenantId) => ({
        items: [tenantUserFixture({ tenantId: requestedTenantId })],
      }),
    });
    render(<PersistentTenantRouteHarness api={api} />);

    await screen.findByRole("heading", { name: "Roster · SOC L1" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Old tenant A route add" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Assignment epochs & roster" }),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Switch persistent operator-team tenant",
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await screen.findByRole("heading", { name: "Roster · Tenant B SOC" });
    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Fresh tenant B route add" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
    );
    const tenantBKey = addOperatorTeamRosterEntry.mock.calls[1]?.[4];
    const tenantBAuthorityLoads = getTenantAuthority.mock.calls.filter(
      ([requestedTenantId]) => requestedTenantId === otherTenantId,
    ).length;

    await act(async () => {
      tenantARosterCommitted = true;
      oldTenantAdd.resolve({
        etag: committedRosterEntry.etag,
        value: committedRosterEntry,
      });
      await oldTenantAdd.promise;
      await Promise.resolve();
    });
    expect(
      getTenantAuthority.mock.calls.filter(
        ([requestedTenantId]) => requestedTenantId === otherTenantId,
      ),
    ).toHaveLength(tenantBAuthorityLoads);
    expect(
      screen.getByRole("button", { name: "Adding member…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Roster reason" })).toHaveValue(
      "Fresh tenant B route add",
    );
    expect(
      screen.queryByText("Route A committed member"),
    ).not.toBeInTheDocument();

    await act(async () => {
      ambiguousTenantAdd.reject(
        new PhaseTwoApiError("ambiguous tenant B add", 503),
      );
      await expect(ambiguousTenantAdd.promise).rejects.toThrow(
        "ambiguous tenant B add",
      );
    });
    expect(await screen.findByText("ambiguous tenant B add")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    await waitFor(() =>
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
    );
    expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).toBe(tenantBKey);
    await act(async () => {
      retryTenantAdd.reject(new PhaseTwoApiError("retry cleanup", 503));
      await expect(retryTenantAdd.promise).rejects.toThrow("retry cleanup");
    });

    fireEvent.click(
      screen.getByRole("button", {
        name: "Switch persistent operator-team tenant",
      }),
    );
    expect(await screen.findByText("Route A committed member")).toBeVisible();
    expect(
      getTenantAuthority.mock.calls.filter(
        ([requestedTenantId]) => requestedTenantId === tenantId,
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it("releases a fulfilled detached start but preserves its successor's ambiguous binding", async () => {
    const detachedSuccess =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const staleSuccess =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const ambiguousSuccessor =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const retry =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["startOperatorTeamAssignmentEpoch"]>>
      >();
    const created = activeEpochFixture({
      epochId: "0198c97d-cf4f-7000-8000-000000000491",
    });
    const pending = [detachedSuccess, staleSuccess, ambiguousSuccessor, retry];
    const startOperatorTeamAssignmentEpoch = vi.fn(
      (
        ..._arguments: Parameters<
          PhaseTwoApi["startOperatorTeamAssignmentEpoch"]
        >
      ) => pending.shift()!.promise,
    );
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture(["operator_team.manage", "operator_team.read"]),
    );
    const api = createPhaseTwoApi({
      getTenantAuthority,
      listTenantOperatorTeamAssignmentEpochs: async () => ({ items: [] }),
      startOperatorTeamAssignmentEpoch,
    });
    render(<PersistentTenantRouteHarness api={api} />);

    async function submitSameStart(): Promise<void> {
      fireEvent.change(
        await screen.findByRole("textbox", { name: "Operator team ID" }),
        { target: { value: teamId } },
      );
      fireEvent.change(
        screen.getByRole("textbox", { name: "Assignment reason" }),
        { target: { value: "Persist this exact tenant start" } },
      );
      fireEvent.click(
        screen.getByRole("button", { name: "Start assignment epoch" }),
      );
    }

    await submitSameStart();
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(1),
    );
    const boundKey = startOperatorTeamAssignmentEpoch.mock.calls[0]?.[3];
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await act(async () => {
      detachedSuccess.resolve({ etag: '"v2"', value: created });
      await detachedSuccess.promise;
      await Promise.resolve();
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await submitSameStart();
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(2),
    );
    const successorKey = startOperatorTeamAssignmentEpoch.mock.calls[1]?.[3];
    expect(successorKey).not.toBe(boundKey);

    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await submitSameStart();
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(3),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[2]?.[3]).toBe(
      successorKey,
    );

    await act(async () => {
      staleSuccess.resolve({ etag: '"v2"', value: created });
      await staleSuccess.promise;
      await Promise.resolve();
    });
    expect(
      screen.getByRole("button", { name: "Starting epoch…" }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );

    await act(async () => {
      ambiguousSuccessor.reject(
        new PhaseTwoApiError("ambiguous remounted start", 503),
      );
      await expect(ambiguousSuccessor.promise).rejects.toThrow(
        "ambiguous remounted start",
      );
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Toggle persistent operator-team route",
      }),
    );
    await submitSameStart();
    await waitFor(() =>
      expect(startOperatorTeamAssignmentEpoch).toHaveBeenCalledTimes(4),
    );
    expect(startOperatorTeamAssignmentEpoch.mock.calls[3]?.[3]).toBe(
      successorKey,
    );
    await act(async () => {
      retry.reject(new PhaseTwoApiError("retry cleanup", 503));
      await expect(retry.promise).rejects.toThrow("retry cleanup");
    });
  });

  it("releases a fulfilled detached add but preserves its successor through expiry", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.setSystemTime(new Date("2026-08-24T10:00:00Z"));
      const detachedSuccess =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
        >();
      const staleSuccess =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
        >();
      const ambiguousSuccessor =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
        >();
      const finalRetry =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["addOperatorTeamRosterEntry"]>>
        >();
      const pending = [
        detachedSuccess,
        staleSuccess,
        ambiguousSuccessor,
        finalRetry,
      ];
      const addOperatorTeamRosterEntry = vi.fn(
        (
          ..._arguments: Parameters<PhaseTwoApi["addOperatorTeamRosterEntry"]>
        ) => pending.shift()!.promise,
      );
      const epoch = activeEpochFixture();
      const created = rosterFixture(
        activeEpochId,
        "Persisted remount member",
        "active",
      );
      const getTenantAuthority = vi.fn(async () =>
        authorityFixture(epochMutationPermissions),
      );
      const api = createPhaseTwoApi({
        addOperatorTeamRosterEntry,
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        getTenantAuthority,
        listOperatorTeamRosterEntries: async () => ({ items: [] }),
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
        listTenantUsers: async () => ({ items: [tenantUserFixture()] }),
      });
      render(<PersistentTenantRouteHarness api={api} />);

      async function submitSameAdd(): Promise<void> {
        await screen.findByRole("heading", { name: "Roster · SOC L1" });
        await selectEpochMutationMember();
        fireEvent.change(
          screen.getByRole("textbox", { name: "Roster reason" }),
          { target: { value: "Persist exact roster coverage" } },
        );
        fireEvent.change(screen.getByRole("textbox", { name: "Expires at" }), {
          target: { value: "2026-08-24T10:01:00.123456Z" },
        });
        fireEvent.click(
          screen.getByRole("button", { name: "Add roster member" }),
        );
      }

      await submitSameAdd();
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1),
      );
      const boundKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];
      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );
      await act(async () => {
        detachedSuccess.resolve({ etag: created.etag, value: created });
        await detachedSuccess.promise;
        await Promise.resolve();
      });

      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );
      await submitSameAdd();
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2),
      );
      const successorKey = addOperatorTeamRosterEntry.mock.calls[1]?.[4];
      expect(successorKey).not.toBe(boundKey);

      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );
      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );
      await submitSameAdd();
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(3),
      );
      expect(addOperatorTeamRosterEntry.mock.calls[2]?.[4]).toBe(successorKey);

      await act(async () => {
        staleSuccess.resolve({ etag: created.etag, value: created });
        await staleSuccess.promise;
        await Promise.resolve();
      });
      expect(
        screen.getByRole("button", { name: "Adding member…" }),
      ).toBeDisabled();
      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );

      await act(async () => {
        ambiguousSuccessor.reject(
          new PhaseTwoApiError("ambiguous remounted add", 503),
        );
        await expect(ambiguousSuccessor.promise).rejects.toThrow(
          "ambiguous remounted add",
        );
      });

      vi.setSystemTime(new Date("2026-08-24T10:02:00Z"));
      fireEvent.click(
        screen.getByRole("button", {
          name: "Toggle persistent operator-team route",
        }),
      );
      await submitSameAdd();
      await waitFor(() =>
        expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(4),
      );
      expect(addOperatorTeamRosterEntry.mock.calls[3]?.[4]).toBe(successorKey);
      await act(async () => {
        finalRetry.reject(new PhaseTwoApiError("retry cleanup", 503));
        await expect(finalRetry.promise).rejects.toThrow("retry cleanup");
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts a pre-end roster page and ignores it after the ended roster refresh", async () => {
    const latePage = createDeferred<{
      items: OperatorTeamRosterEntryView[];
    }>();
    const active = activeEpochFixture();
    const ended = historicalEpochFixture({ epochId: activeEpochId });
    const first = rosterFixture(
      activeEpochId,
      "Initial active member",
      "active",
    );
    const refreshed = rosterFixture(
      activeEpochId,
      "Post-end historical member",
      "expired",
      { id: "0198c97d-cf4f-7000-8000-000000000492" },
    );
    const stale = rosterFixture(
      activeEpochId,
      "Late pre-end active member",
      "active",
      { id: "0198c97d-cf4f-7000-8000-000000000493" },
    );
    let epochLoad = 0;
    let rosterLoad = 0;
    let lateSignal: AbortSignal | undefined;
    const listOperatorTeamRosterEntries = vi.fn(
      async (
        _tenantId: string,
        _operatorTeamId: string,
        _epochId: string,
        options: { after?: string; signal?: AbortSignal },
      ) => {
        if (options.after) {
          lateSignal = options.signal;
          return latePage.promise;
        }
        rosterLoad += 1;
        return rosterLoad === 1
          ? { items: [first], nextCursor: "pre-end-more" }
          : { items: [refreshed] };
      },
    );
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch: async () => undefined,
        getOperatorTeamAssignmentEpoch: async () => {
          epochLoad += 1;
          return {
            etag: epochLoad === 1 ? '"v2"' : '"v3"',
            value: epochLoad === 1 ? active : ended,
          };
        },
        listOperatorTeamRosterEntries,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [active],
        }),
        listTenantUsers: async () => ({ items: [] }),
      }),
      epochMutationPermissions,
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Load more roster entries",
      }),
    );
    await waitFor(() => expect(lateSignal).toBeDefined());
    fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
      target: { value: "Close exact assignment epoch" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() => expect(lateSignal?.aborted).toBe(true));
    expect(await screen.findByText("Post-end historical member")).toBeVisible();
    expect(screen.getByText("History only")).toBeVisible();

    await act(async () => {
      latePage.resolve({ items: [stale] });
      await latePage.promise;
    });
    expect(
      screen.queryByText("Late pre-end active member"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Post-end historical member")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Load more roster entries" }),
    ).not.toBeInTheDocument();
  });

  it("aborts a pre-end first roster page before history mode even when exact refresh fails", async () => {
    const preEndRoster = createDeferred<{
      items: OperatorTeamRosterEntryView[];
    }>();
    const exactRefresh =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["getOperatorTeamAssignmentEpoch"]>>
      >();
    const active = activeEpochFixture();
    let epochLoad = 0;
    let rosterLoad = 0;
    let preEndSignal: AbortSignal | undefined;
    const getOperatorTeamAssignmentEpoch = vi.fn(() => {
      epochLoad += 1;
      return epochLoad === 1
        ? Promise.resolve({ etag: '"v2"', value: active })
        : exactRefresh.promise;
    });
    const listOperatorTeamRosterEntries = vi.fn(
      async (
        _tenantId: string,
        _operatorTeamId: string,
        _epochId: string,
        options: { signal?: AbortSignal },
      ) => {
        rosterLoad += 1;
        if (rosterLoad === 1) {
          preEndSignal = options.signal;
          return preEndRoster.promise;
        }
        return { items: [] };
      },
    );
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch: async () => undefined,
        getOperatorTeamAssignmentEpoch,
        listOperatorTeamRosterEntries,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [active],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant", "user.read"],
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Commit before exact refresh" } },
    );
    await waitFor(() => expect(preEndSignal).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    await waitFor(() => expect(preEndSignal?.aborted).toBe(true));
    expect(await screen.findByText("History only")).toBeVisible();
    await waitFor(() =>
      expect(listOperatorTeamRosterEntries).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      preEndRoster.resolve({
        items: [
          rosterFixture(
            activeEpochId,
            "Forbidden pre-end first-page member",
            "active",
          ),
        ],
      });
      await preEndRoster.promise;
    });
    expect(
      screen.queryByText("Forbidden pre-end first-page member"),
    ).not.toBeInTheDocument();

    await act(async () => {
      exactRefresh.reject(new Error("exact refresh unavailable"));
      await expect(exactRefresh.promise).rejects.toThrow(
        "exact refresh unavailable",
      );
    });
    expect(
      screen.queryByText("Forbidden pre-end first-page member"),
    ).not.toBeInTheDocument();
  });

  it("still accepts the initial roster page after an overlapping mutation fails", async () => {
    const initialRoster = createDeferred<{
      items: OperatorTeamRosterEntryView[];
    }>();
    const epoch = activeEpochFixture();
    renderTeams(
      createPhaseTwoApi({
        endOperatorTeamAssignmentEpoch: async () => {
          throw new PhaseTwoApiError("end rejected", 409);
        },
        getOperatorTeamAssignmentEpoch: async () => ({
          etag: '"v2"',
          value: epoch,
        }),
        listOperatorTeamRosterEntries: async () => initialRoster.promise,
        listTenantOperatorTeamAssignmentEpochs: async () => ({
          items: [epoch],
        }),
      }),
      ["operator_team.manage", "operator_team.read", "role.grant", "user.read"],
    );

    fireEvent.change(
      await screen.findByRole("textbox", { name: "End reason" }),
      { target: { value: "Rejected boundary attempt" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    expect(await screen.findByText("end rejected")).toBeVisible();
    await act(async () => {
      initialRoster.resolve({
        items: [
          rosterFixture(activeEpochId, "Roster survived failure", "active"),
        ],
      });
      await initialRoster.promise;
    });
    expect(await screen.findByText("Roster survived failure")).toBeVisible();
  });

  it("rejects control characters inline for every tenant mutation reason without an API call", async () => {
    const startOperatorTeamAssignmentEpoch = vi.fn();
    const endOperatorTeamAssignmentEpoch = vi.fn();
    const addOperatorTeamRosterEntry = vi.fn();
    const revokeOperatorTeamRosterEntry = vi.fn();
    renderTeams(
      epochMutationApi({
        addOperatorTeamRosterEntry,
        endOperatorTeamAssignmentEpoch,
        revokeOperatorTeamRosterEntry,
        startOperatorTeamAssignmentEpoch,
      }),
      epochMutationPermissions,
    );

    const invalidReason = "Unsafe\u0085reason";
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Operator team ID" }),
      { target: { value: secondTeamId } },
    );
    const startReason = screen.getByRole("textbox", {
      name: "Assignment reason",
    });
    fireEvent.change(startReason, { target: { value: invalidReason } });
    fireEvent.click(
      screen.getByRole("button", { name: "Start assignment epoch" }),
    );
    await waitFor(() =>
      expect(startReason).toHaveAttribute("aria-invalid", "true"),
    );
    expect(startReason).toHaveAccessibleDescription(
      "Use a reason without control characters.",
    );

    const endReason = await screen.findByRole("textbox", {
      name: "End reason",
    });
    fireEvent.change(endReason, { target: { value: invalidReason } });
    fireEvent.click(
      screen.getByRole("button", { name: "End assignment epoch" }),
    );
    expect(endReason).toHaveAttribute("aria-invalid", "true");
    expect(endReason).toHaveAccessibleDescription(
      "Use a reason without control characters.",
    );

    await selectEpochMutationMember();
    const addReason = screen.getByRole("textbox", { name: "Roster reason" });
    fireEvent.change(addReason, { target: { value: invalidReason } });
    fireEvent.click(screen.getByRole("button", { name: "Add roster member" }));
    expect(addReason).toHaveAttribute("aria-invalid", "true");
    expect(addReason).toHaveAccessibleDescription(
      "Use a reason without control characters.",
    );

    fireEvent.click(
      screen.getByRole("button", { name: /Revoke Ada Analyst, edge/u }),
    );
    const revokeReason = screen.getByRole("textbox", {
      name: "Revoke reason",
    });
    fireEvent.change(revokeReason, { target: { value: invalidReason } });
    fireEvent.click(screen.getByRole("button", { name: "Revoke roster edge" }));
    expect(revokeReason).toHaveAttribute("aria-invalid", "true");
    expect(revokeReason).toHaveAccessibleDescription(
      "Use a reason without control characters.",
    );

    expect(startOperatorTeamAssignmentEpoch).not.toHaveBeenCalled();
    expect(endOperatorTeamAssignmentEpoch).not.toHaveBeenCalled();
    expect(addOperatorTeamRosterEntry).not.toHaveBeenCalled();
    expect(revokeOperatorTeamRosterEntry).not.toHaveBeenCalled();
  });

  it("validates optional roster expiry as future RFC 3339 at microsecond precision before the API call", async () => {
    const addOperatorTeamRosterEntry = vi.fn();
    renderTeams(
      epochMutationApi({ addOperatorTeamRosterEntry }),
      epochMutationPermissions,
    );

    await selectEpochMutationMember();
    fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
      target: { value: "Time-box this exact edge" },
    });
    const expiresAt = screen.getByRole("textbox", { name: "Expires at" });
    const addForm = screen
      .getByRole("button", { name: "Add roster member" })
      .closest("form");
    expect(addForm).not.toBeNull();

    fireEvent.change(expiresAt, { target: { value: "not-an-instant" } });
    fireEvent.submit(addForm!);
    expect(expiresAt).toHaveAttribute("aria-invalid", "true");
    expect(expiresAt).toHaveAccessibleDescription(
      "Use an RFC 3339 expiry with microsecond-safe precision.",
    );

    fireEvent.change(expiresAt, {
      target: { value: "2099-01-01T00:00:00.1234567Z" },
    });
    fireEvent.submit(addForm!);
    expect(expiresAt).toHaveAccessibleDescription(
      "Use an RFC 3339 expiry with microsecond-safe precision.",
    );

    fireEvent.change(expiresAt, {
      target: { value: "2020-01-01T00:00:00Z" },
    });
    fireEvent.submit(addForm!);
    expect(expiresAt).toHaveAccessibleDescription(
      "Choose an expiry in the future.",
    );

    fireEvent.change(expiresAt, {
      target: { value: "9999-12-31T23:59:59-23:00" },
    });
    fireEvent.submit(addForm!);
    expect(expiresAt).toHaveAccessibleDescription(
      "Use an RFC 3339 expiry with microsecond-safe precision.",
    );
    expect(addOperatorTeamRosterEntry).not.toHaveBeenCalled();

    fireEvent.change(expiresAt, {
      target: { value: "2099-01-01T00:00:00.123456Z" },
    });
    await waitFor(() => expect(expiresAt).not.toHaveAttribute("aria-invalid"));
    expect(
      screen.getByRole("button", { name: "Add roster member" }),
    ).toBeEnabled();
    expect(addOperatorTeamRosterEntry).not.toHaveBeenCalled();
  });

  it("replays a bound add after its expiry passes but rejects expired payload drift", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.setSystemTime(new Date("2026-08-24T10:00:00Z"));
      const addOperatorTeamRosterEntry = vi
        .fn()
        .mockRejectedValueOnce(
          new PhaseTwoApiError("ambiguous initial add", 503),
        )
        .mockRejectedValueOnce(
          new PhaseTwoApiError("ambiguous bound replay", 503),
        );
      renderTeams(
        epochMutationApi({ addOperatorTeamRosterEntry }),
        epochMutationPermissions,
      );

      await selectEpochMutationMember();
      fireEvent.change(screen.getByRole("textbox", { name: "Roster reason" }), {
        target: { value: "Short exact-epoch coverage" },
      });
      const expiresAt = screen.getByRole("textbox", { name: "Expires at" });
      fireEvent.change(expiresAt, {
        target: { value: "2026-08-24T10:01:00.123456Z" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      expect(await screen.findByText("ambiguous initial add")).toBeVisible();
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(1);
      const boundKey = addOperatorTeamRosterEntry.mock.calls[0]?.[4];

      vi.setSystemTime(new Date("2026-08-24T10:02:00Z"));
      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      expect(await screen.findByText("ambiguous bound replay")).toBeVisible();
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2);
      expect(addOperatorTeamRosterEntry.mock.calls[1]?.[4]).toBe(boundKey);

      fireEvent.change(expiresAt, {
        target: { value: "2026-08-24T10:01:30.123456Z" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Add roster member" }),
      );
      expect(expiresAt).toHaveAttribute("aria-invalid", "true");
      expect(expiresAt).toHaveAccessibleDescription(
        "Choose an expiry in the future.",
      );
      expect(addOperatorTeamRosterEntry).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

function renderTeams(
  api: ReturnType<typeof createPhaseTwoApi>,
  permissions: readonly TenantPermissionKeyView[],
  options: {
    clearSession?: (sessionId: string) => void;
    getTenantAuthority?: PhaseTwoApi["getTenantAuthority"];
    strict?: boolean;
  } = {},
): ReturnType<typeof render> {
  const session = { ...sessionFixture, activeTenantId: tenantId };
  const getTenantAuthority =
    options.getTenantAuthority ?? (async () => authorityFixture(permissions));
  const page = (
    <SessionContext.Provider
      value={{
        api: {
          ...api,
          getTenantAuthority,
        },
        clearSession: options.clearSession ?? vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantOperatorTeamsPage />
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
  return render(options.strict ? <StrictMode>{page}</StrictMode> : page);
}

function TenantAuthorityReloadHarness({
  api,
}: {
  api: PhaseTwoApi;
}): React.JSX.Element {
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: { ...sessionFixture, activeTenantId: tenantId },
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantOperatorTeamsPage />
        <ReloadSamePairAuthorityButton />
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function PersistentTenantRouteHarness({
  api,
}: {
  api: PhaseTwoApi;
}): React.JSX.Element {
  const [activeTenantId, setActiveTenantId] = useState(tenantId);
  const [routeMounted, setRouteMounted] = useState(true);
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: { ...sessionFixture, activeTenantId },
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        {routeMounted ? <TenantOperatorTeamsPage /> : null}
        <button
          type="button"
          onClick={() => setRouteMounted((mounted) => !mounted)}
        >
          Toggle persistent operator-team route
        </button>
        <button
          type="button"
          onClick={() =>
            setActiveTenantId((current) =>
              current === tenantId ? otherTenantId : tenantId,
            )
          }
        >
          Switch persistent operator-team tenant
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function ReloadSamePairAuthorityButton(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button type="button" onClick={authority.reload}>
      Reload same-pair authority
    </button>
  );
}

function SwitchingTenantHarness({
  api,
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
}): React.JSX.Element {
  const [activeTenantId, setActiveTenantId] = useState(tenantId);
  const [sessionId, setSessionId] = useState(sessionFixture.id);
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: { ...sessionFixture, activeTenantId, id: sessionId },
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantOperatorTeamsPage />
        <button
          type="button"
          onClick={() =>
            setActiveTenantId((current) =>
              current === tenantId ? otherTenantId : tenantId,
            )
          }
        >
          Switch operator-team tenant
        </button>
        <button
          type="button"
          onClick={() => setSessionId("0198c97d-cf4f-7000-8000-000000000099")}
        >
          Rotate operator-team session
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function pairIsolationApi(
  listTenantUsers: PhaseTwoApi["listTenantUsers"],
): PhaseTwoApi {
  const permissions: TenantPermissionKeyView[] = [
    "operator_team.read",
    "operator_team.roster.manage",
    "role.grant",
    "user.read",
  ];
  return createPhaseTwoApi({
    getOperatorTeamAssignmentEpoch: async (
      requestedTenantId,
      _operatorTeamId,
      assignmentEpochId,
    ) => ({
      etag: '"v2"',
      value: activeEpochFixture({
        epochId: assignmentEpochId,
        tenantId: requestedTenantId,
      }),
    }),
    getTenantAuthority: async (requestedTenantId) =>
      authorityFixture(permissions, requestedTenantId),
    listOperatorTeamRosterEntries: async () => ({ items: [] }),
    listTenantOperatorTeamAssignmentEpochs: async (requestedTenantId) => ({
      items: [
        activeEpochFixture({
          epochId:
            requestedTenantId === tenantId
              ? activeEpochId
              : "0198c97d-cf4f-7000-8000-000000000461",
          tenantId: requestedTenantId,
        }),
      ],
    }),
    listTenantUsers,
  });
}

function epochMutationApi(
  overrides: Partial<PhaseTwoApi> = {},
): ReturnType<typeof createPhaseTwoApi> {
  const epoch = activeEpochFixture();
  return createPhaseTwoApi({
    getOperatorTeamAssignmentEpoch: async () => ({
      etag: '"v2"',
      value: epoch,
    }),
    getTenantAuthority: async () => authorityFixture(epochMutationPermissions),
    listOperatorTeamRosterEntries: async () => ({
      items: [rosterFixture(activeEpochId, "Ada Analyst", "active")],
    }),
    listTenantOperatorTeamAssignmentEpochs: async () => ({ items: [epoch] }),
    listTenantUsers: async () => ({ items: [tenantUserFixture()] }),
    ...overrides,
  });
}

function multiEpochFixtures(): readonly OperatorTeamAssignmentEpochView[] {
  return [
    activeEpochFixture({
      operatorTeam: {
        id: teamId,
        key: "soc_a",
        name: "SOC A",
        state: "active",
      },
      startedAt: "2026-08-24T10:00:00Z",
    }),
    activeEpochFixture({
      epochId: secondEpochId,
      operatorTeam: {
        id: secondTeamId,
        key: "soc_b",
        name: "SOC B",
        state: "active",
      },
      startedAt: "2026-08-24T09:00:00Z",
    }),
    activeEpochFixture({
      epochId: thirdEpochId,
      operatorTeam: {
        id: thirdTeamId,
        key: "soc_c",
        name: "SOC C",
        state: "active",
      },
      startedAt: "2026-08-24T08:00:00Z",
    }),
  ];
}

function multiEpochMutationApi(
  epochs: readonly OperatorTeamAssignmentEpochView[],
  overrides: Partial<PhaseTwoApi> = {},
): ReturnType<typeof createPhaseTwoApi> {
  return createPhaseTwoApi({
    getOperatorTeamAssignmentEpoch: async (
      requestedTenantId,
      requestedOperatorTeamId,
      assignmentEpochId,
    ) => {
      const epoch = epochs.find(
        (candidate) => candidate.epochId === assignmentEpochId,
      );
      if (
        !epoch ||
        epoch.tenantId !== requestedTenantId ||
        epoch.operatorTeam.id !== requestedOperatorTeamId
      ) {
        throw new Error("The requested exact epoch was not in the fixture.");
      }
      return { etag: `"v${epoch.version}"`, value: epoch };
    },
    getTenantAuthority: async () => authorityFixture(epochMutationPermissions),
    listOperatorTeamRosterEntries: async () => ({ items: [] }),
    listTenantOperatorTeamAssignmentEpochs: async () => ({ items: epochs }),
    listTenantUsers: async () => ({ items: [tenantUserFixture()] }),
    ...overrides,
  });
}

async function startPendingEpochEnd(
  teamName: string,
  reason: string,
): Promise<void> {
  await screen.findByRole("heading", { name: `Roster · ${teamName}` });
  fireEvent.change(screen.getByRole("textbox", { name: "End reason" }), {
    target: { value: reason },
  });
  fireEvent.click(screen.getByRole("button", { name: "End assignment epoch" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Ending epoch…" }),
    ).toBeDisabled(),
  );
}

async function selectEpochMutationMember(): Promise<void> {
  const picker = await screen.findByRole("combobox", { name: "Tenant member" });
  await waitFor(() => expect(picker).toBeEnabled());
  fireEvent.click(picker);
  fireEvent.click(
    await screen.findByRole("option", {
      name: "Ada Target · ada-target@example.invalid",
    }),
  );
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
  authorityTenantId = tenantId,
  operatorTeamPermissions: readonly TenantPermissionKeyView[] = [],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-24T08:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [
      ...permissions.map((permissionKey) => ({
        permissionKey,
        scope: "tenant" as const,
      })),
      ...operatorTeamPermissions.map((permissionKey) => ({
        permissionKey,
        scope: "operator_team" as const,
      })),
    ],
    roleGrants: [],
    tenantId: authorityTenantId,
    userId: sessionFixture.user.id,
  };
}

function activeEpochFixture(
  overrides: Partial<OperatorTeamAssignmentEpochView> = {},
): OperatorTeamAssignmentEpochView {
  return {
    epochId: activeEpochId,
    operatorTeam: {
      id: teamId,
      key: "soc_l1",
      name: "SOC L1",
      state: "active",
    },
    startReason: "Tenant onboarding",
    startedAt: "2026-08-24T08:00:00Z",
    startedByUserId: sessionFixture.user.id,
    state: "active",
    tenantId,
    updatedAt: "2026-08-24T08:00:00Z",
    version: 2,
    ...overrides,
  };
}

function historicalEpochFixture(
  overrides: Partial<OperatorTeamAssignmentEpochView> = {},
): OperatorTeamAssignmentEpochView {
  return {
    ...activeEpochFixture(),
    endedAt: "2026-08-23T12:00:00Z",
    endedByUserId: sessionFixture.user.id,
    endReason: "Previous rotation ended",
    epochId: historicalEpochId,
    startedAt: "2026-08-22T08:00:00Z",
    state: "ended",
    updatedAt: "2026-08-23T12:00:00Z",
    version: 3,
    ...overrides,
  };
}

function rosterFixture(
  assignmentEpochId: string,
  displayName: string,
  state: OperatorTeamRosterEntryView["state"],
  overrides: Partial<OperatorTeamRosterEntryView> = {},
): OperatorTeamRosterEntryView {
  return {
    assignmentEpochId,
    etag: '"v2-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"',
    id: `${assignmentEpochId.slice(0, -3)}499`,
    managedByOperatorTeamApi: true,
    member: {
      displayName,
      membershipId: "0198c97d-cf4f-7000-8000-000000000420",
      membershipStatus: "active",
      userId: "0198c97d-cf4f-7000-8000-000000000421",
    },
    operatorTeamId: teamId,
    provenance: {
      authoritative: false,
      grantedAt: "2026-08-24T08:30:00Z",
      grantedByUserId: sessionFixture.user.id,
      reason: "On-call rotation",
      sourceId: "0198c97d-cf4f-7000-8000-000000000422",
      sourceKind: "manual",
    },
    state,
    tenantId,
    updatedAt: "2026-08-24T08:30:00Z",
    version: 2,
    ...overrides,
  };
}

function tenantUserFixture(
  overrides: Partial<TenantUserSummaryView> = {},
): TenantUserSummaryView {
  return {
    createdAt: "2026-08-20T10:00:00Z",
    etag: '"v1"',
    legacyMembershipRole: "analyst",
    lifecycleRevision: 1,
    membershipId: "0198c97d-cf4f-7000-8000-000000000420",
    membershipStatus: "active",
    tenantId,
    updatedAt: "2026-08-24T08:00:00Z",
    user: {
      active: true,
      displayName: "Ada Target",
      email: "ada-target@example.invalid",
      id: "0198c97d-cf4f-7000-8000-000000000421",
    },
    ...overrides,
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}
