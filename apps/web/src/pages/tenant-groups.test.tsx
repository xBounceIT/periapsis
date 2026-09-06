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
  type PhaseTwoApi,
  PhaseTwoApiError,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
  type TenantRoleSummaryView,
  type TenantSecurityGroupMembershipView,
  type TenantSecurityGroupRoleGrantView,
  type TenantSecurityGroupView,
  type TenantUserSummaryView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TenantGroupsPage } from "./tenant-groups";
import { mergeTenantGroups } from "./tenant-groups-model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const otherTenantId = "0198c97d-cf4f-7000-8000-000000000011";
const groupId = "0198c97d-cf4f-7000-8000-000000000110";
const membershipEdgeEtag = '"v7-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';
const roleEdgeEtag = '"v4-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("TenantGroupsPage", () => {
  it("keeps initial authority pending and clears ready group state before a read-permission loss settles", async () => {
    const group = groupFixture();
    const initialAuthority = createDeferred<TenantAuthorityView>();
    const deniedAuthority = createDeferred<TenantAuthorityView>();
    const delayedPage = createDeferred<{
      items: TenantSecurityGroupView[];
    }>();
    const delayedDetail = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    let paginationSignal: AbortSignal | undefined;
    let detailSignal: AbortSignal | undefined;
    const getTenantAuthority = vi
      .fn()
      .mockImplementationOnce(async () => initialAuthority.promise)
      .mockImplementationOnce(async () => deniedAuthority.promise);
    const listTenantSecurityGroups = vi.fn(
      async (
        _requestedTenantId: string,
        options?: { after?: string; signal?: AbortSignal },
      ) => {
        if (options?.after === "group-page-two") {
          paginationSignal = options.signal;
          return delayedPage.promise;
        }
        return { items: [group], nextCursor: "group-page-two" };
      },
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantSecurityGroup: async (
          _requestedTenantId,
          _requestedGroupId,
          signal,
        ) => {
          detailSignal = signal;
          return delayedDetail.promise;
        },
        listTenantSecurityGroups,
      }),
      vi.fn(),
      true,
    );

    expect(screen.getByLabelText("Loading security groups")).toBeVisible();
    expect(listTenantSecurityGroups).not.toHaveBeenCalled();
    await act(async () => {
      initialAuthority.resolve(authorityFixture(["group.read"]));
      await initialAuthority.promise;
    });
    const open = await screen.findByRole("button", {
      name: "Open IR leads (ir_leads)",
    });
    fireEvent.click(screen.getByRole("button", { name: "Load more groups" }));
    await waitFor(() => expect(paginationSignal).toBeDefined());
    fireEvent.click(open);
    await screen.findByRole("dialog");
    await waitFor(() => expect(detailSignal).toBeDefined());

    fireEvent.click(screen.getByTestId("reload-group-authority"));
    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(paginationSignal?.aborted).toBe(true);
    expect(detailSignal?.aborted).toBe(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Open IR leads (ir_leads)" }),
    ).not.toBeInTheDocument();

    await act(async () => {
      delayedPage.resolve({
        items: [
          groupFixture({
            id: "0198c97d-cf4f-7000-8000-000000000199",
            key: "late_group",
            name: "Late group",
          }),
        ],
      });
      delayedDetail.resolve({ etag: '"v3"', value: group });
      await Promise.all([delayedPage.promise, delayedDetail.promise]);
    });
    expect(screen.queryByText("Late group")).not.toBeInTheDocument();

    await act(async () => {
      deniedAuthority.resolve(authorityFixture([]));
      await deniedAuthority.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantSecurityGroups).toHaveBeenCalledTimes(2);
  });

  it("keeps capability controls fail-closed and does not invalidate on a read 401", async () => {
    const listTenantSecurityGroups = vi.fn();
    const clearSession = vi.fn();
    const { unmount } = renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture([]),
        listTenantSecurityGroups,
      }),
      clearSession,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(listTenantSecurityGroups).not.toHaveBeenCalled();
    unmount();

    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["group.read"]),
        listTenantSecurityGroups: async () => {
          throw new PhaseTwoApiError("expired read", 401);
        },
      }),
      clearSession,
    );

    expect(await screen.findByText("expired read")).toBeVisible();
    expect(clearSession).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Create group" }),
    ).not.toBeInTheDocument();
  });

  it("keeps group actions distinguishable when display names are duplicated", async () => {
    const primary = groupFixture({ name: "Response coordinators" });
    const secondary = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000111",
      key: "response_coordinators_secondary",
      name: "Response coordinators",
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["group.read"]),
        listTenantSecurityGroups: async () => ({
          items: [primary, secondary],
        }),
      }),
    );

    expect(
      await screen.findByRole("button", {
        name: "Open Response coordinators (ir_leads)",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Open Response coordinators (response_coordinators_secondary)",
      }),
    ).toBeVisible();
  });

  it("invalidates the current session when a group mutation returns 401", async () => {
    const clearSession = vi.fn();
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("expired mutation", 401);
        },
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        listTenantSecurityGroups: async () => ({ items: [] }),
      }),
      clearSession,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create group" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Group key" }), {
      target: { value: "expired_group" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
      target: { value: "Expired group" },
    });
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Create group",
      }),
    );

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("renders independently source-qualified membership and role provenance", async () => {
    const group = groupFixture();
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.read", "role.read", "user.read"]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membershipFixture(group)],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [roleEdgeFixture(group)],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    const overviewTab = await screen.findByRole("tab", { name: "Overview" });
    overviewTab.focus();
    fireEvent.keyDown(overviewTab, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Members" })).toHaveFocus();
    fireEvent.click(await screen.findByRole("tab", { name: "Provenance" }));
    const provenancePanel = screen.getByRole("tabpanel");

    expect(
      await within(provenancePanel).findByRole("heading", {
        name: "Two edges, two source owners",
      }),
    ).toBeVisible();
    expect(
      within(provenancePanel).getAllByLabelText(
        "Two-edge access path through IR leads",
      ).length,
    ).toBeGreaterThan(0);
    expect(
      within(provenancePanel).getByText("Membership edge sources"),
    ).toBeVisible();
    expect(
      within(provenancePanel).getByText("Role edge sources"),
    ).toBeVisible();
    expect(
      within(provenancePanel).getByText("Manual roster decision"),
    ).toBeVisible();
    expect(
      within(provenancePanel).getByText("Directory role mapping"),
    ).toBeVisible();
    expect(within(provenancePanel).getByText("identity mapping")).toBeVisible();
    expect(
      within(provenancePanel).getByText("0198c97d-cf4f-7000-8000-000000000151"),
    ).toBeVisible();
    expect(
      within(provenancePanel).getByText("0198c97d-cf4f-7000-8000-000000000152"),
    ).toBeVisible();
  });

  it("distinguishes source retirement from the stored edge lifecycle", async () => {
    const group = groupFixture();
    const roleEdge = roleEdgeFixture(group);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.read", "role.read", "user.read"]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [
            {
              ...roleEdge,
              provenance: {
                ...roleEdge.provenance,
                retiredAt: "2026-08-23T09:00:00Z",
              },
            },
          ],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Provenance" }));

    const record = within(screen.getByRole("tabpanel"))
      .getByText("Directory role mapping")
      .closest("article");
    if (!(record instanceof HTMLElement)) {
      throw new Error(
        "The retired role-edge provenance record was not rendered.",
      );
    }
    expect(within(record).getByText(/^active$/i)).toBeVisible();
    expect(within(record).getByText("Source retirement")).toBeVisible();
    expect(
      within(record).getByText(/stored edge no longer contributes authority/i),
    ).toBeVisible();
    expect(
      within(record).getByText(
        /active badge describes only the edge lifecycle/i,
      ),
    ).toBeVisible();
  });

  it("shows an archived group as an effective-authority blocker without disabling manual edge revocation", async () => {
    const group = groupFixture({
      archived: true,
      archivedAt: "2026-08-23T09:00:00Z",
    });
    const manualRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membershipFixture(group)],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [manualRoleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const membershipTarget = "Mira Responder (mira@example.invalid)";
    const membershipBlockers = await screen.findByLabelText(
      `Effective authority blockers for ${membershipTarget}`,
    );
    expect(
      within(membershipBlockers).getByText(/Edge lifecycle: Active/i),
    ).toBeVisible();
    expect(
      within(membershipBlockers).getByText(
        /Effective authority: Does not contribute/i,
      ),
    ).toBeVisible();
    expect(
      within(membershipBlockers).getByText(/Group prerequisite: Archived/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Revoke membership edge for ${membershipTarget}`,
      }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    const roleTarget = "Incident commander (incident_commander)";
    const roleBlockers = await screen.findByLabelText(
      `Effective authority blockers for ${roleTarget}`,
    );
    expect(
      within(roleBlockers).getByText(/Group prerequisite: Archived/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Revoke role edge for ${roleTarget}`,
      }),
    ).toBeVisible();
  });

  it.each([
    ["invited", "invited"],
    ["suspended", "suspended"],
  ] as const)(
    "shows a %s tenant membership as an effective-authority blocker while its manual edge remains revocable",
    async (membershipStatus, visibleState) => {
      const group = groupFixture();
      const membership = membershipFixture(group, {
        member: {
          ...userFixture(),
          membershipStatus,
        },
      });
      renderGroups(
        createPhaseTwoApi({
          getTenantAuthority: async () =>
            authorityFixture([
              "group.membership.manage",
              "group.read",
              "role.grant",
              "user.read",
            ]),
          getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
          listTenantSecurityGroupMemberships: async () => ({
            items: [membership],
          }),
          listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
          listTenantSecurityGroups: async () => ({ items: [group] }),
        }),
      );

      fireEvent.click(
        await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
      );
      fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
      const target = "Mira Responder (mira@example.invalid)";
      const blockers = await screen.findByLabelText(
        `Effective authority blockers for ${target}`,
      );
      expect(
        within(blockers).getByText(
          new RegExp(`Tenant membership prerequisite: ${visibleState}`, "i"),
        ),
      ).toBeVisible();
      expect(
        within(blockers).getByText(
          /cannot participate until the tenant membership is active/i,
        ),
      ).toBeVisible();
      expect(
        screen.getByRole("button", {
          name: `Revoke membership edge for ${target}`,
        }),
      ).toBeVisible();
    },
  );

  it("accepts a contract-valid nanosecond role-edge expiry", async () => {
    const group = groupFixture();
    const roleEdge = roleEdgeFixture(group, {
      provenance: {
        ...roleEdgeFixture(group).provenance,
        expiresAt: "2026-08-24T10:00:00.123456789Z",
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.read", "role.read"]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [roleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        "Incident commander",
      ),
    ).toBeVisible();
    expect(
      screen.queryByText("The group role edges could not be loaded."),
    ).not.toBeInTheDocument();
  });

  it("shows a disabled user as an effective-authority blocker while its manual membership edge remains revocable", async () => {
    const group = groupFixture();
    const membership = membershipFixture(group, {
      member: {
        ...userFixture(),
        user: { ...userFixture().user, active: false },
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membership],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    const blockers = await screen.findByLabelText(
      `Effective authority blockers for ${target}`,
    );
    expect(
      within(blockers).getByText(/User prerequisite: Disabled/i),
    ).toBeVisible();
    expect(
      within(blockers).getByText(
        /cannot participate while the user is disabled/i,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).toBeVisible();
  });

  it("shows an archived role as an effective-authority blocker while its manual role edge remains revocable", async () => {
    const group = groupFixture();
    const manualRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
      role: {
        ...roleFixture(),
        archived: true,
        archivedAt: "2026-08-23T09:00:00Z",
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.read",
            "role.grant",
            "role.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [manualRoleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    const target = "Incident commander (incident_commander)";
    const blockers = await screen.findByLabelText(
      `Effective authority blockers for ${target}`,
    );
    expect(
      within(blockers).getByText(/Role prerequisite: Archived/i),
    ).toBeVisible();
    expect(
      within(blockers).getByText(
        /does not contribute authority while the role is archived/i,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: `Revoke role edge for ${target}` }),
    ).toBeVisible();
  });

  it("shows a retired source as an effective-authority blocker while source ownership still governs revocation", async () => {
    const group = groupFixture();
    const roleEdge = roleEdgeFixture(group);
    const retiredRoleEdge = {
      ...roleEdge,
      provenance: {
        ...roleEdge.provenance,
        retiredAt: "2026-08-23T09:00:00Z",
      },
    };
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.read",
            "role.grant",
            "role.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [retiredRoleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    const target = "Incident commander (incident_commander)";
    const blockers = await screen.findByLabelText(
      `Effective authority blockers for ${target}`,
    );
    expect(
      within(blockers).getByText(/Source prerequisite: Retired/i),
    ).toBeVisible();
    expect(
      within(blockers).getByText(
        /does not contribute authority because its source is retired/i,
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: `Revoke role edge for ${target}` }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/manual controls cannot reconcile or revoke this edge/i),
    ).toBeVisible();
  });

  it("uses the explicit ownership capability instead of a manual source kind for group-edge revocation", async () => {
    const group = groupFixture();
    const ownedMembership = membershipFixture(group);
    const nonOwnedMembership = membershipFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000164",
      managedByAuthorizationApi: false,
      member: {
        ...userFixture(),
        membershipId: "0198c97d-cf4f-7000-8000-000000000165",
        user: {
          ...userFixture().user,
          displayName: "Non-owned responder",
          email: "non-owned@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000166",
        },
      },
      provenance: {
        ...membershipFixture(group).provenance,
        expiresAt: "2026-08-22T09:00:00Z",
      },
      state: "expired",
    });
    const missingMembershipFixture = membershipFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000167",
      managedByAuthorizationApi: true,
      member: {
        ...userFixture(),
        membershipId: "0198c97d-cf4f-7000-8000-000000000168",
        user: {
          ...userFixture().user,
          displayName: "Rolling responder",
          email: "rolling@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000169",
        },
      },
      provenance: {
        ...membershipFixture(group).provenance,
        expiresAt: "2026-08-22T09:00:00Z",
      },
      state: "expired",
    });
    expect(
      Reflect.deleteProperty(
        missingMembershipFixture,
        "managedByAuthorizationApi",
      ),
    ).toBe(true);

    const manualRoleProvenance = {
      authoritative: false,
      grantedAt: "2026-08-21T10:00:00Z",
      grantedByUserId: sessionFixture.user.id,
      reason: "Manual role decision",
      sourceId: "0198c97d-cf4f-7000-8000-000000000153",
      sourceKind: "manual" as const,
    };
    const ownedRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: manualRoleProvenance,
    });
    const nonOwnedRoleEdge = roleEdgeFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000170",
      managedByAuthorizationApi: false,
      provenance: {
        ...manualRoleProvenance,
        expiresAt: "2026-08-22T09:00:00Z",
        sourceId: "0198c97d-cf4f-7000-8000-000000000171",
      },
      role: {
        ...roleFixture(),
        id: "0198c97d-cf4f-7000-8000-000000000172",
        key: "non_owned_commander",
        name: "Non-owned commander",
      },
      state: "expired",
    });
    const missingRoleFixture = roleEdgeFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000173",
      managedByAuthorizationApi: true,
      provenance: {
        ...manualRoleProvenance,
        expiresAt: "2026-08-22T09:00:00Z",
        sourceId: "0198c97d-cf4f-7000-8000-000000000174",
      },
      role: {
        ...roleFixture(),
        id: "0198c97d-cf4f-7000-8000-000000000175",
        key: "rolling_commander",
        name: "Rolling commander",
      },
      state: "expired",
    });
    expect(
      Reflect.deleteProperty(missingRoleFixture, "managedByAuthorizationApi"),
    ).toBe(true);

    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [
            ownedMembership,
            nonOwnedMembership,
            missingMembershipFixture,
          ],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [ownedRoleEdge, nonOwnedRoleEdge, missingRoleFixture],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const membershipPanel = screen.getByRole("tabpanel");
    expect(
      await screen.findByRole("button", {
        name: "Revoke membership edge for Mira Responder (mira@example.invalid)",
      }),
    ).toBeVisible();
    for (const target of [
      "Non-owned responder (non-owned@example.invalid)",
      "Rolling responder (rolling@example.invalid)",
    ]) {
      const card = within(membershipPanel)
        .getByText(target.split(" (")[0] ?? target)
        .closest("article");
      if (!(card instanceof HTMLElement)) {
        throw new Error(`The ${target} membership edge was not rendered.`);
      }
      expect(
        within(card).getByText(
          /Not managed by the authorization API \(source: manual\); manual controls cannot reconcile or revoke this edge/i,
        ),
      ).toBeVisible();
      expect(
        within(card).queryByRole("button", {
          name: `Revoke membership edge for ${target}`,
        }),
      ).not.toBeInTheDocument();
    }

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    const rolePanel = screen.getByRole("tabpanel");
    expect(
      await screen.findByRole("button", {
        name: "Revoke role edge for Incident commander (incident_commander)",
      }),
    ).toBeVisible();
    for (const target of [
      "Non-owned commander (non_owned_commander)",
      "Rolling commander (rolling_commander)",
    ]) {
      const card = within(rolePanel)
        .getByText(target.split(" (")[0] ?? target)
        .closest("article");
      if (!(card instanceof HTMLElement)) {
        throw new Error(`The ${target} role edge was not rendered.`);
      }
      expect(
        within(card).getByText(
          /Not managed by the authorization API \(source: manual\); manual controls cannot reconcile or revoke this edge/i,
        ),
      ).toBeVisible();
      expect(
        within(card).queryByRole("button", {
          name: `Revoke role edge for ${target}`,
        }),
      ).not.toBeInTheDocument();
    }
  });

  it("updates effective authority when an edge expiry deadline passes while mounted", async () => {
    const group = groupFixture();
    const maximumTimerDelay = 2_147_483_647;
    const start = Date.parse("2035-01-01T00:00:00.000Z");
    const deadline = start + maximumTimerDelay + 1_000;
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(start);
    const membership = membershipFixture(group, {
      provenance: {
        ...membershipFixture(group).provenance,
        expiresAt: new Date(deadline).toISOString(),
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membership],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await screen.findByRole("button", {
      name: `Revoke membership edge for ${target}`,
    });
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(
      screen.queryByLabelText(`Effective authority blockers for ${target}`),
    ).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(maximumTimerDelay);
    });
    expect(
      screen.queryByLabelText(`Effective authority blockers for ${target}`),
    ).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    expect(vi.getTimerCount()).toBe(1);

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(
      screen.queryByLabelText(`Effective authority blockers for ${target}`),
    ).not.toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });

    const blockers = screen.getByLabelText(
      `Effective authority blockers for ${target}`,
    );
    expect(
      within(blockers).getByText(/Edge expiry prerequisite: Expired/i),
    ).toBeVisible();
    expect(
      within(blockers).getByText(/expiry deadline has passed/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).toBeVisible();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    ["malformed", "not-a-valid-expiry-deadline"],
    ["sub-nanosecond", "2026-08-24T10:00:00.1234567891Z"],
  ])(
    "rejects a %s edge expiry before storing the injected page",
    async (_case, expiresAt) => {
      const group = groupFixture();
      const membership = membershipFixture(group, {
        provenance: {
          ...membershipFixture(group).provenance,
          expiresAt,
        },
      });
      renderGroups(
        createPhaseTwoApi({
          getTenantAuthority: async () =>
            authorityFixture([
              "group.membership.manage",
              "group.read",
              "role.grant",
              "user.read",
            ]),
          getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
          listTenantSecurityGroupMemberships: async () => ({
            items: [membership],
          }),
          listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
          listTenantSecurityGroups: async () => ({ items: [group] }),
        }),
      );

      fireEvent.click(
        await screen.findByRole("button", {
          name: "Open IR leads (ir_leads)",
        }),
      );
      fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
      const membershipPanel = screen.getByRole("tabpanel");

      expect(
        await within(membershipPanel).findByText(
          "The group membership edges could not be loaded.",
        ),
      ).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Retry membership edges" }),
      ).toBeVisible();
      expect(screen.queryByText("Mira Responder")).not.toBeInTheDocument();
    },
  );

  it("accepts an offset-bearing edge expiry with nonzero nanosecond digits", async () => {
    const group = groupFixture();
    const membership = membershipFixture(group, {
      provenance: {
        ...membershipFixture(group).provenance,
        expiresAt: "2026-08-22T12:34:56.123456789+02:00",
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membership],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));

    const target = "Mira Responder (mira@example.invalid)";
    expect(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).toBeVisible();
    expect(
      within(
        screen.getByLabelText(`Effective authority blockers for ${target}`),
      ).getByText(/Edge expiry prerequisite: Expired/i),
    ).toBeVisible();
  });

  it("does not offer an inactive identity as a new group member", async () => {
    const group = groupFixture();
    const inactiveUser: TenantUserSummaryView = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000132",
      user: {
        ...userFixture().user,
        active: false,
        displayName: "Inactive responder",
        email: "inactive@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000133",
      },
    };
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({
          items: [userFixture(), inactiveUser],
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Add member edge" }),
    );
    fireEvent.click(
      await screen.findByRole("combobox", { name: "Tenant user" }),
    );

    expect(
      await screen.findByRole("option", {
        name: "Mira Responder · mira@example.invalid",
      }),
    ).toBeVisible();
    expect(
      screen.queryByRole("option", {
        name: "Inactive responder · inactive@example.invalid",
      }),
    ).not.toBeInTheDocument();
  });

  it("reaches member and role options beyond the twentieth cursor page", async () => {
    const group = groupFixture();
    const laterUser: TenantUserSummaryView = {
      ...userFixture(),
      membershipId: "0198c97d-cf4f-7000-8000-000000000132",
      user: {
        ...userFixture().user,
        displayName: "Later responder",
        email: "later@example.invalid",
        id: "0198c97d-cf4f-7000-8000-000000000133",
      },
    };
    const laterRole: TenantRoleSummaryView = {
      ...roleFixture(),
      id: "0198c97d-cf4f-7000-8000-000000000141",
      key: "later_role",
      name: "Later role",
    };
    const listTenantUsers = vi.fn(
      async (_requestedTenantId: string, after?: string) => {
        const page = after ? Number(after.replace("users-", "")) : 0;
        return page === 20
          ? { items: [laterUser] }
          : {
              items: [userFixture()],
              nextCursor: `users-${page + 1}`,
            };
      },
    );
    const listTenantRoles = vi.fn(
      async (
        _requestedTenantId: string,
        options?: { after?: string; signal?: AbortSignal },
      ) => {
        const page = options?.after
          ? Number(options.after.replace("roles-", ""))
          : 0;
        return page === 20
          ? { items: [laterRole] }
          : {
              items: [roleFixture()],
              nextCursor: `roles-${page + 1}`,
            };
      },
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantRoles,
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Add member edge" }),
    );
    await loadTwentyMorePages("tenant users", listTenantUsers);
    fireEvent.click(screen.getByRole("combobox", { name: "Tenant user" }));
    expect(
      (await screen.findAllByText("Later responder · later@example.invalid"))
        .length,
    ).toBeGreaterThan(0);
    fireEvent.keyDown(screen.getByRole("listbox"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Add role edge" }),
    );
    await loadTwentyMorePages("tenant roles", listTenantRoles);
    fireEvent.click(screen.getByRole("combobox", { name: "Tenant role" }));
    expect(
      (await screen.findAllByText("Later role · later_role")).length,
    ).toBeGreaterThan(0);
  }, 15_000);

  it("fails closed on a non-immediate shared-inventory cursor cycle and keeps retry available", async () => {
    const group = groupFixture();
    const secondMember = membershipFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000162",
      member: {
        ...userFixture(),
        membershipId: "0198c97d-cf4f-7000-8000-000000000134",
        user: {
          ...userFixture().user,
          displayName: "Second responder",
          email: "second@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000135",
        },
      },
    });
    const loopMember = membershipFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000163",
      member: {
        ...userFixture(),
        membershipId: "0198c97d-cf4f-7000-8000-000000000136",
        user: {
          ...userFixture().user,
          displayName: "Loop responder",
          email: "loop@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000137",
        },
      },
    });
    const recoveredMember = membershipFixture(group, {
      id: "0198c97d-cf4f-7000-8000-000000000164",
      member: {
        ...userFixture(),
        membershipId: "0198c97d-cf4f-7000-8000-000000000138",
        user: {
          ...userFixture().user,
          displayName: "Recovered responder",
          email: "recovered@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000139",
        },
      },
    });
    let secondCursorCalls = 0;
    const listTenantSecurityGroupMemberships = vi.fn(
      async (
        _requestedTenantId: string,
        _requestedGroupId: string,
        options?: {
          after?: string;
          includeRevoked?: boolean;
          signal?: AbortSignal;
        },
      ) => {
        if (!options?.after) {
          return { items: [membershipFixture(group)], nextCursor: "cursor-a" };
        }
        if (options.after === "cursor-a") {
          return { items: [secondMember], nextCursor: "cursor-b" };
        }
        secondCursorCalls += 1;
        return secondCursorCalls === 1
          ? { items: [loopMember], nextCursor: "cursor-a" }
          : { items: [recoveredMember] };
      },
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.read", "role.read", "user.read"]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const membershipPanel = screen.getByRole("tabpanel");
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Load more membership edges",
      }),
    );
    expect(
      await within(membershipPanel).findByText("Second responder"),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Load more membership edges" }),
    );
    expect(
      await screen.findByText("More membership edges could not be loaded"),
    ).toBeVisible();
    expect(screen.queryByText("Loop responder")).not.toBeInTheDocument();
    const retry = screen.getByRole("button", {
      name: "Load more membership edges",
    });
    expect(retry).toBeEnabled();

    fireEvent.click(retry);
    expect(
      await within(membershipPanel).findByText("Recovered responder"),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Load more membership edges" }),
    ).not.toBeInTheDocument();
  });

  it("retries exactly bound membership and role edges after expiry while rejecting unbound past edits", async () => {
    const group = groupFixture();
    const createTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValue(new Error("membership transport outcome is unknown"));
    const grantTenantSecurityGroupRole = vi
      .fn()
      .mockRejectedValue(new Error("role transport outcome is unknown"));
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership,
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        grantTenantSecurityGroupRole,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Add member edge" }),
    );
    fireEvent.click(
      await screen.findByRole("combobox", { name: "Tenant user" }),
    );
    fireEvent.click(
      await screen.findByRole("option", {
        name: "Mira Responder · mira@example.invalid",
      }),
    );
    fireEvent.change(screen.getByLabelText("Edge expiry"), {
      target: { value: "2099-08-23T12:00:00" },
    });
    const memberReason = screen.getByRole("textbox", { name: "Reason" });
    fireEvent.change(memberReason, { target: { value: "Bound membership" } });
    const memberSubmit = screen.getAllByRole("button", {
      name: "Add member edge",
    })[1];
    if (!memberSubmit) {
      throw new Error("Membership submit button was not rendered.");
    }
    fireEvent.click(memberSubmit);
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(memberSubmit).toBeEnabled());
    const membershipClock = vi
      .spyOn(Date, "now")
      .mockReturnValue(Date.parse("2100-01-01T00:00:00Z"));
    fireEvent.click(memberSubmit);
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(2),
    );
    expect(createTenantSecurityGroupMembership.mock.calls[1]?.[3]).toBe(
      createTenantSecurityGroupMembership.mock.calls[0]?.[3],
    );
    expect(createTenantSecurityGroupMembership.mock.calls[1]?.[4]).toEqual(
      createTenantSecurityGroupMembership.mock.calls[0]?.[4],
    );
    await waitFor(() => expect(memberSubmit).toBeEnabled());
    fireEvent.change(memberReason, {
      target: { value: "Unbound membership edit" },
    });
    fireEvent.click(memberSubmit);
    expect(
      await screen.findByText("Choose a future edge expiry."),
    ).toBeVisible();
    expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(2);
    membershipClock.mockRestore();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Add role edge" }),
    );
    fireEvent.click(
      await screen.findByRole("combobox", { name: "Tenant role" }),
    );
    fireEvent.click(
      await screen.findByRole("option", {
        name: "Incident commander · incident_commander",
      }),
    );
    fireEvent.change(screen.getByLabelText("Edge expiry"), {
      target: { value: "2099-08-23T12:00:00" },
    });
    const roleReason = screen.getByRole("textbox", { name: "Reason" });
    fireEvent.change(roleReason, { target: { value: "Bound role" } });
    const roleSubmit = screen.getAllByRole("button", {
      name: "Add role edge",
    })[1];
    if (!roleSubmit) {
      throw new Error("Role submit button was not rendered.");
    }
    fireEvent.click(roleSubmit);
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(roleSubmit).toBeEnabled());
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2100-01-01T00:00:00Z"));
    fireEvent.click(roleSubmit);
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(2),
    );
    expect(grantTenantSecurityGroupRole.mock.calls[1]?.[3]).toBe(
      grantTenantSecurityGroupRole.mock.calls[0]?.[3],
    );
    expect(grantTenantSecurityGroupRole.mock.calls[1]?.[4]).toEqual(
      grantTenantSecurityGroupRole.mock.calls[0]?.[4],
    );
    await waitFor(() => expect(roleSubmit).toBeEnabled());
    fireEvent.change(roleReason, { target: { value: "Unbound role edit" } });
    fireEvent.click(roleSubmit);
    expect(
      await screen.findByText("Choose a future edge expiry."),
    ).toBeVisible();
    expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(2);
  });

  it("keeps a membership add locked and preserves its draft across tab switches", async () => {
    const group = groupFixture();
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupMembershipView;
    }>();
    const createTenantSecurityGroupMembership = vi.fn(
      async () => createRequest.promise,
    );
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership,
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await submitMembershipAdd("Keep the pending member draft");
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    const pending = screen.getByRole("button", { name: "Adding member…" });
    expect(pending).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Keep the pending member draft",
    );
    fireEvent.click(pending);
    expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);

    await act(async () => {
      const membership = membershipFixture(group);
      createRequest.resolve({ etag: membership.etag, value: membership });
      await createRequest.promise;
    });
  });

  it("keeps a role add locked and preserves its draft across tab switches", async () => {
    const group = groupFixture();
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupRoleGrantView;
    }>();
    const grantTenantSecurityGroupRole = vi.fn(
      async () => createRequest.promise,
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        grantTenantSecurityGroupRole,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    await submitRoleAdd("Keep the pending role draft");
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    const pending = screen.getByRole("button", { name: "Adding role…" });
    expect(pending).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Keep the pending role draft",
    );
    fireEvent.click(pending);
    expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1);

    await act(async () => {
      const roleEdge = roleEdgeFixture(group);
      createRequest.resolve({ etag: roleEdge.etag, value: roleEdge });
      await createRequest.promise;
    });
  });

  it("reconciles a committed membership add while a same-group metadata reload retains its form", async () => {
    const group = groupFixture();
    const current = {
      ...group,
      description: "Concurrent server description",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const membership = membershipFixture(group);
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupMembershipView;
    }>();
    const createTenantSecurityGroupMembership = vi.fn(
      async () => createRequest.promise,
    );
    let committed = false;
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.manage",
        "group.membership.manage",
        "group.read",
        "role.grant",
        "role.read",
        "user.read",
      ]),
    );
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockResolvedValue({ etag: '"v4"', value: current });
    const listTenantSecurityGroupMemberships = vi.fn(async () => ({
      items: committed ? [membership] : [],
    }));
    const updateTenantSecurityGroup = vi
      .fn()
      .mockRejectedValue(new PhaseTwoApiError("stale metadata", 412));
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership,
        getTenantAuthority,
        getTenantSecurityGroup,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await submitMembershipAdd("Commit through metadata reload");
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
      target: { value: "Operator draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(
      await screen.findByText(/resource changed on the server/i),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load current version" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Security group · IR leads" }),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        listTenantSecurityGroupMemberships.mock.calls.length,
      ).toBeGreaterThanOrEqual(2),
    );
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(
      screen.getByRole("button", { name: "Adding member…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Commit through metadata reload",
    );

    committed = true;
    await act(async () => {
      createRequest.resolve({ etag: membership.etag, value: membership });
      await createRequest.promise;
    });

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    expect(
      await screen.findByRole("button", {
        name: "Revoke membership edge for Mira Responder (mira@example.invalid)",
      }),
    ).toBeVisible();
    expect(
      listTenantSecurityGroupMemberships.mock.calls.length,
    ).toBeGreaterThanOrEqual(3);
  });

  it("reconciles a committed role add while a same-group metadata reload retains its form", async () => {
    const group = groupFixture();
    const current = {
      ...group,
      description: "Concurrent server description",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const roleEdge = roleEdgeFixture(group);
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupRoleGrantView;
    }>();
    const grantTenantSecurityGroupRole = vi.fn(
      async () => createRequest.promise,
    );
    let committed = false;
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.manage",
        "group.membership.manage",
        "group.read",
        "role.grant",
        "role.read",
        "user.read",
      ]),
    );
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockResolvedValue({ etag: '"v4"', value: current });
    const listTenantSecurityGroupRoleGrants = vi.fn(async () => ({
      items: committed ? [roleEdge] : [],
    }));
    const updateTenantSecurityGroup = vi
      .fn()
      .mockRejectedValue(new PhaseTwoApiError("stale metadata", 412));
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantSecurityGroup,
        grantTenantSecurityGroupRole,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    await submitRoleAdd("Commit through metadata reload");
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
      target: { value: "Operator draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(
      await screen.findByText(/resource changed on the server/i),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load current version" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Security group · IR leads" }),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        listTenantSecurityGroupRoleGrants.mock.calls.length,
      ).toBeGreaterThanOrEqual(2),
    );
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    expect(screen.getByRole("button", { name: "Adding role…" })).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Commit through metadata reload",
    );

    committed = true;
    await act(async () => {
      createRequest.resolve({ etag: roleEdge.etag, value: roleEdge });
      await createRequest.promise;
    });

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        "Incident commander",
      ),
    ).toBeVisible();
    expect(
      listTenantSecurityGroupRoleGrants.mock.calls.length,
    ).toBeGreaterThanOrEqual(3);
  });

  it("preserves a rejected membership add and its bound key through a same-group metadata reload", async () => {
    const group = groupFixture();
    const current = concurrentGroupFixture(group);
    const membership = membershipFixture(group);
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupMembershipView;
    }>();
    const createTenantSecurityGroupMembership = vi
      .fn<PhaseTwoApi["createTenantSecurityGroupMembership"]>()
      .mockImplementationOnce(async () => createRequest.promise)
      .mockResolvedValueOnce({ etag: membership.etag, value: membership });
    const getTenantSecurityGroup = reloadingGroupDetail(group, current);
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership,
        getTenantAuthority: async () => fullyPrivilegedGroupAuthority(),
        getTenantSecurityGroup,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("stale metadata", 412);
        },
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await submitMembershipAdd("Retry the preserved membership");
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );
    const firstKey = createTenantSecurityGroupMembership.mock.calls[0]?.[3];
    const firstInput = createTenantSecurityGroupMembership.mock.calls[0]?.[4];
    expect(firstKey).toEqual(expect.any(String));
    expect(firstInput).toBeDefined();

    await reloadCurrentGroupAfterMetadataConflict(getTenantSecurityGroup);
    await act(async () => {
      createRequest.reject(
        new Error("membership transport outcome is unknown"),
      );
      await createRequest.promise.catch(() => undefined);
    });

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(
      await screen.findByText(
        "The membership edge was not added. Your input is preserved.",
      ),
    ).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Retry the preserved membership",
    );
    const retry = screen.getAllByRole("button", {
      name: "Add member edge",
    })[1];
    if (!retry)
      throw new Error("The membership retry button was not rendered.");
    fireEvent.click(retry);

    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(2),
    );
    expect(createTenantSecurityGroupMembership.mock.calls[1]?.[3]).toBe(
      firstKey,
    );
    expect(createTenantSecurityGroupMembership.mock.calls[1]?.[4]).toEqual(
      firstInput,
    );
  });

  it("clears the session when a membership add returns 401 after a same-group denial unmounts it", async () => {
    const group = groupFixture();
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupMembershipView;
    }>();
    const clearSession = vi.fn();
    const createTenantSecurityGroupMembership = vi.fn(
      async () => createRequest.promise,
    );
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockRejectedValue(new PhaseTwoApiError("forbidden detail", 403));
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership,
        getTenantAuthority: async () => fullyPrivilegedGroupAuthority(),
        getTenantSecurityGroup,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("stale metadata", 412);
        },
      }),
      clearSession,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await submitMembershipAdd("Expire the retained membership request");
    await waitFor(() =>
      expect(createTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );

    await reloadCurrentGroupAfterMetadataConflict(getTenantSecurityGroup);
    expect(await screen.findByText("Group detail denied")).toBeVisible();
    await waitFor(() =>
      expect(
        screen.queryByRole("button", {
          hidden: true,
          name: "Adding member…",
        }),
      ).not.toBeInTheDocument(),
    );
    await act(async () => {
      createRequest.reject(new PhaseTwoApiError("expired mutation", 401));
      await createRequest.promise.catch(() => undefined);
    });

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("preserves a rejected role add and its bound key through a same-group metadata reload", async () => {
    const group = groupFixture();
    const current = concurrentGroupFixture(group);
    const roleEdge = roleEdgeFixture(group);
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupRoleGrantView;
    }>();
    const grantTenantSecurityGroupRole = vi
      .fn<PhaseTwoApi["grantTenantSecurityGroupRole"]>()
      .mockImplementationOnce(async () => createRequest.promise)
      .mockResolvedValueOnce({ etag: roleEdge.etag, value: roleEdge });
    const getTenantSecurityGroup = reloadingGroupDetail(group, current);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => fullyPrivilegedGroupAuthority(),
        getTenantSecurityGroup,
        grantTenantSecurityGroupRole,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("stale metadata", 412);
        },
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    await submitRoleAdd("Retry the preserved role");
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1),
    );
    const firstKey = grantTenantSecurityGroupRole.mock.calls[0]?.[3];
    const firstInput = grantTenantSecurityGroupRole.mock.calls[0]?.[4];
    expect(firstKey).toEqual(expect.any(String));
    expect(firstInput).toBeDefined();

    await reloadCurrentGroupAfterMetadataConflict(getTenantSecurityGroup);
    await act(async () => {
      createRequest.reject(new Error("role transport outcome is unknown"));
      await createRequest.promise.catch(() => undefined);
    });

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    expect(
      await screen.findByText(
        "The role edge was not added. Your input is preserved.",
      ),
    ).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Reason" })).toHaveValue(
      "Retry the preserved role",
    );
    const retry = screen.getAllByRole("button", {
      name: "Add role edge",
    })[1];
    if (!retry) throw new Error("The role retry button was not rendered.");
    fireEvent.click(retry);

    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(2),
    );
    expect(grantTenantSecurityGroupRole.mock.calls[1]?.[3]).toBe(firstKey);
    expect(grantTenantSecurityGroupRole.mock.calls[1]?.[4]).toEqual(firstInput);
  });

  it("clears the session when a role add returns 401 after a same-group denial unmounts it", async () => {
    const group = groupFixture();
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupRoleGrantView;
    }>();
    const clearSession = vi.fn();
    const grantTenantSecurityGroupRole = vi.fn(
      async () => createRequest.promise,
    );
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockRejectedValue(new PhaseTwoApiError("forbidden detail", 403));
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => fullyPrivilegedGroupAuthority(),
        getTenantSecurityGroup,
        grantTenantSecurityGroupRole,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
        updateTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("stale metadata", 412);
        },
      }),
      clearSession,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    await submitRoleAdd("Expire the retained role request");
    await waitFor(() =>
      expect(grantTenantSecurityGroupRole).toHaveBeenCalledTimes(1),
    );

    await reloadCurrentGroupAfterMetadataConflict(getTenantSecurityGroup);
    expect(await screen.findByText("Group detail denied")).toBeVisible();
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { hidden: true, name: "Adding role…" }),
      ).not.toBeInTheDocument(),
    );
    await act(async () => {
      createRequest.reject(new PhaseTwoApiError("expired mutation", 401));
      await createRequest.promise.catch(() => undefined);
    });

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
  });

  it("ignores a late membership-add success after a newer group opens", async () => {
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupMembershipView;
    }>();
    const alpha = groupFixture({ name: "Alpha group" });
    const bravo = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000123",
      key: "bravo_group",
      name: "Bravo group",
    });
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.manage",
        "group.membership.manage",
        "group.read",
        "role.grant",
        "role.read",
        "user.read",
      ]),
    );
    renderGroups(
      createPhaseTwoApi({
        createTenantSecurityGroupMembership: async () => createRequest.promise,
        getTenantAuthority,
        getTenantSecurityGroup: async (_tenantId, requestedGroupId) => ({
          etag: '"v3"',
          value: requestedGroupId === alpha.id ? alpha : bravo,
        }),
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [alpha, bravo] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha group (ir_leads)",
      }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    await submitMembershipAdd("Complete after Alpha closes");
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo group (bravo_group)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Bravo group",
      }),
    ).toBeVisible();
    const authorityCalls = getTenantAuthority.mock.calls.length;

    await act(async () => {
      const membership = membershipFixture(alpha);
      createRequest.resolve({ etag: membership.etag, value: membership });
      await createRequest.promise;
      await Promise.resolve();
    });

    expect(getTenantAuthority).toHaveBeenCalledTimes(authorityCalls);
    expect(
      screen.getByRole("heading", { name: "Security group · Bravo group" }),
    ).toBeVisible();
  });

  it("ignores a late role-add success after a newer group opens", async () => {
    const createRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupRoleGrantView;
    }>();
    const alpha = groupFixture({ name: "Alpha group" });
    const bravo = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000123",
      key: "bravo_group",
      name: "Bravo group",
    });
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.manage",
        "group.membership.manage",
        "group.read",
        "role.grant",
        "role.read",
        "user.read",
      ]),
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantSecurityGroup: async (_tenantId, requestedGroupId) => ({
          etag: '"v3"',
          value: requestedGroupId === alpha.id ? alpha : bravo,
        }),
        grantTenantSecurityGroupRole: async () => createRequest.promise,
        listTenantRoles: async () => ({ items: [roleFixture()] }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [alpha, bravo] }),
        listTenantUsers: async () => ({ items: [userFixture()] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha group (ir_leads)",
      }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    await submitRoleAdd("Complete after Alpha closes");
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo group (bravo_group)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Bravo group",
      }),
    ).toBeVisible();
    const authorityCalls = getTenantAuthority.mock.calls.length;

    await act(async () => {
      const roleEdge = roleEdgeFixture(alpha);
      createRequest.resolve({ etag: roleEdge.etag, value: roleEdge });
      await createRequest.promise;
      await Promise.resolve();
    });

    expect(getTenantAuthority).toHaveBeenCalledTimes(authorityCalls);
    expect(
      screen.getByRole("heading", { name: "Security group · Bravo group" }),
    ).toBeVisible();
  });

  it("qualifies every membership-edge revoke control with the member email", async () => {
    const group = groupFixture();
    const first = membershipFixture(group);
    const second = {
      ...first,
      id: "0198c97d-cf4f-7000-8000-000000000164",
      member: {
        ...first.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000165",
        user: {
          ...first.member.user,
          email: "mira-secondary@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000166",
        },
      },
      provenance: {
        ...first.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000167",
      },
    };
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [first, second],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const targets = [
      "Mira Responder (mira@example.invalid)",
      "Mira Responder (mira-secondary@example.invalid)",
    ];
    await screen.findByRole("button", {
      name: `Revoke membership edge for ${targets[0]}`,
    });
    for (const target of targets) {
      fireEvent.click(
        screen.getByRole("button", {
          name: `Revoke membership edge for ${target}`,
        }),
      );
    }

    for (const target of targets) {
      const revokeGroup = screen.getByRole("group", {
        name: `Revoke membership edge for ${target}`,
      });
      expect(
        within(revokeGroup).getByRole("textbox", {
          name: `Reason for revoking membership edge for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Confirm revoke membership edge for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Keep edge; cancel revoke membership edge for ${target}`,
        }),
      ).toBeVisible();
    }
  });

  it("ignores lower-version ambiguity and reacquires the unique highest membership edge", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const firstPageMembership = {
      ...staleMembership,
      id: "0198c97d-cf4f-7000-8000-000000000168",
      member: {
        ...staleMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000169",
        user: {
          ...staleMembership.member.user,
          displayName: "First page responder",
          email: "first-page@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000170",
        },
      },
      provenance: {
        ...staleMembership.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000171",
      },
    };
    const currentMembership = {
      ...staleMembership,
      etag: '"v9-current-membership"',
      updatedAt: "2026-08-23T11:00:00Z",
      version: 9,
    };
    const lowerMembership = {
      ...staleMembership,
      etag: '"v6-lower-membership"',
      version: 6,
    };
    const equalVersionFreshMembership = {
      ...staleMembership,
      etag: '"v7-intermediate-membership"',
      member: {
        ...staleMembership.member,
        user: {
          ...staleMembership.member.user,
          displayName: "Mira Intermediate",
        },
      },
    };
    const firstLowerFreshMembership = {
      ...staleMembership,
      etag: '"v8-first-lower-fresh-membership"',
      version: 8,
    };
    const secondLowerFreshMembership = {
      ...staleMembership,
      etag: '"v8-second-lower-fresh-membership"',
      version: 8,
    };
    const revokedMembership = {
      ...currentMembership,
      etag: '"v10-revoked-membership"',
      revokeReason: "Remove completed rotation",
      revokedAt: "2026-08-23T11:30:00Z",
      revokedByUserId: sessionFixture.user.id,
      state: "revoked" as const,
      updatedAt: "2026-08-23T11:30:00Z",
      version: 10,
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [firstPageMembership],
        nextCursor: "membership-page-2",
      })
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({
        items: [
          firstPageMembership,
          staleMembership,
          lowerMembership,
          equalVersionFreshMembership,
          firstLowerFreshMembership,
          secondLowerFreshMembership,
        ],
        nextCursor: "membership-page-2",
      })
      .mockResolvedValueOnce({ items: [currentMembership] })
      .mockResolvedValue({ items: [revokedMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    const revokeGroup = screen.getByRole("group", {
      name: `Revoke membership edge for ${target}`,
    });
    expect(
      within(revokeGroup).getByRole("button", {
        name: `Keep edge; cancel revoke membership edge for ${target}`,
      }),
    ).toBeVisible();
    const reason = within(revokeGroup).getByRole("textbox", {
      name: `Reason for revoking membership edge for ${target}`,
    });
    fireEvent.change(reason, {
      target: { value: "Remove completed rotation" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    await waitFor(() =>
      expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(4),
    );
    expect(listTenantSecurityGroupMemberships.mock.calls[3]?.[2]?.after).toBe(
      "membership-page-2",
    );
    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    const reloadedReason = screen.getByRole("textbox", {
      name: `Reason for revoking membership edge for ${target}`,
    });
    expect(reloadedReason).toHaveValue("Remove completed rotation");
    expect(revokeTenantSecurityGroupMembership).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      group.id,
      staleMembership.id,
      staleMembership.etag,
      { reason: "Remove completed rotation" },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentMembership.id,
        currentMembership.etag,
        { reason: "Remove completed rotation" },
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(4);
  });

  it("fails exact refresh closed when its highest version has multiple fresh ETags", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const firstPageMembership = {
      ...staleMembership,
      id: "0198c97d-cf4f-7000-8000-000000000176",
      member: {
        ...staleMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000177",
        user: {
          ...staleMembership.member.user,
          displayName: "First page responder",
          email: "first-page-ambiguous@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000178",
        },
      },
    };
    const firstFreshMembership = {
      ...staleMembership,
      etag: '"v8-first-fresh-membership"',
      version: 8,
    };
    const secondFreshMembership = {
      ...staleMembership,
      etag: '"v8-second-fresh-membership"',
      version: 8,
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [firstPageMembership],
        nextCursor: "ambiguous-membership-page-2",
      })
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({
        items: [firstFreshMembership],
        nextCursor: "ambiguous-membership-page-2",
      })
      .mockResolvedValueOnce({ items: [secondFreshMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412));
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Keep ambiguous refresh blocked" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    expect(
      await screen.findByText(/multiple entity tags at resource version 8/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
    ).toHaveValue("Keep ambiguous refresh blocked");
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);
  });

  it("preserves a page-two membership revoke draft when stale-edge refresh fails and lets the operator retry", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const firstPageMembership = {
      ...staleMembership,
      id: "0198c97d-cf4f-7000-8000-000000000172",
      member: {
        ...staleMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000173",
        user: {
          ...staleMembership.member.user,
          displayName: "First page responder",
          email: "first-page@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000174",
        },
      },
      provenance: {
        ...staleMembership.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000175",
      },
    };
    const currentMembership = {
      ...staleMembership,
      etag: '"v8-after-refresh-recovery"',
      updatedAt: "2026-08-23T12:00:00Z",
      version: 8,
    };
    const revokedMembership = {
      ...currentMembership,
      etag: '"v9-after-refresh-revoke"',
      revokeReason: "Preserve this recovery draft",
      revokedAt: "2026-08-23T12:15:00Z",
      revokedByUserId: sessionFixture.user.id,
      state: "revoked" as const,
      updatedAt: "2026-08-23T12:15:00Z",
      version: 9,
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [firstPageMembership],
        nextCursor: "membership-page-2",
      })
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({
        items: [firstPageMembership],
        nextCursor: "membership-page-2",
      })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("Membership refresh unavailable.", 503),
      )
      .mockResolvedValueOnce({
        items: [firstPageMembership],
        nextCursor: "membership-page-2",
      })
      .mockResolvedValueOnce({ items: [currentMembership] })
      .mockResolvedValue({ items: [revokedMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Preserve this recovery draft" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    await screen.findByRole("button", {
      name: `Retry loading current membership edge for ${target}`,
    });
    expect(screen.getByText(/Membership refresh unavailable/)).toBeVisible();
    expect(screen.getByText(/Retry loading the current edge/)).toBeVisible();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
    ).toHaveValue("Preserve this recovery draft");
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    ).toBeDisabled();

    fireEvent.click(
      screen.getByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    );
    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
    ).toHaveValue("Preserve this recovery draft");
    await waitFor(() =>
      expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(6),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentMembership.id,
        currentMembership.etag,
        { reason: "Preserve this recovery draft" },
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(6);
  });

  it("keeps a rejected membership ETag blocked until an equal-version full representation changes", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const currentMembership = {
      ...staleMembership,
      etag: '"v7-after-user-summary-change"',
      member: {
        ...staleMembership.member,
        user: {
          ...staleMembership.member.user,
          displayName: "Mira Refreshed",
        },
      },
      updatedAt: "2026-08-23T12:30:00Z",
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({ items: [currentMembership] })
      .mockResolvedValue({ items: [currentMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Do not reuse the rejected ETag" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    await screen.findByRole("button", {
      name: `Retry loading current membership edge for ${target}`,
    });
    const blockedConfirm = screen.getByRole("button", {
      name: `Confirm revoke membership edge for ${target}`,
    });
    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(2);
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);
    expect(blockedConfirm).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
    ).toHaveValue("Do not reuse the rejected ETag");
    expect(screen.getByText(/could not be reloaded/)).toBeVisible();

    fireEvent.click(blockedConfirm);
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(
      screen.getByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
    ).toHaveValue("Do not reuse the rejected ETag");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    );

    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(3);
    const currentTarget = "Mira Refreshed (mira@example.invalid)";
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${currentTarget}`,
      }),
    ).toHaveValue("Do not reuse the rejected ETag");
    const currentConfirm = screen.getByRole("button", {
      name: `Confirm revoke membership edge for ${currentTarget}`,
    });
    expect(currentConfirm).toBeEnabled();
    fireEvent.click(currentConfirm);

    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentMembership.id,
        currentMembership.etag,
        { reason: "Do not reuse the rejected ETag" },
      ),
    );
  });

  it("keeps an equal-version exact refresh when delayed old pagination arrives", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const refreshedMembership = {
      ...staleMembership,
      etag: '"v7-refreshed-user-summary"',
      member: {
        ...staleMembership.member,
        user: {
          ...staleMembership.member.user,
          displayName: "Mira Current",
        },
      },
    };
    const delayedPageCompanion = {
      ...staleMembership,
      etag: '"v7-delayed-page-companion"',
      id: "0198c97d-cf4f-7000-8000-000000000179",
      member: {
        ...staleMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000180",
        user: {
          ...staleMembership.member.user,
          displayName: "Delayed page companion",
          email: "delayed-page@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000181",
        },
      },
      provenance: {
        ...staleMembership.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000182",
      },
    };
    const delayedPage = createDeferred<{
      items: TenantSecurityGroupMembershipView[];
    }>();
    let firstPageLoads = 0;
    const listTenantSecurityGroupMemberships = vi.fn(
      async (
        _tenantId: string,
        _groupId: string,
        options?: { after?: string },
      ) => {
        if (options?.after === "delayed-membership-page") {
          return delayedPage.promise;
        }
        firstPageLoads += 1;
        return firstPageLoads === 1
          ? {
              items: [staleMembership],
              nextCursor: "delayed-membership-page",
            }
          : { items: [refreshedMembership] };
      },
    );
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );
    const staleTarget = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      screen.getByRole("button", {
        name: `Revoke membership edge for ${staleTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${staleTarget}`,
      }),
      { target: { value: "Keep exact refresh ahead of old page" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${staleTarget}`,
      }),
    );

    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    const currentTarget = "Mira Current (mira@example.invalid)";
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${currentTarget}`,
      }),
    ).toHaveValue("Keep exact refresh ahead of old page");

    await act(async () => {
      delayedPage.resolve({ items: [staleMembership, delayedPageCompanion] });
      await delayedPage.promise;
    });
    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        "Delayed page companion",
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        screen.queryByRole("button", {
          name: "Load more membership edges",
        }),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${currentTarget}`,
      }),
    ).toHaveValue("Keep exact refresh ahead of old page");
    expect(
      screen.queryByRole("button", {
        name: `Confirm revoke membership edge for ${staleTarget}`,
      }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${currentTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        refreshedMembership.id,
        refreshedMembership.etag,
        { reason: "Keep exact refresh ahead of old page" },
      ),
    );
  });

  it("fails stale recovery closed on a third same-version ETag", async () => {
    const group = groupFixture();
    const rejectedMembership = membershipFixture(group);
    const acceptedMembership = {
      ...rejectedMembership,
      etag: '"v8-current-summary-a"',
      member: {
        ...rejectedMembership.member,
        user: {
          ...rejectedMembership.member.user,
          displayName: "Mira Current A",
        },
      },
      version: 8,
    };
    const refreshCandidate = {
      ...acceptedMembership,
      etag: '"v8-refresh-summary-b"',
      member: {
        ...acceptedMembership.member,
        user: {
          ...acceptedMembership.member.user,
          displayName: "Mira Refresh B",
        },
      },
    };
    const revokeRequest = createDeferred<void>();
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [rejectedMembership],
        nextCursor: "newer-membership-page",
      })
      .mockResolvedValueOnce({ items: [acceptedMembership] })
      .mockResolvedValueOnce({ items: [refreshCandidate] });
    const revokeTenantSecurityGroupMembership = vi.fn(
      async () => revokeRequest.promise,
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const rejectedTarget = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${rejectedTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${rejectedTarget}`,
      }),
      { target: { value: "Do not choose among three tuples" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${rejectedTarget}`,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Load more membership edges" }),
    );
    const acceptedTarget = "Mira Current A (mira@example.invalid)";
    await screen.findByRole("button", {
      name: `Revoking membership edge for ${acceptedTarget}`,
    });

    await act(async () => {
      revokeRequest.reject(new PhaseTwoApiError("stale", 412));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(
      await screen.findByText(/third entity tag at resource version 8/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Retry loading current membership edge for ${acceptedTarget}`,
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${acceptedTarget}`,
      }),
    ).toBeDisabled();
    expect(screen.queryByText("Mira Refresh B")).not.toBeInTheDocument();
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);
  });

  it("clears stale revoke UI when refresh returns a terminal edge", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const revokedMembership = {
      ...staleMembership,
      etag: '"v8-revoked-membership"',
      revokeReason: "Already revoked by another operator",
      revokedAt: "2026-08-23T13:30:00Z",
      revokedByUserId: sessionFixture.user.id,
      state: "revoked" as const,
      updatedAt: "2026-08-23T13:30:00Z",
      version: 8,
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({ items: [revokedMembership] })
      .mockResolvedValue({ items: [revokedMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412));
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "This draft must close" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    await waitFor(() =>
      expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(2),
    );
    expect(
      screen.queryByRole("group", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/We reloaded the current edge/),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByRole("tabpanel")).getByText(
        "Already revoked by another operator",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).not.toBeInTheDocument();
  });

  it("clears stale revoke UI when the refreshed edge is no longer API-managed", async () => {
    const group = groupFixture();
    const staleMembership = membershipFixture(group);
    const mappedMembership = {
      ...staleMembership,
      etag: '"v8-mapped-membership"',
      managedByAuthorizationApi: false,
      provenance: {
        ...staleMembership.provenance,
        authoritative: true,
        sourceKind: "identity_mapping" as const,
      },
      updatedAt: "2026-08-23T13:45:00Z",
      version: 8,
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleMembership] })
      .mockResolvedValueOnce({ items: [mappedMembership] })
      .mockResolvedValue({ items: [mappedMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412));
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Source ownership changed" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    expect(
      await screen.findByText(
        /Not managed by the authorization API \(source: identity mapping\); manual controls cannot reconcile or revoke this edge/i,
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("group", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: `Retry loading current membership edge for ${target}`,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/We reloaded the current edge/),
    ).not.toBeInTheDocument();
  });

  it("does not let an overlapping older page downgrade a membership edge", async () => {
    const group = groupFixture();
    const olderMembership = membershipFixture(group);
    const currentMembership = {
      ...olderMembership,
      etag: '"v8-current-overlapping-membership"',
      updatedAt: "2026-08-23T14:00:00Z",
      version: 8,
    };
    const olderPageCompanion = {
      ...olderMembership,
      etag: '"v7-older-page-companion"',
      id: "0198c97d-cf4f-7000-8000-000000000183",
      member: {
        ...olderMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000184",
        user: {
          ...olderMembership.member.user,
          displayName: "Older page companion",
          email: "older-page@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000185",
        },
      },
      provenance: {
        ...olderMembership.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000186",
      },
    };
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [currentMembership],
        nextCursor: "overlapping-membership-page",
      })
      .mockResolvedValueOnce({
        items: [olderMembership, olderPageCompanion],
      })
      .mockResolvedValue({ items: [currentMembership] });
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockResolvedValue(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );
    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        "Older page companion",
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        screen.queryByRole("button", {
          name: "Load more membership edges",
        }),
      ).not.toBeInTheDocument(),
    );
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Use the newest overlapping edge" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );

    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentMembership.id,
        currentMembership.etag,
        { reason: "Use the newest overlapping edge" },
      ),
    );
  });

  it("retains the accepted edge when unordered pagination returns another equal-version ETag", async () => {
    const group = groupFixture();
    const currentMembership = membershipFixture(group, {
      etag: '"v8-first-membership-etag"',
      version: 8,
    });
    const conflictingMembership = {
      ...currentMembership,
      etag: '"v8-conflicting-membership-etag"',
      member: {
        ...currentMembership.member,
        user: {
          ...currentMembership.member.user,
          displayName: "Unordered duplicate",
        },
      },
    };
    const equalVersionPageCompanion = {
      ...currentMembership,
      etag: '"v8-equal-version-page-companion"',
      id: "0198c97d-cf4f-7000-8000-000000000187",
      member: {
        ...currentMembership.member,
        membershipId: "0198c97d-cf4f-7000-8000-000000000188",
        user: {
          ...currentMembership.member.user,
          displayName: "Equal-version page companion",
          email: "equal-version-page@example.invalid",
          id: "0198c97d-cf4f-7000-8000-000000000189",
        },
      },
      provenance: {
        ...currentMembership.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000190",
      },
    };
    const revokeTenantSecurityGroupMembership = vi
      .fn()
      .mockResolvedValue(undefined);
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValueOnce({
        items: [currentMembership],
        nextCursor: "conflicting-membership-page",
      })
      .mockResolvedValueOnce({
        items: [conflictingMembership, equalVersionPageCompanion],
      });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more membership edges" }),
    );

    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        "Equal-version page companion",
      ),
    ).toBeVisible();
    await waitFor(() =>
      expect(
        screen.queryByRole("button", {
          name: "Load more membership edges",
        }),
      ).not.toBeInTheDocument(),
    );
    const target = "Mira Responder (mira@example.invalid)";
    expect(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    ).toBeVisible();
    expect(screen.queryByText("Unordered duplicate")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Keep the accepted tuple" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentMembership.id,
        currentMembership.etag,
        { reason: "Keep the accepted tuple" },
      ),
    );
  });

  it.each([
    [
      "whose ETag version prefix does not match",
      { etag: '"v8-wrong-version-prefix"' },
    ],
    [
      "above the contract version maximum",
      {
        etag: '"v2147483648-over-contract-maximum"',
        version: 2_147_483_648,
      },
    ],
  ])("rejects a first-seen edge %s", async (_case, overrides) => {
    const group = groupFixture();
    const malformedMembership = membershipFixture(group, overrides);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.membership.manage",
            "group.read",
            "role.grant",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [malformedMembership],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    expect(
      await within(screen.getByRole("tabpanel")).findByText(
        /invalid resource version/i,
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Retry membership edges" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: "Revoke membership edge for Mira Responder (mira@example.invalid)",
      }),
    ).not.toBeInTheDocument();
  });

  it("drops an old pagination page across an A-to-B-to-A tenant cycle", async () => {
    const oldPage = createDeferred<{
      items: TenantSecurityGroupView[];
      nextCursor?: string;
    }>();
    let firstTenantLoads = 0;
    const api = createPhaseTwoApi({
      getTenantAuthority: async (requestedTenantId) =>
        authorityFixture(["group.read"], requestedTenantId),
      listTenantSecurityGroups: async (requestedTenantId, options) => {
        if (options?.after === "cursor-a") {
          return oldPage.promise;
        }
        if (requestedTenantId === otherTenantId) {
          return {
            items: [
              groupFixture({
                id: "0198c97d-cf4f-7000-8000-000000000120",
                key: "tenant_b",
                name: "Tenant B group",
                tenantId: otherTenantId,
              }),
            ],
          };
        }
        firstTenantLoads += 1;
        return firstTenantLoads === 1
          ? {
              items: [groupFixture({ key: "first_a", name: "First A group" })],
              nextCursor: "cursor-a",
            }
          : {
              items: [
                groupFixture({
                  id: "0198c97d-cf4f-7000-8000-000000000121",
                  key: "fresh_a",
                  name: "Fresh A group",
                }),
              ],
            };
      },
    });
    render(<SwitchingGroupsHarness api={api} />);

    await screen.findByText("First A group");
    fireEvent.click(screen.getByRole("button", { name: "Load more groups" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Switch group tenant" }),
    );
    await screen.findByText("Tenant B group");
    fireEvent.click(
      screen.getByRole("button", { name: "Switch original group tenant" }),
    );
    await screen.findByText("Fresh A group");

    await act(async () => {
      oldPage.resolve({
        items: [
          groupFixture({
            id: "0198c97d-cf4f-7000-8000-000000000122",
            key: "stale_a",
            name: "Stale A page",
          }),
        ],
      });
      await Promise.resolve();
    });

    expect(screen.queryByText("Stale A page")).not.toBeInTheDocument();
    expect(screen.getByText("Fresh A group")).toBeVisible();
  });

  it("fails closed on a non-immediate group cursor cycle and keeps retry available", async () => {
    const secondGroup = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000124",
      key: "second_group",
      name: "Second group",
    });
    const loopGroup = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000125",
      key: "loop_group",
      name: "Loop group",
    });
    const recoveredGroup = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000126",
      key: "recovered_group",
      name: "Recovered group",
    });
    let secondCursorCalls = 0;
    const listTenantSecurityGroups = vi.fn(
      async (
        _requestedTenantId: string,
        options?: {
          after?: string;
          includeArchived?: boolean;
          signal?: AbortSignal;
        },
      ) => {
        if (!options?.after) {
          return {
            items: [groupFixture()],
            nextCursor: "cursor-a",
          };
        }
        if (options.after === "cursor-a") {
          return { items: [secondGroup], nextCursor: "cursor-b" };
        }
        secondCursorCalls += 1;
        return secondCursorCalls === 1
          ? { items: [loopGroup], nextCursor: "cursor-a" }
          : { items: [recoveredGroup] };
      },
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["group.read"]),
        listTenantSecurityGroups,
      }),
    );

    await screen.findByText("IR leads");
    fireEvent.click(screen.getByRole("button", { name: "Load more groups" }));
    expect(await screen.findByText("Second group")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Load more groups" }));
    expect(
      await screen.findByText("More groups could not be loaded"),
    ).toBeVisible();
    expect(screen.queryByText("Loop group")).not.toBeInTheDocument();
    const retry = screen.getByRole("button", { name: "Load more groups" });
    expect(retry).toBeEnabled();

    fireEvent.click(retry);
    expect(await screen.findByText("Recovered group")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Load more groups" }),
    ).not.toBeInTheDocument();
  });

  it("does not let a closed detail response overwrite a newly opened group", async () => {
    const alphaDetail = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    const alpha = groupFixture({ name: "Alpha group" });
    const bravo = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000123",
      key: "bravo_group",
      name: "Bravo group",
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["group.read"]),
        getTenantSecurityGroup: async (_tenantId, requestedGroupId) =>
          requestedGroupId === alpha.id
            ? alphaDetail.promise
            : { etag: '"v3"', value: bravo },
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [alpha, bravo] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha group (ir_leads)",
      }),
    );
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo group (bravo_group)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Bravo group",
      }),
    ).toBeVisible();

    await act(async () => {
      alphaDetail.resolve({ etag: '"v3"', value: alpha });
      await Promise.resolve();
    });
    expect(
      screen.getByRole("heading", { name: "Security group · Bravo group" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Security group · Alpha group" }),
    ).not.toBeInTheDocument();
  });

  it("requires every static permission before offering manual edge revocation", async () => {
    const group = groupFixture();
    const manualRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [membershipFixture(group)],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [manualRoleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    expect(
      screen.queryByRole("button", {
        name: "Revoke membership edge for Mira Responder (mira@example.invalid)",
      }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    expect(
      screen.queryByRole("button", {
        name: "Revoke role edge for Incident commander (incident_commander)",
      }),
    ).not.toBeInTheDocument();
  });

  it("reacquires a stale page-two group-role edge in place and retries with its current ETag", async () => {
    const group = groupFixture();
    const manualRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    const firstPageRoleEdge = {
      ...manualRoleEdge,
      id: "0198c97d-cf4f-7000-8000-000000000172",
      provenance: {
        ...manualRoleEdge.provenance,
        sourceId: "0198c97d-cf4f-7000-8000-000000000173",
      },
      role: {
        ...manualRoleEdge.role,
        id: "0198c97d-cf4f-7000-8000-000000000174",
        key: "first_page_role",
        name: "First page role",
      },
    };
    const currentRoleEdge = {
      ...manualRoleEdge,
      etag: '"v4-current-role-summary"',
      role: {
        ...manualRoleEdge.role,
        name: "Incident commander refreshed",
      },
      updatedAt: "2026-08-23T11:00:00Z",
    };
    const revokedRoleEdge = {
      ...currentRoleEdge,
      etag: '"v5-revoked-role-summary"',
      revokeReason: "Remove role mapping",
      revokedAt: "2026-08-23T11:30:00Z",
      revokedByUserId: sessionFixture.user.id,
      state: "revoked" as const,
      updatedAt: "2026-08-23T11:30:00Z",
      version: 5,
    };
    const listTenantSecurityGroupRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({
        items: [firstPageRoleEdge],
        nextCursor: "role-page-2",
      })
      .mockResolvedValueOnce({ items: [manualRoleEdge] })
      .mockResolvedValueOnce({
        items: [firstPageRoleEdge],
        nextCursor: "role-page-2",
      })
      .mockResolvedValueOnce({ items: [currentRoleEdge] })
      .mockResolvedValue({ items: [revokedRoleEdge] });
    const revokeTenantSecurityGroupRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.read",
            "role.grant",
            "role.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Load more role edges" }),
    );
    const target = "Incident commander (incident_commander)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke role edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${target}`,
      }),
      { target: { value: "Remove role mapping" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${target}`,
      }),
    );

    await waitFor(() =>
      expect(listTenantSecurityGroupRoleGrants).toHaveBeenCalledTimes(4),
    );
    expect(listTenantSecurityGroupRoleGrants.mock.calls[3]?.[2]?.after).toBe(
      "role-page-2",
    );
    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    const currentTarget = "Incident commander refreshed (incident_commander)";
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${currentTarget}`,
      }),
    ).toHaveValue("Remove role mapping");
    expect(revokeTenantSecurityGroupRoleGrant).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      group.id,
      manualRoleEdge.id,
      manualRoleEdge.etag,
      { reason: "Remove role mapping" },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${currentTarget}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentRoleEdge.id,
        currentRoleEdge.etag,
        { reason: "Remove role mapping" },
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(listTenantSecurityGroupRoleGrants).toHaveBeenCalledTimes(4);
  });

  it("preserves a failed role refresh gate across tab switches", async () => {
    const group = groupFixture();
    const staleRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    const currentRoleEdge = {
      ...staleRoleEdge,
      etag: '"v5-role-refresh-recovery"',
      updatedAt: "2026-08-23T13:00:00Z",
      version: 5,
    };
    const revokedRoleEdge = {
      ...currentRoleEdge,
      etag: '"v6-role-refresh-revoked"',
      revokeReason: "Keep the role recovery draft",
      revokedAt: "2026-08-23T13:15:00Z",
      revokedByUserId: sessionFixture.user.id,
      state: "revoked" as const,
      updatedAt: "2026-08-23T13:15:00Z",
      version: 6,
    };
    const roleRefresh = createDeferred<{
      items: TenantSecurityGroupRoleGrantView[];
    }>();
    const listTenantSecurityGroupRoleGrants = vi
      .fn()
      .mockResolvedValueOnce({ items: [staleRoleEdge] })
      .mockImplementationOnce(async () => roleRefresh.promise)
      .mockResolvedValueOnce({ items: [currentRoleEdge] })
      .mockResolvedValue({ items: [revokedRoleEdge] });
    const revokeTenantSecurityGroupRoleGrant = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale", 412))
      .mockResolvedValueOnce(undefined);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.read",
            "role.grant",
            "role.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    const target = "Incident commander (incident_commander)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke role edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${target}`,
      }),
      { target: { value: "Keep the role recovery draft" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${target}`,
      }),
    );

    const refreshing = await screen.findByRole("button", {
      name: `Retry loading current role edge for ${target}`,
    });
    expect(refreshing).toBeDisabled();
    expect(refreshing).toHaveTextContent("Reloading current edge");
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(listTenantSecurityGroupRoleGrants).toHaveBeenCalledTimes(2);

    await act(async () => {
      roleRefresh.reject(new PhaseTwoApiError("Role refresh failed.", 503));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByText(/Role refresh failed/)).not.toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    expect(screen.getByText(/Role refresh failed/)).toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));

    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${target}`,
      }),
    ).toHaveValue("Keep the role recovery draft");
    expect(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${target}`,
      }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", {
        name: `Retry loading current role edge for ${target}`,
      }),
    );
    expect(
      await screen.findByText(/We reloaded the current edge/),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupRoleGrant).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        currentRoleEdge.id,
        currentRoleEdge.etag,
        { reason: "Keep the role recovery draft" },
      ),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(listTenantSecurityGroupRoleGrants).toHaveBeenCalledTimes(3);
  });

  it("keeps membership and role revoke locks active across tab switches", async () => {
    const group = groupFixture();
    const membership = membershipFixture(group);
    const roleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    const membershipRevoke = createDeferred<void>();
    const roleRevoke = createDeferred<void>();
    const revokeTenantSecurityGroupMembership = vi.fn(
      async () => membershipRevoke.promise,
    );
    const revokeTenantSecurityGroupRoleGrant = vi.fn(
      async () => roleRevoke.promise,
    );
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValue({ items: [membership] });
    const listTenantSecurityGroupRoleGrants = vi
      .fn()
      .mockResolvedValue({ items: [roleEdge] });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
        revokeTenantSecurityGroupRoleGrant,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    const membershipTarget = "Mira Responder (mira@example.invalid)";
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${membershipTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${membershipTarget}`,
      }),
      { target: { value: "Membership request remains locked" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${membershipTarget}`,
      }),
    );
    await screen.findByRole("button", {
      name: `Revoking membership edge for ${membershipTarget}`,
    });

    const roleTarget = "Incident commander (incident_commander)";
    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke role edge for ${roleTarget}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${roleTarget}`,
      }),
      { target: { value: "Role request remains locked" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke role edge for ${roleTarget}`,
      }),
    );
    await screen.findByRole("button", {
      name: `Revoking role edge for ${roleTarget}`,
    });

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    const lockedMembership = screen.getByRole("button", {
      name: `Revoking membership edge for ${membershipTarget}`,
    });
    expect(lockedMembership).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${membershipTarget}`,
      }),
    ).toHaveValue("Membership request remains locked");
    fireEvent.click(lockedMembership);
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    const lockedRole = screen.getByRole("button", {
      name: `Revoking role edge for ${roleTarget}`,
    });
    expect(lockedRole).toBeDisabled();
    expect(
      screen.getByRole("textbox", {
        name: `Reason for revoking role edge for ${roleTarget}`,
      }),
    ).toHaveValue("Role request remains locked");
    fireEvent.click(lockedRole);
    expect(revokeTenantSecurityGroupRoleGrant).toHaveBeenCalledTimes(1);

    const membershipListCallsBeforeSuccess =
      listTenantSecurityGroupMemberships.mock.calls.length;
    await act(async () => {
      membershipRevoke.resolve(undefined);
      await membershipRevoke.promise;
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(
      membershipListCallsBeforeSuccess,
    );
    const roleListCallsBeforeSuccess =
      listTenantSecurityGroupRoleGrants.mock.calls.length;
    await act(async () => {
      roleRevoke.resolve(undefined);
      await roleRevoke.promise;
    });
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(listTenantSecurityGroupRoleGrants).toHaveBeenCalledTimes(
      roleListCallsBeforeSuccess,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1);
    expect(revokeTenantSecurityGroupRoleGrant).toHaveBeenCalledTimes(1);
  });

  it("does not start stale recovery after the group detail unmounts", async () => {
    const group = groupFixture();
    const membership = membershipFixture(group);
    const revokeRequest = createDeferred<void>();
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.membership.manage",
        "group.read",
        "role.grant",
        "user.read",
      ]),
    );
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValue({ items: [membership] });
    const revokeTenantSecurityGroupMembership = vi.fn(
      async () => revokeRequest.promise,
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Unmount while request is pending" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const authorityCallsBeforeLateResponse =
      getTenantAuthority.mock.calls.length;

    await act(async () => {
      revokeRequest.reject(new PhaseTwoApiError("late stale response", 412));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(1);
    expect(getTenantAuthority).toHaveBeenCalledTimes(
      authorityCallsBeforeLateResponse,
    );
  });

  it("does not run successful revoke callbacks after the group detail unmounts", async () => {
    const group = groupFixture();
    const membership = membershipFixture(group);
    const revokeRequest = createDeferred<void>();
    const getTenantAuthority = vi.fn(async () =>
      authorityFixture([
        "group.membership.manage",
        "group.read",
        "role.grant",
        "user.read",
      ]),
    );
    const listTenantSecurityGroupMemberships = vi
      .fn()
      .mockResolvedValue({ items: [membership] });
    const revokeTenantSecurityGroupMembership = vi.fn(
      async () => revokeRequest.promise,
    );
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority,
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships,
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        revokeTenantSecurityGroupMembership,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    const target = "Mira Responder (mira@example.invalid)";
    fireEvent.click(
      await screen.findByRole("button", {
        name: `Revoke membership edge for ${target}`,
      }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: `Reason for revoking membership edge for ${target}`,
      }),
      { target: { value: "Close before successful response" } },
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: `Confirm revoke membership edge for ${target}`,
      }),
    );
    await waitFor(() =>
      expect(revokeTenantSecurityGroupMembership).toHaveBeenCalledTimes(1),
    );
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    const membershipCallsBeforeLateSuccess =
      listTenantSecurityGroupMemberships.mock.calls.length;
    const authorityCallsBeforeLateSuccess =
      getTenantAuthority.mock.calls.length;

    await act(async () => {
      revokeRequest.resolve(undefined);
      await revokeRequest.promise;
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(listTenantSecurityGroupMemberships).toHaveBeenCalledTimes(
      membershipCallsBeforeLateSuccess,
    );
    expect(getTenantAuthority).toHaveBeenCalledTimes(
      authorityCallsBeforeLateSuccess,
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("qualifies every role-edge revoke control with the unique role key", async () => {
    const group = groupFixture();
    const firstBase = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "First manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
    });
    const first = {
      ...firstBase,
      id: "0198c97d-cf4f-7000-8000-000000000162",
      role: {
        ...firstBase.role,
        id: "0198c97d-cf4f-7000-8000-000000000142",
        key: "incident_commander_primary",
      },
    };
    const secondBase = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        grantedAt: "2026-08-21T11:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Second manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000154",
        sourceKind: "manual",
      },
    });
    const second = {
      ...secondBase,
      id: "0198c97d-cf4f-7000-8000-000000000163",
      role: {
        ...secondBase.role,
        id: "0198c97d-cf4f-7000-8000-000000000143",
        key: "incident_commander_secondary",
      },
    };
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.read",
            "role.grant",
            "role.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [first, second],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Roles" }));
    const targets = [
      "Incident commander (incident_commander_primary)",
      "Incident commander (incident_commander_secondary)",
    ];
    await screen.findByRole("button", {
      name: `Revoke role edge for ${targets[0]}`,
    });
    for (const target of targets) {
      fireEvent.click(
        screen.getByRole("button", {
          name: `Revoke role edge for ${target}`,
        }),
      );
    }

    for (const target of targets) {
      const revokeGroup = screen.getByRole("group", {
        name: `Revoke role edge for ${target}`,
      });
      expect(revokeGroup).toBeVisible();
      expect(
        within(revokeGroup).getByRole("textbox", {
          name: `Reason for revoking role edge for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Confirm revoke role edge for ${target}`,
        }),
      ).toBeVisible();
      expect(
        within(revokeGroup).getByRole("button", {
          name: `Keep edge; cancel revoke role edge for ${target}`,
        }),
      ).toBeVisible();
    }
  });

  it("keeps a metadata save and archive confirmation locked across tab switches", async () => {
    const group = groupFixture();
    const updated = {
      ...group,
      name: "IR leads updated",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const updateRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    const archiveTenantSecurityGroup = vi.fn(async () => undefined);
    const updateTenantSecurityGroup = vi.fn(async () => updateRequest.promise);
    renderGroups(
      createPhaseTwoApi({
        archiveTenantSecurityGroup,
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive group" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
      target: { value: updated.name },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updateTenantSecurityGroup).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    const saving = screen.getByRole("button", { name: "Saving changes…" });
    const confirmArchive = screen.getByRole("button", {
      name: "Confirm archive",
    });
    expect(saving).toBeDisabled();
    expect(confirmArchive).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Group name" })).toHaveValue(
      updated.name,
    );
    fireEvent.click(saving);
    fireEvent.click(confirmArchive);
    expect(updateTenantSecurityGroup).toHaveBeenCalledTimes(1);
    expect(archiveTenantSecurityGroup).not.toHaveBeenCalled();

    await act(async () => {
      updateRequest.resolve({ etag: '"v4"', value: updated });
      await updateRequest.promise;
    });
    expect(
      await screen.findByRole("heading", {
        name: "Security group · IR leads updated",
      }),
    ).toBeVisible();
  });

  it("keeps an archive request locked across tab switches", async () => {
    const group = groupFixture();
    const archiveRequest = createDeferred<void>();
    const archiveTenantSecurityGroup = vi.fn(
      async () => archiveRequest.promise,
    );
    const updateTenantSecurityGroup = vi.fn();
    renderGroups(
      createPhaseTwoApi({
        archiveTenantSecurityGroup,
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive group" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm archive" }));
    await waitFor(() =>
      expect(archiveTenantSecurityGroup).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    const archiving = screen.getByRole("button", { name: "Archiving…" });
    const save = screen.getByRole("button", { name: "Save changes" });
    expect(archiving).toBeDisabled();
    expect(save).toBeDisabled();
    fireEvent.click(archiving);
    fireEvent.click(save);
    expect(archiveTenantSecurityGroup).toHaveBeenCalledTimes(1);
    expect(updateTenantSecurityGroup).not.toHaveBeenCalled();

    await act(async () => {
      archiveRequest.resolve(undefined);
      await archiveRequest.promise;
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("keeps expired manual edges revocable after their group is archived", async () => {
    const group = groupFixture({
      archived: true,
      archivedAt: "2026-08-23T09:00:00Z",
    });
    const expiredMembership = membershipFixture(group, {
      provenance: {
        ...membershipFixture(group).provenance,
        expiresAt: "2026-08-22T09:00:00Z",
      },
      state: "expired",
    });
    const expiredRoleEdge = roleEdgeFixture(group, {
      managedByAuthorizationApi: true,
      provenance: {
        authoritative: false,
        expiresAt: "2026-08-22T09:00:00Z",
        grantedAt: "2026-08-21T10:00:00Z",
        grantedByUserId: sessionFixture.user.id,
        reason: "Manual role decision",
        sourceId: "0198c97d-cf4f-7000-8000-000000000153",
        sourceKind: "manual",
      },
      state: "expired",
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup: async () => ({ etag: '"v3"', value: group }),
        listTenantSecurityGroupMemberships: async () => ({
          items: [expiredMembership],
        }),
        listTenantSecurityGroupRoleGrants: async () => ({
          items: [expiredRoleEdge],
        }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: "Members" }));
    expect(
      await screen.findByRole("button", {
        name: "Revoke membership edge for Mira Responder (mira@example.invalid)",
      }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("tab", { name: "Roles" }));
    expect(
      await screen.findByRole("button", {
        name: "Revoke role edge for Incident commander (incident_commander)",
      }),
    ).toBeVisible();
  });

  it("keeps reload focus on a stable heading through loading and error, then restores the active tab on success", async () => {
    const group = groupFixture();
    const current = concurrentGroupFixture(group);
    const failedReload = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    const successfulReload = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockImplementationOnce(async () => failedReload.promise)
      .mockImplementationOnce(async () => successfulReload.promise);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        getTenantSecurityGroup,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        updateTenantSecurityGroup: async () => {
          throw new PhaseTwoApiError("stale metadata", 412);
        },
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    const title = await screen.findByRole("heading", {
      name: "Security group · IR leads",
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
      target: { value: "Preserved operator draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(
      await screen.findByText(/resource changed on the server/i),
    ).toBeVisible();

    const loadCurrent = screen.getByRole("button", {
      name: "Load current version",
    });
    loadCurrent.focus();
    fireEvent.click(loadCurrent);

    expect(
      await screen.findByLabelText("Loading security-group detail"),
    ).toBeVisible();
    expect(title).toHaveFocus();
    expect(title).toHaveAttribute("tabindex", "-1");
    expect(
      screen.getByRole("textbox", { hidden: true, name: "Group name" }),
    ).toHaveValue("Preserved operator draft");

    await act(async () => {
      failedReload.reject(
        new PhaseTwoApiError("Current detail temporarily unavailable.", 503),
      );
      await failedReload.promise.catch(() => undefined);
    });

    expect(
      await screen.findByText("Current detail temporarily unavailable."),
    ).toBeVisible();
    expect(title).toHaveFocus();

    const retry = screen.getByRole("button", { name: "Retry group detail" });
    retry.focus();
    fireEvent.click(retry);
    expect(
      await screen.findByLabelText("Loading security-group detail"),
    ).toBeVisible();
    expect(title).toHaveFocus();

    await act(async () => {
      successfulReload.resolve({ etag: '"v4"', value: current });
      await successfulReload.promise;
    });

    const overviewTab = await screen.findByRole("tab", { name: "Overview" });
    await waitFor(() => expect(overviewTab).toHaveFocus());
    expect(screen.getByRole("textbox", { name: "Group name" })).toHaveValue(
      "Preserved operator draft",
    );

    await waitFor(() =>
      expect(
        screen.queryByText(/resource changed on the server/i),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    const laterMutationError = await screen.findByRole("alert");
    expect(laterMutationError).toHaveFocus();
    expect(laterMutationError).toHaveTextContent(
      /resource changed on the server/i,
    );
  });

  it("does not steal focus when detail becomes ready without an internal reload request", async () => {
    const group = groupFixture();
    const detailRequest = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () => authorityFixture(["group.read"]),
        getTenantSecurityGroup: async () => detailRequest.promise,
        listTenantSecurityGroups: async () => ({ items: [group] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    const dialog = await screen.findByRole("dialog");
    const close = within(dialog).getByRole("button", { name: "Close" });
    close.focus();

    await act(async () => {
      detailRequest.resolve({ etag: '"v3"', value: group });
      await detailRequest.promise;
    });

    await screen.findByRole("tab", { name: "Overview" });
    expect(close).toHaveFocus();
  });

  it("preserves metadata edits through a failed stale refresh and retries with the current ETag", async () => {
    const group = groupFixture();
    const current = {
      ...group,
      description: "Server-side description",
      name: "IR leads on server",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const saved = {
      ...current,
      description: "Operator-owned response team",
      name: "IR leads operator draft",
      updatedAt: "2026-08-23T14:30:00Z",
      version: 5,
    };
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("Current detail temporarily unavailable.", 503),
      )
      .mockResolvedValue({ etag: '"v4"', value: current });
    const updateTenantSecurityGroup = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale metadata", 412))
      .mockResolvedValueOnce({ etag: '"v5"', value: saved });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        getTenantSecurityGroup,
        listTenantSecurityGroups: async () => ({ items: [group] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Group name" }),
      { target: { value: saved.name } },
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Description" }), {
      target: { value: saved.description },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    expect(
      await screen.findByText(/resource changed on the server/i),
    ).toBeVisible();
    expect(updateTenantSecurityGroup).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      group.id,
      '"v3"',
      { description: saved.description, name: saved.name },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Load current version" }),
    );

    expect(
      await screen.findByText("Current detail temporarily unavailable."),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Retry group detail" }));

    expect(
      await screen.findByRole("heading", {
        name: "Security group · IR leads on server",
      }),
    ).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Group name" })).toHaveValue(
      saved.name,
    );
    expect(screen.getByRole("textbox", { name: "Description" })).toHaveValue(
      saved.description,
    );
    expect(screen.getByText('"v4"')).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updateTenantSecurityGroup).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        '"v4"',
        { description: saved.description, name: saved.name },
      ),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · IR leads operator draft",
      }),
    ).toBeVisible();
    expect(getTenantSecurityGroup).toHaveBeenCalledTimes(3);
  });

  it("rebases a rejected metadata patch without overwriting a concurrent untouched field", async () => {
    const group = groupFixture();
    const current = {
      ...group,
      description: "Concurrent server description",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const saved = {
      ...current,
      name: "Operator-owned group name",
      updatedAt: "2026-08-23T14:30:00Z",
      version: 5,
    };
    const getTenantSecurityGroup = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v3"', value: group })
      .mockResolvedValueOnce({ etag: '"v4"', value: current });
    const updateTenantSecurityGroup = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale metadata", 412))
      .mockResolvedValueOnce({ etag: '"v5"', value: saved });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture([
            "group.manage",
            "group.membership.manage",
            "group.read",
            "role.grant",
            "role.read",
            "user.read",
          ]),
        getTenantSecurityGroup,
        listTenantSecurityGroupMemberships: async () => ({ items: [] }),
        listTenantSecurityGroupRoleGrants: async () => ({ items: [] }),
        listTenantSecurityGroups: async () => ({ items: [group] }),
        updateTenantSecurityGroup,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Group name" }),
      { target: { value: saved.name } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(
      await screen.findByText(/resource changed on the server/i),
    ).toBeVisible();
    expect(updateTenantSecurityGroup).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      tenantId,
      group.id,
      '"v3"',
      { name: saved.name },
    );

    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    expect(screen.getByText(/resource changed on the server/i)).toBeVisible();
    const reloadButton = screen.getByRole("button", {
      name: "Load current version",
    });
    reloadButton.focus();
    fireEvent.click(reloadButton);

    expect(await screen.findByText('"v4"')).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Group name" })).toHaveValue(
      saved.name,
    );
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "Description" })).toHaveValue(
        current.description,
      ),
    );
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveFocus();

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updateTenantSecurityGroup).toHaveBeenNthCalledWith(
        2,
        sessionFixture.csrfToken,
        tenantId,
        group.id,
        '"v4"',
        { name: saved.name },
      ),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Operator-owned group name",
      }),
    ).toBeVisible();
  });

  it("keeps a mutation-newer group when delayed pagination returns its stale summary", async () => {
    const group = groupFixture();
    const delayedPage = createDeferred<{
      items: TenantSecurityGroupView[];
    }>();
    const updated = {
      ...group,
      name: "IR leads updated",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 4,
    };
    const listTenantSecurityGroups = vi
      .fn()
      .mockResolvedValueOnce({
        items: [group],
        nextCursor: "delayed-group-page",
      })
      .mockImplementationOnce(async () => delayedPage.promise);
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        getTenantSecurityGroup: async () => ({
          etag: '"v3"',
          value: group,
        }),
        listTenantSecurityGroups,
        updateTenantSecurityGroup: async () => ({
          etag: '"v4"',
          value: updated,
        }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more groups" }),
    );
    await waitFor(() =>
      expect(listTenantSecurityGroups).toHaveBeenCalledTimes(2),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open IR leads (ir_leads)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Group name" }),
      { target: { value: updated.name } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(
      await screen.findByRole("heading", {
        name: "Security group · IR leads updated",
      }),
    ).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [group] });
      await delayedPage.promise;
    });
    expect(
      screen.getByRole("button", {
        hidden: true,
        name: "Open IR leads updated (ir_leads)",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        hidden: true,
        name: "Open IR leads (ir_leads)",
      }),
    ).not.toBeInTheDocument();
  });

  it("merges group inventory monotonically and fails closed on equal-version conflicts", () => {
    const original = groupFixture();
    const newer = {
      ...original,
      name: "Newer group",
      updatedAt: "2026-08-23T14:00:00Z",
      version: 5,
    };
    const stale = {
      ...original,
      name: "Stale group",
      updatedAt: "2026-08-23T13:00:00Z",
      version: 4,
    };

    expect(mergeTenantGroups([original], [newer, stale])).toEqual([newer]);
    expect(mergeTenantGroups([newer], [stale])).toEqual([newer]);
    expect(mergeTenantGroups([newer], [{ ...newer }])).toEqual([newer]);
    expect(() =>
      mergeTenantGroups([newer], [{ ...newer, name: "Conflicting group" }]),
    ).toThrow(/conflicting representations/i);
  });

  it("does not let a delayed update for group A replace group B detail", async () => {
    const update = createDeferred<{
      etag: string;
      value: TenantSecurityGroupView;
    }>();
    const alpha = groupFixture({ name: "Alpha group" });
    const bravo = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000123",
      key: "bravo_group",
      name: "Bravo group",
    });
    renderGroups(
      createPhaseTwoApi({
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        getTenantSecurityGroup: async (_tenantId, requestedGroupId) => ({
          etag: '"v3"',
          value: requestedGroupId === alpha.id ? alpha : bravo,
        }),
        listTenantSecurityGroups: async () => ({ items: [alpha, bravo] }),
        updateTenantSecurityGroup: async () => update.promise,
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha group (ir_leads)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Group name" }),
      {
        target: { value: "Updated Alpha group" },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo group (bravo_group)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Bravo group",
      }),
    ).toBeVisible();

    await act(async () => {
      update.resolve({
        etag: '"v4"',
        value: { ...alpha, name: "Updated Alpha group", version: 4 },
      });
      await Promise.resolve();
    });

    expect(
      screen.getByRole("heading", { name: "Security group · Bravo group" }),
    ).toBeVisible();
  });

  it("does not let a delayed archive for group A close group B detail", async () => {
    const archive = createDeferred<void>();
    const alpha = groupFixture({ name: "Alpha group" });
    const bravo = groupFixture({
      id: "0198c97d-cf4f-7000-8000-000000000123",
      key: "bravo_group",
      name: "Bravo group",
    });
    renderGroups(
      createPhaseTwoApi({
        archiveTenantSecurityGroup: async () => archive.promise,
        getTenantAuthority: async () =>
          authorityFixture(["group.manage", "group.read"]),
        getTenantSecurityGroup: async (_tenantId, requestedGroupId) => ({
          etag: '"v3"',
          value: requestedGroupId === alpha.id ? alpha : bravo,
        }),
        listTenantSecurityGroups: async () => ({ items: [alpha, bravo] }),
      }),
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha group (ir_leads)",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive group" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm archive" }));
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo group (bravo_group)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Security group · Bravo group",
      }),
    ).toBeVisible();

    await act(async () => {
      archive.resolve(undefined);
      await Promise.resolve();
    });

    expect(
      screen.getByRole("heading", { name: "Security group · Bravo group" }),
    ).toBeVisible();
  });
});

function renderGroups(
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
        <TenantGroupsPage />
        {showAuthorityReload ? <GroupAuthorityReloadControl /> : null}
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function GroupAuthorityReloadControl(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button
      data-testid="reload-group-authority"
      type="button"
      onClick={authority.reload}
    >
      Reload group authority
    </button>
  );
}

function fullyPrivilegedGroupAuthority(): TenantAuthorityView {
  return authorityFixture([
    "group.manage",
    "group.membership.manage",
    "group.read",
    "role.grant",
    "role.read",
    "user.read",
  ]);
}

function concurrentGroupFixture(
  group: TenantSecurityGroupView,
): TenantSecurityGroupView {
  return {
    ...group,
    description: "Concurrent server description",
    updatedAt: "2026-08-23T14:00:00Z",
    version: 4,
  };
}

function reloadingGroupDetail(
  group: TenantSecurityGroupView,
  current: TenantSecurityGroupView,
) {
  return vi
    .fn()
    .mockResolvedValueOnce({ etag: '"v3"', value: group })
    .mockResolvedValue({ etag: '"v4"', value: current });
}

async function reloadCurrentGroupAfterMetadataConflict(
  getTenantSecurityGroup: ReturnType<typeof vi.fn>,
): Promise<void> {
  fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Group name" }), {
    target: { value: "Operator draft" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  expect(
    await screen.findByText(/resource changed on the server/i),
  ).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Load current version" }));
  await waitFor(() => expect(getTenantSecurityGroup).toHaveBeenCalledTimes(2));
  await waitFor(() =>
    expect(
      screen.queryByLabelText("Loading security-group detail"),
    ).not.toBeInTheDocument(),
  );
}

function SwitchingGroupsHarness({
  api,
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
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
        <TenantGroupsPage />
        <button type="button" onClick={() => setActiveTenantId(otherTenantId)}>
          Switch group tenant
        </button>
        <button type="button" onClick={() => setActiveTenantId(tenantId)}>
          Switch original group tenant
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
  authorityTenantId = tenantId,
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
    tenantId: authorityTenantId,
    userId: sessionFixture.user.id,
  };
}

function groupFixture(
  overrides: Partial<TenantSecurityGroupView> = {},
): TenantSecurityGroupView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    description: "Incident response coordinators",
    id: groupId,
    key: "ir_leads",
    name: "IR leads",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
    ...overrides,
  };
}

function userFixture(): TenantUserSummaryView {
  return {
    createdAt: "2026-08-20T10:00:00Z",
    etag: '"v1"',
    legacyMembershipRole: "analyst",
    lifecycleRevision: 1,
    membershipId: "0198c97d-cf4f-7000-8000-000000000130",
    membershipStatus: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    user: {
      active: true,
      displayName: "Mira Responder",
      email: "mira@example.invalid",
      id: "0198c97d-cf4f-7000-8000-000000000131",
    },
  };
}

function roleFixture(): TenantRoleSummaryView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    id: "0198c97d-cf4f-7000-8000-000000000140",
    key: "incident_commander",
    name: "Incident commander",
    principalKind: "human",
    system: false,
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 2,
  };
}

function membershipFixture(
  group: TenantSecurityGroupView,
  overrides: Partial<TenantSecurityGroupMembershipView> = {},
): TenantSecurityGroupMembershipView {
  return {
    etag: membershipEdgeEtag,
    group,
    id: "0198c97d-cf4f-7000-8000-000000000160",
    managedByAuthorizationApi: true,
    member: userFixture(),
    provenance: {
      authoritative: false,
      grantedAt: "2026-08-21T10:00:00Z",
      grantedByUserId: sessionFixture.user.id,
      reason: "Manual roster decision",
      sourceId: "0198c97d-cf4f-7000-8000-000000000151",
      sourceKind: "manual",
    },
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 7,
    ...overrides,
  };
}

function roleEdgeFixture(
  group: TenantSecurityGroupView,
  overrides: Partial<TenantSecurityGroupRoleGrantView> = {},
): TenantSecurityGroupRoleGrantView {
  return {
    etag: roleEdgeEtag,
    group,
    id: "0198c97d-cf4f-7000-8000-000000000161",
    managedByAuthorizationApi: false,
    provenance: {
      authoritative: true,
      grantedAt: "2026-08-21T10:00:00Z",
      reason: "Directory role mapping",
      sourceId: "0198c97d-cf4f-7000-8000-000000000152",
      sourceKind: "identity_mapping",
    },
    role: roleFixture(),
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 4,
    ...overrides,
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
}

function createDeferred<T>(): Deferred<T> {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    reject = promiseReject;
    resolve = promiseResolve;
  });
  return { promise, reject, resolve };
}

async function submitMembershipAdd(reason: string): Promise<void> {
  fireEvent.click(
    await screen.findByRole("button", { name: "Add member edge" }),
  );
  fireEvent.click(await screen.findByRole("combobox", { name: "Tenant user" }));
  fireEvent.click(
    await screen.findByRole("option", {
      name: "Mira Responder · mira@example.invalid",
    }),
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Reason" }), {
    target: { value: reason },
  });
  const submit = screen.getAllByRole("button", {
    name: "Add member edge",
  })[1];
  if (!submit) {
    throw new Error("The membership submit button was not rendered.");
  }
  fireEvent.click(submit);
}

async function submitRoleAdd(reason: string): Promise<void> {
  fireEvent.click(await screen.findByRole("button", { name: "Add role edge" }));
  fireEvent.click(await screen.findByRole("combobox", { name: "Tenant role" }));
  fireEvent.click(
    await screen.findByRole("option", {
      name: "Incident commander · incident_commander",
    }),
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Reason" }), {
    target: { value: reason },
  });
  const submit = screen.getAllByRole("button", { name: "Add role edge" })[1];
  if (!submit) {
    throw new Error("The role submit button was not rendered.");
  }
  fireEvent.click(submit);
}

async function loadTwentyMorePages(
  label: string,
  load: ReturnType<typeof vi.fn>,
): Promise<void> {
  for (let page = 1; page <= 20; page += 1) {
    // oxlint-disable-next-line no-await-in-loop -- Each explicit page needs the cursor returned by the preceding click.
    const button = await screen.findByRole("button", {
      name: `Load more ${label}`,
    });
    // oxlint-disable-next-line no-await-in-loop -- The next cursor must not be requested while this page is loading.
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    // oxlint-disable-next-line no-await-in-loop -- The assertion advances in lockstep with sequential cursor requests.
    await waitFor(() => expect(load).toHaveBeenCalledTimes(page + 1));
  }
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: `Load more ${label}` }),
    ).not.toBeInTheDocument(),
  );
}
