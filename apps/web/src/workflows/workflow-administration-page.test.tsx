import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  SessionView,
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TenantWorkflowAdministrationPage } from "./workflow-administration-page";
import { workflowAdministrationRoutes } from "./workflow-administration-page-routes";
import type { WorkflowAdministrationApi } from "./workflow-api";
import {
  createWorkflowApiMock,
  workflowTenantId,
} from "./workflow-test-fixtures";

afterEach(cleanup);

describe("workflow administration route boundary", () => {
  it("mounts the canonical tenant child path", () => {
    expect(workflowAdministrationRoutes.map((route) => route.path)).toEqual([
      "tenant/workflows",
    ]);
  });

  it("keeps a deep link closed until live workflow.read authority is ready", async () => {
    const authority = createDeferred<TenantAuthorityView>();
    const list = vi.fn<WorkflowAdministrationApi["list"]>(async () => ({
      items: [],
    }));
    renderPage(createWorkflowApiMock({ list }), () => authority.promise);

    expect(
      await screen.findByRole("heading", {
        name: "Checking workflow authority…",
      }),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();

    await act(async () => {
      authority.resolve(authorityFixture(["workflow.read"]));
      await authority.promise;
    });
    expect(
      await screen.findByText("No workflow lineages are visible."),
    ).toBeVisible();
    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "alert", tenantId: workflowTenantId }),
    );
    expect(
      screen.queryByRole("button", { name: "New lineage" }),
    ).not.toBeInTheDocument();
  });

  it("does not treat Session.permissions as tenant workflow authority", async () => {
    const list = vi.fn<WorkflowAdministrationApi["list"]>();
    renderPage(
      createWorkflowApiMock({ list }),
      async () => authorityFixture([]),
      ["workflow.read", "workflow.manage"],
    );

    expect(
      await screen.findByText("Workflow authority required"),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
  });

  it("does not infer read access from workflow.manage", async () => {
    const list = vi.fn<WorkflowAdministrationApi["list"]>();
    renderPage(createWorkflowApiMock({ list }), async () =>
      authorityFixture(["workflow.manage"]),
    );

    expect(
      await screen.findByText("Workflow authority required"),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
  });
});

function renderPage(
  workflowApi: WorkflowAdministrationApi,
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
          activeTenantId: workflowTenantId,
          permissions,
        }),
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantWorkflowAdministrationPage api={workflowApi} />
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-26T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "01991c20-7d5f-7000-8000-000000000270",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissionKeys.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: workflowTenantId,
    userId: sessionFixture.user.id,
  };
}

function futureSession(session: SessionView): SessionView {
  return {
    ...session,
    absoluteExpiresAt: "2099-08-26T12:00:00Z",
    idleExpiresAt: "2099-08-26T11:00:00Z",
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
