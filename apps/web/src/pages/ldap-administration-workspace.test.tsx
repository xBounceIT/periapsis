import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type TenantLdapAuthProviderBindingView,
  type TenantLdapMappingDryRunResultView,
  type TenantLdapSyncRunView,
  type TenantLdapSyncStatusView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { LdapAdministrationWorkspace } from "./ldap-administration-workspace";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const secondTenantId = "0198c97d-cf4f-7000-8000-000000000011";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";

afterEach(cleanup);

describe("LdapAdministrationWorkspace", () => {
  it("keeps permission visibility advisory and hides unauthorized controls", async () => {
    renderWorkspace(
      createPhaseTwoApi({
        listTenantLdapAuthProviderBindings: async () => ({ items: [] }),
      }),
      {
        canMappingRead: false,
        canProviderManage: false,
      },
    );

    expect(await screen.findByText("No tenant login binding")).toBeVisible();
    expect(
      screen.getByText(/identity_provider\.manage.*required/i),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create binding" }),
    ).not.toBeInTheDocument();
  });

  it("creates a binding with one payload-bound idempotency key", async () => {
    const createTenantLdapAuthProviderBinding = vi.fn<
      PhaseTwoApi["createTenantLdapAuthProviderBinding"]
    >(async (_csrfToken, _tenantId, _key, input) => ({
      etag: '"v1"',
      location: `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}`,
      value: bindingFixture({
        currentAccessEpochId: input.enabled
          ? "0198c97d-cf4f-7000-8000-000000000098"
          : null,
        enabled: input.enabled,
        loginKey: input.loginKey,
        profilePriority: input.profilePriority,
      }),
    }));
    renderWorkspace(
      createPhaseTwoApi({
        createTenantLdapAuthProviderBinding,
        listTenantLdapAuthProviderBindings: async () => ({ items: [] }),
      }),
      { canMappingRead: false },
    );

    await screen.findByText("No tenant login binding");
    fireEvent.change(screen.getByLabelText("Login key"), {
      target: { value: "employees_eu" },
    });
    fireEvent.change(screen.getByLabelText("Profile priority"), {
      target: { value: "25" },
    });
    fireEvent.click(screen.getByLabelText(/Enable tenant login authority/i));
    fireEvent.click(screen.getByRole("button", { name: "Create binding" }));

    await waitFor(() =>
      expect(createTenantLdapAuthProviderBinding).toHaveBeenCalledTimes(1),
    );
    expect(createTenantLdapAuthProviderBinding).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      expect.stringMatching(/^[0-9a-f-]{36}$/),
      {
        enabled: true,
        loginKey: "employees_eu",
        profilePriority: 25,
        providerId,
      },
    );
  });

  it("uses the strong binding ETag and preserves a draft after 412", async () => {
    const binding = bindingFixture();
    const updateTenantLdapAuthProviderBinding = vi.fn<
      PhaseTwoApi["updateTenantLdapAuthProviderBinding"]
    >(async () => {
      throw new PhaseTwoApiError("Binding changed.", 412);
    });
    renderWorkspace(
      createPhaseTwoApi({
        getTenantLdapAuthProviderBinding: async () => ({
          etag: '"v3"',
          value: binding,
        }),
        listTenantLdapAuthProviderBindings: async () => ({
          items: [binding],
        }),
        updateTenantLdapAuthProviderBinding,
      }),
      { canMappingRead: false },
    );

    expect(await screen.findByText("Tenant login binding")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Edit binding" }));
    fireEvent.change(screen.getByLabelText("Login key"), {
      target: { value: "responders_eu" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save binding" }));

    expect(await screen.findByText(/projection is stale/i)).toBeVisible();
    expect(screen.getByDisplayValue("responders_eu")).toBeVisible();
    expect(updateTenantLdapAuthProviderBinding).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      bindingId,
      '"v3"',
      expect.objectContaining({ loginKey: "responders_eu" }),
    );
    expect(updateTenantLdapAuthProviderBinding).toHaveBeenCalledTimes(1);
  });

  it("renders only redacted dry-run output and flags incomplete sync", async () => {
    const binding = bindingFixture();
    const dryRunTenantLdapMappings = vi.fn<
      PhaseTwoApi["dryRunTenantLdapMappings"]
    >(async () => dryRunFixture());
    renderWorkspace(
      createPhaseTwoApi({
        dryRunTenantLdapMappings,
        getTenantLdapAuthProviderBinding: async () => ({
          etag: '"v3"',
          value: binding,
        }),
        getTenantLdapSyncStatus: async () => ({
          etag: '"v4"',
          value: syncStatusFixture(),
        }),
        listTenantLdapAuthProviderBindings: async () => ({
          items: [binding],
        }),
        listTenantLdapMappings: async () => ({ items: [] }),
        listTenantLdapSyncRuns: async () => ({
          items: [incompleteSyncRunFixture()],
        }),
      }),
      { canMappingRead: true, canSync: false },
    );

    expect(await screen.findByText("Redacted mapping dry-run")).toBeVisible();
    const username = "raw-directory-candidate";
    fireEvent.change(screen.getByLabelText("Candidate username"), {
      target: { value: username },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run redacted dry-run" }),
    );

    expect(await screen.findByText("Access plan denied")).toBeVisible();
    expect(
      screen.getByText("Incomplete — absence revokes suppressed"),
    ).toBeVisible();
    expect(screen.getByText("incomplete")).toBeVisible();
    expect(screen.getByText("Suppressed")).toBeVisible();
    expect(document.body.textContent).not.toContain(username);
    expect(document.body.textContent).not.toContain("CN=Secret");
  });

  it("drops a late binding response after the tenant projection changes", async () => {
    const firstPage = createDeferred<{
      items: TenantLdapAuthProviderBindingView[];
    }>();
    const listTenantLdapAuthProviderBindings = vi.fn<
      PhaseTwoApi["listTenantLdapAuthProviderBindings"]
    >((requestedTenantId) =>
      requestedTenantId === tenantId
        ? firstPage.promise
        : Promise.resolve({ items: [] }),
    );
    const api = createPhaseTwoApi({ listTenantLdapAuthProviderBindings });
    const view = renderWorkspace(api, { canMappingRead: false });

    view.rerender(
      <LdapAdministrationWorkspace
        {...workspaceProps(api, {
          canMappingRead: false,
          pairKey: `session:${secondTenantId}`,
          tenantId: secondTenantId,
        })}
      />,
    );
    expect(await screen.findByText("No tenant login binding")).toBeVisible();

    firstPage.resolve({ items: [bindingFixture()] });
    await Promise.resolve();
    expect(screen.queryByText("employees_eu")).not.toBeInTheDocument();
    expect(
      listTenantLdapAuthProviderBindings.mock.calls.some(
        ([requestedTenantId]) => requestedTenantId === secondTenantId,
      ),
    ).toBe(true);
  });
});

function renderWorkspace(
  api: PhaseTwoApi,
  overrides: Partial<
    React.ComponentProps<typeof LdapAdministrationWorkspace>
  > = {},
) {
  return render(
    <LdapAdministrationWorkspace {...workspaceProps(api, overrides)} />,
  );
}

function workspaceProps(
  api: PhaseTwoApi,
  overrides: Partial<
    React.ComponentProps<typeof LdapAdministrationWorkspace>
  > = {},
): React.ComponentProps<typeof LdapAdministrationWorkspace> {
  return {
    api,
    canMappingManage: true,
    canMappingRead: true,
    canProviderManage: true,
    canProviderTest: false,
    canSync: true,
    csrfToken: sessionFixture.csrfToken,
    onPermissionError: vi.fn(),
    onUnauthenticated: vi.fn(),
    pairKey: `session:${tenantId}`,
    providerId,
    tenantId,
    ...overrides,
  };
}

function bindingFixture(
  overrides: Partial<TenantLdapAuthProviderBindingView> = {},
): TenantLdapAuthProviderBindingView {
  return {
    archivedAt: null,
    authRevision: 3,
    createdAt: "2026-08-25T09:00:00Z",
    currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000098",
    enabled: true,
    id: bindingId,
    loginKey: "employees_eu",
    profilePriority: 100,
    providerId,
    tenantId,
    updatedAt: "2026-08-25T09:15:00Z",
    version: 3,
    ...overrides,
  };
}

function syncStatusFixture(): TenantLdapSyncStatusView {
  return {
    activeRunId: null,
    bindingId,
    lastCompletedAt: "2026-08-25T09:15:00Z",
    lastRunId: "0198c97d-cf4f-7000-8000-000000000099",
    lastRunState: "failed",
    nextScheduledAt: null,
    scheduleState: "backoff",
    syncIntervalSeconds: null,
    updatedAt: "2026-08-25T09:15:00Z",
    version: 4,
  };
}

function incompleteSyncRunFixture(): TenantLdapSyncRunView {
  return {
    bindingId,
    completedAt: "2026-08-25T09:15:00Z",
    counters: {
      failed: 1,
      groupEdgesAdded: 0,
      groupEdgesRefreshed: 0,
      groupEdgesRevoked: 0,
      identitiesCreated: 0,
      identitiesLinked: 0,
      observed: 14,
      providerAccessAdded: 0,
      providerAccessSuspended: 0,
      roleEdgesAdded: 0,
      roleEdgesRefreshed: 0,
      roleEdgesRevoked: 0,
      rosterEdgesAdded: 0,
      rosterEdgesRefreshed: 0,
      rosterEdgesRevoked: 0,
      staged: 0,
    },
    createdAt: "2026-08-25T09:10:00Z",
    enumeration: {
      absenceBasedRevocationAllowed: false,
      complete: false,
      cursorState: "discarded",
      entryCount: 14,
      errorCategory: "worker_interrupted",
      pageCount: 2,
      responseBytes: 1024,
      state: "incomplete",
      truncated: false,
    },
    id: "0198c97d-cf4f-7000-8000-000000000099",
    manualReason: "Review the interrupted tenant observation.",
    providerId,
    runErrorCategory: "incomplete_enumeration",
    snapshot: snapshotFixture(),
    startedAt: "2026-08-25T09:11:00Z",
    state: "failed",
    tenantId,
    trigger: "manual",
    updatedAt: "2026-08-25T09:15:00Z",
    version: 2,
  };
}

function dryRunFixture(): TenantLdapMappingDryRunResultView {
  return {
    decision: "deny",
    denialReasons: ["incomplete_observation"],
    dryRunId: "0198c97d-cf4f-7000-8000-000000000100",
    generatedAt: "2026-08-25T09:20:00Z",
    identityDisposition: "unresolved",
    matchedMappingIds: [],
    observationComplete: false,
    outcome: "inconclusive",
    plan: {
      groupActions: [],
      operatorTeamActions: [],
      profileAction: "none",
      providerAccessAction: "none",
      roleActions: [],
    },
    snapshot: snapshotFixture(),
  };
}

function snapshotFixture() {
  return {
    accessEpochId: "0198c97d-cf4f-7000-8000-000000000098",
    bindingId,
    bindingVersion: 3,
    configurationRevision: 4,
    mappingRevisions: [],
    providerId,
    providerVersion: 7,
  };
}

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
