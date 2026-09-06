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
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type TenantAuthorityView,
  type TenantLdapAuthProviderDiagnosticView,
  type TenantLdapAuthProviderView,
  type TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  createLdapProviderDraft,
  toLdapProviderUpdateInput,
} from "./ldap-provider-model";
import {
  LdapProviderEditor,
  TenantLdapProvidersPage,
} from "./tenant-ldap-providers";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const allPermissions: readonly TenantPermissionKeyView[] = [
  "identity_provider.read",
  "identity_provider.manage",
  "identity_provider.test",
];

afterEach(cleanup);

describe("TenantLdapProvidersPage", () => {
  it("renders list and redacted detail while gating actions by live authority", async () => {
    renderPage({}, ["identity_provider.read"]);

    expect(await screen.findByText("Primary directory")).toBeVisible();
    expect(screen.getByText("Not set")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create provider" }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
    expect(await screen.findByText("Endpoint order")).toBeVisible();
    expect(screen.getByText("ldap.example.org:636")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Edit configuration" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Test connection" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/secret-value/i)).not.toBeInTheDocument();
  });

  it("creates a disabled editable template using Location-only success", async () => {
    const createTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["createTenantLdapAuthProvider"]
    >(async () => ({
      location: `/api/v1/tenants/${tenantId}/auth-providers/${providerId}`,
    }));
    renderPage({ createTenantLdapAuthProvider });

    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /OpenLDAP.*entryUUID/i }),
    );
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Corporate OpenLDAP" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );

    await waitFor(() =>
      expect(createTenantLdapAuthProvider).toHaveBeenCalled(),
    );
    const call = createTenantLdapAuthProvider.mock.calls[0]!;
    expect(call[1]).toBe(tenantId);
    expect(call[2]).toMatch(/^[0-9a-f-]{36}$/);
    expect(call[3]).toMatchObject({
      displayName: "Corporate OpenLDAP",
      kind: "ldap",
      configuration: {
        template: "openldap",
        verifyCertificate: true,
        jitMode: "disabled",
      },
    });
    expect(call[3]).not.toHaveProperty("enabled");
    expect(Object.keys(call[3].configuration)).toHaveLength(39);
    expect(await screen.findByText(/created disabled/i)).toBeVisible();
  });

  it("replaces the complete mutable document with the current ETag", async () => {
    const updateTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["updateTenantLdapAuthProvider"]
    >(async () => '"v8"');
    renderPage({ updateTenantLdapAuthProvider });
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Edit configuration" }));
    fireEvent.change(await screen.findByLabelText("Display name"), {
      target: { value: "Primary directory updated" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace provider" }));

    await waitFor(() =>
      expect(updateTenantLdapAuthProvider).toHaveBeenCalled(),
    );
    expect(updateTenantLdapAuthProvider).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v7"',
      expect.objectContaining({
        displayName: "Primary directory updated",
        enabled: false,
      }),
    );
    const input = updateTenantLdapAuthProvider.mock.calls[0]![4];
    expect(Object.keys(input).toSorted()).toEqual(
      [
        "configuration",
        "description",
        "displayName",
        "enabled",
        "endpoints",
        "key",
      ].toSorted(),
    );
    expect(
      await screen.findByText(/full LDAP provider document was replaced/i),
    ).toBeVisible();
  });

  it("preserves an edit draft after a 412 and never auto-retries", async () => {
    const updateTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["updateTenantLdapAuthProvider"]
    >(async () => {
      throw new PhaseTwoApiError("The provider changed.", 412);
    });
    renderPage({ updateTenantLdapAuthProvider });
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Edit configuration" }));
    const nameInput = await screen.findByLabelText("Display name");
    fireEvent.change(nameInput, { target: { value: "Preserved draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace provider" }));

    expect(
      await screen.findByText("Provider changed on the server"),
    ).toBeVisible();
    expect(screen.getByDisplayValue("Preserved draft")).toBeVisible();
    expect(updateTenantLdapAuthProvider).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Replace provider" }),
    ).toBeDisabled();
  });

  it("keeps the old body/ETag display-only and locks every action until refresh succeeds", async () => {
    const provider = providerFixture({
      bindSecretConfigured: true,
      bindSecretRotatedAt: "2026-08-25T09:10:00Z",
    });
    const refresh = createDeferred<{
      etag: string;
      value: TenantLdapAuthProviderView;
    }>();
    const getTenantLdapAuthProvider = vi
      .fn<PhaseTwoApi["getTenantLdapAuthProvider"]>()
      .mockResolvedValueOnce({ etag: '"v7"', value: provider })
      .mockImplementation(async () => refresh.promise);
    const updateTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["updateTenantLdapAuthProvider"]
    >(async () => '"v8"');
    const testTenantLdapAuthProviderConnection = vi.fn<
      PhaseTwoApi["testTenantLdapAuthProviderConnection"]
    >(async () => successDiagnosticFixture());
    const setTenantLdapAuthProviderBindSecret = vi.fn<
      PhaseTwoApi["setTenantLdapAuthProviderBindSecret"]
    >(async () => '"v9"');
    renderPage(
      {
        getTenantLdapAuthProvider,
        setTenantLdapAuthProviderBindSecret,
        testTenantLdapAuthProviderConnection,
        updateTenantLdapAuthProvider,
      },
      allPermissions,
      provider,
    );
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Edit configuration" }));
    fireEvent.change(await screen.findByLabelText("Display name"), {
      target: { value: "Committed replacement" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace provider" }));

    expect(
      await screen.findByText("Showing the last confirmed projection"),
    ).toBeVisible();
    await waitFor(() =>
      expect(getTenantLdapAuthProvider.mock.calls.length).toBeGreaterThan(1),
    );
    expect(
      screen.queryByRole("button", { name: "Edit configuration" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Replace bind secret" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Clear bind secret" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Archive provider" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Test connection" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Test bind" }),
    ).not.toBeInTheDocument();

    refresh.reject(new PhaseTwoApiError("Refresh failed safely.", 503));
    expect(await screen.findByText("Refresh failed safely.")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Edit configuration" }),
    ).not.toBeInTheDocument();
    expect(updateTenantLdapAuthProvider).toHaveBeenCalledTimes(1);
    expect(setTenantLdapAuthProviderBindSecret).not.toHaveBeenCalled();
    expect(testTenantLdapAuthProviderConnection).not.toHaveBeenCalled();
  });

  it("writes a bind secret once, clears the input, and never renders it after success", async () => {
    const setTenantLdapAuthProviderBindSecret = vi.fn<
      PhaseTwoApi["setTenantLdapAuthProviderBindSecret"]
    >(async () => '"v8"');
    renderPage({ setTenantLdapAuthProviderBindSecret });
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Set bind secret" }));
    const secret = "browser-only-bind-secret";
    fireEvent.change(await screen.findByLabelText("Bind secret"), {
      target: { value: secret },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Store write-only secret" }),
    );

    await waitFor(() =>
      expect(setTenantLdapAuthProviderBindSecret).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        tenantId,
        providerId,
        '"v7"',
        { secret },
      ),
    );
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secret);
    expect(
      await screen.findByText(/no longer available to the browser/i),
    ).toBeVisible();
  });

  it("clears a configured secret only through the reason-bearing disabled action", async () => {
    const clearTenantLdapAuthProviderBindSecret = vi.fn<
      PhaseTwoApi["clearTenantLdapAuthProviderBindSecret"]
    >(async () => '"v8"');
    renderPage(
      { clearTenantLdapAuthProviderBindSecret },
      allPermissions,
      providerFixture({
        bindSecretConfigured: true,
        bindSecretRotatedAt: "2026-08-25T09:10:00Z",
      }),
    );
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Clear bind secret" }));
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "Credential is no longer required" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Clear secret" }));

    await waitFor(() =>
      expect(clearTenantLdapAuthProviderBindSecret).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        tenantId,
        providerId,
        '"v7"',
        { reason: "Credential is no longer required" },
      ),
    );
  });

  it("archives with an audit reason and closes the detail", async () => {
    const archiveTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["archiveTenantLdapAuthProvider"]
    >(async () => '"v8"');
    renderPage({ archiveTenantLdapAuthProvider });
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Archive provider" }));
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "Directory retired" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Archive permanently" }),
    );

    await waitFor(() =>
      expect(archiveTenantLdapAuthProvider).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        tenantId,
        providerId,
        '"v7"',
        { reason: "Directory retired" },
      ),
    );
    expect(await screen.findByText(/archived and disabled/i)).toBeVisible();
  });

  it("runs distinct connection and bind tests and renders sanitized categories only", async () => {
    const testTenantLdapAuthProviderConnection = vi.fn<
      PhaseTwoApi["testTenantLdapAuthProviderConnection"]
    >(async () => successDiagnosticFixture());
    const testTenantLdapAuthProviderBind = vi.fn<
      PhaseTwoApi["testTenantLdapAuthProviderBind"]
    >(async () => bindRejectedDiagnosticFixture());
    renderPage(
      {
        testTenantLdapAuthProviderBind,
        testTenantLdapAuthProviderConnection,
      },
      allPermissions,
      providerFixture({
        bindSecretConfigured: true,
        bindSecretRotatedAt: "2026-08-25T09:10:00Z",
      }),
    );
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("Succeeded")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Test bind" }));
    expect(await screen.findByText("Bind rejected")).toBeVisible();
    expect(testTenantLdapAuthProviderConnection).toHaveBeenCalledTimes(1);
    expect(testTenantLdapAuthProviderBind).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain("invalidCredentials");
  });

  it("preserves endpoint input identity while editing priority and removing another endpoint", () => {
    const onChange = vi.fn();
    function EditorHarness(): React.JSX.Element {
      const [draft, setDraft] = useState(() => {
        const initial = createLdapProviderDraft("openldap");
        return {
          ...initial,
          endpoints: [
            initial.endpoints[0]!,
            {
              ...initial.endpoints[0]!,
              host: "secondary.example.org",
              priority: 2,
            },
          ],
        };
      });
      return (
        <LdapProviderEditor
          mode="create"
          draft={draft}
          onChange={(next) => {
            onChange(next);
            setDraft(next);
          }}
        />
      );
    }
    render(<EditorHarness />);
    const hosts = screen.getAllByLabelText<HTMLInputElement>("Host");
    const secondaryHost = hosts[1]!;
    const secondaryRow = secondaryHost.closest<HTMLElement>(
      ".ldap-endpoint-editor",
    )!;
    const priority = within(secondaryRow).getByLabelText("Priority");
    priority.focus();
    fireEvent.change(priority, { target: { value: "3" } });
    expect(priority).toHaveFocus();
    expect(screen.getAllByLabelText("Host")[1]).toBe(secondaryHost);
    fireEvent.click(
      screen.getAllByRole("button", { name: "Remove endpoint" })[0]!,
    );
    expect(screen.getByLabelText("Host")).toBe(secondaryHost);
    expect(secondaryHost).toHaveValue("secondary.example.org");
    expect(screen.getByLabelText("Priority")).toHaveValue(3);
    const latest = onChange.mock.lastCall![0];
    expect(latest.endpoints).toHaveLength(1);
    expect(latest.endpoints[0]).not.toHaveProperty("key");
  });

  it("ignores an expired-session response from a create dialog after its scope unmounts", async () => {
    let rejectRequest!: (error: unknown) => void;
    const pending = new Promise<{ location: string }>((_, reject) => {
      rejectRequest = reject;
    });
    const createTenantLdapAuthProvider = vi.fn<
      PhaseTwoApi["createTenantLdapAuthProvider"]
    >(() => pending);
    const view = renderPage({ createTenantLdapAuthProvider });
    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );
    await waitFor(() =>
      expect(createTenantLdapAuthProvider).toHaveBeenCalledTimes(1),
    );
    view.unmount();
    await act(async () => {
      rejectRequest(new PhaseTwoApiError("The old session expired.", 401));
      await pending.catch(() => undefined);
    });
    expect(view.clearSession).not.toHaveBeenCalled();
  });

  it("shows bounded list failures without exposing management actions", async () => {
    renderPage({
      listTenantLdapAuthProviders: async () => {
        throw new PhaseTwoApiError("Safe inventory failure.", 503);
      },
    });

    expect(await screen.findByText("Safe inventory failure.")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Inspect" }),
    ).not.toBeInTheDocument();
  });
});

async function openDetail(): Promise<void> {
  fireEvent.click(await screen.findByRole("button", { name: "Inspect" }));
  await screen.findByText("Endpoint order");
}

function renderPage(
  overrides: Partial<PhaseTwoApi> = {},
  permissions: readonly TenantPermissionKeyView[] = allPermissions,
  provider = providerFixture(),
) {
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(permissions),
    getTenantLdapAuthProvider: async () => ({
      etag: `"v${provider.version}"`,
      value: provider,
    }),
    listTenantLdapAuthProviders: async () => ({
      items: [summaryFromProvider(provider)],
    }),
    ...overrides,
  });
  const session = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    activeTenantId: tenantId,
    idleExpiresAt: "2099-08-23T12:00:00Z",
  };
  const clearSession = vi.fn();
  const view = render(
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
        <TenantLdapProvidersPage />
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
  return { ...view, clearSession };
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
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
    tenantId,
    userId: sessionFixture.user.id,
  };
}

function providerFixture(
  overrides: Partial<TenantLdapAuthProviderView> = {},
): TenantLdapAuthProviderView {
  const draft = createLdapProviderDraft("openldap");
  const update = toLdapProviderUpdateInput(draft);
  return {
    ...update,
    archiveReason: null,
    archivedAt: null,
    bindSecretConfigured: false,
    bindSecretRotatedAt: null,
    createdAt: "2026-08-25T09:00:00Z",
    description: "Primary workforce directory",
    displayName: "Primary directory",
    enabledEndpointCount: 1,
    id: providerId,
    kind: "ldap",
    template: update.configuration.template,
    tenantId,
    updatedAt: "2026-08-25T09:15:00Z",
    version: 7,
    ...overrides,
  };
}

function summaryFromProvider(provider: TenantLdapAuthProviderView) {
  return {
    archivedAt: provider.archivedAt,
    bindSecretConfigured: provider.bindSecretConfigured,
    createdAt: provider.createdAt,
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    enabledEndpointCount: provider.enabledEndpointCount,
    id: provider.id,
    key: provider.key,
    kind: provider.kind,
    template: provider.template,
    tenantId: provider.tenantId,
    updatedAt: provider.updatedAt,
    version: provider.version,
  };
}

function successDiagnosticFixture(): TenantLdapAuthProviderDiagnosticView {
  return {
    category: "success",
    completedAt: "2026-08-25T09:30:00Z",
    durationMs: 42,
    endpointPriority: 1,
    outcome: "success",
    stale: false,
    testRunId: "0198c97d-cf4f-7000-8000-000000000099",
  };
}

function bindRejectedDiagnosticFixture(): TenantLdapAuthProviderDiagnosticView {
  return {
    category: "bind_rejected",
    completedAt: "2026-08-25T09:30:00Z",
    durationMs: 42,
    endpointPriority: 1,
    outcome: "failure",
    stale: false,
    testRunId: "0198c97d-cf4f-7000-8000-000000000099",
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  reject: (reason: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    reject = promiseReject;
    resolve = promiseResolve;
  });
  return { promise, reject, resolve };
}
