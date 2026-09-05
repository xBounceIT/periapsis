import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  SessionView,
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  TenantCustomFieldAdministrationPage,
  customFieldAdministrationRoutes,
} from "./custom-field-administration-page";
import type { CustomFieldAdministrationApi } from "./custom-field-api";
import type { CustomFieldDefinitionView } from "./model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";

afterEach(cleanup);

describe("tenant custom-field administration", () => {
  it("mounts the canonical tenant route", () => {
    expect(customFieldAdministrationRoutes.map((route) => route.path)).toEqual([
      "tenant/custom-fields",
    ]);
  });

  it("does not derive read authority from session claims", async () => {
    const list = vi.fn<CustomFieldAdministrationApi["list"]>();
    renderPage(apiMock({ list }), [], ["custom_field.read"]);

    expect(
      await screen.findByRole("heading", {
        name: "Custom fields are unavailable.",
      }),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
  });

  it("renders a read-only canonical catalog from live tenant authority", async () => {
    const list = vi.fn<CustomFieldAdministrationApi["list"]>(async () => ({
      items: [definitionFixture()],
    }));
    renderPage(apiMock({ list }), ["custom_field.read"]);

    expect(
      await screen.findByRole("heading", { name: "Incident owner" }),
    ).toBeVisible();
    expect(screen.getByText("Read only")).toBeVisible();
    expect(screen.getByRole("group", { name: "Object type" })).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Alert schema" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.queryByRole("button", { name: /New alert field/u }),
    ).not.toBeInTheDocument();
    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({
        includeArchived: true,
        objectType: "alert",
        tenantId,
      }),
    );
  });

  it("creates a definition only from live manage authority", async () => {
    const create = vi.fn<CustomFieldAdministrationApi["create"]>(
      async (input) => ({
        etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"',
        value: {
          ...definitionFixture(),
          id: input.definitionId,
          key: input.definition.key,
          label: input.definition.label,
        },
      }),
    );
    renderPage(apiMock({ create }), [
      "custom_field.read",
      "custom_field.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "New alert field" }),
    );
    fireEvent.change(screen.getByLabelText("Key"), {
      target: { value: "triage_code" },
    });
    fireEvent.change(screen.getByLabelText("Label"), {
      target: { value: "Triage code" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create field" }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        definition: expect.objectContaining({
          key: "triage_code",
          label: "Triage code",
          objectType: "alert",
        }),
        tenantId,
      }),
    );
  });

  it("aborts and ignores a superseded definition load", async () => {
    const first = definitionFixture({ label: "First field" });
    const second = definitionFixture({
      id: "0198c97d-cf4f-7000-8000-000000000003",
      key: "second_field",
      label: "Second field",
    });
    let resolveFirst:
      | ((
          value: Awaited<ReturnType<CustomFieldAdministrationApi["get"]>>,
        ) => void)
      | undefined;
    let resolveSecond:
      | ((
          value: Awaited<ReturnType<CustomFieldAdministrationApi["get"]>>,
        ) => void)
      | undefined;
    const get = vi.fn<CustomFieldAdministrationApi["get"]>(
      (input) =>
        new Promise((resolve) => {
          if (input.definitionId === first.id) resolveFirst = resolve;
          else resolveSecond = resolve;
        }),
    );
    renderPage(
      apiMock({
        get,
        list: async () => ({ items: [first, second] }),
      }),
      ["custom_field.read", "custom_field.manage"],
    );

    const editButtons = await screen.findAllByRole("button", { name: "Edit" });
    fireEvent.click(editButtons[0]!);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const firstSignal = get.mock.calls[0]![0].signal;
    fireEvent.click(editButtons[1]!);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    expect(firstSignal?.aborted).toBe(true);

    resolveSecond?.({ etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"', value: second });
    expect(
      await screen.findByRole("heading", { name: "Edit Second field" }),
    ).toBeVisible();
    resolveFirst?.({ etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"', value: first });
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Edit Second field" }),
      ).toBeVisible(),
    );
    expect(
      screen.queryByRole("heading", { name: "Edit First field" }),
    ).not.toBeInTheDocument();
  });
});

function renderPage(
  customFieldApi: CustomFieldAdministrationApi,
  permissionKeys: readonly TenantPermissionKeyView[],
  sessionPermissions: readonly string[] = [],
): void {
  const authority = authorityFixture(permissionKeys);
  const phaseTwoApi = createPhaseTwoApi({
    getTenantAuthority: async () => authority,
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseTwoApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: futureSession({
            ...sessionFixture,
            activeTenantId: tenantId,
            permissions: sessionPermissions,
          }),
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <TenantCustomFieldAdministrationPage api={customFieldApi} />
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function apiMock(
  overrides: Partial<CustomFieldAdministrationApi> = {},
): CustomFieldAdministrationApi {
  return {
    list: async () => ({ items: [] }),
    get: async () => ({
      etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"',
      value: definitionFixture(),
    }),
    create: async () => ({
      etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"',
      value: definitionFixture(),
    }),
    replace: async () => ({
      etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"',
      value: definitionFixture(),
    }),
    archive: async () => ({ etag: '"cf-AAAAAAAAAAAAAAAAAAAAAA"' }),
    ...overrides,
  };
}

function definitionFixture(
  overrides: Partial<CustomFieldDefinitionView> = {},
): CustomFieldDefinitionView {
  return {
    id: "0198c97d-cf4f-7000-8000-000000000002",
    tenantId,
    objectType: "alert",
    key: "incident_owner",
    label: "Incident owner",
    description: "Operational owner.",
    dataType: "short_text",
    required: false,
    nullable: true,
    archived: false,
    schemaVersion: 3,
    visibility: { customer: false, operator: true },
    editPolicy: {
      customerCreate: false,
      customerUpdate: false,
      operatorCreate: true,
      operatorUpdate: true,
    },
    placement: {
      showInCreate: true,
      showInDetail: true,
      showInList: true,
      showInExport: true,
    },
    requiredOnTransitions: [],
    searchable: true,
    filterable: true,
    sortable: true,
    allowStructuredJson: false,
    ...overrides,
  };
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-30T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissionKeys.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId,
    userId: sessionFixture.user.id,
  };
}

function futureSession(session: SessionView): SessionView {
  return {
    ...session,
    absoluteExpiresAt: "2099-08-30T12:00:00Z",
    idleExpiresAt: "2099-08-30T11:00:00Z",
  };
}
