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
  CustomFieldImportApiError,
  type CustomFieldImportApi,
} from "./custom-field-import-api";
import {
  TenantCustomFieldImportPage,
  customFieldImportRoutes,
} from "./custom-field-import-page";
import type {
  CustomFieldImportJobView,
  CustomFieldImportResultView,
} from "./custom-field-import-model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const jobId = "0198c97d-cf4f-7000-8000-000000000002";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("tenant custom-field import page", () => {
  it("mounts the canonical tenant route", () => {
    expect(customFieldImportRoutes.map((route) => route.path)).toEqual([
      "tenant/custom-field-imports",
    ]);
  });

  it("does not derive import authority from session claims", async () => {
    const request = vi.fn<CustomFieldImportApi["request"]>();
    renderPage(apiMock({ request }), [], ["custom_field.read", "alert.update"]);

    expect(
      await screen.findByRole("heading", {
        name: "Custom-field imports are unavailable.",
      }),
    ).toBeVisible();
    expect(request).not.toHaveBeenCalled();
  });

  it("reviews and submits distinct missing, null, and empty values", async () => {
    const request = vi.fn<CustomFieldImportApi["request"]>(async () => ({
      job: jobFixture(),
      replayed: false,
      etag: '"v1"',
    }));
    renderPage(apiMock({ request }), ["custom_field.read", "alert.update"]);

    expect(
      await screen.findByRole("heading", { name: "Bulk custom-field import" }),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Review pinned import" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Validate 1 Alert row?" }),
    ).toBeVisible();
    expect(screen.getAllByText("preserved values").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Queue dry run" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    const fields = request.mock.calls[0]![0].body.rows[0]!.fields;
    expect(fields).toEqual([
      { key: "triage.owner", value: "incident-response" },
      { key: "triage.note", value: "" },
      { key: "triage.reviewed_at", value: null },
      { key: "triage.preserve_existing" },
    ]);
    expect(Object.hasOwn(fields[3]!, "value")).toBe(false);
    expect(
      screen.getByRole("button", { name: "Current import is active" }),
    ).toBeDisabled();
  });

  it("keeps object access provider-scoped and moves to the permitted kind", async () => {
    renderPage(apiMock(), ["custom_field.read", "case.update"]);

    const cases = await screen.findByRole("button", { name: "Cases" });
    expect(cases).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Alerts" })).toBeDisabled();

    fireEvent.click(
      screen.getByRole("button", { name: "Review pinned import" }),
    );
    expect(
      await screen.findByRole("heading", { name: "Validate 1 Case row?" }),
    ).toBeVisible();
  });

  it("cancels future rows under the current job revision", async () => {
    const cancel = vi.fn<CustomFieldImportApi["cancel"]>(async (input) => ({
      job: jobFixture({
        state: "cancelled",
        revision: input.expectedRevision + 1,
        updatedAt: "2026-09-03T14:00:01Z",
        terminalAt: "2026-09-03T14:00:01Z",
        progress: {
          ...jobFixture().progress,
          processed: 1,
          cancelled: 1,
        },
      }),
      replayed: false,
      etag: `"v${input.expectedRevision + 1}"`,
    }));
    renderPage(apiMock({ cancel }), ["custom_field.read", "alert.update"]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Review pinned import" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Queue dry run" }));
    expect(
      await screen.findByRole("heading", { name: "Pending" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Stop future rows" }));

    await waitFor(() => expect(cancel).toHaveBeenCalledTimes(1));
    expect(cancel).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedRevision: 1,
        jobId,
        objectType: "alert",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Cancelled" }),
    ).toBeVisible();
  });

  it("polls authoritative progress and renders field-specific results", async () => {
    const completed = jobFixture({
      state: "completed",
      revision: 3,
      attempts: 1,
      updatedAt: "2026-09-03T14:00:03Z",
      terminalAt: "2026-09-03T14:00:03Z",
      progress: {
        ...jobFixture().progress,
        processed: 1,
        rejected: 1,
      },
    });
    const get = vi.fn<CustomFieldImportApi["get"]>(async () => completed);
    const listResults = vi.fn<CustomFieldImportApi["listResults"]>(
      async () => ({ items: [resultFixture()] }),
    );
    renderPage(apiMock({ get, listResults }), [
      "custom_field.read",
      "alert.update",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Review pinned import" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Queue dry run" }));
    expect(await screen.findByText("triage.owner: Required")).toBeVisible();
    expect(listResults).toHaveBeenCalledWith(
      expect.objectContaining({ jobId, objectType: "alert", pageSize: 100 }),
    );
  });

  it("reports malformed JSON locally without contacting the API", async () => {
    const request = vi.fn<CustomFieldImportApi["request"]>();
    renderPage(apiMock({ request }), ["custom_field.read", "alert.update"]);

    fireEvent.change(await screen.findByLabelText("Import rows JSON"), {
      target: { value: "not-json" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review pinned import" }),
    );

    expect(
      await screen.findByText("Enter a valid JSON array of import rows."),
    ).toBeVisible();
    expect(request).not.toHaveBeenCalled();
  });

  it("removes job data when a live authorization recheck revokes access", async () => {
    const getTenantAuthority = vi
      .fn<() => Promise<TenantAuthorityView>>()
      .mockResolvedValueOnce(
        authorityFixture(["custom_field.read", "alert.update"]),
      )
      .mockResolvedValue(authorityFixture([]));
    const get = vi.fn<CustomFieldImportApi["get"]>(async () => {
      throw new CustomFieldImportApiError(
        "Current authority was revoked.",
        403,
        "forbidden",
      );
    });
    renderPage(
      apiMock({ get }),
      ["custom_field.read", "alert.update"],
      [],
      getTenantAuthority,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Review pinned import" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Queue dry run" }));

    expect(
      await screen.findByRole("heading", {
        name: "Custom-field imports are unavailable.",
      }),
    ).toBeVisible();
    expect(getTenantAuthority).toHaveBeenCalledTimes(2);
    expect(
      screen.queryByRole("heading", { name: "Pending" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(`${jobId.slice(0, 8)}…`)).not.toBeInTheDocument();
  });
});

function renderPage(
  customFieldImportApi: CustomFieldImportApi,
  permissionKeys: readonly TenantPermissionKeyView[],
  sessionPermissions: readonly string[] = [],
  getTenantAuthority: () => Promise<TenantAuthorityView> = async () =>
    authorityFixture(permissionKeys),
): void {
  const phaseTwoApi = createPhaseTwoApi({
    getTenantAuthority,
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
          <TenantCustomFieldImportPage api={customFieldImportApi} />
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function apiMock(
  overrides: Partial<CustomFieldImportApi> = {},
): CustomFieldImportApi {
  return {
    request: async () => ({
      job: jobFixture(),
      replayed: false,
      etag: '"v1"',
    }),
    get: async () => jobFixture(),
    cancel: async () => ({
      job: jobFixture({ state: "cancellation_requested", revision: 2 }),
      replayed: false,
      etag: '"v2"',
    }),
    listResults: async () => ({ items: [] }),
    ...overrides,
  };
}

function jobFixture(
  overrides: Partial<CustomFieldImportJobView> = {},
): CustomFieldImportJobView {
  return {
    id: jobId,
    tenantId,
    requesterUserId: sessionFixture.user.id,
    ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000020",
    objectType: "alert",
    mode: "dry_run",
    state: "pending",
    revision: 1,
    attempts: 0,
    progress: {
      total: 1,
      processed: 0,
      succeeded: 0,
      noChange: 0,
      versionConflict: 0,
      notFoundOrHidden: 0,
      authorizationDenied: 0,
      rejected: 0,
      cancelled: 0,
      authorizationRevoked: 0,
      expired: 0,
      internalFailure: 0,
    },
    requestedAt: "2026-09-03T14:00:00Z",
    updatedAt: "2026-09-03T14:00:00Z",
    availableAt: "2026-09-03T14:00:00Z",
    expiresAt: "2026-09-04T14:00:00Z",
    activeAttempt: false,
    ...overrides,
  };
}

function resultFixture(): CustomFieldImportResultView {
  return {
    sequence: 1,
    targetId: "0198c97d-cf4f-7000-8000-000000000101",
    expectedVersion: 7,
    outcome: "validation_failed",
    resultingVersion: 0,
    fieldErrors: [{ field: "triage.owner", code: "required" }],
    recordedAt: "2026-09-03T14:00:01Z",
  };
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-09-03T13:00:00Z",
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
    absoluteExpiresAt: "2099-09-03T15:00:00Z",
    idleExpiresAt: "2099-09-03T14:00:00Z",
  };
}
