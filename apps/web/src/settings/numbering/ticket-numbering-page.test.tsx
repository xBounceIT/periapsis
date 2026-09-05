import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  TicketNumberingDraft,
  TicketNumberingKind,
  TicketNumberingPolicy,
} from "@periapsis/contracts";

import { SessionContext } from "../../auth/session-context";
import { TenantAuthorityProvider } from "../../auth/tenant-authority-context";
import {
  PhaseTwoApiError,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
} from "../../lib/phase-two-types";
import {
  createPhaseTwoApi,
  sessionFixture,
} from "../../test/phase-two-fixtures";
import type { TicketNumberingApi } from "./model";
import { TicketNumberingPage } from "./ticket-numbering-page";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(cleanup);

describe("TicketNumberingPage", () => {
  it("shows Alert and Case policies and server previews read-only to a reader", async () => {
    const api = numberingApiFixture();
    renderPage(api, ["settings.read"]);

    const alertCard = await cardFor("Alert numbers");
    const caseCard = await cardFor("Case numbers");
    expect(await within(alertCard).findByText("ALT-2026-000001")).toBeVisible();
    expect(await within(caseCard).findByText("CAS-2026-000001")).toBeVisible();
    expect(within(alertCard).getByLabelText("Prefix")).toHaveAttribute(
      "readonly",
    );
    expect(within(caseCard).getByLabelText("Counter period")).toBeDisabled();
    expect(screen.getAllByText("Read-only access")).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "Publish policy" }),
    ).not.toBeInTheDocument();
  });

  it("uses preview only while a manager edits and never treats it as a publication", async () => {
    const preview = vi.fn<TicketNumberingApi["preview"]>(
      async (_csrf, requestedTenant, kind, draft) =>
        previewFixture(requestedTenant, kind, draft),
    );
    const update = vi.fn<TicketNumberingApi["update"]>();
    renderPage(numberingApiFixture({ preview, update }), [
      "settings.read",
      "settings.manage",
    ]);
    const alertCard = await cardFor("Alert numbers");
    await within(alertCard).findByText("ALT-2026-000001");
    preview.mockClear();

    fireEvent.change(within(alertCard).getByLabelText("Prefix"), {
      target: { value: "inc" },
    });

    expect(await within(alertCard).findByText("INC-2026-000001")).toBeVisible();
    expect(preview).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      "alert",
      {
        period: "annual",
        prefix: "INC",
        separator: "-",
        start: 1,
        width: 6,
      },
      expect.any(AbortSignal),
    );
    expect(update).not.toHaveBeenCalled();
    expect(
      within(alertCard).getByText("Server-validated · no number allocated"),
    ).toBeVisible();
  });

  it("publishes one version-bound, idempotent Alert policy without changing Case", async () => {
    const update = vi.fn<TicketNumberingApi["update"]>(
      async (_csrf, _tenant, kind, _current, _key, _reason, draft) => ({
        etag: '"v8"',
        replayed: false,
        value: policyFixture(kind, {
          ...draft,
          publishedAt: "2026-09-03T11:00:00Z",
          version: 8,
          versionId: "0198c97d-cf4f-7000-8000-000000000098",
        }),
      }),
    );
    renderPage(numberingApiFixture({ update }), [
      "settings.read",
      "settings.manage",
    ]);
    const alertCard = await cardFor("Alert numbers");
    await within(alertCard).findByText("ALT-2026-000001");

    fireEvent.change(within(alertCard).getByLabelText("Prefix"), {
      target: { value: "INC" },
    });
    fireEvent.change(within(alertCard).getByLabelText("Start value"), {
      target: { value: "25" },
    });
    fireEvent.change(within(alertCard).getByLabelText("Audit reason"), {
      target: { value: "Approved numbering change SEC-2048" },
    });
    const publish = within(alertCard).getByRole("button", {
      name: "Publish policy",
    });
    await waitFor(() => expect(publish).toBeEnabled());
    fireEvent.click(publish);

    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    const call = update.mock.calls[0]!;
    expect(call[0]).toBe(sessionFixture.csrfToken);
    expect(call[1]).toBe(tenantId);
    expect(call[2]).toBe("alert");
    expect(call[3]).toEqual({
      etag: '"v7"',
      value: policyFixture("alert"),
    });
    expect(call[4]).toMatch(/^[A-Za-z0-9._~-]{16,128}$/u);
    expect(call[5]).toBe("Approved numbering change SEC-2048");
    expect(call[6]).toEqual({
      period: "annual",
      prefix: "INC",
      separator: "-",
      start: 25,
      width: 6,
    });
    expect(
      await within(alertCard).findByText(/Version 8 is published/u),
    ).toBeVisible();
    expect(
      within(await cardFor("Case numbers")).getByText("Current v7"),
    ).toBeVisible();
  });

  it("reloads the winning immutable version after stale CAS", async () => {
    let alertReads = 0;
    const get = vi.fn<TicketNumberingApi["get"]>(async (_tenant, kind) => {
      if (kind === "case") {
        return { etag: '"v7"', value: policyFixture("case") };
      }
      alertReads += 1;
      return alertReads === 1
        ? { etag: '"v7"', value: policyFixture("alert") }
        : {
            etag: '"v8"',
            value: policyFixture("alert", {
              prefix: "WIN",
              publishedAt: "2026-09-03T11:02:00Z",
              version: 8,
              versionId: "0198c97d-cf4f-7000-8000-000000000099",
            }),
          };
    });
    const update = vi.fn<TicketNumberingApi["update"]>(async () => {
      throw new PhaseTwoApiError("stale", 412, {
        code: "precondition_failed",
      });
    });
    renderPage(numberingApiFixture({ get, update }), [
      "settings.read",
      "settings.manage",
    ]);
    const alertCard = await cardFor("Alert numbers");
    await within(alertCard).findByText("ALT-2026-000001");
    fireEvent.change(within(alertCard).getByLabelText("Prefix"), {
      target: { value: "INC" },
    });
    fireEvent.change(within(alertCard).getByLabelText("Audit reason"), {
      target: { value: "Approved" },
    });
    await waitFor(() =>
      expect(
        within(alertCard).getByRole("button", { name: "Publish policy" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      within(alertCard).getByRole("button", { name: "Publish policy" }),
    );

    await waitFor(() => expect(alertReads).toBe(2));
    expect(await within(alertCard).findByDisplayValue("WIN")).toBeVisible();
    expect(
      await within(alertCard).findByText(
        /Someone published this policy first/u,
      ),
    ).toBeVisible();
  });

  it("denies the direct route before any policy or preview request", async () => {
    const get = vi.fn<TicketNumberingApi["get"]>();
    const preview = vi.fn<TicketNumberingApi["preview"]>();
    renderPage(numberingApiFixture({ get, preview }), []);
    expect(
      await screen.findByRole("heading", {
        name: "Access was denied by the server.",
      }),
    ).toBeVisible();
    expect(get).not.toHaveBeenCalled();
    expect(preview).not.toHaveBeenCalled();
  });
});

async function cardFor(name: string): Promise<HTMLElement> {
  const title = await screen.findByRole("heading", { name });
  const card = title.closest<HTMLElement>('[data-slot="card"]');
  if (!card) throw new Error(`Missing card for ${name}`);
  return card;
}

function renderPage(
  numberingApi: TicketNumberingApi,
  permissions: readonly TenantPermissionKeyView[],
): void {
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(permissions),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: {
            ...sessionFixture,
            absoluteExpiresAt: "2099-09-02T12:00:00Z",
            activeTenantId: tenantId,
            idleExpiresAt: "2099-09-01T12:00:00Z",
          },
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <TicketNumberingPage api={numberingApi} />
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function numberingApiFixture(
  overrides: Partial<TicketNumberingApi> = {},
): TicketNumberingApi {
  return {
    get: async (_tenantId, kind) => ({
      etag: '"v7"',
      value: policyFixture(kind),
    }),
    preview: async (_csrf, requestedTenant, kind, draft) =>
      previewFixture(requestedTenant, kind, draft),
    update: async (_csrf, _tenant, kind, _current, _key, _reason, draft) => ({
      etag: '"v8"',
      replayed: false,
      value: policyFixture(kind, {
        ...draft,
        publishedAt: "2026-09-03T11:00:00Z",
        version: 8,
        versionId: "0198c97d-cf4f-7000-8000-000000000098",
      }),
    }),
    ...overrides,
  };
}

function policyFixture(
  kind: TicketNumberingKind,
  override: Partial<TicketNumberingPolicy> = {},
): TicketNumberingPolicy {
  return {
    kind,
    period: "annual",
    prefix: kind === "alert" ? "ALT" : "CAS",
    publishedAt: "2026-09-01T18:30:00.123456Z",
    publisher: {
      membershipId: "0198c97d-cf4f-7000-8000-000000000020",
      type: "membership",
    },
    separator: "-",
    start: 1,
    tenantId,
    version: 7,
    versionId:
      kind === "alert"
        ? "0198c97d-cf4f-7000-8000-000000000092"
        : "0198c97d-cf4f-7000-8000-000000000093",
    width: 6,
    ...override,
  };
}

function previewFixture(
  requestedTenant: string,
  kind: TicketNumberingKind,
  draft: TicketNumberingDraft,
) {
  const at = "2026-09-03T10:30:00Z";
  const year = 2026;
  const serial = String(draft.start).padStart(draft.width, "0");
  return {
    ...draft,
    at,
    example:
      draft.period === "annual"
        ? `${draft.prefix}${draft.separator}${year}${draft.separator}${serial}`
        : `${draft.prefix}${draft.separator}${serial}`,
    kind,
    maximumSequence: 10 ** draft.width - 1,
    periodKey: draft.period === "annual" ? year : 0,
    tenantId: requestedTenant,
  };
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-09-01T19:00:00Z",
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
