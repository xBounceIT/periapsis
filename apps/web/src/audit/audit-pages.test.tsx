import { cleanup, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  PhaseTwoApi,
  SessionView,
  TenantAuthorityView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { AuditApiError, type AuditReaderApi } from "./audit-api";
import { PlatformAuditPage, TenantAuditPage } from "./audit-pages";
import {
  auditTenantId,
  createAuditApiMock,
  tenantAuditEventFixture,
} from "./audit-test-fixtures";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("audit route pages", () => {
  it("waits for live tenant authority and forwards the current CSRF context", async () => {
    const authority = authorityFixture();
    const getTenantAuthority = vi.fn(async () => authority);
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>(async () => ({
      items: [tenantAuditEventFixture],
    }));

    renderTenantPage({ getTenantAuthority, listTenant });

    expect(await screen.findByText("SEQ 10")).toBeVisible();
    expect(getTenantAuthority).toHaveBeenCalledWith(
      auditTenantId,
      expect.any(Object),
    );
    expect(listTenant).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: auditTenantId }),
    );
  });

  it("clears the exact session after a tenant audit 401", async () => {
    const clearSession = vi.fn();
    const listTenant = vi
      .fn<AuditReaderApi["listTenant"]>()
      .mockRejectedValue(
        new AuditApiError("The current session was not accepted.", 401),
      );

    renderTenantPage({ clearSession, listTenant });

    await waitFor(() =>
      expect(clearSession).toHaveBeenCalledWith(sessionFixture.id),
    );
    expect(listTenant).toHaveBeenCalledTimes(1);
  });

  it("reloads stale tenant authority once and keeps a denied pair closed", async () => {
    const getTenantAuthority = vi.fn(async () => authorityFixture());
    const listTenant = vi
      .fn<AuditReaderApi["listTenant"]>()
      .mockRejectedValue(
        new AuditApiError("The server denied this audit operation.", 403),
      );

    renderTenantPage({ getTenantAuthority, listTenant });

    await waitFor(() => expect(getTenantAuthority).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Audit authority required")).toBeVisible();
    expect(listTenant).toHaveBeenCalledTimes(1);
  });

  it("revalidates a stale platform capability without retrying the denied read", async () => {
    const clearSession = vi.fn();
    const updateSession = vi.fn();
    const current = platformSession();
    const refreshed = { ...current, permissions: [] };
    const getSession = vi.fn(async () => refreshed);
    const listPlatform = vi
      .fn<AuditReaderApi["listPlatform"]>()
      .mockRejectedValue(
        new AuditApiError("The server denied this audit operation.", 403),
      );
    const sessionApi = createPhaseTwoApi({ getSession });

    renderWithSession(
      <PlatformAuditPage api={createAuditApiMock({ listPlatform })} />,
      {
        api: sessionApi,
        clearSession,
        session: current,
        updateSession,
      },
    );

    await waitFor(() => expect(getSession).toHaveBeenCalledTimes(1));
    expect(updateSession).toHaveBeenCalledWith(current.id, refreshed);
    expect(clearSession).not.toHaveBeenCalled();
    expect(listPlatform).toHaveBeenCalledTimes(1);
  });
});

function renderTenantPage({
  clearSession = vi.fn(),
  getTenantAuthority = vi.fn(async () => authorityFixture()),
  listTenant,
}: {
  clearSession?: (expectedSessionId: string) => void;
  getTenantAuthority?: PhaseTwoApi["getTenantAuthority"];
  listTenant: AuditReaderApi["listTenant"];
}): void {
  const session = tenantSession();
  const api = createPhaseTwoApi({ getTenantAuthority });
  renderWithSession(
    <TenantAuthorityProvider>
      <TenantAuditPage api={createAuditApiMock({ listTenant })} />
    </TenantAuthorityProvider>,
    { api, clearSession, session, updateSession: vi.fn() },
  );
}

function renderWithSession(
  children: ReactNode,
  value: {
    api: PhaseTwoApi;
    clearSession: (expectedSessionId: string) => void;
    session: SessionView;
    updateSession: (expectedSessionId: string, session: SessionView) => void;
  },
): void {
  render(
    <SessionContext.Provider
      value={{
        ...value,
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
      }}
    >
      {children}
    </SessionContext.Provider>,
  );
}

function tenantSession(): SessionView {
  return {
    ...sessionFixture,
    activeTenantId: auditTenantId,
    permissions: [],
  };
}

function platformSession(): SessionView {
  return {
    ...sessionFixture,
    permissions: ["platform.audit.read"],
  };
}

function authorityFixture(): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-26T00:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "01991c20-7d5f-7000-8000-000000000010",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [{ permissionKey: "audit.read", scope: "tenant" }],
    roleGrants: [],
    tenantId: auditTenantId,
    userId: sessionFixture.user.id,
  };
}
