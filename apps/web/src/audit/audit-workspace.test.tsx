import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditApiError, type AuditReaderApi } from "./audit-api";
import {
  PlatformAuditWorkspace,
  TenantAuditWorkspace,
} from "./audit-workspace";
import {
  auditTenantId,
  auditVerificationFixture,
  createAuditApiMock,
  platformAuditEventFixture,
  tenantAuditEventFixture,
} from "./audit-test-fixtures";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("audit workspaces", () => {
  it("denies by default without issuing an audit read", () => {
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>();
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead={false}
        csrfToken="csrf-memory-only"
        tenantId={auditTenantId}
      />,
    );

    expect(screen.getByText("Audit authority required")).toBeVisible();
    expect(screen.getByText("audit.read", { exact: false })).toBeVisible();
    expect(listTenant).not.toHaveBeenCalled();
  });

  it("waits for live authority without flashing a denial or issuing a read", () => {
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>();
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        authorizationStatus="loading"
        canRead={false}
        csrfToken="csrf-memory-only"
        tenantId={auditTenantId}
      />,
    );

    expect(screen.getByText("Checking audit authority")).toBeVisible();
    expect(screen.queryByText("Audit authority required")).toBeNull();
    expect(listTenant).not.toHaveBeenCalled();
  });

  it("reports a missing tenant before evaluating tenant permission", () => {
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>();
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead={false}
        csrfToken="csrf-memory-only"
        tenantId=""
      />,
    );

    expect(screen.getByText("Tenant context required")).toBeVisible();
    expect(screen.queryByText("Audit authority required")).toBeNull();
    expect(listTenant).not.toHaveBeenCalled();
  });

  it("does not duplicate a self-audited read under React StrictMode", async () => {
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>(async () => ({
      items: [tenantAuditEventFixture],
    }));
    render(
      <StrictMode>
        <TenantAuditWorkspace
          api={createAuditApiMock({ listTenant })}
          canRead
          csrfToken="csrf-memory-only"
          tenantId={auditTenantId}
        />
      </StrictMode>,
    );

    expect(await screen.findByText("SEQ 10")).toBeVisible();
    expect(listTenant).toHaveBeenCalledTimes(1);
  });

  it("propagates server denial to the live session and authority boundaries", async () => {
    const onUnauthorized = vi.fn();
    const onForbidden = vi.fn();
    const listTenant = vi
      .fn<AuditReaderApi["listTenant"]>()
      .mockRejectedValueOnce(
        new AuditApiError("The current session was not accepted.", 401),
      );
    const view = render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead
        csrfToken="csrf-memory-only"
        onForbidden={onForbidden}
        onUnauthorized={onUnauthorized}
        tenantId={auditTenantId}
      />,
    );
    await waitFor(() => expect(onUnauthorized).toHaveBeenCalledTimes(1));
    expect(onForbidden).not.toHaveBeenCalled();

    view.unmount();
    listTenant.mockRejectedValueOnce(
      new AuditApiError(
        "The audit projection was not safe to display.",
        undefined,
        "projection_mismatch",
      ),
    );
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead
        csrfToken="csrf-memory-only"
        onForbidden={onForbidden}
        onUnauthorized={onUnauthorized}
        tenantId={auditTenantId}
      />,
    );
    await waitFor(() => expect(onForbidden).toHaveBeenCalledTimes(1));
  });

  it("renders the ordered tenant ledger and structurally redacted detail", async () => {
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock()}
        canRead
        csrfToken="csrf-memory-only"
        tenantId={auditTenantId}
        tenantLabel="Acme SOC"
      />,
    );

    expect(await screen.findByText("SEQ 10")).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "case.transition" }),
    ).toBeVisible();
    expect(screen.getByText(/"status": "contained"/u)).toBeVisible();
    expect(screen.getByText("Acme SOC")).toBeVisible();
    expect(screen.getByText("Server allowlist")).toBeVisible();
  });

  it("keeps applied filters across forward cursor pagination", async () => {
    const second = {
      ...tenantAuditEventFixture,
      id: "01991c20-7d5f-7000-8000-000000000011",
      sequence: 11,
      action: "case.comment.created",
      previousHash: tenantAuditEventFixture.eventHash,
      eventHash: "c".repeat(64),
    };
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>(async (input) =>
      input.afterSequence === 10
        ? { items: [second] }
        : { items: [tenantAuditEventFixture], nextSequence: 10 },
    );
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead
        csrfToken="csrf-memory-only"
        tenantId={auditTenantId}
      />,
    );

    await screen.findByText("SEQ 10");
    fireEvent.change(screen.getByLabelText("Search allowed fields"), {
      target: { value: "containment" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() =>
      expect(listTenant).toHaveBeenLastCalledWith(
        expect.objectContaining({
          filters: expect.objectContaining({ search: "containment" }),
        }),
      ),
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load next sequence" }),
    );
    expect(await screen.findByText("SEQ 11")).toBeVisible();
    expect(listTenant).toHaveBeenLastCalledWith(
      expect.objectContaining({
        afterSequence: 10,
        filters: expect.objectContaining({ search: "containment" }),
      }),
    );
  });

  it("stops pagination when an adjacent page breaks the hash link", async () => {
    const second = {
      ...tenantAuditEventFixture,
      id: "01991c20-7d5f-7000-8000-000000000011",
      sequence: 11,
      previousHash: "d".repeat(64),
      eventHash: "c".repeat(64),
    };
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>(async (input) =>
      input.afterSequence === 10
        ? { items: [second] }
        : { items: [tenantAuditEventFixture], nextSequence: 10 },
    );
    const onForbidden = vi.fn();
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ listTenant })}
        canRead
        csrfToken="csrf-memory-only"
        onForbidden={onForbidden}
        tenantId={auditTenantId}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load next sequence" }),
    );

    expect(await screen.findByText(/broken adjacent hash link/u)).toBeVisible();
    expect(screen.queryByText("SEQ 11")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Load next sequence" }),
    ).not.toBeInTheDocument();
    expect(onForbidden).not.toHaveBeenCalled();
  });

  it("verifies the tenant chain with live CSRF context", async () => {
    const verifyTenant = vi.fn<AuditReaderApi["verifyTenant"]>(
      async () => auditVerificationFixture,
    );
    render(
      <TenantAuditWorkspace
        api={createAuditApiMock({ verifyTenant })}
        canRead
        csrfToken="csrf-memory-only"
        tenantId={auditTenantId}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    expect(await screen.findByText("Audit chain verified")).toBeVisible();
    expect(verifyTenant).toHaveBeenCalledWith(
      expect.objectContaining({
        csrfToken: "csrf-memory-only",
        tenantId: auditTenantId,
      }),
    );
  });

  it("keeps the platform stream independent and omits tenant-only actor filters", async () => {
    const listPlatform = vi.fn<AuditReaderApi["listPlatform"]>(async () => ({
      items: [platformAuditEventFixture],
    }));
    const listTenant = vi.fn<AuditReaderApi["listTenant"]>();
    render(
      <PlatformAuditWorkspace
        api={createAuditApiMock({ listPlatform, listTenant })}
        canRead
        csrfToken="csrf-memory-only"
      />,
    );

    expect(await screen.findByText("SEQ 21")).toBeVisible();
    expect(screen.getByText("platform.audit.read")).toBeVisible();
    expect(
      screen.queryByLabelText("Actor service-account ID"),
    ).not.toBeInTheDocument();
    expect(listPlatform).toHaveBeenCalledTimes(1);
    expect(listTenant).not.toHaveBeenCalled();
  });
});
