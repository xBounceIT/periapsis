import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditApiError } from "./audit-api";
import { AuditOperations } from "./audit-operations";
import type { AuditOperationsApi } from "./audit-operations-api";
import { auditTenantId } from "./audit-test-fixtures";
import { emptyAuditFilterDraft, normalizeAuditFilters } from "./model";

const exportId = "01991c20-7d5f-7000-8000-000000000031";
const requesterId = "01991c20-7d5f-7000-8000-000000000032";
const holdId = "01991c20-7d5f-7000-8000-000000000033";
const scope = { kind: "tenant", tenantId: auditTenantId } as const;
const filters = normalizeAuditFilters(
  { ...emptyAuditFilterDraft, actionPrefix: "case.transition" },
  "tenant",
);

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("AuditOperations", () => {
  it("renders nothing and issues no request without a dedicated permission", () => {
    const getRetention = vi.fn<AuditOperationsApi["getRetention"]>();
    const createExport = vi.fn<AuditOperationsApi["createExport"]>();
    const api = createOperationsApi({ createExport, getRetention });
    const { container } = render(
      <AuditOperations
        api={api}
        canExport={false}
        canManageRetention={false}
        csrfToken="csrf-memory-only"
        filters={filters}
        onBoundaryError={vi.fn()}
        scope={scope}
      />,
    );

    expect(container).toBeEmptyDOMElement();
    expect(getRetention).not.toHaveBeenCalled();
    expect(createExport).not.toHaveBeenCalled();
  });

  it("queues the exact current filter only after an explicit redacted reason", async () => {
    const createExport = vi.fn<AuditOperationsApi["createExport"]>(
      async () => ({
        job: pendingJob(),
        replayed: false,
      }),
    );
    renderOperations(createOperationsApi({ createExport }), {
      canExport: true,
      canManageRetention: false,
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Export current view" }),
    );
    const queue = screen.getByRole("button", { name: "Queue export" });
    expect(queue).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Redacted reason"), {
      target: { value: "Incident evidence review" },
    });
    fireEvent.click(queue);

    await waitFor(() => expect(createExport).toHaveBeenCalledTimes(1));
    expect(createExport).toHaveBeenCalledWith(
      expect.objectContaining({
        csrfToken: "csrf-memory-only",
        filters,
        reason: "Incident evidence review",
        retentionSeconds: 86_400,
        scope,
      }),
    );
    expect(await screen.findByText("pending")).toBeVisible();
  });

  it("requires reason plus affirmative confirmation before releasing a legal hold", async () => {
    const getRetention = vi
      .fn<AuditOperationsApi["getRetention"]>()
      .mockResolvedValueOnce(retentionState(true))
      .mockResolvedValueOnce(retentionState(false));
    const releaseLegalHold = vi.fn<AuditOperationsApi["releaseLegalHold"]>(
      async () => ({
        hold: {
          id: holdId,
          placedAt: "2026-09-01T10:00:00Z",
          releasedAt: "2026-09-01T10:01:00Z",
          revision: 2,
          state: "released",
        },
        replayed: false,
      }),
    );
    renderOperations(createOperationsApi({ getRetention, releaseLegalHold }), {
      canExport: false,
      canManageRetention: true,
    });

    fireEvent.click(screen.getByRole("button", { name: "Retention & hold" }));
    const release = await screen.findByRole("button", {
      name: "Release legal hold",
    });
    expect(release).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Redacted change reason"), {
      target: { value: "Investigation is complete" },
    });
    expect(release).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: "I confirm this release is authorized and the reason contains no protected data.",
      }),
    );
    fireEvent.click(release);

    await waitFor(() => expect(releaseLegalHold).toHaveBeenCalledTimes(1));
    expect(releaseLegalHold).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedRevision: 1,
        holdId,
        reason: "Investigation is complete",
        scope,
      }),
    );
    await waitFor(() => expect(getRetention).toHaveBeenCalledTimes(2));
    expect(screen.getByText("None active")).toBeVisible();
  });

  it("forwards a fresh authorization denial to the owning boundary", async () => {
    const onBoundaryError = vi.fn();
    const createExport = vi.fn<AuditOperationsApi["createExport"]>(async () => {
      throw new AuditApiError("The server denied this audit operation.", 403);
    });
    render(
      <AuditOperations
        api={createOperationsApi({ createExport })}
        canExport
        canManageRetention={false}
        csrfToken="csrf-memory-only"
        filters={filters}
        onBoundaryError={onBoundaryError}
        scope={scope}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Export current view" }),
    );
    fireEvent.change(screen.getByLabelText("Redacted reason"), {
      target: { value: "Incident evidence review" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));

    await waitFor(() =>
      expect(onBoundaryError).toHaveBeenCalledWith(
        expect.objectContaining({ status: 403 }),
      ),
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The server denied this audit operation.",
    );
  });
});

function renderOperations(
  api: AuditOperationsApi,
  permissions: { canExport: boolean; canManageRetention: boolean },
): void {
  render(
    <AuditOperations
      api={api}
      {...permissions}
      csrfToken="csrf-memory-only"
      filters={filters}
      onBoundaryError={vi.fn()}
      scope={scope}
    />,
  );
}

function createOperationsApi(
  overrides: Partial<AuditOperationsApi> = {},
): AuditOperationsApi {
  return {
    cancelExport: vi.fn(),
    createExport: vi.fn(),
    downloadExport: vi.fn(),
    getExport: vi.fn(),
    getRetention: vi.fn(),
    placeLegalHold: vi.fn(),
    releaseLegalHold: vi.fn(),
    updateRetention: vi.fn(),
    ...overrides,
  };
}

function pendingJob() {
  return {
    attempts: 0,
    availableAt: "2026-09-01T10:00:00Z",
    expiresAt: "2026-09-02T10:00:00Z",
    failureCode: "none" as const,
    filter: { actionPrefix: "case.transition" },
    filterSha256: "a".repeat(64),
    format: "jsonl" as const,
    id: exportId,
    maximumAttempts: 3,
    projectionVersion: 1 as const,
    requestedAt: "2026-09-01T10:00:00Z",
    requesterUserId: requesterId,
    revision: 1,
    state: "pending" as const,
    stream: "tenant" as const,
    tenantId: auditTenantId,
    updatedAt: "2026-09-01T10:00:00Z",
  };
}

function retentionState(activeHold: boolean) {
  return {
    anchor: {
      retainedThroughHash: "0".repeat(64),
      retainedThroughSequence: 0,
      revision: 1,
      updatedAt: "2026-09-01T10:00:00Z",
    },
    ...(activeHold
      ? {
          activeLegalHold: {
            id: holdId,
            placedAt: "2026-09-01T10:00:00Z",
            revision: 1,
            state: "active" as const,
          },
        }
      : {}),
    policy: {
      retentionDays: 365,
      revision: 1,
      updatedAt: "2026-09-01T10:00:00Z",
    },
    stream: "tenant" as const,
    tenantId: auditTenantId,
  };
}
