import type { TicketBulkQuerySourceRequest } from "@periapsis/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { TicketBulkApi, TicketBulkJobView } from "../lib/ticket-bulk-api";
import { TicketBulkApiProvider } from "./ticket-bulk-context";
import { TicketBulkControls } from "./ticket-bulk-controls";
import {
  defaultTicketTableColumns,
  inlineSavedViewSpec,
} from "./saved-view-model";
import { tenantId, userId } from "./ticketing-test-fixtures";

const jobId = "0198c97d-cf4f-7000-8000-000000000091";
const membershipId = "0198c97d-cf4f-7000-8000-000000000015";

describe("TicketBulkControls", () => {
  it("submits the immutable query snapshot that the operator reviewed", async () => {
    const request = vi.fn(
      async (_input: Parameters<TicketBulkApi["request"]>[0]) => ({
        job: pendingJob,
        replayed: false,
      }),
    );
    const api: TicketBulkApi = {
      request,
      get: async () => pendingJob,
      cancel: async () => ({ job: pendingJob, replayed: false }),
      listResults: async () => ({ items: [] }),
    };
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const first = inlineQuery("first scope");
    const second = inlineQuery("second scope");
    const view = render(controls(api, queryClient, first));

    fireEvent.change(screen.getByRole("combobox", { name: "Selection" }), {
      target: { value: "query" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review operation" }));
    view.rerender(controls(api, queryClient, second));
    fireEvent.click(screen.getByRole("button", { name: "Queue operation" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]![0].body.selection).toEqual({
      source: "query",
      query: first,
    });
  });
});

function controls(
  api: TicketBulkApi,
  queryClient: QueryClient,
  query: TicketBulkQuerySourceRequest,
): React.JSX.Element {
  return (
    <QueryClientProvider client={queryClient}>
      <TicketBulkApiProvider api={api}>
        <TicketBulkControls
          availableActions={["release"]}
          csrfToken="csrf-memory-only-value"
          kind="alert"
          onClearSelection={vi.fn()}
          query={query}
          selectedTargets={[]}
          tenantId={tenantId}
        />
      </TicketBulkApiProvider>
    </QueryClientProvider>
  );
}

function inlineQuery(search: string): TicketBulkQuerySourceRequest {
  return {
    source: "inline",
    spec: inlineSavedViewSpec({ limit: 30, search }, defaultTicketTableColumns),
  };
}

const pendingJob: TicketBulkJobView = {
  activeBatch: false,
  availableAt: "2026-08-26T18:00:00Z",
  expiresAt: "2026-08-27T18:00:00Z",
  id: jobId,
  kind: "alert",
  mutation: { action: "release" },
  ownerMembershipId: membershipId,
  progress: {
    authorizationDenied: 0,
    authorizationRevoked: 0,
    cancelled: 0,
    internalFailure: 0,
    noChange: 0,
    notFoundOrHidden: 0,
    rejected: 0,
    succeeded: 0,
    total: 1,
    versionConflict: 0,
  },
  requestedAt: "2026-08-26T18:00:00Z",
  requesterUserId: userId,
  revision: 1,
  selection: {
    catalogSha256: "b".repeat(64),
    querySha256: "c".repeat(64),
    querySource: "inline",
    source: "query",
    targetCount: 1,
    targetSetSha256: "a".repeat(64),
  },
  state: "pending",
  tenantId,
  updatedAt: "2026-08-26T18:00:00Z",
};
