import type { TicketExportJobRequest } from "@periapsis/contracts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  TicketExportApi,
  TicketExportJobView,
} from "../lib/ticket-export-api";
import { TicketingApiError } from "../lib/ticketing-api";
import { TicketExportApiProvider } from "./ticket-export-context";
import { TicketExportControls } from "./ticket-export-controls";
import {
  defaultTicketTableColumns,
  inlineSavedViewSpec,
} from "./saved-view-model";
import { tenantId, userId } from "./ticketing-test-fixtures";

const jobId = "0198c97d-cf4f-7000-8000-000000000093";
const membershipId = "0198c97d-cf4f-7000-8000-000000000015";
const source = {
  source: "inline",
  spec: inlineSavedViewSpec(
    { limit: 30, search: "reviewed scope" },
    defaultTicketTableColumns,
  ),
} as const satisfies TicketExportJobRequest["source"];

afterEach(cleanup);

describe("TicketExportControls", () => {
  it("requires a new review after leaving and returning to the original source", () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: succeededJob(body),
        replayed: false,
      }),
    );
    const api = createApi(request);
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const view = render(controls(api, queryClient, false));
    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    expect(screen.getByRole("button", { name: "Queue export" })).toBeVisible();

    const otherSource = {
      source: "inline",
      spec: inlineSavedViewSpec(
        { limit: 30, search: "another scope" },
        defaultTicketTableColumns,
      ),
    } as const satisfies TicketExportJobRequest["source"];
    view.rerender(controls(api, queryClient, false, otherSource));
    expect(screen.queryByRole("button", { name: "Queue export" })).toBeNull();
    view.rerender(controls(api, queryClient, false));
    expect(screen.queryByRole("button", { name: "Queue export" })).toBeNull();
    expect(request).not.toHaveBeenCalled();
  });

  it("removes a reviewed private-comment request when live authority is revoked", async () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: succeededJob(body),
        replayed: false,
      }),
    );
    const api = createApi(request);
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const view = render(controls(api, queryClient, true));

    fireEvent.change(screen.getByRole("combobox", { name: "Comments" }), {
      target: { value: "public_and_private" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    expect(screen.getByRole("button", { name: "Queue export" })).toBeVisible();

    view.rerender(controls(api, queryClient, false));

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Queue export" })).toBeNull(),
    );
    expect(
      screen.queryByRole("option", { name: "Public and private comments" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]![0].body.comments).toBe("public");
  });

  it("uses a fresh idempotency key for each successful identical export", async () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: succeededJob(body),
        replayed: false,
      }),
    );
    const api = createApi(request);
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(controls(api, queryClient, false));

    async function submitExport(expectedCalls: number): Promise<void> {
      const review = screen.getByRole("button", { name: "Review export" });
      await waitFor(() => expect(review).toBeEnabled());
      fireEvent.click(review);
      fireEvent.click(screen.getByRole("button", { name: "Queue export" }));
      await waitFor(() => expect(request).toHaveBeenCalledTimes(expectedCalls));
    }
    await submitExport(1);
    await submitExport(2);

    expect(request.mock.calls[1]![0].body).toEqual(
      request.mock.calls[0]![0].body,
    );
    expect(request.mock.calls[1]![0].idempotencyKey).not.toBe(
      request.mock.calls[0]![0].idempotencyKey,
    );
  });

  it("reauthorizes the exact artifact before exposing a memory-only download link", async () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: succeededJob(body),
        replayed: false,
      }),
    );
    const downloadUrl =
      "https://storage.invalid/private.csv?X-Amz-Signature=memory-only";
    const download = vi.fn(
      async ({
        expectedArtifact,
      }: Parameters<TicketExportApi["download"]>[0]) => ({
        artifact: expectedArtifact,
        downloadUrl,
        expiresAt: "2099-08-26T18:05:00Z",
      }),
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(controls(createApi(request, download), queryClient, false));

    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));
    const prepare = await screen.findByRole("button", {
      name: "Prepare download",
    });
    fireEvent.click(prepare);

    const link = await screen.findByRole("link", { name: "Download CSV" });
    expect(download).toHaveBeenCalledWith(
      expect.objectContaining({
        csrfToken: "csrf-memory-only-value",
        expectedArtifact: succeededJob({
          comments: "none",
          kind: "alert",
          source,
        }).artifact,
        jobId,
        kind: "alert",
        tenantId,
      }),
    );
    expect(link).toHaveAttribute("href", downloadUrl);
    expect(link).toHaveAttribute("rel", "noreferrer");
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(screen.queryByText(downloadUrl)).toBeNull();

    const originalJob = succeededJob({
      comments: "none",
      kind: "alert",
      source,
    });
    const queryKey = ["ticket-export-job", tenantId, "alert", jobId];
    act(() => {
      queryClient.setQueryData(queryKey, {
        ...originalJob,
        revision: originalJob.revision + 1,
      });
    });
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: "Download CSV" })).toBeNull(),
    );
    act(() => {
      queryClient.setQueryData(queryKey, originalJob);
    });
    await screen.findByText(
      new RegExp(`Revision ${originalJob.revision} · expires`),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Prepare download" }),
      ).toBeEnabled(),
    );
    expect(screen.queryByRole("link", { name: "Download CSV" })).toBeNull();
    expect(download).toHaveBeenCalledTimes(1);
  });

  it("removes any capability and reports a live authorization revocation", async () => {
    const request = vi.fn(
      async ({ body }: Parameters<TicketExportApi["request"]>[0]) => ({
        job: succeededJob(body),
        replayed: false,
      }),
    );
    const download = vi.fn(async () => {
      throw new TicketingApiError(
        "The server denied this export operation.",
        403,
        "forbidden",
      );
    });
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(controls(createApi(request, download), queryClient, false));

    fireEvent.click(screen.getByRole("button", { name: "Review export" }));
    fireEvent.click(screen.getByRole("button", { name: "Queue export" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Prepare download" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The server denied this export operation.",
    );
    expect(screen.queryByRole("link", { name: "Download CSV" })).toBeNull();
  });
});

function controls(
  api: TicketExportApi,
  queryClient: QueryClient,
  allowPrivateComments: boolean,
  selectedSource: TicketExportJobRequest["source"] = source,
): React.JSX.Element {
  return (
    <QueryClientProvider client={queryClient}>
      <TicketExportApiProvider api={api}>
        <TicketExportControls
          allowPrivateComments={allowPrivateComments}
          allowPublicComments
          csrfToken="csrf-memory-only-value"
          kind="alert"
          source={selectedSource}
          tenantId={tenantId}
        />
      </TicketExportApiProvider>
    </QueryClientProvider>
  );
}

function createApi(
  request: TicketExportApi["request"],
  download: TicketExportApi["download"] = async ({ expectedArtifact }) => ({
    artifact: expectedArtifact,
    downloadUrl: "https://storage.invalid/private.csv?signature=test",
    expiresAt: "2099-08-26T18:05:00Z",
  }),
): TicketExportApi {
  const fallback = succeededJob({
    comments: "none",
    kind: "alert",
    source,
  });
  return {
    cancel: async () => ({ job: fallback, replayed: false }),
    download,
    get: async () => fallback,
    request,
  };
}

function succeededJob(body: TicketExportJobRequest): TicketExportJobView {
  return {
    artifact: {
      bytes: 21,
      expiresAt: "2026-08-27T18:00:00Z",
      id: "0198c97d-cf4f-7000-8000-000000000094",
      rows: 1,
      sha256: "e".repeat(64),
    },
    attempts: 1,
    availableAt: "2026-08-26T18:00:00Z",
    comments: body.comments,
    expiresAt: "2026-08-27T18:00:00Z",
    failureCode: "none",
    id: jobId,
    kind: body.kind,
    maximumAttempts: 5,
    maximumBytes: body.maximumBytes ?? 67_108_864,
    maximumRows: body.maximumRows ?? 10_000,
    ownerMembershipId: membershipId,
    query: {
      catalogSha256: "b".repeat(64),
      querySha256: "d".repeat(64),
      source: body.source.source,
    },
    requestedAt: "2026-08-26T18:00:00Z",
    requesterUserId: userId,
    revision: 3,
    state: "succeeded",
    tenantId,
    terminalAt: "2026-08-26T18:01:00Z",
    updatedAt: "2026-08-26T18:01:00Z",
  };
}
