import { afterEach, describe, expect, it, vi } from "vitest";

import {
  alertId,
  tenantId,
  userId,
} from "../ticketing/ticketing-test-fixtures";
import { ticketBulkApi } from "./ticket-bulk-api";

const jobId = "0198c97d-cf4f-7000-8000-000000000091";
const membershipId = "0198c97d-cf4f-7000-8000-000000000015";
const targetSetSha256 = "a".repeat(64);

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketBulkApi", () => {
  it("submits exact version pins with request-integrity headers and validates the receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return bulkResponse({ job: pendingJob(), replayed: false }, 202, {
          Location: `/api/v1/tenants/${tenantId}/ticket-bulk-jobs/${jobId}`,
        });
      }),
    );

    const result = await ticketBulkApi.request({
      body: {
        kind: "alert",
        mutation: { action: "release" },
        selection: {
          source: "explicit",
          targets: [{ expectedVersion: 1, id: alertId }],
        },
      },
      csrfToken: "csrf-memory-only-value",
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
      tenantId,
    });

    expect(result).toMatchObject({
      job: {
        id: jobId,
        progress: { total: 1 },
        selection: { source: "explicit", targetCount: 1, targetSetSha256 },
      },
      replayed: false,
    });
    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    await expect(request!.clone().json()).resolves.toEqual({
      kind: "alert",
      mutation: { action: "release" },
      selection: {
        source: "explicit",
        targets: [{ expectedVersion: 1, id: alertId }],
      },
    });
  });

  it("rejects duplicate explicit targets before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketBulkApi.request({
        body: {
          kind: "alert",
          mutation: { action: "release" },
          selection: {
            source: "explicit",
            targets: [
              { expectedVersion: 1, id: alertId },
              { expectedVersion: 2, id: alertId },
            ],
          },
        },
        csrfToken: "csrf-memory-only-value",
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects unsolicited explicit-target members before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const target = { expectedVersion: 1, id: alertId, tenantId };

    await expect(
      ticketBulkApi.request({
        body: {
          kind: "alert",
          mutation: { action: "release" },
          selection: { source: "explicit", targets: [target] },
        },
        csrfToken: "csrf-memory-only-value",
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects a valid-shaped creation receipt for a different operation", async () => {
    const wrongMutation = pendingJob();
    wrongMutation.mutation = { action: "claim", teamId: membershipId };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        bulkResponse({ job: wrongMutation, replayed: false }, 202, {
          Location: `/api/v1/tenants/${tenantId}/ticket-bulk-jobs/${jobId}`,
        }),
      ),
    );

    await expect(
      ticketBulkApi.request({
        body: {
          kind: "alert",
          mutation: { action: "release" },
          selection: {
            source: "explicit",
            targets: [{ expectedVersion: 1, id: alertId }],
          },
        },
        csrfToken: "csrf-memory-only-value",
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("requires successful projections to be private no-store responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(pendingJob()), {
          headers: { "Content-Type": "application/json" },
          status: 200,
        }),
      ),
    );

    await expect(
      ticketBulkApi.get({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects malformed aggregate progress and unsolicited response members", async () => {
    const malformed = pendingJob();
    malformed.progress.succeeded = 2;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(bulkResponse(malformed)));

    await expect(
      ticketBulkApi.get({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          bulkResponse({ ...pendingJob(), rawDatabaseError: "secret" }),
        ),
    );
    await expect(
      ticketBulkApi.get({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("requires saved-view query receipts to carry the exact immutable pin", async () => {
    const malformed = pendingJob();
    malformed.selection = {
      catalogSha256: "b".repeat(64),
      effectiveSpec: {},
      querySha256: "c".repeat(64),
      querySource: "saved_view",
      source: "query",
      targetCount: 1,
      targetSetSha256,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(bulkResponse(malformed)));

    await expect(
      ticketBulkApi.get({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects out-of-order and unknown per-target result receipts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        bulkResponse({
          items: [
            resultReceipt(2, "succeeded"),
            resultReceipt(1, "internal_failure"),
          ],
        }),
      ),
    );
    await expect(
      ticketBulkApi.listResults({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          bulkResponse({ items: [resultReceipt(1, "database_timeout")] }),
        ),
    );
    await expect(
      ticketBulkApi.listResults({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("preserves bounded Problem Details for cancellation failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        bulkResponse(
          {
            code: "precondition_failed",
            detail: "The job changed on the server.",
            status: 412,
            title: "Precondition failed",
            type: "about:blank",
          },
          412,
          { "Content-Type": "application/problem+json" },
        ),
      ),
    );

    await expect(
      ticketBulkApi.cancel({
        csrfToken: "csrf-memory-only-value",
        expectedRevision: 1,
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
        jobId,
        kind: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({
      code: "precondition_failed",
      message: "The job changed on the server.",
      status: 412,
    });
  });
});

function pendingJob(): {
  activeBatch: boolean;
  availableAt: string;
  expiresAt: string;
  id: string;
  kind: "alert";
  mutation: { action: "release" } | { action: "claim"; teamId: string };
  ownerMembershipId: string;
  progress: Record<string, number>;
  requestedAt: string;
  requesterUserId: string;
  revision: number;
  selection: Record<string, unknown>;
  state: "pending";
  tenantId: string;
  updatedAt: string;
} {
  return {
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
      source: "explicit",
      targetCount: 1,
      targetSetSha256,
      targets: [{ expectedVersion: 1, id: alertId }],
    },
    state: "pending",
    tenantId,
    updatedAt: "2026-08-26T18:00:00Z",
  };
}

function resultReceipt(
  sequence: number,
  result: string,
): Record<string, unknown> {
  return {
    recordedAt: "2026-08-26T18:01:00Z",
    result,
    sequence,
    targetId: alertId,
    targetVersion: 1,
  };
}

function bulkResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ...headers,
    },
    status,
  });
}
