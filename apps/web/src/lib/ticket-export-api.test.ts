import type {
  SavedTicketViewSpecInput,
  TicketExportJobRequest,
} from "@periapsis/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  membershipId,
  savedAlertView,
  savedViewId,
  tenantId,
  userId,
} from "../ticketing/ticketing-test-fixtures";
import { ticketExportApi } from "./ticket-export-api";

const jobId = "0198c97d-cf4f-7000-8000-000000000081";
const artifactId = "0198c97d-cf4f-7000-8000-000000000082";
const querySha256 = "c".repeat(64);
const catalogSha256 = "d".repeat(64);
const artifactSha256 = "e".repeat(64);
const idempotencyKey = "0198c97d-cf4f-7000-8000-000000000099";
const csrfToken = "csrf-memory-only-value";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketExportApi", () => {
  it("submits an exact saved-view pin and returns a PII-minimized receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return exportResponse(
          { job: pendingSavedViewJob(), replayed: false },
          202,
          { Location: exportLocation() },
        );
      }),
    );

    const result = await ticketExportApi.request({
      body: {
        comments: "public_and_private",
        kind: "alert",
        maximumBytes: 1_048_576,
        maximumRows: 2_000,
        retentionSeconds: 86_400,
        source: {
          savedView: {
            expectedRevision: savedAlertView.revision,
            expectedSpecSha256: savedAlertView.specSha256,
            id: savedViewId,
          },
          source: "saved_view",
        },
      },
      csrfToken,
      idempotencyKey,
      tenantId,
    });

    expect(result).toEqual({
      job: expect.objectContaining({
        id: jobId,
        query: {
          catalogSha256,
          querySha256,
          savedView: {
            id: savedViewId,
            ownerMembershipId: membershipId,
            revision: savedAlertView.revision,
            specSha256: querySha256,
          },
          source: "saved_view",
        },
      }),
      replayed: false,
    });
    expect(result.job.query).not.toHaveProperty("effectiveSpec");
    expect(requests).toHaveLength(1);
    expect(requests[0]!.headers.get("Idempotency-Key")).toBe(idempotencyKey);
    expect(requests[0]!.headers.get("X-CSRF-Token")).toBe(csrfToken);
    await expect(requests[0]!.clone().json()).resolves.toMatchObject({
      comments: "public_and_private",
      kind: "alert",
      source: {
        savedView: {
          expectedRevision: 3,
          expectedSpecSha256: querySha256,
          id: savedViewId,
        },
        source: "saved_view",
      },
    });
  });

  it("validates inline snapshots and rejects ambiguous or unbounded input before fetch", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const audienceInjection = {
      ...savedViewRequest(),
      audience: "operator",
    };
    const cases: TicketExportJobRequest[] = [
      {
        comments: "public",
        kind: "alert",
        source: {
          savedView: {
            expectedRevision: 3,
            expectedSpecSha256: querySha256,
            id: savedViewId,
          },
          source: "inline",
          spec: inlineSpec(),
        },
      },
      {
        comments: "public",
        kind: "alert",
        maximumRows: 100_001,
        source: { source: "inline", spec: inlineSpec() },
      },
      audienceInjection,
      {
        comments: "public",
        kind: "alert",
        source: {
          source: "inline",
          spec: {
            ...inlineSpec(),
            columns: [
              {
                coreKey: "state",
                pin: "none",
                source: "core",
                visible: true,
              },
            ],
          },
        },
      },
    ];

    await Promise.all(
      cases.map((body) =>
        expect(
          ticketExportApi.request({
            body,
            csrfToken,
            idempotencyKey,
            tenantId,
          }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts canonical hyphenated state keys and binds an inline request receipt", async () => {
    const spec = inlineSpec();
    spec.filters.states = ["waiting-customer"];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse({ job: pendingInlineJob(), replayed: false }, 202, {
          Location: exportLocation(),
        }),
      ),
    );

    const result = await ticketExportApi.request({
      body: {
        comments: "public",
        kind: "alert",
        source: { source: "inline", spec },
      },
      csrfToken,
      idempotencyKey,
      tenantId,
    });

    expect(result.job).toMatchObject({
      maximumBytes: 67_108_864,
      maximumRows: 10_000,
      query: { source: "inline" },
      state: "pending",
    });
  });

  it("accepts an empty successful CSV and rejects worker or object details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(exportResponse(succeededInlineJob())),
    );

    const result = await ticketExportApi.get({
      jobId,
      kind: "alert",
      tenantId,
    });

    expect(result.artifact).toMatchObject({
      bytes: 21,
      id: artifactId,
      rows: 0,
      sha256: artifactSha256,
    });
    expect(result).not.toHaveProperty("lease");
    expect(result).not.toHaveProperty("fence");
    expect(result.artifact).not.toHaveProperty("objectKey");
    expect(result.artifact).not.toHaveProperty("downloadUrl");

    const unsafe = [
      { ...pendingSavedViewJob(), fence: "secret-fence" },
      { ...pendingSavedViewJob(), tenantId: savedViewId },
      { ...pendingSavedViewJob(), artifact: succeededInlineJob().artifact },
      {
        ...pendingSavedViewJob(),
        query: {
          ...pendingSavedViewJob().query,
          savedView: {
            ...pendingSavedViewJob().query.savedView,
            ownerMembershipId: userId,
          },
        },
      },
    ];
    const unsafeFetch = vi.fn();
    for (const value of unsafe) {
      unsafeFetch.mockResolvedValueOnce(exportResponse(value));
    }
    vi.stubGlobal("fetch", unsafeFetch);
    await Promise.all(
      unsafe.map(() =>
        expect(
          ticketExportApi.get({ jobId, kind: "alert", tenantId }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("binds cancellation to the exact owner coordinates, revision, CSRF, and retry key", async () => {
    const requests: Request[] = [];
    const controller = new AbortController();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return exportResponse({
          job: cancellationRequestedJob(),
          replayed: true,
        });
      }),
    );

    const result = await ticketExportApi.cancel({
      csrfToken,
      expectedRevision: 2,
      idempotencyKey,
      jobId,
      kind: "alert",
      signal: controller.signal,
      tenantId,
    });

    expect(result).toMatchObject({
      job: { id: jobId, revision: 3, state: "cancellation_requested" },
      replayed: true,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.signal.aborted).toBe(false);
    controller.abort();
    expect(requests[0]!.signal.aborted).toBe(true);
    expect(requests[0]!.headers.get("Idempotency-Key")).toBe(idempotencyKey);
    expect(requests[0]!.headers.get("X-CSRF-Token")).toBe(csrfToken);
    await expect(requests[0]!.clone().json()).resolves.toEqual({
      expectedRevision: 2,
      kind: "alert",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse({
          job: { ...cancellationRequestedJob(), revision: 4 },
          replayed: false,
        }),
      ),
    );
    await expect(
      ticketExportApi.cancel({
        csrfToken,
        expectedRevision: 2,
        idempotencyKey,
        jobId,
        kind: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("reauthorizes an exact artifact and keeps the signed capability memory-only", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-26T18:00:00Z"));
    const requests: Request[] = [];
    const artifact = succeededInlineJob().artifact;
    const downloadUrl =
      "https://storage.invalid/private.csv?X-Amz-Signature=memory-only";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return exportResponse({
          artifact,
          downloadUrl,
          expiresAt: "2026-08-26T18:05:00Z",
        });
      }),
    );

    const result = await ticketExportApi.download({
      csrfToken,
      expectedArtifact: artifact,
      jobId,
      kind: "alert",
      tenantId,
    });

    expect(result).toEqual({
      artifact,
      downloadUrl,
      expiresAt: "2026-08-26T18:05:00Z",
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.method).toBe("POST");
    expect(requests[0]!.headers.get("X-CSRF-Token")).toBe(csrfToken);
    expect(requests[0]!.headers.has("Idempotency-Key")).toBe(false);
    expect(new URL(requests[0]!.url).searchParams.get("kind")).toBe("alert");
    await expect(requests[0]!.clone().text()).resolves.toBe("");
  });

  it("rejects drifted, overlong, expired, or unsafe download capabilities", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-26T18:00:00Z"));
    const artifact = succeededInlineJob().artifact;
    const valid = {
      artifact,
      downloadUrl: "https://storage.invalid/private.csv?signature=secret",
      expiresAt: "2026-08-26T18:05:00Z",
    };
    const unsafe = [
      { ...valid, artifact: { ...artifact, id: savedViewId } },
      { ...valid, expiresAt: "2026-08-26T18:05:01Z" },
      { ...valid, expiresAt: "2026-08-26T17:59:59Z" },
      {
        ...valid,
        downloadUrl: "https://user:secret@storage.invalid/private.csv",
      },
      { ...valid, downloadUrl: "javascript:alert(1)" },
      { ...valid, downloadUrl: "https://storage.invalid/private.csv#secret" },
    ];
    const fetch = vi.fn();
    for (const value of unsafe) {
      fetch.mockResolvedValueOnce(exportResponse(value));
    }
    vi.stubGlobal("fetch", fetch);

    await Promise.all(
      unsafe.map(() =>
        expect(
          ticketExportApi.download({
            csrfToken,
            expectedArtifact: artifact,
            jobId,
            kind: "alert",
            tenantId,
          }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("rejects non-private success responses and non-canonical creation locations", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse(pendingSavedViewJob(), 200, {
          "Cache-Control": "private",
        }),
      ),
    );
    await expect(
      ticketExportApi.get({ jobId, kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse(
          { job: pendingSavedViewDefaultJob(), replayed: false },
          202,
          {
            Location: `/api/v1/tenants/${tenantId}/ticket-exports/${savedViewId}`,
          },
        ),
      ),
    );
    await expect(
      ticketExportApi.request({
        body: savedViewRequest(),
        csrfToken,
        idempotencyKey,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse({ job: pendingInlineJob(), replayed: false }, 202, {
          Location: exportLocation(),
        }),
      ),
    );
    await expect(
      ticketExportApi.request({
        body: savedViewRequest(),
        csrfToken,
        idempotencyKey,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("maps RFC 9457 failures without reflecting provider or query detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        exportResponse(
          {
            code: "service_unavailable",
            detail: "s3://private-bucket/customer-name and raw database error",
            requestId: "request-safe-17",
            status: 503,
            title: "Storage exploded for customer@example.test",
            type: "about:blank",
          },
          503,
          { "Content-Type": "application/problem+json" },
        ),
      ),
    );

    let thrown: unknown;
    try {
      await ticketExportApi.get({ jobId, kind: "alert", tenantId });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({
      code: "service_unavailable",
      message: "The asynchronous export service is unavailable.",
      requestId: "request-safe-17",
      status: 503,
    });
    expect(String(thrown)).not.toContain("private-bucket");
    expect(String(thrown)).not.toContain("customer@example.test");
  });
});

function savedViewRequest() {
  return {
    comments: "public" as const,
    kind: "alert" as const,
    source: {
      savedView: {
        expectedRevision: savedAlertView.revision,
        expectedSpecSha256: querySha256,
        id: savedViewId,
      },
      source: "saved_view" as const,
    },
  };
}

function inlineSpec(): SavedTicketViewSpecInput {
  return {
    columns: [
      {
        coreKey: "ticket",
        pin: "start",
        source: "core",
        visible: true,
        width: 340,
      },
    ],
    filters: {
      custom: [],
      priorities: ["urgent"],
      queue: "my_operator_teams",
      severities: ["high"],
      states: ["new"],
    },
    sort: {
      coreKey: "updated_at",
      direction: "desc",
      nulls: "last",
      source: "core",
    },
  };
}

function pendingSavedViewJob() {
  return {
    attempts: 0,
    audience: "operator",
    availableAt: "2026-08-26T18:00:00Z",
    comments: "public_and_private",
    expiresAt: "2026-08-27T18:00:00Z",
    failureCode: "none",
    format: "csv",
    id: jobId,
    kind: "alert",
    maximumAttempts: 5,
    maximumBytes: 1_048_576,
    maximumRows: 2_000,
    ownerMembershipId: membershipId,
    projectionVersion: 1,
    query: {
      catalogSha256,
      effectiveSpec: savedAlertView.spec,
      querySha256,
      savedView: {
        id: savedViewId,
        ownerMembershipId: membershipId,
        revision: savedAlertView.revision,
        specSha256: querySha256,
      },
      source: "saved_view",
    },
    requestedAt: "2026-08-26T18:00:00Z",
    requesterUserId: userId,
    revision: 1,
    state: "pending",
    tenantId,
    updatedAt: "2026-08-26T18:00:00Z",
  };
}

function succeededInlineJob() {
  return {
    ...pendingSavedViewJob(),
    artifact: {
      bytes: 21,
      expiresAt: "2026-08-27T18:00:00Z",
      id: artifactId,
      rows: 0,
      sha256: artifactSha256,
    },
    attempts: 1,
    query: {
      catalogSha256,
      effectiveSpec: savedAlertView.spec,
      querySha256,
      source: "inline",
    },
    revision: 3,
    state: "succeeded",
    terminalAt: "2026-08-26T18:01:00Z",
    updatedAt: "2026-08-26T18:01:00Z",
  };
}

function pendingInlineJob() {
  return {
    ...pendingSavedViewJob(),
    comments: "public",
    maximumBytes: 67_108_864,
    maximumRows: 10_000,
    query: {
      catalogSha256,
      effectiveSpec: savedAlertView.spec,
      querySha256,
      source: "inline",
    },
  };
}

function pendingSavedViewDefaultJob() {
  return {
    ...pendingSavedViewJob(),
    comments: "public",
    maximumBytes: 67_108_864,
    maximumRows: 10_000,
  };
}

function cancellationRequestedJob() {
  return {
    ...pendingSavedViewJob(),
    attempts: 1,
    revision: 3,
    state: "cancellation_requested",
    updatedAt: "2026-08-26T18:01:00Z",
  };
}

function exportLocation(): string {
  return `/api/v1/tenants/${tenantId}/ticket-exports/${jobId}`;
}

function exportResponse(
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
