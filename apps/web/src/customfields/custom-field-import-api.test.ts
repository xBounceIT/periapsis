import { afterEach, describe, expect, it, vi } from "vitest";

import { customFieldImportApi } from "./custom-field-import-api";
import type {
  CustomFieldImportJobView,
  CustomFieldImportRequest,
} from "./custom-field-import-model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const jobId = "0198c97d-cf4f-7000-8000-000000000002";
const targetId = "0198c97d-cf4f-7000-8000-000000000003";
const idempotencyKey = "custom-field-import-attempt-0001";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("custom-field import API", () => {
  it("submits the reviewed request with missing, null, and empty values intact", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = canonicalRequest(input, init);
      const body: unknown = await request.clone().json();
      expect(request.method).toBe("POST");
      expect(request.headers.get("Idempotency-Key")).toBe(idempotencyKey);
      expect(request.headers.get("X-CSRF-Token")).toBe("csrf-token");
      expect(body).toEqual(requestFixture());
      return jsonResponse({ job: jobFixture(), replayed: false }, 202, {
        ETag: '"v1"',
        Location: `/api/v1/tenants/${tenantId}/custom-field-imports/${jobId}`,
        "X-Idempotent-Replay": "false",
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await customFieldImportApi.request({
      body: requestFixture(),
      csrfToken: "csrf-token",
      idempotencyKey,
      tenantId,
    });

    expect(result.job.id).toBe(jobId);
    expect(result.etag).toBe('"v1"');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("binds cancellation to both the body revision and strong If-Match", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const request = canonicalRequest(input, init);
      expect(request.method).toBe("POST");
      expect(request.headers.get("If-Match")).toBe('"v1"');
      expect(await request.clone().json()).toEqual({
        objectType: "alert",
        expectedRevision: 1,
      });
      return jsonResponse(
        {
          job: jobFixture({
            state: "cancelled",
            revision: 2,
            terminalAt: "2026-09-03T14:00:01Z",
            updatedAt: "2026-09-03T14:00:01Z",
            progress: {
              ...jobFixture().progress,
              processed: 1,
              cancelled: 1,
            },
          }),
          replayed: false,
        },
        200,
        { ETag: '"v2"', "X-Idempotent-Replay": "false" },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await customFieldImportApi.cancel({
      csrfToken: "csrf-token",
      expectedRevision: 1,
      idempotencyKey,
      jobId,
      objectType: "alert",
      tenantId,
    });

    expect(result.job.state).toBe("cancelled");
    expect(result.etag).toBe('"v2"');
  });

  it("projects strictly ordered, field-specific durable results", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        const request = canonicalRequest(input, init);
        expect(new URL(request.url).searchParams.get("after")).toBe("4");
        expect(new URL(request.url).searchParams.get("pageSize")).toBe("1");
        return jsonResponse({
          items: [
            {
              sequence: 5,
              targetId,
              expectedVersion: 7,
              outcome: "validation_failed",
              resultingVersion: 0,
              fieldErrors: [{ field: "triage.owner", code: "required" }],
              recordedAt: "2026-09-03T14:00:01Z",
            },
          ],
          nextAfter: 5,
        });
      }),
    );

    const page = await customFieldImportApi.listResults({
      after: 4,
      jobId,
      objectType: "alert",
      pageSize: 1,
      tenantId,
    });

    expect(page.items[0]).toEqual(
      expect.objectContaining({
        outcome: "validation_failed",
        fieldErrors: [{ field: "triage.owner", code: "required" }],
      }),
    );
    expect(page.nextAfter).toBe(5);
  });

  it("rejects a response whose ETag does not bind its revision", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse(jobFixture(), 200, { ETag: '"v2"' }),
      ),
    );

    await expect(
      customFieldImportApi.get({ jobId, objectType: "alert", tenantId }),
    ).rejects.toMatchObject({
      code: "projection_mismatch",
    });
  });

  it("rejects a caller-private response that is not marked private no-store", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse(jobFixture(), 200, {
          "Cache-Control": "no-store",
          ETag: '"v1"',
        }),
      ),
    );

    await expect(
      customFieldImportApi.get({ jobId, objectType: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("does not display a cacheable error body or send an oversized CSRF value", async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            detail: "tenant-private definition value",
            status: 403,
            title: "Forbidden",
          }),
          {
            headers: { "Content-Type": "application/problem+json" },
            status: 403,
          },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      customFieldImportApi.get({ jobId, objectType: "alert", tenantId }),
    ).rejects.toMatchObject({
      code: "projection_mismatch",
      message:
        "The custom-field import error response was not safe to display.",
    });
    await expect(
      customFieldImportApi.request({
        body: requestFixture(),
        csrfToken: "x".repeat(4_097),
        idempotencyKey,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects a mutation whose replay header does not bind its body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse({ job: jobFixture(), replayed: false }, 202, {
          ETag: '"v1"',
          Location: `/api/v1/tenants/${tenantId}/custom-field-imports/${jobId}`,
          "X-Idempotent-Replay": "true",
        }),
      ),
    );

    await expect(
      customFieldImportApi.request({
        body: requestFixture(),
        csrfToken: "csrf-token",
        idempotencyKey,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects unknown response members instead of displaying unbound data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse({ ...jobFixture(), manifest: { values: "secret" } }, 200, {
          ETag: '"v1"',
        }),
      ),
    );

    await expect(
      customFieldImportApi.get({ jobId, objectType: "alert", tenantId }),
    ).rejects.toMatchObject({
      code: "projection_mismatch",
    });
  });

  it("accepts an expired terminal projection only when every row is classified", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse(
          jobFixture({
            state: "expired",
            revision: 2,
            progress: {
              ...jobFixture().progress,
              processed: 1,
              expired: 1,
            },
            terminalAt: "2026-09-04T14:00:00Z",
            updatedAt: "2026-09-04T14:00:00Z",
          }),
          200,
          { ETag: '"v2"' },
        ),
      ),
    );

    await expect(
      customFieldImportApi.get({ jobId, objectType: "alert", tenantId }),
    ).resolves.toMatchObject({
      state: "expired",
      progress: { processed: 1, expired: 1 },
    });
  });

  it("rejects result pages with gaps", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse({
          items: [
            {
              sequence: 2,
              targetId,
              expectedVersion: 7,
              outcome: "validation_failed",
              resultingVersion: 9,
              fieldErrors: [],
              recordedAt: "2026-09-03T14:00:01Z",
            },
          ],
        }),
      ),
    );

    await expect(
      customFieldImportApi.listResults({
        jobId,
        objectType: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects result pages with invalid version/error relationships", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse({
          items: [
            {
              sequence: 1,
              targetId,
              expectedVersion: 7,
              outcome: "validation_failed",
              resultingVersion: 9,
              fieldErrors: [],
              recordedAt: "2026-09-03T14:00:01Z",
            },
          ],
        }),
      ),
    );

    await expect(
      customFieldImportApi.listResults({
        jobId,
        objectType: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a continuation cursor on a short result page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        jsonResponse({
          items: [
            {
              sequence: 1,
              targetId,
              expectedVersion: 7,
              outcome: "no_change",
              resultingVersion: 7,
              fieldErrors: [],
              recordedAt: "2026-09-03T14:00:01Z",
            },
          ],
          nextAfter: 1,
        }),
      ),
    );

    await expect(
      customFieldImportApi.listResults({
        jobId,
        objectType: "alert",
        pageSize: 100,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });
});

function requestFixture(): CustomFieldImportRequest {
  return {
    objectType: "alert",
    mode: "dry_run",
    retentionSeconds: 86_400,
    rows: [
      {
        targetId,
        expectedVersion: 7,
        fields: [
          { key: "preserved" },
          { key: "cleared", value: null },
          { key: "empty", value: "" },
        ],
      },
    ],
  };
}

function jobFixture(
  overrides: Partial<CustomFieldImportJobView> = {},
): CustomFieldImportJobView {
  return {
    id: jobId,
    tenantId,
    requesterUserId: "0198c97d-cf4f-7000-8000-000000000004",
    ownerMembershipId: "0198c97d-cf4f-7000-8000-000000000005",
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

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function canonicalRequest(
  input: RequestInfo | URL,
  init?: RequestInit,
): Request {
  return new Request(input, init);
}
