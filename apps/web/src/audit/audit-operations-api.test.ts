import { afterEach, describe, expect, it, vi } from "vitest";

import { auditOperationsApi } from "./audit-operations-api";
import { auditTenantId } from "./audit-test-fixtures";
import { emptyAuditFilterDraft, normalizeAuditFilters } from "./model";

const exportId = "01991c20-7d5f-7000-8000-000000000021";
const requesterId = "01991c20-7d5f-7000-8000-000000000022";
const holdId = "01991c20-7d5f-7000-8000-000000000024";
const hash = "a".repeat(64);
const filters = normalizeAuditFilters(
  { ...emptyAuditFilterDraft, actionPrefix: "case.transition" },
  "tenant",
);

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("auditOperationsApi", () => {
  it("creates a tenant export with pinned filters and mutation-only headers", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { job: pendingJob(), replayed: false },
          202,
          '"v1"',
        );
      }),
    );

    await expect(
      auditOperationsApi.createExport({
        csrfToken: "csrf-memory-only",
        filters,
        idempotencyKey: "audit-export-key-0001",
        reason: "Incident evidence review",
        retentionSeconds: 86_400,
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).resolves.toMatchObject({ job: { id: exportId }, replayed: false });

    const request = requests[0]!;
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${auditTenantId}/audit-exports`,
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "audit-export-key-0001",
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Incident evidence review",
    );
    expect(await request.json()).toEqual({
      filter: { actionPrefix: "case.transition" },
      retentionSeconds: 86_400,
    });
  });

  it("rejects secret-like reasons before transport and cross-scope projection fields", async () => {
    const fetch = vi.fn().mockResolvedValue(
      jsonResponse(
        {
          job: { ...pendingJob(), objectKey: "tenant/private/raw.jsonl" },
          replayed: false,
        },
        202,
        '"v1"',
      ),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(
      auditOperationsApi.createExport({
        csrfToken: "csrf-memory-only",
        filters,
        idempotencyKey: "audit-export-key-0002",
        reason: "token copied from incident",
        retentionSeconds: 86_400,
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(fetch).not.toHaveBeenCalled();

    await expect(
      auditOperationsApi.createExport({
        csrfToken: "csrf-memory-only",
        filters,
        idempotencyKey: "audit-export-key-0003",
        reason: "Incident evidence review",
        retentionSeconds: 86_400,
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("downloads only the proxied manifest-bound blob and rejects redirect locations", async () => {
    const body = '{"sequence":1}\n';
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          binaryResponse(body, {
            "Content-Disposition": `attachment; filename="audit-tenant-${exportId}.jsonl"`,
          }),
        )
        .mockResolvedValueOnce(
          binaryResponse(body, {
            "Content-Disposition": `attachment; filename="audit-tenant-${exportId}.jsonl"`,
            Location: "https://storage.invalid/raw-object",
          }),
        ),
    );

    await expect(
      auditOperationsApi.downloadExport({
        exportId,
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).resolves.toMatchObject({
      filename: `audit-tenant-${exportId}.jsonl`,
    });
    await expect(
      auditOperationsApi.downloadExport({
        exportId,
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("projects the zero retention anchor and binds legal-hold release revision", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementationOnce(async () =>
          jsonResponse(retentionState(), 200, '"v1"'),
        )
        .mockImplementationOnce(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return jsonResponse(
            {
              hold: {
                id: holdId,
                placedAt: "2026-09-01T10:00:00Z",
                releasedAt: "2026-09-01T10:01:00Z",
                revision: 2,
                state: "released",
              },
              replayed: false,
            },
            200,
            '"v2"',
          );
        }),
    );

    await expect(
      auditOperationsApi.getRetention({
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).resolves.toMatchObject({ anchor: { retainedThroughSequence: 0 } });
    await expect(
      auditOperationsApi.releaseLegalHold({
        csrfToken: "csrf-memory-only",
        expectedRevision: 1,
        holdId,
        idempotencyKey: "audit-release-key-01",
        reason: "Investigation is complete",
        scope: { kind: "tenant", tenantId: auditTenantId },
      }),
    ).resolves.toMatchObject({ hold: { state: "released" } });

    expect(requests[0]?.headers.get("If-Match")).toBe('"v1"');
    expect(await requests[0]!.json()).toEqual({ expectedRevision: 1 });
  });
});

function pendingJob() {
  return {
    attempts: 0,
    availableAt: "2026-09-01T10:00:00Z",
    expiresAt: "2026-09-02T10:00:00Z",
    failureCode: "none",
    filter: { actionPrefix: "case.transition" },
    filterSha256: hash,
    format: "jsonl",
    id: exportId,
    maximumAttempts: 3,
    projectionVersion: 1,
    requestedAt: "2026-09-01T10:00:00Z",
    requesterUserId: requesterId,
    revision: 1,
    state: "pending",
    stream: "tenant",
    tenantId: auditTenantId,
    updatedAt: "2026-09-01T10:00:00Z",
  };
}

function retentionState() {
  return {
    anchor: {
      retainedThroughHash: "0".repeat(64),
      retainedThroughSequence: 0,
      revision: 1,
      updatedAt: "2026-09-01T10:00:00Z",
    },
    policy: {
      retentionDays: 365,
      revision: 1,
      updatedAt: "2026-09-01T10:00:00Z",
    },
    stream: "tenant",
    tenantId: auditTenantId,
  };
}

function jsonResponse(value: unknown, status: number, etag: string): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ETag: etag,
    },
    status,
  });
}

function binaryResponse(
  body: string,
  extraHeaders: Record<string, string>,
): Response {
  return new Response(body, {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Length": String(new TextEncoder().encode(body).length),
      "Content-Type": "application/x-ndjson",
      ...extraHeaders,
    },
  });
}
