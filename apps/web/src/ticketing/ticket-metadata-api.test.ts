import type {
  AlertMetadataReplaceRequest,
  CaseMetadataReplaceRequest,
} from "@periapsis/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  TicketMetadataApiError,
  ticketMetadataApi,
} from "./ticket-metadata-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const alertId = "0198c97d-cf4f-7000-8000-000000000002";
const caseId = "0198c97d-cf4f-7000-8000-000000000003";
const alertBody: AlertMetadataReplaceRequest = {
  category: "endpoint",
  classification: null,
  customerVisible: false,
  description: "Confirmed endpoint activity.",
  priority: "high",
  severity: "critical",
  tags: ["confirmed", "endpoint"],
  title: "Endpoint activity",
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketMetadataApi", () => {
  it("binds an Alert replacement to exact headers, body, and no-store result", async () => {
    let request: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        request = input;
        return metadataResponse(
          {
            id: alertId,
            ...alertBody,
            updatedAt: "2026-08-31T08:30:00Z",
            version: 5,
          },
          5,
        );
      }),
    );

    const result = await ticketMetadataApi.replace({
      body: alertBody,
      csrfToken: "csrf-memory-only",
      etag: '"v4"',
      expectedVersion: 4,
      idempotencyKey: "metadata-alert-replace-1",
      kind: "alert",
      resourceId: alertId,
      tenantId,
    });

    expect(result).toEqual({
      etag: '"v5"',
      value: expect.objectContaining({
        id: alertId,
        kind: "alert",
        classification: null,
        version: 5,
      }),
    });
    expect(request?.method).toBe("PUT");
    expect(request?.cache).toBe("no-store");
    expect(request?.headers.get("If-Match")).toBe('"v4"');
    expect(request?.headers.get("Idempotency-Key")).toBe(
      "metadata-alert-replace-1",
    );
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(request?.clone().json()).resolves.toEqual(alertBody);
  });

  it("keeps the Case summary and explicit classification in the exact projection", async () => {
    const body: CaseMetadataReplaceRequest = {
      ...alertBody,
      classification: "restricted",
      summary: "Contained before lateral movement.",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        metadataResponse(
          {
            id: caseId,
            ...body,
            updatedAt: "2026-08-31T08:31:00Z",
            version: 2,
          },
          2,
        ),
      ),
    );

    await expect(
      ticketMetadataApi.replace({
        body,
        csrfToken: "csrf-memory-only",
        etag: '"v1"',
        expectedVersion: 1,
        idempotencyKey: "metadata-case-replace-1",
        kind: "case",
        resourceId: caseId,
        tenantId,
      }),
    ).resolves.toMatchObject({
      value: {
        kind: "case",
        summary: "Contained before lateral movement.",
        classification: "restricted",
      },
    });
  });

  it("rejects cacheable, extra-field, wrong-resource, and stale-version responses", async () => {
    const variants = [
      new Response(
        JSON.stringify({
          id: alertId,
          ...alertBody,
          updatedAt: "2026-08-31T08:30:00Z",
          version: 5,
        }),
        {
          headers: { "Cache-Control": "private", ETag: '"v5"' },
          status: 200,
        },
      ),
      metadataResponse(
        {
          id: alertId,
          ...alertBody,
          secret: "must-not-enter-the-projection",
          updatedAt: "2026-08-31T08:30:00Z",
          version: 5,
        },
        5,
      ),
      metadataResponse(
        {
          id: caseId,
          ...alertBody,
          updatedAt: "2026-08-31T08:30:00Z",
          version: 5,
        },
        5,
      ),
      metadataResponse(
        {
          id: alertId,
          ...alertBody,
          updatedAt: "2026-08-31T08:30:00Z",
          version: 6,
        },
        6,
      ),
    ];
    const fetch = vi.fn();
    for (const response of variants) fetch.mockResolvedValueOnce(response);
    vi.stubGlobal("fetch", fetch);

    await Promise.all(
      variants.map(() =>
        expect(
          ticketMetadataApi.replace({
            body: alertBody,
            csrfToken: "csrf-memory-only",
            etag: '"v4"',
            expectedVersion: 4,
            idempotencyKey: "metadata-alert-replace-1",
            kind: "alert",
            resourceId: alertId,
            tenantId,
          }),
        ).rejects.toBeInstanceOf(TicketMetadataApiError),
      ),
    );
  });

  it("returns a bounded conflict message and never exposes server detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ detail: "sensitive server-side value" }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/problem+json",
            },
            status: 412,
          },
        ),
      ),
    );

    await expect(
      ticketMetadataApi.replace({
        body: alertBody,
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "metadata-alert-replace-1",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({
      message:
        "This ticket changed. Reload the latest snapshot before retrying.",
      status: 412,
    });
  });

  it("rejects non-canonical payloads before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketMetadataApi.replace({
        body: { ...alertBody, tags: ["endpoint", "confirmed"] },
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "metadata-alert-replace-1",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toBeInstanceOf(Error);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("allows CR, LF, and TAB only in multiline metadata", async () => {
    const fetch = vi.fn().mockResolvedValue(
      metadataResponse(
        {
          id: alertId,
          ...alertBody,
          description: "first\r\nsecond\tcolumn",
          updatedAt: "2026-08-31T08:30:00Z",
          version: 5,
        },
        5,
      ),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketMetadataApi.replace({
        body: { ...alertBody, description: "first\r\nsecond\tcolumn" },
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "metadata-alert-replace-1",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).resolves.toMatchObject({ value: { version: 5 } });

    await expect(
      ticketMetadataApi.replace({
        body: { ...alertBody, title: "line\nbreak" },
        csrfToken: "csrf-memory-only",
        etag: '"v4"',
        expectedVersion: 4,
        idempotencyKey: "metadata-alert-replace-2",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toBeInstanceOf(Error);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

function metadataResponse(
  value: unknown,
  version: number,
  status = 200,
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ETag: `"v${version}"`,
    },
    status,
  });
}
