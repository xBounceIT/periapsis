import { afterEach, describe, expect, it, vi } from "vitest";

import { auditReaderApi } from "./audit-api";
import {
  auditTenantId,
  auditVerificationFixture,
  platformAuditEventFixture,
  tenantAuditEventFixture,
} from "./audit-test-fixtures";
import { emptyAuditFilterDraft, normalizeAuditFilters } from "./model";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("auditReaderApi", () => {
  it("uses the generated tenant operation with bounded filters and no-store fetch semantics", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({ items: [tenantAuditEventFixture] });
      }),
    );

    await expect(
      auditReaderApi.listTenant({
        filters: normalizeAuditFilters(
          {
            ...emptyAuditFilterDraft,
            actionPrefix: "case.transition",
            outcome: "success",
            search: "containment",
          },
          "tenant",
        ),
        tenantId: auditTenantId,
      }),
    ).resolves.toMatchObject({ items: [{ sequence: 10 }] });

    const request = requests[0];
    expect(request).toBeDefined();
    const url = new URL(request!.url);
    expect(url.pathname).toBe(`/api/v1/tenants/${auditTenantId}/audit-events`);
    expect(url.searchParams.get("limit")).toBe("50");
    expect(url.searchParams.get("actionPrefix")).toBe("case.transition");
    expect(url.searchParams.get("outcome")).toBe("success");
    expect(url.searchParams.get("search")).toBe("containment");
    expect(request!.cache).toBe("no-store");
  });

  it("rejects cross-scope and nested secret-bearing projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            items: [{ ...tenantAuditEventFixture, tenantId: "another-tenant" }],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...tenantAuditEventFixture,
                metadata: { safe: { client_secret: "must-not-render" } },
              },
            ],
          }),
        ),
    );

    const input = {
      filters: normalizeAuditFilters({ ...emptyAuditFilterDraft }, "tenant"),
      tenantId: auditTenantId,
    };
    await expect(auditReaderApi.listTenant(input)).rejects.toMatchObject({
      code: "projection_mismatch",
    });
    await expect(auditReaderApi.listTenant(input)).rejects.toMatchObject({
      code: "projection_mismatch",
    });
  });

  it("rejects a platform event carrying tenant-only identity fields", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...platformAuditEventFixture,
              actorServiceAccountId: "01991c20-7d5f-7000-8000-000000000009",
            },
          ],
        }),
      ),
    );

    await expect(
      auditReaderApi.listPlatform({
        filters: normalizeAuditFilters(
          { ...emptyAuditFilterDraft },
          "platform",
        ),
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("requires the canonical no-store response protection", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [tenantAuditEventFixture] }, null),
        ),
    );

    await expect(
      auditReaderApi.listTenant({
        filters: normalizeAuditFilters({ ...emptyAuditFilterDraft }, "tenant"),
        tenantId: auditTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("sends CSRF on verification and validates the aggregate invariant", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(auditVerificationFixture);
      }),
    );

    await expect(
      auditReaderApi.verifyTenant({
        csrfToken: "csrf-memory-only",
        tenantId: auditTenantId,
      }),
    ).resolves.toEqual(auditVerificationFixture);
    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
  });

  it("never reflects an untrusted RFC 9457 detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "forbidden",
            detail: "token=protected-material",
            requestId: "01991c20-7d5f-7000-8000-000000000010",
          },
          "no-store",
          403,
        ),
      ),
    );

    await expect(
      auditReaderApi.listPlatform({
        filters: normalizeAuditFilters(
          { ...emptyAuditFilterDraft },
          "platform",
        ),
      }),
    ).rejects.toMatchObject({
      message: "The server denied this audit operation.",
      status: 403,
    });
  });
});

function jsonResponse(
  value: unknown,
  cacheControl: string | null = "no-store",
  status = 200,
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Content-Type": "application/json",
      ...(cacheControl === null ? {} : { "Cache-Control": cacheControl }),
    },
    status,
  });
}
