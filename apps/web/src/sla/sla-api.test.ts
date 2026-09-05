import { afterEach, describe, expect, it, vi } from "vitest";

import type { SlaOverrideRequest } from "./model";
import { slaAdminApi } from "./sla-api";
import {
  calendarFixture,
  slaCalendarId,
  slaInstanceId,
  slaMetricInstanceId,
  slaObjectId,
  slaTenantId,
  ticketSlaFixture,
} from "./sla-test-fixtures";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("slaAdminApi", () => {
  it("uses the generated catalog operation and validates the explicit tenant page", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({
          tenantId: slaTenantId,
          items: [calendarFixture],
        });
      }),
    );

    await expect(
      slaAdminApi.listCalendars({ tenantId: slaTenantId }),
    ).resolves.toEqual({ items: [calendarFixture] });
    const request = requests[0];
    expect(request).toBeDefined();
    expect(new URL(request!.url).pathname).toBe(
      `/api/v1/tenants/${slaTenantId}/business-calendars`,
    );
    expect(new URL(request!.url).searchParams.get("limit")).toBe("100");
    expect(request!.cache).toBe("no-store");
  });

  it("fails closed on a cross-tenant catalog envelope", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          tenantId: "01991c20-7d5f-7000-8000-000000000099",
          items: [calendarFixture],
        }),
      ),
    );

    await expect(
      slaAdminApi.listCalendars({ tenantId: slaTenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("binds operator and customer SLA reads to separate generated routes", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        const customer = new URL(input.url).pathname.includes("/portal/");
        return jsonResponse(
          customer
            ? {
                audience: "customer",
                tenantId: slaTenantId,
                objectType: "case",
                objectId: slaObjectId,
                projectedAt: ticketSlaFixture.projectedAt,
                metrics: [],
                columns: [],
              }
            : ticketSlaFixture,
          customer ? '"sla-customer-current"' : '"sla-object-v3"',
        );
      }),
    );

    await expect(
      slaAdminApi.getTicketSla({
        audience: "customer",
        kind: "case",
        objectId: slaObjectId,
        tenantId: slaTenantId,
      }),
    ).resolves.toMatchObject({ value: { audience: "customer" } });
    await expect(
      slaAdminApi.getTicketSla({
        audience: "operator",
        kind: "case",
        objectId: slaObjectId,
        tenantId: slaTenantId,
      }),
    ).resolves.toMatchObject({ value: { audience: "operator" } });

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/api/v1/tenants/${slaTenantId}/portal/cases/${slaObjectId}/sla`,
      `/api/v1/tenants/${slaTenantId}/cases/${slaObjectId}/sla`,
    ]);
    expect(requests.every((request) => request.cache === "no-store")).toBe(
      true,
    );
  });

  it("rejects unknown SLA route intent instead of falling back", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const invalidAudience = {
      audience: "operator",
      kind: "case",
      objectId: slaObjectId,
      tenantId: slaTenantId,
    } as const;
    Object.defineProperty(invalidAudience, "audience", { value: "future" });

    await expect(slaAdminApi.getTicketSla(invalidAudience)).rejects.toThrow(
      "A valid SLA route intent is required.",
    );
    const invalidKind = {
      audience: "customer",
      kind: "case",
      objectId: slaObjectId,
      tenantId: slaTenantId,
    } as const;
    Object.defineProperty(invalidKind, "kind", { value: "task" });
    await expect(slaAdminApi.getTicketSla(invalidKind)).rejects.toThrow(
      "A valid SLA route intent is required.",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("binds create to CSRF and retry identity and requires the response ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(calendarFixture, '"sla-calendar-v1"', 201);
      }),
    );

    const result = await slaAdminApi.createCalendar({
      body: {
        id: calendarFixture.id,
        key: calendarFixture.key,
        label: calendarFixture.label,
        timezone: calendarFixture.timezone,
        weeklySchedules: calendarFixture.weeklySchedules,
        exceptions: calendarFixture.exceptions,
      },
      csrfToken: "csrf-memory-only",
      idempotencyKey:
        "sla-calendar-create-01991c20-7d5f-7000-8000-000000000099",
      tenantId: slaTenantId,
    });

    expect(result.etag).toBe('"sla-calendar-v1"');
    const request = requests[0];
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request?.headers.get("Idempotency-Key")).toContain(
      "sla-calendar-create",
    );
    await expect(request?.json()).resolves.toMatchObject({
      id: slaCalendarId,
      timezone: "Europe/Rome",
    });
  });

  it("archives with If-Match and verifies the representation-bound follow-up", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        if (input.method === "DELETE") {
          return noContentResponse('"sla-calendar-v2"');
        }
        return jsonResponse(
          {
            ...calendarFixture,
            archivedAt: "2026-08-26T09:00:00Z",
            resourceVersion: 2,
          },
          '"sla-calendar-v2"',
        );
      }),
    );

    await expect(
      slaAdminApi.archiveCalendar({
        csrfToken: "csrf-memory-only",
        etag: '"sla-calendar-v1"',
        id: slaCalendarId,
        idempotencyKey:
          "sla-calendar-archive-01991c20-7d5f-7000-8000-000000000099",
        reason: "Calendar retired after approved migration",
        tenantId: slaTenantId,
      }),
    ).resolves.toMatchObject({ value: { archivedAt: expect.any(String) } });
    expect(requests).toHaveLength(2);
    expect(requests[0]?.headers.get("If-Match")).toBe('"sla-calendar-v1"');
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
  });

  it("posts an exact override then binds the receipt to the current projection", async () => {
    const requests: Request[] = [];
    const body: SlaOverrideRequest = {
      overrideId: "01991c20-7d5f-7000-8000-00000000000c",
      kind: "extend",
      reason: "Customer approved a fifteen minute extension",
      slaInstanceId,
      metricInstanceId: slaMetricInstanceId,
      expectedMetricVersion: 2,
      extensionMicros: 900_000_000,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        if (input.method === "POST") {
          return jsonResponse(
            {
              tenantId: slaTenantId,
              objectType: "case",
              objectId: slaObjectId,
              overrideId: body.overrideId,
              outcome: "metric_updated",
              kind: "extend",
              slaInstanceId,
              metricInstanceId: slaMetricInstanceId,
              previousVersion: 2,
              currentVersion: 3,
              aggregateVersion: 4,
              policyId: ticketSlaFixture.policyId,
              policyVersion: ticketSlaFixture.policyVersion,
              occurredAt: "2026-08-26T08:16:00Z",
              replayed: false,
            },
            '"sla-object-v4"',
          );
        }
        return jsonResponse(
          {
            ...ticketSlaFixture,
            aggregateVersion: 4,
            metrics: ticketSlaFixture.metrics.map((metric) => ({
              ...metric,
              metricVersion: metric.metricVersion + 1,
            })),
          },
          '"sla-object-v4"',
        );
      }),
    );

    await expect(
      slaAdminApi.overrideTicketSla({
        body,
        csrfToken: "csrf-memory-only",
        etag: '"sla-object-v3"',
        idempotencyKey: "sla-override-01991c20-7d5f-7000-8000-000000000099",
        kind: "case",
        objectId: slaObjectId,
        tenantId: slaTenantId,
      }),
    ).resolves.toMatchObject({
      projection: { etag: '"sla-object-v4"' },
      receipt: { overrideId: body.overrideId },
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]?.headers.get("If-Match")).toBe('"sla-object-v3"');
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(requests[0]?.json()).resolves.toEqual(body);
  });

  it("rejects operator identities smuggled into a customer projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            audience: "customer",
            tenantId: slaTenantId,
            objectType: "case",
            objectId: slaObjectId,
            projectedAt: ticketSlaFixture.projectedAt,
            metrics: [],
            columns: [],
            slaInstanceId,
          },
          '"sla-object-v3"',
        ),
      ),
    );

    await expect(
      slaAdminApi.getTicketSla({
        audience: "customer",
        kind: "case",
        objectId: slaObjectId,
        tenantId: slaTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a customer projection returned by an operator route", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            audience: "customer",
            tenantId: slaTenantId,
            objectType: "case",
            objectId: slaObjectId,
            projectedAt: ticketSlaFixture.projectedAt,
            metrics: [],
            columns: [],
          },
          '"sla-customer-current"',
        ),
      ),
    );

    await expect(
      slaAdminApi.getTicketSla({
        audience: "operator",
        kind: "case",
        objectId: slaObjectId,
        tenantId: slaTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("never reflects an untrusted Problem Details body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "forbidden",
            detail: "secret destination and customer payload",
            requestId: "request-1",
          },
          undefined,
          403,
        ),
      ),
    );

    await expect(
      slaAdminApi.listCalendars({ tenantId: slaTenantId }),
    ).rejects.toMatchObject({
      message: "Current authority does not permit this SLA operation.",
      status: 403,
    });
  });
});

function jsonResponse(value: unknown, etag?: string, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Content-Type": "application/json",
      ...(etag ? { ETag: etag } : {}),
    },
    status,
  });
}

function noContentResponse(etag: string): Response {
  return new Response(null, { headers: { ETag: etag }, status: 204 });
}
