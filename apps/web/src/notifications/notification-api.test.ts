import { afterEach, describe, expect, it, vi } from "vitest";

import { notificationAdminApi } from "./notification-api";
import {
  deliveryFixture,
  fixtureTenantId,
  smtpFixture,
  webhookFixture,
  webhookUrlPolicyFixture,
  notificationTemplateFixture,
} from "./notification-test-fixtures";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("notificationAdminApi", () => {
  it("binds webhook rotation to CSRF, If-Match, idempotency, and a write-only request body", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { ...webhookFixture, version: 2, signingKeyVersion: 2 },
          '"v2"',
        );
      }),
    );

    await notificationAdminApi.versionWebhook({
      body: {
        name: webhookFixture.name,
        endpointUrl: webhookFixture.endpointUrl,
        eventTypes: webhookFixture.eventTypes,
        audience: webhookFixture.audience,
        signingKey: "write-only-signing-material",
        timeoutMs: webhookFixture.timeoutMs,
        enabled: true,
      },
      csrfToken: "csrf-memory-only",
      etag: '"v1"',
      id: webhookFixture.id,
      idempotencyKey: "01991c20-7d5f-7000-8000-000000000099",
      tenantId: fixtureTenantId,
    });

    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.headers.get("If-Match")).toBe('"v1"');
    expect(request!.headers.get("Idempotency-Key")).toBe(
      "01991c20-7d5f-7000-8000-000000000099",
    );
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(request!.clone().json()).resolves.toMatchObject({
      signingKey: "write-only-signing-material",
    });
  });

  it("rejects a delivery projection containing a complete destination or secret", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...deliveryFixture,
              recipient: "operator@example.test",
            },
          ],
        }),
      ),
    );

    await expect(
      notificationAdminApi.listDeliveries({ tenantId: fixtureTenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("allows bounded template sample data without confusing a sample recipient for a delivery leak", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...notificationTemplateFixture,
              sampleData: { recipient: "sample@example.test" },
            },
          ],
        }),
      ),
    );

    await expect(
      notificationAdminApi.listTemplates({ tenantId: fixtureTenantId }),
    ).resolves.toMatchObject({
      items: [{ id: notificationTemplateFixture.id }],
    });
  });

  it("rejects cross-tenant projections even when the identifier was requested", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [{ ...deliveryFixture, tenantId: "another-tenant" }],
        }),
      ),
    );

    await expect(
      notificationAdminApi.listDeliveries({ tenantId: fixtureTenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("never reflects an untrusted RFC 9457 detail containing protected material", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "forbidden",
            detail: "password=server-secret",
            requestId: "request-1",
          },
          undefined,
          403,
        ),
      ),
    );

    await expect(
      notificationAdminApi.listRules({ tenantId: fixtureTenantId }),
    ).rejects.toMatchObject({
      message: "The server denied this notification operation.",
      status: 403,
    });
  });

  it("keeps platform SMTP tests health-only on both request and response", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({
          configurationId: smtpFixture.id,
          configurationVersion: 1,
          healthy: true,
          checkedAt: "2026-08-25T10:00:00Z",
          checks: [{ kind: "connect", outcome: "passed" }],
        });
      }),
    );

    await expect(
      notificationAdminApi.testPlatformSmtp({
        body: { configurationVersion: 1, reason: "Release readiness" },
        csrfToken: "csrf-memory-only",
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000098",
      }),
    ).resolves.toMatchObject({ healthy: true });

    await expect(requests[0]!.clone().json()).resolves.toEqual({
      configurationVersion: 1,
      reason: "Release readiness",
    });
  });

  it("rejects a platform SMTP health projection containing a delivery identifier", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          configurationId: smtpFixture.id,
          configurationVersion: 1,
          healthy: true,
          checkedAt: "2026-08-25T10:00:00Z",
          checks: [{ kind: "connect", outcome: "passed" }],
          queuedDeliveryId: deliveryFixture.id,
        }),
      ),
    );

    await expect(
      notificationAdminApi.testPlatformSmtp({
        body: { configurationVersion: 1, reason: "Release readiness" },
        csrfToken: "csrf-memory-only",
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000097",
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("publishes the bootstrap webhook URL policy with exact CAS, audit, CSRF, and replay headers", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(
          JSON.stringify({ policy: webhookUrlPolicyFixture, replayed: false }),
          {
            headers: {
              "Content-Type": "application/json",
              ETag: '"v1"',
              "X-Idempotent-Replay": "false",
            },
            status: 200,
          },
        );
      }),
    );

    await expect(
      notificationAdminApi.publishWebhookUrlPolicy({
        auditReason: "Approve reviewed egress boundary",
        body: {
          expectedVersion: 0,
          rules: [
            {
              effect: "allow",
              match: "exact",
              hostname: "hooks.example.test",
              port: 443,
            },
          ],
        },
        csrfToken: "csrf-memory-only",
        etag: '"v0"',
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000096",
        tenantId: fixtureTenantId,
      }),
    ).resolves.toMatchObject({
      etag: '"v1"',
      replayed: false,
      value: { tenantId: fixtureTenantId, version: 1 },
    });

    const request = requests[0];
    expect(request?.headers.get("If-Match")).toBe('"v0"');
    expect(request?.headers.get("Idempotency-Key")).toBe(
      "01991c20-7d5f-7000-8000-000000000096",
    );
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request?.headers.get("X-Audit-Reason")).toBe(
      "Approve reviewed egress boundary",
    );
  });

  it("returns an explicit empty bootstrap state and rejects unsafe policy projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({}, undefined, 404)),
    );
    await expect(
      notificationAdminApi.getWebhookUrlPolicy({ tenantId: fixtureTenantId }),
    ).resolves.toBeNull();

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            ...webhookUrlPolicyFixture,
            rules: [
              {
                effect: "allow",
                match: "exact",
                hostname: "z.example.test",
                port: 443,
              },
              {
                effect: "allow",
                match: "exact",
                hostname: "a.example.test",
                port: 443,
              },
            ],
          },
          '"v1"',
        ),
      ),
    );
    await expect(
      notificationAdminApi.getWebhookUrlPolicy({ tenantId: fixtureTenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects mismatched policy replay evidence and non-ASCII audit headers before trusting the result", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ policy: webhookUrlPolicyFixture, replayed: true }),
        {
          headers: {
            "Content-Type": "application/json",
            ETag: '"v1"',
            "X-Idempotent-Replay": "false",
          },
          status: 200,
        },
      ),
    );
    vi.stubGlobal("fetch", fetch);
    const input = {
      auditReason: "Approved",
      body: { expectedVersion: 0, rules: [] },
      csrfToken: "csrf-memory-only",
      etag: '"v0"',
      idempotencyKey: "01991c20-7d5f-7000-8000-000000000095",
      tenantId: fixtureTenantId,
    };
    await expect(
      notificationAdminApi.publishWebhookUrlPolicy(input),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      notificationAdminApi.publishWebhookUrlPolicy({
        ...input,
        auditReason: "approv\u00e9",
      }),
    ).rejects.toThrow("valid audited reason");
    expect(fetch).toHaveBeenCalledTimes(1);
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
