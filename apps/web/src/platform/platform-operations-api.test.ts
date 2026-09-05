import { afterEach, describe, expect, it, vi } from "vitest";

import { platformOperationsApi } from "./platform-operations-api";

const firstUserID = "019d4d16-2160-7000-8000-000000000061";
const secondUserID = "019d4d16-2160-7000-8000-000000000062";
const tenantID = "019d4d16-2160-7000-8000-000000000073";
const failureAt = "2026-09-01T10:00:00Z";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("platformOperationsApi", () => {
  it("accepts every stored authentication method and enforces no-store", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            projectionVersion: 1,
            items: [
              {
                active: true,
                activeTenantMembershipCount: 1,
                displayName: "Recovery-capable operator",
                email: null,
                id: firstUserID,
                liveSessionsByAuthenticationMethod: [
                  { liveSessionCount: 1, method: "bootstrap_totp" },
                  { liveSessionCount: 1, method: "ldap" },
                  { liveSessionCount: 1, method: "oidc" },
                  { liveSessionCount: 1, method: "passkey" },
                  { liveSessionCount: 1, method: "recovery_code" },
                  { liveSessionCount: 1, method: "saml" },
                  { liveSessionCount: 1, method: "totp" },
                ],
                platformRoles: ["platform_super_admin"],
                totalTenantMembershipCount: 2,
              },
            ],
            nextCursor: firstUserID,
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse(
            { projectionVersion: 1, items: [], nextCursor: null },
            { "Cache-Control": "private" },
          ),
        ),
    );

    await expect(
      platformOperationsApi.listUsers({ limit: 50 }),
    ).resolves.toMatchObject({
      items: [{ id: firstUserID }],
      nextCursor: firstUserID,
    });
    await expect(
      platformOperationsApi.listUsers({ limit: 50 }),
    ).rejects.toMatchObject({
      status: 200,
    });
  });

  it("binds settings and flag mutations to strong versions and safe reasons", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementationOnce(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return jsonResponse(settings(2), { ETag: '"v2"' });
        })
        .mockImplementationOnce(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return jsonResponse(
            {
              enabled: false,
              key: "platform_failed_notifications_view",
              updatedAt: "2026-09-01T10:00:00Z",
              version: 4,
            },
            { ETag: '"v4"' },
          );
        }),
    );

    await expect(
      platformOperationsApi.updateSettings({
        body: {
          defaultLocale: "it-IT",
          defaultTimezone: "Europe/Rome",
          expectedVersion: 1,
          platformName: "Periapsis SOC",
          supportUrl: "https://support.example.test/help",
        },
        csrfToken: "csrf-memory-only",
        reason: "Align platform defaults",
      }),
    ).resolves.toMatchObject({ version: 2 });
    await expect(
      platformOperationsApi.updateFeatureFlag({
        body: { enabled: false, expectedVersion: 3 },
        csrfToken: "csrf-memory-only",
        flagKey: "platform_failed_notifications_view",
        reason: "Pause the redacted failure view",
      }),
    ).resolves.toMatchObject({ enabled: false, version: 4 });

    expect(requests[0]?.headers.get("If-Match")).toBe('"v1"');
    expect(requests[0]?.headers.get("X-Audit-Reason")).toBe(
      "Align platform defaults",
    );
    expect(requests[1]?.headers.get("If-Match")).toBe('"v3"');
    await expect(
      platformOperationsApi.updateSettings({
        body: { ...settings(1), expectedVersion: 1 },
        csrfToken: "csrf-memory-only",
        reason: "unsafe,reason",
      }),
    ).rejects.toBeDefined();
  });

  it("fails closed on malformed health metrics and failed-notification chronology", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            checkedAt: "2026-09-01T10:00:00Z",
            checks: [
              { key: "database", pendingCount: 0, status: "healthy" },
              { key: "platform_audit_chain", status: "healthy" },
              {
                key: "queue_backlog",
                oldestPendingSeconds: 0,
                pendingCount: 0,
                status: "healthy",
              },
              { failedCount: 0, key: "queue_failures", status: "healthy" },
            ],
            projectionVersion: 1,
            status: "healthy",
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              failedNotification(secondUserID, "2026-09-01T10:01:00Z"),
              failedNotification(firstUserID, "2026-09-01T10:00:00Z", {
                createdAt: "2026-09-01T10:00:01Z",
              }),
            ],
            nextCursor: failedCursor(firstUserID, failureAt),
            projectionVersion: 1,
          }),
        ),
    );

    await expect(platformOperationsApi.getHealth({})).rejects.toBeDefined();
    await expect(
      platformOperationsApi.listFailedNotifications({ limit: 50 }),
    ).rejects.toBeDefined();
  });
});

function settings(version: number) {
  return {
    defaultLocale: "it-IT",
    defaultTimezone: "Europe/Rome",
    platformName: "Periapsis SOC",
    supportUrl: "https://support.example.test/help",
    updatedAt: "2026-09-01T10:00:00Z",
    version,
  };
}

function failedNotification(
  id: string,
  at: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    attemptCount: 2,
    channel: "email",
    createdAt: "2026-09-01T09:00:00Z",
    failureAt: at,
    failureClass: "connectivity",
    failureCode: "unknown",
    id,
    tenantId: tenantID,
    updatedAt: at,
    ...overrides,
  };
}

function failedCursor(id: string, at: string): string {
  return globalThis
    .btoa(JSON.stringify({ v: 1, failureAt: at, id }))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function jsonResponse(
  value: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ...headers,
    },
    status: 200,
  });
}
