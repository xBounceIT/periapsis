import { afterEach, describe, expect, it, vi } from "vitest";

import type { TenantSettings } from "@periapsis/contracts";

import { tenantSettingsApi } from "./tenant-settings-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("tenantSettingsApi", () => {
  it("loads one exact private active-tenant projection", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return settingsResponse();
      }),
    );

    await expect(tenantSettingsApi.get(tenantId)).resolves.toEqual({
      etag: '"v7"',
      value: settingsFixture(),
    });

    const request = requests[0];
    expect(request?.method).toBe("GET");
    expect(request?.url).toContain("/api/v1/tenants/" + tenantId + "/settings");
    expect(request?.credentials).toBe("same-origin");
    expect(request?.cache).toBe("no-store");
  });

  it("binds update to CSRF, strong version, reason, and normalized body", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return settingsResponse(
          {
            accentColor: "#dc6843",
            brandMark: "ORB",
            brandName: "Orbit Response",
            primaryColor: "#103b53",
            updatedAt: "2026-09-01T19:05:00Z",
            version: 8,
          },
          '"v8"',
        );
      }),
    );

    await expect(
      tenantSettingsApi.update(
        "csrf-memory-only",
        tenantId,
        { etag: '"v7"', value: settingsFixture() },
        "Approved identity refresh SEC-2048",
        {
          accentColor: " #DC6843 ",
          brandMark: " orb ",
          brandName: " Orbit Response ",
          locale: "it-IT",
          primaryColor: " #103B53 ",
          timezone: "Europe/Rome",
        },
      ),
    ).resolves.toMatchObject({
      etag: '"v8"',
      value: {
        accentColor: "#dc6843",
        brandMark: "ORB",
        brandName: "Orbit Response",
        primaryColor: "#103b53",
        version: 8,
      },
    });

    const request = requests[0];
    expect(request?.method).toBe("PUT");
    expect(request?.headers.get("If-Match")).toBe('"v7"');
    expect(request?.headers.get("X-Audit-Reason")).toBe(
      "Approved identity refresh SEC-2048",
    );
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(request?.clone().json()).resolves.toEqual({
      accentColor: "#dc6843",
      brandMark: "ORB",
      brandName: "Orbit Response",
      expectedVersion: 7,
      locale: "it-IT",
      primaryColor: "#103b53",
      timezone: "Europe/Rome",
    });
  });

  it.each([
    ["cross-tenant body", { tenantId: "0198c97d-cf4f-7000-8000-000000000092" }],
    ["noncanonical mark", { brandMark: "orb" }],
    ["remote field", { remoteLogo: "https://tracker.invalid/pixel" }],
    ["version zero", { version: 0 }],
    ["malformed instant", { updatedAt: "tomorrow" }],
  ])("rejects %s", async (_name, override) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(settingsResponse(override)),
    );

    await expect(tenantSettingsApi.get(tenantId)).rejects.toMatchObject({
      code: "tenant_projection_mismatch",
    });
  });

  it("rejects cacheable or ETag-incoherent settings", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(settingsResponse({}, '"v8"'))
        .mockResolvedValueOnce(settingsResponse({}, '"v7"', "no-store")),
    );

    await expect(tenantSettingsApi.get(tenantId)).rejects.toMatchObject({
      code: "tenant_projection_mismatch",
    });
    await expect(tenantSettingsApi.get(tenantId)).rejects.toMatchObject({
      message: "The API did not mark tenant settings as private and no-store.",
    });
  });

  it("preserves a 412 conflict for reload instead of blind retry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "precondition_failed",
            detail: "<img src=x onerror=steal()> secret-internal-detail",
            requestId: "0198c97d-cf4f-7000-8000-000000000093",
            status: 412,
            title: "Precondition failed",
            type: "about:blank",
          }),
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
      tenantSettingsApi.update(
        "csrf-memory-only",
        tenantId,
        { etag: '"v7"', value: settingsFixture() },
        "Approved",
        {
          accentColor: "#dc6843",
          brandMark: "ORB",
          brandName: "Orbit Response",
          locale: "it-IT",
          primaryColor: "#103b53",
          timezone: "Europe/Rome",
        },
      ),
    ).rejects.toMatchObject({
      code: "precondition_failed",
      message: "Tenant settings changed after this form was loaded.",
      status: 412,
    });
  });

  it("rejects invalid headers and commands before transport", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const current = { etag: '"v7"', value: settingsFixture() };

    await expect(
      tenantSettingsApi.update(
        "",
        tenantId,
        current,
        "Approved",
        settingsDraft(),
      ),
    ).rejects.toThrow("CSRF");
    await expect(
      tenantSettingsApi.update(
        "csrf",
        tenantId,
        current,
        "contains,comma",
        settingsDraft(),
      ),
    ).rejects.toThrow("command");
    await expect(
      tenantSettingsApi.update(
        "csrf",
        tenantId,
        { ...current, etag: '"v6"' },
        "Approved",
        settingsDraft(),
      ),
    ).rejects.toThrow("command");
    expect(fetch).not.toHaveBeenCalled();
  });
});

function settingsDraft() {
  return {
    accentColor: "#dc6843",
    brandMark: "ORB",
    brandName: "Orbit Response",
    locale: "it-IT",
    primaryColor: "#103b53",
    timezone: "Europe/Rome",
  };
}

function settingsFixture(
  override: Partial<TenantSettings> = {},
): TenantSettings {
  return {
    accentColor: "#dc6843",
    brandMark: "PR",
    brandName: "Periapsis Response",
    locale: "it-IT",
    primaryColor: "#103b53",
    tenantId,
    timezone: "Europe/Rome",
    updatedAt: "2026-09-01T18:30:00.123456Z",
    version: 7,
    ...override,
  };
}

function settingsResponse(
  override: Record<string, unknown> = {},
  etag = '"v7"',
  cacheControl = "private, no-store",
): Response {
  return new Response(JSON.stringify({ ...settingsFixture(), ...override }), {
    headers: {
      "Cache-Control": cacheControl,
      "Content-Type": "application/json",
      ETag: etag,
    },
  });
}
