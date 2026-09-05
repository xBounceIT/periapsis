import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createLdapProviderDraft,
  toLdapProviderCreateInput,
  toLdapProviderUpdateInput,
} from "../pages/ldap-provider-model";
import { phaseTwoApi } from "./phase-two-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const syncRunId = "0198c97d-cf4f-7000-8000-000000000099";
const csrfToken = "csrf-memory-only-test-value";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi LDAP provider contracts", () => {
  it("uses the generated create operation and accepts only Location metadata", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: {
            "Cache-Control": "private, no-store",
            Location: `/api/v1/tenants/${tenantId}/auth-providers/${providerId}`,
          },
          status: 201,
        });
      }),
    );
    const input = toLdapProviderCreateInput(
      createLdapProviderDraft("active_directory"),
    );

    await expect(
      phaseTwoApi.createTenantLdapAuthProvider(
        csrfToken,
        tenantId,
        "0198c97d-cf4f-7000-8000-000000000099",
        input,
      ),
    ).resolves.toEqual({
      location: `/api/v1/tenants/${tenantId}/auth-providers/${providerId}`,
    });

    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.method).toBe("POST");
    expect(request.headers.get("X-CSRF-Token")).toBe(csrfToken);
    expect(request.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(await request.json()).toEqual(input);
  });

  it("performs atomic PUT replacement and returns only the next ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: { "Cache-Control": "no-store", ETag: '"v8"' },
          status: 204,
        });
      }),
    );
    const draft = createLdapProviderDraft("openldap");
    draft.enabled = true;
    const input = toLdapProviderUpdateInput(draft);

    await expect(
      phaseTwoApi.updateTenantLdapAuthProvider(
        csrfToken,
        tenantId,
        providerId,
        '"v7"',
        input,
      ),
    ).resolves.toBe('"v8"');

    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.method).toBe("PUT");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(await request.json()).toEqual(input);
    expect(Object.keys(input).toSorted()).toEqual(
      [
        "configuration",
        "description",
        "displayName",
        "enabled",
        "endpoints",
        "key",
      ].toSorted(),
    );
  });

  it("rejects an extra secret-shaped field in a provider projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { ...providerFixture(), bindSecret: "must-not-escape" },
            200,
            { ETag: '"v7"' },
          ),
        ),
    );

    await expect(
      phaseTwoApi.getTenantLdapAuthProvider(tenantId, providerId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("accepts sanitized diagnostics and rejects contradictory branches", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            category: "certificate_rejected",
            completedAt: "2026-08-25T09:30:00Z",
            durationMs: 42,
            endpointPriority: 1,
            outcome: "failure",
            stale: false,
            testRunId: "0198c97d-cf4f-7000-8000-000000000099",
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            category: "cancelled",
            completedAt: "2026-08-25T09:30:00Z",
            durationMs: 42,
            endpointPriority: 1,
            outcome: "failure",
            stale: false,
            testRunId: "0198c97d-cf4f-7000-8000-000000000099",
          }),
        ),
    );

    await expect(
      phaseTwoApi.testTenantLdapAuthProviderConnection(
        csrfToken,
        tenantId,
        providerId,
      ),
    ).resolves.toMatchObject({ category: "certificate_rejected" });
    await expect(
      phaseTwoApi.testTenantLdapAuthProviderConnection(
        csrfToken,
        tenantId,
        providerId,
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it.each([400, 403, 409, 429])(
    "fails closed when an LDAP Problem response %s omits no-store",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          new Response(
            JSON.stringify({
              detail: "Safe bounded problem detail.",
              status,
              title: "Request rejected",
              type: "about:blank",
            }),
            {
              headers: { "Content-Type": "application/problem+json" },
              status,
            },
          ),
        ),
      );

      await expect(
        phaseTwoApi.listTenantLdapAuthProviders(tenantId),
      ).rejects.toMatchObject({
        message: "The API did not mark the LDAP provider response as no-store.",
        status,
      });
    },
  );

  it("sends the write-only secret once and accepts a no-content ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(null, {
          headers: { "Cache-Control": "no-store", ETag: '"v9"' },
          status: 204,
        });
      }),
    );

    await expect(
      phaseTwoApi.setTenantLdapAuthProviderBindSecret(
        csrfToken,
        tenantId,
        providerId,
        '"v8"',
        { secret: "one-time-browser-value" },
      ),
    ).resolves.toBe('"v9"');
    expect(await requests[0]!.json()).toEqual({
      secret: "one-time-browser-value",
    });
  });

  it("creates a tenant binding through the generated operation with Location and ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(bindingFixture(), 201, {
          ETag: '"v3"',
          Location: `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}`,
        });
      }),
    );

    await expect(
      phaseTwoApi.createTenantLdapAuthProviderBinding(
        csrfToken,
        tenantId,
        "0198c97d-cf4f-7000-8000-000000000101",
        {
          enabled: true,
          loginKey: "employees_eu",
          profilePriority: 100,
          providerId,
        },
      ),
    ).resolves.toMatchObject({
      etag: '"v3"',
      location: `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}`,
      value: { id: bindingId, tenantId },
    });

    const request = requests[0]!;
    expect(request.method).toBe("POST");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000101",
    );
    expect(request.headers.get("X-CSRF-Token")).toBe(csrfToken);
    expect(await request.json()).toEqual({
      enabled: true,
      loginKey: "employees_eu",
      profilePriority: 100,
      providerId,
    });
  });

  it("rejects a directory test response that attempts to expose a raw DN", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          diagnostic: successDiagnosticFixture(),
          entries: [
            {
              attributes: [],
              dn: "CN=Secret,DC=example,DC=invalid",
              dnPresent: true,
              groupValueCount: 2,
              immutableSubjectRedacted: true,
              ordinal: 1,
            },
          ],
          matchedEntryCount: 1,
          truncated: false,
        }),
      ),
    );

    await expect(
      phaseTwoApi.searchTenantLdapAuthProviderUser(
        csrfToken,
        tenantId,
        providerId,
        { username: "candidate" },
      ),
    ).rejects.toMatchObject({
      code: "tenant_projection_mismatch",
    });
  });

  it("preserves incomplete sync state and never upgrades absence revocation", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(incompleteSyncRunFixture(), 200, { ETag: '"v2"' }),
        ),
    );

    await expect(
      phaseTwoApi.getTenantLdapSyncRun(tenantId, bindingId, syncRunId),
    ).resolves.toMatchObject({
      etag: '"v2"',
      value: {
        enumeration: {
          absenceBasedRevocationAllowed: false,
          complete: false,
          state: "incomplete",
          truncated: false,
        },
      },
    });
  });

  it("starts manual sync with status ETag, reason and payload-bound key", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(incompleteSyncRunFixture(), 202, {
          ETag: '"v2"',
          Location: `/api/v1/tenants/${tenantId}/auth-provider-bindings/${bindingId}/sync-runs/${syncRunId}`,
        });
      }),
    );

    await phaseTwoApi.startTenantLdapManualSync(
      csrfToken,
      tenantId,
      bindingId,
      '"v4"',
      "0198c97d-cf4f-7000-8000-000000000102",
      { reason: "Review an incomplete directory observation." },
    );

    const request = requests[0]!;
    expect(request.method).toBe("POST");
    expect(request.headers.get("If-Match")).toBe('"v4"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000102",
    );
    expect(await request.json()).toEqual({
      reason: "Review an incomplete directory observation.",
    });
  });
});

function jsonResponse(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ...headers,
    },
    status,
  });
}

function providerFixture() {
  const draft = createLdapProviderDraft("active_directory");
  return {
    ...toLdapProviderUpdateInput(draft),
    archiveReason: null,
    archivedAt: null,
    bindSecretConfigured: false,
    bindSecretRotatedAt: null,
    createdAt: "2026-08-25T09:00:00Z",
    enabledEndpointCount: 1,
    id: providerId,
    kind: "ldap",
    template: draft.configuration.template,
    tenantId,
    updatedAt: "2026-08-25T09:15:00Z",
    version: 7,
  };
}

function bindingFixture() {
  return {
    archivedAt: null,
    authRevision: 3,
    createdAt: "2026-08-25T09:00:00Z",
    currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000098",
    enabled: true,
    id: bindingId,
    loginKey: "employees_eu",
    profilePriority: 100,
    providerId,
    tenantId,
    updatedAt: "2026-08-25T09:15:00Z",
    version: 3,
  };
}

function successDiagnosticFixture() {
  return {
    category: "success",
    completedAt: "2026-08-25T09:30:00Z",
    durationMs: 42,
    endpointPriority: 1,
    outcome: "success",
    stale: false,
    testRunId: "0198c97d-cf4f-7000-8000-000000000103",
  };
}

function incompleteSyncRunFixture() {
  return {
    bindingId,
    completedAt: "2026-08-25T09:15:00Z",
    counters: {
      failed: 1,
      groupEdgesAdded: 0,
      groupEdgesRefreshed: 0,
      groupEdgesRevoked: 0,
      identitiesCreated: 0,
      identitiesLinked: 0,
      observed: 14,
      providerAccessAdded: 0,
      providerAccessSuspended: 0,
      roleEdgesAdded: 0,
      roleEdgesRefreshed: 0,
      roleEdgesRevoked: 0,
      rosterEdgesAdded: 0,
      rosterEdgesRefreshed: 0,
      rosterEdgesRevoked: 0,
      staged: 0,
    },
    createdAt: "2026-08-25T09:10:00Z",
    enumeration: {
      absenceBasedRevocationAllowed: false,
      complete: false,
      cursorState: "discarded",
      entryCount: 14,
      errorCategory: "worker_interrupted",
      pageCount: 2,
      responseBytes: 1024,
      state: "incomplete",
      truncated: false,
    },
    id: syncRunId,
    manualReason: "Review the interrupted tenant observation.",
    providerId,
    runErrorCategory: "incomplete_enumeration",
    snapshot: {
      accessEpochId: "0198c97d-cf4f-7000-8000-000000000098",
      bindingId,
      bindingVersion: 3,
      configurationRevision: 4,
      mappingRevisions: [],
      providerId,
      providerVersion: 7,
    },
    startedAt: "2026-08-25T09:11:00Z",
    state: "failed",
    tenantId,
    trigger: "manual",
    updatedAt: "2026-08-25T09:15:00Z",
    version: 2,
  };
}
