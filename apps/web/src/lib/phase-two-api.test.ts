import { afterEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import {
  tenantAuthorizationScopes,
  tenantPermissionKeys,
  tenantProjectionMismatchCode,
  type ServiceAccountCredentialView,
  type ServiceAccountRoleGrantView,
  type ServiceAccountView,
  type TenantRoleView,
  type TenantSecurityGroupView,
} from "./phase-two-types";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const userId = "0198c97d-cf4f-7000-8000-000000000021";
const roleId = "0198c97d-cf4f-7000-8000-000000000040";
const groupId = "0198c97d-cf4f-7000-8000-000000000041";
const membershipEdgeId = "0198c97d-cf4f-7000-8000-000000000042";
const grantId = "0198c97d-cf4f-7000-8000-000000000043";
const edgeEtag = '"v7-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';
const otherEdgeEtag = '"v7-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZE"';
const nonCanonicalEdgeEtag = '"v7-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZB"';
const authorizationEdgeKinds = ["direct", "membership", "group-role"] as const;
const otherRoleId = "0198c97d-cf4f-7000-8000-000000000044";
const otherGroupId = "0198c97d-cf4f-7000-8000-000000000045";
const otherTenantId = "0198c97d-cf4f-7000-8000-000000000046";
const serviceAccountId = "0198c97d-cf4f-7000-8000-000000000047";
const credentialId = "0198c97d-cf4f-7000-8000-000000000048";
const operatorTeamId = "0198c97d-cf4f-7000-8000-000000000049";
const assignmentEpochId = "0198c97d-cf4f-7000-8000-00000000004a";
const otherAssignmentEpochId = "0198c97d-cf4f-7000-8000-00000000004b";

const versionedResourceOperations = [
  {
    name: "role create",
    resource: "role",
    invoke: () =>
      phaseTwoApi.createTenantRole(
        "csrf-memory-only-value",
        tenantId,
        "0198c97d-cf4f-7000-8000-000000000098",
        {
          key: "custom_triage",
          name: "Custom triage",
          policy: { delegationCeiling: [], permissions: [] },
        },
      ),
  },
  {
    name: "role get",
    resource: "role",
    expectedPathIdentity: true,
    invoke: () => phaseTwoApi.getTenantRole(tenantId, roleId),
  },
  {
    name: "role update",
    resource: "role",
    expectedPathIdentity: true,
    invoke: () =>
      phaseTwoApi.updateTenantRole(
        "csrf-memory-only-value",
        tenantId,
        roleId,
        '"v3"',
        { name: "Updated role" },
      ),
  },
  {
    name: "role policy update",
    resource: "role",
    expectedPathIdentity: true,
    invoke: () =>
      phaseTwoApi.replaceTenantRolePolicy(
        "csrf-memory-only-value",
        tenantId,
        roleId,
        '"v3"',
        { delegationCeiling: [], permissions: [] },
      ),
  },
  {
    name: "group create",
    resource: "group",
    invoke: () =>
      phaseTwoApi.createTenantSecurityGroup(
        "csrf-memory-only-value",
        tenantId,
        "0198c97d-cf4f-7000-8000-000000000097",
        { key: "ir_leads", name: "IR leads" },
      ),
  },
  {
    name: "group get",
    resource: "group",
    expectedPathIdentity: true,
    invoke: () => phaseTwoApi.getTenantSecurityGroup(tenantId, groupId),
  },
  {
    name: "group update",
    resource: "group",
    expectedPathIdentity: true,
    invoke: () =>
      phaseTwoApi.updateTenantSecurityGroup(
        "csrf-memory-only-value",
        tenantId,
        groupId,
        '"v3"',
        { name: "Updated group" },
      ),
  },
] as const;

type AuthorizationEdgeKind = (typeof authorizationEdgeKinds)[number];

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi logout continuation boundary", () => {
  const continuationId = "0198c97d-cf4f-7000-8000-000000000071";
  const continuationUrl = `/api/v1/auth/logout/continuations/${continuationId}`;

  it("accepts only the opaque same-origin continuation after local revocation", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(JSON.stringify({ continuationUrl }), {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json; charset=utf-8",
            "Referrer-Policy": "no-referrer",
          },
          status: 200,
        });
      }),
    );

    await expect(phaseTwoApi.logout("csrf-memory-only-value")).resolves.toEqual(
      { continuationUrl },
    );
    const request = firstRequest(requests);
    expect(request.method).toBe("DELETE");
    expect(request.credentials).toBe("same-origin");
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
  });

  it("maps the exact no-content response to local-only logout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Promise.resolve(
          new Response(null, {
            headers: {
              "Cache-Control": "no-store",
              "Referrer-Policy": "no-referrer",
            },
            status: 204,
          }),
        ),
      ),
    );

    await expect(
      phaseTwoApi.logout("csrf-memory-only-value"),
    ).resolves.toBeNull();
  });

  it.each([
    [
      "absolute URL",
      { continuationUrl: `https://evil.example/${continuationId}` },
    ],
    [
      "scheme-relative URL",
      { continuationUrl: `//evil.example/${continuationId}` },
    ],
    [
      "query string",
      { continuationUrl: `${continuationUrl}?next=https://evil.example` },
    ],
    ["fragment", { continuationUrl: `${continuationUrl}#id_token_hint` }],
    [
      "non-v7 identifier",
      {
        continuationUrl:
          "/api/v1/auth/logout/continuations/0198c97d-cf4f-4000-8000-000000000071",
      },
    ],
    [
      "uppercase identifier",
      {
        continuationUrl:
          "/api/v1/auth/logout/continuations/0198C97D-CF4F-7000-8000-000000000071",
      },
    ],
    ["missing coordinate", {}],
    ["extra protocol material", { continuationUrl, idTokenHint: "secret" }],
  ] as const)("rejects a %s before browser navigation", async (_name, body) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Promise.resolve(
          new Response(JSON.stringify(body), {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              "Referrer-Policy": "no-referrer",
            },
            status: 200,
          }),
        ),
      ),
    );

    await expect(phaseTwoApi.logout("csrf-memory-only-value")).rejects.toThrow(
      "invalid logout continuation",
    );
  });

  it.each([
    ["unexpected success status", 201, "no-store", "no-referrer"],
    ["cacheable response", 200, "private", "no-referrer"],
    ["referrer-capable response", 200, "no-store", "origin"],
  ] as const)(
    "rejects an %s",
    async (_name, status, cacheControl, referrerPolicy) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          Promise.resolve(
            new Response(JSON.stringify({ continuationUrl }), {
              headers: {
                "Cache-Control": cacheControl,
                "Content-Type": "application/json",
                "Referrer-Policy": referrerPolicy,
              },
              status,
            }),
          ),
        ),
      );

      await expect(
        phaseTwoApi.logout("csrf-memory-only-value"),
      ).rejects.toThrow("invalid logout continuation");
    },
  );
});

describe("phaseTwoApi explicit platform tenant access", () => {
  const membershipId = "0198c97d-cf4f-7000-8000-000000000060";

  it("binds the explicit command to CSRF, If-Match, idempotency, and a no-store receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(
          JSON.stringify({
            authorizationRevision: "27",
            authorizedAt: "2026-09-01T20:30:00.123456Z",
            membershipId,
            membershipRevision: 1,
            replayed: false,
            tenantId,
            tenantVersion: 7,
            userId,
          }),
          {
            status: 201,
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v7"',
            },
          },
        );
      }),
    );

    await expect(
      phaseTwoApi.authorizePlatformTenantAccess(
        "csrf-memory-only-value",
        tenantId,
        '"v7"',
        "tenant-access-key-0001",
        { expectedVersion: 7, reason: "Approved investigation SEC-2048" },
      ),
    ).resolves.toMatchObject({
      authorizationRevision: "27",
      membershipId,
      membershipRevision: 1,
      replayed: false,
      tenantId,
      tenantVersion: 7,
      userId,
    });

    const request = firstRequest(requests);
    expect(request.url).toContain(
      `/api/v1/platform/tenants/${tenantId}/access`,
    );
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "tenant-access-key-0001",
    );
    await expect(request.clone().json()).resolves.toEqual({
      expectedVersion: 7,
      reason: "Approved investigation SEC-2048",
    });
  });

  it("accepts only a coherent 200 replay", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            authorizationRevision: "27",
            authorizedAt: "2026-09-01T20:30:00.123456Z",
            membershipId,
            membershipRevision: 1,
            replayed: true,
            tenantId,
            tenantVersion: 7,
            userId,
          }),
          {
            status: 200,
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: '"v7"',
            },
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.authorizePlatformTenantAccess(
        "csrf-memory-only-value",
        tenantId,
        '"v7"',
        "tenant-access-key-0001",
        { expectedVersion: 7, reason: "Approved investigation SEC-2048" },
      ),
    ).resolves.toMatchObject({ replayed: true });
  });

  it("rejects a cross-tenant or status-incoherent access receipt", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            authorizationRevision: "27",
            authorizedAt: "2026-09-01T20:30:00.123456Z",
            membershipId,
            membershipRevision: 1,
            replayed: true,
            tenantId: otherTenantId,
            tenantVersion: 7,
            userId,
          }),
          {
            status: 201,
            headers: { "Cache-Control": "no-store", ETag: '"v7"' },
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.authorizePlatformTenantAccess(
        "csrf-memory-only-value",
        tenantId,
        '"v7"',
        "tenant-access-key-0001",
        { expectedVersion: 7, reason: "Approved investigation SEC-2048" },
      ),
    ).rejects.toMatchObject({ code: tenantProjectionMismatchCode });
  });
});

describe("phaseTwoApi tenant contracts", () => {
  it("returns the strong server ETag with a tenant-safe role projection", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (input instanceof Request) {
        requests.push(input);
      }
      return jsonResponse(roleFixture(), '"v3"');
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(phaseTwoApi.getTenantRole(tenantId, roleId)).resolves.toEqual({
      etag: '"v3"',
      value: roleFixture(),
    });
    const request = firstRequest(requests);
    expect(request.url).toContain(
      `/api/v1/tenants/${tenantId}/roles/${roleId}`,
    );
    expect(request.credentials).toBe("same-origin");
  });

  it("rejects a versioned response that omits its strong ETag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(roleFixture())),
    );

    await expect(
      phaseTwoApi.getTenantRole(tenantId, roleId),
    ).rejects.toMatchObject({
      message: "The API did not return the required strong resource version.",
    });
  });

  it.each(versionedResourceOperations)(
    "rejects a $name response whose ETag version disagrees with its body",
    async (operation) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              versionedResourceFixture(operation.resource, 4),
              '"v3"',
            ),
          ),
      );

      await expect(operation.invoke()).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(
    versionedResourceOperations.flatMap((operation) =>
      [0, 2_147_483_648].map((version) => ({ operation, version })),
    ),
  )(
    "rejects a $operation.name response with out-of-range version $version",
    async ({ operation, version }) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              versionedResourceFixture(operation.resource, version),
              '"v3"',
            ),
          ),
      );

      await expect(operation.invoke()).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each([
    ["role", () => phaseTwoApi.getTenantRole(tenantId, roleId)],
    ["group", () => phaseTwoApi.getTenantSecurityGroup(tenantId, groupId)],
  ] as const)(
    "accepts the maximum contract version for a %s response",
    async (resource, invoke) => {
      const version = 2_147_483_647;
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse(
              versionedResourceFixture(resource, version),
              `"v${version}"`,
            ),
          ),
      );

      await expect(invoke()).resolves.toMatchObject({ etag: `"v${version}"` });
    },
  );

  it.each(
    versionedResourceOperations.filter(
      (operation) => "expectedPathIdentity" in operation,
    ),
  )(
    "rejects a $name response for a different path resource",
    async (operation) => {
      const fixture = versionedResourceFixture(operation.resource, 3);
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            {
              ...fixture,
              id: operation.resource === "role" ? otherRoleId : otherGroupId,
            },
            '"v3"',
          ),
        ),
      );

      await expect(operation.invoke()).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(["role", "group"] as const)(
    "binds %s creation to the requested immutable key",
    async (resource) => {
      const fixture = versionedResourceFixture(resource, 3);
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse({ ...fixture, key: "misrouted_key" }, '"v3"', 201),
          ),
      );

      const request =
        resource === "role"
          ? versionedResourceOperations[0].invoke()
          : versionedResourceOperations[4].invoke();
      await expect(request).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(authorizationEdgeKinds)(
    "treats an omitted %s ownership hint as false during a rolling deployment",
    async (edgeType) => {
      const edge = authorizationEdgeFixture(edgeType);
      delete edge.managedByAuthorizationApi;
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).resolves.toMatchObject({
        items: [{ managedByAuthorizationApi: false }],
      });
    },
  );

  it.each(authorizationEdgeKinds)(
    "preserves a server-derived true ownership hint for a %s edge",
    async (edgeType) => {
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            jsonResponse({ items: [authorizationEdgeFixture(edgeType)] }),
          ),
      );

      await expect(listAuthorizationEdges(edgeType)).resolves.toMatchObject({
        items: [{ managedByAuthorizationApi: true }],
      });
    },
  );

  it.each(
    authorizationEdgeKinds.flatMap((edgeType) =>
      (["identity mapping", "retired manual"] as const).map(
        (contradiction) => ({ contradiction, edgeType }),
      ),
    ),
  )(
    "rejects a true ownership hint with $contradiction provenance for a $edgeType edge",
    async ({ contradiction, edgeType }) => {
      const edge = authorizationEdgeFixture(edgeType);
      if (!isUnknownRecord(edge.provenance)) {
        throw new Error("The authorization edge fixture has no provenance.");
      }
      edge.provenance =
        contradiction === "identity mapping"
          ? edgeType === "direct"
            ? roleGrantProvenanceForSource(
                "identity_mapping",
                "identity_provider",
              )
            : authorizationEdgeProvenanceForSource("identity_mapping")
          : {
              ...edge.provenance,
              retiredAt: "2026-08-23T09:00:00Z",
            };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it("rejects an edge create response whose body ETag differs from its header", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(directGrantFixture(edgeEtag), otherEdgeEtag, 201),
        ),
    );

    await expect(
      phaseTwoApi.grantUserRole(
        "csrf-memory-only-value",
        tenantId,
        userId,
        "0198c97d-cf4f-7000-8000-000000000099",
        { reason: "Manual role decision", roleId },
      ),
    ).rejects.toMatchObject({
      code: tenantProjectionMismatchCode,
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("rejects the same non-canonical edge digest in both header and body", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            directGrantFixture(nonCanonicalEdgeEtag),
            nonCanonicalEdgeEtag,
            201,
          ),
        ),
    );

    await expect(
      phaseTwoApi.grantUserRole(
        "csrf-memory-only-value",
        tenantId,
        userId,
        "0198c97d-cf4f-7000-8000-000000000096",
        { reason: "Manual role decision", roleId },
      ),
    ).rejects.toMatchObject({
      message:
        "The API did not return the required strong edge representation validator.",
    });
  });

  it.each(["list", "create"] as const)(
    "rejects a direct-grant %s response whose nested role belongs to another tenant",
    async (operation) => {
      const grant = directGrantFixture(edgeEtag);
      grant.role = { ...roleFixture(), tenantId: otherTenantId };
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockResolvedValue(
            operation === "list"
              ? jsonResponse({ items: [grant] })
              : jsonResponse(grant, edgeEtag, 201),
          ),
      );

      const request =
        operation === "list"
          ? phaseTwoApi.listUserRoleGrants(tenantId, userId)
          : phaseTwoApi.grantUserRole(
              "csrf-memory-only-value",
              tenantId,
              userId,
              "0198c97d-cf4f-7000-8000-000000000095",
              { reason: "Manual role decision", roleId },
            );
      await expect(request).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it("binds direct-grant creation to the requested role", async () => {
    const grant = directGrantFixture(edgeEtag);
    grant.role = { ...roleFixture(), id: otherRoleId };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(grant, edgeEtag, 201)),
    );

    await expect(
      phaseTwoApi.grantUserRole(
        "csrf-memory-only-value",
        tenantId,
        userId,
        "0198c97d-cf4f-7000-8000-000000000094",
        { reason: "Manual role decision", roleId },
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("binds group-role creation to the requested role", async () => {
    const grant = groupRoleGrantFixture();
    grant.role = { ...roleFixture(), id: otherRoleId };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(grant, edgeEtag, 201)),
    );

    await expect(
      phaseTwoApi.grantTenantSecurityGroupRole(
        "csrf-memory-only-value",
        tenantId,
        groupId,
        "0198c97d-cf4f-7000-8000-000000000093",
        { reason: "Manual group role", roleId },
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("binds group-membership creation to the requested user", async () => {
    const membership = groupMembershipFixture();
    const member = membership.member;
    if (!isUnknownRecord(member) || !isUnknownRecord(member.user)) {
      throw new Error("The membership fixture has no member/user projection.");
    }
    membership.member = {
      ...member,
      user: {
        ...member.user,
        id: otherRoleId,
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(membership, edgeEtag, 201)),
    );

    await expect(
      phaseTwoApi.createTenantSecurityGroupMembership(
        "csrf-memory-only-value",
        tenantId,
        groupId,
        "0198c97d-cf4f-7000-8000-000000000092",
        { reason: "Manual group membership", userId },
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("binds tenant membership suspension to CSRF, exact revision, and idempotency", async () => {
    const requests: Request[] = [];
    const membershipId = "0198c97d-cf4f-7000-8000-000000000020";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return new Response(
          JSON.stringify({
            tenantId,
            membershipId,
            userId,
            previousStatus: "active",
            status: "suspended",
            lifecycleRevision: 8,
            etag: '"v8"',
            updatedAt: "2026-08-23T10:00:00Z",
            revokedSessionCount: 2,
            revokedContinuationCount: 1,
            replayed: false,
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v8"',
            },
          },
        );
      }),
    );

    await expect(
      phaseTwoApi.changeTenantMembershipLifecycle(
        "csrf-memory-only-value",
        tenantId,
        userId,
        "suspended",
        { etag: '"v7"', lifecycleRevision: 7 },
        "membership-lifecycle-key-0001",
        "Suspend access during offboarding review",
      ),
    ).resolves.toMatchObject({
      membershipId,
      lifecycleRevision: 8,
      etag: '"v8"',
      revokedSessionCount: 2,
      revokedContinuationCount: 1,
    });

    const request = firstRequest(requests);
    expect(request.url).toContain(
      `/api/v1/tenants/${tenantId}/users/${userId}/suspend`,
    );
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    expect(request.headers.get("If-Match")).toBe('"v7"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "membership-lifecycle-key-0001",
    );
    await expect(request.clone().json()).resolves.toEqual({
      expectedRevision: 7,
      reason: "Suspend access during offboarding review",
    });
  });

  it("rejects a tenant membership receipt whose header does not match its revision", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            tenantId,
            membershipId: "0198c97d-cf4f-7000-8000-000000000020",
            userId,
            previousStatus: "suspended",
            status: "active",
            lifecycleRevision: 8,
            etag: '"v8"',
            updatedAt: "2026-08-23T10:00:00Z",
            revokedSessionCount: 0,
            revokedContinuationCount: 0,
            replayed: true,
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: '"v9"',
            },
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.changeTenantMembershipLifecycle(
        "csrf-memory-only-value",
        tenantId,
        userId,
        "active",
        { etag: '"v7"', lifecycleRevision: 7 },
        "membership-lifecycle-key-0002",
        "Access review completed and approved",
      ),
    ).rejects.toMatchObject({ code: tenantProjectionMismatchCode });
  });

  it.each([
    [
      "an expired direct grant without an expiry",
      { ...directGrantFixture(edgeEtag), state: "expired" },
    ],
    [
      "a manual direct grant without a grantor",
      {
        ...directGrantFixture(edgeEtag),
        provenance: withoutProperty(
          roleGrantProvenanceFixture(),
          "grantedByUserId",
        ),
      },
    ],
    [
      "a manual direct grant presented as a system source",
      {
        ...directGrantFixture(edgeEtag),
        provenance: {
          ...roleGrantProvenanceFixture(),
          sourceType: "system",
        },
      },
    ],
    [
      "an identity-mapping direct grant presented as a direct source",
      {
        ...directGrantFixture(edgeEtag),
        provenance: {
          ...roleGrantProvenanceFixture(),
          sourceKind: "identity_mapping",
        },
      },
    ],
    [
      "a tenant-creation direct grant presented as a direct source",
      {
        ...directGrantFixture(edgeEtag),
        provenance: {
          ...roleGrantProvenanceFixture(),
          sourceKind: "tenant_creation",
        },
      },
    ],
    [
      "a revoked direct grant without its revocation metadata",
      { ...directGrantFixture(edgeEtag), state: "revoked" },
    ],
    [
      "an active direct grant carrying revocation metadata",
      {
        ...directGrantFixture(edgeEtag),
        revokedAt: "2026-08-23T10:30:00Z",
        revokedByUserId: userId,
        revokeReason: "Superseded",
      },
    ],
  ])("rejects %s", async (_case, grant) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ items: [grant] })),
    );

    await expect(
      phaseTwoApi.listUserRoleGrants(tenantId, userId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it.each([
    ["manual", "direct"],
    ["identity_mapping", "identity_provider"],
    ["system", "system"],
    ["tenant_creation", "system"],
    ["platform_recovery", "system"],
  ])(
    "accepts a coherent %s direct-grant owner",
    async (sourceKind, sourceType) => {
      const provenance = roleGrantProvenanceForSource(sourceKind, sourceType);
      const grant = {
        ...directGrantFixture(edgeEtag),
        managedByAuthorizationApi: sourceKind === "manual",
        provenance,
      };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [grant] })),
      );

      await expect(
        phaseTwoApi.listUserRoleGrants(tenantId, userId),
      ).resolves.toMatchObject({ items: [{ provenance }] });
    },
  );

  it.each(
    authorizationEdgeKinds.flatMap((edgeType) =>
      [
        ["string", "7"],
        ["zero", 0],
        ["fractional", 1.5],
        ["unsafe", Number.MAX_SAFE_INTEGER + 1],
        ["above the contract maximum", 2_147_483_648],
      ].map(
        ([versionType, version]) => [edgeType, versionType, version] as const,
      ),
    ),
  )(
    "rejects a %s edge with a %s version",
    async (edgeType, _versionType, version) => {
      const edge = { ...authorizationEdgeFixture(edgeType), version };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(authorizationEdgeKinds)(
    "rejects a %s edge whose ETag prefix differs from its body version",
    async (edgeType) => {
      const edge = { ...authorizationEdgeFixture(edgeType), version: 8 };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(authorizationEdgeKinds)(
    "accepts the maximum contract version for a %s edge",
    async (edgeType) => {
      const version = 2_147_483_647;
      const etag = `"v${version}-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"`;
      const edge = { ...authorizationEdgeFixture(edgeType), etag, version };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).resolves.toMatchObject({
        items: [{ etag, version }],
      });
    },
  );

  it.each(authorizationEdgeKinds)(
    "rejects a %s edge with a malformed active expiry",
    async (edgeType) => {
      const edge = authorizationEdgeFixtureWithExpiry(
        edgeType,
        "2026-02-30T10:00:00Z",
      );
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each([
    ["direct", "2026-08-24T12:00:00.123456789+02:00"],
    ["membership", "2026-08-24T03:04:05.000000001-05:30"],
    ["group-role", "2026-08-24T10:00:00.999999999Z"],
  ] as const)(
    "accepts a %s edge with a timezone-qualified nanosecond expiry",
    async (edgeType, expiresAt) => {
      const edge = authorizationEdgeFixtureWithExpiry(edgeType, expiresAt);
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
      );

      await expect(listAuthorizationEdges(edgeType)).resolves.toMatchObject({
        items: [{ provenance: { expiresAt } }],
      });
    },
  );

  it.each([
    [
      "an expired group membership without an expiry",
      "membership",
      { ...groupMembershipFixture(), state: "expired" },
    ],
    [
      "a manual group role grant without a grantor",
      "role",
      {
        ...groupRoleGrantFixture(),
        provenance: withoutProperty(
          authorizationEdgeProvenanceFixture("Manual group role"),
          "grantedByUserId",
        ),
      },
    ],
  ] as const)("rejects %s", async (_case, edgeType, edge) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ items: [edge] })),
    );

    const request =
      edgeType === "membership"
        ? phaseTwoApi.listTenantSecurityGroupMemberships(tenantId, groupId)
        : phaseTwoApi.listTenantSecurityGroupRoleGrants(tenantId, groupId);
    await expect(request).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("sends CSRF and If-Match only on the request and never writes browser storage", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (input instanceof Request) {
        requests.push(input);
      }
      return jsonResponse({ ...roleFixture(), version: 4 }, '"v4"');
    });
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    vi.stubGlobal("fetch", fetchMock);

    await phaseTwoApi.updateTenantRole(
      "csrf-memory-only-value",
      tenantId,
      roleId,
      '"v3"',
      { name: "Updated role" },
    );

    const request = firstRequest(requests);
    expect(request.method).toBe("PATCH");
    expect(request.headers.get("If-Match")).toBe('"v3"');
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    expect(storageWrite).not.toHaveBeenCalled();
  });

  it("uses the source-qualified group edge route with CSRF and the representation-bound If-Match", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) {
          requests.push(input);
        }
        return new Response(null, { status: 204 });
      }),
    );

    await phaseTwoApi.revokeTenantSecurityGroupMembership(
      "csrf-memory-only-value",
      tenantId,
      groupId,
      membershipEdgeId,
      edgeEtag,
      { reason: "Rotation completed" },
    );

    const request = firstRequest(requests);
    expect(request.url).toContain(
      `/api/v1/tenants/${tenantId}/groups/${groupId}/memberships/${membershipEdgeId}/revoke`,
    );
    expect(request.method).toBe("POST");
    expect(request.headers.get("If-Match")).toBe(edgeEtag);
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    await expect(request.clone().json()).resolves.toEqual({
      reason: "Rotation completed",
    });
  });

  it("returns the strong ETag with a tenant-safe security-group detail", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) {
          requests.push(input);
        }
        return jsonResponse(groupFixture(), '"v3"');
      }),
    );

    await expect(
      phaseTwoApi.getTenantSecurityGroup(tenantId, groupId),
    ).resolves.toEqual({ etag: '"v3"', value: groupFixture() });
    expect(firstRequest(requests).url).toContain(
      `/api/v1/tenants/${tenantId}/groups/${groupId}`,
    );
  });

  it.each([
    "not-an-instant",
    "2026-02-30T10:00:00Z",
    "2026-08-24T10:00:00.1234567891Z",
    "2026-08-24T10:00:00+24:00",
  ])("rejects a malformed delegation horizon %s", async (delegableUntil) => {
    const authority = authorityFixture(validDirectAuthorityPathFixture());
    authority.permissions = [{ permissionKey: "role.grant", scope: "tenant" }];
    authority.delegationCeiling = [
      { delegableUntil, permissionKey: "role.grant", scope: "tenant" },
    ];

    await expectAuthorityProjectionRejected(authority);
  });

  it.each([
    [
      "malformed team identifier",
      [{ operatorTeamId: "not-a-uuid", assignmentEpochId }],
    ],
    [
      "malformed assignment epoch identifier",
      [{ operatorTeamId, assignmentEpochId: "not-a-uuid" }],
    ],
    [
      "duplicate team with another epoch",
      [
        { operatorTeamId, assignmentEpochId },
        { operatorTeamId, assignmentEpochId: otherAssignmentEpochId },
      ],
    ],
    [
      "duplicate epoch with another team",
      [
        { operatorTeamId, assignmentEpochId },
        { operatorTeamId: otherRoleId, assignmentEpochId },
      ],
    ],
  ])("rejects %s in authority relationships", async (_name, relationships) => {
    const authority = authorityFixture(validDirectAuthorityPathFixture());
    authority.operatorTeamRelationships = relationships;

    await expectAuthorityProjectionRejected(authority);
  });

  it.each(["2026-08-23T09:59:59.999999999Z", "2026-08-23T10:00:00Z"])(
    "rejects a delegation horizon that is already expired at evaluation (%s)",
    async (delegableUntil) => {
      const authority = authorityFixture(validDirectAuthorityPathFixture());
      authority.permissions = [
        { permissionKey: "role.grant", scope: "tenant" },
      ];
      authority.delegationCeiling = [
        { delegableUntil, permissionKey: "role.grant", scope: "tenant" },
      ];

      await expectAuthorityProjectionRejected(authority);
    },
  );

  it.each([
    "2026-08-24T12:00:00.123456789+02:00",
    "2026-08-24T03:04:05.000000001-05:30",
  ])(
    "accepts a future delegation horizon with offset and nanosecond precision (%s)",
    async (delegableUntil) => {
      const authority = authorityFixture(validDirectAuthorityPathFixture());
      authority.permissions = [
        { permissionKey: "role.grant", scope: "tenant" },
      ];
      authority.delegationCeiling = [
        { delegableUntil, permissionKey: "role.grant", scope: "tenant" },
      ];
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse(authority)),
      );

      await expect(
        phaseTwoApi.getTenantAuthority(tenantId),
      ).resolves.toMatchObject({
        delegationCeiling: [
          { delegableUntil, permissionKey: "role.grant", scope: "tenant" },
        ],
      });
    },
  );

  it.each([
    ["a missing direct branch", { pathType: "direct" }],
    [
      "both authority branches",
      {
        direct: directAuthorityPathFixture(),
        group: {},
        pathType: "direct",
      },
    ],
    [
      "retired direct provenance",
      {
        direct: {
          ...directAuthorityPathFixture(),
          provenance: {
            ...roleGrantProvenanceFixture(),
            retiredAt: "2026-08-23T09:00:00Z",
          },
        },
        pathType: "direct",
      },
    ],
    [
      "retired group membership-edge provenance",
      groupAuthorityPathFixture("membership"),
    ],
    ["retired group role-edge provenance", groupAuthorityPathFixture("role")],
  ])("rejects %s in an effective role path", async (_case, path) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(authorityFixture(path))),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("rejects retired compatible provenance on an effective grant", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          authorityFixture(
            {
              direct: directAuthorityPathFixture(),
              pathType: "direct",
            },
            {
              ...roleGrantProvenanceFixture(),
              retiredAt: "2026-08-23T09:00:00Z",
            },
          ),
        ),
      ),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("rejects manual effective provenance without a grantor", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          authorityFixture(
            {
              direct: {
                ...directAuthorityPathFixture(),
                provenance: withoutProperty(
                  roleGrantProvenanceFixture(),
                  "grantedByUserId",
                ),
              },
              pathType: "direct",
            },
            withoutProperty(roleGrantProvenanceFixture(), "grantedByUserId"),
          ),
        ),
      ),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it.each([
    ["manual", roleGrantProvenanceFixture()],
    [
      "identity mapping",
      roleGrantProvenanceForSource("identity_mapping", "identity_provider"),
    ],
    ["system", roleGrantProvenanceForSource("system", "system")],
    [
      "tenant creation",
      roleGrantProvenanceForSource("tenant_creation", "system"),
    ],
    [
      "platform recovery",
      roleGrantProvenanceForSource("platform_recovery", "system"),
    ],
  ])(
    "accepts coherent %s direct effective provenance",
    async (_case, provenance) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            authorityFixture(
              {
                direct: {
                  grantId,
                  provenance: { ...provenance },
                },
                pathType: "direct",
              },
              { ...provenance },
            ),
          ),
        ),
      );

      await expect(
        phaseTwoApi.getTenantAuthority(tenantId),
      ).resolves.toMatchObject({
        roleGrants: [{ grantId, path: { pathType: "direct" } }],
      });
    },
  );

  it.each([
    ["manual", authorizationEdgeProvenanceFixture("Manual group role")],
    [
      "identity mapping",
      authorizationEdgeProvenanceForSource("identity_mapping"),
    ],
    [
      "platform recovery",
      authorizationEdgeProvenanceForSource("platform_recovery"),
    ],
  ])("accepts coherent %s group effective provenance", async (_case, edge) => {
    const provenance = groupRoleGrantProvenanceFixture(edge);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            authorityFixture(
              groupAuthorityPathFixture(undefined, edge),
              provenance,
            ),
          ),
        ),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).resolves.toMatchObject({
      roleGrants: [{ grantId, path: { pathType: "group" } }],
    });
  });

  it("accepts semantically equal direct provenance and effective expiry instants", async () => {
    const provenance = {
      ...roleGrantProvenanceFixture(),
      expiresAt: "2026-08-24T10:00:00.123456789Z",
    };
    const nestedProvenance = {
      ...provenance,
      expiresAt: "2026-08-24T12:00:00.123456789+02:00",
      grantedAt: "2026-08-22T12:00:00+02:00",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          authorityFixture(
            {
              direct: { grantId, provenance: nestedProvenance },
              pathType: "direct",
            },
            provenance,
            "2026-08-24T06:00:00.123456789-04:00",
          ),
        ),
      ),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).resolves.toMatchObject({
      roleGrants: [
        { effectiveExpiresAt: "2026-08-24T06:00:00.123456789-04:00" },
      ],
    });
  });

  it("accepts the semantic earliest expiry across both group edges", async () => {
    const roleEdge = {
      ...authorizationEdgeProvenanceFixture("Manual group role"),
      expiresAt: "2026-08-25T10:00:00.987654321Z",
    };
    const membershipEdge = {
      ...authorizationEdgeProvenanceFixture("Manual group membership"),
      expiresAt: "2026-08-24T10:00:00.123456789Z",
    };
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            authorityFixture(
              groupAuthorityPathFixture(undefined, roleEdge, membershipEdge),
              groupRoleGrantProvenanceFixture(roleEdge),
              "2026-08-24T12:00:00.123456789+02:00",
            ),
          ),
        ),
    );

    await expect(
      phaseTwoApi.getTenantAuthority(tenantId),
    ).resolves.toMatchObject({
      roleGrants: [
        { effectiveExpiresAt: "2026-08-24T12:00:00.123456789+02:00" },
      ],
    });
  });

  it.each(
    (["direct", "group"] as const).flatMap((pathType) =>
      [
        ["at evaluation", "2026-08-23T10:00:00Z"],
        ["before evaluation", "2026-08-23T09:59:59.999999999Z"],
      ].map(([horizon, expiresAt]) => ({ expiresAt, horizon, pathType })),
    ),
  )(
    "rejects a $pathType effective role path expiring $horizon",
    async ({ expiresAt, pathType }) => {
      if (pathType === "direct") {
        const provenance = { ...roleGrantProvenanceFixture(), expiresAt };
        await expectAuthorityProjectionRejected(
          authorityFixture(
            {
              direct: { grantId, provenance: { ...provenance } },
              pathType: "direct",
            },
            provenance,
            expiresAt,
          ),
        );
        return;
      }

      const roleEdge = {
        ...authorizationEdgeProvenanceFixture("Manual group role"),
        expiresAt,
      };
      await expectAuthorityProjectionRejected(
        authorityFixture(
          groupAuthorityPathFixture(undefined, roleEdge),
          groupRoleGrantProvenanceFixture(roleEdge),
          expiresAt,
        ),
      );
    },
  );

  it("rejects matching unknown group provenance source kinds", async () => {
    const edge = authorizationEdgeProvenanceForSource("future_source");
    await expectAuthorityProjectionRejected(
      authorityFixture(
        groupAuthorityPathFixture(undefined, edge),
        groupRoleGrantProvenanceFixture(edge),
      ),
    );
  });

  it.each([
    [
      "top-level group provenance",
      groupAuthorityPathFixture(),
      withoutProperty(groupRoleGrantProvenanceFixture(), "grantedByUserId"),
    ],
    [
      "group role edge provenance",
      groupAuthorityPathFixture(
        undefined,
        withoutProperty(
          authorizationEdgeProvenanceFixture("Manual group role"),
          "grantedByUserId",
        ),
      ),
      groupRoleGrantProvenanceFixture(),
    ],
    [
      "group membership edge provenance",
      groupAuthorityPathFixture(
        undefined,
        undefined,
        withoutProperty(
          authorizationEdgeProvenanceFixture("Manual group membership"),
          "grantedByUserId",
        ),
      ),
      groupRoleGrantProvenanceFixture(),
    ],
  ])(
    "rejects a missing manual grantor on %s",
    async (_case, path, provenance) => {
      await expectAuthorityProjectionRejected(
        authorityFixture(path, provenance),
      );
    },
  );

  it.each([
    [
      "source",
      roleGrantProvenanceForSource("identity_mapping", "identity_provider"),
    ],
    ["source id", { ...roleGrantProvenanceFixture(), sourceId: groupId }],
    ["grantor", { ...roleGrantProvenanceFixture(), grantedByUserId: groupId }],
    ["reason", { ...roleGrantProvenanceFixture(), reason: "Other reason" }],
    [
      "authoritative flag",
      { ...roleGrantProvenanceFixture(), authoritative: true },
    ],
    [
      "grant instant",
      {
        ...roleGrantProvenanceFixture(),
        grantedAt: "2026-08-22T10:00:00.000000001Z",
      },
    ],
    [
      "expiry",
      {
        ...roleGrantProvenanceFixture(),
        expiresAt: "2026-08-24T10:00:00Z",
      },
    ],
  ])("rejects a direct top/nested %s mismatch", async (_case, nested) => {
    await expectAuthorityProjectionRejected(
      authorityFixture(
        {
          direct: { grantId, provenance: nested },
          pathType: "direct",
        },
        roleGrantProvenanceFixture(),
      ),
    );
  });

  it.each([
    [
      "source",
      groupRoleGrantProvenanceFixture(
        authorizationEdgeProvenanceForSource("identity_mapping"),
      ),
    ],
    ["source id", { ...groupRoleGrantProvenanceFixture(), sourceId: groupId }],
    [
      "grantor",
      { ...groupRoleGrantProvenanceFixture(), grantedByUserId: groupId },
    ],
    [
      "reason",
      { ...groupRoleGrantProvenanceFixture(), reason: "Other reason" },
    ],
    [
      "authoritative flag",
      { ...groupRoleGrantProvenanceFixture(), authoritative: true },
    ],
    [
      "grant instant",
      {
        ...groupRoleGrantProvenanceFixture(),
        grantedAt: "2026-08-22T10:00:00.000000001Z",
      },
    ],
    [
      "expiry",
      {
        ...groupRoleGrantProvenanceFixture(),
        expiresAt: "2026-08-24T10:00:00Z",
      },
    ],
  ])("rejects a group top/role-edge %s mismatch", async (_case, provenance) => {
    await expectAuthorityProjectionRejected(
      authorityFixture(groupAuthorityPathFixture(), provenance),
    );
  });

  it.each([
    [
      "an omitted direct effective expiry",
      authorityFixture(
        {
          direct: {
            grantId,
            provenance: {
              ...roleGrantProvenanceFixture(),
              expiresAt: "2026-08-24T10:00:00Z",
            },
          },
          pathType: "direct",
        },
        {
          ...roleGrantProvenanceFixture(),
          expiresAt: "2026-08-24T10:00:00Z",
        },
      ),
    ],
    [
      "a direct effective expiry on an unbounded path",
      authorityFixture(
        { direct: directAuthorityPathFixture(), pathType: "direct" },
        roleGrantProvenanceFixture(),
        "2026-08-24T10:00:00Z",
      ),
    ],
    [
      "a direct effective expiry that differs by one nanosecond",
      authorityFixture(
        {
          direct: {
            grantId,
            provenance: {
              ...roleGrantProvenanceFixture(),
              expiresAt: "2026-08-24T10:00:00.000000001Z",
            },
          },
          pathType: "direct",
        },
        {
          ...roleGrantProvenanceFixture(),
          expiresAt: "2026-08-24T10:00:00.000000001Z",
        },
        "2026-08-24T10:00:00.000000002Z",
      ),
    ],
    [
      "a later group-edge expiry instead of the earliest expiry",
      (() => {
        const roleEdge = {
          ...authorizationEdgeProvenanceFixture("Manual group role"),
          expiresAt: "2026-08-25T10:00:00Z",
        };
        const membershipEdge = {
          ...authorizationEdgeProvenanceFixture("Manual group membership"),
          expiresAt: "2026-08-24T10:00:00Z",
        };
        return authorityFixture(
          groupAuthorityPathFixture(undefined, roleEdge, membershipEdge),
          groupRoleGrantProvenanceFixture(roleEdge),
          "2026-08-25T10:00:00Z",
        );
      })(),
    ],
    [
      "an omitted group effective expiry",
      (() => {
        const roleEdge = {
          ...authorizationEdgeProvenanceFixture("Manual group role"),
          expiresAt: "2026-08-25T10:00:00Z",
        };
        return authorityFixture(
          groupAuthorityPathFixture(undefined, roleEdge),
          groupRoleGrantProvenanceFixture(roleEdge),
        );
      })(),
    ],
    [
      "a group effective expiry on two unbounded edges",
      authorityFixture(
        groupAuthorityPathFixture(),
        groupRoleGrantProvenanceFixture(),
        "2026-08-24T10:00:00Z",
      ),
    ],
  ])("rejects %s", async (_case, authority) => {
    await expectAuthorityProjectionRejected(authority);
  });

  it("uses the current service-account ETag for metadata updates", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            ...serviceAccountFixture(),
            displayName: "Updated collector",
            version: 4,
          },
          '"v4"',
        );
      }),
    );

    await phaseTwoApi.updateTenantServiceAccount(
      "csrf-memory-only-value",
      tenantId,
      serviceAccountId,
      '"v3"',
      { displayName: "Updated collector" },
    );

    const request = firstRequest(requests);
    expect(request.headers.get("If-Match")).toBe('"v3"');
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    expect(request.cache).toBe("no-store");
  });

  it("rejects a human role in the machine-role grant projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...serviceAccountRoleGrantFixture(),
              role: {
                ...serviceAccountRoleGrantFixture().role,
                principalKind: "human",
              },
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listTenantServiceAccountRoleGrants(
        tenantId,
        serviceAccountId,
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it.each([
    [
      "omitted ownership",
      (() => {
        const { managedByServiceAccountApi: _omitted, ...grant } =
          serviceAccountRoleGrantFixture();
        return grant;
      })(),
    ],
    [
      "managed ownership on an inactive grant",
      { ...serviceAccountRoleGrantFixture(), state: "expired" },
    ],
  ])(
    "rejects %s in the service-account role projection",
    async (_case, grant) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse({ items: [grant] })),
      );

      await expect(
        phaseTwoApi.listTenantServiceAccountRoleGrants(
          tenantId,
          serviceAccountId,
        ),
      ).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it("requires no-store before releasing a one-time credential token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            bearerToken: `periapsis_api_v1.${"a".repeat(80)}`,
            credential: serviceAccountCredentialFixture(),
          },
          '"v3"',
          201,
        ),
      ),
    );

    await expect(
      phaseTwoApi.issueTenantServiceAccountCredential(
        "csrf-memory-only-value",
        tenantId,
        serviceAccountId,
        "0198c97d-cf4f-7000-8000-000000000099",
        {
          allowedNetworks: [],
          expiresAt: "2026-09-20T10:00:00Z",
          label: "Primary collector",
          permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
        },
      ),
    ).rejects.toMatchObject({
      message:
        "The API did not mark the one-time credential response as no-store.",
    });
  });

  it("accepts only PostgreSQL-ordered canonical credential networks", async () => {
    const canonicalNetworks = [
      "2.0.0.0/8",
      "10.0.0.0/8",
      "10.0.0.0/9",
      "10.128.0.0/9",
      "2001:db8::/32",
      "2001:db8::/48",
      "2001:db8:1::/48",
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...serviceAccountCredentialFixture(),
              allowedNetworks: canonicalNetworks,
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listTenantServiceAccountCredentials(
        tenantId,
        serviceAccountId,
      ),
    ).resolves.toMatchObject({
      items: [{ allowedNetworks: canonicalNetworks }],
    });
  });

  it("rejects credential networks returned in lexical rather than PostgreSQL order", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...serviceAccountCredentialFixture(),
              allowedNetworks: ["10.0.0.0/8", "2.0.0.0/8"],
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listTenantServiceAccountCredentials(
        tenantId,
        serviceAccountId,
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it("returns the one-time token only from a no-store secret response", async () => {
    const bearerToken = `periapsis_api_v1.${"a".repeat(80)}`;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            bearerToken,
            credential: serviceAccountCredentialFixture(),
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v3"',
            },
            status: 201,
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.issueTenantServiceAccountCredential(
        "csrf-memory-only-value",
        tenantId,
        serviceAccountId,
        "0198c97d-cf4f-7000-8000-000000000099",
        {
          allowedNetworks: [],
          expiresAt: "2026-09-20T10:00:00Z",
          label: "Primary collector",
          permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
        },
      ),
    ).resolves.toMatchObject({ bearerToken });
  });

  it("preserves only safe one-time replay reconciliation metadata", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "one_time_secret_already_issued",
            credentialId,
            location: `/api/v1/tenants/${tenantId}/service-accounts/${serviceAccountId}/credentials/${credentialId}`,
            requestId: "0198c97d-cf4f-7000-8000-000000000099",
            status: 409,
            title: "One-time credential secret already issued",
            type: "/problems/one-time-secret-already-issued",
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/problem+json",
            },
            status: 409,
          },
        ),
      ),
    );

    await expect(
      phaseTwoApi.issueTenantServiceAccountCredential(
        "csrf-memory-only-value",
        tenantId,
        serviceAccountId,
        "0198c97d-cf4f-7000-8000-000000000099",
        {
          allowedNetworks: [],
          expiresAt: "2026-09-20T10:00:00Z",
          label: "Primary collector",
          permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
        },
      ),
    ).rejects.toMatchObject({
      code: "one_time_secret_already_issued",
      credentialId,
      location: expect.stringContaining(credentialId),
      status: 409,
    });
  });

  it("rejects secret-shaped fields in redacted credential inventory", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...serviceAccountCredentialFixture(),
              bearerToken: `periapsis_api_v1.${"a".repeat(80)}`,
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listTenantServiceAccountCredentials(
        tenantId,
        serviceAccountId,
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });

  it.each([
    [
      "after the representation update",
      {
        lastUsedAt: "2026-08-23T10:00:00Z",
        updatedAt: "2026-08-22T10:00:00Z",
      },
    ],
    [
      "after credential expiry",
      {
        lastUsedAt: "2026-09-21T10:00:00Z",
        updatedAt: "2026-09-22T10:00:00Z",
      },
    ],
  ])("rejects a credential last-used instant %s", async (_case, overrides) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...serviceAccountCredentialFixture(),
              ...overrides,
              lastUsedIp: "192.0.2.10",
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listTenantServiceAccountCredentials(
        tenantId,
        serviceAccountId,
      ),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
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

async function expectAuthorityProjectionRejected(authority: unknown) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(authority)));
  await expect(phaseTwoApi.getTenantAuthority(tenantId)).rejects.toMatchObject({
    message: "The API response did not match the requested tenant projection.",
  });
}

function firstRequest(requests: readonly Request[]): Request {
  const request = requests[0];
  if (!request) {
    throw new Error("The generated client did not call fetch.");
  }
  return request;
}

function roleFixture(): TenantRoleView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    description: "Tenant role",
    id: roleId,
    key: "custom_triage",
    name: "Custom triage",
    policy: { delegationCeiling: [], permissions: [] },
    principalKind: "human",
    system: false,
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
  };
}

describe("tenant role and authority policy read bounds", () => {
  const permissions = tenantPermissionKeys
    .flatMap((permissionKey) =>
      tenantAuthorizationScopes.map((scope) => ({ permissionKey, scope })),
    )
    .slice(0, 176);

  it("hydrates a built-in role policy larger than the custom-role write limit", async () => {
    const role = {
      ...roleFixture(),
      key: "tenant_admin",
      system: true,
      policy: { permissions, delegationCeiling: permissions },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(role, '"v3"')),
    );
    await expect(phaseTwoApi.getTenantRole(tenantId, roleId)).resolves.toEqual({
      etag: '"v3"',
      value: role,
    });
    expect(permissions).toHaveLength(176);
  });

  it("hydrates effective authority larger than the custom-role write limit", async () => {
    const authority = {
      ...authorityFixture(validDirectAuthorityPathFixture()),
      permissions,
      delegationCeiling: permissions,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(authority)));
    await expect(phaseTwoApi.getTenantAuthority(tenantId)).resolves.toEqual(
      authority,
    );
  });

  it.each(["permissions", "delegationCeiling"])(
    "rejects a role %s array above the read hydration bound",
    async (field) => {
      const role = roleFixture();
      Object.assign(role.policy, {
        [field]: Array.from({ length: 501 }, () => permissions[0]),
      });
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse(role, '"v3"')),
      );
      await expect(
        phaseTwoApi.getTenantRole(tenantId, roleId),
      ).rejects.toMatchObject({
        message:
          "The API response did not match the requested tenant projection.",
      });
    },
  );

  it.each(["permissions", "delegationCeiling"])(
    "rejects an effective %s array above the read hydration bound",
    async (field) => {
      const authority = {
        ...authorityFixture(validDirectAuthorityPathFixture()),
        [field]: Array.from({ length: 501 }, () => permissions[0]),
      };
      await expectAuthorityProjectionRejected(authority);
    },
  );

  describe.each(["role", "authority"] as const)("%s policy tuples", (kind) => {
    const tuple = { permissionKey: "case.read", scope: "tenant" };

    async function readPolicy(policy: {
      permissions: unknown[];
      delegationCeiling: unknown[];
    }) {
      const response =
        kind === "role"
          ? { ...roleFixture(), policy }
          : {
              ...authorityFixture(validDirectAuthorityPathFixture()),
              ...policy,
            };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(jsonResponse(response, '"v3"')),
      );
      return kind === "role"
        ? phaseTwoApi.getTenantRole(tenantId, roleId)
        : phaseTwoApi.getTenantAuthority(tenantId);
    }

    it("preserves distinct scopes and an exact reordered delegation subset", async () => {
      const ownTuple = { ...tuple, scope: "own" };
      const policy = {
        permissions: [tuple, ownTuple],
        delegationCeiling: [ownTuple, tuple],
      };
      await expect(readPolicy(policy)).resolves.toMatchObject(
        kind === "role" ? { value: { policy } } : policy,
      );
    });

    describe.each(["permissions", "delegationCeiling"] as const)(
      "%s",
      (field) => {
        it.each([
          { name: "duplicate exact tuples", values: [tuple, { ...tuple }] },
          {
            name: "unknown permission",
            values: [{ ...tuple, permissionKey: "future.permission" }],
          },
          {
            name: "platform permission",
            values: [{ ...tuple, permissionKey: "platform.tenant.read" }],
          },
          {
            name: "unknown scope",
            values: [{ ...tuple, scope: "future_scope" }],
          },
          { name: "platform scope", values: [{ ...tuple, scope: "platform" }] },
          { name: "missing permission", values: [{ scope: "tenant" }] },
          { name: "missing scope", values: [{ permissionKey: "case.read" }] },
          { name: "null tuple", values: [null] },
          { name: "string tuple", values: ["case.read@tenant"] },
        ])("rejects $name", async ({ values }) => {
          await expect(
            readPolicy({
              permissions: [tuple],
              delegationCeiling: [],
              [field]: values,
            }),
          ).rejects.toMatchObject({ code: tenantProjectionMismatchCode });
        });
      },
    );

    it.each([
      { name: "missing permission", permissions: [] },
      {
        name: "same permission with a different scope",
        permissions: [{ ...tuple, scope: "own" }],
      },
    ])(
      "rejects delegation with $name",
      async ({ permissions: grantedPermissions }) => {
        await expect(
          readPolicy({
            permissions: grantedPermissions,
            delegationCeiling: [tuple],
          }),
        ).rejects.toMatchObject({ code: tenantProjectionMismatchCode });
      },
    );
  });

  it("rejects duplicate effective tuples with different delegation horizons", async () => {
    const tuple = { permissionKey: "role.grant", scope: "tenant" };
    await expectAuthorityProjectionRejected({
      ...authorityFixture(validDirectAuthorityPathFixture()),
      permissions: [tuple],
      delegationCeiling: [
        { ...tuple, delegableUntil: "2026-08-24T10:00:00Z" },
        { ...tuple, delegableUntil: "2026-08-25T10:00:00Z" },
      ],
    });
  });
});

function groupFixture(): TenantSecurityGroupView {
  return {
    archived: false,
    createdAt: "2026-08-20T10:00:00Z",
    description: "Incident response coordinators",
    id: groupId,
    key: "ir_leads",
    name: "IR leads",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
  };
}

function serviceAccountFixture(): ServiceAccountView {
  return {
    createdAt: "2026-08-20T10:00:00Z",
    createdByMembershipId: "0198c97d-cf4f-7000-8000-000000000020",
    description: "Forwards governed alert events",
    displayName: "Primary collector",
    id: serviceAccountId,
    key: "primary_collector",
    principalType: "service_account",
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
  };
}

function serviceAccountRoleGrantFixture(): ServiceAccountRoleGrantView {
  return {
    etag: edgeEtag,
    id: grantId,
    managedByServiceAccountApi: true,
    provenance: {
      authoritative: false,
      grantedAt: "2026-08-22T10:00:00Z",
      grantedByUserId: userId,
      reason: "Collector requires alert ingest",
      sourceId: grantId,
      sourceKind: "manual",
    },
    role: {
      id: roleId,
      key: "service_account",
      name: "Service account",
      principalKind: "service_account",
      system: true,
    },
    serviceAccountId,
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 7,
  };
}

function serviceAccountCredentialFixture(): ServiceAccountCredentialView {
  return {
    allowedNetworks: [],
    etag: '"v3"',
    expiresAt: "2026-09-20T10:00:00Z",
    id: credentialId,
    issuedAt: "2026-08-22T10:00:00Z",
    issuedByMembershipId: "0198c97d-cf4f-7000-8000-000000000020",
    label: "Primary collector",
    permissions: [{ permissionKey: "alert.create", scope: "tenant" }],
    serviceAccountId,
    state: "active",
    tenantId,
    updatedAt: "2026-08-22T10:00:00Z",
    version: 3,
  };
}

function versionedResourceFixture(
  resource: "group" | "role",
  version: number,
): TenantRoleView | TenantSecurityGroupView {
  return resource === "role"
    ? { ...roleFixture(), version }
    : { ...groupFixture(), version };
}

function authorizationEdgeFixture(
  edgeType: AuthorizationEdgeKind,
): Record<string, unknown> {
  switch (edgeType) {
    case "direct":
      return directGrantFixture(edgeEtag);
    case "membership":
      return groupMembershipFixture();
    case "group-role":
      return groupRoleGrantFixture();
    default:
      throw new Error("Unsupported authorization edge kind.");
  }
}

function authorizationEdgeFixtureWithExpiry(
  edgeType: AuthorizationEdgeKind,
  expiresAt: string,
): Record<string, unknown> {
  const edge = authorizationEdgeFixture(edgeType);
  const provenance = edge.provenance;
  if (
    typeof provenance !== "object" ||
    provenance === null ||
    Array.isArray(provenance)
  ) {
    throw new Error("The authorization edge fixture has no provenance.");
  }
  return {
    ...edge,
    provenance: {
      ...provenance,
      expiresAt,
    },
  };
}

function listAuthorizationEdges(
  edgeType: AuthorizationEdgeKind,
): Promise<unknown> {
  switch (edgeType) {
    case "direct":
      return phaseTwoApi.listUserRoleGrants(tenantId, userId);
    case "membership":
      return phaseTwoApi.listTenantSecurityGroupMemberships(tenantId, groupId);
    case "group-role":
      return phaseTwoApi.listTenantSecurityGroupRoleGrants(tenantId, groupId);
    default:
      throw new Error("Unsupported authorization edge kind.");
  }
}

function directGrantFixture(etag: string): Record<string, unknown> {
  const { policy: _policy, ...role } = roleFixture();
  return {
    etag,
    id: grantId,
    managedByAuthorizationApi: true,
    pathType: "direct",
    provenance: roleGrantProvenanceFixture(),
    role,
    state: "active",
    tenantId,
    updatedAt: "2026-08-23T10:00:00Z",
    userId,
    version: 7,
  };
}

function groupMembershipFixture(): Record<string, unknown> {
  return {
    etag: edgeEtag,
    group: groupFixture(),
    id: membershipEdgeId,
    managedByAuthorizationApi: true,
    member: {
      createdAt: "2026-08-20T10:00:00Z",
      etag: '"v1"',
      legacyMembershipRole: "analyst",
      lifecycleRevision: 1,
      membershipId: "0198c97d-cf4f-7000-8000-000000000020",
      membershipStatus: "active",
      tenantId,
      updatedAt: "2026-08-22T10:00:00Z",
      user: {
        active: true,
        displayName: "Case analyst",
        email: "analyst@example.test",
        id: userId,
      },
    },
    provenance: authorizationEdgeProvenanceFixture("Manual group membership"),
    state: "active",
    tenantId,
    updatedAt: "2026-08-23T10:00:00Z",
    version: 7,
  };
}

function groupRoleGrantFixture(): Record<string, unknown> {
  const { policy: _policy, ...role } = roleFixture();
  return {
    etag: edgeEtag,
    group: groupFixture(),
    id: grantId,
    managedByAuthorizationApi: true,
    provenance: authorizationEdgeProvenanceFixture("Manual group role"),
    role,
    state: "active",
    tenantId,
    updatedAt: "2026-08-23T10:00:00Z",
    version: 7,
  };
}

function authorityFixture(
  path: unknown,
  provenance: Record<string, unknown> = roleGrantProvenanceFixture(),
  effectiveExpiresAt?: string,
): Record<string, unknown> {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-23T10:00:00Z",
    legacyMembershipRole: "analyst",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [],
    roleGrants: [
      {
        ...(effectiveExpiresAt === undefined ? {} : { effectiveExpiresAt }),
        grantId,
        path,
        provenance,
        roleId,
        roleKey: "custom_triage",
        roleName: "Custom triage",
      },
    ],
    tenantId,
    userId: "0198c97d-cf4f-7000-8000-000000000021",
  };
}

function directAuthorityPathFixture(): Record<string, unknown> {
  return {
    grantId,
    provenance: roleGrantProvenanceFixture(),
  };
}

function validDirectAuthorityPathFixture(): Record<string, unknown> {
  return { direct: directAuthorityPathFixture(), pathType: "direct" };
}

function groupAuthorityPathFixture(
  retiredEdge?: "membership" | "role",
  roleProvenance: Record<string, unknown> = authorizationEdgeProvenanceFixture(
    "Manual group role",
  ),
  membershipProvenance: Record<
    string,
    unknown
  > = authorizationEdgeProvenanceFixture("Manual group membership"),
): unknown {
  return {
    group: {
      group: { id: groupId, key: "ir_leads", name: "IR leads" },
      membershipEdge: {
        id: "0198c97d-cf4f-7000-8000-000000000091",
        provenance:
          retiredEdge === "membership"
            ? { ...membershipProvenance, retiredAt: "2026-08-23T09:00:00Z" }
            : membershipProvenance,
      },
      roleGrantEdge: {
        id: grantId,
        provenance:
          retiredEdge === "role"
            ? { ...roleProvenance, retiredAt: "2026-08-23T09:00:00Z" }
            : roleProvenance,
      },
    },
    pathType: "group",
  };
}

function authorizationEdgeProvenanceFixture(
  reason: string,
): Record<string, unknown> {
  return {
    authoritative: false,
    grantedAt: "2026-08-22T10:00:00Z",
    grantedByUserId: "0198c97d-cf4f-7000-8000-000000000021",
    reason,
    sourceId: "0198c97d-cf4f-7000-8000-000000000092",
    sourceKind: "manual",
  };
}

function authorizationEdgeProvenanceForSource(
  sourceKind: string,
): Record<string, unknown> {
  const provenance = authorizationEdgeProvenanceFixture("Mapped group role");
  provenance.sourceKind = sourceKind;
  if (sourceKind !== "manual") {
    delete provenance.grantedByUserId;
  }
  return provenance;
}

function groupRoleGrantProvenanceFixture(
  edge: Record<string, unknown> = authorizationEdgeProvenanceFixture(
    "Manual group role",
  ),
): Record<string, unknown> {
  return { ...edge, sourceType: "group" };
}

function roleGrantProvenanceFixture(): Record<string, unknown> {
  return {
    authoritative: false,
    grantedAt: "2026-08-22T10:00:00Z",
    grantedByUserId: "0198c97d-cf4f-7000-8000-000000000021",
    reason: "Manual role decision",
    sourceId: grantId,
    sourceKind: "manual",
    sourceType: "direct",
  };
}

function roleGrantProvenanceForSource(
  sourceKind: string,
  sourceType: string,
): Record<string, unknown> {
  const provenance: Record<string, unknown> = {
    ...roleGrantProvenanceFixture(),
    sourceKind,
    sourceType,
  };
  if (sourceKind !== "manual") {
    delete provenance.grantedByUserId;
  }
  return provenance;
}

function withoutProperty(
  value: Record<string, unknown>,
  property: string,
): Record<string, unknown> {
  const copy = { ...value };
  delete copy[property];
  return copy;
}

function isUnknownRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
