import { afterEach, describe, expect, it, vi } from "vitest";

import { workflowAdministrationApi } from "./workflow-api";
import {
  alertWorkflowFixture,
  alertWorkflowId,
  alertWorkflowVersionFixture,
  workflowSimulationFixture,
  workflowTenantId,
} from "./workflow-test-fixtures";

const workflowEtagV1 = '"v1-_VFDEoAgKP5tR_AyfYsxkZwrjrziGnhwdGR6LyK4ovU"';
const workflowEtagV2 = '"v2-_VFDEoAgKP5tR_AyfYsxkZwrjrziGnhwdGR6LyK4ovU"';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("workflowAdministrationApi", () => {
  it("binds publication to same-origin credentials, CSRF, idempotency, and the lineage ETag", async () => {
    const requests: Request[] = [];
    const canonicalTransition = {
      ...alertWorkflowFixture.current.transitions[0]!,
      requiredPermissions: ["alert.update", "alert.assign"] as const,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            replayed: false,
            workflow: {
              ...alertWorkflowFixture,
              revision: 2,
              currentVersion: 2,
              current: {
                ...alertWorkflowFixture.current,
                transitions: [canonicalTransition],
                version: 2,
              },
              updatedAt: "2026-08-26T09:00:00Z",
            },
          },
          workflowEtagV2,
        );
      }),
    );

    await expect(
      workflowAdministrationApi.publish({
        body: {
          design: {
            states: alertWorkflowFixture.current.states,
            transitions: [
              {
                ...canonicalTransition,
                requiredPermissions: ["alert.assign", "alert.update"],
              },
            ],
          },
          expectedRevision: 1,
        },
        csrfToken: "csrf-memory-only",
        etag: workflowEtagV1,
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000299",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).resolves.toMatchObject({ value: { revision: 2 } });

    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.credentials).toBe("same-origin");
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request!.headers.get("Idempotency-Key")).toBe(
      "01991c20-7d5f-7000-8000-000000000299",
    );
    expect(request!.headers.get("If-Match")).toBe(workflowEtagV1);
    await expect(request!.clone().json()).resolves.toMatchObject({
      design: {
        transitions: [
          { requiredPermissions: ["alert.update", "alert.assign"] },
        ],
      },
      expectedRevision: 1,
    });
  });

  it("rejects a malformed or identity-mismatched ETag before a mutation is sent", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      workflowAdministrationApi.archive({
        body: { expectedRevision: 1 },
        csrfToken: "csrf-memory-only",
        etag: '"v1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000298",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({
      message: "A current strong workflow ETag is required.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("canonicalizes condition instants before publication and response comparison", async () => {
    const requests: Request[] = [];
    const canonicalTransition = {
      ...alertWorkflowFixture.current.transitions[0]!,
      condition: {
        kind: "predicate" as const,
        field: "detected_at",
        operator: "greater_than" as const,
        values: [
          {
            type: "instant" as const,
            value: "2026-08-26T08:00:00.123456Z",
          },
        ],
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            replayed: false,
            workflow: {
              ...alertWorkflowFixture,
              revision: 2,
              currentVersion: 2,
              current: {
                ...alertWorkflowFixture.current,
                version: 2,
                transitions: [canonicalTransition],
              },
              updatedAt: "2026-08-26T09:00:00Z",
            },
          },
          workflowEtagV2,
        );
      }),
    );

    await expect(
      workflowAdministrationApi.publish({
        body: {
          design: {
            states: alertWorkflowFixture.current.states,
            transitions: [
              {
                ...canonicalTransition,
                condition: {
                  ...canonicalTransition.condition,
                  values: [
                    {
                      type: "instant",
                      value: "2026-08-26T10:00:00.123456789+02:00",
                    },
                  ],
                },
              },
            ],
          },
          expectedRevision: 1,
        },
        csrfToken: "csrf-memory-only",
        etag: workflowEtagV1,
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000296",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).resolves.toMatchObject({ value: { revision: 2 } });

    const body = await requests[0]!.clone().json();
    expect(body.design.transitions[0].condition.values).toEqual([
      { type: "instant", value: "2026-08-26T08:00:00.123456Z" },
    ]);
  });

  it("rejects cross-tenant catalog projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...alertWorkflowFixture,
              tenantId: "01991c20-7d5f-7000-8000-000000000299",
            },
          ],
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects oversized scalar values in an otherwise bounded projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...alertWorkflowFixture,
              createdAt: "2".repeat(4097),
            },
          ],
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("keeps catalog revision independent from immutable version", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            ...alertWorkflowFixture,
            currentVersion: 2,
            current: { ...alertWorkflowFixture.current, version: 2 },
          },
          workflowEtagV1,
        ),
      ),
    );

    await expect(
      workflowAdministrationApi.get({
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).resolves.toMatchObject({
      value: { currentVersion: 2, revision: 1 },
    });
  });

  it("rejects catalog pages that exceed the requested bound", async () => {
    const secondId = "01991c20-7d5f-7000-8000-000000000204";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            alertWorkflowFixture,
            {
              ...alertWorkflowFixture,
              id: secondId,
              current: { ...alertWorkflowFixture.current, id: secondId },
            },
          ],
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        limit: 1,
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a catalog cursor that does not advance", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [], nextCursor: "same-page" }),
        ),
    );

    await expect(
      workflowAdministrationApi.list({
        after: "same-page",
        kind: "alert",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a catalog search that exceeds the backend byte bound", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        search: "😀".repeat(51),
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({
      message: "The workflow search is invalid.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an empty catalog page that claims a continuation", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [], nextCursor: "unexpected-page" }),
        ),
    );

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("accepts a bounded partial history page with a progressing cursor", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...alertWorkflowVersionFixture,
              definition: {
                ...alertWorkflowVersionFixture.definition,
                version: 2,
              },
            },
          ],
          nextVersion: 2,
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.listVersions({
        limit: 100,
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).resolves.toMatchObject({ nextVersion: 2 });
  });

  it("requires the exact mutation envelope and never accepts retry material in a projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            idempotencyKey: "server-leak",
            replayed: false,
            workflow: alertWorkflowFixture,
          },
          workflowEtagV1,
          201,
        ),
      ),
    );

    await expect(
      workflowAdministrationApi.create({
        body: {
          kind: "alert",
          key: alertWorkflowFixture.key,
          displayName: alertWorkflowFixture.displayName,
          description: alertWorkflowFixture.description,
          design: {
            states: alertWorkflowFixture.current.states,
            transitions: alertWorkflowFixture.current.transitions,
          },
        },
        csrfToken: "csrf-memory-only",
        idempotencyKey: "01991c20-7d5f-7000-8000-000000000297",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("sends simulation CSRF without manufacturing mutation authority", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(workflowSimulationFixture);
      }),
    );

    await workflowAdministrationApi.simulate({
      body: {
        version: 1,
        state: "new",
        commentPresent: false,
        roles: [],
        permissions: ["alert.update"],
        providedCustomFields: [],
        facts: [],
      },
      csrfToken: "csrf-memory-only",
      tenantId: workflowTenantId,
      workflowId: alertWorkflowId,
    });

    expect(requests[0]!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(requests[0]!.headers.has("Idempotency-Key")).toBe(false);
    expect(requests[0]!.headers.has("If-Match")).toBe(false);
  });

  it("accepts kernel-ordered missing permissions in simulation evidence", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          ...workflowSimulationFixture,
          transitions: [
            {
              ...workflowSimulationFixture.transitions[0]!,
              gates: {
                ...workflowSimulationFixture.transitions[0]!.gates,
                permissionsSatisfied: false,
              },
              missingPermissions: ["alert.update", "alert.assign"],
            },
          ],
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 1,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: [],
          providedCustomFields: [],
          facts: [],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).resolves.toMatchObject({
      transitions: [{ missingPermissions: ["alert.update", "alert.assign"] }],
    });
  });

  it("rejects simulation evidence that marks a supplied requirement missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          ...workflowSimulationFixture,
          transitions: [
            {
              ...workflowSimulationFixture.transitions[0]!,
              gates: {
                ...workflowSimulationFixture.transitions[0]!.gates,
                roleSatisfied: false,
              },
              missingRoles: ["analyst"],
            },
          ],
        }),
      ),
    );

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 1,
          state: "new",
          commentPresent: false,
          roles: ["analyst"],
          permissions: [],
          providedCustomFields: [],
          facts: [],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects simulator fact values that conflict with closed fact types", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 0,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: [],
          providedCustomFields: [],
          facts: [{ field: "tag.vip", value: { type: "text", value: "true" } }],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({
      message: "The workflow simulation input is invalid.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a simulator state fact that contradicts the derived request state", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 0,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: [],
          providedCustomFields: [],
          facts: [{ field: "state", value: { type: "text", value: "closed" } }],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({
      message: "The workflow simulation input is invalid.",
    });

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 0,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: [],
          providedCustomFields: [],
          facts: [{ field: "state" }],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({
      message: "The workflow simulation input is invalid.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects successful simulation projections that contradict workflow kind", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(workflowSimulationFixture)),
    );

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 1,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: ["case.update"],
          providedCustomFields: [],
          facts: [],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    await expect(
      workflowAdministrationApi.simulate({
        body: {
          version: 1,
          state: "new",
          commentPresent: false,
          roles: [],
          permissions: [],
          providedCustomFields: [],
          facts: [
            {
              field: "aggregate_kind",
              value: { type: "text", value: "case" },
            },
          ],
        },
        csrfToken: "csrf-memory-only",
        tenantId: workflowTenantId,
        workflowId: alertWorkflowId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("does not reflect untrusted RFC 9457 detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            type: "about:blank",
            title: "Conflict",
            status: 409,
            detail: "idempotencyKey=protected-server-material",
          },
          undefined,
          409,
        ),
      ),
    );

    await expect(
      workflowAdministrationApi.list({
        kind: "alert",
        tenantId: workflowTenantId,
      }),
    ).rejects.toMatchObject({
      message:
        "This attempt conflicts with current workflow state. Reload the workflow and review the latest publication before retrying.",
      status: 409,
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
