import { afterEach, describe, expect, it, vi } from "vitest";

import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

import {
  CaseDfirApiError,
  caseDfirApi,
  projectWorkspace,
  strongVersionEtag,
} from "./case-dfir-api";
import {
  dfirCaseId,
  dfirIndicatorId,
  dfirRelationshipId,
  dfirTaskId,
  dfirTenantId,
  dfirWorkspaceFixture,
} from "./case-dfir-test-fixtures";

type TaskProjection = ReturnType<typeof dfirWorkspaceFixture>["tasks"][number];

function expectTaskProjectionRejected(
  mutate: (task: TaskProjection) => void,
): void {
  const workspace = dfirWorkspaceFixture();
  mutate(workspace.tasks[0]!);
  expect(() => projectWorkspace(workspace, dfirTenantId, dfirCaseId)).toThrow(
    CaseDfirApiError,
  );
}

describe("Case DFIR transport projection", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("projects only an exact tenant and Case-bound operator workspace", () => {
    const source = dfirWorkspaceFixture();
    Reflect.set(source.indicators[0]!, "unexpectedSecret", "do-not-project");
    Reflect.set(
      source.indicators[0]!.indicator,
      "unexpectedSecret",
      "do-not-project",
    );
    const projected = projectWorkspace(source, dfirTenantId, dfirCaseId);

    expect(projected.data.iocs[0]).toMatchObject({
      id: dfirIndicatorId,
      value: "bad.example",
    });
    expect(projected.data.tasks[0]).toMatchObject({
      id: dfirTaskId,
      version: 1,
    });
    expect(projected.data.evidence[0]?.custody[0]?.actorLabel).not.toBe(
      "0198c97d-cf4f-7000-8000-000000000011",
    );
    expect(projected.workspace.indicators[0]).not.toHaveProperty(
      "unexpectedSecret",
    );
    expect(projected.workspace.indicators[0]?.indicator).not.toHaveProperty(
      "unexpectedSecret",
    );
  });

  it("fails closed for cross-tenant, cross-Case, or oversized projections", () => {
    const other = "0198c97d-cf4f-7000-8000-000000000099";
    expect(() =>
      projectWorkspace(dfirWorkspaceFixture(), other, dfirCaseId),
    ).toThrow(CaseDfirApiError);
    expect(() =>
      projectWorkspace(
        dfirWorkspaceFixture({ caseId: other }),
        dfirTenantId,
        dfirCaseId,
      ),
    ).toThrow(CaseDfirApiError);
    expect(() =>
      projectWorkspace(
        dfirWorkspaceFixture({
          indicators: Array.from(
            { length: 501 },
            () => dfirWorkspaceFixture().indicators[0]!,
          ),
        }),
        dfirTenantId,
        dfirCaseId,
      ),
    ).toThrow(CaseDfirApiError);
  });

  it("derives only the backend's canonical strong version precondition", () => {
    expect(strongVersionEtag(17)).toBe('"v17"');
    expect(strongVersionEtag(3_000_000_000)).toBe('"v3000000000"');
    expect(strongVersionEtag(Number.MAX_SAFE_INTEGER)).toBe(
      '"v9007199254740991"',
    );
    expect(() => strongVersionEtag(0)).toThrow(CaseDfirApiError);
    expect(() => strongVersionEtag(Number.MAX_SAFE_INTEGER + 1)).toThrow(
      CaseDfirApiError,
    );
    expect(() => strongVersionEtag(1.5)).toThrow(CaseDfirApiError);
  });

  it("binds replace requests to the generated route, CSRF, retry key, and version", async () => {
    const replacement = dfirWorkspaceFixture().indicators[0]!;
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ...replacement, version: 5 }), {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            ETag: '"v5"',
          },
          status: 200,
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await caseDfirApi.replace({
      caseId: dfirCaseId,
      csrfToken: "csrf-test-token",
      idempotencyKey: "replace-test-key-0001",
      operation: {
        body: {
          expectedVersion: 4,
          indicator: replacement.indicator,
        },
        panel: "iocs",
        resourceId: dfirIndicatorId,
      },
      tenantId: dfirTenantId,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const request: unknown = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) throw new Error("Expected Request");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${dfirTenantId}/cases/${dfirCaseId}/dfir/iocs/${dfirIndicatorId}`,
    );
    expect(request.method).toBe("PUT");
    expect(request.credentials).toBe("same-origin");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-test-token");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "replace-test-key-0001",
    );
    expect(request.headers.get("If-Match")).toBe('"v4"');
    await expect(request.clone().json()).resolves.toEqual({
      expectedVersion: 4,
      indicator: replacement.indicator,
    });
  });

  it.each(
    [
      {
        name: "last exact increment",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        receiptVersion: Number.MAX_SAFE_INTEGER,
        replayed: false,
        accepted: true,
      },
      {
        name: "last exact increment replay",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        receiptVersion: Number.MAX_SAFE_INTEGER,
        replayed: true,
        accepted: true,
      },
      {
        name: "historical exact replay",
        expectedVersion: 4,
        receiptVersion: 5,
        replayed: true,
        accepted: true,
      },
      {
        name: "stale terminal receipt",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        receiptVersion: Number.MAX_SAFE_INTEGER - 1,
        replayed: false,
        accepted: false,
      },
      {
        name: "stale historical receipt",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        receiptVersion: 1,
        replayed: true,
        accepted: false,
      },
      {
        name: "skipped but JSON-safe revision",
        expectedVersion: Number.MAX_SAFE_INTEGER - 2,
        receiptVersion: Number.MAX_SAFE_INTEGER,
        replayed: false,
        accepted: false,
      },
    ].flatMap((scenario) =>
      (["iocs", "assets"] as const).map((panel) => ({ ...scenario, panel })),
    ),
  )(
    "binds $panel replacement to the requested increment: $name",
    async ({ panel, expectedVersion, receiptVersion, replayed, accepted }) => {
      const workspace = dfirWorkspaceFixture();
      const replacement =
        panel === "iocs" ? workspace.indicators[0]! : workspace.assets[0]!;
      const fetchMock = vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(
            JSON.stringify({ ...replacement, version: receiptVersion }),
            {
              headers: {
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
                ETag: `"v${receiptVersion}"`,
                "X-Idempotent-Replay": String(replayed),
              },
              status: 200,
            },
          ),
        ),
      );
      vi.stubGlobal("fetch", fetchMock);
      const operation =
        panel === "iocs"
          ? {
              panel,
              resourceId: replacement.id,
              body: {
                expectedVersion,
                indicator: workspace.indicators[0]!.indicator,
              },
            }
          : {
              panel,
              resourceId: replacement.id,
              body: { expectedVersion, asset: workspace.assets[0]!.asset },
            };
      const result = caseDfirApi.replace({
        caseId: dfirCaseId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "case-replace-revision-0001",
        operation,
        tenantId: dfirTenantId,
      });
      if (accepted) {
        await expect(result).resolves.toBeUndefined();
      } else {
        await expect(result).rejects.toThrow(CaseDfirApiError);
      }
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const request: unknown = fetchMock.mock.calls[0]?.[0];
      if (!(request instanceof Request)) throw new Error("Expected Request");
      expect(request.headers.get("If-Match")).toBe(`"v${expectedVersion}"`);
      await expect(request.clone().json()).resolves.toMatchObject({
        expectedVersion,
      });
    },
  );

  it.each([3_000_000_000, Number.MAX_SAFE_INTEGER - 1])(
    "binds every Case task action at revision %s to its route, payload, and distinct CAS key",
    async (taskVersion) => {
      const currentTask = dfirWorkspaceFixture().tasks[0]!;
      const responseTask = {
        ...currentTask,
        updatedAt: "2026-08-30T09:01:00Z",
        version: taskVersion + 1,
      };
      const fetchMock = vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(JSON.stringify(responseTask), {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: `"v${taskVersion + 1}"`,
            },
            status: 200,
          }),
        ),
      );
      vi.stubGlobal("fetch", fetchMock);
      const common = {
        caseId: dfirCaseId,
        csrfToken: "csrf-test-token",
        taskId: dfirTaskId,
        tenantId: dfirTenantId,
      };
      const checklistId = "0198c97d-cf4f-7000-8000-000000000055";
      const commentId = "0198c97d-cf4f-7000-8000-000000000056";

      await caseDfirApi.replaceTaskDetails({
        ...common,
        body: {
          description: "Revised containment instructions",
          expectedVersion: taskVersion,
          priority: "urgent",
          title: "Contain affected endpoint",
        },
        idempotencyKey: "case-task-details-0001",
      });
      await caseDfirApi.assignTask({
        ...common,
        body: {
          assigneeId: "0198c97d-cf4f-7000-8000-000000000023",
          expectedVersion: taskVersion,
          operatorTeamId: "0198c97d-cf4f-7000-8000-000000000022",
        },
        idempotencyKey: "case-task-assignment-0001",
      });
      await caseDfirApi.rescheduleTask({
        ...common,
        body: {
          dueAt: "2026-08-31T12:00:00.000Z",
          expectedVersion: taskVersion,
        },
        idempotencyKey: "case-task-due-date-0001",
      });
      await caseDfirApi.replaceTaskChecklist({
        ...common,
        body: {
          checklist: [
            { completed: true, id: checklistId, title: "Acquire image" },
          ],
          expectedVersion: taskVersion,
        },
        idempotencyKey: "case-task-checklist-0001",
      });
      await caseDfirApi.replaceTaskComments({
        ...common,
        body: {
          commentIds: [commentId],
          expectedVersion: taskVersion,
        },
        idempotencyKey: "case-task-comments-0001",
      });
      await caseDfirApi.transitionTask({
        ...common,
        body: {
          completionData: { disposition: "contained" },
          expectedVersion: taskVersion,
          reason: "Containment verified",
          target: "done",
        },
        idempotencyKey: "case-task-transition-0001",
      });

      const expected = [
        {
          body: {
            description: "Revised containment instructions",
            expectedVersion: taskVersion,
            priority: "urgent",
            title: "Contain affected endpoint",
          },
          key: "case-task-details-0001",
          method: "PUT",
          suffix: "details",
        },
        {
          body: {
            assigneeId: "0198c97d-cf4f-7000-8000-000000000023",
            expectedVersion: taskVersion,
            operatorTeamId: "0198c97d-cf4f-7000-8000-000000000022",
          },
          key: "case-task-assignment-0001",
          method: "PUT",
          suffix: "assignment",
        },
        {
          body: {
            dueAt: "2026-08-31T12:00:00.000Z",
            expectedVersion: taskVersion,
          },
          key: "case-task-due-date-0001",
          method: "PUT",
          suffix: "due-date",
        },
        {
          body: {
            checklist: [
              { completed: true, id: checklistId, title: "Acquire image" },
            ],
            expectedVersion: taskVersion,
          },
          key: "case-task-checklist-0001",
          method: "PUT",
          suffix: "checklist",
        },
        {
          body: {
            commentIds: [commentId],
            expectedVersion: taskVersion,
          },
          key: "case-task-comments-0001",
          method: "PUT",
          suffix: "comments",
        },
        {
          body: {
            completionData: { disposition: "contained" },
            expectedVersion: taskVersion,
            reason: "Containment verified",
            target: "done",
          },
          key: "case-task-transition-0001",
          method: "POST",
          suffix: "transition",
        },
      ] as const;
      expect(fetchMock).toHaveBeenCalledTimes(expected.length);
      await Promise.all(
        expected.map(async (item, index) => {
          const request: unknown = fetchMock.mock.calls[index]?.[0];
          if (!(request instanceof Request))
            throw new Error("Expected Request");
          expect(new URL(request.url).pathname).toBe(
            `/api/v1/tenants/${dfirTenantId}/cases/${dfirCaseId}/dfir/tasks/${dfirTaskId}/${item.suffix}`,
          );
          expect(request.method).toBe(item.method);
          expect(request.headers.get("X-CSRF-Token")).toBe("csrf-test-token");
          expect(request.headers.get("Idempotency-Key")).toBe(item.key);
          expect(request.headers.get("If-Match")).toBe(`"v${taskVersion}"`);
          await expect(request.clone().json()).resolves.toEqual(item.body);
        }),
      );
      expect(new Set(expected.map(({ key }) => key)).size).toBe(
        expected.length,
      );
    },
  );

  it.each([Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1])(
    "rejects non-incrementable Case task revision %s before transport",
    async (expectedVersion) => {
      const fetchMock = vi.fn<typeof fetch>();
      vi.stubGlobal("fetch", fetchMock);

      await expect(
        caseDfirApi.replaceTaskDetails({
          body: {
            description: "Containment instructions",
            expectedVersion,
            priority: "urgent",
            title: "Contain affected endpoint",
          },
          caseId: dfirCaseId,
          csrfToken: "csrf-test-token",
          idempotencyKey: "case-task-terminal-version-0001",
          taskId: dfirTaskId,
          tenantId: dfirTenantId,
        }),
      ).rejects.toThrow(CaseDfirApiError);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("binds append-only Case relationship retraction to its CAS route", async () => {
    const relationship = dfirWorkspaceFixture().relationships[0]!;
    const retractionId = "0198c97d-cf4f-7000-8000-000000000057";
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            ...relationship,
            active: false,
            retractions: [
              {
                actorId: "0198c97d-cf4f-7000-8000-000000000011",
                id: retractionId,
                occurredAt: "2026-08-30T09:20:00Z",
                reason: "Duplicate relationship",
                sequence: 1,
              },
            ],
            version: 2,
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: '"v2"',
              "X-Idempotent-Replay": "false",
            },
            status: 200,
          },
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await caseDfirApi.retractRelationship({
      body: {
        expectedVersion: 1,
        reason: "Duplicate relationship",
        retractionId,
      },
      caseId: dfirCaseId,
      csrfToken: "csrf-test-token",
      idempotencyKey: "case-retract-key-0001",
      relationshipId: dfirRelationshipId,
      tenantId: dfirTenantId,
    });

    const request: unknown = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) throw new Error("Expected Request");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${dfirTenantId}/cases/${dfirCaseId}/dfir/relationships/${dfirRelationshipId}/retract`,
    );
    expect(request.method).toBe("POST");
    expect(request.headers.get("If-Match")).toBe('"v1"');
    expect(request.headers.get("Idempotency-Key")).toBe(
      "case-retract-key-0001",
    );
    await expect(request.clone().json()).resolves.toEqual({
      expectedVersion: 1,
      reason: "Duplicate relationship",
      retractionId,
    });
  });

  it("accepts the Case task comment reference ceiling and rejects overflow", () => {
    const commentIds = Array.from(
      { length: 1_000 },
      (_, index) =>
        `0198c97d-cf4f-7000-8000-${index.toString(16).padStart(12, "0")}`,
    );
    const task = dfirWorkspaceFixture().tasks[0]!;
    expect(() =>
      projectWorkspace(
        dfirWorkspaceFixture({ tasks: [{ ...task, commentIds }] }),
        dfirTenantId,
        dfirCaseId,
      ),
    ).not.toThrow();
    expect(() =>
      projectWorkspace(
        dfirWorkspaceFixture({
          tasks: [
            {
              ...task,
              commentIds: [
                ...commentIds,
                "0198c97d-cf4f-7000-8000-000000001000",
              ],
            },
          ],
        }),
        dfirTenantId,
        dfirCaseId,
      ),
    ).toThrow(CaseDfirApiError);
  });

  it("projects Case task revisions throughout the JSON-safe bigint range", () => {
    const task = dfirWorkspaceFixture().tasks[0]!;
    const projected = projectWorkspace(
      dfirWorkspaceFixture({
        tasks: [{ ...task, version: 3_000_000_000 }],
      }),
      dfirTenantId,
      dfirCaseId,
    );

    expect(projected.workspace.tasks[0]?.version).toBe(3_000_000_000);
  });

  it("projects generic Case DFIR revisions above int32 while custody keeps its narrower limit", () => {
    const source = dfirWorkspaceFixture();
    source.indicators[0]!.version = 3_000_000_001;
    source.assets[0]!.version = 3_000_000_002;
    source.timeline[0]!.version = 3_000_000_004;
    source.tasks[0]!.version = 3_000_000_005;
    const projected = projectWorkspace(source, dfirTenantId, dfirCaseId);
    expect([
      projected.workspace.indicators[0]?.version,
      projected.workspace.assets[0]?.version,
      projected.workspace.timeline[0]?.version,
      projected.workspace.tasks[0]?.version,
    ]).toEqual([3_000_000_001, 3_000_000_002, 3_000_000_004, 3_000_000_005]);
    expect(projected.workspace.evidence[0]?.version).toBe(3);

    source.assets[0]!.version = Number.MAX_SAFE_INTEGER + 1;
    expect(() => projectWorkspace(source, dfirTenantId, dfirCaseId)).toThrow(
      CaseDfirApiError,
    );
  });

  it("rejects terminal DFIR mutation versions before issuing a request", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
    const replacement = dfirWorkspaceFixture().indicators[0]!;

    await expect(
      caseDfirApi.replace({
        caseId: dfirCaseId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "terminal-version-test-0001",
        operation: {
          body: {
            expectedVersion: Number.MAX_SAFE_INTEGER,
            indicator: replacement.indicator,
          },
          panel: "iocs",
          resourceId: dfirIndicatorId,
        },
        tenantId: dfirTenantId,
      }),
    ).rejects.toThrow(CaseDfirApiError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed for semantically inconsistent Case task projections", () => {
    const actorId = "0198c97d-cf4f-7000-8000-000000000011";
    const teamId = "0198c97d-cf4f-7000-8000-000000000012";
    const itemId = "0198c97d-cf4f-7000-8000-000000000013";

    const validTerminal = dfirWorkspaceFixture();
    Object.assign(validTerminal.tasks[0]!, {
      checklist: [
        {
          completed: true,
          completedAt: "2026-08-30T09:01:00Z",
          completedBy: actorId,
          id: itemId,
          title: "Acquire image",
        },
      ],
      completedAt: "2026-08-30T09:02:00Z",
      completedBy: actorId,
      completionData: { disposition: "contained" },
      status: "done",
      updatedAt: "2026-08-30T09:02:00Z",
    });
    expect(() =>
      projectWorkspace(validTerminal, dfirTenantId, dfirCaseId),
    ).not.toThrow();

    expectTaskProjectionRejected((task) => {
      task.checklist = [
        { completed: false, id: itemId, title: "One" },
        { completed: false, id: itemId, title: "Two" },
      ];
    });
    expectTaskProjectionRejected((task) => {
      task.checklist = [{ completed: true, id: itemId, title: "Forged" }];
    });
    expectTaskProjectionRejected((task) => {
      task.checklist = [
        {
          completed: false,
          completedAt: "2026-08-30T09:01:00Z",
          completedBy: actorId,
          id: itemId,
          title: "Forged",
        },
      ];
    });
    expectTaskProjectionRejected((task) => {
      task.status = "done";
    });
    expectTaskProjectionRejected((task) => {
      task.completionData = { disposition: "forged" };
    });
    expectTaskProjectionRejected((task) => {
      task.assigneeId = actorId;
    });
    expectTaskProjectionRejected((task) => {
      task.createdAt = "2026-08-30T09:02:00Z";
      task.updatedAt = "2026-08-30T09:01:00Z";
    });
    expectTaskProjectionRejected((task) => {
      task.status = "cancelled";
      task.completedAt = "2026-08-30T08:59:00Z";
      task.completedBy = actorId;
      task.updatedAt = "2026-08-30T09:02:00Z";
    });
    expectTaskProjectionRejected((task) => {
      task.checklist = [
        {
          completed: true,
          completedAt: "2026-08-30T09:03:00Z",
          completedBy: actorId,
          id: itemId,
          title: "Out-of-window provenance",
        },
      ];
      task.updatedAt = "2026-08-30T09:02:00Z";
    });
    expectTaskProjectionRejected((task) => {
      task.checklist = [
        { completed: false, id: itemId, title: "Still incomplete" },
      ];
      task.completedAt = "2026-08-30T09:02:00Z";
      task.completedBy = actorId;
      task.operatorTeamId = teamId;
      task.status = "done";
      task.updatedAt = "2026-08-30T09:02:00Z";
    });
  });
});

describe("Case DFIR original-request mutation receipts", () => {
  afterEach(() => vi.unstubAllGlobals());

  const common = {
    caseId: dfirCaseId,
    tenantId: dfirTenantId,
    csrfToken: "csrf-receipt-test",
    idempotencyKey: "case-original-receipt-0001",
  };
  const taskActions = [
    {
      name: "transitionTask",
      prepare: (expectedVersion: number) => {
        const body = {
          expectedVersion,
          target: "in_progress" as const,
          reason: "Containment started",
        };
        return {
          body,
          send: () =>
            caseDfirApi.transitionTask({ ...common, taskId: dfirTaskId, body }),
        };
      },
    },
    {
      name: "replaceTaskDetails",
      prepare: (expectedVersion: number) => {
        const body = {
          expectedVersion,
          title: "Contain affected endpoint",
          description: "Containment instructions",
          priority: "high" as const,
        };
        return {
          body,
          send: () =>
            caseDfirApi.replaceTaskDetails({
              ...common,
              taskId: dfirTaskId,
              body,
            }),
        };
      },
    },
    {
      name: "assignTask",
      prepare: (expectedVersion: number) => {
        const body = {
          expectedVersion,
          operatorTeamId: "0198c97d-cf4f-7000-8000-000000000022",
          assigneeId: "0198c97d-cf4f-7000-8000-000000000023",
        };
        return {
          body,
          send: () =>
            caseDfirApi.assignTask({ ...common, taskId: dfirTaskId, body }),
        };
      },
    },
    {
      name: "rescheduleTask",
      prepare: (expectedVersion: number) => {
        const body = { expectedVersion, dueAt: "2026-08-31T12:00:00Z" };
        return {
          body,
          send: () =>
            caseDfirApi.rescheduleTask({ ...common, taskId: dfirTaskId, body }),
        };
      },
    },
    {
      name: "replaceTaskChecklist",
      prepare: (expectedVersion: number) => {
        const body = { expectedVersion, checklist: [] };
        return {
          body,
          send: () =>
            caseDfirApi.replaceTaskChecklist({
              ...common,
              taskId: dfirTaskId,
              body,
            }),
        };
      },
    },
    {
      name: "replaceTaskComments",
      prepare: (expectedVersion: number) => {
        const body = { expectedVersion, commentIds: [] };
        return {
          body,
          send: () =>
            caseDfirApi.replaceTaskComments({
              ...common,
              taskId: dfirTaskId,
              body,
            }),
        };
      },
    },
  ];

  describe.each(taskActions)("$name", ({ prepare }) => {
    it.each([
      {
        name: "last increment",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        version: Number.MAX_SAFE_INTEGER,
        replayed: false,
        accepted: true,
      },
      {
        name: "last increment replay",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        version: Number.MAX_SAFE_INTEGER,
        replayed: true,
        accepted: true,
      },
      {
        name: "historical exact replay",
        expectedVersion: 4,
        version: 5,
        replayed: true,
        accepted: true,
      },
      {
        name: "stale terminal receipt",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        version: Number.MAX_SAFE_INTEGER - 1,
        replayed: false,
        accepted: false,
      },
      {
        name: "stale historical receipt",
        expectedVersion: Number.MAX_SAFE_INTEGER - 1,
        version: 1,
        replayed: true,
        accepted: false,
      },
      {
        name: "skipped safe receipt",
        expectedVersion: Number.MAX_SAFE_INTEGER - 2,
        version: Number.MAX_SAFE_INTEGER,
        replayed: false,
        accepted: false,
      },
    ])(
      "binds $name to the original request",
      async ({ expectedVersion, version, replayed, accepted }) => {
        const task = dfirWorkspaceFixture().tasks[0]!;
        const fetchMock = stubReceipt(
          { ...task, version },
          version,
          replayed,
          () => {
            command.body.expectedVersion = 2;
          },
        );
        const command = prepare(expectedVersion);
        const result = command.send();
        await expectReceipt(result, accepted);
        await expectOriginalVersion(fetchMock, expectedVersion);
      },
    );
  });

  it.each([
    {
      name: "last append",
      expectedVersion: 999,
      version: 1_000,
      replayed: false,
      accepted: true,
    },
    {
      name: "last append replay",
      expectedVersion: 999,
      version: 1_000,
      replayed: true,
      accepted: true,
    },
    {
      name: "historical exact replay",
      expectedVersion: 1,
      version: 2,
      replayed: true,
      accepted: true,
    },
    {
      name: "stale full chain",
      expectedVersion: 999,
      version: 999,
      replayed: false,
      accepted: false,
    },
    {
      name: "stale historical chain",
      expectedVersion: 999,
      version: 1,
      replayed: true,
      accepted: false,
    },
    {
      name: "skipped full chain",
      expectedVersion: 998,
      version: 1_000,
      replayed: false,
      accepted: false,
    },
  ])(
    "binds custody $name to the original request",
    async ({ expectedVersion, version, replayed, accepted }) => {
      const evidence = dfirWorkspaceFixture().evidence[0]!;
      const fetchMock = stubReceipt(
        {
          ...evidence,
          custody: evidenceCustodyFixture(evidence.custody[0]!, version),
          version,
        },
        version,
        replayed,
        () => {
          body.expectedVersion = 2;
        },
      );
      const body = {
        expectedVersion,
        action: "accessed" as const,
        reason: "Receipt boundary regression",
        custodyEventId: "0198c97d-cf4f-7000-8000-000000009999",
      };
      const result = caseDfirApi.appendCustody({
        ...common,
        evidenceId: evidence.id,
        body,
      });
      await expectReceipt(result, accepted);
      await expectOriginalVersion(fetchMock, expectedVersion);
    },
  );

  it.each([
    { name: "fresh retraction", version: 2, replayed: false, accepted: true },
    {
      name: "exact retraction replay",
      version: 2,
      replayed: true,
      accepted: true,
    },
    {
      name: "still-active receipt",
      version: 1,
      replayed: false,
      accepted: false,
    },
    {
      name: "still-active replay receipt",
      version: 1,
      replayed: true,
      accepted: false,
    },
  ])(
    "binds $name to the original request",
    async ({ version, replayed, accepted }) => {
      const relationship = dfirWorkspaceFixture().relationships[0]!;
      const retractionId = "0198c97d-cf4f-7000-8000-000000000057";
      const fetchMock = stubReceipt(
        {
          ...relationship,
          active: version === 1,
          version,
          retractions:
            version === 1
              ? []
              : [
                  {
                    actorId: "0198c97d-cf4f-7000-8000-000000000011",
                    id: retractionId,
                    occurredAt: "2026-08-30T09:20:00Z",
                    reason: "Duplicate relationship",
                    sequence: 1,
                  },
                ],
        },
        version,
        replayed,
        () => {
          body.expectedVersion = 2;
        },
      );
      const body = {
        expectedVersion: 1,
        reason: "Duplicate relationship",
        retractionId,
      };
      const result = caseDfirApi.retractRelationship({
        ...common,
        relationshipId: relationship.id,
        body,
      });
      await expectReceipt(result, accepted);
      await expectOriginalVersion(fetchMock, 1);
    },
  );
});

function stubReceipt(
  value: unknown,
  version: number,
  replayed: boolean,
  onResponse?: () => void,
) {
  const fetchMock = vi.fn<typeof fetch>(() => {
    // Mutate only after the generated client has serialized the original request.
    onResponse?.();
    return Promise.resolve(
      new Response(JSON.stringify(value), {
        status: 200,
        headers: {
          "Cache-Control": "no-store",
          "Content-Type": "application/json",
          ETag: `"v${version}"`,
          "X-Idempotent-Replay": String(replayed),
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function expectReceipt(result: Promise<void>, accepted: boolean) {
  if (accepted) await expect(result).resolves.toBeUndefined();
  else await expect(result).rejects.toThrow(CaseDfirApiError);
}

async function expectOriginalVersion(
  fetchMock: ReturnType<typeof stubReceipt>,
  expectedVersion: number,
) {
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const request = fetchMock.mock.calls[0]?.[0];
  if (!(request instanceof Request))
    throw new Error("Expected generated Request");
  expect(request.headers.get("If-Match")).toBe(`"v${expectedVersion}"`);
  await expect(request.clone().json()).resolves.toMatchObject({
    expectedVersion,
  });
}
