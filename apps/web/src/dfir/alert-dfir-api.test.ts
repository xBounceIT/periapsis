import { afterEach, describe, expect, it, vi } from "vitest";

import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

import {
  AlertDfirApiError,
  alertDfirApi,
  projectAlertWorkspace,
} from "./alert-dfir-api";
import {
  alertDfirAlertId,
  alertDfirEvidenceId,
  alertDfirIndicatorId,
  alertDfirRelationshipId,
  alertDfirTaskId,
  alertDfirTenantId,
  alertDfirExtendedWorkspaceFixture,
  alertDfirWorkspaceFixture,
} from "./alert-dfir-test-fixtures";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Alert DFIR transport projection", () => {
  it("allowlists an exact tenant and Alert-bound workspace", () => {
    const source = alertDfirExtendedWorkspaceFixture();
    Reflect.set(source.indicators[0]!, "unexpectedSecret", "do-not-project");
    Reflect.set(
      source.indicators[0]!.indicator,
      "unexpectedSecret",
      "do-not-project",
    );

    const projected = projectAlertWorkspace(
      source,
      alertDfirTenantId,
      alertDfirAlertId,
    );

    expect(projected.data.iocs[0]).toMatchObject({
      id: alertDfirIndicatorId,
      value: "bad.example",
    });
    expect(projected.workspace.indicators[0]).not.toHaveProperty(
      "unexpectedSecret",
    );
    expect(projected.workspace.indicators[0]?.indicator).not.toHaveProperty(
      "unexpectedSecret",
    );
    expect(projected.data.evidence[0]).toMatchObject({
      id: alertDfirEvidenceId,
      legalHold: true,
      title: "Memory image",
    });
    expect(projected.data.tasks[0]).toMatchObject({
      checklistTotal: 1,
      id: alertDfirTaskId,
      version: 2,
    });
    expect(projected.data.relationships[0]).toMatchObject({
      id: alertDfirRelationshipId,
      relationshipType: "contains",
    });
  });

  it("accepts the bounded RFC 3339 timestamp shape emitted by Go", () => {
    const source = alertDfirWorkspaceFixture();
    source.indicators[0]!.indicator.firstSeen = "2026-08-30T08:00:00Z";
    source.assets[0]!.asset.lastSeen = "2026-08-30T10:00:00+02:00";

    expect(() =>
      projectAlertWorkspace(source, alertDfirTenantId, alertDfirAlertId),
    ).not.toThrow();
  });

  it("projects generic Alert DFIR revisions above int32 while custody keeps its narrower limit", () => {
    const source = alertDfirExtendedWorkspaceFixture();
    source.indicators[0]!.version = 3_000_000_001;
    source.assets[0]!.version = 3_000_000_002;
    source.timeline[0]!.version = 3_000_000_003;
    source.tasks[0]!.version = 3_000_000_005;
    const projected = projectAlertWorkspace(
      source,
      alertDfirTenantId,
      alertDfirAlertId,
    );
    expect([
      projected.workspace.indicators[0]?.version,
      projected.workspace.assets[0]?.version,
      projected.workspace.timeline[0]?.version,
      projected.workspace.tasks[0]?.version,
    ]).toEqual([3_000_000_001, 3_000_000_002, 3_000_000_003, 3_000_000_005]);
    expect(projected.workspace.evidence[0]?.version).toBe(3);

    source.assets[0]!.version = Number.MAX_SAFE_INTEGER + 1;
    expect(() =>
      projectAlertWorkspace(source, alertDfirTenantId, alertDfirAlertId),
    ).toThrow(AlertDfirApiError);
  });

  it("fails closed for cross-root, duplicate, oversized, or unknown timeline links", () => {
    const other = "0198c97d-cf4f-7000-8000-000000000099";
    expect(() =>
      projectAlertWorkspace(
        alertDfirWorkspaceFixture(),
        other,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);
    expect(() =>
      projectAlertWorkspace(
        alertDfirWorkspaceFixture({ alertId: other }),
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);
    expect(() =>
      projectAlertWorkspace(
        alertDfirWorkspaceFixture({
          indicators: Array.from(
            { length: 501 },
            () => alertDfirWorkspaceFixture().indicators[0]!,
          ),
        }),
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);
    const duplicate = alertDfirWorkspaceFixture();
    duplicate.assets.push(duplicate.assets[0]!);
    expect(() =>
      projectAlertWorkspace(duplicate, alertDfirTenantId, alertDfirAlertId),
    ).toThrow(AlertDfirApiError);
    const withEvidence = alertDfirWorkspaceFixture();
    withEvidence.timeline[0]!.event.evidenceIds = [other];
    expect(() =>
      projectAlertWorkspace(withEvidence, alertDfirTenantId, alertDfirAlertId),
    ).toThrow(AlertDfirApiError);
    const withCrossRootIndicator = alertDfirWorkspaceFixture();
    withCrossRootIndicator.timeline[0]!.event.iocIds = [other];
    expect(() =>
      projectAlertWorkspace(
        withCrossRootIndicator,
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);
  });

  it("rejects spliced Alert evidence, task, attachment, and relationship projections", () => {
    const other = "0198c97d-cf4f-7000-8000-000000000099";

    const brokenCustody = alertDfirExtendedWorkspaceFixture();
    brokenCustody.evidence[0]!.custody.push({
      ...brokenCustody.evidence[0]!.custody[0]!,
      id: "0198c97d-cf4f-7000-8000-000000000031",
      previousHash: "c".repeat(64),
      sequence: 2,
    });
    expect(() =>
      projectAlertWorkspace(brokenCustody, alertDfirTenantId, alertDfirAlertId),
    ).toThrow(AlertDfirApiError);

    const duplicateChecklist = alertDfirExtendedWorkspaceFixture();
    duplicateChecklist.tasks[0]!.checklist.push({
      ...duplicateChecklist.tasks[0]!.checklist[0]!,
    });
    expect(() =>
      projectAlertWorkspace(
        duplicateChecklist,
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);

    const unknownAttachmentSubject = alertDfirExtendedWorkspaceFixture();
    unknownAttachmentSubject.attachments[0]!.subject = {
      id: other,
      kind: "evidence",
    };
    expect(() =>
      projectAlertWorkspace(
        unknownAttachmentSubject,
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);

    const detachedRelationship = alertDfirExtendedWorkspaceFixture();
    detachedRelationship.relationships[0]!.alertId = other;
    expect(() =>
      projectAlertWorkspace(
        detachedRelationship,
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);

    const inconsistentRetraction = alertDfirExtendedWorkspaceFixture();
    inconsistentRetraction.relationships[0]!.active = false;
    expect(() =>
      projectAlertWorkspace(
        inconsistentRetraction,
        alertDfirTenantId,
        alertDfirAlertId,
      ),
    ).toThrow(AlertDfirApiError);
  });

  it("rejects a workspace response that is not explicitly no-store", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(JSON.stringify(alertDfirWorkspaceFixture()), {
            headers: { "Content-Type": "application/json" },
            status: 200,
          }),
        ),
      ),
    );

    await expect(
      alertDfirApi.getWorkspace({
        alertId: alertDfirAlertId,
        tenantId: alertDfirTenantId,
      }),
    ).rejects.toThrow(AlertDfirApiError);
  });

  it("binds replacement to the exact generated path, CSRF, retry key, and version", async () => {
    const replacement = alertDfirWorkspaceFixture().indicators[0]!;
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

    await alertDfirApi.replace({
      alertId: alertDfirAlertId,
      csrfToken: "csrf-test-token",
      idempotencyKey: "replace-test-key-0001",
      operation: {
        body: {
          expectedVersion: 4,
          indicator: replacement.indicator,
        },
        panel: "iocs",
        resourceId: alertDfirIndicatorId,
      },
      tenantId: alertDfirTenantId,
    });

    const request: unknown = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) throw new Error("Expected Request");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${alertDfirTenantId}/alerts/${alertDfirAlertId}/dfir/iocs/${alertDfirIndicatorId}`,
    );
    expect(request.method).toBe("PUT");
    expect(request.credentials).toBe("same-origin");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-test-token");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "replace-test-key-0001",
    );
    expect(request.headers.get("If-Match")).toBe('"v4"');
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
      const workspace = alertDfirWorkspaceFixture();
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
      const result = alertDfirApi.replace({
        alertId: alertDfirAlertId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "alert-replace-revision-0001",
        operation,
        tenantId: alertDfirTenantId,
      });
      if (accepted) {
        await expect(result).resolves.toBeUndefined();
      } else {
        await expect(result).rejects.toThrow(AlertDfirApiError);
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

  it("rejects terminal DFIR mutation versions before issuing a request", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetchMock);
    const replacement = alertDfirWorkspaceFixture().indicators[0]!;

    await expect(
      alertDfirApi.replace({
        alertId: alertDfirAlertId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "terminal-version-test-0001",
        operation: {
          body: {
            expectedVersion: Number.MAX_SAFE_INTEGER,
            indicator: replacement.indicator,
          },
          panel: "iocs",
          resourceId: alertDfirIndicatorId,
        },
        tenantId: alertDfirTenantId,
      }),
    ).rejects.toThrow(AlertDfirApiError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("binds Alert task details, comments, assignment, and relationship retraction to exact CAS paths", async () => {
    const workspace = alertDfirExtendedWorkspaceFixture();
    const task = workspace.tasks[0]!;
    const relationship = workspace.relationships[0]!;
    const detailsVersion = 3_000_000_000;
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...task,
            description: "Revised containment instructions",
            priority: "high",
            title: "Contain affected endpoint",
            updatedAt: "2026-08-30T09:20:00.000Z",
            version: detailsVersion + 1,
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: `"v${detailsVersion + 1}"`,
              "X-Idempotent-Replay": "false",
            },
            status: 200,
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ...task, version: 3 }), {
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            ETag: '"v3"',
            "X-Idempotent-Replay": "false",
          },
          status: 200,
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...task,
            commentIds: ["0198c97d-cf4f-7000-8000-000000000034"],
            version: 4,
          }),
          {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: '"v4"',
              "X-Idempotent-Replay": "false",
            },
            status: 200,
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...relationship,
            active: false,
            retractions: [
              {
                actorId: "0198c97d-cf4f-7000-8000-000000000011",
                id: "0198c97d-cf4f-7000-8000-000000000032",
                occurredAt: "2026-08-30T09:20:00.000Z",
                reason: "Superseded by verified evidence",
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
      );
    vi.stubGlobal("fetch", fetchMock);

    await alertDfirApi.replaceTaskDetails({
      alertId: alertDfirAlertId,
      body: {
        description: "Revised containment instructions",
        expectedVersion: detailsVersion,
        priority: "high",
        title: "Contain affected endpoint",
      },
      csrfToken: "csrf-test-token",
      idempotencyKey: "alert-task-details-0001",
      taskId: alertDfirTaskId,
      tenantId: alertDfirTenantId,
    });
    await alertDfirApi.assignTask({
      alertId: alertDfirAlertId,
      body: {
        expectedVersion: 2,
        operatorTeamId: "0198c97d-cf4f-7000-8000-000000000033",
      },
      csrfToken: "csrf-test-token",
      idempotencyKey: "assign-test-key-0001",
      taskId: alertDfirTaskId,
      tenantId: alertDfirTenantId,
    });
    await alertDfirApi.replaceTaskComments({
      alertId: alertDfirAlertId,
      body: {
        commentIds: ["0198c97d-cf4f-7000-8000-000000000034"],
        expectedVersion: 3,
      },
      csrfToken: "csrf-test-token",
      idempotencyKey: "alert-comments-key-0001",
      taskId: alertDfirTaskId,
      tenantId: alertDfirTenantId,
    });
    await alertDfirApi.retractRelationship({
      alertId: alertDfirAlertId,
      body: {
        expectedVersion: 1,
        reason: "Superseded by verified evidence",
        retractionId: "0198c97d-cf4f-7000-8000-000000000032",
      },
      csrfToken: "csrf-test-token",
      idempotencyKey: "retract-test-key-01",
      relationshipId: alertDfirRelationshipId,
      tenantId: alertDfirTenantId,
    });

    const detailsRequest: unknown = fetchMock.mock.calls[0]?.[0];
    const assignmentRequest: unknown = fetchMock.mock.calls[1]?.[0];
    const commentsRequest: unknown = fetchMock.mock.calls[2]?.[0];
    const retractionRequest: unknown = fetchMock.mock.calls[3]?.[0];
    if (
      !(detailsRequest instanceof Request) ||
      !(assignmentRequest instanceof Request) ||
      !(commentsRequest instanceof Request) ||
      !(retractionRequest instanceof Request)
    ) {
      throw new Error("Expected generated Request values");
    }
    expect(new URL(detailsRequest.url).pathname).toBe(
      `/api/v1/tenants/${alertDfirTenantId}/alerts/${alertDfirAlertId}/dfir/tasks/${alertDfirTaskId}/details`,
    );
    expect(detailsRequest.method).toBe("PUT");
    expect(detailsRequest.headers.get("If-Match")).toBe(`"v${detailsVersion}"`);
    expect(detailsRequest.headers.get("Idempotency-Key")).toBe(
      "alert-task-details-0001",
    );
    await expect(detailsRequest.clone().json()).resolves.toEqual({
      description: "Revised containment instructions",
      expectedVersion: detailsVersion,
      priority: "high",
      title: "Contain affected endpoint",
    });
    expect(new URL(assignmentRequest.url).pathname).toBe(
      `/api/v1/tenants/${alertDfirTenantId}/alerts/${alertDfirAlertId}/dfir/tasks/${alertDfirTaskId}/assignment`,
    );
    expect(assignmentRequest.method).toBe("PUT");
    expect(assignmentRequest.headers.get("If-Match")).toBe('"v2"');
    expect(new URL(commentsRequest.url).pathname).toBe(
      `/api/v1/tenants/${alertDfirTenantId}/alerts/${alertDfirAlertId}/dfir/tasks/${alertDfirTaskId}/comments`,
    );
    expect(commentsRequest.method).toBe("PUT");
    expect(commentsRequest.headers.get("If-Match")).toBe('"v3"');
    expect(commentsRequest.headers.get("Idempotency-Key")).toBe(
      "alert-comments-key-0001",
    );
    expect(new URL(retractionRequest.url).pathname).toBe(
      `/api/v1/tenants/${alertDfirTenantId}/alerts/${alertDfirAlertId}/dfir/relationships/${alertDfirRelationshipId}/retract`,
    );
    expect(retractionRequest.method).toBe("POST");
    expect(retractionRequest.headers.get("If-Match")).toBe('"v1"');
  });
});

describe("Alert DFIR original-request mutation receipts", () => {
  afterEach(() => vi.unstubAllGlobals());

  const common = {
    alertId: alertDfirAlertId,
    tenantId: alertDfirTenantId,
    csrfToken: "csrf-receipt-test",
    idempotencyKey: "alert-original-receipt-0001",
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
            alertDfirApi.transitionTask({
              ...common,
              taskId: alertDfirTaskId,
              body,
            }),
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
            alertDfirApi.replaceTaskDetails({
              ...common,
              taskId: alertDfirTaskId,
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
            alertDfirApi.assignTask({
              ...common,
              taskId: alertDfirTaskId,
              body,
            }),
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
            alertDfirApi.rescheduleTask({
              ...common,
              taskId: alertDfirTaskId,
              body,
            }),
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
            alertDfirApi.replaceTaskChecklist({
              ...common,
              taskId: alertDfirTaskId,
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
            alertDfirApi.replaceTaskComments({
              ...common,
              taskId: alertDfirTaskId,
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
        const task = alertDfirExtendedWorkspaceFixture().tasks[0]!;
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
      const evidence = alertDfirExtendedWorkspaceFixture().evidence[0]!;
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
      const result = alertDfirApi.appendCustody({
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
      const relationship =
        alertDfirExtendedWorkspaceFixture().relationships[0]!;
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
      const result = alertDfirApi.retractRelationship({
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
  else await expect(result).rejects.toThrow(AlertDfirApiError);
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
