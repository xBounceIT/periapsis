import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  OperatorComment,
  SavedTicketViewCreateRequest,
} from "@periapsis/contracts";

import {
  alertId,
  caseId,
  customDefinitionId,
  customerAlert,
  operatorAlertWithDynamicColumns,
  operatorAlert,
  operatorCase,
  savedAlertView,
  savedViewId,
  tenantId,
  teamId,
  userId,
} from "../ticketing/ticketing-test-fixtures";
import { ticketingApi } from "./ticketing-api";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketingApi", () => {
  it("reconstructs a customer Alert from an explicit safe-field allowlist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...customerAlert,
              assignment: operatorAlert.assignment,
              classification: "restricted",
              creator: operatorAlert.creator,
              rawPayload: { token: "must-not-cross-projection" },
            },
          ],
        }),
      ),
    );

    const result = await ticketingApi.listTickets("alert", tenantId, {});

    expect(result.items).toEqual([customerAlert]);
    expect(result.items[0]).not.toHaveProperty("assignment");
    expect(result.items[0]).not.toHaveProperty("rawPayload");
    expect(result.items[0]).not.toHaveProperty("classification");
  });

  it("rejects a detail whose strong ETag disagrees with its body version", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(operatorAlert, '"v2"')),
    );

    await expect(
      ticketingApi.getTicket("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("binds transitions to If-Match, expected version, and one idempotent attempt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { ...operatorAlert, version: 2, updatedAt: "2026-08-25T08:12:00Z" },
          '"v2"',
        );
      }),
    );

    await ticketingApi.mutateTicket({
      action: "transition",
      body: {
        expectedVersion: 1,
        targetStateKey: "investigating",
        transitionKey: "start_investigation",
      },
      csrfToken: "csrf-memory-only-value",
      etag: '"v1"',
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000099",
      kind: "alert",
      resourceId: alertId,
      tenantId,
    });

    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.headers.get("If-Match")).toBe('"v1"');
    expect(request!.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only-value");
    await expect(request!.clone().json()).resolves.toMatchObject({
      expectedVersion: 1,
      targetStateKey: "investigating",
      transitionKey: "start_investigation",
    });
  });

  it("binds Alert deletion to the exact version and validates its tombstone receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            alertId,
            deletedAt: "2026-08-30T18:20:00.123Z",
            previousVersion: 1,
            replayed: false,
            tenantId,
            tombstoneVersion: 2,
          },
          '"v2"',
        );
      }),
    );

    const receipt = await ticketingApi.deleteAlert({
      body: { expectedVersion: 1, reason: "False positive confirmed." },
      csrfToken: "csrf-memory-only-value",
      etag: '"v1"',
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000098",
      resourceId: alertId,
      tenantId,
    });

    expect(receipt).toMatchObject({
      alertId,
      previousVersion: 1,
      tenantId,
      tombstoneVersion: 2,
    });
    const request = requests[0];
    expect(request?.method).toBe("DELETE");
    expect(request?.headers.get("If-Match")).toBe('"v1"');
    expect(request?.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000098",
    );
    await expect(request?.clone().json()).resolves.toEqual({
      expectedVersion: 1,
      reason: "False positive confirmed.",
    });
  });

  it("rejects an incoherent Alert tombstone before exposing success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            alertId,
            deletedAt: "2026-08-30T18:20:00.123Z",
            previousVersion: 1,
            replayed: false,
            tenantId,
            tombstoneVersion: 3,
          },
          '"v3"',
        ),
      ),
    );

    await expect(
      ticketingApi.deleteAlert({
        body: { expectedVersion: 1, reason: "False positive confirmed." },
        csrfToken: "csrf-memory-only-value",
        etag: '"v1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000097",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a claim response whose persisted winner version drifts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            alert: { ...operatorAlert, version: 2 },
            sideEffects: {},
            winner: {
              claimedAt: "2026-08-25T08:13:00Z",
              claimedBy: userId,
              version: 3,
            },
          },
          '"v2"',
        ),
      ),
    );

    await expect(
      ticketingApi.mutateTicket({
        action: "claim",
        body: { expectedVersion: 1, operatorTeamId: teamId },
        csrfToken: "csrf-memory-only-value",
        etag: '"v1"',
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("requires an exact applied-view proof and operator-only dynamic columns", async () => {
    const fetch = vi.fn().mockResolvedValue(
      jsonResponse({
        appliedView: {
          id: savedViewId,
          revision: savedAlertView.revision,
          specSha256: savedAlertView.specSha256,
        },
        items: [operatorAlertWithDynamicColumns],
      }),
    );
    vi.stubGlobal("fetch", fetch);

    const page = await ticketingApi.listTickets("alert", tenantId, {
      limit: 30,
      viewId: savedViewId,
    });

    expect(page.appliedView).toEqual({
      id: savedViewId,
      revision: savedAlertView.revision,
      specSha256: savedAlertView.specSha256,
    });
    expect(page.items[0]).toMatchObject({
      dynamicColumns: operatorAlertWithDynamicColumns.dynamicColumns,
    });
    const request: unknown = fetch.mock.calls[0]?.[0];
    expect(request).toBeInstanceOf(Request);
    if (!(request instanceof Request)) throw new TypeError("Expected request");
    expect(new URL(request.url).searchParams.get("viewId")).toBe(savedViewId);
    expect(new URL(request.url).searchParams.has("sort")).toBe(false);
  });

  it("rejects missing saved-view proof and unsolicited dynamic projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({ items: [operatorAlertWithDynamicColumns] }),
        )
        .mockResolvedValueOnce(
          jsonResponse({ items: [operatorAlertWithDynamicColumns] }),
        ),
    );

    await expect(
      ticketingApi.listTickets("alert", tenantId, { viewId: savedViewId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listTickets("alert", tenantId, {}),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("accepts only a canonical saved-view cursor bound to the final item", async () => {
    const requests: Request[] = [];
    const cursor = "AZjJfc9PcACAAAAAAAAAIA";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({ items: [savedAlertView], nextCursor: cursor });
      }),
    );

    const page = await ticketingApi.listSavedTicketViews({
      after: cursor,
      includeArchived: false,
      kind: "alert",
      tenantId,
    });

    expect(page.nextCursor).toBe(cursor);
    expect(new URL(requests[0]!.url).searchParams.get("after")).toBe(cursor);
    expect(new URL(requests[0]!.url).searchParams.get("limit")).toBe("100");
  });

  it("rejects unsafe saved-view page and cursor projections", async () => {
    const cursor = "AZjJfc9PcACAAAAAAAAAIA";
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [], nextCursor: cursor }))
        .mockResolvedValueOnce(
          jsonResponse({
            items: [savedAlertView],
            nextCursor: "AZjJfc9PcACAAAAAAAAAIQ",
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({ items: [savedAlertView], nextCursor: savedViewId }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            internalSecret: "must-not-cross-the-projection-boundary",
            items: [savedAlertView],
          }),
        ),
    );

    await expect(
      ticketingApi.listSavedTicketViews({ kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listSavedTicketViews({ kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listSavedTicketViews({ kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listSavedTicketViews({ kind: "alert", tenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a malformed saved-view cursor before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketingApi.listSavedTicketViews({
        after: savedViewId,
        kind: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listSavedTicketViews({
        after: "AAAAAAAAAAAAAAAAAAAAAA",
        kind: "alert",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("binds saved-view replacement to exact ETag, revision, CSRF, and idempotency", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { replayed: false, view: savedAlertView },
          `"sha256-${savedAlertView.specSha256}"`,
        );
      }),
    );
    const etag = `"sha256-${savedAlertView.specSha256}"`;
    const idempotencyKey = "saved-view-0198c97d-cf4f-7000-8000-000000000099";

    await ticketingApi.replaceSavedTicketView({
      body: {
        expectedRevision: savedAlertView.revision,
        kind: "alert",
        name: savedAlertView.name,
        spec: {
          filters: {
            states: ["new"],
            severities: ["high"],
            priorities: ["urgent"],
            queue: "my_operator_teams",
            custom: [],
          },
          sort: {
            source: "core",
            coreKey: "updated_at",
            direction: "desc",
            nulls: "last",
          },
          columns: [
            {
              source: "core",
              coreKey: "ticket",
              visible: true,
              pin: "start",
              width: 340,
            },
          ],
        },
      },
      csrfToken: "csrf-memory-only-value",
      etag,
      idempotencyKey,
      tenantId,
      viewId: savedViewId,
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]!.headers.get("If-Match")).toBe(etag);
    expect(requests[0]!.headers.get("Idempotency-Key")).toBe(idempotencyKey);
    expect(requests[0]!.headers.get("X-CSRF-Token")).toBe(
      "csrf-memory-only-value",
    );
    await expect(requests[0]!.clone().json()).resolves.toMatchObject({
      expectedRevision: savedAlertView.revision,
      kind: "alert",
    });
  });

  it("rejects non-canonical saved-view commands before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const mixedCore = savedViewCreateRequest();
    Object.assign(mixedCore.spec.columns[0]!, {
      definitionId: customDefinitionId,
      expectedDefinitionVersion: 4,
    });
    const duplicateDynamic = savedViewCreateRequest();
    duplicateDynamic.spec.columns.push(
      {
        source: "custom_field",
        definitionId: customDefinitionId,
        expectedDefinitionVersion: 4,
        visible: true,
        pin: "none",
      },
      {
        source: "custom_field",
        definitionId: customDefinitionId,
        expectedDefinitionVersion: 4,
        visible: false,
        pin: "none",
      },
    );
    const oversizedUtf8Name = savedViewCreateRequest();
    oversizedUtf8Name.name = "😀".repeat(31);

    await Promise.all(
      [mixedCore, duplicateDynamic, oversizedUtf8Name].map((body) =>
        expect(
          ticketingApi.createSavedTicketView({
            body,
            csrfToken: "csrf-memory-only-value",
            idempotencyKey: "saved-view-0198c97d-cf4f-7000-8000-000000000099",
            tenantId,
          }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects inconsistent dynamic pins and nested response fields", async () => {
    const request = savedViewCreateRequest();
    request.spec.filters.custom.push({
      definitionId: customDefinitionId,
      expectedDefinitionVersion: 4,
      operator: "equal",
      value: "finance",
    });
    request.spec.columns.push({
      source: "custom_field",
      definitionId: customDefinitionId,
      expectedDefinitionVersion: 5,
      visible: true,
      pin: "none",
    });
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      ticketingApi.createSavedTicketView({
        body: request,
        csrfToken: "csrf-memory-only-value",
        idempotencyKey: "saved-view-0198c97d-cf4f-7000-8000-000000000098",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetch).not.toHaveBeenCalled();

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          ...savedAlertView,
          spec: {
            ...savedAlertView.spec,
            columns: savedAlertView.spec.columns.map((column, index) =>
              index === 1
                ? {
                    ...column,
                    definition: {
                      ...column.definition!,
                      secret: "must-not-cross",
                    },
                  }
                : column,
            ),
          },
        }),
      ),
    );
    await expect(
      ticketingApi.getSavedTicketView({
        kind: "alert",
        tenantId,
        viewId: savedViewId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("accepts a dynamic sort whose exactly pinned projection is hidden", async () => {
    const hiddenSortView = {
      ...savedAlertView,
      spec: {
        ...savedAlertView.spec,
        columns: savedAlertView.spec.columns.map((column) =>
          column.source === "sla" ? { ...column, visible: false } : column,
        ),
      },
    };
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(hiddenSortView, `"sha256-${savedAlertView.specSha256}"`),
        ),
    );

    const result = await ticketingApi.getSavedTicketView({
      kind: "alert",
      tenantId,
      viewId: savedViewId,
    });

    expect(result.value.spec.columns.at(-1)).toMatchObject({
      source: "sla",
      visible: false,
    });
  });

  it("preserves canonical wide decimals and rejects numeric response drift", async () => {
    const wide = "9".repeat(200);
    const decimalView = {
      ...savedAlertView,
      spec: {
        ...savedAlertView.spec,
        filters: {
          ...savedAlertView.spec.filters,
          custom: savedAlertView.spec.filters.custom.map((filter) => ({
            ...filter,
            dataType: "decimal" as const,
            value: wide,
          })),
        },
      },
    };
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse(decimalView, `"sha256-${savedAlertView.specSha256}"`),
        )
        .mockResolvedValueOnce(
          jsonResponse(
            {
              ...decimalView,
              spec: {
                ...decimalView.spec,
                filters: {
                  ...decimalView.spec.filters,
                  custom: decimalView.spec.filters.custom.map((filter) => ({
                    ...filter,
                    value: 10.5,
                  })),
                },
              },
            },
            `"sha256-${savedAlertView.specSha256}"`,
          ),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            appliedView: {
              id: savedViewId,
              revision: savedAlertView.revision,
              specSha256: savedAlertView.specSha256,
            },
            items: [
              {
                ...operatorAlertWithDynamicColumns,
                dynamicColumns:
                  operatorAlertWithDynamicColumns.dynamicColumns.map(
                    (column) =>
                      column.source === "sla"
                        ? { ...column, value: 10.5 }
                        : column,
                  ),
              },
            ],
          }),
        ),
    );

    const result = await ticketingApi.getSavedTicketView({
      kind: "alert",
      tenantId,
      viewId: savedViewId,
    });
    expect(result.value.spec.filters.custom[0]?.value).toBe(wide);
    await expect(
      ticketingApi.getSavedTicketView({
        kind: "alert",
        tenantId,
        viewId: savedViewId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listTickets("alert", tenantId, { viewId: savedViewId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects an escalation response with an open or incomplete side-effect plan", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            alert: operatorAlert,
            case: operatorCase,
            links: [],
            sideEffects: ["activity"],
          },
          '"v1"',
        ),
      ),
    );

    await expect(
      ticketingApi.escalateAlert({
        body: {
          expectedVersion: 1,
          reason: "Open a separate investigation.",
          relationType: "escalation",
          sources: [
            {
              alertId,
              copySelection: { fields: ["title"] },
              expectedVersion: 1,
            },
          ],
          target: {
            case: {
              priority: "urgent",
              severity: "high",
              title: "Investigation",
            },
            mode: "create_case",
          },
        },
        csrfToken: "csrf-memory-only-value",
        etag: '"v1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000082",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("routes existing-Case wizard submissions through the explicit link action", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          {
            alert: { ...operatorAlert, version: 2 },
            case: { ...operatorCase, version: 2 },
            links: [operatorLink()],
            sideEffects: ["activity", "audit"],
          },
          '"v2"',
        );
      }),
    );

    await ticketingApi.escalateAlert({
      body: {
        expectedVersion: 1,
        reason: "Correlate with the governed investigation.",
        relationType: "correlation",
        sources: [{ alertId, copySelection: {}, expectedVersion: 1 }],
        target: { caseId, expectedVersion: 1, mode: "existing_case" },
      },
      csrfToken: "csrf-memory-only-value",
      etag: '"v1"',
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000088",
      resourceId: alertId,
      tenantId,
    });

    expect(requests[0]?.url).toContain(`/alerts/${alertId}/link`);
    expect(requests[0]?.url).not.toContain("/escalate");
  });

  it("rejects malformed, cross-root, and duplicate links in link responses", async () => {
    const request = {
      body: {
        expectedVersion: 1,
        reason: "Correlate with the governed investigation.",
        relationType: "correlation" as const,
        sources: [{ alertId, copySelection: {}, expectedVersion: 1 }],
        target: {
          caseId,
          expectedVersion: 1,
          mode: "existing_case" as const,
        },
      },
      csrfToken: "csrf-memory-only-value",
      etag: '"v1"',
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000088",
      resourceId: alertId,
      tenantId,
    };
    const otherUuid = "0198c97d-cf4f-7000-8000-000000000098";
    const invalidLinkSets = [
      [{ ...operatorLink(), id: "not-a-uuid" }],
      [{ ...operatorLink(), linkedAt: "2026-08-25 08:15:00" }],
      [{ ...operatorLink(), tenantId: otherUuid }],
      [{ ...operatorLink(), caseId: otherUuid }],
      [operatorLink(), operatorLink()],
      [operatorLink(), { ...operatorLink(), id: otherUuid }],
    ];

    const fetch = vi.fn();
    for (const links of invalidLinkSets) {
      fetch.mockResolvedValueOnce(
        jsonResponse(
          {
            alert: { ...operatorAlert, version: 2 },
            case: { ...operatorCase, version: 2 },
            links,
            sideEffects: ["activity", "audit"],
          },
          '"v2"',
        ),
      );
    }
    vi.stubGlobal("fetch", fetch);

    await Promise.all(
      invalidLinkSets.map(() =>
        expect(ticketingApi.escalateAlert(request)).rejects.toMatchObject({
          code: "projection_mismatch",
        }),
      ),
    );
  });

  it("rejects duplicate links in active-link list projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ items: [operatorLink(), operatorLink()] }),
        ),
    );

    await expect(
      ticketingApi.listLinks("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("binds unlink to both current versions and rejects a drifted receipt", async () => {
    const requests: Request[] = [];
    const fetch = vi.fn(async (input: RequestInfo | URL) => {
      if (input instanceof Request) requests.push(input);
      return jsonResponse(
        {
          alertId,
          alertVersion: 2,
          caseId,
          caseVersion: 2,
          linkId: operatorLink().id,
          previousAlertVersion: 1,
          previousCaseVersion: 1,
          replayed: false,
          retractedAt: "2026-08-30T18:20:00.123Z",
          tenantId,
        },
        '"v2"',
      );
    });
    vi.stubGlobal("fetch", fetch);

    const body = {
      caseId,
      expectedCaseVersion: 1,
      expectedVersion: 1,
      reason: "This relationship was superseded.",
    };
    await expect(
      ticketingApi.unlinkAlertCase({
        body,
        csrfToken: "csrf-memory-only-value",
        etag: '"v1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000089",
        resourceId: alertId,
        tenantId,
      }),
    ).resolves.toMatchObject({ alertVersion: 2, caseVersion: 2 });
    expect(requests[0]?.url).toContain(`/alerts/${alertId}/unlink`);
    expect(requests[0]?.headers.get("If-Match")).toBe('"v1"');
    await expect(requests[0]?.clone().json()).resolves.toEqual(body);

    fetch.mockImplementationOnce(async () =>
      jsonResponse(
        {
          alertId,
          alertVersion: 2,
          caseId,
          caseVersion: 3,
          linkId: operatorLink().id,
          previousAlertVersion: 1,
          previousCaseVersion: 1,
          replayed: true,
          retractedAt: "2026-08-30T18:20:00.123Z",
          tenantId,
        },
        '"v2"',
      ),
    );
    await expect(
      ticketingApi.unlinkAlertCase({
        body,
        csrfToken: "csrf-memory-only-value",
        etag: '"v1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000089",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("accepts closed service-account, system, and human activity actor projections", async () => {
    const membershipId = "0198c97d-cf4f-7000-8000-000000000083";
    const serviceAccountId = "0198c97d-cf4f-7000-8000-000000000084";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            activity("alert", "created", {
              displayName: "EDR ingest",
              origin: "operator",
              principalType: "service_account",
              serviceAccountId,
            }),
            activity("alert", "assigned", {
              displayName: "System",
              origin: "operator",
              principalType: "system",
            }),
            activity("alert", "transitioned", {
              displayName: "Analyst",
              membershipId,
              origin: "operator",
            }),
          ],
        }),
      ),
    );

    const page = await ticketingApi.listActivities("alert", tenantId, alertId);

    expect(page.items.map((item) => item.actor)).toEqual([
      {
        displayName: "EDR ingest",
        origin: "operator",
        principalType: "service_account",
        serviceAccountId,
      },
      {
        displayName: "System",
        origin: "operator",
        principalType: "system",
      },
      { displayName: "Analyst", membershipId, origin: "operator" },
    ]);
  });

  it("rejects mixed or missing operator activity identities", async () => {
    const mixed = activity("alert", "created", {
      displayName: "Ambiguous",
      membershipId: "0198c97d-cf4f-7000-8000-000000000085",
      origin: "operator",
      principalType: "service_account",
      serviceAccountId: "0198c97d-cf4f-7000-8000-000000000086",
    });
    const missing = activity("alert", "created", {
      displayName: "Incomplete",
      origin: "operator",
      principalType: "service_account",
    });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [mixed] }))
        .mockResolvedValueOnce(jsonResponse({ items: [missing] })),
    );

    await expect(
      ticketingApi.listActivities("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listActivities("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("loads the tenant-wide activity feed with a kind-bound cursor", async () => {
    const after = "0198c97d-cf4f-7000-8000-000000000090";
    const newer = {
      ...activity("alert", "assigned", {
        displayName: "Analyst",
        membershipId: userId,
        origin: "operator",
      }),
      id: "0198c97d-cf4f-7000-8000-000000000089",
      resourceId: alertId,
    };
    const older = {
      ...newer,
      id: "0198c97d-cf4f-7000-8000-000000000088",
      resourceId: "0198c97d-cf4f-7000-8000-000000000081",
    };
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({ items: [newer, older], nextCursor: older.id });
      }),
    );

    const page = await ticketingApi.listActivityFeed("alert", tenantId, after);

    expect(page.items.map((item) => item.resourceId)).toEqual([
      alertId,
      older.resourceId,
    ]);
    expect(page.nextCursor).toBe(older.id);
    expect(requests[0]?.url).toContain(
      `/api/v1/tenants/${tenantId}/activities/alerts`,
    );
    expect(requests[0]?.url).toContain(`after=${after}`);
    expect(requests[0]?.url).toContain("limit=50");
  });

  it("rejects malformed or non-descending tenant activity projections", async () => {
    const item = {
      ...activity("case", "assigned", {
        displayName: "Analyst",
        membershipId: userId,
        origin: "operator",
      }),
      id: "0198c97d-cf4f-7000-8000-000000000088",
      secret: "must not be accepted",
    };
    const withoutSecret = Object.fromEntries(
      Object.entries(item).filter(([key]) => key !== "secret"),
    );
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [item] }))
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              withoutSecret,
              {
                ...withoutSecret,
                id: "0198c97d-cf4f-7000-8000-000000000089",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [withoutSecret],
            nextCursor: "0198c97d-cf4f-7000-8000-000000000087",
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [],
            nextCursor: "0198c97d-cf4f-7000-8000-000000000087",
          }),
        ),
    );

    await expect(
      ticketingApi.listActivityFeed("case", tenantId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listActivityFeed("case", tenantId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listActivityFeed("case", tenantId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listActivityFeed("case", tenantId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("strips server HTML and rejects customer projections on the operator route", async () => {
    const comment = {
      projection: "operator",
      id: "0198c97d-cf4f-7000-8000-000000000080",
      tenantId,
      resourceKind: "alert",
      resourceId: alertId,
      visibility: "public",
      bodyMarkdown: "Customer-safe update",
      bodyHtml: '<img src=x onerror="alert(1)">',
      author: {
        audience: "operator",
        displayName: "Analyst",
        membershipId: userId,
      },
      attachments: [],
      canEdit: false,
      editableUntil: "2026-08-25T08:35:00Z",
      mentions: [],
      origin: "api",
      revision: 1,
      createdAt: "2026-08-25T08:20:00Z",
      updatedAt: "2026-08-25T08:20:00Z",
    } as const;
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [comment] }))
        .mockResolvedValueOnce(
          jsonResponse({
            ...comment,
            projection: "customer",
            author: { audience: "customer", displayName: "Customer" },
            visibility: "public",
          }),
        ),
    );

    const page = await ticketingApi.listComments("alert", tenantId, alertId);
    expect(page.items[0]).not.toHaveProperty("bodyHtml");

    await expect(
      ticketingApi.createComment({
        body: { bodyMarkdown: "No", visibility: "public" },
        csrfToken: "csrf-memory-only-value",
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000081",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("keeps comment lists no-store and rejects bad coordinates or duplicate page items", async () => {
    const requests: Request[] = [];
    const comment = operatorCommentResponse();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        if (requests.length === 1) return jsonResponse({ items: [comment] });
        if (requests.length === 2) {
          return jsonResponse({ items: [comment, comment] });
        }
        return jsonResponse({ items: [comment], nextCursor: "not-a-cursor" });
      }),
    );

    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).resolves.toMatchObject({ items: [{ id: comment.id }] });
    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listComments("alert", tenantId, "not-a-ticket-id"),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listComments("alert", tenantId, alertId, "not-a-cursor"),
    ).rejects.toMatchObject({ code: "projection_mismatch" });

    expect(requests).toHaveLength(3);
    expect(requests[0]?.cache).toBe("no-store");
  });

  it("uses Unicode-scalar comment limits and leaves raw-HTML decisions to the server", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const body = await operatorPreviewRequestBody(input);
      if (body.bodyMarkdown === "<script>alert(1)</script>") {
        return jsonResponse(
          {
            code: "validation_failed",
            status: 422,
            title: "Validation failed",
            type: "about:blank",
          },
          undefined,
          422,
        );
      }
      return jsonResponse({
        attachments: [],
        bodyHtml: "<p>server-only</p>",
        bodyMarkdown: body.bodyMarkdown,
        mentions: [],
        visibility: body.visibility,
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    await Promise.all(
      [
        "`<script>` is evidence",
        "```html\n<script>\n```",
        "😀".repeat(20_000),
        "\uFEFF",
      ].map((bodyMarkdown) =>
        expect(
          ticketingApi.previewComment({
            body: { bodyMarkdown, visibility: "public" },
            csrfToken: "csrf-memory-only-value",
            kind: "alert",
            resourceId: alertId,
            tenantId,
          }),
        ).resolves.toMatchObject({ bodyMarkdown }),
      ),
    );

    await expect(
      ticketingApi.previewComment({
        body: {
          bodyMarkdown: "<script>alert(1)</script>",
          visibility: "public",
        },
        csrfToken: "csrf-memory-only-value",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ status: 422 });
    await expect(
      ticketingApi.previewComment({
        body: { bodyMarkdown: "😀".repeat(20_001), visibility: "public" },
        csrfToken: "csrf-memory-only-value",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it("rejects non-canonical edge whitespace, CR, and bidi controls before transport", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      ticketingApi.previewComment({
        body: { bodyMarkdown: "first\rsecond", visibility: "public" },
        csrfToken: "csrf-memory-only-value",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await Promise.all(
      [" leading", "trailing\u3000", String.fromCharCode(0xd800)].map(
        (bodyMarkdown) =>
          expect(
            ticketingApi.previewComment({
              body: { bodyMarkdown, visibility: "public" },
              csrfToken: "csrf-memory-only-value",
              kind: "alert",
              resourceId: alertId,
              tenantId,
            }),
          ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
    await expect(
      ticketingApi.editComment({
        body: {
          bodyMarkdown: "Corrected evidence",
          reason: "Correct\u202e timeline",
        },
        commentId: operatorCommentResponse().id,
        csrfToken: "csrf-memory-only-value",
        etag: '"comment-r1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000082",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.editComment({
        body: {
          bodyMarkdown: "Corrected evidence",
          reason: "<unfinished",
        },
        commentId: operatorCommentResponse().id,
        csrfToken: "csrf-memory-only-value",
        etag: '"comment-r1"',
        idempotencyKey: "0198c97d-cf4f-7000-8000-000000000082",
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listCommentMentionCandidates({
        kind: "alert",
        resourceId: alertId,
        search: "Analyst\u2066name",
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects mention candidates that repeat a membership under another name", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              audience: "operator",
              displayName: "Analyst A",
              membershipId: userId,
            },
            {
              audience: "operator",
              displayName: "Analyst B",
              membershipId: userId,
            },
          ],
        }),
      ),
    );

    await expect(
      ticketingApi.listCommentMentionCandidates({
        kind: "alert",
        resourceId: alertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects bidi controls in comment Markdown, frozen names, and filenames", async () => {
    const comment = operatorCommentResponse();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            items: [{ ...comment, bodyMarkdown: "Hidden\u202e direction" }],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...comment,
                author: {
                  ...comment.author,
                  displayName: "Analyst\u200fOne",
                },
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...comment,
                attachments: [
                  {
                    id: "0198c97d-cf4f-7000-8000-000000000083",
                    originalFilename: "evidence\u2066.txt",
                    projection: "operator",
                    visibility: "public",
                  },
                ],
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...comment,
                attachments: [
                  {
                    id: "0198c97d-cf4f-7000-8000-000000000083",
                    originalFilename: " evidence.txt",
                    projection: "operator",
                    visibility: "public",
                  },
                ],
              },
            ],
          }),
        ),
    );

    await Promise.all(
      Array.from({ length: 4 }, () =>
        expect(
          ticketingApi.listComments("alert", tenantId, alertId),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("binds operator edits to exact comment CAS and replay receipts", async () => {
    const requests: Request[] = [];
    const comment = operatorCommentResponse({
      bodyMarkdown: "Corrected evidence",
      revision: 2,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request)) {
          throw new TypeError("Expected a generated Request.");
        }
        const request = input;
        requests.push(request);
        return jsonResponse(comment, '"comment-r2"', 200, {
          "X-Idempotent-Replay": "true",
        });
      }),
    );

    const result = await ticketingApi.editComment({
      body: {
        bodyMarkdown: "Corrected evidence",
        reason: "Correct the observed indicator.",
      },
      commentId: comment.id,
      csrfToken: "csrf-memory-only-value",
      etag: '"comment-r1"',
      idempotencyKey: "0198c97d-cf4f-7000-8000-000000000082",
      kind: "alert",
      resourceId: alertId,
      tenantId,
    });

    expect(result).toMatchObject({
      etag: '"comment-r2"',
      replayed: true,
      value: { bodyMarkdown: "Corrected evidence", revision: 2 },
    });
    expect(requests[0]?.headers.get("If-Match")).toBe('"comment-r1"');
    expect(requests[0]?.headers.get("Idempotency-Key")).toBe(
      "0198c97d-cf4f-7000-8000-000000000082",
    );
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe(
      "csrf-memory-only-value",
    );
  });

  it("rejects incoherent operator comment authors and timestamps", async () => {
    const editable = operatorCommentResponse({ canEdit: true });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({ items: [{ ...editable, origin: "system" }] }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...editable,
                author: {
                  audience: "customer",
                  displayName: "Customer contact",
                },
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...operatorCommentResponse(),
                author: {
                  audience: "customer",
                  displayName: "Customer contact",
                  membershipId: userId,
                },
                origin: "system",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...operatorCommentResponse(),
                updatedAt: "2026-08-25T08:19:59Z",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...operatorCommentResponse(),
                updatedAt: "2026-08-25T08:35:01Z",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...operatorCommentResponse(),
                createdAt: "2026-08-25T08:20:00.000000001Z",
                editableUntil: "2026-08-25T08:35:00.000000001Z",
                updatedAt: "2026-08-25T08:35:00.000000002Z",
              },
            ],
          }),
        ),
    );

    await Promise.all(
      Array.from({ length: 6 }, () =>
        expect(
          ticketingApi.listComments("alert", tenantId, alertId),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("accepts scalar-bounded frozen names and canonical comment filenames only", async () => {
    const accepted = operatorCommentResponse({
      attachments: [
        {
          id: "0198c97d-cf4f-7000-8000-000000000083",
          originalFilename: "<evidence>.txt",
          projection: "operator",
          visibility: "public",
        },
      ],
      author: {
        audience: "operator",
        displayName: "😀".repeat(200),
        membershipId: userId,
      },
    });
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [accepted] }))
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...accepted,
                author: {
                  ...accepted.author,
                  displayName: "😀".repeat(201),
                },
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...accepted,
                attachments: [
                  { ...accepted.attachments[0], originalFilename: "." },
                ],
              },
            ],
          }),
        ),
    );

    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).resolves.toMatchObject({
      items: [
        {
          attachments: [{ originalFilename: "<evidence>.txt" }],
          author: { displayName: "😀".repeat(200) },
        },
      ],
    });
    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      ticketingApi.listComments("alert", tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("projects only active contact links bound to the exact Alert root", async () => {
    const link = {
      id: "0198c97d-cf4f-7000-8000-000000000090",
      tenantId,
      resourceKind: "alert",
      resourceId: alertId,
      contactId: "0198c97d-cf4f-7000-8000-000000000091",
      role: "primary",
      origin: "manual",
      version: 1,
      createdAt: "2026-08-25T08:20:00Z",
    } as const;
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse({ items: [link] }))
        .mockResolvedValueOnce(
          jsonResponse({ items: [{ ...link, resourceId: operatorCase.id }] }),
        ),
    );

    await expect(
      ticketingApi.listAlertContactLinks(tenantId, alertId),
    ).resolves.toEqual({ items: [link] });
    await expect(
      ticketingApi.listAlertContactLinks(tenantId, alertId),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });
});

function savedViewCreateRequest(): SavedTicketViewCreateRequest {
  return {
    kind: "alert",
    name: "Finance triage",
    spec: {
      filters: {
        states: ["new"],
        severities: ["high"],
        priorities: ["urgent"],
        queue: "my_operator_teams",
        custom: [],
      },
      sort: {
        source: "core",
        coreKey: "updated_at",
        direction: "desc",
        nulls: "last",
      },
      columns: [
        {
          source: "core",
          coreKey: "ticket",
          visible: true,
          pin: "start",
          width: 340,
        },
      ],
    },
  };
}

function jsonResponse(
  value: unknown,
  etag?: string,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Content-Type": "application/json",
      ...(etag ? { ETag: etag } : {}),
      ...extraHeaders,
    },
    status,
  });
}

function operatorCommentResponse(
  overrides: Partial<OperatorComment> = {},
): OperatorComment {
  return {
    attachments: [],
    author: {
      audience: "operator",
      displayName: "Analyst",
      membershipId: userId,
    },
    bodyHtml: "<p>server rendering</p>",
    bodyMarkdown: "Customer-safe update",
    canEdit: false,
    createdAt: "2026-08-25T08:20:00Z",
    editableUntil: "2026-08-25T08:35:00Z",
    id: "0198c97d-cf4f-7000-8000-000000000080",
    mentions: [],
    origin: "api",
    projection: "operator",
    resourceId: alertId,
    resourceKind: "alert",
    revision: 1,
    tenantId,
    updatedAt: "2026-08-25T08:20:00Z",
    visibility: "public",
    ...overrides,
  };
}

async function operatorPreviewRequestBody(input: RequestInfo | URL): Promise<{
  bodyMarkdown: string;
  visibility: "private" | "public";
}> {
  if (!(input instanceof Request)) {
    throw new TypeError("Expected a generated Request.");
  }
  const body: unknown = await input.clone().json();
  if (
    typeof body !== "object" ||
    body === null ||
    !("bodyMarkdown" in body) ||
    typeof body.bodyMarkdown !== "string" ||
    !("visibility" in body) ||
    (body.visibility !== "private" && body.visibility !== "public")
  ) {
    throw new TypeError("Expected an operator preview body.");
  }
  return {
    bodyMarkdown: body.bodyMarkdown,
    visibility: body.visibility,
  };
}

function activity(
  resourceKind: "alert" | "case",
  kind: string,
  actor: Record<string, string>,
) {
  return {
    projection: "operator",
    id: "0198c97d-cf4f-7000-8000-000000000087",
    tenantId,
    resourceKind,
    resourceId: resourceKind === "alert" ? alertId : operatorCase.id,
    kind,
    summary: "Bounded activity",
    actor,
    occurredAt: "2026-08-25T08:30:00Z",
  };
}

function operatorLink() {
  return {
    projection: "operator" as const,
    id: "0198c97d-cf4f-7000-8000-000000000097",
    tenantId,
    alertId,
    caseId,
    linkedAt: "2026-08-25T08:15:00Z",
    linkedBy: userId,
    relationType: "correlation" as const,
    escalationReason: "Correlated investigation",
    copySelection: {},
    copiedFieldSnapshot: {},
    sourceAlertVersion: 1,
  };
}
