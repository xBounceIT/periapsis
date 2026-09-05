import type { AlertRelation } from "@periapsis/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AlertRelationApiError,
  alertRelationApi,
  isCanonicalAlertRelationReason,
  projectAlertRelationPage,
} from "./alert-relation-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const alertId = "0198c97d-cf4f-7000-8000-000000000011";
const relatedAlertId = "0198c97d-cf4f-7000-8000-000000000021";
const secondRelatedAlertId = "0198c97d-cf4f-7000-8000-000000000022";
const relationId = "0198c97d-cf4f-7000-8000-000000000041";
const newerRelationId = "0198c97d-cf4f-7000-8000-000000000042";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("alertRelationApi", () => {
  it("projects a strict newest-first page and binds the UUIDv7 cursor", async () => {
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        jsonResponse({
          items: [
            relation({
              id: newerRelationId,
              targetAlertId: secondRelatedAlertId,
            }),
            relation(),
          ],
          nextCursor: relationId,
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      alertRelationApi.list({
        after: "0198c97d-cf4f-7000-8000-000000000050",
        alertId,
        limit: 2,
        tenantId,
      }),
    ).resolves.toMatchObject({
      items: [
        { id: newerRelationId, relatedAlert: { id: secondRelatedAlertId } },
        { id: relationId, relatedAlert: { id: relatedAlertId } },
      ],
      nextCursor: relationId,
    });

    const request = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) throw new Error("Expected Request");
    const url = new URL(request.url);
    expect(url.pathname).toBe(
      `/api/v1/tenants/${tenantId}/alerts/${alertId}/related-alerts`,
    );
    expect(url.searchParams.get("after")).toBe(
      "0198c97d-cf4f-7000-8000-000000000050",
    );
    expect(url.searchParams.get("limit")).toBe("2");
    expect(request.cache).toBe("no-store");
    expect(request.credentials).toBe("same-origin");
  });

  it("fails closed on extra data, coordinate drift, semantic drift, and forged cursors", () => {
    const base = relation();
    const variants: unknown[] = [
      { items: [{ ...base, secret: "must-not-project" }] },
      { items: [{ ...base, tenantId: secondRelatedAlertId }] },
      { items: [{ ...base, direction: "symmetric" }] },
      {
        items: [
          { ...base, relatedAlert: { ...base.relatedAlert, id: alertId } },
        ],
      },
      { items: [{ ...base, sourceVersion: base.previousSourceVersion + 2 }] },
      { items: [{ ...base, status: "retracted" }] },
      {
        items: [
          base,
          { ...base, id: newerRelationId, targetAlertId: secondRelatedAlertId },
        ],
      },
      { items: [base, { ...base, id: newerRelationId }] },
      { items: [base], nextCursor: newerRelationId },
      { items: [base], nextCursor: relationId },
      { items: [], nextCursor: relationId },
    ];

    for (const variant of variants) {
      expect(() =>
        projectAlertRelationPage(
          variant,
          tenantId,
          alertId,
          "0198c97d-cf4f-7000-8000-000000000050",
          2,
        ),
      ).toThrow(AlertRelationApiError);
    }
    expect(() =>
      projectAlertRelationPage(
        { items: [] },
        "not-a-tenant",
        alertId,
        undefined,
        2,
      ),
    ).toThrow(AlertRelationApiError);
    expect(() =>
      projectAlertRelationPage({ items: [] }, tenantId, alertId, undefined, 0),
    ).toThrow(AlertRelationApiError);
  });

  it("binds create and append-only retraction to both exact versions", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn<typeof fetch>((input) => {
      if (!(input instanceof Request)) throw new TypeError("Request required");
      requests.push(input);
      const isRetraction = input.url.endsWith(`/${relationId}/retract`);
      return Promise.resolve(
        jsonResponse(
          receipt({
            alertVersion: isRetraction ? 12 : 11,
            previousAlertVersion: isRetraction ? 11 : 10,
            previousRelatedAlertVersion: isRetraction ? 21 : 20,
            relatedAlertVersion: isRetraction ? 22 : 21,
            relationType: isRetraction ? "duplicate_of" : "correlation",
          }),
          200,
          {
            ETag: isRetraction ? '"v12"' : '"v11"',
            "X-Idempotent-Replay": "false",
          },
        ),
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      alertRelationApi.create({
        alertEtag: '"v10"',
        alertId,
        csrfToken: "csrf-relation-memory-only",
        expectedAlertVersion: 10,
        expectedTargetVersion: 20,
        idempotencyKey: "alert-relation-create-0001",
        reason: "Literal <telemetry> match",
        relationType: "correlation",
        targetAlertId: relatedAlertId,
        tenantId,
      }),
    ).resolves.toMatchObject({ alertVersion: 11, relatedAlertVersion: 21 });

    await expect(
      alertRelationApi.retract({
        alertEtag: '"v11"',
        alertId,
        csrfToken: "csrf-relation-memory-only",
        expectedAlertVersion: 11,
        expectedRelatedAlertVersion: 21,
        idempotencyKey: "alert-relation-retract-001",
        reason: "Evidence superseded",
        relation: relation({ relatedVersion: 21 }),
        tenantId,
      }),
    ).resolves.toMatchObject({ alertVersion: 12, relatedAlertVersion: 22 });

    expect(requests).toHaveLength(2);
    expect(requests[0]?.headers.get("If-Match")).toBe('"v10"');
    expect(requests[1]?.headers.get("If-Match")).toBe('"v11"');
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe(
      "csrf-relation-memory-only",
    );
    expect(requests[1]?.url).toContain(`/${relationId}/retract`);
    await expect(requests[0]!.clone().json()).resolves.toEqual({
      expectedTargetVersion: 20,
      expectedVersion: 10,
      reason: "Literal <telemetry> match",
      relationType: "correlation",
      targetAlertId: relatedAlertId,
    });
    await expect(requests[1]!.clone().json()).resolves.toEqual({
      expectedRelatedAlertVersion: 21,
      expectedVersion: 11,
      reason: "Evidence superseded",
      relatedAlertId,
    });
  });

  it("rejects unsafe reason bytes and mismatched receipts before applying them", async () => {
    expect(isCanonicalAlertRelationReason("Literal <indicator> evidence")).toBe(
      true,
    );
    expect(isCanonicalAlertRelationReason("line one\nline two")).toBe(false);
    expect(isCanonicalAlertRelationReason("event\tdata")).toBe(false);
    expect(isCanonicalAlertRelationReason(" bidi\u202e")).toBe(false);
    expect(isCanonicalAlertRelationReason("é".repeat(1_001))).toBe(false);

    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        jsonResponse(receipt({ relatedAlertId: secondRelatedAlertId }), 200, {
          ETag: '"v11"',
          "X-Idempotent-Replay": "false",
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      alertRelationApi.create({
        alertEtag: '"v10"',
        alertId,
        csrfToken: "csrf-relation-memory-only",
        expectedAlertVersion: 10,
        expectedTargetVersion: 20,
        idempotencyKey: "alert-relation-create-0001",
        reason: "Correlated telemetry",
        relationType: "correlation",
        targetAlertId: relatedAlertId,
        tenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });
});

function relation(
  overrides: Partial<AlertRelation & { relatedVersion: number }> = {},
): AlertRelation {
  const { relatedVersion = 7, ...relationOverrides } = overrides;
  const target = relationOverrides.targetAlertId ?? relatedAlertId;
  return {
    id: overrides.id ?? relationId,
    tenantId,
    sourceAlertId: alertId,
    targetAlertId: target,
    relationType: "duplicate_of",
    direction: "outgoing",
    status: "active",
    reason: "Same endpoint telemetry",
    previousSourceVersion: 1,
    sourceVersion: 2,
    previousTargetVersion: 5,
    targetVersion: 6,
    linkedAt: "2026-09-02T08:00:00Z",
    relatedAlert: {
      id: target,
      number: "ALT-2026-000042",
      title: "Related endpoint signal",
      severity: "high",
      stateKey: "investigating",
      version: relatedVersion,
      updatedAt: "2026-09-02T08:01:00Z",
    },
    ...relationOverrides,
  };
}

function receipt(
  overrides: Partial<{
    alertVersion: number;
    previousAlertVersion: number;
    previousRelatedAlertVersion: number;
    relatedAlertId: string;
    relatedAlertVersion: number;
    relationType: "duplicate_of" | "correlation";
  }> = {},
) {
  return {
    tenantId,
    alertId,
    relatedAlertId: overrides.relatedAlertId ?? relatedAlertId,
    relationId,
    relationType: overrides.relationType ?? "correlation",
    previousAlertVersion: overrides.previousAlertVersion ?? 10,
    alertVersion: overrides.alertVersion ?? 11,
    previousRelatedAlertVersion: overrides.previousRelatedAlertVersion ?? 20,
    relatedAlertVersion: overrides.relatedAlertVersion ?? 21,
    occurredAt: "2026-09-02T08:02:00Z",
    replayed: false,
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ...headers,
    },
    status,
  });
}
