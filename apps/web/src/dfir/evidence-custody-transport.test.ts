import type {
  DfirCustodyEvent,
  DfirEvidence,
  DfirEvidenceCollectRequest,
} from "@periapsis/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

import { alertDfirApi, projectAlertWorkspace } from "./alert-dfir-api";
import {
  alertDfirAlertId,
  alertDfirTenantId,
  alertDfirEvidenceId,
  alertDfirExtendedWorkspaceFixture,
} from "./alert-dfir-test-fixtures";
import { caseDfirApi, projectWorkspace } from "./case-dfir-api";
import {
  dfirCaseId,
  dfirTenantId,
  dfirEvidenceId,
  dfirWorkspaceFixture,
} from "./case-dfir-test-fixtures";
import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

type CustodyProjection = Pick<DfirEvidence, "custody" | "version">;

function chain(length: number): DfirCustodyEvent[] {
  return evidenceCustodyFixture(
    dfirWorkspaceFixture().evidence[0]!.custody[0]!,
    length,
  );
}

function collectionBody(
  evidence: Omit<DfirEvidence, "caseId">,
): DfirEvidenceCollectRequest {
  return {
    classification: evidence.classification,
    collectedAt: evidence.collectedAt,
    description: evidence.description,
    evidenceId: evidence.id,
    evidenceType: evidence.evidenceType,
    initialCustodyEventId: chain(1)[0]!.id,
    legalHold: evidence.legalHold,
    source: evidence.source,
    storageObjectId: evidence.storageObjectId,
    title: evidence.title,
  };
}

const paths = [
  {
    name: "Case",
    project: (fields: CustodyProjection) => {
      const source = dfirWorkspaceFixture();
      Object.assign(source.evidence[0]!, fields);
      return projectWorkspace(source, dfirTenantId, dfirCaseId);
    },
    response: (fields: CustodyProjection) => ({
      ...dfirWorkspaceFixture().evidence[0]!,
      ...fields,
    }),
    collect: () =>
      caseDfirApi.create({
        tenantId: dfirTenantId,
        caseId: dfirCaseId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "custody-collection-test-0001",
        operation: {
          panel: "evidence",
          body: collectionBody(dfirWorkspaceFixture().evidence[0]!),
        },
      }),
    append: (expectedVersion: number) =>
      caseDfirApi.appendCustody({
        tenantId: dfirTenantId,
        caseId: dfirCaseId,
        evidenceId: dfirEvidenceId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "custody-boundary-test-0001",
        body: {
          expectedVersion,
          action: "accessed",
          reason: "Boundary regression",
          custodyEventId: "0198c97d-cf4f-7000-8000-000000009999",
        },
      }),
  },
  {
    name: "Alert",
    project: (fields: CustodyProjection) => {
      const source = alertDfirExtendedWorkspaceFixture();
      Object.assign(source.evidence[0]!, fields);
      return projectAlertWorkspace(source, alertDfirTenantId, alertDfirAlertId);
    },
    response: (fields: CustodyProjection) => ({
      ...alertDfirExtendedWorkspaceFixture().evidence[0]!,
      ...fields,
    }),
    collect: () =>
      alertDfirApi.create({
        tenantId: alertDfirTenantId,
        alertId: alertDfirAlertId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "custody-collection-test-0001",
        operation: {
          panel: "evidence",
          body: collectionBody(
            alertDfirExtendedWorkspaceFixture().evidence[0]!,
          ),
        },
      }),
    append: (expectedVersion: number) =>
      alertDfirApi.appendCustody({
        tenantId: alertDfirTenantId,
        alertId: alertDfirAlertId,
        evidenceId: alertDfirEvidenceId,
        csrfToken: "csrf-test-token",
        idempotencyKey: "custody-boundary-test-0001",
        body: {
          expectedVersion,
          action: "accessed",
          reason: "Boundary regression",
          custodyEventId: "0198c97d-cf4f-7000-8000-000000009999",
        },
      }),
  },
];

afterEach(() => vi.unstubAllGlobals());

describe.each(paths)(
  "$name custody transport",
  ({ project, response, append, collect }) => {
    it.each([1, 999, 1_000])(
      "accepts an exact complete chain at revision %i",
      (version) => {
        expect(() =>
          project({ version, custody: chain(version) }),
        ).not.toThrow();
      },
    );

    it.each([0, 1_001, 3_000_000_000, Number.MAX_SAFE_INTEGER])(
      "rejects impossible evidence revision %i",
      (version) => {
        expect(() => project({ version, custody: chain(1) })).toThrow();
      },
    );

    it.each([
      "empty",
      "revision drift",
      "sequence overflow",
      "sequence gap",
      "duplicate ID",
      "spliced hash",
      "zero genesis hash",
    ])("rejects %s", (mutation) => {
      const value = { version: 2, custody: chain(2) };
      switch (mutation) {
        case "empty":
          value.custody = [];
          break;
        case "revision drift":
          value.version = 3;
          break;
        case "sequence overflow":
          value.custody[1]!.sequence = 1_001;
          break;
        case "sequence gap":
          value.custody[1]!.sequence = 3;
          break;
        case "duplicate ID":
          value.custody[1]!.id = value.custody[0]!.id;
          break;
        case "spliced hash":
          value.custody[1]!.previousHash = "a".repeat(64);
          break;
        case "zero genesis hash":
          value.custody[0]!.previousHash = "0".repeat(64);
          break;
      }
      expect(() => project(value)).toThrow();
    });

    it.each([1_000, 1_001, 3_000_000_000])(
      "rejects non-incrementable custody revision %i before network I/O",
      async (version) => {
        const fetchMock = vi.fn<typeof fetch>(() =>
          Promise.resolve(new Response(null, { status: 500 })),
        );
        vi.stubGlobal("fetch", fetchMock);
        await expect(append(version)).rejects.toThrow();
        expect(fetchMock).not.toHaveBeenCalled();
      },
    );

    it("accepts the final append and checks its exact ETag", async () => {
      const fetchMock = vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(
            JSON.stringify(response({ version: 1_000, custody: chain(1_000) })),
            {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                ETag: '"v1000"',
                "X-Idempotent-Replay": "false",
              },
            },
          ),
        ),
      );
      vi.stubGlobal("fetch", fetchMock);
      await expect(append(999)).resolves.toBeUndefined();
      const request = fetchMock.mock.calls[0]?.[0];
      expect(request).toBeInstanceOf(Request);
      if (!(request instanceof Request))
        throw new Error("Expected generated HTTP request");
      expect(request.headers.get("If-Match")).toBe('"v999"');
      await expect(request.json()).resolves.toMatchObject({
        expectedVersion: 999,
      });
    });

    it("rejects an impossible response even when its ETag agrees", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>(() =>
          Promise.resolve(
            new Response(
              JSON.stringify(response({ version: 1_001, custody: chain(1) })),
              {
                status: 200,
                headers: {
                  "Content-Type": "application/json",
                  "Cache-Control": "no-store",
                  ETag: '"v1001"',
                  "X-Idempotent-Replay": "false",
                },
              },
            ),
          ),
        ),
      );
      await expect(append(999)).rejects.toThrow();
    });

    it.each(["fresh", "replay", "empty chain", "revision drift", "wrong ETag"])(
      "validates the %s evidence collection response",
      async (scenario) => {
        const value = response({ version: 1, custody: chain(1) });
        if (scenario === "empty chain") value.custody = [];
        if (scenario === "revision drift") value.version = 2;
        const fetchMock = vi.fn<typeof fetch>(() =>
          Promise.resolve(
            new Response(JSON.stringify(value), {
              status: 201,
              headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                ETag: `"v${scenario === "wrong ETag" ? 2 : value.version}"`,
                "X-Idempotent-Replay": String(scenario === "replay"),
              },
            }),
          ),
        );
        vi.stubGlobal("fetch", fetchMock);
        if (scenario === "fresh" || scenario === "replay") {
          await expect(collect()).resolves.toBeUndefined();
        } else {
          await expect(collect()).rejects.toThrow();
        }
        expect(fetchMock).toHaveBeenCalledTimes(1);
      },
    );
  },
);
