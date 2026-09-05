import { afterEach, describe, expect, it, vi } from "vitest";

import { alertDfirApi } from "./alert-dfir-api";
import { alertDfirWorkspaceFixture } from "./alert-dfir-test-fixtures";
import { caseDfirApi } from "./case-dfir-api";
import { dfirWorkspaceFixture } from "./case-dfir-test-fixtures";

afterEach(() => vi.unstubAllGlobals());

describe("shared resource lifecycle transport", () => {
  for (const rootKind of ["case", "alert"] as const) {
    for (const resourceKind of ["ioc", "asset"] as const) {
      for (const linked of [false, true]) {
        it(`${linked ? "links" : "unlinks"} an existing ${resourceKind} through ${rootKind} with caller ID and CAS`, async () => {
          const workspace =
            rootKind === "case"
              ? dfirWorkspaceFixture()
              : alertDfirWorkspaceFixture();
          const resource =
            resourceKind === "ioc"
              ? workspace.indicators[0]!
              : workspace.assets[0]!;
          const eventId = "0198c97d-cf4f-7000-8000-000000000199";
          const expectedVersion = 3_000_000_000;
          const fetchMock = vi.fn<typeof fetch>(() =>
            Promise.resolve(
              new Response(
                JSON.stringify({ ...resource, version: expectedVersion + 1 }),
                {
                  headers: {
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json",
                    ETag: `"v${expectedVersion + 1}"`,
                  },
                  status: 200,
                },
              ),
            ),
          );
          vi.stubGlobal("fetch", fetchMock);
          const common = {
            eventId,
            expectedVersion,
            linked,
            resourceId: resource.id,
            resourceKind,
            tenantId: workspace.tenantId,
            csrfToken: "csrf-shared-resource",
            idempotencyKey: eventId,
          };
          let rootId: string;
          if ("caseId" in workspace) {
            rootId = workspace.caseId;
            await caseDfirApi.changeLink({ ...common, caseId: rootId });
          } else {
            rootId = workspace.alertId;
            await alertDfirApi.changeLink({ ...common, alertId: rootId });
          }
          const request = fetchMock.mock.calls[0]?.[0];
          if (!(request instanceof Request))
            throw new Error("Expected generated Request");
          expect(new URL(request.url).pathname).toBe(
            `/api/v1/tenants/${workspace.tenantId}/${rootKind}s/${rootId}/dfir/${resourceKind === "ioc" ? "iocs" : "assets"}/${resource.id}/${linked ? "link" : "unlink"}`,
          );
          expect(request.method).toBe("POST");
          expect(request.headers.get("If-Match")).toBe(`"v${expectedVersion}"`);
          expect(request.headers.get("Idempotency-Key")).toBe(eventId);
          expect(request.headers.get("X-CSRF-Token")).toBe(
            "csrf-shared-resource",
          );
          expect(request.cache).toBe("no-store");
          expect(request.credentials).toBe("same-origin");
          await expect(request.clone().json()).resolves.toEqual({
            expectedVersion,
            [linked ? "linkId" : "unlinkId"]: eventId,
          });
        });
      }
    }
  }

  it("rejects a validly tagged response at the wrong result revision", async () => {
    const workspace = dfirWorkspaceFixture();
    const resource = workspace.indicators[0]!;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          new Response(JSON.stringify({ ...resource, version: 4 }), {
            headers: {
              "Cache-Control": "no-store",
              "Content-Type": "application/json",
              ETag: '"v4"',
            },
            status: 200,
          }),
        ),
      ),
    );
    await expect(
      caseDfirApi.changeLink({
        caseId: workspace.caseId,
        tenantId: workspace.tenantId,
        resourceId: resource.id,
        resourceKind: "ioc",
        eventId: "0198c97d-cf4f-7000-8000-000000000199",
        expectedVersion: 1,
        linked: false,
        csrfToken: "csrf-test",
        idempotencyKey: "shared-retry-key-001",
      }),
    ).rejects.toThrow();
  });
});
