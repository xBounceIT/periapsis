import { describe, expect, it } from "vitest";

import { projectAlertWorkspace } from "./alert-dfir-api";
import {
  alertDfirAlertId,
  alertDfirTenantId,
  alertDfirWorkspaceFixture,
} from "./alert-dfir-test-fixtures";
import { projectWorkspace } from "./case-dfir-api";
import {
  dfirCaseId,
  dfirTenantId,
  dfirWorkspaceFixture,
} from "./case-dfir-test-fixtures";

function project(
  source:
    | ReturnType<typeof dfirWorkspaceFixture>
    | ReturnType<typeof alertDfirWorkspaceFixture>,
) {
  return "caseId" in source
    ? projectWorkspace(source, dfirTenantId, dfirCaseId)
    : projectAlertWorkspace(source, alertDfirTenantId, alertDfirAlertId);
}

describe("shared DFIR workspace projection", () => {
  for (const rootKind of ["case", "alert"] as const) {
    const fixture =
      rootKind === "case" ? dfirWorkspaceFixture : alertDfirWorkspaceFixture;

    it(`${rootKind} copies only supplied visible ticket identities`, () => {
      const source = fixture();
      const resource = source.sharedResources[0]!;
      const otherRoot = {
        kind: "case" as const,
        id: "0198c97d-cf4f-7000-8000-000000000088",
      };
      resource.roots.push(otherRoot);
      Reflect.set(resource, "hiddenRootCount", 42);
      Reflect.set(resource.roots[0]!, "hiddenTitle", "private-case-name");
      const result = project(source);
      expect(result.data.iocs[0]!.relatedRoots).toEqual(
        resource.roots.map(({ kind, id }) => ({ kind, id })),
      );
      expect(JSON.stringify(result)).not.toContain("hiddenRootCount");
      expect(JSON.stringify(result)).not.toContain("private-case-name");
      otherRoot.id = "0198c97d-cf4f-7000-8000-000000000089";
      expect(result.data.iocs[0]!.relatedRoots.at(-1)?.id).toBe(
        "0198c97d-cf4f-7000-8000-000000000088",
      );
    });

    it(`${rootKind} rejects missing, duplicate, malformed or unrelated associations`, () => {
      const mutations = [
        (source: ReturnType<typeof fixture>) =>
          Reflect.deleteProperty(source, "sharedResources"),
        (source: ReturnType<typeof fixture>) => source.sharedResources.pop(),
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[1] = structuredClone(
            source.sharedResources[0]!,
          );
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.resourceKind = "asset";
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.resourceId =
            "0198c97d-cf4f-7000-8000-000000000099";
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.roots = [];
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.roots.push(
            source.sharedResources[0]!.roots[0]!,
          );
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.roots[0]!.id =
            "0198c97d-cf4f-7000-8000-000000000099";
        },
        (source: ReturnType<typeof fixture>) =>
          Reflect.set(source.sharedResources[0]!.roots[0]!, "kind", "external"),
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.roots[0]!.id = "javascript:alert(1)";
        },
        (source: ReturnType<typeof fixture>) => {
          source.sharedResources[0]!.roots = Array.from(
            { length: 65 },
            (_, index) => ({
              kind: "case",
              id: `0198c97d-cf4f-7000-8000-${index.toString().padStart(12, "0")}`,
            }),
          );
        },
      ];
      for (const mutate of mutations) {
        const source = fixture();
        mutate(source);
        expect(() => project(source)).toThrow();
      }
    });
  }
});
