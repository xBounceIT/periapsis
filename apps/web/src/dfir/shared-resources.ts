import type { DfirRelatedRoot, DfirSharedResource } from "@periapsis/contracts";

const uuidV7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function sanitizeSharedResources(
  value: unknown,
  indicators: readonly { id: string }[],
  assets: readonly { id: string }[],
  currentRoot: DfirRelatedRoot,
): DfirSharedResource[] {
  if (
    !Array.isArray(value) ||
    value.length > 1_000 ||
    value.length !== indicators.length + assets.length
  ) {
    throw new Error("Invalid shared resource projection");
  }
  const expected = new Set([
    ...indicators.map(({ id }) => `ioc:${id}`),
    ...assets.map(({ id }) => `asset:${id}`),
  ]);
  return value.map((raw: unknown) => {
    if (
      !isRecord(raw) ||
      (raw.resourceKind !== "ioc" && raw.resourceKind !== "asset") ||
      typeof raw.resourceId !== "string" ||
      !uuidV7.test(raw.resourceId) ||
      !expected.delete(`${raw.resourceKind}:${raw.resourceId}`) ||
      !Array.isArray(raw.roots) ||
      raw.roots.length < 1 ||
      raw.roots.length > 64
    ) {
      throw new Error("Invalid shared resource binding");
    }
    const seen = new Set<string>();
    const roots = raw.roots.map((root: unknown): DfirRelatedRoot => {
      if (
        !isRecord(root) ||
        (root.kind !== "case" && root.kind !== "alert") ||
        typeof root.id !== "string" ||
        !uuidV7.test(root.id) ||
        seen.has(`${root.kind}:${root.id}`)
      ) {
        throw new Error("Invalid related ticket");
      }
      seen.add(`${root.kind}:${root.id}`);
      return { kind: root.kind, id: root.id };
    });
    if (!seen.has(`${currentRoot.kind}:${currentRoot.id}`)) {
      throw new Error("Shared resource is not linked to this ticket");
    }
    return {
      resourceKind: raw.resourceKind,
      resourceId: raw.resourceId,
      roots,
    };
  });
}

export function relatedRootsFor(
  resources: readonly DfirSharedResource[],
  kind: "ioc" | "asset",
  id: string,
): DfirRelatedRoot[] {
  const resource = resources.find(
    (item) => item.resourceKind === kind && item.resourceId === id,
  );
  if (resource === undefined) {
    throw new Error("Missing related ticket projection");
  }
  return resource.roots.map(({ kind: rootKind, id: rootId }) => ({
    kind: rootKind,
    id: rootId,
  }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
