import { type TenantSecurityGroupView } from "../lib/phase-two-types";

export function mergeTenantGroups(
  current: readonly TenantSecurityGroupView[],
  incoming: readonly TenantSecurityGroupView[],
): readonly TenantSecurityGroupView[] {
  const merged = tryMergeTenantGroups(current, incoming);
  if (!merged.ok) {
    throw new Error(
      "The security-group inventory returned conflicting representations at the same version.",
    );
  }
  return merged.items;
}

export function tryMergeTenantGroups(
  current: readonly TenantSecurityGroupView[],
  incoming: readonly TenantSecurityGroupView[],
): { items: readonly TenantSecurityGroupView[]; ok: true } | { ok: false } {
  const groups = new Map<string, TenantSecurityGroupView>();
  for (const group of [...current, ...incoming]) {
    if (!validInventoryVersion(group.version)) {
      return { ok: false };
    }
    const accepted = groups.get(group.id);
    if (!accepted || group.version > accepted.version) {
      groups.set(group.id, group);
      continue;
    }
    if (group.version < accepted.version) {
      continue;
    }
    if (!sameGroupRepresentation(accepted, group)) {
      return { ok: false };
    }
  }
  return { items: [...groups.values()], ok: true };
}

export function validInventoryVersion(version: number): boolean {
  return (
    Number.isSafeInteger(version) && version > 0 && version <= 2_147_483_647
  );
}

export function sameGroupRepresentation(
  left: TenantSecurityGroupView,
  right: TenantSecurityGroupView,
): boolean {
  return (
    left.id === right.id &&
    left.tenantId === right.tenantId &&
    left.key === right.key &&
    left.name === right.name &&
    left.description === right.description &&
    left.archived === right.archived &&
    left.archivedAt === right.archivedAt &&
    left.version === right.version &&
    left.createdAt === right.createdAt &&
    left.updatedAt === right.updatedAt
  );
}
