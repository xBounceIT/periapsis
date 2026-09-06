import { type TenantRoleSummaryView } from "../lib/phase-two-types";

export const maximumRoleVersion = 2_147_483_647;

export function mergeTenantRoles(
  current: readonly TenantRoleSummaryView[],
  incoming: readonly TenantRoleSummaryView[],
): readonly TenantRoleSummaryView[] {
  const merged = tryMergeTenantRoles(current, incoming);
  if (!merged.ok) {
    throw new Error(
      "The role inventory returned conflicting representations at the same version.",
    );
  }
  return merged.items;
}

export function tryMergeTenantRoles(
  current: readonly TenantRoleSummaryView[],
  incoming: readonly TenantRoleSummaryView[],
): { items: readonly TenantRoleSummaryView[]; ok: true } | { ok: false } {
  const roles = new Map<string, TenantRoleSummaryView>();
  for (const role of [...current, ...incoming]) {
    if (!validRoleVersion(role.version)) {
      return { ok: false };
    }
    const accepted = roles.get(role.id);
    if (!accepted || role.version > accepted.version) {
      roles.set(role.id, role);
      continue;
    }
    if (role.version < accepted.version) {
      continue;
    }
    if (!sameRoleSummaryRepresentation(accepted, role)) {
      return { ok: false };
    }
  }
  return { items: [...roles.values()], ok: true };
}

export function sameRoleSummaryRepresentation(
  left: TenantRoleSummaryView,
  right: TenantRoleSummaryView,
): boolean {
  return (
    left.id === right.id &&
    left.tenantId === right.tenantId &&
    left.key === right.key &&
    left.name === right.name &&
    left.description === right.description &&
    left.system === right.system &&
    left.principalKind === right.principalKind &&
    left.archived === right.archived &&
    left.archivedAt === right.archivedAt &&
    left.version === right.version &&
    left.createdAt === right.createdAt &&
    left.updatedAt === right.updatedAt
  );
}

export function validRoleVersion(version: number): boolean {
  return (
    Number.isSafeInteger(version) &&
    version > 0 &&
    version <= maximumRoleVersion
  );
}
