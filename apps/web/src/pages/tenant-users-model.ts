import {
  type EffectiveTenantDelegationView,
  type EffectiveTenantRoleGrantView,
  type TenantRoleView,
  type TenantUserSummaryView,
} from "../lib/phase-two-types";
import { hasInstantReached, parseRfc3339Instant } from "../lib/rfc3339-instant";

export interface DelegableRoleChoice {
  delegableUntil?: string;
  role: TenantRoleView;
}

export function effectiveAuthorityPathKey(
  grant: EffectiveTenantRoleGrantView,
): string {
  if (grant.path.pathType === "direct") {
    return `direct:${grant.grantId}`;
  }
  const path = grant.path.group;
  return [
    "group",
    grant.grantId,
    path.group.id,
    path.membershipEdge.id,
    path.roleGrantEdge.id,
  ].join(":");
}

export function deriveDelegableRoleChoice(
  role: TenantRoleView,
  delegation: readonly EffectiveTenantDelegationView[],
): DelegableRoleChoice | null {
  if (role.principalKind !== "human") {
    return null;
  }
  const parsedHorizons = new Map<string, bigint>();
  for (const entry of delegation) {
    if (entry.delegableUntil === undefined) {
      continue;
    }
    const instant = parseRfc3339Instant(entry.delegableUntil);
    if (instant === undefined) {
      return null;
    }
    parsedHorizons.set(entry.delegableUntil, instant);
  }
  const required = new Map<string, { permissionKey: string; scope: string }>();
  for (const tuple of [
    ...role.policy.permissions,
    ...role.policy.delegationCeiling,
  ]) {
    required.set(`${tuple.permissionKey}:${tuple.scope}`, tuple);
  }
  const ceilings = [...required.values()].map((tuple) =>
    delegation.find(
      (entry) =>
        entry.permissionKey === tuple.permissionKey &&
        entry.scope === tuple.scope,
    ),
  );
  if (ceilings.some((entry) => !entry)) {
    return null;
  }
  const horizons = ceilings.flatMap((entry) =>
    entry?.delegableUntil ? [entry.delegableUntil] : [],
  );
  const delegableUntil = horizons.toSorted((first, second) => {
    const firstInstant = parsedHorizons.get(first);
    const secondInstant = parsedHorizons.get(second);
    if (firstInstant === undefined || secondInstant === undefined) return 0;
    return firstInstant < secondInstant
      ? -1
      : firstInstant > secondInstant
        ? 1
        : 0;
  })[0];
  if (
    delegableUntil &&
    hasInstantReached(parsedHorizons.get(delegableUntil) ?? 0n)
  ) {
    return null;
  }
  return {
    ...(delegableUntil ? { delegableUntil } : {}),
    role,
  };
}

export function mergeTenantUsers(
  current: readonly TenantUserSummaryView[],
  incoming: readonly TenantUserSummaryView[],
): readonly TenantUserSummaryView[] {
  const users = new Map(current.map((user) => [user.membershipId, user]));
  for (const user of incoming) {
    users.set(user.membershipId, user);
  }
  return [...users.values()];
}
