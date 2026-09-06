import {
  type OperatorTeamAssignmentEpochView,
  type OperatorTeamRosterEntryView,
} from "../lib/phase-two-types";

export function mergeAssignmentEpochs(
  current: readonly OperatorTeamAssignmentEpochView[],
  incoming: readonly OperatorTeamAssignmentEpochView[],
  tenantId: string,
): readonly OperatorTeamAssignmentEpochView[] {
  const byId = new Map(current.map((epoch) => [epoch.epochId, epoch]));
  for (const epoch of incoming) {
    if (epoch.tenantId !== tenantId) {
      throw new Error(
        "An assignment epoch crossed the active tenant boundary.",
      );
    }
    const existing = byId.get(epoch.epochId);
    if (!existing || epoch.version > existing.version) {
      byId.set(epoch.epochId, epoch);
    } else if (
      epoch.version === existing.version &&
      JSON.stringify(epoch) !== JSON.stringify(existing)
    ) {
      throw new Error(
        "Assignment-epoch pages returned conflicting representations.",
      );
    }
  }
  return [...byId.values()].toSorted((left, right) => {
    if (left.state !== right.state) return left.state === "active" ? -1 : 1;
    return right.startedAt.localeCompare(left.startedAt);
  });
}

export function mergeRosterEntries(
  current: readonly OperatorTeamRosterEntryView[],
  incoming: readonly OperatorTeamRosterEntryView[],
): readonly OperatorTeamRosterEntryView[] {
  const byId = new Map(current.map((entry) => [entry.id, entry]));
  for (const entry of incoming) {
    const existing = byId.get(entry.id);
    if (!existing || entry.version > existing.version)
      byId.set(entry.id, entry);
    else if (
      entry.version === existing.version &&
      JSON.stringify(entry) !== JSON.stringify(existing)
    ) {
      throw new Error(
        "Roster pages returned conflicting edge representations.",
      );
    }
  }
  return [...byId.values()].toSorted((left, right) =>
    left.member.displayName.localeCompare(right.member.displayName),
  );
}
