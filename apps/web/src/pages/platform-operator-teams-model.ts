import { type OperatorTeamView } from "../lib/phase-two-types";

export function mergeOperatorTeams(
  current: readonly OperatorTeamView[],
  incoming: readonly OperatorTeamView[],
): readonly OperatorTeamView[] {
  const byId = new Map(current.map((team) => [team.id, team]));
  for (const team of incoming) {
    const existing = byId.get(team.id);
    if (!existing || team.version > existing.version) {
      byId.set(team.id, team);
    } else if (
      team.version === existing.version &&
      JSON.stringify(team) !== JSON.stringify(existing)
    ) {
      throw new Error(
        "Operator-team pages returned conflicting representations.",
      );
    }
  }
  return [...byId.values()].toSorted((left, right) =>
    left.key.localeCompare(right.key),
  );
}
