import { type SessionSummaryView } from "../lib/phase-two-types";

export function appendUniqueSessions(
  current: readonly SessionSummaryView[],
  incoming: readonly SessionSummaryView[],
): readonly SessionSummaryView[] {
  const seen = new Set(current.map((session) => session.id));
  return [
    ...current,
    ...incoming.filter((session) => {
      if (seen.has(session.id)) {
        return false;
      }
      seen.add(session.id);
      return true;
    }),
  ];
}
