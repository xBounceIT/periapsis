import type { PlatformOperatorTeamMutationRequest } from "./platform-operator-team-coordinator";

export function platformOperatorTeamMutationKey(
  request: PlatformOperatorTeamMutationRequest,
): string {
  return request.kind === "create"
    ? "operator-team:create"
    : platformOperatorTeamResourceKey(request.teamId);
}

export function platformOperatorTeamResourceKey(teamId: string): string {
  return `operator-team:${teamId}`;
}
