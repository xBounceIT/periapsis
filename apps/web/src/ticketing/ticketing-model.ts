import type {
  AlertProjection,
  AlertSeverity,
  CaseProjection,
  TenantPermissionKey,
  TicketPriority,
  TicketSort,
} from "@periapsis/contracts";

import type { TenantAuthorizationScopeView } from "../lib/phase-two-types";
import { formatTenantInstant } from "../lib/tenant-date-time";
import type { TicketKind, TicketProjection } from "../lib/ticketing-api";

export const alertSeverities = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
] as const satisfies readonly AlertSeverity[];

export const ticketPriorities = [
  "low",
  "medium",
  "high",
  "urgent",
  "critical",
] as const satisfies readonly TicketPriority[];

export const ticketSorts = [
  "updated_at_desc",
  "updated_at_asc",
  "created_at_desc",
  "created_at_asc",
  "priority_desc",
  "oldest_unclaimed",
] as const satisfies readonly TicketSort[];

const authorizationScopes = [
  "own",
  "assigned",
  "operator_team",
  "tenant",
] as const satisfies readonly TenantAuthorizationScopeView[];

export function hasAnyTicketPermission(
  check: (
    permission: TenantPermissionKey,
    scope?: TenantAuthorizationScopeView,
  ) => boolean,
  permission: TenantPermissionKey,
): boolean {
  return authorizationScopes.some((scope) => check(permission, scope));
}

export function hasAllTicketPermissionsAtOneScope(
  check: (
    permission: TenantPermissionKey,
    scope?: TenantAuthorizationScopeView,
  ) => boolean,
  permissions: readonly TenantPermissionKey[],
): boolean {
  return authorizationScopes.some((scope) =>
    permissions.every((permission) => check(permission, scope)),
  );
}

export function isAlertTicket(
  kind: TicketKind,
  value: TicketProjection,
): value is AlertProjection {
  return kind === "alert" && "alertNumber" in value;
}

export function isCaseTicket(
  kind: TicketKind,
  value: TicketProjection,
): value is CaseProjection {
  return kind === "case" && "caseNumber" in value;
}

export function ticketNumber(
  kind: TicketKind,
  value: TicketProjection,
): string {
  if (isAlertTicket(kind, value)) return value.alertNumber;
  if (isCaseTicket(kind, value)) return value.caseNumber;
  throw new TypeError("Ticket kind and projection do not match.");
}

export function kindLabel(kind: TicketKind): "Alert" | "Case" {
  return kind === "alert" ? "Alert" : "Case";
}

export function kindLabelPlural(kind: TicketKind): "Alerts" | "Cases" {
  return kind === "alert" ? "Alerts" : "Cases";
}

export function humanizeKey(value: string): string {
  return value
    .replaceAll("_", " ")
    .replaceAll(".", " · ")
    .replace(/^./u, (letter) => letter.toUpperCase());
}

export function formatTicketInstant(value: string | undefined): string {
  return formatTenantInstant(value);
}

export function compactIdentifier(value: string | null | undefined): string {
  if (!value) return "Unassigned";
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value;
}

export function parseTagInput(value: string): string[] {
  const unique = new Set(
    value
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag.length > 0),
  );
  return [...unique].toSorted(codePointCompare);
}

export function parseStatusFilter(value: string): string[] | undefined {
  const statuses = parseTagInput(value);
  return statuses.length > 0 ? statuses : undefined;
}

export function codePointCompare(left: string, right: string): number {
  const leftPoints = Array.from(left).map(
    (character) => character.codePointAt(0) ?? 0,
  );
  const rightPoints = Array.from(right).map(
    (character) => character.codePointAt(0) ?? 0,
  );
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

export function priorityTone(priority: TicketPriority): string {
  return `ticket-tone ticket-tone--priority-${priority}`;
}

export function severityTone(severity: AlertSeverity): string {
  return `ticket-tone ticket-tone--severity-${severity}`;
}
