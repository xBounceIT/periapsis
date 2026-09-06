import type { AuditActorType, AuditOutcome } from "@periapsis/contracts";

import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { formatTenantInstant } from "../lib/tenant-date-time";

export const tenantAuditPermission = "audit.read" as const;
export const platformAuditPermission = "platform.audit.read" as const;
export const tenantAuditExportPermission = "audit.export" as const;
export const tenantAuditRetentionPermission = "audit.retention.manage" as const;
export const platformAuditExportPermission = "platform.audit.export" as const;
export const platformAuditRetentionPermission =
  "platform.audit.retention.manage" as const;

export const tenantAuditRouteDescriptor = {
  path: "/tenant/audit",
  permission: tenantAuditPermission,
  scope: "tenant",
  title: "Audit ledger",
} as const;

export const platformAuditRouteDescriptor = {
  path: "/platform/audit",
  permission: platformAuditPermission,
  scope: "platform",
  title: "Platform audit",
} as const;

export type AuditSurface = "tenant" | "platform";

export interface AuditFilterDraft {
  actionPrefix: string;
  actorServiceAccountId: string;
  actorType: "" | AuditActorType;
  actorUserId: string;
  correlationId: string;
  limit: number;
  occurredBefore: string;
  occurredFrom: string;
  outcome: "" | AuditOutcome;
  requestId: string;
  resourceId: string;
  resourceType: string;
  search: string;
}

export interface AuditQuery {
  actionPrefix?: string;
  actorServiceAccountId?: string;
  actorType?: AuditActorType;
  actorUserId?: string;
  correlationId?: string;
  limit: number;
  occurredBefore?: string;
  occurredFrom?: string;
  outcome?: AuditOutcome;
  requestId?: string;
  resourceId?: string;
  resourceType?: string;
  search?: string;
}

export const emptyAuditFilterDraft: Readonly<AuditFilterDraft> = {
  actionPrefix: "",
  actorServiceAccountId: "",
  actorType: "",
  actorUserId: "",
  correlationId: "",
  limit: 50,
  occurredBefore: "",
  occurredFrom: "",
  outcome: "",
  requestId: "",
  resourceId: "",
  resourceType: "",
  search: "",
};

const actionPattern = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*$/u;
const resourceTypePattern = /^[a-z][a-z0-9_-]*$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function normalizeAuditFilters(
  draft: AuditFilterDraft,
  surface: AuditSurface,
): AuditQuery {
  if (![25, 50, 100].includes(draft.limit)) {
    throw new AuditFilterError("Page size must be 25, 50, or 100 events.");
  }

  const search = boundedText(draft.search, 256, "Search");
  const actionPrefix = patternedText(
    draft.actionPrefix,
    128,
    actionPattern,
    "Action prefix",
  );
  const resourceType = patternedText(
    draft.resourceType,
    128,
    resourceTypePattern,
    "Resource type",
  );
  const actorUserId = optionalUuid(draft.actorUserId, "Actor user ID");
  const actorServiceAccountId = optionalUuid(
    draft.actorServiceAccountId,
    "Actor service-account ID",
  );
  const resourceId = optionalUuid(draft.resourceId, "Resource ID");
  const requestId = optionalUuid(draft.requestId, "Request ID");
  const correlationId = optionalUuid(draft.correlationId, "Correlation ID");
  const occurredFrom = optionalInstant(draft.occurredFrom, "Occurred from");
  const occurredBefore = optionalInstant(
    draft.occurredBefore,
    "Occurred before",
  );

  if (surface === "platform" && actorServiceAccountId) {
    throw new AuditFilterError(
      "Platform audit does not accept a tenant service-account identifier.",
    );
  }
  if (actorUserId && actorServiceAccountId) {
    throw new AuditFilterError("Choose only one exact actor identifier.");
  }
  if (
    (draft.actorType === "user" && actorServiceAccountId) ||
    (draft.actorType === "service_account" && actorUserId) ||
    (draft.actorType === "system" && (actorUserId || actorServiceAccountId))
  ) {
    throw new AuditFilterError(
      "The actor identifier does not match the selected actor type.",
    );
  }
  if (
    occurredFrom &&
    occurredBefore &&
    parseRfc3339Instant(occurredFrom)! >= parseRfc3339Instant(occurredBefore)!
  ) {
    throw new AuditFilterError(
      "Occurred from must be earlier than occurred before.",
    );
  }

  return {
    limit: draft.limit,
    ...(search ? { search } : {}),
    ...(actionPrefix ? { actionPrefix } : {}),
    ...(resourceType ? { resourceType } : {}),
    ...(draft.actorType ? { actorType: draft.actorType } : {}),
    ...(draft.outcome ? { outcome: draft.outcome } : {}),
    ...(actorUserId ? { actorUserId } : {}),
    ...(actorServiceAccountId ? { actorServiceAccountId } : {}),
    ...(resourceId ? { resourceId } : {}),
    ...(requestId ? { requestId } : {}),
    ...(correlationId ? { correlationId } : {}),
    ...(occurredFrom ? { occurredFrom } : {}),
    ...(occurredBefore ? { occurredBefore } : {}),
  };
}

export function auditInstantFromLocalValue(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const instant = new Date(trimmed);
  if (Number.isNaN(instant.valueOf())) {
    throw new AuditFilterError("Enter a valid date and time.");
  }
  return instant.toISOString();
}

export function isAuditTenantId(value: string): boolean {
  return uuidV7Pattern.test(value);
}

export function formatAuditInstant(value: string): string {
  return formatTenantInstant(value, undefined, { precision: "second" });
}

export function compactAuditIdentifier(value: string | undefined): string {
  if (!value) return "Not recorded";
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function boundedText(value: string, maximum: number, label: string): string {
  const normalized = value.trim();
  if (!normalized) return "";
  if (
    Array.from(normalized).length > maximum ||
    hasForbiddenTextControl(normalized)
  ) {
    throw new AuditFilterError(`${label} is not a valid bounded value.`);
  }
  return normalized;
}

function patternedText(
  value: string,
  maximum: number,
  pattern: RegExp,
  label: string,
): string {
  const normalized = boundedText(value, maximum, label);
  if (normalized && !pattern.test(normalized)) {
    throw new AuditFilterError(`${label} has an unsupported format.`);
  }
  return normalized;
}

function optionalUuid(value: string, label: string): string | undefined {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return undefined;
  if (!uuidPattern.test(normalized)) {
    throw new AuditFilterError(`${label} must be a canonical UUID.`);
  }
  return normalized;
}

function optionalInstant(value: string, label: string): string | undefined {
  const normalized = value.trim();
  if (!normalized) return undefined;
  if (parseRfc3339Instant(normalized) === undefined) {
    throw new AuditFilterError(`${label} must be an RFC 3339 instant.`);
  }
  return normalized;
}

function hasForbiddenTextControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      ((codePoint >= 0 && codePoint <= 8) ||
        codePoint === 11 ||
        codePoint === 12 ||
        (codePoint >= 14 && codePoint <= 31) ||
        codePoint === 127)
    ) {
      return true;
    }
  }
  return false;
}

export class AuditFilterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditFilterError";
  }
}
