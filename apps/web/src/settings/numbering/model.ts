import type {
  TicketNumberingDraft,
  TicketNumberingKind,
  TicketNumberingMutationResult,
  TicketNumberingPeriod,
  TicketNumberingPolicy,
  TicketNumberingPreview,
  TicketNumberingSeparator,
  TicketNumberingUpdateRequest,
} from "@periapsis/contracts";

import { parseRfc3339Instant } from "../../lib/rfc3339-instant";
import { isCanonicalUuidV7 } from "../../lib/uuid-v7";

export const ticketNumberingRouteDescriptor = {
  path: "/tenant/settings/numbering",
  label: "Ticket numbering",
  permissions: ["settings.read"] as const,
};

export const ticketNumberingReadPermission = "settings.read" as const;
export const ticketNumberingManagePermission = "settings.manage" as const;

export interface VersionedTicketNumberingPolicy {
  etag: string;
  value: TicketNumberingPolicy;
}

export interface TicketNumberingUpdateResult extends VersionedTicketNumberingPolicy {
  replayed: boolean;
}

export interface TicketNumberingApi {
  get(
    tenantId: string,
    kind: TicketNumberingKind,
    signal?: AbortSignal,
  ): Promise<VersionedTicketNumberingPolicy>;
  preview(
    csrfToken: string,
    tenantId: string,
    kind: TicketNumberingKind,
    draft: TicketNumberingDraft,
    signal?: AbortSignal,
  ): Promise<TicketNumberingPreview>;
  update(
    csrfToken: string,
    tenantId: string,
    kind: TicketNumberingKind,
    current: VersionedTicketNumberingPolicy,
    idempotencyKey: string,
    reason: string,
    draft: TicketNumberingDraft,
    signal?: AbortSignal,
  ): Promise<TicketNumberingUpdateResult>;
}

export interface TicketNumberingFormDraft {
  prefix: string;
  separator: TicketNumberingSeparator;
  period: TicketNumberingPeriod;
  width: string;
  start: string;
}

export type TicketNumberingDraftField = keyof TicketNumberingFormDraft;
export type TicketNumberingFieldErrors = Partial<
  Readonly<Record<TicketNumberingDraftField, string>>
>;

const prefixPattern = /^[A-Z][A-Z0-9]{0,11}$/u;
const integerPattern = /^(?:0|[1-9][0-9]{0,11})$/u;
const strongEntityTagPattern = /^"v([1-9][0-9]{0,9})"$/u;
const maximumResourceVersion = 2_147_483_647;
const separators = new Set<TicketNumberingSeparator>(["-", "/", ".", "_"]);
const periods = new Set<TicketNumberingPeriod>(["annual", "lifetime"]);

export function ticketNumberingQueryKey(
  sessionId: string,
  tenantId: string,
  kind: TicketNumberingKind,
) {
  return ["ticket-numbering-policy", sessionId, tenantId, kind] as const;
}

export function ticketNumberingPreviewQueryKey(
  sessionId: string,
  tenantId: string,
  kind: TicketNumberingKind,
  draft: TicketNumberingDraft,
) {
  return [
    "ticket-numbering-preview",
    sessionId,
    tenantId,
    kind,
    draft.prefix,
    draft.separator,
    draft.period,
    draft.width,
    draft.start,
  ] as const;
}

export function ticketNumberingFormFrom(
  policy: TicketNumberingPolicy,
): TicketNumberingFormDraft {
  return {
    prefix: policy.prefix,
    separator: policy.separator,
    period: policy.period,
    width: String(policy.width),
    start: String(policy.start),
  };
}

export function normalizeTicketNumberingForm(
  draft: TicketNumberingFormDraft,
): TicketNumberingFormDraft {
  return {
    prefix: draft.prefix.trim().toUpperCase(),
    separator: draft.separator,
    period: draft.period,
    width: draft.width.trim(),
    start: draft.start.trim(),
  };
}

export function ticketNumberingFieldErrors(
  draft: TicketNumberingFormDraft,
): TicketNumberingFieldErrors {
  const normalized = normalizeTicketNumberingForm(draft);
  const errors: Partial<Record<TicketNumberingDraftField, string>> = {};
  if (!prefixPattern.test(normalized.prefix)) {
    errors.prefix =
      "Use 1–12 uppercase letters or digits, starting with a letter.";
  }
  if (!separators.has(normalized.separator)) {
    errors.separator = "Choose one supported separator.";
  }
  if (!periods.has(normalized.period)) {
    errors.period = "Choose annual UTC or lifetime numbering.";
  }
  const width = parseCanonicalInteger(normalized.width);
  if (width === undefined || width < 4 || width > 12) {
    errors.width = "Use a fixed width from 4 to 12 digits.";
  }
  const start = parseCanonicalInteger(normalized.start);
  if (start === undefined || start < 1) {
    errors.start = "Use a positive whole number without leading zeroes.";
  } else if (width !== undefined && width >= 4 && width <= 12) {
    const maximum = maximumSequence(width);
    if (start > maximum) {
      errors.start = `Use a value no greater than ${maximum.toLocaleString("en-US")} for this width.`;
    }
  }
  return errors;
}

export function ticketNumberingDraftFromForm(
  draft: TicketNumberingFormDraft,
): TicketNumberingDraft {
  const normalized = normalizeTicketNumberingForm(draft);
  if (Object.keys(ticketNumberingFieldErrors(normalized)).length > 0) {
    throw new TypeError("Ticket numbering draft is invalid.");
  }
  return {
    prefix: normalized.prefix,
    separator: normalized.separator,
    period: normalized.period,
    width: Number(normalized.width),
    start: Number(normalized.start),
  };
}

export function ticketNumberingDraftDiffers(
  policy: TicketNumberingPolicy,
  draft: TicketNumberingDraft,
): boolean {
  return (
    policy.prefix !== draft.prefix ||
    policy.separator !== draft.separator ||
    policy.period !== draft.period ||
    policy.width !== draft.width ||
    policy.start !== draft.start
  );
}

export function ticketNumberingReasonIsValid(reason: string): boolean {
  return (
    reason.length >= 1 &&
    reason.length <= 2048 &&
    /^[\x21-\x2B\x2D-\x7E](?:[\x20-\x2B\x2D-\x7E]*[\x21-\x2B\x2D-\x7E])?$/u.test(
      reason,
    )
  );
}

export function ticketNumberingUpdateRequest(
  expectedVersion: number,
  draft: TicketNumberingDraft,
): TicketNumberingUpdateRequest {
  if (
    !Number.isSafeInteger(expectedVersion) ||
    expectedVersion < 1 ||
    expectedVersion >= maximumResourceVersion ||
    !isTicketNumberingDraft(draft)
  ) {
    throw new TypeError("Ticket numbering update input is invalid.");
  }
  return { expectedVersion, ...draft };
}

export function entityTagVersion(etag: string): number | undefined {
  const match = strongEntityTagPattern.exec(etag);
  if (!match?.[1]) return undefined;
  const version = Number(match[1]);
  return Number.isSafeInteger(version) && version <= maximumResourceVersion
    ? version
    : undefined;
}

export function isTicketNumberingPolicyProjection(
  value: unknown,
  tenantId: string,
  kind: TicketNumberingKind,
): value is TicketNumberingPolicy {
  if (!isExactObject(value, policyKeys)) return false;
  const draftCandidate: unknown = value;
  if (
    !isCanonicalUuidV7(tenantId) ||
    value.tenantId !== tenantId ||
    value.kind !== kind ||
    !isCanonicalUuidV7(value.versionId) ||
    !isResourceVersion(value.version) ||
    typeof value.publishedAt !== "string" ||
    parseRfc3339Instant(value.publishedAt) === undefined ||
    !isTicketNumberingDraft(draftCandidate)
  ) {
    return false;
  }
  return isPublisher(value.publisher, value.version);
}

export function isTicketNumberingPreviewProjection(
  value: unknown,
  tenantId: string,
  kind: TicketNumberingKind,
  draft: TicketNumberingDraft,
): value is TicketNumberingPreview {
  if (!isExactObject(value, previewKeys)) {
    return false;
  }
  const draftCandidate: unknown = value;
  if (!isTicketNumberingDraft(draftCandidate)) return false;
  if (
    value.tenantId !== tenantId ||
    value.kind !== kind ||
    !sameDraft(draftCandidate, draft) ||
    typeof value.at !== "string" ||
    !value.at.endsWith("Z") ||
    parseRfc3339Instant(value.at) === undefined ||
    typeof value.maximumSequence !== "number" ||
    value.maximumSequence !== maximumSequence(draftCandidate.width) ||
    typeof value.periodKey !== "number" ||
    !Number.isSafeInteger(value.periodKey) ||
    typeof value.example !== "string"
  ) {
    return false;
  }
  const year = new Date(value.at).getUTCFullYear();
  const expectedPeriodKey = draftCandidate.period === "annual" ? year : 0;
  return (
    year >= 2000 &&
    year <= 9999 &&
    value.periodKey === expectedPeriodKey &&
    value.example === renderTicketNumberingExample(draftCandidate, year)
  );
}

export function isTicketNumberingMutationProjection(
  value: unknown,
  tenantId: string,
  kind: TicketNumberingKind,
): value is TicketNumberingMutationResult {
  return (
    isExactObject(value, mutationKeys) &&
    typeof value.replayed === "boolean" &&
    isTicketNumberingPolicyProjection(value.policy, tenantId, kind)
  );
}

export function maximumSequence(width: number): number {
  return 10 ** width - 1;
}

function renderTicketNumberingExample(
  draft: TicketNumberingDraft,
  utcYear: number,
): string {
  const serial = String(draft.start).padStart(draft.width, "0");
  return draft.period === "annual"
    ? `${draft.prefix}${draft.separator}${utcYear}${draft.separator}${serial}`
    : `${draft.prefix}${draft.separator}${serial}`;
}

export function isTicketNumberingDraft(
  value: unknown,
): value is TicketNumberingDraft {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Partial<TicketNumberingDraft>;
  return (
    typeof candidate.prefix === "string" &&
    prefixPattern.test(candidate.prefix) &&
    typeof candidate.separator === "string" &&
    separators.has(candidate.separator) &&
    typeof candidate.period === "string" &&
    periods.has(candidate.period) &&
    typeof candidate.width === "number" &&
    Number.isSafeInteger(candidate.width) &&
    candidate.width >= 4 &&
    candidate.width <= 12 &&
    typeof candidate.start === "number" &&
    Number.isSafeInteger(candidate.start) &&
    candidate.start >= 1 &&
    candidate.start <= maximumSequence(candidate.width)
  );
}

function sameDraft(
  left: TicketNumberingDraft,
  right: TicketNumberingDraft,
): boolean {
  return (
    left.prefix === right.prefix &&
    left.separator === right.separator &&
    left.period === right.period &&
    left.width === right.width &&
    left.start === right.start
  );
}

function isPublisher(value: unknown, version: number): boolean {
  if (!isExactObject(value, publisherKeys)) return false;
  if (value.type === "system") {
    return value.membershipId === null && version === 1;
  }
  return value.type === "membership" && isCanonicalUuidV7(value.membershipId);
}

function isResourceVersion(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= maximumResourceVersion
  );
}

function parseCanonicalInteger(value: string): number | undefined {
  if (!integerPattern.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function isExactObject(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const keys = Object.keys(value).toSorted();
  const sortedExpected = expectedKeys.toSorted();
  return (
    keys.length === sortedExpected.length &&
    keys.every((key, index) => key === sortedExpected[index])
  );
}

const policyKeys = [
  "kind",
  "period",
  "prefix",
  "publishedAt",
  "publisher",
  "separator",
  "start",
  "tenantId",
  "version",
  "versionId",
  "width",
] as const;
const previewKeys = [
  "at",
  "example",
  "kind",
  "maximumSequence",
  "period",
  "periodKey",
  "prefix",
  "separator",
  "start",
  "tenantId",
  "width",
] as const;
const publisherKeys = ["membershipId", "type"] as const;
const mutationKeys = ["policy", "replayed"] as const;
