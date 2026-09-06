import {
  createTenantAlertRelation,
  listTenantAlertRelations,
  retractTenantAlertRelation,
  type AlertRelation,
  type AlertRelationMutationReceipt,
  type AlertRelationType,
} from "@periapsis/contracts";

import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
} from "../lib/canonical-display-name";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  hasBidiControlCharacters,
  hasControlCharacters,
} from "../lib/text-validation";

export interface AlertRelationPage {
  items: readonly AlertRelation[];
  nextCursor?: string;
}

export interface AlertRelationListInput {
  after?: string;
  alertId: string;
  limit?: number;
  signal?: AbortSignal;
  tenantId: string;
}

interface AlertRelationMutationInput {
  alertEtag: string;
  alertId: string;
  csrfToken: string;
  expectedAlertVersion: number;
  idempotencyKey: string;
  reason: string;
  signal?: AbortSignal;
  tenantId: string;
}

export interface AlertRelationCreateInput extends AlertRelationMutationInput {
  expectedTargetVersion: number;
  relationType: AlertRelationType;
  targetAlertId: string;
}

export interface AlertRelationRetractInput extends AlertRelationMutationInput {
  expectedRelatedAlertVersion: number;
  relation: AlertRelation;
}

export interface AlertRelationApi {
  create(
    input: AlertRelationCreateInput,
  ): Promise<AlertRelationMutationReceipt>;
  list(input: AlertRelationListInput): Promise<AlertRelationPage>;
  retract(
    input: AlertRelationRetractInput,
  ): Promise<AlertRelationMutationReceipt>;
}

export class AlertRelationApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: "projection_mismatch",
  ) {
    super(message);
    this.name = "AlertRelationApiError";
  }
}

interface GeneratedResult {
  data?: unknown;
  response?: Response;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  cache: "no-store" as const,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

export const alertRelationUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}(?![\s\S])/u;
const workflowStatePattern = /^[a-z][a-z0-9_-]{0,63}(?![\s\S])/u;
const maximumVersion = 2_147_483_647;

export const alertRelationApi: AlertRelationApi = {
  async list(input) {
    const limit = requireListInput(input);
    const result = await listTenantAlertRelations({
      ...sameOrigin,
      path: { alertId: input.alertId, tenantId: input.tenantId },
      query: {
        limit,
        ...(input.after === undefined ? {} : { after: input.after }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    return projectAlertRelationPage(
      result.data,
      input.tenantId,
      input.alertId,
      input.after,
      limit,
    );
  },

  async create(input) {
    requireCreateInput(input);
    const result = await createTenantAlertRelation({
      ...sameOrigin,
      body: {
        expectedTargetVersion: input.expectedTargetVersion,
        expectedVersion: input.expectedAlertVersion,
        reason: input.reason,
        relationType: input.relationType,
        targetAlertId: input.targetAlertId,
      },
      headers: mutationHeaders(input),
      path: { alertId: input.alertId, tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    return projectMutationReceipt(result, {
      alertId: input.alertId,
      expectedAlertVersion: input.expectedAlertVersion,
      expectedRelatedAlertVersion: input.expectedTargetVersion,
      relatedAlertId: input.targetAlertId,
      relationType: input.relationType,
      tenantId: input.tenantId,
    });
  },

  async retract(input) {
    requireRetractInput(input);
    const relatedAlertId = input.relation.relatedAlert.id;
    const result = await retractTenantAlertRelation({
      ...sameOrigin,
      body: {
        expectedRelatedAlertVersion: input.expectedRelatedAlertVersion,
        expectedVersion: input.expectedAlertVersion,
        reason: input.reason,
        relatedAlertId,
      },
      headers: mutationHeaders(input),
      path: {
        alertId: input.alertId,
        relationId: input.relation.id,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    return projectMutationReceipt(result, {
      alertId: input.alertId,
      expectedAlertVersion: input.expectedAlertVersion,
      expectedRelatedAlertVersion: input.expectedRelatedAlertVersion,
      relatedAlertId,
      relationId: input.relation.id,
      relationType: input.relation.relationType,
      tenantId: input.tenantId,
    });
  },
};

export function projectAlertRelationPage(
  source: unknown,
  tenantId: string,
  alertId: string,
  after: string | undefined,
  limit: number,
): AlertRelationPage {
  if (
    !isUuidV7(tenantId) ||
    !isUuidV7(alertId) ||
    (after !== undefined && !isUuidV7(after)) ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100 ||
    !isRecord(source) ||
    !hasOnlyKeys(source, ["items", "nextCursor"]) ||
    !Array.isArray(source["items"]) ||
    source["items"].length > limit
  ) {
    throw projectionMismatch();
  }
  const items = source["items"].map((value) =>
    projectAlertRelation(value, tenantId, alertId),
  );
  let previousId: string | undefined;
  const pairs = new Set<string>();
  for (const item of items) {
    if (
      (previousId !== undefined && previousId <= item.id) ||
      (after !== undefined && item.id >= after)
    ) {
      throw projectionMismatch();
    }
    const pair = [item.sourceAlertId, item.targetAlertId].toSorted().join(":");
    if (pairs.has(pair)) throw projectionMismatch();
    pairs.add(pair);
    previousId = item.id;
  }
  const nextCursor = source["nextCursor"];
  if (
    nextCursor !== undefined &&
    (!isUuidV7(nextCursor) ||
      items.length !== limit ||
      items.at(-1)?.id !== nextCursor ||
      nextCursor === after)
  ) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(typeof nextCursor === "string" ? { nextCursor } : {}),
  };
}

export function isCanonicalAlertRelationReason(value: string): boolean {
  return isCanonicalBoundedText(value, 2_000);
}

function projectAlertRelation(
  source: unknown,
  tenantId: string,
  alertId: string,
): AlertRelation {
  const allowedKeys = [
    "id",
    "tenantId",
    "sourceAlertId",
    "targetAlertId",
    "relationType",
    "direction",
    "status",
    "reason",
    "previousSourceVersion",
    "sourceVersion",
    "previousTargetVersion",
    "targetVersion",
    "linkedAt",
    "relatedAlert",
    "retraction",
  ];
  if (!isRecord(source) || !hasOnlyKeys(source, allowedKeys)) {
    throw projectionMismatch();
  }
  const id = source["id"];
  const sourceAlertId = source["sourceAlertId"];
  const targetAlertId = source["targetAlertId"];
  const relationType = source["relationType"];
  const direction = source["direction"];
  const status = source["status"];
  const previousSourceVersion = source["previousSourceVersion"];
  const sourceVersion = source["sourceVersion"];
  const previousTargetVersion = source["previousTargetVersion"];
  const targetVersion = source["targetVersion"];
  const linkedAt = source["linkedAt"];
  const sourceVersions = projectVersionIncrement(
    previousSourceVersion,
    sourceVersion,
  );
  const targetVersions = projectVersionIncrement(
    previousTargetVersion,
    targetVersion,
  );
  if (
    !isUuidV7(id) ||
    source["tenantId"] !== tenantId ||
    !isUuidV7(sourceAlertId) ||
    !isUuidV7(targetAlertId) ||
    sourceAlertId === targetAlertId ||
    (sourceAlertId !== alertId && targetAlertId !== alertId) ||
    !isRelationType(relationType) ||
    !isDirection(direction) ||
    !isStatus(status) ||
    typeof source["reason"] !== "string" ||
    !isCanonicalAlertRelationReason(source["reason"]) ||
    sourceVersions === undefined ||
    targetVersions === undefined ||
    !isCanonicalInstant(linkedAt)
  ) {
    throw projectionMismatch();
  }
  const validatedSourceVersion = sourceVersions.current;
  const validatedTargetVersion = targetVersions.current;
  if (
    (relationType === "correlation" && direction !== "symmetric") ||
    (relationType === "duplicate_of" &&
      ((sourceAlertId === alertId && direction !== "outgoing") ||
        (targetAlertId === alertId && direction !== "incoming")))
  ) {
    throw projectionMismatch();
  }
  const relatedAlertId =
    sourceAlertId === alertId ? targetAlertId : sourceAlertId;
  const relatedAlert = projectRelatedAlert(
    source["relatedAlert"],
    relatedAlertId,
  );
  const relationFloor =
    relatedAlertId === sourceAlertId
      ? validatedSourceVersion
      : validatedTargetVersion;
  const retraction = projectRetraction(source["retraction"], {
    linkedAt,
    relationSourceVersion: validatedSourceVersion,
    relationTargetVersion: validatedTargetVersion,
    required: status === "retracted",
  });
  const currentFloor =
    retraction === undefined
      ? relationFloor
      : relatedAlertId === sourceAlertId
        ? retraction.sourceVersion
        : retraction.targetVersion;
  if (
    (status === "active" && retraction !== undefined) ||
    relatedAlert.version < currentFloor ||
    parseRfc3339Instant(relatedAlert.updatedAt)! <
      parseRfc3339Instant(retraction?.retractedAt ?? linkedAt)!
  ) {
    throw projectionMismatch();
  }
  return {
    id,
    tenantId,
    sourceAlertId,
    targetAlertId,
    relationType,
    direction,
    status,
    reason: source["reason"],
    previousSourceVersion: sourceVersions.previous,
    sourceVersion: validatedSourceVersion,
    previousTargetVersion: targetVersions.previous,
    targetVersion: validatedTargetVersion,
    linkedAt,
    relatedAlert,
    ...(retraction === undefined ? {} : { retraction }),
  };
}

function projectRelatedAlert(
  source: unknown,
  expectedId: string,
): AlertRelation["relatedAlert"] {
  if (
    !isRecord(source) ||
    !hasExactKeys(source, [
      "id",
      "number",
      "title",
      "severity",
      "stateKey",
      "version",
      "updatedAt",
    ]) ||
    source["id"] !== expectedId ||
    typeof source["number"] !== "string" ||
    !isCanonicalBoundedText(source["number"], 64) ||
    typeof source["title"] !== "string" ||
    !isCanonicalBoundedText(source["title"], 240) ||
    !isSeverity(source["severity"]) ||
    typeof source["stateKey"] !== "string" ||
    !workflowStatePattern.test(source["stateKey"]) ||
    !isResourceVersion(source["version"]) ||
    !isCanonicalInstant(source["updatedAt"])
  ) {
    throw projectionMismatch();
  }
  return {
    id: expectedId,
    number: source["number"],
    title: source["title"],
    severity: source["severity"],
    stateKey: source["stateKey"],
    version: source["version"],
    updatedAt: source["updatedAt"],
  };
}

function projectRetraction(
  source: unknown,
  context: {
    linkedAt: string;
    relationSourceVersion: number;
    relationTargetVersion: number;
    required: boolean;
  },
): AlertRelation["retraction"] {
  if (source === undefined) {
    if (context.required) throw projectionMismatch();
    return undefined;
  }
  const previousSourceVersion = isRecord(source)
    ? source["previousSourceVersion"]
    : undefined;
  const sourceVersion = isRecord(source) ? source["sourceVersion"] : undefined;
  const previousTargetVersion = isRecord(source)
    ? source["previousTargetVersion"]
    : undefined;
  const targetVersion = isRecord(source) ? source["targetVersion"] : undefined;
  const sourceVersions = projectVersionIncrement(
    previousSourceVersion,
    sourceVersion,
  );
  const targetVersions = projectVersionIncrement(
    previousTargetVersion,
    targetVersion,
  );
  if (
    !context.required ||
    !isRecord(source) ||
    !hasExactKeys(source, [
      "reason",
      "previousSourceVersion",
      "sourceVersion",
      "previousTargetVersion",
      "targetVersion",
      "retractedAt",
    ]) ||
    typeof source["reason"] !== "string" ||
    !isCanonicalAlertRelationReason(source["reason"]) ||
    sourceVersions === undefined ||
    targetVersions === undefined ||
    sourceVersions.previous < context.relationSourceVersion ||
    targetVersions.previous < context.relationTargetVersion ||
    !isCanonicalInstant(source["retractedAt"]) ||
    parseRfc3339Instant(source["retractedAt"])! <
      parseRfc3339Instant(context.linkedAt)!
  ) {
    throw projectionMismatch();
  }
  return {
    reason: source["reason"],
    previousSourceVersion: sourceVersions.previous,
    sourceVersion: sourceVersions.current,
    previousTargetVersion: targetVersions.previous,
    targetVersion: targetVersions.current,
    retractedAt: source["retractedAt"],
  };
}

function projectMutationReceipt(
  result: GeneratedResult,
  expected: {
    alertId: string;
    expectedAlertVersion: number;
    expectedRelatedAlertVersion: number;
    relatedAlertId: string;
    relationId?: string;
    relationType: AlertRelationType;
    tenantId: string;
  },
): AlertRelationMutationReceipt {
  const source = result.data;
  if (
    !isRecord(source) ||
    !hasExactKeys(source, [
      "tenantId",
      "alertId",
      "relatedAlertId",
      "relationId",
      "relationType",
      "previousAlertVersion",
      "alertVersion",
      "previousRelatedAlertVersion",
      "relatedAlertVersion",
      "occurredAt",
      "replayed",
    ]) ||
    source["tenantId"] !== expected.tenantId ||
    source["alertId"] !== expected.alertId ||
    source["relatedAlertId"] !== expected.relatedAlertId ||
    !isUuidV7(source["relationId"]) ||
    (expected.relationId !== undefined &&
      source["relationId"] !== expected.relationId) ||
    source["relationType"] !== expected.relationType ||
    source["previousAlertVersion"] !== expected.expectedAlertVersion ||
    source["alertVersion"] !== expected.expectedAlertVersion + 1 ||
    source["previousRelatedAlertVersion"] !==
      expected.expectedRelatedAlertVersion ||
    source["relatedAlertVersion"] !==
      expected.expectedRelatedAlertVersion + 1 ||
    !isCanonicalInstant(source["occurredAt"]) ||
    typeof source["replayed"] !== "boolean" ||
    result.response?.headers.get("ETag") !== `"v${source["alertVersion"]}"` ||
    result.response.headers.get("X-Idempotent-Replay") !==
      String(source["replayed"])
  ) {
    throw projectionMismatch();
  }
  return {
    tenantId: expected.tenantId,
    alertId: expected.alertId,
    relatedAlertId: expected.relatedAlertId,
    relationId: source["relationId"],
    relationType: expected.relationType,
    previousAlertVersion: expected.expectedAlertVersion,
    alertVersion: source["alertVersion"],
    previousRelatedAlertVersion: expected.expectedRelatedAlertVersion,
    relatedAlertVersion: source["relatedAlertVersion"],
    occurredAt: source["occurredAt"],
    replayed: source["replayed"],
  };
}

function requireListInput(input: AlertRelationListInput): number {
  requireCoordinates(input.tenantId, input.alertId);
  const limit = input.limit ?? 50;
  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100 ||
    (input.after !== undefined && !isUuidV7(input.after))
  ) {
    throw new TypeError("A canonical bounded Alert relation page is required.");
  }
  return limit;
}

function requireCreateInput(input: AlertRelationCreateInput): void {
  requireMutationInput(input);
  if (
    !isUuidV7(input.targetAlertId) ||
    input.targetAlertId === input.alertId ||
    !isRelationType(input.relationType) ||
    !isMutableVersion(input.expectedTargetVersion)
  ) {
    throw new TypeError("Canonical related Alert coordinates are required.");
  }
}

function requireRetractInput(input: AlertRelationRetractInput): void {
  requireMutationInput(input);
  const relation = projectAlertRelation(
    input.relation,
    input.tenantId,
    input.alertId,
  );
  if (
    relation.status !== "active" ||
    relation.retraction !== undefined ||
    !isMutableVersion(input.expectedRelatedAlertVersion)
  ) {
    throw new TypeError("An active canonical Alert relation is required.");
  }
}

function requireMutationInput(input: AlertRelationMutationInput): void {
  requireCoordinates(input.tenantId, input.alertId);
  if (
    !isMutableVersion(input.expectedAlertVersion) ||
    input.alertEtag !== `"v${input.expectedAlertVersion}"` ||
    input.csrfToken.trim() === "" ||
    hasControlCharacters(input.csrfToken) ||
    !idempotencyKeyPattern.test(input.idempotencyKey) ||
    !isCanonicalAlertRelationReason(input.reason)
  ) {
    throw new TypeError("Canonical Alert relation mutation input is required.");
  }
}

function requireCoordinates(tenantId: string, alertId: string): void {
  if (!isUuidV7(tenantId) || !isUuidV7(alertId)) {
    throw new TypeError(
      "Canonical tenant and Alert UUIDv7 values are required.",
    );
  }
}

function mutationHeaders(input: AlertRelationMutationInput) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "If-Match": input.alertEtag,
    "X-CSRF-Token": input.csrfToken,
  };
}

function requireStatus(result: GeneratedResult, expected: number): void {
  const response = result.response;
  if (!response || !hasNoStore(response.headers.get("Cache-Control"))) {
    throw projectionMismatch();
  }
  if (response.status !== expected) {
    throw new AlertRelationApiError(
      statusMessage(response.status),
      response.status,
    );
  }
}

function statusMessage(status: number): string {
  switch (status) {
    case 400:
      return "The Alert relationship request was not accepted.";
    case 401:
      return "Your session is no longer valid.";
    case 403:
      return "Your current access does not allow this Alert relationship.";
    case 404:
      return "An Alert or relationship is unavailable in the active tenant.";
    case 409:
      return "This Alert pair or retry key conflicts with current server state.";
    case 412:
    case 428:
      return "One of the Alerts changed. Reload both snapshots before retrying.";
    case 503:
      return "The Alert relationship service is temporarily unavailable.";
    default:
      return "The Alert relationship could not be updated.";
  }
}

function isCanonicalBoundedText(value: string, maximumBytes: number): boolean {
  return (
    value.length > 0 &&
    new TextEncoder().encode(value).length <= maximumBytes &&
    !hasGoTrimSpaceAtEdge(value) &&
    !hasUnpairedSurrogate(value) &&
    !hasControlCharacters(value) &&
    !hasBidiControlCharacters(value)
  );
}

function isCanonicalInstant(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 20 &&
    value.length <= 30 &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) &&
    parseRfc3339Instant(value) !== undefined
  );
}

function projectVersionIncrement(
  previous: unknown,
  current: unknown,
): { current: number; previous: number } | undefined {
  return isMutableVersion(previous) &&
    isResourceVersion(current) &&
    current === previous + 1
    ? { current, previous }
    : undefined;
}

function isMutableVersion(value: unknown): value is number {
  return isResourceVersion(value) && value < maximumVersion;
}

function isResourceVersion(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= maximumVersion
  );
}

function isRelationType(value: unknown): value is AlertRelationType {
  return value === "duplicate_of" || value === "correlation";
}

function isDirection(value: unknown): value is AlertRelation["direction"] {
  return value === "outgoing" || value === "incoming" || value === "symmetric";
}

function isStatus(value: unknown): value is AlertRelation["status"] {
  return value === "active" || value === "retracted";
}

function isSeverity(
  value: unknown,
): value is AlertRelation["relatedAlert"]["severity"] {
  return (
    value === "informational" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
  );
}

function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && alertRelationUuidV7Pattern.test(value);
}

function hasNoStore(value: string | null): boolean {
  return (
    value
      ?.split(",")
      .some((directive) => directive.trim().toLowerCase() === "no-store") ??
    false
  );
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const allowedKeys = new Set(allowed);
  return Object.keys(value).every((key) => allowedKeys.has(key));
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionMismatch(): AlertRelationApiError {
  return new AlertRelationApiError(
    "The Alert relationship response was not safe to apply.",
    undefined,
    "projection_mismatch",
  );
}
