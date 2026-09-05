import {
  getTenantNotificationInboxUnreadCount,
  listTenantNotificationInbox,
  markAllTenantNotificationInboxRead,
  setTenantNotificationInboxReadState,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "../lib/session-transition-transport";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import {
  isCanonicalUuidV7,
  notificationAudiences,
  notificationEventTypes,
  notificationResourceKinds,
  type NotificationAudience,
  type NotificationEventType,
  type NotificationInboxCoordinate,
  type NotificationInboxItemView,
  type NotificationInboxPageView,
  type NotificationMarkAllReadResultView,
  type NotificationReadStateResultView,
  type NotificationResourceKind,
  type NotificationUnreadStateView,
} from "./inbox-model";

export const notificationInboxPageLimit = 50;
export const maximumNotificationInboxRevision = 2_147_483_647;
const maximumPageLimit = 100;
const maximumUnreadCount = 1_000_000;
const maximumClockSkewMilliseconds = 60_000;
const operatorOnlyEventTypes = new Set<NotificationEventType>([
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.private_added",
]);
const utf8Encoder = new TextEncoder();

export interface ListNotificationInboxInput {
  after?: string;
  limit: number;
  signal?: AbortSignal;
  tenantId: string;
  unreadOnly: boolean;
}

export interface CountUnreadNotificationsInput {
  signal?: AbortSignal;
  tenantId: string;
}

export interface SetNotificationReadStateInput {
  csrfToken: string;
  expectedRevision: number;
  idempotencyKey: string;
  itemId: string;
  read: boolean;
  signal?: AbortSignal;
  tenantId: string;
}

export interface MarkAllNotificationsReadInput {
  csrfToken: string;
  expectedRevision: number;
  idempotencyKey: string;
  signal?: AbortSignal;
  tenantId: string;
}

/** An injected boundary matching services/api/internal/notificationinbox. */
export interface NotificationInboxApi {
  countUnread(input: CountUnreadNotificationsInput): Promise<unknown>;
  list(input: ListNotificationInboxInput): Promise<unknown>;
  markAllRead(input: MarkAllNotificationsReadInput): Promise<unknown>;
  setReadState(input: SetNotificationReadStateInput): Promise<unknown>;
}

export class NotificationInboxApiError extends Error {
  readonly code: string | undefined;
  readonly status: number;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "NotificationInboxApiError";
    this.status = status;
    this.code = code;
  }
}

export class NotificationInboxProjectionError extends Error {
  constructor() {
    super("The notification inbox projection was not safe to apply.");
    this.name = "NotificationInboxProjectionError";
  }
}

interface GeneratedInboxResult<T> {
  data?: T;
  error?: unknown;
  response?: Response;
}

const notificationInboxSameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

export const notificationInboxApi: NotificationInboxApi = {
  async list(input) {
    requireNotificationInboxTenant(input.tenantId);
    if (
      !Number.isSafeInteger(input.limit) ||
      input.limit < 1 ||
      input.limit > maximumPageLimit ||
      (input.after !== undefined && !isCanonicalUuidV7(input.after))
    ) {
      throw invalidNotificationInboxRequest();
    }
    const result = await listTenantNotificationInbox({
      ...notificationInboxSameOrigin,
      path: { tenantId: input.tenantId },
      query: {
        limit: input.limit,
        unreadOnly: input.unreadOnly,
        ...(input.after === undefined ? {} : { after: input.after }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return unwrapNotificationInboxResult(result);
  },

  async countUnread(input) {
    requireNotificationInboxTenant(input.tenantId);
    const result = await getTenantNotificationInboxUnreadCount({
      ...notificationInboxSameOrigin,
      path: { tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return unwrapNotificationInboxResult(result);
  },

  async setReadState(input) {
    requireNotificationInboxTenant(input.tenantId);
    if (
      !isCanonicalUuidV7(input.itemId) ||
      !isNotificationExpectedRevision(input.expectedRevision) ||
      !validNotificationInboxCsrf(input.csrfToken) ||
      !validNotificationInboxIdempotencyKey(input.idempotencyKey)
    ) {
      throw invalidNotificationInboxRequest();
    }
    const result = await setTenantNotificationInboxReadState({
      ...notificationInboxSameOrigin,
      body: { read: input.read },
      headers: {
        "Idempotency-Key": input.idempotencyKey,
        "If-Match": notificationInboxEntityTag(input.expectedRevision),
        "X-CSRF-Token": input.csrfToken,
      },
      path: {
        notificationInboxItemId: input.itemId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const value = unwrapNotificationInboxResult(result);
    requireNotificationInboxResponseTag(result.response, value, "item");
    return value;
  },

  async markAllRead(input) {
    requireNotificationInboxTenant(input.tenantId);
    if (
      !isNotificationExpectedRevision(input.expectedRevision, true) ||
      !validNotificationInboxCsrf(input.csrfToken) ||
      !validNotificationInboxIdempotencyKey(input.idempotencyKey)
    ) {
      throw invalidNotificationInboxRequest();
    }
    const result = await markAllTenantNotificationInboxRead({
      ...notificationInboxSameOrigin,
      headers: {
        "Idempotency-Key": input.idempotencyKey,
        "If-Match": notificationInboxEntityTag(input.expectedRevision),
        "X-CSRF-Token": input.csrfToken,
      },
      path: { tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    const value = unwrapNotificationInboxResult(result);
    requireNotificationInboxResponseTag(result.response, value, "inbox");
    return value;
  },
};

export function describeNotificationInboxError(
  error: unknown,
  fallback: string,
): string {
  if (
    error instanceof NotificationInboxApiError &&
    error.message.trim() !== ""
  ) {
    return error.message;
  }
  if (error instanceof NotificationInboxProjectionError) return error.message;
  return fallback;
}

export function projectNotificationInboxPage(
  input: unknown,
  coordinate: NotificationInboxCoordinate,
  request: Pick<ListNotificationInboxInput, "after" | "limit" | "unreadOnly">,
  now = Date.now(),
): NotificationInboxPageView {
  if (
    !isCoordinateCanonical(coordinate) ||
    !Number.isSafeInteger(request.limit) ||
    request.limit < 1 ||
    request.limit > maximumPageLimit ||
    (request.after !== undefined && !isCanonicalUuidV7(request.after))
  ) {
    throw projectionError();
  }
  const record = exactRecord(
    input,
    ["inboxRevision", "items", "tenantId", "userId"],
    ["nextCursor"],
  );
  if (
    !record ||
    record.tenantId !== coordinate.tenantId ||
    record.userId !== coordinate.userId ||
    !Array.isArray(record.items) ||
    record.items.length > request.limit ||
    !isInboxRevision(record.inboxRevision, record.items.length > 0)
  ) {
    throw projectionError();
  }

  const items: NotificationInboxItemView[] = [];
  const seen = new Set<string>();
  let audience: NotificationAudience | undefined;
  let previousId: string | undefined;
  for (const rawItem of record.items) {
    const item = projectNotificationInboxItem(
      rawItem,
      coordinate,
      now,
      audience,
    );
    if (
      (request.unreadOnly && item.readAt !== null) ||
      seen.has(item.id) ||
      (previousId !== undefined && previousId <= item.id) ||
      (request.after !== undefined && item.id >= request.after)
    ) {
      throw projectionError();
    }
    seen.add(item.id);
    audience = item.audience;
    previousId = item.id;
    items.push(item);
  }

  const rawCursor = record.nextCursor;
  if (rawCursor !== undefined) {
    if (
      !isCanonicalUuidV7(rawCursor) ||
      items.length !== request.limit ||
      items.at(-1)?.id !== rawCursor
    ) {
      throw projectionError();
    }
    return {
      inboxRevision: record.inboxRevision,
      items,
      nextCursor: rawCursor,
      tenantId: coordinate.tenantId,
      userId: coordinate.userId,
    };
  }
  return {
    inboxRevision: record.inboxRevision,
    items,
    tenantId: coordinate.tenantId,
    userId: coordinate.userId,
  };
}

export function projectNotificationUnreadState(
  input: unknown,
  coordinate: NotificationInboxCoordinate,
): NotificationUnreadStateView {
  const record = exactRecord(input, [
    "count",
    "inboxRevision",
    "tenantId",
    "userId",
  ]);
  if (
    !isCoordinateCanonical(coordinate) ||
    !record ||
    record.tenantId !== coordinate.tenantId ||
    record.userId !== coordinate.userId ||
    !isSafeIntegerBetween(record.count, 0, maximumUnreadCount) ||
    !isInboxRevision(record.inboxRevision, record.count > 0)
  ) {
    throw projectionError();
  }
  return {
    count: record.count,
    inboxRevision: record.inboxRevision,
    tenantId: coordinate.tenantId,
    userId: coordinate.userId,
  };
}

export function projectNotificationReadStateResult(
  input: unknown,
  coordinate: NotificationInboxCoordinate,
  request: Pick<
    SetNotificationReadStateInput,
    "expectedRevision" | "itemId" | "read"
  > & { audience: NotificationAudience },
  now = Date.now(),
): NotificationReadStateResultView {
  const record = exactRecord(input, [
    "changed",
    "inboxRevision",
    "item",
    "replayed",
  ]);
  if (
    !isCoordinateCanonical(coordinate) ||
    !record ||
    typeof record.changed !== "boolean" ||
    typeof record.replayed !== "boolean" ||
    !isPositiveRevision(record.inboxRevision) ||
    !isNotificationExpectedRevision(request.expectedRevision) ||
    !isCanonicalUuidV7(request.itemId)
  ) {
    throw projectionError();
  }
  const item = projectNotificationInboxItem(
    record.item,
    coordinate,
    now,
    request.audience,
  );
  const expectedResultRevision =
    request.expectedRevision + (record.changed ? 1 : 0);
  if (
    item.id !== request.itemId ||
    (item.readAt !== null) !== request.read ||
    item.revision !== expectedResultRevision ||
    !Number.isSafeInteger(expectedResultRevision)
  ) {
    throw projectionError();
  }
  return {
    changed: record.changed,
    inboxRevision: record.inboxRevision,
    item,
    replayed: record.replayed,
  };
}

export function projectNotificationMarkAllReadResult(
  input: unknown,
  coordinate: NotificationInboxCoordinate,
  expectedRevision: number,
): NotificationMarkAllReadResultView {
  const record = exactRecord(input, [
    "affected",
    "changed",
    "inboxRevision",
    "replayed",
    "tenantId",
    "userId",
  ]);
  if (
    !isCoordinateCanonical(coordinate) ||
    !record ||
    record.tenantId !== coordinate.tenantId ||
    record.userId !== coordinate.userId ||
    typeof record.changed !== "boolean" ||
    typeof record.replayed !== "boolean" ||
    !isSafeIntegerBetween(record.affected, 0, maximumUnreadCount) ||
    record.changed !== record.affected > 0 ||
    !isNotificationExpectedRevision(expectedRevision, true) ||
    record.inboxRevision !== expectedRevision + (record.changed ? 1 : 0) ||
    !isInboxRevision(record.inboxRevision, record.changed)
  ) {
    throw projectionError();
  }
  return {
    affected: record.affected,
    changed: record.changed,
    inboxRevision: record.inboxRevision,
    replayed: record.replayed,
    tenantId: coordinate.tenantId,
    userId: coordinate.userId,
  };
}

export function mergeNotificationInboxPages(
  pages: readonly NotificationInboxPageView[],
  coordinate: NotificationInboxCoordinate,
  unreadOnly: boolean,
): { canonical: boolean; items: readonly NotificationInboxItemView[] } {
  if (!isCoordinateCanonical(coordinate)) {
    return { canonical: false, items: [] };
  }
  const items: NotificationInboxItemView[] = [];
  const seen = new Set<string>();
  let audience: NotificationAudience | undefined;
  let canContinue = true;
  let previousId: string | undefined;
  for (const page of pages) {
    if (
      !canContinue ||
      page.tenantId !== coordinate.tenantId ||
      page.userId !== coordinate.userId ||
      !isInboxRevision(page.inboxRevision, page.items.length > 0) ||
      (page.nextCursor !== undefined &&
        (!isCanonicalUuidV7(page.nextCursor) ||
          page.items.at(-1)?.id !== page.nextCursor))
    ) {
      return { canonical: false, items: [] };
    }
    for (const rawItem of page.items) {
      let item: NotificationInboxItemView;
      try {
        item = projectNotificationInboxItem(
          rawItem,
          coordinate,
          Date.now(),
          audience,
        );
      } catch {
        return { canonical: false, items: [] };
      }
      if (
        item.tenantId !== coordinate.tenantId ||
        item.userId !== coordinate.userId ||
        (unreadOnly && item.readAt !== null) ||
        !isCanonicalUuidV7(item.id) ||
        seen.has(item.id) ||
        (previousId !== undefined && previousId <= item.id)
      ) {
        return { canonical: false, items: [] };
      }
      seen.add(item.id);
      audience = item.audience;
      previousId = item.id;
      items.push(item);
    }
    canContinue = page.nextCursor !== undefined;
  }
  return { canonical: true, items };
}

function projectNotificationInboxItem(
  input: unknown,
  coordinate: NotificationInboxCoordinate,
  now: number,
  expectedAudience?: NotificationAudience,
): NotificationInboxItemView {
  const record = exactRecord(input, [
    "audience",
    "eventType",
    "id",
    "occurredAt",
    "readAt",
    "resourceId",
    "resourceKind",
    "resourceVersion",
    "revision",
    "summary",
    "tenantId",
    "title",
    "userId",
  ]);
  if (
    !record ||
    record.tenantId !== coordinate.tenantId ||
    record.userId !== coordinate.userId ||
    !isOneOf(record.audience, notificationAudiences) ||
    (expectedAudience !== undefined && record.audience !== expectedAudience) ||
    !isOneOf(record.eventType, notificationEventTypes) ||
    !isOneOf(record.resourceKind, notificationResourceKinds) ||
    !validAudienceEvent(record.audience, record.eventType) ||
    !validEventResource(record.eventType, record.resourceKind) ||
    !isCanonicalUuidV7(record.id) ||
    !isCanonicalUuidV7(record.resourceId) ||
    !isPositiveRevision(record.resourceVersion) ||
    !isPositiveRevision(record.revision) ||
    !isBoundedText(record.title, 240, false) ||
    !isBoundedText(record.summary, 2_000, true) ||
    !isCanonicalUtcInstant(record.occurredAt, now)
  ) {
    throw projectionError();
  }
  if (
    record.readAt !== null &&
    (!isCanonicalUtcInstant(record.readAt, now) ||
      parseRfc3339Instant(record.readAt)! <
        parseRfc3339Instant(record.occurredAt)!)
  ) {
    throw projectionError();
  }
  return {
    audience: record.audience,
    eventType: record.eventType,
    id: record.id,
    occurredAt: record.occurredAt,
    readAt: record.readAt,
    resourceId: record.resourceId,
    resourceKind: record.resourceKind,
    resourceVersion: record.resourceVersion,
    revision: record.revision,
    summary: record.summary,
    tenantId: coordinate.tenantId,
    title: record.title,
    userId: coordinate.userId,
  };
}

function validAudienceEvent(
  audience: NotificationAudience,
  eventType: NotificationEventType,
): boolean {
  return audience === "operator" || !operatorOnlyEventTypes.has(eventType);
}

function validEventResource(
  eventType: NotificationEventType,
  resourceKind: NotificationResourceKind,
): boolean {
  if (eventType.startsWith("alert.")) return resourceKind === "alert";
  if (eventType.startsWith("case.")) return resourceKind === "case";
  switch (eventType) {
    case "comment.public_added":
    case "comment.private_added":
    case "sla.warning":
    case "sla.breached":
      return resourceKind === "alert" || resourceKind === "case";
    case "contact.changed":
      return resourceKind === "contact";
    case "task.assigned":
      return resourceKind === "task";
    case "evidence.added":
      return resourceKind === "evidence";
    case "webhook.custom":
      return true;
  }
  return false;
}

function isCanonicalUtcInstant(value: unknown, now: number): value is string {
  if (
    !Number.isFinite(now) ||
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/u.test(value)
  ) {
    return false;
  }
  const instant = parseRfc3339Instant(value);
  return (
    instant !== undefined &&
    instant <=
      BigInt(Math.trunc(now + maximumClockSkewMilliseconds)) * 1_000_000n
  );
}

function isBoundedText(
  value: unknown,
  maximumBytes: number,
  optional: boolean,
): value is string {
  return (
    typeof value === "string" &&
    (optional || value !== "") &&
    value.trim() === value &&
    hasWellFormedUtf16(value) &&
    utf8Encoder.encode(value).length <= maximumBytes &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function hasWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isCoordinateCanonical(
  coordinate: NotificationInboxCoordinate,
): boolean {
  return (
    isCanonicalUuidV7(coordinate.tenantId) &&
    isCanonicalUuidV7(coordinate.userId)
  );
}

function isPositiveRevision(value: unknown): value is number {
  return isSafeIntegerBetween(value, 1, maximumNotificationInboxRevision);
}

function isInboxRevision(
  value: unknown,
  requirePositive: boolean,
): value is number {
  return isSafeIntegerBetween(
    value,
    requirePositive ? 1 : 0,
    maximumNotificationInboxRevision,
  );
}

export function isNotificationExpectedRevision(
  value: unknown,
  allowZero = false,
): value is number {
  return isSafeIntegerBetween(
    value,
    allowZero ? 0 : 1,
    maximumNotificationInboxRevision - 1,
  );
}

function isSafeIntegerBetween(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isOneOf<const T extends string>(
  value: unknown,
  allowed: readonly T[],
): value is T {
  return (
    typeof value === "string" &&
    allowed.some((candidate) => candidate === value)
  );
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> | undefined {
  if (!isRecord(value)) return undefined;
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => allowed.has(key))
    ? value
    : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionError(): NotificationInboxProjectionError {
  return new NotificationInboxProjectionError();
}

function unwrapNotificationInboxResult<T>(result: GeneratedInboxResult<T>): T {
  if (result.data !== undefined) {
    requireNotificationInboxPrivateResponse(result.response);
    return result.data;
  }
  const status = result.response?.status ?? 0;
  const problem = isRecord(result.error) ? result.error : undefined;
  const code =
    typeof problem?.["code"] === "string" ? problem["code"] : undefined;
  throw new NotificationInboxApiError(
    status,
    notificationInboxFallback(status),
    code,
  );
}

function requireNotificationInboxPrivateResponse(response?: Response): void {
  const cacheControl = response?.headers.get("Cache-Control") ?? "";
  const directives = new Set(
    cacheControl
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
  if (!response || !directives.has("private") || !directives.has("no-store")) {
    throw new NotificationInboxApiError(
      0,
      "The notification inbox response was not marked private.",
      "projection_mismatch",
    );
  }
}

function requireNotificationInboxResponseTag(
  response: Response | undefined,
  value: unknown,
  source: "inbox" | "item",
): void {
  if (!isRecord(value)) throw projectionError();
  const revision =
    source === "item" && isRecord(value["item"])
      ? value["item"]["revision"]
      : value["inboxRevision"];
  if (
    !isInboxRevision(revision, source === "item") ||
    response?.headers.get("ETag") !== notificationInboxEntityTag(revision)
  ) {
    throw new NotificationInboxApiError(
      0,
      "The notification inbox response omitted its current version.",
      "projection_mismatch",
    );
  }
}

function requireNotificationInboxTenant(value: string): void {
  if (!isCanonicalUuidV7(value)) throw invalidNotificationInboxRequest();
}

function validNotificationInboxCsrf(value: string): boolean {
  return (
    value.trim() === value &&
    value.length > 0 &&
    value.length <= 128 &&
    !value.includes(",") &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function validNotificationInboxIdempotencyKey(value: string): boolean {
  return (
    value.length >= 16 &&
    value.length <= 128 &&
    /^[A-Za-z0-9._~-]+$/u.test(value)
  );
}

function notificationInboxEntityTag(revision: number): string {
  return `"v${revision}"`;
}

function invalidNotificationInboxRequest(): NotificationInboxApiError {
  return new NotificationInboxApiError(
    400,
    "The notification inbox request was not accepted.",
    "invalid_request",
  );
}

function notificationInboxFallback(status: number): string {
  switch (status) {
    case 400:
      return "The notification inbox request was not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The personal notification inbox is not available for this tenant context.";
    case 404:
      return "The notification is no longer available.";
    case 409:
      return "This retry key conflicts with another notification change.";
    case 412:
      return "This notification changed. Reload the inbox before trying again.";
    case 428:
      return "The current notification version is required.";
    case 503:
      return "The notification inbox is temporarily unavailable.";
    default:
      return "The notification inbox request could not be completed.";
  }
}
