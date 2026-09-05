import { NotificationValidationError } from "./errors.js";
import {
  requireInstant,
  requireKey,
  requireText,
  requireUuidV7,
} from "./validation.js";
import {
  canonicalPersistedTraceContext,
  type PersistedTraceContext,
} from "./telemetry.js";

export const notificationEventTypes = [
  "alert.created",
  "alert.assigned",
  "alert.claimed",
  "alert.status_changed",
  "alert.escalated",
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.created",
  "case.assigned",
  "case.claimed",
  "case.transferred",
  "case.status_changed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.public_added",
  "comment.private_added",
  "contact.changed",
  "sla.warning",
  "sla.breached",
  "task.assigned",
  "evidence.added",
  "webhook.custom",
] as const;

export type NotificationEventType = (typeof notificationEventTypes)[number];
export type NotificationObjectType =
  "alert" | "case" | "task" | "evidence" | "contact";
export type NotificationAudience = "operator" | "customer";
export type NotificationActorKind = "human" | "service_account" | "system";

export type ContextValue =
  | string
  | number
  | boolean
  | null
  | readonly ContextValue[]
  | Readonly<{ [key: string]: ContextValue }>;

export function isContextObject(
  value: unknown,
): value is Readonly<Record<string, ContextValue>> {
  return (
    value !== null &&
    value !== undefined &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

export interface NotificationEventInput {
  id: string;
  tenantId: string;
  type: NotificationEventType;
  objectType: NotificationObjectType;
  objectId: string;
  objectVersion: number;
  occurredAt: Date;
  actorKind: NotificationActorKind;
  actorId?: string;
  source: string;
  context: Readonly<Record<string, ContextValue>>;
  maximumAudience: NotificationAudience;
  traceContext?: PersistedTraceContext;
}

export interface NotificationEvent {
  readonly id: string;
  readonly tenantId: string;
  readonly type: NotificationEventType;
  readonly objectType: NotificationObjectType;
  readonly objectId: string;
  readonly objectVersion: number;
  readonly occurredAt: Date;
  readonly actorKind: NotificationActorKind;
  readonly actorId?: string;
  readonly source: string;
  readonly context: Readonly<Record<string, ContextValue>>;
  readonly maximumAudience: NotificationAudience;
  readonly traceContext?: PersistedTraceContext;
}

const eventTypeSet = new Set<string>(notificationEventTypes);
const operatorOnlyEventTypeSet = new Set<NotificationEventType>([
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.private_added",
]);
const objectTypeSet = new Set<string>([
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
]);
const authenticNotificationEvents = new WeakSet<object>();

export function createNotificationEvent(
  input: NotificationEventInput,
): NotificationEvent {
  requireUuidV7(input.id, "event.id");
  requireUuidV7(input.tenantId, "event.tenantId");
  requireUuidV7(input.objectId, "event.objectId");
  if (input.actorId !== undefined) {
    requireUuidV7(input.actorId, "event.actorId");
  }
  if (
    !Number.isSafeInteger(input.objectVersion) ||
    input.objectVersion < 1 ||
    input.objectVersion > 2_147_483_647 ||
    !["human", "service_account", "system"].includes(input.actorKind) ||
    (input.actorKind === "system") !== (input.actorId === undefined) ||
    (input.maximumAudience !== "operator" &&
      input.maximumAudience !== "customer") ||
    (isOperatorOnlyNotificationEventType(input.type) &&
      input.maximumAudience !== "operator")
  ) {
    throw new NotificationValidationError(
      "event version, actor, or audience is unsupported",
    );
  }
  if (
    !isNotificationEventType(input.type) ||
    !objectTypeSet.has(input.objectType)
  ) {
    throw new NotificationValidationError(
      "event type or object type is unsupported",
    );
  }
  if (!eventTypeSupportsObject(input.type, input.objectType)) {
    throw new NotificationValidationError(
      "event type does not match its object type",
    );
  }
  const occurredAt = requireInstant(input.occurredAt, "event.occurredAt");
  const occurredAtEpoch = occurredAt.getTime();
  const source = requireKey(input.source, "event.source");
  const context = canonicalizeNotificationContext(input.context);
  const traceContext =
    input.traceContext === undefined
      ? undefined
      : canonicalPersistedTraceContext(input.traceContext);
  const hasCustomerProjection = isContextObject(context.customer);
  if (
    (input.maximumAudience === "customer" && !hasCustomerProjection) ||
    (input.maximumAudience === "operator" && Object.hasOwn(context, "customer"))
  ) {
    throw new NotificationValidationError(
      "event context does not match its maximum audience",
    );
  }
  const event = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    type: input.type,
    objectType: input.objectType,
    objectId: input.objectId,
    objectVersion: input.objectVersion,
    get occurredAt(): Date {
      return new Date(occurredAtEpoch);
    },
    actorKind: input.actorKind,
    ...(input.actorId === undefined ? {} : { actorId: input.actorId }),
    source,
    context,
    maximumAudience: input.maximumAudience,
    ...(traceContext === undefined ? {} : { traceContext }),
  });
  authenticNotificationEvents.add(event);
  return event;
}

export function isAuthenticNotificationEvent(
  event: NotificationEvent,
): boolean {
  return (
    event !== null &&
    typeof event === "object" &&
    authenticNotificationEvents.has(event)
  );
}

export function isNotificationEventType(
  value: unknown,
): value is NotificationEventType {
  return typeof value === "string" && eventTypeSet.has(value);
}

export function isOperatorOnlyNotificationEventType(value: unknown): boolean {
  return isNotificationEventType(value) && operatorOnlyEventTypeSet.has(value);
}

export function eventTypeSupportsObject(
  type: NotificationEventType,
  objectType: NotificationObjectType,
): boolean {
  const prefix = type.split(".", 1)[0];
  return !(
    (prefix === "alert" && objectType !== "alert") ||
    (prefix === "case" && objectType !== "case") ||
    (prefix === "task" && objectType !== "task") ||
    (prefix === "evidence" && objectType !== "evidence") ||
    (prefix === "contact" && objectType !== "contact") ||
    (prefix === "comment" && objectType !== "alert" && objectType !== "case") ||
    (prefix === "sla" &&
      objectType !== "alert" &&
      objectType !== "case" &&
      objectType !== "task")
  );
}

export function canonicalizeNotificationContext(
  input: unknown,
): Readonly<Record<string, ContextValue>> {
  if (!isUnknownRecord(input)) {
    throw new NotificationValidationError("event.context must be an object");
  }
  const budget = { nodes: 0, text: 0 };
  const active = new WeakSet<object>();
  const result = canonicalObject(input, 0, budget, active);
  if (budget.nodes > 4_096 || budget.text > 256 * 1_024) {
    throw new NotificationValidationError(
      "event.context exceeds its size limit",
    );
  }
  return result;
}

function isUnknownRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalValue(
  input: unknown,
  depth: number,
  budget: { nodes: number; text: number },
  active: WeakSet<object>,
): ContextValue {
  budget.nodes += 1;
  if (budget.nodes > 4_096 || depth > 8) {
    throw new NotificationValidationError(
      "event.context exceeds its structural limit",
    );
  }
  if (input === null || typeof input === "boolean") {
    return input;
  }
  if (typeof input === "number") {
    if (!Number.isFinite(input) || Object.is(input, -0)) {
      throw new NotificationValidationError(
        "event.context contains a non-canonical number",
      );
    }
    return input;
  }
  if (typeof input === "string") {
    const value = requireText(input, "event.context value", 8_192, {
      allowEmpty: true,
      allowNewlines: true,
    });
    budget.text += value.length;
    return value;
  }
  if (typeof input !== "object") {
    throw new NotificationValidationError(
      "event.context contains an unsupported value",
    );
  }
  if (active.has(input)) {
    throw new NotificationValidationError("event.context contains a cycle");
  }
  active.add(input);
  try {
    if (Array.isArray(input)) {
      return canonicalArray(input, depth + 1, budget, active);
    }
    if (isContextObject(input)) {
      return canonicalObject(input, depth + 1, budget, active);
    }
    throw new NotificationValidationError(
      "event.context contains an unsupported object",
    );
  } finally {
    active.delete(input);
  }
}

function canonicalObject(
  input: Readonly<Record<string, unknown>>,
  depth: number,
  budget: { nodes: number; text: number },
  active: WeakSet<object>,
): Readonly<Record<string, ContextValue>> {
  const prototype = Object.getPrototypeOf(input) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new NotificationValidationError(
      "event.context must contain plain objects only",
    );
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.length > 100 || ownKeys.some((key) => typeof key !== "string")) {
    throw new NotificationValidationError("event.context object is too large");
  }
  const keys = ownKeys
    .filter((key): key is string => typeof key === "string")
    .toSorted((left, right) => left.localeCompare(right));
  const output: Record<string, ContextValue> = {};
  for (const key of keys) {
    if (
      !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(key) ||
      ["constructor", "prototype", "__proto__"].includes(key)
    ) {
      throw new NotificationValidationError(
        "event.context contains an unsafe key",
      );
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      throw new NotificationValidationError(
        "event.context contains an accessor or hidden property",
      );
    }
    budget.text += key.length;
    output[key] = canonicalValue(descriptor.value, depth, budget, active);
  }
  return Object.freeze(output);
}

function canonicalArray(
  input: readonly unknown[],
  depth: number,
  budget: { nodes: number; text: number },
  active: WeakSet<object>,
): readonly ContextValue[] {
  if (Object.getPrototypeOf(input) !== Array.prototype || input.length > 100) {
    throw new NotificationValidationError("event.context array is too large");
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== input.length + 1 ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)),
    )
  ) {
    throw new NotificationValidationError(
      "event.context array has hidden or extra properties",
    );
  }
  const output: ContextValue[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !("value" in descriptor)
    ) {
      throw new NotificationValidationError(
        "event.context array is sparse or contains an accessor",
      );
    }
    output.push(canonicalValue(descriptor.value, depth, budget, active));
  }
  return Object.freeze(output);
}

export function projectEventContext(
  event: NotificationEvent,
  audience: NotificationAudience,
): Readonly<Record<string, ContextValue>> {
  if (!isAuthenticNotificationEvent(event)) {
    throw new NotificationValidationError("event is not authentic");
  }
  if (audience !== "operator" && audience !== "customer") {
    throw new NotificationValidationError("event audience is unsupported");
  }
  if (audience === "customer" && event.maximumAudience === "operator") {
    throw new NotificationValidationError(
      "operator-only event context cannot be projected to customers",
    );
  }
  if (audience === "operator") {
    return event.context;
  }
  const customer = event.context.customer;
  if (!isContextObject(customer)) {
    throw new NotificationValidationError(
      "customer-safe event projection is missing",
    );
  }
  return customer;
}
