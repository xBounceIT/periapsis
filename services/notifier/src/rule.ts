import { NotificationValidationError } from "./errors.js";
import {
  eventTypeSupportsObject,
  isAuthenticNotificationEvent,
  isContextObject,
  isNotificationEventType,
  type ContextValue,
  type NotificationAudience,
  type NotificationEvent,
  type NotificationEventType,
  type NotificationObjectType,
} from "./event.js";
import {
  canonicalEmail,
  exhaustive,
  requireInstant,
  requireInteger,
  requireText,
  requireUuidV7,
} from "./validation.js";

export type ConditionOperator =
  | "equals"
  | "not_equals"
  | "one_of"
  | "none_of"
  | "contains"
  | "exists"
  | "not_exists";

export type ConditionLiteral = string | number | boolean | null;

export type NotificationConditionInput =
  | { kind: "all" | "any"; children: readonly NotificationConditionInput[] }
  | { kind: "not"; children: readonly [NotificationConditionInput] }
  | {
      kind: "predicate";
      path: string;
      operator: ConditionOperator;
      values?: readonly ConditionLiteral[];
    };

export interface NotificationCondition {
  readonly kind: "all" | "any" | "not" | "predicate";
  readonly children: readonly NotificationCondition[];
  readonly path?: string;
  readonly operator?: ConditionOperator;
  readonly values: readonly ConditionLiteral[];
}

export type RecipientSelectorKind =
  | "assignee"
  | "previous_assignee"
  | "operator_team"
  | "watcher"
  | "mentioned"
  | "actor"
  | "tenant_admin"
  | "platform_group"
  | "customer_contacts"
  | "contact_group"
  | "contact_tag"
  | "explicit_email"
  | "custom_email_field";

export interface RecipientSelectorInput {
  kind: RecipientSelectorKind;
  value?: string;
  authorized?: boolean;
  audience?: NotificationAudience;
}

export interface RecipientSelector {
  readonly kind: RecipientSelectorKind;
  readonly value?: string;
  readonly audience: NotificationAudience;
}

export interface QuietHoursInput {
  timezone: string;
  startMinute: number;
  endMinute: number;
  weekdays?: readonly number[];
}

export interface QuietHours {
  readonly timezone: string;
  readonly startMinute: number;
  readonly endMinute: number;
  readonly weekdays: readonly number[];
}

export interface RetryPolicyInput {
  maximumAttempts: number;
  initialDelayMs: number;
  maximumDelayMs: number;
  multiplier: number;
  jitterPercent: number;
}

export interface RetryPolicy extends RetryPolicyInput {}

export interface GroupingPolicyInput {
  mode: "none" | "object" | "tenant";
  windowMs?: number;
  maximumItems?: number;
}

export interface GroupingPolicy {
  readonly mode: "none" | "object" | "tenant";
  readonly windowMs: number;
  readonly maximumItems: number;
}

export interface NotificationRuleInput {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  eventType: NotificationEventType;
  objectType: NotificationObjectType;
  condition: NotificationConditionInput;
  recipients: readonly RecipientSelectorInput[];
  templateId: string;
  templateVersion: number;
  channel: "email" | "webhook";
  priority: number;
  delayMs: number;
  quietHours?: QuietHoursInput;
  deduplicationWindowMs: number;
  grouping: GroupingPolicyInput;
  retry: RetryPolicyInput;
  enabled: boolean;
  version: number;
  effectiveFrom: Date;
  effectiveUntil?: Date;
}

export interface NotificationRule {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly description: string;
  readonly eventType: NotificationEventType;
  readonly objectType: NotificationObjectType;
  readonly condition: NotificationCondition;
  readonly recipients: readonly RecipientSelector[];
  readonly templateId: string;
  readonly templateVersion: number;
  readonly channel: "email" | "webhook";
  readonly priority: number;
  readonly delayMs: number;
  readonly quietHours?: QuietHours;
  readonly deduplicationWindowMs: number;
  readonly grouping: GroupingPolicy;
  readonly retry: RetryPolicy;
  readonly enabled: boolean;
  readonly version: number;
  readonly effectiveFrom: Date;
  readonly effectiveUntil?: Date;
}

const objectTypes = new Set<string>([
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
]);
const recipientKinds = new Set<string>([
  "assignee",
  "previous_assignee",
  "operator_team",
  "watcher",
  "mentioned",
  "actor",
  "tenant_admin",
  "platform_group",
  "customer_contacts",
  "contact_group",
  "contact_tag",
  "explicit_email",
  "custom_email_field",
]);
const authenticNotificationRules = new WeakSet<object>();

export function createNotificationRule(
  input: NotificationRuleInput,
): NotificationRule {
  requireUuidV7(input.id, "rule.id");
  requireUuidV7(input.tenantId, "rule.tenantId");
  requireUuidV7(input.templateId, "rule.templateId");
  requireText(input.name, "rule.name", 160);
  requireText(input.description, "rule.description", 2_048, {
    allowEmpty: true,
    allowNewlines: true,
  });
  if (
    !isNotificationEventType(input.eventType) ||
    !objectTypes.has(input.objectType) ||
    !eventTypeSupportsObject(input.eventType, input.objectType)
  ) {
    throw new NotificationValidationError(
      "rule event or object type is unsupported",
    );
  }
  const condition = createCondition(input.condition);
  const recipients = canonicalRecipients(input.recipients);
  const quietHours =
    input.quietHours === undefined
      ? undefined
      : canonicalQuietHours(input.quietHours);
  const grouping = canonicalGrouping(input.grouping);
  const retry = createRetryPolicy(input.retry);
  const effectiveFrom = requireInstant(
    input.effectiveFrom,
    "rule.effectiveFrom",
  );
  const effectiveUntil =
    input.effectiveUntil === undefined
      ? undefined
      : requireInstant(input.effectiveUntil, "rule.effectiveUntil");
  if (effectiveUntil !== undefined && effectiveUntil <= effectiveFrom) {
    throw new NotificationValidationError(
      "rule effective window must be non-empty",
    );
  }
  if (input.channel !== "email" && input.channel !== "webhook") {
    throw new NotificationValidationError("rule channel is unsupported");
  }
  requireInteger(
    input.templateVersion,
    "rule.templateVersion",
    1,
    2_147_483_647,
  );
  requireInteger(input.priority, "rule.priority", 0, 100);
  requireInteger(input.delayMs, "rule.delayMs", 0, 30 * 24 * 60 * 60 * 1_000);
  requireInteger(
    input.deduplicationWindowMs,
    "rule.deduplicationWindowMs",
    0,
    30 * 24 * 60 * 60 * 1_000,
  );
  requireInteger(input.version, "rule.version", 1, 2_147_483_647);
  const effectiveFromEpoch = effectiveFrom.getTime();
  const effectiveUntilEpoch = effectiveUntil?.getTime();
  const rule = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    name: input.name,
    description: input.description,
    eventType: input.eventType,
    objectType: input.objectType,
    condition,
    recipients,
    templateId: input.templateId,
    templateVersion: input.templateVersion,
    channel: input.channel,
    priority: input.priority,
    delayMs: input.delayMs,
    ...(quietHours === undefined ? {} : { quietHours }),
    deduplicationWindowMs: input.deduplicationWindowMs,
    grouping,
    retry,
    enabled: input.enabled,
    version: input.version,
    get effectiveFrom(): Date {
      return new Date(effectiveFromEpoch);
    },
    ...(effectiveUntilEpoch === undefined
      ? {}
      : {
          get effectiveUntil(): Date {
            return new Date(effectiveUntilEpoch);
          },
        }),
  });
  authenticNotificationRules.add(rule);
  return rule;
}

export function isAuthenticNotificationRule(rule: NotificationRule): boolean {
  return (
    rule !== null &&
    typeof rule === "object" &&
    authenticNotificationRules.has(rule)
  );
}

export function ruleMatches(
  rule: NotificationRule,
  event: NotificationEvent,
  at: Date,
): boolean {
  if (
    !isAuthenticNotificationRule(rule) ||
    !isAuthenticNotificationEvent(event) ||
    !(at instanceof Date) ||
    !Number.isFinite(at.getTime())
  )
    return false;
  if (
    !rule.enabled ||
    rule.tenantId !== event.tenantId ||
    rule.eventType !== event.type ||
    rule.objectType !== event.objectType ||
    at < rule.effectiveFrom ||
    (rule.effectiveUntil !== undefined && at >= rule.effectiveUntil)
  ) {
    return false;
  }
  return evaluateCondition(rule.condition, event);
}

export function createCondition(
  input: NotificationConditionInput,
): NotificationCondition {
  const budget = { count: 0 };
  return canonicalCondition(input, 0, budget, new WeakSet<object>());
}

function canonicalCondition(
  input: NotificationConditionInput,
  depth: number,
  budget: { count: number },
  active: WeakSet<object>,
): NotificationCondition {
  budget.count += 1;
  if (
    input === null ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    budget.count > 256 ||
    depth > 12 ||
    active.has(input)
  ) {
    throw new NotificationValidationError(
      "rule condition exceeds structural limits",
    );
  }
  active.add(input);
  try {
    if (input.kind === "all" || input.kind === "any" || input.kind === "not") {
      const expected = input.kind === "not" ? 1 : undefined;
      if (
        !Array.isArray(input.children) ||
        input.children.length > 64 ||
        (expected === undefined &&
          input.kind === "any" &&
          input.children.length === 0) ||
        (expected !== undefined && input.children.length !== expected)
      ) {
        throw new NotificationValidationError(
          "rule condition has invalid children",
        );
      }
      const children = input.children.map((child) =>
        canonicalCondition(child, depth + 1, budget, active),
      );
      return Object.freeze({
        kind: input.kind,
        children: Object.freeze(children),
        values: Object.freeze([]),
      });
    }
    if (input.kind !== "predicate") {
      throw new NotificationValidationError(
        "rule condition kind is unsupported",
      );
    }
    const path = canonicalConditionPath(input.path);
    const values = canonicalConditionValues(input.operator, input.values ?? []);
    return Object.freeze({
      kind: "predicate",
      children: Object.freeze([]),
      path,
      operator: input.operator,
      values,
    });
  } finally {
    active.delete(input);
  }
}

function canonicalConditionPath(input: string): string {
  requireText(input, "condition.path", 256);
  const segments = input.split(".");
  if (
    segments.length < 2 ||
    segments.length > 10 ||
    ![
      "event",
      "tenant",
      "alert",
      "case",
      "actor",
      "assignee",
      "operatorTeam",
      "contact",
      "comment",
      "sla",
      "task",
      "evidence",
    ].includes(segments[0] ?? "") ||
    !segments.every(
      (segment) =>
        /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(segment) &&
        !["constructor", "prototype", "__proto__"].includes(segment),
    )
  ) {
    throw new NotificationValidationError("condition.path is not allowlisted");
  }
  return input;
}

function canonicalConditionValues(
  operator: ConditionOperator,
  input: readonly ConditionLiteral[],
): readonly ConditionLiteral[] {
  const noValues = operator === "exists" || operator === "not_exists";
  const oneValue =
    operator === "equals" ||
    operator === "not_equals" ||
    operator === "contains";
  const manyValues = operator === "one_of" || operator === "none_of";
  if (
    (!noValues && !oneValue && !manyValues) ||
    (noValues && input.length !== 0) ||
    (oneValue && input.length !== 1) ||
    (manyValues && (input.length === 0 || input.length > 100))
  ) {
    throw new NotificationValidationError(
      "condition predicate has invalid values",
    );
  }
  const seen = new Set<string>();
  const result = input.map((value) => {
    if (
      typeof value === "number" &&
      (!Number.isFinite(value) || Object.is(value, -0))
    ) {
      throw new NotificationValidationError(
        "condition contains a non-canonical number",
      );
    }
    if (typeof value === "string") {
      requireText(value, "condition value", 2_048, { allowEmpty: true });
    }
    const encoded = `${typeof value}:${String(value)}`;
    if (seen.has(encoded)) {
      throw new NotificationValidationError(
        "condition contains duplicate values",
      );
    }
    seen.add(encoded);
    return value;
  });
  return Object.freeze(result);
}

function evaluateCondition(
  condition: NotificationCondition,
  event: NotificationEvent,
): boolean {
  switch (condition.kind) {
    case "all":
      return condition.children.every((child) =>
        evaluateCondition(child, event),
      );
    case "any":
      return condition.children.some((child) =>
        evaluateCondition(child, event),
      );
    case "not":
      return !evaluateCondition(condition.children[0]!, event);
    case "predicate": {
      const actual = readConditionPath(condition.path!, event);
      const expected = condition.values;
      switch (condition.operator) {
        case "exists":
          return actual !== undefined && actual !== null;
        case "not_exists":
          return actual === undefined || actual === null;
        case "equals":
          return scalarEquals(actual, expected[0]);
        case "not_equals":
          return (
            actual !== undefined &&
            actual !== null &&
            !scalarEquals(actual, expected[0])
          );
        case "one_of":
          return expected.some((value) => scalarEquals(actual, value));
        case "none_of":
          return (
            actual !== undefined &&
            actual !== null &&
            expected.every((value) => !scalarEquals(actual, value))
          );
        case "contains":
          return Array.isArray(actual)
            ? actual.some((value) => scalarEquals(value, expected[0]))
            : typeof actual === "string" &&
                typeof expected[0] === "string" &&
                actual.includes(expected[0]);
        default:
          return false;
      }
    }
    default:
      return exhaustive(condition.kind);
  }
}

function readConditionPath(
  path: string,
  event: NotificationEvent,
): ContextValue | undefined {
  if (path === "event.type") return event.type;
  if (path === "event.objectType") return event.objectType;
  if (path === "event.source") return event.source;
  const segments = path.split(".");
  let value: ContextValue | undefined = event.context;
  for (const segment of segments) {
    if (!isContextObject(value)) return undefined;
    value = Object.prototype.hasOwnProperty.call(value, segment)
      ? value[segment]
      : undefined;
  }
  return value;
}

function scalarEquals(
  actual: ContextValue | undefined,
  expected: ConditionLiteral | undefined,
): boolean {
  return (
    (actual === null ||
      typeof actual === "string" ||
      typeof actual === "number" ||
      typeof actual === "boolean") &&
    actual === expected
  );
}

function canonicalRecipients(
  inputs: readonly RecipientSelectorInput[],
): readonly RecipientSelector[] {
  if (inputs.length === 0 || inputs.length > 32) {
    throw new NotificationValidationError(
      "rule must have between one and 32 recipient selectors",
    );
  }
  const result: RecipientSelector[] = [];
  const seen = new Set<string>();
  for (const input of inputs) {
    if (!recipientKinds.has(input.kind)) {
      throw new NotificationValidationError(
        "recipient selector kind is unsupported",
      );
    }
    const wantsValue = [
      "operator_team",
      "platform_group",
      "contact_group",
      "contact_tag",
      "custom_email_field",
    ].includes(input.kind);
    const wantsEmail = input.kind === "explicit_email";
    const wantsNoValue = !wantsValue && !wantsEmail;
    const audience = canonicalRecipientAudience(input.kind, input.audience);
    if (
      (wantsNoValue && input.value !== undefined) ||
      (!wantsNoValue && input.value === undefined) ||
      (wantsEmail && input.authorized !== true) ||
      (!wantsEmail && input.authorized !== undefined)
    ) {
      throw new NotificationValidationError(
        "recipient selector has an invalid shape",
      );
    }
    const value =
      input.value === undefined
        ? undefined
        : wantsEmail
          ? canonicalEmail(input.value, "recipient explicit email")
          : requireText(input.value, "recipient selector value", 320);
    const fingerprint = `${input.kind}\u0000${value ?? ""}\u0000${audience}`;
    if (seen.has(fingerprint)) {
      throw new NotificationValidationError(
        "recipient selectors must be unique",
      );
    }
    seen.add(fingerprint);
    result.push(
      Object.freeze({
        kind: input.kind,
        ...(value === undefined ? {} : { value }),
        audience,
      }),
    );
  }
  return Object.freeze(result);
}

function canonicalRecipientAudience(
  kind: RecipientSelectorKind,
  input: NotificationAudience | undefined,
): NotificationAudience {
  const fixed = operatorRecipientKinds.has(kind)
    ? "operator"
    : customerRecipientKinds.has(kind)
      ? "customer"
      : undefined;
  const audience = input ?? fixed;
  if (
    (audience !== "operator" && audience !== "customer") ||
    (fixed !== undefined && audience !== fixed)
  ) {
    throw new NotificationValidationError(
      "recipient selector has an invalid audience",
    );
  }
  return audience;
}

const operatorRecipientKinds = new Set<RecipientSelectorKind>([
  "assignee",
  "previous_assignee",
  "operator_team",
  "watcher",
  "mentioned",
  "tenant_admin",
  "platform_group",
]);

const customerRecipientKinds = new Set<RecipientSelectorKind>([
  "customer_contacts",
  "contact_group",
  "contact_tag",
]);

function canonicalQuietHours(input: QuietHoursInput): QuietHours {
  requireText(input.timezone, "quietHours.timezone", 128);
  if (input.timezone !== "UTC" && !input.timezone.includes("/")) {
    throw new NotificationValidationError(
      "quietHours.timezone must be an unambiguous IANA timezone",
    );
  }
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: input.timezone }).format(
      new Date(0),
    );
  } catch {
    throw new NotificationValidationError(
      "quietHours.timezone must be an IANA timezone",
    );
  }
  requireInteger(input.startMinute, "quietHours.startMinute", 0, 1_439);
  requireInteger(input.endMinute, "quietHours.endMinute", 0, 1_439);
  if (input.startMinute === input.endMinute) {
    throw new NotificationValidationError(
      "quiet hours cannot cover an ambiguous full day",
    );
  }
  const weekdays = [...(input.weekdays ?? [0, 1, 2, 3, 4, 5, 6])].toSorted(
    (left, right) => left - right,
  );
  if (
    weekdays.length === 0 ||
    weekdays.length > 7 ||
    weekdays.some(
      (value, index) =>
        !Number.isInteger(value) ||
        value < 0 ||
        value > 6 ||
        value === weekdays[index - 1],
    )
  ) {
    throw new NotificationValidationError("quietHours.weekdays is invalid");
  }
  return Object.freeze({ ...input, weekdays: Object.freeze(weekdays) });
}

function canonicalGrouping(input: GroupingPolicyInput): GroupingPolicy {
  if (input.mode === "none") {
    if (input.windowMs !== undefined || input.maximumItems !== undefined) {
      throw new NotificationValidationError(
        "ungrouped rules cannot define a grouping window",
      );
    }
    return Object.freeze({ mode: "none", windowMs: 0, maximumItems: 1 });
  }
  if (input.mode !== "object" && input.mode !== "tenant") {
    throw new NotificationValidationError("grouping mode is unsupported");
  }
  const windowMs = requireInteger(
    input.windowMs ?? 0,
    "grouping.windowMs",
    1_000,
    24 * 60 * 60 * 1_000,
  );
  const maximumItems = requireInteger(
    input.maximumItems ?? 0,
    "grouping.maximumItems",
    2,
    1_000,
  );
  return Object.freeze({ mode: input.mode, windowMs, maximumItems });
}

export function createRetryPolicy(input: RetryPolicyInput): RetryPolicy {
  requireInteger(input.maximumAttempts, "retry.maximumAttempts", 1, 32);
  requireInteger(
    input.initialDelayMs,
    "retry.initialDelayMs",
    1_000,
    24 * 60 * 60 * 1_000,
  );
  requireInteger(
    input.maximumDelayMs,
    "retry.maximumDelayMs",
    input.initialDelayMs,
    30 * 24 * 60 * 60 * 1_000,
  );
  if (
    !Number.isFinite(input.multiplier) ||
    input.multiplier < 1 ||
    input.multiplier > 10
  ) {
    throw new NotificationValidationError(
      "retry.multiplier is outside its supported range",
    );
  }
  requireInteger(input.jitterPercent, "retry.jitterPercent", 0, 100);
  return Object.freeze({ ...input });
}
