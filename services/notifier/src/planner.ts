import { createHash } from "node:crypto";

import {
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import {
  isContextObject,
  isAuthenticNotificationEvent,
  projectEventContext,
  type ContextValue,
  type NotificationAudience,
  type NotificationEvent,
} from "./event.js";
import {
  ruleMatches,
  isAuthenticNotificationRule,
  type NotificationRule,
  type QuietHours,
  type RecipientSelectorKind,
  type RetryPolicy,
} from "./rule.js";
import {
  canonicalEmail,
  requireInstant,
  requireKey,
  requireUuidV7,
} from "./validation.js";

const candidateRecipientKinds = new Set<RecipientSelectorKind>([
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
]);

export interface RecipientCandidateInput {
  tenantId: string;
  email: string;
  audience: NotificationAudience;
  kinds: readonly Exclude<
    RecipientSelectorKind,
    "explicit_email" | "custom_email_field"
  >[];
  values?: Readonly<Partial<Record<RecipientSelectorKind, readonly string[]>>>;
  principalId?: string;
  enabled: boolean;
  emailAllowed: boolean;
}

export interface PlannedRecipient {
  readonly email: string;
  readonly audience: NotificationAudience;
  readonly principalId?: string;
  readonly redactedEmail: string;
}

export interface NotificationPlan {
  readonly tenantId: string;
  readonly eventId: string;
  readonly ruleId: string;
  readonly ruleVersion: number;
  readonly templateId: string;
  readonly templateVersion: number;
  readonly channel: "email" | "webhook";
  readonly priority: number;
  readonly deliverAfter: Date;
  readonly recipients: readonly PlannedRecipient[];
  readonly contexts: Readonly<
    Record<NotificationAudience, Readonly<Record<string, ContextValue>>>
  >;
  readonly deduplicationKey: string;
  readonly groupingKey?: string;
}

interface CanonicalCandidate {
  readonly tenantId: string;
  readonly email: string;
  readonly audience: NotificationAudience;
  readonly kinds: ReadonlySet<RecipientSelectorKind>;
  readonly values: ReadonlyMap<RecipientSelectorKind, ReadonlySet<string>>;
  readonly principalId?: string;
  readonly enabled: boolean;
  readonly emailAllowed: boolean;
}

export function planNotification(
  rule: NotificationRule,
  event: NotificationEvent,
  candidateInputs: readonly RecipientCandidateInput[],
  plannedAt: Date,
): NotificationPlan | null {
  const now = requireInstant(plannedAt, "plannedAt");
  if (
    !isAuthenticNotificationRule(rule) ||
    !isAuthenticNotificationEvent(event)
  ) {
    throw new NotificationValidationError(
      "notification rule or event is not authentic",
    );
  }
  if (rule.tenantId !== event.tenantId) {
    throw new NotificationTenantBoundaryError();
  }
  if (now < event.occurredAt) {
    throw new NotificationValidationError(
      "a notification cannot be planned before its event",
    );
  }
  if (!ruleMatches(rule, event, event.occurredAt)) return null;
  const candidates = canonicalCandidates(candidateInputs, event.tenantId);
  const recipients = resolveRecipients(rule, event, candidates);
  if (recipients.length === 0) return null;

  let deliverAfter = requireInstant(
    new Date(
      Math.max(now.getTime(), event.occurredAt.getTime() + rule.delayMs),
    ),
    "deliverAfter",
  );
  if (rule.quietHours !== undefined) {
    deliverAfter = nextAllowedInstant(deliverAfter, rule.quietHours);
  }
  const deduplicationKey = planDigest(
    "dedup",
    rule,
    event,
    recipients,
    rule.deduplicationWindowMs,
    event.objectId,
  );
  const groupingKey =
    rule.grouping.mode === "none"
      ? undefined
      : planDigest(
          `group:${rule.grouping.mode}`,
          rule,
          event,
          recipients,
          rule.grouping.mode === "tenant"
            ? rule.grouping.windowMs
            : rule.grouping.windowMs,
          rule.grouping.mode === "tenant" ? undefined : event.objectId,
        );
  const audiences = new Set(recipients.map((recipient) => recipient.audience));
  const operatorContext = audiences.has("operator")
    ? projectEventContext(event, "operator")
    : Object.freeze({});
  const customerContext = audiences.has("customer")
    ? projectEventContext(event, "customer")
    : Object.freeze({});
  const deliverAfterEpoch = deliverAfter.getTime();
  return Object.freeze({
    tenantId: event.tenantId,
    eventId: event.id,
    ruleId: rule.id,
    ruleVersion: rule.version,
    templateId: rule.templateId,
    templateVersion: rule.templateVersion,
    channel: rule.channel,
    priority: rule.priority,
    get deliverAfter(): Date {
      return new Date(deliverAfterEpoch);
    },
    recipients,
    contexts: Object.freeze({
      operator: operatorContext,
      customer: customerContext,
    }),
    deduplicationKey,
    ...(groupingKey === undefined ? {} : { groupingKey }),
  });
}

export function nextRetryAt(
  policy: RetryPolicy,
  failedAttempt: number,
  failedAtInput: Date,
  stableJobId: string,
): Date | null {
  requireUuidV7(stableJobId, "job.id");
  const failedAt = requireInstant(failedAtInput, "failedAt");
  if (
    !Number.isInteger(failedAttempt) ||
    failedAttempt < 1 ||
    failedAttempt > policy.maximumAttempts
  ) {
    throw new NotificationValidationError(
      "failedAttempt is outside the retry policy",
    );
  }
  if (failedAttempt >= policy.maximumAttempts) return null;
  const exponential = Math.min(
    policy.maximumDelayMs,
    policy.initialDelayMs * policy.multiplier ** (failedAttempt - 1),
  );
  const random = deterministicFraction(stableJobId, failedAttempt);
  const jitter = exponential * (policy.jitterPercent / 100) * (2 * random - 1);
  return new Date(
    failedAt.getTime() + Math.max(1_000, Math.round(exponential + jitter)),
  );
}

export function nextAllowedInstant(input: Date, quietHours: QuietHours): Date {
  const start = requireInstant(input, "deliverAfter");
  if (!isQuiet(start, quietHours)) return start;
  const candidate = new Date(
    Math.floor(start.getTime() / 60_000) * 60_000 + 60_000,
  );
  for (let minute = 0; minute < 9 * 24 * 60; minute += 1) {
    if (!isQuiet(candidate, quietHours)) return candidate;
    candidate.setTime(candidate.getTime() + 60_000);
  }
  throw new NotificationValidationError(
    "quiet hours did not yield a bounded delivery instant",
  );
}

function canonicalCandidates(
  inputs: readonly RecipientCandidateInput[],
  tenantId: string,
): readonly CanonicalCandidate[] {
  if (inputs.length > 10_000) {
    throw new NotificationValidationError(
      "recipient candidate inventory is too large",
    );
  }
  return Object.freeze(
    inputs.map((input) => {
      if (input.tenantId !== tenantId)
        throw new NotificationTenantBoundaryError();
      requireUuidV7(input.tenantId, "candidate.tenantId");
      if (input.principalId !== undefined)
        requireUuidV7(input.principalId, "candidate.principalId");
      if (input.audience !== "operator" && input.audience !== "customer") {
        throw new NotificationValidationError(
          "candidate audience is unsupported",
        );
      }
      const kinds = new Set<RecipientSelectorKind>();
      for (const kind of input.kinds) {
        if (!candidateRecipientKinds.has(kind) || kinds.has(kind)) {
          throw new NotificationValidationError("candidate kinds are invalid");
        }
        kinds.add(kind);
      }
      const values = new Map<RecipientSelectorKind, ReadonlySet<string>>();
      for (const kindInput of Object.keys(input.values ?? {})) {
        const kind = input.kinds.find((candidate) => candidate === kindInput);
        const sourceValues: unknown = Reflect.get(
          input.values ?? {},
          kindInput,
        );
        if (
          kind === undefined ||
          !kinds.has(kind) ||
          !isStringArray(sourceValues) ||
          sourceValues.length === 0 ||
          sourceValues.length > 100
        ) {
          throw new NotificationValidationError(
            "candidate selector values are invalid",
          );
        }
        const canonical = new Set(
          sourceValues.map((value) =>
            requireKey(value, "candidate selector value"),
          ),
        );
        if (canonical.size !== sourceValues.length) {
          throw new NotificationValidationError(
            "candidate selector values must be unique",
          );
        }
        values.set(kind, canonical);
      }
      return Object.freeze({
        tenantId: input.tenantId,
        email: canonicalEmail(input.email, "candidate.email"),
        audience: input.audience,
        kinds,
        values,
        ...(input.principalId === undefined
          ? {}
          : { principalId: input.principalId }),
        enabled: input.enabled,
        emailAllowed: input.emailAllowed,
      });
    }),
  );
}

function resolveRecipients(
  rule: NotificationRule,
  event: NotificationEvent,
  candidates: readonly CanonicalCandidate[],
): readonly PlannedRecipient[] {
  const selected = new Map<string, PlannedRecipient>();
  const ambiguousPrincipals = new Set<string>();
  for (const selector of rule.recipients) {
    if (selector.kind === "explicit_email") {
      addRecipient(
        selected,
        ambiguousPrincipals,
        selector.value!,
        selector.audience,
        undefined,
        event,
      );
      continue;
    }
    if (selector.kind === "custom_email_field") {
      const value = readCustomEmail(
        projectEventContext(event, selector.audience),
        event.objectType,
        selector.value!,
      );
      if (value !== undefined)
        addRecipient(
          selected,
          ambiguousPrincipals,
          value,
          selector.audience,
          undefined,
          event,
        );
      continue;
    }
    for (const candidate of candidates) {
      if (
        !candidate.enabled ||
        !candidate.emailAllowed ||
        candidate.audience !== selector.audience ||
        !candidate.kinds.has(selector.kind)
      )
        continue;
      if (
        selector.value !== undefined &&
        !candidate.values.get(selector.kind)?.has(selector.value)
      ) {
        continue;
      }
      addRecipient(
        selected,
        ambiguousPrincipals,
        candidate.email,
        candidate.audience,
        candidate.principalId,
        event,
      );
    }
  }
  return Object.freeze(
    [...selected.values()].toSorted((left, right) =>
      left.email.localeCompare(right.email),
    ),
  );
}

function isStringArray(value: unknown): value is readonly string[] {
  return (
    Array.isArray(value) &&
    value.every((item: unknown) => typeof item === "string")
  );
}

function addRecipient(
  selected: Map<string, PlannedRecipient>,
  ambiguousPrincipals: Set<string>,
  emailInput: string,
  audience: NotificationAudience,
  principalId: string | undefined,
  event: NotificationEvent,
): void {
  if (event.maximumAudience === "operator" && audience === "customer") return;
  const email = canonicalEmail(emailInput);
  const existing = selected.get(email);
  if (
    existing !== undefined &&
    existing.audience === "operator" &&
    audience === "customer"
  )
    return;
  if (existing !== undefined && existing.audience === audience) {
    if (ambiguousPrincipals.has(email)) return;
    if (
      existing.principalId !== undefined &&
      principalId !== undefined &&
      existing.principalId !== principalId
    ) {
      ambiguousPrincipals.add(email);
      selected.set(
        email,
        Object.freeze({
          email,
          audience,
          redactedEmail: redactEmail(email),
        }),
      );
      return;
    }
    if (existing.principalId === undefined && principalId !== undefined) {
      selected.set(
        email,
        Object.freeze({
          email,
          audience,
          principalId,
          redactedEmail: redactEmail(email),
        }),
      );
    }
    return;
  }
  const recipient = Object.freeze({
    email,
    audience,
    ...(principalId === undefined ? {} : { principalId }),
    redactedEmail: redactEmail(email),
  });
  if (existing === undefined || audience === "operator") {
    ambiguousPrincipals.delete(email);
    selected.set(email, recipient);
  }
}

function readCustomEmail(
  context: Readonly<Record<string, ContextValue>>,
  objectType: NotificationEvent["objectType"],
  key: string,
): string | undefined {
  const object = context[objectType];
  if (!isContextObject(object)) return undefined;
  const custom = object.custom;
  if (!isContextObject(custom)) return undefined;
  const value = custom[key];
  return typeof value === "string"
    ? canonicalEmail(value, `custom field ${key}`)
    : undefined;
}

function redactEmail(email: string): string {
  const separator = email.lastIndexOf("@");
  const local = email.slice(0, separator);
  const domain = email.slice(separator + 1);
  return `${local.slice(0, 1)}***@${domain}`;
}

function isQuiet(instant: Date, quietHours: QuietHours): boolean {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: quietHours.timezone,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(instant);
  const weekdayName = parts.find((part) => part.type === "weekday")?.value;
  const hour = Number(parts.find((part) => part.type === "hour")?.value);
  const minute = Number(parts.find((part) => part.type === "minute")?.value);
  const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(
    weekdayName ?? "",
  );
  if (weekday < 0 || !Number.isInteger(hour) || !Number.isInteger(minute)) {
    throw new NotificationValidationError(
      "quiet-hours timezone could not be evaluated",
    );
  }
  const localMinute = hour * 60 + minute;
  if (quietHours.startMinute < quietHours.endMinute) {
    return (
      quietHours.weekdays.includes(weekday) &&
      localMinute >= quietHours.startMinute &&
      localMinute < quietHours.endMinute
    );
  }
  if (localMinute >= quietHours.startMinute) {
    return quietHours.weekdays.includes(weekday);
  }
  const previousWeekday = (weekday + 6) % 7;
  return (
    localMinute < quietHours.endMinute &&
    quietHours.weekdays.includes(previousWeekday)
  );
}

function planDigest(
  purpose: string,
  rule: NotificationRule,
  event: NotificationEvent,
  recipients: readonly PlannedRecipient[],
  windowMs: number,
  objectId: string | undefined,
): string {
  requireKey(purpose.replaceAll(":", "."), "digest purpose", 64);
  const bucket =
    windowMs === 0
      ? event.id
      : String(Math.floor(event.occurredAt.getTime() / windowMs));
  const hash = createHash("sha256");
  for (const value of [
    "periapsis:notification-plan:v1",
    purpose,
    rule.tenantId,
    rule.id,
    String(rule.version),
    event.type,
    objectId ?? "",
    bucket,
    ...recipients.map(
      (recipient) => `${recipient.audience}:${recipient.email}`,
    ),
  ]) {
    hash.update(value);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function deterministicFraction(stableJobId: string, attempt: number): number {
  const digest = createHash("sha256")
    .update(stableJobId)
    .update("\0")
    .update(String(attempt))
    .digest();
  return digest.readUInt32BE(0) / 0xffff_ffff;
}
