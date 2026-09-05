import type {
  NotificationCondition,
  NotificationRecipientSelector,
  NotificationRuleWrite,
  NotificationSampleData,
  NotificationTemplateWrite,
  SmtpConfiguration,
  SmtpConfigurationWriteWritable,
  WebhookConfigurationWriteWritable,
} from "@periapsis/contracts";

import { hasUnpairedSurrogate } from "../lib/canonical-display-name";
import { formatTenantInstant } from "../lib/tenant-date-time-context";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { hasControlCharacters } from "../lib/text-validation";
import { NotificationApiError } from "./notification-api";

export type NotificationPanel =
  "rules" | "templates" | "smtp" | "deliveries" | "webhooks" | "egress-policy";

export const tenantNotificationPermission = "notification.manage" as const;
export const platformNotificationPermission =
  "platform.notification.manage" as const;

export const tenantNotificationRouteDescriptor = {
  path: "/tenant/notifications",
  permission: tenantNotificationPermission,
  title: "Notifications",
} as const;

export const platformSmtpRouteDescriptor = {
  path: "/platform/notifications/smtp",
  permission: platformNotificationPermission,
  title: "Platform SMTP",
} as const;

export interface MutationAttemptReference extends IdempotencyReference {}

export interface OpaqueMutationAttemptReference {
  current: string | null;
}

export function bindMutationAttempt(
  reference: MutationAttemptReference,
  operation: string,
  tenantId: string | null,
  body: unknown,
): string {
  return idempotencyKeyForPayload(reference, { body, operation, tenantId });
}

export function resetMutationAttempt(
  reference: MutationAttemptReference,
): void {
  reference.current = null;
}

/** Keeps retry identity stable without retaining write-only material in a fingerprint. */
export function bindOpaqueMutationAttempt(
  reference: OpaqueMutationAttemptReference,
): string {
  reference.current ??= globalThis.crypto.randomUUID();
  return reference.current;
}

export function resetOpaqueMutationAttempt(
  reference: OpaqueMutationAttemptReference,
): void {
  reference.current = null;
}

export function parseSampleData(value: string): NotificationSampleData {
  const parsed: unknown = JSON.parse(value);
  assertBoundedJsonRecord(parsed, 0);
  return parsed;
}

export function parseCondition(value: string): NotificationCondition {
  const parsed: unknown = JSON.parse(value);
  return projectCondition(parsed, 0);
}

export function parseRecipients(
  value: string,
): NotificationRecipientSelector[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 50) {
    throw new TypeError(
      "Recipients must be a JSON array with 1 to 50 selectors.",
    );
  }
  return parsed.map(projectRecipient);
}

export const emptyRuleWrite: NotificationRuleWrite = {
  name: "",
  description: "",
  eventType: "alert.created",
  objectType: "alert",
  condition: { kind: "all", children: [] },
  recipients: [{ kind: "assignee", audience: "operator" }],
  templateId: "",
  templateVersion: 1,
  channel: "email",
  priority: 100,
  delayMs: 0,
  deduplicationWindowMs: 60_000,
  grouping: { mode: "object", windowMs: 60_000, maximumItems: 25 },
  retry: {
    maximumAttempts: 5,
    initialDelayMs: 30_000,
    maximumDelayMs: 3_600_000,
    multiplier: 2,
    jitterPercent: 10,
  },
  enabled: true,
  effectiveFrom: new Date(0).toISOString(),
};

export const emptyTemplateWrite: NotificationTemplateWrite = {
  key: "",
  name: "",
  language: "en",
  subject: "",
  html: "",
  plainText: "",
};

export const emptySmtpWrite: SmtpConfigurationWriteWritable = {
  name: "Tenant mail relay",
  host: "",
  port: 587,
  security: "starttls",
  username: null,
  clearPassword: false,
  fromName: "Periapsis",
  fromEmail: "",
  replyToEmail: null,
  timeoutMs: 10_000,
  maximumConnections: 4,
  maximumMessagesPerConnection: 100,
  rateLimitPerSecond: 10,
  clearDkim: false,
  enabled: true,
};

export const emptyWebhookWrite: WebhookConfigurationWriteWritable = {
  name: "",
  endpointUrl: "",
  eventTypes: ["alert.created"],
  audience: "operator",
  timeoutMs: 10_000,
  enabled: true,
};

export function smtpWriteFromProjection(
  value: SmtpConfiguration,
): SmtpConfigurationWriteWritable {
  return {
    name: value.name,
    host: value.host,
    port: value.port,
    security: value.security,
    username: value.username,
    clearPassword: false,
    fromName: value.fromName,
    fromEmail: value.fromEmail,
    replyToEmail: value.replyToEmail,
    timeoutMs: value.timeoutMs,
    maximumConnections: value.maximumConnections,
    maximumMessagesPerConnection: value.maximumMessagesPerConnection,
    rateLimitPerSecond: value.rateLimitPerSecond,
    ...(value.dkim
      ? {
          dkim: {
            domainName: value.dkim.domainName,
            selector: value.dkim.selector,
          },
        }
      : {}),
    clearDkim: false,
    enabled: value.enabled,
  };
}

export function forgetWriteOnlySmtp(
  value: SmtpConfigurationWriteWritable,
): SmtpConfigurationWriteWritable {
  const { password: _password, ...withoutPassword } = value;
  const dkim = withoutPassword.dkim;
  return {
    ...withoutPassword,
    ...(dkim
      ? {
          dkim: {
            domainName: dkim.domainName,
            selector: dkim.selector,
          },
        }
      : {}),
  };
}

export function forgetWriteOnlyWebhook(
  value: WebhookConfigurationWriteWritable,
): WebhookConfigurationWriteWritable {
  const { signingKey: _signingKey, ...safe } = value;
  return safe;
}

export function safeNotificationError(
  value: unknown,
  fallback: string,
): string {
  return value instanceof NotificationApiError ? value.message : fallback;
}

export function formatNotificationInstant(value: string | undefined): string {
  return formatTenantInstant(value);
}

export function compactNotificationId(value: string): string {
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function assertBoundedJsonRecord(
  value: unknown,
  depth: number,
): asserts value is NotificationSampleData {
  if (depth > 8 || !isRecord(value)) {
    throw new TypeError("JSON must be a bounded object.");
  }
  const entries = Object.entries(value);
  if (entries.length > 100) throw new TypeError("JSON contains too many keys.");
  for (const [key, item] of entries) {
    if (["__proto__", "constructor", "prototype"].includes(key)) {
      throw new TypeError("JSON contains an unsafe key.");
    }
    assertBoundedJsonValue(item, depth + 1);
  }
}

function assertBoundedJsonValue(value: unknown, depth: number): void {
  if (depth > 8) throw new TypeError("JSON is nested too deeply.");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value === "string" && value.length <= 10_000) return;
  if (Array.isArray(value)) {
    if (value.length > 100) throw new TypeError("JSON array is too large.");
    for (const item of value) assertBoundedJsonValue(item, depth + 1);
    return;
  }
  if (isRecord(value)) {
    assertBoundedJsonRecord(value, depth);
    return;
  }
  throw new TypeError("JSON contains an unsupported value.");
}

function projectCondition(
  value: unknown,
  depth: number,
): NotificationCondition {
  if (depth > 8 || !isRecord(value)) {
    throw new TypeError("Condition JSON must contain a supported kind.");
  }
  const kind = value["kind"];
  if (kind === "all" || kind === "any") {
    const children = value["children"];
    if (!Array.isArray(children) || children.length > 50) {
      throw new TypeError("Condition children must be a bounded array.");
    }
    return {
      kind,
      children: children.map((child) => projectCondition(child, depth + 1)),
    };
  }
  if (kind === "not") {
    const children = value["children"];
    if (!Array.isArray(children) || children.length !== 1) {
      throw new TypeError("A not condition requires exactly one child.");
    }
    return { kind, children: [projectCondition(children[0], depth + 1)] };
  }
  if (kind === "predicate") {
    const path = value["path"];
    const operator = value["operator"];
    const values = value["values"];
    if (
      typeof path !== "string" ||
      path.length === 0 ||
      path.length > 240 ||
      !isConditionOperator(operator) ||
      (values !== undefined &&
        (!Array.isArray(values) ||
          values.length > 50 ||
          !values.every(isConditionLiteral)))
    ) {
      throw new TypeError("Predicate condition fields are invalid.");
    }
    return {
      kind,
      path,
      operator,
      ...(values === undefined ? {} : { values }),
    };
  }
  throw new TypeError("Condition JSON must contain a supported kind.");
}

function projectRecipient(value: unknown): NotificationRecipientSelector {
  if (!isRecord(value)) throw new TypeError("Recipient selector is invalid.");
  const kind = value["kind"];
  const audience = value["audience"];
  const selectorValue = value["value"];
  const authorized = value["authorized"];
  const fixedAudience = operatorRecipientKinds.has(kind)
    ? "operator"
    : customerRecipientKinds.has(kind)
      ? "customer"
      : undefined;
  const requiresValue = valueRecipientKinds.has(kind);
  const isExplicitEmail = kind === "explicit_email";
  if (
    !isRecipientKind(kind) ||
    Object.keys(value).some(
      (key) => !["kind", "audience", "value", "authorized"].includes(key),
    ) ||
    (audience !== "operator" && audience !== "customer") ||
    (fixedAudience !== undefined && audience !== fixedAudience) ||
    requiresValue !== (selectorValue !== undefined) ||
    (selectorValue !== undefined && !isRecipientValue(selectorValue)) ||
    (isExplicitEmail &&
      (authorized !== true || !isCanonicalRecipientEmail(selectorValue))) ||
    (!isExplicitEmail && authorized !== undefined)
  ) {
    throw new TypeError("Recipient selector is invalid.");
  }
  return {
    kind,
    audience,
    ...(selectorValue === undefined ? {} : { value: selectorValue }),
    ...(authorized === true ? { authorized: true } : {}),
  };
}

function isConditionOperator(
  value: unknown,
): value is
  | "contains"
  | "equals"
  | "exists"
  | "none_of"
  | "not_equals"
  | "not_exists"
  | "one_of" {
  return typeof value === "string" && conditionOperators.has(value);
}

function isConditionLiteral(
  value: unknown,
): value is boolean | null | number | string {
  return (
    value === null ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value)) ||
    (typeof value === "string" && value.length <= 10_000)
  );
}

function isRecipientKind(
  value: unknown,
): value is NotificationRecipientSelector["kind"] {
  return typeof value === "string" && recipientKinds.has(value);
}

const conditionOperators: ReadonlySet<string> = new Set([
  "equals",
  "not_equals",
  "one_of",
  "none_of",
  "contains",
  "exists",
  "not_exists",
]);
const recipientKinds: ReadonlySet<string> = new Set([
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

const operatorRecipientKinds: ReadonlySet<unknown> = new Set([
  "assignee",
  "previous_assignee",
  "operator_team",
  "watcher",
  "mentioned",
  "tenant_admin",
  "platform_group",
]);

const customerRecipientKinds: ReadonlySet<unknown> = new Set([
  "customer_contacts",
  "contact_group",
  "contact_tag",
]);

const valueRecipientKinds: ReadonlySet<unknown> = new Set([
  "operator_team",
  "platform_group",
  "contact_group",
  "contact_tag",
  "explicit_email",
  "custom_email_field",
]);

function isRecipientValue(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    Array.from(value).length <= 320 &&
    !hasControlCharacters(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isCanonicalRecipientEmail(value: unknown): value is string {
  return (
    isRecipientValue(value) &&
    value === value.trim() &&
    !/[\s<>(),;:\\"[\]]/u.test(value) &&
    /^[^@]+@[^@]+\.[^@]+$/u.test(value)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
