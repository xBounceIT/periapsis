export type SlaObjectType = "alert" | "case";
export type SlaMetricState =
  "pending" | "on_track" | "at_risk" | "paused" | "breached" | "completed";

export type CalendarWeekday =
  | "sunday"
  | "monday"
  | "tuesday"
  | "wednesday"
  | "thursday"
  | "friday"
  | "saturday";

export interface CalendarInterval {
  endMinute: number;
  startMinute: number;
}

export interface CalendarException {
  closed: boolean;
  date: string;
  intervals: CalendarInterval[];
}

export interface CalendarDaySchedule {
  intervals: CalendarInterval[];
  weekday: CalendarWeekday;
}

export interface BusinessCalendarWrite {
  id: string;
  key: string;
  label: string;
  timezone: string;
  weeklySchedules: CalendarDaySchedule[];
  exceptions: CalendarException[];
}

export interface BusinessCalendar extends BusinessCalendarWrite {
  tenantId: string;
  version: number;
  resourceVersion: number;
  revisionDigest: string;
  archivedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export type SlaFactKind =
  | "customer_tier"
  | "object_type"
  | "severity"
  | "priority"
  | "category"
  | "source"
  | "operator_team"
  | "tag"
  | "custom_field"
  | "local_hour"
  | "local_weekday"
  | "customer_contact_class";

export interface SlaFactPath {
  kind: SlaFactKind;
  key?: string | undefined;
}

export type SlaPredicateOperator =
  "equals" | "not_equals" | "one_of" | "none_of" | "exists" | "not_exists";

export type SlaMatchExpression =
  | {
      kind: "all" | "any";
      children: SlaMatchExpression[];
    }
  | {
      kind: "not";
      children: [SlaMatchExpression];
    }
  | {
      kind: "predicate";
      predicate: {
        path: SlaFactPath;
        operator: SlaPredicateOperator;
        values: string[];
      };
    };

export type SlaMetricWarning =
  | { kind: "none" }
  | { kind: "consumed_percent"; consumedPercent: number }
  | { kind: "remaining_duration"; remainingMicros: number };

export interface SlaMetricWrite {
  id: string;
  key: string;
  label: string;
  description: string;
  durationMicros: number;
  clock: "elapsed" | "business";
  calendarId?: string | undefined;
  calendarVersion?: number | undefined;
  startEvent: string;
  pauseEvent?: string | undefined;
  resumeEvent?: string | undefined;
  completionEvent: string;
  resetEvent?: string | undefined;
  resetPolicy: "ignore" | "clear" | "restart";
  warning: SlaMetricWarning;
  breachGraceMicros: number;
  displayFormat: string;
  customerVisible: boolean;
  apiVisible: boolean;
}

export type SlaTriggerAction =
  | {
      kind: "email" | "webhook" | "assign_operator_team";
      configurationId: string;
    }
  | {
      kind: "add_tag" | "change_priority" | "domain_event";
      value: string;
    }
  | { kind: "create_task"; text: string }
  | {
      kind: "create_system_alert";
      value: string;
      allowRecursiveSla: boolean;
    };

export interface SlaTriggerWrite {
  id: string;
  metricDefinitionId: string;
  key: string;
  kind:
    | "consumed_percent"
    | "remaining_duration"
    | "due"
    | "after_breach"
    | "repeated_after_breach"
    | "state_changed"
    | "resumed";
  consumedPercent?: number | undefined;
  remainingMicros?: number | undefined;
  offsetMicros?: number | undefined;
  repeatIntervalMicros?: number | undefined;
  targetState?: SlaMetricState | undefined;
  action: SlaTriggerAction;
}

export interface SlaPolicyWrite {
  id: string;
  key: string;
  name: string;
  description: string;
  objectTypes: SlaObjectType[];
  priority: number;
  matchRule: SlaMatchExpression;
  metrics: SlaMetricWrite[];
  triggers: SlaTriggerWrite[];
  effectiveFrom: string;
  effectiveUntil?: string | undefined;
  enabled: boolean;
  applyToSlaEngineSource: boolean;
}

export interface SlaMetricDefinition extends SlaMetricWrite {
  position: number;
}

export interface SlaTriggerDefinition extends SlaTriggerWrite {
  position: number;
}

export interface SlaPolicy extends Omit<
  SlaPolicyWrite,
  "metrics" | "triggers"
> {
  tenantId: string;
  metrics: SlaMetricDefinition[];
  triggers: SlaTriggerDefinition[];
  version: number;
  resourceVersion: number;
  revisionDigest: string;
  archivedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export type SlaColumnCalculation =
  | "due_at"
  | "remaining_seconds"
  | "state"
  | "consumed_percentage"
  | "breached_at";

export interface SlaColumnStyleRule {
  styleKey: string;
  state?: SlaMetricState | undefined;
  minimumPercentage?: number | undefined;
  maximumRemainingMicros?: number | undefined;
}

export interface SlaColumnWrite {
  id: string;
  key: string;
  label: string;
  metricDefinitionId: string;
  calculation: SlaColumnCalculation;
  format: "datetime" | "duration" | "state_badge" | "percentage";
  sortable: boolean;
  filterable: boolean;
  position: number;
  customerVisible: boolean;
  visibleRoleKeys: string[];
  styleRules: SlaColumnStyleRule[];
}

export interface SlaColumn extends SlaColumnWrite {
  tenantId: string;
  version: number;
  resourceVersion: number;
  revisionDigest: string;
  archivedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface VersionedSlaResource<T> {
  etag: string;
  value: T;
}

export interface SlaCursorPage<T> {
  items: T[];
  nextCursor?: string;
}

export interface SlaSimulationEvent {
  eventId: string;
  key: string;
  occurredAt: string;
}

export interface SlaSimulationFact {
  path: SlaFactPath;
  values: string[];
}

export interface SlaSimulationRequest {
  policyVersion: number;
  snapshot: {
    objectType: SlaObjectType;
    evaluatedAt: string;
    timezone: string;
    facts: SlaSimulationFact[];
  };
  slaInstanceId: string;
  objectId: string;
  createdAt: string;
  evaluateAt: string;
  metricBindings: Array<{
    metricDefinitionId: string;
    metricInstanceId: string;
  }>;
  events: SlaSimulationEvent[];
}

export interface SlaSimulationTriggerProjection {
  triggerDefinitionId: string;
  metricDefinitionId: string;
  scheduledAt?: string | undefined;
  eventDriven: boolean;
  action: SlaTriggerAction;
}

export interface SlaSimulationMetricProjection {
  metricDefinitionId: string;
  metricInstanceId: string;
  metricKey: string;
  state: SlaMetricState;
  startedAt?: string | undefined;
  dueAt?: string | undefined;
  remainingMicros: number;
  consumedPercentage: number;
  breachedAt?: string | undefined;
  completedAt?: string | undefined;
  projectedTriggers: SlaSimulationTriggerProjection[];
}

export interface SlaMetricProjection {
  metricDefinitionId: string;
  metricInstanceId: string;
  metricVersion: number;
  key: string;
  label: string;
  customerVisible: boolean;
  state: SlaMetricState;
  startedAt?: string;
  pausedAt?: string;
  dueAt?: string;
  remainingSeconds: number;
  consumedPercentage: number;
  breachedAt?: string;
  completedAt?: string;
}

export interface SlaCustomerMetricProjection {
  key: string;
  label: string;
  state: SlaMetricState;
  startedAt?: string;
  dueAt?: string;
  remainingSeconds: number;
  consumedPercentage: number;
  breachedAt?: string;
  completedAt?: string;
}

export interface SlaSimulationResult {
  tenantId: string;
  policyId: string;
  policyVersion: number;
  simulationDigest: string;
  metrics: SlaSimulationMetricProjection[];
}

export interface SlaColumnProjection {
  columnId: string;
  key: string;
  label: string;
  calculation: SlaColumnCalculation;
  format: SlaColumnWrite["format"];
  customerVisible: boolean;
  state: SlaMetricState;
  instant?: string;
  durationMicros?: number;
  percentage?: number;
  styleKey?: string;
  materializedAt: string;
}

export interface SlaCustomerColumnProjection {
  key: string;
  label: string;
  calculation: SlaColumnCalculation;
  format: SlaColumnWrite["format"];
  state: SlaMetricState;
  instant?: string;
  durationMicros?: number;
  percentage?: number;
  styleKey?: string;
  materializedAt: string;
}

export interface OperatorTicketSlaProjection {
  audience: "operator";
  tenantId: string;
  objectType: SlaObjectType;
  objectId: string;
  slaInstanceId: string;
  aggregateVersion: number;
  policyId: string;
  policyVersion: number;
  projectedAt: string;
  metrics: SlaMetricProjection[];
  columns: SlaColumnProjection[];
}

export interface CustomerTicketSlaProjection {
  audience: "customer";
  tenantId: string;
  objectType: SlaObjectType;
  objectId: string;
  projectedAt: string;
  metrics: SlaCustomerMetricProjection[];
  columns: SlaCustomerColumnProjection[];
}

export type TicketSlaProjection =
  OperatorTicketSlaProjection | CustomerTicketSlaProjection;

export type SlaOverrideKind =
  | "extend"
  | "suspend"
  | "resume"
  | "complete"
  | "change_calendar"
  | "change_policy"
  | "recalculate";

interface SlaMetricOverrideBase {
  overrideId: string;
  reason: string;
  slaInstanceId: string;
  metricInstanceId: string;
  expectedMetricVersion: number;
}

export type SlaOverrideRequest =
  | (SlaMetricOverrideBase & {
      kind: "extend";
      extensionMicros: number;
    })
  | (SlaMetricOverrideBase & {
      kind: "suspend" | "resume" | "complete";
    })
  | (SlaMetricOverrideBase & {
      kind: "change_calendar";
      replacementCalendarId: string;
      replacementCalendarVersion: number;
      simulationDigest: string;
    })
  | {
      overrideId: string;
      kind: "change_policy";
      reason: string;
      slaInstanceId: string;
      expectedAggregateVersion: number;
      newPolicyId: string;
      newPolicyVersion: number;
      simulationDigest: string;
    }
  | (SlaMetricOverrideBase & {
      kind: "recalculate";
      simulationDigest: string;
    });

export interface SlaOverrideReceipt {
  tenantId: string;
  objectType: SlaObjectType;
  objectId: string;
  overrideId: string;
  kind: SlaOverrideKind;
  outcome: "metric_updated" | "policy_changed";
  aggregateVersion: number;
  slaInstanceId: string;
  metricInstanceId?: string;
  policyId: string;
  policyVersion: number;
  previousVersion: number;
  currentVersion: number;
  occurredAt: string;
  simulationDigest?: string;
  replayed: boolean;
}

export type SlaAdminPanel = "calendars" | "policies" | "columns" | "simulator";

export const slaAdministrationRouteDescriptor = {
  path: "/tenant/sla",
  permissions: ["sla.read", "sla.manage", "sla.simulate"],
} as const;

const keyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const simulationDigestPattern = /^[0-9a-f]{64}$/u;
const displayFormatPattern = /^[a-z][a-z0-9_.-]{0,127}$/u;

export class SlaInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlaInputError";
  }
}

export function parseBoundedJson<T>(
  source: string,
  label: string,
  decode: (value: unknown) => T,
  maximumBytes = 64 * 1024,
): T {
  const normalized = source.trim();
  if (
    !normalized ||
    new TextEncoder().encode(normalized).byteLength > maximumBytes
  ) {
    throw new SlaInputError(
      `${label} must be non-empty and no larger than ${maximumBytes} bytes.`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(normalized);
  } catch {
    throw new SlaInputError(`${label} must be valid JSON.`);
  }
  return decode(parsed);
}

export function normalizeCalendarWrite(
  input: BusinessCalendarWrite,
): BusinessCalendarWrite {
  requireUuid(input.id, "Calendar ID");
  if (input.weeklySchedules.length > 7 || input.exceptions.length > 36_600) {
    throw new SlaInputError("Calendar schedule exceeds bounded limits.");
  }
  const weekdays = new Set<CalendarWeekday>();
  const weeklySchedules = input.weeklySchedules.map((schedule) => {
    if (
      !calendarWeekdays.includes(schedule.weekday) ||
      weekdays.has(schedule.weekday)
    ) {
      throw new SlaInputError(
        "Weekly schedule contains a duplicate or unsupported weekday.",
      );
    }
    weekdays.add(schedule.weekday);
    return {
      weekday: schedule.weekday,
      intervals: normalizeIntervals(schedule.intervals),
    };
  });
  if (weeklySchedules.every((schedule) => schedule.intervals.length === 0)) {
    throw new SlaInputError(
      "Calendar must contain at least one weekly business interval.",
    );
  }
  const exceptions = input.exceptions.map(normalizeCalendarException);
  const exceptionDates = new Set<string>();
  for (const exception of exceptions) {
    if (exceptionDates.has(exception.date)) {
      throw new SlaInputError("Calendar exception dates must be unique.");
    }
    exceptionDates.add(exception.date);
  }
  const value: BusinessCalendarWrite = {
    id: input.id.toLowerCase(),
    key: normalizeKey(input.key, "Calendar key"),
    label: boundedText(input.label, 256, "Calendar label"),
    timezone: normalizeTimezone(input.timezone),
    weeklySchedules: weeklySchedules.toSorted(
      (left, right) =>
        calendarWeekdays.indexOf(left.weekday) -
        calendarWeekdays.indexOf(right.weekday),
    ),
    exceptions: exceptions.toSorted((left, right) =>
      left.date.localeCompare(right.date),
    ),
  };
  return value;
}

export function normalizePolicyWrite(input: SlaPolicyWrite): SlaPolicyWrite {
  requireUuid(input.id, "Policy ID");
  const objectTypes = [...new Set(input.objectTypes)].toSorted();
  if (
    objectTypes.length === 0 ||
    objectTypes.some((kind) => kind !== "alert" && kind !== "case")
  ) {
    throw new SlaInputError("Policy must target Alert, Case, or both.");
  }
  if (
    !Number.isSafeInteger(input.priority) ||
    input.priority < -1_000_000 ||
    input.priority > 1_000_000
  ) {
    throw new SlaInputError(
      "Policy priority must be an integer from -1000000 to 1000000.",
    );
  }
  const effectiveFrom = requireInstant(input.effectiveFrom, "Effective from");
  if (
    input.effectiveUntil !== undefined &&
    requireInstant(input.effectiveUntil, "Effective until") <= effectiveFrom
  ) {
    throw new SlaInputError("Effective until must follow effective from.");
  }
  const matchRule = normalizeMatch(input.matchRule);
  if (input.metrics.length === 0 || input.metrics.length > 32) {
    throw new SlaInputError("Policy must contain between 1 and 32 metrics.");
  }
  const metricKeys = new Set<string>();
  const metricIds = new Set<string>();
  const metrics = input.metrics.map((metric) => {
    requireUuid(metric.id, "Metric definition ID");
    const id = metric.id.toLowerCase();
    const key = normalizeKey(metric.key, "Metric key");
    if (metricKeys.has(key) || metricIds.has(id)) {
      throw new SlaInputError("Metric IDs and keys must be unique.");
    }
    metricKeys.add(key);
    metricIds.add(id);
    if (
      !isBoundedMicros(metric.durationMicros, 1) ||
      metric.durationMicros > 3_153_600_000_000_000 ||
      !isBoundedMicros(metric.breachGraceMicros, 0) ||
      metric.breachGraceMicros > metric.durationMicros
    ) {
      throw new SlaInputError(`Metric ${key} has invalid duration bounds.`);
    }
    const hasCalendar =
      metric.calendarId !== undefined || metric.calendarVersion !== undefined;
    if (metric.clock === "business") {
      if (!metric.calendarId) {
        throw new SlaInputError(
          `Business-time metric ${key} requires a pinned calendar.`,
        );
      }
      requireUuid(metric.calendarId, `Metric ${key} calendar ID`);
      requireVersion(
        metric.calendarVersion ?? 0,
        `Metric ${key} calendar version`,
      );
    } else if (metric.clock !== "elapsed" || hasCalendar) {
      throw new SlaInputError(
        `Elapsed metric ${key} must not contain calendar fields.`,
      );
    }
    const startEvent = normalizeEventKey(
      metric.startEvent,
      `Metric ${key} start event`,
    );
    const completionEvent = normalizeEventKey(
      metric.completionEvent,
      `Metric ${key} completion event`,
    );
    const pauseEvent = normalizeOptionalEventKey(
      metric.pauseEvent,
      `Metric ${key} pause event`,
    );
    const resumeEvent = normalizeOptionalEventKey(
      metric.resumeEvent,
      `Metric ${key} resume event`,
    );
    const resetEvent = normalizeOptionalEventKey(
      metric.resetEvent,
      `Metric ${key} reset event`,
    );
    if ((pauseEvent === undefined) !== (resumeEvent === undefined)) {
      throw new SlaInputError(
        `Metric ${key} must define pause and resume events together.`,
      );
    }
    if ((metric.resetPolicy === "ignore") !== (resetEvent === undefined)) {
      throw new SlaInputError(
        `Metric ${key} reset policy and reset event disagree.`,
      );
    }
    const events = [
      startEvent,
      completionEvent,
      pauseEvent,
      resumeEvent,
      resetEvent,
    ].filter((event): event is string => event !== undefined);
    if (new Set(events).size !== events.length) {
      throw new SlaInputError(`Metric ${key} lifecycle events must be unique.`);
    }
    validateMetricWarning(metric.warning, metric.durationMicros, key);
    if (!displayFormatPattern.test(metric.displayFormat)) {
      throw new SlaInputError(`Metric ${key} display format is invalid.`);
    }
    return {
      ...metric,
      id,
      key,
      label: boundedText(metric.label, 256, `Metric ${key} label`),
      description: boundedText(
        metric.description,
        8192,
        `Metric ${key} description`,
        true,
      ),
      startEvent,
      completionEvent,
      ...(pauseEvent === undefined ? {} : { pauseEvent }),
      ...(resumeEvent === undefined ? {} : { resumeEvent }),
      ...(resetEvent === undefined ? {} : { resetEvent }),
    };
  });
  const triggerKeys = new Set<string>();
  const triggerIds = new Set<string>();
  const triggers = input.triggers.map((trigger) => {
    requireUuid(trigger.id, "Trigger definition ID");
    requireUuid(trigger.metricDefinitionId, "Trigger metric definition ID");
    const id = trigger.id.toLowerCase();
    const metricDefinitionId = trigger.metricDefinitionId.toLowerCase();
    const key = normalizeKey(trigger.key, "Trigger key");
    if (triggerKeys.has(key) || triggerIds.has(id)) {
      throw new SlaInputError("Trigger IDs and keys must be unique.");
    }
    triggerKeys.add(key);
    triggerIds.add(id);
    const metric = metrics.find(
      (candidate) => candidate.id === metricDefinitionId,
    );
    if (!metric) {
      throw new SlaInputError(`Trigger ${key} references an unknown metric.`);
    }
    validateTriggerShape(trigger, metric, key);
    const action = normalizeTriggerAction(trigger.action, key);
    return {
      ...trigger,
      id,
      key,
      metricDefinitionId,
      action,
    };
  });
  return {
    ...input,
    id: input.id.toLowerCase(),
    key: normalizeKey(input.key, "Policy key"),
    name: boundedText(input.name, 256, "Policy name"),
    description: boundedText(
      input.description,
      8192,
      "Policy description",
      true,
    ),
    objectTypes,
    matchRule,
    metrics,
    triggers,
  };
}

export function normalizeColumnWrite(input: SlaColumnWrite): SlaColumnWrite {
  requireUuid(input.id, "Column ID");
  requireUuid(input.metricDefinitionId, "Column metric definition ID");
  const position = input.position;
  if (!Number.isSafeInteger(position) || position < 0 || position > 255) {
    throw new SlaInputError(
      "Column position must be an integer from 0 to 255.",
    );
  }
  validateColumnShape(input.calculation, input.format);
  const roles = input.visibleRoleKeys.map((key) =>
    normalizeKey(key, "Visible role key"),
  );
  if (roles.length > 128 || new Set(roles).size !== roles.length)
    throw new SlaInputError("Visible role keys must be unique.");
  if (input.styleRules.length > 32) {
    throw new SlaInputError("Column supports at most 32 style rules.");
  }
  const styleKeys = new Set<string>();
  const styleRules = input.styleRules.map((rule) => {
    const styleKey = normalizeKey(rule.styleKey, "Column style key");
    if (styleKeys.has(styleKey)) {
      throw new SlaInputError("Column style keys must be unique.");
    }
    styleKeys.add(styleKey);
    if (
      rule.state === undefined &&
      rule.minimumPercentage === undefined &&
      rule.maximumRemainingMicros === undefined
    ) {
      throw new SlaInputError(
        "Column style rule requires at least one matching condition.",
      );
    }
    if (
      rule.minimumPercentage !== undefined &&
      (!Number.isFinite(rule.minimumPercentage) ||
        rule.minimumPercentage < 0 ||
        rule.minimumPercentage > 100)
    ) {
      throw new SlaInputError("Column percentage threshold is invalid.");
    }
    if (
      rule.maximumRemainingMicros !== undefined &&
      !isBoundedMicros(rule.maximumRemainingMicros, 0)
    ) {
      throw new SlaInputError("Column remaining threshold is invalid.");
    }
    return { ...rule, styleKey };
  });
  return {
    ...input,
    id: input.id.toLowerCase(),
    key: normalizeKey(input.key, "Column key"),
    label: boundedText(input.label, 256, "Column label"),
    metricDefinitionId: input.metricDefinitionId.toLowerCase(),
    visibleRoleKeys: [...new Set(roles)].toSorted(),
    styleRules,
  };
}

export function normalizeSimulationRequest(
  input: SlaSimulationRequest,
): SlaSimulationRequest {
  requireVersion(input.policyVersion, "Policy version");
  requireUuid(input.slaInstanceId, "Simulation SLA instance ID");
  requireUuid(input.objectId, "Object ID");
  if (input.slaInstanceId === input.objectId) {
    throw new SlaInputError("Simulation identities must be distinct.");
  }
  const timezone = normalizeTimezone(input.snapshot.timezone);
  requireInstant(input.snapshot.evaluatedAt, "Snapshot evaluated at");
  const createdAt = requireInstant(input.createdAt, "Created at");
  const evaluateAt = requireInstant(input.evaluateAt, "Evaluate at");
  if (evaluateAt < createdAt)
    throw new SlaInputError("Evaluation time cannot precede creation time.");
  if (input.events.length > 10_000)
    throw new SlaInputError("Simulation supports at most 10000 events.");
  const eventIds = new Set<string>();
  let previous = createdAt;
  const events = input.events.map((event) => {
    requireUuid(event.eventId, "Simulation event ID");
    const eventId = event.eventId.toLowerCase();
    if (eventIds.has(eventId)) {
      throw new SlaInputError("Simulation event IDs must be unique.");
    }
    eventIds.add(eventId);
    const occurredAt = requireInstant(event.occurredAt, "Event time");
    if (occurredAt < previous || occurredAt > evaluateAt) {
      throw new SlaInputError(
        "Simulation events must be ordered inside the simulation interval.",
      );
    }
    previous = occurredAt;
    return {
      eventId,
      key: normalizeEventKey(event.key, "Event key"),
      occurredAt: event.occurredAt,
    };
  });
  if (input.metricBindings.length === 0 || input.metricBindings.length > 32) {
    throw new SlaInputError(
      "Simulation must bind between 1 and 32 policy metrics.",
    );
  }
  const metricDefinitionIds = new Set<string>();
  const metricInstanceIds = new Set<string>();
  const metricBindings = input.metricBindings.map((binding) => {
    requireUuid(binding.metricDefinitionId, "Simulation metric definition ID");
    requireUuid(binding.metricInstanceId, "Simulation metric instance ID");
    const metricDefinitionId = binding.metricDefinitionId.toLowerCase();
    const metricInstanceId = binding.metricInstanceId.toLowerCase();
    if (
      metricDefinitionIds.has(metricDefinitionId) ||
      metricInstanceIds.has(metricInstanceId)
    ) {
      throw new SlaInputError("Simulation metric bindings must be unique.");
    }
    metricDefinitionIds.add(metricDefinitionId);
    metricInstanceIds.add(metricInstanceId);
    return { metricDefinitionId, metricInstanceId };
  });
  if (input.snapshot.facts.length > 256) {
    throw new SlaInputError("Simulation supports at most 256 facts.");
  }
  const factPaths = new Set<string>();
  const facts = input.snapshot.facts.map((fact) => {
    const path = normalizeFactPath(fact.path);
    const identity = `${path.kind}:${path.key ?? ""}`;
    if (
      factPaths.has(identity) ||
      path.kind === "object_type" ||
      path.kind === "local_hour" ||
      path.kind === "local_weekday" ||
      fact.values.length === 0 ||
      fact.values.length > 128
    ) {
      throw new SlaInputError(
        "Simulation facts are duplicate, derived, empty, or unbounded.",
      );
    }
    factPaths.add(identity);
    if (
      path.kind !== "tag" &&
      path.kind !== "operator_team" &&
      path.kind !== "custom_field" &&
      fact.values.length !== 1
    ) {
      throw new SlaInputError(
        "This simulation fact kind requires exactly one value.",
      );
    }
    const values = normalizeFactValues(
      path.kind,
      fact.values,
      "Simulation fact value",
    );
    if (new Set(values).size !== values.length) {
      throw new SlaInputError("Simulation fact values must be unique.");
    }
    return { path, values: values.toSorted() };
  });
  return {
    ...input,
    slaInstanceId: input.slaInstanceId.toLowerCase(),
    objectId: input.objectId.toLowerCase(),
    snapshot: { ...input.snapshot, timezone, facts },
    metricBindings,
    events,
  };
}

export function normalizeOverride(
  input: SlaOverrideRequest,
): SlaOverrideRequest {
  requireUuid(input.overrideId, "Override ID");
  requireUuid(input.slaInstanceId, "SLA instance ID");
  const reason = boundedText(input.reason, 1000, "Override reason");
  if (Array.from(reason).length < 8)
    throw new SlaInputError(
      "Override reason must contain at least 8 characters.",
    );
  switch (input.kind) {
    case "extend": {
      requireExactKeys(input, [
        "overrideId",
        "kind",
        "reason",
        "slaInstanceId",
        "metricInstanceId",
        "expectedMetricVersion",
        "extensionMicros",
      ]);
      const metric = normalizeMetricOverrideBase(input, reason);
      if (
        !isBoundedMicros(input.extensionMicros, 60_000_000) ||
        input.extensionMicros > 3_153_600_000_000_000
      ) {
        throw new SlaInputError(
          "Extension requires between 60 seconds and 100 years.",
        );
      }
      return {
        ...metric,
        kind: "extend",
        extensionMicros: input.extensionMicros,
      };
    }
    case "suspend":
    case "resume":
    case "complete": {
      requireExactKeys(input, [
        "overrideId",
        "kind",
        "reason",
        "slaInstanceId",
        "metricInstanceId",
        "expectedMetricVersion",
      ]);
      return {
        ...normalizeMetricOverrideBase(input, reason),
        kind: input.kind,
      };
    }
    case "change_calendar": {
      requireExactKeys(input, [
        "overrideId",
        "kind",
        "reason",
        "slaInstanceId",
        "metricInstanceId",
        "expectedMetricVersion",
        "replacementCalendarId",
        "replacementCalendarVersion",
        "simulationDigest",
      ]);
      requireUuid(input.replacementCalendarId, "Replacement calendar ID");
      requireVersion(
        input.replacementCalendarVersion,
        "Replacement calendar version",
      );
      return {
        ...normalizeMetricOverrideBase(input, reason),
        kind: "change_calendar",
        replacementCalendarId: input.replacementCalendarId.toLowerCase(),
        replacementCalendarVersion: input.replacementCalendarVersion,
        simulationDigest: normalizeSimulationDigest(input.simulationDigest),
      };
    }
    case "change_policy": {
      requireExactKeys(input, [
        "overrideId",
        "kind",
        "reason",
        "slaInstanceId",
        "expectedAggregateVersion",
        "newPolicyId",
        "newPolicyVersion",
        "simulationDigest",
      ]);
      requireVersion(
        input.expectedAggregateVersion,
        "Expected aggregate version",
      );
      requireUuid(input.newPolicyId, "New policy ID");
      requireVersion(input.newPolicyVersion, "New policy version");
      return {
        overrideId: input.overrideId.toLowerCase(),
        kind: "change_policy",
        reason,
        slaInstanceId: input.slaInstanceId.toLowerCase(),
        expectedAggregateVersion: input.expectedAggregateVersion,
        newPolicyId: input.newPolicyId.toLowerCase(),
        newPolicyVersion: input.newPolicyVersion,
        simulationDigest: normalizeSimulationDigest(input.simulationDigest),
      };
    }
    case "recalculate": {
      requireExactKeys(input, [
        "overrideId",
        "kind",
        "reason",
        "slaInstanceId",
        "metricInstanceId",
        "expectedMetricVersion",
        "simulationDigest",
      ]);
      return {
        ...normalizeMetricOverrideBase(input, reason),
        kind: "recalculate",
        simulationDigest: normalizeSimulationDigest(input.simulationDigest),
      };
    }
    default:
      throw new SlaInputError("Override kind is unsupported.");
  }
}

function normalizeMetricOverrideBase(
  input: SlaMetricOverrideBase,
  reason: string,
): SlaMetricOverrideBase {
  requireUuid(input.metricInstanceId, "Metric instance ID");
  requireVersion(input.expectedMetricVersion, "Expected metric version");
  return {
    overrideId: input.overrideId.toLowerCase(),
    reason,
    slaInstanceId: input.slaInstanceId.toLowerCase(),
    metricInstanceId: input.metricInstanceId.toLowerCase(),
    expectedMetricVersion: input.expectedMetricVersion,
  };
}

function normalizeSimulationDigest(value: string): string {
  const digest = boundedText(value, 64, "Simulation digest");
  if (!simulationDigestPattern.test(digest)) {
    throw new SlaInputError(
      "Simulation digest must be a lowercase hexadecimal SHA-256 value.",
    );
  }
  return digest;
}

function requireExactKeys(value: object, expected: readonly string[]): void {
  const expectedKeys = new Set(expected);
  if (
    Object.keys(value).length !== expectedKeys.size ||
    Object.keys(value).some((key) => !expectedKeys.has(key))
  ) {
    throw new SlaInputError(
      "Request contains fields for another operation kind.",
    );
  }
}

export function formatSlaInstant(value: string | undefined): string {
  if (!value) return "Not reached";
  const instant = new Date(value);
  if (Number.isNaN(instant.valueOf())) return "Invalid server time";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(instant);
}

export function formatSlaDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "Unavailable";
  const sign = seconds < 0 ? "−" : "";
  let remaining = Math.abs(Math.trunc(seconds));
  const days = Math.floor(remaining / 86_400);
  remaining %= 86_400;
  const hours = Math.floor(remaining / 3_600);
  remaining %= 3_600;
  const minutes = Math.floor(remaining / 60);
  const parts = [
    days ? `${days}d` : "",
    hours ? `${hours}h` : "",
    minutes ? `${minutes}m` : "",
  ].filter(Boolean);
  return `${sign}${parts.length > 0 ? parts.join(" ") : `${remaining}s`}`;
}

export function safeSlaError(error: unknown, fallback: string): string {
  return error instanceof SlaInputError ? error.message : fallback;
}

export const calendarWeekdays: readonly CalendarWeekday[] = [
  "sunday",
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
];

function normalizeCalendarException(
  value: CalendarException,
): CalendarException {
  if (
    !/^\d{4}-\d{2}-\d{2}$/u.test(value.date) ||
    Number.isNaN(Date.parse(`${value.date}T00:00:00Z`))
  ) {
    throw new SlaInputError("Calendar exception date must use YYYY-MM-DD.");
  }
  const intervals = normalizeIntervals(value.intervals);
  if (value.closed !== (intervals.length === 0)) {
    throw new SlaInputError(
      "A closed exception must have no intervals; an open exception needs intervals.",
    );
  }
  return {
    closed: value.closed,
    date: value.date,
    intervals,
  };
}

function normalizeIntervals(intervals: CalendarInterval[]): CalendarInterval[] {
  if (intervals.length > 32) {
    throw new SlaInputError("Calendar day supports at most 32 intervals.");
  }
  const result = intervals
    .map((interval) => {
      if (
        !Number.isSafeInteger(interval.startMinute) ||
        !Number.isSafeInteger(interval.endMinute) ||
        interval.startMinute < 0 ||
        interval.startMinute >= interval.endMinute ||
        interval.endMinute > 1440
      ) {
        throw new SlaInputError(
          "Calendar intervals must use ordered minute boundaries from 0 to 1440.",
        );
      }
      return {
        startMinute: interval.startMinute,
        endMinute: interval.endMinute,
      };
    })
    .toSorted((left, right) => left.startMinute - right.startMinute);
  for (let index = 1; index < result.length; index += 1) {
    if (result[index - 1]!.endMinute > result[index]!.startMinute) {
      throw new SlaInputError("Calendar intervals cannot overlap.");
    }
  }
  return result;
}

function normalizeMatch(value: SlaMatchExpression): SlaMatchExpression {
  const counter = { nodes: 0 };
  return normalizeMatchNode(value, 0, counter);
}

function normalizeMatchNode(
  value: SlaMatchExpression,
  depth: number,
  counter: { nodes: number },
): SlaMatchExpression {
  counter.nodes += 1;
  if (depth > 16 || counter.nodes > 256) {
    throw new SlaInputError(
      "Policy match expression exceeds bounded depth or size.",
    );
  }
  if (value.kind === "predicate") {
    const path = normalizeFactPath(value.predicate.path);
    const operator = value.predicate.operator;
    const values = normalizeFactValues(
      path.kind,
      value.predicate.values,
      "Policy predicate value",
    );
    const wantsNone = operator === "exists" || operator === "not_exists";
    const wantsOne = operator === "equals" || operator === "not_equals";
    const wantsMany = operator === "one_of" || operator === "none_of";
    if (
      (!wantsNone && !wantsOne && !wantsMany) ||
      (wantsNone && values.length !== 0) ||
      (wantsOne && values.length !== 1) ||
      (wantsMany && (values.length === 0 || values.length > 128)) ||
      new Set(values).size !== values.length
    ) {
      throw new SlaInputError("Policy predicate operator and values disagree.");
    }
    return {
      kind: "predicate",
      predicate: { path, operator, values: values.toSorted() },
    };
  }
  const children = value.children;
  if (
    children.length > 256 ||
    (value.kind === "any" && children.length === 0) ||
    (value.kind === "not" && children.length !== 1)
  ) {
    throw new SlaInputError("Policy boolean expression is malformed.");
  }
  const normalized = children.map((child) =>
    normalizeMatchNode(child, depth + 1, counter),
  );
  return value.kind === "not"
    ? { kind: "not", children: [normalized[0]!] }
    : { kind: value.kind, children: normalized };
}

function normalizeFactPath(path: SlaFactPath): SlaFactPath {
  const kinds: readonly SlaFactKind[] = [
    "customer_tier",
    "object_type",
    "severity",
    "priority",
    "category",
    "source",
    "operator_team",
    "tag",
    "custom_field",
    "local_hour",
    "local_weekday",
    "customer_contact_class",
  ];
  if (!kinds.includes(path.kind)) {
    throw new SlaInputError("Policy fact kind is unsupported.");
  }
  if (path.kind === "custom_field") {
    if (!path.key) {
      throw new SlaInputError("Custom-field fact requires a field key.");
    }
    return { kind: path.kind, key: normalizeKey(path.key, "Custom field key") };
  }
  if (path.key !== undefined) {
    throw new SlaInputError("Only custom-field facts can contain a key.");
  }
  return { kind: path.kind };
}

function normalizeFactValues(
  kind: SlaFactKind,
  inputs: string[],
  label: string,
): string[] {
  return inputs.map((input) => {
    const value = boundedText(input, 2048, label);
    if (kind === "operator_team") {
      requireUuid(value, label);
      return value.toLowerCase();
    }
    if (kind === "object_type") {
      if (value !== "alert" && value !== "case") {
        throw new SlaInputError(`${label} must be alert or case.`);
      }
      return value;
    }
    if (kind === "local_hour") {
      const hour = Number(value);
      if (
        !Number.isInteger(hour) ||
        hour < 0 ||
        hour > 23 ||
        String(hour) !== value
      ) {
        throw new SlaInputError(`${label} must be a canonical local hour.`);
      }
      return value;
    }
    if (kind === "local_weekday") {
      if (
        ![
          "sunday",
          "monday",
          "tuesday",
          "wednesday",
          "thursday",
          "friday",
          "saturday",
        ].includes(value)
      ) {
        throw new SlaInputError(`${label} must be a lowercase weekday.`);
      }
      return value;
    }
    return kind === "custom_field" ? value : normalizeKey(value, label);
  });
}

function validateMetricWarning(
  warning: SlaMetricWarning,
  durationMicros: number,
  metricKey: string,
): void {
  if (warning.kind === "none") return;
  if (
    warning.kind === "consumed_percent" &&
    Number.isSafeInteger(warning.consumedPercent) &&
    warning.consumedPercent >= 1 &&
    warning.consumedPercent <= 99
  ) {
    return;
  }
  if (
    warning.kind === "remaining_duration" &&
    isBoundedMicros(warning.remainingMicros, 1) &&
    warning.remainingMicros < durationMicros
  ) {
    return;
  }
  throw new SlaInputError(`Metric ${metricKey} warning threshold is invalid.`);
}

function validateTriggerShape(
  trigger: SlaTriggerWrite,
  metric: SlaMetricWrite,
  key: string,
): void {
  const hasConsumed = trigger.consumedPercent !== undefined;
  const hasRemaining = trigger.remainingMicros !== undefined;
  const hasOffset = trigger.offsetMicros !== undefined;
  const hasRepeat = trigger.repeatIntervalMicros !== undefined;
  const hasState = trigger.targetState !== undefined;
  const noShape =
    !hasConsumed && !hasRemaining && !hasOffset && !hasRepeat && !hasState;
  let valid = false;
  switch (trigger.kind) {
    case "consumed_percent":
      valid =
        Number.isSafeInteger(trigger.consumedPercent) &&
        trigger.consumedPercent! >= 1 &&
        trigger.consumedPercent! <= 100 &&
        !hasRemaining &&
        !hasOffset &&
        !hasRepeat &&
        !hasState;
      break;
    case "remaining_duration":
      valid =
        isBoundedMicros(trigger.remainingMicros, 1) &&
        trigger.remainingMicros < metric.durationMicros &&
        !hasConsumed &&
        !hasOffset &&
        !hasRepeat &&
        !hasState;
      break;
    case "due":
    case "resumed":
      valid = noShape;
      break;
    case "after_breach":
      valid =
        isBoundedMicros(trigger.offsetMicros, 0) &&
        !hasConsumed &&
        !hasRemaining &&
        !hasRepeat &&
        !hasState;
      break;
    case "repeated_after_breach":
      valid =
        isBoundedMicros(trigger.offsetMicros, 0) &&
        isBoundedMicros(trigger.repeatIntervalMicros, 1) &&
        !hasConsumed &&
        !hasRemaining &&
        !hasState;
      break;
    case "state_changed":
      valid =
        hasState && !hasConsumed && !hasRemaining && !hasOffset && !hasRepeat;
      break;
  }
  if (!valid) {
    throw new SlaInputError(
      `Trigger ${key} has fields for another trigger kind.`,
    );
  }
}

function normalizeTriggerAction(
  action: SlaTriggerAction,
  triggerKey: string,
): SlaTriggerAction {
  switch (action.kind) {
    case "email":
    case "webhook":
    case "assign_operator_team":
      requireExactKeys(action, ["kind", "configurationId"]);
      requireUuid(
        action.configurationId,
        `Trigger ${triggerKey} configuration ID`,
      );
      return {
        kind: action.kind,
        configurationId: action.configurationId.toLowerCase(),
      };
    case "add_tag":
    case "change_priority":
    case "domain_event":
      requireExactKeys(action, ["kind", "value"]);
      return {
        kind: action.kind,
        value: normalizeKey(action.value, `Trigger ${triggerKey} action value`),
      };
    case "create_task": {
      requireExactKeys(action, ["kind", "text"]);
      const text = boundedText(
        action.text,
        2048,
        `Trigger ${triggerKey} task text`,
      );
      if (/[\r\n]/u.test(text)) {
        throw new SlaInputError(
          `Trigger ${triggerKey} task action is invalid.`,
        );
      }
      return { kind: "create_task", text };
    }
    case "create_system_alert":
      requireExactKeys(action, ["kind", "value", "allowRecursiveSla"]);
      return {
        kind: "create_system_alert",
        value: normalizeKey(action.value, `Trigger ${triggerKey} action value`),
        allowRecursiveSla: action.allowRecursiveSla,
      };
    default:
      throw new SlaInputError(`Trigger ${triggerKey} action kind is invalid.`);
  }
}

function validateColumnShape(
  calculation: SlaColumnCalculation,
  format: SlaColumnWrite["format"],
): void {
  const valid =
    ((calculation === "due_at" || calculation === "breached_at") &&
      format === "datetime") ||
    (calculation === "remaining_seconds" && format === "duration") ||
    (calculation === "state" && format === "state_badge") ||
    (calculation === "consumed_percentage" && format === "percentage");
  if (!valid) {
    throw new SlaInputError("Column calculation and display format disagree.");
  }
}

function isBoundedMicros(
  value: number | undefined,
  minimum: number,
): value is number {
  return value !== undefined && Number.isSafeInteger(value) && value >= minimum;
}

function normalizeOptionalEventKey(
  value: string | undefined,
  label: string,
): string | undefined {
  return value === undefined ? undefined : normalizeEventKey(value, label);
}

function normalizeEventKey(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!keyPattern.test(normalized))
    throw new SlaInputError(`${label} is invalid.`);
  return normalized;
}

function normalizeKey(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!keyPattern.test(normalized))
    throw new SlaInputError(`${label} is invalid.`);
  return normalized;
}

function boundedText(
  value: string,
  maximum: number,
  label: string,
  allowEmpty = false,
): string {
  const normalized = value.trim();
  if (
    (!allowEmpty && !normalized) ||
    Array.from(normalized).length > maximum ||
    hasForbiddenControl(normalized)
  ) {
    throw new SlaInputError(`${label} is invalid.`);
  }
  return normalized;
}

function hasForbiddenControl(value: string): boolean {
  for (const character of value) {
    const point = character.codePointAt(0);
    if (
      point !== undefined &&
      (point <= 8 ||
        point === 11 ||
        point === 12 ||
        (point >= 14 && point <= 31) ||
        point === 127)
    ) {
      return true;
    }
  }
  return false;
}

function normalizeTimezone(value: string): string {
  const normalized = boundedText(value, 128, "Timezone");
  try {
    new Intl.DateTimeFormat("en", { timeZone: normalized }).format();
  } catch {
    throw new SlaInputError("Timezone must be a valid IANA name.");
  }
  return normalized;
}

function requireUuid(value: string, label: string): void {
  if (!uuidPattern.test(value.toLowerCase()))
    throw new SlaInputError(`${label} must be a canonical UUIDv7.`);
}

function requireVersion(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1)
    throw new SlaInputError(`${label} must be a positive integer.`);
}

function requireInstant(value: string, label: string): number {
  const instant = Date.parse(value);
  if (!Number.isFinite(instant) || !/(?:Z|[+-]\d{2}:\d{2})$/u.test(value)) {
    throw new SlaInputError(`${label} must be an RFC 3339 instant.`);
  }
  return instant;
}
