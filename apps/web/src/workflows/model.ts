import { parseRfc3339Instant } from "../lib/rfc3339-instant";

export type WorkflowKind = "alert" | "case";
export type WorkflowStatus = "active" | "archived";
export type WorkflowVisibility = "internal" | "customer";
export type WorkflowEffect = "activity" | "audit" | "sla" | "notification";
export type WorkflowAction =
  "create" | "assign" | "claim" | "release" | "transfer" | "escalate" | "link";

export type WorkflowPermission =
  | "alert.create"
  | "alert.update"
  | "alert.assign"
  | "alert.claim"
  | "alert.escalate"
  | "alert.comment.public"
  | "alert.comment.private"
  | "case.create"
  | "case.update"
  | "case.claim"
  | "case.transfer"
  | "case.transition"
  | "case.comment.public"
  | "case.comment.private";

export type WorkflowConditionValue =
  | { type: "text"; value: string }
  | { type: "number"; value: number }
  | { type: "boolean"; value: boolean }
  | { type: "instant"; value: string };

export type WorkflowCondition =
  | {
      kind: "predicate";
      field: string;
      operator:
        | "equal"
        | "not_equal"
        | "in"
        | "not_in"
        | "less_than"
        | "less_than_or_equal"
        | "greater_than"
        | "greater_than_or_equal"
        | "exists"
        | "not_exists";
      values: WorkflowConditionValue[];
    }
  | { kind: "all" | "any"; children: WorkflowCondition[] }
  | { kind: "not"; children: [WorkflowCondition] };

export interface WorkflowStateAction {
  action: WorkflowAction;
  effects: WorkflowEffect[];
}

export interface WorkflowState {
  key: string;
  initial: boolean;
  terminal: boolean;
  visibility: WorkflowVisibility;
  actions: WorkflowStateAction[];
}

export interface WorkflowTransition {
  key: string;
  from: string;
  to: string;
  requiredComment: boolean;
  reopen: boolean;
  requiredRoles: string[];
  requiredPermissions: WorkflowPermission[];
  requiredCustomFields: string[];
  condition?: WorkflowCondition | undefined;
  effects: WorkflowEffect[];
}

export interface WorkflowDesign {
  states: WorkflowState[];
  transitions: WorkflowTransition[];
}

export interface WorkflowDefinition extends WorkflowDesign {
  id: string;
  kind: WorkflowKind;
  version: number;
  initialState: string;
}

export interface ManagedWorkflow {
  id: string;
  tenantId: string;
  kind: WorkflowKind;
  key: string;
  displayName: string;
  description: string;
  isDefault: boolean;
  status: WorkflowStatus;
  revision: number;
  currentVersion: number;
  current: WorkflowDefinition;
  createdAt: string;
  updatedAt: string;
  archivedAt?: string | undefined;
}

export interface WorkflowVersion {
  tenantId: string;
  workflowId: string;
  definition: WorkflowDefinition;
  publishedByMembershipId?: string | undefined;
  publisherDisplayName: string;
  publishedAt: string;
}

export interface WorkflowSimulationFact {
  field: string;
  value?: WorkflowConditionValue | undefined;
}

export interface WorkflowSimulationRequest {
  version: number;
  state: string;
  commentPresent: boolean;
  roles: string[];
  permissions: WorkflowPermission[];
  providedCustomFields: string[];
  facts: WorkflowSimulationFact[];
}

export interface WorkflowTransitionSimulation {
  key: string;
  from: string;
  to: string;
  reopen: boolean;
  eligible: boolean;
  gates: {
    commentSatisfied: boolean;
    roleSatisfied: boolean;
    permissionsSatisfied: boolean;
    customFieldsSatisfied: boolean;
    conditionSatisfied: boolean;
  };
  missingRoles: string[];
  missingPermissions: WorkflowPermission[];
  missingCustomFields: string[];
  effects: WorkflowEffect[];
}

export interface WorkflowSimulationResult {
  workflowId: string;
  kind: WorkflowKind;
  version: number;
  explanatory: true;
  transitions: WorkflowTransitionSimulation[];
}

export const workflowReadPermission = "workflow.read";
export const workflowManagePermission = "workflow.manage";

export const workflowAdministrationRouteDescriptor = {
  path: "/tenant/workflows",
  permissions: [workflowReadPermission],
} as const;

const keyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const conditionKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const catalogKeyPattern = /^[a-z][a-z0-9_]{2,63}$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const effectOrder: readonly WorkflowEffect[] = [
  "activity",
  "audit",
  "sla",
  "notification",
];
const actionOrder: readonly WorkflowAction[] = [
  "create",
  "assign",
  "claim",
  "release",
  "transfer",
  "escalate",
  "link",
];
// Mirrors the kernel enum, which intentionally differs from lexical order.
export const workflowPermissionOrder: readonly WorkflowPermission[] = [
  "alert.create",
  "alert.update",
  "alert.assign",
  "alert.claim",
  "alert.escalate",
  "alert.comment.public",
  "alert.comment.private",
  "case.create",
  "case.update",
  "case.claim",
  "case.transfer",
  "case.transition",
  "case.comment.public",
  "case.comment.private",
];
const permissionsByKind: Readonly<
  Record<WorkflowKind, readonly WorkflowPermission[]>
> = {
  alert: workflowPermissionOrder.slice(0, 7),
  case: workflowPermissionOrder.slice(7),
};
const builtInConditionKinds: Readonly<
  Record<string, WorkflowConditionValue["type"]>
> = {
  aggregate_kind: "text",
  state: "text",
  severity: "text",
  priority: "text",
  category: "text",
  classification: "text",
  source: "text",
  source_type: "text",
  customer_visible: "boolean",
  assigned: "boolean",
  assignee_present: "boolean",
  claimed: "boolean",
  comment_present: "boolean",
  detected_at: "instant",
  received_at: "instant",
  opened_at: "instant",
  created_at: "instant",
  updated_at: "instant",
};

export class WorkflowInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowInputError";
  }
}

export function normalizeWorkflowCatalogKey(value: string): string {
  const key = value.trim().toLowerCase();
  if (!catalogKeyPattern.test(key)) {
    throw new WorkflowInputError(
      "Workflow key must be 3–64 lowercase letters, digits, or underscores.",
    );
  }
  return key;
}

export function normalizeWorkflowDesign(
  kind: WorkflowKind,
  input: WorkflowDesign,
): WorkflowDesign {
  if (kind !== "alert" && kind !== "case") {
    throw new WorkflowInputError("Workflow kind is unsupported.");
  }
  if (input.states.length < 2 || input.states.length > 64) {
    throw new WorkflowInputError("Workflow must contain 2–64 states.");
  }
  if (input.transitions.length < 1 || input.transitions.length > 256) {
    throw new WorkflowInputError("Workflow must contain 1–256 transitions.");
  }

  const stateKeys = new Set<string>();
  const states = input.states.map((state) => {
    const key = normalizeKey(state.key, "State key");
    if (stateKeys.has(key)) {
      throw new WorkflowInputError("Workflow state keys must be unique.");
    }
    stateKeys.add(key);
    if (state.initial && state.terminal) {
      throw new WorkflowInputError("The initial state cannot be terminal.");
    }
    if (state.visibility !== "internal" && state.visibility !== "customer") {
      throw new WorkflowInputError(`State ${key} visibility is unsupported.`);
    }
    const seenActions = new Set<WorkflowAction>();
    const actions = state.actions.map((item) => {
      if (!actionOrder.includes(item.action) || seenActions.has(item.action)) {
        throw new WorkflowInputError(`State ${key} actions must be unique.`);
      }
      if (
        (kind === "alert" && item.action === "link") ||
        (kind === "case" && item.action === "escalate")
      ) {
        throw new WorkflowInputError(
          `Action ${item.action} does not belong to a ${kind} workflow.`,
        );
      }
      seenActions.add(item.action);
      return { action: item.action, effects: normalizeEffects(item.effects) };
    });
    if (seenActions.has("create") !== state.initial) {
      throw new WorkflowInputError(
        `State ${key} must allow create exactly when it is initial.`,
      );
    }
    return {
      key,
      initial: state.initial,
      terminal: state.terminal,
      visibility: state.visibility,
      actions: actions.toSorted(
        (left, right) =>
          actionOrder.indexOf(left.action) - actionOrder.indexOf(right.action),
      ),
    };
  });
  const initial = states.filter((state) => state.initial);
  if (initial.length !== 1 || !states.some((state) => state.terminal)) {
    throw new WorkflowInputError(
      "Workflow requires exactly one initial and at least one terminal state.",
    );
  }

  const stateByKey = new Map(states.map((state) => [state.key, state]));
  const transitionKeys = new Set<string>();
  const edges = new Set<string>();
  const outgoing = new Map<string, string[]>();
  const transitions = input.transitions.map((transition) => {
    const key = normalizeKey(transition.key, "Transition key");
    const from = normalizeKey(transition.from, `Transition ${key} source`);
    const to = normalizeKey(transition.to, `Transition ${key} target`);
    const edge = `${from}\u0000${to}`;
    if (
      transitionKeys.has(key) ||
      edges.has(edge) ||
      from === to ||
      !stateByKey.has(from) ||
      !stateByKey.has(to)
    ) {
      throw new WorkflowInputError(
        `Transition ${key} has a duplicate or invalid edge.`,
      );
    }
    transitionKeys.add(key);
    edges.add(edge);
    const source = stateByKey.get(from)!;
    const target = stateByKey.get(to)!;
    if (
      transition.reopen !== source.terminal ||
      (transition.reopen && target.terminal) ||
      (!transition.reopen && target.initial)
    ) {
      throw new WorkflowInputError(
        `Transition ${key} has invalid terminal or reopen semantics.`,
      );
    }
    outgoing.set(from, [...(outgoing.get(from) ?? []), to]);
    const permissions = normalizePermissions(
      transition.requiredPermissions,
      `Transition ${key} permissions`,
    );
    if (
      permissions.some(
        (permission) => !permissionsByKind[kind].includes(permission),
      )
    ) {
      throw new WorkflowInputError(
        `Transition ${key} contains a permission for another ticket kind.`,
      );
    }
    const { condition } = transition;
    return {
      key,
      from,
      to,
      requiredComment: transition.requiredComment,
      reopen: transition.reopen,
      requiredRoles: normalizeUnique(
        transition.requiredRoles,
        (value) => normalizeKey(value, `Transition ${key} role`),
        `Transition ${key} roles`,
      ),
      requiredPermissions: permissions,
      requiredCustomFields: normalizeUnique(
        transition.requiredCustomFields,
        (value) => normalizeKey(value, `Transition ${key} custom field`),
        `Transition ${key} custom fields`,
      ),
      ...(condition === undefined
        ? {}
        : { condition: normalizeCondition(condition) }),
      effects: normalizeEffects(transition.effects),
    };
  });
  for (const state of states) {
    if (!state.terminal && (outgoing.get(state.key)?.length ?? 0) === 0) {
      throw new WorkflowInputError(
        `Non-terminal state ${state.key} requires an outgoing transition.`,
      );
    }
  }
  requireReachable(initial[0]!.key, states, outgoing);
  return {
    states: states.toSorted((left, right) => compareText(left.key, right.key)),
    transitions: transitions.toSorted((left, right) =>
      compareText(left.key, right.key),
    ),
  };
}

export function normalizeWorkflowSimulation(
  kind: WorkflowKind,
  workflow: WorkflowDefinition,
  input: WorkflowSimulationRequest,
): WorkflowSimulationRequest {
  if (workflow.kind !== kind) {
    throw new WorkflowInputError(
      "Simulation workflow kind does not match its tenant view.",
    );
  }
  const version = requireSimulationVersion(input.version);
  if (version > workflow.version) {
    throw new WorkflowInputError("Simulation version is not published.");
  }
  const state = normalizeKey(input.state, "Simulation state");
  if (
    (version === 0 || version === workflow.version) &&
    !workflow.states.some((candidate) => candidate.key === state)
  ) {
    throw new WorkflowInputError("Simulation state does not exist.");
  }
  const roles = normalizeUnique(
    input.roles,
    (value) => normalizeKey(value, "Simulation role"),
    "Simulation roles",
  );
  const permissions = normalizePermissions(
    input.permissions,
    "Simulation permissions",
  );
  if (
    permissions.some(
      (permission) => !permissionsByKind[kind].includes(permission),
    )
  ) {
    throw new WorkflowInputError(
      "Simulation permission belongs to another ticket kind.",
    );
  }
  const providedCustomFields = normalizeUnique(
    input.providedCustomFields,
    (value) => normalizeKey(value, "Simulation custom field"),
    "Simulation custom fields",
  );
  if (input.facts.length > 256) {
    throw new WorkflowInputError("Simulation supports at most 256 facts.");
  }
  const facts = input.facts.map((fact) => {
    const field = normalizeConditionField(fact.field);
    const value =
      fact.value === undefined
        ? undefined
        : normalizeConditionValue(fact.value);
    const expected = workflowConditionValueType(field);
    if (
      value !== undefined &&
      expected !== undefined &&
      value.type !== expected
    ) {
      throw new WorkflowInputError(
        `Simulation fact ${field} has the wrong scalar type.`,
      );
    }
    return { field, ...(value === undefined ? {} : { value }) };
  });
  const factFields = facts.map((fact) => fact.field);
  if (
    new Set(factFields).size !== facts.length ||
    facts.some(
      (fact) =>
        (fact.field === "aggregate_kind" &&
          (fact.value?.type !== "text" || fact.value.value !== kind)) ||
        (fact.field === "state" &&
          (fact.value?.type !== "text" || fact.value.value !== state)),
    )
  ) {
    throw new WorkflowInputError(
      "Simulation facts are duplicate or conflict with derived facts.",
    );
  }
  return {
    version,
    state,
    commentPresent: input.commentPresent,
    roles,
    permissions,
    providedCustomFields,
    facts: facts.toSorted((left, right) =>
      compareText(left.field, right.field),
    ),
  };
}

export function requireWorkflowUuid(value: string, label: string): string {
  const canonical = value.toLowerCase();
  if (!uuidV7Pattern.test(canonical)) {
    throw new WorkflowInputError(`${label} must be a canonical UUIDv7.`);
  }
  return canonical;
}

export function requireWorkflowVersion(value: number, label: string): number {
  return requireVersion(value, label);
}

export function boundedWorkflowText(
  value: string,
  maximumBytes: number,
  label: string,
  optional = false,
): string {
  const normalized = value.trim();
  if (
    (!optional && normalized.length === 0) ||
    new TextEncoder().encode(normalized).byteLength > maximumBytes ||
    Array.from(normalized).some(isForbiddenWorkflowCharacter)
  ) {
    throw new WorkflowInputError(`${label} is invalid or too long.`);
  }
  return normalized;
}

function normalizeCondition(input: WorkflowCondition): WorkflowCondition {
  const counter = { value: 0 };
  return normalizeConditionNode(input, 1, counter);
}

function normalizeConditionNode(
  input: WorkflowCondition,
  depth: number,
  counter: { value: number },
): WorkflowCondition {
  counter.value += 1;
  if (depth > 8 || counter.value > 128) {
    throw new WorkflowInputError("Workflow condition exceeds bounded size.");
  }
  if (input.kind === "predicate") {
    const field = normalizeConditionField(input.field);
    const values = input.values.map(normalizeConditionValue);
    const operator = input.operator;
    const empty = operator === "exists" || operator === "not_exists";
    const single =
      operator === "equal" ||
      operator === "not_equal" ||
      operator === "less_than" ||
      operator === "less_than_or_equal" ||
      operator === "greater_than" ||
      operator === "greater_than_or_equal";
    const multiple = operator === "in" || operator === "not_in";
    if (
      (empty && values.length !== 0) ||
      (single && values.length !== 1) ||
      (multiple && (values.length < 1 || values.length > 32)) ||
      (!empty && !single && !multiple)
    ) {
      throw new WorkflowInputError(
        `Condition operator ${operator} has invalid values.`,
      );
    }
    if (
      values.some((value) => value.type !== values[0]?.type) ||
      new Set(values.map(conditionValueIdentity)).size !== values.length
    ) {
      throw new WorkflowInputError(
        "Condition values must be unique and have one scalar type.",
      );
    }
    const expected = workflowConditionValueType(field);
    if (
      expected !== undefined &&
      values.some((value) => value.type !== expected)
    ) {
      throw new WorkflowInputError(
        `Condition field ${field} has the wrong scalar type.`,
      );
    }
    if (
      operator.startsWith("less_than") ||
      operator.startsWith("greater_than")
    ) {
      if (values[0]?.type !== "number" && values[0]?.type !== "instant") {
        throw new WorkflowInputError(
          "Ordering conditions require a number or instant.",
        );
      }
    }
    return {
      kind: "predicate",
      field,
      operator,
      values: multiple ? values.toSorted(compareConditionValues) : values,
    };
  }
  const children = input.children;
  if (
    (input.kind !== "not" && (children.length < 2 || children.length > 32)) ||
    (input.kind === "not" && children.length !== 1)
  ) {
    throw new WorkflowInputError("Workflow boolean condition is malformed.");
  }
  const normalized = children.map((child) =>
    normalizeConditionNode(child, depth + 1, counter),
  );
  return input.kind === "not"
    ? { kind: "not", children: [normalized[0]!] }
    : { kind: input.kind, children: normalized };
}

function normalizeConditionField(value: string): string {
  if (builtInConditionKinds[value] !== undefined) return value;
  for (const prefix of ["custom.", "tag."] as const) {
    if (value.startsWith(prefix)) {
      return `${prefix}${normalizeConditionKey(value.slice(prefix.length))}`;
    }
  }
  throw new WorkflowInputError("Condition field is not allowlisted.");
}

export function workflowConditionValueType(
  field: string,
): WorkflowConditionValue["type"] | undefined {
  return (
    builtInConditionKinds[field] ??
    (field.startsWith("tag.") ? "boolean" : undefined)
  );
}

function normalizeConditionValue(
  input: WorkflowConditionValue,
): WorkflowConditionValue {
  switch (input.type) {
    case "text":
      return {
        type: "text",
        value: boundedWorkflowText(input.value, 2048, "Condition text"),
      };
    case "number":
      if (!Number.isFinite(input.value)) {
        throw new WorkflowInputError("Condition number must be finite.");
      }
      return input;
    case "boolean":
      return input;
    case "instant":
      return { type: "instant", value: canonicalWorkflowInstant(input.value) };
    default:
      throw new WorkflowInputError("Condition scalar type is unsupported.");
  }
}

function isForbiddenWorkflowCharacter(character: string): boolean {
  const point = character.codePointAt(0);
  return (
    point === undefined ||
    (point < 32 && point !== 9 && point !== 10) ||
    (point >= 127 && point <= 159) ||
    (point >= 0xd800 && point <= 0xdfff) ||
    point === 0x200e ||
    point === 0x200f ||
    (point >= 0x202a && point <= 0x202e) ||
    (point >= 0x2066 && point <= 0x2069)
  );
}

function normalizeEffects(values: WorkflowEffect[]): WorkflowEffect[] {
  const effects = normalizeUnique(values, (value) => value, "Workflow effects");
  if (
    effects.length < 2 ||
    effects.length > 4 ||
    !effects.includes("activity") ||
    !effects.includes("audit") ||
    effects.some((effect) => !effectOrder.includes(effect))
  ) {
    throw new WorkflowInputError(
      "Every workflow effect plan must include activity and audit.",
    );
  }
  return effects.toSorted(
    (left, right) => effectOrder.indexOf(left) - effectOrder.indexOf(right),
  );
}

function normalizeUnique<T>(
  values: T[],
  normalize: (value: T) => T,
  label: string,
): T[] {
  if (values.length > 64) {
    throw new WorkflowInputError(`${label} exceeds 64 items.`);
  }
  const result = values.map(normalize);
  if (new Set(result).size !== result.length) {
    throw new WorkflowInputError(`${label} must be unique.`);
  }
  return result.toSorted((left, right) =>
    compareText(String(left), String(right)),
  );
}

function normalizePermissions(
  values: WorkflowPermission[],
  label: string,
): WorkflowPermission[] {
  return normalizeUnique(values, (value) => value, label).toSorted(
    (left, right) =>
      workflowPermissionOrder.indexOf(left) -
      workflowPermissionOrder.indexOf(right),
  );
}

function normalizeKey(value: string, label: string): string {
  const key = value.trim().toLowerCase();
  if (!keyPattern.test(key)) {
    throw new WorkflowInputError(`${label} is not a canonical key.`);
  }
  return key;
}

function normalizeConditionKey(value: string): string {
  const key = value.trim().toLowerCase();
  if (!conditionKeyPattern.test(key)) {
    throw new WorkflowInputError("Condition field is not a canonical key.");
  }
  return key;
}

function requireVersion(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new WorkflowInputError(`${label} must be a positive version.`);
  }
  return value;
}

function requireSimulationVersion(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 2_147_483_647) {
    throw new WorkflowInputError(
      "Simulation version must be zero or a positive version.",
    );
  }
  return value;
}

function conditionValueIdentity(value: WorkflowConditionValue): string {
  return `${value.type}:${String(value.value)}`;
}

function compareConditionValues(
  left: WorkflowConditionValue,
  right: WorkflowConditionValue,
): number {
  if (left.type !== right.type) return compareText(left.type, right.type);
  if (left.type === "text" && right.type === "text") {
    return compareUtf8(left.value, right.value);
  }
  if (left.type === "number" && right.type === "number") {
    return left.value < right.value ? -1 : left.value > right.value ? 1 : 0;
  }
  if (left.type === "boolean" && right.type === "boolean") {
    return Number(left.value) - Number(right.value);
  }
  if (left.type === "instant" && right.type === "instant") {
    const leftInstant = parseRfc3339Instant(left.value)!;
    const rightInstant = parseRfc3339Instant(right.value)!;
    return leftInstant < rightInstant ? -1 : leftInstant > rightInstant ? 1 : 0;
  }
  return 0;
}

function canonicalWorkflowInstant(value: string): string {
  const instant = parseRfc3339Instant(value);
  if (instant === undefined) {
    throw new WorkflowInputError(
      "Condition instant must be an RFC 3339 value with an offset.",
    );
  }
  const microseconds = floorDivide(instant, 1_000n);
  const seconds = floorDivide(microseconds, 1_000_000n);
  const fraction = microseconds - seconds * 1_000_000n;
  const base = new Date(Number(seconds * 1_000n)).toISOString();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(base)) {
    throw new WorkflowInputError(
      "Condition instant is outside its safe range.",
    );
  }
  const fractionText = fraction.toString().padStart(6, "0").replace(/0+$/u, "");
  const canonical = `${base.slice(0, 19)}${fractionText ? `.${fractionText}` : ""}Z`;
  if (canonical === "0001-01-01T00:00:00Z") {
    throw new WorkflowInputError(
      "Condition instant is outside its safe range.",
    );
  }
  return canonical;
}

function floorDivide(value: bigint, divisor: bigint): bigint {
  const quotient = value / divisor;
  return value < 0n && value % divisor !== 0n ? quotient - 1n : quotient;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

const textEncoder = new TextEncoder();

function compareUtf8(left: string, right: string): number {
  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function requireReachable(
  initial: string,
  states: WorkflowState[],
  outgoing: Map<string, string[]>,
): void {
  const seen = new Set([initial]);
  const queue = [initial];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const target of outgoing.get(current) ?? []) {
      if (!seen.has(target)) {
        seen.add(target);
        queue.push(target);
      }
    }
  }
  if (seen.size !== states.length) {
    throw new WorkflowInputError(
      "Every workflow state must be reachable from the initial state.",
    );
  }
}
