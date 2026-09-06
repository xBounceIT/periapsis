import { z } from "zod";
import {
  normalizeWorkflowDesign,
  WorkflowInputError,
  type ManagedWorkflow,
  type WorkflowCondition,
  type WorkflowConditionValue,
  type WorkflowDesign,
  type WorkflowKind,
  type WorkflowPermission,
  type WorkflowState,
  type WorkflowTransition,
} from "./model";

export interface WorkflowDraft {
  kind: WorkflowKind;
  key: string;
  displayName: string;
  description: string;
  statesJson: string;
  transitionsJson: string;
}

export function workflowDraftFrom(
  kind: WorkflowKind,
  resource?: ManagedWorkflow,
): WorkflowDraft {
  const design = resource?.current ?? defaultWorkflowDesign(kind);
  return {
    kind,
    key:
      resource?.key ??
      (kind === "alert" ? "alert_triage" : "case_investigation"),
    displayName:
      resource?.displayName ??
      (kind === "alert" ? "Alert triage" : "Case investigation"),
    description: resource?.description ?? "",
    statesJson: JSON.stringify(design.states, null, 2),
    transitionsJson: JSON.stringify(design.transitions, null, 2),
  };
}

export function workflowDesignFromDraft(draft: WorkflowDraft): WorkflowDesign {
  return normalizeWorkflowDesign(draft.kind, {
    states: parseWorkflowJson(
      draft.statesJson,
      "Workflow states",
      workflowStatesSchema,
      128 * 1024,
    ),
    transitions: parseWorkflowJson(
      draft.transitionsJson,
      "Workflow transitions",
      workflowTransitionsSchema,
      512 * 1024,
    ),
  });
}

export function parseWorkflowJson<T>(
  source: string,
  label: string,
  schema: z.ZodType<T>,
  maximumBytes: number,
): T {
  if (
    source.trim().length === 0 ||
    new TextEncoder().encode(source).byteLength > maximumBytes
  ) {
    throw new WorkflowInputError(`${label} is empty or exceeds its bound.`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new WorkflowInputError(`${label} must be valid JSON.`);
  }
  requireBoundedJsonShape(parsed, label);
  const result = schema.safeParse(parsed);
  if (!result.success) {
    throw new WorkflowInputError(`${label} has an unsupported shape.`);
  }
  return result.data;
}

export function requireBoundedJsonShape(value: unknown, label: string): void {
  const pending: Array<{ depth: number; value: unknown }> = [
    { depth: 0, value },
  ];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    nodes += 1;
    if (current.depth > 24 || nodes > 100_000) {
      throw new WorkflowInputError(`${label} has an unsupported shape.`);
    }
    if (Array.isArray(current.value)) {
      if (current.value.length > 500) {
        throw new WorkflowInputError(`${label} has an unsupported shape.`);
      }
      for (const item of current.value) {
        pending.push({ depth: current.depth + 1, value: item });
      }
    } else if (isJsonRecord(current.value)) {
      const values = Object.values(current.value);
      if (values.length > 64) {
        throw new WorkflowInputError(`${label} has an unsupported shape.`);
      }
      for (const item of values) {
        pending.push({ depth: current.depth + 1, value: item });
      }
    }
  }
}

export function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function defaultWorkflowDesign(kind: WorkflowKind): WorkflowDesign {
  const permission: WorkflowPermission =
    kind === "alert" ? "alert.update" : "case.transition";
  return {
    states: [
      {
        key: "new",
        initial: true,
        terminal: false,
        visibility: "internal",
        actions: [
          {
            action: "create",
            effects: ["activity", "audit", "sla"],
          },
        ],
      },
      {
        key: "closed",
        initial: false,
        terminal: true,
        visibility: "internal",
        actions: [],
      },
    ],
    transitions: [
      {
        key: "close",
        from: "new",
        to: "closed",
        requiredComment: true,
        reopen: false,
        requiredRoles: [],
        requiredPermissions: [permission],
        requiredCustomFields: [],
        effects: ["activity", "audit", "sla"],
      },
    ],
  };
}

export const effectSchema = z.enum([
  "activity",
  "audit",
  "sla",
  "notification",
]);

export const actionSchema = z.enum([
  "create",
  "assign",
  "claim",
  "release",
  "transfer",
  "escalate",
  "link",
]);

export const permissionSchema = z.enum([
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
]);

export const conditionValueSchema: z.ZodType<WorkflowConditionValue> =
  z.discriminatedUnion("type", [
    z.strictObject({ type: z.literal("text"), value: z.string() }),
    z.strictObject({ type: z.literal("number"), value: z.number() }),
    z.strictObject({ type: z.literal("boolean"), value: z.boolean() }),
    z.strictObject({ type: z.literal("instant"), value: z.string() }),
  ]);

export const conditionSchema: z.ZodType<WorkflowCondition> = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("predicate"),
      field: z.string(),
      operator: z.enum([
        "equal",
        "not_equal",
        "in",
        "not_in",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
        "exists",
        "not_exists",
      ]),
      values: z.array(conditionValueSchema),
    }),
    z.strictObject({
      kind: z.literal("all"),
      children: z.array(conditionSchema),
    }),
    z.strictObject({
      kind: z.literal("any"),
      children: z.array(conditionSchema),
    }),
    z.strictObject({
      kind: z.literal("not"),
      children: z.tuple([conditionSchema]),
    }),
  ]),
);

export const workflowStateSchema: z.ZodType<WorkflowState> = z.strictObject({
  key: z.string(),
  initial: z.boolean(),
  terminal: z.boolean(),
  visibility: z.enum(["internal", "customer"]),
  actions: z.array(
    z.strictObject({
      action: actionSchema,
      effects: z.array(effectSchema),
    }),
  ),
});

export const workflowTransitionSchema: z.ZodType<WorkflowTransition> =
  z.strictObject({
    key: z.string(),
    from: z.string(),
    to: z.string(),
    requiredComment: z.boolean(),
    reopen: z.boolean(),
    requiredRoles: z.array(z.string()),
    requiredPermissions: z.array(permissionSchema),
    requiredCustomFields: z.array(z.string()),
    condition: conditionSchema.optional(),
    effects: z.array(effectSchema),
  });

export const workflowStatesSchema = z.array(workflowStateSchema);

export const workflowTransitionsSchema = z.array(workflowTransitionSchema);
