import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { z } from "zod";

import { FormField } from "../components/form-field";
import { generateUuidV7 } from "../lib/uuid-v7";
import type {
  SlaMatchExpression,
  SlaMetricWrite,
  SlaPolicy,
  SlaPolicyWrite,
  SlaTriggerWrite,
} from "./model";
import { normalizePolicyWrite, parseBoundedJson } from "./model";
import type { SlaAdminApi } from "./sla-api";
import type { SlaResourceEditorProps } from "./versioned-resource-panel";
import { VersionedResourcePanel } from "./versioned-resource-panel";

interface PolicyDraft {
  applyToSlaEngineSource: boolean;
  description: string;
  effectiveFrom: string;
  effectiveUntil: string;
  enabled: boolean;
  id: string;
  key: string;
  keyLocked: boolean;
  matchRuleJson: string;
  metricsJson: string;
  name: string;
  objectTypes: Array<"alert" | "case">;
  priority: string;
  triggersJson: string;
}

export function PolicyPanel({
  api,
  canManage,
  csrfToken,
  tenantId,
}: {
  api: SlaAdminApi;
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  return (
    <VersionedResourcePanel<SlaPolicy, PolicyDraft>
      archive={(input) => api.archivePolicy(input)}
      canManage={canManage}
      create={({ body, ...context }) =>
        api.createPolicy({ ...context, body: policyWrite(body) })
      }
      csrfToken={csrfToken}
      draftFrom={policyDraft}
      editor={(props) => <PolicyEditor {...props} />}
      emptyDetail="Create a deterministic matching lineage with pinned calendars, metrics, and bounded trigger actions."
      eyebrow="Policy matching / metrics"
      get={(input) => api.getPolicy(input)}
      kindLabel="policy"
      list={(input) => api.listPolicies(input)}
      normalize={normalizePolicyDraft}
      renderSummary={(policy) => (
        <small>
          {policy.objectTypes.join(" + ")} · {policy.metrics.length} metrics ·
          priority {policy.priority}
        </small>
      )}
      tenantId={tenantId}
      version={({ body, ...context }) =>
        api.versionPolicy({ ...context, body: policyVersionWrite(body) })
      }
    />
  );
}

function PolicyEditor({
  draft,
  disabled,
  setDraft,
}: SlaResourceEditorProps<PolicyDraft>): React.JSX.Element {
  function toggleObjectType(kind: "alert" | "case", checked: boolean): void {
    setDraft((current) => ({
      ...current,
      objectTypes: checked
        ? [...new Set([...current.objectTypes, kind])]
        : current.objectTypes.filter((candidate) => candidate !== kind),
    }));
  }

  return (
    <div className="sla-form-grid">
      <FormField htmlFor="sla-policy-key" label="Stable key">
        <Input
          id="sla-policy-key"
          required
          maxLength={64}
          disabled={disabled}
          readOnly={draft.keyLocked}
          value={draft.key}
          onChange={(event) =>
            setDraft((current) => ({ ...current, key: event.target.value }))
          }
        />
      </FormField>
      <FormField htmlFor="sla-policy-name" label="Name">
        <Input
          id="sla-policy-name"
          required
          maxLength={120}
          disabled={disabled}
          value={draft.name}
          onChange={(event) =>
            setDraft((current) => ({ ...current, name: event.target.value }))
          }
        />
      </FormField>
      <FormField
        htmlFor="sla-policy-priority"
        label="Matching priority"
        hint="Lower numbers are evaluated first."
      >
        <Input
          id="sla-policy-priority"
          required
          type="number"
          min={-1000000}
          max={1000000}
          disabled={disabled}
          value={draft.priority}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              priority: event.target.value,
            }))
          }
        />
      </FormField>
      <fieldset className="sla-object-types">
        <legend>Object types</legend>
        {(["alert", "case"] as const).map((kind) => (
          <label key={kind}>
            <Checkbox
              disabled={disabled}
              checked={draft.objectTypes.includes(kind)}
              onCheckedChange={(checked) =>
                toggleObjectType(kind, checked === true)
              }
            />
            <span>{kind === "alert" ? "Alerts" : "Cases"}</span>
          </label>
        ))}
      </fieldset>
      <FormField htmlFor="sla-policy-effective-from" label="Effective from">
        <Input
          id="sla-policy-effective-from"
          required
          disabled={disabled}
          value={draft.effectiveFrom}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              effectiveFrom: event.target.value,
            }))
          }
        />
      </FormField>
      <FormField
        htmlFor="sla-policy-effective-until"
        label="Effective until"
        optional
      >
        <Input
          id="sla-policy-effective-until"
          disabled={disabled}
          value={draft.effectiveUntil}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              effectiveUntil: event.target.value,
            }))
          }
        />
      </FormField>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-policy-description"
          label="Description"
          optional
        >
          <Input
            id="sla-policy-description"
            maxLength={1000}
            disabled={disabled}
            value={draft.description}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                description: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-policy-match-rule"
          label="Declarative match"
          hint="Bounded expression tree only; JavaScript, SQL, and arbitrary code are never accepted."
        >
          <Textarea
            id="sla-policy-match-rule"
            rows={8}
            spellCheck={false}
            disabled={disabled}
            value={draft.matchRuleJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                matchRuleJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-policy-metrics"
          label="Metric definitions"
          hint="Each metric pins clock mode, duration, lifecycle events, warning, and audience."
        >
          <Textarea
            id="sla-policy-metrics"
            rows={14}
            spellCheck={false}
            disabled={disabled}
            value={draft.metricsJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                metricsJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
      <label className="sla-checkline">
        <Checkbox
          disabled={disabled}
          checked={draft.enabled}
          onCheckedChange={(checked) =>
            setDraft((current) => ({
              ...current,
              enabled: checked === true,
            }))
          }
        />
        <span>Enable this policy version for new matching decisions</span>
      </label>
      <label className="sla-checkline">
        <Checkbox
          disabled={disabled}
          checked={draft.applyToSlaEngineSource}
          onCheckedChange={(checked) =>
            setDraft((current) => ({
              ...current,
              applyToSlaEngineSource: checked === true,
            }))
          }
        />
        <span>Allow matching system Alerts whose source is sla-engine</span>
      </label>
      <div className="sla-form-grid__wide">
        <FormField
          htmlFor="sla-policy-triggers"
          label="Trigger actions"
          hint="System Alert actions must explicitly pin source to sla-engine to enforce the no-loop boundary."
        >
          <Textarea
            id="sla-policy-triggers"
            rows={11}
            spellCheck={false}
            disabled={disabled}
            value={draft.triggersJson}
            onChange={(event) =>
              setDraft((current) => ({
                ...current,
                triggersJson: event.target.value,
              }))
            }
          />
        </FormField>
      </div>
    </div>
  );
}

function policyDraft(policy?: SlaPolicy): PolicyDraft {
  const definitions = policy
    ? definitionsForNextVersion(policy)
    : defaultDefinitions();
  const effectiveFrom = new Date().toISOString();
  return {
    id: policy?.id ?? generateUuidV7(),
    key: policy?.key ?? "",
    keyLocked: policy !== undefined,
    name: policy?.name ?? "",
    description: policy?.description ?? "",
    objectTypes: policy?.objectTypes ?? ["alert", "case"],
    priority: String(policy?.priority ?? 100),
    effectiveFrom: policy?.effectiveFrom ?? effectiveFrom,
    effectiveUntil: policy?.effectiveUntil ?? "",
    enabled: policy?.enabled ?? true,
    applyToSlaEngineSource: policy?.applyToSlaEngineSource ?? false,
    matchRuleJson: prettyJson(
      policy?.matchRule ?? {
        kind: "predicate",
        predicate: {
          path: { kind: "severity" },
          operator: "one_of",
          values: ["critical", "high"],
        },
      },
    ),
    metricsJson: prettyJson(definitions.metrics),
    triggersJson: prettyJson(definitions.triggers),
  };
}

function normalizePolicyDraft(draft: PolicyDraft): PolicyDraft {
  const value = normalizePolicyWrite(policyWrite(draft));
  return {
    ...draft,
    key: value.key,
    name: value.name,
    description: value.description,
    objectTypes: value.objectTypes,
    priority: String(value.priority),
    effectiveFrom: value.effectiveFrom,
    effectiveUntil: value.effectiveUntil ?? "",
    enabled: value.enabled,
    applyToSlaEngineSource: value.applyToSlaEngineSource,
    matchRuleJson: prettyJson(value.matchRule),
    metricsJson: prettyJson(value.metrics),
    triggersJson: prettyJson(value.triggers),
  };
}

function policyWrite(draft: PolicyDraft): SlaPolicyWrite {
  return normalizePolicyWrite({
    id: draft.id,
    key: draft.key,
    name: draft.name,
    description: draft.description,
    objectTypes: draft.objectTypes,
    priority: Number(draft.priority),
    effectiveFrom: draft.effectiveFrom,
    ...(draft.effectiveUntil.trim()
      ? { effectiveUntil: draft.effectiveUntil }
      : {}),
    enabled: draft.enabled,
    applyToSlaEngineSource: draft.applyToSlaEngineSource,
    matchRule: parseBoundedJson(draft.matchRuleJson, "Policy match", (value) =>
      matchSchema.parse(value),
    ),
    metrics: parseBoundedJson(draft.metricsJson, "Policy metrics", (value) =>
      metricsSchema.parse(value),
    ),
    triggers: parseBoundedJson(draft.triggersJson, "Policy triggers", (value) =>
      triggersSchema.parse(value),
    ),
  });
}

function policyVersionWrite(draft: PolicyDraft): Omit<SlaPolicyWrite, "id"> {
  const value = policyWrite(draft);
  return {
    key: value.key,
    name: value.name,
    description: value.description,
    objectTypes: value.objectTypes,
    priority: value.priority,
    matchRule: value.matchRule,
    metrics: value.metrics,
    triggers: value.triggers,
    effectiveFrom: value.effectiveFrom,
    ...(value.effectiveUntil === undefined
      ? {}
      : { effectiveUntil: value.effectiveUntil }),
    enabled: value.enabled,
    applyToSlaEngineSource: value.applyToSlaEngineSource,
  };
}

function defaultDefinitions(): {
  metrics: SlaMetricWrite[];
  triggers: SlaTriggerWrite[];
} {
  const metricId = generateUuidV7();
  return {
    metrics: [
      {
        id: metricId,
        key: "first_response",
        label: "First response",
        description: "Time until the first operator response",
        durationMicros: 1_800_000_000,
        clock: "elapsed",
        startEvent: "ticket.created",
        completionEvent: "response.first",
        resetPolicy: "ignore",
        warning: {
          kind: "remaining_duration",
          remainingMicros: 900_000_000,
        },
        breachGraceMicros: 0,
        displayFormat: "duration",
        customerVisible: true,
        apiVisible: true,
      },
    ],
    triggers: [],
  };
}

function definitionsForNextVersion(policy: SlaPolicy): {
  metrics: SlaMetricWrite[];
  triggers: SlaTriggerWrite[];
} {
  const replacements = new Map<string, string>();
  const metrics = policy.metrics.map((metric) => {
    const id = generateUuidV7();
    replacements.set(metric.id, id);
    return metricWrite(metric, id);
  });
  const triggers = policy.triggers.map((trigger) => {
    const metricDefinitionId = replacements.get(trigger.metricDefinitionId);
    if (!metricDefinitionId) {
      throw new TypeError(
        "Published SLA trigger references a metric outside its policy.",
      );
    }
    return triggerWrite(trigger, generateUuidV7(), metricDefinitionId);
  });
  return { metrics, triggers };
}

function metricWrite(
  metric: SlaPolicy["metrics"][number],
  id: string,
): SlaMetricWrite {
  return {
    id,
    key: metric.key,
    label: metric.label,
    description: metric.description,
    durationMicros: metric.durationMicros,
    clock: metric.clock,
    ...(metric.calendarId === undefined
      ? {}
      : {
          calendarId: metric.calendarId,
          calendarVersion: metric.calendarVersion,
        }),
    startEvent: metric.startEvent,
    ...(metric.pauseEvent === undefined
      ? {}
      : { pauseEvent: metric.pauseEvent }),
    ...(metric.resumeEvent === undefined
      ? {}
      : { resumeEvent: metric.resumeEvent }),
    completionEvent: metric.completionEvent,
    ...(metric.resetEvent === undefined
      ? {}
      : { resetEvent: metric.resetEvent }),
    resetPolicy: metric.resetPolicy,
    warning: metric.warning,
    breachGraceMicros: metric.breachGraceMicros,
    displayFormat: metric.displayFormat,
    customerVisible: metric.customerVisible,
    apiVisible: metric.apiVisible,
  };
}

function triggerWrite(
  trigger: SlaPolicy["triggers"][number],
  id: string,
  metricDefinitionId: string,
): SlaTriggerWrite {
  return {
    id,
    metricDefinitionId,
    key: trigger.key,
    kind: trigger.kind,
    ...(trigger.consumedPercent === undefined
      ? {}
      : { consumedPercent: trigger.consumedPercent }),
    ...(trigger.remainingMicros === undefined
      ? {}
      : { remainingMicros: trigger.remainingMicros }),
    ...(trigger.offsetMicros === undefined
      ? {}
      : { offsetMicros: trigger.offsetMicros }),
    ...(trigger.repeatIntervalMicros === undefined
      ? {}
      : { repeatIntervalMicros: trigger.repeatIntervalMicros }),
    ...(trigger.targetState === undefined
      ? {}
      : { targetState: trigger.targetState }),
    action: trigger.action,
  };
}

function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

const factKindSchema = z.enum([
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
]);
const factPathSchema = z
  .object({ kind: factKindSchema, key: z.string().optional() })
  .strict();
const predicateSchema = z
  .object({
    kind: z.literal("predicate"),
    predicate: z
      .object({
        path: factPathSchema,
        operator: z.enum([
          "equals",
          "not_equals",
          "one_of",
          "none_of",
          "exists",
          "not_exists",
        ]),
        values: z.array(z.string()),
      })
      .strict(),
  })
  .strict();
const matchSchema: z.ZodType<SlaMatchExpression> = z.lazy(() =>
  z.union([
    predicateSchema,
    z
      .object({
        kind: z.enum(["all", "any"]),
        children: z.array(matchSchema),
      })
      .strict(),
    z
      .object({
        kind: z.literal("not"),
        children: z.tuple([matchSchema]),
      })
      .strict(),
  ]),
);
const metricSchema: z.ZodType<SlaMetricWrite> = z
  .object({
    id: z.string(),
    key: z.string(),
    label: z.string(),
    description: z.string(),
    durationMicros: z.number().finite(),
    clock: z.enum(["elapsed", "business"]),
    calendarId: z.string().optional(),
    calendarVersion: z.number().finite().optional(),
    startEvent: z.string(),
    pauseEvent: z.string().optional(),
    resumeEvent: z.string().optional(),
    completionEvent: z.string(),
    resetEvent: z.string().optional(),
    resetPolicy: z.enum(["ignore", "clear", "restart"]),
    warning: z.union([
      z.object({ kind: z.literal("none") }).strict(),
      z
        .object({
          kind: z.literal("consumed_percent"),
          consumedPercent: z.number().finite(),
        })
        .strict(),
      z
        .object({
          kind: z.literal("remaining_duration"),
          remainingMicros: z.number().finite(),
        })
        .strict(),
    ]),
    breachGraceMicros: z.number().finite(),
    displayFormat: z.string(),
    customerVisible: z.boolean(),
    apiVisible: z.boolean(),
  })
  .strict();
const metricsSchema: z.ZodType<SlaMetricWrite[]> = z.array(metricSchema);
const triggerSchema: z.ZodType<SlaTriggerWrite> = z
  .object({
    id: z.string(),
    metricDefinitionId: z.string(),
    key: z.string(),
    kind: z.enum([
      "consumed_percent",
      "remaining_duration",
      "due",
      "after_breach",
      "repeated_after_breach",
      "state_changed",
      "resumed",
    ]),
    consumedPercent: z.number().finite().optional(),
    remainingMicros: z.number().finite().optional(),
    offsetMicros: z.number().finite().optional(),
    repeatIntervalMicros: z.number().finite().optional(),
    targetState: z
      .enum([
        "pending",
        "on_track",
        "at_risk",
        "paused",
        "breached",
        "completed",
      ])
      .optional(),
    action: z.union([
      z
        .object({
          kind: z.enum(["email", "webhook", "assign_operator_team"]),
          configurationId: z.string(),
        })
        .strict(),
      z
        .object({
          kind: z.enum(["add_tag", "change_priority", "domain_event"]),
          value: z.string(),
        })
        .strict(),
      z.object({ kind: z.literal("create_task"), text: z.string() }).strict(),
      z
        .object({
          kind: z.literal("create_system_alert"),
          value: z.string(),
          allowRecursiveSla: z.boolean(),
        })
        .strict(),
    ]),
  })
  .strict();
const triggersSchema: z.ZodType<SlaTriggerWrite[]> = z.array(triggerSchema);
