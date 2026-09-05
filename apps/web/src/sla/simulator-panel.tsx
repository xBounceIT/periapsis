import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { Clock3, FlaskConical, Play } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { z } from "zod";

import { FormField } from "../components/form-field";
import { generateUuidV7 } from "../lib/uuid-v7";
import type {
  SlaPolicy,
  SlaSimulationEvent,
  SlaSimulationFact,
  SlaSimulationRequest,
  SlaSimulationResult,
} from "./model";
import {
  formatSlaDuration,
  formatSlaInstant,
  normalizeSimulationRequest,
  parseBoundedJson,
} from "./model";
import type { SlaAdminApi } from "./sla-api";
import {
  SlaEmpty,
  SlaError,
  SlaLoading,
  SlaNativeSelect,
} from "./sla-primitives";

interface SimulationDraft {
  createdAt: string;
  evaluateAt: string;
  eventsJson: string;
  factsJson: string;
  metricBindings: SlaSimulationRequest["metricBindings"];
  objectId: string;
  objectType: "alert" | "case";
  policyId: string;
  policyVersion: string;
  slaInstanceId: string;
  snapshotEvaluatedAt: string;
  timezone: string;
}

export function SimulatorPanel({
  api,
  canSimulate,
  csrfToken,
  tenantId,
}: {
  api: SlaAdminApi;
  canSimulate: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  const [policies, setPolicies] = useState<SlaPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<SlaSimulationResult | null>(null);
  const [draft, setDraft] = useState<SimulationDraft>(initialSimulationDraft);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    void api
      .listPolicies({
        includeArchived: false,
        signal: controller.signal,
        tenantId,
      })
      .then(
        (page) => {
          if (controller.signal.aborted) return;
          setPolicies(page.items);
          setDraft((current) => {
            if (current.policyId || page.items.length === 0) return current;
            const policy = page.items[0]!;
            return bindPolicy(current, policy);
          });
          setLoading(false);
        },
        (caught: unknown) => {
          if (!controller.signal.aborted) {
            setError(caught);
            setLoading(false);
          }
        },
      );
    return () => controller.abort();
  }, [api, tenantId]);

  async function simulate(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!canSimulate) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const body = simulationRequest(draft);
      const response = await api.simulatePolicy({
        body,
        csrfToken,
        id: draft.policyId,
        tenantId,
      });
      validateSimulationResult(response, body, tenantId, draft.policyId);
      setResult(response);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  if (!canSimulate) {
    return (
      <SlaEmpty
        title="Simulation authority required"
        detail="The backend requires sla.simulate; visibility here is advisory only."
      />
    );
  }
  if (loading) return <SlaLoading label="Loading published policies" />;

  return (
    <div className="sla-simulator">
      <section className="sla-simulator__controls">
        <header>
          <div>
            <p className="section-label">Pure evaluation / no persistence</p>
            <h2>Timeline simulator</h2>
          </div>
          <Badge variant="outline">
            <FlaskConical aria-hidden="true" /> sla.simulate
          </Badge>
        </header>
        {policies.length === 0 ? (
          <SlaEmpty
            title="No published policy"
            detail="Publish at least one active policy before running a simulation."
          />
        ) : (
          <form onSubmit={(event) => void simulate(event)}>
            {error ? (
              <SlaError
                error={error}
                fallback="The simulation could not be evaluated."
              />
            ) : null}
            <div className="sla-form-grid">
              <label
                className="sla-native-select"
                htmlFor="sla-simulation-policy"
              >
                <span>Published policy</span>
                <select
                  id="sla-simulation-policy"
                  value={draft.policyId}
                  onChange={(event) => {
                    const policy = policies.find(
                      (candidate) => candidate.id === event.target.value,
                    );
                    setDraft((current) => ({
                      ...(policy ? bindPolicy(current, policy) : current),
                    }));
                  }}
                >
                  {policies.map((policy) => (
                    <option key={policy.id} value={policy.id}>
                      {policy.name} · v{policy.version}
                    </option>
                  ))}
                </select>
              </label>
              <FormField
                htmlFor="sla-simulation-policy-version"
                label="Pinned policy version"
              >
                <Input
                  id="sla-simulation-policy-version"
                  required
                  type="number"
                  min={1}
                  readOnly
                  value={draft.policyVersion}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      policyVersion: event.target.value,
                    }))
                  }
                />
              </FormField>
              <SlaNativeSelect
                id="sla-simulation-object-type"
                label="Object type"
                options={["alert", "case"] as const}
                value={draft.objectType}
                onChange={(objectType) =>
                  setDraft((current) => ({ ...current, objectType }))
                }
              />
              <FormField
                htmlFor="sla-simulation-object-id"
                label="Example object UUIDv7"
              >
                <Input
                  id="sla-simulation-object-id"
                  required
                  value={draft.objectId}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      objectId: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField
                htmlFor="sla-simulation-created"
                label="Created at"
                hint="RFC 3339 with explicit offset."
              >
                <Input
                  id="sla-simulation-created"
                  required
                  value={draft.createdAt}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      createdAt: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField htmlFor="sla-simulation-evaluate" label="Evaluate at">
                <Input
                  id="sla-simulation-evaluate"
                  required
                  value={draft.evaluateAt}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      evaluateAt: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField
                htmlFor="sla-simulation-snapshot-at"
                label="Fact snapshot at"
              >
                <Input
                  id="sla-simulation-snapshot-at"
                  required
                  value={draft.snapshotEvaluatedAt}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      snapshotEvaluatedAt: event.target.value,
                    }))
                  }
                />
              </FormField>
              <FormField
                htmlFor="sla-simulation-timezone"
                label="Fact snapshot timezone"
              >
                <Input
                  id="sla-simulation-timezone"
                  required
                  value={draft.timezone}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      timezone: event.target.value,
                    }))
                  }
                />
              </FormField>
              <div className="sla-form-grid__wide">
                <FormField
                  htmlFor="sla-simulation-facts"
                  label="Object facts"
                  hint="Only bounded declarative facts consumed by the selected policy."
                >
                  <Textarea
                    id="sla-simulation-facts"
                    rows={7}
                    spellCheck={false}
                    value={draft.factsJson}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        factsJson: event.target.value,
                      }))
                    }
                  />
                </FormField>
              </div>
              <div className="sla-form-grid__wide">
                <FormField
                  htmlFor="sla-simulation-events"
                  label="Ordered timeline events"
                >
                  <Textarea
                    id="sla-simulation-events"
                    rows={8}
                    spellCheck={false}
                    value={draft.eventsJson}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        eventsJson: event.target.value,
                      }))
                    }
                  />
                </FormField>
              </div>
            </div>
            <Button type="submit" disabled={busy}>
              <Play aria-hidden="true" />{" "}
              {busy ? "Evaluating…" : "Run simulation"}
            </Button>
          </form>
        )}
      </section>
      <SimulationOutput result={result} />
    </div>
  );
}

function SimulationOutput({
  result,
}: {
  result: SlaSimulationResult | null;
}): React.JSX.Element {
  if (!result) {
    return (
      <aside className="sla-simulator__output">
        <SlaEmpty
          title="Awaiting a timeline"
          detail="The simulator shows pinned metric deadlines and trigger projections without writing SLA state."
        />
      </aside>
    );
  }
  return (
    <aside className="sla-simulator__output" aria-live="polite">
      <header>
        <div>
          <p className="section-label">Policy v{result.policyVersion}</p>
          <h2>Projected clock</h2>
        </div>
        <Badge variant="secondary">{result.metrics.length} metrics</Badge>
      </header>
      <p className="sla-simulator__digest">
        <span>Simulation binding</span>
        <code>{result.simulationDigest}</code>
      </p>
      <div className="sla-metric-stack">
        {result.metrics.map((metric) => (
          <article
            key={metric.metricDefinitionId}
            className={`sla-metric sla-metric--${metric.state}`}
          >
            <header>
              <div>
                <Clock3 aria-hidden="true" />
                <strong>{metric.metricKey.replaceAll("_", " ")}</strong>
                <code>{metric.metricKey}</code>
              </div>
              <Badge
                variant={
                  metric.state === "breached" ? "destructive" : "outline"
                }
              >
                {metric.state.replaceAll("_", " ")}
              </Badge>
            </header>
            <dl>
              <div>
                <dt>Due</dt>
                <dd>{formatSlaInstant(metric.dueAt)}</dd>
              </div>
              <div>
                <dt>Remaining</dt>
                <dd>{formatSlaDuration(metric.remainingMicros / 1_000_000)}</dd>
              </div>
              <div>
                <dt>Consumed</dt>
                <dd>{metric.consumedPercentage.toFixed(1)}%</dd>
              </div>
            </dl>
            {metric.projectedTriggers.length > 0 ? (
              <ul className="sla-trigger-list">
                {metric.projectedTriggers.map((trigger) => (
                  <li key={trigger.triggerDefinitionId}>
                    <span>{trigger.action.kind.replaceAll("_", " ")}</span>
                    <small>
                      {trigger.eventDriven
                        ? "event-driven"
                        : formatSlaInstant(trigger.scheduledAt)}
                    </small>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="sla-muted">No trigger projected.</p>
            )}
          </article>
        ))}
      </div>
    </aside>
  );
}

function initialSimulationDraft(): SimulationDraft {
  const now = new Date();
  const evaluate = new Date(now.valueOf() + 15 * 60 * 1000);
  return {
    policyId: "",
    policyVersion: "1",
    slaInstanceId: generateUuidV7(),
    metricBindings: [],
    objectType: "case",
    objectId: "",
    createdAt: now.toISOString(),
    evaluateAt: evaluate.toISOString(),
    snapshotEvaluatedAt: now.toISOString(),
    timezone: "Europe/Rome",
    factsJson: JSON.stringify(
      [
        { path: { kind: "severity" }, values: ["high"] },
        { path: { kind: "priority" }, values: ["urgent"] },
        { path: { kind: "tag" }, values: ["ransomware"] },
      ],
      null,
      2,
    ),
    eventsJson: JSON.stringify(
      [
        {
          eventId: generateUuidV7(),
          key: "ticket.created",
          occurredAt: now.toISOString(),
        },
      ],
      null,
      2,
    ),
  };
}

function simulationRequest(draft: SimulationDraft): SlaSimulationRequest {
  return normalizeSimulationRequest({
    policyVersion: Number(draft.policyVersion),
    snapshot: {
      objectType: draft.objectType,
      evaluatedAt: draft.snapshotEvaluatedAt,
      timezone: draft.timezone,
      facts: parseBoundedJson(draft.factsJson, "Simulation facts", (value) =>
        simulationFactsSchema.parse(value),
      ),
    },
    slaInstanceId: draft.slaInstanceId,
    objectId: draft.objectId.trim().toLowerCase(),
    createdAt: draft.createdAt,
    evaluateAt: draft.evaluateAt,
    metricBindings: draft.metricBindings,
    events: parseBoundedJson(draft.eventsJson, "Simulation events", (value) =>
      simulationEventsSchema.parse(value),
    ),
  });
}

const simulationFactsSchema: z.ZodType<SlaSimulationFact[]> = z.array(
  z
    .object({
      path: z
        .object({
          kind: z.enum([
            "customer_tier",
            "severity",
            "priority",
            "category",
            "source",
            "operator_team",
            "tag",
            "custom_field",
            "customer_contact_class",
          ]),
          key: z.string().optional(),
        })
        .strict(),
      values: z.array(z.string()),
    })
    .strict(),
);
const simulationEventsSchema: z.ZodType<SlaSimulationEvent[]> = z.array(
  z
    .object({
      key: z.string(),
      eventId: z.string(),
      occurredAt: z.string(),
    })
    .strict(),
);

function bindPolicy(
  current: SimulationDraft,
  policy: SlaPolicy,
): SimulationDraft {
  return {
    ...current,
    policyId: policy.id,
    policyVersion: String(policy.version),
    slaInstanceId: generateUuidV7(),
    metricBindings: policy.metrics.map((metric) => ({
      metricDefinitionId: metric.id,
      metricInstanceId: generateUuidV7(),
    })),
  };
}

function validateSimulationResult(
  response: SlaSimulationResult,
  request: SlaSimulationRequest,
  tenantId: string,
  policyId: string,
): void {
  const bindings = new Map(
    request.metricBindings.map((binding) => [
      binding.metricDefinitionId,
      binding.metricInstanceId,
    ]),
  );
  const seenMetrics = new Set<string>();
  const validStates = new Set([
    "pending",
    "on_track",
    "at_risk",
    "paused",
    "breached",
    "completed",
  ]);
  const malformed =
    response.tenantId !== tenantId ||
    response.policyId !== policyId ||
    response.policyVersion !== request.policyVersion ||
    !/^[0-9a-f]{64}$/u.test(response.simulationDigest) ||
    response.metrics.length !== bindings.size ||
    response.metrics.some((metric) => {
      const expectedInstance = bindings.get(metric.metricDefinitionId);
      if (
        expectedInstance === undefined ||
        expectedInstance !== metric.metricInstanceId ||
        seenMetrics.has(metric.metricDefinitionId) ||
        !/^[a-z][a-z0-9_.-]{0,63}$/u.test(metric.metricKey) ||
        !validStates.has(metric.state) ||
        !Number.isSafeInteger(metric.remainingMicros) ||
        metric.remainingMicros < 0 ||
        !Number.isFinite(metric.consumedPercentage) ||
        metric.consumedPercentage < 0 ||
        metric.consumedPercentage > 100 ||
        !validOptionalInstant(metric.startedAt) ||
        !validOptionalInstant(metric.dueAt) ||
        !validOptionalInstant(metric.breachedAt) ||
        !validOptionalInstant(metric.completedAt) ||
        metric.projectedTriggers.length > 256
      ) {
        return true;
      }
      seenMetrics.add(metric.metricDefinitionId);
      const triggerIds = new Set<string>();
      return metric.projectedTriggers.some((trigger) => {
        if (
          trigger.metricDefinitionId !== metric.metricDefinitionId ||
          triggerIds.has(trigger.triggerDefinitionId) ||
          !isUuidV7(trigger.triggerDefinitionId) ||
          !validOptionalInstant(trigger.scheduledAt) ||
          (trigger.eventDriven && trigger.scheduledAt !== undefined) ||
          !validSimulationAction(trigger.action)
        ) {
          return true;
        }
        triggerIds.add(trigger.triggerDefinitionId);
        return false;
      });
    });
  if (malformed) {
    throw new TypeError(
      "The SLA simulator returned an inconsistent projection.",
    );
  }
}

function validSimulationAction(
  action: SlaSimulationResult["metrics"][number]["projectedTriggers"][number]["action"],
): boolean {
  switch (action.kind) {
    case "email":
    case "webhook":
    case "assign_operator_team":
      return (
        hasExactActionKeys(action, ["kind", "configurationId"]) &&
        isUuidV7(action.configurationId)
      );
    case "add_tag":
    case "change_priority":
    case "domain_event":
      return (
        hasExactActionKeys(action, ["kind", "value"]) &&
        /^[a-z][a-z0-9_.-]{0,63}$/u.test(action.value)
      );
    case "create_task":
      return (
        hasExactActionKeys(action, ["kind", "text"]) &&
        action.text === action.text.trim() &&
        action.text.length > 0 &&
        new TextEncoder().encode(action.text).byteLength <= 2048 &&
        !/[\r\n]/u.test(action.text)
      );
    case "create_system_alert":
      return (
        hasExactActionKeys(action, ["kind", "value", "allowRecursiveSla"]) &&
        /^[a-z][a-z0-9_.-]{0,63}$/u.test(action.value) &&
        typeof action.allowRecursiveSla === "boolean"
      );
    default:
      return false;
  }
}

function hasExactActionKeys(
  value: object,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value);
  const expectedSet = new Set(expected);
  return (
    actual.length === expectedSet.size &&
    actual.every((key) => expectedSet.has(key))
  );
}

function validOptionalInstant(value: string | undefined): boolean {
  return (
    value === undefined ||
    (/(?:Z|[+-]\d{2}:\d{2})$/u.test(value) &&
      Number.isFinite(Date.parse(value)))
  );
}

function isUuidV7(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
    value,
  );
}
