import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Clock3, Gauge, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { FormField } from "../components/form-field";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { generateUuidV7 } from "../lib/uuid-v7";
import type {
  OperatorTicketSlaProjection,
  SlaColumnProjection,
  SlaCustomerColumnProjection,
  SlaMetricProjection,
  SlaObjectType,
  SlaOverrideKind,
  SlaOverrideRequest,
  TicketSlaProjection,
  VersionedSlaResource,
} from "./model";
import {
  formatSlaDuration,
  formatSlaInstant,
  normalizeOverride,
  SlaInputError,
} from "./model";
import type { SlaAdminApi } from "./sla-api";
import {
  SlaEmpty,
  SlaError,
  SlaLoading,
  SlaNativeSelect,
} from "./sla-primitives";
// oxlint-disable-next-line import/no-unassigned-import -- Module-local SLA visual language.
import "./sla.css";

const overrideKinds = [
  "extend",
  "suspend",
  "resume",
  "complete",
  "change_calendar",
  "change_policy",
  "recalculate",
] as const;

export function TicketSlaPanel(props: {
  api: SlaAdminApi;
  canOverride: boolean;
  canRead: boolean;
  csrfToken: string;
  expectedAudience: TicketSlaProjection["audience"];
  kind: SlaObjectType;
  objectId: string;
  tenantId: string;
}): React.JSX.Element {
  const model = useTicketSlaPanelModel(props);
  if (model.kind === "content") return model.content;
  return <TicketSlaPanelView model={model.data} />;
}

function useTicketSlaPanelModel({
  api,
  canOverride,
  canRead,
  csrfToken,
  expectedAudience,
  kind,
  objectId,
  tenantId,
}: {
  api: SlaAdminApi;
  canOverride: boolean;
  canRead: boolean;
  csrfToken: string;
  expectedAudience: TicketSlaProjection["audience"];
  kind: SlaObjectType;
  objectId: string;
  tenantId: string;
}) {
  const [projection, setProjection] =
    useState<VersionedSlaResource<TicketSlaProjection> | null>(null);
  const [loading, setLoading] = useState(canRead);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [kindOverride, setKindOverride] = useState<SlaOverrideKind>("extend");
  const [metricKey, setMetricKey] = useState("");
  const [reason, setReason] = useState("");
  const [extensionSeconds, setExtensionSeconds] = useState("900");
  const [targetId, setTargetId] = useState("");
  const [targetVersion, setTargetVersion] = useState("1");
  const [simulationDigest, setSimulationDigest] = useState("");
  const attempt = useRef<IdempotencyReference>({ current: null });
  const overrideIdentity = useRef<{ fingerprint: string; id: string } | null>(
    null,
  );

  useEffect(() => {
    if (!canRead) {
      setProjection(null);
      setLoading(false);
      return undefined;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    void api
      .getTicketSla({
        audience: expectedAudience,
        kind,
        objectId,
        signal: controller.signal,
        tenantId,
      })
      .then((value) => {
        if (controller.signal.aborted) return;
        validateTicketProjection(
          value.value,
          tenantId,
          kind,
          objectId,
          expectedAudience,
        );
        validateStrongEtag(value.etag);
        setProjection(value);
        setMetricKey(value.value.metrics[0]?.key ?? "");
        setLoading(false);
      })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) {
          setError(caught);
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [api, canRead, expectedAudience, kind, objectId, tenantId]);

  async function applyOverride(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canOverride || !projection || projection.value.audience !== "operator")
      return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const operatorProjection = projection.value;
      const selectedMetric = operatorProjection.metrics.find(
        (metric) => metric.key === metricKey,
      );
      const fingerprint = JSON.stringify({
        aggregateVersion: operatorProjection.aggregateVersion,
        etag: projection.etag,
        extensionSeconds,
        kind: kindOverride,
        metricKey,
        reason,
        simulationDigest,
        slaInstanceId: operatorProjection.slaInstanceId,
        targetId,
        targetVersion,
      });
      if (overrideIdentity.current?.fingerprint !== fingerprint) {
        overrideIdentity.current = { fingerprint, id: generateUuidV7() };
      }
      const body = overrideRequest({
        aggregateVersion: operatorProjection.aggregateVersion,
        extensionSeconds,
        kind: kindOverride,
        overrideId: overrideIdentity.current.id,
        reason,
        selectedMetric,
        simulationDigest,
        slaInstanceId: operatorProjection.slaInstanceId,
        targetId,
        targetVersion,
      });
      const idempotencyKey = idempotencyKeyForPayload(attempt.current, {
        kind,
        objectId,
        etag: projection.etag,
        body,
      });
      const result = await api.overrideTicketSla({
        body,
        csrfToken,
        etag: projection.etag,
        idempotencyKey,
        kind,
        objectId,
        tenantId,
      });
      validateTicketProjection(
        result.projection.value,
        tenantId,
        kind,
        objectId,
        expectedAudience,
      );
      validateStrongEtag(result.projection.etag);
      validateOverrideResult(
        result,
        { etag: projection.etag, value: operatorProjection },
        body,
      );
      setProjection(result.projection);
      setNotice(
        `${result.receipt.kind.replaceAll("_", " ")} recorded at ${formatSlaInstant(result.receipt.occurredAt)}${result.receipt.replayed ? " (replayed)" : ""}.`,
      );
      setReason("");
      attempt.current.current = null;
      overrideIdentity.current = null;
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  if (!canRead)
    return {
      kind: "content" as const,
      content: (
        <SlaEmpty
          title="SLA authority required"
          detail="The ticket API revalidates sla.read and ticket scope before returning any clock."
        />
      ),
    };
  if (loading)
    return {
      kind: "content" as const,
      content: <SlaLoading label="Loading SLA projection" />,
    };
  if (error && !projection)
    return {
      kind: "content" as const,
      content: (
        <SlaError
          error={error}
          fallback="The SLA projection could not be loaded."
        />
      ),
    };
  if (!projection)
    return {
      kind: "content" as const,
      content: (
        <SlaEmpty
          title="No SLA assigned"
          detail="No active policy matched this ticket at the pinned assignment event."
        />
      ),
    };

  const value = projection.value;
  return {
    kind: "ready" as const,
    data: {
      applyOverride,
      busy,
      canOverride,
      error,
      extensionSeconds,
      kind,
      kindOverride,
      metricKey,
      notice,
      reason,
      setExtensionSeconds,
      setKindOverride,
      setMetricKey,
      setReason,
      setSimulationDigest,
      setTargetId,
      setTargetVersion,
      simulationDigest,
      targetId,
      targetVersion,
      value,
    },
  };
}

function TicketSlaPanelView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTicketSlaPanelModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { value, error, notice, canOverride } = model;
  return (
    <div className="ticket-sla">
      <header className="ticket-sla__heading">
        <div>
          <p className="section-label">
            {value.audience === "operator"
              ? `Policy ${compactId(value.policyId)} · v${value.policyVersion}`
              : "Customer-safe projection"}
          </p>
          <h2>Service clocks</h2>
        </div>
        <div>
          <Badge variant="outline">{value.audience} projection</Badge>
          {value.audience === "operator" ? (
            <Badge variant="secondary">
              aggregate v{value.aggregateVersion}
            </Badge>
          ) : null}
        </div>
      </header>
      {error ? (
        <SlaError
          error={error}
          fallback="The SLA operation could not be completed."
        />
      ) : null}
      {notice ? (
        <p className="sla-notice" role="status">
          {notice}
        </p>
      ) : null}
      <div className="ticket-sla__metrics">
        {value.metrics.map((metric) => (
          <TicketSlaMetric key={metric.key} metric={metric} />
        ))}
      </div>
      {value.columns.length > 0 ? (
        <section className="ticket-sla__columns">
          <h3>
            <Gauge aria-hidden="true" /> Materialized columns
          </h3>
          <dl>
            {value.columns.map((column) => (
              <div key={column.key}>
                <dt>{column.label}</dt>
                <dd>{formatColumnValue(column)}</dd>
                <small>
                  {column.styleKey ? `${column.styleKey} · ` : ""}
                  {formatSlaInstant(column.materializedAt)}
                </small>
              </div>
            ))}
          </dl>
        </section>
      ) : null}
      {canOverride && value.audience === "operator" ? (
        <TicketSlaOverride model={model} />
      ) : null}
    </div>
  );
}

function validateTicketProjection(
  value: TicketSlaProjection,
  tenantId: string,
  kind: SlaObjectType,
  objectId: string,
  expectedAudience: TicketSlaProjection["audience"],
): void {
  const topLevel: Record<string, unknown> = { ...value };
  const operator = value.audience === "operator";
  const topLevelKeys = operator
    ? [
        "audience",
        "tenantId",
        "objectType",
        "objectId",
        "slaInstanceId",
        "aggregateVersion",
        "policyId",
        "policyVersion",
        "projectedAt",
        "metrics",
        "columns",
      ]
    : [
        "audience",
        "tenantId",
        "objectType",
        "objectId",
        "projectedAt",
        "metrics",
        "columns",
      ];
  const metricKeys = new Set<string>();
  const metricInstanceIds = new Set<string>();
  const invalidMetric = value.metrics.some((metric) => {
    const record: Record<string, unknown> = { ...metric };
    const commonRequired = [
      "key",
      "label",
      "state",
      "remainingSeconds",
      "consumedPercentage",
    ];
    const commonAllowed = [
      ...commonRequired,
      "startedAt",
      "dueAt",
      "breachedAt",
      "completedAt",
    ];
    if (
      !hasAllowedAndRequiredKeys(
        record,
        operator
          ? [
              ...commonRequired,
              "metricDefinitionId",
              "metricInstanceId",
              "metricVersion",
              "customerVisible",
            ]
          : commonRequired,
        operator
          ? [
              ...commonAllowed,
              "pausedAt",
              "metricDefinitionId",
              "metricInstanceId",
              "metricVersion",
              "customerVisible",
            ]
          : commonAllowed,
      ) ||
      !isCanonicalKey(metric.key) ||
      metric.label.trim().length === 0 ||
      !isMetricState(metric.state) ||
      !Number.isSafeInteger(metric.remainingSeconds) ||
      !Number.isFinite(metric.consumedPercentage) ||
      !validProjectionInstants(record, operator)
    )
      return true;
    if (metricKeys.has(metric.key)) return true;
    metricKeys.add(metric.key);
    if (!operator) return false;
    const metricDefinitionId = record.metricDefinitionId;
    const metricInstanceId = record.metricInstanceId;
    const metricVersion = record.metricVersion;
    if (
      typeof metricDefinitionId !== "string" ||
      !isUuidV7(metricDefinitionId) ||
      typeof metricInstanceId !== "string" ||
      !isUuidV7(metricInstanceId) ||
      typeof metricVersion !== "number" ||
      !isPositiveVersion(metricVersion) ||
      typeof record.customerVisible !== "boolean" ||
      metricInstanceIds.has(metricInstanceId)
    ) {
      return true;
    }
    metricInstanceIds.add(metricInstanceId);
    return false;
  });
  const columnKeys = new Set<string>();
  const invalidColumn = value.columns.some((column) => {
    const record: Record<string, unknown> = { ...column };
    const commonRequired = [
      "key",
      "label",
      "calculation",
      "format",
      "state",
      "materializedAt",
    ];
    const commonAllowed = [
      ...commonRequired,
      "instant",
      "durationMicros",
      "percentage",
      "styleKey",
    ];
    if (
      !hasAllowedAndRequiredKeys(
        record,
        operator
          ? [...commonRequired, "columnId", "customerVisible"]
          : commonRequired,
        operator
          ? [...commonAllowed, "columnId", "customerVisible"]
          : commonAllowed,
      ) ||
      !isCanonicalKey(column.key) ||
      column.label.trim().length === 0 ||
      !isColumnCalculation(column.calculation) ||
      !isColumnFormat(column.format) ||
      !isMetricState(column.state) ||
      !isRfc3339Instant(column.materializedAt) ||
      !validColumnValue(record, column.format) ||
      columnKeys.has(column.key)
    )
      return true;
    columnKeys.add(column.key);
    if (!operator) return false;
    const columnId = record.columnId;
    return (
      typeof columnId !== "string" ||
      !isUuidV7(columnId) ||
      typeof record.customerVisible !== "boolean"
    );
  });
  if (
    !hasAllowedAndRequiredKeys(topLevel, topLevelKeys, topLevelKeys) ||
    value.tenantId !== tenantId ||
    value.objectType !== kind ||
    value.objectId !== objectId ||
    value.audience !== expectedAudience ||
    !isRfc3339Instant(value.projectedAt) ||
    value.metrics.length > 32 ||
    value.columns.length > 1024 ||
    (value.audience !== "operator" && value.audience !== "customer") ||
    invalidMetric ||
    invalidColumn ||
    (operator &&
      (!isUuidV7(value.slaInstanceId) ||
        !isPositiveVersion(value.aggregateVersion) ||
        !isUuidV7(value.policyId) ||
        !isPositiveVersion(value.policyVersion)))
  ) {
    throw new TypeError(
      "The SLA endpoint returned a projection outside the requested audience boundary.",
    );
  }
}

function validateOverrideResult(
  result: Awaited<ReturnType<SlaAdminApi["overrideTicketSla"]>>,
  previous: VersionedSlaResource<OperatorTicketSlaProjection>,
  request: SlaOverrideRequest,
): void {
  const { projection, receipt } = result;
  const nextAggregateVersion = previous.value.aggregateVersion + 1;
  const expectedSimulationDigest =
    request.kind === "change_calendar" ||
    request.kind === "change_policy" ||
    request.kind === "recalculate"
      ? request.simulationDigest
      : undefined;
  if (
    projection.etag === previous.etag ||
    projection.value.audience !== "operator" ||
    projection.value.slaInstanceId !== request.slaInstanceId ||
    projection.value.aggregateVersion !== nextAggregateVersion ||
    receipt.tenantId !== previous.value.tenantId ||
    receipt.objectType !== previous.value.objectType ||
    receipt.objectId !== previous.value.objectId ||
    receipt.overrideId !== request.overrideId ||
    receipt.kind !== request.kind ||
    receipt.slaInstanceId !== request.slaInstanceId ||
    receipt.aggregateVersion !== nextAggregateVersion ||
    receipt.policyId !== projection.value.policyId ||
    receipt.policyVersion !== projection.value.policyVersion ||
    receipt.simulationDigest !== expectedSimulationDigest ||
    typeof receipt.replayed !== "boolean" ||
    !isRfc3339Instant(receipt.occurredAt)
  ) {
    throw new TypeError(
      "The SLA override endpoint returned an inconsistent mutation receipt.",
    );
  }

  if (request.kind === "change_policy") {
    if (
      receipt.outcome !== "policy_changed" ||
      receipt.metricInstanceId !== undefined ||
      receipt.previousVersion !== request.expectedAggregateVersion ||
      receipt.currentVersion !== nextAggregateVersion ||
      projection.value.policyId !== request.newPolicyId ||
      projection.value.policyVersion !== request.newPolicyVersion
    ) {
      throw new TypeError(
        "The SLA override endpoint returned an inconsistent policy transition.",
      );
    }
    return;
  }

  const updatedMetric = projection.value.metrics.find(
    (metric) => metric.metricInstanceId === request.metricInstanceId,
  );
  if (
    receipt.outcome !== "metric_updated" ||
    receipt.metricInstanceId !== request.metricInstanceId ||
    receipt.previousVersion !== request.expectedMetricVersion ||
    receipt.currentVersion !== request.expectedMetricVersion + 1 ||
    updatedMetric?.metricVersion !== receipt.currentVersion
  ) {
    throw new TypeError(
      "The SLA override endpoint returned an inconsistent metric transition.",
    );
  }
}

function validateStrongEtag(value: string): void {
  if (
    value.length < 3 ||
    value.length > 194 ||
    value.startsWith("W/") ||
    value[0] !== '"' ||
    value.at(-1) !== '"' ||
    value.slice(1, -1).includes('"') ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0);
      return point === undefined || point < 33 || point === 127;
    })
  ) {
    throw new TypeError("The SLA endpoint returned a malformed strong ETag.");
  }
}

function overrideRequest(input: {
  aggregateVersion: number;
  extensionSeconds: string;
  kind: SlaOverrideKind;
  overrideId: string;
  reason: string;
  selectedMetric: SlaMetricProjection | undefined;
  simulationDigest: string;
  slaInstanceId: string;
  targetId: string;
  targetVersion: string;
}): SlaOverrideRequest {
  const base = {
    overrideId: input.overrideId,
    reason: input.reason,
    slaInstanceId: input.slaInstanceId,
  };
  if (input.kind === "change_policy") {
    return normalizeOverride({
      ...base,
      kind: "change_policy",
      expectedAggregateVersion: input.aggregateVersion,
      newPolicyId: input.targetId,
      newPolicyVersion: Number(input.targetVersion),
      simulationDigest: input.simulationDigest,
    });
  }
  if (!input.selectedMetric) {
    throw new SlaInputError("Select the exact metric to override.");
  }
  const metric = {
    ...base,
    metricInstanceId: input.selectedMetric.metricInstanceId,
    expectedMetricVersion: input.selectedMetric.metricVersion,
  };
  switch (input.kind) {
    case "extend":
      return normalizeOverride({
        ...metric,
        kind: "extend",
        extensionMicros: Number(input.extensionSeconds) * 1_000_000,
      });
    case "suspend":
    case "resume":
    case "complete":
      return normalizeOverride({ ...metric, kind: input.kind });
    case "change_calendar":
      return normalizeOverride({
        ...metric,
        kind: "change_calendar",
        replacementCalendarId: input.targetId,
        replacementCalendarVersion: Number(input.targetVersion),
        simulationDigest: input.simulationDigest,
      });
    case "recalculate":
      return normalizeOverride({
        ...metric,
        kind: "recalculate",
        simulationDigest: input.simulationDigest,
      });
    default:
      throw new SlaInputError("Override kind is unsupported.");
  }
}

function requiresMetric(kind: SlaOverrideKind): boolean {
  return kind !== "change_policy";
}

function isUuidV7(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
    value,
  );
}

function isPositiveVersion(value: number | undefined): value is number {
  return Number.isSafeInteger(value) && value! >= 1;
}

function isRfc3339Instant(value: string): boolean {
  return (
    /(?:Z|[+-]\d{2}:\d{2})$/u.test(value) && Number.isFinite(Date.parse(value))
  );
}

function compactId(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value;
}

function formatColumnValue(
  column: SlaColumnProjection | SlaCustomerColumnProjection,
): string {
  if (column.format === "datetime") return formatSlaInstant(column.instant);
  if (column.format === "duration")
    return column.durationMicros === undefined
      ? "Not available"
      : formatSlaDuration(column.durationMicros / 1_000_000);
  if (column.format === "percentage")
    return column.percentage === undefined
      ? "Not available"
      : `${column.percentage.toFixed(1)}%`;
  return column.state.replaceAll("_", " ");
}

function hasAllowedAndRequiredKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  allowed: readonly string[],
): boolean {
  const allowedSet = new Set(allowed);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowedSet.has(key))
  );
}

function validProjectionInstants(
  value: Record<string, unknown>,
  operator: boolean,
): boolean {
  const keys = operator
    ? ["startedAt", "pausedAt", "dueAt", "breachedAt", "completedAt"]
    : ["startedAt", "dueAt", "breachedAt", "completedAt"];
  return keys.every(
    (key) => value[key] === undefined || validUnknownInstant(value[key]),
  );
}

function validUnknownInstant(value: unknown): boolean {
  return typeof value === "string" && isRfc3339Instant(value);
}

function validColumnValue(
  value: Record<string, unknown>,
  format: SlaColumnProjection["format"],
): boolean {
  const hasInstant = value.instant !== undefined;
  const hasDuration = value.durationMicros !== undefined;
  const hasPercentage = value.percentage !== undefined;
  if (Number(hasInstant) + Number(hasDuration) + Number(hasPercentage) > 1)
    return false;
  return (
    (!hasInstant ||
      (format === "datetime" && validUnknownInstant(value.instant))) &&
    (!hasDuration ||
      (format === "duration" && Number.isSafeInteger(value.durationMicros))) &&
    (!hasPercentage ||
      (format === "percentage" && Number.isFinite(value.percentage))) &&
    (value.styleKey === undefined ||
      (typeof value.styleKey === "string" && isCanonicalKey(value.styleKey)))
  );
}

function isCanonicalKey(value: string): boolean {
  return /^[a-z][a-z0-9_.-]{0,63}$/u.test(value);
}

function isMetricState(value: string): boolean {
  return [
    "pending",
    "on_track",
    "at_risk",
    "paused",
    "breached",
    "completed",
  ].includes(value);
}

function isColumnCalculation(value: string): boolean {
  return [
    "due_at",
    "remaining_seconds",
    "state",
    "consumed_percentage",
    "breached_at",
  ].includes(value);
}

function isColumnFormat(value: string): boolean {
  return ["datetime", "duration", "state_badge", "percentage"].includes(value);
}

function TicketSlaMetric({
  metric,
}: {
  metric: TicketSlaProjection["metrics"][number];
}): React.JSX.Element {
  return (
    <article className={`sla-metric sla-metric--${metric.state}`}>
      <header>
        <div>
          <Clock3 aria-hidden="true" />
          <strong>{metric.label}</strong>
          <code>{metric.key}</code>
        </div>
        <Badge
          variant={metric.state === "breached" ? "destructive" : "outline"}
        >
          {metric.state.replaceAll("_", " ")}
        </Badge>
      </header>
      <meter
        className="sr-only"
        aria-label={`${metric.label} consumed`}
        min={0}
        max={100}
        value={Math.max(0, Math.min(100, metric.consumedPercentage))}
      />
      <div className="sla-progress" aria-hidden="true">
        <span
          style={{
            width: `${Math.max(0, Math.min(100, metric.consumedPercentage))}%`,
          }}
        />
      </div>
      <dl>
        <div>
          <dt>Due</dt>
          <dd>{formatSlaInstant(metric.dueAt)}</dd>
        </div>
        <div>
          <dt>Remaining</dt>
          <dd>{formatSlaDuration(metric.remainingSeconds)}</dd>
        </div>
        <div>
          <dt>Consumed</dt>
          <dd>{metric.consumedPercentage.toFixed(1)}%</dd>
        </div>
      </dl>
    </article>
  );
}

function TicketSlaOverride({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTicketSlaPanelModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    applyOverride,
    busy,
    extensionSeconds,
    kind,
    kindOverride,
    metricKey,
    reason,
    setExtensionSeconds,
    setKindOverride,
    setMetricKey,
    setReason,
    setSimulationDigest,
    setTargetId,
    setTargetVersion,
    simulationDigest,
    targetId,
    targetVersion,
    value,
  } = model;
  return (
    <form
      className="sla-override"
      onSubmit={(event) => void applyOverride(event)}
    >
      <header>
        <div>
          <ShieldCheck aria-hidden="true" />
          <div>
            <p className="section-label">Privileged mutation</p>
            <h3>Override SLA</h3>
          </div>
        </div>
        <Badge variant="outline">{kind}.sla.override</Badge>
      </header>
      <div className="sla-form-grid">
        <SlaNativeSelect
          id="sla-override-kind"
          label="Override"
          options={overrideKinds}
          value={kindOverride}
          onChange={setKindOverride}
        />
        {requiresMetric(kindOverride) ? (
          <label className="sla-native-select" htmlFor="sla-override-metric">
            <span>Metric</span>
            <select
              id="sla-override-metric"
              value={metricKey}
              onChange={(event) => setMetricKey(event.target.value)}
            >
              {value.metrics.map((metric) => (
                <option key={metric.key} value={metric.key}>
                  {metric.label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {kindOverride === "extend" ? (
          <FormField htmlFor="sla-override-extension" label="Extension seconds">
            <Input
              id="sla-override-extension"
              required
              type="number"
              min={60}
              value={extensionSeconds}
              onChange={(event) => setExtensionSeconds(event.target.value)}
            />
          </FormField>
        ) : null}
        {kindOverride === "change_calendar" ||
        kindOverride === "change_policy" ? (
          <FormField
            htmlFor="sla-override-target-id"
            label={
              kindOverride === "change_calendar" ? "Calendar ID" : "Policy ID"
            }
          >
            <Input
              id="sla-override-target-id"
              required
              value={targetId}
              onChange={(event) => setTargetId(event.target.value)}
            />
          </FormField>
        ) : null}
        {kindOverride === "change_calendar" ||
        kindOverride === "change_policy" ? (
          <FormField
            htmlFor="sla-override-target-version"
            label="Pinned version"
          >
            <Input
              id="sla-override-target-version"
              required
              type="number"
              min={1}
              value={targetVersion}
              onChange={(event) => setTargetVersion(event.target.value)}
            />
          </FormField>
        ) : null}
        {kindOverride === "change_calendar" ||
        kindOverride === "change_policy" ||
        kindOverride === "recalculate" ? (
          <FormField htmlFor="sla-override-digest" label="Simulation digest">
            <Input
              id="sla-override-digest"
              required
              value={simulationDigest}
              onChange={(event) => setSimulationDigest(event.target.value)}
            />
          </FormField>
        ) : null}
        <div className="sla-form-grid__wide">
          <FormField htmlFor="sla-override-reason" label="Audited reason">
            <Input
              id="sla-override-reason"
              required
              minLength={8}
              maxLength={1000}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </FormField>
        </div>
      </div>
      <Button type="submit" disabled={busy || reason.trim().length < 8}>
        {busy ? "Applying…" : "Apply governed override"}
      </Button>
    </form>
  );
}
