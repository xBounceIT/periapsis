import type {
  DeliveryLogger,
  DeliveryRunResult,
  DeliveryTelemetry,
} from "./delivery.js";
import { NotificationValidationError } from "./errors.js";
import type { FanoutRunResult } from "./fanout.js";
import { requireInteger, requireKey, requireText } from "./validation.js";
import { activeTraceCorrelation } from "./telemetry.js";

type DeliveryOutcome = Parameters<DeliveryTelemetry["record"]>[0];

const deliveryOutcomes = new Set<DeliveryOutcome>([
  "delivered",
  "replayed",
  "retried",
  "dead_lettered",
  "uncertain",
]);
const logAttributeNames = new Set([
  "attempt",
  "claimed",
  "deadLettered",
  "deliveries",
  "deliveryId",
  "durationMs",
  "errorClass",
  "eventId",
  "failureClass",
  "iteration",
  "method",
  "outcome",
  "path",
  "release",
  "requestId",
  "replayed",
  "reason",
  "retried",
  "signal",
  "status",
  "tenantId",
  "uncertain",
  "workerId",
]);

export class NotifierMetrics implements DeliveryTelemetry {
  readonly #deliveries = new Map<string, number>();
  readonly #iterations = new Map<string, number>();
  #claimed = 0;
  #fanoutClaims = 0;
  #fanoutDeliveries = 0;
  #queueDepth = 0;
  #oldestPendingSeconds = 0;
  #ready = false;

  record(
    outcome: DeliveryOutcome,
    attributes: Readonly<{ tenantId: string; failureClass?: string }>,
  ): void {
    if (!deliveryOutcomes.has(outcome)) {
      throw new NotificationValidationError(
        "notification metric outcome is unsupported",
      );
    }
    const failureClass = attributes.failureClass ?? "none";
    requireKey(failureClass, "metric failure class", 64);
    const key = `${outcome}\0${failureClass}`;
    this.#deliveries.set(key, (this.#deliveries.get(key) ?? 0) + 1);
  }

  recordIteration(
    outcome: "success" | "failure",
    result?: DeliveryRunResult,
  ): void {
    this.#iterations.set(outcome, (this.#iterations.get(outcome) ?? 0) + 1);
    if (result !== undefined) this.#claimed += result.claimed;
  }

  recordFanout(result: FanoutRunResult): void {
    this.#fanoutClaims += requireInteger(
      result.claimed,
      "fanout claimed metric",
      0,
      1_000,
    );
    this.#fanoutDeliveries += requireInteger(
      result.deliveriesPlanned,
      "fanout deliveries metric",
      0,
      1_000_000,
    );
  }

  setReadiness(
    ready: boolean,
    queueDepth: number,
    oldestPendingSeconds: number,
  ): void {
    this.#ready = ready;
    this.#queueDepth = requireInteger(
      queueDepth,
      "queue depth",
      0,
      1_000_000_000,
    );
    this.#oldestPendingSeconds = requireInteger(
      oldestPendingSeconds,
      "oldest pending outbox age",
      0,
      9_007_199_254_740_991,
    );
  }

  renderPrometheus(): string {
    const lines = [
      "# HELP periapsis_notifier_ready Whether the notifier dependencies are ready.",
      "# TYPE periapsis_notifier_ready gauge",
      `periapsis_notifier_ready ${this.#ready ? 1 : 0}`,
      "# HELP periapsis_notification_queue_depth Number of runnable or leased delivery jobs.",
      "# TYPE periapsis_notification_queue_depth gauge",
      `periapsis_notification_queue_depth ${this.#queueDepth}`,
      "# HELP periapsis_outbox_oldest_pending_seconds Age of the oldest runnable notification outbox event.",
      "# TYPE periapsis_outbox_oldest_pending_seconds gauge",
      `periapsis_outbox_oldest_pending_seconds ${this.#oldestPendingSeconds}`,
      "# HELP periapsis_notification_claims_total Outbox events or delivery jobs claimed by this process.",
      "# TYPE periapsis_notification_claims_total counter",
      `periapsis_notification_claims_total ${this.#claimed}`,
      "# HELP periapsis_notification_fanout_claims_total Notification outbox events claimed for fanout.",
      "# TYPE periapsis_notification_fanout_claims_total counter",
      `periapsis_notification_fanout_claims_total ${this.#fanoutClaims}`,
      "# HELP periapsis_notification_fanout_deliveries_total Delivery jobs planned by notification fanout.",
      "# TYPE periapsis_notification_fanout_deliveries_total counter",
      `periapsis_notification_fanout_deliveries_total ${this.#fanoutDeliveries}`,
      "# HELP periapsis_notifier_iterations_total Worker loop iterations by result.",
      "# TYPE periapsis_notifier_iterations_total counter",
    ];
    for (const outcome of ["success", "failure"] as const) {
      lines.push(
        `periapsis_notifier_iterations_total{outcome="${outcome}"} ${this.#iterations.get(outcome) ?? 0}`,
      );
    }
    lines.push(
      "# HELP periapsis_notification_deliveries_total Notification delivery outcomes.",
      "# TYPE periapsis_notification_deliveries_total counter",
    );
    for (const [key, value] of [...this.#deliveries.entries()].toSorted(
      ([left], [right]) => left.localeCompare(right),
    )) {
      const [outcome = "unknown", failureClass = "unknown"] = key.split("\0");
      lines.push(
        `periapsis_notification_deliveries_total{outcome="${outcome}",failure_class="${failureClass}"} ${value}`,
      );
    }
    return `${lines.join("\n")}\n`;
  }
}

export interface LogSink {
  write(value: string): void;
}

export class StructuredNotifierLogger implements DeliveryLogger {
  readonly #output: LogSink;
  readonly #errors: LogSink;
  readonly #release: string;
  readonly #minimumLevel: "info" | "error";

  constructor(options: {
    output?: LogSink;
    errors?: LogSink;
    release: string;
    minimumLevel?: "info" | "error";
  }) {
    this.#output = options.output ?? process.stdout;
    this.#errors = options.errors ?? process.stderr;
    this.#release = requireText(options.release, "release", 128);
    this.#minimumLevel = options.minimumLevel ?? "info";
  }

  info(
    event: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void {
    if (this.#minimumLevel === "error") return;
    this.#write("info", event, attributes);
  }

  error(
    event: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void {
    this.#write("error", event, attributes);
  }

  #write(
    level: "info" | "error",
    eventInput: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void {
    const event = requireKey(eventInput, "log event", 128);
    const safe: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(attributes)) {
      if (!logAttributeNames.has(key)) {
        throw new NotificationValidationError(
          "notification log attribute is not allowlisted",
        );
      }
      if (typeof value === "string")
        safe[key] = requireText(value, `log attribute ${key}`, 256);
      else if (typeof value === "number")
        safe[key] = Number.isFinite(value) ? value : 0;
      else safe[key] = value;
    }
    const payload = JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      service: "notifier",
      release: this.#release,
      event,
      ...safe,
      ...activeTraceCorrelation(),
    });
    (level === "error" ? this.#errors : this.#output).write(`${payload}\n`);
  }
}
