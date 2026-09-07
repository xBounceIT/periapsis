import { setTimeout as delay } from "node:timers/promises";

import type {
  DeliveryLogger,
  DeliveryRepository,
  DeliveryRunResult,
} from "./delivery.js";
import {
  NotificationConfigurationError,
  NotificationConflictError,
} from "./errors.js";
import type { NotifierMetrics } from "./observability.js";
import type {
  FanoutRunResult,
  NotificationFanoutRepository,
} from "./fanout.js";
import { requireInteger } from "./validation.js";
import type { NotificationTracing } from "./telemetry.js";

export interface NotifierRepository
  extends DeliveryRepository, NotificationFanoutRepository {
  readiness(
    signal: AbortSignal,
  ): Promise<Readonly<{ queueDepth: number; oldestPendingSeconds: number }>>;
  close(): Promise<void>;
}

export interface NotificationRuntimeOptions {
  idlePollIntervalMs: number;
  busyPollIntervalMs: number;
  failurePollIntervalMs: number;
  readinessTimeoutMs: number;
}

export interface DeliveryBatchRunner {
  runOnce(signal: AbortSignal): Promise<DeliveryRunResult>;
}

export interface FanoutBatchRunner {
  runOnce(signal: AbortSignal): Promise<FanoutRunResult>;
}

export class CompositeNotificationBatchRunner implements DeliveryBatchRunner {
  readonly #fanout: FanoutBatchRunner;
  readonly #delivery: DeliveryBatchRunner;
  readonly #webhook: DeliveryBatchRunner;
  readonly #metrics: NotifierMetrics;

  constructor(dependencies: {
    fanout: FanoutBatchRunner;
    delivery: DeliveryBatchRunner;
    webhook: DeliveryBatchRunner;
    metrics: NotifierMetrics;
  }) {
    this.#fanout = dependencies.fanout;
    this.#delivery = dependencies.delivery;
    this.#webhook = dependencies.webhook;
    this.#metrics = dependencies.metrics;
  }

  async runOnce(signal: AbortSignal): Promise<DeliveryRunResult> {
    let fanout: FanoutRunResult | undefined;
    let fanoutError: unknown;
    try {
      fanout = await this.#fanout.runOnce(signal);
      this.#metrics.recordFanout(fanout);
    } catch (error) {
      fanoutError = error;
    }
    if (signal.aborted) throw signal.reason;
    const deliveryResults: DeliveryRunResult[] = [];
    const errors: unknown[] = fanoutError === undefined ? [] : [fanoutError];
    for (const worker of [this.#delivery, this.#webhook]) {
      try {
        // Each channel owns an independent bounded claim batch. Continue with
        // the other channel after a failure so one provider cannot starve it.
        // eslint-disable-next-line no-await-in-loop
        deliveryResults.push(await worker.runOnce(signal));
      } catch (error) {
        errors.push(error);
      }
      if (signal.aborted) throw signal.reason;
    }
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) {
      throw new AggregateError(
        errors,
        "notification fanout or delivery batches failed",
        { cause: errors.at(-1) },
      );
    }
    return Object.freeze({
      claimed:
        (fanout?.claimed ?? 0) +
        deliveryResults.reduce((total, result) => total + result.claimed, 0),
      delivered: deliveryResults.reduce(
        (total, result) => total + result.delivered,
        0,
      ),
      replayed: deliveryResults.reduce(
        (total, result) => total + result.replayed,
        0,
      ),
      retried: deliveryResults.reduce(
        (total, result) => total + result.retried,
        0,
      ),
      deadLettered: deliveryResults.reduce(
        (total, result) => total + result.deadLettered,
        0,
      ),
      uncertain: deliveryResults.reduce(
        (total, result) => total + result.uncertain,
        0,
      ),
    });
  }
}

export class NotificationRuntime {
  readonly #worker: DeliveryBatchRunner;
  readonly #repository: NotifierRepository;
  readonly #metrics: NotifierMetrics;
  readonly #logger: DeliveryLogger;
  readonly #tracing: NotificationTracing;
  readonly #options: Readonly<NotificationRuntimeOptions>;
  #running = false;

  constructor(dependencies: {
    worker: DeliveryBatchRunner;
    repository: NotifierRepository;
    metrics: NotifierMetrics;
    logger: DeliveryLogger;
    tracing: NotificationTracing;
    options: NotificationRuntimeOptions;
  }) {
    this.#worker = dependencies.worker;
    this.#repository = dependencies.repository;
    this.#metrics = dependencies.metrics;
    this.#logger = dependencies.logger;
    this.#tracing = dependencies.tracing;
    this.#options = validateRuntimeOptions(dependencies.options);
  }

  async run(signal: AbortSignal): Promise<void> {
    if (this.#running) {
      throw new NotificationConflictError(
        "notification runtime is already running",
      );
    }
    this.#running = true;
    let iteration = 0;
    try {
      while (!signal.aborted) {
        iteration += 1;
        let waitMs = this.#options.failurePollIntervalMs;
        try {
          // Each run owns one bounded claim batch and drains it before polling.
          // eslint-disable-next-line no-await-in-loop
          const result = await this.#worker.runOnce(signal);
          this.#metrics.recordIteration("success", result);
          this.#logger.info("notifier_iteration_finished", {
            iteration,
            claimed: result.claimed,
            replayed: result.replayed,
            retried: result.retried,
            deadLettered: result.deadLettered,
            uncertain: result.uncertain,
          });
          waitMs =
            result.claimed === 0
              ? this.#options.idlePollIntervalMs
              : this.#options.busyPollIntervalMs;
        } catch (error) {
          if (signal.aborted) return;
          this.#metrics.recordIteration("failure");
          this.#logger.error("notifier_iteration_failed", {
            iteration,
            errorClass: safeErrorClass(error),
          });
        }
        try {
          // Poll waits are cancellable so shutdown does not wait for the interval.
          // eslint-disable-next-line no-await-in-loop
          await delay(waitMs, undefined, { signal });
        } catch {
          if (signal.aborted) return;
        }
      }
    } finally {
      this.#running = false;
    }
  }

  async readiness(signal: AbortSignal): Promise<{
    ready: boolean;
    queueDepth: number;
  }> {
    const timeout = AbortSignal.timeout(this.#options.readinessTimeoutMs);
    const bounded = AbortSignal.any([signal, timeout]);
    const startedAt = performance.now();
    try {
      const result = await this.#tracing.runDatabaseSpan("readiness", () =>
        this.#repository.readiness(bounded),
      );
      this.#metrics.setReadiness(
        true,
        result.queueDepth,
        result.oldestPendingSeconds,
      );
      return { ready: true, queueDepth: result.queueDepth };
    } catch (error) {
      this.#logger.error("notifier_readiness_failed", {
        reason: timeout.aborted
          ? "deadline_exceeded"
          : signal.aborted
            ? "request_canceled"
            : error instanceof NotificationConfigurationError
              ? "configuration_invalid"
              : "query_failed",
        durationMs: Math.round(performance.now() - startedAt),
      });
      if (signal.aborted) throw signal.reason;
      this.#metrics.setReadiness(false, 0, 0);
      return { ready: false, queueDepth: 0 };
    }
  }

  async close(): Promise<void> {
    await this.#repository.close();
  }
}

function validateRuntimeOptions(
  input: NotificationRuntimeOptions,
): Readonly<NotificationRuntimeOptions> {
  requireInteger(input.idlePollIntervalMs, "idle poll interval", 100, 60_000);
  requireInteger(input.busyPollIntervalMs, "busy poll interval", 10, 10_000);
  requireInteger(
    input.failurePollIntervalMs,
    "failure poll interval",
    100,
    5 * 60_000,
  );
  requireInteger(input.readinessTimeoutMs, "readiness timeout", 100, 30_000);
  return Object.freeze({ ...input });
}

function safeErrorClass(error: unknown): string {
  if (error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(error.name))
    return error.name;
  return "UnknownError";
}
