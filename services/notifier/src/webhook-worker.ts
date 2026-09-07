import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import type {
  DeliveryLogger,
  DeliveryRunResult,
  DeliveryTelemetry,
} from "./delivery.js";
import { notificationDispatchLimits } from "./dispatch-limits.js";
import {
  DeliveryProviderError,
  type DeliveryFailureClass,
  NotificationConfigurationError,
  NotificationConflictError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import { nextRetryAt } from "./planner.js";
import {
  createRetryPolicy,
  type RetryPolicy,
  type RetryPolicyInput,
} from "./rule.js";
import type { SecretResolver } from "./smtp.js";
import {
  canonicalPersistedTraceContext,
  type NotificationTracing,
  type PersistedTraceContext,
} from "./telemetry.js";
import {
  requireInstant,
  requireInteger,
  requireText,
  requireUuidV7,
} from "./validation.js";
import {
  createWebhookDeliveryFromSnapshot,
  signWebhookDelivery,
  type PinnedWebhookTransport,
  type SanitizedWebhookResponse,
  type WebhookDelivery,
  type WebhookDeliverySnapshotInput,
} from "./webhook.js";
import {
  isAuthenticWebhookDeliveryEgressPin,
  type WebhookDeliveryEgressPin,
  type WebhookUrlPolicyAttemptPermit,
} from "./webhook-url-policy.js";

export interface WebhookDeliveryClaimInput extends WebhookDeliverySnapshotInput {
  readonly eventId: string;
  readonly retry: RetryPolicyInput;
  readonly attempt: number;
  readonly fenceToken: string;
  readonly leaseUntil: Date;
  readonly egressPin: WebhookDeliveryEgressPin;
  readonly traceContext?: PersistedTraceContext;
}

export interface WebhookDeliveryClaim {
  readonly id: string;
  readonly tenantId: string;
  readonly eventId: string;
  readonly delivery: WebhookDelivery;
  readonly retry: RetryPolicy;
  readonly attempt: number;
  readonly fenceToken: string;
  readonly leaseUntil: Date;
  readonly egressPin: WebhookDeliveryEgressPin;
  readonly traceContext?: PersistedTraceContext;
}

export interface WebhookDeliveryRepository {
  readonly claimWebhookBatch: (input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }) => Promise<readonly WebhookDeliveryClaim[]>;
  readonly heartbeatWebhook: (
    claim: WebhookDeliveryClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ) => Promise<boolean>;
  readonly reserveWebhookSubmission: (
    claim: WebhookDeliveryClaim,
    stableSubmissionId: string,
    at: Date,
    signal: AbortSignal,
  ) => Promise<"reserved" | "already_delivered" | "uncertain">;
  readonly completeWebhook: (
    claim: WebhookDeliveryClaim,
    response: SanitizedWebhookResponse,
    at: Date,
    signal: AbortSignal,
  ) => Promise<void>;
  readonly completeWebhookReplay: (
    claim: WebhookDeliveryClaim,
    at: Date,
    signal: AbortSignal,
  ) => Promise<void>;
  readonly retryWebhook: (
    claim: WebhookDeliveryClaim,
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
    at: Date,
    safeAfterReservation: boolean,
    signal: AbortSignal,
  ) => Promise<void>;
  readonly deadLetterWebhook: (
    claim: WebhookDeliveryClaim,
    failureClass: DeliveryFailureClass | "submission_uncertain",
    at: Date,
    signal: AbortSignal,
  ) => Promise<void>;
}

export interface WebhookDeliveryWorkerOptions {
  readonly workerId: string;
  readonly batchSize: number;
  readonly maximumConcurrency: number;
  readonly leaseDurationMs: number;
  readonly heartbeatIntervalMs: number;
  readonly deliveryTimeoutMs: number;
}

export interface WebhookTransport {
  send(
    input: Parameters<PinnedWebhookTransport["send"]>[0],
    signal: AbortSignal,
    permit: WebhookUrlPolicyAttemptPermit,
  ): ReturnType<PinnedWebhookTransport["send"]>;
}

export interface WebhookUrlPolicyAttemptGate {
  beginAttempt(
    pin: WebhookDeliveryEgressPin,
    signal: AbortSignal,
  ): Promise<WebhookUrlPolicyAttemptPermit>;
}

const authenticWebhookClaims = new WeakSet<WebhookDeliveryClaim>();

export function createWebhookDeliveryClaim(
  input: WebhookDeliveryClaimInput,
  options: { allowPlainLocal?: boolean } = {},
): WebhookDeliveryClaim {
  requireUuidV7(input.eventId, "webhook claim event id");
  const delivery = createWebhookDeliveryFromSnapshot(input, options);
  if (
    input.payload.event.id !== input.eventId ||
    !isAuthenticWebhookDeliveryEgressPin(input.egressPin) ||
    input.egressPin.deliveryId !== delivery.id ||
    input.egressPin.configurationId !== delivery.configurationId ||
    input.egressPin.configurationVersion !== delivery.configurationVersion ||
    input.egressPin.tenantId !== delivery.tenantId ||
    input.egressPin.endpointUrl !== delivery.endpointUrl
  ) {
    throw new NotificationTenantBoundaryError();
  }
  const retry = createRetryPolicy(input.retry);
  requireInteger(
    input.attempt,
    "webhook claim attempt",
    1,
    retry.maximumAttempts,
  );
  requireUuidV7(input.fenceToken, "webhook claim fence token");
  const leaseUntil = requireInstant(
    input.leaseUntil,
    "webhook claim leaseUntil",
  );
  const attemptAt = requireInstant(input.attemptAt, "webhook claim attemptAt");
  if (leaseUntil <= attemptAt) {
    throw new NotificationValidationError(
      "webhook claim lease must follow its attempt timestamp",
    );
  }
  const leaseUntilEpoch = leaseUntil.getTime();
  const traceContext =
    input.traceContext === undefined
      ? undefined
      : canonicalPersistedTraceContext(input.traceContext);
  const claim = Object.freeze({
    id: delivery.id,
    tenantId: delivery.tenantId,
    eventId: input.eventId,
    delivery,
    retry,
    attempt: input.attempt,
    fenceToken: input.fenceToken,
    egressPin: input.egressPin,
    get leaseUntil(): Date {
      return new Date(leaseUntilEpoch);
    },
    ...(traceContext === undefined ? {} : { traceContext }),
  });
  authenticWebhookClaims.add(claim);
  return claim;
}

export class NotificationWebhookDeliveryWorker {
  readonly #repository: WebhookDeliveryRepository;
  readonly #secrets: SecretResolver;
  readonly #transport: WebhookTransport;
  readonly #urlPolicyGate: WebhookUrlPolicyAttemptGate;
  readonly #telemetry: DeliveryTelemetry;
  readonly #logger: DeliveryLogger;
  readonly #tracing: NotificationTracing;
  readonly #options: Readonly<WebhookDeliveryWorkerOptions>;
  readonly #now: () => Date;

  constructor(dependencies: {
    repository: WebhookDeliveryRepository;
    secrets: SecretResolver;
    transport: WebhookTransport;
    urlPolicyGate: WebhookUrlPolicyAttemptGate;
    telemetry: DeliveryTelemetry;
    logger: DeliveryLogger;
    tracing: NotificationTracing;
    options: WebhookDeliveryWorkerOptions;
    now?: () => Date;
  }) {
    this.#repository = dependencies.repository;
    this.#secrets = dependencies.secrets;
    this.#transport = dependencies.transport;
    if (
      dependencies.urlPolicyGate === null ||
      dependencies.urlPolicyGate === undefined ||
      typeof dependencies.urlPolicyGate.beginAttempt !== "function"
    ) {
      throw new NotificationValidationError(
        "webhook URL policy gate is invalid",
      );
    }
    this.#urlPolicyGate = dependencies.urlPolicyGate;
    this.#telemetry = dependencies.telemetry;
    this.#logger = dependencies.logger;
    this.#tracing = dependencies.tracing;
    this.#options = validateWebhookWorkerOptions(dependencies.options);
    this.#now = dependencies.now ?? (() => new Date());
  }

  async runOnce(signal: AbortSignal): Promise<DeliveryRunResult> {
    if (signal.aborted) throw signal.reason;
    const now = requireInstant(this.#now(), "webhook worker now");
    const claims = await this.#repository.claimWebhookBatch({
      workerId: this.#options.workerId,
      limit: this.#options.batchSize,
      leaseDurationMs: this.#options.leaseDurationMs,
      now,
      signal,
    });
    if (claims.length > this.#options.batchSize) {
      throw new NotificationValidationError(
        "repository returned more webhook claims than requested",
      );
    }
    const seen = new Set<string>();
    for (const claim of claims) {
      if (!authenticWebhookClaims.has(claim) || seen.has(claim.id)) {
        throw new NotificationValidationError(
          "repository returned a forged or duplicate webhook claim",
        );
      }
      seen.add(claim.id);
    }
    const outcomes: Array<WebhookOutcome | undefined> = Array.from({
      length: claims.length,
    });
    let next = 0;
    const runners = Array.from(
      { length: Math.min(this.#options.maximumConcurrency, claims.length) },
      async () => {
        while (!signal.aborted) {
          const index = next;
          next += 1;
          if (index >= claims.length) return;
          // This await is bounded by the fixed-size runner pool.
          // eslint-disable-next-line no-await-in-loop
          const claim = claims[index];
          if (claim === undefined) return;
          // The fixed-size runner pool bounds this await.
          // eslint-disable-next-line no-await-in-loop
          outcomes[index] = await this.#tracing.runConsumerSpan(
            "webhook_delivery",
            claim.traceContext,
            () => this.#processClaim(claim, signal),
            (outcome) => outcome,
          );
        }
      },
    );
    await Promise.all(runners);
    if (signal.aborted) throw signal.reason;
    return Object.freeze({
      claimed: claims.length,
      delivered: outcomes.filter((value) => value === "delivered").length,
      replayed: outcomes.filter((value) => value === "replayed").length,
      retried: outcomes.filter((value) => value === "retried").length,
      deadLettered: outcomes.filter((value) => value === "dead_lettered")
        .length,
      uncertain: outcomes.filter((value) => value === "uncertain").length,
    });
  }

  async #processClaim(
    claim: WebhookDeliveryClaim,
    parentSignal: AbortSignal,
  ): Promise<WebhookOutcome> {
    const startedAt = requireInstant(this.#now(), "webhook worker now");
    if (claim.leaseUntil <= startedAt) {
      throw new NotificationConflictError(
        "repository returned an expired webhook claim",
      );
    }
    let reserved = false;
    let providerAccepted = false;
    try {
      return await this.#withHeartbeat(claim, parentSignal, async (signal) => {
        const signed = await signWebhookDelivery(
          claim.delivery,
          this.#secrets,
          signal,
        );
        const stableSubmissionId = stableWebhookSubmissionId(claim);
        // A lost database response cannot prove whether the reservation
        // committed, so ambiguity starts before the state-changing call.
        reserved = true;
        const reservation = await this.#repository.reserveWebhookSubmission(
          claim,
          stableSubmissionId,
          requireInstant(this.#now(), "webhook worker now"),
          signal,
        );
        if (
          reservation !== "reserved" &&
          reservation !== "already_delivered" &&
          reservation !== "uncertain"
        ) {
          throw new NotificationValidationError(
            "repository returned an invalid webhook submission reservation",
          );
        }
        if (reservation === "already_delivered") {
          await this.#repository.completeWebhookReplay(
            claim,
            requireInstant(this.#now(), "webhook worker now"),
            signal,
          );
          this.#recordOutcome("replayed", claim);
          return "replayed";
        }
        if (reservation === "uncertain") {
          await this.#repository.deadLetterWebhook(
            claim,
            "submission_uncertain",
            requireInstant(this.#now(), "webhook worker now"),
            signal,
          );
          this.#recordOutcome("uncertain", claim, "submission_uncertain");
          return "uncertain";
        }
        const permit = await this.#urlPolicyGate.beginAttempt(
          claim.egressPin,
          signal,
        );
        const responseInput = await this.#transport.send(
          signed,
          signal,
          permit,
        );
        providerAccepted = true;
        const response = canonicalWebhookResponse(responseInput);
        await this.#repository.completeWebhook(
          claim,
          response,
          requireInstant(this.#now(), "webhook worker now"),
          signal,
        );
        this.#recordOutcome("delivered", claim);
        return "delivered";
      });
    } catch (error) {
      if (parentSignal.aborted) throw parentSignal.reason;
      if (error instanceof NotificationConflictError) throw error;
      if (providerAccepted) {
        this.#logger.error("notification_webhook_completion_unknown", {
          tenantId: claim.tenantId,
          deliveryId: claim.id,
          attempt: claim.attempt,
        });
        this.#recordOutcome("uncertain", claim, "unknown");
        return "uncertain";
      }
      const classified = classifyWebhookFailure(error, reserved);
      if (classified.retrySafety === "uncertain") {
        await this.#repository.deadLetterWebhook(
          claim,
          "submission_uncertain",
          requireInstant(this.#now(), "webhook worker now"),
          parentSignal,
        );
        this.#recordOutcome("uncertain", claim, classified.failureClass);
        return "uncertain";
      }
      const failedAt = requireInstant(this.#now(), "webhook worker now");
      const nextAt =
        classified.retrySafety === "safe"
          ? nextRetryAt(claim.retry, claim.attempt, failedAt, claim.id)
          : null;
      if (nextAt !== null) {
        await this.#repository.retryWebhook(
          claim,
          classified.failureClass,
          nextAt,
          failedAt,
          reserved,
          parentSignal,
        );
        this.#recordOutcome("retried", claim, classified.failureClass);
        return "retried";
      }
      await this.#repository.deadLetterWebhook(
        claim,
        classified.failureClass,
        requireInstant(this.#now(), "webhook worker now"),
        parentSignal,
      );
      this.#recordOutcome("dead_lettered", claim, classified.failureClass);
      return "dead_lettered";
    }
  }

  async #withHeartbeat<T>(
    claim: WebhookDeliveryClaim,
    parentSignal: AbortSignal,
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const stop = new AbortController();
    const lostLease = new AbortController();
    const timeout = AbortSignal.timeout(this.#options.deliveryTimeoutMs);
    const operationSignal = AbortSignal.any([
      parentSignal,
      lostLease.signal,
      timeout,
    ]);
    const heartbeat = (async (): Promise<void> => {
      while (!stop.signal.aborted) {
        try {
          // Heartbeats remain sequential so fence observations cannot reorder.
          // eslint-disable-next-line no-await-in-loop
          await delay(this.#options.heartbeatIntervalMs, undefined, {
            signal: stop.signal,
          });
        } catch {
          return;
        }
        try {
          const leaseUntil = new Date(
            this.#now().getTime() + this.#options.leaseDurationMs,
          );
          const heartbeatSignal = AbortSignal.any([
            operationSignal,
            stop.signal,
            AbortSignal.timeout(this.#options.heartbeatIntervalMs),
          ]);
          // eslint-disable-next-line no-await-in-loop
          const retained = await this.#repository.heartbeatWebhook(
            claim,
            leaseUntil,
            heartbeatSignal,
          );
          if (!retained) {
            lostLease.abort(
              new NotificationConflictError("webhook lease was fenced"),
            );
            return;
          }
        } catch (error) {
          if (stop.signal.aborted) return;
          lostLease.abort(error);
          return;
        }
      }
    })();
    try {
      return await operation(operationSignal);
    } catch (error) {
      if (lostLease.signal.aborted) {
        const reason = lostLease.signal.reason;
        throw reason instanceof NotificationConflictError
          ? reason
          : new NotificationConflictError("webhook lease renewal failed");
      }
      throw error;
    } finally {
      stop.abort();
      await heartbeat;
    }
  }

  #recordOutcome(
    outcome: WebhookOutcome,
    claim: WebhookDeliveryClaim,
    failureClass?: string,
  ): void {
    this.#telemetry.record(
      outcome,
      Object.freeze({
        tenantId: claim.tenantId,
        ...(failureClass === undefined ? {} : { failureClass }),
      }),
    );
    this.#logger.info("notification_webhook_finished", {
      tenantId: claim.tenantId,
      deliveryId: claim.id,
      attempt: claim.attempt,
      outcome,
      ...(failureClass === undefined ? {} : { failureClass }),
    });
  }
}

type WebhookOutcome =
  "delivered" | "replayed" | "retried" | "dead_lettered" | "uncertain";

function validateWebhookWorkerOptions(
  input: WebhookDeliveryWorkerOptions,
): Readonly<WebhookDeliveryWorkerOptions> {
  const workerId = requireText(input.workerId, "webhook worker id", 128);
  requireInteger(
    input.batchSize,
    "webhook worker batch size",
    1,
    notificationDispatchLimits.maximumBatchSize,
  );
  requireInteger(input.maximumConcurrency, "webhook worker concurrency", 1, 64);
  requireInteger(
    input.leaseDurationMs,
    "webhook worker lease duration",
    5_000,
    notificationDispatchLimits.maximumLeaseDurationMs,
  );
  requireInteger(
    input.heartbeatIntervalMs,
    "webhook worker heartbeat interval",
    1_000,
    input.leaseDurationMs - 1,
  );
  if (input.heartbeatIntervalMs * 3 >= input.leaseDurationMs) {
    throw new NotificationValidationError(
      "webhook heartbeat must leave at least two recovery intervals",
    );
  }
  requireInteger(
    input.deliveryTimeoutMs,
    "webhook worker delivery timeout",
    1_000,
    input.leaseDurationMs - 1,
  );
  return Object.freeze({ ...input, workerId });
}

function stableWebhookSubmissionId(claim: WebhookDeliveryClaim): string {
  const digest = createHash("sha256")
    .update("periapsis:webhook:v1\0")
    .update(claim.tenantId)
    .update("\0")
    .update(claim.id)
    .update("\0")
    .update(claim.delivery.configurationId)
    .update("\0")
    .update(String(claim.delivery.configurationVersion))
    .digest("hex");
  return `<${digest}@notifications.periapsis.invalid>`;
}

function canonicalWebhookResponse(
  input: SanitizedWebhookResponse,
): SanitizedWebhookResponse {
  if (
    input === null ||
    typeof input !== "object" ||
    input.provider !== "webhook" ||
    Object.keys(input).some(
      (key) => !["provider", "receiptDigest", "statusCode"].includes(key),
    )
  ) {
    throw new NotificationValidationError(
      "webhook transport returned an invalid response",
    );
  }
  requireInteger(input.statusCode, "webhook response status", 200, 299);
  const receiptDigest = requireDigest(
    input.receiptDigest,
    "webhook response receipt digest",
  );
  return Object.freeze({
    provider: "webhook",
    statusCode: input.statusCode,
    receiptDigest,
  });
}

function requireDigest(value: string, field: string): string {
  requireText(value, field, 64);
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new NotificationValidationError(`${field} must be a SHA-256 digest`);
  }
  return value;
}

function classifyWebhookFailure(
  error: unknown,
  reserved: boolean,
): {
  failureClass: DeliveryFailureClass;
  retrySafety: "safe" | "uncertain" | "terminal";
} {
  if (error instanceof DeliveryProviderError) {
    return { failureClass: error.failureClass, retrySafety: error.retrySafety };
  }
  if (
    error instanceof NotificationTenantBoundaryError ||
    error instanceof NotificationValidationError
  ) {
    return { failureClass: "security", retrySafety: "terminal" };
  }
  if (error instanceof NotificationConfigurationError) {
    return { failureClass: "authentication", retrySafety: "terminal" };
  }
  if (error instanceof NotificationConflictError) {
    return { failureClass: "unknown", retrySafety: "terminal" };
  }
  if (error instanceof DOMException && error.name === "TimeoutError") {
    return {
      failureClass: "timeout",
      retrySafety: reserved ? "uncertain" : "safe",
    };
  }
  return {
    failureClass: "unknown",
    retrySafety: reserved ? "uncertain" : "safe",
  };
}
