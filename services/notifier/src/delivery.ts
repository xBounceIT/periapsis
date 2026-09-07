import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import {
  DeliveryProviderError,
  type DeliveryFailureClass,
  NotificationConflictError,
  NotificationRenderError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import {
  canonicalizeNotificationContext,
  type ContextValue,
  type NotificationAudience,
} from "./event.js";
import { notificationDispatchLimits } from "./dispatch-limits.js";
import { nextRetryAt } from "./planner.js";
import {
  createRetryPolicy,
  type RetryPolicy,
  type RetryPolicyInput,
} from "./rule.js";
import type { EmailDeliveryInput, SanitizedProviderResponse } from "./smtp.js";
import {
  createNotificationTemplate,
  renderNotificationTemplate,
  type NotificationTemplate,
  type NotificationTemplateInput,
} from "./template.js";
import {
  canonicalEmail,
  requireInstant,
  requireInteger,
  requireText,
  requireUuidV7,
} from "./validation.js";
import {
  canonicalPersistedTraceContext,
  type NotificationTracing,
  type PersistedTraceContext,
} from "./telemetry.js";

export interface DeliveryClaimInput {
  id: string;
  tenantId: string;
  eventId: string;
  ruleId: string;
  ruleVersion: number;
  smtpConfigurationScope: "tenant" | "platform";
  smtpConfigurationId: string;
  smtpConfigurationVersion: number;
  deduplicationKey: string;
  recipient: string;
  audience: NotificationAudience;
  context: Readonly<Record<string, ContextValue>>;
  template: NotificationTemplateInput;
  retry: RetryPolicyInput;
  attempt: number;
  fenceToken: string;
  leaseUntil: Date;
  traceContext?: PersistedTraceContext;
}

export interface DeliveryClaim {
  readonly id: string;
  readonly tenantId: string;
  readonly eventId: string;
  readonly ruleId: string;
  readonly ruleVersion: number;
  readonly smtpConfigurationScope: "tenant" | "platform";
  readonly smtpConfigurationId: string;
  readonly smtpConfigurationVersion: number;
  readonly deduplicationKey: string;
  readonly recipient: string;
  readonly audience: NotificationAudience;
  readonly context: Readonly<Record<string, ContextValue>>;
  readonly template: NotificationTemplate;
  readonly retry: RetryPolicy;
  readonly attempt: number;
  readonly fenceToken: string;
  readonly leaseUntil: Date;
  readonly traceContext?: PersistedTraceContext;
}

export interface DeliveryRepository {
  claimBatch(input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }): Promise<readonly DeliveryClaim[]>;
  heartbeat(
    claim: DeliveryClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean>;
  reserveSubmission(
    claim: DeliveryClaim,
    stableMessageId: string,
    at: Date,
    signal: AbortSignal,
  ): Promise<"reserved" | "already_delivered" | "uncertain">;
  complete(
    claim: DeliveryClaim,
    response: SanitizedProviderResponse,
    at: Date,
    signal: AbortSignal,
  ): Promise<void>;
  completeReplay(
    claim: DeliveryClaim,
    at: Date,
    signal: AbortSignal,
  ): Promise<void>;
  retry(
    claim: DeliveryClaim,
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
    at: Date,
    safeAfterReservation: boolean,
    signal: AbortSignal,
  ): Promise<void>;
  deadLetter(
    claim: DeliveryClaim,
    failureClass: DeliveryFailureClass | "submission_uncertain",
    at: Date,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface EmailDeliveryProvider {
  send(
    input: EmailDeliveryInput,
    signal: AbortSignal,
  ): Promise<SanitizedProviderResponse>;
}

export interface EmailDeliveryProviderResolver {
  resolve(
    tenantId: string,
    configuration: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<EmailDeliveryProvider>;
}

export interface DeliveryTelemetry {
  record(
    outcome:
      "delivered" | "replayed" | "retried" | "dead_lettered" | "uncertain",
    attributes: Readonly<{ tenantId: string; failureClass?: string }>,
  ): void;
}

export interface DeliveryLogger {
  info(
    event: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void;
  error(
    event: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void;
}

export interface DeliveryWorkerOptions {
  workerId: string;
  batchSize: number;
  maximumConcurrency: number;
  leaseDurationMs: number;
  heartbeatIntervalMs: number;
  deliveryTimeoutMs: number;
  renderTimeoutMs: number;
  maximumOutputBytes: number;
}

export interface DeliveryRunResult {
  readonly claimed: number;
  readonly delivered: number;
  readonly replayed: number;
  readonly retried: number;
  readonly deadLettered: number;
  readonly uncertain: number;
}

const authenticClaims = new WeakSet<DeliveryClaim>();

export function createDeliveryClaim(input: DeliveryClaimInput): DeliveryClaim {
  requireUuidV7(input.id, "claim.id");
  requireUuidV7(input.tenantId, "claim.tenantId");
  requireUuidV7(input.eventId, "claim.eventId");
  requireUuidV7(input.ruleId, "claim.ruleId");
  requireInteger(input.ruleVersion, "claim.ruleVersion", 1, 2_147_483_647);
  if (
    input.smtpConfigurationScope !== "tenant" &&
    input.smtpConfigurationScope !== "platform"
  ) {
    throw new NotificationValidationError(
      "claim SMTP configuration scope is unsupported",
    );
  }
  requireUuidV7(input.smtpConfigurationId, "claim.smtpConfigurationId");
  requireInteger(
    input.smtpConfigurationVersion,
    "claim.smtpConfigurationVersion",
    1,
    2_147_483_647,
  );
  const deduplicationKey = requireDigest(
    input.deduplicationKey,
    "claim.deduplicationKey",
  );
  const recipient = canonicalEmail(input.recipient, "claim.recipient");
  if (input.audience !== "operator" && input.audience !== "customer") {
    throw new NotificationValidationError("claim audience is unsupported");
  }
  const context = canonicalizeNotificationContext(input.context);
  const template = createNotificationTemplate(input.template);
  if (template.tenantId !== input.tenantId)
    throw new NotificationTenantBoundaryError();
  const retry = createRetryPolicy(input.retry);
  requireInteger(input.attempt, "claim.attempt", 1, retry.maximumAttempts);
  const fenceToken = requireUuidV7(input.fenceToken, "claim.fenceToken");
  const leaseUntil = requireInstant(input.leaseUntil, "claim.leaseUntil");
  const leaseUntilEpoch = leaseUntil.getTime();
  const traceContext =
    input.traceContext === undefined
      ? undefined
      : canonicalPersistedTraceContext(input.traceContext);
  const claim = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    eventId: input.eventId,
    ruleId: input.ruleId,
    ruleVersion: input.ruleVersion,
    smtpConfigurationScope: input.smtpConfigurationScope,
    smtpConfigurationId: input.smtpConfigurationId,
    smtpConfigurationVersion: input.smtpConfigurationVersion,
    deduplicationKey,
    recipient,
    audience: input.audience,
    context,
    template,
    retry,
    attempt: input.attempt,
    fenceToken,
    get leaseUntil(): Date {
      return new Date(leaseUntilEpoch);
    },
    ...(traceContext === undefined ? {} : { traceContext }),
  });
  authenticClaims.add(claim);
  return claim;
}

export class NotificationDeliveryWorker {
  readonly #repository: DeliveryRepository;
  readonly #providers: EmailDeliveryProviderResolver;
  readonly #telemetry: DeliveryTelemetry;
  readonly #logger: DeliveryLogger;
  readonly #tracing: NotificationTracing;
  readonly #options: Readonly<DeliveryWorkerOptions>;
  readonly #now: () => Date;

  constructor(dependencies: {
    repository: DeliveryRepository;
    providers: EmailDeliveryProviderResolver;
    telemetry: DeliveryTelemetry;
    logger: DeliveryLogger;
    tracing: NotificationTracing;
    options: DeliveryWorkerOptions;
    now?: () => Date;
  }) {
    this.#repository = dependencies.repository;
    this.#providers = dependencies.providers;
    this.#telemetry = dependencies.telemetry;
    this.#logger = dependencies.logger;
    this.#tracing = dependencies.tracing;
    this.#options = validateWorkerOptions(dependencies.options);
    this.#now = dependencies.now ?? (() => new Date());
  }

  async runOnce(signal: AbortSignal): Promise<DeliveryRunResult> {
    if (signal.aborted) throw signal.reason;
    const now = requireInstant(this.#now(), "worker.now");
    const claims = await this.#repository.claimBatch({
      workerId: this.#options.workerId,
      limit: this.#options.batchSize,
      leaseDurationMs: this.#options.leaseDurationMs,
      now,
      signal,
    });
    if (claims.length > this.#options.batchSize) {
      throw new NotificationValidationError(
        "repository returned more claims than requested",
      );
    }
    const seenClaims = new Set<string>();
    for (const claim of claims) {
      if (!authenticClaims.has(claim) || seenClaims.has(claim.id)) {
        throw new NotificationValidationError(
          "repository returned a forged or duplicate delivery claim",
        );
      }
      seenClaims.add(claim.id);
    }
    const outcomes: Array<DeliveryOutcome | undefined> = Array.from({
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
          // This await is intentionally bounded by the fixed-size runner pool.
          // eslint-disable-next-line no-await-in-loop
          const claim = claims[index];
          if (claim === undefined) return;
          // eslint-disable-next-line no-await-in-loop
          outcomes[index] = await this.#tracing.runConsumerSpan(
            "email_delivery",
            claim.traceContext,
            () => this.#processClaim(claim, signal),
            (outcome) => outcome,
          );
        }
      },
    );
    await Promise.all(runners);
    if (signal.aborted) throw signal.reason;
    const result: DeliveryRunResult = {
      claimed: claims.length,
      delivered: outcomes.filter((value) => value === "delivered").length,
      replayed: outcomes.filter((value) => value === "replayed").length,
      retried: outcomes.filter((value) => value === "retried").length,
      deadLettered: outcomes.filter((value) => value === "dead_lettered")
        .length,
      uncertain: outcomes.filter((value) => value === "uncertain").length,
    };
    return Object.freeze(result);
  }

  async #processClaim(
    claim: DeliveryClaim,
    parentSignal: AbortSignal,
  ): Promise<DeliveryOutcome> {
    const startedAt = requireInstant(this.#now(), "worker.now");
    if (claim.leaseUntil <= startedAt) {
      throw new NotificationConflictError(
        "repository returned an expired delivery claim",
      );
    }
    let reserved = false;
    let providerAccepted = false;
    try {
      return await this.#withHeartbeat(claim, parentSignal, async (signal) => {
        const rendered = renderNotificationTemplate(
          claim.template,
          claim.context,
          {
            audience: claim.audience,
            timeoutMs: this.#options.renderTimeoutMs,
            maximumOutputBytes: this.#options.maximumOutputBytes,
          },
        );
        const provider = await this.#providers.resolve(
          claim.tenantId,
          {
            scope: claim.smtpConfigurationScope,
            id: claim.smtpConfigurationId,
            version: claim.smtpConfigurationVersion,
          },
          signal,
        );
        const messageId = stableMessageId(claim);
        // From this point a missing repository response is ambiguous: the
        // reservation transaction may already have committed.
        reserved = true;
        const reservation = await this.#repository.reserveSubmission(
          claim,
          messageId,
          requireInstant(this.#now(), "worker.now"),
          signal,
        );
        if (
          reservation !== "reserved" &&
          reservation !== "already_delivered" &&
          reservation !== "uncertain"
        ) {
          throw new NotificationValidationError(
            "repository returned an invalid submission reservation",
          );
        }
        if (reservation === "already_delivered") {
          await this.#repository.completeReplay(
            claim,
            requireInstant(this.#now(), "worker.now"),
            signal,
          );
          this.#recordOutcome("replayed", claim);
          return "replayed";
        }
        if (reservation === "uncertain") {
          await this.#repository.deadLetter(
            claim,
            "submission_uncertain",
            requireInstant(this.#now(), "worker.now"),
            signal,
          );
          this.#recordOutcome("uncertain", claim, "submission_uncertain");
          return "uncertain";
        }
        const responseInput = await provider.send(
          {
            tenantId: claim.tenantId,
            recipient: claim.recipient,
            subject: rendered.subject,
            html: rendered.html,
            plainText: rendered.plainText,
            headers: Object.freeze({
              "message-id": messageId,
              "x-periapsis-delivery-id": claim.id,
            }),
          },
          signal,
        );
        providerAccepted = true;
        const response = canonicalProviderResponse(responseInput);
        await this.#repository.complete(
          claim,
          response,
          requireInstant(this.#now(), "worker.now"),
          signal,
        );
        this.#recordOutcome("delivered", claim);
        return "delivered";
      });
    } catch (error) {
      if (parentSignal.aborted) throw parentSignal.reason;
      if (error instanceof NotificationConflictError) throw error;
      if (providerAccepted) {
        // The provider accepted the message. A failed completion may have committed
        // despite a lost response, so the fenced reservation is deliberately left
        // for receipt replay/uncertain recovery instead of being overwritten.
        this.#logger.error("notification_delivery_completion_unknown", {
          tenantId: claim.tenantId,
          deliveryId: claim.id,
          attempt: claim.attempt,
        });
        this.#recordOutcome("uncertain", claim, "unknown");
        return "uncertain";
      }
      const classified = classifyDeliveryFailure(error, reserved);
      if (classified.retrySafety === "uncertain") {
        await this.#repository.deadLetter(
          claim,
          "submission_uncertain",
          requireInstant(this.#now(), "worker.now"),
          parentSignal,
        );
        this.#recordOutcome("uncertain", claim, classified.failureClass);
        return "uncertain";
      }
      const failedAt = requireInstant(this.#now(), "worker.now");
      const nextAt =
        classified.retrySafety === "safe"
          ? nextRetryAt(claim.retry, claim.attempt, failedAt, claim.id)
          : null;
      if (nextAt !== null) {
        await this.#repository.retry(
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
      await this.#repository.deadLetter(
        claim,
        classified.failureClass,
        requireInstant(this.#now(), "worker.now"),
        parentSignal,
      );
      this.#recordOutcome("dead_lettered", claim, classified.failureClass);
      return "dead_lettered";
    }
  }

  async #withHeartbeat<T>(
    claim: DeliveryClaim,
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
          // Heartbeats are sequential: overlapping renewals could reorder fences.
          // eslint-disable-next-line no-await-in-loop
          await delay(this.#options.heartbeatIntervalMs, undefined, {
            signal: stop.signal,
          });
        } catch {
          return;
        }
        const leaseUntil = new Date(
          this.#now().getTime() + this.#options.leaseDurationMs,
        );
        try {
          const heartbeatSignal = AbortSignal.any([
            operationSignal,
            stop.signal,
            AbortSignal.timeout(this.#options.heartbeatIntervalMs),
          ]);
          // The next renewal must observe the current fenced result.
          // eslint-disable-next-line no-await-in-loop
          const retained = await this.#repository.heartbeat(
            claim,
            leaseUntil,
            heartbeatSignal,
          );
          if (!retained) {
            lostLease.abort(
              new NotificationConflictError("delivery lease was fenced"),
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
    } finally {
      stop.abort();
      await heartbeat;
    }
  }

  #recordOutcome(
    outcome: Exclude<DeliveryOutcome, "uncertain"> | "uncertain",
    claim: DeliveryClaim,
    failureClass?: string,
  ): void {
    const attributes = Object.freeze({
      tenantId: claim.tenantId,
      ...(failureClass === undefined ? {} : { failureClass }),
    });
    this.#telemetry.record(outcome, attributes);
    this.#logger.info("notification_delivery_finished", {
      tenantId: claim.tenantId,
      deliveryId: claim.id,
      attempt: claim.attempt,
      outcome,
      ...(failureClass === undefined ? {} : { failureClass }),
    });
  }
}

type DeliveryOutcome =
  "delivered" | "replayed" | "retried" | "dead_lettered" | "uncertain";

function validateWorkerOptions(
  input: DeliveryWorkerOptions,
): Readonly<DeliveryWorkerOptions> {
  const workerId = requireText(input.workerId, "worker.id", 128);
  requireInteger(
    input.batchSize,
    "worker.batchSize",
    1,
    notificationDispatchLimits.maximumBatchSize,
  );
  requireInteger(input.maximumConcurrency, "worker.maximumConcurrency", 1, 64);
  requireInteger(
    input.leaseDurationMs,
    "worker.leaseDurationMs",
    5_000,
    notificationDispatchLimits.maximumLeaseDurationMs,
  );
  requireInteger(
    input.heartbeatIntervalMs,
    "worker.heartbeatIntervalMs",
    1_000,
    input.leaseDurationMs - 1,
  );
  if (input.heartbeatIntervalMs * 3 >= input.leaseDurationMs) {
    throw new NotificationValidationError(
      "worker heartbeat must leave at least two recovery intervals",
    );
  }
  requireInteger(
    input.deliveryTimeoutMs,
    "worker.deliveryTimeoutMs",
    1_000,
    input.leaseDurationMs - 1,
  );
  requireInteger(input.renderTimeoutMs, "worker.renderTimeoutMs", 1, 5_000);
  requireInteger(
    input.maximumOutputBytes,
    "worker.maximumOutputBytes",
    1_024,
    1024 * 1_024,
  );
  return Object.freeze({ ...input, workerId });
}

function stableMessageId(claim: DeliveryClaim): string {
  const digest = createHash("sha256")
    .update("periapsis:email:v1\0")
    .update(claim.tenantId)
    .update("\0")
    .update(claim.deduplicationKey)
    .update("\0")
    .update(claim.recipient)
    .digest("hex");
  return `<${digest}@notifications.periapsis.invalid>`;
}

function requireDigest(value: string, field: string): string {
  requireText(value, field, 64);
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new NotificationValidationError(`${field} must be a SHA-256 digest`);
  }
  return value;
}

function canonicalProviderResponse(
  input: SanitizedProviderResponse,
): SanitizedProviderResponse {
  if (
    input === null ||
    typeof input !== "object" ||
    input.provider !== "smtp" ||
    Object.keys(input).some(
      (key) =>
        ![
          "acceptedCount",
          "provider",
          "receiptDigest",
          "rejectedCount",
          "responseClass",
        ].includes(key),
    )
  ) {
    throw new NotificationValidationError(
      "delivery provider returned an invalid response",
    );
  }
  const receiptDigest = requireDigest(
    input.receiptDigest,
    "provider receipt digest",
  );
  requireInteger(input.acceptedCount, "provider accepted count", 0, 1_000);
  requireInteger(input.rejectedCount, "provider rejected count", 0, 1_000);
  if (
    input.acceptedCount !== 1 ||
    input.rejectedCount !== 0 ||
    (input.responseClass !== undefined &&
      input.responseClass !== 2 &&
      input.responseClass !== 4 &&
      input.responseClass !== 5)
  ) {
    throw new NotificationValidationError(
      "delivery provider returned an inconsistent response",
    );
  }
  return Object.freeze({
    provider: "smtp",
    receiptDigest,
    acceptedCount: input.acceptedCount,
    rejectedCount: input.rejectedCount,
    ...(input.responseClass === undefined
      ? {}
      : { responseClass: input.responseClass }),
  });
}

function classifyDeliveryFailure(
  error: unknown,
  reserved: boolean,
): {
  failureClass: DeliveryFailureClass;
  retrySafety: "safe" | "uncertain" | "terminal";
} {
  if (error instanceof DeliveryProviderError) {
    return { failureClass: error.failureClass, retrySafety: error.retrySafety };
  }
  if (error instanceof NotificationTenantBoundaryError) {
    return { failureClass: "security", retrySafety: "terminal" };
  }
  if (
    error instanceof NotificationRenderError ||
    error instanceof NotificationValidationError
  ) {
    return { failureClass: "render", retrySafety: "terminal" };
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
