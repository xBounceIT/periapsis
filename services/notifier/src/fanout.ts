import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import type { DeliveryLogger } from "./delivery.js";
import { notificationDispatchLimits } from "./dispatch-limits.js";
import {
  NotificationConfigurationError,
  NotificationConflictError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import {
  createNotificationEvent,
  type ContextValue,
  type NotificationEvent,
  type NotificationEventInput,
} from "./event.js";
import { planNotification, type RecipientCandidateInput } from "./planner.js";
import {
  createNotificationRule,
  type NotificationRule,
  type NotificationRuleInput,
  type RetryPolicyInput,
} from "./rule.js";
import {
  createNotificationTemplate,
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
import type { NotificationTracing } from "./telemetry.js";

export interface FanoutClaimInput {
  id: string;
  tenantId: string;
  event: NotificationEventInput;
  attempt: number;
  maximumAttempts: number;
  fenceToken: string;
  leaseUntil: Date;
}

export interface FanoutClaim {
  readonly id: string;
  readonly tenantId: string;
  readonly event: NotificationEvent;
  readonly attempt: number;
  readonly maximumAttempts: number;
  readonly fenceToken: string;
  readonly leaseUntil: Date;
}

export interface SmtpConfigurationPin {
  readonly scope: "tenant" | "platform";
  readonly id: string;
  readonly version: number;
}

export interface NotificationFanoutInputs {
  readonly rules: readonly NotificationRuleInput[];
  readonly candidates: readonly RecipientCandidateInput[];
  readonly templates: readonly NotificationTemplateInput[];
  readonly smtpConfiguration: SmtpConfigurationPin | null;
}

export interface PlannedEmailDelivery {
  readonly deliveryKey: string;
  readonly tenantId: string;
  readonly eventId: string;
  readonly ruleId: string;
  readonly ruleVersion: number;
  readonly smtpConfigurationScope: "tenant" | "platform";
  readonly smtpConfigurationId: string;
  readonly smtpConfigurationVersion: number;
  readonly template: NotificationTemplateInput;
  readonly recipient: string;
  readonly audience: "operator" | "customer";
  readonly principalId?: string;
  readonly context: Readonly<Record<string, ContextValue>>;
  readonly priority: number;
  readonly deliverAfter: Date;
  readonly deduplicationKey: string;
  readonly groupingKey?: string;
  readonly groupingWindowMs: number;
  readonly groupingMaximumItems: number;
  readonly retry: RetryPolicyInput;
}

export interface FanoutCommitResult {
  readonly outcome: "committed" | "already_committed";
  readonly emailCount: number;
  readonly webhookCount: number;
  readonly cancelledWebhookCount: number;
  readonly totalCount: number;
}

export type FanoutDeadLetterReason =
  "configuration" | "security" | "validation" | "attempts_exhausted";

export interface NotificationFanoutRepository {
  claimFanoutBatch(input: {
    workerId: string;
    limit: number;
    leaseDurationMs: number;
    now: Date;
    signal: AbortSignal;
  }): Promise<readonly FanoutClaim[]>;
  heartbeatFanout(
    claim: FanoutClaim,
    leaseUntil: Date,
    signal: AbortSignal,
  ): Promise<boolean>;
  loadFanoutInputs(
    claim: FanoutClaim,
    signal: AbortSignal,
  ): Promise<NotificationFanoutInputs>;
  commitFanout(
    claim: FanoutClaim,
    deliveries: readonly PlannedEmailDelivery[],
    at: Date,
    signal: AbortSignal,
  ): Promise<FanoutCommitResult>;
  retryFanout(
    claim: FanoutClaim,
    nextAttemptAt: Date,
    at: Date,
    signal: AbortSignal,
  ): Promise<void>;
  deadLetterFanout(
    claim: FanoutClaim,
    reason: FanoutDeadLetterReason,
    at: Date,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface NotificationFanoutOptions {
  workerId: string;
  batchSize: number;
  maximumConcurrency: number;
  leaseDurationMs: number;
  heartbeatIntervalMs: number;
  processingTimeoutMs: number;
  initialRetryDelayMs: number;
  maximumRetryDelayMs: number;
}

export interface FanoutRunResult {
  readonly claimed: number;
  readonly committed: number;
  readonly replayed: number;
  readonly retried: number;
  readonly deadLettered: number;
  readonly fenced: number;
  readonly deliveriesPlanned: number;
}

type FanoutOutcome = Readonly<{
  kind: "committed" | "replayed" | "retried" | "dead_lettered" | "fenced";
  deliveries: number;
}>;

const authenticFanoutClaims = new WeakSet<FanoutClaim>();
const authenticPlannedDeliveries = new WeakSet<PlannedEmailDelivery>();

export function createFanoutClaim(input: FanoutClaimInput): FanoutClaim {
  requireUuidV7(input.id, "fanout claim id");
  requireUuidV7(input.tenantId, "fanout claim tenantId");
  requireUuidV7(input.fenceToken, "fanout claim fenceToken");
  requireInteger(input.maximumAttempts, "fanout maximumAttempts", 1, 100);
  requireInteger(input.attempt, "fanout attempt", 1, input.maximumAttempts);
  const event = createNotificationEvent(input.event);
  if (event.tenantId !== input.tenantId) {
    throw new NotificationTenantBoundaryError();
  }
  if (event.id !== input.id) {
    throw new NotificationValidationError(
      "fanout claim and notification event ids must match",
    );
  }
  const leaseUntil = requireInstant(input.leaseUntil, "fanout leaseUntil");
  const leaseUntilEpoch = leaseUntil.getTime();
  const claim = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    event,
    attempt: input.attempt,
    maximumAttempts: input.maximumAttempts,
    fenceToken: input.fenceToken,
    get leaseUntil(): Date {
      return new Date(leaseUntilEpoch);
    },
  });
  authenticFanoutClaims.add(claim);
  return claim;
}

export function isAuthenticFanoutClaim(claim: FanoutClaim): boolean {
  return authenticFanoutClaims.has(claim);
}

export function isAuthenticPlannedEmailDelivery(
  delivery: PlannedEmailDelivery,
): boolean {
  return authenticPlannedDeliveries.has(delivery);
}

export class NotificationFanoutWorker {
  readonly #repository: NotificationFanoutRepository;
  readonly #logger: DeliveryLogger;
  readonly #tracing: NotificationTracing;
  readonly #options: Readonly<NotificationFanoutOptions>;
  readonly #now: () => Date;

  constructor(dependencies: {
    repository: NotificationFanoutRepository;
    logger: DeliveryLogger;
    tracing: NotificationTracing;
    options: NotificationFanoutOptions;
    now?: () => Date;
  }) {
    this.#repository = dependencies.repository;
    this.#logger = dependencies.logger;
    this.#tracing = dependencies.tracing;
    this.#options = validateOptions(dependencies.options);
    this.#now = dependencies.now ?? (() => new Date());
  }

  async runOnce(signal: AbortSignal): Promise<FanoutRunResult> {
    if (signal.aborted) throw signal.reason;
    const now = requireInstant(this.#now(), "fanout now");
    const claims = await this.#repository.claimFanoutBatch({
      workerId: this.#options.workerId,
      limit: this.#options.batchSize,
      leaseDurationMs: this.#options.leaseDurationMs,
      now,
      signal,
    });
    if (!Array.isArray(claims) || claims.length > this.#options.batchSize) {
      throw new NotificationValidationError(
        "fanout repository returned an invalid claim batch",
      );
    }
    const seen = new Set<string>();
    for (const claim of claims) {
      if (
        !authenticFanoutClaims.has(claim) ||
        seen.has(claim.id) ||
        claim.leaseUntil <= now
      ) {
        throw new NotificationValidationError(
          "fanout repository returned a forged, duplicate, or expired claim",
        );
      }
      seen.add(claim.id);
    }

    const outcomes: Array<FanoutOutcome | undefined> = Array.from({
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
          // The fixed-size runner pool is the concurrency boundary.
          // eslint-disable-next-line no-await-in-loop
          const claim = claims[index];
          if (claim === undefined) return;
          // eslint-disable-next-line no-await-in-loop
          outcomes[index] = await this.#tracing.runConsumerSpan(
            "fanout",
            claim.event.traceContext,
            () => this.#process(claim, signal),
            (outcome) => outcome.kind,
          );
        }
      },
    );
    await Promise.all(runners);
    if (signal.aborted) throw signal.reason;
    return Object.freeze({
      claimed: claims.length,
      committed: outcomes.filter((value) => value?.kind === "committed").length,
      replayed: outcomes.filter((value) => value?.kind === "replayed").length,
      retried: outcomes.filter((value) => value?.kind === "retried").length,
      deadLettered: outcomes.filter((value) => value?.kind === "dead_lettered")
        .length,
      fenced: outcomes.filter((value) => value?.kind === "fenced").length,
      deliveriesPlanned: outcomes.reduce(
        (sum, value) => sum + (value?.deliveries ?? 0),
        0,
      ),
    });
  }

  async #process(
    claim: FanoutClaim,
    parentSignal: AbortSignal,
  ): Promise<FanoutOutcome> {
    try {
      return await this.#withHeartbeat(claim, parentSignal, async (signal) => {
        const inputs = await this.#repository.loadFanoutInputs(claim, signal);
        const observedAt = requireInstant(this.#now(), "fanout now");
        const committedAt = new Date(
          Math.max(observedAt.getTime(), claim.event.occurredAt.getTime()),
        );
        const deliveries = buildEmailDeliveries(claim, inputs, committedAt);
        const commit = canonicalFanoutCommitResult(
          await this.#repository.commitFanout(
            claim,
            deliveries,
            committedAt,
            signal,
          ),
        );
        this.#logger.info("notification_fanout_finished", {
          tenantId: claim.tenantId,
          eventId: claim.id,
          outcome: commit.outcome,
          emailDeliveries: commit.emailCount,
          webhookDeliveries: commit.webhookCount,
          cancelledWebhookDeliveries: commit.cancelledWebhookCount,
          deliveries: commit.totalCount,
        });
        return Object.freeze({
          kind: commit.outcome === "committed" ? "committed" : "replayed",
          deliveries: commit.outcome === "committed" ? commit.totalCount : 0,
        });
      });
    } catch (error) {
      if (parentSignal.aborted) throw parentSignal.reason;
      if (error instanceof NotificationConflictError) {
        this.#logger.info("notification_fanout_fenced", {
          tenantId: claim.tenantId,
          eventId: claim.id,
        });
        return Object.freeze({ kind: "fenced", deliveries: 0 });
      }
      const terminalReason = classifyTerminalFanoutFailure(error);
      const failedAt = requireInstant(this.#now(), "fanout now");
      if (terminalReason !== null || claim.attempt >= claim.maximumAttempts) {
        const reason: FanoutDeadLetterReason =
          terminalReason ?? "attempts_exhausted";
        await this.#repository.deadLetterFanout(
          claim,
          reason,
          failedAt,
          parentSignal,
        );
        this.#logger.error("notification_fanout_dead_lettered", {
          tenantId: claim.tenantId,
          eventId: claim.id,
          attempt: claim.attempt,
          reason,
        });
        return Object.freeze({ kind: "dead_lettered", deliveries: 0 });
      }
      const nextAttemptAt = nextFanoutAttemptAt(
        claim,
        failedAt,
        this.#options.initialRetryDelayMs,
        this.#options.maximumRetryDelayMs,
      );
      await this.#repository.retryFanout(
        claim,
        nextAttemptAt,
        failedAt,
        parentSignal,
      );
      this.#logger.info("notification_fanout_retried", {
        tenantId: claim.tenantId,
        eventId: claim.id,
        attempt: claim.attempt,
      });
      return Object.freeze({ kind: "retried", deliveries: 0 });
    }
  }

  async #withHeartbeat<T>(
    claim: FanoutClaim,
    parentSignal: AbortSignal,
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const stop = new AbortController();
    const lostLease = new AbortController();
    const timeout = AbortSignal.timeout(this.#options.processingTimeoutMs);
    const operationSignal = AbortSignal.any([
      parentSignal,
      lostLease.signal,
      timeout,
    ]);
    const heartbeat = (async (): Promise<void> => {
      while (!stop.signal.aborted) {
        try {
          // Heartbeats are serialized to preserve fence ordering.
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
          const retained = await this.#repository.heartbeatFanout(
            claim,
            leaseUntil,
            heartbeatSignal,
          );
          if (!retained) {
            lostLease.abort(
              new NotificationConflictError("fanout lease was fenced"),
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
          : new NotificationConflictError("fanout lease renewal failed");
      }
      throw error;
    } finally {
      stop.abort();
      await heartbeat;
    }
  }
}

function canonicalFanoutCommitResult(
  input: FanoutCommitResult,
): FanoutCommitResult {
  if (
    input === null ||
    typeof input !== "object" ||
    (input.outcome !== "committed" && input.outcome !== "already_committed")
  ) {
    throw new NotificationValidationError(
      "fanout repository returned an invalid commit outcome",
    );
  }
  requireInteger(input.emailCount, "fanout committed email count", 0, 10_000);
  requireInteger(
    input.webhookCount,
    "fanout committed webhook count",
    0,
    1_000,
  );
  requireInteger(
    input.cancelledWebhookCount,
    "fanout cancelled webhook count",
    0,
    input.webhookCount,
  );
  requireInteger(input.totalCount, "fanout committed total count", 0, 11_000);
  if (
    input.totalCount !== input.emailCount + input.webhookCount ||
    (input.outcome === "already_committed" && input.totalCount !== 0)
  ) {
    throw new NotificationValidationError(
      "fanout repository returned inconsistent commit counts",
    );
  }
  return Object.freeze({ ...input });
}

function buildEmailDeliveries(
  claim: FanoutClaim,
  inputs: NotificationFanoutInputs,
  plannedAtInput: Date,
): readonly PlannedEmailDelivery[] {
  if (
    inputs === null ||
    typeof inputs !== "object" ||
    !Array.isArray(inputs.rules) ||
    !Array.isArray(inputs.candidates) ||
    !Array.isArray(inputs.templates) ||
    inputs.rules.length > 1_000 ||
    inputs.candidates.length > 10_000 ||
    inputs.templates.length > 1_000
  ) {
    throw new NotificationValidationError(
      "fanout inputs are malformed or oversized",
    );
  }
  const clockNow = requireInstant(plannedAtInput, "fanout plannedAt");
  const plannedAt = new Date(
    Math.max(clockNow.getTime(), claim.event.occurredAt.getTime()),
  );
  const rules = inputs.rules.map(createNotificationRule);
  const ruleIds = new Set<string>();
  for (const rule of rules) {
    if (
      rule.tenantId !== claim.tenantId ||
      rule.channel !== "email" ||
      ruleIds.has(rule.id)
    ) {
      throw new NotificationTenantBoundaryError();
    }
    ruleIds.add(rule.id);
  }
  const templates = new Map<string, NotificationTemplate>();
  for (const input of inputs.templates) {
    const template = createNotificationTemplate(input);
    if (template.tenantId !== claim.tenantId) {
      throw new NotificationTenantBoundaryError();
    }
    const key = `${template.id}:${template.version}`;
    if (templates.has(key)) {
      throw new NotificationValidationError(
        "fanout template inventory contains a duplicate pin",
      );
    }
    templates.set(key, template);
  }

  const deliveries: PlannedEmailDelivery[] = [];
  const deliveryKeys = new Set<string>();
  for (const rule of rules.toSorted(compareRules)) {
    const plan = planNotification(
      rule,
      claim.event,
      inputs.candidates,
      plannedAt,
    );
    if (plan === null) continue;
    const template = templates.get(
      `${plan.templateId}:${plan.templateVersion}`,
    );
    if (template === undefined) {
      throw new NotificationConfigurationError(
        "fanout template pin is unavailable",
      );
    }
    const smtp = canonicalSmtpPin(inputs.smtpConfiguration);
    for (const recipient of plan.recipients) {
      const delivery = createPlannedEmailDelivery(
        claim,
        rule,
        template,
        smtp,
        recipient.email,
        recipient.audience,
        recipient.principalId,
        plan.contexts[recipient.audience],
        plan.deliverAfter,
        plan.deduplicationKey,
        plan.groupingKey,
      );
      if (deliveryKeys.has(delivery.deliveryKey)) {
        throw new NotificationValidationError(
          "fanout produced a duplicate delivery key",
        );
      }
      deliveryKeys.add(delivery.deliveryKey);
      deliveries.push(delivery);
    }
  }
  return Object.freeze(deliveries);
}

function createPlannedEmailDelivery(
  claim: FanoutClaim,
  rule: NotificationRule,
  template: NotificationTemplate,
  smtp: SmtpConfigurationPin,
  recipientInput: string,
  audience: "operator" | "customer",
  principalId: string | undefined,
  context: Readonly<Record<string, ContextValue>>,
  deliverAfterInput: Date,
  deduplicationKey: string,
  groupingKey: string | undefined,
): PlannedEmailDelivery {
  const recipient = canonicalEmail(recipientInput, "fanout recipient");
  if (principalId !== undefined) {
    requireUuidV7(principalId, "fanout principalId");
  }
  const deliverAfter = requireInstant(deliverAfterInput, "fanout deliverAfter");
  const deliverAfterEpoch = deliverAfter.getTime();
  const deliveryKey = createHash("sha256")
    .update("periapsis:notification-delivery:v1\0")
    .update(claim.tenantId)
    .update("\0")
    .update(claim.event.id)
    .update("\0")
    .update(rule.id)
    .update("\0")
    .update(String(rule.version))
    .update("\0")
    .update(recipient)
    .update("\0")
    .update(deduplicationKey)
    .digest("hex");
  const retry = Object.freeze({ ...rule.retry });
  const delivery = Object.freeze({
    deliveryKey,
    tenantId: claim.tenantId,
    eventId: claim.event.id,
    ruleId: rule.id,
    ruleVersion: rule.version,
    smtpConfigurationScope: smtp.scope,
    smtpConfigurationId: smtp.id,
    smtpConfigurationVersion: smtp.version,
    template: templateToInput(template),
    recipient,
    audience,
    ...(principalId === undefined ? {} : { principalId }),
    context,
    priority: rule.priority,
    get deliverAfter(): Date {
      return new Date(deliverAfterEpoch);
    },
    deduplicationKey,
    ...(groupingKey === undefined ? {} : { groupingKey }),
    groupingWindowMs: rule.grouping.windowMs,
    groupingMaximumItems: rule.grouping.maximumItems,
    retry,
  });
  authenticPlannedDeliveries.add(delivery);
  return delivery;
}

function templateToInput(
  template: NotificationTemplate,
): NotificationTemplateInput {
  return Object.freeze({
    id: template.id,
    tenantId: template.tenantId,
    key: template.key,
    name: template.name,
    language: template.language,
    version: template.version,
    subject: template.subject,
    html: template.html,
    ...(template.plainText === undefined
      ? {}
      : { plainText: template.plainText }),
    ...(template.css === "" ? {} : { css: template.css }),
  });
}

function canonicalSmtpPin(
  input: SmtpConfigurationPin | null,
): SmtpConfigurationPin {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new NotificationConfigurationError(
      "an enabled SMTP configuration pin is required",
    );
  }
  requireUuidV7(input.id, "fanout SMTP configuration id");
  if (input.scope !== "tenant" && input.scope !== "platform") {
    throw new NotificationConfigurationError(
      "fanout SMTP configuration scope is unsupported",
    );
  }
  requireInteger(
    input.version,
    "fanout SMTP configuration version",
    1,
    2_147_483_647,
  );
  return Object.freeze({
    scope: input.scope,
    id: input.id,
    version: input.version,
  });
}

function compareRules(left: NotificationRule, right: NotificationRule): number {
  return right.priority - left.priority || left.id.localeCompare(right.id);
}

function classifyTerminalFanoutFailure(
  error: unknown,
): FanoutDeadLetterReason | null {
  if (error instanceof NotificationTenantBoundaryError) return "security";
  if (error instanceof NotificationConfigurationError) return "configuration";
  if (error instanceof NotificationValidationError) {
    return "validation";
  }
  return null;
}

function nextFanoutAttemptAt(
  claim: FanoutClaim,
  failedAt: Date,
  initialDelayMs: number,
  maximumDelayMs: number,
): Date {
  const exponential = Math.min(
    maximumDelayMs,
    initialDelayMs * 2 ** (claim.attempt - 1),
  );
  const digest = createHash("sha256")
    .update("periapsis:fanout-retry:v1\0")
    .update(claim.id)
    .update("\0")
    .update(String(claim.attempt))
    .digest();
  const fraction = digest.readUInt32BE(0) / 0xffff_ffff;
  const jittered = exponential * (0.8 + fraction * 0.4);
  return new Date(failedAt.getTime() + Math.max(1_000, Math.round(jittered)));
}

function validateOptions(
  input: NotificationFanoutOptions,
): Readonly<NotificationFanoutOptions> {
  const workerId = requireText(input.workerId, "fanout workerId", 128);
  requireInteger(
    input.batchSize,
    "fanout batchSize",
    1,
    notificationDispatchLimits.maximumBatchSize,
  );
  requireInteger(input.maximumConcurrency, "fanout maximumConcurrency", 1, 64);
  requireInteger(
    input.leaseDurationMs,
    "fanout leaseDurationMs",
    5_000,
    notificationDispatchLimits.maximumLeaseDurationMs,
  );
  requireInteger(
    input.heartbeatIntervalMs,
    "fanout heartbeatIntervalMs",
    1_000,
    input.leaseDurationMs - 1,
  );
  if (input.heartbeatIntervalMs * 3 >= input.leaseDurationMs) {
    throw new NotificationValidationError(
      "fanout heartbeat must leave at least two recovery intervals",
    );
  }
  requireInteger(
    input.processingTimeoutMs,
    "fanout processingTimeoutMs",
    1_000,
    input.leaseDurationMs - 1,
  );
  requireInteger(
    input.initialRetryDelayMs,
    "fanout initialRetryDelayMs",
    1_000,
    24 * 60 * 60_000,
  );
  requireInteger(
    input.maximumRetryDelayMs,
    "fanout maximumRetryDelayMs",
    input.initialRetryDelayMs,
    7 * 24 * 60 * 60_000,
  );
  return Object.freeze({ ...input, workerId });
}
