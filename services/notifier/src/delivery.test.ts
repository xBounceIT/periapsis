import { describe, expect, it } from "vitest";

import {
  createDeliveryClaim,
  DeliveryProviderError,
  NotificationDeliveryWorker,
  type DeliveryClaim,
  type DeliveryFailureClass,
  type DeliveryRepository,
  type EmailDeliveryProvider,
  type SanitizedProviderResponse,
} from "./index.js";
import {
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import { baseRule, id } from "./test/fixtures.js";
import { disabledTestTracing } from "./test/telemetry.js";

const now = new Date("2026-08-25T10:00:00.000Z");

describe("notification delivery worker", () => {
  it("sends once with a stable opaque message id and records a sanitized receipt", async () => {
    const claim = deliveryClaim();
    const repository = new FakeRepository([claim]);
    const sent: Array<{ recipient: string; messageId: string }> = [];
    const provider: EmailDeliveryProvider = {
      async send(input) {
        sent.push({
          recipient: input.recipient,
          messageId: input.headers?.["message-id"] ?? "",
        });
        return response();
      },
    };
    const { worker, logs } = workerWith(repository, provider);
    const result = await worker.runOnce(new AbortController().signal);

    expect(result).toEqual({
      claimed: 1,
      delivered: 1,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      uncertain: 0,
    });
    expect(sent).toHaveLength(1);
    expect(sent[0]?.messageId).toMatch(
      /^<[0-9a-f]{64}@notifications\.periapsis\.invalid>$/u,
    );
    expect(repository.completed).toHaveLength(1);
    expect(repository.completed[0]?.response).toEqual(response());
    expect(JSON.stringify(logs)).not.toContain("analyst@example.com");
  });

  it("replays a durable receipt without contacting the provider", async () => {
    const repository = new FakeRepository([deliveryClaim()]);
    repository.reservation = "already_delivered";
    let sends = 0;
    const { worker } = workerWith(repository, {
      async send() {
        sends += 1;
        return response();
      },
    });
    const result = await worker.runOnce(new AbortController().signal);
    expect(result.replayed).toBe(1);
    expect(sends).toBe(0);
    expect(repository.replays).toBe(1);
  });

  it("retries only definitely safe provider failures and dead-letters uncertain submissions", async () => {
    const safeRepository = new FakeRepository([deliveryClaim()]);
    const safe = workerWith(safeRepository, {
      async send() {
        throw new DeliveryProviderError("connectivity", "safe");
      },
    }).worker;
    const safeResult = await safe.runOnce(new AbortController().signal);
    expect(safeResult.retried).toBe(1);
    expect(safeRepository.retries[0]?.failureClass).toBe("connectivity");
    expect(safeRepository.retries[0]?.nextAttemptAt.getTime()).toBeGreaterThan(
      now.getTime(),
    );

    const uncertainRepository = new FakeRepository([deliveryClaim()]);
    const uncertain = workerWith(uncertainRepository, {
      async send() {
        throw new DeliveryProviderError("timeout", "uncertain");
      },
    }).worker;
    const uncertainResult = await uncertain.runOnce(
      new AbortController().signal,
    );
    expect(uncertainResult.uncertain).toBe(1);
    expect(uncertainRepository.deadLetters[0]?.failureClass).toBe(
      "submission_uncertain",
    );
    expect(uncertainRepository.retries).toHaveLength(0);
  });

  it("leaves response-lost completion for fenced replay instead of resending", async () => {
    const claim = deliveryClaim();
    const repository = new FakeRepository([claim]);
    repository.completeError = new Error("simulated response loss");
    let sends = 0;
    const { worker } = workerWith(repository, {
      async send() {
        sends += 1;
        return response();
      },
    });
    const first = await worker.runOnce(new AbortController().signal);
    expect(first.uncertain).toBe(1);
    expect(repository.retries).toHaveLength(0);
    expect(repository.deadLetters).toHaveLength(0);

    repository.completeError = undefined;
    repository.reservation = "already_delivered";
    repository.claims = [claim];
    const second = await worker.runOnce(new AbortController().signal);
    expect(second.replayed).toBe(1);
    expect(sends).toBe(1);
  });

  it("dead-letters a lost reservation response as submission-uncertain", async () => {
    const repository = new FakeRepository([deliveryClaim()]);
    repository.reservationError = new Error(
      "database response containing secret details was lost",
    );
    let sends = 0;
    const { worker, logs } = workerWith(repository, {
      async send() {
        sends += 1;
        return response();
      },
    });

    const result = await worker.runOnce(new AbortController().signal);

    expect(result.uncertain).toBe(1);
    expect(sends).toBe(0);
    expect(repository.retries).toHaveLength(0);
    expect(repository.deadLetters).toEqual([
      { failureClass: "submission_uncertain" },
    ]);
    expect(JSON.stringify(logs)).not.toContain("secret details");
  });

  it("fails closed for forged and cross-tenant claims", async () => {
    const authentic = deliveryClaim();
    const forged = { ...authentic };
    const repository = new FakeRepository([forged]);
    const { worker } = workerWith(repository, {
      async send() {
        return response();
      },
    });
    await expect(worker.runOnce(new AbortController().signal)).rejects.toThrow(
      NotificationValidationError,
    );

    const input = deliveryClaimInput();
    input.template.tenantId = id(99);
    expect(() => createDeliveryClaim(input)).toThrow(
      NotificationTenantBoundaryError,
    );

    const duplicate = deliveryClaim(9);
    const duplicateRepository = new FakeRepository([duplicate, duplicate]);
    const duplicateWorker = workerWith(duplicateRepository, {
      async send() {
        return response();
      },
    }).worker;
    await expect(
      duplicateWorker.runOnce(new AbortController().signal),
    ).rejects.toThrow(NotificationValidationError);
  });

  it("bounds concurrency across a claimed batch", async () => {
    const claims = [1, 2, 3, 4].map((value) => deliveryClaim(value));
    const repository = new FakeRepository(claims);
    let active = 0;
    let maximum = 0;
    const provider: EmailDeliveryProvider = {
      async send() {
        active += 1;
        maximum = Math.max(maximum, active);
        await new Promise((resolve) => setTimeout(resolve, 10));
        active -= 1;
        return response();
      },
    };
    const { worker } = workerWith(repository, provider, {
      maximumConcurrency: 2,
      batchSize: 4,
    });
    const result = await worker.runOnce(new AbortController().signal);
    expect(result.delivered).toBe(4);
    expect(maximum).toBe(2);
  });

  it("rejects malformed repository states and never persists provider extras", async () => {
    const invalidReservationRepository = new FakeRepository([deliveryClaim()]);
    Reflect.set(invalidReservationRepository, "reservation", "invalid");
    const invalidReservationWorker = workerWith(invalidReservationRepository, {
      async send() {
        return response();
      },
    }).worker;
    const reservationResult = await invalidReservationWorker.runOnce(
      new AbortController().signal,
    );
    expect(reservationResult.deadLettered).toBe(1);
    expect(invalidReservationRepository.completed).toHaveLength(0);

    const invalidResponseRepository = new FakeRepository([deliveryClaim(2)]);
    const { worker, logs } = workerWith(invalidResponseRepository, {
      async send() {
        return { ...response(), rawResponse: "recipient@example.com secret" };
      },
    });
    const providerResult = await worker.runOnce(new AbortController().signal);
    expect(providerResult.uncertain).toBe(1);
    expect(invalidResponseRepository.completed).toHaveLength(0);
    expect(JSON.stringify(logs)).not.toContain("recipient@example.com");
  });

  it("cancels an in-flight lease heartbeat after delivery completes", async () => {
    const repository = new FakeRepository([deliveryClaim()]);
    let markHeartbeatStarted!: () => void;
    const heartbeatStarted = new Promise<void>((resolve) => {
      markHeartbeatStarted = resolve;
    });
    repository.heartbeat = async (_claim, _leaseUntil, signal) =>
      new Promise<boolean>((_resolve, reject) => {
        markHeartbeatStarted();
        if (signal.aborted) {
          reject(signal.reason);
          return;
        }
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
      });
    const { worker } = workerWith(
      repository,
      {
        async send() {
          await heartbeatStarted;
          return response();
        },
      },
      {
        leaseDurationMs: 5_000,
        heartbeatIntervalMs: 1_000,
        deliveryTimeoutMs: 4_000,
      },
    );
    const startedAt = performance.now();
    const result = await worker.runOnce(new AbortController().signal);
    expect(result.delivered).toBe(1);
    expect(performance.now() - startedAt).toBeLessThan(2_500);
  });
});

class FakeRepository implements DeliveryRepository {
  claims: readonly DeliveryClaim[];
  reservation: "reserved" | "already_delivered" | "uncertain" = "reserved";
  reservationError: Error | undefined;
  completeError: Error | undefined;
  completed: Array<{ response: SanitizedProviderResponse }> = [];
  replays = 0;
  retries: Array<{ failureClass: DeliveryFailureClass; nextAttemptAt: Date }> =
    [];
  deadLetters: Array<{
    failureClass: DeliveryFailureClass | "submission_uncertain";
  }> = [];

  constructor(claims: readonly DeliveryClaim[]) {
    this.claims = claims;
  }

  async claimBatch(): Promise<readonly DeliveryClaim[]> {
    const claims = this.claims;
    this.claims = [];
    return claims;
  }

  heartbeat: DeliveryRepository["heartbeat"] = async () => true;

  async reserveSubmission(): Promise<
    "reserved" | "already_delivered" | "uncertain"
  > {
    if (this.reservationError !== undefined) throw this.reservationError;
    return this.reservation;
  }

  async complete(
    _claim: DeliveryClaim,
    responseValue: SanitizedProviderResponse,
  ): Promise<void> {
    this.completed.push({ response: responseValue });
    if (this.completeError !== undefined) throw this.completeError;
  }

  async completeReplay(): Promise<void> {
    this.replays += 1;
  }

  async retry(
    _claim: DeliveryClaim,
    failureClass: DeliveryFailureClass,
    nextAttemptAt: Date,
  ): Promise<void> {
    this.retries.push({ failureClass, nextAttemptAt });
  }

  async deadLetter(
    _claim: DeliveryClaim,
    failureClass: DeliveryFailureClass | "submission_uncertain",
  ): Promise<void> {
    this.deadLetters.push({ failureClass });
  }
}

function workerWith(
  repository: FakeRepository,
  provider: EmailDeliveryProvider,
  overrides: Partial<
    ConstructorParameters<typeof NotificationDeliveryWorker>[0]["options"]
  > = {},
) {
  const logs: unknown[] = [];
  return {
    logs,
    worker: new NotificationDeliveryWorker({
      repository,
      providers: {
        async resolve() {
          return provider;
        },
      },
      telemetry: { record() {} },
      logger: {
        info(event, attributes) {
          logs.push({ event, attributes });
        },
        error(event, attributes) {
          logs.push({ event, attributes });
        },
      },
      tracing: disabledTestTracing,
      options: {
        workerId: "notifier-test-1",
        batchSize: 10,
        maximumConcurrency: 2,
        leaseDurationMs: 10_000,
        heartbeatIntervalMs: 2_000,
        deliveryTimeoutMs: 5_000,
        renderTimeoutMs: 100,
        maximumOutputBytes: 256 * 1_024,
        ...overrides,
      },
      now: () => new Date(now),
    }),
  };
}

function deliveryClaim(sequence = 1): DeliveryClaim {
  return createDeliveryClaim(deliveryClaimInput(sequence));
}

function deliveryClaimInput(sequence = 1) {
  const rule = baseRule();
  return {
    id: id(100 + sequence),
    tenantId: id(2),
    eventId: id(200 + sequence),
    ruleId: rule.id,
    ruleVersion: rule.version,
    smtpConfigurationScope: "tenant" as const,
    smtpConfigurationId: id(60),
    smtpConfigurationVersion: 1,
    deduplicationKey: sequence.toString(16).padStart(64, "0"),
    recipient: `analyst${sequence}@example.com`,
    audience: "operator" as const,
    context: {
      alert: { title: "Critical alert" },
      links: { alert: "https://portal.example.test/1" },
    },
    template: {
      id: rule.templateId,
      tenantId: id(2),
      key: "critical_alert",
      name: "Critical alert",
      language: "en-US",
      version: rule.templateVersion,
      subject: "Alert {{alert.title}}",
      html: '<p>{{alert.title}}</p><a href="{{links.alert}}">Open</a>',
      plainText: "{{alert.title}} {{links.alert}}",
    },
    retry: rule.retry,
    attempt: 1,
    fenceToken: id(300 + sequence),
    leaseUntil: new Date(now.getTime() + 60_000),
    traceContext: {
      traceParent: "00-11111111111111111111111111111111-2222222222222222-01",
    },
  };
}

function response(): SanitizedProviderResponse {
  return {
    provider: "smtp",
    receiptDigest: "a".repeat(64),
    acceptedCount: 1,
    rejectedCount: 0,
    responseClass: 2,
  };
}
