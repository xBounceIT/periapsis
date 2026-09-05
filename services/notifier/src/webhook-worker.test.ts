import { describe, expect, it, vi } from "vitest";

import type { DeliveryLogger, DeliveryTelemetry } from "./delivery.js";
import {
  DeliveryProviderError,
  NotificationValidationError,
} from "./errors.js";
import { id, protectedSecret } from "./test/fixtures.js";
import { disabledTestTracing } from "./test/telemetry.js";
import type { NotificationTracing } from "./telemetry.js";
import type { SignedWebhookRequest } from "./webhook.js";
import {
  createWebhookConfigurationPolicyPin,
  createWebhookDeliveryPolicyPin,
  createWebhookUrlPolicyVersion,
} from "./webhook-url-policy.js";
import {
  createWebhookDeliveryClaim,
  NotificationWebhookDeliveryWorker,
  type WebhookDeliveryClaim,
  type WebhookDeliveryClaimInput,
  type WebhookDeliveryRepository,
  type WebhookTransport,
  type WebhookUrlPolicyAttemptGate,
} from "./webhook-worker.js";

describe("notification webhook delivery worker", () => {
  it("signs, reserves, and completes an exact immutable webhook claim", async () => {
    const claim = webhookClaim();
    const repository = repositoryFor([claim]);
    const send = vi.fn(
      async (_input: SignedWebhookRequest, _signal: AbortSignal) => ({
        provider: "webhook" as const,
        statusCode: 204,
        receiptDigest: "a".repeat(64),
      }),
    );
    const worker = workerFor(repository, { send });

    await expect(worker.runOnce(new AbortController().signal)).resolves.toEqual(
      {
        claimed: 1,
        delivered: 1,
        replayed: 0,
        retried: 0,
        deadLettered: 0,
        uncertain: 0,
      },
    );

    expect(repository.reserveWebhookSubmission).toHaveBeenCalledWith(
      claim,
      expect.stringMatching(
        /^<[0-9a-f]{64}@notifications[.]periapsis[.]invalid>$/u,
      ),
      now,
      expect.any(AbortSignal),
    );
    expect(send).toHaveBeenCalledTimes(1);
    const request = send.mock.calls[0]?.[0];
    expect(request?.headers["x-periapsis-delivery-id"]).toBe(claim.id);
    expect(request?.headers["x-periapsis-signature"]).toMatch(
      /^v1=[0-9a-f]{64}$/u,
    );
    expect(repository.completeWebhook).toHaveBeenCalledWith(
      claim,
      { provider: "webhook", statusCode: 204, receiptDigest: "a".repeat(64) },
      now,
      expect.any(AbortSignal),
    );
  });

  it("releases a safely failed reserved submission for retry", async () => {
    const claim = webhookClaim();
    const repository = repositoryFor([claim]);
    const worker = workerFor(repository, {
      async send() {
        throw new DeliveryProviderError("connectivity", "safe");
      },
    });

    await expect(
      worker.runOnce(new AbortController().signal),
    ).resolves.toMatchObject({
      claimed: 1,
      retried: 1,
      uncertain: 0,
    });
    expect(repository.retryWebhook).toHaveBeenCalledWith(
      claim,
      "connectivity",
      expect.any(Date),
      now,
      true,
      expect.any(AbortSignal),
    );
    expect(repository.deadLetterWebhook).not.toHaveBeenCalled();
  });

  it("dead-letters an ambiguous reserved submission without retrying it", async () => {
    const claim = webhookClaim();
    const repository = repositoryFor([claim]);
    const worker = workerFor(repository, {
      async send() {
        throw new DeliveryProviderError("timeout", "uncertain");
      },
    });

    await expect(
      worker.runOnce(new AbortController().signal),
    ).resolves.toMatchObject({
      claimed: 1,
      retried: 0,
      uncertain: 1,
    });
    expect(repository.deadLetterWebhook).toHaveBeenCalledWith(
      claim,
      "submission_uncertain",
      now,
      expect.any(AbortSignal),
    );
    expect(repository.retryWebhook).not.toHaveBeenCalled();
  });

  it("treats a lost reservation response as submission uncertainty", async () => {
    const claim = webhookClaim();
    const repository: WebhookDeliveryRepository = {
      ...repositoryFor([claim]),
      reserveWebhookSubmission: vi.fn(async () => {
        throw new Error("database response lost");
      }),
    };
    const send = vi.fn();
    const worker = workerFor(repository, { send });

    await expect(
      worker.runOnce(new AbortController().signal),
    ).resolves.toMatchObject({
      claimed: 1,
      retried: 0,
      uncertain: 1,
    });
    expect(repository.deadLetterWebhook).toHaveBeenCalledWith(
      claim,
      "submission_uncertain",
      now,
      expect.any(AbortSignal),
    );
    expect(send).not.toHaveBeenCalled();
  });

  it("revalidates only fresh submissions and does so after reservation", async () => {
    const claim = webhookClaim();
    const freshRepository = repositoryFor([claim]);
    const beginAttempt = vi.fn(async () => ({
      attemptEvidence: {
        allowed: true as const,
        reason: "allowed_by_rule" as const,
        policyId: id(115),
        policyVersion: 3,
        policyDigest: "a".repeat(64),
        endpointDigest: "b".repeat(64),
      },
    }));
    const send = vi.fn(async () => ({
      provider: "webhook" as const,
      statusCode: 204,
      receiptDigest: "c".repeat(64),
    }));
    await workerFor(freshRepository, { send }, disabledTestTracing, {
      beginAttempt,
    }).runOnce(new AbortController().signal);

    const reserveOrder = vi.mocked(freshRepository.reserveWebhookSubmission)
      .mock.invocationCallOrder[0];
    const gateOrder = beginAttempt.mock.invocationCallOrder[0];
    const sendOrder = send.mock.invocationCallOrder[0];
    expect(reserveOrder).toBeLessThan(gateOrder!);
    expect(gateOrder).toBeLessThan(sendOrder!);

    const replayRepository: WebhookDeliveryRepository = {
      ...repositoryFor([claim]),
      reserveWebhookSubmission: vi.fn(async () => "already_delivered" as const),
    };
    beginAttempt.mockClear();
    send.mockClear();
    await expect(
      workerFor(replayRepository, { send }, disabledTestTracing, {
        beginAttempt,
      }).runOnce(new AbortController().signal),
    ).resolves.toMatchObject({ replayed: 1, delivered: 0 });
    expect(beginAttempt).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("rejects forged repository claims before any egress", async () => {
    const authentic = webhookClaim();
    const repository = repositoryFor([{ ...authentic }]);
    const send = vi.fn();
    const worker = workerFor(repository, { send });

    await expect(worker.runOnce(new AbortController().signal)).rejects.toThrow(
      NotificationValidationError,
    );
    expect(send).not.toHaveBeenCalled();
  });

  it("rejects cross-tenant signing material while decoding a claim", () => {
    const input = webhookClaimInput();

    expect(() =>
      createWebhookDeliveryClaim({
        ...input,
        signingKey: protectedSecret("webhook_signing_key", id(3), 1),
      }),
    ).toThrow(NotificationValidationError);
  });

  it("rejects a payload bound to a different outbox event", () => {
    const input = webhookClaimInput();

    expect(() =>
      createWebhookDeliveryClaim({
        ...input,
        payload: {
          ...input.payload,
          event: { ...input.payload.event, id: id(119) },
        },
      }),
    ).toThrow("notification data crossed a tenant boundary");
  });

  it("continues the persisted producer trace in a bounded consumer span", async () => {
    const traceContext = {
      traceParent: "00-11111111111111111111111111111111-2222222222222222-01",
      traceState: "vendor=value",
    } as const;
    const claim = createWebhookDeliveryClaim({
      ...webhookClaimInput(),
      traceContext,
    });
    const runConsumerSpan = vi.fn(
      async (_operation, _producer, work, _outcome) => work(),
    );
    const tracing: NotificationTracing = {
      ...disabledTestTracing,
      runConsumerSpan,
    };
    const worker = workerFor(
      repositoryFor([claim]),
      {
        async send() {
          return {
            provider: "webhook",
            statusCode: 204,
            receiptDigest: "a".repeat(64),
          };
        },
      },
      tracing,
    );

    await expect(
      worker.runOnce(new AbortController().signal),
    ).resolves.toMatchObject({
      delivered: 1,
    });
    expect(runConsumerSpan).toHaveBeenCalledWith(
      "webhook_delivery",
      traceContext,
      expect.any(Function),
      expect.any(Function),
    );
  });

  it("uses a root consumer span when trace context is absent and rejects hostile context", async () => {
    const claim = webhookClaim();
    const runConsumerSpan = vi.fn(
      async (_operation, _producer, work, _outcome) => work(),
    );
    const tracing: NotificationTracing = {
      ...disabledTestTracing,
      runConsumerSpan,
    };
    const worker = workerFor(
      repositoryFor([claim]),
      {
        async send() {
          return {
            provider: "webhook",
            statusCode: 204,
            receiptDigest: "a".repeat(64),
          };
        },
      },
      tracing,
    );

    await worker.runOnce(new AbortController().signal);
    expect(runConsumerSpan).toHaveBeenCalledWith(
      "webhook_delivery",
      undefined,
      expect.any(Function),
      expect.any(Function),
    );
    expect(() =>
      createWebhookDeliveryClaim({
        ...webhookClaimInput(),
        traceContext: {
          traceParent:
            "00-11111111111111111111111111111111-2222222222222222-01",
          traceState: "vendor=unicode-💥",
        },
      }),
    ).toThrow(NotificationValidationError);
  });
});

const now = new Date("2026-08-25T10:02:00.000Z");

function webhookClaim(): WebhookDeliveryClaim {
  return createWebhookDeliveryClaim(webhookClaimInput());
}

function webhookClaimInput(): WebhookDeliveryClaimInput {
  const policy = createWebhookUrlPolicyVersion({
    id: id(115),
    versionId: id(116),
    tenantId: id(2),
    version: 3,
    rules: [
      {
        effect: "allow",
        match: "exact",
        hostname: "hooks.example.test",
        port: 443,
      },
    ],
    publishedByMembershipId: id(117),
    publishedAt: new Date("2026-08-25T09:00:00.000Z"),
  });
  const configurationPin = createWebhookConfigurationPolicyPin(policy, {
    configurationId: id(112),
    configurationVersion: 4,
    tenantId: id(2),
    endpointUrl: "https://hooks.example.test/periapsis",
  });
  return {
    id: id(110),
    tenantId: id(2),
    eventId: id(111),
    configurationId: id(112),
    configurationVersion: 4,
    endpointUrl: "https://hooks.example.test/periapsis",
    signingKey: protectedSecret("webhook_signing_key", id(2), 1),
    timeoutMs: 2_000,
    createdAt: new Date("2026-08-25T10:00:00.000Z"),
    attemptAt: new Date("2026-08-25T10:01:00.000Z"),
    payload: {
      schemaVersion: 1,
      event: {
        id: id(111),
        type: "alert.created",
        objectType: "alert",
        objectId: id(113),
        objectVersion: 2,
        occurredAt: new Date("2026-08-25T09:59:00.000Z"),
      },
      context: { alert: { severity: "high" } },
    },
    retry: {
      maximumAttempts: 5,
      initialDelayMs: 1_000,
      maximumDelayMs: 60_000,
      multiplier: 2,
      jitterPercent: 20,
    },
    attempt: 1,
    fenceToken: id(114),
    leaseUntil: new Date("2026-08-25T10:10:00.000Z"),
    egressPin: createWebhookDeliveryPolicyPin(configurationPin, {
      deliveryId: id(110),
      configurationId: id(112),
      configurationVersion: 4,
      tenantId: id(2),
      endpointUrl: "https://hooks.example.test/periapsis",
    }),
  };
}

function repositoryFor(
  claims: readonly WebhookDeliveryClaim[],
): WebhookDeliveryRepository {
  return {
    claimWebhookBatch: vi.fn(async () => claims),
    heartbeatWebhook: vi.fn(async () => true),
    reserveWebhookSubmission: vi.fn(async () => "reserved" as const),
    completeWebhook: vi.fn(async () => undefined),
    completeWebhookReplay: vi.fn(async () => undefined),
    retryWebhook: vi.fn(async () => undefined),
    deadLetterWebhook: vi.fn(async () => undefined),
  };
}

function workerFor(
  repository: WebhookDeliveryRepository,
  transport: WebhookTransport,
  tracing: NotificationTracing = disabledTestTracing,
  urlPolicyGate: WebhookUrlPolicyAttemptGate = defaultPolicyGate(),
): NotificationWebhookDeliveryWorker {
  const telemetry: DeliveryTelemetry = { record: vi.fn() };
  const logger: DeliveryLogger = { info: vi.fn(), error: vi.fn() };
  return new NotificationWebhookDeliveryWorker({
    repository,
    transport,
    urlPolicyGate,
    secrets: {
      async read() {
        return new TextEncoder().encode("0123456789abcdef0123456789abcdef");
      },
    },
    telemetry,
    logger,
    tracing,
    options: {
      workerId: "webhook-test",
      batchSize: 10,
      maximumConcurrency: 2,
      leaseDurationMs: 5_000,
      heartbeatIntervalMs: 1_000,
      deliveryTimeoutMs: 4_000,
    },
    now: () => new Date(now),
  });
}

function defaultPolicyGate(): WebhookUrlPolicyAttemptGate {
  return {
    async beginAttempt(pin) {
      if (!("policyId" in pin)) {
        throw new NotificationValidationError("unexpected local pin");
      }
      return Object.freeze({
        attemptEvidence: Object.freeze({
          allowed: true,
          reason: "allowed_by_rule" as const,
          policyId: pin.policyId,
          policyVersion: pin.policyVersion,
          policyDigest: pin.policyDigest,
          endpointDigest: pin.endpointDigest,
        }),
      });
    },
  };
}
