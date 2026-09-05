import { describe, expect, it, vi } from "vitest";

import {
  createFanoutClaim,
  isAuthenticPlannedEmailDelivery,
  NotificationFanoutWorker,
  type FanoutClaim,
  type NotificationFanoutInputs,
  type NotificationFanoutRepository,
  type PlannedEmailDelivery,
} from "./fanout.js";
import type { NotificationRuleInput } from "./rule.js";
import type { NotificationTemplateInput } from "./template.js";
import { baseRule, id } from "./test/fixtures.js";
import { disabledTestTracing } from "./test/telemetry.js";

const now = new Date("2026-08-25T10:00:01.000Z");

describe("notification outbox fanout", () => {
  it("commits deterministic email jobs with exact rule, template, and SMTP pins", async () => {
    const claim = publicClaim();
    const commitFanout = vi.fn<NotificationFanoutRepository["commitFanout"]>(
      async (
        receivedClaim: FanoutClaim,
        deliveries: readonly PlannedEmailDelivery[],
      ) => {
        expect(receivedClaim).toBe(claim);
        expect(deliveries).toHaveLength(2);
        expect(deliveries.every(isAuthenticPlannedEmailDelivery)).toBe(true);
        expect(
          new Set(deliveries.map((delivery) => delivery.deliveryKey)).size,
        ).toBe(2);
        expect(deliveries[0]).toMatchObject({
          tenantId: id(2),
          eventId: id(41),
          ruleId: id(20),
          ruleVersion: 4,
          smtpConfigurationScope: "tenant",
          smtpConfigurationId: id(60),
          smtpConfigurationVersion: 7,
          deduplicationKey: expect.stringMatching(/^[0-9a-f]{64}$/u),
          groupingKey: expect.stringMatching(/^[0-9a-f]{64}$/u),
          groupingMaximumItems: 25,
          groupingWindowMs: 300_000,
        });
        const customer = deliveries.find(
          (delivery) => delivery.audience === "customer",
        );
        expect(customer?.recipient).toBe("customer@example.com");
        expect(customer?.principalId).toBe(id(62));
        expect(customer?.context).toEqual({
          alert: { severity: "critical" },
        });
        const operator = deliveries.find(
          (delivery) => delivery.audience === "operator",
        );
        expect(operator?.recipient).toBe("soc-escalation@example.com");
        expect(operator?.context).toMatchObject({
          comment: { body: "operator-only detail" },
        });
        return committedResult(2);
      },
    );
    const repository = repositoryFor({
      claim,
      inputs: publicInputs(),
      commitFanout,
    });

    await expect(
      workerFor(repository).runOnce(new AbortController().signal),
    ).resolves.toEqual({
      claimed: 1,
      committed: 1,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      fenced: 0,
      deliveriesPlanned: 2,
    });
    expect(commitFanout).toHaveBeenCalledOnce();
  });

  it("drops customer recipients and context for private comment events", async () => {
    const claim = privateClaim();
    const inputs = privateInputs();
    const commitFanout = vi.fn<NotificationFanoutRepository["commitFanout"]>(
      async (
        _claim: FanoutClaim,
        deliveries: readonly PlannedEmailDelivery[],
      ) => {
        expect(deliveries).toHaveLength(1);
        expect(deliveries[0]?.audience).toBe("operator");
        expect(deliveries[0]?.recipient).toBe("operator@example.com");
        expect(deliveries[0]?.context).toMatchObject({
          comment: { body: "private investigation note" },
        });
        return committedResult(1);
      },
    );
    const repository = repositoryFor({ claim, inputs, commitFanout });

    const result = await workerFor(repository).runOnce(
      new AbortController().signal,
    );
    expect(result.deliveriesPlanned).toBe(1);
  });

  it("dead-letters missing pinned configuration without committing partial work", async () => {
    const claim = publicClaim();
    const inputs = { ...publicInputs(), smtpConfiguration: null };
    const commitFanout = vi.fn<NotificationFanoutRepository["commitFanout"]>(
      async () => committedResult(0),
    );
    const deadLetterFanout = vi.fn<
      NotificationFanoutRepository["deadLetterFanout"]
    >(async () => undefined);
    const repository = repositoryFor({
      claim,
      inputs,
      commitFanout,
      deadLetterFanout,
    });

    const result = await workerFor(repository).runOnce(
      new AbortController().signal,
    );
    expect(result.deadLettered).toBe(1);
    expect(commitFanout).not.toHaveBeenCalled();
    expect(deadLetterFanout).toHaveBeenCalledWith(
      claim,
      "configuration",
      now,
      expect.any(AbortSignal),
    );
  });

  it("retries transient repository failures with a stable bounded instant", async () => {
    const claim = publicClaim();
    const retryFanout = vi.fn<NotificationFanoutRepository["retryFanout"]>(
      async () => undefined,
    );
    const repository = repositoryFor({
      claim,
      inputs: publicInputs(),
      retryFanout,
      async loadFanoutInputs() {
        throw new Error("temporary database failure");
      },
    });
    const worker = workerFor(repository);

    const first = await worker.runOnce(new AbortController().signal);
    const retryAt = retryFanout.mock.calls[0]?.[1];
    expect(first.retried).toBe(1);
    expect(retryAt).toBeInstanceOf(Date);
    expect(retryAt!.getTime()).toBeGreaterThanOrEqual(now.getTime() + 1_000);

    retryFanout.mockClear();
    await worker.runOnce(new AbortController().signal);
    expect(retryFanout.mock.calls[0]?.[1]).toEqual(retryAt);
  });

  it("reports an exact atomic replay without counting duplicate deliveries", async () => {
    const claim = publicClaim();
    const commitFanout = vi.fn<NotificationFanoutRepository["commitFanout"]>(
      async () => replayedResult(),
    );
    const repository = repositoryFor({
      claim,
      inputs: publicInputs(),
      commitFanout,
    });

    const result = await workerFor(repository).runOnce(
      new AbortController().signal,
    );
    expect(result).toMatchObject({ replayed: 1, deliveriesPlanned: 0 });
    expect(commitFanout.mock.calls[0]?.[1]).toHaveLength(2);
  });

  it("rejects forged or duplicate repository claims before processing", async () => {
    const claim = publicClaim();
    const repository = repositoryFor({ claim, inputs: publicInputs() });
    repository.claimFanoutBatch = vi.fn(async () => [claim, claim]);
    await expect(
      workerFor(repository).runOnce(new AbortController().signal),
    ).rejects.toThrow("forged, duplicate, or expired");

    repository.claimFanoutBatch = vi.fn(async () => [{ ...claim }]);
    await expect(
      workerFor(repository).runOnce(new AbortController().signal),
    ).rejects.toThrow("forged, duplicate, or expired");
  });

  it("cancels an in-flight heartbeat when fanout completes", async () => {
    const claim = publicClaim();
    let markHeartbeatStarted!: () => void;
    const heartbeatStarted = new Promise<void>((resolve) => {
      markHeartbeatStarted = resolve;
    });
    const repository = repositoryFor({
      claim,
      inputs: publicInputs(),
      async loadFanoutInputs() {
        await heartbeatStarted;
        return publicInputs();
      },
    });
    repository.heartbeatFanout = vi.fn(
      async (_claim, _leaseUntil, signal) =>
        new Promise<boolean>((_resolve, reject) => {
          markHeartbeatStarted();
          if (signal.aborted) {
            reject(signal.reason);
            return;
          }
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        }),
    );
    const startedAt = performance.now();
    const result = await workerFor(repository, {
      leaseDurationMs: 5_000,
      heartbeatIntervalMs: 1_000,
      processingTimeoutMs: 4_000,
    }).runOnce(new AbortController().signal);
    expect(result.committed).toBe(1);
    expect(performance.now() - startedAt).toBeLessThan(2_500);
  });
});

function workerFor(
  repository: NotificationFanoutRepository,
  overrides: Partial<
    ConstructorParameters<typeof NotificationFanoutWorker>[0]["options"]
  > = {},
): NotificationFanoutWorker {
  return new NotificationFanoutWorker({
    repository,
    logger: { info() {}, error() {} },
    tracing: disabledTestTracing,
    now: () => new Date(now),
    options: {
      workerId: "notifier-test",
      batchSize: 10,
      maximumConcurrency: 2,
      leaseDurationMs: 60_000,
      heartbeatIntervalMs: 15_000,
      processingTimeoutMs: 30_000,
      initialRetryDelayMs: 1_000,
      maximumRetryDelayMs: 60_000,
      ...overrides,
    },
  });
}

function repositoryFor(options: {
  claim: FanoutClaim;
  inputs: NotificationFanoutInputs;
  commitFanout?: NotificationFanoutRepository["commitFanout"];
  retryFanout?: NotificationFanoutRepository["retryFanout"];
  deadLetterFanout?: NotificationFanoutRepository["deadLetterFanout"];
  loadFanoutInputs?: NotificationFanoutRepository["loadFanoutInputs"];
}): NotificationFanoutRepository {
  return {
    async claimFanoutBatch() {
      return [options.claim];
    },
    async heartbeatFanout() {
      return true;
    },
    loadFanoutInputs: options.loadFanoutInputs ?? (async () => options.inputs),
    commitFanout: options.commitFanout ?? (async () => committedResult(2)),
    retryFanout: options.retryFanout ?? (async () => undefined),
    deadLetterFanout: options.deadLetterFanout ?? (async () => undefined),
  };
}

function committedResult(emailCount: number, webhookCount = 0) {
  return Object.freeze({
    outcome: "committed" as const,
    emailCount,
    webhookCount,
    cancelledWebhookCount: 0,
    totalCount: emailCount + webhookCount,
  });
}

function replayedResult() {
  return Object.freeze({
    outcome: "already_committed" as const,
    emailCount: 0,
    webhookCount: 0,
    cancelledWebhookCount: 0,
    totalCount: 0,
  });
}

function publicClaim(): FanoutClaim {
  return createFanoutClaim({
    id: id(41),
    tenantId: id(2),
    event: {
      id: id(41),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(42),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "human",
      actorId: id(5),
      source: "api",
      traceContext: {
        traceParent: "00-11111111111111111111111111111111-2222222222222222-01",
      },
      context: {
        alert: { severity: "critical", tags: ["ransomware"] },
        comment: { body: "operator-only detail" },
        customer: { alert: { severity: "critical" } },
      },
      maximumAudience: "customer",
    },
    attempt: 1,
    maximumAttempts: 5,
    fenceToken: id(70),
    leaseUntil: new Date("2026-08-25T10:01:01.000Z"),
  });
}

function privateClaim(): FanoutClaim {
  return createFanoutClaim({
    id: id(43),
    tenantId: id(2),
    event: {
      id: id(43),
      tenantId: id(2),
      type: "comment.private_added",
      objectType: "case",
      objectId: id(44),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "human",
      actorId: id(5),
      source: "web",
      context: {
        case: { number: "CASE-1" },
        comment: { body: "private investigation note" },
      },
      maximumAudience: "operator",
    },
    attempt: 1,
    maximumAttempts: 5,
    fenceToken: id(71),
    leaseUntil: new Date("2026-08-25T10:01:01.000Z"),
  });
}

function publicInputs(): NotificationFanoutInputs {
  const rule = baseRule();
  rule.recipients = [
    ...rule.recipients,
    { kind: "customer_contacts", audience: "customer" },
  ];
  return {
    rules: [rule],
    candidates: [
      {
        tenantId: id(2),
        email: "customer@example.com",
        audience: "customer",
        kinds: ["customer_contacts"],
        principalId: id(62),
        enabled: true,
        emailAllowed: true,
      },
    ],
    templates: [alertTemplate()],
    smtpConfiguration: { scope: "tenant", id: id(60), version: 7 },
  };
}

function privateInputs(): NotificationFanoutInputs {
  const rule: NotificationRuleInput = {
    ...baseRule(),
    eventType: "comment.private_added",
    objectType: "case",
    condition: { kind: "all", children: [] },
    recipients: [
      { kind: "customer_contacts" },
      {
        kind: "explicit_email",
        value: "operator@example.com",
        authorized: true,
        audience: "operator",
      },
    ],
  };
  return {
    rules: [rule],
    candidates: [
      {
        tenantId: id(2),
        email: "customer@example.com",
        audience: "customer",
        kinds: ["customer_contacts"],
        enabled: true,
        emailAllowed: true,
      },
    ],
    templates: [caseTemplate()],
    smtpConfiguration: { scope: "tenant", id: id(60), version: 7 },
  };
}

function alertTemplate(): NotificationTemplateInput {
  return {
    id: id(21),
    tenantId: id(2),
    key: "critical_alert",
    name: "Critical alert",
    language: "en-US",
    version: 3,
    subject: "Critical alert",
    html: "<p>Severity: {{alert.severity}}</p>",
  };
}

function caseTemplate(): NotificationTemplateInput {
  return {
    id: id(21),
    tenantId: id(2),
    key: "private_case_comment",
    name: "Private case comment",
    language: "en-US",
    version: 3,
    subject: "Private case comment",
    html: "<p>{{case.number}}: {{comment.body}}</p>",
  };
}
