import { describe, expect, it, vi } from "vitest";

import type { DeliveryRepository, DeliveryRunResult } from "./delivery.js";
import { NotifierMetrics } from "./observability.js";
import {
  CompositeNotificationBatchRunner,
  NotificationRuntime,
  type DeliveryBatchRunner,
  type NotifierRepository,
} from "./runtime.js";
import { disabledTestTracing } from "./test/telemetry.js";

describe("notification runtime", () => {
  it("polls one bounded batch at a time and stops promptly", async () => {
    const stop = new AbortController();
    const result: DeliveryRunResult = {
      claimed: 0,
      delivered: 0,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      uncertain: 0,
    };
    const runOnce = vi.fn(async () => {
      stop.abort();
      return result;
    });
    const runtime = createRuntime({ runOnce });

    await expect(runtime.run(stop.signal)).resolves.toBeUndefined();
    expect(runOnce).toHaveBeenCalledOnce();
  });

  it("fails readiness closed on a bounded repository failure", async () => {
    const repository = fakeRepository();
    repository.readiness = vi.fn(async () => {
      throw new Error("database details must not escape");
    });
    const runtime = createRuntime({ runOnce: vi.fn() }, repository);

    await expect(
      runtime.readiness(new AbortController().signal),
    ).resolves.toEqual({ ready: false, queueDepth: 0 });
  });

  it("fans out before email and webhook delivery and aggregates both channels", async () => {
    const calls: string[] = [];
    const metrics = new NotifierMetrics();
    const runner = new CompositeNotificationBatchRunner({
      metrics,
      fanout: {
        async runOnce() {
          calls.push("fanout");
          return {
            claimed: 2,
            committed: 1,
            replayed: 0,
            retried: 1,
            deadLettered: 0,
            fenced: 0,
            deliveriesPlanned: 3,
          };
        },
      },
      delivery: {
        async runOnce() {
          calls.push("email");
          return {
            claimed: 3,
            delivered: 3,
            replayed: 0,
            retried: 0,
            deadLettered: 0,
            uncertain: 0,
          };
        },
      },
      webhook: {
        async runOnce() {
          calls.push("webhook");
          return {
            claimed: 2,
            delivered: 1,
            replayed: 0,
            retried: 1,
            deadLettered: 0,
            uncertain: 0,
          };
        },
      },
    });
    await expect(
      runner.runOnce(new AbortController().signal),
    ).resolves.toMatchObject({ claimed: 7, delivered: 4, retried: 1 });
    expect(calls).toEqual(["fanout", "email", "webhook"]);
    expect(metrics.renderPrometheus()).toContain(
      "periapsis_notification_fanout_deliveries_total 3",
    );
  });

  it("still drains both delivery channels when a fanout batch fails", async () => {
    const delivery = vi.fn(async () => ({
      claimed: 1,
      delivered: 1,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      uncertain: 0,
    }));
    const runner = new CompositeNotificationBatchRunner({
      metrics: new NotifierMetrics(),
      fanout: {
        async runOnce() {
          throw new Error("fanout unavailable");
        },
      },
      delivery: { runOnce: delivery },
      webhook: { runOnce: delivery },
    });
    await expect(runner.runOnce(new AbortController().signal)).rejects.toThrow(
      "fanout unavailable",
    );
    expect(delivery).toHaveBeenCalledTimes(2);
  });

  it("does not let one delivery-channel failure starve the other", async () => {
    const webhook = vi.fn(async () => ({
      claimed: 1,
      delivered: 1,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      uncertain: 0,
    }));
    const runner = new CompositeNotificationBatchRunner({
      metrics: new NotifierMetrics(),
      fanout: {
        async runOnce() {
          return {
            claimed: 0,
            committed: 0,
            replayed: 0,
            retried: 0,
            deadLettered: 0,
            fenced: 0,
            deliveriesPlanned: 0,
          };
        },
      },
      delivery: {
        async runOnce() {
          throw new Error("SMTP unavailable");
        },
      },
      webhook: { runOnce: webhook },
    });

    await expect(runner.runOnce(new AbortController().signal)).rejects.toThrow(
      "SMTP unavailable",
    );
    expect(webhook).toHaveBeenCalledOnce();
  });
});

function createRuntime(
  worker: DeliveryBatchRunner,
  repository = fakeRepository(),
): NotificationRuntime {
  return new NotificationRuntime({
    worker,
    repository,
    metrics: new NotifierMetrics(),
    logger: { info() {}, error() {} },
    tracing: disabledTestTracing,
    options: {
      idlePollIntervalMs: 100,
      busyPollIntervalMs: 10,
      failurePollIntervalMs: 100,
      readinessTimeoutMs: 100,
    },
  });
}

function fakeRepository(): NotifierRepository {
  return {
    claimBatch: unsupported,
    heartbeat: unsupported,
    reserveSubmission: unsupported,
    complete: unsupported,
    completeReplay: unsupported,
    retry: unsupported,
    deadLetter: unsupported,
    claimFanoutBatch: unsupported,
    heartbeatFanout: unsupported,
    loadFanoutInputs: unsupported,
    commitFanout: unsupported,
    retryFanout: unsupported,
    deadLetterFanout: unsupported,
    async readiness() {
      return { queueDepth: 0, oldestPendingSeconds: 0 };
    },
    async close() {},
  } satisfies DeliveryRepository & NotifierRepository;
}

async function unsupported(): Promise<never> {
  throw new Error("not used");
}
