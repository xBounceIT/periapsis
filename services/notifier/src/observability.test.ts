import { describe, expect, it } from "vitest";

import { NotificationValidationError } from "./errors.js";
import {
  NotifierMetrics,
  StructuredNotifierLogger,
  type LogSink,
} from "./observability.js";
import { id } from "./test/fixtures.js";

describe("notifier observability", () => {
  it("always exports the oldest pending outbox gauge", () => {
    expect(new NotifierMetrics().renderPrometheus()).toContain(
      "periapsis_outbox_oldest_pending_seconds 0",
    );
  });

  it("exports bounded low-cardinality delivery and queue metrics", () => {
    const metrics = new NotifierMetrics();
    metrics.setReadiness(true, 7, 42);
    metrics.record("delivered", { tenantId: id(2) });
    metrics.record("uncertain", {
      tenantId: id(3),
      failureClass: "submission_uncertain",
    });
    metrics.recordIteration("success", {
      claimed: 2,
      delivered: 1,
      replayed: 0,
      retried: 0,
      deadLettered: 0,
      uncertain: 1,
    });
    metrics.recordFanout({
      claimed: 2,
      committed: 1,
      replayed: 0,
      retried: 1,
      deadLettered: 0,
      fenced: 0,
      deliveriesPlanned: 3,
    });

    const output = metrics.renderPrometheus();
    expect(output).toContain("periapsis_notifier_ready 1");
    expect(output).toContain("periapsis_notification_queue_depth 7");
    expect(output).toContain("periapsis_outbox_oldest_pending_seconds 42");
    expect(output).toContain('outcome="delivered",failure_class="none"} 1');
    expect(output).toContain("periapsis_notification_fanout_claims_total 2");
    expect(output).not.toContain(id(2));
  });

  it("writes structured allowlisted logs and rejects sensitive fields", () => {
    const lines: string[] = [];
    const sink: LogSink = { write: (value) => lines.push(value) };
    const logger = new StructuredNotifierLogger({
      output: sink,
      errors: sink,
      release: "test",
    });
    logger.info("notification_delivery_finished", {
      tenantId: id(2),
      deliveryId: id(3),
      attempt: 1,
      outcome: "delivered",
    });
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      level: "info",
      service: "notifier",
      outcome: "delivered",
    });
    expect(() =>
      logger.error("unsafe", { recipient: "secret@example.com" }),
    ).toThrow(NotificationValidationError);
    expect(() =>
      logger.info("forged_trace", { traceId: "a".repeat(32) }),
    ).toThrow(NotificationValidationError);
  });
});
