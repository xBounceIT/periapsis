import { describe, expect, it } from "vitest";

import { createNotificationEvent } from "./event.js";
import {
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import {
  nextAllowedInstant,
  nextRetryAt,
  planNotification,
} from "./planner.js";
import { createNotificationRule } from "./rule.js";
import { baseRule, id } from "./test/fixtures.js";

describe("notification planning", () => {
  it("deduplicates recipients and keeps customer context customer-safe", () => {
    const rule = createNotificationRule({
      ...baseRule(),
      recipients: [{ kind: "customer_contacts" }, { kind: "assignee" }],
    });
    const event = publicEvent();
    const candidates = [
      {
        tenantId: id(2),
        email: "same@example.com",
        audience: "customer" as const,
        kinds: ["customer_contacts" as const],
        enabled: true,
        emailAllowed: true,
      },
      {
        tenantId: id(2),
        email: "same@example.com",
        audience: "operator" as const,
        kinds: ["assignee" as const],
        principalId: id(30),
        enabled: true,
        emailAllowed: true,
      },
    ];
    const plan = planNotification(rule, event, candidates, event.occurredAt);
    expect(plan?.recipients).toHaveLength(1);
    expect(plan?.recipients[0]?.audience).toBe("operator");
    expect(plan?.recipients[0]?.redactedEmail).toBe("s***@example.com");
    expect(plan?.contexts.operator.comment).toEqual({
      body: "operator detail",
    });
    expect(plan?.contexts.customer.comment).toBeUndefined();

    const reversed = planNotification(
      rule,
      event,
      candidates.toReversed(),
      event.occurredAt,
    );
    expect(reversed?.deduplicationKey).toBe(plan?.deduplicationKey);
  });

  it("fails closed on mixed-tenant candidates and drops customer recipients for private comments", () => {
    const ruleInput = baseRule();
    ruleInput.eventType = "comment.private_added";
    ruleInput.objectType = "case";
    ruleInput.condition = { kind: "all", children: [] };
    ruleInput.recipients = [
      { kind: "customer_contacts" },
      {
        kind: "explicit_email",
        value: "operator@example.com",
        authorized: true,
        audience: "operator",
      },
    ];
    const rule = createNotificationRule(ruleInput);
    const event = createNotificationEvent({
      id: id(31),
      tenantId: id(2),
      type: "comment.private_added",
      objectType: "case",
      objectId: id(32),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "web",
      context: {
        comment: { body: "private" },
      },
      maximumAudience: "operator",
    });
    const customer = {
      tenantId: id(2),
      email: "customer@example.com",
      audience: "customer" as const,
      kinds: ["customer_contacts" as const],
      enabled: true,
      emailAllowed: true,
    };
    const plan = planNotification(rule, event, [customer], event.occurredAt);
    expect(plan?.recipients.map((recipient) => recipient.email)).toEqual([
      "operator@example.com",
    ]);
    expect(plan?.contexts.customer).toEqual({});

    expect(() =>
      planNotification(
        rule,
        event,
        [{ ...customer, tenantId: id(99) }],
        event.occurredAt,
      ),
    ).toThrow(NotificationTenantBoundaryError);

    const foreignRuleInput = ruleInput;
    foreignRuleInput.tenantId = id(99);
    const foreignRule = createNotificationRule(foreignRuleInput);
    expect(() =>
      planNotification(foreignRule, event, [], event.occurredAt),
    ).toThrow(NotificationTenantBoundaryError);
  });

  it("routes a comment mention only to the matching operator candidate", () => {
    const input = baseRule();
    input.eventType = "comment.private_added";
    input.objectType = "case";
    input.condition = { kind: "all", children: [] };
    input.recipients = [{ kind: "mentioned" }];
    const rule = createNotificationRule(input);
    const event = createNotificationEvent({
      id: id(82),
      tenantId: id(2),
      type: "comment.private_added",
      objectType: "case",
      objectId: id(83),
      objectVersion: 7,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "api",
      context: { comment: { revision: 2 } },
      maximumAudience: "operator",
    });
    const candidates = [
      {
        tenantId: id(2),
        email: "mentioned@example.com",
        audience: "operator" as const,
        kinds: ["mentioned" as const],
        principalId: id(84),
        enabled: true,
        emailAllowed: true,
      },
      {
        tenantId: id(2),
        email: "customer@example.com",
        audience: "customer" as const,
        kinds: ["mentioned" as const],
        enabled: true,
        emailAllowed: true,
      },
    ];

    const plan = planNotification(rule, event, candidates, event.occurredAt);
    expect(plan?.recipients).toEqual([
      {
        email: "mentioned@example.com",
        audience: "operator",
        principalId: id(84),
        redactedEmail: "m***@example.com",
      },
    ]);
  });

  it("preserves only an unambiguous server-authorized principal", () => {
    const input = baseRule();
    input.recipients = [
      {
        kind: "explicit_email",
        value: "shared@example.com",
        authorized: true,
        audience: "operator",
      },
      { kind: "assignee", audience: "operator" },
    ];
    const rule = createNotificationRule(input);
    const event = publicEvent();
    const candidate = {
      tenantId: id(2),
      email: "shared@example.com",
      audience: "operator" as const,
      kinds: ["assignee" as const],
      principalId: id(84),
      enabled: true,
      emailAllowed: true,
    };

    expect(
      planNotification(rule, event, [candidate], event.occurredAt)?.recipients,
    ).toEqual([
      {
        email: "shared@example.com",
        audience: "operator",
        principalId: id(84),
        redactedEmail: "s***@example.com",
      },
    ]);

    const ambiguous = planNotification(
      rule,
      event,
      [{ ...candidate, principalId: id(85) }, candidate],
      event.occurredAt,
    );
    expect(ambiguous?.recipients).toEqual([
      {
        email: "shared@example.com",
        audience: "operator",
        redactedEmail: "s***@example.com",
      },
    ]);

    const explicitOnly = createNotificationRule({
      ...input,
      recipients: [input.recipients[0]!],
    });
    expect(
      planNotification(explicitOnly, event, [candidate], event.occurredAt)
        ?.recipients[0]?.principalId,
    ).toBeUndefined();
  });

  it("respects DST-aware overnight quiet hours and deterministic bounded retry", () => {
    const quiet = {
      timezone: "Europe/Rome",
      startMinute: 22 * 60,
      endMinute: 7 * 60,
      weekdays: [0, 1, 2, 3, 4, 5, 6],
    } as const;
    const duringSpringForward = new Date("2026-03-29T00:30:00.000Z");
    expect(nextAllowedInstant(duringSpringForward, quiet).toISOString()).toBe(
      "2026-03-29T05:00:00.000Z",
    );

    const retry = baseRule().retry;
    const first = nextRetryAt(
      retry,
      1,
      new Date("2026-08-25T10:00:00.000Z"),
      id(40),
    );
    const replay = nextRetryAt(
      retry,
      1,
      new Date("2026-08-25T10:00:00.000Z"),
      id(40),
    );
    expect(first?.toISOString()).toBe(replay?.toISOString());
    expect(
      nextRetryAt(retry, retry.maximumAttempts, new Date(), id(40)),
    ).toBeNull();
  });

  it("rejects domain objects forged after validation", () => {
    const rule = createNotificationRule(baseRule());
    const event = publicEvent();
    expect(() =>
      planNotification({ ...rule }, event, [], event.occurredAt),
    ).toThrow(NotificationValidationError);
    expect(() =>
      planNotification(rule, { ...event }, [], event.occurredAt),
    ).toThrow(NotificationValidationError);
  });

  it("groups tenant-wide rules independently of the source object", () => {
    const input = baseRule();
    input.grouping = { mode: "tenant", windowMs: 300_000, maximumItems: 25 };
    const rule = createNotificationRule(input);
    const first = publicEvent();
    const second = createNotificationEvent({
      id: id(43),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(44),
      objectVersion: 2,
      occurredAt: new Date("2026-08-25T10:00:30.000Z"),
      actorKind: "system",
      source: "api",
      context: {
        alert: { severity: "critical", tags: ["ransomware"] },
        customer: { alert: { severity: "critical" } },
      },
      maximumAudience: "customer",
    });
    const candidates = [
      {
        tenantId: id(2),
        email: "analyst@example.com",
        audience: "operator" as const,
        kinds: ["assignee" as const],
        enabled: true,
        emailAllowed: true,
      },
    ];
    const firstPlan = planNotification(
      rule,
      first,
      candidates,
      first.occurredAt,
    );
    const secondPlan = planNotification(
      rule,
      second,
      candidates,
      second.occurredAt,
    );
    expect(firstPlan?.groupingKey).toBe(secondPlan?.groupingKey);
    expect(firstPlan?.deduplicationKey).not.toBe(secondPlan?.deduplicationKey);
  });
});

function publicEvent() {
  return createNotificationEvent({
    id: id(41),
    tenantId: id(2),
    type: "alert.created",
    objectType: "alert",
    objectId: id(42),
    objectVersion: 1,
    occurredAt: new Date("2026-08-25T10:00:00.000Z"),
    actorKind: "system",
    source: "api",
    context: {
      alert: { severity: "critical", tags: ["ransomware"] },
      comment: { body: "operator detail" },
      customer: { alert: { severity: "critical" } },
    },
    maximumAudience: "customer",
  });
}
