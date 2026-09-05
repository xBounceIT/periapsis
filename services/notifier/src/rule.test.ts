import { describe, expect, it } from "vitest";

import { createNotificationEvent } from "./event.js";
import { NotificationValidationError } from "./errors.js";
import {
  createNotificationRule,
  isAuthenticNotificationRule,
  ruleMatches,
  type NotificationRuleInput,
} from "./rule.js";
import { baseRule, id } from "./test/fixtures.js";

describe("notification rules", () => {
  it("matches bounded declarative conditions and pins its effective window", () => {
    const input = baseRule();
    const rule = createNotificationRule(input);
    input.effectiveFrom.setUTCFullYear(2030);
    const exposed = rule.effectiveFrom;
    exposed.setUTCFullYear(2031);
    const event = createNotificationEvent({
      id: id(10),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(11),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "api",
      context: {
        alert: { severity: "critical", tags: ["malware", "ransomware"] },
        customer: { alert: { severity: "critical" } },
      },
      maximumAudience: "customer",
    });
    expect(rule.effectiveFrom.toISOString()).toBe("2026-08-25T00:00:00.000Z");
    expect(ruleMatches(rule, event, event.occurredAt)).toBe(true);
    expect(isAuthenticNotificationRule(rule)).toBe(true);
  });

  it.each([
    ["alert.watcher_added", "alert"],
    ["alert.watcher_removed", "alert"],
    ["case.watcher_added", "case"],
    ["case.watcher_removed", "case"],
  ] as const)("binds %s rules to %s", (eventType, objectType) => {
    const input = baseRule();
    input.eventType = eventType;
    input.objectType = objectType;
    expect(createNotificationRule(input).eventType).toBe(eventType);

    input.objectType = objectType === "alert" ? "case" : "alert";
    expect(() => createNotificationRule(input)).toThrow(
      NotificationValidationError,
    );
  });

  it("rejects cycles, ambiguous recipient authority, and duplicate values", () => {
    const cyclicChildren: NotificationRuleInput["condition"][] = [];
    const cyclic: NotificationRuleInput["condition"] = {
      kind: "all",
      children: cyclicChildren,
    };
    cyclicChildren.push(cyclic);
    const mutations: Array<(input: NotificationRuleInput) => void> = [
      (input) => {
        input.condition = cyclic;
      },
      (input) => {
        input.recipients = [
          {
            kind: "explicit_email",
            value: "external@example.com",
            audience: "customer",
          },
        ];
      },
      (input) => {
        input.condition = {
          kind: "predicate",
          path: "alert.severity",
          operator: "one_of",
          values: ["critical", "critical"],
        };
      },
      (input) => {
        input.objectType = "case";
      },
      (input) => {
        input.quietHours = {
          timezone: "CET",
          startMinute: 1_320,
          endMinute: 420,
        };
      },
      (input) => {
        input.condition = {
          kind: "predicate",
          path: "alert.__proto__.polluted",
          operator: "exists",
        };
      },
    ];
    for (const mutate of mutations) {
      const input = baseRule();
      mutate(input);
      expect(() => createNotificationRule(input)).toThrow(
        NotificationValidationError,
      );
    }
  });

  it("binds mentioned and other relationship selectors to their real audience", () => {
    const mentioned = baseRule();
    mentioned.recipients = [{ kind: "mentioned" }];
    expect(createNotificationRule(mentioned).recipients).toEqual([
      { kind: "mentioned", audience: "operator" },
    ]);

    const operatorTeam = baseRule();
    operatorTeam.recipients = [
      { kind: "operator_team", value: id(81), audience: "operator" },
    ];
    expect(createNotificationRule(operatorTeam).recipients[0]).toEqual({
      kind: "operator_team",
      value: id(81),
      audience: "operator",
    });

    for (const recipients of [
      [{ kind: "mentioned", audience: "customer" }],
      [{ kind: "customer_contacts", audience: "operator" }],
      [{ kind: "actor" }],
      [{ kind: "operator_team", audience: "operator" }],
    ] as const) {
      const invalid = baseRule();
      invalid.recipients = recipients;
      expect(() => createNotificationRule(invalid)).toThrow(
        NotificationValidationError,
      );
    }
  });

  it("does not let negative predicates match a missing fact", () => {
    const event = createNotificationEvent({
      id: id(12),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(13),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "api",
      context: { alert: {}, customer: { alert: {} } },
      maximumAudience: "customer",
    });
    for (const operator of ["not_equals", "none_of"] as const) {
      const input = baseRule();
      input.condition = {
        kind: "predicate",
        path: "alert.severity",
        operator,
        values: ["low"],
      };
      expect(
        ruleMatches(createNotificationRule(input), event, event.occurredAt),
      ).toBe(false);
    }
  });

  it("fails closed for forged rules, forged events, and malformed runtime input", () => {
    const rule = createNotificationRule(baseRule());
    const event = createNotificationEvent({
      id: id(14),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(15),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "api",
      context: {
        alert: { severity: "critical" },
        customer: { alert: { severity: "critical" } },
      },
      maximumAudience: "customer",
    });

    expect(ruleMatches({ ...rule }, event, event.occurredAt)).toBe(false);
    expect(ruleMatches(rule, { ...event }, event.occurredAt)).toBe(false);

    const input = baseRule();
    Reflect.set(input, "condition", null);
    expect(() => createNotificationRule(input)).toThrow(
      NotificationValidationError,
    );
  });
});
