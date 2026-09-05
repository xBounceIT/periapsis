import { describe, expect, it } from "vitest";

import { NotificationValidationError } from "./errors.js";
import {
  createNotificationEvent,
  isAuthenticNotificationEvent,
  isContextObject,
  isNotificationEventType,
  isOperatorOnlyNotificationEventType,
  projectEventContext,
  type ContextValue,
} from "./event.js";
import { id } from "./test/fixtures.js";

describe("notification event", () => {
  it("owns and freezes canonical context without leaking mutable instants", () => {
    const occurredAt = new Date("2026-08-25T10:00:00.000Z");
    const alert = { severity: "critical", tags: ["malware"] };
    const source = {
      alert,
      customer: { alert: { severity: "critical" } },
    } satisfies Record<string, ContextValue>;
    const event = createNotificationEvent({
      id: id(1),
      tenantId: id(2),
      type: "alert.created",
      objectType: "alert",
      objectId: id(3),
      objectVersion: 1,
      occurredAt,
      actorKind: "human",
      actorId: id(4),
      source: "api",
      context: source,
      maximumAudience: "customer",
    });

    occurredAt.setUTCFullYear(2030);
    alert.severity = "low";
    const leaked = event.occurredAt;
    leaked.setUTCFullYear(2031);

    expect(event.occurredAt.toISOString()).toBe("2026-08-25T10:00:00.000Z");
    const projectedAlert = event.context.alert;
    expect(isContextObject(projectedAlert)).toBe(true);
    if (!isContextObject(projectedAlert))
      throw new Error("expected alert context");
    expect(projectedAlert.severity).toBe("critical");
    expect(Object.isFrozen(event.context)).toBe(true);
    expect(isAuthenticNotificationEvent(event)).toBe(true);
  });

  it("fails closed for cycles, unsafe keys, and non-finite numbers", () => {
    const cyclic: Record<string, ContextValue> = {};
    cyclic.self = cyclic;
    for (const context of [
      cyclic,
      { constructor: "pollution" },
      { alert: { score: Number.NaN } },
    ]) {
      expect(() => baseEvent("alert.created", context)).toThrow(
        NotificationValidationError,
      );
    }
  });

  it("rejects accessors without executing them", () => {
    let executed = false;
    const alert = {};
    Object.defineProperty(alert, "title", {
      enumerable: true,
      get() {
        executed = true;
        return "secret";
      },
    });
    expect(() =>
      baseEvent("alert.created", {
        alert,
        customer: { alert: {} },
      }),
    ).toThrow(NotificationValidationError);
    expect(executed).toBe(false);
  });

  it("never projects a private comment to a customer", () => {
    const event = baseEvent("comment.private_added", {
      comment: { body: "operator-only" },
    });
    expect(event.maximumAudience).toBe("operator");
    expect(() => projectEventContext(event, "customer")).toThrow(
      NotificationValidationError,
    );
  });

  it("honors an explicit operator-only projection for otherwise public event types", () => {
    const event = createNotificationEvent({
      id: id(10),
      tenantId: id(2),
      type: "case.status_changed",
      objectType: "case",
      objectId: id(11),
      objectVersion: 7,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "worker",
      context: { case: { status: "investigating" } },
      maximumAudience: "operator",
    });
    expect(event.objectVersion).toBe(7);
    expect(event.actorKind).toBe("system");
    expect(() => projectEventContext(event, "customer")).toThrow(
      NotificationValidationError,
    );
  });

  it.each([
    ["alert.watcher_added", "alert"],
    ["alert.watcher_removed", "alert"],
    ["case.watcher_added", "case"],
    ["case.watcher_removed", "case"],
  ] as const)(
    "accepts the %s database event for its ticket kind",
    (type, objectType) => {
      const event = createNotificationEvent({
        id: id(30),
        tenantId: id(2),
        type,
        objectType,
        objectId: id(31),
        objectVersion: 2,
        occurredAt: new Date("2026-09-01T08:00:00.000Z"),
        actorKind: "human",
        actorId: id(4),
        source: "ticketing",
        context: { [objectType]: { id: id(31), version: 2 } },
        maximumAudience: "operator",
      });

      expect(event.type).toBe(type);
      expect(event.objectType).toBe(objectType);
      expect(isNotificationEventType(type)).toBe(true);
      expect(isOperatorOnlyNotificationEventType(type)).toBe(true);
      expect(() => projectEventContext(event, "customer")).toThrow(
        NotificationValidationError,
      );
      expect(() =>
        createNotificationEvent({
          ...event,
          context: {
            [objectType]: { id: id(31), version: 2 },
            customer: { [objectType]: { id: id(31), version: 2 } },
          },
          maximumAudience: "customer",
        }),
      ).toThrow(NotificationValidationError);
    },
  );

  it("rejects unknown event types through the shared decoder predicate", () => {
    expect(isNotificationEventType("alert.watcher_renamed")).toBe(false);
    expect(isNotificationEventType(null)).toBe(false);
  });

  it("rejects inconsistent actor and audience envelopes", () => {
    const valid = {
      id: id(20),
      tenantId: id(2),
      type: "alert.created" as const,
      objectType: "alert" as const,
      objectId: id(21),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system" as const,
      source: "api",
      context: {
        alert: { severity: "critical" },
        customer: { alert: { severity: "critical" } },
      },
      maximumAudience: "customer" as const,
    };
    expect(() =>
      createNotificationEvent({ ...valid, actorId: id(22) }),
    ).toThrow(NotificationValidationError);
    expect(() =>
      createNotificationEvent({
        ...valid,
        actorKind: "human",
      }),
    ).toThrow(NotificationValidationError);
    expect(() =>
      createNotificationEvent({
        ...valid,
        maximumAudience: "operator",
      }),
    ).toThrow(NotificationValidationError);
  });

  it("rejects forged events at projection boundaries", () => {
    const authentic = baseEvent("alert.created", {
      alert: { severity: "critical" },
      customer: { alert: { severity: "critical" } },
    });
    const forged = { ...authentic };

    expect(isAuthenticNotificationEvent(forged)).toBe(false);
    expect(() => projectEventContext(forged, "operator")).toThrow(
      NotificationValidationError,
    );
  });
});

function baseEvent(
  type: "alert.created" | "comment.private_added",
  context: Record<string, ContextValue>,
) {
  return createNotificationEvent({
    id: id(1),
    tenantId: id(2),
    type,
    objectType: type === "alert.created" ? "alert" : "case",
    objectId: id(3),
    objectVersion: 1,
    occurredAt: new Date("2026-08-25T10:00:00.000Z"),
    actorKind: "human",
    actorId: id(4),
    source: "api",
    context,
    maximumAudience: type === "comment.private_added" ? "operator" : "customer",
  });
}
