import type { NotificationRuleInput } from "../rule.js";
import {
  createNotificationProtectedSecret,
  type NotificationProtectedSecret,
  type NotificationSecretKind,
} from "../keyring.js";

export function id(value: number): string {
  return `019d0000-0000-7000-8000-${value.toString().padStart(12, "0")}`;
}

export function protectedSecret(
  kind: NotificationSecretKind,
  tenantId?: string,
  secretVersion = 1,
): NotificationProtectedSecret {
  return createNotificationProtectedSecret({
    ...(tenantId === undefined ? {} : { tenantId }),
    secretId: id(700 + secretVersion),
    secretVersion,
    kind,
    keyVersion: 1,
    nonce: new Uint8Array(12),
    ciphertext: new Uint8Array(17),
  });
}

export function baseRule(): NotificationRuleInput {
  return {
    id: id(20),
    tenantId: id(2),
    name: "Critical alert",
    description: "Notify the assigned analyst",
    eventType: "alert.created",
    objectType: "alert",
    condition: {
      kind: "all",
      children: [
        {
          kind: "predicate",
          path: "alert.severity",
          operator: "equals",
          values: ["critical"],
        },
        {
          kind: "predicate",
          path: "alert.tags",
          operator: "contains",
          values: ["ransomware"],
        },
      ],
    },
    recipients: [
      { kind: "assignee" },
      {
        kind: "explicit_email",
        value: "SOC-Escalation@Example.com",
        authorized: true,
        audience: "operator",
      },
    ],
    templateId: id(21),
    templateVersion: 3,
    channel: "email",
    priority: 80,
    delayMs: 0,
    deduplicationWindowMs: 60_000,
    grouping: { mode: "object", windowMs: 300_000, maximumItems: 25 },
    retry: {
      maximumAttempts: 5,
      initialDelayMs: 1_000,
      maximumDelayMs: 60_000,
      multiplier: 2,
      jitterPercent: 20,
    },
    enabled: true,
    version: 4,
    effectiveFrom: new Date("2026-08-25T00:00:00.000Z"),
  };
}
