import { describe, expect, it } from "vitest";

import {
  formatSlaDuration,
  normalizeCalendarWrite,
  normalizeOverride,
  normalizePolicyWrite,
  SlaInputError,
} from "./model";
import type { SlaOverrideRequest } from "./model";
import {
  calendarFixture,
  policyFixture,
  slaInstanceId,
  slaMetricInstanceId,
} from "./sla-test-fixtures";

describe("SLA UI domain validation", () => {
  it("validates IANA calendars and rejects overlapping local windows", () => {
    expect(normalizeCalendarWrite(calendarFixture)).toMatchObject({
      timezone: "Europe/Rome",
    });
    expect(() =>
      normalizeCalendarWrite({
        ...calendarFixture,
        weeklySchedules: [
          {
            weekday: "monday",
            intervals: [
              { startMinute: 540, endMinute: 720 },
              { startMinute: 660, endMinute: 840 },
            ],
          },
        ],
      }),
    ).toThrow(SlaInputError);
    expect(() =>
      normalizeCalendarWrite({
        ...calendarFixture,
        timezone: "Europe/Not_A_Zone",
      }),
    ).toThrow(/IANA/u);
    expect(
      normalizeCalendarWrite({
        ...calendarFixture,
        weeklySchedules: (
          [
            "sunday",
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
          ] as const
        ).map((weekday) => ({
          weekday,
          intervals: [{ startMinute: 0, endMinute: 1440 }],
        })),
      }).weeklySchedules[0],
    ).toEqual({
      weekday: "sunday",
      intervals: [{ startMinute: 0, endMinute: 1440 }],
    });
  });

  it("keeps policy metrics unique and limits recursive SLA to system Alerts", () => {
    expect(normalizePolicyWrite(policyFixture).metrics).toHaveLength(1);
    expect(() =>
      normalizePolicyWrite({
        ...policyFixture,
        metrics: [policyFixture.metrics[0]!, policyFixture.metrics[0]!],
      }),
    ).toThrow(/unique/u);
    const actionWithForeignField = {
      ...policyFixture.triggers[0]!.action,
    };
    Object.defineProperty(actionWithForeignField, "allowRecursiveSla", {
      enumerable: true,
      value: true,
    });
    expect(() =>
      normalizePolicyWrite({
        ...policyFixture,
        triggers: [
          { ...policyFixture.triggers[0]!, action: actionWithForeignField },
        ],
      }),
    ).toThrow(/fields/u);
    expect(
      normalizePolicyWrite({
        ...policyFixture,
        triggers: [
          {
            ...policyFixture.triggers[0]!,
            action: {
              kind: "create_system_alert",
              value: "sla.escalation",
              allowRecursiveSla: true,
            },
          },
        ],
      }).triggers[0]?.action,
    ).toMatchObject({ kind: "create_system_alert", allowRecursiveSla: true });
  });

  it("requires exact override bindings and an audited reason", () => {
    expect(() =>
      normalizeOverride({
        overrideId: "01991c20-7d5f-7000-8000-00000000000c",
        kind: "extend",
        reason: "short",
        slaInstanceId,
        metricInstanceId: slaMetricInstanceId,
        expectedMetricVersion: 2,
        extensionMicros: 900_000_000,
      }),
    ).toThrow(/at least 8/u);
    expect(
      normalizeOverride({
        overrideId: "01991c20-7d5f-7000-8000-00000000000c",
        kind: "extend",
        reason: "Customer-approved extension",
        slaInstanceId,
        metricInstanceId: slaMetricInstanceId,
        expectedMetricVersion: 2,
        extensionMicros: 900_000_000,
      }),
    ).toMatchObject({ kind: "extend", expectedMetricVersion: 2 });
    const policyOverride: SlaOverrideRequest = {
      overrideId: "01991c20-7d5f-7000-8000-00000000000c",
      kind: "change_policy",
      reason: "Move to the approved recovery policy",
      slaInstanceId,
      expectedAggregateVersion: 3,
      newPolicyId: policyFixture.id,
      newPolicyVersion: 1,
      simulationDigest:
        "7f8fe0d33c8e9ca1f05dcff86e9fe8e70c74723228115db159224389f84be22b",
    };
    Object.defineProperties(policyOverride, {
      metricInstanceId: { enumerable: true, value: slaMetricInstanceId },
      expectedMetricVersion: { enumerable: true, value: 2 },
    });
    expect(() => normalizeOverride(policyOverride)).toThrow(/fields/u);
    expect(() =>
      normalizeOverride({
        overrideId: "01991c20-7d5f-7000-8000-00000000000c",
        kind: "change_policy",
        reason: "Move to the approved recovery policy",
        slaInstanceId,
        expectedAggregateVersion: 3,
        newPolicyId: policyFixture.id,
        newPolicyVersion: 1,
        simulationDigest: "7F8FE0D33C8E9CA1",
      }),
    ).toThrow(/lowercase hexadecimal SHA-256/u);
  });

  it("formats positive and breached durations without using color as the signal", () => {
    expect(formatSlaDuration(90_060)).toBe("1d 1h 1m");
    expect(formatSlaDuration(-900)).toBe("−15m");
  });
});
