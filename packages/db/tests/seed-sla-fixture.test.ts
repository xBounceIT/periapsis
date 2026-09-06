import { describe, expect, it } from "vitest";

import {
  demoSlaCalendarDocument,
  demoSlaPolicyDocument,
} from "../seeds/sla-fixture.js";

describe("kernel-generated demo SLA publication documents", () => {
  it("retains explicit absent pins and the elapsed-clock demo semantics", () => {
    expect(demoSlaCalendarDocument).toMatchObject({
      timezone: "UTC",
      exceptions: [],
      weekly_schedule: [
        { weekday: 1, intervals: [{ start_minute: 0, end_minute: 1_440 }] },
      ],
    });
    expect(demoSlaCalendarDocument.revision_digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(demoSlaPolicyDocument.match_rule).toEqual({ kind: "all" });
    expect(demoSlaPolicyDocument).toMatchObject({
      object_types: ["case"],
      apply_to_sla_engine_source: false,
      effective_until: null,
      metrics: [
        {
          duration_micros: 14_400_000_000,
          clock: "elapsed",
          calendar_id: null,
          calendar_version: null,
          pause_event: null,
          resume_event: null,
          reset_event: null,
          warning_consumed_percent: null,
          warning_remaining_micros: null,
        },
      ],
      triggers: [
        {
          kind: "due",
          action_kind: "add_tag",
          action_value: "sla-breached",
          action_configuration_id: null,
          allow_recursive_sla: false,
        },
      ],
    });
  });
});
