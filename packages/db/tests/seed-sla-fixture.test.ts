import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  demoSlaCalendarDocument,
  demoSlaPolicyDocument,
} from "../seeds/sla-fixture.js";

const root = resolve(import.meta.dirname, "../../..");

describe("kernel-generated demo SLA publication documents", () => {
  it("binds the generated documents to the canonical fixture input", () => {
    const input: unknown = JSON.parse(
      readFileSync(
        resolve(root, "packages/db/seeds/sla-fixture-input.json"),
        "utf8",
      ),
    );
    const generated: unknown = JSON.parse(
      readFileSync(
        resolve(root, "packages/db/seeds/sla-fixture.generated.json"),
        "utf8",
      ),
    );
    expect(generated).toEqual(expect.objectContaining({ identity: input }));
  });

  it("retains explicit absent pins and the elapsed-clock demo semantics", () => {
    expect(demoSlaCalendarDocument).toMatchObject({
      timezone: "UTC",
      exceptions: [],
      weekly_schedule: [
        { weekday: 1, intervals: [{ start_minute: 0, end_minute: 1_440 }] },
      ],
    });
    expect(demoSlaPolicyDocument).toMatchObject({
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

  it("feeds generated documents to the existing publication ABIs", () => {
    const seed = readFileSync(
      resolve(root, "packages/db/seeds/seed.ts"),
      "utf8",
    );
    expect(seed).toContain('from "./sla-fixture.js"');
    expect(seed).toContain("JSON.stringify(demoSlaCalendarDocument)");
    expect(seed).toContain("JSON.stringify(demoSlaPolicyDocument)");
    expect(seed).not.toContain("match_rule: {}");
    expect(demoSlaCalendarDocument.revision_digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(demoSlaPolicyDocument.match_rule).toEqual({ kind: "all" });
    expect(demoSlaPolicyDocument.object_types).toEqual(["case"]);
    expect(demoSlaPolicyDocument.apply_to_sla_engine_source).toBe(false);
  });
});
