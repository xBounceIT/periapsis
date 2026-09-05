import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { phaseOneFixtures } from "../src/testing/fixtures.js";

const fixture: unknown = JSON.parse(
  readFileSync(
    new URL("./sla-fixture.generated.json", import.meta.url),
    "utf8",
  ),
);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

assert(isRecord(fixture), "generated SLA fixture must be an object");
assert(isRecord(fixture.identity), "generated SLA fixture identity is missing");
assert(isRecord(fixture.calendar), "generated SLA calendar is missing");
assert(isRecord(fixture.policy), "generated SLA policy is missing");

// Calendar and policy digests include these exact tenant/resource identities.
// Never reuse a generated document under different seed IDs.
assert.deepEqual(fixture.identity, {
  tenant_id: phaseOneFixtures.tenants.acme.id,
  calendar_id: phaseOneFixtures.demo.sla.calendar,
  policy_id: phaseOneFixtures.demo.sla.policy,
  metric_id: phaseOneFixtures.demo.sla.metric,
  trigger_id: phaseOneFixtures.demo.sla.trigger,
  object_type: "case",
  key_prefix: "demo",
  effective_from: "2026-01-02T12:00:00Z",
  duration_micros: 14_400_000_000,
  completion_event: "ticket.in_progress",
});

export const demoSlaCalendarDocument = fixture.calendar;
export const demoSlaPolicyDocument = fixture.policy;
