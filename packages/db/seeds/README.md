# Synthetic seed SLA documents

`sla-fixture-input.json` is the canonical synthetic response-policy preset input.
`sla-fixture.go` constructs the calendar, rule, metric, trigger and policy with
`modules/sla`, then exports their publication documents and kernel digests. The
committed `sla-fixture.generated.json` is generated, not hand-maintained. The seed
loads it without requiring Go at runtime and verifies its identity bindings
against `phaseOneFixtures` before publishing through the existing database ABIs.

From the repository root:

```sh
corepack pnpm generate:sla-fixture
corepack pnpm verify:sla-fixture
```

The focused DB test `tests/seed-sla-fixture.test.ts` verifies identity and seed
wiring without requiring Go in the TypeScript-only test job. The root `generate`
command includes fixture regeneration. Root `verify` and the Go-pinned generated-drift
jobs in both CI workflows run `verify:sla-fixture`: the non-mutating generation check,
standalone Go round-trip/planner tests, and Go vet.
Formatting is ignored by the drift check; JSON values, field ordering and array
ordering are not. This does not replace a fresh seed followed by the real
PostgreSQL ingress worker's claim, plan and commit path.

For an isolated performance fixture, provide another input file with
`object_type: "alert"` and its exact tenant/calendar/policy/metric/trigger IDs,
key prefix, effective instant and duration in microseconds. An optional
`column_id` exports a kernel-constructed `due_at`/`datetime` column with its own
revision digest, bound to that exact metric and tenant. Publish this column too
before creating source tickets that need its materialized values. The same command
exports a bounded elapsed-clock response policy and due/add-tag trigger. It is
not a general configuration serializer. Publish the result through the canonical
API/SQL path before creating the source tickets; do not insert fabricated SLA
instances or consume ingress as `no_policy` for a matched policy.

The checked performance preset is `tests/performance/sla-fixture-input.json`.
Both root commands generate/check its adjacent `sla-fixture.generated.json` along
with the demo preset. Its Alert metric lasts one elapsed second. Both presets
explicitly declare `completion_event: "ticket.in_progress"`, matching the canonical
nonterminal workflow-state event; there is no generic `ticket.transitioned` ingress
event. A missing or invalid completion key is rejected by generation.
The performance SQL publishes calendar/policy/column before source Alerts.
Materialized values and timers come from the real worker, not SQL fixture inserts;
the seeded Alert retains its earlier frozen no-policy decision.

The demo calendar remains UTC, Monday 00:00–24:00; the metric uses elapsed time,
so it has no calendar pin. All absent optional publication fields stay `null`.
The calendar and policy digests bind the exact tenant, IDs and revision 1; metric
and trigger digests bind their definitions and metric relationship. Changing any
identity or definition requires regeneration, not transplanting a digest.

The seed's durable re-entry guards deliberately do not rewrite already published
immutable revisions or their frozen ingress snapshots. Test this correction on a
fresh database. Existing malformed demo fixtures need a separately authorized
forward publication/remediation decision; this generator does not repair them.
