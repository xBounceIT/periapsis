import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) =>
  readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("performance SLA publications bind the generated preset before immutable ticket snapshots", async () => {
  const [input, generated, fixture, manifest] = await Promise.all([
    read("tests/performance/sla-fixture-input.json").then(JSON.parse),
    read("tests/performance/sla-fixture.generated.json").then(JSON.parse),
    read("tests/performance/ticketing-100k-fixture.sql"),
    read("package.json").then(JSON.parse),
  ]);
  assert.deepEqual(generated.identity, input);
  assert.equal(input.object_type, "alert");
  assert.equal(input.duration_micros, 1_000_000);
  assert.equal(generated.policy.metrics[0].start_event, "ticket.created");
  assert.equal(
    generated.policy.metrics[0].completion_event,
    "ticket.in_progress",
  );
  assert.equal(generated.column.metric_definition_id, input.metric_id);
  assert.equal(generated.column.calculation, "due_at");
  assert.equal(generated.column.key, "performance-due-at");
  const publication = fixture.slice(
    fixture.indexOf("DO $publish_performance_sla$"),
    fixture.indexOf("$publish_performance_sla$;"),
  );
  const pin = publication.match(/IS DISTINCT FROM '([\s\S]+?)'::jsonb/u);
  assert.ok(pin);
  assert.deepEqual(JSON.parse(pin[1]), input);
  assert.ok(
    fixture.indexOf("$publish_performance_sla$;") <
      fixture.indexOf("DO $load_alert_batches$"),
  );
  for (const kind of ["calendar", "policy", "column"]) {
    assert.ok(publication.includes(`app.publish_sla_${kind}_v2(`));
    assert.ok(publication.includes(`fixture->'${kind}'`));
  }
  assert.match(
    fixture,
    /BEGIN;\s+SET LOCAL ROLE periapsis_api;\s+DO \$publish_performance_sla\$/u,
  );
  assert.doesNotMatch(
    fixture,
    /\b(?:INSERT INTO|UPDATE|DELETE FROM)\s+public\.sla_[a-z_]+/iu,
  );
  assert.doesNotMatch(fixture, /performance-(?:policy|metric|column)-v1/u);
  assert.match(
    manifest.scripts["generate:sla-fixture"],
    /--input tests\/performance\/sla-fixture-input.json --output tests\/performance\/sla-fixture.generated.json/u,
  );
  assert.match(
    manifest.scripts["verify:sla-fixture"],
    /--input tests\/performance\/sla-fixture-input.json --check tests\/performance\/sla-fixture.generated.json/u,
  );
});

test("performance runner settles ingress and measures finalized timers without queue SQL writes", async () => {
  const runner = await read("scripts/performance/run-ticketing-hot-paths.mjs");
  const fixtureStart = runner.indexOf('stage = "fixture"');
  const drain = runner.indexOf(
    'runSlaWorker("ingress", evidence.slaProcessing, "after_fixture")',
  );
  assert.ok(fixtureStart >= 0 && drain > fixtureStart);
  assert.ok(drain < runner.indexOf('stage = "dataset_verification"'));
  assert.match(runner, /value.slaValueCount !== 99_999/u);
  assert.match(runner, /value.slaCompletedMetricCount !== 1_000/u);
  assert.match(runner, /value.slaRunningMetricCount !== 98_999/u);
  assert.match(runner, /value.slaPendingIngressCount !== 0/u);
  assert.match(
    runner,
    /runSlaWorker\("ingress", evidence.slaProcessing, "after_ticket_loads"\)/u,
  );
  assert.match(runner, /await measureSlaTimers\(targetUrl, urls, evidence\)/u);
  assert.doesNotMatch(runner, /app\.claim_sla_evaluation_jobs_v[0-9]+\(/u);
  assert.match(runner, /result.after.completed - before.completed/u);
  assert.match(
    runner,
    /result.after.aggregateVersions <= before.aggregateVersions/u,
  );
  assert.match(
    runner,
    /PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE: slaWorkerCredential.file/u,
  );
  assert.match(runner, /runTrackedCommand\(slaWorkerExecutable, args/u);
  assert.ok(
    runner.indexOf("await terminateAndAwaitActiveProcessTrees()") <
      runner.indexOf("await removeSlaWorkerCredential(slaWorkerCredential)"),
  );
});
