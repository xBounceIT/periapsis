import assert from "node:assert/strict";
import test from "node:test";

import {
  assertSlaWorkerReport,
  parseSlaWorkerReport,
} from "../../scripts/performance/sla-worker-report.mjs";

const snapshotDigest = "a".repeat(64);
const receiptDigest = "b".repeat(64);

function queue(completed = 0, total = 1000) {
  return {
    total,
    queued: total - completed,
    leased: 0,
    retryScheduled: 0,
    completed,
    deadLettered: 0,
  };
}

function ingressReport() {
  return {
    schemaVersion: 1,
    mode: "ingress",
    status: "passed",
    batches: 10,
    claimed: 1000,
    completed: 998,
    replayed: 2,
    retryScheduled: 0,
    deadLettered: 0,
    fenceLost: 0,
    durationMs: 2000,
    processingMs: 1900,
    queueBefore: queue(),
    queueAfter: queue(1000),
    snapshotBefore: snapshotDigest,
    snapshotAfter: snapshotDigest,
    snapshotsStable: true,
    receiptsDigest: receiptDigest,
    outcomes: { assigned: 950, no_policy: 48, replayed: 2 },
  };
}

function timerReport() {
  const report = ingressReport();
  report.mode = "timers";
  report.batches = 1;
  report.claimed = 100;
  report.completed = 100;
  report.replayed = 0;
  report.queueAfter = queue(100);
  report.outcomes = { "completed/applied": 100 };
  delete report.snapshotBefore;
  delete report.snapshotAfter;
  delete report.snapshotsStable;
  return report;
}

function parse(report, mode = report.mode) {
  return parseSlaWorkerReport(JSON.stringify(report), mode);
}

test("ingress report proves every event settled and the frozen assignment snapshot is unchanged", () => {
  const original = ingressReport();
  const report = parse(original);
  assert.deepEqual(report, original);
  assert.doesNotThrow(() => assertSlaWorkerReport(report, "ingress"));
  assert.equal(
    report.queueAfter.completed - report.queueBefore.completed,
    report.claimed,
  );
  assert.equal(report.snapshotBefore, report.snapshotAfter);
});

test("already settled ingress accepts zero work without a receipt digest", () => {
  const original = ingressReport();
  original.batches = 1;
  original.claimed = 0;
  original.completed = 0;
  original.replayed = 0;
  original.queueBefore = queue(1000);
  original.outcomes = {};
  delete original.receiptsDigest;
  assert.doesNotThrow(() => assertSlaWorkerReport(parse(original), "ingress"));
});

test("timer report proves exactly one fully finalized 100-job batch", () => {
  const report = parse(timerReport());
  assert.equal(report.snapshotsStable, false);
  assert.equal(report.claimed, 100);
  assert.equal(report.completed, 100);
  assert.doesNotThrow(() => assertSlaWorkerReport(report, "timers"));
});

test("timer success does not require global queue deltas to equal a single concurrent worker batch", () => {
  const original = timerReport();
  original.queueAfter = queue(400);
  assert.doesNotThrow(() => assertSlaWorkerReport(parse(original), "timers"));
});

test("failed worker evidence is retained but can never pass the processing gate", () => {
  for (const original of [ingressReport(), timerReport()]) {
    original.status = "failed";
    original.errorCode = "worker_processing_failed";
    original.completed = 1;
    original.retryScheduled = 1;
    const report = parse(original);
    assert.equal(report.status, "failed");
    assert.equal(report.errorCode, "worker_processing_failed");
    assert.equal(report.retryScheduled, 1);
    assert.throws(
      () => assertSlaWorkerReport(report, original.mode),
      /successful processing/,
    );
  }
});

test("malformed JSON, protocol versions, modes and statuses fail with generic errors", () => {
  for (const output of ["", "not-json", '{"sensitive":"synthetic-password"']) {
    assert.throws(
      () => parseSlaWorkerReport(output, "ingress"),
      (error) => {
        assert.equal(error.message, "SLA worker report is not JSON");
        assert.doesNotMatch(error.message, /synthetic-password/);
        return true;
      },
    );
  }
  for (const original of [
    null,
    [],
    1,
    "string",
    {},
    { ...ingressReport(), schemaVersion: 2 },
    { ...ingressReport(), mode: "unknown" },
    { ...ingressReport(), status: "complete" },
  ]) {
    assert.throws(
      () => parseSlaWorkerReport(JSON.stringify(original), "ingress"),
      /report is malformed/,
    );
  }
  assert.throws(() => parse(ingressReport(), "timers"), /report is malformed/);
  assert.throws(
    () => parse(ingressReport(), "unsupported"),
    /report is malformed/,
  );
});

test("every top-level counter must be present, nonnegative and JSON-safe", () => {
  for (const key of [
    "batches",
    "claimed",
    "completed",
    "replayed",
    "retryScheduled",
    "deadLettered",
    "fenceLost",
    "durationMs",
    "processingMs",
  ]) {
    for (const value of [
      undefined,
      null,
      -1,
      0.5,
      Number.MAX_SAFE_INTEGER + 1,
      "1",
      true,
    ]) {
      const original = ingressReport();
      original[key] = value;
      assert.throws(
        () => parse(original),
        /report is malformed/,
        `${key}=${String(value)}`,
      );
    }
  }
});

test("queue counters must be valid and each queue total must equal its statuses", () => {
  for (const queueName of ["queueBefore", "queueAfter"]) {
    for (const key of [
      "total",
      "queued",
      "leased",
      "retryScheduled",
      "completed",
      "deadLettered",
    ]) {
      for (const value of [undefined, -1, Number.MAX_SAFE_INTEGER + 1, "1"]) {
        const original = ingressReport();
        original[queueName][key] = value;
        assert.throws(() => parse(original), /queue report is malformed/);
      }
    }
    const original = ingressReport();
    original[queueName].total += 1;
    assert.throws(() => parse(original), /queue totals disagree/);
  }
});

test("ingress success rejects missing or changed immutable snapshot proof", () => {
  const mutations = [
    (report) => {
      delete report.snapshotBefore;
    },
    (report) => {
      delete report.snapshotAfter;
    },
    (report) => {
      delete report.snapshotsStable;
    },
    (report) => {
      report.snapshotsStable = false;
    },
    (report) => {
      report.snapshotsStable = "true";
    },
    (report) => {
      report.snapshotAfter = "c".repeat(64);
    },
  ];
  for (const mutate of mutations) {
    const original = ingressReport();
    mutate(original);
    assert.throws(
      () => assertSlaWorkerReport(parse(original), "ingress"),
      /snapshot proof failed/,
    );
  }
});

test("ingress success rejects remaining work, changed queue population or an unproven completed delta", () => {
  const mutations = [
    (report) => {
      report.queueAfter = queue(999);
    },
    (report) => {
      report.queueAfter = queue(1001, 1001);
    },
    (report) => {
      report.queueBefore = queue(1);
    },
  ];
  for (const mutate of mutations) {
    const original = ingressReport();
    mutate(original);
    assert.throws(
      () => assertSlaWorkerReport(parse(original), "ingress"),
      /settlement/,
    );
  }
});

test("processing gates reject partial completion, retry, dead-letter, lost fences or missing receipts", () => {
  const mutations = [
    (report) => {
      report.completed -= 1;
    },
    (report) => {
      report.retryScheduled = 1;
    },
    (report) => {
      report.deadLettered = 1;
    },
    (report) => {
      report.fenceLost = 1;
    },
    (report) => {
      report.errorCode = "incomplete";
    },
    (report) => {
      delete report.receiptsDigest;
    },
    (report) => {
      delete report.queueBefore;
    },
    (report) => {
      delete report.queueAfter;
    },
  ];
  for (const makeReport of [ingressReport, timerReport]) {
    for (const mutate of mutations) {
      const original = makeReport();
      mutate(original);
      assert.throws(
        () => assertSlaWorkerReport(parse(original), original.mode),
        /successful processing/,
      );
    }
  }
});

test("timer processing rejects any batch size other than 100 new finalized jobs", () => {
  const mutations = [
    (report) => {
      report.batches = 0;
    },
    (report) => {
      report.batches = 2;
    },
    (report) => {
      report.claimed = 99;
      report.completed = 99;
    },
    (report) => {
      report.claimed = 101;
      report.completed = 101;
    },
    (report) => {
      report.completed = 99;
      report.replayed = 1;
    },
  ];
  for (const mutate of mutations) {
    const original = timerReport();
    mutate(original);
    assert.throws(
      () => assertSlaWorkerReport(parse(original), "timers"),
      /exactly one batch/,
    );
  }
});

test("digest and error-code fields require bounded scalar strings", () => {
  for (const key of ["snapshotBefore", "snapshotAfter", "receiptsDigest"]) {
    for (const value of [
      null,
      "",
      "A".repeat(64),
      "a".repeat(63),
      "a".repeat(65),
      [snapshotDigest],
    ]) {
      const original = ingressReport();
      original[key] = value;
      assert.throws(() => parse(original), /digest is malformed/);
    }
  }
  for (const value of [
    null,
    "",
    "UpperCase",
    "a".repeat(41),
    "unsafe/message",
    ["worker_failed"],
  ]) {
    const original = ingressReport();
    original.errorCode = value;
    assert.throws(() => parse(original), /error code is malformed/);
  }
});

test("outcomes require a bounded object of safe names and nonnegative safe counters", () => {
  const tooMany = Object.fromEntries(
    Array.from({ length: 33 }, (_, index) => [
      `outcome_${String.fromCharCode(97 + Math.floor(index / 26))}${String.fromCharCode(97 + (index % 26))}`,
      1,
    ]),
  );
  for (const value of [
    null,
    [],
    true,
    1,
    { "unsafe path": 1 },
    { "a/b/c/d": 1 },
    { valid: -1 },
    { valid: Number.MAX_SAFE_INTEGER + 1 },
    tooMany,
  ]) {
    const original = ingressReport();
    original.outcomes = value;
    assert.throws(() => parse(original), /outcomes are malformed/);
  }
});

test("parsing drops all unknown child fields instead of retaining sensitive output", () => {
  const original = ingressReport();
  original.databaseUrl = "synthetic-sensitive-top-level";
  original.rawError = { password: "synthetic-sensitive-error" };
  original.queueBefore.sql = "synthetic-sensitive-query";
  original.queueAfter.connection = { password: "synthetic-sensitive-nested" };
  const report = parse(original);
  assert.deepEqual(report, ingressReport());
  assert.doesNotMatch(JSON.stringify(report), /synthetic-sensitive/);
  assert.doesNotThrow(() => assertSlaWorkerReport(report, "ingress"));
});
