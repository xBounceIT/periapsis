import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import test from "node:test";
import { Script } from "node:vm";

import {
  createShutdownLatch,
  sanitizedPostgresEnvironment,
} from "../../scripts/performance/harness-safety.mjs";
import {
  assertSlaWorkerReport,
  parseSlaWorkerReport,
} from "../../scripts/performance/sla-worker-report.mjs";
import {
  activeProcessTreeCount,
  preflightWindowsSystemTools,
  runTrackedCommand,
  terminateActiveProcessTrees,
} from "../../scripts/performance/tracked-command.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const windowsSystemTools = preflightWindowsSystemTools();
const source = await readFile(
  join(repositoryRoot, "scripts/performance/run-ticketing-hot-paths.mjs"),
  "utf8",
);

function sourceBetween(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(
    start >= 0 && end > start,
    "actual runner function boundaries must exist",
  );
  assert.equal(
    source.indexOf(startMarker, start + startMarker.length),
    -1,
    "actual runner start boundary must be unique",
  );
  return source.slice(start, end);
}

const workerSource = sourceBetween(
  "async function runSlaWorker(",
  "function runPsql(",
);
const shutdownSource = sourceBetween(
  "function assertShutdownWasNotRequested()",
  "const planBudgets =",
);

function queue(completed, total) {
  return {
    total,
    queued: total - completed,
    leased: 0,
    retryScheduled: 0,
    completed,
    deadLettered: 0,
  };
}

function workerReport(mode, completed) {
  const report = {
    schemaVersion: 1,
    status: "passed",
    mode,
    batches: completed === 0 ? 0 : Math.ceil(completed / 100),
    claimed: completed,
    completed,
    replayed: 0,
    retryScheduled: 0,
    deadLettered: 0,
    fenceLost: 0,
    durationMs: 10,
    processingMs: 5,
    queueBefore: queue(0, completed),
    queueAfter: queue(completed, completed),
    outcomes:
      mode === "timers"
        ? { timer_completed: completed }
        : { assigned: completed },
  };
  if (completed > 0) report.receiptsDigest = "b".repeat(64);
  if (mode === "ingress") {
    report.snapshotBefore = "a".repeat(64);
    report.snapshotAfter = report.snapshotBefore;
    report.snapshotsStable = true;
  }
  return report;
}

function invocation(
  report,
  { rawOutput, exitCode = 0, onSpawn, childCode } = {},
) {
  const calls = [];
  const reports = {};
  let signalCallbacks = 0;
  const shutdownLatch = createShutdownLatch(() => {
    signalCallbacks += 1;
    terminateActiveProcessTrees();
  });
  const credentialFile = join(
    tmpdir(),
    "periapsis-performance-sla-worker-synthetic",
    "database-url.conf",
  );
  const expectedDirectory = join(
    tmpdir(),
    "periapsis-performance-pg-synthetic",
  );
  const executable = join(
    tmpdir(),
    process.platform === "win32" ? "performance-sla.exe" : "performance-sla",
  );
  const scope = {
    performance,
    repositoryRoot,
    windowsSystemTools,
    shutdownLatch,
    loadBudgets: { sla_worker_claim: { maxWorkerMs: 30_000 } },
    slaWorkerExecutable: executable,
    slaWorkerCredential: { file: credentialFile },
    expectedClusterDataDirectory: expectedDirectory,
    process: {
      env: {
        ...process.env,
        DATABASE_URL: "synthetic-inherited-secret",
        DATABASE_URL_FILE: "synthetic-inherited-file",
        PGPASSWORD: "synthetic-inherited-password",
        PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE:
          "synthetic-poisoned-worker-file",
        PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY:
          "synthetic-poisoned-directory",
        PERIAPSIS_PERFORMANCE_UNKNOWN: "synthetic-unapproved-setting",
      },
    },
    sanitizedPostgresEnvironment,
    parseSlaWorkerReport,
    assertSlaWorkerReport,
    runTrackedCommand: async (command, args, options) => {
      assert.equal(command, executable);
      const mode = report.mode;
      assert.deepEqual(
        Array.from(args),
        mode === "ingress"
          ? [
              "--mode",
              "ingress",
              "--timeout",
              "1800000ms",
              "--max-events",
              "500000",
            ]
          : [
              "--mode",
              "timers",
              "--timeout",
              "30000ms",
              "--max-events",
              "100",
              "--max-batches",
              "1",
            ],
      );
      assert.equal(options.cwd, repositoryRoot);
      assert.equal(options.maxOutputBytes, 64 * 1024);
      assert.equal(options.timeoutMs, mode === "ingress" ? 1_805_000 : 35_000);
      assert.equal(options.windowsTaskkillPath, windowsSystemTools?.taskkill);
      assert.equal(
        options.env.PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE,
        credentialFile,
      );
      assert.equal(
        options.env.PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY,
        expectedDirectory,
      );
      for (const key of [
        "DATABASE_URL",
        "DATABASE_URL_FILE",
        "PGPASSWORD",
        "PERIAPSIS_PERFORMANCE_UNKNOWN",
      ]) {
        assert.equal(
          options.env[key],
          undefined,
          `${key} must not leak into the child`,
        );
      }
      calls.push({
        command,
        args: Array.from(args),
        timeoutMs: options.timeoutMs,
      });
      // The actual adapter, sanitizer, tracker and parser execute unchanged.
      // Only the executable payload is replaced: this child never opens a DB.
      const code =
        childCode ??
        `process.stdout.write(${JSON.stringify(rawOutput ?? JSON.stringify(report))}); process.stderr.write("synthetic-private-stderr"); process.exitCode = ${exitCode};`;
      const pending = runTrackedCommand(
        process.execPath,
        ["-e", code],
        options,
      );
      onSpawn?.(shutdownLatch);
      return pending;
    },
  };
  const run = new Script(
    `${shutdownSource}\n${workerSource}\nrunSlaWorker;`,
  ).runInNewContext(scope);
  return {
    calls,
    reports,
    shutdownLatch,
    signalCallbacks: () => signalCallbacks,
    run: () => run(report.mode, reports, "probe"),
  };
}

for (const completed of [0, 1000]) {
  test(`actual ingress invocation sanitizes its file-only environment and accepts ${completed} settled events`, async () => {
    const original = workerReport("ingress", completed);
    const probe = invocation(original);
    const report = await probe.run();
    assert.equal(probe.calls.length, 1);
    assert.equal(report.completed, completed);
    assert.equal(report.snapshotBefore, report.snapshotAfter);
    assert.equal(report.snapshotsStable, true);
    assert.ok(report.wallMs > 0);
    assert.equal(probe.reports.probe, report);
    assert.doesNotMatch(
      JSON.stringify(report),
      /synthetic-private-stderr|synthetic-inherited/,
    );
    assert.equal(activeProcessTreeCount(), 0);
  });
}

test("actual timer invocation passes one bounded 100-job batch to a tracked child", async () => {
  const probe = invocation(workerReport("timers", 100));
  const report = await probe.run();
  assert.equal(probe.calls.length, 1);
  assert.equal(report.claimed, 100);
  assert.equal(report.completed, 100);
  assert.equal(report.batches, 1);
  assert.equal(activeProcessTreeCount(), 0);
});

test("actual invocation retains a failed report even when the child exits nonzero", async () => {
  const original = workerReport("ingress", 100);
  original.status = "failed";
  original.errorCode = "worker_failed";
  original.completed = 99;
  original.retryScheduled = 1;
  const probe = invocation(original, { exitCode: 1 });
  await assert.rejects(probe.run(), /SLA worker process failed/);
  assert.equal(probe.reports.probe.status, "failed");
  assert.equal(probe.reports.probe.errorCode, "worker_failed");
  assert.equal(probe.reports.probe.retryScheduled, 1);
  assert.doesNotMatch(
    JSON.stringify(probe.reports),
    /synthetic-private-stderr/,
  );
  assert.equal(activeProcessTreeCount(), 0);
});

test("actual invocation retains malformed-output failure without retaining arbitrary stdout", async () => {
  const probe = invocation(workerReport("timers", 100), {
    rawOutput: "synthetic-private-invalid-json",
  });
  await assert.rejects(probe.run(), /SLA worker did not return a valid report/);
  assert.equal(probe.reports.probe.status, "failed");
  assert.equal(probe.reports.probe.errorCode, "invalid_worker_report");
  assert.doesNotMatch(JSON.stringify(probe.reports), /synthetic-private/);
  assert.equal(activeProcessTreeCount(), 0);
});

test("actual invocation retains valid JSON before rejecting unproven timer processing", async () => {
  const original = workerReport("timers", 100);
  original.completed = 99;
  const probe = invocation(original);
  await assert.rejects(probe.run(), /successful processing/);
  assert.equal(probe.reports.probe.claimed, 100);
  assert.equal(probe.reports.probe.completed, 99);
  assert.equal(activeProcessTreeCount(), 0);
});

test("actual runner shutdown guard prevents a new worker after the signal callback", async () => {
  const probe = invocation(workerReport("timers", 100));
  probe.shutdownLatch.handle("SIGTERM");
  await assert.rejects(probe.run(), /SIGTERM; cleanup is required/);
  assert.equal(probe.signalCallbacks(), 1);
  assert.equal(probe.calls.length, 0);
  assert.equal(activeProcessTreeCount(), 0);
});

test("shutdown callback terminates the real tracked child and keeps bounded failure evidence", async () => {
  const probe = invocation(workerReport("timers", 100), {
    childCode: "setInterval(() => {}, 1000);",
    onSpawn: (latch) => latch.handle("SIGTERM"),
  });
  await assert.rejects(probe.run(), /SLA worker did not return a valid report/);
  assert.equal(probe.signalCallbacks(), 1);
  assert.equal(probe.calls.length, 1);
  assert.equal(probe.reports.probe.errorCode, "invalid_worker_report");
  assert.equal(activeProcessTreeCount(), 0);
});

test("real tracker accepts the CLI's 30-minute limit plus grace and rejects a larger timeout before spawning", async () => {
  const options = {
    cwd: repositoryRoot,
    env: sanitizedPostgresEnvironment(process.env),
    timeoutMs: 1_805_000,
    windowsTaskkillPath: windowsSystemTools?.taskkill,
  };
  const result = await runTrackedCommand(
    process.execPath,
    ["-e", "process.exitCode = 0;"],
    options,
  );
  assert.equal(result.status, 0);
  assert.equal(result.treeQuiesced, true);
  assert.throws(
    () =>
      runTrackedCommand(process.execPath, ["-e", "process.exitCode = 0;"], {
        ...options,
        timeoutMs: 1_805_001,
      }),
    /tracked command timeout is invalid/,
  );
  assert.equal(activeProcessTreeCount(), 0);
});
