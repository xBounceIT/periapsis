import assert from "node:assert/strict";
import { mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { URL } from "node:url";

import {
  assertLoadBudget,
  assertPlanBudget,
  parseExplainJson,
  summarizePlan,
} from "../../scripts/performance/plan-budget.mjs";
import {
  assertDisposableDatabaseName,
  assertExpectedClusterDataDirectory,
  assertFreshClusterFacts,
  assertOwnedBackendSettlement,
  assertPostgresVersion,
  blockedCleanupIdentifiers,
  catchableShutdownSignals,
  createDisposableDatabaseName,
  createRecoveredCleanupError,
  createShutdownLatch,
  databaseUrl,
  mergeShutdownFailure,
  parseMigrationManifest,
  parseLocalAdminUrl,
  parseWindowsIdentitySid,
  passwordlessConnectionUrl,
  pgPassEntry,
  preflightPsqlExecutable,
  publishFileNoReplace,
  redactConnectionText,
  sanitizedPostgresEnvironment,
} from "../../scripts/performance/harness-safety.mjs";

async function unlinkIfPresent(path) {
  try {
    await unlink(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

const explain = JSON.stringify([
  {
    Plan: {
      "Node Type": "Limit",
      "Actual Rows": 101,
      "Actual Loops": 1,
      "Shared Hit Blocks": 120,
      "Shared Read Blocks": 4,
      "Temp Read Blocks": 0,
      "Temp Written Blocks": 0,
      Plans: [
        {
          "Node Type": "Index Scan",
          "Relation Name": "alerts",
          "Index Name": "alerts_tenant_created_idx",
          "Actual Rows": 101,
          "Actual Loops": 1,
        },
      ],
    },
    "Planning Time": 1.5,
    "Execution Time": 12.25,
  },
]);

test("summarizes bounded PostgreSQL JSON plan evidence", () => {
  const summary = summarizePlan(parseExplainJson(explain));
  assert.deepEqual(summary.indexes, ["alerts_tenant_created_idx"]);
  assert.deepEqual(summary.sequentialScans, []);
  assert.equal(summary.sharedBlocks, 124);
  assert.equal(summary.actualRows, 101);
  assert.equal(summary.actualLoops, 1);
  assert.deepEqual(summary.buffers, {
    sharedHitBlocks: 120,
    sharedReadBlocks: 4,
    tempReadBlocks: 0,
    tempWrittenBlocks: 0,
  });
  assert.deepEqual(summary.scans, [
    {
      nodeType: "Index Scan",
      relation: "alerts",
      index: "alerts_tenant_created_idx",
      actualRows: 101,
      actualLoops: 1,
      totalRows: 101,
    },
  ]);
  assertPlanBudget("alert_created_page", summary, {
    maxExecutionMs: 50,
    maxPlanningMs: 10,
    maxSharedBlocks: 200,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_created_idx"],
    forbiddenSequentialScans: ["alerts"],
  });
});

test("removes inherited PostgreSQL connection and option variables", () => {
  assert.deepEqual(
    sanitizedPostgresEnvironment(
      {
        Path: "safe-path",
        PGOPTIONS: "-c session_replication_role=replica",
        pgpassword: "do-not-inherit",
        DATABASE_URL: "postgres://wrong.invalid/wrong",
        DATABASE_URL_FILE: "must-not-read-inherited-database-url",
        database_url_file: "must-not-read-case-variant-on-windows",
        PERIAPSIS_PERFORMANCE_ADMIN_URL:
          "postgres://postgres:secret@127.0.0.1/postgres",
        PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE:
          "must-not-read-inherited-worker-url",
        PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY:
          "must-not-pin-inherited-directory",
      },
      {
        DATABASE_URL: "postgres://postgres@127.0.0.1/disposable",
        PGAPPNAME: "periapsis-performance-gate",
      },
    ),
    {
      Path: "safe-path",
      DATABASE_URL: "postgres://postgres@127.0.0.1/disposable",
      PGAPPNAME: "periapsis-performance-gate",
    },
  );
  assert.deepEqual(
    sanitizedPostgresEnvironment(
      {},
      {
        PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE: "explicit-owned-worker-url",
        PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY:
          "explicit-owned-directory",
      },
    ),
    {
      PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE: "explicit-owned-worker-url",
      PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY: "explicit-owned-directory",
    },
  );
  assert.throws(
    () => sanitizedPostgresEnvironment([], {}),
    /environment is malformed/,
  );
  assert.throws(
    () =>
      sanitizedPostgresEnvironment({}, { PGOPTIONS: "-c row_security=off" }),
    /override is malformed/,
  );
});

test("rejects missing indexes, sequential scans, and disk spills", () => {
  const hostile = JSON.stringify([
    {
      Plan: {
        "Node Type": "Sort",
        "Actual Rows": 101,
        "Actual Loops": 1,
        "Shared Hit Blocks": 100,
        "Shared Read Blocks": 0,
        "Temp Read Blocks": 8,
        "Temp Written Blocks": 8,
        "Sort Space Type": "Disk",
        "Sort Method": "external merge",
        "Sort Space Used": 64,
        Plans: [
          {
            "Node Type": "Seq Scan",
            "Relation Name": "alerts",
            "Actual Rows": 100_000,
            "Actual Loops": 1,
          },
        ],
      },
      "Planning Time": 1,
      "Execution Time": 20,
    },
  ]);
  const summary = summarizePlan(parseExplainJson(hostile));
  assert.throws(
    () =>
      assertPlanBudget("alert_assignee_page", summary, {
        maxExecutionMs: 50,
        maxPlanningMs: 10,
        maxSharedBlocks: 200,
        maxTempBlocks: 0,
        minResultRows: 101,
        maxResultRows: 101,
        requiredIndexes: ["alerts_tenant_assignment_idx"],
        forbiddenSequentialScans: ["alerts"],
      }),
    (error) => {
      assert.match(
        error.message,
        /required index alerts_tenant_assignment_idx/,
      );
      assert.match(error.message, /sequential scan used on alerts/);
      assert.match(error.message, /temporary blocks 16 exceeds 0/);
      assert.match(error.message, /spilled a sort to disk/);
      return true;
    },
  );
});

test("does not credit plan branches that never executed", () => {
  const skippedIndex = JSON.stringify([
    {
      Plan: {
        "Node Type": "Result",
        "Actual Rows": 101,
        "Actual Loops": 1,
        "Shared Hit Blocks": 1,
        "Shared Read Blocks": 0,
        "Temp Read Blocks": 0,
        "Temp Written Blocks": 0,
        Plans: [
          {
            "Node Type": "Index Scan",
            "Relation Name": "alerts",
            "Index Name": "alerts_tenant_updated_idx",
            "Actual Rows": 0,
            "Actual Loops": 0,
          },
        ],
      },
      "Planning Time": 1,
      "Execution Time": 1,
    },
  ]);
  const summary = summarizePlan(parseExplainJson(skippedIndex));
  assert.deepEqual(summary.indexes, []);
  assert.equal(summary.scans[0].totalRows, 0);
  assert.throws(
    () =>
      assertPlanBudget("alert_updated_page", summary, {
        maxExecutionMs: 500,
        maxPlanningMs: 100,
        maxSharedBlocks: 20_000,
        maxTempBlocks: 0,
        minResultRows: 101,
        maxResultRows: 101,
        requiredIndexes: ["alerts_tenant_updated_idx"],
        forbiddenSequentialScans: ["alerts"],
      }),
    /required index alerts_tenant_updated_idx was not used/,
  );
});

test("does not credit an executed index scan that contributes no rows", () => {
  const emptyIndex = JSON.stringify([
    {
      Plan: {
        "Node Type": "Limit",
        "Actual Rows": 101,
        "Actual Loops": 1,
        "Shared Hit Blocks": 1,
        "Shared Read Blocks": 0,
        "Temp Read Blocks": 0,
        "Temp Written Blocks": 0,
        Plans: [
          {
            "Node Type": "Index Scan",
            "Relation Name": "sla_materialized_column_values",
            "Index Name": "sla_materialized_projection_instant_sort_idx",
            "Actual Rows": 0,
            "Actual Loops": 1,
          },
        ],
      },
      "Planning Time": 1,
      "Execution Time": 1,
    },
  ]);
  const summary = summarizePlan(parseExplainJson(emptyIndex));
  assert.deepEqual(summary.indexes, []);
  assert.deepEqual(summary.scans[0], {
    nodeType: "Index Scan",
    relation: "sla_materialized_column_values",
    index: "sla_materialized_projection_instant_sort_idx",
    actualRows: 0,
    actualLoops: 1,
    totalRows: 0,
  });
  assert.throws(
    () =>
      assertPlanBudget("alert_sla_due_sort", summary, {
        maxExecutionMs: 1_000,
        maxPlanningMs: 100,
        maxSharedBlocks: 60_000,
        maxTempBlocks: 0,
        minResultRows: 101,
        maxResultRows: 101,
        requiredIndexes: ["sla_materialized_projection_instant_sort_idx"],
        forbiddenSequentialScans: ["sla_materialized_column_values"],
      }),
    /required index sla_materialized_projection_instant_sort_idx was not used/,
  );
});

test("requires one executed root loop", () => {
  const summary = summarizePlan(parseExplainJson(explain));
  assert.throws(
    () =>
      assertPlanBudget(
        "alert_updated_page",
        { ...summary, actualLoops: 2 },
        {
          maxExecutionMs: 500,
          maxPlanningMs: 100,
          maxSharedBlocks: 20_000,
          maxTempBlocks: 0,
          minResultRows: 101,
          maxResultRows: 101,
          requiredIndexes: ["alerts_tenant_created_idx"],
          forbiddenSequentialScans: ["alerts"],
        },
      ),
    /root loops 2 differs from 1/,
  );
});

test("treats parallel sequential scans as forbidden scans", () => {
  const hostile = JSON.stringify([
    {
      Plan: {
        "Node Type": "Gather",
        "Actual Rows": 101,
        "Actual Loops": 1,
        "Shared Hit Blocks": 10,
        "Shared Read Blocks": 0,
        "Temp Read Blocks": 0,
        "Temp Written Blocks": 0,
        Plans: [
          {
            "Node Type": "Parallel Seq Scan",
            "Relation Name": "alerts",
            "Actual Rows": 50_000,
            "Actual Loops": 2,
          },
        ],
      },
      "Planning Time": 1,
      "Execution Time": 20,
    },
  ]);
  const summary = summarizePlan(parseExplainJson(hostile));
  assert.deepEqual(summary.sequentialScans, ["alerts"]);
});

test("rejects a hidden or empty runtime projection", () => {
  const summary = summarizePlan(
    parseExplainJson(
      JSON.stringify([
        {
          Plan: {
            "Node Type": "Limit",
            "Actual Rows": 0,
            "Actual Loops": 1,
            "Shared Hit Blocks": 1,
            "Shared Read Blocks": 0,
            "Temp Read Blocks": 0,
            "Temp Written Blocks": 0,
            Plans: [
              {
                "Node Type": "Index Scan",
                "Relation Name": "alerts",
                "Index Name": "alerts_tenant_updated_idx",
                "Actual Rows": 0,
                "Actual Loops": 1,
              },
            ],
          },
          "Planning Time": 1,
          "Execution Time": 1,
        },
      ]),
    ),
  );
  assert.throws(
    () =>
      assertPlanBudget("alert_updated_page", summary, {
        maxExecutionMs: 500,
        maxPlanningMs: 100,
        maxSharedBlocks: 20_000,
        maxTempBlocks: 0,
        minResultRows: 101,
        maxResultRows: 101,
        requiredIndexes: ["alerts_tenant_updated_idx"],
        forbiddenSequentialScans: ["alerts"],
      }),
    /result rows 0 is below 101/,
  );
});

test("rejects malformed or unbounded explain evidence", () => {
  assert.throws(() => parseExplainJson(""), /empty/);
  assert.throws(() => parseExplainJson("{}"), /exactly one/);
  assert.throws(
    () =>
      parseExplainJson(JSON.stringify([{ Plan: { "Node Type": "Result" } }])),
    /timing evidence/,
  );
  assert.throws(
    () =>
      summarizePlan([
        {
          Plan: {
            "Node Type": "Result",
            "Actual Rows": 1,
            "Actual Loops": 1,
          },
          "Planning Time": 0,
          "Execution Time": 0,
        },
      ]),
    /Shared Hit Blocks is malformed/,
  );
});

test("only derives disposable loopback database targets", () => {
  const admin = parseLocalAdminUrl(
    "postgres://postgres:local-only@127.0.0.1:55491/postgres?sslmode=disable",
  );
  const name = createDisposableDatabaseName(1_800_000_000_000, "001122aabbcc");
  assert.equal(name, "periapsis_performance_1800000000000_001122aabbcc");
  assert.doesNotThrow(() => assertDisposableDatabaseName(name));
  assert.equal(new URL(databaseUrl(admin, name)).pathname, `/${name}`);
  assert.throws(
    () => parseLocalAdminUrl("postgres://postgres@example.com/postgres"),
    /loopback/,
  );
  assert.throws(
    () =>
      parseLocalAdminUrl(
        "postgres://postgres@127.0.0.1/postgres?options=-c%20session_replication_role%3Dreplica",
      ),
    /only permits sslmode=disable/,
  );
  assert.throws(
    () => parseLocalAdminUrl("postgres://postgres@127.0.0.1/postgres/other"),
    /name a user and database/,
  );
  assert.throws(
    () => parseLocalAdminUrl("postgres://postgres@localhost/postgres"),
    /numeric loopback/,
  );
  assert.throws(() => assertDisposableDatabaseName("postgres"), /refusing/);
});

test("accepts only a fresh disposable PostgreSQL cluster", () => {
  const fresh = {
    currentDatabase: "postgres",
    currentUserIsSuperuser: true,
    serverAddress: "127.0.0.1",
    serverTimezone: "UTC",
    databaseRoleSettingCount: 0,
    nonTemplateDatabases: ["postgres"],
    userRelationCount: 0,
    existingPeriapsisRoles: 0,
    existingDisposableDatabases: 0,
  };
  assert.deepEqual(assertFreshClusterFacts(fresh), fresh);
  for (const hostile of [
    { ...fresh, currentDatabase: "application" },
    { ...fresh, currentUserIsSuperuser: false },
    { ...fresh, serverAddress: "198.51.100.10" },
    { ...fresh, nonTemplateDatabases: ["postgres", "customer"] },
    { ...fresh, userRelationCount: 1 },
    { ...fresh, existingPeriapsisRoles: 1 },
    { ...fresh, existingDisposableDatabases: 1 },
    { ...fresh, serverTimezone: "Europe/Rome" },
    { ...fresh, serverTimezone: undefined },
    { ...fresh, databaseRoleSettingCount: 1 },
    { ...fresh, databaseRoleSettingCount: undefined },
  ]) {
    assert.throws(
      () => assertFreshClusterFacts(hostile),
      /fresh disposable PostgreSQL cluster/,
    );
  }
  assert.throws(
    () => assertFreshClusterFacts(null),
    /cluster preflight is malformed/,
  );
});

test("pins the connected PostgreSQL data directory to the owned cluster", () => {
  const expected = join(tmpdir(), "periapsis-performance-pg-expected");
  const observed = join(tmpdir(), "periapsis-performance-pg-observed");
  const canonical = join(tmpdir(), "periapsis-performance-pg-canonical");
  assert.deepEqual(
    assertExpectedClusterDataDirectory(expected, observed, {
      realpathImplementation: (value) =>
        value === expected || value === observed ? canonical : value,
      statImplementation: () => ({ isDirectory: () => true }),
    }),
    { pinned: true },
  );
  assert.throws(
    () =>
      assertExpectedClusterDataDirectory(expected, observed, {
        realpathImplementation: (value) => value,
        statImplementation: () => ({ isDirectory: () => true }),
      }),
    /differs from the pin/,
  );
  assert.throws(
    () =>
      assertExpectedClusterDataDirectory("relative", observed, {
        realpathImplementation: (value) => value,
        statImplementation: () => ({ isDirectory: () => true }),
      }),
    /pin is malformed/,
  );
});

test("requires a unique owned CREATE backend to quiesce", () => {
  assert.deepEqual(
    assertOwnedBackendSettlement({ matched: 1, terminated: 1, remaining: 0 }),
    { matched: 1, terminated: 1, remaining: 0 },
  );
  assert.deepEqual(
    assertOwnedBackendSettlement({ matched: 0, terminated: 0, remaining: 0 }),
    { matched: 0, terminated: 0, remaining: 0 },
  );
  for (const hostile of [
    { matched: 2, terminated: 2, remaining: 0 },
    { matched: 1, terminated: 0, remaining: 1 },
    { matched: 0, terminated: 1, remaining: 0 },
  ]) {
    assert.throws(
      () => assertOwnedBackendSettlement(hostile),
      /did not quiesce safely/,
    );
  }
});

test("redacts URLs and credentials from subprocess failures", () => {
  const admin = parseLocalAdminUrl(
    "postgres://postgres:local-only@127.0.0.1:55491/postgres",
  );
  const output = redactConnectionText(
    `connection ${admin.href} failed for local-only`,
    [admin],
  );
  assert.equal(output.includes("local-only"), false);
  assert.equal(output.includes(admin.href), false);
  const encoded = parseLocalAdminUrl(
    "postgres://postgres:p%40ss@127.0.0.1:55491/postgres",
  );
  assert.equal(
    redactConnectionText(`password p@ss or p%40ss at ${encoded.href}`, [
      encoded,
    ]),
    "password [REDACTED] or [REDACTED] at [REDACTED_DATABASE_URL]",
  );
  assert.throws(
    () => parseLocalAdminUrl("not-a-url-with-password-local-only"),
    (error) => {
      assert.equal(String(error).includes("local-only"), false);
      return true;
    },
  );
});

test("pins the PostgreSQL performance baseline", () => {
  assert.doesNotThrow(() => assertPostgresVersion("180006", "18.6"));
  assert.doesNotThrow(() =>
    assertPostgresVersion("180006", "18.6 (Debian 18.6-1)"),
  );
  assert.throws(
    () => assertPostgresVersion("180005", "18.5"),
    /require PostgreSQL 18.6/,
  );
});

test("requires an explicit canonical psql executable", () => {
  const executable =
    process.platform === "win32"
      ? "C:\\pgsql\\bin\\psql.exe"
      : "/opt/pgsql/bin/psql";
  assert.equal(
    preflightPsqlExecutable(executable, {
      platformName: process.platform,
      realpathImplementation: (value) => value,
      statImplementation: () => ({ isFile: () => true }),
    }),
    executable,
  );
  assert.throws(
    () => preflightPsqlExecutable("psql"),
    /must be an absolute path/,
  );
  assert.throws(
    () =>
      preflightPsqlExecutable(executable, {
        platformName: process.platform,
        realpathImplementation: () =>
          process.platform === "win32"
            ? "C:\\pgsql\\bin\\not-psql.exe"
            : "/opt/pgsql/bin/not-psql",
        statImplementation: () => ({ isFile: () => true }),
      }),
    /executable boundary is invalid/,
  );
});

test("keeps PostgreSQL passwords out of process arguments", () => {
  const admin = parseLocalAdminUrl(
    "postgres://operator:p%40ss%3Aword%5Cvalue@127.0.0.1:55491/postgres?sslmode=disable",
  );
  const argvUrl = passwordlessConnectionUrl(admin);
  assert.equal(argvUrl.includes("word"), false);
  assert.equal(new URL(argvUrl).password, "");
  assert.equal(
    pgPassEntry(admin),
    "127.0.0.1:55491:*:operator:p@ss\\:word\\\\value\n",
  );
  assert.equal(
    pgPassEntry(
      parseLocalAdminUrl(
        "postgres://postgres@127.0.0.1:55491/postgres?sslmode=disable",
      ),
    ),
    null,
  );
  assert.equal(
    pgPassEntry("postgres://operator:secret@[::1]:55491/postgres"),
    "\\:\\:1:55491:*:operator:secret\n",
  );
  assert.throws(
    () =>
      pgPassEntry("postgres://operator:line%0Abreak@127.0.0.1:55491/postgres"),
    /password is malformed/,
  );
});

test("accepts only a bounded Windows user SID for credential ACLs", () => {
  assert.equal(
    parseWindowsIdentitySid('"EXAMPLE\\operator","S-1-5-21-111-222-333-1001"'),
    "S-1-5-21-111-222-333-1001",
  );
  for (const hostile of [
    "Everyone",
    '"Everyone","Everyone"',
    '"operator","S-1-5-21-111"\ntrailing',
    '"operator","S-1-5-21-111-222-333-1001","extra"',
  ]) {
    assert.throws(
      () => parseWindowsIdentitySid(hostile),
      /identity is malformed/,
    );
  }
});

test("turns late catchable shutdown signals into a failed gate", () => {
  assert.deepEqual(catchableShutdownSignals("win32"), ["SIGINT"]);
  assert.deepEqual(catchableShutdownSignals("linux"), ["SIGINT", "SIGTERM"]);
  assert.throws(
    () => catchableShutdownSignals("unsupported"),
    /platform is unsupported/,
  );

  const signalOnly = mergeShutdownFailure(undefined, "SIGTERM");
  assert.match(signalOnly.message, /received SIGTERM/);

  const original = new Error("plan budget failed");
  const combined = mergeShutdownFailure(original, "SIGINT");
  assert.ok(combined instanceof AggregateError);
  assert.equal(combined.cause, original);
  assert.equal(combined.errors[0], original);
  assert.match(combined.errors[1].message, /received SIGINT/);

  assert.equal(mergeShutdownFailure(original, null), original);
  assert.throws(
    () => mergeShutdownFailure(original, "SIGKILL"),
    /shutdown signal is invalid/,
  );
});

test("shutdown latch catches repeated delivery and terminates only once", () => {
  const observed = [];
  const latch = createShutdownLatch((signal) => observed.push(signal));
  assert.equal(latch.signal, null);
  assert.equal(latch.handle("SIGINT"), "SIGINT");
  assert.equal(latch.handle("SIGINT"), "SIGINT");
  assert.equal(latch.handle("SIGTERM"), "SIGINT");
  assert.equal(latch.signal, "SIGINT");
  assert.deepEqual(observed, ["SIGINT"]);
  assert.throws(() => latch.handle("SIGKILL"), /signal is invalid/);
});

test("uncertain cleanup failure retains authoritative zero evidence", () => {
  const cleanupEvidence = Object.freeze({
    backendSettlements: Object.freeze([
      Object.freeze({
        application: "drop_1",
        matched: 1,
        remaining: 0,
        terminated: 1,
      }),
    ]),
    dropAttempts: 1,
    finalDatabaseCount: 0,
    status: "recovered_failed",
  });
  const failure = new Error("lost DROP response");
  const error = createRecoveredCleanupError([failure], cleanupEvidence);
  assert.ok(error instanceof AggregateError);
  assert.equal(error.cause, failure);
  assert.equal(error.cleanupEvidence, cleanupEvidence);
  assert.equal(error.cleanupEvidence.finalDatabaseCount, 0);
  assert.equal(error.cleanupEvidence.status, "recovered_failed");
  assert.throws(
    () =>
      createRecoveredCleanupError([failure], {
        ...cleanupEvidence,
        finalDatabaseCount: 1,
      }),
    /evidence is malformed/,
  );
});

test("blocked cleanup exposes only bounded manual-recovery identifiers", () => {
  assert.deepEqual(
    blockedCleanupIdentifiers(
      [4002, 4001],
      [5002, 5001],
      "periapsis-performance-pgpass-Abc_123",
    ),
    {
      activeProcessTreePids: [5001, 5002],
      activePsqlPids: [4001, 4002],
      credentialDirectoryBasename: "periapsis-performance-pgpass-Abc_123",
    },
  );
  assert.deepEqual(blockedCleanupIdentifiers([], [], null), {
    activeProcessTreePids: [],
    activePsqlPids: [],
    credentialDirectoryBasename: null,
  });
  for (const hostile of [
    [[0], [], null],
    [[4001, 4001], [], null],
    [[4001], [5001, 5001], null],
    [[4001], [], "C:\\secret\\pgpass"],
  ]) {
    assert.throws(
      () => blockedCleanupIdentifiers(...hostile),
      /identifiers are malformed/,
    );
  }
});

test("immutable evidence publication never replaces an existing target", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-performance-evidence-test-"),
  );
  const staging = join(directory, "evidence.json.tmp");
  const target = join(directory, "evidence.json");
  try {
    await writeFile(staging, "replacement", { flag: "wx" });
    await writeFile(target, "original", { flag: "wx" });
    await assert.rejects(
      publishFileNoReplace(staging, target),
      (error) => error?.code === "EEXIST",
    );
    assert.equal(await readFile(target, "utf8"), "original");
    assert.equal(await readFile(staging, "utf8"), "replacement");
  } finally {
    await Promise.all([staging, target].map(unlinkIfPresent));
    await rmdir(directory);
  }
});

test("post-commit staging cleanup cannot invert immutable evidence", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-performance-evidence-commit-test-"),
  );
  const staging = join(directory, "evidence.json.tmp");
  const target = join(directory, "evidence.json");
  try {
    await writeFile(staging, '{"status":"passed"}\n', { flag: "wx" });
    const publication = await publishFileNoReplace(staging, target, {
      unlinkImplementation: async () => {
        throw new Error("injected unlink failure");
      },
    });
    assert.deepEqual(publication, { stagingRemoved: false });
    assert.equal(await readFile(target, "utf8"), '{"status":"passed"}\n');
    assert.equal(await readFile(staging, "utf8"), '{"status":"passed"}\n');
  } finally {
    await Promise.all([staging, target].map(unlinkIfPresent));
    await rmdir(directory);
  }
});

test("parses exactly one bounded canonical migration pin", () => {
  const predecessorHash = "a".repeat(64);
  const currentHash =
    "0e36df4fb3b7c636ce95d4c05bd3a87185f0e038bfd9b681a87b791e55b8e721";
  const source = `
  export const expectedMigrationCount = 2;
  export const expectedMigrationCreatedAt = 1787741355171;
  export const expectedMigrationHash =
    "${currentHash}";
  export const expectedMigrationFingerprint =
    "1787741354171@${predecessorHash}:1787741355171@${currentHash}";
`;
  assert.deepEqual(parseMigrationManifest(source), {
    count: 2,
    createdAt: 1_787_741_355_171,
    fingerprint: `1787741354171@${predecessorHash}:1787741355171@${currentHash}`,
    hash: currentHash,
  });
  assert.throws(
    () => parseMigrationManifest(`${source}\n${source}`),
    /missing or ambiguous/,
  );
  assert.throws(
    () =>
      parseMigrationManifest(
        source.replace(
          "expectedMigrationCount = 2",
          "expectedMigrationCount = 0",
        ),
      ),
    /out of bounds/,
  );
  assert.throws(
    () =>
      parseMigrationManifest(source.replace(predecessorHash, "b".repeat(63))),
    /fingerprint is malformed/,
  );
});

test("enforces explicit concurrent load budgets", () => {
  assert.equal(
    assertLoadBudget(
      "concurrent_ingest",
      {
        operations: 160,
        successfulOperations: 160,
        distinctOperations: 160,
        wallMs: 4_000,
        maximumWorkerMs: 3_900,
      },
      {
        expectedOperations: 160,
        maxWallMs: 15_000,
        maxWorkerMs: 15_000,
        minOperationsPerSecond: 10,
      },
    ),
    40,
  );
  assert.throws(
    () =>
      assertLoadBudget(
        "concurrent_claim",
        {
          operations: 160,
          successfulOperations: 159,
          distinctOperations: 159,
          wallMs: 20_000,
          maximumWorkerMs: 20_000,
        },
        {
          expectedOperations: 160,
          maxWallMs: 15_000,
          maxWorkerMs: 15_000,
          minOperationsPerSecond: 10,
        },
      ),
    /successful operations 159.*wall time.*worker time.*throughput/s,
  );
  assert.throws(
    () =>
      assertLoadBudget(
        "concurrent_ingest",
        {
          operations: 160,
          successfulOperations: 80,
          distinctOperations: 80,
          wallMs: 20_000,
          maximumWorkerMs: 19_000,
        },
        {
          expectedOperations: 160,
          maxWallMs: 30_000,
          maxWorkerMs: 30_000,
          minOperationsPerSecond: 5,
        },
      ),
    /throughput 4\.00 is below 5/,
  );
  assert.throws(
    () =>
      assertLoadBudget(
        "concurrent_claim",
        {
          operations: 160,
          successfulOperations: 160,
          distinctOperations: 80,
          wallMs: 4_000,
          maximumWorkerMs: 3_900,
        },
        {
          expectedOperations: 160,
          maxWallMs: 15_000,
          maxWorkerMs: 15_000,
          minOperationsPerSecond: 30,
        },
      ),
    /distinct operations 80 differs from successful operations 160; throughput 20\.00 is below 30/,
  );
  assert.throws(
    () =>
      assertLoadBudget(
        "concurrent_claim",
        {
          operations: 1,
          successfulOperations: 1,
          distinctOperations: 1,
          wallMs: 1,
          maximumWorkerMs: 1,
        },
        {
          expectedOperations: 1.5,
          maxWallMs: 1,
          maxWorkerMs: 1,
          minOperationsPerSecond: 1,
        },
      ),
    /bounds are invalid/,
  );
  assert.throws(
    () =>
      assertLoadBudget(
        "concurrent_claim",
        {
          operations: 1,
          successfulOperations: 1,
          distinctOperations: 1,
          wallMs: 0,
          maximumWorkerMs: 0,
        },
        {
          expectedOperations: 1,
          maxWallMs: 1,
          maxWorkerMs: 1,
          minOperationsPerSecond: 1,
        },
      ),
    /counters are malformed/,
  );
});
