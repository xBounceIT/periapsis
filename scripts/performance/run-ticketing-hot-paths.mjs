import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { chmod, lstat, mkdir, open, readFile, unlink } from "node:fs/promises";
import { cpus, platform, release, totalmem } from "node:os";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import process from "node:process";
import { clearTimeout, setTimeout } from "node:timers";
import { fileURLToPath, URL } from "node:url";
import { performance } from "node:perf_hooks";

import {
  assertLoadBudget,
  assertPlanBudget,
  parseExplainJson,
  summarizePlan,
} from "./plan-budget.mjs";
import {
  terminateAndAwaitActiveChildren,
  trackChildUntilClose,
} from "./child-lifecycle.mjs";
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
  parseLocalAdminUrl,
  parseMigrationManifest,
  parseWindowsIdentitySid,
  passwordlessConnectionUrl,
  preflightPsqlExecutable,
  publishFileNoReplace,
  redactConnectionText,
  sanitizedPostgresEnvironment,
} from "./harness-safety.mjs";
import {
  credentialFromPreparationError,
  postgresCredentialDirectoryBasename,
  preparePostgresCredential,
  removePostgresCredential,
} from "./postgres-credential.mjs";
import {
  prepareSlaWorkerCredential,
  removeSlaWorkerCredential,
  slaWorkerCredentialFromPreparationError,
  slaWorkerCredentialDirectoryBasename,
} from "./sla-worker-credential.mjs";
import {
  assertSlaWorkerReport,
  parseSlaWorkerReport,
} from "./sla-worker-report.mjs";
import {
  activeProcessTreePids,
  preflightWindowsSystemTools,
  runTrackedCommand,
  terminateAndAwaitActiveProcessTrees,
  terminateActiveProcessTrees,
} from "./tracked-command.mjs";

const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const requireFromHarness = createRequire(import.meta.url);
const databasePackageDirectory = resolve(repositoryRoot, "packages/db");
const fixturePath = resolve(
  repositoryRoot,
  "tests/performance/ticketing-100k-fixture.sql",
);
const slaFixturePath = resolve(
  repositoryRoot,
  "tests/performance/sla-fixture.generated.json",
);
const evidenceDirectory = resolve(repositoryRoot, "tmp/performance");
const migrationManifestPath = resolve(
  repositoryRoot,
  "packages/db/src/admin/schema-compatibility-manifest.gen.ts",
);
const psql = preflightPsqlExecutable(
  process.env.PERIAPSIS_PERFORMANCE_PSQL ?? "",
);
const expectedClusterDataDirectory =
  process.env.PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY ?? "";
const maximumOutputBytes = 2 * 1024 * 1024;
const windowsSystemTools = preflightWindowsSystemTools();
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
let postgresCredentialEnvironment = {};
let slaWorkerCredential = null;
let slaWorkerExecutable;
const activePsqlChildren = new Set();
const shutdownHandlers = new Map();
const shutdownLatch = createShutdownLatch(() => {
  for (const child of activePsqlChildren) {
    child.kill();
  }
  terminateActiveProcessTrees();
});

for (const signal of catchableShutdownSignals()) {
  const handler = () => shutdownLatch.handle(signal);
  shutdownHandlers.set(signal, handler);
  process.on(signal, handler);
}

function assertShutdownWasNotRequested() {
  if (shutdownLatch.signal !== null) {
    throw new Error(
      `performance gate received ${shutdownLatch.signal}; cleanup is required`,
    );
  }
}

const planBudgets = Object.freeze({
  alert_updated_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_updated_idx"],
    forbiddenSequentialScans: ["alerts"],
  }),
  alert_created_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_created_idx"],
    forbiddenSequentialScans: ["alerts"],
  }),
  case_updated_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["cases_tenant_updated_idx"],
    forbiddenSequentialScans: ["cases"],
  }),
  alert_state_severity_page: Object.freeze({
    maxExecutionMs: 750,
    maxPlanningMs: 100,
    maxSharedBlocks: 30_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_state_priority_idx"],
    forbiddenSequentialScans: ["alerts"],
  }),
  alert_state_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexAlternatives: Object.freeze({
      relation: "alerts",
      indexes: Object.freeze([
        "alerts_tenant_created_idx",
        "alerts_tenant_state_priority_idx",
      ]),
    }),
    forbiddenSequentialScans: ["alerts"],
  }),
  alert_severity_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_created_idx"],
    forbiddenSequentialScans: ["alerts"],
  }),
  alert_assignee_page: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["alerts_tenant_assignment_idx"],
    forbiddenSequentialScans: ["alerts"],
  }),
  alert_custom_integer_filter: Object.freeze({
    maxExecutionMs: 1_000,
    maxPlanningMs: 100,
    maxSharedBlocks: 50_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["custom_field_values_definition_integer_idx"],
    forbiddenSequentialScans: ["alerts", "custom_field_values"],
  }),
  alert_sla_due_sort: Object.freeze({
    maxExecutionMs: 1_000,
    maxPlanningMs: 100,
    maxSharedBlocks: 60_000,
    maxTempBlocks: 0,
    minResultRows: 101,
    maxResultRows: 101,
    requiredIndexes: ["sla_materialized_projection_instant_sort_idx"],
    forbiddenSequentialScans: ["alerts", "sla_materialized_column_values"],
  }),
  sla_worker_claim_candidates: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 10_000,
    maxTempBlocks: 0,
    minResultRows: 100,
    maxResultRows: 100,
    requiredIndexes: ["sla_evaluation_jobs_claim_idx"],
    forbiddenSequentialScans: ["sla_evaluation_jobs"],
  }),
  notification_fanout_claim_candidates: Object.freeze({
    maxExecutionMs: 500,
    maxPlanningMs: 100,
    maxSharedBlocks: 20_000,
    maxTempBlocks: 0,
    minResultRows: 100,
    maxResultRows: 100,
    requiredIndexes: ["outbox_events_dequeue_idx"],
    forbiddenSequentialScans: ["outbox_events"],
  }),
});

const loadBudgets = Object.freeze({
  concurrent_ingest: Object.freeze({
    expectedOperations: 160,
    maxWallMs: 60_000,
    maxWorkerMs: 60_000,
    minOperationsPerSecond: 4,
  }),
  concurrent_claim: Object.freeze({
    expectedOperations: 160,
    maxWallMs: 60_000,
    maxWorkerMs: 60_000,
    minOperationsPerSecond: 4,
  }),
  sla_worker_claim: Object.freeze({
    expectedOperations: 400,
    maxWallMs: 30_000,
    maxWorkerMs: 30_000,
    minOperationsPerSecond: 10,
  }),
  notification_fanout_claim: Object.freeze({
    expectedOperations: 400,
    maxWallMs: 20_000,
    maxWorkerMs: 20_000,
    minOperationsPerSecond: 20,
  }),
});

function log(message) {
  process.stdout.write(`[performance] ${message}\n`);
}

function commandFailure(command, result, urls) {
  const detail = redactConnectionText(
    `${result.error?.message ?? ""}\n${result.stderr ?? ""}`,
    urls,
  )
    .trim()
    .slice(0, 8_192);
  const outcome = result.timedOut
    ? " timed out"
    : result.outputExceeded
      ? " exceeded the bounded output size"
      : result.status === null
        ? " failed or was terminated"
        : ` failed with exit ${result.status}`;
  return new Error(`${command}${outcome}${detail === "" ? "" : `: ${detail}`}`);
}

function runSync(
  command,
  args,
  { env = {}, timeout = 60_000, urls = [] } = {},
) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: sanitizedPostgresEnvironment(process.env, {
      ...postgresCredentialEnvironment,
      ...env,
    }),
    encoding: "utf8",
    maxBuffer: maximumOutputBytes,
    timeout,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw commandFailure(command, result, urls);
  }
  return String(result.stdout ?? "").trim();
}

async function restrictCredentialPath(path, isDirectory, windowsIdentitySid) {
  if (process.platform === "win32") {
    if (windowsSystemTools === null || typeof windowsIdentitySid !== "string") {
      throw new Error("Windows credential boundary was not preflighted");
    }
    runSync(
      windowsSystemTools.icacls,
      [
        path,
        "/inheritance:r",
        "/grant:r",
        `*${windowsIdentitySid}:${isDirectory ? "(OI)(CI)F" : "(F)"}`,
      ],
      { timeout: 10_000 },
    );
    return;
  }
  await chmod(path, isDirectory ? 0o700 : 0o600);
  const facts = await lstat(path);
  const forbiddenMode = isDirectory ? 0o077 : 0o177;
  if (
    !facts[isDirectory ? "isDirectory" : "isFile"]() ||
    (facts.mode & forbiddenMode) !== 0
  ) {
    throw new Error("temporary PostgreSQL credential permissions are unsafe");
  }
}

function psqlSync(connectionUrl, sql, options = {}) {
  const args = [
    "-X",
    "-qAt",
    "-v",
    "ON_ERROR_STOP=1",
    "-d",
    passwordlessConnectionUrl(connectionUrl),
  ];
  if (options.slaFixture !== undefined) {
    args.push("-v", `sla_fixture=${JSON.stringify(options.slaFixture)}`);
  }
  if (options.file) {
    args.push("-f", options.file);
  } else {
    args.push("-c", sql);
  }
  return runSync(psql, args, {
    timeout: options.timeout ?? 60_000,
    urls: options.urls,
    env: {
      PGAPPNAME: assertApplicationName(
        options.applicationName ?? "periapsis-performance-gate",
      ),
      PGCONNECT_TIMEOUT: "5",
    },
  });
}

async function runDatabaseScript(script, targetUrl, urls) {
  const scripts = new Map([
    [
      "db:migrate",
      Object.freeze({
        entrypoint: resolve(databasePackageDirectory, "src/admin/migrate.ts"),
        timeoutMs: 10 * 60_000,
      }),
    ],
    [
      "db:seed",
      Object.freeze({
        entrypoint: resolve(databasePackageDirectory, "seeds/seed.ts"),
        timeoutMs: 2 * 60_000,
      }),
    ],
  ]);
  const definition = scripts.get(script);
  if (definition === undefined) {
    throw new TypeError("database performance script is not allowlisted");
  }
  const env = sanitizedPostgresEnvironment(process.env, {
    ...postgresCredentialEnvironment,
    DATABASE_URL: targetUrl,
  });
  const command = process.execPath;
  const args = [
    requireFromHarness.resolve("tsx/cli", {
      paths: [databasePackageDirectory],
    }),
    definition.entrypoint,
  ];
  const result = await runTrackedCommand(command, args, {
    cwd: databasePackageDirectory,
    env,
    maxOutputBytes: maximumOutputBytes,
    timeoutMs: definition.timeoutMs,
    windowsTaskkillPath: windowsSystemTools?.taskkill,
  });
  if (
    result.error ||
    result.status !== 0 ||
    result.outputExceeded ||
    result.timedOut
  ) {
    throw commandFailure(command, result, urls);
  }
  return result.stdout.trim();
}

async function runSlaWorker(mode, reports, label) {
  assertShutdownWasNotRequested();
  const timeoutMs =
    mode === "ingress" ? 30 * 60_000 : loadBudgets.sla_worker_claim.maxWorkerMs;
  const args = [
    "--mode",
    mode,
    "--timeout",
    `${timeoutMs}ms`,
    "--max-events",
    mode === "ingress" ? "500000" : "100",
  ];
  if (mode === "timers") args.push("--max-batches", "1");
  const started = performance.now();
  const result = await runTrackedCommand(slaWorkerExecutable, args, {
    cwd: repositoryRoot,
    env: sanitizedPostgresEnvironment(process.env, {
      PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE: slaWorkerCredential.file,
      PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY:
        expectedClusterDataDirectory,
    }),
    maxOutputBytes: 64 * 1024,
    timeoutMs: timeoutMs + 5_000,
    windowsTaskkillPath: windowsSystemTools?.taskkill,
  });
  // No raw child stdout/stderr is retained: only the bounded redacted protocol.
  let report;
  try {
    report = parseSlaWorkerReport(result.stdout, mode);
  } catch {
    reports[label] = { status: "failed", errorCode: "invalid_worker_report" };
    throw new Error("SLA worker did not return a valid report");
  }
  report.wallMs = performance.now() - started;
  reports[label] = report;
  if (
    result.error ||
    result.status !== 0 ||
    result.outputExceeded ||
    result.timedOut
  ) {
    throw new Error("SLA worker process failed");
  }
  assertSlaWorkerReport(report, mode);
  return report;
}

function runPsql(connectionUrl, sql, { timeoutMs = 60_000, urls = [] } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new TypeError("psql timeout is invalid");
  }
  assertShutdownWasNotRequested();
  return (async () => {
    const args = [
      "-X",
      "-qAt",
      "-v",
      "ON_ERROR_STOP=1",
      "-v",
      "VERBOSITY=verbose",
      "-d",
      passwordlessConnectionUrl(connectionUrl),
      "-c",
      sql,
    ];
    const started = performance.now();
    const child = spawn(psql, args, {
      cwd: repositoryRoot,
      env: {
        ...sanitizedPostgresEnvironment(
          process.env,
          postgresCredentialEnvironment,
        ),
        PGAPPNAME: "periapsis-performance-gate",
        PGCONNECT_TIMEOUT: "5",
      },
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const childClosed = trackChildUntilClose(child, activePsqlChildren);
    let stdout = "";
    let stderr = "";
    let exceeded = false;
    let terminationError = null;
    let timedOut = false;
    const requestTermination = () => {
      try {
        if (!child.kill()) {
          terminationError ??= new Error("psql termination request failed");
        }
      } catch (error) {
        terminationError ??=
          error instanceof Error
            ? error
            : new Error("psql termination request failed");
      }
    };
    const append = (current, chunk) => {
      const next = current + chunk.toString("utf8");
      if (Buffer.byteLength(next) > maximumOutputBytes) {
        exceeded = true;
        requestTermination();
        return current;
      }
      return next;
    };
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      requestTermination();
    }, timeoutMs);
    let closeDeadline;
    let outcome;
    try {
      outcome = await Promise.race([
        childClosed,
        new Promise((_, rejectPromise) => {
          closeDeadline = setTimeout(
            () =>
              rejectPromise(new Error("psql did not quiesce after timeout")),
            timeoutMs + 10_000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timeout);
      clearTimeout(closeDeadline);
    }
    const durationMs = performance.now() - started;
    if (outcome.error) {
      throw new Error(
        redactConnectionText(
          `psql process failed: ${outcome.error.message}`,
          urls,
        ),
      );
    }
    if (exceeded) {
      throw new Error("psql output exceeded the bounded capture size");
    }
    if (timedOut) {
      throw new Error("psql exceeded its bounded execution time");
    }
    if (terminationError) {
      throw new Error(
        redactConnectionText(
          `psql termination failed: ${terminationError.message}`,
          urls,
        ),
      );
    }
    if (outcome.status !== 0) {
      throw commandFailure(
        psql,
        { error: undefined, status: outcome.status, stderr },
        urls,
      );
    }
    return { durationMs, stderr, stdout: stdout.trim() };
  })();
}

function quoteIdentifier(value) {
  assertDisposableDatabaseName(value);
  return `"${value}"`;
}

function databaseNameLiteral(value) {
  assertDisposableDatabaseName(value);
  return `'${value}'`;
}

function uuidLiteral(value, label) {
  if (typeof value !== "string" || !uuidV7Pattern.test(value)) {
    throw new TypeError(`${label} is not a UUIDv7`);
  }
  return `'${value}'::uuid`;
}

function uuidArrayLiteral(values, label) {
  if (!Array.isArray(values) || values.length === 0 || values.length > 1_000) {
    throw new TypeError(`${label} UUID list is malformed`);
  }
  return `ARRAY[${values
    .map((value, index) => uuidLiteral(value, `${label}[${index}]`))
    .join(",")}]::uuid[]`;
}

function workflowStateLiteral(value) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_]{2,63}$/.test(value)) {
    throw new TypeError("claim race workflow state is malformed");
  }
  return `'${value}'`;
}

function timestampLiteral(value, label) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new TypeError(`${label} is not a canonical timestamp`);
  }
  return `TIMESTAMPTZ '${value}'`;
}

function assertApplicationName(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(value)) {
    throw new TypeError("performance application name is malformed");
  }
  return value;
}

function applicationNameLiteral(value) {
  return `'${assertApplicationName(value)}'`;
}

function parseSingleInteger(output, label) {
  if (!/^[0-9]+$/.test(output)) {
    throw new Error(`${label} returned a malformed operation count`);
  }
  const value = Number(output);
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} returned an unbounded operation count`);
  }
  return value;
}

function quiesceOwnedBackend(adminUrl, applicationName, urls) {
  const name = assertApplicationName(applicationName);
  const termination = JSON.parse(
    psqlSync(
      adminUrl,
      `WITH matching AS MATERIALIZED (
         SELECT activity.pid
         FROM pg_catalog.pg_stat_activity AS activity
         WHERE activity.datname = current_database()
           AND activity.application_name = ${applicationNameLiteral(name)}
           AND activity.backend_type = 'client backend'
           AND activity.pid <> pg_backend_pid()
       ), terminated AS MATERIALIZED (
         SELECT matching.pid, pg_terminate_backend(matching.pid, 5000) AS terminated
         FROM matching
       )
       SELECT jsonb_build_object(
         'matched', count(*)::integer,
         'terminated', count(*) FILTER (WHERE terminated)::integer
       )::text
       FROM terminated`,
      {
        applicationName: "periapsis-cleanup-observer",
        timeout: 15_000,
        urls,
      },
    ),
  );
  const remaining = parseSingleInteger(
    psqlSync(
      adminUrl,
      `SELECT count(*)
       FROM pg_catalog.pg_stat_activity AS activity
       WHERE activity.datname = current_database()
         AND activity.application_name = ${applicationNameLiteral(name)}
         AND activity.backend_type = 'client backend'
         AND activity.pid <> pg_backend_pid()`,
      {
        applicationName: "periapsis-cleanup-observer",
        timeout: 15_000,
        urls,
      },
    ),
    "owned PostgreSQL backend settlement",
  );
  return assertOwnedBackendSettlement({ ...termination, remaining });
}

function disposableDatabaseCount(adminUrl, databaseName, urls) {
  const count = parseSingleInteger(
    psqlSync(
      adminUrl,
      `SELECT count(*) FROM pg_catalog.pg_database
       WHERE datname = ${databaseNameLiteral(databaseName)}`,
      {
        applicationName: "periapsis-cleanup-observer",
        timeout: 30_000,
        urls,
      },
    ),
    "performance cleanup probe",
  );
  if (count > 1) {
    throw new Error("performance cleanup database probe is impossible");
  }
  return count;
}

function cleanupDisposableDatabase({
  adminUrl,
  createApplicationName,
  databaseName,
  dropApplicationNames,
  urls,
}) {
  const backendSettlements = [
    {
      application: "create",
      ...quiesceOwnedBackend(adminUrl, createApplicationName, urls),
    },
  ];
  let databaseCount = disposableDatabaseCount(adminUrl, databaseName, urls);
  const dropFailures = [];
  let dropAttempts = 0;
  for (const applicationName of dropApplicationNames) {
    if (databaseCount === 0) {
      break;
    }
    dropAttempts += 1;
    try {
      psqlSync(
        adminUrl,
        `DROP DATABASE ${quoteIdentifier(databaseName)} WITH (FORCE)`,
        { applicationName, timeout: 30_000, urls },
      );
    } catch (error) {
      dropFailures.push(error);
    }
    backendSettlements.push({
      application: `drop_${dropAttempts}`,
      ...quiesceOwnedBackend(adminUrl, applicationName, urls),
    });
    databaseCount = disposableDatabaseCount(adminUrl, databaseName, urls);
  }
  const finalDatabaseCount = disposableDatabaseCount(
    adminUrl,
    databaseName,
    urls,
  );
  if (finalDatabaseCount !== 0) {
    throw new Error("disposable performance database survived cleanup");
  }
  const cleanupEvidence = Object.freeze({
    backendSettlements: Object.freeze(backendSettlements),
    dropAttempts,
    finalDatabaseCount,
    status:
      dropFailures.length > 0
        ? "recovered_failed"
        : dropAttempts === 0
          ? "not_created"
          : "dropped",
  });
  if (dropFailures.length > 0) {
    throw createRecoveredCleanupError(dropFailures, cleanupEvidence);
  }
  return cleanupEvidence;
}

function parseWorkerIds(output, label, expectedCount) {
  let value;
  try {
    value = JSON.parse(output);
  } catch (error) {
    throw new Error(`${label} returned malformed JSON`, { cause: error });
  }
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.hasOwn(value, "ids") ||
    !Array.isArray(value.ids) ||
    value.ids.length !== expectedCount
  ) {
    throw new Error(`${label} returned an unexpected operation receipt`);
  }
  for (const id of value.ids) {
    if (typeof id !== "string" || !uuidV7Pattern.test(id)) {
      throw new Error(`${label} returned a malformed operation identifier`);
    }
  }
  if (new Set(value.ids).size !== value.ids.length) {
    throw new Error(`${label} returned duplicate operation identifiers`);
  }
  return Object.freeze([...value.ids]);
}

function operationIdDigest(ids) {
  return createHash("sha256")
    .update(ids.toSorted().join("\n"), "utf8")
    .digest("hex");
}

function parseCommittedPostcondition(output, label, expectedCount) {
  let value;
  try {
    value = JSON.parse(output);
  } catch (error) {
    throw new Error(`${label} committed postcondition is malformed`, {
      cause: error,
    });
  }
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).toSorted().join(",") !== "committed,total" ||
    value.total !== expectedCount ||
    value.committed !== expectedCount
  ) {
    throw new Error(`${label} committed postcondition failed`);
  }
  return Object.freeze({ committed: value.committed, total: value.total });
}

function parseFacts(output, migrationPin) {
  let value;
  try {
    value = JSON.parse(output);
  } catch (error) {
    throw new Error("performance fixture facts are malformed", {
      cause: error,
    });
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("performance fixture facts are not an object");
  }
  for (const key of [
    "tenantId",
    "adminUserId",
    "analystUserId",
    "teamId",
    "assignmentEpochId",
    "workflowId",
    "customDefinitionId",
    "slaColumnId",
  ]) {
    uuidLiteral(value[key], key);
  }
  workflowStateLiteral(value.initialState);
  workflowStateLiteral(value.activeState);
  if (
    value.activeState === value.initialState ||
    value.activeStateCount !== 1_000 ||
    value.activeCriticalCount !== 200 ||
    value.creationBatchCount !== 100 ||
    value.alertCount !== 100_000 ||
    value.caseCount !== 100_000 ||
    value.customValueCount !== 100_000 ||
    value.customMatchCount !== 1_000 ||
    value.slaValueCount !== 99_999 ||
    value.slaInstanceCount !== 99_999 ||
    value.slaCompletedMetricCount !== 1_000 ||
    value.slaRunningMetricCount !== 98_999 ||
    !Number.isSafeInteger(value.slaJobCount) ||
    value.slaJobCount < 98_999 ||
    value.slaPendingIngressCount !== 0 ||
    value.notificationEventCount !== 10_000 ||
    value.migrationCount !== migrationPin.count ||
    value.latestMigrationId !== migrationPin.count ||
    value.latestMigrationCreatedAt !== migrationPin.createdAt ||
    value.latestMigrationHash !== migrationPin.hash ||
    value.migrationFingerprint !== migrationPin.fingerprint
  ) {
    throw new Error(
      "performance fixture cardinality or migration journal drifted",
    );
  }
  if (
    !Number.isSafeInteger(value.latestMigrationId) ||
    value.latestMigrationId < 1 ||
    !Number.isSafeInteger(value.latestMigrationCreatedAt) ||
    value.latestMigrationCreatedAt < 1 ||
    value.databaseCollation !== "C" ||
    value.databaseCType !== "C" ||
    value.databaseTimezone !== "UTC"
  ) {
    throw new Error("performance database provenance drifted");
  }
  if (
    typeof value.latestMigrationHash !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.latestMigrationHash)
  ) {
    throw new Error("performance migration hash is malformed");
  }
  assertPostgresVersion(value.serverVersionNumber, value.serverVersion);
  return Object.freeze(value);
}

function apiPlanSql(facts, query) {
  return `
BEGIN;
SET LOCAL ROLE periapsis_api;
SET LOCAL row_security = on;
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';
SET LOCAL work_mem = '16MB';
SET LOCAL jit = off;
SET LOCAL max_parallel_workers_per_gather = 0;
SET LOCAL app.tenant_id = '${facts.tenantId}';
SET LOCAL app.user_id = '${facts.adminUserId}';
SET LOCAL app.service_account_id = '';
EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS, SUMMARY, FORMAT JSON)
${query};
ROLLBACK;`;
}

function runtimeOwnerPlanSql(role, query) {
  if (
    !new Set([
      "periapsis_sla_worker_owner",
      "periapsis_notification_dispatch_owner",
    ]).has(role)
  ) {
    throw new TypeError("performance runtime owner role is invalid");
  }
  return `
BEGIN;
SET LOCAL ROLE ${role};
SET LOCAL row_security = on;
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';
SET LOCAL work_mem = '16MB';
SET LOCAL jit = off;
SET LOCAL max_parallel_workers_per_gather = 0;
EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS, SUMMARY, FORMAT JSON)
${query};
ROLLBACK;`;
}

function alertProjection(facts, joins = "") {
  if (typeof joins !== "string") {
    throw new TypeError("Alert projection joins are malformed");
  }
  return `
SELECT ticket.*, workflow_version.states, workflow_version.transitions,
       creator_user.display_name AS creator_name,
       creator_service.display_name AS creator_service_name
FROM public.alerts AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'alert'
 AND workflow_version.version = ticket.workflow_version
LEFT JOIN public.users AS creator_user ON creator_user.id = ticket.created_by
LEFT JOIN app.ticket_service_account_attributions_v1 AS creator_service
  ON creator_service.tenant_id = ticket.tenant_id
 AND creator_service.id = ticket.created_by_service_account_id
${joins}
WHERE ticket.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}`;
}

function caseProjection(facts) {
  return `
SELECT ticket.*, workflow_version.states, workflow_version.transitions,
       creator_user.display_name AS creator_name
FROM public.cases AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'case'
 AND workflow_version.version = ticket.workflow_version
JOIN public.users AS creator_user ON creator_user.id = ticket.created_by_user_id
WHERE ticket.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}`;
}

function planQueries(facts, observedAt) {
  const observedAtLiteral = timestampLiteral(observedAt, "plan observation");
  const base = alertProjection(facts);
  return [
    {
      name: "alert_updated_page",
      sql: apiPlanSql(
        facts,
        `${base}\nORDER BY ticket.updated_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_created_page",
      sql: apiPlanSql(
        facts,
        `${base}\nORDER BY ticket.created_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "case_updated_page",
      sql: apiPlanSql(
        facts,
        `${caseProjection(facts)}\nORDER BY ticket.updated_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_state_severity_page",
      sql: apiPlanSql(
        facts,
        `${base}\n  AND ticket.state_key = ANY(ARRAY[${workflowStateLiteral(facts.activeState)}]::text[])\n  AND ticket.severity::text = ANY(ARRAY['critical']::text[])\nORDER BY ticket.updated_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_state_page",
      sql: apiPlanSql(
        facts,
        `${base}\n  AND ticket.state_key = ANY(ARRAY[${workflowStateLiteral(facts.activeState)}]::text[])\nORDER BY ticket.created_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_severity_page",
      sql: apiPlanSql(
        facts,
        `${base}\n  AND ticket.severity::text = ANY(ARRAY['critical']::text[])\nORDER BY ticket.created_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_assignee_page",
      sql: apiPlanSql(
        facts,
        `${base}\n  AND ticket.assigned_team_id = ${uuidLiteral(facts.teamId, "teamId")}\n  AND ticket.assignee_user_id = ${uuidLiteral(facts.analystUserId, "analystUserId")}\nORDER BY ticket.updated_at DESC, ticket.id DESC\nLIMIT 101`,
      ),
    },
    {
      name: "alert_custom_integer_filter",
      sql: apiPlanSql(
        facts,
        `${base}
  AND EXISTS (
    SELECT 1
    FROM public.custom_field_values AS filtered
    WHERE filtered.tenant_id = ticket.tenant_id
      AND filtered.object_type = 'alert'
      AND filtered.alert_id = ticket.id
      AND filtered.definition_id = ${uuidLiteral(facts.customDefinitionId, "customDefinitionId")}
      AND filtered.definition_schema_version = 1
      AND filtered.data_type = 'integer'
      AND filtered.presence = 'present'
      AND filtered.integer_value = 42
      AND filtered.canonical_value = '42'::jsonb
  )
ORDER BY ticket.created_at DESC, ticket.id DESC
LIMIT 101`,
      ),
    },
    {
      name: "alert_sla_due_sort",
      sql: apiPlanSql(
        facts,
        `${alertProjection(
          facts,
          `LEFT JOIN app.ticket_sla_instant_sort_values_v1 AS saved_view_sort
  ON saved_view_sort.tenant_id = ticket.tenant_id
 AND saved_view_sort.object_type = 'alert'
 AND saved_view_sort.object_id = ticket.id
 AND saved_view_sort.column_id = ${uuidLiteral(facts.slaColumnId, "slaColumnId")}
 AND saved_view_sort.column_version = 1`,
        )}
ORDER BY saved_view_sort.instant_value DESC NULLS LAST, ticket.id DESC
LIMIT 101`,
      ),
    },
    {
      name: "sla_worker_claim_candidates",
      sql: runtimeOwnerPlanSql(
        "periapsis_sla_worker_owner",
        `SELECT job.tenant_id, job.id
FROM public.sla_evaluation_jobs AS job
JOIN public.sla_instances AS instance
  ON instance.tenant_id = job.tenant_id
 AND instance.id = job.sla_instance_id
WHERE job.attempt < job.maximum_attempts
  AND (
    job.status IN ('queued', 'retry_scheduled')
      AND job.available_at <= ${observedAtLiteral}
    OR job.status = 'leased'
      AND job.lease_expires_at <= ${observedAtLiteral}
  )
  AND NOT EXISTS (
    SELECT 1
    FROM public.sla_object_event_ingress AS ingress
    WHERE ingress.tenant_id = instance.tenant_id
      AND ingress.object_type = instance.object_type
      AND ingress.object_id = instance.object_id
      AND ingress.status <> 'completed'
  )
ORDER BY coalesce(job.lease_expires_at, job.available_at), job.tenant_id, job.id
FOR UPDATE OF job SKIP LOCKED
LIMIT 100`,
      ),
    },
    {
      name: "notification_fanout_claim_candidates",
      sql: runtimeOwnerPlanSql(
        "periapsis_notification_dispatch_owner",
        `SELECT event.id
FROM public.outbox_events AS event
WHERE event.event_type LIKE 'notification.%'
  AND event.schema_version = 2
  AND event.processed_at IS NULL
  AND event.dead_lettered_at IS NULL
  AND event.available_at <= ${observedAtLiteral}
  AND event.attempts < event.max_attempts
  AND (event.lease_until IS NULL OR event.lease_until <= ${observedAtLiteral})
ORDER BY event.available_at, event.occurred_at, event.id
FOR UPDATE SKIP LOCKED
LIMIT 100`,
      ),
    },
  ];
}

function apiSlaProjectionCardinalitySql(facts) {
  return `
BEGIN;
SET LOCAL ROLE periapsis_api;
SET LOCAL row_security = on;
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';
SET LOCAL app.tenant_id = '${facts.tenantId}';
SET LOCAL app.user_id = '${facts.adminUserId}';
SET LOCAL app.service_account_id = '';
SELECT count(*)
FROM app.ticket_sla_instant_sort_values_v1 AS projected
WHERE projected.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
  AND projected.object_type = 'alert'
  AND projected.column_id = ${uuidLiteral(facts.slaColumnId, "slaColumnId")}
  AND projected.column_version = 1
  AND projected.instant_value IS NOT NULL;
ROLLBACK;`;
}

async function measurePlans(targetUrl, facts, urls, evidence) {
  const observedAt = new Date().toISOString();
  evidence.planObservedAt = observedAt;
  const apiSlaProjectionValues = parseSingleInteger(
    psqlSync(targetUrl, apiSlaProjectionCardinalitySql(facts), {
      timeout: 60_000,
      urls,
    }),
    "API SLA projection cardinality",
  );
  if (apiSlaProjectionValues !== 99_999) {
    throw new Error(
      `API SLA projection cardinality ${apiSlaProjectionValues} differs from 100000`,
    );
  }
  evidence.dataset.apiSlaProjectionValues = apiSlaProjectionValues;
  for (const gate of planQueries(facts, observedAt)) {
    assertShutdownWasNotRequested();
    log(`warming ${gate.name}`);
    psqlSync(targetUrl, gate.sql, { timeout: 60_000, urls });
    log(`measuring ${gate.name}`);
    const raw = psqlSync(targetUrl, gate.sql, { timeout: 60_000, urls });
    assertShutdownWasNotRequested();
    const explain = parseExplainJson(raw);
    const summary = summarizePlan(explain);
    evidence.plans[gate.name] = {
      budget: planBudgets[gate.name],
      explain,
      summary,
      status: "measured",
    };
    assertPlanBudget(gate.name, summary, planBudgets[gate.name]);
    evidence.plans[gate.name].status = "passed";
  }
}

function humanContext(facts) {
  return `
BEGIN;
SET LOCAL ROLE periapsis_api;
SET LOCAL row_security = on;
SET LOCAL statement_timeout = '55s';
SET LOCAL lock_timeout = '45s';
SET LOCAL app.tenant_id = '${facts.tenantId}';
SET LOCAL app.user_id = '${facts.adminUserId}';
SET LOCAL app.service_account_id = '';`;
}

function ingestSql(facts, worker, perWorker) {
  const start = worker * perWorker + 1;
  const end = start + perWorker - 1;
  return `${humanContext(facts)}
SELECT jsonb_build_object(
  'ids', coalesce(jsonb_agg(created.id ORDER BY created.id), '[]'::jsonb)
)::text
FROM generate_series(${start}, ${end}) AS input(sequence)
CROSS JOIN LATERAL app.create_tenant_alert_as_human_v3(
  'Concurrent performance ingest ' || input.sequence,
  'Synthetic non-sensitive performance payload.',
  'performance-ingest-' || input.sequence,
  'medium', 'performance_harness', 'performance',
  'performance-ingest-' || input.sequence,
  '{}'::jsonb, 'medium', 'performance', NULL, transaction_timestamp(),
  false, ARRAY['performance']::text[], '{}'::jsonb,
  NULL, NULL, NULL,
  sha256(convert_to('performance-ingest-key-' || input.sequence, 'UTF8')),
  sha256(convert_to('performance-ingest-request-' || input.sequence, 'UTF8')),
  uuidv7(), uuidv7(), '192.0.2.10'::inet,
  'Periapsis performance harness', 'totp', NULL, NULL
) AS created;
COMMIT;`;
}

function claimBatchSql(facts, worker, workerCount, perWorker) {
  return `${humanContext(facts)}
WITH candidates AS MATERIALIZED (
  SELECT ticket.*
  FROM public.alerts AS ticket
  WHERE ticket.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
    AND ticket.external_id ~ '^performance-alert-[0-9]{6}$'
    AND ticket.assigned_team_id IS NOT NULL
    AND ticket.claimed_by_user_id IS NULL
    AND ticket.version = 1
    AND ((right(ticket.external_id, 6)::integer / 10) - 1) % ${workerCount} = ${worker}
  ORDER BY ticket.external_id
  LIMIT ${perWorker}
)
SELECT jsonb_build_object(
  'ids', coalesce(jsonb_agg(ticket.id ORDER BY ticket.id), '[]'::jsonb)
)::text
FROM candidates AS ticket
CROSS JOIN LATERAL app.apply_tenant_ticket_mutation_v2(
  'alert', ticket.id, 'claim', 1, 2,
  ticket.workflow_id, ticket.workflow_version,
  ticket.state_key, ticket.state_key, NULL,
  ticket.customer_visible, ticket.assigned_team_id,
  ${uuidLiteral(facts.adminUserId, "adminUserId")},
  ${uuidLiteral(facts.adminUserId, "adminUserId")},
  'Synthetic concurrent claim performance proof.',
  NULL, NULL, '{}'::jsonb, NULL, NULL,
  uuidv7(), uuidv7(), '192.0.2.11'::inet,
  'Periapsis performance harness', 'totp'
) AS claimed;
COMMIT;`;
}

function verifyIngestCommitted(targetUrl, facts, ids, urls) {
  const expectedCount = ids.length;
  return parseCommittedPostcondition(
    psqlSync(
      targetUrl,
      `SELECT jsonb_build_object(
         'total', count(*)::integer,
         'committed', count(*) FILTER (
           WHERE alert.version = 1
             AND alert.external_id ~ '^performance-ingest-[0-9]+$'
             AND alert.created_by = ${uuidLiteral(facts.adminUserId, "adminUserId")}
             AND alert.created_by_membership_id IS NOT NULL
             AND alert.created_by_service_account_id IS NULL
         )::integer
       )::text
       FROM public.alerts AS alert
       WHERE alert.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
         AND alert.id = ANY(${uuidArrayLiteral(ids, "ingested alerts")})`,
      { urls },
    ),
    "concurrent ingest",
    expectedCount,
  );
}

function verifyClaimsCommitted(targetUrl, facts, ids, urls) {
  const expectedCount = ids.length;
  return parseCommittedPostcondition(
    psqlSync(
      targetUrl,
      `SELECT jsonb_build_object(
         'total', count(*)::integer,
         'committed', count(*) FILTER (
           WHERE alert.version = 2
             AND alert.assignee_user_id = ${uuidLiteral(facts.adminUserId, "adminUserId")}
             AND alert.claimed_by_user_id = ${uuidLiteral(facts.adminUserId, "adminUserId")}
             AND alert.claimed_at IS NOT NULL
         )::integer
       )::text
       FROM public.alerts AS alert
       WHERE alert.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
         AND alert.id = ANY(${uuidArrayLiteral(ids, "claimed alerts")})`,
      { urls },
    ),
    "concurrent claims",
    expectedCount,
  );
}

function timerProgress(targetUrl, urls) {
  const result = JSON.parse(
    psqlSync(
      targetUrl,
      `SELECT jsonb_build_object(
    'completed', (SELECT count(*)::integer FROM public.sla_evaluation_jobs WHERE status = 'completed'),
    'unsettled', (SELECT count(*)::integer FROM public.sla_evaluation_jobs
      WHERE status IN ('leased', 'retry_scheduled', 'dead_lettered')),
    'aggregateVersions', (SELECT coalesce(sum(aggregate_version), 0)::bigint FROM public.sla_instances)
  )::text`,
      { urls },
    ),
  );
  if (
    ["completed", "unsettled", "aggregateVersions"].some(
      (key) => !Number.isSafeInteger(result[key]) || result[key] < 0,
    )
  ) {
    throw new Error("SLA timer progress is malformed");
  }
  return result;
}

async function measureSlaTimers(targetUrl, urls, evidence) {
  const name = "sla_worker_claim";
  const budget = loadBudgets[name];
  const before = timerProgress(targetUrl, urls);
  if (before.unsettled !== 0) throw new Error("SLA timer queue is not clean");
  const result = { status: "running", budget, workers: {}, before };
  evidence.loads[name] = result;
  const started = performance.now();
  const settled = await Promise.allSettled(
    Array.from({ length: 4 }, (_, worker) =>
      runSlaWorker("timers", result.workers, String(worker)),
    ),
  );
  result.wallMs = performance.now() - started;
  result.after = timerProgress(targetUrl, urls);
  if (settled.some((worker) => worker.status !== "fulfilled")) {
    result.status = "failed";
    throw new Error("Concurrent SLA timer processing failed");
  }
  const reports = settled.map((worker) => worker.value);
  const summary = {
    operations: 400,
    successfulOperations: reports.reduce(
      (sum, report) => sum + report.completed,
      0,
    ),
    distinctOperations: result.after.completed - before.completed,
    wallMs: result.wallMs,
    maximumWorkerMs: Math.max(...reports.map((report) => report.wallMs)),
  };
  Object.assign(result, summary);
  try {
    if (
      result.after.unsettled !== 0 ||
      result.after.aggregateVersions <= before.aggregateVersions
    ) {
      throw new Error("SLA timers did not commit real aggregate progress");
    }
    result.operationsPerSecond = assertLoadBudget(name, summary, budget);
    result.committedPostcondition = {
      completedJobs: summary.distinctOperations,
      aggregateVersionIncrements:
        result.after.aggregateVersions - before.aggregateVersions,
      unsettledJobs: result.after.unsettled,
    };
    result.status = "passed";
  } catch (error) {
    result.status = "failed";
    throw error;
  }
}

function verifyNotificationClaimsCommitted(targetUrl, ids, urls) {
  const expectedCount = ids.length;
  return parseCommittedPostcondition(
    psqlSync(
      targetUrl,
      `SELECT jsonb_build_object(
         'total', count(*)::integer,
         'committed', count(*) FILTER (
           WHERE event.processed_at IS NULL
             AND event.dead_lettered_at IS NULL
             AND event.attempts = 1
             AND event.locked_at IS NOT NULL
             AND event.locked_by IS NOT NULL
             AND event.lease_token IS NOT NULL
             AND event.lease_until > clock_timestamp()
         )::integer
       )::text
       FROM public.outbox_events AS event
       WHERE event.id = ANY(${uuidArrayLiteral(ids, "claimed notification events")})`,
      { urls },
    ),
    "notification fanout claims",
    expectedCount,
  );
}

async function measureConcurrentSql({
  name,
  sqlStatements,
  expectedPerWorker,
  evidence,
  targetUrl,
  urls,
  verifyCommitted,
}) {
  const started = performance.now();
  const budget = loadBudgets[name];
  const settledWorkers = await Promise.allSettled(
    sqlStatements.map((sql) =>
      runPsql(targetUrl, sql, { timeoutMs: budget.maxWorkerMs, urls }),
    ),
  );
  const wallMs = performance.now() - started;
  const returnedIds = [];
  const workers = settledWorkers.map((settled, worker) => {
    if (settled.status === "rejected") {
      return {
        worker,
        status: "failed",
        durationMs: null,
        error: redactConnectionText(
          settled.reason?.message ?? settled.reason,
          urls,
        ).slice(0, 2_048),
      };
    }
    try {
      const ids = parseWorkerIds(
        settled.value.stdout,
        `${name} worker ${worker}`,
        expectedPerWorker,
      );
      returnedIds.push(...ids);
      return {
        worker,
        status: "completed",
        durationMs: settled.value.durationMs,
        returnedOperations: ids.length,
        receiptDigest: operationIdDigest(ids),
      };
    } catch (error) {
      return {
        worker,
        status: "failed",
        durationMs: settled.value.durationMs,
        error: String(error?.message ?? error).slice(0, 2_048),
      };
    }
  });
  const successfulOperations = returnedIds.length;
  const distinctOperations = new Set(returnedIds).size;
  const measuredWorkerDurations = workers
    .map((worker) => worker.durationMs)
    .filter((duration) => Number.isFinite(duration));
  const summary = {
    operations: sqlStatements.length * expectedPerWorker,
    successfulOperations,
    distinctOperations,
    duplicateOperations: successfulOperations - distinctOperations,
    wallMs,
    maximumWorkerMs:
      measuredWorkerDurations.length === 0
        ? wallMs
        : Math.max(...measuredWorkerDurations),
    workerCount: workers.length,
  };
  const result = {
    ...summary,
    budget,
    operationsPerSecond:
      wallMs > 0 ? (distinctOperations * 1000) / wallMs : null,
    receiptDigest:
      returnedIds.length === 0 ? null : operationIdDigest(returnedIds),
    workers,
    status: "measured",
  };
  evidence[name] = result;
  try {
    result.operationsPerSecond = assertLoadBudget(name, summary, budget);
    if (typeof verifyCommitted !== "function") {
      throw new TypeError(`${name} committed-state verifier is required`);
    }
    result.committedPostcondition = verifyCommitted(returnedIds);
    result.status = "passed";
    return result;
  } catch (error) {
    result.status = "failed";
    throw error;
  }
}

async function measureLoads(targetUrl, facts, urls, evidence, databaseName) {
  assertDisposableDatabaseName(databaseName);
  assertShutdownWasNotRequested();
  const concurrency = 8;
  const operationsPerWorker = 20;
  log("running concurrent Alert ingest");
  evidence.loads.concurrent_ingest = await measureConcurrentSql({
    name: "concurrent_ingest",
    sqlStatements: Array.from({ length: concurrency }, (_, worker) =>
      ingestSql(facts, worker, operationsPerWorker),
    ),
    expectedPerWorker: operationsPerWorker,
    evidence: evidence.loads,
    targetUrl,
    urls,
    verifyCommitted: (ids) =>
      verifyIngestCommitted(targetUrl, facts, ids, urls),
  });

  log("running independent concurrent ticket claims");
  evidence.loads.concurrent_claim = await measureConcurrentSql({
    name: "concurrent_claim",
    sqlStatements: Array.from({ length: concurrency }, (_, worker) =>
      claimBatchSql(facts, worker, concurrency, operationsPerWorker),
    ),
    expectedPerWorker: operationsPerWorker,
    evidence: evidence.loads,
    targetUrl,
    urls,
    verifyCommitted: (ids) =>
      verifyClaimsCommitted(targetUrl, facts, ids, urls),
  });

  const raceTarget = JSON.parse(
    psqlSync(
      targetUrl,
      `SELECT jsonb_build_object(
         'id', ticket.id, 'workflowId', ticket.workflow_id,
         'workflowVersion', ticket.workflow_version,
         'stateKey', ticket.state_key, 'teamId', ticket.assigned_team_id,
         'customerVisible', ticket.customer_visible
       )::text
       FROM public.alerts AS ticket
       WHERE ticket.tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
         AND ticket.external_id ~ '^performance-alert-[0-9]{6}$'
         AND ticket.assigned_team_id IS NOT NULL
         AND ticket.claimed_by_user_id IS NULL
         AND ticket.version = 1
       ORDER BY ticket.id
       LIMIT 1`,
      { urls },
    ),
  );
  for (const [key, label] of [
    ["id", "race ticket"],
    ["workflowId", "race workflow"],
    ["teamId", "race team"],
  ]) {
    uuidLiteral(raceTarget[key], label);
  }
  if (
    !Number.isSafeInteger(raceTarget.workflowVersion) ||
    raceTarget.workflowVersion < 1 ||
    typeof raceTarget.stateKey !== "string" ||
    typeof raceTarget.customerVisible !== "boolean"
  ) {
    throw new Error("claim race target projection is malformed");
  }
  const raceReleaseAt = new Date(Date.now() + 10_000).toISOString();
  const raceApplicationPrefix = `periapsis-race-${databaseName.slice(-12)}-`;
  const raceSql = (worker) => `${humanContext(facts)}
SET LOCAL application_name = ${applicationNameLiteral(`${raceApplicationPrefix}${worker}`)};
SELECT pg_sleep(greatest(
  0,
  extract(epoch FROM (${timestampLiteral(raceReleaseAt, "claim race release")} - clock_timestamp()))
));
CREATE TEMP TABLE claim_race_outcome (
  sqlstate text NOT NULL CHECK (sqlstate IN ('00000', '40001')),
  attempted_at timestamp with time zone NOT NULL
) ON COMMIT DROP;
DO $claim_race$
DECLARE
  attempt_time timestamp with time zone := clock_timestamp();
BEGIN
  PERFORM 1 FROM app.apply_tenant_ticket_mutation_v2(
    'alert', ${uuidLiteral(raceTarget.id, "race ticket")}, 'claim', 1, 2,
    ${uuidLiteral(raceTarget.workflowId, "race workflow")},
    ${raceTarget.workflowVersion}, ${workflowStateLiteral(raceTarget.stateKey)},
    ${workflowStateLiteral(raceTarget.stateKey)}, NULL, ${raceTarget.customerVisible},
    ${uuidLiteral(raceTarget.teamId, "race team")},
    ${uuidLiteral(facts.adminUserId, "adminUserId")},
    ${uuidLiteral(facts.adminUserId, "adminUserId")},
    'Synthetic one-winner claim race proof.', NULL, NULL, '{}'::jsonb,
    NULL, NULL, uuidv7(), uuidv7(), '192.0.2.12'::inet,
    'Periapsis performance harness', 'totp'
  );
  INSERT INTO claim_race_outcome VALUES ('00000', attempt_time);
EXCEPTION
  WHEN serialization_failure THEN
    INSERT INTO claim_race_outcome VALUES ('40001', attempt_time);
END;
$claim_race$;
SELECT jsonb_build_object(
  'sqlstate', sqlstate,
  'attemptedAt', attempted_at
)::text
FROM claim_race_outcome;
COMMIT;`;
  log("running one-winner ticket claim race");
  const raceStarted = performance.now();
  const racePromises = Array.from({ length: concurrency }, (_, worker) =>
    runPsql(targetUrl, raceSql(worker), { urls }),
  );
  const raceSettlement = Promise.allSettled(racePromises);
  let readyContenders = 0;
  let readyObservedAt = null;
  while (Date.now() < Date.parse(raceReleaseAt) - 750) {
    if (shutdownLatch.signal !== null) {
      break;
    }
    readyContenders = parseSingleInteger(
      psqlSync(
        targetUrl,
        `SELECT count(*)
         FROM pg_catalog.pg_stat_activity
         WHERE datname = ${databaseNameLiteral(databaseName)}
           AND left(application_name, ${raceApplicationPrefix.length}) = ${applicationNameLiteral(raceApplicationPrefix)}
           AND wait_event_type = 'Timeout'
           AND wait_event = 'PgSleep'`,
        { urls },
      ),
      "claim race readiness",
    );
    if (readyContenders === concurrency) {
      readyObservedAt = new Date().toISOString();
      break;
    }
    // The poll observes one evolving barrier; concurrent polls would only add
    // superuser connections and could not establish a stronger ordering fact.
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  const settledRaceResults = await raceSettlement;
  const raceWorkers = settledRaceResults.map((settled, worker) => {
    if (settled.status === "rejected") {
      return {
        worker,
        status: "failed",
        durationMs: null,
        error: redactConnectionText(
          settled.reason?.message ?? settled.reason,
          urls,
        ).slice(0, 2_048),
      };
    }
    let receipt;
    try {
      receipt = JSON.parse(settled.value.stdout);
    } catch (error) {
      return {
        worker,
        status: "failed",
        durationMs: settled.value.durationMs,
        error: `claim race receipt is malformed: ${String(error?.message ?? error).slice(0, 512)}`,
      };
    }
    if (
      typeof receipt !== "object" ||
      receipt === null ||
      Array.isArray(receipt) ||
      Object.keys(receipt).toSorted().join(",") !== "attemptedAt,sqlstate" ||
      !new Set(["00000", "40001"]).has(receipt.sqlstate) ||
      typeof receipt.attemptedAt !== "string" ||
      !Number.isFinite(Date.parse(receipt.attemptedAt))
    ) {
      return {
        worker,
        status: "failed",
        durationMs: settled.value.durationMs,
        error: "claim race receipt has an invalid shape",
      };
    }
    return {
      worker,
      status: "completed",
      durationMs: settled.value.durationMs,
      sqlstate: receipt.sqlstate,
      attemptedAt: receipt.attemptedAt,
    };
  });
  const completedRaceWorkers = raceWorkers.filter(
    (worker) => worker.status === "completed",
  );
  const attemptTimes = completedRaceWorkers.map((worker) =>
    Date.parse(worker.attemptedAt),
  );
  const states = completedRaceWorkers.map((worker) => worker.sqlstate);
  const raceEvidence = {
    contenders: concurrency,
    readyContenders,
    readyObservedAt,
    scheduledReleaseAt: raceReleaseAt,
    readyLeadMs:
      readyObservedAt === null
        ? null
        : Date.parse(raceReleaseAt) - Date.parse(readyObservedAt),
    attemptSkewMs:
      attemptTimes.length === 0
        ? null
        : Math.max(...attemptTimes) - Math.min(...attemptTimes),
    winnerCount: states.filter((state) => state === "00000").length,
    staleCasCount: states.filter((state) => state === "40001").length,
    wallMs: performance.now() - raceStarted,
    maximumWorkerMs: Math.max(
      ...completedRaceWorkers.map((worker) => worker.durationMs),
      0,
    ),
    workers: raceWorkers,
    status: "measured",
  };
  evidence.loads.claim_race = raceEvidence;
  if (
    readyContenders !== concurrency ||
    raceEvidence.readyLeadMs === null ||
    raceEvidence.readyLeadMs < 500 ||
    raceWorkers.some((worker) => worker.status !== "completed") ||
    raceEvidence.attemptSkewMs === null ||
    raceEvidence.attemptSkewMs > 500 ||
    raceEvidence.winnerCount !== 1 ||
    raceEvidence.staleCasCount !== concurrency - 1
  ) {
    raceEvidence.status = "failed";
    throw new Error("claim race barrier or one-winner evidence failed");
  }
  const claimedState = psqlSync(
    targetUrl,
    `SELECT count(*) FROM public.alerts
     WHERE id = ${uuidLiteral(raceTarget.id, "race ticket")}
       AND tenant_id = ${uuidLiteral(facts.tenantId, "tenantId")}
       AND version = 2
       AND assignee_user_id = ${uuidLiteral(facts.adminUserId, "adminUserId")}
       AND claimed_by_user_id = ${uuidLiteral(facts.adminUserId, "adminUserId")}`,
    { urls },
  );
  if (claimedState !== "1") {
    throw new Error("claim race did not persist exactly one winner");
  }
  raceEvidence.status = "passed";

  const runtimeConcurrency = 4;
  log("settling ingress produced by ingest and ticket claims");
  await runSlaWorker("ingress", evidence.slaProcessing, "after_ticket_loads");
  log("running four concurrent real SLA timer workers");
  await measureSlaTimers(targetUrl, urls, evidence);

  log("running concurrent notification fanout claims");
  evidence.loads.notification_fanout_claim = await measureConcurrentSql({
    name: "notification_fanout_claim",
    sqlStatements: Array.from(
      { length: runtimeConcurrency },
      (_, worker) => `BEGIN;
SET LOCAL ROLE periapsis_notifier;
SET LOCAL statement_timeout = '15s';
WITH claimed AS (
  SELECT (fanout.claim ->> 'id')::uuid AS event_id
  FROM app.claim_notification_fanout_batch_v1(
    'performance-${worker}', 100, 120000, clock_timestamp()
  ) AS fanout
)
SELECT jsonb_build_object(
  'ids', coalesce(jsonb_agg(claimed.event_id ORDER BY claimed.event_id), '[]'::jsonb)
)::text
FROM claimed;
COMMIT;`,
    ),
    expectedPerWorker: 100,
    evidence: evidence.loads,
    targetUrl,
    urls,
    verifyCommitted: (ids) =>
      verifyNotificationClaimsCommitted(targetUrl, ids, urls),
  });
}

async function writeEvidenceFile(databaseName, evidence) {
  assertDisposableDatabaseName(databaseName);
  await mkdir(evidenceDirectory, { recursive: true });
  const target = resolve(evidenceDirectory, `${databaseName}.json`);
  const staging = resolve(evidenceDirectory, `${databaseName}.json.tmp`);
  if (
    dirname(target) !== evidenceDirectory ||
    dirname(staging) !== evidenceDirectory
  ) {
    throw new Error("performance evidence path escaped its boundary");
  }
  let handle;
  try {
    handle = await open(staging, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    const publication = await publishFileNoReplace(staging, target);
    if (!publication.stagingRemoved) {
      process.stderr.write(
        "[performance] evidence committed; staging hard link could not be removed\n",
      );
    }
    return target;
  } catch (error) {
    const cleanupErrors = [];
    if (handle) {
      try {
        await handle.close();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    try {
      await unlink(staging);
    } catch (cleanupError) {
      if (cleanupError?.code !== "ENOENT") {
        cleanupErrors.push(cleanupError);
      }
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "performance evidence write and staging cleanup failed",
        { cause: error },
      );
    }
    throw error;
  }
}

const adminUrl = parseLocalAdminUrl(
  process.env.PERIAPSIS_PERFORMANCE_ADMIN_URL ?? "",
);
const migrationPin = parseMigrationManifest(
  await readFile(migrationManifestPath, "utf8"),
);
const databaseName = createDisposableDatabaseName();
const targetUrl = new URL(databaseUrl(adminUrl, databaseName));
const destructiveApplicationSuffix = databaseName.slice(-12);
const createApplicationName = `periapsis-create-${destructiveApplicationSuffix}`;
const dropApplicationNames = Object.freeze([
  `periapsis-drop-${destructiveApplicationSuffix}-1`,
  `periapsis-drop-${destructiveApplicationSuffix}-2`,
]);
const urls = [adminUrl, targetUrl];
const evidence = {
  schemaVersion: 4,
  status: "running",
  generatedAt: new Date().toISOString(),
  environment: {
    node: process.version,
    platform: platform(),
    release: release(),
    architecture: process.arch,
    logicalCpuCount: cpus().length,
    cpuModel: cpus()[0]?.model ?? "unknown",
    totalMemoryBytes: totalmem(),
    alertCount: 100_000,
    caseCount: 100_000,
  },
  migrations: null,
  dataset: null,
  plans: {},
  loads: {},
  slaProcessing: {},
  setupTimings: {},
};
let databaseCreationAttempted = false;
let postgresCredential = null;
let failure;
let stage = "client_preflight";
let processTreeQuiescenceEstablished = false;
let psqlQuiescenceEstablished = false;

try {
  const clientVersion = runSync(psql, ["--version"], { urls });
  if (!/\b18\.6\b/.test(clientVersion)) {
    throw new Error(
      "performance gates require the PostgreSQL 18.6 psql client",
    );
  }
  stage = "sla_worker_preflight";
  if (
    adminUrl.username !== "postgres" ||
    adminUrl.pathname !== "/postgres" ||
    adminUrl.port === "" ||
    adminUrl.search !== "?sslmode=disable"
  ) {
    throw new Error(
      "SLA performance requires postgres, an explicit port and sslmode=disable",
    );
  }
  const executable = process.env.PERIAPSIS_PERFORMANCE_SLA_WORKER ?? "";
  if (
    !isAbsolute(executable) ||
    basename(executable) !==
      (process.platform === "win32"
        ? "performance-sla.exe"
        : "performance-sla") ||
    !(await lstat(executable)).isFile()
  ) {
    throw new Error(
      "PERIAPSIS_PERFORMANCE_SLA_WORKER must name the compiled absolute worker executable",
    );
  }
  slaWorkerExecutable = executable;
  evidence.slaWorkerBinaryDigest = createHash("sha256")
    .update(await readFile(executable))
    .digest("hex");
  stage = "credential_boundary";
  let windowsIdentitySid;
  try {
    postgresCredential = await preparePostgresCredential(adminUrl, {
      restrictPath: (path, isDirectory) => {
        if (windowsSystemTools !== null && windowsIdentitySid === undefined) {
          windowsIdentitySid = parseWindowsIdentitySid(
            runSync(windowsSystemTools.whoami, ["/user", "/fo", "csv", "/nh"], {
              timeout: 10_000,
            }),
          );
        }
        return restrictCredentialPath(
          path,
          isDirectory,
          windowsIdentitySid ?? null,
        );
      },
    });
  } catch (credentialPreparationError) {
    postgresCredential = credentialFromPreparationError(
      credentialPreparationError,
    );
    evidence.credentialMode =
      postgresCredential === null
        ? "setup_failed_before_allocation"
        : "temporary_pgpass_setup_failed";
    if (credentialPreparationError?.credentialCleanupEvidence !== undefined) {
      evidence.credentialPreparationCleanup =
        credentialPreparationError.credentialCleanupEvidence;
    }
    throw credentialPreparationError;
  }
  postgresCredentialEnvironment =
    postgresCredential === null ? {} : { PGPASSFILE: postgresCredential.file };
  evidence.credentialMode =
    postgresCredential === null ? "trust_or_external" : "temporary_pgpass";
  try {
    slaWorkerCredential = await prepareSlaWorkerCredential(targetUrl, {
      restrictPath: (path, isDirectory) => {
        if (windowsSystemTools !== null && windowsIdentitySid === undefined) {
          windowsIdentitySid = parseWindowsIdentitySid(
            runSync(windowsSystemTools.whoami, ["/user", "/fo", "csv", "/nh"], {
              timeout: 10_000,
            }),
          );
        }
        return restrictCredentialPath(
          path,
          isDirectory,
          windowsIdentitySid ?? null,
        );
      },
    });
  } catch (error) {
    slaWorkerCredential = slaWorkerCredentialFromPreparationError(error);
    evidence.slaWorkerCredentialPreparationCleanup =
      error?.credentialCleanupEvidence;
    throw error;
  }
  stage = "server_preflight";
  assertShutdownWasNotRequested();
  const [serverVersionNumber, serverVersion] = psqlSync(
    adminUrl.href,
    "SELECT current_setting('server_version_num'), current_setting('server_version')",
    { urls },
  ).split("|");
  assertPostgresVersion(serverVersionNumber, serverVersion);

  const rawClusterFacts = JSON.parse(
    psqlSync(
      adminUrl.href,
      `SELECT jsonb_build_object(
          'currentDatabase', current_database(),
          'currentUserIsSuperuser', role.rolsuper,
          'serverAddress', host(inet_server_addr()),
          'serverTimezone', current_setting('TimeZone'),
          'databaseRoleSettingCount', (
            SELECT count(*)::integer FROM pg_catalog.pg_db_role_setting
          ),
          'dataDirectory', current_setting('data_directory'),
          'nonTemplateDatabases', (
            SELECT jsonb_agg(database.datname ORDER BY database.datname)
            FROM pg_catalog.pg_database AS database
            WHERE NOT database.datistemplate
          ),
          'userRelationCount', (
            SELECT count(*)::integer
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
              AND namespace.nspname NOT LIKE 'pg_toast%'
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          ),
          'existingPeriapsisRoles', (
            SELECT count(*)::integer FROM pg_catalog.pg_roles
            WHERE rolname ~ '^periapsis_'
          ),
          'existingDisposableDatabases', (
            SELECT count(*)::integer FROM pg_catalog.pg_database
            WHERE datname ~ '^periapsis_performance_[0-9]{13}_[0-9a-f]{12}$'
          )
        )::text
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = current_user`,
      { urls },
    ),
  );
  evidence.clusterIdentity = assertExpectedClusterDataDirectory(
    expectedClusterDataDirectory,
    rawClusterFacts.dataDirectory,
  );
  const clusterFacts = assertFreshClusterFacts(rawClusterFacts);
  evidence.clusterPreflight = clusterFacts;
  assertShutdownWasNotRequested();

  stage = "create_database";
  log(`creating disposable database ${databaseName}`);
  databaseCreationAttempted = true;
  psqlSync(
    adminUrl.href,
    `CREATE DATABASE ${quoteIdentifier(databaseName)} WITH TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'`,
    { applicationName: createApplicationName, timeout: 30_000, urls },
  );
  assertShutdownWasNotRequested();
  // UTC comes from the pinned fresh server, not pg_db_role_setting: persistent
  // database settings would change the canonical migration dependency seal.

  stage = "migrate";
  log("applying the canonical migration bundle");
  await runDatabaseScript("db:migrate", targetUrl.href, urls);
  assertShutdownWasNotRequested();
  stage = "seed";
  log("loading the canonical seed");
  await runDatabaseScript("db:seed", targetUrl.href, urls);
  assertShutdownWasNotRequested();
  stage = "fixture";
  log("loading the 100k-Alert and 100k-Case fixture");
  const fixtureStarted = performance.now();
  try {
    psqlSync(targetUrl.href, "", {
      file: fixturePath,
      slaFixture: JSON.parse(await readFile(slaFixturePath, "utf8")),
      timeout: 15 * 60_000,
      urls,
    });
  } finally {
    evidence.setupTimings.fixtureMs = performance.now() - fixtureStarted;
  }
  assertShutdownWasNotRequested();

  stage = "sla_ingress";
  log("processing immutable ticket ingress through the real SLA worker");
  await runSlaWorker("ingress", evidence.slaProcessing, "after_fixture");
  psqlSync(
    targetUrl.href,
    `ANALYZE public.sla_instances;
    ANALYZE public.sla_metric_instances;
    ANALYZE public.sla_materialized_column_values;
    ANALYZE public.sla_evaluation_jobs;
    ANALYZE public.sla_object_event_ingress;`,
    { urls },
  );

  stage = "dataset_verification";
  const facts = parseFacts(
    psqlSync(
      targetUrl.href,
      `SELECT jsonb_build_object(
        'serverVersionNumber', current_setting('server_version_num'),
        'serverVersion', current_setting('server_version'),
        'migrationCount', (SELECT count(*)::integer FROM drizzle.__drizzle_migrations),
        'migrationFingerprint', (
          SELECT string_agg(
            migration.created_at::text || '@' || lower(migration.hash::text),
            ':' ORDER BY migration.created_at, migration.id
          )
          FROM drizzle.__drizzle_migrations AS migration
        ),
        'latestMigrationId', (
          SELECT id FROM drizzle.__drizzle_migrations
          ORDER BY created_at DESC, id DESC LIMIT 1
        ),
        'latestMigrationCreatedAt', (
          SELECT created_at FROM drizzle.__drizzle_migrations
          ORDER BY created_at DESC, id DESC LIMIT 1
        ),
        'latestMigrationHash', (
          SELECT lower(hash::text) FROM drizzle.__drizzle_migrations
          ORDER BY created_at DESC, id DESC LIMIT 1
        ),
        'databaseCollation', (
          SELECT datcollate FROM pg_catalog.pg_database
          WHERE datname = current_database()
        ),
        'databaseCType', (
          SELECT datctype FROM pg_catalog.pg_database
          WHERE datname = current_database()
        ),
        'databaseTimezone', current_setting('TimeZone'),
        'tenantId', tenant.id,
        'adminUserId', administrator.user_id,
        'analystUserId', analyst.user_id,
        'teamId', team.id,
        'assignmentEpochId', epoch.id,
        'workflowId', workflow.id,
        'customDefinitionId', definition.id,
        'slaColumnId', sla_column.id,
        'activeState', selected_transition.value ->> 'to',
        'activeStateCount', (
          SELECT count(*)::integer FROM public.alerts AS ticket
          WHERE ticket.tenant_id = tenant.id
            AND ticket.state_key = selected_transition.value ->> 'to'
        ),
        'activeCriticalCount', (
          SELECT count(*)::integer FROM public.alerts AS ticket
          WHERE ticket.tenant_id = tenant.id AND ticket.severity = 'critical'
            AND ticket.state_key = selected_transition.value ->> 'to'
        ),
        'creationBatchCount', (
          SELECT count(DISTINCT ticket.created_at)::integer FROM public.alerts AS ticket
          WHERE ticket.tenant_id = tenant.id AND ticket.external_id LIKE 'performance-alert-%'
        ),
        'initialState', (
          SELECT state.value ->> 'key'
          FROM public.ticket_workflow_versions AS version,
               LATERAL jsonb_array_elements(version.states) AS state(value)
          WHERE version.tenant_id = tenant.id
            AND version.workflow_id = workflow.id
            AND version.aggregate_kind = 'alert'
            AND version.version = workflow.current_version
            AND (state.value ->> 'initial')::boolean
        ),
        'alertCount', (SELECT count(*)::integer FROM public.alerts WHERE tenant_id = tenant.id),
        'caseCount', (SELECT count(*)::integer FROM public.cases WHERE tenant_id = tenant.id),
        'customValueCount', (
          SELECT count(*)::integer FROM public.custom_field_values AS value
          WHERE value.tenant_id = tenant.id AND value.definition_id = definition.id
        ),
        'customMatchCount', (
          SELECT count(*)::integer FROM public.custom_field_values AS value
          WHERE value.tenant_id = tenant.id AND value.definition_id = definition.id
            AND value.integer_value = 42
        ),
        'slaValueCount', (
          SELECT count(*)::integer FROM public.sla_materialized_column_values AS value
          WHERE value.tenant_id = tenant.id AND value.column_id = sla_column.id
        ),
        'slaJobCount', (
          SELECT count(*)::integer FROM public.sla_evaluation_jobs AS job
          WHERE job.tenant_id = tenant.id
        ),
        'slaInstanceCount', (
          SELECT count(*)::integer FROM public.sla_instances AS instance
          WHERE instance.tenant_id = tenant.id
            AND instance.policy_id = '01b00000-0000-7000-8000-000000000020'::uuid
        ),
        'slaCompletedMetricCount', (
          SELECT count(*)::integer FROM public.sla_metric_instances AS metric
          WHERE metric.tenant_id = tenant.id
            AND metric.definition_id = '01b00000-0000-7000-8000-000000000021'::uuid
            AND metric.lifecycle = 'completed'
        ),
        'slaRunningMetricCount', (
          SELECT count(*)::integer FROM public.sla_metric_instances AS metric
          WHERE metric.tenant_id = tenant.id
            AND metric.definition_id = '01b00000-0000-7000-8000-000000000021'::uuid
            AND metric.lifecycle = 'running'
        ),
        'slaPendingIngressCount', (
          SELECT count(*)::integer FROM public.sla_object_event_ingress WHERE status <> 'completed'
        ),
        'notificationEventCount', (
          SELECT count(*)::integer FROM public.outbox_events AS event
          WHERE event.tenant_id = tenant.id
            AND event.event_type = 'notification.alert.created'
            AND event.schema_version = 2
        )
      )::text
      FROM public.tenants AS tenant
      JOIN public.tenant_memberships AS administrator
        ON administrator.tenant_id = tenant.id
       AND administrator.role = 'tenant_admin'
       AND administrator.status = 'active'
      JOIN public.tenant_memberships AS analyst
        ON analyst.tenant_id = tenant.id
       AND analyst.role = 'analyst'
       AND analyst.status = 'active'
      JOIN public.operator_teams AS team ON team.key = 'soc_l1'
      JOIN public.operator_team_assignment_epochs AS epoch
        ON epoch.tenant_id = tenant.id AND epoch.operator_team_id = team.id
       AND epoch.ended_at IS NULL
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id = tenant.id
       AND workflow.aggregate_kind = 'alert'
       AND workflow.key = 'default_alert'
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id = tenant.id AND workflow_version.workflow_id = workflow.id
       AND workflow_version.aggregate_kind = 'alert' AND workflow_version.version = workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.transitions) AS selected_transition(value)
      JOIN public.custom_field_definitions AS definition
        ON definition.tenant_id = tenant.id
       AND definition.key = 'performance_score'
      JOIN public.sla_columns AS sla_column
        ON sla_column.tenant_id = tenant.id
       AND sla_column.key = 'performance-due-at'
      WHERE tenant.slug = 'acme' AND selected_transition.value ->> 'key' = 'start_investigation'`,
      { urls },
    ),
    migrationPin,
  );
  evidence.migrations = {
    expected: migrationPin,
    count: facts.migrationCount,
    fingerprint: facts.migrationFingerprint,
    latestId: facts.latestMigrationId,
    latestCreatedAt: facts.latestMigrationCreatedAt,
    latestHash: facts.latestMigrationHash,
    postgres: facts.serverVersion,
  };
  evidence.dataset = {
    alerts: facts.alertCount,
    cases: facts.caseCount,
    customFieldValues: facts.customValueCount,
    customFieldMatches: facts.customMatchCount,
    slaMaterializedValues: facts.slaValueCount,
    slaJobs: facts.slaJobCount,
    slaInstances: facts.slaInstanceCount,
    slaCompletedMetrics: facts.slaCompletedMetricCount,
    slaRunningMetrics: facts.slaRunningMetricCount,
    notificationEvents: facts.notificationEventCount,
    activeState: facts.activeState,
    activeStateCount: facts.activeStateCount,
    activeCriticalCount: facts.activeCriticalCount,
    creationBatchCount: facts.creationBatchCount,
  };

  stage = "query_plans";
  await measurePlans(targetUrl.href, facts, urls, evidence);
  assertShutdownWasNotRequested();
  stage = "concurrent_load";
  await measureLoads(targetUrl.href, facts, urls, evidence, databaseName);
  assertShutdownWasNotRequested();
  if (
    createHash("sha256")
      .update(await readFile(slaWorkerExecutable))
      .digest("hex") !== evidence.slaWorkerBinaryDigest
  ) {
    throw new Error("SLA worker executable changed during the benchmark");
  }
  evidence.status = "passed";
} catch (error) {
  failure = error;
  evidence.status = "failed";
  evidence.failureStage = stage;
  evidence.failure = redactConnectionText(error?.message ?? error, urls).slice(
    0,
    8_192,
  );
} finally {
  const quiescenceFailures = [];
  try {
    evidence.processTreeQuiescence =
      await terminateAndAwaitActiveProcessTrees();
    processTreeQuiescenceEstablished = true;
  } catch (quiescenceError) {
    evidence.status = "failed";
    evidence.processTreeQuiescence = {
      ...quiescenceError?.quiescenceEvidence,
      activeProcessTreePids: activeProcessTreePids(),
      status: "failed",
    };
    evidence.processTreeQuiescenceFailure = String(
      quiescenceError?.message ?? quiescenceError,
    ).slice(0, 2_048);
    quiescenceFailures.push(quiescenceError);
  }
  try {
    evidence.psqlQuiescence =
      await terminateAndAwaitActiveChildren(activePsqlChildren);
    psqlQuiescenceEstablished = true;
  } catch (quiescenceError) {
    evidence.status = "failed";
    evidence.psqlQuiescence = {
      activePsqlPids: [...activePsqlChildren]
        .map((child) => child.pid)
        .filter((pid) => Number.isSafeInteger(pid) && pid > 0)
        .toSorted((a, b) => a - b),
      observed: activePsqlChildren.size,
      remaining: activePsqlChildren.size,
      status: "failed",
    };
    const redacted = String(quiescenceError?.message ?? quiescenceError).slice(
      0,
      2_048,
    );
    evidence.psqlQuiescenceFailure = redacted;
    quiescenceFailures.push(quiescenceError);
  }
  const cleanupClientsQuiesced =
    processTreeQuiescenceEstablished && psqlQuiescenceEstablished;
  if (!cleanupClientsQuiesced) {
    const blockedIdentifiers = blockedCleanupIdentifiers(
      [...activePsqlChildren]
        .map((child) => child.pid)
        .filter((pid) => Number.isSafeInteger(pid) && pid > 0),
      activeProcessTreePids(),
      postgresCredentialDirectoryBasename(postgresCredential),
    );
    evidence.cleanupBlockers = blockedIdentifiers;
    process.stderr.write(
      `[performance] cleanup blocked; active psql PIDs: ${blockedIdentifiers.activePsqlPids.join(",") || "none"}; active tracked process-tree PIDs: ${blockedIdentifiers.activeProcessTreePids.join(",") || "none"}; credential directory: ${blockedIdentifiers.credentialDirectoryBasename ?? "not-required"}\n`,
    );
    const quiescenceError = new AggregateError(
      quiescenceFailures,
      "performance client quiescence failed",
      { cause: quiescenceFailures[0] },
    );
    if (failure) {
      failure = new AggregateError(
        [failure, quiescenceError],
        "gate and client quiescence failed",
        { cause: failure },
      );
    } else {
      failure = quiescenceError;
      evidence.failureStage = "client_quiescence";
      evidence.failure = quiescenceError.message;
    }
  }
  if (databaseCreationAttempted && cleanupClientsQuiesced) {
    try {
      log(`quiescing and dropping disposable database ${databaseName}`);
      const cleanupResult = cleanupDisposableDatabase({
        adminUrl: adminUrl.href,
        createApplicationName,
        databaseName,
        dropApplicationNames,
        urls,
      });
      evidence.cleanup = cleanupResult.status;
      evidence.cleanupEvidence = cleanupResult;
    } catch (cleanupError) {
      evidence.status = "failed";
      evidence.cleanup = cleanupError?.cleanupEvidence?.status ?? "failed";
      if (cleanupError?.cleanupEvidence !== undefined) {
        evidence.cleanupEvidence = cleanupError.cleanupEvidence;
      }
      const redacted = redactConnectionText(
        cleanupError?.message ?? cleanupError,
        urls,
      ).slice(0, 8_192);
      if (failure) {
        failure = new AggregateError(
          [failure, cleanupError],
          "gate and cleanup failed",
          { cause: failure },
        );
      } else {
        failure = cleanupError;
        evidence.failureStage = "cleanup";
        evidence.failure = redacted;
      }
      evidence.cleanupFailure = redacted;
    }
  } else if (databaseCreationAttempted) {
    evidence.cleanup = "blocked_by_active_clients";
  } else {
    evidence.cleanup = "not_created";
  }
  if (cleanupClientsQuiesced) {
    try {
      const credentialCleanup =
        await removePostgresCredential(postgresCredential);
      evidence.credentialCleanup = credentialCleanup.status;
      evidence.credentialCleanupEvidence = credentialCleanup;
      postgresCredentialEnvironment = {};
    } catch (credentialCleanupError) {
      evidence.status = "failed";
      evidence.credentialCleanup = "failed";
      evidence.credentialCleanupEvidence =
        credentialCleanupError?.credentialCleanupEvidence ??
        Object.freeze({
          directoryBasename:
            postgresCredentialDirectoryBasename(postgresCredential),
          status: "failed",
        });
      const redacted = String(
        credentialCleanupError?.message ?? credentialCleanupError,
      ).slice(0, 2_048);
      if (failure) {
        failure = new AggregateError(
          [failure, credentialCleanupError],
          "gate and credential cleanup failed",
          { cause: failure },
        );
      } else {
        failure = credentialCleanupError;
        evidence.failureStage = "credential_cleanup";
        evidence.failure = redacted;
      }
      evidence.credentialCleanupFailure = redacted;
    }
  } else {
    evidence.credentialCleanup =
      postgresCredential === null
        ? "not_required"
        : "blocked_by_active_clients";
    evidence.credentialCleanupEvidence = Object.freeze({
      directoryBasename:
        postgresCredentialDirectoryBasename(postgresCredential),
      status: evidence.credentialCleanup,
    });
  }
  if (cleanupClientsQuiesced) {
    try {
      evidence.slaWorkerCredentialCleanup =
        await removeSlaWorkerCredential(slaWorkerCredential);
    } catch (error) {
      evidence.status = "failed";
      evidence.slaWorkerCredentialCleanup =
        error?.credentialCleanupEvidence ?? { status: "failed" };
      if (!failure) {
        evidence.failureStage = "sla_worker_credential_cleanup";
        evidence.failure = "SLA worker credential cleanup failed";
      }
      failure = failure
        ? new AggregateError(
            [failure, error],
            "gate and SLA worker credential cleanup failed",
          )
        : error;
    }
  } else {
    evidence.slaWorkerCredentialCleanup = {
      status:
        slaWorkerCredential === null
          ? "not_required"
          : "blocked_by_active_clients",
      directoryBasename:
        slaWorkerCredentialDirectoryBasename(slaWorkerCredential),
    };
  }
  evidence.completedAt = new Date().toISOString();
  if (shutdownLatch.signal !== null) {
    const priorFailure = failure;
    failure = mergeShutdownFailure(failure, shutdownLatch.signal);
    evidence.status = "failed";
    evidence.shutdownSignal = shutdownLatch.signal;
    if (!priorFailure) {
      evidence.failureStage = "shutdown";
      evidence.failure = failure.message;
    }
  }
  for (const [signal, handler] of shutdownHandlers) {
    process.off(signal, handler);
  }
  try {
    const evidencePath = await writeEvidenceFile(databaseName, evidence);
    log(`evidence written to ${evidencePath}`);
  } catch (evidenceWriteError) {
    evidence.status = "failed";
    const redacted = String(
      evidenceWriteError?.message ?? evidenceWriteError,
    ).slice(0, 2_048);
    process.stderr.write(`[performance] evidence write failed: ${redacted}\n`);
    if (failure) {
      failure = new AggregateError(
        [failure, evidenceWriteError],
        "gate and evidence write failed",
        { cause: failure },
      );
    } else {
      failure = evidenceWriteError;
      evidence.failureStage = "evidence_write";
      evidence.failure = redacted;
    }
  }
}

if (failure) {
  throw failure;
}
log("all ticketing performance gates passed");
