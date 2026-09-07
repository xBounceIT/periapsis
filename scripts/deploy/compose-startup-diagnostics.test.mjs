import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  collectComposeStartupDiagnostics,
  redactComposeStartupLogs,
} from "./compose-startup-diagnostics.mjs";

const container = "a".repeat(64);
const state = {
  status: "exited",
  exitCode: 1,
  oomKilled: false,
  errorPresent: false,
  health: null,
};
const canary = "private-canary-never-print";

test("readiness diagnostics preserve only finite dependency and failure labels", () => {
  const api = redactComposeStartupLogs(
    "api",
    JSON.stringify({
      level: "WARN",
      msg: "readiness dependency unavailable",
      dependency: "ticket_operations",
      error: canary,
    }),
  );
  assert.deepEqual(api.events, [
    { kind: "runtime_readiness", dependency: "ticket_operations" },
  ]);
  const worker = redactComposeStartupLogs(
    "worker",
    JSON.stringify({
      level: "WARN",
      msg: "SLA event ingress failed",
      failure: canary,
      error: canary,
    }),
  );
  assert.deepEqual(worker.events, [
    {
      kind: "worker_readiness",
      operation: "SLA event ingress failed",
      failure: "UNCLASSIFIED",
    },
  ]);
  const unknown = redactComposeStartupLogs(
    "api",
    JSON.stringify({
      level: "WARN",
      msg: "readiness dependency unavailable",
      dependency: canary,
    }),
  );
  assert.equal(unknown.events[0].dependency, "UNCLASSIFIED");
  assert.ok(!JSON.stringify([api, worker, unknown]).includes(canary));
});

function success(stdout = "", stderr = "") {
  return { status: 0, signal: null, stdout, stderr };
}

function driver(code, extra = {}) {
  return JSON.stringify({
    service: "database-task",
    event: "database_task_failed",
    code,
    ...extra,
  });
}

function databaseDriver(code, mode = "unknown", phase = "unknown") {
  return { kind: "database_driver", code, mode, phase };
}

function codeList(source) {
  const body = /const databaseCodes = new Set\(\[([\s\S]*?)\]\);/u.exec(
    source,
  )?.[1];
  assert.ok(body);
  return [...body.matchAll(/"([A-Z0-9_]+)"/gu)].map((entry) => entry[1]);
}

test("migration diagnostics retain only reviewed driver and native error codes", () => {
  const result = redactComposeStartupLogs(
    "migration",
    [
      driver("EXIT_1", {
        mode: canary,
        url: `postgresql://${canary}`,
        error: canary,
      }),
      "  code: '42702',",
      "  code: 'MIGRATION_SEALER_DIVERGED',",
      driver("EACCES"),
      driver("SIGNAL_SIGILL"),
      driver("28P01"),
      driver(canary.toUpperCase()),
      driver(["EXIT_1"]),
      driver("EXIT_256"),
      driver("EXIT_0"),
      driver("EACCES", { service: canary }),
      `password=${canary}`,
      `query: 'ALTER ROLE someone PASSWORD ${canary}'`,
      `::error::${canary}`,
    ].join("\n"),
  );
  assert.deepEqual(result.events, [
    databaseDriver("EXIT_1"),
    { kind: "database_error_property", code: "42702" },
    { kind: "database_error_property", code: "MIGRATION_SEALER_DIVERGED" },
    databaseDriver("EACCES"),
    databaseDriver("SIGNAL_SIGILL"),
    databaseDriver("28P01"),
    ...Array.from({ length: 4 }, () => databaseDriver("UNCLASSIFIED")),
  ]);
  assert.equal(result.redactedLines, 4);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private|password|postgresql|ALTER ROLE|::error/iu,
  );
});

test("recognized task failures keep only finite phase/mode and fixed unknown-code evidence", () => {
  for (const phase of [
    "configuration",
    "migration",
    "runtime_credentials",
    "runtime_provision",
    "seed",
  ]) {
    for (const mode of [
      "migrate",
      "provision-notifier",
      "seed",
      "unsupported",
    ]) {
      for (const code of [
        undefined,
        null,
        7,
        {},
        ["EACCES"],
        canary,
        "CONNECT_TIMEOUT",
      ]) {
        const result = redactComposeStartupLogs(
          "migration",
          driver(code, {
            phase,
            mode,
            message: canary,
            stack: canary,
            sql: canary,
            parameters: [canary],
            cause: { code: "EACCES", message: canary },
          }),
        );
        assert.deepEqual(result, {
          events: [databaseDriver("UNCLASSIFIED", mode, phase)],
          redactedLines: 0,
        });
        assert.ok(!JSON.stringify(result).includes(canary));
      }
    }
  }
  for (const value of [undefined, null, {}, ["migration"], canary]) {
    assert.deepEqual(
      redactComposeStartupLogs(
        "migration",
        driver("EACCES", { phase: value, mode: value }),
      ),
      { events: [databaseDriver("EACCES")], redactedLines: 0 },
    );
  }
  for (const raw of [
    "null",
    "[]",
    "{",
    JSON.stringify(canary),
    driver("EACCES", { service: null }),
    driver("EACCES", { event: canary }),
    `  code: '${canary}',`,
  ]) {
    assert.deepEqual(redactComposeStartupLogs("migration", raw), {
      events: [],
      redactedLines: 1,
    });
  }
});

test("producer and collector retain the same finite code set and bounded exits", async () => {
  const [producer, collector] = await Promise.all([
    readFile(
      new URL("../../deploy/compose/database-task.mjs", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("./compose-startup-diagnostics.mjs", import.meta.url),
      "utf8",
    ),
  ]);
  assert.deepEqual(codeList(producer), codeList(collector));
  for (const code of codeList(producer)) {
    assert.deepEqual(
      redactComposeStartupLogs("migration", driver(code)).events,
      [databaseDriver(code)],
    );
  }
  for (const code of ["EXIT_1", "EXIT_255"]) {
    assert.deepEqual(
      redactComposeStartupLogs("migration", driver(code)).events,
      [databaseDriver(code)],
    );
  }
  for (const code of [
    "EXIT_0",
    "EXIT_01",
    "EXIT_256",
    "EXIT_1000",
    "EXIT_-1",
  ]) {
    assert.deepEqual(
      redactComposeStartupLogs("migration", driver(code)).events,
      [databaseDriver("UNCLASSIFIED")],
    );
  }
});

function runProducer(scenario) {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (
      /^(?:NODE_OPTIONS|NODE_PATH|DATABASE_URL(?:_FILE)?|PERIAPSIS_.*)$/iu.test(
        name,
      )
    )
      delete environment[name];
  }
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(
        new URL("./fixtures/database-task-producer.mjs", import.meta.url),
      ),
      JSON.stringify(scenario),
    ],
    {
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      env: environment,
      encoding: "utf8",
      timeout: 5_000,
      maxBuffer: 65_536,
      killSignal: "SIGKILL",
      windowsHide: true,
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.ok(
    !`${result.stdout}${result.stderr}`.includes("private-producer-canary"),
  );
  return { ...result, trace: JSON.parse(result.stdout) };
}

test("actual producer reports each failure phase without forwarding errors or credentials", () => {
  for (const [scenario, mode, phase, code] of [
    [
      { failure: "configuration", code: "ENOENT" },
      "migrate",
      "configuration",
      "ENOENT",
    ],
    [
      { environment: canary },
      "migrate",
      "configuration",
      "INVALID_ENVIRONMENT",
    ],
    [{ mode: canary }, "unsupported", "configuration", "UNSUPPORTED_TASK"],
    [{ failure: "migration" }, "migrate", "migration", "EXIT_1"],
    [
      { failure: "migration", signal: "SIGTERM" },
      "migrate",
      "migration",
      "SIGNAL_SIGTERM",
    ],
    [
      { failure: "read_api", code: "EACCES" },
      "migrate",
      "runtime_credentials",
      "EACCES",
    ],
    [
      { failure: "read_worker", code: "EACCES" },
      "migrate",
      "runtime_credentials",
      "EACCES",
    ],
    [
      { failure: "read_notifier", code: "EACCES" },
      "migrate",
      "runtime_credentials",
      "EACCES",
    ],
    [
      { mode: "provision-notifier", failure: "read_notifier", code: "EACCES" },
      "provision-notifier",
      "runtime_credentials",
      "EACCES",
    ],
    [
      { failure: "connect", code: "ECONNREFUSED" },
      "migrate",
      "runtime_provision",
      "ECONNREFUSED",
    ],
    [
      { failure: "begin", code: "42501" },
      "migrate",
      "runtime_provision",
      "42501",
    ],
    [
      { failure: "provision_statement", code: "42702" },
      "migrate",
      "runtime_provision",
      "42702",
    ],
    [
      { failure: "provision_statement", code: "42P18" },
      "migrate",
      "runtime_provision",
      "42P18",
    ],
    [
      { failure: "cleanup", code: "ETIMEDOUT" },
      "migrate",
      "runtime_provision",
      "ETIMEDOUT",
    ],
    [
      { mode: "provision-notifier", failure: "begin", code: "23505" },
      "provision-notifier",
      "runtime_provision",
      "23505",
    ],
    [
      { mode: "seed", failure: "seed", exitCode: 255 },
      "seed",
      "seed",
      "EXIT_255",
    ],
  ]) {
    const result = runProducer(scenario);
    assert.equal(result.status, 1);
    const envelope = JSON.parse(result.stderr);
    assert.deepEqual(Object.keys(envelope), [
      "timestamp",
      "level",
      "service",
      "event",
      "mode",
      "phase",
      "code",
    ]);
    assert.ok(Number.isFinite(Date.parse(envelope.timestamp)));
    assert.deepEqual(
      { ...envelope, timestamp: null },
      {
        timestamp: null,
        level: "error",
        service: "database-task",
        event: "database_task_failed",
        mode,
        phase,
        code,
      },
    );
    assert.deepEqual(redactComposeStartupLogs("migration", result.stderr), {
      events: [databaseDriver(code, mode, phase)],
      redactedLines: 0,
    });
    if (["begin", "provision_statement"].includes(scenario.failure))
      assert.equal(result.trace.at(-1), "cleanup");
  }
});

test("actual producer rejects arbitrary codes, coercion, getters and out-of-range exits", () => {
  for (const scenario of [
    ...[
      undefined,
      null,
      42702,
      ["EACCES"],
      { code: "EACCES" },
      canary,
      "CONNECT_TIMEOUT",
    ].map((code) => ({ failure: "begin", code })),
    { failure: "begin", codeGetter: true },
    { failure: "migration", exitCode: 256 },
    { failure: "migration", childError: true, code: canary },
  ]) {
    const result = runProducer(scenario);
    assert.equal(result.status, 1);
    const envelope = JSON.parse(result.stderr);
    assert.equal(envelope.code, "UNCLASSIFIED");
    assert.equal(
      envelope.phase,
      scenario.failure === "migration" ? "migration" : "runtime_provision",
    );
    assert.equal(envelope.mode, "migrate");
  }
});

test("actual producer preserves task ordering and environment-specific credential reads", () => {
  for (const [scenario, prefix, roleCount] of [
    [
      {},
      [
        "configuration",
        "read_admin",
        "migration",
        "read_api",
        "read_worker",
        "read_notifier",
        "connect",
        "begin",
      ],
      3,
    ],
    [
      { environment: "test" },
      [
        "configuration",
        "read_admin",
        "migration",
        "read_api",
        "read_worker",
        "connect",
        "begin",
      ],
      2,
    ],
    [
      { mode: "provision-notifier" },
      ["configuration", "read_admin", "read_notifier", "connect", "begin"],
      1,
    ],
    [{ mode: "seed" }, ["configuration", "read_admin", "seed"], 0],
  ]) {
    const result = runProducer(scenario);
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    assert.deepEqual(result.trace.slice(0, prefix.length), prefix);
    for (const operation of ["alter", "reset", "grant", "membership_lookup"])
      assert.equal(
        result.trace.filter((entry) => entry === operation).length,
        roleCount,
      );
    assert.equal(result.trace.at(-1), roleCount === 0 ? "seed" : "cleanup");
  }
});

test("actual configureLogin binds typed format arguments with quoted passwords on repeat", () => {
  const first = runProducer({ quotePassword: true });
  const repeated = runProducer({ quotePassword: true });
  for (const result of [first, repeated]) {
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    for (const operation of ["alter", "grant", "reset"])
      assert.equal(
        result.trace.filter((entry) => entry === operation).length,
        3,
      );
  }
  assert.deepEqual(repeated.trace, first.trace);
});

test("MinIO diagnostics reconstruct known operations without copying credentials or payloads", () => {
  const result = redactComposeStartupLogs(
    "minio-provision",
    [
      `mc: <ERROR> Unable to initialize new alias from the provided credentials. ${canary}: connection refused`,
      `mc: <ERROR> Invalid secret key \`${canary}\`.`,
      `mc: <ERROR> Unable to set bucket CORS configuration for ${canary}. Not implemented`,
      `mc: <ERROR> Unable to add new user ${canary}. Access Denied`,
      `mkdir: can't create directory '/tmp/${canary}': Read-only file system`,
      `/usr/local/bin/provision-minio: line 9: can't open /run/secrets/${canary}: Permission denied`,
      `\u001b[31mmc: <ERROR> Unable to create new policy ${canary}.\u001b[0m`,
      `mc: <ERROR> ${canary}`,
      `-----BEGIN PRIVATE KEY-----\n${canary}\n-----END PRIVATE KEY-----`,
      `AWS_SECRET_ACCESS_KEY=${canary}`,
    ].join("\n"),
  );
  assert.deepEqual(result.events, [
    {
      kind: "minio_startup",
      operation: "alias_set",
      observedReason: "connection_refused",
    },
    {
      kind: "minio_startup",
      operation: "alias_secret_key_validation",
      observedReason: null,
    },
    {
      kind: "minio_startup",
      operation: "cors_set",
      observedReason: "not_implemented",
    },
    {
      kind: "minio_startup",
      operation: "user_add",
      observedReason: "access_denied",
    },
    {
      kind: "minio_startup",
      operation: "mkdir",
      observedReason: "read_only_filesystem",
    },
    {
      kind: "minio_startup",
      operation: "shell",
      observedReason: "permission_denied",
    },
    { kind: "minio_startup", operation: "policy_create", observedReason: null },
    { kind: "minio_startup", operation: "unclassified", observedReason: null },
  ]);
  assert.equal(result.redactedLines, 4);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private-canary|\/tmp\/|\/run\/|BEGIN PRIVATE|AWS_/u,
  );
});

test("empty, unknown and oversized logs cannot invent a cause or bypass bounds", () => {
  assert.deepEqual(redactComposeStartupLogs("minio-provision", ""), {
    events: [],
    redactedLines: 0,
  });
  assert.deepEqual(redactComposeStartupLogs("postgres", driver("EACCES")), {
    events: [],
    redactedLines: 1,
  });
  const result = redactComposeStartupLogs(
    "migration",
    `${driver("EACCES")}\n`.repeat(500),
  );
  assert.equal(result.events.length, 100);
  assert.equal(result.redactedLines, 0);
  assert.ok(JSON.stringify(result).length < 16_384);
  assert.deepEqual(
    redactComposeStartupLogs("migration", canary.repeat(100_000)),
    { events: [], redactedLines: 1 },
  );
});

test("runtime startup diagnostics retain reviewed failures and redact arbitrary errors", () => {
  assert.deepEqual(
    redactComposeStartupLogs(
      "api",
      JSON.stringify({
        level: "ERROR",
        msg: "api stopped",
        error: `initialize OIDC upstream client\n${canary}\nshutdown API OpenTelemetry runtime`,
      }),
    ).events,
    [
      {
        kind: "runtime_startup",
        error:
          "initialize OIDC upstream client; UNCLASSIFIED; shutdown API OpenTelemetry runtime",
      },
    ],
  );
  for (const service of ["api", "worker"]) {
    const source = [
      {
        level: "ERROR",
        msg: `${service} stopped`,
        error: "create database pool",
        token: canary,
      },
      { level: "ERROR", msg: `${service} stopped`, error: canary },
      { level: "ERROR", msg: `${service} stopped`, error: { value: canary } },
      { level: "INFO", msg: `${service} started`, address: canary },
    ]
      .map((entry) => JSON.stringify(entry))
      .join("\n");
    assert.deepEqual(redactComposeStartupLogs(service, source), {
      events: [
        { kind: "runtime_startup", error: "create database pool" },
        { kind: "runtime_startup", error: "UNCLASSIFIED" },
        { kind: "runtime_startup", error: "UNCLASSIFIED" },
      ],
      redactedLines: 1,
    });
  }
});

test("collector uses at most sixteen bounded read-only commands for six fixed services", () => {
  const calls = [];
  const result = collectComposeStartupDiagnostics((command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === "compose") return success(`${container}\n`);
    if (args[0] === "inspect")
      return success(
        JSON.stringify({ ...state, Error: canary, Config: { Env: [canary] } }),
      );
    return success(canary, driver("EACCES"));
  });
  assert.equal(result.profile, "minimal");
  assert.deepEqual(
    result.services.map((entry) => entry.service),
    ["minio-provision", "migration", "minio", "postgres", "api", "worker"],
  );
  assert.equal(calls.length, 16);
  for (const call of calls) {
    assert.equal(call.command, "docker");
    assert.deepEqual(call.options, {
      encoding: "utf8",
      timeout: 5_000,
      killSignal: "SIGKILL",
      maxBuffer: 65_536,
      windowsHide: true,
    });
    if (call.args[0] === "compose") {
      assert.deepEqual(call.args.slice(0, -1), [
        "compose",
        "--file",
        "deploy/compose/compose.yaml",
        "--profile",
        "minimal",
        "ps",
        "--all",
        "--quiet",
      ]);
    } else if (call.args[0] === "inspect") {
      assert.equal(call.args.length, 4);
      assert.equal(call.args[1], "--format");
      assert.equal(call.args[3], container);
      assert.doesNotMatch(
        call.args[2],
        /\.Config|\.Env|\.Mounts|\.Health\.Log|json \.State\}\}/u,
      );
    } else {
      assert.deepEqual(call.args, ["logs", "--tail", "100", container]);
    }
  }
  assert.equal(calls.filter((call) => call.args[0] === "logs").length, 4);
  for (const entry of result.services) assert.deepEqual(entry.state, state);
  assert.deepEqual(
    result.services.slice(2, 4).map((entry) => entry.logs),
    ["not-collected", "not-collected"],
  );
  assert.doesNotMatch(JSON.stringify(result), new RegExp(canary, "u"));
});

test("failed, overflowing, timed-out and ambiguous lookups cannot expose raw output", () => {
  for (const failed of [
    { ...success(canary), status: 1 },
    { ...success(canary), signal: "SIGKILL" },
    { ...success(canary), error: new Error(canary) },
    success(`${container}\n${container}`),
    success(canary),
    success(""),
  ]) {
    let calls = 0;
    const result = collectComposeStartupDiagnostics(() => {
      calls += 1;
      return failed;
    });
    assert.equal(calls, 6);
    assert.ok(result.services.every((entry) => entry.state === "unavailable"));
    assert.doesNotMatch(JSON.stringify(result), new RegExp(canary, "u"));
  }
  assert.ok(
    collectComposeStartupDiagnostics(() => {
      throw new Error(canary);
    }).services.every((entry) => entry.state === "unavailable"),
  );
});

test("invalid state and failed logs are independently withheld", () => {
  for (const invalid of [
    canary,
    "null",
    JSON.stringify({ ...state, exitCode: 256 }),
    JSON.stringify({ ...state, health: canary }),
    JSON.stringify({ ...state, status: canary }),
    JSON.stringify({ ...state, oomKilled: canary }),
  ]) {
    const result = collectComposeStartupDiagnostics((_command, args) => {
      if (args[0] === "compose") return success(container);
      if (args[0] === "inspect") return success(invalid);
      return success("", driver("EXIT_1"));
    });
    assert.ok(result.services.every((entry) => entry.state === "unavailable"));
    assert.deepEqual(result.services[1].logs.events, [
      databaseDriver("EXIT_1"),
    ]);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(canary, "u"));
  }
  const result = collectComposeStartupDiagnostics((_command, args) => {
    if (args[0] === "compose") return success(container);
    if (args[0] === "inspect") return success(JSON.stringify(state));
    return { ...success(canary), status: 1 };
  });
  assert.deepEqual(result.services[0].state, state);
  assert.equal(result.services[0].logs, "unavailable");
});

function assertWorkflow(source) {
  const start = source.indexOf("\n  containers:\n");
  assert.ok(start > 0);
  const job = source.slice(
    start,
    source.indexOf("\n  postgres-security-upgrades:\n", start),
  );
  const diagnostic =
    "      - name: Collect bounded redacted minimal startup diagnostics\n";
  const begin = job.indexOf(diagnostic);
  const end = job.indexOf("      - name: Stop minimal stack\n");
  assert.ok(
    begin > job.indexOf("      - name: Wait for service health\n") &&
      begin < end,
  );
  assert.equal(
    job.slice(begin, end),
    `${diagnostic}        if: \${{ failure() && (steps.minimal-stack-start.outcome == 'failure' || steps.minimal-stack-start.outcome == 'success') }}\n        timeout-minutes: 2\n        run: node scripts/deploy/compose-startup-diagnostics.mjs\n`,
  );
  assert.match(
    job,
    /- name: Start hardened minimal stack\n        id: minimal-stack-start\n        run: docker compose --file deploy\/compose\/compose.yaml --profile minimal up --detach --no-build/u,
  );
  assert.match(
    job.slice(end),
    /^      - name: Stop minimal stack\n        if: always\(\)\n        run: docker compose --file deploy\/compose\/compose.yaml --profile minimal down --volumes --remove-orphans/u,
  );
  assert.doesNotMatch(job, /--profile minimal (?:logs\b|ps --all\s*$)/mu);
  assert.match(
    job,
    /if \[ "\$\{healthy\}" != "true" \]; then\n            exit 1\n          fi/u,
  );
  assert.match(source, /run: pnpm test:operations\s*$/mu);
}

test("CI retains fail-closed smoke and always teardown with redacted evidence after failed up", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  );
  assert.ok(
    manifest.scripts["test:operations"]
      .split(" ")
      .includes("scripts/deploy/compose-startup-diagnostics.test.mjs"),
  );
  const source = (
    await readFile(
      new URL("../../.github/workflows/ci.yml", import.meta.url),
      "utf8",
    )
  ).replaceAll("\r\n", "\n");
  assertWorkflow(source);
  for (const mutated of [
    source.replace("id: minimal-stack-start", "id: wrong-step"),
    source.replace(
      "failure() && (steps.minimal-stack-start",
      "success() && (steps.minimal-stack-start",
    ),
    source.replace(
      "run: node scripts/deploy/compose-startup-diagnostics.mjs",
      "run: docker compose --file deploy/compose/compose.yaml --profile minimal logs --no-color",
    ),
    source.replace(
      "if: always()\n        run: docker compose --file deploy/compose/compose.yaml --profile minimal down",
      "if: success()\n        run: docker compose --file deploy/compose/compose.yaml --profile minimal down",
    ),
    source.replace("run: pnpm test:operations", "run: pnpm test:other"),
  ])
    assert.throws(() => assertWorkflow(mutated));
});
