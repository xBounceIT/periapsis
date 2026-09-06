import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

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
    { kind: "database_driver", code: "EXIT_1" },
    { kind: "database_error_property", code: "42702" },
    { kind: "database_error_property", code: "MIGRATION_SEALER_DIVERGED" },
    { kind: "database_driver", code: "EACCES" },
    { kind: "database_driver", code: "SIGNAL_SIGILL" },
    { kind: "database_driver", code: "28P01" },
  ]);
  assert.equal(result.redactedLines, 8);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private|password|postgresql|ALTER ROLE|::error/iu,
  );
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

test("collector uses at most ten bounded read-only commands for four fixed services", () => {
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
    ["minio-provision", "migration", "minio", "postgres"],
  );
  assert.equal(calls.length, 10);
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
  assert.equal(calls.filter((call) => call.args[0] === "logs").length, 2);
  for (const entry of result.services) assert.deepEqual(entry.state, state);
  assert.deepEqual(
    result.services.slice(2).map((entry) => entry.logs),
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
    assert.equal(calls, 4);
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
      { kind: "database_driver", code: "EXIT_1" },
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
    `${diagnostic}        if: \${{ failure() && (steps.minimal-stack-start.outcome == 'failure' || steps.minimal-stack-start.outcome == 'success') }}\n        timeout-minutes: 1\n        run: node scripts/deploy/compose-startup-diagnostics.mjs\n`,
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
  assert.match(
    source,
    /run: node --test scripts\/deploy\/validate-manifests\.test\.mjs scripts\/deploy\/compose-startup-diagnostics\.test\.mjs/u,
  );
}

test("CI retains fail-closed smoke and always teardown with redacted evidence after failed up", async () => {
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
    source.replace(
      "scripts/deploy/compose-startup-diagnostics.test.mjs",
      "scripts/deploy/other.test.mjs",
    ),
  ])
    assert.throws(() => assertWorkflow(mutated));
});
