import assert from "node:assert/strict";
import test from "node:test";
import {
  collectOpenLdapDiagnostics,
  redactStartupLogs,
} from "./openldap-diagnostics.mjs";

const container = "a".repeat(64);
const state = {
  status: "exited",
  exitCode: 1,
  oomKilled: false,
  errorPresent: false,
  health: "unhealthy",
};

function success(stdout = "", stderr = "") {
  return { status: 0, signal: null, stdout, stderr };
}

test("LDAP diagnostics redact free-form logs while retaining safe filesystem errors", () => {
  const privateText = "private-canary-never-print";
  const result = redactStartupLogs(
    [
      `password=${privateText}`,
      `-----BEGIN PRIVATE KEY-----\n${privateText}\n-----END PRIVATE KEY-----`,
      `chown: changing ownership of '/etc/ldap/${privateText}': Read-only file system`,
      `mkdir: cannot create directory '/run/slapd/${privateText}': Permission denied`,
      `chown: '${privateText}': Operation not permitted`,
      `::warning::${privateText}`,
    ].join("\n"),
  );
  assert.doesNotMatch(JSON.stringify(result), new RegExp(privateText, "u"));
  assert.deepEqual(result.filesystemErrors, [
    {
      tailLine: 5,
      operation: "chown",
      pathRoot: "/etc/ldap",
      reason: "Read-only file system",
    },
    {
      tailLine: 6,
      operation: "mkdir",
      pathRoot: "/run/slapd",
      reason: "Permission denied",
    },
    {
      tailLine: 7,
      operation: "chown",
      pathRoot: null,
      reason: "Operation not permitted",
    },
  ]);
  assert.equal(result.redactedLines, 5);
});

test("LDAP log evidence is capped at 100 lines with no unbounded free-form values", () => {
  const result = redactStartupLogs(
    "chown: '/tmp/x': Permission denied\n".repeat(500),
  );
  assert.equal(result.filesystemErrors.length, 100);
  assert.equal(result.redactedLines, 0);
  assert.ok(JSON.stringify(result).length < 16_384);
  assert.equal(redactStartupLogs("x".repeat(1_000_000)).redactedLines, 1);
});

test("LDAP collection only uses three bounded read-only commands and allowlisted state", () => {
  const calls = [];
  const result = collectOpenLdapDiagnostics((command, args, options) => {
    calls.push({ command, args, options });
    if (calls.length === 1) return success(`${container}\n`);
    if (calls.length === 2) {
      return success(
        JSON.stringify({
          ...state,
          Error: "private-state-canary",
          Config: { Env: ["private-env-canary"] },
        }),
      );
    }
    return success("", "chown: '/etc/ldap/x': Read-only file system\n");
  });
  assert.deepEqual(result.state, state);
  assert.doesNotMatch(JSON.stringify(result), /private-.*-canary/u);
  assert.equal(result.logs.filesystemErrors.length, 1);
  assert.equal(calls.length, 3);
  for (const call of calls) {
    assert.equal(call.command, "docker");
    assert.equal(call.options.timeout, 10_000);
    assert.equal(call.options.maxBuffer, 65_536);
    assert.equal(call.options.killSignal, "SIGKILL");
  }
  assert.deepEqual(calls[0].args, [
    "compose",
    "--file",
    "deploy/compose/compose.yaml",
    "--profile",
    "auth-test",
    "ps",
    "--all",
    "--quiet",
    "openldap",
  ]);
  assert.equal(calls[1].args[0], "inspect");
  assert.doesNotMatch(
    calls[1].args[2],
    /\.Config|\.Env|\.Health\.Log|json \.State\}\}/u,
  );
  assert.deepEqual(calls[2].args, ["logs", "--tail", "100", container]);
});

test("LDAP command errors, timeouts and unexpected containers never disclose raw output", () => {
  for (const failure of [
    { ...success("private-canary"), status: 1 },
    { ...success("private-canary"), signal: "SIGKILL" },
    { ...success("private-canary"), error: new Error("private-canary") },
    success(`${container}\n${container}`),
    success("private-canary"),
  ]) {
    let calls = 0;
    const result = collectOpenLdapDiagnostics(() => {
      calls += 1;
      return failure;
    });
    assert.equal(calls, 1);
    assert.deepEqual(result, {
      service: "openldap",
      state: "unavailable",
      logs: "unavailable",
    });
  }
});

test("LDAP malformed state is withheld without preventing independent redacted logs", () => {
  for (const invalid of [
    "private-canary",
    JSON.stringify({ ...state, status: "private-canary" }),
    JSON.stringify({ ...state, exitCode: "private-canary" }),
  ]) {
    let calls = 0;
    const result = collectOpenLdapDiagnostics(() => {
      calls += 1;
      if (calls === 1) return success(container);
      return calls === 2 ? success(invalid) : success("private-canary");
    });
    assert.equal(result.state, "unavailable");
    assert.deepEqual(result.logs, {
      filesystemErrors: [],
      bootstrapErrors: [],
      redactedLines: 1,
    });
  }
});

test("owned LDAP bootstrap diagnostics accept only exact fixed stage codes", () => {
  const result = redactStartupLogs(
    [
      "PERIAPSIS_OPENLDAP_ERROR stage=config_import",
      "PERIAPSIS_OPENLDAP_ERROR stage=private-value",
      "PERIAPSIS_OPENLDAP_ERROR stage=tls private-value",
      "private-value PERIAPSIS_OPENLDAP_ERROR stage=storage",
      "PERIAPSIS_OPENLDAP_ERROR stage=existing_state",
    ].join("\n"),
  );
  assert.deepEqual(result.bootstrapErrors, [
    { tailLine: 1, stage: "config_import" },
    { tailLine: 5, stage: "existing_state" },
  ]);
  assert.equal(result.redactedLines, 3);
  assert.doesNotMatch(JSON.stringify(result), /private-value/u);
});
