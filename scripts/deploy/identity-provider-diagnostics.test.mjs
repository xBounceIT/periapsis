import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  collectIdentityProviderDiagnostics,
  redactIdentityProviderLogs,
} from "./identity-provider-diagnostics.mjs";

const container = "b".repeat(64);
const privateText = "private-fixture-canary-never-print";
const state = {
  status: "exited",
  exitCode: 1,
  oomKilled: false,
  errorPresent: false,
  health: "unhealthy",
};
const success = (stdout = "", stderr = "") => ({
  status: 0,
  signal: null,
  stdout,
  stderr,
});
const read = (relative) =>
  readFileSync(new URL(`../../${relative}`, import.meta.url), "utf8");

test("identity-provider diagnostics reconstruct only fixed observed error categories", () => {
  const result = redactIdentityProviderLogs(
    [
      `ERROR: File name / realm name mismatch. ${privateText}-realm.json, contains realm ${privateText}`,
      `2026-09-06 14:59:40,100 ERROR [org.keycloak.quarkus.runtime.cli.ExecutionExceptionHandler] (main) ERROR: Failed to run import ${privateText}`,
      `ERROR: Key material not provided to setup HTTPS. ${privateText}`,
      `ERROR: hostname is not configured; ${privateText}`,
      `ERROR: Provided hostname is neither a plain hostname nor a valid URL ${privateText}`,
      `ERROR: The '--optimized' flag was used for first ever server start. ${privateText}`,
      `ERROR: /opt/keycloak/data/${privateText}: Read-only file system`,
      `ERROR: /opt/keycloak/data/${privateText}: Permission denied`,
      `Caused by: java.nio.file.AccessDeniedException: /${privateText}`,
      `ERROR: Operation not permitted ${privateText}`,
      `ERROR: No such file or directory ${privateText}`,
      `Caused by: java.nio.file.NoSuchFileException: /${privateText}`,
      `ERROR: Failed to obtain JDBC connection ${privateText}`,
      `ERROR: Address already in use ${privateText}`,
      `Caused by: java.lang.OutOfMemoryError: ${privateText}`,
      `ERROR: Unknown option: ${privateText}`,
      `ERROR: Failed to start server in (production) mode ${privateText}`,
      `ERROR: Failed to run 'start' command. ${privateText}`,
    ].join("\n"),
  );
  assert.deepEqual(
    result.events.map((event) => event.category),
    [
      "realm_filename_mismatch",
      "startup_import_failed",
      "https_key_material_missing",
      "hostname_missing",
      "hostname_invalid",
      "optimized_build_missing",
      "read_only_filesystem",
      "permission_denied",
      "permission_denied",
      "operation_not_permitted",
      "file_missing",
      "file_missing",
      "database_connection_failed",
      "address_in_use",
      "out_of_memory",
      "unknown_option",
      "startup_failed",
      "startup_failed",
    ],
  );
  assert.equal(result.redactedLines, 0);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private-fixture|keycloak\/data|https?:|ERROR:|realm\.json/u,
  );
});

test("identity-provider diagnostics withhold unknown errors, realms, credentials and escape sequences", () => {
  const result = redactIdentityProviderLogs(
    [
      `KC_BOOTSTRAP_ADMIN_PASSWORD=${privateText}`,
      `https://user:${privateText}@idp.invalid/${privateText}`,
      `dn: cn=${privateText},dc=private`,
      `{"realm":"${privateText}","assertion":"${privateText}"}`,
      `-----BEGIN PRIVATE KEY-----\n${privateText}\n-----END PRIVATE KEY-----`,
      `ERROR: ${privateText}`,
      `INFO File name / realm name mismatch. ${privateText}`,
      `::error::${privateText}`,
      `\u001b[31mERROR: Permission denied ${privateText}\u001b[0m`,
    ].join("\n"),
  );
  assert.deepEqual(result.events, [
    { tailLine: 11, category: "permission_denied" },
  ]);
  assert.equal(result.redactedLines, 10);
  assert.doesNotMatch(
    JSON.stringify(result),
    /private|https?:|dn:|PASSWORD|PRIVATE KEY|assertion/u,
  );
  assert.equal(JSON.stringify(result).includes("\\u001b"), false);
});

test("identity-provider log tails and output stay bounded", () => {
  const result = redactIdentityProviderLogs(
    "ERROR: Permission denied\n".repeat(500),
  );
  assert.equal(result.events.length, 100);
  assert.ok(JSON.stringify(result).length < 8192);
  assert.deepEqual(redactIdentityProviderLogs("x".repeat(1_000_000)), {
    events: [],
    redactedLines: 1,
  });
  assert.deepEqual(redactIdentityProviderLogs(""), {
    events: [],
    redactedLines: 0,
  });
});

test("both allowed profiles issue only three bounded read-only Docker commands", () => {
  for (const profile of ["auth-test", "full"]) {
    const calls = [];
    const result = collectIdentityProviderDiagnostics(
      profile,
      (command, args, options) => {
        calls.push({ command, args, options });
        if (calls.length === 1) return success(`${container}\n`);
        if (calls.length === 2)
          return success(
            JSON.stringify({
              ...state,
              Config: { Env: [privateText] },
              Error: privateText,
            }),
          );
        return success(
          "",
          `ERROR: File name / realm name mismatch. ${privateText}`,
        );
      },
    );
    assert.deepEqual(result.state, state);
    assert.deepEqual(result.logs, {
      events: [{ tailLine: 2, category: "realm_filename_mismatch" }],
      redactedLines: 0,
    });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(privateText, "u"));
    assert.equal(calls.length, 3);
    for (const call of calls) {
      assert.equal(call.command, "docker");
      assert.equal(call.options.timeout, 5000);
      assert.equal(call.options.maxBuffer, 65_536);
      assert.equal(call.options.killSignal, "SIGKILL");
      assert.equal(call.options.windowsHide, true);
    }
    assert.deepEqual(calls[0].args, [
      "compose",
      "--file",
      "deploy/compose/compose.yaml",
      "--profile",
      profile,
      "ps",
      "--all",
      "--quiet",
      "identity-provider",
    ]);
    assert.equal(calls[1].args[0], "inspect");
    assert.doesNotMatch(
      calls[1].args[2],
      /\.Config|\.Env|\.Health\.Log|json \.State\}\}/u,
    );
    assert.deepEqual(calls[2].args, ["logs", "--tail", "100", container]);
  }
});

test("unexpected profile or container cannot become a Docker target", () => {
  assert.throws(
    () =>
      collectIdentityProviderDiagnostics(privateText, () =>
        assert.fail("must not run"),
      ),
    /unsupported identity provider profile/u,
  );
  for (const invalid of [
    privateText,
    `${container}\n${container}`,
    "",
    `--${container}`,
  ]) {
    let calls = 0;
    const result = collectIdentityProviderDiagnostics("auth-test", () => {
      calls++;
      return success(invalid);
    });
    assert.equal(calls, 1);
    assert.deepEqual(result, {
      service: "identity-provider",
      state: "unavailable",
      logs: "unavailable",
    });
  }
});

test("lookup errors and timeouts never disclose free-form output", () => {
  for (const failure of [
    { ...success(privateText), status: 1 },
    { ...success(privateText), signal: "SIGKILL" },
    { ...success(privateText), error: new Error(privateText) },
    { ...success(), stdout: undefined },
  ]) {
    const result = collectIdentityProviderDiagnostics("full", () => failure);
    assert.deepEqual(result, {
      service: "identity-provider",
      state: "unavailable",
      logs: "unavailable",
    });
  }
  assert.equal(
    collectIdentityProviderDiagnostics("full", () => {
      throw new Error(privateText);
    }).state,
    "unavailable",
  );
});

test("invalid states are withheld while independent safe logs remain available", () => {
  for (const invalid of [
    privateText,
    ...[
      { status: privateText },
      { exitCode: 256 },
      { exitCode: -1 },
      { exitCode: "1" },
      { oomKilled: privateText },
      { errorPresent: privateText },
      { health: privateText },
    ].map((override) => JSON.stringify({ ...state, ...override })),
  ]) {
    let calls = 0;
    const result = collectIdentityProviderDiagnostics("full", () => {
      calls++;
      if (calls === 1) return success(container);
      return calls === 2
        ? success(invalid)
        : success(`ERROR: Permission denied ${privateText}`);
    });
    assert.equal(result.state, "unavailable");
    assert.equal(result.logs.events[0].category, "permission_denied");
    assert.doesNotMatch(JSON.stringify(result), new RegExp(privateText, "u"));
  }
});

test("inspect and log command failures remain independent and redacted", () => {
  for (const failingCall of [2, 3]) {
    let calls = 0;
    const result = collectIdentityProviderDiagnostics("auth-test", () => {
      calls++;
      if (calls === failingCall) throw new Error(privateText);
      if (calls === 1) return success(container);
      return calls === 2
        ? success(JSON.stringify(state))
        : success(`ERROR: Permission denied ${privateText}`);
    });
    assert.equal(calls, 3);
    if (failingCall === 2) {
      assert.equal(result.state, "unavailable");
      assert.equal(result.logs.events.length, 1);
    } else {
      assert.deepEqual(result.state, state);
      assert.equal(result.logs, "unavailable");
    }
  }
});

test("startup directory import filename matches the declared Keycloak realm", () => {
  // Keycloak 26.7.2 DirImportProvider.java:106-134 derives the realm from the
  // *-realm.json basename and throws if JSON.realm disagrees. Startup import
  // routes these files to this provider, not the permissive single-file provider.
  const realm = JSON.parse(read("deploy/compose/auth/keycloak-realm.json"));
  assert.match(realm.realm, /^[a-z0-9-]+$/u);
  const compose = read("deploy/compose/compose.base.yaml");
  const block = compose.slice(
    compose.indexOf("  identity-provider:"),
    compose.indexOf("  mailpit:"),
  );
  const mounts = [
    ...block.matchAll(
      /- \.\/auth\/keycloak-realm\.json:(\/opt\/keycloak\/data\/import\/[^:\s]+):ro/gu,
    ),
  ];
  assert.equal(mounts.length, 1);
  const expected = `/opt/keycloak/data/import/${realm.realm}-realm.json`;
  assert.equal(mounts[0][1], expected);
  assert.notEqual(
    "/opt/keycloak/data/import/periapsis-realm.json",
    expected,
    "the previously published mount must remain a negative control",
  );
  assert.match(block, /- --optimized\n\s+- --import-realm/u);
  assert.match(block, /read_only: true/u);
  assert.match(block, /cap_drop:\n\s+- ALL/u);
});

test("both workflow failure paths collect IdP diagnostics before teardown", () => {
  for (const [workflow, profile, startId, teardown] of [
    [
      ".github/workflows/deployment-security.yml",
      "auth-test",
      "auth-provider-smoke",
      "Tear down authentication smoke profile",
    ],
    [
      ".github/workflows/ci.yml",
      "full",
      "full-stack-start",
      "Stop composed full acceptance stack",
    ],
  ]) {
    const source = read(workflow);
    const command = `node scripts/deploy/identity-provider-diagnostics.mjs ${profile}`;
    const index = source.indexOf(command);
    assert.notEqual(index, -1);
    assert.ok(index < source.indexOf(`- name: ${teardown}`));
    const preceding = source.slice(
      source.lastIndexOf("      - name:", index),
      index,
    );
    assert.match(preceding, /timeout-minutes: 1/u);
    assert.ok(preceding.includes(`failure() && steps.${startId}.outcome`));
    assert.ok(source.includes(`id: ${startId}`));
  }
  const scripts = JSON.parse(read("package.json")).scripts;
  assert.ok(
    scripts["test:operations"].includes(
      "scripts/deploy/identity-provider-diagnostics.test.mjs",
    ),
  );
});
