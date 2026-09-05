import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import test from "node:test";

import {
  runIntegrationSuite,
  selectIntegrationSuite,
} from "../run-integration.mjs";

test("integration selector defaults to auth and rejects unsupported values", () => {
  assert.equal(basename(selectIntegrationSuite({}).script), "auth-smoke.mjs");
  assert.throws(
    () => selectIntegrationSuite({ PERIAPSIS_INTEGRATION_SUITE: "both" }),
    /unsupported PERIAPSIS_INTEGRATION_SUITE "both"/u,
  );
});

test("integration selector maps each accepted value to one bounded suite", () => {
  assert.equal(
    basename(
      selectIntegrationSuite({ PERIAPSIS_INTEGRATION_SUITE: "auth" }).script,
    ),
    "auth-smoke.mjs",
  );
  assert.equal(
    basename(
      selectIntegrationSuite({ PERIAPSIS_INTEGRATION_SUITE: " ldap " }).script,
    ),
    "ldap-auth-acceptance.mjs",
  );
});

test("the default auth suite targets the published local TLS edge", async () => {
  const source = await readFile(
    new URL("../../tests/integration/auth-smoke.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /PERIAPSIS_SMOKE_BASE_URL \?\? "https:\/\/localhost:8443"/u,
  );
  assert.doesNotMatch(source, /"http:\/\/localhost:18081"/u);
});

test("integration runner launches exactly the selected suite without a shell", () => {
  const calls = [];
  const environment = {
    PERIAPSIS_INTEGRATION_SUITE: "ldap",
    PERIAPSIS_LDAP_ACCEPTANCE_BASE_URL: "https://localhost:18081",
  };
  const status = runIntegrationSuite(environment, (...args) => {
    calls.push(args);
    return { status: 0 };
  });

  assert.equal(status, 0);
  assert.equal(calls.length, 1);
  const [command, args, options] = calls[0];
  assert.equal(command, process.execPath);
  assert.deepEqual(
    args.map((value) => basename(value)),
    ["ldap-auth-acceptance.mjs"],
  );
  assert.equal(options.env, environment);
  assert.equal(options.stdio, "inherit");
  assert.equal(Object.hasOwn(options, "shell"), false);
});

test("integration runner preserves a selected suite failure status", () => {
  const status = runIntegrationSuite(
    { PERIAPSIS_INTEGRATION_SUITE: "auth" },
    () => ({ status: 17 }),
  );
  assert.equal(status, 17);
});
