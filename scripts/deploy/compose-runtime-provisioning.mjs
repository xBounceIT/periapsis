// Runs only against the dedicated disposable PostgreSQL CI cluster.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { compileFunction } from "node:vm";

const databaseUrl = process.env.PERIAPSIS_COMPOSE_PROVISION_TEST_DATABASE_URL;
assert.ok(
  databaseUrl,
  "a dedicated Compose provisioning test database is required",
);
const require = createRequire(
  new URL("../../packages/db/package.json", import.meta.url),
);
const postgres = require("postgres");
const source = await readFile(
  new URL("../../deploy/compose/database-task.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf("async function provisionRuntimeLogins(");
assert.ok(start >= 0, "cannot locate the actual Compose provisioner");
// Execute the actual SQL-producing functions without invoking the CLI migration
// or reading mounted deployment secrets. This is trusted repository source.
const provision = compileFunction(
  `${source.slice(start)}\nreturn provisionRuntimeLogins;`,
  ["postgres"],
)(postgres);
let sql;
let phase = "connect";
async function assertReady(expected) {
  const [state] =
    await sql`SELECT app.release_runtime_schema_readiness_v52() AS ready`;
  assert.equal(
    state?.ready,
    expected,
    "unexpected schema attestation after provisioning",
  );
}
try {
  sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
  phase = "initial_attestation";
  await assertReady(true);
  const [notifier] =
    await sql`SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notifier_login'`;
  assert.ok(
    !notifier?.rolcanlogin,
    "test requires an inactive notifier in its disposable cluster",
  );
  // Reproduce the former minimal-stack placeholder without granting access.
  phase = "legacy_placeholder";
  await sql.unsafe(`DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'periapsis_notifier_login') THEN
      CREATE ROLE periapsis_notifier_login NOLOGIN;
    END IF;
    ALTER ROLE periapsis_notifier_login CONNECTION LIMIT -1;
    REVOKE periapsis_notifier FROM periapsis_notifier_login;
  END $test$`);
  await assertReady(false);
  const passwords = {
    api: randomBytes(32).toString("hex"),
    worker: randomBytes(32).toString("hex"),
  };
  phase = "minimal_repair";
  await provision(databaseUrl, passwords, { webhookPlainLocalOptIn: true });
  await assertReady(true);
  const [pending] =
    await sql`SELECT NOT rolcanlogin AND rolconnlimit = 20 AS safe FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notifier_login'`;
  assert.equal(
    pending?.safe,
    true,
    "minimal provisioning must keep the notifier inactive",
  );
  phase = "minimal_repeat";
  await provision(databaseUrl, passwords, { webhookPlainLocalOptIn: true });
  await assertReady(true);
  phase = "notifier_activation";
  await provision(
    databaseUrl,
    { notifier: randomBytes(32).toString("hex") },
    { webhookPlainLocalOptIn: true },
  );
  await provision(databaseUrl, passwords, { webhookPlainLocalOptIn: true });
  await assertReady(true);
  const [active] =
    await sql`SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notifier_login'`;
  assert.equal(
    active?.rolcanlogin,
    true,
    "minimal reprovisioning must preserve an active notifier",
  );
  console.log(
    "Compose pending-role repair, activation and reprovisioning passed.",
  );
} catch {
  // Never print a PostgreSQL error that could contain generated role credentials.
  process.stderr.write(
    `Compose runtime provisioning regression failed: ${phase}\n`,
  );
  process.exitCode = 1;
} finally {
  if (sql) await sql.end({ timeout: 5 });
}
