import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";

const authorityA = Buffer.alloc(32, 0xa1);
const authorityB = Buffer.alloc(32, 0xa2);
const verifierA = Buffer.alloc(32, 0xf1);
const verifierB = Buffer.alloc(32, 0xf2);

type ConfigurationRow = {
  authority_token_digest: Buffer | null;
  authority_configured_at: Date | null;
  master_key_verifier: Buffer | null;
  master_key_verifier_bound_at: Date | null;
  completed_at: Date | null;
};

type ErrorWithCode = Error & { code?: string };

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

function withTimeout<T>(promise: Promise<T>, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), 5_000);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function callAsApi(
  sql: Sql,
  authority: Buffer | null,
  verifier: Buffer | null,
): Promise<boolean> {
  return sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    const [result] = await transaction<{ available: boolean }[]>`
      SELECT app.verify_protected_configuration(
        ${authority}::bytea,
        ${verifier}::bytea
      ) AS available
    `;
    assert(result, "protected-configuration verifier returned no row");
    return result.available;
  });
}

async function readConfiguration(sql: Sql): Promise<ConfigurationRow> {
  const [state] = await sql<ConfigurationRow[]>`
    SELECT authority_token_digest, authority_configured_at,
           master_key_verifier, master_key_verifier_bound_at, completed_at
    FROM public.platform_bootstrap_state
    WHERE singleton = true
  `;
  assert(state, "bootstrap singleton is missing");
  return state;
}

function assertUnconfigured(state: ConfigurationRow): void {
  assert.equal(state.authority_token_digest, null);
  assert.equal(state.authority_configured_at, null);
  assert.equal(state.master_key_verifier, null);
  assert.equal(state.master_key_verifier_bound_at, null);
  assert.equal(state.completed_at, null);
}

async function waitForRowLock(sql: Sql, processID: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  const poll = async (): Promise<void> => {
    const [activity] = await sql<
      { wait_event_type: string | null; wait_event: string | null }[]
    >`
      SELECT wait_event_type, wait_event
      FROM pg_catalog.pg_stat_activity
      WHERE pid = ${processID}
    `;
    if (activity?.wait_event_type === "Lock") {
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        "concurrent verifier did not wait on the bootstrap row lock",
      );
    }
    await delay(20);
    return poll();
  };
  return poll();
}

const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseURL, { max: 1, onnotice: () => undefined });
let ownsFreshFixture = false;
let releaseWinningTransaction: (() => void) | undefined;

try {
  const enrollmentRows = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.platform_bootstrap_enrollments
  `;
  assert.equal(
    enrollmentRows[0]?.count,
    0,
    "security test requires a freshly migrated database without enrollments",
  );
  assertUnconfigured(await readConfiguration(admin));
  ownsFreshFixture = true;

  await assert.rejects(
    callAsApi(winner, authorityA.subarray(0, 31), verifierA),
    (error) => assertSqlState(error, "22023"),
  );
  await assert.rejects(callAsApi(winner, authorityA, null), (error) =>
    assertSqlState(error, "22023"),
  );
  assertUnconfigured(await readConfiguration(admin));

  const rollbackMarker = new Error(
    "intentional protected-configuration rollback",
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [result] = await transaction<{ available: boolean }[]>`
        SELECT app.verify_protected_configuration(
          ${authorityA}::bytea,
          ${verifierA}::bytea
        ) AS available
      `;
      assert.equal(result?.available, true);
      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
  assertUnconfigured(await readConfiguration(admin));

  const winnerReady = Promise.withResolvers<void>();
  const releaseWinner = Promise.withResolvers<void>();
  releaseWinningTransaction = releaseWinner.resolve;
  const contenderPID = Promise.withResolvers<number>();

  const winnerTransaction = winner.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    const [result] = await transaction<{ available: boolean }[]>`
      SELECT app.verify_protected_configuration(
        ${authorityA}::bytea,
        ${verifierA}::bytea
      ) AS available
    `;
    assert.equal(result?.available, true);
    winnerReady.resolve();
    await releaseWinner.promise;
    return result.available;
  });
  const winnerOutcome = winnerTransaction.then(
    (available) => ({ available }),
    (error: unknown) => ({ error }),
  );

  const winnerStart = await Promise.race([
    winnerReady.promise.then(() => "ready" as const),
    winnerOutcome.then(() => "settled" as const),
  ]);
  assert.equal(winnerStart, "ready", "winning verifier failed before binding");

  const contenderTransaction = contender.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    const [backend] = await transaction<{ pid: number }[]>`
      SELECT pg_catalog.pg_backend_pid() AS pid
    `;
    assert(backend, "contender connection has no backend PID");
    contenderPID.resolve(backend.pid);
    const [result] = await transaction<{ available: boolean }[]>`
      SELECT app.verify_protected_configuration(
        ${authorityB}::bytea,
        ${verifierB}::bytea
      ) AS available
    `;
    assert(result, "contending verifier returned no row");
    return result.available;
  });
  const contenderOutcome = contenderTransaction.then(
    (available) => ({ available }),
    (error: unknown) => ({ error }),
  );

  try {
    const processID = await withTimeout(
      contenderPID.promise,
      "contending verifier did not start",
    );
    const concurrencyState = await Promise.race([
      waitForRowLock(admin, processID).then(() => "locked" as const),
      contenderOutcome.then(() => "settled" as const),
    ]);
    assert.equal(
      concurrencyState,
      "locked",
      "contending verifier completed before the winning transaction",
    );
  } finally {
    releaseWinner.resolve();
    releaseWinningTransaction = undefined;
  }

  const firstOutcome = await withTimeout(
    winnerOutcome,
    "winning verifier did not commit",
  );
  assert("available" in firstOutcome);
  assert.equal(firstOutcome.available, true);

  const secondOutcome = await withTimeout(
    contenderOutcome,
    "contending verifier did not finish after the lock was released",
  );
  assert(
    "error" in secondOutcome,
    "mismatched contender unexpectedly succeeded",
  );
  assertSqlState(secondOutcome.error, "42501");

  await assert.rejects(callAsApi(winner, authorityB, verifierA), (error) =>
    assertSqlState(error, "42501"),
  );
  await assert.rejects(callAsApi(winner, authorityA, verifierB), (error) =>
    assertSqlState(error, "42501"),
  );
  assert.equal(await callAsApi(winner, authorityA, verifierA), true);

  const state = await readConfiguration(admin);
  assert.deepEqual(state.authority_token_digest, authorityA);
  assert(state.authority_configured_at);
  assert.deepEqual(state.master_key_verifier, verifierA);
  assert(state.master_key_verifier_bound_at);
  assert.equal(state.completed_at, null);

  process.stdout.write(
    "bootstrap protected-configuration rollback and concurrency checks passed\n",
  );
} finally {
  releaseWinningTransaction?.();
  if (ownsFreshFixture) {
    await admin`
      UPDATE public.platform_bootstrap_state
      SET authority_token_digest = NULL,
          authority_configured_at = NULL,
          master_key_verifier = NULL,
          master_key_verifier_bound_at = NULL
      WHERE singleton = true AND completed_at IS NULL
    `;
  }
  await Promise.allSettled([admin.end(), winner.end(), contender.end()]);
}
