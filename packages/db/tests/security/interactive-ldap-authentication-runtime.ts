import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_INTERACTIVE_LDAP_AUTH_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_INTERACTIVE_LDAP_AUTH_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const runtimeRoles = [
  "periapsis_api",
  "periapsis_worker",
  "periapsis_notifier",
  "periapsis_auditor",
] as const;

const uuid = (sequence: number): string =>
  `019d2fa7-2000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): Buffer =>
  createHash("sha256").update(`interactive-ldap-runtime:${label}`).digest();

function assertSqlState(
  error: unknown,
  expected: string,
): asserts error is ErrorWithCode {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
}

async function asRole<T>(
  role: (typeof runtimeRoles)[number],
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function readiness(): Promise<boolean> {
  const [row] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v50() AS ready
      `,
  );
  assert(row, "interactive LDAP readiness returned no row");
  return row.ready;
}

async function bestEffort(statement: string): Promise<void> {
  try {
    await sql.unsafe(statement);
  } catch {
    // Preserve the original assertion while restoring the isolated database.
  }
}

async function forEachSequential<T>(
  values: readonly T[],
  operation: (value: T) => Promise<void>,
  index = 0,
): Promise<void> {
  const value = values[index];
  if (value === undefined) return;
  await operation(value);
  await forEachSequential(values, operation, index + 1);
}

const networkRateKey = digest("network");
const accountRateKey = digest("account");
const providerRateKey = digest("provider");

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    version?.version.startsWith("18."),
    "interactive LDAP security harness requires PostgreSQL 18",
  );
  assert.equal(await readiness(), true);

  const [surface] = await sql<
    {
      relation_count: number;
      exact_policy_count: number;
      api_direct_count: number;
      worker_direct_count: number;
    }[]
  >`
    SELECT count(*)::integer AS relation_count,
      count(*) FILTER (
        WHERE relation.relrowsecurity AND relation.relforcerowsecurity
          AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_migrator'
      )::integer AS exact_policy_count,
      count(*) FILTER (
        WHERE pg_catalog.has_table_privilege(
          'periapsis_api',relation.oid,'SELECT,INSERT,UPDATE,DELETE'
        )
      )::integer AS api_direct_count,
      count(*) FILTER (
        WHERE pg_catalog.has_table_privilege(
          'periapsis_worker',relation.oid,'SELECT,INSERT,UPDATE,DELETE'
        )
      )::integer AS worker_direct_count
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='public' AND relation.relname IN (
      'auth_session_ldap_provenance','tenant_post_primary_ldap_provenance'
    )
  `;
  assert.deepEqual(surface, {
    relation_count: 2,
    exact_policy_count: 2,
    api_direct_count: 0,
    worker_direct_count: 0,
  });

  await forEachSequential(runtimeRoles, async (role) => {
    await assert.rejects(
      asRole(
        role,
        (transaction) =>
          transaction`SELECT count(*) FROM public.auth_session_ldap_provenance`,
      ),
      (error) => {
        assertSqlState(error, "42501");
        return true;
      },
    );
  });
  const [workerReadiness] = await asRole(
    "periapsis_worker",
    (transaction) =>
      transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v50() AS ready
      `,
  );
  assert.equal(workerReadiness?.ready, true);
  await forEachSequential(
    ["periapsis_notifier", "periapsis_auditor"] as const,
    async (role) => {
      await assert.rejects(
        asRole(
          role,
          (transaction) =>
            transaction`SELECT app.release_runtime_schema_readiness_v50()`,
        ),
        (error) => {
          assertSqlState(error, "42501");
          return true;
        },
      );
    },
  );
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`SELECT app.validate_ldap_primary_provenance_v1()`,
    ),
    (error) => {
      assertSqlState(error, "42501");
      return true;
    },
  );

  // Exercise the anonymous LDAP pre-auth ABI until the account meter blocks.
  // The locator is deliberately unresolved; every attempt must stay
  // non-enumerating while the shared, digest-only database throttle advances.
  await forEachSequential(
    Array.from({ length: 11 }, (_, attempt) => attempt),
    async (attempt) => {
      const sequence = 100 + attempt * 4;
      const [row] = await asRole(
        "periapsis_api",
        (transaction) =>
          transaction<{ result_count: number }[]>`
            SELECT count(*)::integer AS result_count
            FROM app.begin_tenant_ldap_jit_authentication_v1(
              ${uuid(sequence)}::uuid,
              ${digest(`receipt-${attempt}`)}::bytea,
              'missing-tenant'::text,
              'directory'::text,
              ${networkRateKey}::bytea,
              ${accountRateKey}::bytea,
              ${providerRateKey}::bytea,
              ${uuid(sequence + 1)}::uuid,
              ${uuid(sequence + 2)}::uuid,
              ${uuid(sequence + 3)}::uuid,
              '192.0.2.75'::inet,
              'Periapsis interactive LDAP PostgreSQL security test'::text
            )
          `,
      );
      assert.deepEqual(row, { result_count: 0 });
    },
  );
  const [accountMeter] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<
        { attempt_count: number; blocked: boolean; digest_size: number }[]
      >`
        SELECT rate.attempt_count::integer AS attempt_count,
          (rate.blocked_until > statement_timestamp()) AS blocked,
          octet_length(${accountRateKey}::bytea)::integer AS digest_size
        FROM app.get_auth_rate_limit(
          'ldap_account'::public.auth_rate_limit_scope,
          ${accountRateKey}::bytea
        ) AS rate
      `,
  );
  assert(accountMeter, "LDAP account rate meter was not persisted");
  assert.equal(accountMeter.attempt_count, 11);
  assert.equal(accountMeter.blocked, true);
  assert.equal(accountMeter.digest_size, 32);

  // Readiness must reject even a transient direct-table privilege drift and
  // recover after the isolated test restores the intended ACL.
  await sql.unsafe(
    "GRANT SELECT ON public.auth_session_ldap_provenance TO periapsis_api",
  );
  assert.equal(await readiness(), false);
  await sql.unsafe(
    "REVOKE SELECT ON public.auth_session_ldap_provenance FROM periapsis_api",
  );
  assert.equal(await readiness(), true);
} finally {
  await bestEffort(
    "REVOKE SELECT ON public.auth_session_ldap_provenance FROM periapsis_api",
  );
  await sql.end();
}
