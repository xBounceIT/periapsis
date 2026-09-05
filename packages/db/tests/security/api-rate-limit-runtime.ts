import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql, type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole =
  | "periapsis_api"
  | "periapsis_worker"
  | "periapsis_notifier"
  | "periapsis_auditor";
type Admission = {
  admitted: boolean;
  retry_after_seconds: number;
};
type RateDigests = readonly [Buffer, Buffer, Buffer];

const databaseUrl = process.env.PERIAPSIS_API_RATE_LIMIT_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_API_RATE_LIMIT_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database with migration 0220 applied",
  );
}

const roleStatements: Record<RuntimeRole, string> = {
  periapsis_api: 'SET LOCAL ROLE "periapsis_api"',
  periapsis_worker: 'SET LOCAL ROLE "periapsis_worker"',
  periapsis_notifier: 'SET LOCAL ROLE "periapsis_notifier"',
  periapsis_auditor: 'SET LOCAL ROLE "periapsis_auditor"',
};
const runID = `${Date.now()}:${process.pid}`;
const testDigests = new Map<string, Buffer>();

function digest(label: string): Buffer {
  const value = createHash("sha256")
    .update(`api-rate-limit-runtime:${runID}:${label}`)
    .digest();
  testDigests.set(value.toString("hex"), value);
  return value;
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function asRole<T>(
  connection: Sql,
  role: RuntimeRole,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await connection.begin(async (transaction) => {
    await transaction.unsafe(roleStatements[role]);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function admit(
  connection: Sql,
  digests: RateDigests,
  limit: number,
): Promise<Admission> {
  return asRole(connection, "periapsis_api", async (transaction) => {
    const [decision] = await transaction<Admission[]>`
      SELECT admission.admitted, admission.retry_after_seconds
      FROM app.admit_api_request_v1(
        ARRAY[
          'api_network'::public.auth_rate_limit_scope,
          'api_credential'::public.auth_rate_limit_scope,
          'api_tenant_subject'::public.auth_rate_limit_scope
        ],
        ARRAY[
          ${digests[0]}::bytea,
          ${digests[1]}::bytea,
          ${digests[2]}::bytea
        ]::bytea[],
        ARRAY[${limit}, ${limit}, ${limit}]::integer[]
      ) AS admission
    `;
    assert(decision, "admission must return one decision");
    return decision;
  });
}

async function admitNetwork(
  connection: Sql,
  keyDigest: Buffer,
  limit: number,
): Promise<Admission> {
  return asRole(connection, "periapsis_api", async (transaction) => {
    const [decision] = await transaction<Admission[]>`
      SELECT admission.admitted, admission.retry_after_seconds
      FROM app.admit_api_request_v1(
        ARRAY['api_network'::public.auth_rate_limit_scope],
        ARRAY[${keyDigest}::bytea]::bytea[],
        ARRAY[${limit}]::integer[]
      ) AS admission
    `;
    assert(decision, "network admission must return one decision");
    return decision;
  });
}

const admin = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const replicaA = postgres(databaseUrl, { max: 8, onnotice: () => undefined });
const replicaB = postgres(databaseUrl, { max: 8, onnotice: () => undefined });

try {
  const [server] = await admin<{ major: number }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major
  `;
  assert.equal(server?.major, 18, "runtime proof requires PostgreSQL 18");

  const enumValues = await admin<{ value: string }[]>`
    SELECT enum.enumlabel AS value
    FROM pg_catalog.pg_enum AS enum
    JOIN pg_catalog.pg_type AS type ON type.oid = enum.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = type.typnamespace
    WHERE namespace.nspname = 'public'
      AND type.typname = 'auth_rate_limit_scope'
    ORDER BY enum.enumsortorder
  `;
  assert.deepEqual(
    enumValues.slice(0, 3).map(({ value }) => value),
    ["api_network", "api_credential", "api_tenant_subject"],
  );
  assert(enumValues.some(({ value }) => value === "local_login"));

  const [security] = await admin<
    {
      rls_enabled: boolean;
      rls_forced: boolean;
      api_table_access: boolean;
      worker_table_access: boolean;
      notifier_table_access: boolean;
      auditor_table_access: boolean;
      api_execute: boolean;
      worker_execute: boolean;
      notifier_execute: boolean;
      auditor_execute: boolean;
      api_wrapper_execute: boolean;
      worker_wrapper_execute: boolean;
      notifier_wrapper_execute: boolean;
      auditor_wrapper_execute: boolean;
    }[]
  >`
    SELECT relation.relrowsecurity AS rls_enabled,
      relation.relforcerowsecurity AS rls_forced,
      has_table_privilege('periapsis_api', relation.oid, 'SELECT')
        OR has_table_privilege('periapsis_api', relation.oid, 'INSERT')
        OR has_table_privilege('periapsis_api', relation.oid, 'UPDATE')
        OR has_table_privilege('periapsis_api', relation.oid, 'DELETE')
        OR has_table_privilege('periapsis_api', relation.oid, 'TRUNCATE')
        OR has_table_privilege('periapsis_api', relation.oid, 'REFERENCES')
        OR has_table_privilege('periapsis_api', relation.oid, 'TRIGGER')
        AS api_table_access,
      has_table_privilege('periapsis_worker', relation.oid, 'SELECT')
        OR has_table_privilege('periapsis_worker', relation.oid, 'INSERT')
        OR has_table_privilege('periapsis_worker', relation.oid, 'UPDATE')
        OR has_table_privilege('periapsis_worker', relation.oid, 'DELETE')
        OR has_table_privilege('periapsis_worker', relation.oid, 'TRUNCATE')
        OR has_table_privilege('periapsis_worker', relation.oid, 'REFERENCES')
        OR has_table_privilege('periapsis_worker', relation.oid, 'TRIGGER')
        AS worker_table_access,
      has_table_privilege('periapsis_notifier', relation.oid, 'SELECT')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'INSERT')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'UPDATE')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'DELETE')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'TRUNCATE')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'REFERENCES')
        OR has_table_privilege('periapsis_notifier', relation.oid, 'TRIGGER')
        AS notifier_table_access,
      has_table_privilege('periapsis_auditor', relation.oid, 'SELECT')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'INSERT')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'UPDATE')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'DELETE')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'TRUNCATE')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'REFERENCES')
        OR has_table_privilege('periapsis_auditor', relation.oid, 'TRIGGER')
        AS auditor_table_access,
      has_function_privilege(
        'periapsis_api',
        'app.admit_auth_attempts(public.auth_rate_limit_scope[],bytea[],integer[],integer[],integer[])',
        'EXECUTE'
      ) AS api_execute,
      has_function_privilege(
        'periapsis_worker',
        'app.admit_auth_attempts(public.auth_rate_limit_scope[],bytea[],integer[],integer[],integer[])',
        'EXECUTE'
      ) AS worker_execute,
      has_function_privilege(
        'periapsis_notifier',
        'app.admit_auth_attempts(public.auth_rate_limit_scope[],bytea[],integer[],integer[],integer[])',
        'EXECUTE'
      ) AS notifier_execute,
      has_function_privilege(
        'periapsis_auditor',
        'app.admit_auth_attempts(public.auth_rate_limit_scope[],bytea[],integer[],integer[],integer[])',
        'EXECUTE'
      ) AS auditor_execute,
      has_function_privilege(
        'periapsis_api',
        'app.admit_api_request_v1(public.auth_rate_limit_scope[],bytea[],integer[])',
        'EXECUTE'
      ) AS api_wrapper_execute,
      has_function_privilege(
        'periapsis_worker',
        'app.admit_api_request_v1(public.auth_rate_limit_scope[],bytea[],integer[])',
        'EXECUTE'
      ) AS worker_wrapper_execute,
      has_function_privilege(
        'periapsis_notifier',
        'app.admit_api_request_v1(public.auth_rate_limit_scope[],bytea[],integer[])',
        'EXECUTE'
      ) AS notifier_wrapper_execute,
      has_function_privilege(
        'periapsis_auditor',
        'app.admit_api_request_v1(public.auth_rate_limit_scope[],bytea[],integer[])',
        'EXECUTE'
      ) AS auditor_wrapper_execute
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = 'auth_rate_limits'
  `;
  assert.deepEqual(security, {
    rls_enabled: true,
    rls_forced: true,
    api_table_access: false,
    worker_table_access: false,
    notifier_table_access: false,
    auditor_table_access: false,
    api_execute: true,
    worker_execute: false,
    notifier_execute: false,
    auditor_execute: false,
    api_wrapper_execute: true,
    worker_wrapper_execute: false,
    notifier_wrapper_execute: false,
    auditor_wrapper_execute: false,
  });

  await assert.rejects(
    asRole(
      replicaA,
      "periapsis_api",
      async (transaction) =>
        transaction`SELECT count(*) FROM public.auth_rate_limits`,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asRole(
      replicaA,
      "periapsis_worker",
      async (transaction) =>
        transaction`
        SELECT * FROM app.admit_api_request_v1(
          ARRAY['api_network'::public.auth_rate_limit_scope],
          ARRAY[${digest("worker-denied")}::bytea]::bytea[],
          ARRAY[1]::integer[]
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const retryDigest = digest("retry-network");
  const firstRetryDecision = await asRole(
    replicaA,
    "periapsis_api",
    async (transaction) => {
      const [decision] = await transaction<
        { admitted: boolean; retry_after_seconds: number }[]
      >`
        SELECT admission.admitted, admission.retry_after_seconds
        FROM app.admit_api_request_v1(
          ARRAY['api_network'::public.auth_rate_limit_scope],
          ARRAY[${retryDigest}::bytea]::bytea[],
          ARRAY[1]::integer[]
        ) AS admission
      `;
      return decision;
    },
  );
  assert.deepEqual(firstRetryDecision, {
    admitted: true,
    retry_after_seconds: 0,
  });
  const deniedRetryDecision = await asRole(
    replicaB,
    "periapsis_api",
    async (transaction) => {
      const [decision] = await transaction<
        { admitted: boolean; retry_after_seconds: number }[]
      >`
        SELECT admission.admitted, admission.retry_after_seconds
        FROM app.admit_api_request_v1(
          ARRAY['api_network'::public.auth_rate_limit_scope],
          ARRAY[${retryDigest}::bytea]::bytea[],
          ARRAY[1]::integer[]
        ) AS admission
      `;
      return decision;
    },
  );
  assert.equal(deniedRetryDecision?.admitted, false);
  assert(Number.isInteger(deniedRetryDecision?.retry_after_seconds));
  assert((deniedRetryDecision?.retry_after_seconds ?? 0) >= 1);

  const staleAPIDigests: RateDigests = [
    digest("stale-api-network"),
    digest("stale-api-credential"),
    digest("stale-api-tenant-subject"),
  ];
  const staleAuthDigest = digest("stale-auth-control");
  await admin`
    INSERT INTO public.auth_rate_limits (
      id, scope, key_digest, attempt_count, window_started_at,
      window_expires_at, blocked_until
    ) VALUES
      (
        uuidv7(), 'api_network', ${staleAPIDigests[0]}::bytea, 1,
        transaction_timestamp() - interval '2 days',
        transaction_timestamp() - interval '1 day', NULL
      ),
      (
        uuidv7(), 'api_credential', ${staleAPIDigests[1]}::bytea, 1,
        transaction_timestamp() - interval '2 days',
        transaction_timestamp() - interval '1 day', NULL
      ),
      (
        uuidv7(), 'api_tenant_subject', ${staleAPIDigests[2]}::bytea, 1,
        transaction_timestamp() - interval '2 days',
        transaction_timestamp() - interval '1 day', NULL
      ),
      (
        uuidv7(), 'local_login', ${staleAuthDigest}::bytea, 1,
        transaction_timestamp() - interval '3 days',
        transaction_timestamp() - interval '2 days', NULL
      )
  `;
  await admit(
    replicaA,
    [
      digest("cleanup-trigger-network"),
      digest("cleanup-trigger-credential"),
      digest("cleanup-trigger-tenant-subject"),
    ],
    100,
  );
  const [staleCounts] = await admin<
    { api_count: number; auth_count: number }[]
  >`
    SELECT
      count(*) FILTER (
        WHERE key_digest IN (
          ${staleAPIDigests[0]}::bytea,
          ${staleAPIDigests[1]}::bytea,
          ${staleAPIDigests[2]}::bytea
        )
      )::integer AS api_count,
      count(*) FILTER (
        WHERE key_digest = ${staleAuthDigest}::bytea
      )::integer AS auth_count
    FROM public.auth_rate_limits
  `;
  assert.deepEqual(staleCounts, { api_count: 0, auth_count: 1 });

  const sharedDigests: RateDigests = [
    digest("shared-network"),
    digest("shared-credential"),
    digest("shared-tenant-subject"),
  ];
  const decisions = await Promise.all(
    Array.from({ length: 30 }, (_, index) =>
      admit(index % 2 === 0 ? replicaA : replicaB, sharedDigests, 20),
    ),
  );
  assert.equal(
    decisions.filter(({ admitted }) => admitted).length,
    20,
    "two replica pools must share one exact database admission budget",
  );
  assert.equal(decisions.filter(({ admitted }) => !admitted).length, 10);
  assert(
    decisions
      .filter(({ admitted }) => !admitted)
      .every(({ retry_after_seconds }) => retry_after_seconds >= 1),
  );

  const sharedRows = await admin<{ scope: string; attempt_count: number }[]>`
    SELECT scope::text AS scope, attempt_count
    FROM public.auth_rate_limits
    WHERE (scope, key_digest) IN (
      ('api_network'::public.auth_rate_limit_scope, ${sharedDigests[0]}::bytea),
      ('api_credential'::public.auth_rate_limit_scope, ${sharedDigests[1]}::bytea),
      ('api_tenant_subject'::public.auth_rate_limit_scope, ${sharedDigests[2]}::bytea)
    )
    ORDER BY scope::text
  `;
  assert.equal(sharedRows.length, 3);
  assert(sharedRows.every(({ attempt_count }) => attempt_count === 30));

  const blockedNetwork = digest("atomic-blocked-network");
  assert.equal(
    (await admitNetwork(replicaA, blockedNetwork, 1)).admitted,
    true,
  );
  assert.equal(
    (await admitNetwork(replicaB, blockedNetwork, 1)).admitted,
    false,
  );
  const aggregateDigests: RateDigests = [
    blockedNetwork,
    digest("atomic-new-credential"),
    digest("atomic-new-tenant-subject"),
  ];
  assert.equal((await admit(replicaA, aggregateDigests, 100)).admitted, false);
  const aggregateRows = await admin<{ scope: string }[]>`
    SELECT scope::text AS scope
    FROM public.auth_rate_limits
    WHERE key_digest IN (
      ${aggregateDigests[0]}::bytea,
      ${aggregateDigests[1]}::bytea,
      ${aggregateDigests[2]}::bytea
    )
    ORDER BY scope::text
  `;
  assert.deepEqual(
    aggregateRows.map(({ scope }) => scope),
    ["api_network"],
  );

  await assert.rejects(
    asRole(
      replicaA,
      "periapsis_api",
      async (transaction) =>
        transaction`
        SELECT * FROM app.admit_api_request_v1(
          ARRAY[
            'api_network'::public.auth_rate_limit_scope,
            'api_network'::public.auth_rate_limit_scope
          ],
          ARRAY[
            ${blockedNetwork}::bytea,
            ${blockedNetwork}::bytea
          ]::bytea[],
          ARRAY[1, 1]::integer[]
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  process.stdout.write(
    "api rate-limit runtime security and multi-replica admission checks passed\n",
  );
} finally {
  try {
    await Promise.all(
      [...testDigests.values()].map(
        (keyDigest) => admin`
          DELETE FROM public.auth_rate_limits
          WHERE key_digest = ${keyDigest}::bytea
        `,
      ),
    );
  } finally {
    await Promise.allSettled([admin.end(), replicaA.end(), replicaB.end()]);
  }
}
