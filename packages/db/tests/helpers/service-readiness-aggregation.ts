/* eslint-disable no-await-in-loop -- Catalog changes, role switches and restored prepared queries deliberately share one ordered transaction. */
import assert, { AssertionError } from "node:assert/strict";

import type { Sql, TransactionSql } from "postgres";

export type ServiceReadinessHealthRow = {
  applied_count: number | string;
  latest_created_at: number | string;
  latest_hash: string;
  migration_fingerprint: string;
  array: boolean[];
  source_hashes: string[];
  catalog_ready: boolean;
  verify_identity_keyring_v3?: boolean;
};

type HealthProbe = Readonly<{
  query: string;
  parameters: NonNullable<Parameters<Sql["unsafe"]>[1]>;
  assertReady: (row: ServiceReadinessHealthRow | undefined) => void;
}>;

type AggregateProfile = Readonly<{
  role: "periapsis_api" | "periapsis_worker";
  otherRole: "periapsis_api" | "periapsis_worker";
  signature:
    | "app.api_runtime_schema_readiness_v59()"
    | "app.worker_runtime_schema_readiness_v59()";
  cardinality: 8 | 5;
  probe: HealthProbe;
}>;

type PreparedState = { name: string; pid: number };
type CatalogSnapshot = { digest: string };
type AggregateSnapshot = CatalogSnapshot & { source_hash: string };
type HashCounter = {
  function_oid: string;
  calls: string;
  tracked: boolean;
  observed: boolean;
};

async function keyringSnapshot(sql: Sql): Promise<CatalogSnapshot> {
  return sql.begin("read only", async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    const rows = await transaction<CatalogSnapshot[]>`
      SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        coalesce(jsonb_agg(to_jsonb(keyring) ORDER BY keyring.key_version),
          '[]'::jsonb)::text, 'UTF8'
      )), 'hex') AS digest
      FROM public.identity_keyring_versions AS keyring
    `;
    assert.equal(rows.length, 1);
    return rows[0]!;
  });
}

async function aggregateSnapshot(
  transaction: TransactionSql,
  signature: AggregateProfile["signature"],
): Promise<AggregateSnapshot> {
  const rows = await transaction<AggregateSnapshot[]>`
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      row_to_json(function_row)::text, 'UTF8'
    )), 'hex') AS digest,
      pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc, 'UTF8'
      )), 'hex') AS source_hash
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid=pg_catalog.to_regprocedure(${signature})
  `;
  assert.equal(rows.length, 1, "aggregate catalog row is missing");
  return rows[0]!;
}

async function hashCounter(transaction: TransactionSql): Promise<HashCounter> {
  const rows = await transaction<HashCounter[]>`
    SELECT function_row.oid::text AS function_oid,
           coalesce(statistics.calls, 0)::text AS calls,
           current_setting('track_functions')='all' AS tracked,
           statistics.funcid IS NOT NULL AS observed
    FROM pg_catalog.pg_proc AS function_row
    LEFT JOIN pg_catalog.pg_stat_xact_user_functions AS statistics
      ON statistics.funcid=function_row.oid
    WHERE function_row.oid=pg_catalog.to_regprocedure(
      'app.private_release_runtime_dependency_surface_hash_v59()'
    )
  `;
  assert.equal(rows.length, 1, "exact V59 hash routine is missing");
  assert.equal(rows[0]!.tracked, true, "function-call tracking is not active");
  return rows[0]!;
}

async function preparedState(
  transaction: TransactionSql,
  query: string,
): Promise<PreparedState> {
  const rows = await transaction<PreparedState[]>`
    SELECT prepared.name, pg_catalog.pg_backend_pid() AS pid
    FROM pg_catalog.pg_prepared_statements AS prepared
    WHERE prepared.statement=${query}
  `;
  assert.equal(rows.length, 1, "actual Go health SQL was not prepared once");
  return rows[0]!;
}

async function queryAsRole(
  transaction: TransactionSql,
  profile: AggregateProfile,
  userId: string,
  backendPid: number,
): Promise<ServiceReadinessHealthRow> {
  await transaction.unsafe(`SET LOCAL ROLE "${profile.role}"`);
  await transaction`
    SELECT set_config('app.tenant_id', '', true),
           set_config('app.user_id', ${userId}, true),
           set_config('app.service_account_id', '', true)
  `;
  const [context] = await transaction<
    { pid: number; role: string; timeout: string; read_only: string }[]
  >`
    SELECT pg_catalog.pg_backend_pid() AS pid, current_user::text AS role,
           current_setting('statement_timeout') AS timeout,
           current_setting('transaction_read_only') AS read_only
  `;
  assert.deepEqual(context, {
    pid: backendPid,
    role: profile.role,
    timeout: "10s",
    read_only: "off",
  });
  // Explicitly prepare the unchanged SQL parsed from health.go. Repeating it
  // after DDL/rollback exercises PostgreSQL's cached-plan invalidation path.
  const rows = await transaction.unsafe<ServiceReadinessHealthRow[]>(
    profile.probe.query,
    [...profile.probe.parameters],
    { prepare: true },
  );
  assert.equal(rows.length, 1, `${profile.role} health returned no unique row`);
  await transaction.unsafe("RESET ROLE");
  return rows[0]!;
}

async function verifyProfile(
  transaction: TransactionSql,
  profile: AggregateProfile,
  userId: string,
  backendPid: number,
): Promise<void> {
  const beforeCounter = await hashCounter(transaction);
  const baseline = await queryAsRole(transaction, profile, userId, backendPid);
  const afterCounter = await hashCounter(transaction);
  profile.probe.assertReady(baseline);
  assert.equal(afterCounter.function_oid, beforeCounter.function_oid);
  assert.equal(afterCounter.observed, true, "hash call was not observed");
  assert.equal(
    BigInt(afterCounter.calls) - BigInt(beforeCounter.calls),
    1n,
    `${profile.role} actual health SQL must execute the full catalog hash once`,
  );
  const prepared = await preparedState(transaction, profile.probe.query);
  assert.equal(prepared.pid, backendPid);
  const catalog = await aggregateSnapshot(transaction, profile.signature);
  const aggregateSourceHash = catalog.source_hash;
  assert.match(aggregateSourceHash, /^[0-9a-f]{64}$/u);
  const aggregateSourceIndex =
    baseline.source_hashes.indexOf(aggregateSourceHash);
  assert(
    aggregateSourceIndex >= 0,
    "aggregate source is absent from Go health",
  );
  assert.equal(
    baseline.source_hashes.lastIndexOf(aggregateSourceHash),
    aggregateSourceIndex,
    "aggregate source must have one unambiguous Go health position",
  );

  const allTrue = Array.from({ length: profile.cardinality }, () => true);
  const mutations = [
    {
      label: "source returning all true",
      kind: "source",
      sql: `CREATE OR REPLACE FUNCTION ${profile.signature}
        RETURNS boolean[] LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tamper$
        BEGIN RETURN ARRAY[${allTrue.join(",")}]::boolean[]; END;
        $tamper$;`,
    },
    {
      label: "owner",
      kind: "catalog",
      sql: `ALTER FUNCTION ${profile.signature} OWNER TO periapsis_auditor`,
    },
    {
      label: "volatility",
      kind: "catalog",
      sql: `ALTER FUNCTION ${profile.signature} VOLATILE`,
    },
    {
      label: "search path",
      kind: "catalog",
      sql: `ALTER FUNCTION ${profile.signature} SET search_path=pg_catalog,app`,
    },
    {
      label: "wrong-role ACL",
      kind: "catalog",
      sql: `GRANT EXECUTE ON FUNCTION ${profile.signature} TO ${profile.otherRole}`,
    },
    {
      label: "PUBLIC ACL",
      kind: "catalog",
      sql: `GRANT EXECUTE ON FUNCTION ${profile.signature} TO PUBLIC`,
    },
    {
      label: "grant option",
      kind: "catalog",
      sql: `GRANT EXECUTE ON FUNCTION ${profile.signature} TO ${profile.role} WITH GRANT OPTION`,
    },
    {
      label: "missing aggregate",
      kind: "missing",
      sql: `DROP FUNCTION ${profile.signature}`,
    },
  ] as const;

  for (const mutation of mutations) {
    const rollback = new Error(`${profile.role} ${mutation.label} rollback`);
    await assert.rejects(
      transaction.savepoint(async (nested) => {
        await nested.unsafe(mutation.sql);
        if (mutation.kind === "missing") {
          await assert.rejects(
            queryAsRole(nested, profile, userId, backendPid),
            (error: unknown) =>
              error instanceof Error &&
              "code" in error &&
              error.code === "42883",
            "dropping the actual aggregate must fail with undefined_function",
          );
        } else {
          const row = await queryAsRole(nested, profile, userId, backendPid);
          // The supplied callback is the binding fixture's complete Go-health
          // contract: journal, all bits, exact source list, catalog and keyring.
          // A failing partial bit is not sufficient evidence for this proof.
          assert.throws(
            () => profile.probe.assertReady(row),
            (error: unknown) => error instanceof AssertionError,
            `${profile.role} accepted ${mutation.label}`,
          );
          if (mutation.kind === "source") {
            assert.deepEqual(row.array, allTrue);
            assert.equal(row.catalog_ready, true);
            assert.notEqual(
              row.source_hashes[aggregateSourceIndex],
              aggregateSourceHash,
            );
          } else {
            assert.equal(row.catalog_ready, false);
          }
          assert.deepEqual(
            await preparedState(nested, profile.probe.query),
            prepared,
          );
        }
        throw rollback;
      }),
      (error: unknown) => error === rollback,
    );
    assert.deepEqual(
      await aggregateSnapshot(transaction, profile.signature),
      catalog,
      `${profile.role} ${mutation.label} did not roll back exactly`,
    );
    const restored = await queryAsRole(
      transaction,
      profile,
      userId,
      backendPid,
    );
    profile.probe.assertReady(restored);
    assert.deepEqual(
      await preparedState(transaction, profile.probe.query),
      prepared,
    );
  }
}

export async function assertServiceReadinessAggregation({
  admin,
  userId,
  api,
  worker,
}: Readonly<{
  admin: Sql;
  userId: string;
  api: HealthProbe;
  worker: HealthProbe;
}>): Promise<void> {
  const keyring = await keyringSnapshot(admin);
  const rollback = new Error("service readiness aggregation rollback");
  await assert.rejects(
    admin.begin("read write", async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
      await transaction.unsafe("SET LOCAL lock_timeout = '5s'");
      // This superuser-only setting is installed before either SET LOCAL ROLE;
      // transaction-local counters avoid shared resets and backend-flush races.
      await transaction.unsafe("SET LOCAL track_functions = 'all'");
      const [identity] = await transaction<
        { pid: number; administrator: boolean }[]
      >`
        SELECT pg_catalog.pg_backend_pid() AS pid,
               current_user=session_user AND role.rolsuper AS administrator
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname=current_user
      `;
      assert.equal(identity?.administrator, true);
      const backendPid = identity.pid;
      for (const profile of [
        {
          role: "periapsis_api",
          otherRole: "periapsis_worker",
          signature: "app.api_runtime_schema_readiness_v59()",
          cardinality: 8,
          probe: api,
        },
        {
          role: "periapsis_worker",
          otherRole: "periapsis_api",
          signature: "app.worker_runtime_schema_readiness_v59()",
          cardinality: 5,
          probe: worker,
        },
      ] as const) {
        await verifyProfile(transaction, profile, userId, backendPid);
      }
      // The worker's ordinary keyring upsert is allowed but never committed.
      throw rollback;
    }),
    (error: unknown) => error === rollback,
  );
  assert.deepEqual(await keyringSnapshot(admin), keyring);
}
