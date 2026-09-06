import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import postgres, { type Sql } from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedNotificationDispatchReadinessV50SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV50SourceHash,
  expectedPrivateReleaseRuntimeReadinessV50SourceHash,
  expectedReleaseRuntimeReadinessV50SourceHash,
  expectedSchemaCompatibilityV50SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type CompatibilityRow = {
  applied_count: number | string;
  latest_created_at: number | string;
  latest_hash: string;
  migration_fingerprint: string;
};

type FunctionCatalogRow = {
  acl_roles: string[];
  function_name: string;
  owner_name: string;
  runtime_execute_count: number;
};

type JournalRow = CompatibilityRow & {
  latest_rows: number | string;
};

type ReadinessRow = {
  catalog_digest: string;
  readiness: boolean[];
};

const retiredV48Roots = [
  "schema_compatibility_v48",
  "release_runtime_schema_readiness_v48",
  "federated_authentication_schema_readiness_v48",
  "platform_oidc_direct_runtime_schema_readiness_v48",
  "platform_saml_direct_runtime_schema_readiness_v48",
  "platform_local_account_runtime_schema_readiness_v48",
  "sla_trigger_action_runtime_schema_readiness_v48",
  "sla_object_event_ingress_schema_readiness_v48",
  "ticket_bulk_runtime_schema_readiness_v48",
  "ticket_export_runtime_schema_readiness_v48",
  "ticket_metadata_runtime_schema_readiness_v48",
] as const;

const retainedPrivateV48Roots = [
  "private_schema_compatibility_journal_v48",
  "private_release_runtime_dependency_surface_hash_v48",
  "private_release_runtime_schema_readiness_v48",
  "private_rotate_sla_readiness_v48",
] as const;

const retiredV49Roots = [
  "schema_compatibility_v49",
  "release_runtime_schema_readiness_v49",
  "federated_authentication_schema_readiness_v49",
  "platform_oidc_direct_runtime_schema_readiness_v49",
  "platform_saml_direct_runtime_schema_readiness_v49",
  "platform_local_account_runtime_schema_readiness_v49",
  "sla_trigger_action_runtime_schema_readiness_v49",
  "sla_object_event_ingress_schema_readiness_v49",
  "ticket_bulk_runtime_schema_readiness_v49",
  "ticket_export_runtime_schema_readiness_v49",
  "ticket_metadata_runtime_schema_readiness_v49",
  "notification_dispatch_readiness_v49",
] as const;

const retainedPrivateV49Roots = [
  "private_schema_compatibility_journal_v49",
  "private_release_runtime_dependency_surface_hash_v49",
  "private_release_runtime_schema_readiness_v49",
  "private_rotate_notification_readiness_v49",
] as const;

const runtimeRoles = [
  "periapsis_api",
  "periapsis_worker",
  "periapsis_notifier",
  "periapsis_auditor",
] as const;

const migrationsRoot = resolve(import.meta.dirname, "../../migrations");
const v50Migration = await readFile(
  resolve(migrationsRoot, "0231_v50_compatibility.sql"),
  "utf8",
);
const expectedCatalogDigest =
  /private_release_runtime_dependency_surface_hash_v50\(\)<>\s*'([0-9a-f]{64})'/u.exec(
    v50Migration,
  )?.[1];
assert(
  expectedCatalogDigest,
  "0231 must pin the exact V50 release catalog digest",
);
assert.equal(
  expectedCatalogDigest,
  "e68c7797c4f72188d1ddd4d133e5adff3f099004578fa77ad9f6472027fea9f8",
);

async function readFunctionCatalog(
  sql: Sql,
  functionNames: readonly string[],
): Promise<FunctionCatalogRow[]> {
  const rows = await sql.unsafe<FunctionCatalogRow[]>(
    `
      SELECT function_row.proname::text AS function_name,
             owner.rolname::text AS owner_name,
             coalesce(array_agg(
               coalesce(grantee.rolname::text, 'PUBLIC')
               ORDER BY coalesce(grantee.rolname::text, 'PUBLIC') COLLATE "C"
             ) FILTER (WHERE function_acl.privilege_type = 'EXECUTE'),
               ARRAY[]::text[]) AS acl_roles,
             count(*) FILTER (
               WHERE function_acl.privilege_type = 'EXECUTE'
                 AND coalesce(grantee.rolname::text, 'PUBLIC') = ANY($2::text[])
             )::integer AS runtime_execute_count
      FROM pg_catalog.pg_proc AS function_row
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = function_row.pronamespace
       AND namespace.nspname = 'app'
      JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
      LEFT JOIN LATERAL pg_catalog.aclexplode(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f', function_row.proowner)
      )) AS function_acl ON true
      LEFT JOIN pg_catalog.pg_roles AS grantee
        ON grantee.oid = function_acl.grantee
      WHERE function_row.proname = ANY($1::text[])
        AND function_row.pronargs = 0
      GROUP BY function_row.proname, owner.rolname
      ORDER BY function_row.proname COLLATE "C"
    `,
    [functionNames, runtimeRoles],
  );
  return Array.from(rows);
}

async function readV50Readiness(
  sql: Sql | postgres.TransactionSql,
): Promise<ReadinessRow> {
  const [row] = await sql<ReadinessRow[]>`
    SELECT app.private_release_runtime_dependency_surface_hash_v50()
             AS catalog_digest,
           ARRAY[
             app.private_release_runtime_schema_readiness_v50(),
             app.release_runtime_schema_readiness_v50(),
             app.federated_authentication_schema_readiness_v50(),
             app.platform_oidc_direct_runtime_schema_readiness_v50(),
             app.platform_saml_direct_runtime_schema_readiness_v50(),
             app.platform_local_account_runtime_schema_readiness_v50(),
             app.sla_trigger_action_runtime_schema_readiness_v50(),
             app.sla_object_event_ingress_schema_readiness_v50(),
             app.ticket_bulk_runtime_schema_readiness_v50(),
             app.ticket_export_runtime_schema_readiness_v50(),
             app.ticket_metadata_runtime_schema_readiness_v50(),
             app.alert_dfir_runtime_schema_readiness_v2(),
             (SELECT readiness.schema_safe
              FROM app.notification_dispatch_readiness_v50() AS readiness)
           ]::boolean[] AS readiness
  `;
  assert(row, "V50 readiness returned no row");
  return row;
}

async function readCatalogDigest(
  sql: Sql | postgres.TransactionSql,
): Promise<string> {
  const [row] = await sql<{ digest: string }[]>`
    SELECT app.private_release_runtime_dependency_surface_hash_v50()
             AS digest
  `;
  assert(row, "V50 catalog digest returned no row");
  return row.digest;
}

async function readNotifierSourceAttestation(
  sql: Sql | postgres.TransactionSql,
): Promise<boolean> {
  const [row] = await sql<{ source_safe: boolean }[]>`
    WITH expected(signature, source_hash) AS (
      VALUES
        ('app.schema_compatibility_v50()',
          ${expectedSchemaCompatibilityV50SourceHash}),
        ('app.private_release_runtime_dependency_surface_hash_v50()',
          ${expectedPrivateReleaseRuntimeDependencySurfaceHashV50SourceHash}),
        ('app.private_release_runtime_schema_readiness_v50()',
          ${expectedPrivateReleaseRuntimeReadinessV50SourceHash}),
        ('app.release_runtime_schema_readiness_v50()',
          ${expectedReleaseRuntimeReadinessV50SourceHash}),
        ('app.notification_dispatch_readiness_v50()',
          ${expectedNotificationDispatchReadinessV50SourceHash})
    )
    SELECT count(function_row.oid)=5 AND coalesce(bool_and(
             pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
               function_row.prosrc,'UTF8'
             )),'hex')=expected.source_hash
           ),false) AS source_safe
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.signature)
  `;
  assert(row, "notifier V50 source attestation returned no row");
  return row.source_safe;
}

const databaseUrl =
  process.env.PERIAPSIS_SCHEMA_COMPATIBILITY_V50_SECURITY_TEST_DATABASE_URL;
assert(
  databaseUrl !== undefined && databaseUrl.trim() !== "",
  "PERIAPSIS_SCHEMA_COMPATIBILITY_V50_SECURITY_TEST_DATABASE_URL is required",
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

try {
  const [server] = await sql<
    {
      character_type: string;
      collation: string;
      encoding: string;
      version: string;
      version_num: number;
    }[]
  >`
    SELECT current_setting('server_version') AS version,
           current_setting('server_version_num')::integer AS version_num,
           pg_catalog.pg_encoding_to_char(database.encoding) AS encoding,
           database.datcollate AS collation,
           database.datctype AS character_type
    FROM pg_catalog.pg_database AS database
    WHERE database.datname=pg_catalog.current_database()
  `;
  assert.deepEqual(server, {
    character_type: "C",
    collation: "C",
    encoding: "UTF8",
    version: "18.6",
    version_num: 180_006,
  });

  const [journal] = await sql<JournalRow[]>`
    SELECT count(*)::bigint AS applied_count,
           max(migration.created_at)::bigint AS latest_created_at,
           count(*) FILTER (
             WHERE migration.created_at = latest.value
           )::bigint AS latest_rows,
           (
             SELECT lower(last_migration.hash::text)
             FROM drizzle.__drizzle_migrations AS last_migration
             ORDER BY last_migration.created_at DESC, last_migration.id DESC
             LIMIT 1
           ) AS latest_hash,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at, migration.id
           ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
    CROSS JOIN LATERAL (
      SELECT max(candidate.created_at)::bigint AS value
      FROM drizzle.__drizzle_migrations AS candidate
    ) AS latest
  `;
  assert(journal, "migration journal returned no row");
  assert.deepEqual(
    {
      applied_count: Number(journal.applied_count),
      latest_created_at: Number(journal.latest_created_at),
      latest_hash: journal.latest_hash,
      latest_rows: Number(journal.latest_rows),
      migration_fingerprint: journal.migration_fingerprint,
    },
    {
      applied_count: expectedMigrationCount,
      latest_created_at: expectedMigrationCreatedAt,
      latest_hash: expectedMigrationHash,
      latest_rows: 1,
      migration_fingerprint: expectedMigrationFingerprint,
    },
  );

  const [compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v50()
  `;
  assert(compatibility, "schema_compatibility_v50 returned no row");
  assert.deepEqual(
    {
      applied_count: Number(compatibility.applied_count),
      latest_created_at: Number(compatibility.latest_created_at),
      latest_hash: compatibility.latest_hash,
      migration_fingerprint: compatibility.migration_fingerprint,
    },
    {
      applied_count: expectedMigrationCount,
      latest_created_at: expectedMigrationCreatedAt,
      latest_hash: expectedMigrationHash,
      migration_fingerprint: expectedMigrationFingerprint,
    },
  );

  const readiness = await readV50Readiness(sql);
  assert.equal(readiness.catalog_digest, expectedCatalogDigest);
  assert.equal(readiness.readiness.length, 13);
  assert(!readiness.readiness.includes(false), "a V50 readiness root failed");
  assert.equal(await readNotifierSourceAttestation(sql), true);

  const [federatedJitRepair] = await sql<
    {
      core_primitive_present: boolean;
      legacy_primitive_absent: boolean;
      pgcrypto_primitive_absent: boolean;
      source_hash: string;
    }[]
  >`
    SELECT pg_catalog.strpos(
             function_row.prosrc,
             'pg_catalog.sha256(pg_catalog.uuid_send(pg_catalog.gen_random_uuid()) || pg_catalog.uuid_send(pg_catalog.gen_random_uuid()))'
           ) > 0 AS core_primitive_present,
           pg_catalog.strpos(function_row.prosrc,'gen_random_bytes(32)') = 0
             AS legacy_primitive_absent,
           pg_catalog.to_regprocedure('gen_random_bytes(integer)') IS NULL
             AS pgcrypto_primitive_absent,
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             function_row.prosrc,'UTF8'
           )),'hex') AS source_hash
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid=
      'app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,public.auth_provider_kind,bigint,bigint,timestamp with time zone)'::regprocedure
  `;
  assert.deepEqual(federatedJitRepair, {
    core_primitive_present: true,
    legacy_primitive_absent: true,
    pgcrypto_primitive_absent: true,
    source_hash:
      "f064d2874523976d14529a4ac239f4a6c892b6e50b212c6b126c90b8a5d2d022",
  });

  const [credentialProbeCatalog] = await sql<
    { acl_exact: boolean; catalog_exact: boolean }[]
  >`
    SELECT owner.rolsuper
             AND owner.rolname <> ALL(ARRAY[
               'periapsis_api','periapsis_worker','periapsis_notifier',
               'periapsis_auditor','periapsis_api_login',
               'periapsis_worker_login','periapsis_notifier_login',
               'periapsis_auditor_login'
             ]::text[])
             AND language.lanname='sql'
             AND function_row.provolatile='s'
             AND function_row.prosecdef
             AND NOT function_row.proisstrict
             AND NOT function_row.proleakproof
             AND function_row.proparallel='u'
             AND function_row.proconfig IS NOT DISTINCT FROM
               ARRAY['search_path=pg_catalog']::text[]
             AND pg_catalog.pg_get_function_result(function_row.oid)=
               'TABLE(role_name text, credential_state text)'
               AS catalog_exact,
           (
             SELECT count(*)=2 AND coalesce(bool_and(
               function_acl.grantor=function_row.proowner
               AND function_acl.grantee IN (
                 function_row.proowner,
                 (SELECT role.oid FROM pg_catalog.pg_roles AS role
                  WHERE role.rolname='periapsis_migrator')
               )
               AND function_acl.privilege_type='EXECUTE'
               AND NOT function_acl.is_grantable
             ),false)
             FROM pg_catalog.aclexplode(coalesce(
               function_row.proacl,
               pg_catalog.acldefault('f',function_row.proowner)
             )) AS function_acl
           ) AS acl_exact
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
    WHERE function_row.oid=
      'app.private_runtime_login_credential_state_v49()'::regprocedure
  `;
  assert.deepEqual(credentialProbeCatalog, {
    acl_exact: true,
    catalog_exact: true,
  });

  const retiredCatalog = await readFunctionCatalog(sql, retiredV48Roots);
  assert.equal(retiredCatalog.length, retiredV48Roots.length);
  for (const root of retiredCatalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const retiredV49Catalog = await readFunctionCatalog(sql, retiredV49Roots);
  assert.equal(retiredV49Catalog.length, 12);
  for (const root of retiredV49Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v49";
    assert.equal(
      root.owner_name,
      notificationRoot
        ? "periapsis_notification_readiness_owner"
        : "periapsis_migrator",
    );
    assert.deepEqual(
      root.acl_roles,
      notificationRoot
        ? ["periapsis_migrator", "periapsis_notification_readiness_owner"]
        : ["periapsis_migrator"],
    );
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV49Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV49Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV49Privileges, { granted_count: 0 });

  const [retiredV49Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v49()
  `;
  assert(retiredV49Compatibility, "retired V49 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV49Compatibility,
      applied_count: Number(retiredV49Compatibility.applied_count),
      latest_created_at: Number(retiredV49Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV49Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v49()'::regprocedure
  `;
  assert.deepEqual(retiredV49Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const [alertDFIRCatalog] = await sql<
    {
      current_ready: boolean;
      retired_runtime_execute_count: number;
    }[]
  >`
    SELECT app.alert_dfir_runtime_schema_readiness_v2() AS current_ready,
           (
             SELECT count(*)::integer
             FROM (VALUES
               ('periapsis_api'), ('periapsis_worker'),
               ('periapsis_notifier'), ('periapsis_auditor')
             ) AS runtime_role(name)
             WHERE has_function_privilege(
               runtime_role.name,
               'app.alert_dfir_runtime_schema_readiness_v1()',
               'EXECUTE'
             )
           ) AS retired_runtime_execute_count
  `;
  assert.deepEqual(alertDFIRCatalog, {
    current_ready: true,
    retired_runtime_execute_count: 0,
  });

  const notifierCatalog = await readFunctionCatalog(sql, [
    "notification_dispatch_readiness_v4",
    "notification_dispatch_readiness_v49",
    "notification_dispatch_readiness_v50",
  ]);
  assert.deepEqual(notifierCatalog, [
    {
      acl_roles: ["periapsis_notification_readiness_owner"],
      function_name: "notification_dispatch_readiness_v4",
      owner_name: "periapsis_notification_readiness_owner",
      runtime_execute_count: 0,
    },
    {
      acl_roles: [
        "periapsis_migrator",
        "periapsis_notification_readiness_owner",
      ],
      function_name: "notification_dispatch_readiness_v49",
      owner_name: "periapsis_notification_readiness_owner",
      runtime_execute_count: 0,
    },
    {
      acl_roles: [
        "periapsis_migrator",
        "periapsis_notification_readiness_owner",
        "periapsis_notifier",
      ],
      function_name: "notification_dispatch_readiness_v50",
      owner_name: "periapsis_notification_readiness_owner",
      runtime_execute_count: 1,
    },
  ]);

  const privateCatalog = await readFunctionCatalog(
    sql,
    retainedPrivateV48Roots,
  );
  assert.equal(privateCatalog.length, retainedPrivateV48Roots.length);
  for (const root of privateCatalog) {
    const expectedOwner =
      root.function_name === "private_rotate_sla_readiness_v48"
        ? "periapsis_sla_readiness_owner"
        : "periapsis_migrator";
    assert.equal(root.owner_name, expectedOwner);
    assert.deepEqual(
      root.acl_roles,
      root.function_name === "private_rotate_sla_readiness_v48"
        ? ["periapsis_migrator", "periapsis_sla_readiness_owner"]
        : ["periapsis_migrator"],
    );
    assert.equal(root.runtime_execute_count, 0);
  }

  const privateV49Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV49Roots,
  );
  assert.equal(privateV49Catalog.length, retainedPrivateV49Roots.length);
  for (const root of privateV49Catalog) {
    const notificationRotation =
      root.function_name === "private_rotate_notification_readiness_v49";
    assert.equal(
      root.owner_name,
      notificationRotation
        ? "periapsis_notification_readiness_owner"
        : "periapsis_migrator",
    );
    assert.deepEqual(
      root.acl_roles,
      notificationRotation
        ? ["periapsis_migrator", "periapsis_notification_readiness_owner"]
        : ["periapsis_migrator"],
    );
    assert.equal(root.runtime_execute_count, 0);
  }

  const normalizedV49GrantRollback = {
    kind: "normalized-v49-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v49()
        TO periapsis_api
      `;
      const drifted = await readV50Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V49 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V50 root must independently reject a restored V49 grant",
      );
      throw normalizedV49GrantRollback;
    }),
    (error: unknown) => error === normalizedV49GrantRollback,
  );

  const normalizedV49NotifierGrantRollback = {
    kind: "normalized-v49-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v49()
        TO periapsis_notifier
      `;
      const drifted = await readV50Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV49NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV49NotifierGrantRollback,
  );

  const rotatedV49AclTamperRollback = {
    kind: "rotated-v49-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v49()
        TO periapsis_auditor
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV49AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV49AclTamperRollback,
  );

  const rotatedV49ConfigTamperRollback = {
    kind: "rotated-v49-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v49() SET work_mem='64kB'
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV49ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV49ConfigTamperRollback,
  );

  const unnormalizedV49ConfigRollback = {
    kind: "unnormalized-private-v49-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v49()
        SET work_mem='64kB'
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV49ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV49ConfigRollback,
  );

  const historicalV49SourceRollback = {
    kind: "historical-v49-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v49()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V49 private root is no longer self-excluded in V50",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV49SourceRollback;
    }),
    (error: unknown) => error === historicalV49SourceRollback,
  );

  const normalizedGrantRollback = { kind: "normalized-v48-grant" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v48()
        TO periapsis_api
      `;
      const drifted = await readV50Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V48 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V50 root must independently reject a restored V48 grant",
      );
      throw normalizedGrantRollback;
    }),
    (error: unknown) => error === normalizedGrantRollback,
  );

  const rotatedAclTamperRollback = {
    kind: "rotated-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v48()
        TO periapsis_auditor
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "an unrecognized ACL on an exact rotated root must remain attested",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedAclTamperRollback;
    }),
    (error: unknown) => error === rotatedAclTamperRollback,
  );

  const rotatedConfigTamperRollback = {
    kind: "rotated-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v48()
        SET work_mem='64kB'
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "an unrecognized config on an exact rotated root must remain attested",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedConfigTamperRollback,
  );

  const unnormalizedConfigRollback = {
    kind: "unnormalized-private-v48-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v48()
        SET work_mem='64kB'
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedConfigRollback;
    }),
    (error: unknown) => error === unnormalizedConfigRollback,
  );

  const historicalSourceTamperRollback = {
    kind: "historical-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_mfa_policy_administration_schema_readiness_v5()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN false;
        END;
        $tampered$
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "unknown source at a historical coordinate must not be normalized",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalSourceTamperRollback;
    }),
    (error: unknown) => error === historicalSourceTamperRollback,
  );

  const materialAbsenceSourceRollback = {
    kind: "tenant-provider-material-absence-source-tamper",
  } as const;
  const [materialAbsenceWitness] = await sql<
    { owner_name: string; runtime_executable: boolean }[]
  >`
    SELECT owner.rolname::text AS owner_name,
           EXISTS (
             SELECT 1 FROM pg_catalog.pg_roles AS runtime
             WHERE runtime.rolname = ANY(${runtimeRoles}::text[])
               AND pg_catalog.has_function_privilege(runtime.oid, function_row.oid, 'EXECUTE')
           ) AS runtime_executable
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
    WHERE function_row.oid = pg_catalog.to_regprocedure(
      'app.private_tenant_provider_oidc_material_absence_attested_v1(uuid,uuid,uuid)'
    )
  `;
  assert.deepEqual(materialAbsenceWitness, {
    owner_name: "periapsis_migrator",
    runtime_executable: false,
  });
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_tenant_provider_oidc_material_absence_attested_v1(
            p_tenant_id uuid,p_session_id uuid,p_continuation_id uuid
          )
        RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
          SELECT true;
        $tampered$
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the tenant-provider OIDC absence witness must be catalog-attested",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      assert.equal(drifted.readiness[2], false);
      throw materialAbsenceSourceRollback;
    }),
    (error: unknown) => error === materialAbsenceSourceRollback,
  );
  assert.deepEqual(await readV50Readiness(sql), readiness);

  const sqlStandardBodyRollback = {
    kind: "sql-standard-body-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [before] = await transaction<
        { has_sql_body: boolean; source_bytes: number }[]
      >`
        SELECT function_row.prosqlbody IS NOT NULL AS has_sql_body,
               pg_catalog.octet_length(function_row.prosrc) AS source_bytes
        FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid=
          'app.private_ticket_numbering_namespace_digest_v1(text,text,public.ticket_numbering_period,integer)'::regprocedure
      `;
      assert.deepEqual(before, { has_sql_body: true, source_bytes: 0 });
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_ticket_numbering_namespace_digest_v1(
            p_prefix text,
            p_separator text,
            p_period public.ticket_numbering_period,
            p_width integer
          )
        RETURNS bytea LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT
        SET search_path=pg_catalog,public,app
        RETURN pg_catalog.sha256(pg_catalog.convert_to(
          'v50-tampered-ticket-namespace', 'UTF8'
        ))
      `);
      const [after] = await transaction<
        { has_sql_body: boolean; source_bytes: number }[]
      >`
        SELECT function_row.prosqlbody IS NOT NULL AS has_sql_body,
               pg_catalog.octet_length(function_row.prosrc) AS source_bytes
        FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid=
          'app.private_ticket_numbering_namespace_digest_v1(text,text,public.ticket_numbering_period,integer)'::regprocedure
      `;
      assert.deepEqual(after, { has_sql_body: true, source_bytes: 0 });
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "a parsed SQL-standard body must be covered even when prosrc is empty",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw sqlStandardBodyRollback;
    }),
    (error: unknown) => error === sqlStandardBodyRollback,
  );

  const rewriteRuleRollback = { kind: "rewrite-rule-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE RULE v50_rewrite_tamper
        AS ON DELETE TO public.alert_relation_retractions
        DO INSTEAD NOTHING
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rewriteRuleRollback;
    }),
    (error: unknown) => error === rewriteRuleRollback,
  );

  const enumAclRollback = { kind: "enum-acl-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        REVOKE USAGE ON TYPE public.alert_status FROM PUBLIC
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw enumAclRollback;
    }),
    (error: unknown) => error === enumAclRollback,
  );

  const internalConstraintTriggerRollback = {
    kind: "internal-constraint-trigger-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER TABLE public.audit_chain_heads DISABLE TRIGGER ALL
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw internalConstraintTriggerRollback;
    }),
    (error: unknown) => error === internalConstraintTriggerRollback,
  );

  const appViewRollback = { kind: "app-view-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE VIEW app.ticket_service_account_attributions_v1 AS
        SELECT tenant_id,id,display_name
        FROM public.tenant_service_accounts
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw appViewRollback;
    }),
    (error: unknown) => error === appViewRollback,
  );

  const inheritanceRollback = { kind: "inheritance-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER TABLE public.tenant_role_permissions
        INHERIT public.platform_role_permissions
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw inheritanceRollback;
    }),
    (error: unknown) => error === inheritanceRollback,
  );

  const publicFunctionRollback = { kind: "public-function-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION public.v50_public_function_probe()
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true'
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw publicFunctionRollback;
    }),
    (error: unknown) => error === publicFunctionRollback,
  );

  const castRollback = { kind: "cast-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE CAST (text AS public.alert_status) WITH INOUT AS IMPLICIT
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw castRollback;
    }),
    (error: unknown) => error === castRollback,
  );

  const operatorRollback = { kind: "operator-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE SCHEMA v50_evil;
        CREATE FUNCTION v50_evil.alert_status_eq(
          public.alert_status,
          public.alert_status
        ) RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT false'
      `);
      assert.equal(
        await readCatalogDigest(transaction),
        expectedCatalogDigest,
        "an external helper alone is outside the application namespace",
      );
      const [before] = await transaction.unsafe<{ result: boolean }[]>(`
        SELECT 'new'::public.alert_status = 'new'::public.alert_status
          AS result /* v50-operator-before */
      `);
      assert.equal(before?.result, true);
      await transaction.unsafe(`
        CREATE OPERATOR public.= (
          LEFTARG=public.alert_status,
          RIGHTARG=public.alert_status,
          FUNCTION=v50_evil.alert_status_eq
        )
      `);
      const [after] = await transaction.unsafe<{ result: boolean }[]>(`
        SELECT 'new'::public.alert_status = 'new'::public.alert_status
          AS result /* v50-operator-after */
      `);
      assert.equal(after?.result, false);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw operatorRollback;
    }),
    (error: unknown) => error === operatorRollback,
  );

  const columnAclRollback = { kind: "column-acl-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        CREATE ROLE periapsis_v50_column_acl_probe NOLOGIN
      `;
      const roleOnlyDigest = await readCatalogDigest(transaction);
      await transaction`
        GRANT SELECT (title) ON public.alerts
        TO periapsis_v50_column_acl_probe
      `;
      assert.notEqual(
        await readCatalogDigest(transaction),
        roleOnlyDigest,
        "a column ACL must add OID-independent grant evidence",
      );
      assert.equal((await readV50Readiness(transaction)).readiness[0], false);
      throw columnAclRollback;
    }),
    (error: unknown) => error === columnAclRollback,
  );

  const domainConstraintRollback = {
    kind: "domain-constraint-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE DOMAIN public.v50_domain_probe AS integer
      `);
      const domainOnlyDigest = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        ALTER DOMAIN public.v50_domain_probe
        ADD CONSTRAINT v50_positive CHECK (VALUE > 0)
      `);
      const constraintDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        constraintDigest,
        domainOnlyDigest,
        "a domain CHECK must add its own catalog evidence",
      );
      assert.equal((await readV50Readiness(transaction)).readiness[0], false);
      throw domainConstraintRollback;
    }),
    (error: unknown) => error === domainConstraintRollback,
  );

  const eventTriggerRollback = { kind: "event-trigger-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION public.v50_event_trigger_handler()
        RETURNS event_trigger LANGUAGE plpgsql
        SET search_path=pg_catalog
        AS 'BEGIN NULL; END'
      `);
      const handlerOnlyDigest = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        CREATE EVENT TRIGGER v50_event_trigger_probe
        ON ddl_command_end
        WHEN TAG IN ('CREATE TABLE')
        EXECUTE FUNCTION public.v50_event_trigger_handler()
      `);
      const eventTriggerDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        eventTriggerDigest,
        handlerOnlyDigest,
        "an event trigger must add evidence beyond its handler function",
      );
      assert.equal((await readV50Readiness(transaction)).readiness[0], false);
      throw eventTriggerRollback;
    }),
    (error: unknown) => error === eventTriggerRollback,
  );

  const sessionReplicationRoleRollback = {
    kind: "session-replication-role-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`SET LOCAL session_replication_role=replica`);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw sessionReplicationRoleRollback;
    }),
    (error: unknown) => error === sessionReplicationRoleRollback,
  );

  const rowSecuritySettingRollback = {
    kind: "row-security-setting-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`SET LOCAL row_security=off`);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rowSecuritySettingRollback;
    }),
    (error: unknown) => error === rowSecuritySettingRollback,
  );

  const publicationRollback = { kind: "publication-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE PUBLICATION v50_alert_leak
        FOR TABLE public.alerts (id) WHERE (id IS NOT NULL)
      `);
      const initialPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(initialPublicationDigest, expectedCatalogDigest);
      await transaction.unsafe(`
        CREATE PUBLICATION v50_public_schema_leak
        FOR TABLES IN SCHEMA public
      `);
      const schemaPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        schemaPublicationDigest,
        initialPublicationDigest,
        "publication schema mappings must be catalog-attested",
      );
      await transaction.unsafe(`
        CREATE PUBLICATION v50_all_tables_leak FOR ALL TABLES
      `);
      const allTablesPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        allTablesPublicationDigest,
        schemaPublicationDigest,
        "FOR ALL TABLES publications must be catalog-attested",
      );
      await transaction.unsafe(`
        ALTER PUBLICATION v50_alert_leak SET (publish='insert')
      `);
      assert.notEqual(
        await readCatalogDigest(transaction),
        allTablesPublicationDigest,
        "publication operation flags must be catalog-attested",
      );
      const drifted = await readV50Readiness(transaction);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw publicationRollback;
    }),
    (error: unknown) => error === publicationRollback,
  );

  const subscriptionRollback = { kind: "subscription-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE SUBSCRIPTION v50_injection
        CONNECTION 'host=127.0.0.1 port=1 dbname=none user=nobody'
        PUBLICATION v50_pub
        WITH (connect=false, create_slot=false, enabled=false)
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw subscriptionRollback;
    }),
    (error: unknown) => error === subscriptionRollback,
  );

  const alternateSealerOwnerRollback = {
    kind: "alternate-sealer-owner",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE ROLE v50_alternate_sealer SUPERUSER NOLOGIN;
        ALTER FUNCTION app.private_runtime_login_credential_state_v49()
          OWNER TO v50_alternate_sealer;
        SET ROLE v50_alternate_sealer;
        REVOKE ALL ON FUNCTION
          app.private_runtime_login_credential_state_v49()
          FROM PUBLIC,periapsis_migrator;
        GRANT EXECUTE ON FUNCTION
          app.private_runtime_login_credential_state_v49()
          TO periapsis_migrator;
        RESET ROLE
      `);
      assert.equal(
        await readCatalogDigest(transaction),
        expectedCatalogDigest,
        "the exact helper must normalize an alternate superuser sealer",
      );
      throw alternateSealerOwnerRollback;
    }),
    (error: unknown) => error === alternateSealerOwnerRollback,
  );

  const loginAttributeRollback = { kind: "login-attribute-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER ROLE periapsis_api_login CONNECTION LIMIT 41
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw loginAttributeRollback;
    }),
    (error: unknown) => error === loginAttributeRollback,
  );

  const loginExpiryRollback = { kind: "login-expiry-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER ROLE periapsis_api_login
        VALID UNTIL '2026-09-04T00:00:00Z'
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw loginExpiryRollback;
    }),
    (error: unknown) => error === loginExpiryRollback,
  );

  const loginPasswordMissingRollback = {
    kind: "login-password-missing-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER ROLE periapsis_api_login PASSWORD NULL
      `;
      const [credential] = await transaction<{ credential_state: string }[]>`
        SELECT credential_state
        FROM app.private_runtime_login_credential_state_v49()
        WHERE role_name='periapsis_api_login'
      `;
      assert.equal(credential?.credential_state, "absent");
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw loginPasswordMissingRollback;
    }),
    (error: unknown) => error === loginPasswordMissingRollback,
  );

  const loginPasswordFormatRollback = {
    kind: "login-password-format-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        ALTER ROLE periapsis_api_login
        PASSWORD 'md5deadbeefdeadbeefdeadbeefdeadbeef'
      `);
      const [credential] = await transaction<{ credential_state: string }[]>`
        SELECT credential_state
        FROM app.private_runtime_login_credential_state_v49()
        WHERE role_name='periapsis_api_login'
      `;
      assert.equal(credential?.credential_state, "other");
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw loginPasswordFormatRollback;
    }),
    (error: unknown) => error === loginPasswordFormatRollback,
  );

  const loginMembershipRollback = {
    kind: "login-membership-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT periapsis_migrator TO periapsis_api_login
        WITH ADMIN FALSE, INHERIT TRUE, SET TRUE
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw loginMembershipRollback;
    }),
    (error: unknown) => error === loginMembershipRollback,
  );

  const alternateGrantorRollback = {
    kind: "alternate-login-grantor",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [revoke] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'REVOKE %I FROM %I GRANTED BY %I CASCADE',
          granted_role.rolname,
          member_role.rolname,
          grantor_role.rolname
        ) AS statement
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role
          ON granted_role.oid=membership.roleid
        JOIN pg_catalog.pg_roles AS member_role
          ON member_role.oid=membership.member
        JOIN pg_catalog.pg_roles AS grantor_role
          ON grantor_role.oid=membership.grantor
        WHERE granted_role.rolname='periapsis_api'
          AND member_role.rolname='periapsis_api_login'
      `;
      assert(revoke, "the provisioned API membership is missing");
      await transaction.unsafe(`
        CREATE ROLE v50_alternate_membership_grantor NOLOGIN;
        GRANT periapsis_api TO v50_alternate_membership_grantor
          WITH ADMIN OPTION
      `);
      const withOriginalGrantor = await readCatalogDigest(transaction);
      await transaction.unsafe(revoke.statement);
      assert.notEqual(
        await readCatalogDigest(transaction),
        withOriginalGrantor,
        "removing the required login edge must remain catalog-attested",
      );
      await transaction.unsafe(`
        GRANT periapsis_api TO periapsis_api_login
          WITH ADMIN FALSE, INHERIT TRUE, SET TRUE
          GRANTED BY v50_alternate_membership_grantor
      `);
      const [edge] = await transaction<{ grantor: string }[]>`
        SELECT grantor_role.rolname::text AS grantor
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role
          ON granted_role.oid=membership.roleid
        JOIN pg_catalog.pg_roles AS member_role
          ON member_role.oid=membership.member
        JOIN pg_catalog.pg_roles AS grantor_role
          ON grantor_role.oid=membership.grantor
        WHERE granted_role.rolname='periapsis_api'
          AND member_role.rolname='periapsis_api_login'
      `;
      assert.equal(edge?.grantor, "v50_alternate_membership_grantor");
      assert.equal(
        await readCatalogDigest(transaction),
        withOriginalGrantor,
        "the one exact lifecycle edge must normalize independently of its configured admin grantor",
      );
      throw alternateGrantorRollback;
    }),
    (error: unknown) => error === alternateGrantorRollback,
  );

  const membershipOptionsRollback = {
    kind: "membership-options-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE ROLE periapsis_v50_membership_granted NOLOGIN;
        CREATE ROLE periapsis_v50_membership_member NOLOGIN;
        GRANT periapsis_v50_membership_granted
          TO periapsis_v50_membership_member
          WITH ADMIN FALSE, INHERIT TRUE, SET TRUE
      `);
      const inherited = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        GRANT periapsis_v50_membership_granted
          TO periapsis_v50_membership_member
          WITH ADMIN FALSE, INHERIT FALSE, SET FALSE
      `);
      const fenced = await readCatalogDigest(transaction);
      assert.notEqual(
        fenced,
        inherited,
        "membership INHERIT and SET options must be catalog-attested",
      );
      throw membershipOptionsRollback;
    }),
    (error: unknown) => error === membershipOptionsRollback,
  );

  const aclGrantorRollback = { kind: "acl-grantor-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE ROLE periapsis_v50_acl_grantor NOLOGIN;
        CREATE ROLE periapsis_v50_acl_grantee NOLOGIN;
        GRANT USAGE ON SCHEMA app TO periapsis_v50_acl_grantor;
        CREATE FUNCTION app.v50_acl_grantor_probe()
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true';
        ALTER FUNCTION app.v50_acl_grantor_probe()
          OWNER TO periapsis_migrator;
        REVOKE ALL ON FUNCTION app.v50_acl_grantor_probe() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app.v50_acl_grantor_probe()
          TO periapsis_v50_acl_grantor WITH GRANT OPTION;
        SET ROLE periapsis_v50_acl_grantor;
        GRANT EXECUTE ON FUNCTION app.v50_acl_grantor_probe()
          TO periapsis_v50_acl_grantee;
        RESET ROLE
      `);
      const delegated = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        SET ROLE periapsis_v50_acl_grantor;
        REVOKE EXECUTE ON FUNCTION app.v50_acl_grantor_probe()
          FROM periapsis_v50_acl_grantee;
        RESET ROLE;
        SET ROLE periapsis_migrator;
        GRANT EXECUTE ON FUNCTION app.v50_acl_grantor_probe()
          TO periapsis_v50_acl_grantee;
        RESET ROLE
      `);
      const ownerGranted = await readCatalogDigest(transaction);
      assert.notEqual(
        ownerGranted,
        delegated,
        "the same effective ACL with a different grantor must change the digest",
      );
      throw aclGrantorRollback;
    }),
    (error: unknown) => error === aclGrantorRollback,
  );

  const parameterAclRollback = { kind: "parameter-acl-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT SET ON PARAMETER session_replication_role TO periapsis_api
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw parameterAclRollback;
    }),
    (error: unknown) => error === parameterAclRollback,
  );

  const defaultAclRollback = { kind: "default-acl-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE ROLE v50_external_default_acl_owner NOLOGIN;
        ALTER DEFAULT PRIVILEGES FOR ROLE v50_external_default_acl_owner
          GRANT SELECT ON TABLES TO periapsis_api
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw defaultAclRollback;
    }),
    (error: unknown) => error === defaultAclRollback,
  );

  const databaseAclRollback = { kind: "database-acl-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [grant] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'GRANT CREATE ON DATABASE %I TO periapsis_api',
          pg_catalog.current_database()
        ) AS statement
      `;
      assert(grant, "database ACL tamper statement was not generated");
      await transaction.unsafe(grant.statement);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw databaseAclRollback;
    }),
    (error: unknown) => error === databaseAclRollback,
  );

  const databaseOwnerRollback = { kind: "database-owner-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [alter] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'ALTER DATABASE %I OWNER TO periapsis_api',
          pg_catalog.current_database()
        ) AS statement
      `;
      assert(alter, "database owner tamper statement was not generated");
      await transaction.unsafe(alter.statement);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw databaseOwnerRollback;
    }),
    (error: unknown) => error === databaseOwnerRollback,
  );

  const alternateDatabaseOwnerRollback = {
    kind: "alternate-database-owner",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        CREATE ROLE v50_alternate_database_owner SUPERUSER NOLOGIN
      `;
      const [alter] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'ALTER DATABASE %I OWNER TO v50_alternate_database_owner',
          pg_catalog.current_database()
        ) AS statement
      `;
      assert(alter, "alternate database owner statement was not generated");
      await transaction.unsafe(alter.statement);
      assert.equal(
        await readCatalogDigest(transaction),
        expectedCatalogDigest,
        "an exact non-runtime superuser database owner must remain deployment-neutral",
      );
      throw alternateDatabaseOwnerRollback;
    }),
    (error: unknown) => error === alternateDatabaseOwnerRollback,
  );

  const databaseSettingRollback = {
    kind: "database-setting-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      const [alter] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'ALTER DATABASE %I SET work_mem = %L',
          pg_catalog.current_database(),
          '64MB'
        ) AS statement
      `;
      assert(alter, "database setting tamper statement was not generated");
      await transaction.unsafe(alter.statement);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw databaseSettingRollback;
    }),
    (error: unknown) => error === databaseSettingRollback,
  );

  const globalRoleSettingRollback = {
    kind: "global-role-setting-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        ALTER ROLE ALL SET application_name = 'v50-global-role-tamper'
      `);
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw globalRoleSettingRollback;
    }),
    (error: unknown) => error === globalRoleSettingRollback,
  );

  const notifierChainSourceRollback = {
    kind: "notifier-chain-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v50()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      assert.equal(
        await readCatalogDigest(transaction),
        expectedCatalogDigest,
        "the exact private V50 root remains self-excluded from its own digest",
      );
      assert.equal(
        await readNotifierSourceAttestation(transaction),
        false,
        "the notifier must independently source-attest its V50 trust chain",
      );
      throw notifierChainSourceRollback;
    }),
    (error: unknown) => error === notifierChainSourceRollback,
  );

  const sameNameOverloadRollback = {
    kind: "same-name-v50-overload",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION app.release_runtime_schema_readiness_v50(text)
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true'
      `);
      await transaction`
        ALTER FUNCTION app.release_runtime_schema_readiness_v50(text)
        OWNER TO periapsis_migrator
      `;
      await transaction`
        REVOKE ALL ON FUNCTION app.release_runtime_schema_readiness_v50(text)
        FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
             periapsis_auditor
      `;
      const drifted = await readV50Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "a same-name overload must not inherit the exact V50 self-exclusion",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw sameNameOverloadRollback;
    }),
    (error: unknown) => error === sameNameOverloadRollback,
  );

  assert.deepEqual(await readV50Readiness(sql), readiness);
} finally {
  await sql.end();
}
