import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import postgres, { type Sql } from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedNotificationDispatchReadinessV60SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV60SourceHash,
  expectedPrivateReleaseRuntimeReadinessV60SourceHash,
  expectedReleaseRuntimeReadinessV60SourceHash,
  expectedRetiredSchemaCompatibilityV50SourceHash,
  expectedRetiredSchemaCompatibilityV51SourceHash,
  expectedRetiredSchemaCompatibilityV52SourceHash,
  expectedRetiredSchemaCompatibilityV53SourceHash,
  expectedRetiredSchemaCompatibilityV54SourceHash,
  expectedRetiredSchemaCompatibilityV55SourceHash,
  expectedRetiredSchemaCompatibilityV56SourceHash,
  expectedRetiredSchemaCompatibilityV57SourceHash,
  expectedRetiredSchemaCompatibilityV58SourceHash,
  expectedRetiredSchemaCompatibilityV59SourceHash,
  expectedSchemaCompatibilityV60SourceHash,
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

const retiredV50Roots = [
  "schema_compatibility_v50",
  "release_runtime_schema_readiness_v50",
  "federated_authentication_schema_readiness_v50",
  "platform_oidc_direct_runtime_schema_readiness_v50",
  "platform_saml_direct_runtime_schema_readiness_v50",
  "platform_local_account_runtime_schema_readiness_v50",
  "sla_trigger_action_runtime_schema_readiness_v50",
  "sla_object_event_ingress_schema_readiness_v50",
  "ticket_bulk_runtime_schema_readiness_v50",
  "ticket_export_runtime_schema_readiness_v50",
  "ticket_metadata_runtime_schema_readiness_v50",
  "notification_dispatch_readiness_v50",
] as const;

const retainedPrivateV50Roots = [
  "private_schema_compatibility_journal_v50",
  "private_release_runtime_dependency_surface_hash_v50",
  "private_release_runtime_schema_readiness_v50",
] as const;

const retiredV51Roots = [
  "schema_compatibility_v51",
  "release_runtime_schema_readiness_v51",
  "federated_authentication_schema_readiness_v51",
  "platform_oidc_direct_runtime_schema_readiness_v51",
  "platform_saml_direct_runtime_schema_readiness_v51",
  "platform_local_account_runtime_schema_readiness_v51",
  "sla_trigger_action_runtime_schema_readiness_v51",
  "sla_object_event_ingress_schema_readiness_v51",
  "ticket_bulk_runtime_schema_readiness_v51",
  "ticket_export_runtime_schema_readiness_v51",
  "ticket_metadata_runtime_schema_readiness_v51",
  "notification_dispatch_readiness_v51",
] as const;

const retainedPrivateV51Roots = [
  "private_schema_compatibility_journal_v51",
  "private_release_runtime_dependency_surface_hash_v51",
  "private_release_runtime_schema_readiness_v51",
] as const;

const retiredV52Roots = [
  "schema_compatibility_v52",
  "release_runtime_schema_readiness_v52",
  "federated_authentication_schema_readiness_v52",
  "platform_oidc_direct_runtime_schema_readiness_v52",
  "platform_saml_direct_runtime_schema_readiness_v52",
  "platform_local_account_runtime_schema_readiness_v52",
  "sla_trigger_action_runtime_schema_readiness_v52",
  "sla_object_event_ingress_schema_readiness_v52",
  "ticket_bulk_runtime_schema_readiness_v52",
  "ticket_export_runtime_schema_readiness_v52",
  "ticket_metadata_runtime_schema_readiness_v52",
  "notification_dispatch_readiness_v52",
  "api_runtime_schema_readiness_v52",
  "worker_runtime_schema_readiness_v52",
] as const;

const retainedPrivateV52Roots = [
  "private_schema_compatibility_journal_v52",
  "private_release_runtime_dependency_surface_hash_v52",
  "private_release_runtime_schema_readiness_v52",
] as const;

const retiredV53Roots = [
  "schema_compatibility_v53",
  "release_runtime_schema_readiness_v53",
  "federated_authentication_schema_readiness_v53",
  "platform_oidc_direct_runtime_schema_readiness_v53",
  "platform_saml_direct_runtime_schema_readiness_v53",
  "platform_local_account_runtime_schema_readiness_v53",
  "sla_trigger_action_runtime_schema_readiness_v53",
  "sla_object_event_ingress_schema_readiness_v53",
  "ticket_bulk_runtime_schema_readiness_v53",
  "ticket_export_runtime_schema_readiness_v53",
  "ticket_metadata_runtime_schema_readiness_v53",
  "notification_dispatch_readiness_v53",
  "api_runtime_schema_readiness_v53",
  "worker_runtime_schema_readiness_v53",
] as const;

const retainedPrivateV53Roots = [
  "private_schema_compatibility_journal_v53",
  "private_release_runtime_dependency_surface_hash_v53",
  "private_release_runtime_schema_readiness_v53",
] as const;

const retiredV54Roots = [
  "schema_compatibility_v54",
  "release_runtime_schema_readiness_v54",
  "federated_authentication_schema_readiness_v54",
  "platform_oidc_direct_runtime_schema_readiness_v54",
  "platform_saml_direct_runtime_schema_readiness_v54",
  "platform_local_account_runtime_schema_readiness_v54",
  "sla_trigger_action_runtime_schema_readiness_v54",
  "sla_object_event_ingress_schema_readiness_v54",
  "ticket_bulk_runtime_schema_readiness_v54",
  "ticket_export_runtime_schema_readiness_v54",
  "ticket_metadata_runtime_schema_readiness_v54",
  "notification_dispatch_readiness_v54",
  "api_runtime_schema_readiness_v54",
  "worker_runtime_schema_readiness_v54",
] as const;

const retainedPrivateV54Roots = [
  "private_schema_compatibility_journal_v54",
  "private_release_runtime_dependency_surface_hash_v54",
  "private_release_runtime_schema_readiness_v54",
] as const;

const retiredV55Roots = [
  "schema_compatibility_v55",
  "release_runtime_schema_readiness_v55",
  "federated_authentication_schema_readiness_v55",
  "platform_oidc_direct_runtime_schema_readiness_v55",
  "platform_saml_direct_runtime_schema_readiness_v55",
  "platform_local_account_runtime_schema_readiness_v55",
  "sla_trigger_action_runtime_schema_readiness_v55",
  "sla_object_event_ingress_schema_readiness_v55",
  "ticket_bulk_runtime_schema_readiness_v55",
  "ticket_export_runtime_schema_readiness_v55",
  "ticket_metadata_runtime_schema_readiness_v55",
  "notification_dispatch_readiness_v55",
  "api_runtime_schema_readiness_v55",
  "worker_runtime_schema_readiness_v55",
] as const;

const retainedPrivateV55Roots = [
  "private_schema_compatibility_journal_v55",
  "private_release_runtime_dependency_surface_hash_v55",
  "private_release_runtime_schema_readiness_v55",
] as const;

const retiredV56Roots = [
  "schema_compatibility_v56",
  "release_runtime_schema_readiness_v56",
  "federated_authentication_schema_readiness_v56",
  "platform_oidc_direct_runtime_schema_readiness_v56",
  "platform_saml_direct_runtime_schema_readiness_v56",
  "platform_local_account_runtime_schema_readiness_v56",
  "sla_trigger_action_runtime_schema_readiness_v56",
  "sla_object_event_ingress_schema_readiness_v56",
  "ticket_bulk_runtime_schema_readiness_v56",
  "ticket_export_runtime_schema_readiness_v56",
  "ticket_metadata_runtime_schema_readiness_v56",
  "notification_dispatch_readiness_v56",
  "api_runtime_schema_readiness_v56",
  "worker_runtime_schema_readiness_v56",
] as const;

const retainedPrivateV56Roots = [
  "private_schema_compatibility_journal_v56",
  "private_release_runtime_dependency_surface_hash_v56",
  "private_release_runtime_schema_readiness_v56",
] as const;

const retiredV57Roots = [
  "schema_compatibility_v57",
  "release_runtime_schema_readiness_v57",
  "federated_authentication_schema_readiness_v57",
  "platform_oidc_direct_runtime_schema_readiness_v57",
  "platform_saml_direct_runtime_schema_readiness_v57",
  "platform_local_account_runtime_schema_readiness_v57",
  "sla_trigger_action_runtime_schema_readiness_v57",
  "sla_object_event_ingress_schema_readiness_v57",
  "ticket_bulk_runtime_schema_readiness_v57",
  "ticket_export_runtime_schema_readiness_v57",
  "ticket_metadata_runtime_schema_readiness_v57",
  "notification_dispatch_readiness_v57",
  "api_runtime_schema_readiness_v57",
  "worker_runtime_schema_readiness_v57",
] as const;

const retainedPrivateV57Roots = [
  "private_schema_compatibility_journal_v57",
  "private_release_runtime_dependency_surface_hash_v57",
  "private_release_runtime_schema_readiness_v57",
] as const;

const retiredV58Roots = [
  "schema_compatibility_v58",
  "release_runtime_schema_readiness_v58",
  "federated_authentication_schema_readiness_v58",
  "platform_oidc_direct_runtime_schema_readiness_v58",
  "platform_saml_direct_runtime_schema_readiness_v58",
  "platform_local_account_runtime_schema_readiness_v58",
  "sla_trigger_action_runtime_schema_readiness_v58",
  "sla_object_event_ingress_schema_readiness_v58",
  "ticket_bulk_runtime_schema_readiness_v58",
  "ticket_export_runtime_schema_readiness_v58",
  "ticket_metadata_runtime_schema_readiness_v58",
  "notification_dispatch_readiness_v58",
  "api_runtime_schema_readiness_v58",
  "worker_runtime_schema_readiness_v58",
] as const;

const retainedPrivateV58Roots = [
  "private_schema_compatibility_journal_v58",
  "private_release_runtime_dependency_surface_hash_v58",
  "private_release_runtime_schema_readiness_v58",
] as const;

const retiredV59Roots = [
  "schema_compatibility_v59",
  "release_runtime_schema_readiness_v59",
  "federated_authentication_schema_readiness_v59",
  "platform_oidc_direct_runtime_schema_readiness_v59",
  "platform_saml_direct_runtime_schema_readiness_v59",
  "platform_local_account_runtime_schema_readiness_v59",
  "sla_trigger_action_runtime_schema_readiness_v59",
  "sla_object_event_ingress_schema_readiness_v59",
  "ticket_bulk_runtime_schema_readiness_v59",
  "ticket_export_runtime_schema_readiness_v59",
  "ticket_metadata_runtime_schema_readiness_v59",
  "notification_dispatch_readiness_v59",
  "api_runtime_schema_readiness_v59",
  "worker_runtime_schema_readiness_v59",
] as const;

const retainedPrivateV59Roots = [
  "private_schema_compatibility_journal_v59",
  "private_release_runtime_dependency_surface_hash_v59",
  "private_release_runtime_schema_readiness_v59",
] as const;

const runtimeRoles = [
  "periapsis_api",
  "periapsis_worker",
  "periapsis_notifier",
  "periapsis_auditor",
] as const;

const migrationsRoot = resolve(import.meta.dirname, "../../migrations");
const v60Migration = await readFile(
  resolve(migrationsRoot, "0251_v60_compatibility.sql"),
  "utf8",
);
const expectedCatalogDigest =
  /private_release_runtime_dependency_surface_hash_v60\(\)<>\s*'([0-9a-f]{64})'/u.exec(
    v60Migration,
  )?.[1];
assert(
  expectedCatalogDigest,
  "0251 must pin the exact V60 release catalog digest",
);
assert.notEqual(
  expectedCatalogDigest,
  "0".repeat(64),
  "0251 must contain the independently derived V60 digest, not a placeholder",
);
assert.equal(
  expectedCatalogDigest,
  "6b34359cbbd03507f2eb268447438630ef38581ed757cdf341c50d93064c4d7f",
);
assert.equal(expectedMigrationCount, 252);
assert.equal(expectedMigrationCreatedAt, 1_788_877_946_518);

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

async function readV60Readiness(
  sql: Sql | postgres.TransactionSql,
): Promise<ReadinessRow> {
  const [row] = await sql<ReadinessRow[]>`
    SELECT app.private_release_runtime_dependency_surface_hash_v60()
             AS catalog_digest,
           ARRAY[
             app.private_release_runtime_schema_readiness_v60(),
             app.release_runtime_schema_readiness_v60(),
             app.federated_authentication_schema_readiness_v60(),
             app.platform_oidc_direct_runtime_schema_readiness_v60(),
             app.platform_saml_direct_runtime_schema_readiness_v60(),
             app.platform_local_account_runtime_schema_readiness_v60(),
             app.sla_trigger_action_runtime_schema_readiness_v60(),
             app.sla_object_event_ingress_schema_readiness_v60(),
             app.ticket_bulk_runtime_schema_readiness_v60(),
             app.ticket_export_runtime_schema_readiness_v60(),
             app.ticket_metadata_runtime_schema_readiness_v60(),
             app.alert_dfir_runtime_schema_readiness_v2(),
             (SELECT readiness.schema_safe
              FROM app.notification_dispatch_readiness_v60() AS readiness)
           ]::boolean[] || app.api_runtime_schema_readiness_v60()
             || app.worker_runtime_schema_readiness_v60() AS readiness
  `;
  assert(row, "V60 readiness returned no row");
  assert.equal(row.readiness.length, 26);
  if (row.readiness[1] === false) {
    assert.deepEqual(
      row.readiness.slice(13),
      Array<boolean>(13).fill(false),
      "both service aggregates must close for every rejected catalog fixture",
    );
  }
  return row;
}

async function readCatalogDigest(
  sql: Sql | postgres.TransactionSql,
): Promise<string> {
  const [row] = await sql<{ digest: string }[]>`
    SELECT app.private_release_runtime_dependency_surface_hash_v60()
             AS digest
  `;
  assert(row, "V60 catalog digest returned no row");
  return row.digest;
}

async function readNotifierSourceAttestation(
  sql: Sql | postgres.TransactionSql,
): Promise<boolean> {
  const [row] = await sql<{ source_safe: boolean }[]>`
    WITH expected(signature, source_hash) AS (
      VALUES
        ('app.schema_compatibility_v60()',
          ${expectedSchemaCompatibilityV60SourceHash}),
        ('app.private_release_runtime_dependency_surface_hash_v60()',
          ${expectedPrivateReleaseRuntimeDependencySurfaceHashV60SourceHash}),
        ('app.private_release_runtime_schema_readiness_v60()',
          ${expectedPrivateReleaseRuntimeReadinessV60SourceHash}),
        ('app.release_runtime_schema_readiness_v60()',
          ${expectedReleaseRuntimeReadinessV60SourceHash}),
        ('app.notification_dispatch_readiness_v60()',
          ${expectedNotificationDispatchReadinessV60SourceHash})
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
  assert(row, "notifier V60 source attestation returned no row");
  return row.source_safe;
}

const databaseUrl =
  process.env.PERIAPSIS_SCHEMA_COMPATIBILITY_V60_SECURITY_TEST_DATABASE_URL;
assert(
  databaseUrl !== undefined && databaseUrl.trim() !== "",
  "PERIAPSIS_SCHEMA_COMPATIBILITY_V60_SECURITY_TEST_DATABASE_URL is required",
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
    SELECT * FROM app.schema_compatibility_v60()
  `;
  assert(compatibility, "schema_compatibility_v60 returned no row");
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

  const readiness = await readV60Readiness(sql);
  assert.equal(readiness.catalog_digest, expectedCatalogDigest);
  assert.equal(readiness.readiness.length, 26);
  assert(!readiness.readiness.includes(false), "a V60 readiness root failed");
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

  const retiredV50Catalog = await readFunctionCatalog(sql, retiredV50Roots);
  assert.equal(retiredV50Catalog.length, 12);
  for (const root of retiredV50Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v50";
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

  const [retiredV50Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV50Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV50Privileges, { granted_count: 0 });

  const [retiredV50Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v50()
  `;
  assert(retiredV50Compatibility, "retired V50 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV50Compatibility,
      applied_count: Number(retiredV50Compatibility.applied_count),
      latest_created_at: Number(retiredV50Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV50Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v50()'::regprocedure
  `;
  assert.deepEqual(retiredV50Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV51Catalog = await readFunctionCatalog(sql, retiredV51Roots);
  assert.equal(retiredV51Catalog.length, 12);
  for (const root of retiredV51Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v51";
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

  const [retiredV51Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV51Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV51Privileges, { granted_count: 0 });

  const [retiredV51Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v51()
  `;
  assert(retiredV51Compatibility, "retired V51 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV51Compatibility,
      applied_count: Number(retiredV51Compatibility.applied_count),
      latest_created_at: Number(retiredV51Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV51Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v51()'::regprocedure
  `;
  assert.deepEqual(retiredV51Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV52Catalog = await readFunctionCatalog(sql, retiredV52Roots);
  assert.equal(retiredV52Catalog.length, 14);
  for (const root of retiredV52Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v52";
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

  const [retiredV52Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV52Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV52Privileges, { granted_count: 0 });

  const [retiredV52Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v52()
  `;
  assert(retiredV52Compatibility, "retired V52 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV52Compatibility,
      applied_count: Number(retiredV52Compatibility.applied_count),
      latest_created_at: Number(retiredV52Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV52Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v52()'::regprocedure
  `;
  assert.deepEqual(retiredV52Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV53Catalog = await readFunctionCatalog(sql, retiredV53Roots);
  assert.equal(retiredV53Catalog.length, 14);
  for (const root of retiredV53Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v53";
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

  const [retiredV53Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV53Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV53Privileges, { granted_count: 0 });

  const [retiredV53Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v53()
  `;
  assert(retiredV53Compatibility, "retired V53 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV53Compatibility,
      applied_count: Number(retiredV53Compatibility.applied_count),
      latest_created_at: Number(retiredV53Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV53Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v53()'::regprocedure
  `;
  assert.deepEqual(retiredV53Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV54Catalog = await readFunctionCatalog(sql, retiredV54Roots);
  assert.equal(retiredV54Catalog.length, 14);
  for (const root of retiredV54Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v54";
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

  const [retiredV54Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV54Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV54Privileges, { granted_count: 0 });

  const [retiredV54Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v54()
  `;
  assert(retiredV54Compatibility, "retired V54 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV54Compatibility,
      applied_count: Number(retiredV54Compatibility.applied_count),
      latest_created_at: Number(retiredV54Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV54Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v54()'::regprocedure
  `;
  assert.deepEqual(retiredV54Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV55Catalog = await readFunctionCatalog(sql, retiredV55Roots);
  assert.equal(retiredV55Catalog.length, 14);
  for (const root of retiredV55Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v55";
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

  const [retiredV55Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV55Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV55Privileges, { granted_count: 0 });

  const [retiredV55Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v55()
  `;
  assert(retiredV55Compatibility, "retired V55 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV55Compatibility,
      applied_count: Number(retiredV55Compatibility.applied_count),
      latest_created_at: Number(retiredV55Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV55Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v55()'::regprocedure
  `;
  assert.deepEqual(retiredV55Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV56Catalog = await readFunctionCatalog(sql, retiredV56Roots);
  assert.equal(retiredV56Catalog.length, 14);
  for (const root of retiredV56Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v56";
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

  const [retiredV56Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV56Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV56Privileges, { granted_count: 0 });

  const [retiredV56Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v56()
  `;
  assert(retiredV56Compatibility, "retired V56 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV56Compatibility,
      applied_count: Number(retiredV56Compatibility.applied_count),
      latest_created_at: Number(retiredV56Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV56Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v56()'::regprocedure
  `;
  assert.deepEqual(retiredV56Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV57Catalog = await readFunctionCatalog(sql, retiredV57Roots);
  assert.equal(retiredV57Catalog.length, 14);
  for (const root of retiredV57Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v57";
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

  const [retiredV57Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV57Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV57Privileges, { granted_count: 0 });

  const [retiredV57Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v57()
  `;
  assert(retiredV57Compatibility, "retired V57 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV57Compatibility,
      applied_count: Number(retiredV57Compatibility.applied_count),
      latest_created_at: Number(retiredV57Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV57Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v57()'::regprocedure
  `;
  assert.deepEqual(retiredV57Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV58Catalog = await readFunctionCatalog(sql, retiredV58Roots);
  assert.equal(retiredV58Catalog.length, 14);
  for (const root of retiredV58Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v58";
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

  const [retiredV58Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV58Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV58Privileges, { granted_count: 0 });

  const [retiredV58Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v58()
  `;
  assert(retiredV58Compatibility, "retired V58 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV58Compatibility,
      applied_count: Number(retiredV58Compatibility.applied_count),
      latest_created_at: Number(retiredV58Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV58Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v58()'::regprocedure
  `;
  assert.deepEqual(retiredV58Config, {
    config: [
      "search_path=pg_catalog",
      "app.schema_compatibility_fingerprint=RETIRED",
    ],
  });

  const retiredV59Catalog = await readFunctionCatalog(sql, retiredV59Roots);
  assert.equal(retiredV59Catalog.length, 14);
  for (const root of retiredV59Catalog) {
    const notificationRoot =
      root.function_name === "notification_dispatch_readiness_v59";
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

  const [retiredV59Privileges] = await sql<{ granted_count: number }[]>`
    SELECT count(*)::integer AS granted_count
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=function_row.pronamespace
    CROSS JOIN unnest(${[...runtimeRoles]}::text[]) AS runtime_role(name)
    WHERE namespace.nspname='app' AND function_row.pronargs=0
      AND function_row.proname=ANY(${[...retiredV59Roots]}::text[])
      AND pg_catalog.has_function_privilege(
        runtime_role.name,function_row.oid,'EXECUTE'
      )
  `;
  assert.deepEqual(retiredV59Privileges, { granted_count: 0 });

  const [retiredV59Compatibility] = await sql<CompatibilityRow[]>`
    SELECT * FROM app.schema_compatibility_v59()
  `;
  assert(retiredV59Compatibility, "retired V59 compatibility returned no row");
  assert.deepEqual(
    {
      ...retiredV59Compatibility,
      applied_count: Number(retiredV59Compatibility.applied_count),
      latest_created_at: Number(retiredV59Compatibility.latest_created_at),
    },
    {
      applied_count: 0,
      latest_created_at: 0,
      latest_hash: "UNSUPPORTED",
      migration_fingerprint: "UNSUPPORTED",
    },
  );
  const [retiredV59Config] = await sql<{ config: string[] }[]>`
    SELECT function_row.proconfig AS config
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid='app.schema_compatibility_v59()'::regprocedure
  `;
  assert.deepEqual(retiredV59Config, {
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
    "notification_dispatch_readiness_v60",
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
      ],
      function_name: "notification_dispatch_readiness_v50",
      owner_name: "periapsis_notification_readiness_owner",
      runtime_execute_count: 0,
    },
    {
      acl_roles: [
        "periapsis_migrator",
        "periapsis_notification_readiness_owner",
        "periapsis_notifier",
      ],
      function_name: "notification_dispatch_readiness_v60",
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

  const privateV50Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV50Roots,
  );
  assert.equal(privateV50Catalog.length, retainedPrivateV50Roots.length);
  for (const root of privateV50Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV50Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v50()'::regprocedure
  `;
  assert.equal(
    retiredV50Source?.source_hash,
    expectedRetiredSchemaCompatibilityV50SourceHash,
  );

  const normalizedV50GrantRollback = {
    kind: "normalized-v50-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v50()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V50 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V50 grant",
      );
      throw normalizedV50GrantRollback;
    }),
    (error: unknown) => error === normalizedV50GrantRollback,
  );

  const normalizedV50NotifierGrantRollback = {
    kind: "normalized-v50-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v50()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV50NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV50NotifierGrantRollback,
  );

  const rotatedV50AclTamperRollback = {
    kind: "rotated-v50-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v50()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV50AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV50AclTamperRollback,
  );

  const rotatedV50ConfigTamperRollback = {
    kind: "rotated-v50-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v50() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV50ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV50ConfigTamperRollback,
  );

  const unnormalizedV50ConfigRollback = {
    kind: "unnormalized-private-v50-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v50()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV50ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV50ConfigRollback,
  );

  const historicalV50SourceRollback = {
    kind: "historical-v50-private-readiness-source-tamper",
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
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V50 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV50SourceRollback;
    }),
    (error: unknown) => error === historicalV50SourceRollback,
  );

  const privateV51Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV51Roots,
  );
  assert.equal(privateV51Catalog.length, retainedPrivateV51Roots.length);
  for (const root of privateV51Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV51Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v51()'::regprocedure
  `;
  assert.equal(
    retiredV51Source?.source_hash,
    expectedRetiredSchemaCompatibilityV51SourceHash,
  );

  const normalizedV51GrantRollback = {
    kind: "normalized-v51-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v51()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V51 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V51 grant",
      );
      throw normalizedV51GrantRollback;
    }),
    (error: unknown) => error === normalizedV51GrantRollback,
  );

  const normalizedV51NotifierGrantRollback = {
    kind: "normalized-v51-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v51()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV51NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV51NotifierGrantRollback,
  );

  const rotatedV51AclTamperRollback = {
    kind: "rotated-v51-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v51()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV51AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV51AclTamperRollback,
  );

  const rotatedV51ConfigTamperRollback = {
    kind: "rotated-v51-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v51() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV51ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV51ConfigTamperRollback,
  );

  const unnormalizedV51ConfigRollback = {
    kind: "unnormalized-private-v51-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v51()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV51ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV51ConfigRollback,
  );

  const historicalV51SourceRollback = {
    kind: "historical-v51-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v51()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V51 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV51SourceRollback;
    }),
    (error: unknown) => error === historicalV51SourceRollback,
  );

  const privateV52Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV52Roots,
  );
  assert.equal(privateV52Catalog.length, retainedPrivateV52Roots.length);
  for (const root of privateV52Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV52Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v52()'::regprocedure
  `;
  assert.equal(
    retiredV52Source?.source_hash,
    expectedRetiredSchemaCompatibilityV52SourceHash,
  );

  const normalizedV52GrantRollback = {
    kind: "normalized-v52-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v52()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V52 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V52 grant",
      );
      throw normalizedV52GrantRollback;
    }),
    (error: unknown) => error === normalizedV52GrantRollback,
  );

  const normalizedV52NotifierGrantRollback = {
    kind: "normalized-v52-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v52()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV52NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV52NotifierGrantRollback,
  );

  const rotatedV52AclTamperRollback = {
    kind: "rotated-v52-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v52()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV52AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV52AclTamperRollback,
  );

  const rotatedV52ConfigTamperRollback = {
    kind: "rotated-v52-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v52() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV52ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV52ConfigTamperRollback,
  );

  const unnormalizedV52ConfigRollback = {
    kind: "unnormalized-private-v52-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v52()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV52ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV52ConfigRollback,
  );

  const historicalV52SourceRollback = {
    kind: "historical-v52-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v52()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V52 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV52SourceRollback;
    }),
    (error: unknown) => error === historicalV52SourceRollback,
  );

  const privateV53Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV53Roots,
  );
  assert.equal(privateV53Catalog.length, retainedPrivateV53Roots.length);
  for (const root of privateV53Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV53Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v53()'::regprocedure
  `;
  assert.equal(
    retiredV53Source?.source_hash,
    expectedRetiredSchemaCompatibilityV53SourceHash,
  );

  const normalizedV53GrantRollback = {
    kind: "normalized-v53-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v53()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V53 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V53 grant",
      );
      throw normalizedV53GrantRollback;
    }),
    (error: unknown) => error === normalizedV53GrantRollback,
  );

  const normalizedV53NotifierGrantRollback = {
    kind: "normalized-v53-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v53()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV53NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV53NotifierGrantRollback,
  );

  const rotatedV53AclTamperRollback = {
    kind: "rotated-v53-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v53()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV53AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV53AclTamperRollback,
  );

  const rotatedV53ConfigTamperRollback = {
    kind: "rotated-v53-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v53() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV53ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV53ConfigTamperRollback,
  );

  const unnormalizedV53ConfigRollback = {
    kind: "unnormalized-private-v53-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v53()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV53ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV53ConfigRollback,
  );

  const historicalV53SourceRollback = {
    kind: "historical-v53-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v53()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V53 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV53SourceRollback;
    }),
    (error: unknown) => error === historicalV53SourceRollback,
  );

  const privateV54Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV54Roots,
  );
  assert.equal(privateV54Catalog.length, retainedPrivateV54Roots.length);
  for (const root of privateV54Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV54Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v54()'::regprocedure
  `;
  assert.equal(
    retiredV54Source?.source_hash,
    expectedRetiredSchemaCompatibilityV54SourceHash,
  );

  const normalizedV54GrantRollback = {
    kind: "normalized-v54-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v54()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V54 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V54 grant",
      );
      throw normalizedV54GrantRollback;
    }),
    (error: unknown) => error === normalizedV54GrantRollback,
  );

  const normalizedV54NotifierGrantRollback = {
    kind: "normalized-v54-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v54()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV54NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV54NotifierGrantRollback,
  );

  const rotatedV54AclTamperRollback = {
    kind: "rotated-v54-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v54()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV54AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV54AclTamperRollback,
  );

  const rotatedV54ConfigTamperRollback = {
    kind: "rotated-v54-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v54() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV54ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV54ConfigTamperRollback,
  );

  const unnormalizedV54ConfigRollback = {
    kind: "unnormalized-private-v54-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v54()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV54ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV54ConfigRollback,
  );

  const historicalV54SourceRollback = {
    kind: "historical-v54-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v54()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V54 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV54SourceRollback;
    }),
    (error: unknown) => error === historicalV54SourceRollback,
  );

  const privateV55Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV55Roots,
  );
  assert.equal(privateV55Catalog.length, retainedPrivateV55Roots.length);
  for (const root of privateV55Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV55Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v55()'::regprocedure
  `;
  assert.equal(
    retiredV55Source?.source_hash,
    expectedRetiredSchemaCompatibilityV55SourceHash,
  );

  const normalizedV55GrantRollback = {
    kind: "normalized-v55-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v55()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V55 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V55 grant",
      );
      throw normalizedV55GrantRollback;
    }),
    (error: unknown) => error === normalizedV55GrantRollback,
  );

  const normalizedV55NotifierGrantRollback = {
    kind: "normalized-v55-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v55()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV55NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV55NotifierGrantRollback,
  );

  const rotatedV55AclTamperRollback = {
    kind: "rotated-v55-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v55()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV55AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV55AclTamperRollback,
  );

  const rotatedV55ConfigTamperRollback = {
    kind: "rotated-v55-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v55() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV55ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV55ConfigTamperRollback,
  );

  const unnormalizedV55ConfigRollback = {
    kind: "unnormalized-private-v55-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v55()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV55ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV55ConfigRollback,
  );

  const historicalV55SourceRollback = {
    kind: "historical-v55-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v55()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V55 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV55SourceRollback;
    }),
    (error: unknown) => error === historicalV55SourceRollback,
  );

  const privateV56Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV56Roots,
  );
  assert.equal(privateV56Catalog.length, retainedPrivateV56Roots.length);
  for (const root of privateV56Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV56Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v56()'::regprocedure
  `;
  assert.equal(
    retiredV56Source?.source_hash,
    expectedRetiredSchemaCompatibilityV56SourceHash,
  );

  const normalizedV56GrantRollback = {
    kind: "normalized-v56-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v56()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V56 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V56 grant",
      );
      throw normalizedV56GrantRollback;
    }),
    (error: unknown) => error === normalizedV56GrantRollback,
  );

  const normalizedV56NotifierGrantRollback = {
    kind: "normalized-v56-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v56()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV56NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV56NotifierGrantRollback,
  );

  const rotatedV56AclTamperRollback = {
    kind: "rotated-v56-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v56()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV56AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV56AclTamperRollback,
  );

  const rotatedV56ConfigTamperRollback = {
    kind: "rotated-v56-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v56() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV56ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV56ConfigTamperRollback,
  );

  const unnormalizedV56ConfigRollback = {
    kind: "unnormalized-private-v56-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v56()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV56ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV56ConfigRollback,
  );

  const historicalV56SourceRollback = {
    kind: "historical-v56-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v56()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V56 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV56SourceRollback;
    }),
    (error: unknown) => error === historicalV56SourceRollback,
  );

  const privateV57Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV57Roots,
  );
  assert.equal(privateV57Catalog.length, retainedPrivateV57Roots.length);
  for (const root of privateV57Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV57Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v57()'::regprocedure
  `;
  assert.equal(
    retiredV57Source?.source_hash,
    expectedRetiredSchemaCompatibilityV57SourceHash,
  );

  const normalizedV57GrantRollback = {
    kind: "normalized-v57-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v57()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V57 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V57 grant",
      );
      throw normalizedV57GrantRollback;
    }),
    (error: unknown) => error === normalizedV57GrantRollback,
  );

  const normalizedV57NotifierGrantRollback = {
    kind: "normalized-v57-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v57()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV57NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV57NotifierGrantRollback,
  );

  const rotatedV57AclTamperRollback = {
    kind: "rotated-v57-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v57()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV57AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV57AclTamperRollback,
  );

  const rotatedV57ConfigTamperRollback = {
    kind: "rotated-v57-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v57() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV57ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV57ConfigTamperRollback,
  );

  const unnormalizedV57ConfigRollback = {
    kind: "unnormalized-private-v57-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v57()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV57ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV57ConfigRollback,
  );

  const historicalV57SourceRollback = {
    kind: "historical-v57-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v57()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V57 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV57SourceRollback;
    }),
    (error: unknown) => error === historicalV57SourceRollback,
  );

  const privateV58Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV58Roots,
  );
  assert.equal(privateV58Catalog.length, retainedPrivateV58Roots.length);
  for (const root of privateV58Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV58Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v58()'::regprocedure
  `;
  assert.equal(
    retiredV58Source?.source_hash,
    expectedRetiredSchemaCompatibilityV58SourceHash,
  );

  const normalizedV58GrantRollback = {
    kind: "normalized-v58-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v58()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V58 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V58 grant",
      );
      throw normalizedV58GrantRollback;
    }),
    (error: unknown) => error === normalizedV58GrantRollback,
  );

  const normalizedV58NotifierGrantRollback = {
    kind: "normalized-v58-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v58()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV58NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV58NotifierGrantRollback,
  );

  const rotatedV58AclTamperRollback = {
    kind: "rotated-v58-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v58()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV58AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV58AclTamperRollback,
  );

  const rotatedV58ConfigTamperRollback = {
    kind: "rotated-v58-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v58() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV58ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV58ConfigTamperRollback,
  );

  const unnormalizedV58ConfigRollback = {
    kind: "unnormalized-private-v58-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v58()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV58ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV58ConfigRollback,
  );

  const historicalV58SourceRollback = {
    kind: "historical-v58-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v58()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V58 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV58SourceRollback;
    }),
    (error: unknown) => error === historicalV58SourceRollback,
  );

  const privateV59Catalog = await readFunctionCatalog(
    sql,
    retainedPrivateV59Roots,
  );
  assert.equal(privateV59Catalog.length, retainedPrivateV59Roots.length);
  for (const root of privateV59Catalog) {
    assert.equal(root.owner_name, "periapsis_migrator");
    assert.deepEqual(root.acl_roles, ["periapsis_migrator"]);
    assert.equal(root.runtime_execute_count, 0);
  }

  const [retiredV59Source] = await sql<{ source_hash: string }[]>`
    SELECT encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
    FROM pg_catalog.pg_proc WHERE oid='app.schema_compatibility_v59()'::regprocedure
  `;
  assert.equal(
    retiredV59Source?.source_hash,
    expectedRetiredSchemaCompatibilityV59SourceHash,
  );

  const normalizedV59GrantRollback = {
    kind: "normalized-v59-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v59()
        TO periapsis_api
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V59 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V59 grant",
      );
      throw normalizedV59GrantRollback;
    }),
    (error: unknown) => error === normalizedV59GrantRollback,
  );

  const normalizedV59NotifierGrantRollback = {
    kind: "normalized-v59-notifier-grant",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v59()
        TO periapsis_notifier
      `;
      const drifted = await readV60Readiness(transaction);
      assert.equal(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], true);
      assert.equal(drifted.readiness[1], false);
      assert.equal(
        drifted.readiness[12],
        false,
        "current notification readiness must reject the restored historical grant",
      );
      throw normalizedV59NotifierGrantRollback;
    }),
    (error: unknown) => error === normalizedV59NotifierGrantRollback,
  );

  const rotatedV59AclTamperRollback = {
    kind: "rotated-v59-acl-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        GRANT EXECUTE ON FUNCTION
          app.ticket_metadata_runtime_schema_readiness_v59()
        TO periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV59AclTamperRollback;
    }),
    (error: unknown) => error === rotatedV59AclTamperRollback,
  );

  const rotatedV59ConfigTamperRollback = {
    kind: "rotated-v59-config-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.schema_compatibility_v59() SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw rotatedV59ConfigTamperRollback;
    }),
    (error: unknown) => error === rotatedV59ConfigTamperRollback,
  );

  const unnormalizedV59ConfigRollback = {
    kind: "unnormalized-private-v59-config",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        ALTER FUNCTION app.private_schema_compatibility_journal_v59()
        SET work_mem='64kB'
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(drifted.catalog_digest, expectedCatalogDigest);
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw unnormalizedV59ConfigRollback;
    }),
    (error: unknown) => error === unnormalizedV59ConfigRollback,
  );

  const historicalV59SourceRollback = {
    kind: "historical-v59-private-readiness-source-tamper",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE OR REPLACE FUNCTION
          app.private_release_runtime_schema_readiness_v59()
        RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public,app AS $tampered$
        BEGIN
          RETURN true;
        END;
        $tampered$
      `);
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V59 private root is no longer self-excluded in V60",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw historicalV59SourceRollback;
    }),
    (error: unknown) => error === historicalV59SourceRollback,
  );

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
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V49 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(drifted.readiness[0], true);
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V49 grant",
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the historical V49 private root is no longer self-excluded in V60",
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
      const drifted = await readV60Readiness(transaction);
      assert.equal(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "the exact V48 ACL rotation is intentionally digest-normalized",
      );
      assert.equal(
        drifted.readiness[1],
        false,
        "the public V60 root must independently reject a restored V48 grant",
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
  assert.deepEqual(await readV60Readiness(sql), readiness);

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
          'v60-tampered-ticket-namespace', 'UTF8'
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE RULE v60_rewrite_tamper
        AS ON DELETE TO public.alert_relation_retractions
        DO INSTEAD NOTHING
      `);
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE FUNCTION public.v60_public_function_probe()
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true'
      `);
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE SCHEMA v60_evil;
        CREATE FUNCTION v60_evil.alert_status_eq(
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
          AS result /* v60-operator-before */
      `);
      assert.equal(before?.result, true);
      await transaction.unsafe(`
        CREATE OPERATOR public.= (
          LEFTARG=public.alert_status,
          RIGHTARG=public.alert_status,
          FUNCTION=v60_evil.alert_status_eq
        )
      `);
      const [after] = await transaction.unsafe<{ result: boolean }[]>(`
        SELECT 'new'::public.alert_status = 'new'::public.alert_status
          AS result /* v60-operator-after */
      `);
      assert.equal(after?.result, false);
      const drifted = await readV60Readiness(transaction);
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
        CREATE ROLE periapsis_v60_column_acl_probe NOLOGIN
      `;
      const roleOnlyDigest = await readCatalogDigest(transaction);
      await transaction`
        GRANT SELECT (title) ON public.alerts
        TO periapsis_v60_column_acl_probe
      `;
      assert.notEqual(
        await readCatalogDigest(transaction),
        roleOnlyDigest,
        "a column ACL must add OID-independent grant evidence",
      );
      assert.equal((await readV60Readiness(transaction)).readiness[0], false);
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
        CREATE DOMAIN public.v60_domain_probe AS integer
      `);
      const domainOnlyDigest = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        ALTER DOMAIN public.v60_domain_probe
        ADD CONSTRAINT v60_positive CHECK (VALUE > 0)
      `);
      const constraintDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        constraintDigest,
        domainOnlyDigest,
        "a domain CHECK must add its own catalog evidence",
      );
      assert.equal((await readV60Readiness(transaction)).readiness[0], false);
      throw domainConstraintRollback;
    }),
    (error: unknown) => error === domainConstraintRollback,
  );

  const eventTriggerRollback = { kind: "event-trigger-tamper" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION public.v60_event_trigger_handler()
        RETURNS event_trigger LANGUAGE plpgsql
        SET search_path=pg_catalog
        AS 'BEGIN NULL; END'
      `);
      const handlerOnlyDigest = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        CREATE EVENT TRIGGER v60_event_trigger_probe
        ON ddl_command_end
        WHEN TAG IN ('CREATE TABLE')
        EXECUTE FUNCTION public.v60_event_trigger_handler()
      `);
      const eventTriggerDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        eventTriggerDigest,
        handlerOnlyDigest,
        "an event trigger must add evidence beyond its handler function",
      );
      assert.equal((await readV60Readiness(transaction)).readiness[0], false);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE PUBLICATION v60_alert_leak
        FOR TABLE public.alerts (id) WHERE (id IS NOT NULL)
      `);
      const initialPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(initialPublicationDigest, expectedCatalogDigest);
      await transaction.unsafe(`
        CREATE PUBLICATION v60_public_schema_leak
        FOR TABLES IN SCHEMA public
      `);
      const schemaPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        schemaPublicationDigest,
        initialPublicationDigest,
        "publication schema mappings must be catalog-attested",
      );
      await transaction.unsafe(`
        CREATE PUBLICATION v60_all_tables_leak FOR ALL TABLES
      `);
      const allTablesPublicationDigest = await readCatalogDigest(transaction);
      assert.notEqual(
        allTablesPublicationDigest,
        schemaPublicationDigest,
        "FOR ALL TABLES publications must be catalog-attested",
      );
      await transaction.unsafe(`
        ALTER PUBLICATION v60_alert_leak SET (publish='insert')
      `);
      assert.notEqual(
        await readCatalogDigest(transaction),
        allTablesPublicationDigest,
        "publication operation flags must be catalog-attested",
      );
      const drifted = await readV60Readiness(transaction);
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
        CREATE SUBSCRIPTION v60_injection
        CONNECTION 'host=127.0.0.1 port=1 dbname=none user=nobody'
        PUBLICATION v60_pub
        WITH (connect=false, create_slot=false, enabled=false)
      `);
      const drifted = await readV60Readiness(transaction);
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
        CREATE ROLE v60_alternate_sealer SUPERUSER NOLOGIN;
        ALTER FUNCTION app.private_runtime_login_credential_state_v49()
          OWNER TO v60_alternate_sealer;
        SET ROLE v60_alternate_sealer;
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE ROLE v60_alternate_membership_grantor NOLOGIN;
        GRANT periapsis_api TO v60_alternate_membership_grantor
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
          GRANTED BY v60_alternate_membership_grantor
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
      assert.equal(edge?.grantor, "v60_alternate_membership_grantor");
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
        CREATE ROLE periapsis_v60_membership_granted NOLOGIN;
        CREATE ROLE periapsis_v60_membership_member NOLOGIN;
        GRANT periapsis_v60_membership_granted
          TO periapsis_v60_membership_member
          WITH ADMIN FALSE, INHERIT TRUE, SET TRUE
      `);
      const inherited = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        GRANT periapsis_v60_membership_granted
          TO periapsis_v60_membership_member
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
        CREATE ROLE periapsis_v60_acl_grantor NOLOGIN;
        CREATE ROLE periapsis_v60_acl_grantee NOLOGIN;
        GRANT USAGE ON SCHEMA app TO periapsis_v60_acl_grantor;
        CREATE FUNCTION app.v60_acl_grantor_probe()
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true';
        ALTER FUNCTION app.v60_acl_grantor_probe()
          OWNER TO periapsis_migrator;
        REVOKE ALL ON FUNCTION app.v60_acl_grantor_probe() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION app.v60_acl_grantor_probe()
          TO periapsis_v60_acl_grantor WITH GRANT OPTION;
        SET ROLE periapsis_v60_acl_grantor;
        GRANT EXECUTE ON FUNCTION app.v60_acl_grantor_probe()
          TO periapsis_v60_acl_grantee;
        RESET ROLE
      `);
      const delegated = await readCatalogDigest(transaction);
      await transaction.unsafe(`
        SET ROLE periapsis_v60_acl_grantor;
        REVOKE EXECUTE ON FUNCTION app.v60_acl_grantor_probe()
          FROM periapsis_v60_acl_grantee;
        RESET ROLE;
        SET ROLE periapsis_migrator;
        GRANT EXECUTE ON FUNCTION app.v60_acl_grantor_probe()
          TO periapsis_v60_acl_grantee;
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE ROLE v60_external_default_acl_owner NOLOGIN;
        ALTER DEFAULT PRIVILEGES FOR ROLE v60_external_default_acl_owner
          GRANT SELECT ON TABLES TO periapsis_api
      `);
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
      const drifted = await readV60Readiness(transaction);
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
        CREATE ROLE v60_alternate_database_owner SUPERUSER NOLOGIN
      `;
      const [alter] = await transaction<{ statement: string }[]>`
        SELECT pg_catalog.format(
          'ALTER DATABASE %I OWNER TO v60_alternate_database_owner',
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
      const drifted = await readV60Readiness(transaction);
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
        ALTER ROLE ALL SET application_name = 'v60-global-role-tamper'
      `);
      const drifted = await readV60Readiness(transaction);
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
          app.private_release_runtime_schema_readiness_v60()
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
        "the exact private V60 root remains self-excluded from its own digest",
      );
      assert.equal(
        await readNotifierSourceAttestation(transaction),
        false,
        "the notifier must independently source-attest its V60 trust chain",
      );
      throw notifierChainSourceRollback;
    }),
    (error: unknown) => error === notifierChainSourceRollback,
  );

  const sameNameOverloadRollback = {
    kind: "same-name-v60-overload",
  } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(`
        CREATE FUNCTION app.release_runtime_schema_readiness_v60(text)
        RETURNS boolean LANGUAGE sql IMMUTABLE
        SET search_path=pg_catalog
        AS 'SELECT true'
      `);
      await transaction`
        ALTER FUNCTION app.release_runtime_schema_readiness_v60(text)
        OWNER TO periapsis_migrator
      `;
      await transaction`
        REVOKE ALL ON FUNCTION app.release_runtime_schema_readiness_v60(text)
        FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
             periapsis_auditor
      `;
      const drifted = await readV60Readiness(transaction);
      assert.notEqual(
        drifted.catalog_digest,
        expectedCatalogDigest,
        "a same-name overload must not inherit the exact V60 self-exclusion",
      );
      assert.equal(drifted.readiness[0], false);
      assert.equal(drifted.readiness[1], false);
      throw sameNameOverloadRollback;
    }),
    (error: unknown) => error === sameNameOverloadRollback,
  );

  assert.deepEqual(await readV60Readiness(sql), readiness);
} finally {
  await sql.end();
}
