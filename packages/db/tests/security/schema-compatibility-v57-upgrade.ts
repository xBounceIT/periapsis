import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { readMigrationFiles } from "drizzle-orm/migrator";
import { PgDialect } from "drizzle-orm/pg-core";
import { PostgresJsSession } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
  expectedRetiredSchemaCompatibilityV49SourceHash,
  expectedRetiredSchemaCompatibilityV50SourceHash,
  expectedRetiredSchemaCompatibilityV56SourceHash,
  expectedSealSchemaCompatibilityManifestV56SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import {
  executeMigrationBatches,
  migrateSchema,
  partitionMigrationsAtEnumCommitBoundaries,
} from "../../src/admin/schema-migration.js";

type JournalEntry = {
  breakpoints: boolean;
  idx: number;
  tag: string;
  version: string;
  when: number;
};
type Journal = { dialect: string; entries: JournalEntry[]; version: string };
type CompatibilityRow = {
  applied_count: string;
  latest_created_at: string;
  latest_hash: string;
  migration_fingerprint: string;
};
type LogoutCommand = {
  operationRunId: string;
  sessionId: string;
  userId: string;
  tenantId: string | null;
  tokenDigest: string;
  requestDigest: string;
  requestUpstream: boolean;
  requestedAt: string;
  continuationId: string;
  continuationDigest: string;
  continuationExpiresAt: string;
  audit: {
    requestId: string;
    correlationId: string;
    remoteAddress: string;
    userAgent: string;
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJSONRecord(
  value: unknown,
): value is { [key: string]: postgres.JSONValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  assert(isRecord(value));
  assert(typeof value.dialect === "string");
  assert(typeof value.version === "string");
  assert(Array.isArray(value.entries));
  assert(
    value.entries.every(
      (entry): entry is JournalEntry =>
        isRecord(entry) &&
        typeof entry.breakpoints === "boolean" &&
        Number.isSafeInteger(entry.idx) &&
        typeof entry.tag === "string" &&
        typeof entry.version === "string" &&
        Number.isSafeInteger(entry.when),
    ),
  );
  return {
    dialect: value.dialect,
    version: value.version,
    entries: value.entries,
  };
}

const databaseUrl =
  process.env.PERIAPSIS_SCHEMA_COMPATIBILITY_V57_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SCHEMA_COMPATIBILITY_V57_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 UTF8 C/C database whose cluster has no periapsis_* roles",
  );
}

const migrationsRoot = resolve(import.meta.dirname, "../../migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const v56Count = 244;
const v56Manifest = expectedMigrations.slice(0, v56Count);
const v56Latest = v56Manifest.at(-1);
assert(v56Latest);
assert.deepEqual(v56Latest, {
  tag: "0243_v56_compatibility",
  createdAt: 1_788_805_357_439,
  hash: "063de048384760bffed8bdd2d7094447ecd49a85cb778ae56dda761dd531c559",
});
assert.equal(journal.entries.length, 254);
assert.equal(expectedMigrationCount, 254);
assert.equal(expectedMigrations.length, 254);
assert.deepEqual(
  journal.entries.slice(-10).map((entry) => entry.tag),
  [
    "0244_sla_authority_epochs",
    "0245_v57_compatibility",
    "0246_sla_notification_contact_runtime",
    "0247_v58_compatibility",
    "0248_ticket_operation_base64",
    "0249_v59_compatibility",
    "0250_ticket_export_authority",
    "0251_v60_compatibility",
    "0252_ticket_comment_authority",
    "0253_v61_compatibility",
  ],
);
const v56Fingerprint = v56Manifest
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
const v56CatalogDigest =
  "7fed00140286fdae9f79c9fb1a8f5ff1a39353962d4f5364873bef0a4e635f67";
const v61Migration = await readFile(
  resolve(migrationsRoot, "0253_v61_compatibility.sql"),
  "utf8",
);
const v61CatalogDigest =
  /private_release_runtime_dependency_surface_hash_v61\(\)<>\s*'([0-9a-f]{64})'/u.exec(
    v61Migration,
  )?.[1];
assert(v61CatalogDigest, "0245 must pin the V61 catalog digest");
assert.notEqual(
  v61CatalogDigest,
  "0".repeat(64),
  "V61 cannot run with a placeholder digest",
);
assert.equal(
  v61CatalogDigest,
  "76a834205fc0aa75b5c30370694a6f45e7d97b78380d0a6c5ecfd877204a5add",
);
const unsupported: CompatibilityRow = {
  applied_count: "0",
  latest_created_at: "0",
  latest_hash: "UNSUPPORTED",
  migration_fingerprint: "UNSUPPORTED",
};
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
];
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
];
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
];
const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-schema-v57-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const uuid = (sequence: number): string =>
  `019d2fc0-6000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): string =>
  createHash("sha256").update(label).digest("base64");
const tenant = uuid(1);
const user = uuid(2);
const tenantSession = uuid(3);
const platformSession = uuid(4);

async function stagePrefix(count: number): Promise<void> {
  const entries = journal.entries.slice(0, count);
  assert.equal(entries.length, count);
  await mkdir(resolve(stageRoot, "meta"), { recursive: true });
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map(async (entry, index) => {
      const expected = expectedMigrations[index];
      assert(expected);
      assert.equal(entry.idx, index);
      assert.equal(entry.tag, expected.tag);
      assert.equal(entry.when, expected.createdAt);
      const source = resolve(migrationsRoot, `${entry.tag}.sql`);
      assert.equal(
        createHash("sha256")
          .update(await readFile(source))
          .digest("hex"),
        expected.hash,
      );
      await copyFile(source, resolve(stageRoot, `${entry.tag}.sql`));
    }),
  );
}

async function migrateStagedPrefix(): Promise<void> {
  const config = { migrationsFolder: stageRoot };
  const dialect = new PgDialect();
  const session = new PostgresJsSession<
    postgres.Sql,
    Record<string, never>,
    Record<string, never>
  >(sql, dialect, undefined);
  await executeMigrationBatches(
    partitionMigrationsAtEnumCommitBoundaries(readMigrationFiles(config)),
    (batch) => dialect.migrate(batch, session, config),
  );
}

async function assertAppliedPrefix(count: number): Promise<void> {
  const rows = await sql<{ created_at: string; hash: string }[]>`
    SELECT created_at::text, hash FROM drizzle.__drizzle_migrations ORDER BY created_at, id
  `;
  assert.deepEqual(
    rows.map(({ created_at, hash }) => ({ created_at, hash })),
    expectedMigrations.slice(0, count).map((entry) => ({
      created_at: String(entry.createdAt),
      hash: entry.hash,
    })),
  );
  assert.equal(rows.length, count);
}

async function sealV56(): Promise<void> {
  const [attestation] = await sql<{ value: boolean }[]>`
    SELECT count(*) = 1 AND coalesce(bool_and(
      owner.rolname = 'periapsis_migrator' AND language.lanname = 'plpgsql'
      AND procedure.prokind = 'f' AND procedure.provolatile = 'v'
      AND procedure.prosecdef AND NOT procedure.proisstrict
      AND NOT procedure.proleakproof AND procedure.proparallel = 'u'
      AND procedure.pronargs = 4 AND procedure.pronargdefaults = 0
      AND procedure.proargtypes = '20 20 25 25'::oidvector
      AND procedure.proargnames = ARRAY['p_expected_count', 'p_expected_latest_created_at',
        'p_expected_latest_hash', 'p_expected_migration_fingerprint']::text[]
      AND procedure.proargmodes IS NULL AND NOT procedure.proretset
      AND procedure.prorettype = 'void'::regtype
      AND procedure.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::text[]
      AND encode(sha256(convert_to(procedure.prosrc, 'UTF8')), 'hex') =
        ${expectedSealSchemaCompatibilityManifestV56SourceHash}
      AND (SELECT count(*) = 1 AND coalesce(bool_and(
        privilege.grantor = procedure.proowner AND privilege.grantee = procedure.proowner
        AND privilege.privilege_type = 'EXECUTE' AND NOT privilege.is_grantable
      ), false) FROM aclexplode(coalesce(procedure.proacl,
        acldefault('f', procedure.proowner))) AS privilege)
    ), false) AS value
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = procedure.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
    WHERE procedure.oid = to_regprocedure('app.seal_schema_compatibility_manifest(bigint,bigint,text,text)')
  `;
  assert.equal(attestation?.value, true);
  await sql`SELECT app.seal_schema_compatibility_manifest(${v56Count}::bigint,
    ${v56Latest!.createdAt}::bigint, ${v56Latest!.hash}::text, ${v56Fingerprint}::text)`;
  await sql`SELECT app.seal_schema_compatibility_manifest(${v56Count}::bigint,
    ${v56Latest!.createdAt}::bigint, ${v56Latest!.hash}::text, ${v56Fingerprint}::text)`;
}

// The same local TOTP session shape as the real Go repository fixture. The
// platform session genuinely has no tenant; no synthetic tenant substitutes it.
async function seedLogoutSessions(): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction`SET LOCAL ROLE periapsis_migrator`;
    await transaction`INSERT INTO public.tenants(id, slug, name)
      VALUES (${tenant}::uuid, 'v61-logout-upgrade', 'V61 logout upgrade')`;
    await transaction`INSERT INTO public.audit_chain_heads(tenant_id) VALUES (${tenant}::uuid)`;
    await transaction`INSERT INTO public.users(id, email, display_name)
      VALUES (${user}::uuid, 'v61-logout-upgrade@example.invalid', 'V61 logout upgrade')`;
    await transaction`INSERT INTO public.tenant_memberships(id, tenant_id, user_id, role, status)
      VALUES (${uuid(5)}::uuid, ${tenant}::uuid, ${user}::uuid, 'tenant_admin', 'active')`;
    await transaction`SELECT app.seed_tenant_authorization(${tenant}::uuid, ${uuid(5)}::uuid)`;
    await Promise.all(
      [
        { session: tenantSession, tenant, family: uuid(6) },
        { session: platformSession, tenant: null, family: uuid(7) },
      ].map(async (fixture) => {
        await transaction`INSERT INTO public.auth_sessions(
        id, user_id, rotation_family_id, active_tenant_id, token_digest, csrf_secret_digest,
        authentication_method, mfa_satisfied_at, last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES (${fixture.session}::uuid, ${user}::uuid, ${fixture.family}::uuid,
        ${fixture.tenant}::uuid, decode(${digest(`token-${fixture.session}`)}, 'base64'),
        decode(${digest(`csrf-${fixture.session}`)}, 'base64'), 'totp',
        date_trunc('second',transaction_timestamp())-interval '2 minutes',
        date_trunc('second',transaction_timestamp()),
        date_trunc('second',transaction_timestamp())+interval '1 hour',
        date_trunc('second',transaction_timestamp())+interval '8 hours',
        date_trunc('second',transaction_timestamp())-interval '10 minutes')`;
      }),
    );
  });
}

// Matches the complete Go/SAML wire envelope, including explicit nullable
// tenantId, bounded continuation and the verified transactional audit actor.
function logoutCommand(
  sessionId: string,
  tenantId: string | null,
  sequence: number,
): LogoutCommand {
  const requestedAt = new Date();
  return {
    operationRunId: uuid(sequence),
    sessionId,
    userId: user,
    tenantId,
    tokenDigest: digest(`token-${sessionId}`),
    requestDigest: digest(`request-${sequence}`),
    requestUpstream: true,
    requestedAt: requestedAt.toISOString(),
    continuationId: uuid(sequence + 100),
    continuationDigest: digest(`continuation-${sequence}`),
    continuationExpiresAt: new Date(
      requestedAt.getTime() + 60_000,
    ).toISOString(),
    audit: {
      requestId: uuid(sequence + 200),
      correlationId: uuid(sequence + 300),
      remoteAddress: "192.0.2.40",
      userAgent: "schema-v61-logout-upgrade",
    },
  };
}

async function revoke(
  command: LogoutCommand,
): Promise<postgres.JSONValue | null> {
  const result = await sql.begin(async (transaction) => {
    await transaction`SET LOCAL ROLE periapsis_api`;
    await transaction`SELECT set_config('app.tenant_id', coalesce(${command.tenantId}::uuid::text, ''), true),
      set_config('app.user_id', ${command.userId}::uuid::text, true)`;
    const [row] = await transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.revoke_local_session_for_logout_v1(${transaction.json(command)}::jsonb) AS value
    `;
    assert(row);
    return { value: row.value };
  });
  return result.value;
}

async function redactedSnapshot(): Promise<postgres.JSONValue> {
  const [row] = await sql<{ value: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'sessions', (SELECT jsonb_agg(to_jsonb(session)-'token_digest'-'csrf_secret_digest' ORDER BY id)
        FROM public.auth_sessions AS session WHERE user_id=${user}::uuid),
      'commands', (SELECT jsonb_agg(to_jsonb(command)-'request_digest' ORDER BY operation_run_id)
        FROM public.tenant_oidc_logout_commands AS command WHERE session_id IN (${tenantSession}::uuid, ${platformSession}::uuid)),
      'continuations', (SELECT jsonb_agg(to_jsonb(continuation)-'token_digest' ORDER BY id)
        FROM public.session_logout_continuations AS continuation WHERE user_id=${user}::uuid),
      'retryJobs', (SELECT jsonb_agg(to_jsonb(job) ORDER BY id)
        FROM public.tenant_oidc_logout_retry_jobs AS job WHERE operation_run_id IN (
          SELECT operation_run_id FROM public.tenant_oidc_logout_commands WHERE session_id IN (${tenantSession}::uuid, ${platformSession}::uuid))),
      'tenantAudit', (SELECT jsonb_agg(to_jsonb(audit) ORDER BY id) FROM public.audit_events AS audit WHERE actor_user_id=${user}::uuid),
      'platformAudit', (SELECT jsonb_agg(to_jsonb(audit) ORDER BY id) FROM public.platform_audit_events AS audit WHERE actor_user_id=${user}::uuid)
    ) AS value
  `;
  assert(row);
  return row.value;
}

async function assertLogoutEffects(
  command: LogoutCommand,
  receipt: postgres.JSONValue | null,
): Promise<void> {
  assert(isJSONRecord(receipt));
  assert.equal(receipt.category, "revoked_local_only");
  assert.equal(receipt.operationRunId, command.operationRunId);
  assert.equal(receipt.sessionId, command.sessionId);
  assert.equal(receipt.userId, command.userId);
  assert.equal(receipt.tenantId, command.tenantId);
  assert.equal(receipt.previousVersion, 1);
  assert(typeof receipt.revokedAt === "string");
  assert(typeof receipt.observedAt === "string");
  assert(typeof receipt.requestedAt === "string");
  assert.equal(
    new Date(receipt.requestedAt).getTime(),
    new Date(command.requestedAt).getTime(),
  );
  const [effects] = await sql<
    {
      commands: number;
      revoked: number;
      continuations: number;
      audit: number;
      exact_audit: boolean;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_oidc_logout_commands WHERE operation_run_id=${command.operationRunId}::uuid
        AND session_id=${command.sessionId}::uuid AND tenant_id IS NOT DISTINCT FROM ${command.tenantId}::uuid
        AND authority=CASE WHEN ${command.tenantId}::uuid IS NULL THEN 'platform_session' ELSE 'tenant_session' END
        AND expected_version=1 AND result_snapshot=${sql.json(receipt)}::jsonb) AS commands,
      (SELECT count(*)::integer FROM public.auth_sessions WHERE id=${command.sessionId}::uuid
        AND revoked_at=${receipt.revokedAt}::text::timestamptz AND revoke_reason='totp_local_logout') AS revoked,
      (SELECT count(*)::integer FROM public.session_logout_continuations WHERE operation_run_id=${command.operationRunId}::uuid) AS continuations,
      count(*)::integer AS audit,
      coalesce(bool_and(actor_type='user' AND actor_user_id=${user}::uuid
        AND request_id=${command.audit.requestId}::uuid AND correlation_id=${command.audit.correlationId}::uuid
        AND authentication_method='totp' AND outcome='success' AND metadata=
          '{"upstream_requested":true,"continuation_created":false,"material_present":false,"material_disclosed":false}'::jsonb), false) AS exact_audit
    FROM (
      SELECT actor_type, actor_user_id, request_id, correlation_id, authentication_method, outcome, metadata
      FROM public.audit_events WHERE tenant_id=${command.tenantId}::uuid AND resource_id=${command.sessionId}::uuid
        AND resource_type='auth_session' AND action='tenant.identity.session_local_logout'
      UNION ALL
      SELECT actor_type, actor_user_id, request_id, correlation_id, authentication_method, outcome, metadata
      FROM public.platform_audit_events WHERE ${command.tenantId}::uuid IS NULL AND resource_id=${command.sessionId}::uuid
        AND resource_type='auth_session' AND action='platform.identity.session_local_logout'
    ) AS audit
  `;
  assert.deepEqual(effects, {
    commands: 1,
    revoked: 1,
    continuations: 0,
    audit: 1,
    exact_audit: true,
  });
}

async function assertSealedV61(): Promise<void> {
  await assertAppliedPrefix(254);
  const [current] = await sql<
    (CompatibilityRow & {
      catalog_digest: string;
      ready: boolean;
      api_array: boolean[];
      worker_array: boolean[];
    })[]
  >`
    SELECT compatibility.*, app.private_release_runtime_dependency_surface_hash_v61() AS catalog_digest,
      app.api_runtime_schema_readiness_v61() AS api_array,
      app.worker_runtime_schema_readiness_v61() AS worker_array,
      app.release_runtime_schema_readiness_v61() AS ready FROM app.schema_compatibility_v61() AS compatibility
  `;
  assert.deepEqual(current, {
    applied_count: String(expectedMigrationCount),
    latest_created_at: String(expectedMigrationCreatedAt),
    latest_hash: expectedMigrationHash,
    migration_fingerprint: expectedMigrationFingerprint,
    catalog_digest: v61CatalogDigest,
    ready: true,
    api_array: Array<boolean>(8).fill(true),
    worker_array: Array<boolean>(5).fill(true),
  });
  await Promise.all(
    [
      {
        signature: "app.schema_compatibility_v49()",
        sourceHash: expectedRetiredSchemaCompatibilityV49SourceHash,
      },
      {
        signature: "app.schema_compatibility_v50()",
        sourceHash: expectedRetiredSchemaCompatibilityV50SourceHash,
      },
      {
        signature: "app.schema_compatibility_v56()",
        sourceHash: expectedRetiredSchemaCompatibilityV56SourceHash,
      },
    ].map(async (root) => {
      const [retired] = await sql<{ config: string[]; source_hash: string }[]>`
      SELECT proconfig AS config, encode(sha256(convert_to(prosrc, 'UTF8')), 'hex') AS source_hash
      FROM pg_catalog.pg_proc WHERE oid=to_regprocedure(${root.signature})
    `;
      assert.deepEqual(retired, {
        config: [
          "search_path=pg_catalog",
          "app.schema_compatibility_fingerprint=RETIRED",
        ],
        source_hash: root.sourceHash,
      });
      const [retiredCompatibility] = await sql.unsafe<CompatibilityRow[]>(
        `SELECT * FROM ${root.signature}`,
      );
      assert.deepEqual(retiredCompatibility, unsupported);
    }),
  );
  const roots = await sql<{ name: string; runtime_grants: number }[]>`
    SELECT root.name, (SELECT count(*)::integer FROM (VALUES
      ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'), ('periapsis_auditor')
    ) AS role(name) WHERE has_function_privilege(role.name, procedure.oid, 'EXECUTE')) AS runtime_grants
    FROM unnest(${[...retiredV49Roots, ...retiredV50Roots, ...retiredV56Roots]}::text[]) AS root(name)
    JOIN pg_catalog.pg_proc AS procedure ON procedure.oid=to_regprocedure('app.' || root.name || '()')
    ORDER BY root.name
  `;
  assert.deepEqual(
    roots.map(({ name, runtime_grants }) => ({ name, runtime_grants })),
    [...retiredV49Roots, ...retiredV50Roots, ...retiredV56Roots]
      .toSorted()
      .map((name) => ({ name, runtime_grants: 0 })),
  );
}

try {
  const [database] = await sql<
    {
      version: number;
      encoding: string;
      collation: string;
      character_type: string;
      empty: boolean;
      isolated_roles: boolean;
    }[]
  >`
    SELECT current_setting('server_version_num')::integer AS version,
      pg_encoding_to_char(database.encoding) AS encoding, database.datcollate AS collation,
      database.datctype AS character_type,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class AS relation JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid=relation.relnamespace WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
        AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp%') AS empty,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE starts_with(rolname, 'periapsis_')) AS isolated_roles
    FROM pg_catalog.pg_database AS database WHERE datname=current_database()
  `;
  assert.deepEqual(database, {
    version: 180_006,
    encoding: "UTF8",
    collation: "C",
    character_type: "C",
    empty: true,
    isolated_roles: true,
  });
  await sql`SET TIME ZONE 'UTC'`;
  await stagePrefix(v56Count);
  await migrateStagedPrefix();
  await assertAppliedPrefix(v56Count);
  const [unsealed] = await sql<
    CompatibilityRow[]
  >`SELECT * FROM app.schema_compatibility_v56()`;
  assert.deepEqual(unsealed, unsupported);
  await sealV56();
  const [sealed] = await sql<
    (CompatibilityRow & { catalog_digest: string; ready: boolean })[]
  >`
    SELECT compatibility.*, app.private_release_runtime_dependency_surface_hash_v56() AS catalog_digest,
      app.release_runtime_schema_readiness_v56() AS ready FROM app.schema_compatibility_v56() AS compatibility
  `;
  assert.deepEqual(sealed, {
    applied_count: String(v56Count),
    latest_created_at: String(v56Latest.createdAt),
    latest_hash: v56Latest.hash,
    migration_fingerprint: v56Fingerprint,
    catalog_digest: v56CatalogDigest,
    ready: true,
  });

  await seedLogoutSessions();
  const tenantCommand = logoutCommand(tenantSession, tenant, 10);
  const tenantReceipt = await revoke(tenantCommand);
  await assertLogoutEffects(tenantCommand, tenantReceipt);
  const [livePlatform] = await sql<{ value: boolean }[]>`
    SELECT count(*)=1 AND coalesce(bool_and(active_tenant_id IS NULL
      AND revoked_at IS NULL AND absolute_expires_at>transaction_timestamp()
      AND idle_expires_at>transaction_timestamp()), false) AS value
    FROM public.auth_sessions WHERE id=${platformSession}::uuid AND user_id=${user}::uuid
  `;
  assert.equal(livePlatform?.value, true);
  const before = await redactedSnapshot();

  await stagePrefix(245);
  await migrateStagedPrefix();
  await assertAppliedPrefix(245);
  assert.deepEqual(
    await redactedSnapshot(),
    before,
    "0244 must preserve existing receipt/audit and live platform session",
  );
  const [partial] = await sql<
    CompatibilityRow[]
  >`SELECT * FROM app.schema_compatibility_v56()`;
  assert.deepEqual(partial, unsupported);
  const [interval] = await sql<
    {
      old_ready: boolean;
      current_root_absent: boolean;
      current_ready_absent: boolean;
      writers_offline: boolean;
      api_array: boolean[];
      worker_array: boolean[];
    }[]
  >`
    SELECT app.release_runtime_schema_readiness_v56() AS old_ready,
      app.api_runtime_schema_readiness_v57() AS api_array,
      app.worker_runtime_schema_readiness_v57() AS worker_array,
      to_regprocedure('app.schema_compatibility_v57()') IS NULL AS current_root_absent,
      to_regprocedure('app.release_runtime_schema_readiness_v57()') IS NULL AS current_ready_absent,
      NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname IN
        ('periapsis_api','periapsis_worker','periapsis_notifier') AND rolcanlogin) AS writers_offline
  `;
  assert.deepEqual(interval, {
    old_ready: false,
    api_array: Array<boolean>(8).fill(false),
    worker_array: Array<boolean>(5).fill(false),
    current_root_absent: true,
    current_ready_absent: true,
    writers_offline: true,
  });

  await migrateSchema(sql, migrationsRoot);
  await assertSealedV61();
  assert.deepEqual(
    await redactedSnapshot(),
    before,
    "V61 sealing must not mutate historical logout data",
  );
  assert.deepEqual(
    await revoke(tenantCommand),
    tenantReceipt,
    "historical tenant receipt must replay exactly after V61",
  );
  assert.deepEqual(await redactedSnapshot(), before);

  const platformCommand = logoutCommand(platformSession, null, 30);
  const platformReceipt = await revoke(platformCommand);
  await assertLogoutEffects(platformCommand, platformReceipt);
  const afterPlatform = await redactedSnapshot();
  assert.deepEqual(await revoke(platformCommand), platformReceipt);
  assert.deepEqual(
    await redactedSnapshot(),
    afterPlatform,
    "platform immutable replay must not duplicate audit",
  );
  const freshReceipt = await revoke(logoutCommand(platformSession, null, 40));
  assert(isJSONRecord(freshReceipt));
  assert.equal(freshReceipt.category, "revoked_local_only");
  assert.equal(freshReceipt.tenantId, null);
  assert.deepEqual(
    await redactedSnapshot(),
    afterPlatform,
    "a fresh request for an already revoked platform session must not mint command/audit",
  );

  await migrateSchema(sql, migrationsRoot);
  await assertSealedV61();
  assert.deepEqual(
    await redactedSnapshot(),
    afterPlatform,
    "normal runner restart must preserve both logout histories",
  );
  assert.deepEqual(await revoke(tenantCommand), tenantReceipt);
  assert.deepEqual(await revoke(platformCommand), platformReceipt);
  assert.deepEqual(await redactedSnapshot(), afterPlatform);
  // Reuse the ordinary administrative graph and direct planning/apply -> tenant
  // switch -> first revalidation -> logout suite, never a copied SAML fixture.
  try {
    await promisify(execFile)(
      process.execPath,
      [
        "--import",
        "tsx",
        resolve(import.meta.dirname, "saml-session-material-id-runtime.ts"),
      ],
      {
        cwd: resolve(import.meta.dirname, "../.."),
        env: {
          ...process.env,
          PERIAPSIS_SAML_MATERIAL_TEST_DATABASE_URL: databaseUrl,
        },
        timeout: 300_000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
      },
    );
  } catch {
    // Child errors may contain SQL parameters; do not forward captured output.
    throw new Error(
      "ordinary SAML admission/runtime proof failed after V56 -> V61 upgrade",
    );
  }
  await assertSealedV61();
  assert.deepEqual(
    await redactedSnapshot(),
    afterPlatform,
    "the independent SAML graph must not mutate existing logout histories",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { force: true, recursive: true });
}
