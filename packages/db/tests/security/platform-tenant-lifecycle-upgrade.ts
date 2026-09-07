import assert from "node:assert/strict";
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

import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import { migrateSchema } from "../../src/admin/schema-migration.js";

type JournalEntry = {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
};

type Journal = {
  version: string;
  dialect: string;
  entries: JournalEntry[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return (
    isRecord(value) &&
    Number.isSafeInteger(value.idx) &&
    typeof value.version === "string" &&
    Number.isSafeInteger(value.when) &&
    typeof value.tag === "string" &&
    typeof value.breakpoints === "boolean"
  );
}

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    typeof value.dialect !== "string" ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isJournalEntry)
  ) {
    throw new Error("The Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

const databaseUrl =
  process.env.PERIAPSIS_TENANT_LIFECYCLE_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_LIFECYCLE_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d3b20-6000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  platformGrant: uuid(4),
  session: uuid(5),
  family: uuid(6),
  audit: uuid(7),
  request: uuid(8),
  correlation: uuid(9),
} as const;

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 149;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
assert.equal(predecessorEntries.length, 150);
assert.equal(predecessor?.tag, "0149_condemned_bedlam");
assert.equal(predecessor.createdAt, 1787756689913);
assert.equal(
  predecessor.hash,
  "0f5a388806ac70eb58aa11782575b57ff66bc650df981b36fd3a065dfa713c6a",
);
assert.equal(expectedMigrationCount, 242);
assert.equal(expectedMigrationCreatedAt, 1788800892499);
const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-tenant-lifecycle-rolling-0149-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18.6"),
    "upgrade harness requires PostgreSQL 18.6",
  );

  await mkdir(resolve(stageRoot, "meta"));
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: predecessorEntries }, null, 2)}\n`,
  );
  await Promise.all(
    predecessorEntries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );

  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [prefix] = await sql<
    {
      count: number;
      latestCreatedAt: string;
      latestHash: string;
      currentCount: number;
      predecessorCount: number;
      retiredCount: number;
      lifecycleFunctionPresent: boolean;
    }[]
  >`
    SELECT count(*)::integer AS count,
           max(migration.created_at)::text AS "latestCreatedAt",
           (array_agg(lower(migration.hash::text)
              ORDER BY migration.created_at DESC, migration.id DESC))[1]
             AS "latestHash",
           (SELECT applied_count::integer
            FROM app.schema_compatibility_v31()) AS "currentCount",
           (SELECT applied_count::integer
            FROM app.schema_compatibility_v30()) AS "predecessorCount",
           (SELECT applied_count::integer
            FROM app.schema_compatibility_v29()) AS "retiredCount",
           to_regprocedure(
             'app.change_platform_tenant_lifecycle(uuid,uuid,public.tenant_status,integer,text,uuid,uuid,uuid,inet,text,text)'
           ) IS NOT NULL AS "lifecycleFunctionPresent"
    FROM drizzle.__drizzle_migrations AS migration
  `;
  assert.deepEqual(prefix, {
    count: 150,
    latestCreatedAt: String(predecessor.createdAt),
    latestHash: predecessor.hash,
    currentCount: 150,
    predecessorCount: 0,
    retiredCount: 0,
    lifecycleFunctionPresent: false,
  });

  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 60 * 60_000);
  const nowWire = now.toISOString();
  const expiresWire = expires.toISOString();
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES (
        ${fixture.user}::uuid, 'lifecycle.upgrade@example.invalid',
        'Lifecycle rolling-upgrade operator'
      )
    `;
    await transaction`
      INSERT INTO public.tenants (id, slug, name, status, version)
      VALUES (
        ${fixture.tenant}::uuid, 'lifecycle-upgrade',
        'Lifecycle rolling-upgrade tenant', 'active', 1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status, created_at, updated_at
      ) VALUES (
        ${fixture.membership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.user}::uuid, 'tenant_admin', 'active',
        ${nowWire}::timestamptz, ${nowWire}::timestamptz
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,
        ${fixture.membership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id, granted_at
      )
      SELECT ${fixture.platformGrant}::uuid, ${fixture.user}::uuid,
             role.id, ${fixture.user}::uuid, ${nowWire}::timestamptz
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES (
        ${fixture.session}::uuid, ${fixture.user}::uuid,
        ${fixture.family}::uuid, NULL, ${Buffer.alloc(32, 21)}::bytea,
        ${Buffer.alloc(32, 22)}::bytea, 'totp', ${nowWire}::timestamptz,
        ${nowWire}::timestamptz, ${expiresWire}::timestamptz,
        ${expiresWire}::timestamptz, ${nowWire}::timestamptz
      )
    `;
  });

  const [prefixAuthorizationState] = await sql<{ revision: string }[]>`
    SELECT revision::text AS revision
    FROM public.tenant_authorization_states
    WHERE tenant_id = ${fixture.tenant}::uuid
  `;
  assert.deepEqual(prefixAuthorizationState, { revision: "1" });

  await migrateSchema(sql, migrationsRoot);
  const appendedCreatedAt = expectedMigrations
    .slice(predecessorIndex + 1)
    .map((entry) => entry.createdAt);
  assert.equal(appendedCreatedAt.length, 92);
  assert.deepEqual(
    appendedCreatedAt.slice(0, 5),
    [1787758674256, 1787758694313, 1787759373746, 1787852011539, 1787852085088],
  );
  assert.equal(appendedCreatedAt.at(-1), 1788800892499);

  const [compatibility] = await sql<
    {
      currentCount: number;
      currentLatest: string;
      currentHash: string;
      currentFingerprint: string;
      predecessorCount: number;
      predecessorLatest: string;
      predecessorHash: string;
      predecessorFingerprint: string;
      retiredCount: number;
      releaseReady: boolean;
      federationV55Ready: boolean;
      lifecycleReady: boolean;
      federationReady: boolean;
      savedViewsReady: boolean;
      projectionsReady: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS "currentCount",
           current_projection.latest_created_at::text AS "currentLatest",
           current_projection.latest_hash AS "currentHash",
           current_projection.migration_fingerprint AS "currentFingerprint",
           predecessor_projection.applied_count::integer AS "predecessorCount",
           predecessor_projection.latest_created_at::text AS "predecessorLatest",
           predecessor_projection.latest_hash AS "predecessorHash",
           predecessor_projection.migration_fingerprint AS "predecessorFingerprint",
           retired_projection.applied_count::integer AS "retiredCount",
           app.release_runtime_schema_readiness_v55() AS "releaseReady",
           app.federated_authentication_schema_readiness_v55()
             AS "federationV55Ready",
           app.platform_tenant_lifecycle_schema_readiness_v1()
             AS "lifecycleReady",
           app.federated_authentication_schema_readiness_v1()
             AS "federationReady",
           app.ticket_saved_views_schema_readiness_v1() AS "savedViewsReady",
           app.ticket_query_projections_readiness_v1() AS "projectionsReady"
    FROM app.schema_compatibility_v55() AS current_projection
    CROSS JOIN app.schema_compatibility_v32() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v31() AS retired_projection
  `;
  assert.deepEqual(compatibility, {
    currentCount: expectedMigrationCount,
    currentLatest: String(expectedMigrationCreatedAt),
    currentHash: expectedMigrationHash,
    currentFingerprint: expectedMigrationFingerprint,
    predecessorCount: 0,
    predecessorLatest: "0",
    predecessorHash: "UNSUPPORTED",
    predecessorFingerprint: "UNSUPPORTED",
    retiredCount: 0,
    releaseReady: true,
    federationV55Ready: true,
    lifecycleReady: false,
    federationReady: false,
    savedViewsReady: false,
    projectionsReady: false,
  });

  const [preLifecycleState] = await sql<{ revision: string }[]>`
    SELECT revision::text AS revision
    FROM public.tenant_authorization_states
    WHERE tenant_id = ${fixture.tenant}::uuid
  `;
  // The current tail performs 34 real authorization invalidations: MFA-policy
  // and alert-delete grants/ceilings/role versions, the SLA service principal,
  // audit-operation grants/ceilings, and tenant-settings grants/ceilings/roles.
  assert.deepEqual(preLifecycleState, { revision: "35" });
  const preLifecycleRevision = BigInt(preLifecycleState.revision);
  const postLifecycleRevision = (preLifecycleRevision + 1n).toString();
  assert.equal(postLifecycleRevision, "36");

  const lifecycleReceipt = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction`
      SELECT set_config('app.user_id', ${fixture.user}, true)
    `;
    const [catalog] = await transaction<
      { v3Permissions: string[]; v2Permissions: string[] }[]
    >`
      SELECT v3.platform_permissions AS "v3Permissions",
             v2.platform_permissions AS "v2Permissions"
      FROM app.get_auth_session_v3(${Buffer.alloc(32, 21)}::bytea) AS v3
      CROSS JOIN app.get_auth_session_v2(${Buffer.alloc(32, 21)}::bytea) AS v2
    `;
    assert(catalog?.v3Permissions.includes("platform.tenant.manage"));
    assert(!catalog?.v2Permissions.includes("platform.tenant.manage"));
    const [receipt] = await transaction<
      { status: string; version: number; replayed: boolean }[]
    >`
      SELECT status::text, version, replayed
      FROM app.change_platform_tenant_lifecycle(
        ${fixture.session}::uuid, ${fixture.tenant}::uuid, 'suspended', 1,
        'Rolling-upgrade suspension proof', ${fixture.audit}::uuid,
        ${fixture.request}::uuid, ${fixture.correlation}::uuid,
        '198.51.100.42'::inet, 'Periapsis lifecycle upgrade proof', 'totp'
      )
    `;
    return receipt;
  });
  assert.deepEqual(lifecycleReceipt, {
    status: "suspended",
    version: 2,
    replayed: false,
  });

  const [persisted] = await sql<
    {
      status: string;
      version: number;
      revision: string;
      auditCount: number;
      auditPreviousRevision: string;
      auditResultRevision: string;
    }[]
  >`
    SELECT tenant.status, tenant.version,
           state.revision::text AS revision,
           (SELECT count(*)::integer
             FROM public.platform_audit_events AS event
             WHERE event.resource_id = tenant.id
               AND event.action = 'platform.tenant.suspended') AS "auditCount",
           (SELECT event.metadata ->> 'previous_authorization_revision'
             FROM public.platform_audit_events AS event
             WHERE event.resource_id = tenant.id
               AND event.action = 'platform.tenant.suspended'
             LIMIT 1) AS "auditPreviousRevision",
           (SELECT event.metadata ->> 'authorization_revision'
             FROM public.platform_audit_events AS event
             WHERE event.resource_id = tenant.id
               AND event.action = 'platform.tenant.suspended'
             LIMIT 1) AS "auditResultRevision"
    FROM public.tenants AS tenant
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
    WHERE tenant.id = ${fixture.tenant}::uuid
  `;
  assert.deepEqual(persisted, {
    status: "suspended",
    version: 2,
    revision: postLifecycleRevision,
    auditCount: 1,
    auditPreviousRevision: preLifecycleState.revision,
    auditResultRevision: postLifecycleRevision,
  });
  process.stdout.write(
    "platform tenant lifecycle rolling-upgrade proof passed\n",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
