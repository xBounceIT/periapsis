import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
import postgres, { type Sql } from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import {
  executeWithCleanup,
  migrateSchema,
} from "../../src/admin/schema-migration.js";

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
type CompatibilityRow = {
  applied_count: number;
  latest_created_at: string | null;
  latest_hash: string | null;
  migration_fingerprint: string | null;
};
type PredecessorDirectGrantRow = {
  grant_id: string;
  membership_id: string;
  target_user_id?: string;
  role_key: string;
  source_kind: string;
  source_authoritative: boolean;
  source_retired_at: string | null;
  source_type: string;
  grant_state: string;
  version: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return isRecord(error) && error.code === code;
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
    throw new Error("Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

const fixture = {
  legacyInitializedTenant: "01993ea0-6a00-7000-8000-000000000001",
  legacyUninitializedTenant: "01993ea0-6a00-7000-8000-000000000002",
  freshInitializedTenant: "01993ea0-6a00-7000-8000-000000000003",
  legacyInitializedUser: "01993ea0-6a00-7000-8000-000000000101",
  legacyUninitializedUser: "01993ea0-6a00-7000-8000-000000000102",
  freshInitializedUser: "01993ea0-6a00-7000-8000-000000000103",
  legacyInitializedMembership: "01993ea0-6a00-7000-8000-000000000201",
  legacyUninitializedMembership: "01993ea0-6a00-7000-8000-000000000202",
  freshInitializedMembership: "01993ea0-6a00-7000-8000-000000000203",
  freshInitializationEvent: "01993ea0-6a00-7000-8000-000000000301",
  preHardeningOperatorTeam: "01993ea0-6a00-7000-8000-000000000401",
  preHardeningAssignment: "01993ea0-6a00-7000-8000-000000000501",
} as const;

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);

assert.equal(journal.entries.at(10)?.tag, "0010_phase_2b_tenant_rbac");
assert.equal(
  journal.entries.at(24)?.tag,
  "0024_direct_grant_inventory_boundary_hardening",
);
assert.equal(
  journal.entries.at(25)?.tag,
  "0025_authorization_compatibility_and_ownership",
);
assert.equal(
  journal.entries.at(26)?.tag,
  "0026_schema_compatibility_fail_closed",
);
assert.equal(journal.entries.at(29)?.tag, "0029_operator_team_readiness_v4");
assert.equal(journal.entries.at(32)?.tag, "0032_operator_team_readiness_v5");
assert.equal(
  journal.entries.at(38)?.tag,
  "0038_service_principal_readiness_v6",
);
assert.equal(
  journal.entries.at(39)?.tag,
  "0039_service_principal_audit_readiness",
);

const databaseURL =
  process.env.PERIAPSIS_AUTHORIZATION_UPGRADE_TEST_DATABASE_URL;
if (databaseURL === undefined || databaseURL.trim() === "") {
  throw new Error(
    "PERIAPSIS_AUTHORIZATION_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18 database whose cluster has no periapsis_* roles",
  );
}

async function stagedMigrations(
  lastIndex: number,
  stageRoots: string[],
): Promise<string> {
  const stageRoot = await mkdtemp(
    join(tmpdir(), `periapsis-authorization-upgrade-${lastIndex}-`),
  );
  stageRoots.push(stageRoot);
  await mkdir(resolve(stageRoot, "meta"));
  const entries = journal.entries.slice(0, lastIndex + 1);
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );
  return stageRoot;
}

async function compatibility(
  sql: Sql,
  functionName:
    | "schema_compatibility"
    | "schema_compatibility_v2"
    | "schema_compatibility_v3"
    | "schema_compatibility_v4"
    | "schema_compatibility_v5"
    | "schema_compatibility_v6",
): Promise<CompatibilityRow> {
  const [row] = await sql.unsafe<CompatibilityRow[]>(`
    SELECT applied_count::integer AS applied_count,
           latest_created_at::text AS latest_created_at,
           latest_hash,
           migration_fingerprint
    FROM app.${functionName}()
  `);
  assert(row, `${functionName} returned no compatibility row`);
  return row;
}

function expectedCompatibility(
  migrationHashes: string[],
  entries: JournalEntry[],
  bindTimestamps = false,
): CompatibilityRow {
  const latestEntry = entries.at(-1);
  const latestHash = migrationHashes.at(-1);
  assert(
    latestEntry && latestHash && migrationHashes.length === entries.length,
  );
  return {
    applied_count: entries.length,
    latest_created_at: String(latestEntry.when),
    latest_hash: latestHash,
    migration_fingerprint: migrationHashes
      .map((hash, index) =>
        bindTimestamps ? `${entries[index]!.when}@${hash}` : hash,
      )
      .join(":"),
  };
}

async function sealCompatibility(
  sql: Sql,
  manifest: CompatibilityRow,
): Promise<void> {
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${manifest.applied_count}::bigint,
      ${manifest.latest_created_at}::bigint,
      ${manifest.latest_hash}::text,
      ${manifest.migration_fingerprint}::text
    )
  `;
}

async function assertAuditChain(sql: Sql, tenantID: string): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantID}, true)
    `;
    const rows = await transaction<{ valid: boolean }[]>`
      SELECT valid
      FROM app.verify_audit_chain(${tenantID}::uuid)
    `;
    assert(rows.length >= 2, `audit chain for ${tenantID} has no sealed event`);
    assert(
      rows.every((row) => row.valid),
      `audit chain for ${tenantID} failed verification`,
    );
  });
}

const migrationSql = await Promise.all(
  journal.entries.map((entry) =>
    readFile(resolve(migrationsRoot, `${entry.tag}.sql`)),
  ),
);
const migrationHashes = migrationSql.map((source) =>
  createHash("sha256").update(source).digest("hex"),
);
const legacyManifest = expectedCompatibility(
  migrationHashes.slice(0, 25),
  journal.entries.slice(0, 25),
);
const phase0025Manifest = expectedCompatibility(
  migrationHashes.slice(0, 26),
  journal.entries.slice(0, 26),
);
const phase0025TimestampBoundManifest = expectedCompatibility(
  migrationHashes.slice(0, 26),
  journal.entries.slice(0, 26),
  true,
);
const phase0026Manifest = expectedCompatibility(
  migrationHashes.slice(0, 27),
  journal.entries.slice(0, 27),
  true,
);
const phase0029Manifest = expectedCompatibility(
  migrationHashes.slice(0, 30),
  journal.entries.slice(0, 30),
  true,
);
const phase0032Manifest = expectedCompatibility(
  migrationHashes.slice(0, 33),
  journal.entries.slice(0, 33),
  true,
);
const phase0038Manifest = expectedCompatibility(
  migrationHashes.slice(0, 39),
  journal.entries.slice(0, 39),
  true,
);
const phase0039Manifest = expectedCompatibility(
  migrationHashes.slice(0, 40),
  journal.entries.slice(0, 40),
  true,
);
const currentManifest = expectedCompatibility(
  migrationHashes,
  journal.entries,
  true,
);
const failClosedCompatibility: CompatibilityRow = {
  applied_count: 0,
  latest_created_at: "0",
  latest_hash: "UNSUPPORTED",
  migration_fingerprint: "UNSUPPORTED",
};
assert.deepEqual(
  currentManifest,
  {
    applied_count: expectedMigrationCount,
    latest_created_at: String(expectedMigrationCreatedAt),
    latest_hash: expectedMigrationHash,
    migration_fingerprint: expectedMigrationFingerprint,
  },
  "generated migration manifest is stale",
);
const stageRoots: string[] = [];
let closeClient: (() => Promise<void>) | undefined;

await executeWithCleanup(
  async () => {
    const phase0010 = await stagedMigrations(10, stageRoots);
    const phase0024 = await stagedMigrations(24, stageRoots);
    const phase0025 = await stagedMigrations(25, stageRoots);
    const phase0026 = await stagedMigrations(26, stageRoots);
    const phase0029 = await stagedMigrations(29, stageRoots);
    const phase0032 = await stagedMigrations(32, stageRoots);
    const phase0038 = await stagedMigrations(38, stageRoots);
    const phase0039 = await stagedMigrations(39, stageRoots);
    const client = postgres(databaseURL, { max: 1, onnotice: () => undefined });
    closeClient = () => client.end();

    const [databaseState] = await client<
      { has_application_schema: boolean; periapsis_role_count: number }[]
    >`
    SELECT to_regclass('public.tenants') IS NOT NULL AS has_application_schema,
           (
             SELECT count(*)::integer
             FROM pg_catalog.pg_roles
             WHERE rolname IN (
               'periapsis_api', 'periapsis_auditor', 'periapsis_migrator',
               'periapsis_notifier', 'periapsis_worker'
             )
           ) AS periapsis_role_count
  `;
    assert(databaseState);
    assert.equal(
      databaseState.has_application_schema,
      false,
      "upgrade test database is not empty",
    );
    assert.equal(
      databaseState.periapsis_role_count,
      0,
      "upgrade test cluster already contains periapsis_* roles",
    );

    await client`SET TIME ZONE 'UTC'`;
    await client`SELECT set_config('search_path', 'public', false)`;
    await migrate(drizzle(client), { migrationsFolder: phase0010 });

    await client.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.legacyInitializedUser}::uuid, 'legacy-admin@upgrade.invalid', 'Legacy administrator'),
        (${fixture.legacyUninitializedUser}::uuid, 'legacy-analyst@upgrade.invalid', 'Legacy analyst')
    `;
      await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.legacyInitializedTenant}::uuid, 'legacy-initialized', 'Legacy initialized tenant'),
        (${fixture.legacyUninitializedTenant}::uuid, 'legacy-uninitialized', 'Legacy uninitialized tenant')
    `;
      await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (
          ${fixture.legacyInitializedMembership}::uuid,
          ${fixture.legacyInitializedTenant}::uuid,
          ${fixture.legacyInitializedUser}::uuid,
          'tenant_admin', 'active'
        ),
        (
          ${fixture.legacyUninitializedMembership}::uuid,
          ${fixture.legacyUninitializedTenant}::uuid,
          ${fixture.legacyUninitializedUser}::uuid,
          'analyst', 'active'
        )
    `;
    });

    await migrate(drizzle(client), { migrationsFolder: phase0024 });

    const legacyStates = await client<
      { tenant_id: string; initialized: boolean }[]
    >`
    SELECT tenant_id::text, initialized_at IS NOT NULL AS initialized
    FROM public.tenant_authorization_states
    WHERE tenant_id IN (
      ${fixture.legacyInitializedTenant}::uuid,
      ${fixture.legacyUninitializedTenant}::uuid
    )
    ORDER BY tenant_id
  `;
    assert.deepEqual(Array.from(legacyStates), [
      { tenant_id: fixture.legacyInitializedTenant, initialized: true },
      { tenant_id: fixture.legacyUninitializedTenant, initialized: false },
    ]);

    await client.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES (
        ${fixture.freshInitializedUser}::uuid,
        'fresh-admin@upgrade.invalid',
        'Fresh administrator'
      )
    `;
      await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES (
        ${fixture.freshInitializedTenant}::uuid,
        'fresh-initialized',
        'Fresh initialized tenant'
      )
    `;
      await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES (
        ${fixture.freshInitializedMembership}::uuid,
        ${fixture.freshInitializedTenant}::uuid,
        ${fixture.freshInitializedUser}::uuid,
        'tenant_admin', 'active'
      )
    `;
      await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.freshInitializedTenant}::uuid,
        ${fixture.freshInitializedMembership}::uuid
      )
    `;
      await transaction`
      INSERT INTO public.audit_events (
        id, tenant_id, sequence, actor_type, actor_user_id, action,
        resource_type, resource_id, authentication_method, outcome,
        after, metadata
      ) VALUES (
        ${fixture.freshInitializationEvent}::uuid,
        ${fixture.freshInitializedTenant}::uuid,
        0, 'user', ${fixture.freshInitializedUser}::uuid,
        'tenant.authorization.initialized', 'tenant',
        ${fixture.freshInitializedTenant}::uuid,
        'bootstrap_totp', 'success',
        jsonb_build_object('tenant_authorization_initialized', true),
        jsonb_build_object('source', 'platform_tenant_creation')
      )
    `;
    });

    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      legacyManifest,
      "pre-0025 database does not match the legacy manifest",
    );

    const [preflightFirstMigration] = await client<
      { id: number; hash: string }[]
    >`
    SELECT id, hash::text
    FROM drizzle.__drizzle_migrations
    ORDER BY created_at, id
    LIMIT 1
  `;
    assert(preflightFirstMigration);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"0".repeat(64)}
          WHERE id = ${preflightFirstMigration.id}
        `;
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted a divergent predecessor",
        );
        const [failedPreflightState] = await client<
          { applied_count: number; has_v2_projection: boolean }[]
        >`
          SELECT count(*)::integer AS applied_count,
                 to_regprocedure('app.schema_compatibility_v2()') IS NOT NULL
                   AS has_v2_projection
          FROM drizzle.__drizzle_migrations
        `;
        assert.deepEqual(failedPreflightState, {
          applied_count: 25,
          has_v2_projection: false,
        });
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${preflightFirstMigration.hash}
          WHERE id = ${preflightFirstMigration.id}
        `;
      },
      "preflight divergence checks and journal restoration both failed",
    );

    await migrate(drizzle(client), { migrationsFolder: phase0025 });

    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      phase0025Manifest,
      "raw Drizzle unexpectedly enabled the unsealed legacy projection",
    );

    const callerSpoofedProjection = await client.begin(async (transaction) => {
      await transaction`
      SELECT set_config(
        'app.schema_compatibility_fingerprint',
        ${phase0025Manifest.migration_fingerprint},
        true
      )
    `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [row] = await transaction<CompatibilityRow[]>`
      SELECT applied_count::integer AS applied_count,
             latest_created_at::text AS latest_created_at,
             latest_hash,
             migration_fingerprint
      FROM app.schema_compatibility()
    `;
      assert(row);
      return row;
    });
    assert.deepEqual(
      callerSpoofedProjection,
      phase0025Manifest,
      "a runtime caller bypassed the UNSEALED function setting",
    );

    await assert.rejects(
      async () =>
        client.begin(async (transaction) => {
          await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
          await transaction`
          SELECT app.seal_schema_compatibility_manifest(
            ${phase0025Manifest.applied_count}::bigint,
            ${phase0025Manifest.latest_created_at}::bigint,
            ${phase0025Manifest.latest_hash}::text,
            ${phase0025Manifest.migration_fingerprint}::text
          )
        `;
        }),
      (error) => hasErrorCode(error, "42501"),
      "the API runtime role executed the migrator-only seal",
    );

    await assert.rejects(
      async () => {
        await client`
        SELECT app.seal_schema_compatibility_manifest(
          ${legacyManifest.applied_count}::bigint,
          ${legacyManifest.latest_created_at}::bigint,
          ${legacyManifest.latest_hash}::text,
          ${legacyManifest.migration_fingerprint}::text
        )
      `;
      },
      (error) => hasErrorCode(error, "55000"),
      "the seal accepted a stale external manifest",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      phase0025Manifest,
      "a rejected seal changed the fail-closed sentinel",
    );

    await sealCompatibility(client, phase0025Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      legacyManifest,
      "the trusted 0025 seal did not enable the exact 0000-0024 projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "0025 current projection does not match the complete manifest",
    );

    await sealCompatibility(client, phase0025Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      legacyManifest,
      "repeating the canonical seal changed the legacy projection",
    );

    await assert.rejects(
      async () => {
        await client`
        SELECT app.seal_schema_compatibility_manifest(
          ${legacyManifest.applied_count}::bigint,
          ${legacyManifest.latest_created_at}::bigint,
          ${legacyManifest.latest_hash}::text,
          ${legacyManifest.migration_fingerprint}::text
        )
      `;
      },
      (error) => hasErrorCode(error, "55000"),
      "a stale reseal unexpectedly succeeded",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      legacyManifest,
      "a rejected reseal replaced the last trusted fingerprint",
    );

    const predecessorProjection = await client.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
      SELECT set_config(
               'app.tenant_id', ${fixture.legacyInitializedTenant}, true
             ),
             set_config(
               'app.user_id', ${fixture.legacyInitializedUser}, true
             )
    `;
      const listed = await transaction<PredecessorDirectGrantRow[]>`
      SELECT role_grant.grant_id::text AS grant_id,
             role_grant.membership_id::text AS membership_id,
             role_grant.role_key::text AS role_key,
             role_grant.source_kind::text AS source_kind,
             role_grant.source_authoritative::boolean AS source_authoritative,
             role_grant.source_retired_at::text AS source_retired_at,
             role_grant.source_type::text AS source_type,
             role_grant.grant_state::text AS grant_state,
             role_grant.version::integer AS version
      FROM app.list_tenant_membership_role_grants(
        ${fixture.legacyInitializedUser}::uuid,
        NULL::uuid,
        true,
        101
      ) AS role_grant(
        grant_id, membership_id, role_id, role_key, role_name,
        role_description, role_system, role_archived_at, role_version,
        role_created_at, role_updated_at, source_id, source_kind,
        source_authoritative, source_retired_at, source_type,
        granted_by_membership_id, granted_by_user_id, grant_reason,
        granted_at, expires_at, revoked_at, revoked_by_membership_id,
        revoked_by_user_id, revoke_reason, grant_state, version, updated_at
      )
    `;
      assert.equal(
        listed.length,
        1,
        "0024 list projection lost the tenant-creation recovery grant",
      );
      const listRow = listed[0];
      assert(listRow);
      const [detail] = await transaction<PredecessorDirectGrantRow[]>`
      SELECT role_grant.grant_id::text AS grant_id,
             role_grant.membership_id::text AS membership_id,
             role_grant.target_user_id::text AS target_user_id,
             role_grant.role_key::text AS role_key,
             role_grant.source_kind::text AS source_kind,
             role_grant.source_authoritative::boolean AS source_authoritative,
             role_grant.source_retired_at::text AS source_retired_at,
             role_grant.source_type::text AS source_type,
             role_grant.grant_state::text AS grant_state,
             role_grant.version::integer AS version
      FROM app.get_tenant_membership_role_grant(
        ${listRow.grant_id}::uuid
      ) AS role_grant(
        grant_id, membership_id, target_user_id, role_id, role_key,
        role_name, role_description, role_system, role_archived_at,
        role_version, role_created_at, role_updated_at, source_id,
        source_kind, source_authoritative, source_retired_at, source_type,
        granted_by_membership_id, granted_by_user_id, grant_reason,
        granted_at, expires_at, revoked_at, revoked_by_membership_id,
        revoked_by_user_id, revoke_reason, grant_state, version, updated_at
      )
    `;
      assert(detail, "0024 get projection returned no recovery grant");
      return { detail, listRow };
    });
    const expectedPredecessorProjection = {
      membership_id: fixture.legacyInitializedMembership,
      role_key: "tenant_admin",
      source_kind: "tenant_creation",
      source_authoritative: false,
      source_retired_at: null,
      source_type: "system",
      grant_state: "active",
      version: 1,
    };
    assert.deepEqual(
      {
        membership_id: predecessorProjection.listRow.membership_id,
        role_key: predecessorProjection.listRow.role_key,
        source_kind: predecessorProjection.listRow.source_kind,
        source_authoritative:
          predecessorProjection.listRow.source_authoritative,
        source_retired_at: predecessorProjection.listRow.source_retired_at,
        source_type: predecessorProjection.listRow.source_type,
        grant_state: predecessorProjection.listRow.grant_state,
        version: predecessorProjection.listRow.version,
      },
      expectedPredecessorProjection,
      "0025 changed the positional 0024 list projection",
    );
    assert.deepEqual(
      {
        membership_id: predecessorProjection.detail.membership_id,
        role_key: predecessorProjection.detail.role_key,
        source_kind: predecessorProjection.detail.source_kind,
        source_authoritative: predecessorProjection.detail.source_authoritative,
        source_retired_at: predecessorProjection.detail.source_retired_at,
        source_type: predecessorProjection.detail.source_type,
        grant_state: predecessorProjection.detail.grant_state,
        version: predecessorProjection.detail.version,
      },
      expectedPredecessorProjection,
      "0025 changed the positional 0024 get projection",
    );
    assert.equal(
      predecessorProjection.detail.target_user_id,
      fixture.legacyInitializedUser,
    );

    const migrationEvents = await client<
      {
        tenant_id: string;
        actor_type: string;
        actor_user_id: string | null;
        impersonated_by_user_id: string | null;
        request_id: string | null;
        correlation_id: string | null;
        ip_address: string | null;
        user_agent: string | null;
        reason: string | null;
        before: unknown;
        authentication_method: string | null;
        after: Record<string, boolean>;
        metadata: Record<string, string>;
        sealed: boolean;
      }[]
    >`
    SELECT tenant_id::text, actor_type::text, actor_user_id::text,
           impersonated_by_user_id::text, request_id::text,
           correlation_id::text, ip_address::text, user_agent, reason,
           before, authentication_method, after, metadata,
           sequence > 0
             AND previous_hash ~ '^[0-9a-f]{64}$'
             AND event_hash ~ '^[0-9a-f]{64}$'
             AND event_hash <> repeat('0', 64)::character(64) AS sealed
    FROM public.audit_events
    WHERE action = 'tenant.authorization.migration_backfilled'
    ORDER BY tenant_id
  `;
    assert.equal(migrationEvents.length, 2);
    assert.deepEqual(
      Array.from(migrationEvents, (event) => event.tenant_id),
      [fixture.legacyInitializedTenant, fixture.legacyUninitializedTenant],
    );
    for (const event of migrationEvents) {
      assert.equal(event.actor_type, "system");
      assert.equal(event.actor_user_id, null);
      assert.equal(event.impersonated_by_user_id, null);
      assert.equal(event.request_id, null);
      assert.equal(event.correlation_id, null);
      assert.equal(event.ip_address, null);
      assert.equal(event.user_agent, null);
      assert.equal(event.reason, null);
      assert.equal(event.before, null);
      assert.equal(event.authentication_method, "database_migration");
      assert.equal(event.sealed, true);
      assert.deepEqual(event.metadata, {
        migration: "0025_authorization_compatibility_and_ownership",
        source: "phase_2b_1_existing_tenant_backfill",
      });
    }
    assert.deepEqual(migrationEvents[0]?.after, {
      rbac_bootstrap_backfilled: true,
      authorization_initialized: true,
      recovery_grant_initialized: true,
    });
    assert.deepEqual(migrationEvents[1]?.after, {
      rbac_bootstrap_backfilled: true,
      authorization_initialized: false,
      recovery_grant_initialized: false,
    });

    const migration0025 = migrationSql[25]?.toString("utf8");
    assert(migration0025);
    const backfillStart = migration0025.lastIndexOf(
      "INSERT INTO public.audit_events",
    );
    assert(backfillStart >= 0, "0025 audit backfill statement is missing");
    await client.unsafe(migration0025.slice(backfillStart));
    const [idempotentResult] = await client<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.audit_events
    WHERE action = 'tenant.authorization.migration_backfilled'
  `;
    assert(idempotentResult);
    assert.equal(
      idempotentResult.count,
      2,
      "0025 audit marker is not idempotent",
    );

    await Promise.all(
      [
        fixture.legacyInitializedTenant,
        fixture.legacyUninitializedTenant,
        fixture.freshInitializedTenant,
      ].map((tenantID) => assertAuditChain(client, tenantID)),
    );

    const firstMigration = await client<{ id: number; hash: string }[]>`
    SELECT id, hash::text
    FROM drizzle.__drizzle_migrations
    ORDER BY created_at, id
    LIMIT 1
  `;
    const first = firstMigration[0];
    assert(first);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"0".repeat(64)}
          WHERE id = ${first.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility"),
          legacyManifest,
          "legacy projection accepted a divergent prefix",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${first.hash}
          WHERE id = ${first.id}
        `;
      },
      "legacy prefix checks and journal restoration both failed",
    );

    const migration0025Entry = journal.entries[25];
    assert(migration0025Entry);
    const [migration0025JournalRow] = await client<
      { id: number; hash: string }[]
    >`
    SELECT id, hash::text
    FROM drizzle.__drizzle_migrations
    WHERE created_at = ${migration0025Entry.when}
  `;
    assert(migration0025JournalRow);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"0".repeat(64)}
          WHERE id = ${migration0025JournalRow.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility"),
          legacyManifest,
          "legacy projection accepted a divergent 0025 hash",
        );
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility_v2"),
          phase0025Manifest,
          "current projection accepted a divergent 0025 hash",
        );
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted a divergent 0025 hash",
        );
        const [stillDivergent0025] = await client<{ hash: string }[]>`
          SELECT hash::text
          FROM drizzle.__drizzle_migrations
          WHERE id = ${migration0025JournalRow.id}
        `;
        assert.equal(
          stillDivergent0025?.hash,
          "0".repeat(64),
          "failed preflight modified the divergent journal",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${migration0025JournalRow.hash}
          WHERE id = ${migration0025JournalRow.id}
        `;
      },
      "0025 hash checks and journal restoration both failed",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      legacyManifest,
      "restoring the exact 0025 hash did not restore the sealed legacy edge",
    );

    await executeWithCleanup(
      async () => {
        await client`
          INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
          VALUES (${"f".repeat(64)}, ${migration0025Entry.when + 1})
        `;
        const laterState = await compatibility(client, "schema_compatibility");
        assert.equal(laterState.applied_count, 27);
        assert.notDeepEqual(
          laterState,
          legacyManifest,
          "legacy projection accepted a later migration",
        );
      },
      async () => {
        await client`
          DELETE FROM drizzle.__drizzle_migrations
          WHERE hash = ${"f".repeat(64)}
            AND created_at = ${migration0025Entry.when + 1}
        `;
      },
      "later-migration checks and journal restoration both failed",
    );

    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET created_at = ${migration0025Entry.when + 1}
          WHERE id = ${migration0025JournalRow.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility"),
          legacyManifest,
          "legacy projection accepted a different 0025 timestamp",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET created_at = ${migration0025Entry.when}
          WHERE id = ${migration0025JournalRow.id}
        `;
      },
      "0025 timestamp checks and journal restoration both failed",
    );

    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "0025 compatibility probes did not restore the exact journal",
    );

    await migrate(drizzle(client), { migrationsFolder: phase0026 });
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "raw 0026 current projection does not match the complete manifest",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      failClosedCompatibility,
      "raw Drizzle unexpectedly enabled the unsealed v2 predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      failClosedCompatibility,
      "raw 0026 did not retire the legacy compatibility projection",
    );

    await sealCompatibility(client, phase0026Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "0026 current projection does not match the complete manifest after sealing",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "0026 sealed predecessor projection does not match the exact 0025 manifest",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      failClosedCompatibility,
      "0026 did not retire the legacy compatibility projection",
    );

    const phase0026Fingerprint = phase0026Manifest.migration_fingerprint;
    assert(phase0026Fingerprint);
    const invalidPhase0026Manifests: CompatibilityRow[] = [
      {
        ...phase0026Manifest,
        applied_count: phase0026Manifest.applied_count - 1,
      },
      {
        ...phase0026Manifest,
        migration_fingerprint: migrationHashes.slice(0, 27).join(":"),
      },
      {
        ...phase0026Manifest,
        migration_fingerprint: phase0026Fingerprint.replace(
          `${phase0026Manifest.latest_created_at}@${phase0026Manifest.latest_hash}`,
          `${Number(phase0026Manifest.latest_created_at) - 1}@${phase0026Manifest.latest_hash}`,
        ),
      },
    ];
    await Promise.all(
      invalidPhase0026Manifests.map((invalidManifest) =>
        assert.rejects(
          async () => sealCompatibility(client, invalidManifest),
          (error) => hasErrorCode(error, "22023"),
          "the 0026 seal accepted an invalid timestamp-bound manifest",
        ),
      ),
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "an invalid 0026 seal changed the trusted predecessor fingerprint",
    );

    await sealCompatibility(client, phase0026Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "repeating the canonical 0026 seal changed the current projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "repeating the canonical 0026 seal changed the predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      failClosedCompatibility,
      "repeating the canonical 0026 seal changed the legacy sentinel",
    );

    const interiorMigrationIndex = 12;
    const interiorMigrationEntry = journal.entries[interiorMigrationIndex];
    const followingMigrationEntry = journal.entries[interiorMigrationIndex + 1];
    assert(interiorMigrationEntry && followingMigrationEntry);
    const driftedInteriorTimestamp = interiorMigrationEntry.when + 1;
    assert(
      driftedInteriorTimestamp < followingMigrationEntry.when,
      "interior timestamp drift must preserve journal ordering",
    );
    const [interiorMigrationJournalRow] = await client<{ id: number }[]>`
    SELECT id
    FROM drizzle.__drizzle_migrations
    WHERE created_at = ${interiorMigrationEntry.when}
  `;
    assert(interiorMigrationJournalRow);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET created_at = ${driftedInteriorTimestamp}
          WHERE id = ${interiorMigrationJournalRow.id}
        `;
        const driftedInteriorCurrent = await compatibility(
          client,
          "schema_compatibility_v3",
        );
        assert.equal(
          driftedInteriorCurrent.applied_count,
          phase0026Manifest.applied_count,
        );
        assert.equal(
          driftedInteriorCurrent.latest_created_at,
          phase0026Manifest.latest_created_at,
        );
        assert.equal(
          driftedInteriorCurrent.latest_hash,
          phase0026Manifest.latest_hash,
        );
        assert.notDeepEqual(
          driftedInteriorCurrent,
          phase0026Manifest,
          "current readiness accepted an interior migration timestamp drift",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v2"),
          failClosedCompatibility,
          "sealed v2 accepted an interior migration timestamp drift",
        );
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted an interior timestamp drift",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0026Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the current seal accepted an interior migration timestamp drift",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET created_at = ${interiorMigrationEntry.when}
          WHERE id = ${interiorMigrationJournalRow.id}
        `;
      },
      "interior timestamp checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0026Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "restoring and resealing the interior timestamp did not recover current readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "restoring and resealing the interior timestamp did not recover predecessor readiness",
    );

    const migration0026Entry = journal.entries[26];
    assert(migration0026Entry);
    const [migration0026JournalRow] = await client<
      { id: number; hash: string }[]
    >`
    SELECT id, hash::text
    FROM drizzle.__drizzle_migrations
    WHERE created_at = ${migration0026Entry.when}
  `;
    assert(migration0026JournalRow);
    await executeWithCleanup(
      async () => {
        const deleted0026Rows = await client<{ id: number }[]>`
          DELETE FROM drizzle.__drizzle_migrations
          WHERE id = ${migration0026JournalRow.id}
          RETURNING id
        `;
        assert.deepEqual(Array.from(deleted0026Rows), [
          { id: migration0026JournalRow.id },
        ]);
        const deleted0026Current = await compatibility(
          client,
          "schema_compatibility_v3",
        );
        assert.deepEqual(
          deleted0026Current,
          phase0025TimestampBoundManifest,
          "v3 did not expose the exact incomplete 26-row journal",
        );
        assert.notDeepEqual(
          deleted0026Current,
          phase0026Manifest,
          "current readiness accepted the journal with 0026 deleted",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v2"),
          failClosedCompatibility,
          "sealed v2 exposed a released prefix after deleting 0026",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility"),
          failClosedCompatibility,
          "deleting 0026 changed the retired legacy sentinel",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0026Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the current seal accepted a journal with 0026 deleted",
        );
      },
      async () => {
        await client`
          INSERT INTO drizzle.__drizzle_migrations (id, hash, created_at)
          VALUES (
            ${migration0026JournalRow.id},
            ${migration0026JournalRow.hash},
            ${migration0026Entry.when}
          )
          ON CONFLICT (id) DO UPDATE
          SET hash = EXCLUDED.hash,
              created_at = EXCLUDED.created_at
        `;
      },
      "0026 deletion checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0026Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "restoring and resealing 0026 did not recover current readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "restoring and resealing 0026 did not recover predecessor readiness",
    );

    await executeWithCleanup(
      async () => {
        const deleted0025Rows = await client<{ id: number }[]>`
          DELETE FROM drizzle.__drizzle_migrations
          WHERE id = ${migration0025JournalRow.id}
          RETURNING id
        `;
        assert.deepEqual(Array.from(deleted0025Rows), [
          { id: migration0025JournalRow.id },
        ]);
        const deleted0025Legacy = await compatibility(
          client,
          "schema_compatibility",
        );
        const deleted0025Predecessor = await compatibility(
          client,
          "schema_compatibility_v2",
        );
        const deleted0025Current = await compatibility(
          client,
          "schema_compatibility_v3",
        );
        assert.deepEqual(
          deleted0025Legacy,
          failClosedCompatibility,
          "deleting 0025 escaped the forward legacy sentinel",
        );
        assert.deepEqual(
          deleted0025Predecessor,
          failClosedCompatibility,
          "deleting 0025 escaped the sealed predecessor sentinel",
        );
        for (const acceptedManifest of [
          legacyManifest,
          phase0025Manifest,
          phase0026Manifest,
        ]) {
          assert.notDeepEqual(
            deleted0025Legacy,
            acceptedManifest,
            "legacy readiness accepted the journal with 0025 deleted",
          );
          assert.notDeepEqual(
            deleted0025Predecessor,
            acceptedManifest,
            "v2 predecessor readiness accepted the journal with 0025 deleted",
          );
          assert.notDeepEqual(
            deleted0025Current,
            acceptedManifest,
            "v3 current readiness accepted the journal with 0025 deleted",
          );
        }
      },
      async () => {
        await client`
          INSERT INTO drizzle.__drizzle_migrations (id, hash, created_at)
          VALUES (
            ${migration0025JournalRow.id},
            ${migration0025JournalRow.hash},
            ${migration0025Entry.when}
          )
          ON CONFLICT (id) DO UPDATE
          SET hash = EXCLUDED.hash,
              created_at = EXCLUDED.created_at
        `;
      },
      "0025 deletion checks and journal restoration both failed",
    );

    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "restoring 0025 did not restore the exact current journal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      phase0025Manifest,
      "restoring 0025 did not restore the sealed predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility"),
      failClosedCompatibility,
      "restoring 0025 changed the retired legacy projection",
    );

    await migrate(drizzle(client), { migrationsFolder: phase0029 });
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      phase0029Manifest,
      "raw 0029 v4 projection does not expose the complete 30-row journal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      failClosedCompatibility,
      "raw 0029 unexpectedly enabled the unsealed v3 predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      failClosedCompatibility,
      "raw 0029 unexpectedly revived the retired v2 projection",
    );

    await sealCompatibility(client, phase0029Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      phase0029Manifest,
      "canonical 0029 seal did not preserve the exact current projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "canonical 0029 seal did not expose the exact 27-row rolling predecessor",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v2"),
      failClosedCompatibility,
      "canonical 0029 seal revived an unsupported two-release-old projection",
    );

    const migration0028Entry = journal.entries[28];
    assert(migration0028Entry);
    const [migration0028JournalRow] = await client<
      { id: number; hash: string }[]
    >`
      SELECT id, hash::text
      FROM drizzle.__drizzle_migrations
      WHERE created_at = ${migration0028Entry.when}
    `;
    assert(migration0028JournalRow);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"0".repeat(64)}
          WHERE id = ${migration0028JournalRow.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility_v4"),
          phase0029Manifest,
          "v4 readiness accepted a divergent operator-team migration",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v3"),
          failClosedCompatibility,
          "the rolling predecessor accepted a divergent 30-row journal",
        );
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted a divergent 0028 hash",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0029Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the v4 seal accepted a divergent operator-team migration",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${migration0028JournalRow.hash}
          WHERE id = ${migration0028JournalRow.id}
        `;
      },
      "0028 rolling-upgrade drift checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0029Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      phase0029Manifest,
      "restoring and resealing 0028 did not recover v4 readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      phase0026Manifest,
      "restoring and resealing 0028 did not recover rolling predecessor readiness",
    );

    await client`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES (
        ${fixture.preHardeningOperatorTeam}::uuid,
        'upgrade_pre_hardening_team',
        'Pre-hardening operator team',
        'Strong ETag rolling invalidation proof.',
        ${fixture.legacyInitializedUser}::uuid
      )
    `;
    await client`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason
      ) VALUES (
        ${fixture.preHardeningAssignment}::uuid,
        ${fixture.legacyInitializedTenant}::uuid,
        ${fixture.preHardeningOperatorTeam}::uuid,
        ${fixture.legacyInitializedMembership}::uuid,
        'Strong ETag rolling invalidation proof.'
      )
    `;
    const [preHardeningVersions] = await client<
      { team_version: number; assignment_version: number }[]
    >`
      SELECT team.version AS team_version,
             assignment.version AS assignment_version
      FROM public.operator_teams AS team
      JOIN public.operator_team_assignment_epochs AS assignment
        ON assignment.operator_team_id = team.id
      WHERE team.id = ${fixture.preHardeningOperatorTeam}::uuid
        AND assignment.id = ${fixture.preHardeningAssignment}::uuid
    `;
    assert.deepEqual(preHardeningVersions, {
      team_version: 1,
      assignment_version: 1,
    });

    await migrate(drizzle(client), { migrationsFolder: phase0032 });
    const [invalidatedVersions] = await client<
      { team_version: number; assignment_version: number }[]
    >`
      SELECT team.version AS team_version,
             assignment.version AS assignment_version
      FROM public.operator_teams AS team
      JOIN public.operator_team_assignment_epochs AS assignment
        ON assignment.operator_team_id = team.id
      WHERE team.id = ${fixture.preHardeningOperatorTeam}::uuid
        AND assignment.id = ${fixture.preHardeningAssignment}::uuid
    `;
    assert.deepEqual(invalidatedVersions, {
      team_version: 2,
      assignment_version: 2,
    });

    // Simulate an already-entered v4 metadata body by updating the team row
    // directly. The 0031 table trigger must still advance the nested
    // assignment representation exactly once.
    await client`
      UPDATE public.operator_teams
      SET display_name = 'Crossing old-body operator team',
          version = version + 1,
          updated_at = transaction_timestamp()
      WHERE id = ${fixture.preHardeningOperatorTeam}::uuid
    `;
    const [crossingWriterVersions] = await client<
      { team_version: number; assignment_version: number }[]
    >`
      SELECT team.version AS team_version,
             assignment.version AS assignment_version
      FROM public.operator_teams AS team
      JOIN public.operator_team_assignment_epochs AS assignment
        ON assignment.operator_team_id = team.id
      WHERE team.id = ${fixture.preHardeningOperatorTeam}::uuid
        AND assignment.id = ${fixture.preHardeningAssignment}::uuid
    `;
    assert.deepEqual(crossingWriterVersions, {
      team_version: 3,
      assignment_version: 3,
    });

    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "raw 0032 v5 projection does not expose the complete 33-row journal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      failClosedCompatibility,
      "raw 0032 unexpectedly enabled the unsealed v4 predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      failClosedCompatibility,
      "raw 0032 unexpectedly revived the retired v3 projection",
    );

    await sealCompatibility(client, phase0032Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "canonical 0032 seal did not preserve the exact current projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      phase0029Manifest,
      "canonical 0032 seal did not expose the exact 30-row rolling predecessor",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v3"),
      failClosedCompatibility,
      "canonical 0032 seal revived an unsupported two-release-old projection",
    );

    const migration0031Entry = journal.entries[31];
    assert(migration0031Entry);
    const [migration0031JournalRow] = await client<
      { id: number; hash: string }[]
    >`
      SELECT id, hash::text
      FROM drizzle.__drizzle_migrations
      WHERE created_at = ${migration0031Entry.when}
    `;
    assert(migration0031JournalRow);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"f".repeat(64)}
          WHERE id = ${migration0031JournalRow.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility_v5"),
          phase0032Manifest,
          "v5 readiness accepted a divergent hardening migration",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v4"),
          failClosedCompatibility,
          "the rolling predecessor accepted a divergent 33-row journal",
        );
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted a divergent 0031 hash",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0032Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the v5 seal accepted a divergent hardening migration",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${migration0031JournalRow.hash}
          WHERE id = ${migration0031JournalRow.id}
        `;
      },
      "0031 readiness drift checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0032Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "restoring and resealing 0031 did not recover v5 readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      phase0029Manifest,
      "restoring and resealing 0031 did not recover rolling predecessor readiness",
    );

    await migrate(drizzle(client), { migrationsFolder: phase0038 });
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0038Manifest,
      "raw 0038 v6 projection does not expose the complete 39-row journal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      failClosedCompatibility,
      "raw 0038 unexpectedly enabled the unsealed v5 predecessor projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      failClosedCompatibility,
      "raw 0038 unexpectedly revived the retired v4 projection",
    );

    await sealCompatibility(client, phase0038Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0038Manifest,
      "canonical 0038 seal did not preserve the exact current projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "canonical 0038 seal did not expose the exact 33-row predecessor",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      failClosedCompatibility,
      "canonical 0038 seal revived an unsupported two-release-old projection",
    );

    await migrate(drizzle(client), { migrationsFolder: phase0039 });
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0039Manifest,
      "raw 0039 v6 projection does not expose the complete 40-row journal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      failClosedCompatibility,
      "raw 0039 unexpectedly retained the prior v5 seal",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      failClosedCompatibility,
      "raw 0039 unexpectedly revived the retired v4 projection",
    );

    await sealCompatibility(client, phase0039Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0039Manifest,
      "canonical 0039 seal did not preserve the exact current v6 projection",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "canonical 0039 seal did not expose the exact 33-row v5 predecessor",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v4"),
      failClosedCompatibility,
      "canonical 0039 seal revived an unsupported v4 projection",
    );

    const migration0038Entry = journal.entries[38];
    assert(migration0038Entry);
    const [migration0038JournalRow] = await client<
      { id: number; hash: string }[]
    >`
      SELECT id, hash::text
      FROM drizzle.__drizzle_migrations
      WHERE created_at = ${migration0038Entry.when}
    `;
    assert(migration0038JournalRow);
    await executeWithCleanup(
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${"e".repeat(64)}
          WHERE id = ${migration0038JournalRow.id}
        `;
        assert.notDeepEqual(
          await compatibility(client, "schema_compatibility_v6"),
          phase0039Manifest,
          "v6 readiness accepted a divergent 0038 migration hash",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v5"),
          failClosedCompatibility,
          "sealed v5 accepted a divergent 40-row journal",
        );
        await assert.rejects(
          async () => migrateSchema(client, migrationsRoot),
          (error) => hasErrorCode(error, "MIGRATION_JOURNAL_DIVERGED"),
          "canonical migration preflight accepted a divergent 0038 hash",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0039Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the v6 seal accepted a divergent 0038 hash",
        );
      },
      async () => {
        await client`
          UPDATE drizzle.__drizzle_migrations
          SET hash = ${migration0038JournalRow.hash}
          WHERE id = ${migration0038JournalRow.id}
        `;
      },
      "0038 readiness drift checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0039Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0039Manifest,
      "restoring and resealing 0038 did not recover v6 readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "restoring and resealing 0038 did not recover v5 predecessor readiness",
    );

    const migration0039Entry = journal.entries[39];
    assert(migration0039Entry);
    const [migration0039JournalRow] = await client<
      { id: number; hash: string }[]
    >`
      SELECT id, hash::text
      FROM drizzle.__drizzle_migrations
      WHERE created_at = ${migration0039Entry.when}
    `;
    assert(migration0039JournalRow);
    await executeWithCleanup(
      async () => {
        const deleted0039Rows = await client<{ id: number }[]>`
          DELETE FROM drizzle.__drizzle_migrations
          WHERE id = ${migration0039JournalRow.id}
          RETURNING id
        `;
        assert.deepEqual(Array.from(deleted0039Rows), [
          { id: migration0039JournalRow.id },
        ]);
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v6"),
          failClosedCompatibility,
          "v6 readiness exposed a truncated 39-row journal",
        );
        assert.deepEqual(
          await compatibility(client, "schema_compatibility_v5"),
          failClosedCompatibility,
          "sealed v5 exposed its predecessor after deleting 0039",
        );
        await assert.rejects(
          async () => sealCompatibility(client, phase0039Manifest),
          (error) => hasErrorCode(error, "55000"),
          "the v6 seal accepted a journal with 0039 deleted",
        );
      },
      async () => {
        await client`
          INSERT INTO drizzle.__drizzle_migrations (id, hash, created_at)
          VALUES (
            ${migration0039JournalRow.id},
            ${migration0039JournalRow.hash},
            ${migration0039Entry.when}
          )
          ON CONFLICT (id) DO UPDATE
          SET hash = EXCLUDED.hash,
              created_at = EXCLUDED.created_at
        `;
      },
      "0039 truncation checks and journal restoration both failed",
    );

    await sealCompatibility(client, phase0039Manifest);
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v6"),
      phase0039Manifest,
      "restoring and resealing 0039 did not recover v6 readiness",
    );
    assert.deepEqual(
      await compatibility(client, "schema_compatibility_v5"),
      phase0032Manifest,
      "restoring and resealing 0039 did not recover v5 predecessor readiness",
    );
  },
  () =>
    executeWithCleanup(
      async () => {
        await closeClient?.();
      },
      async () => {
        const cleanupResults = await Promise.allSettled(
          stageRoots.map((path) => rm(path, { recursive: true, force: true })),
        );
        const cleanupErrors = cleanupResults.flatMap((result) =>
          result.status === "rejected" ? [result.reason] : [],
        );
        if (cleanupErrors.length === 1) {
          throw cleanupErrors[0];
        }
        if (cleanupErrors.length > 1) {
          throw new AggregateError(
            cleanupErrors,
            "multiple staged migration directories could not be removed",
            { cause: cleanupErrors.at(-1) },
          );
        }
      },
      "database client and staged migration cleanup both failed",
    ),
  "authorization upgrade and resource cleanup both failed",
);
process.stdout.write(
  "authorization 0025 upgrade, 0026 v3 to 0029 v4 to 0032 v5 to 0038/0039 v6 rolling readiness, sealed predecessor recovery, drift/truncation rejection, and sealed audit backfill checks passed\n",
);
