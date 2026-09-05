import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";

type ErrorWithCode = Error & { code?: string };
type MutationResult = {
  result_resource_id: string;
  result_version: number;
  replayed: boolean;
};
type RolePath = {
  path_type: string;
  effective_expires_at: Date | string | null;
  role_id: string;
  role_source_id: string;
  role_source_kind: string;
  role_source_authoritative: boolean;
  role_source_retired_at: Date | string | null;
  group_id: string | null;
  group_membership_id: string | null;
  membership_source_id: string | null;
  membership_source_kind: string | null;
  membership_source_authoritative: boolean | null;
  membership_source_retired_at: Date | string | null;
};

const fixture = {
  tenant: "01993eb0-5000-7000-8000-000000000001",
  foreignTenant: "01993eb0-5000-7000-8000-000000000002",
  adminUser: "01993eb0-5000-7000-8000-000000000101",
  targetUser: "01993eb0-5000-7000-8000-000000000102",
  limitedUser: "01993eb0-5000-7000-8000-000000000103",
  limitedSession: "01993eb0-5000-7000-8000-000000000113",
  limitedSessionFamily: "01993eb0-5000-7000-8000-000000000123",
  sourceUser: "01993eb0-5000-7000-8000-000000000104",
  foreignUser: "01993eb0-5000-7000-8000-000000000105",
  adminMembership: "01993eb0-5000-7000-8000-000000000201",
  targetMembership: "01993eb0-5000-7000-8000-000000000202",
  limitedMembership: "01993eb0-5000-7000-8000-000000000203",
  sourceMembership: "01993eb0-5000-7000-8000-000000000204",
  foreignMembership: "01993eb0-5000-7000-8000-000000000205",
  group: "01993eb0-5000-7000-8000-000000000301",
  replayGroup: "01993eb0-5000-7000-8000-000000000302",
  rollbackGroup: "01993eb0-5000-7000-8000-000000000303",
  cleanupGroup: "01993eb0-5000-7000-8000-000000000304",
  foreignGroup: "01993eb0-5000-7000-8000-000000000305",
  externalManualGroup: "01993eb0-5000-7000-8000-000000000306",
  targetRole: "01993eb0-5000-7000-8000-000000000311",
  delegatorRole: "01993eb0-5000-7000-8000-000000000312",
  legacyAdminRole: "01993eb0-5000-7000-8000-000000000313",
  groupMembership: "01993eb0-5000-7000-8000-000000000401",
  identityMembership: "01993eb0-5000-7000-8000-000000000402",
  foreignGroupMembership: "01993eb0-5000-7000-8000-000000000403",
  replayMembership: "01993eb0-5000-7000-8000-000000000404",
  replayMembershipAttempt: "01993eb0-5000-7000-8000-000000000405",
  externalManualMembership: "01993eb0-5000-7000-8000-000000000406",
  adminGroupGrant: "01993eb0-5000-7000-8000-000000000411",
  targetGroupGrant: "01993eb0-5000-7000-8000-000000000412",
  cleanupGroupGrant: "01993eb0-5000-7000-8000-000000000413",
  externalManualGroupGrant: "01993eb0-5000-7000-8000-000000000415",
  limitedDirectGrant: "01993eb0-5000-7000-8000-000000000421",
  targetDirectGrant: "01993eb0-5000-7000-8000-000000000422",
  identitySource: "01993eb0-5000-7000-8000-000000000431",
  externalManualSource: "01993eb0-5000-7000-8000-000000000432",
} as const;

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

function asMillis(value: Date | string | null): number | null {
  if (value === null) {
    return null;
  }
  return value instanceof Date ? value.getTime() : new Date(value).getTime();
}

function withTimeout<T>(promise: Promise<T>, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), 10_000);
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

async function setApiContext(
  transaction: postgres.TransactionSql,
  userID: string,
  tenantID = fixture.tenant,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantID}, true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function backendPID(
  transaction: postgres.TransactionSql,
): Promise<number> {
  const [backend] = await transaction<{ pid: number }[]>`
    SELECT pg_catalog.pg_backend_pid() AS pid
  `;
  assert(backend, "transaction has no PostgreSQL backend PID");
  return backend.pid;
}

async function waitForRowLock(sql: Sql, processID: number): Promise<void> {
  const deadline = Date.now() + 10_000;
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
      throw new Error("group authority contender did not wait on a lock");
    }
    await delay(20);
    return poll();
  };
  return poll();
}

async function createGroup(
  transaction: postgres.TransactionSql,
  groupID: string,
  digestByte: number,
  key: string,
  name: string,
  auditEventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.create_tenant_security_group(
      ${groupID}::uuid,
      ${Buffer.alloc(32, digestByte)}::bytea,
      ${key}, ${name}, 'Executable tenant security-group proof.',
      ${auditEventID}::uuid,
      '01993eb0-5000-7000-8000-000000000601'::uuid,
      '01993eb0-5000-7000-8000-000000000701'::uuid,
      '192.0.2.60'::inet,
      'Periapsis security-group concurrency proof', 'totp'
    )
  `;
  assert(result, "create_tenant_security_group returned no result");
  return result;
}

async function addGroupMember(
  transaction: postgres.TransactionSql,
  edgeID: string,
  digestByte: number,
  targetUserID: string,
  expiresAt: Date | null,
  auditEventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.add_tenant_security_group_member(
      ${edgeID}::uuid,
      ${Buffer.alloc(32, digestByte)}::bytea,
      ${fixture.group}::uuid, ${targetUserID}::uuid,
      'Concurrent group membership proof.', ${expiresAt}::timestamptz,
      ${auditEventID}::uuid,
      '01993eb0-5000-7000-8000-000000000602'::uuid,
      '01993eb0-5000-7000-8000-000000000702'::uuid,
      '192.0.2.60'::inet,
      'Periapsis security-group concurrency proof', 'totp'
    )
  `;
  assert(result, "add_tenant_security_group_member returned no result");
  return result;
}

async function grantGroupRole(
  transaction: postgres.TransactionSql,
  grantID: string,
  digestByte: number,
  groupID: string,
  roleID: string,
  expiresAt: Date | null,
  auditEventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.grant_tenant_security_group_role(
      ${grantID}::uuid,
      ${Buffer.alloc(32, digestByte)}::bytea,
      ${groupID}::uuid, ${roleID}::uuid,
      'Executable group role grant proof.', ${expiresAt}::timestamptz,
      ${auditEventID}::uuid,
      '01993eb0-5000-7000-8000-000000000603'::uuid,
      '01993eb0-5000-7000-8000-000000000703'::uuid,
      '192.0.2.60'::inet,
      'Periapsis security-group concurrency proof', 'totp'
    )
  `;
  assert(result, "grant_tenant_security_group_role returned no result");
  return result;
}

async function grantDirectRole(
  transaction: postgres.TransactionSql,
  grantID: string,
  digestByte: number,
  targetUserID: string,
  roleID: string,
  expiresAt: Date | null,
  auditEventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.grant_tenant_user_role(
      ${grantID}::uuid,
      ${Buffer.alloc(32, digestByte)}::bytea,
      ${targetUserID}::uuid, ${roleID}::uuid,
      'Executable direct role grant proof.', ${expiresAt}::timestamptz,
      ${auditEventID}::uuid,
      '01993eb0-5000-7000-8000-000000000604'::uuid,
      '01993eb0-5000-7000-8000-000000000704'::uuid,
      '192.0.2.60'::inet,
      'Periapsis security-group concurrency proof', 'totp'
    )
  `;
  assert(result, "grant_tenant_user_role returned no result");
  return result;
}

async function currentRolePaths(
  sql: postgres.TransactionSql,
  userID: string,
): Promise<RolePath[]> {
  await setApiContext(sql, userID);
  return sql<RolePath[]>`
    SELECT * FROM app.resolve_current_tenant_human_role_grant_paths(201)
  `;
}

const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseURL, { max: 1, onnotice: () => undefined });
let releaseHeldTransaction: (() => void) | undefined;

const membershipExpiry = new Date(Date.now() + 60 * 60 * 1_000);
const limitedDelegationExpiry = new Date(Date.now() + 90 * 60 * 1_000);
const roleGrantExpiry = new Date(Date.now() + 120 * 60 * 1_000);

try {
  const existing = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenants
    WHERE id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
       OR slug IN ('security-group-concurrency', 'security-group-foreign')
  `;
  assert.equal(
    existing[0]?.count,
    0,
    "security-group proof requires a fresh disposable database",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.tenant}::uuid, 'security-group-concurrency', 'Security group concurrency proof'),
        (${fixture.foreignTenant}::uuid, 'security-group-foreign', 'Foreign security group proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.adminUser}::uuid, 'groups.admin@example.invalid', 'Group admin'),
        (${fixture.targetUser}::uuid, 'groups.target@example.invalid', 'Group target'),
        (${fixture.limitedUser}::uuid, 'groups.limited@example.invalid', 'Limited delegator'),
        (${fixture.sourceUser}::uuid, 'groups.source@example.invalid', 'Mapped source user'),
        (${fixture.foreignUser}::uuid, 'groups.foreign@example.invalid', 'Foreign group user')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      )
      VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.targetMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.targetUser}::uuid, 'analyst', 'active'),
        (${fixture.limitedMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.limitedUser}::uuid, 'analyst', 'active'),
        (${fixture.sourceMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.sourceUser}::uuid, 'analyst', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, last_seen_at,
        idle_expires_at, absolute_expires_at, created_at
      ) VALUES (
        ${fixture.limitedSession}::uuid, ${fixture.limitedUser}::uuid,
        ${fixture.limitedSessionFamily}::uuid, ${fixture.tenant}::uuid,
        ${Buffer.alloc(32, 0x91)}::bytea, ${Buffer.alloc(32, 0x92)}::bytea,
        'totp', date_trunc('milliseconds', transaction_timestamp()),
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '2 hours',
        date_trunc('milliseconds', transaction_timestamp())
      )
    `;

    const [foreignManualSource] = await transaction<{ id: string }[]>`
      SELECT id
      FROM public.tenant_authorization_sources
      WHERE tenant_id = ${fixture.foreignTenant}::uuid AND key = 'manual'
    `;
    assert(foreignManualSource, "foreign tenant manual source is missing");
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES (
        ${fixture.foreignGroup}::uuid, ${fixture.foreignTenant}::uuid,
        'foreign_group', 'Foreign group', 'Cross-tenant nested ID proof.',
        ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_group_memberships (
        id, tenant_id, group_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.foreignGroupMembership}::uuid,
        ${fixture.foreignTenant}::uuid, ${fixture.foreignGroup}::uuid,
        ${fixture.foreignMembership}::uuid, ${foreignManualSource.id}::uuid,
        ${fixture.foreignMembership}::uuid, 'Cross-tenant nested ID proof.'
      )
    `;
  });

  const [futureAdminRole] = await admin<
    {
      id: string;
      version: number;
      policy_count: number;
      catalog_count: number;
    }[]
  >`
    SELECT role.id, role.version,
           count(policy.permission_id)::integer AS policy_count,
           (SELECT count(*)::integer
            FROM public.tenant_permission_scopes) AS catalog_count
    FROM public.tenant_roles AS role
    JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
    WHERE role.tenant_id = ${fixture.tenant}::uuid AND role.key = 'tenant_admin'
    GROUP BY role.id, role.version
  `;
  assert(futureAdminRole, "future tenant_admin role is missing");
  assert.equal(futureAdminRole.version, 1);
  // Future tenant administrators receive the complete current permission
  // scope catalog. This assertion intentionally follows later vertical
  // slices instead of freezing the Phase 2B count in this runtime harness.
  assert.equal(futureAdminRole.policy_count, futureAdminRole.catalog_count);

  const [legacyAdminProjection] = await admin<
    { permission_keys: string[]; permission_scopes: string[] }[]
  >`
    SELECT array_agg(permission.key ORDER BY permission.key, policy.scope)
             AS permission_keys,
           array_agg(policy.scope::text ORDER BY permission.key, policy.scope)
             AS permission_scopes
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = ${fixture.tenant}::uuid
      AND policy.role_id = ${futureAdminRole.id}::uuid
      AND permission.key IN (
        'membership.manage',
        'permission.read',
        'role.grant',
        'role.manage',
        'role.read',
        'user.read',
        'group.read',
        'group.manage',
        'group.membership.manage',
        'operator_team.read',
        'operator_team.manage',
        'operator_team.roster.manage'
      )
  `;
  assert(legacyAdminProjection, "legacy administrator projection is missing");
  assert.equal(legacyAdminProjection.permission_keys.length, 14);
  const createdLegacyAdminRole = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<MutationResult[]>`
      SELECT *
      FROM app.create_tenant_role(
        ${fixture.legacyAdminRole}::uuid,
        ${Buffer.alloc(32, 0x74)}::bytea,
        'legacy_admin_projection',
        'Legacy administrator projection',
        'Human-only pre-ADR administrator policy used by compatibility tests.',
        ${legacyAdminProjection.permission_keys}::text[],
        ${legacyAdminProjection.permission_scopes}::public.authorization_scope[],
        ${legacyAdminProjection.permission_keys}::text[],
        ${legacyAdminProjection.permission_scopes}::public.authorization_scope[],
        '01993eb0-5000-7000-8000-000000000533'::uuid,
        '01993eb0-5000-7000-8000-000000000633'::uuid,
        '01993eb0-5000-7000-8000-000000000733'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof',
        'totp'
      )
    `;
    assert(result, "legacy administrator role creation returned no result");
    return result;
  });
  assert.deepEqual(createdLegacyAdminRole, {
    result_resource_id: fixture.legacyAdminRole,
    result_version: 1,
    replayed: false,
  });
  const legacyAdminRole = { id: createdLegacyAdminRole.result_resource_id };

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`SELECT count(*) FROM public.tenant_security_groups`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const createdGroup = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return createGroup(
      transaction,
      fixture.group,
      0x61,
      "incident_responders",
      "Incident responders",
      "01993eb0-5000-7000-8000-000000000501",
    );
  });
  assert.deepEqual(createdGroup, {
    result_resource_id: fixture.group,
    result_version: 1,
    replayed: false,
  });

  const replayedGroup = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return createGroup(
      transaction,
      fixture.replayGroup,
      0x61,
      "incident_responders",
      "Incident responders",
      "01993eb0-5000-7000-8000-000000000502",
    );
  });
  assert.deepEqual(replayedGroup, {
    result_resource_id: fixture.group,
    result_version: 1,
    replayed: true,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await createGroup(
        transaction,
        fixture.replayGroup,
        0x61,
        "incident_responders",
        "Changed replay payload",
        "01993eb0-5000-7000-8000-000000000503",
      );
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const replayMembershipExpiry = new Date(Date.now() + 3_000);
  const createdReplayMembership = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return addGroupMember(
      transaction,
      fixture.replayMembership,
      0x60,
      fixture.sourceUser,
      replayMembershipExpiry,
      "01993eb0-5000-7000-8000-000000000528",
    );
  });
  assert.deepEqual(createdReplayMembership, {
    result_resource_id: fixture.replayMembership,
    result_version: 1,
    replayed: false,
  });

  await delay(Math.max(0, replayMembershipExpiry.getTime() - Date.now() + 100));

  const replayedMembership = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return addGroupMember(
      transaction,
      fixture.replayMembershipAttempt,
      0x60,
      fixture.sourceUser,
      replayMembershipExpiry,
      "01993eb0-5000-7000-8000-000000000529",
    );
  });
  assert.deepEqual(replayedMembership, {
    result_resource_id: fixture.replayMembership,
    result_version: 1,
    replayed: true,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await addGroupMember(
        transaction,
        fixture.replayMembershipAttempt,
        0x60,
        fixture.targetUser,
        replayMembershipExpiry,
        "01993eb0-5000-7000-8000-000000000530",
      );
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.update_tenant_security_group_metadata(
          ${fixture.group}::uuid, 0, 'Stale name', NULL,
          '01993eb0-5000-7000-8000-000000000504'::uuid,
          '01993eb0-5000-7000-8000-000000000605'::uuid,
          '01993eb0-5000-7000-8000-000000000705'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await createGroup(
        transaction,
        fixture.rollbackGroup,
        0x63,
        "rollback_group",
        "Rollback group",
        "01993eb0-5000-7000-8000-000000000505",
      );
      await transaction.unsafe("SELECT 1 / 0");
    }),
    (error: unknown) => assertSqlState(error, "22012"),
  );
  const [rollbackState] = await admin<
    { groups: number; audits: number; commands: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_security_groups
       WHERE id = ${fixture.rollbackGroup}::uuid) AS groups,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id = '01993eb0-5000-7000-8000-000000000505'::uuid) AS audits,
      (SELECT count(*)::integer FROM public.tenant_authorization_commands
       WHERE result_resource_id = ${fixture.rollbackGroup}::uuid) AS commands
  `;
  assert.deepEqual(rollbackState, { groups: 0, audits: 0, commands: 0 });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await grantGroupRole(
        transaction,
        "01993eb0-5000-7000-8000-000000000414",
        0x64,
        fixture.group,
        legacyAdminRole.id,
        new Date(0),
        "01993eb0-5000-7000-8000-000000000506",
      );
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    await transaction`
      SELECT * FROM app.create_tenant_role(
        ${fixture.targetRole}::uuid, ${Buffer.alloc(32, 0x65)}::bytea,
        'group_reader', 'Group reader', 'Latent group-role horizon proof.',
        ARRAY['group.read']::text[],
        ARRAY['tenant']::public.authorization_scope[],
        ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
        '01993eb0-5000-7000-8000-000000000507'::uuid,
        '01993eb0-5000-7000-8000-000000000607'::uuid,
        '01993eb0-5000-7000-8000-000000000707'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      )
    `;
    await transaction`
      SELECT * FROM app.create_tenant_role(
        ${fixture.delegatorRole}::uuid, ${Buffer.alloc(32, 0x66)}::bytea,
        'bounded_delegator', 'Bounded delegator', 'Effective minimum horizon proof.',
        ARRAY[
          'membership.manage', 'permission.read', 'role.grant',
          'role.manage', 'role.read', 'user.read',
          'group.read', 'group.manage', 'group.membership.manage',
          'operator_team.manage',
          'operator_team.read', 'operator_team.read',
          'operator_team.roster.manage', 'operator_team.roster.manage'
        ]::text[],
        ARRAY[
          'tenant', 'tenant', 'tenant', 'tenant', 'tenant', 'tenant',
          'tenant', 'tenant', 'tenant', 'tenant',
          'tenant', 'operator_team', 'tenant', 'operator_team'
        ]::public.authorization_scope[],
        ARRAY[
          'membership.manage', 'permission.read', 'role.grant',
          'role.manage', 'role.read', 'user.read',
          'group.read', 'group.manage', 'group.membership.manage',
          'operator_team.manage',
          'operator_team.read', 'operator_team.read',
          'operator_team.roster.manage', 'operator_team.roster.manage'
        ]::text[],
        ARRAY[
          'tenant', 'tenant', 'tenant', 'tenant', 'tenant', 'tenant',
          'tenant', 'tenant', 'tenant', 'tenant',
          'tenant', 'operator_team', 'tenant', 'operator_team'
        ]::public.authorization_scope[],
        '01993eb0-5000-7000-8000-000000000508'::uuid,
        '01993eb0-5000-7000-8000-000000000608'::uuid,
        '01993eb0-5000-7000-8000-000000000708'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      )
    `;
    await grantDirectRole(
      transaction,
      fixture.limitedDirectGrant,
      0x67,
      fixture.limitedUser,
      fixture.delegatorRole,
      limitedDelegationExpiry,
      "01993eb0-5000-7000-8000-000000000509",
    );
  });

  const winnerReady = Promise.withResolvers<void>();
  const releaseWinner = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseWinner.resolve;
  const contenderPID = Promise.withResolvers<number>();

  const winnerMembership = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const result = await addGroupMember(
      transaction,
      fixture.groupMembership,
      0x62,
      fixture.targetUser,
      membershipExpiry,
      "01993eb0-5000-7000-8000-000000000510",
    );
    winnerReady.resolve();
    await releaseWinner.promise;
    return result;
  });
  const winnerOutcome = winnerMembership.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    winnerReady.promise,
    "group membership winner did not lock",
  );

  const contenderGrant = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    contenderPID.resolve(await backendPID(transaction));
    return grantGroupRole(
      transaction,
      fixture.adminGroupGrant,
      0x68,
      fixture.group,
      legacyAdminRole.id,
      roleGrantExpiry,
      "01993eb0-5000-7000-8000-000000000511",
    );
  });
  const contenderOutcome = contenderGrant.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );

  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        contenderPID.promise,
        "group role contender did not start",
      ),
    );
  } finally {
    releaseWinner.resolve();
    releaseHeldTransaction = undefined;
  }

  const memberResult = await withTimeout(
    winnerOutcome,
    "group membership winner did not commit",
  );
  const groupRoleResult = await withTimeout(
    contenderOutcome,
    "group role contender did not commit",
  );
  assert("result" in memberResult, "group membership winner failed");
  assert("result" in groupRoleResult, "group role contender failed");
  assert.equal(memberResult.result.result_resource_id, fixture.groupMembership);
  assert.equal(
    groupRoleResult.result.result_resource_id,
    fixture.adminGroupGrant,
  );

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    await grantGroupRole(
      transaction,
      fixture.targetGroupGrant,
      0x69,
      fixture.group,
      fixture.targetRole,
      roleGrantExpiry,
      "01993eb0-5000-7000-8000-000000000512",
    );
  });

  const targetPaths = await winner.begin(async (transaction) =>
    currentRolePaths(transaction, fixture.targetUser),
  );
  assert.equal(targetPaths.length, 2);
  for (const path of targetPaths) {
    assert.equal(path.path_type, "group");
    assert.equal(path.group_id, fixture.group);
    assert.equal(path.group_membership_id, fixture.groupMembership);
    assert.equal(path.role_source_kind, "manual");
    assert.equal(path.role_source_authoritative, false);
    assert.equal(path.role_source_retired_at, null);
    assert.equal(path.membership_source_kind, "manual");
    assert.equal(path.membership_source_authoritative, false);
    assert.equal(path.membership_source_retired_at, null);
    assert(path.role_source_id, "group role source is missing");
    assert(path.membership_source_id, "group membership source is missing");
    assert.equal(
      asMillis(path.effective_expires_at),
      membershipExpiry.getTime(),
    );
  }

  const targetAuthority = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.targetUser);
    const current = await transaction<
      { permission_key: string; scope: string }[]
    >`
      SELECT permission_key, scope
      FROM app.resolve_current_tenant_human_authority_v2(501)
    `;
    const legacy = await transaction<
      { permission_key: string; scope: string }[]
    >`
      SELECT permission_key, scope
      FROM app.resolve_current_tenant_human_authority(501)
    `;
    return { current, legacy };
  });
  assert.equal(targetAuthority.current.length, 14);
  assert.equal(
    new Set(targetAuthority.current.map((row) => row.permission_key)).size,
    12,
  );
  assert.equal(
    targetAuthority.current.filter((row) =>
      row.permission_key.startsWith("operator_team."),
    ).length,
    5,
  );
  assert.equal(targetAuthority.legacy.length, 9);
  assert(
    targetAuthority.legacy.every(
      (row) => !row.permission_key.startsWith("operator_team."),
    ),
  );

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.limitedUser);
    await transaction`
      SELECT *
      FROM app.change_tenant_membership_lifecycle_v1(
        ${fixture.limitedSession}::uuid, ${fixture.targetUser}::uuid,
        'suspended'::public.membership_status, 1,
        'Suspend membership for the group authority consequence proof.',
        ${Buffer.alloc(32, 0x93)}::bytea,
        '01993eb0-5000-7000-8000-000000000513'::uuid,
        '01993eb0-5000-7000-8000-000000000613'::uuid,
        '01993eb0-5000-7000-8000-000000000713'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      )
    `;
  });
  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.limitedUser);
    await transaction`
      SELECT *
      FROM app.change_tenant_membership_lifecycle_v1(
        ${fixture.limitedSession}::uuid, ${fixture.targetUser}::uuid,
        'active'::public.membership_status, 2,
        'Reactivate membership after the group authority consequence proof.',
        ${Buffer.alloc(32, 0x94)}::bytea,
        '01993eb0-5000-7000-8000-000000000514'::uuid,
        '01993eb0-5000-7000-8000-000000000614'::uuid,
        '01993eb0-5000-7000-8000-000000000714'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      )
    `;
  });

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.limitedUser);
    const [policy] = await transaction<{ version: number }[]>`
      SELECT app.replace_tenant_role_policy(
        ${fixture.targetRole}::uuid, 1,
        ARRAY['group.read']::text[],
        ARRAY['tenant']::public.authorization_scope[],
        ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
        '01993eb0-5000-7000-8000-000000000515'::uuid,
        '01993eb0-5000-7000-8000-000000000615'::uuid,
        '01993eb0-5000-7000-8000-000000000715'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(policy?.version, 2);
  });

  const [boundedPolicyState] = await admin<
    { version: number; audits: number }[]
  >`
    SELECT role.version,
           (SELECT count(*)::integer FROM public.audit_events
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND id = '01993eb0-5000-7000-8000-000000000515'::uuid) AS audits
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = ${fixture.tenant}::uuid
      AND role.id = ${fixture.targetRole}::uuid
  `;
  assert.deepEqual(boundedPolicyState, { version: 2, audits: 1 });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      await transaction`
        UPDATE public.tenant_memberships AS membership
        SET status = 'suspended'::public.membership_status,
            updated_at = transaction_timestamp()
        WHERE membership.tenant_id = ${fixture.tenant}::uuid
          AND membership.user_id = ${fixture.adminUser}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "23514"),
  );

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    await grantDirectRole(
      transaction,
      fixture.targetDirectGrant,
      0x6a,
      fixture.targetUser,
      legacyAdminRole.id,
      null,
      "01993eb0-5000-7000-8000-000000000517",
    );
  });
  const duplicateAdminPaths = await winner.begin(async (transaction) => {
    const paths = await currentRolePaths(transaction, fixture.targetUser);
    return paths.filter((path) => path.role_id === legacyAdminRole.id);
  });
  assert.deepEqual(
    duplicateAdminPaths.map((path) => path.path_type).toSorted(),
    ["direct", "group"],
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.identitySource}::uuid, ${fixture.tenant}::uuid,
        'identity_mapping', 'oidc:security-group-proof', true, false
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_group_memberships (
        id, tenant_id, group_id, membership_id, source_id, grant_reason
      ) VALUES (
        ${fixture.identityMembership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.group}::uuid, ${fixture.sourceMembership}::uuid,
        ${fixture.identitySource}::uuid, 'Authoritative source retirement proof.'
      )
    `;
  });
  const mappedPaths = await winner.begin(async (transaction) =>
    currentRolePaths(transaction, fixture.sourceUser),
  );
  assert.equal(mappedPaths.length, 2);
  assert(
    mappedPaths.every(
      (path) => path.membership_source_kind === "identity_mapping",
    ),
  );
  assert(mappedPaths.every((path) => path.membership_source_authoritative));

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.limitedUser);
      await transaction`
        SELECT app.replace_tenant_role_policy(
          ${fixture.targetRole}::uuid, 2,
          ARRAY['group.read']::text[],
          ARRAY['tenant']::public.authorization_scope[],
          ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
          '01993eb0-5000-7000-8000-000000000532'::uuid,
          '01993eb0-5000-7000-8000-000000000632'::uuid,
          '01993eb0-5000-7000-8000-000000000732'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const [unboundedPolicyState] = await admin<
    { version: number; rejected_audits: number }[]
  >`
    SELECT role.version,
           (SELECT count(*)::integer FROM public.audit_events
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND id = '01993eb0-5000-7000-8000-000000000532'::uuid)
             AS rejected_audits
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = ${fixture.tenant}::uuid
      AND role.id = ${fixture.targetRole}::uuid
  `;
  assert.deepEqual(unboundedPolicyState, {
    version: 2,
    rejected_audits: 0,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.revoke_tenant_security_group_membership(
          ${fixture.group}::uuid, ${fixture.identityMembership}::uuid, 1,
          'Wrong source owner proof.',
          '01993eb0-5000-7000-8000-000000000518'::uuid,
          '01993eb0-5000-7000-8000-000000000618'::uuid,
          '01993eb0-5000-7000-8000-000000000718'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_authorization_sources
      SET retired_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.identitySource}::uuid
    `;
  });
  const retiredPaths = await winner.begin(async (transaction) =>
    currentRolePaths(transaction, fixture.sourceUser),
  );
  assert.equal(retiredPaths.length, 0);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT * FROM app.get_tenant_security_group_membership(
          ${fixture.group}::uuid, ${fixture.foreignGroupMembership}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.revoke_tenant_security_group_membership(
          ${fixture.group}::uuid, ${fixture.foreignGroupMembership}::uuid, 1,
          'Cross-tenant nested ID proof.',
          '01993eb0-5000-7000-8000-000000000519'::uuid,
          '01993eb0-5000-7000-8000-000000000619'::uuid,
          '01993eb0-5000-7000-8000-000000000719'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [archivedVersion] = await transaction<{ version: number }[]>`
      SELECT app.archive_tenant_role(
        ${fixture.targetRole}::uuid, 2,
        '01993eb0-5000-7000-8000-000000000520'::uuid,
        '01993eb0-5000-7000-8000-000000000620'::uuid,
        '01993eb0-5000-7000-8000-000000000720'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(archivedVersion?.version, 3);
    const [revokedVersion] = await transaction<{ version: number }[]>`
      SELECT app.revoke_tenant_security_group_role_grant(
        ${fixture.group}::uuid, ${fixture.targetGroupGrant}::uuid, 1,
        'Archived role cleanup proof.',
        '01993eb0-5000-7000-8000-000000000521'::uuid,
        '01993eb0-5000-7000-8000-000000000621'::uuid,
        '01993eb0-5000-7000-8000-000000000721'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(revokedVersion?.version, 2);
  });

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    await createGroup(
      transaction,
      fixture.cleanupGroup,
      0x6b,
      "cleanup_group",
      "Cleanup group",
      "01993eb0-5000-7000-8000-000000000522",
    );
    await grantGroupRole(
      transaction,
      fixture.cleanupGroupGrant,
      0x6c,
      fixture.cleanupGroup,
      fixture.delegatorRole,
      roleGrantExpiry,
      "01993eb0-5000-7000-8000-000000000523",
    );
    const [archivedVersion] = await transaction<{ version: number }[]>`
      SELECT app.archive_tenant_security_group(
        ${fixture.cleanupGroup}::uuid, 1,
        '01993eb0-5000-7000-8000-000000000524'::uuid,
        '01993eb0-5000-7000-8000-000000000624'::uuid,
        '01993eb0-5000-7000-8000-000000000724'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(archivedVersion?.version, 2);
    const [revokedVersion] = await transaction<{ version: number }[]>`
      SELECT app.revoke_tenant_security_group_role_grant(
        ${fixture.cleanupGroup}::uuid, ${fixture.cleanupGroupGrant}::uuid, 1,
        'Archived group cleanup proof.',
        '01993eb0-5000-7000-8000-000000000525'::uuid,
        '01993eb0-5000-7000-8000-000000000625'::uuid,
        '01993eb0-5000-7000-8000-000000000725'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(revokedVersion?.version, 2);
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.revoke_tenant_security_group_membership(
          ${fixture.group}::uuid, ${fixture.groupMembership}::uuid, 0,
          'Stale membership version proof.',
          '01993eb0-5000-7000-8000-000000000526'::uuid,
          '01993eb0-5000-7000-8000-000000000626'::uuid,
          '01993eb0-5000-7000-8000-000000000726'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [revokedVersion] = await transaction<{ version: number }[]>`
      SELECT app.revoke_tenant_security_group_membership(
        ${fixture.group}::uuid, ${fixture.groupMembership}::uuid, 1,
        'Immediate group authority revocation proof.',
        '01993eb0-5000-7000-8000-000000000527'::uuid,
        '01993eb0-5000-7000-8000-000000000627'::uuid,
        '01993eb0-5000-7000-8000-000000000727'::uuid,
        '192.0.2.60'::inet,
        'Periapsis security-group concurrency proof', 'totp'
      ) AS version
    `;
    assert.equal(revokedVersion?.version, 2);
  });
  const postRevokePaths = await winner.begin(async (transaction) =>
    currentRolePaths(transaction, fixture.targetUser),
  );
  assert.equal(
    postRevokePaths.filter((path) => path.path_type === "group").length,
    0,
  );
  assert.equal(
    postRevokePaths.filter((path) => path.path_type === "direct").length,
    1,
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.externalManualSource}::uuid, ${fixture.tenant}::uuid,
        'manual', 'manual.external', false, true
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id, tenant_id, key, display_name, description,
        created_by_membership_id
      ) VALUES (
        ${fixture.externalManualGroup}::uuid, ${fixture.tenant}::uuid,
        'external_manual_group', 'External manual group',
        'Exact mutation ownership proof.', ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_group_memberships (
        id, tenant_id, group_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.externalManualMembership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.externalManualGroup}::uuid, ${fixture.targetMembership}::uuid,
        ${fixture.externalManualSource}::uuid, ${fixture.adminMembership}::uuid,
        'External manual membership proof.'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_group_role_grants (
        id, tenant_id, group_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.externalManualGroupGrant}::uuid, ${fixture.tenant}::uuid,
        ${fixture.externalManualGroup}::uuid, ${legacyAdminRole.id}::uuid,
        ${fixture.externalManualSource}::uuid, ${fixture.adminMembership}::uuid,
        'External manual group role proof.'
      )
    `;
  });

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [legacyMembership] = await transaction<{ source_kind: string }[]>`
      SELECT source_kind
      FROM app.get_tenant_security_group_membership(
        ${fixture.externalManualGroup}::uuid,
        ${fixture.externalManualMembership}::uuid
      )
    `;
    assert.equal(legacyMembership?.source_kind, "manual");

    const [canonicalMembership] = await transaction<
      { managed_by_authorization_api: boolean }[]
    >`
      SELECT managed_by_authorization_api
      FROM app.get_tenant_security_group_membership_v2(
        ${fixture.group}::uuid, ${fixture.groupMembership}::uuid
      )
    `;
    assert.equal(canonicalMembership?.managed_by_authorization_api, true);
    const [externalMembership] = await transaction<
      { managed_by_authorization_api: boolean }[]
    >`
      SELECT managed_by_authorization_api
      FROM app.get_tenant_security_group_membership_v2(
        ${fixture.externalManualGroup}::uuid,
        ${fixture.externalManualMembership}::uuid
      )
    `;
    assert.equal(externalMembership?.managed_by_authorization_api, false);

    const [canonicalRoleGrant] = await transaction<
      { managed_by_authorization_api: boolean }[]
    >`
      SELECT managed_by_authorization_api
      FROM app.get_tenant_security_group_role_grant_v2(
        ${fixture.group}::uuid, ${fixture.targetGroupGrant}::uuid
      )
    `;
    assert.equal(canonicalRoleGrant?.managed_by_authorization_api, true);
    const [externalRoleGrant] = await transaction<
      { managed_by_authorization_api: boolean }[]
    >`
      SELECT managed_by_authorization_api
      FROM app.get_tenant_security_group_role_grant_v2(
        ${fixture.externalManualGroup}::uuid,
        ${fixture.externalManualGroupGrant}::uuid
      )
    `;
    assert.equal(externalRoleGrant?.managed_by_authorization_api, false);
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.revoke_tenant_security_group_membership(
          ${fixture.externalManualGroup}::uuid,
          ${fixture.externalManualMembership}::uuid, 1,
          'Reject external manual membership mutation.',
          '01993eb0-5000-7000-8000-000000000530'::uuid,
          '01993eb0-5000-7000-8000-000000000630'::uuid,
          '01993eb0-5000-7000-8000-000000000730'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.revoke_tenant_security_group_role_grant(
          ${fixture.externalManualGroup}::uuid,
          ${fixture.externalManualGroupGrant}::uuid, 1,
          'Reject external manual group role mutation.',
          '01993eb0-5000-7000-8000-000000000531'::uuid,
          '01993eb0-5000-7000-8000-000000000631'::uuid,
          '01993eb0-5000-7000-8000-000000000731'::uuid,
          '192.0.2.60'::inet,
          'Periapsis security-group concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  const [externalMutationState] = await admin<
    { membership_version: number; grant_version: number; audits: number }[]
  >`
    SELECT
      (SELECT version FROM public.tenant_security_group_memberships
       WHERE id = ${fixture.externalManualMembership}::uuid) AS membership_version,
      (SELECT version FROM public.tenant_security_group_role_grants
       WHERE id = ${fixture.externalManualGroupGrant}::uuid) AS grant_version,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id IN (
         '01993eb0-5000-7000-8000-000000000530'::uuid,
         '01993eb0-5000-7000-8000-000000000531'::uuid
       )) AS audits
  `;
  assert.deepEqual(externalMutationState, {
    membership_version: 1,
    grant_version: 1,
    audits: 0,
  });

  const [auditState] = await admin<
    { mutation_count: number; rolled_back: number; stale: number }[]
  >`
    SELECT
      count(*) FILTER (WHERE action LIKE 'tenant.security_group.%')::integer AS mutation_count,
      count(*) FILTER (WHERE id = '01993eb0-5000-7000-8000-000000000505'::uuid)::integer AS rolled_back,
      count(*) FILTER (WHERE id IN (
        '01993eb0-5000-7000-8000-000000000504'::uuid,
        '01993eb0-5000-7000-8000-000000000526'::uuid
      ))::integer AS stale
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
  `;
  assert(auditState && auditState.mutation_count >= 10);
  assert.equal(auditState.rolled_back, 0);
  assert.equal(auditState.stale, 0);

  process.stdout.write(
    "tenant security-group RLS, provenance, lifetime, rollback, and concurrency checks passed\n",
  );
} finally {
  releaseHeldTransaction?.();
  await Promise.allSettled([admin.end(), winner.end(), contender.end()]);
}
