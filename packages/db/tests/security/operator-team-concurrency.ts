import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";

type ErrorWithCode = Error & { code?: string; constraint_name?: string };
type MutationResult = {
  result_resource_id: string;
  result_version: number;
  replayed: boolean;
};

const fixture = {
  tenant: "01993ec5-7000-7000-8000-000000000001",
  foreignTenant: "01993ec5-7000-7000-8000-000000000002",
  adminUser: "01993ec5-7000-7000-8000-000000000101",
  adminSession: "01993ec5-7000-7000-8000-000000000111",
  adminSessionFamily: "01993ec5-7000-7000-8000-000000000121",
  readerUser: "01993ec5-7000-7000-8000-000000000102",
  inactiveUser: "01993ec5-7000-7000-8000-000000000103",
  targetUser: "01993ec5-7000-7000-8000-000000000104",
  limitedUser: "01993ec5-7000-7000-8000-000000000105",
  sourceUser: "01993ec5-7000-7000-8000-000000000106",
  foreignUser: "01993ec5-7000-7000-8000-000000000107",
  managerOnlyUser: "01993ec5-7000-7000-8000-000000000108",
  adminMembership: "01993ec5-7000-7000-8000-000000000201",
  targetMembership: "01993ec5-7000-7000-8000-000000000202",
  limitedMembership: "01993ec5-7000-7000-8000-000000000203",
  sourceMembership: "01993ec5-7000-7000-8000-000000000204",
  foreignMembership: "01993ec5-7000-7000-8000-000000000205",
  managerOnlyMembership: "01993ec5-7000-7000-8000-000000000206",
  platformManagerRole: "01993ec5-7000-7000-8000-000000000301",
  platformReaderRole: "01993ec5-7000-7000-8000-000000000302",
  adminPlatformRole: "01993ec5-7000-7000-8000-000000000311",
  readerPlatformRole: "01993ec5-7000-7000-8000-000000000312",
  inactivePlatformRole: "01993ec5-7000-7000-8000-000000000313",
  targetRole: "01993ec5-7000-7000-8000-000000000321",
  limitedRole: "01993ec5-7000-7000-8000-000000000322",
  managerOnlyRole: "01993ec5-7000-7000-8000-000000000323",
  targetRoleGrant: "01993ec5-7000-7000-8000-000000000331",
  limitedRoleGrant: "01993ec5-7000-7000-8000-000000000332",
  managerOnlyRoleGrant: "01993ec5-7000-7000-8000-000000000333",
  identitySource: "01993ec5-7000-7000-8000-000000000341",
  team: "01993ec5-7000-7000-8000-000000000401",
  replayTeamAttempt: "01993ec5-7000-7000-8000-000000000402",
  foreignTeam: "01993ec5-7000-7000-8000-000000000403",
  rollbackTeam: "01993ec5-7000-7000-8000-000000000404",
  endAddRaceTeam: "01993ec5-7000-7000-8000-000000000411",
  archiveStartRaceTeam: "01993ec5-7000-7000-8000-000000000413",
  capacitySecondTeam: "01993ec9-0002-7000-8000-000000000002",
  firstEpoch: "01993ec5-7000-7000-8000-000000000501",
  replayEpochAttempt: "01993ec5-7000-7000-8000-000000000502",
  duplicateEpochAttempt: "01993ec5-7000-7000-8000-000000000503",
  foreignEpoch: "01993ec5-7000-7000-8000-000000000504",
  rollbackEpoch: "01993ec5-7000-7000-8000-000000000505",
  secondEpoch: "01993ec5-7000-7000-8000-000000000506",
  endAddRaceEpoch: "01993ec5-7000-7000-8000-000000000511",
  archiveStartRaceEpoch: "01993ec5-7000-7000-8000-000000000513",
  capacitySecondEpoch: "01993eca-0002-7000-8000-000000000002",
  firstRoster: "01993ec5-7000-7000-8000-000000000601",
  replayRosterAttempt: "01993ec5-7000-7000-8000-000000000602",
  secondRoster: "01993ec5-7000-7000-8000-000000000603",
  secondEpochRoster: "01993ec5-7000-7000-8000-000000000604",
  lifetimeRoster: "01993ec5-7000-7000-8000-000000000605",
  identityRoster: "01993ec5-7000-7000-8000-000000000606",
  foreignRoster: "01993ec5-7000-7000-8000-000000000607",
  rollbackRoster: "01993ec5-7000-7000-8000-000000000608",
  endAddRaceRoster: "01993ec5-7000-7000-8000-000000000611",
  capacitySecondRoster: "01993ecb-0002-7000-8000-000000000002",
  platformCreateAudit: "01993ec5-7000-7000-8000-000000000701",
  platformReplayAudit: "01993ec5-7000-7000-8000-000000000702",
  platformDriftAudit: "01993ec5-7000-7000-8000-000000000703",
  foreignTeamCreateAudit: "01993ec5-7000-7000-8000-000000000704",
  rollbackTeamCreateAudit: "01993ec5-7000-7000-8000-000000000705",
  updateStaleAudit: "01993ec5-7000-7000-8000-000000000706",
  updateAudit: "01993ec5-7000-7000-8000-000000000707",
  archiveConflictAudit: "01993ec5-7000-7000-8000-000000000708",
  archiveStaleAudit: "01993ec5-7000-7000-8000-000000000709",
  archiveAudit: "01993ec5-7000-7000-8000-000000000710",
  firstStartTenantAudit: "01993ec5-7000-7000-8000-000000000711",
  firstStartPlatformAudit: "01993ec5-7000-7000-8000-000000000712",
  replayStartTenantAudit: "01993ec5-7000-7000-8000-000000000713",
  replayStartPlatformAudit: "01993ec5-7000-7000-8000-000000000714",
  driftStartTenantAudit: "01993ec5-7000-7000-8000-000000000715",
  driftStartPlatformAudit: "01993ec5-7000-7000-8000-000000000716",
  duplicateStartTenantAudit: "01993ec5-7000-7000-8000-000000000717",
  duplicateStartPlatformAudit: "01993ec5-7000-7000-8000-000000000718",
  foreignStartTenantAudit: "01993ec5-7000-7000-8000-000000000719",
  foreignStartPlatformAudit: "01993ec5-7000-7000-8000-000000000720",
  rollbackStartTenantAudit: "01993ec5-7000-7000-8000-000000000721",
  rollbackStartPlatformAudit: "01993ec5-7000-7000-8000-000000000722",
  foreignRosterAudit: "01993ec5-7000-7000-8000-000000000723",
  pastExpiryAudit: "01993ec5-7000-7000-8000-000000000724",
  firstRosterAudit: "01993ec5-7000-7000-8000-000000000725",
  replayRosterAudit: "01993ec5-7000-7000-8000-000000000726",
  driftRosterAudit: "01993ec5-7000-7000-8000-000000000727",
  staleRevokeAudit: "01993ec5-7000-7000-8000-000000000728",
  revokeAudit: "01993ec5-7000-7000-8000-000000000729",
  secondRosterAudit: "01993ec5-7000-7000-8000-000000000730",
  missingGrantTenantAudit: "01993ec5-7000-7000-8000-000000000731",
  missingGrantPlatformAudit: "01993ec5-7000-7000-8000-000000000732",
  consequenceTenantAudit: "01993ec5-7000-7000-8000-000000000733",
  consequencePlatformAudit: "01993ec5-7000-7000-8000-000000000734",
  firstEndTenantAudit: "01993ec5-7000-7000-8000-000000000735",
  firstEndPlatformAudit: "01993ec5-7000-7000-8000-000000000736",
  secondStartTenantAudit: "01993ec5-7000-7000-8000-000000000737",
  secondStartPlatformAudit: "01993ec5-7000-7000-8000-000000000738",
  secondEpochRosterAudit: "01993ec5-7000-7000-8000-000000000739",
  suspendMembershipAudit: "01993ec5-7000-7000-8000-000000000740",
  activateMembershipAudit: "01993ec5-7000-7000-8000-000000000741",
  lifetimeRosterAudit: "01993ec5-7000-7000-8000-000000000742",
  secondEndTenantAudit: "01993ec5-7000-7000-8000-000000000743",
  secondEndPlatformAudit: "01993ec5-7000-7000-8000-000000000744",
  representationUpdateAudit: "01993ec5-7000-7000-8000-000000000745",
  endAddRaceTenantAudit: "01993ec5-7000-7000-8000-000000000746",
  endAddRacePlatformAudit: "01993ec5-7000-7000-8000-000000000747",
  endAddRaceRosterAudit: "01993ec5-7000-7000-8000-000000000748",
  revokePolicyRaceAudit: "01993ec5-7000-7000-8000-000000000749",
  replacePolicyRaceAudit: "01993ec5-7000-7000-8000-000000000750",
  archiveStartRaceArchiveAudit: "01993ec5-7000-7000-8000-000000000751",
  archiveStartRaceTenantAudit: "01993ec5-7000-7000-8000-000000000752",
  archiveStartRacePlatformAudit: "01993ec5-7000-7000-8000-000000000753",
  platformRequest: "01993ec5-7000-7000-8000-000000000801",
  startRequest: "01993ec5-7000-7000-8000-000000000802",
  endRequest: "01993ec5-7000-7000-8000-000000000803",
  rosterRequest: "01993ec5-7000-7000-8000-000000000804",
  rollbackRequest: "01993ec5-7000-7000-8000-000000000805",
  platformCorrelation: "01993ec5-7000-7000-8000-000000000901",
  startCorrelation: "01993ec5-7000-7000-8000-000000000902",
  endCorrelation: "01993ec5-7000-7000-8000-000000000903",
  rosterCorrelation: "01993ec5-7000-7000-8000-000000000904",
  rollbackCorrelation: "01993ec5-7000-7000-8000-000000000905",
} as const;

const fixtureNames = {
  tenantSlug: "operator-team-concurrency-c6",
  foreignTenantSlug: "operator-team-foreign-c6",
  emailPattern: "operator-team-c6.%@example.invalid",
  platformManagerRole: "ot_live_manager_c6",
  platformReaderRole: "ot_live_reader_c6",
  targetRole: "ot_scoped_reader_c6",
  limitedRole: "ot_limited_manager_c6",
  managerOnlyRole: "ot_manager_only_c6",
  teamPattern: "live_operator_team_c6_%",
  primaryTeam: "live_operator_team_c6_primary",
  foreignTeam: "live_operator_team_c6_foreign",
  rollbackTeam: "live_operator_team_c6_rollback",
} as const;

function assertSqlState(
  error: unknown,
  expected: string,
  expectedConstraint?: string,
  expectedMessage?: RegExp,
): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  const sqlError = error as ErrorWithCode;
  assert.equal(sqlError.code, expected);
  if (expectedConstraint !== undefined) {
    assert.equal(sqlError.constraint_name, expectedConstraint);
  }
  if (expectedMessage !== undefined) {
    assert.match(sqlError.message, expectedMessage);
  }
  return true;
}

function withTimeout<T>(
  promise: Promise<T>,
  message: string,
  timeoutMilliseconds = 10_000,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(message)),
      timeoutMilliseconds,
    );
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
  tenantID: string = fixture.tenant,
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
      throw new Error("operator-team contender did not wait on a lock");
    }
    await delay(20);
    return poll();
  };
  return poll();
}

async function createTeam(
  transaction: postgres.TransactionSql,
  teamID: string,
  digestByte: number,
  key: string,
  displayName: string,
  auditID: string,
  authenticationMethod = "totp",
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.create_platform_operator_team(
      ${teamID}::uuid, ${Buffer.alloc(32, digestByte)}::bytea,
      ${key}, ${displayName}, 'Executable operator-team security proof.',
      ${auditID}::uuid, ${fixture.platformRequest}::uuid,
      ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
      'Periapsis operator-team concurrency proof', ${authenticationMethod}
    )
  `;
  assert(result, "create_platform_operator_team returned no result");
  return result;
}

async function startAssignment(
  transaction: postgres.TransactionSql,
  epochID: string,
  digestByte: number,
  teamID: string,
  reason: string,
  tenantAuditID: string,
  platformAuditID: string,
  requestID: string = fixture.startRequest,
  correlationID: string = fixture.startCorrelation,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.start_tenant_operator_team_assignment(
      ${epochID}::uuid, ${Buffer.alloc(32, digestByte)}::bytea,
      ${teamID}::uuid, ${reason}, ${tenantAuditID}::uuid,
      ${platformAuditID}::uuid, ${requestID}::uuid,
      ${correlationID}::uuid, '192.0.2.70'::inet,
      'Periapsis operator-team concurrency proof', 'totp'
    )
  `;
  assert(result, "start_tenant_operator_team_assignment returned no result");
  return result;
}

async function endAssignment(
  transaction: postgres.TransactionSql,
  teamID: string,
  epochID: string,
  expectedVersion: number,
  reason: string,
  tenantAuditID: string,
  platformAuditID: string,
): Promise<number> {
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.end_tenant_operator_team_assignment(
      ${teamID}::uuid, ${epochID}::uuid, ${expectedVersion}, ${reason},
      ${tenantAuditID}::uuid, ${platformAuditID}::uuid,
      ${fixture.endRequest}::uuid, ${fixture.endCorrelation}::uuid,
      '192.0.2.70'::inet, 'Periapsis operator-team concurrency proof', 'totp'
    ) AS version
  `;
  assert(result, "end_tenant_operator_team_assignment returned no result");
  return result.version;
}

async function addRosterEntry(
  transaction: postgres.TransactionSql,
  rosterID: string,
  digestByte: number,
  teamID: string,
  epochID: string,
  membershipID: string,
  reason: string,
  expiresAt: Date | null,
  auditID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.add_tenant_operator_team_roster_entry(
      ${rosterID}::uuid, ${Buffer.alloc(32, digestByte)}::bytea,
      ${teamID}::uuid, ${epochID}::uuid, ${membershipID}::uuid,
      ${reason}, ${expiresAt}::timestamptz, ${auditID}::uuid,
      ${fixture.rosterRequest}::uuid, ${fixture.rosterCorrelation}::uuid,
      '192.0.2.70'::inet, 'Periapsis operator-team concurrency proof', 'totp'
    )
  `;
  assert(result, "add_tenant_operator_team_roster_entry returned no result");
  return result;
}

async function revokeRosterEntry(
  transaction: postgres.TransactionSql,
  rosterID: string,
  expectedVersion: number,
  reason: string,
  auditID: string,
): Promise<number> {
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.revoke_tenant_operator_team_roster_entry(
      ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid,
      ${rosterID}::uuid, ${expectedVersion}, ${reason}, ${auditID}::uuid,
      ${fixture.rosterRequest}::uuid, ${fixture.rosterCorrelation}::uuid,
      '192.0.2.70'::inet, 'Periapsis operator-team concurrency proof', 'totp'
    ) AS version
  `;
  assert(result, "revoke_tenant_operator_team_roster_entry returned no result");
  return result.version;
}

async function resolveRelationships(
  sql: postgres.TransactionSql,
  userID: string,
): Promise<{ operator_team_id: string; assignment_epoch_id: string }[]> {
  await setApiContext(sql, userID);
  const rows = await sql<
    { operator_team_id: string; assignment_epoch_id: string }[]
  >`SELECT * FROM app.resolve_current_tenant_operator_teams(201)`;
  return [...rows];
}

const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseURL, { max: 1, onnotice: () => undefined });
let releaseHeldTransaction: (() => void) | undefined;

try {
  const [collision] = await admin<{ count: number }[]>`
    SELECT (
      (SELECT count(*) FROM public.tenants
       WHERE id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
          OR slug IN (${fixtureNames.tenantSlug}, ${fixtureNames.foreignTenantSlug}))
      +
      (SELECT count(*) FROM public.users
       WHERE id IN (
         ${fixture.adminUser}::uuid, ${fixture.readerUser}::uuid,
         ${fixture.inactiveUser}::uuid, ${fixture.targetUser}::uuid,
         ${fixture.limitedUser}::uuid, ${fixture.sourceUser}::uuid,
         ${fixture.foreignUser}::uuid, ${fixture.managerOnlyUser}::uuid
       ) OR email LIKE ${fixtureNames.emailPattern})
      +
      (SELECT count(*) FROM public.operator_teams
       WHERE id IN (
         ${fixture.team}::uuid, ${fixture.replayTeamAttempt}::uuid,
         ${fixture.foreignTeam}::uuid, ${fixture.rollbackTeam}::uuid
       ) OR key LIKE ${fixtureNames.teamPattern})
    )::integer AS count
  `;
  assert.equal(
    collision?.count,
    0,
    "operator-team proof requires a fresh disposable database",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.tenant}::uuid, ${fixtureNames.tenantSlug}, 'Operator team concurrency proof'),
        (${fixture.foreignTenant}::uuid, ${fixtureNames.foreignTenantSlug}, 'Foreign operator team proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active)
      VALUES
        (${fixture.adminUser}::uuid, 'operator-team-c6.admin@example.invalid', 'Operator team administrator', true),
        (${fixture.readerUser}::uuid, 'operator-team-c6.reader@example.invalid', 'Operator team reader', true),
        (${fixture.inactiveUser}::uuid, 'operator-team-c6.inactive@example.invalid', 'Inactive platform manager', false),
        (${fixture.targetUser}::uuid, 'operator-team-c6.target@example.invalid', 'Operator team target', true),
        (${fixture.limitedUser}::uuid, 'operator-team-c6.limited@example.invalid', 'Limited consequence manager', true),
        (${fixture.sourceUser}::uuid, 'operator-team-c6.source@example.invalid', 'Operator team source target', true),
        (${fixture.foreignUser}::uuid, 'operator-team-c6.foreign@example.invalid', 'Foreign operator team admin', true),
        (${fixture.managerOnlyUser}::uuid, 'operator-team-c6.manager-only@example.invalid', 'Manager without role grant', true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
      VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.targetMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.targetUser}::uuid, 'analyst', 'active'),
        (${fixture.limitedMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.limitedUser}::uuid, 'analyst', 'active'),
        (${fixture.sourceMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.sourceUser}::uuid, 'analyst', 'active'),
        (${fixture.managerOnlyMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.managerOnlyUser}::uuid, 'analyst', 'active'),
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
        ${fixture.adminSession}::uuid, ${fixture.adminUser}::uuid,
        ${fixture.adminSessionFamily}::uuid, ${fixture.tenant}::uuid,
        ${Buffer.alloc(32, 0xa1)}::bytea, ${Buffer.alloc(32, 0xa2)}::bytea,
        'totp', date_trunc('milliseconds', transaction_timestamp()),
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '2 hours',
        date_trunc('milliseconds', transaction_timestamp())
      )
    `;

    await transaction`
      INSERT INTO public.platform_roles (id, key, display_name, system)
      VALUES
        (${fixture.platformManagerRole}::uuid, ${fixtureNames.platformManagerRole}, 'Operator-team live manager', false),
        (${fixture.platformReaderRole}::uuid, ${fixtureNames.platformReaderRole}, 'Operator-team live reader', false)
    `;
    await transaction`
      INSERT INTO public.platform_role_permissions (role_id, permission_id)
      SELECT role.id, permission.id
      FROM public.platform_roles AS role
      JOIN public.platform_permissions AS permission
        ON (
          role.id = ${fixture.platformManagerRole}::uuid
          AND permission.key IN ('platform.operator_team.read', 'platform.operator_team.manage')
        ) OR (
          role.id = ${fixture.platformReaderRole}::uuid
          AND permission.key = 'platform.operator_team.read'
        )
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id
      ) VALUES
        (${fixture.adminPlatformRole}::uuid, ${fixture.adminUser}::uuid, ${fixture.platformManagerRole}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.readerPlatformRole}::uuid, ${fixture.readerUser}::uuid, ${fixture.platformReaderRole}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.inactivePlatformRole}::uuid, ${fixture.inactiveUser}::uuid, ${fixture.platformManagerRole}::uuid, ${fixture.adminUser}::uuid)
    `;

    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES
        (${fixture.targetRole}::uuid, ${fixture.tenant}::uuid, ${fixtureNames.targetRole}, 'Exact operator-team reader', 'Exact relationship scope proof.', ${fixture.adminMembership}::uuid),
        (${fixture.limitedRole}::uuid, ${fixture.tenant}::uuid, ${fixtureNames.limitedRole}, 'Limited operator-team manager', 'Has role.grant but no operator-team delegation ceiling.', ${fixture.adminMembership}::uuid),
        (${fixture.managerOnlyRole}::uuid, ${fixture.tenant}::uuid, ${fixtureNames.managerOnlyRole}, 'Operator-team manager only', 'Does not include role.grant.', ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      )
      SELECT ${fixture.tenant}::uuid, requested.role_id,
             permission.id, requested.scope, ${fixture.adminMembership}::uuid
      FROM (
        VALUES
          (${fixture.targetRole}::uuid, 'operator_team.read'::text, 'operator_team'::public.authorization_scope),
          (${fixture.limitedRole}::uuid, 'operator_team.manage'::text, 'tenant'::public.authorization_scope),
          (${fixture.limitedRole}::uuid, 'role.grant'::text, 'tenant'::public.authorization_scope),
          (${fixture.managerOnlyRole}::uuid, 'operator_team.manage'::text, 'tenant'::public.authorization_scope)
      ) AS requested(role_id, permission_key, scope)
      JOIN public.tenant_permissions AS permission
        ON permission.key = requested.permission_key
    `;
    const [manualSource] = await transaction<{ id: string }[]>`
      SELECT id FROM public.tenant_authorization_sources
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND kind = 'manual' AND key = 'manual' AND protected
    `;
    assert(manualSource, "tenant manual authorization source is missing");
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES
        (${fixture.targetRoleGrant}::uuid, ${fixture.tenant}::uuid, ${fixture.targetMembership}::uuid, ${fixture.targetRole}::uuid, ${manualSource.id}::uuid, ${fixture.adminMembership}::uuid, 'Exact operator-team relationship proof.'),
        (${fixture.limitedRoleGrant}::uuid, ${fixture.tenant}::uuid, ${fixture.limitedMembership}::uuid, ${fixture.limitedRole}::uuid, ${manualSource.id}::uuid, ${fixture.adminMembership}::uuid, 'Consequence recheck proof.'),
        (${fixture.managerOnlyRoleGrant}::uuid, ${fixture.tenant}::uuid, ${fixture.managerOnlyMembership}::uuid, ${fixture.managerOnlyRole}::uuid, ${manualSource.id}::uuid, ${fixture.adminMembership}::uuid, 'Missing role.grant proof.')
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.identitySource}::uuid, ${fixture.tenant}::uuid,
        'identity_mapping', 'oidc.operator-team-proof', true, false
      )
    `;
  });

  const operatorPermissionCatalog = await admin<
    { key: string; scope: string; service_account_allowed: boolean }[]
  >`
    SELECT permission.key, permission_scope.scope,
           permission.service_account_allowed
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key IN (
      'operator_team.read', 'operator_team.manage',
      'operator_team.roster.manage'
    )
    ORDER BY permission.key, permission_scope.scope
  `;
  assert.equal(operatorPermissionCatalog.length, 5);
  assert(
    operatorPermissionCatalog.every((row) => !row.service_account_allowed),
  );

  await Promise.all(
    [
      "operator_teams",
      "platform_commands",
      "operator_team_assignment_epochs",
      "operator_team_roster_entries",
    ].map((table) =>
      assert.rejects(
        winner.begin(async (transaction) => {
          await setApiContext(transaction, fixture.adminUser);
          await transaction.unsafe(`SELECT count(*) FROM public.${table}`);
        }),
        (error: unknown) => assertSqlState(error, "42501"),
      ),
    ),
  );

  const platformReaderList = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.readerUser);
    return transaction<{ operator_team_id: string }[]>`
      SELECT operator_team_id
      FROM app.list_platform_operator_teams(NULL, false, 101)
    `;
  });
  assert(
    platformReaderList.every(
      (operatorTeam) => operatorTeam.operator_team_id !== fixture.team,
    ),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.readerUser);
      await createTeam(
        transaction,
        fixture.team,
        0x10,
        fixtureNames.primaryTeam,
        "Primary operator team",
        fixture.platformCreateAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "42501",
        undefined,
        /platform\.operator_team\.manage permission is required/,
      ),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.inactiveUser);
      await transaction`SELECT * FROM app.list_platform_operator_teams(NULL, false, 101)`;
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "42501",
        undefined,
        /platform\.operator_team\.read permission is required/,
      ),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await createTeam(
        transaction,
        fixture.team,
        0x10,
        fixtureNames.primaryTeam,
        "Primary operator team",
        fixture.platformCreateAudit,
        "service_account",
      );
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const winnerReady = Promise.withResolvers<void>();
  const releaseWinner = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseWinner.resolve;
  const contenderPID = Promise.withResolvers<number>();
  const winningCreate = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const result = await createTeam(
      transaction,
      fixture.team,
      0x11,
      fixtureNames.primaryTeam,
      "Primary operator team",
      fixture.platformCreateAudit,
    );
    winnerReady.resolve();
    await releaseWinner.promise;
    return result;
  });
  const winningOutcome = winningCreate.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(winnerReady.promise, "winning team create did not start");

  const contendingCreate = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    contenderPID.resolve(await backendPID(transaction));
    return createTeam(
      transaction,
      fixture.replayTeamAttempt,
      0x11,
      fixtureNames.primaryTeam,
      "Primary operator team",
      fixture.platformReplayAudit,
    );
  });
  const contendingOutcome = contendingCreate.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        contenderPID.promise,
        "contending team create did not start",
      ),
    );
  } finally {
    releaseWinner.resolve();
    releaseHeldTransaction = undefined;
  }
  const firstCreate = await withTimeout(
    winningOutcome,
    "winning team create did not commit",
  );
  const secondCreate = await withTimeout(
    contendingOutcome,
    "contending team create did not replay",
  );
  assert("result" in firstCreate, "winning operator-team create failed");
  assert("result" in secondCreate, "contending operator-team create failed");
  assert.deepEqual(firstCreate.result, {
    result_resource_id: fixture.team,
    result_version: 1,
    replayed: false,
  });
  assert.deepEqual(secondCreate.result, {
    result_resource_id: fixture.team,
    result_version: 1,
    replayed: true,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await createTeam(
        transaction,
        fixture.replayTeamAttempt,
        0x11,
        fixtureNames.primaryTeam,
        "Drifted operator team",
        fixture.platformDriftAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(error, "23505", "platform_commands_replay_key"),
  );
  const [createState] = await admin<
    { teams: number; commands: number; audits: number }[]
  >`
    SELECT
      count(*) FILTER (WHERE id IN (
        ${fixture.team}::uuid, ${fixture.replayTeamAttempt}::uuid
      ))::integer AS teams,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id = ${fixture.adminUser}::uuid
         AND operation = 'operator_team.create'
         AND key_digest = ${Buffer.alloc(32, 0x11)}::bytea) AS commands,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE id IN (
         ${fixture.platformCreateAudit}::uuid,
         ${fixture.platformReplayAudit}::uuid,
         ${fixture.platformDriftAudit}::uuid
       )) AS audits
    FROM public.operator_teams
  `;
  assert.deepEqual(createState, { teams: 1, commands: 1, audits: 1 });

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    assert.deepEqual(
      await createTeam(
        transaction,
        fixture.foreignTeam,
        0x12,
        fixtureNames.foreignTeam,
        "Foreign tenant operator team",
        fixture.foreignTeamCreateAudit,
      ),
      {
        result_resource_id: fixture.foreignTeam,
        result_version: 1,
        replayed: false,
      },
    );
    assert.deepEqual(
      await createTeam(
        transaction,
        fixture.rollbackTeam,
        0x13,
        fixtureNames.rollbackTeam,
        "Rollback operator team",
        fixture.rollbackTeamCreateAudit,
      ),
      {
        result_resource_id: fixture.rollbackTeam,
        result_version: 1,
        replayed: false,
      },
    );
  });

  const updatedVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.update_platform_operator_team_metadata(
        ${fixture.team}::uuid, 1, 'Primary operator team updated', NULL,
        ${fixture.updateAudit}::uuid, ${fixture.platformRequest}::uuid,
        ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
        'Periapsis operator-team concurrency proof', 'totp'
      ) AS version
    `;
    return result?.version;
  });
  assert.equal(updatedVersion, 2);
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.update_platform_operator_team_metadata(
          ${fixture.team}::uuid, 1, 'Never committed', NULL,
          ${fixture.updateStaleAudit}::uuid, ${fixture.platformRequest}::uuid,
          ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
          'Periapsis operator-team concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const firstAssignment = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return startAssignment(
      transaction,
      fixture.firstEpoch,
      0x21,
      fixture.team,
      "Initial tenant assignment.",
      fixture.firstStartTenantAudit,
      fixture.firstStartPlatformAudit,
    );
  });
  assert.deepEqual(firstAssignment, {
    result_resource_id: fixture.firstEpoch,
    result_version: 1,
    replayed: false,
  });
  const replayedAssignment = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return startAssignment(
      transaction,
      fixture.replayEpochAttempt,
      0x21,
      fixture.team,
      "Initial tenant assignment.",
      fixture.replayStartTenantAudit,
      fixture.replayStartPlatformAudit,
    );
  });
  assert.deepEqual(replayedAssignment, {
    result_resource_id: fixture.firstEpoch,
    result_version: 1,
    replayed: true,
  });
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await startAssignment(
        transaction,
        fixture.replayEpochAttempt,
        0x21,
        fixture.team,
        "Drifted tenant assignment.",
        fixture.driftStartTenantAudit,
        fixture.driftStartPlatformAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "tenant_authorization_commands_replay_key",
      ),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await startAssignment(
        transaction,
        fixture.duplicateEpochAttempt,
        0x22,
        fixture.team,
        "Duplicate active assignment.",
        fixture.duplicateStartTenantAudit,
        fixture.duplicateStartPlatformAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "operator_team_assignment_epochs_active_key",
      ),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.archive_platform_operator_team(
          ${fixture.team}::uuid, 3, 'Blocked by active assignment.',
          ${fixture.archiveConflictAudit}::uuid,
          ${fixture.platformRequest}::uuid,
          ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
          'Periapsis operator-team concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23503",
        "operator_team_assignment_epochs_active_team",
      ),
  );

  const [startedRepresentation] = await admin<
    { team_version: number; assignment_version: number }[]
  >`
    SELECT team.version AS team_version,
           assignment.version AS assignment_version
    FROM public.operator_teams AS team
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.operator_team_id = team.id
    WHERE team.id = ${fixture.team}::uuid
      AND assignment.id = ${fixture.firstEpoch}::uuid
  `;
  assert.deepEqual(startedRepresentation, {
    team_version: 3,
    assignment_version: 1,
  });

  const representationUpdateVersion = await winner.begin(
    async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      const [result] = await transaction<{ version: number }[]>`
        SELECT app.update_platform_operator_team_metadata(
          ${fixture.team}::uuid, 3, 'Primary operator team representation', NULL,
          ${fixture.representationUpdateAudit}::uuid,
          ${fixture.platformRequest}::uuid,
          ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
          'Periapsis operator-team concurrency proof', 'totp'
        ) AS version
      `;
      assert(result, "representation update returned no result");
      return result.version;
    },
  );
  assert.equal(representationUpdateVersion, 4);
  const [renamedRepresentation] = await admin<
    { team_version: number; assignment_version: number }[]
  >`
    SELECT team.version AS team_version,
           assignment.version AS assignment_version
    FROM public.operator_teams AS team
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.operator_team_id = team.id
    WHERE team.id = ${fixture.team}::uuid
      AND assignment.id = ${fixture.firstEpoch}::uuid
  `;
  assert.deepEqual(renamedRepresentation, {
    team_version: 4,
    assignment_version: 2,
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await startAssignment(
        transaction,
        fixture.rollbackEpoch,
        0x23,
        fixture.rollbackTeam,
        "Rollback atomicity assignment.",
        fixture.rollbackStartTenantAudit,
        fixture.rollbackStartPlatformAudit,
        fixture.rollbackRequest,
        fixture.rollbackCorrelation,
      );
      throw new Error("deliberate operator-team transaction rollback");
    }),
    /deliberate operator-team transaction rollback/,
  );
  const [rollbackState] = await admin<
    {
      epochs: number;
      commands: number;
      tenant_audits: number;
      platform_audits: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.operator_team_assignment_epochs
       WHERE id = ${fixture.rollbackEpoch}::uuid) AS epochs,
      (SELECT count(*)::integer FROM public.tenant_authorization_commands
       WHERE result_resource_id = ${fixture.rollbackEpoch}::uuid) AS commands,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id = ${fixture.rollbackStartTenantAudit}::uuid) AS tenant_audits,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE id = ${fixture.rollbackStartPlatformAudit}::uuid) AS platform_audits
  `;
  assert.deepEqual(rollbackState, {
    epochs: 0,
    commands: 0,
    tenant_audits: 0,
    platform_audits: 0,
  });

  const foreignAssignment = await winner.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignUser,
      fixture.foreignTenant,
    );
    return startAssignment(
      transaction,
      fixture.foreignEpoch,
      0x24,
      fixture.foreignTeam,
      "Foreign tenant exact epoch.",
      fixture.foreignStartTenantAudit,
      fixture.foreignStartPlatformAudit,
    );
  });
  assert.equal(foreignAssignment.result_resource_id, fixture.foreignEpoch);
  const foreignRoster = await winner.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignUser,
      fixture.foreignTenant,
    );
    return addRosterEntry(
      transaction,
      fixture.foreignRoster,
      0x31,
      fixture.foreignTeam,
      fixture.foreignEpoch,
      fixture.foreignMembership,
      "Foreign tenant nested roster.",
      null,
      fixture.foreignRosterAudit,
    );
  });
  assert.equal(foreignRoster.result_resource_id, fixture.foreignRoster);
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT * FROM app.get_tenant_operator_team_assignment_epoch(
          ${fixture.foreignTeam}::uuid, ${fixture.foreignEpoch}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT * FROM app.get_tenant_operator_team_roster_entry(
          ${fixture.foreignTeam}::uuid, ${fixture.foreignEpoch}::uuid,
          ${fixture.foreignRoster}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await addRosterEntry(
        transaction,
        fixture.rollbackRoster,
        0x32,
        fixture.foreignTeam,
        fixture.foreignEpoch,
        fixture.targetMembership,
        "Cross-tenant nested ID must fail.",
        null,
        fixture.pastExpiryAudit,
      );
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.targetUser);
      await transaction`
        SELECT * FROM app.get_tenant_operator_team_assignment_epoch(
          ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await addRosterEntry(
        transaction,
        fixture.firstRoster,
        0x33,
        fixture.team,
        fixture.firstEpoch,
        fixture.targetMembership,
        "Past expiry must fail.",
        new Date(Date.now() - 1_000),
        fixture.pastExpiryAudit,
      );
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const firstRoster = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return addRosterEntry(
      transaction,
      fixture.firstRoster,
      0x34,
      fixture.team,
      fixture.firstEpoch,
      fixture.targetMembership,
      "Initial exact-epoch roster edge.",
      null,
      fixture.firstRosterAudit,
    );
  });
  assert.deepEqual(firstRoster, {
    result_resource_id: fixture.firstRoster,
    result_version: 1,
    replayed: false,
  });
  const replayedRoster = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return addRosterEntry(
      transaction,
      fixture.replayRosterAttempt,
      0x34,
      fixture.team,
      fixture.firstEpoch,
      fixture.targetMembership,
      "Initial exact-epoch roster edge.",
      null,
      fixture.replayRosterAudit,
    );
  });
  assert.deepEqual(replayedRoster, {
    result_resource_id: fixture.firstRoster,
    result_version: 1,
    replayed: true,
  });
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await addRosterEntry(
        transaction,
        fixture.replayRosterAttempt,
        0x34,
        fixture.team,
        fixture.firstEpoch,
        fixture.targetMembership,
        "Drifted roster request.",
        null,
        fixture.driftRosterAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "23505",
        "tenant_authorization_commands_replay_key",
      ),
  );

  const rosterProjection = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [get] = await transaction<
      {
        roster_entry_id: string;
        assignment_epoch_id: string;
        membership_id: string;
        source_kind: string;
        source_key: string;
        source_authoritative: boolean;
        roster_state: string;
        version: number;
      }[]
    >`
      SELECT roster_entry_id, assignment_epoch_id, membership_id,
             source_kind, source_key, source_authoritative,
             roster_state, version
      FROM app.get_tenant_operator_team_roster_entry(
        ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid,
        ${fixture.firstRoster}::uuid
      )
    `;
    const list = await transaction<
      { roster_entry_id: string; source_id: string; source_key: string }[]
    >`
      SELECT roster_entry_id, source_id, source_key
      FROM app.list_tenant_operator_team_roster_entries(
        ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid,
        NULL, false, 101
      )
    `;
    return { get, list: [...list] };
  });
  assert.deepEqual(rosterProjection.get, {
    roster_entry_id: fixture.firstRoster,
    assignment_epoch_id: fixture.firstEpoch,
    membership_id: fixture.targetMembership,
    source_kind: "manual",
    source_key: "manual",
    source_authoritative: false,
    roster_state: "active",
    version: 1,
  });
  assert.deepEqual(rosterProjection.list, [
    {
      roster_entry_id: fixture.firstRoster,
      source_id: rosterProjection.list[0]?.source_id,
      source_key: "manual",
    },
  ]);

  const scopedAfter = await winner.begin(async (transaction) => {
    const relationships = await resolveRelationships(
      transaction,
      fixture.targetUser,
    );
    const epoch = await transaction`
      SELECT * FROM app.get_tenant_operator_team_assignment_epoch(
        ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid
      )
    `;
    return { relationships, epoch };
  });
  assert.deepEqual(scopedAfter.relationships, [
    { operator_team_id: fixture.team, assignment_epoch_id: fixture.firstEpoch },
  ]);
  assert.equal(scopedAfter.epoch.length, 1);
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.targetUser);
      await transaction`
        SELECT * FROM app.get_tenant_operator_team_assignment_epoch(
          ${fixture.foreignTeam}::uuid, ${fixture.foreignEpoch}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const revokedVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return revokeRosterEntry(
      transaction,
      fixture.firstRoster,
      1,
      "Roster access withdrawn.",
      fixture.revokeAudit,
    );
  });
  assert.equal(revokedVersion, 2);
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await revokeRosterEntry(
        transaction,
        fixture.firstRoster,
        1,
        "Stale roster revocation.",
        fixture.staleRevokeAudit,
      );
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const revokedProjection = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [row] = await transaction<
      { roster_state: string; version: number; revoke_reason: string | null }[]
    >`
      SELECT roster_state, version, revoke_reason
      FROM app.get_tenant_operator_team_roster_entry(
        ${fixture.team}::uuid, ${fixture.firstEpoch}::uuid,
        ${fixture.firstRoster}::uuid
      )
    `;
    return row;
  });
  assert.deepEqual(revokedProjection, {
    roster_state: "revoked",
    version: 2,
    revoke_reason: "Roster access withdrawn.",
  });
  const scopedAfterRevoke = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.targetUser),
  );
  assert.deepEqual(scopedAfterRevoke, []);

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const restored = await addRosterEntry(
      transaction,
      fixture.secondRoster,
      0x35,
      fixture.team,
      fixture.firstEpoch,
      fixture.targetMembership,
      "Restore exact-epoch relationship for end checks.",
      null,
      fixture.secondRosterAudit,
    );
    assert.equal(restored.result_resource_id, fixture.secondRoster);
  });

  // Prove that assignment end is bounded by the permission catalog rather
  // than roster cardinality. These 500 provider-owned provenance rows plus
  // the manual row above are one exact relationship but 501 live roster rows.
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      )
      SELECT format(
               '01993ec7-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.tenant}::uuid,
             'identity_mapping'::public.authorization_source_kind,
             format('operator-team-c6-bulk-%s', entry),
             true,
             false
      FROM generate_series(1, 500) AS generated(entry)
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT format(
               '01993ec8-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.tenant}::uuid,
             ${fixture.firstEpoch}::uuid,
             ${fixture.targetMembership}::uuid,
             format(
               '01993ec7-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.adminMembership}::uuid,
             'Set-based 501-row assignment-end proof.'
      FROM generate_series(1, 500) AS generated(entry)
    `;
  });
  const [largeRoster] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.operator_team_roster_entries
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND assignment_epoch_id = ${fixture.firstEpoch}::uuid
      AND revoked_at IS NULL
      AND (expires_at IS NULL OR expires_at > transaction_timestamp())
  `;
  assert.equal(largeRoster?.count, 501);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.managerOnlyUser);
      await endAssignment(
        transaction,
        fixture.team,
        fixture.firstEpoch,
        2,
        "Missing role.grant must fail.",
        fixture.missingGrantTenantAudit,
        fixture.missingGrantPlatformAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "42501",
        undefined,
        /role\.grant tenant scope is required/,
      ),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.limitedUser);
      await endAssignment(
        transaction,
        fixture.team,
        fixture.firstEpoch,
        2,
        "Missing consequence ceiling must fail.",
        fixture.consequenceTenantAudit,
        fixture.consequencePlatformAudit,
      );
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "42501",
        undefined,
        /exceeds the exact delegation ceiling or lifetime/,
      ),
  );
  const firstEndedVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return endAssignment(
      transaction,
      fixture.team,
      fixture.firstEpoch,
      2,
      "Conclude initial assignment.",
      fixture.firstEndTenantAudit,
      fixture.firstEndPlatformAudit,
    );
  });
  assert.equal(firstEndedVersion, 3);
  const [firstEndedRepresentation] = await admin<
    { team_version: number; assignment_version: number }[]
  >`
    SELECT team.version AS team_version,
           assignment.version AS assignment_version
    FROM public.operator_teams AS team
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.operator_team_id = team.id
    WHERE team.id = ${fixture.team}::uuid
      AND assignment.id = ${fixture.firstEpoch}::uuid
  `;
  assert.deepEqual(firstEndedRepresentation, {
    team_version: 5,
    assignment_version: 3,
  });
  const [largeRosterAudit] = await admin<{ checked: number }[]>`
    SELECT (metadata ->> 'roster_entries_checked')::integer AS checked
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.firstEndTenantAudit}::uuid
  `;
  assert.equal(largeRosterAudit?.checked, 501);

  const secondAssignment = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return startAssignment(
      transaction,
      fixture.secondEpoch,
      0x25,
      fixture.team,
      "New assignment epoch must not revive old roster.",
      fixture.secondStartTenantAudit,
      fixture.secondStartPlatformAudit,
    );
  });
  assert.equal(secondAssignment.result_resource_id, fixture.secondEpoch);
  const [secondStartedTeam] = await admin<{ version: number }[]>`
    SELECT version FROM public.operator_teams
    WHERE id = ${fixture.team}::uuid
  `;
  assert.equal(secondStartedTeam?.version, 6);
  const relationshipAtNewEpoch = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.targetUser),
  );
  assert.deepEqual(relationshipAtNewEpoch, []);

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const added = await addRosterEntry(
      transaction,
      fixture.secondEpochRoster,
      0x36,
      fixture.team,
      fixture.secondEpoch,
      fixture.targetMembership,
      "Explicit roster for the new epoch.",
      null,
      fixture.secondEpochRosterAudit,
    );
    assert.equal(added.result_resource_id, fixture.secondEpochRoster);
  });
  const exactNewRelationship = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.targetUser),
  );
  assert.deepEqual(exactNewRelationship, [
    {
      operator_team_id: fixture.team,
      assignment_epoch_id: fixture.secondEpoch,
    },
  ]);

  type EpochImmutabilitySnapshot = {
    source_team_version: number;
    destination_team_version: number;
    ended_assignment_version: number;
    ended_assignment_team_id: string;
    ended_by_membership_id: string | null;
    end_reason: string | null;
    ended_at: string | null;
    active_assignment_version: number;
    active_assignment_team_id: string;
    active_assignment_reason: string;
    active_assigned_by_membership_id: string;
    active_assigned_at: string;
    active_roster_epoch_id: string;
  };
  const readEpochImmutabilitySnapshot =
    async (): Promise<EpochImmutabilitySnapshot> => {
      const [snapshot] = await admin<EpochImmutabilitySnapshot[]>`
      SELECT
        (SELECT team.version
         FROM public.operator_teams AS team
         WHERE team.id = ${fixture.team}::uuid) AS source_team_version,
        (SELECT team.version
         FROM public.operator_teams AS team
         WHERE team.id = ${fixture.rollbackTeam}::uuid) AS destination_team_version,
        ended_assignment.version AS ended_assignment_version,
        ended_assignment.operator_team_id AS ended_assignment_team_id,
        ended_assignment.ended_by_membership_id,
        ended_assignment.end_reason,
        ended_assignment.ended_at::text AS ended_at,
        active_assignment.version AS active_assignment_version,
        active_assignment.operator_team_id AS active_assignment_team_id,
        active_assignment.assignment_reason AS active_assignment_reason,
        active_assignment.assigned_by_membership_id
          AS active_assigned_by_membership_id,
        active_assignment.assigned_at::text AS active_assigned_at,
        active_roster.assignment_epoch_id AS active_roster_epoch_id
      FROM public.operator_team_assignment_epochs AS ended_assignment
      JOIN public.operator_team_assignment_epochs AS active_assignment
        ON active_assignment.tenant_id = ended_assignment.tenant_id
       AND active_assignment.id = ${fixture.secondEpoch}::uuid
      JOIN public.operator_team_roster_entries AS active_roster
        ON active_roster.tenant_id = active_assignment.tenant_id
       AND active_roster.assignment_epoch_id = active_assignment.id
       AND active_roster.id = ${fixture.secondEpochRoster}::uuid
      WHERE ended_assignment.tenant_id = ${fixture.tenant}::uuid
        AND ended_assignment.id = ${fixture.firstEpoch}::uuid
    `;
      assert(snapshot, "assignment immutability snapshot is missing");
      return snapshot;
    };
  const rejectEpochMutation = async (
    mutation: (transaction: postgres.TransactionSql) => Promise<unknown>,
    expectedMessage: RegExp,
  ): Promise<void> => {
    await assert.rejects(
      admin.begin(async (transaction) => {
        await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
        await mutation(transaction);
      }),
      (error: unknown) =>
        assertSqlState(error, "55000", undefined, expectedMessage),
    );
  };

  const immutableEpochBefore = await readEpochImmutabilitySnapshot();
  await Promise.all(
    [
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET id = ${fixture.replayEpochAttempt}::uuid
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET tenant_id = ${fixture.foreignTenant}::uuid
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET operator_team_id = ${fixture.rollbackTeam}::uuid
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET assigned_by_membership_id = ${fixture.targetMembership}::uuid
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET assignment_reason = 'Rewritten assignment provenance.'
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET assigned_at = assigned_at + interval '1 second'
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
    ].map((mutation) =>
      rejectEpochMutation(mutation, /identity and provenance are immutable/),
    ),
  );

  await rejectEpochMutation(
    (transaction) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET ended_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.secondEpoch}::uuid
    `,
    /end must be an atomic transition/,
  );
  await rejectEpochMutation(
    (transaction) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET ended_at = NULL, ended_by_membership_id = NULL, end_reason = NULL
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.firstEpoch}::uuid
    `,
    /assignment epoch history is immutable/,
  );
  await Promise.all(
    [
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET ended_at = ended_at + interval '1 second'
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.firstEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET ended_by_membership_id = ${fixture.targetMembership}::uuid
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.firstEpoch}::uuid
    `,
      (transaction: postgres.TransactionSql) => transaction`
      UPDATE public.operator_team_assignment_epochs
      SET end_reason = 'Rewritten assignment end history.'
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.firstEpoch}::uuid
    `,
    ].map((mutation) =>
      rejectEpochMutation(mutation, /assignment epoch history is immutable/),
    ),
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    const noOp = await transaction<{ id: string }[]>`
      UPDATE public.operator_team_assignment_epochs
      SET id = id,
          tenant_id = tenant_id,
          operator_team_id = operator_team_id,
          assigned_by_membership_id = assigned_by_membership_id,
          assignment_reason = assignment_reason,
          assigned_at = assigned_at,
          ended_at = ended_at,
          ended_by_membership_id = ended_by_membership_id,
          end_reason = end_reason,
          version = version,
          updated_at = updated_at
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.firstEpoch}::uuid
      RETURNING id
    `;
    assert.equal(noOp.length, 1);
  });

  assert.deepEqual(await readEpochImmutabilitySnapshot(), immutableEpochBefore);
  const exactAfterRejectedEpochMutations = await winner.begin(
    async (transaction) =>
      resolveRelationships(transaction, fixture.targetUser),
  );
  assert.deepEqual(exactAfterRejectedEpochMutations, exactNewRelationship);

  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [membership] = await transaction<{ id: string }[]>`
      SELECT membership_id AS id
      FROM app.change_tenant_membership_lifecycle_v1(
        ${fixture.adminSession}::uuid, ${fixture.targetUser}::uuid,
        'suspended'::public.membership_status, 1,
        'Suspend membership for the operator-team consequence proof.',
        ${Buffer.alloc(32, 0xa3)}::bytea,
        ${fixture.suspendMembershipAudit}::uuid,
        ${fixture.rosterRequest}::uuid, ${fixture.rosterCorrelation}::uuid,
        '192.0.2.70'::inet, 'Periapsis operator-team concurrency proof', 'totp'
      )
    `;
    assert.equal(membership?.id, fixture.targetMembership);
  });
  await assert.rejects(
    winner.begin(async (transaction) => {
      await resolveRelationships(transaction, fixture.targetUser);
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const suspendedRoster = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [row] = await transaction<{ roster_state: string }[]>`
      SELECT roster_state
      FROM app.get_tenant_operator_team_roster_entry(
        ${fixture.team}::uuid, ${fixture.secondEpoch}::uuid,
        ${fixture.secondEpochRoster}::uuid
      )
    `;
    return row;
  });
  assert.equal(suspendedRoster?.roster_state, "expired");
  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    await transaction`
      SELECT *
      FROM app.change_tenant_membership_lifecycle_v1(
        ${fixture.adminSession}::uuid, ${fixture.targetUser}::uuid,
        'active'::public.membership_status, 2,
        'Reactivate membership after the operator-team consequence proof.',
        ${Buffer.alloc(32, 0xa4)}::bytea,
        ${fixture.activateMembershipAudit}::uuid,
        ${fixture.rosterRequest}::uuid, ${fixture.rosterCorrelation}::uuid,
        '192.0.2.70'::inet, 'Periapsis operator-team concurrency proof', 'totp'
      )
    `;
  });
  const restoredMembershipRelationship = await winner.begin(
    async (transaction) =>
      resolveRelationships(transaction, fixture.targetUser),
  );
  assert.deepEqual(restoredMembershipRelationship, [
    {
      operator_team_id: fixture.team,
      assignment_epoch_id: fixture.secondEpoch,
    },
  ]);

  const lifetimeExpiry = new Date(Date.now() + 1_500);
  await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const added = await addRosterEntry(
      transaction,
      fixture.lifetimeRoster,
      0x37,
      fixture.team,
      fixture.secondEpoch,
      fixture.sourceMembership,
      "Short-lived roster edge.",
      lifetimeExpiry,
      fixture.lifetimeRosterAudit,
    );
    assert.equal(added.result_resource_id, fixture.lifetimeRoster);
  });
  const liveLifetimeRelationship = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.sourceUser),
  );
  assert.deepEqual(liveLifetimeRelationship, [
    {
      operator_team_id: fixture.team,
      assignment_epoch_id: fixture.secondEpoch,
    },
  ]);
  await delay(Math.max(0, lifetimeExpiry.getTime() - Date.now() + 150));
  const expiredLifetimeRelationship = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.sourceUser),
  );
  assert.deepEqual(expiredLifetimeRelationship, []);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.identityRoster}::uuid, ${fixture.tenant}::uuid,
        ${fixture.secondEpoch}::uuid, ${fixture.sourceMembership}::uuid,
        ${fixture.identitySource}::uuid, NULL,
        'Authoritative identity-source roster proof.'
      )
    `;
  });
  const identityRelationship = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.sourceUser),
  );
  assert.deepEqual(identityRelationship, [
    {
      operator_team_id: fixture.team,
      assignment_epoch_id: fixture.secondEpoch,
    },
  ]);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_authorization_sources
      SET retired_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.identitySource}::uuid
    `;
  });
  const retiredSourceRelationship = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.sourceUser),
  );
  assert.deepEqual(retiredSourceRelationship, []);
  const retiredSourceProjection = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [row] = await transaction<
      {
        roster_state: string;
        source_authoritative: boolean;
        retired: boolean;
      }[]
    >`
      SELECT roster_state, source_authoritative,
             source_retired_at IS NOT NULL AS retired
      FROM app.get_tenant_operator_team_roster_entry(
        ${fixture.team}::uuid, ${fixture.secondEpoch}::uuid,
        ${fixture.identityRoster}::uuid
      )
    `;
    return row;
  });
  assert.deepEqual(retiredSourceProjection, {
    roster_state: "expired",
    source_authoritative: true,
    retired: true,
  });

  const secondEndedVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return endAssignment(
      transaction,
      fixture.team,
      fixture.secondEpoch,
      1,
      "Conclude replacement assignment.",
      fixture.secondEndTenantAudit,
      fixture.secondEndPlatformAudit,
    );
  });
  assert.equal(secondEndedVersion, 2);
  const [secondEndedTeam] = await admin<{ version: number }[]>`
    SELECT version FROM public.operator_teams
    WHERE id = ${fixture.team}::uuid
  `;
  assert.equal(secondEndedTeam?.version, 7);
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT app.archive_platform_operator_team(
          ${fixture.team}::uuid, 1, 'Stale archive must fail.',
          ${fixture.archiveStaleAudit}::uuid,
          ${fixture.platformRequest}::uuid,
          ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
          'Periapsis operator-team concurrency proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const archivedVersion = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.archive_platform_operator_team(
        ${fixture.team}::uuid, 7, 'Operator-team proof complete.',
        ${fixture.archiveAudit}::uuid, ${fixture.platformRequest}::uuid,
        ${fixture.platformCorrelation}::uuid, '192.0.2.70'::inet,
        'Periapsis operator-team concurrency proof', 'totp'
      ) AS version
    `;
    return result?.version;
  });
  assert.equal(archivedVersion, 8);

  // Capacity is based on potentially live exact relationships, so reversible
  // principal gates cannot be used to accumulate dormant edges. Populate 200
  // relationships while both gates are closed, allow duplicate provenance,
  // and reject an expired edge when a provider tries to refresh it as #201.
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_memberships
      SET status = 'suspended', updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.targetMembership}::uuid
    `;
    await transaction`
      UPDATE public.users
      SET active = false, updated_at = transaction_timestamp()
      WHERE id = ${fixture.targetUser}::uuid
    `;
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      )
      SELECT format(
               '01993ec9-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             format('live_operator_team_c6_capacity_%s', entry),
             format('Capacity team %s', entry),
             'Potential relationship capacity proof.',
             ${fixture.adminUser}::uuid
      FROM generate_series(1, 201) AS generated(entry)
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason
      )
      SELECT format(
               '01993eca-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.tenant}::uuid,
             format(
               '01993ec9-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.adminMembership}::uuid,
             'Potential relationship capacity proof.'
      FROM generate_series(1, 201) AS generated(entry)
    `;
    // Seed the first 199 valid rows as fixture state without turning this
    // boundary regression into 199 repeated full-cardinality scans. DDL is
    // transactional, and the guard is re-enabled before the 200th insert.
    await transaction.unsafe(`
      ALTER TABLE public.operator_team_roster_entries
      DISABLE TRIGGER operator_team_roster_entries_capacity_guard
    `);
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT format(
               '01993ecb-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.tenant}::uuid,
             format(
               '01993eca-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.targetMembership}::uuid,
             source.id,
             ${fixture.adminMembership}::uuid,
             'Potential relationship capacity proof.'
      FROM generate_series(1, 199) AS generated(entry)
      CROSS JOIN LATERAL (
        SELECT id
        FROM public.tenant_authorization_sources
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND kind = 'manual'
          AND key = 'manual'
          AND protected
      ) AS source
    `;
    await transaction.unsafe(`
      ALTER TABLE public.operator_team_roster_entries
      ENABLE TRIGGER operator_team_roster_entries_capacity_guard
    `);
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT '01993ecb-00c8-7000-8000-0000000000c8'::uuid,
             ${fixture.tenant}::uuid,
             '01993eca-00c8-7000-8000-0000000000c8'::uuid,
             ${fixture.targetMembership}::uuid,
             source.id,
             ${fixture.adminMembership}::uuid,
             'The 200th potential relationship must be accepted.'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.kind = 'manual'
        AND source.key = 'manual'
        AND source.protected
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason, granted_at, expires_at,
        updated_at
      )
      SELECT '01993ecb-00c9-7000-8000-0000000000c9'::uuid,
             ${fixture.tenant}::uuid,
             '01993eca-00c9-7000-8000-0000000000c9'::uuid,
             ${fixture.targetMembership}::uuid,
             source.id,
             ${fixture.adminMembership}::uuid,
             'Expired provider edge awaiting refresh.',
             transaction_timestamp() - interval '2 hours',
             transaction_timestamp() - interval '1 hour',
             transaction_timestamp() - interval '2 hours'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.kind = 'manual'
        AND source.key = 'manual'
        AND source.protected
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        '01993ecb-0ffe-7000-8000-000000000ffe'::uuid,
        ${fixture.tenant}::uuid,
        '01993eca-0001-7000-8000-000000000001'::uuid,
        ${fixture.targetMembership}::uuid,
        '01993ec7-0001-7000-8000-000000000001'::uuid,
        ${fixture.adminMembership}::uuid,
        'Duplicate provenance must not consume exact capacity.'
      )
    `;
  });

  const [potentialAtBoundary] = await admin<{ count: number }[]>`
    SELECT count(DISTINCT assignment.id)::integer AS count
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS team
      ON team.id = assignment.operator_team_id
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = assignment.tenant_id
     AND roster.assignment_epoch_id = assignment.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    WHERE assignment.tenant_id = ${fixture.tenant}::uuid
      AND roster.membership_id = ${fixture.targetMembership}::uuid
      AND assignment.ended_at IS NULL
      AND team.archived_at IS NULL
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
  `;
  assert.equal(potentialAtBoundary?.count, 200);

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.operator_team_roster_entries
        SET expires_at = transaction_timestamp() + interval '1 hour',
            updated_at = transaction_timestamp()
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = '01993ecb-00c9-7000-8000-0000000000c9'::uuid
      `;
    }),
    (error: unknown) =>
      assertSqlState(
        error,
        "55000",
        undefined,
        /relationship limit of 200 exceeded/,
      ),
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.users
      SET active = true, updated_at = transaction_timestamp()
      WHERE id = ${fixture.targetUser}::uuid
    `;
    await transaction`
      UPDATE public.tenant_memberships
      SET status = 'active', updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.targetMembership}::uuid
    `;
  });
  const relationshipsAtBoundary = await winner.begin(async (transaction) =>
    resolveRelationships(transaction, fixture.targetUser),
  );
  assert.equal(relationshipsAtBoundary.length, 200);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.platform_commands (
        id, actor_user_id, operation, key_digest, request_digest,
        result_resource_id, result_version, created_at, expires_at
      )
      SELECT format(
               '01993ecc-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.adminUser}::uuid,
             'operator_team.create',
             decode(repeat('ca', 31) || lpad(to_hex(entry), 2, '0'), 'hex'),
             decode(repeat('cb', 31) || lpad(to_hex(entry), 2, '0'), 'hex'),
             ${fixture.team}::uuid,
             8,
             CASE WHEN entry <= 3
               THEN transaction_timestamp() - interval '2 days'
               ELSE transaction_timestamp()
             END,
             CASE WHEN entry <= 3
               THEN transaction_timestamp() - interval '1 day'
               ELSE transaction_timestamp() + interval '1 day'
             END
      FROM generate_series(1, 4) AS generated(entry)
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_commands (
        id, tenant_id, actor_membership_id, operation, key_digest,
        request_digest, result_resource_id, result_version, created_at,
        expires_at
      )
      SELECT format(
               '01993ecd-%s-7000-8000-%s',
               lpad(to_hex(entry), 4, '0'),
               lpad(to_hex(entry), 12, '0')
             )::uuid,
             ${fixture.tenant}::uuid,
             ${fixture.adminMembership}::uuid,
             'operator_team_assignment.create',
             decode(repeat('da', 31) || lpad(to_hex(entry), 2, '0'), 'hex'),
             decode(repeat('db', 31) || lpad(to_hex(entry), 2, '0'), 'hex'),
             ${fixture.firstEpoch}::uuid,
             4,
             CASE WHEN entry <= 3
               THEN transaction_timestamp() - interval '2 days'
               ELSE transaction_timestamp()
             END,
             CASE WHEN entry <= 3
               THEN transaction_timestamp() - interval '1 day'
               ELSE transaction_timestamp() + interval '1 day'
             END
      FROM generate_series(1, 4) AS generated(entry)
    `;
  });

  await assert.rejects(
    winner.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT * FROM app.prune_expired_authorization_commands(2)
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const pruneBatch = async (): Promise<{
    platform_commands_deleted: number;
    tenant_commands_deleted: number;
  }> =>
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      const [result] = await transaction<
        {
          platform_commands_deleted: number;
          tenant_commands_deleted: number;
        }[]
      >`SELECT * FROM app.prune_expired_authorization_commands(2)`;
      assert(result, "authorization command pruner returned no result");
      return result;
    });

  assert.deepEqual(await pruneBatch(), {
    platform_commands_deleted: 2,
    tenant_commands_deleted: 2,
  });
  assert.deepEqual(await pruneBatch(), {
    platform_commands_deleted: 1,
    tenant_commands_deleted: 1,
  });
  const [retainedCommands] = await admin<
    { platform_count: number; tenant_count: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.platform_commands
       WHERE id::text LIKE '01993ecc-%') AS platform_count,
      (SELECT count(*)::integer
       FROM public.tenant_authorization_commands
       WHERE id::text LIKE '01993ecd-%') AS tenant_count
  `;
  assert.deepEqual(retainedCommands, {
    platform_count: 1,
    tenant_count: 1,
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES
        (
          ${fixture.endAddRaceTeam}::uuid,
          'live_operator_team_c6_race_end_add',
          'End versus add race team',
          'Deterministic state-first serialization proof.',
          ${fixture.adminUser}::uuid
        ),
        (
          ${fixture.archiveStartRaceTeam}::uuid,
          'live_operator_team_c6_race_archive_start',
          'Archive versus start race team',
          'Deterministic team lifecycle serialization proof.',
          ${fixture.adminUser}::uuid
        )
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason
      ) VALUES (
        ${fixture.endAddRaceEpoch}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.endAddRaceTeam}::uuid,
        ${fixture.adminMembership}::uuid,
        'End versus add serialization proof.'
      )
    `;
  });

  const endReady = Promise.withResolvers<void>();
  const releaseEnd = Promise.withResolvers<void>();
  const endingRace = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const version = await endAssignment(
      transaction,
      fixture.endAddRaceTeam,
      fixture.endAddRaceEpoch,
      1,
      "End wins before a concurrent roster add.",
      fixture.endAddRaceTenantAudit,
      fixture.endAddRacePlatformAudit,
    );
    endReady.resolve();
    await releaseEnd.promise;
    return version;
  });
  const endingRaceOutcome = endingRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(endReady.promise, "end-vs-add winner did not start");
  const endAddPID = Promise.withResolvers<number>();
  const addingRace = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    endAddPID.resolve(await backendPID(transaction));
    return addRosterEntry(
      transaction,
      fixture.endAddRaceRoster,
      0x61,
      fixture.endAddRaceTeam,
      fixture.endAddRaceEpoch,
      fixture.sourceMembership,
      "Concurrent add must observe the ended epoch.",
      null,
      fixture.endAddRaceRosterAudit,
    );
  });
  const addingRaceOutcome = addingRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        endAddPID.promise,
        "end-vs-add contender did not start",
      ),
    );
  } finally {
    releaseEnd.resolve();
  }
  const endedRace = await withTimeout(
    endingRaceOutcome,
    "end-vs-add winner did not commit",
  );
  const addedRace = await withTimeout(
    addingRaceOutcome,
    "end-vs-add contender did not finish",
  );
  assert("result" in endedRace, "end-vs-add winner failed");
  assert.equal(endedRace.result, 2);
  assert("error" in addedRace, "roster add committed after assignment end");
  assertSqlState(addedRace.error, "P0002");

  const revokeReady = Promise.withResolvers<void>();
  const releaseRevoke = Promise.withResolvers<void>();
  const revokingRace = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.revoke_tenant_operator_team_roster_entry(
        ${fixture.capacitySecondTeam}::uuid,
        ${fixture.capacitySecondEpoch}::uuid,
        ${fixture.capacitySecondRoster}::uuid,
        1,
        'Revoke wins before a concurrent role policy replacement.',
        ${fixture.revokePolicyRaceAudit}::uuid,
        ${fixture.rosterRequest}::uuid,
        ${fixture.rosterCorrelation}::uuid,
        '192.0.2.70'::inet,
        'Periapsis operator-team concurrency proof',
        'totp'
      ) AS version
    `;
    assert(result, "revoke-vs-policy winner returned no result");
    revokeReady.resolve();
    await releaseRevoke.promise;
    return result.version;
  });
  const revokingRaceOutcome = revokingRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    revokeReady.promise,
    "revoke-vs-policy winner did not start",
  );
  const policyPID = Promise.withResolvers<number>();
  const replacingPolicyRace = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    policyPID.resolve(await backendPID(transaction));
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.replace_tenant_role_policy_v2(
        ${fixture.targetRole}::uuid,
        1,
        ARRAY['operator_team.roster.manage']::text[],
        ARRAY['operator_team']::public.authorization_scope[],
        ARRAY[]::text[],
        ARRAY[]::public.authorization_scope[],
        ${fixture.replacePolicyRaceAudit}::uuid,
        ${fixture.rosterRequest}::uuid,
        ${fixture.rosterCorrelation}::uuid,
        '192.0.2.70'::inet,
        'Periapsis operator-team concurrency proof',
        'totp'
      ) AS version
    `;
    assert(result, "revoke-vs-policy contender returned no result");
    return result.version;
  });
  const replacingPolicyOutcome = replacingPolicyRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  const policyBackendID = await withTimeout(
    policyPID.promise,
    "revoke-vs-policy contender did not start",
  );
  try {
    await waitForRowLock(admin, policyBackendID);
  } finally {
    releaseRevoke.resolve();
  }
  const revokedRace = await withTimeout(
    revokingRaceOutcome,
    "revoke-vs-policy winner did not commit",
  );
  let replacedPolicy: Awaited<typeof replacingPolicyOutcome>;
  try {
    replacedPolicy = await withTimeout(
      replacingPolicyOutcome,
      "revoke-vs-policy contender did not finish",
      30_000,
    );
  } catch (error) {
    const [activity] = await admin<
      {
        state: string;
        wait_event_type: string | null;
        wait_event: string | null;
        blockers: string;
      }[]
    >`
      SELECT state, wait_event_type, wait_event,
             pg_catalog.pg_blocking_pids(pid)::text AS blockers
      FROM pg_catalog.pg_stat_activity
      WHERE pid = ${policyBackendID}
    `;
    throw new Error(
      `revoke-vs-policy contender timeout: ${JSON.stringify(activity)}`,
      { cause: error },
    );
  }
  assert("result" in revokedRace, "revoke-vs-policy winner failed");
  assert.equal(revokedRace.result, 2);
  assert("result" in replacedPolicy, "revoke-vs-policy contender failed");
  assert.equal(replacedPolicy.result, 2);
  const [serializedPolicyState] = await admin<
    {
      roster_version: number;
      revoked: boolean;
      role_version: number;
      permission_key: string;
    }[]
  >`
    SELECT roster.version AS roster_version,
           roster.revoked_at IS NOT NULL AS revoked,
           role.version AS role_version,
           permission.key AS permission_key
    FROM public.operator_team_roster_entries AS roster
    JOIN public.tenant_roles AS role
      ON role.tenant_id = roster.tenant_id
     AND role.id = ${fixture.targetRole}::uuid
    JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id
     AND policy.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE roster.tenant_id = ${fixture.tenant}::uuid
      AND roster.id = ${fixture.capacitySecondRoster}::uuid
  `;
  assert.deepEqual(serializedPolicyState, {
    roster_version: 2,
    revoked: true,
    role_version: 2,
    permission_key: "operator_team.roster.manage",
  });

  const archiveReady = Promise.withResolvers<void>();
  const releaseArchive = Promise.withResolvers<void>();
  const archivingRace = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.archive_platform_operator_team(
        ${fixture.archiveStartRaceTeam}::uuid,
        1,
        'Archive wins before a concurrent assignment start.',
        ${fixture.archiveStartRaceArchiveAudit}::uuid,
        ${fixture.platformRequest}::uuid,
        ${fixture.platformCorrelation}::uuid,
        '192.0.2.70'::inet,
        'Periapsis operator-team concurrency proof',
        'totp'
      ) AS version
    `;
    assert(result, "archive-vs-start winner returned no result");
    archiveReady.resolve();
    await releaseArchive.promise;
    return result.version;
  });
  const archivingRaceOutcome = archivingRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    archiveReady.promise,
    "archive-vs-start winner did not start",
  );
  const startPID = Promise.withResolvers<number>();
  const startingRace = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    startPID.resolve(await backendPID(transaction));
    return startAssignment(
      transaction,
      fixture.archiveStartRaceEpoch,
      0x62,
      fixture.archiveStartRaceTeam,
      "Concurrent start must observe the archived team.",
      fixture.archiveStartRaceTenantAudit,
      fixture.archiveStartRacePlatformAudit,
    );
  });
  const startingRaceOutcome = startingRace.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        startPID.promise,
        "archive-vs-start contender did not start",
      ),
    );
  } finally {
    releaseArchive.resolve();
  }
  const archivedRace = await withTimeout(
    archivingRaceOutcome,
    "archive-vs-start winner did not commit",
  );
  const startedRace = await withTimeout(
    startingRaceOutcome,
    "archive-vs-start contender did not finish",
  );
  assert("result" in archivedRace, "archive-vs-start winner failed");
  assert.equal(archivedRace.result, 2);
  assert("error" in startedRace, "assignment started after team archive");
  assertSqlState(startedRace.error, "P0002");

  const correlatedAudits = await admin<
    {
      id: string;
      action: string;
      request_id: string | null;
      correlation_id: string | null;
      peer_audit_id: string | null;
    }[]
  >`
    SELECT event.id, event.action, event.request_id, event.correlation_id,
           event.metadata ->> 'platform_audit_event_id' AS peer_audit_id
    FROM public.audit_events AS event
    WHERE event.tenant_id = ${fixture.tenant}::uuid
      AND event.id IN (
        ${fixture.firstStartTenantAudit}::uuid,
        ${fixture.firstEndTenantAudit}::uuid,
        ${fixture.secondStartTenantAudit}::uuid,
        ${fixture.secondEndTenantAudit}::uuid
      )
    UNION ALL
    SELECT event.id, event.action, event.request_id, event.correlation_id,
           event.metadata ->> 'tenant_audit_event_id' AS peer_audit_id
    FROM public.platform_audit_events AS event
    WHERE event.id IN (
        ${fixture.firstStartPlatformAudit}::uuid,
        ${fixture.firstEndPlatformAudit}::uuid,
        ${fixture.secondStartPlatformAudit}::uuid,
        ${fixture.secondEndPlatformAudit}::uuid
      )
    ORDER BY id
  `;
  assert.equal(correlatedAudits.length, 8);
  const auditByID = new Map(correlatedAudits.map((event) => [event.id, event]));
  for (const [tenantAuditID, platformAuditID, requestID, correlationID] of [
    [
      fixture.firstStartTenantAudit,
      fixture.firstStartPlatformAudit,
      fixture.startRequest,
      fixture.startCorrelation,
    ],
    [
      fixture.firstEndTenantAudit,
      fixture.firstEndPlatformAudit,
      fixture.endRequest,
      fixture.endCorrelation,
    ],
    [
      fixture.secondStartTenantAudit,
      fixture.secondStartPlatformAudit,
      fixture.startRequest,
      fixture.startCorrelation,
    ],
    [
      fixture.secondEndTenantAudit,
      fixture.secondEndPlatformAudit,
      fixture.endRequest,
      fixture.endCorrelation,
    ],
  ] as const) {
    assert.equal(auditByID.get(tenantAuditID)?.peer_audit_id, platformAuditID);
    assert.equal(auditByID.get(platformAuditID)?.peer_audit_id, tenantAuditID);
    assert.equal(auditByID.get(tenantAuditID)?.request_id, requestID);
    assert.equal(auditByID.get(platformAuditID)?.request_id, requestID);
    assert.equal(auditByID.get(tenantAuditID)?.correlation_id, correlationID);
    assert.equal(auditByID.get(platformAuditID)?.correlation_id, correlationID);
  }

  const [rosterAudits] = await admin<
    { tenant_count: number; platform_count: number; failed_count: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND action IN (
           'tenant.operator_team.roster_entry_added',
           'tenant.operator_team.roster_entry_revoked'
         )) AS tenant_count,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE resource_type = 'operator_team_roster_entry'
         AND request_id = ${fixture.rosterRequest}::uuid) AS platform_count,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id IN (
         ${fixture.replayRosterAudit}::uuid,
         ${fixture.driftRosterAudit}::uuid,
         ${fixture.staleRevokeAudit}::uuid,
         ${fixture.missingGrantTenantAudit}::uuid,
         ${fixture.consequenceTenantAudit}::uuid
       )) AS failed_count
  `;
  assert(rosterAudits && rosterAudits.tenant_count >= 5);
  assert.equal(rosterAudits.platform_count, 0);
  assert.equal(rosterAudits.failed_count, 0);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        UPDATE public.audit_events SET reason = 'tampered'
        WHERE id = ${fixture.firstStartTenantAudit}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        UPDATE public.platform_audit_events SET reason = 'tampered'
        WHERE id = ${fixture.firstStartPlatformAudit}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const tenantChain = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true)
    `;
    return transaction<{ valid: boolean }[]>`
      SELECT valid FROM app.verify_audit_chain(${fixture.tenant}::uuid)
    `;
  });
  assert(tenantChain.length > 0);
  assert(tenantChain.every((event) => event.valid));
  const platformChain = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    return transaction<{ valid: boolean }[]>`
      SELECT valid FROM app.verify_platform_audit_chain()
    `;
  });
  assert(platformChain.length > 0);
  assert(platformChain.every((event) => event.valid));

  const [finalState] = await admin<
    {
      team_version: number;
      archived: boolean;
      first_assignment_version: number;
      second_assignment_version: number;
      active_primary_epochs: number;
      replay_attempts: number;
      failed_audits: number;
    }[]
  >`
    SELECT
      team.version AS team_version,
      team.archived_at IS NOT NULL AS archived,
      (SELECT assignment.version
       FROM public.operator_team_assignment_epochs AS assignment
       WHERE assignment.id = ${fixture.firstEpoch}::uuid) AS first_assignment_version,
      (SELECT assignment.version
       FROM public.operator_team_assignment_epochs AS assignment
       WHERE assignment.id = ${fixture.secondEpoch}::uuid) AS second_assignment_version,
      (SELECT count(*)::integer
       FROM public.operator_team_assignment_epochs AS assignment
       WHERE assignment.tenant_id = ${fixture.tenant}::uuid
         AND assignment.operator_team_id = ${fixture.team}::uuid
         AND assignment.ended_at IS NULL) AS active_primary_epochs,
      (SELECT count(*)::integer
       FROM public.operator_team_assignment_epochs
       WHERE id IN (
         ${fixture.replayEpochAttempt}::uuid,
         ${fixture.duplicateEpochAttempt}::uuid,
         ${fixture.rollbackEpoch}::uuid
       )) AS replay_attempts,
      (SELECT count(*)::integer
       FROM public.platform_audit_events
       WHERE id IN (
         ${fixture.platformReplayAudit}::uuid,
         ${fixture.platformDriftAudit}::uuid,
         ${fixture.updateStaleAudit}::uuid,
         ${fixture.archiveConflictAudit}::uuid,
         ${fixture.archiveStaleAudit}::uuid,
         ${fixture.missingGrantPlatformAudit}::uuid,
         ${fixture.consequencePlatformAudit}::uuid,
         ${fixture.rollbackStartPlatformAudit}::uuid
       )) AS failed_audits
    FROM public.operator_teams AS team
    WHERE team.id = ${fixture.team}::uuid
  `;
  assert.deepEqual(finalState, {
    team_version: 8,
    archived: true,
    first_assignment_version: 4,
    second_assignment_version: 3,
    active_primary_epochs: 0,
    replay_attempts: 0,
    failed_audits: 0,
  });

  process.stdout.write(
    "operator-team RLS, exact-epoch, idempotency, audit, and concurrency checks passed\n",
  );
} finally {
  releaseHeldTransaction?.();
  await Promise.allSettled([admin.end(), winner.end(), contender.end()]);
}
