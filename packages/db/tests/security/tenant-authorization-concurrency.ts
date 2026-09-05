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

const fixture = {
  tenant: "01993ea0-5e00-7000-8000-000000000001",
  firstUser: "01993ea0-5000-7000-8000-000000000101",
  secondUser: "01993ea0-5000-7000-8000-000000000102",
  firstMembership: "01993ea0-5000-7000-8000-000000000201",
  secondMembership: "01993ea0-5000-7000-8000-000000000202",
  winnerRole: "01993ea0-5000-7000-8000-000000000301",
  contenderRole: "01993ea0-5000-7000-8000-000000000302",
  secondAdminGrant: "01993ea0-5000-7000-8000-000000000401",
  expiringDirectGrant: "01993ea0-5000-7000-8000-000000000402",
  replacementDirectGrant: "01993ea0-5000-7000-8000-000000000403",
  replayDirectGrantAttempt: "01993ea0-5000-7000-8000-000000000404",
  externalManualSource: "01993ea0-5000-7000-8000-000000000405",
  externalManualGrant: "01993ea0-5000-7000-8000-000000000406",
} as const;

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
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
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
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
      throw new Error(
        "contending authorization transaction did not wait on a lock",
      );
    }
    await delay(20);
    return poll();
  };
  return poll();
}

async function createRole(
  transaction: postgres.TransactionSql,
  roleID: string,
  eventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.create_tenant_role(
      ${roleID}::uuid,
      ${Buffer.alloc(32, 0x51)}::bytea,
      'concurrent_empty_role',
      'Concurrent empty role',
      'Idempotency serialization proof.',
      ARRAY[]::text[],
      ARRAY[]::public.authorization_scope[],
      ARRAY[]::text[],
      ARRAY[]::public.authorization_scope[],
      ${eventID}::uuid,
      '01993ea0-5000-7000-8000-000000000601'::uuid,
      '01993ea0-5000-7000-8000-000000000701'::uuid,
      '192.0.2.50'::inet,
      'Periapsis authorization concurrency proof',
      'totp'
    )
  `;
  assert(result, "create_tenant_role returned no result");
  return result;
}

async function suspendRecoveryFixture(
  transaction: postgres.TransactionSql,
  userID: string,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    UPDATE public.tenant_memberships AS membership
    SET status = 'suspended'::public.membership_status,
        updated_at = transaction_timestamp()
    WHERE membership.tenant_id = ${fixture.tenant}::uuid
      AND membership.user_id = ${userID}::uuid
  `;
}

async function grantRole(
  transaction: postgres.TransactionSql,
  grantID: string,
  digestByte: number,
  roleID: string,
  expiresAt: Date | null,
  eventID: string,
): Promise<MutationResult> {
  const [result] = await transaction<MutationResult[]>`
    SELECT *
    FROM app.grant_tenant_user_role(
      ${grantID}::uuid,
      ${Buffer.alloc(32, digestByte)}::bytea,
      ${fixture.secondUser}::uuid,
      ${roleID}::uuid,
      'Direct grant supersession audit proof.',
      ${expiresAt}::timestamptz,
      ${eventID}::uuid,
      '01993ea0-5000-7000-8000-000000000604'::uuid,
      '01993ea0-5000-7000-8000-000000000704'::uuid,
      '192.0.2.50'::inet,
      'Periapsis authorization concurrency proof',
      'totp'
    )
  `;
  assert(result, "grant_tenant_user_role returned no result");
  return result;
}

const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseURL, { max: 1, onnotice: () => undefined });
let releaseHeldTransaction: (() => void) | undefined;

try {
  const existing = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenants
    WHERE id = ${fixture.tenant}::uuid OR slug = 'authorization-concurrency'
  `;
  assert.equal(
    existing[0]?.count,
    0,
    "authorization concurrency proof requires a fresh disposable database",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES (
        ${fixture.tenant}::uuid,
        'authorization-concurrency',
        'Authorization concurrency proof'
      )
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.firstUser}::uuid, 'authorization.concurrent.a@example.invalid', 'Concurrent admin A'),
        (${fixture.secondUser}::uuid, 'authorization.concurrent.b@example.invalid', 'Concurrent admin B')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      )
      VALUES
        (${fixture.firstMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.firstUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.secondMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.secondUser}::uuid, 'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,
        ${fixture.firstMembership}::uuid
      )
    `;
  });

  const winnerReady = Promise.withResolvers<void>();
  const releaseWinner = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseWinner.resolve;
  const contenderPID = Promise.withResolvers<number>();

  const winnerCreate = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.firstUser);
    const result = await createRole(
      transaction,
      fixture.winnerRole,
      "01993ea0-5000-7000-8000-000000000501",
    );
    winnerReady.resolve();
    await releaseWinner.promise;
    return result;
  });
  const winnerCreateOutcome = winnerCreate.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    winnerReady.promise,
    "winning create did not acquire its lock",
  );

  const contenderCreate = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.firstUser);
    contenderPID.resolve(await backendPID(transaction));
    return createRole(
      transaction,
      fixture.contenderRole,
      "01993ea0-5000-7000-8000-000000000502",
    );
  });
  const contenderCreateOutcome = contenderCreate.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );

  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        contenderPID.promise,
        "contending create did not start",
      ),
    );
  } finally {
    releaseWinner.resolve();
    releaseHeldTransaction = undefined;
  }

  const firstCreate = await withTimeout(
    winnerCreateOutcome,
    "winning create did not commit",
  );
  const secondCreate = await withTimeout(
    contenderCreateOutcome,
    "contending create did not replay",
  );
  assert("result" in firstCreate, "winning create failed");
  assert("result" in secondCreate, "contending create failed");
  assert.equal(firstCreate.result.result_resource_id, fixture.winnerRole);
  assert.equal(firstCreate.result.result_version, 1);
  assert.equal(firstCreate.result.replayed, false);
  assert.equal(secondCreate.result.result_resource_id, fixture.winnerRole);
  assert.equal(secondCreate.result.result_version, 1);
  assert.equal(secondCreate.result.replayed, true);

  const { result: expiringGrant, expiresAt: expiringGrantExpiry } =
    await winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.firstUser);
      const expiresAt = new Date(Date.now() + 2_000);
      const result = await grantRole(
        transaction,
        fixture.expiringDirectGrant,
        0x53,
        fixture.winnerRole,
        expiresAt,
        "01993ea0-5000-7000-8000-000000000510",
      );
      return { expiresAt, result };
    });
  assert.deepEqual(expiringGrant, {
    result_resource_id: fixture.expiringDirectGrant,
    result_version: 1,
    replayed: false,
  });

  await delay(Math.max(0, expiringGrantExpiry.getTime() - Date.now() + 100));

  const replacementGrant = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.firstUser);
    return grantRole(
      transaction,
      fixture.replacementDirectGrant,
      0x54,
      fixture.winnerRole,
      null,
      "01993ea0-5000-7000-8000-000000000511",
    );
  });
  assert.deepEqual(replacementGrant, {
    result_resource_id: fixture.replacementDirectGrant,
    result_version: 1,
    replayed: false,
  });

  const replayedReplacement = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.firstUser);
    return grantRole(
      transaction,
      fixture.replayDirectGrantAttempt,
      0x54,
      fixture.winnerRole,
      null,
      "01993ea0-5000-7000-8000-000000000512",
    );
  });
  assert.deepEqual(replayedReplacement, {
    result_resource_id: fixture.replacementDirectGrant,
    result_version: 1,
    replayed: true,
  });

  const [supersededGrant] = await admin<
    { version: number; revoked: boolean; revoke_reason: string | null }[]
  >`
    SELECT version,
           revoked_at IS NOT NULL AS revoked,
           revoke_reason
    FROM public.tenant_membership_role_grants
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.expiringDirectGrant}::uuid
  `;
  assert.deepEqual(supersededGrant, {
    version: 2,
    revoked: true,
    revoke_reason: "Superseded after the prior direct grant expired.",
  });

  const replacementAudits = await admin<{ superseded_role_grants: unknown }[]>`
    SELECT metadata -> 'superseded_role_grants' AS superseded_role_grants
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'tenant.role_grant.created'
      AND resource_id = ${fixture.replacementDirectGrant}::uuid
  `;
  assert.equal(replacementAudits.length, 1);
  const replacementAudit = replacementAudits[0];
  assert.deepEqual(replacementAudit?.superseded_role_grants, [
    {
      role_grant_id: fixture.expiringDirectGrant,
      prior_version: 1,
      result_version: 2,
    },
  ]);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.externalManualSource}::uuid,
        ${fixture.tenant}::uuid,
        'manual'::public.authorization_source_kind,
        'manual.external',
        false,
        true
      )
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.externalManualGrant}::uuid,
        ${fixture.tenant}::uuid,
        ${fixture.secondMembership}::uuid,
        ${fixture.winnerRole}::uuid,
        ${fixture.externalManualSource}::uuid,
        ${fixture.firstMembership}::uuid,
        'External manual owner boundary proof.'
      )
    `;
  });

  const compatibilityProjection = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.firstUser);
    const [current] = await transaction<
      { managed_by_authorization_api: boolean }[]
    >`
      SELECT managed_by_authorization_api
      FROM app.get_tenant_membership_role_grant_v2(
        ${fixture.externalManualGrant}::uuid
      )
    `;
    const [legacy] = await transaction<
      { grant_id: string; source_type: string; version: number }[]
    >`
      SELECT grant_id, source_type, version
      FROM app.get_tenant_membership_role_grant(
        ${fixture.externalManualGrant}::uuid
      )
    `;
    const [legacyAuthority] = await transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM app.resolve_current_tenant_human_role_grants(201)
    `;
    return { current, legacy, legacyAuthority };
  });
  assert.deepEqual(compatibilityProjection.current, {
    managed_by_authorization_api: false,
  });
  assert.deepEqual(compatibilityProjection.legacy, {
    grant_id: fixture.externalManualGrant,
    source_type: "direct",
    version: 1,
  });
  assert.equal(compatibilityProjection.legacyAuthority?.count, 1);

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.firstUser);
      await transaction`
        SELECT app.revoke_tenant_user_role_grant(
          ${fixture.externalManualGrant}::uuid,
          1,
          'The canonical direct API must not own this edge.',
          '01993ea0-5000-7000-8000-000000000513'::uuid,
          '01993ea0-5000-7000-8000-000000000613'::uuid,
          '01993ea0-5000-7000-8000-000000000713'::uuid,
          '192.0.2.50'::inet,
          'Periapsis authorization ownership proof',
          'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const [externalManualEdge] = await admin<
    { version: number; revoked: boolean; revoke_audits: number }[]
  >`
    SELECT role_grant.version,
           role_grant.revoked_at IS NOT NULL AS revoked,
           count(audit.id)::integer AS revoke_audits
    FROM public.tenant_membership_role_grants AS role_grant
    LEFT JOIN public.audit_events AS audit
      ON audit.tenant_id = role_grant.tenant_id
     AND audit.action = 'tenant.role_grant.revoked'
     AND audit.resource_id = role_grant.id
    WHERE role_grant.tenant_id = ${fixture.tenant}::uuid
      AND role_grant.id = ${fixture.externalManualGrant}::uuid
    GROUP BY role_grant.version, role_grant.revoked_at
  `;
  assert.deepEqual(externalManualEdge, {
    version: 1,
    revoked: false,
    revoke_audits: 0,
  });

  const [adminRole] = await admin<{ id: string }[]>`
    SELECT id
    FROM public.tenant_roles
    WHERE tenant_id = ${fixture.tenant}::uuid AND key = 'tenant_admin'
  `;
  assert(adminRole, "protected tenant_admin role is missing");

  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.firstUser);
      await transaction`
        SELECT *
        FROM app.grant_tenant_user_role(
          ${fixture.secondAdminGrant}::uuid,
          ${Buffer.alloc(32, 0x52)}::bytea,
          ${fixture.secondUser}::uuid,
          ${adminRole.id}::uuid,
          'Legacy recovery administrator grant must fail closed.',
          NULL,
          '01993ea0-5000-7000-8000-000000000503'::uuid,
          '01993ea0-5000-7000-8000-000000000603'::uuid,
          '01993ea0-5000-7000-8000-000000000703'::uuid,
          '192.0.2.50'::inet,
          'Periapsis authorization concurrency proof',
          'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  // tenant_admin now carries service-principal administration policy. The
  // rolling-compatible human-role ABI must not mutate it, so this fixture-only
  // edge is installed by the migration owner before exercising the independent
  // recovery-administrator suspension race below.
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT ${fixture.secondAdminGrant}::uuid,
             ${fixture.tenant}::uuid,
             ${fixture.secondMembership}::uuid,
             ${adminRole.id}::uuid,
             source.id,
             ${fixture.firstMembership}::uuid,
             'Fixture for concurrent recovery administrator proof.'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.key = 'manual'
        AND source.kind = 'manual'
        AND source.protected
        AND source.retired_at IS NULL
    `;
  });

  const suspensionReady = Promise.withResolvers<void>();
  const releaseSuspension = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseSuspension.resolve;
  const suspensionContenderPID = Promise.withResolvers<number>();

  const winnerSuspension = winner.begin(async (transaction) => {
    await suspendRecoveryFixture(transaction, fixture.firstUser);
    suspensionReady.resolve();
    await releaseSuspension.promise;
  });
  const winnerSuspensionOutcome = winnerSuspension.then(
    () => ({ committed: true as const }),
    (error: unknown) => ({ error }),
  );
  await withTimeout(
    Promise.race([
      suspensionReady.promise,
      winnerSuspensionOutcome.then((outcome) => {
        if ("error" in outcome) {
          throw outcome.error;
        }
      }),
    ]),
    "winning recovery-admin suspension did not acquire its lock",
  );

  const contenderSuspension = contender.begin(async (transaction) => {
    suspensionContenderPID.resolve(await backendPID(transaction));
    await suspendRecoveryFixture(transaction, fixture.secondUser);
  });
  const contenderSuspensionOutcome = contenderSuspension.then(
    () => ({ committed: true as const }),
    (error: unknown) => ({ error }),
  );

  try {
    await waitForRowLock(
      admin,
      await withTimeout(
        suspensionContenderPID.promise,
        "contending recovery-admin suspension did not start",
      ),
    );
  } finally {
    releaseSuspension.resolve();
    releaseHeldTransaction = undefined;
  }

  const firstSuspension = await withTimeout(
    winnerSuspensionOutcome,
    "winning recovery-admin suspension did not commit",
  );
  assert("committed" in firstSuspension);

  const secondSuspension = await withTimeout(
    contenderSuspensionOutcome,
    "contending recovery-admin suspension did not finish",
  );
  assert(
    "error" in secondSuspension,
    "both concurrent recovery administrators were suspended",
  );
  assertSqlState(secondSuspension.error, "23514");

  const [activeRecovery] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_membership_role_grants AS role_grant
    JOIN public.tenant_roles AS role
      ON role.tenant_id = role_grant.tenant_id
     AND role.id = role_grant.role_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = role_grant.tenant_id
     AND membership.id = role_grant.membership_id
    WHERE role_grant.tenant_id = ${fixture.tenant}::uuid
      AND role.key = 'tenant_admin'
      AND role_grant.revoked_at IS NULL
      AND role_grant.expires_at IS NULL
      AND membership.status = 'active'
  `;
  assert.equal(activeRecovery?.count, 1);

  process.stdout.write(
    "tenant authorization idempotency and recovery-admin concurrency checks passed\n",
  );
} finally {
  releaseHeldTransaction?.();
  await Promise.allSettled([admin.end(), winner.end(), contender.end()]);
}
