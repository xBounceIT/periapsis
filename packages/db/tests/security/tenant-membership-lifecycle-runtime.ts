import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql } from "postgres";

type ErrorWithCode = Error & { code?: string };

type LifecycleResult = {
  tenant_id: string;
  membership_id: string;
  target_user_id: string;
  previous_status: string;
  status: string;
  lifecycle_revision: number;
  updated_at: Date;
  revoked_session_count: number;
  revoked_continuation_count: number;
  replayed: boolean;
};

const databaseUrl =
  process.env.PERIAPSIS_TENANT_MEMBERSHIP_LIFECYCLE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_MEMBERSHIP_LIFECYCLE_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database with migration 0212 applied",
  );
}

const uuid = (sequence: number): string =>
  `019d4d12-1200-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const sequence = Date.now() * 100 + (process.pid % 100);
const fixture = {
  tenant: uuid(sequence + 1),
  foreignTenant: uuid(sequence + 2),
  actorUser: uuid(sequence + 3),
  targetUser: uuid(sequence + 4),
  foreignAdminUser: uuid(sequence + 5),
  actorMembership: uuid(sequence + 6),
  targetMembership: uuid(sequence + 7),
  foreignTargetMembership: uuid(sequence + 8),
  foreignAdminMembership: uuid(sequence + 9),
  targetLoginIdentifier: uuid(sequence + 10),
  targetCredential: uuid(sequence + 11),
  actorSession: uuid(sequence + 12),
  actorFamily: uuid(sequence + 13),
  targetLocalSession: uuid(sequence + 14),
  targetLocalFamily: uuid(sequence + 15),
  targetLdapSession: uuid(sequence + 16),
  targetLdapFamily: uuid(sequence + 17),
  targetFederatedSession: uuid(sequence + 18),
  targetFederatedFamily: uuid(sequence + 19),
  foreignSession: uuid(sequence + 20),
  foreignFamily: uuid(sequence + 21),
  platformSession: uuid(sequence + 22),
  platformFamily: uuid(sequence + 23),
  continuation: uuid(sequence + 24),
  expiredCommand: uuid(sequence + 25),
  raceSession: uuid(sequence + 26),
  raceFamily: uuid(sequence + 27),
  localRotateSource: uuid(sequence + 28),
  localRotateFamily: uuid(sequence + 29),
  localRotateSuccessor: uuid(sequence + 30),
  tenantSwitchSuccessor: uuid(sequence + 31),
  raceContinuation: uuid(sequence + 32),
} as const;

function digest(label: string): Buffer {
  return createHash("sha256").update(`${label}:${sequence}`).digest();
}

function eventID(offset: number): string {
  return uuid(sequence + 100 + offset);
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function withTimeout<T>(promise: Promise<T>, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), 15_000);
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
  tenantID: string,
  userID: string,
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

async function waitForLock(sql: Sql, processID: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  const poll = async (): Promise<void> => {
    const [activity] = await sql<
      { wait_event_type: string | null; wait_event: string | null }[]
    >`
      SELECT wait_event_type,wait_event
      FROM pg_catalog.pg_stat_activity
      WHERE pid=${processID}
    `;
    if (activity?.wait_event_type === "Lock") return;
    if (Date.now() >= deadline) {
      throw new Error("membership lifecycle contender did not wait on a lock");
    }
    await delay(20);
    return poll();
  };
  return poll();
}

async function changeMembership(
  transaction: postgres.TransactionSql,
  input: {
    targetUserID: string;
    targetStatus: "active" | "suspended";
    expectedRevision: number;
    reason: string;
    keyDigest: Buffer;
    traceOffset: number;
  },
): Promise<LifecycleResult> {
  const [result] = await transaction<LifecycleResult[]>`
    SELECT tenant_id,membership_id,target_user_id,previous_status::text,
           status::text,lifecycle_revision,updated_at,
           revoked_session_count,revoked_continuation_count,replayed
    FROM app.change_tenant_membership_lifecycle_v1(
      ${fixture.actorSession}::uuid,
      ${input.targetUserID}::uuid,
      ${input.targetStatus}::public.membership_status,
      ${input.expectedRevision},
      ${input.reason},
      ${input.keyDigest}::bytea,
      ${eventID(input.traceOffset)}::uuid,
      ${eventID(input.traceOffset + 1)}::uuid,
      ${eventID(input.traceOffset + 2)}::uuid,
      '198.51.100.42'::inet,
      'Periapsis membership lifecycle runtime proof',
      'totp'
    )
  `;
  assert(result, "membership lifecycle command returned no receipt");
  return result;
}

async function insertSession(
  transaction: postgres.TransactionSql,
  input: {
    id: string;
    userID: string;
    familyID: string;
    tenantID: string | null;
    method: "totp" | "ldap" | "oidc";
    label: string;
    createdAt: Date;
  },
): Promise<void> {
  const idleExpiresAt = new Date(input.createdAt.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(
    input.createdAt.getTime() + 2 * 60 * 60_000,
  );
  await transaction`
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,last_seen_at,idle_expires_at,
      absolute_expires_at,created_at
    ) VALUES (
      ${input.id}::uuid,${input.userID}::uuid,${input.familyID}::uuid,
      ${input.tenantID}::uuid,${digest(`${input.label}:token`)}::bytea,
      ${digest(`${input.label}:csrf`)}::bytea,${input.method},${input.createdAt},
      ${idleExpiresAt},${absoluteExpiresAt},${input.createdAt}
    )
  `;
}

async function rotateLocalSession(
  transaction: postgres.TransactionSql,
  traceOffset: number,
): Promise<string | null> {
  const now = Date.now();
  const [result] = await transaction<{ id: string | null }[]>`
    SELECT app.rotate_auth_session(
      ${digest("local-rotate-source:token")}::bytea,
      ${fixture.localRotateSuccessor}::uuid,
      ${digest("local-rotate-successor:token")}::bytea,
      ${digest("local-rotate-successor:csrf")}::bytea,
      ${new Date(now + 20 * 60_000)},${new Date(now + 40 * 60_000)},
      ${eventID(traceOffset)}::uuid,${eventID(traceOffset + 1)}::uuid,
      ${eventID(traceOffset + 2)}::uuid,'198.51.100.42'::inet,
      'Periapsis local rotation membership race'
    ) AS id
  `;
  assert(result, "local rotation returned no result");
  return result.id;
}

async function rotatePlatformSessionIntoTenant(
  transaction: postgres.TransactionSql,
  traceOffset: number,
): Promise<string | null> {
  const now = Date.now();
  const [result] = await transaction<{ id: string | null }[]>`
    SELECT app.rotate_auth_session_tenant(
      ${digest("platform:token")}::bytea,
      ${fixture.tenantSwitchSuccessor}::uuid,
      ${digest("tenant-switch-successor:token")}::bytea,
      ${digest("tenant-switch-successor:csrf")}::bytea,
      ${fixture.tenant}::uuid,
      ${new Date(now + 20 * 60_000)},${new Date(now + 40 * 60_000)},
      ${eventID(traceOffset)}::uuid,${eventID(traceOffset + 1)}::uuid,
      ${eventID(traceOffset + 2)}::uuid,'198.51.100.42'::inet,
      'Periapsis tenant switch membership race'
    ) AS id
  `;
  assert(result, "tenant-switch rotation returned no result");
  return result.id;
}

const admin = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const winner = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const creator = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
let releaseHeldTransaction: (() => void) | undefined;

try {
  const [server] = await admin<{ major: number; migration: boolean }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major,
           to_regprocedure(
             'app.change_tenant_membership_lifecycle_v1(uuid,uuid,public.membership_status,integer,text,bytea,uuid,uuid,uuid,inet,text,text)'
           ) IS NOT NULL AS migration
  `;
  assert.deepEqual(server, { major: 18, migration: true });

  const createdAt = new Date(Date.now() - 60_000);
  const existing = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.tenants
    WHERE id IN (${fixture.tenant}::uuid,${fixture.foreignTenant}::uuid)
  `;
  assert.equal(
    existing[0]?.count,
    0,
    "membership lifecycle runtime proof requires unused fixture identifiers",
  );

  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES
        (${fixture.tenant}::uuid,${`membership-lifecycle-${sequence.toString(36)}`},
          'Membership lifecycle runtime','active',${createdAt},${createdAt}),
        (${fixture.foreignTenant}::uuid,${`membership-lifecycle-foreign-${sequence.toString(36)}`},
          'Membership lifecycle foreign runtime','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (
        id,email,display_name,active,created_at,updated_at
      ) VALUES
        (${fixture.actorUser}::uuid,${`membership-actor-${sequence.toString(36)}@example.invalid`},
          'Membership lifecycle actor',true,${createdAt},${createdAt}),
        (${fixture.targetUser}::uuid,${`membership-target-${sequence.toString(36)}@example.invalid`},
          'Membership lifecycle target',true,${createdAt},${createdAt}),
        (${fixture.foreignAdminUser}::uuid,${`membership-foreign-${sequence.toString(36)}@example.invalid`},
          'Membership lifecycle foreign admin',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES
        (${fixture.actorMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.actorUser}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${fixture.targetMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.targetUser}::uuid,'customer_user','active',${createdAt},${createdAt}),
        (${fixture.foreignAdminMembership}::uuid,${fixture.foreignTenant}::uuid,
          ${fixture.foreignAdminUser}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${fixture.foreignTargetMembership}::uuid,${fixture.foreignTenant}::uuid,
          ${fixture.targetUser}::uuid,'customer_user','active',${createdAt},${createdAt})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.actorMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,${fixture.foreignAdminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.user_login_identifiers (
        id,user_id,kind,canonical_value,verified_at,created_at,updated_at
      ) VALUES (
        ${fixture.targetLoginIdentifier}::uuid,${fixture.targetUser}::uuid,
        'local_email',${`membership-target-${sequence.toString(36)}@example.invalid`},
        ${createdAt},${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.local_break_glass_credentials (
        id,user_id,login_identifier_id,password_phc,password_version,
        changed_at,created_at,updated_at
      ) VALUES (
        ${fixture.targetCredential}::uuid,${fixture.targetUser}::uuid,
        ${fixture.targetLoginIdentifier}::uuid,
        '$argon2id$v=19$m=65536,t=3,p=1$cnVudGltZQ$bm90LWEtcmVhbC1zZWNyZXQ',
        1,${createdAt},${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${fixture.targetUser}::uuid,
        ${digest("target-user-handle")}::bytea,1,1,1,${createdAt},${createdAt}
      )
    `;

    await insertSession(transaction, {
      id: fixture.actorSession,
      userID: fixture.actorUser,
      familyID: fixture.actorFamily,
      tenantID: fixture.tenant,
      method: "totp",
      label: "actor",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.targetLocalSession,
      userID: fixture.targetUser,
      familyID: fixture.targetLocalFamily,
      tenantID: fixture.tenant,
      method: "totp",
      label: "target-local",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.targetLdapSession,
      userID: fixture.targetUser,
      familyID: fixture.targetLdapFamily,
      tenantID: fixture.tenant,
      method: "ldap",
      label: "target-ldap",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.targetFederatedSession,
      userID: fixture.targetUser,
      familyID: fixture.targetFederatedFamily,
      tenantID: fixture.tenant,
      method: "oidc",
      label: "target-federated",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.foreignSession,
      userID: fixture.targetUser,
      familyID: fixture.foreignFamily,
      tenantID: fixture.foreignTenant,
      method: "ldap",
      label: "foreign-tenant",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.platformSession,
      userID: fixture.targetUser,
      familyID: fixture.platformFamily,
      tenantID: null,
      method: "totp",
      label: "platform",
      createdAt,
    });
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,local_credential_id,primary_revision,
        session_invalidation_epoch,state,version,created_at,expires_at
      ) VALUES (
        ${fixture.continuation}::uuid,${fixture.tenant}::uuid,
        ${fixture.targetUser}::uuid,${digest("target-continuation")}::bytea,1,
        'session.create','tenant-console','local_credential',
        ${fixture.targetCredential}::uuid,1,1,'pending',1,${createdAt},
        ${new Date(createdAt.getTime() + 60 * 60_000)}
      )
    `;
  });

  const unsafeReason = "password=correct-horse-battery-staple";
  const unsafeKey = digest("unsafe-reason-key");
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.tenant, fixture.actorUser);
      return changeMembership(transaction, {
        targetUserID: fixture.targetUser,
        targetStatus: "suspended",
        expectedRevision: 1,
        reason: unsafeReason,
        keyDigest: unsafeKey,
        traceOffset: 1,
      });
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const [unsafePersistence] = await admin<
    { receipts: number; audits: number; revision: number; status: string }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_membership_lifecycle_commands
       WHERE tenant_id=${fixture.tenant}::uuid AND key_digest=${unsafeKey}) AS receipts,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid AND reason=${unsafeReason}) AS audits,
      membership.lifecycle_revision AS revision,membership.status::text
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id=${fixture.tenant}::uuid
      AND membership.id=${fixture.targetMembership}::uuid
  `;
  assert.deepEqual(unsafePersistence, {
    receipts: 0,
    audits: 0,
    revision: 1,
    status: "active",
  });

  const sameReason = "Security review requires temporary access suspension.";
  const sameKey = digest("concurrent-same-payload-key");
  const winnerReady = Promise.withResolvers<void>();
  const releaseWinner = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseWinner.resolve;
  const contenderPID = Promise.withResolvers<number>();
  const winningChange = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    const result = await changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 1,
      reason: sameReason,
      keyDigest: sameKey,
      traceOffset: 10,
    });
    winnerReady.resolve();
    await releaseWinner.promise;
    return result;
  });
  await withTimeout(winnerReady.promise, "winning suspension did not apply");
  const replayingChange = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    contenderPID.resolve(await backendPID(transaction));
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 1,
      reason: sameReason,
      keyDigest: sameKey,
      traceOffset: 20,
    });
  });
  try {
    await waitForLock(
      admin,
      await withTimeout(contenderPID.promise, "replay contender did not start"),
    );
  } finally {
    releaseWinner.resolve();
    releaseHeldTransaction = undefined;
  }
  const [appliedSuspension, replayedSuspension] = await Promise.all([
    withTimeout(winningChange, "winning suspension did not commit"),
    withTimeout(replayingChange, "concurrent suspension did not replay"),
  ]);
  assert.equal(appliedSuspension.replayed, false);
  assert.equal(replayedSuspension.replayed, true);
  assert.deepEqual(
    { ...replayedSuspension, replayed: false },
    appliedSuspension,
    "same-payload replay was not the exact durable receipt",
  );
  assert.equal(appliedSuspension.revoked_session_count, 3);
  assert.equal(appliedSuspension.revoked_continuation_count, 1);

  const [suspendedState] = await admin<
    {
      status: string;
      revision: number;
      targetRevoked: number;
      targetReasonCount: number;
      continuationState: string;
      continuationVersion: number;
      foreignRevoked: boolean;
      platformRevoked: boolean;
      invalidationEpoch: number;
      subjectVersion: number;
      auditCount: number;
      auditReason: string;
    }[]
  >`
    SELECT membership.status::text,membership.lifecycle_revision AS revision,
      (SELECT count(*)::integer FROM public.auth_sessions AS session
       WHERE session.id IN (
         ${fixture.targetLocalSession}::uuid,${fixture.targetLdapSession}::uuid,
         ${fixture.targetFederatedSession}::uuid
       ) AND session.revoked_at IS NOT NULL) AS "targetRevoked",
      (SELECT count(*)::integer FROM public.auth_sessions AS session
       WHERE session.id IN (
         ${fixture.targetLocalSession}::uuid,${fixture.targetLdapSession}::uuid,
         ${fixture.targetFederatedSession}::uuid
       ) AND session.revoke_reason='tenant_membership_suspended') AS "targetReasonCount",
      continuation.state AS "continuationState",
      continuation.version::integer AS "continuationVersion",
      foreign_session.revoked_at IS NOT NULL AS "foreignRevoked",
      platform_session.revoked_at IS NOT NULL AS "platformRevoked",
      subject.session_invalidation_epoch::integer AS "invalidationEpoch",
      subject.version::integer AS "subjectVersion",
      count(audit.id)::integer AS "auditCount",max(audit.reason) AS "auditReason"
    FROM public.tenant_memberships AS membership
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id=${fixture.continuation}::uuid
    JOIN public.auth_sessions AS foreign_session
      ON foreign_session.id=${fixture.foreignSession}::uuid
    JOIN public.auth_sessions AS platform_session
      ON platform_session.id=${fixture.platformSession}::uuid
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id=membership.tenant_id
     AND subject.user_id=membership.user_id
    LEFT JOIN public.audit_events AS audit
      ON audit.tenant_id=membership.tenant_id
     AND audit.resource_id=membership.id
     AND audit.action='tenant.membership.suspended'
    WHERE membership.tenant_id=${fixture.tenant}::uuid
      AND membership.id=${fixture.targetMembership}::uuid
    GROUP BY membership.status,membership.lifecycle_revision,
      continuation.state,continuation.version,foreign_session.revoked_at,
      platform_session.revoked_at,subject.session_invalidation_epoch,
      subject.version
  `;
  assert.deepEqual(suspendedState, {
    status: "suspended",
    revision: 2,
    targetRevoked: 3,
    targetReasonCount: 3,
    continuationState: "revoked",
    continuationVersion: 2,
    foreignRevoked: false,
    platformRevoked: false,
    invalidationEpoch: 2,
    subjectVersion: 2,
    auditCount: 1,
    auditReason: sameReason,
  });

  const firstReactivation = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "active",
      expectedRevision: 2,
      reason: "The access review completed and reactivation is approved.",
      keyDigest: digest("first-reactivation-key"),
      traceOffset: 30,
    });
  });
  assert.equal(firstReactivation.lifecycle_revision, 3);
  assert.equal(firstReactivation.replayed, false);
  const [noZombieAfterReactivation] = await admin<
    {
      targetLive: number;
      continuationPending: boolean;
      invalidationEpoch: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.auth_sessions AS session
       WHERE session.id IN (
         ${fixture.targetLocalSession}::uuid,${fixture.targetLdapSession}::uuid,
         ${fixture.targetFederatedSession}::uuid
       ) AND session.revoked_at IS NULL) AS "targetLive",
      continuation.state='pending' AS "continuationPending",
      subject.session_invalidation_epoch::integer AS "invalidationEpoch"
    FROM public.tenant_post_primary_continuations AS continuation
    CROSS JOIN public.tenant_mfa_subjects AS subject
    WHERE continuation.id=${fixture.continuation}::uuid
      AND subject.tenant_id=${fixture.tenant}::uuid
      AND subject.user_id=${fixture.targetUser}::uuid
  `;
  assert.deepEqual(noZombieAfterReactivation, {
    targetLive: 0,
    continuationPending: false,
    invalidationEpoch: 2,
  });

  const reusedKey = digest("concurrent-different-payload-key");
  const mismatchWinnerReady = Promise.withResolvers<void>();
  const releaseMismatchWinner = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseMismatchWinner.resolve;
  const mismatchPID = Promise.withResolvers<number>();
  const firstMismatch = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    const result = await changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 3,
      reason: "The second access review requires suspension.",
      keyDigest: reusedKey,
      traceOffset: 40,
    });
    mismatchWinnerReady.resolve();
    await releaseMismatchWinner.promise;
    return result;
  });
  await withTimeout(
    mismatchWinnerReady.promise,
    "different-payload winner did not apply",
  );
  const secondMismatch = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    mismatchPID.resolve(await backendPID(transaction));
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 3,
      reason: "A different reason must not reuse the same command key.",
      keyDigest: reusedKey,
      traceOffset: 50,
    });
  });
  try {
    await waitForLock(
      admin,
      await withTimeout(mismatchPID.promise, "payload mismatch did not start"),
    );
  } finally {
    releaseMismatchWinner.resolve();
    releaseHeldTransaction = undefined;
  }
  const mismatchApplied = await withTimeout(
    firstMismatch,
    "different-payload winner did not commit",
  );
  assert.equal(mismatchApplied.lifecycle_revision, 4);
  await assert.rejects(
    withTimeout(secondMismatch, "different-payload contender did not finish"),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const secondReactivation = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "active",
      expectedRevision: 4,
      reason: "The second access review completed successfully.",
      keyDigest: digest("second-reactivation-key"),
      traceOffset: 60,
    });
  });
  assert.equal(secondReactivation.lifecycle_revision, 5);

  const selfSuspendKey = digest("last-admin-self-suspend-key");
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.tenant, fixture.actorUser);
      return changeMembership(transaction, {
        targetUserID: fixture.actorUser,
        targetStatus: "suspended",
        expectedRevision: 1,
        reason:
          "This must roll back because no recovery administrator remains.",
        keyDigest: selfSuspendKey,
        traceOffset: 70,
      });
    }),
    (error: unknown) => assertSqlState(error, "23514"),
  );
  const [selfRollback] = await admin<
    {
      status: string;
      revision: number;
      actorRevoked: boolean;
      receipts: number;
      audits: number;
    }[]
  >`
    SELECT membership.status::text,membership.lifecycle_revision AS revision,
      session.revoked_at IS NOT NULL AS "actorRevoked",
      (SELECT count(*)::integer
       FROM public.tenant_membership_lifecycle_commands
       WHERE tenant_id=${fixture.tenant}::uuid
         AND key_digest=${selfSuspendKey}) AS receipts,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND action='tenant.membership.suspended'
         AND resource_id=${fixture.actorMembership}::uuid) AS audits
    FROM public.tenant_memberships AS membership
    JOIN public.auth_sessions AS session ON session.id=${fixture.actorSession}::uuid
    WHERE membership.tenant_id=${fixture.tenant}::uuid
      AND membership.id=${fixture.actorMembership}::uuid
  `;
  assert.deepEqual(selfRollback, {
    status: "active",
    revision: 1,
    actorRevoked: false,
    receipts: 0,
    audits: 0,
  });

  const oldTransactionStarted = Promise.withResolvers<Date>();
  const creatorHasFence = Promise.withResolvers<Date>();
  const releaseCreator = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseCreator.resolve;
  const suspensionPID = Promise.withResolvers<number>();
  const raceSuspension = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    const [started] = await transaction<{ at: Date }[]>`
      SELECT transaction_timestamp() AS at
    `;
    assert(started);
    oldTransactionStarted.resolve(started.at);
    await creatorHasFence.promise;
    suspensionPID.resolve(await backendPID(transaction));
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 5,
      reason: "Concurrent session issuance must linearize before suspension.",
      keyDigest: digest("session-creator-race-key"),
      traceOffset: 80,
    });
  });
  const raceStartedAt = await withTimeout(
    oldTransactionStarted.promise,
    "race suspension transaction did not start",
  );
  await delay(25);
  const racingCreator = creator.begin(async (transaction) => {
    const [clock] = await transaction<{ at: Date }[]>`
      SELECT date_trunc('milliseconds',clock_timestamp()) AS at
    `;
    assert(clock);
    await insertSession(transaction, {
      id: fixture.raceSession,
      userID: fixture.targetUser,
      familyID: fixture.raceFamily,
      tenantID: fixture.tenant,
      method: "ldap",
      label: "race-ldap-session",
      createdAt: clock.at,
    });
    creatorHasFence.resolve(clock.at);
    await releaseCreator.promise;
    return clock.at;
  });
  const raceCreatedAt = await withTimeout(
    creatorHasFence.promise,
    "racing session creator did not acquire the common fence",
  );
  assert(raceCreatedAt.getTime() > raceStartedAt.getTime());
  try {
    await waitForLock(
      admin,
      await withTimeout(suspensionPID.promise, "race suspension did not start"),
    );
  } finally {
    releaseCreator.resolve();
    releaseHeldTransaction = undefined;
  }
  await withTimeout(racingCreator, "racing session creator did not commit");
  const raceReceipt = await withTimeout(
    raceSuspension,
    "race suspension did not finish",
  );
  assert.equal(raceReceipt.lifecycle_revision, 6);
  assert.equal(raceReceipt.revoked_session_count, 1);
  assert(raceReceipt.updated_at.getTime() >= raceCreatedAt.getTime());
  const [raceSession] = await admin<
    { createdAt: Date; revokedAt: Date; reason: string }[]
  >`
    SELECT created_at AS "createdAt",revoked_at AS "revokedAt",
           revoke_reason AS reason
    FROM public.auth_sessions WHERE id=${fixture.raceSession}::uuid
  `;
  assert(raceSession);
  assert(raceSession.revokedAt.getTime() >= raceSession.createdAt.getTime());
  assert.equal(raceSession.reason, "tenant_membership_suspended");

  const finalReactivation = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "active",
      expectedRevision: 6,
      reason: "Final runtime reactivation keeps all old tokens invalid.",
      keyDigest: digest("final-reactivation-key"),
      traceOffset: 90,
    });
  });
  assert.equal(finalReactivation.lifecycle_revision, 7);
  const [raceStillRevoked] = await admin<{ revoked: boolean }[]>`
    SELECT revoked_at IS NOT NULL AS revoked
    FROM public.auth_sessions WHERE id=${fixture.raceSession}::uuid
  `;
  assert.equal(raceStillRevoked?.revoked, true);

  const [localSourceClock] = await admin<{ at: Date }[]>`
    SELECT date_trunc('milliseconds',clock_timestamp()) AS at
  `;
  assert(localSourceClock);
  await admin.begin((transaction) =>
    insertSession(transaction, {
      id: fixture.localRotateSource,
      userID: fixture.targetUser,
      familyID: fixture.localRotateFamily,
      tenantID: fixture.tenant,
      method: "totp",
      label: "local-rotate-source",
      createdAt: localSourceClock.at,
    }),
  );
  const localRotationReady = Promise.withResolvers<string | null>();
  const releaseLocalRotation = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseLocalRotation.resolve;
  const localSuspensionPID = Promise.withResolvers<number>();
  const localRotation = creator.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.targetUser);
    const successor = await rotateLocalSession(transaction, 110);
    localRotationReady.resolve(successor);
    await releaseLocalRotation.promise;
    return successor;
  });
  assert.equal(
    await withTimeout(
      localRotationReady.promise,
      "local rotation did not acquire the membership fence",
    ),
    fixture.localRotateSuccessor,
  );
  const localRaceSuspension = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    localSuspensionPID.resolve(await backendPID(transaction));
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 7,
      reason: "A completed local rotation must be revoked by suspension.",
      keyDigest: digest("local-rotation-wins-key"),
      traceOffset: 120,
    });
  });
  try {
    await waitForLock(
      admin,
      await withTimeout(
        localSuspensionPID.promise,
        "local rotation race suspension did not start",
      ),
    );
  } finally {
    releaseLocalRotation.resolve();
    releaseHeldTransaction = undefined;
  }
  await withTimeout(localRotation, "local rotation did not commit");
  const localRaceReceipt = await withTimeout(
    localRaceSuspension,
    "local rotation race suspension did not finish",
  );
  assert.equal(localRaceReceipt.lifecycle_revision, 8);
  assert.equal(localRaceReceipt.revoked_session_count, 1);
  const [localRaceState] = await admin<
    { sourceReason: string; successorReason: string }[]
  >`
    SELECT source.revoke_reason AS "sourceReason",
           successor.revoke_reason AS "successorReason"
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${fixture.localRotateSuccessor}::uuid
    WHERE source.id=${fixture.localRotateSource}::uuid
  `;
  assert.deepEqual(localRaceState, {
    sourceReason: "rotated",
    successorReason: "tenant_membership_suspended",
  });

  const postLocalReactivation = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "active",
      expectedRevision: 8,
      reason: "Reactivation after the local rotation race is approved.",
      keyDigest: digest("post-local-race-reactivation-key"),
      traceOffset: 130,
    });
  });
  assert.equal(postLocalReactivation.lifecycle_revision, 9);

  const switchSuspensionReady = Promise.withResolvers<LifecycleResult>();
  const releaseSwitchSuspension = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseSwitchSuspension.resolve;
  const switchPID = Promise.withResolvers<number>();
  const switchWinningSuspension = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    const receipt = await changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 9,
      reason: "Suspension must prevent a later tenant-switch successor.",
      keyDigest: digest("tenant-switch-suspend-wins-key"),
      traceOffset: 140,
    });
    switchSuspensionReady.resolve(receipt);
    await releaseSwitchSuspension.promise;
    return receipt;
  });
  const heldSwitchReceipt = await withTimeout(
    switchSuspensionReady.promise,
    "tenant-switch race suspension did not apply",
  );
  assert.equal(heldSwitchReceipt.lifecycle_revision, 10);
  const blockedTenantSwitch = contender.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.targetUser);
    switchPID.resolve(await backendPID(transaction));
    return rotatePlatformSessionIntoTenant(transaction, 150);
  });
  try {
    await waitForLock(
      admin,
      await withTimeout(switchPID.promise, "tenant switch did not start"),
    );
  } finally {
    releaseSwitchSuspension.resolve();
    releaseHeldTransaction = undefined;
  }
  await withTimeout(
    switchWinningSuspension,
    "tenant-switch race suspension did not commit",
  );
  await assert.rejects(
    withTimeout(blockedTenantSwitch, "blocked tenant switch did not finish"),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [tenantSwitchState] = await admin<
    { successors: number; sourceRevoked: boolean }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${fixture.tenantSwitchSuccessor}::uuid) AS successors,
      source.revoked_at IS NOT NULL AS "sourceRevoked"
    FROM public.auth_sessions AS source
    WHERE source.id=${fixture.platformSession}::uuid
  `;
  assert.deepEqual(tenantSwitchState, {
    successors: 0,
    sourceRevoked: false,
  });

  const postSwitchReactivation = await winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "active",
      expectedRevision: 10,
      reason: "Reactivation after the rejected tenant switch is approved.",
      keyDigest: digest("post-switch-race-reactivation-key"),
      traceOffset: 160,
    });
  });
  assert.equal(postSwitchReactivation.lifecycle_revision, 11);

  const oldContinuationTransaction = Promise.withResolvers<Date>();
  const continuationHasFence = Promise.withResolvers<Date>();
  const releaseContinuation = Promise.withResolvers<void>();
  releaseHeldTransaction = releaseContinuation.resolve;
  const continuationSuspensionPID = Promise.withResolvers<number>();
  const continuationRaceSuspension = winner.begin(async (transaction) => {
    await setApiContext(transaction, fixture.tenant, fixture.actorUser);
    const [started] = await transaction<{ at: Date }[]>`
      SELECT transaction_timestamp() AS at
    `;
    assert(started);
    oldContinuationTransaction.resolve(started.at);
    await continuationHasFence.promise;
    continuationSuspensionPID.resolve(await backendPID(transaction));
    return changeMembership(transaction, {
      targetUserID: fixture.targetUser,
      targetStatus: "suspended",
      expectedRevision: 11,
      reason: "A completed continuation issue must be revoked by suspension.",
      keyDigest: digest("continuation-creator-race-key"),
      traceOffset: 170,
    });
  });
  const continuationTransactionStarted = await withTimeout(
    oldContinuationTransaction.promise,
    "continuation race suspension transaction did not start",
  );
  await delay(25);
  const racingContinuation = creator.begin(async (transaction) => {
    const [clock] = await transaction<{ at: Date }[]>`
      SELECT date_trunc('milliseconds',clock_timestamp()) AS at
    `;
    assert(clock);
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,local_credential_id,primary_revision,
        session_invalidation_epoch,state,version,created_at,expires_at
      )
      SELECT ${fixture.raceContinuation}::uuid,subject.tenant_id,
        subject.user_id,${digest("race-continuation")}::bytea,
        subject.identity_epoch,'session.create','tenant-console',
        'local_credential',${fixture.targetCredential}::uuid,1,
        subject.session_invalidation_epoch,'pending',1,${clock.at},
        ${new Date(clock.at.getTime() + 30 * 60_000)}
      FROM public.tenant_mfa_subjects AS subject
      WHERE subject.tenant_id=${fixture.tenant}::uuid
        AND subject.user_id=${fixture.targetUser}::uuid
    `;
    continuationHasFence.resolve(clock.at);
    await releaseContinuation.promise;
    return clock.at;
  });
  const continuationCreatedAt = await withTimeout(
    continuationHasFence.promise,
    "continuation creator did not acquire the common fence",
  );
  assert(
    continuationCreatedAt.getTime() > continuationTransactionStarted.getTime(),
  );
  try {
    await waitForLock(
      admin,
      await withTimeout(
        continuationSuspensionPID.promise,
        "continuation race suspension did not start",
      ),
    );
  } finally {
    releaseContinuation.resolve();
    releaseHeldTransaction = undefined;
  }
  await withTimeout(racingContinuation, "racing continuation did not commit");
  const continuationRaceReceipt = await withTimeout(
    continuationRaceSuspension,
    "continuation race suspension did not finish",
  );
  assert.equal(continuationRaceReceipt.lifecycle_revision, 12);
  assert.equal(continuationRaceReceipt.revoked_continuation_count, 1);
  const [continuationRaceState] = await admin<
    { state: string; reason: string; createdAt: Date; revokedAt: Date }[]
  >`
    SELECT state,revoke_reason AS reason,created_at AS "createdAt",
           revoked_at AS "revokedAt"
    FROM public.tenant_post_primary_continuations
    WHERE id=${fixture.raceContinuation}::uuid
  `;
  assert(continuationRaceState);
  assert.equal(continuationRaceState.state, "revoked");
  assert.equal(continuationRaceState.reason, "tenant_membership_suspended");
  assert(
    continuationRaceState.revokedAt.getTime() >=
      continuationRaceState.createdAt.getTime(),
  );

  const postContinuationReactivation = await winner.begin(
    async (transaction) => {
      await setApiContext(transaction, fixture.tenant, fixture.actorUser);
      return changeMembership(transaction, {
        targetUserID: fixture.targetUser,
        targetStatus: "active",
        expectedRevision: 12,
        reason: "Final reactivation preserves the revoked continuation.",
        keyDigest: digest("post-continuation-race-reactivation-key"),
        traceOffset: 180,
      });
    },
  );
  assert.equal(postContinuationReactivation.lifecycle_revision, 13);

  const [targetCurrent] = await admin<{ revision: number }[]>`
    SELECT lifecycle_revision AS revision
    FROM public.tenant_memberships
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.targetMembership}::uuid
  `;
  assert(targetCurrent);
  await admin`
    INSERT INTO public.tenant_membership_lifecycle_commands (
      id,tenant_id,actor_membership_id,target_membership_id,target_user_id,
      operation,key_digest,request_digest,expected_revision,previous_status,
      result_status,result_revision,result_updated_at,revoked_session_count,
      revoked_continuation_count,created_at,expires_at
    )
    SELECT ${fixture.expiredCommand}::uuid,membership.tenant_id,
      ${fixture.actorMembership}::uuid,membership.id,membership.user_id,
      'tenant_membership.reactivate',${digest("expired-command-key")}::bytea,
      ${digest("expired-command-request")}::bytea,
      membership.lifecycle_revision - 1,'suspended','active',
      membership.lifecycle_revision,membership.updated_at,0,0,
      membership.updated_at - interval '2 hours',
      membership.updated_at - interval '1 hour'
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id=${fixture.tenant}::uuid
      AND membership.id=${fixture.targetMembership}::uuid
  `;
  await assert.rejects(
    winner.begin(async (transaction) => {
      await setApiContext(transaction, fixture.tenant, fixture.actorUser);
      await transaction`
        SELECT *
        FROM app.prune_expired_tenant_membership_lifecycle_commands_v1(1)
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [pruned] = await winner.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    return transaction<
      { tenant_membership_lifecycle_commands_deleted: number }[]
    >`
      SELECT *
      FROM app.prune_expired_tenant_membership_lifecycle_commands_v1(1)
    `;
  });
  assert.equal(pruned?.tenant_membership_lifecycle_commands_deleted, 1);

  const [catalog] = await admin<
    {
      expiredReceipts: number;
      durableReceipts: number;
      inactiveSessionZombies: number;
      inactiveContinuationZombies: number;
      sessionTriggerEnabled: boolean;
      continuationTriggerEnabled: boolean;
      localRotateExecutable: boolean;
      tenantRotateExecutable: boolean;
      privateLocalExecutable: boolean;
      privateTenantExecutable: boolean;
      legacyWriterExecutable: boolean;
      workerPrunerExecutable: boolean;
      apiPrunerExecutable: boolean;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_membership_lifecycle_commands
       WHERE id=${fixture.expiredCommand}::uuid) AS "expiredReceipts",
      (SELECT count(*)::integer
       FROM public.tenant_membership_lifecycle_commands
       WHERE tenant_id=${fixture.tenant}::uuid) AS "durableReceipts",
      (SELECT count(*)::integer FROM public.auth_sessions AS session
       WHERE session.active_tenant_id IS NOT NULL AND session.revoked_at IS NULL
         AND NOT EXISTS (
           SELECT 1 FROM public.tenants AS tenant
           JOIN public.tenant_memberships AS membership
             ON membership.tenant_id=tenant.id
            AND membership.user_id=session.user_id
           JOIN public.users AS identity ON identity.id=membership.user_id
           WHERE tenant.id=session.active_tenant_id AND tenant.status='active'
             AND membership.status='active' AND identity.active
         )) AS "inactiveSessionZombies",
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations AS continuation
       WHERE continuation.state='pending' AND NOT EXISTS (
         SELECT 1 FROM public.tenants AS tenant
         JOIN public.tenant_memberships AS membership
           ON membership.tenant_id=tenant.id
          AND membership.user_id=continuation.user_id
         JOIN public.users AS identity ON identity.id=membership.user_id
         WHERE tenant.id=continuation.tenant_id AND tenant.status='active'
           AND membership.status='active' AND identity.active
       )) AS "inactiveContinuationZombies",
      EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid='public.auth_sessions'::regclass
          AND trigger.tgname='auth_sessions_tenant_membership_fence_v1'
          AND trigger.tgenabled='O' AND NOT trigger.tgisinternal)
        AS "sessionTriggerEnabled",
      EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid='public.tenant_post_primary_continuations'::regclass
          AND trigger.tgname='tenant_post_primary_membership_fence_v1'
          AND trigger.tgenabled='O' AND NOT trigger.tgisinternal)
        AS "continuationTriggerEnabled",
      has_function_privilege('periapsis_api',
        'app.rotate_auth_session(bytea,uuid,bytea,bytea,timestamptz,timestamptz,uuid,uuid,uuid,inet,text)'::regprocedure,
        'EXECUTE') AS "localRotateExecutable",
      has_function_privilege('periapsis_api',
        'app.rotate_auth_session_tenant(bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,uuid,uuid,uuid,inet,text)'::regprocedure,
        'EXECUTE') AS "tenantRotateExecutable",
      has_function_privilege('periapsis_api',
        'app.private_unfenced_rotate_auth_session_v1(bytea,uuid,bytea,bytea,timestamptz,timestamptz,uuid,uuid,uuid,inet,text)'::regprocedure,
        'EXECUTE') AS "privateLocalExecutable",
      has_function_privilege('periapsis_api',
        'app.private_unfenced_rotate_auth_session_tenant_v2(bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,uuid,uuid,uuid,inet,text)'::regprocedure,
        'EXECUTE') AS "privateTenantExecutable",
      has_function_privilege('periapsis_api',
        'app.set_tenant_user_membership_status(uuid,public.membership_status,uuid,uuid,uuid,inet,text,text)'::regprocedure,
        'EXECUTE') AS "legacyWriterExecutable",
      has_function_privilege('periapsis_worker',
        'app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)'::regprocedure,
        'EXECUTE') AS "workerPrunerExecutable",
      has_function_privilege('periapsis_api',
        'app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)'::regprocedure,
        'EXECUTE') AS "apiPrunerExecutable"
  `;
  assert.deepEqual(catalog, {
    expiredReceipts: 0,
    durableReceipts: 12,
    inactiveSessionZombies: 0,
    inactiveContinuationZombies: 0,
    sessionTriggerEnabled: true,
    continuationTriggerEnabled: true,
    localRotateExecutable: true,
    tenantRotateExecutable: true,
    privateLocalExecutable: false,
    privateTenantExecutable: false,
    legacyWriterExecutable: false,
    workerPrunerExecutable: true,
    apiPrunerExecutable: false,
  });

  process.stdout.write(
    "tenant membership lifecycle runtime, replay, race, audit, revocation, and pruning checks passed\n",
  );
} finally {
  releaseHeldTransaction?.();
  await Promise.allSettled([
    admin.end(),
    winner.end(),
    contender.end(),
    creator.end(),
  ]);
}
