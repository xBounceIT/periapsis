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
import postgres from "postgres";

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
  process.env.PERIAPSIS_TENANT_MEMBERSHIP_LIFECYCLE_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_MEMBERSHIP_LIFECYCLE_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d4d13-1200-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  actorUser: uuid(2),
  targetUser: uuid(3),
  actorMembership: uuid(4),
  targetMembership: uuid(5),
  actorLoginIdentifier: uuid(6),
  targetLoginIdentifier: uuid(7),
  actorCredential: uuid(8),
  targetCredential: uuid(9),
  actorSession: uuid(10),
  actorFamily: uuid(11),
  typedZombieSession: uuid(12),
  typedZombieFamily: uuid(13),
  platformSession: uuid(14),
  platformFamily: uuid(15),
  pendingZombieContinuation: uuid(16),
  audit: uuid(17),
  request: uuid(18),
  correlation: uuid(19),
} as const;

function digest(label: string): Buffer {
  return createHash("sha256").update(`membership-upgrade:${label}`).digest();
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const lifecycleJournalIndex = journal.entries.findIndex(
  (entry) => entry.tag === "0212_tenant_membership_lifecycle",
);
const predecessorEntries =
  lifecycleJournalIndex < 0
    ? journal.entries
    : journal.entries.slice(0, lifecycleJournalIndex);
assert(
  predecessorEntries.some(
    (entry) => entry.tag === "0209_ticket_comment_aggregate_guard_v48",
  ),
  "membership lifecycle upgrade proof requires the sealed 0209 predecessor",
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-membership-lifecycle-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

try {
  const [server] = await sql<{ major: number }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major
  `;
  assert.equal(server?.major, 18, "upgrade proof requires PostgreSQL 18");

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

  const createdAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
  const actorEmail = "membership-upgrade-actor@example.invalid";
  const targetEmail = "membership-upgrade-target@example.invalid";
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES (${fixture.tenant}::uuid,'membership-lifecycle-upgrade',
        'Membership lifecycle upgrade','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (
        id,email,display_name,active,created_at,updated_at
      ) VALUES
        (${fixture.actorUser}::uuid,${actorEmail},
          'Membership upgrade actor',true,${createdAt},${createdAt}),
        (${fixture.targetUser}::uuid,${targetEmail},
          'Membership upgrade target',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES
        (${fixture.actorMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.actorUser}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${fixture.targetMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.targetUser}::uuid,'customer_user','active',${createdAt},${createdAt})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.actorMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.user_login_identifiers (
        id,user_id,kind,canonical_value,verified_at,created_at,updated_at
      ) VALUES
        (${fixture.actorLoginIdentifier}::uuid,${fixture.actorUser}::uuid,
          'local_email',${actorEmail},${createdAt},${createdAt},${createdAt}),
        (${fixture.targetLoginIdentifier}::uuid,${fixture.targetUser}::uuid,
          'local_email',${targetEmail},${createdAt},${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.local_break_glass_credentials (
        id,user_id,login_identifier_id,password_phc,password_version,
        changed_at,created_at,updated_at
      ) VALUES
        (${fixture.actorCredential}::uuid,${fixture.actorUser}::uuid,
          ${fixture.actorLoginIdentifier}::uuid,
          '$argon2id$v=19$m=65536,t=3,p=1$dXBncmFkZQ$bm90LWEtcmVhbC1zZWNyZXQ',
          1,${createdAt},${createdAt},${createdAt}),
        (${fixture.targetCredential}::uuid,${fixture.targetUser}::uuid,
          ${fixture.targetLoginIdentifier}::uuid,
          '$argon2id$v=19$m=65536,t=3,p=1$dXBncmFkZTI$bm90LWEtcmVhbC1zZWNyZXQ',
          1,${createdAt},${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.targetUser}::uuid,
        ${digest("target-handle")}::bytea,1,1,1,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,last_seen_at,idle_expires_at,
        absolute_expires_at,created_at
      ) VALUES
        (${fixture.actorSession}::uuid,${fixture.actorUser}::uuid,
          ${fixture.actorFamily}::uuid,${fixture.tenant}::uuid,
          ${digest("actor-token")}::bytea,${digest("actor-csrf")}::bytea,
          'totp',${createdAt},${expiresAt},${expiresAt},${createdAt}),
        (${fixture.typedZombieSession}::uuid,${fixture.targetUser}::uuid,
          ${fixture.typedZombieFamily}::uuid,${fixture.tenant}::uuid,
          ${digest("typed-token")}::bytea,${digest("typed-csrf")}::bytea,
          'totp',${createdAt},${expiresAt},${expiresAt},${createdAt}),
        (${fixture.platformSession}::uuid,${fixture.targetUser}::uuid,
          ${fixture.platformFamily}::uuid,NULL,
          ${digest("platform-token")}::bytea,${digest("platform-csrf")}::bytea,
          'totp',${createdAt},${expiresAt},${expiresAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,
        session_invalidation_epoch,issued_at
      ) VALUES (${fixture.typedZombieSession}::uuid,${fixture.tenant}::uuid,
        ${fixture.targetUser}::uuid,1,1,false,'tenant-console',
        'local_credential',1,${createdAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_local_credential_provenance (
        tenant_id,session_id,user_id,credential_id,credential_revision,
        authenticated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.typedZombieSession}::uuid,
        ${fixture.targetUser}::uuid,${fixture.targetCredential}::uuid,1,
        ${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,local_credential_id,primary_revision,
        session_invalidation_epoch,state,version,created_at,expires_at
      ) VALUES (${fixture.pendingZombieContinuation}::uuid,
        ${fixture.tenant}::uuid,${fixture.targetUser}::uuid,
        ${digest("pending-continuation")}::bytea,1,'session.create',
        'tenant-console','local_credential',${fixture.targetCredential}::uuid,
        1,1,'pending',1,${createdAt},${expiresAt})
    `;
  });

  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.actorUser},true)
    `;
    await transaction`
      SELECT app.set_tenant_user_membership_status(
        ${fixture.targetUser}::uuid,'suspended'::public.membership_status,
        ${fixture.audit}::uuid,${fixture.request}::uuid,
        ${fixture.correlation}::uuid,'198.51.100.42'::inet,
        'Periapsis membership lifecycle upgrade proof','totp'
      )
    `;
  });

  const [predecessorZombie] = await sql<
    {
      membershipStatus: string;
      typedSessionLive: boolean;
      actorSessionLive: boolean;
      platformSessionLive: boolean;
      continuationState: string;
    }[]
  >`
    SELECT membership.status::text AS "membershipStatus",
      typed_session.revoked_at IS NULL AS "typedSessionLive",
      actor_session.revoked_at IS NULL AS "actorSessionLive",
      platform_session.revoked_at IS NULL AS "platformSessionLive",
      continuation.state AS "continuationState"
    FROM public.tenant_memberships AS membership
    JOIN public.auth_sessions AS typed_session
      ON typed_session.id=${fixture.typedZombieSession}::uuid
    JOIN public.auth_sessions AS actor_session
      ON actor_session.id=${fixture.actorSession}::uuid
    JOIN public.auth_sessions AS platform_session
      ON platform_session.id=${fixture.platformSession}::uuid
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id=${fixture.pendingZombieContinuation}::uuid
    WHERE membership.id=${fixture.targetMembership}::uuid
  `;
  assert.deepEqual(predecessorZombie, {
    membershipStatus: "suspended",
    typedSessionLive: true,
    actorSessionLive: true,
    platformSessionLive: true,
    continuationState: "pending",
  });

  const migrationSource = await readFile(
    resolve(migrationsRoot, "0212_tenant_membership_lifecycle.sql"),
    "utf8",
  );
  await sql.begin((transaction) => transaction.unsafe(migrationSource));

  const [upgraded] = await sql<
    {
      targetRevision: number;
      actorReason: string;
      typedReason: string;
      typedStateCount: number;
      platformLive: boolean;
      continuationState: string;
      continuationVersion: number;
      continuationReason: string;
      inactiveSessionZombies: number;
      inactiveContinuationZombies: number;
      ledgerOwner: string;
    }[]
  >`
    SELECT membership.lifecycle_revision AS "targetRevision",
      actor_session.revoke_reason AS "actorReason",
      typed_session.revoke_reason AS "typedReason",
      (SELECT count(*)::integer FROM public.auth_session_mfa_states
       WHERE session_id=${fixture.typedZombieSession}::uuid) AS "typedStateCount",
      platform_session.revoked_at IS NULL AS "platformLive",
      continuation.state AS "continuationState",
      continuation.version::integer AS "continuationVersion",
      continuation.revoke_reason AS "continuationReason",
      (SELECT count(*)::integer FROM public.auth_sessions AS session
       WHERE session.active_tenant_id IS NOT NULL AND session.revoked_at IS NULL
         AND NOT EXISTS (
           SELECT 1 FROM public.tenants AS tenant
           JOIN public.tenant_memberships AS member
             ON member.tenant_id=tenant.id AND member.user_id=session.user_id
           JOIN public.users AS identity ON identity.id=member.user_id
           WHERE tenant.id=session.active_tenant_id AND tenant.status='active'
             AND member.status='active' AND identity.active
         )) AS "inactiveSessionZombies",
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations AS pending
       WHERE pending.state='pending' AND NOT EXISTS (
         SELECT 1 FROM public.tenants AS tenant
         JOIN public.tenant_memberships AS member
           ON member.tenant_id=tenant.id AND member.user_id=pending.user_id
         JOIN public.users AS identity ON identity.id=member.user_id
         WHERE tenant.id=pending.tenant_id AND tenant.status='active'
           AND member.status='active' AND identity.active
       )) AS "inactiveContinuationZombies",
      (SELECT pg_get_userbyid(relation.relowner)
       FROM pg_catalog.pg_class AS relation
       WHERE relation.oid=
         'public.tenant_membership_lifecycle_commands'::regclass)
        AS "ledgerOwner"
    FROM public.tenant_memberships AS membership
    JOIN public.auth_sessions AS actor_session
      ON actor_session.id=${fixture.actorSession}::uuid
    JOIN public.auth_sessions AS typed_session
      ON typed_session.id=${fixture.typedZombieSession}::uuid
    JOIN public.auth_sessions AS platform_session
      ON platform_session.id=${fixture.platformSession}::uuid
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id=${fixture.pendingZombieContinuation}::uuid
    WHERE membership.id=${fixture.targetMembership}::uuid
  `;
  assert.deepEqual(upgraded, {
    targetRevision: 1,
    actorReason: "untyped_tenant_session_membership_fence_upgrade",
    typedReason: "inactive_tenant_membership_fence_upgrade",
    typedStateCount: 1,
    platformLive: true,
    continuationState: "revoked",
    continuationVersion: 2,
    continuationReason: "inactive_tenant_membership_fence_upgrade",
    inactiveSessionZombies: 0,
    inactiveContinuationZombies: 0,
    ledgerOwner: "periapsis_migrator",
  });

  process.stdout.write(
    "tenant membership lifecycle pre-0212 typed-zombie upgrade checks passed\n",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
