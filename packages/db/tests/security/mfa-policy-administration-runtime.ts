import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };
type JsonObject = Record<string, postgres.JSONValue>;

const databaseUrl = process.env.PERIAPSIS_MFA_POLICY_ADMIN_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_MFA_POLICY_ADMIN_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18.6 database",
  );
}

const sql = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
const uuid = (sequence: number): string =>
  `019d7000-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
let sequence = 100;
const nextUuid = (): string => uuid((sequence += 1));
const digest = (label: string): Buffer =>
  createHash("sha256").update(`mfa-policy-runtime:${label}`).digest();
const noop = (): void => undefined;

const fixture = {
  platformUser: uuid(1),
  platformGrant: uuid(2),
  platformIdentifier: uuid(3),
  platformCredential: uuid(4),
  platformTotp: uuid(5),
  platformSession: uuid(6),
  platformFamily: uuid(7),
  tenant: uuid(10),
  tenantUser: uuid(11),
  tenantMembership: uuid(12),
  tenantIdentifier: uuid(13),
  tenantCredential: uuid(14),
  tenantGlobalTotp: uuid(15),
  tenantFactor: uuid(16),
  tenantSubject: uuid(17),
  tenantSession: uuid(18),
  tenantFamily: uuid(19),
  tenantPrimaryEvidence: uuid(20),
  tenantTotpEvidence: uuid(21),
  tenantGroup: uuid(22),
  tenantGroupMembership: uuid(23),
  unauthorizedUser: uuid(30),
  unauthorizedSession: uuid(31),
  unauthorizedFamily: uuid(32),
} as const;

const requirement = (
  level: "primary" | "mfa" | "phishing_resistant" = "primary",
  localRequired = true,
): JsonObject => ({
  level,
  localRequired,
  freshnessSeconds: 0,
  enrollmentDeadline: null,
});

const audit = (): JsonObject => ({
  eventId: nextUuid(),
  requestId: nextUuid(),
  correlationId: nextUuid(),
  ipAddress: "198.51.100.41",
  userAgent: "Periapsis MFA policy PostgreSQL runtime proof",
});

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function record(
  value: postgres.JSONValue | undefined,
  label: string,
): JsonObject {
  assert(isJsonObject(value), `${label} must be an object`);
  return value;
}

function isJsonObject(
  value: postgres.JSONValue | undefined,
): value is JsonObject {
  return (
    value !== undefined &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function stringValue(
  value: postgres.JSONValue | undefined,
  label: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

async function asApi<T>(
  userId: string,
  tenantId: string | null,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const wrapped = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    await transaction`
      SELECT set_config('app.user_id',${userId},true),
             set_config('app.tenant_id',${tenantId ?? ""},true),
             set_config('app.service_account_id','',true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

async function seed(): Promise<void> {
  const now = new Date();
  now.setMilliseconds(0);
  const expires = new Date(now.getTime() + 2 * 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (id,email,display_name,active,created_at,updated_at)
      VALUES
        (${fixture.platformUser}::uuid,'mfa-platform@example.invalid',
         'MFA platform administrator',true,${now},${now}),
        (${fixture.tenantUser}::uuid,'mfa-tenant@example.invalid',
         'MFA tenant administrator',true,${now},${now}),
        (${fixture.unauthorizedUser}::uuid,'mfa-denied@example.invalid',
         'MFA denied user',true,${now},${now})
    `;
    await transaction`
      INSERT INTO public.user_login_identifiers (
        id,user_id,kind,canonical_value,verified_at,created_at,updated_at
      ) VALUES
        (${fixture.platformIdentifier}::uuid,${fixture.platformUser}::uuid,
         'local_email','mfa-platform@example.invalid',${now},${now},${now}),
        (${fixture.tenantIdentifier}::uuid,${fixture.tenantUser}::uuid,
         'local_email','mfa-tenant@example.invalid',${now},${now},${now})
    `;
    await transaction`
      INSERT INTO public.local_break_glass_credentials (
        id,user_id,login_identifier_id,password_phc,password_version,
        changed_at,created_at,updated_at
      ) VALUES
        (${fixture.platformCredential}::uuid,${fixture.platformUser}::uuid,
         ${fixture.platformIdentifier}::uuid,
         '$argon2id$v=19$m=65536,t=3,p=1$YWJjZA$YWJjZGVmZ2hpamtsbW5vcA',
         1,${now},${now},${now}),
        (${fixture.tenantCredential}::uuid,${fixture.tenantUser}::uuid,
         ${fixture.tenantIdentifier}::uuid,
         '$argon2id$v=19$m=65536,t=3,p=1$YWJjZA$YWJjZGVmZ2hpamtsbW5vcA',
         1,${now},${now},${now})
    `;
    await transaction`
      INSERT INTO public.totp_credentials (
        id,user_id,secret_ciphertext,secret_nonce,secret_aad,key_version,
        confirmed_at,last_accepted_counter,security_revision,created_at,updated_at
      ) VALUES
        (${fixture.platformTotp}::uuid,${fixture.platformUser}::uuid,
         ${Buffer.alloc(32, 0x51)},${Buffer.alloc(12, 0x52)},${digest("platform-aad")},
         1,${now},1,1,${now},${now}),
        (${fixture.tenantGlobalTotp}::uuid,${fixture.tenantUser}::uuid,
         ${Buffer.alloc(32, 0x53)},${Buffer.alloc(12, 0x54)},${digest("tenant-aad")},
         1,${now},1,1,${now},${now})
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id,user_id,role_id,granted_by_user_id,granted_at
      )
      SELECT ${fixture.platformGrant}::uuid,${fixture.platformUser}::uuid,
             role.id,${fixture.platformUser}::uuid,${now}
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES (${fixture.tenant}::uuid,'mfa-policy-runtime','MFA policy runtime',
              'active',${now},${now})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES (${fixture.tenantMembership}::uuid,${fixture.tenant}::uuid,
                ${fixture.tenantUser}::uuid,'tenant_admin','active',${now},${now})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.tenantMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id,tenant_id,key,display_name,description,created_by_membership_id,
        created_at,updated_at
      ) VALUES (${fixture.tenantGroup}::uuid,${fixture.tenant}::uuid,
                'recovery_observer','Recovery observer','Recovery race proof',
                ${fixture.tenantMembership}::uuid,${now},${now})
    `;
    await transaction`
      INSERT INTO public.tenant_security_group_memberships (
        id,tenant_id,group_id,membership_id,source_id,granted_by_membership_id,
        grant_reason,granted_at,updated_at
      )
      SELECT ${fixture.tenantGroupMembership}::uuid,${fixture.tenant}::uuid,
             ${fixture.tenantGroup}::uuid,${fixture.tenantMembership}::uuid,
             source.id,${fixture.tenantMembership}::uuid,
             'Recovery race proof',${now},${now}
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = ${fixture.tenant}::uuid
        AND source.kind = 'tenant_creation' AND source.retired_at IS NULL
      ORDER BY source.id LIMIT 1
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.tenantUser}::uuid,
                ${digest("tenant-user-handle")},1,1,1,${now},${now})
    `;
    await transaction`
      INSERT INTO public.tenant_totp_factors (
        id,tenant_id,user_id,secret_envelope,key_version,last_accepted_counter,
        record_version,security_revision,status,confirmed_at,created_at,updated_at
      ) VALUES (${fixture.tenantFactor}::uuid,${fixture.tenant}::uuid,
                ${fixture.tenantUser}::uuid,${Buffer.alloc(32, 0x55)},1,-1,
                1,1,'active',${now},${now},${now})
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      ) VALUES
        (${fixture.platformSession}::uuid,${fixture.platformUser}::uuid,
         ${fixture.platformFamily}::uuid,NULL,${digest("platform-token")},
         ${digest("platform-csrf")},'totp',${now},${now},${expires},${expires},${now}),
        (${fixture.tenantSession}::uuid,${fixture.tenantUser}::uuid,
         ${fixture.tenantFamily}::uuid,${fixture.tenant}::uuid,${digest("tenant-token")},
         ${digest("tenant-csrf")},'totp',${now},${now},${expires},${expires},${now}),
        (${fixture.unauthorizedSession}::uuid,${fixture.unauthorizedUser}::uuid,
         ${fixture.unauthorizedFamily}::uuid,NULL,${digest("denied-token")},
         ${digest("denied-csrf")},'totp',${now},${now},${expires},${expires},${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,issued_at
      ) VALUES (${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,
                ${fixture.tenantUser}::uuid,1,1,false,'tenant-console',
                'local_credential',1,${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_local_credential_provenance (
        tenant_id,session_id,user_id,credential_id,credential_revision,authenticated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.tenantSession}::uuid,
                ${fixture.tenantUser}::uuid,${fixture.tenantCredential}::uuid,1,${now})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence (
        id,tenant_id,session_id,local_credential_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (${fixture.tenantPrimaryEvidence}::uuid,${fixture.tenant}::uuid,
                ${fixture.tenantSession}::uuid,${fixture.tenantCredential}::uuid,
                'primary','local_credential',${now},1)
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence (
        id,tenant_id,session_id,totp_factor_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (${fixture.tenantTotpEvidence}::uuid,${fixture.tenant}::uuid,
                ${fixture.tenantSession}::uuid,${fixture.tenantFactor}::uuid,
                'mfa','totp',${now},1)
    `;
  });
}

try {
  const [version] = await sql<{ version: number }[]>`
    SELECT current_setting('server_version_num')::integer AS version
  `;
  assert(version !== undefined && version.version >= 180_000);

  const [journal] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count,max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.equal(journal?.count, expectedMigrationCount);
  assert.equal(journal?.latest, String(expectedMigrationCreatedAt));

  await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).map(async (role) => {
      const [ready] = await sql.begin(async (transaction) => {
        await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
        return transaction<{ value: boolean }[]>`
          SELECT app.release_runtime_schema_readiness_v50() AS value
        `;
      });
      assert.equal(ready?.value, true);
    }),
  );

  const [initial] = await sql<{ floorCount: number; commandCount: number }[]>`
    SELECT
      (SELECT count(*)::integer FROM public.mfa_policy_revisions
       WHERE scope = 'platform_floor') AS "floorCount",
      (SELECT count(*)::integer FROM public.mfa_policy_commands) AS "commandCount"
  `;
  assert.deepEqual(initial, { floorCount: 0, commandCount: 0 });

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`INSERT INTO public.mfa_policy_commands DEFAULT VALUES`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await seed();

  await assert.rejects(
    asApi(
      fixture.unauthorizedUser,
      null,
      (transaction) => transaction`
      SELECT * FROM app.list_platform_mfa_policies_v1(
        ${fixture.unauthorizedSession}::uuid,'totp',NULL,NULL,50,false
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const unsafeSimulationRequest = {
    operation: "publish",
    target: { scope: "platform_floor" },
    expectedRevision: 0,
    requirement: requirement("phishing_resistant"),
  };
  const [unsafeSimulation] = await asApi(
    fixture.platformUser,
    null,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.simulate_platform_mfa_policy_change_v1(
        ${fixture.platformSession}::uuid,'totp',
        ${transaction.json(unsafeSimulationRequest)}::jsonb
      ) AS value
    `,
  );
  const unsafeRecovery = record(
    record(unsafeSimulation?.value, "platform simulation").recovery,
    "platform recovery",
  );
  assert.equal(unsafeRecovery.safe, false);
  assert.deepEqual(unsafeRecovery.reasonCodes, [
    "no_ready_local_phishing_resistant",
  ]);

  const platformCommandID = nextUuid();
  const platformFirstAudit = audit();
  const platformCommand = {
    commandId: platformCommandID,
    target: { scope: "platform_floor" },
    expectedRevision: 0,
    requirement: requirement(),
    reason: "Establish the explicit platform recovery floor",
    audit: platformFirstAudit,
  };
  const [platformCreated] = await asApi(
    fixture.platformUser,
    null,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.publish_platform_mfa_policy_v1(
        ${fixture.platformSession}::uuid,'totp',
        ${transaction.json(platformCommand)}::jsonb
      ) AS value
    `,
  );
  const platformCreatedResult = record(
    platformCreated?.value,
    "platform create",
  );
  assert.equal(platformCreatedResult.replayed, false);
  const platformPolicy = record(
    platformCreatedResult.policy,
    "platform policy",
  );
  assert.equal(platformPolicy.revision, 1);
  assert.match(
    stringValue(platformPolicy.createdAt, "platform createdAt"),
    /^\d{4}-\d{2}-\d{2}T.*\.\d{3}Z$/u,
  );

  const replayCommand = {
    ...platformCommand,
    audit: audit(),
  };
  const [platformReplay] = await asApi(
    fixture.platformUser,
    null,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.publish_platform_mfa_policy_v1(
        ${fixture.platformSession}::uuid,'totp',
        ${transaction.json(replayCommand)}::jsonb
      ) AS value
    `,
  );
  const platformReplayResult = record(platformReplay?.value, "platform replay");
  assert.equal(platformReplayResult.replayed, true);
  assert.deepEqual(platformReplayResult.policy, platformPolicy);

  const [platformAuditCount] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.platform_audit_events
    WHERE id = ${stringValue(platformFirstAudit.eventId, "platform audit event id")}::uuid
  `;
  assert.equal(platformAuditCount?.count, 1);

  await assert.rejects(
    asApi(
      fixture.platformUser,
      null,
      (transaction) => transaction`
      SELECT app.publish_platform_mfa_policy_v1(
        ${fixture.platformSession}::uuid,'totp',
        ${transaction.json({ ...replayCommand, reason: "Divergent semantic retry" })}::jsonb
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  await assert.rejects(
    asApi(
      fixture.platformUser,
      null,
      (transaction) => transaction`
      SELECT app.publish_platform_mfa_policy_v1(
        ${fixture.platformSession}::uuid,'totp',
        ${transaction.json({ ...platformCommand, commandId: nextUuid(), audit: audit() })}::jsonb
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  await assert.rejects(
    asApi(
      fixture.platformUser,
      null,
      (transaction) => transaction`
      SELECT * FROM app.list_platform_mfa_policies_v1(
        ${fixture.platformSession}::uuid,'totp',NULL,NULL,102,false
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const platformList = await asApi(
    fixture.platformUser,
    null,
    (transaction) => transaction<{ document: postgres.JSONValue }[]>`
      SELECT document FROM app.list_platform_mfa_policies_v1(
        ${fixture.platformSession}::uuid,'totp',NULL,NULL,101,false
      )
    `,
  );
  assert.equal(platformList.length, 1);

  const tenantContext = {
    roleIds: [],
    securityGroupIds: [],
    action: "identity_policy.manage",
  };
  const tenantTarget = {
    scope: "tenant_baseline",
    tenantId: fixture.tenant,
  };
  const tenantSimulationRequest = {
    operation: "publish",
    target: tenantTarget,
    expectedRevision: 0,
    requirement: requirement(),
    context: tenantContext,
  };
  const [tenantSimulation] = await asApi(
    fixture.tenantUser,
    fixture.tenant,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.simulate_tenant_mfa_policy_change_v1(
        ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
        ${transaction.json(tenantSimulationRequest)}::jsonb
      ) AS value
    `,
  );
  const tenantSimulationResult = record(
    tenantSimulation?.value,
    "tenant simulation",
  );
  assert.deepEqual(tenantSimulationResult.context, tenantContext);
  const effective = record(
    tenantSimulationResult.effective,
    "effective policy",
  );
  assert(Array.isArray(effective.sources));
  assert.equal(effective.sources.length, 2);
  assert.equal(
    record(tenantSimulationResult.recovery, "tenant recovery").safe,
    true,
  );

  const tenantCommandID = nextUuid();
  const tenantCommand = {
    commandId: tenantCommandID,
    target: tenantTarget,
    expectedRevision: 0,
    requirement: requirement(),
    reason: "Establish the explicit tenant baseline",
    audit: audit(),
  };
  const [tenantCreated] = await asApi(
    fixture.tenantUser,
    fixture.tenant,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.publish_tenant_mfa_policy_v1(
        ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
        ${transaction.json(tenantCommand)}::jsonb
      ) AS value
    `,
  );
  const tenantPolicy = record(
    record(tenantCreated?.value, "tenant create").policy,
    "tenant policy",
  );
  assert.equal(tenantPolicy.revision, 1);

  const tenantPolicyID = stringValue(tenantPolicy.id, "tenant policy id");
  const tenantReplace = {
    ...tenantCommand,
    commandId: nextUuid(),
    expectedRevision: 1,
    expectedPolicyId: tenantPolicyID,
    requirement: requirement("mfa"),
    reason: "Raise tenant baseline assurance",
    audit: audit(),
  };
  const [tenantReplaced] = await asApi(
    fixture.tenantUser,
    fixture.tenant,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.publish_tenant_mfa_policy_v1(
        ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
        ${transaction.json(tenantReplace)}::jsonb
      ) AS value
    `,
  );
  assert.equal(
    record(record(tenantReplaced?.value, "tenant replacement").policy, "policy")
      .revision,
    2,
  );

  await assert.rejects(
    asApi(
      fixture.tenantUser,
      fixture.tenant,
      (transaction) => transaction`
      SELECT app.publish_tenant_mfa_policy_v1(
        ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
        ${transaction.json({ ...tenantReplace, commandId: nextUuid(), audit: audit() })}::jsonb
      )
    `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const historical = await asApi(
    fixture.tenantUser,
    fixture.tenant,
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.get_tenant_mfa_policy_v1(
        ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
        ${tenantPolicyID}::uuid,1
      ) AS value
    `,
  );
  assert.equal(
    record(historical[0]?.value, "historical policy").status,
    "retired",
  );

  let releasePlatformPublisher = noop;
  let markPlatformPublisherStarted = noop;
  const platformPublisherStarted = new Promise<void>((resolve) => {
    markPlatformPublisherStarted = resolve;
  });
  const holdPlatformPublisher = new Promise<void>((resolve) => {
    releasePlatformPublisher = resolve;
  });
  const platformRaceCommand = {
    commandId: nextUuid(),
    target: { scope: "platform_floor" },
    expectedRevision: 1,
    expectedPolicyId: stringValue(platformPolicy.id, "platform policy id"),
    requirement: requirement("mfa"),
    reason: "Exercise recovery lifecycle serialization",
    audit: audit(),
  };
  const platformPublisher = asApi(
    fixture.platformUser,
    null,
    async (transaction) => {
      await transaction`
        SELECT app.publish_platform_mfa_policy_v1(
          ${fixture.platformSession}::uuid,'totp',
          ${transaction.json(platformRaceCommand)}::jsonb
        )
      `;
      markPlatformPublisherStarted();
      await holdPlatformPublisher;
    },
  );
  await platformPublisherStarted;
  let platformLifecycleSettled = false;
  const platformLifecycle = sql`
    UPDATE public.users SET active = false
    WHERE id = ${fixture.platformUser}::uuid
  `.then(() => {
    platformLifecycleSettled = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(
    platformLifecycleSettled,
    false,
    "platform lifecycle removal passed the recovery proof before commit",
  );
  releasePlatformPublisher();
  await Promise.all([platformPublisher, platformLifecycle]);

  let releaseTenantPublisher = noop;
  let markTenantPublisherStarted = noop;
  const tenantPublisherStarted = new Promise<void>((resolve) => {
    markTenantPublisherStarted = resolve;
  });
  const holdTenantPublisher = new Promise<void>((resolve) => {
    releaseTenantPublisher = resolve;
  });
  const tenantRaceCommand = {
    ...tenantReplace,
    commandId: nextUuid(),
    expectedRevision: 2,
    reason: "Exercise group membership serialization",
    audit: audit(),
  };
  const tenantPublisher = asApi(
    fixture.tenantUser,
    fixture.tenant,
    async (transaction) => {
      await transaction`
        SELECT app.publish_tenant_mfa_policy_v1(
          ${fixture.tenantSession}::uuid,${fixture.tenant}::uuid,'totp',
          ${transaction.json(tenantRaceCommand)}::jsonb
        )
      `;
      markTenantPublisherStarted();
      await holdTenantPublisher;
    },
  );
  await tenantPublisherStarted;
  let groupLifecycleSettled = false;
  const groupLifecycle = sql`
    UPDATE public.tenant_security_group_memberships
    SET revoked_at = transaction_timestamp(),
        revoked_by_membership_id = ${fixture.tenantMembership}::uuid,
        revoke_reason = 'Recovery race proof completed',
        version = version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.tenantGroupMembership}::uuid
      AND revoked_at IS NULL
  `.then(() => {
    groupLifecycleSettled = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(
    groupLifecycleSettled,
    false,
    "group membership removal passed the recovery proof before commit",
  );
  releaseTenantPublisher();
  await Promise.all([tenantPublisher, groupLifecycle]);

  const [finalCounts] = await sql<
    { revisions: number; commands: number; tenantAudits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.mfa_policy_revisions) AS revisions,
      (SELECT count(*)::integer FROM public.mfa_policy_commands) AS commands,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE action = 'tenant.identity_policy.published') AS "tenantAudits"
  `;
  assert.deepEqual(finalCounts, { revisions: 5, commands: 5, tenantAudits: 3 });
} finally {
  await sql.end();
}
