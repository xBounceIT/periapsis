import assert from "node:assert/strict";

import postgres, { type Sql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_notifier" | "periapsis_worker";
type AccessReceipt = {
  tenant_id: string;
  membership_id: string;
  user_id: string;
  tenant_version: number;
  membership_revision: number;
  authorization_revision: string;
  authorized_at: Date;
  replayed: boolean;
};

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_TENANT_ACCESS_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_TENANT_ACCESS_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(databaseUrl, { max: 2, onnotice: () => undefined });
const contenderA = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const contenderB = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d3c20-5000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (value: number): Buffer => Buffer.alloc(32, value);

const fixture = {
  tenant: uuid(1),
  suspendedTenant: uuid(2),
  mainActor: uuid(3),
  deniedActor: uuid(4),
  customRoleActor: uuid(5),
  activeMemberActor: uuid(6),
  suspendedMemberActor: uuid(7),
  atomicActor: uuid(8),
  concurrentActor: uuid(9),
  tenantAdmin: uuid(10),
  victim: uuid(11),
  customRole: uuid(12),
  mainSession: uuid(13),
  staleSession: uuid(14),
  revokedSession: uuid(15),
  recoverySession: uuid(16),
  futureMfaSession: uuid(17),
  deniedSession: uuid(18),
  customRoleSession: uuid(19),
  activeMemberSession: uuid(20),
  suspendedMemberSession: uuid(21),
  atomicSession: uuid(22),
  concurrentSession: uuid(23),
  switchedSession: uuid(24),
  tenantAdminSession: uuid(25),
  tenantAdminMembership: uuid(26),
  victimMembership: uuid(27),
  activeExistingMembership: uuid(28),
  suspendedExistingMembership: uuid(29),
  mainMembership: uuid(30),
  mainRoleGrant: uuid(31),
  mainPlatformAudit: uuid(32),
  mainTenantAudit: uuid(33),
  mainRequest: uuid(34),
  mainCorrelation: uuid(35),
  replayMembership: uuid(36),
  replayRoleGrant: uuid(37),
  replayPlatformAudit: uuid(38),
  replayTenantAudit: uuid(39),
  replayRequest: uuid(40),
  replayCorrelation: uuid(41),
  atomicMembership: uuid(42),
  atomicRoleGrant: uuid(43),
  atomicTenantAudit: uuid(44),
  atomicRequest: uuid(45),
  atomicCorrelation: uuid(46),
  concurrentMembershipA: uuid(47),
  concurrentMembershipB: uuid(48),
  concurrentGrantA: uuid(49),
  concurrentGrantB: uuid(50),
  concurrentPlatformAuditA: uuid(51),
  concurrentPlatformAuditB: uuid(52),
  concurrentTenantAuditA: uuid(53),
  concurrentTenantAuditB: uuid(54),
  concurrentRequestA: uuid(55),
  concurrentRequestB: uuid(56),
  concurrentCorrelationA: uuid(57),
  concurrentCorrelationB: uuid(58),
  suspendTenantAudit: uuid(59),
  suspendTenantRequest: uuid(60),
  suspendTenantCorrelation: uuid(61),
  reactivateTenantAudit: uuid(62),
  reactivateTenantRequest: uuid(63),
  reactivateTenantCorrelation: uuid(64),
  switchAudit: uuid(65),
  switchRequest: uuid(66),
  switchCorrelation: uuid(67),
  victimSuspendAudit: uuid(68),
  victimSuspendRequest: uuid(69),
  victimSuspendCorrelation: uuid(70),
  selfSuspendAudit: uuid(71),
  selfSuspendRequest: uuid(72),
  selfSuspendCorrelation: uuid(73),
  nonUserAudit: uuid(74),
  mismatchedActorAudit: uuid(75),
  suspendedTenantAdminMembership: uuid(76),
} as const;

const mainKey = digest(201);
const concurrentKey = digest(202);

function assertSqlState(error: unknown, expected: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function asRole<T>(
  client: Sql,
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  context?: { tenant?: string; user?: string },
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    if (context?.tenant !== undefined) {
      await transaction`
        SELECT set_config('app.tenant_id', ${context.tenant}, true)
      `;
    }
    if (context?.user !== undefined) {
      await transaction`
        SELECT set_config('app.user_id', ${context.user}, true)
      `;
    }
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function authorizeAccess(
  client: Sql,
  input: {
    actor: string;
    session: string;
    tenant?: string;
    membership: string;
    roleGrant: string;
    expectedVersion?: number;
    reason?: string;
    key: Buffer;
    platformAudit: string;
    tenantAudit: string;
    request: string;
    correlation: string;
    authenticationMethod?: string;
  },
): Promise<AccessReceipt> {
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [receipt] = await transaction<AccessReceipt[]>`
        SELECT tenant_id,membership_id,user_id,tenant_version,
               membership_revision,authorization_revision::text,
               authorized_at,replayed
        FROM app.authorize_platform_tenant_access_v1(
          ${input.session}::uuid,
          ${input.tenant ?? fixture.tenant}::uuid,
          ${input.membership}::uuid,
          ${input.roleGrant}::uuid,
          ${input.expectedVersion ?? 1}::integer,
          ${input.reason ?? "IR-2026-0215 approved explicit tenant access"}::text,
          ${input.key}::bytea,
          ${input.platformAudit}::uuid,
          ${input.tenantAudit}::uuid,
          ${input.request}::uuid,
          ${input.correlation}::uuid,
          '198.51.100.215'::inet,
          'Periapsis platform tenant-access runtime proof',
          ${input.authenticationMethod ?? "totp"}::text
        )
      `;
      assert(receipt, "tenant-access command returned no receipt");
      return receipt;
    },
    { user: input.actor },
  );
}

async function changePlatformTenantLifecycle(input: {
  target: "active" | "suspended";
  expectedVersion: number;
  audit: string;
  request: string;
  correlation: string;
}): Promise<void> {
  await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      await transaction`
        SELECT *
        FROM app.change_platform_tenant_lifecycle(
          ${fixture.mainSession}::uuid,
          ${fixture.tenant}::uuid,
          ${input.target}::public.tenant_status,
          ${input.expectedVersion}::integer,
          'IR-2026-0215 tenant revision advance'::text,
          ${input.audit}::uuid,
          ${input.request}::uuid,
          ${input.correlation}::uuid,
          '198.51.100.215'::inet,
          'Periapsis platform tenant-access runtime proof',
          'totp'::text
        )
      `;
    },
    { user: fixture.mainActor },
  );
}

async function changeMembership(input: {
  actor: string;
  session: string;
  targetUser: string;
  expectedRevision: number;
  key: Buffer;
  audit: string;
  request: string;
  correlation: string;
}): Promise<void> {
  await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      await transaction`
        SELECT *
        FROM app.change_tenant_membership_lifecycle_v1(
          ${input.session}::uuid,
          ${input.targetUser}::uuid,
          'suspended'::public.membership_status,
          ${input.expectedRevision}::integer,
          'IR-2026-0215 explicit access lifecycle proof'::text,
          ${input.key}::bytea,
          ${input.audit}::uuid,
          ${input.request}::uuid,
          ${input.correlation}::uuid,
          '198.51.100.215'::inet,
          'Periapsis platform tenant-access runtime proof',
          'totp'::text
        )
      `;
    },
    { tenant: fixture.tenant, user: input.actor },
  );
}

async function seedFixture(): Promise<void> {
  const createdAt = new Date(Date.now() - 2 * 60_000);
  const staleCreatedAt = new Date(Date.now() - 20 * 60_000);
  const freshMfaAt = new Date(Date.now() - 60_000);
  const staleMfaAt = new Date(Date.now() - 16 * 60_000);
  const futureMfaAt = new Date(Date.now() + 60_000);
  const idleExpiresAt = new Date(Date.now() + 60 * 60_000);
  const absoluteExpiresAt = new Date(Date.now() + 2 * 60 * 60_000);

  await admin.begin(async (transaction) => {
    const [existing] = await transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM public.tenants
      WHERE id IN (${fixture.tenant}::uuid,${fixture.suspendedTenant}::uuid)
         OR slug IN ('platform-access-runtime','platform-access-suspended')
    `;
    assert.equal(
      existing?.count,
      0,
      "platform tenant-access proof requires a fresh disposable database",
    );

    await transaction`
      INSERT INTO public.users(id,email,display_name)
      VALUES
        (${fixture.mainActor}::uuid,'access.main@example.invalid','Access main'),
        (${fixture.deniedActor}::uuid,'access.denied@example.invalid','Access denied'),
        (${fixture.customRoleActor}::uuid,'access.custom@example.invalid','Access custom'),
        (${fixture.activeMemberActor}::uuid,'access.active@example.invalid','Access existing active'),
        (${fixture.suspendedMemberActor}::uuid,'access.suspended@example.invalid','Access existing suspended'),
        (${fixture.atomicActor}::uuid,'access.atomic@example.invalid','Access atomic'),
        (${fixture.concurrentActor}::uuid,'access.concurrent@example.invalid','Access concurrent'),
        (${fixture.tenantAdmin}::uuid,'access.tenant-admin@example.invalid','Tenant administrator'),
        (${fixture.victim}::uuid,'access.victim@example.invalid','Tenant lifecycle target')
    `;
    await transaction`
      INSERT INTO public.platform_roles(id,key,display_name,system)
      VALUES (
        ${fixture.customRole}::uuid,'tenant_access_runtime_custom',
        'Tenant access runtime custom role',false
      )
    `;
    await transaction`
      INSERT INTO public.platform_role_permissions(role_id,permission_id)
      SELECT ${fixture.customRole}::uuid,permission.id
      FROM public.platform_permissions AS permission
      WHERE permission.key='platform.tenant.access'
    `;
    await transaction`
      INSERT INTO public.user_platform_roles(
        id,user_id,role_id,granted_by_user_id,granted_at
      )
      SELECT uuidv7(),candidate.user_id,role.id,${fixture.mainActor}::uuid,
             ${createdAt}
      FROM (VALUES
        (${fixture.mainActor}::uuid),
        (${fixture.activeMemberActor}::uuid),
        (${fixture.suspendedMemberActor}::uuid),
        (${fixture.atomicActor}::uuid),
        (${fixture.concurrentActor}::uuid)
      ) AS candidate(user_id)
      CROSS JOIN public.platform_roles AS role
      WHERE role.key='platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.user_platform_roles(
        id,user_id,role_id,granted_by_user_id,granted_at
      ) VALUES (
        uuidv7(),${fixture.customRoleActor}::uuid,${fixture.customRole}::uuid,
        ${fixture.mainActor}::uuid,${createdAt}
      )
    `;

    await transaction`
      INSERT INTO public.auth_sessions(
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,revoked_at,revoke_reason,created_at
      ) VALUES
        (${fixture.mainSession}::uuid,${fixture.mainActor}::uuid,uuidv7(),NULL,
         ${digest(1)}::bytea,${digest(2)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.staleSession}::uuid,${fixture.mainActor}::uuid,uuidv7(),NULL,
         ${digest(3)}::bytea,${digest(4)}::bytea,'totp',${staleMfaAt},${staleCreatedAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${staleCreatedAt}),
        (${fixture.revokedSession}::uuid,${fixture.mainActor}::uuid,uuidv7(),NULL,
         ${digest(5)}::bytea,${digest(6)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},${freshMfaAt},'runtime revocation',${createdAt}),
        (${fixture.recoverySession}::uuid,${fixture.mainActor}::uuid,uuidv7(),NULL,
         ${digest(7)}::bytea,${digest(8)}::bytea,'recovery_code',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.futureMfaSession}::uuid,${fixture.mainActor}::uuid,uuidv7(),NULL,
         ${digest(9)}::bytea,${digest(10)}::bytea,'totp',${futureMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.deniedSession}::uuid,${fixture.deniedActor}::uuid,uuidv7(),NULL,
         ${digest(11)}::bytea,${digest(12)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.customRoleSession}::uuid,${fixture.customRoleActor}::uuid,uuidv7(),NULL,
         ${digest(13)}::bytea,${digest(14)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.activeMemberSession}::uuid,${fixture.activeMemberActor}::uuid,uuidv7(),NULL,
         ${digest(15)}::bytea,${digest(16)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.suspendedMemberSession}::uuid,${fixture.suspendedMemberActor}::uuid,uuidv7(),NULL,
         ${digest(17)}::bytea,${digest(18)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.atomicSession}::uuid,${fixture.atomicActor}::uuid,uuidv7(),NULL,
         ${digest(19)}::bytea,${digest(20)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt}),
        (${fixture.concurrentSession}::uuid,${fixture.concurrentActor}::uuid,uuidv7(),NULL,
         ${digest(21)}::bytea,${digest(22)}::bytea,'totp',${freshMfaAt},${createdAt},
         ${idleExpiresAt},${absoluteExpiresAt},NULL,NULL,${createdAt})
    `;

    await transaction`
      INSERT INTO public.tenants(id,slug,name,status,version)
      VALUES
        (${fixture.tenant}::uuid,'platform-access-runtime',
         'Platform access runtime','active',1),
        (${fixture.suspendedTenant}::uuid,'platform-access-suspended',
         'Platform access suspended','suspended',1)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status,lifecycle_revision,
        created_at,updated_at
      ) VALUES
        (${fixture.tenantAdminMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.tenantAdmin}::uuid,'tenant_admin','active',1,${createdAt},${createdAt}),
        (${fixture.victimMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.victim}::uuid,'analyst','active',1,${createdAt},${createdAt}),
        (${fixture.activeExistingMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.activeMemberActor}::uuid,'analyst','active',1,${createdAt},${createdAt}),
        (${fixture.suspendedExistingMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.suspendedMemberActor}::uuid,'analyst','suspended',1,${createdAt},${createdAt}),
        (${fixture.suspendedTenantAdminMembership}::uuid,${fixture.suspendedTenant}::uuid,
         ${fixture.tenantAdmin}::uuid,'tenant_admin','active',1,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_states(
        tenant_id,initialized_at,revision,updated_at
      ) VALUES
        (${fixture.tenant}::uuid,${createdAt},0,${createdAt}),
        (${fixture.suspendedTenant}::uuid,${createdAt},0,${createdAt})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.tenantAdminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.suspendedTenant}::uuid,
        ${fixture.suspendedTenantAdminMembership}::uuid
      )
    `;
  });
}

async function assertCatalogAndRlsBoundary(): Promise<void> {
  const [catalog] = await admin<
    {
      owner: string;
      api: boolean;
      worker: boolean;
      notifier: boolean;
      triggerNames: string[];
      sealSource: string;
    }[]
  >`
    SELECT owner.rolname AS owner,
      has_function_privilege(
        'periapsis_api',
        'app.authorize_platform_tenant_access_v1(uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text)',
        'EXECUTE'
      ) AS api,
      has_function_privilege(
        'periapsis_worker',
        'app.authorize_platform_tenant_access_v1(uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text)',
        'EXECUTE'
      ) AS worker,
      has_function_privilege(
        'periapsis_notifier',
        'app.authorize_platform_tenant_access_v1(uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text)',
        'EXECUTE'
      ) AS notifier,
      ARRAY(
        SELECT trigger.tgname::text
        FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid='public.audit_events'::regclass
          AND NOT trigger.tgisinternal
          AND (trigger.tgtype & 2)=2
        ORDER BY trigger.tgname
      ) AS "triggerNames",
      pg_get_functiondef('app.seal_audit_event()'::regprocedure) AS "sealSource"
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
    WHERE procedure.oid=
      'app.authorize_platform_tenant_access_v1(uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text)'::regprocedure
  `;
  assert(catalog, "tenant-access function is missing");
  assert.equal(catalog.owner, "periapsis_migrator");
  assert.equal(catalog.api, true);
  assert.equal(catalog.worker, false);
  assert.equal(catalog.notifier, false);
  assert(
    catalog.triggerNames.indexOf(
      "audit_events_platform_access_attribution_before_insert",
    ) < catalog.triggerNames.indexOf("audit_events_seal_before_insert"),
    "platform attribution must run before the immutable audit seal",
  );
  assert(!catalog.sealSource.includes("platform_super_admin_access"));

  await assert.rejects(
    asRole(
      admin,
      "periapsis_worker",
      (transaction) =>
        transaction`
        SELECT * FROM app.authorize_platform_tenant_access_v1(
          ${fixture.mainSession}::uuid,${fixture.tenant}::uuid,uuidv7(),uuidv7(),
          1,'IR-2026-0215 ACL proof',${digest(203)}::bytea,
          uuidv7(),uuidv7(),uuidv7(),uuidv7(),'198.51.100.215'::inet,
          'Periapsis platform tenant-access runtime proof','totp'
        )
      `,
    ),
    (error) => assertSqlState(error, "42501"),
  );

  const visibleBefore = await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM public.tenant_memberships
        WHERE tenant_id=${fixture.tenant}::uuid
      `;
      return row?.count;
    },
    { tenant: fixture.tenant, user: fixture.mainActor },
  );
  assert.equal(visibleBefore, 0, "platform authority bypassed tenant RLS");
}

async function assertDeniedAuthorityMatrix(): Promise<void> {
  const common = {
    actor: fixture.mainActor,
    tenant: fixture.tenant,
    membership: uuid(100),
    roleGrant: uuid(101),
    expectedVersion: 1,
    reason: "IR-2026-0215 denied authority proof",
    key: digest(210),
    platformAudit: uuid(102),
    tenantAudit: uuid(103),
    request: uuid(104),
    correlation: uuid(105),
  };

  await assert.rejects(
    authorizeAccess(admin, { ...common, session: fixture.staleSession }),
    (error) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      session: fixture.revokedSession,
      key: digest(211),
    }),
    (error) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      session: fixture.futureMfaSession,
      key: digest(212),
    }),
    (error) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      session: fixture.recoverySession,
      authenticationMethod: "recovery_code",
      key: digest(213),
    }),
    (error) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      actor: fixture.deniedActor,
      session: fixture.deniedSession,
      key: digest(214),
    }),
    (error) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      actor: fixture.customRoleActor,
      session: fixture.customRoleSession,
      key: digest(215),
    }),
    (error) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      session: fixture.mainSession,
      expectedVersion: 2,
      key: digest(216),
    }),
    (error) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      session: fixture.mainSession,
      tenant: fixture.suspendedTenant,
      key: digest(217),
    }),
    (error) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      actor: fixture.activeMemberActor,
      session: fixture.activeMemberSession,
      key: digest(218),
    }),
    (error) => assertSqlState(error, "23505"),
  );
  await assert.rejects(
    authorizeAccess(admin, {
      ...common,
      actor: fixture.suspendedMemberActor,
      session: fixture.suspendedMemberSession,
      key: digest(219),
    }),
    (error) => assertSqlState(error, "23505"),
  );

  const [counts] = await admin<
    { memberships: number; commands: number; tenantAudits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_memberships
       WHERE tenant_id=${fixture.tenant}::uuid
         AND user_id IN (${fixture.mainActor}::uuid,${fixture.deniedActor}::uuid,
                         ${fixture.customRoleActor}::uuid)) AS memberships,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE operation='platform.tenant_access.authorize') AS commands,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND action='tenant.access.authorized') AS "tenantAudits"
  `;
  assert.deepEqual(counts, { memberships: 0, commands: 0, tenantAudits: 0 });
}

async function assertFirstApplyReplayAndAtomicity(): Promise<void> {
  const first = await authorizeAccess(admin, {
    actor: fixture.mainActor,
    session: fixture.mainSession,
    membership: fixture.mainMembership,
    roleGrant: fixture.mainRoleGrant,
    key: mainKey,
    platformAudit: fixture.mainPlatformAudit,
    tenantAudit: fixture.mainTenantAudit,
    request: fixture.mainRequest,
    correlation: fixture.mainCorrelation,
  });
  assert.equal(first.replayed, false);
  assert.equal(first.tenant_id, fixture.tenant);
  assert.equal(first.membership_id, fixture.mainMembership);
  assert.equal(first.user_id, fixture.mainActor);
  assert.equal(first.tenant_version, 1);
  assert.equal(first.membership_revision, 1);
  assert(Number(first.authorization_revision) > 0);

  const [created] = await admin<
    {
      status: string;
      role: string;
      lifecycleRevision: number;
      sourceKind: string;
      sourceKey: string;
      authoritative: boolean;
      protected: boolean;
      grantCount: number;
      platformAuditCount: number;
      tenantAuditCount: number;
      commandCount: number;
      tenantImpersonator: string | null;
    }[]
  >`
    SELECT membership.status,membership.role,
      membership.lifecycle_revision AS "lifecycleRevision",
      source.kind AS "sourceKind",source.key AS "sourceKey",
      source.authoritative,source.protected,
      (SELECT count(*)::integer
       FROM public.tenant_membership_role_grants AS grant_row
       JOIN public.tenant_roles AS role
         ON role.tenant_id=grant_row.tenant_id AND role.id=grant_row.role_id
       WHERE grant_row.id=${fixture.mainRoleGrant}::uuid
         AND grant_row.tenant_id=${fixture.tenant}::uuid
         AND grant_row.membership_id=${fixture.mainMembership}::uuid
         AND grant_row.granted_by_membership_id=${fixture.mainMembership}::uuid
         AND grant_row.source_id=source.id
         AND grant_row.revoked_at IS NULL
         AND role.key='tenant_admin' AND role.system_role AND role.protected_role
      ) AS "grantCount",
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE id=${fixture.mainPlatformAudit}::uuid
         AND action='platform.tenant_access.authorized'
         AND request_id=${fixture.mainRequest}::uuid
         AND correlation_id=${fixture.mainCorrelation}::uuid) AS "platformAuditCount",
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id=${fixture.mainTenantAudit}::uuid
         AND action='tenant.access.authorized'
         AND request_id=${fixture.mainRequest}::uuid
         AND correlation_id=${fixture.mainCorrelation}::uuid) AS "tenantAuditCount",
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id=${fixture.mainActor}::uuid
         AND operation='platform.tenant_access.authorize'
         AND key_digest=${mainKey}::bytea) AS "commandCount",
      (SELECT impersonated_by_user_id FROM public.audit_events
       WHERE id=${fixture.mainTenantAudit}::uuid) AS "tenantImpersonator"
    FROM public.tenant_memberships AS membership
    JOIN public.tenant_membership_role_grants AS grant_row
      ON grant_row.tenant_id=membership.tenant_id
     AND grant_row.membership_id=membership.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id=grant_row.tenant_id AND source.id=grant_row.source_id
    WHERE membership.id=${fixture.mainMembership}::uuid
  `;
  assert.deepEqual(created, {
    status: "active",
    role: "tenant_admin",
    lifecycleRevision: 1,
    sourceKind: "manual",
    sourceKey: "platform_super_admin_access",
    authoritative: false,
    protected: true,
    grantCount: 1,
    platformAuditCount: 1,
    tenantAuditCount: 1,
    commandCount: 1,
    tenantImpersonator: fixture.mainActor,
  });

  const replay = await authorizeAccess(admin, {
    actor: fixture.mainActor,
    session: fixture.mainSession,
    membership: fixture.replayMembership,
    roleGrant: fixture.replayRoleGrant,
    key: mainKey,
    platformAudit: fixture.replayPlatformAudit,
    tenantAudit: fixture.replayTenantAudit,
    request: fixture.replayRequest,
    correlation: fixture.replayCorrelation,
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.membership_id, fixture.mainMembership);
  assert.equal(replay.authorized_at.getTime(), first.authorized_at.getTime());

  await assert.rejects(
    authorizeAccess(admin, {
      actor: fixture.mainActor,
      session: fixture.mainSession,
      membership: fixture.replayMembership,
      roleGrant: fixture.replayRoleGrant,
      reason: "IR-2026-0215 changed idempotency payload",
      key: mainKey,
      platformAudit: fixture.replayPlatformAudit,
      tenantAudit: fixture.replayTenantAudit,
      request: fixture.replayRequest,
      correlation: fixture.replayCorrelation,
    }),
    (error) => assertSqlState(error, "23505"),
  );

  await assert.rejects(
    authorizeAccess(admin, {
      actor: fixture.atomicActor,
      session: fixture.atomicSession,
      membership: fixture.atomicMembership,
      roleGrant: fixture.atomicRoleGrant,
      key: digest(220),
      platformAudit: fixture.mainPlatformAudit,
      tenantAudit: fixture.atomicTenantAudit,
      request: fixture.atomicRequest,
      correlation: fixture.atomicCorrelation,
    }),
    (error) => assertSqlState(error, "23505"),
  );
  const [atomic] = await admin<
    { membership: number; grant: number; audit: number; command: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_memberships
       WHERE id=${fixture.atomicMembership}::uuid) AS membership,
      (SELECT count(*)::integer FROM public.tenant_membership_role_grants
       WHERE id=${fixture.atomicRoleGrant}::uuid) AS grant,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE id=${fixture.atomicTenantAudit}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id=${fixture.atomicActor}::uuid
         AND operation='platform.tenant_access.authorize') AS command
  `;
  assert.deepEqual(atomic, { membership: 0, grant: 0, audit: 0, command: 0 });
}

async function assertConcurrentReplay(): Promise<void> {
  const results = await Promise.all([
    authorizeAccess(contenderA, {
      actor: fixture.concurrentActor,
      session: fixture.concurrentSession,
      membership: fixture.concurrentMembershipA,
      roleGrant: fixture.concurrentGrantA,
      key: concurrentKey,
      platformAudit: fixture.concurrentPlatformAuditA,
      tenantAudit: fixture.concurrentTenantAuditA,
      request: fixture.concurrentRequestA,
      correlation: fixture.concurrentCorrelationA,
    }),
    authorizeAccess(contenderB, {
      actor: fixture.concurrentActor,
      session: fixture.concurrentSession,
      membership: fixture.concurrentMembershipB,
      roleGrant: fixture.concurrentGrantB,
      key: concurrentKey,
      platformAudit: fixture.concurrentPlatformAuditB,
      tenantAudit: fixture.concurrentTenantAuditB,
      request: fixture.concurrentRequestB,
      correlation: fixture.concurrentCorrelationB,
    }),
  ]);
  assert.deepEqual(
    results
      .map((result) => result.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );
  assert.equal(results[0]?.membership_id, results[1]?.membership_id);

  const [counts] = await admin<
    {
      membership: number;
      command: number;
      tenantAudit: number;
      platformAudit: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_memberships
       WHERE tenant_id=${fixture.tenant}::uuid
         AND user_id=${fixture.concurrentActor}::uuid) AS membership,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id=${fixture.concurrentActor}::uuid
         AND operation='platform.tenant_access.authorize'
         AND key_digest=${concurrentKey}::bytea) AS command,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND actor_user_id=${fixture.concurrentActor}::uuid
         AND action='tenant.access.authorized') AS "tenantAudit",
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE actor_user_id=${fixture.concurrentActor}::uuid
         AND action='platform.tenant_access.authorized') AS "platformAudit"
  `;
  assert.deepEqual(counts, {
    membership: 1,
    command: 1,
    tenantAudit: 1,
    platformAudit: 1,
  });
}

async function assertReplayTenantRevisionFence(): Promise<void> {
  await changePlatformTenantLifecycle({
    target: "suspended",
    expectedVersion: 1,
    audit: fixture.suspendTenantAudit,
    request: fixture.suspendTenantRequest,
    correlation: fixture.suspendTenantCorrelation,
  });
  await changePlatformTenantLifecycle({
    target: "active",
    expectedVersion: 2,
    audit: fixture.reactivateTenantAudit,
    request: fixture.reactivateTenantRequest,
    correlation: fixture.reactivateTenantCorrelation,
  });
  const [before] = await admin<{ audit: number; command: number }[]>`
    SELECT
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND action='tenant.access.authorized') AS audit,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id=${fixture.mainActor}::uuid
         AND operation='platform.tenant_access.authorize') AS command
  `;
  await assert.rejects(
    authorizeAccess(admin, {
      actor: fixture.mainActor,
      session: fixture.mainSession,
      membership: fixture.replayMembership,
      roleGrant: fixture.replayRoleGrant,
      key: mainKey,
      platformAudit: fixture.replayPlatformAudit,
      tenantAudit: fixture.replayTenantAudit,
      request: fixture.replayRequest,
      correlation: fixture.replayCorrelation,
    }),
    (error) => assertSqlState(error, "40001"),
  );
  const [after] = await admin<
    { version: number; audit: number; command: number }[]
  >`
    SELECT tenant.version,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=tenant.id AND action='tenant.access.authorized') AS audit,
      (SELECT count(*)::integer FROM public.platform_commands
       WHERE actor_user_id=${fixture.mainActor}::uuid
         AND operation='platform.tenant_access.authorize') AS command
    FROM public.tenants AS tenant
    WHERE tenant.id=${fixture.tenant}::uuid
  `;
  assert.equal(after?.version, 3);
  assert.deepEqual(
    { audit: after?.audit, command: after?.command },
    before,
    "stale tenant-version replay performed a write",
  );
}

async function assertNormalSwitchAndAttribution(): Promise<void> {
  const newIdle = new Date(Date.now() + 30 * 60_000);
  const newAbsolute = new Date(Date.now() + 60 * 60_000);
  const switched = await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ id: string | null }[]>`
        SELECT app.rotate_auth_session_tenant(
          ${digest(1)}::bytea,${fixture.switchedSession}::uuid,
          ${digest(23)}::bytea,${digest(24)}::bytea,${fixture.tenant}::uuid,
          ${newIdle},${newAbsolute},${fixture.switchAudit}::uuid,
          ${fixture.switchRequest}::uuid,${fixture.switchCorrelation}::uuid,
          '198.51.100.215'::inet,
          'Periapsis platform tenant-access runtime proof'
        ) AS id
      `;
      return row?.id;
    },
    { user: fixture.mainActor },
  );
  assert.equal(switched, fixture.switchedSession);

  const [switchState] = await admin<
    { activeTenant: string | null; switchAudit: number }[]
  >`
    SELECT session.active_tenant_id AS "activeTenant",
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE id=${fixture.switchAudit}::uuid
         AND action='authentication.session.tenant_switched') AS "switchAudit"
    FROM public.auth_sessions AS session
    WHERE session.id=${fixture.switchedSession}::uuid
  `;
  assert.deepEqual(switchState, {
    activeTenant: fixture.tenant,
    switchAudit: 1,
  });
  const visibleAfterSwitch = await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM public.tenant_memberships
        WHERE tenant_id=${fixture.tenant}::uuid
      `;
      return row?.count;
    },
    { tenant: fixture.tenant, user: fixture.mainActor },
  );
  assert((visibleAfterSwitch ?? 0) > 0);

  const now = new Date(Date.now() - 1000);
  const expires = new Date(Date.now() + 60 * 60_000);
  await admin`
    INSERT INTO public.auth_sessions(
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${fixture.tenantAdminSession}::uuid,${fixture.tenantAdmin}::uuid,uuidv7(),
      ${fixture.tenant}::uuid,${digest(25)}::bytea,${digest(26)}::bytea,
      'totp',${now},${now},${expires},${expires},${now}
    )
  `;

  await changeMembership({
    actor: fixture.tenantAdmin,
    session: fixture.tenantAdminSession,
    targetUser: fixture.victim,
    expectedRevision: 1,
    key: digest(230),
    audit: fixture.victimSuspendAudit,
    request: fixture.victimSuspendRequest,
    correlation: fixture.victimSuspendCorrelation,
  });
  const [normalAudit] = await admin<
    { impersonator: string | null; actor: string }[]
  >`
    SELECT impersonated_by_user_id AS impersonator,actor_user_id AS actor
    FROM public.audit_events
    WHERE id=${fixture.victimSuspendAudit}::uuid
  `;
  assert.deepEqual(normalAudit, {
    impersonator: null,
    actor: fixture.tenantAdmin,
  });

  const rollbackMarker = new Error(
    "rollback temporary audit insert privileges",
  );
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe(
        `CREATE FUNCTION pg_temp.emit_platform_access_audit_test_v1(
          p_id uuid,p_actor_type public.audit_actor_type,p_actor_user_id uuid,
          p_action text
        ) RETURNS public.audit_events
        LANGUAGE sql VOLATILE SECURITY DEFINER
        SET search_path=pg_catalog,public,app
        AS $test$
          INSERT INTO public.audit_events(
            id,tenant_id,sequence,actor_type,actor_user_id,action,
            resource_type,resource_id,request_id,correlation_id,ip_address,
            user_agent,authentication_method,outcome,metadata
          ) VALUES (
            p_id,app.context_tenant_id(),0,p_actor_type,p_actor_user_id,p_action,
            'tenant',app.context_tenant_id(),uuidv7(),uuidv7(),
            '198.51.100.215'::inet,
            'Periapsis platform tenant-access runtime proof',
            CASE WHEN p_actor_type='system' THEN 'system' ELSE 'totp' END,
            (CASE WHEN p_actor_type='system' THEN 'success' ELSE 'failure' END)
              ::public.audit_outcome,
            '{}'::jsonb
          ) RETURNING *
        $test$`,
      );
      await transaction.unsafe(
        "GRANT EXECUTE ON FUNCTION pg_temp.emit_platform_access_audit_test_v1(uuid,public.audit_actor_type,uuid,text) TO periapsis_api",
      );
      await assert.rejects(
        transaction.savepoint(async (nested) => {
          await nested.unsafe('SET LOCAL ROLE "periapsis_api"');
          await nested`
            SELECT set_config('app.tenant_id',${fixture.tenant},true),
                   set_config('app.user_id',${fixture.mainActor},true)
          `;
          await nested`
            SELECT pg_temp.emit_platform_access_audit_test_v1(
              ${fixture.mismatchedActorAudit}::uuid,'user'::public.audit_actor_type,
              ${fixture.tenantAdmin}::uuid,'runtime.actor_mismatch'
            )
          `;
        }),
        (error) => assertSqlState(error, "23514"),
      );
      const [nonUser] = await transaction.savepoint(async (nested) => {
        await nested.unsafe('SET LOCAL ROLE "periapsis_api"');
        await nested`
          SELECT set_config('app.tenant_id',${fixture.tenant},true),
                 set_config('app.user_id',${fixture.mainActor},true)
        `;
        return nested<{ impersonator: string | null; hashLength: number }[]>`
          SELECT (event).impersonated_by_user_id AS impersonator,
                 length((event).event_hash)::integer AS "hashLength"
          FROM (
            SELECT pg_temp.emit_platform_access_audit_test_v1(
              ${fixture.nonUserAudit}::uuid,'system'::public.audit_actor_type,
              NULL::uuid,'runtime.system_event'
            ) AS event
          ) AS emitted
        `;
      });
      assert.deepEqual(nonUser, { impersonator: null, hashLength: 64 });
      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );

  await changeMembership({
    actor: fixture.mainActor,
    session: fixture.switchedSession,
    targetUser: fixture.mainActor,
    expectedRevision: 1,
    key: digest(231),
    audit: fixture.selfSuspendAudit,
    request: fixture.selfSuspendRequest,
    correlation: fixture.selfSuspendCorrelation,
  });
  const terminal = await admin.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true)
    `;
    const [row] = await transaction<
      {
        status: string;
        sessionRevoked: boolean;
        allowed: boolean;
        impersonator: string | null;
        chainValid: boolean;
      }[]
    >`
      SELECT membership.status,
        session.revoked_at IS NOT NULL AS "sessionRevoked",
        app.session_tenant_allowed(${fixture.mainActor}::uuid,${fixture.tenant}::uuid)
          AS allowed,
        audit.impersonated_by_user_id AS impersonator,
        NOT EXISTS (
          SELECT 1 FROM app.verify_audit_chain(${fixture.tenant}::uuid)
          WHERE NOT valid
        ) AS "chainValid"
      FROM public.tenant_memberships AS membership
      JOIN public.auth_sessions AS session ON session.id=${fixture.switchedSession}::uuid
      JOIN public.audit_events AS audit ON audit.id=${fixture.selfSuspendAudit}::uuid
      WHERE membership.id=${fixture.mainMembership}::uuid
    `;
    assert(row, "terminal membership state query returned no row");
    return row;
  });
  assert.deepEqual(terminal, {
    status: "suspended",
    sessionRevoked: true,
    allowed: false,
    impersonator: fixture.mainActor,
    chainValid: true,
  });

  const visibleAfterSuspension = await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [row] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM public.tenant_memberships
        WHERE tenant_id=${fixture.tenant}::uuid
      `;
      return row?.count;
    },
    { tenant: fixture.tenant, user: fixture.mainActor },
  );
  assert.equal(visibleAfterSuspension, 0);
}

async function main(): Promise<void> {
  const [server] = await admin<
    { serverVersion: number }[]
  >`SELECT current_setting('server_version_num')::integer AS "serverVersion"`;
  assert(server, "PostgreSQL server version query returned no row");
  assert(server.serverVersion >= 180_000, "PostgreSQL 18 or newer is required");

  await seedFixture();
  await assertCatalogAndRlsBoundary();
  await assertDeniedAuthorityMatrix();
  await assertFirstApplyReplayAndAtomicity();
  await assertConcurrentReplay();
  await assertReplayTenantRevisionFence();
  await assertNormalSwitchAndAttribution();
}

try {
  await main();
  process.stdout.write("platform tenant-access runtime proof passed\n");
} finally {
  await Promise.all([admin.end(), contenderA.end(), contenderB.end()]);
}
