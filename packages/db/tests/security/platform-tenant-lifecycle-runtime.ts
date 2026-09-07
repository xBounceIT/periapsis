import assert from "node:assert/strict";

import postgres, { type Sql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_notifier" | "periapsis_worker";
type LifecycleTarget = "active" | "suspended";
type LifecycleReceipt = {
  tenant_id: string;
  previous_status: LifecycleTarget;
  status: LifecycleTarget;
  version: number;
  updated_at: Date;
  replayed: boolean;
};

const databaseUrl = process.env.PERIAPSIS_TENANT_LIFECYCLE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_LIFECYCLE_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(databaseUrl, { max: 2, onnotice: () => undefined });
const contenderA = postgres(databaseUrl, {
  max: 1,
  onnotice: () => undefined,
});
const contenderB = postgres(databaseUrl, {
  max: 1,
  onnotice: () => undefined,
});

const uuid = (sequence: number): string =>
  `019d3b10-5000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  operator: uuid(2),
  unauthorizedUser: uuid(3),
  membership: uuid(4),
  operatorGrant: uuid(5),
  session: uuid(6),
  revokedSession: uuid(7),
  unauthorizedSession: uuid(8),
  operatorFamily: uuid(9),
  revokedFamily: uuid(10),
  unauthorizedFamily: uuid(11),
  alert: uuid(14),
  case: uuid(15),
  firstAudit: uuid(16),
  firstRequest: uuid(17),
  firstCorrelation: uuid(18),
  reactivationAudit: uuid(19),
  reactivationRequest: uuid(20),
  reactivationCorrelation: uuid(21),
  concurrentAuditA: uuid(22),
  concurrentAuditB: uuid(23),
  concurrentRequestA: uuid(24),
  concurrentRequestB: uuid(25),
  concurrentCorrelationA: uuid(26),
  concurrentCorrelationB: uuid(27),
  finalAudit: uuid(28),
  finalRequest: uuid(29),
  finalCorrelation: uuid(30),
  queuedEvent: uuid(31),
  leasedEvent: uuid(32),
  reservedEvent: uuid(33),
  futureEvent: uuid(34),
  queuedDelivery: uuid(35),
  leasedDelivery: uuid(36),
  reservedDelivery: uuid(37),
  futureDelivery: uuid(38),
  leasedFence: uuid(39),
  reservedFence: uuid(40),
  smtpConfiguration: uuid(41),
  slaPolicy: uuid(42),
  slaInstanceQueued: uuid(43),
  slaInstanceLeased: uuid(44),
  slaInstanceRetry: uuid(45),
  slaInstanceFuture: uuid(46),
  slaAssignmentQueued: uuid(47),
  slaAssignmentLeased: uuid(48),
  slaAssignmentRetry: uuid(49),
  slaAssignmentFuture: uuid(50),
  slaObjectQueued: uuid(51),
  slaObjectLeased: uuid(52),
  slaObjectRetry: uuid(53),
  slaObjectFuture: uuid(54),
  slaJobQueued: uuid(55),
  slaJobLeased: uuid(56),
  slaJobRetry: uuid(57),
  slaJobFuture: uuid(58),
  slaWorker: uuid(59),
} as const;

const templateSnapshot = {
  key: "system.smtp-test",
  name: "Periapsis SMTP test",
  language: "en",
  version: 1,
  subject: "Periapsis SMTP test",
  html: "<p>This message verifies your Periapsis SMTP configuration.</p>",
  plainText: "This message verifies your Periapsis SMTP configuration.",
  css: "",
} as const;

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

async function changeLifecycle(
  client: Sql,
  input: {
    actor?: string;
    session?: string;
    tenant?: string;
    target: LifecycleTarget;
    expectedVersion: number;
    reason: string | null;
    auditId: string;
    requestId: string;
    correlationId: string;
    authenticationMethod?: string;
  },
): Promise<LifecycleReceipt> {
  return asRole(
    client,
    "periapsis_api",
    async (transaction) => {
      const [receipt] = await transaction<LifecycleReceipt[]>`
        SELECT *
        FROM app.change_platform_tenant_lifecycle(
          ${input.session ?? fixture.session}::uuid,
          ${input.tenant ?? fixture.tenant}::uuid,
          ${input.target}::public.tenant_status,
          ${input.expectedVersion}::integer,
          ${input.reason}::text,
          ${input.auditId}::uuid,
          ${input.requestId}::uuid,
          ${input.correlationId}::uuid,
          '198.51.100.41'::inet,
          'Periapsis tenant lifecycle runtime proof',
          ${input.authenticationMethod ?? "totp"}::text
        )
      `;
      assert(receipt, "tenant lifecycle function returned no receipt");
      return receipt;
    },
    { user: input.actor ?? fixture.operator },
  );
}

async function seedBaseFixture(): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 60 * 60_000);
  await admin.begin(async (transaction) => {
    const [existing] = await transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM public.tenants
      WHERE id = ${fixture.tenant}::uuid OR slug = 'lifecycle-runtime'
    `;
    assert.equal(
      existing?.count,
      0,
      "tenant lifecycle runtime proof requires a fresh disposable database",
    );

    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.operator}::uuid, 'lifecycle.operator@example.invalid', 'Lifecycle operator'),
        (${fixture.unauthorizedUser}::uuid, 'lifecycle.denied@example.invalid', 'Denied operator')
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id, granted_at
      )
      SELECT ${fixture.operatorGrant}::uuid, ${fixture.operator}::uuid,
             role.id, ${fixture.operator}::uuid, ${now}
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, revoked_at,
        revoke_reason, created_at
      ) VALUES
        (
          ${fixture.session}::uuid, ${fixture.operator}::uuid,
          ${fixture.operatorFamily}::uuid, NULL, ${Buffer.alloc(32, 1)}::bytea,
          ${Buffer.alloc(32, 2)}::bytea, 'totp', ${now}, ${now}, ${expires},
          ${expires}, NULL, NULL, ${now}
        ),
        (
          ${fixture.revokedSession}::uuid, ${fixture.operator}::uuid,
          ${fixture.revokedFamily}::uuid, NULL, ${Buffer.alloc(32, 3)}::bytea,
          ${Buffer.alloc(32, 4)}::bytea, 'totp', ${now}, ${now}, ${expires},
          ${expires}, ${now}, 'runtime revoked session', ${now}
        ),
        (
          ${fixture.unauthorizedSession}::uuid, ${fixture.unauthorizedUser}::uuid,
          ${fixture.unauthorizedFamily}::uuid, NULL, ${Buffer.alloc(32, 5)}::bytea,
          ${Buffer.alloc(32, 6)}::bytea, 'totp', ${now}, ${now}, ${expires},
          ${expires}, NULL, NULL, ${now}
        )
    `;
    await transaction`
      INSERT INTO public.tenants (
        id, slug, name, status, version, created_at, updated_at
      )
      VALUES (
        ${fixture.tenant}::uuid, 'lifecycle-runtime',
        'Tenant lifecycle runtime', 'active', 1, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status, created_at, updated_at
      ) VALUES (
        ${fixture.membership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.operator}::uuid, 'tenant_admin', 'active', ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_states (
        tenant_id, initialized_at, revision, updated_at
      ) VALUES (${fixture.tenant}::uuid, ${now}, 0, ${now})
    `;
    await transaction`
      SELECT app.private_seed_tenant_ticketing_workflows_v1(
        ${fixture.tenant}::uuid
      )
    `;
    const workflows = await transaction<
      { aggregateKind: "alert" | "case"; id: string }[]
    >`
      SELECT aggregate_kind AS "aggregateKind", id
      FROM public.ticket_workflows
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND is_default
        AND archived_at IS NULL
    `;
    const alertWorkflow = workflows.find(
      (workflow) => workflow.aggregateKind === "alert",
    );
    const caseWorkflow = workflows.find(
      (workflow) => workflow.aggregateKind === "case",
    );
    assert(alertWorkflow, "default Alert workflow was not seeded");
    assert(caseWorkflow, "default Case workflow was not seeded");
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true)
    `;
    await transaction`
      INSERT INTO public.alerts (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, created_by, created_by_membership_id, created_at, updated_at
      ) VALUES (
        ${fixture.alert}::uuid, ${fixture.tenant}::uuid, 'ALT-2026-000001',
        ${alertWorkflow.id}::uuid, 1, 'new', 'Lifecycle alert',
        ${fixture.operator}::uuid, ${fixture.membership}::uuid, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.cases (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, created_by_membership_id, created_by_user_id,
        created_at, updated_at, opened_at
      ) VALUES (
        ${fixture.case}::uuid, ${fixture.tenant}::uuid, 'CAS-2026-000001',
        ${caseWorkflow.id}::uuid, 1, 'open', 'Lifecycle case',
        ${fixture.membership}::uuid, ${fixture.operator}::uuid,
        ${now}, ${now}, ${now}
      )
    `;
  });
}

async function seedQueueFixture(): Promise<void> {
  const now = new Date(Date.now() - 5_000);
  const leaseUntil = new Date(Date.now() + 5 * 60_000);
  const eventRows = [
    [fixture.queuedEvent, "queued"],
    [fixture.leasedEvent, "leased"],
    [fixture.reservedEvent, "reserved"],
    [fixture.futureEvent, "future"],
  ] as const;
  await admin.begin(async (transaction) => {
    await Promise.all(
      eventRows.map(
        ([eventId, label]) => transaction`
          INSERT INTO public.outbox_events (
            id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
            event_type, schema_version, payload, deduplication_key,
            occurred_at, available_at, created_at
          ) VALUES (
            ${eventId}::uuid, ${fixture.tenant}::uuid, 'runtime',
            ${eventId}::uuid, 1, 'notification.runtime', 1, '{}'::jsonb,
            ${`tenant-lifecycle-${label}`}, ${now}, ${now}, ${now}
          )
        `,
      ),
    );

    await transaction`
      INSERT INTO public.tenant_notification_deliveries (
        id, tenant_id, event_id, delivery_key, template_snapshot,
        smtp_configuration_scope, smtp_configuration_id,
        smtp_configuration_version, channel, audience, recipient,
        destination_redacted, context, priority, deduplication_key,
        grouping_window_ms, grouping_maximum_items, retry, status,
        attempt_count, maximum_attempts, next_attempt_at, lease_owner,
        fence_token, lease_until, stable_message_id, reserved_at,
        created_at, updated_at
      ) VALUES
        (
          ${fixture.queuedDelivery}::uuid, ${fixture.tenant}::uuid,
          ${fixture.queuedEvent}::uuid, ${"a".repeat(64)},
          ${transaction.json(templateSnapshot)}::jsonb, 'platform',
          ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
          'queued@example.invalid', 'q***@example.invalid', '{}'::jsonb,
          90, 'lifecycle-queued', 0, 1, '{}'::jsonb, 'queued', 0, 3,
          ${now}, NULL, NULL, NULL, NULL, NULL, ${now}, ${now}
        ),
        (
          ${fixture.leasedDelivery}::uuid, ${fixture.tenant}::uuid,
          ${fixture.leasedEvent}::uuid, ${"b".repeat(64)},
          ${transaction.json(templateSnapshot)}::jsonb, 'platform',
          ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
          'leased@example.invalid', 'l***@example.invalid', '{}'::jsonb,
          80, 'lifecycle-leased', 0, 1, '{}'::jsonb, 'leased', 1, 3,
          ${now}, 'runtime-worker', ${fixture.leasedFence}::uuid,
          ${leaseUntil}, NULL, NULL, ${now}, ${now}
        ),
        (
          ${fixture.reservedDelivery}::uuid, ${fixture.tenant}::uuid,
          ${fixture.reservedEvent}::uuid, ${"c".repeat(64)},
          ${transaction.json(templateSnapshot)}::jsonb, 'platform',
          ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
          'reserved@example.invalid', 'r***@example.invalid', '{}'::jsonb,
          70, 'lifecycle-reserved', 0, 1, '{}'::jsonb, 'reserved', 1, 3,
          ${now}, 'runtime-worker', ${fixture.reservedFence}::uuid,
          ${leaseUntil}, 'periapsis-runtime-message', ${now}, ${now}, ${now}
        )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_delivery_attempts (
        tenant_id, delivery_id, attempt, fence_token, started_at
      ) VALUES
        (${fixture.tenant}::uuid, ${fixture.leasedDelivery}::uuid, 1,
         ${fixture.leasedFence}::uuid, ${now}),
        (${fixture.tenant}::uuid, ${fixture.reservedDelivery}::uuid, 1,
         ${fixture.reservedFence}::uuid, ${now})
    `;

    await transaction`
      INSERT INTO public.sla_policies (
        id, tenant_id, key, active_version, resource_version,
        created_by_membership_id, updated_by_membership_id,
        created_at, updated_at
      ) VALUES (
        ${fixture.slaPolicy}::uuid, ${fixture.tenant}::uuid,
        'lifecycle_runtime', 1, 1, ${fixture.membership}::uuid,
        ${fixture.membership}::uuid, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.sla_policy_versions (
        tenant_id, policy_id, version, name, priority, object_types,
        match_rule, effective_from, enabled, revision_digest,
        created_by_membership_id, created_at
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.slaPolicy}::uuid, 1,
        'Lifecycle runtime', 0, ARRAY['alert']::public.sla_object_type[],
        '{}'::jsonb, ${now}, true, ${Buffer.alloc(32, 7)}::bytea,
        ${fixture.membership}::uuid, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.sla_instances (
        id, tenant_id, object_type, object_id, policy_id, policy_version,
        aggregate_version, assignment_event_id, created_at, updated_at
      ) VALUES
        (${fixture.slaInstanceQueued}::uuid, ${fixture.tenant}::uuid, 'alert',
         ${fixture.slaObjectQueued}::uuid, ${fixture.slaPolicy}::uuid, 1, 1,
         ${fixture.slaAssignmentQueued}::uuid, ${now}, ${now}),
        (${fixture.slaInstanceLeased}::uuid, ${fixture.tenant}::uuid, 'alert',
         ${fixture.slaObjectLeased}::uuid, ${fixture.slaPolicy}::uuid, 1, 1,
         ${fixture.slaAssignmentLeased}::uuid, ${now}, ${now}),
        (${fixture.slaInstanceRetry}::uuid, ${fixture.tenant}::uuid, 'alert',
         ${fixture.slaObjectRetry}::uuid, ${fixture.slaPolicy}::uuid, 1, 1,
         ${fixture.slaAssignmentRetry}::uuid, ${now}, ${now}),
        (${fixture.slaInstanceFuture}::uuid, ${fixture.tenant}::uuid, 'alert',
         ${fixture.slaObjectFuture}::uuid, ${fixture.slaPolicy}::uuid, 1, 1,
         ${fixture.slaAssignmentFuture}::uuid, ${now}, ${now})
    `;
    await transaction`
      INSERT INTO public.sla_evaluation_jobs (
        id, tenant_id, sla_instance_id, expected_aggregate_version,
        status, available_at, attempt, maximum_attempts, worker_id,
        lease_expires_at, fence, created_at, updated_at
      ) VALUES
        (${fixture.slaJobQueued}::uuid, ${fixture.tenant}::uuid,
         ${fixture.slaInstanceQueued}::uuid, 1, 'queued', ${now}, 0, 3,
         NULL, NULL, 0, ${now}, ${now}),
        (${fixture.slaJobLeased}::uuid, ${fixture.tenant}::uuid,
         ${fixture.slaInstanceLeased}::uuid, 1, 'leased', ${now}, 1, 3,
         ${fixture.slaWorker}::uuid, ${leaseUntil}, 1, ${now}, ${now}),
        (${fixture.slaJobRetry}::uuid, ${fixture.tenant}::uuid,
         ${fixture.slaInstanceRetry}::uuid, 1, 'retry_scheduled', ${now}, 1, 3,
         NULL, NULL, 1, ${now}, ${now})
    `;
  });
}

async function rlsCounts(): Promise<{ alerts: number; cases: number }> {
  return asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [counts] = await transaction<{ alerts: number; cases: number }[]>`
        SELECT
          (SELECT count(*)::integer FROM public.alerts
           WHERE id = ${fixture.alert}::uuid) AS alerts,
          (SELECT count(*)::integer FROM public.cases
           WHERE id = ${fixture.case}::uuid) AS cases
      `;
      assert(counts);
      return counts;
    },
    { tenant: fixture.tenant, user: fixture.operator },
  );
}

async function main(): Promise<void> {
  await seedBaseFixture();

  const [acl] = await admin<
    { apiExecute: boolean; workerExecute: boolean; apiTenantUpdate: boolean }[]
  >`
    SELECT
      has_function_privilege(
        'periapsis_api',
        'app.change_platform_tenant_lifecycle(uuid,uuid,public.tenant_status,integer,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
        'EXECUTE'
      ) AS "apiExecute",
      has_function_privilege(
        'periapsis_worker',
        'app.change_platform_tenant_lifecycle(uuid,uuid,public.tenant_status,integer,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
        'EXECUTE'
      ) AS "workerExecute",
      has_table_privilege('periapsis_api', 'public.tenants', 'UPDATE')
        AS "apiTenantUpdate"
  `;
  assert.deepEqual(acl, {
    apiExecute: true,
    workerExecute: false,
    apiTenantUpdate: false,
  });

  await assert.rejects(
    asRole(
      admin,
      "periapsis_api",
      (transaction) =>
        transaction`
          UPDATE public.tenants SET status = 'suspended'
          WHERE id = ${fixture.tenant}::uuid
        `.then(() => undefined),
      { user: fixture.operator },
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const sessionCatalog = await asRole(
    admin,
    "periapsis_api",
    async (transaction) => {
      const [v3] = await transaction<{ permissions: string[] }[]>`
        SELECT platform_permissions AS permissions
        FROM app.get_auth_session_v3(${Buffer.alloc(32, 1)}::bytea)
      `;
      const [v2] = await transaction<{ permissions: string[] }[]>`
        SELECT platform_permissions AS permissions
        FROM app.get_auth_session_v2(${Buffer.alloc(32, 1)}::bytea)
      `;
      assert(v3 && v2);
      return { v2: v2.permissions, v3: v3.permissions };
    },
  );
  assert(sessionCatalog.v3.includes("platform.tenant.manage"));
  assert(!sessionCatalog.v2.includes("platform.tenant.manage"));
  assert.deepEqual(await rlsCounts(), { alerts: 1, cases: 1 });

  const exactReason = "A".repeat(2_048);
  const suspended = await changeLifecycle(admin, {
    target: "suspended",
    expectedVersion: 1,
    reason: exactReason,
    auditId: fixture.firstAudit,
    requestId: fixture.firstRequest,
    correlationId: fixture.firstCorrelation,
  });
  assert.deepEqual(
    {
      tenant: suspended.tenant_id,
      previous: suspended.previous_status,
      status: suspended.status,
      version: suspended.version,
      replayed: suspended.replayed,
    },
    {
      tenant: fixture.tenant,
      previous: "active",
      status: "suspended",
      version: 2,
      replayed: false,
    },
  );
  const [firstState] = await admin<
    { status: string; version: number; revision: string; reasonBytes: number }[]
  >`
    SELECT tenant.status, tenant.version, state.revision::text AS revision,
           octet_length(event.reason)::integer AS "reasonBytes"
    FROM public.tenants AS tenant
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
    JOIN public.platform_audit_events AS event
      ON event.id = ${fixture.firstAudit}::uuid
    WHERE tenant.id = ${fixture.tenant}::uuid
  `;
  assert.deepEqual(firstState, {
    status: "suspended",
    version: 2,
    revision: "2",
    reasonBytes: 2_048,
  });

  await assert.rejects(
    changeLifecycle(admin, {
      target: "suspended",
      expectedVersion: 2,
      reason: "No-op must fail",
      auditId: uuid(100),
      requestId: uuid(101),
      correlationId: uuid(102),
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    changeLifecycle(admin, {
      target: "active",
      expectedVersion: 2,
      reason: "Duplicate audit must roll back",
      auditId: fixture.firstAudit,
      requestId: uuid(103),
      correlationId: uuid(104),
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  const [rolledBack] = await admin<
    { status: string; version: number; revision: string }[]
  >`
    SELECT tenant.status, tenant.version, state.revision::text AS revision
    FROM public.tenants AS tenant
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
    WHERE tenant.id = ${fixture.tenant}::uuid
  `;
  assert.deepEqual(rolledBack, {
    status: "suspended",
    version: 2,
    revision: "2",
  });

  const reactivated = await changeLifecycle(admin, {
    target: "active",
    expectedVersion: 2,
    reason: "Suspension cause resolved",
    auditId: fixture.reactivationAudit,
    requestId: fixture.reactivationRequest,
    correlationId: fixture.reactivationCorrelation,
  });
  assert.equal(reactivated.version, 3);

  const deniedLifecycleChanges = [
    changeLifecycle(admin, {
      actor: fixture.unauthorizedUser,
      session: fixture.unauthorizedSession,
      target: "suspended",
      expectedVersion: 3,
      reason: "Unauthorized",
      auditId: uuid(105),
      requestId: uuid(106),
      correlationId: uuid(107),
    }),
    changeLifecycle(admin, {
      session: fixture.revokedSession,
      target: "suspended",
      expectedVersion: 3,
      reason: "Revoked session",
      auditId: uuid(108),
      requestId: uuid(109),
      correlationId: uuid(110),
    }),
    changeLifecycle(admin, {
      target: "suspended",
      expectedVersion: 3,
      reason: "Method mismatch",
      authenticationMethod: "saml",
      auditId: uuid(111),
      requestId: uuid(112),
      correlationId: uuid(113),
    }),
  ];
  await Promise.all(
    deniedLifecycleChanges.map((denied) =>
      assert.rejects(denied, (error: unknown) =>
        assertSqlState(error, "42501"),
      ),
    ),
  );
  await assert.rejects(
    changeLifecycle(admin, {
      target: "suspended",
      expectedVersion: 3,
      reason: null,
      auditId: uuid(114),
      requestId: uuid(115),
      correlationId: uuid(116),
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    changeLifecycle(admin, {
      tenant: uuid(117),
      target: "suspended",
      expectedVersion: 1,
      reason: "Missing target",
      auditId: uuid(118),
      requestId: uuid(119),
      correlationId: uuid(120),
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  await seedQueueFixture();
  const concurrent = await Promise.allSettled([
    changeLifecycle(contenderA, {
      target: "suspended",
      expectedVersion: 3,
      reason: "Concurrent suspension A",
      auditId: fixture.concurrentAuditA,
      requestId: fixture.concurrentRequestA,
      correlationId: fixture.concurrentCorrelationA,
    }),
    changeLifecycle(contenderB, {
      target: "suspended",
      expectedVersion: 3,
      reason: "Concurrent suspension B",
      auditId: fixture.concurrentAuditB,
      requestId: fixture.concurrentRequestB,
      correlationId: fixture.concurrentCorrelationB,
    }),
  ]);
  const winners = concurrent.filter(
    (result): result is PromiseFulfilledResult<LifecycleReceipt> =>
      result.status === "fulfilled",
  );
  const losers = concurrent.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.equal(winners.length, 1, "concurrent suspension must have one winner");
  assert.equal(losers.length, 1, "concurrent suspension must have one loser");
  assertSqlState(losers[0]!.reason, "40001");

  const deliveries = await admin<
    {
      id: string;
      status: string;
      failureCode: string | null;
      stableMessageId: string | null;
    }[]
  >`
    SELECT id, status, failure_code AS "failureCode",
           stable_message_id AS "stableMessageId"
    FROM public.tenant_notification_deliveries
    WHERE tenant_id = ${fixture.tenant}::uuid
    ORDER BY id
  `;
  assert.deepEqual(Array.from(deliveries), [
    {
      id: fixture.queuedDelivery,
      status: "dead_lettered",
      failureCode: "tenant_suspended",
      stableMessageId: null,
    },
    {
      id: fixture.leasedDelivery,
      status: "dead_lettered",
      failureCode: "tenant_suspended",
      stableMessageId: null,
    },
    {
      id: fixture.reservedDelivery,
      status: "reserved",
      failureCode: null,
      stableMessageId: "periapsis-runtime-message",
    },
  ]);
  const attempts = await admin<
    {
      deliveryId: string;
      outcome: string | null;
      failureClass: string | null;
    }[]
  >`
    SELECT delivery_id AS "deliveryId", outcome,
           failure_class AS "failureClass"
    FROM public.tenant_notification_delivery_attempts
    WHERE tenant_id = ${fixture.tenant}::uuid
    ORDER BY delivery_id
  `;
  assert.deepEqual(Array.from(attempts), [
    {
      deliveryId: fixture.leasedDelivery,
      outcome: "fenced",
      failureClass: "security",
    },
    {
      deliveryId: fixture.reservedDelivery,
      outcome: null,
      failureClass: null,
    },
  ]);
  const slaJobs = await admin<
    { id: string; status: string; failureCode: string | null }[]
  >`
    SELECT id, status, last_failure_code AS "failureCode"
    FROM public.sla_evaluation_jobs
    WHERE tenant_id = ${fixture.tenant}::uuid
    ORDER BY id
  `;
  assert.deepEqual(
    Array.from(slaJobs),
    [fixture.slaJobQueued, fixture.slaJobLeased, fixture.slaJobRetry].map(
      (id) => ({
        id,
        status: "dead_lettered",
        failureCode: "tenant_suspended",
      }),
    ),
  );
  assert.deepEqual(await rlsCounts(), { alerts: 0, cases: 0 });
  await assert.rejects(
    admin`
      UPDATE public.alerts SET title = 'Blocked while suspended'
      WHERE id = ${fixture.alert}::uuid
    `,
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    admin`
      UPDATE public.cases SET title = 'Blocked while suspended'
      WHERE id = ${fixture.case}::uuid
    `,
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const now = new Date(Date.now() - 1_000);
  await admin`
    INSERT INTO public.tenant_notification_deliveries (
      id, tenant_id, event_id, delivery_key, template_snapshot,
      smtp_configuration_scope, smtp_configuration_id,
      smtp_configuration_version, channel, audience, recipient,
      destination_redacted, context, priority, deduplication_key,
      grouping_window_ms, grouping_maximum_items, retry, status,
      attempt_count, maximum_attempts, next_attempt_at, created_at, updated_at
    ) VALUES (
      ${fixture.futureDelivery}::uuid, ${fixture.tenant}::uuid,
      ${fixture.futureEvent}::uuid, ${"d".repeat(64)},
      ${admin.json(templateSnapshot)}::jsonb, 'platform',
      ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
      'future@example.invalid', 'f***@example.invalid', '{}'::jsonb,
      60, 'lifecycle-future', 0, 1, '{}'::jsonb, 'queued', 0, 3,
      ${now}, ${now}, ${now}
    )
  `;
  await admin`
    INSERT INTO public.sla_evaluation_jobs (
      id, tenant_id, sla_instance_id, expected_aggregate_version,
      status, available_at, attempt, maximum_attempts, fence,
      created_at, updated_at
    ) VALUES (
      ${fixture.slaJobFuture}::uuid, ${fixture.tenant}::uuid,
      ${fixture.slaInstanceFuture}::uuid, 1, 'queued', ${now}, 0, 3, 0,
      ${now}, ${now}
    )
  `;
  const notificationClaims = await asRole(
    admin,
    "periapsis_notifier",
    async (transaction) => {
      const [count] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM app.claim_notification_delivery_batch_v1(
          'lifecycle-runtime-worker', 10, 30000, transaction_timestamp()
        )
      `;
      return count?.count;
    },
  );
  assert.equal(notificationClaims, 0);
  const slaClaims = await asRole(
    admin,
    "periapsis_worker",
    async (transaction) => {
      const [count] = await transaction<{ count: number }[]>`
        SELECT count(*)::integer AS count
        FROM app.claim_sla_evaluation_jobs_v3(
          ${fixture.slaWorker}::uuid, transaction_timestamp(), 10, 30000000
        )
      `;
      return count?.count;
    },
  );
  assert.equal(slaClaims, 0);
  await admin`
    DELETE FROM public.tenant_notification_deliveries
    WHERE id = ${fixture.futureDelivery}::uuid
  `;
  await admin`
    DELETE FROM public.outbox_events WHERE id = ${fixture.futureEvent}::uuid
  `;
  await admin`
    DELETE FROM public.sla_evaluation_jobs WHERE id = ${fixture.slaJobFuture}::uuid
  `;

  const finalReceipt = await changeLifecycle(admin, {
    target: "active",
    expectedVersion: 4,
    reason: "Concurrent suspension cause resolved",
    auditId: fixture.finalAudit,
    requestId: fixture.finalRequest,
    correlationId: fixture.finalCorrelation,
  });
  assert.equal(finalReceipt.version, 5);
  assert.deepEqual(await rlsCounts(), { alerts: 1, cases: 1 });
  await admin`
    UPDATE public.alerts SET title = 'Restored after reactivation'
    WHERE id = ${fixture.alert}::uuid
  `;
  await admin`
    UPDATE public.cases SET title = 'Restored after reactivation'
    WHERE id = ${fixture.case}::uuid
  `;
  const terminalCounts = await admin<
    {
      deadDeliveries: number;
      reservedDeliveries: number;
      deadSlaJobs: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_notification_deliveries
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND status = 'dead_lettered') AS "deadDeliveries",
      (SELECT count(*)::integer
       FROM public.tenant_notification_deliveries
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND status = 'reserved') AS "reservedDeliveries",
      (SELECT count(*)::integer
       FROM public.sla_evaluation_jobs
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND status = 'dead_lettered') AS "deadSlaJobs"
  `;
  assert.deepEqual(terminalCounts[0], {
    deadDeliveries: 2,
    reservedDeliveries: 1,
    deadSlaJobs: 3,
  });
  const [finalState] = await admin<
    { status: string; version: number; revision: string; auditCount: number }[]
  >`
    SELECT tenant.status, tenant.version, state.revision::text AS revision,
      (SELECT count(*)::integer
       FROM public.platform_audit_events AS event
       WHERE event.resource_id = tenant.id
         AND event.action IN (
           'platform.tenant.suspended', 'platform.tenant.reactivated'
         )) AS "auditCount"
    FROM public.tenants AS tenant
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
    WHERE tenant.id = ${fixture.tenant}::uuid
  `;
  assert.deepEqual(finalState, {
    status: "active",
    version: 5,
    revision: "5",
    auditCount: 4,
  });

  const readiness = await Promise.all(
    (["periapsis_api", "periapsis_worker"] as const).map(async (role) => ({
      role,
      ready: await asRole(admin, role, async (transaction) => {
        const [row] = await transaction<{ ready: boolean }[]>`
          SELECT app.release_runtime_schema_readiness_v56() AS ready
        `;
        return row?.ready;
      }),
    })),
  );
  for (const { role, ready } of readiness) {
    assert.equal(ready, true, `${role} lifecycle readiness failed`);
  }
}

try {
  await main();
  process.stdout.write("platform tenant lifecycle runtime proof passed\n");
} finally {
  await Promise.all([admin.end(), contenderA.end(), contenderB.end()]);
}
