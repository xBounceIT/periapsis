import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql, type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type Document = Record<string, unknown>;
type QueueSource = {
  key: string;
  pendingCount: number;
  inFlightCount: number;
  failedCount: number;
  oldestPendingSeconds: number;
};
type Trace = readonly [string, string, string];

const runtimeRoles = [
  "periapsis_api",
  "periapsis_worker",
  "periapsis_notifier",
  "periapsis_auditor",
] as const;
const platformProjectionTables = [
  "platform_global_settings",
  "platform_feature_flags",
  "users",
  "tenants",
  "tenant_memberships",
  "auth_sessions",
  "platform_roles",
  "user_platform_roles",
  "platform_audit_chain_head",
  "outbox_events",
  "tenant_notification_deliveries",
  "ticket_bulk_jobs",
  "ticket_export_jobs",
  "ticket_export_artifact_cleanups",
  "tenant_audit_export_jobs",
  "platform_audit_export_jobs",
  "sla_evaluation_jobs",
  "sla_trigger_action_executions",
  "sla_object_event_ingress",
  "dfir_storage_objects",
  "tenant_ldap_sync_runs",
] as const;

const databaseUrl = process.env.PERIAPSIS_PLATFORM_OPERATIONS_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_OPERATIONS_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database with migration 0216 applied",
  );
}

const runSequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4d16-1600-7000-8000-${(runSequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  adminUser: uuid(1),
  auditorUser: uuid(2),
  ordinaryUser: uuid(3),
  tenant: uuid(4),
  adminRoleGrant: uuid(11),
  auditorRoleGrant: uuid(12),
  membership: uuid(20),
  adminMembership: uuid(21),
  adminSession: uuid(30),
  adminFamily: uuid(31),
  auditorSession: uuid(32),
  auditorFamily: uuid(33),
  tenantSession: uuid(34),
  tenantFamily: uuid(35),
  staleMfaSession: uuid(36),
  staleMfaFamily: uuid(37),
  notificationEvent: uuid(40),
  staleNotificationEvent: uuid(41),
  slaEvent: uuid(42),
  deadNotification: uuid(50),
  staleNotification: uuid(51),
  notificationFence: uuid(52),
  smtpConfiguration: uuid(53),
  slaIngress: uuid(60),
  slaObject: uuid(61),
  slaWorker: uuid(62),
  platformAuditExport: uuid(70),
  auditExportWorker: uuid(71),
} as const;

const suffix = runSequence.toString(36);
const digest = (label: string): Buffer =>
  createHash("sha256")
    .update(`platform-operations-runtime:${suffix}:${label}`)
    .digest();
let traceSequence = 100;
const nextID = (): string => {
  traceSequence += 1;
  return uuid(traceSequence);
};
const nextTrace = (): Trace => [nextID(), nextID(), nextID()];

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function isDocument(value: unknown): value is Document {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readDocuments(value: unknown, label: string): Document[] {
  if (!Array.isArray(value) || !value.every(isDocument)) {
    throw new TypeError(`${label} must be an array of documents`);
  }
  return value;
}

function readString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

function readQueueSources(value: unknown): QueueSource[] {
  return readDocuments(value, "queue sources").map((source) => {
    const {
      key,
      pendingCount,
      inFlightCount,
      failedCount,
      oldestPendingSeconds,
    } = source;
    if (
      typeof key !== "string" ||
      typeof pendingCount !== "number" ||
      typeof inFlightCount !== "number" ||
      typeof failedCount !== "number" ||
      typeof oldestPendingSeconds !== "number"
    ) {
      throw new TypeError("queue source contains an invalid field");
    }
    return {
      key,
      pendingCount,
      inFlightCount,
      failedCount,
      oldestPendingSeconds,
    };
  });
}

async function expectSqlState(
  operation: Promise<unknown>,
  expected: string,
  message: string,
): Promise<void> {
  await assert.rejects(
    operation,
    (error: unknown) => assertSqlState(error, expected),
    message,
  );
}

async function setApiContext(
  transaction: TransactionSql,
  userID: string,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', '', true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function asApi<T>(
  connection: Sql,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await connection.begin(async (transaction) => {
    await setApiContext(transaction, userID);
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function readDocument(
  connection: Sql,
  userID: string,
  query: (
    transaction: TransactionSql,
    trace: Trace,
  ) => PromiseLike<{ document: Document }[]>,
): Promise<Document> {
  return asApi(connection, userID, async (transaction) => {
    const rows = await query(transaction, nextTrace());
    assert.equal(rows.length, 1);
    return rows[0]!.document;
  });
}

async function expectApiDirectProjectionDenied(
  connection: Sql,
  table: (typeof platformProjectionTables)[number],
): Promise<void> {
  try {
    const rows = await connection.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', '', true),
          set_config('app.user_id', ${fixture.adminUser}, true)
      `;
      return transaction.unsafe<{ visible: number }[]>(
        `SELECT count(*)::integer AS visible FROM public."${table}"`,
      );
    });
    assert.equal(
      rows[0]?.visible,
      0,
      `tenantless API direct read must project no public.${table} rows`,
    );
  } catch (error) {
    assertSqlState(error, "42501");
  }
}

const admin = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const first = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const second = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

try {
  const [server] = await admin<{ major: number; migration: boolean }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major,
      to_regprocedure(
        'app.update_platform_feature_flag_v1(uuid,text,integer,boolean,text,uuid,uuid,uuid,inet,text)'
      ) IS NOT NULL AS migration
  `;
  assert.deepEqual(server, { major: 18, migration: true });

  const createdAt = new Date(Date.now() - 20 * 60_000);
  const updatedAt = new Date(Date.now() - 15 * 60_000);
  const staleLeaseAt = new Date(Date.now() - 10 * 60_000);
  const liveUntil = new Date(Date.now() + 60 * 60_000);
  const absoluteUntil = new Date(Date.now() + 2 * 60 * 60_000);
  const freshMfaAt = new Date(Date.now() - 60_000);
  const staleMfaAt = new Date(Date.now() - 30 * 60_000);
  const templateSnapshot = {
    key: "system.smtp-test",
    name: "Periapsis SMTP test",
    language: "en",
    version: 1,
    subject: "Periapsis SMTP test",
    html: "<p>This message verifies your Periapsis SMTP configuration.</p>",
    plainText: "This message verifies your Periapsis SMTP configuration.",
    css: "",
  };

  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users(id,email,display_name,active,created_at,updated_at)
      VALUES
        (${fixture.adminUser}::uuid,${`platform-admin-${suffix}@example.invalid`},
          'Platform Runtime Admin',true,${createdAt},${createdAt}),
        (${fixture.auditorUser}::uuid,${`platform-auditor-${suffix}@example.invalid`},
          'Platform Runtime Auditor',true,${createdAt},${createdAt}),
        (${fixture.ordinaryUser}::uuid,${`ordinary-${suffix}@example.invalid`},
          'Ordinary Runtime User',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.user_platform_roles(id,user_id,role_id,granted_at)
      SELECT ${fixture.adminRoleGrant}::uuid,${fixture.adminUser}::uuid,role.id,${createdAt}
      FROM public.platform_roles AS role
      WHERE role.key='platform_super_admin' AND role.system
    `;
    await transaction`
      INSERT INTO public.user_platform_roles(id,user_id,role_id,granted_at)
      SELECT ${fixture.auditorRoleGrant}::uuid,${fixture.auditorUser}::uuid,role.id,${createdAt}
      FROM public.platform_roles AS role
      WHERE role.key='platform_auditor' AND role.system
    `;
    await transaction`
      INSERT INTO public.tenants(id,slug,name,status,version)
      VALUES (
        ${fixture.tenant}::uuid,${`platform-operations-${suffix}`},
        'Platform operations runtime','active',1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status,lifecycle_revision,created_at,updated_at
      ) VALUES (
        ${fixture.membership}::uuid,${fixture.tenant}::uuid,${fixture.ordinaryUser}::uuid,
        'analyst','active',1,${createdAt},${createdAt}
      ),(
        ${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,${fixture.adminUser}::uuid,
        'tenant_admin','active',1,${createdAt},${createdAt}
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.adminMembership}::uuid
      )
    `;

    const sessions = [
      [
        fixture.adminSession,
        fixture.adminFamily,
        fixture.adminUser,
        null,
        freshMfaAt,
      ],
      [
        fixture.auditorSession,
        fixture.auditorFamily,
        fixture.auditorUser,
        null,
        freshMfaAt,
      ],
      [
        fixture.tenantSession,
        fixture.tenantFamily,
        fixture.adminUser,
        fixture.tenant,
        freshMfaAt,
      ],
      [
        fixture.staleMfaSession,
        fixture.staleMfaFamily,
        fixture.adminUser,
        null,
        staleMfaAt,
      ],
    ] as const;
    await Promise.all(
      sessions.map(
        ([id, family, user, activeTenant, mfaAt]) => transaction`
        INSERT INTO public.auth_sessions(
          id,user_id,rotation_family_id,active_tenant_id,token_digest,
          csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
          idle_expires_at,absolute_expires_at,created_at
        ) VALUES (
          ${id}::uuid,${user}::uuid,${family}::uuid,${activeTenant}::uuid,
          ${digest(`${id}:token`)}::bytea,${digest(`${id}:csrf`)}::bytea,
          'totp',${mfaAt},${createdAt},${liveUntil},${absoluteUntil},${createdAt}
        )
      `,
      ),
    );

    const outboxFixtures = [
      [
        fixture.notificationEvent,
        "dead-notification",
        "notification.webhook.custom",
        2,
      ],
      [
        fixture.staleNotificationEvent,
        "stale-notification",
        "notification.webhook.custom",
        2,
      ],
      [fixture.slaEvent, "sla-event", "sla.alert.updated", 1],
    ] as const;
    await Promise.all(
      outboxFixtures.map(
        ([eventID, label, eventType, schemaVersion]) => transaction`
        INSERT INTO public.outbox_events(
          id,tenant_id,aggregate_type,aggregate_id,aggregate_version,
          event_type,schema_version,payload,deduplication_key,actor_kind,
          producer,maximum_audience,occurred_at,available_at,created_at
        ) VALUES (
          ${eventID}::uuid,${fixture.tenant}::uuid,'runtime',${eventID}::uuid,
          1,${eventType},${schemaVersion},
          ${transaction.json({ operatorContext: {}, secretCanary: `never-project-${suffix}` })}::jsonb,
          ${`platform-operations-${label}-${suffix}`},'system',
          'platform.operations.runtime','operator',${createdAt},${createdAt},${createdAt}
        )
      `,
      ),
    );
    await transaction`
      INSERT INTO public.tenant_notification_deliveries(
        id,tenant_id,event_id,delivery_key,template_snapshot,
        smtp_configuration_scope,smtp_configuration_id,
        smtp_configuration_version,channel,audience,recipient,
        destination_redacted,context,priority,deduplication_key,
        grouping_window_ms,grouping_maximum_items,retry,status,attempt_count,
        maximum_attempts,next_attempt_at,lease_owner,fence_token,lease_until,
        failure_at,failure_class,failure_code,provider_receipt,created_at,updated_at
      ) VALUES
        (
          ${fixture.deadNotification}::uuid,${fixture.tenant}::uuid,
          ${fixture.notificationEvent}::uuid,${digest("dead-delivery").toString("hex")},
          ${transaction.json(templateSnapshot)}::jsonb,'platform',
          ${fixture.smtpConfiguration}::uuid,1,'email','operator',
          ${`secret-recipient-${suffix}@example.invalid`},'s***@example.invalid',
          ${transaction.json({ private: `never-project-${suffix}` })}::jsonb,
          50,${`dead-${suffix}`},0,1,'{}'::jsonb,'dead_lettered',3,3,
          NULL,NULL,NULL,NULL,${staleLeaseAt},'connectivity','connection_reset',
          ${transaction.json({ providerSecret: `never-project-${suffix}` })}::jsonb,
          ${createdAt},${updatedAt}
        ),
        (
          ${fixture.staleNotification}::uuid,${fixture.tenant}::uuid,
          ${fixture.staleNotificationEvent}::uuid,${digest("stale-delivery").toString("hex")},
          ${transaction.json(templateSnapshot)}::jsonb,'platform',
          ${fixture.smtpConfiguration}::uuid,1,'email','operator',
          'stale@example.invalid','s***@example.invalid','{}'::jsonb,
          40,${`stale-${suffix}`},0,1,'{}'::jsonb,'leased',1,3,
          ${createdAt},'runtime-worker',${fixture.notificationFence}::uuid,
          ${staleLeaseAt},NULL,NULL,NULL,NULL,${createdAt},${updatedAt}
        )
    `;
    await transaction`
      INSERT INTO public.sla_object_event_ingress(
        id,tenant_id,object_type,object_id,object_sequence,source_event_id,
        source_event_type,source_schema_version,source_digest,event_key,
        occurred_at,status,available_at,attempt,maximum_attempts,worker_id,
        lease_expires_at,fence,created_at,updated_at
      ) VALUES (
        ${fixture.slaIngress}::uuid,${fixture.tenant}::uuid,'alert',
        ${fixture.slaObject}::uuid,2,${fixture.slaEvent}::uuid,
        'sla.alert.updated',1,${digest("sla-source")}::bytea,'ticket.updated',
        ${createdAt},'leased',${createdAt},1,12,${fixture.slaWorker}::uuid,
        ${staleLeaseAt},1,${createdAt},${updatedAt}
      )
    `;
    const [epoch] = await transaction<{ permission_epoch: number }[]>`
      SELECT permission_epoch FROM public.platform_user_authorization_epochs
      WHERE user_id=${fixture.adminUser}::uuid
    `;
    assert(epoch, "platform permission epoch was not initialized");
    await transaction`
      INSERT INTO public.platform_audit_export_jobs(
        id,requester_user_id,requester_session_id,permission_epoch,
        normalized_filter,filter_digest,projection_version,format,state,
        revision,attempts,maximum_attempts,failure_code,requested_at,updated_at,
        available_at,expires_at,lease_worker_id,lease_fence,lease_claimed_at,
        lease_expires_at
      ) VALUES (
        ${fixture.platformAuditExport}::uuid,${fixture.adminUser}::uuid,
        ${fixture.adminSession}::uuid,${epoch.permission_epoch},'{}'::jsonb,
        ${digest("audit-filter")}::bytea,1,'jsonl','running',1,1,5,'none',
        ${createdAt},${updatedAt},${createdAt},${liveUntil},
        ${fixture.auditExportWorker}::uuid,${digest("audit-fence")}::bytea,
        ${updatedAt},${staleLeaseAt}
      )
    `;
  });

  const [privileges] = await admin<
    {
      apiSettings: boolean;
      workerSettings: boolean;
      auditorSource: boolean;
      apiPrivateHelper: boolean;
      workerPublicFunction: boolean;
      ownerLogin: boolean;
      ownerBypass: boolean;
    }[]
  >`
    SELECT
      has_table_privilege('periapsis_api','public.platform_global_settings','SELECT') AS "apiSettings",
      has_table_privilege('periapsis_worker','public.platform_global_settings','UPDATE') AS "workerSettings",
      has_table_privilege('periapsis_auditor','public.tenant_notification_deliveries','SELECT') AS "auditorSource",
      has_function_privilege('periapsis_api',
        'app.private_require_platform_operations_actor_v1(uuid,text,boolean)'::regprocedure,
        'EXECUTE') AS "apiPrivateHelper",
      has_function_privilege('periapsis_worker',
        'app.list_platform_operation_queues_v1(uuid,uuid,uuid,uuid,inet,text)'::regprocedure,
        'EXECUTE') AS "workerPublicFunction",
      role.rolcanlogin AS "ownerLogin", role.rolbypassrls AS "ownerBypass"
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname='periapsis_platform_operations_owner'
  `;
  assert.deepEqual(privileges, {
    apiSettings: false,
    workerSettings: false,
    auditorSource: false,
    apiPrivateHelper: false,
    workerPublicFunction: false,
    ownerLogin: false,
    ownerBypass: false,
  });
  const rlsState = await admin<
    { tableName: string; enabled: boolean; forced: boolean }[]
  >`
    SELECT relation.relname AS "tableName",
      relation.relrowsecurity AS enabled,
      relation.relforcerowsecurity AS forced
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='public'
      AND relation.relname IN ${admin(platformProjectionTables)}
    ORDER BY relation.relname
  `;
  assert.equal(rlsState.length, platformProjectionTables.length);
  assert(
    rlsState.every((row) => row.enabled && row.forced),
    `every projection source must enforce RLS: ${JSON.stringify(rlsState)}`,
  );
  const inheritedDirectSelects = await admin<
    { roleName: string; tableName: string }[]
  >`
    SELECT runtime_role.role_name AS "roleName",
      source_table.table_name AS "tableName"
    FROM unnest(${[...runtimeRoles]}::text[]) AS runtime_role(role_name)
    CROSS JOIN unnest(${[...platformProjectionTables]}::text[])
      AS source_table(table_name)
    WHERE has_table_privilege(
      runtime_role.role_name,
      format('public.%I', source_table.table_name),
      'SELECT'
    )
    ORDER BY runtime_role.role_name,source_table.table_name
  `;
  assert.deepEqual(
    [...inheritedDirectSelects],
    [
      { roleName: "periapsis_api", tableName: "dfir_storage_objects" },
      { roleName: "periapsis_api", tableName: "tenant_memberships" },
      { roleName: "periapsis_api", tableName: "tenants" },
      { roleName: "periapsis_api", tableName: "users" },
      { roleName: "periapsis_worker", tableName: "dfir_storage_objects" },
      { roleName: "periapsis_worker", tableName: "outbox_events" },
    ],
  );
  await Promise.all(
    platformProjectionTables.map((table) =>
      expectApiDirectProjectionDenied(admin, table),
    ),
  );
  await expectSqlState(
    asApi(
      first,
      fixture.adminUser,
      (transaction) =>
        transaction`SELECT * FROM public.platform_global_settings`,
    ),
    "42501",
    "the API role must not read the owner table directly",
  );
  await expectSqlState(
    asApi(
      first,
      fixture.adminUser,
      (transaction) =>
        transaction`SELECT * FROM app.private_require_platform_operations_actor_v1(
        ${fixture.adminSession}::uuid,'platform.operations.read',false
      )`,
    ),
    "42501",
    "the API role must not call the private authority helper",
  );
  const invalidTrace = nextTrace();
  await expectSqlState(
    asApi(
      first,
      fixture.adminUser,
      (transaction) => transaction`
        SELECT app.get_platform_operation_health_v1(
          ${fixture.adminSession}::uuid,NULL::uuid,
          ${invalidTrace[1]}::uuid,${invalidTrace[2]}::uuid,
          '198.51.100.16'::inet,'Periapsis platform operations runtime'
        )
      `,
    ),
    "22023",
    "a null audit event id must not bypass the trace validator",
  );
  const nullUserLimitTrace = nextTrace();
  const nullFailureLimitTrace = nextTrace();
  await Promise.all([
    expectSqlState(
      asApi(
        first,
        fixture.adminUser,
        (transaction) => transaction`
        SELECT app.list_platform_users_v1(
          ${fixture.adminSession}::uuid,NULL::uuid,NULL::integer,
          ${nullUserLimitTrace[0]}::uuid,${nullUserLimitTrace[1]}::uuid,
          ${nullUserLimitTrace[2]}::uuid,'198.51.100.16'::inet,
          'Periapsis platform operations runtime'
        )
      `,
      ),
      "22023",
      "platform user inventory must reject a null page limit",
    ),
    expectSqlState(
      asApi(
        second,
        fixture.adminUser,
        (transaction) => transaction`
        SELECT app.list_platform_failed_notifications_v1(
          ${fixture.adminSession}::uuid,NULL::timestamptz,NULL::uuid,NULL::integer,
          ${nullFailureLimitTrace[0]}::uuid,${nullFailureLimitTrace[1]}::uuid,
          ${nullFailureLimitTrace[2]}::uuid,'198.51.100.16'::inet,
          'Periapsis platform operations runtime'
        )
      `,
      ),
      "22023",
      "failed notification inventory must reject a null page limit",
    ),
  ]);

  const usersTrace = nextTrace();
  const usersDocument = await asApi(
    first,
    fixture.adminUser,
    async (transaction) => {
      const [row] = await transaction<{ document: Document }[]>`
        SELECT app.list_platform_users_v1(
          ${fixture.adminSession}::uuid,NULL,100,${usersTrace[0]}::uuid,
          ${usersTrace[1]}::uuid,${usersTrace[2]}::uuid,'198.51.100.16'::inet,
          'Periapsis platform operations runtime'
        ) AS document
      `;
      assert(row);
      return row.document;
    },
  );
  const userItems = readDocuments(usersDocument.items, "user inventory items");
  const ordinary = userItems.find((item) => item.id === fixture.ordinaryUser);
  assert(ordinary, "redacted user inventory omitted the ordinary user");
  assert.deepEqual(Object.keys(ordinary).toSorted(), [
    "active",
    "activeTenantMembershipCount",
    "displayName",
    "email",
    "id",
    "liveSessionsByAuthenticationMethod",
    "platformRoles",
    "totalTenantMembershipCount",
  ]);
  assert.equal(ordinary.activeTenantMembershipCount, 1);
  assert.equal(ordinary.totalTenantMembershipCount, 1);
  assert(!JSON.stringify(usersDocument).includes("token"));

  const firstUserPage = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.list_platform_users_v1(
        ${fixture.adminSession}::uuid,NULL,1,${trace[0]}::uuid,
        ${trace[1]}::uuid,${trace[2]}::uuid,'198.51.100.16'::inet,
        'Periapsis platform operations runtime'
      ) AS document
    `,
  );
  const firstUserItems = readDocuments(firstUserPage.items, "first user page");
  assert.equal(firstUserItems.length, 1);
  const firstUserCursor = readString(
    firstUserPage.nextCursor,
    "first user page cursor",
  );
  const secondUserPage = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.list_platform_users_v1(
        ${fixture.adminSession}::uuid,${firstUserCursor}::uuid,
        1,${trace[0]}::uuid,${trace[1]}::uuid,${trace[2]}::uuid,
        '198.51.100.16'::inet,'Periapsis platform operations runtime'
      ) AS document
    `,
  );
  const secondUserItems = readDocuments(
    secondUserPage.items,
    "second user page",
  );
  assert.equal(secondUserItems.length, 1);
  assert.notEqual(
    firstUserItems[0]?.id,
    secondUserItems[0]?.id,
    "cursor pagination must neither replay nor skip onto the same user",
  );

  const queuesDocument = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.list_platform_operation_queues_v1(
        ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
        ${trace[2]}::uuid,'198.51.100.16'::inet,
        'Periapsis platform operations runtime'
      ) AS document
    `,
  );
  const queueSources = readQueueSources(queuesDocument.sources);
  assert.equal(queueSources.length, 13);
  for (const key of [
    "notification_delivery",
    "sla_event_ingress",
    "platform_audit_export",
  ]) {
    const source = queueSources.find((item) => item.key === key);
    assert(source, `missing ${key} queue source`);
    assert(source.pendingCount >= 1, `${key} stale lease was not reclaimable`);
    assert(
      source.oldestPendingSeconds > 0,
      `${key} stale age was not reported`,
    );
  }
  assert(!JSON.stringify(queuesDocument).includes(`never-project-${suffix}`));

  const healthDocument = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.get_platform_operation_health_v1(
        ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
        ${trace[2]}::uuid,'198.51.100.16'::inet,
        'Periapsis platform operations runtime'
      ) AS document
    `,
  );
  assert.equal(healthDocument.status, "degraded");
  assert.equal(typeof healthDocument.checkedAt, "string");
  const healthChecks = readDocuments(healthDocument.checks, "health checks");
  const databaseCheck = healthChecks.find((check) => check.key === "database");
  const backlogCheck = healthChecks.find(
    (check) => check.key === "queue_backlog",
  );
  const failureCheck = healthChecks.find(
    (check) => check.key === "queue_failures",
  );
  assert.equal(databaseCheck?.status, "healthy");
  assert.equal(backlogCheck?.status, "degraded");
  assert.equal(failureCheck?.status, "degraded");
  assert(Number(failureCheck?.failedCount) >= 1);
  const notificationQueue = queueSources.find(
    (item) => item.key === "notification_delivery",
  );
  assert(notificationQueue && notificationQueue.failedCount >= 1);

  const initialSettings = await asApi(
    first,
    fixture.adminUser,
    async (transaction) => {
      const trace = nextTrace();
      const [row] = await transaction<
        { platform_name: string; version: number }[]
      >`
        SELECT platform_name,version FROM app.get_platform_global_settings_v1(
          ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,
          'Periapsis platform operations runtime'
        )
      `;
      assert(row);
      return row;
    },
  );
  assert.deepEqual(initialSettings, { platform_name: "Periapsis", version: 1 });

  const settingsAudit = nextTrace();
  const [updatedSettings] = await asApi(
    first,
    fixture.adminUser,
    (transaction) => transaction<
      { platform_name: string; default_locale: string; version: number }[]
    >`
      SELECT platform_name,default_locale,version
      FROM app.update_platform_global_settings_v1(
        ${fixture.adminSession}::uuid,1,'Periapsis Control','it-IT','Europe/Rome',
        'https://support.example.invalid/help','Approve platform defaults.',
        ${settingsAudit[0]}::uuid,${settingsAudit[1]}::uuid,
        ${settingsAudit[2]}::uuid,'198.51.100.16'::inet,
        'Periapsis platform operations runtime'
      )
    `,
  );
  assert.deepEqual(updatedSettings, {
    platform_name: "Periapsis Control",
    default_locale: "it-IT",
    version: 2,
  });
  const [settingsAuditRow] = await admin<{ reason: string; action: string }[]>`
    SELECT reason,action FROM public.platform_audit_events
    WHERE id=${settingsAudit[0]}::uuid
  `;
  assert.deepEqual(settingsAuditRow, {
    reason: "Approve platform defaults.",
    action: "platform.settings.updated",
  });
  await expectSqlState(
    asApi(first, fixture.adminUser, async (transaction) => {
      const trace = nextTrace();
      await transaction`
        SELECT * FROM app.update_platform_global_settings_v1(
          ${fixture.adminSession}::uuid,2,'Invalid','en','Not/A-Timezone',NULL,
          'Unsafe timezone.',${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        )
      `;
    }),
    "22023",
    "unknown timezones must be rejected",
  );
  await expectSqlState(
    asApi(first, fixture.adminUser, async (transaction) => {
      const trace = nextTrace();
      await transaction`
        SELECT * FROM app.update_platform_global_settings_v1(
          ${fixture.staleMfaSession}::uuid,2,'Stale MFA','en','UTC',NULL,
          'Stale MFA must fail.',${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        )
      `;
    }),
    "42501",
    "mutations must require fresh MFA",
  );

  const race = await Promise.allSettled(
    [first, second].map((connection, index) =>
      asApi(connection, fixture.adminUser, async (transaction) => {
        const trace = nextTrace();
        const [row] = await transaction<{ version: number }[]>`
          SELECT version FROM app.update_platform_global_settings_v1(
            ${fixture.adminSession}::uuid,2,${`Periapsis Race ${index}`},'it-IT',
            'Europe/Rome','https://support.example.invalid/help',
            ${`Concurrent settings update ${index}.`},${trace[0]}::uuid,
            ${trace[1]}::uuid,${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
          )
        `;
        return row?.version;
      }),
    ),
  );
  assert.equal(
    race.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejectedRace = race.find((result) => result.status === "rejected");
  assert(rejectedRace?.status === "rejected");
  assertSqlState(rejectedRace.reason, "40001");

  const flagOffTrace = nextTrace();
  const [flagOff] = await asApi(
    first,
    fixture.adminUser,
    (transaction) => transaction<{ enabled: boolean; version: number }[]>`
      SELECT enabled,version FROM app.update_platform_feature_flag_v1(
        ${fixture.adminSession}::uuid,'platform_failed_notifications_view',1,
        false,'Temporarily hide failed notifications.',${flagOffTrace[0]}::uuid,
        ${flagOffTrace[1]}::uuid,${flagOffTrace[2]}::uuid,
        '198.51.100.16'::inet,'runtime'
      )
    `,
  );
  assert.deepEqual(flagOff, { enabled: false, version: 2 });
  await expectSqlState(
    readDocument(
      first,
      fixture.adminUser,
      (transaction, trace) => transaction<{ document: Document }[]>`
        SELECT app.list_platform_failed_notifications_v1(
          ${fixture.adminSession}::uuid,NULL,NULL,50,${trace[0]}::uuid,
          ${trace[1]}::uuid,${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        ) AS document
      `,
    ),
    "42501",
    "the real feature flag must gate the failed notification projection",
  );
  const flagsWhileOff = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.list_platform_feature_flags_v1(
        ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
        ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
      ) AS document
    `,
  );
  assert.equal(
    readDocuments(flagsWhileOff.items, "feature flag items")[0]?.enabled,
    false,
  );
  await asApi(first, fixture.adminUser, async (transaction) => {
    const trace = nextTrace();
    await transaction`
      SELECT * FROM app.update_platform_feature_flag_v1(
        ${fixture.adminSession}::uuid,'platform_failed_notifications_view',2,
        true,'Restore failed notification visibility.',${trace[0]}::uuid,
        ${trace[1]}::uuid,${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
      )
    `;
  });

  const failedDocument = await readDocument(
    first,
    fixture.adminUser,
    (transaction, trace) => transaction<{ document: Document }[]>`
      SELECT app.list_platform_failed_notifications_v1(
        ${fixture.adminSession}::uuid,NULL,NULL,50,${trace[0]}::uuid,
        ${trace[1]}::uuid,${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
      ) AS document
    `,
  );
  const failedItem = readDocuments(
    failedDocument.items,
    "failed notification items",
  ).find((item) => item.id === fixture.deadNotification);
  assert(failedItem, "failed notification projection omitted fixture");
  assert.deepEqual(Object.keys(failedItem).toSorted(), [
    "attemptCount",
    "channel",
    "createdAt",
    "failureAt",
    "failureClass",
    "failureCode",
    "id",
    "tenantId",
    "updatedAt",
  ]);
  assert.equal(failedItem.failureCode, "unknown");
  assert(!JSON.stringify(failedDocument).includes(`never-project-${suffix}`));
  assert(!JSON.stringify(failedDocument).includes("secret-recipient"));

  await expectSqlState(
    readDocument(
      first,
      fixture.auditorUser,
      (transaction, trace) => transaction<{ document: Document }[]>`
        SELECT app.list_platform_operation_queues_v1(
          ${fixture.auditorSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        ) AS document
      `,
    ),
    "42501",
    "platform auditor must not inherit operations permissions",
  );
  await expectSqlState(
    readDocument(
      first,
      fixture.adminUser,
      (transaction, trace) => transaction<{ document: Document }[]>`
        SELECT app.list_platform_operation_queues_v1(
          ${fixture.tenantSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        ) AS document
      `,
    ),
    "42501",
    "tenant-scoped sessions must not cross into platform operations",
  );

  await admin`
    DELETE FROM public.platform_role_permissions AS role_permission
    USING public.platform_roles AS role, public.platform_permissions AS permission
    WHERE role_permission.role_id=role.id
      AND role_permission.permission_id=permission.id
      AND role.key='platform_super_admin'
      AND permission.key='platform.operations.read'
  `;
  await expectSqlState(
    readDocument(
      first,
      fixture.adminUser,
      (transaction, trace) => transaction<{ document: Document }[]>`
        SELECT app.list_platform_operation_queues_v1(
          ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        ) AS document
      `,
    ),
    "42501",
    "permission revocation must take effect on the next request",
  );
  await admin`
    INSERT INTO public.platform_role_permissions(role_id,permission_id)
    SELECT role.id,permission.id
    FROM public.platform_roles AS role
    CROSS JOIN public.platform_permissions AS permission
    WHERE role.key='platform_super_admin' AND role.system
      AND permission.key='platform.operations.read'
  `;

  await admin`
    UPDATE public.auth_sessions
    SET revoked_at=clock_timestamp(),revoke_reason='platform operations runtime revocation'
    WHERE id=${fixture.adminSession}::uuid
  `;
  await expectSqlState(
    asApi(first, fixture.adminUser, async (transaction) => {
      const trace = nextTrace();
      await transaction`
        SELECT * FROM app.get_platform_global_settings_v1(
          ${fixture.adminSession}::uuid,${trace[0]}::uuid,${trace[1]}::uuid,
          ${trace[2]}::uuid,'198.51.100.16'::inet,'runtime'
        )
      `;
    }),
    "42501",
    "session revocation must take effect on the next request",
  );

  const [auditSummary] = await admin<
    { calls: number; unsafe: number; actor_mismatch: number }[]
  >`
    SELECT count(*)::integer AS calls,
      count(*) FILTER (WHERE metadata::text LIKE ${`%never-project-${suffix}%`})::integer AS unsafe,
      count(*) FILTER (WHERE actor_user_id<>${fixture.adminUser}::uuid)::integer AS actor_mismatch
    FROM public.platform_audit_events
    WHERE action LIKE 'platform.operations.%'
       OR action IN ('platform.users.read','platform.settings.read',
         'platform.settings.updated','platform.feature_flags.read',
         'platform.feature_flag.updated')
  `;
  assert(auditSummary && auditSummary.calls >= 10);
  assert.equal(auditSummary.unsafe, 0);
  assert.equal(auditSummary.actor_mismatch, 0);

  process.stdout.write(
    `${JSON.stringify({
      database: new URL(databaseUrl).pathname.slice(1),
      postgresMajor: server.major,
      queueSources: queueSources.length,
      auditedCalls: auditSummary.calls,
      result: "platform operations runtime proof passed",
    })}\n`,
  );
} finally {
  await Promise.all([admin.end(), first.end(), second.end()]);
}
