import assert from "node:assert/strict";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_NOTIFICATION_SECURITY_TEST_DATABASE_URL;
const notifierDatabaseUrl =
  process.env.PERIAPSIS_NOTIFICATION_SECURITY_NOTIFIER_DATABASE_URL;
const apiDatabaseUrl =
  process.env.PERIAPSIS_NOTIFICATION_SECURITY_API_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_NOTIFICATION_SECURITY_TEST_DATABASE_URL must name a fresh migrated and seeded PostgreSQL 18 database",
  );
}
if (notifierDatabaseUrl === undefined || notifierDatabaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_NOTIFICATION_SECURITY_NOTIFIER_DATABASE_URL must authenticate as the exact least-privileged periapsis_notifier_login role",
  );
}
if (apiDatabaseUrl === undefined || apiDatabaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_NOTIFICATION_SECURITY_API_DATABASE_URL must authenticate as the exact least-privileged periapsis_api_login role",
  );
}

const fixture = {
  tenant: "01a05700-1000-7000-8000-000000000001",
  foreignTenant: "01a05700-1000-7000-8000-000000000002",
  user: "01a05700-1000-7000-8000-000000000101",
  membership: "01a05700-1000-7000-8000-000000000201",
  secret: "01a05700-1000-7000-8000-000000000301",
  smtpConfiguration: "01a05700-1000-7000-8000-000000000302",
  deliveryEvent: "01a05700-1000-7000-8000-000000000401",
  delivery: "01a05700-1000-7000-8000-000000000402",
  foreignEvent: "01a05700-1000-7000-8000-000000000403",
  crossTenantDelivery: "01a05700-1000-7000-8000-000000000404",
  pendingEvent: "01a05700-1000-7000-8000-000000000405",
  unicodeTraceEvent: "01a05700-1000-7000-8000-000000000406",
  oversizedTraceEvent: "01a05700-1000-7000-8000-000000000407",
} as const;

const traceParent = "00-11111111111111111111111111111111-2222222222222222-01";
const traceState = "vendor=value";
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
const retryPolicy = {
  maximumAttempts: 3,
  initialDelayMs: 1_000,
  maximumDelayMs: 30_000,
  multiplier: 2,
  jitterPercent: 10,
} as const;

const admin = postgres(databaseUrl, { max: 8, onnotice: () => undefined });
const notifier = postgres(notifierDatabaseUrl, {
  max: 4,
  onnotice: () => undefined,
});
const api = postgres(apiDatabaseUrl, { max: 1, onnotice: () => undefined });

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

async function asNotifier<T>(
  action: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await notifier.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await action(transaction) };
  });
  return result.value;
}

async function claimEmail(
  workerID: string,
): Promise<readonly Record<string, unknown>[]> {
  return asNotifier(async (transaction) => {
    const rows = await transaction<{ claim: Record<string, unknown> }[]>`
      SELECT claim
      FROM app.claim_notification_delivery_batch_v1(
        ${workerID}, 1, 5000, transaction_timestamp()
      )
    `;
    return rows.map((row) => row.claim);
  });
}

async function dispatchReadiness(): Promise<{
  queueDepth: number;
  oldestPendingSeconds: number;
  roleSafe: boolean;
  schemaSafe: boolean;
}> {
  return asNotifier(async (transaction) => {
    const [row] = await transaction<
      {
        queue_depth: string;
        oldest_pending_seconds: string;
        role_safe: boolean;
        schema_safe: boolean;
      }[]
    >`SELECT * FROM app.notification_dispatch_readiness_v53()`;
    assert(row, "notification readiness returned no row");
    return {
      queueDepth: Number(row.queue_depth),
      oldestPendingSeconds: Number(row.oldest_pending_seconds),
      roleSafe: row.role_safe,
      schemaSafe: row.schema_safe,
    };
  });
}

async function verifyKeyring(versions: readonly number[]): Promise<boolean> {
  return api.begin(async (transaction) => {
    const [row] = await transaction<{ verified: boolean }[]>`
      SELECT app.verify_notification_keyring_v1(
        ${Array.from(versions)}::smallint[]
      ) AS verified
    `;
    assert(row, "notification keyring verifier returned no row");
    return row.verified;
  });
}

try {
  const createdAt = new Date(Date.now() - 10_000);

  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, 'notification-security-proof',
         'Notification security proof'),
        (${fixture.foreignTenant}::uuid, 'notification-security-foreign',
         'Notification security foreign')
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES (
        ${fixture.user}::uuid, 'notification-proof@example.invalid',
        'Notification proof'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES (
        ${fixture.membership}::uuid, ${fixture.tenant}::uuid,
        ${fixture.user}::uuid, 'tenant_admin', 'active'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_secret_versions (
        tenant_id, secret_id, version, kind, key_version, nonce, ciphertext,
        created_at, created_by_membership_id, created_by_user_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.secret}::uuid, 1,
        'smtp_password', 1, decode(repeat('aa', 12), 'hex'),
        decode(repeat('bb', 17), 'hex'), ${createdAt},
        ${fixture.membership}::uuid, ${fixture.user}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_secret_versions (
        tenant_id, secret_id, version, kind, key_version, nonce, ciphertext,
        created_at, created_by_membership_id, created_by_user_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.secret}::uuid, 2,
        'smtp_password', 2, decode(repeat('cc', 12), 'hex'),
        decode(repeat('dd', 17), 'hex'), ${createdAt},
        ${fixture.membership}::uuid, ${fixture.user}::uuid
      ), (
        ${fixture.tenant}::uuid, ${fixture.secret}::uuid, 3,
        'smtp_password', 3, decode(repeat('ee', 12), 'hex'),
        decode(repeat('ff', 17), 'hex'), ${createdAt},
        ${fixture.membership}::uuid, ${fixture.user}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_smtp_configurations (
        id, tenant_id, current_version, created_at,
        created_by_membership_id, created_by_user_id, updated_at
      ) VALUES (
        ${fixture.smtpConfiguration}::uuid, ${fixture.tenant}::uuid, 1,
        ${createdAt}, ${fixture.membership}::uuid, ${fixture.user}::uuid,
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_smtp_configuration_versions (
        tenant_id, configuration_id, version, name, host, port, security,
        username, password_secret_id, password_secret_version,
        from_name, from_email, timeout_ms, maximum_connections,
        maximum_messages_per_connection, rate_limit_per_second, enabled,
        created_at, created_by_membership_id, created_by_user_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.smtpConfiguration}::uuid, 1,
        'Security proof SMTP', 'smtp.example.invalid', 465, 'tls',
        'proof-user', ${fixture.secret}::uuid, 1,
        'Periapsis proof', 'proof@example.invalid', 10000, 1, 100, 10, true,
        ${createdAt}, ${fixture.membership}::uuid, ${fixture.user}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_smtp_configuration_versions (
        tenant_id, configuration_id, version, name, host, port, security,
        username, password_secret_id, password_secret_version,
        from_name, from_email, timeout_ms, maximum_connections,
        maximum_messages_per_connection, rate_limit_per_second, enabled,
        created_at, created_by_membership_id, created_by_user_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.smtpConfiguration}::uuid, 2,
        'Security proof SMTP rotated', 'smtp.example.invalid', 465, 'tls',
        'proof-user', ${fixture.secret}::uuid, 2,
        'Periapsis proof', 'proof@example.invalid', 10000, 1, 100, 10, true,
        ${createdAt}, ${fixture.membership}::uuid, ${fixture.user}::uuid
      )
    `;
    await transaction`
      UPDATE public.tenant_notification_smtp_configurations
      SET current_version = 2, updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.smtpConfiguration}::uuid
    `;
    await transaction`
      INSERT INTO public.outbox_events (
        id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, schema_version, payload, deduplication_key,
        actor_kind, producer, maximum_audience, traceparent, tracestate,
        occurred_at, available_at, processed_at, created_at
      ) VALUES (
        ${fixture.deliveryEvent}::uuid, ${fixture.tenant}::uuid, 'contact',
        ${fixture.smtpConfiguration}::uuid, 1, 'notification.webhook.custom',
        2, ${admin.json({ operatorContext: {} })}::jsonb,
        'notification-security-delivery-event', 'system',
        'notification.security_test', 'operator', ${traceParent}, ${traceState},
        ${createdAt}, ${createdAt}, ${createdAt}, ${createdAt}
      ), (
        ${fixture.foreignEvent}::uuid, ${fixture.foreignTenant}::uuid, 'contact',
        ${fixture.smtpConfiguration}::uuid, 1, 'notification.webhook.custom',
        2, ${admin.json({ operatorContext: {} })}::jsonb,
        'notification-security-foreign-event', 'system',
        'notification.security_test', 'operator', NULL, NULL,
        ${createdAt}, ${createdAt}, ${createdAt}, ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_deliveries (
        id, tenant_id, event_id, delivery_key, template_snapshot,
        smtp_configuration_scope, smtp_configuration_id,
        smtp_configuration_version, channel, audience, recipient,
        destination_redacted, context, priority, deduplication_key,
        grouping_window_ms, grouping_maximum_items, retry,
        maximum_attempts, next_attempt_at, created_at, updated_at
      ) VALUES (
        ${fixture.delivery}::uuid, ${fixture.tenant}::uuid,
        ${fixture.deliveryEvent}::uuid, ${"a".repeat(64)},
        ${admin.json(templateSnapshot)}::jsonb, 'tenant',
        ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
        'recipient@example.invalid', 'r***@example.invalid', '{}'::jsonb,
        100, 'notification-security-delivery', 0, 1,
        ${admin.json(retryPolicy)}::jsonb, 3, ${createdAt},
        ${createdAt}, ${createdAt}
      )
    `;
  });

  await assert.rejects(
    asNotifier(async (transaction) => {
      await transaction`SELECT count(*) FROM public.tenant_notification_deliveries`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    api`SELECT count(*) FROM public.tenant_notification_deliveries`,
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [apiBoundary] = await admin<
    {
      canReadDeliveries: boolean;
      canExecutePrivateTraceValidator: boolean;
      notifierCanInsertAudit: boolean;
    }[]
  >`
    SELECT
      pg_catalog.has_table_privilege(
        'periapsis_api', 'public.tenant_notification_deliveries', 'SELECT'
      ) AS "canReadDeliveries",
      pg_catalog.has_function_privilege(
        'periapsis_api',
        'app.private_notification_trace_context_is_safe_v1(text,text)'::regprocedure,
        'EXECUTE'
      ) AS "canExecutePrivateTraceValidator",
      pg_catalog.has_any_column_privilege(
        'periapsis_notifier', 'public.audit_events', 'INSERT'
      ) AS "notifierCanInsertAudit"
  `;
  assert.deepEqual(apiBoundary, {
    canReadDeliveries: false,
    canExecutePrivateTraceValidator: false,
    notifierCanInsertAudit: false,
  });

  const emptyReadiness = await dispatchReadiness();
  assert.deepEqual(emptyReadiness, {
    queueDepth: 1,
    oldestPendingSeconds: 0,
    roleSafe: true,
    schemaSafe: true,
  });
  assert.equal(
    await verifyKeyring([2]),
    false,
    "an in-flight delivery must retain its historical key version",
  );
  assert.equal(await verifyKeyring([1, 2]), true);

  const raced = (
    await Promise.all([
      claimEmail("notification-worker-a"),
      claimEmail("notification-worker-b"),
    ])
  ).flat();
  assert.equal(raced.length, 1, "two workers must have one delivery winner");
  const firstClaim = raced[0];
  assert(firstClaim, "delivery claim is missing");
  assert.equal(firstClaim.id, fixture.delivery);
  assert.equal(firstClaim.smtpConfigurationScope, "tenant");
  assert.deepEqual(firstClaim.traceContext, {
    traceParent,
    traceState,
  });
  const firstFence = String(firstClaim.fenceToken);
  const stableMessageID = `<${"c".repeat(64)}@notifications.periapsis.invalid>`;

  const reserve = async (): Promise<string> =>
    asNotifier(async (transaction) => {
      const [row] = await transaction<{ outcome: string }[]>`
        SELECT app.reserve_notification_delivery_submission_v2(
          ${fixture.delivery}::uuid, ${firstFence}::uuid, 'email',
          ${stableMessageID}, transaction_timestamp()
        ) AS outcome
      `;
      assert(row);
      return row.outcome;
    });
  assert.equal(await reserve(), "reserved");
  assert.equal(
    await reserve(),
    "reserved",
    "lost reserve response must replay",
  );

  await assert.rejects(
    asNotifier(async (transaction) => {
      await transaction`
        SELECT app.complete_notification_delivery_v2(
          ${fixture.delivery}::uuid, ${firstFence}::uuid, 'email',
          ${admin.json({
            provider: "smtp",
            receiptDigest: "d".repeat(64),
            acceptedCount: "1",
            rejectedCount: 0,
            responseClass: 2,
          })}::jsonb,
          transaction_timestamp()
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  await assert.rejects(
    asNotifier(async (transaction) => {
      await transaction`
        SELECT app.complete_notification_delivery_v2(
          ${fixture.delivery}::uuid, ${firstFence}::uuid, 'email',
          ${admin.json({
            provider: "smtp",
            receiptDigest: "d".repeat(64),
            acceptedCount: 1,
            rejectedCount: 0,
            responseClass: 4,
          })}::jsonb,
          transaction_timestamp()
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const failedAt = new Date(Date.now() - 2_000);
  const dueAt = new Date(failedAt.getTime() + 1_000);
  await asNotifier(async (transaction) => {
    await transaction`
      SELECT app.retry_notification_delivery_v2(
        ${fixture.delivery}::uuid, ${firstFence}::uuid, 'email',
        'connectivity', ${dueAt}, ${failedAt}, true
      )
    `;
  });
  await asNotifier(async (transaction) => {
    await transaction`
      SELECT app.retry_notification_delivery_v2(
        ${fixture.delivery}::uuid, ${firstFence}::uuid, 'email',
        'connectivity', ${dueAt}, ${failedAt}, true
      )
    `;
  });

  const [secondClaim] = await claimEmail("notification-worker-b");
  assert(secondClaim, "retry was not claimable");
  const secondFence = String(secondClaim.fenceToken);
  await admin`
    UPDATE public.tenant_notification_deliveries
    SET lease_until = transaction_timestamp() - interval '1 second'
    WHERE id = ${fixture.delivery}::uuid AND fence_token = ${secondFence}::uuid
  `;
  const [thirdClaim] = await claimEmail("notification-worker-c");
  assert(thirdClaim, "expired lease was not reclaimable");
  const thirdFence = String(thirdClaim.fenceToken);
  assert.notEqual(thirdFence, secondFence);

  const [oldHeartbeat] = await asNotifier(
    async (transaction) =>
      transaction<{ retained: boolean }[]>`
      SELECT app.heartbeat_notification_delivery_v1(
        ${fixture.delivery}::uuid, ${secondFence}::uuid,
        transaction_timestamp() + interval '30 seconds'
      ) AS retained
    `,
  );
  assert.equal(oldHeartbeat?.retained, false, "old worker was not fenced");

  const receipt = {
    provider: "smtp",
    receiptDigest: "e".repeat(64),
    acceptedCount: 1,
    rejectedCount: 0,
    responseClass: 2,
  } as const;

  await assert.rejects(
    asNotifier(async (transaction) => {
      await transaction`
        SELECT app.complete_notification_delivery_v3(
          ${fixture.delivery}::uuid, ${secondFence}::uuid, 'email',
          ${admin.json(receipt)}::jsonb, transaction_timestamp()
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const [auditBeforeCompletion] = await admin<{ count: string }[]>`
    SELECT count(*)::text AS count
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'notification.email.delivered'
      AND resource_id = ${fixture.delivery}::uuid
  `;
  assert.equal(auditBeforeCompletion?.count, "0");

  await asNotifier(async (transaction) => {
    await transaction`
      SELECT app.reserve_notification_delivery_submission_v2(
        ${fixture.delivery}::uuid, ${thirdFence}::uuid, 'email',
        ${stableMessageID}, transaction_timestamp()
      )
    `;
  });
  await Promise.all([
    asNotifier(async (transaction) => {
      await transaction`
        SELECT app.complete_notification_delivery_v3(
          ${fixture.delivery}::uuid, ${thirdFence}::uuid, 'email',
          ${admin.json(receipt)}::jsonb, transaction_timestamp()
        )
      `;
    }),
    asNotifier(async (transaction) => {
      await transaction`
        SELECT app.complete_notification_delivery_v3(
          ${fixture.delivery}::uuid, ${thirdFence}::uuid, 'email',
          ${admin.json(receipt)}::jsonb, transaction_timestamp()
        )
      `;
    }),
  ]);
  await asNotifier(async (transaction) => {
    await transaction`
      SELECT app.complete_notification_delivery_v2(
        ${fixture.delivery}::uuid, ${thirdFence}::uuid, 'email',
        ${admin.json(receipt)}::jsonb, transaction_timestamp()
      )
    `;
    await transaction`
      SELECT app.complete_notification_delivery_replay_v2(
        ${fixture.delivery}::uuid, ${thirdFence}::uuid, 'email',
        transaction_timestamp()
      )
    `;
  });

  const deliveryAudits = await admin<
    {
      actorType: string;
      actorUserId: string | null;
      actorServiceAccountId: string | null;
      impersonatedByUserId: string | null;
      action: string;
      resourceType: string;
      resourceId: string;
      requestId: string | null;
      correlationId: string | null;
      ipAddress: string | null;
      userAgent: string | null;
      authenticationMethod: string | null;
      outcome: string;
      metadata: Record<string, unknown>;
      reason: string | null;
      before: unknown;
      after: unknown;
    }[]
  >`
    SELECT actor_type AS "actorType", actor_user_id AS "actorUserId",
           actor_service_account_id AS "actorServiceAccountId",
           impersonated_by_user_id AS "impersonatedByUserId", action,
           resource_type AS "resourceType", resource_id AS "resourceId",
           request_id AS "requestId", correlation_id AS "correlationId",
           ip_address AS "ipAddress", user_agent AS "userAgent",
           authentication_method AS "authenticationMethod", outcome,
           metadata, reason, before, after
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'notification.email.delivered'
      AND resource_id = ${fixture.delivery}::uuid
    ORDER BY sequence
  `;
  assert.deepEqual(Array.from(deliveryAudits), [
    {
      actorType: "system",
      actorUserId: null,
      actorServiceAccountId: null,
      impersonatedByUserId: null,
      action: "notification.email.delivered",
      resourceType: "notification_delivery",
      resourceId: fixture.delivery,
      requestId: fixture.delivery,
      correlationId: null,
      ipAddress: null,
      userAgent: null,
      authenticationMethod: "notifier",
      outcome: "success",
      metadata: { receiptDigest: receipt.receiptDigest },
      reason: null,
      before: null,
      after: null,
    },
  ]);
  assert.doesNotMatch(
    JSON.stringify(deliveryAudits),
    /recipient|subject|body|secret|password|banner/iu,
  );

  const attempts = await admin<{ attempt: number; outcome: string | null }[]>`
    SELECT attempt, outcome
    FROM public.tenant_notification_delivery_attempts
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND delivery_id = ${fixture.delivery}::uuid
    ORDER BY attempt
  `;
  assert.deepEqual(Array.from(attempts), [
    { attempt: 1, outcome: "retried" },
    { attempt: 2, outcome: "fenced" },
    { attempt: 3, outcome: "delivered" },
  ]);
  assert.equal(
    await verifyKeyring([2]),
    true,
    "terminal historical and wholly unreachable key versions must retire",
  );

  await assert.rejects(
    admin`
      INSERT INTO public.tenant_notification_deliveries (
        id, tenant_id, event_id, delivery_key, template_snapshot,
        smtp_configuration_scope, smtp_configuration_id,
        smtp_configuration_version, channel, audience, recipient,
        destination_redacted, context, priority, deduplication_key,
        grouping_window_ms, grouping_maximum_items, retry,
        maximum_attempts, next_attempt_at
      ) VALUES (
        ${fixture.crossTenantDelivery}::uuid, ${fixture.tenant}::uuid,
        ${fixture.foreignEvent}::uuid, ${"f".repeat(64)},
        ${admin.json(templateSnapshot)}::jsonb, 'tenant',
        ${fixture.smtpConfiguration}::uuid, 1, 'email', 'operator',
        'recipient@example.invalid', 'r***@example.invalid', '{}'::jsonb,
        100, 'notification-security-cross-tenant', 0, 1,
        ${admin.json(retryPolicy)}::jsonb, 3, transaction_timestamp()
      )
    `,
    (error: unknown) => assertSqlState(error, "23514"),
  );

  const unsafeTraceState = async (
    eventID: string,
    tracestate: string,
  ): Promise<void> => {
    await admin`
      INSERT INTO public.outbox_events (
        id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, schema_version, payload, deduplication_key,
        actor_kind, producer, maximum_audience, traceparent, tracestate
      ) VALUES (
        ${eventID}::uuid, ${fixture.tenant}::uuid, 'contact',
        ${fixture.smtpConfiguration}::uuid, 1, 'notification.webhook.custom',
        2, ${admin.json({ operatorContext: {} })}::jsonb,
        ${`notification-security-trace-${eventID}`}, 'system',
        'notification.security_test', 'operator', ${traceParent}, ${tracestate}
      )
    `;
  };
  await assert.rejects(
    unsafeTraceState(fixture.unicodeTraceEvent, "vendor=unicode-💥"),
    (error: unknown) => assertSqlState(error, "23514"),
  );
  await assert.rejects(
    unsafeTraceState(
      fixture.oversizedTraceEvent,
      `${"a".repeat(250)}@tenant=value`,
    ),
    (error: unknown) => assertSqlState(error, "23514"),
  );

  const pendingAt = new Date(Date.now() - 120_000);
  await admin`
    INSERT INTO public.outbox_events (
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      actor_kind, producer, maximum_audience, traceparent, tracestate,
      occurred_at, available_at, created_at
    ) VALUES (
      ${fixture.pendingEvent}::uuid, ${fixture.tenant}::uuid, 'contact',
      ${fixture.smtpConfiguration}::uuid, 1, 'notification.webhook.custom',
      2, ${admin.json({ operatorContext: {} })}::jsonb,
      'notification-security-pending-event', 'system',
      'notification.security_test', 'operator', ${traceParent}, ${traceState},
      ${pendingAt}, ${pendingAt}, ${pendingAt}
    )
  `;
  const pendingReadiness = await dispatchReadiness();
  assert.equal(pendingReadiness.roleSafe, true);
  assert.equal(pendingReadiness.schemaSafe, true);
  assert(
    pendingReadiness.oldestPendingSeconds >= 119,
    "oldest pending age must use PostgreSQL server time",
  );

  const [fanoutClaim] = await asNotifier(
    async (transaction) =>
      transaction<{ claim: Record<string, unknown> }[]>`
      SELECT claim
      FROM app.claim_notification_fanout_batch_v1(
        'notification-fanout-worker', 1, 5000, transaction_timestamp()
      )
    `,
  );
  assert.equal(fanoutClaim?.claim.id, fixture.pendingEvent);
  const claimedEvent = fanoutClaim.claim.event;
  assert(
    claimedEvent !== null &&
      typeof claimedEvent === "object" &&
      !Array.isArray(claimedEvent),
  );
  assert.deepEqual(Reflect.get(claimedEvent, "traceContext"), {
    traceParent,
    traceState,
  });
  assert.equal((await dispatchReadiness()).oldestPendingSeconds, 0);

  await asNotifier(async (transaction) => {
    await transaction`
      SELECT app.dead_letter_notification_fanout_v1(
        ${fixture.pendingEvent}::uuid,
        ${String(fanoutClaim.claim.fenceToken)}::uuid,
        'validation', transaction_timestamp()
      )
    `;
  });
  assert.equal((await dispatchReadiness()).oldestPendingSeconds, 0);
} finally {
  await Promise.all([admin.end(), notifier.end(), api.end()]);
}
