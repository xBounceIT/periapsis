import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_TICKET_METADATA_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_METADATA_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4a17-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  readerUser: uuid(102),
  foreignUser: uuid(103),
  adminMembership: uuid(201),
  readerMembership: uuid(202),
  foreignMembership: uuid(203),
  alert: uuid(301),
  case: uuid(302),
  foreignAlert: uuid(303),
} as const;

const primary = postgres(databaseUrl, { max: 4, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-metadata-runtime:${label}`)
    .digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function expectSqlState(
  operation: Promise<unknown>,
  expected: string,
  message: string,
): Promise<void> {
  await assert.rejects(
    operation,
    (error) => assertSqlState(error, expected),
    message,
  );
}

async function asRole<T>(
  client: typeof primary,
  role: "periapsis_api" | "periapsis_worker" | "periapsis_notifier",
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantID}, true),
             set_config('app.user_id', ${userID}, true),
             set_config('app.service_account_id', '', true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate', 'ticket_metadata=runtime', true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function asApi<T>(
  client: typeof primary,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  return asRole(client, "periapsis_api", tenantID, userID, operation);
}

type MutationInput = {
  kind: "alert" | "case";
  ticketID: string;
  expectedVersion: number;
  title: string;
  description: string;
  summary: string | null;
  severity: string;
  priority: string;
  category: string;
  classification: string | null;
  customerVisible: boolean;
  tags: string[];
  key: Buffer;
  request: Buffer;
  requestID: string;
  correlationID: string;
};

type MutationRow = {
  result_version: string;
  result_updated_at: Date;
  result_metadata: Record<string, unknown>;
  replayed: boolean;
};

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolvePromise: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve;
  });
  assert(resolvePromise, "deferred resolver was not initialized");
  return { promise, resolve: resolvePromise };
}

async function replaceMetadata(
  transaction: TransactionSql,
  input: MutationInput,
): Promise<MutationRow> {
  const [row] = await transaction<MutationRow[]>`
    SELECT result_version::text, result_updated_at, result_metadata, replayed
    FROM app.replace_tenant_ticket_metadata_v1(
      ${input.kind}::public.ticket_aggregate_kind,
      ${input.ticketID}::uuid,
      ${input.expectedVersion}::bigint,
      ${input.title}, ${input.description}, ${input.summary},
      ${input.severity}, ${input.priority}, ${input.category},
      ${input.classification}, ${input.customerVisible}, ${input.tags}::text[],
      ${input.key}, ${input.request},
      ${input.requestID}::uuid, ${input.correlationID}::uuid,
      '127.0.0.1'::inet, 'ticket-metadata-security', 'totp'
    )
  `;
  assert(row, "ticket metadata mutation returned no row");
  return row;
}

async function waitForMetadataLockWaiters(expected: number): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    // eslint-disable-next-line no-await-in-loop -- Polling must observe a later catalog snapshot.
    const [row] = await primary<{ waiters: number }[]>`
      SELECT count(*)::integer AS waiters
      FROM pg_catalog.pg_stat_activity AS activity
      WHERE activity.datname=current_database()
        AND activity.pid<>pg_backend_pid()
        AND activity.wait_event_type='Lock'
        AND activity.query LIKE '%replace_tenant_ticket_metadata_v1%'
    `;
    if ((row?.waiters ?? 0) >= expected) {
      return;
    }
    // eslint-disable-next-line no-await-in-loop -- This is a bounded lock-wait poll.
    await delay(10);
  }
  throw new Error(`timed out waiting for ${expected} metadata lock waiters`);
}

async function setup(): Promise<void> {
  await primary.begin(async (transaction) => {
    const suffix = sequence.toString(36);
    const ticketNumber = (Number(sequence % 800_000n) + 100_000)
      .toString()
      .padStart(6, "0");
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, ${`ticket-metadata-${suffix}`},
         'Ticket metadata runtime'),
        (${fixture.foreignTenant}::uuid,
         ${`ticket-metadata-foreign-${suffix}`}, 'Ticket metadata foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active) VALUES
        (${fixture.adminUser}::uuid,
         ${`metadata-admin-${suffix}@example.invalid`}, 'Admin', true),
        (${fixture.readerUser}::uuid,
         ${`metadata-reader-${suffix}@example.invalid`}, 'Reader', true),
        (${fixture.foreignUser}::uuid,
         ${`metadata-foreign-${suffix}@example.invalid`}, 'Foreign', true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.readerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.readerUser}::uuid, 'read_only', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
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
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.adminUser}, true)
    `;
    await transaction`
      INSERT INTO public.alerts (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, description, severity, priority, category, tags,
        created_by, created_by_membership_id, version, updated_at
      )
      SELECT ${fixture.alert}::uuid, ${fixture.tenant}::uuid,
             ${`ALT-2099-${ticketNumber}`}, workflow.id,
             workflow.current_version, 'new', 'Mutable Alert', 'Initial alert',
             'medium', 'medium', 'general', ARRAY[]::text[],
             ${fixture.adminUser}::uuid, ${fixture.adminMembership}::uuid,
             1, transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_alert'
    `;
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.foreignTenant}, true),
             set_config('app.user_id', ${fixture.foreignUser}, true)
    `;
    await transaction`
      INSERT INTO public.alerts (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, description, severity, priority, category, tags,
        created_by, created_by_membership_id, version, updated_at
      )
      SELECT ${fixture.foreignAlert}::uuid, ${fixture.foreignTenant}::uuid,
             ${`ALT-2098-${ticketNumber}`}, workflow.id,
             workflow.current_version, 'new', 'Foreign Alert', 'Initial alert',
             'medium', 'medium', 'general', ARRAY[]::text[],
             ${fixture.foreignUser}::uuid, ${fixture.foreignMembership}::uuid,
             1, transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_alert'
    `;
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.adminUser}, true)
    `;
    await transaction`
      INSERT INTO public.cases (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, description, summary, severity, priority, category, tags,
        created_by_membership_id, created_by_user_id, version, updated_at
      )
      SELECT ${fixture.case}::uuid, ${fixture.tenant}::uuid,
             ${`CAS-2099-${ticketNumber}`}, workflow.id,
             workflow.current_version, 'new', 'Mutable Case', 'Initial case',
             'Initial summary', 'medium', 'medium', 'general', ARRAY[]::text[],
             ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid,
             1, transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_case'
    `;
  });
}

const alertMutation = (
  overrides: Partial<MutationInput> = {},
): MutationInput => ({
  kind: "alert",
  ticketID: fixture.alert,
  expectedVersion: 1,
  title: "Private Alert Title",
  description: "Private alert description",
  summary: null,
  severity: "high",
  priority: "urgent",
  category: "malware",
  classification: "restricted",
  customerVisible: false,
  tags: ["blue", "triage"],
  key: digest("alert-key"),
  request: digest("alert-request"),
  requestID: uuid(401),
  correlationID: uuid(402),
  ...overrides,
});

const caseMutation = (
  overrides: Partial<MutationInput> = {},
): MutationInput => ({
  kind: "case",
  ticketID: fixture.case,
  expectedVersion: 1,
  title: "Private Case Title",
  description: "Private case description",
  summary: "Private case summary",
  severity: "critical",
  priority: "critical",
  category: "incident",
  classification: null,
  customerVisible: false,
  tags: ["case", "response"],
  key: digest("case-key"),
  request: digest("case-request"),
  requestID: uuid(411),
  correlationID: uuid(412),
  ...overrides,
});

async function main(): Promise<void> {
  await setup();

  const [readiness] = await primary<[{ ready: boolean }]>`
    SELECT app.ticket_metadata_runtime_schema_readiness_v58() AS ready
  `;
  assert.equal(readiness?.ready, true);

  await expectSqlState(
    asRole(
      primary,
      "periapsis_worker",
      fixture.tenant,
      fixture.adminUser,
      (transaction) => replaceMetadata(transaction, alertMutation()),
    ),
    "42501",
    "the worker role must not execute the human metadata writer",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_notifier",
      fixture.tenant,
      fixture.adminUser,
      (transaction) => replaceMetadata(transaction, alertMutation()),
    ),
    "42501",
    "the notifier role must not execute the human metadata writer",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.readerUser, (transaction) =>
      replaceMetadata(transaction, alertMutation()),
    ),
    "42501",
    "a read-only membership must be denied",
  );
  await expectSqlState(
    asApi(primary, fixture.foreignTenant, fixture.foreignUser, (transaction) =>
      replaceMetadata(transaction, alertMutation()),
    ),
    "42501",
    "a foreign tenant must not discover or mutate the Alert",
  );
  for (const invalid of [
    caseMutation({ summary: "line one\u0007line two" }),
    caseMutation({ description: "line one\u0001line two" }),
    alertMutation({ classification: "" }),
    alertMutation({ tags: ["invalid tag"] }),
    alertMutation({ title: " leading" }),
    alertMutation({ category: "trailing " }),
    alertMutation({ description: " leading" }),
    alertMutation({ title: "\u00a0leading" }),
    alertMutation({ category: "trailing\u3000" }),
    caseMutation({ summary: "\u202fleading" }),
    caseMutation({ description: "trailing\u205f" }),
  ]) {
    // eslint-disable-next-line no-await-in-loop -- Invalid writes share one fixture and are intentionally serialized.
    await expectSqlState(
      asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
        replaceMetadata(transaction, invalid),
      ),
      "22023",
      "the protected ABI must reject a non-canonical metadata document",
    );
  }
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (transaction) => {
      await transaction`SELECT * FROM public.ticket_commands`;
    }),
    "42501",
    "the API role must not read immutable command receipts directly",
  );

  const first = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) => replaceMetadata(transaction, alertMutation()),
  );
  assert.equal(first.result_version, "2");
  assert.equal(first.replayed, false);
  assert.deepEqual(
    Object.keys(first.result_metadata).toSorted(),
    [
      "aggregate_kind",
      "category",
      "classification",
      "customer_visible",
      "description",
      "schema_version",
      "severity",
      "summary",
      "tags",
      "tenant_id",
      "ticket_id",
      "title",
      "updated_at",
      "version",
      "priority",
    ].toSorted(),
  );
  assert.equal(first.result_metadata.summary, "");
  assert.equal(first.result_metadata.version, 2);
  assert.equal(first.result_metadata.ticket_id, fixture.alert);

  const replay = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      replaceMetadata(
        transaction,
        alertMutation({ requestID: uuid(403), correlationID: uuid(404) }),
      ),
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.result_version, first.result_version);
  assert.equal(
    replay.result_updated_at.toISOString(),
    first.result_updated_at.toISOString(),
  );
  assert.deepEqual(replay.result_metadata, first.result_metadata);

  const [alertEffects] = await primary<
    [{ commands: string; activities: string; audits: string; outbox: string }]
  >`
    SELECT
      (SELECT count(*)::text FROM public.ticket_commands
       WHERE tenant_id=${fixture.tenant}::uuid
         AND operation='alert.metadata.replace'
         AND result_alert_id=${fixture.alert}::uuid) AS commands,
      (SELECT count(*)::text FROM public.ticket_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND alert_id=${fixture.alert}::uuid
         AND kind='alert.metadata_updated') AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_id=${fixture.alert}::uuid
         AND action='tenant.alert.metadata_updated') AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND aggregate_id=${fixture.alert}::uuid
         AND event_type='alert.metadata_updated') AS outbox
  `;
  assert.deepEqual(alertEffects, {
    commands: "1",
    activities: "1",
    audits: "1",
    outbox: "1",
  });
  const [redaction] = await primary<
    [{ activity: string; audit: string; outbox: string }]
  >`
    SELECT
      (SELECT row_to_json(activity)::text FROM public.ticket_activities activity
       WHERE tenant_id=${fixture.tenant}::uuid
         AND alert_id=${fixture.alert}::uuid
         AND kind='alert.metadata_updated') AS activity,
      (SELECT row_to_json(audit)::text FROM public.audit_events audit
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_id=${fixture.alert}::uuid
         AND action='tenant.alert.metadata_updated') AS audit,
      (SELECT row_to_json(event)::text FROM public.outbox_events event
       WHERE tenant_id=${fixture.tenant}::uuid
         AND aggregate_id=${fixture.alert}::uuid
         AND event_type='alert.metadata_updated') AS outbox
  `;
  for (const value of [redaction.activity, redaction.audit, redaction.outbox]) {
    assert(!value.includes("Private Alert Title"));
    assert(!value.includes("Private alert description"));
  }
  assert(redaction.audit.includes('"content_redacted": true'));
  assert(redaction.audit.includes('"changed_fields"'));

  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(
        transaction,
        alertMutation({ request: digest("divergent-request") }),
      ),
    ),
    "23505",
    "an idempotency key cannot be reused for a divergent request",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(
        transaction,
        alertMutation({
          expectedVersion: 2,
          key: digest("alert-noop-key"),
          request: digest("alert-noop-request"),
        }),
      ),
    ),
    "23514",
    "an exact metadata no-op must be rejected",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(
        transaction,
        alertMutation({
          expectedVersion: 1,
          title: "A stale update",
          key: digest("alert-stale-key"),
          request: digest("alert-stale-request"),
        }),
      ),
    ),
    "40001",
    "stale metadata CAS must be deterministic",
  );

  const caseFirst = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      replaceMetadata(
        transaction,
        caseMutation({
          description: "Private case\tdescription\r\nsecond line",
          summary: "Private case summary\nsecond line",
        }),
      ),
  );
  assert.equal(caseFirst.replayed, false);
  assert.equal(
    caseFirst.result_metadata.summary,
    "Private case summary\nsecond line",
  );

  const identicalRaceInput = caseMutation({
    expectedVersion: 2,
    title: "Concurrent idempotent result",
    key: digest("identical-race-key"),
    request: digest("identical-race-request"),
    requestID: uuid(411),
    correlationID: uuid(412),
  });
  const releaseTicketLockSignal = deferred();
  const ticketLockedSignal = deferred();
  const ticketLock = primary.begin(async (transaction) => {
    await transaction`
      SELECT id FROM public.cases
      WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.case}::uuid
      FOR UPDATE
    `;
    ticketLockedSignal.resolve();
    await releaseTicketLockSignal.promise;
  });
  await ticketLockedSignal.promise;
  const identicalRaceRequests = [
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(transaction, identicalRaceInput),
    ),
    asApi(contender, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(transaction, identicalRaceInput),
    ),
  ] as const;
  try {
    await waitForMetadataLockWaiters(2);
  } finally {
    releaseTicketLockSignal.resolve();
  }
  await ticketLock;
  const identicalRace = await Promise.all(identicalRaceRequests);
  assert.deepEqual(
    identicalRace
      .map((result) => result.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );
  assert.equal(identicalRace[0].result_version, "3");
  assert.equal(identicalRace[1].result_version, "3");
  assert.deepEqual(
    identicalRace[0].result_metadata,
    identicalRace[1].result_metadata,
  );
  assert.equal(
    identicalRace[0].result_updated_at.toISOString(),
    identicalRace[1].result_updated_at.toISOString(),
  );

  const raceInputs = [
    caseMutation({
      expectedVersion: 3,
      title: "Race winner A",
      key: digest("race-a-key"),
      request: digest("race-a-request"),
      requestID: uuid(421),
      correlationID: uuid(422),
    }),
    caseMutation({
      expectedVersion: 3,
      title: "Race winner B",
      key: digest("race-b-key"),
      request: digest("race-b-request"),
      requestID: uuid(423),
      correlationID: uuid(424),
    }),
  ];
  const race = await Promise.allSettled([
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(transaction, raceInputs[0]!),
    ),
    asApi(contender, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(transaction, raceInputs[1]!),
    ),
  ]);
  assert.equal(
    race.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejected = race.find((result) => result.status === "rejected");
  assert(rejected?.status === "rejected");
  assertSqlState(rejected.reason, "40001");
  const [currentCase] = await primary<[{ version: number; title: string }]>`
    SELECT version,title FROM public.cases
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.case}::uuid
  `;
  assert.equal(currentCase?.version, 4);
  assert(["Race winner A", "Race winner B"].includes(currentCase?.title ?? ""));

  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [deleted] = await transaction<[{ tombstone_version: string }]>`
        SELECT tombstone_version::text
        FROM app.delete_tenant_alert_v1(
          ${fixture.alert}::uuid, 2, 'test tombstone',
          ${digest("delete-key")}, ${digest("delete-request")},
          ${uuid(431)}::uuid, ${uuid(432)}::uuid, '127.0.0.1'::inet,
          'ticket-metadata-security', 'totp'
        )
      `;
      assert.equal(deleted?.tombstone_version, "3");
    },
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      replaceMetadata(transaction, alertMutation()),
    ),
    "42501",
    "a tombstoned Alert must not replay or mutate metadata",
  );
}

try {
  await main();
} finally {
  await Promise.all([
    primary.end({ timeout: 5 }),
    contender.end({ timeout: 5 }),
  ]);
}
