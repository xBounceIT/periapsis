import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_SLA_RUNTIME_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SLA_RUNTIME_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a05700-5000-7000-8000-000000000001",
  foreignTenant: "01a05700-5000-7000-8000-000000000002",
  user: "01a05700-5000-7000-8000-000000000101",
  foreignUser: "01a05700-5000-7000-8000-000000000102",
  membership: "01a05700-5000-7000-8000-000000000201",
  foreignMembership: "01a05700-5000-7000-8000-000000000202",
  calendar: "01a05700-5000-7000-8000-000000000301",
  policy: "01a05700-5000-7000-8000-000000000302",
  metricDefinition: "01a05700-5000-7000-8000-000000000303",
  triggerDefinition: "01a05700-5000-7000-8000-000000000304",
  column: "01a05700-5000-7000-8000-000000000305",
  slaInstance: "01a05700-5000-7000-8000-000000000401",
  metricInstance: "01a05700-5000-7000-8000-000000000402",
  runtimeAlert: "01a05700-5000-7000-8000-000000000403",
  assignmentEvent: "01a05700-5000-7000-8000-000000000404",
  job: "01a05700-5000-7000-8000-000000000405",
  worker: "01a05700-5000-7000-8000-000000000406",
  retryJob: "01a05700-5000-7000-8000-000000000407",
  occurrence: "01a05700-5000-7000-8000-000000000408",
  eventAlert: "01a05700-5000-7000-8000-000000000409",
  objectEvent: "01a05700-5000-7000-8000-000000000410",
  objectEventOrigin: "01a05700-5000-7000-8000-000000000411",
  override: "01a05700-5000-7000-8000-000000000412",
  metricsLeaseInstance: "01a05700-5000-7000-8000-000000000413",
  metricsLeaseJob: "01a05700-5000-7000-8000-000000000414",
  metricsLeaseAlert: "01a05700-5000-7000-8000-000000000415",
  metricsLeaseAssignment: "01a05700-5000-7000-8000-000000000416",
  ingressBarrierJob: "01a05700-5000-7000-8000-000000000417",
  ingressBarrierEvent: "01a05700-5000-7000-8000-000000000418",
  request: "01a05700-5000-7000-8000-000000000501",
  correlation: "01a05700-5000-7000-8000-000000000502",
  policyRequest: "01a05700-5000-7000-8000-000000000503",
  policyCorrelation: "01a05700-5000-7000-8000-000000000504",
} as const;

type Publication = {
  resource_id: string;
  resource_version: number;
  active_version: number;
  replayed: boolean;
  document: Record<string, unknown>;
};

type Claim = {
  job_id: string;
  tenant_id: string;
  sla_instance_id: string;
  expected_aggregate_version: number;
  fence: string;
  attempt: number;
  observed_at: Date;
  lease_expires_at: Date;
  state_document: Record<string, unknown>;
};

type IngressClaim = {
  job_id: string;
  tenant_id: string;
  source_digest: Buffer;
  fence: string;
};

type QueueMetrics = {
  observed_at: Date;
  pending_jobs: string;
  oldest_pending_micros: string;
};

type ExplainRow = { "QUERY PLAN": string };

function digest(label: string): Buffer {
  return createHash("sha256").update(`sla-security:${label}`).digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
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

function serially<T>(
  values: readonly T[],
  operation: (value: T) => Promise<void>,
): Promise<void> {
  return values.reduce(
    (pending, value) => pending.then(() => operation(value)),
    Promise.resolve(),
  );
}

async function asApi<T>(
  transaction: TransactionSql,
  tenantId: string,
  userId: string,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe('SET LOCAL ROLE "periapsis_api"');
    await sql`
      SELECT set_config('app.tenant_id', ${tenantId}, true),
             set_config('app.user_id', ${userId}, true),
             set_config('app.service_account_id', '', true),
             set_config('app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true),
             set_config('app.tracestate', 'fixture=value', true)
    `;
    const value = await operation(sql);
    await sql.unsafe("RESET ROLE");
    return { value };
  });
  return result.value;
}

async function asWorker<T>(
  transaction: TransactionSql,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe('SET LOCAL ROLE "periapsis_worker"');
    const value = await operation(sql);
    await sql.unsafe("RESET ROLE");
    return { value };
  });
  return result.value;
}

async function asRole<T>(
  transaction: TransactionSql,
  role: "periapsis_notifier" | "periapsis_auditor",
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe(`SET LOCAL ROLE "${role}"`);
    const value = await operation(sql);
    await sql.unsafe("RESET ROLE");
    return { value };
  });
  return result.value;
}

async function assertQueueMetricsPlans(
  transaction: TransactionSql,
): Promise<void> {
  await transaction.unsafe("SET LOCAL enable_seqscan = off");
  const claimPlan = await transaction.unsafe<ExplainRow[]>(`
    EXPLAIN (COSTS OFF)
    WITH observed AS MATERIALIZED (
      SELECT clock_timestamp() AS observed_at
    )
    SELECT job.available_at
    FROM public.sla_evaluation_jobs AS job
    CROSS JOIN observed
    WHERE job.status IN ('queued', 'retry_scheduled')
      AND job.available_at <= observed.observed_at
  `);
  const reclaimPlan = await transaction.unsafe<ExplainRow[]>(`
    EXPLAIN (COSTS OFF)
    WITH observed AS MATERIALIZED (
      SELECT clock_timestamp() AS observed_at
    )
    SELECT job.lease_expires_at
    FROM public.sla_evaluation_jobs AS job
    CROSS JOIN observed
    WHERE job.status = 'leased'
      AND job.lease_expires_at <= observed.observed_at
  `);
  await transaction.unsafe("RESET enable_seqscan");
  assert(
    claimPlan.some((row) =>
      row["QUERY PLAN"].includes("sla_evaluation_jobs_claim_idx"),
    ),
    "ready queue scan did not use the claim partial index",
  );
  assert(
    reclaimPlan.some((row) =>
      row["QUERY PLAN"].includes("sla_evaluation_jobs_reclaim_idx"),
    ),
    "expired lease scan did not use the reclaim partial index",
  );
}

const calendarDocument = {
  key: "support-hours",
  label: "Support hours",
  timezone: "UTC",
  weekly_schedule: [
    {
      weekday: 1,
      intervals: [{ start_minute: 0, end_minute: 1_440 }],
    },
  ],
  exceptions: [],
  revision_digest: digest("calendar-revision").toString("hex"),
} as const;

const policyDocument = {
  key: "task-response",
  name: "Task response",
  description: "Security fixture policy",
  priority: 0,
  object_types: ["alert"],
  match_rule: {},
  effective_from: "2026-01-01T00:00:00.000000Z",
  effective_until: null,
  enabled: true,
  apply_to_sla_engine_source: false,
  revision_digest: digest("policy-revision").toString("hex"),
  metrics: [
    {
      id: fixture.metricDefinition,
      key: "response-time",
      label: "Response time",
      description: "",
      duration_micros: 60_000_000,
      clock: "elapsed",
      calendar_id: null,
      calendar_version: null,
      start_event: "task.created",
      pause_event: null,
      resume_event: null,
      completion_event: "task.completed",
      reset_event: null,
      reset_policy: "ignore",
      warning_kind: "none",
      warning_consumed_percent: null,
      warning_remaining_micros: null,
      breach_grace_micros: 0,
      display_format: "duration",
      customer_visible: false,
      api_visible: true,
      position: 0,
      definition_digest: digest("metric-definition").toString("hex"),
    },
  ],
  triggers: [
    {
      id: fixture.triggerDefinition,
      metric_definition_id: fixture.metricDefinition,
      key: "due-tag",
      kind: "due",
      consumed_percent: null,
      remaining_micros: null,
      offset_micros: null,
      repeat_interval_micros: null,
      target_state: null,
      action_kind: "add_tag",
      action_configuration_id: null,
      action_value: "sla-breached",
      allow_recursive_sla: false,
      position: 0,
      definition_digest: digest("trigger-definition").toString("hex"),
    },
  ],
} as const;

async function publishCalendar(
  sql: TransactionSql,
  keyDigest: Buffer,
  requestDigest: Buffer,
): Promise<Publication> {
  const [publication] = await sql<Publication[]>`
    SELECT * FROM app.publish_sla_calendar_v2(
      ${fixture.tenant}::uuid, ${fixture.calendar}::uuid, 0,
      ${sql.json(calendarDocument)}::jsonb, ${keyDigest}::bytea,
      ${requestDigest}::bytea, ${fixture.request}::uuid,
      ${fixture.correlation}::uuid, '127.0.0.1'::inet,
      'sla-security-test', 'totp'
    )
  `;
  assert(publication, "calendar publication returned no row");
  return publication;
}

async function publishPolicy(sql: TransactionSql): Promise<Publication> {
  const [publication] = await sql<Publication[]>`
    SELECT * FROM app.publish_sla_policy_v2(
      ${fixture.tenant}::uuid, ${fixture.policy}::uuid, 0,
      ${sql.json(policyDocument)}::jsonb, ${digest("policy-key")}::bytea,
      ${digest("policy-request")}::bytea, ${fixture.policyRequest}::uuid,
      ${fixture.policyCorrelation}::uuid, '127.0.0.1'::inet,
      'sla-security-test', 'totp'
    )
  `;
  assert(publication, "policy publication returned no row");
  return publication;
}

const database = postgres(databaseUrl, {
  max: 1,
  onnotice: () => undefined,
});
const rollbackMarker = new Error("intentional SLA security fixture rollback");

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      await transaction`DELETE FROM public.sla_evaluation_jobs`;
      await assertQueueMetricsPlans(transaction);
      const [readiness] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v51() AS ready
      `;
      assert.equal(readiness?.ready, true, "SLA readiness is not current");
      const [emptyMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(emptyMetrics, "empty SLA queue metrics returned no row");
      assert.equal(emptyMetrics.pending_jobs, "0");
      assert.equal(emptyMetrics.oldest_pending_micros, "0");
      assert(emptyMetrics.observed_at instanceof Date);
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, async (sql) => {
          await sql`SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()`;
        }),
        "42501",
        "the API runtime read the global SLA queue aggregate",
      );
      await expectSqlState(
        asRole(transaction, "periapsis_notifier", async (sql) => {
          await sql`SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()`;
        }),
        "42501",
        "the notifier runtime read the global SLA queue aggregate",
      );
      await expectSqlState(
        asRole(transaction, "periapsis_auditor", async (sql) => {
          await sql`SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()`;
        }),
        "42501",
        "the auditor runtime read the global SLA queue aggregate",
      );
      await transaction`
        INSERT INTO public.tenants (id, slug, name) VALUES
          (${fixture.tenant}::uuid, 'sla-security-proof', 'SLA security proof'),
          (${fixture.foreignTenant}::uuid, 'sla-security-foreign',
           'SLA security foreign')
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id) VALUES
          (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active) VALUES
          (${fixture.user}::uuid, 'sla-proof@example.invalid',
           'SLA proof', true),
          (${fixture.foreignUser}::uuid, 'sla-foreign@example.invalid',
           'SLA foreign', true)
      `;
      await transaction`
        INSERT INTO public.tenant_memberships (
          id, tenant_id, user_id, role, status
        ) VALUES
          (${fixture.membership}::uuid, ${fixture.tenant}::uuid,
           ${fixture.user}::uuid, 'tenant_admin', 'active'),
          (${fixture.foreignMembership}::uuid,
           ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid,
           'tenant_admin', 'active')
      `;
      await transaction`
        INSERT INTO public.tenant_user_profiles (
          tenant_id, membership_id, user_id, display_name, email
        ) VALUES
          (${fixture.tenant}::uuid, ${fixture.membership}::uuid,
           ${fixture.user}::uuid, 'SLA proof',
           'sla-proof@example.invalid'),
          (${fixture.foreignTenant}::uuid,
           ${fixture.foreignMembership}::uuid,
           ${fixture.foreignUser}::uuid, 'SLA foreign',
           'sla-foreign@example.invalid')
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.tenant}::uuid, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.foreignTenant}::uuid,
          ${fixture.foreignMembership}::uuid
        )
      `;
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.user}, true),
               set_config('app.service_account_id', '', true),
               set_config('app.traceparent',
                 '00-11111111111111111111111111111111-2222222222222222-01',
                 true),
               set_config('app.tracestate', 'fixture=value', true)
      `;
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          customer_visible, title, created_by, created_by_membership_id
        )
        SELECT alert_row.id::uuid, ${fixture.tenant}::uuid,
               alert_row.number, workflow.id, workflow.current_version,
               'new', false, alert_row.title, ${fixture.user}::uuid,
               ${fixture.membership}::uuid
        FROM (VALUES
          (${fixture.eventAlert}, 'ALT-2026-500001',
           'No-policy event fixture'),
          (${fixture.runtimeAlert}, 'ALT-2026-500002',
           'Runtime SLA fixture')
        ) AS alert_row(id, number, title)
        JOIN public.ticket_workflows AS workflow
          ON workflow.tenant_id = ${fixture.tenant}::uuid
         AND workflow.key = 'default_alert'
      `;

      // Creating the alerts emits canonical ticket.created ingress. Settle that
      // work before installing the hand-built timer fixture; the current claim
      // ABI intentionally fences timers while object-event ingress is pending.
      const creationIngress = await asWorker(
        transaction,
        (sql) => sql<IngressClaim[]>`
          SELECT job_id,tenant_id,source_digest,fence
          FROM app.claim_sla_object_events_v1(
            ${fixture.worker}::uuid,
            date_trunc('microseconds',clock_timestamp()),10,60000000
          )
        `,
      );
      assert.equal(creationIngress.length, 2);
      await serially(creationIngress, async (ingress) => {
        const [completionClock] = await transaction<{ completedAt: Date }[]>`
          SELECT date_trunc(
                   'milliseconds',greatest(clock_timestamp(),updated_at)
                 ) + interval '1 millisecond' AS "completedAt"
          FROM public.sla_object_event_ingress
          WHERE tenant_id=${ingress.tenant_id}::uuid
            AND id=${ingress.job_id}::uuid
        `;
        assert(completionClock);
        await asWorker(transaction, async (sql) => {
          await sql`
            SELECT * FROM app.commit_sla_object_event_ingress_v1(
              ${fixture.worker}::uuid,${ingress.job_id}::uuid,
              ${ingress.tenant_id}::uuid,${ingress.fence}::bigint,
              ${ingress.source_digest}::bytea,'no_policy',NULL,0,0,NULL,0,
              ${completionClock.completedAt},
              ${sql.json({
                metrics: [],
                cursors: [],
                occurrences: [],
                columns: [],
                next_evaluation_at: null,
                aggregate_completed_at: null,
              })}::jsonb
            )
          `;
        });
      });

      const keyDigest = digest("calendar-key");
      const calendarRequestDigest = digest("calendar-request");
      const first = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => publishCalendar(sql, keyDigest, calendarRequestDigest),
      );
      assert.deepEqual(
        {
          resource_id: first.resource_id,
          resource_version: first.resource_version,
          active_version: first.active_version,
          replayed: first.replayed,
        },
        {
          resource_id: fixture.calendar,
          resource_version: 1,
          active_version: 1,
          replayed: false,
        },
        "fresh calendar publication receipt changed",
      );
      assert.equal(first.document.key, calendarDocument.key);
      assert.equal(first.document.active_version, 1);
      const replay = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => publishCalendar(sql, keyDigest, calendarRequestDigest),
      );
      assert.equal(replay.replayed, true, "exact replay was not detected");
      assert.deepEqual(
        {
          resource_id: replay.resource_id,
          resource_version: replay.resource_version,
          active_version: replay.active_version,
          replayed: false,
        },
        {
          resource_id: first.resource_id,
          resource_version: first.resource_version,
          active_version: first.active_version,
          replayed: first.replayed,
        },
        "exact replay did not return the original current receipt",
      );
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, (sql) =>
          publishCalendar(sql, keyDigest, digest("changed-calendar-request")),
        ),
        "23505",
        "changed payload reused an idempotency key",
      );
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, async (sql) => {
          await sql`
            SELECT * FROM app.publish_sla_calendar_v2(
              ${fixture.foreignTenant}::uuid, ${fixture.calendar}::uuid, 0,
              ${sql.json(calendarDocument)}::jsonb,
              ${digest("foreign-key")}::bytea,
              ${digest("foreign-request")}::bytea, ${fixture.request}::uuid,
              ${fixture.correlation}::uuid, '127.0.0.1'::inet,
              'sla-security-test', 'totp'
            )
          `;
        }),
        "22023",
        "cross-tenant publication escaped the tenant context",
      );
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, async (sql) => {
          await sql`SELECT count(*) FROM public.sla_business_calendars`;
        }),
        "42501",
        "runtime role received direct SLA table privileges",
      );

      const [effects] = await transaction<
        { commands: string; revisions: string; outbox: string }[]
      >`
        SELECT
          (SELECT count(*)::text FROM public.sla_configuration_commands
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND resource_id = ${fixture.calendar}::uuid) AS commands,
          (SELECT count(*)::text FROM public.sla_business_calendar_versions
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND calendar_id = ${fixture.calendar}::uuid) AS revisions,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND aggregate_id = ${fixture.calendar}::uuid
             AND event_type = 'sla.calendar.published') AS outbox
      `;
      assert.deepEqual(
        effects,
        { commands: "1", revisions: "1", outbox: "1" },
        "replay duplicated a command, revision, or outbox effect",
      );
      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            UPDATE public.sla_business_calendar_versions
            SET label = 'tampered'
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND calendar_id = ${fixture.calendar}::uuid
          `;
          return {};
        }),
        "55000",
        "immutable calendar revision accepted an update",
      );

      const eventOccurredAt = new Date(Date.now() - 8_000);
      const eventKeyDigest = digest("object-event-key");
      const eventRequestDigest = digest("object-event-request");
      const commitNoPolicy = async (
        sql: TransactionSql,
        candidateRequestDigest: Buffer,
      ) => {
        const [begin] = await sql<
          {
            fresh: boolean;
            event_id: string;
            outcome: string | null;
            sla_instance_id: string | null;
            aggregate_version: number | null;
            policy_id: string | null;
            policy_version: number | null;
            state_document: Record<string, unknown> | null;
          }[]
        >`
          SELECT * FROM app.begin_sla_object_event_v2(
            ${fixture.tenant}::uuid, ${fixture.objectEvent}::uuid, 'alert',
            ${fixture.eventAlert}::uuid, 'alert.activity',
            ${fixture.objectEventOrigin}::uuid, ${eventOccurredAt},
            ${eventKeyDigest}::bytea, ${candidateRequestDigest}::bytea,
            ${fixture.membership}::uuid
          )
        `;
        assert(begin, "object-event begin returned no result");
        if (!begin.fresh) {
          return {
            event_id: begin.event_id,
            outcome: begin.outcome,
            sla_instance_id: begin.sla_instance_id,
            aggregate_version: begin.aggregate_version,
            policy_id: begin.policy_id,
            policy_version: begin.policy_version,
            replayed: true,
          };
        }
        assert(
          begin.state_document,
          "fresh object-event omitted planner state",
        );
        const [receipt] = await sql<
          {
            event_id: string;
            outcome: string;
            sla_instance_id: string | null;
            aggregate_version: number;
            policy_id: string | null;
            policy_version: number;
            replayed: boolean;
          }[]
        >`
          SELECT * FROM app.commit_sla_object_event_v1(
            ${fixture.tenant}::uuid, ${fixture.objectEvent}::uuid, 'alert',
            ${fixture.eventAlert}::uuid, 'alert.activity',
            ${fixture.objectEventOrigin}::uuid, 'no_policy', NULL, 0, 0,
            NULL, 0, ${eventOccurredAt}, ${sql.json({})}::jsonb,
            ${eventKeyDigest}::bytea, ${candidateRequestDigest}::bytea,
            ${fixture.request}::uuid, ${fixture.correlation}::uuid,
            '127.0.0.1'::inet, 'sla-security-test', 'totp'
          )
        `;
        assert(receipt, "object-event commit returned no receipt");
        return receipt;
      };
      const eventReceipt = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => commitNoPolicy(sql, eventRequestDigest),
      );
      assert.deepEqual(eventReceipt, {
        event_id: fixture.objectEvent,
        outcome: "no_policy",
        sla_instance_id: null,
        aggregate_version: 0,
        policy_id: null,
        policy_version: 0,
        replayed: false,
      });
      const eventReplay = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => commitNoPolicy(sql, eventRequestDigest),
      );
      assert.equal(eventReplay.replayed, true);
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, (sql) =>
          commitNoPolicy(sql, digest("changed-object-event-request")),
        ),
        "23505",
        "object-event idempotency key accepted a changed request",
      );

      const policy = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        publishPolicy,
      );
      assert.equal(policy.replayed, false);
      assert.equal(policy.resource_version, 1);
      await transaction`
        INSERT INTO public.sla_columns (
          id, tenant_id, key, active_version, resource_version,
          created_by_membership_id, updated_by_membership_id
        ) VALUES (
          ${fixture.column}::uuid, ${fixture.tenant}::uuid, 'due-at', 1, 1,
          ${fixture.membership}::uuid, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.sla_column_versions (
          tenant_id, column_id, version, label, metric_definition_id,
          calculation, format, sortable, filterable, customer_visible,
          visible_role_keys, position, style_rules, revision_digest,
          created_by_membership_id
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.column}::uuid, 1, 'Due at',
          ${fixture.metricDefinition}::uuid, 'due_at', 'datetime', true,
          true, false, ARRAY['tenant_admin']::text[], 0, '[]'::jsonb,
          ${digest("column-revision")}::bytea,
          ${fixture.membership}::uuid
        )
      `;
      const observedAt = new Date(Date.now() - 10_000);
      await transaction`
        INSERT INTO public.sla_instances (
          id, tenant_id, object_type, object_id, policy_id, policy_version,
          aggregate_version, assignment_event_id, created_at, updated_at
        ) VALUES (
          ${fixture.slaInstance}::uuid, ${fixture.tenant}::uuid, 'alert',
          ${fixture.runtimeAlert}::uuid, ${fixture.policy}::uuid, 1, 1,
          ${fixture.assignmentEvent}::uuid, ${observedAt}, ${observedAt}
        )
      `;
      await transaction`
        INSERT INTO public.sla_metric_instances (
          id, tenant_id, sla_instance_id, definition_id, policy_id,
          policy_version, version, lifecycle, state, created_at, updated_at,
          extension_micros, consumed_micros
        ) VALUES (
          ${fixture.metricInstance}::uuid, ${fixture.tenant}::uuid,
          ${fixture.slaInstance}::uuid, ${fixture.metricDefinition}::uuid,
          ${fixture.policy}::uuid, 1, 1, 'pending', 'pending',
          ${observedAt}, ${observedAt}, 0, 0
        )
      `;
      await transaction`
        INSERT INTO public.sla_evaluation_jobs (
          id, tenant_id, sla_instance_id, expected_aggregate_version,
          status, available_at, attempt, maximum_attempts, fence,
          created_at, updated_at
        ) VALUES (
          ${fixture.job}::uuid, ${fixture.tenant}::uuid,
          ${fixture.slaInstance}::uuid, 1, 'queued', ${observedAt},
          0, 3, 0, ${observedAt}, ${observedAt}
        )
      `;

      const [readyMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(readyMetrics, "ready SLA queue metrics returned no row");
      assert.equal(readyMetrics.pending_jobs, "1");
      assert(
        BigInt(readyMetrics.oldest_pending_micros) >= 9_000_000n,
        "ready age did not use the database observation instant",
      );

      await transaction`
        INSERT INTO public.sla_instances (
          id, tenant_id, object_type, object_id, policy_id, policy_version,
          aggregate_version, assignment_event_id, created_at, updated_at
        ) VALUES (
          ${fixture.metricsLeaseInstance}::uuid, ${fixture.tenant}::uuid,
          'alert', ${fixture.metricsLeaseAlert}::uuid,
          ${fixture.policy}::uuid, 1, 1,
          ${fixture.metricsLeaseAssignment}::uuid,
          ${observedAt}, ${observedAt}
        )
      `;
      await transaction`
        INSERT INTO public.sla_evaluation_jobs (
          id, tenant_id, sla_instance_id, expected_aggregate_version,
          status, available_at, attempt, maximum_attempts, worker_id,
          lease_expires_at, fence, created_at, updated_at
        ) VALUES (
          ${fixture.metricsLeaseJob}::uuid, ${fixture.tenant}::uuid,
          ${fixture.metricsLeaseInstance}::uuid, 1, 'leased', ${observedAt},
          1, 3, ${fixture.worker}::uuid,
          ${new Date(observedAt.getTime() + 1_000)}, 1,
          ${observedAt}, ${observedAt}
        )
      `;
      const [combinedMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(combinedMetrics, "combined SLA queue metrics returned no row");
      assert.equal(
        combinedMetrics.pending_jobs,
        "2",
        "ready and expired-lease branches were not combined exactly once",
      );
      assert(
        BigInt(combinedMetrics.oldest_pending_micros) >= 9_000_000n,
        "combined queue metrics did not retain the oldest ready instant",
      );
      await transaction`
        DELETE FROM public.sla_evaluation_jobs
        WHERE id = ${fixture.metricsLeaseJob}::uuid
      `;
      await transaction`
        DELETE FROM public.sla_instances
        WHERE id = ${fixture.metricsLeaseInstance}::uuid
      `;

      await transaction`
        UPDATE public.sla_evaluation_jobs
        SET status = 'retry_scheduled',
            available_at = clock_timestamp() + interval '1 hour',
            updated_at = clock_timestamp()
        WHERE id = ${fixture.job}::uuid
      `;
      const [futureRetryMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(futureRetryMetrics, "future retry metrics returned no row");
      assert.equal(futureRetryMetrics.pending_jobs, "0");
      assert.equal(futureRetryMetrics.oldest_pending_micros, "0");

      await transaction`
        UPDATE public.sla_evaluation_jobs
        SET status = 'leased', worker_id = ${fixture.worker}::uuid,
            lease_expires_at = created_at + interval '1 second',
            attempt = 1, fence = 1, updated_at = created_at
        WHERE id = ${fixture.job}::uuid
      `;
      const [expiredLeaseMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(expiredLeaseMetrics, "expired lease metrics returned no row");
      assert.equal(expiredLeaseMetrics.pending_jobs, "1");
      assert(
        BigInt(expiredLeaseMetrics.oldest_pending_micros) >= 8_000_000n,
        "expired lease age was not derived from lease_expires_at",
      );

      await transaction`
        UPDATE public.sla_evaluation_jobs
        SET lease_expires_at = clock_timestamp() + interval '1 hour',
            updated_at = clock_timestamp()
        WHERE id = ${fixture.job}::uuid
      `;
      const [liveLeaseMetrics] = await asWorker(
        transaction,
        (sql) =>
          sql<QueueMetrics[]>`
            SELECT * FROM app.read_sla_evaluation_queue_metrics_v1()
          `,
      );
      assert(liveLeaseMetrics, "live lease metrics returned no row");
      assert.equal(liveLeaseMetrics.pending_jobs, "0");
      assert.equal(liveLeaseMetrics.oldest_pending_micros, "0");

      await transaction`
        UPDATE public.sla_evaluation_jobs
        SET status = 'queued', available_at = ${observedAt},
            worker_id = NULL, lease_expires_at = NULL,
            attempt = 0, fence = 0, updated_at = clock_timestamp()
        WHERE id = ${fixture.job}::uuid
      `;

      const [claim] = await asWorker(
        transaction,
        async (sql) =>
          sql<Claim[]>`
          SELECT * FROM app.claim_sla_evaluation_jobs_v3(
            ${fixture.worker}::uuid, clock_timestamp(), 10, 60000000
          )
        `,
      );
      assert(claim, "worker did not claim the due SLA job");
      assert.equal(claim.job_id, fixture.job);
      assert.equal(claim.tenant_id, fixture.tenant);
      assert.equal(claim.sla_instance_id, fixture.slaInstance);
      assert.equal(claim.expected_aggregate_version, 1);
      assert.equal(claim.fence, "1");
      assert.equal(claim.attempt, 1);
      assert.equal(
        claim.lease_expires_at.getTime() - claim.observed_at.getTime(),
        60_000,
        "claim lease was not derived from the supplied observation instant",
      );
      assert(Array.isArray(claim.state_document.metrics));

      const finalizedAt = new Date(claim.observed_at.getTime() + 1_000);
      const occurrenceDigest = digest("trigger-occurrence");
      const finalizedMetric = {
        id: fixture.metricInstance,
        definition_id: fixture.metricDefinition,
        policy_id: fixture.policy,
        policy_version: 1,
        version: 2,
        lifecycle: "pending",
        state: "pending",
        created_at: observedAt.toISOString(),
        updated_at: finalizedAt.toISOString(),
        extension_micros: 0,
        consumed_micros: 0,
        started_at: null,
        last_resumed_at: null,
        paused_at: null,
        completed_at: null,
        due_at: null,
        breach_threshold_at: null,
        breached_at: null,
        last_event_id: null,
        last_event_key: null,
        last_event_at: null,
        last_override_id: null,
        last_override_digest: null,
      } as const;
      const finalizePlan = {
        metrics: [finalizedMetric],
        cursors: [],
        occurrences: [
          {
            id: fixture.occurrence,
            metric_instance_id: fixture.metricInstance,
            trigger_definition_id: fixture.triggerDefinition,
            scheduled_at: finalizedAt.toISOString(),
            deduplication_digest: occurrenceDigest.toString("hex"),
            action_kind: "add_tag",
            action_configuration_id: null,
            action_value: "sla-breached",
            allow_recursive_sla: false,
          },
        ],
        columns: [
          {
            metric_instance_id: fixture.metricInstance,
            column_id: fixture.column,
            column_version: 1,
            state_value: null,
            instant_value: new Date(
              finalizedAt.getTime() + 60_000,
            ).toISOString(),
            duration_micros_value: null,
            percentage_value: null,
            style_key: null,
            next_refresh_at: null,
          },
        ],
        next_evaluation_at: null,
        aggregate_completed_at: null,
      } as const;
      await expectSqlState(
        asWorker(transaction, async (sql) => {
          await sql`
            SELECT app.finalize_sla_evaluation_job_v1(
              ${fixture.worker}::uuid, ${fixture.job}::uuid,
              ${fixture.tenant}::uuid, ${fixture.slaInstance}::uuid,
              1, 2, ${finalizedAt}, ${sql.json(finalizePlan)}::jsonb
            )
          `;
        }),
        "40001",
        "a stale worker fence finalized the job",
      );
      const [finalized] = await asWorker(
        transaction,
        (sql) =>
          sql<{ aggregate_version: number }[]>`
          SELECT app.finalize_sla_evaluation_job_v1(
            ${fixture.worker}::uuid, ${fixture.job}::uuid,
            ${fixture.tenant}::uuid, ${fixture.slaInstance}::uuid,
            1, 1, ${finalizedAt}, ${sql.json(finalizePlan)}::jsonb
          ) AS aggregate_version
        `,
      );
      assert.equal(finalized?.aggregate_version, 2);
      const [finalizedEffects] = await transaction<
        {
          aggregate_version: number;
          metric_version: number;
          occurrences: string;
          columns: string;
          outbox: string;
        }[]
      >`
        SELECT
          (SELECT aggregate_version FROM public.sla_instances
           WHERE id = ${fixture.slaInstance}::uuid) AS aggregate_version,
          (SELECT version FROM public.sla_metric_instances
           WHERE id = ${fixture.metricInstance}::uuid) AS metric_version,
          (SELECT count(*)::text FROM public.sla_trigger_occurrences
           WHERE id = ${fixture.occurrence}::uuid) AS occurrences,
          (SELECT count(*)::text FROM public.sla_materialized_column_values
           WHERE column_id = ${fixture.column}::uuid) AS columns,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND deduplication_key = ${`sla:occurrence:${occurrenceDigest.toString("hex")}`}) AS outbox
      `;
      assert.deepEqual(finalizedEffects, {
        aggregate_version: 2,
        metric_version: 2,
        occurrences: "1",
        columns: "1",
        outbox: "1",
      });

      await transaction`
        INSERT INTO public.sla_evaluation_jobs (
          id, tenant_id, sla_instance_id, expected_aggregate_version,
          status, available_at, attempt, maximum_attempts, fence,
          created_at, updated_at
        ) VALUES (
          ${fixture.retryJob}::uuid, ${fixture.tenant}::uuid,
          ${fixture.slaInstance}::uuid, 2, 'queued', ${finalizedAt},
          0, 3, 0, ${finalizedAt}, ${finalizedAt}
        )
      `;
      const retryClaimAt = new Date(finalizedAt.getTime() + 1);
      const [retryClaim] = await asWorker(
        transaction,
        (sql) =>
          sql<Claim[]>`
            SELECT * FROM app.claim_sla_evaluation_jobs_v3(
              ${fixture.worker}::uuid, ${retryClaimAt}, 10, 60000000
            )
          `,
      );
      assert(retryClaim, "worker did not claim the retry fixture job");
      const failedAt = new Date(retryClaim.observed_at.getTime() + 1_000);
      const retryAt = new Date(retryClaim.observed_at.getTime() + 2_000);
      await expectSqlState(
        asWorker(transaction, async (sql) => {
          await sql`
            SELECT app.fail_sla_evaluation_job_v1(
              ${fixture.worker}::uuid, ${fixture.retryJob}::uuid,
              ${fixture.tenant}::uuid, 2, 1, 'timeout', false,
              ${failedAt}, ${retryAt}
            )
          `;
        }),
        "40001",
        "a stale worker fence changed the retry fixture job",
      );
      const [retry] = await asWorker(
        transaction,
        (sql) =>
          sql<{ status: string }[]>`
            SELECT app.fail_sla_evaluation_job_v1(
              ${fixture.worker}::uuid, ${fixture.retryJob}::uuid,
              ${fixture.tenant}::uuid, 1, 1, 'timeout', false,
              ${failedAt}, ${retryAt}
            )::text AS status
          `,
      );
      assert.equal(retry?.status, "retry_scheduled");
      const reclaimAt = new Date(retryAt.getTime() + 1);
      const [reclaim] = await asWorker(
        transaction,
        (sql) =>
          sql<Claim[]>`
            SELECT * FROM app.claim_sla_evaluation_jobs_v3(
              ${fixture.worker}::uuid, ${reclaimAt}, 10, 60000000
            )
          `,
      );
      assert(reclaim, "retryable SLA job was not reclaimable");
      assert.equal(reclaim.fence, "2");
      assert.equal(reclaim.attempt, 2);
      const permanentAt = new Date(reclaim.observed_at.getTime() + 1_000);
      const [deadLetter] = await asWorker(
        transaction,
        (sql) =>
          sql<{ status: string }[]>`
            SELECT app.fail_sla_evaluation_job_v1(
              ${fixture.worker}::uuid, ${fixture.retryJob}::uuid,
              ${fixture.tenant}::uuid, 2, 2, 'malformed_projection', true,
              ${permanentAt}, NULL
            )::text AS status
          `,
      );
      assert.equal(deadLetter?.status, "dead_lettered");
      const afterDeadLetter = await asWorker(
        transaction,
        (sql) =>
          sql<Claim[]>`
            SELECT * FROM app.claim_sla_evaluation_jobs_v3(
              ${fixture.worker}::uuid,
              ${new Date(reclaimAt.getTime() + 120_000)}, 10, 60000000
            )
          `,
      );
      assert.equal(
        afterDeadLetter.length,
        0,
        "dead-lettered job was reclaimed",
      );

      const [epochs] = await transaction<
        { permission_epoch: string; subject_epoch: string }[]
      >`
        SELECT state.revision::text AS permission_epoch,
               profile.version::text AS subject_epoch
        FROM public.tenant_authorization_states AS state
        JOIN public.tenant_user_profiles AS profile
          ON profile.tenant_id = state.tenant_id
         AND profile.membership_id = ${fixture.membership}::uuid
        WHERE state.tenant_id = ${fixture.tenant}::uuid
      `;
      assert(epochs, "SLA override authority epochs were not seeded");
      const overrideAt = new Date(finalizedAt.getTime() + 5_000);
      const commandDigest = digest("override-command");
      const overrideKeyDigest = digest("override-key");
      const overrideRequestDigest = digest("override-request");
      const overridePlan = {
        metrics: [
          {
            ...finalizedMetric,
            version: 3,
            updated_at: overrideAt.toISOString(),
            extension_micros: 1_000_000,
            last_override_id: fixture.override,
            last_override_digest: commandDigest.toString("hex"),
          },
        ],
        cursors: [],
        occurrences: [],
        columns: [
          {
            metric_instance_id: fixture.metricInstance,
            column_id: fixture.column,
            column_version: 1,
            state_value: null,
            instant_value: new Date(
              overrideAt.getTime() + 60_000,
            ).toISOString(),
            duration_micros_value: null,
            percentage_value: null,
            style_key: null,
            next_refresh_at: null,
          },
        ],
        next_evaluation_at: null,
        aggregate_completed_at: null,
        previous_snapshot: { version: 2 },
        current_snapshot: { version: 3 },
      } as const;
      const commitOverride = async (
        sql: TransactionSql,
        candidateRequestDigest: Buffer,
        candidateSubjectEpoch = epochs.subject_epoch,
      ) => {
        const [begin] = await sql<
          {
            fresh: boolean;
            override_id: string;
            outcome: string | null;
            metric_instance_id: string | null;
            current_version: number | null;
            aggregate_version: number | null;
            policy_id: string | null;
            policy_version: number | null;
            permission_epoch: string | null;
            subject_epoch: string | null;
            occurred_at: Date | null;
            state_document: Record<string, unknown> | null;
          }[]
        >`
          SELECT override_id, fresh, outcome::text, metric_instance_id,
                 current_version, aggregate_version, policy_id,
                 policy_version, permission_epoch::text,
                 subject_epoch::text, occurred_at, state_document
          FROM app.begin_sla_override_v2(
            ${fixture.tenant}::uuid, ${fixture.override}::uuid, 'alert',
            ${fixture.runtimeAlert}::uuid, ${fixture.slaInstance}::uuid,
            ${fixture.metricInstance}::uuid, 'extend', 2, 2,
            NULL, 0, NULL, 0, NULL,
            ${overrideKeyDigest}::bytea, ${candidateRequestDigest}::bytea,
            ${fixture.membership}::uuid, 'alert.sla.override'
          )
        `;
        assert(begin, "override begin returned no result");
        if (!begin.fresh) {
          return {
            override_id: begin.override_id,
            outcome: begin.outcome,
            metric_instance_id: begin.metric_instance_id,
            current_version: begin.current_version,
            aggregate_version: begin.aggregate_version,
            policy_id: begin.policy_id,
            policy_version: begin.policy_version,
            permission_epoch: begin.permission_epoch,
            subject_epoch: begin.subject_epoch,
            replayed: true,
          };
        }
        assert(begin.state_document, "fresh override omitted planner state");
        const [receipt] = await sql<
          {
            override_id: string;
            outcome: string;
            metric_instance_id: string | null;
            current_version: number;
            aggregate_version: number;
            policy_id: string;
            policy_version: number;
            permission_epoch: string;
            subject_epoch: string;
            replayed: boolean;
          }[]
        >`
          SELECT override_id, outcome::text, metric_instance_id,
                 current_version, aggregate_version, policy_id,
                 policy_version, permission_epoch::text,
                 subject_epoch::text, replayed
          FROM app.commit_sla_override_v1(
            ${fixture.tenant}::uuid, ${fixture.override}::uuid, 'alert',
            ${fixture.runtimeAlert}::uuid, ${fixture.slaInstance}::uuid,
            ${fixture.metricInstance}::uuid, 'extend',
            'Security fixture extension', 'metric_updated', 2, 3, 2, 3,
            ${fixture.policy}::uuid, 1, ${epochs.permission_epoch}::bigint,
            ${candidateSubjectEpoch}::bigint, ${overrideAt},
            ${commandDigest}::bytea, ${digest("override-simulation")}::bytea,
            ${sql.json(overridePlan)}::jsonb, ${overrideKeyDigest}::bytea,
            ${candidateRequestDigest}::bytea, ${fixture.policyRequest}::uuid,
            ${fixture.policyCorrelation}::uuid, '127.0.0.1'::inet,
            'sla-security-test', 'totp'
          )
        `;
        assert(receipt, "override commit returned no receipt");
        return receipt;
      };
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, (sql) =>
          commitOverride(
            sql,
            overrideRequestDigest,
            (BigInt(epochs.subject_epoch) + 1n).toString(),
          ),
        ),
        "42501",
        "stale subject epoch authorized an override",
      );
      const overrideReceipt = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => commitOverride(sql, overrideRequestDigest),
      );
      assert.deepEqual(overrideReceipt, {
        override_id: fixture.override,
        outcome: "metric_updated",
        metric_instance_id: fixture.metricInstance,
        current_version: 3,
        aggregate_version: 3,
        policy_id: fixture.policy,
        policy_version: 1,
        permission_epoch: epochs.permission_epoch,
        subject_epoch: epochs.subject_epoch,
        replayed: false,
      });
      const overrideReplay = await asApi(
        transaction,
        fixture.tenant,
        fixture.user,
        (sql) => commitOverride(sql, overrideRequestDigest),
      );
      assert.equal(overrideReplay.replayed, true);
      await expectSqlState(
        asApi(transaction, fixture.tenant, fixture.user, (sql) =>
          commitOverride(sql, digest("changed-override-request")),
        ),
        "23505",
        "override idempotency key accepted a changed request",
      );
      const [overrideEffects] = await transaction<
        {
          aggregate_version: number;
          metric_version: number;
          overrides: string;
          outbox: string;
        }[]
      >`
        SELECT
          (SELECT aggregate_version FROM public.sla_instances
           WHERE id = ${fixture.slaInstance}::uuid) AS aggregate_version,
          (SELECT version FROM public.sla_metric_instances
           WHERE id = ${fixture.metricInstance}::uuid) AS metric_version,
          (SELECT count(*)::text FROM public.sla_overrides
           WHERE id = ${fixture.override}::uuid) AS overrides,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND aggregate_id = ${fixture.metricInstance}::uuid
             AND event_type = 'sla.override.committed') AS outbox
      `;
      assert.deepEqual(overrideEffects, {
        aggregate_version: 3,
        metric_version: 3,
        overrides: "1",
        outbox: "1",
      });

      const barrierAt = new Date(overrideAt.getTime() + 10_000);
      await transaction`
        INSERT INTO public.sla_evaluation_jobs (
          id, tenant_id, sla_instance_id, expected_aggregate_version,
          status, available_at, attempt, maximum_attempts, fence,
          created_at, updated_at
        ) VALUES (
          ${fixture.ingressBarrierJob}::uuid, ${fixture.tenant}::uuid,
          ${fixture.slaInstance}::uuid, 3, 'queued', ${barrierAt},
          0, 3, 0, ${barrierAt}, ${barrierAt}
        )
      `;
      await transaction`
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          correlation_id, causation_id, occurred_at, available_at
        ) VALUES (
          ${fixture.ingressBarrierEvent}::uuid, ${fixture.tenant}::uuid,
          'alert', ${fixture.runtimeAlert}::uuid, 1,
          'sla.alert.transitioned', 1,
          jsonb_build_object(
            'alert_id', ${fixture.runtimeAlert}::uuid,
            'version', 1, 'action', 'transitioned'
          ),
          'sla:security:ingress-barrier', ${fixture.correlation}::uuid,
          ${fixture.request}::uuid, ${barrierAt}, ${barrierAt}
        )
      `;
      for (const claimFunction of [
        "app.claim_sla_evaluation_jobs_v3",
        "app.claim_sla_evaluation_jobs_v2",
      ]) {
        // eslint-disable-next-line no-await-in-loop -- Rolling timer ABIs share one transaction and must be checked serially.
        const blocked = await asWorker(transaction, (sql) =>
          sql.unsafe<Claim[]>(
            `SELECT * FROM ${claimFunction}($1::uuid,$2::timestamptz,10,60000000)`,
            [fixture.worker, barrierAt],
          ),
        );
        assert.equal(
          blocked.length,
          0,
          `${claimFunction} bypassed a pending object-event ingress row`,
        );
      }

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end();
}
