import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_SLA_TRIGGER_ACTION_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SLA_TRIGGER_ACTION_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a0a100-0000-7000-8000-000000000001",
  foreignTenant: "01a0a100-0000-7000-8000-000000000002",
  user: "01a0a100-0000-7000-8000-000000000101",
  foreignUser: "01a0a100-0000-7000-8000-000000000102",
  membership: "01a0a100-0000-7000-8000-000000000201",
  foreignMembership: "01a0a100-0000-7000-8000-000000000202",
  policy: "01a0a100-0000-7000-8000-000000000301",
  metricDefinition: "01a0a100-0000-7000-8000-000000000302",
  triggerDefinition: "01a0a100-0000-7000-8000-000000000303",
  alert: "01a0a100-0000-7000-8000-000000000401",
  slaInstance: "01a0a100-0000-7000-8000-000000000402",
  metricInstance: "01a0a100-0000-7000-8000-000000000403",
  assignmentEvent: "01a0a100-0000-7000-8000-000000000404",
  occurrence: "01a0a100-0000-7000-8000-000000000405",
  worker: "01a0a100-0000-7000-8000-000000000501",
  otherWorker: "01a0a100-0000-7000-8000-000000000502",
  request: "01a0a100-0000-7000-8000-000000000601",
  correlation: "01a0a100-0000-7000-8000-000000000602",
} as const;

type Claim = {
  occurrence_id: string;
  tenant_id: string;
  action_kind: string;
  deduplication_digest: Buffer;
  fence: string;
  attempt: number;
  claimed_at: Date;
  lease_expires_at: Date;
};

function digest(label: string): Buffer {
  return createHash("sha256").update(`sla-action-security:${label}`).digest();
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
  transaction: TransactionSql,
  role:
    | "periapsis_api"
    | "periapsis_worker"
    | "periapsis_sla_worker_owner"
    | "periapsis_notifier"
    | "periapsis_auditor",
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

async function asApi<T>(
  transaction: TransactionSql,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  return asRole(transaction, "periapsis_api", async (sql) => {
    await sql`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.user}, true),
             set_config('app.service_account_id', '', true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate', 'sla-action=runtime', true)
    `;
    return operation(sql);
  });
}

const policyDocument = {
  key: "action-security",
  name: "Action security",
  description: "Runtime action security fixture",
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
      start_event: "ticket.created",
      pause_event: null,
      resume_event: null,
      completion_event: "ticket.closed",
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

const database = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const rollbackMarker = new Error("intentional SLA action security rollback");

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
      await transaction`
        INSERT INTO public.tenants (id, slug, name) VALUES
          (${fixture.tenant}::uuid, 'sla-action-security',
           'SLA action security'),
          (${fixture.foreignTenant}::uuid, 'sla-action-security-foreign',
           'SLA action security foreign')
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id) VALUES
          (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active) VALUES
          (${fixture.user}::uuid, 'sla-action@example.invalid',
           'SLA action operator', true),
          (${fixture.foreignUser}::uuid, 'sla-action-foreign@example.invalid',
           'SLA action foreign', true)
      `;
      await transaction`
        INSERT INTO public.tenant_memberships (
          id, tenant_id, user_id, role, status
        ) VALUES
          (${fixture.membership}::uuid, ${fixture.tenant}::uuid,
           ${fixture.user}::uuid, 'tenant_admin', 'active'),
          (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
           ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
      `;
      await transaction`
        INSERT INTO public.tenant_user_profiles (
          tenant_id, membership_id, user_id, display_name, email
        ) VALUES
          (${fixture.tenant}::uuid, ${fixture.membership}::uuid,
           ${fixture.user}::uuid, 'SLA action operator',
           'sla-action@example.invalid'),
          (${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid,
           ${fixture.foreignUser}::uuid, 'SLA action foreign',
           'sla-action-foreign@example.invalid')
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.tenant}::uuid, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid
        )
      `;
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.user}, true),
               set_config('app.service_account_id', '', true)
      `;
      for (const relation of [
        "tenant_notification_smtp_configurations",
        "tenant_notification_webhook_configurations",
      ] as const) {
        // eslint-disable-next-line no-await-in-loop -- Each role proof shares the fixture transaction.
        await transaction.savepoint(async (proof) => {
          const table = proof(`public.${relation}`);
          await proof`
            INSERT INTO ${table} (
              id, tenant_id, created_by_membership_id, created_by_user_id
            ) VALUES
              (${fixture.request}::uuid, ${fixture.tenant}::uuid,
               ${fixture.membership}::uuid, ${fixture.user}::uuid),
              (${fixture.correlation}::uuid, ${fixture.foreignTenant}::uuid,
               ${fixture.foreignMembership}::uuid, ${fixture.foreignUser}::uuid)
          `;
          await asRole(proof, "periapsis_sla_worker_owner", async (owner) => {
            const rows = await owner<{ id: string }[]>`
              SELECT id::text FROM ${table} FOR SHARE
            `;
            assert.deepEqual(
              rows.map((row) => row.id),
              [fixture.request],
            );
            await expectSqlState(
              owner.savepoint(async (denied) => {
                await denied`UPDATE ${table} SET id = id`;
              }),
              "42501",
              "lock privilege enabled writes",
            );
          });
          await proof`
            UPDATE ${table} SET revoked_at = transaction_timestamp()
            WHERE id = ${fixture.request}::uuid
          `;
          await asRole(proof, "periapsis_sla_worker_owner", async (owner) => {
            const rows = await owner`SELECT id FROM ${table} FOR SHARE`;
            assert.equal(
              rows.length,
              0,
              "revoked configuration remained visible",
            );
          });
        });
      }
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          customer_visible, title, description,
          created_by, created_by_membership_id
        )
        SELECT ${fixture.alert}::uuid, ${fixture.tenant}::uuid,
               'ALT-2026-810001', workflow.id, workflow.current_version,
               'new', false, 'Private action fixture',
               'must-never-escape-action-secret', ${fixture.user}::uuid,
               ${fixture.membership}::uuid
        FROM public.ticket_workflows AS workflow
        WHERE workflow.tenant_id = ${fixture.tenant}::uuid
          AND workflow.key = 'default_alert'
      `;

      await asApi(transaction, async (sql) => {
        const [published] = await sql<{ replayed: boolean }[]>`
          SELECT * FROM app.publish_sla_policy_v2(
            ${fixture.tenant}::uuid, ${fixture.policy}::uuid, 0,
            ${sql.json(policyDocument)}::jsonb,
            ${digest("policy-key")}::bytea,
            ${digest("policy-request")}::bytea,
            ${fixture.request}::uuid, ${fixture.correlation}::uuid,
            '127.0.0.1'::inet, 'sla-action-security', 'totp'
          )
        `;
        assert.equal(published?.replayed, false);
      });

      const [runtimeWindow] = await transaction<{ queued_at: Date }[]>`
        SELECT transaction_timestamp() - interval '2 seconds' AS queued_at
      `;
      assert(runtimeWindow, "database SLA runtime window is missing");
      const queuedAt = runtimeWindow.queued_at;
      const occurrenceDigest = digest("occurrence");
      await transaction`
        INSERT INTO public.sla_instances (
          id, tenant_id, object_type, object_id, policy_id, policy_version,
          aggregate_version, assignment_event_id, created_at, updated_at
        ) VALUES (
          ${fixture.slaInstance}::uuid, ${fixture.tenant}::uuid, 'alert',
          ${fixture.alert}::uuid, ${fixture.policy}::uuid, 1, 1,
          ${fixture.assignmentEvent}::uuid, ${queuedAt}, ${queuedAt}
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
          ${queuedAt}, ${queuedAt}, 0, 0
        )
      `;
      await transaction`
        INSERT INTO public.sla_trigger_occurrences (
          id, tenant_id, sla_instance_id, metric_instance_id,
          trigger_definition_id, scheduled_at, deduplication_digest,
          action_kind, action_configuration_id, action_value,
          allow_recursive_sla, created_at
        ) VALUES (
          ${fixture.occurrence}::uuid, ${fixture.tenant}::uuid,
          ${fixture.slaInstance}::uuid, ${fixture.metricInstance}::uuid,
          ${fixture.triggerDefinition}::uuid, ${queuedAt},
          ${occurrenceDigest}::bytea, 'add_tag', NULL, 'sla-breached', false,
          ${queuedAt}
        )
      `;

      const [ready] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ ready: boolean }[]>`
            SELECT app.sla_trigger_action_runtime_schema_readiness_v58()
              AS ready
          `,
      );
      assert.equal(ready?.ready, true, "SLA action readiness is false");

      for (const role of [
        "periapsis_api",
        "periapsis_notifier",
        "periapsis_auditor",
      ] as const) {
        // eslint-disable-next-line no-await-in-loop -- Role savepoints share one transaction and must be serialized.
        await expectSqlState(
          asRole(transaction, role, async (sql) => {
            await sql`
              SELECT * FROM app.claim_sla_trigger_actions_v1(
                ${fixture.worker}::uuid, ${fixture.tenant}::uuid,
                clock_timestamp(), 1, 30000000
              )
            `;
          }),
          "42501",
          `${role} executed the worker-only SLA action claim`,
        );
        // eslint-disable-next-line no-await-in-loop -- Role savepoints share one transaction and must be serialized.
        await expectSqlState(
          asRole(transaction, role, async (sql) => {
            await sql`SELECT * FROM public.sla_trigger_action_executions`;
          }),
          "42501",
          `${role} retained direct SLA action table access`,
        );
      }
      await expectSqlState(
        asRole(transaction, "periapsis_worker", async (sql) => {
          await sql`SELECT * FROM public.sla_trigger_action_receipts`;
        }),
        "42501",
        "worker retained direct receipt access",
      );

      const [metrics] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ pending_actions: string; oldest_pending_micros: string }[]>`
            SELECT * FROM app.read_sla_trigger_action_queue_metrics_v1()
          `,
      );
      assert.equal(metrics?.pending_actions, "1");
      assert(BigInt(metrics?.oldest_pending_micros ?? "0") >= 1_000_000n);
      const queue = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ tenant_id: string }[]>`
            SELECT * FROM app.list_sla_trigger_action_queues_v1(
              clock_timestamp(), 10
            )
          `,
      );
      assert.deepEqual(
        queue.map((row) => row.tenant_id),
        [fixture.tenant],
      );

      const [claim] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<Claim[]>`
            SELECT * FROM app.claim_sla_trigger_actions_v1(
              ${fixture.worker}::uuid, ${fixture.tenant}::uuid,
              clock_timestamp(), 1, 30000000
            )
          `,
      );
      assert(claim, "worker did not claim the SLA action");
      assert.equal(claim.occurrence_id, fixture.occurrence);
      assert.equal(claim.tenant_id, fixture.tenant);
      assert.equal(claim.action_kind, "add_tag");
      assert.equal(claim.fence, "1");
      assert.equal(claim.attempt, 1);
      assert.equal(
        claim.lease_expires_at.getTime() - claim.claimed_at.getTime(),
        30_000,
      );

      const appliedAt = new Date(claim.claimed_at.getTime() + 1_000);
      const [wrongFence] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ disposition: string }[]>`
            SELECT app.execute_sla_trigger_action_v1(
              ${fixture.worker}::uuid, ${fixture.tenant}::uuid,
              ${fixture.occurrence}::uuid, 2, ${occurrenceDigest}::bytea,
              'add_tag', ${appliedAt}
            ) AS disposition
          `,
      );
      assert.equal(wrongFence?.disposition, "fence_lost");
      const [wrongDigest] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ disposition: string }[]>`
            SELECT app.execute_sla_trigger_action_v1(
              ${fixture.worker}::uuid, ${fixture.tenant}::uuid,
              ${fixture.occurrence}::uuid, 1, ${digest("wrong")}::bytea,
              'add_tag', ${appliedAt}
            ) AS disposition
          `,
      );
      assert.equal(wrongDigest?.disposition, "fence_lost");

      const execute = (worker: string, fence: number) =>
        asRole(
          transaction,
          "periapsis_worker",
          (sql) =>
            sql<{ disposition: string }[]>`
            SELECT app.execute_sla_trigger_action_v1(
              ${worker}::uuid, ${fixture.tenant}::uuid,
              ${fixture.occurrence}::uuid, ${fence},
              ${occurrenceDigest}::bytea, 'add_tag', ${appliedAt}
            ) AS disposition
          `,
        );
      const [applied] = await execute(fixture.worker, 1);
      assert.equal(applied?.disposition, "applied");

      const [effects] = await transaction<
        {
          tags: string[];
          version: number;
          receipts: string;
          activities: string;
          audits: string;
          outbox: string;
          redacted: boolean;
        }[]
      >`
        SELECT
          (SELECT tags FROM public.alerts
           WHERE id = ${fixture.alert}::uuid) AS tags,
          (SELECT version FROM public.alerts
           WHERE id = ${fixture.alert}::uuid) AS version,
          (SELECT count(*)::text FROM public.sla_trigger_action_receipts
           WHERE occurrence_id = ${fixture.occurrence}::uuid) AS receipts,
          (SELECT count(*)::text FROM public.ticket_activities
           WHERE alert_id = ${fixture.alert}::uuid
             AND kind = 'sla.action.executed') AS activities,
          (SELECT count(*)::text FROM public.audit_events
           WHERE resource_id = ${fixture.occurrence}::uuid
             AND action = 'tenant.sla.action.executed') AS audits,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE aggregate_id = ${fixture.occurrence}::uuid
             AND event_type = 'sla.action.executed') AS outbox,
          NOT EXISTS (
            SELECT 1
            FROM public.audit_events AS audit
            WHERE audit.resource_id = ${fixture.occurrence}::uuid
              AND (audit.metadata::text LIKE '%must-never-escape%'
                OR audit.metadata ->> 'contentRedacted' <> 'true')
          ) AND NOT EXISTS (
            SELECT 1
            FROM public.outbox_events AS event
            WHERE event.aggregate_id = ${fixture.occurrence}::uuid
              AND (event.payload::text LIKE '%must-never-escape%'
                OR event.payload ->> 'contentRedacted' <> 'true')
          ) AS redacted
      `;
      assert.deepEqual(effects, {
        tags: ["sla-breached"],
        version: 2,
        receipts: "1",
        activities: "1",
        audits: "1",
        outbox: "1",
        redacted: true,
      });

      const [replayed] = await execute(fixture.worker, 1);
      assert.equal(replayed?.disposition, "replayed");
      const [lost] = await execute(fixture.otherWorker, 1);
      assert.equal(lost?.disposition, "fence_lost");
      const [stableCounts] = await transaction<
        {
          receipts: string;
          activities: string;
          audits: string;
          outbox: string;
        }[]
      >`
        SELECT
          (SELECT count(*)::text FROM public.sla_trigger_action_receipts
           WHERE occurrence_id = ${fixture.occurrence}::uuid) AS receipts,
          (SELECT count(*)::text FROM public.ticket_activities
           WHERE alert_id = ${fixture.alert}::uuid
             AND kind = 'sla.action.executed') AS activities,
          (SELECT count(*)::text FROM public.audit_events
           WHERE resource_id = ${fixture.occurrence}::uuid
             AND action = 'tenant.sla.action.executed') AS audits,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE aggregate_id = ${fixture.occurrence}::uuid
             AND event_type = 'sla.action.executed') AS outbox
      `;
      assert.deepEqual(stableCounts, {
        receipts: "1",
        activities: "1",
        audits: "1",
        outbox: "1",
      });
      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            UPDATE public.sla_trigger_action_receipts
            SET applied_at = applied_at + interval '1 microsecond'
            WHERE occurrence_id = ${fixture.occurrence}::uuid
          `;
          return {};
        }),
        "55000",
        "append-only SLA action receipt was mutable",
      );

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end({ timeout: 5 });
}
