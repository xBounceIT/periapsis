import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type ExplainRow = { "QUERY PLAN": string };

function assertIndexScanPlan(
  plan: ExplainRow[],
  index: string,
  description: string,
): void {
  const rendered = plan.map((row) => row["QUERY PLAN"]).join(" | ");
  assert(
    plan.some(
      (row) =>
        /Index(?: Only)? Scan/.test(row["QUERY PLAN"]) &&
        row["QUERY PLAN"].includes(index),
    ),
    `${description} did not use ${index}: ${rendered}`,
  );
}

const databaseUrl =
  process.env.PERIAPSIS_TICKET_QUERY_PROJECTION_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_QUERY_PROJECTION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "019d2fd0-1000-7000-8000-000000000001",
  foreignTenant: "019d2fd0-1000-7000-8000-000000000002",
  user: "019d2fd0-1000-7000-8000-000000000101",
  foreignUser: "019d2fd0-1000-7000-8000-000000000102",
  membership: "019d2fd0-1000-7000-8000-000000000201",
  foreignMembership: "019d2fd0-1000-7000-8000-000000000202",
  serviceAccount: "019d2fd0-1000-7000-8000-000000000301",
  foreignServiceAccount: "019d2fd0-1000-7000-8000-000000000302",
  serviceAlert: "019d2fd0-1000-7000-8000-000000000401",
  humanAlert: "019d2fd0-1000-7000-8000-000000000402",
  foreignAlert: "019d2fd0-1000-7000-8000-000000000403",
  localCase: "019d2fd0-1000-7000-8000-000000000404",
  foreignCase: "019d2fd0-1000-7000-8000-000000000405",
  systemActivity: "019d2fd0-1000-7000-8000-000000000502",
  policy: "019d2fd0-1000-7000-8000-000000000601",
  foreignPolicy: "019d2fd0-1000-7000-8000-000000000602",
  metric: "019d2fd0-1000-7000-8000-000000000603",
  foreignMetric: "019d2fd0-1000-7000-8000-000000000604",
  column: "019d2fd0-1000-7000-8000-000000000605",
  foreignColumn: "019d2fd0-1000-7000-8000-000000000606",
  slaInstance: "019d2fd0-1000-7000-8000-000000000701",
  foreignSlaInstance: "019d2fd0-1000-7000-8000-000000000702",
  metricInstance: "019d2fd0-1000-7000-8000-000000000703",
  foreignMetricInstance: "019d2fd0-1000-7000-8000-000000000704",
  assignment: "019d2fd0-1000-7000-8000-000000000705",
  foreignAssignment: "019d2fd0-1000-7000-8000-000000000706",
} as const;

const database = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const rollbackMarker = new Error("intentional ticket projection rollback");

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-query-projection:${label}`)
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

async function asApi<T>(
  transaction: TransactionSql,
  tenantID: string,
  userID: string,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe('SET LOCAL ROLE "periapsis_api"');
    await sql.unsafe("SET LOCAL statement_timeout = '15s'");
    await sql`
      SELECT set_config('app.tenant_id', ${tenantID}, true),
             set_config('app.user_id', ${userID}, true),
             set_config('app.service_account_id', '', true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate', 'projection=runtime', true)
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

async function insertFixture(transaction: TransactionSql): Promise<void> {
  await transaction`
    INSERT INTO public.tenants (id, slug, name) VALUES
      (${fixture.tenant}::uuid, 'ticket-projection-local',
       'Ticket projection local'),
      (${fixture.foreignTenant}::uuid, 'ticket-projection-foreign',
       'Ticket projection foreign')
  `;
  await transaction`
    INSERT INTO public.audit_chain_heads (tenant_id) VALUES
      (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
  `;
  await transaction`
    INSERT INTO public.users (id, email, display_name, active) VALUES
      (${fixture.user}::uuid, 'projection-local@example.invalid',
       'Local operator', true),
      (${fixture.foreignUser}::uuid, 'projection-foreign@example.invalid',
       'Foreign operator', true)
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
       ${fixture.user}::uuid, 'Local operator',
       'projection-local@example.invalid'),
      (${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid,
       ${fixture.foreignUser}::uuid, 'Foreign operator',
       'projection-foreign@example.invalid')
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
    INSERT INTO public.tenant_service_accounts (
      id, tenant_id, key, display_name, description,
      created_by_membership_id
    ) VALUES
      (${fixture.serviceAccount}::uuid, ${fixture.tenant}::uuid,
       'ticket_projection_local', 'Local automation',
       'private-local-description', ${fixture.membership}::uuid),
      (${fixture.foreignServiceAccount}::uuid,
       ${fixture.foreignTenant}::uuid, 'ticket_projection_foreign',
       'Foreign automation', 'private-foreign-description',
       ${fixture.foreignMembership}::uuid)
  `;
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
           set_config('app.user_id', ${fixture.user}, true)
  `;
  await transaction`
    INSERT INTO public.alerts (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, title, created_by_service_account_id,
      updated_at
    )
    SELECT ${fixture.serviceAlert}::uuid, ${fixture.tenant}::uuid,
           'ALT-2026-700001', workflow.id, workflow.current_version, 'new',
           false, 'Service-created alert', ${fixture.serviceAccount}::uuid,
           clock_timestamp()
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = ${fixture.tenant}::uuid
      AND workflow.key = 'default_alert'
  `;
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.foreignTenant}, true),
           set_config('app.user_id', ${fixture.foreignUser}, true)
  `;
  await transaction`
    INSERT INTO public.alerts (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, title, created_by_service_account_id,
      updated_at
    )
    SELECT ${fixture.foreignAlert}::uuid, ${fixture.foreignTenant}::uuid,
           'ALT-2026-700002', workflow.id, workflow.current_version, 'new',
           false, 'Foreign service-created alert',
           ${fixture.foreignServiceAccount}::uuid, clock_timestamp()
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = ${fixture.foreignTenant}::uuid
      AND workflow.key = 'default_alert'
  `;
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
           set_config('app.user_id', ${fixture.user}, true)
  `;
  await transaction`
    INSERT INTO public.alerts (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, title, created_by, created_by_membership_id,
      updated_at
    )
    SELECT ${fixture.humanAlert}::uuid, ${fixture.tenant}::uuid,
           'ALT-2026-700003', workflow.id, workflow.current_version,
           'new', false, 'Human-created alert', ${fixture.user}::uuid,
           ${fixture.membership}::uuid, clock_timestamp()
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = ${fixture.tenant}::uuid
      AND workflow.key = 'default_alert'
  `;
  await transaction`
    INSERT INTO public.cases (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      title, created_by_membership_id, created_by_user_id, updated_at
    )
    SELECT ${fixture.localCase}::uuid, ${fixture.tenant}::uuid,
           'CAS-2026-700001', workflow.id, workflow.current_version, 'new',
           'Local case', ${fixture.membership}::uuid, ${fixture.user}::uuid,
           clock_timestamp()
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = ${fixture.tenant}::uuid
      AND workflow.key = 'default_case'
  `;
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.foreignTenant}, true),
           set_config('app.user_id', ${fixture.foreignUser}, true)
  `;
  await transaction`
    INSERT INTO public.cases (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      title, created_by_membership_id, created_by_user_id, updated_at
    )
    SELECT ${fixture.foreignCase}::uuid, ${fixture.foreignTenant}::uuid,
           'CAS-2026-700002', workflow.id, workflow.current_version, 'new',
           'Foreign case', ${fixture.foreignMembership}::uuid,
           ${fixture.foreignUser}::uuid, clock_timestamp()
    FROM public.ticket_workflows AS workflow
    WHERE workflow.tenant_id = ${fixture.foreignTenant}::uuid
      AND workflow.key = 'default_case'
  `;
  await transaction`
    SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
           set_config('app.user_id', ${fixture.user}, true)
  `;
  await transaction`
    INSERT INTO public.ticket_activities (
      id, tenant_id, alert_id, sequence, kind, summary,
      actor_principal_kind, actor_service_account_id, origin, details
    ) VALUES (
      ${fixture.systemActivity}::uuid, ${fixture.tenant}::uuid,
      ${fixture.serviceAlert}::uuid, 2, 'alert.transitioned',
      'Transitioned by system', 'system', NULL, 'system', '{}'::jsonb
    )
  `;
  await transaction`
    INSERT INTO public.sla_policies (
      id, tenant_id, key, active_version, resource_version,
      created_by_membership_id, updated_by_membership_id
    ) VALUES
      (${fixture.policy}::uuid, ${fixture.tenant}::uuid,
       'projection_policy', 1, 1, ${fixture.membership}::uuid,
       ${fixture.membership}::uuid),
      (${fixture.foreignPolicy}::uuid, ${fixture.foreignTenant}::uuid,
       'projection_policy', 1, 1, ${fixture.foreignMembership}::uuid,
       ${fixture.foreignMembership}::uuid)
  `;
  await transaction`
    INSERT INTO public.sla_policy_versions (
      tenant_id, policy_id, version, name, priority, object_types,
      match_rule, effective_from, enabled, revision_digest,
      created_by_membership_id
    ) VALUES
      (${fixture.tenant}::uuid, ${fixture.policy}::uuid, 1,
       'Projection policy', 0, ARRAY['alert']::public.sla_object_type[],
       '{}'::jsonb, '2026-01-01T00:00:00Z', true,
       ${digest("policy")}, ${fixture.membership}::uuid),
      (${fixture.foreignTenant}::uuid, ${fixture.foreignPolicy}::uuid, 1,
       'Foreign projection policy', 0,
       ARRAY['alert']::public.sla_object_type[], '{}'::jsonb,
       '2026-01-01T00:00:00Z', true, ${digest("foreign-policy")},
       ${fixture.foreignMembership}::uuid)
  `;
  await transaction`
    INSERT INTO public.sla_metric_definitions (
      tenant_id, policy_id, policy_version, id, key, label,
      duration_micros, clock, start_event, completion_event,
      reset_policy, warning_kind, breach_grace_micros, display_format,
      customer_visible, api_visible, position, definition_digest
    ) VALUES
      (${fixture.tenant}::uuid, ${fixture.policy}::uuid, 1,
       ${fixture.metric}::uuid, 'response_time', 'Response time',
       60000000, 'elapsed', 'alert.created', 'alert.completed',
       'ignore', 'none', 0, 'duration', false, true, 0,
       ${digest("metric")}),
      (${fixture.foreignTenant}::uuid, ${fixture.foreignPolicy}::uuid, 1,
       ${fixture.foreignMetric}::uuid, 'response_time', 'Response time',
       60000000, 'elapsed', 'alert.created', 'alert.completed',
       'ignore', 'none', 0, 'duration', false, true, 0,
       ${digest("foreign-metric")})
  `;
  await transaction`
    INSERT INTO public.sla_columns (
      id, tenant_id, key, active_version, resource_version,
      created_by_membership_id, updated_by_membership_id
    ) VALUES
      (${fixture.column}::uuid, ${fixture.tenant}::uuid, 'due_at', 1, 1,
       ${fixture.membership}::uuid, ${fixture.membership}::uuid),
      (${fixture.foreignColumn}::uuid, ${fixture.foreignTenant}::uuid,
       'due_at', 1, 1, ${fixture.foreignMembership}::uuid,
       ${fixture.foreignMembership}::uuid)
  `;
  await transaction`
    INSERT INTO public.sla_column_versions (
      tenant_id, column_id, version, label, metric_definition_id,
      calculation, format, sortable, filterable, customer_visible,
      visible_role_keys, position, style_rules, revision_digest,
      created_by_membership_id
    ) VALUES
      (${fixture.tenant}::uuid, ${fixture.column}::uuid, 1, 'Due at',
       ${fixture.metric}::uuid, 'due_at', 'datetime', true, true, false,
       ARRAY['tenant_admin']::text[], 0, '[]'::jsonb,
       ${digest("column")}, ${fixture.membership}::uuid),
      (${fixture.foreignTenant}::uuid, ${fixture.foreignColumn}::uuid, 1,
       'Foreign due at', ${fixture.foreignMetric}::uuid, 'due_at',
       'datetime', true, true, false, ARRAY['tenant_admin']::text[], 0,
       '[]'::jsonb, ${digest("foreign-column")},
       ${fixture.foreignMembership}::uuid)
  `;
  const observedAt = new Date("2026-08-26T12:00:00Z");
  await transaction`
    INSERT INTO public.sla_instances (
      id, tenant_id, object_type, object_id, policy_id, policy_version,
      aggregate_version, assignment_event_id, created_at, updated_at
    ) VALUES
      (${fixture.slaInstance}::uuid, ${fixture.tenant}::uuid, 'alert',
       ${fixture.serviceAlert}::uuid, ${fixture.policy}::uuid, 1, 1,
       ${fixture.assignment}::uuid, ${observedAt}, ${observedAt}),
      (${fixture.foreignSlaInstance}::uuid, ${fixture.foreignTenant}::uuid,
       'alert', ${fixture.foreignAlert}::uuid,
       ${fixture.foreignPolicy}::uuid, 1, 1,
       ${fixture.foreignAssignment}::uuid, ${observedAt}, ${observedAt})
  `;
  await transaction`
    INSERT INTO public.sla_metric_instances (
      id, tenant_id, sla_instance_id, definition_id, policy_id,
      policy_version, version, lifecycle, state, created_at, updated_at,
      extension_micros, consumed_micros
    ) VALUES
      (${fixture.metricInstance}::uuid, ${fixture.tenant}::uuid,
       ${fixture.slaInstance}::uuid, ${fixture.metric}::uuid,
       ${fixture.policy}::uuid, 1, 1, 'pending', 'pending',
       ${observedAt}, ${observedAt}, 0, 0),
      (${fixture.foreignMetricInstance}::uuid,
       ${fixture.foreignTenant}::uuid, ${fixture.foreignSlaInstance}::uuid,
       ${fixture.foreignMetric}::uuid, ${fixture.foreignPolicy}::uuid,
       1, 1, 'pending', 'pending', ${observedAt}, ${observedAt}, 0, 0)
  `;
  await transaction`
    INSERT INTO public.sla_materialized_column_values (
      tenant_id, object_type, object_id, sla_instance_id,
      metric_instance_id, column_id, column_version, instant_value,
      style_key, materialized_at
    ) VALUES
      (${fixture.tenant}::uuid, 'alert', ${fixture.serviceAlert}::uuid,
       ${fixture.slaInstance}::uuid, ${fixture.metricInstance}::uuid,
       ${fixture.column}::uuid, 1, '2026-08-26T13:00:00Z',
       'warning', ${observedAt}),
      (${fixture.foreignTenant}::uuid, 'alert',
       ${fixture.foreignAlert}::uuid, ${fixture.foreignSlaInstance}::uuid,
       ${fixture.foreignMetricInstance}::uuid,
       ${fixture.foreignColumn}::uuid, 1, '2026-08-26T14:00:00Z',
       'critical', ${observedAt})
  `;
}

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '30s'");
      await insertFixture(transaction);

      await asApi(transaction, fixture.tenant, fixture.user, async (sql) => {
        const [readiness] = await sql<{ ready: boolean }[]>`
            SELECT app.release_runtime_schema_readiness_v61() AS ready
          `;
        assert.equal(readiness?.ready, true, "projection readiness is false");

        const expectDeniedSource = async (source: string): Promise<void> => {
          await expectSqlState(
            sql.savepoint(async (nested) => {
              await nested.unsafe(`SELECT * FROM public.${source} LIMIT 1`);
              return {};
            }),
            "42501",
            `API retained direct SELECT on ${source}`,
          );
        };
        await expectDeniedSource("tenant_service_accounts");
        await expectDeniedSource("sla_column_versions");
        await expectDeniedSource("sla_materialized_column_values");
        const [ownerMemberships] = await sql<
          { attribution: boolean; sla: boolean }[]
        >`
            SELECT pg_has_role(
                     'periapsis_api',
                     'periapsis_ticket_attribution_owner', 'MEMBER'
                   ) AS attribution,
                   pg_has_role(
                     'periapsis_api',
                     'periapsis_ticket_sla_projection_owner', 'MEMBER'
                   ) AS sla
          `;
        assert.deepEqual(ownerMemberships, { attribution: false, sla: false });

        const attribution = await sql<
          { tenant_id: string; id: string; display_name: string }[]
        >`
            SELECT * FROM app.ticket_service_account_attributions_v1
            ORDER BY id
          `;
        assert.deepEqual(attribution[0], {
          tenant_id: fixture.tenant,
          id: fixture.serviceAccount,
          display_name: "Local automation",
        });
        assert.deepEqual(Object.keys(attribution[0] ?? {}).toSorted(), [
          "display_name",
          "id",
          "tenant_id",
        ]);

        const alertList = await sql<
          { id: string; service_name: string | null }[]
        >`
            SELECT ticket.id, creator_service.display_name AS service_name
            FROM public.alerts AS ticket
            LEFT JOIN app.ticket_service_account_attributions_v1
              AS creator_service
              ON creator_service.tenant_id = ticket.tenant_id
             AND creator_service.id = ticket.created_by_service_account_id
            WHERE ticket.tenant_id = ${fixture.tenant}::uuid
            ORDER BY ticket.updated_at DESC, ticket.id DESC
          `;
        assert.equal(alertList.length, 2, "alert list leaked or lost a row");
        assert.equal(
          alertList.find((row) => row.id === fixture.serviceAlert)
            ?.service_name,
          "Local automation",
        );
        assert.equal(
          alertList.find((row) => row.id === fixture.humanAlert)?.service_name,
          null,
          "human attribution invented a service account",
        );

        const alertGet = await sql<
          { id: string; service_name: string | null }[]
        >`
            SELECT ticket.id, creator_service.display_name AS service_name
            FROM public.alerts AS ticket
            LEFT JOIN app.ticket_service_account_attributions_v1
              AS creator_service
              ON creator_service.tenant_id = ticket.tenant_id
             AND creator_service.id = ticket.created_by_service_account_id
            WHERE ticket.tenant_id = ${fixture.tenant}::uuid
              AND ticket.id = ${fixture.serviceAlert}::uuid
          `;
        assert.deepEqual(alertGet[0], {
          id: fixture.serviceAlert,
          service_name: "Local automation",
        });
        const missingForeignAlert = await sql`
            SELECT ticket.id
            FROM public.alerts AS ticket
            LEFT JOIN app.ticket_service_account_attributions_v1
              AS creator_service
              ON creator_service.tenant_id = ticket.tenant_id
             AND creator_service.id = ticket.created_by_service_account_id
            WHERE ticket.id = ${fixture.foreignAlert}::uuid
          `;
        assert.equal(
          missingForeignAlert.length,
          0,
          "alert get exposed a foreign tenant existence oracle",
        );

        const activity = await sql<
          { sequence: number; display_name: string }[]
        >`
            SELECT activity.sequence,
                   coalesce(identity.display_name,
                            service_account.display_name, 'System')
                     AS display_name
            FROM public.ticket_activities AS activity
            JOIN public.ticket_activity_author_snapshots AS author_snapshot
              ON author_snapshot.tenant_id = activity.tenant_id
             AND author_snapshot.activity_id = activity.id
            LEFT JOIN public.users AS identity
              ON identity.id = activity.actor_user_id
            LEFT JOIN app.ticket_service_account_attributions_v1
              AS service_account
              ON service_account.tenant_id = activity.tenant_id
             AND service_account.id = activity.actor_service_account_id
            WHERE activity.tenant_id = ${fixture.tenant}::uuid
              AND activity.alert_id = ${fixture.serviceAlert}::uuid
            ORDER BY activity.sequence
        `;
        assert.deepEqual(Array.from(activity), [
          { sequence: 1, display_name: "Local automation" },
          { sequence: 2, display_name: "System" },
        ]);

        const revision = await sql<{ format: string; sortable: boolean }[]>`
            SELECT format::text, sortable
            FROM app.ticket_sla_column_revisions_v1
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND column_id = ${fixture.column}::uuid
              AND version = 1
          `;
        assert.deepEqual(revision[0], {
          format: "datetime",
          sortable: true,
        });
        const missingRevision = await sql`
            SELECT format
            FROM app.ticket_sla_column_revisions_v1
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND column_id = ${fixture.foreignColumn}::uuid
              AND version = 1
          `;
        assert.equal(
          missingRevision.length,
          0,
          "SLA resolver exposed a foreign revision existence oracle",
        );

        const sorted = await sql<{ id: string; instant_value: Date | null }[]>`
            SELECT ticket.id, value.instant_value
            FROM public.alerts AS ticket
            LEFT JOIN app.ticket_sla_instant_sort_values_v1 AS value
              ON value.tenant_id = ticket.tenant_id
             AND value.object_type = 'alert'
             AND value.object_id = ticket.id
             AND value.column_id = ${fixture.column}::uuid
             AND value.column_version = 1
            WHERE ticket.tenant_id = ${fixture.tenant}::uuid
            ORDER BY value.instant_value ASC NULLS LAST, ticket.id ASC
          `;
        assert.equal(sorted.length, 2, "SLA sort changed alert cardinality");
        assert.equal(sorted[0]?.id, fixture.serviceAlert);
        assert(sorted[0]?.instant_value instanceof Date);
        assert.equal(sorted[1]?.instant_value, null);

        const loaded = await sql<
          {
            object_id: string;
            column_id: string;
            column_version: number;
            format: string;
            instant_value: Date | null;
            style_key: string | null;
          }[]
        >`
            SELECT object_id, column_id, column_version, format::text,
                   instant_value, style_key
            FROM app.ticket_sla_materialized_values_v1
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND object_type = 'alert'
              AND object_id = ${fixture.serviceAlert}::uuid
          `;
        assert.deepEqual(loaded[0], {
          object_id: fixture.serviceAlert,
          column_id: fixture.column,
          column_version: 1,
          format: "datetime",
          instant_value: new Date("2026-08-26T13:00:00Z"),
          style_key: "warning",
        });
        const foreignLoaded = await sql`
            SELECT object_id
            FROM app.ticket_sla_materialized_values_v1
            WHERE object_id = ${fixture.foreignAlert}::uuid
          `;
        assert.equal(
          foreignLoaded.length,
          0,
          "SLA loader exposed a foreign materialized value",
        );

        await sql.unsafe("SET LOCAL enable_seqscan = off");
        const alertPlan = await sql<ExplainRow[]>`
            EXPLAIN (COSTS OFF)
            SELECT ticket.id FROM public.alerts AS ticket
            WHERE ticket.tenant_id = ${fixture.tenant}::uuid
            ORDER BY ticket.updated_at DESC, ticket.id DESC LIMIT 50
          `;
        const casePlan = await sql<ExplainRow[]>`
            EXPLAIN (COSTS OFF)
            SELECT ticket.id FROM public.cases AS ticket
            WHERE ticket.tenant_id = ${fixture.tenant}::uuid
            ORDER BY ticket.updated_at DESC, ticket.id DESC LIMIT 50
          `;
        const slaPlan = await sql<ExplainRow[]>`
            EXPLAIN (COSTS OFF)
            SELECT value.object_id
            FROM app.ticket_sla_instant_sort_values_v1 AS value
            WHERE value.tenant_id = ${fixture.tenant}::uuid
              AND value.object_type = 'alert'
              AND value.column_id = ${fixture.column}::uuid
            ORDER BY value.instant_value ASC NULLS LAST,
                     value.object_id ASC
          `;
        const slaDescendingPlan = await sql<ExplainRow[]>`
            EXPLAIN (COSTS OFF)
            SELECT value.object_id
            FROM app.ticket_sla_instant_sort_values_v1 AS value
            WHERE value.tenant_id = ${fixture.tenant}::uuid
              AND value.object_type = 'alert'
              AND value.column_id = ${fixture.column}::uuid
            ORDER BY value.instant_value DESC NULLS FIRST,
                     value.object_id DESC
          `;
        const otherTypedSLAPlans = await Promise.all(
          [
            {
              view: "ticket_sla_duration_sort_values_v1",
              column: "duration_micros_value",
              index: "sla_materialized_projection_duration_sort_idx",
            },
            {
              view: "ticket_sla_percentage_sort_values_v1",
              column: "percentage_value",
              index: "sla_materialized_projection_percent_sort_idx",
            },
            {
              view: "ticket_sla_state_sort_values_v1",
              column: "state_value",
              index: "sla_materialized_projection_state_sort_idx",
            },
          ].map(async (projection) => ({
            index: projection.index,
            plan: await sql.unsafe<ExplainRow[]>(
              `EXPLAIN (COSTS OFF)
               SELECT value.object_id
               FROM app.${projection.view} AS value
               WHERE value.tenant_id = $1::uuid
                 AND value.object_type = 'alert'
                 AND value.column_id = $2::uuid
               ORDER BY value.${projection.column} ASC NULLS LAST,
                        value.object_id ASC`,
              [fixture.tenant, fixture.column],
            ),
          })),
        );
        await sql.unsafe("RESET enable_seqscan");
        assertIndexScanPlan(
          alertPlan,
          "alerts_tenant_updated_idx",
          "alert default order",
        );
        assertIndexScanPlan(
          casePlan,
          "cases_tenant_updated_idx",
          "case default order",
        );
        for (const [direction, plan] of [
          ["ascending", slaPlan],
          ["descending", slaDescendingPlan],
        ] as const) {
          assertIndexScanPlan(
            plan,
            "sla_materialized_projection_instant_sort_idx",
            `${direction} SLA barrier order`,
          );
        }
        for (const { index, plan } of otherTypedSLAPlans) {
          assertIndexScanPlan(plan, index, "typed SLA barrier order");
        }
      });

      await expectSqlState(
        asApi(
          transaction,
          fixture.tenant,
          fixture.foreignUser,
          async (sql) =>
            sql`SELECT id FROM app.ticket_service_account_attributions_v1`,
        ),
        "42501",
        "non-member read the ticket attribution projection",
      );
      await asWorker(transaction, async (sql) => {
        await expectSqlState(
          sql.savepoint(async (nested) => {
            await nested`
              SELECT * FROM app.ticket_service_account_attributions_v1
            `;
            return {};
          }),
          "42501",
          "worker read the API attribution projection",
        );
        await expectSqlState(
          sql.savepoint(async (nested) => {
            await nested`
              SELECT * FROM app.ticket_sla_materialized_values_v1
            `;
            return {};
          }),
          "42501",
          "worker read the API SLA projection",
        );
      });

      await transaction`
        UPDATE public.tenant_memberships SET status = 'suspended'
        WHERE id = ${fixture.membership}::uuid
      `;
      await expectSqlState(
        asApi(
          transaction,
          fixture.tenant,
          fixture.user,
          async (sql) =>
            sql`SELECT column_id FROM app.ticket_sla_column_revisions_v1`,
        ),
        "42501",
        "suspended membership retained the SLA projection",
      );

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end({ timeout: 5 });
}
