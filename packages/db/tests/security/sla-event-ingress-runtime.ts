import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_SLA_EVENT_INGRESS_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SLA_EVENT_INGRESS_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a05e00-5000-7000-8000-000000000001",
  user: "01a05e00-5000-7000-8000-000000000101",
  membership: "01a05e00-5000-7000-8000-000000000201",
  alert: "01a05e00-5000-7000-8000-000000000301",
  assignedEvent: "01a05e00-5000-7000-8000-000000000402",
  claimedEvent: "01a05e00-5000-7000-8000-000000000403",
  releasedEvent: "01a05e00-5000-7000-8000-000000000404",
  transferredEvent: "01a05e00-5000-7000-8000-000000000405",
  transitionEvent: "01a05e00-5000-7000-8000-000000000406",
  terminalEvent: "01a05e00-5000-7000-8000-000000000407",
  untrustedEvent: "01a05e00-5000-7000-8000-000000000408",
  mismatchedEvent: "01a05e00-5000-7000-8000-000000000409",
  worker: "01a05e00-5000-7000-8000-000000000501",
  competingWorker: "01a05e00-5000-7000-8000-000000000502",
  policy: "01a05e00-5000-7000-8000-000000000601",
  metric: "01a05e00-5000-7000-8000-000000000602",
  request: "01a05e00-5000-7000-8000-000000000701",
  correlation: "01a05e00-5000-7000-8000-000000000702",
} as const;

type Claim = {
  job_id: string;
  tenant_id: string;
  object_type: string;
  object_id: string;
  object_sequence: number;
  source_event_id: string;
  source_digest: Buffer;
  event_key: string;
  occurred_at: Date;
  state_mode: string;
  sla_instance_id: string | null;
  aggregate_version: number;
  policy_id: string | null;
  policy_version: number;
  fence: string;
  attempt: number;
  claimed_at: Date;
  lease_expires_at: Date;
  state_document: Record<string, unknown> | null;
};

type Commit = {
  transition: string;
  outcome: string;
  sla_instance_id: string | null;
  aggregate_version: number;
};

type CommentReceipt = {
  comment_id: string;
  result_revision: number;
  replayed: boolean;
};

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`sla-event-ingress-security:${label}`)
    .digest();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

async function asApi<T>(
  transaction: TransactionSql,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe('SET LOCAL ROLE "periapsis_api"');
    await sql`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.user}, true),
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

async function asRuntimeRole<T>(
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

async function claim(
  transaction: TransactionSql,
  workerId: string,
  batchSize = 10,
): Promise<Claim[]> {
  return asWorker(
    transaction,
    (sql) => sql<Claim[]>`
    SELECT * FROM app.claim_sla_object_events_v1(
      ${workerId}::uuid,
      date_trunc('microseconds', clock_timestamp()),
      ${batchSize}, 60000000
    )
  `,
  );
}

const emptyPlan = {
  metrics: [],
  cursors: [],
  occurrences: [],
  columns: [],
  next_evaluation_at: null,
  aggregate_completed_at: null,
} as const;

async function commitNoPolicy(
  transaction: TransactionSql,
  candidate: Claim,
  completedAtExact: string,
): Promise<Commit> {
  const [result] = await asWorker(
    transaction,
    (sql) => sql<Commit[]>`
    SELECT * FROM app.commit_sla_object_event_ingress_v1(
      ${fixture.worker}::uuid, ${candidate.job_id}::uuid,
      ${candidate.tenant_id}::uuid, ${candidate.fence}::bigint,
      ${candidate.source_digest}::bytea, 'no_policy', NULL, 0, 0,
      NULL, 0, ${completedAtExact}::timestamptz,
      ${sql.json(emptyPlan)}::jsonb
    )
  `,
  );
  assert(result, "SLA event commit returned no receipt");
  return result;
}

async function exactDatabaseClock(
  transaction: TransactionSql,
): Promise<string> {
  const [clock] = await transaction<{ observed_at: string }[]>`
    SELECT date_trunc('microseconds', clock_timestamp())::text AS observed_at
  `;
  assert(clock, "database did not return a completion timestamp");
  return clock.observed_at;
}

async function exactLeaseCompletionClock(
  transaction: TransactionSql,
  candidate: Claim,
): Promise<string> {
  const [clock] = await transaction<{ observed_at: string }[]>`
    SELECT (
             date_trunc(
               'milliseconds',
               greatest(clock_timestamp(), ingress.updated_at)
             ) + interval '1 millisecond'
           )::text AS observed_at
    FROM public.sla_object_event_ingress AS ingress
    WHERE ingress.tenant_id = ${candidate.tenant_id}::uuid
      AND ingress.id = ${candidate.job_id}::uuid
  `;
  assert(clock, "leased event did not expose a completion timestamp");
  return clock.observed_at;
}

const database = postgres(databaseUrl, {
  max: 1,
  onnotice: () => undefined,
});
const rollbackMarker = new Error("intentional SLA event ingress rollback");

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
      const [clock] = await transaction<{ now: Date }[]>`
        SELECT date_trunc('microseconds', transaction_timestamp()) AS now
      `;
      assert(clock, "database clock was unavailable");
      const createdAt = new Date(clock.now.getTime() - 2_000);

      await transaction`
        INSERT INTO public.tenants (id, slug, name, timezone) VALUES (
          ${fixture.tenant}::uuid, 'sla-event-ingress-proof',
          'SLA event ingress proof', 'Europe/Rome'
        )
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id)
        VALUES (${fixture.tenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active) VALUES (
          ${fixture.user}::uuid, 'sla-event-ingress@example.invalid',
          'SLA event ingress proof', true
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
        INSERT INTO public.tenant_user_profiles (
          tenant_id, membership_id, user_id, display_name, email
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.membership}::uuid,
          ${fixture.user}::uuid, 'SLA event ingress proof',
          'sla-event-ingress@example.invalid'
        )
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.tenant}::uuid, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        SELECT set_config('app.tenant_id',${fixture.tenant},true),
               set_config('app.user_id',${fixture.user},true),
               set_config('app.service_account_id','',true)
      `;
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          customer_visible, title, source, severity, priority, category,
          created_by, created_by_membership_id, version, created_at, updated_at
        )
        SELECT ${fixture.alert}::uuid, ${fixture.tenant}::uuid,
               'ALT-2026-510001', workflow.id, workflow.current_version,
               'new', true, 'Frozen no-policy ingress proof', 'manual',
               'high', 'high', 'incident', ${fixture.user}::uuid,
               ${fixture.membership}::uuid, 1, ${createdAt}, ${createdAt}
        FROM public.ticket_workflows AS workflow
        WHERE workflow.tenant_id = ${fixture.tenant}::uuid
          AND workflow.key = 'default_alert'
      `;

      const createSources = await transaction<
        { id: string; occurred_at: Date }[]
      >`
        SELECT source.id, source.occurred_at
        FROM public.outbox_events AS source
        WHERE source.tenant_id = ${fixture.tenant}::uuid
          AND source.aggregate_type = 'alert'
          AND source.aggregate_id = ${fixture.alert}::uuid
          AND source.event_type = 'sla.alert.created'
        ORDER BY source.id
      `;
      assert.equal(
        createSources.length,
        1,
        "alert creation did not emit exactly one production SLA source event",
      );
      const createSource = createSources[0];
      assert(createSource, "alert creation omitted its SLA source event");

      // The source delivery envelope is mutable, but its semantic attestation
      // is not. Claiming after this update proves delivery fields are excluded.
      await transaction`
        UPDATE public.outbox_events SET attempts = attempts + 1
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${createSource.id}::uuid
      `;

      // Activate a matching policy only after creation. The initial claim must
      // still see the empty snapshot frozen by the source transaction.
      await transaction`
        INSERT INTO public.sla_policies (
          id, tenant_id, key, active_version, resource_version,
          created_by_membership_id, updated_by_membership_id
        ) VALUES (
          ${fixture.policy}::uuid, ${fixture.tenant}::uuid,
          'too-late-policy', 1, 1,
          ${fixture.membership}::uuid, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.sla_policy_versions (
          tenant_id, policy_id, version, name, description, priority,
          object_types, match_rule, effective_from, enabled,
          apply_to_sla_engine_source, revision_digest,
          created_by_membership_id
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.policy}::uuid, 1,
          'Too late policy', '', 100, ARRAY['alert']::public.sla_object_type[],
          '{}'::jsonb, ${new Date(createdAt.getTime() - 1_000)}, true, false,
          ${digest("late-policy")}::bytea, ${fixture.membership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.sla_metric_definitions (
          tenant_id, policy_id, policy_version, id, key, label, description,
          duration_micros, clock, start_event, completion_event,
          reset_policy, warning_kind, breach_grace_micros, display_format,
          customer_visible, api_visible, position, definition_digest
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.policy}::uuid, 1,
          ${fixture.metric}::uuid, 'late-response', 'Late response', '',
          60000000, 'elapsed', 'ticket.claimed', 'ticket.transferred',
          'ignore', 'none', 0, 'duration', false, true, 0,
          ${digest("late-metric")}::bytea
        )
      `;

      const appendCanonicalAssignmentSource = async (
        action: "assigned" | "claimed" | "released" | "transferred",
        nextVersion: number,
        eventId: string,
      ): Promise<void> => {
        const occurredAt = await exactDatabaseClock(transaction);
        const updated = await transaction<{ version: number }[]>`
          UPDATE public.alerts
          SET version = ${nextVersion},
              updated_at = ${occurredAt}::timestamptz
          WHERE tenant_id = ${fixture.tenant}::uuid
            AND id = ${fixture.alert}::uuid
            AND version = ${nextVersion - 1}
          RETURNING version
        `;
        assert.equal(
          updated[0]?.version,
          nextVersion,
          `failed to advance the ${action} source projection`,
        );
        await transaction`
          INSERT INTO public.outbox_events (
            id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
            event_type, schema_version, payload, deduplication_key,
            correlation_id, causation_id, actor_kind, actor_id, producer,
            maximum_audience, occurred_at, available_at
          ) VALUES (
            ${eventId}::uuid, ${fixture.tenant}::uuid,
            'alert', ${fixture.alert}::uuid, ${nextVersion}::integer,
            ${`sla.alert.${action}`}::text, 1,
            jsonb_build_object(
              'alert_id', ${fixture.alert}::uuid,
              'version', ${nextVersion}::integer,
              'action', ${action}::text
            ), ${`sla:event-ingress:${action}`}::text,
            ${fixture.correlation}::uuid, ${fixture.request}::uuid,
            'human', ${fixture.user}::uuid, 'ticketing', 'operator',
            ${occurredAt}::timestamptz, ${occurredAt}::timestamptz
          )
        `;
      };

      await appendCanonicalAssignmentSource(
        "assigned",
        2,
        fixture.assignedEvent,
      );
      await appendCanonicalAssignmentSource("claimed", 3, fixture.claimedEvent);
      await appendCanonicalAssignmentSource(
        "released",
        4,
        fixture.releasedEvent,
      );
      await appendCanonicalAssignmentSource(
        "transferred",
        5,
        fixture.transferredEvent,
      );

      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            INSERT INTO public.outbox_events (
              id, tenant_id, aggregate_type, aggregate_id,
              aggregate_version, event_type, schema_version, payload,
              deduplication_key, occurred_at, available_at
            ) VALUES (
              ${fixture.mismatchedEvent}::uuid, ${fixture.tenant}::uuid,
              'alert', ${fixture.alert}::uuid, 5,
              'sla.alert.assigned', 1,
              jsonb_build_object(
                'alert_id', ${fixture.alert}::uuid,
                'version', 5, 'action', 'claimed'
              ), 'sla:event-ingress:mismatched-action',
              date_trunc('microseconds', clock_timestamp()),
              date_trunc('microseconds', clock_timestamp())
            )
          `;
          return {};
        }),
        "22023",
        "an assignment source with a mismatched action entered the stream",
      );

      await transaction`
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          occurred_at, available_at
        ) VALUES (
          ${fixture.untrustedEvent}::uuid, ${fixture.tenant}::uuid,
          'alert', ${fixture.alert}::uuid, 5,
          'sla.alert.custom_metric', 1,
          jsonb_build_object(
            'alert_id', ${fixture.alert}::uuid, 'version', 5,
            'event_key', 'ticket.injected'
          ), 'sla:event-ingress:untrusted-key',
          date_trunc('microseconds', clock_timestamp()),
          date_trunc('microseconds', clock_timestamp())
        )
      `;
      const [untrustedIngress] = await transaction<{ count: number }[]>`
        SELECT count(*)::int AS count
        FROM public.sla_object_event_ingress
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND source_event_id = ${fixture.untrustedEvent}::uuid
      `;
      assert.equal(
        untrustedIngress?.count,
        0,
        "an untrusted payload event key entered the SLA stream",
      );

      const transitionAt = await exactDatabaseClock(transaction);

      await transaction`
        UPDATE public.alerts
        SET state_key = 'in_progress', version = 6,
            updated_at = ${transitionAt}::timestamptz
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.alert}::uuid AND version = 5
      `;
      await transaction`
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          correlation_id, causation_id, actor_kind, actor_id, producer,
          maximum_audience, occurred_at, available_at
        ) VALUES (
          ${fixture.transitionEvent}::uuid, ${fixture.tenant}::uuid,
          'alert', ${fixture.alert}::uuid, 6,
          'sla.alert.transitioned', 1,
          jsonb_build_object(
            'alert_id', ${fixture.alert}::uuid,
            'version', 6, 'action', 'transitioned'
          ), 'sla:event-ingress:transition', ${fixture.correlation}::uuid,
          ${fixture.request}::uuid, 'human', ${fixture.user}::uuid,
          'ticketing', 'operator',
          ${transitionAt}::timestamptz, ${transitionAt}::timestamptz
        )
      `;

      const [publicComment] = await asApi(
        transaction,
        (sql) => sql<CommentReceipt[]>`
          SELECT comment_id, result_revision, replayed
          FROM app.create_tenant_ticket_comment_v2(
            'alert', ${fixture.alert}::uuid, 'public',
            'Operator response', '<p>Operator response</p>',
            ARRAY[]::uuid[], ARRAY[]::uuid[],
            ${digest("public-comment-key")}::bytea,
            ${digest("public-comment-request")}::bytea,
            ${fixture.request}::uuid, ${fixture.correlation}::uuid,
            '127.0.0.1'::inet, 'sla-event-ingress-security', 'totp'
          )
        `,
      );
      assert(publicComment, "public comment creation returned no receipt");
      assert.equal(publicComment.result_revision, 1);
      assert.equal(publicComment.replayed, false);

      await asApi(transaction, async (sql) => {
        await sql`
          SELECT * FROM app.create_tenant_ticket_comment_v2(
            'alert', ${fixture.alert}::uuid, 'private',
            'Private operator note', '<p>Private operator note</p>',
            ARRAY[]::uuid[], ARRAY[]::uuid[],
            ${digest("private-comment-key")}::bytea,
            ${digest("private-comment-request")}::bytea,
            ${fixture.request}::uuid, ${fixture.correlation}::uuid,
            '127.0.0.1'::inet, 'sla-event-ingress-security', 'totp'
          )
        `;
      });

      const [commentEvent] = await transaction<
        { source_event_id: string; occurred_at: Date }[]
      >`
        SELECT ingress.source_event_id, ingress.occurred_at
        FROM public.sla_object_event_ingress AS ingress
        WHERE ingress.tenant_id = ${fixture.tenant}::uuid
          AND ingress.object_type = 'alert'
          AND ingress.object_id = ${fixture.alert}::uuid
          AND ingress.event_key = 'response.first'
      `;
      assert(commentEvent, "public operator comment did not enqueue SLA work");

      const terminalAt = new Date(commentEvent.occurred_at.getTime() + 1);
      await transaction`
        UPDATE public.alerts
        SET state_key = 'closed', version = 8, updated_at = ${terminalAt}
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.alert}::uuid AND version = 7
      `;
      await transaction`
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          correlation_id, causation_id, actor_kind, actor_id, producer,
          maximum_audience, occurred_at, available_at
        ) VALUES (
          ${fixture.terminalEvent}::uuid, ${fixture.tenant}::uuid,
          'alert', ${fixture.alert}::uuid, 8,
          'sla.alert.transitioned', 1,
          jsonb_build_object(
            'alert_id', ${fixture.alert}::uuid,
            'version', 8, 'action', 'transitioned'
          ), 'sla:event-ingress:terminal', ${fixture.correlation}::uuid,
          ${fixture.request}::uuid, 'human', ${fixture.user}::uuid,
          'ticketing', 'operator', ${terminalAt}, ${terminalAt}
        )
      `;

      const eventRows = await transaction<
        {
          object_sequence: number;
          event_key: string;
          source_event_type: string;
          assignment_snapshot: Record<string, unknown> | null;
        }[]
      >`
        SELECT object_sequence, event_key, source_event_type,
               assignment_snapshot
        FROM public.sla_object_event_ingress
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND object_type = 'alert' AND object_id = ${fixture.alert}::uuid
        ORDER BY object_sequence
      `;
      assert.deepEqual(
        eventRows.map((row) => [row.object_sequence, row.event_key]),
        [
          [1, "ticket.created"],
          [2, "ticket.assigned"],
          [3, "ticket.claimed"],
          [4, "ticket.released"],
          [5, "ticket.transferred"],
          [6, "ticket.in_progress"],
          [7, "response.first"],
          [8, "ticket.resolved"],
        ],
        "ticket source events were not mapped into one ordered stream",
      );
      assert.deepEqual(
        eventRows.slice(1, 5).map((row) => row.source_event_type),
        [
          "sla.alert.assigned",
          "sla.alert.claimed",
          "sla.alert.released",
          "sla.alert.transferred",
        ],
        "canonical assignment sources lost their production event identity",
      );
      const snapshot = eventRows[0]?.assignment_snapshot;
      assert(
        isRecord(snapshot),
        "creation event did not freeze an assignment snapshot",
      );
      assert(isRecord(snapshot.facts), "snapshot facts are malformed");
      assert.equal(snapshot.facts.timezone, "Europe/Rome");
      assert.deepEqual(snapshot.policies, []);
      assert.deepEqual(snapshot.calendars, []);
      assert.deepEqual(snapshot.columns, []);
      const [latePolicies] = await transaction<{ count: number }[]>`
        SELECT count(*)::int AS count FROM public.sla_policies
        WHERE tenant_id = ${fixture.tenant}::uuid
      `;
      assert.equal(
        latePolicies?.count,
        1,
        "late policy fixture was not active at claim time",
      );

      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            UPDATE public.sla_object_event_ingress
            SET event_key = 'ticket.tampered'
            WHERE tenant_id = ${fixture.tenant}::uuid
              AND source_event_id = ${createSource.id}::uuid
          `;
          return {};
        }),
        "55000",
        "immutable ingress source accepted an event-key rewrite",
      );

      const firstClaims = await claim(transaction, fixture.worker);
      assert.equal(firstClaims.length, 1);
      const first = firstClaims[0];
      assert(first, "creation event was not claimable");
      assert.equal(first.object_sequence, 1);
      assert.equal(first.state_mode, "unassigned");
      assert(first.state_document, "initial claim omitted its frozen state");
      assert.deepEqual(
        first.state_document.policies,
        [],
        "claim consulted the policy activated after ticket creation",
      );
      assert.equal(
        (await claim(transaction, fixture.competingWorker)).length,
        0,
        "a later event bypassed its leased predecessor",
      );
      const firstCompletedAt = await exactLeaseCompletionClock(
        transaction,
        first,
      );

      const [leaseProof] = await transaction<
        {
          status_matches: boolean;
          worker_matches: boolean;
          fence_matches: boolean;
          source_matches: boolean;
          completion_in_lease: boolean;
        }[]
      >`
        SELECT ingress.status = 'leased' AS status_matches,
               ingress.worker_id = ${fixture.worker}::uuid AS worker_matches,
               ingress.fence = ${first.fence}::bigint AS fence_matches,
               ingress.source_digest = ${first.source_digest}::bytea
                 AS source_matches,
               ${firstCompletedAt}::timestamptz
                 BETWEEN ingress.updated_at AND ingress.lease_expires_at
                 AS completion_in_lease
        FROM public.sla_object_event_ingress AS ingress
        WHERE ingress.tenant_id = ${first.tenant_id}::uuid
          AND ingress.id = ${first.job_id}::uuid
      `;
      assert(leaseProof, "claimed SLA event lease row is unavailable");
      assert.equal(leaseProof.status_matches, true, "claimed status was lost");
      assert.equal(
        leaseProof.worker_matches,
        true,
        "claim worker token changed",
      );
      assert.equal(leaseProof.fence_matches, true, "claim fence token changed");
      assert.equal(
        leaseProof.source_matches,
        true,
        "claim source digest token changed",
      );
      assert.equal(
        leaseProof.completion_in_lease,
        true,
        "claim completion timestamp is outside its lease",
      );

      const firstCommit = await commitNoPolicy(
        transaction,
        first,
        firstCompletedAt,
      );
      assert.deepEqual(firstCommit, {
        transition: "applied",
        outcome: "no_policy",
        sla_instance_id: null,
        aggregate_version: 0,
      });
      const replay = await commitNoPolicy(transaction, first, firstCompletedAt);
      assert.equal(replay.transition, "replayed");

      for (const [sequence, eventKey] of [
        [2, "ticket.assigned"],
        [3, "ticket.claimed"],
        [4, "ticket.released"],
        [5, "ticket.transferred"],
        [6, "ticket.in_progress"],
        [7, "response.first"],
        [8, "ticket.resolved"],
      ] as const) {
        // eslint-disable-next-line no-await-in-loop -- Ordered claims intentionally share one transactional object stream.
        const candidates = await claim(transaction, fixture.worker);
        assert.equal(candidates.length, 1);
        const candidate = candidates[0];
        assert(candidate, `sequence ${sequence} was not claimable`);
        assert.equal(candidate.object_sequence, sequence);
        assert.equal(candidate.event_key, eventKey);
        assert.equal(candidate.state_mode, "no_policy");
        assert.equal(candidate.state_document, null);
        // eslint-disable-next-line no-await-in-loop -- The completion timestamp must be observed after each ordered claim.
        const completedAt = await exactLeaseCompletionClock(
          transaction,
          candidate,
        );
        // eslint-disable-next-line no-await-in-loop -- Each lease token is checked immediately before its fenced commit.
        const [successorLease] = await transaction<
          {
            status_matches: boolean;
            worker_matches: boolean;
            fence_matches: boolean;
            source_matches: boolean;
            completion_after_update: boolean;
            completion_before_expiry: boolean;
            completion_token: string;
            updated_at: string;
            completion_delta_micros: string;
          }[]
        >`
          SELECT ingress.status = 'leased' AS status_matches,
                 ingress.worker_id = ${fixture.worker}::uuid
                   AS worker_matches,
                 ingress.fence = ${candidate.fence}::bigint
                   AS fence_matches,
                 ingress.source_digest = ${candidate.source_digest}::bytea
                   AS source_matches,
                 ${completedAt}::timestamptz >= ingress.updated_at
                   AS completion_after_update,
                 ${completedAt}::timestamptz <= ingress.lease_expires_at
                   AS completion_before_expiry,
                 ${completedAt}::timestamptz::text AS completion_token,
                 ingress.updated_at::text AS updated_at,
                 (
                   extract(epoch FROM (
                     ${completedAt}::timestamptz - ingress.updated_at
                   )) * 1000000
                 )::numeric::text AS completion_delta_micros
          FROM public.sla_object_event_ingress AS ingress
          WHERE ingress.tenant_id = ${candidate.tenant_id}::uuid
            AND ingress.id = ${candidate.job_id}::uuid
        `;
        assert(successorLease, `sequence ${sequence} lease row disappeared`);
        assert.equal(successorLease.status_matches, true);
        assert.equal(successorLease.worker_matches, true);
        assert.equal(successorLease.fence_matches, true);
        assert.equal(successorLease.source_matches, true);
        assert.equal(
          successorLease.completion_after_update,
          true,
          `sequence ${sequence} completion ${successorLease.completion_token} precedes update ${successorLease.updated_at} by ${successorLease.completion_delta_micros}us`,
        );
        assert.equal(successorLease.completion_before_expiry, true);
        // eslint-disable-next-line no-await-in-loop -- Each successor becomes eligible only after its predecessor commits.
        const result = await commitNoPolicy(
          transaction,
          candidate,
          completedAt,
        );
        assert.equal(result.transition, "applied");
        assert.equal(result.outcome, "no_policy");
      }
      assert.equal((await claim(transaction, fixture.worker)).length, 0);

      const [effects] = await transaction<
        {
          completed: number;
          ledgers: number;
          audits: number;
          receipts: number;
          instances: number;
          timers: number;
          occurrences: number;
          actions: number;
        }[]
      >`
        SELECT
          (SELECT count(*)::int FROM public.sla_object_event_ingress
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND object_id = ${fixture.alert}::uuid
             AND status = 'completed') AS completed,
          (SELECT count(*)::int FROM public.sla_object_event_ledger
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND object_id = ${fixture.alert}::uuid
             AND outcome = 'no_policy') AS ledgers,
          (SELECT count(*)::int FROM public.audit_events
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND action = 'tenant.sla.event.ingested'
             AND resource_type = 'sla_object_event_ingress') AS audits,
          (SELECT count(*)::int FROM public.outbox_events
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND event_type = 'sla.object_event.ingested') AS receipts,
          (SELECT count(*)::int FROM public.sla_instances
           WHERE tenant_id = ${fixture.tenant}::uuid
             AND object_type = 'alert'
             AND object_id = ${fixture.alert}::uuid) AS instances,
          (SELECT count(*)::int FROM public.sla_evaluation_jobs AS job
           JOIN public.sla_instances AS instance
             ON instance.tenant_id = job.tenant_id
            AND instance.id = job.sla_instance_id
           WHERE instance.tenant_id = ${fixture.tenant}::uuid
             AND instance.object_id = ${fixture.alert}::uuid) AS timers,
          (SELECT count(*)::int FROM public.sla_trigger_occurrences AS occurrence
           JOIN public.sla_instances AS instance
             ON instance.tenant_id = occurrence.tenant_id
            AND instance.id = occurrence.sla_instance_id
           WHERE instance.tenant_id = ${fixture.tenant}::uuid
             AND instance.object_id = ${fixture.alert}::uuid) AS occurrences,
          (SELECT count(*)::int
           FROM public.sla_trigger_action_executions AS execution
           JOIN public.sla_trigger_occurrences AS occurrence
             ON occurrence.tenant_id = execution.tenant_id
            AND occurrence.id = execution.occurrence_id
           JOIN public.sla_instances AS instance
             ON instance.tenant_id = occurrence.tenant_id
            AND instance.id = occurrence.sla_instance_id
           WHERE instance.tenant_id = ${fixture.tenant}::uuid
             AND instance.object_id = ${fixture.alert}::uuid) AS actions
      `;
      assert.deepEqual(effects, {
        completed: 8,
        ledgers: 8,
        audits: 8,
        receipts: 8,
        instances: 0,
        timers: 0,
        occurrences: 0,
        actions: 0,
      });

      const [readiness] = await asWorker(
        transaction,
        (sql) => sql<{ ready: boolean }[]>`
          SELECT app.sla_object_event_ingress_schema_readiness_v58() AS ready
        `,
      );
      assert.equal(readiness?.ready, true);
      const [ledgerAcl] = await transaction<
        {
          table_insert_denied: boolean;
          required_insert_granted: boolean;
          extra_insert_denied: boolean;
        }[]
      >`
        SELECT
          NOT has_table_privilege(
            'periapsis_sla_worker_owner',
            'public.sla_object_event_ledger', 'INSERT'
          ) AS table_insert_denied,
          (
            SELECT bool_and(has_column_privilege(
              'periapsis_sla_worker_owner',
              'public.sla_object_event_ledger', required.column_name,
              'INSERT'
            ))
            FROM unnest(ARRAY[
              'tenant_id', 'event_id', 'object_type', 'object_id', 'origin',
              'origin_id', 'key_digest', 'request_digest', 'outcome',
              'sla_instance_id', 'aggregate_version', 'policy_id',
              'policy_version', 'occurred_at', 'committed_at'
            ]) AS required(column_name)
          ) AS required_insert_granted,
          NOT EXISTS (
            SELECT 1 FROM pg_attribute AS attribute
            WHERE attribute.attrelid =
                    'public.sla_object_event_ledger'::regclass
              AND attribute.attnum > 0 AND NOT attribute.attisdropped
              AND NOT (attribute.attname = ANY(ARRAY[
                'tenant_id', 'event_id', 'object_type', 'object_id', 'origin',
                'origin_id', 'key_digest', 'request_digest', 'outcome',
                'sla_instance_id', 'aggregate_version', 'policy_id',
                'policy_version', 'occurred_at', 'committed_at'
              ]))
              AND has_column_privilege(
                'periapsis_sla_worker_owner',
                'public.sla_object_event_ledger', attribute.attname,
                'INSERT'
              )
          ) AS extra_insert_denied
      `;
      assert.deepEqual(ledgerAcl, {
        table_insert_denied: true,
        required_insert_granted: true,
        extra_insert_denied: true,
      });
      for (const directRead of [
        () =>
          asApi(transaction, async (sql) => {
            await sql`SELECT count(*) FROM public.sla_object_event_ingress`;
          }),
        () =>
          asWorker(transaction, async (sql) => {
            await sql`SELECT count(*) FROM public.sla_object_event_ingress`;
          }),
        () =>
          asRuntimeRole(transaction, "periapsis_notifier", async (sql) => {
            await sql`SELECT count(*) FROM public.sla_object_event_ingress`;
          }),
        () =>
          asRuntimeRole(transaction, "periapsis_auditor", async (sql) => {
            await sql`SELECT count(*) FROM public.sla_object_event_ingress`;
          }),
      ]) {
        // eslint-disable-next-line no-await-in-loop -- Role savepoints share one transaction and must be serialized.
        await expectSqlState(
          directRead(),
          "42501",
          "a runtime role received direct SLA ingress table authority",
        );
      }
      await expectSqlState(
        asApi(transaction, async (sql) => {
          await sql`
            SELECT * FROM app.claim_sla_object_events_v1(
              ${fixture.worker}::uuid, clock_timestamp(), 1, 60000000
            )
          `;
        }),
        "42501",
        "the API runtime executed the SLA ingress worker claim ABI",
      );

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end();
}
