import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonObject = { [key: string]: postgres.JSONValue };

const databaseUrl =
  process.env.PERIAPSIS_TICKET_BULK_EXPORT_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_BULK_EXPORT_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a0b100-0000-7000-8000-000000000001",
  foreignTenant: "01a0b100-0000-7000-8000-000000000002",
  user: "01a0b100-0000-7000-8000-000000000101",
  foreignUser: "01a0b100-0000-7000-8000-000000000102",
  membership: "01a0b100-0000-7000-8000-000000000201",
  foreignMembership: "01a0b100-0000-7000-8000-000000000202",
  session: "01a0b100-0000-7000-8000-000000000301",
  sessionFamily: "01a0b100-0000-7000-8000-000000000302",
  alert: "01a0b100-0000-7000-8000-000000000401",
  bulkJob: "01a0b100-0000-7000-8000-000000000501",
  exportJob: "01a0b100-0000-7000-8000-000000000502",
  exportArtifact: "01a0b100-0000-7000-8000-000000000503",
  worker: "01a0b100-0000-7000-8000-000000000601",
  otherWorker: "01a0b100-0000-7000-8000-000000000602",
  ticketRuntimePrincipal: "01890f00-0000-7000-8000-0000000000f1",
  request: "01a0b100-0000-7000-8000-000000000701",
  correlation: "01a0b100-0000-7000-8000-000000000702",
  operatorTeam: "01a0b100-0000-7000-8000-000000000801",
  operatorTeamEpoch: "01a0b100-0000-7000-8000-000000000802",
  operatorTeamRoster: "01a0b100-0000-7000-8000-000000000803",
} as const;

function digest(label: string): string {
  return createHash("sha256")
    .update(`ticket-bulk-export-security:${label}`)
    .digest("hex");
}

function isJsonObject(
  value: postgres.JSONValue | undefined,
): value is JsonObject {
  return (
    value !== null &&
    value !== undefined &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

function asObject(
  value: postgres.JSONValue | undefined,
  message: string,
): JsonObject {
  assert(isJsonObject(value), message);
  return value;
}

function asArray(
  value: postgres.JSONValue | undefined,
  message: string,
): postgres.JSONValue[] {
  assert(Array.isArray(value), message);
  return value;
}

function asString(
  value: postgres.JSONValue | undefined,
  message: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(message);
  }
  return value;
}

function asNumber(
  value: postgres.JSONValue | undefined,
  message: string,
): number {
  if (typeof value !== "number") {
    throw new TypeError(message);
  }
  return value;
}

function requiredJson(
  value: postgres.JSONValue | undefined,
  message: string,
): postgres.JSONValue {
  if (value === undefined) {
    throw new TypeError(message);
  }
  return value;
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
             set_config('app.tracestate', 'ticket-runtime=security', true)
    `;
    return operation(sql);
  });
}

const actor: JsonObject = {
  userId: fixture.user,
  sessionId: fixture.session,
  activeTenantId: fixture.tenant,
  authenticationMethod: "totp",
};

const audit: JsonObject = {
  requestId: fixture.request,
  correlationId: fixture.correlation,
  remoteAddress: "127.0.0.1",
  userAgent: "ticket-bulk-export-security",
};

const workerIdentity = (
  purpose: "ticket_bulk" | "ticket_export",
): JsonObject => ({
  serviceAccountId: fixture.ticketRuntimePrincipal,
  workerId: fixture.worker,
  purpose,
});

function savedViewResolveSpec(): JsonObject {
  return {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    actorId: fixture.user,
    ownerMembershipId: fixture.membership,
    aggregateKind: "alert",
    filters: {
      states: [],
      severities: [],
      priorities: [],
      assignedTeamId: "",
      assigneeUserId: "",
      claimedBy: "",
      queue: "all",
      customerVisible: null,
      search: "",
      custom: [],
    },
    sort: {
      source: "core",
      coreKey: "updated_at",
      definitionId: "",
      expectedDefinitionVersion: 0,
      direction: "desc",
      nulls: "last",
    },
    columns: [
      {
        source: "core",
        coreKey: "ticket",
        definitionId: "",
        expectedDefinitionVersion: 0,
        width: 0,
        visible: true,
        pin: "none",
      },
    ],
  };
}

async function callApi(
  sql: TransactionSql,
  functionName:
    | "commit_ticket_bulk_request_v1"
    | "commit_ticket_bulk_cancellation_v1"
    | "get_ticket_bulk_v1"
    | "resolve_ticket_export_query_v2"
    | "commit_ticket_export_request_v2"
    | "commit_ticket_export_owner_transition_v2"
    | "get_ticket_export_v2",
  request: JsonObject,
): Promise<JsonObject | undefined> {
  const [row] = await sql<{ response: JsonObject }[]>`
    SELECT response
    FROM ${sql(`app.${functionName}`)}(${sql.json(request)}::jsonb)
  `;
  return row?.response;
}

const database = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const rollbackMarker = new Error(
  "intentional ticket runtime security rollback",
);

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '30s'");
      await transaction`
        INSERT INTO public.tenants (id, slug, name) VALUES
          (${fixture.tenant}::uuid, 'ticket-runtime-security',
           'Ticket runtime security'),
          (${fixture.foreignTenant}::uuid, 'ticket-runtime-security-foreign',
           'Ticket runtime security foreign')
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id) VALUES
          (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active) VALUES
          (${fixture.user}::uuid, 'ticket-runtime@example.invalid',
           'Ticket runtime operator', true),
          (${fixture.foreignUser}::uuid, 'ticket-runtime-foreign@example.invalid',
           'Ticket runtime foreign', true)
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
           ${fixture.user}::uuid, 'Ticket runtime operator',
           'ticket-runtime@example.invalid'),
          (${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid,
           ${fixture.foreignUser}::uuid, 'Ticket runtime foreign',
           'ticket-runtime-foreign@example.invalid')
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
      const [sessionWindow] = await transaction<{ now: Date; expires: Date }[]>`
        SELECT transaction_timestamp() - interval '1 second' AS now,
               transaction_timestamp() + interval '1 hour' AS expires
      `;
      assert(sessionWindow, "database session window is missing");
      const { now, expires } = sessionWindow;
      await transaction`
        INSERT INTO public.auth_sessions (
          id, user_id, rotation_family_id, active_tenant_id,
          token_digest, csrf_secret_digest, authentication_method,
          mfa_satisfied_at, last_seen_at, idle_expires_at,
          absolute_expires_at, created_at
        ) VALUES (
          ${fixture.session}::uuid, ${fixture.user}::uuid,
          ${fixture.sessionFamily}::uuid, ${fixture.tenant}::uuid,
          ${Buffer.from(digest("session-token"), "hex")}::bytea,
          ${Buffer.from(digest("session-csrf"), "hex")}::bytea,
          'totp', ${now}, ${now}, ${expires}, ${expires}, ${now}
        )
      `;
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.user}, true),
               set_config('app.service_account_id', '', true)
      `;
      await transaction`
        INSERT INTO public.operator_teams (
          id, key, display_name, description, created_by_user_id
        ) VALUES (
          ${fixture.operatorTeam}::uuid, 'ticket_runtime_security_team',
          'Ticket runtime security team',
          'Live bulk notification routing proof.', ${fixture.user}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.operator_team_assignment_epochs (
          id, tenant_id, operator_team_id, assigned_by_membership_id,
          assignment_reason, assigned_at
        ) VALUES (
          ${fixture.operatorTeamEpoch}::uuid, ${fixture.tenant}::uuid,
          ${fixture.operatorTeam}::uuid, ${fixture.membership}::uuid,
          'Live bulk notification routing proof.', ${now}
        )
      `;
      await transaction`
        INSERT INTO public.operator_team_roster_entries (
          id, tenant_id, assignment_epoch_id, membership_id, source_id,
          granted_by_membership_id, grant_reason, granted_at
        )
        SELECT ${fixture.operatorTeamRoster}::uuid, ${fixture.tenant}::uuid,
               ${fixture.operatorTeamEpoch}::uuid, ${fixture.membership}::uuid,
               source.id, ${fixture.membership}::uuid,
               'Live bulk notification routing proof.', ${now}
        FROM public.tenant_authorization_sources AS source
        WHERE source.tenant_id=${fixture.tenant}::uuid
          AND source.key='manual' AND source.kind='manual'
          AND source.retired_at IS NULL
      `;
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          customer_visible, title, description,
          assigned_team_id, assigned_team_epoch_id, assignee_user_id,
          created_by, created_by_membership_id
        )
        SELECT ${fixture.alert}::uuid, ${fixture.tenant}::uuid,
               'ALT-2026-820001', workflow.id, workflow.current_version,
               'new', true, 'Private bulk/export title',
               'must-never-escape-ticket-runtime-secret',
               ${fixture.operatorTeam}::uuid,
               ${fixture.operatorTeamEpoch}::uuid, ${fixture.user}::uuid,
               ${fixture.user}::uuid, ${fixture.membership}::uuid
        FROM public.ticket_workflows AS workflow
        WHERE workflow.tenant_id = ${fixture.tenant}::uuid
          AND workflow.key = 'default_alert'
      `;

      for (const role of ["periapsis_api", "periapsis_worker"] as const) {
        // eslint-disable-next-line no-await-in-loop -- Role savepoints share one transaction and must be serialized.
        const [readiness] = await asRole(
          transaction,
          role,
          (sql) =>
            sql<{ bulk: boolean; export: boolean }[]>`
            SELECT app.ticket_bulk_runtime_schema_readiness_v52() AS bulk,
                   app.ticket_export_runtime_schema_readiness_v52() AS export
          `,
        );
        assert.deepEqual(readiness, { bulk: true, export: true });
      }
      for (const role of [
        "periapsis_api",
        "periapsis_worker",
        "periapsis_notifier",
        "periapsis_auditor",
      ] as const) {
        for (const tableName of [
          "ticket_bulk_jobs",
          "ticket_export_jobs",
        ] as const) {
          // eslint-disable-next-line no-await-in-loop -- Role savepoints share one transaction and must be serialized.
          await expectSqlState(
            asRole(transaction, role, async (sql) => {
              await sql.unsafe(`SELECT id FROM public.${tableName} LIMIT 1`);
            }),
            "42501",
            `${role} retained direct ${tableName} access`,
          );
        }
      }
      await expectSqlState(
        asRole(transaction, "periapsis_auditor", async (sql) => {
          await sql`SELECT app.ticket_bulk_runtime_schema_readiness_v52()`;
        }),
        "42501",
        "auditor executed ticket runtime readiness",
      );

      const requestedAt = now.toISOString();
      const expiresAt = expires.toISOString();
      const bulkRequest: JsonObject = {
        schemaVersion: 1,
        actor,
        audit,
        tenantId: fixture.tenant,
        ownerMembershipId: fixture.membership,
        kind: "alert",
        requiredCapability: "ticket.bulk.request",
        jobId: fixture.bulkJob,
        explicitTargets: [{ id: fixture.alert, version: 1 }],
        query: null,
        mutation: {
          action: "transition",
          transition: "start_investigation",
          to: "in_progress",
          teamId: "",
          assigneeId: "",
        },
        requestedAt,
        expiresAt,
        action: "request",
        idempotencyKeySha256: digest("bulk-key"),
        requestFingerprintSha256: digest("bulk-fingerprint"),
      };
      const bulk = await asApi(transaction, (sql) =>
        callApi(sql, "commit_ticket_bulk_request_v1", bulkRequest),
      );
      assert(bulk, "bulk request returned no row");
      assert.equal(bulk.replayed, false);
      const bulkRecord = asObject(bulk.record, "bulk record is missing");
      const bulkJob = asObject(bulkRecord.job, "bulk job is missing");
      assert.equal(bulkJob.state, "pending");

      const bulkReplay = await asApi(transaction, (sql) =>
        callApi(sql, "commit_ticket_bulk_request_v1", bulkRequest),
      );
      assert.equal(bulkReplay?.replayed, true);
      await expectSqlState(
        asApi(transaction, (sql) =>
          callApi(sql, "commit_ticket_bulk_request_v1", {
            ...bulkRequest,
            requestFingerprintSha256: digest("bulk-divergent"),
          }),
        ),
        "23505",
        "bulk idempotency key accepted a divergent payload",
      );

      const resolved = await asApi(transaction, (sql) =>
        callApi(sql, "resolve_ticket_export_query_v2", {
          schemaVersion: 1,
          actor,
          tenantId: fixture.tenant,
          ownerMembershipId: fixture.membership,
          kind: "alert",
          audience: "operator",
          source: { mode: "inline", spec: savedViewResolveSpec() },
        }),
      );
      const query = asObject(resolved?.query, "export query was not resolved");
      const exportDefinition: JsonObject = {
        id: fixture.exportJob,
        tenantId: fixture.tenant,
        requesterId: fixture.user,
        ownerMembershipId: fixture.membership,
        customerContactId: "",
        kind: "alert",
        audience: "operator",
        commentScope: "public_and_private",
        querySource: "inline",
        savedView: null,
        querySha256: requiredJson(query.querySha256, "query digest is missing"),
        catalogSha256: requiredJson(
          query.catalogSha256,
          "catalog digest is missing",
        ),
        projectionVersion: 1,
        format: "csv",
        maximumRows: 100,
        maximumBytes: 1_048_576,
        maximumAttempts: 3,
      };
      const exportJobProjection: JsonObject = {
        definition: exportDefinition,
        state: "pending",
        revision: 1,
        attempts: 0,
        failureCode: "none",
        requestedAt,
        updatedAt: requestedAt,
        availableAt: requestedAt,
        expiresAt,
        lease: null,
        artifact: null,
        terminalAt: null,
      };
      const exportRequest: JsonObject = {
        schemaVersion: 1,
        actor,
        audit,
        requiredCapability: "ticket_export.request",
        expectedRevision: 0,
        next: exportJobProjection,
        query,
        action: "request",
        idempotencyKeySha256: digest("export-key"),
        requestFingerprintSha256: digest("export-fingerprint"),
      };
      const exported = await asApi(transaction, (sql) =>
        callApi(sql, "commit_ticket_export_request_v2", exportRequest),
      );
      assert(exported, "export request returned no row");
      assert.equal(exported.replayed, false);
      const exportRecord = asObject(
        exported.record,
        "export record is missing",
      );
      const exportJob = asObject(exportRecord.job, "export job is missing");
      assert.equal(exportJob.state, "pending");

      const exportReplay = await asApi(transaction, (sql) =>
        callApi(sql, "commit_ticket_export_request_v2", exportRequest),
      );
      assert.equal(exportReplay?.replayed, true);
      await expectSqlState(
        asApi(transaction, (sql) =>
          callApi(sql, "commit_ticket_export_request_v2", {
            ...exportRequest,
            requestFingerprintSha256: digest("export-divergent"),
          }),
        ),
        "23505",
        "export idempotency key accepted a divergent payload",
      );

      const staleAt = new Date(now.getTime() + 1_000).toISOString();
      await expectSqlState(
        asApi(transaction, (sql) =>
          callApi(sql, "commit_ticket_export_owner_transition_v2", {
            schemaVersion: 1,
            actor,
            audit,
            requiredCapability: "ticket_export.cancel",
            expectedRevision: 2,
            next: {
              ...exportJob,
              state: "cancelled",
              revision: 3,
              updatedAt: staleAt,
              terminalAt: staleAt,
            },
            query,
            action: "cancel",
            idempotencyKeySha256: digest("stale-export-cancel-key"),
            requestFingerprintSha256: digest("stale-export-cancel-fingerprint"),
          }),
        ),
        "40001",
        "stale export revision bypassed compare-and-swap",
      );

      await expectSqlState(
        asApi(transaction, (sql) =>
          callApi(sql, "get_ticket_bulk_v1", {
            schemaVersion: 1,
            actor: { ...actor, activeTenantId: fixture.foreignTenant },
            tenantId: fixture.foreignTenant,
            ownerMembershipId: fixture.foreignMembership,
            kind: "alert",
            capability: "ticket.bulk.read",
            jobId: fixture.bulkJob,
          }),
        ),
        "42501",
        "bulk get accepted a cross-tenant actor envelope",
      );
      await expectSqlState(
        asRole(transaction, "periapsis_worker", async (sql) => {
          await sql`
            SELECT * FROM app.commit_ticket_bulk_request_v1(
              ${sql.json(bulkRequest)}::jsonb
            )
          `;
        }),
        "42501",
        "worker executed an API-only bulk command",
      );
      await expectSqlState(
        asApi(transaction, async (sql) => {
          await sql`
            SELECT * FROM app.claim_ticket_export_v2(
              ${sql.json({
                schemaVersion: 1,
                identity: workerIdentity("ticket_export"),
                tenantId: fixture.tenant,
                kind: "alert",
                audience: "operator",
                artifactId: fixture.exportArtifact,
                now: new Date().toISOString(),
                leaseMicroseconds: 30_000_000,
              })}::jsonb
            )
          `;
        }),
        "42501",
        "API executed a worker-only export claim",
      );

      await expectSqlState(
        asRole(transaction, "periapsis_worker", async (sql) => {
          await sql`
            SELECT * FROM app.claim_ticket_bulk_batch_v1(
              ${sql.json({
                schemaVersion: 1,
                identity: {
                  serviceAccountId: fixture.otherWorker,
                  workerId: fixture.worker,
                  purpose: "ticket_bulk",
                },
                tenantId: fixture.tenant,
                kind: "alert",
                now: new Date().toISOString(),
                leaseMicroseconds: 30_000_000,
                limit: 1,
              })}::jsonb
            )
          `;
        }),
        "42501",
        "bulk claim accepted an unknown runtime service principal",
      );

      const [bulkClaimRow] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ response: JsonObject }[]>`
            SELECT response FROM app.claim_ticket_bulk_batch_v1(
              ${sql.json({
                schemaVersion: 1,
                identity: workerIdentity("ticket_bulk"),
                tenantId: fixture.tenant,
                kind: "alert",
                now: new Date().toISOString(),
                leaseMicroseconds: 30_000_000,
                limit: 1,
              })}::jsonb
            )
          `,
      );
      assert(bulkClaimRow, "bulk worker did not receive a claim");
      const bulkBinding = asObject(
        bulkClaimRow.response.binding,
        "bulk binding is missing",
      );
      const [bulkTargetValue] = asArray(
        bulkClaimRow.response.targets,
        "bulk targets are missing",
      );
      const bulkTarget = asObject(bulkTargetValue, "bulk target is invalid");
      const applyBulk = (
        identity: JsonObject,
        binding: JsonObject,
      ): Promise<{ response: JsonObject }[]> =>
        asRole(
          transaction,
          "periapsis_worker",
          (sql) =>
            sql<{ response: JsonObject }[]>`
            SELECT response FROM app.apply_ticket_bulk_target_v2(
              ${sql.json({
                schemaVersion: 1,
                identity,
                binding,
                sequence: bulkTarget.sequence,
                targetId: bulkTarget.id,
                targetVersion: bulkTarget.version,
                action: "transition",
              })}::jsonb
            )
          `,
        );
      await expectSqlState(
        applyBulk(
          {
            serviceAccountId: fixture.ticketRuntimePrincipal,
            workerId: fixture.otherWorker,
            purpose: "ticket_bulk",
          },
          bulkBinding,
        ),
        "42501",
        "bulk apply accepted a worker outside its claim binding",
      );
      const [lostBulk] = await applyBulk(workerIdentity("ticket_bulk"), {
        ...bulkBinding,
        fenceSha256: "0".repeat(64),
      });
      assert.equal(lostBulk?.response.disposition, "fence_lost");
      const [appliedBulk] = await applyBulk(
        workerIdentity("ticket_bulk"),
        bulkBinding,
      );
      assert.equal(appliedBulk?.response.disposition, "applied");
      assert.equal(
        appliedBulk?.response.result,
        "succeeded",
        JSON.stringify(appliedBulk?.response),
      );
      const [replayedBulk] = await applyBulk(
        workerIdentity("ticket_bulk"),
        bulkBinding,
      );
      assert.equal(replayedBulk?.response.disposition, "replayed");

      const notifications = await transaction<
        {
          id: string;
          event_type: string;
          schema_version: number;
          maximum_audience: string;
          actor_kind: string;
          actor_id: string | null;
          producer: string;
          payload: JsonObject;
        }[]
      >`
        SELECT id::text,event_type,schema_version,maximum_audience,
               actor_kind,actor_id::text,producer,payload
        FROM public.outbox_events
        WHERE tenant_id=${fixture.tenant}::uuid
          AND aggregate_id=${fixture.alert}::uuid
          AND event_type='notification.alert.status_changed'
      `;
      assert.equal(
        notifications.length,
        1,
        "bulk notification was not exactly-once",
      );
      const [notification] = notifications;
      assert(
        notification,
        "bulk transition did not append a notification event",
      );
      assert.equal(notification.schema_version, 2);
      assert.equal(notification.maximum_audience, "operator");
      assert.equal(notification.actor_kind, "system");
      assert.equal(notification.actor_id, null);
      assert.equal(notification.producer, "ticket-bulk-worker");
      assert.equal(notification.payload.customerContext, undefined);
      assert(
        !JSON.stringify(notification.payload).includes("must-never-escape"),
        "bulk notification exposed private ticket content",
      );
      const operatorContext = asObject(
        notification.payload.operatorContext,
        "bulk notification operator context is missing",
      );
      const routing = asObject(
        operatorContext.routing,
        "bulk notification routing context is missing",
      );
      assert.equal(routing.assigneeUserId, fixture.user);
      assert.equal(routing.operatorTeamId, fixture.operatorTeam);
      assert.equal(routing.operatorTeamEpochId, fixture.operatorTeamEpoch);

      const [candidate] = await transaction<{ value: JsonObject }[]>`
        SELECT value
        FROM app.private_notification_operator_candidates_v2(
          ${fixture.tenant}::uuid, ${notification.id}::uuid
        )
        WHERE sort_principal=${fixture.user}::uuid
      `;
      assert(candidate, "live assignee/team notification candidate is missing");
      const candidateKinds = asArray(
        candidate.value.kinds,
        "notification candidate kinds are missing",
      );
      assert(candidateKinds.includes("assignee"));
      assert(candidateKinds.includes("operator_team"));
      const candidateValues = asObject(
        candidate.value.values,
        "notification candidate values are missing",
      );
      assert.deepEqual(candidateValues.operator_team, [fixture.operatorTeam]);

      const [exportClaimRow] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ response: JsonObject }[]>`
            SELECT response FROM app.claim_ticket_export_v2(
              ${sql.json({
                schemaVersion: 1,
                identity: workerIdentity("ticket_export"),
                tenantId: fixture.tenant,
                kind: "alert",
                audience: "operator",
                artifactId: fixture.exportArtifact,
                now: new Date().toISOString(),
                leaseMicroseconds: 30_000_000,
              })}::jsonb
            )
          `,
      );
      assert(exportClaimRow, "export worker did not receive a claim");
      const claimedExportJob = asObject(
        exportClaimRow.response.job,
        "claimed export job is missing",
      );
      assert.equal(claimedExportJob.state, "running");
      const lease = asObject(claimedExportJob.lease, "export lease is missing");
      const claimedDefinition = asObject(
        claimedExportJob.definition,
        "claimed export definition is missing",
      );
      const exportBinding: JsonObject = {
        tenantId: fixture.tenant,
        jobId: fixture.exportJob,
        kind: "alert",
        audience: "operator",
        workerId: requiredJson(lease.workerId, "lease worker is missing"),
        revision: requiredJson(
          claimedExportJob.revision,
          "revision is missing",
        ),
        attempt: requiredJson(claimedExportJob.attempts, "attempt is missing"),
        fenceSha256: requiredJson(lease.fenceSha256, "lease fence is missing"),
        querySha256: requiredJson(
          claimedDefinition.querySha256,
          "query digest is missing",
        ),
        catalogSha256: requiredJson(
          claimedDefinition.catalogSha256,
          "catalog digest is missing",
        ),
        projectionVersion: requiredJson(
          claimedDefinition.projectionVersion,
          "projection version is missing",
        ),
        leaseClaimedAt: requiredJson(lease.claimedAt, "claim time is missing"),
        leaseExpiresAt: requiredJson(
          lease.expiresAt,
          "lease expiry is missing",
        ),
        jobExpiresAt: requiredJson(
          claimedExportJob.expiresAt,
          "job expiry is missing",
        ),
      };
      const [fencedPage] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ response: JsonObject }[]>`
            SELECT response FROM app.read_ticket_export_page_v2(
              ${sql.json({
                schemaVersion: 1,
                identity: workerIdentity("ticket_export"),
                binding: { ...exportBinding, fenceSha256: "0".repeat(64) },
                after: "",
                limit: 100,
              })}::jsonb
            )
          `,
      );
      assert.equal(fencedPage?.response.control, "fence_lost");
      assert.deepEqual(fencedPage?.response.rows, []);
      const [page] = await asRole(
        transaction,
        "periapsis_worker",
        (sql) =>
          sql<{ response: JsonObject }[]>`
            SELECT response FROM app.read_ticket_export_page_v2(
              ${sql.json({
                schemaVersion: 1,
                identity: workerIdentity("ticket_export"),
                binding: exportBinding,
                after: "",
                limit: 100,
              })}::jsonb
            )
          `,
      );
      assert.equal(page?.response.control, "ready");
      const exportedRows = asArray(
        page?.response.rows,
        "export page rows are missing",
      );
      assert.equal(exportedRows.length, 1);
      assert(
        !JSON.stringify(exportedRows).includes("must-never-escape"),
        "export page leaked a non-selected private description",
      );

      const [evidence] = await transaction<
        {
          receipts: string;
          audits: string;
          outbox: string;
          redacted: boolean;
          alert_state: string;
          alert_version: number;
        }[]
      >`
        SELECT
          ((SELECT count(*)
            FROM public.ticket_bulk_command_receipts
            WHERE job_id = ${fixture.bulkJob}::uuid)
           + (SELECT count(*)
              FROM public.ticket_export_command_receipts
              WHERE job_id = ${fixture.exportJob}::uuid))::text AS receipts,
          (SELECT count(*)::text FROM public.audit_events
           WHERE resource_id IN (${fixture.bulkJob}::uuid, ${fixture.exportJob}::uuid)
             AND action IN ('ticket.bulk.requested','ticket.export.requested'))
            AS audits,
          (SELECT count(*)::text FROM public.outbox_events
           WHERE aggregate_id IN (${fixture.bulkJob}::uuid, ${fixture.exportJob}::uuid)
             AND event_type IN ('ticket.bulk.requested','ticket.export.requested'))
            AS outbox,
          NOT EXISTS (
            SELECT 1 FROM public.audit_events AS event
            WHERE event.resource_id IN (
              ${fixture.bulkJob}::uuid, ${fixture.exportJob}::uuid
            ) AND (event.metadata::text LIKE '%must-never-escape%'
              OR event.metadata ->> 'contentRedacted' <> 'true')
          ) AND NOT EXISTS (
            SELECT 1 FROM public.outbox_events AS event
            WHERE event.aggregate_id IN (
              ${fixture.bulkJob}::uuid, ${fixture.exportJob}::uuid
            ) AND (event.payload::text LIKE '%must-never-escape%'
              OR event.payload ->> 'contentRedacted' <> 'true')
          ) AS redacted,
          (SELECT state_key FROM public.alerts
           WHERE id = ${fixture.alert}::uuid) AS alert_state,
          (SELECT version FROM public.alerts
           WHERE id = ${fixture.alert}::uuid) AS alert_version
      `;
      assert.equal(Number(evidence?.receipts), 2);
      assert.equal(evidence?.audits, "2");
      assert.equal(evidence?.outbox, "2");
      assert.equal(evidence?.redacted, true);
      assert.equal(evidence?.alert_state, "in_progress");
      assert.equal(evidence?.alert_version, 2);

      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            UPDATE public.ticket_bulk_command_receipts
            SET expires_at = expires_at + interval '1 microsecond'
            WHERE job_id = ${fixture.bulkJob}::uuid
          `;
          return {};
        }),
        "55000",
        "immutable ticket runtime receipt was mutable",
      );
      await expectSqlState(
        transaction.savepoint(async (sql) => {
          await sql`
            UPDATE public.ticket_export_command_receipts
            SET expires_at = expires_at + interval '1 microsecond'
            WHERE job_id = ${fixture.exportJob}::uuid
          `;
          return {};
        }),
        "55000",
        "immutable ticket export receipt was mutable",
      );

      assert.equal(asString(query.source, "query source is missing"), "inline");
      assert.equal(
        asNumber(claimedExportJob.revision, "revision is missing"),
        2,
      );
      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end({ timeout: 5 });
}
