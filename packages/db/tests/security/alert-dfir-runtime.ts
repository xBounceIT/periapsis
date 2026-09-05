import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_ALERT_DFIR_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_ALERT_DFIR_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4a10-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  peerUser: uuid(102),
  foreignUser: uuid(103),
  adminMembership: uuid(201),
  peerMembership: uuid(202),
  foreignMembership: uuid(203),
  adminSession: uuid(204),
  peerSession: uuid(206),
  foreignSession: uuid(208),
  alert: uuid(301),
  foreignAlert: uuid(302),
  case: uuid(303),
  team: uuid(304),
  teamEpoch: uuid(305),
  otherAlert: uuid(306),
  ioc: uuid(401),
  commandA: uuid(501),
  commandB: uuid(502),
  activityA: uuid(601),
  activityB: uuid(602),
  auditA: uuid(701),
  auditB: uuid(702),
  outboxA: uuid(801),
  outboxB: uuid(802),
  timeline: uuid(901),
  timelineEvidence: uuid(902),
  storage: uuid(903),
  attachment: uuid(904),
  evidence: uuid(905),
  custody: uuid(906),
  relationship: uuid(907),
  retraction: uuid(908),
  caseStorage: uuid(909),
  caseAttachment: uuid(910),
  task: uuid(911),
} as const;

const primary = postgres(databaseUrl, { max: 4, onnotice: () => undefined });
const contender = postgres(databaseUrl, {
  max: 2,
  onnotice: () => undefined,
});

function digest(label: string): Buffer {
  return createHash("sha256").update(`alert-dfir-runtime:${label}`).digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function isJSONRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function receiptProjectionDescription(value: unknown): unknown {
  if (!isJSONRecord(value) || !isJSONRecord(value.projection)) {
    return undefined;
  }
  return value.projection.description;
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
  client: typeof primary,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
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
             set_config('app.tracestate', 'alert_dfir=runtime', true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function setup(): Promise<void> {
  await primary.begin(async (transaction) => {
    const suffix = sequence.toString(36);
    const ticketNumber = (Number(sequence % 800_000n) + 100_000)
      .toString()
      .padStart(6, "0");
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, ${`alert-dfir-${suffix}`},
         'Alert DFIR runtime'),
        (${fixture.foreignTenant}::uuid, ${`alert-dfir-foreign-${suffix}`},
         'Alert DFIR foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active) VALUES
        (${fixture.adminUser}::uuid,
         ${`alert-dfir-admin-${suffix}@example.invalid`}, 'Admin', true),
        (${fixture.peerUser}::uuid,
         ${`alert-dfir-peer-${suffix}@example.invalid`}, 'Peer', true),
        (${fixture.foreignUser}::uuid,
         ${`alert-dfir-foreign-${suffix}@example.invalid`}, 'Foreign', true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.peerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.peerUser}::uuid, 'read_only', 'active'),
        (${fixture.foreignMembership}::uuid,
         ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid,
         'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,
        ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES (
        ${fixture.team}::uuid, ${`alert_dfir_download_${suffix}`},
        'Alert DFIR download runtime team',
        'Runtime assignment-scope denial proof', ${fixture.adminUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason
      ) VALUES (
        ${fixture.teamEpoch}::uuid, ${fixture.tenant}::uuid,
        ${fixture.team}::uuid, ${fixture.adminMembership}::uuid,
        'Alert DFIR download runtime assignment'
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES
      (
        ${fixture.adminSession}::uuid, ${fixture.adminUser}::uuid,
        ${uuid(205)}::uuid, ${fixture.tenant}::uuid,
        ${digest(`download-session-token:${suffix}`)},
        ${digest(`download-session-csrf:${suffix}`)}, 'totp',
        date_trunc('milliseconds', transaction_timestamp()) - interval '2 minutes',
        date_trunc('milliseconds', transaction_timestamp()) - interval '1 minute',
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '8 hours',
        date_trunc('milliseconds', transaction_timestamp()) - interval '10 minutes'
      ),
      (
        ${fixture.peerSession}::uuid, ${fixture.peerUser}::uuid,
        ${uuid(207)}::uuid, ${fixture.tenant}::uuid,
        ${digest(`peer-download-session-token:${suffix}`)},
        ${digest(`peer-download-session-csrf:${suffix}`)}, 'totp',
        date_trunc('milliseconds', transaction_timestamp()) - interval '2 minutes',
        date_trunc('milliseconds', transaction_timestamp()) - interval '1 minute',
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '8 hours',
        date_trunc('milliseconds', transaction_timestamp()) - interval '10 minutes'
      ),
      (
        ${fixture.foreignSession}::uuid, ${fixture.foreignUser}::uuid,
        ${uuid(209)}::uuid, ${fixture.foreignTenant}::uuid,
        ${digest(`foreign-download-session-token:${suffix}`)},
        ${digest(`foreign-download-session-csrf:${suffix}`)}, 'totp',
        date_trunc('milliseconds', transaction_timestamp()) - interval '2 minutes',
        date_trunc('milliseconds', transaction_timestamp()) - interval '1 minute',
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '8 hours',
        date_trunc('milliseconds', transaction_timestamp()) - interval '10 minutes'
      )
    `;
    const insertAlert = async (input: {
      id: string;
      tenantId: string;
      number: string;
      title: string;
      userId: string;
      membershipId: string;
    }): Promise<void> => {
      await transaction`
        SELECT set_config('app.tenant_id', ${input.tenantId}, true),
               set_config('app.user_id', ${input.userId}, true)
      `;
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          title, created_by, created_by_membership_id, version, updated_at
        )
        SELECT ${input.id}::uuid, ${input.tenantId}::uuid, ${input.number},
               workflow.id, workflow.current_version, 'new', ${input.title},
               ${input.userId}::uuid, ${input.membershipId}::uuid, 1,
               transaction_timestamp()
        FROM public.ticket_workflows AS workflow
        WHERE workflow.tenant_id = ${input.tenantId}::uuid
          AND workflow.key = 'default_alert'
      `;
    };
    await insertAlert({
      id: fixture.alert,
      tenantId: fixture.tenant,
      number: `ALT-2099-${ticketNumber}`,
      title: "Alert DFIR source",
      userId: fixture.adminUser,
      membershipId: fixture.adminMembership,
    });
    await insertAlert({
      id: fixture.foreignAlert,
      tenantId: fixture.foreignTenant,
      number: `ALT-2098-${ticketNumber}`,
      title: "Foreign Alert DFIR source",
      userId: fixture.foreignUser,
      membershipId: fixture.foreignMembership,
    });
    await insertAlert({
      id: fixture.otherAlert,
      tenantId: fixture.tenant,
      number: `ALT-2097-${ticketNumber}`,
      title: "Other Alert DFIR root",
      userId: fixture.adminUser,
      membershipId: fixture.adminMembership,
    });
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.adminUser}, true)
    `;
    await transaction`
      INSERT INTO public.cases (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        title, created_by_membership_id, created_by_user_id, version,
        updated_at
      )
      SELECT ${fixture.case}::uuid, ${fixture.tenant}::uuid,
             ${`CAS-2099-${ticketNumber}`}, workflow.id,
             workflow.current_version, state.value->>'key',
             'Case download audit source', ${fixture.adminMembership}::uuid,
             ${fixture.adminUser}::uuid, 1, transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id = workflow.tenant_id
       AND workflow_version.workflow_id = workflow.id
       AND workflow_version.aggregate_kind = workflow.aggregate_kind
       AND workflow_version.version = workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
      WHERE workflow.tenant_id = ${fixture.tenant}::uuid
        AND workflow.key = 'default_case'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.dfir_storage_objects (
        id, tenant_id, bucket, object_key, original_filename,
        classification, state, expected_size_bytes, upload_expires_at,
        content_sha256, size_bytes, detected_mime, verified_at,
        created_by_membership_id, created_at, updated_at
      ) VALUES (
        ${fixture.storage}::uuid, ${fixture.tenant}::uuid, 'periapsis-runtime',
        ${`${fixture.tenant}/${fixture.storage}`}, 'memory.bin', 'internal',
        'available', 32, transaction_timestamp() + interval '30 minutes',
        ${digest("evidence-content")}, 32, 'application/octet-stream',
        transaction_timestamp(), ${fixture.adminMembership}::uuid,
        transaction_timestamp(), transaction_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.dfir_attachments (
        id, tenant_id, subject_kind, alert_id, storage_object_id,
        original_filename, visibility, scan_state,
        uploaded_by_membership_id, uploaded_at, version
      ) VALUES (
        ${fixture.attachment}::uuid, ${fixture.tenant}::uuid, 'alert',
        ${fixture.alert}::uuid, ${fixture.storage}::uuid, 'memory.bin',
        'private', 'available', ${fixture.adminMembership}::uuid,
        transaction_timestamp(), 1
      )
    `;
    await transaction`
      INSERT INTO public.dfir_storage_objects (
        id, tenant_id, bucket, object_key, original_filename,
        classification, state, expected_size_bytes, upload_expires_at,
        content_sha256, size_bytes, detected_mime, verified_at,
        created_by_membership_id, created_at, updated_at
      ) VALUES (
        ${fixture.caseStorage}::uuid, ${fixture.tenant}::uuid,
        'must-never-leak-download-bucket',
        ${`${fixture.tenant}/${fixture.caseStorage}`},
        'must-never-leak-download-filename.bin', 'internal', 'available',
        64, transaction_timestamp() + interval '30 minutes',
        ${digest("must-never-leak-download-content")}, 64,
        'application/x-must-never-leak', transaction_timestamp(),
        ${fixture.adminMembership}::uuid, transaction_timestamp(),
        transaction_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.dfir_attachments (
        id, tenant_id, subject_kind, case_id, storage_object_id,
        original_filename, visibility, scan_state,
        uploaded_by_membership_id, uploaded_at, version
      ) VALUES (
        ${fixture.caseAttachment}::uuid, ${fixture.tenant}::uuid, 'case',
        ${fixture.case}::uuid, ${fixture.caseStorage}::uuid,
        'must-never-leak-download-filename.bin', 'private', 'available',
        ${fixture.adminMembership}::uuid, transaction_timestamp(), 1
      )
    `;
  });
}

type OperatorDownloadAuditInput = {
  actorMembershipID: string;
  actorSessionID: string;
  actorUserID: string;
  attachmentID: string;
  attachmentState?: "available" | "quarantined";
  attachmentVersion?: number;
  correlationID: string;
  eventID: string;
  expiresAt: Date;
  ipAddress?: string;
  requestID: string;
  rootID: string;
  rootKind: "alert" | "case";
  rootVersion?: number;
  scope?: "assigned" | "operator_team" | "tenant";
  storageID: string;
  storageState?: "available" | "quarantined";
  storageVersion?: number;
  tenantID: string;
};

async function appendOperatorDownloadAudit(
  input: OperatorDownloadAuditInput,
): Promise<string> {
  return asApi(primary, input.tenantID, input.actorUserID, (transaction) =>
    callOperatorDownloadAudit(transaction, input),
  );
}

async function callOperatorDownloadAudit(
  transaction: TransactionSql,
  input: OperatorDownloadAuditInput,
): Promise<string> {
  const [row] = await transaction<{ event_id: string }[]>`
    SELECT app.append_dfir_download_grant_audit_v1(
      ${input.eventID}::uuid, 'human', ${input.actorSessionID}::uuid,
      ${input.actorMembershipID}::uuid,
      ${input.rootKind}::public.ticket_aggregate_kind,
      ${input.rootID}::uuid, ${input.rootVersion ?? 1}::bigint,
      ${input.rootKind}::public.dfir_entity_kind,
      ${input.rootID}::uuid, ${input.attachmentID}::uuid,
      ${input.attachmentVersion ?? 1}::bigint,
      ${input.storageID}::uuid, ${input.storageVersion ?? 1}::bigint,
      ${input.attachmentState ?? "available"}::public.dfir_scan_state,
      ${input.storageState ?? "available"}::public.dfir_scan_state,
      'operator', ${input.scope ?? "tenant"}::public.authorization_scope,
      NULL::uuid,
      ${input.expiresAt}::timestamptz, ${input.requestID}::uuid,
      ${input.correlationID}::uuid, ${input.ipAddress ?? "192.0.2.90"}::inet,
      'alert-dfir-download-runtime', 'totp'
    )::text AS event_id
  `;
  assert(row, "DFIR download audit returned no event identifier");
  return row.event_id;
}

function operatorDownloadInput(
  overrides: Partial<OperatorDownloadAuditInput> = {},
): OperatorDownloadAuditInput {
  return {
    actorMembershipID: fixture.adminMembership,
    actorSessionID: fixture.adminSession,
    actorUserID: fixture.adminUser,
    attachmentID: fixture.attachment,
    correlationID: uuid(2001),
    eventID: uuid(2002),
    expiresAt: new Date(Date.now() + 4 * 60_000),
    requestID: uuid(2003),
    rootID: fixture.alert,
    rootKind: "alert",
    storageID: fixture.storage,
    tenantID: fixture.tenant,
    ...overrides,
  };
}

async function verifyOperatorDownloadGrantAuditing(): Promise<void> {
  const signature =
    "app.append_dfir_download_grant_audit_v1(uuid,text,uuid,uuid,public.ticket_aggregate_kind,uuid,bigint,public.dfir_entity_kind,uuid,uuid,bigint,uuid,bigint,public.dfir_scan_state,public.dfir_scan_state,text,public.authorization_scope,uuid,timestamp with time zone,uuid,uuid,inet,text,text)";
  const [catalog] = await primary<
    {
      api_execute: boolean;
      owner: string;
      security_definer: boolean;
      worker_execute: boolean;
    }[]
  >`
    SELECT pg_get_userbyid(procedure.proowner) AS owner,
           procedure.prosecdef AS security_definer,
           has_function_privilege(
             'periapsis_api', procedure.oid, 'EXECUTE'
           ) AS api_execute,
           has_function_privilege(
             'periapsis_worker', procedure.oid, 'EXECUTE'
           ) AS worker_execute
    FROM pg_proc AS procedure
    WHERE procedure.oid = to_regprocedure(${signature})
  `;
  assert.deepEqual(catalog, {
    api_execute: true,
    owner: "periapsis_migrator",
    security_definer: true,
    worker_execute: false,
  });

  const expiresAt = new Date(Date.now() + 4 * 60_000);
  const alertEventA = uuid(2101);
  const alertEventB = uuid(2102);
  const caseEvent = uuid(2103);
  const alertA = operatorDownloadInput({
    correlationID: uuid(2111),
    eventID: alertEventA,
    expiresAt,
    requestID: uuid(2121),
  });
  const alertB = operatorDownloadInput({
    correlationID: uuid(2111),
    eventID: alertEventB,
    expiresAt,
    requestID: uuid(2121),
  });
  const caseInput = operatorDownloadInput({
    attachmentID: fixture.caseAttachment,
    correlationID: uuid(2113),
    eventID: caseEvent,
    expiresAt,
    requestID: uuid(2123),
    rootID: fixture.case,
    rootKind: "case",
    storageID: fixture.caseStorage,
  });
  assert.equal(await appendOperatorDownloadAudit(alertA), alertEventA);
  assert.equal(await appendOperatorDownloadAudit(alertB), alertEventB);
  assert.equal(await appendOperatorDownloadAudit(caseInput), caseEvent);

  const auditRows = await primary<
    {
      action: string;
      actor_user_id: string;
      after: postgres.JSONValue | null;
      authentication_method: string;
      before: postgres.JSONValue | null;
      correlation_id: string;
      event_json: postgres.JSONValue;
      id: string;
      ip_address: string;
      metadata: Record<string, unknown>;
      request_id: string;
      resource_id: string;
      resource_type: string;
      user_agent: string;
    }[]
  >`
    SELECT event.id::text, event.action, event.resource_type,
           event.resource_id::text, event.actor_user_id::text,
           event.request_id::text, event.correlation_id::text,
           event.ip_address::text, event.user_agent,
           event.authentication_method, event.before, event.after,
           event.metadata, to_jsonb(event) AS event_json
    FROM public.audit_events AS event
    WHERE event.id = ANY(${[alertEventA, alertEventB, caseEvent]}::uuid[])
    ORDER BY event.id
  `;
  assert.equal(auditRows.length, 3);
  const byID = new Map(auditRows.map((row) => [row.id, row]));
  for (const [input, expectedAction] of [
    [alertA, "dfir.alert.attachment.download_grant_issued"],
    [alertB, "dfir.alert.attachment.download_grant_issued"],
    [caseInput, "dfir.case.attachment.download_grant_issued"],
  ] as const) {
    const row = byID.get(input.eventID);
    assert(row, `missing download audit ${input.eventID}`);
    assert.equal(row.action, expectedAction);
    assert.equal(row.resource_type, "dfir_attachment");
    assert.equal(row.resource_id, input.attachmentID);
    assert.equal(row.actor_user_id, fixture.adminUser);
    assert.equal(row.request_id, input.requestID);
    assert.equal(row.correlation_id, input.correlationID);
    assert.equal(row.ip_address, "192.0.2.90/32");
    assert.equal(row.user_agent, "alert-dfir-download-runtime");
    assert.equal(row.authentication_method, "totp");
    assert.equal(row.before, null);
    assert.equal(row.after, null);
    assert.deepEqual(Object.keys(row.metadata).toSorted(), [
      "actorMembershipId",
      "actorSessionId",
      "actorUserId",
      "attachmentId",
      "audience",
      "expiresAt",
      "rootId",
      "rootKind",
      "storageObjectId",
      "tenantId",
    ]);
    assert.equal(row.metadata["tenantId"], fixture.tenant);
    assert.equal(row.metadata["actorUserId"], fixture.adminUser);
    assert.equal(row.metadata["actorSessionId"], fixture.adminSession);
    assert.equal(row.metadata["actorMembershipId"], fixture.adminMembership);
    assert.equal(row.metadata["rootKind"], input.rootKind);
    assert.equal(row.metadata["rootId"], input.rootID);
    assert.equal(row.metadata["attachmentId"], input.attachmentID);
    assert.equal(row.metadata["storageObjectId"], input.storageID);
    assert.equal(row.metadata["audience"], "operator");
    assert.equal(
      new Date(String(row.metadata["expiresAt"])).getTime(),
      expiresAt.getTime(),
    );
    assert.doesNotMatch(
      JSON.stringify(row.event_json),
      /must-never-leak|x-amz-(?:credential|signature)|sha256/iu,
    );
  }

  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        actorMembershipID: fixture.peerMembership,
        actorSessionID: fixture.peerSession,
        actorUserID: fixture.peerUser,
        eventID: uuid(2201),
        requestID: uuid(2202),
      }),
    ),
    "42501",
    "an operator without DFIR attachment authority emitted a grant audit",
  );
  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        actorMembershipID: fixture.foreignMembership,
        actorSessionID: fixture.foreignSession,
        actorUserID: fixture.foreignUser,
        eventID: uuid(2203),
        requestID: uuid(2204),
        tenantID: fixture.foreignTenant,
      }),
    ),
    "P0002",
    "a foreign tenant observed or audited a local attachment grant",
  );
  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        eventID: uuid(2205),
        requestID: uuid(2206),
        rootVersion: 2,
      }),
    ),
    "40001",
    "a stale root revision emitted a grant audit",
  );
  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        eventID: uuid(2211),
        requestID: uuid(2212),
        scope: "assigned",
      }),
    ),
    "42501",
    "assigned scope authorized an unassigned Alert with null assignee and claimer",
  );
  await expectSqlState(
    primary.begin(async (transaction) => {
      await transaction`
        UPDATE public.alerts
        SET assigned_team_id = ${fixture.team}::uuid,
            assigned_team_epoch_id = ${fixture.teamEpoch}::uuid,
            assignee_user_id = ${fixture.peerUser}::uuid,
            claimed_by_user_id = NULL
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.alert}::uuid
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.adminUser}, true)
      `;
      return callOperatorDownloadAudit(
        transaction,
        operatorDownloadInput({
          eventID: uuid(2213),
          requestID: uuid(2214),
          scope: "assigned",
        }),
      );
    }),
    "42501",
    "assigned scope authorized an Alert assigned to another user when the claimer was null",
  );
  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        attachmentID: fixture.caseAttachment,
        eventID: uuid(2221),
        requestID: uuid(2222),
        rootID: fixture.case,
        rootKind: "case",
        scope: "assigned",
        storageID: fixture.caseStorage,
      }),
    ),
    "42501",
    "assigned scope authorized an unassigned Case with null assignee and claimer",
  );
  await expectSqlState(
    primary.begin(async (transaction) => {
      await transaction`
        UPDATE public.cases
        SET assigned_team_id = ${fixture.team}::uuid,
            assigned_team_epoch_id = ${fixture.teamEpoch}::uuid,
            assignee_user_id = ${fixture.peerUser}::uuid,
            claimed_by_user_id = NULL
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.case}::uuid
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.adminUser}, true)
      `;
      return callOperatorDownloadAudit(
        transaction,
        operatorDownloadInput({
          attachmentID: fixture.caseAttachment,
          eventID: uuid(2223),
          requestID: uuid(2224),
          rootID: fixture.case,
          rootKind: "case",
          scope: "assigned",
          storageID: fixture.caseStorage,
        }),
      );
    }),
    "42501",
    "assigned scope authorized a Case assigned to another user when the claimer was null",
  );
  await expectSqlState(
    appendOperatorDownloadAudit(
      operatorDownloadInput({
        eventID: uuid(2215),
        ipAddress: "192.0.2.0/24",
        requestID: uuid(2216),
      }),
    ),
    "22023",
    "a network-valued audit IP address was accepted as an actor host",
  );
  await expectSqlState(
    primary.begin(async (transaction) => {
      await transaction`
        UPDATE public.dfir_storage_objects
        SET state = 'quarantined'
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.caseStorage}::uuid
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.adminUser}, true)
      `;
      return callOperatorDownloadAudit(
        transaction,
        operatorDownloadInput({
          attachmentID: fixture.caseAttachment,
          eventID: uuid(2207),
          requestID: uuid(2208),
          rootID: fixture.case,
          rootKind: "case",
          storageID: fixture.caseStorage,
        }),
      );
    }),
    "40001",
    "a storage-state drift emitted a grant audit",
  );

  const [successfulCount] = await primary<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action IN (
        'dfir.alert.attachment.download_grant_issued',
        'dfir.case.attachment.download_grant_issued'
      )
  `;
  assert.equal(successfulCount?.count, 3);
}

type Reservation = {
  command_id: string;
  result_resource_id: string;
  result_snapshot: postgres.JSONValue;
  result_version: string;
  replayed: boolean;
};

async function reserveIOC(
  transaction: TransactionSql,
  commandID: string,
  requestDigest: Buffer,
): Promise<Reservation> {
  const [row] = await transaction<Reservation[]>`
    SELECT command_id::text,result_resource_id::text,
           result_snapshot,result_version::text,replayed
    FROM app.reserve_dfir_mutation_command_v1(
      ${commandID}::uuid,'alert',${fixture.alert}::uuid,
      'dfir.ioc.create','ioc',${fixture.ioc}::uuid,NULL,1,
      ${digest("key")},${requestDigest}
    )
  `;
  assert(row, "Alert DFIR reservation returned no row");
  return row;
}

async function insertIOCAndEffects(
  transaction: TransactionSql,
  commandID: string,
  activityID: string,
  auditID: string,
  outboxID: string,
): Promise<void> {
  const observedAt = new Date("2026-08-30T12:00:00.000Z");
  await transaction`
    INSERT INTO public.dfir_iocs (
      id, tenant_id, type, value, normalized_value, description, source,
      confidence, tlp, first_seen, last_seen, malicious_state, tags,
      enrichment, created_by_membership_id, updated_by_membership_id,
      version
    ) VALUES (
      ${fixture.ioc}::uuid, ${fixture.tenant}::uuid, 'domain',
      'private-indicator.example', 'private-indicator.example', '',
      'manual', 80, 'amber', ${observedAt}, ${observedAt}, 'suspicious',
      ARRAY[]::text[], '{}'::jsonb, ${fixture.adminMembership}::uuid,
      ${fixture.adminMembership}::uuid, 1
    )
  `;
  await transaction`
    INSERT INTO public.dfir_ioc_links (
      tenant_id, ioc_id, alert_id, created_by_membership_id
    ) VALUES (
      ${fixture.tenant}::uuid, ${fixture.ioc}::uuid,
      ${fixture.alert}::uuid, ${fixture.adminMembership}::uuid
    )
  `;
  await transaction`
    SELECT app.append_alert_dfir_mutation_effects_v1(
      ${fixture.alert}::uuid, 'dfir.ioc.manage', 'dfir.ioc.created',
      'dfir_ioc', ${fixture.ioc}::uuid, 1, 'dfir.ioc.create',
      ${digest("key")}, ${digest("request")}, ${activityID}::uuid,
      '{}'::jsonb,
      '{"value":"must-never-leak","version":1}'::jsonb,
      '{"objectKey":"must-never-leak","commandOperation":"dfir.ioc.create"}'::jsonb,
      ${auditID}::uuid, ${outboxID}::uuid, ${uuid(1001)}::uuid,
      ${uuid(1002)}::uuid, '127.0.0.1'::inet, 'alert-dfir-test', 'totp'
    )
  `;
  await transaction`
    SELECT app.store_dfir_mutation_command_result_v1(
      ${commandID}::uuid,
      jsonb_build_object(
        'schemaVersion',1,'tenantId',resource.tenant_id::text,
        'rootKind','alert','rootId',${fixture.alert}::text,
        'operation','dfir.ioc.create','resourceKind','ioc',
        'resourceId',resource.id::text,'resultVersion',1,
        'projection',jsonb_build_object(
          'id',resource.id::text,'tenantId',resource.tenant_id::text,
          'type',resource.type::text,'value',resource.value,
          'normalizedValue',resource.normalized_value,
          'description',resource.description,'source',resource.source,
          'confidence',resource.confidence,'tlp',resource.tlp::text,
          'firstSeen',resource.first_seen,'lastSeen',resource.last_seen,
          'malicious',resource.malicious_state::text,'tags',resource.tags,
          'enrichment',resource.enrichment
        )
      )
    )
    FROM public.dfir_iocs AS resource
    WHERE resource.tenant_id=${fixture.tenant}::uuid
      AND resource.id=${fixture.ioc}::uuid
  `;
}

function genericIOCReceiptSnapshot(
  resourceID: string,
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    rootKind: "alert",
    rootId: fixture.alert,
    operation: "dfir.ioc.create",
    resourceKind: "ioc",
    resourceId: resourceID,
    resultVersion: 1,
    projection: {
      id: resourceID,
      tenantId: fixture.tenant,
      type: "domain",
      value: "poison.example",
      normalizedValue: "poison.example",
      description: "",
      source: "runtime",
      confidence: 0,
      tlp: "clear",
      firstSeen: "2026-09-04T10:00:00Z",
      lastSeen: "2026-09-04T10:00:00Z",
      malicious: "unknown",
      tags: [],
    },
  };
}

async function verifyGenericReceiptNullPoison(): Promise<void> {
  const envelopeFields = [
    "schemaVersion",
    "tenantId",
    "rootKind",
    "rootId",
    "operation",
    "resourceKind",
    "resourceId",
    "resultVersion",
    "projection",
  ] as const;
  const poisoners: Array<{
    label: string;
    apply(snapshot: Record<string, unknown>): void;
  }> = [];
  for (const field of envelopeFields) {
    poisoners.push(
      {
        label: `${field}-absent`,
        apply: (snapshot) => {
          delete snapshot[field];
        },
      },
      {
        label: `${field}-null`,
        apply: (snapshot) => {
          snapshot[field] = null;
        },
      },
    );
  }
  poisoners.push(
    {
      label: "unexpected-null-secondary",
      apply: (snapshot) => {
        snapshot.secondaryResourceId = null;
      },
    },
    {
      label: "projection-id-absent",
      apply: (snapshot) => {
        assert(isJSONRecord(snapshot.projection));
        delete snapshot.projection.id;
      },
    },
    {
      label: "projection-id-null",
      apply: (snapshot) => {
        assert(isJSONRecord(snapshot.projection));
        snapshot.projection.id = null;
      },
    },
    {
      label: "projection-tenant-null",
      apply: (snapshot) => {
        assert(isJSONRecord(snapshot.projection));
        snapshot.projection.tenantId = null;
      },
    },
  );

  await Promise.all(
    poisoners.map(async (poisoner, index) => {
      const resourceID = uuid(2200 + index * 2);
      const commandID = uuid(2201 + index * 2);
      const snapshot = genericIOCReceiptSnapshot(resourceID);
      poisoner.apply(snapshot);
      await expectSqlState(
        asApi(
          primary,
          fixture.tenant,
          fixture.adminUser,
          async (transaction) => {
            const [reservation] = await transaction<{ command_id: string }[]>`
              SELECT command_id::text
              FROM app.reserve_dfir_mutation_command_v1(
                ${commandID}::uuid,'alert',${fixture.alert}::uuid,
                'dfir.ioc.create','ioc',${resourceID}::uuid,NULL,1,
                ${digest(`poison-key-${index}`)},
                ${digest(`poison-request-${index}`)}
              )
            `;
            assert(reservation);
            await transaction`
              SELECT app.store_dfir_mutation_command_result_v1(
                ${reservation.command_id}::uuid,
                ${JSON.stringify(snapshot)}::jsonb
              )
            `;
          },
        ),
        "22023",
        `${poisoner.label} receipt poison was accepted`,
      );
    }),
  );

  await Promise.all(
    ([null, undefined] as const).map(async (fieldValue, index) => {
      const resourceID = uuid(2300 + index * 2);
      const commandID = uuid(2301 + index * 2);
      const snapshot = {
        schemaVersion: 1,
        tenantId: fixture.tenant,
        rootKind: "case",
        rootId: fixture.case,
        operation: "dfir.timeline.create",
        resourceKind: "timeline_event",
        resourceId: resourceID,
        resultVersion: 1,
        projection: {
          id: resourceID,
          tenantId: fixture.tenant,
          ...(fieldValue === undefined ? {} : { caseId: fieldValue }),
          eventTime: "2026-09-04T10:00:00Z",
          ingestedAt: "2026-09-04T10:00:00Z",
          originalTimezone: "UTC",
          precision: "second",
          source: "runtime",
          category: "poison",
          title: "root poison",
          description: "",
          iocIds: [],
          assetIds: [],
          evidenceIds: [],
          tags: [],
        },
      };
      await expectSqlState(
        asApi(
          primary,
          fixture.tenant,
          fixture.adminUser,
          async (transaction) => {
            const [reservation] = await transaction<{ command_id: string }[]>`
              SELECT command_id::text
              FROM app.reserve_dfir_mutation_command_v1(
                ${commandID}::uuid,'case',${fixture.case}::uuid,
                'dfir.timeline.create','timeline_event',${resourceID}::uuid,
                NULL,1,${digest(`timeline-poison-key-${index}`)},
                ${digest(`timeline-poison-request-${index}`)}
              )
            `;
            assert(reservation);
            await transaction`
              SELECT app.store_dfir_mutation_command_result_v1(
                ${reservation.command_id}::uuid,
                ${JSON.stringify(snapshot)}::jsonb
              )
            `;
          },
        ),
        "22023",
        `timeline projection root ${fieldValue === null ? "null" : "absent"} was accepted`,
      );
    }),
  );
}

async function runConcurrentCreate(): Promise<void> {
  const request = digest("request");
  const execute = async (
    client: typeof primary,
    commandID: string,
    activityID: string,
    auditID: string,
    outboxID: string,
  ): Promise<boolean> =>
    asApi(client, fixture.tenant, fixture.adminUser, async (transaction) => {
      const reservation = await reserveIOC(transaction, commandID, request);
      assert.equal(reservation.result_resource_id, fixture.ioc);
      assert.equal(reservation.result_version, "1");
      if (!reservation.replayed) {
        await insertIOCAndEffects(
          transaction,
          reservation.command_id,
          activityID,
          auditID,
          outboxID,
        );
      } else {
        assert.equal(
          receiptProjectionDescription(reservation.result_snapshot),
          "",
        );
      }
      return reservation.replayed;
    });

  const results = await Promise.all([
    execute(
      primary,
      fixture.commandA,
      fixture.activityA,
      fixture.auditA,
      fixture.outboxA,
    ),
    execute(
      contender,
      fixture.commandB,
      fixture.activityB,
      fixture.auditB,
      fixture.outboxB,
    ),
  ]);
  assert.deepEqual(
    results.toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );

  await primary`
    UPDATE public.dfir_iocs
    SET description='later live mutation',version=2
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.ioc}::uuid
  `;
  const historical = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) => reserveIOC(transaction, uuid(504), request),
  );
  assert.equal(historical.replayed, true);
  assert.equal(
    receiptProjectionDescription(historical.result_snapshot),
    "",
    "replay followed the later live IOC projection",
  );
}

async function reserveAlertInvestigation(
  transaction: TransactionSql,
  commandID: string,
  operation: string,
  resourceID: string,
  resultVersion: number,
  key: Buffer,
  request: Buffer,
): Promise<{
  command_id: string;
  replayed: boolean;
  result_snapshot: unknown;
}> {
  const [row] = await transaction<
    { command_id: string; replayed: boolean; result_snapshot: unknown }[]
  >`
    SELECT command_id::text, replayed, result_snapshot
    FROM app.reserve_alert_investigation_command_v1(
      ${commandID}::uuid, ${fixture.alert}::uuid, ${operation},
      ${resourceID}::uuid, ${resultVersion}, ${key}, ${request}
    )
  `;
  assert(row, "Alert investigation reservation returned no row");
  return row;
}

async function appendInvestigationEffects(
  transaction: TransactionSql,
  input: {
    operation: string;
    activityType: string;
    auditAction: string;
    auditReason: string;
    outboxType: string;
    resourceType: string;
    resourceID: string;
    version: number;
    key: Buffer;
    request: Buffer;
    activityID: string;
    auditID: string;
    outboxID: string;
    requestID: string;
    correlationID: string;
  },
): Promise<void> {
  await transaction`
    SELECT app.append_alert_investigation_effects_v1(
      ${fixture.alert}::uuid, ${input.operation}, ${input.activityType},
      ${input.auditAction}, ${input.auditReason}, ${input.outboxType},
      ${input.resourceType}, ${input.resourceID}::uuid, ${input.version},
      ${input.key}, ${input.request}, ${input.activityID}::uuid,
      '{}'::jsonb, '{"secret":"must-never-leak"}'::jsonb,
      '{"secret":"must-never-leak"}'::jsonb, ${input.auditID}::uuid,
      ${input.outboxID}::uuid, ${input.requestID}::uuid,
      ${input.correlationID}::uuid, '127.0.0.1'::inet,
      'alert-investigation-runtime', 'totp'
    )
  `;
}

async function createAlertComment(
  tenantID: string,
  userID: string,
  alertID: string,
  label: string,
  offset: number,
): Promise<string> {
  const [receipt] = await asApi(
    primary,
    tenantID,
    userID,
    (transaction) => transaction<{ comment_id: string; replayed: boolean }[]>`
      SELECT comment_id::text,replayed
      FROM app.create_tenant_ticket_comment_v2(
        'alert',${alertID}::uuid,'private',${`Runtime ${label}`},
        ${`<p>Runtime ${label}</p>`},ARRAY[]::uuid[],ARRAY[]::uuid[],
        ${digest(`${label}:key`)},${digest(`${label}:request`)},
        ${uuid(offset)}::uuid,${uuid(offset + 1)}::uuid,'127.0.0.1'::inet,
        'alert-dfir-runtime','totp'
      )
    `,
  );
  assert(receipt, `${label} comment creation returned no receipt`);
  assert.equal(receipt.replayed, false);
  return receipt.comment_id;
}

function alertTaskSnapshot(
  commentID: string,
  updatedAt: string,
): postgres.JSONValue {
  return {
    kind: "alert_task",
    task: {
      id: fixture.task,
      tenantId: fixture.tenant,
      alertId: fixture.alert,
      title: "Runtime Alert task",
      description: "Explicit full-replace comment association",
      status: "todo",
      priority: "medium",
      checklist: [],
      commentIds: [commentID],
      createdAt: "2026-09-04T10:00:00Z",
      updatedAt,
      version: 2,
    },
  };
}

async function runAlertTaskCommentsLifecycle(): Promise<void> {
  const mainComment = await createAlertComment(
    fixture.tenant,
    fixture.adminUser,
    fixture.alert,
    "main-alert-comment",
    2301,
  );
  const otherComment = await createAlertComment(
    fixture.tenant,
    fixture.adminUser,
    fixture.otherAlert,
    "other-alert-comment",
    2303,
  );
  const foreignComment = await createAlertComment(
    fixture.foreignTenant,
    fixture.foreignUser,
    fixture.foreignAlert,
    "foreign-alert-comment",
    2305,
  );
  await primary`
    INSERT INTO public.dfir_tasks(
      id,tenant_id,alert_id,case_id,title,description,status,priority,
      checklist,comment_ids,created_by_membership_id,
      updated_by_membership_id,version,created_at,updated_at
    ) VALUES (
      ${fixture.task}::uuid,${fixture.tenant}::uuid,${fixture.alert}::uuid,NULL,
      'Runtime Alert task','Explicit full-replace comment association',
      'todo','medium','[]'::jsonb,ARRAY[]::uuid[],
      ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,1,
      '2026-09-04T10:00:00Z','2026-09-04T10:00:00Z'
    )
  `;

  await Promise.all(
    (
      [
        [otherComment, "Alert task accepted a comment from another Alert root"],
        [foreignComment, "Alert task accepted a cross-tenant comment"],
      ] as const
    ).map(([commentID, message]) =>
      expectSqlState(
        asApi(
          primary,
          fixture.tenant,
          fixture.adminUser,
          (transaction) => transaction`
            UPDATE public.dfir_tasks
            SET comment_ids=ARRAY[${commentID}::uuid]
            WHERE tenant_id=${fixture.tenant}::uuid
              AND alert_id=${fixture.alert}::uuid AND case_id IS NULL
              AND id=${fixture.task}::uuid
          `,
        ),
        "23503",
        message,
      ),
    ),
  );

  const operation = "dfir.alert.task.comments.replace";
  const key = digest("alert-task-comments-key");
  const request = digest("alert-task-comments-request");
  const updatedAt = "2026-09-04T10:00:01Z";
  const snapshot = alertTaskSnapshot(mainComment, updatedAt);
  const commandID = uuid(2310);
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlertInvestigation(
        transaction,
        commandID,
        operation,
        fixture.task,
        2,
        key,
        request,
      );
      assert.equal(reservation.replayed, false);
      const updated = await transaction<{ version: string }[]>`
        UPDATE public.dfir_tasks
        SET comment_ids=ARRAY[${mainComment}::uuid],version=2,
            updated_by_membership_id=${fixture.adminMembership}::uuid,
            updated_at=${updatedAt}::timestamptz
        WHERE tenant_id=${fixture.tenant}::uuid
          AND alert_id=${fixture.alert}::uuid AND case_id IS NULL
          AND id=${fixture.task}::uuid AND version=1
        RETURNING version::text
      `;
      assert.equal(updated[0]?.version, "2");
      await appendInvestigationEffects(transaction, {
        operation,
        activityType: "alert.task.comments_replaced",
        auditAction: "dfir.alert.task.comments.replace",
        auditReason: "Associate the reviewed Alert comment",
        outboxType: "alert.task.comments_replaced.v1",
        resourceType: "dfir_task",
        resourceID: fixture.task,
        version: 2,
        key,
        request,
        activityID: uuid(2311),
        auditID: uuid(2312),
        outboxID: uuid(2313),
        requestID: uuid(2314),
        correlationID: uuid(2315),
      });
      const [stored] = await transaction<{ stored: boolean }[]>`
        SELECT app.store_alert_investigation_command_result_v1(
          ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
        ) AS stored
      `;
      assert.equal(stored?.stored, true);
    },
  );

  const later = await primary<{ version: string }[]>`
    UPDATE public.dfir_tasks
    SET title='Runtime Alert task after comment association',version=3,
        updated_at='2026-09-04T10:00:02Z'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND alert_id=${fixture.alert}::uuid AND case_id IS NULL
      AND id=${fixture.task}::uuid AND version=2
    RETURNING version::text
  `;
  assert.equal(later[0]?.version, "3");

  const replay = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveAlertInvestigation(
        transaction,
        uuid(2320),
        operation,
        fixture.task,
        2,
        key,
        request,
      ),
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.command_id, commandID);
  assert.deepEqual(
    replay.result_snapshot,
    snapshot,
    "Alert task replay followed the later live task version",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      reserveAlertInvestigation(
        transaction,
        uuid(2321),
        operation,
        fixture.task,
        2,
        key,
        digest("alert-task-comments-divergent"),
      ),
    ),
    "23505",
    "Alert task comment replay accepted a divergent request",
  );

  const [effects] = await primary<
    { activities: string; audits: string; outbox: string }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.ticket_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND alert_id=${fixture.alert}::uuid
         AND kind='alert.task.comments_replaced'
         AND details->>'resourceId'=${fixture.task}) AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND action='dfir.alert.task.comments.replace'
         AND resource_id=${fixture.task}::uuid) AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND event_type='alert.task.comments_replaced.v1'
         AND aggregate_id=${fixture.task}::uuid) AS outbox
  `;
  assert.deepEqual(effects, { activities: "1", audits: "1", outbox: "1" });

  await primary`
    INSERT INTO public.tenant_membership_role_grants(
      id,tenant_id,membership_id,role_id,source_id,
      granted_by_membership_id,grant_reason
    )
    SELECT ${uuid(2330)}::uuid,${fixture.tenant}::uuid,
           ${fixture.peerMembership}::uuid,role.id,source.id,
           ${fixture.adminMembership}::uuid,
           'Preserve a recovery administrator while testing replay revocation'
    FROM public.tenant_roles AS role
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id=role.tenant_id
     AND source.key='manual' AND source.retired_at IS NULL
    WHERE role.tenant_id=${fixture.tenant}::uuid
      AND role.key='tenant_admin' AND role.system_role
  `;
  await primary`
    UPDATE public.tenant_memberships
    SET status='suspended'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.adminMembership}::uuid
  `;
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      reserveAlertInvestigation(
        transaction,
        uuid(2322),
        operation,
        fixture.task,
        2,
        key,
        request,
      ),
    ),
    "42501",
    "revoked actor recovered the immutable Alert task replay snapshot",
  );
}

async function runAlertEvidenceLifecycle(): Promise<void> {
  const collectedAt = new Date(Date.now() - 2_000);
  const [hashes] = await primary<{ anchor: Buffer; event: Buffer }[]>`
    SELECT anchor,
           app.private_dfir_custody_hash_v1(
             anchor, ${uuid(1602)}::uuid, ${fixture.tenant}::uuid,
             ${fixture.evidence}::uuid, 1, 'collected',
             ${fixture.adminUser}::uuid, 'initial collection', '',
             ${collectedAt}::timestamptz
           ) AS event
    FROM (
      SELECT app.private_alert_dfir_anchor_hash_v1(
        ${fixture.evidence}::uuid, ${fixture.tenant}::uuid,
        ${fixture.alert}::uuid, ${fixture.storage}::uuid,
        'Memory image', '', 'memory_image', 'internal',
        ${digest("evidence-content")}, 'application/octet-stream',
        'endpoint_sensor', 32, ${collectedAt}::timestamptz,
        ${fixture.adminMembership}::uuid, 'available', NULL, false
      ) AS anchor
    ) AS computed
  `;
  assert(hashes, "evidence hashes were not computed");
  const createKey = digest("alert-evidence-create-key");
  const createRequest = digest("alert-evidence-create-request");
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1601),
        "dfir.alert.evidence.create",
        fixture.evidence,
        1,
        createKey,
        createRequest,
      );
      assert.equal(reservation.replayed, false);
      const [created] = await transaction<
        { evidence_id: string; evidence_version: string }[]
      >`
      SELECT evidence_id::text, evidence_version::text
      FROM app.create_alert_dfir_evidence_v1(
        ${reservation.command_id}::uuid, ${fixture.evidence}::uuid,
        ${fixture.alert}::uuid, ${fixture.storage}::uuid, 'Memory image',
        '', 'memory_image', 'internal', ${collectedAt}::timestamptz,
        'endpoint_sensor', NULL, false, ${uuid(1602)}::uuid,
        ${hashes.anchor}, ${hashes.event}
      )
    `;
      assert.equal(created?.evidence_id, fixture.evidence);
      assert.equal(created?.evidence_version, "1");
      await appendInvestigationEffects(transaction, {
        operation: "dfir.alert.evidence.create",
        activityType: "alert.evidence.added",
        auditAction: "dfir.alert.evidence.create",
        auditReason: "collect volatile memory",
        outboxType: "alert.evidence.added.v1",
        resourceType: "dfir_evidence",
        resourceID: fixture.evidence,
        version: 1,
        key: createKey,
        request: createRequest,
        activityID: uuid(1603),
        auditID: uuid(1604),
        outboxID: uuid(1605),
        requestID: uuid(1606),
        correlationID: uuid(1607),
      });
      await transaction`
      SELECT app.store_alert_investigation_command_result_v1(
        ${reservation.command_id}::uuid,
        jsonb_build_object(
          'kind','alert_evidence','evidence',jsonb_build_object(
            'tenantId',${fixture.tenant}::text,'alertId',${fixture.alert}::text,
            'id',${fixture.evidence}::text,'version',1
          )
        )
      )
    `;
    },
  );

  const replay = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveAlertInvestigation(
        transaction,
        uuid(1608),
        "dfir.alert.evidence.create",
        fixture.evidence,
        1,
        createKey,
        createRequest,
      ),
  );
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.result_snapshot, {
    kind: "alert_evidence",
    evidence: {
      tenantId: fixture.tenant,
      alertId: fixture.alert,
      id: fixture.evidence,
      version: 1,
    },
  });

  const [head] = await primary<{ event_hash: Buffer }[]>`
    SELECT event_hash FROM public.dfir_custody_events
    WHERE tenant_id=${fixture.tenant}::uuid AND evidence_id=${fixture.evidence}::uuid
      AND sequence=1
  `;
  assert(head);
  const occurredAt = new Date();
  const [nextHash] = await primary<{ value: Buffer }[]>`
    SELECT app.private_dfir_custody_hash_v1(
      ${head.event_hash}, ${fixture.custody}::uuid, ${fixture.tenant}::uuid,
      ${fixture.evidence}::uuid, 2, 'accessed', ${fixture.adminUser}::uuid,
      'forensic review', '', ${occurredAt}::timestamptz
    ) AS value
  `;
  assert(nextHash);
  const custodyKey = digest("alert-custody-key");
  const custodyRequest = digest("alert-custody-request");
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1610),
        "dfir.alert.evidence.custody.append",
        fixture.evidence,
        2,
        custodyKey,
        custodyRequest,
      );
      const [updated] = await transaction<
        { evidence_id: string; evidence_version: string }[]
      >`
      SELECT evidence_id::text, evidence_version::text
      FROM app.append_alert_dfir_custody_event_v1(
        ${reservation.command_id}::uuid, ${fixture.evidence}::uuid,
        ${fixture.alert}::uuid, 1, ${fixture.custody}::uuid,
        'accessed', 'forensic review', '',
        ${head.event_hash}, ${nextHash.value}, ${occurredAt}::timestamptz
      )
    `;
      assert.equal(updated?.evidence_version, "2");
      await appendInvestigationEffects(transaction, {
        operation: "dfir.alert.evidence.custody.append",
        activityType: "alert.evidence.custody_appended",
        auditAction: "dfir.alert.evidence.custody.append",
        auditReason: "forensic review",
        outboxType: "alert.evidence.custody_appended.v1",
        resourceType: "dfir_evidence",
        resourceID: fixture.evidence,
        version: 2,
        key: custodyKey,
        request: custodyRequest,
        activityID: uuid(1611),
        auditID: uuid(1612),
        outboxID: uuid(1613),
        requestID: uuid(1614),
        correlationID: uuid(1615),
      });
      await transaction`
      SELECT app.store_alert_investigation_command_result_v1(
        ${reservation.command_id}::uuid,
        jsonb_build_object(
          'kind','alert_evidence','evidence',jsonb_build_object(
            'tenantId',${fixture.tenant}::text,'alertId',${fixture.alert}::text,
            'id',${fixture.evidence}::text,'version',2
          )
        )
      )
    `;
    },
  );
  const [attribution] = await primary<
    {
      actor_id: string;
      actor_membership_id: string;
      actor_user_id: string;
      reason: string;
    }[]
  >`
    SELECT event.actor_id::text,event.actor_membership_id::text,
           event.actor_user_id::text,audit.reason
    FROM public.dfir_custody_events AS event
    JOIN public.audit_events AS audit
      ON audit.tenant_id=event.tenant_id
     AND audit.id=${uuid(1612)}::uuid
    WHERE event.tenant_id=${fixture.tenant}::uuid
      AND event.id=${fixture.custody}::uuid
  `;
  assert.equal(attribution?.actor_id, fixture.adminUser);
  assert.equal(attribution?.actor_user_id, fixture.adminUser);
  assert.equal(attribution?.actor_membership_id, fixture.adminMembership);
  assert.equal(attribution?.reason, "forensic review");

  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      await transaction`
      INSERT INTO public.dfir_timeline_events (
        id,tenant_id,alert_id,case_id,event_time,ingested_at,
        original_timezone,precision,source,category,title,description,tags,
        created_by_membership_id,version
      ) VALUES (
        ${uuid(1618)}::uuid,${fixture.tenant}::uuid,${fixture.alert}::uuid,NULL,
        transaction_timestamp(),transaction_timestamp(),'UTC','millisecond',
        'manual','investigation','Evidence acquired','',ARRAY[]::text[],
        ${fixture.adminMembership}::uuid,1
      )
    `;
      await transaction`
      INSERT INTO public.dfir_timeline_evidence_links (
        tenant_id,timeline_event_id,evidence_id
      ) VALUES (
        ${fixture.tenant}::uuid,${uuid(1618)}::uuid,${fixture.evidence}::uuid
      )
    `;
    },
  );

  const transitionedAt = new Date(Date.now() + 10);
  await expectSqlState(
    primary.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction`
        SELECT set_config('app.tenant_id',${fixture.tenant},true),
               set_config('app.user_id','',true)
      `;
      return transaction`
        SELECT * FROM app.advance_dfir_storage_object_as_worker_v3(
          ${fixture.storage}::uuid,1,'deleted',${digest("evidence-content")},
          32,'application/octet-stream',${transitionedAt}::timestamptz,
          ${uuid(1620)}::uuid,${uuid(1621)}::uuid,${uuid(1622)}::uuid,
          ${uuid(1623)}::uuid,${uuid(1624)}::uuid
        )
      `;
    }),
    "42501",
    "worker retained the superseded direct storage transition ABI",
  );
  const [destroyed] = await primary<
    {
      custody_count: string;
      destroyed: boolean;
      evidence_state: string;
      storage_state: string;
      storage_version: string;
      version: string;
    }[]
  >`
    SELECT evidence.destroyed,evidence.version::text,
           evidence.scan_state::text AS evidence_state,
           storage.state::text AS storage_state,
           storage.version::text AS storage_version,
           (SELECT count(*)::text
            FROM public.dfir_custody_events AS event
            WHERE event.tenant_id=evidence.tenant_id
              AND event.evidence_id=evidence.id
              AND event.sequence=3) AS custody_count
    FROM public.dfir_evidence AS evidence
    JOIN public.dfir_storage_objects AS storage
      ON storage.tenant_id=evidence.tenant_id
     AND storage.id=evidence.storage_object_id
    WHERE evidence.tenant_id=${fixture.tenant}::uuid
      AND evidence.id=${fixture.evidence}::uuid
  `;
  assert.equal(destroyed?.destroyed, false);
  assert.equal(destroyed?.version, "2");
  assert.equal(destroyed?.evidence_state, "available");
  assert.equal(destroyed?.storage_state, "available");
  assert.equal(destroyed?.storage_version, "1");
  assert.equal(destroyed?.custody_count, "0");
}

async function runAlertRelationshipLifecycle(): Promise<void> {
  const createdAt = new Date(Date.now() - 1_000);
  const createKey = digest("alert-relationship-create-key");
  const createRequest = digest("alert-relationship-create-request");
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1701),
        "dfir.alert.relationship.create",
        fixture.relationship,
        1,
        createKey,
        createRequest,
      );
      const [created] = await transaction<{ relationship_id: string }[]>`
      SELECT relationship_id::text
      FROM app.create_alert_dfir_relationship_v1(
        ${reservation.command_id}::uuid,${fixture.relationship}::uuid,
        ${fixture.alert}::uuid,'alert',${fixture.alert}::uuid,NULL,NULL,
        'external',NULL,'url','https://example.invalid/artifact','references',
        '{"confidence":"high"}'::jsonb,${createdAt}::timestamptz
      )
    `;
      assert.equal(created?.relationship_id, fixture.relationship);
      await appendInvestigationEffects(transaction, {
        operation: "dfir.alert.relationship.create",
        activityType: "alert.relationship.created",
        auditAction: "dfir.alert.relationship.create",
        auditReason: "link external artifact",
        outboxType: "alert.relationship.created.v1",
        resourceType: "dfir_relationship",
        resourceID: fixture.relationship,
        version: 1,
        key: createKey,
        request: createRequest,
        activityID: uuid(1702),
        auditID: uuid(1703),
        outboxID: uuid(1704),
        requestID: uuid(1705),
        correlationID: uuid(1706),
      });
      await transaction`
      SELECT app.store_alert_investigation_command_result_v1(
        ${reservation.command_id}::uuid,
        ${transaction.json({
          kind: "alert_relationship",
          relationship: {
            id: fixture.relationship,
            tenantId: fixture.tenant,
            alertId: fixture.alert,
            source: { kind: "alert", id: fixture.alert },
            target: {
              kind: "external",
              externalType: "url",
              externalId: "https://example.invalid/artifact",
            },
            relationshipType: "references",
            metadata: { confidence: "high" },
            createdBy: fixture.adminMembership,
            createdAt: createdAt.toISOString(),
            version: 1,
            retractions: [],
          },
        })}::jsonb
      )
    `;
    },
  );
  await expectSqlState(
    primary.begin(
      (transaction) =>
        transaction`
        INSERT INTO public.dfir_relationship_retractions (
          id,tenant_id,relationship_id,alert_id,case_id,
          retracted_by_membership_id,reason,prior_version,result_version,retracted_at
        ) VALUES (
          ${uuid(1707)}::uuid,${fixture.tenant}::uuid,
          ${fixture.relationship}::uuid,${fixture.foreignAlert}::uuid,NULL,
          ${fixture.adminMembership}::uuid,'splice',1,2,transaction_timestamp()
        )
      `,
    ),
    "23503",
    "relationship retraction accepted a spliced Alert root",
  );
  const retractKey = digest("alert-relationship-retract-key");
  const retractRequest = digest("alert-relationship-retract-request");
  const retractedAt = new Date();
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1710),
        "dfir.alert.relationship.retract",
        fixture.relationship,
        2,
        retractKey,
        retractRequest,
      );
      const [retracted] = await transaction<
        { relationship_id: string; relationship_version: string }[]
      >`
      SELECT relationship_id::text,relationship_version::text
      FROM app.retract_alert_dfir_relationship_v1(
        ${reservation.command_id}::uuid,${fixture.relationship}::uuid,
        ${fixture.alert}::uuid,1,${fixture.retraction}::uuid,
        'superseded artifact',${retractedAt}::timestamptz
      )
    `;
      assert.equal(retracted?.relationship_version, "2");
      await appendInvestigationEffects(transaction, {
        operation: "dfir.alert.relationship.retract",
        activityType: "alert.relationship.retracted",
        auditAction: "dfir.alert.relationship.retract",
        auditReason: "superseded artifact",
        outboxType: "alert.relationship.retracted.v1",
        resourceType: "dfir_relationship",
        resourceID: fixture.relationship,
        version: 2,
        key: retractKey,
        request: retractRequest,
        activityID: uuid(1711),
        auditID: uuid(1712),
        outboxID: uuid(1713),
        requestID: uuid(1714),
        correlationID: uuid(1715),
      });
      await transaction`
      SELECT app.store_alert_investigation_command_result_v1(
        ${reservation.command_id}::uuid,
        ${transaction.json({
          kind: "alert_relationship",
          relationship: {
            id: fixture.relationship,
            tenantId: fixture.tenant,
            alertId: fixture.alert,
            source: { kind: "alert", id: fixture.alert },
            target: {
              kind: "external",
              externalType: "url",
              externalId: "https://example.invalid/artifact",
            },
            relationshipType: "references",
            metadata: { confidence: "high" },
            createdBy: fixture.adminMembership,
            createdAt: createdAt.toISOString(),
            version: 2,
            retractions: [
              {
                id: fixture.retraction,
                tenantId: fixture.tenant,
                relationshipId: fixture.relationship,
                sequence: 1,
                actorId: fixture.adminMembership,
                reason: "superseded artifact",
                occurredAt: retractedAt.toISOString(),
              },
            ],
          },
        })}::jsonb
      )
    `;
    },
  );
  const [retraction] = await primary<
    { alert_id: string; actor_id: string; version: string }[]
  >`
    SELECT retraction.alert_id::text,
           retraction.retracted_by_membership_id::text AS actor_id,
           relationship.version::text
    FROM public.dfir_relationship_retractions AS retraction
    JOIN public.dfir_relationships AS relationship
      ON relationship.tenant_id=retraction.tenant_id
     AND relationship.id=retraction.relationship_id
    WHERE retraction.tenant_id=${fixture.tenant}::uuid
      AND retraction.id=${fixture.retraction}::uuid
  `;
  assert.equal(retraction?.alert_id, fixture.alert);
  assert.equal(retraction?.actor_id, fixture.adminMembership);
  assert.equal(retraction?.version, "2");
}

try {
  await setup();

  const [ready] = await primary<{ ready: boolean }[]>`
    SELECT app.alert_dfir_runtime_schema_readiness_v2() AS ready
  `;
  assert.equal(ready?.ready, true, "Alert DFIR readiness is false");

  await verifyGenericReceiptNullPoison();
  await verifyOperatorDownloadGrantAuditing();

  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`SELECT * FROM public.alert_dfir_resource_commands`,
    ),
    "42501",
    "API retained direct receipt-table access",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`SELECT * FROM public.alert_dfir_resource_command_results`,
    ),
    "42501",
    "API retained direct command-result access",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`
        UPDATE public.dfir_relationships SET version = version + 1
        WHERE tenant_id = ${fixture.tenant}::uuid
      `,
    ),
    "42501",
    "API retained direct relationship update access",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`
        SELECT * FROM app.advance_dfir_storage_object_as_worker_v3(
          ${fixture.storage}::uuid,1,'deleted',${digest("evidence-content")},
          32,'application/octet-stream',transaction_timestamp(),
          ${uuid(1003)}::uuid,${uuid(1004)}::uuid,${uuid(1005)}::uuid,
          ${uuid(1006)}::uuid,${uuid(1007)}::uuid
        )
      `,
    ),
    "42501",
    "API executed the worker-only storage transition",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      reserveAlertInvestigation(
        transaction,
        uuid(1008),
        "dfir.alert.task.create",
        uuid(1009),
        1,
        digest("missing-result-key"),
        digest("missing-result-request"),
      ),
    ),
    "23514",
    "fresh Alert investigation command committed without a result snapshot",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (transaction) => {
      const resourceID = uuid(1010);
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1011),
        "dfir.alert.task.create",
        resourceID,
        1,
        digest("oversized-result-key"),
        digest("oversized-result-request"),
      );
      await transaction`
        SELECT app.store_alert_investigation_command_result_v1(
          ${reservation.command_id}::uuid,
          jsonb_build_object(
            'kind','alert_task','task',jsonb_build_object(
              'tenantId',${fixture.tenant}::text,
              'alertId',${fixture.alert}::text,
              'id',${resourceID}::text,'version',1
            ),
            'padding',repeat('x',16777216)
          )
        )
      `;
    }),
    "22023",
    "compressible result exceeded the logical 16 MiB snapshot bound",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (transaction) => {
      const resourceID = uuid(1012);
      const reservation = await reserveAlertInvestigation(
        transaction,
        uuid(1013),
        "dfir.alert.relationship.create",
        resourceID,
        1,
        digest("oversized-metadata-key"),
        digest("oversized-metadata-request"),
      );
      await transaction`
        SELECT * FROM app.create_alert_dfir_relationship_v1(
          ${reservation.command_id}::uuid,${resourceID}::uuid,
          ${fixture.alert}::uuid,'alert',${fixture.alert}::uuid,NULL,NULL,
          'external',NULL,'url','https://example.invalid/oversized',
          'references',jsonb_build_object('padding',repeat('x',65536)),
          transaction_timestamp()
        )
      `;
    }),
    "23514",
    "compressible relationship metadata exceeded the logical 64 KiB bound",
  );
  await expectSqlState(
    primary.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction`
        SELECT * FROM app.reserve_alert_dfir_resource_command_v1(
          ${uuid(1101)}::uuid, ${fixture.alert}::uuid, 'dfir.ioc.create',
          ${uuid(1102)}::uuid, 1, ${digest("worker-key")},
          ${digest("worker-request")}
        )
      `;
      return {};
    }),
    "42501",
    "worker executed the API-only reservation",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.peerUser,
      (transaction) =>
        transaction`
        SELECT * FROM app.reserve_dfir_mutation_command_v1(
          ${uuid(1201)}::uuid,'alert',${fixture.alert}::uuid,
          'dfir.ioc.create','ioc',${uuid(1202)}::uuid,NULL,1,
          ${digest("peer-key")},
          ${digest("peer-request")}
        )
      `,
    ),
    "42501",
    "unprivileged human reserved an Alert DFIR command",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.foreignTenant,
      fixture.foreignUser,
      (transaction) =>
        transaction`
        SELECT * FROM app.reserve_dfir_mutation_command_v1(
          ${uuid(1301)}::uuid,'alert',${fixture.alert}::uuid,
          'dfir.ioc.create','ioc',${uuid(1302)}::uuid,NULL,1,
          ${digest("foreign-key")},
          ${digest("foreign-request")}
        )
      `,
    ),
    "42501",
    "cross-tenant reservation disclosed the Alert",
  );
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`
        SELECT * FROM app.reserve_dfir_mutation_command_v1(
          ${uuid(1401)}::uuid,'alert',${fixture.alert}::uuid,
          'dfir.unknown','ioc',${uuid(1402)}::uuid,NULL,1,
          ${digest("unknown-key")},
          ${digest("unknown-request")}
        )
      `,
    ),
    "22023",
    "unknown command operation was accepted",
  );

  await runConcurrentCreate();
  await runAlertRelationshipLifecycle();
  await runAlertEvidenceLifecycle();

  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        transaction`
        SELECT * FROM app.reserve_dfir_mutation_command_v1(
          ${uuid(1501)}::uuid,'alert',${fixture.alert}::uuid,
          'dfir.ioc.create','ioc',${fixture.ioc}::uuid,NULL,1,
          ${digest("key")},
          ${digest("divergent-request")}
        )
      `,
    ),
    "23505",
    "divergent idempotency replay was accepted",
  );

  const [effects] = await primary<
    {
      activities: string;
      audits: string;
      outbox: string;
      payload_keys: string[];
      leaked: boolean;
    }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.ticket_activities
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND alert_id = ${fixture.alert}::uuid
         AND kind = 'dfir.ioc.created') AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND action = 'dfir.ioc.created'
         AND resource_id = ${fixture.ioc}::uuid) AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND event_type = 'dfir.ioc.created'
         AND aggregate_id = ${fixture.ioc}::uuid) AS outbox,
      (SELECT array_agg(key ORDER BY key)
       FROM public.outbox_events AS event,
            LATERAL jsonb_object_keys(event.payload) AS key
       WHERE event.tenant_id = ${fixture.tenant}::uuid
         AND event.event_type = 'dfir.ioc.created'
         AND event.aggregate_id = ${fixture.ioc}::uuid) AS payload_keys,
      EXISTS (
        SELECT 1 FROM public.audit_events AS event
        WHERE event.tenant_id = ${fixture.tenant}::uuid
          AND event.action = 'dfir.ioc.created'
          AND (event.before::text LIKE '%must-never-leak%'
            OR event.after::text LIKE '%must-never-leak%'
            OR event.metadata::text LIKE '%must-never-leak%')
      ) OR EXISTS (
        SELECT 1 FROM public.ticket_activities AS activity
        WHERE activity.tenant_id = ${fixture.tenant}::uuid
          AND activity.alert_id = ${fixture.alert}::uuid
          AND activity.details::text LIKE '%must-never-leak%'
      ) OR EXISTS (
        SELECT 1 FROM public.outbox_events AS event
        WHERE event.tenant_id = ${fixture.tenant}::uuid
          AND event.event_type = 'dfir.ioc.created'
          AND event.payload::text LIKE '%must-never-leak%'
      ) AS leaked
  `;
  assert(effects);
  assert.equal(effects.activities, "1");
  assert.equal(effects.audits, "1");
  assert.equal(effects.outbox, "1");
  assert.deepEqual(effects.payload_keys, [
    "alertId",
    "resourceId",
    "resourceVersion",
    "tenantId",
  ]);
  assert.equal(effects.leaked, false, "sensitive resource values leaked");

  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      await transaction`
      INSERT INTO public.dfir_timeline_events (
        id, tenant_id, alert_id, case_id, event_time, ingested_at,
        original_timezone, precision, source, category, title, description,
        tags, created_by_membership_id, version
      ) VALUES (
        ${fixture.timeline}::uuid, ${fixture.tenant}::uuid,
        ${fixture.alert}::uuid, NULL, transaction_timestamp(),
        transaction_timestamp(), 'UTC', 'millisecond', 'manual',
        'investigation', 'Alert timeline event', '', ARRAY[]::text[],
        ${fixture.adminMembership}::uuid, 1
      )
    `;
      await transaction`
      INSERT INTO public.dfir_timeline_ioc_links (
        tenant_id, timeline_event_id, ioc_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.timeline}::uuid,
        ${fixture.ioc}::uuid
      )
    `;
      await expectSqlState(
        transaction.savepoint(
          (nested) => nested`
        INSERT INTO public.dfir_timeline_evidence_links (
          tenant_id, timeline_event_id, evidence_id
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.timeline}::uuid,
          ${fixture.timelineEvidence}::uuid
        )
      `,
        ),
        "23503",
        "Alert timeline accepted evidence outside the same live Alert root",
      );
    },
  );
  await runAlertTaskCommentsLifecycle();
} finally {
  await Promise.all([
    primary.end({ timeout: 5 }),
    contender.end({ timeout: 5 }),
  ]);
}
