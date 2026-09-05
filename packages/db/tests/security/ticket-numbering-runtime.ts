import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql, type TransactionSql } from "postgres";

type PgError = Error & { code?: string; constraint_name?: string };
type Kind = "alert" | "case";
type Period = "annual" | "lifetime";
type PolicyRow = {
  replayed?: boolean;
  version_id: string;
  tenant_id: string;
  aggregate_kind: Kind;
  version: number;
  prefix: string;
  separator: string;
  period: Period;
  width: number;
  start: string | number;
  published_by_membership_id: string | null;
  published_at: Date;
};
type SLAClaim = {
  occurrence_id: string;
  action_kind: string;
  fence: string;
  claimed_at: Date;
};

const databaseUrl = process.env.PERIAPSIS_TICKET_NUMBERING_TEST_DATABASE_URL;
if (!databaseUrl?.trim()) {
  throw new Error(
    "PERIAPSIS_TICKET_NUMBERING_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7800-2400-7000-8000-${(sequence + BigInt(offset)).toString(16).padStart(12, "0")}`;
const ids = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  suspendedTenant: uuid(3),
  futureSuspendedTenant: uuid(4),
  admin: uuid(101),
  viewer: uuid(102),
  foreignAdmin: uuid(103),
  adminMembership: uuid(201),
  viewerMembership: uuid(202),
  foreignMembership: uuid(203),
  suspendedMembership: uuid(204),
  serviceAccount: uuid(205),
  serviceRoleGrant: uuid(206),
  serviceCredential: uuid(207),
  adminSession: uuid(301),
  viewerSession: uuid(302),
  foreignSession: uuid(303),
  adminFamily: uuid(311),
  viewerFamily: uuid(312),
  foreignFamily: uuid(313),
  directAlert: uuid(401),
  directCase: uuid(402),
  rollbackCase: uuid(403),
  annualCaseOne: uuid(404),
  annualCaseTwo: uuid(405),
  lifetimeCaseOne: uuid(406),
  namespaceCase: uuid(407),
  otherNamespaceCase: uuid(408),
  reactivatedNamespaceCase: uuid(409),
  exhaustedCase: uuid(410),
  exhaustedFailureCase: uuid(411),
  suspendedAllocation: uuid(412),
  caseViaABI: uuid(413),
  escalationSource: uuid(414),
  escalationCase: uuid(415),
  existingEscalationSource: uuid(416),
  linkSource: uuid(417),
  escalationLink: uuid(418),
  existingEscalationLink: uuid(419),
  correlationLink: uuid(420),
  futureSkewAlert: uuid(421),
  slaPolicy: uuid(501),
  slaMetricDefinition: uuid(502),
  slaTriggerDefinition: uuid(503),
  slaInstance: uuid(504),
  slaMetricInstance: uuid(505),
  slaAssignmentEvent: uuid(506),
  slaOccurrence: uuid(507),
  slaWorker: uuid(508),
  slaRequest: uuid(509),
  slaCorrelation: uuid(510),
} as const;

const suffix = sequence.toString(36);
const escalationLinkedAt = new Date();
let dynamicID = 1_000;
const nextID = (): string => uuid(++dynamicID);
const database = postgres(databaseUrl, { max: 16, onnotice: () => undefined });
const first = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-numbering-runtime:${suffix}:${label}`)
    .digest();
}

function namespaceDigest(
  prefix: string,
  separator: string,
  period: Period,
  width: number,
): Buffer {
  const kernelPeriod = period === "lifetime" ? "none" : "annual";
  return createHash("sha256")
    .update(
      `periapsis/ticket-numbering/namespace/v1\0${prefix}\0${separator}\0${kernelPeriod}\0${width}`,
    )
    .digest();
}

const slaPolicyDocument = {
  key: "numbering-system-alert",
  name: "Numbering system Alert runtime",
  description: "Exercises the SLA system Alert numbering call site",
  priority: 0,
  object_types: ["alert"],
  match_rule: {},
  effective_from: "2026-01-01T00:00:00.000000Z",
  effective_until: null,
  enabled: true,
  apply_to_sla_engine_source: false,
  revision_digest: digest("sla-policy-revision").toString("hex"),
  metrics: [
    {
      id: ids.slaMetricDefinition,
      key: "numbering-response-time",
      label: "Numbering response time",
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
      definition_digest: digest("sla-metric-definition").toString("hex"),
    },
  ],
  triggers: [
    {
      id: ids.slaTriggerDefinition,
      metric_definition_id: ids.slaMetricDefinition,
      key: "numbering-create-system-alert",
      kind: "due",
      consumed_percent: null,
      remaining_micros: null,
      offset_micros: null,
      repeat_interval_micros: null,
      target_state: null,
      action_kind: "create_system_alert",
      action_configuration_id: null,
      action_value: "sla.runtime",
      allow_recursive_sla: true,
      position: 0,
      definition_digest: digest("sla-trigger-definition").toString("hex"),
    },
  ],
} as const;

function assertSqlState(
  error: unknown,
  code: string,
  constraint?: string,
): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  const sqlError = error as PgError;
  assert.equal(sqlError.code, code, sqlError.message);
  if (constraint !== undefined) {
    assert.equal(sqlError.constraint_name, constraint, sqlError.message);
  }
  return true;
}

async function rejects(
  operation: Promise<unknown>,
  code: string,
  message: string,
  constraint?: string,
): Promise<void> {
  await assert.rejects(
    operation,
    (error: unknown) => assertSqlState(error, code, constraint),
    message,
  );
}

async function setContext(
  transaction: TransactionSql,
  role:
    | "periapsis_api"
    | "periapsis_migrator"
    | "periapsis_worker"
    | "periapsis_sla_worker_owner",
  tenantID: string,
  userID?: string,
): Promise<void> {
  await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
  await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
  await transaction`
    SELECT set_config('app.tenant_id',${tenantID},true),
           set_config('app.user_id',${userID ?? ""},true),
           set_config('app.service_account_id','',true),
           set_config(
             'app.traceparent',
             '00-11111111111111111111111111111111-2222222222222222-01',
             true
           ),
           set_config('app.tracestate','numbering=runtime',true)
  `;
}

async function asRole<T>(
  connection: Sql,
  role:
    | "periapsis_api"
    | "periapsis_migrator"
    | "periapsis_worker"
    | "periapsis_sla_worker_owner",
  tenantID: string,
  userID: string | undefined,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await connection.begin(async (transaction) => {
    await setContext(transaction, role, tenantID, userID);
    return { value: await operation(transaction) };
  });
  return result.value;
}

const asApi = <T>(
  connection: Sql,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> =>
  asRole(connection, "periapsis_api", tenantID, userID, operation);

async function insertSession(
  transaction: TransactionSql,
  id: string,
  familyID: string,
  userID: string,
  tenantID: string,
  label: string,
  createdAt: Date,
): Promise<void> {
  await transaction`
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${id}::uuid,${userID}::uuid,${familyID}::uuid,${tenantID}::uuid,
      ${digest(`${label}:token`)}::bytea,${digest(`${label}:csrf`)}::bytea,
      'totp',${createdAt},${createdAt},
      ${new Date(createdAt.getTime() + 60 * 60_000)},
      ${new Date(createdAt.getTime() + 2 * 60 * 60_000)},${createdAt}
    )
  `;
}

async function readPolicy(
  connection: Sql,
  tenantID: string,
  userID: string,
  sessionID: string,
  kind: Kind,
): Promise<PolicyRow> {
  return asApi(connection, tenantID, userID, async (transaction) => {
    const [row] = await transaction<PolicyRow[]>`
      SELECT * FROM app.get_tenant_ticket_numbering_policy_v1(
        ${sessionID}::uuid,'totp',${kind}::public.ticket_aggregate_kind
      )
    `;
    assert(row, "numbering policy read returned no row");
    return row;
  });
}

type Replacement = {
  expectedVersion: number;
  kind: Kind;
  prefix: string;
  separator: string;
  period: Period;
  width: number;
  start: number;
  key: string;
  request: string;
  reason?: string;
  publishedAt?: Date;
};

async function replacePolicy(
  connection: Sql,
  input: Replacement,
): Promise<PolicyRow & { replayed: boolean }> {
  return asApi(
    connection,
    ids.tenant,
    ids.admin,
    async (transaction): Promise<PolicyRow & { replayed: boolean }> => {
      const key = digest(`command:${input.key}`);
      const request = digest(`request:${input.request}`);
      const [prepared] = await transaction<PolicyRow[]>`
        SELECT * FROM app.prepare_replace_tenant_ticket_numbering_policy_v1(
          ${ids.adminSession}::uuid,'totp',
          ${input.kind}::public.ticket_aggregate_kind,
          ${key}::bytea,${request}::bytea
        )
      `;
      assert(prepared, "numbering policy prepare returned no row");
      if (prepared.replayed) {
        return { ...prepared, replayed: true };
      }
      const publishedAt = input.publishedAt ?? new Date();
      const [committed] = await transaction<PolicyRow[]>`
        SELECT * FROM app.commit_replace_tenant_ticket_numbering_policy_v1(
          ${ids.adminSession}::uuid,'totp',
          ${input.kind}::public.ticket_aggregate_kind,
          ${input.expectedVersion},${key}::bytea,${request}::bytea,
          ${nextID()}::uuid,${input.expectedVersion + 1},
          ${input.prefix},${input.separator},
          ${input.period}::public.ticket_numbering_period,
          ${input.width},${input.start},
          ${namespaceDigest(input.prefix, input.separator, input.period, input.width)}::bytea,
          ${publishedAt},${input.reason ?? "Approve reviewed ticket numbering"},
          ${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,
          '198.51.100.42'::inet,'Periapsis ticket numbering runtime proof'
        )
      `;
      assert(committed, "numbering policy commit returned no row");
      return { ...committed, replayed: false };
    },
  );
}

async function defaultWorkflow(
  transaction: TransactionSql,
  tenantID: string,
  kind: Kind,
): Promise<{ id: string; version: number; state: string }> {
  const [row] = await transaction<
    { id: string; version: number; state: string }[]
  >`
    SELECT workflow.id,workflow.current_version AS version,
           state.value ->> 'key' AS state
    FROM public.ticket_workflows AS workflow
    JOIN public.ticket_workflow_versions AS version
      ON version.tenant_id=workflow.tenant_id
     AND version.workflow_id=workflow.id
     AND version.aggregate_kind=workflow.aggregate_kind
     AND version.version=workflow.current_version
    CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
    WHERE workflow.tenant_id=${tenantID}::uuid
      AND workflow.aggregate_kind=${kind}::public.ticket_aggregate_kind
      AND workflow.is_default AND workflow.archived_at IS NULL
      AND (state.value ->> 'initial')::boolean
  `;
  assert(row, `default ${kind} workflow is unavailable`);
  return row;
}

async function insertDirectCase(
  connection: Sql,
  tenantID: string,
  caseID: string,
  suppliedNumber: string,
  at = new Date(),
): Promise<string> {
  return asRole(
    connection,
    "periapsis_migrator",
    tenantID,
    tenantID === ids.foreignTenant ? ids.foreignAdmin : ids.admin,
    async (transaction) => {
      const workflow = await defaultWorkflow(transaction, tenantID, "case");
      const creatorMembership =
        tenantID === ids.foreignTenant
          ? ids.foreignMembership
          : ids.adminMembership;
      const creatorUser =
        tenantID === ids.foreignTenant ? ids.foreignAdmin : ids.admin;
      const [row] = await transaction<{ number: string }[]>`
        INSERT INTO public.cases (
          id,tenant_id,number,workflow_id,workflow_version,state_key,
          title,description,summary,created_by_membership_id,created_by_user_id,
          detection_time,opened_at,created_at,updated_at
        ) VALUES (
          ${caseID}::uuid,${tenantID}::uuid,${suppliedNumber},${workflow.id}::uuid,
          ${workflow.version},${workflow.state},'Numbering runtime Case','','',
          ${creatorMembership}::uuid,${creatorUser}::uuid,
          ${at},${at},${at},${at}
        ) RETURNING number
      `;
      assert(row);
      return row.number;
    },
  );
}

async function insertDirectAlert(
  connection: Sql,
  alertID: string,
  suppliedNumber: string,
): Promise<string> {
  return asRole(
    connection,
    "periapsis_migrator",
    ids.tenant,
    ids.admin,
    async (transaction) => {
      const now = new Date();
      const [row] = await transaction<{ number: string }[]>`
        INSERT INTO public.alerts (
          id,tenant_id,number,title,description,severity,source,source_type,
          created_by,created_by_membership_id,detected_at,received_at,
          created_at,updated_at
        ) VALUES (
          ${alertID}::uuid,${ids.tenant}::uuid,${suppliedNumber},
          'Numbering runtime Alert','', 'medium','runtime','runtime',
          ${ids.admin}::uuid,${ids.adminMembership}::uuid,
          ${now},${now},${now},${now}
        ) RETURNING number
      `;
      assert(row);
      return row.number;
    },
  );
}

async function createHumanAlert(
  connection: Sql,
  keyLabel: string,
  requestLabel: string,
): Promise<{ id: string; number: string; replayed: boolean }> {
  return asApi(connection, ids.tenant, ids.admin, async (transaction) => {
    const [row] = await transaction<
      { id: string; number: string; replayed: boolean }[]
    >`
      SELECT id,number,replayed FROM app.create_tenant_alert_as_human_v3(
        'Human numbering runtime Alert','',NULL,'medium'::public.alert_severity,
        'runtime','runtime',NULL,'{}'::jsonb,'medium','general',NULL,NULL,
        false,ARRAY[]::text[],'{}'::jsonb,NULL,NULL,NULL,
        ${digest(keyLabel)}::bytea,${digest(requestLabel)}::bytea,
        ${nextID()}::uuid,${nextID()}::uuid,'198.51.100.42'::inet,
        'Periapsis ticket numbering runtime proof','totp',
        '00-11111111111111111111111111111111-2222222222222222-01',
        'numbering=runtime'
      )
    `;
    assert(row);
    return row;
  });
}

async function createServiceAlert(
  connection: Sql,
  keyLabel: string,
  requestLabel: string,
): Promise<{ id: string; number: string; replayed: boolean }> {
  const result = await connection.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    const [row] = await transaction<
      { id: string; number: string; replayed: boolean }[]
    >`
      SELECT id,number,replayed
      FROM app.create_tenant_alert_as_service_account_v3(
        ${ids.tenant}::uuid,${Buffer.alloc(16, 0x71)}::bytea,71,
        ${digest("service-secret")}::bytea,'198.51.100.43'::inet,
        'Service numbering runtime Alert','',NULL,
        'high'::public.alert_severity,'service_account','runtime',NULL,
        '{}'::jsonb,'medium','general',NULL,NULL,false,
        ARRAY[]::text[],'{}'::jsonb,NULL,NULL,NULL,
        ${digest(keyLabel)}::bytea,${digest(requestLabel)}::bytea,
        ${nextID()}::uuid,${nextID()}::uuid,
        'Periapsis ticket numbering service runtime proof',
        '00-33333333333333333333333333333333-4444444444444444-01',
        'numbering=runtime'
      )
    `;
    assert(row);
    return { value: row };
  });
  return result.value;
}

async function createCaseViaABI(
  connection: Sql,
  caseID: string,
  keyLabel: string,
  requestLabel: string,
): Promise<{ case_id: string; result_version: number; replayed: boolean }> {
  return asApi(connection, ids.tenant, ids.admin, async (transaction) => {
    const workflow = await defaultWorkflow(transaction, ids.tenant, "case");
    const [row] = await transaction<
      { case_id: string; result_version: number; replayed: boolean }[]
    >`
      SELECT * FROM app.create_tenant_case_v1(
        ${caseID}::uuid,${workflow.id}::uuid,${workflow.version},
        'Case ABI numbering runtime','','','medium'::public.alert_severity,
        'medium','general',NULL,ARRAY[]::text[],'{}'::jsonb,false,NULL,
        NULL,NULL,${digest(keyLabel)}::bytea,${digest(requestLabel)}::bytea,
        ${nextID()}::uuid,${nextID()}::uuid,'198.51.100.44'::inet,
        'Periapsis ticket numbering Case ABI proof','totp'
      )
    `;
    assert(row);
    return row;
  });
}

type EscalationFunction =
  "app.commit_tenant_ticket_escalation_v4" | "app.commit_tenant_ticket_link_v1";

async function commitEscalation(
  connection: Sql,
  input: {
    functionName: EscalationFunction;
    sourceAlertID: string;
    caseID: string;
    createCase: boolean;
    linkID: string;
    expectedCaseVersion?: number;
    expectedSourceVersion?: number;
    key: string;
  },
): Promise<{
  result_case_id: string;
  result_case_version: number;
  result_path_alert_version: number;
  replayed: boolean;
}> {
  return asApi(connection, ids.tenant, ids.admin, async (transaction) => {
    const [source] = await transaction<
      {
        workflow_id: string;
        workflow_version: number;
        state_key: string;
        version: number;
      }[]
    >`
      SELECT workflow_id,workflow_version,state_key,version
      FROM public.alerts
      WHERE tenant_id=${ids.tenant}::uuid AND id=${input.sourceAlertID}::uuid
    `;
    assert(source, "escalation source Alert is missing");
    const sourceVersion = input.expectedSourceVersion ?? source.version;
    const sources = [
      {
        alertId: input.sourceAlertID,
        linkId: input.linkID,
        linkedAt: escalationLinkedAt.toISOString(),
        expectedVersion: sourceVersion,
        resultVersion: sourceVersion + 1,
        workflowId: source.workflow_id,
        workflowVersion: source.workflow_version,
        stateKey: source.state_key,
        copyFields: [],
        customFieldKeys: [],
        itemIds: {},
        publicCommentIds: [],
      },
    ];
    let target: postgres.JSONValue;
    if (input.createCase) {
      const workflow = await defaultWorkflow(transaction, ids.tenant, "case");
      target = {
        workflowId: workflow.id,
        workflowVersion: workflow.version,
        stateKey: workflow.state,
        resultVersion: 1,
        title: "Escalated numbering runtime Case",
        description: "",
        summary: "",
        severity: "medium",
        priority: "medium",
        category: "general",
        classification: null,
        tags: [],
        customFields: {},
        customerVisible: false,
        assignedTeamId: null,
        assigneeUserId: null,
      };
    } else {
      const [current] = await transaction<
        {
          workflow_id: string;
          workflow_version: number;
          state_key: string;
          version: number;
        }[]
      >`
        SELECT workflow_id,workflow_version,state_key,version
        FROM public.cases
        WHERE tenant_id=${ids.tenant}::uuid AND id=${input.caseID}::uuid
      `;
      assert(current, "existing escalation Case is missing");
      assert.equal(current.version, input.expectedCaseVersion);
      target = {
        workflowId: current.workflow_id,
        workflowVersion: current.workflow_version,
        stateKey: current.state_key,
        expectedVersion: current.version,
        resultVersion: current.version + 1,
      };
    }
    const query = `
      SELECT result_case_id,result_case_version,result_path_alert_version,replayed
      FROM ${input.functionName}(
        $1::uuid,$2::uuid,$3::boolean,$4::jsonb,$5::jsonb,$6::text,$7::text,
        $8::bytea,$9::bytea,$10::text[],$11::uuid,$12::uuid,$13::inet,$14::text,$15::text
      )
    `;
    const [envelope] = await transaction.unsafe<
      {
        source_type: string;
        source_count: number;
        source_size: number;
        source_version: number;
        case_version: number;
        key_size: number;
        request_size: number;
      }[]
    >(
      `SELECT jsonb_typeof($1::jsonb) AS source_type,
              jsonb_array_length($1::jsonb) AS source_count,
              pg_column_size($1::jsonb) AS source_size,
              uuid_extract_version($2::uuid) AS source_version,
              uuid_extract_version($3::uuid) AS case_version,
              octet_length($4::bytea) AS key_size,
              octet_length($5::bytea) AS request_size`,
      [
        transaction.json(sources),
        input.sourceAlertID,
        input.caseID,
        digest(`${input.key}:key`),
        digest(`${input.key}:request`),
      ],
    );
    assert.deepEqual(envelope, {
      source_type: "array",
      source_count: 1,
      source_size: envelope?.source_size,
      source_version: 7,
      case_version: 7,
      key_size: 32,
      request_size: 32,
    });
    assert((envelope?.source_size ?? 0) <= 1_048_576);
    const [row] = await transaction.unsafe<
      {
        result_case_id: string;
        result_case_version: number;
        result_path_alert_version: number;
        replayed: boolean;
      }[]
    >(query, [
      input.sourceAlertID,
      input.caseID,
      input.createCase,
      transaction.json(target),
      transaction.json(sources),
      input.functionName.endsWith("link_v1") ? "correlation" : "escalation",
      "Approved runtime escalation",
      digest(`${input.key}:key`),
      digest(`${input.key}:request`),
      input.functionName.endsWith("link_v1")
        ? ["activity", "audit", "sla"]
        : ["activity", "audit", "sla", "notification"],
      nextID(),
      nextID(),
      "198.51.100.45",
      "Periapsis ticket numbering escalation proof",
      "totp",
    ]);
    assert(row, "escalation commit returned no row");
    return row;
  });
}

try {
  const [server] = await database<{ major: number; migration: boolean }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major,
           to_regprocedure(
             'app.private_allocate_ticket_number_v2(uuid,public.ticket_aggregate_kind,uuid,timestamp with time zone)'
           ) IS NOT NULL AS migration
  `;
  assert.deepEqual(server, { major: 18, migration: true });

  const createdAt = new Date(Date.now() - 60_000);
  await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants(id,slug,name,status,created_at,updated_at) VALUES
        (${ids.tenant}::uuid,${`numbering-${suffix}`},'Numbering runtime','active',${createdAt},${createdAt}),
        (${ids.foreignTenant}::uuid,${`numbering-foreign-${suffix}`},'Foreign numbering runtime','active',${createdAt},${createdAt}),
        (${ids.suspendedTenant}::uuid,${`numbering-suspended-${suffix}`},'Suspended numbering runtime','suspended',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${ids.tenant}::uuid),(${ids.foreignTenant}::uuid),(${ids.suspendedTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active,created_at,updated_at) VALUES
        (${ids.admin}::uuid,${`numbering-admin-${suffix}@example.invalid`},'Numbering admin',true,${createdAt},${createdAt}),
        (${ids.viewer}::uuid,${`numbering-viewer-${suffix}@example.invalid`},'Numbering viewer',true,${createdAt},${createdAt}),
        (${ids.foreignAdmin}::uuid,${`numbering-foreign-${suffix}@example.invalid`},'Foreign numbering admin',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status,created_at,updated_at) VALUES
        (${ids.adminMembership}::uuid,${ids.tenant}::uuid,${ids.admin}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${ids.viewerMembership}::uuid,${ids.tenant}::uuid,${ids.viewer}::uuid,'analyst','active',${createdAt},${createdAt}),
        (${ids.foreignMembership}::uuid,${ids.foreignTenant}::uuid,${ids.foreignAdmin}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${ids.suspendedMembership}::uuid,${ids.suspendedTenant}::uuid,${ids.admin}::uuid,'tenant_admin','active',${createdAt},${createdAt})
    `;
    await transaction`SELECT app.seed_tenant_authorization(${ids.tenant}::uuid,${ids.adminMembership}::uuid)`;
    await transaction`SELECT app.seed_tenant_authorization(${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid)`;
    await transaction`SELECT app.seed_tenant_authorization(${ids.suspendedTenant}::uuid,${ids.suspendedMembership}::uuid)`;
    await transaction`
      INSERT INTO public.tenant_service_accounts(
        id,tenant_id,key,display_name,description,created_by_membership_id
      ) VALUES (
        ${ids.serviceAccount}::uuid,${ids.tenant}::uuid,
        'numbering_runtime','Numbering runtime collector','',
        ${ids.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_service_account_role_grants(
        id,tenant_id,service_account_id,role_id,role_principal_kind,
        source_id,granted_by_membership_id,grant_reason
      )
      SELECT ${ids.serviceRoleGrant}::uuid,${ids.tenant}::uuid,
             ${ids.serviceAccount}::uuid,role.id,'service_account',source.id,
             ${ids.adminMembership}::uuid,
             'Authorize the numbering runtime service principal'
      FROM public.tenant_roles AS role
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=role.tenant_id AND source.key='manual'
       AND source.retired_at IS NULL
      WHERE role.tenant_id=${ids.tenant}::uuid
        AND role.key='service_account' AND role.principal_kind='service_account'
    `;
    await transaction`
      INSERT INTO public.tenant_api_credentials(
        id,tenant_id,service_account_id,label,format_version,locator,
        key_version,secret_digest,issued_by_membership_id,issued_at,
        expires_at,updated_at
      ) VALUES (
        ${ids.serviceCredential}::uuid,${ids.tenant}::uuid,
        ${ids.serviceAccount}::uuid,'Numbering runtime credential',1,
        ${Buffer.alloc(16, 0x71)}::bytea,71,${digest("service-secret")}::bytea,
        ${ids.adminMembership}::uuid,${createdAt},
        ${new Date(createdAt.getTime() + 24 * 60 * 60_000)},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_api_credential_permissions(
        tenant_id,credential_id,permission_id,
        permission_service_account_allowed,scope
      )
      SELECT ${ids.tenant}::uuid,${ids.serviceCredential}::uuid,
             permission.id,true,'tenant'
      FROM public.tenant_permissions AS permission
      WHERE permission.key='alert.create' AND permission.service_account_allowed
    `;
    await insertSession(
      transaction,
      ids.adminSession,
      ids.adminFamily,
      ids.admin,
      ids.tenant,
      "admin",
      createdAt,
    );
    await insertSession(
      transaction,
      ids.viewerSession,
      ids.viewerFamily,
      ids.viewer,
      ids.tenant,
      "viewer",
      createdAt,
    );
    await insertSession(
      transaction,
      ids.foreignSession,
      ids.foreignFamily,
      ids.foreignAdmin,
      ids.foreignTenant,
      "foreign",
      createdAt,
    );
  });

  const defaults = await database<
    {
      tenant_id: string;
      aggregate_kind: Kind;
      prefix: string;
      separator: string;
      period: Period;
      width: number;
      start: string | number;
      published_by_membership_id: string | null;
    }[]
  >`
    SELECT version.tenant_id,version.aggregate_kind,version.prefix,
           version.separator,version.period,version.width,version.start,
           version.published_by_membership_id
    FROM public.tenant_ticket_numbering_policy_versions AS version
    WHERE version.tenant_id IN (
      ${ids.tenant}::uuid,${ids.foreignTenant}::uuid,${ids.suspendedTenant}::uuid
    ) AND version.version=1
    ORDER BY version.tenant_id,version.aggregate_kind
  `;
  assert.equal(
    defaults.length,
    6,
    "every active and suspended tenant needs both defaults",
  );
  for (const row of defaults) {
    assert.equal(row.published_by_membership_id, null);
    assert.deepEqual(
      row.aggregate_kind === "alert"
        ? [row.prefix, row.separator, row.period, row.width, Number(row.start)]
        : [row.prefix, row.separator, row.period, row.width, Number(row.start)],
      row.aggregate_kind === "alert"
        ? ["ALT", "-", "annual", 6, 1]
        : ["CAS", "-", "annual", 6, 1],
    );
  }

  await database`
    INSERT INTO public.tenants(id,slug,name,status) VALUES (
      ${ids.futureSuspendedTenant}::uuid,${`numbering-future-${suffix}`},
      'Future suspended numbering runtime','suspended'
    )
  `;
  const [futureSeed] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_ticket_numbering_policy_versions
    WHERE tenant_id=${ids.futureSuspendedTenant}::uuid AND version=1
  `;
  assert.equal(
    futureSeed?.count,
    2,
    "future suspended tenant was not atomically seeded",
  );

  const [security] = await database<
    {
      bypass: boolean;
      forced: boolean;
      api_select: boolean;
      api_insert: boolean;
      legacy_human: boolean;
      legacy_service: boolean;
      old_consumers: number;
    }[]
  >`
    SELECT owner.rolbypassrls AS bypass,
      bool_and(class.relforcerowsecurity) AS forced,
      has_table_privilege('periapsis_api','public.tenant_ticket_numbering_policy_versions','SELECT') AS api_select,
      has_table_privilege('periapsis_api','public.tenant_ticket_numbering_policy_versions','INSERT') AS api_insert,
      has_function_privilege(
        'periapsis_api',
        'app.create_tenant_alert_as_human_v1(text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,inet,text,text)',
        'EXECUTE'
      ) AS legacy_human,
      has_function_privilege(
        'periapsis_api',
        'app.create_tenant_alert_as_service_account_v1(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,text)',
        'EXECUTE'
      ) AS legacy_service,
      (SELECT count(*)::integer FROM pg_proc AS procedure
       JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
       WHERE namespace.nspname='app'
         AND procedure.proname <> 'private_next_ticket_number_v1'
         AND strpos(procedure.prosrc,'private_next_ticket_number_v1') > 0) AS old_consumers
    FROM pg_roles AS owner
    CROSS JOIN pg_class AS class
    WHERE owner.rolname='periapsis_ticket_numbering_owner'
      AND class.oid IN (
        'public.tenant_ticket_numbering_policy_versions'::regclass,
        'public.tenant_ticket_numbering_policies'::regclass,
        'public.tenant_ticket_numbering_receipts'::regclass,
        'public.tenant_ticket_numbering_commands'::regclass
      )
    GROUP BY owner.rolbypassrls
  `;
  assert.deepEqual(security, {
    bypass: false,
    forced: true,
    api_select: false,
    api_insert: false,
    legacy_human: false,
    legacy_service: false,
    old_consumers: 0,
  });

  const [slaLockContract] = await database<
    {
      bypass: boolean;
      account_lock: boolean;
      workflow_lock: boolean;
      version_lock: boolean;
      policies: number;
    }[]
  >`
    SELECT owner.rolbypassrls AS bypass,
      has_column_privilege(
        owner.rolname,'public.tenant_service_accounts','id','UPDATE'
      ) AS account_lock,
      has_column_privilege(
        owner.rolname,'public.ticket_workflows','id','UPDATE'
      ) AS workflow_lock,
      has_column_privilege(
        owner.rolname,'public.ticket_workflow_versions','id','UPDATE'
      ) AS version_lock,
      (SELECT count(*)::integer FROM pg_catalog.pg_policy AS policy
       WHERE policy.polname IN (
         'tenant_service_accounts_sla_action_lock_v1',
         'ticket_workflows_sla_action_lock_v1',
         'ticket_workflow_versions_sla_action_lock_v1'
       ) AND policy.polcmd='w'
         AND pg_catalog.pg_get_expr(
           policy.polwithcheck,policy.polrelid
         )='false') AS policies
    FROM pg_catalog.pg_roles AS owner
    WHERE owner.rolname='periapsis_sla_worker_owner'
  `;
  assert.deepEqual(slaLockContract, {
    bypass: false,
    account_lock: true,
    workflow_lock: true,
    version_lock: true,
    policies: 3,
  });
  await rejects(
    asRole(
      first,
      "periapsis_sla_worker_owner",
      ids.tenant,
      undefined,
      (transaction) => transaction`
        UPDATE public.tenant_service_accounts SET id=id
        WHERE tenant_id=${ids.tenant}::uuid AND key='sla_action_runtime'
      `,
    ),
    "42501",
    "SLA lock-only policy allowed direct service-account mutation",
  );
  await rejects(
    asRole(
      first,
      "periapsis_sla_worker_owner",
      ids.tenant,
      undefined,
      (transaction) => transaction`
        UPDATE public.ticket_workflows SET id=id
        WHERE tenant_id=${ids.tenant}::uuid
      `,
    ),
    "42501",
    "SLA lock-only policy allowed direct workflow mutation",
  );
  await rejects(
    asRole(
      first,
      "periapsis_sla_worker_owner",
      ids.tenant,
      undefined,
      (transaction) => transaction`
        UPDATE public.ticket_workflow_versions SET id=id
        WHERE tenant_id=${ids.tenant}::uuid
      `,
    ),
    "55000",
    "SLA lock-only policy allowed direct workflow-version mutation",
  );
  const crossTenantLocks = await asRole(
    first,
    "periapsis_sla_worker_owner",
    ids.tenant,
    undefined,
    (transaction) => transaction<{ workflow_id: string }[]>`
      SELECT workflow.id AS workflow_id
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id=workflow.tenant_id
       AND version.workflow_id=workflow.id
       AND version.version=workflow.current_version
      WHERE workflow.tenant_id=${ids.foreignTenant}::uuid
      FOR SHARE OF workflow,version
    `,
  );
  assert.equal(crossTenantLocks.length, 0);

  await rejects(
    asApi(
      first,
      ids.tenant,
      ids.admin,
      (transaction) =>
        transaction`SELECT tenant_id FROM public.tenant_ticket_numbering_policy_versions`,
    ),
    "42501",
    "API read numbering tables directly",
  );
  const initialAlert = await readPolicy(
    first,
    ids.tenant,
    ids.admin,
    ids.adminSession,
    "alert",
  );
  const initialCase = await readPolicy(
    first,
    ids.tenant,
    ids.admin,
    ids.adminSession,
    "case",
  );
  assert.equal(initialAlert.prefix, "ALT");
  assert.equal(initialCase.prefix, "CAS");
  assert.equal(initialAlert.published_by_membership_id, null);

  await rejects(
    readPolicy(first, ids.tenant, ids.viewer, ids.viewerSession, "alert"),
    "42501",
    "membership without settings.read read policy",
  );
  await rejects(
    readPolicy(first, ids.foreignTenant, ids.admin, ids.adminSession, "alert"),
    "42501",
    "session crossed active tenant",
  );

  const directAlertNumber = await insertDirectAlert(
    database,
    ids.directAlert,
    "FORGED-9999",
  );
  assert.match(directAlertNumber, /^ALT-\d{4}-\d{6}$/);
  assert.notEqual(directAlertNumber, "FORGED-9999");
  const directCaseNumber = await insertDirectCase(
    database,
    ids.tenant,
    ids.directCase,
    "FORGED/9999",
  );
  assert.match(directCaseNumber, /^CAS-\d{4}-\d{6}$/);
  assert.notEqual(directCaseNumber, "FORGED/9999");
  const [directReceipts] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_ticket_numbering_receipts
    WHERE tenant_id=${ids.tenant}::uuid
      AND aggregate_id IN (${ids.directAlert}::uuid,${ids.directCase}::uuid)
  `;
  assert.equal(
    directReceipts?.count,
    2,
    "direct ticket inserts were not ledgerized",
  );

  await rejects(
    database`UPDATE public.alerts SET number='ALT-2026-999999' WHERE id=${ids.directAlert}::uuid`,
    "55000",
    "Alert number was mutable",
  );
  await rejects(
    database`UPDATE public.cases SET number='CAS-2026-999999' WHERE id=${ids.directCase}::uuid`,
    "55000",
    "Case number was mutable",
  );

  const human = await createHumanAlert(first, "human-key", "human-request");
  assert.equal(human.replayed, false);
  assert.match(human.number, /^ALT-\d{4}-\d{6}$/);
  const [sideEffectsBeforeReplay] = await database<
    { activities: number; audit: number; outbox: number; receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_activities WHERE alert_id=${human.id}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=${human.id}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=${human.id}::uuid) AS outbox,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${human.id}::uuid) AS receipts
  `;
  const replay = await createHumanAlert(first, "human-key", "human-request");
  assert.deepEqual(replay, { ...human, replayed: true });
  const [sideEffectsAfterReplay] = await database<
    { activities: number; audit: number; outbox: number; receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_activities WHERE alert_id=${human.id}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=${human.id}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=${human.id}::uuid) AS outbox,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${human.id}::uuid) AS receipts
  `;
  assert.deepEqual(sideEffectsAfterReplay, sideEffectsBeforeReplay);
  assert.equal(sideEffectsAfterReplay?.receipts, 1);

  const serviceAlert = await createServiceAlert(
    first,
    "service-key",
    "service-request",
  );
  assert.equal(serviceAlert.replayed, false);
  assert.match(serviceAlert.number, /^ALT-\d{4}-\d{6}$/);
  const [serviceBeforeReplay] = await database<
    { activities: number; audit: number; outbox: number; receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_activities WHERE alert_id=${serviceAlert.id}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=${serviceAlert.id}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=${serviceAlert.id}::uuid) AS outbox,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${serviceAlert.id}::uuid) AS receipts
  `;
  const serviceReplay = await createServiceAlert(
    first,
    "service-key",
    "service-request",
  );
  assert.deepEqual(serviceReplay, { ...serviceAlert, replayed: true });
  const [serviceAfterReplay] = await database<
    { activities: number; audit: number; outbox: number; receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_activities WHERE alert_id=${serviceAlert.id}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=${serviceAlert.id}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=${serviceAlert.id}::uuid) AS outbox,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${serviceAlert.id}::uuid) AS receipts
  `;
  assert.deepEqual(serviceAfterReplay, serviceBeforeReplay);
  assert.equal(serviceAfterReplay?.receipts, 1);

  const caseCreated = await createCaseViaABI(
    first,
    ids.caseViaABI,
    "case-abi-key",
    "case-abi-request",
  );
  assert.deepEqual(caseCreated, {
    case_id: ids.caseViaABI,
    result_version: 1,
    replayed: false,
  });
  const [caseABIState] = await database<
    {
      number: string;
      receipts: number;
      activities: number;
      audit: number;
      outbox: number;
    }[]
  >`
    SELECT case_row.number,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=case_row.id) AS receipts,
      (SELECT count(*)::integer FROM public.ticket_activities WHERE case_id=case_row.id) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=case_row.id) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=case_row.id) AS outbox
    FROM public.cases AS case_row WHERE case_row.id=${ids.caseViaABI}::uuid
  `;
  assert.match(caseABIState?.number ?? "", /^CAS-\d{4}-\d{6}$/);
  assert.equal(caseABIState?.receipts, 1);
  assert((caseABIState?.activities ?? 0) >= 1);
  assert((caseABIState?.audit ?? 0) >= 1);
  assert((caseABIState?.outbox ?? 0) >= 1);
  const caseReplay = await createCaseViaABI(
    first,
    ids.caseViaABI,
    "case-abi-key",
    "case-abi-request",
  );
  assert.equal(caseReplay.replayed, true);
  const [caseABIReplayState] = await database<
    { receipts: number; activities: number; audit: number; outbox: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${ids.caseViaABI}::uuid) AS receipts,
      (SELECT count(*)::integer FROM public.ticket_activities WHERE case_id=${ids.caseViaABI}::uuid) AS activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE resource_id=${ids.caseViaABI}::uuid) AS audit,
      (SELECT count(*)::integer FROM public.outbox_events WHERE aggregate_id=${ids.caseViaABI}::uuid) AS outbox
  `;
  assert.deepEqual(caseABIReplayState, {
    receipts: caseABIState?.receipts ?? 0,
    activities: caseABIState?.activities ?? 0,
    audit: caseABIState?.audit ?? 0,
    outbox: caseABIState?.outbox ?? 0,
  });

  await insertDirectAlert(database, ids.escalationSource, "FORGED");
  const escalated = await commitEscalation(first, {
    functionName: "app.commit_tenant_ticket_escalation_v4",
    sourceAlertID: ids.escalationSource,
    caseID: ids.escalationCase,
    createCase: true,
    linkID: ids.escalationLink,
    expectedSourceVersion: 1,
    key: "new-case-escalation",
  });
  assert.deepEqual(escalated, {
    result_case_id: ids.escalationCase,
    result_case_version: 1,
    result_path_alert_version: 2,
    replayed: false,
  });
  const [escalationState] = await database<
    {
      number: string;
      receipts: number;
      links: number;
      counter_receipts: number;
    }[]
  >`
    SELECT case_row.number,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=case_row.id) AS receipts,
      (SELECT count(*)::integer FROM public.alert_case_links WHERE case_id=case_row.id) AS links,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE tenant_id=case_row.tenant_id AND aggregate_kind='case') AS counter_receipts
    FROM public.cases AS case_row WHERE case_row.id=${ids.escalationCase}::uuid
  `;
  assert.match(escalationState?.number ?? "", /^CAS-\d{4}-\d{6}$/);
  assert.equal(escalationState?.receipts, 1);
  assert.equal(escalationState?.links, 1);
  const escalationReplay = await commitEscalation(first, {
    functionName: "app.commit_tenant_ticket_escalation_v4",
    sourceAlertID: ids.escalationSource,
    caseID: ids.escalationCase,
    createCase: true,
    linkID: ids.escalationLink,
    expectedSourceVersion: 1,
    key: "new-case-escalation",
  });
  assert.equal(escalationReplay.replayed, true);
  const [escalationReplayState] = await database<
    { receipts: number; links: number; case_receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${ids.escalationCase}::uuid) AS receipts,
      (SELECT count(*)::integer FROM public.alert_case_links WHERE case_id=${ids.escalationCase}::uuid) AS links,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE tenant_id=${ids.tenant}::uuid AND aggregate_kind='case') AS case_receipts
  `;
  assert.equal(escalationReplayState?.receipts, 1);
  assert.equal(escalationReplayState?.links, 1);
  assert.equal(
    escalationReplayState?.case_receipts,
    escalationState?.counter_receipts,
    "escalation replay consumed another Case number",
  );

  await insertDirectAlert(database, ids.existingEscalationSource, "FORGED");
  const existingEscalation = await commitEscalation(first, {
    functionName: "app.commit_tenant_ticket_escalation_v4",
    sourceAlertID: ids.existingEscalationSource,
    caseID: ids.caseViaABI,
    createCase: false,
    linkID: ids.existingEscalationLink,
    expectedCaseVersion: 1,
    key: "existing-case-escalation",
  });
  assert.equal(existingEscalation.result_case_id, ids.caseViaABI);
  assert.equal(existingEscalation.result_case_version, 2);
  const [existingReceiptCount] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.tenant_ticket_numbering_receipts
    WHERE aggregate_id=${ids.caseViaABI}::uuid
  `;
  assert.equal(
    existingReceiptCount?.count,
    1,
    "existing Case escalation reallocated its number",
  );

  await insertDirectAlert(database, ids.linkSource, "FORGED");
  const linkedExisting = await commitEscalation(first, {
    functionName: "app.commit_tenant_ticket_link_v1",
    sourceAlertID: ids.linkSource,
    caseID: ids.caseViaABI,
    createCase: false,
    linkID: ids.correlationLink,
    expectedCaseVersion: 2,
    key: "existing-case-link",
  });
  assert.equal(linkedExisting.result_case_id, ids.caseViaABI);
  assert.equal(linkedExisting.result_case_version, 3);
  const [linkReceiptCount] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.tenant_ticket_numbering_receipts
    WHERE aggregate_id=${ids.caseViaABI}::uuid
  `;
  assert.equal(
    linkReceiptCount?.count,
    1,
    "linking to an existing Case reallocated its number",
  );

  const [publishedSLA] = await asApi(
    first,
    ids.tenant,
    ids.admin,
    (transaction) => transaction<{ replayed: boolean }[]>`
      SELECT replayed FROM app.publish_sla_policy_v2(
        ${ids.tenant}::uuid,${ids.slaPolicy}::uuid,0,
        ${transaction.json(slaPolicyDocument)}::jsonb,
        ${digest("sla-policy-key")}::bytea,
        ${digest("sla-policy-request")}::bytea,
        ${ids.slaRequest}::uuid,${ids.slaCorrelation}::uuid,
        '198.51.100.46'::inet,'Ticket numbering SLA runtime','totp'
      )
    `,
  );
  assert.equal(publishedSLA?.replayed, false);
  const [slaWindow] = await database<{ queued_at: Date }[]>`
    SELECT transaction_timestamp() - interval '2 seconds' AS queued_at
  `;
  assert(slaWindow, "database SLA action window is missing");
  const occurrenceDigest = digest("sla-occurrence");
  await database.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.sla_instances (
        id,tenant_id,object_type,object_id,policy_id,policy_version,
        aggregate_version,assignment_event_id,created_at,updated_at
      ) VALUES (
        ${ids.slaInstance}::uuid,${ids.tenant}::uuid,'alert',
        ${ids.directAlert}::uuid,${ids.slaPolicy}::uuid,1,1,
        ${ids.slaAssignmentEvent}::uuid,${slaWindow.queued_at},${slaWindow.queued_at}
      )
    `;
    await transaction`
      INSERT INTO public.sla_metric_instances (
        id,tenant_id,sla_instance_id,definition_id,policy_id,policy_version,
        version,lifecycle,state,created_at,updated_at,extension_micros,
        consumed_micros
      ) VALUES (
        ${ids.slaMetricInstance}::uuid,${ids.tenant}::uuid,
        ${ids.slaInstance}::uuid,${ids.slaMetricDefinition}::uuid,
        ${ids.slaPolicy}::uuid,1,1,'pending','pending',
        ${slaWindow.queued_at},${slaWindow.queued_at},0,0
      )
    `;
    await transaction`
      INSERT INTO public.sla_trigger_occurrences (
        id,tenant_id,sla_instance_id,metric_instance_id,
        trigger_definition_id,scheduled_at,deduplication_digest,action_kind,
        action_configuration_id,action_value,allow_recursive_sla,created_at
      ) VALUES (
        ${ids.slaOccurrence}::uuid,${ids.tenant}::uuid,
        ${ids.slaInstance}::uuid,${ids.slaMetricInstance}::uuid,
        ${ids.slaTriggerDefinition}::uuid,${slaWindow.queued_at},
        ${occurrenceDigest}::bytea,'create_system_alert',NULL,'sla.runtime',
        true,${slaWindow.queued_at}
      )
    `;
  });
  const [alertReceiptsBeforeSLA] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_ticket_numbering_receipts
    WHERE tenant_id=${ids.tenant}::uuid AND aggregate_kind='alert'
  `;
  const [slaClaim] = await asRole(
    first,
    "periapsis_worker",
    ids.tenant,
    undefined,
    (transaction) => transaction<SLAClaim[]>`
      SELECT occurrence_id,action_kind,fence,claimed_at
      FROM app.claim_sla_trigger_actions_v1(
        ${ids.slaWorker}::uuid,${ids.tenant}::uuid,clock_timestamp(),1,30000000
      )
    `,
  );
  assert(slaClaim, "worker did not claim the SLA system Alert action");
  assert.equal(slaClaim.occurrence_id, ids.slaOccurrence);
  assert.equal(slaClaim.action_kind, "create_system_alert");
  const slaAppliedAt = new Date(slaClaim.claimed_at.getTime() + 1_000);
  const executeSLA = () =>
    asRole(
      first,
      "periapsis_worker",
      ids.tenant,
      undefined,
      (transaction) => transaction<{ disposition: string }[]>`
        SELECT app.execute_sla_trigger_action_v1(
          ${ids.slaWorker}::uuid,${ids.tenant}::uuid,
          ${ids.slaOccurrence}::uuid,${slaClaim.fence}::bigint,
          ${occurrenceDigest}::bytea,
          'create_system_alert'::public.sla_trigger_action_kind,
          ${slaAppliedAt}
        ) AS disposition
      `,
    );
  const [slaApplied] = await executeSLA();
  assert.equal(slaApplied?.disposition, "applied");
  const [slaEffect] = await database<
    {
      effect_id: string;
      effect_kind: string;
      number: string;
      source: string;
      numbering_receipts: number;
      creation_activities: number;
      origins: number;
      recursive_outbox: number;
      action_audit: number;
      action_outbox: number;
      alert_receipts: number;
    }[]
  >`
    SELECT action.effect_id,action.effect_kind,alert.number,alert.source,
      (SELECT count(*)::integer
       FROM public.tenant_ticket_numbering_receipts AS receipt
       WHERE receipt.aggregate_id=action.effect_id) AS numbering_receipts,
      (SELECT count(*)::integer
       FROM public.ticket_activities AS activity
       WHERE activity.alert_id=action.effect_id AND activity.sequence=1
         AND activity.kind='alert.created') AS creation_activities,
      (SELECT count(*)::integer
       FROM public.sla_system_alert_origins AS origin
       WHERE origin.alert_id=action.effect_id
         AND origin.source_occurrence_id=${ids.slaOccurrence}::uuid) AS origins,
      (SELECT count(*)::integer
       FROM public.outbox_events AS event
       WHERE event.aggregate_id=action.effect_id
         AND event.event_type='sla.alert.created') AS recursive_outbox,
      (SELECT count(*)::integer
       FROM public.audit_events AS audit
       WHERE audit.resource_id=${ids.slaOccurrence}::uuid
         AND audit.action='tenant.sla.action.executed') AS action_audit,
      (SELECT count(*)::integer
       FROM public.outbox_events AS event
       WHERE event.aggregate_id=${ids.slaOccurrence}::uuid
         AND event.event_type='sla.action.executed') AS action_outbox,
      (SELECT count(*)::integer
       FROM public.tenant_ticket_numbering_receipts AS receipt
       WHERE receipt.tenant_id=${ids.tenant}::uuid
         AND receipt.aggregate_kind='alert') AS alert_receipts
    FROM public.sla_trigger_action_receipts AS action
    JOIN public.alerts AS alert ON alert.tenant_id=action.tenant_id
      AND alert.id=action.effect_id
    WHERE action.tenant_id=${ids.tenant}::uuid
      AND action.occurrence_id=${ids.slaOccurrence}::uuid
  `;
  assert(slaEffect, "SLA system Alert effect is missing");
  assert.equal(slaEffect.effect_kind, "system_alert");
  assert.match(slaEffect.number, /^ALT-\d{4}-\d{6}$/);
  assert.equal(slaEffect.source, "sla-engine");
  assert.equal(slaEffect.numbering_receipts, 1);
  assert.equal(
    slaEffect.creation_activities,
    1,
    "SLA system Alert must have exactly one sequence=1 creation activity",
  );
  assert.equal(slaEffect.origins, 1);
  assert.equal(slaEffect.recursive_outbox, 1);
  assert.equal(slaEffect.action_audit, 1);
  assert.equal(slaEffect.action_outbox, 1);
  assert.equal(
    slaEffect.alert_receipts,
    (alertReceiptsBeforeSLA?.count ?? 0) + 1,
  );
  const [slaReplayed] = await executeSLA();
  assert.equal(slaReplayed?.disposition, "replayed");
  const [slaStable] = await database<
    {
      receipts: number;
      activities: number;
      origins: number;
      alert_receipts: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.sla_trigger_action_receipts
       WHERE occurrence_id=${ids.slaOccurrence}::uuid) AS receipts,
      (SELECT count(*)::integer FROM public.ticket_activities
       WHERE alert_id=${slaEffect.effect_id}::uuid AND sequence=1
         AND kind='alert.created') AS activities,
      (SELECT count(*)::integer FROM public.sla_system_alert_origins
       WHERE alert_id=${slaEffect.effect_id}::uuid) AS origins,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts
       WHERE tenant_id=${ids.tenant}::uuid AND aggregate_kind='alert') AS alert_receipts
  `;
  assert.deepEqual(slaStable, {
    receipts: 1,
    activities: 1,
    origins: 1,
    alert_receipts: slaEffect.alert_receipts,
  });

  const futureSkewPublishedAt = new Date(Date.now() + 59_000);
  const futureSkewPolicy = await replacePolicy(first, {
    expectedVersion: 1,
    kind: "alert",
    prefix: "SKW",
    separator: "-",
    period: "annual",
    width: 6,
    start: 1,
    key: "future-clock-skew",
    request: "future-clock-skew",
    publishedAt: futureSkewPublishedAt,
  });
  assert.equal(
    futureSkewPolicy.published_at.getTime(),
    futureSkewPublishedAt.getTime(),
  );
  assert.equal(
    await insertDirectAlert(database, ids.futureSkewAlert, "FORGED"),
    `SKW-${futureSkewPublishedAt.getUTCFullYear()}-000001`,
  );
  const [futureSkewReceipt] = await database<{ allocated_at: Date }[]>`
    SELECT allocated_at
    FROM public.tenant_ticket_numbering_receipts
    WHERE tenant_id=${ids.tenant}::uuid AND aggregate_kind='alert'
      AND aggregate_id=${ids.futureSkewAlert}::uuid
  `;
  assert.equal(
    futureSkewReceipt?.allocated_at.getTime(),
    futureSkewPublishedAt.getTime(),
  );

  const lifetime = await replacePolicy(first, {
    expectedVersion: 1,
    kind: "case",
    prefix: "INC",
    separator: "/",
    period: "lifetime",
    width: 8,
    start: 100,
    key: "case-lifetime",
    request: "case-lifetime",
  });
  assert.equal(lifetime.version, 2);
  assert.equal(lifetime.published_by_membership_id, ids.adminMembership);
  const lifetimeReplay = await replacePolicy(first, {
    expectedVersion: 1,
    kind: "case",
    prefix: "INC",
    separator: "/",
    period: "lifetime",
    width: 8,
    start: 100,
    key: "case-lifetime",
    request: "case-lifetime",
  });
  assert.equal(lifetimeReplay.replayed, true);
  assert.equal(lifetimeReplay.version_id, lifetime.version_id);

  await rejects(
    replacePolicy(first, {
      expectedVersion: 1,
      kind: "case",
      prefix: "OTHER",
      separator: "/",
      period: "lifetime",
      width: 8,
      start: 100,
      key: "case-lifetime",
      request: "divergent",
    }),
    "23505",
    "divergent idempotency key was accepted",
    "tenant_ticket_numbering_commands_pkey",
  );

  const lifetimeNumber = await insertDirectCase(
    database,
    ids.tenant,
    ids.lifetimeCaseOne,
    "FORGED-0000",
  );
  assert.equal(lifetimeNumber, "INC/00000100");
  const [lifetimeReceipt] = await database<
    { period: number; sequence: string | number }[]
  >`
    SELECT period,sequence FROM public.tenant_ticket_numbering_receipts
    WHERE aggregate_id=${ids.lifetimeCaseOne}::uuid
  `;
  assert.deepEqual(
    [lifetimeReceipt?.period, Number(lifetimeReceipt?.sequence)],
    [0, 100],
  );

  const temporary = await replacePolicy(first, {
    expectedVersion: 2,
    kind: "case",
    prefix: "TMP",
    separator: "-",
    period: "lifetime",
    width: 8,
    start: 1,
    key: "temporary-namespace",
    request: "temporary-namespace",
  });
  assert.equal(temporary.version, 3);
  assert.equal(
    await insertDirectCase(
      database,
      ids.tenant,
      ids.otherNamespaceCase,
      "IGNORED",
    ),
    "TMP-00000001",
  );
  const reactivated = await replacePolicy(first, {
    expectedVersion: 3,
    kind: "case",
    prefix: "INC",
    separator: "/",
    period: "lifetime",
    width: 8,
    start: 1,
    key: "reactivate-namespace",
    request: "reactivate-namespace",
  });
  assert.equal(reactivated.version, 4);
  assert.equal(
    await insertDirectCase(
      database,
      ids.tenant,
      ids.reactivatedNamespaceCase,
      "IGNORED",
    ),
    "INC/00000101",
    "reactivating a namespace rewound its durable counter",
  );

  await rejects(
    replacePolicy(first, {
      expectedVersion: 4,
      kind: "case",
      prefix: "INC",
      separator: "/",
      period: "lifetime",
      width: 8,
      start: 1,
      key: "no-change",
      request: "no-change",
    }),
    "23505",
    "database ABI accepted a no-op policy publication",
    "tenant_ticket_numbering_policy_no_change",
  );

  const concurrencyPolicy = await replacePolicy(first, {
    expectedVersion: 4,
    kind: "case",
    prefix: "CON",
    separator: "_",
    period: "lifetime",
    width: 6,
    start: 1,
    key: "concurrency",
    request: "concurrency",
  });
  assert.equal(concurrencyPolicy.version, 5);
  const concurrentIDs = Array.from({ length: 32 }, (_, index) =>
    uuid(2_000 + index),
  );
  const concurrentNumbers = await Promise.all(
    concurrentIDs.map((id) =>
      insertDirectCase(database, ids.tenant, id, "EXPLICIT"),
    ),
  );
  assert.equal(new Set(concurrentNumbers).size, concurrentNumbers.length);
  assert.deepEqual(
    concurrentNumbers.toSorted(),
    Array.from(
      { length: 32 },
      (_, index) => `CON_${String(index + 1).padStart(6, "0")}`,
    ),
  );

  const [counterBeforeRollback] = await database<
    { next_value: string | number }[]
  >`
    SELECT next_value FROM public.ticket_number_counters
    WHERE tenant_id=${ids.tenant}::uuid AND aggregate_kind='case'
      AND namespace_digest=${namespaceDigest("CON", "_", "lifetime", 6)}::bytea
      AND period=0
  `;
  await assert.rejects(
    database.begin(async (transaction) => {
      await setContext(
        transaction,
        "periapsis_migrator",
        ids.tenant,
        ids.admin,
      );
      const workflow = await defaultWorkflow(transaction, ids.tenant, "case");
      await transaction`
        INSERT INTO public.cases(
          id,tenant_id,number,workflow_id,workflow_version,state_key,title,
          created_by_membership_id,created_by_user_id
        ) VALUES (
          ${ids.rollbackCase}::uuid,${ids.tenant}::uuid,'ROLLBACK',
          ${workflow.id}::uuid,${workflow.version},${workflow.state},'Rollback Case',
          ${ids.adminMembership}::uuid,${ids.admin}::uuid
        )
      `;
      throw new Error("force ticket transaction rollback");
    }),
    /force ticket transaction rollback/,
  );
  const [rollbackState] = await database<
    { next_value: string | number; receipts: number; cases: number }[]
  >`
    SELECT counter.next_value,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${ids.rollbackCase}::uuid) AS receipts,
      (SELECT count(*)::integer FROM public.cases WHERE id=${ids.rollbackCase}::uuid) AS cases
    FROM public.ticket_number_counters AS counter
    WHERE counter.tenant_id=${ids.tenant}::uuid AND counter.aggregate_kind='case'
      AND counter.namespace_digest=${namespaceDigest("CON", "_", "lifetime", 6)}::bytea
      AND counter.period=0
  `;
  assert.equal(
    Number(rollbackState?.next_value),
    Number(counterBeforeRollback?.next_value),
  );
  assert.equal(rollbackState?.receipts, 0);
  assert.equal(rollbackState?.cases, 0);

  const exhausted = await replacePolicy(first, {
    expectedVersion: 5,
    kind: "case",
    prefix: "END",
    separator: ".",
    period: "lifetime",
    width: 4,
    start: 9_999,
    key: "exhaustion",
    request: "exhaustion",
  });
  assert.equal(exhausted.version, 6);
  assert.equal(
    await insertDirectCase(database, ids.tenant, ids.exhaustedCase, "FORGED"),
    "END.9999",
  );
  await rejects(
    insertDirectCase(database, ids.tenant, ids.exhaustedFailureCase, "FORGED"),
    "54000",
    "exhausted namespace allocated another number",
  );
  const [exhaustionFailure] = await database<
    { cases: number; receipts: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.cases WHERE id=${ids.exhaustedFailureCase}::uuid) AS cases,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts WHERE aggregate_id=${ids.exhaustedFailureCase}::uuid) AS receipts
  `;
  assert.deepEqual(exhaustionFailure, { cases: 0, receipts: 0 });

  assert.equal(
    await insertDirectCase(
      database,
      ids.foreignTenant,
      ids.annualCaseOne,
      "FORGED",
      new Date("2026-12-31T23:59:59.999Z"),
    ),
    "CAS-2026-000001",
  );
  assert.equal(
    await insertDirectCase(
      database,
      ids.foreignTenant,
      ids.annualCaseTwo,
      "FORGED",
      new Date("2027-01-01T00:00:00.000Z"),
    ),
    "CAS-2027-000001",
  );

  await rejects(
    asRole(
      first,
      "periapsis_migrator",
      ids.suspendedTenant,
      ids.admin,
      (transaction) => transaction`
        SELECT app.private_allocate_ticket_number_v2(
          ${ids.suspendedTenant}::uuid,'case',${ids.suspendedAllocation}::uuid,now()
        )
      `,
    ),
    "42501",
    "suspended tenant allocated a number",
  );

  await rejects(
    database`UPDATE public.tenant_ticket_numbering_policy_versions SET prefix='BAD' WHERE id=${lifetime.version_id}::uuid`,
    "55000",
    "policy history was mutable",
  );
  await rejects(
    database`UPDATE public.tenant_ticket_numbering_receipts SET number=number WHERE aggregate_id=${ids.directCase}::uuid`,
    "55000",
    "receipt history was mutable",
  );

  const [audit] = await database<
    {
      reason: string;
      before_text: string;
      after_text: string;
      metadata_text: string;
    }[]
  >`
    SELECT reason,before::text AS before_text,after::text AS after_text,
           metadata::text AS metadata_text
    FROM public.audit_events
    WHERE tenant_id=${ids.tenant}::uuid
      AND action='tenant.ticket_numbering.policy.replace'
      AND resource_id=${lifetime.version_id}::uuid
  `;
  assert(audit, "policy replacement audit is missing");
  assert.equal(audit.reason, "Approve reviewed ticket numbering");
  assert(
    !audit.before_text.includes("INC") && !audit.after_text.includes("INC"),
  );
  assert(!audit.before_text.includes("/") && !audit.after_text.includes("/"));
  assert(audit.metadata_text.includes('"contentRedacted": true'));

  await database`UPDATE public.auth_sessions SET revoked_at=now() WHERE id=${ids.adminSession}::uuid`;
  await rejects(
    readPolicy(first, ids.tenant, ids.admin, ids.adminSession, "case"),
    "42501",
    "revoked session read numbering policy",
  );

  const [receiptContract] = await database<
    { tickets: number; receipts: number; duplicates: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM (
        SELECT id FROM public.alerts WHERE tenant_id IN (${ids.tenant}::uuid,${ids.foreignTenant}::uuid)
        UNION ALL
        SELECT id FROM public.cases WHERE tenant_id IN (${ids.tenant}::uuid,${ids.foreignTenant}::uuid)
      ) AS ticket) AS tickets,
      (SELECT count(*)::integer FROM public.tenant_ticket_numbering_receipts
       WHERE tenant_id IN (${ids.tenant}::uuid,${ids.foreignTenant}::uuid)) AS receipts,
      (SELECT count(*)::integer FROM (
        SELECT tenant_id,aggregate_kind,number
        FROM public.tenant_ticket_numbering_receipts
        WHERE tenant_id IN (${ids.tenant}::uuid,${ids.foreignTenant}::uuid)
        GROUP BY tenant_id,aggregate_kind,number HAVING count(*) > 1
      ) AS duplicate) AS duplicates
  `;
  assert.equal(receiptContract?.tickets, receiptContract?.receipts);
  assert.equal(receiptContract?.duplicates, 0);
} finally {
  await Promise.all([database.end({ timeout: 5 }), first.end({ timeout: 5 })]);
}
