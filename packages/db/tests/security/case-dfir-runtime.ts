import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

type Reservation = {
  command_id: string;
  replayed: boolean;
  result_resource_id: string;
  result_snapshot: postgres.JSONValue;
  result_version: string;
};

const databaseUrl = process.env.PERIAPSIS_CASE_DFIR_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_CASE_DFIR_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4a20-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  scopedUser: uuid(102),
  unrosteredUser: uuid(103),
  foreignUser: uuid(104),
  adminMembership: uuid(201),
  scopedMembership: uuid(202),
  unrosteredMembership: uuid(203),
  foreignMembership: uuid(204),
  scopedRole: uuid(301),
  scopedGrant: uuid(302),
  team: uuid(401),
  teamEpoch: uuid(402),
  teamRoster: uuid(403),
  adminRoster: uuid(404),
  foreignTeam: uuid(405),
  foreignTeamEpoch: uuid(406),
  mainCase: uuid(501),
  otherCase: uuid(502),
  foreignCase: uuid(503),
  alert: uuid(504),
  highTask: uuid(601),
  concurrentTask: uuid(602),
  alternateTask: uuid(603),
  createdTask: uuid(604),
  policy: uuid(701),
  foreignPolicy: uuid(702),
  mainCaseSla: uuid(711),
  otherCaseSla: uuid(712),
  alertSla: uuid(713),
  foreignCaseSla: uuid(714),
  mainCaseSlaEvent: uuid(721),
  otherCaseSlaEvent: uuid(722),
  alertSlaEvent: uuid(723),
  foreignCaseSlaEvent: uuid(724),
  checklistItem: uuid(801),
  relationship: uuid(851),
  relationshipRetraction: uuid(852),
} as const;

const primary = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
const contender = postgres(databaseUrl, {
  max: 3,
  onnotice: () => undefined,
});

function digest(label: string): Buffer {
  return createHash("sha256").update(`case-dfir-runtime:${label}`).digest();
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
  client: typeof primary,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id',${tenantID},true),
             set_config('app.user_id',${userID},true),
             set_config('app.service_account_id','',true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate','case_dfir=runtime',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function setupCore(): Promise<void> {
  const suffix = sequence.toString(36);
  const ticketSuffix = (Number(sequence % 800_000n) + 100_000)
    .toString()
    .padStart(6, "0");
  await primary.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${fixture.tenant}::uuid,${`case-dfir-${suffix}`},'Case DFIR runtime'),
        (${fixture.foreignTenant}::uuid,${`case-dfir-foreign-${suffix}`},'Foreign Case DFIR runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.adminUser}::uuid,${`case-dfir-admin-${suffix}@example.invalid`},'Case administrator',true),
        (${fixture.scopedUser}::uuid,${`case-dfir-scoped-${suffix}@example.invalid`},'Case scoped operator',true),
        (${fixture.unrosteredUser}::uuid,${`case-dfir-unrostered-${suffix}@example.invalid`},'Unrostered operator',true),
        (${fixture.foreignUser}::uuid,${`case-dfir-foreign-${suffix}@example.invalid`},'Foreign administrator',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status) VALUES
        (${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,${fixture.adminUser}::uuid,'tenant_admin','active'),
        (${fixture.scopedMembership}::uuid,${fixture.tenant}::uuid,${fixture.scopedUser}::uuid,'analyst','active'),
        (${fixture.unrosteredMembership}::uuid,${fixture.tenant}::uuid,${fixture.unrosteredUser}::uuid,'analyst','active'),
        (${fixture.foreignMembership}::uuid,${fixture.foreignTenant}::uuid,${fixture.foreignUser}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,'Case administrator',${`case-dfir-admin-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.scopedMembership}::uuid,${fixture.scopedUser}::uuid,'Case scoped operator',${`case-dfir-scoped-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.unrosteredMembership}::uuid,${fixture.unrosteredUser}::uuid,'Unrostered operator',${`case-dfir-unrostered-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,${fixture.foreignUser}::uuid,'Foreign administrator',${`case-dfir-foreign-${suffix}@example.invalid`})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_roles(
        id,tenant_id,key,display_name,description,system_role,protected_role,
        principal_kind,created_by_membership_id
      ) VALUES (
        ${fixture.scopedRole}::uuid,${fixture.tenant}::uuid,
        ${`case_dfir_scope_${suffix}`},'Case DFIR scoped operator',
        'Runtime operator-team scope proof',false,false,'human',
        ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions(
        tenant_id,role_id,permission_id,scope
      )
      SELECT ${fixture.tenant}::uuid,${fixture.scopedRole}::uuid,
             permission.id,'operator_team'
      FROM public.tenant_permissions AS permission
      WHERE permission.key='dfir.task.manage'
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT ${fixture.scopedGrant}::uuid,${fixture.tenant}::uuid,
             ${fixture.scopedMembership}::uuid,${fixture.scopedRole}::uuid,
             source.id,${fixture.adminMembership}::uuid,
             'Runtime operator-team scope proof'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id=${fixture.tenant}::uuid
        AND source.key='manual' AND source.retired_at IS NULL
    `;
    await transaction`
      UPDATE public.tenant_authorization_states
      SET revision=revision+1,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
    `;
    await transaction`
      INSERT INTO public.operator_teams(
        id,key,display_name,description,created_by_user_id
      ) VALUES
        (${fixture.team}::uuid,${`case_dfir_${suffix}`},'Case DFIR team','Local runtime team',${fixture.adminUser}::uuid),
        (${fixture.foreignTeam}::uuid,${`case_dfir_foreign_${suffix}`},'Foreign Case DFIR team','Foreign runtime team',${fixture.foreignUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs(
        id,tenant_id,operator_team_id,assigned_by_membership_id,
        assignment_reason
      ) VALUES
        (${fixture.teamEpoch}::uuid,${fixture.tenant}::uuid,${fixture.team}::uuid,${fixture.adminMembership}::uuid,'Case DFIR runtime assignment'),
        (${fixture.foreignTeamEpoch}::uuid,${fixture.foreignTenant}::uuid,${fixture.foreignTeam}::uuid,${fixture.foreignMembership}::uuid,'Foreign Case DFIR runtime assignment')
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries(
        id,tenant_id,assignment_epoch_id,membership_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT roster.id::uuid,${fixture.tenant}::uuid,${fixture.teamEpoch}::uuid,
             roster.membership_id::uuid,source.id,
             ${fixture.adminMembership}::uuid,'Case DFIR runtime roster'
      FROM (VALUES
        (${fixture.teamRoster},${fixture.scopedMembership}),
        (${fixture.adminRoster},${fixture.adminMembership})
      ) AS roster(id,membership_id)
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=${fixture.tenant}::uuid
       AND source.key='manual' AND source.retired_at IS NULL
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        assigned_team_id,assigned_team_epoch_id,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT source.id::uuid,${fixture.tenant}::uuid,source.number,
             workflow.id,workflow.current_version,state.value->>'key',
             source.title,source.team_id::uuid,source.epoch_id::uuid,
             ${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,1,
             transaction_timestamp()
      FROM (VALUES
        (${fixture.mainCase},${`CAS-2099-${ticketSuffix}`},'Main Case DFIR root',${fixture.team},${fixture.teamEpoch}),
        (${fixture.otherCase},${`CAS-2098-${ticketSuffix}`},'Other Case DFIR root',NULL,NULL)
      ) AS source(id,number,title,team_id,epoch_id)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id=${fixture.tenant}::uuid
       AND workflow.key='default_case'
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
      WHERE (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${fixture.alert}::uuid,${fixture.tenant}::uuid,
             ${`ALT-2099-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key','Case DFIR guard Alert',
             ${fixture.adminUser}::uuid,${fixture.adminMembership}::uuid,1,
             transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.foreignTenant},true),
             set_config('app.user_id',${fixture.foreignUser},true)
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT ${fixture.foreignCase}::uuid,${fixture.foreignTenant}::uuid,
             ${`CAS-2097-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key','Foreign Case DFIR root',
             ${fixture.foreignMembership}::uuid,${fixture.foreignUser}::uuid,1,
             transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_case'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.sla_policies(
        id,tenant_id,key,active_version,resource_version,
        created_by_membership_id,updated_by_membership_id
      ) VALUES
        (${fixture.policy}::uuid,${fixture.tenant}::uuid,${`case_dfir_${suffix}`},1,1,${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid),
        (${fixture.foreignPolicy}::uuid,${fixture.foreignTenant}::uuid,${`case_dfir_foreign_${suffix}`},1,1,${fixture.foreignMembership}::uuid,${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.sla_policy_versions(
        tenant_id,policy_id,version,name,description,priority,object_types,
        match_rule,effective_from,enabled,apply_to_sla_engine_source,
        revision_digest,created_by_membership_id
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.policy}::uuid,1,'Case DFIR SLA','Runtime exact-root proof',0,ARRAY['case','alert']::public.sla_object_type[],'{}'::jsonb,'2026-01-01T00:00:00Z',true,false,${digest("policy")},${fixture.adminMembership}::uuid),
        (${fixture.foreignTenant}::uuid,${fixture.foreignPolicy}::uuid,1,'Foreign Case DFIR SLA','Foreign runtime exact-root proof',0,ARRAY['case']::public.sla_object_type[],'{}'::jsonb,'2026-01-01T00:00:00Z',true,false,${digest("foreign-policy")},${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.sla_instances(
        id,tenant_id,object_type,object_id,policy_id,policy_version,
        aggregate_version,assignment_event_id,created_at,updated_at
      ) VALUES
        (${fixture.mainCaseSla}::uuid,${fixture.tenant}::uuid,'case',${fixture.mainCase}::uuid,${fixture.policy}::uuid,1,1,${fixture.mainCaseSlaEvent}::uuid,'2026-09-04T09:00:00Z','2026-09-04T09:00:00Z'),
        (${fixture.otherCaseSla}::uuid,${fixture.tenant}::uuid,'case',${fixture.otherCase}::uuid,${fixture.policy}::uuid,1,1,${fixture.otherCaseSlaEvent}::uuid,'2026-09-04T09:00:00Z','2026-09-04T09:00:00Z'),
        (${fixture.alertSla}::uuid,${fixture.tenant}::uuid,'alert',${fixture.alert}::uuid,${fixture.policy}::uuid,1,1,${fixture.alertSlaEvent}::uuid,'2026-09-04T09:00:00Z','2026-09-04T09:00:00Z'),
        (${fixture.foreignCaseSla}::uuid,${fixture.foreignTenant}::uuid,'case',${fixture.foreignCase}::uuid,${fixture.foreignPolicy}::uuid,1,1,${fixture.foreignCaseSlaEvent}::uuid,'2026-09-04T09:00:00Z','2026-09-04T09:00:00Z')
    `;
  });
}

async function createComment(
  tenantID: string,
  userID: string,
  kind: "alert" | "case",
  ticketID: string,
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
        ${kind},${ticketID}::uuid,'private',${`Runtime ${label}`},
        ${`<p>Runtime ${label}</p>`},ARRAY[]::uuid[],ARRAY[]::uuid[],
        ${digest(`${label}:key`)},${digest(`${label}:request`)},
        ${uuid(offset)}::uuid,${uuid(offset + 1)}::uuid,'127.0.0.1'::inet,
        'case-dfir-runtime','totp'
      )
    `,
  );
  assert(receipt, `${label} comment creation returned no receipt`);
  assert.equal(receipt.replayed, false);
  return receipt.comment_id;
}

type Comments = {
  alert: string;
  foreignCase: string;
  mainCase: string;
  otherCase: string;
};

async function setupComments(): Promise<Comments> {
  const mainCase = await createComment(
    fixture.tenant,
    fixture.adminUser,
    "case",
    fixture.mainCase,
    "main-case-comment",
    901,
  );
  const otherCase = await createComment(
    fixture.tenant,
    fixture.adminUser,
    "case",
    fixture.otherCase,
    "other-case-comment",
    903,
  );
  const alert = await createComment(
    fixture.tenant,
    fixture.adminUser,
    "alert",
    fixture.alert,
    "alert-comment",
    905,
  );
  const foreignCase = await createComment(
    fixture.foreignTenant,
    fixture.foreignUser,
    "case",
    fixture.foreignCase,
    "foreign-case-comment",
    907,
  );
  return { alert, foreignCase, mainCase, otherCase };
}

async function setupTasks(mainComment: string): Promise<void> {
  await primary`
    INSERT INTO public.dfir_tasks(
      id,tenant_id,case_id,title,description,status,priority,checklist,
      comment_ids,sla_instance_id,created_by_membership_id,
      updated_by_membership_id,version,created_at,updated_at
    ) VALUES
      (${fixture.highTask}::uuid,${fixture.tenant}::uuid,${fixture.mainCase}::uuid,
       'High version task','Exact bigint receipt proof','todo','high','[]'::jsonb,
       ARRAY[${mainComment}::uuid],${fixture.mainCaseSla}::uuid,
       ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,
       2999999999,'2026-09-04T10:00:00Z','2026-09-04T10:00:00Z'),
      (${fixture.concurrentTask}::uuid,${fixture.tenant}::uuid,${fixture.mainCase}::uuid,
       'Concurrent task','Exact replay serialization proof','todo','medium','[]'::jsonb,
       ARRAY[]::uuid[],NULL,${fixture.adminMembership}::uuid,
       ${fixture.adminMembership}::uuid,40,
       '2026-09-04T10:00:00Z','2026-09-04T10:00:00Z'),
      (${fixture.alternateTask}::uuid,${fixture.tenant}::uuid,${fixture.mainCase}::uuid,
       'Alternate task','Replay coordinate mismatch proof','todo','medium','[]'::jsonb,
       ARRAY[]::uuid[],NULL,${fixture.adminMembership}::uuid,
       ${fixture.adminMembership}::uuid,40,
       '2026-09-04T10:00:00Z','2026-09-04T10:00:00Z')
  `;
}

async function verifyDfirResourceVersionConstraints(): Promise<void> {
  const constraintNames = [
    "dfir_assets_version_check",
    "dfir_iocs_version_check",
    "dfir_storage_objects_version_check",
    "dfir_timeline_events_version_check",
  ] as const;
  const constraints = await primary<
    { conname: string; definition: string; validated: boolean }[]
  >`
    SELECT conname,pg_get_constraintdef(oid) AS definition,
           convalidated AS validated
    FROM pg_constraint
    WHERE conname=ANY(${constraintNames}::text[])
    ORDER BY conname
  `;
  assert.deepEqual(
    constraints.map((constraint) => constraint.conname),
    constraintNames,
  );
  for (const constraint of constraints) {
    assert.equal(
      constraint.validated,
      true,
      `${constraint.conname} is not valid`,
    );
    assert.match(
      constraint.definition,
      /version >= 1.*version <= '9007199254740991'::bigint/,
      `${constraint.conname} does not enforce the exact JSON ceiling`,
    );
  }

  const maximum = "9007199254740991";
  const unsafe = "9007199254740992";
  const observedAt = new Date("2026-09-04T10:00:00.000Z");
  const insertIOC = (id: string, value: string, version: string) => primary`
    INSERT INTO public.dfir_iocs(
      id,tenant_id,type,value,normalized_value,description,source,confidence,
      tlp,first_seen,last_seen,malicious_state,tags,enrichment,
      created_by_membership_id,updated_by_membership_id,version
    ) VALUES (
      ${id}::uuid,${fixture.tenant}::uuid,'domain',${value},${value},'',
      'runtime',0,'clear',${observedAt},${observedAt},'unknown',
      ARRAY[]::text[],'{}'::jsonb,${fixture.adminMembership}::uuid,
      ${fixture.adminMembership}::uuid,${version}::bigint
    )
  `;
  const insertAsset = (id: string, externalID: string, version: string) =>
    primary`
      INSERT INTO public.dfir_assets(
        id,tenant_id,original_identifiers,asset_type,criticality,environment,
        external_id,tags,first_seen,last_seen,created_by_membership_id,
        updated_by_membership_id,version
      ) VALUES (
        ${id}::uuid,${fixture.tenant}::uuid,
        '{"ipAddresses":[],"macAddresses":[]}'::jsonb,
        'endpoint','low','test',${externalID},ARRAY[]::text[],
        ${observedAt},${observedAt},${fixture.adminMembership}::uuid,
        ${fixture.adminMembership}::uuid,${version}::bigint
      )
    `;
  const insertStorage = (
    id: string,
    suffix: string,
    version: string,
  ) => primary`
    INSERT INTO public.dfir_storage_objects(
      id,tenant_id,bucket,object_key,original_filename,classification,state,
      expected_size_bytes,upload_expires_at,created_by_membership_id,version,
      created_at,updated_at
    ) VALUES (
      ${id}::uuid,${fixture.tenant}::uuid,'dfir-boundary',
      ${`${fixture.tenant}/boundary-${suffix}`},${`boundary-${suffix}.bin`},
      'internal','pending_upload',1,${new Date("2026-09-04T10:30:00.000Z")},
      ${fixture.adminMembership}::uuid,${version}::bigint,
      ${observedAt},${observedAt}
    )
  `;
  const insertTimeline = (
    id: string,
    title: string,
    version: string,
  ) => primary`
    INSERT INTO public.dfir_timeline_events(
      id,tenant_id,case_id,event_time,ingested_at,original_timezone,precision,
      source,category,title,description,tags,created_by_membership_id,version,
      created_at,updated_at
    ) VALUES (
      ${id}::uuid,${fixture.tenant}::uuid,${fixture.mainCase}::uuid,
      ${observedAt},${observedAt},'UTC','second','runtime','revision_check',
      ${title},'',ARRAY[]::text[],${fixture.adminMembership}::uuid,
      ${version}::bigint,${observedAt},${observedAt}
    )
  `;

  await Promise.all([
    insertIOC(uuid(1501), "maximum-safe.example", maximum),
    insertAsset(uuid(1502), "maximum-safe-asset", maximum),
    insertStorage(uuid(1503), "maximum-safe", maximum),
    insertTimeline(uuid(1504), "Maximum safe timeline", maximum),
  ]);
  await Promise.all([
    expectSqlState(
      insertIOC(uuid(1511), "unsafe.example", unsafe),
      "23514",
      "IOC accepted a non-JSON-safe revision",
    ),
    expectSqlState(
      insertAsset(uuid(1512), "unsafe-asset", unsafe),
      "23514",
      "asset accepted a non-JSON-safe revision",
    ),
    expectSqlState(
      insertStorage(uuid(1513), "unsafe", unsafe),
      "23514",
      "storage object accepted a non-JSON-safe revision",
    ),
    expectSqlState(
      insertTimeline(uuid(1514), "Unsafe timeline", unsafe),
      "23514",
      "timeline event accepted a non-JSON-safe revision",
    ),
  ]);
}

type TaskSnapshotOptions = {
  caseID?: string;
  checklist?: postgres.JSONValue[];
  commentIDs?: string[];
  completedAt?: string;
  completedBy?: string;
  completionData?: Record<string, postgres.JSONValue>;
  description?: string;
  dueAt?: string;
  id: string;
  operatorTeamID?: string;
  assigneeID?: string;
  priority?: "high" | "low" | "medium" | "urgent";
  slaInstanceID?: string;
  status?: "blocked" | "cancelled" | "done" | "in_progress" | "todo";
  title?: string;
  createdAt?: string;
  updatedAt?: string;
  version: number;
};

function taskSnapshot(options: TaskSnapshotOptions): postgres.JSONValue {
  return {
    kind: "case_task",
    task: {
      id: options.id,
      tenantId: fixture.tenant,
      caseId: options.caseID ?? fixture.mainCase,
      title: options.title ?? "Runtime Case task",
      description: options.description ?? "Bounded runtime snapshot",
      status: options.status ?? "todo",
      priority: options.priority ?? "medium",
      ...(options.assigneeID === undefined
        ? {}
        : { assigneeId: options.assigneeID }),
      ...(options.operatorTeamID === undefined
        ? {}
        : { operatorTeamId: options.operatorTeamID }),
      ...(options.dueAt === undefined ? {} : { dueAt: options.dueAt }),
      checklist: options.checklist ?? [],
      ...(options.completedAt === undefined
        ? {}
        : { completedAt: options.completedAt }),
      ...(options.completedBy === undefined
        ? {}
        : { completedBy: options.completedBy }),
      ...(options.completionData === undefined
        ? {}
        : { completionData: options.completionData }),
      commentIds: options.commentIDs ?? [],
      ...(options.slaInstanceID === undefined
        ? {}
        : { slaInstanceId: options.slaInstanceID }),
      createdAt: options.createdAt ?? "2026-09-04T10:00:00Z",
      updatedAt: options.updatedAt ?? "2026-09-04T10:00:00Z",
      version: options.version,
    },
  };
}

type ReserveInput = {
  actor?: string;
  caseID?: string;
  client?: typeof primary;
  commandID: string;
  key: string;
  operation: string;
  request?: string;
  resourceID: string;
  snapshot?: postgres.JSONValue;
  tenant?: string;
  version: number;
};

async function reserve(input: ReserveInput): Promise<Reservation> {
  return asApi(
    input.client ?? primary,
    input.tenant ?? fixture.tenant,
    input.actor ?? fixture.adminUser,
    async (transaction) => {
      const [row] = await transaction<Reservation[]>`
        SELECT command_id::text,result_resource_id::text,
               result_version::text,result_snapshot,replayed
        FROM app.reserve_case_dfir_command_v1(
          ${input.commandID}::uuid,${input.caseID ?? fixture.mainCase}::uuid,
          ${input.operation},${input.resourceID}::uuid,${input.version}::bigint,
          ${digest(`${input.key}:key`)},
          ${digest(`${input.request ?? input.key}:request`)},
          ${
            input.snapshot === undefined || input.snapshot === null
              ? null
              : JSON.stringify(input.snapshot)
          }::jsonb
        )
      `;
      assert(row, "Case DFIR reservation returned no row");
      return row;
    },
  );
}

async function verifyCatalog(): Promise<void> {
  const [catalog] = await primary<
    {
      api_execute: boolean;
      api_ticket_acl: string[];
      guard_owner: string;
      guard_private: boolean;
      helper_owner: string;
      helper_private: boolean;
      reserve_owner: string;
      reserve_private: boolean;
      reserve_search_path: string[];
      trigger_enabled: string;
    }[]
  >`
    SELECT
      pg_get_userbyid(reserve.proowner) AS reserve_owner,
      reserve.prosecdef AS reserve_private,
      reserve.proconfig AS reserve_search_path,
      pg_get_userbyid(helper.proowner) AS helper_owner,
      helper.prosecdef AS helper_private,
      pg_get_userbyid(guard.proowner) AS guard_owner,
      guard.prosecdef AS guard_private,
      has_function_privilege(
        'periapsis_api',reserve.oid,'EXECUTE'
      ) AS api_execute,
      ARRAY(
        SELECT privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee='periapsis_api' AND table_schema='public'
          AND table_name='ticket_commands'
        ORDER BY privilege_type
      ) AS api_ticket_acl,
      trigger_row.tgenabled::text AS trigger_enabled
    FROM pg_proc AS reserve
    JOIN pg_proc AS helper ON helper.oid=
      'app.private_case_dfir_task_snapshot_valid_v1(jsonb,uuid,uuid,uuid,bigint)'::regprocedure
    JOIN pg_proc AS guard ON guard.oid=
      'app.validate_dfir_task_links_v1()'::regprocedure
    JOIN pg_trigger AS trigger_row
      ON trigger_row.tgrelid='public.dfir_tasks'::regclass
     AND trigger_row.tgname='dfir_tasks_links_validate_v1'
     AND trigger_row.tgfoid=guard.oid
    WHERE reserve.oid=
      'app.reserve_case_dfir_command_v1(uuid,uuid,text,uuid,bigint,bytea,bytea,jsonb)'::regprocedure
  `;
  assert.deepEqual(catalog, {
    api_execute: true,
    api_ticket_acl: [],
    guard_owner: "periapsis_migrator",
    guard_private: true,
    helper_owner: "periapsis_migrator",
    helper_private: true,
    reserve_owner: "periapsis_migrator",
    reserve_private: true,
    reserve_search_path: ["search_path=pg_catalog, public, app"],
    trigger_enabled: "O",
  });
}

async function verifyScopeAndLookupOnly(): Promise<void> {
  const before = await primary<{ count: string }[]>`
    SELECT count(*)::text AS count FROM public.ticket_commands
  `;
  const scoped = await reserve({
    actor: fixture.scopedUser,
    commandID: uuid(1001),
    key: "scoped-main-lookup",
    operation: "case.dfir.task.assign",
    resourceID: fixture.concurrentTask,
    version: 41,
  });
  assert.equal(scoped.replayed, false);
  assert.equal(scoped.result_snapshot, null);
  const after = await primary<{ count: string }[]>`
    SELECT count(*)::text AS count FROM public.ticket_commands
  `;
  assert.deepEqual(after, before, "lookup-only reservation created a receipt");

  await expectSqlState(
    reserve({
      actor: fixture.scopedUser,
      caseID: fixture.otherCase,
      commandID: uuid(1002),
      key: "scoped-other-case",
      operation: "case.dfir.task.create",
      resourceID: uuid(1003),
      version: 1,
    }),
    "42501",
    "operator-team scope escaped its assigned Case root",
  );
  await expectSqlState(
    reserve({
      caseID: fixture.foreignCase,
      commandID: uuid(1004),
      key: "cross-tenant-case",
      operation: "case.dfir.task.create",
      resourceID: uuid(1005),
      version: 1,
    }),
    "P0002",
    "local actor reached a foreign tenant Case",
  );
  await expectSqlState(
    reserve({
      caseID: fixture.otherCase,
      commandID: uuid(1006),
      key: "wrong-root-task",
      operation: "case.dfir.task.assign",
      resourceID: fixture.concurrentTask,
      version: 41,
    }),
    "P0002",
    "mutation reservation accepted a task from another Case root",
  );
}

async function verifyHighVersionAndReplay(mainComment: string): Promise<void> {
  const snapshot = taskSnapshot({
    commentIDs: [mainComment],
    id: fixture.highTask,
    slaInstanceID: fixture.mainCaseSla,
    status: "in_progress",
    updatedAt: "2026-09-04T10:00:01Z",
    version: 3_000_000_000,
  });
  const first = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [receipt] = await transaction<Reservation[]>`
        SELECT command_id::text,result_resource_id::text,
               result_version::text,result_snapshot,replayed
        FROM app.reserve_case_dfir_command_v1(
          ${uuid(1101)}::uuid,${fixture.mainCase}::uuid,
          'case.dfir.task.transition',${fixture.highTask}::uuid,
          3000000000,${digest("high:key")},${digest("high:request")},
          ${transaction.json(snapshot)}::jsonb
        )
      `;
      assert(receipt);
      assert.equal(receipt.replayed, false);
      const updated = await transaction<{ version: string }[]>`
        UPDATE public.dfir_tasks
        SET status='in_progress',version=3000000000,
            updated_at='2026-09-04T10:00:01Z'
        WHERE tenant_id=${fixture.tenant}::uuid
          AND case_id=${fixture.mainCase}::uuid
          AND id=${fixture.highTask}::uuid AND version=2999999999
        RETURNING version::text
      `;
      assert.equal(updated.length, 1);
      assert.equal(updated[0]?.version, "3000000000");
      return receipt;
    },
  );
  assert.equal(first.result_version, "3000000000");
  assert.deepEqual(first.result_snapshot, snapshot);
  const [storedReceipt] = await primary<
    { envelope_version: number; task_version: string }[]
  >`
    SELECT result_version AS envelope_version,
           result_metadata #>> '{task,version}' AS task_version
    FROM public.ticket_commands
    WHERE tenant_id=${fixture.tenant}::uuid
      AND operation='case.dfir.task.transition'
      AND key_digest=${digest("high:key")}
  `;
  assert.deepEqual(storedReceipt, {
    envelope_version: 1,
    task_version: "3000000000",
  });

  const firstLaterMutation = await primary<{ version: string }[]>`
    UPDATE public.dfir_tasks
    SET title='High version task after first mutation',version=3000000001,
        updated_at='2026-09-04T10:00:02Z'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND case_id=${fixture.mainCase}::uuid
      AND id=${fixture.highTask}::uuid AND version=3000000000
    RETURNING version::text
  `;
  assert.equal(firstLaterMutation[0]?.version, "3000000001");
  const secondLaterMutation = await primary<{ version: string }[]>`
    UPDATE public.dfir_tasks
    SET title='High version task after second mutation',version=3000000002,
        updated_at='2026-09-04T10:00:03Z'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND case_id=${fixture.mainCase}::uuid
      AND id=${fixture.highTask}::uuid AND version=3000000001
    RETURNING version::text
  `;
  assert.equal(secondLaterMutation[0]?.version, "3000000002");
  const replay = await reserve({
    commandID: uuid(1102),
    key: "high",
    operation: "case.dfir.task.transition",
    resourceID: fixture.highTask,
    snapshot: null,
    version: 3_000_000_000,
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.command_id, first.command_id);
  assert.deepEqual(replay.result_snapshot, snapshot);

  await expectSqlState(
    reserve({
      commandID: uuid(1103),
      key: "high",
      operation: "case.dfir.task.transition",
      request: "high-mismatch",
      resourceID: fixture.highTask,
      version: 3_000_000_000,
    }),
    "23505",
    "same idempotency key accepted a different payload digest",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1104),
      key: "high",
      operation: "case.dfir.task.transition",
      resourceID: fixture.alternateTask,
      version: 3_000_000_000,
    }),
    "23505",
    "same idempotency key and payload escaped to another task coordinate",
  );
}

async function concurrentMutation(
  client: typeof primary,
  commandID: string,
  snapshot: postgres.JSONValue,
): Promise<Reservation> {
  return asApi(
    client,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [receipt] = await transaction<Reservation[]>`
        SELECT command_id::text,result_resource_id::text,
               result_version::text,result_snapshot,replayed
        FROM app.reserve_case_dfir_command_v1(
          ${commandID}::uuid,${fixture.mainCase}::uuid,
          'case.dfir.task.reschedule',${fixture.concurrentTask}::uuid,41,
          ${digest("concurrent:key")},${digest("concurrent:request")},
          ${transaction.json(snapshot)}::jsonb
        )
      `;
      assert(receipt);
      if (!receipt.replayed) {
        const updated = await transaction<{ version: string }[]>`
          UPDATE public.dfir_tasks
          SET due_at='2026-09-05T10:00:00Z',version=41,
              updated_at='2026-09-04T10:00:02Z'
          WHERE tenant_id=${fixture.tenant}::uuid
            AND case_id=${fixture.mainCase}::uuid
            AND id=${fixture.concurrentTask}::uuid AND version=40
          RETURNING version::text
        `;
        assert.equal(updated.length, 1);
        assert.equal(updated[0]?.version, "41");
        await transaction`SELECT pg_sleep(0.1)`;
      }
      return receipt;
    },
  );
}

async function verifyConcurrentReplay(): Promise<void> {
  const snapshot = taskSnapshot({
    dueAt: "2026-09-05T10:00:00Z",
    id: fixture.concurrentTask,
    updatedAt: "2026-09-04T10:00:02Z",
    version: 41,
  });
  const results = await Promise.all([
    concurrentMutation(primary, uuid(1201), snapshot),
    concurrentMutation(contender, uuid(1202), snapshot),
  ]);
  assert.deepEqual(
    results
      .map((result) => result.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
    "concurrent identical requests did not serialize to one exact replay",
  );
  assert.deepEqual(results[0]?.result_snapshot, snapshot);
  assert.deepEqual(results[1]?.result_snapshot, snapshot);
  assert.equal(results[0]?.command_id, results[1]?.command_id);

  const stale = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) => transaction<{ version: string }[]>`
      UPDATE public.dfir_tasks
      SET title='stale write must not land',version=41,
          updated_at='2026-09-04T10:00:03Z'
      WHERE tenant_id=${fixture.tenant}::uuid
        AND case_id=${fixture.mainCase}::uuid
        AND id=${fixture.concurrentTask}::uuid AND version=40
      RETURNING version::text
    `,
  );
  assert.equal(stale.length, 0, "stale task CAS unexpectedly updated a row");
}

async function verifyCreateAndSnapshotPoison(): Promise<void> {
  const validCreate = taskSnapshot({
    checklist: [
      {
        id: fixture.checklistItem,
        title: "Preserve evidence",
        completed: false,
      },
    ],
    id: fixture.createdTask,
    version: 1,
  });
  const created = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [receipt] = await transaction<Reservation[]>`
        SELECT command_id::text,result_resource_id::text,
               result_version::text,result_snapshot,replayed
        FROM app.reserve_case_dfir_command_v1(
          ${uuid(1301)}::uuid,${fixture.mainCase}::uuid,
          'case.dfir.task.create',${fixture.createdTask}::uuid,1,
          ${digest("create:key")},${digest("create:request")},
          ${transaction.json(validCreate)}::jsonb
        )
      `;
      assert(receipt);
      await transaction`
        INSERT INTO public.dfir_tasks(
          id,tenant_id,case_id,title,description,status,priority,checklist,
          comment_ids,created_by_membership_id,updated_by_membership_id,
          version,created_at,updated_at
        ) VALUES (
          ${fixture.createdTask}::uuid,${fixture.tenant}::uuid,
          ${fixture.mainCase}::uuid,'Runtime Case task',
          'Bounded runtime snapshot','todo','medium',
          ${transaction.json([
            {
              id: fixture.checklistItem,
              title: "Preserve evidence",
              completed: false,
            },
          ])}::jsonb,ARRAY[]::uuid[],${fixture.adminMembership}::uuid,
          ${fixture.adminMembership}::uuid,1,
          '2026-09-04T10:00:00Z','2026-09-04T10:00:00Z'
        )
      `;
      return receipt;
    },
  );
  assert.equal(created.replayed, false);
  assert.deepEqual(created.result_snapshot, validCreate);

  await expectSqlState(
    reserve({
      commandID: uuid(1302),
      key: "forged-create",
      operation: "case.dfir.task.create",
      resourceID: uuid(1303),
      snapshot: taskSnapshot({
        completedAt: "2026-09-04T10:00:00Z",
        completedBy: fixture.adminUser,
        completionData: { reason: "forged" },
        id: uuid(1303),
        status: "done",
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "create receipt accepted forged lifecycle state",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1304),
      key: "duplicate-checklist",
      operation: "case.dfir.task.create",
      resourceID: uuid(1305),
      snapshot: taskSnapshot({
        checklist: [
          { id: fixture.checklistItem, title: "One", completed: false },
          { id: fixture.checklistItem, title: "Two", completed: false },
        ],
        id: uuid(1305),
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted duplicate checklist identifiers",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1306),
      key: "missing-provenance",
      operation: "case.dfir.task.create",
      resourceID: uuid(1307),
      snapshot: taskSnapshot({
        checklist: [
          { id: fixture.checklistItem, title: "Forged", completed: true },
        ],
        id: uuid(1307),
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted completed checklist state without server provenance",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1308),
      key: "timestamp-window",
      operation: "case.dfir.task.create",
      resourceID: uuid(1309),
      snapshot: taskSnapshot({
        createdAt: "2026-09-04T10:00:02Z",
        id: uuid(1309),
        updatedAt: "2026-09-04T10:00:01Z",
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted a reversed task timestamp window",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1310),
      key: "noncanonical-instant",
      operation: "case.dfir.task.create",
      resourceID: uuid(1311),
      snapshot: taskSnapshot({
        id: uuid(1311),
        updatedAt: "2026-09-04T10:00:00.123456789Z",
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted sub-microsecond timestamp precision",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1312),
      key: "unsafe-title",
      operation: "case.dfir.task.create",
      resourceID: uuid(1313),
      snapshot: taskSnapshot({
        id: uuid(1313),
        title: "Forged\nmultiline title",
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted a multiline task title",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1314),
      key: "oversized-completion",
      operation: "case.dfir.task.create",
      resourceID: uuid(1315),
      snapshot: taskSnapshot({
        completedAt: "2026-09-04T10:00:00Z",
        completedBy: fixture.adminUser,
        completionData: { padding: "x".repeat(70_000) },
        id: uuid(1315),
        status: "cancelled",
        version: 1,
      }),
      version: 1,
    }),
    "22023",
    "receipt accepted oversized completion data",
  );
}

type GuardTaskInput = {
  alertID?: string;
  assigneeID?: string;
  caseID?: string;
  commentIDs?: string[];
  id: string;
  operatorTeamEpochID?: string;
  operatorTeamID?: string;
  slaInstanceID?: string;
};

async function insertGuardTask(input: GuardTaskInput): Promise<void> {
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      await transaction`
        INSERT INTO public.dfir_tasks(
          id,tenant_id,alert_id,case_id,title,description,status,priority,
          assignee_user_id,operator_team_id,operator_team_epoch_id,checklist,
          comment_ids,sla_instance_id,created_by_membership_id,
          updated_by_membership_id,version,created_at,updated_at
        ) VALUES (
          ${input.id}::uuid,${fixture.tenant}::uuid,
          ${input.alertID ?? null}::uuid,${input.caseID ?? null}::uuid,
          'Reference guard task','Exact root reference validation','todo',
          'medium',${input.assigneeID ?? null}::uuid,
          ${input.operatorTeamID ?? null}::uuid,
          ${input.operatorTeamEpochID ?? null}::uuid,'[]'::jsonb,
          ${input.commentIDs ?? []}::uuid[],${input.slaInstanceID ?? null}::uuid,
          ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,
          1,'2026-09-04T10:00:00Z','2026-09-04T10:00:00Z'
        )
      `;
    },
  );
}

async function verifyReferenceGuard(comments: Comments): Promise<void> {
  await insertGuardTask({
    caseID: fixture.mainCase,
    commentIDs: [comments.mainCase],
    id: uuid(1401),
    slaInstanceID: fixture.mainCaseSla,
  });
  await insertGuardTask({
    alertID: fixture.alert,
    commentIDs: [comments.alert],
    id: uuid(1402),
    slaInstanceID: fixture.alertSla,
  });
  await insertGuardTask({
    assigneeID: fixture.scopedUser,
    caseID: fixture.mainCase,
    id: uuid(1403),
    operatorTeamEpochID: fixture.teamEpoch,
    operatorTeamID: fixture.team,
  });

  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      commentIDs: [comments.mainCase, comments.mainCase],
      id: uuid(1404),
    }),
    "23514",
    "DFIR task accepted duplicate comment references",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      commentIDs: [uuid(1499)],
      id: uuid(1405),
    }),
    "23503",
    "DFIR task accepted an unknown comment reference",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      commentIDs: [comments.otherCase],
      id: uuid(1406),
    }),
    "23503",
    "DFIR task accepted a same-tenant comment from another Case",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      commentIDs: [comments.foreignCase],
      id: uuid(1407),
    }),
    "23503",
    "DFIR task accepted a cross-tenant comment reference",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      id: uuid(1408),
      slaInstanceID: fixture.otherCaseSla,
    }),
    "23503",
    "DFIR task accepted a same-tenant SLA from another Case",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      id: uuid(1409),
      slaInstanceID: fixture.foreignCaseSla,
    }),
    "23503",
    "DFIR task accepted a cross-tenant SLA reference",
  );
  await expectSqlState(
    insertGuardTask({
      assigneeID: fixture.unrosteredUser,
      caseID: fixture.mainCase,
      id: uuid(1410),
      operatorTeamEpochID: fixture.teamEpoch,
      operatorTeamID: fixture.team,
    }),
    "23503",
    "DFIR task accepted an assignee outside the exact team epoch",
  );
  await expectSqlState(
    insertGuardTask({
      caseID: fixture.mainCase,
      id: uuid(1411),
      operatorTeamEpochID: fixture.foreignTeamEpoch,
      operatorTeamID: fixture.foreignTeam,
    }),
    "23503",
    "DFIR task accepted a cross-tenant operator-team epoch",
  );
}

async function appendCaseMutationEffects(
  transaction: TransactionSql,
  input: {
    action: string;
    resourceType: string;
    resourceID: string;
    resourceVersion: number;
    activityKind: "case" | "task";
    activityResourceID: string;
    summary: string;
    before: postgres.JSONValue;
    after: postgres.JSONValue;
    metadata: postgres.JSONValue;
    offset: number;
  },
): Promise<void> {
  await transaction`
    SELECT app.append_phase4_mutation_effects_v1(
      ${input.action.startsWith("dfir.task.") ? "dfir.task.manage" : "dfir.relationship.manage"},
      ${input.action},${input.resourceType},${input.resourceID}::uuid,
      ${input.resourceVersion}::bigint,${fixture.mainCase}::uuid,
      ${uuid(input.offset)}::uuid,${input.activityKind}::public.dfir_entity_kind,
      ${input.activityResourceID}::uuid,${input.summary},
      ${transaction.json(input.before)}::jsonb,
      ${transaction.json(input.after)}::jsonb,
      ${transaction.json(input.metadata)}::jsonb,${uuid(input.offset + 1)}::uuid,
      ${uuid(input.offset + 2)}::uuid,${uuid(input.offset + 3)}::uuid,
      ${uuid(input.offset + 4)}::uuid,'127.0.0.1'::inet,
      'case-dfir-runtime','totp'
    )
  `;
}

async function verifyTaskCommentsReplace(mainComment: string): Promise<void> {
  const key = "task-comments-replace";
  const updatedAt = "2026-09-04T10:00:01Z";
  const checklist = [
    { id: fixture.checklistItem, title: "Preserve evidence", completed: false },
  ];
  const snapshot = taskSnapshot({
    checklist,
    commentIDs: [mainComment],
    id: fixture.createdTask,
    updatedAt,
    version: 2,
  });
  const commandID = uuid(1601);
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [reservation] = await transaction<Reservation[]>`
        SELECT command_id::text,result_resource_id::text,
               result_version::text,result_snapshot,replayed
        FROM app.reserve_case_dfir_command_v1(
          ${commandID}::uuid,${fixture.mainCase}::uuid,
          'case.dfir.task.comments.replace',${fixture.createdTask}::uuid,2,
          ${digest(`${key}:key`)},${digest(`${key}:request`)},
          ${transaction.json(snapshot)}::jsonb
        )
      `;
      assert(reservation, "Case task comment replacement returned no receipt");
      assert.equal(reservation.replayed, false);
      assert.deepEqual(reservation.result_snapshot, snapshot);
      const updated = await transaction<{ version: string }[]>`
        UPDATE public.dfir_tasks
        SET comment_ids=ARRAY[${mainComment}::uuid],version=2,
            updated_by_membership_id=${fixture.adminMembership}::uuid,
            updated_at=${updatedAt}::timestamptz
        WHERE tenant_id=${fixture.tenant}::uuid
          AND case_id=${fixture.mainCase}::uuid AND alert_id IS NULL
          AND id=${fixture.createdTask}::uuid AND version=1
        RETURNING version::text
      `;
      assert.equal(updated[0]?.version, "2");
      await appendCaseMutationEffects(transaction, {
        action: "dfir.task.comments_replaced",
        resourceType: "dfir_task",
        resourceID: fixture.createdTask,
        resourceVersion: 2,
        activityKind: "task",
        activityResourceID: fixture.createdTask,
        summary: "DFIR task comments replaced",
        before: { version: 1, commentCount: 0 },
        after: { version: 2, commentCount: 1 },
        metadata: {
          commandOperation: "case.dfir.task.comments.replace",
          reason: "Associate the reviewed Case comment",
        },
        offset: 1602,
      });
    },
  );

  const later = await primary<{ version: string }[]>`
    UPDATE public.dfir_tasks
    SET title='Runtime Case task after comment association',version=3,
        updated_at='2026-09-04T10:00:02Z'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND case_id=${fixture.mainCase}::uuid AND alert_id IS NULL
      AND id=${fixture.createdTask}::uuid AND version=2
    RETURNING version::text
  `;
  assert.equal(later[0]?.version, "3");

  const replay = await reserve({
    commandID: uuid(1610),
    key,
    operation: "case.dfir.task.comments.replace",
    resourceID: fixture.createdTask,
    version: 2,
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.command_id, commandID);
  assert.deepEqual(
    replay.result_snapshot,
    snapshot,
    "Case task replay followed the later live task version",
  );
  await expectSqlState(
    reserve({
      commandID: uuid(1611),
      key,
      operation: "case.dfir.task.comments.replace",
      request: "task-comments-divergent",
      resourceID: fixture.createdTask,
      version: 2,
    }),
    "23505",
    "Case task comment replay accepted a divergent request",
  );

  const [effects] = await primary<
    { activities: string; audits: string; outbox: string }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.dfir_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND case_id=${fixture.mainCase}::uuid
         AND resource_kind='task' AND resource_id=${fixture.createdTask}::uuid
         AND action='dfir.task.comments_replaced') AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_id=${fixture.createdTask}::uuid
         AND action='dfir.task.comments_replaced') AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND aggregate_id=${fixture.createdTask}::uuid
         AND event_type='dfir.task.comments_replaced') AS outbox
  `;
  assert.deepEqual(effects, { activities: "1", audits: "1", outbox: "1" });
}

type GenericReservation = {
  command_id: string;
  result_resource_id: string;
  result_secondary_resource_id: string;
  result_version: string;
  result_snapshot: postgres.JSONValue;
  replayed: boolean;
};

async function reserveRelationshipRetraction(
  transaction: TransactionSql,
  input: {
    commandID: string;
    caseID?: string;
    key: string;
    request?: string;
    retractionID: string;
    tenantID?: string;
    relationshipID?: string;
  },
): Promise<GenericReservation> {
  const [reservation] = await transaction<GenericReservation[]>`
    SELECT command_id::text,result_resource_id::text,
           result_secondary_resource_id::text,result_version::text,
           result_snapshot,replayed
    FROM app.reserve_dfir_mutation_command_v1(
      ${input.commandID}::uuid,'case',${input.caseID ?? fixture.mainCase}::uuid,
      'dfir.relationship.retract','relationship',
      ${input.relationshipID ?? fixture.relationship}::uuid,
      ${input.retractionID}::uuid,2,
      ${digest(`${input.key}:key`)},
      ${digest(`${input.request ?? input.key}:request`)}
    )
  `;
  assert(reservation, "Case relationship retraction returned no reservation");
  return reservation;
}

async function verifyCaseRelationshipRetraction(): Promise<void> {
  const createdAt = new Date(Date.now() - 5_000);
  const retractedAt = new Date();
  const reason = "Superseded external artifact";
  await primary`
    INSERT INTO public.dfir_relationships(
      id,tenant_id,alert_id,case_id,source_kind,source_id,
      source_external_type,source_external_id,target_kind,target_id,
      target_external_type,target_external_id,relationship_type,metadata,
      created_by_membership_id,version,created_at
    ) VALUES (
      ${fixture.relationship}::uuid,${fixture.tenant}::uuid,NULL,
      ${fixture.mainCase}::uuid,'case',${fixture.mainCase}::uuid,NULL,NULL,
      'external',NULL,'url','https://example.invalid/case-artifact',
      'references','{"confidence":"high"}'::jsonb,
      ${fixture.adminMembership}::uuid,1,${createdAt}::timestamptz
    )
  `;

  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (transaction) => {
      const reservation = await reserveRelationshipRetraction(transaction, {
        commandID: uuid(1701),
        caseID: fixture.otherCase,
        key: "relationship-wrong-root",
        retractionID: uuid(1702),
      });
      await transaction`
          SELECT * FROM app.retract_case_dfir_relationship_v1(
            ${reservation.command_id}::uuid,${fixture.relationship}::uuid,
            ${fixture.otherCase}::uuid,1,${uuid(1702)}::uuid,
            ${reason},${retractedAt}::timestamptz
          )
        `;
    }),
    "P0002",
    "Case relationship retraction escaped to another Case root",
  );
  await expectSqlState(
    asApi(primary, fixture.foreignTenant, fixture.foreignUser, (transaction) =>
      reserveRelationshipRetraction(transaction, {
        commandID: uuid(1703),
        key: "relationship-cross-tenant",
        retractionID: uuid(1704),
      }),
    ),
    "42501",
    "foreign tenant reserved a Case relationship retraction",
  );

  const key = "relationship-retract";
  const snapshot = {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    rootKind: "case",
    rootId: fixture.mainCase,
    operation: "dfir.relationship.retract",
    resourceKind: "relationship",
    resourceId: fixture.relationship,
    secondaryResourceId: fixture.relationshipRetraction,
    resultVersion: 2,
    projection: {
      id: fixture.relationship,
      tenantId: fixture.tenant,
      source: { kind: "case", id: fixture.mainCase },
      target: {
        kind: "external",
        externalType: "url",
        externalId: "https://example.invalid/case-artifact",
      },
      relationshipType: "references",
      metadata: { confidence: "high" },
      createdBy: fixture.adminMembership,
      createdAt: createdAt.toISOString(),
      version: 2,
      retractions: [
        {
          id: fixture.relationshipRetraction,
          tenantId: fixture.tenant,
          relationshipId: fixture.relationship,
          sequence: 1,
          actorId: fixture.adminMembership,
          reason,
          occurredAt: retractedAt.toISOString(),
        },
      ],
    },
  } satisfies postgres.JSONValue;
  const commandID = uuid(1710);
  await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveRelationshipRetraction(transaction, {
        commandID,
        key,
        retractionID: fixture.relationshipRetraction,
      });
      assert.equal(reservation.replayed, false);
      assert.equal(reservation.result_snapshot, null);
      const [retracted] = await transaction<
        { relationship_id: string; relationship_version: string }[]
      >`
        SELECT relationship_id::text,relationship_version::text
        FROM app.retract_case_dfir_relationship_v1(
          ${reservation.command_id}::uuid,${fixture.relationship}::uuid,
          ${fixture.mainCase}::uuid,1,${fixture.relationshipRetraction}::uuid,
          ${reason},${retractedAt}::timestamptz
        )
      `;
      assert.deepEqual(retracted, {
        relationship_id: fixture.relationship,
        relationship_version: "2",
      });
      await appendCaseMutationEffects(transaction, {
        action: "dfir.relationship.retracted",
        resourceType: "dfir_relationship",
        resourceID: fixture.relationship,
        resourceVersion: 2,
        activityKind: "case",
        activityResourceID: fixture.mainCase,
        summary: "DFIR relationship retracted",
        before: { version: 1, active: true, retractionCount: 0 },
        after: { version: 2, active: false, retractionCount: 1 },
        metadata: {
          commandOperation: "dfir.relationship.retract",
          retractionId: fixture.relationshipRetraction,
          reason,
        },
        offset: 1711,
      });
      const [stored] = await transaction<{ stored: boolean }[]>`
        SELECT app.store_dfir_mutation_command_result_v1(
          ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
        ) AS stored
      `;
      assert.equal(stored?.stored, true);
    },
  );

  const replay = await asApi(
    primary,
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveRelationshipRetraction(transaction, {
        commandID: uuid(1720),
        key,
        retractionID: fixture.relationshipRetraction,
      }),
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.command_id, commandID);
  assert.deepEqual(replay.result_snapshot, snapshot);

  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, (transaction) =>
      reserveRelationshipRetraction(transaction, {
        commandID: uuid(1721),
        key: "relationship-same-retraction-new-key",
        retractionID: fixture.relationshipRetraction,
      }),
    ),
    "23505",
    "caller-owned relationship retraction identifier was reusable",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (transaction) => {
      const nextRetraction = uuid(1722);
      const reservation = await reserveRelationshipRetraction(transaction, {
        commandID: uuid(1723),
        key: "relationship-terminal-cas",
        retractionID: nextRetraction,
      });
      await transaction`
          SELECT * FROM app.retract_case_dfir_relationship_v1(
            ${reservation.command_id}::uuid,${fixture.relationship}::uuid,
            ${fixture.mainCase}::uuid,1,${nextRetraction}::uuid,
            'Duplicate terminal retraction',transaction_timestamp()
          )
        `;
    }),
    "40001",
    "terminal Case relationship accepted a second CAS retraction",
  );
  await expectSqlState(
    primary`
      UPDATE public.dfir_relationship_retractions
      SET reason='mutated history'
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.relationshipRetraction}::uuid
    `,
    "55000",
    "Case relationship retraction history was mutable",
  );

  const [effects] = await primary<
    { activities: string; audits: string; outbox: string; registry: string }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.dfir_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND case_id=${fixture.mainCase}::uuid
         AND action='dfir.relationship.retracted'
         AND resource_kind='case' AND resource_id=${fixture.mainCase}::uuid) AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND action='dfir.relationship.retracted'
         AND resource_id=${fixture.relationship}::uuid) AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND event_type='dfir.relationship.retracted'
         AND aggregate_id=${fixture.relationship}::uuid) AS outbox,
      (SELECT count(*)::text FROM public.dfir_mutation_resource_ids
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_kind='relationship_retraction'
         AND resource_id=${fixture.relationshipRetraction}::uuid) AS registry
  `;
  assert.deepEqual(effects, {
    activities: "1",
    audits: "1",
    outbox: "1",
    registry: "1",
  });

  await primary`
    INSERT INTO public.tenant_membership_role_grants(
      id,tenant_id,membership_id,role_id,source_id,
      granted_by_membership_id,grant_reason
    )
    SELECT ${uuid(1740)}::uuid,${fixture.tenant}::uuid,
           ${fixture.scopedMembership}::uuid,role.id,source.id,
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
      reserveRelationshipRetraction(transaction, {
        commandID: uuid(1730),
        key,
        retractionID: fixture.relationshipRetraction,
      }),
    ),
    "42501",
    "revoked actor recovered the immutable relationship replay snapshot",
  );
}

async function main(): Promise<void> {
  await setupCore();
  await verifyDfirResourceVersionConstraints();
  const comments = await setupComments();
  await setupTasks(comments.mainCase);
  await verifyCatalog();
  await verifyScopeAndLookupOnly();
  await verifyHighVersionAndReplay(comments.mainCase);
  await verifyConcurrentReplay();
  await verifyCreateAndSnapshotPoison();
  await verifyReferenceGuard(comments);
  await verifyTaskCommentsReplace(comments.mainCase);
  await verifyCaseRelationshipRetraction();
  // oxlint-disable-next-line no-console -- bounded security harness evidence.
  console.log(
    "case DFIR task comments, relationship retraction, scope, concurrency, JSON-safe revisions, exact replay, and root/reference guards passed",
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
