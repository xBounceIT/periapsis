import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_TICKET_WATCHER_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_WATCHER_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4b21-2000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  watcherUser: uuid(102),
  peerUser: uuid(103),
  inactiveUser: uuid(104),
  customerUser: uuid(105),
  capacityUser: uuid(106),
  foreignUser: uuid(107),
  adminMembership: uuid(201),
  watcherMembership: uuid(202),
  peerMembership: uuid(203),
  inactiveMembership: uuid(204),
  customerMembership: uuid(205),
  capacityMembership: uuid(206),
  foreignMembership: uuid(207),
  readerRole: uuid(301),
  watcherGrant: uuid(311),
  watcherReplacementGrant: uuid(312),
  peerGrant: uuid(313),
  inactiveGrant: uuid(314),
  customerGrant: uuid(315),
  capacityGrant: uuid(316),
  alert: uuid(401),
  raceAlert: uuid(402),
  capacityAlert: uuid(403),
  case: uuid(404),
  foreignAlert: uuid(405),
  preAddEvent: uuid(501),
  betweenEvent: uuid(502),
  teamEvent: uuid(503),
  operatorTeam: uuid(601),
  operatorTeamEpoch: uuid(602),
  operatorTeamRoster: uuid(603),
  operatorTeamSource: uuid(604),
} as const;

const primary = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 3, onnotice: () => undefined });

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-watcher-runtime:${label}`)
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

type RuntimeRole =
  | "periapsis_api"
  | "periapsis_worker"
  | "periapsis_notifier"
  | "periapsis_notification_dispatch_owner";

async function asRole<T>(
  client: typeof primary,
  role: RuntimeRole,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    await transaction`
      SELECT set_config('app.tenant_id',${tenantID},true),
             set_config('app.user_id',${userID},true),
             set_config('app.service_account_id','',true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate','ticket_watcher=runtime',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

type WatcherProjection = {
  schema_version: number;
  tenant_id: string;
  ticket_id: string;
  aggregate_kind: "alert" | "case";
  version: number;
  updated_at: string;
  watchers: Array<{
    user_id: string;
    display_name: string;
    added_at: string;
  }>;
};

type MutationRow = {
  result_version: string;
  result_updated_at: Date;
  result_projection: WatcherProjection;
  replayed: boolean;
};

type Mutation = {
  kind?: "alert" | "case";
  ticketID?: string;
  expectedVersion: number;
  action: "add" | "remove";
  targetUserID?: string;
  key: string;
  request?: string;
  requestID?: string;
  correlationID?: string;
};

async function mutate(
  transaction: TransactionSql,
  input: Mutation,
): Promise<MutationRow> {
  const [row] = await transaction<MutationRow[]>`
    SELECT result_version::text,result_updated_at,result_projection,replayed
    FROM app.mutate_tenant_ticket_watcher_v1(
      ${input.kind ?? "alert"}::public.ticket_aggregate_kind,
      ${input.ticketID ?? fixture.alert}::uuid,
      ${input.expectedVersion}::bigint,
      ${input.action},
      ${input.targetUserID ?? fixture.watcherUser}::uuid,
      ${digest(input.key)},${digest(input.request ?? input.key)},
      ${input.requestID ?? uuid(801)}::uuid,
      ${input.correlationID ?? uuid(802)}::uuid,
      '127.0.0.1'::inet,'ticket-watcher-security','totp'
    )
  `;
  assert(row, "watcher mutation returned no row");
  return row;
}

async function listWatchers(
  transaction: TransactionSql,
  kind: "alert" | "case" = "alert",
  ticketID: string = fixture.alert,
): Promise<WatcherProjection> {
  const [row] = await transaction<
    Array<{ result_projection: WatcherProjection }>
  >`
    SELECT result_projection
    FROM app.list_tenant_ticket_watchers_v1(
      ${kind}::public.ticket_aggregate_kind,${ticketID}::uuid
    )
  `;
  assert(row, "watcher list returned no row");
  return row.result_projection;
}

async function watcherCandidateKinds(eventID: string): Promise<string[]> {
  return asRole(
    primary,
    "periapsis_notification_dispatch_owner",
    fixture.tenant,
    fixture.adminUser,
    async (transaction) => {
      const [row] = await transaction<Array<{ kinds: string[] }>>`
        SELECT ARRAY(
          SELECT jsonb_array_elements_text(candidate.value -> 'kinds')
        ) AS kinds
        FROM app.private_notification_operator_candidates_v1(
          ${fixture.tenant}::uuid,${eventID}::uuid
        ) AS candidate
        WHERE candidate.sort_principal=${fixture.watcherUser}::uuid
      `;
      return row?.kinds ?? [];
    },
  );
}

async function setup(): Promise<void> {
  await primary.begin(async (transaction) => {
    const suffix = sequence.toString(36);
    const ticketNumber = Number(sequence % 700_000n) + 200_000;
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${fixture.tenant}::uuid,${`watchers-${suffix}`},'Watcher runtime'),
        (${fixture.foreignTenant}::uuid,${`watchers-foreign-${suffix}`},
         'Watcher foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.adminUser}::uuid,${`admin-${suffix}@example.invalid`},
         'Admin Operator',true),
        (${fixture.watcherUser}::uuid,${`watcher-${suffix}@example.invalid`},
         'Zulu Watcher',true),
        (${fixture.peerUser}::uuid,${`peer-${suffix}@example.invalid`},
         'Alpha Watcher',true),
        (${fixture.inactiveUser}::uuid,
         ${`inactive-${suffix}@example.invalid`},'Inactive Operator',false),
        (${fixture.customerUser}::uuid,
         ${`customer-${suffix}@example.invalid`},'Customer Contact',true),
        (${fixture.capacityUser}::uuid,
         ${`capacity-${suffix}@example.invalid`},'Capacity Operator',true),
        (${fixture.foreignUser}::uuid,
         ${`foreign-${suffix}@example.invalid`},'Foreign Operator',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      ) VALUES
        (${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid,'tenant_admin','active'),
        (${fixture.watcherMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.watcherUser}::uuid,'analyst','active'),
        (${fixture.peerMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.peerUser}::uuid,'analyst','active'),
        (${fixture.inactiveMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.inactiveUser}::uuid,'analyst','active'),
        (${fixture.customerMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.customerUser}::uuid,'customer_user','active'),
        (${fixture.capacityMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.capacityUser}::uuid,'read_only','active'),
        (${fixture.foreignMembership}::uuid,${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.adminMembership}::uuid,
         ${fixture.adminUser}::uuid,'Admin Operator',
         ${`admin-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.watcherMembership}::uuid,
         ${fixture.watcherUser}::uuid,'Zulu Watcher',
         ${`watcher-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.peerMembership}::uuid,
         ${fixture.peerUser}::uuid,'Alpha Watcher',
         ${`peer-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.inactiveMembership}::uuid,
         ${fixture.inactiveUser}::uuid,'Inactive Operator',
         ${`inactive-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.customerMembership}::uuid,
         ${fixture.customerUser}::uuid,'Customer Contact',
         ${`customer-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.capacityMembership}::uuid,
         ${fixture.capacityUser}::uuid,'Capacity Operator',
         ${`capacity-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,
         ${fixture.foreignUser}::uuid,'Foreign Operator',
         ${`foreign-${suffix}@example.invalid`})
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
        id,tenant_id,key,display_name,description,created_by_membership_id
      ) VALUES (
        ${fixture.readerRole}::uuid,${fixture.tenant}::uuid,
        'ticket_watcher_reader','Ticket watcher reader',
        'Exact read permission used by the watcher runtime proof',
        ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions(
        tenant_id,role_id,permission_id,scope,created_by_membership_id
      )
      SELECT ${fixture.tenant}::uuid,${fixture.readerRole}::uuid,
             permission.id,'tenant',${fixture.adminMembership}::uuid
      FROM public.tenant_permissions AS permission
      WHERE permission.key IN ('alert.read','case.read')
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT input.grant_id,${fixture.tenant}::uuid,input.membership_id,
             ${fixture.readerRole}::uuid,source.id,
             ${fixture.adminMembership}::uuid,'Watcher runtime proof'
      FROM (VALUES
        (${fixture.watcherGrant}::uuid,${fixture.watcherMembership}::uuid),
        (${fixture.peerGrant}::uuid,${fixture.peerMembership}::uuid),
        (${fixture.inactiveGrant}::uuid,${fixture.inactiveMembership}::uuid),
        (${fixture.customerGrant}::uuid,${fixture.customerMembership}::uuid),
        (${fixture.capacityGrant}::uuid,${fixture.capacityMembership}::uuid)
      ) AS input(grant_id,membership_id)
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=${fixture.tenant}::uuid
       AND source.key='manual' AND source.kind='manual'
      AND source.retired_at IS NULL
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources(
        id,tenant_id,kind,key,authoritative,protected
      ) VALUES (
        ${fixture.operatorTeamSource}::uuid,${fixture.tenant}::uuid,
        'identity_mapping',${`watcher-team-${suffix}`},true,false
      )
    `;
    await transaction`
      INSERT INTO public.operator_teams(
        id,key,display_name,description,created_by_user_id
      ) VALUES (
        ${fixture.operatorTeam}::uuid,${`watcher_team_${suffix}`},
        'Watcher proof team','Retired source notification proof',
        ${fixture.adminUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs(
        id,tenant_id,operator_team_id,assigned_by_membership_id,
        assignment_reason
      ) VALUES (
        ${fixture.operatorTeamEpoch}::uuid,${fixture.tenant}::uuid,
        ${fixture.operatorTeam}::uuid,${fixture.adminMembership}::uuid,
        'Watcher notification source retirement proof'
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries(
        id,tenant_id,assignment_epoch_id,membership_id,source_id,
        granted_by_membership_id,grant_reason
      ) VALUES (
        ${fixture.operatorTeamRoster}::uuid,${fixture.tenant}::uuid,
        ${fixture.operatorTeamEpoch}::uuid,${fixture.watcherMembership}::uuid,
        ${fixture.operatorTeamSource}::uuid,${fixture.adminMembership}::uuid,
        'Watcher notification source retirement proof'
      )
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        title,description,severity,priority,category,tags,
        created_by,created_by_membership_id,version,updated_at
      )
      SELECT input.id,${fixture.tenant}::uuid,input.number,workflow.id,
             workflow.current_version,'new',input.title,'Private body',
             'medium','medium','general',ARRAY[]::text[],
             ${fixture.adminUser}::uuid,${fixture.adminMembership}::uuid,
             1,transaction_timestamp()
      FROM (VALUES
        (${fixture.alert}::uuid,${`ALT-2099-${ticketNumber}`},'Watcher alert'),
        (${fixture.raceAlert}::uuid,${`ALT-2099-${ticketNumber + 1}`},
         'Watcher race alert'),
        (${fixture.capacityAlert}::uuid,${`ALT-2099-${ticketNumber + 2}`},
         'Watcher capacity alert')
      ) AS input(id,number,title)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id=${fixture.tenant}::uuid
       AND workflow.key='default_alert'
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.foreignTenant},true),
             set_config('app.user_id',${fixture.foreignUser},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        title,created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${fixture.foreignAlert}::uuid,${fixture.foreignTenant}::uuid,
             ${`ALT-2099-${ticketNumber + 3}`},workflow.id,
             workflow.current_version,'new','Foreign watcher alert',
             ${fixture.foreignUser}::uuid,${fixture.foreignMembership}::uuid,
             1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_alert'
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT ${fixture.case}::uuid,${fixture.tenant}::uuid,
             ${`CAS-2099-${ticketNumber}`},workflow.id,
             workflow.current_version,'open','Watcher case',
             ${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,
             1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_case'
    `;
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,aggregate_version,
        event_type,schema_version,payload,deduplication_key,
        correlation_id,causation_id,actor_kind,actor_id,producer,
        maximum_audience,occurred_at,available_at
      ) VALUES (
        ${fixture.preAddEvent}::uuid,${fixture.tenant}::uuid,'alert',
        ${fixture.alert}::uuid,1,'notification.alert.status_changed',2,
        jsonb_build_object('operatorContext',jsonb_build_object(
          'alert',jsonb_build_object('id',${fixture.alert}::uuid,'version',1),
          'actor',jsonb_build_object('id',${fixture.adminUser}::uuid),
          'action','transitioned','metadata',jsonb_build_object(
            'content_redacted',true
          ),'routing',jsonb_build_object(
            'creatorUserId',${fixture.adminUser}::uuid
          )
        )),${`watcher-pre-add-${suffix}`},${uuid(701)}::uuid,
        ${uuid(702)}::uuid,'human',${fixture.adminUser}::uuid,'ticketing',
        'operator',clock_timestamp(),clock_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,aggregate_version,
        event_type,schema_version,payload,deduplication_key,
        correlation_id,causation_id,actor_kind,actor_id,producer,
        maximum_audience,occurred_at,available_at
      ) VALUES (
        ${fixture.teamEvent}::uuid,${fixture.tenant}::uuid,'alert',
        ${fixture.alert}::uuid,1,'notification.alert.status_changed',2,
        jsonb_build_object('operatorContext',jsonb_build_object(
          'alert',jsonb_build_object('id',${fixture.alert}::uuid,'version',1),
          'actor',jsonb_build_object('id',${fixture.adminUser}::uuid),
          'action','transitioned','metadata',jsonb_build_object(
            'content_redacted',true
          ),'routing',jsonb_build_object(
            'operatorTeamId',${fixture.operatorTeam}::uuid,
            'operatorTeamEpochId',${fixture.operatorTeamEpoch}::uuid
          )
        )),${`watcher-team-${suffix}`},${uuid(703)}::uuid,
        ${uuid(704)}::uuid,'human',${fixture.adminUser}::uuid,'ticketing',
        'operator',clock_timestamp(),clock_timestamp()
      )
    `;
  });
}

async function main(): Promise<void> {
  await setup();

  const [readiness] = await primary<
    Array<{ watcher_ready: boolean; convergence_ready: boolean }>
  >`
    SELECT app.release_runtime_schema_readiness_v60() AS watcher_ready,
           app.private_v47_migration_convergence_schema_readiness_v1()
             AS convergence_ready
  `;
  assert.equal(readiness?.watcher_ready, true);
  assert.equal(readiness?.convergence_ready, true);

  const [bidiGuard] = await primary<Array<{ rejects_all: boolean }>>`
    SELECT bool_and(NOT app.private_ticket_watcher_display_name_valid_v1(
      'Operator ' || chr(codepoint)
    )) AS rejects_all
    FROM unnest(ARRAY[
      8206,8207,8234,8235,8236,8237,8238,8294,8295,8296,8297
    ]::integer[]) AS bidi(codepoint)
  `;
  assert.equal(bidiGuard?.rejects_all, true);

  const [unicodeWhitespaceGuard] = await primary<
    Array<{
      rejects_all_edges: boolean;
      accepts_internal: boolean;
      accepts_non_whitespace_format: boolean;
    }>
  >`
    WITH whitespace(codepoint) AS (
      SELECT unnest(ARRAY[
        9,10,11,12,13,32,133,160,5760,
        8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,
        8232,8233,8239,8287,12288
      ]::integer[])
    ), edge_value(value) AS (
      SELECT chr(codepoint) || 'Operator' FROM whitespace
      UNION ALL
      SELECT 'Operator' || chr(codepoint) FROM whitespace
    )
    SELECT bool_and(
             NOT app.private_ticket_watcher_display_name_valid_v1(value)
           ) AS rejects_all_edges,
           app.private_ticket_watcher_display_name_valid_v1(
             'Operator' || chr(160) || 'One'
           ) AS accepts_internal,
           app.private_ticket_watcher_display_name_valid_v1(
             chr(65279) || 'Operator' || chr(65279)
           ) AS accepts_non_whitespace_format
    FROM edge_value
  `;
  assert.deepEqual(unicodeWhitespaceGuard, {
    rejects_all_edges: true,
    accepts_internal: true,
    accepts_non_whitespace_format: true,
  });

  const unicodeWhitespaceTamperRollback = new Error(
    "rollback watcher Unicode whitespace helper tamper",
  );
  await assert.rejects(
    primary.begin(async (transaction) => {
      await transaction.unsafe(String.raw`
        CREATE OR REPLACE FUNCTION
          app.private_ticket_watcher_display_name_valid_v1(p_value text)
        RETURNS boolean
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path=pg_catalog
        AS $function$
          SELECT btrim(p_value)<>''
            AND btrim(p_value)=p_value
            AND char_length(p_value)<=160
            AND p_value !~ '[[:cntrl:]]'
            AND p_value !~ U&'[\200E\200F\202A-\202E\2066-\2069]';
        $function$;
      `);
      const [tampered] = await transaction<Array<{ ready: boolean }>>`
        SELECT app.release_runtime_schema_readiness_v60() AS ready
      `;
      assert.equal(
        tampered?.ready,
        false,
        "V60 release readiness accepted a helper without Unicode edge whitespace",
      );
      throw unicodeWhitespaceTamperRollback;
    }),
    (error) => error === unicodeWhitespaceTamperRollback,
  );
  const [afterUnicodeWhitespaceTamper] = await primary<
    Array<{ ready: boolean }>
  >`
    SELECT app.release_runtime_schema_readiness_v60() AS ready
  `;
  assert.equal(afterUnicodeWhitespaceTamper?.ready, true);

  await primary.begin(async (transaction) => {
    await transaction`
      ALTER TABLE public.ticket_watcher_events
        DROP CONSTRAINT ticket_watcher_events_display_name_check
    `;
    await transaction`
      ALTER TABLE public.ticket_watcher_events
        ADD CONSTRAINT ticket_watcher_events_display_name_check
        CHECK (display_name_snapshot !~ '[[:cntrl:]]')
    `;
    const [tampered] = await transaction<Array<{ ready: boolean }>>`
      SELECT app.release_runtime_schema_readiness_v60() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "V60 release readiness accepted a watcher snapshot constraint without bidi controls",
    );
    await transaction`
      ALTER TABLE public.ticket_watcher_events
        DROP CONSTRAINT ticket_watcher_events_display_name_check
    `;
    await transaction`
      ALTER TABLE public.ticket_watcher_events
        ADD CONSTRAINT ticket_watcher_events_display_name_check CHECK (
          app.private_ticket_watcher_display_name_valid_v1(display_name_snapshot)
        )
    `;
  });

  await primary.begin(async (transaction) => {
    await transaction`
      GRANT EXECUTE ON FUNCTION app.list_tenant_ticket_watchers_v1(
        public.ticket_aggregate_kind,uuid
      ) TO periapsis_auditor
    `;
    const [tampered] = await transaction<Array<{ ready: boolean }>>`
      SELECT app.release_runtime_schema_readiness_v60() AS ready
    `;
    assert.equal(
      tampered?.ready,
      false,
      "watcher readiness accepted an extra runtime EXECUTE grant",
    );
    await transaction`
      REVOKE ALL ON FUNCTION app.list_tenant_ticket_watchers_v1(
        public.ticket_aggregate_kind,uuid
      ) FROM periapsis_auditor
    `;
  });

  assert(
    (await watcherCandidateKinds(fixture.teamEvent)).includes("operator_team"),
  );
  await primary`
    UPDATE public.tenant_authorization_sources
    SET retired_at=transaction_timestamp()
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.operatorTeamSource}::uuid
  `;
  assert(
    !(await watcherCandidateKinds(fixture.teamEvent)).includes("operator_team"),
    "a retired roster authorization source still produced a team candidate",
  );

  await expectSqlState(
    asRole(
      primary,
      "periapsis_worker",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 1,
          action: "add",
          key: "worker-denied",
        }),
    ),
    "42501",
    "worker execution of the human watcher ABI was not closed",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      async (transaction) => {
        await transaction`SELECT * FROM public.ticket_watcher_events`;
      },
    ),
    "42501",
    "the API role read the private watcher ledger directly",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.foreignTenant,
      fixture.foreignUser,
      (transaction) => listWatchers(transaction),
    ),
    "42501",
    "a foreign tenant discovered the watcher projection",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 1,
          action: "add",
          targetUserID: fixture.inactiveUser,
          key: "inactive-denied",
        }),
    ),
    "42501",
    "an inactive operator became a watcher",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 1,
          action: "add",
          targetUserID: fixture.customerUser,
          key: "customer-denied",
        }),
    ),
    "42501",
    "a customer contact role became an operator watcher",
  );

  await primary`
    UPDATE public.tenant_user_profiles
    SET display_name=chr(160) || 'Alpha Watcher'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.peerUser}::uuid
  `;
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 1,
          action: "add",
          targetUserID: fixture.peerUser,
          key: "unicode-whitespace-display-name-denied",
        }),
    ),
    "23514",
    "a display name with Go TrimSpace edge whitespace entered watcher history",
  );
  const projectionAfterUnicodeWhitespace = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) => listWatchers(transaction),
  );
  assert.equal(projectionAfterUnicodeWhitespace.version, 1);
  assert.deepEqual(projectionAfterUnicodeWhitespace.watchers, []);

  await primary`
    UPDATE public.tenant_user_profiles
    SET display_name='Alpha ' || chr(8238) || 'Watcher'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.peerUser}::uuid
  `;
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 1,
          action: "add",
          targetUserID: fixture.peerUser,
          key: "bidi-display-name-denied",
        }),
    ),
    "23514",
    "a bidi-formatted display name entered watcher history",
  );
  await primary`
    UPDATE public.tenant_user_profiles SET display_name='Alpha Watcher'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.peerUser}::uuid
  `;

  const first = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 1,
        action: "add",
        key: "first-add",
      }),
  );
  assert.equal(first.result_version, "2");
  assert.equal(first.replayed, false);
  assert.deepEqual(
    new Set(Object.keys(first.result_projection)),
    new Set([
      "schema_version",
      "tenant_id",
      "ticket_id",
      "aggregate_kind",
      "version",
      "updated_at",
      "watchers",
    ]),
  );
  assert.equal(first.result_projection.watchers.length, 1);
  assert.deepEqual(first.result_projection.watchers[0], {
    user_id: fixture.watcherUser,
    display_name: "Zulu Watcher",
    added_at: first.result_projection.watchers[0]?.added_at,
  });

  const [addedNotification] = await primary<
    Array<{ id: string; count: string }>
  >`
    SELECT (array_agg(id ORDER BY id))[1]::text AS id,count(*)::text AS count
    FROM public.outbox_events
    WHERE tenant_id=${fixture.tenant}::uuid
      AND aggregate_id=${fixture.alert}::uuid
      AND aggregate_version=2
      AND event_type='notification.alert.watcher_added'
  `;
  assert.equal(addedNotification?.count, "1");
  assert(addedNotification?.id);
  assert(
    !(await watcherCandidateKinds(fixture.preAddEvent)).includes("watcher"),
  );
  assert.equal(
    (await watcherCandidateKinds(addedNotification.id)).filter(
      (kind) => kind === "watcher",
    ).length,
    1,
    "a live watcher was emitted more than once for one notification event",
  );

  await primary`
    UPDATE public.tenant_user_profiles SET display_name='Bravo Watcher'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.watcherUser}::uuid
  `;
  const liveName = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) => listWatchers(transaction),
  );
  assert.deepEqual(liveName, first.result_projection);

  const replay = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 1,
        action: "add",
        key: "first-add",
        requestID: uuid(803),
        correlationID: uuid(804),
      }),
  );
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.result_projection, first.result_projection);
  assert.equal(
    replay.result_updated_at.toISOString(),
    first.result_updated_at.toISOString(),
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 2,
          action: "remove",
          key: "first-add",
          request: "cross-operation-request",
        }),
    ),
    "23505",
    "an idempotency key was reused across watcher operations",
  );

  const addNoop = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 2,
        action: "add",
        key: "add-noop",
      }),
  );
  assert.equal(addNoop.replayed, false);
  assert.equal(addNoop.result_version, "2");

  const [effectsAfterNoop] = await primary<
    Array<{
      activities: string;
      audits: string;
      notifications: string;
      commands: string;
      redacted: boolean;
      leaked: boolean;
    }>
  >`
    SELECT
      (SELECT count(*)::text FROM public.ticket_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND alert_id=${fixture.alert}::uuid
         AND kind='alert.watcher_added') AS activities,
      (SELECT count(*)::text FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_id=${fixture.alert}::uuid
         AND action='tenant.alert.watcher_added') AS audits,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND aggregate_id=${fixture.alert}::uuid
         AND event_type='notification.alert.watcher_added') AS notifications,
      (SELECT count(*)::text FROM public.ticket_watcher_commands
       WHERE tenant_id=${fixture.tenant}::uuid
         AND alert_id=${fixture.alert}::uuid) AS commands,
      EXISTS (
        SELECT 1 FROM public.audit_events
        WHERE tenant_id=${fixture.tenant}::uuid
          AND resource_id=${fixture.alert}::uuid
          AND action='tenant.alert.watcher_added'
          AND metadata ->> 'content_redacted'='true'
      ) AS redacted,
      EXISTS (
        SELECT 1 FROM public.outbox_events
        WHERE tenant_id=${fixture.tenant}::uuid
          AND aggregate_id=${fixture.alert}::uuid
          AND (payload::text LIKE '%Bravo Watcher%'
            OR payload::text LIKE '%example.invalid%')
      ) AS leaked
  `;
  assert.deepEqual(effectsAfterNoop, {
    activities: "1",
    audits: "1",
    notifications: "1",
    commands: "2",
    redacted: true,
    leaked: false,
  });

  await primary`
    UPDATE public.tenant_membership_role_grants SET
      revoked_at=clock_timestamp(),
      revoked_by_membership_id=${fixture.adminMembership}::uuid,
      revoke_reason='Lost watcher read authority',version=version+1,
      updated_at=clock_timestamp()
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.watcherGrant}::uuid
  `;
  assert(
    !(await watcherCandidateKinds(addedNotification.id)).includes("watcher"),
  );
  const replayAfterRevocation = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 1,
        action: "add",
        key: "first-add",
        requestID: uuid(805),
        correlationID: uuid(806),
      }),
  );
  assert.equal(replayAfterRevocation.replayed, true);
  assert.deepEqual(
    replayAfterRevocation.result_projection,
    first.result_projection,
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          expectedVersion: 2,
          action: "add",
          key: "fresh-add-after-revocation",
        }),
    ),
    "42501",
    "a fresh add kept an existing watcher after live read authority was lost",
  );
  const removedAfterRevocation = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 2,
        action: "remove",
        key: "remove-after-revocation",
      }),
  );
  assert.equal(removedAfterRevocation.result_version, "3");
  assert.deepEqual(removedAfterRevocation.result_projection.watchers, []);
  assert(
    !(await watcherCandidateKinds(addedNotification.id)).includes("watcher"),
  );

  const removeNoop = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 3,
        action: "remove",
        key: "remove-noop",
      }),
  );
  assert.equal(removeNoop.replayed, false);
  assert.equal(removeNoop.result_version, "3");

  await primary`
    INSERT INTO public.outbox_events(
      id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
      schema_version,payload,deduplication_key,correlation_id,causation_id,
      actor_kind,actor_id,producer,maximum_audience,occurred_at,available_at
    ) VALUES (
      ${fixture.betweenEvent}::uuid,${fixture.tenant}::uuid,'alert',
      ${fixture.alert}::uuid,3,'notification.alert.status_changed',2,
      jsonb_build_object('operatorContext',jsonb_build_object(
        'alert',jsonb_build_object('id',${fixture.alert}::uuid,'version',3),
        'actor',jsonb_build_object('id',${fixture.adminUser}::uuid),
        'action','transitioned','metadata',jsonb_build_object(
          'content_redacted',true
        ),'routing',jsonb_build_object(
          'creatorUserId',${fixture.adminUser}::uuid
        )
      )),${`watcher-between-${sequence.toString(36)}`},${uuid(711)}::uuid,
      ${uuid(712)}::uuid,'human',${fixture.adminUser}::uuid,'ticketing',
      'operator',clock_timestamp(),clock_timestamp()
    )
  `;
  await primary`
    INSERT INTO public.tenant_membership_role_grants(
      id,tenant_id,membership_id,role_id,source_id,
      granted_by_membership_id,grant_reason
    )
    SELECT ${fixture.watcherReplacementGrant}::uuid,${fixture.tenant}::uuid,
           ${fixture.watcherMembership}::uuid,${fixture.readerRole}::uuid,
           source.id,${fixture.adminMembership}::uuid,
           'Watcher read authority restored'
    FROM public.tenant_authorization_sources AS source
    WHERE source.tenant_id=${fixture.tenant}::uuid
      AND source.key='manual' AND source.kind='manual'
      AND source.retired_at IS NULL
  `;
  const readded = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 3,
        action: "add",
        key: "re-add",
      }),
  );
  assert.equal(readded.result_version, "4");
  assert.equal(
    readded.result_projection.watchers[0]?.display_name,
    "Bravo Watcher",
  );
  assert.notEqual(
    readded.result_projection.watchers[0]?.added_at,
    first.result_projection.watchers[0]?.added_at,
  );
  assert(
    !(await watcherCandidateKinds(fixture.preAddEvent)).includes("watcher"),
  );
  assert(
    !(await watcherCandidateKinds(fixture.betweenEvent)).includes("watcher"),
  );
  const [readdNotification] = await primary<Array<{ id: string }>>`
    SELECT id::text FROM public.outbox_events
    WHERE tenant_id=${fixture.tenant}::uuid
      AND aggregate_id=${fixture.alert}::uuid
      AND aggregate_version=4
      AND event_type='notification.alert.watcher_added'
  `;
  assert(readdNotification?.id);
  assert.equal(
    (await watcherCandidateKinds(readdNotification.id)).filter(
      (kind) => kind === "watcher",
    ).length,
    1,
    "a re-added watcher was emitted more than once for one notification event",
  );

  await primary`
    UPDATE public.users SET active=false
    WHERE id=${fixture.watcherUser}::uuid
  `;
  assert(
    !(await watcherCandidateKinds(readdNotification.id)).includes("watcher"),
  );
  const removedWhileInactive = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        expectedVersion: 4,
        action: "remove",
        key: "remove-inactive",
      }),
  );
  assert.equal(removedWhileInactive.result_version, "5");

  const caseAdd = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      mutate(transaction, {
        kind: "case",
        ticketID: fixture.case,
        expectedVersion: 1,
        action: "add",
        targetUserID: fixture.peerUser,
        key: "case-add",
      }),
  );
  assert.equal(caseAdd.result_projection.aggregate_kind, "case");
  assert.equal(caseAdd.result_projection.version, 2);
  const [caseNotification] = await primary<Array<{ count: string }>>`
    SELECT count(*)::text AS count FROM public.outbox_events
    WHERE tenant_id=${fixture.tenant}::uuid
      AND aggregate_id=${fixture.case}::uuid
      AND event_type='notification.case.watcher_added'
  `;
  assert.equal(caseNotification?.count, "1");

  const sameKeyInput: Mutation = {
    ticketID: fixture.raceAlert,
    expectedVersion: 1,
    action: "add",
    targetUserID: fixture.peerUser,
    key: "same-key-race",
  };
  const sameKey = await Promise.all([
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) => mutate(transaction, sameKeyInput),
    ),
    asRole(
      contender,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) => mutate(transaction, sameKeyInput),
    ),
  ]);
  assert.deepEqual(
    sameKey
      .map((result) => result.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );
  assert.deepEqual(
    sameKey[0]?.result_projection,
    sameKey[1]?.result_projection,
  );

  const casRace = await Promise.allSettled([
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          ticketID: fixture.raceAlert,
          expectedVersion: 2,
          action: "add",
          targetUserID: fixture.capacityUser,
          key: "cas-race-a",
        }),
    ),
    asRole(
      contender,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          ticketID: fixture.raceAlert,
          expectedVersion: 2,
          action: "remove",
          targetUserID: fixture.peerUser,
          key: "cas-race-b",
        }),
    ),
  ]);
  assert.equal(
    casRace.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const casRejected = casRace.find((result) => result.status === "rejected");
  assert(casRejected?.status === "rejected");
  assertSqlState(casRejected.reason, "40001");

  await primary.begin(async (transaction) => {
    await transaction`
      CREATE TEMP TABLE capacity_watcher_fixture(
        user_id uuid PRIMARY KEY,membership_id uuid NOT NULL,
        ordinal integer NOT NULL
      ) ON COMMIT DROP
    `;
    await transaction`
      INSERT INTO capacity_watcher_fixture(user_id,membership_id,ordinal)
      SELECT uuidv7(),uuidv7(),ordinal
      FROM generate_series(1,1000) AS ordinal
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      SELECT user_id,
             'capacity-'||ordinal::text||'-'||${sequence.toString(36)}
               ||'@example.invalid',
             'Capacity '||lpad(ordinal::text,4,'0'),true
      FROM capacity_watcher_fixture
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      )
      SELECT membership_id,${fixture.tenant}::uuid,user_id,
             'read_only','active'
      FROM capacity_watcher_fixture
    `;
    await transaction`
      UPDATE public.alerts SET version=1001,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.capacityAlert}::uuid
    `;
    await transaction`
      SELECT set_config('app.ticket_runtime_write_v1','enabled',true)
    `;
    await transaction`
      INSERT INTO public.ticket_watcher_events(
        tenant_id,alert_id,target_user_id,action,display_name_snapshot,
        ticket_version,actor_membership_id,actor_user_id,occurred_at
      )
      SELECT ${fixture.tenant}::uuid,${fixture.capacityAlert}::uuid,user_id,
             'add','Capacity '||lpad(ordinal::text,4,'0'),ordinal+1,
             ${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,
             transaction_timestamp()
      FROM capacity_watcher_fixture
    `;
  });
  const capacityProjection = await asRole(
    primary,
    "periapsis_api",
    fixture.tenant,
    fixture.adminUser,
    (transaction) => listWatchers(transaction, "alert", fixture.capacityAlert),
  );
  assert.equal(capacityProjection.watchers.length, 1000);
  assert.equal(
    capacityProjection.watchers.at(0)?.display_name,
    "Capacity 0001",
  );
  assert.equal(
    capacityProjection.watchers.at(-1)?.display_name,
    "Capacity 1000",
  );
  await expectSqlState(
    asRole(
      primary,
      "periapsis_api",
      fixture.tenant,
      fixture.adminUser,
      (transaction) =>
        mutate(transaction, {
          ticketID: fixture.capacityAlert,
          expectedVersion: 1001,
          action: "add",
          targetUserID: fixture.capacityUser,
          key: "capacity-overflow",
        }),
    ),
    "54000",
    "a 1001st live watcher bypassed the cardinality limit",
  );

  const [commandClock] = await primary<Array<{ invalid: string }>>`
    SELECT count(*) FILTER (
      WHERE result_updated_at>created_at
    )::text AS invalid
    FROM public.ticket_watcher_commands
    WHERE tenant_id=${fixture.tenant}::uuid
  `;
  assert.equal(
    commandClock?.invalid,
    "0",
    "a watcher result timestamp exceeded its transaction command timestamp",
  );

  await expectSqlState(
    primary`
      UPDATE drizzle.__periapsis_migration_convergence_attestations
      SET attested_at=attested_at
      WHERE convergence_version=46
    `,
    "55000",
    "the V46 convergence attestation was updateable",
  );
  await expectSqlState(
    primary`
      DELETE FROM drizzle.__periapsis_migration_convergence_attestations
      WHERE convergence_version=46
    `,
    "55000",
    "the V46 convergence attestation was deletable",
  );
  await expectSqlState(
    primary`TRUNCATE drizzle.__periapsis_migration_convergence_attestations`,
    "55000",
    "the V46 convergence attestation was truncatable",
  );
  const [migrationEvidence] = await primary<
    Array<{
      metadata_hash: string;
      compatibility_hash: string;
      attestation_count: string;
    }>
  >`
    SELECT
      (SELECT lower(hash::text) FROM drizzle.__drizzle_migrations
       WHERE created_at=1788128074116) AS metadata_hash,
      (SELECT lower(hash::text) FROM drizzle.__drizzle_migrations
       WHERE created_at=1788128702258) AS compatibility_hash,
      (SELECT count(*)::text
       FROM drizzle.__periapsis_migration_convergence_attestations
       WHERE convergence_version=46) AS attestation_count
  `;
  assert(migrationEvidence);
  assert.equal(migrationEvidence.attestation_count, "1");
  assert(
    [
      "0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e",
      "6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4",
    ].includes(migrationEvidence.metadata_hash),
  );
  assert(
    [
      "0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c",
      "fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea",
    ].includes(migrationEvidence.compatibility_hash),
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
