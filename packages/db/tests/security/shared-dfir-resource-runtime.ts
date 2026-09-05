/* eslint-disable no-await-in-loop -- Each assertion observes the preceding committed CAS/replay state. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

type Reservation = {
  command_id: string;
  replayed: boolean;
  result_resource_id: string;
  result_secondary_resource_id: string;
  result_snapshot: postgres.JSONValue;
  result_version: string;
};

const databaseUrl =
  process.env.PERIAPSIS_SHARED_DFIR_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SHARED_DFIR_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4a30-1000-7000-8000-${(sequence + BigInt(offset))
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
  return createHash("sha256").update(`shared-dfir-runtime:${label}`).digest();
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
        (${fixture.tenant}::uuid,${`shared-dfir-${suffix}`},'Case DFIR runtime'),
        (${fixture.foreignTenant}::uuid,${`shared-dfir-foreign-${suffix}`},'Foreign Case DFIR runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.adminUser}::uuid,${`shared-dfir-admin-${suffix}@example.invalid`},'Case administrator',true),
        (${fixture.scopedUser}::uuid,${`shared-dfir-scoped-${suffix}@example.invalid`},'Case scoped operator',true),
        (${fixture.unrosteredUser}::uuid,${`shared-dfir-unrostered-${suffix}@example.invalid`},'Unrostered operator',true),
        (${fixture.foreignUser}::uuid,${`shared-dfir-foreign-${suffix}@example.invalid`},'Foreign administrator',true)
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
        (${fixture.tenant}::uuid,${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,'Case administrator',${`shared-dfir-admin-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.scopedMembership}::uuid,${fixture.scopedUser}::uuid,'Case scoped operator',${`shared-dfir-scoped-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.unrosteredMembership}::uuid,${fixture.unrosteredUser}::uuid,'Unrostered operator',${`shared-dfir-unrostered-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,${fixture.foreignUser}::uuid,'Foreign administrator',${`shared-dfir-foreign-${suffix}@example.invalid`})
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
      WHERE permission.key IN ('dfir.ioc.manage','dfir.asset.manage','dfir.attachment.manage')
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

type ResourceKind = "ioc" | "asset";
type LinkInput = {
  kind: ResourceKind;
  rootKind: "case" | "alert";
  rootID: string;
  resourceID: string;
  eventID: string;
  version: number;
  linked: boolean;
  key: string;
  userID?: string;
};
let nextOffset = 2000;
const nextID = (): string => uuid(nextOffset++);

async function seedResource(kind: ResourceKind): Promise<string> {
  const id = nextID();
  await primary.begin(async (tx) => {
    if (kind === "ioc") {
      await tx`INSERT INTO public.dfir_iocs(
        id,tenant_id,type,value,normalized_value,source,confidence,tlp,first_seen,last_seen,malicious_state,created_by_membership_id,updated_by_membership_id
      ) VALUES (${id}::uuid,${fixture.tenant}::uuid,'domain',${`${id}.example.invalid`},${`${id}.example.invalid`},
        'runtime',50,'amber','2026-09-04T00:00:00Z','2026-09-04T00:00:00Z','unknown',${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid)`;
      await tx`INSERT INTO public.dfir_ioc_links(id,tenant_id,ioc_id,case_id,created_by_membership_id)
        VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${id}::uuid,${fixture.mainCase}::uuid,${fixture.adminMembership}::uuid)`;
    } else {
      await tx`INSERT INTO public.dfir_assets(
        id,tenant_id,hostname,normalized_hostname,original_identifiers,asset_type,criticality,environment,first_seen,last_seen,created_by_membership_id,updated_by_membership_id
      ) VALUES (${id}::uuid,${fixture.tenant}::uuid,'shared-host','shared-host',
        '{"hostname":"shared-host"}'::jsonb,'server','medium','test','2026-09-04T00:00:00Z','2026-09-04T00:00:00Z',${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid)`;
      await tx`INSERT INTO public.dfir_asset_links(id,tenant_id,asset_id,case_id,created_by_membership_id)
        VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${id}::uuid,${fixture.mainCase}::uuid,${fixture.adminMembership}::uuid)`;
    }
  });
  return id;
}

async function resourceSnapshot(
  tx: TransactionSql,
  input: LinkInput,
): Promise<postgres.JSONValue> {
  const projection =
    input.kind === "ioc"
      ? (
          await tx<{ projection: postgres.JSONValue }[]>`
      SELECT jsonb_build_object('id',id,'tenantId',tenant_id,'type',type,'value',value,
        'normalizedValue',normalized_value,'description',description,'source',source,
        'confidence',confidence,'tlp',tlp,'firstSeen',first_seen,'lastSeen',last_seen,
        'malicious',malicious_state,'tags',to_jsonb(tags)) AS projection
      FROM public.dfir_iocs WHERE tenant_id=${fixture.tenant}::uuid AND id=${input.resourceID}::uuid`
        )[0]?.projection
      : (
          await tx<{ projection: postgres.JSONValue }[]>`
      SELECT jsonb_build_object('id',id,'tenantId',tenant_id,'hostname',hostname,
        'normalizedHostname',normalized_hostname,'fqdn',coalesce(fqdn,''),'normalizedFqdn',coalesce(normalized_fqdn,''),
        'ipAddresses',to_jsonb(ip_addresses),'macAddresses',to_jsonb(mac_addresses),
        'assetType',asset_type,'operatingSystem',operating_system,'owner',owner,
        'businessUnit',business_unit,'criticality',criticality,'environment',environment,
        'externalId',coalesce(external_id,''),'tags',to_jsonb(tags),'firstSeen',first_seen,'lastSeen',last_seen) AS projection
      FROM public.dfir_assets WHERE tenant_id=${fixture.tenant}::uuid AND id=${input.resourceID}::uuid`
        )[0]?.projection;
  assert(projection);
  return {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    rootKind: input.rootKind,
    rootId: input.rootID,
    operation: `dfir.${input.kind}.${input.linked ? "link" : "unlink"}`,
    resourceKind: input.kind,
    resourceId: input.resourceID,
    secondaryResourceId: input.eventID,
    resultVersion: input.version + 1,
    projection,
  };
}

async function changeLink(
  input: LinkInput,
  client = primary,
): Promise<Reservation> {
  return asApi(
    client,
    fixture.tenant,
    input.userID ?? fixture.adminUser,
    async (tx) => {
      const operation = `dfir.${input.kind}.${input.linked ? "link" : "unlink"}`;
      const [receipt] = await tx<
        Reservation[]
      >`SELECT command_id::text,replayed,
        result_resource_id::text,result_secondary_resource_id::text,result_version::text,result_snapshot
      FROM app.reserve_dfir_mutation_command_v1(
        ${nextID()}::uuid,${input.rootKind}::public.dfir_mutation_root_kind,${input.rootID}::uuid,
        ${operation},${input.kind},${input.resourceID}::uuid,${input.eventID}::uuid,
        ${input.version + 1}::bigint,${digest(input.key)},${digest(JSON.stringify(input))}
      )`;
      assert(receipt);
      if (!receipt.replayed) {
        await tx`SELECT app.change_dfir_shared_link_v1(
        ${receipt.command_id}::uuid,${nextID()}::uuid,${nextID()}::uuid,
        ${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,'shared-dfir-runtime','totp')`;
        receipt.result_snapshot = await resourceSnapshot(tx, input);
        await tx`SELECT app.store_dfir_mutation_command_result_v1(
        ${receipt.command_id}::uuid,${tx.json(receipt.result_snapshot)}::jsonb)`;
      }
      return receipt;
    },
  );
}

async function assertResourceVersion(
  kind: ResourceKind,
  id: string,
  expected: number,
): Promise<void> {
  const [row] =
    kind === "ioc"
      ? await primary<
          { version: string }[]
        >`SELECT version::text FROM public.dfir_iocs WHERE id=${id}::uuid`
      : await primary<
          { version: string }[]
        >`SELECT version::text FROM public.dfir_assets WHERE id=${id}::uuid`;
  assert.equal(row?.version, String(expected));
}

async function lifecycleMatrix(): Promise<void> {
  for (const kind of ["ioc", "asset"] as const) {
    const resourceID = await seedResource(kind);
    const linkCase: LinkInput = {
      kind,
      resourceID,
      rootKind: "case",
      rootID: fixture.otherCase,
      eventID: nextID(),
      version: 1,
      linked: true,
      key: `${kind}:link-case`,
    };
    const first = await changeLink(linkCase);
    assert.equal(first.replayed, false);
    assert.equal(first.result_secondary_resource_id, linkCase.eventID);
    assert.equal(first.result_version, "2");
    const replay = await changeLink(linkCase);
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.result_snapshot, first.result_snapshot);
    const linkAlert: LinkInput = {
      ...linkCase,
      rootKind: "alert",
      rootID: fixture.alert,
      eventID: nextID(),
      version: 2,
      key: `${kind}:link-alert`,
    };
    await changeLink(linkAlert);
    await assertResourceVersion(kind, resourceID, 3);
    await expectSqlState(
      changeLink({
        ...linkAlert,
        version: 1,
        eventID: nextID(),
        key: `${kind}:duplicate`,
      }),
      "23514",
      "duplicate association succeeded",
    );
    await expectSqlState(
      changeLink({
        ...linkCase,
        rootID: fixture.foreignCase,
        eventID: nextID(),
        version: 3,
        key: `${kind}:foreign`,
      }),
      "42501",
      "cross-tenant root accepted",
    );
    await expectSqlState(
      changeLink({
        ...linkCase,
        rootID: fixture.mainCase,
        linked: false,
        version: 3,
        eventID: nextID(),
        userID: fixture.scopedUser,
        key: `${kind}:scoped`,
      }),
      "42501",
      "path-only authority changed shared resource",
    );
    const unlinkCase: LinkInput = {
      ...linkCase,
      linked: false,
      version: 3,
      eventID: nextID(),
      key: `${kind}:unlink-case`,
    };
    const unlinked = await changeLink(unlinkCase);
    await assertResourceVersion(kind, resourceID, 4);
    const unlinkReplay = await changeLink(unlinkCase);
    assert.equal(unlinkReplay.replayed, true);
    assert.deepEqual(unlinkReplay.result_snapshot, unlinked.result_snapshot);
    await expectSqlState(
      changeLink(linkCase),
      "42501",
      "link replay disclosed a resource after its path association was removed",
    );
    const unlinkAlert: LinkInput = {
      ...linkAlert,
      linked: false,
      version: 4,
      eventID: nextID(),
      key: `${kind}:unlink-alert`,
    };
    await changeLink(unlinkAlert);
    await assertResourceVersion(kind, resourceID, 5);
    assert.deepEqual(
      (await changeLink(unlinkCase)).result_snapshot,
      unlinked.result_snapshot,
    );
    await expectSqlState(
      changeLink({
        ...unlinkCase,
        rootID: fixture.mainCase,
        version: 5,
        eventID: nextID(),
        key: `${kind}:last`,
      }),
      "23514",
      "last association removed",
    );
    const [counts] = await primary<
      { events: string; activities: string; outbox: string }[]
    >`
      SELECT
        (SELECT count(*)::text FROM public.dfir_shared_resource_link_events WHERE tenant_id=${fixture.tenant}::uuid AND coalesce(ioc_id,asset_id)=${resourceID}::uuid) AS events,
        (SELECT count(*)::text FROM (
          SELECT details FROM public.dfir_activities WHERE tenant_id=${fixture.tenant}::uuid
          UNION ALL SELECT details FROM public.ticket_activities WHERE tenant_id=${fixture.tenant}::uuid
        ) AS activity WHERE details->>'resourceId'=${resourceID}) AS activities,
        (SELECT count(*)::text FROM public.outbox_events WHERE tenant_id=${fixture.tenant}::uuid AND aggregate_id=${resourceID}::uuid) AS outbox`;
    assert.deepEqual(counts, { events: "5", activities: "10", outbox: "4" });
    await expectSqlState(
      primary`UPDATE public.dfir_shared_resource_link_events SET event_kind='imported' WHERE id=${linkCase.eventID}::uuid`,
      "55000",
      "immutable history changed",
    );
    await expectSqlState(
      changeLink({
        ...linkCase,
        eventID: unlinkCase.eventID,
        version: 5,
        key: `${kind}:event-reuse`,
      }),
      "23505",
      "unlink event UUID reused",
    );
  }
}

async function concurrentCAS(): Promise<void> {
  const resourceID = await seedResource("ioc");
  const base: LinkInput = {
    kind: "ioc",
    resourceID,
    rootKind: "case",
    rootID: fixture.otherCase,
    eventID: nextID(),
    version: 1,
    linked: true,
    key: "race-case",
  };
  const results = await Promise.allSettled([
    changeLink(base),
    changeLink(
      {
        ...base,
        rootKind: "alert",
        rootID: fixture.alert,
        eventID: nextID(),
        key: "race-alert",
      },
      contender,
    ),
  ]);
  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejected = results.find((result) => result.status === "rejected");
  assert(rejected?.status === "rejected");
  assertSqlState(rejected.reason, "40001");
  await assertResourceVersion("ioc", resourceID, 2);
}

async function danglingReferences(): Promise<void> {
  for (const kind of ["ioc", "asset"] as const) {
    for (const rootKind of ["case", "alert"] as const) {
      const resourceID = await seedResource(kind);
      const rootID = rootKind === "case" ? fixture.otherCase : fixture.alert;
      const base: LinkInput = {
        kind,
        resourceID,
        rootKind,
        rootID,
        eventID: nextID(),
        version: 1,
        linked: true,
        key: `references:${kind}:${rootKind}`,
      };
      await changeLink(base);
      const timelineID = nextID();
      await primary.begin(async (tx) => {
        await tx`INSERT INTO public.dfir_timeline_events(
          id,tenant_id,case_id,alert_id,event_time,ingested_at,original_timezone,precision,source,category,title,created_by_membership_id
        ) VALUES(${timelineID}::uuid,${fixture.tenant}::uuid,${rootKind === "case" ? rootID : null}::uuid,
          ${rootKind === "alert" ? rootID : null}::uuid,now(),now(),'UTC','second','runtime','observed','Bounded linked timeline',${fixture.adminMembership}::uuid)`;
        if (kind === "ioc")
          await tx`INSERT INTO public.dfir_timeline_ioc_links(tenant_id,timeline_event_id,ioc_id)
          VALUES(${fixture.tenant}::uuid,${timelineID}::uuid,${resourceID}::uuid)`;
        else
          await tx`INSERT INTO public.dfir_timeline_asset_links(tenant_id,timeline_event_id,asset_id)
          VALUES(${fixture.tenant}::uuid,${timelineID}::uuid,${resourceID}::uuid)`;
      });
      const unlink: LinkInput = {
        ...base,
        linked: false,
        version: 2,
        eventID: nextID(),
        key: `timeline:${kind}:${rootKind}`,
      };
      await expectSqlState(
        changeLink(unlink),
        "23503",
        "unlink left a dangling timeline reference",
      );
      // Use a separate resource so the relationship assertion cannot pass because of the timeline.
      const relatedID = await seedResource(kind);
      await changeLink({
        ...base,
        resourceID: relatedID,
        eventID: nextID(),
        key: `relation-link:${kind}:${rootKind}`,
      });
      await primary`INSERT INTO public.dfir_relationships(
        id,tenant_id,case_id,alert_id,source_kind,source_id,target_kind,target_id,relationship_type,created_by_membership_id
      ) VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${rootKind === "case" ? rootID : null}::uuid,
        ${rootKind === "alert" ? rootID : null}::uuid,${kind}::public.dfir_entity_kind,${relatedID}::uuid,
        ${rootKind}::public.dfir_entity_kind,${rootID}::uuid,'related_to',${fixture.adminMembership}::uuid)`;
      await expectSqlState(
        changeLink({
          ...unlink,
          resourceID: relatedID,
          eventID: nextID(),
          key: `relation:${kind}:${rootKind}`,
        }),
        "23503",
        "unlink left a dangling relationship reference",
      );
    }
  }
}

async function rootCardinality(): Promise<void> {
  const resourceID = await seedResource("ioc");
  await primary.begin(async (tx) => {
    await tx`SELECT set_config('app.tenant_id',${fixture.tenant},true),set_config('app.user_id',${fixture.adminUser},true)`;
    for (let index = 0; index < 63; index++) {
      const caseID = nextID();
      await tx`INSERT INTO public.cases(id,tenant_id,number,workflow_id,workflow_version,state_key,title,created_by_membership_id,created_by_user_id)
        SELECT ${caseID}::uuid,tenant_id,${`CAS-2096-${String(100000 + index)}`},
          workflow_id,workflow_version,state_key,'Fanout bound fixture',created_by_membership_id,created_by_user_id
        FROM public.cases WHERE id=${fixture.mainCase}::uuid`;
      await tx`INSERT INTO public.dfir_ioc_links(id,tenant_id,ioc_id,case_id,created_by_membership_id)
        VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${resourceID}::uuid,${caseID}::uuid,${fixture.adminMembership}::uuid)`;
    }
  });
  await assertResourceVersion("ioc", resourceID, 64);
  const base: LinkInput = {
    kind: "ioc",
    resourceID,
    rootKind: "case",
    rootID: fixture.otherCase,
    eventID: nextID(),
    version: 64,
    linked: true,
    key: "fanout-65",
  };
  await expectSqlState(
    changeLink(base),
    "23514",
    "resource was shared into a 65th root",
  );
  await changeLink({
    ...base,
    rootID: fixture.mainCase,
    linked: false,
    eventID: nextID(),
    key: "fanout-unlink",
  });
  await assertResourceVersion("ioc", resourceID, 65);
  await changeLink({
    ...base,
    eventID: nextID(),
    version: 65,
    key: "fanout-restored",
  });
  await assertResourceVersion("ioc", resourceID, 66);
}

async function revokedReplay(): Promise<void> {
  const resourceID = await seedResource("asset");
  await primary`UPDATE public.tenant_role_permissions SET scope='tenant'
    WHERE tenant_id=${fixture.tenant}::uuid AND role_id=${fixture.scopedRole}::uuid`;
  const base: LinkInput = {
    kind: "asset",
    resourceID,
    rootKind: "case",
    rootID: fixture.otherCase,
    eventID: nextID(),
    version: 1,
    linked: true,
    key: "revoked-link",
    userID: fixture.scopedUser,
  };
  await changeLink(base);
  const unlink: LinkInput = {
    ...base,
    eventID: nextID(),
    version: 2,
    linked: false,
    key: "revoked-unlink",
  };
  await changeLink(unlink);
  await primary`UPDATE public.tenant_role_permissions SET scope='operator_team'
    WHERE tenant_id=${fixture.tenant}::uuid AND role_id=${fixture.scopedRole}::uuid
      AND permission_id IN (SELECT id FROM public.tenant_permissions WHERE key IN ('dfir.ioc.manage','dfir.asset.manage','dfir.attachment.manage'))`;
  await expectSqlState(
    changeLink(unlink),
    "42501",
    "removed-path unlink replay bypassed current path permission",
  );
  await primary`UPDATE public.tenant_memberships SET status='suspended'
    WHERE id=${fixture.scopedMembership}::uuid`;
  await expectSqlState(
    changeLink(unlink),
    "42501",
    "revoked actor recovered historical resource",
  );
}

type UploadInput = {
  kind: ResourceKind;
  subjectID: string;
  rootKind: "case" | "alert";
  rootID: string;
  storageID: string;
  attachmentID: string;
  key: string;
  userID: string;
  membershipID: string;
};
async function prepareSharedUpload(input: UploadInput): Promise<Reservation> {
  return asApi(primary, fixture.tenant, input.userID, async (tx) => {
    const [receipt] = await tx<
      Reservation[]
    >`SELECT command_id::text,replayed,result_resource_id::text,
      result_secondary_resource_id::text,result_version::text,result_snapshot
      FROM app.reserve_dfir_mutation_command_v1(${nextID()}::uuid,${input.rootKind}::public.dfir_mutation_root_kind,
        ${input.rootID}::uuid,'dfir.attachment.prepare','storage_object',${input.storageID}::uuid,
        ${input.attachmentID}::uuid,1,${digest(input.key)},${digest(input.key + ":request")})`;
    assert(receipt);
    if (receipt.replayed) return receipt;
    const [storage] = await tx<
      { created_at: Date; upload_expires_at: Date }[]
    >`INSERT INTO public.dfir_storage_objects(
      id,tenant_id,bucket,object_key,original_filename,classification,expected_size_bytes,upload_expires_at,state,created_by_membership_id
    ) VALUES(${input.storageID}::uuid,${fixture.tenant}::uuid,'runtime-bucket',${fixture.tenant + "/" + input.storageID},
      'sensitive-original.txt','restricted',10,now()+interval '15 minutes','pending_upload',${input.membershipID}::uuid)
      RETURNING created_at,upload_expires_at`;
    assert(storage);
    await tx`INSERT INTO public.dfir_attachments(
      id,tenant_id,subject_kind,ioc_id,asset_id,storage_object_id,original_filename,visibility,scan_state,uploaded_by_membership_id,uploaded_at
    ) VALUES(${input.attachmentID}::uuid,${fixture.tenant}::uuid,${input.kind}::public.dfir_entity_kind,
      ${input.kind === "ioc" ? input.subjectID : null}::uuid,${input.kind === "asset" ? input.subjectID : null}::uuid,
      ${input.storageID}::uuid,'sensitive-original.txt','private','pending_upload',${input.membershipID}::uuid,${storage.created_at})`;
    if (input.rootKind === "alert") {
      await tx`SELECT app.append_alert_dfir_mutation_effects_v1(
        ${input.rootID}::uuid,'dfir.attachment.manage','dfir.attachment.prepared','dfir_storage_object',
        ${input.storageID}::uuid,1,'dfir.attachment.prepare',${digest(input.key)},${digest(input.key + ":request")},
        ${nextID()}::uuid,'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,
        ${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,'shared-dfir-runtime','totp')`;
    } else {
      await tx`SELECT app.append_phase4_mutation_effects_v1(
        'dfir.attachment.manage','dfir.attachment.prepared','dfir_storage_object',${input.storageID}::uuid,1,
        ${input.rootID}::uuid,${nextID()}::uuid,'attachment'::public.dfir_entity_kind,${input.attachmentID}::uuid,
        'Attachment upload prepared','{}'::jsonb,'{}'::jsonb,'{}'::jsonb,
        ${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,'shared-dfir-runtime','totp')`;
    }
    await tx`SELECT app.append_shared_dfir_activities_v1(${receipt.command_id}::uuid,${[nextID(), nextID()]}::uuid[])`;
    const snapshot = {
      schemaVersion: 1,
      tenantId: fixture.tenant,
      rootKind: input.rootKind,
      rootId: input.rootID,
      operation: "dfir.attachment.prepare",
      resourceKind: "storage_object",
      resourceId: input.storageID,
      secondaryResourceId: input.attachmentID,
      resultVersion: 1,
      projection: {
        storageId: input.storageID,
        tenantId: fixture.tenant,
        createdBy: input.userID,
        createdAt: storage.created_at.toISOString(),
        uploadExpiresAt: storage.upload_expires_at.toISOString(),
        storageVersion: 1,
        storageState: "pending_upload",
        attachment: {
          id: input.attachmentID,
          tenantId: fixture.tenant,
          subject: { kind: input.kind, id: input.subjectID },
          storageObjectId: input.storageID,
          originalFilename: "sensitive-original.txt",
          visibility: "private",
          uploadedBy: input.userID,
          uploadedAt: storage.created_at.toISOString(),
          scanState: "pending_upload",
        },
      },
    };
    await tx`SELECT app.store_dfir_mutation_command_result_v1(${receipt.command_id}::uuid,${tx.json(snapshot)}::jsonb)`;
    receipt.result_snapshot = snapshot;
    return receipt;
  });
}
async function sharedAttachments(): Promise<void> {
  await primary`UPDATE public.tenant_role_permissions SET scope='tenant' WHERE role_id=${fixture.scopedRole}::uuid`;
  for (const kind of ["ioc", "asset"] as const) {
    const subjectID = await seedResource(kind);
    await changeLink({
      kind,
      resourceID: subjectID,
      rootKind: "case",
      rootID: fixture.otherCase,
      eventID: nextID(),
      version: 1,
      linked: true,
      key: `upload-case:${kind}`,
    });
    await changeLink({
      kind,
      resourceID: subjectID,
      rootKind: "alert",
      rootID: fixture.alert,
      eventID: nextID(),
      version: 2,
      linked: true,
      key: `upload-alert:${kind}`,
    });
    for (const rootKind of ["case", "alert"] as const) {
      const input: UploadInput = {
        kind,
        subjectID,
        rootKind,
        rootID: rootKind === "case" ? fixture.mainCase : fixture.alert,
        storageID: nextID(),
        attachmentID: nextID(),
        key: `upload:${kind}:${rootKind}`,
        userID: fixture.scopedUser,
        membershipID: fixture.scopedMembership,
      };
      const first = await prepareSharedUpload(input);
      assert.equal(first.replayed, false);
      const replay = await prepareSharedUpload(input);
      assert.equal(replay.replayed, true);
      assert.deepEqual(replay.result_snapshot, first.result_snapshot);
      const activities = await primary<
        { details: postgres.JSONValue }[]
      >`SELECT details FROM public.dfir_activities
        WHERE tenant_id=${fixture.tenant}::uuid AND resource_id=${input.attachmentID}::uuid
        UNION ALL SELECT details FROM public.ticket_activities WHERE tenant_id=${fixture.tenant}::uuid AND details->>'resourceId'=${input.attachmentID}`;
      assert.equal(activities.length, 3);
      assert(!JSON.stringify(activities).includes("sensitive-original"));
      await primary`UPDATE public.tenant_role_permissions SET scope='operator_team' WHERE role_id=${fixture.scopedRole}::uuid`;
      await expectSqlState(
        prepareSharedUpload(input),
        "42501",
        "shared attachment replay ignored lost authority on another root",
      );
      await expectSqlState(
        prepareSharedUpload({
          ...input,
          rootKind: "case",
          rootID: fixture.mainCase,
          storageID: nextID(),
          attachmentID: nextID(),
          key: input.key + ":denied",
        }),
        "42501",
        "new shared upload ignored hidden-root authority",
      );
      await primary`UPDATE public.tenant_role_permissions SET scope='tenant' WHERE role_id=${fixture.scopedRole}::uuid`;
    }
  }
}

async function seedIndependentAttachmentCopy(
  attachmentID: string,
): Promise<void> {
  await primary.begin(async (tx) => {
    await tx`SELECT set_config('app.tenant_id',${fixture.tenant},true),
      set_config('app.user_id',${fixture.adminUser},true)`;
    let [provenance] = await tx<{ id: string; source_alert_version: number }[]>`
      SELECT id::text,source_alert_version FROM public.alert_case_links
      WHERE tenant_id=${fixture.tenant}::uuid AND case_id=${fixture.otherCase}::uuid
        AND alert_id=${fixture.alert}::uuid`;
    if (!provenance) {
      [provenance] = await tx<{ id: string; source_alert_version: number }[]>`
        INSERT INTO public.alert_case_links(
          id,tenant_id,alert_id,case_id,relation,reason,linked_by_membership_id,
          linked_by_user_id,source_alert_version,linked_at
        ) SELECT ${nextID()}::uuid,${fixture.tenant}::uuid,alert.id,${fixture.otherCase}::uuid,
          'escalation','Independent attachment copy',${fixture.adminMembership}::uuid,
          ${fixture.adminUser}::uuid,alert.version,now()
        FROM public.alerts AS alert WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.alert}::uuid
        RETURNING id::text,source_alert_version`;
    }
    assert(provenance);
    await tx`INSERT INTO public.dfir_attachment_case_links(
      id,tenant_id,attachment_id,case_id,source_alert_id,source_alert_version,
      escalation_link_id,created_by_membership_id,created_at
    ) VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${attachmentID}::uuid,
      ${fixture.otherCase}::uuid,${fixture.alert}::uuid,${provenance.source_alert_version},
      ${provenance.id}::uuid,${fixture.adminMembership}::uuid,now())`;
  });
}

async function attachmentRelationshipReferences(): Promise<void> {
  const missingRejections: string[] = [];
  for (const kind of ["ioc", "asset"] as const) {
    for (const rootKind of ["case", "alert"] as const) {
      for (const attachmentSide of ["source", "target"] as const) {
        const key = `attachment-reference:${kind}:${rootKind}:${attachmentSide}`;
        const resourceID = await seedResource(kind);
        for (const [linkedKind, linkedID, version] of [
          ["case", fixture.otherCase, 1],
          ["alert", fixture.alert, 2],
        ] as const) {
          await changeLink({
            kind,
            resourceID,
            rootKind: linkedKind,
            rootID: linkedID,
            eventID: nextID(),
            version,
            linked: true,
            key: `${key}:link:${linkedKind}`,
          });
        }
        const rootID = rootKind === "case" ? fixture.otherCase : fixture.alert;
        const attachmentID = nextID();
        await prepareSharedUpload({
          kind,
          subjectID: resourceID,
          rootKind,
          rootID,
          storageID: nextID(),
          attachmentID,
          key: `${key}:upload`,
          userID: fixture.adminUser,
          membershipID: fixture.adminMembership,
        });
        await primary`INSERT INTO public.dfir_relationships(
          id,tenant_id,case_id,alert_id,source_kind,source_id,
          target_kind,target_id,relationship_type,created_by_membership_id
        ) VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,
          ${rootKind === "case" ? rootID : null}::uuid,
          ${rootKind === "alert" ? rootID : null}::uuid,
          ${attachmentSide === "source" ? "attachment" : rootKind}::public.dfir_entity_kind,
          ${attachmentSide === "source" ? attachmentID : rootID}::uuid,
          ${attachmentSide === "target" ? "attachment" : rootKind}::public.dfir_entity_kind,
          ${attachmentSide === "target" ? attachmentID : rootID}::uuid,
          'related_to',${fixture.adminMembership}::uuid)`;
        try {
          await changeLink({
            kind,
            resourceID,
            rootKind,
            rootID,
            eventID: nextID(),
            version: 3,
            linked: false,
            key: `${key}:unlink`,
          });
          missingRejections.push(key);
        } catch (error) {
          assertSqlState(error, "23503");
          await assertResourceVersion(kind, resourceID, 3);
          if (rootKind === "case") {
            await seedIndependentAttachmentCopy(attachmentID);
            await changeLink({
              kind,
              resourceID,
              rootKind,
              rootID,
              eventID: nextID(),
              version: 3,
              linked: false,
              key: `${key}:copied-unlink`,
            });
            await assertResourceVersion(kind, resourceID, 4);
          }
        }
      }
    }
  }
  assert.deepEqual(
    missingRejections,
    [],
    "unlink must preserve root-local relationships through shared attachments",
  );
}

async function closedMutationBoundary(): Promise<void> {
  const resourceID = await seedResource("ioc");
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.adminUser,
      (tx) => tx`
    INSERT INTO public.dfir_ioc_links(id,tenant_id,ioc_id,case_id,created_by_membership_id)
    VALUES(${nextID()}::uuid,${fixture.tenant}::uuid,${resourceID}::uuid,${fixture.otherCase}::uuid,${fixture.adminMembership}::uuid)`,
    ),
    "42501",
    "raw API INSERT bypassed shared lifecycle audit/receipt",
  );
  await expectSqlState(
    asApi(primary, fixture.tenant, fixture.adminUser, async (tx) => {
      const input: LinkInput = {
        kind: "ioc",
        resourceID,
        rootKind: "case",
        rootID: fixture.otherCase,
        eventID: nextID(),
        version: 1,
        linked: true,
        key: "forged-empty",
      };
      const [receipt] = await tx<
        Reservation[]
      >`SELECT command_id::text FROM app.reserve_dfir_mutation_command_v1(
      ${nextID()}::uuid,'case',${input.rootID}::uuid,'dfir.ioc.link','ioc',${resourceID}::uuid,${input.eventID}::uuid,2,
      ${digest(input.key)},${digest(input.key + ":request")})`;
      assert(receipt);
      const snapshot = await resourceSnapshot(tx, input);
      await tx`SELECT app.store_dfir_mutation_command_result_v1(${receipt.command_id}::uuid,${tx.json(snapshot)}::jsonb)`;
    }),
    "23514",
    "a link receipt committed without immutable mutation history",
  );
}
async function escalationLink(createCase = false): Promise<void> {
  const mode = createCase ? "create-case" : "link-case";
  await primary`INSERT INTO public.tenant_role_permissions(tenant_id,role_id,permission_id,scope)
    SELECT ${fixture.tenant}::uuid,${fixture.scopedRole}::uuid,id,'tenant' FROM public.tenant_permissions
    WHERE key IN ('case.create','case.transfer','case.update','case.read','alert.read','alert.escalate','alert.comment.read','dfir.ioc.read','dfir.asset.read')
    ON CONFLICT DO NOTHING`;
  await primary`UPDATE public.tenant_role_permissions SET scope='tenant' WHERE role_id=${fixture.scopedRole}::uuid`;
  const ioc = await seedResource("ioc"),
    asset = await seedResource("asset");
  for (const [kind, resourceID] of [
    ["ioc", ioc],
    ["asset", asset],
  ] as const)
    await changeLink({
      kind,
      resourceID,
      rootKind: "alert",
      rootID: fixture.alert,
      eventID: nextID(),
      version: 1,
      linked: true,
      key: "escalation-source:" + mode + ":" + kind,
    });
  const [alert] = await primary<
    {
      workflow_id: string;
      workflow_version: number;
      state_key: string;
      version: string;
    }[]
  >`
    SELECT workflow_id::text,workflow_version,state_key,version::text FROM public.alerts WHERE id=${fixture.alert}::uuid`;
  const [targetCase] = await primary<
    {
      workflow_id: string;
      workflow_version: number;
      state_key: string;
      version: string;
    }[]
  >`
    SELECT workflow_id::text,workflow_version,state_key,version::text FROM public.cases WHERE id=${fixture.otherCase}::uuid`;
  assert(alert && targetCase);
  const targetID = createCase ? nextID() : fixture.otherCase;
  const target = createCase
    ? {
        workflowId: targetCase.workflow_id,
        workflowVersion: targetCase.workflow_version,
        stateKey: targetCase.state_key,
        resultVersion: 2,
        title: "Shared-resource escalation runtime",
        description: "Current authority and exact lifecycle provenance",
        summary: "",
        severity: "medium",
        priority: "medium",
        category: "general",
        tags: [],
        customFields: {},
        customerVisible: false,
        assignedTeamId: fixture.team,
        assigneeUserId: fixture.scopedUser,
      }
    : {
        workflowId: targetCase.workflow_id,
        workflowVersion: targetCase.workflow_version,
        stateKey: targetCase.state_key,
        expectedVersion: Number(targetCase.version),
        resultVersion: Number(targetCase.version) + 1,
      };
  const sources = [
    {
      alertId: fixture.alert,
      linkId: nextID(),
      linkedAt: new Date(Date.now() - 1000).toISOString(),
      expectedVersion: Number(alert.version),
      resultVersion: Number(alert.version) + 1,
      workflowId: alert.workflow_id,
      workflowVersion: alert.workflow_version,
      stateKey: alert.state_key,
      copyFields: ["assets", "iocs"],
      customFieldKeys: [],
      itemIds: { iocIds: [ioc], assetIds: [asset] },
      publicCommentIds: [],
    },
  ];
  const key = digest("escalation-" + mode),
    request = digest("escalation-" + mode + ":request");
  type EscalationReceipt = {
    result_case_id: string;
    result_case_version: number;
    result_metadata: postgres.JSONValue;
    replayed: boolean;
  };
  const commit = () =>
    asApi(primary, fixture.tenant, fixture.scopedUser, (tx) =>
      createCase
        ? tx<EscalationReceipt[]>`
    SELECT result_case_id::text,result_case_version,result_metadata,replayed
    FROM app.commit_tenant_ticket_escalation_v4(${fixture.alert}::uuid,${targetID}::uuid,true,
      ${tx.json(target)}::jsonb,${tx.json(sources)}::jsonb,'escalation','Shared resource runtime',
      ${key},${request},ARRAY['activity','audit','sla','notification']::text[],${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,'shared-dfir-runtime','totp')`
        : tx<EscalationReceipt[]>`
    SELECT result_case_id::text,result_case_version,result_metadata,replayed
    FROM app.commit_tenant_ticket_link_v1(${fixture.alert}::uuid,${targetID}::uuid,false,
      ${tx.json(target)}::jsonb,${tx.json(sources)}::jsonb,'correlation','Shared resource runtime',
      ${key},${request},ARRAY['activity','audit','sla']::text[],${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,'shared-dfir-runtime','totp')`,
    );
  const first = (await commit())[0];
  assert(first);
  assert.equal(first.replayed, false);
  assert.equal(first.result_case_id, targetID);
  assert.equal(
    first.result_case_version,
    createCase ? 2 : Number(targetCase.version) + 1,
  );
  await assertResourceVersion("ioc", ioc, 3);
  await assertResourceVersion("asset", asset, 3);
  assert.deepEqual((await commit())[0], { ...first, replayed: true });
  await assertResourceVersion("ioc", ioc, 3);
  const lookup = () =>
    asApi(primary, fixture.tenant, fixture.scopedUser, (tx) =>
      createCase
        ? tx`
    SELECT * FROM app.lookup_tenant_ticket_escalation_replay_v3(${key},${request})`
        : tx`
    SELECT * FROM app.lookup_tenant_ticket_link_replay_v1(${key},${request})`,
    );
  assert.equal((await lookup()).length, 1);
  await primary`UPDATE public.tenant_role_permissions SET scope='operator_team'
    WHERE role_id=${fixture.scopedRole}::uuid AND permission_id IN (SELECT id FROM public.tenant_permissions WHERE key='dfir.ioc.manage')`;
  if (createCase) {
    await primary.begin(async (tx) => {
      await tx`SELECT set_config('app.tenant_id',${fixture.tenant},true),set_config('app.user_id',${fixture.scopedUser},true)`;
      const [access] = await tx<
        { path_allowed: boolean; other_root_allowed: boolean }[]
      >`
        SELECT app.private_current_dfir_scope_allows_v1('dfir.ioc.manage',${targetID}::uuid) AS path_allowed,
          app.private_current_alert_dfir_manage_scope_allows_v1('dfir.ioc.manage',${fixture.alert}::uuid) AS other_root_allowed`;
      assert.deepEqual(access, {
        path_allowed: true,
        other_root_allowed: false,
      });
    });
  }
  await expectSqlState(
    lookup(),
    "42501",
    "early escalation replay bypassed shared-resource authority",
  );
  await expectSqlState(
    commit(),
    "42501",
    "direct escalation commit replay bypassed shared-resource authority",
  );
  await primary`UPDATE public.tenant_role_permissions SET scope='tenant' WHERE role_id=${fixture.scopedRole}::uuid`;
}

try {
  const [version] = await primary<
    { major: string }[]
  >`SELECT current_setting('server_version_num') AS major`;
  assert.equal(version?.major.slice(0, 2), "18");
  await setupCore();
  await lifecycleMatrix();
  await concurrentCAS();
  await danglingReferences();
  await rootCardinality();
  await sharedAttachments();
  await closedMutationBoundary();
  await escalationLink();
  await escalationLink(true);
  await attachmentRelationshipReferences();
  await revokedReplay();
  process.stdout.write("Shared DFIR lifecycle PostgreSQL 18 runtime: PASS\n");
} finally {
  await Promise.all([primary.end(), contender.end()]);
}
