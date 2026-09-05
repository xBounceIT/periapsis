import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type PgError = Error & { code?: string };
type CreateReceipt = {
  result_relation_id: string;
  result_relation_type: "duplicate_of" | "correlation";
  previous_source_version: number;
  result_source_version: number;
  previous_target_version: number;
  result_target_version: number;
  linked_at: Date;
  replayed: boolean;
};
type RetractReceipt = {
  result_relation_id: string;
  previous_alert_version: number;
  result_alert_version: number;
  previous_related_alert_version: number;
  result_related_alert_version: number;
  retracted_at: Date;
  replayed: boolean;
};

const databaseUrl = process.env.PERIAPSIS_ALERT_RELATION_TEST_DATABASE_URL;
if (!databaseUrl?.trim()) {
  throw new Error(
    "PERIAPSIS_ALERT_RELATION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}
const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7500-2100-7000-8000-${(sequence + BigInt(offset)).toString(16).padStart(12, "0")}`;
const ids = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  admin: uuid(101),
  scopedActor: uuid(102),
  foreignActor: uuid(103),
  adminMembership: uuid(201),
  scopedMembership: uuid(202),
  foreignMembership: uuid(203),
  source: uuid(301),
  firstTarget: uuid(302),
  secondTarget: uuid(303),
  ownSource: uuid(304),
  ownTarget: uuid(305),
  disjointSource: uuid(306),
  disjointTarget: uuid(307),
  foreignAlert: uuid(308),
  scopedRole: uuid(401),
  scopedGrant: uuid(402),
  team: uuid(403),
  assignmentEpoch: uuid(404),
} as const;
const database = postgres(databaseUrl, { max: 5, onnotice: () => undefined });

const digest = (label: string): Buffer =>
  createHash("sha256").update(`alert-relation:${sequence}:${label}`).digest();
const errorCode = (error: unknown): string | undefined =>
  error instanceof Error ? (error as PgError).code : undefined;
async function rejects(
  operation: Promise<unknown>,
  code: string,
  message: string,
): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert(error instanceof Error, message);
    assert.equal(errorCode(error), code, error.message);
    return true;
  });
}
async function asApi<T>(
  tenantID: string,
  userID: string,
  action: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id',${tenantID},true),
             set_config('app.user_id',${userID},true),
             set_config('app.service_account_id','',true),
             set_config('app.traceparent','00-11111111111111111111111111111111-2222222222222222-01',true),
             set_config('app.tracestate','alert_relation=runtime',true)
    `;
    return { value: await action(transaction) };
  });
  return result.value;
}
const alertNumber = (offset: number): string =>
  `ALT-2026-${(Number((sequence + BigInt(offset)) % 900_000n) + 100_000)
    .toString()
    .padStart(6, "0")}`;

async function setup(): Promise<void> {
  await database.begin(async (transaction) => {
    const suffix = sequence.toString(36);
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${ids.tenant}::uuid,${`alert-relation-${suffix}`},'Alert relation runtime'),
        (${ids.foreignTenant}::uuid,${`alert-relation-foreign-${suffix}`},'Foreign Alert relation runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${ids.tenant}::uuid),(${ids.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${ids.admin}::uuid,${`relation-admin-${suffix}@example.invalid`},'Relation admin',true),
        (${ids.scopedActor}::uuid,${`relation-scoped-${suffix}@example.invalid`},'Scoped operator',true),
        (${ids.foreignActor}::uuid,${`relation-foreign-${suffix}@example.invalid`},'Foreign relation admin',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status) VALUES
        (${ids.adminMembership}::uuid,${ids.tenant}::uuid,${ids.admin}::uuid,'tenant_admin','active'),
        (${ids.scopedMembership}::uuid,${ids.tenant}::uuid,${ids.scopedActor}::uuid,'analyst','active'),
        (${ids.foreignMembership}::uuid,${ids.foreignTenant}::uuid,${ids.foreignActor}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(tenant_id,membership_id,user_id,display_name,email) VALUES
        (${ids.tenant}::uuid,${ids.adminMembership}::uuid,${ids.admin}::uuid,'Relation admin',${`relation-admin-${suffix}@example.invalid`}),
        (${ids.tenant}::uuid,${ids.scopedMembership}::uuid,${ids.scopedActor}::uuid,'Scoped operator',${`relation-scoped-${suffix}@example.invalid`}),
        (${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid,${ids.foreignActor}::uuid,'Foreign relation admin',${`relation-foreign-${suffix}@example.invalid`})
    `;
    await transaction`SELECT app.seed_tenant_authorization(${ids.tenant}::uuid,${ids.adminMembership}::uuid)`;
    await transaction`SELECT app.seed_tenant_authorization(${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid)`;
    await transaction`
      INSERT INTO public.tenant_roles(
        id,tenant_id,key,display_name,description,system_role,protected_role,
        principal_kind,created_by_membership_id
      ) VALUES (
        ${ids.scopedRole}::uuid,${ids.tenant}::uuid,'relation_scoped',
        'Scoped relation operator','Runtime same-scope proof',false,false,'human',
        ${ids.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions(tenant_id,role_id,permission_id,scope)
      SELECT ${ids.tenant}::uuid,${ids.scopedRole}::uuid,permission.id,'own'
      FROM public.tenant_permissions AS permission
      WHERE permission.key IN ('alert.read','alert.update')
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,granted_by_membership_id,grant_reason
      )
      SELECT ${ids.scopedGrant}::uuid,${ids.tenant}::uuid,${ids.scopedMembership}::uuid,
             ${ids.scopedRole}::uuid,source.id,${ids.adminMembership}::uuid,
             'Runtime scoped relation proof'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id=${ids.tenant}::uuid AND source.key='manual'
    `;
    await transaction`
      UPDATE public.tenant_authorization_states
      SET revision=revision+1,updated_at=transaction_timestamp()
      WHERE tenant_id=${ids.tenant}::uuid
    `;
    await transaction`
      INSERT INTO public.operator_teams(id,key,display_name,description,created_by_user_id)
      VALUES (${ids.team}::uuid,${`relation_${suffix}`},'Relation runtime team','Runtime assignment proof',${ids.admin}::uuid)
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs(
        id,tenant_id,operator_team_id,assigned_by_membership_id,assignment_reason
      ) VALUES (${ids.assignmentEpoch}::uuid,${ids.tenant}::uuid,${ids.team}::uuid,
                ${ids.adminMembership}::uuid,'Runtime Alert assignment')
    `;

    const alerts = [
      [ids.source, ids.admin, ids.adminMembership, null],
      [ids.firstTarget, ids.admin, ids.adminMembership, null],
      [ids.secondTarget, ids.admin, ids.adminMembership, null],
      [ids.ownSource, ids.admin, ids.adminMembership, ids.scopedActor],
      [ids.ownTarget, ids.admin, ids.adminMembership, ids.scopedActor],
      [ids.disjointSource, ids.scopedActor, ids.scopedMembership, null],
      [ids.disjointTarget, ids.admin, ids.adminMembership, ids.scopedActor],
    ] as const;
    await transaction`
      SELECT set_config('app.tenant_id',${ids.tenant},true),
             set_config('app.user_id',${ids.admin},true)
    `;
    await Promise.all(
      alerts.map(
        ([id, owner, membership, assignee], index) => transaction`
        INSERT INTO public.alerts(
          id,tenant_id,number,workflow_id,workflow_version,state_key,
          customer_visible,title,created_by,created_by_membership_id,
          assigned_team_id,assigned_team_epoch_id,assignee_user_id,version,updated_at
        )
        SELECT ${id}::uuid,${ids.tenant}::uuid,${alertNumber(index)},workflow.id,
               workflow.current_version,state.value->>'key',false,${`Runtime Alert ${index}`},
               ${owner}::uuid,${membership}::uuid,
               ${assignee === null ? null : ids.team}::uuid,
               ${assignee === null ? null : ids.assignmentEpoch}::uuid,
               ${assignee}::uuid,1,transaction_timestamp()
        FROM public.ticket_workflows AS workflow
        JOIN public.ticket_workflow_versions AS version
          ON version.tenant_id=workflow.tenant_id
         AND version.workflow_id=workflow.id
         AND version.aggregate_kind=workflow.aggregate_kind
         AND version.version=workflow.current_version
        CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
        WHERE workflow.tenant_id=${ids.tenant}::uuid AND workflow.key='default_alert'
          AND (state.value->>'initial')::boolean
      `,
      ),
    );
    await transaction`
      SELECT set_config('app.tenant_id',${ids.foreignTenant},true),
             set_config('app.user_id',${ids.foreignActor},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,customer_visible,
        title,created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${ids.foreignAlert}::uuid,${ids.foreignTenant}::uuid,${alertNumber(99)},workflow.id,
             workflow.current_version,state.value->>'key',false,'Foreign runtime Alert',
             ${ids.foreignActor}::uuid,${ids.foreignMembership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id=workflow.tenant_id
       AND version.workflow_id=workflow.id
       AND version.aggregate_kind=workflow.aggregate_kind
       AND version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
      WHERE workflow.tenant_id=${ids.foreignTenant}::uuid AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;
  });
}

async function create(
  tenant: string,
  actor: string,
  source: string,
  target: string,
  sourceVersion: number,
  targetVersion: number,
  type: "duplicate_of" | "correlation",
  label: string,
): Promise<CreateReceipt> {
  const [receipt] = await asApi(
    tenant,
    actor,
    (transaction) =>
      transaction<CreateReceipt[]>`
      SELECT result_relation_id::text,result_relation_type,previous_source_version,
             result_source_version,previous_target_version,result_target_version,
             linked_at,replayed
      FROM app.commit_tenant_alert_relation_create_v1(
        ${source}::uuid,${target}::uuid,${type},${sourceVersion},${targetVersion},
        ${`Explicit <${label}> evidence`},${digest(`${label}:key`)},${digest(`${label}:request`)},
        ${uuid(500 + label.length)}::uuid,${uuid(600 + label.length)}::uuid,
        '127.0.0.1'::inet,'alert-relation-runtime','totp'
      )
    `,
  );
  assert(receipt);
  return receipt;
}

async function invalidBoundary(
  reason: string,
  requestID: string,
  userAgent: string,
  label: string,
): Promise<unknown> {
  return asApi(
    ids.tenant,
    ids.admin,
    (transaction) => transaction`
    SELECT * FROM app.commit_tenant_alert_relation_create_v1(
      ${ids.source}::uuid,${ids.firstTarget}::uuid,'correlation',1,1,${reason},
      ${digest(`${label}:key`)},${digest(`${label}:request`)},${requestID}::uuid,
      ${uuid(710 + label.length)}::uuid,'127.0.0.1'::inet,${userAgent},'totp'
    )
  `,
  );
}

async function main(): Promise<void> {
  await setup();
  const [catalog] = await database<
    {
      relation_rls: boolean;
      relation_force: boolean;
      retraction_rls: boolean;
      retraction_force: boolean;
      relation_acl: string[];
      retraction_acl: string[];
    }[]
  >`
    SELECT
      (SELECT relrowsecurity FROM pg_class WHERE oid='public.alert_relations'::regclass) relation_rls,
      (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.alert_relations'::regclass) relation_force,
      (SELECT relrowsecurity FROM pg_class WHERE oid='public.alert_relation_retractions'::regclass) retraction_rls,
      (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.alert_relation_retractions'::regclass) retraction_force,
      ARRAY(SELECT privilege_type FROM information_schema.role_table_grants
            WHERE grantee='periapsis_api' AND table_name='alert_relations' ORDER BY privilege_type) relation_acl,
      ARRAY(SELECT privilege_type FROM information_schema.role_table_grants
            WHERE grantee='periapsis_api' AND table_name='alert_relation_retractions' ORDER BY privilege_type) retraction_acl
  `;
  assert.deepEqual(catalog, {
    relation_rls: true,
    relation_force: true,
    retraction_rls: true,
    retraction_force: true,
    relation_acl: ["SELECT"],
    retraction_acl: ["SELECT"],
  });

  await rejects(
    create(
      ids.tenant,
      ids.scopedActor,
      ids.ownSource,
      ids.ownTarget,
      1,
      1,
      "correlation",
      "own-assignee",
    ),
    "42501",
    "own scope authorized a mere assignee",
  );
  await database`
    INSERT INTO public.tenant_role_permissions(tenant_id,role_id,permission_id,scope)
    SELECT ${ids.tenant}::uuid,${ids.scopedRole}::uuid,permission.id,'assigned'
    FROM public.tenant_permissions permission WHERE permission.key IN ('alert.read','alert.update')
  `;
  await database`
    UPDATE public.tenant_authorization_states SET revision=revision+1,updated_at=transaction_timestamp()
    WHERE tenant_id=${ids.tenant}::uuid
  `;
  await rejects(
    create(
      ids.tenant,
      ids.scopedActor,
      ids.disjointSource,
      ids.disjointTarget,
      1,
      1,
      "correlation",
      "disjoint-scope",
    ),
    "42501",
    "different scopes were spliced",
  );
  await rejects(
    invalidBoundary(
      " Invalid reason ",
      uuid(701),
      "alert-relation-runtime",
      "reason",
    ),
    "22023",
    "non-canonical reason accepted",
  );
  await rejects(
    invalidBoundary(
      "é".repeat(1001),
      uuid(703),
      "alert-relation-runtime",
      "reason-bytes",
    ),
    "22023",
    "reason above the 2,000 UTF-8 byte boundary was accepted",
  );
  await rejects(
    invalidBoundary(
      "Bounded audit evidence",
      uuid(702),
      "u".repeat(513),
      "agent",
    ),
    "22023",
    "oversized user-agent accepted",
  );
  await rejects(
    invalidBoundary(
      "UUIDv7 audit evidence",
      "11111111-1111-4111-8111-111111111111",
      "alert-relation-runtime",
      "request",
    ),
    "22023",
    "non-UUIDv7 request ID accepted",
  );

  const candidates = [
    {
      target: ids.firstTarget,
      label: "race-first",
      type: "duplicate_of" as const,
      promise: create(
        ids.tenant,
        ids.admin,
        ids.source,
        ids.firstTarget,
        1,
        1,
        "duplicate_of",
        "race-first",
      ),
    },
    {
      target: ids.secondTarget,
      label: "race-second",
      type: "correlation" as const,
      promise: create(
        ids.tenant,
        ids.admin,
        ids.source,
        ids.secondTarget,
        1,
        1,
        "correlation",
        "race-second",
      ),
    },
  ];
  const settled = await Promise.allSettled(
    candidates.map((value) => value.promise),
  );
  assert.equal(
    settled.filter((value) => value.status === "fulfilled").length,
    1,
  );
  assert.equal(
    settled.filter((value) => value.status === "rejected").length,
    1,
  );
  const winnerIndex = settled.findIndex(
    (value) => value.status === "fulfilled",
  );
  const loserIndex = settled.findIndex((value) => value.status === "rejected");
  const winner = candidates[winnerIndex];
  const loser = candidates[loserIndex];
  const createdResult = settled[winnerIndex];
  const staleResult = settled[loserIndex];
  assert(
    winner &&
      loser &&
      createdResult?.status === "fulfilled" &&
      staleResult?.status === "rejected",
  );
  assert.equal(errorCode(staleResult.reason), "40001");
  const created = createdResult.value;
  assert.equal(created.replayed, false);
  assert.deepEqual(
    [
      created.previous_source_version,
      created.result_source_version,
      created.previous_target_version,
      created.result_target_version,
    ],
    [1, 2, 1, 2],
  );

  const replay = await create(
    ids.tenant,
    ids.admin,
    ids.source,
    winner.target,
    1,
    1,
    winner.type,
    winner.label,
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.result_relation_id, created.result_relation_id);
  assert.equal(replay.linked_at.toISOString(), created.linked_at.toISOString());

  const contradiction =
    winner.type === "correlation" ? "duplicate_of" : "correlation";
  await rejects(
    create(
      ids.tenant,
      ids.admin,
      winner.target,
      ids.source,
      2,
      2,
      contradiction,
      "reverse-conflict",
    ),
    "23505",
    "reverse contradictory pair accepted",
  );

  const retractKey = digest("retract:key");
  const retractDigest = digest("retract:request");
  const retract = async (): Promise<RetractReceipt> => {
    const [receipt] = await asApi(
      ids.tenant,
      ids.admin,
      (transaction) =>
        transaction<RetractReceipt[]>`
        SELECT result_relation_id::text,previous_alert_version,result_alert_version,
               previous_related_alert_version,result_related_alert_version,retracted_at,replayed
        FROM app.commit_tenant_alert_relation_retract_v1(
          ${ids.source}::uuid,${winner.target}::uuid,${created.result_relation_id}::uuid,2,2,
          'Evidence was disproven',${retractKey},${retractDigest},${uuid(801)}::uuid,
          ${uuid(802)}::uuid,'127.0.0.1'::inet,'alert-relation-runtime','totp'
        )
      `,
    );
    assert(receipt);
    return receipt;
  };
  const withdrawn = await retract();
  assert.deepEqual(
    [
      withdrawn.replayed,
      withdrawn.previous_alert_version,
      withdrawn.result_alert_version,
      withdrawn.previous_related_alert_version,
      withdrawn.result_related_alert_version,
    ],
    [false, 2, 3, 2, 3],
  );
  const withdrawReplay = await retract();
  assert.equal(withdrawReplay.replayed, true);
  assert.equal(
    withdrawReplay.retracted_at.toISOString(),
    withdrawn.retracted_at.toISOString(),
  );
  await rejects(
    create(
      ids.tenant,
      ids.admin,
      winner.target,
      ids.source,
      3,
      3,
      contradiction,
      "terminal-relink",
    ),
    "23505",
    "retraction made pair reusable",
  );
  await rejects(
    create(
      ids.tenant,
      ids.admin,
      ids.source,
      ids.source,
      3,
      3,
      "correlation",
      "self-link",
    ),
    "22023",
    "self relation accepted",
  );

  const [evidence] = await database<
    {
      relations: number;
      retractions: number;
      activities: number;
      audits: number;
      outbox: number;
      notifications: number;
      commands: number;
      source_version: number;
      winner_version: number;
      loser_version: number;
      original_reason: string;
      relation_result_version: number;
      retraction_prior_version: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_relations WHERE tenant_id=${ids.tenant}::uuid) relations,
      (SELECT count(*)::integer FROM public.alert_relation_retractions WHERE tenant_id=${ids.tenant}::uuid) retractions,
      (SELECT count(*)::integer FROM public.ticket_activities WHERE tenant_id=${ids.tenant}::uuid
       AND kind IN ('alert.relation_added','alert.relation_retracted')) activities,
      (SELECT count(*)::integer FROM public.audit_events WHERE tenant_id=${ids.tenant}::uuid
       AND action IN ('tenant.alert.relation_added','tenant.alert.relation_retracted')) audits,
      (SELECT count(*)::integer FROM public.outbox_events WHERE tenant_id=${ids.tenant}::uuid
       AND event_type IN ('alert.relation_added','alert.relation_retracted')) outbox,
      (SELECT count(*)::integer FROM public.outbox_events WHERE tenant_id=${ids.tenant}::uuid
       AND event_type LIKE 'notification.alert.relation_%') notifications,
      (SELECT count(*)::integer FROM public.ticket_commands WHERE tenant_id=${ids.tenant}::uuid
       AND operation IN ('alert.relation.create','alert.relation.retract')) commands,
      (SELECT version FROM public.alerts WHERE tenant_id=${ids.tenant}::uuid AND id=${ids.source}::uuid) source_version,
      (SELECT version FROM public.alerts WHERE tenant_id=${ids.tenant}::uuid AND id=${winner.target}::uuid) winner_version,
      (SELECT version FROM public.alerts WHERE tenant_id=${ids.tenant}::uuid AND id=${loser.target}::uuid) loser_version,
      (SELECT reason FROM public.alert_relations WHERE id=${created.result_relation_id}::uuid) original_reason,
      (SELECT result_source_version FROM public.alert_relations WHERE id=${created.result_relation_id}::uuid) relation_result_version,
      (SELECT prior_source_version FROM public.alert_relation_retractions WHERE relation_id=${created.result_relation_id}::uuid) retraction_prior_version
  `;
  assert.deepEqual(evidence, {
    relations: 1,
    retractions: 1,
    activities: 4,
    audits: 4,
    outbox: 4,
    notifications: 0,
    commands: 2,
    source_version: 3,
    winner_version: 3,
    loser_version: 1,
    original_reason: `Explicit <${winner.label}> evidence`,
    relation_result_version: 2,
    retraction_prior_version: 2,
  });
  await rejects(
    database`UPDATE public.alert_relations SET reason='rewritten' WHERE id=${created.result_relation_id}::uuid`,
    "55000",
    "relation history was mutable",
  );
  await rejects(
    database`DELETE FROM public.alert_relation_retractions WHERE relation_id=${created.result_relation_id}::uuid`,
    "55000",
    "retraction history was mutable",
  );

  const [foreignView] = await asApi(
    ids.foreignTenant,
    ids.foreignActor,
    (transaction) =>
      transaction<
        { count: number }[]
      >`SELECT count(*)::integer count FROM public.alert_relations`,
  );
  assert.deepEqual(foreignView, { count: 0 });
  await rejects(
    create(
      ids.foreignTenant,
      ids.foreignActor,
      ids.foreignAlert,
      ids.source,
      1,
      3,
      "correlation",
      "cross-tenant",
    ),
    "P0002",
    "cross-tenant relation accepted",
  );
}

try {
  await main();
  process.stdout.write(
    "Alert relation PostgreSQL runtime invariants verified.\n",
  );
} finally {
  await database.end({ timeout: 5 });
}
