import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type WorkflowPin = {
  id: string;
  key: string;
  version: number;
  state_key: string;
  effects: string[];
};
type LinkReceipt = {
  result_case_id: string;
  result_case_version: number;
  result_path_alert_version: number;
  result_metadata: {
    effects: string[];
    linkIds: string[];
    pathAlertVersion: number;
  };
  replayed: boolean;
};
type UnlinkReceipt = {
  result_link_id: string;
  previous_alert_version: number;
  result_alert_version: number;
  previous_case_version: number;
  result_case_version: number;
  retracted_at: Date;
  replayed: boolean;
};

const databaseUrl =
  process.env.PERIAPSIS_TICKET_LINK_LIFECYCLE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_LINK_LIFECYCLE_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7500-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  actor: uuid(101),
  foreignActor: uuid(102),
  membership: uuid(201),
  foreignMembership: uuid(202),
  alert: uuid(301),
  case: uuid(302),
  link: uuid(303),
  forbiddenRelink: uuid(304),
  storage: uuid(401),
  attachment: uuid(402),
  linkRequest: uuid(501),
  linkCorrelation: uuid(502),
  unlinkRequest: uuid(503),
  unlinkCorrelation: uuid(504),
  relinkRequest: uuid(505),
  relinkCorrelation: uuid(506),
} as const;

const database = postgres(databaseUrl, { max: 2, onnotice: () => undefined });
const linkKey = digest("link-key");
const linkRequestDigest = digest("link-request");
const unlinkKey = digest("unlink-key");
const unlinkRequestDigest = digest("unlink-request");
const lifecycleEffects = ["activity", "audit", "sla"] as const;

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-link-lifecycle:${sequence}:${label}`)
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
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await database.begin(async (transaction) => {
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
             set_config('app.tracestate','ticket_link=runtime',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function setup(): Promise<{
  alert: WorkflowPin;
  case: WorkflowPin;
}> {
  await database.begin(async (transaction) => {
    const suffix = sequence.toString(36);
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${fixture.tenant}::uuid,${`ticket-link-${suffix}`},
         'Ticket link lifecycle runtime'),
        (${fixture.foreignTenant}::uuid,${`ticket-link-foreign-${suffix}`},
         'Ticket link lifecycle foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.actor}::uuid,${`ticket-link-${suffix}@example.invalid`},
         'Ticket link operator',true),
        (${fixture.foreignActor}::uuid,
         ${`ticket-link-foreign-${suffix}@example.invalid`},
         'Foreign ticket link operator',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      ) VALUES
        (${fixture.membership}::uuid,${fixture.tenant}::uuid,
         ${fixture.actor}::uuid,'tenant_admin','active'),
        (${fixture.foreignMembership}::uuid,${fixture.foreignTenant}::uuid,
         ${fixture.foreignActor}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.membership}::uuid,
         ${fixture.actor}::uuid,'Ticket link operator',
         ${`ticket-link-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,
         ${fixture.foreignActor}::uuid,'Foreign ticket link operator',
         ${`ticket-link-foreign-${suffix}@example.invalid`})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.membership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.actor},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        customer_visible,title,created_by,created_by_membership_id,version,
        updated_at
      )
      SELECT ${fixture.alert}::uuid,${fixture.tenant}::uuid,
             ${`ALT-2026-${(sequence % 900_000n).toString().padStart(6, "0")}`},
             workflow.id,workflow.current_version,state.value->>'key',false,
             'Runtime Alert',${fixture.actor}::uuid,
             ${fixture.membership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id=workflow.tenant_id
       AND version.workflow_id=workflow.id
       AND version.aggregate_kind=workflow.aggregate_kind
       AND version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        customer_visible,title,created_by_membership_id,created_by_user_id,
        version,updated_at
      )
      SELECT ${fixture.case}::uuid,${fixture.tenant}::uuid,
             ${`CAS-2026-${(sequence % 900_000n).toString().padStart(6, "0")}`},
             workflow.id,workflow.current_version,state.value->>'key',false,
             'Runtime Case',${fixture.membership}::uuid,
             ${fixture.actor}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id=workflow.tenant_id
       AND version.workflow_id=workflow.id
       AND version.aggregate_kind=workflow.aggregate_kind
       AND version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_case'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.dfir_storage_objects(
        id,tenant_id,bucket,object_key,original_filename,classification,state,
        expected_size_bytes,upload_expires_at,content_sha256,size_bytes,
        detected_mime,verified_at,created_by_membership_id,created_at,updated_at
      ) VALUES (
        ${fixture.storage}::uuid,${fixture.tenant}::uuid,'periapsis-runtime',
        ${`${fixture.tenant}/ticket-link-runtime/evidence.bin`},'evidence.bin',
        'internal','available',4,transaction_timestamp()+interval '30 minutes',
        ${digest("attachment-content")},4,'application/octet-stream',
        transaction_timestamp(),${fixture.membership}::uuid,
        transaction_timestamp(),transaction_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.dfir_attachments(
        id,tenant_id,subject_kind,alert_id,storage_object_id,
        original_filename,visibility,scan_state,uploaded_by_membership_id,
        uploaded_at,version
      ) VALUES (
        ${fixture.attachment}::uuid,${fixture.tenant}::uuid,'alert',
        ${fixture.alert}::uuid,${fixture.storage}::uuid,'evidence.bin',
        'private','available',${fixture.membership}::uuid,
        transaction_timestamp(),1
      )
    `;
  });

  const workflows = await database<WorkflowPin[]>`
    SELECT workflow.id::text,workflow.key,
           workflow.current_version::integer AS version,
           state.value->>'key' AS state_key,
           ARRAY(
             SELECT effect.value
             FROM jsonb_array_elements(state.value->'actions') AS action(value)
             CROSS JOIN LATERAL jsonb_array_elements_text(
               action.value->'effects'
             ) AS effect(value)
             WHERE action.value->>'action'=CASE workflow.aggregate_kind
               WHEN 'alert' THEN 'escalate' ELSE 'link' END
             ORDER BY effect.value COLLATE "C"
           ) AS effects
    FROM public.ticket_workflows AS workflow
    JOIN public.ticket_workflow_versions AS version
      ON version.tenant_id=workflow.tenant_id
     AND version.workflow_id=workflow.id
     AND version.aggregate_kind=workflow.aggregate_kind
     AND version.version=workflow.current_version
    CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
    WHERE workflow.tenant_id=${fixture.tenant}::uuid
      AND workflow.key IN ('default_alert','default_case')
      AND (state.value->>'initial')::boolean
    ORDER BY workflow.key
  `;
  const alertWorkflow = workflows.find(
    (workflow) => workflow.key === "default_alert",
  );
  const caseWorkflow = workflows.find(
    (workflow) => workflow.key === "default_case",
  );
  assert(caseWorkflow && alertWorkflow, "default ticket workflows are missing");
  assert(alertWorkflow.effects.includes("notification"));
  assert(caseWorkflow.effects.includes("notification"));
  return { alert: alertWorkflow, case: caseWorkflow };
}

function target(workflow: WorkflowPin, expectedVersion: number) {
  return {
    workflowId: workflow.id,
    workflowVersion: workflow.version,
    stateKey: workflow.state_key,
    expectedVersion,
    resultVersion: expectedVersion + 1,
  };
}

function sources(
  workflow: WorkflowPin,
  linkID: string,
  expectedVersion: number,
) {
  return [
    {
      alertId: fixture.alert,
      linkId: linkID,
      // The production planner timestamps before the repository transaction.
      linkedAt: new Date(Date.now() - 1_000).toISOString(),
      expectedVersion,
      resultVersion: expectedVersion + 1,
      workflowId: workflow.id,
      workflowVersion: workflow.version,
      stateKey: workflow.state_key,
      copyFields: ["attachments"],
      customFieldKeys: [],
      itemIds: { attachmentIds: [fixture.attachment] },
      publicCommentIds: [],
    },
  ];
}

async function link(
  transaction: TransactionSql,
  workflows: { alert: WorkflowPin; case: WorkflowPin },
  input: {
    linkID: string;
    expectedAlertVersion: number;
    expectedCaseVersion: number;
    key: Buffer;
    requestDigest: Buffer;
    requestID: string;
    correlationID: string;
  },
): Promise<LinkReceipt> {
  const encodedSources = sources(
    workflows.alert,
    input.linkID,
    input.expectedAlertVersion,
  );
  const [shape] = await transaction<
    {
      alert_version: number;
      case_version: number;
      key_size: number;
      request_size: number;
      source_count: number;
      source_type: string;
    }[]
  >`
    SELECT uuid_extract_version(${fixture.alert}::uuid) AS alert_version,
           uuid_extract_version(${fixture.case}::uuid) AS case_version,
           octet_length(${input.key}::bytea) AS key_size,
           octet_length(${input.requestDigest}::bytea) AS request_size,
           jsonb_array_length(${transaction.json(encodedSources)}::jsonb)
             AS source_count,
           jsonb_typeof(${transaction.json(encodedSources)}::jsonb)
             AS source_type
  `;
  assert.deepEqual(shape, {
    alert_version: 7,
    case_version: 7,
    key_size: 32,
    request_size: 32,
    source_count: 1,
    source_type: "array",
  });
  const [receipt] = await transaction<LinkReceipt[]>`
    SELECT result_case_id::text,result_case_version,
           result_path_alert_version,result_metadata,replayed
    FROM app.commit_tenant_ticket_link_v1(
      ${fixture.alert}::uuid,${fixture.case}::uuid,false,
      ${transaction.json(
        target(workflows.case, input.expectedCaseVersion),
      )}::jsonb,
      ${transaction.json(encodedSources)}::jsonb,
      'correlation','Explicit runtime link',${input.key},
      ${input.requestDigest},${lifecycleEffects}::text[],
      ${input.requestID}::uuid,${input.correlationID}::uuid,
      '127.0.0.1'::inet,'ticket-link-lifecycle-runtime','totp'
    )
  `;
  assert(receipt, "link returned no receipt");
  return receipt;
}

async function unlink(
  transaction: TransactionSql,
  workflows: { alert: WorkflowPin; case: WorkflowPin },
): Promise<UnlinkReceipt> {
  const [receipt] = await transaction<UnlinkReceipt[]>`
    SELECT result_link_id::text,previous_alert_version,
           result_alert_version,previous_case_version,result_case_version,
           retracted_at,replayed
    FROM app.commit_tenant_alert_case_unlink_v1(
      ${fixture.alert}::uuid,${fixture.case}::uuid,${fixture.link}::uuid,
      ${workflows.alert.id}::uuid,${workflows.alert.version},
      ${workflows.alert.state_key},2,3,
      ${workflows.case.id}::uuid,${workflows.case.version},
      ${workflows.case.state_key},2,3,
      'False-positive correlation retired',${unlinkKey},
      ${unlinkRequestDigest},${lifecycleEffects}::text[],
      ${fixture.unlinkRequest}::uuid,${fixture.unlinkCorrelation}::uuid,
      '127.0.0.1'::inet,'ticket-link-lifecycle-runtime','totp'
    )
  `;
  assert(receipt, "unlink returned no receipt");
  return receipt;
}

async function main(): Promise<void> {
  const workflows = await setup();
  const linked = await asApi(fixture.tenant, fixture.actor, (transaction) =>
    link(transaction, workflows, {
      linkID: fixture.link,
      expectedAlertVersion: 1,
      expectedCaseVersion: 1,
      key: linkKey,
      requestDigest: linkRequestDigest,
      requestID: fixture.linkRequest,
      correlationID: fixture.linkCorrelation,
    }),
  );
  assert.equal(linked.replayed, false);
  assert.equal(linked.result_case_version, 2);
  assert.equal(linked.result_path_alert_version, 2);
  assert.deepEqual(linked.result_metadata.effects, lifecycleEffects);
  assert.deepEqual(linked.result_metadata.linkIds, [fixture.link]);

  const [linkEvidence] = await database<
    {
      command_count: number;
      activity_count: number;
      lifecycle_outbox_count: number;
      notification_count: number;
      copied_attachment_count: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.ticket_commands
       WHERE tenant_id=${fixture.tenant}::uuid AND operation='ticket.link'
         AND key_digest=${linkKey}) AS command_count,
      (SELECT count(*)::integer FROM public.ticket_activities
       WHERE tenant_id=${fixture.tenant}::uuid
         AND kind IN ('alert.linked','case.linked')
         AND (alert_id=${fixture.alert}::uuid OR case_id=${fixture.case}::uuid)
      ) AS activity_count,
      (SELECT count(*)::integer FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND event_type IN (
           'alert.linked','case.linked','sla.alert.linked','sla.case.linked'
         )
         AND aggregate_id IN (${fixture.alert}::uuid,${fixture.case}::uuid)
      ) AS lifecycle_outbox_count,
      (SELECT count(*)::integer FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND event_type IN (
           'notification.alert.linked','notification.case.linked'
         )
      ) AS notification_count,
      (SELECT count(*)::integer FROM public.dfir_attachment_case_links
       WHERE tenant_id=${fixture.tenant}::uuid
         AND attachment_id=${fixture.attachment}::uuid
         AND case_id=${fixture.case}::uuid
         AND escalation_link_id=${fixture.link}::uuid
      ) AS copied_attachment_count
  `;
  assert.deepEqual(linkEvidence, {
    command_count: 1,
    activity_count: 2,
    lifecycle_outbox_count: 4,
    notification_count: 0,
    copied_attachment_count: 1,
  });

  const unlinked = await asApi(fixture.tenant, fixture.actor, (transaction) =>
    unlink(transaction, workflows),
  );
  assert.equal(unlinked.replayed, false);
  assert.equal(unlinked.result_link_id, fixture.link);
  assert.equal(unlinked.previous_alert_version, 2);
  assert.equal(unlinked.result_alert_version, 3);
  assert.equal(unlinked.previous_case_version, 2);
  assert.equal(unlinked.result_case_version, 3);

  const replayedUnlink = await asApi(
    fixture.tenant,
    fixture.actor,
    (transaction) => unlink(transaction, workflows),
  );
  assert.equal(replayedUnlink.replayed, true);
  assert.equal(
    replayedUnlink.retracted_at.toISOString(),
    unlinked.retracted_at.toISOString(),
  );

  const [historicalReplay] = await asApi(
    fixture.tenant,
    fixture.actor,
    (transaction) => transaction<LinkReceipt[]>`
      SELECT result_case_id::text,
             result_case_version,result_path_alert_version,result_metadata,
             true AS replayed
      FROM app.lookup_tenant_ticket_link_replay_v1(
        ${linkKey},${linkRequestDigest}
      )
    `,
  );
  assert(historicalReplay, "historical link replay disappeared after unlink");
  assert.equal(historicalReplay.result_case_version, 2);
  assert.equal(historicalReplay.result_path_alert_version, 2);
  assert.deepEqual(historicalReplay.result_metadata.linkIds, [fixture.link]);

  const [projection] = await database<
    {
      historical_links: number;
      retractions: number;
      live_links: number;
      copied_attachments: number;
      alert_belongs_to_case: boolean;
      attachment_belongs_to_case: boolean;
      lifecycle_notifications: number;
      alert_version: number;
      case_version: number;
      unlink_receipts: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.alert_case_links AS link
       WHERE link.tenant_id=${fixture.tenant}::uuid
         AND link.alert_id=${fixture.alert}::uuid
         AND link.case_id=${fixture.case}::uuid) AS historical_links,
      (SELECT count(*)::integer FROM public.alert_case_link_retractions
       WHERE tenant_id=${fixture.tenant}::uuid
         AND link_id=${fixture.link}::uuid) AS retractions,
      (SELECT count(*)::integer FROM public.alert_case_links AS link
       WHERE link.tenant_id=${fixture.tenant}::uuid
         AND link.alert_id=${fixture.alert}::uuid
         AND link.case_id=${fixture.case}::uuid
         AND NOT EXISTS (
           SELECT 1 FROM public.alert_case_link_retractions AS retraction
           WHERE retraction.tenant_id=link.tenant_id
             AND retraction.link_id=link.id
         )) AS live_links,
      (SELECT count(*)::integer FROM public.dfir_attachment_case_links
       WHERE tenant_id=${fixture.tenant}::uuid
         AND attachment_id=${fixture.attachment}::uuid
         AND case_id=${fixture.case}::uuid) AS copied_attachments,
      app.private_dfir_resource_belongs_to_case_v1(
        ${fixture.tenant}::uuid,${fixture.case}::uuid,'alert',
        ${fixture.alert}::uuid
      ) AS alert_belongs_to_case,
      app.private_dfir_resource_belongs_to_case_v1(
        ${fixture.tenant}::uuid,${fixture.case}::uuid,'attachment',
        ${fixture.attachment}::uuid
      ) AS attachment_belongs_to_case,
      (SELECT count(*)::integer FROM public.outbox_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND event_type IN (
           'notification.alert.linked','notification.case.linked',
           'notification.alert.unlinked','notification.case.unlinked'
         )) AS lifecycle_notifications,
      (SELECT version FROM public.alerts
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${fixture.alert}::uuid) AS alert_version,
      (SELECT version FROM public.cases
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${fixture.case}::uuid) AS case_version,
      (SELECT count(*)::integer FROM public.ticket_commands
       WHERE tenant_id=${fixture.tenant}::uuid AND operation='ticket.unlink'
         AND key_digest=${unlinkKey}) AS unlink_receipts
  `;
  assert.deepEqual(projection, {
    historical_links: 1,
    retractions: 1,
    live_links: 0,
    copied_attachments: 1,
    alert_belongs_to_case: false,
    attachment_belongs_to_case: true,
    lifecycle_notifications: 0,
    alert_version: 3,
    case_version: 3,
    unlink_receipts: 1,
  });

  const [foreignProjection] = await asApi(
    fixture.foreignTenant,
    fixture.foreignActor,
    (transaction) => transaction<{ visible: number }[]>`
      SELECT count(*)::integer AS visible
      FROM public.alert_case_link_retractions
      WHERE link_id=${fixture.link}::uuid
    `,
  );
  assert.equal(foreignProjection?.visible, 0);

  await expectSqlState(
    asApi(fixture.tenant, fixture.actor, (transaction) =>
      link(transaction, workflows, {
        linkID: fixture.forbiddenRelink,
        expectedAlertVersion: 3,
        expectedCaseVersion: 3,
        key: digest("terminal-relink-key"),
        requestDigest: digest("terminal-relink-request"),
        requestID: fixture.relinkRequest,
        correlationID: fixture.relinkCorrelation,
      }),
    ),
    "23505",
    "a retracted Alert/Case pair was linked again",
  );

  const [versionsAfterConflict] = await database<
    { alert_version: number; case_version: number; commands: number }[]
  >`
    SELECT
      (SELECT version FROM public.alerts
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${fixture.alert}::uuid) AS alert_version,
      (SELECT version FROM public.cases
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${fixture.case}::uuid) AS case_version,
      (SELECT count(*)::integer FROM public.ticket_commands
       WHERE tenant_id=${fixture.tenant}::uuid
         AND operation='ticket.link') AS commands
  `;
  assert.deepEqual(versionsAfterConflict, {
    alert_version: 3,
    case_version: 3,
    commands: 1,
  });

  await expectSqlState(
    asApi(
      fixture.tenant,
      fixture.actor,
      (transaction) => transaction`
      SELECT * FROM app.lookup_tenant_ticket_link_replay_v1(
        ${linkKey},${digest("payload-drift")}
      )
    `,
    ),
    "23505",
    "link replay accepted a different payload digest",
  );
  await expectSqlState(
    database`
      UPDATE public.alert_case_links SET reason='tampered'
      WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.link}::uuid
    `,
    "55000",
    "committed link provenance was mutable",
  );
  await expectSqlState(
    database`
      DELETE FROM public.alert_case_link_retractions
      WHERE tenant_id=${fixture.tenant}::uuid AND link_id=${fixture.link}::uuid
    `,
    "55000",
    "link retraction was mutable",
  );
}

await main().finally(async () => {
  await database.end({ timeout: 5 });
});
