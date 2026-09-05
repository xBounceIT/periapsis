import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type EntityKind =
  | "alert"
  | "asset"
  | "attachment"
  | "case"
  | "evidence"
  | "external"
  | "ioc"
  | "task";
type Reference =
  | { id: string; kind: Exclude<EntityKind, "external"> }
  | { externalId: string; externalType: string; kind: "external" };

type GenericReservation = {
  command_id: string;
  replayed: boolean;
  result_resource_id: string;
  result_secondary_resource_id: string | null;
  result_snapshot: postgres.JSONValue;
  result_version: string;
};

type AlertReservation = {
  command_id: string;
  replayed: boolean;
  result_resource_id: string;
  result_snapshot: postgres.JSONValue;
  result_version: string;
};

type Relationship = {
  createdAt: Date;
  createdBy: string;
  id: string;
  metadata: postgres.JSONValue;
  relationshipType: string;
  source: Reference;
  target: Reference;
};

type Retraction = {
  actorID: string;
  id: string;
  occurredAt: Date;
  reason: string;
};

const databaseUrl =
  process.env.PERIAPSIS_DFIR_GENERIC_RELATIONSHIP_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_DFIR_GENERIC_RELATIONSHIP_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
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
  foreignUser: uuid(103),
  adminMembership: uuid(201),
  scopedMembership: uuid(202),
  foreignMembership: uuid(203),
  scopedRole: uuid(301),
  scopedGrant: uuid(302),
  team: uuid(401),
  teamEpoch: uuid(402),
  scopedRoster: uuid(403),
  caseA: uuid(501),
  caseB: uuid(502),
  caseUnscoped: uuid(503),
  foreignCase: uuid(504),
  alertA: uuid(511),
  alertB: uuid(512),
  alertUnscoped: uuid(513),
  foreignAlert: uuid(514),
  sharedIOC: uuid(601),
  unlinkedIOC: uuid(602),
  archivedIOC: uuid(603),
  foreignIOC: uuid(604),
  sharedAsset: uuid(611),
  caseEvidence: uuid(701),
  alertEvidence: uuid(702),
  caseTask: uuid(711),
  alertTask: uuid(712),
  caseEvidenceStorage: uuid(721),
  alertEvidenceStorage: uuid(722),
  attachmentStorage: uuid(723),
  sharedAttachment: uuid(731),
} as const;

const primary = postgres(databaseUrl, { max: 6, onnotice: () => undefined });

let nextOffset = 1000;
const nextID = (): string => uuid(nextOffset++);

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`dfir-generic-relationship-runtime:${label}`)
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
  const result = await primary.begin(async (transaction) => {
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
             set_config('app.tracestate','generic_relationship=runtime',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

function referenceSnapshot(reference: Reference): postgres.JSONValue {
  if (reference.kind === "external") {
    return {
      externalId: reference.externalId,
      externalType: reference.externalType,
      kind: reference.kind,
    };
  }
  return { id: reference.id, kind: reference.kind };
}

function referenceDatabaseValues(reference: Reference): {
  externalID: string | null;
  externalType: string | null;
  id: string | null;
} {
  if (reference.kind === "external") {
    return {
      externalID: reference.externalId,
      externalType: reference.externalType,
      id: null,
    };
  }
  return { externalID: null, externalType: null, id: reference.id };
}

function genericSnapshot(
  rootID: string,
  operation: "dfir.relationship.create" | "dfir.relationship.retract",
  relationship: Relationship,
  retraction?: Retraction,
): postgres.JSONValue {
  const projection: Record<string, postgres.JSONValue> = {
    createdAt: relationship.createdAt.toISOString(),
    createdBy: relationship.createdBy,
    id: relationship.id,
    metadata: relationship.metadata,
    relationshipType: relationship.relationshipType,
    source: referenceSnapshot(relationship.source),
    target: referenceSnapshot(relationship.target),
    tenantId: fixture.tenant,
    version: retraction === undefined ? 1 : 2,
  };
  if (retraction !== undefined) {
    projection.retractions = [
      {
        actorId: retraction.actorID,
        id: retraction.id,
        occurredAt: retraction.occurredAt.toISOString(),
        reason: retraction.reason,
        relationshipId: relationship.id,
        sequence: 1,
        tenantId: fixture.tenant,
      },
    ];
  }
  const snapshot: Record<string, postgres.JSONValue> = {
    operation,
    projection,
    resourceId: relationship.id,
    resourceKind: "relationship",
    resultVersion: retraction === undefined ? 1 : 2,
    rootId: rootID,
    rootKind: "case",
    schemaVersion: 1,
    tenantId: fixture.tenant,
  };
  if (retraction !== undefined) {
    snapshot.secondaryResourceId = retraction.id;
  }
  return snapshot;
}

function alertSnapshot(
  rootID: string,
  relationship: Relationship,
  retraction?: Retraction,
): postgres.JSONValue {
  return {
    kind: "alert_relationship",
    relationship: {
      alertId: rootID,
      createdAt: relationship.createdAt.toISOString(),
      createdBy: relationship.createdBy,
      id: relationship.id,
      metadata: relationship.metadata,
      relationshipType: relationship.relationshipType,
      retractions:
        retraction === undefined
          ? []
          : [
              {
                actorId: retraction.actorID,
                id: retraction.id,
                occurredAt: retraction.occurredAt.toISOString(),
                reason: retraction.reason,
                relationshipId: relationship.id,
                sequence: 1,
                tenantId: fixture.tenant,
              },
            ],
      source: referenceSnapshot(relationship.source),
      target: referenceSnapshot(relationship.target),
      tenantId: fixture.tenant,
      version: retraction === undefined ? 1 : 2,
    },
  };
}

async function setup(): Promise<void> {
  const suffix = sequence.toString(36);
  const ticketSuffix = (Number(sequence % 800_000n) + 100_000)
    .toString()
    .padStart(6, "0");
  await primary.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${fixture.tenant}::uuid,${`generic-relationship-${suffix}`},
         'Generic relationship runtime'),
        (${fixture.foreignTenant}::uuid,
         ${`generic-relationship-foreign-${suffix}`},
         'Foreign generic relationship runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.adminUser}::uuid,
         ${`generic-relationship-admin-${suffix}@example.invalid`},
         'Relationship administrator',true),
        (${fixture.scopedUser}::uuid,
         ${`generic-relationship-scoped-${suffix}@example.invalid`},
         'Relationship scoped analyst',true),
        (${fixture.foreignUser}::uuid,
         ${`generic-relationship-foreign-${suffix}@example.invalid`},
         'Foreign relationship administrator',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      ) VALUES
        (${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid,'tenant_admin','active'),
        (${fixture.scopedMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.scopedUser}::uuid,'analyst','active'),
        (${fixture.foreignMembership}::uuid,${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.adminMembership}::uuid,
         ${fixture.adminUser}::uuid,'Relationship administrator',
         ${`generic-relationship-admin-${suffix}@example.invalid`}),
        (${fixture.tenant}::uuid,${fixture.scopedMembership}::uuid,
         ${fixture.scopedUser}::uuid,'Relationship scoped analyst',
         ${`generic-relationship-scoped-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,
         ${fixture.foreignUser}::uuid,'Foreign relationship administrator',
         ${`generic-relationship-foreign-${suffix}@example.invalid`})
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
        ${`generic_relationship_scope_${suffix}`},
        'Generic relationship scoped analyst',
        'Operator-team relationship authority runtime proof',false,false,
        'human',${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions(
        tenant_id,role_id,permission_id,scope
      )
      SELECT ${fixture.tenant}::uuid,${fixture.scopedRole}::uuid,
             permission.id,'operator_team'
      FROM public.tenant_permissions AS permission
      WHERE permission.key='dfir.relationship.manage'
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT ${fixture.scopedGrant}::uuid,${fixture.tenant}::uuid,
             ${fixture.scopedMembership}::uuid,${fixture.scopedRole}::uuid,
             source.id,${fixture.adminMembership}::uuid,
             'Generic relationship runtime scope'
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
      ) VALUES (
        ${fixture.team}::uuid,${`generic_relationship_${suffix}`},
        'Generic relationship team','Runtime path authority team',
        ${fixture.adminUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs(
        id,tenant_id,operator_team_id,assigned_by_membership_id,
        assignment_reason
      ) VALUES (
        ${fixture.teamEpoch}::uuid,${fixture.tenant}::uuid,
        ${fixture.team}::uuid,${fixture.adminMembership}::uuid,
        'Generic relationship runtime assignment'
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries(
        id,tenant_id,assignment_epoch_id,membership_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT ${fixture.scopedRoster}::uuid,${fixture.tenant}::uuid,
             ${fixture.teamEpoch}::uuid,${fixture.scopedMembership}::uuid,
             source.id,${fixture.adminMembership}::uuid,
             'Generic relationship runtime roster'
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id=${fixture.tenant}::uuid
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
      SELECT candidate.id::uuid,${fixture.tenant}::uuid,candidate.number,
             workflow.id,workflow.current_version,state.value->>'key',
             candidate.title,candidate.team_id::uuid,candidate.epoch_id::uuid,
             ${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,1,
             transaction_timestamp()
      FROM (VALUES
        (${fixture.caseA},${`CAS-3101-${ticketSuffix}`},
         'Generic relationship Case A',${fixture.team},${fixture.teamEpoch}),
        (${fixture.caseB},${`CAS-3102-${ticketSuffix}`},
         'Generic relationship Case B',${fixture.team},${fixture.teamEpoch}),
        (${fixture.caseUnscoped},${`CAS-3103-${ticketSuffix}`},
         'Unscoped generic relationship Case',NULL,NULL)
      ) AS candidate(id,number,title,team_id,epoch_id)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id=${fixture.tenant}::uuid
       AND workflow.key='default_case'
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        assigned_team_id,assigned_team_epoch_id,created_by,
        created_by_membership_id,version,updated_at
      )
      SELECT candidate.id::uuid,${fixture.tenant}::uuid,candidate.number,
             workflow.id,workflow.current_version,state.value->>'key',
             candidate.title,candidate.team_id::uuid,candidate.epoch_id::uuid,
             ${fixture.adminUser}::uuid,${fixture.adminMembership}::uuid,1,
             transaction_timestamp()
      FROM (VALUES
        (${fixture.alertA},${`ALT-3101-${ticketSuffix}`},
         'Generic relationship Alert A',${fixture.team},${fixture.teamEpoch}),
        (${fixture.alertB},${`ALT-3102-${ticketSuffix}`},
         'Generic relationship Alert B',${fixture.team},${fixture.teamEpoch}),
        (${fixture.alertUnscoped},${`ALT-3103-${ticketSuffix}`},
         'Unscoped generic relationship Alert',NULL,NULL)
      ) AS candidate(id,number,title,team_id,epoch_id)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id=${fixture.tenant}::uuid
       AND workflow.key='default_alert'
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE (state.value->>'initial')::boolean
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
             ${`CAS-3191-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key',
             'Foreign generic relationship Case',
             ${fixture.foreignMembership}::uuid,${fixture.foreignUser}::uuid,
             1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_case'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${fixture.foreignAlert}::uuid,${fixture.foreignTenant}::uuid,
             ${`ALT-3191-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key',
             'Foreign generic relationship Alert',${fixture.foreignUser}::uuid,
             ${fixture.foreignMembership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;

    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    const observedAt = new Date("2026-09-04T10:00:00.000Z");
    await transaction`
      INSERT INTO public.dfir_iocs(
        id,tenant_id,type,value,normalized_value,description,source,confidence,
        tlp,first_seen,last_seen,malicious_state,tags,enrichment,
        created_by_membership_id,updated_by_membership_id,archived_at
      ) VALUES
        (${fixture.sharedIOC}::uuid,${fixture.tenant}::uuid,'domain',
         ${`shared-${suffix}.example.invalid`},
         ${`shared-${suffix}.example.invalid`},'', 'runtime',80,'amber',
         ${observedAt},${observedAt},'suspicious',ARRAY[]::text[],'{}'::jsonb,
         ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,NULL),
        (${fixture.unlinkedIOC}::uuid,${fixture.tenant}::uuid,'domain',
         ${`unlinked-${suffix}.example.invalid`},
         ${`unlinked-${suffix}.example.invalid`},'', 'runtime',20,'clear',
         ${observedAt},${observedAt},'unknown',ARRAY[]::text[],'{}'::jsonb,
         ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,NULL),
        (${fixture.archivedIOC}::uuid,${fixture.tenant}::uuid,'domain',
         ${`archived-${suffix}.example.invalid`},
         ${`archived-${suffix}.example.invalid`},'', 'runtime',20,'clear',
         ${observedAt},${observedAt},'unknown',ARRAY[]::text[],'{}'::jsonb,
         ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,
         NULL)
    `;
    await transaction`
      INSERT INTO public.dfir_assets(
        id,tenant_id,hostname,normalized_hostname,original_identifiers,
        asset_type,criticality,environment,external_id,tags,first_seen,
        last_seen,created_by_membership_id,updated_by_membership_id
      ) VALUES (
        ${fixture.sharedAsset}::uuid,${fixture.tenant}::uuid,
        ${`relationship-${suffix}`},${`relationship-${suffix}`},
        jsonb_build_object('hostname',${`relationship-${suffix}`}::text),
        'endpoint','medium','test',${`generic-relationship-${suffix}`},
        ARRAY[]::text[],${observedAt},${observedAt},
        ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.dfir_ioc_links(
        id,tenant_id,ioc_id,alert_id,case_id,created_by_membership_id
      )
      SELECT candidate.id::uuid,${fixture.tenant}::uuid,
             candidate.ioc_id::uuid,candidate.alert_id::uuid,
             candidate.case_id::uuid,${fixture.adminMembership}::uuid
      FROM (VALUES
        (${nextID()},${fixture.sharedIOC},NULL,${fixture.caseA}),
        (${nextID()},${fixture.sharedIOC},NULL,${fixture.caseB}),
        (${nextID()},${fixture.sharedIOC},${fixture.alertA},NULL),
        (${nextID()},${fixture.sharedIOC},${fixture.alertB},NULL),
        (${nextID()},${fixture.archivedIOC},NULL,${fixture.caseA})
      ) AS candidate(id,ioc_id,alert_id,case_id)
    `;
    await transaction`
      UPDATE public.dfir_iocs
      SET archived_at=transaction_timestamp(),updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.archivedIOC}::uuid
    `;
    await transaction`
      INSERT INTO public.dfir_asset_links(
        id,tenant_id,asset_id,alert_id,case_id,created_by_membership_id
      )
      SELECT candidate.id::uuid,${fixture.tenant}::uuid,
             ${fixture.sharedAsset}::uuid,candidate.alert_id::uuid,
             candidate.case_id::uuid,${fixture.adminMembership}::uuid
      FROM (VALUES
        (${nextID()},NULL,${fixture.caseA}),
        (${nextID()},NULL,${fixture.caseB}),
        (${nextID()},${fixture.alertA},NULL),
        (${nextID()},${fixture.alertB},NULL)
      ) AS candidate(id,alert_id,case_id)
    `;

    await transaction`
      SELECT set_config('app.tenant_id',${fixture.foreignTenant},true),
             set_config('app.user_id',${fixture.foreignUser},true)
    `;
    await transaction`
      INSERT INTO public.dfir_iocs(
        id,tenant_id,type,value,normalized_value,description,source,confidence,
        tlp,first_seen,last_seen,malicious_state,tags,enrichment,
        created_by_membership_id,updated_by_membership_id
      ) VALUES (
        ${fixture.foreignIOC}::uuid,${fixture.foreignTenant}::uuid,'domain',
        ${`foreign-${suffix}.example.invalid`},
        ${`foreign-${suffix}.example.invalid`},'', 'runtime',20,'clear',
        ${observedAt},${observedAt},'unknown',ARRAY[]::text[],'{}'::jsonb,
        ${fixture.foreignMembership}::uuid,${fixture.foreignMembership}::uuid
      )
    `;

    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    const storageIDs = [
      fixture.caseEvidenceStorage,
      fixture.alertEvidenceStorage,
      fixture.attachmentStorage,
    ];
    for (const [index, storageID] of storageIDs.entries()) {
      // oxlint-disable-next-line no-await-in-loop -- one setup transaction deliberately preserves fixture order.
      await transaction`
        INSERT INTO public.dfir_storage_objects(
          id,tenant_id,bucket,object_key,original_filename,classification,
          state,expected_size_bytes,upload_expires_at,content_sha256,
          size_bytes,detected_mime,verified_at,created_by_membership_id,
          created_at,updated_at
        ) VALUES (
          ${storageID}::uuid,${fixture.tenant}::uuid,'relationship-runtime',
          ${`${fixture.tenant}/${storageID}`},${`relationship-${index}.bin`},
          'internal','available',32,transaction_timestamp()+interval '30 minutes',
          ${digest(`storage-${index}`)},32,'application/octet-stream',
          transaction_timestamp(),${fixture.adminMembership}::uuid,
          transaction_timestamp(),transaction_timestamp()
        )
      `;
    }
    await transaction`
      INSERT INTO public.dfir_evidence(
        id,tenant_id,alert_id,case_id,storage_object_id,title,description,
        evidence_type,classification,content_sha256,size_bytes,detected_mime,
        collected_at,collected_by_membership_id,source,initial_scan_state,
        scan_state,anchor_hash,custody_head_hash,custody_count,version
      ) VALUES
        (${fixture.caseEvidence}::uuid,${fixture.tenant}::uuid,NULL,
         ${fixture.caseA}::uuid,${fixture.caseEvidenceStorage}::uuid,
         'Case relationship evidence','','memory','internal',
         ${digest("case-evidence")},32,'application/octet-stream',
         transaction_timestamp(),${fixture.adminMembership}::uuid,'runtime',
         'available','available',${digest("case-anchor")},
         ${digest("case-custody")},1,1),
        (${fixture.alertEvidence}::uuid,${fixture.tenant}::uuid,
         ${fixture.alertA}::uuid,NULL,${fixture.alertEvidenceStorage}::uuid,
         'Alert relationship evidence','','memory','internal',
         ${digest("alert-evidence")},32,'application/octet-stream',
         transaction_timestamp(),${fixture.adminMembership}::uuid,'runtime',
         'available','available',${digest("alert-anchor")},
         ${digest("alert-custody")},1,1)
    `;
    await transaction`
      INSERT INTO public.dfir_tasks(
        id,tenant_id,alert_id,case_id,title,description,status,priority,
        checklist,comment_ids,created_by_membership_id,
        updated_by_membership_id,version
      ) VALUES
        (${fixture.caseTask}::uuid,${fixture.tenant}::uuid,NULL,
         ${fixture.caseA}::uuid,'Case relationship task','','todo','medium',
         '[]'::jsonb,ARRAY[]::uuid[],${fixture.adminMembership}::uuid,
         ${fixture.adminMembership}::uuid,1),
        (${fixture.alertTask}::uuid,${fixture.tenant}::uuid,
         ${fixture.alertA}::uuid,NULL,'Alert relationship task','','todo',
         'medium','[]'::jsonb,ARRAY[]::uuid[],
         ${fixture.adminMembership}::uuid,${fixture.adminMembership}::uuid,1)
    `;
    await transaction`
      INSERT INTO public.dfir_attachments(
        id,tenant_id,subject_kind,ioc_id,storage_object_id,
        original_filename,visibility,scan_state,uploaded_by_membership_id,
        uploaded_at,version
      ) VALUES (
        ${fixture.sharedAttachment}::uuid,${fixture.tenant}::uuid,'ioc',
        ${fixture.sharedIOC}::uuid,${fixture.attachmentStorage}::uuid,
        'relationship-2.bin','private','available',
        ${fixture.adminMembership}::uuid,transaction_timestamp(),1
      )
    `;
  });
}

async function reserveCase(
  transaction: TransactionSql,
  input: {
    commandID: string;
    key: string;
    operation: "dfir.relationship.create" | "dfir.relationship.retract";
    relationshipID: string;
    request?: string;
    retractionID?: string;
    rootID: string;
  },
): Promise<GenericReservation> {
  const [reservation] = await transaction<GenericReservation[]>`
    SELECT command_id::text,result_resource_id::text,
           result_secondary_resource_id::text,result_version::text,
           result_snapshot,replayed
    FROM app.reserve_dfir_mutation_command_v1(
      ${input.commandID}::uuid,'case',${input.rootID}::uuid,
      ${input.operation},'relationship',${input.relationshipID}::uuid,
      ${input.retractionID ?? null}::uuid,
      ${input.operation === "dfir.relationship.create" ? 1 : 2},
      ${digest(`${input.key}:key`)},
      ${digest(`${input.request ?? input.key}:request`)}
    )
  `;
  assert(reservation, "Case relationship reservation returned no row");
  return reservation;
}

async function insertCaseRelationship(
  transaction: TransactionSql,
  rootID: string,
  relationship: Relationship,
): Promise<void> {
  const source = referenceDatabaseValues(relationship.source);
  const target = referenceDatabaseValues(relationship.target);
  const [inserted] = await transaction<{ id: string }[]>`
    INSERT INTO public.dfir_relationships(
      id,tenant_id,alert_id,case_id,source_kind,source_id,
      source_external_type,source_external_id,target_kind,target_id,
      target_external_type,target_external_id,relationship_type,metadata,
      created_by_membership_id,version,created_at
    ) VALUES (
      ${relationship.id}::uuid,${fixture.tenant}::uuid,NULL,${rootID}::uuid,
      ${relationship.source.kind}::public.dfir_entity_kind,${source.id}::uuid,
      ${source.externalType},${source.externalID},
      ${relationship.target.kind}::public.dfir_entity_kind,${target.id}::uuid,
      ${target.externalType},${target.externalID},
      ${relationship.relationshipType},${transaction.json(relationship.metadata)}::jsonb,
      ${relationship.createdBy}::uuid,1,${relationship.createdAt}::timestamptz
    ) RETURNING id::text
  `;
  assert.equal(inserted?.id, relationship.id);
}

async function createCaseRelationship(input: {
  actorMembership?: string;
  actorUser?: string;
  key: string;
  proveExactStore?: boolean;
  relationship: Relationship;
  rootID: string;
}): Promise<{ commandID: string; snapshot: postgres.JSONValue }> {
  const commandID = nextID();
  const snapshot = genericSnapshot(
    input.rootID,
    "dfir.relationship.create",
    input.relationship,
  );
  await asApi(
    fixture.tenant,
    input.actorUser ?? fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveCase(transaction, {
        commandID,
        key: input.key,
        operation: "dfir.relationship.create",
        relationshipID: input.relationship.id,
        rootID: input.rootID,
      });
      assert.equal(reservation.replayed, false);
      await insertCaseRelationship(transaction, input.rootID, {
        ...input.relationship,
        createdBy: input.actorMembership ?? input.relationship.createdBy,
      });
      if (input.proveExactStore === true) {
        const spliced = {
          operation: "dfir.relationship.create",
          projection: {
            createdAt: input.relationship.createdAt.toISOString(),
            createdBy: input.relationship.createdBy,
            id: input.relationship.id,
            metadata: input.relationship.metadata,
            relationshipType: "references",
            source: { id: input.rootID, kind: "case" },
            target: {
              externalId: "https://example.invalid/spliced",
              externalType: "url",
              kind: "external",
            },
            tenantId: fixture.tenant,
            version: 1,
          },
          resourceId: input.relationship.id,
          resourceKind: "relationship",
          resultVersion: 1,
          rootId: input.rootID,
          rootKind: "case",
          schemaVersion: 1,
          tenantId: fixture.tenant,
        } satisfies postgres.JSONValue;
        await expectSqlState(
          transaction.savepoint(
            (nested) => nested`
            SELECT app.store_dfir_mutation_command_result_v1(
              ${reservation.command_id}::uuid,
              ${nested.json(spliced)}::jsonb
            )
          `,
          ),
          "22023",
          "Case result store accepted a spliced relationship snapshot",
        );
      }
      const [stored] = await transaction<{ stored: boolean }[]>`
        SELECT app.store_dfir_mutation_command_result_v1(
          ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
        ) AS stored
      `;
      assert.equal(stored?.stored, true);
    },
  );
  return { commandID, snapshot };
}

async function retractCaseRelationship(input: {
  key: string;
  relationship: Relationship;
  retraction: Retraction;
  rootID: string;
}): Promise<{ commandID: string; snapshot: postgres.JSONValue }> {
  const commandID = nextID();
  const snapshot = genericSnapshot(
    input.rootID,
    "dfir.relationship.retract",
    input.relationship,
    input.retraction,
  );
  await asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
    const reservation = await reserveCase(transaction, {
      commandID,
      key: input.key,
      operation: "dfir.relationship.retract",
      relationshipID: input.relationship.id,
      retractionID: input.retraction.id,
      rootID: input.rootID,
    });
    assert.equal(reservation.replayed, false);
    const [retracted] = await transaction<
      { relationship_id: string; relationship_version: string }[]
    >`
      SELECT relationship_id::text,relationship_version::text
      FROM app.retract_case_dfir_relationship_v1(
        ${reservation.command_id}::uuid,${input.relationship.id}::uuid,
        ${input.rootID}::uuid,1,${input.retraction.id}::uuid,
        ${input.retraction.reason},${input.retraction.occurredAt}::timestamptz
      )
    `;
    assert.deepEqual(retracted, {
      relationship_id: input.relationship.id,
      relationship_version: "2",
    });
    const [stored] = await transaction<{ stored: boolean }[]>`
      SELECT app.store_dfir_mutation_command_result_v1(
        ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
      ) AS stored
    `;
    assert.equal(stored?.stored, true);
  });
  return { commandID, snapshot };
}

async function reserveAlert(
  transaction: TransactionSql,
  input: {
    commandID: string;
    key: string;
    operation:
      "dfir.alert.relationship.create" | "dfir.alert.relationship.retract";
    relationshipID: string;
    request?: string;
    rootID: string;
  },
): Promise<AlertReservation> {
  const [reservation] = await transaction<AlertReservation[]>`
    SELECT command_id::text,result_resource_id::text,result_version::text,
           result_snapshot,replayed
    FROM app.reserve_alert_investigation_command_v1(
      ${input.commandID}::uuid,${input.rootID}::uuid,${input.operation},
      ${input.relationshipID}::uuid,
      ${input.operation === "dfir.alert.relationship.create" ? 1 : 2},
      ${digest(`${input.key}:key`)},
      ${digest(`${input.request ?? input.key}:request`)}
    )
  `;
  assert(reservation, "Alert relationship reservation returned no row");
  return reservation;
}

async function insertAlertRelationship(
  transaction: TransactionSql,
  commandID: string,
  rootID: string,
  relationship: Relationship,
): Promise<void> {
  const source = referenceDatabaseValues(relationship.source);
  const target = referenceDatabaseValues(relationship.target);
  const [created] = await transaction<{ relationship_id: string }[]>`
    SELECT relationship_id::text
    FROM app.create_alert_dfir_relationship_v1(
      ${commandID}::uuid,${relationship.id}::uuid,${rootID}::uuid,
      ${relationship.source.kind}::public.dfir_entity_kind,${source.id}::uuid,
      ${source.externalType},${source.externalID},
      ${relationship.target.kind}::public.dfir_entity_kind,${target.id}::uuid,
      ${target.externalType},${target.externalID},
      ${relationship.relationshipType},
      ${transaction.json(relationship.metadata)}::jsonb,
      ${relationship.createdAt}::timestamptz
    )
  `;
  assert.equal(created?.relationship_id, relationship.id);
}

async function createAlertRelationship(input: {
  actorUser?: string;
  key: string;
  proveExactStore?: boolean;
  relationship: Relationship;
  rootID: string;
}): Promise<{ commandID: string; snapshot: postgres.JSONValue }> {
  const commandID = nextID();
  const snapshot = alertSnapshot(input.rootID, input.relationship);
  await asApi(
    fixture.tenant,
    input.actorUser ?? fixture.adminUser,
    async (transaction) => {
      const reservation = await reserveAlert(transaction, {
        commandID,
        key: input.key,
        operation: "dfir.alert.relationship.create",
        relationshipID: input.relationship.id,
        rootID: input.rootID,
      });
      assert.equal(reservation.replayed, false);
      await insertAlertRelationship(
        transaction,
        reservation.command_id,
        input.rootID,
        input.relationship,
      );
      if (input.proveExactStore === true) {
        const minimal = {
          kind: "alert_relationship",
          relationship: {
            alertId: input.rootID,
            id: input.relationship.id,
            tenantId: fixture.tenant,
            version: 1,
          },
        } satisfies postgres.JSONValue;
        await expectSqlState(
          transaction.savepoint(
            (nested) => nested`
            SELECT app.store_alert_investigation_command_result_v1(
              ${reservation.command_id}::uuid,
              ${nested.json(minimal)}::jsonb
            )
          `,
          ),
          "22023",
          "Alert result store accepted a minimal relationship snapshot",
        );
      }
      const [stored] = await transaction<{ stored: boolean }[]>`
        SELECT app.store_alert_investigation_command_result_v1(
          ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
        ) AS stored
      `;
      assert.equal(stored?.stored, true);
    },
  );
  return { commandID, snapshot };
}

async function retractAlertRelationship(input: {
  key: string;
  relationship: Relationship;
  retraction: Retraction;
  rootID: string;
}): Promise<{ commandID: string; snapshot: postgres.JSONValue }> {
  const commandID = nextID();
  const snapshot = alertSnapshot(
    input.rootID,
    input.relationship,
    input.retraction,
  );
  await asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
    const reservation = await reserveAlert(transaction, {
      commandID,
      key: input.key,
      operation: "dfir.alert.relationship.retract",
      relationshipID: input.relationship.id,
      rootID: input.rootID,
    });
    assert.equal(reservation.replayed, false);
    const [retracted] = await transaction<
      { relationship_id: string; relationship_version: string }[]
    >`
      SELECT relationship_id::text,relationship_version::text
      FROM app.retract_alert_dfir_relationship_v1(
        ${reservation.command_id}::uuid,${input.relationship.id}::uuid,
        ${input.rootID}::uuid,1,${input.retraction.id}::uuid,
        ${input.retraction.reason},${input.retraction.occurredAt}::timestamptz
      )
    `;
    assert.deepEqual(retracted, {
      relationship_id: input.relationship.id,
      relationship_version: "2",
    });
    const [stored] = await transaction<{ stored: boolean }[]>`
      SELECT app.store_alert_investigation_command_result_v1(
        ${reservation.command_id}::uuid,${transaction.json(snapshot)}::jsonb
      ) AS stored
    `;
    assert.equal(stored?.stored, true);
  });
  return { commandID, snapshot };
}

function makeRelationship(
  id: string,
  source: Reference,
  target: Reference,
  relationshipType: string,
  createdBy = fixture.adminMembership,
): Relationship {
  return {
    createdAt: new Date(Date.now() - 5_000),
    createdBy,
    id,
    metadata: { confidence: "high", runtime: "generic-relationship" },
    relationshipType,
    source,
    target,
  };
}

async function verifyCaseChildLifecycle(): Promise<void> {
  const value = makeRelationship(
    nextID(),
    { id: fixture.sharedIOC, kind: "ioc" },
    { id: fixture.sharedAsset, kind: "asset" },
    "observed_on",
  );
  const created = await createCaseRelationship({
    key: "case-child-create",
    proveExactStore: true,
    relationship: value,
    rootID: fixture.caseA,
  });

  const initialReplay = await asApi(
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-create",
        operation: "dfir.relationship.create",
        relationshipID: value.id,
        rootID: fixture.caseA,
      }),
  );
  assert.equal(initialReplay.replayed, true);
  assert.equal(initialReplay.command_id, created.commandID);
  assert.deepEqual(initialReplay.result_snapshot, created.snapshot);

  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-create",
        operation: "dfir.relationship.create",
        relationshipID: value.id,
        rootID: fixture.caseB,
      }),
    ),
    "23505",
    "Case create replay crossed its persisted path root",
  );

  const duplicate = makeRelationship(
    nextID(),
    value.source,
    value.target,
    value.relationshipType,
  );
  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
      const reservation = await reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-duplicate",
        operation: "dfir.relationship.create",
        relationshipID: duplicate.id,
        rootID: fixture.caseA,
      });
      await insertCaseRelationship(transaction, fixture.caseA, duplicate);
      return reservation;
    }),
    "23505",
    "Case root accepted a duplicate active relationship coordinate",
  );

  const sameCoordinate = makeRelationship(
    nextID(),
    value.source,
    value.target,
    value.relationshipType,
  );
  await createCaseRelationship({
    key: "case-child-other-root",
    relationship: sameCoordinate,
    rootID: fixture.caseB,
  });

  const retraction: Retraction = {
    actorID: fixture.adminMembership,
    id: nextID(),
    occurredAt: new Date(),
    reason: "Superseded child relationship",
  };
  const retracted = await retractCaseRelationship({
    key: "case-child-retract",
    relationship: value,
    retraction,
    rootID: fixture.caseA,
  });

  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-retract",
        operation: "dfir.relationship.retract",
        relationshipID: value.id,
        retractionID: retraction.id,
        rootID: fixture.caseB,
      }),
    ),
    "P0002",
    "Case retract replay returned a receipt outside its persisted path root",
  );

  const historicalCreateReplay = await asApi(
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-create",
        operation: "dfir.relationship.create",
        relationshipID: value.id,
        rootID: fixture.caseA,
      }),
  );
  assert.equal(historicalCreateReplay.replayed, true);
  assert.deepEqual(historicalCreateReplay.result_snapshot, created.snapshot);

  const retractionReplay = await asApi(
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-child-retract",
        operation: "dfir.relationship.retract",
        relationshipID: value.id,
        retractionID: retraction.id,
        rootID: fixture.caseA,
      }),
  );
  assert.equal(retractionReplay.replayed, true);
  assert.equal(retractionReplay.command_id, retracted.commandID);
  assert.deepEqual(retractionReplay.result_snapshot, retracted.snapshot);
}

async function verifyAlertChildLifecycle(): Promise<void> {
  const value = makeRelationship(
    nextID(),
    { id: fixture.sharedIOC, kind: "ioc" },
    { id: fixture.sharedAsset, kind: "asset" },
    "observed_on",
  );
  const created = await createAlertRelationship({
    key: "alert-child-create",
    proveExactStore: true,
    relationship: value,
    rootID: fixture.alertA,
  });

  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-child-create",
        operation: "dfir.alert.relationship.create",
        relationshipID: value.id,
        rootID: fixture.alertB,
      }),
    ),
    "23505",
    "Alert create replay crossed its persisted path root",
  );

  const duplicate = makeRelationship(
    nextID(),
    value.source,
    value.target,
    value.relationshipType,
  );
  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
      const reservation = await reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-child-duplicate",
        operation: "dfir.alert.relationship.create",
        relationshipID: duplicate.id,
        rootID: fixture.alertA,
      });
      await insertAlertRelationship(
        transaction,
        reservation.command_id,
        fixture.alertA,
        duplicate,
      );
    }),
    "23505",
    "Alert root accepted a duplicate active relationship coordinate",
  );

  const sameCoordinate = makeRelationship(
    nextID(),
    value.source,
    value.target,
    value.relationshipType,
  );
  await createAlertRelationship({
    key: "alert-child-other-root",
    relationship: sameCoordinate,
    rootID: fixture.alertB,
  });

  const retraction: Retraction = {
    actorID: fixture.adminMembership,
    id: nextID(),
    occurredAt: new Date(),
    reason: "Superseded Alert child relationship",
  };
  const retracted = await retractAlertRelationship({
    key: "alert-child-retract",
    relationship: value,
    retraction,
    rootID: fixture.alertA,
  });

  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-child-retract",
        operation: "dfir.alert.relationship.retract",
        relationshipID: value.id,
        rootID: fixture.alertB,
      }),
    ),
    "P0002",
    "Alert retract replay returned a receipt outside its persisted path root",
  );

  const historicalCreateReplay = await asApi(
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-child-create",
        operation: "dfir.alert.relationship.create",
        relationshipID: value.id,
        rootID: fixture.alertA,
      }),
  );
  assert.equal(historicalCreateReplay.replayed, true);
  assert.equal(historicalCreateReplay.command_id, created.commandID);
  assert.deepEqual(historicalCreateReplay.result_snapshot, created.snapshot);

  const retractionReplay = await asApi(
    fixture.tenant,
    fixture.adminUser,
    (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-child-retract",
        operation: "dfir.alert.relationship.retract",
        relationshipID: value.id,
        rootID: fixture.alertA,
      }),
  );
  assert.equal(retractionReplay.replayed, true);
  assert.equal(retractionReplay.command_id, retracted.commandID);
  assert.deepEqual(retractionReplay.result_snapshot, retracted.snapshot);
}

async function verifyEveryEndpointKind(): Promise<void> {
  const caseEvidenceTask = makeRelationship(
    nextID(),
    { id: fixture.caseEvidence, kind: "evidence" },
    { id: fixture.caseTask, kind: "task" },
    "requires_review",
  );
  await createCaseRelationship({
    key: "case-evidence-task",
    relationship: caseEvidenceTask,
    rootID: fixture.caseA,
  });

  const alertEvidenceTask = makeRelationship(
    nextID(),
    { id: fixture.alertEvidence, kind: "evidence" },
    { id: fixture.alertTask, kind: "task" },
    "requires_review",
  );
  await createAlertRelationship({
    key: "alert-evidence-task",
    relationship: alertEvidenceTask,
    rootID: fixture.alertA,
  });

  const caseAttachmentExternal = makeRelationship(
    nextID(),
    { id: fixture.sharedAttachment, kind: "attachment" },
    {
      externalId: "https://example.invalid/case-artifact",
      externalType: "url",
      kind: "external",
    },
    "references",
  );
  await createCaseRelationship({
    key: "case-attachment-external",
    relationship: caseAttachmentExternal,
    rootID: fixture.caseA,
  });

  const alertAttachmentExternal = makeRelationship(
    nextID(),
    { id: fixture.sharedAttachment, kind: "attachment" },
    {
      externalId: "https://example.invalid/alert-artifact",
      externalType: "url",
      kind: "external",
    },
    "references",
  );
  await createAlertRelationship({
    key: "alert-attachment-external",
    relationship: alertAttachmentExternal,
    rootID: fixture.alertA,
  });
}

async function expectCaseCreateDenied(
  label: string,
  source: Reference,
  target: Reference,
): Promise<void> {
  const value = makeRelationship(nextID(), source, target, "references");
  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
      await reserveCase(transaction, {
        commandID: nextID(),
        key: label,
        operation: "dfir.relationship.create",
        relationshipID: value.id,
        rootID: fixture.caseA,
      });
      await insertCaseRelationship(transaction, fixture.caseA, value);
    }),
    "42501",
    `${label} endpoint was accepted under a Case root`,
  );
}

async function expectAlertCreateDenied(
  label: string,
  source: Reference,
  target: Reference,
): Promise<void> {
  const value = makeRelationship(nextID(), source, target, "references");
  await expectSqlState(
    asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
      const reservation = await reserveAlert(transaction, {
        commandID: nextID(),
        key: label,
        operation: "dfir.alert.relationship.create",
        relationshipID: value.id,
        rootID: fixture.alertA,
      });
      await insertAlertRelationship(
        transaction,
        reservation.command_id,
        fixture.alertA,
        value,
      );
    }),
    "42501",
    `${label} endpoint was accepted under an Alert root`,
  );
}

async function verifyEndpointDenials(): Promise<void> {
  await expectCaseCreateDenied(
    "case-archived-ioc",
    { id: fixture.archivedIOC, kind: "ioc" },
    { id: fixture.sharedAsset, kind: "asset" },
  );
  await expectAlertCreateDenied(
    "alert-unlinked-ioc",
    { id: fixture.unlinkedIOC, kind: "ioc" },
    { id: fixture.sharedAsset, kind: "asset" },
  );
  await expectCaseCreateDenied(
    "case-cross-tenant-ioc",
    { id: fixture.foreignIOC, kind: "ioc" },
    { id: fixture.sharedAsset, kind: "asset" },
  );
  await expectCaseCreateDenied(
    "case-wrong-root-evidence",
    { id: fixture.caseEvidence, kind: "evidence" },
    { id: fixture.alertTask, kind: "task" },
  );
}

async function verifyDedicatedAlertPairConstraint(): Promise<void> {
  for (const relationshipType of ["duplicate_of", "correlation"] as const) {
    const value = makeRelationship(
      nextID(),
      { id: fixture.alertA, kind: "alert" },
      { id: fixture.alertB, kind: "alert" },
      relationshipType,
    );
    // oxlint-disable-next-line no-await-in-loop -- each expected rollback uses an isolated transaction.
    await expectSqlState(
      asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
        const reservation = await reserveAlert(transaction, {
          commandID: nextID(),
          key: `dedicated-${relationshipType}`,
          operation: "dfir.alert.relationship.create",
          relationshipID: value.id,
          rootID: fixture.alertA,
        });
        await insertAlertRelationship(
          transaction,
          reservation.command_id,
          fixture.alertA,
          value,
        );
      }),
      "23514",
      `${relationshipType} bypassed the dedicated Alert relation model`,
    );
  }
}

async function setRootTeam(
  kind: "alert" | "case",
  rootID: string,
  assigned: boolean,
): Promise<void> {
  if (kind === "case") {
    await primary`
      UPDATE public.cases
      SET assigned_team_id=${assigned ? fixture.team : null}::uuid,
          assigned_team_epoch_id=${assigned ? fixture.teamEpoch : null}::uuid
      WHERE tenant_id=${fixture.tenant}::uuid AND id=${rootID}::uuid
    `;
    return;
  }
  await primary`
    UPDATE public.alerts
    SET assigned_team_id=${assigned ? fixture.team : null}::uuid,
        assigned_team_epoch_id=${assigned ? fixture.teamEpoch : null}::uuid
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${rootID}::uuid
  `;
}

async function verifyReferencedRootRevocation(): Promise<void> {
  const caseValue = makeRelationship(
    nextID(),
    { id: fixture.caseB, kind: "case" },
    { id: fixture.alertB, kind: "alert" },
    "depends_on",
    fixture.scopedMembership,
  );
  const caseCreated = await createCaseRelationship({
    actorMembership: fixture.scopedMembership,
    actorUser: fixture.scopedUser,
    key: "case-referenced-authority",
    relationship: caseValue,
    rootID: fixture.caseA,
  });
  const caseReplay = await asApi(
    fixture.tenant,
    fixture.scopedUser,
    (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-referenced-authority",
        operation: "dfir.relationship.create",
        relationshipID: caseValue.id,
        rootID: fixture.caseA,
      }),
  );
  assert.equal(caseReplay.replayed, true);
  assert.deepEqual(caseReplay.result_snapshot, caseCreated.snapshot);

  await setRootTeam("case", fixture.caseB, false);
  await expectSqlState(
    asApi(fixture.tenant, fixture.scopedUser, (transaction) =>
      reserveCase(transaction, {
        commandID: nextID(),
        key: "case-referenced-authority",
        operation: "dfir.relationship.create",
        relationshipID: caseValue.id,
        rootID: fixture.caseA,
      }),
    ),
    "42501",
    "Case receipt replay ignored revoked referenced-Case authority",
  );
  await setRootTeam("case", fixture.caseB, true);

  const alertValue = makeRelationship(
    nextID(),
    { id: fixture.caseB, kind: "case" },
    { id: fixture.alertB, kind: "alert" },
    "depends_on",
    fixture.scopedMembership,
  );
  const alertCreated = await createAlertRelationship({
    actorUser: fixture.scopedUser,
    key: "alert-referenced-authority",
    relationship: alertValue,
    rootID: fixture.alertA,
  });
  const alertReplay = await asApi(
    fixture.tenant,
    fixture.scopedUser,
    (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-referenced-authority",
        operation: "dfir.alert.relationship.create",
        relationshipID: alertValue.id,
        rootID: fixture.alertA,
      }),
  );
  assert.equal(alertReplay.replayed, true);
  assert.deepEqual(alertReplay.result_snapshot, alertCreated.snapshot);

  await setRootTeam("alert", fixture.alertB, false);
  await expectSqlState(
    asApi(fixture.tenant, fixture.scopedUser, (transaction) =>
      reserveAlert(transaction, {
        commandID: nextID(),
        key: "alert-referenced-authority",
        operation: "dfir.alert.relationship.create",
        relationshipID: alertValue.id,
        rootID: fixture.alertA,
      }),
    ),
    "42501",
    "Alert receipt replay ignored revoked referenced-Alert authority",
  );
  await setRootTeam("alert", fixture.alertB, true);
}

async function verifyPersistedRoots(): Promise<void> {
  const rows = await primary<
    { alert_id: string | null; case_id: string | null; count: string }[]
  >`
    SELECT alert_id::text,case_id::text,count(*)::text
    FROM public.dfir_relationships
    WHERE tenant_id=${fixture.tenant}::uuid
    GROUP BY alert_id,case_id
  `;
  assert(rows.some((row) => row.case_id === fixture.caseA));
  assert(rows.some((row) => row.case_id === fixture.caseB));
  assert(rows.some((row) => row.alert_id === fixture.alertA));
  assert(rows.some((row) => row.alert_id === fixture.alertB));
  for (const row of rows) {
    assert.notEqual(row.alert_id === null, row.case_id === null);
    assert(Number(row.count) > 0);
  }
}

async function main(): Promise<void> {
  await setup();
  await verifyCaseChildLifecycle();
  await verifyAlertChildLifecycle();
  await verifyEveryEndpointKind();
  await verifyEndpointDenials();
  await verifyDedicatedAlertPairConstraint();
  await verifyReferencedRootRevocation();
  await verifyPersistedRoots();
  // oxlint-disable-next-line no-console -- bounded security harness evidence.
  console.log(
    "generic path-rooted DFIR relationship create/retract, root-scoped duplicates, exact replay, endpoint liveness, association, and current authority passed",
  );
}

try {
  await main();
} finally {
  await primary.end({ timeout: 5 });
}
