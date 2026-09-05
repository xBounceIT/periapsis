import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

type ScanClaim = {
  attempt: number;
  event_id: string;
  execute_attempt: boolean;
  lease_token: string;
  maximum_attempts: number;
  storage_object_id: string;
  storage_version: string;
  tenant_id: string;
};

type CleanupClaim = {
  cleanup_fence: string;
  cleanup_lease_expires_at: Date;
  storage_object_id: string;
  tenant_id: string;
};

const databaseUrl =
  process.env.PERIAPSIS_DFIR_STORAGE_SCAN_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_DFIR_STORAGE_SCAN_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4b30-2000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
let identifierOffset = 2_000;
function identifiers(count: 1): [string];
function identifiers(count: 2): [string, string];
function identifiers(count: 3): [string, string, string];
function identifiers(count: 4): [string, string, string, string];
function identifiers(count: 5): [string, string, string, string, string];
function identifiers(
  count: 6,
): [string, string, string, string, string, string];
function identifiers(count: number): string[] {
  return Array.from({ length: count }, () => uuid(identifierOffset++));
}

const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  user: uuid(101),
  foreignUser: uuid(102),
  membership: uuid(201),
  foreignMembership: uuid(202),
  case: uuid(301),
  alert: uuid(302),
  sequenceCase: uuid(303),
  sharedIOC: uuid(304),
  sharedIOCAlertLink: uuid(305),
  sharedIOCCaseLink: uuid(306),
  fanoutIOC: uuid(307),
  foreignCase: uuid(308),
} as const;

const primary = postgres(databaseUrl, { max: 8, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`dfir-storage-scan-runtime:${label}`)
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

async function asRole<T>(
  client: typeof primary,
  role: "periapsis_api" | "periapsis_worker" | "periapsis_notifier",
  operation: (transaction: TransactionSql) => PromiseLike<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function asApi<T>(
  client: typeof primary,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => PromiseLike<T>,
): Promise<T> {
  return asRole(client, "periapsis_api", async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${tenantID},true),
             set_config('app.user_id',${userID},true),
             set_config('app.service_account_id','',true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate','dfir_scan=runtime',true)
    `;
    return operation(transaction);
  });
}

async function asWorker<T>(
  client: typeof primary,
  operation: (transaction: TransactionSql) => PromiseLike<T>,
): Promise<T> {
  return asRole(client, "periapsis_worker", operation);
}

async function setupCore(): Promise<void> {
  const suffix = sequence.toString(36);
  const ticket = (Number(sequence % 800_000n) + 100_000)
    .toString()
    .padStart(6, "0");
  await primary.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${fixture.tenant}::uuid,${`dfir-scan-${suffix}`},'DFIR scan runtime'),
        (${fixture.foreignTenant}::uuid,${`dfir-scan-foreign-${suffix}`},'Foreign DFIR scan runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${fixture.user}::uuid,${`dfir-scan-${suffix}@example.invalid`},'DFIR scan operator',true),
        (${fixture.foreignUser}::uuid,${`dfir-scan-foreign-${suffix}@example.invalid`},'Foreign DFIR scan operator',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status) VALUES
        (${fixture.membership}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,'tenant_admin','active'),
        (${fixture.foreignMembership}::uuid,${fixture.foreignTenant}::uuid,${fixture.foreignUser}::uuid,'tenant_admin','active')
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.membership}::uuid,${fixture.user}::uuid,'DFIR scan operator',${`dfir-scan-${suffix}@example.invalid`}),
        (${fixture.foreignTenant}::uuid,${fixture.foreignMembership}::uuid,${fixture.foreignUser}::uuid,'Foreign DFIR scan operator',${`dfir-scan-foreign-${suffix}@example.invalid`})
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
             set_config('app.user_id',${fixture.user},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${fixture.alert}::uuid,${fixture.tenant}::uuid,
             ${`ALT-2099-${ticket}`},workflow.id,workflow.current_version,
             'new','Shared IOC alert',${fixture.user}::uuid,
             ${fixture.membership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_alert'
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT source.id::uuid,${fixture.tenant}::uuid,source.number,
             workflow.id,workflow.current_version,'new',source.title,
             ${fixture.membership}::uuid,${fixture.user}::uuid,1,
             transaction_timestamp()
      FROM (VALUES
        (${fixture.case},${`CAS-2099-${ticket}`},'Shared IOC case'),
        (${fixture.sequenceCase},${`CAS-2098-${ticket}`},'Sequence exhaustion case')
      ) AS source(id,number,title)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id=${fixture.tenant}::uuid
       AND workflow.key='default_case'
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
             ${`CAS-2097-${ticket}`},workflow.id,workflow.current_version,
             'new','Foreign DFIR scan case',${fixture.foreignMembership}::uuid,
             ${fixture.foreignUser}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.foreignTenant}::uuid
        AND workflow.key='default_case'
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    const observedAt = new Date(Date.now() - 10_000);
    await transaction`
      INSERT INTO public.dfir_iocs(
        id,tenant_id,type,value,normalized_value,description,source,
        confidence,tlp,first_seen,last_seen,malicious_state,tags,enrichment,
        created_by_membership_id,updated_by_membership_id,version
      ) VALUES
        (${fixture.sharedIOC}::uuid,${fixture.tenant}::uuid,'domain',
         'shared.example','shared.example','','runtime',0,'clear',
         ${observedAt},${observedAt},'unknown',ARRAY[]::text[],'{}'::jsonb,
         ${fixture.membership}::uuid,${fixture.membership}::uuid,1),
        (${fixture.fanoutIOC}::uuid,${fixture.tenant}::uuid,'domain',
         'fanout.example','fanout.example','','runtime',0,'clear',
         ${observedAt},${observedAt},'unknown',ARRAY[]::text[],'{}'::jsonb,
         ${fixture.membership}::uuid,${fixture.membership}::uuid,1)
    `;
    await transaction`
      INSERT INTO public.dfir_ioc_links(
        id,tenant_id,ioc_id,alert_id,case_id,created_by_membership_id
      ) VALUES
        (${fixture.sharedIOCAlertLink}::uuid,${fixture.tenant}::uuid,
         ${fixture.sharedIOC}::uuid,${fixture.alert}::uuid,NULL,
         ${fixture.membership}::uuid),
        (${fixture.sharedIOCCaseLink}::uuid,${fixture.tenant}::uuid,
         ${fixture.sharedIOC}::uuid,NULL,${fixture.case}::uuid,
         ${fixture.membership}::uuid)
    `;
  });
}

type PreparedUpload = {
  attachment: string;
  cause: string;
  correlation: string;
  event: string;
  storage: string;
  tenant: string;
};

async function insertPreparedUpload(input: {
  expiresAt: Date;
  foreign?: boolean;
  subjectID?: string;
  subjectKind?: "case" | "ioc";
}): Promise<PreparedUpload> {
  const [storage, attachment, cause, event, correlation] = identifiers(5);
  const tenant = input.foreign ? fixture.foreignTenant : fixture.tenant;
  const user = input.foreign ? fixture.foreignUser : fixture.user;
  const membership = input.foreign
    ? fixture.foreignMembership
    : fixture.membership;
  const subjectKind = input.subjectKind ?? "case";
  const subjectID = input.subjectID ?? fixture.case;
  const createdAt = new Date(
    Math.min(Date.now() - 5_000, input.expiresAt.getTime() - 30_000),
  );
  await primary.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${tenant},true),
             set_config('app.user_id',${user},true)
    `;
    await transaction`
      INSERT INTO public.dfir_storage_objects(
        id,tenant_id,bucket,object_key,original_filename,classification,state,
        expected_size_bytes,upload_expires_at,created_by_membership_id,
        version,created_at,updated_at
      ) VALUES (
        ${storage}::uuid,${tenant}::uuid,'periapsis-runtime',
        ${`${tenant}/${storage}`},'evidence.txt','internal','pending_upload',
        32,${input.expiresAt},${membership}::uuid,1,${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.dfir_attachments(
        id,tenant_id,subject_kind,case_id,ioc_id,storage_object_id,
        original_filename,visibility,scan_state,uploaded_by_membership_id,
        uploaded_at,version
      ) VALUES (
        ${attachment}::uuid,${tenant}::uuid,${subjectKind},
        ${subjectKind === "case" ? subjectID : null}::uuid,
        ${subjectKind === "ioc" ? subjectID : null}::uuid,
        ${storage}::uuid,'evidence.txt','private','pending_upload',
        ${membership}::uuid,${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
        schema_version,payload,deduplication_key,correlation_id,actor_kind,
        actor_id,producer,maximum_audience,occurred_at,available_at
      ) VALUES (
        ${cause}::uuid,${tenant}::uuid,'dfir_storage_object',${storage}::uuid,
        1,'dfir.attachment.prepared',1,'{}'::jsonb,
        ${`prepared:${cause}`},${correlation}::uuid,'human',${user}::uuid,
        'api','operator',${createdAt},${createdAt}
      )
    `;
  });
  await asApi(
    primary,
    tenant,
    user,
    (transaction) => transaction`
    SELECT app.enqueue_dfir_storage_scan_v1(
      ${event}::uuid,${storage}::uuid,'text/plain',${createdAt},
      ${correlation}::uuid,${cause}::uuid
    )
  `,
  );
  return { attachment, cause, correlation, event, storage, tenant };
}

async function claimScan(
  client: typeof primary,
  limit = 1,
): Promise<ScanClaim[]> {
  const [workerID] = identifiers(1);
  return asWorker(
    client,
    (transaction) => transaction<ScanClaim[]>`
    SELECT event_id::text,tenant_id::text,storage_object_id::text,
           lease_token::text,attempt,maximum_attempts,execute_attempt,
           storage_version::text
    FROM app.claim_dfir_storage_scan_v1(
      ${workerID}::uuid,${limit},300,transaction_timestamp()
    )
  `,
  );
}

async function advance(
  client: typeof primary,
  claim: ScanClaim,
  expectedVersion: number,
  nextState:
    "available" | "quarantined" | "scanning" | "uploaded" | "verifying",
  metadata: { detected?: string; digest?: Buffer; size?: number } = {},
  complete = false,
): Promise<{ storage_version: string }[]> {
  const [operation, request, audit, outbox] = identifiers(4);
  return asWorker(
    client,
    (transaction) => transaction<{ storage_version: string }[]>`
    SELECT storage_version::text
    FROM app.advance_dfir_storage_scan_job_v1(
      ${claim.event_id}::uuid,${claim.lease_token}::uuid,
      ${claim.storage_object_id}::uuid,${expectedVersion}::bigint,
      ${nextState}::public.dfir_scan_state,
      ${metadata.digest ?? null}::bytea,${metadata.size ?? null}::bigint,
      ${metadata.detected ?? null},transaction_timestamp(),
      ${operation}::uuid,${request}::uuid,${audit}::uuid,${outbox}::uuid,
      NULL,${complete},NULL,NULL
    )
  `,
  );
}

async function verifyCatalog(): Promise<void> {
  const [catalog] = await primary<
    {
      api_enqueue: boolean;
      api_worker_claim: boolean;
      old_v2: boolean;
      old_v3: boolean;
      private_activity: boolean;
      worker_cleanup_v1: boolean;
      worker_cleanup_v2: boolean;
      worker_scan: boolean;
    }[]
  >`
    SELECT
      has_function_privilege(
        'periapsis_api',
        'app.enqueue_dfir_storage_scan_v1(uuid,uuid,text,timestamp with time zone,uuid,uuid)',
        'EXECUTE'
      ) AS api_enqueue,
      has_function_privilege(
        'periapsis_api',
        'app.claim_dfir_storage_scan_v1(uuid,integer,integer,timestamp with time zone)',
        'EXECUTE'
      ) AS api_worker_claim,
      has_function_privilege(
        'periapsis_worker',
        'app.claim_dfir_storage_scan_v1(uuid,integer,integer,timestamp with time zone)',
        'EXECUTE'
      ) AS worker_scan,
      has_function_privilege(
        'periapsis_worker',
        'app.finalize_dfir_orphan_upload_cleanup_v1(uuid,bigint,timestamp with time zone,uuid,uuid,uuid,uuid)',
        'EXECUTE'
      ) AS worker_cleanup_v1,
      has_function_privilege(
        'periapsis_worker',
        'app.finalize_dfir_orphan_upload_cleanup_v2(uuid,bigint,timestamp with time zone,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
      ) AS worker_cleanup_v2,
      has_function_privilege(
        'periapsis_worker',
        'app.private_append_dfir_scan_ticket_activity_v1(uuid,public.ticket_aggregate_kind,uuid,uuid,uuid,public.dfir_scan_state,bigint,timestamp with time zone)',
        'EXECUTE'
      ) AS private_activity,
      has_function_privilege(
        'periapsis_worker',
        'app.advance_dfir_storage_object_as_worker_v2(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid)',
        'EXECUTE'
      ) AS old_v2,
      has_function_privilege(
        'periapsis_worker',
        'app.advance_dfir_storage_object_as_worker_v3(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid,uuid)',
        'EXECUTE'
      ) AS old_v3
  `;
  assert(catalog);
  assert.equal(catalog.api_enqueue, true);
  assert.equal(catalog.api_worker_claim, false);
  assert.equal(catalog.worker_scan, true);
  assert.equal(catalog.worker_cleanup_v1, true);
  assert.equal(catalog.worker_cleanup_v2, true);
  assert.equal(catalog.private_activity, false);
  assert.equal(catalog.old_v2, false);
  assert.equal(catalog.old_v3, false);
  await expectSqlState(
    asRole(
      primary,
      "periapsis_notifier",
      (transaction) => transaction`
      SELECT * FROM app.claim_dfir_storage_scan_v1(
        ${uuid(2_900)}::uuid,1,300,transaction_timestamp()
      )
    `,
    ),
    "42501",
    "notifier executed the worker-only scan claim",
  );
}

async function verifyTenantEnqueueBoundary(): Promise<void> {
  const foreign = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
    foreign: true,
    subjectID: fixture.foreignCase,
  });
  const [event, correlation] = identifiers(2);
  await expectSqlState(
    asApi(
      primary,
      fixture.tenant,
      fixture.user,
      (transaction) => transaction`
      SELECT app.enqueue_dfir_storage_scan_v1(
        ${event}::uuid,${foreign.storage}::uuid,'text/plain',
        transaction_timestamp(),${correlation}::uuid,${foreign.cause}::uuid
      )
    `,
    ),
    "55000",
    "same-ID worker queue boundary exposed a foreign tenant upload",
  );
  await primary`
    UPDATE public.outbox_events SET processed_at=transaction_timestamp()
    WHERE id=${foreign.event}::uuid
  `;
}

async function verifyClaimConcurrency(): Promise<void> {
  const first = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  const second = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  const [left, right] = await Promise.all([
    claimScan(primary),
    claimScan(contender),
  ]);
  assert.equal(left.length, 1);
  assert.equal(right.length, 1);
  assert.notEqual(left[0]?.event_id, right[0]?.event_id);
  assert.deepEqual(
    new Set([left[0]?.event_id, right[0]?.event_id]),
    new Set([first.event, second.event]),
  );
  await primary`
    UPDATE public.outbox_events
    SET processed_at=transaction_timestamp(),locked_at=NULL,locked_by=NULL,
        lease_token=NULL,lease_until=NULL
    WHERE id IN (${first.event}::uuid,${second.event}::uuid)
  `;
}

async function verifyWaitRefundsAttempt(): Promise<void> {
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  const [claim] = await claimScan(primary);
  assert(claim);
  assert.equal(claim.event_id, upload.event);
  await asWorker(
    primary,
    (transaction) => transaction`
    SELECT app.wait_dfir_storage_scan_job_v1(
      ${claim.event_id}::uuid,${claim.lease_token}::uuid,
      transaction_timestamp(),transaction_timestamp()+interval '2 seconds'
    )
  `,
  );
  const [stored] = await primary<
    {
      attempts: number;
      lease_token: string | null;
      processed_at: Date | null;
    }[]
  >`
    SELECT attempts,lease_token::text,processed_at
    FROM public.outbox_events WHERE id=${upload.event}::uuid
  `;
  assert(stored);
  assert.equal(stored.attempts, 0);
  assert.equal(stored.lease_token, null);
  assert.equal(stored.processed_at, null);
  await primary`
    UPDATE public.outbox_events SET processed_at=transaction_timestamp()
    WHERE id=${upload.event}::uuid
  `;
}

async function verifyFullTransitionAndFanout(): Promise<void> {
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
    subjectID: fixture.sharedIOC,
    subjectKind: "ioc",
  });
  const [claim] = await claimScan(primary);
  assert(claim);
  assert.equal(claim.event_id, upload.event);
  await advance(primary, claim, 1, "uploaded");
  await advance(primary, claim, 2, "verifying");
  const contentDigest = digest("verified-content");
  await advance(primary, claim, 3, "quarantined", {
    detected: "text/plain; charset=utf-8",
    digest: contentDigest,
    size: 32,
  });
  await advance(primary, claim, 4, "scanning", {
    detected: "text/plain; charset=utf-8",
    digest: contentDigest,
    size: 32,
  });
  await advance(
    primary,
    claim,
    5,
    "available",
    { detected: "text/plain; charset=utf-8", digest: contentDigest, size: 32 },
    true,
  );
  const [projection] = await primary<
    {
      activity_count: string;
      audit_count: string;
      outbox_versions: string[];
      state: string;
      version: string;
    }[]
  >`
    SELECT storage.state::text,storage.version::text,
      (SELECT count(*)::text FROM public.audit_events AS audit
       WHERE audit.tenant_id=storage.tenant_id
         AND audit.resource_id=storage.id
         AND audit.action='dfir.storage.state_changed') AS audit_count,
      (SELECT array_agg(effect.aggregate_version::text ORDER BY effect.aggregate_version)
       FROM public.outbox_events AS effect
       WHERE effect.tenant_id=storage.tenant_id
         AND effect.aggregate_id=storage.id
         AND effect.event_type='dfir.storage.state_changed') AS outbox_versions,
      (SELECT count(*)::text FROM public.ticket_activities AS activity
       WHERE activity.tenant_id=storage.tenant_id
         AND activity.kind='dfir.attachment.scan_state_changed'
         AND activity.details->>'attachmentId'=${upload.attachment}) AS activity_count
    FROM public.dfir_storage_objects AS storage
    WHERE storage.id=${upload.storage}::uuid
  `;
  assert(projection);
  assert.equal(projection.state, "available");
  assert.equal(projection.version, "6");
  assert.equal(projection.audit_count, "5");
  assert.deepEqual(projection.outbox_versions, ["2", "3", "4", "5", "6"]);
  assert.equal(projection.activity_count, "10");

  const [redaction] = await primary<{ leaked: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM public.audit_events AS audit
      WHERE audit.resource_id=${upload.storage}::uuid
        AND (audit.metadata::text LIKE '%evidence.txt%'
          OR audit.metadata::text LIKE '%periapsis-runtime%'
          OR audit.metadata::text LIKE ${`%${upload.storage}%`})
    ) OR EXISTS (
      SELECT 1 FROM public.ticket_activities AS activity
      WHERE activity.details->>'attachmentId'=${upload.attachment}
        AND activity.details::text LIKE '%evidence.txt%'
    ) AS leaked
  `;
  assert(redaction);
  assert.equal(redaction.leaked, false);
  const [staleToken] = identifiers(1);
  const [operation, request, audit, outbox] = identifiers(4);
  await expectSqlState(
    asWorker(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.advance_dfir_storage_scan_job_v1(
        ${upload.event}::uuid,${staleToken}::uuid,${upload.storage}::uuid,
        6,'scanning',${contentDigest},32,'text/plain; charset=utf-8',
        transaction_timestamp(),${operation}::uuid,
        ${request}::uuid,${audit}::uuid,
        ${outbox}::uuid,NULL,false,NULL,NULL
      )
    `,
    ),
    "40001",
    "completed scan job accepted a stale lease token",
  );
}

async function verifyConcurrentActivitySequence(): Promise<void> {
  const first = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  const second = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  const claims = await claimScan(primary, 2);
  assert.equal(claims.length, 2);
  const byID = new Map(claims.map((claim) => [claim.storage_object_id, claim]));
  await Promise.all([
    advance(primary, byID.get(first.storage)!, 1, "uploaded"),
    advance(contender, byID.get(second.storage)!, 1, "uploaded"),
  ]);
  const rows = await primary<{ sequence: number }[]>`
    SELECT sequence FROM public.ticket_activities
    WHERE tenant_id=${fixture.tenant}::uuid AND case_id=${fixture.case}::uuid
      AND kind='dfir.attachment.scan_state_changed'
      AND details->>'attachmentId' IN (${first.attachment},${second.attachment})
    ORDER BY sequence
  `;
  assert.equal(rows.length, 2);
  assert.notEqual(rows[0]?.sequence, rows[1]?.sequence);
  await primary`
    UPDATE public.outbox_events
    SET processed_at=transaction_timestamp(),locked_at=NULL,locked_by=NULL,
        lease_token=NULL,lease_until=NULL
    WHERE id IN (${first.event}::uuid,${second.event}::uuid)
  `;
}

async function verifyExpiredCleanup(): Promise<void> {
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() - 10 * 60_000),
  });
  const [scanClaim] = await claimScan(primary);
  assert(scanClaim);
  await asWorker(
    primary,
    (transaction) => transaction`
    SELECT app.complete_dfir_storage_scan_job_v1(
      ${scanClaim.event_id}::uuid,${scanClaim.lease_token}::uuid,
      transaction_timestamp(),'upload_expired',false
    )
  `,
  );
  const firstCleanup = await asWorker(
    primary,
    (transaction) => transaction<CleanupClaim[]>`
    SELECT tenant_id::text,storage_object_id::text,cleanup_fence::text,
           cleanup_lease_expires_at
    FROM app.claim_dfir_orphan_uploads_v1(
      1,300,transaction_timestamp()
    )
  `,
  );
  assert.equal(firstCleanup.length, 1);
  const first = firstCleanup[0]!;
  await primary`
    UPDATE public.dfir_storage_objects
    SET cleanup_claimed_at=transaction_timestamp()-interval '2 seconds',
        cleanup_lease_expires_at=transaction_timestamp()-interval '1 second'
    WHERE id=${upload.storage}::uuid
  `;
  await expectSqlState(
    asWorker(
      primary,
      (transaction) => transaction`
      SELECT app.retry_dfir_orphan_upload_cleanup_v1(
        ${upload.storage}::uuid,${first.cleanup_fence}::bigint,
        'delete_failed',transaction_timestamp(),
        transaction_timestamp()+interval '10 seconds'
      )
    `,
    ),
    "40001",
    "expired cleanup worker extended its stale lease",
  );
  const [reclaimed] = await asWorker(
    primary,
    (transaction) => transaction<CleanupClaim[]>`
    SELECT tenant_id::text,storage_object_id::text,cleanup_fence::text,
           cleanup_lease_expires_at
    FROM app.claim_dfir_orphan_uploads_v1(
      1,300,transaction_timestamp()
    )
  `,
  );
  assert(reclaimed);
  assert.equal(
    BigInt(reclaimed.cleanup_fence),
    BigInt(first.cleanup_fence) + 1n,
  );
  const duplicate = identifiers(1)[0];
  await expectSqlState(
    asWorker(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.finalize_dfir_orphan_upload_cleanup_v1(
        ${upload.storage}::uuid,${reclaimed.cleanup_fence}::bigint,
        transaction_timestamp(),${duplicate}::uuid,${duplicate}::uuid,
        ${identifiers(1)[0]}::uuid,${identifiers(1)[0]}::uuid
      )
    `,
    ),
    "22023",
    "rolling cleanup ABI accepted duplicate journal identifiers",
  );
  const [operation, audit, outbox, request, correlation] = identifiers(5);
  await asWorker(
    primary,
    (transaction) => transaction`
    SELECT * FROM app.finalize_dfir_orphan_upload_cleanup_v2(
      ${upload.storage}::uuid,${reclaimed.cleanup_fence}::bigint,
      transaction_timestamp(),${operation}::uuid,${audit}::uuid,
      ${outbox}::uuid,${request}::uuid,${correlation}::uuid
    )
  `,
  );
  const [projection] = await primary<
    {
      activity_count: string;
      aggregate_version: string;
      attachment_version: string;
      state: string;
      version: string;
    }[]
  >`
    SELECT storage.state::text,storage.version::text,
      attachment.version::text AS attachment_version,
      effect.aggregate_version::text AS aggregate_version,
      (SELECT count(*)::text FROM public.ticket_activities AS activity
       WHERE activity.tenant_id=storage.tenant_id
         AND activity.kind='dfir.attachment.scan_state_changed'
         AND activity.details->>'attachmentId'=${upload.attachment}
         AND activity.details->>'state'='deleted') AS activity_count
    FROM public.dfir_storage_objects AS storage
    JOIN public.dfir_attachments AS attachment
      ON attachment.tenant_id=storage.tenant_id
     AND attachment.storage_object_id=storage.id
    JOIN public.outbox_events AS effect
      ON effect.tenant_id=storage.tenant_id
     AND effect.aggregate_id=storage.id
     AND effect.event_type='dfir.storage.orphan_deleted'
    WHERE storage.id=${upload.storage}::uuid
  `;
  assert(projection);
  assert.deepEqual(projection, {
    activity_count: "1",
    aggregate_version: "2",
    attachment_version: "2",
    state: "deleted",
    version: "2",
  });
  const [replayAudit, replayOutbox, replayRequest, replayCorrelation] =
    identifiers(4);
  const [replay] = await asWorker(
    primary,
    (transaction) => transaction<
      { replayed: boolean; storage_version: string }[]
    >`
    SELECT storage_version::text,replayed
    FROM app.finalize_dfir_orphan_upload_cleanup_v1(
      ${upload.storage}::uuid,${reclaimed.cleanup_fence}::bigint,
      transaction_timestamp(),${replayAudit}::uuid,${replayOutbox}::uuid,
      ${replayRequest}::uuid,${replayCorrelation}::uuid
    )
  `,
  );
  assert.deepEqual(replay, { replayed: true, storage_version: "2" });
  const [retryReplay] = await asWorker(
    primary,
    (transaction) => transaction<{ replayed: boolean }[]>`
    SELECT app.retry_dfir_orphan_upload_cleanup_v1(
      ${upload.storage}::uuid,${reclaimed.cleanup_fence}::bigint,
      'response_lost',transaction_timestamp(),
      transaction_timestamp()+interval '10 seconds'
    ) AS replayed
  `,
  );
  assert.equal(retryReplay?.replayed, true);
  const [replayProjection] = await primary<
    {
      activities: string;
      audits: string;
      effects: string;
      lease: Date | null;
    }[]
  >`
    SELECT storage.cleanup_lease_expires_at AS lease,
      (SELECT count(*)::text FROM public.audit_events AS audit_event
       WHERE audit_event.tenant_id=storage.tenant_id
         AND audit_event.resource_id=storage.id
         AND audit_event.action='dfir.storage.orphan_deleted') AS audits,
      (SELECT count(*)::text FROM public.outbox_events AS effect
       WHERE effect.tenant_id=storage.tenant_id
         AND effect.aggregate_id=storage.id
         AND effect.event_type='dfir.storage.orphan_deleted') AS effects,
      (SELECT count(*)::text FROM public.ticket_activities AS activity
       WHERE activity.tenant_id=storage.tenant_id
         AND activity.kind='dfir.attachment.scan_state_changed'
         AND activity.details->>'attachmentId'=${upload.attachment}
         AND activity.details->>'state'='deleted') AS activities
    FROM public.dfir_storage_objects AS storage
    WHERE storage.id=${upload.storage}::uuid
  `;
  assert.deepEqual(replayProjection, {
    activities: "1",
    audits: "1",
    effects: "1",
    lease: null,
  });
}

async function verifySequenceExhaustionRollsBack(): Promise<void> {
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
    subjectID: fixture.sequenceCase,
  });
  await primary`
    INSERT INTO public.ticket_activities(
      id,tenant_id,case_id,sequence,kind,summary,
      actor_principal_kind,origin,details,occurred_at
    ) VALUES (
      ${identifiers(1)[0]}::uuid,${fixture.tenant}::uuid,
      ${fixture.sequenceCase}::uuid,2147483647,'runtime.sequence.maximum',
      'Runtime sequence boundary','system','system','{}'::jsonb,
      transaction_timestamp()
    )
  `;
  const [claim] = await claimScan(primary);
  assert(claim);
  await expectSqlState(
    advance(primary, claim, 1, "uploaded"),
    "54000",
    "scan transition wrapped a ticket activity sequence",
  );
  const [stored] = await primary<{ state: string; version: string }[]>`
    SELECT state::text,version::text FROM public.dfir_storage_objects
    WHERE id=${upload.storage}::uuid
  `;
  assert.deepEqual(stored, { state: "pending_upload", version: "1" });
  await primary`
    UPDATE public.outbox_events
    SET processed_at=transaction_timestamp(),locked_at=NULL,locked_by=NULL,
        lease_token=NULL,lease_until=NULL
    WHERE id=${upload.event}::uuid
  `;
}

async function verifyFanoutBound(): Promise<void> {
  const ticketSuffix = (Number(sequence % 700_000n) + 200_000)
    .toString()
    .padStart(6, "0");
  await primary.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT uuidv7(),${fixture.tenant}::uuid,
             'CAS-'||${ticketSuffix}||'-'||lpad(source.ordinal::text,3,'0'),
             workflow.id,workflow.current_version,'new',
             'Fanout root '||source.ordinal::text,${fixture.membership}::uuid,
             ${fixture.user}::uuid,1,transaction_timestamp()
      FROM generate_series(1,65) AS source(ordinal)
      CROSS JOIN public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_case'
    `;
    await transaction`
      INSERT INTO public.dfir_ioc_links(
        id,tenant_id,ioc_id,case_id,created_by_membership_id
      )
      SELECT uuidv7(),${fixture.tenant}::uuid,${fixture.fanoutIOC}::uuid,
             case_record.id,${fixture.membership}::uuid
      FROM public.cases AS case_record
      WHERE case_record.tenant_id=${fixture.tenant}::uuid
        AND case_record.title LIKE 'Fanout root %'
        AND case_record.title<>'Fanout root 65'
    `;
  });
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
    subjectID: fixture.fanoutIOC,
    subjectKind: "ioc",
  });
  const insertOverflowLink = (transaction: TransactionSql) => transaction`
    INSERT INTO public.dfir_ioc_links(
      id,tenant_id,ioc_id,case_id,created_by_membership_id
    )
    SELECT uuidv7(),${fixture.tenant}::uuid,${fixture.fanoutIOC}::uuid,
           case_record.id,${fixture.membership}::uuid
    FROM public.cases AS case_record
    WHERE case_record.tenant_id=${fixture.tenant}::uuid
      AND case_record.title='Fanout root 65'
  `;
  await expectSqlState(
    primary.begin(insertOverflowLink),
    "23514",
    "the association writer must reject the 65th root",
  );
  await primary.begin(async (transaction) => {
    // Deliberately corrupt this disposable admin fixture to test the worker's
    // independent bound. The production trigger stays enabled after commit.
    await transaction`
      ALTER TABLE public.dfir_ioc_links
      DISABLE TRIGGER dfir_ioc_links_shared_guard_v1
    `;
    await insertOverflowLink(transaction);
    await transaction`
      ALTER TABLE public.dfir_ioc_links
      ENABLE TRIGGER dfir_ioc_links_shared_guard_v1
    `;
  });
  const [oversized] = await primary<
    { count: number; trigger_enabled: boolean }[]
  >`
    SELECT count(*)::integer AS count,
           (SELECT trigger.tgenabled='O' FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid='public.dfir_ioc_links'::regclass
              AND trigger.tgname='dfir_ioc_links_shared_guard_v1') AS trigger_enabled
    FROM public.dfir_ioc_links
    WHERE tenant_id=${fixture.tenant}::uuid AND ioc_id=${fixture.fanoutIOC}::uuid
  `;
  assert.deepEqual(oversized, { count: 65, trigger_enabled: true });
  const [claim] = await claimScan(primary);
  assert(claim);
  await expectSqlState(
    advance(primary, claim, 1, "uploaded"),
    "55000",
    "scan transition accepted more than 64 active roots",
  );
  const [stored] = await primary<{ state: string; version: string }[]>`
    SELECT state::text,version::text FROM public.dfir_storage_objects
    WHERE id=${upload.storage}::uuid
  `;
  assert.deepEqual(stored, { state: "pending_upload", version: "1" });
  await primary`
    UPDATE public.outbox_events
    SET processed_at=transaction_timestamp(),locked_at=NULL,locked_by=NULL,
        lease_token=NULL,lease_until=NULL
    WHERE id=${upload.event}::uuid
  `;
}

async function insertEvidenceScanJob(version: string): Promise<{
  evidence: string;
  job: string;
  storage: string;
}> {
  const [storage, evidence, attachment, cause, job, correlation] =
    identifiers(6);
  const observedAt = new Date(Date.now() - 5_000);
  const contentDigest = digest(`evidence-${version}`);
  await primary.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.dfir_storage_objects(
        id,tenant_id,bucket,object_key,original_filename,classification,state,
        expected_size_bytes,upload_expires_at,content_sha256,size_bytes,
        detected_mime,verified_at,created_by_membership_id,version,
        created_at,updated_at
      ) VALUES (
        ${storage}::uuid,${fixture.tenant}::uuid,'periapsis-runtime',
        ${`${fixture.tenant}/${storage}`},'evidence.bin','internal','scanning',
        32,${new Date(Date.now() + 15 * 60_000)},${contentDigest},32,
        'application/octet-stream',${observedAt},${fixture.membership}::uuid,
        1,${observedAt},${observedAt}
      )
    `;
    await transaction`
      INSERT INTO public.dfir_evidence(
        id,tenant_id,case_id,storage_object_id,title,description,evidence_type,
        classification,content_sha256,size_bytes,detected_mime,collected_at,
        collected_by_membership_id,source,initial_retention_until,
        retention_until,initial_legal_hold,legal_hold,initial_scan_state,
        scan_state,sealed,destroyed,anchor_hash,custody_head_hash,
        custody_count,version,created_at,updated_at
      ) VALUES (
        ${evidence}::uuid,${fixture.tenant}::uuid,${fixture.case}::uuid,
        ${storage}::uuid,'Evidence boundary','','runtime','internal',
        ${contentDigest},32,'application/octet-stream',${observedAt},
        ${fixture.membership}::uuid,'runtime',NULL,NULL,false,false,
        'scanning','scanning',false,false,${digest("anchor")},
        ${digest(`custody-${version}`)},${version}::bigint,${version}::bigint,
        ${observedAt},${observedAt}
      )
    `;
    await transaction`
      INSERT INTO public.dfir_attachments(
        id,tenant_id,subject_kind,evidence_id,storage_object_id,
        original_filename,visibility,scan_state,uploaded_by_membership_id,
        uploaded_at,version
      ) VALUES (
        ${attachment}::uuid,${fixture.tenant}::uuid,'evidence',
        ${evidence}::uuid,${storage}::uuid,'evidence.bin','private','scanning',
        ${fixture.membership}::uuid,${observedAt},1
      )
    `;
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
        schema_version,payload,deduplication_key,correlation_id,causation_id,
        actor_kind,actor_id,producer,maximum_audience,occurred_at,available_at,
        attempts,max_attempts
      ) VALUES
        (${cause}::uuid,${fixture.tenant}::uuid,'dfir_storage_object',
         ${storage}::uuid,1,'dfir.attachment.prepared',1,'{}'::jsonb,
         ${`evidence-cause:${cause}`},${correlation}::uuid,NULL,'system',NULL,
         'api','operator',${observedAt},${observedAt},0,12),
        (${job}::uuid,${fixture.tenant}::uuid,'dfir_storage_object',
         ${storage}::uuid,1,'dfir.storage.scan.requested',1,
         jsonb_build_object('tenantId',${fixture.tenant}::uuid,
           'resourceId',${storage}::uuid,
           'declaredMime','application/octet-stream'),
         ${`evidence-scan:${job}`},${correlation}::uuid,${cause}::uuid,
         'system',NULL,'api','operator',${observedAt},${observedAt},0,12)
    `;
  });
  return { evidence, job, storage };
}

async function verifyEvidenceVersionBoundary(): Promise<void> {
  const ordinary = await insertEvidenceScanJob("999");
  const [ordinaryClaim] = await claimScan(primary);
  assert(ordinaryClaim);
  assert.equal(ordinaryClaim.event_id, ordinary.job);
  await expectSqlState(
    completeCustodyLimitedScan(ordinaryClaim),
    "55000",
    "a custody-limit failure category cannot terminate an evidence below the limit",
  );
  const [ordinaryStored] = await advance(
    primary,
    ordinaryClaim,
    1,
    "available",
    {
      detected: "application/octet-stream",
      digest: digest("evidence-999"),
      size: 32,
    },
    true,
  );
  assert.equal(ordinaryStored?.storage_version, "2");
  const [evidence] = await primary<{ version: string }[]>`
    SELECT version::text FROM public.dfir_evidence
    WHERE id=${ordinary.evidence}::uuid
  `;
  assert.equal(evidence?.version, "1000");

  const maximum = await insertEvidenceScanJob("1000");
  const [maximumClaim] = await claimScan(primary);
  assert(maximumClaim);
  assert.equal(maximumClaim.event_id, maximum.job);
  await expectSqlState(
    advance(
      primary,
      maximumClaim,
      1,
      "available",
      {
        detected: "application/octet-stream",
        digest: digest("evidence-1000"),
        size: 32,
      },
      true,
    ),
    "P5401",
    "scan transition must report the custody limit before any projection changes",
  );
  const [wrongLease] = identifiers(1);
  await expectSqlState(
    completeCustodyLimitedScan({ ...maximumClaim, lease_token: wrongLease }),
    "40001",
    "a stale worker cannot terminate a custody-limited scan",
  );
  await Promise.all(
    [
      { category: "evidence_custody_limit", deadLetter: false },
      { category: "attempts_exhausted", deadLetter: true },
    ].map((mode) =>
      expectSqlState(
        asWorker(
          primary,
          (transaction) => transaction`
        SELECT app.complete_dfir_storage_scan_job_v1(
          ${maximumClaim.event_id}::uuid,${maximumClaim.lease_token}::uuid,
          transaction_timestamp(),${mode.category},${mode.deadLetter}
        )
        `,
        ),
        "55000",
        "a custody-limited scan requires its exact dead-letter completion mode",
      ),
    ),
  );
  await completeCustodyLimitedScan(maximumClaim);
  const [maximumStored] = await primary<
    {
      attachment_state: string;
      attachment_version: string;
      custody_events: number;
      evidence_state: string;
      evidence_version: string;
      storage_state: string;
      storage_version: string;
    }[]
  >`
    SELECT evidence.version::text AS evidence_version,
           evidence.scan_state::text AS evidence_state,
           storage.version::text AS storage_version,
           storage.state::text AS storage_state,
           attachment.version::text AS attachment_version,
           attachment.scan_state::text AS attachment_state,
           (SELECT count(*)::integer FROM public.dfir_custody_events AS event
            WHERE event.tenant_id=evidence.tenant_id
              AND event.evidence_id=evidence.id) AS custody_events
    FROM public.dfir_evidence AS evidence
    JOIN public.dfir_storage_objects AS storage
      ON storage.tenant_id=evidence.tenant_id
     AND storage.id=evidence.storage_object_id
    JOIN public.dfir_attachments AS attachment
      ON attachment.tenant_id=evidence.tenant_id
     AND attachment.evidence_id=evidence.id
    WHERE evidence.id=${maximum.evidence}::uuid
  `;
  assert.deepEqual(maximumStored, {
    evidence_version: "1000",
    evidence_state: "scanning",
    storage_version: "1",
    storage_state: "scanning",
    attachment_version: "1",
    attachment_state: "scanning",
    custody_events: 0,
  });
  const [completed] = await primary<
    {
      dead_lettered: boolean;
      failure_category: string;
      processed: boolean;
      released: boolean;
    }[]
  >`
    SELECT dead_lettered_at IS NOT NULL AS dead_lettered,
           failure_category,processed_at IS NOT NULL AS processed,
           locked_at IS NULL AND locked_by IS NULL
             AND lease_token IS NULL AND lease_until IS NULL AS released
    FROM public.outbox_events
    WHERE id=${maximum.job}::uuid
  `;
  assert.deepEqual(completed, {
    dead_lettered: true,
    failure_category: "evidence_custody_limit",
    processed: true,
    released: true,
  });
  assert.equal((await claimScan(primary)).length, 0);
}

async function completeCustodyLimitedScan(claim: ScanClaim): Promise<unknown> {
  return asWorker(
    primary,
    (transaction) => transaction`
    SELECT app.complete_dfir_storage_scan_job_v1(
      ${claim.event_id}::uuid,${claim.lease_token}::uuid,
      transaction_timestamp(),'evidence_custody_limit',true
    )
  `,
  );
}

async function verifyPoisonReadiness(): Promise<void> {
  const upload = await insertPreparedUpload({
    expiresAt: new Date(Date.now() + 15 * 60_000),
  });
  await primary`
    UPDATE public.outbox_events SET processed_at=transaction_timestamp()
    WHERE id=${upload.event}::uuid
  `;
  const [poison] = identifiers(1);
  await primary`
    INSERT INTO public.outbox_events(
      id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
      schema_version,payload,deduplication_key,correlation_id,causation_id,
      actor_kind,producer,maximum_audience,occurred_at,available_at,max_attempts
    ) VALUES (
      ${poison}::uuid,${fixture.tenant}::uuid,'dfir_storage_object',
      ${upload.storage}::uuid,1,'dfir.storage.scan.requested',1,
      jsonb_build_object('tenantId',${fixture.tenant}::uuid,
        'resourceId',${upload.storage}::uuid),${`poison:${poison}`},
      ${identifiers(1)[0]}::uuid,${upload.cause}::uuid,'system','api',
      'operator',transaction_timestamp(),transaction_timestamp(),12
    )
  `;
  const [ready] = await asWorker(
    primary,
    (transaction) => transaction<{ value: boolean }[]>`
    SELECT app.dfir_storage_scan_runtime_ready_v1() AS value
  `,
  );
  assert.equal(ready?.value, false);
  await expectSqlState(
    claimScan(primary),
    "55000",
    "scan claim ignored a poisoned dedicated queue event",
  );
  await primary`DELETE FROM public.outbox_events WHERE id=${poison}::uuid`;
}

async function main(): Promise<void> {
  await setupCore();
  await verifyCatalog();
  await verifyTenantEnqueueBoundary();
  await verifyClaimConcurrency();
  await verifyWaitRefundsAttempt();
  await verifyFullTransitionAndFanout();
  await verifyConcurrentActivitySequence();
  await verifyExpiredCleanup();
  await verifyEvidenceVersionBoundary();
  await verifySequenceExhaustionRollsBack();
  await verifyFanoutBound();
  await verifyPoisonReadiness();
  // oxlint-disable-next-line no-console -- bounded security harness evidence.
  console.log(
    "DFIR scan queue leases, recovery, tenant ACLs, root activity, exact revisions, and orphan cleanup passed",
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
