import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

import postgres, { type Sql, type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonRecord = Record<string, unknown>;
type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
type JsonInput = { readonly [key: string]: JsonValue };
type ScopeContext = { tenantId: string | null; userId: string };
type ExportDigests = { filter: Buffer; payload: Buffer };
type RetentionStateDocument = {
  policy: { retentionDays: number; revision: number };
  anchor: {
    retainedThroughSequence: number;
    retainedThroughHash: string;
    revision: number;
  };
  activeLegalHold?: { id: string; revision: number; state: string };
};
type ExportClaim = {
  job_id: string;
  tenant_id?: string;
  object_key: string;
};
type Segment = {
  segment_id: string;
  tenant_id?: string;
  start_sequence: string;
  end_sequence: string;
  previous_hash: string;
  end_hash: string;
  event_count: string;
  object_key: string;
};

const databaseUrl = process.env.PERIAPSIS_AUDIT_OPERATIONS_TEST_DATABASE_URL;
if (!databaseUrl?.trim()) {
  throw new Error(
    "PERIAPSIS_AUDIT_OPERATIONS_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database with migration 0213 applied",
  );
}

function uuidV7(): string {
  const bytes = randomBytes(16);
  const timestamp = BigInt(Date.now());
  bytes[0] = Number((timestamp >> 40n) & 0xffn);
  bytes[1] = Number((timestamp >> 32n) & 0xffn);
  bytes[2] = Number((timestamp >> 24n) & 0xffn);
  bytes[3] = Number((timestamp >> 16n) & 0xffn);
  bytes[4] = Number((timestamp >> 8n) & 0xffn);
  bytes[5] = Number(timestamp & 0xffn);
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const fixture = {
  tenant: uuidV7(),
  foreignTenant: uuidV7(),
  tenantAdminUser: uuidV7(),
  tenantAdminMembership: uuidV7(),
  tenantAnalystUser: uuidV7(),
  tenantAnalystMembership: uuidV7(),
  platformAdminUser: uuidV7(),
  tenantSession: uuidV7(),
  analystSession: uuidV7(),
  platformSession: uuidV7(),
  platformRoleGrant: uuidV7(),
  tenantWorker: uuidV7(),
  platformWorker: uuidV7(),
} as const;
const suffix = randomBytes(6).toString("hex");
const tenantContext: ScopeContext = {
  tenantId: fixture.tenant,
  userId: fixture.tenantAdminUser,
};
const analystContext: ScopeContext = {
  tenantId: fixture.tenant,
  userId: fixture.tenantAnalystUser,
};
const platformContext: ScopeContext = {
  tenantId: null,
  userId: fixture.platformAdminUser,
};
const exportFilter = { actionPrefix: "never.matches.runtime" } as const;
const exportReason = "Security runtime export proof";
const userAgent = "Periapsis audit operations PostgreSQL 18 runtime proof";

function digest(label: string): Buffer {
  return createHash("sha256").update(`${suffix}:${label}`).digest();
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

async function auditOwnerMutationCount(
  sql: Sql,
  operation: (transaction: TransactionSql) => Promise<readonly unknown[]>,
): Promise<number> {
  try {
    return await sql.begin(async (transaction) => {
      await transaction.unsafe(
        'SET LOCAL ROLE "periapsis_audit_operations_owner"',
      );
      return (await operation(transaction)).length;
    });
  } catch (error) {
    assertSqlState(error, "42501");
    return 0;
  }
}

async function asApi<T>(
  sql: Sql,
  context: ScopeContext,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${context.tenantId ?? ""}, true),
             set_config('app.user_id', ${context.userId}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { operationResult: await operation(transaction) };
  });
  return result.operationResult;
}

async function asWorker<T>(
  sql: Sql,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { operationResult: await operation(transaction) };
  });
  return result.operationResult;
}

function envelope() {
  return {
    audit: uuidV7(),
    request: uuidV7(),
    correlation: uuidV7(),
  };
}

async function exportDigests(
  sql: Sql,
  filter: JsonInput,
  retentionSeconds: number,
  reason: string,
): Promise<ExportDigests> {
  const [row] = await sql<{ filter: Buffer; payload: Buffer }[]>`
    SELECT
      sha256(convert_to(${sql.json(filter)}::jsonb::text,'UTF8')) AS filter,
      sha256(convert_to(jsonb_build_object(
        'filter',${sql.json(filter)}::jsonb,
        'retentionSeconds',${retentionSeconds}::bigint,
        'projectionVersion',1,'format','jsonl','reason',${reason}::text
      )::text,'UTF8')) AS payload
  `;
  assert(row, "database did not calculate export digests");
  return row;
}

async function payloadDigest(sql: Sql, document: JsonInput): Promise<Buffer> {
  const [row] = await sql<{ payload: Buffer }[]>`
    SELECT sha256(convert_to(${sql.json(document)}::jsonb::text,'UTF8')) AS payload
  `;
  assert(row, "database did not calculate payload digest");
  return row.payload;
}

async function createTenantExport(
  sql: Sql,
  input: {
    keyDigest: Buffer;
    jobId: string;
    retentionSeconds?: number;
    auditId?: string;
  },
): Promise<JsonRecord> {
  const retentionSeconds = input.retentionSeconds ?? 86_400;
  const calculated = await exportDigests(
    sql,
    exportFilter,
    retentionSeconds,
    exportReason,
  );
  const access = envelope();
  return asApi(sql, tenantContext, async (transaction) => {
    const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.create_tenant_audit_export_v1(
        ${fixture.tenantSession}::uuid,'audit.export','audit.read',
        ${input.keyDigest}::bytea,${calculated.payload}::bytea,
        ${input.jobId}::uuid,${transaction.json(exportFilter)}::jsonb,
        ${calculated.filter}::bytea,${retentionSeconds}::bigint,${exportReason},
        ${input.auditId ?? access.audit}::uuid,${access.request}::uuid,
        ${access.correlation}::uuid,'198.51.100.71'::inet,${userAgent}
      ) AS document
    `;
    assert(row, "tenant export create returned no document");
    return row.document;
  });
}

async function createPlatformExport(
  sql: Sql,
  input: { keyDigest: Buffer; jobId: string },
): Promise<JsonRecord> {
  const calculated = await exportDigests(
    sql,
    exportFilter,
    86_400,
    exportReason,
  );
  const access = envelope();
  return asApi(sql, platformContext, async (transaction) => {
    const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.create_platform_audit_export_v1(
        ${fixture.platformSession}::uuid,'platform.audit.export','platform.audit.read',
        ${input.keyDigest}::bytea,${calculated.payload}::bytea,
        ${input.jobId}::uuid,${transaction.json(exportFilter)}::jsonb,
        ${calculated.filter}::bytea,86400::bigint,${exportReason},
        ${access.audit}::uuid,${access.request}::uuid,
        ${access.correlation}::uuid,'198.51.100.72'::inet,${userAgent}
      ) AS document
    `;
    assert(row, "platform export create returned no document");
    return row.document;
  });
}

function exportJob(document: JsonRecord): JsonRecord {
  const job = document["job"];
  assert(isRecord(job));
  return job;
}

function isRecord(value: unknown): value is JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

async function initializeFixture(admin: Sql): Promise<void> {
  await admin.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      INSERT INTO public.tenants(id,slug,name)
      VALUES
        (${fixture.tenant}::uuid,${`audit-ops-${suffix}`},'Audit operations runtime'),
        (${fixture.foreignTenant}::uuid,${`audit-ops-foreign-${suffix}`},'Foreign audit operations runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id)
      VALUES (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      VALUES
        (${fixture.tenantAdminUser}::uuid,${`audit-admin-${suffix}@example.invalid`},'Audit tenant admin',true),
        (${fixture.tenantAnalystUser}::uuid,${`audit-analyst-${suffix}@example.invalid`},'Audit tenant analyst',true),
        (${fixture.platformAdminUser}::uuid,${`audit-platform-${suffix}@example.invalid`},'Audit platform admin',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status)
      VALUES
        (${fixture.tenantAdminMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.tenantAdminUser}::uuid,'tenant_admin','active'),
        (${fixture.tenantAnalystMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.tenantAnalystUser}::uuid,'analyst','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.tenantAdminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.user_platform_roles(id,user_id,role_id,granted_by_user_id)
      SELECT ${fixture.platformRoleGrant}::uuid,${fixture.platformAdminUser}::uuid,
             role.id,${fixture.platformAdminUser}::uuid
      FROM public.platform_roles AS role
      WHERE role.key='platform_super_admin' AND role.system
    `;

    const sessions = [
      {
        id: fixture.tenantSession,
        user: fixture.tenantAdminUser,
        tenant: fixture.tenant,
        label: "tenant",
      },
      {
        id: fixture.analystSession,
        user: fixture.tenantAnalystUser,
        tenant: fixture.tenant,
        label: "analyst",
      },
      {
        id: fixture.platformSession,
        user: fixture.platformAdminUser,
        tenant: null,
        label: "platform",
      },
    ] as const;
    await insertSessions(transaction, sessions);
  });
}

async function insertSessions(
  transaction: TransactionSql,
  sessions: readonly {
    id: string;
    user: string;
    tenant: string | null;
    label: string;
  }[],
  index = 0,
): Promise<void> {
  const session = sessions[index];
  if (!session) return;
  await transaction`
    INSERT INTO public.auth_sessions(
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${session.id}::uuid,${session.user}::uuid,${uuidV7()}::uuid,
      ${session.tenant}::uuid,${digest(`${session.label}:token`)}::bytea,
      ${digest(`${session.label}:csrf`)}::bytea,'totp',
      date_trunc('milliseconds',transaction_timestamp())-interval '2 minutes',
      date_trunc('milliseconds',transaction_timestamp())-interval '1 minute',
      date_trunc('milliseconds',transaction_timestamp())+interval '1 hour',
      date_trunc('milliseconds',transaction_timestamp())+interval '8 hours',
      date_trunc('milliseconds',transaction_timestamp())-interval '10 minutes'
    )
  `;
  await insertSessions(transaction, sessions, index + 1);
}

async function proveCatalogAndFutureTenantPolicy(admin: Sql): Promise<void> {
  const [acl] = await admin<
    {
      direct_deletes: string;
      runtime_updates: string;
      owner_update_policies: string;
      unforced: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::text
       FROM information_schema.role_table_grants AS grant_row
       WHERE grant_row.grantee IN (
         'periapsis_api','periapsis_worker','periapsis_notifier','periapsis_auditor'
       ) AND grant_row.privilege_type='DELETE'
         AND grant_row.table_name IN (
           'audit_events','platform_audit_events',
           'tenant_ldap_jit_authentication_runs','tenant_ldap_jit_run_mappings'
         )) AS direct_deletes,
      (SELECT count(*)::text
       FROM information_schema.role_table_grants AS grant_row
       WHERE grant_row.grantee IN (
         'periapsis_api','periapsis_worker','periapsis_notifier','periapsis_auditor'
       ) AND grant_row.privilege_type='UPDATE'
         AND grant_row.table_name IN (
           'auth_sessions','tenant_memberships','tenant_authorization_states'
         )) AS runtime_updates,
      (SELECT count(*)::text
       FROM pg_catalog.pg_policy AS policy
       JOIN pg_catalog.pg_class AS relation ON relation.oid=policy.polrelid
       JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
       WHERE namespace.nspname='public'
         AND relation.relname IN (
           'auth_sessions','tenant_memberships','tenant_authorization_states'
         ) AND policy.polcmd='w'
         AND 'periapsis_audit_operations_owner' = ANY (
           SELECT role.rolname FROM pg_catalog.pg_roles AS role
           WHERE role.oid=ANY(policy.polroles)
         )) AS owner_update_policies,
      (SELECT count(*)::text FROM pg_catalog.pg_class AS relation
       JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
       WHERE namespace.nspname='public'
         AND relation.relname LIKE '%audit%'
         AND relation.relname IN (
           'tenant_audit_export_jobs','platform_audit_export_jobs',
           'tenant_audit_operation_receipts','platform_audit_operation_receipts',
           'tenant_audit_export_manifests','platform_audit_export_manifests',
           'tenant_audit_retention_policies','platform_audit_retention_policy',
           'tenant_audit_legal_holds','platform_audit_legal_holds',
           'tenant_audit_segments','platform_audit_segments',
           'tenant_audit_retention_anchors','platform_audit_retention_anchor'
         ) AND (NOT relation.relrowsecurity OR NOT relation.relforcerowsecurity)) AS unforced
  `;
  assert.deepEqual(acl, {
    direct_deletes: "0",
    runtime_updates: "0",
    owner_update_policies: "0",
    unforced: "0",
  });

  const directUpdates = {
    sessionRows: await auditOwnerMutationCount(
      admin,
      (transaction) => transaction`
      UPDATE public.auth_sessions SET last_seen_at=clock_timestamp()
      WHERE id=${fixture.tenantSession}::uuid RETURNING id
    `,
    ),
    membershipRows: await auditOwnerMutationCount(
      admin,
      (transaction) => transaction`
      UPDATE public.tenant_memberships SET role='analyst'
      WHERE id=${fixture.tenantAdminMembership}::uuid RETURNING id
    `,
    ),
    authorizationRows: await auditOwnerMutationCount(
      admin,
      (transaction) => transaction`
      UPDATE public.tenant_authorization_states SET revision=revision+1
      WHERE tenant_id=${fixture.tenant}::uuid RETURNING tenant_id
    `,
    ),
  };
  assert.deepEqual(
    directUpdates,
    { sessionRows: 0, membershipRows: 0, authorizationRows: 0 },
    "instrumental row-lock privileges allowed the NOLOGIN owner to mutate fenced rows",
  );

  await expectSqlState(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id',${fixture.tenant},true),
               set_config('app.user_id',${fixture.tenantAdminUser},true)
      `;
      await transaction`
        SELECT * FROM app.private_require_tenant_audit_operation_actor_v1(
          ${fixture.tenantSession}::uuid,'audit.export',true
        )
      `;
      return { unexpectedlyAuthorized: true };
    }),
    "42501",
    "the API runtime role directly executed the migrator-owned tenant authority helper",
  );
  await expectSqlState(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction`
        SELECT set_config('app.tenant_id','',true),
               set_config('app.user_id',${fixture.platformAdminUser},true)
      `;
      await transaction`
        SELECT * FROM app.private_require_platform_audit_operation_actor_v1(
          ${fixture.platformSession}::uuid,'platform.audit.export',true
        )
      `;
      return { unexpectedlyAuthorized: true };
    }),
    "42501",
    "the API runtime role directly executed the migrator-owned platform authority helper",
  );

  const [grantCounts] = await admin<
    {
      admin_count: string;
      analyst_count: string;
      ceiling_count: string;
    }[]
  >`
    SELECT
      count(*) FILTER (WHERE role.key='tenant_admin')::text AS admin_count,
      count(*) FILTER (WHERE role.key='analyst')::text AS analyst_count,
      (SELECT count(*)::text
       FROM public.tenant_role_delegation_ceilings AS ceiling
       JOIN public.tenant_roles AS role ON role.id=ceiling.role_id
       JOIN public.tenant_permissions AS permission ON permission.id=ceiling.permission_id
       WHERE ceiling.tenant_id=${fixture.tenant}::uuid
         AND role.key='tenant_admin'
         AND permission.key IN ('audit.export','audit.retention.manage')) AS ceiling_count
    FROM public.tenant_role_permissions AS grant_row
    JOIN public.tenant_roles AS role ON role.id=grant_row.role_id
    JOIN public.tenant_permissions AS permission ON permission.id=grant_row.permission_id
    WHERE grant_row.tenant_id=${fixture.tenant}::uuid
      AND permission.key IN ('audit.export','audit.retention.manage')
  `;
  assert.deepEqual(grantCounts, {
    admin_count: "2",
    analyst_count: "0",
    ceiling_count: "2",
  });

  await expectSqlState(
    asApi(admin, analystContext, async (transaction) => {
      const calculated = await exportDigests(
        admin,
        exportFilter,
        86_400,
        exportReason,
      );
      const access = envelope();
      await transaction`
        SELECT app.create_tenant_audit_export_v1(
          ${fixture.analystSession}::uuid,'audit.export','audit.read',
          ${digest("analyst-denied-key")}::bytea,${calculated.payload}::bytea,
          ${uuidV7()}::uuid,${transaction.json(exportFilter)}::jsonb,
          ${calculated.filter}::bytea,86400::bigint,${exportReason},
          ${access.audit}::uuid,${access.request}::uuid,${access.correlation}::uuid,
          '198.51.100.73'::inet,${userAgent}
        )
      `;
    }),
    "42501",
    "analyst reached tenant audit export",
  );
}

async function proveTenantExportLifecycle(
  admin: Sql,
  apiA: Sql,
  apiB: Sql,
  worker: Sql,
) {
  const keyDigest = digest("tenant-concurrent-key");
  const firstJob = uuidV7();
  const [left, right] = await Promise.all([
    createTenantExport(apiA, { keyDigest, jobId: firstJob }),
    createTenantExport(apiB, { keyDigest, jobId: uuidV7() }),
  ]);
  const documents = [left, right];
  assert.deepEqual(
    documents
      .map((document) => document["replayed"])
      .toSorted((first, second) => Number(first) - Number(second)),
    [false, true],
    "same-key race did not apply once and replay once",
  );
  assert.equal(exportJob(left)["id"], exportJob(right)["id"]);
  const createdJobId = String(exportJob(left)["id"]);

  await expectSqlState(
    createTenantExport(apiB, {
      keyDigest,
      jobId: uuidV7(),
      retentionSeconds: 3_600,
    }),
    "23505",
    "same key with different payload did not fail as key reuse",
  );

  const [reasonEvidence] = await admin<
    { reason: string; metadata: JsonRecord }[]
  >`
    SELECT reason,metadata FROM public.audit_events
    WHERE tenant_id=${fixture.tenant}::uuid AND action='audit.export.created'
      AND resource_id=${createdJobId}::uuid
  `;
  assert.equal(reasonEvidence?.reason, exportReason);
  assert.equal(reasonEvidence?.metadata["projectionVersion"], 1);

  const statusDocument = await asApi(
    apiA,
    tenantContext,
    async (transaction) => {
      const access = envelope();
      const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.get_tenant_audit_export_v1(
        ${fixture.tenantSession}::uuid,'audit.export','audit.read',${createdJobId}::uuid,
        ${access.audit}::uuid,${access.request}::uuid,${access.correlation}::uuid,
        '198.51.100.74'::inet,${userAgent}
      ) AS document
    `;
      assert(row);
      return row.document;
    },
  );
  assert.equal(statusDocument["id"], createdJobId);
  const [statusEvidence] = await admin<{ count: string }[]>`
    SELECT count(*)::text AS count FROM public.audit_events
    WHERE tenant_id=${fixture.tenant}::uuid
      AND action='audit.export.status_accessed' AND resource_id=${createdJobId}::uuid
  `;
  assert.equal(statusEvidence?.count, "1");

  const fence = digest("tenant-success-fence");
  const [claim] = await asWorker(
    worker,
    (transaction) =>
      transaction<ExportClaim[]>`
      SELECT * FROM app.claim_tenant_audit_export_v1(
        ${fixture.tenantWorker}::uuid,${fence}::bytea,300,${uuidV7()}::uuid
      )
    `,
  );
  assert.equal(claim?.job_id, createdJobId);
  assert.match(
    claim?.object_key ?? "",
    new RegExp(
      `^tenants/${fixture.tenant}/audit/exports/${createdJobId}/v1\\.jsonl$`,
      "u",
    ),
  );
  const page = await asWorker(
    worker,
    (transaction) =>
      transaction`
      SELECT * FROM app.read_tenant_audit_export_page_v1(
        ${fixture.tenantWorker}::uuid,${createdJobId}::uuid,${fence}::bytea,0,100
      )
    `,
  );
  assert.equal(page.length, 0, "non-matching filter returned audit rows");

  const artifactId = uuidV7();
  const artifactDigest = digest("empty-tenant-artifact");
  const finalized = await asWorker(worker, async (transaction) => {
    const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.finalize_tenant_audit_export_v1(
        ${fixture.tenantWorker}::uuid,${createdJobId}::uuid,${fence}::bytea,
        ${artifactId}::uuid,${artifactDigest}::bytea,0,0,${uuidV7()}::uuid
      ) AS document
    `;
    return row?.document;
  });
  assert.equal(finalized?.["state"], "succeeded");
  const finalizeReplay = await asWorker(worker, async (transaction) => {
    const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.finalize_tenant_audit_export_v1(
        ${fixture.tenantWorker}::uuid,${createdJobId}::uuid,${fence}::bytea,
        ${artifactId}::uuid,${artifactDigest}::bytea,0,0,${uuidV7()}::uuid
      ) AS document
    `;
    return row?.document;
  });
  assert.deepEqual(
    finalizeReplay,
    finalized,
    "finalization lost-response replay drifted",
  );

  const authorized = await asApi(apiA, tenantContext, async (transaction) => {
    const access = envelope();
    return transaction`
      SELECT * FROM app.authorize_tenant_audit_export_download_v1(
        ${fixture.tenantSession}::uuid,'audit.export','audit.read',${createdJobId}::uuid,
        ${access.audit}::uuid,${access.request}::uuid,${access.correlation}::uuid,
        '198.51.100.74'::inet,${userAgent}
      )
    `;
  });
  assert.equal(authorized[0]?.["bytes"], "0");

  const cancelJob = uuidV7();
  await createTenantExport(apiA, {
    keyDigest: digest("tenant-cancel-create"),
    jobId: cancelJob,
  });
  const cancelKey = digest("tenant-cancel-key");
  const cancelReason = "Export superseded by narrower scope";
  const cancelPayload = await payloadDigest(admin, {
    exportId: cancelJob,
    expectedRevision: 1,
    reason: cancelReason,
  });
  const cancel = async (auditId: string): Promise<JsonRecord> =>
    asApi(apiA, tenantContext, async (transaction) => {
      const access = envelope();
      const [row] = await transaction<{ document: JsonRecord }[]>`
        SELECT app.cancel_tenant_audit_export_v1(
          ${fixture.tenantSession}::uuid,'audit.export','audit.read',${cancelJob}::uuid,1,
          ${cancelKey}::bytea,${cancelPayload}::bytea,${cancelReason},
          ${auditId}::uuid,${access.request}::uuid,${access.correlation}::uuid,
          '198.51.100.75'::inet,${userAgent}
        ) AS document
      `;
      assert(row);
      return row.document;
    });
  const cancelled = await cancel(uuidV7());
  const cancelledReplay = await cancel(uuidV7());
  assert.equal(exportJob(cancelled)["state"], "cancelled");
  assert.equal(cancelledReplay["replayed"], true);

  return createdJobId;
}

async function proveTenantAuthorizationRace(
  admin: Sql,
  api: Sql,
  worker: Sql,
): Promise<void> {
  const jobId = uuidV7();
  await createTenantExport(api, {
    keyDigest: digest("tenant-revocation-create"),
    jobId,
  });
  const fence = digest("tenant-revocation-fence");
  let releaseClaim!: () => void;
  let reportClaim!: () => void;
  const claimReady = new Promise<void>((resolve) => {
    reportClaim = resolve;
  });
  const allowCommit = new Promise<void>((resolve) => {
    releaseClaim = resolve;
  });

  const claimPromise = worker.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    const [claim] = await transaction<ExportClaim[]>`
      SELECT * FROM app.claim_tenant_audit_export_v1(
        ${fixture.tenantWorker}::uuid,${fence}::bytea,300,${uuidV7()}::uuid
      )
    `;
    assert.equal(claim?.job_id, jobId);
    reportClaim();
    await allowCommit;
  });
  await claimReady;
  const bumpPromise = admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`SELECT app.bump_tenant_authorization_revision(${fixture.tenant}::uuid)`;
  });
  await delay(50);
  releaseClaim();
  await Promise.all([claimPromise, bumpPromise]);

  await expectSqlState(
    asWorker(
      worker,
      (transaction) =>
        transaction`
        SELECT * FROM app.read_tenant_audit_export_page_v1(
          ${fixture.tenantWorker}::uuid,${jobId}::uuid,${fence}::bytea,0,100
        )
      `,
    ),
    "42501",
    "permission epoch race left a tenant export page executable",
  );
  const [revoked] = await asWorker(
    worker,
    (transaction) =>
      transaction<{ document: JsonRecord }[]>`
      SELECT app.finalize_tenant_audit_export_v1(
        ${fixture.tenantWorker}::uuid,${jobId}::uuid,${fence}::bytea,
        ${uuidV7()}::uuid,${digest("discarded-tenant-artifact")}::bytea,0,0,
        ${uuidV7()}::uuid
      ) AS document
    `,
  );
  assert.equal(revoked?.document["state"], "authorization_revoked");
}

async function tenantRetentionState(api: Sql): Promise<RetentionStateDocument> {
  return asApi(api, tenantContext, async (transaction) => {
    const access = envelope();
    const [row] = await transaction<{ document: RetentionStateDocument }[]>`
      SELECT app.get_tenant_audit_retention_v1(
        ${fixture.tenantSession}::uuid,'audit.retention.manage',${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.76'::inet,
        ${userAgent}
      ) AS document
    `;
    assert(row);
    return row.document;
  });
}

async function platformRetentionState(
  api: Sql,
): Promise<RetentionStateDocument> {
  return asApi(api, platformContext, async (transaction) => {
    const access = envelope();
    const [row] = await transaction<{ document: RetentionStateDocument }[]>`
      SELECT app.get_platform_audit_retention_v1(
        ${fixture.platformSession}::uuid,'platform.audit.retention.manage',${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.77'::inet,
        ${userAgent}
      ) AS document
    `;
    assert(row);
    return row.document;
  });
}

async function proveRetentionPoliciesAndHolds(
  admin: Sql,
  api: Sql,
  worker: Sql,
): Promise<void> {
  const tenantState = await tenantRetentionState(api);
  assert.equal(tenantState.anchor.retainedThroughSequence, 0);
  assert.equal(tenantState.anchor.retainedThroughHash, "0".repeat(64));
  const tenantReason = "Annual tenant retention review";
  const tenantPayload = await payloadDigest(admin, {
    expectedRevision: tenantState.policy.revision,
    reason: tenantReason,
    retentionDays: 30,
  });
  const tenantKey = digest("tenant-retention-change");
  const updateTenant = async (): Promise<JsonRecord> =>
    asApi(api, tenantContext, async (transaction) => {
      const access = envelope();
      const [row] = await transaction<{ document: JsonRecord }[]>`
        SELECT app.update_tenant_audit_retention_v1(
          ${fixture.tenantSession}::uuid,'audit.retention.manage',
          ${tenantState.policy.revision},30,${tenantKey}::bytea,${tenantPayload}::bytea,
          ${tenantReason},${access.audit}::uuid,${access.request}::uuid,
          ${access.correlation}::uuid,'198.51.100.78'::inet,${userAgent}
        ) AS document
      `;
      assert(row);
      return row.document;
    });
  const updated = await updateTenant();
  const replayed = await updateTenant();
  assert.equal(updated["replayed"], false);
  assert.equal(replayed["replayed"], true);

  const holdId = uuidV7();
  const holdReason = "Regulatory evidence preservation";
  const holdPayload = await payloadDigest(admin, { reason: holdReason });
  await asApi(api, tenantContext, async (transaction) => {
    const access = envelope();
    await transaction`
      SELECT app.place_tenant_audit_legal_hold_v1(
        ${fixture.tenantSession}::uuid,'audit.retention.manage',${holdId}::uuid,
        ${digest("tenant-hold-place")}::bytea,${holdPayload}::bytea,${holdReason},
        ${access.audit}::uuid,${access.request}::uuid,${access.correlation}::uuid,
        '198.51.100.79'::inet,${userAgent}
      )
    `;
  });
  const heldClosure = await asWorker(
    worker,
    (transaction) =>
      transaction`
      SELECT * FROM app.close_tenant_audit_segment_v1(
        ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,100000,
        'Scheduled tenant retention closure',${uuidV7()}::uuid
      )
    `,
  );
  assert.equal(
    heldClosure.length,
    0,
    "legal hold allowed tenant segment closure",
  );

  const releaseReason = "Regulatory hold released by counsel";
  const releasePayload = await payloadDigest(admin, {
    expectedRevision: 1,
    holdId,
    reason: releaseReason,
  });
  await asApi(api, tenantContext, async (transaction) => {
    const access = envelope();
    await transaction`
      SELECT app.release_tenant_audit_legal_hold_v1(
        ${fixture.tenantSession}::uuid,'audit.retention.manage',${holdId}::uuid,1,
        ${digest("tenant-hold-release")}::bytea,${releasePayload}::bytea,
        ${releaseReason},${access.audit}::uuid,${access.request}::uuid,
        ${access.correlation}::uuid,'198.51.100.80'::inet,${userAgent}
      )
    `;
  });

  const platformState = await platformRetentionState(api);
  assert.equal(platformState.anchor.retainedThroughSequence, 0);
  const platformReason = "Annual platform retention review";
  const platformPayload = await payloadDigest(admin, {
    expectedRevision: platformState.policy.revision,
    reason: platformReason,
    retentionDays: 30,
  });
  const [platformUpdated] = await asApi(api, platformContext, (transaction) => {
    const access = envelope();
    return transaction<{ document: JsonRecord }[]>`
      SELECT app.update_platform_audit_retention_v1(
        ${fixture.platformSession}::uuid,'platform.audit.retention.manage',
        ${platformState.policy.revision},30,${digest("platform-retention-change")}::bytea,
        ${platformPayload}::bytea,${platformReason},${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.81'::inet,
        ${userAgent}
      ) AS document
    `;
  });
  assert.equal(platformUpdated?.document["replayed"], false);

  const platformHoldId = uuidV7();
  const platformHoldReason = "Platform investigation evidence preservation";
  const platformHoldPayload = await payloadDigest(admin, {
    reason: platformHoldReason,
  });
  await asApi(api, platformContext, async (transaction) => {
    const access = envelope();
    await transaction`
      SELECT app.place_platform_audit_legal_hold_v1(
        ${fixture.platformSession}::uuid,'platform.audit.retention.manage',
        ${platformHoldId}::uuid,${digest("platform-hold-place")}::bytea,
        ${platformHoldPayload}::bytea,${platformHoldReason},${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.82'::inet,
        ${userAgent}
      )
    `;
  });
  await ageAuditChain(admin, { kind: "platform" });
  const heldPlatformClosure = await asWorker(
    worker,
    (transaction) =>
      transaction`
      SELECT * FROM app.close_platform_audit_segment_v1(
        ${fixture.platformWorker}::uuid,100000,
        'Scheduled platform retention closure',${uuidV7()}::uuid
      )
    `,
  );
  assert.equal(
    heldPlatformClosure.length,
    0,
    "legal hold allowed platform segment closure",
  );
  const platformReleaseReason = "Platform evidence hold released by counsel";
  const platformReleasePayload = await payloadDigest(admin, {
    expectedRevision: 1,
    holdId: platformHoldId,
    reason: platformReleaseReason,
  });
  await asApi(api, platformContext, async (transaction) => {
    const access = envelope();
    await transaction`
      SELECT app.release_platform_audit_legal_hold_v1(
        ${fixture.platformSession}::uuid,'platform.audit.retention.manage',
        ${platformHoldId}::uuid,1,${digest("platform-hold-release")}::bytea,
        ${platformReleasePayload}::bytea,${platformReleaseReason},${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.83'::inet,
        ${userAgent}
      )
    `;
  });

  const platformRetentionKey = digest("platform-retention-change");
  await admin`
    UPDATE public.tenant_audit_operation_receipts
    SET created_at=transaction_timestamp()-interval '2 days',
        expires_at=transaction_timestamp()-interval '1 day'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND action='retention.change' AND idempotency_key_digest=${tenantKey}::bytea
  `;
  await admin`
    UPDATE public.platform_audit_operation_receipts
    SET created_at=transaction_timestamp()-interval '2 days',
        expires_at=transaction_timestamp()-interval '1 day'
    WHERE action='retention.change' AND idempotency_key_digest=${platformRetentionKey}::bytea
  `;
  const [tenantReceiptPrune] = await asWorker(
    worker,
    (transaction) =>
      transaction<{ deleted: number }[]>`
      SELECT app.prune_tenant_audit_operation_receipts_v1(
        ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,10,
        'Expired tenant audit operation receipt cleanup',${uuidV7()}::uuid
      ) AS deleted
    `,
  );
  const [platformReceiptPrune] = await asWorker(
    worker,
    (transaction) =>
      transaction<{ deleted: number }[]>`
      SELECT app.prune_platform_audit_operation_receipts_v1(
        ${fixture.platformWorker}::uuid,10,
        'Expired platform audit operation receipt cleanup',${uuidV7()}::uuid
      ) AS deleted
    `,
  );
  assert.equal(tenantReceiptPrune?.deleted, 1);
  assert.equal(platformReceiptPrune?.deleted, 1);
}

async function ageAuditChain(
  admin: Sql,
  scope: { kind: "tenant"; tenantId: string } | { kind: "platform" },
): Promise<void> {
  await admin.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    if (scope.kind === "tenant") {
      await transaction`
        UPDATE public.audit_events SET occurred_at=occurred_at-interval '31 days'
        WHERE tenant_id=${scope.tenantId}::uuid
      `;
      const [anchor] = await transaction<{ hash: string }[]>`
        SELECT coalesce(anchor.retained_through_hash,repeat('0',64)) AS hash
        FROM (SELECT 1) AS singleton
        LEFT JOIN public.tenant_audit_retention_anchors AS anchor
          ON anchor.tenant_id=${scope.tenantId}::uuid
      `;
      const events = await transaction<{ id: string }[]>`
        SELECT id::text FROM public.audit_events
        WHERE tenant_id=${scope.tenantId}::uuid ORDER BY sequence
      `;
      const lastHash = await resealTenantEvents(
        transaction,
        events,
        anchor?.hash ?? "0".repeat(64),
      );
      const [last] = await transaction<{ sequence: string }[]>`
        SELECT coalesce(max(sequence),0)::text AS sequence FROM public.audit_events
        WHERE tenant_id=${scope.tenantId}::uuid
      `;
      await transaction`
        UPDATE public.audit_chain_heads SET last_sequence=${last?.sequence ?? "0"}::bigint,
          last_event_hash=${lastHash}::character(64),updated_at=clock_timestamp()
        WHERE tenant_id=${scope.tenantId}::uuid
      `;
      return;
    }
    await transaction`
      UPDATE public.platform_audit_events SET occurred_at=occurred_at-interval '31 days'
    `;
    const [anchor] = await transaction<{ hash: string }[]>`
      SELECT retained_through_hash AS hash FROM public.platform_audit_retention_anchor
      WHERE singleton
    `;
    const events = await transaction<{ id: string }[]>`
      SELECT id::text FROM public.platform_audit_events ORDER BY sequence
    `;
    const lastHash = await resealPlatformEvents(
      transaction,
      events,
      anchor?.hash ?? "0".repeat(64),
    );
    const [last] = await transaction<{ sequence: string }[]>`
      SELECT coalesce(max(sequence),0)::text AS sequence FROM public.platform_audit_events
    `;
    await transaction`
      UPDATE public.platform_audit_chain_head SET
        last_sequence=${last?.sequence ?? "0"}::bigint,
        last_event_hash=${lastHash}::character(64),updated_at=clock_timestamp()
      WHERE singleton
    `;
  });
}

async function resealTenantEvents(
  transaction: TransactionSql,
  events: readonly { id: string }[],
  previousHash: string,
  index = 0,
): Promise<string> {
  const event = events[index];
  if (!event) return previousHash;
  await transaction`
    UPDATE public.audit_events SET previous_hash=${previousHash}::character(64)
    WHERE id=${event.id}::uuid
  `;
  const [calculated] = await transaction<{ hash: string }[]>`
    SELECT app.calculate_audit_event_hash(event,${previousHash}::character(64)) AS hash
    FROM public.audit_events AS event WHERE event.id=${event.id}::uuid
  `;
  assert(calculated);
  await transaction`
    UPDATE public.audit_events SET event_hash=${calculated.hash}::character(64)
    WHERE id=${event.id}::uuid
  `;
  return resealTenantEvents(transaction, events, calculated.hash, index + 1);
}

async function resealPlatformEvents(
  transaction: TransactionSql,
  events: readonly { id: string }[],
  previousHash: string,
  index = 0,
): Promise<string> {
  const event = events[index];
  if (!event) return previousHash;
  await transaction`
    UPDATE public.platform_audit_events SET previous_hash=${previousHash}::character(64)
    WHERE id=${event.id}::uuid
  `;
  const [calculated] = await transaction<{ hash: string }[]>`
    SELECT app.calculate_platform_audit_event_hash(event,${previousHash}::character(64)) AS hash
    FROM public.platform_audit_events AS event WHERE event.id=${event.id}::uuid
  `;
  assert(calculated);
  await transaction`
    UPDATE public.platform_audit_events SET event_hash=${calculated.hash}::character(64)
    WHERE id=${event.id}::uuid
  `;
  return resealPlatformEvents(transaction, events, calculated.hash, index + 1);
}

async function proveTenantSegmentRetention(
  admin: Sql,
  api: Sql,
  worker: Sql,
): Promise<void> {
  await ageAuditChain(admin, { kind: "tenant", tenantId: fixture.tenant });
  const [segment] = await asWorker(
    worker,
    (transaction) =>
      transaction<Segment[]>`
      SELECT * FROM app.close_tenant_audit_segment_v1(
        ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,100000,
        'Scheduled tenant retention closure',${uuidV7()}::uuid
      )
    `,
  );
  assert(segment, "eligible tenant prefix did not close");
  assert.equal(segment.previous_hash, "0".repeat(64));
  const rows = await asWorker(
    worker,
    (transaction) =>
      transaction`
      SELECT * FROM app.read_tenant_audit_segment_page_v1(
        ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,
        ${segment.segment_id}::uuid,0,1000
      )
    `,
  );
  assert.equal(String(rows.length), segment.event_count);

  const artifactDigest = digest("tenant-segment-artifact");
  const signature = Buffer.concat([
    digest("tenant-signature-a"),
    digest("tenant-signature-b"),
  ]);
  const [preserved] = await asWorker(
    worker,
    (transaction) =>
      transaction<{ document: JsonRecord }[]>`
      SELECT app.preserve_tenant_audit_segment_v1(
        ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,${segment.segment_id}::uuid,1,
        ${artifactDigest}::bytea,4096,'runtime-ed25519-v1',${signature}::bytea,
        'Tenant segment signed and preserved',${uuidV7()}::uuid
      ) AS document
    `,
  );
  assert.equal(preserved?.document["state"], "preserved");

  await expectSqlState(
    asWorker(
      worker,
      (transaction) =>
        transaction`
        SELECT app.prune_tenant_audit_segment_v1(
          ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,${segment.segment_id}::uuid,2,
          ${`${segment.object_key}.tampered`},${artifactDigest}::bytea,4096,
          'runtime-ed25519-v1',${signature}::bytea,true,
          'Tenant anchored prefix prune',${uuidV7()}::uuid
        )
      `,
    ),
    "55000",
    "tampered tenant object key was accepted",
  );
  const prune = async (): Promise<JsonRecord> => {
    const [row] = await asWorker(
      worker,
      (transaction) =>
        transaction<{ document: JsonRecord }[]>`
        SELECT app.prune_tenant_audit_segment_v1(
          ${fixture.tenantWorker}::uuid,${fixture.tenant}::uuid,${segment.segment_id}::uuid,2,
          ${segment.object_key},${artifactDigest}::bytea,4096,
          'runtime-ed25519-v1',${signature}::bytea,true,
          'Tenant anchored prefix prune',${uuidV7()}::uuid
        ) AS document
      `,
    );
    assert(row);
    return row.document;
  };
  const pruned = await prune();
  const pruneReplay = await prune();
  assert.equal(pruned["state"], "pruned");
  assert.deepEqual(pruneReplay, pruned, "tenant prune exact replay drifted");

  const verification = await asApi(api, tenantContext, async (transaction) => {
    const access = envelope();
    const [row] = await transaction<
      {
        valid: boolean;
        retained_through_sequence: string;
      }[]
    >`
      SELECT valid,retained_through_sequence::text
      FROM app.verify_tenant_audit_chain_v2(
        ${fixture.tenantSession}::uuid,'audit.read',${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.82'::inet,
        ${userAgent},${fixture.tenant}::uuid
      )
    `;
    return row;
  });
  assert.equal(verification?.valid, true);
  assert.equal(verification?.retained_through_sequence, segment.end_sequence);
}

async function provePlatformEpochAndRetention(
  admin: Sql,
  api: Sql,
  worker: Sql,
): Promise<void> {
  const jobId = uuidV7();
  await createPlatformExport(api, {
    keyDigest: digest("platform-revocation-create"),
    jobId,
  });
  const platformStatus = await asApi(
    api,
    platformContext,
    async (transaction) => {
      const access = envelope();
      const [row] = await transaction<{ document: JsonRecord }[]>`
      SELECT app.get_platform_audit_export_v1(
        ${fixture.platformSession}::uuid,'platform.audit.export','platform.audit.read',
        ${jobId}::uuid,${access.audit}::uuid,${access.request}::uuid,
        ${access.correlation}::uuid,'198.51.100.84'::inet,${userAgent}
      ) AS document
    `;
      assert(row);
      return row.document;
    },
  );
  assert.equal(platformStatus["id"], jobId);
  const [before] = await admin<{ permission_epoch: string }[]>`
    SELECT permission_epoch::text FROM public.platform_user_authorization_epochs
    WHERE user_id=${fixture.platformAdminUser}::uuid
  `;
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      DELETE FROM public.platform_role_permissions AS grant_row
      USING public.platform_roles AS role,public.platform_permissions AS permission
      WHERE grant_row.role_id=role.id AND grant_row.permission_id=permission.id
        AND role.key='platform_super_admin' AND permission.key='platform.audit.export'
    `;
  });
  const [afterDelete] = await admin<{ permission_epoch: string }[]>`
    SELECT permission_epoch::text FROM public.platform_user_authorization_epochs
    WHERE user_id=${fixture.platformAdminUser}::uuid
  `;
  assert(
    BigInt(afterDelete!.permission_epoch) > BigInt(before!.permission_epoch),
  );
  const noClaim = await asWorker(
    worker,
    (transaction) =>
      transaction<ExportClaim[]>`
      SELECT * FROM app.claim_platform_audit_export_v1(
        ${fixture.platformWorker}::uuid,${digest("platform-revoked-fence")}::bytea,
        300,${uuidV7()}::uuid
      )
    `,
  );
  assert.equal(noClaim.length, 0);
  const [revokedJob] = await admin<{ state: string }[]>`
    SELECT state FROM public.platform_audit_export_jobs WHERE id=${jobId}::uuid
  `;
  assert.equal(revokedJob?.state, "authorization_revoked");

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.platform_role_permissions(role_id,permission_id)
      SELECT role.id,permission.id
      FROM public.platform_roles AS role
      CROSS JOIN public.platform_permissions AS permission
      WHERE role.key='platform_super_admin' AND permission.key='platform.audit.export'
      ON CONFLICT DO NOTHING
    `;
  });
  const [afterInsert] = await admin<{ permission_epoch: string }[]>`
    SELECT permission_epoch::text FROM public.platform_user_authorization_epochs
    WHERE user_id=${fixture.platformAdminUser}::uuid
  `;
  assert(
    BigInt(afterInsert!.permission_epoch) >
      BigInt(afterDelete!.permission_epoch),
  );

  await ageAuditChain(admin, { kind: "platform" });
  const [segment] = await asWorker(
    worker,
    (transaction) =>
      transaction<Segment[]>`
      SELECT * FROM app.close_platform_audit_segment_v1(
        ${fixture.platformWorker}::uuid,100000,
        'Scheduled platform retention closure',${uuidV7()}::uuid
      )
    `,
  );
  assert(segment, "eligible platform prefix did not close");
  const artifactDigest = digest("platform-segment-artifact");
  const signature = Buffer.concat([
    digest("platform-signature-a"),
    digest("platform-signature-b"),
  ]);
  await asWorker(
    worker,
    (transaction) =>
      transaction`
      SELECT app.preserve_platform_audit_segment_v1(
        ${fixture.platformWorker}::uuid,${segment.segment_id}::uuid,1,
        ${artifactDigest}::bytea,4096,'runtime-ed25519-v1',${signature}::bytea,
        'Platform segment signed and preserved',${uuidV7()}::uuid
      )
    `,
  );
  const [pruned] = await asWorker(
    worker,
    (transaction) =>
      transaction<{ document: JsonRecord }[]>`
      SELECT app.prune_platform_audit_segment_v1(
        ${fixture.platformWorker}::uuid,${segment.segment_id}::uuid,2,
        ${segment.object_key},${artifactDigest}::bytea,4096,'runtime-ed25519-v1',
        ${signature}::bytea,true,'Platform anchored prefix prune',${uuidV7()}::uuid
      ) AS document
    `,
  );
  assert.equal(pruned?.document["state"], "pruned");
  const verification = await asApi(
    api,
    platformContext,
    async (transaction) => {
      const access = envelope();
      const [row] = await transaction<
        {
          valid: boolean;
          retained_through_sequence: string;
        }[]
      >`
      SELECT valid,retained_through_sequence::text
      FROM app.verify_platform_audit_chain_v2(
        ${fixture.platformSession}::uuid,'platform.audit.read',${access.audit}::uuid,
        ${access.request}::uuid,${access.correlation}::uuid,'198.51.100.83'::inet,
        ${userAgent}
      )
    `;
      return row;
    },
  );
  assert.equal(verification?.valid, true);
  assert.equal(verification?.retained_through_sequence, segment.end_sequence);
}

const admin = postgres(databaseUrl, { max: 4, onnotice: () => undefined });
const apiA = postgres(databaseUrl, { max: 2, onnotice: () => undefined });
const apiB = postgres(databaseUrl, { max: 2, onnotice: () => undefined });
const worker = postgres(databaseUrl, { max: 3, onnotice: () => undefined });

try {
  await initializeFixture(admin);
  await proveCatalogAndFutureTenantPolicy(admin);
  const downloadableJob = await proveTenantExportLifecycle(
    admin,
    apiA,
    apiB,
    worker,
  );
  await proveTenantAuthorizationRace(admin, apiA, worker);
  await proveRetentionPoliciesAndHolds(admin, apiA, worker);
  await proveTenantSegmentRetention(admin, apiA, worker);
  await provePlatformEpochAndRetention(admin, apiA, worker);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`SELECT app.bump_tenant_authorization_revision(${fixture.tenant}::uuid)`;
  });
  await expectSqlState(
    asApi(apiA, tenantContext, async (transaction) => {
      const access = envelope();
      await transaction`
        SELECT * FROM app.authorize_tenant_audit_export_download_v1(
          ${fixture.tenantSession}::uuid,'audit.export','audit.read',${downloadableJob}::uuid,
          ${access.audit}::uuid,${access.request}::uuid,${access.correlation}::uuid,
          '198.51.100.84'::inet,${userAgent}
        )
      `;
    }),
    "42501",
    "download remained authorized after its pinned permission epoch changed",
  );

  // oxlint-disable-next-line no-console -- bounded security harness evidence.
  console.log(
    "audit export and retention runtime invariants verified (tenant/platform replay, races, revocation, hold, signed-prefix prune)",
  );
} finally {
  await Promise.all([admin.end(), apiA.end(), apiB.end(), worker.end()]);
}
