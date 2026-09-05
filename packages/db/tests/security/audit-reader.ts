import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";

type ErrorWithCode = Error & { code?: string };

type JsonValue =
  | null
  | string
  | number
  | boolean
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
type JsonObject = { readonly [key: string]: JsonValue };

type AuditEventRow = {
  id: string;
  sequence: string;
  action: string;
  actor_user_id: string | null;
  authentication_method: string | null;
  metadata: Record<string, unknown>;
};

type VerificationRow = {
  event_count: string;
  last_sequence: string;
  first_invalid_sequence: string | null;
  head_valid: boolean;
  valid: boolean;
};

type ApiContext = {
  tenantId: string | null;
  userId: string;
};

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

function digest(label: string): Buffer {
  return createHash("sha256").update(`audit-reader-fixture:${label}`).digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
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
  transaction: TransactionSql,
  context: ApiContext,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const savepointResult = await transaction.savepoint(async (sql) => {
    await sql.unsafe('SET LOCAL ROLE "periapsis_api"');
    await sql`
      SELECT set_config('app.tenant_id', ${context.tenantId ?? ""}, true),
             set_config('app.user_id', ${context.userId}, true),
             set_config('app.service_account_id', '', true)
    `;
    const operationResult = await operation(sql);
    await sql.unsafe("RESET ROLE");
    return { operationResult };
  });
  return savepointResult.operationResult;
}

async function forEachSequential<T>(
  values: readonly T[],
  operation: (value: T) => Promise<void>,
  index = 0,
): Promise<void> {
  const value = values[index];
  if (value === undefined) {
    return;
  }
  await operation(value);
  await forEachSequential(values, operation, index + 1);
}

function accessEnvelope(): {
  auditId: string;
  requestId: string;
  correlationId: string;
} {
  return {
    auditId: uuidV7(),
    requestId: uuidV7(),
    correlationId: uuidV7(),
  };
}

async function listTenantAuditEvents(
  sql: TransactionSql,
  sessionId: string,
  permission: string,
  afterSequence: bigint,
  access: ReturnType<typeof accessEnvelope>,
): Promise<AuditEventRow[]> {
  const rows = await sql<AuditEventRow[]>`
    SELECT event.id::text, event.sequence::text, event.action,
           event.actor_user_id::text, event.authentication_method,
           event.metadata
    FROM app.list_tenant_audit_events_v1(
      ${sessionId}::uuid, ${permission}::text,
      ${afterSequence.toString()}::bigint,
      100::integer, NULL::timestamp with time zone,
      NULL::timestamp with time zone, NULL::public.audit_actor_type,
      NULL::uuid, NULL::uuid, 'audit.fixture'::text, NULL::text,
      NULL::uuid, NULL::uuid, NULL::uuid, NULL::public.audit_outcome,
      NULL::text, ${access.auditId}::uuid, ${access.requestId}::uuid,
      ${access.correlationId}::uuid, '127.0.0.1'::inet,
      'periapsis-audit-reader-security-test'::text
    ) AS event
  `;
  return Array.from(rows);
}

async function listPlatformAuditEvents(
  sql: TransactionSql,
  sessionId: string,
  permission: string,
  afterSequence: bigint,
  access: ReturnType<typeof accessEnvelope>,
): Promise<AuditEventRow[]> {
  const rows = await sql<AuditEventRow[]>`
    SELECT event.id::text, event.sequence::text, event.action,
           event.actor_user_id::text, event.authentication_method,
           event.metadata
    FROM app.list_platform_audit_events_v1(
      ${sessionId}::uuid, ${permission}::text,
      ${afterSequence.toString()}::bigint,
      100::integer, NULL::timestamp with time zone,
      NULL::timestamp with time zone, NULL::public.audit_actor_type,
      NULL::uuid, 'audit.fixture'::text, NULL::text, NULL::uuid,
      NULL::uuid, NULL::uuid, NULL::public.audit_outcome, NULL::text,
      ${access.auditId}::uuid, ${access.requestId}::uuid,
      ${access.correlationId}::uuid, '127.0.0.1'::inet,
      'periapsis-audit-reader-security-test'::text
    ) AS event
  `;
  return Array.from(rows);
}

async function verifyTenantAuditChain(
  sql: TransactionSql,
  sessionId: string,
  permission: string,
  tenantId: string,
  access: ReturnType<typeof accessEnvelope>,
): Promise<VerificationRow> {
  const [row] = await sql<VerificationRow[]>`
    SELECT verification.event_count::text,
           verification.last_sequence::text,
           verification.first_invalid_sequence::text,
           verification.head_valid, verification.valid
    FROM app.verify_tenant_audit_chain_v1(
      ${sessionId}::uuid, ${permission}::text, ${access.auditId}::uuid,
      ${access.requestId}::uuid, ${access.correlationId}::uuid,
      '127.0.0.1'::inet, 'periapsis-audit-reader-security-test'::text,
      ${tenantId}::uuid
    ) AS verification
  `;
  assert(row, "tenant audit verifier returned no row");
  return row;
}

async function verifyPlatformAuditChain(
  sql: TransactionSql,
  sessionId: string,
  permission: string,
  access: ReturnType<typeof accessEnvelope>,
): Promise<VerificationRow> {
  const [row] = await sql<VerificationRow[]>`
    SELECT verification.event_count::text,
           verification.last_sequence::text,
           verification.first_invalid_sequence::text,
           verification.head_valid, verification.valid
    FROM app.verify_platform_audit_chain_v1(
      ${sessionId}::uuid, ${permission}::text, ${access.auditId}::uuid,
      ${access.requestId}::uuid, ${access.correlationId}::uuid,
      '127.0.0.1'::inet, 'periapsis-audit-reader-security-test'::text
    ) AS verification
  `;
  assert(row, "platform audit verifier returned no row");
  return row;
}

async function tenantHead(
  sql: TransactionSql,
  tenantId: string,
): Promise<bigint> {
  const [row] = await sql<{ last_sequence: string }[]>`
    SELECT last_sequence::text
    FROM public.audit_chain_heads
    WHERE tenant_id = ${tenantId}::uuid
  `;
  assert(row, "tenant audit chain head is missing");
  return BigInt(row.last_sequence);
}

async function platformHead(sql: TransactionSql): Promise<bigint> {
  const [row] = await sql<{ last_sequence: string }[]>`
    SELECT last_sequence::text
    FROM public.platform_audit_chain_head
    WHERE singleton
  `;
  assert(row, "platform audit chain head is missing");
  return BigInt(row.last_sequence);
}

async function appendTenantFixtureEvent(
  sql: TransactionSql,
  eventId: string,
  tenantId: string,
  userId: string,
  metadata: JsonObject,
): Promise<void> {
  await sql`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', ${userId}, true),
           set_config('app.service_account_id', '', true)
  `;
  await sql.unsafe('SET LOCAL ROLE "periapsis_migrator"');
  await sql`
    SELECT app.append_tenant_authorization_audit(
      ${eventId}::uuid, 'audit.fixture.tenant'::text,
      'audit_fixture'::text, ${tenantId}::uuid, ${uuidV7()}::uuid,
      ${uuidV7()}::uuid, '127.0.0.1'::inet,
      'periapsis-audit-reader-security-test'::text, 'totp'::text,
      NULL::jsonb, NULL::jsonb, ${sql.json(metadata)}::jsonb
    )
  `;
  await sql.unsafe("RESET ROLE");
}

async function appendPlatformFixtureEvent(
  sql: TransactionSql,
  eventId: string,
  userId: string,
  metadata: JsonObject,
): Promise<void> {
  await sql.unsafe('SET LOCAL ROLE "periapsis_migrator"');
  await sql`
    SELECT app.append_platform_audit_event(
      ${eventId}::uuid, 'user'::public.audit_actor_type, ${userId}::uuid,
      'audit.fixture.platform'::text, 'audit_fixture'::text, NULL::uuid,
      ${uuidV7()}::uuid, ${uuidV7()}::uuid, '127.0.0.1'::inet,
      'periapsis-audit-reader-security-test'::text, 'totp'::text,
      'success'::public.audit_outcome, NULL::text,
      ${sql.json(metadata)}::jsonb
    )
  `;
  await sql.unsafe("RESET ROLE");
}

const fixture = {
  tenant: uuidV7(),
  foreignTenant: uuidV7(),
  tenantReaderUser: uuidV7(),
  tenantReaderMembership: uuidV7(),
  foreignTenantReaderMembership: uuidV7(),
  unprivilegedUser: uuidV7(),
  unprivilegedMembership: uuidV7(),
  platformAuditorUser: uuidV7(),
  platformRoleGrant: uuidV7(),
  tenantSession: uuidV7(),
  revokedSession: uuidV7(),
  expiredSession: uuidV7(),
  missingMfaSession: uuidV7(),
  mismatchedTenantSession: uuidV7(),
  unprivilegedSession: uuidV7(),
  platformSession: uuidV7(),
  tenantFixtureEvent: uuidV7(),
  platformFixtureEvent: uuidV7(),
  unsafeTenantEvent: uuidV7(),
  unsafePlatformEvent: uuidV7(),
} as const;

const suffix = randomBytes(6).toString("hex");
const tenantReaderContext: ApiContext = {
  tenantId: fixture.tenant,
  userId: fixture.tenantReaderUser,
};
const unprivilegedContext: ApiContext = {
  tenantId: fixture.tenant,
  userId: fixture.unprivilegedUser,
};
const platformAuditorContext: ApiContext = {
  tenantId: null,
  userId: fixture.platformAuditorUser,
};
const databaseURL = requireDatabaseUrl();
const admin = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const rollbackMarker = new Error("intentional audit-reader fixture rollback");

try {
  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      await transaction`
        INSERT INTO public.tenants (id, slug, name)
        VALUES
          (${fixture.tenant}::uuid, ${`audit-reader-${suffix}`}, 'Audit reader security fixture'),
          (${fixture.foreignTenant}::uuid, ${`audit-reader-foreign-${suffix}`}, 'Foreign audit reader fixture')
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id)
        VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active)
        VALUES
          (${fixture.tenantReaderUser}::uuid, ${`audit-reader-${suffix}@example.invalid`}, 'Tenant audit reader', true),
          (${fixture.unprivilegedUser}::uuid, ${`audit-unprivileged-${suffix}@example.invalid`}, 'Unprivileged tenant user', true),
          (${fixture.platformAuditorUser}::uuid, ${`platform-auditor-${suffix}@example.invalid`}, 'Platform audit reader', true)
      `;
      await transaction`
        INSERT INTO public.tenant_memberships (
          id, tenant_id, user_id, role, status
        ) VALUES
          (${fixture.tenantReaderMembership}::uuid, ${fixture.tenant}::uuid,
           ${fixture.tenantReaderUser}::uuid, 'tenant_admin', 'active'),
          (${fixture.foreignTenantReaderMembership}::uuid,
           ${fixture.foreignTenant}::uuid, ${fixture.tenantReaderUser}::uuid,
           'tenant_admin', 'active'),
          (${fixture.unprivilegedMembership}::uuid, ${fixture.tenant}::uuid,
           ${fixture.unprivilegedUser}::uuid, 'analyst', 'active')
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.tenant}::uuid, ${fixture.tenantReaderMembership}::uuid
        )
      `;
      await transaction`
        SELECT app.seed_tenant_authorization(
          ${fixture.foreignTenant}::uuid,
          ${fixture.foreignTenantReaderMembership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.user_platform_roles (
          id, user_id, role_id, granted_by_user_id
        )
        SELECT ${fixture.platformRoleGrant}::uuid,
               ${fixture.platformAuditorUser}::uuid, role.id,
               ${fixture.platformAuditorUser}::uuid
        FROM public.platform_roles AS role
        WHERE role.key = 'platform_auditor' AND role.system
      `;

      const sessions = [
        {
          id: fixture.tenantSession,
          userId: fixture.tenantReaderUser,
          activeTenantId: fixture.tenant,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-1 minute",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: "-2 minutes",
          revokedOffset: null,
        },
        {
          id: fixture.revokedSession,
          userId: fixture.tenantReaderUser,
          activeTenantId: fixture.tenant,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-2 minutes",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: "-3 minutes",
          revokedOffset: "-1 minute",
        },
        {
          id: fixture.expiredSession,
          userId: fixture.tenantReaderUser,
          activeTenantId: fixture.tenant,
          createdOffset: "-2 hours",
          lastSeenOffset: "-90 minutes",
          idleOffset: "-30 minutes",
          absoluteOffset: "+30 minutes",
          mfaOffset: "-100 minutes",
          revokedOffset: null,
        },
        {
          id: fixture.missingMfaSession,
          userId: fixture.tenantReaderUser,
          activeTenantId: fixture.tenant,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-1 minute",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: null,
          revokedOffset: null,
        },
        {
          id: fixture.mismatchedTenantSession,
          userId: fixture.tenantReaderUser,
          activeTenantId: fixture.foreignTenant,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-1 minute",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: "-2 minutes",
          revokedOffset: null,
        },
        {
          id: fixture.unprivilegedSession,
          userId: fixture.unprivilegedUser,
          activeTenantId: fixture.tenant,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-1 minute",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: "-2 minutes",
          revokedOffset: null,
        },
        {
          id: fixture.platformSession,
          userId: fixture.platformAuditorUser,
          activeTenantId: null,
          createdOffset: "-10 minutes",
          lastSeenOffset: "-1 minute",
          idleOffset: "+30 minutes",
          absoluteOffset: "+8 hours",
          mfaOffset: "-2 minutes",
          revokedOffset: null,
        },
      ] as const;

      await forEachSequential(sessions, async (session) => {
        await transaction`
          INSERT INTO public.auth_sessions (
            id, user_id, rotation_family_id, active_tenant_id,
            token_digest, csrf_secret_digest, authentication_method,
            mfa_satisfied_at, last_seen_at, idle_expires_at,
            absolute_expires_at, revoked_at, revoke_reason, created_at
          ) VALUES (
            ${session.id}::uuid, ${session.userId}::uuid, ${uuidV7()}::uuid,
            ${session.activeTenantId}::uuid,
            ${digest(`${session.id}:token`)}::bytea,
            ${digest(`${session.id}:csrf`)}::bytea, 'totp',
            CASE WHEN ${session.mfaOffset}::text IS NULL THEN NULL
                 ELSE transaction_timestamp() + ${session.mfaOffset}::interval END,
            transaction_timestamp() + ${session.lastSeenOffset}::interval,
            date_trunc('milliseconds', transaction_timestamp()) +
              ${session.idleOffset}::interval,
            date_trunc('milliseconds', transaction_timestamp()) +
              ${session.absoluteOffset}::interval,
            CASE WHEN ${session.revokedOffset}::text IS NULL THEN NULL
                 ELSE transaction_timestamp() + ${session.revokedOffset}::interval END,
            CASE WHEN ${session.revokedOffset}::text IS NULL THEN NULL
                 ELSE 'security test revocation' END,
            transaction_timestamp() + ${session.createdOffset}::interval
          )
        `;
      });

      const safeMetadata = {
        operation: "credential.rotation",
        details: {
          secretId: uuidV7(),
          secretVersion: 2,
          secretMaterialIncluded: false,
          tokenKind: "bearer",
        },
        history: [{ credentialId: uuidV7(), credentialVersion: 1 }],
      };
      const [safeMetadataValidation] = await transaction<
        { document: unknown; safe: boolean }[]
      >`
        SELECT ${transaction.json(safeMetadata)}::jsonb AS document,
               app.audit_json_document_safe_v1(
                 ${transaction.json(safeMetadata)}::jsonb, 16384, false
               ) AS safe
      `;
      assert.equal(
        safeMetadataValidation?.safe,
        true,
        `safe typed fixture metadata does not satisfy the 0103 guard: ${JSON.stringify(safeMetadataValidation?.document)}`,
      );
      await appendTenantFixtureEvent(
        transaction,
        fixture.tenantFixtureEvent,
        fixture.tenant,
        fixture.tenantReaderUser,
        safeMetadata,
      );

      const [storedSafeEvent] = await transaction<
        { metadata: Record<string, unknown> }[]
      >`
        SELECT metadata
        FROM public.audit_events
        WHERE id = ${fixture.tenantFixtureEvent}::uuid
      `;
      assert.deepEqual(
        storedSafeEvent?.metadata,
        safeMetadata,
        "safe typed metadata was not accepted intact",
      );

      const tenantHeadBeforeUnsafe = await tenantHead(
        transaction,
        fixture.tenant,
      );
      await expectSqlState(
        transaction.savepoint((sql) =>
          appendTenantFixtureEvent(
            sql,
            fixture.unsafeTenantEvent,
            fixture.tenant,
            fixture.tenantReaderUser,
            { details: { entries: [{ password: "must-never-be-stored" }] } },
          ),
        ),
        "23514",
        "tenant audit accepted a recursively nested password",
      );
      assert.equal(
        await tenantHead(transaction, fixture.tenant),
        tenantHeadBeforeUnsafe,
        "rejected tenant metadata advanced the audit chain",
      );

      const platformHeadBeforeFixture = await platformHead(transaction);
      await appendPlatformFixtureEvent(
        transaction,
        fixture.platformFixtureEvent,
        fixture.platformAuditorUser,
        safeMetadata,
      );
      const platformHeadAfterFixture = await platformHead(transaction);
      assert.equal(platformHeadAfterFixture, platformHeadBeforeFixture + 1n);

      await expectSqlState(
        transaction.savepoint((sql) =>
          appendPlatformFixtureEvent(
            sql,
            fixture.unsafePlatformEvent,
            fixture.platformAuditorUser,
            {
              envelope: [{ nested: { clientSecret: "must-never-be-stored" } }],
            },
          ),
        ),
        "23514",
        "platform audit accepted a recursively nested client secret",
      );
      assert.equal(
        await platformHead(transaction),
        platformHeadAfterFixture,
        "rejected platform metadata advanced the audit chain",
      );

      await forEachSequential(
        [
          "public.audit_events",
          "public.audit_chain_heads",
          "public.platform_audit_events",
          "public.platform_audit_chain_head",
        ],
        (table) =>
          expectSqlState(
            asApi(transaction, tenantReaderContext, async (sql) => {
              await sql.unsafe(`SELECT 1 FROM ${table} LIMIT 1`);
            }),
            "42501",
            `periapsis_api read ${table} directly`,
          ),
      );

      const tenantHeadBeforeList = await tenantHead(
        transaction,
        fixture.tenant,
      );
      const tenantListAccess = accessEnvelope();
      const tenantRows = await asApi(transaction, tenantReaderContext, (sql) =>
        listTenantAuditEvents(
          sql,
          fixture.tenantSession,
          "audit.read",
          0n,
          tenantListAccess,
        ),
      );
      assert.deepEqual(
        tenantRows.map((row) => row.id),
        [fixture.tenantFixtureEvent],
        "tenant projection leaked its own access event or missed the fixture",
      );
      assert.equal(
        await tenantHead(transaction, fixture.tenant),
        tenantHeadBeforeList + 1n,
      );

      const [tenantListEvidence] = await transaction<AuditEventRow[]>`
        SELECT id::text, sequence::text, action, actor_user_id::text,
               authentication_method, metadata
        FROM public.audit_events
        WHERE id = ${tenantListAccess.auditId}::uuid
      `;
      assert(tenantListEvidence, "tenant list did not append access evidence");
      assert.equal(tenantListEvidence.action, "audit.accessed");
      assert.equal(tenantListEvidence.actor_user_id, fixture.tenantReaderUser);
      assert.equal(tenantListEvidence.authentication_method, "totp");
      assert.deepEqual(tenantListEvidence.metadata, {
        afterSequence: 0,
        filtersApplied: 1,
        limit: 100,
        returnedCount: 1,
      });

      const tenantHeadBeforeAtomicFailure = await tenantHead(
        transaction,
        fixture.tenant,
      );
      await expectSqlState(
        asApi(transaction, tenantReaderContext, (sql) =>
          listTenantAuditEvents(sql, fixture.tenantSession, "audit.read", 0n, {
            ...accessEnvelope(),
            auditId: fixture.tenantFixtureEvent,
          }),
        ),
        "23505",
        "tenant projection committed despite a failed self-audit append",
      );
      assert.equal(
        await tenantHead(transaction, fixture.tenant),
        tenantHeadBeforeAtomicFailure,
        "failed tenant self-audit append was not atomic",
      );

      const deniedTenantCases = [
        {
          name: "missing permission",
          context: unprivilegedContext,
          sessionId: fixture.unprivilegedSession,
          permission: "audit.read",
          sqlState: "42501",
        },
        {
          name: "wrong permission key",
          context: tenantReaderContext,
          sessionId: fixture.tenantSession,
          permission: "case.read",
          sqlState: "22023",
        },
        {
          name: "revoked session",
          context: tenantReaderContext,
          sessionId: fixture.revokedSession,
          permission: "audit.read",
          sqlState: "42501",
        },
        {
          name: "expired session",
          context: tenantReaderContext,
          sessionId: fixture.expiredSession,
          permission: "audit.read",
          sqlState: "42501",
        },
        {
          name: "session without MFA",
          context: tenantReaderContext,
          sessionId: fixture.missingMfaSession,
          permission: "audit.read",
          sqlState: "42501",
        },
        {
          name: "active tenant mismatch",
          context: tenantReaderContext,
          sessionId: fixture.mismatchedTenantSession,
          permission: "audit.read",
          sqlState: "42501",
        },
      ] as const;

      await forEachSequential(deniedTenantCases, async (denied) => {
        const headBefore = await tenantHead(transaction, fixture.tenant);
        await expectSqlState(
          asApi(transaction, denied.context, (sql) =>
            listTenantAuditEvents(
              sql,
              denied.sessionId,
              denied.permission,
              0n,
              accessEnvelope(),
            ),
          ),
          denied.sqlState,
          `${denied.name} reached the tenant audit projection`,
        );
        assert.equal(
          await tenantHead(transaction, fixture.tenant),
          headBefore,
          `${denied.name} appended tenant access evidence`,
        );
      });

      const tenantHeadBeforeTenantMismatch = await tenantHead(
        transaction,
        fixture.tenant,
      );
      await expectSqlState(
        asApi(transaction, tenantReaderContext, (sql) =>
          verifyTenantAuditChain(
            sql,
            fixture.tenantSession,
            "audit.read",
            fixture.foreignTenant,
            accessEnvelope(),
          ),
        ),
        "22023",
        "tenant verifier accepted a tenant ID outside the request context",
      );
      assert.equal(
        await tenantHead(transaction, fixture.tenant),
        tenantHeadBeforeTenantMismatch,
      );

      const tenantHeadBeforeVerify = await tenantHead(
        transaction,
        fixture.tenant,
      );
      const tenantVerifyAccess = accessEnvelope();
      const tenantVerification = await asApi(
        transaction,
        tenantReaderContext,
        (sql) =>
          verifyTenantAuditChain(
            sql,
            fixture.tenantSession,
            "audit.read",
            fixture.tenant,
            tenantVerifyAccess,
          ),
      );
      assert.deepEqual(tenantVerification, {
        event_count: tenantHeadBeforeVerify.toString(),
        last_sequence: tenantHeadBeforeVerify.toString(),
        first_invalid_sequence: null,
        head_valid: true,
        valid: true,
      });
      assert.equal(
        await tenantHead(transaction, fixture.tenant),
        tenantHeadBeforeVerify + 1n,
        "tenant verification did not append its post-snapshot evidence",
      );

      const [tenantVerifyEvidence] = await transaction<AuditEventRow[]>`
        SELECT id::text, sequence::text, action, actor_user_id::text,
               authentication_method, metadata
        FROM public.audit_events
        WHERE id = ${tenantVerifyAccess.auditId}::uuid
      `;
      assert.equal(tenantVerifyEvidence?.action, "audit.chain_verified");
      assert.equal(
        tenantVerifyEvidence?.metadata.lastSequence,
        Number(tenantHeadBeforeVerify),
        "tenant verification evidence did not preserve its pre-self-audit head",
      );

      const platformHeadBeforeDenied = await platformHead(transaction);
      await expectSqlState(
        asApi(transaction, tenantReaderContext, (sql) =>
          listPlatformAuditEvents(
            sql,
            fixture.tenantSession,
            "platform.audit.read",
            platformHeadBeforeFixture,
            accessEnvelope(),
          ),
        ),
        "42501",
        "tenant audit permission implied platform audit permission",
      );
      assert.equal(await platformHead(transaction), platformHeadBeforeDenied);

      const platformListAccess = accessEnvelope();
      const platformRows = await asApi(
        transaction,
        platformAuditorContext,
        (sql) =>
          listPlatformAuditEvents(
            sql,
            fixture.platformSession,
            "platform.audit.read",
            platformHeadBeforeFixture,
            platformListAccess,
          ),
      );
      assert.deepEqual(
        platformRows.map((row) => row.id),
        [fixture.platformFixtureEvent],
        "platform projection leaked its own access event or missed the fixture",
      );

      const [platformListEvidence] = await transaction<AuditEventRow[]>`
        SELECT id::text, sequence::text, action, actor_user_id::text,
               authentication_method, metadata
        FROM public.platform_audit_events
        WHERE id = ${platformListAccess.auditId}::uuid
      `;
      assert.equal(platformListEvidence?.action, "audit.accessed");
      assert.equal(
        platformListEvidence?.actor_user_id,
        fixture.platformAuditorUser,
      );
      assert.equal(platformListEvidence?.authentication_method, "totp");

      const platformHeadBeforeVerify = await platformHead(transaction);
      const platformVerifyAccess = accessEnvelope();
      const platformVerification = await asApi(
        transaction,
        platformAuditorContext,
        (sql) =>
          verifyPlatformAuditChain(
            sql,
            fixture.platformSession,
            "platform.audit.read",
            platformVerifyAccess,
          ),
      );
      assert.deepEqual(platformVerification, {
        event_count: platformHeadBeforeVerify.toString(),
        last_sequence: platformHeadBeforeVerify.toString(),
        first_invalid_sequence: null,
        head_valid: true,
        valid: true,
      });
      assert.equal(
        await platformHead(transaction),
        platformHeadBeforeVerify + 1n,
        "platform verification did not append its post-snapshot evidence",
      );

      const [platformVerifyEvidence] = await transaction<AuditEventRow[]>`
        SELECT id::text, sequence::text, action, actor_user_id::text,
               authentication_method, metadata
        FROM public.platform_audit_events
        WHERE id = ${platformVerifyAccess.auditId}::uuid
      `;
      assert.equal(platformVerifyEvidence?.action, "audit.chain_verified");
      assert.equal(
        platformVerifyEvidence?.metadata.lastSequence,
        Number(platformHeadBeforeVerify),
        "platform verification evidence did not preserve its pre-self-audit head",
      );

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
  process.stdout.write(
    "audit reader least-privilege, live-session, self-audit, and redaction checks passed\n",
  );
} finally {
  await admin.end();
}
