import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql, type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type SettingsRow = {
  tenant_id: string;
  brand_name: string;
  brand_mark: string;
  primary_color: string;
  accent_color: string;
  timezone: string;
  locale: string;
  version: number;
  updated_at: Date;
};

const databaseUrl = process.env.PERIAPSIS_TENANT_SETTINGS_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_SETTINGS_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database with migration 0214 applied",
  );
}

const runSequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4d14-1400-7000-8000-${(runSequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  customerUser: uuid(102),
  foreignAdminUser: uuid(103),
  adminMembership: uuid(201),
  customerMembership: uuid(202),
  foreignAdminMembership: uuid(203),
  customerRoleGrant: uuid(204),
  adminSession: uuid(301),
  adminFamily: uuid(302),
  customerSession: uuid(303),
  customerFamily: uuid(304),
  foreignSession: uuid(305),
  foreignFamily: uuid(306),
} as const;

const suffix = runSequence.toString(36);
let traceSequence = 400;
const nextID = (): string => {
  traceSequence += 1;
  return uuid(traceSequence);
};
const digest = (label: string): Buffer =>
  createHash("sha256")
    .update(`tenant-settings-runtime:${suffix}:${label}`)
    .digest();

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
    (error: unknown) => assertSqlState(error, expected),
    message,
  );
}

async function setApiContext(
  transaction: TransactionSql,
  tenantID: string,
  userID: string,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantID}, true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function asApi<T>(
  connection: Sql,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await connection.begin(async (transaction) => {
    await setApiContext(transaction, tenantID, userID);
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function readSettings(
  connection: Sql,
  tenantID: string,
  userID: string,
  sessionID: string,
): Promise<SettingsRow> {
  return asApi(connection, tenantID, userID, async (transaction) => {
    const [row] = await transaction<SettingsRow[]>`
      SELECT tenant_id,brand_name,brand_mark,primary_color,accent_color,
             timezone,locale,version,updated_at
      FROM app.get_tenant_settings_v1(${sessionID}::uuid,'totp')
    `;
    assert(row, "tenant settings read returned no row");
    return row;
  });
}

type SettingsInput = {
  brandName: string;
  brandMark: string;
  primaryColor: string;
  accentColor: string;
  timezone: string;
  locale: string;
  reason: string;
};

async function updateSettings(
  connection: Sql,
  sessionID: string,
  userID: string,
  expectedVersion: number,
  input: SettingsInput,
  traceIDs: readonly [string, string, string] = [nextID(), nextID(), nextID()],
): Promise<SettingsRow> {
  return asApi(connection, fixture.tenant, userID, async (transaction) => {
    const [row] = await transaction<SettingsRow[]>`
      SELECT tenant_id,brand_name,brand_mark,primary_color,accent_color,
             timezone,locale,version,updated_at
      FROM app.update_tenant_settings_v1(
        ${sessionID}::uuid,'totp',${expectedVersion},${input.brandName},
        ${input.brandMark},${input.primaryColor},${input.accentColor},
        ${input.timezone},${input.locale},${input.reason},
        ${traceIDs[0]}::uuid,${traceIDs[1]}::uuid,${traceIDs[2]}::uuid,
        '198.51.100.42'::inet,'Periapsis tenant settings runtime proof'
      )
    `;
    assert(row, "tenant settings update returned no row");
    return row;
  });
}

async function insertSession(
  transaction: TransactionSql,
  input: {
    id: string;
    familyID: string;
    userID: string;
    tenantID: string;
    label: string;
    createdAt: Date;
  },
): Promise<void> {
  const idleExpiresAt = new Date(input.createdAt.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(
    input.createdAt.getTime() + 2 * 60 * 60_000,
  );
  await transaction`
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${input.id}::uuid,${input.userID}::uuid,${input.familyID}::uuid,
      ${input.tenantID}::uuid,${digest(`${input.label}:token`)}::bytea,
      ${digest(`${input.label}:csrf`)}::bytea,'totp',${input.createdAt},
      ${input.createdAt},${idleExpiresAt},${absoluteExpiresAt},${input.createdAt}
    )
  `;
}

const admin = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const first = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const second = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

try {
  const [server] = await admin<{ major: number; migration: boolean }[]>`
    SELECT current_setting('server_version_num')::integer / 10000 AS major,
           to_regprocedure(
             'app.update_tenant_settings_v1(uuid,text,integer,text,text,text,text,text,text,text,uuid,uuid,uuid,inet,text)'
           ) IS NOT NULL AS migration
  `;
  assert.deepEqual(server, { major: 18, migration: true });

  const createdAt = new Date(Date.now() - 60_000);
  const existing = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.tenants
    WHERE id IN (${fixture.tenant}::uuid,${fixture.foreignTenant}::uuid)
  `;
  assert.equal(existing[0]?.count, 0, "runtime proof requires unused IDs");

  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES
        (${fixture.tenant}::uuid,${`settings-${suffix}`},
          'Northstar Response','active',${createdAt},${createdAt}),
        (${fixture.foreignTenant}::uuid,${`settings-foreign-${suffix}`},
          'Foreign Response','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name,active,created_at,updated_at)
      VALUES
        (${fixture.adminUser}::uuid,${`settings-admin-${suffix}@example.invalid`},
          'Settings admin',true,${createdAt},${createdAt}),
        (${fixture.customerUser}::uuid,${`settings-customer-${suffix}@example.invalid`},
          'Settings customer',true,${createdAt},${createdAt}),
        (${fixture.foreignAdminUser}::uuid,${`settings-foreign-${suffix}@example.invalid`},
          'Foreign settings admin',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES
        (${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.adminUser}::uuid,'tenant_admin','active',${createdAt},${createdAt}),
        (${fixture.customerMembership}::uuid,${fixture.tenant}::uuid,
          ${fixture.customerUser}::uuid,'customer_user','active',${createdAt},${createdAt}),
        (${fixture.foreignAdminMembership}::uuid,${fixture.foreignTenant}::uuid,
          ${fixture.foreignAdminUser}::uuid,'tenant_admin','active',${createdAt},${createdAt})
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid,${fixture.foreignAdminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason,granted_at,version,updated_at
      )
      SELECT ${fixture.customerRoleGrant}::uuid,${fixture.tenant}::uuid,
             ${fixture.customerMembership}::uuid,role.id,source.id,
             ${fixture.adminMembership}::uuid,
             'Grant the built-in customer portal role for runtime proof',
             ${createdAt},1,${createdAt}
      FROM public.tenant_roles AS role
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=role.tenant_id AND source.key='manual'
      WHERE role.tenant_id=${fixture.tenant}::uuid
        AND role.key='customer_user'
    `;
    await insertSession(transaction, {
      id: fixture.adminSession,
      familyID: fixture.adminFamily,
      userID: fixture.adminUser,
      tenantID: fixture.tenant,
      label: "admin",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.customerSession,
      familyID: fixture.customerFamily,
      userID: fixture.customerUser,
      tenantID: fixture.tenant,
      label: "customer",
      createdAt,
    });
    await insertSession(transaction, {
      id: fixture.foreignSession,
      familyID: fixture.foreignFamily,
      userID: fixture.foreignAdminUser,
      tenantID: fixture.foreignTenant,
      label: "foreign",
      createdAt,
    });
  });

  const initial = await readSettings(
    first,
    fixture.tenant,
    fixture.customerUser,
    fixture.customerSession,
  );
  assert.equal(initial.brand_name, "Northstar Response");
  assert.equal(initial.version, 1);

  const [initialTenant] = await admin<
    { version: number; timezone: string; locale: string }[]
  >`
    SELECT version,timezone,locale FROM public.tenants
    WHERE id=${fixture.tenant}::uuid
  `;
  assert(initialTenant, "fixture tenant is missing");

  await expectSqlState(
    updateSettings(first, fixture.customerSession, fixture.customerUser, 1, {
      brandName: "Customer Override",
      brandMark: "NO",
      primaryColor: "#112233",
      accentColor: "#445566",
      timezone: "UTC",
      locale: "en",
      reason: "Customers must not administer tenant settings",
    }),
    "42501",
    "customer role changed tenant settings",
  );

  await expectSqlState(
    readSettings(
      first,
      fixture.foreignTenant,
      fixture.adminUser,
      fixture.adminSession,
    ),
    "42501",
    "a session crossed the active-tenant boundary",
  );

  await expectSqlState(
    asApi(
      first,
      fixture.tenant,
      fixture.adminUser,
      async (transaction) =>
        transaction`SELECT tenant_id FROM public.tenant_settings`,
    ),
    "42501",
    "the API role read tenant settings directly",
  );

  await expectSqlState(
    updateSettings(first, fixture.adminSession, fixture.adminUser, 1, {
      brandName: "Trusted\u202eexe",
      brandMark: "NO",
      primaryColor: "#112233",
      accentColor: "#445566",
      timezone: "UTC",
      locale: "en",
      reason: "Reject an invisible brand control",
    }),
    "22023",
    "a bidirectional format control reached tenant branding",
  );

  const firstInput: SettingsInput = {
    brandName: "Aurora Response",
    brandMark: "AUR",
    primaryColor: "#2855d9",
    accentColor: "#12a594",
    timezone: "UTC",
    locale: "it-IT",
    reason: "Apply the approved Aurora tenant identity",
  };
  const secondInput: SettingsInput = {
    brandName: "Borealis Response",
    brandMark: "BOR",
    primaryColor: "#5639c7",
    accentColor: "#d97706",
    timezone: "Europe/Rome",
    locale: "en-GB",
    reason: "Apply the approved Borealis tenant identity",
  };
  const firstAuditID = nextID();
  const secondAuditID = nextID();
  const outcomes = await Promise.allSettled([
    updateSettings(
      first,
      fixture.adminSession,
      fixture.adminUser,
      1,
      firstInput,
      [firstAuditID, nextID(), nextID()],
    ),
    updateSettings(
      second,
      fixture.adminSession,
      fixture.adminUser,
      1,
      secondInput,
      [secondAuditID, nextID(), nextID()],
    ),
  ]);
  const fulfilled = outcomes.filter(
    (outcome): outcome is PromiseFulfilledResult<SettingsRow> =>
      outcome.status === "fulfilled",
  );
  const rejected = outcomes.filter(
    (outcome): outcome is PromiseRejectedResult =>
      outcome.status === "rejected",
  );
  assert.equal(fulfilled.length, 1, "exactly one CAS update must commit");
  assert.equal(rejected.length, 1, "exactly one CAS update must lose");
  assertSqlState(rejected[0]?.reason, "40001");
  const winner = fulfilled[0]?.value;
  assert(winner, "the CAS race produced no winner");
  assert.equal(winner.version, 2);
  const winningInput =
    winner.brand_name === firstInput.brandName ? firstInput : secondInput;
  assert.equal(winner.brand_name, winningInput.brandName);
  assert.equal(winner.timezone, winningInput.timezone);
  assert.equal(winner.locale, winningInput.locale);

  const persisted = await readSettings(
    first,
    fixture.tenant,
    fixture.customerUser,
    fixture.customerSession,
  );
  assert.deepEqual(
    {
      brandName: persisted.brand_name,
      brandMark: persisted.brand_mark,
      primaryColor: persisted.primary_color,
      accentColor: persisted.accent_color,
      timezone: persisted.timezone,
      locale: persisted.locale,
      version: persisted.version,
    },
    {
      brandName: winningInput.brandName,
      brandMark: winningInput.brandMark,
      primaryColor: winningInput.primaryColor,
      accentColor: winningInput.accentColor,
      timezone: winningInput.timezone,
      locale: winningInput.locale,
      version: 2,
    },
  );

  const [tenantState] = await admin<
    { version: number; timezone: string; locale: string }[]
  >`
    SELECT version,timezone,locale FROM public.tenants
    WHERE id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(tenantState, {
    version: initialTenant.version + 1,
    timezone: winningInput.timezone,
    locale: winningInput.locale,
  });

  const auditRows = await admin<
    {
      id: string;
      reason: string;
      before: Record<string, unknown>;
      after: Record<string, unknown>;
      sequence: string;
      previous_hash: string;
      event_hash: string;
    }[]
  >`
    SELECT id,reason,before,after,sequence,previous_hash,event_hash
    FROM public.audit_events
    WHERE tenant_id=${fixture.tenant}::uuid
      AND action='tenant.settings.update'
  `;
  assert.equal(auditRows.length, 1, "CAS loser emitted an audit event");
  const audit = auditRows[0];
  assert(audit, "settings audit event is missing");
  assert([firstAuditID, secondAuditID].includes(audit.id));
  assert.equal(audit.reason, winningInput.reason);
  assert.equal(audit.before["version"], 1);
  assert.equal(audit.after["version"], 2);
  assert.equal(audit.after["brandName"], winningInput.brandName);
  assert.match(audit.previous_hash, /^[0-9a-f]{64}$/);
  assert.match(audit.event_hash, /^[0-9a-f]{64}$/);

  await expectSqlState(
    updateSettings(
      first,
      fixture.adminSession,
      fixture.adminUser,
      1,
      firstInput,
    ),
    "40001",
    "a stale settings representation was accepted",
  );

  const brandOnly = await updateSettings(
    first,
    fixture.adminSession,
    fixture.adminUser,
    2,
    {
      ...winningInput,
      brandName: "Safe Response Identity",
      brandMark: "SAFE",
      reason: "Refresh safe text branding without changing regional settings",
    },
  );
  assert.equal(brandOnly.version, 3);
  const [tenantAfterBrandOnly] = await admin<
    { version: number; timezone: string; locale: string }[]
  >`
    SELECT version,timezone,locale FROM public.tenants
    WHERE id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(
    tenantAfterBrandOnly,
    tenantState,
    "a branding-only update churned the independent tenant lifecycle version",
  );
  await expectSqlState(
    updateSettings(first, fixture.adminSession, fixture.adminUser, 3, {
      ...winningInput,
      brandName: brandOnly.brand_name,
      brandMark: brandOnly.brand_mark,
      reason: "Reject a no-op settings update",
    }),
    "22023",
    "a no-op settings update created audit churn",
  );

  await admin`
    UPDATE public.auth_sessions
    SET revoked_at=clock_timestamp(),revoke_reason='runtime proof complete'
    WHERE id=${fixture.adminSession}::uuid
  `;
  await expectSqlState(
    readSettings(
      first,
      fixture.tenant,
      fixture.adminUser,
      fixture.adminSession,
    ),
    "42501",
    "a revoked session read tenant settings",
  );

  const [catalog] = await admin<
    {
      owner: string;
      forcedRls: boolean;
      apiSelect: boolean;
      apiUpdate: boolean;
      apiGet: boolean;
      apiWrite: boolean;
    }[]
  >`
    SELECT pg_get_userbyid(relation.relowner) AS owner,
           relation.relforcerowsecurity AS "forcedRls",
           has_table_privilege('periapsis_api','public.tenant_settings','SELECT') AS "apiSelect",
           has_table_privilege('periapsis_api','public.tenant_settings','UPDATE') AS "apiUpdate",
           has_function_privilege('periapsis_api',
             'app.get_tenant_settings_v1(uuid,text)'::regprocedure,'EXECUTE') AS "apiGet",
           has_function_privilege('periapsis_api',
             'app.update_tenant_settings_v1(uuid,text,integer,text,text,text,text,text,text,text,uuid,uuid,uuid,inet,text)'::regprocedure,
             'EXECUTE') AS "apiWrite"
    FROM pg_catalog.pg_class AS relation
    WHERE relation.oid='public.tenant_settings'::regclass
  `;
  assert.deepEqual(catalog, {
    owner: "periapsis_tenant_settings_owner",
    forcedRls: true,
    apiSelect: false,
    apiUpdate: false,
    apiGet: true,
    apiWrite: true,
  });

  process.stdout.write(
    "tenant settings RLS, authorization, CAS, audit, and revocation checks passed\n",
  );
} finally {
  await Promise.allSettled([admin.end(), first.end(), second.end()]);
}
