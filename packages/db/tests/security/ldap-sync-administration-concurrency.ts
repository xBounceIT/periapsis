import assert from "node:assert/strict";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_LDAP_SYNC_ADMINISTRATION_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_LDAP_SYNC_ADMINISTRATION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a05600-1000-7000-8000-000000000001",
  foreignTenant: "01a05600-1000-7000-8000-000000000002",
  adminUser: "01a05600-1000-7000-8000-000000000101",
  analystUser: "01a05600-1000-7000-8000-000000000102",
  foreignUser: "01a05600-1000-7000-8000-000000000103",
  adminMembership: "01a05600-1000-7000-8000-000000000201",
  analystMembership: "01a05600-1000-7000-8000-000000000202",
  foreignMembership: "01a05600-1000-7000-8000-000000000203",
  provider: "01a05600-1000-7000-8000-000000000301",
  endpoint: "01a05600-1000-7000-8000-000000000302",
  secret: "01a05600-1000-7000-8000-000000000303",
  bindingProposal: "01a05600-1000-7000-8000-000000000304",
  firstRun: "01a05600-1000-7000-8000-000000000401",
  replayProposal: "01a05600-1000-7000-8000-000000000402",
  staleRun: "01a05600-1000-7000-8000-000000000403",
  claim: "01a05600-1000-7000-8000-000000000404",
} as const;

const admin = postgres(databaseUrl, { max: 8, onnotice: () => undefined });

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

async function setAPIContext(
  transaction: postgres.TransactionSql,
  tenantID: string = fixture.tenant,
  userID: string = fixture.adminUser,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantID}, true),
           set_config('app.user_id', ${userID}, true)
  `;
}

async function beginManual(input: {
  key: Buffer;
  request: Buffer;
  runID: string;
  bindingID: string;
  bindingVersion: number;
  reason?: string;
}): Promise<{ sync_run_id: string; replayed: boolean }[]> {
  return admin.begin(async (transaction) => {
    await setAPIContext(transaction);
    return transaction<{ sync_run_id: string; replayed: boolean }[]>`
      SELECT * FROM app.begin_tenant_ldap_manual_sync_run_v2(
        ${input.key}, ${input.request}, ${input.runID}::uuid,
        ${input.bindingID}::uuid, ${input.bindingVersion},
        ${input.reason ?? "bounded manual synchronization proof"},
        uuidv7(), uuidv7(), uuidv7(), '192.0.2.90'::inet,
        'Periapsis LDAP administration security proof', 'totp'
      )
    `;
  });
}

try {
  const [compatibility] = await admin<
    {
      current_count: string;
      current_latest: string;
      current_hash: string;
      current_fingerprint: string;
      legacy_count: string;
      legacy_latest: string;
      legacy_hash: string;
      legacy_fingerprint: string;
      release_ready: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::text AS current_count,
           current_projection.latest_created_at::text AS current_latest,
           current_projection.latest_hash AS current_hash,
           current_projection.migration_fingerprint AS current_fingerprint,
           legacy_projection.applied_count::text AS legacy_count,
           legacy_projection.latest_created_at::text AS legacy_latest,
           legacy_projection.latest_hash AS legacy_hash,
           legacy_projection.migration_fingerprint AS legacy_fingerprint,
           app.release_runtime_schema_readiness_v56() AS release_ready
    FROM app.schema_compatibility_v56() AS current_projection
    CROSS JOIN app.schema_compatibility_v15() AS legacy_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: String(expectedMigrationCount),
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    legacy_count: "0",
    legacy_latest: "0",
    legacy_hash: "UNSUPPORTED",
    legacy_fingerprint: "UNSUPPORTED",
    release_ready: true,
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, 'ldap-administration-proof', 'LDAP administration proof'),
        (${fixture.foreignTenant}::uuid, 'ldap-administration-foreign', 'LDAP administration foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES
        (${fixture.adminUser}::uuid, 'ldap-admin@example.invalid', 'LDAP admin'),
        (${fixture.analystUser}::uuid, 'ldap-analyst@example.invalid', 'LDAP analyst'),
        (${fixture.foreignUser}::uuid, 'ldap-foreign@example.invalid', 'LDAP foreign admin')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.analystMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.analystUser}::uuid, 'analyst', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES (1, decode(repeat('11', 32), 'hex'), true)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES (
        ${fixture.provider}::uuid, ${fixture.tenant}::uuid,
        'administration_directory', 'Administration directory',
        'LDAP administration security proof.', 'ldap', true,
        ${fixture.adminMembership}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_configs (
        tenant_id, provider_id, template, bind_dn, user_base_dn,
        group_base_dn, user_search_filter, first_name_attribute,
        last_name_attribute, display_name_attribute, username_attribute,
        email_attribute, immutable_subject_attribute,
        immutable_subject_format, group_membership_attribute, jit_mode,
        no_match_policy, sync_interval_seconds, updated_by_membership_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.provider}::uuid,
        'active_directory', 'cn=svc,dc=example,dc=invalid',
        'ou=users,dc=example,dc=invalid',
        'ou=groups,dc=example,dc=invalid',
        '(&(objectClass=user)(sAMAccountName={username}))',
        'givenName', 'sn', 'displayName', 'sAMAccountName', 'mail',
        'objectGUID', 'ad_object_guid', 'memberOf', 'existing_identity',
        'provider_access_only', 300, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_urls (
        id, tenant_id, provider_id, priority, host, port, transport,
        tls_server_name
      ) VALUES (
        ${fixture.endpoint}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, 1, 'ldap.example.invalid', 636,
        'ldaps', 'ldap.example.invalid'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_secrets (
        id, tenant_id, provider_id, secret_ciphertext, secret_nonce,
        key_version, rotated_by_membership_id
      ) VALUES (
        ${fixture.secret}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, decode(repeat('aa', 17), 'hex'),
        decode(repeat('bb', 12), 'hex'), 1,
        ${fixture.adminMembership}::uuid
      )
    `;
  });

  const [binding] = await admin.begin(async (transaction) => {
    await setAPIContext(transaction);
    return transaction<
      {
        result_resource_id: string;
        result_version: number;
        replayed: boolean;
      }[]
    >`
      SELECT * FROM app.create_tenant_auth_provider_binding_v2(
        decode(repeat('31', 32), 'hex'), ${fixture.provider}::uuid,
        'administration_ldap', true, 300, ${fixture.bindingProposal}::uuid,
        uuidv7(), uuidv7(), '192.0.2.90'::inet,
        'Periapsis LDAP administration security proof', 'totp'
      )
    `;
  });
  assert(binding, "binding creation returned no row");
  assert.equal(binding.replayed, false);

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setAPIContext(transaction);
      await transaction`SELECT count(*) FROM public.tenant_ldap_sync_runs`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const [initialStatus] = await admin.begin(async (transaction) => {
    await setAPIContext(transaction);
    return transaction<{ binding_id: string; schedule_state: string }[]>`
      SELECT * FROM app.get_tenant_ldap_sync_status_v1(
        ${binding.result_resource_id}::uuid
      )
    `;
  });
  assert.equal(initialStatus?.binding_id, binding.result_resource_id);
  assert.equal(initialStatus.schedule_state, "idle");

  const key = Buffer.alloc(32, 0x41);
  const request = Buffer.alloc(32, 0x42);
  const concurrent = await Promise.all([
    beginManual({
      key,
      request,
      runID: fixture.firstRun,
      bindingID: binding.result_resource_id,
      bindingVersion: binding.result_version,
    }),
    beginManual({
      key,
      request,
      runID: fixture.replayProposal,
      bindingID: binding.result_resource_id,
      bindingVersion: binding.result_version,
    }),
  ]);
  const starts = concurrent.flat();
  assert.equal(starts.length, 2);
  assert.equal(new Set(starts.map((row) => row.sync_run_id)).size, 1);
  assert.deepEqual(
    starts
      .map((row) => row.replayed)
      .toSorted((left, right) => Number(left) - Number(right)),
    [false, true],
  );
  assert.equal(starts[0]?.sync_run_id, fixture.firstRun);

  const runs = await admin.begin(async (transaction) => {
    await setAPIContext(transaction);
    return transaction<{ id: string; state: string; manual_reason: string }[]>`
      SELECT * FROM app.list_tenant_ldap_sync_runs_v1(
        ${binding.result_resource_id}::uuid, NULL, 101
      )
    `;
  });
  assert.equal(runs.length, 1);
  assert.equal(runs[0]?.id, fixture.firstRun);
  assert.equal(runs[0]?.state, "queued");
  assert.equal(runs[0]?.manual_reason, "bounded manual synchronization proof");

  await assert.rejects(
    beginManual({
      key,
      request: Buffer.alloc(32, 0x43),
      runID: fixture.replayProposal,
      bindingID: binding.result_resource_id,
      bindingVersion: binding.result_version,
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  await assert.rejects(
    beginManual({
      key: Buffer.alloc(32, 0x44),
      request: Buffer.alloc(32, 0x45),
      runID: fixture.staleRun,
      bindingID: binding.result_resource_id,
      bindingVersion: binding.result_version + 1,
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setAPIContext(transaction, fixture.tenant, fixture.analystUser);
      await transaction`
        SELECT * FROM app.get_tenant_ldap_sync_status_v1(
          ${binding.result_resource_id}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setAPIContext(
        transaction,
        fixture.foreignTenant,
        fixture.foreignUser,
      );
      await transaction`
        SELECT * FROM app.get_tenant_ldap_sync_run_v1(
          ${binding.result_resource_id}::uuid, ${fixture.firstRun}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const [claim] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.foreignTenant}, true),
             set_config('app.user_id', '', true)
    `;
    return transaction<{ sync_run_id: string; run_version: number }[]>`
      SELECT * FROM app.claim_next_tenant_ldap_sync_run_v2(
        ${fixture.claim}::uuid, decode(repeat('51', 32), 'hex'), 30,
        'Periapsis LDAP administration security proof'
      )
    `;
  });
  assert.equal(claim?.sync_run_id, fixture.firstRun);
  assert.equal(claim.run_version, 2);

  const [responseLostReplay] = await beginManual({
    key,
    request,
    runID: fixture.replayProposal,
    bindingID: binding.result_resource_id,
    bindingVersion: binding.result_version,
  });
  assert.equal(responseLostReplay?.sync_run_id, fixture.firstRun);
  assert.equal(responseLostReplay.replayed, true);

  const [current] = await admin.begin(async (transaction) => {
    await setAPIContext(transaction);
    return transaction<{ id: string; state: string; version: number }[]>`
      SELECT * FROM app.get_tenant_ldap_sync_run_v1(
        ${binding.result_resource_id}::uuid, ${fixture.firstRun}::uuid
      )
    `;
  });
  assert.equal(current?.state, "enumerating");
  assert.equal(current.version, 2);

  const [readiness] = await admin<
    {
      legacy_ready: boolean;
      api_v1: boolean;
      api_v2: boolean;
      public_v2: boolean;
    }[]
  >`
    SELECT app.ldap_administration_schema_readiness_v1() AS legacy_ready,
           has_function_privilege(
             'periapsis_api',
             'app.begin_tenant_ldap_manual_sync_run_v1(uuid,uuid,text,uuid,uuid,uuid,inet,text,text)',
             'EXECUTE'
           ) AS api_v1,
           has_function_privilege(
             'periapsis_api',
             'app.begin_tenant_ldap_manual_sync_run_v2(bytea,bytea,uuid,uuid,integer,text,uuid,uuid,uuid,inet,text,text)',
             'EXECUTE'
           ) AS api_v2,
           EXISTS (
             SELECT 1
             FROM pg_proc AS procedure
             CROSS JOIN LATERAL aclexplode(
               coalesce(procedure.proacl, acldefault('f', procedure.proowner))
             ) AS privilege
             WHERE procedure.oid =
               'app.begin_tenant_ldap_manual_sync_run_v2(bytea,bytea,uuid,uuid,integer,text,uuid,uuid,uuid,inet,text,text)'::regprocedure
               AND privilege.grantee = 0
               AND privilege.privilege_type = 'EXECUTE'
           ) AS public_v2
  `;
  assert.deepEqual(readiness, {
    legacy_ready: false,
    api_v1: false,
    api_v2: true,
    public_v2: false,
  });
} finally {
  await admin.end();
}
