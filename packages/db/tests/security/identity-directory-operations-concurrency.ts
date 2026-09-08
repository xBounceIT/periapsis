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
  process.env.PERIAPSIS_IDENTITY_DIRECTORY_OPERATION_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_IDENTITY_DIRECTORY_OPERATION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "0199f300-1000-7000-8000-000000000001",
  foreignTenant: "0199f300-1000-7000-8000-000000000002",
  adminUser: "0199f300-1000-7000-8000-000000000101",
  managerUser: "0199f300-1000-7000-8000-000000000102",
  targetUser: "0199f300-1000-7000-8000-000000000103",
  foreignUser: "0199f300-1000-7000-8000-000000000104",
  adminMembership: "0199f300-1000-7000-8000-000000000201",
  managerMembership: "0199f300-1000-7000-8000-000000000202",
  targetMembership: "0199f300-1000-7000-8000-000000000203",
  foreignMembership: "0199f300-1000-7000-8000-000000000204",
  provider: "0199f300-1000-7000-8000-000000000301",
  foreignProvider: "0199f300-1000-7000-8000-000000000302",
  endpoint: "0199f300-1000-7000-8000-000000000401",
  secret: "0199f300-1000-7000-8000-000000000402",
  group: "0199f300-1000-7000-8000-000000000403",
  targetRole: "0199f300-1000-7000-8000-000000000404",
  managerRole: "0199f300-1000-7000-8000-000000000405",
  managerSource: "0199f300-1000-7000-8000-000000000406",
  managerGrant: "0199f300-1000-7000-8000-000000000407",
  externalIdentity: "0199f300-1000-7000-8000-000000000501",
  subjectAlias: "0199f300-1000-7000-8000-000000000502",
  accessGrant: "0199f300-1000-7000-8000-000000000503",
  normalRun: "0199f300-1000-7000-8000-000000000701",
  activeDryRun: "0199f300-1000-7000-8000-000000000702",
  suspendedDryRun: "0199f300-1000-7000-8000-000000000703",
  disabledUserDryRun: "0199f300-1000-7000-8000-000000000704",
  rateRunA: "0199f300-1000-7000-8000-000000000705",
  rateRunB: "0199f300-1000-7000-8000-000000000706",
  foreignRun: "0199f300-1000-7000-8000-000000000799",
} as const;

const operationCorrelation = new Map<
  string,
  { requestId: string; correlationId: string }
>([
  [
    fixture.normalRun,
    {
      requestId: "0199f300-1000-7000-8000-000000000801",
      correlationId: "0199f300-1000-7000-8000-000000000901",
    },
  ],
  [
    fixture.activeDryRun,
    {
      requestId: "0199f300-1000-7000-8000-000000000802",
      correlationId: "0199f300-1000-7000-8000-000000000902",
    },
  ],
  [
    fixture.suspendedDryRun,
    {
      requestId: "0199f300-1000-7000-8000-000000000803",
      correlationId: "0199f300-1000-7000-8000-000000000903",
    },
  ],
  [
    fixture.disabledUserDryRun,
    {
      requestId: "0199f300-1000-7000-8000-000000000804",
      correlationId: "0199f300-1000-7000-8000-000000000904",
    },
  ],
  [
    fixture.rateRunA,
    {
      requestId: "0199f300-1000-7000-8000-000000000805",
      correlationId: "0199f300-1000-7000-8000-000000000905",
    },
  ],
  [
    fixture.rateRunB,
    {
      requestId: "0199f300-1000-7000-8000-000000000806",
      correlationId: "0199f300-1000-7000-8000-000000000906",
    },
  ],
  [
    fixture.foreignRun,
    {
      requestId: "0199f300-1000-7000-8000-000000000807",
      correlationId: "0199f300-1000-7000-8000-000000000907",
    },
  ],
]);

type NetworkSnapshot = {
  operation_run_id: string;
  provider_id: string;
  bind_secret_ciphertext: Buffer;
  bind_secret_nonce: Buffer;
  bind_secret_key_version: number;
  binding_id: string | null;
  rule_set_revision: string | null;
  authorization_revision: string | null;
  mapping_revisions: unknown[];
};

type Completion = {
  operation_run_id: string;
  outcome: string;
  category: string;
  endpoint_priority: number | null;
  matched_entry_count: number;
  truncated: boolean;
  stale: boolean;
};

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

const admin = postgres(databaseUrl, { max: 8, onnotice: () => undefined });

async function setApiContext(
  transaction: postgres.TransactionSql,
  userId: string = fixture.adminUser,
  tenantId: string = fixture.tenant,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', ${userId}, true)
  `;
}

function correlationFor(runId: string): {
  requestId: string;
  correlationId: string;
} {
  const correlation = operationCorrelation.get(runId);
  assert(correlation, `missing operation correlation for ${runId}`);
  return correlation;
}

async function beginAdministrativeOperation(
  runId: string,
  kind: "search_user" | "filter_user" | "filter_group",
  providerId: string = fixture.provider,
): Promise<NetworkSnapshot> {
  const correlation = correlationFor(runId);
  const rows = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<NetworkSnapshot[]>`
      SELECT * FROM app.begin_tenant_ldap_administrative_search_v1(
        ${runId}::uuid, ${providerId}::uuid,
        ${kind}::public.ldap_directory_operation_kind,
        'bounded administrative directory operation', uuidv7(),
        ${correlation.requestId}::uuid, ${correlation.correlationId}::uuid,
        '192.0.2.110'::inet, 'Periapsis D4 security proof', 'totp'
      )
    `;
  });
  const row = rows[0];
  assert(row, "administrative begin returned no snapshot");
  return row;
}

async function beginDryRun(
  runId: string,
  bindingId: string,
  disabledMappingIds: string[],
): Promise<NetworkSnapshot> {
  const correlation = correlationFor(runId);
  const rows = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<NetworkSnapshot[]>`
      SELECT * FROM app.begin_tenant_ldap_mapping_dry_run_v1(
        ${runId}::uuid, ${bindingId}::uuid,
        ${disabledMappingIds}::uuid[],
        'bounded mapping dry-run proof', uuidv7(),
        ${correlation.requestId}::uuid, ${correlation.correlationId}::uuid,
        '192.0.2.110'::inet, 'Periapsis D4 security proof', 'totp'
      )
    `;
  });
  const row = rows[0];
  assert(row, "dry-run begin returned no snapshot");
  return row;
}

async function completeOperation(
  runId: string,
  matchedEntryCount: number,
): Promise<Completion> {
  const correlation = correlationFor(runId);
  const rows = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<Completion[]>`
      SELECT * FROM app.complete_tenant_ldap_directory_operation_v1(
        ${runId}::uuid, 'success', 'success', 1, 25,
        ${matchedEntryCount}, false, uuidv7(),
        ${correlation.requestId}::uuid, ${correlation.correlationId}::uuid,
        '192.0.2.110'::inet, 'Periapsis D4 security proof', 'totp'
      )
    `;
  });
  const row = rows[0];
  assert(row, "directory completion returned no result");
  return row;
}

try {
  const [compatibility] = await admin<
    {
      applied_count: string;
      latest_created_at: string;
      latest_hash: string;
      migration_fingerprint: string;
    }[]
  >`SELECT applied_count::text, latest_created_at::text, latest_hash,
           migration_fingerprint
    FROM app.schema_compatibility_v59()`;
  assert.equal(compatibility?.applied_count, String(expectedMigrationCount));
  assert.equal(
    compatibility.latest_created_at,
    String(expectedMigrationCreatedAt),
  );
  assert.equal(compatibility.latest_hash, expectedMigrationHash);
  assert.equal(
    compatibility.migration_fingerprint,
    expectedMigrationFingerprint,
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, 'directory-operation-proof', 'Directory operation proof'),
        (${fixture.foreignTenant}::uuid, 'directory-operation-foreign', 'Directory operation foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES
        (${fixture.adminUser}::uuid, 'directory.admin@example.invalid', 'Directory admin'),
        (${fixture.managerUser}::uuid, NULL, 'Mutation manager'),
        (${fixture.targetUser}::uuid, NULL, 'Federated target'),
        (${fixture.foreignUser}::uuid, 'directory.foreign@example.invalid', 'Foreign admin')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.managerMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.managerUser}::uuid, 'analyst', 'active'),
        (${fixture.targetMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.targetUser}::uuid, 'analyst', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
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
      ) VALUES
        (1, decode(repeat('11', 32), 'hex'), false),
        (2, decode(repeat('22', 32), 'hex'), true)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES
        (${fixture.provider}::uuid, ${fixture.tenant}::uuid,
         'bounded_directory', 'Bounded directory', 'D4 security proof.',
         'ldap', true, ${fixture.adminMembership}::uuid,
         ${fixture.adminMembership}::uuid),
        (${fixture.foreignProvider}::uuid, ${fixture.foreignTenant}::uuid,
         'foreign_directory', 'Foreign directory', 'Cross-tenant proof.',
         'ldap', true, ${fixture.foreignMembership}::uuid,
         ${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_configs (
        tenant_id, provider_id, template, bind_dn, user_base_dn,
        group_base_dn, user_search_filter, first_name_attribute,
        last_name_attribute, display_name_attribute, username_attribute,
        email_attribute, immutable_subject_attribute,
        immutable_subject_format, group_membership_attribute, jit_mode,
        no_match_policy, updated_by_membership_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.provider}::uuid,
        'active_directory', 'cn=svc,dc=example,dc=invalid',
        'ou=users,dc=example,dc=invalid',
        'ou=groups,dc=example,dc=invalid',
        '(&(objectClass=user)(sAMAccountName={username}))',
        'givenName', 'sn', 'displayName', 'sAMAccountName', 'mail',
        'objectGUID', 'ad_object_guid', 'memberOf', 'existing_identity',
        'provider_access_only', ${fixture.adminMembership}::uuid
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
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id, tenant_id, key, display_name, description,
        created_by_membership_id
      ) VALUES (
        ${fixture.group}::uuid, ${fixture.tenant}::uuid, 'directory_group',
        'Directory group', '', ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description,
        created_by_membership_id
      ) VALUES
        (${fixture.targetRole}::uuid, ${fixture.tenant}::uuid,
         'directory_target', 'Directory target', '',
         ${fixture.adminMembership}::uuid),
        (${fixture.managerRole}::uuid, ${fixture.tenant}::uuid,
         'directory_mutation_manager', 'Directory mutation manager', '',
         ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      )
      SELECT ${fixture.tenant}::uuid, ${fixture.managerRole}::uuid,
             permission.id, 'tenant', ${fixture.adminMembership}::uuid
      FROM public.tenant_permissions AS permission
      WHERE permission.key IN (
        'identity_provider.manage', 'identity_mapping.manage', 'role.grant'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id, tenant_id, kind, key, authoritative, protected
      ) VALUES (
        ${fixture.managerSource}::uuid, ${fixture.tenant}::uuid, 'manual',
        'manual:directory_mutation_manager', false, false
      )
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      ) VALUES (
        ${fixture.managerGrant}::uuid, ${fixture.tenant}::uuid,
        ${fixture.managerMembership}::uuid, ${fixture.managerRole}::uuid,
        ${fixture.managerSource}::uuid, ${fixture.adminMembership}::uuid,
        'mutation projection proof'
      )
    `;
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      await transaction`
        SELECT count(*) FROM public.tenant_ldap_directory_operation_runs
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      await transaction`
        INSERT INTO public.tenant_ldap_directory_operation_runs (
          id, tenant_id, provider_id, operation_kind, provider_version,
          configuration_version, endpoint_snapshot_digest, bind_secret_id,
          bind_secret_version, bind_secret_key_version,
          bind_secret_algorithm, reason, started_by_membership_id,
          request_id, correlation_id, expires_at
        ) VALUES (
          uuidv7(), ${fixture.tenant}::uuid, ${fixture.provider}::uuid,
          'search_user', 1, 1, decode(repeat('00', 32), 'hex'),
          ${fixture.secret}::uuid, 1, 1, 'aes-256-gcm', 'denied direct DML',
          ${fixture.adminMembership}::uuid, uuidv7(), uuidv7(),
          transaction_timestamp() + interval '1 minute'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const [binding] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        result_resource_id: string;
        result_version: number;
        replayed: boolean;
      }[]
    >`
      SELECT * FROM app.create_tenant_auth_provider_binding_v2(
        decode(repeat('31', 32), 'hex'), ${fixture.provider}::uuid,
        'bounded_ldap', true, 100, uuidv7(), uuidv7(), uuidv7(),
        '192.0.2.110'::inet, 'Periapsis D4 security proof', 'totp'
      )
    `;
  });
  assert(binding, "binding create returned no result");

  const createMapping = async (
    digestByte: string,
    matcherValue: string,
    notes: string,
  ) =>
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      return transaction<
        {
          id: string;
          notes: string;
          enabled: boolean;
          version: number;
          replayed: boolean;
        }[]
      >`
        SELECT * FROM app.create_tenant_ldap_mapping_rule_v2(
          decode(repeat(${digestByte}, 32), 'hex'),
          ${binding.result_resource_id}::uuid, 'exact_cn', ${matcherValue},
          'insensitive', 10, ${fixture.group}::uuid, 'authoritative',
          ARRAY[${fixture.targetRole}::uuid]::uuid[], NULL, NULL,
          ${notes}, 'create bounded mapping proof', uuidv7(), uuidv7(),
          uuidv7(), '192.0.2.110'::inet,
          'Periapsis D4 security proof', 'totp'
        )
      `;
    });

  const [mapping] = await createMapping("32", "soc-blue", "persisted note");
  assert(mapping, "mapping create returned no row");
  assert.equal(mapping.notes, "persisted note");
  assert.equal(mapping.replayed, false);
  const [mappingReplay] = await createMapping(
    "32",
    "soc-blue",
    "persisted note",
  );
  assert(mappingReplay, "mapping replay returned no row");
  assert.equal(mappingReplay.id, mapping.id);
  assert.equal(mappingReplay.notes, "persisted note");
  assert.equal(mappingReplay.replayed, true);

  const [disabledMapping] = await createMapping("33", "soc-green", "");
  assert(disabledMapping, "disabled mapping create returned no row");
  assert.equal(disabledMapping.enabled, false);

  const [updatedVersion] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<{ version: number }[]>`
      SELECT app.update_tenant_ldap_mapping_rule_v1(
        ${mapping.id}::uuid, 1, 'exact_cn', 'soc-blue', 'insensitive', 10,
        ${fixture.group}::uuid, 'authoritative',
        ARRAY[${fixture.targetRole}::uuid]::uuid[], NULL, NULL, true,
        'persisted note', 'enable bounded mapping proof', uuidv7(), uuidv7(),
        uuidv7(), '192.0.2.110'::inet,
        'Periapsis D4 security proof', 'totp'
      ) AS version
    `;
  });
  assert.equal(updatedVersion?.version, 2);

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.managerUser);
      await transaction`
        SELECT * FROM app.get_tenant_auth_provider_binding_v1(
          ${binding.result_resource_id}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [managedBinding] = await admin.begin(async (transaction) => {
    await setApiContext(transaction, fixture.managerUser);
    return transaction<{ id: string; version: number }[]>`
      SELECT * FROM app.get_tenant_auth_provider_binding_mutation_result_v1(
        ${binding.result_resource_id}::uuid
      )
    `;
  });
  assert.equal(managedBinding?.id, binding.result_resource_id);
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.managerUser);
      await transaction`
        SELECT * FROM app.get_tenant_ldap_mapping_rule_v1(${mapping.id}::uuid)
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [managedMapping] = await admin.begin(async (transaction) => {
    await setApiContext(transaction, fixture.managerUser);
    return transaction<{ id: string; notes: string; version: number }[]>`
      SELECT * FROM app.get_tenant_ldap_mapping_rule_mutation_result_v1(
        ${mapping.id}::uuid
      )
    `;
  });
  assert.equal(managedMapping?.notes, "persisted note");
  assert.equal(managedMapping.version, 2);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    const [access] = await transaction<
      { access_epoch_id: string; source_id: string }[]
    >`
      SELECT binding.current_access_epoch_id AS access_epoch_id,
             epoch.source_id
      FROM public.tenant_auth_provider_bindings AS binding
      JOIN public.tenant_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = binding.tenant_id
       AND epoch.id = binding.current_access_epoch_id
      WHERE binding.tenant_id = ${fixture.tenant}::uuid
        AND binding.id = ${binding.result_resource_id}::uuid
    `;
    assert(access, "binding access epoch was not created");
    await transaction`
      INSERT INTO public.tenant_ldap_external_identities (
        id, tenant_id, provider_id, user_id, subject_format,
        subject_ciphertext, subject_nonce, key_version,
        admitted_configuration_version
      ) VALUES (
        ${fixture.externalIdentity}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.targetUser}::uuid,
        'ad_object_guid', decode(repeat('cc', 17), 'hex'),
        decode(repeat('dd', 12), 'hex'), 2, 1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_external_identity_subject_aliases (
        id, tenant_id, provider_id, external_identity_id,
        digest_key_version, subject_digest
      ) VALUES (
        ${fixture.subjectAlias}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.externalIdentity}::uuid,
        2, decode(repeat('ee', 32), 'hex')
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_access_grants (
        id, tenant_id, provider_id, binding_id, access_epoch_id, source_id,
        external_identity_id, membership_id, user_id, configuration_version
      ) VALUES (
        ${fixture.accessGrant}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${binding.result_resource_id}::uuid,
        ${access.access_epoch_id}::uuid, ${access.source_id}::uuid,
        ${fixture.externalIdentity}::uuid, ${fixture.targetMembership}::uuid,
        ${fixture.targetUser}::uuid, 1
      )
    `;
  });

  await assert.rejects(
    beginAdministrativeOperation(
      fixture.foreignRun,
      "search_user",
      fixture.foreignProvider,
    ),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const normalSnapshot = await beginAdministrativeOperation(
    fixture.normalRun,
    "filter_user",
  );
  assert.equal(normalSnapshot.bind_secret_key_version, 1);
  assert.equal(normalSnapshot.bind_secret_nonce.length, 12);
  assert.equal(normalSnapshot.bind_secret_ciphertext.length, 17);
  const normalCompletion = await completeOperation(fixture.normalRun, 3);
  assert.equal(normalCompletion.outcome, "success");
  assert.equal(normalCompletion.category, "success");
  assert.equal(normalCompletion.endpoint_priority, 1);
  assert.equal(normalCompletion.matched_entry_count, 3);
  const [administrativeAudit] = await admin<
    { before: Record<string, unknown> | null }[]
  >`
    SELECT event.before
    FROM public.audit_events AS event
    WHERE event.tenant_id = ${fixture.tenant}::uuid
      AND event.resource_id = ${fixture.normalRun}::uuid
      AND event.action = 'tenant.identity_provider.directory_test_completed'
  `;
  assert(administrativeAudit?.before);
  assert.equal(
    Object.hasOwn(administrativeAudit.before, "authorization_revision"),
    false,
    "administrative completion retained a null authorization revision",
  );

  const activeDryRun = await beginDryRun(
    fixture.activeDryRun,
    binding.result_resource_id,
    [disabledMapping.id],
  );
  assert.equal(activeDryRun.mapping_revisions.length, 2);
  const [activePlan] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        external_identity_exists: boolean;
        user_active: boolean;
        tenant_membership_exists: boolean;
        tenant_membership_active: boolean;
        access_grant_live: boolean;
        rules: unknown[];
      }[]
    >`
      SELECT * FROM app.get_tenant_ldap_dry_run_planning_snapshot_v1(
        ${fixture.activeDryRun}::uuid, ARRAY[2]::integer[],
        ARRAY[decode(repeat('ee', 32), 'hex')]::bytea[]
      )
    `;
  });
  assert(activePlan, "active planner projection returned no row");
  assert.equal(activePlan.external_identity_exists, true);
  assert.equal(activePlan.user_active, true);
  assert.equal(activePlan.tenant_membership_exists, true);
  assert.equal(activePlan.tenant_membership_active, true);
  assert.equal(activePlan.access_grant_live, true);
  assert.equal(activePlan.rules.length, 2);
  await completeOperation(fixture.activeDryRun, 1);
  const [dryRunAudit] = await admin<
    { before: Record<string, unknown> | null }[]
  >`
    SELECT event.before
    FROM public.audit_events AS event
    WHERE event.tenant_id = ${fixture.tenant}::uuid
      AND event.resource_id = ${fixture.activeDryRun}::uuid
      AND event.action = 'tenant.identity_mapping.dry_run_completed'
  `;
  assert(dryRunAudit?.before);
  assert.equal(
    typeof dryRunAudit.before.authorization_revision,
    "number",
    "mapping dry-run completion lost its authorization revision",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.users SET active = false, updated_at = transaction_timestamp()
      WHERE id = ${fixture.targetUser}::uuid
    `;
  });
  await beginDryRun(fixture.disabledUserDryRun, binding.result_resource_id, [
    disabledMapping.id,
  ]);
  const [disabledUserPlan] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        user_active: boolean;
        tenant_membership_active: boolean;
        access_grant_live: boolean;
      }[]
    >`
      SELECT user_active, tenant_membership_active, access_grant_live
      FROM app.get_tenant_ldap_dry_run_planning_snapshot_v1(
        ${fixture.disabledUserDryRun}::uuid, ARRAY[2]::integer[],
        ARRAY[decode(repeat('ee', 32), 'hex')]::bytea[]
      )
    `;
  });
  assert.deepEqual(disabledUserPlan, {
    user_active: false,
    tenant_membership_active: true,
    access_grant_live: false,
  });
  await completeOperation(fixture.disabledUserDryRun, 1);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.users SET active = true, updated_at = transaction_timestamp()
      WHERE id = ${fixture.targetUser}::uuid
    `;
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_memberships
      SET status = 'suspended', updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.targetMembership}::uuid
    `;
  });
  await beginDryRun(fixture.suspendedDryRun, binding.result_resource_id, [
    disabledMapping.id,
  ]);
  const [suspendedPlan] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        user_active: boolean;
        tenant_membership_active: boolean;
        access_grant_live: boolean;
      }[]
    >`
      SELECT user_active, tenant_membership_active, access_grant_live
      FROM app.get_tenant_ldap_dry_run_planning_snapshot_v1(
        ${fixture.suspendedDryRun}::uuid, ARRAY[2]::integer[],
        ARRAY[decode(repeat('ee', 32), 'hex')]::bytea[]
      )
    `;
  });
  assert.deepEqual(suspendedPlan, {
    user_active: true,
    tenant_membership_active: false,
    access_grant_live: false,
  });
  await completeOperation(fixture.suspendedDryRun, 1);

  const competingStarts = await Promise.allSettled([
    beginAdministrativeOperation(fixture.rateRunA, "filter_group"),
    beginAdministrativeOperation(fixture.rateRunB, "filter_group"),
  ]);
  const fulfilled = competingStarts.filter(
    (result): result is PromiseFulfilledResult<NetworkSnapshot> =>
      result.status === "fulfilled",
  );
  const rejected = competingStarts.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.equal(fulfilled.length, 1, "exactly one fifth operation must start");
  assert.equal(rejected.length, 1, "the concurrent sixth operation must fail");
  assertSqlState(rejected[0]!.reason, "53300");
  const activeRateRun = fulfilled[0]!.value.operation_run_id;

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_ldap_provider_secrets
      SET secret_ciphertext = decode(repeat('ab', 17), 'hex'),
          secret_nonce = decode(repeat('bc', 12), 'hex'),
          key_version = 2, rotated_at = transaction_timestamp(),
          version = version + 1, updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND provider_id = ${fixture.provider}::uuid
    `;
  });

  const [transientInventory] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<{ valid: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[2]::integer[],
        ARRAY[decode(repeat('22', 32), 'hex')]::bytea[], 2
      ) AS valid
    `;
  });
  assert.equal(transientInventory?.valid, false);
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      await transaction`
        SELECT app.verify_identity_keyring_v2(
          ARRAY[2]::integer[],
          ARRAY[decode(repeat('22', 32), 'hex')]::bytea[], 2
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const completedRateRun = await completeOperation(activeRateRun, 2);
  assert.equal(completedRateRun.category, "stale_configuration");
  assert.equal(completedRateRun.endpoint_priority, null);
  const [settledInventory] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<{ valid: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[2]::integer[],
        ARRAY[decode(repeat('22', 32), 'hex')]::bytea[], 2
      ) AS valid
    `;
  });
  assert.equal(settledInventory?.valid, true);

  const [auditLeak] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM public.audit_events AS audit
      WHERE audit.tenant_id = ${fixture.tenant}::uuid
        AND to_jsonb(audit)::text ~*
            '(secret_ciphertext|secret_nonce|custom_ca_pem|user_search_filter)'
    `;
  });
  assert.equal(auditLeak?.count, 0);
} finally {
  await admin.end();
}
