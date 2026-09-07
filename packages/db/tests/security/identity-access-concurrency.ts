import assert from "node:assert/strict";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_IDENTITY_ACCESS_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_IDENTITY_ACCESS_TEST_DATABASE_URL must name a fresh migrated PostgreSQL database",
  );
}

const fixture = {
  tenant: "0199f100-1000-7000-8000-000000000001",
  foreignTenant: "0199f100-1000-7000-8000-000000000002",
  adminUser: "0199f100-1000-7000-8000-000000000101",
  limitedUser: "0199f100-1000-7000-8000-000000000102",
  foreignUser: "0199f100-1000-7000-8000-000000000103",
  adminMembership: "0199f100-1000-7000-8000-000000000201",
  limitedMembership: "0199f100-1000-7000-8000-000000000202",
  foreignMembership: "0199f100-1000-7000-8000-000000000203",
  provider: "0199f100-1000-7000-8000-000000000301",
  foreignProvider: "0199f100-1000-7000-8000-000000000302",
  binding: "0199f100-1000-7000-8000-000000000401",
  externalIdentity: "0199f100-1000-7000-8000-000000000501",
  subjectAlias: "0199f100-1000-7000-8000-000000000502",
  accessGrant: "0199f100-1000-7000-8000-000000000503",
  profileContribution: "0199f100-1000-7000-8000-000000000504",
  rejectedContribution: "0199f100-1000-7000-8000-000000000505",
} as const;

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

const admin = postgres(databaseUrl, { max: 4, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

async function setApiContext(
  transaction: postgres.TransactionSql,
  userId: string,
  tenantId: string = fixture.tenant,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', ${userId}, true)
  `;
}

async function updateBinding(
  transaction: postgres.TransactionSql,
  expectedVersion: number,
  enabled: boolean,
): Promise<number> {
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.update_tenant_auth_provider_binding_v1(
      ${fixture.binding}::uuid, ${expectedVersion}, 'security_ldap',
      ${enabled}, 100,
      '0199f100-1000-7000-8000-000000000601'::uuid,
      '0199f100-1000-7000-8000-000000000701'::uuid,
      '192.0.2.80'::inet, 'Periapsis identity-access proof', 'totp'
    ) AS version
  `;
  assert(result, "binding update returned no result");
  return result.version;
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
           app.release_runtime_schema_readiness_v55() AS release_ready
    FROM app.schema_compatibility_v55() AS current_projection
    CROSS JOIN app.schema_compatibility_v8() AS legacy_projection
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

  const [existing] = await admin<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenants
    WHERE id IN (${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid)
       OR slug IN ('identity-access-proof', 'identity-access-foreign-proof')
  `;
  assert.equal(
    existing?.count,
    0,
    "identity-access proof requires a fresh disposable database",
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.tenant}::uuid, 'identity-access-proof', 'Identity access proof'),
        (${fixture.foreignTenant}::uuid, 'identity-access-foreign-proof', 'Foreign identity access proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.adminUser}::uuid, 'identity.access.admin@example.invalid', 'Identity access admin'),
        (${fixture.limitedUser}::uuid, NULL, 'Federated-ready user'),
        (${fixture.foreignUser}::uuid, 'identity.access.foreign@example.invalid', 'Foreign identity admin')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.limitedMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.limitedUser}::uuid, 'analyst', 'active'),
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
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES
        (${fixture.provider}::uuid, ${fixture.tenant}::uuid,
         'security_directory', 'Security directory', 'Identity access proof.',
         'ldap', true, ${fixture.adminMembership}::uuid, ${fixture.adminMembership}::uuid),
        (${fixture.foreignProvider}::uuid, ${fixture.foreignTenant}::uuid,
         'foreign_directory', 'Foreign directory', 'Cross-tenant proof.',
         'ldap', true, ${fixture.foreignMembership}::uuid, ${fixture.foreignMembership}::uuid)
    `;
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`SELECT count(*) FROM public.tenant_auth_provider_bindings`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.limitedUser);
      await transaction`
        SELECT * FROM app.create_tenant_auth_provider_binding_v1(
          ${fixture.binding}::uuid, ${fixture.provider}::uuid,
          'security_ldap', true, 100,
          '0199f100-1000-7000-8000-000000000602'::uuid,
          '0199f100-1000-7000-8000-000000000702'::uuid,
          '192.0.2.80'::inet, 'Periapsis identity-access proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      await transaction`
        SELECT * FROM app.create_tenant_auth_provider_binding_v1(
          ${fixture.binding}::uuid, ${fixture.foreignProvider}::uuid,
          'security_ldap', true, 100,
          '0199f100-1000-7000-8000-000000000603'::uuid,
          '0199f100-1000-7000-8000-000000000703'::uuid,
          '192.0.2.80'::inet, 'Periapsis identity-access proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const [created] = await admin.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return transaction<{ binding_id: string; binding_version: number }[]>`
      SELECT * FROM app.create_tenant_auth_provider_binding_v1(
        ${fixture.binding}::uuid, ${fixture.provider}::uuid,
        'security_ldap', true, 100,
        '0199f100-1000-7000-8000-000000000604'::uuid,
        '0199f100-1000-7000-8000-000000000704'::uuid,
        '192.0.2.80'::inet, 'Periapsis identity-access proof', 'totp'
      )
    `;
  });
  assert.deepEqual(created, {
    binding_id: fixture.binding,
    binding_version: 1,
  });

  const [initialState] = await admin<
    {
      enabled: boolean;
      sequence: number;
      source_kind: string;
      source_retired: boolean;
    }[]
  >`
    SELECT binding.enabled, epoch.sequence, source.kind::text AS source_kind,
           source.retired_at IS NOT NULL AS source_retired
    FROM public.tenant_auth_provider_bindings AS binding
    JOIN public.tenant_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE binding.tenant_id = ${fixture.tenant}::uuid
      AND binding.id = ${fixture.binding}::uuid
  `;
  assert.deepEqual(initialState, {
    enabled: true,
    sequence: 1,
    source_kind: "identity_provider_access",
    source_retired: false,
  });

  const competingUpdates = await Promise.allSettled([
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      return updateBinding(transaction, 1, false);
    }),
    contender.begin(async (transaction) => {
      await setApiContext(transaction, fixture.adminUser);
      return updateBinding(transaction, 1, false);
    }),
  ]);
  const fulfilled = competingUpdates.filter(
    (result): result is PromiseFulfilledResult<number> =>
      result.status === "fulfilled",
  );
  const rejected = competingUpdates.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.deepEqual(
    fulfilled.map((result) => result.value),
    [2],
  );
  assert.equal(rejected.length, 1);
  assertSqlState(rejected[0]!.reason, "40001");

  const [closedFirstEpoch] = await admin<
    { ended: boolean; source_retired: boolean }[]
  >`
    SELECT epoch.ended_at IS NOT NULL AS ended,
           source.retired_at IS NOT NULL AS source_retired
    FROM public.tenant_identity_provider_access_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE epoch.tenant_id = ${fixture.tenant}::uuid
      AND epoch.binding_id = ${fixture.binding}::uuid
      AND epoch.sequence = 1
  `;
  assert.deepEqual(closedFirstEpoch, { ended: true, source_retired: true });

  const reenabledVersion = await admin.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    return updateBinding(transaction, 2, true);
  });
  assert.equal(reenabledVersion, 3);

  const [epochState] = await admin<
    { epoch_count: number; live_sequence: number; distinct_sources: number }[]
  >`
    SELECT count(*)::integer AS epoch_count,
           max(epoch.sequence) FILTER (WHERE epoch.ended_at IS NULL)::integer AS live_sequence,
           count(DISTINCT epoch.source_id)::integer AS distinct_sources
    FROM public.tenant_identity_provider_access_epochs AS epoch
    WHERE epoch.tenant_id = ${fixture.tenant}::uuid
      AND epoch.binding_id = ${fixture.binding}::uuid
  `;
  assert.deepEqual(epochState, {
    epoch_count: 2,
    live_sequence: 2,
    distinct_sources: 2,
  });

  const [initialKeyringEvidence] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    return transaction<{ ready: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[1]::integer[],
        ARRAY[decode(repeat('7a', 32), 'hex')]::bytea[],
        1
      ) AS ready
    `;
  });
  assert.equal(initialKeyringEvidence?.ready, true);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_ldap_external_identities (
        id, tenant_id, provider_id, user_id, subject_format,
        subject_ciphertext, subject_nonce, key_version,
        admitted_configuration_version
      ) VALUES (
        ${fixture.externalIdentity}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.limitedUser}::uuid,
        'ad_object_guid', decode(repeat('a1', 17), 'hex'),
        decode(repeat('b2', 12), 'hex'), 1, 1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_external_identity_subject_aliases (
        id, tenant_id, provider_id, external_identity_id,
        digest_key_version, subject_digest
      ) VALUES (
        ${fixture.subjectAlias}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, ${fixture.externalIdentity}::uuid,
        1, decode(repeat('c3', 32), 'hex')
      )
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_access_grants (
        id, tenant_id, provider_id, binding_id, access_epoch_id, source_id,
        external_identity_id, membership_id, user_id, configuration_version
      )
      SELECT ${fixture.accessGrant}::uuid, binding.tenant_id,
             binding.provider_id, binding.id, epoch.id, epoch.source_id,
             ${fixture.externalIdentity}::uuid,
             ${fixture.limitedMembership}::uuid,
             ${fixture.limitedUser}::uuid, 1
      FROM public.tenant_auth_provider_bindings AS binding
      JOIN public.tenant_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = binding.tenant_id
       AND epoch.id = binding.current_access_epoch_id
      WHERE binding.tenant_id = ${fixture.tenant}::uuid
        AND binding.id = ${fixture.binding}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_ldap_provider_profile_contributions (
        id, tenant_id, access_grant_id, display_name, username, email,
        configuration_version
      ) VALUES (
        ${fixture.profileContribution}::uuid, ${fixture.tenant}::uuid,
        ${fixture.accessGrant}::uuid, 'Directory display',
        'directory-user', 'directory.user@example.invalid', 1
      )
    `;
    await transaction`
      SELECT app.private_materialize_tenant_user_profile_v1(
        ${fixture.tenant}::uuid, ${fixture.limitedMembership}::uuid
      )
    `;
  });

  const [providerProfile] = await admin<
    { display_name: string; username: string; email: string }[]
  >`
    SELECT display_name, username, email
    FROM public.tenant_user_profiles
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND membership_id = ${fixture.limitedMembership}::uuid
  `;
  assert.deepEqual(providerProfile, {
    display_name: "Directory display",
    username: "directory-user",
    email: "directory.user@example.invalid",
  });

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_user_manual_profile_overrides (
        tenant_id, membership_id, user_id, display_name, reason,
        updated_by_membership_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.limitedMembership}::uuid,
        ${fixture.limitedUser}::uuid, 'Manual display',
        'Identity access precedence proof.', ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.private_materialize_tenant_user_profile_v1(
        ${fixture.tenant}::uuid, ${fixture.limitedMembership}::uuid
      )
    `;
  });

  const [manualFirstProfile] = await admin<
    { display_name: string; username: string; email: string }[]
  >`
    SELECT display_name, username, email
    FROM public.tenant_user_profiles
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND membership_id = ${fixture.limitedMembership}::uuid
  `;
  assert.deepEqual(manualFirstProfile, {
    display_name: "Manual display",
    username: "directory-user",
    email: "directory.user@example.invalid",
  });

  const [completeKeyringEvidence] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    return transaction<{ ready: boolean }[]>`
      SELECT app.verify_identity_keyring_v3(
        ARRAY[1]::integer[],
        ARRAY[decode(repeat('7a', 32), 'hex')]::bytea[],
        1
      ) AS ready
    `;
  });
  assert.equal(completeKeyringEvidence?.ready, true);

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_ldap_external_identities
        SET retired_at = transaction_timestamp(),
            retired_by_membership_id = ${fixture.adminMembership}::uuid,
            retire_reason = 'Premature retirement proof.',
            version = version + 1,
            updated_at = transaction_timestamp()
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.externalIdentity}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_auth_providers
        SET enabled = false
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${fixture.provider}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const archivedVersion = await admin.begin(async (transaction) => {
    await setApiContext(transaction, fixture.adminUser);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.archive_tenant_auth_provider_binding_v1(
        ${fixture.binding}::uuid, 3, 'Identity access proof complete.',
        '0199f100-1000-7000-8000-000000000605'::uuid,
        '0199f100-1000-7000-8000-000000000705'::uuid,
        '192.0.2.80'::inet, 'Periapsis identity-access proof', 'totp'
      ) AS version
    `;
    assert(result, "binding archive returned no result");
    return result.version;
  });
  assert.equal(archivedVersion, 4);

  const [closedProviderProjection] = await admin<
    {
      grant_ended: boolean;
      contribution_retired: boolean;
      display_name: string;
      username: string | null;
      profile_email: string | null;
      global_display_name: string;
      global_email: string | null;
    }[]
  >`
    SELECT access_grant.ended_at IS NOT NULL AS grant_ended,
           contribution.retired_at IS NOT NULL AS contribution_retired,
           profile.display_name, profile.username,
           profile.email AS profile_email,
           admitted_user.display_name AS global_display_name,
           admitted_user.email AS global_email
    FROM public.tenant_ldap_provider_access_grants AS access_grant
    JOIN public.tenant_ldap_provider_profile_contributions AS contribution
      ON contribution.tenant_id = access_grant.tenant_id
     AND contribution.access_grant_id = access_grant.id
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id = access_grant.tenant_id
     AND profile.membership_id = access_grant.membership_id
    JOIN public.users AS admitted_user ON admitted_user.id = access_grant.user_id
    WHERE access_grant.tenant_id = ${fixture.tenant}::uuid
      AND access_grant.id = ${fixture.accessGrant}::uuid
  `;
  assert.deepEqual(closedProviderProjection, {
    grant_ended: true,
    contribution_retired: true,
    display_name: "Manual display",
    username: null,
    profile_email: null,
    global_display_name: "Federated-ready user",
    global_email: null,
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.tenant_ldap_provider_profile_contributions (
          id, tenant_id, access_grant_id, display_name, configuration_version
        ) VALUES (
          ${fixture.rejectedContribution}::uuid, ${fixture.tenant}::uuid,
          ${fixture.accessGrant}::uuid, 'Closed grant contribution', 1
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23514"),
  );

  const [finalState] = await admin<
    {
      enabled: boolean;
      archived: boolean;
      current_epoch: string | null;
      live_epochs: number;
      live_sources: number;
      membership_status: string;
      audit_count: number;
    }[]
  >`
    SELECT binding.enabled,
           binding.archived_at IS NOT NULL AS archived,
           binding.current_access_epoch_id::text AS current_epoch,
           (SELECT count(*)::integer
            FROM public.tenant_identity_provider_access_epochs AS epoch
            WHERE epoch.tenant_id = binding.tenant_id
              AND epoch.binding_id = binding.id
              AND epoch.ended_at IS NULL) AS live_epochs,
           (SELECT count(*)::integer
            FROM public.tenant_identity_provider_access_epochs AS epoch
            JOIN public.tenant_authorization_sources AS source
              ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
            WHERE epoch.tenant_id = binding.tenant_id
              AND epoch.binding_id = binding.id
              AND source.retired_at IS NULL) AS live_sources,
           membership.status::text AS membership_status,
           (SELECT count(*)::integer
            FROM public.audit_events AS audit
            WHERE audit.tenant_id = binding.tenant_id
              AND audit.resource_type = 'identity_provider_binding'
              AND audit.resource_id = binding.id) AS audit_count
    FROM public.tenant_auth_provider_bindings AS binding
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = binding.tenant_id
     AND membership.id = ${fixture.limitedMembership}::uuid
    WHERE binding.tenant_id = ${fixture.tenant}::uuid
      AND binding.id = ${fixture.binding}::uuid
  `;
  assert.deepEqual(finalState, {
    enabled: false,
    archived: true,
    current_epoch: null,
    live_epochs: 0,
    live_sources: 0,
    membership_status: "active",
    audit_count: 4,
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_identity_provider_access_epochs
        SET ended_at = NULL, ended_by_membership_id = NULL,
            end_reason = NULL, version = 1
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND binding_id = ${fixture.binding}::uuid
          AND sequence = 1
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const [foreignProjection] = await admin.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignUser,
      fixture.foreignTenant,
    );
    return transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM app.get_tenant_auth_provider_binding_v1(${fixture.binding}::uuid)
    `;
  });
  assert.equal(foreignProjection?.count, 0);
} finally {
  await Promise.allSettled([admin.end(), contender.end()]);
}
