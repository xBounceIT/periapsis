import assert from "node:assert/strict";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_IDENTITY_MAPPING_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_IDENTITY_MAPPING_TEST_DATABASE_URL must name a fresh migrated PostgreSQL database",
  );
}

const fixture = {
  tenant: "0199f200-1000-7000-8000-000000000001",
  foreignTenant: "0199f200-1000-7000-8000-000000000002",
  adminUser: "0199f200-1000-7000-8000-000000000101",
  targetUser: "0199f200-1000-7000-8000-000000000102",
  foreignUser: "0199f200-1000-7000-8000-000000000103",
  adminMembership: "0199f200-1000-7000-8000-000000000201",
  targetMembership: "0199f200-1000-7000-8000-000000000202",
  foreignMembership: "0199f200-1000-7000-8000-000000000203",
  provider: "0199f200-1000-7000-8000-000000000301",
  foreignProvider: "0199f200-1000-7000-8000-000000000302",
  group: "0199f200-1000-7000-8000-000000000401",
  replacementGroup: "0199f200-1000-7000-8000-000000000402",
  foreignGroup: "0199f200-1000-7000-8000-000000000403",
  role: "0199f200-1000-7000-8000-000000000501",
  replacementRole: "0199f200-1000-7000-8000-000000000502",
  platformRole: "0199f200-1000-7000-8000-000000000503",
  team: "0199f200-1000-7000-8000-000000000601",
  replacementTeam: "0199f200-1000-7000-8000-000000000602",
  assignment: "0199f200-1000-7000-8000-000000000701",
  replacementAssignment: "0199f200-1000-7000-8000-000000000702",
  badRule: "0199f200-1000-7000-8000-000000000801",
  groupEdge: "0199f200-1000-7000-8000-000000000811",
  roleEdge: "0199f200-1000-7000-8000-000000000812",
  rosterEdge: "0199f200-1000-7000-8000-000000000813",
} as const;

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

const admin = postgres(databaseUrl, { max: 5, onnotice: () => undefined });
const contender = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

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

async function updateMapping(
  transaction: postgres.TransactionSql,
  mappingId: string,
  expectedVersion: number,
  notes: string,
): Promise<number> {
  const [result] = await transaction<{ version: number }[]>`
    SELECT app.update_tenant_ldap_mapping_rule_v1(
      ${mappingId}::uuid, ${expectedVersion}, 'exact_cn', 'ir-team',
      'insensitive', 20, ${fixture.replacementGroup}::uuid,
      'authoritative', ARRAY[${fixture.replacementRole}::uuid]::uuid[],
      ${fixture.replacementTeam}::uuid,
      ${fixture.replacementAssignment}::uuid, true, ${notes},
      'concurrent replacement check', uuidv7(), uuidv7(), uuidv7(),
      '192.0.2.91'::inet, 'Periapsis mapping proof', 'totp'
    ) AS version
  `;
  assert(result, "mapping update returned no row");
  return result.version;
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
    FROM app.schema_compatibility_v57()`;
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
        (${fixture.tenant}::uuid, 'identity-mapping-proof', 'Identity mapping proof'),
        (${fixture.foreignTenant}::uuid, 'identity-mapping-foreign-proof', 'Foreign mapping proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES
        (${fixture.adminUser}::uuid, 'mapping.admin@example.invalid', 'Mapping admin'),
        (${fixture.targetUser}::uuid, NULL, 'Mapping target'),
        (${fixture.foreignUser}::uuid, 'mapping.foreign@example.invalid', 'Foreign admin')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid, ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
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
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES
        (${fixture.provider}::uuid, ${fixture.tenant}::uuid, 'mapping_directory',
         'Mapping directory', 'Mapping proof.', 'ldap', true,
         ${fixture.adminMembership}::uuid, ${fixture.adminMembership}::uuid),
        (${fixture.foreignProvider}::uuid, ${fixture.foreignTenant}::uuid, 'foreign_mapping_directory',
         'Foreign mapping directory', 'Foreign proof.', 'ldap', true,
         ${fixture.foreignMembership}::uuid, ${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_security_groups (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES
        (${fixture.group}::uuid, ${fixture.tenant}::uuid, 'mapped_group', 'Mapped group', '', ${fixture.adminMembership}::uuid),
        (${fixture.replacementGroup}::uuid, ${fixture.tenant}::uuid, 'replacement_group', 'Replacement group', '', ${fixture.adminMembership}::uuid),
        (${fixture.foreignGroup}::uuid, ${fixture.foreignTenant}::uuid, 'foreign_group', 'Foreign group', '', ${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description, created_by_membership_id
      ) VALUES
        (${fixture.role}::uuid, ${fixture.tenant}::uuid, 'mapped_role', 'Mapped role', '', ${fixture.adminMembership}::uuid),
        (${fixture.replacementRole}::uuid, ${fixture.tenant}::uuid, 'replacement_role', 'Replacement role', '', ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.platform_roles (id, key, display_name)
      VALUES (${fixture.platformRole}::uuid, 'mapping_platform_role', 'Mapping platform role')
    `;
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES
        (${fixture.team}::uuid, 'mapping_team', 'Mapping team', '', ${fixture.adminUser}::uuid),
        (${fixture.replacementTeam}::uuid, 'replacement_mapping_team', 'Replacement mapping team', '', ${fixture.adminUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason
      ) VALUES
        (${fixture.assignment}::uuid, ${fixture.tenant}::uuid, ${fixture.team}::uuid,
         ${fixture.adminMembership}::uuid, 'mapping proof'),
        (${fixture.replacementAssignment}::uuid, ${fixture.tenant}::uuid,
         ${fixture.replacementTeam}::uuid, ${fixture.adminMembership}::uuid,
         'replacement mapping proof')
    `;
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      await transaction`SELECT count(*) FROM public.tenant_ldap_mapping_rules`;
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
        decode(repeat('11', 32), 'hex'), ${fixture.provider}::uuid,
        'mapping_ldap', true, 100,
        '0199f200-1000-7000-8000-000000000901'::uuid,
        '0199f200-1000-7000-8000-000000000902'::uuid,
        '0199f200-1000-7000-8000-000000000903'::uuid,
        '192.0.2.91'::inet, 'Periapsis mapping proof', 'totp'
      )
    `;
  });
  assert(binding);
  assert.equal(binding.result_version, 1);
  assert.equal(binding.replayed, false);

  const [bindingReplay] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        result_resource_id: string;
        result_version: number;
        replayed: boolean;
      }[]
    >`
      SELECT * FROM app.create_tenant_auth_provider_binding_v2(
        decode(repeat('11', 32), 'hex'), ${fixture.provider}::uuid,
        'mapping_ldap', true, 100, uuidv7(), uuidv7(), uuidv7(),
        '192.0.2.91'::inet, 'Periapsis mapping proof', 'totp'
      )
    `;
  });
  assert.deepEqual(bindingReplay, {
    result_resource_id: binding.result_resource_id,
    result_version: 1,
    replayed: true,
  });
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      await transaction`
        SELECT * FROM app.create_tenant_auth_provider_binding_v2(
          decode(repeat('11', 32), 'hex'), ${fixture.provider}::uuid,
          'mapping_ldap', true, 101, uuidv7(), uuidv7(), uuidv7(),
          '192.0.2.91'::inet, 'Periapsis mapping proof', 'totp'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.tenant_authorization_commands (
          tenant_id, actor_membership_id, operation, key_digest,
          request_digest, result_resource_id, result_version
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid,
          'identity_mapping.create', decode(repeat('12', 32), 'hex'),
          decode(repeat('13', 32), 'hex'), ${binding.result_resource_id}::uuid, 1
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23503"),
  );

  await Promise.all(
    (
      [
        [fixture.role, fixture.foreignGroup, "P0002"],
        [fixture.platformRole, fixture.group, "P0002"],
      ] as const
    ).map(([roleId, groupId, expected]) =>
      assert.rejects(
        admin.begin(async (transaction) => {
          await setApiContext(transaction);
          await transaction`
            SELECT * FROM app.create_tenant_ldap_mapping_rule_v2(
              decode(repeat('21', 32), 'hex'), ${binding.result_resource_id}::uuid,
              'exact_cn', 'responders', 'insensitive', 10, ${groupId}::uuid,
              'additive', ARRAY[${roleId}::uuid]::uuid[], NULL, NULL,
              '', 'negative target proof', uuidv7(), uuidv7(), uuidv7(),
              '192.0.2.91'::inet, 'Periapsis mapping proof', 'totp'
            )
          `;
        }),
        (error: unknown) => assertSqlState(error, expected),
      ),
    ),
  );

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.tenant_ldap_mapping_rules (
          id, tenant_id, binding_id, matcher_type, matcher_value, case_mode,
          priority, tenant_security_group_id, reconciliation_mode,
          operator_team_id, operator_team_assignment_epoch_id,
          created_by_membership_id, updated_by_membership_id
        ) VALUES (
          ${fixture.badRule}::uuid, ${fixture.tenant}::uuid,
          ${binding.result_resource_id}::uuid, 'exact_cn', 'bad-team',
          'insensitive', 10, ${fixture.group}::uuid, 'additive',
          ${fixture.replacementTeam}::uuid, ${fixture.assignment}::uuid,
          ${fixture.adminMembership}::uuid, ${fixture.adminMembership}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23503"),
  );

  const [mapping] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      {
        result_resource_id: string;
        result_version: number;
        replayed: boolean;
      }[]
    >`
      SELECT id AS result_resource_id, version AS result_version, replayed
      FROM app.create_tenant_ldap_mapping_rule_v2(
        decode(repeat('22', 32), 'hex'), ${binding.result_resource_id}::uuid,
        'exact_cn', 'responders', 'insensitive', 10, ${fixture.group}::uuid,
        'additive', ARRAY[${fixture.role}::uuid]::uuid[], ${fixture.team}::uuid,
        ${fixture.assignment}::uuid, '', 'create mapping proof',
        uuidv7(), uuidv7(), uuidv7(), '192.0.2.91'::inet,
        'Periapsis mapping proof', 'totp'
      )
    `;
  });
  assert(mapping);
  assert.equal(mapping.result_version, 1);

  const [listed] = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<
      { id: string; current_source_epoch_activated_at: Date | null }[]
    >`SELECT id, current_source_epoch_activated_at
      FROM app.list_tenant_ldap_mapping_rules_v1(NULL, NULL, NULL, false, 100)`;
  });
  assert.equal(listed?.id, mapping.result_resource_id);
  assert.equal(listed.current_source_epoch_activated_at, null);

  const enabledVersion = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.update_tenant_ldap_mapping_rule_v1(
        ${mapping.result_resource_id}::uuid, 1, 'exact_cn', 'responders',
        'insensitive', 10, ${fixture.group}::uuid, 'additive',
        ARRAY[${fixture.role}::uuid]::uuid[], ${fixture.team}::uuid,
        ${fixture.assignment}::uuid, true, '', 'enable mapping proof',
        uuidv7(), uuidv7(), uuidv7(), '192.0.2.91'::inet,
        'Periapsis mapping proof', 'totp'
      ) AS version
    `;
    return result?.version;
  });
  assert.equal(enabledVersion, 2);

  const [firstEpoch] = await admin<
    { epoch_id: string; source_id: string; authoritative: boolean }[]
  >`
    SELECT epoch.id AS epoch_id, epoch.source_id, source.authoritative
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE epoch.tenant_id = ${fixture.tenant}::uuid
      AND epoch.mapping_rule_id = ${mapping.result_resource_id}::uuid
      AND epoch.sequence = 1
  `;
  assert(firstEpoch);
  assert.equal(firstEpoch.authoritative, false);

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenant_security_group_memberships (
        id, tenant_id, group_id, membership_id, source_id, grant_reason
      ) VALUES (
        ${fixture.groupEdge}::uuid, ${fixture.tenant}::uuid, ${fixture.group}::uuid,
        ${fixture.targetMembership}::uuid, ${firstEpoch.source_id}::uuid,
        'mapping provenance proof'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id, grant_reason
      ) VALUES (
        ${fixture.roleEdge}::uuid, ${fixture.tenant}::uuid,
        ${fixture.targetMembership}::uuid, ${fixture.role}::uuid,
        ${firstEpoch.source_id}::uuid, 'mapping provenance proof'
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        grant_reason
      ) VALUES (
        ${fixture.rosterEdge}::uuid, ${fixture.tenant}::uuid,
        ${fixture.assignment}::uuid, ${fixture.targetMembership}::uuid,
        ${firstEpoch.source_id}::uuid, 'mapping provenance proof'
      )
    `;
  });

  const replacedVersion = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return updateMapping(
      transaction,
      mapping.result_resource_id,
      2,
      "replacement",
    );
  });
  assert.equal(replacedVersion, 3);

  const [history] = await admin<
    {
      first_group_id: string;
      first_mode: string;
      first_retired: boolean;
      second_group_id: string;
      second_mode: string;
      second_authoritative: boolean;
      live_edges: number;
    }[]
  >`
    SELECT first_epoch.tenant_security_group_id AS first_group_id,
           first_epoch.reconciliation_mode::text AS first_mode,
           first_source.retired_at IS NOT NULL AS first_retired,
           second_epoch.tenant_security_group_id AS second_group_id,
           second_epoch.reconciliation_mode::text AS second_mode,
           second_source.authoritative AS second_authoritative,
           (SELECT count(*)::integer FROM (
             SELECT id FROM public.tenant_security_group_memberships
             WHERE id = ${fixture.groupEdge}::uuid AND revoked_at IS NULL
             UNION ALL
             SELECT id FROM public.tenant_membership_role_grants
             WHERE id = ${fixture.roleEdge}::uuid AND revoked_at IS NULL
             UNION ALL
             SELECT id FROM public.operator_team_roster_entries
             WHERE id = ${fixture.rosterEdge}::uuid AND revoked_at IS NULL
           ) AS preserved) AS live_edges
    FROM public.tenant_ldap_mapping_rule_epochs AS first_epoch
    JOIN public.tenant_authorization_sources AS first_source
      ON first_source.tenant_id = first_epoch.tenant_id
     AND first_source.id = first_epoch.source_id
    JOIN public.tenant_ldap_mapping_rule_epochs AS second_epoch
      ON second_epoch.tenant_id = first_epoch.tenant_id
     AND second_epoch.mapping_rule_id = first_epoch.mapping_rule_id
     AND second_epoch.sequence = 2
    JOIN public.tenant_authorization_sources AS second_source
      ON second_source.tenant_id = second_epoch.tenant_id
     AND second_source.id = second_epoch.source_id
    WHERE first_epoch.tenant_id = ${fixture.tenant}::uuid
      AND first_epoch.mapping_rule_id = ${mapping.result_resource_id}::uuid
      AND first_epoch.sequence = 1
  `;
  assert.deepEqual(history, {
    first_group_id: fixture.group,
    first_mode: "additive",
    first_retired: true,
    second_group_id: fixture.replacementGroup,
    second_mode: "authoritative",
    second_authoritative: true,
    live_edges: 3,
  });

  const concurrent = await Promise.allSettled([
    admin.begin(async (transaction) => {
      await setApiContext(transaction);
      return updateMapping(
        transaction,
        mapping.result_resource_id,
        3,
        "winner-a",
      );
    }),
    contender.begin(async (transaction) => {
      await setApiContext(transaction);
      return updateMapping(
        transaction,
        mapping.result_resource_id,
        3,
        "winner-b",
      );
    }),
  ]);
  const winners = concurrent.filter(
    (result): result is PromiseFulfilledResult<number> =>
      result.status === "fulfilled",
  );
  const losers = concurrent.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.deepEqual(
    winners.map((result) => result.value),
    [4],
  );
  assert.equal(losers.length, 1);
  assertSqlState(losers[0]!.reason, "40001");

  const archivedVersion = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    const [result] = await transaction<{ version: number }[]>`
      SELECT app.archive_tenant_ldap_mapping_rule_v1(
        ${mapping.result_resource_id}::uuid, 4, 'archive mapping proof',
        uuidv7(), uuidv7(), uuidv7(), '192.0.2.91'::inet,
        'Periapsis mapping proof', 'totp'
      ) AS version
    `;
    return result?.version;
  });
  assert.equal(archivedVersion, 5);

  const [archived] = await admin<
    { live_epochs: number; live_sources: number; live_edges: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenant_ldap_mapping_rule_epochs
       WHERE tenant_id = ${fixture.tenant}::uuid
         AND mapping_rule_id = ${mapping.result_resource_id}::uuid
         AND ended_at IS NULL) AS live_epochs,
      (SELECT count(*)::integer
       FROM public.tenant_ldap_mapping_rule_epochs epoch
       JOIN public.tenant_authorization_sources source
         ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
       WHERE epoch.tenant_id = ${fixture.tenant}::uuid
         AND epoch.mapping_rule_id = ${mapping.result_resource_id}::uuid
         AND source.retired_at IS NULL) AS live_sources,
      (SELECT count(*)::integer FROM (
        SELECT id FROM public.tenant_security_group_memberships
        WHERE id = ${fixture.groupEdge}::uuid AND revoked_at IS NULL
        UNION ALL SELECT id FROM public.tenant_membership_role_grants
        WHERE id = ${fixture.roleEdge}::uuid AND revoked_at IS NULL
        UNION ALL SELECT id FROM public.operator_team_roster_entries
        WHERE id = ${fixture.rosterEdge}::uuid AND revoked_at IS NULL
      ) preserved) AS live_edges
  `;
  assert.deepEqual(archived, {
    live_epochs: 0,
    live_sources: 0,
    live_edges: 3,
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.tenant_ldap_mapping_rule_epochs
        SET ended_at = NULL, ended_by_membership_id = NULL,
            end_reason = NULL, version = 1
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND id = ${firstEpoch.epoch_id}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const [foreignRead] = await admin.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.foreignUser,
      fixture.foreignTenant,
    );
    return transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM app.get_tenant_ldap_mapping_rule_v1(${mapping.result_resource_id}::uuid)
    `;
  });
  assert.equal(foreignRead?.count, 0);
} finally {
  await Promise.allSettled([admin.end(), contender.end()]);
}
