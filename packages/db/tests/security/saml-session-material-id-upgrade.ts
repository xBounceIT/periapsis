import assert from "node:assert/strict";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
} from "../../src/admin/schema-compatibility-manifest.gen.js";
import { migrateSchema } from "../../src/admin/schema-migration.js";

type JournalEntry = {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
};

type Journal = {
  version: string;
  dialect: string;
  entries: JournalEntry[];
};

type ErrorWithCode = Error & { code?: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return (
    isRecord(value) &&
    Number.isSafeInteger(value.idx) &&
    typeof value.version === "string" &&
    Number.isSafeInteger(value.when) &&
    typeof value.tag === "string" &&
    typeof value.breakpoints === "boolean"
  );
}

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    typeof value.dialect !== "string" ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isJournalEntry)
  ) {
    throw new Error("The Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

function assertSqlState(
  error: unknown,
  expected: string,
): asserts error is ErrorWithCode {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
}

const databaseUrl =
  process.env.PERIAPSIS_SAML_MATERIAL_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SAML_MATERIAL_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d2fc0-4000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 141;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const predecessor = expectedMigrations[predecessorIndex];
assert.equal(predecessorEntries.length, 142);
assert.equal(predecessor?.tag, "0141_ticket_query_projections_readiness");
assert.equal(predecessor.createdAt, 1787747400262);
assert.equal(
  predecessor.hash,
  "d7db1d274a73068b9152b822082f8752d4fc30e9ddb675904cba1ce1b6cba40c",
);
assert.equal(expectedMigrationCount, 232);
assert.equal(expectedMigrationCreatedAt, 1788650095675);
const predecessorFingerprint = expectedMigrations
  .slice(0, predecessorIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");

const legacy = {
  tenant: uuid(1),
  user: uuid(2),
  provider: uuid(3),
  binding: uuid(4),
  externalIdentity: uuid(5),
  session: uuid(6),
  family: uuid(7),
  continuation: uuid(8),
  sessionMaterial: uuid(9),
  continuationMaterial: uuid(10),
  missingSession: uuid(11),
  missingFamily: uuid(12),
  missingContinuation: uuid(13),
  membership: uuid(14),
};

const current = {
  tenant: uuid(21),
  user: uuid(22),
  provider: uuid(23),
  binding: uuid(24),
  externalIdentity: uuid(25),
  session: uuid(26),
  family: uuid(27),
  material: uuid(28),
  application: uuid(29),
};

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-saml-material-rolling-0141-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18.6"),
    "upgrade harness requires PostgreSQL 18.6",
  );

  await mkdir(resolve(stageRoot, "meta"));
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: predecessorEntries }, null, 2)}\n`,
  );
  await Promise.all(
    predecessorEntries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );

  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [prefix] = await sql<
    {
      count: number;
      latest_created_at: string;
      latest_hash: string;
      migration_fingerprint: string;
    }[]
  >`
    SELECT count(*)::integer AS count,
           max(created_at)::text AS latest_created_at,
           (array_agg(lower(hash::text)
              ORDER BY created_at DESC, id DESC))[1] AS latest_hash,
           string_agg(
             created_at::text || '@' || lower(hash::text), ':'
             ORDER BY created_at, id
           ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(prefix, {
    count: 142,
    latest_created_at: String(predecessor.createdAt),
    latest_hash: predecessor.hash,
    migration_fingerprint: predecessorFingerprint,
  });

  const now = new Date(Date.now() - 60_000);
  const idleExpiresAt = new Date(now.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(now.getTime() + 2 * 60 * 60_000);
  const continuationExpiresAt = new Date(now.getTime() + 5 * 60_000);
  const nowWire = now.toISOString();
  const idleExpiresAtWire = idleExpiresAt.toISOString();
  const absoluteExpiresAtWire = absoluteExpiresAt.toISOString();
  const continuationExpiresAtWire = continuationExpiresAt.toISOString();
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenants (id,slug,name)
      VALUES (${legacy.tenant}::uuid,'saml-material-upgrade','SAML material upgrade')
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name)
      VALUES (
        ${legacy.user}::uuid,'saml-material-upgrade@example.invalid',
        'SAML material upgrade user'
      )
    `;
    // The fixture predates 0142, but the modern tail reaches 0182 where every
    // extant tenant must already have canonical authorization state and its
    // protected tenant_admin role. Seed that prerequisite through the same
    // idempotent entry point used by production tenant creation.
    await transaction`
      INSERT INTO public.tenant_memberships (id,tenant_id,user_id,role,status)
      VALUES (
        ${legacy.membership}::uuid,${legacy.tenant}::uuid,${legacy.user}::uuid,
        'tenant_admin','active'
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,last_seen_at,idle_expires_at,
        absolute_expires_at,created_at
      ) VALUES
      (
        ${legacy.session}::uuid,${legacy.user}::uuid,${legacy.family}::uuid,
        ${legacy.tenant}::uuid,decode(repeat('11',32),'hex'),
        decode(repeat('12',32),'hex'),'saml',${nowWire}::timestamptz,
        ${idleExpiresAtWire}::timestamptz,
        ${absoluteExpiresAtWire}::timestamptz,${nowWire}::timestamptz
      ),
      (
        ${legacy.missingSession}::uuid,${legacy.user}::uuid,
        ${legacy.missingFamily}::uuid,${legacy.tenant}::uuid,
        decode(repeat('14',32),'hex'),decode(repeat('15',32),'hex'),'saml',
        ${nowWire}::timestamptz,${idleExpiresAtWire}::timestamptz,
        ${absoluteExpiresAtWire}::timestamptz,${nowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        provider_id,binding_id,provider_kind,external_identity_id,
        external_identity_revision,trust_rule_revision,authenticated_at
      ) VALUES
      (
        ${legacy.tenant}::uuid,${legacy.session}::uuid,${legacy.user}::uuid,
        'tenant_provider','saml',${legacy.provider}::uuid,
        ${legacy.binding}::uuid,'saml',${legacy.externalIdentity}::uuid,
        1,1,${nowWire}::timestamptz
      ),
      (
        ${legacy.tenant}::uuid,${legacy.missingSession}::uuid,
        ${legacy.user}::uuid,'tenant_provider','saml',${legacy.provider}::uuid,
        ${legacy.binding}::uuid,'saml',${legacy.externalIdentity}::uuid,
        1,1,${nowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,provider_id,binding_id,provider_kind,external_identity_id,
        primary_revision,session_invalidation_epoch,state,version,created_at,
        expires_at
      ) VALUES
      (
        ${legacy.continuation}::uuid,${legacy.tenant}::uuid,${legacy.user}::uuid,
        decode(repeat('13',32),'hex'),1,'mfa.step_up','api','tenant_provider',
        ${legacy.provider}::uuid,${legacy.binding}::uuid,'saml',
        ${legacy.externalIdentity}::uuid,1,1,'pending',1,
        ${nowWire}::timestamptz,${continuationExpiresAtWire}::timestamptz
      ),
      (
        ${legacy.missingContinuation}::uuid,${legacy.tenant}::uuid,
        ${legacy.user}::uuid,decode(repeat('16',32),'hex'),1,'mfa.step_up',
        'api','tenant_provider',${legacy.provider}::uuid,
        ${legacy.binding}::uuid,'saml',${legacy.externalIdentity}::uuid,
        1,1,'pending',1,${nowWire}::timestamptz,
        ${continuationExpiresAtWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.tenant_saml_session_materials (
        id,tenant_id,session_id,continuation_id,user_id,provider_id,binding_id,
        provider_kind,external_identity_id,session_index_digest,key_version,
        ciphertext,created_at
      ) VALUES
      (
        ${legacy.sessionMaterial}::uuid,${legacy.tenant}::uuid,
        ${legacy.session}::uuid,NULL,${legacy.user}::uuid,
        ${legacy.provider}::uuid,${legacy.binding}::uuid,'saml',
        ${legacy.externalIdentity}::uuid,NULL,1,${Buffer.alloc(32, 1)},
        ${nowWire}::timestamptz
      ),
      (
        ${legacy.continuationMaterial}::uuid,${legacy.tenant}::uuid,NULL,
        ${legacy.continuation}::uuid,${legacy.user}::uuid,
        ${legacy.provider}::uuid,${legacy.binding}::uuid,'saml',
        ${legacy.externalIdentity}::uuid,NULL,1,${Buffer.alloc(32, 2)},
        ${nowWire}::timestamptz
      )
    `;
  });

  await sql`
    SELECT app.seed_tenant_authorization(
      ${legacy.tenant}::uuid,${legacy.membership}::uuid
    )
  `;
  await migrateSchema(sql, migrationsRoot);

  const [retired] = await sql<
    {
      revoked_session: boolean;
      session_reason: string | null;
      continuation_state: string;
      continuation_version: string;
      continuation_reason: string | null;
      missing_session_revoked: boolean;
      missing_continuation_state: string;
      active_legacy: number;
      audits: number;
      redacted_audits: number;
      aad_v1_audits: number;
      absent_audits: number;
    }[]
  >`
    SELECT session.revoked_at IS NOT NULL AS revoked_session,
           session.revoke_reason AS session_reason,
           continuation.state AS continuation_state,
           continuation.version::text AS continuation_version,
           continuation.revoke_reason AS continuation_reason,
           (SELECT revoked_at IS NOT NULL
            FROM public.auth_sessions
            WHERE id = ${legacy.missingSession}::uuid)
             AS missing_session_revoked,
           (SELECT state::text
            FROM public.tenant_post_primary_continuations
            WHERE tenant_id = ${legacy.tenant}::uuid
              AND id = ${legacy.missingContinuation}::uuid)
             AS missing_continuation_state,
           (
             SELECT count(*)::integer
             FROM public.tenant_saml_session_materials AS material
             LEFT JOIN public.auth_sessions AS material_session
               ON material_session.id = material.session_id
              AND material_session.active_tenant_id = material.tenant_id
             LEFT JOIN public.tenant_post_primary_continuations AS material_continuation
               ON material_continuation.tenant_id = material.tenant_id
              AND material_continuation.id = material.continuation_id
             WHERE material.aad_version = 1
               AND (
                 (material.session_id IS NOT NULL
                   AND material_session.revoked_at IS NULL)
                 OR (material.continuation_id IS NOT NULL
                   AND material_continuation.state = 'pending')
               )
           ) AS active_legacy,
           (
             SELECT count(*)::integer FROM public.audit_events
             WHERE tenant_id = ${legacy.tenant}::uuid
               AND action = 'tenant.identity.saml_legacy_material_retired'
           ) AS audits,
           (
             SELECT count(*)::integer FROM public.audit_events
             WHERE tenant_id = ${legacy.tenant}::uuid
               AND action = 'tenant.identity.saml_legacy_material_retired'
               AND actor_type = 'system'
               AND actor_user_id IS NULL
               AND metadata - 'legacy_material_state' = jsonb_build_object(
                 'authority_revoked',true,'material_disclosed',false
               )
           ) AS redacted_audits
           ,(
             SELECT count(*)::integer FROM public.audit_events
             WHERE tenant_id = ${legacy.tenant}::uuid
               AND action = 'tenant.identity.saml_legacy_material_retired'
               AND metadata ->> 'legacy_material_state' = 'aad_v1'
           ) AS aad_v1_audits
           ,(
             SELECT count(*)::integer FROM public.audit_events
             WHERE tenant_id = ${legacy.tenant}::uuid
               AND action = 'tenant.identity.saml_legacy_material_retired'
               AND metadata ->> 'legacy_material_state' = 'absent'
           ) AS absent_audits
    FROM public.auth_sessions AS session
    CROSS JOIN public.tenant_post_primary_continuations AS continuation
    WHERE session.id = ${legacy.session}::uuid
      AND continuation.tenant_id = ${legacy.tenant}::uuid
      AND continuation.id = ${legacy.continuation}::uuid
  `;
  assert.deepEqual(retired, {
    revoked_session: true,
    session_reason: "saml_legacy_material_retired",
    continuation_state: "revoked",
    continuation_version: "2",
    continuation_reason: "saml_legacy_material_retired",
    missing_session_revoked: true,
    missing_continuation_state: "revoked",
    active_legacy: 0,
    audits: 4,
    redacted_audits: 4,
    aad_v1_audits: 2,
    absent_audits: 2,
  });

  await assert.rejects(
    sql`
      INSERT INTO public.tenant_saml_session_materials (
        id,tenant_id,session_id,user_id,provider_id,binding_id,provider_kind,
        external_identity_id,aad_version,key_version,ciphertext,created_at
      ) VALUES (
        ${uuid(14)}::uuid,${legacy.tenant}::uuid,${legacy.session}::uuid,
        ${legacy.user}::uuid,${legacy.provider}::uuid,${legacy.binding}::uuid,
        'saml',${legacy.externalIdentity}::uuid,1,1,${Buffer.alloc(32, 3)},
        transaction_timestamp()
      )
    `,
    (error) => {
      assertSqlState(error, "23514");
      return true;
    },
  );

  const currentNow = new Date();
  const currentExpiresAt = new Date(currentNow.getTime() + 5 * 60_000);
  const currentIdleExpiresAt = new Date(currentNow.getTime() + 60 * 60_000);
  const currentAbsoluteExpiresAt = new Date(
    currentNow.getTime() + 2 * 60 * 60_000,
  );
  const currentNowWire = currentNow.toISOString();
  const currentExpiresAtWire = currentExpiresAt.toISOString();
  const currentIdleExpiresAtWire = currentIdleExpiresAt.toISOString();
  const currentAbsoluteExpiresAtWire = currentAbsoluteExpiresAt.toISOString();
  const currentRequestSnapshot = JSON.stringify({
    samlSession: { materialId: current.material },
  });
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenants (id,slug,name)
      VALUES (${current.tenant}::uuid,'saml-material-current','SAML material current')
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name)
      VALUES (
        ${current.user}::uuid,'saml-material-current@example.invalid',
        'SAML material current user'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_policies (
        tenant_id,provider_id,binding_id,provider_kind,configuration_revision,
        security_revision,plan_revision,assurance_policy_revision,jit_mode,
        no_match_policy,enabled,created_at,updated_at
      ) VALUES (
        ${current.tenant}::uuid,${current.provider}::uuid,${current.binding}::uuid,
        'saml',1,1,1,1,'disabled','deny',true,
        ${currentNowWire}::timestamptz,${currentNowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identities (
        id,tenant_id,provider_id,binding_id,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,
        admitted_configuration_revision,last_observed_at,version,
        created_at,updated_at
      ) VALUES (
        ${current.externalIdentity}::uuid,${current.tenant}::uuid,
        ${current.provider}::uuid,${current.binding}::uuid,${current.user}::uuid,
        'utf8_exact',${Buffer.alloc(17, 4)},${Buffer.alloc(12, 4)},1,1,
        ${currentNowWire}::timestamptz,1,${currentNowWire}::timestamptz,
        ${currentNowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,last_seen_at,idle_expires_at,
        absolute_expires_at,created_at
      ) VALUES (
        ${current.session}::uuid,${current.user}::uuid,${current.family}::uuid,
        ${current.tenant}::uuid,decode(repeat('41',32),'hex'),
        decode(repeat('42',32),'hex'),'saml',${currentNowWire}::timestamptz,
        ${currentIdleExpiresAtWire}::timestamptz,
        ${currentAbsoluteExpiresAtWire}::timestamptz,
        ${currentNowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        issued_at
      ) VALUES (
        ${current.session}::uuid,${current.tenant}::uuid,${current.user}::uuid,
        1,1,false,'api','tenant_provider',1,${currentNowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        provider_id,binding_id,provider_kind,external_identity_id,
        external_identity_revision,trust_rule_revision,authenticated_at
      ) VALUES (
        ${current.tenant}::uuid,${current.session}::uuid,${current.user}::uuid,
        'tenant_provider','saml',${current.provider}::uuid,
        ${current.binding}::uuid,'saml',${current.externalIdentity}::uuid,
        1,1,${currentNowWire}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_authentication_transactions (
        transaction_id,tenant_id,provider_id,binding_id,provider_kind,protocol,
        operation_run_id,operation_digest,receipt_digest,network_digest,
        account_digest,provider_digest,relay_state_digest,browser_digest,
        provider_revision,binding_revision,configuration_revision,
        security_revision,plan_revision,mapping_revision,authorization_revision,
        assurance_policy_revision,metadata_revision,metadata_digest,
        sp_key_revision,configuration_digest,request_id,return_path,state,
        version,created_at,expires_at
      ) VALUES (
        decode(repeat('43',32),'hex'),${current.tenant}::uuid,
        ${current.provider}::uuid,${current.binding}::uuid,'saml','saml',
        ${current.material}::uuid,decode(repeat('44',32),'hex'),
        decode(repeat('45',32),'hex'),decode(repeat('46',32),'hex'),
        decode(repeat('47',32),'hex'),decode(repeat('48',32),'hex'),
        decode(repeat('49',32),'hex'),decode(repeat('4a',32),'hex'),
        1,1,1,1,1,1,1,1,1,decode(repeat('4b',32),'hex'),1,
        decode(repeat('4c',32),'hex'),'_current_request','/portal','pending',
        1,${currentNowWire}::timestamptz,${currentExpiresAtWire}::timestamptz
      )
    `;
  });

  await sql`
    INSERT INTO public.tenant_saml_session_materials (
      id,tenant_id,session_id,continuation_id,user_id,provider_id,binding_id,
      provider_kind,external_identity_id,session_index_digest,aad_version,
      key_version,ciphertext,logout_configuration,created_at
    ) VALUES (
      ${current.material}::uuid,${current.tenant}::uuid,${current.session}::uuid,
      NULL,${current.user}::uuid,${current.provider}::uuid,
      ${current.binding}::uuid,'saml',${current.externalIdentity}::uuid,
      NULL,2,NULL,NULL,
      jsonb_build_object(
        'authentication',jsonb_build_object(
          'provider',jsonb_build_object(
            'scope','tenant',
            'tenantId',${current.tenant}::text,
            'providerId',${current.provider}::text,
            'bindingId',${current.binding}::text
          )
        )
      ),
      ${currentNowWire}::timestamptz
    )
  `;
  await sql.begin(async (transaction) => {
    await transaction`
      UPDATE public.tenant_federated_authentication_transactions
      SET state = 'completed',version = 2,
          completed_at = ${currentNowWire}::timestamptz
      WHERE tenant_id = ${current.tenant}::uuid
        AND operation_run_id = ${current.material}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_federated_authentication_applications (
        id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
        binding_id,provider_kind,response_id_digest,assertion_id_digest,
        category,primary_kind,user_id,session_id,request_snapshot,
        result_snapshot,applied_at
      ) VALUES (
        ${current.application}::uuid,${current.tenant}::uuid,'saml',
        decode(repeat('43',32),'hex'),decode(repeat('4d',32),'hex'),
        ${current.provider}::uuid,${current.binding}::uuid,'saml',
        decode(repeat('4e',32),'hex'),decode(repeat('4f',32),'hex'),
        'success','tenant_provider',${current.user}::uuid,
        ${current.session}::uuid,
        ${currentRequestSnapshot}::jsonb,
        '{}'::jsonb,${currentNowWire}::timestamptz
      )
    `;
  });

  const [currentMaterial] = await sql<
    { id: string; aad_version: number; marker_only: boolean }[]
  >`
    SELECT id::text AS id,aad_version,
           key_version IS NULL AND ciphertext IS NULL AS marker_only
    FROM public.tenant_saml_session_materials
    WHERE tenant_id = ${current.tenant}::uuid AND id = ${current.material}::uuid
  `;
  assert.deepEqual(currentMaterial, {
    id: current.material,
    aad_version: 2,
    marker_only: true,
  });

  const [compatibility] = await sql<
    {
      current_count: number;
      current_latest: string;
      current_hash: string;
      current_fingerprint: string;
      predecessor_count: number;
      predecessor_latest: string;
      predecessor_hash: string;
      predecessor_fingerprint: string;
      retired_count: number;
      release_ready: boolean;
      current_federation_ready: boolean;
      material_ready: boolean;
      federation_ready: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS current_count,
           current_projection.latest_created_at::text AS current_latest,
           current_projection.latest_hash AS current_hash,
           current_projection.migration_fingerprint AS current_fingerprint,
           predecessor_projection.applied_count::integer AS predecessor_count,
           predecessor_projection.latest_created_at::text AS predecessor_latest,
           predecessor_projection.latest_hash AS predecessor_hash,
           predecessor_projection.migration_fingerprint AS predecessor_fingerprint,
           retired_projection.applied_count::integer AS retired_count,
           app.release_runtime_schema_readiness_v50() AS release_ready,
           app.federated_authentication_schema_readiness_v50()
             AS current_federation_ready,
           app.private_saml_session_material_id_readiness_v1() AS material_ready,
           app.federated_authentication_schema_readiness_v1() AS federation_ready
    FROM app.schema_compatibility_v50() AS current_projection
    CROSS JOIN app.schema_compatibility_v30() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v29() AS retired_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: expectedMigrationCount,
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    predecessor_count: 0,
    predecessor_latest: "0",
    predecessor_hash: "UNSUPPORTED",
    predecessor_fingerprint: "UNSUPPORTED",
    retired_count: 0,
    release_ready: true,
    current_federation_ready: true,
    material_ready: false,
    federation_ready: false,
  });

  const [acl] = await sql<
    {
      api_lookup: boolean;
      api_apply: boolean;
      api_logout: boolean;
      api_legacy_logout: boolean;
      api_private_apply: boolean;
      worker_logout: boolean;
      api_material_table: boolean;
      api_logout_table: boolean;
    }[]
  >`
    SELECT has_function_privilege(
             'periapsis_api',
             'app.lookup_saml_authentication_transaction_v1(jsonb)',
             'EXECUTE'
           ) AS api_lookup,
           has_function_privilege(
             'periapsis_api','app.apply_federated_authentication_v1(jsonb)',
             'EXECUTE'
           ) AS api_apply,
           has_function_privilege(
             'periapsis_api','app.revoke_local_session_for_logout_v1(jsonb)',
             'EXECUTE'
           ) AS api_logout,
           has_function_privilege(
             'periapsis_api','app.revoke_local_saml_session_v1(uuid,jsonb)',
             'EXECUTE'
           ) AS api_legacy_logout,
           has_function_privilege(
             'periapsis_api',
             'app.private_apply_federated_authentication_v30(jsonb)',
             'EXECUTE'
           ) AS api_private_apply,
           has_function_privilege(
             'periapsis_worker','app.revoke_local_saml_session_v1(uuid,jsonb)',
             'EXECUTE'
           ) AS worker_logout,
           has_any_column_privilege(
             'periapsis_api','public.tenant_saml_session_materials','SELECT'
           ) AS api_material_table,
           has_any_column_privilege(
             'periapsis_api','public.tenant_saml_logout_commands','SELECT'
           ) AS api_logout_table
  `;
  assert.deepEqual(acl, {
    api_lookup: true,
    api_apply: true,
    api_logout: true,
    api_legacy_logout: false,
    api_private_apply: false,
    worker_logout: false,
    api_material_table: false,
    api_logout_table: false,
  });
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
