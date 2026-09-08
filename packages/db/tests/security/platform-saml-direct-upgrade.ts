import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };
type JournalEntry = {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
};
type Journal = { version: string; dialect: string; entries: JournalEntry[] };

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

function isJournal(value: unknown): value is Journal {
  return (
    isRecord(value) &&
    typeof value.version === "string" &&
    typeof value.dialect === "string" &&
    Array.isArray(value.entries) &&
    value.entries.every(isJournalEntry)
  );
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function assertMigrationSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a migration error");
  const cause = (error as Error & { cause?: unknown }).cause;
  return assertSqlState(cause, expected);
}

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_SAML_DIRECT_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_SAML_DIRECT_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const parsedJournal: unknown = JSON.parse(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
assert(isJournal(parsedJournal));
const journal = parsedJournal;
assert.equal(journal.entries.length, 248);
assert.equal(expectedMigrationCount, 248);
assert.equal(journal.entries[184]?.tag, "0184_platform_saml_direct_runtime");
assert.equal(
  journal.entries[185]?.tag,
  "0185_platform_saml_direct_compatibility",
);
assert.equal(
  journal.entries[186]?.tag,
  "0186_platform_saml_direct_runtime_successor",
);
assert.equal(
  journal.entries[187]?.tag,
  "0187_platform_saml_direct_compatibility",
);
assert.equal(
  journal.entries[188]?.tag,
  "0188_platform_saml_metadata_projection_fix",
);
assert.equal(
  journal.entries[189]?.tag,
  "0189_platform_saml_metadata_projection_compatibility",
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-platform-saml-direct-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

async function writeStage(
  name: string,
  entries: readonly JournalEntry[],
): Promise<string> {
  const root = resolve(stageRoot, name);
  await mkdir(resolve(root, "meta"), { recursive: true });
  await writeFile(
    resolve(root, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(root, `${entry.tag}.sql`),
      ),
    ),
  );
  return root;
}

function fingerprint(count: number): string {
  return expectedMigrations
    .slice(0, count)
    .map((entry) => `${entry.createdAt}@${entry.hash}`)
    .join(":");
}

async function seal(count: number): Promise<void> {
  const latest = expectedMigrations[count - 1];
  assert(latest);
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      ${count}::bigint,${latest.createdAt}::bigint,${latest.hash}::text,
      ${fingerprint(count)}::text
    )
  `;
}

async function asApi<T>(
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function assertRuntimeACLClosed(): Promise<void> {
  const [functions] = await sql<{ closed: boolean }[]>`
    WITH expected(signature,api_callable) AS (VALUES
      ('app.private_platform_saml_tenant_switch_assurance_v1(uuid,timestamp with time zone)',false),
      ('app.lookup_platform_saml_tenant_switch_replay_v1(jsonb)',true),
      ('app.apply_platform_saml_tenant_switch_v1(jsonb)',true),
      ('app.load_platform_saml_tenant_switch_revalidation_v1(jsonb)',false),
      ('app.load_platform_saml_tenant_switch_v1(jsonb)',true),
      ('app.private_platform_saml_totp_completion_fence_v1()',false),
      ('app.cleanup_platform_saml_post_primary_totp_apply_v1(jsonb)',true),
      ('app.begin_platform_post_primary_totp_v2(jsonb)',true)
    ), actual AS (
      SELECT expected.*,to_regprocedure(expected.signature) AS oid
      FROM expected
    )
    SELECT count(*)=8 AND coalesce(bool_and(
      actual.oid IS NOT NULL
      AND function_row.proowner='periapsis_migrator'::regrole
      AND function_row.prosecdef
      AND NOT EXISTS (
        SELECT 1
        FROM aclexplode(coalesce(
          function_row.proacl,acldefault('f',function_row.proowner)
        )) AS acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
      )
      AND has_function_privilege(
        'periapsis_api',actual.oid,'EXECUTE'
      )=actual.api_callable
      AND NOT has_function_privilege(
        'periapsis_worker',actual.oid,'EXECUTE'
      )
      AND NOT has_function_privilege(
        'periapsis_notifier',actual.oid,'EXECUTE'
      )
    ),false) AS closed
    FROM actual
    LEFT JOIN pg_proc AS function_row ON function_row.oid=actual.oid
  `;
  assert.equal(functions?.closed, true);

  const [relation] = await sql<{ closed: boolean }[]>`
    SELECT relation.relowner='periapsis_migrator'::regrole
      AND relation.relrowsecurity
      AND NOT has_table_privilege(
        'periapsis_api',relation.oid,'SELECT,INSERT,UPDATE,DELETE'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM aclexplode(coalesce(
          relation.relacl,acldefault('r',relation.relowner)
        )) AS acl
        WHERE acl.grantee=0
      ) AS closed
    FROM pg_class AS relation
    WHERE relation.oid=
      'public.platform_saml_tenant_switch_commands'::regclass
  `;
  assert.equal(relation?.closed, true);
}

async function assertProjectionACLClosed(): Promise<void> {
  const [row] = await sql<{ closed: boolean }[]>`
    SELECT function_row.proowner='periapsis_migrator'::regrole
      AND function_row.prosecdef AND function_row.provolatile='s'
      AND function_row.proconfig=ARRAY[
        'search_path=pg_catalog, public, app'
      ]::text[]
      AND NOT EXISTS (
        SELECT 1
        FROM aclexplode(coalesce(
          function_row.proacl,acldefault('f',function_row.proowner)
        )) AS acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
      )
      AND has_function_privilege(
        'periapsis_api',function_row.oid,'EXECUTE'
      )
      AND NOT has_function_privilege(
        'periapsis_worker',function_row.oid,'EXECUTE'
      )
      AND NOT has_function_privilege(
        'periapsis_notifier',function_row.oid,'EXECUTE'
      ) AS closed
    FROM pg_proc AS function_row
    WHERE function_row.oid=
      'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure
  `;
  assert.equal(row?.closed, true);
}

const fixture = {
  user: "019d8000-4000-7000-8000-000000000001",
  provider: "019d8000-4000-7000-8000-000000000002",
  spKey: "019d8000-4000-7000-8000-000000000003",
  floor: "019d8000-4000-7000-8000-000000000004",
} as const;
const providerKey = "saml_upgrade_v43";
const metadataDocument = Buffer.from(
  '<EntityDescriptor entityID="https://idp.example.invalid/metadata"/>',
  "utf8",
);
const metadataDigest = createHash("sha256").update(metadataDocument).digest();
const certificateBundle = [
  Buffer.from("upgrade-certificate-zero"),
  Buffer.from("upgrade-certificate-one"),
  Buffer.from("upgrade-certificate-two"),
] as const;

async function seedProjection(): Promise<void> {
  const now = new Date();
  now.setMilliseconds(0);
  const metadataMaximum = new Date(now.getTime() + 24 * 60 * 60_000);
  const nowInstant = now.toISOString();
  const metadataMaximumInstant = metadataMaximum.toISOString();
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (
        id,email,display_name,active,version,authentication_revision,
        created_at,updated_at
      ) VALUES (
        ${fixture.user}::uuid,'saml-upgrade-v43@example.invalid',
        'SAML v43 upgrade proof',true,1,1,
        ${nowInstant}::timestamptz,${nowInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version,verifier,is_active,bound_at
      ) VALUES (
        1,${Buffer.alloc(32, 0x51)},true,${nowInstant}::timestamptz
      )
      ON CONFLICT (key_version) DO NOTHING
    `;
    await transaction`
      INSERT INTO public.platform_auth_providers (
        id,key,display_name,description,kind,enabled,
        created_by_user_id,updated_by_user_id,version,created_at,updated_at
      ) VALUES (
        ${fixture.provider}::uuid,${providerKey},'SAML v43 upgrade proof',
        'Append-only metadata projection upgrade proof','saml',true,
        ${fixture.user}::uuid,${fixture.user}::uuid,1,
        ${nowInstant}::timestamptz,${nowInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.platform_federated_provider_policies (
        provider_id,provider_kind,configuration_revision,security_revision,
        plan_revision,assurance_policy_revision,account_mode,
        platform_login_enabled,enabled,created_at,updated_at
      ) VALUES (
        ${fixture.provider}::uuid,'saml',1,1,1,1,'disabled',false,true,
        ${nowInstant}::timestamptz,${nowInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_provider_configurations (
        provider_id,provider_kind,expected_entity_id,sp_entity_id,acs_url,
        sp_key_revision,metadata_revision,redirect_signature_algorithm,
        signature_policy,encryption_policy,decryption_key_versions,
        requested_authn_contexts,subject_source,subject_attribute_name,
        subject_attribute_name_format,clock_skew_nanoseconds,
        max_authentication_age_nanoseconds,version,created_at,updated_at
      ) VALUES (
        ${fixture.provider}::uuid,'saml',
        'https://idp.example.invalid/metadata',
        ${`https://periapsis.example.invalid/api/v1/auth/platform/saml/${providerKey}/metadata`},
        'https://periapsis.example.invalid/api/v1/auth/platform/saml/acs',
        1,1,'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'signed_assertion','disabled',ARRAY[]::integer[],
        ARRAY['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport']::text[],
        'persistent_nameid',NULL,NULL,30000000000,3600000000000,1,
        ${nowInstant}::timestamptz,${nowInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_metadata_snapshots (
        provider_id,revision,document,document_digest,retrieved_at,
        maximum_valid_until
      ) VALUES (
        ${fixture.provider}::uuid,1,${metadataDocument},${metadataDigest},
        ${nowInstant}::timestamptz,
        ${metadataMaximumInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_sp_keys (
        id,provider_id,revision,key_version,nonce,ciphertext,created_at
      ) VALUES (
        ${fixture.spKey}::uuid,${fixture.provider}::uuid,1,1,
        ${Buffer.alloc(12, 0x52)},${Buffer.alloc(64, 0x53)},
        ${nowInstant}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_sp_certificates (
        key_id,sequence,certificate_der
      ) VALUES
        (${fixture.spKey}::uuid,0,${certificateBundle[0]}),
        (${fixture.spKey}::uuid,1,${certificateBundle[1]}),
        (${fixture.spKey}::uuid,2,${certificateBundle[2]})
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.floor}:1`},true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,enrollment_deadline,created_at
      ) VALUES (
        ${fixture.floor}::uuid,1,NULL,'platform_floor','primary',false,
        0,NULL,${nowInstant}::timestamptz
      )
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1','',true)
    `;
  });
}

async function loadProjection(): Promise<postgres.JSONValue | null> {
  const [row] = await asApi(
    (transaction) =>
      transaction<{ value: postgres.JSONValue | null }[]>`
        SELECT app.load_platform_saml_metadata_projection_v1(
          ${providerKey}::text
        ) AS value
      `,
  );
  return row?.value ?? null;
}

function assertProjection(value: unknown): void {
  assert(isRecord(value));
  assert.equal(value.providerKey, providerKey);
  assert(Array.isArray(value.certificates));
  assert.equal(value.certificates.length, 3);
  assert.deepEqual(
    value.certificates.map((certificate) => {
      assert(isRecord(certificate));
      return certificate.certificateDer;
    }),
    certificateBundle.map((certificate) => certificate.toString("base64")),
  );
}

try {
  const [version] = await sql<{ version: number }[]>`
    SELECT current_setting('server_version_num')::integer AS version
  `;
  assert(version !== undefined && version.version >= 180_000);

  const v40Stage = await writeStage("v40", journal.entries.slice(0, 182));
  const mfaRuntimeStage = await writeStage(
    "mfa-runtime",
    journal.entries.slice(0, 183),
  );
  const v41Stage = await writeStage("v41", journal.entries.slice(0, 184));
  const v42RuntimeStage = await writeStage(
    "v42-runtime",
    journal.entries.slice(0, 185),
  );
  const v42CompatibilityStage = await writeStage(
    "v42-compatibility",
    journal.entries.slice(0, 186),
  );
  const stoppedAt186Stage = await writeStage(
    "stopped-at-0186",
    journal.entries.slice(0, 187),
  );
  const v42Stage = await writeStage("v42", journal.entries.slice(0, 188));
  const fixedStage = await writeStage(
    "fixed-stopped-at-0188",
    journal.entries.slice(0, 189),
  );
  const v43Stage = await writeStage("v43", journal.entries.slice(0, 190));

  await migrate(drizzle(sql), { migrationsFolder: v40Stage });
  await seal(182);
  const [v40] = await sql<
    { schema: number; identity: boolean; direct: boolean }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v40())::integer AS schema,
           app.platform_identity_runtime_schema_readiness_v6() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
  `;
  assert.deepEqual(v40, { schema: 182, identity: true, direct: true });

  await migrate(drizzle(sql), { migrationsFolder: mfaRuntimeStage });
  const [mfaUnsupported] = await sql<
    { schema: number; identity: boolean; direct: boolean }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v40())::integer AS schema,
           app.platform_identity_runtime_schema_readiness_v6() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
  `;
  assert.deepEqual(mfaUnsupported, {
    schema: 0,
    identity: false,
    direct: false,
  });

  await migrate(drizzle(sql), { migrationsFolder: v41Stage });
  await seal(184);
  const [v41] = await sql<
    { schema: number; identity: boolean; direct: boolean; mfa: boolean }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v41())::integer AS schema,
           app.platform_identity_runtime_schema_readiness_v7() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v3() AS direct,
           app.mfa_policy_administration_schema_readiness_v1() AS mfa
  `;
  assert.deepEqual(v41, {
    schema: 184,
    identity: true,
    direct: true,
    mfa: true,
  });

  await migrate(drizzle(sql), { migrationsFolder: v42RuntimeStage });
  await migrate(drizzle(sql), { migrationsFolder: v42CompatibilityStage });
  await migrate(drizzle(sql), { migrationsFolder: stoppedAt186Stage });
  const [unsupported] = await sql<
    { count: number; schema: number; v42Absent: boolean }[]
  >`
    SELECT (SELECT count(*)::integer FROM drizzle.__drizzle_migrations) AS count,
           (SELECT applied_count FROM app.schema_compatibility_v41())::integer AS schema,
           to_regprocedure('app.schema_compatibility_v42()') IS NULL AS "v42Absent"
  `;
  assert.deepEqual(unsupported, { count: 187, schema: 0, v42Absent: true });
  await assertRuntimeACLClosed();

  await migrate(drizzle(sql), { migrationsFolder: v42Stage });
  await seal(188);
  const [v42] = await sql<
    {
      schema: number;
      mfa: boolean;
      identity: boolean;
      oidc: boolean;
      saml: boolean;
    }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v42())::integer AS schema,
           app.mfa_policy_administration_schema_readiness_v2() AS mfa,
           app.platform_identity_runtime_schema_readiness_v8() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v4() AS oidc,
           app.platform_saml_direct_runtime_schema_readiness_v1() AS saml
  `;
  assert.deepEqual(v42, {
    schema: 188,
    mfa: true,
    identity: true,
    oidc: true,
    saml: true,
  });

  await seedProjection();
  await assert.rejects(
    () => loadProjection(),
    (error) => assertSqlState(error, "42702"),
  );

  await sql.unsafe(
    "ALTER FUNCTION app.load_platform_saml_metadata_projection_v1(text) SECURITY INVOKER",
  );
  await assert.rejects(
    () => migrate(drizzle(sql), { migrationsFolder: fixedStage }),
    (error) => assertMigrationSqlState(error, "55000"),
  );
  const [stoppedAfterTamper] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM drizzle.__drizzle_migrations
  `;
  assert.equal(stoppedAfterTamper?.count, 188);
  await sql.unsafe(
    "ALTER FUNCTION app.load_platform_saml_metadata_projection_v1(text) SECURITY DEFINER",
  );

  await migrate(drizzle(sql), { migrationsFolder: fixedStage });
  const [fixed] = await sql<
    { count: number; v42Schema: number; v42SAML: boolean; v43Absent: boolean }[]
  >`
    SELECT (SELECT count(*)::integer FROM drizzle.__drizzle_migrations) AS count,
           (SELECT applied_count FROM app.schema_compatibility_v42())::integer AS "v42Schema",
           app.platform_saml_direct_runtime_schema_readiness_v1() AS "v42SAML",
           to_regprocedure('app.schema_compatibility_v43()') IS NULL AS "v43Absent"
  `;
  assert.deepEqual(fixed, {
    count: 189,
    v42Schema: 0,
    v42SAML: false,
    v43Absent: true,
  });
  await assertRuntimeACLClosed();
  await assertProjectionACLClosed();
  assertProjection(await loadProjection());

  await migrate(drizzle(sql), { migrationsFolder: v43Stage });
  const [unsealed] = await sql<
    {
      schema: number;
      mfa: boolean;
      identity: boolean;
      oidc: boolean;
      saml: boolean;
    }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v43())::integer AS schema,
           app.mfa_policy_administration_schema_readiness_v3() AS mfa,
           app.platform_identity_runtime_schema_readiness_v9() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v5() AS oidc,
           app.platform_saml_direct_runtime_schema_readiness_v2() AS saml
  `;
  assert.deepEqual(unsealed, {
    schema: 0,
    mfa: false,
    identity: false,
    oidc: false,
    saml: false,
  });

  const latest = expectedMigrations[189];
  assert(latest);
  await assert.rejects(
    () =>
      sql.begin(async (transaction) => {
        await transaction.unsafe(
          "ALTER FUNCTION app.load_platform_saml_metadata_projection_v1(text) SECURITY INVOKER",
        );
        await transaction`
          SELECT app.seal_schema_compatibility_manifest(
            190::bigint,${latest.createdAt}::bigint,${latest.hash}::text,
            ${fingerprint(190)}::text
          )
        `;
      }),
    (error) => assertSqlState(error, "55000"),
  );
  await assertProjectionACLClosed();

  await seal(190);
  const [v43] = await sql<
    {
      schema: number;
      mfa: boolean;
      identity: boolean;
      oidc: boolean;
      saml: boolean;
    }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v43())::integer AS schema,
           app.mfa_policy_administration_schema_readiness_v3() AS mfa,
           app.platform_identity_runtime_schema_readiness_v9() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v5() AS oidc,
           app.platform_saml_direct_runtime_schema_readiness_v2() AS saml
  `;
  assert.deepEqual(v43, {
    schema: 190,
    mfa: true,
    identity: true,
    oidc: true,
    saml: true,
  });
  assertProjection(await loadProjection());

  const [retired] = await sql<{ retired: boolean }[]>`
    SELECT NOT has_function_privilege(
      'periapsis_api','app.schema_compatibility_v42()','EXECUTE'
    ) AND NOT has_function_privilege(
      'periapsis_api',
      'app.platform_identity_runtime_schema_readiness_v8()','EXECUTE'
    ) AND NOT has_function_privilege(
      'periapsis_api',
      'app.platform_oidc_direct_runtime_schema_readiness_v4()','EXECUTE'
    ) AND NOT has_function_privilege(
      'periapsis_api',
      'app.platform_saml_direct_runtime_schema_readiness_v1()','EXECUTE'
    ) AND NOT has_function_privilege(
      'periapsis_api',
      'app.mfa_policy_administration_schema_readiness_v2()','EXECUTE'
    ) AS retired
  `;
  assert.equal(retired?.retired, true);
  assert.equal(expectedMigrationHash, expectedMigrations.at(-1)?.hash);
  assert.equal(
    expectedMigrationFingerprint,
    expectedMigrations
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":"),
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
