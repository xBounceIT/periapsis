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
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
  expectedPlatformIdentityRuntimeReadinessV4SourceHash,
  expectedPlatformIdentityRuntimeReadinessV5SourceHash,
  expectedPlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV1SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV5SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV5SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV1SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV1SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedRetiredSchemaCompatibilityV38SourceHash,
  expectedRetiredSchemaCompatibilityV39SourceHash,
  expectedSchemaCompatibilityV39SourceHash,
  expectedSchemaCompatibilityV40SourceHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker";
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
    throw new Error("Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

function assertSqlState(error: unknown, code: string): boolean {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, code, error.message);
  return true;
}

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_OIDC_DIRECT_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_OIDC_DIRECT_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d6ea0-9000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  operator: uuid(1),
  accountUser: uuid(2),
  operatorGrant: uuid(3),
  operatorSession: uuid(4),
  operatorFamily: uuid(5),
  provider: uuid(10),
  providerCommand: uuid(11),
  providerAudit: uuid(12),
  account: uuid(20),
  accountCommand: uuid(21),
  accountAudit: uuid(22),
  totpCredential: uuid(30),
} as const;

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = 176;
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const v39Index = 179;
const v39Entries = journal.entries.slice(0, v39Index + 1);
const runtimeEntries = journal.entries.slice(0, v39Index + 2);
const v40Entries = journal.entries.slice(0, v39Index + 3);
const v40Latest = expectedMigrations[v39Index + 2];
assert.equal(predecessorEntries.length, 177);
assert.equal(
  predecessorEntries.at(-1)?.tag,
  "0176_platform_identity_account_observation_compatibility",
);
assert.equal(journal.entries.at(177)?.tag, "0177_aspiring_mojo");
assert.equal(journal.entries.at(178)?.tag, "0178_platform_oidc_direct_runtime");
assert.equal(
  journal.entries.at(179)?.tag,
  "0179_platform_oidc_direct_compatibility",
);
assert.equal(
  journal.entries.at(180)?.tag,
  "0180_platform_oidc_direct_administration",
);
assert.equal(
  journal.entries.at(181)?.tag,
  "0181_platform_oidc_direct_administration_compatibility",
);
assert.equal(expectedMigrationCount, 238);
assert.equal(expectedMigrationCreatedAt, 1788790964334);
assert.equal(expectedMigrationCount, expectedMigrations.length);
assert.equal(expectedMigrationHash, expectedMigrations.at(-1)?.hash);
assert.equal(
  expectedMigrations
    .map((entry) => `${entry.createdAt}@${entry.hash}`)
    .join(":"),
  expectedMigrationFingerprint,
);
const predecessorFingerprint = expectedMigrations
  .slice(0, predecessorIndex + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
const v39Fingerprint = expectedMigrations
  .slice(0, v39Index + 1)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
const v40Fingerprint = expectedMigrations
  .slice(0, v39Index + 3)
  .map((entry) => `${entry.createdAt}@${entry.hash}`)
  .join(":");
assert(v40Latest);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-platform-oidc-direct-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const activeKeyVersion = 32_767;
const issuer = "https://platform-direct-upgrade-idp.example.invalid";
const directRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/platform/oidc/callback";
const tenantRedirectUri =
  "https://periapsis.example.invalid/api/v1/auth/federated/oidc/callback";
let sequence = 1_000;

function nextUuid(): string {
  sequence += 1;
  return uuid(sequence);
}

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`platform-oidc-direct-upgrade:${label}`)
    .digest();
}

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

async function asRole<T>(
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const wrapped = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', '', true),
             set_config('app.user_id', ${fixture.operator}, true),
             set_config('app.service_account_id', '', true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

async function createProviderV2(): Promise<void> {
  const configuration = {
    issuer,
    clientId: "periapsis-platform-direct-upgrade",
    redirectUri: directRedirectUri,
    postLogoutRedirectUri: "https://periapsis.example.invalid/login",
    extraScopes: ["groups"],
    allowRefreshToken: false,
    useUserInfo: true,
  } as const;
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      { providerId: string; version: number; replayed: boolean }[]
    >`
      SELECT result.provider_id AS "providerId",
             result.version::integer AS version,
             result.replayed
      FROM app.create_platform_oidc_auth_provider_v2(
        ${fixture.operatorSession}::uuid, ${fixture.providerCommand}::uuid,
        ${fixture.provider}::uuid, 'platform_direct_upgrade'::text,
        'Platform direct upgrade'::text,
        'Dormant direct platform OIDC rolling-upgrade fixture'::text,
        ${JSON.stringify(configuration)}::jsonb,
        ${tenantRedirectUri}::text,
        ${digest("provider-key")}::bytea,
        ${digest("provider-request")}::bytea,
        ${fixture.providerAudit}::uuid, ${nextUuid()}::uuid,
        ${nextUuid()}::uuid, '198.51.100.92'::inet,
        'Periapsis platform direct OIDC upgrade proof'::text,
        'totp'::text, 'Create dormant direct upgrade provider'::text
      ) AS result
    `,
  );
  assert.deepEqual(created, {
    providerId: fixture.provider,
    version: 1,
    replayed: false,
  });
}

async function prelinkAccountV2(): Promise<void> {
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<
      { accountId: string; version: number; replayed: boolean }[]
    >`
      SELECT result.account_id AS "accountId",
             result.version::integer AS version,
             result.replayed
      FROM app.prelink_platform_identity_account_v2(
        ${fixture.operatorSession}::uuid, ${fixture.accountCommand}::uuid,
        ${fixture.account}::uuid, ${fixture.provider}::uuid,
        ${fixture.accountUser}::uuid, ${issuer}::text,
        'utf8_exact'::public.identity_subject_format,
        ${Buffer.alloc(32, 0x63)}::bytea, ${Buffer.alloc(12, 0x6e)}::bytea,
        ${activeKeyVersion}::integer, ARRAY[${activeKeyVersion}]::integer[],
        ARRAY[${digest("subject-alias")}::bytea]::bytea[],
        ${digest("account-key")}::bytea,
        ${digest("account-request")}::bytea,
        ${fixture.accountAudit}::uuid, ${nextUuid()}::uuid,
        ${nextUuid()}::uuid, '198.51.100.92'::inet,
        'Periapsis platform direct OIDC upgrade proof'::text,
        'totp'::text, 'Prelink dormant direct upgrade account'::text
      ) AS result
    `,
  );
  assert.deepEqual(created, {
    accountId: fixture.account,
    version: 1,
    replayed: false,
  });
}

async function v38Readiness(role: RuntimeRole): Promise<boolean> {
  const [result] = await asRole(
    role,
    (transaction) => transaction<{ ready: boolean }[]>`
      SELECT app.platform_identity_runtime_schema_readiness_v4() AS ready
    `,
  );
  assert(result, `${role} v38 readiness returned no row`);
  return result.ready;
}

async function v39Readiness(
  role: RuntimeRole,
): Promise<{ identity: boolean; direct: boolean }> {
  const [result] = await asRole(
    role,
    (transaction) => transaction<{ identity: boolean; direct: boolean }[]>`
      SELECT app.platform_identity_runtime_schema_readiness_v5() AS identity,
             app.platform_oidc_direct_runtime_schema_readiness_v1() AS direct
    `,
  );
  assert(result, `${role} v39 readiness returned no row`);
  return result;
}

async function v39BinaryHealth(role: RuntimeRole): Promise<boolean> {
  const v39Latest = expectedMigrations[v39Index];
  assert(v39Latest);
  const [result] = await asRole(
    role,
    (transaction) => transaction<{ ready: boolean }[]>`
      WITH compatibility AS (
        SELECT * FROM app.schema_compatibility_v39()
      ), expected(signature, source_hash) AS (
        VALUES
          ('app.schema_compatibility_v39()',
           ${expectedSchemaCompatibilityV39SourceHash}),
          ('app.private_platform_identity_dependency_surface_hash_v5()',
           ${expectedPrivatePlatformIdentityDependencySurfaceHashV5SourceHash}),
          ('app.private_platform_identity_runtime_schema_readiness_v5()',
           ${expectedPrivatePlatformIdentityRuntimeReadinessV5SourceHash}),
          ('app.platform_identity_runtime_schema_readiness_v5()',
           ${expectedPlatformIdentityRuntimeReadinessV5SourceHash}),
          ('app.private_platform_oidc_direct_dependency_surface_hash_v1()',
           ${expectedPrivatePlatformOIDCDirectDependencySurfaceHashV1SourceHash}),
          ('app.private_platform_oidc_direct_runtime_schema_readiness_v1()',
           ${expectedPrivatePlatformOIDCDirectRuntimeReadinessV1SourceHash}),
          ('app.platform_oidc_direct_runtime_schema_readiness_v1()',
           ${expectedPlatformOIDCDirectRuntimeReadinessV1SourceHash})
      ), catalog AS (
        SELECT count(*) = 7
          AND bool_and(
            encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex') =
              expected.source_hash
          ) AS ready
        FROM expected
        JOIN pg_catalog.pg_proc AS function_row
          ON function_row.oid = expected.signature::regprocedure
      )
      SELECT coalesce(
        compatibility.applied_count = 180
        AND compatibility.latest_created_at = ${v39Latest.createdAt}::bigint
        AND compatibility.latest_hash = ${v39Latest.hash}
        AND compatibility.migration_fingerprint = ${v39Fingerprint}
        AND catalog.ready
        AND app.platform_identity_runtime_schema_readiness_v5()
        AND app.platform_oidc_direct_runtime_schema_readiness_v1(),
        false
      ) AS ready
      FROM compatibility CROSS JOIN catalog
    `,
  );
  assert(result, `${role} v39 health returned no row`);
  return result.ready;
}

async function currentReadiness(
  role: RuntimeRole,
): Promise<{ identity: boolean; direct: boolean }> {
  const [result] = await asRole(
    role,
    (transaction) => transaction<{ identity: boolean; direct: boolean }[]>`
      SELECT app.platform_identity_runtime_schema_readiness_v6() AS identity,
             app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
    `,
  );
  assert(result, `${role} v40 readiness returned no row`);
  return result;
}

async function assertRuntimeCatalog(): Promise<void> {
  const signatures = [
    "app.schema_compatibility_v38()",
    "app.private_platform_identity_dependency_surface_hash_v4()",
    "app.private_platform_identity_runtime_schema_readiness_v4()",
    "app.platform_identity_runtime_schema_readiness_v4()",
    "app.schema_compatibility_v39()",
    "app.private_platform_identity_dependency_surface_hash_v5()",
    "app.private_platform_identity_runtime_schema_readiness_v5()",
    "app.platform_identity_runtime_schema_readiness_v5()",
    "app.private_platform_oidc_direct_dependency_surface_hash_v1()",
    "app.private_platform_oidc_direct_runtime_schema_readiness_v1()",
    "app.platform_oidc_direct_runtime_schema_readiness_v1()",
    "app.schema_compatibility_v40()",
    "app.private_platform_identity_dependency_surface_hash_v6()",
    "app.private_platform_identity_runtime_schema_readiness_v6()",
    "app.platform_identity_runtime_schema_readiness_v6()",
    "app.private_platform_oidc_direct_dependency_surface_hash_v2()",
    "app.private_platform_oidc_direct_runtime_schema_readiness_v2()",
    "app.platform_oidc_direct_runtime_schema_readiness_v2()",
  ] as const;
  const expectedHashes = [
    expectedRetiredSchemaCompatibilityV38SourceHash,
    expectedPrivatePlatformIdentityDependencySurfaceHashV4SourceHash,
    expectedPrivatePlatformIdentityRuntimeReadinessV4SourceHash,
    expectedPlatformIdentityRuntimeReadinessV4SourceHash,
    expectedRetiredSchemaCompatibilityV39SourceHash,
    expectedPrivatePlatformIdentityDependencySurfaceHashV5SourceHash,
    expectedPrivatePlatformIdentityRuntimeReadinessV5SourceHash,
    expectedPlatformIdentityRuntimeReadinessV5SourceHash,
    expectedPrivatePlatformOIDCDirectDependencySurfaceHashV1SourceHash,
    expectedPrivatePlatformOIDCDirectRuntimeReadinessV1SourceHash,
    expectedPlatformOIDCDirectRuntimeReadinessV1SourceHash,
    expectedSchemaCompatibilityV40SourceHash,
    expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
    expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
    expectedPlatformIdentityRuntimeReadinessV6SourceHash,
    expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
    expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
    expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
  ] as const;
  const catalog = await sql<
    { signature: string; owner: string; sourceHash: string }[]
  >`
    SELECT expected.signature,
           owner.rolname AS owner,
           encode(sha256(convert_to(function.prosrc, 'UTF8')), 'hex')
             AS "sourceHash"
    FROM unnest(${signatures}::text[]) WITH ORDINALITY
      AS expected(signature, ordinal)
    JOIN pg_catalog.pg_proc AS function
      ON function.oid = to_regprocedure(expected.signature)
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
    ORDER BY expected.ordinal
  `;
  assert.deepEqual(
    Array.from(catalog),
    signatures.map((signature, index) => ({
      signature,
      owner: "periapsis_migrator",
      sourceHash: expectedHashes[index],
    })),
  );
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(server?.version.startsWith("18.6"));

  const predecessorStage = await writeStage("v38", predecessorEntries);
  const v39Stage = await writeStage("v39", v39Entries);
  const runtimeStage = await writeStage("v40-runtime", runtimeEntries);
  const sealStage = await writeStage("v40-seal", v40Entries);
  await migrate(drizzle(sql), { migrationsFolder: predecessorStage });
  const [predecessorJournal] = await sql<
    { count: number; latestCreatedAt: string; latestHash: string }[]
  >`
    SELECT count(*)::integer AS count,
           max(created_at)::text AS "latestCreatedAt",
           (SELECT lower(latest.hash::text)
            FROM drizzle.__drizzle_migrations AS latest
            ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1)
             AS "latestHash"
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(predecessorJournal, {
    count: 177,
    latestCreatedAt: String(expectedMigrations[predecessorIndex]?.createdAt),
    latestHash: expectedMigrations[predecessorIndex]?.hash,
  });
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      177::bigint,
      ${expectedMigrations[predecessorIndex]?.createdAt}::bigint,
      ${expectedMigrations[predecessorIndex]?.hash}::text,
      ${predecessorFingerprint}::text
    )
  `;

  const [predecessorCompatibility] = await sql<
    { count: number; latestHash: string; fingerprint: string }[]
  >`
    SELECT applied_count::integer AS count,
           latest_hash AS "latestHash",
           migration_fingerprint AS fingerprint
    FROM app.schema_compatibility_v38()
  `;
  assert.deepEqual(predecessorCompatibility, {
    count: 177,
    latestHash: expectedMigrations[predecessorIndex]?.hash,
    fingerprint: predecessorFingerprint,
  });
  assert.equal(await v38Readiness("periapsis_api"), true);
  assert.equal(await v38Readiness("periapsis_worker"), true);

  const now = new Date(Date.now() - 60_000).toISOString();
  const expires = new Date(Date.now() + 60 * 60_000).toISOString();
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.operator}::uuid,
         'platform-direct-upgrade.operator@example.invalid',
         'Platform direct upgrade operator'),
        (${fixture.accountUser}::uuid,
         'platform-direct-upgrade.account@example.invalid',
         'Platform direct upgrade account')
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id, user_id, role_id, granted_by_user_id, granted_at
      )
      SELECT ${fixture.operatorGrant}::uuid, ${fixture.operator}::uuid,
             role.id, ${fixture.operator}::uuid, ${now}
      FROM public.platform_roles AS role
      WHERE role.key = 'platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES (
        ${fixture.operatorSession}::uuid, ${fixture.operator}::uuid,
        ${fixture.operatorFamily}::uuid, NULL,
        ${digest("operator-token")}::bytea,
        ${digest("operator-csrf")}::bytea, 'totp', ${now}, ${now},
        ${expires}, ${expires}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES (
        ${activeKeyVersion}, ${digest("active-key")}::bytea, true
      )
    `;
    await transaction`
      INSERT INTO public.totp_credentials (
        id, user_id, secret_ciphertext, secret_nonce, secret_aad,
        key_version, encryption_algorithm, otp_algorithm, digits,
        period_seconds, confirmed_at, last_accepted_counter,
        created_at, updated_at
      ) VALUES (
        ${fixture.totpCredential}::uuid, ${fixture.accountUser}::uuid,
        ${Buffer.alloc(32, 0x74)}::bytea,
        ${Buffer.alloc(12, 0x6e)}::bytea,
        ${digest("totp-aad")}::bytea, ${activeKeyVersion},
        'aes-256-gcm', 'SHA1', 6, 30, ${now}, 41, ${now}, ${now}
      )
    `;
  });
  await createProviderV2();
  await prelinkAccountV2();

  const [preV39Shape] = await sql<
    {
      loginPolicyTable: string | null;
      authRevisionColumn: number;
      factorRevisionColumn: number;
    }[]
  >`
    SELECT to_regclass('public.platform_oidc_login_policies')::text
             AS "loginPolicyTable",
           count(*) FILTER (
             WHERE column_row.attrelid = 'public.users'::regclass
               AND column_row.attname = 'authentication_revision'
           )::integer AS "authRevisionColumn",
           count(*) FILTER (
             WHERE column_row.attrelid = 'public.totp_credentials'::regclass
               AND column_row.attname = 'security_revision'
           )::integer AS "factorRevisionColumn"
    FROM pg_catalog.pg_attribute AS column_row
  `;
  assert.deepEqual(preV39Shape, {
    loginPolicyTable: null,
    authRevisionColumn: 0,
    factorRevisionColumn: 0,
  });

  await migrate(drizzle(sql), { migrationsFolder: v39Stage });
  const v39Latest = expectedMigrations[v39Index];
  assert(v39Latest);
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      180::bigint,${v39Latest.createdAt}::bigint,${v39Latest.hash}::text,
      ${v39Fingerprint}::text
    )
  `;

  const [backfill] = await sql<
    {
      accountMode: string;
      enabled: boolean;
      revision: number;
      loginPolicyCount: number;
      platformLoginEnabled: boolean;
      providerCount: number;
      accountCount: number;
      userAuthenticationRevision: number;
      totpSecurityRevision: number;
      lastAcceptedCounter: number;
    }[]
  >`
    SELECT policy.account_mode AS "accountMode",
           policy.enabled,
           policy.revision::integer AS revision,
           (SELECT count(*)::integer
            FROM ONLY public.platform_oidc_login_policies AS candidate
            WHERE candidate.provider_id = ${fixture.provider}::uuid)
             AS "loginPolicyCount",
           runtime_policy.platform_login_enabled AS "platformLoginEnabled",
           (SELECT count(*)::integer
            FROM ONLY public.platform_auth_providers AS provider
            WHERE provider.id = ${fixture.provider}::uuid) AS "providerCount",
           (SELECT count(*)::integer
            FROM ONLY public.platform_federated_external_identities AS identity
            WHERE identity.id = ${fixture.account}::uuid
              AND identity.user_id = ${fixture.accountUser}::uuid
              AND identity.retired_at IS NULL) AS "accountCount",
           local_user.authentication_revision::integer
             AS "userAuthenticationRevision",
           factor.security_revision::integer AS "totpSecurityRevision",
           factor.last_accepted_counter::integer AS "lastAcceptedCounter"
    FROM ONLY public.platform_oidc_login_policies AS policy
    JOIN ONLY public.users AS local_user
      ON local_user.id = ${fixture.accountUser}::uuid
    JOIN ONLY public.totp_credentials AS factor
      ON factor.id = ${fixture.totpCredential}::uuid
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = policy.provider_id
     AND runtime_policy.provider_kind = policy.provider_kind
    WHERE policy.provider_id = ${fixture.provider}::uuid
      AND policy.provider_kind = 'oidc'
  `;
  assert.deepEqual(backfill, {
    accountMode: "disabled",
    enabled: false,
    revision: 1,
    loginPolicyCount: 1,
    platformLoginEnabled: false,
    providerCount: 1,
    accountCount: 1,
    userAuthenticationRevision: 1,
    totpSecurityRevision: 1,
    lastAcceptedCounter: 41,
  });

  const [begin] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ document: unknown }[]>`
      SELECT app.begin_platform_oidc_authentication_v1(
        ${JSON.stringify({
          loginKey: "platform_direct_upgrade",
        })}::jsonb
      ) AS document
    `,
  );
  assert(begin, "direct platform OIDC begin returned no projection row");
  assert.equal(begin.document, null, "dormant direct login must fail closed");

  const retiredFunctions = [
    "app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
  ] as const;
  const currentFunctions = [
    "app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
    "app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
  ] as const;
  const retiredReadinessFunctions = [
    "app.schema_compatibility_v38()",
    "app.platform_identity_runtime_schema_readiness_v4()",
  ] as const;
  const currentReadinessFunctions = [
    "app.schema_compatibility_v39()",
    "app.platform_identity_runtime_schema_readiness_v5()",
    "app.platform_oidc_direct_runtime_schema_readiness_v1()",
  ] as const;
  const [acl] = await sql<
    {
      retiredApi: boolean;
      retiredWorker: boolean;
      retiredMigrator: boolean;
      currentApi: boolean;
      currentWorker: boolean;
      currentMigrator: boolean;
      retiredReadinessApi: boolean;
      retiredReadinessWorker: boolean;
      currentReadinessApi: boolean;
      currentReadinessWorker: boolean;
    }[]
  >`
    SELECT NOT bool_or(has_function_privilege(
             'periapsis_api', retired.signature, 'EXECUTE'
           )) AS "retiredApi",
           NOT bool_or(has_function_privilege(
             'periapsis_worker', retired.signature, 'EXECUTE'
           )) AS "retiredWorker",
           bool_and(has_function_privilege(
             'periapsis_migrator', retired.signature, 'EXECUTE'
           )) AS "retiredMigrator",
           bool_and(has_function_privilege(
             'periapsis_api', current_function.signature, 'EXECUTE'
           )) AS "currentApi",
           NOT bool_or(has_function_privilege(
             'periapsis_worker', current_function.signature, 'EXECUTE'
           )) AS "currentWorker",
           bool_and(has_function_privilege(
             'periapsis_migrator', current_function.signature, 'EXECUTE'
           )) AS "currentMigrator",
           NOT bool_or(has_function_privilege(
             'periapsis_api', retired_readiness.signature, 'EXECUTE'
           )) AS "retiredReadinessApi",
           NOT bool_or(has_function_privilege(
             'periapsis_worker', retired_readiness.signature, 'EXECUTE'
           )) AS "retiredReadinessWorker",
           bool_and(has_function_privilege(
             'periapsis_api', current_readiness.signature, 'EXECUTE'
           )) AS "currentReadinessApi",
           bool_and(has_function_privilege(
             'periapsis_worker', current_readiness.signature, 'EXECUTE'
           )) AS "currentReadinessWorker"
    FROM unnest(${retiredFunctions}::text[]) AS retired(signature)
    CROSS JOIN unnest(${currentFunctions}::text[]) AS current_function(signature)
    CROSS JOIN unnest(${retiredReadinessFunctions}::text[])
      AS retired_readiness(signature)
    CROSS JOIN unnest(${currentReadinessFunctions}::text[])
      AS current_readiness(signature)
  `;
  assert.deepEqual(acl, {
    retiredApi: true,
    retiredWorker: true,
    retiredMigrator: true,
    currentApi: true,
    currentWorker: true,
    currentMigrator: true,
    retiredReadinessApi: true,
    retiredReadinessWorker: true,
    currentReadinessApi: true,
    currentReadinessWorker: true,
  });

  const [retiredV38] = await sql<{ retired: boolean }[]>`
    SELECT coalesce(function.proconfig, ARRAY[]::text[]) @>
             ARRAY['app.schema_compatibility_fingerprint=RETIRED']::text[]
             AS retired
    FROM pg_catalog.pg_proc AS function
    WHERE function.oid = 'app.schema_compatibility_v38()'::regprocedure
  `;
  assert.equal(retiredV38?.retired, true);

  assert.deepEqual(await v39Readiness("periapsis_api"), {
    identity: true,
    direct: true,
  });
  assert.deepEqual(await v39Readiness("periapsis_worker"), {
    identity: true,
    direct: true,
  });
  assert.equal(await v39BinaryHealth("periapsis_api"), true);
  assert.equal(await v39BinaryHealth("periapsis_worker"), true);

  const [v39Compatibility] = await sql<
    {
      count: number;
      latestCreatedAt: string;
      latestHash: string;
      fingerprint: string;
    }[]
  >`
    SELECT applied_count::integer AS count,
           latest_created_at::text AS "latestCreatedAt",
           latest_hash AS "latestHash",
           migration_fingerprint AS fingerprint
    FROM app.schema_compatibility_v39()
  `;
  assert.deepEqual(v39Compatibility, {
    count: 180,
    latestCreatedAt: String(expectedMigrations[v39Index]?.createdAt),
    latestHash: expectedMigrations[v39Index]?.hash,
    fingerprint: v39Fingerprint,
  });

  await migrate(drizzle(sql), { migrationsFolder: runtimeStage });
  const [unsupportedInterval] = await sql<
    { count: number; v40Root: string | null; v39SourceHash: string }[]
  >`
    SELECT (SELECT count(*)::integer
            FROM drizzle.__drizzle_migrations) AS count,
           to_regprocedure('app.schema_compatibility_v40()')::text
             AS "v40Root",
           encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex')
             AS "v39SourceHash"
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid = 'app.schema_compatibility_v39()'::regprocedure
  `;
  assert.deepEqual(unsupportedInterval, {
    count: 181,
    v40Root: null,
    v39SourceHash: expectedSchemaCompatibilityV39SourceHash,
  });
  assert.equal(await v39BinaryHealth("periapsis_api"), false);
  assert.equal(await v39BinaryHealth("periapsis_worker"), false);
  assert.deepEqual(await v39Readiness("periapsis_api"), {
    identity: false,
    direct: false,
  });

  await migrate(drizzle(sql), { migrationsFolder: sealStage });
  const [preSeal] = await sql<{ count: number; compatibilityCount: number }[]>`
    SELECT (SELECT count(*)::integer
            FROM drizzle.__drizzle_migrations) AS count,
           compatibility.applied_count::integer AS "compatibilityCount"
    FROM app.schema_compatibility_v40() AS compatibility
  `;
  assert.deepEqual(preSeal, { count: 182, compatibilityCount: 0 });
  assert.equal(await v39BinaryHealth("periapsis_api"), false);
  await sql`
    SELECT app.seal_schema_compatibility_manifest(
      182::bigint,
      ${v40Latest.createdAt}::bigint,
      ${v40Latest.hash}::text,
      ${v40Fingerprint}::text
    )
  `;
  const predecessorReadinessFunctions = [
    "app.schema_compatibility_v39()",
    "app.platform_identity_runtime_schema_readiness_v5()",
    "app.platform_oidc_direct_runtime_schema_readiness_v1()",
  ] as const;
  const activeReadinessFunctions = [
    "app.schema_compatibility_v40()",
    "app.platform_identity_runtime_schema_readiness_v6()",
    "app.platform_oidc_direct_runtime_schema_readiness_v2()",
  ] as const;
  const [cutoverAcl] = await sql<
    {
      predecessorApi: boolean;
      predecessorWorker: boolean;
      predecessorMigrator: boolean;
      activeApi: boolean;
      activeWorker: boolean;
      activeMigrator: boolean;
    }[]
  >`
    SELECT NOT bool_or(has_function_privilege(
             'periapsis_api', predecessor.signature, 'EXECUTE'
           )) AS "predecessorApi",
           NOT bool_or(has_function_privilege(
             'periapsis_worker', predecessor.signature, 'EXECUTE'
           )) AS "predecessorWorker",
           bool_and(has_function_privilege(
             'periapsis_migrator', predecessor.signature, 'EXECUTE'
           )) AS "predecessorMigrator",
           bool_and(has_function_privilege(
             'periapsis_api', active.signature, 'EXECUTE'
           )) AS "activeApi",
           bool_and(has_function_privilege(
             'periapsis_worker', active.signature, 'EXECUTE'
           )) AS "activeWorker",
           bool_and(has_function_privilege(
             'periapsis_migrator', active.signature, 'EXECUTE'
           )) AS "activeMigrator"
    FROM unnest(${predecessorReadinessFunctions}::text[])
      AS predecessor(signature)
    CROSS JOIN unnest(${activeReadinessFunctions}::text[])
      AS active(signature)
  `;
  assert.deepEqual(cutoverAcl, {
    predecessorApi: true,
    predecessorWorker: true,
    predecessorMigrator: true,
    activeApi: true,
    activeWorker: true,
    activeMigrator: true,
  });
  await assert.rejects(v39BinaryHealth("periapsis_api"), (error: unknown) =>
    assertSqlState(error, "42501"),
  );
  const [retiredV39] = await sql<{ retired: boolean; sourceHash: string }[]>`
    SELECT coalesce(function_row.proconfig, ARRAY[]::text[]) @>
             ARRAY['app.schema_compatibility_fingerprint=RETIRED']::text[]
             AS retired,
           encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex')
             AS "sourceHash"
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid = 'app.schema_compatibility_v39()'::regprocedure
  `;
  assert.deepEqual(retiredV39, {
    retired: true,
    sourceHash: expectedRetiredSchemaCompatibilityV39SourceHash,
  });
  assert.deepEqual(await currentReadiness("periapsis_api"), {
    identity: true,
    direct: true,
  });
  assert.deepEqual(await currentReadiness("periapsis_worker"), {
    identity: true,
    direct: true,
  });
  await assertRuntimeCatalog();

  const [compatibility] = await sql<
    {
      count: number;
      latestCreatedAt: string;
      latestHash: string;
      fingerprint: string;
    }[]
  >`
    SELECT applied_count::integer AS count,
           latest_created_at::text AS "latestCreatedAt",
           latest_hash AS "latestHash",
           migration_fingerprint AS fingerprint
    FROM app.schema_compatibility_v40()
  `;
  assert.deepEqual(compatibility, {
    count: 182,
    latestCreatedAt: String(v40Latest.createdAt),
    latestHash: v40Latest.hash,
    fingerprint: v40Fingerprint,
  });

  const alteredLatestHash = `${v40Latest.hash[0] === "0" ? "1" : "0"}${v40Latest.hash.slice(1)}`;
  await assert.rejects(
    sql`
      SELECT app.seal_schema_compatibility_manifest(
        182::bigint,
        ${v40Latest.createdAt}::bigint,
        ${alteredLatestHash}::text,
        ${v40Fingerprint}::text
      )
    `,
    (error: unknown) => assertSqlState(error, "55000"),
  );

  const rollbackMarker = { kind: "readiness rollback" } as const;
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction`
        DELETE FROM drizzle.__drizzle_migrations
        WHERE created_at = ${v40Latest.createdAt}
      `;
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [downgraded] = await transaction<
        { identity: boolean; direct: boolean }[]
      >`
        SELECT app.platform_identity_runtime_schema_readiness_v6() AS identity,
               app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
      `;
      assert.deepEqual(downgraded, { identity: false, direct: false });
      throw rollbackMarker;
    }),
    (error: unknown) => error === rollbackMarker,
  );
  assert.deepEqual(await currentReadiness("periapsis_api"), {
    identity: true,
    direct: true,
  });

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe(
        "ALTER FUNCTION app.begin_platform_oidc_authentication_v1(jsonb) VOLATILE",
      );
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.platform_oidc_direct_runtime_schema_readiness_v2() AS ready
      `;
      assert.equal(tampered?.ready, false);
      throw rollbackMarker;
    }),
    (error: unknown) => error === rollbackMarker,
  );
  assert.deepEqual(await currentReadiness("periapsis_api"), {
    identity: true,
    direct: true,
  });

  const beforeIdempotence = { backfill, compatibility };
  await migrate(drizzle(sql), { migrationsFolder: sealStage });
  const [idempotentJournal] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM drizzle.__drizzle_migrations
  `;
  const [idempotentBackfill] = await sql<
    {
      accountMode: string;
      enabled: boolean;
      revision: number;
      userAuthenticationRevision: number;
      totpSecurityRevision: number;
      lastAcceptedCounter: number;
    }[]
  >`
    SELECT policy.account_mode AS "accountMode", policy.enabled,
           policy.revision::integer AS revision,
           local_user.authentication_revision::integer
             AS "userAuthenticationRevision",
           factor.security_revision::integer AS "totpSecurityRevision",
           factor.last_accepted_counter::integer AS "lastAcceptedCounter"
    FROM ONLY public.platform_oidc_login_policies AS policy
    JOIN ONLY public.users AS local_user
      ON local_user.id = ${fixture.accountUser}::uuid
    JOIN ONLY public.totp_credentials AS factor
      ON factor.id = ${fixture.totpCredential}::uuid
    WHERE policy.provider_id = ${fixture.provider}::uuid
  `;
  assert.equal(idempotentJournal?.count, 182);
  assert.deepEqual(idempotentBackfill, {
    accountMode: beforeIdempotence.backfill?.accountMode,
    enabled: beforeIdempotence.backfill?.enabled,
    revision: beforeIdempotence.backfill?.revision,
    userAuthenticationRevision:
      beforeIdempotence.backfill?.userAuthenticationRevision,
    totpSecurityRevision: beforeIdempotence.backfill?.totpSecurityRevision,
    lastAcceptedCounter: beforeIdempotence.backfill?.lastAcceptedCounter,
  });
  const [idempotentCompatibility] = await sql<
    { count: number; latestHash: string; fingerprint: string }[]
  >`
    SELECT applied_count::integer AS count, latest_hash AS "latestHash",
           migration_fingerprint AS fingerprint
    FROM app.schema_compatibility_v40()
  `;
  assert.deepEqual(idempotentCompatibility, {
    count: beforeIdempotence.compatibility?.count,
    latestHash: beforeIdempotence.compatibility?.latestHash,
    fingerprint: beforeIdempotence.compatibility?.fingerprint,
  });
  assert.deepEqual(await currentReadiness("periapsis_api"), {
    identity: true,
    direct: true,
  });

  process.stdout.write(
    "direct platform OIDC v40 coordinated-cutover proof passed\n",
  );
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
