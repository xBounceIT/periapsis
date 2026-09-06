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
  expectedMigrationFingerprint,
  expectedMigrationHash,
  expectedMigrations,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

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

const databaseUrl =
  process.env.PERIAPSIS_MFA_POLICY_ADMIN_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_MFA_POLICY_ADMIN_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const parsedJournal: unknown = JSON.parse(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
assert(isJournal(parsedJournal));
const journal = parsedJournal;
assert.equal(journal.entries.length, 232);
assert.equal(expectedMigrationCount, 234);
assert.equal(
  journal.entries[181]?.tag,
  "0181_platform_oidc_direct_administration_compatibility",
);
assert.equal(journal.entries[182]?.tag, "0182_mfa_policy_administration");
assert.equal(
  journal.entries[183]?.tag,
  "0183_mfa_policy_administration_compatibility",
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-mfa-policy-upgrade-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

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

try {
  const [version] = await sql<{ version: number }[]>`
    SELECT current_setting('server_version_num')::integer AS version
  `;
  assert(version !== undefined && version.version >= 180_000);

  const predecessor = await writeStage("v40", journal.entries.slice(0, 182));
  const runtime = await writeStage("runtime", journal.entries.slice(0, 183));
  const complete = await writeStage("complete", journal.entries.slice(0, 184));

  await migrate(drizzle(sql), { migrationsFolder: predecessor });
  await seal(182);
  const [v40] = await sql<
    { schema: number; identity: boolean; direct: boolean }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v40())::integer AS schema,
           app.platform_identity_runtime_schema_readiness_v6() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
  `;
  assert.deepEqual(v40, { schema: 182, identity: true, direct: true });

  const tenant = "019d7000-2000-7000-8000-000000000001";
  const user = "019d7000-2000-7000-8000-000000000002";
  const membership = "019d7000-2000-7000-8000-000000000003";
  await sql`
    INSERT INTO public.tenants (id,slug,name,status)
    VALUES (${tenant}::uuid,'mfa-policy-upgrade','MFA policy upgrade','active')
  `;
  await sql`
    INSERT INTO public.users (id,email,display_name)
    VALUES (${user}::uuid,'mfa-upgrade@example.invalid','MFA upgrade administrator')
  `;
  await sql`
    INSERT INTO public.tenant_memberships (id,tenant_id,user_id,role,status)
    VALUES (${membership}::uuid,${tenant}::uuid,${user}::uuid,'tenant_admin','active')
  `;
  await sql`SELECT app.seed_tenant_authorization(${tenant}::uuid,${membership}::uuid)`;

  await migrate(drizzle(sql), { migrationsFolder: runtime });
  const [unsupported] = await sql<
    { schema: number; identity: boolean; direct: boolean }[]
  >`
    SELECT (SELECT applied_count FROM app.schema_compatibility_v40())::integer AS schema,
           app.platform_identity_runtime_schema_readiness_v6() AS identity,
           app.platform_oidc_direct_runtime_schema_readiness_v2() AS direct
  `;
  assert.deepEqual(unsupported, { schema: 0, identity: false, direct: false });
  const [runtimeShape] = await sql<
    {
      policies: string | null;
      commands: string | null;
      permissionCount: number;
    }[]
  >`
    SELECT to_regclass('public.mfa_policy_revisions')::text AS policies,
           to_regclass('public.mfa_policy_commands')::text AS commands,
           (SELECT count(*)::integer
            FROM public.tenant_roles AS role
            JOIN public.tenant_role_permissions AS role_permission
              ON role_permission.tenant_id = role.tenant_id
             AND role_permission.role_id = role.id
            JOIN public.tenant_permissions AS permission
              ON permission.id = role_permission.permission_id
            JOIN public.tenant_role_delegation_ceilings AS ceiling
              ON ceiling.tenant_id = role_permission.tenant_id
             AND ceiling.role_id = role_permission.role_id
             AND ceiling.permission_id = role_permission.permission_id
             AND ceiling.scope = role_permission.scope
            WHERE role.tenant_id = ${tenant}::uuid AND role.key = 'tenant_admin'
              AND permission.key IN ('identity_policy.read','identity_policy.manage'))
             AS "permissionCount"
  `;
  assert.deepEqual(runtimeShape, {
    policies: "mfa_policy_revisions",
    commands: "mfa_policy_commands",
    permissionCount: 2,
  });

  await migrate(drizzle(sql), { migrationsFolder: complete });
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
  assert.equal(expectedMigrationHash, expectedMigrations.at(-1)?.hash);
  assert.equal(
    expectedMigrationFingerprint,
    expectedMigrations
      .map((entry) => `${entry.createdAt}@${entry.hash}`)
      .join(":"),
  );

  await sql
    .begin(async (transaction) => {
      await transaction`
      UPDATE public.tenant_permissions SET service_account_allowed = true
      WHERE key = 'identity_policy.manage'
    `;
      const [tampered] = await transaction<{ ready: boolean }[]>`
      SELECT app.mfa_policy_administration_schema_readiness_v1() AS ready
    `;
      assert.equal(tampered?.ready, false);
      throw new Error("rollback expected tamper");
    })
    .catch((error: unknown) => {
      assert(
        error instanceof Error && error.message === "rollback expected tamper",
      );
    });
  const [restored] = await sql<{ ready: boolean }[]>`
    SELECT app.mfa_policy_administration_schema_readiness_v1() AS ready
  `;
  assert.equal(restored?.ready, true);
} finally {
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
