import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function postgresState(error: unknown): string | undefined {
  let current = error;
  for (let depth = 0; depth < 8 && isRecord(current); depth += 1) {
    if (typeof current.code === "string") {
      return current.code;
    }
    current = current.cause;
  }
  return undefined;
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

const databaseUrl =
  process.env.PERIAPSIS_TENANT_PROVIDER_MFA_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_PROVIDER_MFA_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

const uuid = (sequence: number): string =>
  `019d30ab-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  pendingProvider: uuid(3),
  consumedProvider: uuid(4),
  revokedProvider: uuid(5),
  pendingPasskey: uuid(6),
  provider: uuid(7),
  binding: uuid(8),
  externalIdentity: uuid(9),
  passkeyCredential: uuid(10),
  cloneCredential: uuid(11),
  cloneAudit: uuid(12),
  cloneAnchor: uuid(13),
  membership: uuid(14),
} as const;
const cloneCeremonyId = Buffer.alloc(32, 0x41);
const cloneCredentialWireId = Buffer.alloc(32, 0x42);

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorEntries = journal.entries.slice(0, 165);
const targetEntries = journal.entries.slice(0, 166);
const readinessEntries = journal.entries.slice(0, 167);
assert.equal(
  predecessorEntries.at(-1)?.tag,
  "0164_platform_oidc_binding_lifecycle",
);
assert.equal(targetEntries.at(-1)?.tag, "0165_platform_oidc_binding_runtime");
assert.equal(
  readinessEntries.at(-1)?.tag,
  "0166_platform_oidc_binding_readiness",
);

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-tenant-provider-mfa-rolling-0164-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const writerSql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

async function enableScramLogin(login: string): Promise<string> {
  const password = randomBytes(32).toString("base64url");
  const [command] = await sql<{ statement: string }[]>`
    SELECT pg_catalog.format(
      'ALTER ROLE %I LOGIN PASSWORD %L',
      ${login}::text,
      ${password}::text
    ) AS statement
  `;
  assert(command, `could not build SCRAM provisioning command for ${login}`);
  await sql.unsafe(command.statement);
  return password;
}

async function writeStage(entries: readonly JournalEntry[]): Promise<void> {
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries }, null, 2)}\n`,
  );
  await Promise.all(
    entries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );
}

async function assertTargetNotApplied(label: string): Promise<void> {
  const [applied] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM drizzle.__drizzle_migrations
  `;
  assert.equal(
    applied?.count,
    predecessorEntries.length,
    `${label} migration attempt did not roll back atomically`,
  );
}

async function proveBusyDrainFailsWithoutDeadlock(
  order: "session_then_continuation" | "continuation_then_session",
): Promise<void> {
  let signalReady: (() => void) | undefined;
  let releaseWriter: (() => void) | undefined;
  const ready = new Promise<void>((resolveReady) => {
    signalReady = resolveReady;
  });
  const released = new Promise<void>((resolveRelease) => {
    releaseWriter = resolveRelease;
  });

  const writer = writerSql.begin(async (transaction) => {
    if (order === "session_then_continuation") {
      await transaction.unsafe(
        "LOCK TABLE ONLY public.auth_sessions IN ROW EXCLUSIVE MODE",
      );
      await transaction.unsafe(
        "LOCK TABLE ONLY public.tenant_post_primary_continuations IN ROW EXCLUSIVE MODE",
      );
    } else {
      await transaction.unsafe(
        "LOCK TABLE ONLY public.tenant_post_primary_continuations IN ROW EXCLUSIVE MODE",
      );
      await transaction.unsafe(
        "LOCK TABLE ONLY public.auth_sessions IN ROW EXCLUSIVE MODE",
      );
    }
    signalReady?.();
    await released;
  });

  await Promise.race([
    ready,
    writer.then(() => {
      throw new Error(`writer ${order} ended before the migration probe`);
    }),
  ]);
  try {
    await assert.rejects(
      migrate(drizzle(sql), { migrationsFolder: stageRoot }),
      (error: unknown) => {
        assert.equal(postgresState(error), "55P03");
        return true;
      },
      `v35 migration waited on the ${order} writer instead of failing busy`,
    );
  } finally {
    releaseWriter?.();
    await writer;
  }

  await assertTargetNotApplied(`busy ${order}`);
}

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert.equal(version?.version, "18.6");

  await mkdir(resolve(stageRoot, "meta"));
  await writeStage(predecessorEntries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });

  const createdAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  const terminalAt = new Date().toISOString();
  const cloneSnapshot = {
    outcome: "committed",
    credential: {
      credentialVersion: 4,
      status: "clone_suspected",
    },
    tenantId: fixture.tenant,
    userId: fixture.user,
    identityEpoch: 1,
    auditId: fixture.cloneAudit,
    mutation: "revoke",
    sessionVersion: 1,
    recoveryRestricted: false,
  };
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES (${fixture.tenant}::uuid,'generic-mfa-upgrade',
        'Generic MFA upgrade','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name,active,created_at,updated_at)
      VALUES (${fixture.user}::uuid,'generic-mfa-upgrade@example.invalid',
        'Generic MFA upgrade user',true,${createdAt},${createdAt})
    `;
    // The isolated 0165/0166 proof later advances through the modern tail.
    // Seed the historical tenant through the canonical authorization entry
    // point so 0182 can extend an already valid protected tenant_admin role.
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES (
        ${fixture.membership}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,'tenant_admin','active',${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,passkey_credential_id,provider_id,binding_id,provider_kind,
        external_identity_id,primary_revision,session_invalidation_epoch,
        state,version,created_at,expires_at,consumed_at,revoked_at,revoke_reason
      ) VALUES
      (${fixture.pendingProvider}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,sha256(convert_to('pending-provider','UTF8')),1,
        'session.create','api','tenant_provider',NULL,${fixture.provider}::uuid,
        ${fixture.binding}::uuid,'oidc',${fixture.externalIdentity}::uuid,
        1,1,'pending',1,${createdAt},${expiresAt},NULL,NULL,NULL),
      (${fixture.consumedProvider}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,sha256(convert_to('consumed-provider','UTF8')),1,
        'session.create','api','tenant_provider',NULL,${fixture.provider}::uuid,
        ${fixture.binding}::uuid,'oidc',${fixture.externalIdentity}::uuid,
        1,1,'consumed',2,${createdAt},${expiresAt},${terminalAt},NULL,NULL),
      (${fixture.revokedProvider}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,sha256(convert_to('revoked-provider','UTF8')),1,
        'session.create','api','tenant_provider',NULL,${fixture.provider}::uuid,
        ${fixture.binding}::uuid,'oidc',${fixture.externalIdentity}::uuid,
        1,1,'revoked',2,${createdAt},${expiresAt},NULL,${terminalAt},
        'preexisting terminal history'),
      (${fixture.pendingPasskey}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,sha256(convert_to('pending-passkey','UTF8')),1,
        'session.create','api','passkey',${fixture.passkeyCredential}::uuid,
        NULL,NULL,NULL,NULL,1,1,'pending',1,${createdAt},
        ${expiresAt},NULL,NULL,NULL)
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credentials (
        id,tenant_id,user_id,credential_id,public_key,display_name,
        user_handle_digest,rp_id,rp_revision,sign_count,discoverable,
        user_verification,backup_eligible,backed_up,aaguid,
        attestation_format,attestation_type,attestation_trusted,
        metadata_revision,status,version,security_revision,created_at,
        last_used_at,revoked_at,revoke_reason,updated_at
      ) VALUES (${fixture.cloneCredential}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,${cloneCredentialWireId},${Buffer.alloc(64, 0x51)},
        'Historical clone',${Buffer.alloc(32, 0x52)},'example.invalid',1,4,
        true,true,true,true,${Buffer.alloc(16)},'none','none',false,0,
        'clone_suspected',4,1,${createdAt},${terminalAt},${terminalAt},
        'sign_count_regression',${terminalAt})
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_authority_anchors (
        id,tenant_id,user_id,flow,identity_epoch,recovery_restricted,
        action,audience,requirement_level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (${fixture.cloneAnchor}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,'primary',1,false,'tenant.authentication.login',
        'api','primary',false,0,${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_ceremonies (
        id,tenant_id,authority_anchor_id,challenge_digest,browser_digest,
        rp_id,rp_revision,allowed_origins,purpose,mode,user_handle_digest,
        require_user_presence,user_verification,resident_key,attestation,
        metadata_revision,state,completion_request_digest,result_snapshot,
        version,created_at,expires_at,claimed_at,completed_at
      ) VALUES (${cloneCeremonyId},${fixture.tenant}::uuid,
        ${fixture.cloneAnchor}::uuid,${Buffer.alloc(32, 0x53)},
        ${Buffer.alloc(32, 0x54)},'example.invalid',1,
        ARRAY['https://example.invalid'],'primary_authentication','known_user',
        ${Buffer.alloc(32, 0x55)},true,'preferred','preferred','none',0,
        'completed',${Buffer.alloc(32, 0x56)},
        ${JSON.stringify(cloneSnapshot)}::jsonb,3,${createdAt},${expiresAt},
        ${terminalAt},${terminalAt})
    `;
  });

  // Insert the historical clone event with the real audit-chain trigger active.
  // This keeps the chain head synchronized before canonical authorization
  // seeding appends its own events.
  await sql`
    INSERT INTO public.audit_events (
      id,tenant_id,sequence,occurred_at,actor_type,action,resource_type,
      resource_id,outcome,metadata,previous_hash,event_hash
    ) VALUES (${fixture.cloneAudit}::uuid,${fixture.tenant}::uuid,0,
      ${terminalAt},'system','mfa.passkey_clone_suspected',
      'webauthn_credential',${fixture.cloneCredential}::uuid,'success',
      '{}'::jsonb,repeat('0',64),repeat('0',64))
  `;

  await sql`
    SELECT app.seed_tenant_authorization(
      ${fixture.tenant}::uuid,${fixture.membership}::uuid
    )
  `;
  const [terminalBefore] = await sql<{ snapshot: postgres.JSONValue }[]>`
    SELECT jsonb_agg(to_jsonb(continuation) ORDER BY continuation.id) AS snapshot
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id IN (
      ${fixture.consumedProvider}::uuid,${fixture.revokedProvider}::uuid
    )
  `;
  assert(terminalBefore);

  await writeStage(targetEntries);
  await sql.unsafe(
    "CREATE ROLE periapsis_upgrade_writer_probe LOGIN INHERIT NOSUPERUSER " +
      "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
  );
  await sql.unsafe("GRANT periapsis_api TO periapsis_upgrade_writer_probe");
  await assert.rejects(
    migrate(drizzle(sql), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert.equal(postgresState(error), "55000");
      return true;
    },
    "v35 cutover accepted an unexpected LOGIN role inheriting a writer group",
  );
  await assertTargetNotApplied("unexpected inherited writer");
  await sql.unsafe("REVOKE periapsis_api FROM periapsis_upgrade_writer_probe");
  await sql.unsafe("DROP ROLE periapsis_upgrade_writer_probe");

  await sql.unsafe(
    "CREATE ROLE periapsis_api_login LOGIN INHERIT NOSUPERUSER " +
      "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
      "CONNECTION LIMIT 40",
  );
  await sql.unsafe("SET password_encryption = 'scram-sha-256'");
  const pausedRuntimePassword = await enableScramLogin("periapsis_api_login");
  await assert.rejects(
    migrate(drizzle(sql), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert.equal(postgresState(error), "55000");
      return true;
    },
    "v35 cutover accepted a LOGIN-enabled runtime writer role",
  );
  await assertTargetNotApplied("LOGIN-enabled writer");

  const pausedRuntime = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
    username: "periapsis_api_login",
    password: pausedRuntimePassword,
  });
  try {
    await pausedRuntime`SELECT pg_backend_pid()`;
    await sql.unsafe("ALTER ROLE periapsis_api_login NOLOGIN");
    await assert.rejects(
      migrate(drizzle(sql), { migrationsFolder: stageRoot }),
      (error: unknown) => {
        assert.equal(postgresState(error), "55000");
        return true;
      },
      "v35 cutover accepted an existing NOLOGIN runtime writer session",
    );
    await assertTargetNotApplied("undrained NOLOGIN writer");
  } finally {
    await pausedRuntime.end();
  }

  await proveBusyDrainFailsWithoutDeadlock("session_then_continuation");
  await proveBusyDrainFailsWithoutDeadlock("continuation_then_session");
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });

  const [pendingProvider] = await sql<
    {
      state: string;
      version: number;
      reason: string | null;
    }[]
  >`
    SELECT state,version::integer AS version,revoke_reason AS reason
    FROM public.tenant_post_primary_continuations
    WHERE id=${fixture.pendingProvider}::uuid
  `;
  assert.deepEqual(pendingProvider, {
    state: "expired",
    version: 2,
    reason: "unsealed_tenant_provider_authority_upgrade",
  });

  const [terminalAfter] = await sql<{ snapshot: postgres.JSONValue }[]>`
    SELECT jsonb_agg(to_jsonb(continuation) ORDER BY continuation.id) AS snapshot
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id IN (
      ${fixture.consumedProvider}::uuid,${fixture.revokedProvider}::uuid
    )
  `;
  assert.deepEqual(
    terminalAfter?.snapshot,
    terminalBefore.snapshot,
    "v35 cutover rewrote terminal tenant-provider history",
  );

  const [pendingPasskey] = await sql<
    {
      state: string;
      version: number;
      reason: string | null;
      millisecondCanonical: boolean;
    }[]
  >`
    SELECT state,version::integer AS version,revoke_reason AS reason,
      date_trunc('milliseconds',expires_at) = expires_at AS "millisecondCanonical"
    FROM public.tenant_post_primary_continuations
    WHERE id=${fixture.pendingPasskey}::uuid
  `;
  assert.deepEqual(pendingPasskey, {
    state: "expired",
    version: 2,
    reason: "unsealed_passkey_authority_upgrade",
    millisecondCanonical: true,
  });

  const [cloneReplay] = await sql<{ snapshot: postgres.JSONValue }[]>`
    SELECT result_snapshot AS snapshot
    FROM public.tenant_webauthn_ceremonies
    WHERE id=${cloneCeremonyId}
  `;
  assert.deepEqual(cloneReplay?.snapshot, {
    ...cloneSnapshot,
    credential: {
      ...cloneSnapshot.credential,
      securityRevision: 4,
    },
    sessionVersion: 0,
  });
  const [cloneCredential] = await sql<
    {
      securityRevision: number;
    }[]
  >`
    SELECT security_revision::integer AS "securityRevision"
    FROM public.tenant_webauthn_credentials
    WHERE id=${fixture.cloneCredential}::uuid
  `;
  assert.deepEqual(cloneCredential, { securityRevision: 4 });

  const [children] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_post_primary_federated_provenance
    WHERE continuation_id IN (
      ${fixture.pendingProvider}::uuid,${fixture.consumedProvider}::uuid,
      ${fixture.revokedProvider}::uuid
    )
  `;
  assert.deepEqual(children, { count: 0 });

  const [applied] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count,
      max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(applied, {
    count: 166,
    latest: String(targetEntries.at(-1)?.when),
  });

  await sql.unsafe(
    "GRANT periapsis_api TO periapsis_api_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );
  await writeStage(readinessEntries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  // The rolling proof isolates 0165/0166 first, then must exercise the whole
  // currently supported tail before asserting current-release readiness.
  // Production migration also owns the compatibility seal, so do not invoke
  // the generic sealer against an intentionally partial historical journal.
  await migrateSchema(sql, migrationsRoot);

  await sql.unsafe(
    "CREATE ROLE periapsis_worker_login NOLOGIN INHERIT NOSUPERUSER " +
      "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
      "CONNECTION LIMIT 20",
  );
  await sql.unsafe(
    "CREATE ROLE periapsis_notifier_login NOLOGIN INHERIT NOSUPERUSER " +
      "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
      "CONNECTION LIMIT 20",
  );
  await sql.unsafe(
    "CREATE ROLE periapsis_auditor_login NOLOGIN INHERIT NOSUPERUSER " +
      "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
      "CONNECTION LIMIT -1",
  );
  await sql.unsafe(
    "GRANT periapsis_worker TO periapsis_worker_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );
  await sql.unsafe(
    "GRANT periapsis_notifier TO periapsis_notifier_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );
  await sql.unsafe(
    "GRANT periapsis_auditor TO periapsis_auditor_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );

  const [quiescedLogins] = await sql<{ count: number; allNoLogin: boolean }[]>`
    SELECT count(*)::integer AS count,
      bool_and(NOT role_row.rolcanlogin) AS "allNoLogin"
    FROM pg_catalog.pg_roles AS role_row
    WHERE role_row.rolname IN (
      'periapsis_api_login',
      'periapsis_worker_login',
      'periapsis_notifier_login',
      'periapsis_auditor_login'
    )
  `;
  assert.deepEqual(quiescedLogins, { count: 4, allNoLogin: true });

  const [quiescedReadiness] = await sql<
    {
      dependencyHash: string;
      privateReady: boolean;
      publicReady: boolean;
    }[]
  >`
    SELECT
      app.private_release_runtime_dependency_surface_hash_v58()
        AS "dependencyHash",
      app.private_release_runtime_schema_readiness_v58()
        AS "privateReady",
      app.release_runtime_schema_readiness_v58()
        AS "publicReady"
  `;
  assert.equal(
    quiescedReadiness?.privateReady,
    true,
    "quiesced current V58 private readiness",
  );
  assert.equal(
    quiescedReadiness?.publicReady,
    true,
    "quiesced current V58 public readiness",
  );

  await sql.unsafe("SET password_encryption = 'scram-sha-256'");
  await enableScramLogin("periapsis_api_login");
  await enableScramLogin("periapsis_worker_login");
  await enableScramLogin("periapsis_notifier_login");
  await enableScramLogin("periapsis_auditor_login");
  const [provisionedReadiness] = await sql<
    {
      dependencyHash: string;
      privateReady: boolean;
      publicReady: boolean;
    }[]
  >`
    SELECT
      app.private_release_runtime_dependency_surface_hash_v58()
        AS "dependencyHash",
      app.private_release_runtime_schema_readiness_v58()
        AS "privateReady",
      app.release_runtime_schema_readiness_v58()
        AS "publicReady"
  `;
  assert.deepEqual(provisionedReadiness, {
    dependencyHash: quiescedReadiness?.dependencyHash,
    privateReady: true,
    publicReady: true,
  });

  const [readinessApplied] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count,
      max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(readinessApplied, {
    count: expectedMigrationCount,
    latest: String(expectedMigrationCreatedAt),
  });
} finally {
  await writerSql.end();
  await sql.end();
  await rm(stageRoot, { recursive: true, force: true });
}
