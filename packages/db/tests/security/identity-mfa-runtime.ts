import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };

type AuthoritySnapshot = {
  tenantId: string;
  userId: string;
  identityEpoch: number;
  sessionId: string;
  sessionFamilyId: string;
  anchorVersion: number;
  anchorExpiresAt: string;
  anchorRecoveryRestricted: boolean;
  action: string;
  audience: string;
  requirement: {
    level: string;
    localRequired: boolean;
    freshnessNanoseconds: number;
    enrollmentDeadline: string | null;
    policyRevisions: Array<{ policyId: string; revision: number }>;
  };
  baselineEvidence: postgres.JSONValue[];
  totpFactorIds: string[];
};

type PrimaryPasskeySnapshot = {
  tenantId: string;
  userId: string;
  identityEpoch: number;
  mode: string;
  userHandle: string;
  credentialIds: string[];
};

const databaseUrl =
  process.env.PERIAPSIS_IDENTITY_MFA_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_IDENTITY_MFA_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sql = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

const protectedRelations = [
  "auth_session_local_credential_provenance",
  "auth_session_mfa_evidence",
  "auth_session_mfa_policy_pins",
  "auth_session_mfa_states",
  "auth_session_passkey_provenance",
  "mfa_policy_revisions",
  "tenant_mfa_authority_anchors",
  "tenant_mfa_authority_evidence",
  "tenant_mfa_authority_policy_pins",
  "tenant_mfa_step_up_challenges",
  "tenant_mfa_subjects",
  "tenant_post_primary_continuation_evidence",
  "tenant_post_primary_continuation_policy_pins",
  "tenant_post_primary_continuations",
  "tenant_recovery_code_sets",
  "tenant_recovery_codes",
  "tenant_totp_enrollments",
  "tenant_totp_factors",
  "tenant_webauthn_ceremonies",
  "tenant_webauthn_ceremony_credentials",
  "tenant_webauthn_credential_transports",
  "tenant_webauthn_credentials",
] as const;

const publicFunctions = [
  "admit_mfa_operation_v1",
  "claim_mfa_step_up_challenge_v2",
  "claim_totp_enrollment_v2",
  "claim_webauthn_ceremony_v2",
  "complete_mfa_passkey_authentication_v1",
  "complete_mfa_passkey_registration_v1",
  "complete_mfa_recovery_step_up_v1",
  "complete_mfa_totp_step_up_v1",
  "complete_totp_enrollment_v1",
  "create_mfa_step_up_challenge_v1",
  "create_webauthn_ceremony_v1",
  "fail_mfa_step_up_challenge_v1",
  "fail_totp_enrollment_v1",
  "fail_webauthn_ceremony_v1",
  "load_mfa_recovery_set_v1",
  "load_mfa_totp_factor_v1",
  "load_webauthn_credential_v1",
  "list_my_mfa_devices_v1",
  "rename_my_passkey_v1",
  "replace_mfa_recovery_codes_v1",
  "revoke_my_mfa_device_v1",
  "resolve_mfa_authority_v2",
  "resolve_primary_passkey_v1",
  "start_totp_enrollment_v1",
] as const;

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function uuid(sequence: number): string {
  return `019d2f44-9000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
}

const lifecycleSequence = Date.now() * 100 + (process.pid % 100);
function fixtureDigest(label: string): Buffer {
  return createHash("sha256").update(`${label}:${lifecycleSequence}`).digest();
}

const lifecycleFixture = {
  tenantId: uuid(lifecycleSequence + 1),
  userId: uuid(lifecycleSequence + 2),
  membershipId: uuid(lifecycleSequence + 3),
  loginIdentifierId: uuid(lifecycleSequence + 4),
  credentialId: uuid(lifecycleSequence + 5),
  sessionId: uuid(lifecycleSequence + 6),
  sessionFamilyId: uuid(lifecycleSequence + 7),
  policyId: uuid(lifecycleSequence + 8),
  factorId: uuid(lifecycleSequence + 9),
  webauthnCredentialId: uuid(lifecycleSequence + 10),
  rotatedSessionId: uuid(lifecycleSequence + 11),
  wrongFamilyId: uuid(lifecycleSequence + 12),
  passkeyRotatedSessionId: uuid(lifecycleSequence + 13),
  slug: `mfa-runtime-${lifecycleSequence.toString(36)}`,
  email: `mfa-runtime-${lifecycleSequence.toString(36)}@example.invalid`,
} as const;

const fixtureUserHandle = fixtureDigest("user-handle");
const fixtureCredentialWireID = fixtureDigest("credential-id");

async function createLifecycleFixture(now: Date): Promise<void> {
  const fixture = lifecycleFixture;
  const idleExpiresAt = new Date(now.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(now.getTime() + 2 * 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id, slug, name, status, created_at, updated_at)
      VALUES (${fixture.tenantId}::uuid, ${fixture.slug}, 'MFA runtime fixture',
              'active', ${now}, ${now})
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active, created_at, updated_at)
      VALUES (${fixture.userId}::uuid, ${fixture.email},
              'MFA runtime fixture', true, ${now}, ${now})
    `;
    await transaction`
      INSERT INTO public.user_login_identifiers (
        id, user_id, kind, canonical_value, verified_at, created_at, updated_at
      ) VALUES (
        ${fixture.loginIdentifierId}::uuid, ${fixture.userId}::uuid, 'local_email',
        ${fixture.email}, ${now}, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.local_break_glass_credentials (
        id, user_id, login_identifier_id, password_phc, password_version,
        changed_at, created_at, updated_at
      ) VALUES (
        ${fixture.credentialId}::uuid, ${fixture.userId}::uuid,
        ${fixture.loginIdentifierId}::uuid,
        '$argon2id$v=19$m=65536,t=3,p=1$YWJjZA$YWJjZGVmZ2hpamtsbW5vcA',
        1, ${now}, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status, created_at, updated_at
      ) VALUES (
        ${fixture.membershipId}::uuid, ${fixture.tenantId}::uuid,
        ${fixture.userId}::uuid, 'tenant_admin', 'active', ${now}, ${now}
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenantId}::uuid,
        ${fixture.membershipId}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id, user_id, webauthn_user_handle, identity_epoch,
        session_invalidation_epoch, version, created_at, updated_at
      ) VALUES (
        ${fixture.tenantId}::uuid, ${fixture.userId}::uuid, ${fixtureUserHandle},
        1, 1, 1, ${now}, ${now}
      )
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.policyId}:1`},
        true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id, revision, tenant_id, scope, level, local_required,
        freshness_nanoseconds, created_at
      ) VALUES (
        ${fixture.policyId}::uuid, 1, ${fixture.tenantId}::uuid,
        'tenant_baseline', 'mfa', true, 0, ${now}
      )
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1', '', true)
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, last_seen_at,
        idle_expires_at, absolute_expires_at, created_at
      ) VALUES (
        ${fixture.sessionId}::uuid, ${fixture.userId}::uuid,
        ${fixture.sessionFamilyId}::uuid, ${fixture.tenantId}::uuid,
        ${fixtureDigest("session-token")}, ${fixtureDigest("session-csrf")}, 'totp', ${now},
        ${idleExpiresAt}, ${absoluteExpiresAt}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id, tenant_id, user_id, session_version, identity_epoch,
        recovery_restricted, audience, primary_kind,
        session_invalidation_epoch, issued_at
      ) VALUES (
        ${fixture.sessionId}::uuid, ${fixture.tenantId}::uuid,
        ${fixture.userId}::uuid, 1, 1, false, 'tenant-console',
        'local_credential', 1, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_local_credential_provenance (
        tenant_id, session_id, user_id, credential_id,
        credential_revision, authenticated_at
      ) VALUES (
        ${fixture.tenantId}::uuid, ${fixture.sessionId}::uuid,
        ${fixture.userId}::uuid, ${fixture.credentialId}::uuid, 1, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence (
        tenant_id, session_id, local_credential_id, level, kind,
        authenticated_at, factor_revision
      ) VALUES (
        ${fixture.tenantId}::uuid, ${fixture.sessionId}::uuid,
        ${fixture.credentialId}::uuid, 'primary', 'local_credential', ${now}, 1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id, session_id, policy_id, policy_revision
      ) VALUES (
        ${fixture.tenantId}::uuid, ${fixture.sessionId}::uuid,
        ${fixture.policyId}::uuid, 1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_totp_factors (
        id, tenant_id, user_id, secret_envelope, key_version,
        last_accepted_counter, record_version, security_revision,
        status, confirmed_at, created_at, updated_at
      ) VALUES (
        ${fixture.factorId}::uuid, ${fixture.tenantId}::uuid,
        ${fixture.userId}::uuid, ${Buffer.alloc(32, 0x73)}, 1,
        -1, 1, 1, 'active', ${now}, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credentials (
        id, tenant_id, user_id, credential_id, public_key, display_name,
        user_handle_digest, rp_id, rp_revision, sign_count, discoverable,
        user_verification, backup_eligible, backed_up, aaguid,
        attestation_format, attestation_type, attestation_trusted,
        metadata_revision, status, version, created_at, updated_at
      ) VALUES (
        ${fixture.webauthnCredentialId}::uuid, ${fixture.tenantId}::uuid,
        ${fixture.userId}::uuid, ${fixtureCredentialWireID}, ${Buffer.alloc(64, 0x82)},
        'Runtime passkey', ${createHash("sha256").update(fixtureUserHandle).digest()},
        'example.invalid', 1, 0, true, true, false, false,
        ${Buffer.alloc(16)}, 'none', 'none', false, 0, 'active', 1, ${now}, ${now}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credential_transports (
        tenant_id, credential_id, transport
      ) VALUES (
        ${fixture.tenantId}::uuid, ${fixture.webauthnCredentialId}::uuid, 'internal'
      )
    `;
  });
}

async function asApi<T>(
  callback: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await callback(transaction) };
  });
  return result.value;
}

async function asScopedApi<T>(
  callback: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  return asApi(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id', ${lifecycleFixture.tenantId}, true),
             set_config('app.user_id', ${lifecycleFixture.userId}, true)
    `;
    return callback(transaction);
  });
}

async function collectAdmissions(
  attempt: number,
  outcomes: Array<{ outcome: string; retry_at: Date | null }>,
): Promise<void> {
  if (attempt >= 35) {
    return;
  }
  const [result] = await asApi(
    (transaction) =>
      transaction<{ outcome: string; retry_at: Date | null }[]>`
      SELECT outcome, retry_at
      FROM app.admit_mfa_operation_v1(
        ${uuid(attempt + 1)}::uuid,
        ${Buffer.alloc(32, 0x41)}, ${Buffer.alloc(32, 0x42)},
        ${Buffer.alloc(32, 0x43)}, transaction_timestamp()
      )
    `,
  );
  assert(result !== undefined);
  assert(["allowed", "rate_limited", "locked"].includes(result.outcome));
  if (result.outcome === "allowed") {
    assert.equal(result.retry_at, null);
  } else {
    assert(result.retry_at instanceof Date);
  }
  outcomes.push(result);
  return collectAdmissions(attempt + 1, outcomes);
}

try {
  const [version] = await sql<{ version: number }[]>`
    SELECT current_setting('server_version_num')::integer AS version
  `;
  assert(version !== undefined && version.version >= 180_000);

  const [readiness] = await asApi(
    (transaction) =>
      transaction<{ ready: boolean }[]>`
      SELECT app.release_runtime_schema_readiness_v55() AS ready
    `,
  );
  assert.equal(readiness?.ready, true);

  const tableBoundary = await sql<
    {
      relation_name: string;
      owner_name: string;
      row_security: boolean;
      force_row_security: boolean;
      api_access: boolean;
      worker_access: boolean;
      notifier_access: boolean;
      auditor_access: boolean;
    }[]
  >`
    SELECT class.relname AS relation_name,
           pg_get_userbyid(class.relowner) AS owner_name,
           class.relrowsecurity AS row_security,
           class.relforcerowsecurity AS force_row_security,
           has_table_privilege('periapsis_api', class.oid, 'SELECT,INSERT,UPDATE,DELETE') AS api_access,
           has_table_privilege('periapsis_worker', class.oid, 'SELECT,INSERT,UPDATE,DELETE') AS worker_access,
           has_table_privilege('periapsis_notifier', class.oid, 'SELECT,INSERT,UPDATE,DELETE') AS notifier_access,
           has_table_privilege('periapsis_auditor', class.oid, 'SELECT,INSERT,UPDATE,DELETE') AS auditor_access
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = ANY(${protectedRelations as readonly string[]}::text[])
    ORDER BY class.relname
  `;
  assert.deepEqual(
    tableBoundary.map((entry) => entry.relation_name),
    protectedRelations.toSorted(),
  );
  for (const entry of tableBoundary) {
    assert.equal(entry.owner_name, "periapsis_migrator", entry.relation_name);
    assert.equal(entry.row_security, true, entry.relation_name);
    assert.equal(entry.force_row_security, true, entry.relation_name);
    assert.equal(entry.api_access, false, entry.relation_name);
    assert.equal(entry.worker_access, false, entry.relation_name);
    assert.equal(entry.notifier_access, false, entry.relation_name);
    assert.equal(entry.auditor_access, false, entry.relation_name);
  }

  await assert.rejects(
    asApi((transaction) =>
      transaction.unsafe(
        "SELECT count(*) FROM public.tenant_webauthn_credentials",
      ),
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await Promise.all(
    [
      "SELECT app.private_mfa_request_digest_v1('{}'::jsonb)",
      "SELECT app.private_mfa_complete_webauthn_registration_v1('{}'::jsonb, 'Passkey')",
      "SELECT app.private_mfa_complete_webauthn_authentication_v1('{}'::jsonb)",
    ].map((statement) =>
      assert.rejects(
        asApi((transaction) => transaction.unsafe(statement)),
        (error: unknown) => assertSqlState(error, "42501"),
      ),
    ),
  );

  const functionBoundary = await sql<
    {
      function_name: string;
      owner_name: string;
      security_definer: boolean;
      api_execute: boolean;
      public_execute: boolean;
      worker_execute: boolean;
    }[]
  >`
    SELECT procedure.proname AS function_name,
           pg_get_userbyid(procedure.proowner) AS owner_name,
           procedure.prosecdef AS security_definer,
           has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE') AS api_execute,
           EXISTS (
             SELECT 1
             FROM aclexplode(
               coalesce(procedure.proacl, acldefault('f', procedure.proowner))
             ) AS privilege
             WHERE privilege.grantee = 0
               AND privilege.privilege_type = 'EXECUTE'
           ) AS public_execute,
           has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE') AS worker_execute
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname = ANY(${publicFunctions as readonly string[]}::text[])
    ORDER BY procedure.proname
  `;
  assert.deepEqual(
    functionBoundary.map((entry) => entry.function_name),
    publicFunctions.toSorted(),
  );
  for (const entry of functionBoundary) {
    assert.equal(entry.owner_name, "periapsis_migrator", entry.function_name);
    assert.equal(entry.security_definer, true, entry.function_name);
    assert.equal(entry.api_execute, true, entry.function_name);
    assert.equal(entry.public_execute, false, entry.function_name);
    assert.equal(entry.worker_execute, false, entry.function_name);
  }
  const [removedCompletionBoundary] = await sql<
    { registration: string | null; authentication: string | null }[]
  >`
    SELECT to_regprocedure('app.complete_webauthn_registration_v1(jsonb)')::text AS registration,
           to_regprocedure('app.complete_webauthn_authentication_v1(jsonb)')::text AS authentication
  `;
  assert.deepEqual(removedCompletionBoundary, {
    registration: null,
    authentication: null,
  });

  const rawColumns = await sql<{ column_name: string }[]>`
    SELECT schema_column.column_name
    FROM information_schema.columns AS schema_column
    WHERE schema_column.table_schema = 'public'
      AND schema_column.table_name = ANY(${protectedRelations as readonly string[]}::text[])
      AND schema_column.column_name ~ '(plaintext|raw|token|csrf|assertion|signature|client_data)'
  `;
  assert.equal(rawColumns.length, 0);

  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.start_totp_enrollment_v1(
          ${sql.json({ secret: "redacted-canary" })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT * FROM app.admit_mfa_operation_v1(
          ${"00000000-0000-4000-8000-000000000001"}::uuid,
          ${Buffer.alloc(32, 0x11)}, ${Buffer.alloc(32, 0x22)},
          ${Buffer.alloc(32, 0x33)}, transaction_timestamp()
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );

  const outcomes: Array<{ outcome: string; retry_at: Date | null }> = [];
  await collectAdmissions(0, outcomes);
  assert(outcomes.some((entry) => entry.outcome !== "allowed"));

  const fixtureClock = new Date();
  await createLifecycleFixture(fixtureClock);
  const action = "ticket.comment.public";
  const [authorityRow] = await asApi(
    (transaction) =>
      transaction<{ snapshot: AuthoritySnapshot }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${lifecycleFixture.sessionId}::uuid, 'session', ${action},
        'tenant-console', ${fixtureClock},NULL::bytea
      ) AS snapshot
    `,
  );
  assert(authorityRow !== undefined);
  const authority = authorityRow.snapshot;
  assert.equal(authority.tenantId, lifecycleFixture.tenantId);
  assert.equal(authority.userId, lifecycleFixture.userId);
  assert.equal(authority.requirement.level, "mfa");
  assert.equal(authority.requirement.localRequired, true);
  assert.deepEqual(authority.requirement.policyRevisions, [
    { policyId: lifecycleFixture.policyId, revision: 1 },
  ]);
  assert.equal(authority.baselineEvidence.length, 1);
  assert.deepEqual(authority.totpFactorIds, [lifecycleFixture.factorId]);

  const binding = {
    flow: "session",
    tenantId: authority.tenantId,
    userId: authority.userId,
    identityEpoch: authority.identityEpoch,
    sessionId: authority.sessionId,
    sessionFamilyId: authority.sessionFamilyId,
    anchorVersion: authority.anchorVersion,
    anchorExpiresAt: authority.anchorExpiresAt,
    anchorRecoveryRestricted: authority.anchorRecoveryRestricted,
    action: authority.action,
    audience: authority.audience,
    requirement: authority.requirement,
    baselineEvidence: authority.baselineEvidence,
  };
  const challengeId = fixtureDigest("step-up-challenge");
  const browserDigest = Buffer.alloc(32, 0x52);
  const challengeCreatedAt = new Date(fixtureClock.getTime() + 1_000);
  const challengeExpiresAt = new Date(fixtureClock.getTime() + 6 * 60_000);
  const challengeRequest = {
    id: challengeId.toString("base64"),
    browserDigest: browserDigest.toString("base64"),
    binding,
    allowedFactors: ["totp"],
    createdAt: challengeCreatedAt.toISOString(),
    expiresAt: challengeExpiresAt.toISOString(),
    state: "pending",
    version: 1,
  };
  const [created] = await asApi(
    (transaction) =>
      transaction<{ created: boolean }[]>`
      SELECT app.create_mfa_step_up_challenge_v1(
        ${sql.json(challengeRequest)}::jsonb
      ) AS created
    `,
  );
  assert.equal(created?.created, true);

  const claimedAt = new Date(challengeCreatedAt.getTime() + 1_000);
  const [claimed] = await asApi(
    (transaction) =>
      transaction<
        {
          challenge: {
            claimedFactorKind: string;
            state: string;
            version: number;
          };
        }[]
      >`
      SELECT app.claim_mfa_step_up_challenge_v2(
        ${challengeId}, ${browserDigest}, 'totp', ${claimedAt},NULL::bytea
      ) AS challenge
    `,
  );
  assert.equal(claimed?.challenge.state, "claimed");
  assert.equal(claimed?.challenge.version, 2);
  assert.equal(claimed?.challenge.claimedFactorKind, "totp");
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.claim_mfa_step_up_challenge_v2(
          ${challengeId}, ${browserDigest}, 'totp', ${claimedAt},NULL::bytea
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const [failed] = await asApi(
    (transaction) =>
      transaction<{ failed: boolean }[]>`
      SELECT app.fail_mfa_step_up_challenge_v1(
        ${challengeId}, 2, 'failed', 'factor_rejected',
        ${new Date(claimedAt.getTime() + 1_000)}
      ) AS failed
    `,
  );
  assert.equal(failed?.failed, true);

  const [primaryPasskeyRow] = await asApi(
    (transaction) =>
      transaction<{ snapshot: PrimaryPasskeySnapshot }[]>`
      SELECT app.resolve_primary_passkey_v1(
        ${lifecycleFixture.userId}::uuid, 'login', 'tenant-console',
        ${fixtureClock}
      ) AS snapshot
    `,
  );
  assert(primaryPasskeyRow !== undefined);
  assert.equal(primaryPasskeyRow.snapshot.tenantId, lifecycleFixture.tenantId);
  assert.equal(primaryPasskeyRow.snapshot.userId, lifecycleFixture.userId);
  assert.equal(primaryPasskeyRow.snapshot.identityEpoch, 1);
  assert.equal(primaryPasskeyRow.snapshot.mode, "known_user");
  assert.equal(
    primaryPasskeyRow.snapshot.userHandle,
    fixtureUserHandle.toString("base64"),
  );
  assert.deepEqual(primaryPasskeyRow.snapshot.credentialIds, [
    fixtureCredentialWireID.toString("base64"),
  ]);

  const ceremonyId = fixtureDigest("webauthn-ceremony");
  const ceremonyBrowserDigest = Buffer.alloc(32, 0x55);
  const ceremonyCreatedAt = new Date(fixtureClock.getTime() + 2_000);
  const ceremonyRequest = {
    id: ceremonyId.toString("base64"),
    challengeDigest: Buffer.alloc(32, 0x56).toString("base64"),
    browserDigest: ceremonyBrowserDigest.toString("base64"),
    relyingParty: {
      id: "example.invalid",
      origins: ["https://example.invalid"],
      revision: 1,
    },
    binding: { ...binding, purpose: "step_up_authentication", flow: undefined },
    policy: {
      requireUserPresence: true,
      userVerification: "required",
      residentKey: "preferred",
      attestation: "none",
      metadataRevision: 0,
    },
    mode: "known_user",
    userHandleDigest: createHash("sha256")
      .update(fixtureUserHandle)
      .digest("base64"),
    allowedCredentialIds: [fixtureCredentialWireID.toString("base64")],
    createdAt: ceremonyCreatedAt.toISOString(),
    expiresAt: new Date(ceremonyCreatedAt.getTime() + 5 * 60_000).toISOString(),
    state: "pending",
    version: 1,
  };
  const [ceremonyCreated] = await asApi(
    (transaction) =>
      transaction<{ created: boolean }[]>`
      SELECT app.create_webauthn_ceremony_v1(
        ${sql.json(ceremonyRequest)}::jsonb
      ) AS created
    `,
  );
  assert.equal(ceremonyCreated?.created, true);
  const ceremonyClaimedAt = new Date(ceremonyCreatedAt.getTime() + 1_000);
  const [ceremonyClaimed] = await asApi(
    (transaction) =>
      transaction<{ ceremony: { state: string; version: number } }[]>`
      SELECT app.claim_webauthn_ceremony_v2(
        ${ceremonyId}, ${ceremonyBrowserDigest}, ${ceremonyClaimedAt},
        NULL::bytea
      ) AS ceremony
    `,
  );
  assert.equal(ceremonyClaimed?.ceremony.state, "claimed");
  assert.equal(ceremonyClaimed?.ceremony.version, 2);
  const [ceremonyFailed] = await asApi(
    (transaction) =>
      transaction<{ failed: boolean }[]>`
      SELECT app.fail_webauthn_ceremony_v1(
        ${ceremonyId}, 2, 'failed', 'verification_rejected',
        ${new Date(ceremonyClaimedAt.getTime() + 1_000)}
      ) AS failed
    `,
  );
  assert.equal(ceremonyFailed?.failed, true);

  const driftedRequest = {
    ...challengeRequest,
    id: fixtureDigest("drifted-step-up-challenge").toString("base64"),
    binding: { ...binding, baselineEvidence: [] },
  };
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.create_mfa_step_up_challenge_v1(
          ${sql.json(driftedRequest)}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.resolve_mfa_authority_v2(
          ${lifecycleFixture.sessionId}::uuid, 'session', ${action},
          'wrong-audience', ${fixtureClock},NULL::bytea
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const completionChallengeId = fixtureDigest("completion-step-up-challenge");
  const completionChallengeRequest = {
    ...challengeRequest,
    id: completionChallengeId.toString("base64"),
  };
  const [completionChallengeCreated] = await asApi(
    (transaction) =>
      transaction<{ created: boolean }[]>`
      SELECT app.create_mfa_step_up_challenge_v1(
        ${sql.json(completionChallengeRequest)}::jsonb
      ) AS created
    `,
  );
  assert.equal(completionChallengeCreated?.created, true);
  const completionClaimedAt = new Date(challengeCreatedAt.getTime() + 2_000);
  const [completionClaimed] = await asApi(
    (transaction) =>
      transaction<
        {
          challenge: {
            claimedFactorKind: string;
            state: string;
            version: number;
          };
        }[]
      >`
      SELECT app.claim_mfa_step_up_challenge_v2(
        ${completionChallengeId}, ${browserDigest}, 'totp',
        ${completionClaimedAt},NULL::bytea
      ) AS challenge
    `,
  );
  assert.equal(completionClaimed?.challenge.state, "claimed");
  assert.equal(completionClaimed?.challenge.version, 2);
  assert.equal(completionClaimed?.challenge.claimedFactorKind, "totp");

  const completedAt = new Date(completionClaimedAt.getTime() + 1_000);
  const sessionReservation = {
    sessionId: lifecycleFixture.rotatedSessionId,
    familyId: lifecycleFixture.sessionFamilyId,
    tokenDigest: fixtureDigest("rotated-session-token").toString("base64"),
    csrfDigest: fixtureDigest("rotated-session-csrf").toString("base64"),
    authenticationMethod: "totp",
    idleExpiresAt: new Date(completedAt.getTime() + 30 * 60_000).toISOString(),
    absoluteExpiresAt: new Date(
      completedAt.getTime() + 60 * 60_000,
    ).toISOString(),
  };
  const completionRequest = {
    challengeId: completionChallengeId.toString("base64"),
    expectedChallengeVersion: 2,
    binding,
    factorId: lifecycleFixture.factorId,
    expectedFactorVersion: 1,
    expectedSecurityRevision: 1,
    counter: 0,
    completedAt: completedAt.toISOString(),
    sessionMutation: "rotate",
    auditKind: "mfa.totp_step_up_completed",
    recoveryRestricted: false,
    session: sessionReservation,
  };
  await assert.rejects(
    asApi(async (transaction) => {
      await transaction`
        SELECT set_config('app.tenant_id', ${lifecycleFixture.tenantId}, true),
               set_config('app.user_id', ${lifecycleFixture.wrongFamilyId}, true)
      `;
      return transaction`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${sql.json(completionRequest)}::jsonb
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${sql.json({
            ...completionRequest,
            session: {
              ...sessionReservation,
              familyId: lifecycleFixture.wrongFamilyId,
            },
          })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${sql.json({
            ...completionRequest,
            session: {
              ...sessionReservation,
              csrfDigest: sessionReservation.tokenDigest,
            },
          })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const [rolledBack] = await sql<
    {
      last_counter: number;
      old_revoked: boolean;
      challenge_state: string;
    }[]
  >`
    SELECT factor.last_accepted_counter::integer AS last_counter,
           session.revoked_at IS NOT NULL AS old_revoked,
           challenge.state AS challenge_state
    FROM public.tenant_totp_factors AS factor
    CROSS JOIN public.auth_sessions AS session
    CROSS JOIN public.tenant_mfa_step_up_challenges AS challenge
    WHERE factor.id = ${lifecycleFixture.factorId}::uuid
      AND session.id = ${lifecycleFixture.sessionId}::uuid
      AND challenge.id = ${completionChallengeId}
  `;
  assert.deepEqual(rolledBack, {
    last_counter: -1,
    old_revoked: false,
    challenge_state: "claimed",
  });

  const [completion] = await asApi(
    (transaction) =>
      transaction<
        {
          result: {
            mutation: string;
            newSessionId: string;
            newSessionFamilyId: string;
            sessionVersion: number;
            recoveryRestricted: boolean;
          };
        }[]
      >`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${sql.json(completionRequest)}::jsonb
      ) AS result
    `,
  );
  assert.equal(completion?.result.mutation, "rotate");
  assert.equal(
    completion?.result.newSessionId,
    lifecycleFixture.rotatedSessionId,
  );
  assert.equal(
    completion?.result.newSessionFamilyId,
    lifecycleFixture.sessionFamilyId,
  );
  assert.equal(completion?.result.sessionVersion, 2);
  assert.equal(completion?.result.recoveryRestricted, false);
  const [replayed] = await asApi(
    (transaction) =>
      transaction<{ result: typeof completion.result }[]>`
      SELECT app.complete_mfa_totp_step_up_v1(
        ${sql.json(completionRequest)}::jsonb
      ) AS result
    `,
  );
  assert.deepEqual(replayed?.result, completion.result);
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${sql.json({ ...completionRequest, counter: 1 })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const [committedState] = await sql<
    {
      old_reason: string;
      token_matches: boolean;
      csrf_matches: boolean;
      state_version: number;
      evidence_count: number;
      policy_count: number;
      audit_count: number;
    }[]
  >`
    SELECT old_session.revoke_reason AS old_reason,
           new_session.token_digest = ${fixtureDigest("rotated-session-token")} AS token_matches,
           new_session.csrf_secret_digest = ${fixtureDigest("rotated-session-csrf")} AS csrf_matches,
           state.session_version::integer AS state_version,
           (SELECT count(*)::integer FROM public.auth_session_mfa_evidence AS evidence
             WHERE evidence.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND evidence.session_id = ${lifecycleFixture.rotatedSessionId}::uuid) AS evidence_count,
           (SELECT count(*)::integer FROM public.auth_session_mfa_policy_pins AS pin
             WHERE pin.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND pin.session_id = ${lifecycleFixture.rotatedSessionId}::uuid) AS policy_count,
           (SELECT count(*)::integer FROM public.audit_events AS event
             WHERE event.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND event.action = 'tenant.identity.mfa_totp_step_up_completed') AS audit_count
    FROM public.auth_sessions AS old_session
    JOIN public.auth_sessions AS new_session
      ON new_session.id = ${lifecycleFixture.rotatedSessionId}::uuid
    JOIN public.auth_session_mfa_states AS state
      ON state.session_id = new_session.id
    WHERE old_session.id = ${lifecycleFixture.sessionId}::uuid
  `;
  assert.deepEqual(committedState, {
    old_reason: "mfa_session_rotated",
    token_matches: true,
    csrf_matches: true,
    state_version: 2,
    evidence_count: 2,
    policy_count: 1,
    audit_count: 1,
  });

  const passkeyAuthorityAt = new Date(completedAt.getTime() + 1_000);
  const [passkeyAuthorityRow] = await asApi(
    (transaction) =>
      transaction<{ snapshot: AuthoritySnapshot }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${lifecycleFixture.rotatedSessionId}::uuid, 'session', ${action},
        'tenant-console', ${passkeyAuthorityAt},NULL::bytea
      ) AS snapshot
    `,
  );
  assert(passkeyAuthorityRow !== undefined);
  const passkeyAuthority = passkeyAuthorityRow.snapshot;
  assert.equal(passkeyAuthority.baselineEvidence.length, 2);
  const passkeyBinding = {
    tenantId: passkeyAuthority.tenantId,
    userId: passkeyAuthority.userId,
    identityEpoch: passkeyAuthority.identityEpoch,
    sessionId: passkeyAuthority.sessionId,
    sessionFamilyId: passkeyAuthority.sessionFamilyId,
    anchorVersion: passkeyAuthority.anchorVersion,
    anchorExpiresAt: passkeyAuthority.anchorExpiresAt,
    anchorRecoveryRestricted: passkeyAuthority.anchorRecoveryRestricted,
    action: passkeyAuthority.action,
    audience: passkeyAuthority.audience,
    requirement: passkeyAuthority.requirement,
    baselineEvidence: passkeyAuthority.baselineEvidence,
    purpose: "step_up_authentication",
  };
  const completionCeremonyId = fixtureDigest("completion-webauthn-ceremony");
  const completionCeremonyBrowserDigest = fixtureDigest(
    "completion-webauthn-browser",
  );
  const completionCeremonyCreatedAt = new Date(
    passkeyAuthorityAt.getTime() + 1_000,
  );
  const completionCeremonyRequest = {
    ...ceremonyRequest,
    id: completionCeremonyId.toString("base64"),
    challengeDigest: fixtureDigest("completion-webauthn-challenge").toString(
      "base64",
    ),
    browserDigest: completionCeremonyBrowserDigest.toString("base64"),
    binding: passkeyBinding,
    createdAt: completionCeremonyCreatedAt.toISOString(),
    expiresAt: new Date(
      completionCeremonyCreatedAt.getTime() + 5 * 60_000,
    ).toISOString(),
  };
  const [completionCeremonyCreated] = await asApi(
    (transaction) =>
      transaction<{ created: boolean }[]>`
      SELECT app.create_webauthn_ceremony_v1(
        ${sql.json(completionCeremonyRequest)}::jsonb
      ) AS created
    `,
  );
  assert.equal(completionCeremonyCreated?.created, true);
  const completionCeremonyClaimedAt = new Date(
    completionCeremonyCreatedAt.getTime() + 1_000,
  );
  const [completionCeremonyClaimed] = await asApi(
    (transaction) =>
      transaction<{ ceremony: { state: string; version: number } }[]>`
      SELECT app.claim_webauthn_ceremony_v2(
        ${completionCeremonyId}, ${completionCeremonyBrowserDigest},
        ${completionCeremonyClaimedAt},NULL::bytea
      ) AS ceremony
    `,
  );
  assert.equal(completionCeremonyClaimed?.ceremony.state, "claimed");
  assert.equal(completionCeremonyClaimed?.ceremony.version, 2);

  const passkeyCompletedAt = new Date(
    completionCeremonyClaimedAt.getTime() + 1_000,
  );
  const passkeySessionReservation = {
    sessionId: lifecycleFixture.passkeyRotatedSessionId,
    familyId: lifecycleFixture.sessionFamilyId,
    tokenDigest: fixtureDigest("passkey-session-token").toString("base64"),
    csrfDigest: fixtureDigest("passkey-session-csrf").toString("base64"),
    authenticationMethod: "passkey",
    idleExpiresAt: new Date(
      passkeyCompletedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: new Date(
      passkeyCompletedAt.getTime() + 60 * 60_000,
    ).toISOString(),
  };
  const passkeyCompletionRequest = {
    completion: {
      ceremonyId: completionCeremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: passkeyBinding,
      resolvedUserId: lifecycleFixture.userId,
      expectedIdentityEpoch: passkeyAuthority.identityEpoch,
      credentialId: fixtureCredentialWireID.toString("base64"),
      expectedCredentialVersion: 1,
      completedAt: passkeyCompletedAt.toISOString(),
      expectedSignCount: 0,
      observedSignCount: 1,
      expectedBackedUp: false,
      counterDisposition: "advance",
      userVerified: true,
      backupEligible: false,
      backedUp: false,
    },
    audit: {
      kind: "mfa.passkey_step_up_completed",
      tenantId: lifecycleFixture.tenantId,
      userId: lifecycleFixture.userId,
      action,
      occurredAt: passkeyCompletedAt.toISOString(),
      policyRevisions: passkeyAuthority.requirement.policyRevisions,
    },
    session: {
      mutation: "rotate",
      expectedSessionId: lifecycleFixture.rotatedSessionId,
      expectedFamilyId: lifecycleFixture.sessionFamilyId,
      expectedAnchorVersion: passkeyAuthority.anchorVersion,
      expectedIdentityEpoch: passkeyAuthority.identityEpoch,
      expectedAnchorExpiry: passkeyAuthority.anchorExpiresAt,
      audience: passkeyAuthority.audience,
      requirement: passkeyAuthority.requirement,
      recoveryRestricted: false,
      reservation: passkeySessionReservation,
    },
  };
  type PasskeyCompletionRow = {
    result: {
      outcome: string;
      mutation: string;
      newSessionId: string;
      newSessionFamilyId: string;
      sessionVersion: number;
      credential: {
        credentialVersion: number;
        securityRevision: number;
        signCount: number;
      };
    };
  };
  const passkeyCompletions = await Promise.all(
    [0, 1].map(() =>
      asApi(
        (transaction) =>
          transaction<PasskeyCompletionRow[]>`
          SELECT app.complete_mfa_passkey_authentication_v1(
            ${sql.json(passkeyCompletionRequest)}::jsonb
          ) AS result
        `,
      ),
    ),
  );
  const [passkeyCompletion] = passkeyCompletions[0] ?? [];
  const [concurrentPasskeyReplay] = passkeyCompletions[1] ?? [];
  assert.deepEqual(concurrentPasskeyReplay, passkeyCompletion);
  assert.equal(passkeyCompletion?.result.outcome, "committed");
  assert.equal(passkeyCompletion?.result.mutation, "rotate");
  assert.equal(
    passkeyCompletion?.result.newSessionId,
    lifecycleFixture.passkeyRotatedSessionId,
  );
  assert.equal(
    passkeyCompletion?.result.newSessionFamilyId,
    lifecycleFixture.sessionFamilyId,
  );
  assert.equal(passkeyCompletion?.result.sessionVersion, 3);
  assert.deepEqual(passkeyCompletion?.result.credential, {
    credentialVersion: 2,
    securityRevision: 1,
    status: "active",
    signCount: 1,
    backupEligible: false,
    backedUp: false,
  });
  const [passkeyReplay] = await asApi(
    (transaction) =>
      transaction<{ result: typeof passkeyCompletion.result }[]>`
      SELECT app.complete_mfa_passkey_authentication_v1(
        ${sql.json(passkeyCompletionRequest)}::jsonb
      ) AS result
    `,
  );
  assert.deepEqual(passkeyReplay?.result, passkeyCompletion.result);
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`
        SELECT app.complete_mfa_passkey_authentication_v1(
          ${sql.json({
            ...passkeyCompletionRequest,
            completion: {
              ...passkeyCompletionRequest.completion,
              observedSignCount: 2,
            },
          })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const [passkeyCommittedState] = await sql<
    {
      source_reason: string;
      credential_version: number;
      sign_count: number;
      token_matches: boolean;
      csrf_matches: boolean;
      evidence_count: number;
      passkey_audit_count: number;
    }[]
  >`
    SELECT source_session.revoke_reason AS source_reason,
           credential.version::integer AS credential_version,
           credential.sign_count::integer AS sign_count,
           new_session.token_digest = ${fixtureDigest("passkey-session-token")} AS token_matches,
           new_session.csrf_secret_digest = ${fixtureDigest("passkey-session-csrf")} AS csrf_matches,
           (SELECT count(*)::integer FROM public.auth_session_mfa_evidence AS evidence
             WHERE evidence.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND evidence.session_id = ${lifecycleFixture.passkeyRotatedSessionId}::uuid) AS evidence_count,
           (SELECT count(*)::integer FROM public.audit_events AS event
             WHERE event.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND event.action = 'tenant.identity.mfa_passkey_step_up_completed') AS passkey_audit_count
    FROM public.auth_sessions AS source_session
    JOIN public.auth_sessions AS new_session
      ON new_session.id = ${lifecycleFixture.passkeyRotatedSessionId}::uuid
    CROSS JOIN public.tenant_webauthn_credentials AS credential
    WHERE source_session.id = ${lifecycleFixture.rotatedSessionId}::uuid
      AND credential.id = ${lifecycleFixture.webauthnCredentialId}::uuid
  `;
  assert.deepEqual(passkeyCommittedState, {
    source_reason: "mfa_session_rotated",
    credential_version: 2,
    sign_count: 1,
    token_matches: true,
    csrf_matches: true,
    evidence_count: 3,
    passkey_audit_count: 1,
  });

  const verificationResult = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    await transaction`
      SELECT set_config('app.tenant_id', ${lifecycleFixture.tenantId}, true)
    `;
    return {
      value: await transaction<{ row_count: number; all_valid: boolean }[]>`
        SELECT count(*)::integer AS row_count, bool_and(valid) AS all_valid
        FROM app.verify_audit_chain(${lifecycleFixture.tenantId}::uuid)
      `,
    };
  });
  const [auditVerification] = verificationResult.value;
  // Tenant authorization seeding contributes seven events; the two step-up
  // events plus the verifier's terminal anchor bring this projection to ten.
  assert.equal(auditVerification?.row_count, 10);
  assert.equal(auditVerification?.all_valid, true);

  type DeviceProjection = {
    id: string;
    kind: "totp" | "passkey";
    status: "active" | "revoked";
    displayName: string;
    version: number;
    discoverable: boolean;
    backupEligible: boolean;
    backedUp: boolean;
    transports: string[];
    createdAt: string;
    lastUsedAt: string | null;
    revokedAt: string | null;
  };
  const [devicePage] = await asScopedApi(
    (transaction) =>
      transaction<{ page: { items: DeviceProjection[] } }[]>`
      SELECT app.list_my_mfa_devices_v1(
        ${lifecycleFixture.passkeyRotatedSessionId}::uuid,
        NULL, NULL, 101, false
      ) AS page
    `,
  );
  assert.equal(devicePage?.page.items.length, 2);
  assert.deepEqual(
    devicePage?.page.items.map((device) => device.kind).toSorted(),
    ["passkey", "totp"],
  );
  const serializedDevicePage = JSON.stringify(devicePage?.page);
  for (const forbidden of [
    "secretEnvelope",
    "publicKey",
    "aaguid",
    "signCount",
    "credentialId",
    "userHandleDigest",
    "keyVersion",
    "lastAcceptedCounter",
  ]) {
    assert.equal(serializedDevicePage.includes(forbidden), false, forbidden);
  }

  await assert.rejects(
    asApi(async (transaction) => {
      await transaction`
        SELECT set_config('app.tenant_id', ${lifecycleFixture.wrongFamilyId}, true),
               set_config('app.user_id', ${lifecycleFixture.userId}, true)
      `;
      return transaction`
        SELECT app.list_my_mfa_devices_v1(
          ${lifecycleFixture.passkeyRotatedSessionId}::uuid,
          NULL, NULL, 10, false
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const renameAt = new Date(passkeyCompletedAt.getTime() + 1_000);
  const renameRequest = {
    sessionId: lifecycleFixture.passkeyRotatedSessionId,
    tenantId: lifecycleFixture.tenantId,
    userId: lifecycleFixture.userId,
    deviceId: lifecycleFixture.webauthnCredentialId,
    kind: "passkey",
    displayName: "Security key",
    expectedVersion: 2,
    occurredAt: renameAt.toISOString(),
  };
  const [renamedDevice] = await asScopedApi(
    (transaction) =>
      transaction<
        {
          result: { device: DeviceProjection; currentSessionRevoked: boolean };
        }[]
      >`
      SELECT app.rename_my_passkey_v1(
        ${sql.json(renameRequest)}::jsonb
      ) AS result
    `,
  );
  assert.equal(renamedDevice?.result.device.displayName, "Security key");
  assert.equal(renamedDevice?.result.device.version, 3);
  assert.equal(renamedDevice?.result.currentSessionRevoked, false);
  await assert.rejects(
    asScopedApi(
      (transaction) =>
        transaction`
        SELECT app.rename_my_passkey_v1(
          ${sql.json({ ...renameRequest, displayName: "Stale", occurredAt: new Date(renameAt.getTime() + 500).toISOString() })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const revokeRequest = {
    sessionId: lifecycleFixture.passkeyRotatedSessionId,
    tenantId: lifecycleFixture.tenantId,
    userId: lifecycleFixture.userId,
    deviceId: lifecycleFixture.webauthnCredentialId,
    kind: "passkey",
    expectedVersion: 3,
    occurredAt: new Date(renameAt.getTime() + 1_000).toISOString(),
  };
  const [revokedDevice] = await asScopedApi(
    (transaction) =>
      transaction<
        {
          result: { device: DeviceProjection; currentSessionRevoked: boolean };
        }[]
      >`
      SELECT app.revoke_my_mfa_device_v1(
        ${sql.json(revokeRequest)}::jsonb
      ) AS result
    `,
  );
  assert.equal(revokedDevice?.result.device.status, "revoked");
  assert.equal(revokedDevice?.result.device.version, 4);
  assert.equal(revokedDevice?.result.currentSessionRevoked, true);

  const [deviceCommit] = await sql<
    {
      session_revoked: boolean;
      audit_count: number;
      metadata_redacted: boolean;
    }[]
  >`
    SELECT session.revoked_at IS NOT NULL AS session_revoked,
           (SELECT count(*)::integer
              FROM public.audit_events AS event
             WHERE event.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND event.action IN (
                 'tenant.identity.mfa_passkey_renamed',
                 'tenant.identity.mfa_passkey_revoked'
               )) AS audit_count,
           NOT EXISTS (
             SELECT 1 FROM public.audit_events AS event
             WHERE event.tenant_id = ${lifecycleFixture.tenantId}::uuid
               AND event.action IN (
                 'tenant.identity.mfa_passkey_renamed',
                 'tenant.identity.mfa_passkey_revoked'
               )
               AND (
                 event.metadata ?| ARRAY[
                   'displayName', 'credentialId', 'publicKey',
                   'secretEnvelope', 'aaguid'
                 ]
                 OR event.metadata::text LIKE '%Security key%'
                 OR event.metadata ->> 'secret_material_included' <> 'false'
               )
           ) AS metadata_redacted
    FROM public.auth_sessions AS session
    WHERE session.id = ${lifecycleFixture.passkeyRotatedSessionId}::uuid
  `;
  assert.deepEqual(deviceCommit, {
    session_revoked: true,
    audit_count: 2,
    metadata_redacted: true,
  });
  const deviceAuditVerification = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    await transaction`
      SELECT set_config('app.tenant_id', ${lifecycleFixture.tenantId}, true)
    `;
    return {
      value: await transaction<{ row_count: number; all_valid: boolean }[]>`
        SELECT count(*)::integer AS row_count, bool_and(valid) AS all_valid
        FROM app.verify_audit_chain(${lifecycleFixture.tenantId}::uuid)
      `,
    };
  });
  const [deviceAuditState] = deviceAuditVerification.value;
  // Revoking the TOTP and passkey devices appends two more audit events.
  assert.deepEqual(deviceAuditState, { row_count: 12, all_valid: true });

  const [compatibility] = await sql<
    {
      current_count: number;
      current_latest: string;
      current_hash: string;
      current_fingerprint: string;
      predecessor_count: number;
      predecessor_hash: string;
      predecessor_fingerprint: string;
      retired_count: number;
      retired_hash: string;
      retired_fingerprint: string;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS current_count,
           current_projection.latest_created_at::text AS current_latest,
           current_projection.latest_hash AS current_hash,
           current_projection.migration_fingerprint AS current_fingerprint,
           predecessor_projection.applied_count::integer AS predecessor_count,
           predecessor_projection.latest_hash AS predecessor_hash,
           predecessor_projection.migration_fingerprint AS predecessor_fingerprint,
           retired_projection.applied_count::integer AS retired_count,
           retired_projection.latest_hash AS retired_hash,
           retired_projection.migration_fingerprint AS retired_fingerprint
    FROM app.schema_compatibility_v55() AS current_projection
    CROSS JOIN app.schema_compatibility_v47() AS predecessor_projection
    CROSS JOIN app.schema_compatibility_v46() AS retired_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: expectedMigrationCount,
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    predecessor_count: 0,
    predecessor_hash: "UNSUPPORTED",
    predecessor_fingerprint: "UNSUPPORTED",
    retired_count: 0,
    retired_hash: "UNSUPPORTED",
    retired_fingerprint: "UNSUPPORTED",
  });
} finally {
  await sql.end();
}
