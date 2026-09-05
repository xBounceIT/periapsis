import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type JsonRecord = Record<string, postgres.JSONValue>;

const databaseUrl = process.env.PERIAPSIS_TENANT_PROVIDER_MFA_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_PROVIDER_MFA_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sql = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d30aa-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const bytes = (label: string): Buffer =>
  createHash("sha256").update(label).digest();
const b64 = (label: string): string => bytes(label).toString("base64");

const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  provider: uuid(4),
  binding: uuid(5),
  epoch1: uuid(6),
  source1: uuid(7),
  grant1: uuid(8),
  identity: uuid(9),
  alias: uuid(10),
  policy: uuid(11),
  epoch2: uuid(12),
  source2: uuid(13),
  grant2: uuid(14),
  replaySession: uuid(20),
  capAllowedSession: uuid(21),
  capDeniedSession: uuid(22),
  expiredSession: uuid(23),
  terminalSession: uuid(24),
  contentionSession: uuid(25),
  replayFamily: uuid(30),
  capAllowedFamily: uuid(31),
  capDeniedFamily: uuid(32),
  expiredFamily: uuid(33),
  terminalFamily: uuid(34),
  contentionFamily: uuid(35),
  replayContinuation: uuid(40),
  capAllowedContinuation: uuid(41),
  capDeniedContinuation: uuid(42),
  expiredContinuation: uuid(43),
  initialContinuation: uuid(44),
  contentionContinuation: uuid(45),
  initialExpiredContinuation: uuid(46),
  initialOperation: uuid(47),
  initialExpiredOperation: uuid(48),
  trustRule: uuid(49),
  clientSecret: uuid(50),
  totpFactor: uuid(51),
  materiallessSession: uuid(52),
  materiallessFamily: uuid(53),
  materiallessRotatedSession: uuid(54),
  materiallessStepUp: uuid(55),
  materiallessPromotedSession: uuid(56),
  epochInitialContinuation: uuid(58),
  epochInitialOperation: uuid(59),
  directInitialOperation: uuid(60),
  directInitialSession: uuid(61),
  directInitialFamily: uuid(62),
  directRotatedSession: uuid(63),
  directFinalSession: uuid(64),
} as const;

const sessionIds = [
  fixture.replaySession,
  fixture.capAllowedSession,
  fixture.capDeniedSession,
  fixture.expiredSession,
  fixture.terminalSession,
  fixture.contentionSession,
] as const;
const familyIds = [
  fixture.replayFamily,
  fixture.capAllowedFamily,
  fixture.capDeniedFamily,
  fixture.expiredFamily,
  fixture.terminalFamily,
  fixture.contentionFamily,
] as const;

function assertSqlState(
  error: unknown,
  expected: string,
): asserts error is Error {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert("code" in error, "expected a PostgreSQL SQLSTATE");
  assert.equal(error.code, expected, error.message);
}

function isJsonRecord(
  value: postgres.JSONValue | undefined,
): value is JsonRecord {
  return (
    value !== undefined &&
    value !== null &&
    !Array.isArray(value) &&
    typeof value === "object"
  );
}

function object(
  value: postgres.JSONValue | undefined,
  label: string,
): JsonRecord {
  assert(isJsonRecord(value), `${label} must be an object`);
  return value;
}

function jsonField(value: JsonRecord, key: string): postgres.JSONValue {
  const field = value[key];
  if (field === undefined) {
    throw new Error(`${key} is required`);
  }
  return field;
}

async function asApi<T>(
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    await transaction`
      SELECT set_config('app.user_id',${fixture.user},true),
             set_config('app.tenant_id',${fixture.tenant},true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function mutationSnapshot(): Promise<postgres.JSONValue> {
  const [row] = await sql<{ snapshot: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'users',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.users AS t WHERE t.id=${fixture.user}::uuid),
      'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_memberships AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'identities',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_federated_external_identities AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'aliases',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_federated_external_identity_aliases AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'grants',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_federated_provider_access_grants AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'profiles',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_federated_provider_profile_contributions AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'materializedProfiles',(SELECT coalesce(jsonb_agg(to_jsonb(t)
        ORDER BY t.tenant_id,t.membership_id),'[]')
        FROM public.tenant_user_profiles AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.auth_sessions AS t WHERE t.user_id=${fixture.user}::uuid),
      'states',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.session_id),'[]')
        FROM public.auth_session_mfa_states AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid AND t.user_id=${fixture.user}::uuid),
      'sessionProvenance',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.session_id),'[]')
        FROM public.auth_session_federated_provenance AS t WHERE t.tenant_id=${fixture.tenant}::uuid),
      'sessionPins',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.session_id,t.policy_id),'[]')
        FROM public.auth_session_mfa_policy_pins AS t WHERE t.tenant_id=${fixture.tenant}::uuid),
      'sessionEvidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.auth_session_mfa_evidence AS t WHERE t.tenant_id=${fixture.tenant}::uuid),
      'factors',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_totp_factors AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid AND t.user_id=${fixture.user}::uuid),
      'challenges',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_mfa_step_up_challenges AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_mfa_authority_anchors AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'anchorPins',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.anchor_id,t.policy_id),'[]')
        FROM public.tenant_mfa_authority_policy_pins AS t WHERE t.tenant_id=${fixture.tenant}::uuid),
      'anchorEvidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_mfa_authority_evidence AS t WHERE t.tenant_id=${fixture.tenant}::uuid),
      'materials',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_oidc_session_materials AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'commands',(SELECT coalesce(jsonb_agg(to_jsonb(t)
        ORDER BY t.session_id,t.expected_version),'[]')
        FROM public.tenant_federated_session_revalidation_commands AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'continuations',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_post_primary_continuations AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'provenance',(SELECT coalesce(jsonb_agg(to_jsonb(t)
        ORDER BY t.continuation_id),'[]')
        FROM public.tenant_post_primary_federated_provenance AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'applications',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_federated_authentication_applications AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'transactions',(SELECT coalesce(jsonb_agg(to_jsonb(t)
        ORDER BY t.transaction_id),'[]')
        FROM public.tenant_federated_authentication_transactions AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'evidence',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.tenant_post_primary_continuation_evidence AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'pins',(SELECT coalesce(jsonb_agg(to_jsonb(t)
        ORDER BY t.continuation_id,t.policy_id),'[]')
        FROM public.tenant_post_primary_continuation_policy_pins AS t
        WHERE t.tenant_id=${fixture.tenant}::uuid),
      'audit',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]')
        FROM public.audit_events AS t WHERE t.tenant_id=${fixture.tenant}::uuid)
    ) AS snapshot
  `;
  assert(row);
  return row.snapshot;
}

async function loadRevalidation(sessionId: string): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_session_revalidation_v1(
        ${transaction.json({
          sessionId,
          tenantId: fixture.tenant,
          audience: "api",
          authenticationMethod: "oidc",
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  assert.notEqual(
    row?.value,
    null,
    "generic revalidation authority is required",
  );
  return object(row?.value ?? undefined, "generic revalidation authority");
}

async function applyRevalidation(mutation: JsonRecord): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_session_revalidation_v1(
        ${transaction.json(mutation)}::jsonb
      ) AS value
    `,
  );
  return object(row?.value, "generic revalidation result");
}

function stepUpMutation(
  authority: JsonRecord,
  sessionId: string,
  continuationId: string,
  receiptLabel: string,
  observedAt = new Date(),
  expiresAt = new Date(Date.now() + 10 * 60_000),
): JsonRecord {
  const snapshot = object(authority.snapshot, "generic snapshot");
  const live = object(authority.live, "generic live authority");
  return {
    tenantId: fixture.tenant,
    sessionId,
    userId: fixture.user,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(snapshot, "version"),
    observedAt: observedAt.toISOString(),
    decision: "step_up",
    reason: "assurance_insufficient",
    requirement: jsonField(live, "requirement"),
    continuation: {
      continuationId,
      receiptDigest: b64(receiptLabel),
      expiresAt: expiresAt.toISOString(),
    },
  };
}

async function resolveContinuation(
  continuationId: string,
  receiptLabel: string,
  evaluatedAt = new Date(),
): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${continuationId}::uuid,'continuation','session.create','api',
        ${evaluatedAt},${bytes(receiptLabel)}::bytea
      ) AS value
    `,
  );
  return object(row?.value, "generic continuation authority");
}

async function createAndClaimTotpChallenge(
  authority: JsonRecord,
  receiptLabel: string,
  label: string,
): Promise<{ binding: JsonRecord; challengeId: string; completedAt: Date }> {
  const binding: JsonRecord = Object.fromEntries(
    [
      "flow",
      "tenantId",
      "userId",
      "identityEpoch",
      "continuationId",
      "anchorVersion",
      "anchorExpiresAt",
      "anchorRecoveryRestricted",
      "action",
      "audience",
      "requirement",
      "baselineEvidence",
    ].map((field) => [field, jsonField(authority, field)]),
  );
  const challengeId = b64(`${label}:challenge`);
  const browserDigest = bytes(`${label}:browser`);
  const createdAt = new Date();
  const [created] = await asApi(
    (transaction) => transaction<{ value: boolean }[]>`
    SELECT app.create_mfa_step_up_challenge_v1(${transaction.json({
      id: challengeId,
      browserDigest: browserDigest.toString("base64"),
      binding,
      continuationReceiptDigest: b64(receiptLabel),
      allowedFactors: ["totp"],
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + 5 * 60_000).toISOString(),
      state: "pending",
      version: 1,
    })}::jsonb) AS value
  `,
  );
  assert.equal(created?.value, true);
  const [claimed] = await asApi(
    (transaction) => transaction<{ value: JsonRecord }[]>`
    SELECT app.claim_mfa_step_up_challenge_v2(
      ${Buffer.from(challengeId, "base64")}::bytea,${browserDigest}::bytea,
      'totp',${new Date()},${bytes(receiptLabel)}::bytea
    ) AS value
  `,
  );
  assert.equal(claimed?.value.state, "claimed");
  assert.equal(claimed?.value.version, 2);
  return { binding, challengeId, completedAt: new Date() };
}

function totpCompletion(
  challenge: Awaited<ReturnType<typeof createAndClaimTotpChallenge>>,
  receiptLabel: string,
  sessionId: string,
  familyId: string,
  factorVersion: number,
  absoluteExpiresAt = new Date(challenge.completedAt.getTime() + 60 * 60_000),
): JsonRecord {
  return {
    challengeId: challenge.challengeId,
    expectedChallengeVersion: 2,
    binding: challenge.binding,
    factorId: fixture.totpFactor,
    expectedFactorVersion: factorVersion,
    expectedSecurityRevision: 1,
    counter: factorVersion - 1,
    completedAt: challenge.completedAt.toISOString(),
    sessionMutation: "consume_continuation",
    auditKind: "mfa.totp_step_up_completed",
    recoveryRestricted: false,
    session: {
      sessionId,
      familyId,
      tokenDigest: b64(`${sessionId}:token`),
      csrfDigest: b64(`${sessionId}:csrf`),
      authenticationMethod: "totp",
      idleExpiresAt: new Date(
        challenge.completedAt.getTime() + 20 * 60_000,
      ).toISOString(),
      absoluteExpiresAt: absoluteExpiresAt.toISOString(),
    },
    continuationReceiptDigest: b64(receiptLabel),
  };
}

async function completeTotp(command: JsonRecord): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: JsonRecord }[]>`
    SELECT app.complete_mfa_totp_step_up_v1(${transaction.json(command)}::jsonb) AS value
  `,
  );
  return object(row?.value, "generic MFA completion");
}

async function assertCompletionSucceedsWithoutCommit(
  command: JsonRecord,
): Promise<void> {
  const before = await mutationSnapshot();
  const rollback = new Error("rollback successful material-backed MFA control");
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
      await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
      await transaction`
      SELECT set_config('app.user_id',${fixture.user},true),set_config('app.tenant_id',${fixture.tenant},true)
    `;
      const [result] = await transaction<{ value: JsonRecord }[]>`
      SELECT app.complete_mfa_totp_step_up_v1(${transaction.json(command)}::jsonb) AS value
    `;
      assert.equal(
        result?.value.newSessionId,
        object(command.session, "positive material-backed session").sessionId,
      );
      await transaction.unsafe("SET CONSTRAINTS ALL IMMEDIATE");
      throw rollback;
    }),
    (error: unknown) => error === rollback,
  );
  assert.deepEqual(
    await mutationSnapshot(),
    before,
    "material-backed positive control did not roll back completely",
  );
}

async function assertRejectedWithoutMutation(
  label: string,
  operation: () => Promise<unknown>,
  code = "40001",
): Promise<void> {
  const before = await mutationSnapshot();
  await assert.rejects(operation(), (error: unknown) => {
    assertSqlState(error, code);
    return true;
  });
  assert.deepEqual(await mutationSnapshot(), before, label);
}

async function tamperFixture(
  operation: (transaction: postgres.TransactionSql) => Promise<unknown>,
): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await operation(transaction);
  });
}

async function assertRequiredMaterialCannotDisappear(
  materialId: string,
  operation: () => Promise<unknown>,
): Promise<void> {
  const before = await mutationSnapshot();
  const [material] = await sql<{ value: JsonRecord }[]>`
    SELECT to_jsonb(material) AS value FROM public.tenant_oidc_session_materials AS material
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${materialId}::uuid
  `;
  assert(material);
  await tamperFixture(
    (transaction) => transaction`
    DELETE FROM public.tenant_oidc_session_materials
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${materialId}::uuid
  `,
  );
  try {
    await assertRejectedWithoutMutation(
      "a login that pinned logout material cannot use the absence exception",
      operation,
    );
  } finally {
    // Restore the exact pre-tamper row, including any legitimate owner transfer.
    await tamperFixture(
      (transaction) => transaction`
      INSERT INTO public.tenant_oidc_session_materials
      SELECT * FROM jsonb_populate_record(
        NULL::public.tenant_oidc_session_materials,${transaction.json(material.value)}::jsonb
      )
    `,
    );
  }
  assert.deepEqual(
    await mutationSnapshot(),
    before,
    "missing-material rejection and restoration changed state",
  );
}

async function assertMateriallessOwners(
  label: string,
  owners: string[],
): Promise<void> {
  const [row] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.tenant_oidc_session_materials
    WHERE tenant_id=${fixture.tenant}::uuid
      AND (session_id=ANY(${owners}::uuid[]) OR continuation_id=ANY(${owners}::uuid[]))
  `;
  assert.equal(row?.count, 0, label);
}

async function advanceMfaPolicy(
  previousRevision: number,
  freshness: number,
  level: "primary" | "mfa" = "mfa",
): Promise<void> {
  const changedAt = new Date();
  await sql.begin(async (transaction) => {
    await transaction`SELECT set_config('app.mfa_policy_write_v1',${`retire:${fixture.policy}:${previousRevision}`},true)`;
    await transaction`
      UPDATE public.mfa_policy_revisions SET retired_at=${changedAt}
      WHERE id=${fixture.policy}::uuid AND revision=${previousRevision}
        AND retired_at IS NULL
    `;
    await transaction`SELECT set_config('app.mfa_policy_write_v1',${`insert:${fixture.policy}:${previousRevision + 1}`},true)`;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,freshness_nanoseconds,created_at
      ) VALUES (${fixture.policy}::uuid,${previousRevision + 1},${fixture.tenant}::uuid,
        'tenant_baseline',${level},${level === "mfa"},${freshness},${changedAt})
    `;
    await transaction`SELECT set_config('app.mfa_policy_write_v1','',true)`;
  });
}

async function verifyMateriallessMfaLifecycle(
  initialAuthority: JsonRecord,
): Promise<void> {
  const initialLabel = "generic-mfa:initial-receipt";
  await assertMateriallessOwners("initial login does not require a vault row", [
    fixture.initialContinuation,
  ]);
  const challenge = await createAndClaimTotpChallenge(
    initialAuthority,
    initialLabel,
    "materialless-initial",
  );
  const completion = totpCompletion(
    challenge,
    initialLabel,
    fixture.materiallessSession,
    fixture.materiallessFamily,
    1,
  );

  const [factor] = await sql<{ updatedAt: Date }[]>`
    SELECT updated_at AS "updatedAt" FROM public.tenant_totp_factors
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.totpFactor}::uuid
  `;
  assert(factor);
  await tamperFixture(
    (transaction) => transaction`
    UPDATE public.tenant_totp_factors SET status='revoked',record_version=2,
      security_revision=2,revoked_at=transaction_timestamp(),
      revoke_reason='runtime revoked factor proof',updated_at=transaction_timestamp()
    WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.totpFactor}::uuid
  `,
  );
  try {
    await assertRejectedWithoutMutation(
      "revoked factor cannot consume the material-less continuation",
      () => completeTotp(completion),
      "42501",
    );
  } finally {
    await tamperFixture(
      (transaction) => transaction`
      UPDATE public.tenant_totp_factors SET status='active',record_version=1,
        security_revision=1,revoked_at=NULL,revoke_reason=NULL,updated_at=${factor.updatedAt}
      WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.totpFactor}::uuid
    `,
    );
  }

  await tamperFixture(
    (transaction) => transaction`
    UPDATE public.tenant_federated_authentication_applications
    SET transaction_id=${bytes("materialless:altered-source")}::bytea
    WHERE tenant_id=${fixture.tenant}::uuid AND continuation_id=${fixture.initialContinuation}::uuid
  `,
  );
  try {
    await assertRejectedWithoutMutation(
      "altered immutable login lineage cannot promote a continuation",
      () => completeTotp(completion),
    );
  } finally {
    await tamperFixture(
      (transaction) => transaction`
      UPDATE public.tenant_federated_authentication_applications
      SET transaction_id=${bytes("generic-mfa:initial:transaction")}::bytea
      WHERE tenant_id=${fixture.tenant}::uuid AND continuation_id=${fixture.initialContinuation}::uuid
    `,
    );
  }

  const completed = await completeTotp(completion);
  assert.equal(completed.newSessionId, fixture.materiallessSession);
  const completedSnapshot = await mutationSnapshot();
  assert.deepEqual(await completeTotp(completion), completed);
  assert.deepEqual(
    await mutationSnapshot(),
    completedSnapshot,
    "exact material-less MFA replay mutated state",
  );
  const [initialSession] = await sql<
    {
      authenticationMethod: string;
      familyId: string;
      absoluteExpiresAt: Date;
    }[]
  >`
    SELECT authentication_method AS "authenticationMethod",rotation_family_id::text AS "familyId",
      absolute_expires_at AS "absoluteExpiresAt" FROM public.auth_sessions
    WHERE id=${fixture.materiallessSession}::uuid
  `;
  assert(initialSession);
  assert.equal(initialSession.authenticationMethod, "oidc");
  assert.equal(initialSession.familyId, fixture.materiallessFamily);
  await assertMateriallessOwners("MFA promotion retains material absence", [
    fixture.initialContinuation,
    fixture.materiallessSession,
  ]);

  await advanceMfaPolicy(1, 0);
  const rotateAuthority = await loadRevalidation(fixture.materiallessSession);
  const rotateMutation: JsonRecord = {
    tenantId: fixture.tenant,
    sessionId: fixture.materiallessSession,
    userId: fixture.user,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(
      object(rotateAuthority.snapshot, "rotation snapshot"),
      "version",
    ),
    observedAt: new Date().toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(
      object(rotateAuthority.live, "rotation live"),
      "requirement",
    ),
    session: {
      sessionId: fixture.materiallessRotatedSession,
      familyId: fixture.materiallessFamily,
      tokenDigest: b64("materialless-rotation:token"),
      csrfDigest: b64("materialless-rotation:csrf"),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(Date.now() + 20 * 60_000).toISOString(),
      absoluteExpiresAt: initialSession.absoluteExpiresAt.toISOString(),
    },
  };
  const rotated = await applyRevalidation(rotateMutation);
  assert.equal(rotated.newSessionId, fixture.materiallessRotatedSession);
  const rotationSnapshot = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(rotateMutation), rotated);
  assert.deepEqual(
    await mutationSnapshot(),
    rotationSnapshot,
    "exact material-less rotation replay mutated state",
  );

  // Whole-second freshness makes the existing factor stale before step-up.
  await new Promise((resolve) =>
    setTimeout(
      resolve,
      Math.max(0, challenge.completedAt.getTime() + 1_100 - Date.now()),
    ),
  );
  await advanceMfaPolicy(2, 1_000_000_000);
  const stepUpAuthority = await loadRevalidation(
    fixture.materiallessRotatedSession,
  );
  const stepUpLabel = "materialless-revalidation:receipt";
  const stepUp = stepUpMutation(
    stepUpAuthority,
    fixture.materiallessRotatedSession,
    fixture.materiallessStepUp,
    stepUpLabel,
  );
  const stepUpResult = await applyRevalidation(stepUp);
  assert.equal(stepUpResult.continuationId, fixture.materiallessStepUp);
  const stepUpSnapshot = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(stepUp), stepUpResult);
  assert.deepEqual(
    await mutationSnapshot(),
    stepUpSnapshot,
    "exact material-less step-up replay mutated state",
  );
  const continuationAuthority = await resolveContinuation(
    fixture.materiallessStepUp,
    stepUpLabel,
  );
  assert.equal(
    continuationAuthority.continuationOrigin,
    "session_revalidation",
  );
  assert.equal(
    continuationAuthority.sourceSessionId,
    fixture.materiallessRotatedSession,
  );
  assert.equal(
    continuationAuthority.sourceSessionFamilyId,
    fixture.materiallessFamily,
  );
  const secondChallenge = await createAndClaimTotpChallenge(
    continuationAuthority,
    stepUpLabel,
    "materialless-revalidation",
  );
  const secondCompletion = totpCompletion(
    secondChallenge,
    stepUpLabel,
    fixture.materiallessPromotedSession,
    fixture.materiallessFamily,
    2,
    initialSession.absoluteExpiresAt,
  );
  const extendedDeadline = structuredClone(secondCompletion);
  object(extendedDeadline.session, "extended session").absoluteExpiresAt =
    new Date(initialSession.absoluteExpiresAt.getTime() + 1).toISOString();
  await assertRejectedWithoutMutation(
    "step-up cannot extend the family deadline",
    () => completeTotp(extendedDeadline),
    "22023",
  );
  const secondResult = await completeTotp(secondCompletion);
  assert.equal(secondResult.newSessionId, fixture.materiallessPromotedSession);
  const secondSnapshot = await mutationSnapshot();
  assert.deepEqual(await completeTotp(secondCompletion), secondResult);
  assert.deepEqual(
    await mutationSnapshot(),
    secondSnapshot,
    "exact promoted material-less MFA replay mutated state",
  );
  const [lineage] = await sql<
    {
      sameFamily: boolean;
      sameDeadline: boolean;
      primaryPreserved: boolean;
      rotatedFrom: string;
      sourceRevoked: boolean;
    }[]
  >`
    SELECT initial.rotation_family_id=rotated.rotation_family_id
      AND initial.rotation_family_id=promoted.rotation_family_id AS "sameFamily",
      initial.absolute_expires_at=rotated.absolute_expires_at
      AND initial.absolute_expires_at=promoted.absolute_expires_at AS "sameDeadline",
      initial.authentication_method='oidc' AND rotated.authentication_method='oidc'
      AND promoted.authentication_method='oidc' AS "primaryPreserved",
      rotated.rotated_from_session_id::text AS "rotatedFrom",
      initial.revoked_at IS NOT NULL AND rotated.revoked_at IS NOT NULL AS "sourceRevoked"
    FROM public.auth_sessions AS initial
    JOIN public.auth_sessions AS rotated ON rotated.id=${fixture.materiallessRotatedSession}::uuid
    JOIN public.auth_sessions AS promoted ON promoted.id=${fixture.materiallessPromotedSession}::uuid
    WHERE initial.id=${fixture.materiallessSession}::uuid
  `;
  assert.deepEqual(lineage, {
    sameFamily: true,
    sameDeadline: true,
    primaryPreserved: true,
    rotatedFrom: fixture.materiallessSession,
    sourceRevoked: true,
  });
  await assertMateriallessOwners(
    "complete material-less lifecycle never fabricates a vault marker",
    [
      fixture.initialContinuation,
      fixture.materiallessSession,
      fixture.materiallessRotatedSession,
      fixture.materiallessStepUp,
      fixture.materiallessPromotedSession,
    ],
  );
  assert(await loadRevalidation(fixture.materiallessPromotedSession));
}

async function directRotationMutation(
  sourceId: string,
  successorId: string,
): Promise<JsonRecord> {
  const authority = await loadRevalidation(sourceId);
  const [source] = await sql<{ familyId: string; absoluteExpiresAt: Date }[]>`
    SELECT rotation_family_id::text AS "familyId",absolute_expires_at AS "absoluteExpiresAt"
    FROM public.auth_sessions WHERE id=${sourceId}::uuid
  `;
  assert(source);
  return {
    tenantId: fixture.tenant,
    sessionId: sourceId,
    userId: fixture.user,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(
      object(authority.snapshot, "direct rotation snapshot"),
      "version",
    ),
    observedAt: new Date().toISOString(),
    decision: "rotate",
    reason: "policy_refresh",
    requirement: jsonField(
      object(authority.live, "direct rotation live"),
      "requirement",
    ),
    session: {
      sessionId: successorId,
      familyId: source.familyId,
      tokenDigest: b64(`${successorId}:direct-token`),
      csrfDigest: b64(`${successorId}:direct-csrf`),
      authenticationMethod: "oidc",
      idleExpiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      absoluteExpiresAt: source.absoluteExpiresAt.toISOString(),
    },
  };
}

async function verifyDirectInitialMateriallessLineage(): Promise<void> {
  // This distinct final fixture permits primary-only login so the public apply
  // path legitimately issues a session instead of an MFA continuation.
  await advanceMfaPolicy(3, 0, "primary");
  await seedClaimedOidcTransaction(
    "generic-mfa:direct-initial",
    fixture.directInitialOperation,
  );
  const appliedAt = new Date();
  const command = initialApplyCommand(
    "generic-mfa:direct-initial",
    await loadInitialPlanning(),
    fixture.directInitialOperation,
    uuid(999),
    "generic-mfa:unused-direct-receipt",
    appliedAt,
  );
  const apply = object(command.apply, "direct initial apply");
  apply.disposition = "session";
  apply.assurance = "satisfied";
  delete apply.continuation;
  apply.session = {
    sessionId: fixture.directInitialSession,
    familyId: fixture.directInitialFamily,
    tokenDigest: b64("direct-initial:token"),
    csrfDigest: b64("direct-initial:csrf"),
    authenticationMethod: "oidc",
    idleExpiresAt: new Date(appliedAt.getTime() + 5 * 60_000).toISOString(),
    absoluteExpiresAt: new Date(
      appliedAt.getTime() + 10 * 60_000,
    ).toISOString(),
  };
  const admitted = await applyInitial(command);
  assert.equal(admitted.category, "success");
  assert.equal(admitted.sessionId, fixture.directInitialSession);
  const admittedSnapshot = await mutationSnapshot();
  assert.equal((await applyInitial(command)).replayed, true);
  assert.deepEqual(
    await mutationSnapshot(),
    admittedSnapshot,
    "direct initial replay mutated session authority",
  );
  await assertMateriallessOwners(
    "direct initial login requires no vault material",
    [fixture.directInitialSession],
  );
  await advanceMfaPolicy(4, 0, "primary");
  const firstRotation = await directRotationMutation(
    fixture.directInitialSession,
    fixture.directRotatedSession,
  );
  assert.equal(
    (await applyRevalidation(firstRotation)).newSessionId,
    fixture.directRotatedSession,
  );
  await advanceMfaPolicy(5, 0, "primary");
  const secondRotation = await directRotationMutation(
    fixture.directRotatedSession,
    fixture.directFinalSession,
  );
  const assertDirectAttestation = async (expected: boolean): Promise<void> => {
    // Observe the private predicate as admin without extending runtime grants;
    // the public writer may independently reject drift before reaching it.
    const [row] = await sql<{ value: boolean }[]>`
      SELECT app.private_tenant_provider_oidc_material_absence_attested_v1(
        ${fixture.tenant}::uuid,${fixture.directRotatedSession}::uuid,NULL
      ) AS value
    `;
    assert.equal(row?.value, expected, "direct lineage absence attestation");
  };
  await assertDirectAttestation(true);
  await tamperFixture(
    (transaction) => transaction`
    UPDATE public.auth_session_federated_provenance
    SET authenticated_at=authenticated_at + interval '1 millisecond'
    WHERE tenant_id=${fixture.tenant}::uuid
      AND session_id IN (${fixture.directInitialSession}::uuid,${fixture.directRotatedSession}::uuid)
  `,
  );
  try {
    await assertDirectAttestation(false);
    await assertRejectedWithoutMutation(
      "matching drift on root and successor cannot replace the immutable login timestamp",
      () => applyRevalidation(secondRotation),
    );
  } finally {
    await tamperFixture(
      (transaction) => transaction`
      UPDATE public.auth_session_federated_provenance
      SET authenticated_at=authenticated_at - interval '1 millisecond'
      WHERE tenant_id=${fixture.tenant}::uuid
        AND session_id IN (${fixture.directInitialSession}::uuid,${fixture.directRotatedSession}::uuid)
    `,
    );
  }
  await assertDirectAttestation(true);
  const [originalApplication] = await sql<{ value: JsonRecord }[]>`
    SELECT request_snapshot AS value
    FROM public.tenant_federated_authentication_applications
    WHERE tenant_id=${fixture.tenant}::uuid AND session_id=${fixture.directInitialSession}::uuid
  `;
  assert(originalApplication);
  assert.equal(
    object(
      object(
        object(
          originalApplication.value.authentication,
          "direct authentication",
        ).oidc,
        "direct OIDC authentication",
      ).pins,
      "direct OIDC pins",
    ).providerRevision,
    1,
  );
  await tamperFixture(
    (transaction) => transaction`
    UPDATE public.tenant_federated_authentication_applications
    SET request_snapshot=jsonb_set(request_snapshot,
      '{authentication,oidc,pins,providerRevision}','999'::jsonb)
    WHERE tenant_id=${fixture.tenant}::uuid AND session_id=${fixture.directInitialSession}::uuid
  `,
  );
  try {
    await assertDirectAttestation(false);
    await assertRejectedWithoutMutation(
      "duplicate OIDC authentication pins cannot diverge from the original transaction",
      () => applyRevalidation(secondRotation),
    );
  } finally {
    await tamperFixture(
      (transaction) => transaction`
      UPDATE public.tenant_federated_authentication_applications
      SET request_snapshot=${transaction.json(originalApplication.value)}::jsonb
      WHERE tenant_id=${fixture.tenant}::uuid AND session_id=${fixture.directInitialSession}::uuid
    `,
    );
  }
  await assertDirectAttestation(true);
  const rotated = await applyRevalidation(secondRotation);
  assert.equal(rotated.newSessionId, fixture.directFinalSession);
  const rotatedSnapshot = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(secondRotation), rotated);
  assert.deepEqual(
    await mutationSnapshot(),
    rotatedSnapshot,
    "direct successor replay mutated authority",
  );
  await assertMateriallessOwners(
    "direct initial lineage stays material-less after two rotations",
    [
      fixture.directInitialSession,
      fixture.directRotatedSession,
      fixture.directFinalSession,
    ],
  );
}

async function seedFixture(): Promise<void> {
  const createdAt = new Date(Date.now() - 5 * 60_000);
  const idleExpiresAt = new Date(Date.now() + 30 * 60_000);
  const absoluteExpiresAt = new Date(Date.now() + 60 * 60_000);
  await assert.rejects(
    sql`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (${fixture.policy}::uuid,1,NULL,
        'platform_floor','primary',false,0,${createdAt})
    `,
    (error: unknown) => {
      assertSqlState(error, "42501");
      assert.equal(
        error.message,
        "MFA policy revision writer capability is required",
      );
      return true;
    },
    "an MFA policy fixture write bypassed the revision capability",
  );
  await sql.begin(async (transaction) => {
    // Replica mode is limited to the legacy bulk bootstrap below. The MFA
    // policy mutation temporarily returns to origin so its guard is exercised.
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES (${fixture.tenant}::uuid,'generic-mfa-runtime',
        'Generic MFA runtime','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name,active,created_at,updated_at)
      VALUES (${fixture.user}::uuid,'generic-mfa@example.invalid',
        'Generic MFA user',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES (${fixture.membership}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,'tenant_admin','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.user}::uuid,
        ${bytes("generic-mfa:user-handle")}::bytea,1,1,1,
        ${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version,verifier,bound_at,is_active
      ) VALUES (1,${bytes("generic-mfa:keyring")}::bytea,${createdAt},true)
    `;
    await transaction`
      INSERT INTO public.tenant_totp_factors (
        id,tenant_id,user_id,secret_envelope,key_version,otp_algorithm,
        digits,period_seconds,last_accepted_counter,record_version,
        security_revision,status,confirmed_at,created_at,updated_at
      ) VALUES (${fixture.totpFactor}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
        ${Buffer.alloc(32, 0x73)}::bytea,1,'SHA1',6,30,-1,1,1,
        'active',${createdAt},${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id,tenant_id,key,display_name,description,kind,enabled,
        created_by_membership_id,updated_by_membership_id,version,
        created_at,updated_at
      ) VALUES (${fixture.provider}::uuid,${fixture.tenant}::uuid,
        'generic_oidc','Generic OIDC','Generic OIDC runtime fixture','oidc',true,
        ${fixture.membership}::uuid,${fixture.membership}::uuid,1,
        ${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_bindings (
        id,tenant_id,provider_id,key,enabled,profile_priority,auth_revision,
        current_access_epoch_id,created_by_membership_id,
        updated_by_membership_id,version,created_at,updated_at,mapping_revision
      ) VALUES (${fixture.binding}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,'generic_oidc',true,100,1,
        ${fixture.epoch1}::uuid,${fixture.membership}::uuid,
        ${fixture.membership}::uuid,1,${createdAt},${createdAt},1)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_login_keys (
        tenant_id,binding_family,binding_id,key,created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,'tenant_provider',
        ${fixture.binding}::uuid,'generic_oidc',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_policies (
        tenant_id,provider_id,binding_id,provider_kind,
        configuration_revision,security_revision,plan_revision,
        assurance_policy_revision,jit_mode,no_match_policy,enabled,
        created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.provider}::uuid,
        ${fixture.binding}::uuid,'oidc',1,1,1,1,'disabled',
        'provider_access_only',true,
        ${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_provider_configurations (
        tenant_id,provider_id,provider_kind,issuer,client_id,redirect_uri,
        post_logout_redirect_uri,extra_scopes,allow_refresh_token,use_user_info,
        client_secret_revision,discovery_revision,jwks_revision,version,
        created_at,updated_at
      ) VALUES (${fixture.tenant}::uuid,${fixture.provider}::uuid,'oidc',
        'https://generic-oidc.example.invalid','generic-runtime-client',
        'https://generic.example.invalid/oidc/callback',
        'https://generic.example.invalid/logout',ARRAY[]::text[],false,false,
        1,2,1,1,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_client_secrets (
        id,tenant_id,provider_id,revision,key_version,nonce,ciphertext,created_at
      ) VALUES (${fixture.clientSecret}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,1,1,${Buffer.alloc(12, 0x63)}::bytea,
        ${Buffer.alloc(32, 0x64)}::bytea,${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_discovery_snapshots (
        tenant_id,provider_id,revision,issuer,document,document_digest,
        retrieved_at,fresh_until,cacheable,must_revalidate,
        client_authentication,signing_algorithms
      ) VALUES (${fixture.tenant}::uuid,${fixture.provider}::uuid,2,
        'https://generic-oidc.example.invalid',${Buffer.from("{}")}::bytea,
        ${bytes("generic-mfa:discovery")}::bytea,${createdAt},
        ${absoluteExpiresAt},true,false,'client_secret_basic',ARRAY['RS256']::text[])
    `;
    // The legacy sessions pin an older discovery that supported logout;
    // new logins use revision 2, which intentionally has no retained material.
    await transaction`
      INSERT INTO public.tenant_oidc_discovery_snapshots (
        tenant_id,provider_id,revision,issuer,document,document_digest,
        retrieved_at,fresh_until,cacheable,must_revalidate,
        client_authentication,signing_algorithms
      ) VALUES (${fixture.tenant}::uuid,${fixture.provider}::uuid,1,
        'https://generic-oidc.example.invalid',
        ${Buffer.from(
          JSON.stringify({
            end_session_endpoint: "https://generic-oidc.example.invalid/logout",
          }),
        )}::bytea,
        ${bytes("generic-mfa:legacy-discovery")}::bytea,${createdAt},
        ${absoluteExpiresAt},true,false,'client_secret_basic',ARRAY['RS256']::text[])
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_jwks_snapshots (
        tenant_id,provider_id,revision,document,document_digest,
        retrieved_at,fresh_until,cacheable,must_revalidate
      ) VALUES (${fixture.tenant}::uuid,${fixture.provider}::uuid,1,
        ${Buffer.from("{}")}::bytea,${bytes("generic-mfa:jwks")}::bytea,
        ${createdAt},${absoluteExpiresAt},true,false)
    `;
    await transaction`
      INSERT INTO public.tenant_federated_trust_rules (
        id,tenant_id,provider_id,binding_id,provider_kind,revision,enabled,
        level,exact_value,required_values,maximum_authentication_age_seconds,
        created_at
      ) VALUES (${fixture.trustRule}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc',1,true,
        'mfa','mfa',ARRAY[]::text[],3600,${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identities (
        id,tenant_id,provider_id,binding_id,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,
        admitted_configuration_revision,last_observed_at,version,
        created_at,updated_at
      ) VALUES (${fixture.identity}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.binding}::uuid,${fixture.user}::uuid,
        'utf8_exact',${Buffer.alloc(32, 0x61)}::bytea,
        ${Buffer.alloc(12, 0x62)}::bytea,1,1,${createdAt},1,
        ${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identity_aliases (
        id,tenant_id,provider_id,external_identity_id,key_version,
        subject_digest,created_at
      ) VALUES (${fixture.alias}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.identity}::uuid,1,
        ${bytes("generic-mfa:subject")}::bytea,${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id,tenant_id,kind,key,authoritative,protected,created_at
      ) VALUES (${fixture.source1}::uuid,${fixture.tenant}::uuid,
        'identity_provider_access',
        ${`identity_provider_access:${fixture.binding}:1`},true,false,${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs (
        id,tenant_id,binding_id,provider_id,source_id,sequence,
        started_by_membership_id,started_at,version
      ) VALUES (${fixture.epoch1}::uuid,${fixture.tenant}::uuid,
        ${fixture.binding}::uuid,${fixture.provider}::uuid,
        ${fixture.source1}::uuid,1,${fixture.membership}::uuid,${createdAt},1)
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_access_grants (
        id,tenant_id,provider_id,binding_id,access_epoch_id,source_id,
        external_identity_id,membership_id,user_id,owns_membership,
        started_at,last_observed_at,version
      ) VALUES (${fixture.grant1}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.binding}::uuid,
        ${fixture.epoch1}::uuid,${fixture.source1}::uuid,
        ${fixture.identity}::uuid,${fixture.membership}::uuid,
        ${fixture.user}::uuid,false,${createdAt},${createdAt},1)
    `;
    await transaction.unsafe("SET LOCAL session_replication_role = origin");
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.membership}::uuid
      )
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.policy}:1`},
        true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (${fixture.policy}::uuid,1,${fixture.tenant}::uuid,
        'tenant_baseline','mfa',true,0,${createdAt})
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1','',true)
    `;
    await transaction.unsafe("SET LOCAL session_replication_role = replica");

    await Promise.all(
      sessionIds.map(async (sessionId, index) => {
        const familyId = familyIds[index];
        assert(familyId);
        await transaction`
        INSERT INTO public.auth_sessions (
          id,user_id,rotation_family_id,active_tenant_id,token_digest,
          csrf_secret_digest,authentication_method,last_seen_at,
          idle_expires_at,absolute_expires_at,created_at
        ) VALUES (${sessionId}::uuid,${fixture.user}::uuid,${familyId}::uuid,
          ${fixture.tenant}::uuid,${bytes(`generic-mfa:token:${index}`)}::bytea,
          ${bytes(`generic-mfa:csrf:${index}`)}::bytea,'oidc',${createdAt},
          ${idleExpiresAt},${absoluteExpiresAt},${createdAt})
      `;
        await transaction`
        INSERT INTO public.auth_session_mfa_states (
          session_id,tenant_id,user_id,session_version,identity_epoch,
          recovery_restricted,audience,primary_kind,
          session_invalidation_epoch,issued_at
        ) VALUES (${sessionId}::uuid,${fixture.tenant}::uuid,
          ${fixture.user}::uuid,1,1,false,'api','tenant_provider',1,${createdAt})
      `;
        await transaction`
        INSERT INTO public.auth_session_federated_provenance (
          tenant_id,session_id,user_id,primary_kind,authentication_method,
          provider_id,binding_id,provider_kind,external_identity_id,
          external_identity_revision,trust_rule_revision,authenticated_at
        ) VALUES (${fixture.tenant}::uuid,${sessionId}::uuid,
          ${fixture.user}::uuid,'tenant_provider','oidc',${fixture.provider}::uuid,
          ${fixture.binding}::uuid,'oidc',${fixture.identity}::uuid,1,1,
          ${createdAt})
      `;
        await transaction`
        INSERT INTO public.auth_session_mfa_policy_pins (
          tenant_id,session_id,policy_id,policy_revision
        ) VALUES (${fixture.tenant}::uuid,${sessionId}::uuid,
          ${fixture.policy}::uuid,1)
      `;
        await transaction`
        INSERT INTO public.auth_session_mfa_evidence (
          id,tenant_id,session_id,level,kind,provider_id,binding_id,
          authenticated_at,trust_rule_revision
        ) VALUES (uuidv7(),${fixture.tenant}::uuid,${sessionId}::uuid,
          'primary','provider',${fixture.provider}::uuid,
          ${fixture.binding}::uuid,${createdAt},1)
      `;
      }),
    );
  });

  await Promise.all(
    sessionIds.map(async (sessionId, index) => {
      const familyId = familyIds[index];
      assert(familyId);
      await seedClaimedOidcTransaction(
        `generic-mfa:legacy-session-${index}`,
        uuid(100 + index),
        {
          sessionId,
          familyId,
          appliedAt: createdAt,
          expiresAt: new Date(createdAt.getTime() + 10 * 60_000),
        },
      );
    }),
  );

  await sql`
    INSERT INTO public.auth_session_mfa_evidence (
      id,tenant_id,session_id,level,kind,provider_id,binding_id,
      authenticated_at,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,evidence.session_id,evidence.level,
      evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    CROSS JOIN generate_series(1,1022)
    WHERE evidence.session_id=${fixture.capAllowedSession}::uuid
  `;
  await sql`
    INSERT INTO public.auth_session_mfa_evidence (
      id,tenant_id,session_id,level,kind,provider_id,binding_id,
      authenticated_at,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,evidence.session_id,evidence.level,
      evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    CROSS JOIN generate_series(1,1023)
    WHERE evidence.session_id=${fixture.capDeniedSession}::uuid
  `;
}

async function seedClaimedOidcTransaction(
  label: string,
  operationRunId: string,
  legacySession?: {
    sessionId: string;
    familyId: string;
    appliedAt: Date;
    expiresAt: Date;
  },
): Promise<void> {
  const appliedAt = legacySession?.appliedAt;
  const createdAt = new Date((appliedAt?.getTime() ?? Date.now()) - 60_000);
  const claimedAt = new Date((appliedAt?.getTime() ?? Date.now()) - 1_000);
  const expiresAt =
    legacySession?.expiresAt ?? new Date(Date.now() + 10 * 60_000);
  const discoveryRevision = legacySession === undefined ? 2 : 1;
  const discoveryDigest = bytes(
    legacySession === undefined
      ? "generic-mfa:discovery"
      : "generic-mfa:legacy-discovery",
  );
  const legacyPlanning =
    legacySession === undefined ? undefined : await loadInitialPlanning();
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenant_federated_authentication_transactions (
        transaction_id,tenant_id,provider_id,binding_id,provider_kind,protocol,
        operation_run_id,operation_digest,receipt_digest,network_digest,
        account_digest,provider_digest,state_digest,browser_digest,nonce_digest,
        provider_revision,binding_revision,configuration_revision,
        security_revision,plan_revision,mapping_revision,authorization_revision,
        assurance_policy_revision,client_secret_revision,discovery_revision,
        discovery_digest,jwks_revision,jwks_digest,verifier_key_version,
        verifier_ciphertext,client_id,redirect_uri,post_logout_redirect_uri,
        scopes,allow_refresh_token,use_user_info,return_path,state,version,
        claim_attempt_id,created_at,expires_at,claimed_at,completed_at
      ) VALUES (
        ${bytes(`${label}:transaction`)}::bytea,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc','oidc',
        ${operationRunId}::uuid,${bytes(`${label}:begin-operation`)}::bytea,
        ${bytes(`${label}:begin-receipt`)}::bytea,
        ${bytes(`${label}:network`)}::bytea,${bytes(`${label}:account`)}::bytea,
        ${bytes(`${label}:provider`)}::bytea,${bytes(`${label}:state`)}::bytea,
        ${bytes(`${label}:browser`)}::bytea,${bytes(`${label}:nonce`)}::bytea,
        1,1,1,1,1,1,1,1,1,${discoveryRevision},${discoveryDigest}::bytea,
        1,${bytes("generic-mfa:jwks")}::bytea,1,
        ${Buffer.alloc(32, 0x76)}::bytea,'generic-runtime-client',
        'https://generic.example.invalid/oidc/callback',
        'https://generic.example.invalid/logout',ARRAY['openid']::text[],
        false,false,'/portal',${legacySession === undefined ? "claimed" : "completed"},
        ${legacySession === undefined ? 2 : 3},${bytes(`${label}:claim`)}::bytea,
        ${createdAt},${expiresAt},${claimedAt},${appliedAt ?? null}
      )
    `;
    if (legacySession !== undefined) {
      assert(legacyPlanning);
      const requestSnapshot = object(
        initialApplyCommand(
          label,
          legacyPlanning,
          operationRunId,
          uuid(999),
          `${label}:unused-continuation`,
          legacySession.appliedAt,
          legacySession.expiresAt,
        ).apply,
        "legacy admitted application",
      );
      delete requestSnapshot.continuation;
      requestSnapshot.disposition = "session";
      requestSnapshot.assurance = "satisfied";
      const authentication = object(
        requestSnapshot.authentication,
        "legacy authentication",
      );
      authentication.validUntil = legacySession.expiresAt.toISOString();
      authentication.evidence = [
        {
          level: "primary",
          kind: "factor",
          local: false,
          providerId: fixture.provider,
          bindingId: fixture.binding,
          authenticatedAt: legacySession.appliedAt.toISOString(),
          expiresAt: null,
          factorRevision: null,
          trustRuleRevision: 1,
        },
      ];
      const protocol = object(authentication.oidc, "legacy OIDC pins");
      protocol.pins = {
        ...initialPins,
        discoveryRevision,
        discoveryDigest: discoveryDigest.toString("base64"),
      };
      // The actual wrapper strips vault data and materialId from its immutable
      // predecessor request while storing the vault row separately.
      delete protocol.materialId;
      const [sessionSnapshot] = await transaction<{ value: JsonRecord }[]>`
        SELECT jsonb_build_object(
          'sessionId',id::text,'familyId',rotation_family_id::text,
          'tokenDigest',replace(encode(token_digest,'base64'),E'\n',''),
          'csrfDigest',replace(encode(csrf_secret_digest,'base64'),E'\n',''),
          'authenticationMethod',authentication_method,
          'idleExpiresAt',idle_expires_at,'absoluteExpiresAt',absolute_expires_at
        ) AS value FROM public.auth_sessions WHERE id=${legacySession.sessionId}::uuid
      `;
      assert(sessionSnapshot);
      requestSnapshot.session = sessionSnapshot.value;
      await transaction`
        INSERT INTO public.tenant_federated_authentication_applications (
          id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
          binding_id,provider_kind,category,primary_kind,user_id,session_id,
          request_snapshot,result_snapshot,applied_at
        ) VALUES (uuidv7(),${fixture.tenant}::uuid,'oidc',
          ${bytes(`${label}:transaction`)}::bytea,${bytes(`${label}:apply-operation`)}::bytea,
          ${fixture.provider}::uuid,${fixture.binding}::uuid,'oidc','success',
          'tenant_provider',${fixture.user}::uuid,${legacySession.sessionId}::uuid,
          ${transaction.json(requestSnapshot)}::jsonb,
          ${transaction.json({ category: "success", sessionId: legacySession.sessionId })}::jsonb,
          ${legacySession.appliedAt})
      `;
      // Exercise the current vault source/owner guard for the legacy fixtures.
      await transaction.unsafe("SET LOCAL session_replication_role = origin");
      await transaction`
        INSERT INTO public.tenant_oidc_session_materials (
          id,tenant_id,authority,session_id,rotation_family_id,user_id,
          provider_id,binding_id,provider_kind,external_identity_id,aad_version,
          id_token_key_version,id_token_ciphertext,id_token_digest,expires_at,
          client_id,end_session_endpoint,post_logout_redirect_uri,
          logout_disposition,created_at,updated_at
        ) VALUES (${operationRunId}::uuid,${fixture.tenant}::uuid,'tenant_provider',
          ${legacySession.sessionId}::uuid,${legacySession.familyId}::uuid,
          ${fixture.user}::uuid,${fixture.provider}::uuid,${fixture.binding}::uuid,
          'oidc',${fixture.identity}::uuid,1,1,${Buffer.alloc(32, 0x65)}::bytea,
          ${bytes(`${label}:id-token`)}::bytea,${legacySession.expiresAt},
          'generic-runtime-client','https://generic-oidc.example.invalid/logout',
          'https://generic.example.invalid/logout','available',
          ${legacySession.appliedAt},${legacySession.appliedAt})
      `;
    }
  });
}

const initialAliases = [
  { keyVersion: 1, digest: b64("generic-mfa:subject") },
] as const;

const initialPins: JsonRecord = {
  provider: {
    scope: "tenant",
    tenantId: fixture.tenant,
    providerId: fixture.provider,
    bindingId: fixture.binding,
  },
  providerRevision: 1,
  bindingRevision: 1,
  configurationRevision: 1,
  securityRevision: 1,
  mappingRevision: 1,
  authorizationRevision: 1,
  assurancePolicyRevision: 1,
  clientSecretRevision: 1,
  discoveryRevision: 2,
  discoveryDigest: b64("generic-mfa:discovery"),
  jwksRevision: 1,
  jwksDigest: b64("generic-mfa:jwks"),
};

async function loadInitialPlanning(): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_authentication_planning_state_v1(
        ${transaction.json({
          protocol: "oidc",
          tenantId: fixture.tenant,
          provider: initialPins.provider,
          subjectFormat: "utf8_exact",
          subjectAliases: initialAliases,
          providerRevision: 1,
          bindingRevision: 1,
          configurationRevision: 1,
          securityRevision: 1,
          mappingRevision: 1,
          authorizationRevision: 1,
          assurancePolicyRevision: 1,
        })}::jsonb
      ) AS value
    `,
  );
  assert.notEqual(row?.value, null, "generic initial planning is required");
  return object(row?.value ?? undefined, "generic initial planning");
}

function absentProfile(): JsonRecord[] {
  return [
    "first_name",
    "last_name",
    "display_name",
    "username",
    "alternate_username",
    "email",
  ].map((field) => ({ field, present: false }));
}

function initialApplyCommand(
  label: string,
  planning: JsonRecord,
  materialId: string,
  continuationId: string,
  receiptLabel: string,
  appliedAt = new Date(),
  expiresAt = new Date(Date.now() + 10 * 60_000),
): JsonRecord {
  const validUntil = new Date(appliedAt.getTime() + 10 * 60_000);
  const planningMapping = object(planning.mapping, "initial mapping authority");
  assert.deepEqual(planningMapping.rules, []);
  assert.deepEqual(planningMapping.liveOwnedEdges, []);
  // Authorization bootstrap grants the existing tenant administrator role.
  // A provider-access-only plan preserves that authority without adding edges.
  const roleIds = jsonField(planningMapping, "existingEffectiveRoleIds");
  assert(Array.isArray(roleIds));
  assert.equal(roleIds.length, 1);
  return {
    operationDigest: b64(`${label}:apply-operation`),
    apply: {
      authentication: {
        protocol: "oidc",
        method: "oidc",
        tenantId: fixture.tenant,
        authenticatedAt: appliedAt.toISOString(),
        validUntil: validUntil.toISOString(),
        evidence: [
          {
            level: "mfa",
            kind: "factor",
            local: false,
            providerId: fixture.provider,
            bindingId: fixture.binding,
            authenticatedAt: appliedAt.toISOString(),
            expiresAt: validUntil.toISOString(),
            factorRevision: null,
            trustRuleRevision: 1,
          },
        ],
        oidc: {
          materialId,
          transactionId: b64(`${label}:transaction`),
          expectedVersion: 2,
          pins: initialPins,
          completedAt: appliedAt.toISOString(),
          returnPath: "/portal",
        },
      },
      plan: {
        planRevision: jsonField(planning, "planRevision"),
        tenantId: fixture.tenant,
        userId: jsonField(planning, "userId"),
        identityEpoch: jsonField(planning, "identityEpoch"),
        providerRevision: 1,
        bindingRevision: 1,
        configurationRevision: 1,
        securityRevision: 1,
        mappingRevision: 1,
        authorizationRevision: 1,
        policyRevision: 1,
        roleIds,
        securityGroupIds: [],
        subject: {
          externalIdentityId: jsonField(planning, "externalIdentityId"),
          aliases: initialAliases,
          envelope: {
            keyVersion: 1,
            format: "utf8_exact",
            nonce: Buffer.alloc(12, 0x6e).toString("base64"),
            ciphertext: Buffer.alloc(32, 0x70).toString("base64"),
          },
        },
        mapping: {
          disposition: "admitted",
          reason: "provider_access_only",
          identityAction: "no_change",
          accessAction: "no_change",
          matchedRuleIds: [],
          securityGroupIds: [],
          roleIds,
          operatorTeams: [],
          changes: [],
          profile: absentProfile(),
        },
        requirement: jsonField(planning, "requirement"),
        hasEnrollableFactor: jsonField(planning, "hasEnrollableFactor"),
      },
      disposition: "continuation",
      assurance: "step_up_required",
      appliedAt: appliedAt.toISOString(),
      continuation: {
        continuationId,
        receiptDigest: b64(receiptLabel),
        expiresAt: expiresAt.toISOString(),
      },
    },
  };
}

async function applyInitial(command: JsonRecord): Promise<JsonRecord> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_authentication_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  return object(row?.value, "generic initial apply result");
}

async function replaceAccessEpoch(): Promise<void> {
  const changedAt = new Date();
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_federated_provider_access_grants
      SET ended_at=${changedAt},version=2
      WHERE id=${fixture.grant1}::uuid
    `;
    await transaction`
      UPDATE public.tenant_identity_provider_access_epochs
      SET ended_at=${changedAt},ended_by_membership_id=${fixture.membership}::uuid,
          end_reason='runtime replacement',version=2
      WHERE id=${fixture.epoch1}::uuid
    `;
    await transaction`
      UPDATE public.tenant_authorization_sources
      SET retired_at=${changedAt} WHERE id=${fixture.source1}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (
        id,tenant_id,kind,key,authoritative,protected,created_at
      ) VALUES (${fixture.source2}::uuid,${fixture.tenant}::uuid,
        'identity_provider_access',
        ${`identity_provider_access:${fixture.binding}:2`},true,false,${changedAt})
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs (
        id,tenant_id,binding_id,provider_id,source_id,sequence,
        started_by_membership_id,started_at,version
      ) VALUES (${fixture.epoch2}::uuid,${fixture.tenant}::uuid,
        ${fixture.binding}::uuid,${fixture.provider}::uuid,
        ${fixture.source2}::uuid,2,${fixture.membership}::uuid,${changedAt},1)
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_access_grants (
        id,tenant_id,provider_id,binding_id,access_epoch_id,source_id,
        external_identity_id,membership_id,user_id,owns_membership,
        started_at,last_observed_at,version
      ) VALUES (${fixture.grant2}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${fixture.binding}::uuid,
        ${fixture.epoch2}::uuid,${fixture.source2}::uuid,
        ${fixture.identity}::uuid,${fixture.membership}::uuid,
        ${fixture.user}::uuid,false,${changedAt},${changedAt},1)
    `;
    await transaction`
      UPDATE public.tenant_auth_provider_bindings
      SET current_access_epoch_id=${fixture.epoch2}::uuid,updated_at=${changedAt}
      WHERE id=${fixture.binding}::uuid
    `;
  });
}

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    version?.version.startsWith("18."),
    "runtime harness requires PostgreSQL 18",
  );
  await seedFixture();
  await Promise.all([
    seedClaimedOidcTransaction("generic-mfa:initial", fixture.initialOperation),
    seedClaimedOidcTransaction(
      "generic-mfa:initial-expired",
      fixture.initialExpiredOperation,
    ),
  ]);

  const initialPlanning = await loadInitialPlanning();
  assert.equal(initialPlanning.userId, fixture.user);
  assert.equal(initialPlanning.externalIdentityId, fixture.identity);
  const initialCommand = initialApplyCommand(
    "generic-mfa:initial",
    initialPlanning,
    fixture.initialOperation,
    fixture.initialContinuation,
    "generic-mfa:initial-receipt",
  );
  const oversizedCommand = structuredClone(initialCommand);
  oversizedCommand.operationDigest = "A".repeat(2_097_152);
  const oversizedBefore = await mutationSnapshot();
  await assert.rejects(applyInitial(oversizedCommand), (error: unknown) => {
    assertSqlState(error, "22023");
    return true;
  });
  assert.deepEqual(
    await mutationSnapshot(),
    oversizedBefore,
    "oversized federated apply command mutated transaction or authority state",
  );
  const initialResult = await applyInitial(initialCommand);
  assert.equal(initialResult.category, "success");
  assert.equal(initialResult.continuationId, fixture.initialContinuation);
  const initialAuthority = await resolveContinuation(
    fixture.initialContinuation,
    "generic-mfa:initial-receipt",
  );
  assert.equal(initialAuthority.continuationOrigin, "initial_login");
  assert.equal(initialAuthority.authenticationMethod, "oidc");
  assert.equal(initialAuthority.providerKind, "oidc");
  const initialReservation = object(
    initialAuthority.federatedReservation,
    "generic initial reservation",
  );
  assert.equal(initialReservation.authenticationMethod, "oidc");
  assert.equal(initialReservation.providerKind, "oidc");

  const initialReplayBefore = await mutationSnapshot();
  const initialReplay = await applyInitial(initialCommand);
  assert.equal(initialReplay.category, "success");
  assert.equal(initialReplay.replayed, true);
  assert.deepEqual(
    await mutationSnapshot(),
    initialReplayBefore,
    "exact generic initial apply replay mutated state",
  );

  const expiredInitialBefore = await mutationSnapshot();
  const backdatedInitial = new Date(Date.now() - 2 * 60_000);
  await assert.rejects(
    applyInitial(
      initialApplyCommand(
        "generic-mfa:initial-expired",
        initialPlanning,
        fixture.initialExpiredOperation,
        fixture.initialExpiredContinuation,
        "generic-mfa:initial-expired-receipt",
        backdatedInitial,
        new Date(Date.now() - 1_000),
      ),
    ),
    (error: unknown) => {
      assertSqlState(error, "22023");
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    expiredInitialBefore,
    "DB-expired initial reservation mutated transaction or authority state",
  );

  await verifyMateriallessMfaLifecycle(initialAuthority);

  const replayAuthority = await loadRevalidation(fixture.replaySession);
  const replayMutation = stepUpMutation(
    replayAuthority,
    fixture.replaySession,
    fixture.replayContinuation,
    "generic-mfa:replay-receipt",
  );
  await assertRequiredMaterialCannotDisappear(uuid(100), () =>
    applyRevalidation(replayMutation),
  );
  const firstResult = await applyRevalidation(replayMutation);
  assert.equal(firstResult.continuationId, fixture.replayContinuation);
  const legacyContinuationAuthority = await resolveContinuation(
    fixture.replayContinuation,
    "generic-mfa:replay-receipt",
  );
  const legacyChallenge = await createAndClaimTotpChallenge(
    legacyContinuationAuthority,
    "generic-mfa:replay-receipt",
    "required-material-completion",
  );
  const [legacyDeadline] = await sql<{ absoluteExpiresAt: Date }[]>`
    SELECT absolute_expires_at AS "absoluteExpiresAt" FROM public.auth_sessions
    WHERE id=${fixture.replaySession}::uuid
  `;
  assert(legacyDeadline);
  const legacyCompletion = totpCompletion(
    legacyChallenge,
    "generic-mfa:replay-receipt",
    uuid(57),
    fixture.replayFamily,
    3,
    legacyDeadline.absoluteExpiresAt,
  );
  await assertRequiredMaterialCannotDisappear(uuid(100), () =>
    completeTotp(legacyCompletion),
  );
  await assertCompletionSucceedsWithoutCommit(legacyCompletion);
  const replayBefore = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(replayMutation), firstResult);
  assert.deepEqual(
    await mutationSnapshot(),
    replayBefore,
    "exact retry mutated state",
  );
  const mismatch = structuredClone(replayMutation);
  object(mismatch.continuation, "mismatch continuation").receiptDigest = b64(
    "generic-mfa:mismatch",
  );
  await assert.rejects(applyRevalidation(mismatch), (error: unknown) => {
    assertSqlState(error, "40001");
    return true;
  });
  assert.deepEqual(
    await mutationSnapshot(),
    replayBefore,
    "mismatch mutated state",
  );

  const terminalAuthority = await loadRevalidation(fixture.terminalSession);
  const terminalSnapshot = object(
    terminalAuthority.snapshot,
    "terminal snapshot",
  );
  const terminalLive = object(terminalAuthority.live, "terminal live");
  const terminalMutation: JsonRecord = {
    tenantId: fixture.tenant,
    sessionId: fixture.terminalSession,
    userId: fixture.user,
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: jsonField(terminalSnapshot, "version"),
    observedAt: new Date().toISOString(),
    decision: "revoke",
    reason: "lifecycle",
    requirement: jsonField(terminalLive, "requirement"),
  };
  const terminalResult = await applyRevalidation(terminalMutation);
  const terminalBefore = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(terminalMutation), terminalResult);
  assert.deepEqual(
    await mutationSnapshot(),
    terminalBefore,
    "terminal replay mutated revoked state",
  );

  const capAllowedAuthority = await loadRevalidation(fixture.capAllowedSession);
  const capAllowedResult = await applyRevalidation(
    stepUpMutation(
      capAllowedAuthority,
      fixture.capAllowedSession,
      fixture.capAllowedContinuation,
      "generic-mfa:cap-1023",
    ),
  );
  assert.equal(capAllowedResult.continuationId, fixture.capAllowedContinuation);
  const [allowedEvidence] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_post_primary_continuation_evidence
    WHERE continuation_id=${fixture.capAllowedContinuation}::uuid
  `;
  assert.equal(allowedEvidence?.count, 1023);

  const capDeniedAuthority = await loadRevalidation(fixture.capDeniedSession);
  const capDeniedBefore = await mutationSnapshot();
  await assert.rejects(
    applyRevalidation(
      stepUpMutation(
        capDeniedAuthority,
        fixture.capDeniedSession,
        fixture.capDeniedContinuation,
        "generic-mfa:cap-1024",
      ),
    ),
    (error: unknown) => {
      assertSqlState(error, "22023");
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    capDeniedBefore,
    "1024 evidence stranded a parent, ledger, child, or audit row",
  );

  const expiredAuthority = await loadRevalidation(fixture.expiredSession);
  const expiredBefore = await mutationSnapshot();
  const backdated = new Date(Date.now() - 2 * 60_000);
  await assert.rejects(
    applyRevalidation(
      stepUpMutation(
        expiredAuthority,
        fixture.expiredSession,
        fixture.expiredContinuation,
        "generic-mfa:expired",
        backdated,
        new Date(Date.now() - 1_000),
      ),
    ),
    (error: unknown) => {
      assertSqlState(error, "22023");
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    expiredBefore,
    "backdated caller time bypassed DB-live continuation expiry",
  );

  const contentionAuthority = await loadRevalidation(fixture.contentionSession);
  const contentionMutation = stepUpMutation(
    contentionAuthority,
    fixture.contentionSession,
    fixture.contentionContinuation,
    "generic-mfa:contention",
  );
  const contentionBefore = await mutationSnapshot();
  await sql.begin(async (locker) => {
    await locker`
      SELECT session.id
      FROM public.auth_sessions AS session
      JOIN public.auth_session_mfa_states AS state
        ON state.tenant_id=${fixture.tenant}::uuid
       AND state.session_id=session.id
      WHERE session.id=${fixture.contentionSession}::uuid
      FOR UPDATE OF session,state
    `;
    await assert.rejects(
      applyRevalidation(contentionMutation),
      (error: unknown) => {
        assertSqlState(error, "40001");
        return true;
      },
    );
  });
  assert.deepEqual(
    await mutationSnapshot(),
    contentionBefore,
    "source/state contention mutated continuation state",
  );

  // Keep a distinct initial-login continuation pending: the material-less
  // lifecycle above intentionally consumed the original one.
  await seedClaimedOidcTransaction(
    "generic-mfa:epoch-initial",
    fixture.epochInitialOperation,
  );
  const epochInitialCommand = initialApplyCommand(
    "generic-mfa:epoch-initial",
    await loadInitialPlanning(),
    fixture.epochInitialOperation,
    fixture.epochInitialContinuation,
    "generic-mfa:epoch-initial-receipt",
  );
  const epochInitialResult = await applyInitial(epochInitialCommand);
  assert.equal(epochInitialResult.category, "success");
  assert.equal(
    epochInitialResult.continuationId,
    fixture.epochInitialContinuation,
  );
  assert.equal(
    (
      await resolveContinuation(
        fixture.epochInitialContinuation,
        "generic-mfa:epoch-initial-receipt",
      )
    ).continuationOrigin,
    "initial_login",
  );
  const epochInitialReplay = await applyInitial(epochInitialCommand);
  assert.equal(epochInitialReplay.category, "success");
  assert.equal(epochInitialReplay.replayed, true);
  await replaceAccessEpoch();

  const staleReplayBefore = await mutationSnapshot();
  assert.deepEqual(await applyRevalidation(replayMutation), firstResult);
  assert.deepEqual(
    await mutationSnapshot(),
    staleReplayBefore,
    "terminal command replay after epoch drift mutated state",
  );
  await assert.rejects(
    resolveContinuation(
      fixture.replayContinuation,
      "generic-mfa:replay-receipt",
    ),
    (error: unknown) => {
      assertSqlState(error, "42501");
      return true;
    },
  );
  const staleInitialReplay = await applyInitial(epochInitialCommand);
  assert.equal(staleInitialReplay.category, "denied");
  await assert.rejects(
    resolveContinuation(
      fixture.epochInitialContinuation,
      "generic-mfa:epoch-initial-receipt",
    ),
    (error: unknown) => {
      assertSqlState(error, "42501");
      return true;
    },
  );
  assert.deepEqual(
    await mutationSnapshot(),
    staleReplayBefore,
    "old epoch continuation was revived or mutated",
  );
  await verifyDirectInitialMateriallessLineage();
} finally {
  await sql.end();
}
