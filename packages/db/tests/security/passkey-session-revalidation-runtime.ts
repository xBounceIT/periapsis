import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type JsonObject = Record<string, postgres.JSONValue>;
type SqlError = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_PASSKEY_REVALIDATION_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PASSKEY_REVALIDATION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18.6 database",
  );
}

const sql = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
const uuid = (sequence: number): string =>
  `019d31c0-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): Buffer =>
  createHash("sha256").update(`passkey-v35:${label}`).digest();
const base64 = (label: string): string => digest(label).toString("base64");

const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  policy: uuid(4),
  credential: uuid(5),
  secondaryCredential: uuid(6),
  loginOneSession: uuid(10),
  loginOneFamily: uuid(11),
  loginTwoSession: uuid(12),
  loginTwoFamily: uuid(13),
  liveSession: uuid(14),
  liveFamily: uuid(15),
  rotatedSession: uuid(16),
  continuation: uuid(17),
  continuationSuccessor: uuid(18),
  revokeSession: uuid(19),
  revokeFamily: uuid(20),
  denySession: uuid(21),
  denyFamily: uuid(22),
} as const;

const userHandle = digest("user-handle");
const credentialWireId = digest("credential-id");
const secondaryCredentialWireId = digest("secondary-credential-id");
function isObject(value: postgres.JSONValue | undefined): value is JsonObject {
  return (
    value !== null &&
    value !== undefined &&
    !Array.isArray(value) &&
    typeof value === "object"
  );
}

function object(
  value: postgres.JSONValue | undefined,
  label: string,
): JsonObject {
  assert(isObject(value), `${label} must be an object`);
  return value;
}

function stringField(value: JsonObject, key: string): string {
  const field = value[key];
  if (typeof field !== "string") {
    throw new TypeError(`${key} must be a string`);
  }
  return field;
}

function numberField(value: JsonObject, key: string): number {
  const field = value[key];
  if (typeof field !== "number") {
    throw new TypeError(`${key} must be a number`);
  }
  return field;
}

function jsonField(value: JsonObject, key: string): postgres.JSONValue {
  const field = value[key];
  if (field === undefined) {
    throw new TypeError(`${key} is required`);
  }
  return field;
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as SqlError).code, expected, error.message);
  return true;
}

async function asApi<T>(
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const wrapped = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

async function currentRequirement(at: Date): Promise<postgres.JSONValue> {
  const [row] = await sql<{ requirement: postgres.JSONValue }[]>`
    SELECT app.private_mfa_policy_snapshot_v1(
      ${fixture.tenant}::uuid,${fixture.user}::uuid,
      'tenant.authentication.login',${at}
    ) -> 'requirement' AS requirement
  `;
  assert(row);
  return row.requirement;
}

type PendingPasskeyArtifact = {
  ceremonyId: Buffer;
  browserDigest: Buffer;
  createdAt: Date;
};

async function createPrimaryPasskeyArtifact(options: {
  label: string;
  mode: "known_user" | "discoverable";
  allowedCredentialIds: string[];
}): Promise<PendingPasskeyArtifact> {
  const createdAt = new Date(Date.now() - 1_000);
  const requirement = await currentRequirement(createdAt);
  const ceremonyId = digest(`${options.label}:ceremony`);
  const browserDigest = digest(`${options.label}:browser`);
  const binding: JsonObject = {
    purpose: "primary_authentication",
    tenantId: fixture.tenant,
    identityEpoch: options.mode === "known_user" ? 1 : 0,
    anchorVersion: 0,
    anchorExpiresAt: null,
    anchorRecoveryRestricted: false,
    action: "tenant.authentication.login",
    audience: "api",
    requirement,
    baselineEvidence: [],
  };
  if (options.mode === "known_user") {
    binding.userId = fixture.user;
  }
  const [created] = await asApi(
    (transaction) => transaction<{ value: boolean }[]>`
      SELECT app.create_webauthn_ceremony_v1(
        ${transaction.json({
          id: ceremonyId.toString("base64"),
          challengeDigest: base64(`${options.label}:challenge`),
          browserDigest: browserDigest.toString("base64"),
          relyingParty: {
            id: "example.invalid",
            origins: ["https://example.invalid"],
            revision: 1,
          },
          binding,
          policy: {
            requireUserPresence: true,
            userVerification:
              options.mode === "discoverable" ? "required" : "preferred",
            residentKey:
              options.mode === "discoverable" ? "required" : "preferred",
            attestation: "none",
            metadataRevision: 0,
          },
          mode: options.mode,
          userHandleDigest:
            options.mode === "known_user"
              ? createHash("sha256").update(userHandle).digest("base64")
              : Buffer.alloc(32).toString("base64"),
          allowedCredentialIds: options.allowedCredentialIds,
          createdAt: createdAt.toISOString(),
          expiresAt: new Date(createdAt.getTime() + 5 * 60_000).toISOString(),
          state: "pending",
          version: 1,
        })}::jsonb
      ) AS value
    `,
  );
  assert.equal(created?.value, true);
  return { ceremonyId, browserDigest, createdAt };
}

async function resolvePrimaryPasskeyArtifact(
  artifact: PendingPasskeyArtifact,
  selectedCredentialId: Buffer,
): Promise<JsonObject> {
  const [prepared] = await asApi(
    (transaction) => transaction<
      {
        value: postgres.JSONValue;
      }[]
    >`
    SELECT app.resolve_mfa_completion_artifact_v1(
      ${transaction.json({
        artifactKind: "webauthn_authentication",
        artifactId: artifact.ceremonyId.toString("base64"),
        browserDigest: artifact.browserDigest.toString("base64"),
        selectedFactorKind: "passkey",
        selectedFactorId: selectedCredentialId.toString("base64"),
        requestedAt: new Date().toISOString(),
      })}::jsonb
    ) AS value
  `,
  );
  return object(prepared?.value, "prepared primary passkey artifact");
}

async function assertPasskeyCeremonySnapshotGuards(): Promise<void> {
  const beforeSecondary = await createPrimaryPasskeyArtifact({
    label: "known-before-secondary",
    mode: "known_user",
    allowedCredentialIds: [credentialWireId.toString("base64")],
  });
  const createdAt = new Date();
  await sql`
    INSERT INTO public.tenant_webauthn_credentials (
      id,tenant_id,user_id,credential_id,public_key,display_name,
      user_handle_digest,rp_id,rp_revision,sign_count,discoverable,
      user_verification,backup_eligible,backed_up,aaguid,
      attestation_format,attestation_type,attestation_trusted,
      metadata_revision,status,version,security_revision,created_at,updated_at
    ) VALUES (${fixture.secondaryCredential}::uuid,${fixture.tenant}::uuid,
      ${fixture.user}::uuid,${secondaryCredentialWireId},
      ${Buffer.alloc(64, 0x72)},'Non-discoverable secondary passkey',
      ${createHash("sha256").update(userHandle).digest()},'example.invalid',1,
      0,false,true,false,false,${Buffer.alloc(16)},'none','none',false,0,
      'active',1,1,${createdAt},${createdAt})
  `;
  await assert.rejects(
    resolvePrimaryPasskeyArtifact(beforeSecondary, secondaryCredentialWireId),
    (error: unknown) => assertSqlState(error, "42501"),
    "a credential added after ceremony start entered the known-user snapshot",
  );

  const wrongKnownUser = await createPrimaryPasskeyArtifact({
    label: "known-wrong-credential",
    mode: "known_user",
    allowedCredentialIds: [credentialWireId.toString("base64")],
  });
  await assert.rejects(
    resolvePrimaryPasskeyArtifact(wrongKnownUser, secondaryCredentialWireId),
    (error: unknown) => assertSqlState(error, "42501"),
    "a credential outside the known-user allow-list was accepted",
  );

  const discoverable = await createPrimaryPasskeyArtifact({
    label: "discoverable-non-discoverable-credential",
    mode: "discoverable",
    allowedCredentialIds: [],
  });
  await assert.rejects(
    resolvePrimaryPasskeyArtifact(discoverable, secondaryCredentialWireId),
    (error: unknown) => assertSqlState(error, "42501"),
    "a non-discoverable credential entered a discoverable ceremony",
  );

  const crossFlow = await createPrimaryPasskeyArtifact({
    label: "primary-purpose-flow-mismatch",
    mode: "known_user",
    allowedCredentialIds: [credentialWireId.toString("base64")],
  });
  await sql`
    UPDATE public.tenant_webauthn_ceremonies
    SET purpose='step_up_authentication'
    WHERE id=${crossFlow.ceremonyId}
  `;
  await assert.rejects(
    resolvePrimaryPasskeyArtifact(crossFlow, credentialWireId),
    (error: unknown) => assertSqlState(error, "42501"),
    "a primary anchor was projected as a session step-up ceremony",
  );
}

async function seed(): Promise<void> {
  const createdAt = new Date(Date.now() - 60_000);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id,slug,name,status,created_at,updated_at)
      VALUES (${fixture.tenant}::uuid,'passkey-v35-runtime',
        'Passkey v35 runtime','active',${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name,active,created_at,updated_at)
      VALUES (${fixture.user}::uuid,'passkey-v35@example.invalid',
        'Passkey v35 runtime',true,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_states (
        tenant_id,initialized_at,revision,updated_at
      ) VALUES (${fixture.tenant}::uuid,${createdAt},1,${createdAt})
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
      ) VALUES (${fixture.tenant}::uuid,${fixture.user}::uuid,${userHandle},
        1,1,1,${createdAt},${createdAt})
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
        'tenant_baseline','primary',false,0,${createdAt})
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1', '', true)
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credentials (
        id,tenant_id,user_id,credential_id,public_key,display_name,
        user_handle_digest,rp_id,rp_revision,sign_count,discoverable,
        user_verification,backup_eligible,backed_up,aaguid,
        attestation_format,attestation_type,attestation_trusted,
        metadata_revision,status,version,security_revision,created_at,updated_at
      ) VALUES (${fixture.credential}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,${credentialWireId},${Buffer.alloc(64, 0x71)},
        'Primary passkey',${createHash("sha256").update(userHandle).digest()},
        'example.invalid',1,0,true,true,false,false,${Buffer.alloc(16)},
        'none','none',false,0,'active',1,1,${createdAt},${createdAt})
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credential_transports (
        tenant_id,credential_id,transport
      ) VALUES (${fixture.tenant}::uuid,${fixture.credential}::uuid,'internal')
    `;
  });
}

type PrimaryLogin = {
  request: JsonObject;
  result: JsonObject;
  sessionId: string;
  familyId: string;
  completedAt: Date;
};

async function completePrimaryLogin(options: {
  label: string;
  sessionId: string;
  familyId: string;
  expectedVersion: number;
  expectedSignCount: number;
  observedSignCount: number;
  expectedBackedUp: boolean;
  backupEligible: boolean;
  backedUp: boolean;
  concurrent?: boolean;
}): Promise<PrimaryLogin> {
  const createdAt = new Date(Date.now() - 1_000);
  const requirement = await currentRequirement(createdAt);
  const binding: JsonObject = {
    purpose: "primary_authentication",
    tenantId: fixture.tenant,
    userId: fixture.user,
    identityEpoch: 1,
    anchorVersion: 0,
    anchorExpiresAt: null,
    anchorRecoveryRestricted: false,
    action: "tenant.authentication.login",
    audience: "api",
    requirement,
    baselineEvidence: [],
  };
  const ceremonyId = digest(`${options.label}:ceremony`);
  const browserDigest = digest(`${options.label}:browser`);
  const ceremony = {
    id: ceremonyId.toString("base64"),
    challengeDigest: base64(`${options.label}:challenge`),
    browserDigest: browserDigest.toString("base64"),
    relyingParty: {
      id: "example.invalid",
      origins: ["https://example.invalid"],
      revision: 1,
    },
    binding,
    policy: {
      requireUserPresence: true,
      userVerification: "preferred",
      residentKey: "preferred",
      attestation: "none",
      metadataRevision: 0,
    },
    mode: "known_user",
    userHandleDigest: createHash("sha256").update(userHandle).digest("base64"),
    allowedCredentialIds: [credentialWireId.toString("base64")],
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + 5 * 60_000).toISOString(),
    state: "pending",
    version: 1,
  };
  const [created] = await asApi(
    (transaction) => transaction<{ value: boolean }[]>`
      SELECT app.create_webauthn_ceremony_v1(
        ${transaction.json(ceremony)}::jsonb
      ) AS value
    `,
  );
  assert.equal(created?.value, true);
  const [prepared] = await asApi(
    (transaction) => transaction<
      {
        value: postgres.JSONValue;
      }[]
    >`
    SELECT app.resolve_mfa_completion_artifact_v1(
      ${transaction.json({
        artifactKind: "webauthn_authentication",
        artifactId: ceremonyId.toString("base64"),
        browserDigest: browserDigest.toString("base64"),
        selectedFactorKind: "passkey",
        selectedFactorId: credentialWireId.toString("base64"),
        requestedAt: createdAt.toISOString(),
      })}::jsonb
    ) AS value
  `,
  );
  const preparedArtifact = object(
    prepared?.value,
    "prepared primary passkey artifact",
  );
  assert.deepEqual(
    Object.keys(preparedArtifact).toSorted(),
    [
      "action",
      "anchorExpiresAt",
      "anchorVersion",
      "artifactId",
      "artifactKind",
      "audience",
      "browserDigest",
      "continuationId",
      "continuationReceiptDigest",
      "factorId",
      "factorKind",
      "flow",
      "identityEpoch",
      "loadedAt",
      "reservationAuthenticationMethod",
      "reservationDisposition",
      "resolvedIdentityEpoch",
      "resolvedUserId",
      "resultAuthenticationMethod",
      "sessionFamilyId",
      "sessionId",
      "sourceAbsoluteExpiresAt",
      "sourceSessionFamilyId",
      "sourceSessionId",
      "sourceSessionVersion",
      "tenantId",
      "userId",
    ].toSorted(),
  );
  assert.equal(
    stringField(preparedArtifact, "artifactKind"),
    "webauthn_authentication",
  );
  assert.equal(stringField(preparedArtifact, "factorKind"), "passkey");
  assert.equal(
    stringField(preparedArtifact, "factorId"),
    credentialWireId.toString("base64"),
  );
  assert.equal(stringField(preparedArtifact, "flow"), "primary");
  assert.equal(stringField(preparedArtifact, "resolvedUserId"), fixture.user);
  assert.equal(
    stringField(preparedArtifact, "reservationDisposition"),
    "create",
  );
  assert.equal(
    stringField(preparedArtifact, "reservationAuthenticationMethod"),
    "passkey",
  );
  assert.equal(
    stringField(preparedArtifact, "resultAuthenticationMethod"),
    "passkey",
  );
  const claimedAt = new Date(createdAt.getTime() + 100);
  const [claimed] = await asApi(
    (transaction) => transaction<
      {
        value: postgres.JSONValue;
      }[]
    >`
    SELECT app.claim_webauthn_ceremony_v2(
      ${ceremonyId},${browserDigest},${claimedAt},NULL::bytea
    ) AS value
  `,
  );
  const claimedBinding = object(
    object(claimed?.value, "claimed primary ceremony").binding,
    "claimed primary binding",
  );
  claimedBinding.anchorExpiresAt = null;
  const claimedRequirement = object(
    claimedBinding.requirement,
    "claimed primary requirement",
  );
  const completedAt = new Date();
  const request: JsonObject = {
    completion: {
      ceremonyId: ceremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: claimedBinding,
      resolvedUserId: fixture.user,
      expectedIdentityEpoch: 1,
      credentialId: credentialWireId.toString("base64"),
      expectedCredentialVersion: options.expectedVersion,
      completedAt: completedAt.toISOString(),
      expectedSignCount: options.expectedSignCount,
      observedSignCount: options.observedSignCount,
      expectedBackedUp: options.expectedBackedUp,
      counterDisposition: "advance",
      userVerified: false,
      backupEligible: options.backupEligible,
      backedUp: options.backedUp,
    },
    audit: {
      kind: "mfa.passkey_authenticated",
      tenantId: fixture.tenant,
      userId: fixture.user,
      action: "tenant.authentication.login",
      occurredAt: completedAt.toISOString(),
      policyRevisions: claimedRequirement.policyRevisions ?? [],
    },
    session: {
      mutation: "create",
      expectedAnchorVersion: 0,
      expectedIdentityEpoch: 1,
      expectedAnchorExpiry: "-infinity",
      audience: "api",
      requirement: claimedRequirement,
      recoveryRestricted: false,
      reservation: {
        sessionId: options.sessionId,
        familyId: options.familyId,
        tokenDigest: base64(`${options.label}:token`),
        csrfDigest: base64(`${options.label}:csrf`),
        authenticationMethod: "passkey",
        idleExpiresAt: new Date(
          completedAt.getTime() + 30 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: new Date(
          completedAt.getTime() + 60 * 60_000,
        ).toISOString(),
      },
    },
  };
  const execute = () =>
    asApi(async (transaction) => {
      const [row] = await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_authentication_v1(
          ${transaction.json(request)}::jsonb
        ) AS value
      `;
      return object(row?.value, "primary login result");
    });
  const result = options.concurrent
    ? (await Promise.all([execute(), execute()]))[0]
    : await execute();
  if (options.concurrent) {
    const replayPair = await Promise.all([execute(), execute()]);
    assert.deepEqual(replayPair[0], result);
    assert.deepEqual(replayPair[1], result);
  }
  assert.equal(stringField(result, "newSessionId"), options.sessionId);
  assert.equal(stringField(result, "mutation"), "create");
  return {
    request,
    result,
    sessionId: options.sessionId,
    familyId: options.familyId,
    completedAt,
  };
}

async function completePrimaryClone(): Promise<void> {
  const artifact = await createPrimaryPasskeyArtifact({
    label: "primary-clone",
    mode: "known_user",
    allowedCredentialIds: [credentialWireId.toString("base64")],
  });
  const prepared = await resolvePrimaryPasskeyArtifact(
    artifact,
    credentialWireId,
  );
  assert.equal(prepared.flow, "primary");
  const claimedAt = new Date(artifact.createdAt.getTime() + 100);
  const [claimed] = await asApi(
    (transaction) => transaction<
      {
        value: postgres.JSONValue;
      }[]
    >`
    SELECT app.claim_webauthn_ceremony_v2(
      ${artifact.ceremonyId},${artifact.browserDigest},${claimedAt},NULL::bytea
    ) AS value
  `,
  );
  const claimedBinding = object(
    object(claimed?.value, "claimed clone ceremony").binding,
    "claimed clone binding",
  );
  claimedBinding.anchorExpiresAt = null;
  const requirement = object(
    claimedBinding.requirement,
    "claimed clone requirement",
  );
  const completedAt = new Date();
  const request: JsonObject = {
    completion: {
      ceremonyId: artifact.ceremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: claimedBinding,
      resolvedUserId: fixture.user,
      expectedIdentityEpoch: 1,
      credentialId: credentialWireId.toString("base64"),
      expectedCredentialVersion: 6,
      completedAt: completedAt.toISOString(),
      expectedSignCount: 4,
      observedSignCount: 3,
      expectedBackedUp: true,
      counterDisposition: "clone_suspected",
      userVerified: false,
      backupEligible: true,
      backedUp: true,
    },
    audit: {
      kind: "mfa.passkey_clone_suspected",
      tenantId: fixture.tenant,
      userId: fixture.user,
      action: "tenant.authentication.login",
      occurredAt: completedAt.toISOString(),
      policyRevisions: requirement.policyRevisions ?? [],
    },
    session: {
      mutation: "revoke",
      expectedAnchorVersion: 0,
      expectedIdentityEpoch: 1,
      expectedAnchorExpiry: "-infinity",
      audience: "api",
      requirement,
      recoveryRestricted: false,
    },
  };
  const complete = async (): Promise<JsonObject> => {
    const [row] = await asApi(
      (transaction) => transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_authentication_v1(
          ${transaction.json(request)}::jsonb
        ) AS value
      `,
    );
    return object(row?.value, "primary clone result");
  };
  const result = await complete();
  assert.equal(result.mutation, "revoke");
  assert.equal(result.sessionVersion, 0);
  assert.equal(result.newSessionId, undefined);
  assert.equal(result.consumedContinuationId, undefined);
  assert.equal(result.revokedAnchorId, undefined);
  assert.deepEqual(await complete(), result, "primary clone replay drifted");
  const [credential] = await sql<
    {
      status: string;
      version: number;
      securityRevision: number;
    }[]
  >`
    SELECT status,version::integer AS version,
      security_revision::integer AS "securityRevision"
    FROM public.tenant_webauthn_credentials
    WHERE id=${fixture.credential}::uuid
  `;
  assert.deepEqual(credential, {
    status: "clone_suspected",
    version: 7,
    securityRevision: 3,
  });
}

async function loadRevalidation(sessionId: string): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_session_revalidation_v1(
        ${transaction.json({
          sessionId,
          tenantId: fixture.tenant,
          audience: "api",
          authenticationMethod: "passkey",
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
  );
  assert.notEqual(row?.value, null, "passkey CurrentSession must be projected");
  return object(row?.value ?? undefined, "passkey revalidation projection");
}

function revalidationMutation(
  authority: JsonObject,
  decision: string,
  reason: string,
  extra: JsonObject = {},
): JsonObject {
  const snapshot = object(authority.snapshot, "revalidation snapshot");
  const live = object(authority.live, "revalidation live");
  return {
    sessionId: stringField(snapshot, "sessionId"),
    tenantId: fixture.tenant,
    userId: fixture.user,
    audience: "api",
    authenticationMethod: "passkey",
    expectedVersion: numberField(snapshot, "version"),
    observedAt: new Date().toISOString(),
    decision,
    reason,
    requirement: jsonField(live, "requirement"),
    ...extra,
  };
}

async function applyRevalidation(mutation: JsonObject): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_session_revalidation_v1(
        ${transaction.json(mutation)}::jsonb
      ) AS value
    `,
  );
  return object(row?.value, "passkey revalidation result");
}

async function advancePolicy(revision: number, level: string): Promise<void> {
  const changedAt = new Date();
  await sql.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`retire:${fixture.policy}:${revision - 1}`},
        true
      )
    `;
    await transaction`
      UPDATE public.mfa_policy_revisions
      SET retired_at=${changedAt}
      WHERE id=${fixture.policy}::uuid AND retired_at IS NULL
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`insert:${fixture.policy}:${revision}`},
        true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (${fixture.policy}::uuid,${revision},${fixture.tenant}::uuid,
        'tenant_baseline',${level},false,0,${changedAt})
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1', '', true)
    `;
  });
}

async function seedPasskeySession(
  sessionId: string,
  familyId: string,
  credentialRevision: number,
  policyRevision: number,
  authenticatedAt: Date,
): Promise<void> {
  const createdAt = new Date();
  const idle = new Date(createdAt.getTime() + 30 * 60_000);
  const absolute = new Date(createdAt.getTime() + 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      ) VALUES (${sessionId}::uuid,${fixture.user}::uuid,${familyId}::uuid,
        ${fixture.tenant}::uuid,${digest(`${sessionId}:token`)},
        ${digest(`${sessionId}:csrf`)},'passkey',${authenticatedAt},${createdAt},
        ${idle},${absolute},${createdAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        issued_at
      ) VALUES (${sessionId}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,1,1,false,'api','passkey',1,${createdAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_passkey_provenance (
        tenant_id,session_id,user_id,primary_kind,credential_id,
        credential_revision,authenticated_at
      ) VALUES (${fixture.tenant}::uuid,${sessionId}::uuid,
        ${fixture.user}::uuid,'passkey',${fixture.credential}::uuid,
        ${credentialRevision},${authenticatedAt})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence (
        tenant_id,session_id,webauthn_credential_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (${fixture.tenant}::uuid,${sessionId}::uuid,
        ${fixture.credential}::uuid,'primary','webauthn',${authenticatedAt},
        ${credentialRevision})
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES (${fixture.tenant}::uuid,${sessionId}::uuid,
        ${fixture.policy}::uuid,${policyRevision})
    `;
  });
}

function authorityBinding(authority: JsonObject, purpose: string): JsonObject {
  const binding: JsonObject = {
    tenantId: jsonField(authority, "tenantId"),
    userId: jsonField(authority, "userId"),
    identityEpoch: jsonField(authority, "identityEpoch"),
    anchorVersion: jsonField(authority, "anchorVersion"),
    anchorExpiresAt: jsonField(authority, "anchorExpiresAt"),
    anchorRecoveryRestricted: jsonField(authority, "anchorRecoveryRestricted"),
    action: jsonField(authority, "action"),
    audience: jsonField(authority, "audience"),
    requirement: jsonField(authority, "requirement"),
    baselineEvidence: jsonField(authority, "baselineEvidence"),
    purpose,
  };
  for (const key of [
    "sessionId",
    "sessionFamilyId",
    "continuationId",
  ] as const) {
    const value = authority[key];
    if (value !== undefined) {
      binding[key] = value;
    }
  }
  return binding;
}

async function resolveContinuation(
  continuationId: string,
  receipt: Buffer,
): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${continuationId}::uuid,'continuation','session.create','api',
        transaction_timestamp(),${receipt}
      ) AS value
    `,
  );
  return object(row?.value, "passkey continuation authority");
}

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert.equal(version?.version, "18.6");
  await seed();
  await assertPasskeyCeremonySnapshotGuards();

  const loginOne = await completePrimaryLogin({
    label: "primary-one",
    sessionId: fixture.loginOneSession,
    familyId: fixture.loginOneFamily,
    expectedVersion: 1,
    expectedSignCount: 0,
    observedSignCount: 1,
    expectedBackedUp: false,
    backupEligible: false,
    backedUp: false,
    concurrent: true,
  });
  const loginOneCredential = object(loginOne.result.credential, "credential");
  assert.equal(numberField(loginOneCredential, "credentialVersion"), 2);
  assert.equal(numberField(loginOneCredential, "securityRevision"), 1);
  const currentOne = await loadRevalidation(loginOne.sessionId);
  assert.equal(stringField(currentOne, "authenticationMethod"), "passkey");
  assert.equal(object(currentOne.live, "live").primaryActive, true);

  const renameAt = new Date(loginOne.completedAt.getTime() + 1);
  const [rename] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.rename_my_passkey_v1(${transaction.json({
        sessionId: loginOne.sessionId,
        tenantId: fixture.tenant,
        userId: fixture.user,
        deviceId: fixture.credential,
        kind: "passkey",
        displayName: "Renamed primary passkey",
        expectedVersion: 2,
        occurredAt: renameAt.toISOString(),
      })}::jsonb) AS value
    `,
  );
  assert.equal(object(rename?.value, "rename").currentSessionRevoked, false);
  assert.equal(
    object((await loadRevalidation(loginOne.sessionId)).live, "live")
      .primaryActive,
    true,
    "presentation rename changed authority epoch",
  );

  await completePrimaryLogin({
    label: "primary-two",
    sessionId: fixture.loginTwoSession,
    familyId: fixture.loginTwoFamily,
    expectedVersion: 3,
    expectedSignCount: 1,
    observedSignCount: 2,
    expectedBackedUp: false,
    backupEligible: false,
    backedUp: false,
  });
  assert.equal(
    object((await loadRevalidation(loginOne.sessionId)).live, "live")
      .primaryActive,
    true,
    "ordinary second assertion changed authority epoch",
  );

  const liveLogin = await completePrimaryLogin({
    label: "primary-backup-transition",
    sessionId: fixture.liveSession,
    familyId: fixture.liveFamily,
    expectedVersion: 4,
    expectedSignCount: 2,
    observedSignCount: 3,
    expectedBackedUp: false,
    backupEligible: true,
    backedUp: true,
  });
  assert.equal(
    numberField(
      object(liveLogin.result.credential, "credential"),
      "securityRevision",
    ),
    2,
  );
  assert.equal(
    object((await loadRevalidation(loginOne.sessionId)).live, "live")
      .primaryActive,
    false,
    "backup-state drift revived an old session",
  );
  assert.equal(
    object((await loadRevalidation(liveLogin.sessionId)).live, "live")
      .primaryActive,
    true,
  );

  const usableAuthority = await loadRevalidation(liveLogin.sessionId);
  const usableMutation = revalidationMutation(
    usableAuthority,
    "usable",
    "current",
  );
  const usable = await applyRevalidation(usableMutation);
  assert.equal(usable.decision, "usable");
  assert.deepEqual(await applyRevalidation(usableMutation), usable);

  await advancePolicy(2, "primary");
  const rotateAuthority = await loadRevalidation(liveLogin.sessionId);
  const rotateSnapshot = object(rotateAuthority.snapshot, "rotate snapshot");
  const rotateMutation = revalidationMutation(
    rotateAuthority,
    "rotate",
    "policy_refresh",
    {
      session: {
        sessionId: fixture.rotatedSession,
        familyId: liveLogin.familyId,
        tokenDigest: base64("revalidation-rotate-token"),
        csrfDigest: base64("revalidation-rotate-csrf"),
        authenticationMethod: "passkey",
        idleExpiresAt: new Date(Date.now() + 20 * 60_000).toISOString(),
        absoluteExpiresAt: stringField(rotateSnapshot, "absoluteExpiresAt"),
      },
    },
  );
  const rotated = await applyRevalidation(rotateMutation);
  assert.equal(rotated.newSessionId, fixture.rotatedSession);
  await sql`
    UPDATE public.auth_sessions SET last_seen_at=transaction_timestamp()
    WHERE id=${fixture.rotatedSession}::uuid
  `;
  assert.deepEqual(
    await applyRevalidation(rotateMutation),
    rotated,
    "rotate replay depended on mutable successor state",
  );

  await advancePolicy(3, "mfa");
  const stepUpAuthority = await loadRevalidation(fixture.rotatedSession);
  const receipt = digest("step-up-receipt");
  const stepUpMutation = revalidationMutation(
    stepUpAuthority,
    "step_up",
    "assurance_insufficient",
    {
      continuation: {
        continuationId: fixture.continuation,
        receiptDigest: receipt.toString("base64"),
        expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
      },
    },
  );
  const stepUp = await applyRevalidation(stepUpMutation);
  assert.equal(stepUp.continuationId, fixture.continuation);
  await assert.rejects(
    resolveContinuation(fixture.continuation, digest("wrong-receipt")),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const continuationAuthority = await resolveContinuation(
    fixture.continuation,
    receipt,
  );
  assert.equal(continuationAuthority.primaryKind, "passkey");
  const reservation = object(
    continuationAuthority.federatedReservation,
    "passkey reservation",
  );
  assert.equal(reservation.providerKind, "passkey");
  assert.equal(reservation.authenticationMethod, "passkey");
  assert.equal(reservation.credentialId, fixture.credential);
  assert.equal(reservation.credentialRevision, 2);

  const ceremonyId = digest("continuation-ceremony");
  const browserDigest = digest("continuation-browser");
  const ceremonyCreatedAt = new Date(Date.now() - 1_000);
  const continuationBinding = authorityBinding(
    continuationAuthority,
    "continuation_authentication",
  );
  await asApi(
    (transaction) => transaction`
    SELECT app.create_webauthn_ceremony_v1(${transaction.json({
      id: ceremonyId.toString("base64"),
      challengeDigest: base64("continuation-challenge"),
      browserDigest: browserDigest.toString("base64"),
      relyingParty: {
        id: "example.invalid",
        origins: ["https://example.invalid"],
        revision: 1,
      },
      binding: continuationBinding,
      continuationReceiptDigest: receipt.toString("base64"),
      policy: {
        requireUserPresence: true,
        userVerification: "preferred",
        residentKey: "preferred",
        attestation: "none",
        metadataRevision: 0,
      },
      mode: "known_user",
      userHandleDigest: createHash("sha256")
        .update(userHandle)
        .digest("base64"),
      allowedCredentialIds: [credentialWireId.toString("base64")],
      createdAt: ceremonyCreatedAt.toISOString(),
      expiresAt: new Date(
        ceremonyCreatedAt.getTime() + 5 * 60_000,
      ).toISOString(),
      state: "pending",
      version: 1,
    })}::jsonb)
  `,
  );
  const claimedAt = new Date(ceremonyCreatedAt.getTime() + 100);
  await asApi(
    (transaction) => transaction`
    SELECT app.claim_webauthn_ceremony_v2(
      ${ceremonyId},${browserDigest},${claimedAt},${receipt}
    )
  `,
  );
  const completedAt = new Date();
  const continuationSnapshot = object(
    stepUpAuthority.snapshot,
    "step-up source snapshot",
  );
  const completionRequest: JsonObject = {
    completion: {
      ceremonyId: ceremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: continuationBinding,
      resolvedUserId: fixture.user,
      expectedIdentityEpoch: 1,
      credentialId: credentialWireId.toString("base64"),
      expectedCredentialVersion: 5,
      completedAt: completedAt.toISOString(),
      expectedSignCount: 3,
      observedSignCount: 4,
      expectedBackedUp: true,
      counterDisposition: "advance",
      userVerified: false,
      backupEligible: true,
      backedUp: true,
    },
    audit: {
      kind: "mfa.passkey_step_up_completed",
      tenantId: fixture.tenant,
      userId: fixture.user,
      action: "session.create",
      occurredAt: completedAt.toISOString(),
      policyRevisions:
        object(continuationAuthority.requirement, "continuation requirement")
          .policyRevisions ?? [],
    },
    session: {
      mutation: "consume_continuation",
      expectedContinuationId: fixture.continuation,
      expectedAnchorVersion: numberField(
        continuationAuthority,
        "anchorVersion",
      ),
      expectedIdentityEpoch: 1,
      expectedAnchorExpiry: stringField(
        continuationAuthority,
        "anchorExpiresAt",
      ),
      audience: "api",
      requirement: jsonField(continuationAuthority, "requirement"),
      recoveryRestricted: false,
      continuationReceiptDigest: receipt.toString("base64"),
      reservation: {
        sessionId: fixture.continuationSuccessor,
        familyId: liveLogin.familyId,
        tokenDigest: base64("continuation-successor-token"),
        csrfDigest: base64("continuation-successor-csrf"),
        authenticationMethod: "passkey",
        idleExpiresAt: new Date(
          completedAt.getTime() + 20 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: stringField(
          continuationSnapshot,
          "absoluteExpiresAt",
        ),
      },
    },
  };
  const [completion] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.complete_mfa_passkey_authentication_v1(
        ${transaction.json(completionRequest)}::jsonb
      ) AS value
    `,
  );
  const completionResult = object(completion?.value, "continuation completion");
  assert.equal(completionResult.newSessionId, fixture.continuationSuccessor);
  const [exactEvidence] = await sql<{ count: number; revision: number }[]>`
    SELECT count(*)::integer AS count,
           min(factor_revision)::integer AS revision
    FROM public.auth_session_mfa_evidence
    WHERE tenant_id=${fixture.tenant}::uuid
      AND session_id=${fixture.continuationSuccessor}::uuid
      AND webauthn_credential_id=${fixture.credential}::uuid
  `;
  assert.deepEqual(exactEvidence, { count: 1, revision: 2 });
  const [capabilityCleanup] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenant_mfa_webauthn_evidence_copy_capabilities
    WHERE tenant_id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(capabilityCleanup, { count: 0 });
  const [completionReplay] = await asApi(
    (transaction) => transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.complete_mfa_passkey_authentication_v1(
        ${transaction.json(completionRequest)}::jsonb
      ) AS value
    `,
  );
  assert.deepEqual(completionReplay?.value, completionResult);
  assert.deepEqual(
    await applyRevalidation(stepUpMutation),
    stepUp,
    "step-up replay depended on consumed continuation/source state",
  );

  await seedPasskeySession(
    fixture.revokeSession,
    fixture.revokeFamily,
    2,
    3,
    completedAt,
  );
  await seedPasskeySession(
    fixture.denySession,
    fixture.denyFamily,
    2,
    3,
    completedAt,
  );
  const revokeResult = await applyRevalidation(
    revalidationMutation(
      await loadRevalidation(fixture.revokeSession),
      "revoke",
      "expired",
    ),
  );
  assert.equal(revokeResult.decision, "revoke");
  const denyResult = await applyRevalidation(
    revalidationMutation(
      await loadRevalidation(fixture.denySession),
      "deny",
      "malformed",
    ),
  );
  assert.equal(denyResult.decision, "deny");
  const [terminalFamilies] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count FROM public.auth_sessions
    WHERE id IN (${fixture.revokeSession}::uuid,${fixture.denySession}::uuid)
      AND revoked_at IS NOT NULL
  `;
  assert.deepEqual(terminalFamilies, { count: 2 });

  await assert.rejects(
    applyRevalidation({ ...usableMutation, unexpected: true }),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  await completePrimaryClone();
} finally {
  await sql.end();
}
