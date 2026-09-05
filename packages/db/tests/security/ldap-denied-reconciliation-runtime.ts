import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_LDAP_DENIED_RECONCILIATION_TEST_DATABASE_URL ?? "";
if (databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_LDAP_DENIED_RECONCILIATION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

// Reuse the real provider/binding/mapping/identity fixture. This suite owns a
// distinct fresh database in CI, so importing the fixture remains isolated.
process.env.PERIAPSIS_IDENTITY_DIRECTORY_OPERATION_TEST_DATABASE_URL =
  databaseUrl;
await import("./identity-directory-operations-concurrency.js");

const fixture = {
  tenant: "0199f300-1000-7000-8000-000000000001",
  adminUser: "0199f300-1000-7000-8000-000000000101",
  adminMembership: "0199f300-1000-7000-8000-000000000201",
  targetUser: "0199f300-1000-7000-8000-000000000103",
  targetMembership: "0199f300-1000-7000-8000-000000000203",
  provider: "0199f300-1000-7000-8000-000000000301",
  group: "0199f300-1000-7000-8000-000000000403",
  role: "0199f300-1000-7000-8000-000000000404",
  externalIdentity: "0199f300-1000-7000-8000-000000000501",
  subjectAlias: "0199f300-1000-7000-8000-000000000502",
  accessGrant: "0199f300-1000-7000-8000-000000000503",
} as const;

const uuid = (sequence: number): string =>
  `01a05f10-0000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): Buffer =>
  createHash("sha256")
    .update(`ldap-denied-reconciliation-runtime:${label}`)
    .digest();
const base64Digest = (label: string): string =>
  digest(label).toString("base64");

const sql = postgres(databaseUrl, { max: 12, onnotice: () => undefined });

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function asRole<T>(
  role: "periapsis_api" | "periapsis_worker" | "periapsis_migrator",
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const wrapped = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await operation(transaction) };
  });
  return wrapped.value;
}

type JitNetworkSnapshot = {
  operation_run_id: string;
  tenant_id: string;
  started_at: string;
  expires_at: string;
};

type JitPlanningSnapshot = {
  operation_run_id: string;
  tenant_id: string;
  external_identity_id: string;
  user_id: string;
  membership_id: string;
  rules: {
    ruleEpochId: string;
    matcherValue: string;
  }[];
};

type JitApplication = {
  application_id: string;
  decision: "admitted" | "denied";
  ensured_edge_count: number;
  revoked_edge_count: number;
  replayed: boolean;
};

type AuthorityIssueResult = {
  category: "success";
  disposition: "session" | "continuation";
  userId: string;
  sessionId?: string;
  continuationId?: string;
  returnPath: string;
  replayed: boolean;
};

type SessionReservation = {
  sessionId: string;
  familyId: string;
  tokenDigest: string;
  csrfDigest: string;
  authenticationMethod: "ldap" | "totp" | "recovery_code" | "passkey";
  idleExpiresAt: string;
  absoluteExpiresAt: string;
};

type IssueRequest = {
  runId: string;
  receipt: Buffer;
  applicationId: string;
  disposition: "session" | "continuation";
  assurance: "satisfied" | "step_up_required" | "enrollment_only";
  authenticatedAt: Date | string;
  appliedAt: Date;
  returnPath: string;
  session: SessionReservation | null;
  continuation: {
    continuationId: string;
    receiptDigest: string;
    expiresAt: string;
  } | null;
  auditEventId: string;
  ipAddress: string;
  userAgent: string;
};

type JsonObject = Record<string, postgres.JSONValue>;

function isJsonObject(
  value: postgres.JSONValue | undefined,
): value is JsonObject {
  return (
    value !== undefined &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function jsonObject(
  value: postgres.JSONValue | undefined,
  label: string,
): JsonObject {
  if (!isJsonObject(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  return value;
}

function jsonField(value: JsonObject, key: string): postgres.JSONValue {
  const field = value[key];
  if (field === undefined) {
    throw new Error(`${key} is required`);
  }
  return field;
}

function stringField(value: JsonObject, key: string): string {
  const field = jsonField(value, key);
  if (typeof field !== "string") {
    throw new TypeError(`${key} must be a string`);
  }
  return field;
}

async function beginJit(
  runId: string,
  receipt: Buffer,
  sequence: number,
): Promise<JitNetworkSnapshot> {
  const [snapshot] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<JitNetworkSnapshot[]>`
      SELECT operation_run_id,tenant_id,started_at::text,expires_at::text
      FROM app.begin_tenant_ldap_jit_authentication_v1(
        ${runId}::uuid, ${receipt}::bytea,
        'directory-operation-proof'::text, 'bounded_ldap'::text,
        ${digest(`network-${sequence}`)}::bytea,
        ${digest(`account-${sequence}`)}::bytea,
        ${digest(`provider-${sequence}`)}::bytea,
        ${uuid(sequence + 1)}::uuid, ${uuid(sequence + 2)}::uuid,
        ${uuid(sequence + 3)}::uuid, '192.0.2.211'::inet,
        'Periapsis LDAP denied reconciliation runtime'::text
      )
    `,
  );
  assert(snapshot, "LDAP JIT begin returned no network snapshot");
  return snapshot;
}

async function claimJit(
  runId: string,
  receipt: Buffer,
  sequence: number,
): Promise<JitPlanningSnapshot> {
  const [snapshot] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<JitPlanningSnapshot[]>`
      SELECT * FROM app.claim_tenant_ldap_jit_planning_v1(
        ${runId}::uuid, ${receipt}::bytea, ARRAY[2]::integer[],
        ARRAY[decode(repeat('ee',32),'hex')]::bytea[],
        ${uuid(sequence + 4)}::uuid, ${uuid(sequence + 5)}::uuid,
        ${uuid(sequence + 6)}::uuid, '192.0.2.211'::inet,
        'Periapsis LDAP denied reconciliation runtime'::text
      )
    `,
  );
  assert(snapshot, "LDAP JIT claim returned no planning snapshot");
  assert.equal(snapshot.external_identity_id, fixture.externalIdentity);
  assert.equal(snapshot.user_id, fixture.targetUser);
  assert.equal(snapshot.membership_id, fixture.targetMembership);
  return snapshot;
}

async function applyAdmittedJit(
  runId: string,
  receipt: Buffer,
  applicationId: string,
  ruleEpochId: string,
  sequence: number,
  accessGrantId: string = fixture.accessGrant,
): Promise<JitApplication> {
  const [application] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<JitApplication[]>`
      SELECT * FROM app.apply_tenant_ldap_jit_identity_plan_v1(
        ${runId}::uuid, ${receipt}::bytea, ${applicationId}::uuid,
        ${digest(`plan-${sequence}`)}::bytea, 'admitted', NULL::text,
        ${fixture.externalIdentity}::uuid, ${fixture.targetUser}::uuid,
        ${fixture.targetMembership}::uuid, ${accessGrantId}::uuid,
        ${uuid(sequence + 7)}::uuid, 'ad_object_guid',
        decode(repeat('cc',17),'hex'), decode(repeat('dd',12),'hex'), 2,
        ARRAY[${fixture.subjectAlias}::uuid]::uuid[], ARRAY[2]::integer[],
        ARRAY[decode(repeat('ee',32),'hex')]::bytea[],
        'LDAP Target', 'Target', 'User', 'target.user',
        'target@example.invalid', ARRAY[${ruleEpochId}::uuid]::uuid[],
        transaction_timestamp(), ${uuid(sequence + 8)}::uuid,
        ${uuid(sequence + 9)}::uuid, ${uuid(sequence + 10)}::uuid,
        '192.0.2.211'::inet,
        'Periapsis LDAP denied reconciliation runtime'::text
      )
    `,
  );
  assert(application, "LDAP JIT apply returned no application");
  assert.equal(application.decision, "admitted");
  assert.equal(application.replayed, false);
  assert(application.ensured_edge_count >= 0);
  return application;
}

async function invokeAuthorityIssue(
  transaction: postgres.TransactionSql,
  request: IssueRequest,
  wireShape?: {
    sessionJsonNull?: boolean;
    continuationJsonNull?: boolean;
  },
): Promise<AuthorityIssueResult> {
  // postgres.js encodes a parameter inferred as timestamptz through Date and
  // would truncate the database-issued JIT fence to milliseconds. Preserve
  // the exact textual token through bytea before PostgreSQL parses it.
  const authenticatedAt = Buffer.from(
    typeof request.authenticatedAt === "string"
      ? request.authenticatedAt
      : request.authenticatedAt.toISOString(),
    "utf8",
  );
  const session = wireShape?.sessionJsonNull
    ? transaction`jsonb_build_array(NULL)->0`
    : request.session === null
      ? transaction`${null}::jsonb`
      : transaction`${transaction.json(request.session)}::jsonb`;
  const continuation = wireShape?.continuationJsonNull
    ? transaction`jsonb_build_array(NULL)->0`
    : request.continuation === null
      ? transaction`${null}::jsonb`
      : transaction`${transaction.json(request.continuation)}::jsonb`;
  const rows = Array.from(
    await transaction<{ result: AuthorityIssueResult }[]>`
      SELECT app.issue_tenant_ldap_jit_authority_v1(
        ${request.runId}::uuid, ${request.receipt}::bytea,
        ${request.applicationId}::uuid, ${request.disposition},
        ${request.assurance},
        convert_from(${authenticatedAt}::bytea,'UTF8')::timestamptz,
        ${request.appliedAt}::timestamptz, ${request.returnPath},
        ${session}, ${continuation},
        ${request.auditEventId}::uuid, ${request.ipAddress}::inet,
        ${request.userAgent}
      ) AS result
    `,
  );
  const [row] = rows;
  assert(row, "LDAP authority issuance returned no result");
  return row.result;
}

async function issueAuthority(
  request: IssueRequest,
  wireShape?: {
    sessionJsonNull?: boolean;
    continuationJsonNull?: boolean;
  },
): Promise<AuthorityIssueResult> {
  return asRole("periapsis_api", (transaction) =>
    invokeAuthorityIssue(transaction, request, wireShape),
  );
}

async function createAdmittedJit(
  sequence: number,
  accessGrantId: string = fixture.accessGrant,
): Promise<{
  runId: string;
  receipt: Buffer;
  applicationId: string;
  network: JitNetworkSnapshot;
}> {
  const runId = uuid(sequence);
  const receipt = digest(`jit-receipt-${sequence}`);
  const applicationId = uuid(sequence + 20);
  const network = await beginJit(runId, receipt, sequence);
  const planning = await claimJit(runId, receipt, sequence);
  const rule = planning.rules.find(
    (candidate) =>
      candidate.matcherValue.toLocaleLowerCase("en-US") === "soc-blue",
  );
  assert(rule, "SOC mapping was not pinned by the JIT claim");
  await applyAdmittedJit(
    runId,
    receipt,
    applicationId,
    rule.ruleEpochId,
    sequence,
    accessGrantId,
  );
  return { runId, receipt, applicationId, network };
}

async function createRootSession(
  sequence: number,
  accessGrantId: string = fixture.accessGrant,
): Promise<{
  runId: string;
  session: SessionReservation;
  appliedAt: Date;
}> {
  const run = await createAdmittedJit(sequence, accessGrantId);
  const appliedAt = new Date();
  const session: SessionReservation = {
    sessionId: uuid(sequence + 30),
    familyId: uuid(sequence + 31),
    tokenDigest: base64Digest(`root-session-${sequence}-token`),
    csrfDigest: base64Digest(`root-session-${sequence}-csrf`),
    authenticationMethod: "ldap",
    idleExpiresAt: new Date(appliedAt.getTime() + 60 * 60_000).toISOString(),
    absoluteExpiresAt: new Date(
      appliedAt.getTime() + 24 * 60 * 60_000,
    ).toISOString(),
  };
  const result = await issueAuthority({
    runId: run.runId,
    receipt: run.receipt,
    applicationId: run.applicationId,
    disposition: "session",
    assurance: "satisfied",
    authenticatedAt: run.network.started_at,
    appliedAt,
    returnPath: "/tickets",
    session,
    continuation: null,
    auditEventId: uuid(sequence + 32),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denied reconciliation runtime",
  });
  assert.equal(result.sessionId, session.sessionId);
  return { runId: run.runId, session, appliedAt };
}

async function createRootContinuation(
  sequence: number,
  continuationIdOverride?: string,
  accessGrantId: string = fixture.accessGrant,
): Promise<{
  runId: string;
  receipt: Buffer;
  network: JitNetworkSnapshot;
  continuationId: string;
  continuationReceipt: Buffer;
  expiresAt: Date;
}> {
  const run = await createAdmittedJit(sequence, accessGrantId);
  const appliedAt = new Date();
  const continuationId = continuationIdOverride ?? uuid(sequence + 30);
  const continuationReceipt = digest(`root-continuation-${sequence}`);
  const expiresAt = new Date(appliedAt.getTime() + 10 * 60_000);
  const result = await issueAuthority({
    runId: run.runId,
    receipt: run.receipt,
    applicationId: run.applicationId,
    disposition: "continuation",
    assurance: "step_up_required",
    authenticatedAt: run.network.started_at,
    appliedAt,
    returnPath: "/tickets",
    session: null,
    continuation: {
      continuationId,
      receiptDigest: continuationReceipt.toString("base64"),
      expiresAt: expiresAt.toISOString(),
    },
    auditEventId: uuid(sequence + 32),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denied reconciliation runtime",
  });
  assert.equal(result.continuationId, continuationId);
  return {
    runId: run.runId,
    receipt: run.receipt,
    network: run.network,
    continuationId,
    continuationReceipt,
    expiresAt,
  };
}

async function resolveAuthority(
  referenceId: string,
  flow: "session" | "continuation" | "enrollment",
  action: string,
  evaluatedAt: Date,
  continuationReceipt: Buffer | null = null,
): Promise<JsonObject> {
  const [row] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_authority_v2(
        ${referenceId}::uuid,${flow},${action},'api',
        ${evaluatedAt}::timestamptz,${continuationReceipt}::bytea
      ) AS value
    `,
    ),
  );
  return jsonObject(row?.value, "LDAP MFA authority");
}

function stepUpBinding(authority: JsonObject): JsonObject {
  const flow = stringField(authority, "flow");
  assert(flow === "session" || flow === "continuation");
  return {
    flow,
    tenantId: jsonField(authority, "tenantId"),
    userId: jsonField(authority, "userId"),
    identityEpoch: jsonField(authority, "identityEpoch"),
    ...(flow === "session"
      ? {
          sessionId: jsonField(authority, "sessionId"),
          sessionFamilyId: jsonField(authority, "sessionFamilyId"),
        }
      : { continuationId: jsonField(authority, "continuationId") }),
    anchorVersion: jsonField(authority, "anchorVersion"),
    anchorExpiresAt: jsonField(authority, "anchorExpiresAt"),
    anchorRecoveryRestricted: jsonField(authority, "anchorRecoveryRestricted"),
    action: jsonField(authority, "action"),
    audience: jsonField(authority, "audience"),
    requirement: jsonField(authority, "requirement"),
    baselineEvidence: jsonField(authority, "baselineEvidence"),
  };
}

function webauthnBinding(
  authority: JsonObject,
  purpose:
    "step_up_authentication" | "continuation_authentication" | "registration",
): JsonObject {
  const flow = stringField(authority, "flow");
  assert(flow === "session" || flow === "continuation");
  return {
    purpose,
    tenantId: jsonField(authority, "tenantId"),
    userId: jsonField(authority, "userId"),
    identityEpoch: jsonField(authority, "identityEpoch"),
    ...(flow === "session"
      ? {
          sessionId: jsonField(authority, "sessionId"),
          sessionFamilyId: jsonField(authority, "sessionFamilyId"),
        }
      : { continuationId: jsonField(authority, "continuationId") }),
    anchorVersion: jsonField(authority, "anchorVersion"),
    anchorExpiresAt: jsonField(authority, "anchorExpiresAt"),
    anchorRecoveryRestricted: jsonField(authority, "anchorRecoveryRestricted"),
    action: jsonField(authority, "action"),
    audience: jsonField(authority, "audience"),
    requirement: jsonField(authority, "requirement"),
    baselineEvidence: jsonField(authority, "baselineEvidence"),
  };
}

async function createAndClaimFactorChallenge(input: {
  authority: JsonObject;
  factorKind: "totp" | "recovery_code";
  selectedFactorId?: string;
  sequence: number;
  createdAt: Date;
  continuationReceipt?: Buffer;
}): Promise<{
  binding: JsonObject;
  challengeId: Buffer;
  completedAt: Date;
}> {
  const binding = stepUpBinding(input.authority);
  const challengeId = digest(`factor-challenge-${input.sequence}`);
  const browserDigest = digest(`factor-browser-${input.sequence}`);
  const created = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: boolean }[]>`
      SELECT app.create_mfa_step_up_challenge_v1(
        ${transaction.json({
          id: challengeId.toString("base64"),
          browserDigest: browserDigest.toString("base64"),
          binding,
          allowedFactors: [input.factorKind],
          ...(input.continuationReceipt === undefined
            ? {}
            : {
                continuationReceiptDigest:
                  input.continuationReceipt.toString("base64"),
              }),
          createdAt: input.createdAt.toISOString(),
          expiresAt: new Date(
            input.createdAt.getTime() + 5 * 60_000,
          ).toISOString(),
          state: "pending",
          version: 1,
        })}::jsonb
      ) AS value
    `,
    ),
  );
  assert.equal(created[0]?.value, true);
  const artifact = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_completion_artifact_v1(
        ${transaction.json({
          artifactKind: "step_up_challenge",
          artifactId: challengeId.toString("base64"),
          browserDigest: browserDigest.toString("base64"),
          selectedFactorKind: input.factorKind,
          ...(input.selectedFactorId === undefined
            ? {}
            : { selectedFactorId: input.selectedFactorId }),
          ...(input.continuationReceipt === undefined
            ? {}
            : {
                continuationReceiptDigest:
                  input.continuationReceipt.toString("base64"),
              }),
          requestedAt: input.createdAt.toISOString(),
        })}::jsonb
      ) AS value
    `,
    ),
  );
  const artifactValue = jsonObject(
    artifact[0]?.value,
    "LDAP MFA completion artifact",
  );
  assert.equal(
    stringField(artifactValue, "resultAuthenticationMethod"),
    "ldap",
  );
  assert.notEqual(
    stringField(artifactValue, "reservationAuthenticationMethod"),
    "ldap",
  );
  const claimedAt = new Date(input.createdAt.getTime() + 1_000);
  const claimed = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.claim_mfa_step_up_challenge_v2(
        ${challengeId}::bytea,${browserDigest}::bytea,${input.factorKind},
        ${claimedAt}::timestamptz,
        ${input.continuationReceipt ?? null}::bytea
      ) AS value
    `,
    ),
  );
  const claimedValue = jsonObject(claimed[0]?.value, "claimed LDAP factor");
  assert.equal(jsonField(claimedValue, "version"), 2);
  assert.equal(
    stringField(claimedValue, "claimedFactorKind"),
    input.factorKind,
  );
  return {
    binding,
    challengeId,
    completedAt: new Date(claimedAt.getTime() + 1_000),
  };
}

async function createAndClaimRegistrationCeremony(input: {
  authority: JsonObject;
  credentialWireId: Buffer;
  userHandleDigest: Buffer;
  sequence: number;
  createdAt: Date;
  continuationReceipt?: Buffer;
}): Promise<{
  binding: JsonObject;
  ceremonyId: Buffer;
  completedAt: Date;
  artifact: JsonObject;
}> {
  const binding = webauthnBinding(input.authority, "registration");
  const ceremonyId = digest(`registration-ceremony-${input.sequence}`);
  const browserDigest = digest(`registration-browser-${input.sequence}`);
  const created = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: boolean }[]>`
      SELECT app.create_webauthn_ceremony_v1(
        ${transaction.json({
          id: ceremonyId.toString("base64"),
          challengeDigest: base64Digest(
            `registration-challenge-${input.sequence}`,
          ),
          browserDigest: browserDigest.toString("base64"),
          relyingParty: {
            id: "example.invalid",
            origins: ["https://example.invalid"],
            revision: 1,
          },
          binding,
          policy: {
            requireUserPresence: true,
            userVerification: "required",
            residentKey: "preferred",
            attestation: "none",
            metadataRevision: 0,
          },
          userHandleDigest: input.userHandleDigest.toString("base64"),
          allowedCredentialIds: [],
          ...(input.continuationReceipt === undefined
            ? {}
            : {
                continuationReceiptDigest:
                  input.continuationReceipt.toString("base64"),
              }),
          createdAt: input.createdAt.toISOString(),
          expiresAt: new Date(
            input.createdAt.getTime() + 5 * 60_000,
          ).toISOString(),
          state: "pending",
          version: 1,
        })}::jsonb
      ) AS value
    `,
    ),
  );
  assert.equal(created[0]?.value, true);
  const artifactRows = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.resolve_mfa_completion_artifact_v1(
        ${transaction.json({
          artifactKind: "webauthn_registration",
          artifactId: ceremonyId.toString("base64"),
          browserDigest: browserDigest.toString("base64"),
          selectedFactorKind: "passkey",
          selectedFactorId: input.credentialWireId.toString("base64"),
          ...(input.continuationReceipt === undefined
            ? {}
            : {
                continuationReceiptDigest:
                  input.continuationReceipt.toString("base64"),
              }),
          requestedAt: input.createdAt.toISOString(),
        })}::jsonb
      ) AS value
    `,
    ),
  );
  const artifact = jsonObject(
    artifactRows[0]?.value,
    "LDAP registration artifact",
  );
  const flow = stringField(input.authority, "flow");
  assert.equal(stringField(artifact, "flow"), flow);
  if (flow === "session") {
    assert.equal(stringField(artifact, "reservationDisposition"), "rotate");
    assert.equal(
      stringField(artifact, "reservationAuthenticationMethod"),
      "passkey",
    );
    assert.equal(stringField(artifact, "resultAuthenticationMethod"), "ldap");
  } else {
    assert.equal(stringField(artifact, "reservationDisposition"), "none");
    assert.equal(jsonField(artifact, "reservationAuthenticationMethod"), null);
    assert.equal(jsonField(artifact, "resultAuthenticationMethod"), null);
  }
  const claimedAt = new Date(input.createdAt.getTime() + 1_000);
  const claimed = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.claim_webauthn_ceremony_v2(
        ${ceremonyId}::bytea,${browserDigest}::bytea,
        ${claimedAt}::timestamptz,
        ${input.continuationReceipt ?? null}::bytea
      ) AS value
    `,
    ),
  );
  const claimedValue = jsonObject(
    claimed[0]?.value,
    "claimed LDAP registration ceremony",
  );
  assert.equal(jsonField(claimedValue, "version"), 2);
  assert.equal(stringField(claimedValue, "state"), "claimed");
  return {
    binding,
    ceremonyId,
    completedAt: new Date(claimedAt.getTime() + 1_000),
    artifact,
  };
}

async function loadRevalidation(sessionId: string): Promise<JsonObject> {
  const [row] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.load_federated_session_revalidation_v1(
        ${transaction.json({
          sessionId,
          tenantId: fixture.tenant,
          audience: "api",
          authenticationMethod: "ldap",
          observedAt: new Date().toISOString(),
        })}::jsonb
      ) AS value
    `,
    ),
  );
  assert.notEqual(row?.value, null, "LDAP session must be projected");
  return jsonObject(row?.value ?? undefined, "LDAP revalidation projection");
}

async function applyRevalidation(mutation: JsonObject): Promise<JsonObject> {
  return asRole("periapsis_api", (transaction) =>
    invokeRevalidation(transaction, mutation),
  );
}

async function invokeRevalidation(
  transaction: postgres.TransactionSql,
  mutation: JsonObject,
): Promise<JsonObject> {
  const [row] = Array.from(
    await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_federated_session_revalidation_v1(
        ${transaction.json(mutation)}::jsonb
      ) AS value
    `,
  );
  return jsonObject(row?.value, "LDAP revalidation result");
}

function revalidationMutation(
  projection: JsonObject,
  decision: "usable" | "rotate" | "step_up" | "revoke" | "deny",
  reason: string,
  extra: JsonObject = {},
): JsonObject {
  const snapshot = jsonObject(
    jsonField(projection, "snapshot"),
    "LDAP revalidation snapshot",
  );
  const live = jsonObject(
    jsonField(projection, "live"),
    "LDAP revalidation live projection",
  );
  return {
    sessionId: jsonField(snapshot, "sessionId"),
    tenantId: fixture.tenant,
    userId: fixture.targetUser,
    audience: "api",
    authenticationMethod: "ldap",
    expectedVersion: jsonField(snapshot, "version"),
    observedAt: new Date().toISOString(),
    decision,
    reason,
    requirement: jsonField(live, "requirement"),
    ...extra,
  };
}

async function advanceTenantBaseline(
  revision: number,
  level: "primary" | "mfa" | "phishing_resistant",
): Promise<void> {
  const changedAt = new Date();
  await sql.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',
        ${`retire:${uuid(2)}:${revision - 1}`},true
      )
    `;
    await transaction`
      UPDATE public.mfa_policy_revisions
      SET retired_at=${changedAt}
      WHERE id=${uuid(2)}::uuid AND retired_at IS NULL
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',${`insert:${uuid(2)}:${revision}`},true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions(
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (
        ${uuid(2)}::uuid,${revision},${fixture.tenant}::uuid,
        'tenant_baseline',${level},false,0,${changedAt}
      )
    `;
  });
}

async function exerciseGenericFederatedRecoveryReplacement(
  authenticationMethod: "oidc" | "saml",
  sequence: number,
  platformFloorId: string,
  tenantBaselineId: string,
): Promise<void> {
  const userId = uuid(sequence + 1);
  const membershipId = uuid(sequence + 2);
  const providerId = uuid(sequence + 3);
  const bindingId = uuid(sequence + 4);
  const externalIdentityId = uuid(sequence + 5);
  const sourceId = uuid(sequence + 6);
  const accessEpochId = uuid(sequence + 7);
  const accessGrantId = uuid(sequence + 8);
  const trustRuleId = uuid(sequence + 9);
  const recoverySetId = uuid(sequence + 10);
  const recoveryCodeId = uuid(sequence + 11);
  const sourceSessionId = uuid(sequence + 12);
  const familyId = uuid(sequence + 13);
  const successorSessionId = uuid(sequence + 14);
  const replacementSetId = uuid(sequence + 15);
  const samlMaterialId = uuid(sequence + 16);
  const oidcMaterialId = uuid(sequence + 17);
  const authenticationApplicationId = uuid(sequence + 18);
  const authenticationTransactionId = digest(
    `${authenticationMethod}-recovery-authentication-transaction`,
  );
  const createdAt = new Date();
  const authenticationExpiresAt = new Date(createdAt.getTime() + 10 * 60_000);
  const idleExpiresAt = new Date(createdAt.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(createdAt.getTime() + 2 * 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.users(
        id,email,display_name,active,created_at,updated_at
      ) VALUES (
        ${userId}::uuid,
        ${`recovery-${authenticationMethod}-${sequence}@example.invalid`},
        ${`${authenticationMethod.toUpperCase()} recovery replacement`},
        true,${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES (
        ${membershipId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        'analyst','active',${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects(
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${userId}::uuid,
        ${digest(`${authenticationMethod}-user-handle`)}::bytea,
        1,1,1,${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers(
        id,tenant_id,key,display_name,description,kind,enabled,
        created_by_membership_id,updated_by_membership_id,version,
        created_at,updated_at
      ) VALUES (
        ${providerId}::uuid,${fixture.tenant}::uuid,
        ${`recovery_${authenticationMethod}_${sequence}`},
        ${`${authenticationMethod.toUpperCase()} recovery provider`},
        'Recovery replacement runtime fixture',${authenticationMethod},true,
        ${membershipId}::uuid,${membershipId}::uuid,1,
        ${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_bindings(
        id,tenant_id,provider_id,key,enabled,profile_priority,auth_revision,
        current_access_epoch_id,created_by_membership_id,
        updated_by_membership_id,version,created_at,updated_at,mapping_revision
      ) VALUES (
        ${bindingId}::uuid,${fixture.tenant}::uuid,${providerId}::uuid,
        ${`recovery_${authenticationMethod}_${sequence}`},true,100,1,
        ${accessEpochId}::uuid,${membershipId}::uuid,${membershipId}::uuid,
        1,${createdAt},${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_policies(
        tenant_id,provider_id,binding_id,provider_kind,
        configuration_revision,security_revision,plan_revision,
        assurance_policy_revision,jit_mode,no_match_policy,enabled,
        created_at,updated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${providerId}::uuid,${bindingId}::uuid,
        ${authenticationMethod},1,1,1,1,'disabled','provider_access_only',true,
        ${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_trust_rules(
        id,tenant_id,provider_id,binding_id,provider_kind,revision,enabled,
        level,exact_value,required_values,maximum_authentication_age_seconds,
        created_at
      ) VALUES (
        ${trustRuleId}::uuid,${fixture.tenant}::uuid,${providerId}::uuid,
        ${bindingId}::uuid,${authenticationMethod},1,true,'mfa','mfa',
        ARRAY[]::text[],3600,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identities(
        id,tenant_id,provider_id,binding_id,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,
        admitted_configuration_revision,last_observed_at,version,
        created_at,updated_at
      ) VALUES (
        ${externalIdentityId}::uuid,${fixture.tenant}::uuid,
        ${providerId}::uuid,${bindingId}::uuid,${userId}::uuid,'utf8_exact',
        ${Buffer.alloc(32, sequence % 255)}::bytea,
        ${Buffer.alloc(12, (sequence + 1) % 255)}::bytea,2,1,
        ${createdAt},1,${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources(
        id,tenant_id,kind,key,authoritative,protected,created_at
      ) VALUES (
        ${sourceId}::uuid,${fixture.tenant}::uuid,'identity_provider_access',
        ${`identity_provider_access:${bindingId}:1`},true,false,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs(
        id,tenant_id,binding_id,provider_id,source_id,sequence,
        started_by_membership_id,started_at,version
      ) VALUES (
        ${accessEpochId}::uuid,${fixture.tenant}::uuid,${bindingId}::uuid,
        ${providerId}::uuid,${sourceId}::uuid,1,${membershipId}::uuid,
        ${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_access_grants(
        id,tenant_id,provider_id,binding_id,access_epoch_id,source_id,
        external_identity_id,membership_id,user_id,owns_membership,
        started_at,last_observed_at,version
      ) VALUES (
        ${accessGrantId}::uuid,${fixture.tenant}::uuid,${providerId}::uuid,
        ${bindingId}::uuid,${accessEpochId}::uuid,${sourceId}::uuid,
        ${externalIdentityId}::uuid,${membershipId}::uuid,${userId}::uuid,
        false,${createdAt},${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_code_sets(
        id,tenant_id,user_id,digest_key_version,record_version,
        security_revision,completion_request_digest,result_snapshot,status,
        generated_at,updated_at
      ) VALUES (
        ${recoverySetId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        1,1,1,${digest(`${authenticationMethod}-recovery-set`)}::bytea,
        '{}'::jsonb,'active',${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_codes(
        id,tenant_id,set_id,code_digest,created_at
      ) VALUES (
        ${recoveryCodeId}::uuid,${fixture.tenant}::uuid,
        ${recoverySetId}::uuid,
        ${digest(`${authenticationMethod}-recovery-code`)}::bytea,
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions(
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      ) VALUES (
        ${sourceSessionId}::uuid,${userId}::uuid,${familyId}::uuid,
        ${fixture.tenant}::uuid,
        ${digest(`${authenticationMethod}-source-token`)}::bytea,
        ${digest(`${authenticationMethod}-source-csrf`)}::bytea,
        ${authenticationMethod},${createdAt},${createdAt},${idleExpiresAt},
        ${absoluteExpiresAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states(
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,
        session_invalidation_epoch,issued_at
      ) VALUES (
        ${sourceSessionId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        1,1,true,'api','tenant_provider',1,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance(
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        provider_id,binding_id,provider_kind,external_identity_id,
        external_identity_revision,trust_rule_revision,authenticated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,${userId}::uuid,
        'tenant_provider',${authenticationMethod},${providerId}::uuid,
        ${bindingId}::uuid,${authenticationMethod},${externalIdentityId}::uuid,
        1,1,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_policy_pins(
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES
        (${fixture.tenant}::uuid,${sourceSessionId}::uuid,
         ${platformFloorId}::uuid,1),
        (${fixture.tenant}::uuid,${sourceSessionId}::uuid,
         ${tenantBaselineId}::uuid,1)
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,level,kind,provider_id,binding_id,
        authenticated_at,trust_rule_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,'mfa','provider',
        ${providerId}::uuid,${bindingId}::uuid,${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,recovery_code_set_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,
        ${recoverySetId}::uuid,'mfa','recovery',${createdAt},1
      )
    `;
    await transaction.unsafe("SET LOCAL session_replication_role = origin");
    if (authenticationMethod === "oidc") {
      await transaction`
        INSERT INTO public.tenant_federated_authentication_transactions(
          transaction_id,tenant_id,provider_id,binding_id,provider_kind,
          protocol,operation_run_id,operation_digest,receipt_digest,
          network_digest,account_digest,provider_digest,state_digest,
          browser_digest,nonce_digest,provider_revision,binding_revision,
          configuration_revision,security_revision,plan_revision,
          mapping_revision,authorization_revision,assurance_policy_revision,
          client_secret_revision,discovery_revision,discovery_digest,
          jwks_revision,jwks_digest,verifier_key_version,verifier_ciphertext,
          client_id,redirect_uri,post_logout_redirect_uri,scopes,
          allow_refresh_token,use_user_info,return_path,state,version,
          created_at,expires_at
        ) VALUES (
          ${authenticationTransactionId}::bytea,${fixture.tenant}::uuid,
          ${providerId}::uuid,${bindingId}::uuid,'oidc','oidc',
          ${oidcMaterialId}::uuid,
          ${digest("oidc-recovery-operation")}::bytea,
          ${digest("oidc-recovery-receipt")}::bytea,
          ${digest("oidc-recovery-network")}::bytea,
          ${digest("oidc-recovery-account")}::bytea,
          ${digest("oidc-recovery-provider")}::bytea,
          ${digest("oidc-recovery-state")}::bytea,
          ${digest("oidc-recovery-browser")}::bytea,
          ${digest("oidc-recovery-nonce")}::bytea,
          1,1,1,1,1,1,
          (SELECT revision FROM public.tenant_authorization_states
           WHERE tenant_id=${fixture.tenant}::uuid),
          1,1,1,${digest("oidc-recovery-discovery")}::bytea,
          1,${digest("oidc-recovery-jwks")}::bytea,1,
          ${Buffer.alloc(32, 0xa1)}::bytea,
          'recovery-runtime-client',
          'https://app.example.invalid/api/v1/auth/federated/oidc/callback',
          'https://app.example.invalid/logout',
          ARRAY['openid','email']::text[],false,false,'/portal','pending',1,
          ${createdAt},${authenticationExpiresAt}
        )
      `;
      await transaction`
        UPDATE public.tenant_federated_authentication_transactions
        SET state='claimed',version=2,
          claim_attempt_id=${digest("oidc-recovery-claim-attempt")}::bytea,
          claimed_at=${createdAt}
        WHERE tenant_id=${fixture.tenant}::uuid
          AND transaction_id=${authenticationTransactionId}::bytea
      `;
      await transaction`
        UPDATE public.tenant_federated_authentication_transactions
        SET state='completed',version=3,completed_at=${createdAt}
        WHERE tenant_id=${fixture.tenant}::uuid
          AND transaction_id=${authenticationTransactionId}::bytea
      `;
      await transaction`
        INSERT INTO public.tenant_federated_authentication_applications(
          id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
          binding_id,provider_kind,category,primary_kind,user_id,session_id,
          request_snapshot,result_snapshot,applied_at
        ) VALUES (
          ${authenticationApplicationId}::uuid,${fixture.tenant}::uuid,'oidc',
          ${authenticationTransactionId}::bytea,
          ${digest("oidc-recovery-application")}::bytea,
          ${providerId}::uuid,${bindingId}::uuid,'oidc','success',
          'tenant_provider',${userId}::uuid,${sourceSessionId}::uuid,
          ${transaction.json({
            authentication: { validUntil: absoluteExpiresAt.toISOString() },
          })}::jsonb,
          ${transaction.json({ category: "success" })}::jsonb,${createdAt}
        )
      `;
      await transaction`
        INSERT INTO public.tenant_oidc_session_materials(
          id,tenant_id,authority,session_id,rotation_family_id,user_id,
          provider_id,binding_id,provider_kind,external_identity_id,
          aad_version,expires_at,client_id,post_logout_redirect_uri,
          logout_disposition,created_at,updated_at
        ) VALUES (
          ${oidcMaterialId}::uuid,${fixture.tenant}::uuid,'tenant_provider',
          ${sourceSessionId}::uuid,${familyId}::uuid,${userId}::uuid,
          ${providerId}::uuid,${bindingId}::uuid,'oidc',
          ${externalIdentityId}::uuid,1,${absoluteExpiresAt},
          'recovery-runtime-client','https://app.example.invalid/logout',
          'not_configured',${createdAt},${createdAt}
        )
      `;
    }
    if (authenticationMethod === "saml") {
      const sessionIndexDigest = digest("saml-recovery-session-index");
      await transaction`
        INSERT INTO public.tenant_federated_authentication_transactions(
          transaction_id,tenant_id,provider_id,binding_id,provider_kind,
          protocol,operation_run_id,operation_digest,receipt_digest,
          network_digest,account_digest,provider_digest,relay_state_digest,
          browser_digest,provider_revision,binding_revision,
          configuration_revision,security_revision,plan_revision,
          mapping_revision,authorization_revision,assurance_policy_revision,
          metadata_revision,metadata_digest,sp_key_revision,
          configuration_digest,request_id,return_path,state,version,
          created_at,expires_at
        ) VALUES (
          ${authenticationTransactionId}::bytea,${fixture.tenant}::uuid,
          ${providerId}::uuid,${bindingId}::uuid,'saml','saml',
          ${samlMaterialId}::uuid,
          ${digest("saml-recovery-operation")}::bytea,
          ${digest("saml-recovery-receipt")}::bytea,
          ${digest("saml-recovery-network")}::bytea,
          ${digest("saml-recovery-account")}::bytea,
          ${digest("saml-recovery-provider")}::bytea,
          ${digest("saml-recovery-relay-state")}::bytea,
          ${digest("saml-recovery-browser")}::bytea,
          1,1,1,1,1,1,
          (SELECT revision FROM public.tenant_authorization_states
           WHERE tenant_id=${fixture.tenant}::uuid),
          1,1,${digest("saml-recovery-metadata")}::bytea,1,
          ${digest("saml-recovery-configuration")}::bytea,
          ${`_recovery_${sequence}`},'/portal','pending',1,
          ${createdAt},${authenticationExpiresAt}
        )
      `;
      await transaction`
        INSERT INTO public.tenant_saml_session_materials(
          id,tenant_id,session_id,continuation_id,user_id,provider_id,
          binding_id,provider_kind,external_identity_id,
          session_index_digest,key_version,ciphertext,logout_configuration,
          created_at,aad_version
        ) VALUES (
          ${samlMaterialId}::uuid,${fixture.tenant}::uuid,
          ${sourceSessionId}::uuid,NULL,${userId}::uuid,${providerId}::uuid,
          ${bindingId}::uuid,'saml',${externalIdentityId}::uuid,
          ${sessionIndexDigest}::bytea,NULL,NULL,
          ${transaction.json({
            authentication: {
              provider: {
                scope: "tenant",
                tenantId: fixture.tenant,
                providerId,
                bindingId,
              },
              providerRevision: 1,
              bindingRevision: 1,
              configurationRevision: 1,
              securityRevision: 1,
              mappingRevision: 1,
              authorizationRevision: 1,
              assurancePolicyRevision: 1,
              spKeyRevision: 1,
            },
            expectedEntityId: "https://idp.example.invalid/metadata",
            metadataRevision: 1,
          })}::jsonb,${createdAt},2
        )
      `;
      await transaction`
        UPDATE public.tenant_federated_authentication_transactions
        SET state='completed',version=2,completed_at=${createdAt}
        WHERE tenant_id=${fixture.tenant}::uuid
          AND transaction_id=${authenticationTransactionId}::bytea
      `;
      await transaction`
        INSERT INTO public.tenant_federated_authentication_applications(
          id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
          binding_id,provider_kind,response_id_digest,assertion_id_digest,
          session_index_digest,category,primary_kind,user_id,session_id,
          request_snapshot,result_snapshot,applied_at
        ) VALUES (
          ${authenticationApplicationId}::uuid,${fixture.tenant}::uuid,'saml',
          ${authenticationTransactionId}::bytea,
          ${digest("saml-recovery-application")}::bytea,
          ${providerId}::uuid,${bindingId}::uuid,'saml',
          ${digest("saml-recovery-response")}::bytea,
          ${digest("saml-recovery-assertion")}::bytea,
          ${sessionIndexDigest}::bytea,'success','tenant_provider',
          ${userId}::uuid,${sourceSessionId}::uuid,
          ${transaction.json({
            authentication: { validUntil: absoluteExpiresAt.toISOString() },
          })}::jsonb,
          ${transaction.json({ category: "success" })}::jsonb,${createdAt}
        )
      `;
    }
  });

  const completedAt = new Date(createdAt.getTime() + 1_000);
  const authority = await resolveAuthority(
    sourceSessionId,
    "session",
    "mfa.recovery_codes.replace",
    completedAt,
  );
  assert.equal(stringField(authority, "primaryKind"), "tenant_provider");
  const requirement = jsonObject(
    jsonField(authority, "requirement"),
    `${authenticationMethod} recovery replacement requirement`,
  );
  const request = {
    newSetId: replacementSetId,
    digestKeyVersion: 1,
    expectedSetId: recoverySetId,
    expectedSetVersion: 1,
    binding: stepUpBinding(authority),
    digests: Array.from({ length: 8 }, (_, index) =>
      base64Digest(`${authenticationMethod}-replacement-code-${index}`),
    ),
    generatedAt: completedAt.toISOString(),
    audit: {
      kind: "mfa.recovery_codes_regenerated",
      tenantId: fixture.tenant,
      userId,
      action: jsonField(authority, "action"),
      occurredAt: completedAt.toISOString(),
      policyRevisions: jsonField(requirement, "policyRevisions"),
    },
    session: {
      mutation: "rotate",
      expectedSessionId: sourceSessionId,
      expectedFamilyId: familyId,
      expectedAnchorVersion: jsonField(authority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(authority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(authority, "anchorExpiresAt"),
      audience: jsonField(authority, "audience"),
      requirement: jsonField(authority, "requirement"),
      recoveryRestricted: true,
      reservation: {
        sessionId: successorSessionId,
        familyId,
        tokenDigest: base64Digest(`${authenticationMethod}-successor-token`),
        csrfDigest: base64Digest(`${authenticationMethod}-successor-csrf`),
        authenticationMethod: "recovery_code",
        idleExpiresAt: idleExpiresAt.toISOString(),
        absoluteExpiresAt: absoluteExpiresAt.toISOString(),
      },
    },
  };
  const [completion] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(request)}::jsonb
        ) AS result
      `,
    ),
  );
  const result = jsonObject(
    completion?.result,
    `${authenticationMethod} recovery replacement`,
  );
  assert.equal(stringField(result, "newSessionId"), successorSessionId);
  const [replay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(request)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(replay?.result, completion?.result);
  const [state] = await sql<
    {
      source_reason: string;
      successor_method: string;
      provider_evidence: number;
      recovery_evidence: number;
      federated_provenance: number;
      ldap_provenance: number;
      capability_count: number;
      new_code_count: number;
      authentication_transaction_count: number;
      authentication_application_count: number;
      oidc_material_count: number;
      saml_material_count: number;
      saml_logout_configuration_count: number;
    }[]
  >`
    SELECT source.revoke_reason AS source_reason,
      successor.authentication_method AS successor_method,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid AND kind='provider')
        AS provider_evidence,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid AND kind='recovery')
        AS recovery_evidence,
      (SELECT count(*)::integer
       FROM public.auth_session_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid
         AND authentication_method=${authenticationMethod})
        AS federated_provenance,
      (SELECT count(*)::integer FROM public.auth_session_ldap_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid) AS ldap_provenance,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count,
      (SELECT count(*)::integer FROM public.tenant_recovery_codes
       WHERE tenant_id=${fixture.tenant}::uuid
         AND set_id=${replacementSetId}::uuid) AS new_code_count,
      (SELECT count(*)::integer
       FROM public.tenant_federated_authentication_transactions
       WHERE tenant_id=${fixture.tenant}::uuid
         AND transaction_id=${authenticationTransactionId}::bytea
         AND operation_run_id=${
           authenticationMethod === "oidc" ? oidcMaterialId : samlMaterialId
         }::uuid
         AND protocol=${authenticationMethod} AND state='completed')
        AS authentication_transaction_count,
      (SELECT count(*)::integer
       FROM public.tenant_federated_authentication_applications
       WHERE id=${authenticationApplicationId}::uuid
         AND tenant_id=${fixture.tenant}::uuid
         AND transaction_id=${authenticationTransactionId}::bytea
         AND protocol=${authenticationMethod} AND category='success'
         AND user_id=${userId}::uuid AND session_id=${sourceSessionId}::uuid)
        AS authentication_application_count,
      (SELECT count(*)::integer FROM public.tenant_oidc_session_materials
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid) AS oidc_material_count,
      (SELECT count(*)::integer FROM public.tenant_saml_session_materials
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid) AS saml_material_count,
      (SELECT count(*)::integer FROM public.tenant_saml_session_materials
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid
         AND logout_configuration #>> '{authentication,provider,scope}' = 'tenant'
         AND logout_configuration #>> '{authentication,provider,tenantId}' =
           ${fixture.tenant}
         AND logout_configuration #>> '{authentication,provider,providerId}' =
           ${providerId}
         AND logout_configuration #>> '{authentication,provider,bindingId}' =
           ${bindingId}) AS saml_logout_configuration_count
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${successorSessionId}::uuid
    WHERE source.id=${sourceSessionId}::uuid
  `;
  assert.deepEqual(state, {
    source_reason: "mfa_session_rotated",
    successor_method: authenticationMethod,
    provider_evidence: 1,
    recovery_evidence: 0,
    federated_provenance: 1,
    ldap_provenance: 0,
    capability_count: 0,
    new_code_count: 8,
    authentication_transaction_count: 1,
    authentication_application_count: 1,
    oidc_material_count: authenticationMethod === "oidc" ? 1 : 0,
    saml_material_count: authenticationMethod === "saml" ? 1 : 0,
    saml_logout_configuration_count: authenticationMethod === "saml" ? 1 : 0,
  });
}

async function exercisePasskeyRecoveryReplacement(
  platformFloorId: string,
  tenantBaselineId: string,
  tenantBaselineRevision: number,
): Promise<void> {
  const userId = uuid(2990);
  const membershipId = uuid(2991);
  const credentialId = uuid(2992);
  const familyId = uuid(3000);
  const sourceSessionId = uuid(3001);
  const recoverySetId = uuid(3002);
  const recoveryCodeId = uuid(3003);
  const successorSessionId = uuid(3004);
  const replacementSetId = uuid(3005);
  const createdAt = new Date();
  const completedAt = new Date(createdAt.getTime() + 1_000);
  const idleExpiresAt = new Date(createdAt.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(createdAt.getTime() + 2 * 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.users(
        id,email,display_name,active,created_at,updated_at
      ) VALUES (
        ${userId}::uuid,'passkey-replacement@example.invalid',
        'Passkey recovery replacement',true,${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status,created_at,updated_at
      ) VALUES (
        ${membershipId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        'analyst','active',${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects(
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${userId}::uuid,
        ${digest("passkey-replacement-user-handle")}::bytea,1,1,1,
        ${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credentials(
        id,tenant_id,user_id,credential_id,public_key,display_name,
        user_handle_digest,rp_id,rp_revision,sign_count,discoverable,
        user_verification,backup_eligible,backed_up,aaguid,
        attestation_format,attestation_type,attestation_trusted,
        metadata_revision,status,version,security_revision,created_at,
        last_used_at,updated_at
      ) VALUES (
        ${credentialId}::uuid,${fixture.tenant}::uuid,${userId}::uuid,
        ${digest("passkey-replacement-credential-wire")}::bytea,
        ${Buffer.alloc(64, 0x87)}::bytea,'Passkey replacement credential',
        ${digest("passkey-replacement-user-handle-digest")}::bytea,
        'example.invalid',1,7,true,true,false,false,${Buffer.alloc(16)}::bytea,
        'none','none',false,0,'active',3,1,${createdAt},${createdAt},
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credential_transports(
        tenant_id,credential_id,transport
      ) VALUES (${fixture.tenant}::uuid,${credentialId}::uuid,'internal')
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_code_sets(
        id,tenant_id,user_id,digest_key_version,record_version,
        security_revision,completion_request_digest,result_snapshot,status,
        generated_at,updated_at
      ) VALUES (
        ${recoverySetId}::uuid,${fixture.tenant}::uuid,
        ${userId}::uuid,1,1,1,
        ${digest("passkey-recovery-set")}::bytea,'{}'::jsonb,'active',
        ${createdAt},${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_codes(
        id,tenant_id,set_id,code_digest,created_at
      ) VALUES (
        ${recoveryCodeId}::uuid,${fixture.tenant}::uuid,
        ${recoverySetId}::uuid,${digest("passkey-recovery-code")}::bytea,
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions(
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      ) VALUES (
        ${sourceSessionId}::uuid,${userId}::uuid,${familyId}::uuid,
        ${fixture.tenant}::uuid,${digest("passkey-replacement-source-token")}::bytea,
        ${digest("passkey-replacement-source-csrf")}::bytea,'passkey',
        ${createdAt},${createdAt},${idleExpiresAt},${absoluteExpiresAt},
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states(
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,
        session_invalidation_epoch,issued_at
      ) VALUES (
        ${sourceSessionId}::uuid,${fixture.tenant}::uuid,
        ${userId}::uuid,1,1,true,'api','passkey',1,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_passkey_provenance(
        tenant_id,session_id,user_id,primary_kind,credential_id,
        credential_revision,authenticated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,
        ${userId}::uuid,'passkey',${credentialId}::uuid,1,
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,webauthn_credential_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,
        ${credentialId}::uuid,'primary','webauthn',${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,recovery_code_set_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${sourceSessionId}::uuid,
        ${recoverySetId}::uuid,'mfa','recovery',${createdAt},1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_policy_pins(
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES
        (${fixture.tenant}::uuid,${sourceSessionId}::uuid,
         ${platformFloorId}::uuid,1),
        (${fixture.tenant}::uuid,${sourceSessionId}::uuid,
         ${tenantBaselineId}::uuid,${tenantBaselineRevision})
    `;
  });

  const authority = await resolveAuthority(
    sourceSessionId,
    "session",
    "mfa.recovery_codes.replace",
    completedAt,
  );
  assert.equal(stringField(authority, "primaryKind"), "passkey");
  const requirement = jsonObject(
    jsonField(authority, "requirement"),
    "passkey recovery replacement requirement",
  );
  const request = {
    newSetId: replacementSetId,
    digestKeyVersion: 1,
    expectedSetId: recoverySetId,
    expectedSetVersion: 1,
    binding: stepUpBinding(authority),
    digests: Array.from({ length: 8 }, (_, index) =>
      base64Digest(`passkey-replacement-code-${index}`),
    ),
    generatedAt: completedAt.toISOString(),
    audit: {
      kind: "mfa.recovery_codes_regenerated",
      tenantId: fixture.tenant,
      userId,
      action: jsonField(authority, "action"),
      occurredAt: completedAt.toISOString(),
      policyRevisions: jsonField(requirement, "policyRevisions"),
    },
    session: {
      mutation: "rotate",
      expectedSessionId: sourceSessionId,
      expectedFamilyId: familyId,
      expectedAnchorVersion: jsonField(authority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(authority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(authority, "anchorExpiresAt"),
      audience: jsonField(authority, "audience"),
      requirement: jsonField(authority, "requirement"),
      recoveryRestricted: true,
      reservation: {
        sessionId: successorSessionId,
        familyId,
        tokenDigest: base64Digest("passkey-replacement-successor-token"),
        csrfDigest: base64Digest("passkey-replacement-successor-csrf"),
        authenticationMethod: "passkey",
        idleExpiresAt: idleExpiresAt.toISOString(),
        absoluteExpiresAt: absoluteExpiresAt.toISOString(),
      },
    },
  };
  const [completion] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(request)}::jsonb
        ) AS result
      `,
    ),
  );
  const result = jsonObject(completion?.result, "passkey recovery replacement");
  assert.equal(stringField(result, "newSessionId"), successorSessionId);
  const [replay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(request)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(replay?.result, completion?.result);
  const [state] = await sql<
    {
      source_reason: string;
      successor_method: string;
      passkey_provenance: number;
      passkey_evidence: number;
      recovery_evidence: number;
      capability_count: number;
      new_code_count: number;
    }[]
  >`
    SELECT source.revoke_reason AS source_reason,
      successor.authentication_method AS successor_method,
      (SELECT count(*)::integer FROM public.auth_session_passkey_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid) AS passkey_provenance,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid AND kind='webauthn')
        AS passkey_evidence,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${successorSessionId}::uuid AND kind='recovery')
        AS recovery_evidence,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count,
      (SELECT count(*)::integer FROM public.tenant_recovery_codes
       WHERE tenant_id=${fixture.tenant}::uuid
         AND set_id=${replacementSetId}::uuid) AS new_code_count
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${successorSessionId}::uuid
    WHERE source.id=${sourceSessionId}::uuid
  `;
  assert.deepEqual(state, {
    source_reason: "mfa_session_rotated",
    successor_method: "passkey",
    passkey_provenance: 1,
    passkey_evidence: 1,
    recovery_evidence: 0,
    capability_count: 0,
    new_code_count: 8,
  });
}

type SyncClaim = {
  claim_id: string;
  claim_fence: string;
  run_version: number;
};

type SyncPlanning = {
  provider_version: number;
  configuration_revision: number;
  binding_id: string;
  binding_version: number;
  binding_auth_revision: number;
  binding_access_epoch_id: string;
  rule_set_revision: string;
  authorization_revision: string;
  external_identity_id: string;
  user_id: string;
  membership_id: string;
  access_grant_id: string;
  live_owned_edges: JsonObject[];
  rules: JsonObject[];
};

type PreparedSync = {
  sequence: number;
  runId: string;
  observationId: string;
  claim: SyncClaim;
  receipt: Buffer;
  observationDigest: Buffer;
  observedAt: Date;
  planning: SyncPlanning;
};

type EnumerationResult = {
  status: string;
  version: number;
};

async function asWorker<T>(
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  contextTenant: string = fixture.tenant,
): Promise<T> {
  return asRole("periapsis_worker", async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${contextTenant},true),
             set_config('app.user_id','',true)
    `;
    return operation(transaction);
  });
}

async function configureSync(
  mode: "retain" | "grace" | "immediate",
  graceSeconds = 0,
): Promise<string> {
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_ldap_provider_configs
      SET deprovision_mode=${mode}::public.identity_deprovision_mode,
          deprovision_grace_seconds=${graceSeconds},
          sync_interval_seconds=300,version=version+1,
          updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND provider_id=${fixture.provider}::uuid
    `;
  });
  const [binding] = await sql<{ id: string }[]>`
    SELECT id FROM public.tenant_auth_provider_bindings
    WHERE tenant_id=${fixture.tenant}::uuid
      AND provider_id=${fixture.provider}::uuid
  `;
  assert(binding);
  return binding.id;
}

async function invokeEnumerationCompletion(
  transaction: postgres.TransactionSql,
  prepared: Pick<PreparedSync, "sequence" | "runId" | "claim" | "receipt">,
): Promise<EnumerationResult> {
  const [result] = await transaction<EnumerationResult[]>`
    SELECT status,version
    FROM app.complete_tenant_ldap_sync_enumeration_v3(
      ${prepared.runId}::uuid,${prepared.claim.claim_id}::uuid,
      ${prepared.receipt},${prepared.claim.claim_fence}::bigint,
      ${prepared.claim.run_version},true,false,NULL,NULL,
      ${uuid(prepared.sequence + 6)}::uuid,
      ${uuid(prepared.sequence + 7)}::uuid,
      ${uuid(prepared.sequence + 8)}::uuid,
      'LDAP denied reconciliation runtime'
    )
  `;
  assert(result, "LDAP sync enumeration completion returned no result");
  return result;
}

async function prepareObservedSync(
  bindingId: string,
  sequence: number,
  completeEnumeration = true,
): Promise<PreparedSync> {
  const runId = uuid(sequence);
  const claimId = uuid(sequence + 1);
  const observationId = uuid(sequence + 2);
  const receipt = digest(`sync-claim-${sequence}`);
  const observationDigest = digest(`sync-observation-${sequence}`);
  const subjectDigest = Buffer.alloc(32, 0xee);
  await asWorker(
    (transaction) =>
      transaction`
      SELECT * FROM app.begin_tenant_ldap_scheduled_sync_run_v1(
        ${runId}::uuid,${bindingId}::uuid,'scheduled_sync',
        ${uuid(sequence + 3)}::uuid,${uuid(sequence + 4)}::uuid,
        ${uuid(sequence + 5)}::uuid,'LDAP denied reconciliation runtime'
      )
    `,
  );
  const [claim] = await asWorker<SyncClaim[]>(
    async (transaction) =>
      Array.from(
        await transaction<SyncClaim[]>`
        SELECT claim_id,claim_fence::text,run_version
        FROM app.claim_next_tenant_ldap_sync_run_v2(
          ${claimId}::uuid,${receipt},60,
          'LDAP denied reconciliation runtime'
        )
      `,
      ),
    "00000000-0000-0000-0000-000000000001",
  );
  assert(claim);
  const [staged] = await asWorker(
    (transaction) =>
      transaction<{ external_identity_id: string | null }[]>`
      SELECT app.stage_tenant_ldap_sync_observation_v2(
        ${runId}::uuid,${claim.claim_id}::uuid,${receipt},
        ${claim.claim_fence}::bigint,${observationId}::uuid,1,2,
        ${subjectDigest},${observationDigest}
      ) AS external_identity_id
    `,
  );
  assert.equal(staged?.external_identity_id, fixture.externalIdentity);
  const [planning] = await asWorker<SyncPlanning[]>(
    async (transaction) =>
      Array.from(
        await transaction<SyncPlanning[]>`
        SELECT * FROM app.claim_tenant_ldap_sync_observation_planning_v3(
          ${runId}::uuid,${observationId}::uuid,${claim.claim_id}::uuid,
          ${receipt},${claim.claim_fence}::bigint,ARRAY[2]::integer[],
          ARRAY[${subjectDigest}::bytea]::bytea[]
        )
      `,
      ),
    "00000000-0000-0000-0000-000000000001",
  );
  assert(planning);
  const prepared = {
    sequence,
    runId,
    observationId,
    claim,
    receipt,
    observationDigest,
    observedAt: new Date(),
    planning,
  };
  if (completeEnumeration) {
    const enumeration = await asWorker((transaction) =>
      invokeEnumerationCompletion(transaction, prepared),
    );
    assert.deepEqual(enumeration, { status: "applying", version: 3 });
  }
  return prepared;
}

function revocationEpochIDs(planning: SyncPlanning): string[] {
  return [
    ...new Set(
      planning.live_owned_edges.flatMap((edge) => {
        const kind = edge.kind;
        const epoch = edge.ruleEpochId;
        return (kind === "security_group_membership" ||
          kind === "operator_team_roster") &&
          typeof epoch === "string"
          ? [epoch]
          : [];
      }),
    ),
  ].toSorted();
}

async function applyDeniedSync(
  prepared: PreparedSync,
): Promise<{ result: JsonObject; applicationId: string }> {
  const applicationId = uuid(prepared.sequence + 10);
  const apply = async (): Promise<JsonObject> => {
    return asWorker((transaction) =>
      invokeDeniedSync(transaction, prepared, applicationId),
    );
  };
  const first = await apply();
  assert.equal(jsonField(first, "decision"), "denied");
  assert.equal(jsonField(first, "replayed"), false);
  const replay = await apply();
  assert.equal(jsonField(replay, "replayed"), true);
  assert.equal(
    jsonField(replay, "revoked_edge_count"),
    jsonField(first, "revoked_edge_count"),
  );
  return { result: first, applicationId };
}

async function invokeDeniedSync(
  transaction: postgres.TransactionSql,
  prepared: PreparedSync,
  applicationId: string,
): Promise<JsonObject> {
  const { planning } = prepared;
  const epochs = revocationEpochIDs(planning);
  const [row] = await transaction<{ value: postgres.JSONValue }[]>`
    SELECT to_jsonb(result) AS value
    FROM app.apply_tenant_ldap_sync_identity_plan_v3(
      ${prepared.runId}::uuid,${prepared.observationId}::uuid,
      ${prepared.claim.claim_id}::uuid,${prepared.receipt},
      ${prepared.claim.claim_fence}::bigint,${applicationId}::uuid,
      ${prepared.observationDigest},${planning.binding_id}::uuid,
      ${planning.provider_version},${planning.configuration_revision},
      ${planning.binding_version},${planning.binding_auth_revision},
      ${planning.binding_access_epoch_id}::uuid,
      ${planning.rule_set_revision}::bigint,
      ${planning.authorization_revision}::bigint,
      'denied'::public.ldap_identity_apply_decision,'no_mapping',
      ${planning.external_identity_id}::uuid,${planning.user_id}::uuid,
      ${planning.membership_id}::uuid,${planning.access_grant_id}::uuid,
      ${epochs}::uuid[],NULL,NULL,NULL,NULL,NULL,
      NULL,NULL,NULL,NULL,ARRAY[]::uuid[],ARRAY[]::integer[],
      ARRAY[]::bytea[],NULL,NULL,NULL,NULL,NULL,ARRAY[]::uuid[],
      ${prepared.observedAt},${uuid(prepared.sequence + 11)}::uuid,
      ${uuid(prepared.sequence + 12)}::uuid,
      ${uuid(prepared.sequence + 13)}::uuid,NULL::inet,
      'LDAP denied reconciliation runtime'
    ) AS result
  `;
  return jsonObject(row?.value, "denied LDAP sync result");
}

type SubjectAliasPin = {
  digest_key_version: number;
  subject_digest: Buffer;
};

async function loadSubjectAliasPin(): Promise<SubjectAliasPin> {
  const [alias] = await sql<
    { digest_key_version: number; subject_digest: Buffer }[]
  >`
    SELECT digest_key_version,subject_digest
    FROM public.tenant_ldap_external_identity_subject_aliases
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.subjectAlias}::uuid AND retired_at IS NULL
  `;
  assert(alias);
  return alias;
}

async function invokeAdmittedSync(
  transaction: postgres.TransactionSql,
  prepared: PreparedSync,
  alias: SubjectAliasPin,
): Promise<JsonObject> {
  const { planning } = prepared;
  const matchedEpochs = planning.rules.flatMap((rule) =>
    typeof rule.ruleEpochId === "string" ? [rule.ruleEpochId] : [],
  );
  assert.equal(matchedEpochs.length, 1);
  const [row] = await transaction<{ value: postgres.JSONValue }[]>`
    SELECT to_jsonb(result) AS value
    FROM app.apply_tenant_ldap_sync_identity_plan_v3(
      ${prepared.runId}::uuid,${prepared.observationId}::uuid,
      ${prepared.claim.claim_id}::uuid,${prepared.receipt},
      ${prepared.claim.claim_fence}::bigint,
      ${uuid(prepared.sequence + 10)}::uuid,${prepared.observationDigest},
      ${planning.binding_id}::uuid,${planning.provider_version},
      ${planning.configuration_revision},${planning.binding_version},
      ${planning.binding_auth_revision},
      ${planning.binding_access_epoch_id}::uuid,
      ${planning.rule_set_revision}::bigint,
      ${planning.authorization_revision}::bigint,
      'admitted'::public.ldap_identity_apply_decision,NULL,
      NULL,NULL,NULL,NULL,ARRAY[]::uuid[],
      ${planning.external_identity_id}::uuid,${planning.user_id}::uuid,
      ${planning.membership_id}::uuid,${planning.access_grant_id}::uuid,
      ${uuid(prepared.sequence + 11)}::uuid,'ad_object_guid',
      ${Buffer.alloc(17, prepared.sequence % 251)},
      ${Buffer.alloc(12, (prepared.sequence + 1) % 251)},2,
      ARRAY[${fixture.subjectAlias}::uuid]::uuid[],
      ARRAY[${alias.digest_key_version}]::integer[],
      ARRAY[${alias.subject_digest}::bytea]::bytea[],
      'Directory target','Directory','Target','directory.target',
      'directory.target@example.invalid',${matchedEpochs}::uuid[],
      ${prepared.observedAt},${uuid(prepared.sequence + 12)}::uuid,
      ${uuid(prepared.sequence + 13)}::uuid,
      ${uuid(prepared.sequence + 14)}::uuid,NULL::inet,
      'LDAP admitted reconciliation runtime'
    ) AS result
  `;
  const result = jsonObject(row?.value, "admitted LDAP sync result");
  assert.equal(jsonField(result, "decision"), "admitted");
  return result;
}

async function applyAdmittedSync(prepared: PreparedSync): Promise<JsonObject> {
  const alias = await loadSubjectAliasPin();
  return asWorker((transaction) =>
    invokeAdmittedSync(transaction, prepared, alias),
  );
}

async function waitForBlockedBackend(
  blockedPid: number,
  blockerPid: number,
  attempts = 100,
): Promise<void> {
  const [state] = await sql<{ blocked: boolean }[]>`
    SELECT ${blockerPid}::integer = ANY(
      pg_catalog.pg_blocking_pids(${blockedPid}::integer)
    ) AS blocked
  `;
  if (state?.blocked) return;
  if (attempts <= 1) {
    throw new Error(`backend ${blockedPid} did not block behind ${blockerPid}`);
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
  return waitForBlockedBackend(blockedPid, blockerPid, attempts - 1);
}

async function raceEnumerationReplayWithAdmitted(
  prepared: PreparedSync,
): Promise<void> {
  const replayConnection = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  let replayPromise: Promise<EnumerationResult> | undefined;
  try {
    const alias = await loadSubjectAliasPin();
    await sql.begin(async (winner) => {
      // The migration owner is used only to hold the exact internal run-row
      // lock that a definer completion acquires; the contending caller still
      // executes through the public worker ABI.
      await winner.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await winner.unsafe("SET LOCAL statement_timeout = '15s'");
      await winner`
        SELECT set_config('app.tenant_id',${fixture.tenant},true),
               set_config('app.user_id','',true)
      `;
      const [blocker] = await winner<{ pid: number }[]>`
        SELECT pg_catalog.pg_backend_pid() AS pid
      `;
      assert(blocker);
      await winner`
        SELECT 1 FROM public.tenant_ldap_sync_runs
        WHERE tenant_id=${fixture.tenant}::uuid
          AND id=${prepared.runId}::uuid
        FOR UPDATE
      `;

      let publishReplayPid: ((pid: number) => void) | undefined;
      const replayPid = new Promise<number>((resolve) => {
        publishReplayPid = resolve;
      });
      replayPromise = replayConnection.begin(async (replay) => {
        await replay.unsafe('SET LOCAL ROLE "periapsis_worker"');
        await replay.unsafe("SET LOCAL statement_timeout = '15s'");
        await replay`
          SELECT set_config('app.tenant_id',${fixture.tenant},true),
                 set_config('app.user_id','',true)
        `;
        const [backend] = await replay<{ pid: number }[]>`
          SELECT pg_catalog.pg_backend_pid() AS pid
        `;
        assert(backend);
        assert(publishReplayPid);
        publishReplayPid(backend.pid);
        return invokeEnumerationCompletion(replay, prepared);
      });
      await waitForBlockedBackend(await replayPid, blocker.pid);

      const completion = await invokeEnumerationCompletion(winner, prepared);
      assert.deepEqual(completion, { status: "applying", version: 3 });
      await invokeAdmittedSync(winner, prepared, alias);
    });
    assert(replayPromise, "enumeration replay was not dispatched");
    assert.deepEqual(await replayPromise, { status: "applying", version: 3 });
  } finally {
    await replayConnection.end();
  }
}

async function assertDeniedFenceRejects(
  prepared: PreparedSync,
  contenders: {
    expectBlocked: boolean;
    invoke: (transaction: postgres.TransactionSql) => Promise<unknown>;
  }[],
): Promise<void> {
  const blocker = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
  const contenderConnections = contenders.map(() =>
    postgres(databaseUrl, { max: 1, onnotice: () => undefined }),
  );
  type ContenderOutcome =
    { ok: true; value: unknown } | { ok: false; error: unknown };
  const assertSerializationFailure = (outcome: ContenderOutcome): void => {
    assert.equal(outcome.ok, false, "LDAP authority contender must fail");
    if (!outcome.ok) assertSqlState(outcome.error, "40001");
  };
  let blockedPromises: Promise<ContenderOutcome>[] = [];
  try {
    await blocker.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      await transaction`
        SELECT set_config('app.tenant_id',${fixture.tenant},true),
               set_config('app.user_id','',true)
      `;
      const [blockerBackend] = await transaction<{ pid: number }[]>`
        SELECT pg_catalog.pg_backend_pid() AS pid
      `;
      assert(blockerBackend);
      const result = await invokeDeniedSync(
        transaction,
        prepared,
        uuid(prepared.sequence + 10),
      );
      assert.equal(jsonField(result, "decision"), "denied");

      const attempts = contenders.map((contender, index) => {
        let publishPid: ((pid: number) => void) | undefined;
        const pid = new Promise<number>((resolve) => {
          publishPid = resolve;
        });
        const connection = contenderConnections[index];
        assert(connection);
        const attempt: Promise<ContenderOutcome> = connection
          .begin(async (candidate) => {
            await candidate.unsafe('SET LOCAL ROLE "periapsis_api"');
            await candidate.unsafe("SET LOCAL statement_timeout = '15s'");
            const [backend] = await candidate<{ pid: number }[]>`
              SELECT pg_catalog.pg_backend_pid() AS pid
            `;
            assert(backend);
            assert(publishPid);
            publishPid(backend.pid);
            return contender.invoke(candidate);
          })
          .then(
            (value): ContenderOutcome => ({ ok: true, value }),
            (error: unknown): ContenderOutcome => ({ ok: false, error }),
          );
        return { ...contender, pid, attempt };
      });
      const blockedAttempts = attempts.filter(
        (contender) => contender.expectBlocked,
      );
      const immediateAttempts = attempts.filter(
        (contender) => !contender.expectBlocked,
      );
      const backendPids = await Promise.all(
        blockedAttempts.map((contender) => contender.pid),
      );
      await Promise.all(
        backendPids.map((pid) =>
          waitForBlockedBackend(pid, blockerBackend.pid),
        ),
      );
      await Promise.all(
        immediateAttempts.map(async (contender) =>
          assertSerializationFailure(await contender.attempt),
        ),
      );
      blockedPromises = blockedAttempts.map((contender) => contender.attempt);
    });
    await Promise.all(
      blockedPromises.map(async (contender) =>
        assertSerializationFailure(await contender),
      ),
    );
  } finally {
    await Promise.all(
      contenderConnections.map((connection) => connection.end()),
    );
    await blocker.end();
  }
}

async function assertGlobalAuthorityFenceRejects(
  mutate: (transaction: postgres.TransactionSql) => Promise<unknown>,
  contender: (transaction: postgres.TransactionSql) => Promise<unknown>,
): Promise<void> {
  const blocker = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
  const candidate = postgres(databaseUrl, {
    max: 1,
    onnotice: () => undefined,
  });
  try {
    await blocker.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
      await mutate(transaction);
      const outcome = await candidate
        .begin(async (connection) => {
          await connection.unsafe('SET LOCAL ROLE "periapsis_api"');
          await connection.unsafe("SET LOCAL statement_timeout = '15s'");
          return contender(connection);
        })
        .then(
          (value) => ({ ok: true as const, value }),
          (error: unknown) => ({ ok: false as const, error }),
        );
      assert.equal(outcome.ok, false, "global authority race must fail closed");
      if (!outcome.ok) assertSqlState(outcome.error, "40001");
    });
  } finally {
    await candidate.end();
    await blocker.end();
  }
}

async function completePreparedSync(
  prepared: Pick<PreparedSync, "sequence" | "runId" | "claim" | "receipt">,
): Promise<void> {
  const [version] = await asWorker(
    (transaction) =>
      transaction<{ value: number }[]>`
      SELECT app.complete_tenant_ldap_sync_run_v2(
        ${prepared.runId}::uuid,${prepared.claim.claim_id}::uuid,
        ${prepared.receipt},${prepared.claim.claim_fence}::bigint,3,
        ${uuid(prepared.sequence + 20)}::uuid,
        ${uuid(prepared.sequence + 21)}::uuid,
        ${uuid(prepared.sequence + 22)}::uuid,
        'LDAP denied reconciliation runtime'
      ) AS value
    `,
  );
  assert.equal(version?.value, 4);
}

async function prepareEmptySync(
  bindingId: string,
  sequence: number,
): Promise<Omit<PreparedSync, "observationId" | "planning">> {
  const runId = uuid(sequence);
  const claimId = uuid(sequence + 1);
  const receipt = digest(`empty-sync-claim-${sequence}`);
  await asWorker(
    (transaction) =>
      transaction`
      SELECT * FROM app.begin_tenant_ldap_scheduled_sync_run_v1(
        ${runId}::uuid,${bindingId}::uuid,'scheduled_sync',
        ${uuid(sequence + 3)}::uuid,${uuid(sequence + 4)}::uuid,
        ${uuid(sequence + 5)}::uuid,'LDAP absence reconciliation runtime'
      )
    `,
  );
  const [claim] = await asWorker(
    (transaction) =>
      transaction<SyncClaim[]>`
      SELECT claim_id,claim_fence::text,run_version
      FROM app.claim_next_tenant_ldap_sync_run_v2(
        ${claimId}::uuid,${receipt},60,'LDAP absence reconciliation runtime'
      )
    `,
  );
  assert(claim);
  const [enumeration] = await asWorker(
    (transaction) =>
      transaction<{ status: string; version: number }[]>`
      SELECT status,version
      FROM app.complete_tenant_ldap_sync_enumeration_v3(
        ${runId}::uuid,${claim.claim_id}::uuid,${receipt},
        ${claim.claim_fence}::bigint,${claim.run_version},true,false,NULL,NULL,
        ${uuid(sequence + 6)}::uuid,${uuid(sequence + 7)}::uuid,
        ${uuid(sequence + 8)}::uuid,'LDAP absence reconciliation runtime'
      )
    `,
  );
  assert.deepEqual(enumeration, { status: "applying", version: 3 });
  return {
    sequence,
    runId,
    claim,
    receipt,
    observationDigest: digest(`empty-sync-${sequence}`),
    observedAt: new Date(),
  };
}

type AbsenceChunkResult = {
  inspected_count: number;
  revoked_count: number;
  remaining_count: number;
};

async function applyAbsenceChunk(
  prepared: Omit<PreparedSync, "observationId" | "planning">,
): Promise<AbsenceChunkResult> {
  const apply = async (): Promise<AbsenceChunkResult> => {
    const [result] = await asWorker(
      (transaction) =>
        transaction<AbsenceChunkResult[]>`
        SELECT * FROM app.apply_tenant_ldap_sync_absence_chunk_v3(
          ${prepared.runId}::uuid,${prepared.claim.claim_id}::uuid,
          ${prepared.receipt},${prepared.claim.claim_fence}::bigint,100,
          ${uuid(prepared.sequence + 10)}::uuid,
          ${uuid(prepared.sequence + 11)}::uuid,
          ${uuid(prepared.sequence + 12)}::uuid,
          'LDAP absence reconciliation runtime'
        )
      `,
    );
    assert(result, "LDAP absence chunk returned no result");
    return result;
  };
  const first = await apply();
  const replay = await apply();
  assert.deepEqual(replay, first);
  return first;
}

async function assertAbsenceAuthorityRevoked(input: {
  bindingId: string;
  accessGrantId: string;
  secondaryAccessGrantId: string;
  sourceSessionId: string;
  continuationId: string;
  priorSubjectEpoch: number;
}): Promise<void> {
  const [state] = await sql<
    {
      ldap_access_live: boolean;
      federated_access_live: boolean;
      membership_status: string;
      source_session_reason: string;
      continuation_state: string;
      continuation_reason: string;
      session_invalidation_epoch: number;
      live_ldap_sessions: number;
      live_ldap_continuations: number;
      absence_status: string;
    }[]
  >`
    SELECT ldap_access.ended_at IS NULL AS ldap_access_live,
      federated_access.ended_at IS NULL AS federated_access_live,
      membership.status AS membership_status,
      source_session.revoke_reason AS source_session_reason,
      continuation.state AS continuation_state,
      continuation.revoke_reason AS continuation_reason,
      subject.session_invalidation_epoch::integer,
      absence.status AS absence_status,
      (SELECT count(*)::integer FROM public.auth_sessions AS live_session
       WHERE live_session.user_id=${fixture.targetUser}::uuid
         AND live_session.revoked_at IS NULL
         AND live_session.rotation_family_id IN (
           SELECT root.rotation_family_id
           FROM public.auth_session_ldap_provenance AS provenance
           JOIN public.auth_sessions AS root ON root.id=provenance.session_id
           WHERE provenance.tenant_id=${fixture.tenant}::uuid
             AND provenance.provider_id=${fixture.provider}::uuid
             AND provenance.binding_id=${input.bindingId}::uuid
             AND provenance.external_identity_id=${fixture.externalIdentity}::uuid
         )) AS live_ldap_sessions,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations AS live_continuation
       WHERE live_continuation.tenant_id=${fixture.tenant}::uuid
         AND live_continuation.user_id=${fixture.targetUser}::uuid
         AND live_continuation.state='pending'
         AND EXISTS (
           SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
           WHERE provenance.tenant_id=live_continuation.tenant_id
             AND provenance.continuation_id=live_continuation.id
             AND provenance.provider_id=${fixture.provider}::uuid
             AND provenance.binding_id=${input.bindingId}::uuid
             AND provenance.external_identity_id=${fixture.externalIdentity}::uuid
         )) AS live_ldap_continuations
    FROM public.tenant_ldap_provider_access_grants AS ldap_access
    JOIN public.tenant_federated_provider_access_grants AS federated_access
      ON federated_access.id=${input.secondaryAccessGrantId}::uuid
    JOIN public.tenant_memberships AS membership
      ON membership.id=ldap_access.membership_id
     AND membership.tenant_id=ldap_access.tenant_id
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id=ldap_access.tenant_id
     AND subject.user_id=ldap_access.user_id
    JOIN public.auth_sessions AS source_session
      ON source_session.id=${input.sourceSessionId}::uuid
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.id=${input.continuationId}::uuid
     AND continuation.tenant_id=ldap_access.tenant_id
    JOIN public.tenant_ldap_sync_absences AS absence
      ON absence.tenant_id=ldap_access.tenant_id
     AND absence.binding_id=ldap_access.binding_id
     AND absence.external_identity_id=ldap_access.external_identity_id
    WHERE ldap_access.tenant_id=${fixture.tenant}::uuid
      AND ldap_access.id=${input.accessGrantId}::uuid
  `;
  assert(state, "LDAP absence did not preserve its terminal authority rows");
  assert.deepEqual(
    {
      ldap_access_live: state.ldap_access_live,
      federated_access_live: state.federated_access_live,
      membership_status: state.membership_status,
      source_session_reason: state.source_session_reason,
      continuation_state: state.continuation_state,
      continuation_reason: state.continuation_reason,
      live_ldap_sessions: state.live_ldap_sessions,
      live_ldap_continuations: state.live_ldap_continuations,
      absence_status: state.absence_status,
    },
    {
      ldap_access_live: false,
      federated_access_live: true,
      membership_status: "active",
      source_session_reason: "ldap_identity_sync_authoritative_absence",
      continuation_state: "revoked",
      continuation_reason: "ldap_identity_sync_authoritative_absence",
      live_ldap_sessions: 0,
      live_ldap_continuations: 0,
      absence_status: "applied",
    },
  );
  assert.equal(state.session_invalidation_epoch, input.priorSubjectEpoch + 1);
}

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(version?.version.startsWith("18."));

  await sql.begin(async (transaction) => {
    await transaction`
      UPDATE public.tenant_memberships
      SET status='active',updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.targetMembership}::uuid
    `;
  });
  const platformFloorId = uuid(1);
  const tenantBaselineId = uuid(2);
  await sql.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',${`insert:${platformFloorId}:1`},true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions(
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (
        ${platformFloorId}::uuid,1,NULL,'platform_floor','primary',false,0,
        transaction_timestamp()
      )
    `;
    await transaction`
      SELECT set_config(
        'app.mfa_policy_write_v1',${`insert:${tenantBaselineId}:1`},true
      )
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions(
        id,revision,tenant_id,scope,level,local_required,
        freshness_nanoseconds,created_at
      ) VALUES (
        ${tenantBaselineId}::uuid,1,${fixture.tenant}::uuid,
        'tenant_baseline','primary',false,0,transaction_timestamp()
      )
    `;
  });

  const [receiptSurface] = await sql<
    {
      owner: string;
      row_security: boolean;
      force_row_security: boolean;
      api_direct: boolean;
      worker_direct: boolean;
      policy_count: number;
    }[]
  >`
    SELECT pg_get_userbyid(relation.relowner) AS owner,
      relation.relrowsecurity AS row_security,
      relation.relforcerowsecurity AS force_row_security,
      has_table_privilege('periapsis_api',relation.oid,
        'SELECT,INSERT,UPDATE,DELETE') AS api_direct,
      has_table_privilege('periapsis_worker',relation.oid,
        'SELECT,INSERT,UPDATE,DELETE') AS worker_direct,
      (SELECT count(*)::integer FROM pg_policies AS policy
       WHERE policy.schemaname='public'
         AND policy.tablename=relation.relname
         AND policy.policyname=
           'tenant_ldap_jit_authority_issuance_receipts_migrator_v1'
         AND policy.roles=ARRAY['periapsis_migrator']::name[]
         AND policy.cmd='ALL') AS policy_count
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='public'
      AND relation.relname='tenant_ldap_jit_authority_issuance_receipts'
  `;
  assert.deepEqual(receiptSurface, {
    owner: "periapsis_migrator",
    row_security: true,
    force_row_security: true,
    api_direct: false,
    worker_direct: false,
    policy_count: 1,
  });
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`
        SELECT count(*)
        FROM public.tenant_ldap_jit_authority_issuance_receipts
      `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  // The shared recovery replacement entrypoint invokes the LDAP preparer for
  // every primary kind. A real local-credential rotation must still use the
  // generic writer and must not mint an inert LDAP-only capability.
  const localCreatedAt = new Date();
  const localLoginIdentifierId = uuid(1900);
  const localCredentialId = uuid(1901);
  const localSourceSessionId = uuid(1902);
  const localSessionFamilyId = uuid(1903);
  const localRecoverySetId = uuid(1904);
  const localRecoveryCodeId = uuid(1905);
  const localSuccessorSessionId = uuid(1906);
  const localReplacementSetId = uuid(1907);
  const localIdleExpiresAt = new Date(localCreatedAt.getTime() + 60 * 60_000);
  const localAbsoluteExpiresAt = new Date(
    localCreatedAt.getTime() + 2 * 60 * 60_000,
  );
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.user_login_identifiers(
        id,user_id,kind,canonical_value,verified_at,created_at,updated_at
      ) VALUES (
        ${localLoginIdentifierId}::uuid,${fixture.adminUser}::uuid,
        'local_email','directory.admin@example.invalid',${localCreatedAt},
        ${localCreatedAt},${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.local_break_glass_credentials(
        id,user_id,login_identifier_id,password_phc,password_version,
        changed_at,created_at,updated_at
      ) VALUES (
        ${localCredentialId}::uuid,${fixture.adminUser}::uuid,
        ${localLoginIdentifierId}::uuid,
        '$argon2id$v=19$m=65536,t=3,p=1$YWJjZA$YWJjZGVmZ2hpamtsbW5vcA',
        1,${localCreatedAt},${localCreatedAt},${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects(
        tenant_id,user_id,webauthn_user_handle,identity_epoch,
        session_invalidation_epoch,version,created_at,updated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${fixture.adminUser}::uuid,
        ${digest("local-admin-user-handle")}::bytea,1,1,1,
        ${localCreatedAt},${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_code_sets(
        id,tenant_id,user_id,digest_key_version,record_version,
        security_revision,completion_request_digest,result_snapshot,status,
        generated_at,updated_at
      ) VALUES (
        ${localRecoverySetId}::uuid,${fixture.tenant}::uuid,
        ${fixture.adminUser}::uuid,1,1,1,
        ${digest("local-recovery-set")}::bytea,'{}'::jsonb,'active',
        ${localCreatedAt},${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_codes(
        id,tenant_id,set_id,code_digest,created_at
      ) VALUES (
        ${localRecoveryCodeId}::uuid,${fixture.tenant}::uuid,
        ${localRecoverySetId}::uuid,${digest("local-recovery-code")}::bytea,
        ${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions(
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      ) VALUES (
        ${localSourceSessionId}::uuid,${fixture.adminUser}::uuid,
        ${localSessionFamilyId}::uuid,${fixture.tenant}::uuid,
        ${digest("local-source-token")}::bytea,
        ${digest("local-source-csrf")}::bytea,'recovery_code',
        ${localCreatedAt},${localCreatedAt},${localIdleExpiresAt},
        ${localAbsoluteExpiresAt},${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states(
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,
        session_invalidation_epoch,issued_at
      ) VALUES (
        ${localSourceSessionId}::uuid,${fixture.tenant}::uuid,
        ${fixture.adminUser}::uuid,1,1,true,'api','local_credential',1,
        ${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_local_credential_provenance(
        tenant_id,session_id,user_id,credential_id,credential_revision,
        authenticated_at
      ) VALUES (
        ${fixture.tenant}::uuid,${localSourceSessionId}::uuid,
        ${fixture.adminUser}::uuid,${localCredentialId}::uuid,1,
        ${localCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,local_credential_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${localSourceSessionId}::uuid,
        ${localCredentialId}::uuid,'primary','local_credential',
        ${localCreatedAt},1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_evidence(
        tenant_id,session_id,recovery_code_set_id,level,kind,
        authenticated_at,factor_revision
      ) VALUES (
        ${fixture.tenant}::uuid,${localSourceSessionId}::uuid,
        ${localRecoverySetId}::uuid,'mfa','recovery',${localCreatedAt},1
      )
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_policy_pins(
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES
        (${fixture.tenant}::uuid,${localSourceSessionId}::uuid,
         ${platformFloorId}::uuid,1),
        (${fixture.tenant}::uuid,${localSourceSessionId}::uuid,
         ${tenantBaselineId}::uuid,1)
    `;
  });
  const localReplacementAt = new Date(localCreatedAt.getTime() + 1_000);
  const localAuthority = await resolveAuthority(
    localSourceSessionId,
    "session",
    "mfa.recovery_codes.replace",
    localReplacementAt,
  );
  assert.equal(stringField(localAuthority, "primaryKind"), "local_credential");
  const localRequirement = jsonObject(
    jsonField(localAuthority, "requirement"),
    "local recovery replacement requirement",
  );
  const localReplacementRequest = {
    newSetId: localReplacementSetId,
    digestKeyVersion: 1,
    expectedSetId: localRecoverySetId,
    expectedSetVersion: 1,
    binding: stepUpBinding(localAuthority),
    digests: Array.from({ length: 8 }, (_, index) =>
      base64Digest(`local-replacement-code-${index}`),
    ),
    generatedAt: localReplacementAt.toISOString(),
    audit: {
      kind: "mfa.recovery_codes_regenerated",
      tenantId: fixture.tenant,
      userId: fixture.adminUser,
      action: jsonField(localAuthority, "action"),
      occurredAt: localReplacementAt.toISOString(),
      policyRevisions: jsonField(localRequirement, "policyRevisions"),
    },
    session: {
      mutation: "rotate",
      expectedSessionId: localSourceSessionId,
      expectedFamilyId: localSessionFamilyId,
      expectedAnchorVersion: jsonField(localAuthority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(localAuthority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(localAuthority, "anchorExpiresAt"),
      audience: jsonField(localAuthority, "audience"),
      requirement: jsonField(localAuthority, "requirement"),
      recoveryRestricted: true,
      reservation: {
        sessionId: localSuccessorSessionId,
        familyId: localSessionFamilyId,
        tokenDigest: base64Digest("local-successor-token"),
        csrfDigest: base64Digest("local-successor-csrf"),
        authenticationMethod: "recovery_code",
        idleExpiresAt: localIdleExpiresAt.toISOString(),
        absoluteExpiresAt: localAbsoluteExpiresAt.toISOString(),
      },
    },
  };
  const [localReplacement] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(localReplacementRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  const localReplacementResult = jsonObject(
    localReplacement?.result,
    "local recovery replacement",
  );
  assert.equal(
    stringField(localReplacementResult, "newSessionId"),
    localSuccessorSessionId,
  );
  const [localReplay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(localReplacementRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(localReplay?.result, localReplacement?.result);
  const [localCapabilityState] = await sql<
    {
      source_reason: string;
      successor_method: string;
      capability_count: number;
      ldap_provenance_count: number;
      local_provenance_count: number;
      recovery_evidence_count: number;
      new_code_count: number;
    }[]
  >`
    SELECT source.revoke_reason AS source_reason,
      successor.authentication_method AS successor_method,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count,
      (SELECT count(*)::integer FROM public.auth_session_ldap_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${localSuccessorSessionId}::uuid)
        AS ldap_provenance_count,
      (SELECT count(*)::integer
       FROM public.auth_session_local_credential_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${localSuccessorSessionId}::uuid)
        AS local_provenance_count,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${localSuccessorSessionId}::uuid
         AND kind='recovery') AS recovery_evidence_count,
      (SELECT count(*)::integer FROM public.tenant_recovery_codes
       WHERE tenant_id=${fixture.tenant}::uuid
         AND set_id=${localReplacementSetId}::uuid) AS new_code_count
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${localSuccessorSessionId}::uuid
    WHERE source.id=${localSourceSessionId}::uuid
  `;
  assert.deepEqual(localCapabilityState, {
    source_reason: "mfa_session_rotated",
    successor_method: "recovery_code",
    capability_count: 0,
    ldap_provenance_count: 0,
    local_provenance_count: 1,
    recovery_evidence_count: 0,
    new_code_count: 8,
  });
  await exerciseGenericFederatedRecoveryReplacement(
    "oidc",
    2000,
    platformFloorId,
    tenantBaselineId,
  );
  await exerciseGenericFederatedRecoveryReplacement(
    "saml",
    2300,
    platformFloorId,
    tenantBaselineId,
  );

  const runId = uuid(100);
  const runReceipt = digest("root-session-receipt");
  const applicationId = uuid(110);
  const network = await beginJit(runId, runReceipt, 100);
  const planning = await claimJit(runId, runReceipt, 100);
  const rule = planning.rules.find(
    (candidate) =>
      candidate.matcherValue.toLocaleLowerCase("en-US") === "soc-blue",
  );
  assert(rule, "SOC mapping was not pinned by the JIT claim");
  const initialApplication = await applyAdmittedJit(
    runId,
    runReceipt,
    applicationId,
    rule.ruleEpochId,
    100,
  );
  assert(initialApplication.ensured_edge_count >= 2);
  const [runState] = await sql<
    {
      authorization_revision: string;
      result_authorization_revision: string;
      current_authorization_revision: string;
      convalidated: boolean;
    }[]
  >`
    SELECT run.authorization_revision::text,
      run.result_authorization_revision::text,
      state.revision::text AS current_authorization_revision,
      constraint_row.convalidated
    FROM public.tenant_ldap_jit_authentication_runs AS run
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id=run.tenant_id
    JOIN pg_constraint AS constraint_row
      ON constraint_row.conname=
        'tenant_ldap_jit_runs_result_authorization_revision_check'
    WHERE run.tenant_id=${fixture.tenant}::uuid AND run.id=${runId}::uuid
  `;
  assert(runState);
  assert.equal(
    runState.result_authorization_revision,
    runState.current_authorization_revision,
  );
  assert(
    BigInt(runState.result_authorization_revision) >
      BigInt(runState.authorization_revision),
  );
  assert.equal(runState.convalidated, true);

  const appliedAt = new Date();
  const idleExpiresAt = new Date(appliedAt.getTime() + 60 * 60 * 1000);
  const absoluteExpiresAt = new Date(appliedAt.getTime() + 24 * 60 * 60 * 1000);
  const sessionReservation: SessionReservation = {
    sessionId: uuid(120),
    familyId: uuid(121),
    tokenDigest: base64Digest("root-session-token"),
    csrfDigest: base64Digest("root-session-csrf"),
    authenticationMethod: "ldap",
    idleExpiresAt: idleExpiresAt.toISOString(),
    absoluteExpiresAt: absoluteExpiresAt.toISOString(),
  };
  const issueRequest: IssueRequest = {
    runId,
    receipt: runReceipt,
    applicationId,
    disposition: "session",
    assurance: "satisfied",
    authenticatedAt: network.started_at,
    appliedAt,
    returnPath: "/tickets",
    session: sessionReservation,
    continuation: null,
    auditEventId: uuid(122),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denied reconciliation runtime",
  };
  const issued = await issueAuthority(issueRequest);
  assert.deepEqual(issued, {
    category: "success",
    disposition: "session",
    userId: fixture.targetUser,
    sessionId: sessionReservation.sessionId,
    continuationId: null,
    returnPath: "/tickets",
    replayed: false,
  });
  const replayed = await issueAuthority(issueRequest);
  assert.deepEqual(replayed, {
    category: "success",
    disposition: "session",
    userId: fixture.targetUser,
    sessionId: sessionReservation.sessionId,
    continuationId: null,
    returnPath: "/tickets",
    replayed: true,
  });
  await assert.rejects(
    issueAuthority(issueRequest, { continuationJsonNull: true }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const [providerEvidence] = await sql<
    { authenticated_at: Date; expires_at: Date }[]
  >`
    SELECT authenticated_at,expires_at
    FROM public.auth_session_mfa_evidence
    WHERE tenant_id=${fixture.tenant}::uuid
      AND session_id=${sessionReservation.sessionId}::uuid
      AND kind='provider'
  `;
  assert(providerEvidence);
  assert.equal(
    providerEvidence.authenticated_at.toISOString(),
    new Date(network.started_at).toISOString(),
  );
  assert.equal(
    providerEvidence.expires_at.toISOString(),
    absoluteExpiresAt.toISOString(),
  );
  assert(providerEvidence.expires_at > new Date(network.expires_at));

  const [beforeMismatch] = await sql<
    { receipts: number; sessions: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_ldap_jit_authority_issuance_receipts
       WHERE tenant_id=${fixture.tenant}::uuid AND jit_run_id=${runId}::uuid)
        AS receipts,
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${sessionReservation.sessionId}::uuid) AS sessions,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${issueRequest.auditEventId}::uuid) AS audits
  `;
  assert.deepEqual(beforeMismatch, { receipts: 1, sessions: 1, audits: 1 });
  const mismatches: IssueRequest[] = [
    { ...issueRequest, returnPath: "/mutated" },
    { ...issueRequest, applicationId: uuid(130) },
    { ...issueRequest, disposition: "continuation" },
    { ...issueRequest, assurance: "step_up_required" },
    {
      ...issueRequest,
      session: { ...sessionReservation, tokenDigest: base64Digest("mutated") },
    },
    { ...issueRequest, auditEventId: uuid(131) },
    { ...issueRequest, appliedAt: new Date(appliedAt.getTime() + 1000) },
    { ...issueRequest, ipAddress: "192.0.2.212" },
    { ...issueRequest, userAgent: "mutated LDAP issuance retry" },
  ];
  await Promise.all(
    mismatches.map((mismatch) =>
      assert.rejects(issueAuthority(mismatch), (error: unknown) =>
        assertSqlState(error, "40001"),
      ),
    ),
  );
  const [afterMismatch] = await sql<
    { receipts: number; sessions: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_ldap_jit_authority_issuance_receipts
       WHERE tenant_id=${fixture.tenant}::uuid AND jit_run_id=${runId}::uuid)
        AS receipts,
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${sessionReservation.sessionId}::uuid) AS sessions,
      (SELECT count(*)::integer FROM public.audit_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id IN (${issueRequest.auditEventId}::uuid,${uuid(131)}::uuid))
        AS audits
  `;
  assert.deepEqual(afterMismatch, beforeMismatch);

  const usableProjection = await loadRevalidation(sessionReservation.sessionId);
  assert.equal(stringField(usableProjection, "authenticationMethod"), "ldap");
  const usableMutation = revalidationMutation(
    usableProjection,
    "usable",
    "current",
  );
  const usableResult = await applyRevalidation(usableMutation);
  assert.deepEqual(usableResult, {
    applied: true,
    decision: "usable",
    tenantId: fixture.tenant,
    sessionId: sessionReservation.sessionId,
    expectedVersion: 1,
  });
  assert.deepEqual(await applyRevalidation(usableMutation), usableResult);

  // Policy-only drift must rotate an otherwise-current LDAP session and keep
  // the exact root/source family lineage without generic OIDC/SAML rows.
  const rotateRoot = await createRootSession(300);
  await advanceTenantBaseline(2, "primary");
  const rotateProjection = await loadRevalidation(rotateRoot.session.sessionId);
  const rotateSnapshot = jsonObject(
    jsonField(rotateProjection, "snapshot"),
    "LDAP rotate snapshot",
  );
  const rotateObservedAt = new Date();
  const rotateSessionId = uuid(340);
  const rotateMutation = revalidationMutation(
    rotateProjection,
    "rotate",
    "policy_refresh",
    {
      session: {
        sessionId: rotateSessionId,
        familyId: stringField(rotateSnapshot, "rotationFamilyId"),
        tokenDigest: base64Digest("ldap-rotate-token"),
        csrfDigest: base64Digest("ldap-rotate-csrf"),
        authenticationMethod: "ldap",
        idleExpiresAt: new Date(
          rotateObservedAt.getTime() + 30 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: stringField(rotateSnapshot, "absoluteExpiresAt"),
      },
    },
  );
  rotateMutation.observedAt = rotateObservedAt.toISOString();
  const rotateResult = await applyRevalidation(rotateMutation);
  assert.deepEqual(rotateResult, {
    applied: true,
    decision: "rotate",
    tenantId: fixture.tenant,
    sessionId: rotateRoot.session.sessionId,
    expectedVersion: 1,
    newSessionId: rotateSessionId,
  });
  assert.deepEqual(await applyRevalidation(rotateMutation), rotateResult);
  const [rotateState] = await sql<
    {
      source_reason: string;
      successor_live: boolean;
      ldap_lineage: number;
      generic_lineage: number;
    }[]
  >`
    SELECT source.revoke_reason AS source_reason,
      successor.revoked_at IS NULL AS successor_live,
      (SELECT count(*)::integer FROM public.auth_session_ldap_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${rotateSessionId}::uuid
         AND source_session_id=${rotateRoot.session.sessionId}::uuid
         AND root_jit_run_id=${rotateRoot.runId}::uuid) AS ldap_lineage,
      (SELECT count(*)::integer FROM public.auth_session_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${rotateSessionId}::uuid) AS generic_lineage
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${rotateSessionId}::uuid
    WHERE source.id=${rotateRoot.session.sessionId}::uuid
  `;
  assert.deepEqual(rotateState, {
    source_reason: "ldap_session_rotated",
    successor_live: true,
    ldap_lineage: 1,
    generic_lineage: 0,
  });

  // Increased assurance produces a bounded LDAP continuation. Provider
  // evidence is clamped to the continuation, not the root JIT receipt.
  const stepUpRoot = await createRootSession(400);
  await advanceTenantBaseline(3, "mfa");
  const stepUpProjection = await loadRevalidation(stepUpRoot.session.sessionId);
  const stepUpObservedAt = new Date();
  const stepUpContinuationId = uuid(440);
  const stepUpExpiresAt = new Date(stepUpObservedAt.getTime() + 10 * 60_000);
  const stepUpMutation = revalidationMutation(
    stepUpProjection,
    "step_up",
    "assurance_insufficient",
    {
      continuation: {
        continuationId: stepUpContinuationId,
        receiptDigest: base64Digest("ldap-step-up-receipt"),
        expiresAt: stepUpExpiresAt.toISOString(),
      },
    },
  );
  stepUpMutation.observedAt = stepUpObservedAt.toISOString();
  const stepUpResult = await applyRevalidation(stepUpMutation);
  assert.deepEqual(stepUpResult, {
    applied: true,
    decision: "step_up",
    tenantId: fixture.tenant,
    sessionId: stepUpRoot.session.sessionId,
    expectedVersion: 1,
    continuationId: stepUpContinuationId,
  });
  assert.deepEqual(await applyRevalidation(stepUpMutation), stepUpResult);
  const [stepUpState] = await sql<
    {
      session_version: number;
      provider_expiry: Date;
      ldap_lineage: number;
      generic_lineage: number;
    }[]
  >`
    SELECT state.session_version::integer,
      evidence.expires_at AS provider_expiry,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_ldap_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND continuation_id=${stepUpContinuationId}::uuid
         AND source_session_id=${stepUpRoot.session.sessionId}::uuid)
        AS ldap_lineage,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND continuation_id=${stepUpContinuationId}::uuid)
        AS generic_lineage
    FROM public.auth_session_mfa_states AS state
    JOIN public.tenant_post_primary_continuation_evidence AS evidence
      ON evidence.tenant_id=state.tenant_id
     AND evidence.continuation_id=${stepUpContinuationId}::uuid
     AND evidence.kind='provider'
    WHERE state.tenant_id=${fixture.tenant}::uuid
      AND state.session_id=${stepUpRoot.session.sessionId}::uuid
  `;
  assert(stepUpState);
  assert.equal(stepUpState.session_version, 2);
  assert.equal(
    stepUpState.provider_expiry.toISOString(),
    stepUpExpiresAt.toISOString(),
  );
  assert.equal(stepUpState.ldap_lineage, 1);
  assert.equal(stepUpState.generic_lineage, 0);

  const rootContinuationRun = await createAdmittedJit(500);
  const rootContinuationAppliedAt = new Date();
  const rootContinuationId = uuid(530);
  const rootContinuationExpiresAt = new Date(
    rootContinuationAppliedAt.getTime() + 10 * 60_000,
  );
  const rootContinuationRequest: IssueRequest = {
    runId: rootContinuationRun.runId,
    receipt: rootContinuationRun.receipt,
    applicationId: rootContinuationRun.applicationId,
    disposition: "continuation",
    assurance: "step_up_required",
    authenticatedAt: rootContinuationRun.network.started_at,
    appliedAt: rootContinuationAppliedAt,
    returnPath: "/tickets",
    session: null,
    continuation: {
      continuationId: rootContinuationId,
      receiptDigest: base64Digest("root-continuation-receipt"),
      expiresAt: rootContinuationExpiresAt.toISOString(),
    },
    auditEventId: uuid(532),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denied reconciliation runtime",
  };
  const rootContinuation = await issueAuthority(rootContinuationRequest);
  assert.equal(rootContinuation.continuationId, rootContinuationId);
  assert.equal(rootContinuation.replayed, false);
  assert.equal((await issueAuthority(rootContinuationRequest)).replayed, true);
  await assert.rejects(
    issueAuthority(rootContinuationRequest, { sessionJsonNull: true }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const [rootContinuationEvidence] = await sql<{ expires_at: Date }[]>`
    SELECT expires_at
    FROM public.tenant_post_primary_continuation_evidence
    WHERE tenant_id=${fixture.tenant}::uuid
      AND continuation_id=${rootContinuationId}::uuid
      AND kind='provider'
  `;
  assert(rootContinuationEvidence);
  assert.equal(
    rootContinuationEvidence.expires_at.toISOString(),
    rootContinuationExpiresAt.toISOString(),
  );
  assert(
    rootContinuationEvidence.expires_at >
      new Date(rootContinuationRun.network.expires_at),
  );
  const evaluatedAfterReceiptExpiry = new Date(
    new Date(rootContinuationRun.network.expires_at).getTime() + 30_000,
  );
  assert(evaluatedAfterReceiptExpiry < rootContinuationExpiresAt);
  const [futureAuthority] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.resolve_mfa_authority_v2(
          ${rootContinuationId}::uuid,'continuation','session.create','api',
          ${evaluatedAfterReceiptExpiry}::timestamptz,
          ${digest("root-continuation-receipt")}::bytea
        ) AS value
      `,
    ),
  );
  const futureAuthorityValue = jsonObject(
    futureAuthority?.value,
    "LDAP continuation authority after JIT receipt expiry",
  );
  assert.equal(stringField(futureAuthorityValue, "flow"), "continuation");
  assert.equal(
    stringField(futureAuthorityValue, "authenticationMethod"),
    "ldap",
  );

  // Negative terminal decisions use the historical serialization fence: the
  // live-only predicates are intentionally not required before family revoke.
  await advanceTenantBaseline(4, "primary");
  const terminalReasons = [
    "lifecycle",
    "identity_epoch",
    "primary_drift",
    "factor_drift",
    "trust_drift",
    "expired",
    "malformed",
  ] as const;
  const terminalResults = await terminalReasons.reduce<Promise<string[]>>(
    async (pendingResults, reason, index) => {
      const results = await pendingResults;
      const terminalRoot = await createRootSession(600 + index * 50);
      const projection = await loadRevalidation(terminalRoot.session.sessionId);
      const decision = reason === "malformed" ? "deny" : "revoke";
      const mutation = revalidationMutation(projection, decision, reason);
      const result = await applyRevalidation(mutation);
      assert.equal(stringField(result, "decision"), decision);
      assert.equal(jsonField(result, "applied"), true);
      if (index === 0) {
        assert.deepEqual(await applyRevalidation(mutation), result);
      }
      const [session] = await sql<{ revoke_reason: string | null }[]>`
        SELECT revoke_reason FROM public.auth_sessions
        WHERE id=${terminalRoot.session.sessionId}::uuid
      `;
      assert.equal(session?.revoke_reason, `ldap_revalidation_${reason}`);
      return [...results, stringField(result, "sessionId")];
    },
    Promise.resolve([]),
  );
  assert.equal(new Set(terminalResults).size, terminalReasons.length);

  const totpFactorId = uuid(1100);
  const recoverySetId = uuid(1101);
  const recoveryCodeId = uuid(1102);
  const webauthnCredentialId = uuid(1103);
  const webauthnCredentialWireId = digest("terminal-webauthn-credential");
  const recoveryCodeDigest = digest("terminal-recovery-code");
  const factorCreatedAt = new Date();
  const [subjectHandle] = await sql<{ webauthn_user_handle: Buffer }[]>`
    SELECT webauthn_user_handle
    FROM public.tenant_mfa_subjects
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.targetUser}::uuid
  `;
  assert(subjectHandle);
  const webauthnUserHandleDigest = createHash("sha256")
    .update(subjectHandle.webauthn_user_handle)
    .digest();
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenant_totp_factors(
        id,tenant_id,user_id,secret_envelope,key_version,
        last_accepted_counter,record_version,security_revision,status,
        confirmed_at,created_at,updated_at
      ) VALUES (
        ${totpFactorId}::uuid,${fixture.tenant}::uuid,
        ${fixture.targetUser}::uuid,${digest("terminal-totp-envelope")}::bytea,
        1,-1,1,1,'active',${factorCreatedAt},${factorCreatedAt},
        ${factorCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_code_sets(
        id,tenant_id,user_id,digest_key_version,record_version,
        security_revision,completion_request_digest,result_snapshot,status,
        generated_at,updated_at
      ) VALUES (
        ${recoverySetId}::uuid,${fixture.tenant}::uuid,
        ${fixture.targetUser}::uuid,1,1,1,
        ${digest("terminal-recovery-set")}::bytea,'{}'::jsonb,'active',
        ${factorCreatedAt},${factorCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_recovery_codes(
        id,tenant_id,set_id,code_digest,created_at
      ) VALUES (
        ${recoveryCodeId}::uuid,${fixture.tenant}::uuid,
        ${recoverySetId}::uuid,${recoveryCodeDigest}::bytea,
        ${factorCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credentials(
        id,tenant_id,user_id,credential_id,public_key,display_name,
        user_handle_digest,rp_id,rp_revision,sign_count,discoverable,
        user_verification,backup_eligible,backed_up,aaguid,
        attestation_format,attestation_type,attestation_trusted,
        metadata_revision,status,version,security_revision,created_at,
        last_used_at,updated_at
      ) VALUES (
        ${webauthnCredentialId}::uuid,${fixture.tenant}::uuid,
        ${fixture.targetUser}::uuid,${webauthnCredentialWireId}::bytea,
        ${Buffer.alloc(64, 0x82)}::bytea,'LDAP runtime passkey',
        ${webauthnUserHandleDigest}::bytea,'example.invalid',1,5,true,true,
        false,false,${Buffer.alloc(16)}::bytea,'none','none',false,0,
        'active',3,1,${factorCreatedAt},${factorCreatedAt},${factorCreatedAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_webauthn_credential_transports(
        tenant_id,credential_id,transport
      ) VALUES (
        ${fixture.tenant}::uuid,${webauthnCredentialId}::uuid,'internal'
      )
    `;
  });
  await exercisePasskeyRecoveryReplacement(
    platformFloorId,
    tenantBaselineId,
    4,
  );
  await advanceTenantBaseline(5, "mfa");

  // TOTP terminal completion crosses the real repository resolver, claim and
  // public completion ABIs after the root JIT receipt has expired, while the
  // bounded LDAP continuation remains live.
  const totpContinuation = await createRootContinuation(1200);
  const totpChallengeAt = new Date(
    new Date(totpContinuation.network.expires_at).getTime() + 30_000,
  );
  assert(totpChallengeAt < totpContinuation.expiresAt);
  const totpAuthority = await resolveAuthority(
    totpContinuation.continuationId,
    "continuation",
    "session.create",
    totpChallengeAt,
    totpContinuation.continuationReceipt,
  );
  const totpChallenge = await createAndClaimFactorChallenge({
    authority: totpAuthority,
    factorKind: "totp",
    selectedFactorId: totpFactorId,
    sequence: 1230,
    createdAt: totpChallengeAt,
    continuationReceipt: totpContinuation.continuationReceipt,
  });
  const totpSession: SessionReservation = {
    sessionId: uuid(1240),
    familyId: uuid(1241),
    tokenDigest: base64Digest("terminal-totp-token"),
    csrfDigest: base64Digest("terminal-totp-csrf"),
    authenticationMethod: "totp",
    idleExpiresAt: new Date(
      totpChallenge.completedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: new Date(
      totpChallenge.completedAt.getTime() + 2 * 60 * 60_000,
    ).toISOString(),
  };
  const totpCompletionRequest = {
    challengeId: totpChallenge.challengeId.toString("base64"),
    expectedChallengeVersion: 2,
    binding: totpChallenge.binding,
    factorId: totpFactorId,
    expectedFactorVersion: 1,
    expectedSecurityRevision: 1,
    counter: 0,
    completedAt: totpChallenge.completedAt.toISOString(),
    sessionMutation: "consume_continuation",
    auditKind: "mfa.totp_step_up_completed",
    recoveryRestricted: false,
    continuationReceiptDigest:
      totpContinuation.continuationReceipt.toString("base64"),
    session: totpSession,
  };
  const [totpCompletion] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${transaction.json(totpCompletionRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  const totpResult = jsonObject(totpCompletion?.result, "LDAP TOTP result");
  assert.equal(stringField(totpResult, "newSessionId"), totpSession.sessionId);
  const [totpReplay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_totp_step_up_v1(
          ${transaction.json(totpCompletionRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(totpReplay?.result, totpCompletion?.result);
  const [totpCommitted] = await sql<
    { provider_evidence: number; totp_evidence: number; generic_rows: number }[]
  >`
    SELECT
      count(*) FILTER (WHERE evidence.kind='provider')::integer
        AS provider_evidence,
      count(*) FILTER (
        WHERE evidence.kind='totp'
          AND evidence.totp_factor_id=${totpFactorId}::uuid
      )::integer AS totp_evidence,
      (SELECT count(*)::integer
       FROM public.auth_session_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${totpSession.sessionId}::uuid) AS generic_rows
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id=${fixture.tenant}::uuid
      AND evidence.session_id=${totpSession.sessionId}::uuid
  `;
  assert.deepEqual(totpCommitted, {
    provider_evidence: 1,
    totp_evidence: 1,
    generic_rows: 0,
  });

  // Recovery uses the same typed LDAP terminal path, consumes exactly one
  // code and marks the successor restricted. The successor then exercises the
  // baseline-only recovery replacement path that must omit the retired set.
  const recoveryContinuation = await createRootContinuation(1300);
  const recoveryChallengeAt = new Date();
  const recoveryAuthority = await resolveAuthority(
    recoveryContinuation.continuationId,
    "continuation",
    "session.create",
    recoveryChallengeAt,
    recoveryContinuation.continuationReceipt,
  );
  const recoveryChallenge = await createAndClaimFactorChallenge({
    authority: recoveryAuthority,
    factorKind: "recovery_code",
    sequence: 1330,
    createdAt: recoveryChallengeAt,
    continuationReceipt: recoveryContinuation.continuationReceipt,
  });
  const recoverySession: SessionReservation = {
    sessionId: uuid(1340),
    familyId: uuid(1341),
    tokenDigest: base64Digest("terminal-recovery-token"),
    csrfDigest: base64Digest("terminal-recovery-csrf"),
    authenticationMethod: "recovery_code",
    idleExpiresAt: new Date(
      recoveryChallenge.completedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: new Date(
      recoveryChallenge.completedAt.getTime() + 2 * 60 * 60_000,
    ).toISOString(),
  };
  const recoveryCompletionRequest = {
    challengeId: recoveryChallenge.challengeId.toString("base64"),
    expectedChallengeVersion: 2,
    binding: recoveryChallenge.binding,
    factorId: "",
    expectedFactorVersion: 1,
    expectedSecurityRevision: 1,
    setId: recoverySetId,
    codeDigest: recoveryCodeDigest.toString("base64"),
    completedAt: recoveryChallenge.completedAt.toISOString(),
    sessionMutation: "consume_continuation",
    auditKind: "mfa.recovery_code_used",
    recoveryRestricted: true,
    continuationReceiptDigest:
      recoveryContinuation.continuationReceipt.toString("base64"),
    session: recoverySession,
  };
  const [recoveryCompletion] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_recovery_step_up_v1(
          ${transaction.json(recoveryCompletionRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  const recoveryResult = jsonObject(
    recoveryCompletion?.result,
    "LDAP recovery result",
  );
  assert.equal(
    stringField(recoveryResult, "newSessionId"),
    recoverySession.sessionId,
  );
  assert.equal(jsonField(recoveryResult, "recoveryRestricted"), true);
  const [recoveryReplay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_recovery_step_up_v1(
          ${transaction.json(recoveryCompletionRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(recoveryReplay?.result, recoveryCompletion?.result);

  const replacementAt = new Date(
    recoveryChallenge.completedAt.getTime() + 1_000,
  );
  const replacementAuthority = await resolveAuthority(
    recoverySession.sessionId,
    "session",
    "mfa.recovery_codes.replace",
    replacementAt,
  );
  const replacementBinding = stepUpBinding(replacementAuthority);
  const replacementRequirement = jsonObject(
    jsonField(replacementAuthority, "requirement"),
    "LDAP replacement requirement",
  );
  const replacementSession: SessionReservation = {
    sessionId: uuid(1360),
    familyId: recoverySession.familyId,
    tokenDigest: base64Digest("replacement-recovery-token"),
    csrfDigest: base64Digest("replacement-recovery-csrf"),
    authenticationMethod: "ldap",
    idleExpiresAt: new Date(
      replacementAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: recoverySession.absoluteExpiresAt,
  };
  const replacementRequest = {
    newSetId: uuid(1361),
    digestKeyVersion: 1,
    expectedSetId: recoverySetId,
    expectedSetVersion: 2,
    binding: replacementBinding,
    digests: Array.from({ length: 8 }, (_, index) =>
      base64Digest(`replacement-recovery-code-${index}`),
    ),
    generatedAt: replacementAt.toISOString(),
    audit: {
      kind: "mfa.recovery_codes_regenerated",
      tenantId: fixture.tenant,
      userId: fixture.targetUser,
      action: jsonField(replacementAuthority, "action"),
      occurredAt: replacementAt.toISOString(),
      policyRevisions: jsonField(replacementRequirement, "policyRevisions"),
    },
    session: {
      mutation: "rotate",
      expectedSessionId: recoverySession.sessionId,
      expectedFamilyId: recoverySession.familyId,
      expectedAnchorVersion: jsonField(replacementAuthority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(replacementAuthority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(replacementAuthority, "anchorExpiresAt"),
      audience: jsonField(replacementAuthority, "audience"),
      requirement: jsonField(replacementAuthority, "requirement"),
      recoveryRestricted: true,
      reservation: replacementSession,
    },
  };
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json({
            ...replacementRequest,
            session: {
              ...replacementRequest.session,
              replacedRecoverySetId: recoverySetId,
            },
          })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const [afterForgedReplacement] = await sql<
    {
      old_set_status: string;
      old_set_version: number;
      source_live: boolean;
      capability_count: number;
      new_set_count: number;
    }[]
  >`
    SELECT code_set.status AS old_set_status,
      code_set.record_version::integer AS old_set_version,
      source.revoked_at IS NULL AS source_live,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count,
      (SELECT count(*)::integer FROM public.tenant_recovery_code_sets
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${replacementRequest.newSetId}::uuid) AS new_set_count
    FROM public.tenant_recovery_code_sets AS code_set
    JOIN public.auth_sessions AS source
      ON source.id=${recoverySession.sessionId}::uuid
    WHERE code_set.tenant_id=${fixture.tenant}::uuid
      AND code_set.id=${recoverySetId}::uuid
  `;
  assert.deepEqual(afterForgedReplacement, {
    old_set_status: "active",
    old_set_version: 2,
    source_live: true,
    capability_count: 0,
    new_set_count: 0,
  });
  const [replacement] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(replacementRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  const replacementResult = jsonObject(
    replacement?.result,
    "LDAP recovery replacement",
  );
  assert.equal(
    stringField(replacementResult, "newSessionId"),
    replacementSession.sessionId,
  );
  const [replacementReplay] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.replace_mfa_recovery_codes_v1(
          ${transaction.json(replacementRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  assert.deepEqual(replacementReplay?.result, replacement?.result);
  const [replacementState] = await sql<
    {
      provider_evidence: number;
      recovery_evidence: number;
      new_set_evidence: number;
      new_code_count: number;
      recovery_restricted: boolean;
      capability_count: number;
    }[]
  >`
    SELECT
      count(*) FILTER (WHERE evidence.kind='provider')::integer
        AS provider_evidence,
      count(*) FILTER (WHERE evidence.kind='recovery')::integer
        AS recovery_evidence,
      count(*) FILTER (
        WHERE evidence.recovery_code_set_id=${replacementRequest.newSetId}::uuid
      )::integer AS new_set_evidence,
      (SELECT count(*)::integer FROM public.tenant_recovery_codes
       WHERE tenant_id=${fixture.tenant}::uuid
         AND set_id=${replacementRequest.newSetId}::uuid) AS new_code_count,
      state.recovery_restricted,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.auth_session_mfa_states AS state
      ON state.tenant_id=evidence.tenant_id
     AND state.session_id=evidence.session_id
    WHERE evidence.tenant_id=${fixture.tenant}::uuid
      AND evidence.session_id=${replacementSession.sessionId}::uuid
    GROUP BY state.recovery_restricted
  `;
  assert.deepEqual(replacementState, {
    provider_evidence: 1,
    recovery_evidence: 0,
    new_set_evidence: 0,
    new_code_count: 8,
    recovery_restricted: true,
    capability_count: 0,
  });

  // WebAuthn terminal completion must traverse the LDAP-aware artifact
  // resolver and carry the security revision, not the independently advanced
  // sign-counter version, into successor evidence.
  const passkeyContinuation = await createRootContinuation(1400);
  const passkeyCeremonyAt = new Date();
  const passkeyAuthority = await resolveAuthority(
    passkeyContinuation.continuationId,
    "continuation",
    "session.create",
    passkeyCeremonyAt,
    passkeyContinuation.continuationReceipt,
  );
  const passkeyBinding = webauthnBinding(
    passkeyAuthority,
    "continuation_authentication",
  );
  const passkeyCeremonyId = digest("terminal-passkey-ceremony");
  const passkeyBrowserDigest = digest("terminal-passkey-browser");
  const passkeyCeremonyRequest = {
    id: passkeyCeremonyId.toString("base64"),
    challengeDigest: base64Digest("terminal-passkey-challenge"),
    browserDigest: passkeyBrowserDigest.toString("base64"),
    relyingParty: {
      id: "example.invalid",
      origins: ["https://example.invalid"],
      revision: 1,
    },
    binding: passkeyBinding,
    policy: {
      requireUserPresence: true,
      userVerification: "required",
      residentKey: "preferred",
      attestation: "none",
      metadataRevision: 0,
    },
    mode: "known_user",
    userHandleDigest: webauthnUserHandleDigest.toString("base64"),
    allowedCredentialIds: [webauthnCredentialWireId.toString("base64")],
    continuationReceiptDigest:
      passkeyContinuation.continuationReceipt.toString("base64"),
    createdAt: passkeyCeremonyAt.toISOString(),
    expiresAt: new Date(passkeyCeremonyAt.getTime() + 5 * 60_000).toISOString(),
    state: "pending",
    version: 1,
  };
  const [passkeyCeremonyCreated] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ value: boolean }[]>`
        SELECT app.create_webauthn_ceremony_v1(
          ${transaction.json(passkeyCeremonyRequest)}::jsonb
        ) AS value
      `,
      ),
  );
  assert.equal(passkeyCeremonyCreated?.value, true);
  const [passkeyArtifact] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.resolve_mfa_completion_artifact_v1(
          ${transaction.json({
            artifactKind: "webauthn_authentication",
            artifactId: passkeyCeremonyId.toString("base64"),
            browserDigest: passkeyBrowserDigest.toString("base64"),
            selectedFactorKind: "passkey",
            selectedFactorId: webauthnCredentialWireId.toString("base64"),
            continuationReceiptDigest:
              passkeyContinuation.continuationReceipt.toString("base64"),
            requestedAt: passkeyCeremonyAt.toISOString(),
          })}::jsonb
        ) AS value
      `,
    ),
  );
  const passkeyArtifactValue = jsonObject(
    passkeyArtifact?.value,
    "LDAP passkey artifact",
  );
  assert.equal(
    stringField(passkeyArtifactValue, "resultAuthenticationMethod"),
    "ldap",
  );
  assert.equal(
    stringField(passkeyArtifactValue, "reservationAuthenticationMethod"),
    "passkey",
  );
  const passkeyClaimedAt = new Date(passkeyCeremonyAt.getTime() + 1_000);
  const [passkeyClaimed] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.claim_webauthn_ceremony_v2(
          ${passkeyCeremonyId}::bytea,${passkeyBrowserDigest}::bytea,
          ${passkeyClaimedAt}::timestamptz,
          ${passkeyContinuation.continuationReceipt}::bytea
        ) AS value
      `,
    ),
  );
  const passkeyClaimedValue = jsonObject(
    passkeyClaimed?.value,
    "claimed LDAP passkey ceremony",
  );
  assert.equal(jsonField(passkeyClaimedValue, "version"), 2);
  const passkeyCompletedAt = new Date(passkeyClaimedAt.getTime() + 1_000);
  const passkeySession: SessionReservation = {
    sessionId: uuid(1440),
    familyId: uuid(1441),
    tokenDigest: base64Digest("terminal-passkey-token"),
    csrfDigest: base64Digest("terminal-passkey-csrf"),
    authenticationMethod: "passkey",
    idleExpiresAt: new Date(
      passkeyCompletedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: new Date(
      passkeyCompletedAt.getTime() + 2 * 60 * 60_000,
    ).toISOString(),
  };
  const passkeyRequirement = jsonObject(
    jsonField(passkeyAuthority, "requirement"),
    "LDAP passkey requirement",
  );
  const passkeyCompletionRequest = {
    completion: {
      ceremonyId: passkeyCeremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: passkeyBinding,
      resolvedUserId: fixture.targetUser,
      expectedIdentityEpoch: jsonField(passkeyAuthority, "identityEpoch"),
      credentialId: webauthnCredentialWireId.toString("base64"),
      expectedCredentialVersion: 3,
      completedAt: passkeyCompletedAt.toISOString(),
      expectedSignCount: 5,
      observedSignCount: 6,
      expectedBackedUp: false,
      counterDisposition: "advance",
      userVerified: true,
      backupEligible: false,
      backedUp: false,
    },
    audit: {
      kind: "mfa.passkey_step_up_completed",
      tenantId: fixture.tenant,
      userId: fixture.targetUser,
      action: jsonField(passkeyAuthority, "action"),
      occurredAt: passkeyCompletedAt.toISOString(),
      policyRevisions: jsonField(passkeyRequirement, "policyRevisions"),
    },
    session: {
      mutation: "consume_continuation",
      expectedContinuationId: passkeyContinuation.continuationId,
      expectedAnchorVersion: jsonField(passkeyAuthority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(passkeyAuthority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(passkeyAuthority, "anchorExpiresAt"),
      audience: jsonField(passkeyAuthority, "audience"),
      requirement: jsonField(passkeyAuthority, "requirement"),
      recoveryRestricted: false,
      continuationReceiptDigest:
        passkeyContinuation.continuationReceipt.toString("base64"),
      reservation: passkeySession,
    },
  };
  const [passkeyCompletion] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_authentication_v1(
          ${transaction.json(passkeyCompletionRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  const passkeyResult = jsonObject(
    passkeyCompletion?.result,
    "LDAP passkey completion",
  );
  assert.equal(
    stringField(passkeyResult, "newSessionId"),
    passkeySession.sessionId,
  );
  const [passkeyReplay] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_authentication_v1(
          ${transaction.json(passkeyCompletionRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  assert.deepEqual(passkeyReplay?.result, passkeyCompletion?.result);
  const [passkeyState] = await sql<
    {
      credential_version: number;
      security_revision: number;
      sign_count: number;
      evidence_revision: number;
      provider_evidence: number;
      generic_rows: number;
    }[]
  >`
    SELECT credential.version::integer AS credential_version,
      credential.security_revision::integer AS security_revision,
      credential.sign_count::integer AS sign_count,
      evidence.factor_revision::integer AS evidence_revision,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${passkeySession.sessionId}::uuid
         AND kind='provider') AS provider_evidence,
      (SELECT count(*)::integer
       FROM public.auth_session_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${passkeySession.sessionId}::uuid) AS generic_rows
    FROM public.tenant_webauthn_credentials AS credential
    JOIN public.auth_session_mfa_evidence AS evidence
      ON evidence.tenant_id=credential.tenant_id
     AND evidence.session_id=${passkeySession.sessionId}::uuid
     AND evidence.kind='webauthn'
     AND evidence.webauthn_credential_id=credential.id
    WHERE credential.tenant_id=${fixture.tenant}::uuid
      AND credential.id=${webauthnCredentialId}::uuid
  `;
  assert.deepEqual(passkeyState, {
    credential_version: 4,
    security_revision: 1,
    sign_count: 6,
    evidence_revision: 1,
    provider_evidence: 1,
    generic_rows: 0,
  });

  // Enrollment resolves the polymorphic reference to the concrete LDAP
  // session flow. Registration is baseline-only: the source authority is
  // rotated with its provider evidence intact, and the newly enrolled
  // credential is not misrepresented as authentication evidence. A forged
  // recovery-replacement hint is rejected before any transaction state can
  // escape.
  await advanceTenantBaseline(6, "primary");
  const registrationRoot = await createRootSession(1500);
  const registrationAt = new Date();
  const registrationAuthority = await resolveAuthority(
    registrationRoot.session.sessionId,
    "enrollment",
    "mfa.passkeys.enroll",
    registrationAt,
  );
  assert.equal(stringField(registrationAuthority, "flow"), "session");
  const registrationCredentialWireId = digest(
    "session-registration-credential",
  );
  const registrationCeremony = await createAndClaimRegistrationCeremony({
    authority: registrationAuthority,
    credentialWireId: registrationCredentialWireId,
    userHandleDigest: webauthnUserHandleDigest,
    sequence: 1530,
    createdAt: registrationAt,
  });
  const registrationRequirement = jsonObject(
    jsonField(registrationAuthority, "requirement"),
    "LDAP registration requirement",
  );
  const registrationSession: SessionReservation = {
    sessionId: uuid(1540),
    familyId: registrationRoot.session.familyId,
    tokenDigest: base64Digest("registration-session-token"),
    csrfDigest: base64Digest("registration-session-csrf"),
    authenticationMethod: "ldap",
    idleExpiresAt: new Date(
      registrationCeremony.completedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: registrationRoot.session.absoluteExpiresAt,
  };
  const registrationRequest = {
    completion: {
      ceremonyId: registrationCeremony.ceremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: registrationCeremony.binding,
      completedAt: registrationCeremony.completedAt.toISOString(),
      credential: {
        id: registrationCredentialWireId.toString("base64"),
        publicKey: Buffer.alloc(64, 0x91).toString("base64"),
        tenantId: fixture.tenant,
        userId: fixture.targetUser,
        identityEpoch: jsonField(registrationAuthority, "identityEpoch"),
        userHandleDigest: webauthnUserHandleDigest.toString("base64"),
        rpId: "example.invalid",
        rpRevision: 1,
        version: 1,
        securityRevision: 1,
        status: "active",
        signCount: 0,
        discoverable: true,
        userVerification: true,
        backupEligible: false,
        backedUp: false,
        transports: ["internal"],
      },
      aaguid: Buffer.alloc(16, 0x92).toString("base64"),
      attestationFormat: "none",
      attestationType: "none",
      attestationTrusted: false,
      metadataRevision: 0,
    },
    displayName: "LDAP enrolled passkey",
    audit: {
      kind: "mfa.passkey_enrolled",
      tenantId: fixture.tenant,
      userId: fixture.targetUser,
      action: jsonField(registrationAuthority, "action"),
      occurredAt: registrationCeremony.completedAt.toISOString(),
      policyRevisions: jsonField(registrationRequirement, "policyRevisions"),
    },
    session: {
      mutation: "rotate",
      expectedSessionId: registrationRoot.session.sessionId,
      expectedFamilyId: registrationRoot.session.familyId,
      expectedAnchorVersion: jsonField(registrationAuthority, "anchorVersion"),
      expectedIdentityEpoch: jsonField(registrationAuthority, "identityEpoch"),
      expectedAnchorExpiry: jsonField(registrationAuthority, "anchorExpiresAt"),
      audience: jsonField(registrationAuthority, "audience"),
      requirement: jsonField(registrationAuthority, "requirement"),
      recoveryRestricted: false,
      reservation: registrationSession,
    },
  };
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`
        SELECT app.complete_mfa_passkey_registration_v1(
          ${transaction.json({
            ...registrationRequest,
            session: {
              ...registrationRequest.session,
              replacedRecoverySetId: replacementRequest.newSetId,
            },
          })}::jsonb
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "22023"),
  );
  const [registrationAfterInjection] = await sql<
    {
      credential_count: number;
      successor_count: number;
      source_live: boolean;
      capability_count: number;
      ceremony_state: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_webauthn_credentials AS credential
       WHERE credential.tenant_id=${fixture.tenant}::uuid
         AND credential.credential_id=${registrationCredentialWireId}::bytea)
        AS credential_count,
      (SELECT count(*)::integer FROM public.auth_sessions AS successor
       WHERE successor.id=${registrationSession.sessionId}::uuid)
        AS successor_count,
      source.revoked_at IS NULL AS source_live,
      (SELECT count(*)::integer
       FROM public.tenant_mfa_ldap_recovery_replacement_capabilities)
        AS capability_count,
      ceremony.state AS ceremony_state
    FROM public.auth_sessions AS source
    JOIN public.tenant_webauthn_ceremonies AS ceremony
      ON ceremony.id=${registrationCeremony.ceremonyId}::bytea
    WHERE source.id=${registrationRoot.session.sessionId}::uuid
  `;
  assert.deepEqual(registrationAfterInjection, {
    credential_count: 0,
    successor_count: 0,
    source_live: true,
    capability_count: 0,
    ceremony_state: "claimed",
  });
  const [registration] = await asRole("periapsis_api", async (transaction) =>
    Array.from(
      await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_registration_v1(
          ${transaction.json(registrationRequest)}::jsonb
        ) AS result
      `,
    ),
  );
  const registrationResult = jsonObject(
    registration?.result,
    "LDAP session registration",
  );
  assert.equal(
    stringField(registrationResult, "newSessionId"),
    registrationSession.sessionId,
  );
  const [registrationReplay] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_registration_v1(
          ${transaction.json(registrationRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  assert.deepEqual(registrationReplay?.result, registration?.result);
  const [registrationState] = await sql<
    {
      source_reason: string;
      provider_evidence: number;
      enrolled_evidence: number;
      credential_count: number;
      generic_rows: number;
      successor_method: string;
    }[]
  >`
    SELECT source.revoke_reason AS source_reason,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${registrationSession.sessionId}::uuid
         AND kind='provider') AS provider_evidence,
      (SELECT count(*)::integer FROM public.auth_session_mfa_evidence
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${registrationSession.sessionId}::uuid
         AND webauthn_credential_id=credential.id) AS enrolled_evidence,
      count(*)::integer AS credential_count,
      (SELECT count(*)::integer
       FROM public.auth_session_federated_provenance
       WHERE tenant_id=${fixture.tenant}::uuid
         AND session_id=${registrationSession.sessionId}::uuid)
        AS generic_rows,
      successor.authentication_method AS successor_method
    FROM public.auth_sessions AS source
    JOIN public.auth_sessions AS successor
      ON successor.id=${registrationSession.sessionId}::uuid
    JOIN public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id=${fixture.tenant}::uuid
     AND credential.credential_id=${registrationCredentialWireId}::bytea
    WHERE source.id=${registrationRoot.session.sessionId}::uuid
    GROUP BY source.revoke_reason,successor.authentication_method,
      credential.id
  `;
  assert.deepEqual(registrationState, {
    source_reason: "mfa_session_rotated",
    provider_evidence: 1,
    enrolled_evidence: 0,
    credential_count: 1,
    generic_rows: 0,
    successor_method: "ldap",
  });

  // The same enrollment reference contract resolves a continuation to its
  // concrete flow. Registration retains (rather than consumes) that bounded
  // authority and performs no session reservation.
  await advanceTenantBaseline(7, "mfa");
  const continuationRegistrationRoot = await createRootContinuation(1600);
  const continuationRegistrationAt = new Date();
  const continuationRegistrationAuthority = await resolveAuthority(
    continuationRegistrationRoot.continuationId,
    "enrollment",
    "mfa.passkeys.enroll",
    continuationRegistrationAt,
    continuationRegistrationRoot.continuationReceipt,
  );
  assert.equal(
    stringField(continuationRegistrationAuthority, "flow"),
    "continuation",
  );
  const continuationRegistrationCredentialWireId = digest(
    "continuation-registration-credential",
  );
  const continuationRegistrationCeremony =
    await createAndClaimRegistrationCeremony({
      authority: continuationRegistrationAuthority,
      credentialWireId: continuationRegistrationCredentialWireId,
      userHandleDigest: webauthnUserHandleDigest,
      sequence: 1630,
      createdAt: continuationRegistrationAt,
      continuationReceipt: continuationRegistrationRoot.continuationReceipt,
    });
  const continuationRegistrationRequirement = jsonObject(
    jsonField(continuationRegistrationAuthority, "requirement"),
    "LDAP continuation registration requirement",
  );
  const continuationRegistrationRequest = {
    completion: {
      ceremonyId:
        continuationRegistrationCeremony.ceremonyId.toString("base64"),
      expectedCeremonyVersion: 2,
      binding: continuationRegistrationCeremony.binding,
      completedAt: continuationRegistrationCeremony.completedAt.toISOString(),
      credential: {
        id: continuationRegistrationCredentialWireId.toString("base64"),
        publicKey: Buffer.alloc(64, 0x93).toString("base64"),
        tenantId: fixture.tenant,
        userId: fixture.targetUser,
        identityEpoch: jsonField(
          continuationRegistrationAuthority,
          "identityEpoch",
        ),
        userHandleDigest: webauthnUserHandleDigest.toString("base64"),
        rpId: "example.invalid",
        rpRevision: 1,
        version: 1,
        securityRevision: 1,
        status: "active",
        signCount: 0,
        discoverable: true,
        userVerification: true,
        backupEligible: false,
        backedUp: false,
        transports: ["internal"],
      },
      aaguid: Buffer.alloc(16, 0x94).toString("base64"),
      attestationFormat: "none",
      attestationType: "none",
      attestationTrusted: false,
      metadataRevision: 0,
    },
    displayName: "LDAP continuation enrolled passkey",
    audit: {
      kind: "mfa.passkey_enrolled",
      tenantId: fixture.tenant,
      userId: fixture.targetUser,
      action: jsonField(continuationRegistrationAuthority, "action"),
      occurredAt: continuationRegistrationCeremony.completedAt.toISOString(),
      policyRevisions: jsonField(
        continuationRegistrationRequirement,
        "policyRevisions",
      ),
    },
    session: {
      mutation: "retain_continuation",
      expectedContinuationId: continuationRegistrationRoot.continuationId,
      expectedAnchorVersion: jsonField(
        continuationRegistrationAuthority,
        "anchorVersion",
      ),
      expectedIdentityEpoch: jsonField(
        continuationRegistrationAuthority,
        "identityEpoch",
      ),
      expectedAnchorExpiry: jsonField(
        continuationRegistrationAuthority,
        "anchorExpiresAt",
      ),
      audience: jsonField(continuationRegistrationAuthority, "audience"),
      requirement: jsonField(continuationRegistrationAuthority, "requirement"),
      recoveryRestricted: false,
      continuationReceiptDigest:
        continuationRegistrationRoot.continuationReceipt.toString("base64"),
    },
  };
  const [continuationRegistration] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_registration_v1(
          ${transaction.json(continuationRegistrationRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  const continuationRegistrationResult = jsonObject(
    continuationRegistration?.result,
    "LDAP continuation registration",
  );
  assert.equal(
    stringField(continuationRegistrationResult, "retainedContinuationId"),
    continuationRegistrationRoot.continuationId,
  );
  assert.equal(jsonField(continuationRegistrationResult, "sessionVersion"), 2);
  const [continuationRegistrationReplay] = await asRole(
    "periapsis_api",
    async (transaction) =>
      Array.from(
        await transaction<{ result: postgres.JSONValue }[]>`
        SELECT app.complete_mfa_passkey_registration_v1(
          ${transaction.json(continuationRegistrationRequest)}::jsonb
        ) AS result
      `,
      ),
  );
  assert.deepEqual(
    continuationRegistrationReplay?.result,
    continuationRegistration?.result,
  );
  const [continuationRegistrationState] = await sql<
    {
      state: string;
      version: number;
      credential_count: number;
      evidence_count: number;
    }[]
  >`
    SELECT continuation.state,continuation.version::integer,
      (SELECT count(*)::integer
       FROM public.tenant_webauthn_credentials AS credential
       WHERE credential.tenant_id=${fixture.tenant}::uuid
         AND credential.credential_id=
           ${continuationRegistrationCredentialWireId}::bytea)
        AS credential_count,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuation_evidence AS evidence
       WHERE evidence.tenant_id=${fixture.tenant}::uuid
         AND evidence.continuation_id=continuation.id) AS evidence_count
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id=${fixture.tenant}::uuid
      AND continuation.id=
        ${continuationRegistrationRoot.continuationId}::uuid
  `;
  assert.deepEqual(continuationRegistrationState, {
    state: "pending",
    version: 2,
    credential_count: 1,
    evidence_count: 1,
  });

  // UUID namespaces are table-local, so an enrollment reference can exist as
  // both a session and a continuation. The LDAP router must reject that
  // ambiguous reference before choosing either authority.
  await advanceTenantBaseline(8, "primary");
  const ambiguousSession = await createRootSession(1700);
  await advanceTenantBaseline(9, "mfa");
  const ambiguousContinuation = await createRootContinuation(
    1800,
    ambiguousSession.session.sessionId,
  );
  await assert.rejects(
    resolveAuthority(
      ambiguousSession.session.sessionId,
      "enrollment",
      "mfa.passkeys.enroll",
      new Date(),
      ambiguousContinuation.continuationReceipt,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  // Global invalidation, user disable and tenant suspension must serialize
  // with positive LDAP revalidation. Each mutation wins its row lock and the
  // API contender fails with 40001 without minting a successor.
  const logoutProjection = await loadRevalidation(totpSession.sessionId);
  const logoutSnapshot = jsonObject(
    jsonField(logoutProjection, "snapshot"),
    "LDAP logout race snapshot",
  );
  const logoutRaceAt = new Date();
  const logoutRotateSessionId = uuid(3600);
  const logoutRotateMutation = revalidationMutation(
    logoutProjection,
    "rotate",
    "policy_refresh",
    {
      session: {
        sessionId: logoutRotateSessionId,
        familyId: stringField(logoutSnapshot, "rotationFamilyId"),
        tokenDigest: base64Digest("logout-race-rotate-token"),
        csrfDigest: base64Digest("logout-race-rotate-csrf"),
        authenticationMethod: "ldap",
        idleExpiresAt: new Date(
          logoutRaceAt.getTime() + 30 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: stringField(logoutSnapshot, "absoluteExpiresAt"),
      },
    },
  );
  logoutRotateMutation.observedAt = logoutRaceAt.toISOString();
  const [beforeLogoutRace] = await sql<
    { session_invalidation_epoch: number }[]
  >`
    SELECT session_invalidation_epoch::integer
    FROM public.tenant_mfa_subjects
    WHERE tenant_id=${fixture.tenant}::uuid
      AND user_id=${fixture.targetUser}::uuid
  `;
  assert(beforeLogoutRace);
  await assertGlobalAuthorityFenceRejects(
    (transaction) =>
      transaction`
        UPDATE public.tenant_mfa_subjects
        SET session_invalidation_epoch=session_invalidation_epoch+1,
            version=version+1,updated_at=transaction_timestamp()
        WHERE tenant_id=${fixture.tenant}::uuid
          AND user_id=${fixture.targetUser}::uuid
      `,
    (transaction) => invokeRevalidation(transaction, logoutRotateMutation),
  );
  const [afterLogoutRace] = await sql<
    { session_invalidation_epoch: number; successor_count: number }[]
  >`
    SELECT subject.session_invalidation_epoch::integer,
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${logoutRotateSessionId}::uuid) AS successor_count
    FROM public.tenant_mfa_subjects AS subject
    WHERE subject.tenant_id=${fixture.tenant}::uuid
      AND subject.user_id=${fixture.targetUser}::uuid
  `;
  assert.deepEqual(afterLogoutRace, {
    session_invalidation_epoch: beforeLogoutRace.session_invalidation_epoch + 1,
    successor_count: 0,
  });

  await advanceTenantBaseline(10, "primary");
  const disabledRaceSession = await createRootSession(3650);
  await advanceTenantBaseline(11, "mfa");
  const disabledProjection = await loadRevalidation(
    disabledRaceSession.session.sessionId,
  );
  const disabledRaceAt = new Date();
  const disabledStepUpContinuationId = uuid(3700);
  const disabledStepUpMutation = revalidationMutation(
    disabledProjection,
    "step_up",
    "assurance_insufficient",
    {
      continuation: {
        continuationId: disabledStepUpContinuationId,
        receiptDigest: base64Digest("disabled-race-step-up-receipt"),
        expiresAt: new Date(
          disabledRaceAt.getTime() + 10 * 60_000,
        ).toISOString(),
      },
    },
  );
  disabledStepUpMutation.observedAt = disabledRaceAt.toISOString();
  await assertGlobalAuthorityFenceRejects(
    (transaction) =>
      transaction`
        UPDATE public.users SET active=false,
          updated_at=transaction_timestamp()
        WHERE id=${fixture.targetUser}::uuid
      `,
    (transaction) => invokeRevalidation(transaction, disabledStepUpMutation),
  );
  const [disabledRaceState] = await sql<
    { active: boolean; successor_count: number }[]
  >`
    SELECT users.active,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${disabledStepUpContinuationId}::uuid) AS successor_count
    FROM public.users WHERE id=${fixture.targetUser}::uuid
  `;
  assert.deepEqual(disabledRaceState, { active: false, successor_count: 0 });
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.users SET active=true,updated_at=transaction_timestamp()
      WHERE id=${fixture.targetUser}::uuid
    `;
  });

  await advanceTenantBaseline(12, "primary");
  const tenantRaceSession = await createRootSession(3800);
  const tenantProjection = await loadRevalidation(
    tenantRaceSession.session.sessionId,
  );
  const tenantSnapshot = jsonObject(
    jsonField(tenantProjection, "snapshot"),
    "LDAP tenant race snapshot",
  );
  const tenantRaceAt = new Date();
  const tenantRotateSessionId = uuid(3900);
  const tenantRotateMutation = revalidationMutation(
    tenantProjection,
    "rotate",
    "policy_refresh",
    {
      session: {
        sessionId: tenantRotateSessionId,
        familyId: stringField(tenantSnapshot, "rotationFamilyId"),
        tokenDigest: base64Digest("tenant-race-rotate-token"),
        csrfDigest: base64Digest("tenant-race-rotate-csrf"),
        authenticationMethod: "ldap",
        idleExpiresAt: new Date(
          tenantRaceAt.getTime() + 30 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: stringField(tenantSnapshot, "absoluteExpiresAt"),
      },
    },
  );
  tenantRotateMutation.observedAt = tenantRaceAt.toISOString();
  await assertGlobalAuthorityFenceRejects(
    (transaction) =>
      transaction`
        UPDATE public.tenants SET status='suspended',version=version+1,
          updated_at=transaction_timestamp()
        WHERE id=${fixture.tenant}::uuid
      `,
    (transaction) => invokeRevalidation(transaction, tenantRotateMutation),
  );
  const [tenantRaceState] = await sql<
    { status: string; successor_count: number }[]
  >`
    SELECT tenant.status,
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${tenantRotateSessionId}::uuid) AS successor_count
    FROM public.tenants AS tenant WHERE tenant.id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(tenantRaceState, {
    status: "suspended",
    successor_count: 0,
  });
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenants SET status='active',version=version+1,
        updated_at=transaction_timestamp()
      WHERE id=${fixture.tenant}::uuid
    `;
  });

  // A mapped observation that no longer matches must revoke only the exact
  // per-user authoritative edges. Retain keeps provider access intact, and a
  // repeated no-match carries no fabricated epoch merely because the shared
  // group-role grant remains live.
  const retainBinding = await configureSync("retain");
  const retainFirst = await prepareObservedSync(retainBinding, 4000);
  const retainFirstApplication = await applyDeniedSync(retainFirst);
  assert.equal(
    jsonField(retainFirstApplication.result, "revoked_edge_count"),
    1,
  );
  const [retainFirstState] = await sql<
    {
      access_live: boolean;
      membership_status: string;
      live_user_edges: number;
      live_role_edges: number;
      absence_count: number;
    }[]
  >`
    SELECT access_grant.ended_at IS NULL AS access_live,
      membership.status AS membership_status,
      (SELECT count(*)::integer FROM public.tenant_security_group_memberships
       WHERE tenant_id=${fixture.tenant}::uuid
         AND membership_id=${fixture.targetMembership}::uuid
         AND revoked_at IS NULL) AS live_user_edges,
      (SELECT count(*)::integer FROM public.tenant_security_group_role_grants
       WHERE tenant_id=${fixture.tenant}::uuid
         AND revoked_at IS NULL) AS live_role_edges,
      (SELECT count(*)::integer FROM public.tenant_ldap_sync_absences
       WHERE tenant_id=${fixture.tenant}::uuid
         AND binding_id=${retainBinding}::uuid
         AND external_identity_id=${fixture.externalIdentity}::uuid)
        AS absence_count
    FROM public.tenant_ldap_provider_access_grants AS access_grant
    JOIN public.tenant_memberships AS membership
      ON membership.id=access_grant.membership_id
     AND membership.tenant_id=access_grant.tenant_id
    WHERE access_grant.tenant_id=${fixture.tenant}::uuid
      AND access_grant.id=${fixture.accessGrant}::uuid
  `;
  assert(retainFirstState);
  assert.deepEqual(
    {
      access_live: retainFirstState.access_live,
      membership_status: retainFirstState.membership_status,
      live_user_edges: retainFirstState.live_user_edges,
      absence_count: retainFirstState.absence_count,
    },
    {
      access_live: true,
      membership_status: "active",
      live_user_edges: 0,
      absence_count: 0,
    },
  );
  assert(retainFirstState.live_role_edges > 0);
  await completePreparedSync(retainFirst);

  const retainRepeated = await prepareObservedSync(retainBinding, 4100);
  assert.deepEqual(revocationEpochIDs(retainRepeated.planning), []);
  assert(
    retainRepeated.planning.live_owned_edges.some(
      (edge) => edge.kind === "security_group_role_grant",
    ),
  );
  const retainRepeatedApplication = await applyDeniedSync(retainRepeated);
  assert.equal(
    jsonField(retainRepeatedApplication.result, "revoked_edge_count"),
    0,
  );
  await completePreparedSync(retainRepeated);

  // Grace preserves the first timer across repeated observed no-matches. A
  // real admitted mapping clears it, and the next no-match starts a new clock.
  const graceBinding = await configureSync("grace", 120);
  const initialMatch = await prepareObservedSync(graceBinding, 4200);
  await applyAdmittedSync(initialMatch);
  await completePreparedSync(initialMatch);

  const graceFirst = await prepareObservedSync(graceBinding, 4300);
  await applyDeniedSync(graceFirst);
  const [firstAbsence] = await sql<
    {
      status: string;
      first_missing_run_id: string;
      latest_missing_run_id: string;
      first_missing_at: Date;
      apply_after: Date;
    }[]
  >`
    SELECT status,first_missing_run_id,latest_missing_run_id,
      first_missing_at,apply_after
    FROM public.tenant_ldap_sync_absences
    WHERE tenant_id=${fixture.tenant}::uuid
      AND binding_id=${graceBinding}::uuid
      AND external_identity_id=${fixture.externalIdentity}::uuid
  `;
  assert(firstAbsence);
  assert.equal(firstAbsence.status, "pending");
  assert.equal(firstAbsence.first_missing_run_id, graceFirst.runId);
  assert.equal(firstAbsence.latest_missing_run_id, graceFirst.runId);
  assert(firstAbsence.apply_after > firstAbsence.first_missing_at);
  await completePreparedSync(graceFirst);

  const graceRepeated = await prepareObservedSync(graceBinding, 4400);
  assert.deepEqual(revocationEpochIDs(graceRepeated.planning), []);
  await applyDeniedSync(graceRepeated);
  const [repeatedAbsence] = await sql<
    {
      status: string;
      first_missing_run_id: string;
      latest_missing_run_id: string;
      first_missing_at: Date;
      apply_after: Date;
    }[]
  >`
    SELECT status,first_missing_run_id,latest_missing_run_id,
      first_missing_at,apply_after
    FROM public.tenant_ldap_sync_absences
    WHERE tenant_id=${fixture.tenant}::uuid
      AND binding_id=${graceBinding}::uuid
      AND external_identity_id=${fixture.externalIdentity}::uuid
  `;
  assert(repeatedAbsence);
  assert.equal(repeatedAbsence.status, "pending");
  assert.equal(repeatedAbsence.first_missing_run_id, graceFirst.runId);
  assert.equal(repeatedAbsence.latest_missing_run_id, graceRepeated.runId);
  assert.equal(
    repeatedAbsence.first_missing_at.toISOString(),
    firstAbsence.first_missing_at.toISOString(),
  );
  assert.equal(
    repeatedAbsence.apply_after.toISOString(),
    firstAbsence.apply_after.toISOString(),
  );
  await completePreparedSync(graceRepeated);

  // Hold the run row so an exact enumeration replay observes the old
  // enumerating state and then blocks. The winning transaction completes the
  // run and applies the admitted observation before the replay resumes. The
  // replay must not reopen the just-cleared absence.
  const recoveredMatch = await prepareObservedSync(graceBinding, 4500, false);
  await raceEnumerationReplayWithAdmitted(recoveredMatch);
  const [clearedAbsence] = await sql<
    { status: string; resolved_at: Date | null; observation_applied: boolean }[]
  >`
    SELECT absence.status,absence.resolved_at,
      observation.applied_at IS NOT NULL AS observation_applied
    FROM public.tenant_ldap_sync_absences AS absence
    JOIN public.tenant_ldap_sync_staged_observations AS observation
      ON observation.tenant_id=absence.tenant_id
     AND observation.sync_run_id=${recoveredMatch.runId}::uuid
     AND observation.external_identity_id=absence.external_identity_id
    WHERE absence.tenant_id=${fixture.tenant}::uuid
      AND absence.binding_id=${graceBinding}::uuid
      AND absence.external_identity_id=${fixture.externalIdentity}::uuid
  `;
  assert(clearedAbsence);
  assert.equal(clearedAbsence.status, "cleared");
  assert(clearedAbsence.resolved_at);
  assert.equal(clearedAbsence.observation_applied, true);
  await completePreparedSync(recoveredMatch);

  const afterRecovery = await prepareObservedSync(graceBinding, 4600);
  await applyDeniedSync(afterRecovery);
  const [newAbsence] = await sql<
    { status: string; first_missing_run_id: string; first_missing_at: Date }[]
  >`
    SELECT status,first_missing_run_id,first_missing_at
    FROM public.tenant_ldap_sync_absences
    WHERE tenant_id=${fixture.tenant}::uuid
      AND binding_id=${graceBinding}::uuid
      AND external_identity_id=${fixture.externalIdentity}::uuid
  `;
  assert(newAbsence);
  assert.equal(newAbsence.status, "pending");
  assert.equal(newAbsence.first_missing_run_id, afterRecovery.runId);
  assert(newAbsence.first_missing_at > firstAbsence.first_missing_at);
  await completePreparedSync(afterRecovery);

  // Complete inventory absence has a distinct path. After another admitted
  // recovery, a run with no observation must reopen the cleared row with a
  // fresh clock instead of inheriting the prior grace deadline.
  const beforeInventoryMatch = await prepareObservedSync(graceBinding, 4700);
  await applyAdmittedSync(beforeInventoryMatch);
  await completePreparedSync(beforeInventoryMatch);
  const emptyInventory = await prepareEmptySync(graceBinding, 4800);
  const absenceChunk = await applyAbsenceChunk(emptyInventory);
  assert(absenceChunk.inspected_count >= 1);
  assert.equal(absenceChunk.revoked_count, 0);
  const [inventoryAbsence] = await sql<
    { status: string; first_missing_run_id: string; first_missing_at: Date }[]
  >`
    SELECT status,first_missing_run_id,first_missing_at
    FROM public.tenant_ldap_sync_absences
    WHERE tenant_id=${fixture.tenant}::uuid
      AND binding_id=${graceBinding}::uuid
      AND external_identity_id=${fixture.externalIdentity}::uuid
  `;
  assert(inventoryAbsence);
  assert.equal(inventoryAbsence.status, "pending");
  assert.equal(inventoryAbsence.first_missing_run_id, emptyInventory.runId);
  assert(inventoryAbsence.first_missing_at > newAbsence.first_missing_at);
  await completePreparedSync(emptyInventory);

  // A second live provider grant makes this membership shared. Inventory
  // deprovision must end only LDAP access, revoke every typed LDAP authority,
  // increment the subject epoch, and leave the shared membership active.
  const secondaryExternalIdentity = uuid(4900);
  const secondaryAccessGrant = uuid(4901);
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_ldap_provider_access_grants
      SET owns_membership=true,version=version+1,
          updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.accessGrant}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_federated_external_identities(
        id,tenant_id,provider_id,binding_id,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,
        admitted_configuration_revision,last_observed_at,version,
        created_at,updated_at
      ) VALUES (
        ${secondaryExternalIdentity}::uuid,${fixture.tenant}::uuid,
        ${uuid(2003)}::uuid,${uuid(2004)}::uuid,${fixture.targetUser}::uuid,
        'utf8_exact',${Buffer.alloc(32, 0xa6)},${Buffer.alloc(12, 0xa7)},2,1,
        transaction_timestamp(),1,transaction_timestamp(),
        transaction_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_access_grants(
        id,tenant_id,provider_id,binding_id,access_epoch_id,source_id,
        external_identity_id,membership_id,user_id,owns_membership,
        started_at,last_observed_at,version
      ) VALUES (
        ${secondaryAccessGrant}::uuid,${fixture.tenant}::uuid,
        ${uuid(2003)}::uuid,${uuid(2004)}::uuid,${uuid(2007)}::uuid,
        ${uuid(2006)}::uuid,${secondaryExternalIdentity}::uuid,
        ${fixture.targetMembership}::uuid,${fixture.targetUser}::uuid,false,
        transaction_timestamp(),transaction_timestamp(),1
      )
    `;
  });

  // A denied identity plan holds the same authority fence as root issuance
  // and positive revalidation. Exercise both policy modes while the denial is
  // uncommitted: the contenders must fail closed and mint no successor.
  const raceImmediateBinding = await configureSync("immediate");
  const primaryRaceSession = await createRootSession(5000);
  const pendingSessionRun = await createAdmittedJit(6000);
  const pendingSessionAppliedAt = new Date();
  const pendingSessionReservation: SessionReservation = {
    sessionId: uuid(6030),
    familyId: uuid(6031),
    tokenDigest: base64Digest("denial-race-root-session-token"),
    csrfDigest: base64Digest("denial-race-root-session-csrf"),
    authenticationMethod: "ldap",
    idleExpiresAt: new Date(
      pendingSessionAppliedAt.getTime() + 30 * 60_000,
    ).toISOString(),
    absoluteExpiresAt: new Date(
      pendingSessionAppliedAt.getTime() + 2 * 60 * 60_000,
    ).toISOString(),
  };
  const pendingSessionRequest: IssueRequest = {
    runId: pendingSessionRun.runId,
    receipt: pendingSessionRun.receipt,
    applicationId: pendingSessionRun.applicationId,
    disposition: "session",
    assurance: "satisfied",
    authenticatedAt: pendingSessionRun.network.started_at,
    appliedAt: pendingSessionAppliedAt,
    returnPath: "/tickets",
    session: pendingSessionReservation,
    continuation: null,
    auditEventId: uuid(6032),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denial race runtime",
  };
  const rotateRaceProjection = await loadRevalidation(
    primaryRaceSession.session.sessionId,
  );
  const rotateRaceSnapshot = jsonObject(
    jsonField(rotateRaceProjection, "snapshot"),
    "LDAP denial rotate snapshot",
  );
  const rotateRaceAt = new Date();
  const rotateRaceSessionId = uuid(6100);
  const rotateRaceMutation = revalidationMutation(
    rotateRaceProjection,
    "rotate",
    "policy_refresh",
    {
      session: {
        sessionId: rotateRaceSessionId,
        familyId: stringField(rotateRaceSnapshot, "rotationFamilyId"),
        tokenDigest: base64Digest("denial-race-rotate-token"),
        csrfDigest: base64Digest("denial-race-rotate-csrf"),
        authenticationMethod: "ldap",
        idleExpiresAt: new Date(
          rotateRaceAt.getTime() + 30 * 60_000,
        ).toISOString(),
        absoluteExpiresAt: stringField(rotateRaceSnapshot, "absoluteExpiresAt"),
      },
    },
  );
  rotateRaceMutation.observedAt = rotateRaceAt.toISOString();
  const primaryDenialRace = await prepareObservedSync(
    raceImmediateBinding,
    6200,
  );
  await assertDeniedFenceRejects(primaryDenialRace, [
    {
      expectBlocked: true,
      invoke: (transaction) =>
        invokeAuthorityIssue(transaction, pendingSessionRequest),
    },
    {
      expectBlocked: false,
      invoke: (transaction) =>
        invokeRevalidation(transaction, rotateRaceMutation),
    },
  ]);
  const [primaryRaceDestinations] = await sql<
    { root_session_count: number; rotate_session_count: number }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${pendingSessionReservation.sessionId}::uuid)
        AS root_session_count,
      (SELECT count(*)::integer FROM public.auth_sessions
       WHERE id=${rotateRaceSessionId}::uuid) AS rotate_session_count
  `;
  assert.deepEqual(primaryRaceDestinations, {
    root_session_count: 0,
    rotate_session_count: 0,
  });
  await completePreparedSync(primaryDenialRace);

  const mfaRaceAccessGrant = uuid(6990);
  const mfaRaceSession = await createRootSession(6250, mfaRaceAccessGrant);
  await advanceTenantBaseline(13, "mfa");
  const mfaRaceRootContinuation = await createRootContinuation(
    5100,
    undefined,
    mfaRaceAccessGrant,
  );
  const pendingContinuationRun = await createAdmittedJit(
    6300,
    mfaRaceAccessGrant,
  );
  const pendingContinuationAppliedAt = new Date();
  const pendingContinuationId = uuid(6330);
  const pendingContinuationReceipt = digest(
    "denial-race-root-continuation-receipt",
  );
  const pendingContinuationRequest: IssueRequest = {
    runId: pendingContinuationRun.runId,
    receipt: pendingContinuationRun.receipt,
    applicationId: pendingContinuationRun.applicationId,
    disposition: "continuation",
    assurance: "step_up_required",
    authenticatedAt: pendingContinuationRun.network.started_at,
    appliedAt: pendingContinuationAppliedAt,
    returnPath: "/tickets",
    session: null,
    continuation: {
      continuationId: pendingContinuationId,
      receiptDigest: pendingContinuationReceipt.toString("base64"),
      expiresAt: new Date(
        pendingContinuationAppliedAt.getTime() + 10 * 60_000,
      ).toISOString(),
    },
    auditEventId: uuid(6332),
    ipAddress: "192.0.2.211",
    userAgent: "Periapsis LDAP denial race runtime",
  };
  const stepUpRaceProjection = await loadRevalidation(
    mfaRaceSession.session.sessionId,
  );
  const stepUpRaceAt = new Date();
  const stepUpRaceContinuationId = uuid(6400);
  const stepUpRaceMutation = revalidationMutation(
    stepUpRaceProjection,
    "step_up",
    "assurance_insufficient",
    {
      continuation: {
        continuationId: stepUpRaceContinuationId,
        receiptDigest: base64Digest("denial-race-step-up-receipt"),
        expiresAt: new Date(stepUpRaceAt.getTime() + 10 * 60_000).toISOString(),
      },
    },
  );
  stepUpRaceMutation.observedAt = stepUpRaceAt.toISOString();
  const mfaDenialRace = await prepareObservedSync(raceImmediateBinding, 6500);
  await assertDeniedFenceRejects(mfaDenialRace, [
    {
      expectBlocked: true,
      invoke: (transaction) =>
        invokeAuthorityIssue(transaction, pendingContinuationRequest),
    },
    {
      expectBlocked: false,
      invoke: (transaction) =>
        invokeRevalidation(transaction, stepUpRaceMutation),
    },
  ]);
  const [mfaRaceDestinations] = await sql<
    { root_continuation_count: number; step_up_continuation_count: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${pendingContinuationId}::uuid) AS root_continuation_count,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${stepUpRaceContinuationId}::uuid)
        AS step_up_continuation_count
  `;
  assert.deepEqual(mfaRaceDestinations, {
    root_continuation_count: 0,
    step_up_continuation_count: 0,
  });
  await completePreparedSync(mfaDenialRace);
  const [committedRaceRevocation] = await sql<
    { session_reason: string; continuation_state: string }[]
  >`
    SELECT session.revoke_reason AS session_reason,
      continuation.state AS continuation_state
    FROM public.auth_sessions AS session
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id=${fixture.tenant}::uuid
     AND continuation.id=${mfaRaceRootContinuation.continuationId}::uuid
    WHERE session.id=${mfaRaceSession.session.sessionId}::uuid
  `;
  assert.deepEqual(committedRaceRevocation, {
    session_reason: "ldap_identity_sync_authoritative_absence",
    continuation_state: "revoked",
  });

  // Re-admit a fresh access generation after the committed races, recreate a
  // grace clock, then prove that a complete inventory with no observation
  // atomically retires access, sessions and continuations.
  const graceTerminalAccessGrant = uuid(6991);
  await advanceTenantBaseline(14, "primary");
  const graceExpiredSession = await createRootSession(
    6700,
    graceTerminalAccessGrant,
  );
  await advanceTenantBaseline(15, "mfa");
  const graceExpiredContinuation = await createRootContinuation(
    6800,
    undefined,
    graceTerminalAccessGrant,
  );
  await configureSync("grace", 120);
  const postRaceEmptyInventory = await prepareEmptySync(graceBinding, 6900);
  const postRaceAbsence = await applyAbsenceChunk(postRaceEmptyInventory);
  assert.equal(postRaceAbsence.revoked_count, 0);
  await completePreparedSync(postRaceEmptyInventory);
  const [beforeGraceExpired] = await sql<
    { session_invalidation_epoch: number; owns_membership: boolean }[]
  >`
    SELECT subject.session_invalidation_epoch::integer,
      access_grant.owns_membership
    FROM public.tenant_mfa_subjects AS subject
    JOIN public.tenant_ldap_provider_access_grants AS access_grant
     ON access_grant.tenant_id=subject.tenant_id
     AND access_grant.user_id=subject.user_id
     AND access_grant.id=${graceTerminalAccessGrant}::uuid
    WHERE subject.tenant_id=${fixture.tenant}::uuid
      AND subject.user_id=${fixture.targetUser}::uuid
  `;
  assert(beforeGraceExpired);
  assert.equal(beforeGraceExpired.owns_membership, false);
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_ldap_sync_absences
      SET first_missing_at=transaction_timestamp()-interval '2 seconds',
          apply_after=transaction_timestamp()-interval '1 second'
      WHERE tenant_id=${fixture.tenant}::uuid
        AND binding_id=${graceBinding}::uuid
        AND external_identity_id=${fixture.externalIdentity}::uuid
        AND status='pending'
    `;
  });
  const graceExpired = await prepareEmptySync(graceBinding, 7000);
  const graceExpiredChunk = await applyAbsenceChunk(graceExpired);
  assert(graceExpiredChunk.inspected_count >= 1);
  assert.equal(graceExpiredChunk.revoked_count, 1);
  await assertAbsenceAuthorityRevoked({
    bindingId: graceBinding,
    accessGrantId: graceTerminalAccessGrant,
    secondaryAccessGrantId: secondaryAccessGrant,
    sourceSessionId: graceExpiredSession.session.sessionId,
    continuationId: graceExpiredContinuation.continuationId,
    priorSubjectEpoch: beforeGraceExpired.session_invalidation_epoch,
  });
  await completePreparedSync(graceExpired);

  // A later admitted login creates a new access generation. Immediate mode
  // must revoke that generation through the same empty-inventory path without
  // relying on the observed no-match planner.
  const replacementAccessGrant = uuid(5300);
  await advanceTenantBaseline(16, "primary");
  const immediateSession = await createRootSession(
    5400,
    replacementAccessGrant,
  );
  await advanceTenantBaseline(17, "mfa");
  const immediateContinuation = await createRootContinuation(
    5500,
    undefined,
    replacementAccessGrant,
  );
  const [beforeImmediate] = await sql<
    { session_invalidation_epoch: number; owns_membership: boolean }[]
  >`
    SELECT subject.session_invalidation_epoch::integer,
      access_grant.owns_membership
    FROM public.tenant_mfa_subjects AS subject
    JOIN public.tenant_ldap_provider_access_grants AS access_grant
      ON access_grant.tenant_id=subject.tenant_id
     AND access_grant.user_id=subject.user_id
     AND access_grant.id=${replacementAccessGrant}::uuid
    WHERE subject.tenant_id=${fixture.tenant}::uuid
      AND subject.user_id=${fixture.targetUser}::uuid
  `;
  assert(beforeImmediate);
  assert.equal(beforeImmediate.owns_membership, false);
  const immediateBinding = await configureSync("immediate");
  const immediate = await prepareEmptySync(immediateBinding, 5600);
  const immediateChunk = await applyAbsenceChunk(immediate);
  assert(immediateChunk.inspected_count >= 1);
  assert.equal(immediateChunk.revoked_count, 1);
  await assertAbsenceAuthorityRevoked({
    bindingId: immediateBinding,
    accessGrantId: replacementAccessGrant,
    secondaryAccessGrantId: secondaryAccessGrant,
    sourceSessionId: immediateSession.session.sessionId,
    continuationId: immediateContinuation.continuationId,
    priorSubjectEpoch: beforeImmediate.session_invalidation_epoch,
  });
  await completePreparedSync(immediate);
} finally {
  await sql.end();
}
