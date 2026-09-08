import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonObject = Record<string, postgres.JSONValue>;

const databaseUrl =
  process.env.PERIAPSIS_PLATFORM_SAML_DIRECT_RUNTIME_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_PLATFORM_SAML_DIRECT_RUNTIME_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18.6 database",
  );
}

const sql = postgres(databaseUrl, { max: 12, onnotice: () => undefined });
const runPrefix = randomBytes(4).toString("hex");
const uuid = (sequence: number): string =>
  `019d8000-2000-7000-8000-${runPrefix}${sequence
    .toString(16)
    .padStart(4, "0")}`;
let uuidSequence = 100;
const nextUuid = (): string => uuid((uuidSequence += 1));
const digest = (label: string): Buffer =>
  createHash("sha256").update(`platform-saml-direct-runtime:${label}`).digest();
const encodedDigest = (label: string): string =>
  digest(label).toString("base64");

const fixture = {
  user: uuid(1),
  provider: uuid(2),
  spKey: uuid(3),
  floor: "019d8000-2000-7000-8000-000000000004",
  identity: uuid(5),
  alias: uuid(6),
  platformGrant: uuid(7),
} as const;

const providerKey = `saml_runtime_${runPrefix}`;
const publicOrigin = "https://periapsis.example.invalid";
const metadataDocument = Buffer.from(
  '<EntityDescriptor entityID="https://idp.example.invalid/metadata"/>',
  "utf8",
);
const metadataDigest = createHash("sha256").update(metadataDocument).digest();
const certificateBundle = [
  Buffer.from("ordered-certificate-zero"),
  Buffer.from("ordered-certificate-one"),
  Buffer.from("ordered-certificate-two"),
] as const;

function isObject(value: postgres.JSONValue | undefined): value is JsonObject {
  return (
    value !== undefined &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function objectValue(
  value: postgres.JSONValue | undefined,
  label: string,
): JsonObject {
  assert(isObject(value), `${label} must be an object`);
  return value;
}

function stringValue(
  value: postgres.JSONValue | undefined,
  label: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

function numberValue(
  value: postgres.JSONValue | undefined,
  label: string,
): number {
  if (typeof value !== "number") {
    throw new TypeError(`${label} must be a number`);
  }
  return value;
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

function audit(): JsonObject {
  return {
    requestId: nextUuid(),
    correlationId: nextUuid(),
    ipAddress: "198.51.100.84",
    userAgent: "Periapsis direct SAML PostgreSQL runtime proof",
  };
}

async function asApi<T>(
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function seed(): Promise<void> {
  const now = new Date();
  now.setMilliseconds(0);
  const metadataMaximum = new Date(now.getTime() + 24 * 60 * 60_000);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (
        id,email,display_name,active,version,authentication_revision,
        created_at,updated_at
      ) VALUES (
        ${fixture.user}::uuid,${`saml-runtime-${runPrefix}@example.invalid`},
        'Direct SAML runtime administrator',true,1,1,${now},${now}
      )
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version,verifier,is_active,bound_at
      ) VALUES (1,${digest("keyring-verifier")},true,${now})
      ON CONFLICT (key_version) DO NOTHING
    `;
    await transaction`
      INSERT INTO public.platform_auth_providers (
        id,key,display_name,description,kind,enabled,
        created_by_user_id,updated_by_user_id,version,created_at,updated_at
      ) VALUES (
        ${fixture.provider}::uuid,${providerKey},${`Direct SAML runtime ${runPrefix}`},
        'Direct platform SAML PostgreSQL runtime proof','saml',true,
        ${fixture.user}::uuid,${fixture.user}::uuid,1,${now},${now}
      )
    `;
    await transaction`
      INSERT INTO public.platform_federated_provider_policies (
        provider_id,provider_kind,configuration_revision,security_revision,
        plan_revision,assurance_policy_revision,account_mode,
        platform_login_enabled,enabled,created_at,updated_at
      ) VALUES (
        ${fixture.provider}::uuid,'saml',1,1,1,1,'disabled',false,true,
        ${now},${now}
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
        ${`${publicOrigin}/api/v1/auth/platform/saml/${providerKey}/metadata`},
        ${`${publicOrigin}/api/v1/auth/platform/saml/acs`},
        1,1,'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'signed_assertion','disabled',ARRAY[]::integer[],
        ARRAY['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport']::text[],
        'persistent_nameid',NULL,NULL,30000000000,3600000000000,1,
        ${now},${now}
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_metadata_snapshots (
        provider_id,revision,document,document_digest,retrieved_at,
        maximum_valid_until
      ) VALUES (
        ${fixture.provider}::uuid,1,${metadataDocument},${metadataDigest},
        ${now},${metadataMaximum}
      )
    `;
    await transaction`
      INSERT INTO public.platform_saml_sp_keys (
        id,provider_id,revision,key_version,nonce,ciphertext,created_at
      ) VALUES (
        ${fixture.spKey}::uuid,${fixture.provider}::uuid,1,1,
        ${Buffer.alloc(12, 0x31)},${Buffer.alloc(64, 0x32)},${now}
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
        0,NULL,${now}
      )
      ON CONFLICT (id,revision) DO NOTHING
    `;
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1','',true),
             set_config('app.platform_saml_direct_policy_write_v1','on',true)
    `;
    await transaction`
      UPDATE ONLY public.platform_saml_login_policies AS policy
      SET account_mode='existing_identity',enabled=true,revision=2,
          updated_at=GREATEST(policy.created_at,${now})
      WHERE policy.provider_id=${fixture.provider}::uuid
        AND policy.revision=1 AND NOT policy.enabled
    `;
    await transaction`
      SELECT set_config('app.platform_saml_direct_policy_write_v1','',true)
    `;
    await transaction`
      INSERT INTO public.user_platform_roles (
        id,user_id,role_id,granted_by_user_id,granted_at
      )
      SELECT ${fixture.platformGrant}::uuid,${fixture.user}::uuid,role.id,
             ${fixture.user}::uuid,${now}
      FROM public.platform_roles AS role
      WHERE role.key='platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.platform_federated_external_identities (
        id,platform_provider_id,provider_kind,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,
        admitted_configuration_revision,admitted_security_revision,
        last_observed_at,last_observation_state,version,resource_version,
        created_at,updated_at
      ) VALUES (
        ${fixture.identity}::uuid,${fixture.provider}::uuid,'saml',
        ${fixture.user}::uuid,'utf8_exact',${Buffer.alloc(32, 0x41)},
        ${Buffer.alloc(12, 0x42)},1,1,1,transaction_timestamp(),
        'known',1,1,transaction_timestamp(),transaction_timestamp()
      )
    `;
    await transaction`
      INSERT INTO public.platform_federated_external_identity_aliases (
        id,platform_provider_id,external_identity_id,key_version,
        subject_digest,created_at
      ) VALUES (
        ${fixture.alias}::uuid,${fixture.provider}::uuid,
        ${fixture.identity}::uuid,1,${digest("subject-alias")},
        transaction_timestamp()
      )
    `;
  });
}

async function loadConfiguration(): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) =>
      transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.begin_platform_saml_authentication_v1(
        ${transaction.json({ loginKey: providerKey })}::jsonb
      ) AS value
    `,
  );
  assert(row?.value !== null && row?.value !== undefined);
  return objectValue(row.value, "SAML begin configuration");
}

function createRequest(configuration: JsonObject): JsonObject {
  const now = new Date();
  now.setMilliseconds(0);
  const operationRunId = nextUuid();
  return {
    begin: {
      operationRunId,
      receiptDigest: encodedDigest(`receipt-${operationRunId}`),
      networkDigest: encodedDigest(`network-${operationRunId}`),
      accountDigest: encodedDigest(`account-${operationRunId}`),
      providerDigest: encodedDigest(`provider-${operationRunId}`),
    },
    current: {
      transactionId: encodedDigest(`transaction-${operationRunId}`),
      materialId: operationRunId,
      requestId: `request-${operationRunId}`,
      relayStateDigest: encodedDigest(`relay-${operationRunId}`),
      browserDigest: encodedDigest(`browser-${operationRunId}`),
      returnPath: "/incidents",
      state: "pending",
      version: 1,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString(),
    },
    pins: {
      protocol: {
        ...objectValue(configuration.pins, "configuration pins"),
        configurationDigest: encodedDigest(`configuration-${operationRunId}`),
      },
      platformFloorPolicyId: stringValue(
        objectValue(configuration.platformFloor, "platform floor").id,
        "platform floor id",
      ),
      platformFloorPolicyRevision: numberValue(
        objectValue(configuration.platformFloor, "platform floor").revision,
        "platform floor revision",
      ),
    },
    audit: audit(),
  };
}

async function createTransaction(request: JsonObject): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) =>
      transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.create_platform_saml_authentication_transaction_v1(
        ${transaction.json(request)}::jsonb
      ) AS value
    `,
  );
  assert(row?.value !== null && row?.value !== undefined);
  return objectValue(row.value, "SAML transaction receipt");
}

function withFreshAudit(request: JsonObject): JsonObject {
  return { ...request, audit: audit() };
}

function applyCommand(
  transaction: JsonObject,
  create: JsonObject,
  configuration: JsonObject,
): JsonObject {
  const now = new Date();
  now.setMilliseconds(0);
  const sessionId = nextUuid();
  const rotationFamilyId = nextUuid();
  const authority = {
    transactionId: stringValue(transaction.transactionId, "transaction id"),
    materialId: stringValue(
      objectValue(create.current, "create current").materialId,
      "material id",
    ),
    expectedVersion: numberValue(transaction.version, "transaction version"),
    pins: objectValue(
      objectValue(create.pins, "create pins").protocol,
      "create protocol pins",
    ),
    responseIdDigest: encodedDigest(`response-${sessionId}`),
    assertionIdDigest: encodedDigest(`assertion-${sessionId}`),
    hasSessionIndex: false,
    hasSessionMaterial: false,
    consumedAt: now.toISOString(),
    returnPath: stringValue(transaction.returnPath, "transaction return path"),
  };
  const floor = objectValue(configuration.platformFloor, "platform floor");
  const validUntil = new Date(now.getTime() + 60 * 60_000);
  const plan = {
    disposition: "immediate_session",
    pins: objectValue(create.pins, "create pins"),
    provenance: {
      provider: { scope: "platform", providerId: fixture.provider },
      userId: fixture.user,
      externalIdentityId: fixture.identity,
      identityRevision: 1,
      userAuthenticationRevision: 1,
      matchedAliasKeyVersion: 1,
      platformAuthorityId: fixture.platformGrant,
      platformAuthorityRevision: 1,
      authenticatedAt: now.toISOString(),
      validUntil: validUntil.toISOString(),
      selectedAssurance: {
        level: "primary",
        authenticatedAt: now.toISOString(),
      },
    },
    subject: {
      aliases: [
        {
          keyVersion: 1,
          digest: encodedDigest("subject-alias"),
        },
      ],
      subjectFormat: "utf8_exact",
      envelope: {
        format: "utf8_exact",
        ciphertext: Buffer.alloc(32, 0x51).toString("base64"),
        nonce: Buffer.alloc(12, 0x52).toString("base64"),
        keyVersion: 1,
      },
    },
    platformFloor: floor,
  };
  return {
    authority,
    plan,
    session: {
      id: sessionId,
      rotationFamilyId,
      tokenDigest: encodedDigest(`token-${sessionId}`),
      csrfSecretDigest: encodedDigest(`csrf-${sessionId}`),
      authenticationMethod: "saml",
      idleExpiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
      absoluteExpiresAt: new Date(now.getTime() + 60 * 60_000).toISOString(),
    },
    sessionAudience: "api",
    recoveryRestricted: false,
    appliedAt: now.toISOString(),
    audit: audit(),
    proofDigest: encodedDigest(`proof-${sessionId}`),
  };
}

async function applyAuthentication(command: JsonObject): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) =>
      transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.apply_platform_saml_authentication_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  assert(row);
  return objectValue(row.value, "SAML apply result");
}

async function recoverApply(command: JsonObject): Promise<JsonObject> {
  const [row] = await asApi(
    (transaction) =>
      transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.recover_platform_saml_authentication_apply_v1(
        ${transaction.json(command)}::jsonb
      ) AS value
    `,
  );
  assert(row);
  return objectValue(row.value, "SAML apply recovery");
}

try {
  const [version] = await sql<{ version: number }[]>`
    SELECT current_setting('server_version_num')::integer AS version
  `;
  assert(version !== undefined && version.version >= 180_000);
  await seed();

  assert.equal(
    await asApi(async (transaction) => {
      const [ready] = await transaction<{ value: boolean }[]>`
          SELECT app.platform_saml_direct_runtime_schema_readiness_v62() AS value
      `;
      return ready?.value;
    }),
    true,
  );
  await assert.rejects(
    asApi(
      (transaction) =>
        transaction`INSERT INTO public.platform_saml_authentication_transactions DEFAULT VALUES`,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const configuration = await loadConfiguration();
  const metadata = await asApi(async (transaction) => {
    const [row] = await transaction<{ value: postgres.JSONValue }[]>`
      SELECT app.load_platform_saml_metadata_projection_v1(${providerKey}) AS value
    `;
    assert(row);
    return objectValue(row.value, "SAML metadata projection");
  });
  const projectedCertificates = metadata.certificates;
  assert(Array.isArray(projectedCertificates));
  assert.equal(projectedCertificates.length, certificateBundle.length);
  for (const [index, certificate] of projectedCertificates.entries()) {
    const projected = objectValue(certificate, `certificate ${index}`);
    assert.equal(
      stringValue(projected.certificateDer, `certificate ${index} DER`),
      certificateBundle[index]?.toString("base64"),
    );
  }

  const create = createRequest(configuration);
  const createResults = await Promise.all(
    Array.from({ length: 6 }, () => createTransaction(withFreshAudit(create))),
  );
  for (const result of createResults.slice(1)) {
    assert.deepEqual(result, createResults[0]);
  }
  const transaction = createResults[0];
  assert(transaction);
  const [createState] = await sql<{ rows: number; audits: number }[]>`
    SELECT
      (SELECT count(*)::integer
       FROM ONLY public.platform_saml_authentication_transactions) AS rows,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action='platform.saml.login.started'
         AND resource_id=${fixture.provider}::uuid) AS audits
  `;
  assert.deepEqual(createState, { rows: 1, audits: 1 });

  const recovery = await asApi(async (transactionSql) => {
    const [row] = await transactionSql<{ value: postgres.JSONValue | null }[]>`
      SELECT app.recover_platform_saml_authentication_transaction_create_v1(
        ${transactionSql.json(withFreshAudit(create))}::jsonb
      ) AS value
    `;
    return row?.value;
  });
  assert.deepEqual(recovery, transaction);
  const mismatchedCreate = structuredClone(create);
  objectValue(mismatchedCreate.current, "mismatched current").returnPath =
    "/different";
  await assert.rejects(
    createTransaction(withFreshAudit(mismatchedCreate)),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const command = applyCommand(transaction, create, configuration);
  const applyResults = await Promise.all(
    Array.from({ length: 6 }, () =>
      applyAuthentication(withFreshAudit(command)),
    ),
  );
  const success = applyResults.filter(
    (result) => result.category === "success",
  );
  assert.equal(success.length, 1);
  for (const result of applyResults) {
    assert(
      result.category === "success" ||
        result.category === "already_applied" ||
        result.category === "stale",
      `unexpected concurrent apply category ${JSON.stringify(result.category)}`,
    );
  }
  await Promise.all(
    applyResults
      .filter((result) => result.category !== "success")
      .map(async () => {
        const recovered = await recoverApply(withFreshAudit(command));
        assert.equal(recovered.matched, true);
        const recoveredResult = objectValue(
          recovered.result,
          "recovered apply result",
        );
        assert.equal(recoveredResult.category, "already_applied");
        assert.equal(recoveredResult.sessionId, success[0]?.sessionId);
      }),
  );
  const [applyState] = await sql<
    { applications: number; sessions: number; audits: number }[]
  >`
    SELECT
      (SELECT count(*)::integer
       FROM ONLY public.platform_saml_authentication_applications) AS applications,
      (SELECT count(*)::integer FROM ONLY public.auth_sessions
       WHERE authentication_method='saml') AS sessions,
      (SELECT count(*)::integer FROM public.platform_audit_events
       WHERE action='platform.saml.login.succeeded'
         AND resource_id=${fixture.identity}::uuid) AS audits
  `;
  assert.deepEqual(applyState, { applications: 1, sessions: 1, audits: 1 });

  const mismatchedApply = structuredClone(command);
  mismatchedApply.proofDigest = encodedDigest("mismatched-proof");
  await assert.rejects(
    applyAuthentication(withFreshAudit(mismatchedApply)),
    (error: unknown) => assertSqlState(error, "23505"),
  );

  const applied = success[0];
  assert(applied);
  const cleanup = {
    result: applied,
    reason: "delivery_failed",
    cleanedUpAt: new Date().toISOString(),
    audit: audit(),
  } satisfies JsonObject;
  await Promise.all(
    Array.from({ length: 6 }, () =>
      asApi(async (transactionSql) => {
        const [row] = await transactionSql<{ value: boolean }[]>`
          SELECT app.cleanup_platform_saml_authentication_v1(
            ${transactionSql.json(withFreshAudit(cleanup))}::jsonb
          ) AS value
        `;
        assert.equal(row?.value, true);
      }),
    ),
  );
  const [cleanupState] = await sql<
    {
      revoked: boolean;
      reason: string;
      cleaned: boolean;
      cleanupAudits: number;
    }[]
  >`
    SELECT session.revoked_at IS NOT NULL AS revoked,
           session.revoke_reason AS reason,
           application.cleaned_up_at IS NOT NULL AS cleaned,
           (SELECT count(*)::integer FROM public.platform_audit_events
            WHERE action='platform.saml.login.delivery_failed'
              AND resource_id=${fixture.provider}::uuid) AS "cleanupAudits"
    FROM ONLY public.platform_saml_authentication_applications AS application
    JOIN ONLY public.auth_sessions AS session ON session.id=application.session_id
  `;
  assert.deepEqual(cleanupState, {
    revoked: true,
    reason: "saml_delivery_failed",
    cleaned: true,
    cleanupAudits: 1,
  });

  const conflictingCleanup = structuredClone(cleanup);
  conflictingCleanup.reason = "protocol_failed";
  await assert.rejects(
    asApi(async (transactionSql) => {
      await transactionSql`
        SELECT app.cleanup_platform_saml_authentication_v1(
          ${transactionSql.json(withFreshAudit(conflictingCleanup))}::jsonb
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
} finally {
  await sql.end();
}
