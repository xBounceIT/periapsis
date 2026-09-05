import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker" | "periapsis_notifier";
type RuntimeActor = { tenant: string | null; user: string };
type SAMLLogoutCommandWire = Readonly<
  Record<
    | "operationRunId"
    | "userId"
    | "sessionId"
    | "tokenDigest"
    | "requestDigest"
    | "requestedAt"
    | "continuationId"
    | "continuationDigest"
    | "continuationExpiresAt",
    string
  > &
    Record<"requestUpstream", boolean> & {
      tenantId: string | null;
      audit: Record<
        "requestId" | "correlationId" | "remoteAddress" | "userAgent",
        string
      >;
    }
>;

const databaseUrl = process.env.PERIAPSIS_SAML_MATERIAL_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SAML_MATERIAL_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sql = postgres(databaseUrl, { max: 3, onnotice: () => undefined });
const uuid = (sequence: number): string =>
  `019d2fb0-3000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): string =>
  createHash("sha256").update(label).digest("base64");

function assertSqlState(
  error: unknown,
  expected: string,
): asserts error is ErrorWithCode {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
}

function isJSONRecord(
  value: unknown,
): value is { [key: string]: postgres.JSONValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function serially<T>(
  values: readonly T[],
  operation: (value: T) => Promise<void>,
): Promise<void> {
  return values.reduce(
    (pending, value) => pending.then(() => operation(value)),
    Promise.resolve(),
  );
}

async function asRole<T>(
  role: RuntimeRole,
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
  actor?: RuntimeActor,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    if (actor !== undefined) {
      const [installed] = await transaction<
        {
          tenant: string;
          user: string;
        }[]
      >`
        SELECT
          set_config('app.tenant_id', coalesce(${actor.tenant}::uuid::text, ''), true)
            AS tenant,
          set_config('app.user_id', ${actor.user}::uuid::text, true)
            AS user
      `;
      assert.deepEqual(installed, {
        tenant: actor.tenant ?? "",
        user: actor.user,
      });
    }
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function revokeSAMLSession(
  transaction: postgres.TransactionSql,
  command: SAMLLogoutCommandWire,
): Promise<{ value: postgres.JSONValue | null }> {
  const [result] = await transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.revoke_local_session_for_logout_v1(
      ${transaction.json(command)}::jsonb
    ) AS value
  `;
  assert(result !== undefined);
  return result;
}

type SAMLFixture = {
  tenant: string;
  user: string;
  membership: string;
  provider: string;
  binding: string;
  externalIdentity: string;
  session: string;
  family: string;
  material: string;
  transactionHex: string;
  application: string;
  hasEnvelope: boolean;
};

function logoutCommand(
  fixture: Pick<SAMLFixture, "user" | "session" | "transactionHex"> & {
    tenant: string | null;
  },
  sequence: number,
  requestUpstream: boolean,
): SAMLLogoutCommandWire {
  const requestedAt = new Date();
  return {
    operationRunId: uuid(sequence),
    tenantId: fixture.tenant,
    userId: fixture.user,
    sessionId: fixture.session,
    tokenDigest: Buffer.from(fixture.transactionHex.repeat(32), "hex").toString(
      "base64",
    ),
    requestDigest: digest(`saml-material-logout-${sequence}`),
    requestUpstream,
    requestedAt: requestedAt.toISOString(),
    continuationId: uuid(sequence + 100),
    continuationDigest: digest(`saml-material-continuation-${sequence}`),
    continuationExpiresAt: new Date(
      requestedAt.getTime() + 60_000,
    ).toISOString(),
    audit: {
      requestId: uuid(sequence + 200),
      correlationId: uuid(sequence + 300),
      remoteAddress: "192.0.2.1",
      userAgent: "periapsis-saml-material-runtime",
    },
  };
}

function assertLocalOnlySnapshot(
  snapshot: postgres.JSONValue | null | undefined,
  fixture: SAMLFixture,
): void {
  assert(isJSONRecord(snapshot));
  assert.equal(snapshot.category, "revoked_local_only");
  assert.equal(snapshot.sessionId, fixture.session);
  assert.equal(snapshot.userId, fixture.user);
  assert.equal(snapshot.tenantId, fixture.tenant);
  assert.equal(snapshot.previousVersion, 1);
  assert.deepEqual(Object.keys(snapshot).toSorted(), [
    "category",
    "observedAt",
    "operationRunId",
    "previousVersion",
    "requestedAt",
    "revokedAt",
    "sessionId",
    "tenantId",
    "userId",
  ]);
}

type SAMLDataViolations = {
  active_legacy_sessions: number;
  invalid_live_session_materials: number;
  invalid_pending_continuation_materials: number;
  active_legacy_continuations: number;
  invalid_application_materials: number;
};

// V49 attests the current catalog/ACL graph; these five data checks retain the
// material-lineage guarantees of the superseded V30 readiness implementation.
async function assertSAMLDataInvariants(
  label: string,
  expected: Partial<SAMLDataViolations> = {},
): Promise<void> {
  const [violations] = await sql<SAMLDataViolations[]>`
    SELECT
      (SELECT count(*)::integer
       FROM public.tenant_saml_session_materials AS material
       LEFT JOIN public.auth_sessions AS session
         ON session.id = material.session_id
        AND session.active_tenant_id = material.tenant_id
       WHERE material.aad_version = 1 AND material.session_id IS NOT NULL
         AND (session.id IS NULL OR session.revoked_at IS NULL))
        AS active_legacy_sessions,
      (SELECT count(*)::integer
       FROM public.auth_sessions AS session
       JOIN public.auth_session_federated_provenance AS provenance
         ON provenance.tenant_id = session.active_tenant_id
        AND provenance.session_id = session.id
        AND provenance.user_id = session.user_id
        AND provenance.primary_kind = 'tenant_provider'
        AND provenance.authentication_method = 'saml'
        AND provenance.provider_kind = 'saml'
       WHERE session.authentication_method = 'saml'
         AND session.revoked_at IS NULL
         AND (SELECT count(*)
              FROM public.tenant_saml_session_materials AS material
              WHERE material.tenant_id = session.active_tenant_id
                AND material.session_id = session.id
                AND material.continuation_id IS NULL
                AND material.user_id = session.user_id
                AND material.provider_id = provenance.provider_id
                AND material.binding_id = provenance.binding_id
                AND material.external_identity_id = provenance.external_identity_id
                AND material.aad_version = 2) <> 1)
        AS invalid_live_session_materials,
      (SELECT count(*)::integer
       FROM public.tenant_post_primary_continuations AS continuation
       WHERE continuation.primary_kind = 'tenant_provider'
         AND continuation.provider_kind = 'saml'
         AND continuation.state = 'pending'
         AND (SELECT count(*)
              FROM public.tenant_saml_session_materials AS material
              WHERE material.tenant_id = continuation.tenant_id
                AND material.session_id IS NULL
                AND material.continuation_id = continuation.id
                AND material.user_id = continuation.user_id
                AND material.provider_id = continuation.provider_id
                AND material.binding_id = continuation.binding_id
                AND material.external_identity_id = continuation.external_identity_id
                AND material.aad_version = 2) <> 1)
        AS invalid_pending_continuation_materials,
      (SELECT count(*)::integer
       FROM public.tenant_saml_session_materials AS material
       LEFT JOIN public.tenant_post_primary_continuations AS continuation
         ON continuation.tenant_id = material.tenant_id
        AND continuation.id = material.continuation_id
       WHERE material.aad_version = 1 AND material.continuation_id IS NOT NULL
         AND (continuation.id IS NULL OR continuation.state = 'pending'))
        AS active_legacy_continuations,
      (SELECT count(*)::integer
       FROM public.tenant_saml_session_materials AS material
       LEFT JOIN public.tenant_federated_authentication_transactions AS transaction
         ON transaction.tenant_id = material.tenant_id
        AND transaction.operation_run_id = material.id
        AND transaction.protocol = 'saml'
        AND transaction.provider_id = material.provider_id
        AND transaction.binding_id = material.binding_id
        AND transaction.state = 'completed'
       LEFT JOIN public.tenant_federated_authentication_applications AS application
         ON application.tenant_id = material.tenant_id
        AND application.protocol = 'saml'
        AND application.transaction_id = transaction.transaction_id
        AND application.category = 'success'
        AND application.user_id = material.user_id
        AND application.provider_id = material.provider_id
        AND application.binding_id = material.binding_id
        AND application.request_snapshot #>> '{samlSession,materialId}' = material.id::text
       WHERE material.aad_version = 2
         AND (transaction.transaction_id IS NULL OR application.id IS NULL))
        AS invalid_application_materials
  `;
  assert.deepEqual(
    violations,
    {
      active_legacy_sessions: 0,
      invalid_live_session_materials: 0,
      invalid_pending_continuation_materials: 0,
      active_legacy_continuations: 0,
      invalid_application_materials: 0,
      ...expected,
    },
    label,
  );
}

const marker: SAMLFixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(10),
  provider: uuid(3),
  binding: uuid(4),
  externalIdentity: uuid(5),
  session: uuid(6),
  family: uuid(7),
  material: uuid(8),
  transactionHex: "11",
  application: uuid(9),
  hasEnvelope: false,
};
const envelope: SAMLFixture = {
  tenant: uuid(11),
  user: uuid(12),
  membership: uuid(20),
  provider: uuid(13),
  binding: uuid(14),
  externalIdentity: uuid(15),
  session: uuid(16),
  family: uuid(17),
  material: uuid(18),
  transactionHex: "22",
  application: uuid(19),
  hasEnvelope: true,
};
const localEnvelope: SAMLFixture = {
  tenant: uuid(21),
  user: uuid(22),
  membership: uuid(30),
  provider: uuid(23),
  binding: uuid(24),
  externalIdentity: uuid(25),
  session: uuid(26),
  family: uuid(27),
  material: uuid(28),
  transactionHex: "33",
  application: uuid(29),
  hasEnvelope: true,
};
const lineage: SAMLFixture = {
  tenant: uuid(31),
  user: uuid(32),
  membership: uuid(40),
  provider: uuid(33),
  binding: uuid(34),
  externalIdentity: uuid(35),
  session: uuid(36),
  family: uuid(37),
  material: uuid(38),
  transactionHex: "44",
  application: uuid(39),
  hasEnvelope: false,
};

async function seedFixture(
  transaction: postgres.TransactionSql,
  fixture: SAMLFixture,
  sequence: number,
): Promise<void> {
  const now = new Date(Date.now() - 60_000);
  const expiresAt = new Date(now.getTime() + 5 * 60_000);
  const idleExpiresAt = new Date(now.getTime() + 60 * 60_000);
  const absoluteExpiresAt = new Date(now.getTime() + 2 * 60 * 60_000);
  const requestSnapshot = {
    samlSession: { materialId: fixture.material },
  };
  await transaction`
    INSERT INTO public.tenants (id, slug, name)
    VALUES (
      ${fixture.tenant}::uuid,
      ${`saml-material-${sequence}`},
      ${`SAML material ${sequence}`}
    )
  `;
  await transaction`
    INSERT INTO public.users (id, email, display_name)
    VALUES (
      ${fixture.user}::uuid,
      ${`saml-material-${sequence}@example.invalid`},
      ${`SAML material user ${sequence}`}
    )
  `;
  await transaction`
    INSERT INTO public.tenant_memberships (
      id,tenant_id,user_id,role,status,created_at,updated_at
    ) VALUES (
      ${fixture.membership}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
      'tenant_admin','active',${now},${now}
    )
  `;
  await transaction`
    INSERT INTO public.tenant_federated_provider_policies (
      tenant_id,provider_id,binding_id,provider_kind,
      configuration_revision,security_revision,plan_revision,
      assurance_policy_revision,jit_mode,no_match_policy,enabled,
      created_at,updated_at
    ) VALUES (
      ${fixture.tenant}::uuid,${fixture.provider}::uuid,${fixture.binding}::uuid,
      'saml',1,1,1,1,'disabled','deny',true,${now},${now}
    )
  `;
  await transaction`
    INSERT INTO public.tenant_federated_external_identities (
      id,tenant_id,provider_id,binding_id,user_id,subject_format,
      subject_ciphertext,subject_nonce,key_version,
      admitted_configuration_revision,last_observed_at,version,
      created_at,updated_at
    ) VALUES (
      ${fixture.externalIdentity}::uuid,${fixture.tenant}::uuid,
      ${fixture.provider}::uuid,${fixture.binding}::uuid,${fixture.user}::uuid,
      'utf8_exact',${Buffer.alloc(17, sequence)},${Buffer.alloc(12, sequence)},
      1,1,${now},1,${now},${now}
    )
  `;
  await transaction`
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${fixture.session}::uuid,${fixture.user}::uuid,${fixture.family}::uuid,
      ${fixture.tenant}::uuid,decode(repeat(${fixture.transactionHex},32),'hex'),
      decode(repeat(${sequence.toString(16).padStart(2, "0")},32),'hex'),
      'saml',${now},${now},${idleExpiresAt},${absoluteExpiresAt},${now}
    )
  `;
  await transaction`
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,session_invalidation_epoch,
      issued_at
    ) VALUES (
      ${fixture.session}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
      1,1,false,'api','tenant_provider',1,${now}
    )
  `;
  await transaction`
    INSERT INTO public.auth_session_federated_provenance (
      tenant_id,session_id,user_id,primary_kind,authentication_method,
      provider_id,binding_id,provider_kind,external_identity_id,
      external_identity_revision,trust_rule_revision,authenticated_at
    ) VALUES (
      ${fixture.tenant}::uuid,${fixture.session}::uuid,${fixture.user}::uuid,
      'tenant_provider','saml',${fixture.provider}::uuid,${fixture.binding}::uuid,
      'saml',${fixture.externalIdentity}::uuid,1,1,${now}
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
      sp_key_revision,configuration_digest,request_id,return_path,state,version,
      created_at,expires_at,completed_at
    ) VALUES (
      decode(repeat(${fixture.transactionHex},32),'hex'),${fixture.tenant}::uuid,
      ${fixture.provider}::uuid,${fixture.binding}::uuid,'saml','saml',
      ${fixture.material}::uuid,decode(repeat('31',32),'hex'),
      decode(repeat(${(32 + sequence).toString(16).padStart(2, "0")},32),'hex'),
      decode(repeat('33',32),'hex'),
      decode(repeat('34',32),'hex'),decode(repeat('35',32),'hex'),
      decode(repeat(${sequence.toString(16).padStart(2, "0")},32),'hex'),
      decode(repeat('37',32),'hex'),1,1,1,1,1,1,1,1,1,
      decode(repeat('38',32),'hex'),1,decode(repeat('39',32),'hex'),
      ${`_request_${sequence}`},'/portal','completed',2,
      ${now},${expiresAt},${now}
    )
  `;
  await transaction`
    INSERT INTO public.tenant_federated_authentication_applications (
      id,tenant_id,protocol,transaction_id,operation_digest,provider_id,
      binding_id,provider_kind,response_id_digest,assertion_id_digest,
      category,primary_kind,user_id,session_id,request_snapshot,result_snapshot,
      applied_at
    ) VALUES (
      ${fixture.application}::uuid,${fixture.tenant}::uuid,'saml',
      decode(repeat(${fixture.transactionHex},32),'hex'),
      decode(repeat(${(40 + sequence).toString(16).padStart(2, "0")},32),'hex'),
      ${fixture.provider}::uuid,${fixture.binding}::uuid,'saml',
      decode(repeat(${(50 + sequence).toString(16).padStart(2, "0")},32),'hex'),
      decode(repeat(${(60 + sequence).toString(16).padStart(2, "0")},32),'hex'),
      'success','tenant_provider',${fixture.user}::uuid,${fixture.session}::uuid,
      ${transaction.json(requestSnapshot)}::jsonb,'{}'::jsonb,${now}
    )
  `;
  await transaction`
    INSERT INTO public.tenant_saml_session_materials (
      id,tenant_id,session_id,continuation_id,user_id,provider_id,binding_id,
      provider_kind,external_identity_id,session_index_digest,aad_version,
      key_version,ciphertext,created_at
    ) VALUES (
      ${fixture.material}::uuid,${fixture.tenant}::uuid,${fixture.session}::uuid,
      NULL,${fixture.user}::uuid,${fixture.provider}::uuid,${fixture.binding}::uuid,
      'saml',${fixture.externalIdentity}::uuid,NULL,2,
      ${fixture.hasEnvelope ? 1 : null}::integer,
      ${fixture.hasEnvelope ? Buffer.alloc(32, sequence) : null}::bytea,
      ${now}
    )
  `;
}

type SAMLOrigin =
  "tenant_provider" | "platform_provider" | "tenant_platform_provider";
type SAMLUpstreamFixture = SAMLFixture & {
  origin: SAMLOrigin;
  ownerSession: string;
  sequence: number;
};

function upstreamFixture(
  origin: SAMLOrigin,
  sequence: number,
): SAMLUpstreamFixture {
  const base = sequence * 1000;
  return {
    origin,
    sequence,
    tenant: uuid(base + 1),
    user: uuid(base + 2),
    membership: uuid(base + 3),
    provider: uuid(base + 4),
    binding: uuid(base + 5),
    externalIdentity: uuid(base + 6),
    session: uuid(base + 7),
    ownerSession: uuid(base + 8),
    family: uuid(base + 9),
    material: uuid(base + 10),
    application: uuid(base + 11),
    transactionHex: (sequence + 80).toString(16).padStart(2, "0"),
    hasEnvelope: true,
  };
}

const upstreamFixtures = [
  upstreamFixture("tenant_provider", 5),
  upstreamFixture("platform_provider", 6),
  upstreamFixture("tenant_platform_provider", 7),
] as const;

async function seedUpstreamConfiguration(
  transaction: postgres.TransactionSql,
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  const platform = fixture.origin !== "tenant_provider";
  const providerKey = `saml_upstream_${fixture.sequence}`;
  const now = new Date(Date.now() - 60_000);
  const maximum = new Date(Date.now() + 60 * 60_000);
  const entity = `https://idp.example.invalid/${providerKey}`;
  const spEntity = platform
    ? `https://periapsis.example.invalid/api/v1/auth/platform/saml/${providerKey}/metadata`
    : `https://periapsis.example.invalid/api/v1/auth/federated/saml/${providerKey}/metadata`;
  const acs = `https://periapsis.example.invalid/api/v1/auth/${platform ? "platform" : "federated"}/saml/acs`;
  // Public synthetic protocol data, not a signed login proof. This suite tests
  // the SQL logout projection; signature/key parsing is covered by Go adapters.
  const metadata = Buffer.from(
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entity}" validUntil="${maximum.toISOString()}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entity}/slo"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entity}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
  );
  const keyId = uuid(fixture.sequence * 1000 + 12);
  if (platform) {
    await transaction`
      INSERT INTO public.platform_auth_providers (
        id,key,display_name,kind,enabled,created_by_user_id,updated_by_user_id
      ) VALUES (${fixture.provider}::uuid,${providerKey},${providerKey},'saml',true,
        ${fixture.user}::uuid,${fixture.user}::uuid)
    `;
    await transaction`
      INSERT INTO public.platform_federated_provider_policies (
        provider_id,provider_kind,configuration_revision,security_revision,
        plan_revision,assurance_policy_revision,account_mode,platform_login_enabled,
        enabled,created_at,updated_at
      ) VALUES (${fixture.provider}::uuid,'saml',1,1,1,1,'disabled',false,true,${now},${now})
    `;
    await transaction`
      INSERT INTO public.platform_saml_login_policies (
        provider_id,account_mode,enabled,revision
      ) VALUES (${fixture.provider}::uuid,'existing_identity',true,1)
    `;
  } else {
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id,tenant_id,key,display_name,kind,enabled,
        created_by_membership_id,updated_by_membership_id
      ) VALUES (${fixture.provider}::uuid,${fixture.tenant}::uuid,
        ${providerKey},${providerKey},'saml',true,
        ${fixture.membership}::uuid,${fixture.membership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_bindings (
        id,tenant_id,provider_id,key,enabled,current_access_epoch_id,
        created_by_membership_id,updated_by_membership_id
      ) VALUES (${fixture.binding}::uuid,${fixture.tenant}::uuid,
        ${fixture.provider}::uuid,${providerKey},true,${uuid(fixture.sequence * 1000 + 13)}::uuid,
        ${fixture.membership}::uuid,${fixture.membership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_login_keys (tenant_id,binding_family,binding_id,key)
      VALUES (${fixture.tenant}::uuid,'tenant_provider',${fixture.binding}::uuid,${providerKey})
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (id,tenant_id,kind,key,authoritative)
      VALUES (${uuid(fixture.sequence * 1000 + 14)}::uuid,${fixture.tenant}::uuid,
        'identity_provider_access',${`identity_provider_access:${fixture.binding}:1`},true)
    `;
    await transaction`
      INSERT INTO public.tenant_identity_provider_access_epochs (
        id,tenant_id,binding_id,provider_id,source_id,sequence,started_by_membership_id
      ) VALUES (${uuid(fixture.sequence * 1000 + 13)}::uuid,${fixture.tenant}::uuid,
        ${fixture.binding}::uuid,${fixture.provider}::uuid,${uuid(fixture.sequence * 1000 + 14)}::uuid,
        1,${fixture.membership}::uuid)
    `;
  }
  // Only closed, test-owned relation names are interpolated; every value remains
  // a SQL parameter. Both origins use the canonical configuration projector.
  const prefix = platform ? "platform" : "tenant";
  const tenantColumn = platform ? "" : "tenant_id,";
  const tenantValue = platform ? "" : "$1::uuid,";
  await transaction.unsafe(
    `WITH fixture_tenant AS (SELECT $1::uuid)
    INSERT INTO public.${prefix}_saml_provider_configurations (
      ${tenantColumn}provider_id,expected_entity_id,sp_entity_id,acs_url,
      sp_key_revision,metadata_revision,redirect_signature_algorithm,signature_policy,
      encryption_policy,decryption_key_versions,requested_authn_contexts,subject_source,
      clock_skew_nanoseconds,max_authentication_age_nanoseconds
    ) VALUES (${tenantValue}$2::uuid,$3,$4,$5,1,1,
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256','signed_assertion','disabled',
      ARRAY[]::integer[],ARRAY['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'],
      'persistent_nameid',30000000000,3600000000000)`,
    [fixture.tenant, fixture.provider, entity, spEntity, acs],
  );
  await transaction.unsafe(
    `WITH fixture_tenant AS (SELECT $1::uuid)
    INSERT INTO public.${prefix}_saml_metadata_snapshots (
      ${tenantColumn}provider_id,revision,document,document_digest,retrieved_at,maximum_valid_until
    ) VALUES (${tenantValue}$2::uuid,1,$3::bytea,sha256($3::bytea),$4::timestamptz,$5::timestamptz)`,
    [
      fixture.tenant,
      fixture.provider,
      metadata,
      now.toISOString(),
      maximum.toISOString(),
    ],
  );
  if (platform) {
    await transaction`
      INSERT INTO public.platform_saml_sp_keys (id,provider_id,revision,key_version,nonce,ciphertext)
      VALUES (${keyId}::uuid,${fixture.provider}::uuid,1,1,${Buffer.alloc(12, 61)},${Buffer.alloc(32, 62)})
    `;
  } else {
    await transaction`
      INSERT INTO public.tenant_saml_sp_keys (tenant_id,id,provider_id,revision,key_version,ciphertext)
      VALUES (${fixture.tenant}::uuid,${keyId}::uuid,${fixture.provider}::uuid,1,1,${Buffer.alloc(32, 62)})
    `;
  }
  await transaction.unsafe(
    `WITH fixture_tenant AS (SELECT $1::uuid)
    INSERT INTO public.${prefix}_saml_sp_certificates (
      ${tenantColumn}key_id,sequence,certificate_der
    ) VALUES (${tenantValue}$2::uuid,0,$3::bytea)`,
    [fixture.tenant, keyId, Buffer.from("synthetic-public-SP-certificate")],
  );
  const [projection] = platform
    ? await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.private_platform_saml_direct_configuration_v1(${fixture.provider}::uuid,NULL) AS value
      `
    : await transaction<{ value: postgres.JSONValue }[]>`
        SELECT app.private_saml_logout_configuration_record_v1(
          ${fixture.tenant}::uuid,${fixture.provider}::uuid,${fixture.binding}::uuid
        ) AS value
      `;
  assert(
    isJSONRecord(projection?.value),
    `${fixture.origin}: configuration unavailable`,
  );
  const projectedMetadata = platform
    ? projection.value.metadata
    : projection.value;
  assert(isJSONRecord(projectedMetadata));
  assert.equal(
    projectedMetadata[platform ? "document" : "metadataDocument"],
    metadata.toString("base64"),
  );
  assert.equal(
    projectedMetadata[platform ? "digest" : "metadataDigest"],
    createHash("sha256").update(metadata).digest("base64"),
  );
  return projection.value;
}

async function seedUpstreamFixture(
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  return sql.begin(async (transaction) => {
    // Privileged stored-state fixture, as above; every tested revoke/claim below
    // runs with ordinary triggers enabled and only the real API role.
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    const now = new Date(Date.now() - 60_000);
    if (fixture.origin === "tenant_provider") {
      await seedFixture(transaction, fixture, fixture.sequence);
    } else {
      await transaction`
        INSERT INTO public.users (id,email,display_name)
        VALUES (${fixture.user}::uuid,${`saml-upstream-${fixture.sequence}@example.invalid`},'SAML upstream fixture')
      `;
      await transaction`
        INSERT INTO public.auth_sessions (
          id,user_id,rotation_family_id,token_digest,csrf_secret_digest,authentication_method,
          last_seen_at,idle_expires_at,absolute_expires_at,created_at
        ) VALUES (${fixture.ownerSession}::uuid,${fixture.user}::uuid,${fixture.family}::uuid,
          ${Buffer.from(fixture.transactionHex.repeat(32), "hex")},${Buffer.alloc(32, fixture.sequence)},
          'saml',${now},${new Date(Date.now() + 30 * 60_000)},${new Date(Date.now() + 60 * 60_000)},${now})
      `;
      await transaction`
        INSERT INTO public.auth_session_platform_saml_states (
          session_id,user_id,session_version,user_authentication_revision,recovery_restricted,audience,issued_at
        ) VALUES (${fixture.ownerSession}::uuid,${fixture.user}::uuid,1,1,false,'api',${now})
      `;
      if (fixture.origin === "tenant_platform_provider") {
        await transaction`
          INSERT INTO public.tenants (id,slug,name)
          VALUES (${fixture.tenant}::uuid,'saml-upstream-admitted','SAML upstream admission')
        `;
        await transaction`
          INSERT INTO public.tenant_memberships (id,tenant_id,user_id,role,status)
          VALUES (${fixture.membership}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,'tenant_admin','active')
        `;
        await transaction`
          UPDATE public.auth_sessions SET revoked_at=transaction_timestamp(),revoke_reason='rotated'
          WHERE id=${fixture.ownerSession}::uuid
        `;
        await transaction`
          INSERT INTO public.auth_sessions (
            id,user_id,rotation_family_id,active_tenant_id,token_digest,csrf_secret_digest,
            authentication_method,last_seen_at,idle_expires_at,absolute_expires_at,created_at
          ) SELECT ${fixture.session}::uuid,user_id,rotation_family_id,${fixture.tenant}::uuid,
              ${Buffer.from((fixture.sequence + 90).toString(16).repeat(32), "hex")},csrf_secret_digest,
              authentication_method,last_seen_at,idle_expires_at,absolute_expires_at,transaction_timestamp()
            FROM public.auth_sessions WHERE id=${fixture.ownerSession}::uuid
        `;
        await transaction`
          INSERT INTO public.auth_session_mfa_states (
            session_id,tenant_id,user_id,session_version,identity_epoch,recovery_restricted,
            audience,primary_kind,session_invalidation_epoch,issued_at
          ) VALUES (${fixture.session}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
            1,1,false,'api','tenant_platform_provider',1,${now})
        `;
        await transaction`
          INSERT INTO public.auth_session_tenant_platform_federated_provenance (
            tenant_id,session_id,user_id,authentication_method,platform_provider_id,binding_id,
            access_epoch_id,access_source_id,access_grant_id,membership_id,external_identity_id,
            external_identity_revision,provider_revision,binding_revision,security_revision,
            mapping_revision,authorization_revision,subject_alias_key_version,trust_rule_revision,authenticated_at
          ) VALUES (${fixture.tenant}::uuid,${fixture.session}::uuid,${fixture.user}::uuid,
            'saml',${fixture.provider}::uuid,${fixture.binding}::uuid,
            ${uuid(7101)}::uuid,${uuid(7102)}::uuid,${uuid(7103)}::uuid,
            ${fixture.membership}::uuid,${fixture.externalIdentity}::uuid,1,1,1,1,1,1,1,1,${now})
        `;
        await transaction`
          INSERT INTO public.platform_saml_tenant_switch_commands (
            source_session_id,expected_version,target_tenant_id,target_tenant_version,
            membership_id,binding_id,binding_version,mapping_revision,authorization_revision,
            access_epoch_id,access_epoch_version,access_source_id,access_grant_id,access_grant_version,
            request_digest,request_snapshot,decision,rotated_session_id,result_snapshot,applied_at
          ) VALUES (${fixture.ownerSession}::uuid,1,${fixture.tenant}::uuid,1,
            ${fixture.membership}::uuid,${fixture.binding}::uuid,1,1,1,
            ${uuid(7101)}::uuid,1,${uuid(7102)}::uuid,${uuid(7103)}::uuid,1,
            ${Buffer.alloc(32, 71)},'{}','rotated',${fixture.session}::uuid,'{}',transaction_timestamp())
        `;
      }
    }
    const configuration = await seedUpstreamConfiguration(transaction, fixture);
    if (fixture.origin === "tenant_provider") {
      await transaction`
        UPDATE public.tenant_saml_session_materials
        SET logout_configuration=${transaction.json(configuration)}::jsonb
        WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.material}::uuid
      `;
    } else {
      await transaction`
        INSERT INTO public.platform_saml_session_materials (
          id,session_id,user_id,platform_provider_id,external_identity_id,
          login_policy_revision,key_version,nonce,ciphertext,logout_configuration,created_at
        ) VALUES (${fixture.material}::uuid,${fixture.ownerSession}::uuid,${fixture.user}::uuid,
          ${fixture.provider}::uuid,${fixture.externalIdentity}::uuid,1,1,
          ${Buffer.alloc(12, fixture.sequence)},${Buffer.alloc(32, fixture.sequence)},
          ${transaction.json(configuration)}::jsonb,${now})
      `;
    }
    return configuration;
  });
}

async function claimSAMLContinuation(
  command: SAMLLogoutCommandWire,
  overrides: Partial<{ continuationId: string; tokenDigest: string }> = {},
): Promise<postgres.JSONValue | null> {
  return asRole("periapsis_api", async (transaction) => {
    const [row] = await transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.claim_session_logout_continuation_v1(${transaction.json({
        continuationId: command.continuationId,
        tokenDigest: command.continuationDigest,
        claimedAt: new Date().toISOString(),
        ...overrides,
      })}::jsonb) AS value
    `;
    assert(row);
    return row.value;
  });
}

async function upstreamLogoutSnapshot(
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  const [row] = await sql<{ value: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'sessions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.auth_sessions t WHERE t.user_id=${fixture.user}::uuid),
      'tenantStates',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.session_id) FROM public.auth_session_mfa_states t WHERE t.user_id=${fixture.user}::uuid),
      'platformStates',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.session_id) FROM public.auth_session_platform_saml_states t WHERE t.user_id=${fixture.user}::uuid),
      'tenantMaterials',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.tenant_saml_session_materials t WHERE t.user_id=${fixture.user}::uuid),
      'platformMaterials',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.platform_saml_session_materials t WHERE t.user_id=${fixture.user}::uuid),
      'commands',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.operation_run_id) FROM public.tenant_oidc_logout_commands t WHERE t.session_id IN (${fixture.session}::uuid,${fixture.ownerSession}::uuid)),
      'continuations',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.session_logout_continuations t WHERE t.user_id=${fixture.user}::uuid),
      'legacyCommands',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.operation_run_id) FROM public.tenant_saml_logout_commands t WHERE t.session_id IN (${fixture.session}::uuid,${fixture.ownerSession}::uuid)),
      'tenantAudit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.audit_events t WHERE t.resource_id IN (${fixture.session}::uuid,${fixture.ownerSession}::uuid)),
      'platformAudit',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM public.platform_audit_events t WHERE t.resource_id IN (${fixture.session}::uuid,${fixture.ownerSession}::uuid))
    ) AS value
  `;
  assert(row);
  return row.value;
}

async function advanceUpstreamMetadata(
  fixture: SAMLUpstreamFixture,
): Promise<void> {
  const platform = fixture.origin !== "tenant_provider";
  const prefix = platform ? "platform" : "tenant";
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction.unsafe(
      `INSERT INTO public.${prefix}_saml_metadata_snapshots (
        ${platform ? "" : "tenant_id,"}provider_id,revision,document,document_digest,retrieved_at,maximum_valid_until
      ) SELECT ${platform ? "" : "tenant_id,"}provider_id,2,
          convert_to(replace(convert_from(document,'UTF8'),'/slo','/successor-slo'),'UTF8'),
          sha256(convert_to(replace(convert_from(document,'UTF8'),'/slo','/successor-slo'),'UTF8')),
          retrieved_at,maximum_valid_until
        FROM public.${prefix}_saml_metadata_snapshots WHERE provider_id=$1::uuid AND revision=1`,
      [fixture.provider],
    );
    await transaction.unsafe(
      `UPDATE public.${prefix}_saml_provider_configurations SET metadata_revision=2 WHERE provider_id=$1::uuid`,
      [fixture.provider],
    );
  });
  const [current] = platform
    ? await sql<{ value: postgres.JSONValue }[]>`
        SELECT app.private_platform_saml_direct_configuration_v1(${fixture.provider}::uuid,NULL) AS value
      `
    : await sql<{ value: postgres.JSONValue }[]>`
        SELECT app.private_saml_logout_configuration_record_v1(${fixture.tenant}::uuid,${fixture.provider}::uuid,${fixture.binding}::uuid) AS value
      `;
  assert(isJSONRecord(current?.value));
  const metadata = platform ? current.value.metadata : current.value;
  assert(isJSONRecord(metadata));
  assert.equal(metadata[platform ? "revision" : "metadataRevision"], 2);
}

async function verifyUpstreamLogout(
  fixture: SAMLUpstreamFixture,
): Promise<void> {
  const configuration = await seedUpstreamFixture(fixture);
  await advanceUpstreamMetadata(fixture);
  const tenant = fixture.origin === "platform_provider" ? null : fixture.tenant;
  const session =
    fixture.origin === "platform_provider"
      ? fixture.ownerSession
      : fixture.session;
  const command = logoutCommand(
    {
      ...fixture,
      tenant,
      session,
      transactionHex:
        fixture.origin === "tenant_platform_provider"
          ? (fixture.sequence + 90).toString(16)
          : fixture.transactionHex,
    },
    fixture.sequence * 1000 + 500,
    true,
  );
  // Match RevokeLocalSession: the verified credential supplies transaction-local
  // audit context, and the writer independently reattests the session/token.
  let revokeAttempt = 0;
  const revoke = async (value = command) => {
    revokeAttempt += 1;
    try {
      return await asRole(
        "periapsis_api",
        (transaction) => revokeSAMLSession(transaction, value),
        { tenant: value.tenantId, user: value.userId },
      );
    } catch (cause) {
      throw new Error(`${fixture.origin}: revoke attempt ${revokeAttempt}`, {
        cause,
      });
    }
  };
  const before = await upstreamLogoutSnapshot(fixture);
  assert.equal(
    (
      await revoke({
        ...command,
        tokenDigest: digest("wrong upstream session credential"),
      })
    ).value,
    null,
  );
  assert.deepEqual(await upstreamLogoutSnapshot(fixture), before);
  const result = (await revoke()).value;
  assert(isJSONRecord(result), `${fixture.origin}: missing logout receipt`);
  assert.equal(result.category, "logout_continuation", fixture.origin);
  assert.equal(result.continuationId, command.continuationId);
  assert.equal(result.sessionId, session);
  assert.equal(result.tenantId, tenant);
  assert.equal(result.previousVersion, 1);
  assert.deepEqual(Object.keys(result).toSorted(), [
    "category",
    "continuationExpiresAt",
    "continuationId",
    "observedAt",
    "operationRunId",
    "previousVersion",
    "requestedAt",
    "revokedAt",
    "sessionId",
    "tenantId",
    "userId",
  ]);
  const beforeClaim = await upstreamLogoutSnapshot(fixture);
  assert.deepEqual((await revoke()).value, result);
  assert.equal(
    (
      await revoke({
        ...command,
        requestDigest: digest("divergent upstream logout"),
      })
    ).value,
    null,
  );
  assert.equal(
    await claimSAMLContinuation(command, {
      tokenDigest: digest("wrong continuation credential"),
    }),
    null,
  );
  assert.equal(
    await claimSAMLContinuation(command, { continuationId: uuid(99990) }),
    null,
  );
  assert.deepEqual(await upstreamLogoutSnapshot(fixture), beforeClaim);

  const claims = await Promise.all(
    Array.from({ length: 3 }, () => claimSAMLContinuation(command)),
  );
  const winners = claims.filter((claim) => claim !== null);
  assert.equal(
    winners.length,
    1,
    `${fixture.origin}: one protected-material disclosure`,
  );
  const claimed = winners[0];
  assert(isJSONRecord(claimed));
  assert.equal(claimed.category, "saml_logout");
  assert.equal(claimed.continuationId, command.continuationId);
  assert.equal(claimed.operationRunId, command.operationRunId);
  assert.equal(claimed.sessionId, session);
  assert.equal(claimed.userId, fixture.user);
  assert.equal(claimed.tenantId, tenant);
  assert.equal(claimed.previousVersion, 1);
  assert.equal(claimed.materialId, fixture.material);
  assert.deepEqual(Object.keys(claimed).toSorted(), [
    ...(fixture.origin === "tenant_platform_provider" ? ["admission"] : []),
    "bindingId",
    "category",
    "configuration",
    "continuationId",
    "expiresAt",
    "materialId",
    "observedAt",
    "operationRunId",
    "previousVersion",
    "protectedMaterial",
    "provider",
    "requestedClaimedAt",
    "revokedAt",
    "sessionId",
    "tenantId",
    "userId",
  ]);
  assert.deepEqual(
    claimed.configuration,
    configuration,
    `${fixture.origin}: exact immutable metadata/configuration`,
  );
  assert.deepEqual(
    claimed.provider,
    fixture.origin === "tenant_provider"
      ? {
          scope: "tenant",
          tenantId: tenant,
          providerId: fixture.provider,
          bindingId: fixture.binding,
        }
      : { scope: "platform", providerId: fixture.provider },
  );
  assert.equal(
    claimed.bindingId,
    fixture.origin === "tenant_provider" ? fixture.binding : null,
  );
  assert.deepEqual(
    claimed.admission,
    fixture.origin === "tenant_platform_provider"
      ? { tenantId: tenant, bindingId: fixture.binding }
      : undefined,
  );
  assert.deepEqual(claimed.protectedMaterial, {
    keyVersion: 1,
    ciphertext: (fixture.origin === "tenant_provider"
      ? Buffer.alloc(32, fixture.sequence)
      : Buffer.concat([
          Buffer.alloc(12, fixture.sequence),
          Buffer.alloc(32, fixture.sequence),
        ])
    ).toString("base64"),
  });
  const consumed = await upstreamLogoutSnapshot(fixture);
  assert.equal(await claimSAMLContinuation(command), null);
  const replay = (await revoke()).value;
  assert(isJSONRecord(replay));
  assert.equal(replay.category, "revoked_local_only");
  assert.equal(replay.continuationId, undefined);
  assert.equal(replay.configuration, undefined);
  assert.equal(replay.protectedMaterial, undefined);
  assert.equal(
    (await revoke({ ...command, requestUpstream: false })).value,
    null,
  );
  assert.deepEqual(await upstreamLogoutSnapshot(fixture), consumed);
  const [state] = await sql<
    {
      revoked: boolean;
      commands: number;
      continuations: number;
      consumed: number;
      audits: number;
    }[]
  >`
    SELECT
      (SELECT revoked_at IS NOT NULL FROM public.auth_sessions WHERE id=${session}::uuid) AS revoked,
      (SELECT count(*)::integer FROM public.tenant_oidc_logout_commands WHERE session_id=${session}::uuid) AS commands,
      (SELECT count(*)::integer FROM public.session_logout_continuations WHERE session_id=${session}::uuid) AS continuations,
      (SELECT count(*)::integer FROM public.session_logout_continuations WHERE session_id=${session}::uuid AND consumed_at IS NOT NULL) AS consumed,
      ((SELECT count(*) FROM public.audit_events WHERE resource_id=${session}::uuid AND action='tenant.identity.session_local_logout')
        + (SELECT count(*) FROM public.platform_audit_events WHERE resource_id=${session}::uuid AND action='platform.identity.session_local_logout'))::integer AS audits
  `;
  assert.deepEqual(state, {
    revoked: true,
    commands: 1,
    continuations: 1,
    consumed: 1,
    audits: 1,
  });
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18.6"),
    "runtime harness requires PostgreSQL 18.6",
  );

  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await seedFixture(transaction, marker, 1);
    await seedFixture(transaction, envelope, 2);
    await seedFixture(transaction, localEnvelope, 3);
    await seedFixture(transaction, lineage, 4);
  });

  const [ready] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(ready, { ready: true });
  await assertSAMLDataInvariants("seeded SAML material lineage");

  await serially(
    ["tenant_saml_session_materials", "tenant_saml_logout_commands"],
    async (relation) => {
      await assert.rejects(
        asRole("periapsis_api", (transaction) =>
          transaction.unsafe(`SELECT count(*) FROM public.${relation}`),
        ),
        (error) => {
          assertSqlState(error, "42501");
          return true;
        },
      );
    },
  );
  await serially(
    ["periapsis_worker", "periapsis_notifier"] as const,
    async (role) => {
      await assert.rejects(
        asRole(
          role,
          (transaction) =>
            transaction`
            SELECT app.revoke_local_session_for_logout_v1('{}'::jsonb)
          `,
        ),
        (error) => {
          assertSqlState(error, "42501");
          return true;
        },
      );
    },
  );
  await serially(
    ["periapsis_api", "periapsis_worker", "periapsis_notifier"] as const,
    async (role) => {
      await assert.rejects(
        asRole(
          role,
          (transaction) => transaction`
            SELECT app.revoke_local_saml_session_v1(${marker.user}::uuid, '{}'::jsonb)
          `,
        ),
        (error) => {
          assertSqlState(error, "42501");
          return true;
        },
      );
    },
  );

  const markerCommand = logoutCommand(marker, 70, false);
  const [markerResult] = await asRole(
    "periapsis_api",
    async (transaction) => [
      await revokeSAMLSession(transaction, markerCommand),
    ],
    { tenant: marker.tenant, user: marker.user },
  );
  const markerSnapshot = markerResult?.value;
  assertLocalOnlySnapshot(markerSnapshot, marker);

  const [markerReplay] = await asRole(
    "periapsis_api",
    async (transaction) => [
      await revokeSAMLSession(transaction, markerCommand),
    ],
    { tenant: marker.tenant, user: marker.user },
  );
  assert.deepEqual(markerReplay?.value, markerResult.value);
  const [divergentReplay] = await asRole(
    "periapsis_api",
    async (transaction) => [
      await revokeSAMLSession(transaction, {
        ...markerCommand,
        requestUpstream: true,
      }),
    ],
    { tenant: marker.tenant, user: marker.user },
  );
  assert.deepEqual(divergentReplay, { value: null });

  // The current logout boundary authenticates the exact session credential,
  // not caller-installed tenant/user GUCs. Each mismatched component fails closed.
  await serially(
    [
      { tenantId: envelope.tenant },
      { userId: envelope.user },
      { sessionId: envelope.session },
      { tokenDigest: digest("wrong-session-credential") },
    ],
    async (mismatch) => {
      const rejected = await asRole(
        "periapsis_api",
        (transaction) =>
          revokeSAMLSession(transaction, { ...markerCommand, ...mismatch }),
        { tenant: marker.tenant, user: marker.user },
      );
      assert.deepEqual(rejected, { value: null });
    },
  );

  const localEnvelopeCommand = logoutCommand(localEnvelope, 73, false);
  const [localEnvelopeResult] = await asRole(
    "periapsis_api",
    async (transaction) => [
      await revokeSAMLSession(transaction, localEnvelopeCommand),
    ],
    { tenant: localEnvelope.tenant, user: localEnvelope.user },
  );
  const localEnvelopeSnapshot = localEnvelopeResult?.value;
  assertLocalOnlySnapshot(localEnvelopeSnapshot, localEnvelope);

  const envelopeCommand = logoutCommand(envelope, 72, true);
  const [envelopeResult] = await asRole(
    "periapsis_api",
    async (transaction) => [
      await revokeSAMLSession(transaction, envelopeCommand),
    ],
    { tenant: envelope.tenant, user: envelope.user },
  );
  const envelopeSnapshot = envelopeResult?.value;
  // An encrypted envelope without an admitted logout configuration cannot
  // produce an upstream continuation or disclose protected material.
  assertLocalOnlySnapshot(envelopeSnapshot, envelope);

  const [state] = await sql<
    {
      revoked_sessions: number;
      advanced_states: number;
      commands: number;
      material_ids: number;
      skipped_materials: number;
      continuations: number;
      legacy_commands: number;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.auth_sessions
      WHERE id IN (
         ${marker.session}::uuid,${envelope.session}::uuid,
         ${localEnvelope.session}::uuid
       )
         AND revoked_at IS NOT NULL) AS revoked_sessions,
      (SELECT count(*)::integer FROM public.auth_session_mfa_states
       WHERE session_id IN (
         ${marker.session}::uuid,${envelope.session}::uuid,
         ${localEnvelope.session}::uuid
       )
         AND session_version = 2) AS advanced_states,
      (SELECT count(*)::integer FROM public.tenant_oidc_logout_commands
       WHERE session_id IN (
         ${marker.session}::uuid,${envelope.session}::uuid,
         ${localEnvelope.session}::uuid
       ))
        AS commands,
      (SELECT count(*)::integer FROM public.tenant_saml_logout_commands)
        AS legacy_commands,
      (SELECT count(*)::integer FROM public.session_logout_continuations)
        AS continuations,
      (SELECT count(*)::integer FROM public.tenant_saml_session_materials
       WHERE (id,logout_operation_run_id) IN (
         (${marker.material}::uuid,${markerCommand.operationRunId}::uuid),
         (${envelope.material}::uuid,${envelopeCommand.operationRunId}::uuid),
         (${localEnvelope.material}::uuid,${localEnvelopeCommand.operationRunId}::uuid)
       ) AND logout_disposition = 'skipped') AS skipped_materials,
      (SELECT count(DISTINCT id)::integer
       FROM public.tenant_saml_session_materials
       WHERE id IN (
         ${marker.material}::uuid,${envelope.material}::uuid,
         ${localEnvelope.material}::uuid
       ))
        AS material_ids
  `;
  assert.deepEqual(state, {
    revoked_sessions: 3,
    advanced_states: 3,
    commands: 3,
    material_ids: 3,
    skipped_materials: 3,
    continuations: 0,
    legacy_commands: 0,
  });

  const rotatedSession = uuid(90);
  const stepUpContinuation = uuid(91);
  const promotedSession = uuid(92);
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.auth_sessions
      SET revoked_at = transaction_timestamp(),revoke_reason = 'rotated'
      WHERE id = ${lineage.session}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      )
      SELECT ${rotatedSession}::uuid,user_id,rotation_family_id,active_tenant_id,
        decode(repeat('71',32),'hex'),decode(repeat('72',32),'hex'),
        authentication_method,mfa_satisfied_at,transaction_timestamp(),
        idle_expires_at,absolute_expires_at,transaction_timestamp()
      FROM public.auth_sessions WHERE id = ${lineage.session}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        issued_at
      )
      SELECT ${rotatedSession}::uuid,tenant_id,user_id,2,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        transaction_timestamp()
      FROM public.auth_session_mfa_states
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND session_id = ${lineage.session}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        provider_id,binding_id,provider_kind,external_identity_id,
        external_identity_revision,trust_rule_revision,authenticated_at
      )
      SELECT tenant_id,${rotatedSession}::uuid,user_id,primary_kind,
        authentication_method,provider_id,binding_id,provider_kind,
        external_identity_id,external_identity_revision,trust_rule_revision,
        transaction_timestamp()
      FROM public.auth_session_federated_provenance
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND session_id = ${lineage.session}::uuid
    `;
    await transaction`
      UPDATE public.tenant_saml_session_materials
      SET session_id = ${rotatedSession}::uuid
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND id = ${lineage.material}::uuid
    `;
  });
  const [afterRotation] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(afterRotation, { ready: true });
  await assertSAMLDataInvariants("rotation retains the original material ID");

  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.auth_sessions
      SET revoked_at = transaction_timestamp(),revoke_reason = 'mfa_step_up'
      WHERE id = ${rotatedSession}::uuid
    `;
    await transaction`
      INSERT INTO public.tenant_post_primary_continuations (
        id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
        primary_kind,provider_id,binding_id,provider_kind,external_identity_id,
        primary_revision,session_invalidation_epoch,state,version,created_at,
        expires_at
      ) VALUES (
        ${stepUpContinuation}::uuid,${lineage.tenant}::uuid,
        ${lineage.user}::uuid,decode(repeat('73',32),'hex'),1,'mfa.step_up',
        'api','tenant_provider',${lineage.provider}::uuid,
        ${lineage.binding}::uuid,'saml',${lineage.externalIdentity}::uuid,
        1,1,'pending',1,transaction_timestamp(),
        date_trunc('milliseconds',transaction_timestamp()) + interval '5 minutes'
      )
    `;
    await transaction`
      UPDATE public.tenant_saml_session_materials
      SET session_id = NULL,continuation_id = ${stepUpContinuation}::uuid
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND id = ${lineage.material}::uuid
    `;
  });
  const [afterStepUp] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(afterStepUp, { ready: true });
  await assertSAMLDataInvariants(
    "step-up transfers material to the continuation",
  );

  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_post_primary_continuations
      SET state = 'consumed',version = 2,consumed_at = transaction_timestamp()
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND id = ${stepUpContinuation}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id,user_id,rotation_family_id,active_tenant_id,token_digest,
        csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
        idle_expires_at,absolute_expires_at,created_at
      )
      SELECT ${promotedSession}::uuid,user_id,rotation_family_id,active_tenant_id,
        decode(repeat('74',32),'hex'),decode(repeat('75',32),'hex'),
        authentication_method,transaction_timestamp(),transaction_timestamp(),
        idle_expires_at,absolute_expires_at,transaction_timestamp()
      FROM public.auth_sessions WHERE id = ${rotatedSession}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_session_mfa_states (
        session_id,tenant_id,user_id,session_version,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        issued_at
      )
      SELECT ${promotedSession}::uuid,tenant_id,user_id,3,identity_epoch,
        recovery_restricted,audience,primary_kind,session_invalidation_epoch,
        transaction_timestamp()
      FROM public.auth_session_mfa_states
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND session_id = ${rotatedSession}::uuid
    `;
    await transaction`
      INSERT INTO public.auth_session_federated_provenance (
        tenant_id,session_id,user_id,primary_kind,authentication_method,
        provider_id,binding_id,provider_kind,external_identity_id,
        external_identity_revision,trust_rule_revision,authenticated_at
      )
      SELECT tenant_id,${promotedSession}::uuid,user_id,primary_kind,
        authentication_method,provider_id,binding_id,provider_kind,
        external_identity_id,external_identity_revision,trust_rule_revision,
        transaction_timestamp()
      FROM public.auth_session_federated_provenance
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND session_id = ${rotatedSession}::uuid
    `;
    await transaction`
      UPDATE public.tenant_saml_session_materials
      SET session_id = ${promotedSession}::uuid,continuation_id = NULL
      WHERE tenant_id = ${lineage.tenant}::uuid
        AND id = ${lineage.material}::uuid
    `;
  });
  const [afterPromotion] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(afterPromotion, { ready: true });
  await assertSAMLDataInvariants("promotion retains the original material ID");

  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.tenant_saml_session_materials (
        id,tenant_id,session_id,user_id,provider_id,binding_id,provider_kind,
        external_identity_id,aad_version,key_version,ciphertext,created_at
      ) VALUES (
        ${uuid(75)}::uuid,${marker.tenant}::uuid,${uuid(76)}::uuid,
        ${marker.user}::uuid,${marker.provider}::uuid,${marker.binding}::uuid,
        'saml',${marker.externalIdentity}::uuid,1,1,${Buffer.alloc(32, 5)},
        transaction_timestamp()
      )
    `;
  });
  const [ambiguousLegacy] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(ambiguousLegacy, { ready: true });
  await assertSAMLDataInvariants("orphaned legacy material is detected", {
    active_legacy_sessions: 1,
  });
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      DELETE FROM public.tenant_saml_session_materials
      WHERE tenant_id = ${marker.tenant}::uuid AND id = ${uuid(75)}::uuid
    `;
    await transaction`
      UPDATE public.tenant_federated_authentication_applications
      SET request_snapshot = '{}'::jsonb
      WHERE tenant_id = ${marker.tenant}::uuid
        AND id = ${marker.application}::uuid
    `;
  });
  const [driftedApplication] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(driftedApplication, { ready: true });
  await assertSAMLDataInvariants("application material ID drift is detected", {
    invalid_application_materials: 1,
  });
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      UPDATE public.tenant_federated_authentication_applications
      SET request_snapshot = ${transaction.json({
        samlSession: { materialId: marker.material },
      })}::jsonb
      WHERE tenant_id = ${marker.tenant}::uuid
        AND id = ${marker.application}::uuid
    `;
  });
  const [restoredReadiness] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(restoredReadiness, { ready: true });
  await assertSAMLDataInvariants("application material ID restored");

  await serially(
    [
      {
        name: "tenant_saml_session_materials_v2_guard",
        relation: "tenant_saml_session_materials",
        events: "INSERT OR UPDATE",
        functionName: "app.guard_saml_session_material_v2()",
      },
      {
        name: "tenant_saml_logout_commands_immutable_v1",
        relation: "tenant_saml_logout_commands",
        events: "UPDATE OR DELETE",
        functionName: "app.guard_federated_immutable_ledger_v1()",
      },
      {
        name: "tenant_post_primary_continuations_federated_provenance_v1",
        relation: "tenant_post_primary_continuations",
        events: "INSERT OR UPDATE",
        functionName: "app.validate_federated_continuation_provenance_v1()",
      },
    ],
    async (trigger) => {
      await sql.unsafe(
        `DROP TRIGGER ${trigger.name} ON public.${trigger.relation}`,
      );
      await sql.unsafe(
        `CREATE TRIGGER ${trigger.name} BEFORE ${trigger.events} ON public.tenants FOR EACH ROW EXECUTE FUNCTION ${trigger.functionName}`,
      );
      const [spoofed] = await sql<{ ready: boolean }[]>`
      SELECT app.private_release_runtime_schema_readiness_v49() AS ready
    `;
      assert.deepEqual(spoofed, { ready: false });
      await sql.unsafe(`DROP TRIGGER ${trigger.name} ON public.tenants`);
      await sql.unsafe(
        `CREATE TRIGGER ${trigger.name} BEFORE ${trigger.events} ON public.${trigger.relation} FOR EACH ROW EXECUTE FUNCTION ${trigger.functionName}`,
      );
      await sql.unsafe(
        `DROP TRIGGER ${trigger.name} ON public.${trigger.relation}`,
      );
      await sql.unsafe(
        `CREATE TRIGGER ${trigger.name} BEFORE ${trigger.events} ON public.${trigger.relation} FOR EACH ROW WHEN (false) EXECUTE FUNCTION ${trigger.functionName}`,
      );
      const [conditional] = await sql<{ ready: boolean }[]>`
      SELECT app.private_release_runtime_schema_readiness_v49() AS ready
    `;
      assert.deepEqual(conditional, { ready: false });
      await sql.unsafe(
        `DROP TRIGGER ${trigger.name} ON public.${trigger.relation}`,
      );
      await sql.unsafe(
        `CREATE TRIGGER ${trigger.name} BEFORE ${trigger.events} ON public.${trigger.relation} FOR EACH ROW EXECUTE FUNCTION ${trigger.functionName}`,
      );
    },
  );
  const [exactTriggersRestored] = await sql<{ ready: boolean }[]>`
    SELECT app.private_release_runtime_schema_readiness_v49() AS ready
  `;
  assert.deepEqual(exactTriggersRestored, { ready: true });

  await serially(
    [
      {
        grant:
          "GRANT EXECUTE ON FUNCTION app.revoke_local_session_for_logout_v1(jsonb) TO periapsis_api WITH GRANT OPTION",
        revoke:
          "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION app.revoke_local_session_for_logout_v1(jsonb) FROM periapsis_api",
      },
      {
        grant:
          "GRANT EXECUTE ON FUNCTION app.private_saml_logout_configuration_record_v1(uuid,uuid,uuid) TO periapsis_audit_reader_owner",
        revoke:
          "REVOKE EXECUTE ON FUNCTION app.private_saml_logout_configuration_record_v1(uuid,uuid,uuid) FROM periapsis_audit_reader_owner",
      },
      {
        grant:
          "GRANT EXECUTE ON FUNCTION app.revoke_local_session_for_logout_v1(jsonb) TO periapsis_ticket_saved_view_owner",
        revoke:
          "REVOKE EXECUTE ON FUNCTION app.revoke_local_session_for_logout_v1(jsonb) FROM periapsis_ticket_saved_view_owner",
      },
      {
        grant:
          "GRANT SELECT ON TABLE public.tenant_saml_logout_commands TO periapsis_sla_readiness_owner",
        revoke:
          "REVOKE SELECT ON TABLE public.tenant_saml_logout_commands FROM periapsis_sla_readiness_owner",
      },
      {
        grant:
          "GRANT MAINTAIN ON TABLE public.tenant_saml_logout_commands TO periapsis_audit_reader_owner",
        revoke:
          "REVOKE MAINTAIN ON TABLE public.tenant_saml_logout_commands FROM periapsis_audit_reader_owner",
      },
      {
        grant:
          "GRANT SELECT (result_snapshot) ON TABLE public.tenant_saml_logout_commands TO periapsis_audit_reader_owner",
        revoke:
          "REVOKE SELECT (result_snapshot) ON TABLE public.tenant_saml_logout_commands FROM periapsis_audit_reader_owner",
      },
    ],
    async (unexpectedGrant) => {
      await sql.unsafe(unexpectedGrant.grant);
      const [overGranted] = await sql<{ ready: boolean }[]>`
      SELECT app.private_release_runtime_schema_readiness_v49() AS ready
    `;
      assert.deepEqual(overGranted, { ready: false });
      await sql.unsafe(unexpectedGrant.revoke);
      const [grantRevoked] = await sql<{ ready: boolean }[]>`
      SELECT app.private_release_runtime_schema_readiness_v49() AS ready
    `;
      assert.deepEqual(grantRevoked, { ready: true });
    },
  );

  // The unified local-only receipt does not manufacture a legacy SAML command
  // FK; material cleanup is privileged, never available to a runtime role.
  await serially(
    ["periapsis_api", "periapsis_worker", "periapsis_notifier"] as const,
    async (role) => {
      await assert.rejects(
        asRole(
          role,
          (transaction) => transaction`
          DELETE FROM public.tenant_saml_session_materials
          WHERE tenant_id = ${marker.tenant}::uuid AND id = ${marker.material}::uuid
        `,
        ),
        (error) => {
          assertSqlState(error, "42501");
          return true;
        },
      );
    },
  );

  await assert.rejects(
    sql`
      UPDATE public.tenant_saml_session_materials
      SET id = ${uuid(80)}::uuid
      WHERE tenant_id = ${marker.tenant}::uuid AND id = ${marker.material}::uuid
    `,
    (error) => {
      assertSqlState(error, "55000");
      return true;
    },
  );
  await assert.rejects(
    sql`
      INSERT INTO public.tenant_saml_session_materials (
        id,tenant_id,session_id,user_id,provider_id,binding_id,provider_kind,
        external_identity_id,aad_version,created_at
      ) VALUES (
        ${uuid(74)}::uuid,${marker.tenant}::uuid,${marker.session}::uuid,
        ${marker.user}::uuid,${marker.provider}::uuid,${marker.binding}::uuid,
        'saml',${marker.externalIdentity}::uuid,2,transaction_timestamp()
      )
    `,
    (error) => {
      assertSqlState(error, "23514");
      return true;
    },
  );
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL session_replication_role = replica");
    await transaction`
      INSERT INTO public.identity_keyring_versions (key_version,verifier,is_active,bound_at)
      VALUES (1,${Buffer.alloc(32, 63)},true,transaction_timestamp())
      ON CONFLICT (key_version) DO NOTHING
    `;
    await transaction`
      INSERT INTO public.mfa_policy_revisions (
        id,revision,tenant_id,scope,level,local_required,freshness_nanoseconds,created_at
      ) VALUES (${uuid(99980)}::uuid,1,NULL,'platform_floor','primary',false,0,transaction_timestamp())
    `;
  });
  await serially(upstreamFixtures, verifyUpstreamLogout);
} finally {
  await sql.end();
}
