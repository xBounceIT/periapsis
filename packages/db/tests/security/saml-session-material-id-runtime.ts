import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };
type RuntimeRole = "periapsis_api" | "periapsis_worker" | "periapsis_notifier";
type RuntimeActor = { tenant: string | null; user: string };
type JSONRecord = Record<string, postgres.JSONValue>;
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

function jsonRecord(value: unknown, label: string): JSONRecord {
  assert(isJSONRecord(value), `${label}: expected an object`);
  return value;
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

// V54 attests the current catalog/ACL graph; these five data checks retain the
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

async function assertTenantInitialization(
  tenantIds: string[],
  label: string,
): Promise<void> {
  const [state] = await sql<
    {
      tenants: number;
      authorization_states: number;
      system_principals: number;
      principal_catalog_ready: boolean;
      local_account_ready: boolean;
    }[]
  >`
    SELECT
      (SELECT count(*)::integer FROM public.tenants
       WHERE id = ANY(${sql.array(tenantIds)}::uuid[])) AS tenants,
      (SELECT count(*)::integer FROM public.tenant_authorization_states
       WHERE tenant_id = ANY(${sql.array(tenantIds)}::uuid[])
         AND initialized_at IS NOT NULL) AS authorization_states,
      (SELECT count(*)::integer FROM public.tenant_service_accounts
       WHERE tenant_id = ANY(${sql.array(tenantIds)}::uuid[])
         AND key = 'sla_action_runtime' AND system_owned
         AND created_by_membership_id IS NULL AND archived_at IS NULL)
        AS system_principals,
      app.private_sla_system_principal_catalog_ready_v1() AS principal_catalog_ready,
      app.platform_local_account_runtime_schema_readiness_v1() AS local_account_ready
  `;
  assert.deepEqual(
    state,
    {
      tenants: tenantIds.length,
      authorization_states: tenantIds.length,
      system_principals: tenantIds.length,
      principal_catalog_ready: true,
      local_account_ready: true,
    },
    label,
  );
}

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
  // Tenant initialization is ordinary even when the caller installs a stored
  // SAML graph below. Its authorization-state trigger creates the protected,
  // non-login SLA principal; replica mode must not suppress that bootstrap.
  await transaction.unsafe("SET LOCAL session_replication_role = origin");
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
    SELECT app.seed_tenant_authorization(${fixture.tenant}::uuid,${fixture.membership}::uuid)
  `;
  // Only the pre-existing synthetic SAML lineage uses the privileged fixture
  // mode. All tested authentication, revalidation and logout calls remain normal.
  await transaction.unsafe("SET LOCAL session_replication_role = replica");
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

// Retained lookup aliases and the active ciphertext root are independent.
const admittedSubjectKeys = { alias: 2, ciphertext: 1 } as const;

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
    if (fixture.origin !== "tenant_platform_provider") {
      await transaction`
        INSERT INTO public.platform_saml_login_policies (
          provider_id,account_mode,enabled,revision
        ) VALUES (${fixture.provider}::uuid,'existing_identity',true,1)
      `;
    }
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
  if (fixture.origin === "tenant_platform_provider") {
    // The configuration INSERT installs the disabled login policy. Activate it
    // only after its complete configuration/key graph exists, with its guard on.
    await transaction`
      SELECT set_config('app.platform_saml_direct_policy_write_v1','on',true)
    `;
    const activated = await transaction`
      UPDATE public.platform_saml_login_policies
      SET account_mode='existing_identity',enabled=true,revision=2,
          updated_at=transaction_timestamp()
      WHERE provider_id=${fixture.provider}::uuid AND revision=1 AND NOT enabled
      RETURNING provider_id
    `;
    assert.equal(
      activated.length,
      1,
      "activate the existing SAML login policy",
    );
    await transaction`
      SELECT set_config('app.platform_saml_direct_policy_write_v1','',true)
    `;
  }
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

async function admissionAuthoritySnapshot(
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  const [row] = await sql<{ value: postgres.JSONValue }[]>`
    SELECT jsonb_build_object(
      'platformRoles',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id)
        FROM public.user_platform_roles g WHERE g.user_id=${fixture.user}::uuid),
      'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id)
        FROM public.tenant_memberships m WHERE m.user_id=${fixture.user}::uuid),
      'tenantRoles',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id)
        FROM public.tenant_membership_role_grants g
        JOIN public.tenant_memberships m ON m.tenant_id=g.tenant_id AND m.id=g.membership_id
        WHERE m.user_id=${fixture.user}::uuid)
    ) AS value
  `;
  assert(row);
  return row.value;
}

async function seedTenantPlatformAdmission(
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  const base = fixture.sequence * 1000;
  const floor = uuid(base + 30);
  const baseline = uuid(base + 31);
  const alias = uuid(base + 32);
  const platformGrant = uuid(base + 33);
  const epoch = uuid(base + 34);
  const source = uuid(base + 35);
  const grant = uuid(base + 36);
  const tenantAdministrator = uuid(base + 37);
  const administratorMembership = uuid(base + 38);
  const providerKey = `saml_upstream_${fixture.sequence}`;
  const subjectDigest = digest(`saml-upstream-subject-${fixture.sequence}`);
  const subjectAliases = [
    {
      keyVersion: admittedSubjectKeys.ciphertext,
      digest: digest(`saml-upstream-active-subject-${fixture.sequence}`),
    },
    { keyVersion: admittedSubjectKeys.alias, digest: subjectDigest },
  ];

  // Administrative fixture setup with ordinary constraints and triggers. These
  // pre-existing grants are inputs to authentication, never assertion outputs.
  const setupConfiguration = await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.users (id,email,display_name)
      VALUES (${fixture.user}::uuid,${`saml-upstream-${fixture.sequence}@example.invalid`},
        'Prelinked SAML admission fixture')
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (key_version,verifier,is_active,bound_at)
      VALUES (1,${Buffer.from(digest("saml-upstream-keyring"), "base64")},true,transaction_timestamp())
      ON CONFLICT (key_version) DO NOTHING
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (key_version,verifier,is_active,bound_at)
      VALUES (${admittedSubjectKeys.alias},
        ${Buffer.from(digest("saml-upstream-retained-keyring"), "base64")},false,transaction_timestamp())
    `;
    const projected = await seedUpstreamConfiguration(transaction, fixture);
    await transaction`
      INSERT INTO public.user_platform_roles (id,user_id,role_id,granted_by_user_id)
      SELECT ${platformGrant}::uuid,${fixture.user}::uuid,id,${fixture.user}::uuid
      FROM public.platform_roles WHERE key='platform_super_admin'
    `;
    await transaction`
      INSERT INTO public.platform_federated_external_identities (
        id,platform_provider_id,provider_kind,user_id,subject_format,
        subject_ciphertext,subject_nonce,key_version,admitted_configuration_revision,
        admitted_security_revision,last_observed_at,last_observation_state,
        version,resource_version,created_at,updated_at
      ) VALUES (${fixture.externalIdentity}::uuid,${fixture.provider}::uuid,'saml',
        ${fixture.user}::uuid,'utf8_exact',${Buffer.alloc(32, 0x41)},${Buffer.alloc(12, 0x42)},
        ${admittedSubjectKeys.ciphertext},1,1,transaction_timestamp(),'known',1,1,
        transaction_timestamp(),transaction_timestamp())
    `;
    await transaction`
      INSERT INTO public.platform_federated_external_identity_aliases (
        id,platform_provider_id,external_identity_id,key_version,subject_digest
      ) VALUES (${alias}::uuid,${fixture.provider}::uuid,${fixture.externalIdentity}::uuid,
        ${admittedSubjectKeys.alias},${Buffer.from(subjectDigest, "base64")})
    `;
    await transaction`
      INSERT INTO public.tenants (id,slug,name)
      VALUES (${fixture.tenant}::uuid,'saml-upstream-admitted','SAML upstream admission')
    `;
    await transaction`
      INSERT INTO public.users (id,email,display_name)
      VALUES (${tenantAdministrator}::uuid,'saml-admission-owner@example.invalid','SAML tenant setup owner')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id,tenant_id,user_id,role,status)
      VALUES (${administratorMembership}::uuid,${fixture.tenant}::uuid,${tenantAdministrator}::uuid,
        'tenant_admin','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(${fixture.tenant}::uuid,${administratorMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id,tenant_id,user_id,role,status)
      VALUES (${fixture.membership}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
        'read_only','active')
    `;
    await transaction`
      INSERT INTO public.tenant_mfa_subjects (
        tenant_id,user_id,webauthn_user_handle,identity_epoch,session_invalidation_epoch,version
      ) VALUES (${fixture.tenant}::uuid,${fixture.user}::uuid,
        ${Buffer.from(digest("saml-upstream-user-handle"), "base64")},1,1,1)
    `;
    await serially(
      [
        { id: floor, tenant: null, scope: "platform_floor" },
        { id: baseline, tenant: fixture.tenant, scope: "tenant_baseline" },
      ],
      async (policy) => {
        const current = await transaction<
          { id: string; level: string; local: boolean }[]
        >`
          SELECT id,level,local_required AS local FROM public.mfa_policy_revisions
          WHERE scope=${policy.scope} AND tenant_id IS NOT DISTINCT FROM ${policy.tenant}::uuid
            AND retired_at IS NULL
        `;
        if (current.length > 0) {
          assert.equal(current.length, 1, "one live policy per fixture scope");
          assert.equal(
            current[0]?.level,
            "primary",
            "reuse the existing primary policy",
          );
          assert.equal(
            current[0]?.local,
            false,
            "existing policy does not require a local factor",
          );
          return;
        }
        await transaction`
        SELECT set_config('app.mfa_policy_write_v1',${`insert:${policy.id}:1`},true)
      `;
        await transaction`
        INSERT INTO public.mfa_policy_revisions (
          id,revision,tenant_id,scope,level,local_required,freshness_nanoseconds
        ) VALUES (${policy.id}::uuid,1,${policy.tenant}::uuid,${policy.scope},'primary',false,0)
      `;
      },
    );
    await transaction`
      SELECT set_config('app.mfa_policy_write_v1','',true)
    `;
    // The ordinary lifecycle is disabled binding -> exact epoch -> activation.
    // Inserting an already-enabled binding would bypass its actual state machine.
    await transaction`
      INSERT INTO public.tenant_auth_provider_login_keys (tenant_id,binding_family,binding_id,key)
      VALUES (${fixture.tenant}::uuid,'platform_provider',${fixture.binding}::uuid,${providerKey})
    `;
    await transaction`
      INSERT INTO public.tenant_platform_auth_provider_bindings (
        id,tenant_id,platform_provider_id,key,created_by_user_id,updated_by_user_id
      ) VALUES (${fixture.binding}::uuid,${fixture.tenant}::uuid,${fixture.provider}::uuid,
        ${providerKey},${fixture.user}::uuid,${fixture.user}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_authorization_sources (id,tenant_id,kind,key,authoritative,protected)
      VALUES (${source}::uuid,${fixture.tenant}::uuid,'identity_provider_access',
        ${`identity_provider_access:${fixture.binding}:1`},true,false)
    `;
    await transaction`
      INSERT INTO public.tenant_platform_identity_provider_access_epochs (
        id,tenant_id,binding_id,platform_provider_id,source_id,sequence,started_by_user_id
      ) VALUES (${epoch}::uuid,${fixture.tenant}::uuid,${fixture.binding}::uuid,
        ${fixture.provider}::uuid,${source}::uuid,1,${fixture.user}::uuid)
    `;
    await transaction`
      UPDATE public.tenant_platform_auth_provider_bindings
      SET enabled=true,current_access_epoch_id=${epoch}::uuid,version=2,
          auth_revision=2,mapping_revision=2,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid AND id=${fixture.binding}::uuid AND version=1
    `;
    await transaction`
      INSERT INTO public.tenant_platform_federated_provider_access_grants (
        id,tenant_id,platform_provider_id,binding_id,access_epoch_id,source_id,
        external_identity_id,membership_id,user_id,owns_membership,started_at,last_observed_at
      ) VALUES (${grant}::uuid,${fixture.tenant}::uuid,${fixture.provider}::uuid,
        ${fixture.binding}::uuid,${epoch}::uuid,${source}::uuid,${fixture.externalIdentity}::uuid,
        ${fixture.membership}::uuid,${fixture.user}::uuid,false,transaction_timestamp(),transaction_timestamp())
    `;
    return projected;
  });

  const authorityBefore = await admissionAuthoritySnapshot(fixture);
  const [retainedAliasBefore] = await sql<{ value: postgres.JSONValue }[]>`
    SELECT to_jsonb(retained) AS value
    FROM public.platform_federated_external_identity_aliases AS retained
    WHERE retained.id=${alias}::uuid
      AND retained.platform_provider_id=${fixture.provider}::uuid
      AND retained.external_identity_id=${fixture.externalIdentity}::uuid
      AND retained.key_version=${admittedSubjectKeys.alias}
  `;
  assert(retainedAliasBefore !== undefined, "prelinked retained SAML alias");
  const [begin] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.begin_platform_saml_authentication_v1(
      ${transaction.json({ loginKey: providerKey })}::jsonb
    ) AS value
  `,
  );
  const directConfiguration = jsonRecord(
    begin?.value,
    "direct SAML configuration",
  );
  const directMetadata = jsonRecord(
    directConfiguration.metadata,
    "direct SAML begin metadata",
  );
  assert.deepEqual(
    directMetadata,
    jsonRecord(setupConfiguration, "administrative SAML configuration")
      .metadata,
    "ordinary begin preserves the exact administratively configured metadata",
  );
  assert(typeof directMetadata.document === "string");
  assert.equal(
    directMetadata.digest,
    createHash("sha256")
      .update(Buffer.from(directMetadata.document, "base64"))
      .digest("base64"),
    "ordinary begin metadata digest binds its exact document bytes",
  );
  const directFloor = jsonRecord(
    directConfiguration.platformFloor,
    "platform floor",
  );
  // Keep the caller's clock deliberately behind PostgreSQL, while preserving
  // transaction creation before its later application. Never copy DB time into
  // a command to satisfy an identity/alias observation guard.
  const createdAt = new Date(Date.now() - 5_000);
  const protocolPins = {
    ...jsonRecord(directConfiguration.pins, "direct configuration pins"),
    configurationDigest: digest("saml-upstream-configuration-proof"),
  };
  const pins = {
    protocol: protocolPins,
    platformFloorPolicyId: directFloor.id,
    platformFloorPolicyRevision: directFloor.revision,
  };
  const audit = (offset: number) => ({
    requestId: uuid(base + offset),
    correlationId: uuid(base + offset + 1),
    ipAddress: "192.0.2.1",
    userAgent: "periapsis-saml-admission-runtime",
  });
  const create = {
    begin: {
      operationRunId: fixture.material,
      receiptDigest: digest("saml-upstream-login-receipt"),
      networkDigest: digest("saml-upstream-login-network"),
      accountDigest: digest("saml-upstream-login-account"),
      providerDigest: digest("saml-upstream-login-provider"),
    },
    current: {
      transactionId: digest("saml-upstream-login-transaction"),
      materialId: fixture.material,
      requestId: `request-${fixture.material}`,
      relayStateDigest: digest("saml-upstream-login-relay"),
      browserDigest: digest("saml-upstream-login-browser"),
      returnPath: "/incidents",
      state: "pending",
      version: 1,
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + 5 * 60_000).toISOString(),
    },
    pins,
    audit: audit(40),
  };
  const [created] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.create_platform_saml_authentication_transaction_v1(
      ${transaction.json(create)}::jsonb
    ) AS value
  `,
  );
  const loginTransaction = jsonRecord(
    created?.value,
    "direct SAML transaction",
  );
  assert.equal(loginTransaction.version, 1);
  const observedAt = new Date(Date.now() - 2_000);
  const [planning] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.load_platform_saml_planning_state_v1(${transaction.json({
      transactionId: loginTransaction.transactionId,
      observedAt: observedAt.toISOString(),
      pins,
      // Planning uses the Go enum UTF8Exact=3; apply uses the textual format.
      subjectFormat: 3,
      subjectAliases,
    })}::jsonb) AS value
  `,
  ).catch((error: unknown) => {
    // PostgreSQL errors can carry query text and parameter details. Keep the
    // failing public stage and SQLSTATE in runtime evidence, not that payload.
    const code =
      error instanceof Error ? (error as ErrorWithCode).code : undefined;
    if (code !== undefined && /^[A-Z0-9]{5}$/u.test(code)) {
      throw new Error(`direct SAML planning ABI failed (SQLSTATE ${code})`);
    }
    throw error;
  });
  const planningState = jsonRecord(
    planning?.value,
    "prelinked SAML planning state",
  );
  assert.equal(planningState.providerEnabled, true);
  assert.equal(planningState.platformLoginLive, true);
  assert(Array.isArray(planningState.matches));
  assert.equal(planningState.matches.length, 1);
  const match = jsonRecord(
    planningState.matches[0],
    "exact prelinked SAML identity",
  );
  assert.equal(match.userId, fixture.user);
  assert.equal(match.externalIdentityId, fixture.externalIdentity);
  assert.equal(match.platformAuthorityId, platformGrant);
  assert.equal(match.protectedPlatformAuthorityLive, true);
  assert.deepEqual(match.alias, {
    keyVersion: admittedSubjectKeys.alias,
    digest: subjectDigest,
  });
  const expiresBase = Math.floor(observedAt.getTime() / 1000) * 1000;
  const absoluteExpiresAt = new Date(expiresBase + 60 * 60_000).toISOString();
  const idleExpiresAt = new Date(expiresBase + 30 * 60_000).toISOString();
  const login = {
    authority: {
      transactionId: loginTransaction.transactionId,
      materialId: fixture.material,
      expectedVersion: loginTransaction.version,
      pins: protocolPins,
      responseIdDigest: digest("saml-upstream-response"),
      assertionIdDigest: digest("saml-upstream-assertion"),
      hasSessionIndex: false,
      hasSessionMaterial: true,
      consumedAt: observedAt.toISOString(),
      returnPath: loginTransaction.returnPath,
    },
    plan: {
      disposition: "immediate_session",
      pins,
      provenance: {
        provider: { scope: "platform", providerId: fixture.provider },
        userId: match.userId,
        externalIdentityId: match.externalIdentityId,
        identityRevision: match.identityRevision,
        userAuthenticationRevision: match.userAuthenticationRevision,
        matchedAliasKeyVersion: jsonRecord(match.alias, "matched SAML alias")
          .keyVersion,
        platformAuthorityId: match.platformAuthorityId,
        platformAuthorityRevision: match.platformAuthorityRevision,
        authenticatedAt: observedAt.toISOString(),
        validUntil: absoluteExpiresAt,
        selectedAssurance: {
          level: "primary",
          authenticatedAt: observedAt.toISOString(),
        },
      },
      subject: {
        aliases: subjectAliases,
        subjectFormat: "utf8_exact",
        envelope: {
          format: "utf8_exact",
          ciphertext: Buffer.alloc(32, 0x51).toString("base64"),
          nonce: Buffer.alloc(12, 0x52).toString("base64"),
          keyVersion: admittedSubjectKeys.ciphertext,
        },
      },
      platformFloor: directFloor,
    },
    session: {
      id: fixture.ownerSession,
      rotationFamilyId: fixture.family,
      tokenDigest: Buffer.from(
        fixture.transactionHex.repeat(32),
        "hex",
      ).toString("base64"),
      csrfSecretDigest: digest("saml-upstream-owner-csrf"),
      authenticationMethod: "saml",
      idleExpiresAt,
      absoluteExpiresAt,
    },
    protectedSessionMaterial: {
      keyVersion: 1,
      nonce: Buffer.alloc(12, fixture.sequence).toString("base64"),
      ciphertext: Buffer.alloc(32, fixture.sequence).toString("base64"),
    },
    sessionAudience: "api",
    recoveryRestricted: false,
    appliedAt: observedAt.toISOString(),
    audit: audit(42),
    proofDigest: digest("saml-upstream-login-proof"),
  };
  const [authenticated] = await asRole("periapsis_api", async (transaction) => {
    const result = await transaction<
      {
        value: postgres.JSONValue | null;
        configuration_observed_at: postgres.JSONValue;
      }[]
    >`
        SELECT app.apply_platform_saml_authentication_v1(${transaction.json(login)}::jsonb) AS value,
          to_jsonb(statement_timestamp()) AS configuration_observed_at
      `;
    // The production write above runs only as the API role. Restore the
    // test role for read-only inspection in that exact same transaction.
    await transaction.unsafe("RESET ROLE");
    const [aliasObservation] = await transaction<
      {
        alias_count: number;
        created_with_database_time: boolean;
        differs_from_application_time: boolean;
        active_alias_digest: string;
        retained_alias: postgres.JSONValue;
      }[]
    >`
        SELECT
          (SELECT count(*)::integer
           FROM public.platform_federated_external_identity_aliases AS candidate
           WHERE candidate.platform_provider_id=${fixture.provider}::uuid
             AND candidate.external_identity_id=${fixture.externalIdentity}::uuid) AS alias_count,
          fresh.created_at=transaction_timestamp() AS created_with_database_time,
          fresh.created_at<>${login.appliedAt}::timestamptz AS differs_from_application_time,
          replace(encode(fresh.subject_digest,'base64'),E'\\n','') AS active_alias_digest,
          to_jsonb(retained) AS retained_alias
        FROM public.platform_federated_external_identity_aliases AS fresh
        JOIN public.platform_federated_external_identity_aliases AS retained
          ON retained.id=${alias}::uuid
          AND retained.platform_provider_id=fresh.platform_provider_id
          AND retained.external_identity_id=fresh.external_identity_id
        WHERE fresh.platform_provider_id=${fixture.provider}::uuid
          AND fresh.external_identity_id=${fixture.externalIdentity}::uuid
          AND fresh.key_version=${admittedSubjectKeys.ciphertext}
          AND fresh.retired_at IS NULL
      `;
    assert.deepEqual(aliasObservation, {
      alias_count: 2,
      created_with_database_time: true,
      differs_from_application_time: true,
      active_alias_digest: subjectAliases[0]?.digest,
      retained_alias: retainedAliasBefore.value,
    });
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    return result;
  });
  const authenticatedResult = jsonRecord(
    authenticated?.value,
    "direct SAML login receipt",
  );
  assert.equal(authenticatedResult.category, "success");
  assert.equal(authenticatedResult.sessionId, fixture.ownerSession);
  const configurationObservedAt = authenticated?.configuration_observed_at;
  assert(typeof configurationObservedAt === "string");
  // 0228 snapshots the ordinary begin document using the admitted authority
  // pins and the apply statement's database clock. Build this expectation from
  // those independent inputs, before metadata mutation or any logout claim;
  // never use the material/claim configuration as its own expected value.
  const admittedConfiguration: JSONRecord = {
    ...directConfiguration,
    observedAt: configurationObservedAt,
    pins: protocolPins,
  };
  const admittedPins = jsonRecord(
    admittedConfiguration.pins,
    "admitted SAML configuration pins",
  );
  assert.equal(
    admittedPins.configurationDigest,
    digest("saml-upstream-configuration-proof"),
  );
  assert.equal(admittedPins.metadataDigest, directMetadata.digest);
  assert.equal(admittedPins.metadataRevision, directMetadata.revision);
  const [subjectObservation] = await sql<
    {
      ciphertext_key_version: number;
      alias_key_version: number;
      request_alias_key_version: number;
      request_ciphertext_key_version: number;
      request_applied_at: string;
      request_configuration_pins: postgres.JSONValue;
      receipt: postgres.JSONValue;
    }[]
  >`
    SELECT identity.key_version AS ciphertext_key_version,provenance.alias_key_version,
      (application.request_snapshot #>> '{plan,provenance,matchedAliasKeyVersion}')::integer
        AS request_alias_key_version,
      (application.request_snapshot #>> '{plan,subject,envelope,keyVersion}')::integer
        AS request_ciphertext_key_version,
      application.request_snapshot ->> 'appliedAt' AS request_applied_at,
      application.request_snapshot #> '{authority,pins}' AS request_configuration_pins,
      application.result_snapshot AS receipt
    FROM public.platform_federated_external_identities identity
    JOIN public.auth_session_platform_saml_provenance provenance
      ON provenance.platform_provider_id=identity.platform_provider_id
      AND provenance.external_identity_id=identity.id AND provenance.user_id=identity.user_id
    JOIN public.platform_saml_authentication_applications application
      ON application.session_id=provenance.session_id AND application.user_id=provenance.user_id
      AND application.platform_provider_id=identity.platform_provider_id
      AND application.external_identity_id=identity.id
    WHERE identity.platform_provider_id=${fixture.provider}::uuid
      AND identity.id=${fixture.externalIdentity}::uuid AND identity.user_id=${fixture.user}::uuid
      AND provenance.session_id=${fixture.ownerSession}::uuid
  `;
  assert.deepEqual(subjectObservation, {
    ciphertext_key_version: admittedSubjectKeys.ciphertext,
    alias_key_version: admittedSubjectKeys.alias,
    request_alias_key_version: admittedSubjectKeys.alias,
    request_ciphertext_key_version: admittedSubjectKeys.ciphertext,
    request_applied_at: login.appliedAt,
    request_configuration_pins: protocolPins,
    receipt: authenticatedResult,
  });
  const loginReplaySnapshot = async () => {
    const [snapshot] = await sql<{ value: postgres.JSONValue }[]>`
      SELECT jsonb_build_object(
        'aliases',(SELECT jsonb_agg(to_jsonb(candidate) ORDER BY candidate.id)
          FROM public.platform_federated_external_identity_aliases AS candidate
          WHERE candidate.platform_provider_id=${fixture.provider}::uuid
            AND candidate.external_identity_id=${fixture.externalIdentity}::uuid),
        'sessions',(SELECT jsonb_agg(encode(sha256(convert_to(to_jsonb(session)::text,'UTF8')),'hex') ORDER BY session.id)
          FROM public.auth_sessions AS session WHERE session.user_id=${fixture.user}::uuid),
        'applications',(SELECT jsonb_agg(encode(sha256(convert_to(to_jsonb(application)::text,'UTF8')),'hex') ORDER BY application.transaction_id)
          FROM public.platform_saml_authentication_applications AS application
          WHERE application.user_id=${fixture.user}::uuid),
        'audits',(SELECT jsonb_agg(encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex') ORDER BY event.id)
          FROM public.platform_audit_events AS event WHERE event.actor_user_id=${fixture.user}::uuid)
      ) AS value
    `;
    assert(snapshot !== undefined);
    return snapshot.value;
  };
  const beforeLoginReplay = await loginReplaySnapshot();
  const [replayedLogin] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.apply_platform_saml_authentication_v1(${transaction.json(login)}::jsonb) AS value
    `,
  );
  assert.deepEqual(replayedLogin?.value, {
    ...authenticatedResult,
    category: "already_applied",
  });
  assert.deepEqual(await loginReplaySnapshot(), beforeLoginReplay);
  assert.deepEqual(await admissionAuthoritySnapshot(fixture), authorityBefore);

  const switchObservedAt = new Date().toISOString();
  const [loaded] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.load_platform_saml_tenant_switch_v1(${transaction.json({
      sourceSessionId: fixture.ownerSession,
      targetTenantId: fixture.tenant,
      observedAt: switchObservedAt,
    })}::jsonb) AS value
  `,
  );
  const switchSnapshot = jsonRecord(
    loaded?.value,
    "SAML tenant-switch snapshot",
  );
  const sourceRevisions = jsonRecord(
    jsonRecord(switchSnapshot.source, "direct SAML switch source").revisions,
    "direct SAML switch source revisions",
  );
  assert.deepEqual(sourceRevisions.subjectAliasKey, {
    pinned: admittedSubjectKeys.alias,
    current: admittedSubjectKeys.alias,
  });
  const target = jsonRecord(
    switchSnapshot.commandPins,
    "live SAML target command pins",
  );
  assert.equal(target.tenantId, fixture.tenant);
  assert.equal(target.membershipId, fixture.membership);
  assert.equal(target.bindingId, fixture.binding);
  assert.equal(target.accessEpochId, epoch);
  assert.equal(target.accessSourceId, source);
  assert.equal(target.accessGrantId, grant);
  assert.equal(target.bindingVersion, 2);
  assert.equal(target.externalIdentityId, fixture.externalIdentity);
  assert.equal(target.aliasKeyVersion, admittedSubjectKeys.alias);
  const switchCommand = {
    sourceSessionId: fixture.ownerSession,
    expectedVersion: 1,
    authenticationMethod: "saml",
    target,
    requestDigest: digest("saml-upstream-switch-request"),
    decision: "rotate",
    session: {
      id: fixture.session,
      rotationFamilyId: fixture.family,
      tokenDigest: Buffer.from(
        (fixture.sequence + 90).toString(16).repeat(32),
        "hex",
      ).toString("base64"),
      csrfSecretDigest: digest("saml-upstream-successor-csrf"),
      audience: "api",
      idleExpiresAt,
      absoluteExpiresAt,
      sessionVersion: 2,
      recoveryRestricted: false,
    },
    observedAt: switchObservedAt,
    audit: {
      ...audit(44),
      eventId: uuid(base + 46),
      authenticationMethod: "saml",
    },
  };
  // V50 failed here at the deferred typed-provenance constraint. V51 must
  // produce the successor and receipt through this ordinary production writer.
  const switched = await asRole("periapsis_api", async (transaction) => {
    const [result] = await transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.apply_platform_saml_tenant_switch_v1(
        ${transaction.json(switchCommand)}::jsonb
      ) AS value
    `;
    return jsonRecord(result?.value, "SAML tenant-switch receipt");
  });
  assert.deepEqual(switched, {
    applied: true,
    decision: "rotated",
    sourceSessionId: fixture.ownerSession,
    sessionId: fixture.session,
    targetTenantId: fixture.tenant,
    sessionVersion: 2,
  });
  assert.deepEqual(await admissionAuthoritySnapshot(fixture), authorityBefore);
  await verifyAdmittedSAMLRevalidation(fixture);
  const [replayed] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.apply_platform_saml_tenant_switch_v1(${transaction.json(switchCommand)}::jsonb) AS value
  `,
  );
  assert.deepEqual(
    replayed?.value,
    switched,
    "switch replay survives later session revision",
  );
  assert.deepEqual(await admissionAuthoritySnapshot(fixture), authorityBefore);
  return admittedConfiguration;
}

async function verifyAdmittedSAMLRevalidation(
  fixture: SAMLUpstreamFixture,
): Promise<void> {
  const lookup = {
    tenantId: fixture.tenant,
    sessionId: fixture.session,
    audience: "api",
    authenticationMethod: "saml",
    observedAt: new Date().toISOString(),
  };
  const [loaded] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.load_federated_session_revalidation_v1(${transaction.json(lookup)}::jsonb) AS value
  `,
  );
  const revalidation = jsonRecord(
    loaded?.value,
    "admitted SAML first revalidation",
  );
  const snapshot = jsonRecord(
    revalidation.snapshot,
    "admitted SAML session snapshot",
  );
  const live = jsonRecord(revalidation.live, "admitted SAML live authority");
  assert.deepEqual(revalidation.lookup, lookup);
  assert.equal(revalidation.authenticationMethod, "saml");
  assert.equal(snapshot.version, 2);
  assert.equal(snapshot.tenantId, fixture.tenant);
  assert.equal(snapshot.userId, fixture.user);
  assert.equal(snapshot.rotationFamilyId, fixture.family);
  const primary = jsonRecord(snapshot.primary, "admitted SAML primary");
  assert.equal(primary.kind, "platform_provider_binding");
  assert.deepEqual(primary.provider, {
    scope: "platform",
    providerId: fixture.provider,
  });
  assert.deepEqual(primary.admission, {
    tenantId: fixture.tenant,
    bindingId: fixture.binding,
  });
  for (const fact of [
    "sessionActive",
    "rotationFamilyActive",
    "userActive",
    "tenantActive",
    "membershipActive",
    "primaryActive",
  ]) {
    assert.equal(live[fact], true, `first SAML revalidation: ${fact}`);
  }
  assert.equal(live.identityEpoch, snapshot.identityEpoch);
  assert.equal(live.sessionInvalidationEpoch, primary.sessionInvalidationEpoch);
  assert.equal(live.primaryRevision, primary.primaryRevision);
  assert(Array.isArray(live.trustRules));
  assert.equal(live.trustRules.length, 1);
  assert.equal(
    jsonRecord(live.trustRules[0], "SAML trust source").active,
    true,
  );
  const requirement = jsonRecord(live.requirement, "admitted SAML requirement");
  assert.equal(requirement.level, "primary");
  assert.equal(requirement.localRequired, false);
  const mutation = {
    ...lookup,
    userId: fixture.user,
    expectedVersion: 2,
    observedAt: new Date().toISOString(),
    decision: "usable",
    reason: "current",
    requirement,
  };
  const [applied] = await asRole(
    "periapsis_api",
    (transaction) => transaction<{ value: postgres.JSONValue | null }[]>`
    SELECT app.apply_federated_session_revalidation_v1(${transaction.json(mutation)}::jsonb) AS value
  `,
  );
  assert.deepEqual(applied?.value, {
    tenantId: fixture.tenant,
    sessionId: fixture.session,
    expectedVersion: 2,
    decision: "usable",
    applied: true,
  });
  const [stored] = await sql<
    {
      version: number;
      live: boolean;
      parent: string;
      alias_key_version: number;
      ciphertext_key_version: number;
    }[]
  >`
    SELECT state.session_version::integer AS version,session.revoked_at IS NULL AS live,
           session.rotated_from_session_id AS parent,
           provenance.subject_alias_key_version AS alias_key_version,
           identity.key_version AS ciphertext_key_version
    FROM public.auth_session_mfa_states state
    JOIN public.auth_sessions session ON session.id=state.session_id
    JOIN public.auth_session_tenant_platform_federated_provenance provenance
      ON provenance.tenant_id=state.tenant_id AND provenance.session_id=state.session_id
      AND provenance.user_id=state.user_id
    JOIN public.platform_federated_external_identities identity
      ON identity.platform_provider_id=provenance.platform_provider_id
      AND identity.id=provenance.external_identity_id AND identity.user_id=provenance.user_id
    WHERE state.tenant_id=${fixture.tenant}::uuid AND state.session_id=${fixture.session}::uuid
  `;
  assert.deepEqual(stored, {
    version: 3,
    live: true,
    parent: fixture.ownerSession,
    alias_key_version: admittedSubjectKeys.alias,
    ciphertext_key_version: admittedSubjectKeys.ciphertext,
  });
}

async function seedUpstreamFixture(
  fixture: SAMLUpstreamFixture,
): Promise<postgres.JSONValue> {
  if (fixture.origin === "tenant_platform_provider") {
    return seedTenantPlatformAdmission(fixture);
  }
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
  const previousVersion = fixture.origin === "tenant_platform_provider" ? 3 : 1;
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
  assert.equal(result.previousVersion, previousVersion);
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
  assert.equal(claimed.previousVersion, previousVersion);
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
  `;
  assert.deepEqual(ready, { ready: true });
  await assertSAMLDataInvariants("seeded SAML material lineage");
  await assertTenantInitialization(
    [marker.tenant, envelope.tenant, localEnvelope.tenant, lineage.tenant],
    "stored SAML graphs preserve normal tenant initialization",
  );

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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
      SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
      SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
    SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
      SELECT app.private_release_runtime_schema_readiness_v54() AS ready
    `;
      assert.deepEqual(overGranted, { ready: false });
      await sql.unsafe(unexpectedGrant.revoke);
      const [grantRevoked] = await sql<{ ready: boolean }[]>`
      SELECT app.private_release_runtime_schema_readiness_v54() AS ready
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
  await assertTenantInitialization(
    [
      marker.tenant,
      envelope.tenant,
      localEnvelope.tenant,
      lineage.tenant,
      ...upstreamFixtures
        .filter((fixture) => fixture.origin !== "platform_provider")
        .map((fixture) => fixture.tenant),
    ],
    "all three upstream SAML origins preserve normal tenant initialization",
  );
} finally {
  await sql.end();
}
