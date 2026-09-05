import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type Sql, type TransactionSql } from "postgres";

type PgError = Error & { code?: string; constraint_name?: string };
type Rule = Readonly<{
  effect: "allow" | "deny";
  match: "exact" | "subdomains";
  hostname: string;
  port: number;
}>;
type PolicyDocument = Readonly<{
  id: string;
  versionId: string;
  tenantId: string;
  version: number;
  rules: readonly Rule[];
  publishedByMembershipId: string;
  publishedAt: string;
  digest: string;
  semanticDigest: string;
}>;
type ClaimDocument = Readonly<{
  id: string;
  endpointDigest: string;
  policyDigest: string | null;
  localDevelopmentExemption: boolean;
  urlPolicy: PolicyDocument | null;
}> &
  Record<string, unknown>;

const databaseUrl = process.env.PERIAPSIS_WEBHOOK_URL_POLICY_TEST_DATABASE_URL;
const apiDatabaseUrl =
  process.env.PERIAPSIS_WEBHOOK_URL_POLICY_API_DATABASE_URL;
const notifierDatabaseUrl =
  process.env.PERIAPSIS_WEBHOOK_URL_POLICY_NOTIFIER_DATABASE_URL;
if (
  !databaseUrl?.trim() ||
  !apiDatabaseUrl?.trim() ||
  !notifierDatabaseUrl?.trim()
) {
  throw new Error(
    "PERIAPSIS_WEBHOOK_URL_POLICY_TEST_DATABASE_URL plus exact API and notifier login URLs must name one fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7b00-2700-7000-8000-${(sequence + BigInt(offset)).toString(16).padStart(12, "0")}`;
const ids = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  admin: uuid(101),
  viewer: uuid(102),
  foreignAdmin: uuid(103),
  adminMembership: uuid(201),
  viewerMembership: uuid(202),
  foreignMembership: uuid(203),
  recoveryGrant: uuid(204),
  adminSession: uuid(301),
  viewerSession: uuid(302),
  foreignSession: uuid(303),
  adminFamily: uuid(311),
  viewerFamily: uuid(312),
  foreignFamily: uuid(313),
  policy: uuid(401),
  policyVersionOne: uuid(402),
  policyVersionTwo: uuid(403),
  policyVersionThree: uuid(404),
  configuration: uuid(501),
  configurationSecret: uuid(502),
  deniedConfiguration: uuid(503),
  deniedSecret: uuid(504),
  localConfiguration: uuid(505),
  localSecret: uuid(506),
  validEvent: uuid(601),
  staleEvent: uuid(602),
  currentEvent: uuid(603),
  localEvent: uuid(604),
  allowedLocalEvent: uuid(605),
  suspendedLocalEvent: uuid(606),
  validDelivery: uuid(701),
  staleDelivery: uuid(702),
  currentDelivery: uuid(703),
  localDelivery: uuid(704),
  allowedLocalDelivery: uuid(705),
  suspendedLocalDelivery: uuid(706),
} as const;

const suffix = sequence.toString(36);
const admin = postgres(databaseUrl, { max: 8, onnotice: () => undefined });
const api = postgres(apiDatabaseUrl, { max: 4, onnotice: () => undefined });
const notifier = postgres(notifierDatabaseUrl, {
  max: 4,
  onnotice: () => undefined,
});
let dynamicID = 1_000;
const nextID = (): string => uuid(++dynamicID);

function sha(label: string): Buffer {
  return createHash("sha256")
    .update(`webhook-url-policy-runtime:${suffix}:${label}`)
    .digest();
}

function framedDigest(parts: readonly string[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) {
    const value = Buffer.from(part, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    hash.update(length);
    hash.update(value);
  }
  return hash.digest();
}

function canonicalRules(rules: readonly Rule[]): Rule[] {
  return Array.from(rules).toSorted((left, right) => {
    const leftKey = `${left.effect}\0${left.match}\0${left.hostname}\0${left.port}`;
    const rightKey = `${right.effect}\0${right.match}\0${right.hostname}\0${right.port}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

function policyDigests(input: {
  tenantId: string;
  policyId: string;
  versionId: string;
  version: number;
  membershipId: string;
  publishedAt: Date;
  rules: readonly Rule[];
}): { semantic: Buffer; policy: Buffer } {
  const rules = canonicalRules(input.rules);
  const semantic = framedDigest([
    "periapsis.webhook-url-policy-semantics.v1",
    "https",
    "deny",
    ...rules.map(
      (rule) => `${rule.effect}\0${rule.match}\0${rule.hostname}\0${rule.port}`,
    ),
  ]);
  return {
    semantic,
    policy: framedDigest([
      "periapsis.webhook-url-policy-version.v1",
      input.tenantId,
      input.policyId,
      input.versionId,
      String(input.version),
      input.membershipId,
      input.publishedAt.toISOString(),
      semantic.toString("hex"),
    ]),
  };
}

function assertSqlState(error: unknown, code: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as PgError).code, code, error.message);
  return true;
}

async function rejects(
  operation: Promise<unknown>,
  code: string,
  message: string,
): Promise<void> {
  await assert.rejects(
    operation,
    (error: unknown) => {
      assertSqlState(error, code);
      return true;
    },
    message,
  );
}

async function setRuntimeContext(
  transaction: TransactionSql,
  tenantID: string,
  userID: string,
  allowPlainLocal = false,
): Promise<void> {
  await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
  await transaction`
    SELECT set_config('app.tenant_id',${tenantID},true),
           set_config('app.user_id',${userID},true),
           set_config('app.service_account_id','',true),
           set_config(
             'app.webhook_plain_local_exemption',
             ${allowPlainLocal ? "true" : "false"},true
           )
  `;
}

async function asLogin<T>(
  connection: Sql,
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
  allowPlainLocal = false,
): Promise<T> {
  const result = await connection.begin(async (transaction) => {
    await setRuntimeContext(transaction, tenantID, userID, allowPlainLocal);
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function asAdminRole<T>(
  role: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await admin.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function insertSession(
  transaction: TransactionSql,
  id: string,
  familyID: string,
  userID: string,
  tenantID: string,
  label: string,
  createdAt: Date,
): Promise<void> {
  await transaction`
    INSERT INTO public.auth_sessions(
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      ${id}::uuid,${userID}::uuid,${familyID}::uuid,${tenantID}::uuid,
      ${sha(`${label}:token`)},${sha(`${label}:csrf`)},'totp',
      ${createdAt},${createdAt},
      ${new Date(createdAt.getTime() + 60 * 60_000)},
      ${new Date(createdAt.getTime() + 2 * 60 * 60_000)},${createdAt}
    )
  `;
}

async function setup(): Promise<void> {
  const createdAt = new Date(Date.now() - 60_000);
  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${ids.tenant}::uuid,${`webhook-policy-${suffix}`},
         'Webhook policy runtime'),
        (${ids.foreignTenant}::uuid,${`webhook-policy-foreign-${suffix}`},
         'Foreign webhook policy runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${ids.tenant}::uuid),(${ids.foreignTenant}::uuid)
      ON CONFLICT DO NOTHING
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${ids.admin}::uuid,${`webhook-admin-${suffix}@example.invalid`},
         'Webhook admin',true),
        (${ids.viewer}::uuid,${`webhook-viewer-${suffix}@example.invalid`},
         'Webhook viewer',true),
        (${ids.foreignAdmin}::uuid,
         ${`webhook-foreign-${suffix}@example.invalid`},
         'Foreign webhook admin',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status)
      VALUES
        (${ids.adminMembership}::uuid,${ids.tenant}::uuid,
         ${ids.admin}::uuid,'tenant_admin','active'),
        (${ids.viewerMembership}::uuid,${ids.tenant}::uuid,
         ${ids.viewer}::uuid,'customer_user','active'),
        (${ids.foreignMembership}::uuid,${ids.foreignTenant}::uuid,
         ${ids.foreignAdmin}::uuid,'tenant_admin','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${ids.tenant}::uuid,${ids.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid
      )
    `;
    await insertSession(
      transaction,
      ids.adminSession,
      ids.adminFamily,
      ids.admin,
      ids.tenant,
      "admin",
      createdAt,
    );
    await insertSession(
      transaction,
      ids.viewerSession,
      ids.viewerFamily,
      ids.viewer,
      ids.tenant,
      "viewer",
      createdAt,
    );
    await insertSession(
      transaction,
      ids.foreignSession,
      ids.foreignFamily,
      ids.foreignAdmin,
      ids.foreignTenant,
      "foreign",
      createdAt,
    );
    await transaction`
      INSERT INTO public.webhook_plain_local_runtime_role_opt_ins(
        role_name,enabled,updated_at
      ) VALUES
        ('periapsis_api_login',false,clock_timestamp()),
        ('periapsis_notifier_login',false,clock_timestamp())
      ON CONFLICT (role_name) DO UPDATE
      SET enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at
    `;
  });
}

async function publish(input: {
  expectedVersion: number;
  policyId: string;
  versionId: string;
  rules: readonly Rule[];
  key: Buffer;
  request: Buffer;
  publishedAt: Date;
  reason: string;
}): Promise<{ policy: PolicyDocument; replayed: boolean }> {
  return asLogin(api, ids.tenant, ids.admin, async (transaction) => {
    const [prepared] = await transaction<
      { replayed: boolean; policy: PolicyDocument | null }[]
    >`
      SELECT replayed,policy
      FROM app.prepare_publish_tenant_webhook_url_policy_v1(
        ${ids.adminSession}::uuid,'totp',${input.key},${input.request}
      )
    `;
    assert(prepared, "policy prepare returned no row");
    if (prepared.replayed) {
      assert(prepared.policy, "policy replay returned no result");
      return { policy: prepared.policy, replayed: true };
    }
    const rules = canonicalRules(input.rules);
    const digests = policyDigests({
      tenantId: ids.tenant,
      policyId: input.policyId,
      versionId: input.versionId,
      version: input.expectedVersion + 1,
      membershipId: ids.adminMembership,
      publishedAt: input.publishedAt,
      rules,
    });
    const [committed] = await transaction<
      { policy: PolicyDocument; replayed: boolean }[]
    >`
      SELECT policy,replayed
      FROM app.commit_publish_tenant_webhook_url_policy_v1(
        ${ids.adminSession}::uuid,'totp',${input.expectedVersion},
        ${input.key},${input.request},${input.policyId}::uuid,
        ${input.versionId}::uuid,${transaction.json(rules)}::jsonb,
        ${digests.semantic},${digests.policy},${input.publishedAt},
        ${input.reason},${nextID()}::uuid,${nextID()}::uuid,${nextID()}::uuid,
        '127.0.0.1'::inet,'webhook-url-policy-runtime/1',
        ${ids.adminMembership}::uuid
      )
    `;
    assert(committed, "policy commit returned no row");
    return committed;
  });
}

function webhookPayload(eventID: string, occurredAt: Date) {
  return {
    schemaVersion: 1,
    event: {
      id: eventID,
      type: "alert.created",
      objectType: "alert",
      objectId: ids.configuration,
      objectVersion: 1,
      occurredAt: occurredAt.toISOString(),
    },
    context: {},
  };
}

const retry = {
  maximumAttempts: 3,
  initialDelayMs: 1_000,
  maximumDelayMs: 30_000,
  multiplier: 2,
  jitterPercent: 10,
} as const;

async function mutateWebhook(input: {
  configurationId: string;
  expectedVersion: number | null;
  endpointUrl: string;
  secretId: string;
  retainSigningKey: boolean;
  key: Buffer;
  request: Buffer;
  allowPlainLocal?: boolean;
}): Promise<{ projection: Record<string, unknown>; replayed: boolean }> {
  const payload = {
    name: `Webhook ${input.configurationId.slice(-4)}`,
    endpointUrl: input.endpointUrl,
    eventTypes: ["alert.created"],
    audience: "operator",
    retainSigningKey: input.retainSigningKey,
    timeoutMs: 5_000,
    enabled: true,
    ...(input.retainSigningKey
      ? {}
      : {
          signingKey: {
            id: input.secretId,
            version: 1,
            kind: "webhook_signing_key",
            keyVersion: 1,
            nonce: Buffer.alloc(12, 0x31).toString("base64"),
            ciphertext: Buffer.alloc(17, 0x32).toString("base64"),
          },
        }),
  };
  return asLogin(
    api,
    ids.tenant,
    ids.admin,
    async (transaction) => {
      const operation =
        input.expectedVersion === null ? "webhook.create" : "webhook.version";
      const [row] = await transaction<
        { projection: Record<string, unknown>; replayed: boolean }[]
      >`
        SELECT projection,replayed
        FROM app.mutate_tenant_notification_definition_v1(
          ${operation},${input.configurationId}::uuid,
          ${input.expectedVersion},${transaction.json(payload)}::jsonb,
          ${input.key},${input.request},date_trunc('milliseconds',clock_timestamp()),
          ${nextID()}::uuid,${nextID()}::uuid,'127.0.0.1'::inet,
          'webhook-url-policy-runtime/1','totp'
        )
      `;
      assert(row, "webhook mutation returned no row");
      return row;
    },
    input.allowPlainLocal ?? false,
  );
}

async function insertDelivery(input: {
  eventId: string;
  deliveryId: string;
  configurationId: string;
  configurationVersion: number;
  endpointUrl: string;
}): Promise<void> {
  const occurredAt = new Date(Date.now() - 5_000);
  const [configuration] = await admin<
    { secret_id: string; secret_version: number; key_version: number }[]
  >`
    SELECT version.signing_secret_id AS secret_id,
           version.signing_secret_version AS secret_version,
           secret.key_version
    FROM public.tenant_notification_webhook_configuration_versions AS version
    JOIN public.tenant_notification_secret_versions AS secret
      ON secret.tenant_id=version.tenant_id
     AND secret.secret_id=version.signing_secret_id
     AND secret.version=version.signing_secret_version
    WHERE version.tenant_id=${ids.tenant}::uuid
      AND version.configuration_id=${input.configurationId}::uuid
      AND version.version=${input.configurationVersion}
  `;
  assert(configuration, "delivery configuration secret is missing");
  await admin.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
        schema_version,payload,deduplication_key,actor_kind,producer,
        maximum_audience,occurred_at,available_at,created_at
      ) VALUES (
        ${input.eventId}::uuid,${ids.tenant}::uuid,'alert',
        ${ids.configuration}::uuid,1,'notification.webhook.custom',2,
        ${transaction.json({ operatorContext: {} })}::jsonb,
        ${`webhook-policy-${input.eventId}`},'system',
        'webhook.policy_runtime','operator',${occurredAt},${occurredAt},
        ${occurredAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_deliveries(
        id,tenant_id,event_id,delivery_key,webhook_configuration_id,
        webhook_configuration_version,webhook_signing_secret_id,
        webhook_signing_secret_version,webhook_signing_key_version,
        webhook_payload_version,webhook_payload,channel,audience,recipient,
        destination_redacted,context,priority,deduplication_key,
        grouping_window_ms,grouping_maximum_items,retry,maximum_attempts,
        next_attempt_at,created_at,updated_at
      ) VALUES (
        ${input.deliveryId}::uuid,${ids.tenant}::uuid,${input.eventId}::uuid,
        ${sha(`delivery:${input.deliveryId}`).toString("hex")},
        ${input.configurationId}::uuid,${input.configurationVersion},
        ${configuration.secret_id}::uuid,${configuration.secret_version},
        ${configuration.key_version},1,
        ${transaction.json(webhookPayload(input.eventId, occurredAt))}::jsonb,
        'webhook','operator',${input.endpointUrl},'webhook destination',
        '{}'::jsonb,50,${`webhook-policy-delivery-${input.deliveryId}`},
        0,1,${transaction.json(retry)}::jsonb,3,${occurredAt},
        ${occurredAt},${occurredAt}
      )
    `;
  });
}

async function claim(
  worker: string,
  allowPlainLocal = false,
): Promise<readonly ClaimDocument[]> {
  const result = await notifier.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    await transaction`
        SELECT set_config(
          'app.webhook_plain_local_exemption',
          ${allowPlainLocal ? "true" : "false"},true
        )
      `;
    const rows = await transaction<{ claim: ClaimDocument }[]>`
        SELECT claim
        FROM app.claim_notification_webhook_delivery_batch_v1(
          ${worker},10,300000,date_trunc('milliseconds',clock_timestamp())
        )
      `;
    return { value: rows.map((row) => row.claim) };
  });
  return result.value;
}

async function localDeliveryAuthorized(
  tenantID: string,
  allowPlainLocal = true,
): Promise<boolean> {
  const result = await notifier.begin(async (transaction) => {
    await transaction`
      SELECT set_config(
        'app.webhook_plain_local_exemption',
        ${allowPlainLocal ? "true" : "false"},true
      )
    `;
    const [authorization] = await transaction<{ allowed: boolean }[]>`
      SELECT allowed FROM app.get_local_webhook_delivery_authorization_v1(
        ${tenantID}::uuid
      )
    `;
    return { value: authorization?.allowed === true };
  });
  return result.value;
}

try {
  await setup();

  await Promise.all(
    ["periapsis_migrator", "periapsis_webhook_url_policy_owner"].map((role) =>
      rejects(
        asAdminRole(role, async (transaction) => {
          await transaction`
          INSERT INTO public.webhook_plain_local_runtime_role_opt_ins(
            role_name,enabled
          ) VALUES ('periapsis_api_login',true)
          ON CONFLICT (role_name) DO UPDATE SET enabled=EXCLUDED.enabled
        `;
        }),
        "42501",
        `${role} changed deployment-owned local webhook opt-in`,
      ),
    ),
  );
  await Promise.all(
    [api, notifier].map((connection) =>
      rejects(
        connection`
        UPDATE public.webhook_plain_local_runtime_role_opt_ins
        SET enabled=true WHERE role_name=session_user::text
      `,
        "42501",
        "runtime login changed deployment-owned local webhook opt-in",
      ),
    ),
  );
  const forgedBySetRole = await asAdminRole(
    "periapsis_api",
    async (transaction) => {
      await transaction`SELECT set_config(
        'app.webhook_plain_local_exemption','true',true
      )`;
      const [row] = await transaction<{ allowed: boolean }[]>`
        SELECT allowed FROM app.webhook_plain_local_delivery_authorized_v1()
      `;
      return row?.allowed;
    },
  );
  assert.equal(
    forgedBySetRole,
    false,
    "SET ROLE must not spoof the immutable login identity",
  );
  await admin`
    DELETE FROM public.webhook_plain_local_runtime_role_opt_ins
    WHERE role_name='periapsis_api_login'
  `;
  const absentApiOptIn = await asLogin(
    api,
    ids.tenant,
    ids.admin,
    async (transaction) =>
      (
        await transaction<{ allowed: boolean }[]>`
      SELECT allowed FROM app.webhook_plain_local_delivery_authorized_v1()
    `
      )[0]?.allowed,
    true,
  );
  assert.equal(
    absentApiOptIn,
    false,
    "an absent durable opt-in was treated as enabled",
  );
  await admin`
    INSERT INTO public.webhook_plain_local_runtime_role_opt_ins(
      role_name,enabled,updated_at
    ) VALUES ('periapsis_api_login',false,clock_timestamp())
  `;

  const initialRules = canonicalRules([
    {
      effect: "allow",
      match: "exact",
      hostname: "hooks.example.com",
      port: 443,
    },
    {
      effect: "deny",
      match: "subdomains",
      hostname: "blocked.example.com",
      port: 443,
    },
  ]);
  const firstKey = sha("policy-key-one");
  const firstRequest = sha("policy-request-one");
  const firstPublishedAt = new Date();
  firstPublishedAt.setUTCMilliseconds(
    Math.floor(firstPublishedAt.getUTCMilliseconds()),
  );
  const first = await publish({
    expectedVersion: 0,
    policyId: ids.policy,
    versionId: ids.policyVersionOne,
    rules: initialRules,
    key: firstKey,
    request: firstRequest,
    publishedAt: firstPublishedAt,
    reason: "Establish outbound webhook allowlist",
  });
  assert.equal(first.replayed, false);
  assert.equal(first.policy.version, 1);
  assert.deepEqual(first.policy.rules, initialRules);
  assert.equal(
    first.policy.digest,
    policyDigests({
      tenantId: ids.tenant,
      policyId: ids.policy,
      versionId: ids.policyVersionOne,
      version: 1,
      membershipId: ids.adminMembership,
      publishedAt: firstPublishedAt,
      rules: initialRules,
    }).policy.toString("hex"),
    "PostgreSQL and runtime policy digests diverged",
  );

  const [read] = await asLogin(
    api,
    ids.tenant,
    ids.admin,
    (transaction) =>
      transaction<{ policy: PolicyDocument }[]>`
      SELECT policy FROM app.get_tenant_webhook_url_policy_v1(
        ${ids.adminSession}::uuid,'totp'
      )
    `,
  );
  assert.equal(read?.policy.digest, first.policy.digest);
  await rejects(
    asLogin(
      api,
      ids.tenant,
      ids.viewer,
      (transaction) =>
        transaction`
        SELECT policy FROM app.get_tenant_webhook_url_policy_v1(
          ${ids.viewerSession}::uuid,'totp'
        )
      `,
    ),
    "42501",
    "viewer read the webhook URL policy",
  );
  await rejects(
    asLogin(
      api,
      ids.tenant,
      ids.foreignAdmin,
      (transaction) =>
        transaction`
        SELECT policy FROM app.get_tenant_webhook_url_policy_v1(
          ${ids.foreignSession}::uuid,'totp'
        )
      `,
    ),
    "42501",
    "foreign session crossed the tenant boundary",
  );

  const configKey = sha("config-key-one");
  const configRequest = sha("config-request-one");
  const created = await mutateWebhook({
    configurationId: ids.configuration,
    expectedVersion: null,
    endpointUrl: "HTTPS://hooks.example.com:443/notify?source=runtime",
    secretId: ids.configurationSecret,
    retainSigningKey: false,
    key: configKey,
    request: configRequest,
  });
  assert.equal(created.replayed, false);
  const [pinned] = await admin<
    {
      endpoint_url: string;
      endpoint_canonical_url: string;
      endpoint_digest: Buffer;
      policy_id: string;
      policy_version_id: string;
      policy_version: number;
      policy_digest: Buffer;
      local_development_exemption: boolean;
    }[]
  >`
    SELECT endpoint_url,endpoint_canonical_url,endpoint_digest,
           webhook_url_policy_id AS policy_id,
           webhook_url_policy_version_id AS policy_version_id,
           webhook_url_policy_version AS policy_version,
           webhook_url_policy_digest AS policy_digest,
           local_development_exemption
    FROM public.tenant_notification_webhook_configuration_versions
    WHERE tenant_id=${ids.tenant}::uuid
      AND configuration_id=${ids.configuration}::uuid AND version=1
  `;
  assert(pinned, "webhook configuration was not persisted");
  assert.equal(
    pinned.endpoint_url,
    "https://hooks.example.com/notify?source=runtime",
  );
  assert.equal(pinned.endpoint_canonical_url, pinned.endpoint_url);
  assert.equal(pinned.policy_id, ids.policy);
  assert.equal(pinned.policy_version_id, ids.policyVersionOne);
  assert.equal(pinned.policy_version, 1);
  assert.equal(pinned.policy_digest.toString("hex"), first.policy.digest);
  assert.equal(pinned.local_development_exemption, false);
  const configReplay = await mutateWebhook({
    configurationId: ids.configuration,
    expectedVersion: null,
    endpointUrl: "HTTPS://hooks.example.com:443/notify?source=runtime",
    secretId: ids.configurationSecret,
    retainSigningKey: false,
    key: configKey,
    request: configRequest,
  });
  assert.equal(configReplay.replayed, true);
  const [configCounts] = await admin<{ versions: string; secrets: string }[]>`
    SELECT
      (SELECT count(*)::text
       FROM public.tenant_notification_webhook_configuration_versions
       WHERE tenant_id=${ids.tenant}::uuid
         AND configuration_id=${ids.configuration}::uuid) AS versions,
      (SELECT count(*)::text FROM public.tenant_notification_secret_versions
       WHERE tenant_id=${ids.tenant}::uuid
         AND secret_id=${ids.configurationSecret}::uuid) AS secrets
  `;
  assert.deepEqual(configCounts, { versions: "1", secrets: "1" });

  await rejects(
    mutateWebhook({
      configurationId: ids.deniedConfiguration,
      expectedVersion: null,
      endpointUrl: "https://denied.example.com/notify",
      secretId: ids.deniedSecret,
      retainSigningKey: false,
      key: sha("denied-config-key"),
      request: sha("denied-config-request"),
    }),
    "42501",
    "configuration was created outside the allowlist",
  );
  const [deniedCounts] = await admin<
    { configurations: string; secrets: string }[]
  >`
    SELECT
      (SELECT count(*)::text
       FROM public.tenant_notification_webhook_configurations
       WHERE id=${ids.deniedConfiguration}::uuid) AS configurations,
      (SELECT count(*)::text FROM public.tenant_notification_secret_versions
       WHERE secret_id=${ids.deniedSecret}::uuid) AS secrets
  `;
  assert.deepEqual(
    deniedCounts,
    { configurations: "0", secrets: "0" },
    "denied configuration did not roll back identity and secret writes",
  );

  await insertDelivery({
    eventId: ids.validEvent,
    deliveryId: ids.validDelivery,
    configurationId: ids.configuration,
    configurationVersion: 1,
    endpointUrl: pinned.endpoint_url,
  });
  const [validClaim] = await claim("webhook-policy-valid");
  assert(validClaim, "valid pinned webhook delivery was not claimed");
  assert.equal(validClaim.id, ids.validDelivery);
  assert.equal(
    validClaim.endpointDigest,
    pinned.endpoint_digest.toString("hex"),
  );
  assert.equal(validClaim.policyDigest, first.policy.digest);
  assert.equal(validClaim.localDevelopmentExemption, false);
  assert.equal(validClaim.urlPolicy?.versionId, ids.policyVersionOne);

  const secondRules = canonicalRules([
    {
      effect: "allow",
      match: "exact",
      hostname: "updated.example.com",
      port: 443,
    },
  ]);
  const secondPublishedAt = new Date(
    Math.max(Date.now(), firstPublishedAt.getTime()),
  );
  secondPublishedAt.setUTCMilliseconds(
    Math.floor(secondPublishedAt.getUTCMilliseconds()),
  );
  const second = await publish({
    expectedVersion: 1,
    policyId: ids.policy,
    versionId: ids.policyVersionTwo,
    rules: secondRules,
    key: sha("policy-key-two"),
    request: sha("policy-request-two"),
    publishedAt: secondPublishedAt,
    reason: "Rotate outbound webhook allowlist",
  });
  assert.equal(second.policy.version, 2);
  const replay = await publish({
    expectedVersion: 0,
    policyId: ids.policy,
    versionId: ids.policyVersionOne,
    rules: initialRules,
    key: firstKey,
    request: firstRequest,
    publishedAt: firstPublishedAt,
    reason: "Establish outbound webhook allowlist",
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.policy.version, 1);
  const [currentAfterReplay] = await admin<{ current_version: number }[]>`
    SELECT current_version FROM public.tenant_webhook_url_policies
    WHERE tenant_id=${ids.tenant}::uuid
  `;
  assert.equal(currentAfterReplay?.current_version, 2);
  await rejects(
    publish({
      expectedVersion: 1,
      policyId: ids.policy,
      versionId: ids.policyVersionThree,
      rules: initialRules,
      key: sha("policy-key-stale"),
      request: sha("policy-request-stale"),
      publishedAt: new Date(Math.max(Date.now(), secondPublishedAt.getTime())),
      reason: "Attempt stale policy replacement",
    }),
    "40001",
    "stale policy CAS was accepted",
  );
  await rejects(
    publish({
      expectedVersion: 2,
      policyId: ids.policy,
      versionId: ids.policyVersionThree,
      rules: secondRules,
      key: sha("policy-key-no-change"),
      request: sha("policy-request-no-change"),
      publishedAt: new Date(Math.max(Date.now(), secondPublishedAt.getTime())),
      reason: "Attempt semantic no-op replacement",
    }),
    "23505",
    "semantic no-op policy replacement was accepted",
  );
  await rejects(
    asLogin(
      api,
      ids.tenant,
      ids.admin,
      (transaction) =>
        transaction`
        SELECT replayed,policy
        FROM app.prepare_publish_tenant_webhook_url_policy_v1(
          ${ids.adminSession}::uuid,'totp',${firstKey},${sha("divergent")}
        )
      `,
    ),
    "23505",
    "divergent policy idempotency reuse was accepted",
  );

  await insertDelivery({
    eventId: ids.staleEvent,
    deliveryId: ids.staleDelivery,
    configurationId: ids.configuration,
    configurationVersion: 1,
    endpointUrl: pinned.endpoint_url,
  });
  const staleClaims = await claim("webhook-policy-stale");
  assert.equal(staleClaims.length, 0, "stale policy pin reached the notifier");
  const [staleStatus] = await admin<
    {
      status: string;
      failure_code: string | null;
      failure_class: string | null;
    }[]
  >`
    SELECT status,failure_code,failure_class
    FROM public.tenant_notification_deliveries
    WHERE id=${ids.staleDelivery}::uuid
  `;
  assert.deepEqual(staleStatus, {
    status: "dead_lettered",
    failure_code: "configuration_revoked",
    failure_class: "security",
  });

  const currentConfigKey = sha("config-key-two");
  const currentConfigRequest = sha("config-request-two");
  const currentConfig = await mutateWebhook({
    configurationId: ids.configuration,
    expectedVersion: 1,
    endpointUrl: "https://updated.example.com/current",
    secretId: ids.configurationSecret,
    retainSigningKey: true,
    key: currentConfigKey,
    request: currentConfigRequest,
  });
  assert.equal(currentConfig.replayed, false);
  const [currentPin] = await admin<
    { endpoint_url: string; policy_version: number; policy_digest: Buffer }[]
  >`
    SELECT endpoint_url,webhook_url_policy_version AS policy_version,
           webhook_url_policy_digest AS policy_digest
    FROM public.tenant_notification_webhook_configuration_versions
    WHERE tenant_id=${ids.tenant}::uuid
      AND configuration_id=${ids.configuration}::uuid AND version=2
  `;
  assert(currentPin, "current webhook configuration pin was not persisted");
  assert.equal(currentPin.policy_version, 2);
  assert.equal(currentPin.policy_digest.toString("hex"), second.policy.digest);
  const currentConfigReplay = await mutateWebhook({
    configurationId: ids.configuration,
    expectedVersion: 1,
    endpointUrl: "https://updated.example.com/current",
    secretId: ids.configurationSecret,
    retainSigningKey: true,
    key: currentConfigKey,
    request: currentConfigRequest,
  });
  assert.equal(currentConfigReplay.replayed, true);
  await insertDelivery({
    eventId: ids.currentEvent,
    deliveryId: ids.currentDelivery,
    configurationId: ids.configuration,
    configurationVersion: 2,
    endpointUrl: currentPin.endpoint_url,
  });
  const [currentClaim] = await claim("webhook-policy-current");
  assert(currentClaim, "current webhook delivery was not claimed");
  assert.equal(currentClaim.id, ids.currentDelivery);
  assert.equal(currentClaim.urlPolicy?.versionId, ids.policyVersionTwo);

  const [policyForDelivery] = await notifier<
    { policy: PolicyDocument | null }[]
  >`
    SELECT policy FROM app.get_current_webhook_url_policy_for_delivery_v1(
      ${ids.tenant}::uuid,${ids.policy}::uuid
    )
  `;
  assert.equal(policyForDelivery?.policy?.version, 2);
  const [foreignPolicy] = await notifier<{ policy: PolicyDocument | null }[]>`
    SELECT policy FROM app.get_current_webhook_url_policy_for_delivery_v1(
      ${ids.foreignTenant}::uuid,${ids.policy}::uuid
    )
  `;
  assert.equal(foreignPolicy?.policy, null);

  const exactApiBefore = await asLogin(
    api,
    ids.tenant,
    ids.admin,
    async (transaction) =>
      (
        await transaction<{ allowed: boolean }[]>`
      SELECT allowed FROM app.webhook_plain_local_delivery_authorized_v1()
    `
      )[0]?.allowed,
    true,
  );
  assert.equal(exactApiBefore, false, "disabled role opt-in was ignored");
  await admin`
    UPDATE public.webhook_plain_local_runtime_role_opt_ins
    SET enabled=true,updated_at=clock_timestamp()
    WHERE role_name IN ('periapsis_api_login','periapsis_notifier_login')
  `;
  const exactApiAfter = await asLogin(
    api,
    ids.tenant,
    ids.admin,
    async (transaction) =>
      (
        await transaction<{ allowed: boolean }[]>`
      SELECT allowed FROM app.webhook_plain_local_delivery_authorized_v1()
    `
      )[0]?.allowed,
    true,
  );
  assert.equal(
    exactApiAfter,
    true,
    "double consent did not authorize API login",
  );
  const gucMissing = await asLogin(
    api,
    ids.tenant,
    ids.admin,
    async (transaction) =>
      (
        await transaction<{ allowed: boolean }[]>`
      SELECT allowed FROM app.webhook_plain_local_delivery_authorized_v1()
    `
      )[0]?.allowed,
  );
  assert.equal(
    gucMissing,
    false,
    "durable opt-in bypassed per-request consent",
  );

  await Promise.all(
    (
      [
        ["http://localhost.evil/hook", "42501"],
        ["http://127.0.0.2/hook", "42501"],
        ["http://10.0.0.1/hook", "42501"],
        ["http://169.254.169.254/hook", "42501"],
        ["https://127.0.0.1/hook", "22023"],
        ["https://169.254.169.254/hook", "22023"],
      ] as const
    ).map(([endpoint, code]) =>
      rejects(
        mutateWebhook({
          configurationId: nextID(),
          expectedVersion: null,
          endpointUrl: endpoint,
          secretId: nextID(),
          retainSigningKey: false,
          key: sha(`unsafe-key:${endpoint}`),
          request: sha(`unsafe-request:${endpoint}`),
          allowPlainLocal: true,
        }),
        code,
        `unsafe endpoint ${endpoint} passed the database boundary`,
      ),
    ),
  );
  const localKey = sha("local-config-key");
  const localRequest = sha("local-config-request");
  const localConfig = await mutateWebhook({
    configurationId: ids.localConfiguration,
    expectedVersion: null,
    endpointUrl: "http://localhost:8080/hook",
    secretId: ids.localSecret,
    retainSigningKey: false,
    key: localKey,
    request: localRequest,
    allowPlainLocal: true,
  });
  assert.equal(localConfig.replayed, false);
  const [localPin] = await admin<
    { endpoint_url: string; endpoint_digest: Buffer; local: boolean }[]
  >`
    SELECT endpoint_url,endpoint_digest,local_development_exemption AS local
    FROM public.tenant_notification_webhook_configuration_versions
    WHERE tenant_id=${ids.tenant}::uuid
      AND configuration_id=${ids.localConfiguration}::uuid AND version=1
  `;
  assert(localPin, "local webhook configuration pin was not persisted");
  assert.equal(localPin.local, true);
  await insertDelivery({
    eventId: ids.localEvent,
    deliveryId: ids.localDelivery,
    configurationId: ids.localConfiguration,
    configurationVersion: 1,
    endpointUrl: localPin.endpoint_url,
  });
  assert.equal(
    (await claim("webhook-policy-local-disabled")).length,
    0,
    "plain local delivery was claimed without per-request consent",
  );
  const [localDeadLetter] = await admin<{ status: string }[]>`
    SELECT status FROM public.tenant_notification_deliveries
    WHERE id=${ids.localDelivery}::uuid
  `;
  assert.equal(localDeadLetter?.status, "dead_lettered");
  await insertDelivery({
    eventId: ids.allowedLocalEvent,
    deliveryId: ids.allowedLocalDelivery,
    configurationId: ids.localConfiguration,
    configurationVersion: 1,
    endpointUrl: localPin.endpoint_url,
  });
  const [allowedLocalClaim] = await claim("webhook-policy-local-enabled", true);
  assert.equal(
    allowedLocalClaim?.id,
    ids.allowedLocalDelivery,
    "exact localhost was not claimed after both deployment consents",
  );
  assert.equal(allowedLocalClaim?.localDevelopmentExemption, true);

  assert.equal(
    await localDeliveryAuthorized(ids.tenant),
    true,
    "notifier could not revalidate an active local-development tenant",
  );
  await insertDelivery({
    eventId: ids.suspendedLocalEvent,
    deliveryId: ids.suspendedLocalDelivery,
    configurationId: ids.localConfiguration,
    configurationVersion: 1,
    endpointUrl: localPin.endpoint_url,
  });
  await admin`
    UPDATE public.tenants
    SET status='suspended',version=version+1,updated_at=clock_timestamp()
    WHERE id=${ids.tenant}::uuid
  `;
  assert.equal(
    await localDeliveryAuthorized(ids.tenant),
    false,
    "suspended tenant retained local-development delivery authorization",
  );
  assert.equal(
    (await claim("webhook-policy-local-suspended", true)).length,
    0,
    "plain local delivery was claimed for a suspended tenant",
  );
  const [suspendedLocal] = await admin<{ status: string }[]>`
    SELECT status FROM public.tenant_notification_deliveries
    WHERE id=${ids.suspendedLocalDelivery}::uuid
  `;
  assert.match(
    suspendedLocal?.status ?? "",
    /^(?:queued|dead_lettered)$/u,
    "suspended local delivery entered an active state",
  );
  await admin`
    UPDATE public.tenants
    SET status='active',version=version+1,updated_at=clock_timestamp()
    WHERE id=${ids.tenant}::uuid
  `;

  const audit = await admin<
    {
      before: unknown;
      after: unknown;
      metadata: unknown;
      reason: string | null;
    }[]
  >`
    SELECT before,after,metadata,reason FROM public.audit_events
    WHERE tenant_id=${ids.tenant}::uuid
      AND action='tenant.notification.webhook_url_policy.publish'
    ORDER BY sequence
  `;
  assert.equal(audit.length, 2);
  assert.equal(audit[0]?.reason, "Establish outbound webhook allowlist");
  assert.doesNotMatch(
    JSON.stringify(audit),
    /hooks[.]example|updated[.]example|blocked[.]example|semanticDigest|policyDigest|hostname|rules/iu,
    "webhook URL policy audit leaked policy content",
  );

  await admin`
    INSERT INTO public.tenant_membership_role_grants(
      id,tenant_id,membership_id,role_id,source_id,
      granted_by_membership_id,grant_reason
    )
    SELECT ${ids.recoveryGrant}::uuid,${ids.tenant}::uuid,
           ${ids.viewerMembership}::uuid,role.id,source.id,
           ${ids.adminMembership}::uuid,
           'Webhook policy runtime recovery administrator'
    FROM public.tenant_roles AS role
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id=role.tenant_id
     AND source.key='manual' AND source.retired_at IS NULL
    WHERE role.tenant_id=${ids.tenant}::uuid
      AND role.key='tenant_admin' AND role.archived_at IS NULL
  `;
  await admin`
    UPDATE public.tenant_memberships
    SET status='suspended',updated_at=clock_timestamp()
    WHERE id=${ids.adminMembership}::uuid
  `;
  await rejects(
    asLogin(
      api,
      ids.tenant,
      ids.admin,
      (transaction) =>
        transaction`
        SELECT policy FROM app.get_tenant_webhook_url_policy_v1(
          ${ids.adminSession}::uuid,'totp'
        )
      `,
    ),
    "42501",
    "suspended membership retained policy access",
  );
  await admin`
    UPDATE public.tenant_memberships
    SET status='active',updated_at=clock_timestamp()
    WHERE id=${ids.adminMembership}::uuid
  `;
  await admin`
    UPDATE public.auth_sessions SET revoked_at=clock_timestamp()
    WHERE id=${ids.adminSession}::uuid
  `;
  await rejects(
    asLogin(
      api,
      ids.tenant,
      ids.admin,
      (transaction) =>
        transaction`
        SELECT policy FROM app.get_tenant_webhook_url_policy_v1(
          ${ids.adminSession}::uuid,'totp'
        )
      `,
    ),
    "42501",
    "revoked session retained policy access",
  );

  process.stdout.write("webhook URL policy PostgreSQL runtime checks passed\n");
} finally {
  await Promise.all([admin.end(), api.end(), notifier.end()]);
}
