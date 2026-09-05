import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
import postgres, { type TransactionSql } from "postgres";

type JournalEntry = Readonly<{
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
}>;

type Journal = Readonly<{
  version: string;
  dialect: string;
  entries: readonly JournalEntry[];
}>;

type ErrorWithCode = Error & { code?: string };
type JsonValue = boolean | number | string | null | JsonObject | JsonValue[];
type JsonObject = { [key: string]: JsonValue };

const databaseUrl =
  process.env.PERIAPSIS_TENANT_FEDERATION_ADMIN_UPGRADE_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TENANT_FEDERATION_ADMIN_UPGRADE_TEST_DATABASE_URL must name an isolated empty PostgreSQL 18.6 database whose cluster has no periapsis_* roles",
  );
}

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

function parseJournal(source: string): Journal {
  const value: unknown = JSON.parse(source);
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    typeof value.dialect !== "string" ||
    !Array.isArray(value.entries) ||
    !value.entries.every(isJournalEntry)
  ) {
    throw new Error("the Drizzle migration journal is malformed");
  }
  return {
    version: value.version,
    dialect: value.dialect,
    entries: value.entries,
  };
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorTag = "0227_tenant_webhook_url_policy";
const targetTag = "0228_tenant_federation_administration";
const predecessorIndex = journal.entries.findIndex(
  (entry) => entry.tag === predecessorTag,
);
assert(predecessorIndex >= 0, `${predecessorTag} is absent from the journal`);
const predecessor = journal.entries[predecessorIndex];
assert(predecessor, `${predecessorTag} has no journal entry`);

const journalTargetIndex = journal.entries.findIndex(
  (entry) => entry.tag === targetTag,
);
const journalTarget = journal.entries[journalTargetIndex];
if (journalTarget !== undefined) {
  assert.equal(
    journalTargetIndex,
    predecessorIndex + 1,
    `${targetTag} must immediately follow ${predecessorTag}`,
  );
  assert.equal(journalTarget.idx, predecessor.idx + 1);
}

// The final migration journal is generated only after the coordinated 0228
// source freezes. A deterministic local entry keeps this exact source-level
// 0227 -> 0228 proof runnable while that generation is intentionally pending;
// once generated, the authoritative journal entry above is used instead.
const target: JournalEntry = journalTarget ?? {
  idx: predecessor.idx + 1,
  version: predecessor.version,
  when: predecessor.when + 1,
  tag: targetTag,
  breakpoints: true,
};
const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const targetEntries = [...predecessorEntries, target];

await readFile(resolve(migrationsRoot, `${targetTag}.sql`), "utf8");

const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-tenant-federation-upgrade-0227-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d7c20-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  user: uuid(3),
  foreignUser: uuid(4),
  membership: uuid(5),
  foreignMembership: uuid(6),
  provider: uuid(7),
  binding: uuid(8),
  command: uuid(9),
  createdProvider: uuid(10),
  createdBinding: uuid(11),
  request: uuid(12),
  correlation: uuid(13),
  secret: uuid(14),
} as const;

const publicSignatures = [
  "app.list_tenant_federated_auth_providers_v1(jsonb)",
  "app.get_tenant_federated_auth_provider_v1(jsonb)",
  "app.create_tenant_federated_auth_provider_v1(jsonb)",
  "app.update_tenant_federated_auth_provider_v1(jsonb)",
  "app.archive_tenant_federated_auth_provider_v1(jsonb)",
  "app.prepare_tenant_oidc_client_secret_v1(jsonb)",
  "app.replace_tenant_oidc_client_secret_v1(jsonb)",
  "app.clear_tenant_oidc_client_secret_v1(jsonb)",
  "app.get_tenant_federated_mapping_policy_v1(jsonb)",
  "app.replace_tenant_federated_mapping_policy_v1(jsonb)",
  "app.get_tenant_federated_assurance_policy_v1(jsonb)",
  "app.replace_tenant_federated_assurance_policy_v1(jsonb)",
  "app.prepare_tenant_oidc_trust_documents_v1(jsonb)",
  "app.commit_tenant_oidc_trust_documents_v1(jsonb)",
  "app.prepare_tenant_saml_metadata_v1(jsonb)",
  "app.replace_tenant_saml_metadata_v1(jsonb)",
  "app.prepare_tenant_saml_sp_credential_v1(jsonb)",
  "app.replace_tenant_saml_sp_credential_v1(jsonb)",
  "app.clear_tenant_saml_sp_credential_v1(jsonb)",
  "app.get_tenant_saml_sp_metadata_v1(jsonb)",
] as const;

async function writeStage(entries: readonly JournalEntry[]): Promise<void> {
  await mkdir(resolve(stageRoot, "meta"), { recursive: true });
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

async function setApiContext(
  transaction: TransactionSql,
  tenantId: string,
  userId: string,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', ${userId}, true)
  `;
}

async function callAsApi(
  functionName:
    | "create_tenant_federated_auth_provider_v1"
    | "get_tenant_federated_auth_provider_v1"
    | "list_tenant_federated_auth_providers_v1",
  request: JsonObject,
  tenantId: string = fixture.tenant,
  userId: string = fixture.user,
): Promise<JsonValue> {
  const result = await sql.begin(async (transaction) => {
    await setApiContext(transaction, tenantId, userId);
    const [row] = await transaction<{ response: JsonValue }[]>`
      SELECT ${transaction(`app.${functionName}`)}(
        ${JSON.stringify(request)}::jsonb
      ) AS response
    `;
    assert(row, `${functionName} returned no row`);
    return { response: row.response };
  });
  return result.response;
}

async function providerSnapshot(): Promise<JsonValue> {
  const [row] = await sql<{ snapshot: JsonValue }[]>`
    SELECT jsonb_build_object(
      'provider', to_jsonb(provider),
      'binding', to_jsonb(binding),
      'policy', to_jsonb(policy),
      'configuration', to_jsonb(configuration),
      'claims', coalesce((
        SELECT jsonb_agg(to_jsonb(claim) ORDER BY claim.source, claim.sequence)
        FROM public.tenant_oidc_claim_rules AS claim
        WHERE claim.tenant_id = provider.tenant_id
          AND claim.provider_id = provider.id
      ), '[]'::jsonb)
    ) AS snapshot
    FROM public.tenant_auth_providers AS provider
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = provider.tenant_id
     AND binding.provider_id = provider.id
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = provider.tenant_id
     AND policy.provider_id = provider.id
    JOIN public.tenant_oidc_provider_configurations AS configuration
      ON configuration.tenant_id = provider.tenant_id
     AND configuration.provider_id = provider.id
    WHERE provider.tenant_id = ${fixture.tenant}::uuid
      AND provider.id = ${fixture.provider}::uuid
  `;
  assert(row, "the predecessor OIDC provider is missing");
  return row.snapshot;
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert.equal(server?.version, "18.6");

  await writeStage(predecessorEntries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
  const [predecessorState] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count, max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(predecessorState, {
    count: predecessorEntries.length,
    latest: String(predecessor.when),
  });

  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, 'federation-upgrade', 'Federation upgrade'),
        (${fixture.foreignTenant}::uuid, 'federation-upgrade-foreign', 'Federation upgrade foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name) VALUES
        (${fixture.user}::uuid, 'federation-upgrade@example.invalid', 'Federation upgrade actor'),
        (${fixture.foreignUser}::uuid, 'federation-upgrade-foreign@example.invalid', 'Federation upgrade foreign actor')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
        (${fixture.membership}::uuid, ${fixture.tenant}::uuid, ${fixture.user}::uuid, 'tenant_admin', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid, ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.membership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_auth_providers (
        id, tenant_id, key, display_name, description, kind, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES (${fixture.provider}::uuid, ${fixture.tenant}::uuid,
        'predecessor_oidc', 'Predecessor OIDC',
        'Created while 0227 is the schema head.', 'oidc', false,
        ${fixture.membership}::uuid, ${fixture.membership}::uuid)
    `;
    await transaction`
      SELECT app.private_create_tenant_auth_provider_login_claim_v1(
        ${fixture.tenant}::uuid, 'tenant_provider',
        ${fixture.binding}::uuid, 'predecessor-oidc'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_auth_provider_bindings (
        id, tenant_id, binding_family, provider_id, key, enabled,
        created_by_membership_id, updated_by_membership_id
      ) VALUES (${fixture.binding}::uuid, ${fixture.tenant}::uuid,
        'tenant_provider', ${fixture.provider}::uuid, 'predecessor-oidc', false,
        ${fixture.membership}::uuid, ${fixture.membership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_federated_provider_policies (
        tenant_id, provider_id, binding_id, provider_kind,
        configuration_revision, security_revision, plan_revision,
        assurance_policy_revision, jit_mode, no_match_policy, enabled
      ) VALUES (${fixture.tenant}::uuid, ${fixture.provider}::uuid,
        ${fixture.binding}::uuid, 'oidc', 1, 1, 1, 1,
        'disabled', 'deny', false)
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_provider_configurations (
        tenant_id, provider_id, provider_kind, issuer, client_id, redirect_uri,
        post_logout_redirect_uri, extra_scopes, allow_refresh_token, use_user_info,
        client_secret_revision, discovery_revision, jwks_revision, version
      ) VALUES (${fixture.tenant}::uuid, ${fixture.provider}::uuid, 'oidc',
        'https://idp.example.invalid/realms/predecessor', 'predecessor-client',
        'https://soc.example.invalid/api/v1/auth/federated/oidc/callback',
        'https://soc.example.invalid/signed-out', ARRAY['email','profile'],
        false, false, 1, 1, 1, 1)
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_claim_rules (
        tenant_id, provider_id, source, sequence, kind, claim_name,
        profile_field, required
      ) VALUES (${fixture.tenant}::uuid, ${fixture.provider}::uuid,
        'id_token', 0, 'profile', 'preferred_username', 'username', true)
    `;
    await transaction`
      INSERT INTO public.identity_keyring_versions (
        key_version, verifier, is_active
      ) VALUES (1, ${Buffer.alloc(32, 0x71)}, true)
    `;
    await transaction`
      INSERT INTO public.tenant_oidc_client_secrets (
        id, tenant_id, provider_id, revision, key_version, nonce, ciphertext
      ) VALUES (
        ${fixture.secret}::uuid, ${fixture.tenant}::uuid,
        ${fixture.provider}::uuid, 1, 1,
        ${Buffer.alloc(12, 0x72)}, ${Buffer.alloc(32, 0x73)}
      )
    `;
  });

  const before = await providerSnapshot();
  const [missingFunctions] = await sql<{ missing: number }[]>`
    SELECT count(*)::integer AS missing
    FROM unnest(${publicSignatures}::text[]) AS signature
    WHERE to_regprocedure(signature) IS NULL
  `;
  assert.equal(
    missingFunctions?.missing,
    publicSignatures.length,
    "0228 administration functions leaked into the 0227 predecessor",
  );

  await writeStage(targetEntries);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });

  assert.deepEqual(
    await providerSnapshot(),
    before,
    "0228 rewrote an existing tenant OIDC provider",
  );
  const [targetState] = await sql<{ count: number; latest: string }[]>`
    SELECT count(*)::integer AS count, max(created_at)::text AS latest
    FROM drizzle.__drizzle_migrations
  `;
  assert.deepEqual(targetState, {
    count: targetEntries.length,
    latest: String(target.when),
  });

  const functionAcls = await Promise.all(
    publicSignatures.map(async (signature) => {
      const [acl] = await sql<
        {
          apiExecute: boolean;
          forbiddenExecute: boolean;
          owner: string;
          publicExecute: boolean;
          searchPath: string[] | null;
          securityDefiner: boolean;
        }[]
      >`
        SELECT pg_get_userbyid(procedure.proowner) AS owner,
          procedure.prosecdef AS "securityDefiner",
          procedure.proconfig AS "searchPath",
          has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE')
            AS "apiExecute",
          has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE')
            OR has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE')
            OR has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
            AS "forbiddenExecute",
          EXISTS (
            SELECT 1
            FROM aclexplode(coalesce(procedure.proacl, acldefault('f', procedure.proowner))) AS privilege
            WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
          ) AS "publicExecute"
        FROM pg_proc AS procedure
        WHERE procedure.oid = to_regprocedure(${signature})
      `;
      return { acl, signature };
    }),
  );
  for (const { acl, signature } of functionAcls) {
    assert.deepEqual(
      acl,
      {
        apiExecute: true,
        forbiddenExecute: false,
        owner: "periapsis_migrator",
        publicExecute: false,
        searchPath: ["search_path=pg_catalog, public, app"],
        securityDefiner: true,
      },
      `${signature} is not a fixed-path API-only security definer`,
    );
  }

  const [keyringVerifier] = await sql<
    {
      apiExecute: boolean;
      auditorExecute: boolean;
      owner: string;
      publicExecute: boolean;
      searchPath: string[] | null;
      securityDefiner: boolean;
      workerExecute: boolean;
    }[]
  >`
    SELECT pg_get_userbyid(procedure.proowner) AS owner,
      procedure.prosecdef AS "securityDefiner",
      procedure.proconfig AS "searchPath",
      has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE')
        AS "apiExecute",
      has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE')
        AS "workerExecute",
      has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE')
        OR has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
        AS "auditorExecute",
      EXISTS (
        SELECT 1
        FROM aclexplode(coalesce(procedure.proacl, acldefault('f', procedure.proowner))) AS privilege
        WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
      ) AS "publicExecute"
    FROM pg_proc AS procedure
    WHERE procedure.oid =
      'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
  `;
  assert.deepEqual(keyringVerifier, {
    apiExecute: true,
    auditorExecute: false,
    owner: "periapsis_migrator",
    publicExecute: false,
    searchPath: ["search_path=pg_catalog, public, app"],
    securityDefiner: true,
    workerExecute: true,
  });

  const rollbackKeyringProbe = new Error(
    "rollback upgraded tenant federation keyring probe",
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.identity_keyring_versions
        SET is_active = false
        WHERE key_version = 1
      `;
      await transaction`
        INSERT INTO public.identity_keyring_versions (
          key_version, verifier, is_active
        ) VALUES (2, ${Buffer.alloc(32, 0x72)}, true)
      `;
      const [omitted] = await transaction<{ verified: boolean }[]>`
        SELECT app.verify_identity_keyring_v3(
          ARRAY[2]::integer[], ARRAY[${Buffer.alloc(32, 0x72)}::bytea], 2
        ) AS verified
      `;
      assert.equal(omitted?.verified, false);
      const [retained] = await transaction<{ verified: boolean }[]>`
        SELECT app.verify_identity_keyring_v3(
          ARRAY[1, 2]::integer[],
          ARRAY[
            ${Buffer.alloc(32, 0x71)}::bytea,
            ${Buffer.alloc(32, 0x72)}::bytea
          ],
          2
        ) AS verified
      `;
      assert.equal(retained?.verified, true);
      throw rollbackKeyringProbe;
    }),
    (error: unknown) => error === rollbackKeyringProbe,
  );

  const visible = await callAsApi("list_tenant_federated_auth_providers_v1", {
    after: null,
    includeArchived: false,
    limit: 25,
  });
  assert(Array.isArray(visible));
  assert.equal(visible.length, 1);
  assert.equal(
    isRecord(visible[0]) ? visible[0].id : undefined,
    fixture.provider,
  );
  assert.deepEqual(
    await callAsApi(
      "list_tenant_federated_auth_providers_v1",
      { after: null, includeArchived: false, limit: 25 },
      fixture.foreignTenant,
      fixture.foreignUser,
    ),
    [],
  );
  await assert.rejects(
    callAsApi(
      "get_tenant_federated_auth_provider_v1",
      { providerId: fixture.provider },
      fixture.foreignTenant,
      fixture.foreignUser,
    ),
    (error: unknown) => assertSqlState(error, "P0002"),
  );

  const occurredAt = new Date().toISOString();
  const created = await callAsApi("create_tenant_federated_auth_provider_v1", {
    audit: {
      authenticationMethod: "totp",
      correlationId: fixture.correlation,
      remoteAddress: "192.0.2.228",
      requestId: fixture.request,
      userAgent: "Periapsis 0227 to 0228 upgrade proof",
    },
    bindingId: fixture.createdBinding,
    commandId: fixture.command,
    description: "Created after the exact 0227 to 0228 transition.",
    displayName: "Post-upgrade OIDC",
    idempotencyDigest: createHash("sha256")
      .update("tenant-federation-upgrade-idempotency")
      .digest("base64"),
    jitMode: "disabled",
    key: "post_upgrade_oidc",
    kind: "oidc",
    loginKey: "post-upgrade-oidc",
    membershipId: fixture.membership,
    noMatchPolicy: "deny",
    occurredAt,
    oidc: {
      allowRefreshToken: false,
      clientId: "post-upgrade-client",
      extraScopes: ["email", "profile"],
      issuer: "https://idp.example.invalid/realms/post-upgrade",
      postLogoutRedirectUri: "https://soc.example.invalid/signed-out",
      useUserInfo: false,
    },
    oidcRedirectUri:
      "https://soc.example.invalid/api/v1/auth/federated/oidc/callback",
    providerId: fixture.createdProvider,
    reason: "prove the post-upgrade tenant administration writer",
    requestDigest: createHash("sha256")
      .update("tenant-federation-upgrade-request")
      .digest("base64"),
    saml: null,
    samlAcsUrl: "https://soc.example.invalid/api/v1/auth/federated/saml/acs",
    samlSpMetadataBaseUrl:
      "https://soc.example.invalid/api/v1/auth/federated/saml",
  });
  assert(
    isRecord(created) &&
      created.replayed === false &&
      isRecord(created.provider) &&
      created.provider.id === fixture.createdProvider,
    "the post-upgrade provider writer did not return its new provider",
  );
  const [audit] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND resource_id = ${fixture.createdProvider}::uuid
      AND action = 'tenant.identity_provider.federated.created'
  `;
  assert.equal(audit?.count, 1);

  process.stdout.write(
    "tenant federation administration 0227 to 0228 upgrade checks passed\n",
  );
} finally {
  await Promise.all([
    sql.end({ timeout: 5 }),
    rm(stageRoot, { recursive: true, force: true }),
  ]);
}
