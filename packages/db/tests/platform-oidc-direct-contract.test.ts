import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  expectedPlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
  expectedRetiredSchemaCompatibilityV39SourceHash,
  expectedSchemaCompatibilityV39SourceHash,
  expectedSchemaCompatibilityV40SourceHash,
} from "../src/admin/schema-compatibility-manifest.gen.js";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const source = (path: string): string =>
  readFileSync(resolve(packageRoot, path), "utf8");
const repositorySource = (path: string): string =>
  readFileSync(resolve(repositoryRoot, path), "utf8");

const directSchema = source("src/schema/identity-platform-login.ts");
const identitySchema = source("src/schema/identity.ts");
const authenticationSchema = source("src/schema/authentication.ts");
const generatedMigration = source("migrations/0177_aspiring_mojo.sql");
const runtime = source("migrations/0178_platform_oidc_direct_runtime.sql");
const readiness = source(
  "migrations/0179_platform_oidc_direct_compatibility.sql",
);
const administration = source(
  "migrations/0180_platform_oidc_direct_administration.sql",
);
const administrationReadiness = source(
  "migrations/0181_platform_oidc_direct_administration_compatibility.sql",
);
const tenantFederationAdministration = source(
  "migrations/0228_tenant_federation_administration.sql",
);
const generator = repositorySource("scripts/generate-schema-compatibility.mjs");
const apiHealth = repositorySource("services/api/internal/postgres/health.go");
const workerHealth = repositorySource(
  "services/worker/internal/postgres/health.go",
);
type JournalEntry = {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const isJournalEntry = (value: unknown): value is JournalEntry =>
  isRecord(value) &&
  Number.isSafeInteger(value.idx) &&
  typeof value.version === "string" &&
  Number.isSafeInteger(value.when) &&
  typeof value.tag === "string" &&
  typeof value.breakpoints === "boolean";

const parsedJournal: unknown = JSON.parse(
  source("migrations/meta/_journal.json"),
);
if (
  !isRecord(parsedJournal) ||
  !Array.isArray(parsedJournal.entries) ||
  !parsedJournal.entries.every(isJournalEntry)
) {
  throw new Error("Drizzle migration journal is malformed");
}
const journal = { entries: parsedJournal.entries };

const escapeRegExp = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const withoutWhitespace = (value: string): string => value.replace(/\s+/gu, "");

const functionBodyFrom = (sql: string, name: string): string => {
  const marker = new RegExp(
    `CREATE (?:OR REPLACE )?FUNCTION app\\.${escapeRegExp(name)}\\(`,
    "u",
  ).exec(sql);
  expect(marker, `missing app.${name}`).not.toBeNull();
  const end = sql.indexOf("$function$;", marker!.index);
  expect(end, `unterminated app.${name}`).toBeGreaterThan(marker!.index);
  return sql.slice(marker!.index, end + "$function$;".length);
};

const drizzleTableBody = (name: string): string => {
  const marker = directSchema.indexOf(`\n  "${name}",`);
  expect(marker, `missing Drizzle table ${name}`).toBeGreaterThan(-1);
  const end = directSchema.indexOf(").enableRLS();", marker);
  expect(end, `unterminated Drizzle table ${name}`).toBeGreaterThan(marker);
  return directSchema.slice(marker, end + ").enableRLS();".length);
};

const migrationTableBody = (name: string): string => {
  const marker = generatedMigration.indexOf(`CREATE TABLE "${name}" (`);
  expect(marker, `missing generated table ${name}`).toBeGreaterThan(-1);
  const end = generatedMigration.indexOf(");", marker);
  expect(end, `unterminated generated table ${name}`).toBeGreaterThan(marker);
  return generatedMigration.slice(marker, end + 2);
};

const platformTables = [
  "platform_oidc_login_policies",
  "platform_oidc_authentication_transactions",
  "platform_post_primary_continuations",
  "platform_post_primary_continuation_evidence",
  "platform_post_primary_continuation_policy_pins",
  "platform_post_primary_totp_challenges",
  "auth_session_platform_oidc_states",
  "auth_session_platform_oidc_provenance",
  "auth_session_platform_oidc_evidence",
  "auth_session_platform_oidc_policy_pins",
  "platform_oidc_authentication_applications",
  "platform_oidc_session_revalidation_commands",
  "platform_oidc_tenant_switch_commands",
] as const;

const directJsonAbis = [
  "begin_platform_oidc_authentication_v1",
  "resolve_platform_oidc_authentication_configuration_v1",
  "create_platform_oidc_authentication_transaction_v1",
  "claim_platform_oidc_authentication_transaction_v1",
  "resolve_platform_oidc_authentication_v1",
  "fail_platform_oidc_authentication_transaction_v1",
  "load_platform_oidc_client_secret_v1",
  "load_platform_oidc_trust_snapshot_v1",
  "load_platform_oidc_planning_state_v1",
  "apply_platform_oidc_authentication_v1",
  "begin_platform_post_primary_totp_v1",
  "load_platform_post_primary_totp_v1",
  "record_platform_post_primary_totp_failure_v1",
  "apply_platform_post_primary_totp_v1",
  "abandon_platform_post_primary_totp_v1",
  "load_platform_oidc_session_revalidation_v1",
  "apply_platform_oidc_session_revalidation_v1",
  "load_platform_oidc_tenant_switch_v1",
  "apply_platform_oidc_tenant_switch_v1",
  "cleanup_platform_oidc_authentication_runtime_v1",
] as const;

describe("direct platform OIDC v39 database contract", () => {
  it("keeps exactly thirteen platform-owned physical relations outside tenant ownership", () => {
    expect(directSchema.match(/\.enableRLS\(\)/gu)).toHaveLength(
      platformTables.length,
    );
    expect(generatedMigration.match(/^CREATE TABLE /gmu)).toHaveLength(
      platformTables.length,
    );
    expect(
      generatedMigration.match(/ENABLE ROW LEVEL SECURITY/gmu),
    ).toHaveLength(platformTables.length);

    for (const table of platformTables) {
      const drizzle = drizzleTableBody(table);
      const generated = migrationTableBody(table);
      expect(drizzle).not.toContain('tenantId: uuid("tenant_id")');
      expect(generated).not.toMatch(/^\s*"tenant_id"\s/gmu);
      expect(runtime).toContain(
        `ALTER TABLE ONLY public.${table}\n  FORCE ROW LEVEL SECURITY;`,
      );
      expect(runtime).toContain(
        `ALTER TABLE public.${table} OWNER TO periapsis_migrator;`,
      );
    }

    expect(readiness).toContain("SELECT count(*) = 13");
    expect(readiness).toContain("relation.relrowsecurity");
    expect(readiness).toContain("relation.relforcerowsecurity");
    expect(readiness).toContain("pg_catalog.pg_policy");
  });

  it("pins the exact callback, S256 and the explicit refresh opt-in", () => {
    const transaction = drizzleTableBody(
      "platform_oidc_authentication_transactions",
    );
    const configuration = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_configuration_v1",
    );
    const createTransaction = functionBodyFrom(
      runtime,
      "create_platform_oidc_authentication_transaction_v1",
    );

    for (const contract of [transaction, generatedMigration, configuration]) {
      expect(contract).toContain(
        "^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$",
      );
    }
    expect(transaction).toContain("${table.codeChallengeMethod} = 'S256'");
    expect(transaction).not.toContain("not ${table.allowRefreshToken}");
    expect(generatedMigration).toContain(
      'CONSTRAINT "platform_oidc_auth_transactions_refresh_check" CHECK (not "platform_oidc_authentication_transactions"."allow_refresh_token")',
    );
    expect(configuration).toContain(
      "AND NOT configuration.allow_refresh_token",
    );
    expect(tenantFederationAdministration).toContain(
      "DROP CONSTRAINT platform_oidc_auth_transactions_refresh_check",
    );
    expect(tenantFederationAdministration).toContain(
      "v_old text := E'     AND NOT configuration.allow_refresh_token\\n'",
    );
    expect(tenantFederationAdministration).toContain(
      "EXECUTE replace(v_definition,v_old,'')",
    );
    expect(createTransaction).toContain(
      "current_request ->> 'codeChallengeMethod' <> 'S256'",
    );
    expect(createTransaction).toContain(
      "(live_record #>> '{authorization,allowRefreshToken}')::boolean",
    );
    expect(readiness).toContain("WHERE transaction.allow_refresh_token");
    expect(transaction).toContain(
      'browserCapabilityDigest: bytea("browser_capability_digest").notNull()',
    );
    expect(generatedMigration).toContain(
      '"browser_capability_digest" "bytea" NOT NULL',
    );
    expect(transaction).toContain(
      "${table.browserCapabilityDigest} <> ${table.browserDigest}",
    );
    expect(createTransaction).toContain(
      "browser_capability_digest,nonce_digest",
    );
    expect(readiness).toContain(
      "transaction.browser_capability_digest = transaction.browser_digest",
    );
  });

  it("resolves start by public login key and meters each atomic create", () => {
    const begin = functionBodyFrom(
      runtime,
      "begin_platform_oidc_authentication_v1",
    );
    const callback = functionBodyFrom(
      runtime,
      "resolve_platform_oidc_authentication_configuration_v1",
    );
    const createTransaction = functionBodyFrom(
      runtime,
      "create_platform_oidc_authentication_transaction_v1",
    );

    expect(withoutWhitespace(begin)).toContain(
      "p_lookup,ARRAY['loginKey'],ARRAY['loginKey'],4096",
    );
    expect(begin).toContain("provider.key = login_key");
    expect(begin).not.toContain("p_lookup -> 'provider'");
    expect(callback).toContain(
      "ARRAY['transactionId','expectedVersion','pins','browserCapabilityDigest']",
    );
    expect(callback).toContain("transaction.state = 'claimed'");
    expect(callback).toContain(
      "transaction.browser_capability_digest = browser_capability_digest",
    );
    expect(callback).toContain("'returnPath',transaction_record.return_path");
    expect(callback).toContain("'configuration',configuration");

    for (const scope of [
      "platform_oidc_network",
      "platform_oidc_account",
      "platform_oidc_provider",
    ]) {
      expect(generatedMigration).toContain(`ADD VALUE '${scope}'`);
      expect(createTransaction).toContain(`'${scope}'`);
      expect(readiness).toContain(`'${scope}'`);
    }
    expect(createTransaction).toContain("FROM app.admit_auth_attempts(");
    expect(createTransaction).toContain("ARRAY[60,900,60]::integer[]");
    expect(createTransaction).toContain("ARRAY[30,10,100]::integer[]");
    expect(createTransaction).toContain("ARRAY[300,900,300]::integer[]");
    expect(createTransaction.indexOf("IF FOUND THEN")).toBeLessThan(
      createTransaction.indexOf("FROM app.admit_auth_attempts("),
    );
    expect(
      createTransaction.indexOf("IF NOT admission.admitted THEN"),
    ).toBeLessThan(
      createTransaction.indexOf(
        "UPDATE ONLY public.platform_oidc_authentication_transactions AS previous",
      ),
    );
  });

  it("leaves direct login dormant behind a separate disabled-only policy", () => {
    const policyGuard = functionBodyFrom(
      runtime,
      "guard_platform_oidc_login_policy_v1",
    );
    const configuration = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_configuration_v1",
    );
    const createProvider = functionBodyFrom(
      runtime,
      "create_platform_oidc_auth_provider_v3",
    );

    expect(runtime).toContain(
      "SELECT provider.id, 'oidc', 'disabled', false, 1,",
    );
    expect(runtime).toContain("WHERE policy.platform_login_enabled");
    expect(runtime).not.toMatch(
      /UPDATE(?: ONLY)? public\.platform_oidc_login_policies/u,
    );
    expect(policyGuard).toContain("NEW.account_mode <> 'disabled'");
    expect(policyGuard).toContain(
      "direct platform OIDC policy has no v39 mutation ABI",
    );
    expect(configuration).toContain(
      "NOT runtime_policy.platform_login_enabled",
    );
    expect(configuration).toContain("login_policy.enabled");
    expect(configuration).toContain(
      "login_policy.account_mode = 'existing_identity'",
    );
    expect(createProvider).toContain(
      "FROM app.create_platform_oidc_auth_provider_v2(",
    );
    expect(createProvider).toContain(
      "created.provider_id,'oidc','disabled',false,1,",
    );
    expect(readiness).toContain("login_policy.account_mode <> 'disabled'");
    expect(readiness).toContain("OR login_policy.enabled");
  });

  it("separates user and TOTP security authority from presentation and replay counters", () => {
    const userGuard = functionBodyFrom(
      runtime,
      "guard_user_platform_identity_projection_v1",
    );
    const totpGuard = functionBodyFrom(
      runtime,
      "guard_totp_credential_security_revision_v1",
    );
    const applyTotp = functionBodyFrom(
      runtime,
      "apply_platform_post_primary_totp_v1",
    );

    expect(identitySchema).toContain(
      'authenticationRevision: bigint("authentication_revision"',
    );
    expect(authenticationSchema).toContain(
      'securityRevision: bigint("security_revision"',
    );
    expect(generatedMigration).toContain(
      'ALTER TABLE "users" ADD COLUMN "authentication_revision" bigint DEFAULT 1 NOT NULL',
    );
    expect(generatedMigration).toContain(
      'ALTER TABLE "totp_credentials" ADD COLUMN "security_revision" bigint DEFAULT 1 NOT NULL',
    );

    expect(userGuard).toContain(
      "active_changed := NEW.active IS DISTINCT FROM OLD.active",
    );
    expect(userGuard).toContain(
      "NEW.authentication_revision := OLD.authentication_revision + 1",
    );
    expect(userGuard).toContain(
      "user authentication revision changed without active state",
    );
    expect(totpGuard).toContain("NEW.secret_ciphertext");
    expect(totpGuard).toContain("NEW.disabled_at");
    expect(totpGuard).not.toContain("last_accepted_counter");
    expect(totpGuard).toContain(
      "NEW.security_revision := OLD.security_revision + 1",
    );
    expect(applyTotp).toContain("SET last_accepted_counter = accepted_counter");
    expect(applyTotp).toContain(
      "factor.last_accepted_counter < accepted_counter",
    );
    expect(applyTotp).toContain(
      "factor.security_revision = challenge_record.totp_security_revision",
    );
  });

  it("binds every post-primary TOTP operation to the exact continuation capability", () => {
    const functions = [
      {
        name: "load_platform_post_primary_totp_v1",
        argument: "p_lookup",
        maximumSize: 16384,
        keys: [
          "challengeId",
          "browserDigest",
          "continuationId",
          "receiptDigest",
          "observedAt",
        ],
      },
      {
        name: "record_platform_post_primary_totp_failure_v1",
        argument: "p_request",
        maximumSize: 24576,
        keys: [
          "challengeId",
          "browserDigest",
          "continuationId",
          "receiptDigest",
          "expectedVersion",
          "observedAt",
          "audit",
        ],
      },
      {
        name: "apply_platform_post_primary_totp_v1",
        argument: "p_request",
        maximumSize: 65536,
        keys: [
          "challengeId",
          "browserDigest",
          "continuationId",
          "receiptDigest",
          "expectedVersion",
          "acceptedCounter",
          "completionRequestDigest",
          "session",
          "observedAt",
          "audit",
        ],
      },
      {
        name: "abandon_platform_post_primary_totp_v1",
        argument: "p_request",
        maximumSize: 24576,
        keys: [
          "challengeId",
          "browserDigest",
          "continuationId",
          "receiptDigest",
          "expectedVersion",
          "observedAt",
          "reason",
          "audit",
        ],
      },
    ] as const;

    for (const contract of functions) {
      const body = functionBodyFrom(runtime, contract.name);
      const compact = withoutWhitespace(body);
      const exactKeys = `ARRAY[${contract.keys
        .map((key) => `'${key}'`)
        .join(",")}]`;
      expect(compact).toContain(
        withoutWhitespace(
          `${contract.argument},${exactKeys},${exactKeys},${contract.maximumSize}`,
        ),
      );
      expect(compact).toContain(
        `continuation_id:=app.private_mfa_require_uuidv7_v1(${contract.argument}->>'continuationId')`,
      );
      expect(compact).toContain(
        `receipt_digest:=app.private_mfa_decode_base64_v1(${contract.argument}->>'receiptDigest',32,32)`,
      );
      expect(body).toContain("continuation.id = continuation_id");
      expect(body).toContain("continuation.receipt_digest = receipt_digest");
      expect(body).toContain(
        "app.private_platform_oidc_direct_authority_live_v1(",
      );
      expect(body).toContain(
        contract.name === "load_platform_post_primary_totp_v1"
          ? "factor.id = continuation.selected_totp_credential_id"
          : contract.name === "apply_platform_post_primary_totp_v1"
            ? "factor.id = challenge_record.totp_credential_id"
            : "factor.id = continuation_record.selected_totp_credential_id",
      );
      expect(body).toContain(
        contract.name === "load_platform_post_primary_totp_v1"
          ? "continuation.selected_totp_security_revision"
          : "continuation_record.selected_totp_security_revision",
      );
      expect(body).toContain("challenge_id = decode(repeat('00',32),'hex')");
      expect(body).toContain("browser_digest = decode(repeat('00',32),'hex')");
      expect(body).toContain("receipt_digest = decode(repeat('00',32),'hex')");
      expect(body).toContain("challenge_id = browser_digest");
    }

    const begin = functionBodyFrom(
      runtime,
      "begin_platform_post_primary_totp_v1",
    );
    expect(begin).toContain("receipt_digest = decode(repeat('00',32),'hex')");
    expect(begin).toContain("challenge_id = decode(repeat('00',32),'hex')");
    expect(begin).toContain("browser_digest = decode(repeat('00',32),'hex')");
    expect(begin).toContain("challenge_id = browser_digest");
    expect(begin).toContain("expires_at > continuation_record.expires_at");

    const load = functionBodyFrom(
      runtime,
      "load_platform_post_primary_totp_v1",
    );
    expect(load).toContain("'authority','direct_platform_oidc'");
    expect(load).toContain("'continuationId',continuation.id::text");
    expect(load).toContain(
      "'receiptDigest',replace(encode(continuation.receipt_digest,'base64'),E'\\n','')",
    );
    expect(load).toContain("challenge.continuation_id = continuation_id");
    expect(load).not.toMatch(/\n\s+(?:UPDATE|INSERT|DELETE)\s/iu);

    for (const name of [
      "record_platform_post_primary_totp_failure_v1",
      "apply_platform_post_primary_totp_v1",
      "abandon_platform_post_primary_totp_v1",
    ] as const) {
      const body = functionBodyFrom(runtime, name);
      const firstMutation = body.search(/\n\s+(?:UPDATE ONLY|INSERT INTO)\s/iu);
      expect(firstMutation, `missing mutation in app.${name}`).toBeGreaterThan(
        0,
      );
      for (const check of [
        "continuation.id = continuation_id",
        "continuation.receipt_digest = receipt_digest",
        "app.private_platform_oidc_direct_authority_live_v1(",
        "continuation_record.selected_totp_credential_id",
        "continuation_record.selected_totp_security_revision",
      ]) {
        const checkIndex = body.indexOf(check);
        expect(
          checkIndex,
          `${check} must precede mutation in app.${name}`,
        ).toBeGreaterThan(-1);
        expect(
          checkIndex,
          `${check} must precede mutation in app.${name}`,
        ).toBeLessThan(firstMutation);
      }
    }

    const failure = functionBodyFrom(
      runtime,
      "record_platform_post_primary_totp_failure_v1",
    );
    expect(failure).toContain("challenge.continuation_id = continuation_id");
    expect(failure).toMatch(
      /UPDATE ONLY public\.platform_post_primary_totp_challenges[\s\S]+?AND EXISTS \([\s\S]+?continuation\.receipt_digest = receipt_digest[\s\S]+?continuation\.version = challenge\.expected_continuation_version/u,
    );

    const apply = functionBodyFrom(
      runtime,
      "apply_platform_post_primary_totp_v1",
    );
    expect(apply).toContain(
      "continuation_record.receipt_digest <> receipt_digest",
    );
    expect(apply).toContain(
      "completion_request_digest = decode(repeat('00',32),'hex')",
    );
    expect(apply).toMatch(
      /UPDATE ONLY public\.platform_post_primary_continuations[\s\S]+?continuation\.id = continuation_id[\s\S]+?continuation\.receipt_digest = receipt_digest[\s\S]+?continuation\.version = challenge_record\.expected_continuation_version/u,
    );
    expect(apply).toMatch(
      /UPDATE ONLY public\.platform_post_primary_totp_challenges[\s\S]+?challenge\.id = challenge_id[\s\S]+?challenge\.continuation_id = continuation_id[\s\S]+?challenge\.version = expected_version/u,
    );

    const abandon = functionBodyFrom(
      runtime,
      "abandon_platform_post_primary_totp_v1",
    );
    expect(abandon).toMatch(
      /UPDATE ONLY public\.platform_post_primary_continuations[\s\S]+?continuation\.id = continuation_id[\s\S]+?continuation\.receipt_digest = receipt_digest[\s\S]+?continuation\.state = 'pending'/u,
    );
    expect(abandon).toMatch(
      /UPDATE ONLY public\.platform_post_primary_totp_challenges[\s\S]+?challenge\.id = challenge_id[\s\S]+?challenge\.continuation_id = continuation_id[\s\S]+?challenge\.version = expected_version/u,
    );

    const continuationAuthority = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_continuation_source_live_v1",
    );
    expect(continuationAuthority).toContain("p_continuation.audience = 'api'");
    expect(continuationAuthority).toContain(
      "p_continuation.action = CASE p_continuation.origin",
    );
    expect(continuationAuthority).toContain("SELECT count(*) = 1");
    expect(continuationAuthority).toContain(
      "evidence.kind = 'platform_provider'",
    );
    expect(continuationAuthority).toContain("SELECT count(*) = 3");
    expect(continuationAuthority).toContain(
      "platform_floor.level IN ('primary','mfa')",
    );
    expect(continuationAuthority).toContain(
      "p_continuation.origin = 'session_revalidation' AND EXISTS",
    );
  });

  it("freezes every public direct runtime ABI to one bounded jsonb envelope", () => {
    for (const name of directJsonAbis) {
      const occurrences = runtime.match(
        new RegExp(`CREATE FUNCTION app\\.${escapeRegExp(name)}\\(`, "gu"),
      );
      expect(occurrences, `duplicate ABI app.${name}`).toHaveLength(1);
      const body = functionBodyFrom(runtime, name);
      expect(body).toMatch(
        new RegExp(
          `CREATE FUNCTION app\\.${escapeRegExp(name)}\\(\\s*p_[a-z_]+ jsonb\\s*\\)`,
          "u",
        ),
      );
      expect(body).toContain("RETURNS jsonb");
      expect(body).toContain("SECURITY DEFINER");
      expect(body).toContain("SET search_path = pg_catalog, public, app");
      expect(body).toContain("app.private_platform_oidc_direct_json_v1(");
    }

    expect(readiness).toContain("SELECT count(*) = 21");
    for (const name of directJsonAbis.slice(0, -1)) {
      expect(readiness).toContain(`app.${name}(jsonb)`);
    }
    expect(readiness).toContain(
      "app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)",
    );
  });

  it("resolves only an exact prelinked subject alias and never performs JIT", () => {
    const resolveAuthentication = functionBodyFrom(
      runtime,
      "resolve_platform_oidc_authentication_v1",
    );
    const applyAuthentication = functionBodyFrom(
      runtime,
      "apply_platform_oidc_authentication_v1",
    );

    for (const predicate of [
      "alias.platform_provider_id = provider_id",
      "alias.key_version = alias_key_version",
      "alias.subject_digest = alias_digest",
      "alias.retired_at IS NULL",
      "identity.platform_provider_id = alias.platform_provider_id",
      "identity.id = alias.external_identity_id",
      "identity.provider_kind = 'oidc'",
      "identity.retired_at IS NULL",
      "local_user.id = identity.user_id AND local_user.active",
    ]) {
      expect(resolveAuthentication).toContain(predicate);
    }
    expect(resolveAuthentication).toContain(
      "'accountMode','existing_identity'",
    );
    expect(resolveAuthentication).not.toMatch(
      /INSERT INTO public\.(users|platform_federated_external_identities|platform_federated_external_identity_aliases)/u,
    );
    expect(applyAuthentication).not.toMatch(
      /INSERT INTO public\.(users|platform_federated_external_identities)/u,
    );
    expect(applyAuthentication).toContain(
      "INSERT INTO public.platform_federated_external_identity_aliases",
    );
    expect(applyAuthentication).toContain("SET subject_format = 'utf8_exact'");
    expect(applyAuthentication).toContain(
      "subject_ciphertext = observation_ciphertext",
    );
    expect(applyAuthentication).toContain("subject_nonce = observation_nonce");
    expect(applyAuthentication).toContain(
      "key_version = observation_key_version",
    );
  });

  it("atomically binds a truthful exact-subject observation to replay and retained aliases", () => {
    const applyAuthentication = functionBodyFrom(
      runtime,
      "apply_platform_oidc_authentication_v1",
    );
    const identityGuard = functionBodyFrom(
      runtime,
      "guard_platform_federated_external_identity_v4",
    );

    expect(applyAuthentication).toContain(
      "'browserCapabilityDigest','returnPath','subject','observation'",
    );
    expect(applyAuthentication).toContain(
      "ARRAY['externalIdentityId','format','envelope','aliases']",
    );
    expect(applyAuthentication).toContain(
      "ARRAY['keyVersion','format','nonce','ciphertext']",
    );
    expect(applyAuthentication).toContain(
      "observation ->> 'format' <> 'utf8_exact'",
    );
    expect(applyAuthentication).toContain(
      "observation_envelope ->> 'format' <> 'utf8_exact'",
    );
    expect(applyAuthentication).not.toContain("unicode_casefold");
    expect(applyAuthentication).toContain(
      "observation_envelope ->> 'nonce',12,12",
    );
    expect(applyAuthentication).toContain(
      "observation_envelope ->> 'ciphertext',17,4112",
    );
    expect(withoutWhitespace(applyAuthentication)).toContain(
      "transaction_record.browser_capability_digest<>browser_capability_digest",
    );
    expect(applyAuthentication).toContain(
      "transaction_record.return_path <> return_path",
    );
    expect(applyAuthentication).toContain(
      "existing.request_snapshot ->> 'browserCapabilityDigest'",
    );
    expect(applyAuthentication).toContain(
      "existing.request_snapshot ->> 'returnPath'",
    );
    expect(applyAuthentication).toContain(
      "existing.request_snapshot ->> 'requestDigest'",
    );
    expect(applyAuthentication).toContain(
      "sha256(convert_to(p_command::text,'UTF8'))",
    );
    expect(applyAuthentication).toContain("provider_id::text || ':' ||");
    expect(applyAuthentication).toContain("),81460322");
    expect(applyAuthentication).toContain(
      "LOCK TABLE ONLY public.platform_federated_external_identities,",
    );
    expect(applyAuthentication).toContain(
      "WHERE keyring.retired_at IS NULL) <> observation_alias_count",
    );
    expect(applyAuthentication).toContain(
      "keyring.is_active AND keyring.retired_at IS NULL",
    );
    expect(applyAuthentication).toContain(
      "alias.external_identity_id <> external_identity_id",
    );
    expect(applyAuthentication).toContain(
      "'applied',false,'category','identity_collision'",
    );
    expect(applyAuthentication).toContain(
      "AND identity.version = identity_version",
    );
    expect(applyAuthentication).toContain("last_observation_state = 'known'");

    expect(identityGuard).toContain("NEW.version <> OLD.version");
    expect(identityGuard).toContain("NEW.last_observation_state <> 'known'");
    expect(identityGuard).toContain(
      "NEW.last_observed_at IS DISTINCT FROM transaction_timestamp()",
    );
    expect(identityGuard).toContain(
      "ROW(NEW.subject_format, NEW.subject_ciphertext, NEW.subject_nonce,",
    );
    expect(identityGuard).toContain(
      "NEW.resource_version := OLD.resource_version + 1",
    );
  });

  it("carries exact provider, policy, subject, factor and trust pins end to end", () => {
    const configuration = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_configuration_v1",
    );
    const planning = functionBodyFrom(
      runtime,
      "load_platform_oidc_planning_state_v1",
    );
    const authority = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_authority_live_v1",
    );
    const trust = functionBodyFrom(
      runtime,
      "load_platform_oidc_trust_snapshot_v1",
    );
    const applyAuthentication = functionBodyFrom(
      runtime,
      "apply_platform_oidc_authentication_v1",
    );

    for (const pin of [
      "providerRevision",
      "loginPolicyRevision",
      "configurationRevision",
      "securityRevision",
      "planRevision",
      "assurancePolicyRevision",
      "platformFloorPolicyId",
      "platformFloorPolicyRevision",
      "clientSecretRevision",
      "discoveryRevision",
      "discoveryDigest",
      "jwksRevision",
      "jwksDigest",
    ]) {
      expect(configuration).toContain(`'${pin}'`);
    }
    expect(configuration).toContain(
      "FROM ONLY public.mfa_policy_revisions AS counted_floor",
    );
    expect(configuration).toContain(
      "counted_floor.retired_at IS NULL\n      ) = 1",
    );
    for (const field of [
      "'id',platform_floor.id::text",
      "'revision',platform_floor.revision",
      "'level',platform_floor.level",
      "'localRequired',platform_floor.local_required",
      "'freshnessNanoseconds',platform_floor.freshness_nanoseconds",
      "'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline)",
      "'identityVersion',identity.version",
      "'aliasKeyVersion',alias.key_version",
      "'userAuthenticationRevision',local_user.authentication_revision",
      "'id',factor.id::text",
      "'userId',factor.user_id::text",
      "'securityRevision',factor.security_revision",
      "'active',factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL",
      "'confirmedAt',to_jsonb(factor.confirmed_at)",
    ]) {
      expect(planning).toContain(field);
    }
    expect(planning).toContain("ORDER BY factor.id");
    expect(planning).toContain("LIMIT 1");

    for (const predicate of [
      "provider.version = p_provider_revision",
      "runtime_policy.security_revision = p_security_revision",
      "runtime_policy.assurance_policy_revision = p_assurance_policy_revision",
      "login_policy.revision = p_login_policy_revision",
      "local_user.authentication_revision = p_user_authentication_revision",
      "identity.version = p_identity_version",
      "alias.key_version = p_alias_key_version",
      "platform_floor.id = p_platform_floor_policy_id",
      "platform_floor.revision = p_platform_floor_policy_revision",
      "trust.id = p_trust_rule_id",
      "trust.revision = p_trust_rule_revision",
    ]) {
      expect(authority).toContain(predicate);
    }
    expect(trust).toContain(
      "'assurancePolicyRevision',(pins ->> 'assurancePolicyRevision')::bigint",
    );
    expect(trust).toContain("ORDER BY rule.id,rule.revision");
    expect(applyAuthentication).toContain("assurance_level = 'primary' AND (");
    expect(applyAuthentication).toContain(
      "assurance_level IN ('mfa','phishing_resistant') AND (",
    );
    expect(applyAuthentication).toContain(
      "factor.id = selected_totp_credential_id",
    );
    expect(applyAuthentication).toContain(
      "factor.security_revision = selected_totp_security_revision",
    );
    expect(applyAuthentication).toContain(
      "selected_totp_security_revision,trust_rule_id,trust_rule_revision",
    );
    expect(applyAuthentication).toContain(
      "'platform_provider',assurance_level",
    );
    expect(
      functionBodyFrom(runtime, "apply_platform_post_primary_totp_v1"),
    ).toContain(
      "continuation_record.trust_rule_id,continuation_record.trust_rule_revision",
    );
  });

  it("guards a direct session as tenantless OIDC with exactly one typed provenance", () => {
    const createSession = functionBodyFrom(
      runtime,
      "private_platform_oidc_create_direct_session_v1",
    );
    const guardSession = functionBodyFrom(
      runtime,
      "assert_platform_oidc_direct_session_v1",
    );
    const revalidation = functionBodyFrom(
      runtime,
      "load_platform_oidc_session_revalidation_v1",
    );
    const directReadiness = functionBodyFrom(
      readiness,
      "private_platform_oidc_direct_runtime_schema_readiness_v1",
    );

    expect(createSession).toContain(
      "session_id,p_user_id,rotation_family_id,NULL,token_digest,",
    );
    expect(createSession).toContain("csrf_secret_digest,'oidc'");
    expect(createSession).toContain("'platform_provider',p_issued_at");
    expect(createSession).toContain(
      "INSERT INTO public.auth_session_platform_oidc_provenance",
    );
    expect(createSession).toContain(
      "(session_id,'login',p_provider_id,p_login_policy_revision)",
    );
    expect(createSession).toContain(
      "(session_id,'assurance',p_provider_id,p_assurance_policy_revision)",
    );
    expect(createSession).toContain(
      "(session_id,'platform_floor',p_platform_floor_policy_id,",
    );
    expect(createSession).toContain("OR audience <> 'api'");
    expect(createSession).toContain("platform_floor_freshness_nanoseconds > 0");
    expect(createSession).toContain(
      "direct platform OIDC platform floor evidence is stale",
    );
    expect(createSession).toContain("provider_floor_eligible :=");
    expect(createSession).toContain("totp_floor_eligible :=");
    expect(directReadiness).toContain("direct_state.audience <> 'api'");
    expect(directReadiness).toContain("direct_state.recovery_restricted");
    expect(directReadiness).toContain(
      "direct_state.primary_kind <> 'platform_provider'",
    );

    for (const predicate of [
      "session.active_tenant_id IS NULL",
      "session.authentication_method = 'oidc'",
      "state.primary_kind = 'platform_provider'",
      "provenance.user_id = state.user_id",
      "provenance.primary_kind = state.primary_kind",
    ]) {
      expect(guardSession).toContain(predicate);
    }
    for (const conflictingFamily of [
      "auth_session_mfa_states",
      "auth_session_federated_provenance",
      "auth_session_tenant_platform_federated_provenance",
    ]) {
      expect(guardSession).toContain(conflictingFamily);
    }
    expect(revalidation).toContain("'policyPinsExact',(");
    expect(revalidation).toContain("SELECT count(*) = 3");
    expect(revalidation).toContain("p_lookup,ARRAY['sessionId','observedAt'],");
    expect(revalidation).toContain("'currentVersion',state.session_version");
    expect(revalidation).not.toContain("'expectedVersion'");
    for (const rawFact of [
      "'authenticationMethod',session.authentication_method",
      "'audience',state.audience",
      "'primaryKind',state.primary_kind",
      "'issuedAt',to_jsonb(state.issued_at)",
      "'recoveryRestricted',state.recovery_restricted",
      "'userAuthenticationRevision',state.user_authentication_revision",
      "'directStateCount'",
      "'directProvenanceCount'",
      "'tenantProvenanceCount'",
      "'providerEvidenceCount'",
      "'totpEvidenceCount'",
      "'rotationFamilyLive'",
      "'runtimePolicyEnabled',runtime_policy.enabled",
      "'legacyPlatformLoginEnabled',runtime_policy.platform_login_enabled",
      "'loginPolicyEnabled',login_policy.enabled",
      "'accountMode',login_policy.account_mode",
      "'identityCurrentProviderId',identity.platform_provider_id::text",
      "'identityCurrentUserId',identity.user_id::text",
      "'aliasCurrentProviderId',alias.platform_provider_id::text",
      "'aliasCurrentIdentityId',alias.external_identity_id::text",
      "'currentScope',platform_floor.scope",
      "'currentTenantId',platform_floor.tenant_id",
      "'currentRetiredAt',to_jsonb(platform_floor.retired_at)",
      "'currentCount'",
      "'factorAuthorities'",
      "'trustAuthorities'",
    ]) {
      expect(revalidation).toContain(rawFact);
    }
    expect(revalidation).toContain(
      "LEFT JOIN ONLY public.auth_session_platform_oidc_states AS state",
    );
    expect(revalidation).toMatch(
      /'trustAuthorities'[\s\S]+?LEFT JOIN ONLY public\.platform_federated_trust_rules AS trust\s+ON trust\.id = evidence\.trust_rule_id\s+WHERE evidence\.session_id = session\.id/u,
    );
    expect(revalidation).toContain("WHERE session.id = session_id;");
    expect(revalidation).not.toContain(
      "WHERE session.id = session_id AND session.active_tenant_id IS NULL",
    );
    const applyRevalidation = functionBodyFrom(
      runtime,
      "apply_platform_oidc_session_revalidation_v1",
    );
    expect(applyRevalidation).toContain("'expectedVersion',expected_version");
    expect(applyRevalidation).toContain("'userId',state_record.user_id::text");
    expect(applyRevalidation).toContain(
      "authority #>> '{session,audience}' = 'api'",
    );
    expect(applyRevalidation).toContain(
      "CASE authority #>> '{authority,platformFloor,level}'",
    );
    expect(applyRevalidation).toContain(
      "'{authority,platformFloor,localRequired}'",
    );
    expect(applyRevalidation).toContain(
      "trust.maximum_authentication_age_seconds",
    );
    expect(applyRevalidation).toContain(
      "'{authority,platformFloor,freshnessNanoseconds}'",
    );
    expect(applyRevalidation).toContain(
      "evidence.authenticated_at > state_record.issued_at",
    );
    expect(applyRevalidation).toContain(
      "WHERE evidence.session_id = session_id\n      AND evidence.kind = 'platform_provider'",
    );
    expect(applyRevalidation).toContain(
      "'newVersion',0,'newSessionId',new_session_id::text",
    );
    expect(applyRevalidation).toContain(
      "'{authority,legacyPlatformLoginEnabled}')::boolean",
    );
    expect(applyRevalidation).not.toContain(
      "app.private_platform_oidc_direct_audit_v1(",
    );
    expect(readiness).toContain("direct_provenance.count <> 1");
    expect(readiness).toContain("direct_provenance.user_id <> session.user_id");
  });

  it("keeps transaction floor pins and evidence or replay ledgers immutable", () => {
    const transactionGuard = functionBodyFrom(
      runtime,
      "guard_platform_oidc_transaction_v1",
    );
    const runtimeWriteGuard = functionBodyFrom(
      runtime,
      "guard_platform_oidc_runtime_write_v1",
    );

    expect(transactionGuard).toContain(
      "NEW.assurance_policy_revision, NEW.platform_floor_policy_id,",
    );
    expect(transactionGuard).toContain(
      "NEW.platform_floor_policy_revision, NEW.client_secret_revision,",
    );
    expect(transactionGuard).toContain(
      "OLD.assurance_policy_revision, OLD.platform_floor_policy_id,",
    );
    expect(transactionGuard).toContain(
      "OLD.platform_floor_policy_revision, OLD.client_secret_revision,",
    );
    expect(transactionGuard).toContain(
      ") IS DISTINCT FROM ROW(\n      OLD.transaction_id",
    );

    const immutableRelations = [
      "platform_oidc_authentication_applications",
      "platform_post_primary_continuation_evidence",
      "platform_post_primary_continuation_policy_pins",
      "auth_session_platform_oidc_provenance",
      "auth_session_platform_oidc_evidence",
      "auth_session_platform_oidc_policy_pins",
      "platform_oidc_session_revalidation_commands",
      "platform_oidc_tenant_switch_commands",
    ] as const;
    expect(runtimeWriteGuard).toContain(
      "IF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN (",
    );
    for (const relation of immutableRelations) {
      expect(runtimeWriteGuard).toContain(`'${relation}'`);
    }
    expect(runtimeWriteGuard).toContain(
      "direct platform OIDC evidence and replay rows are immutable",
    );
    expect(runtimeWriteGuard).toContain("IF TG_OP = 'DELETE' THEN");
    expect(runtimeWriteGuard).toContain(
      "direct platform OIDC runtime rows are archival",
    );
  });

  it("uses replay ledgers, exact CAS and a direct-to-tenant switch graph", () => {
    const createTransaction = functionBodyFrom(
      runtime,
      "create_platform_oidc_authentication_transaction_v1",
    );
    const claimTransaction = functionBodyFrom(
      runtime,
      "claim_platform_oidc_authentication_transaction_v1",
    );
    const failTransaction = functionBodyFrom(
      runtime,
      "fail_platform_oidc_authentication_transaction_v1",
    );
    const loadClientSecret = functionBodyFrom(
      runtime,
      "load_platform_oidc_client_secret_v1",
    );
    const applyAuthentication = functionBodyFrom(
      runtime,
      "apply_platform_oidc_authentication_v1",
    );
    const applyTotp = functionBodyFrom(
      runtime,
      "apply_platform_post_primary_totp_v1",
    );
    const revalidate = functionBodyFrom(
      runtime,
      "apply_platform_oidc_session_revalidation_v1",
    );
    const loadSwitch = functionBodyFrom(
      runtime,
      "load_platform_oidc_tenant_switch_v1",
    );
    const applySwitch = functionBodyFrom(
      runtime,
      "apply_platform_oidc_tenant_switch_v1",
    );

    expect(createTransaction).toContain("pg_advisory_xact_lock");
    expect(createTransaction).toContain(
      "direct platform OIDC transaction replay collision",
    );
    expect(claimTransaction).toContain(
      "ARRAY['stateDigest','browserDigest','authorizationCodeDigest',",
    );
    expect(claimTransaction).not.toContain("ARRAY['id','stateDigest'");
    expect(claimTransaction).toContain(
      "WHERE transaction.state_digest = state_digest",
    );
    expect(claimTransaction).toContain(
      "AND transaction.browser_digest = browser_digest",
    );
    expect(claimTransaction).toContain(
      "transaction_record.claimed_at IS DISTINCT FROM claimed_at",
    );
    expect(claimTransaction).toContain(
      "direct platform OIDC claim replay collision",
    );
    expect(loadClientSecret).toContain("'secretId',secret.id::text");
    expect(loadClientSecret).toContain("'provider',provider,'pins',pins");
    expect(failTransaction).toContain(
      "transaction_record.completed_at IS DISTINCT FROM completed_at",
    );
    expect(failTransaction).toContain(
      "transaction_record.version <> expected_version + 1",
    );
    expect(failTransaction).toContain(
      "FROM ONLY public.platform_audit_events AS audit_event",
    );
    expect(applyAuthentication).toContain(
      "direct platform OIDC apply replay collision",
    );
    expect(applyAuthentication).toContain(
      "direct platform OIDC apply lost transaction CAS",
    );
    expect(applyTotp).toContain(
      "direct platform OIDC TOTP apply replay collision",
    );
    expect(applyTotp).toContain("'category','replay'");
    expect(revalidate).toContain(
      "direct platform OIDC revalidation replay collision",
    );
    expect(revalidate).toContain(
      "direct platform OIDC revalidation lost session CAS",
    );

    for (const targetEdge of [
      "public.tenant_memberships",
      "public.tenant_mfa_subjects",
      "public.tenant_platform_auth_provider_bindings",
      "public.tenant_platform_identity_provider_access_epochs",
      "public.tenant_authorization_sources",
      "public.tenant_platform_federated_provider_access_grants",
    ]) {
      expect(loadSwitch).toContain(targetEdge);
    }
    for (const sourceFact of [
      "'authenticationMethod',session.authentication_method",
      "'primaryKind',state.primary_kind",
      "'directStateCount'",
      "'directProvenanceCount'",
      "'tenantProvenanceCount'",
      "'rotationFamilyLive'",
      "'platformLoginLive'",
      "'accountMode',login_policy.account_mode",
      "'revisions',jsonb_build_object(",
    ]) {
      expect(loadSwitch).toContain(sourceFact);
    }
    for (const targetFact of [
      "'tenantExecutionLive'",
      "'tenant',jsonb_build_object(",
      "'membership',jsonb_build_object(",
      "'binding',jsonb_build_object(",
      "'accessEpoch',jsonb_build_object(",
      "'accessSource',jsonb_build_object(",
      "'externalIdentity',jsonb_build_object(",
      "'subjectAlias',jsonb_build_object(",
      "'accessGrant',jsonb_build_object(",
      "'commandPins',command_pins",
    ]) {
      expect(loadSwitch).toContain(targetFact);
    }
    expect(loadSwitch).toContain(
      "revalidation_snapshot := app.load_platform_oidc_session_revalidation_v1(",
    );
    expect(loadSwitch).toContain(
      "'evidence',revalidation_snapshot -> 'evidence'",
    );
    expect(loadSwitch).toContain("IF source_ready THEN");
    expect(loadSwitch).toContain(
      "ARRAY['sourceSessionId','targetTenantId','observedAt']",
    );
    expect(loadSwitch).not.toContain("p_lookup ->> 'expectedVersion'");
    expect(loadSwitch).toContain("'currentVersion',state.session_version");
    expect(applySwitch).toContain(
      "live_snapshot -> 'commandPins' IS DISTINCT FROM target",
    );
    expect(applySwitch).toContain(
      "SELECT evidence.level,evidence.authenticated_at,evidence.expires_at",
    );
    expect(applySwitch).toContain("AND evidence.kind = 'platform_provider'");
    expect(applySwitch).toContain("OR local_required");
    expect(applySwitch).not.toContain(
      "(assurance_snapshot ->> 'localSatisfied')::boolean",
    );
    expect(applySwitch).toContain(
      "request_digest = decode(repeat('00',32),'hex')",
    );
    expect(applySwitch).toContain(
      "source_session.active_tenant_id IS NOT NULL",
    );
    expect(applySwitch).toContain("audience <> 'api'");
    expect(applySwitch).toContain("audience <> source_state.audience");
    expect(applySwitch).toContain(
      "recovery_restricted <> source_state.recovery_restricted",
    );
    expect(applySwitch).toContain("OR recovery_restricted THEN");
    expect(applySwitch).toContain(
      "Hold every source and target authority row through rotation",
    );
    for (const lockedAuthority of [
      "public.users AS local_user",
      "public.platform_auth_providers AS provider",
      "public.platform_federated_provider_policies AS runtime_policy",
      "public.platform_oidc_login_policies AS login_policy",
      "public.platform_federated_external_identities AS identity",
      "public.platform_federated_external_identity_aliases AS alias",
      "public.mfa_policy_revisions AS platform_floor",
      "public.tenants AS tenant",
      "public.tenant_memberships AS membership",
      "public.tenant_mfa_subjects AS subject",
      "public.tenant_platform_auth_provider_bindings AS binding",
      "public.tenant_platform_identity_provider_access_epochs AS epoch",
      "public.tenant_authorization_sources AS authorization_source",
      "public.tenant_platform_federated_provider_access_grants AS grant_row",
    ]) {
      expect(applySwitch).toContain(lockedAuthority);
    }
    expect(applySwitch).toContain(
      "FOR SHARE OF local_user,provider,runtime_policy,login_policy,provenance,",
    );
    expect(applySwitch).not.toContain("'expectedVersion',expected_version");
    expect(applySwitch).toContain(
      "INSERT INTO public.auth_session_tenant_platform_federated_provenance",
    );
    expect(applySwitch).toContain(
      "revoke_reason = 'platform_oidc_tenant_switch_rotated'",
    );
    expect(applySwitch).toContain(
      "direct platform OIDC tenant switch replay collision",
    );
  });

  it("extends provider creation and account retirement without bypassing older invariants", () => {
    const createProvider = functionBodyFrom(
      runtime,
      "create_platform_oidc_auth_provider_v3",
    );
    const retireAccount = functionBodyFrom(
      runtime,
      "retire_platform_identity_account_v4",
    );

    expect(createProvider).toContain(
      "FROM app.create_platform_oidc_auth_provider_v2(",
    );
    expect(createProvider).toContain(
      "INSERT INTO public.platform_oidc_login_policies",
    );
    expect(retireAccount).toContain(
      "FROM app.retire_platform_identity_account_v3(",
    );
    for (const revokedFamily of [
      "platform_post_primary_totp_challenges",
      "platform_post_primary_continuations",
      "tenant_post_primary_continuations",
      "auth_session_platform_oidc_provenance",
      "auth_session_tenant_platform_federated_provenance",
    ]) {
      expect(retireAccount).toContain(revokedFamily);
    }
    expect(runtime).toContain(
      "REVOKE ALL ON FUNCTION\n  app.create_platform_oidc_auth_provider_v2(",
    );
    expect(runtime).toContain("app.retire_platform_identity_account_v3(\n");
    expect(readiness).toContain(
      "app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)",
    );
    expect(readiness).toContain(
      "app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)",
    );
  });

  it("rejects unknown or oversized JSON and emits correlated redacted audit", () => {
    const jsonGuard = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_json_v1",
    );
    const audit = functionBodyFrom(
      runtime,
      "private_platform_oidc_direct_audit_v1",
    );

    expect(jsonGuard).toContain("jsonb_typeof(p_value) <> 'object'");
    expect(jsonGuard).toContain(
      "pg_column_size(p_value) NOT BETWEEN 2 AND p_maximum_size",
    );
    expect(jsonGuard).toContain("jsonb_object_keys(p_value)");
    expect(jsonGuard).toContain("WHERE NOT key.name = ANY(p_allowed)");
    expect(jsonGuard).toContain("unnest(p_required)");

    expect(audit).toContain(
      "ARRAY['eventId','requestId','correlationId','authenticationMethod']",
    );
    expect(audit).toContain("p_audit ->> 'authenticationMethod' <> 'oidc'");
    for (const forbidden of [
      "authorizationCode",
      "stateDigest",
      "nonceDigest",
      "browserDigest",
      "tokenDigest",
      "secretCiphertext",
      "receiptDigest",
      "subjectDigest",
    ]) {
      expect(audit).toContain(`'${forbidden}'`);
    }
    expect(audit).toContain("app.append_platform_audit_event(");
    expect(audit).toContain("request_id,correlation_id,ip_address");

    for (const mutation of [
      "create_platform_oidc_authentication_transaction_v1",
      "claim_platform_oidc_authentication_transaction_v1",
      "apply_platform_oidc_authentication_v1",
      "fail_platform_oidc_authentication_transaction_v1",
      "begin_platform_post_primary_totp_v1",
      "record_platform_post_primary_totp_failure_v1",
      "apply_platform_post_primary_totp_v1",
      "abandon_platform_post_primary_totp_v1",
      "apply_platform_oidc_tenant_switch_v1",
      "cleanup_platform_oidc_authentication_runtime_v1",
    ]) {
      expect(functionBodyFrom(runtime, mutation)).toContain(
        "app.private_platform_oidc_direct_audit_v1(",
      );
    }
    expect(
      functionBodyFrom(runtime, "apply_platform_oidc_session_revalidation_v1"),
    ).not.toContain("app.private_platform_oidc_direct_audit_v1(");
  });

  it("exposes no table DML and grants only API commands or worker cleanup", () => {
    expect(runtime).toContain("REVOKE ALL ON TABLE\n");
    for (const table of platformTables) {
      expect(runtime).toContain(`public.${table}`);
    }
    expect(runtime).toContain(
      "FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,",
    );
    expect(readiness).toContain(
      "'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'",
    );
    expect(readiness).toContain("pg_catalog.has_table_privilege(");
    expect(readiness).toContain("'periapsis_api',checked.oid,'EXECUTE'");
    expect(readiness).toContain("'periapsis_migrator',checked.oid,'EXECUTE'");
    expect(readiness).toContain("'periapsis_worker',checked.oid,'EXECUTE'");
    expect(readiness).toContain(
      "'periapsis_worker',\n    'app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)'::regprocedure",
    );
    expect(readiness).toContain(
      "'periapsis_api',\n    'app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)'::regprocedure",
    );
    expect(runtime).toContain(
      "app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)\nTO periapsis_worker;",
    );
    expect(runtime).not.toContain(
      "app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)\nTO periapsis_api;",
    );

    const privateReadiness = functionBodyFrom(
      readiness,
      "private_platform_oidc_direct_runtime_schema_readiness_v1",
    );
    expect(privateReadiness).toContain("owner.rolname <> 'periapsis_migrator'");
    expect(privateReadiness).toContain("NOT function_row.prosecdef");
    expect(privateReadiness).toContain("'search_path=pg_catalog, public, app'");
    expect(privateReadiness).toContain(
      "'periapsis_api',function_row.oid,'EXECUTE'",
    );
    expect(privateReadiness).toContain(
      "'periapsis_worker',function_row.oid,'EXECUTE'",
    );
  });

  it("preserves v39/v40 predecessor evidence under the v48 manifest", () => {
    expect(journal.entries.length).toBeGreaterThanOrEqual(219);
    expect(journal.entries[218]).toMatchObject({
      idx: 218,
      when: 1_788_276_517_454,
      tag: "0218_v48_compatibility",
    });
    expect(journal.entries.slice(177, 184)).toEqual([
      {
        idx: 177,
        version: "7",
        when: 1788073466742,
        tag: "0177_aspiring_mojo",
        breakpoints: true,
      },
      {
        idx: 178,
        version: "7",
        when: 1788075000000,
        tag: "0178_platform_oidc_direct_runtime",
        breakpoints: true,
      },
      {
        idx: 179,
        version: "7",
        when: 1788077000000,
        tag: "0179_platform_oidc_direct_compatibility",
        breakpoints: true,
      },
      {
        idx: 180,
        version: "7",
        when: 1788085734144,
        tag: "0180_platform_oidc_direct_administration",
        breakpoints: true,
      },
      {
        idx: 181,
        version: "7",
        when: 1788085744122,
        tag: "0181_platform_oidc_direct_administration_compatibility",
        breakpoints: true,
      },
      {
        idx: 182,
        version: "7",
        when: 1788091350019,
        tag: "0182_mfa_policy_administration",
        breakpoints: true,
      },
      {
        idx: 183,
        version: "7",
        when: 1788094095501,
        tag: "0183_mfa_policy_administration_compatibility",
        breakpoints: true,
      },
    ]);

    for (const hash of [
      expectedSchemaCompatibilityV40SourceHash,
      expectedPrivatePlatformIdentityDependencySurfaceHashV6SourceHash,
      expectedPrivatePlatformIdentityRuntimeReadinessV6SourceHash,
      expectedPlatformIdentityRuntimeReadinessV6SourceHash,
      expectedPrivatePlatformOIDCDirectDependencySurfaceHashV2SourceHash,
      expectedPrivatePlatformOIDCDirectRuntimeReadinessV2SourceHash,
      expectedPlatformOIDCDirectRuntimeReadinessV2SourceHash,
    ]) {
      expect(hash).toMatch(/^[0-9a-f]{64}$/u);
    }
    expect(expectedRetiredSchemaCompatibilityV39SourceHash).toBe(
      expectedSchemaCompatibilityV39SourceHash,
    );
    expect(administration).toContain(
      "CREATE FUNCTION app.activate_platform_oidc_direct_login_v1(",
    );
    expect(administrationReadiness).toContain(
      "derived_definition,'journal_count = 180','journal_count = 182'",
    );
    expect(administrationReadiness).toContain(
      "derived_definition,'current_count = 180','current_count = 182'",
    );
    expect(administrationReadiness).toContain(
      "'^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){181}$'",
    );
    expect(administrationReadiness).toContain(
      "app.private_platform_identity_runtime_schema_readiness_v6()",
    );
    expect(administrationReadiness).toContain(
      "app.private_platform_oidc_direct_runtime_schema_readiness_v2()",
    );
    expect(administrationReadiness).toContain(
      "app.platform_oidc_direct_runtime_schema_readiness_v2()",
    );
    expect(administrationReadiness).toContain(
      "ALTER FUNCTION app.schema_compatibility_v39()\n      SET app.schema_compatibility_fingerprint = 'RETIRED'",
    );
    expect(administrationReadiness).toContain(
      "REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()",
    );

    expect(generator).toContain('constant: "SchemaCompatibilityV40"');
    expect(generator).toContain('sourceConstant: "SchemaCompatibilityV39"');
    expect(generator).toContain(
      'constant: "PrivatePlatformOIDCDirectDependencySurfaceHashV2"',
    );
    expect(generator).toContain(
      'constant: "PrivatePlatformOIDCDirectRuntimeReadinessV2"',
    );
    expect(generator).toContain(
      'constant: "PlatformOIDCDirectRuntimeReadinessV2"',
    );
  });

  it("binds API and worker health to the current V58 release roots", () => {
    for (const health of [apiHealth, workerHealth]) {
      for (const root of [
        "app.schema_compatibility_v58()",
        "app.schema_compatibility_v51()",
        "app.schema_compatibility_v50()",
        "app.schema_compatibility_v49()",
        "app.private_v47_migration_convergence_schema_readiness_v1()",
        "app.private_schema_compatibility_journal_v58()",
        "app.private_release_runtime_dependency_surface_hash_v58()",
        "app.private_release_runtime_schema_readiness_v58()",
        "app.release_runtime_schema_readiness_v58()",
        "app.ticket_bulk_runtime_schema_readiness_v58()",
        "app.ticket_export_runtime_schema_readiness_v58()",
        "app.private_rotate_sla_readiness_v48()",
      ]) {
        expect(health).toContain(root);
      }
      expect(health).toContain(
        "expectedRetiredSchemaCompatibilityV49SourceHash",
      );
      expect(health).toContain(
        "expectedRetiredSchemaCompatibilityV50SourceHash",
      );
      expect(health).toContain(
        "expectedRetiredSchemaCompatibilityV51SourceHash",
      );
      expect(health).not.toContain("from app.schema_compatibility_v51()");
      expect(health).not.toContain("from app.schema_compatibility_v50()");
      expect(health).not.toContain("from app.schema_compatibility_v49()");
      expect(health).not.toContain("from app.schema_compatibility_v48()");
      expect(health).not.toContain(
        "app.platform_identity_runtime_schema_readiness_v13()",
      );
    }
    expect(apiHealth).toContain(
      "count(*) = 24 and coalesce(bool_and(catalog_ready), false)",
    );
    expect(workerHealth).toContain(
      "count(*) = 21 and coalesce(bool_and(catalog_ready), false)",
    );
  });
});
