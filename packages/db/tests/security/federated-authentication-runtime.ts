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

const databaseUrl =
  process.env.PERIAPSIS_FEDERATED_AUTH_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_FEDERATED_AUTH_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sql = postgres(databaseUrl, { max: 2, onnotice: () => undefined });

const uuid = (sequence: number): string =>
  `019d2f99-1000-7000-8000-${sequence.toString(16).padStart(12, "0")}`;
const digest = (label: string): string =>
  createHash("sha256").update(label).digest("base64");

function assertSqlState(
  error: unknown,
  expected: string,
): asserts error is ErrorWithCode {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
}

async function asRole<T>(
  role: "periapsis_api" | "periapsis_worker" | "periapsis_notifier",
  operation: (transaction: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '10s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function forEachSequential<T>(
  values: readonly T[],
  operation: (value: T) => Promise<void>,
  index = 0,
): Promise<void> {
  const value = values[index];
  if (value === undefined) {
    return;
  }
  await operation(value);
  await forEachSequential(values, operation, index + 1);
}

const begin = {
  operationRunId: uuid(1),
  receiptDigest: digest("receipt"),
  networkDigest: digest("network"),
  accountDigest: digest("account"),
  providerDigest: digest("provider"),
} as const;

try {
  const [version] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    version?.version.startsWith("18."),
    "runtime harness requires PostgreSQL 18",
  );

  const [ready] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<{ ready: boolean }[]>`
      SELECT app.federated_authentication_schema_readiness_v52() AS ready
    `,
  );
  assert.deepEqual(ready, { ready: true });

  const [compatibility] = await sql<
    {
      current_count: number;
      current_latest: string;
      current_hash: string;
      current_fingerprint: string;
      legacy_count: number;
      legacy_hash: string;
      legacy_fingerprint: string;
      predecessor_count: number;
      predecessor_hash: string;
      predecessor_fingerprint: string;
      release_ready: boolean;
    }[]
  >`
    SELECT current_projection.applied_count::integer AS current_count,
           current_projection.latest_created_at::text AS current_latest,
           current_projection.latest_hash AS current_hash,
           current_projection.migration_fingerprint AS current_fingerprint,
           legacy_projection.applied_count::integer AS legacy_count,
           legacy_projection.latest_hash AS legacy_hash,
           legacy_projection.migration_fingerprint AS legacy_fingerprint,
           predecessor_projection.applied_count::integer AS predecessor_count,
           predecessor_projection.latest_hash AS predecessor_hash,
           predecessor_projection.migration_fingerprint AS predecessor_fingerprint,
           app.release_runtime_schema_readiness_v52() AS release_ready
    FROM app.schema_compatibility_v52() AS current_projection
    CROSS JOIN app.schema_compatibility_v28() AS legacy_projection
    CROSS JOIN app.schema_compatibility_v27() AS predecessor_projection
  `;
  assert.deepEqual(compatibility, {
    current_count: expectedMigrationCount,
    current_latest: String(expectedMigrationCreatedAt),
    current_hash: expectedMigrationHash,
    current_fingerprint: expectedMigrationFingerprint,
    legacy_count: 0,
    legacy_hash: "UNSUPPORTED",
    legacy_fingerprint: "UNSUPPORTED",
    predecessor_count: 0,
    predecessor_hash: "UNSUPPORTED",
    predecessor_fingerprint: "UNSUPPORTED",
    release_ready: true,
  });

  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`SELECT count(*) FROM public.tenant_federated_external_identities`,
    ),
    (error) => {
      assertSqlState(error, "42501");
      return true;
    },
  );
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`SELECT app.guard_federated_immutable_ledger_v1()`,
    ),
    (error) => {
      assertSqlState(error, "42501");
      return true;
    },
  );
  await assert.rejects(
    asRole(
      "periapsis_worker",
      (transaction) =>
        transaction`SELECT app.begin_tenant_oidc_authentication_v1(
        ${transaction.json({ begin, tenantSlug: "7", loginKey: "oidc" })}::jsonb
      )`,
    ),
    (error) => {
      assertSqlState(error, "42501");
      return true;
    },
  );
  await assert.rejects(
    asRole(
      "periapsis_notifier",
      (transaction) =>
        transaction`SELECT app.federated_authentication_schema_readiness_v52()`,
    ),
    (error) => {
      assertSqlState(error, "42501");
      return true;
    },
  );

  const [numericSlug] = await asRole(
    "periapsis_api",
    (transaction) =>
      transaction<{ value: postgres.JSONValue | null }[]>`
      SELECT app.begin_tenant_oidc_authentication_v1(
        ${transaction.json({ begin, tenantSlug: "7", loginKey: "oidc" })}::jsonb
      ) AS value
    `,
  );
  assert.deepEqual(numericSlug, { value: null });
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`SELECT app.begin_tenant_oidc_authentication_v1(
        ${transaction.json({ begin, tenantSlug: "a-", loginKey: "oidc" })}::jsonb
      )`,
    ),
    (error) => {
      assertSqlState(error, "22023");
      return true;
    },
  );

  const future = new Date(Date.now() + 60 * 60_000);
  const futureExpiry = new Date(future.getTime() + 5 * 60_000);
  const futureOIDC = {
    begin,
    current: {
      id: digest("transaction"),
      stateDigest: digest("state"),
      browserDigest: digest("browser"),
      nonceDigest: digest("nonce"),
      verifierKeyVersion: 1,
      verifierCiphertext: digest("verifier"),
      pins: {
        provider: {
          scope: "tenant",
          tenantId: uuid(2),
          providerId: uuid(3),
          bindingId: uuid(4),
        },
        providerRevision: 1,
        bindingRevision: 1,
        configurationRevision: 1,
        securityRevision: 1,
        mappingRevision: 1,
        authorizationRevision: 1,
        assurancePolicyRevision: 1,
        clientSecretRevision: 1,
        discoveryRevision: 1,
        discoveryDigest: digest("discovery"),
        jwksRevision: 1,
        jwksDigest: digest("jwks"),
      },
      clientId: "runtime-client",
      redirectUri: "https://example.invalid/oidc/callback",
      postLogoutRedirectUri: "https://example.invalid/logout",
      returnPath: "/portal",
      scopes: ["openid"],
      allowRefreshToken: false,
      useUserInfo: false,
      createdAt: future.toISOString(),
      expiresAt: futureExpiry.toISOString(),
      state: "pending",
      version: 1,
    },
  } as const;
  await assert.rejects(
    asRole(
      "periapsis_api",
      (transaction) =>
        transaction`SELECT app.create_oidc_authentication_transaction_v1(
        ${transaction.json(futureOIDC)}::jsonb
      )`,
    ),
    (error) => {
      assertSqlState(error, "22023");
      return true;
    },
  );

  const missingMutation = (sessionId: string) => ({
    sessionId,
    tenantId: uuid(6),
    userId: uuid(7),
    audience: "api",
    authenticationMethod: "oidc",
    expectedVersion: 1,
    observedAt: new Date().toISOString(),
    decision: "usable",
    reason: "current",
    requirement: {},
  });
  await forEachSequential([uuid(8), uuid(9)], async (sessionId) => {
    await assert.rejects(
      asRole(
        "periapsis_api",
        (transaction) =>
          transaction`SELECT app.apply_federated_session_revalidation_v1(
          ${transaction.json(missingMutation(sessionId))}::jsonb
        )`,
      ),
      (error) => {
        assertSqlState(error, "40001");
        assert.equal(error.message, "federated session authority unavailable");
        assert(!error.message.includes(sessionId));
        return true;
      },
    );
  });
} finally {
  await sql.end();
}
